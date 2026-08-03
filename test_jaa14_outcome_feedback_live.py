"""Operational and adversarial acceptance for the live JAA-14 ledger."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.models import PipelineState
from career_automation.outcome_feedback import (
    FROZEN_OUTCOME_FEEDBACK_CONTRACT,
    compile_strategy_experiment,
)
from career_automation.outcome_feedback_live import (
    OutcomeEvidenceError,
    OutcomeFeedbackLedger,
    PredictionOrderError,
)
from career_automation.status_ingestion_live import (
    ApplicationReceiptBinding,
    EmployerFollowUpPolicy,
    FollowUpDueLedger,
    ingest_local_status_exports,
)


BASE = datetime(2030, 1, 1, 12, tzinfo=timezone.utc)
MODEL = hashlib.sha256(b"model-v1").hexdigest()
DATA = hashlib.sha256(b"training-data-v1").hexdigest()
BASELINE = hashlib.sha256(b"baseline-policy").hexdigest()
CANDIDATE = hashlib.sha256(b"candidate-policy").hexdigest()
FACTS = hashlib.sha256(b"approved-candidate-facts").hexdigest()
STRATEGY = hashlib.sha256(b"strategy").hexdigest()
LOCKED_SNAPSHOT = hashlib.sha256(b"locked-snapshot").hexdigest()
HOLDOUT_SNAPSHOT = hashlib.sha256(b"holdout-snapshot").hexdigest()


def _binding(application_id: str) -> ApplicationReceiptBinding:
    return ApplicationReceiptBinding(
        application_id=application_id,
        job_key=f"job:{application_id}",
        employer_key="employer",
        receipt_sha256=hashlib.sha256(f"receipt:{application_id}".encode()).hexdigest(),
        released_application_sha256=hashlib.sha256(
            f"release:{application_id}".encode()
        ).hexdigest(),
        release_manifest_sha256=hashlib.sha256(
            f"manifest:{application_id}".encode()
        ).hexdigest(),
        receipt_observed_at=BASE - timedelta(days=1),
    )


def _status(
    root: Path,
    binding: ApplicationReceiptBinding,
    status: str | None,
    *,
    observed_at: datetime = BASE + timedelta(days=2),
):
    policy = EmployerFollowUpPolicy(
        employer_key="employer",
        policy_id="fixture-follow-up",
        version="v1",
        delay_seconds_by_state={
            PipelineState.RECEIPT_CONFIRMED: 86_400,
            PipelineState.SCREENING: 86_400,
            PipelineState.INTERVIEW: 86_400,
        },
    )
    source_paths: list[str] = []
    if status is not None:
        filename = f"{binding.application_id}-{hashlib.sha256(status.encode()).hexdigest()[:8]}.json"
        document = {
            "schema_version": "jaa-status-export-v1",
            "application_id": binding.application_id,
            "job_key": binding.job_key,
            "receipt_sha256": binding.receipt_sha256,
            "source_kind": "official_portal_export",
            "events": [
                {
                    "event_id": f"event:{binding.application_id}:{status.replace(' ', '_')}",
                    "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
                    "status": status,
                }
            ],
        }
        (root / filename).write_text(json.dumps(document), encoding="utf-8")
        source_paths.append(filename)
    return ingest_local_status_exports(
        source_paths=source_paths,
        allowed_root=root,
        binding=binding,
        follow_up_policy=policy,
        follow_up_ledger=FollowUpDueLedger(root / "follow-up.sqlite3"),
    )


def _predict(
    ledger: OutcomeFeedbackLedger,
    binding: ApplicationReceiptBinding,
    *,
    policy: str = BASELINE,
    probability: int = 6_000,
    cohort_id: str = "cohort:locked",
    cohort_kind: str = "locked",
    snapshot: str = LOCKED_SNAPSHOT,
    predicted_at: datetime = BASE,
    data_through: datetime | None = None,
    experiment=None,
):
    return ledger.record_prediction(
        binding=binding,
        candidate_facts_sha256=FACTS,
        predictor_kind="configured_model",
        predictor_id="predictor:operational",
        predictor_version="v1",
        model_sha256=MODEL,
        data_sha256=DATA,
        predictor_policy_sha256=policy,
        strategy_sha256=STRATEGY,
        cohort_id=cohort_id,
        cohort_kind=cohort_kind,
        cohort_snapshot_sha256=snapshot,
        target_state=PipelineState.INTERVIEW,
        probability_bp=probability,
        data_observed_through=data_through or predicted_at - timedelta(seconds=1),
        predicted_at=predicted_at,
        horizon_at=predicted_at + timedelta(days=30),
        experiment=experiment,
    )


def test_prediction_is_durable_pre_outcome_and_hash_bound(tmp_path: Path) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    prediction = _predict(ledger, _binding("application:one"))

    assert prediction.model_sha256 == MODEL
    assert prediction.data_sha256 == DATA
    assert prediction.candidate_facts_sha256 == FACTS
    assert prediction.cohort_snapshot_sha256 == LOCKED_SNAPSHOT
    assert prediction.manual_prediction is False
    assert prediction.policy_promotion_authority is False
    assert ledger.counts() == {
        "predictions": 1,
        "source_events": 0,
        "outcomes": 0,
        "evaluations": 0,
    }

    with sqlite3.connect(ledger.path) as connection, pytest.raises(
        sqlite3.IntegrityError, match="immutable"
    ):
        connection.execute("UPDATE predictions SET policy_sha256='forged'")


def test_source_backed_progression_scores_and_calibrates(tmp_path: Path) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    binding = _binding("application:progress")
    prediction = _predict(ledger, binding, probability=7_000)
    status = _status(tmp_path, binding, "interview requested")

    outcome = ledger.score_status(
        prediction_id=prediction.prediction_id,
        status=status,
        current_candidate_facts_sha256=FACTS,
        as_of=BASE + timedelta(days=2),
    )
    assert outcome.outcome_status == "progressed"
    assert outcome.actual_bp == 10_000
    assert outcome.squared_error_bp == 900
    assert outcome.source_event_sha256s == (status.events[0].event_sha256,)
    assert outcome.source_file_sha256s
    assert outcome.policy_promotion_authority is False

    summary = ledger.calibration_summary(
        predictor_policy_sha256=BASELINE,
        model_sha256=MODEL,
        data_sha256=DATA,
        cohort_id="cohort:locked",
        cohort_kind="locked",
        cohort_snapshot_sha256=LOCKED_SNAPSHOT,
    )
    assert summary.resolved_count == 1
    assert summary.censored_count == 0
    assert summary.mean_brier_bp == 900
    assert summary.calibration_bins == ((7_000, 1, 7_000, 10_000),)
    assert summary.policy_promotion_authority is False


def test_explicit_rejection_and_silence_censor_are_distinct(tmp_path: Path) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    rejected_binding = _binding("application:rejected")
    silent_binding = _binding("application:silent")
    rejected = _predict(ledger, rejected_binding)
    silent = _predict(ledger, silent_binding)

    rejection = ledger.score_status(
        prediction_id=rejected.prediction_id,
        status=_status(tmp_path, rejected_binding, "rejected by employer"),
        current_candidate_facts_sha256=FACTS,
        as_of=BASE + timedelta(days=2),
    )
    censor = ledger.score_status(
        prediction_id=silent.prediction_id,
        status=_status(tmp_path, silent_binding, None),
        current_candidate_facts_sha256=FACTS,
        as_of=BASE + timedelta(days=31),
    )

    assert rejection.outcome_status == "explicit_rejection"
    assert rejection.actual_bp == 0
    assert rejection.outcome_attribution == "source_backed_employer_rejection"
    assert censor.outcome_status == "censored"
    assert censor.actual_bp is None
    assert censor.squared_error_bp is None
    assert censor.outcome_attribution == "censored_silence_not_rejection"
    assert censor.source_event_sha256s == ()


def test_post_hoc_prediction_and_existing_event_prediction_fail_closed(tmp_path: Path) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    binding = _binding("application:post-hoc")
    prediction = _predict(ledger, binding, predicted_at=BASE + timedelta(days=3))
    status = _status(tmp_path, binding, "interview requested")
    with pytest.raises(PredictionOrderError, match="post-hoc"):
        ledger.score_status(
            prediction_id=prediction.prediction_id,
            status=status,
            current_candidate_facts_sha256=FACTS,
            as_of=BASE + timedelta(days=4),
        )

    clean = _binding("application:event-first")
    first = _predict(ledger, clean)
    ledger.score_status(
        prediction_id=first.prediction_id,
        status=_status(tmp_path, clean, "under review"),
        current_candidate_facts_sha256=FACTS,
        as_of=BASE + timedelta(days=31),
    )
    with pytest.raises(PredictionOrderError, match="outside the prediction data cutoff"):
        _predict(ledger, clean, policy=CANDIDATE)


def test_candidate_fact_change_and_evidence_leakage_are_rejected(tmp_path: Path) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    binding = _binding("application:security")
    prediction = _predict(ledger, binding)
    status = _status(tmp_path, binding, "interview requested")
    with pytest.raises(OutcomeEvidenceError, match="candidate fact"):
        ledger.score_status(
            prediction_id=prediction.prediction_id,
            status=status,
            current_candidate_facts_sha256="f" * 64,
            as_of=BASE + timedelta(days=2),
        )

    source_hash = status.events[0].sources[0].source_sha256
    leakage_binding = _binding("application:leakage")
    leaked = ledger.record_prediction(
        binding=leakage_binding,
        candidate_facts_sha256=FACTS,
        predictor_kind="configured_model",
        predictor_id="predictor:operational",
        predictor_version="v1",
        model_sha256=MODEL,
        data_sha256=source_hash,
        predictor_policy_sha256=BASELINE,
        strategy_sha256=STRATEGY,
        cohort_id="cohort:locked",
        cohort_kind="locked",
        cohort_snapshot_sha256=LOCKED_SNAPSHOT,
        target_state=PipelineState.INTERVIEW,
        probability_bp=5_000,
        data_observed_through=BASE - timedelta(seconds=1),
        predicted_at=BASE,
        horizon_at=BASE + timedelta(days=30),
    )
    leaked_status = _status(tmp_path, leakage_binding, "interview requested")
    # Rebind the prediction data hash to this application's actual source hash
    # using a fresh ledger/prediction to test exact evidence leakage.
    leak_ledger = OutcomeFeedbackLedger(tmp_path / "leak.sqlite3")
    exact = leak_ledger.record_prediction(
        binding=leakage_binding,
        candidate_facts_sha256=FACTS,
        predictor_kind="configured_model",
        predictor_id="predictor:operational",
        predictor_version="v1",
        model_sha256=MODEL,
        data_sha256=leaked_status.events[0].sources[0].source_sha256,
        predictor_policy_sha256=BASELINE,
        strategy_sha256=STRATEGY,
        cohort_id="cohort:locked",
        cohort_kind="locked",
        cohort_snapshot_sha256=LOCKED_SNAPSHOT,
        target_state=PipelineState.INTERVIEW,
        probability_bp=5_000,
        data_observed_through=BASE - timedelta(seconds=1),
        predicted_at=BASE,
        horizon_at=BASE + timedelta(days=30),
    )
    assert leaked.data_sha256 == source_hash
    with pytest.raises(OutcomeEvidenceError, match="leak"):
        leak_ledger.score_status(
            prediction_id=exact.prediction_id,
            status=leaked_status,
            current_candidate_facts_sha256=FACTS,
            as_of=BASE + timedelta(days=2),
        )


def test_experiment_assignment_is_single_variable_deterministic_and_receipted(
    tmp_path: Path,
) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    experiment = compile_strategy_experiment(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        experiment_name="positioning",
        variable_names=("positioning_strategy",),
        baseline_value_sha256=hashlib.sha256(b"old").hexdigest(),
        treatment_value_sha256=hashlib.sha256(b"new").hexdigest(),
        assignment_policy_sha256=hashlib.sha256(b"assignment-policy").hexdigest(),
        created_at=BASE - timedelta(days=1),
    )
    first = _predict(ledger, _binding("application:experiment"), experiment=experiment)
    retry_ledger = OutcomeFeedbackLedger(tmp_path / "retry.sqlite3")
    second = _predict(
        retry_ledger, _binding("application:experiment"), experiment=experiment
    )
    assert first.experiment_variable == "positioning_strategy"
    assert first.experiment_arm in {"baseline", "treatment"}
    assert first.experiment_arm == second.experiment_arm
    assert first.assignment_receipt_sha256 == second.assignment_receipt_sha256

    with pytest.raises(ValueError, match="exactly one"):
        compile_strategy_experiment(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            experiment_name="confounded",
            variable_names=("positioning", "cv_template"),
            baseline_value_sha256=hashlib.sha256(b"one").hexdigest(),
            treatment_value_sha256=hashlib.sha256(b"two").hexdigest(),
            assignment_policy_sha256=hashlib.sha256(b"assignment").hexdigest(),
            created_at=BASE - timedelta(days=1),
        )


def test_duplicate_or_forged_status_result_fails_closed(tmp_path: Path) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    binding = _binding("application:forged")
    _predict(ledger, binding)
    status = _status(tmp_path, binding, "interview requested")
    with pytest.raises(ValueError, match="identity"):
        replace(status, events=(status.events[0], status.events[0]))


def _seed_policy_comparison(ledger: OutcomeFeedbackLedger, root: Path):
    groups = (
        ("locked", "cohort:locked", LOCKED_SNAPSHOT),
        ("holdout", "cohort:holdout", HOLDOUT_SNAPSHOT),
    )
    for kind, cohort_id, snapshot in groups:
        for index in range(2):
            binding = _binding(f"application:{kind}:{index}")
            baseline = _predict(
                ledger,
                binding,
                policy=BASELINE,
                probability=2_000,
                cohort_id=cohort_id,
                cohort_kind=kind,
                snapshot=snapshot,
            )
            candidate = _predict(
                ledger,
                binding,
                policy=CANDIDATE,
                probability=8_000,
                cohort_id=cohort_id,
                cohort_kind=kind,
                snapshot=snapshot,
            )
            status = _status(root, binding, "interview requested")
            for prediction in (baseline, candidate):
                ledger.score_status(
                    prediction_id=prediction.prediction_id,
                    status=status,
                    current_candidate_facts_sha256=FACTS,
                    as_of=BASE + timedelta(days=2),
                )
    def summary(policy: str, kind: str, cohort_id: str, snapshot: str):
        return ledger.calibration_summary(
            predictor_policy_sha256=policy,
            model_sha256=MODEL,
            data_sha256=DATA,
            cohort_id=cohort_id,
            cohort_kind=kind,
            cohort_snapshot_sha256=snapshot,
        )
    return (
        summary(BASELINE, "locked", "cohort:locked", LOCKED_SNAPSHOT),
        summary(CANDIDATE, "locked", "cohort:locked", LOCKED_SNAPSHOT),
        summary(BASELINE, "holdout", "cohort:holdout", HOLDOUT_SNAPSHOT),
        summary(CANDIDATE, "holdout", "cohort:holdout", HOLDOUT_SNAPSHOT),
    )


def test_promotion_is_evaluation_only_and_withheld_without_every_gate(
    tmp_path: Path,
) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    reports = _seed_policy_comparison(ledger, tmp_path)
    evaluation = ledger.evaluate_policy_candidate(
        locked_baseline=reports[0],
        locked_candidate=reports[1],
        holdout_baseline=reports[2],
        holdout_candidate=reports[3],
        rollback_policy_sha256=None,
        upstream_jaa13_certification_sha256=None,
        locked_non_regression_evidence_sha256=None,
        independent_holdout_evidence_sha256=None,
        minimum_resolved=2,
    )
    assert evaluation.eligible_for_independent_review is False
    assert set(evaluation.reason_codes) == {
        "upstream_jaa13_not_certified",
        "rollback_not_bound",
        "locked_non_regression_not_certified",
        "independent_holdout_not_certified",
    }
    assert evaluation.promotion_authority is False
    assert evaluation.applied is False


def test_all_evaluation_gates_only_make_review_eligible_never_apply_policy(
    tmp_path: Path,
) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    reports = _seed_policy_comparison(ledger, tmp_path)
    evaluation = ledger.evaluate_policy_candidate(
        locked_baseline=reports[0],
        locked_candidate=reports[1],
        holdout_baseline=reports[2],
        holdout_candidate=reports[3],
        rollback_policy_sha256=BASELINE,
        upstream_jaa13_certification_sha256=hashlib.sha256(b"jaa13-cert").hexdigest(),
        locked_non_regression_evidence_sha256=hashlib.sha256(b"locked-cert").hexdigest(),
        independent_holdout_evidence_sha256=hashlib.sha256(b"independent-cert").hexdigest(),
        minimum_resolved=2,
    )
    assert evaluation.eligible_for_independent_review is True
    assert evaluation.reason_codes == ("all_evaluation_gates_satisfied",)
    assert evaluation.promotion_authority is False
    assert evaluation.applied is False
    assert ledger.counts()["evaluations"] == 1


def test_unresolved_before_horizon_is_not_scored(tmp_path: Path) -> None:
    ledger = OutcomeFeedbackLedger(tmp_path / "outcomes.sqlite3")
    binding = _binding("application:unresolved")
    prediction = _predict(ledger, binding)
    with pytest.raises(OutcomeEvidenceError, match="unresolved"):
        ledger.score_status(
            prediction_id=prediction.prediction_id,
            status=_status(tmp_path, binding, None),
            current_candidate_facts_sha256=FACTS,
            as_of=BASE + timedelta(days=2),
        )
