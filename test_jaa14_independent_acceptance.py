"""Independent acceptance for the bounded local JAA-14 contract."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from career_automation.models import PipelineState
from career_automation.outcome_feedback import (
    FROZEN_OUTCOME_FEEDBACK_CONTRACT,
    compile_calibration_report,
    compile_strategy_experiment,
    evaluate_policy_candidate,
    record_pre_outcome_prediction,
    score_prediction,
)
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    censor_status_silence,
    classify_status_evidence,
    compile_local_export_evidence,
    compile_status_timeline,
)


PREDICTED_AT = datetime(2030, 1, 1, tzinfo=timezone.utc)
HORIZON_AT = PREDICTED_AT + timedelta(days=30)
BASE_POLICY = hashlib.sha256(b"baseline-policy").hexdigest()
CANDIDATE_POLICY = hashlib.sha256(b"candidate-policy").hexdigest()


def _timeline(application_id: str, codes: tuple[str, ...]):
    observations = []
    for index, code in enumerate(codes):
        raw = compile_local_export_evidence(
            FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
            application_id=application_id,
            job_key=f"job:{application_id}",
            source_kind="local_portal_export",
            source_record_id=f"{application_id}:status:{index}",
            raw_export_bytes=code.encode(),
            observed_at=PREDICTED_AT + timedelta(days=index + 1),
        )
        observations.append(
            classify_status_evidence(
                FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
                raw,
                explicit_status_code=code,
            )
        )
    return compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=application_id,
        job_key=f"job:{application_id}",
        observations=tuple(observations),
    )


def _prediction(
    application_id: str,
    *,
    policy_sha256: str = BASE_POLICY,
    probability_bp: int = 6_000,
    cohort_id: str = "cohort:locked",
    cohort_kind: str = "locked",
    target_state: PipelineState = PipelineState.INTERVIEW,
    experiment=None,
    experiment_arm: str | None = None,
):
    return record_pre_outcome_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        application_id=application_id,
        job_key=f"job:{application_id}",
        predictor_kind="configured_model",
        predictor_id="predictor:fixture",
        predictor_version="1",
        predictor_policy_sha256=policy_sha256,
        input_snapshot_sha256=hashlib.sha256(
            f"input:{application_id}".encode()
        ).hexdigest(),
        strategy_id=hashlib.sha256(
            f"strategy:{application_id}".encode()
        ).hexdigest(),
        cohort_id=cohort_id,
        cohort_kind=cohort_kind,
        target_state=target_state,
        probability_bp=probability_bp,
        predicted_at=PREDICTED_AT,
        horizon_at=HORIZON_AT,
        experiment=experiment,
        experiment_arm=experiment_arm,
    )


def _score(
    application_id: str,
    *,
    policy_sha256: str,
    probability_bp: int,
    cohort_id: str,
    cohort_kind: str,
    progressed: bool,
    experiment=None,
    experiment_arm: str | None = None,
):
    prediction = _prediction(
        application_id,
        policy_sha256=policy_sha256,
        probability_bp=probability_bp,
        cohort_id=cohort_id,
        cohort_kind=cohort_kind,
        experiment=experiment,
        experiment_arm=experiment_arm,
    )
    codes = (
        ("under_review", "interview_requested")
        if progressed
        else ("under_review", "rejected_by_employer")
    )
    return score_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        prediction,
        _timeline(application_id, codes),
    )


def test_contract_binds_upstream_policies_and_withholds_every_mutation() -> None:
    contract = FROZEN_OUTCOME_FEEDBACK_CONTRACT
    document = contract.document()
    assert len(contract.contract_sha256) == 64
    assert document["runtime_learning_authority"] == "withheld"
    assert document["policy_promotion_authority"] == "withheld"
    assert document["gap_mutation_authority"] == "withheld"
    assert document["connector_authority"] == "withheld"
    assert document["dependency_satisfied"] is False
    assert document["certifies_slice"] is False


def test_prediction_is_pre_outcome_receipted_and_experiment_bound() -> None:
    experiment = compile_strategy_experiment(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        experiment_name="positioning experiment",
        variable_names=("positioning_strategy",),
        baseline_value_sha256=hashlib.sha256(b"baseline").hexdigest(),
        treatment_value_sha256=hashlib.sha256(b"treatment").hexdigest(),
        assignment_policy_sha256=hashlib.sha256(b"assignment").hexdigest(),
        created_at=PREDICTED_AT - timedelta(days=1),
    )
    prediction = record_pre_outcome_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        application_id="application:experiment",
        job_key="job:application:experiment",
        predictor_kind="deterministic_policy",
        predictor_id="predictor:fixture",
        predictor_version="1",
        predictor_policy_sha256=BASE_POLICY,
        input_snapshot_sha256=hashlib.sha256(b"input").hexdigest(),
        strategy_id=hashlib.sha256(b"strategy").hexdigest(),
        cohort_id="cohort:experiment",
        cohort_kind="holdout",
        target_state=PipelineState.INTERVIEW,
        probability_bp=6_500,
        predicted_at=PREDICTED_AT,
        horizon_at=HORIZON_AT,
        experiment=experiment,
        experiment_arm="treatment",
    )
    assert prediction.experiment_id == experiment.experiment_id
    assert len(prediction.assignment_receipt_sha256) == 64
    assert prediction.manual_prediction is False
    assert prediction.dependency_satisfied is False
    assert prediction.certifies_slice is False


def test_explicit_progression_rejection_and_silence_are_distinct() -> None:
    progressed = score_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        _prediction("application:progressed"),
        _timeline(
            "application:progressed",
            ("under_review", "interview_requested"),
        ),
    )
    rejected = score_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        _prediction("application:rejected"),
        _timeline(
            "application:rejected",
            ("under_review", "rejected_by_employer"),
        ),
    )
    censored_timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id="application:silent",
        job_key="job:application:silent",
        observations=(),
        censored_silence=(
            censor_status_silence(
                application_id="application:silent",
                job_key="job:application:silent",
                as_of=HORIZON_AT,
            ),
        ),
    )
    censored = score_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        _prediction("application:silent"),
        censored_timeline,
    )
    assert progressed.outcome_status == "progressed"
    assert progressed.actual_bp == 10_000
    assert rejected.outcome_status == "explicit_rejection"
    assert rejected.actual_bp == 0
    assert censored.outcome_status == "censored"
    assert censored.actual_bp is None
    assert censored.squared_error_bp is None


def test_candidate_terminal_states_are_censored_not_negative() -> None:
    for codes in (
        (
            "under_review",
            "interview_requested",
            "final_stage",
            "offer",
            "declined_by_candidate",
        ),
        ("under_review", "withdrawn_by_candidate"),
        ("under_review", "expired"),
    ):
        application_id = f"application:terminal-censor:{codes[-1]}"
        censored = score_prediction(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            _prediction(
                application_id,
                target_state=PipelineState.ACCEPTED,
            ),
            _timeline(application_id, codes),
        )
        assert censored.outcome_status == "censored"
        assert censored.actual_bp is None
        assert censored.squared_error_bp is None
        assert censored.outcome_attribution == "candidate_or_expiry_censor"


def test_calibration_excludes_censoring_from_score_arithmetic() -> None:
    resolved = _score(
        "application:report:resolved",
        policy_sha256=BASE_POLICY,
        probability_bp=7_000,
        cohort_id="cohort:report",
        cohort_kind="holdout",
        progressed=True,
    )
    censored_timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id="application:report:censored",
        job_key="job:application:report:censored",
        observations=(),
        censored_silence=(
            censor_status_silence(
                application_id="application:report:censored",
                job_key="job:application:report:censored",
                as_of=HORIZON_AT,
            ),
        ),
    )
    censored = score_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        _prediction(
            "application:report:censored",
            policy_sha256=BASE_POLICY,
            cohort_id="cohort:report",
            cohort_kind="holdout",
        ),
        censored_timeline,
    )
    report = compile_calibration_report(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        (resolved, censored),
    )
    assert report.scores == (resolved, censored)
    assert report.document()["scores"] == (
        resolved.document(),
        censored.document(),
    )
    assert report.resolved_count == 1
    assert report.censored_count == 1
    assert report.mean_brier_bp == resolved.squared_error_bp
    assert report.policy_promotion_authority == "withheld"


def test_policy_candidate_requires_locked_non_regression_and_holdout_gain() -> None:
    experiment = compile_strategy_experiment(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        experiment_name="promotion experiment",
        variable_names=("positioning_strategy",),
        baseline_value_sha256=hashlib.sha256(b"baseline").hexdigest(),
        treatment_value_sha256=hashlib.sha256(b"treatment").hexdigest(),
        assignment_policy_sha256=hashlib.sha256(b"assignment").hexdigest(),
        created_at=PREDICTED_AT - timedelta(days=1),
    )

    def report(
        member_prefix: str,
        policy: str,
        probability: int,
        cohort_id: str,
        cohort_kind: str,
        experiment_arm: str,
    ):
        return compile_calibration_report(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            tuple(
                _score(
                    f"application:{member_prefix}:{index}",
                    policy_sha256=policy,
                    probability_bp=probability,
                    cohort_id=cohort_id,
                    cohort_kind=cohort_kind,
                    progressed=True,
                    experiment=experiment,
                    experiment_arm=experiment_arm,
                )
                for index in range(2)
            ),
        )

    locked_baseline = report(
        "locked-members",
        BASE_POLICY,
        6_000,
        "cohort:locked",
        "locked",
        "baseline",
    )
    locked_candidate = report(
        "locked-members",
        CANDIDATE_POLICY,
        6_000,
        "cohort:locked",
        "locked",
        "treatment",
    )
    holdout_baseline = report(
        "holdout-members",
        BASE_POLICY,
        5_000,
        "cohort:holdout",
        "holdout",
        "baseline",
    )
    holdout_candidate = report(
        "holdout-members",
        CANDIDATE_POLICY,
        8_000,
        "cohort:holdout",
        "holdout",
        "treatment",
    )
    evaluation = evaluate_policy_candidate(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        locked_baseline=locked_baseline,
        locked_candidate=locked_candidate,
        holdout_baseline=holdout_baseline,
        holdout_candidate=holdout_candidate,
    )
    assert evaluation.locked_baseline is locked_baseline
    assert evaluation.locked_candidate is locked_candidate
    assert evaluation.holdout_baseline is holdout_baseline
    assert evaluation.holdout_candidate is holdout_candidate
    assert evaluation.document()["locked_baseline"] == (
        locked_baseline.document()
    )
    assert evaluation.eligible_for_review is True
    assert evaluation.reason_codes == (
        "locked_non_regression",
        "holdout_improvement",
    )
    assert evaluation.rollback_policy_sha256 == BASE_POLICY
    assert evaluation.promotion_authority == "withheld"
    assert evaluation.applied is False
    assert evaluation.dependency_satisfied is False
