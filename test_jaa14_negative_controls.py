"""Adversarial controls for the bounded local JAA-14 contract."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import timedelta

import pytest

from career_automation.models import PipelineState
from career_automation.outcome_feedback import (
    FROZEN_OUTCOME_FEEDBACK_CONTRACT,
    OutcomeFeedbackContract,
    compile_calibration_report,
    compile_strategy_experiment,
    evaluate_policy_candidate,
    record_pre_outcome_prediction,
    score_prediction,
)
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    compile_status_timeline,
)
from test_jaa14_independent_acceptance import (
    BASE_POLICY,
    CANDIDATE_POLICY,
    HORIZON_AT,
    PREDICTED_AT,
    _prediction,
    _score,
    _timeline,
)


def test_noncanonical_contract_cannot_claim_mutation_authority() -> None:
    contract = FROZEN_OUTCOME_FEEDBACK_CONTRACT
    with pytest.raises(ValueError, match="differs from accepted"):
        OutcomeFeedbackContract(
            upstream_status_contract_sha256="0" * 64,
            opportunity_policy_hash=contract.opportunity_policy_hash,
            gap_policy_sha256=contract.gap_policy_sha256,
            prediction_policy_sha256=contract.prediction_policy_sha256,
            scoring_policy_sha256=contract.scoring_policy_sha256,
            experiment_policy_sha256=contract.experiment_policy_sha256,
            promotion_policy_sha256=contract.promotion_policy_sha256,
        )
    with pytest.raises(ValueError, match="cannot mutate or certify"):
        replace(contract, policy_promotion_authority="granted")


def test_manual_unreceipted_or_post_horizon_prediction_fails() -> None:
    prediction = _prediction("application:tamper")
    with pytest.raises(ValueError, match="manual or certify"):
        replace(prediction, manual_prediction=True)
    with pytest.raises(ValueError, match="predictor receipt"):
        replace(prediction, predictor_receipt_sha256="not-a-hash")
    with pytest.raises(ValueError, match="horizon must follow"):
        replace(prediction, horizon_at=prediction.predicted_at)
    with pytest.raises(ValueError, match="receipt differs from output"):
        replace(prediction, probability_bp=9_999)


def test_prediction_must_predate_every_resolving_evidence_item() -> None:
    timeline = _timeline(
        "application:post-hoc",
        ("under_review", "interview_requested"),
    )
    post_hoc = record_pre_outcome_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        application_id="application:post-hoc",
        job_key="job:application:post-hoc",
        predictor_kind="configured_model",
        predictor_id="predictor:fixture",
        predictor_version="1",
        predictor_policy_sha256=BASE_POLICY,
        input_snapshot_sha256=hashlib.sha256(b"input").hexdigest(),
        strategy_id=hashlib.sha256(b"strategy").hexdigest(),
        cohort_id="cohort:locked",
        cohort_kind="locked",
        target_state=PipelineState.INTERVIEW,
        probability_bp=5_000,
        predicted_at=PREDICTED_AT + timedelta(days=1),
        horizon_at=HORIZON_AT,
    )
    with pytest.raises(ValueError, match="predate every resolving"):
        score_prediction(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            post_hoc,
            timeline,
        )


def test_prediction_and_timeline_cannot_mix_applications() -> None:
    with pytest.raises(ValueError, match="different applications"):
        score_prediction(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            _prediction("application:one"),
            _timeline(
                "application:two",
                ("under_review", "interview_requested"),
            ),
        )


def test_unresolved_timeline_requires_real_horizon_censor() -> None:
    timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id="application:unresolved",
        job_key="job:application:unresolved",
        observations=(),
    )
    with pytest.raises(ValueError, match="censor evidence is required"):
        score_prediction(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            _prediction("application:unresolved"),
            timeline,
        )


def test_two_variable_or_identical_arm_experiment_is_rejected() -> None:
    base = {
        "contract": FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        "experiment_name": "bad experiment",
        "baseline_value_sha256": hashlib.sha256(b"baseline").hexdigest(),
        "treatment_value_sha256": hashlib.sha256(b"treatment").hexdigest(),
        "assignment_policy_sha256": hashlib.sha256(b"assignment").hexdigest(),
        "created_at": PREDICTED_AT - timedelta(days=1),
    }
    with pytest.raises(ValueError, match="exactly one"):
        compile_strategy_experiment(
            **base,
            variable_names=("positioning", "document"),
        )
    with pytest.raises(ValueError, match="arms must differ"):
        compile_strategy_experiment(
            **{
                **base,
                "treatment_value_sha256": base["baseline_value_sha256"],
            },
            variable_names=("positioning",),
        )


def test_experiment_must_predate_prediction_and_bind_an_arm() -> None:
    experiment = compile_strategy_experiment(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        experiment_name="fixture experiment",
        variable_names=("positioning",),
        baseline_value_sha256=hashlib.sha256(b"baseline").hexdigest(),
        treatment_value_sha256=hashlib.sha256(b"treatment").hexdigest(),
        assignment_policy_sha256=hashlib.sha256(b"assignment").hexdigest(),
        created_at=PREDICTED_AT,
    )
    kwargs = {
        "contract": FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        "application_id": "application:experiment-negative",
        "job_key": "job:application:experiment-negative",
        "predictor_kind": "configured_model",
        "predictor_id": "predictor:fixture",
        "predictor_version": "1",
        "predictor_policy_sha256": BASE_POLICY,
        "input_snapshot_sha256": hashlib.sha256(b"input").hexdigest(),
        "strategy_id": hashlib.sha256(b"strategy").hexdigest(),
        "cohort_id": "cohort:holdout",
        "cohort_kind": "holdout",
        "target_state": PipelineState.INTERVIEW,
        "probability_bp": 5_000,
        "predicted_at": PREDICTED_AT,
        "horizon_at": HORIZON_AT,
    }
    with pytest.raises(ValueError, match="exist before prediction"):
        record_pre_outcome_prediction(
            **kwargs,
            experiment=experiment,
            experiment_arm="baseline",
        )
    with pytest.raises(ValueError, match="arm requires"):
        record_pre_outcome_prediction(
            **kwargs,
            experiment_arm="baseline",
        )
    accepted_created_at = (PREDICTED_AT - timedelta(days=1)).isoformat()
    body = experiment.document(include_identity=False)
    body["created_at"] = accepted_created_at
    accepted_experiment = type(experiment)(**{
        **vars(experiment),
        "created_at": accepted_created_at,
        "experiment_id": hashlib.sha256(
            json.dumps(
                body,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest(),
    })
    prediction = record_pre_outcome_prediction(
        **kwargs,
        experiment=accepted_experiment,
        experiment_arm="baseline",
    )
    with pytest.raises(ValueError, match="assignment receipt is invalid"):
        replace(prediction, assignment_receipt_sha256="0" * 64)


def test_calibration_report_rejects_duplicates_and_mixed_cohorts() -> None:
    one = _score(
        "application:report-one",
        policy_sha256=BASE_POLICY,
        probability_bp=5_000,
        cohort_id="cohort:one",
        cohort_kind="locked",
        progressed=True,
    )
    two = _score(
        "application:report-two",
        policy_sha256=BASE_POLICY,
        probability_bp=5_000,
        cohort_id="cohort:two",
        cohort_kind="locked",
        progressed=True,
    )
    with pytest.raises(ValueError, match="identities must be unique"):
        compile_calibration_report(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            (one, one),
        )
    with pytest.raises(ValueError, match="mix policy, cohort or experiment"):
        compile_calibration_report(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            (one, two),
        )


def _report(
    member_prefix: str,
    policy: str,
    probability: int,
    cohort_id: str,
    cohort_kind: str,
    experiment,
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


def test_promotion_requires_same_members_and_one_controlled_experiment() -> None:
    experiment = compile_strategy_experiment(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        experiment_name="membership experiment",
        variable_names=("positioning",),
        baseline_value_sha256=hashlib.sha256(b"baseline").hexdigest(),
        treatment_value_sha256=hashlib.sha256(b"treatment").hexdigest(),
        assignment_policy_sha256=hashlib.sha256(b"assignment").hexdigest(),
        created_at=PREDICTED_AT - timedelta(days=1),
    )
    aligned = {
        "holdout_baseline": _report(
            "holdout-members",
            BASE_POLICY,
            5_000,
            "cohort:holdout",
            "holdout",
            experiment,
            "baseline",
        ),
        "holdout_candidate": _report(
            "holdout-members",
            CANDIDATE_POLICY,
            8_000,
            "cohort:holdout",
            "holdout",
            experiment,
            "treatment",
        ),
    }
    with pytest.raises(ValueError, match="identical cohort membership"):
        evaluate_policy_candidate(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            locked_baseline=_report(
                "locked-baseline-members",
                BASE_POLICY,
                6_000,
                "cohort:locked",
                "locked",
                experiment,
                "baseline",
            ),
            locked_candidate=_report(
                "locked-candidate-members",
                CANDIDATE_POLICY,
                6_000,
                "cohort:locked",
                "locked",
                experiment,
                "treatment",
            ),
            **aligned,
        )
    with pytest.raises(ValueError, match="controlled experiment"):
        evaluate_policy_candidate(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT,
            locked_baseline=_report(
                "locked-members-no-experiment",
                BASE_POLICY,
                6_000,
                "cohort:locked-no-experiment",
                "locked",
                None,
                None,
            ),
            locked_candidate=_report(
                "locked-members-no-experiment",
                CANDIDATE_POLICY,
                6_000,
                "cohort:locked-no-experiment",
                "locked",
                None,
                None,
            ),
            holdout_baseline=_report(
                "holdout-members-no-experiment",
                BASE_POLICY,
                5_000,
                "cohort:holdout-no-experiment",
                "holdout",
                None,
                None,
            ),
            holdout_candidate=_report(
                "holdout-members-no-experiment",
                CANDIDATE_POLICY,
                8_000,
                "cohort:holdout-no-experiment",
                "holdout",
                None,
                None,
            ),
        )


def test_locked_regression_or_flat_holdout_cannot_be_review_eligible() -> None:
    experiment = compile_strategy_experiment(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        experiment_name="negative promotion experiment",
        variable_names=("positioning",),
        baseline_value_sha256=hashlib.sha256(b"baseline").hexdigest(),
        treatment_value_sha256=hashlib.sha256(b"treatment").hexdigest(),
        assignment_policy_sha256=hashlib.sha256(b"assignment").hexdigest(),
        created_at=PREDICTED_AT - timedelta(days=1),
    )
    evaluation = evaluate_policy_candidate(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        locked_baseline=_report(
            "locked-members",
            BASE_POLICY,
            8_000,
            "cohort:locked",
            "locked",
            experiment,
            "baseline",
        ),
        locked_candidate=_report(
            "locked-members",
            CANDIDATE_POLICY,
            4_000,
            "cohort:locked",
            "locked",
            experiment,
            "treatment",
        ),
        holdout_baseline=_report(
            "holdout-members",
            BASE_POLICY,
            7_000,
            "cohort:holdout",
            "holdout",
            experiment,
            "baseline",
        ),
        holdout_candidate=_report(
            "holdout-members",
            CANDIDATE_POLICY,
            7_000,
            "cohort:holdout",
            "holdout",
            experiment,
            "treatment",
        ),
    )
    assert evaluation.eligible_for_review is False
    assert evaluation.reason_codes == (
        "locked_regression",
        "holdout_not_improved",
    )
    assert evaluation.promotion_authority == "withheld"
    assert evaluation.applied is False


def test_promotion_evaluation_cannot_apply_or_claim_certification() -> None:
    experiment = compile_strategy_experiment(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        experiment_name="apply promotion experiment",
        variable_names=("positioning",),
        baseline_value_sha256=hashlib.sha256(b"baseline").hexdigest(),
        treatment_value_sha256=hashlib.sha256(b"treatment").hexdigest(),
        assignment_policy_sha256=hashlib.sha256(b"assignment").hexdigest(),
        created_at=PREDICTED_AT - timedelta(days=1),
    )
    evaluation = evaluate_policy_candidate(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        locked_baseline=_report(
            "locked-members-apply",
            BASE_POLICY,
            6_000,
            "cohort:locked-apply",
            "locked",
            experiment,
            "baseline",
        ),
        locked_candidate=_report(
            "locked-members-apply",
            CANDIDATE_POLICY,
            7_000,
            "cohort:locked-apply",
            "locked",
            experiment,
            "treatment",
        ),
        holdout_baseline=_report(
            "holdout-members-apply",
            BASE_POLICY,
            5_000,
            "cohort:holdout-apply",
            "holdout",
            experiment,
            "baseline",
        ),
        holdout_candidate=_report(
            "holdout-members-apply",
            CANDIDATE_POLICY,
            8_000,
            "cohort:holdout-apply",
            "holdout",
            experiment,
            "treatment",
        ),
    )
    for field, value in (
        ("promotion_authority", "granted"),
        ("applied", True),
        ("dependency_satisfied", True),
        ("certifies_slice", True),
    ):
        with pytest.raises(ValueError, match="cannot apply policy"):
            replace(evaluation, **{field: value})


def test_product_module_has_no_runtime_or_external_action_capability() -> None:
    from career_automation import outcome_feedback

    source = outcome_feedback.__file__
    text = open(source, encoding="utf-8").read().casefold()
    for forbidden in (
        "requests.",
        "urllib.request",
        "httpx",
        "aiohttp",
        "socket",
        "playwright",
        "subprocess",
        "sqlite3",
        "policy_store",
        "send_message",
        "candidate_graph",
    ):
        assert forbidden not in text
