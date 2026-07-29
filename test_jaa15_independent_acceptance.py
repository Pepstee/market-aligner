"""Independent acceptance for the bounded local JAA-15 contract."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from career_automation.models import PipelineState
from career_automation.outcome_feedback import (
    FROZEN_OUTCOME_FEEDBACK_CONTRACT,
    record_pre_outcome_prediction,
)
from career_automation.source_expansion import (
    FROZEN_SOURCE_EXPANSION_CONTRACT,
    compile_adapter_candidate,
    compile_adapter_measurement,
    evaluate_adapter_candidate,
    rank_expansion_candidates,
    record_adapter_evidence_reference,
    record_adapter_quality_snapshot,
    record_adapter_value_observation,
)


WINDOW_START = datetime(2030, 1, 1, tzinfo=timezone.utc)
WINDOW_END = datetime(2030, 2, 1, tzinfo=timezone.utc)
EVIDENCE_AT = datetime(2030, 2, 2, tzinfo=timezone.utc)
PREDICTOR_POLICY = hashlib.sha256(b"jaa15-predictor-policy").hexdigest()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _candidate(
    adapter_id: str,
    *,
    route_status: str = "supported",
    version: str = "v2",
):
    return compile_adapter_candidate(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        adapter_id=adapter_id,
        adapter_version=version,
        capability_kind="source_and_route",
        route_status=route_status,
        workflow_sha256=_hash(f"{adapter_id}:workflow:{version}"),
        extraction_policy_sha256=_hash(
            f"{adapter_id}:extraction:{version}"
        ),
        selector_policy_sha256=_hash(f"{adapter_id}:selectors:{version}"),
        route_policy_sha256=_hash(f"{adapter_id}:route:{version}"),
        eligibility_policy_sha256=_hash(
            f"{adapter_id}:eligibility:{version}"
        ),
        payroll_policy_sha256=_hash(f"{adapter_id}:payroll:{version}"),
        rollback_adapter_version="v1",
        country_scopes=("GB",),
        employer_scopes=("employer:all",),
    )


def _observation(
    candidate,
    index: int,
    *,
    worthwhile: bool = True,
    probability_bp: int = 6_000,
):
    job_key = f"job:{candidate.adapter_id}:{index}"
    prediction = record_pre_outcome_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        application_id=f"application:{candidate.adapter_id}:{index}",
        job_key=job_key,
        predictor_kind="configured_model",
        predictor_id="predictor:jaa15-fixture",
        predictor_version="1",
        predictor_policy_sha256=PREDICTOR_POLICY,
        input_snapshot_sha256=_hash(f"input:{candidate.adapter_id}:{index}"),
        strategy_id=_hash(f"strategy:{candidate.adapter_id}:{index}"),
        cohort_id="cohort:jaa15-locked",
        cohort_kind="locked",
        target_state=PipelineState.INTERVIEW,
        probability_bp=probability_bp,
        predicted_at=WINDOW_START + timedelta(days=index + 1),
        horizon_at=WINDOW_END + timedelta(days=30),
    )
    return record_adapter_value_observation(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        candidate,
        prediction,
        source_snapshot_sha256=_hash(
            f"source:{candidate.adapter_id}:{index}"
        ),
        viability_receipt_sha256=_hash(
            f"viability:{candidate.adapter_id}:{index}"
        ),
        worthwhile_vacancy=worthwhile,
        measurement_window_start=WINDOW_START,
        measurement_window_end=WINDOW_END,
    )


def _measurement(candidate, *, cost: int = 10, friction: int = 5):
    return compile_adapter_measurement(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        candidate,
        (
            _observation(candidate, 0, probability_bp=7_000),
            _observation(candidate, 1, probability_bp=6_000),
            _observation(candidate, 2, worthwhile=False),
        ),
        cohort_id="cohort:jaa15-locked",
        implementation_cost_points=cost,
        operational_friction_points=friction,
    )


def _evidence(candidate, *, include_real: bool = True):
    kinds = ["fixture_runtime", "independent_test"]
    if include_real:
        kinds.append("real_runtime")
    return tuple(
        record_adapter_evidence_reference(
            FROZEN_SOURCE_EXPANSION_CONTRACT,
            candidate,
            evidence_kind=kind,
            evidence_sha256=_hash(
                f"{candidate.adapter_id}:{candidate.adapter_version}:{kind}"
            ),
            observed_at=EVIDENCE_AT,
        )
        for kind in kinds
    )


def _qualities(
    candidate,
    *,
    baseline_freshness: int = 9_500,
    candidate_freshness: int = 9_800,
    candidate_receipt_violations: int = 0,
):
    sample_ids = tuple(_hash(f"quality:{index}") for index in range(3))
    baseline = record_adapter_quality_snapshot(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        candidate,
        phase="baseline",
        sample_ids=sample_ids,
        freshness_pass_rate_bp=baseline_freshness,
    )
    current = record_adapter_quality_snapshot(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        candidate,
        phase="candidate",
        sample_ids=sample_ids,
        freshness_pass_rate_bp=candidate_freshness,
        receipt_integrity_violations=candidate_receipt_violations,
    )
    return baseline, current


def _evaluation(
    candidate,
    *,
    include_real: bool = True,
    baseline_freshness: int = 9_500,
    candidate_freshness: int = 9_800,
    candidate_receipt_violations: int = 0,
    cost: int = 10,
    friction: int = 5,
):
    baseline, current = _qualities(
        candidate,
        baseline_freshness=baseline_freshness,
        candidate_freshness=candidate_freshness,
        candidate_receipt_violations=candidate_receipt_violations,
    )
    return evaluate_adapter_candidate(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        candidate,
        _measurement(candidate, cost=cost, friction=friction),
        _evidence(candidate, include_real=include_real),
        baseline_quality=baseline,
        candidate_quality=current,
    )


def test_contract_binds_exact_inputs_and_withholds_external_authority() -> None:
    contract = FROZEN_SOURCE_EXPANSION_CONTRACT
    document = contract.document()
    assert len(contract.contract_sha256) == 64
    assert document["crawl_authority"] == "withheld"
    assert document["adapter_activation_authority"] == "withheld"
    assert document["connector_authority"] == "withheld"
    assert document["submission_authority"] == "withheld"
    assert document["production_certification"] == "withheld"
    assert document["dependency_satisfied"] is False
    assert document["certifies_slice"] is False


def test_candidate_binds_versioned_workflow_policies_and_rollback() -> None:
    candidate = _candidate("adapter:measured")
    assert candidate.adapter_version == "v2"
    assert candidate.rollback_adapter_version == "v1"
    assert candidate.country_scopes == ("GB",)
    assert len(candidate.workflow_sha256) == 64
    assert len(candidate.selector_policy_sha256) == 64
    assert len(candidate.eligibility_policy_sha256) == 64
    assert len(candidate.payroll_policy_sha256) == 64
    assert candidate.activation_authority == "withheld"


def test_measurement_uses_worthwhile_vacancies_predictions_cost_and_friction() -> None:
    candidate = _candidate("adapter:value")
    measurement = _measurement(candidate, cost=10, friction=5)
    assert measurement.sample_count == 3
    assert measurement.worthwhile_vacancies == 2
    assert measurement.expected_interviews_bp == 13_000
    assert measurement.value_score == 31_500
    assert len(measurement.observation_ids) == 3
    assert measurement.activation_authority == "withheld"


def test_complete_adapter_gate_is_review_only_and_preserves_quality() -> None:
    candidate = _candidate("adapter:eligible")
    evaluation = _evaluation(candidate)
    assert evaluation.eligible_for_review is True
    assert evaluation.reason_codes == ()
    assert evaluation.evidence_kinds == (
        "fixture_runtime",
        "independent_test",
        "real_runtime",
    )
    assert evaluation.candidate == candidate
    assert evaluation.measurement.candidate_id == candidate.candidate_id
    assert tuple(
        row.evidence_id for row in evaluation.evidence
    ) == evaluation.evidence_ids
    assert evaluation.baseline_quality.phase == "baseline"
    assert evaluation.candidate_quality.phase == "candidate"
    assert evaluation.rollback_adapter_version == "v1"
    assert evaluation.activation_authority == "withheld"
    assert evaluation.production_certification == "withheld"
    assert evaluation.dependency_satisfied is False
    assert evaluation.certifies_slice is False


def test_portfolio_ranks_value_and_keeps_blocked_routes_visible() -> None:
    eligible = _candidate("adapter:eligible")
    missing_runtime = _candidate("adapter:missing-runtime")
    unsupported = _candidate(
        "adapter:unsupported",
        route_status="unsupported",
    )
    evaluations = (
        _evaluation(missing_runtime, include_real=False, cost=1, friction=1),
        _evaluation(unsupported, cost=1, friction=1),
        _evaluation(eligible, cost=10, friction=5),
    )
    portfolio = rank_expansion_candidates(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        evaluations,
    )
    assert tuple(row.adapter_id for row in portfolio.entries) == (
        "adapter:eligible",
        "adapter:missing-runtime",
        "adapter:unsupported",
    )
    assert tuple(row.status for row in portfolio.entries) == (
        "eligible_for_review",
        "blocked",
        "blocked",
    )
    assert portfolio.entries[1].reason_codes == (
        "missing_real_runtime_evidence",
    )
    assert portfolio.entries[2].reason_codes == ("unsupported_route",)
    assert tuple(
        row.evaluation.evaluation_id for row in portfolio.entries
    ) == tuple(row.evaluation_id for row in portfolio.entries)
    assert portfolio.blocked_candidates_visible is True
    assert portfolio.activation_authority == "withheld"
    assert portfolio.certifies_slice is False


def test_portfolio_rederives_highest_value_first_for_reviewable_entries() -> None:
    lower_value = _evaluation(
        _candidate("adapter:lower-value"),
        cost=100,
        friction=100,
    )
    higher_value = _evaluation(
        _candidate("adapter:higher-value"),
        cost=1,
        friction=1,
    )
    portfolio = rank_expansion_candidates(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        (lower_value, higher_value),
    )

    assert tuple(row.evaluation for row in portfolio.entries) == (
        higher_value,
        lower_value,
    )
    portfolio.verify()
