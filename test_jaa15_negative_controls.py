"""Adversarial controls for the bounded local JAA-15 contract."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from career_automation.models import PipelineState
from career_automation.outcome_feedback import (
    FROZEN_OUTCOME_FEEDBACK_CONTRACT,
    record_pre_outcome_prediction,
)
from career_automation.source_expansion import (
    FROZEN_SOURCE_EXPANSION_CONTRACT,
    SourceExpansionContract,
    compile_adapter_measurement,
    evaluate_adapter_candidate,
    rank_expansion_candidates,
    record_adapter_evidence_reference,
    record_adapter_quality_snapshot,
    record_adapter_value_observation,
)
from test_jaa15_independent_acceptance import (
    EVIDENCE_AT,
    PREDICTOR_POLICY,
    WINDOW_END,
    WINDOW_START,
    _candidate,
    _evidence,
    _evaluation,
    _hash,
    _measurement,
    _observation,
    _qualities,
)


def test_noncanonical_contract_cannot_claim_activation() -> None:
    contract = FROZEN_SOURCE_EXPANSION_CONTRACT
    with pytest.raises(ValueError, match="differs from accepted"):
        SourceExpansionContract(
            **{
                **vars(contract),
                "scrapling_requirements_sha256": "0" * 64,
            }
        )
    with pytest.raises(ValueError, match="cannot activate or certify"):
        replace(contract, adapter_activation_authority="granted")


def test_candidate_requires_distinct_rollback_and_canonical_scopes() -> None:
    candidate = _candidate("adapter:rollback")
    with pytest.raises(ValueError, match="different version"):
        replace(candidate, rollback_adapter_version=candidate.adapter_version)
    with pytest.raises(ValueError, match="unique and sorted"):
        replace(candidate, country_scopes=("GB", "GB"))


def test_candidate_policy_or_identity_tampering_fails() -> None:
    candidate = _candidate("adapter:tamper")
    with pytest.raises(ValueError, match="identity is invalid"):
        replace(
            candidate,
            selector_policy_sha256=hashlib.sha256(
                b"foreign-selector-policy"
            ).hexdigest(),
        )
    with pytest.raises(ValueError, match="cannot crawl or activate"):
        replace(candidate, activation_authority="granted")


def test_value_observation_rejects_post_window_prediction() -> None:
    candidate = _candidate("adapter:post-window")
    observation = _observation(candidate, 0)
    with pytest.raises(ValueError, match="inside the measurement window"):
        replace(
            observation,
            predicted_at=(WINDOW_END + timedelta(seconds=1)).isoformat(),
        )


def test_expected_interviews_require_an_interview_target_prediction() -> None:
    candidate = _candidate("adapter:wrong-target")
    prediction = record_pre_outcome_prediction(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT,
        application_id="application:wrong-target",
        job_key="job:wrong-target",
        predictor_kind="configured_model",
        predictor_id="predictor:jaa15-fixture",
        predictor_version="1",
        predictor_policy_sha256=PREDICTOR_POLICY,
        input_snapshot_sha256=_hash("wrong-target-input"),
        strategy_id=_hash("wrong-target-strategy"),
        cohort_id="cohort:jaa15-locked",
        cohort_kind="locked",
        target_state=PipelineState.OFFER,
        probability_bp=6_000,
        predicted_at=WINDOW_START + timedelta(days=1),
        horizon_at=WINDOW_END + timedelta(days=30),
    )
    with pytest.raises(ValueError, match="interview-target prediction"):
        record_adapter_value_observation(
            FROZEN_SOURCE_EXPANSION_CONTRACT,
            candidate,
            prediction,
            source_snapshot_sha256=_hash("wrong-target-source"),
            viability_receipt_sha256=_hash("wrong-target-viability"),
            worthwhile_vacancy=True,
            measurement_window_start=WINDOW_START,
            measurement_window_end=WINDOW_END,
        )


def test_measurement_rejects_duplicate_and_mixed_adapter_evidence() -> None:
    one = _candidate("adapter:one")
    two = _candidate("adapter:two")
    observation = _observation(one, 0)
    with pytest.raises(ValueError, match="duplicate jobs"):
        compile_adapter_measurement(
            FROZEN_SOURCE_EXPANSION_CONTRACT,
            one,
            (observation, observation),
            cohort_id="cohort:jaa15-locked",
            implementation_cost_points=1,
            operational_friction_points=1,
        )
    with pytest.raises(ValueError, match="mixes adapter candidates"):
        compile_adapter_measurement(
            FROZEN_SOURCE_EXPANSION_CONTRACT,
            one,
            (observation, _observation(two, 1)),
            cohort_id="cohort:jaa15-locked",
            implementation_cost_points=1,
            operational_friction_points=1,
        )


def test_measurement_score_cannot_be_rehashed_to_another_formula() -> None:
    measurement = _measurement(_candidate("adapter:score"))
    with pytest.raises(ValueError, match="differs from ranking policy"):
        replace(
            measurement,
            value_score=measurement.value_score + 1,
            measurement_id=hashlib.sha256(b"forged-measurement").hexdigest(),
        )


def test_adapter_cannot_inherit_another_policy_or_evidence() -> None:
    one = _candidate("adapter:one-policy")
    two = _candidate("adapter:two-policy")
    baseline, current = _qualities(one)
    foreign = record_adapter_evidence_reference(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        two,
        evidence_kind="real_runtime",
        evidence_sha256=_hash("foreign-real-runtime"),
        observed_at=EVIDENCE_AT,
    )
    with pytest.raises(
        ValueError,
        match="another adapter or policy",
    ):
        evaluate_adapter_candidate(
            FROZEN_SOURCE_EXPANSION_CONTRACT,
            one,
            _measurement(one),
            (*_evidence(one, include_real=False), foreign),
            baseline_quality=baseline,
            candidate_quality=current,
        )


def test_adapter_evidence_must_follow_the_measurement_window() -> None:
    candidate = _candidate("adapter:stale-runtime-evidence")
    baseline, current = _qualities(candidate)
    evidence = (
        *_evidence(candidate, include_real=False),
        record_adapter_evidence_reference(
            FROZEN_SOURCE_EXPANSION_CONTRACT,
            candidate,
            evidence_kind="real_runtime",
            evidence_sha256=_hash("stale-real-runtime"),
            observed_at=WINDOW_START,
        ),
    )
    with pytest.raises(ValueError, match="follow the measurement window"):
        evaluate_adapter_candidate(
            FROZEN_SOURCE_EXPANSION_CONTRACT,
            candidate,
            _measurement(candidate),
            evidence,
            baseline_quality=baseline,
            candidate_quality=current,
        )


def test_missing_runtime_evidence_blocks_but_remains_visible() -> None:
    candidate = _candidate("adapter:no-runtime")
    evaluation = _evaluation(candidate, include_real=False)
    assert evaluation.eligible_for_review is False
    assert evaluation.visible is True
    assert evaluation.reason_codes == ("missing_real_runtime_evidence",)
    portfolio = rank_expansion_candidates(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        (evaluation,),
    )
    assert len(portfolio.entries) == 1
    assert portfolio.entries[0].status == "blocked"
    assert portfolio.entries[0].candidate_id == candidate.candidate_id


def test_freshness_regression_blocks_review() -> None:
    candidate = _candidate("adapter:stale")
    evaluation = _evaluation(
        candidate,
        baseline_freshness=9_900,
        candidate_freshness=9_800,
    )
    assert evaluation.eligible_for_review is False
    assert evaluation.reason_codes == ("source_freshness_regression",)


def test_receipt_or_hard_quality_regression_blocks_review() -> None:
    candidate = _candidate("adapter:receipt-regression")
    evaluation = _evaluation(
        candidate,
        candidate_receipt_violations=1,
    )
    assert evaluation.eligible_for_review is False
    assert evaluation.reason_codes == (
        "candidate_hard_quality_regression",
    )


def test_non_positive_value_is_visible_but_blocked() -> None:
    candidate = _candidate("adapter:negative-value")
    evaluation = _evaluation(candidate, cost=500, friction=500)
    assert evaluation.value_score < 0
    assert evaluation.eligible_for_review is False
    assert evaluation.reason_codes == ("non_positive_incremental_value",)


def test_quality_snapshot_cannot_change_policy_or_phase() -> None:
    candidate = _candidate("adapter:quality")
    baseline, _ = _qualities(candidate)
    with pytest.raises(ValueError, match="identity is invalid"):
        replace(
            baseline,
            eligibility_policy_sha256=hashlib.sha256(
                b"foreign-eligibility"
            ).hexdigest(),
        )
    with pytest.raises(ValueError, match="phase is unsupported"):
        replace(baseline, phase="production")


def test_quality_nonregression_requires_identical_sample_membership() -> None:
    candidate = _candidate("adapter:quality-membership")
    baseline, _ = _qualities(candidate)
    current = record_adapter_quality_snapshot(
        FROZEN_SOURCE_EXPANSION_CONTRACT,
        candidate,
        phase="candidate",
        sample_ids=(_hash("different-quality-member"),),
        freshness_pass_rate_bp=10_000,
    )
    with pytest.raises(ValueError, match="identical membership"):
        evaluate_adapter_candidate(
            FROZEN_SOURCE_EXPANSION_CONTRACT,
            candidate,
            _measurement(candidate),
            _evidence(candidate),
            baseline_quality=baseline,
            candidate_quality=current,
        )


def test_even_eligible_result_cannot_activate_or_certify() -> None:
    evaluation = _evaluation(_candidate("adapter:no-activation"))
    for changes in (
        {"activation_authority": "granted"},
        {"crawl_authority": "granted"},
        {"production_certification": "granted"},
        {"dependency_satisfied": True},
        {"certifies_slice": True},
        {"visible": False},
    ):
        with pytest.raises(ValueError):
            replace(evaluation, **changes)


def test_product_module_has_no_fetch_crawl_or_external_action_capability() -> None:
    source = (
        Path(__file__).parent
        / "career_automation"
        / "source_expansion.py"
    ).read_text(encoding="utf-8")
    forbidden = (
        "requests.",
        "urllib.request",
        "httpx",
        "aiohttp",
        "socket",
        "playwright",
        "subprocess",
        "Fetcher.",
        "Spider(",
        "Collector(",
        "send_message",
        "load_adapter(",
    )
    for token in forbidden:
        assert token not in source
