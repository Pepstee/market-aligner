from __future__ import annotations

import inspect

import pytest

from career_automation.certification_candidate_compiler import (
    CertificationCandidateError,
    compile_certification_candidate,
)
from career_automation.hard_metrics_evaluation import (
    FULL_SUBMIT_EVIDENCE_REGISTRY,
    FULL_SUBMIT_WITHHELD_REASON,
    EvidenceClass,
    MetricStatus,
    evaluate_full_submit_hard_metrics,
    full_submit_evidence_registry_document,
    full_submit_evidence_registry_sha256,
)
from career_automation.shadow_certification import HARD_QUALITY_TARGETS


def _metrics_by_name():
    evaluation = evaluate_full_submit_hard_metrics()
    return evaluation, {metric.metric_name: metric for metric in evaluation.metrics}


def test_full_submit_registry_is_fixed_and_evaluator_accepts_no_input() -> None:
    assert tuple(inspect.signature(evaluate_full_submit_hard_metrics).parameters) == ()
    assert set(FULL_SUBMIT_EVIDENCE_REGISTRY) == {
        "jaa07-locked-application-packs-v1",
        "jaa07-locked-evaluation-report-v1",
        "jaa10-frozen-replay-pair-primary-v1",
        "jaa10-full-submit-v2-shadow-cohort-5bb09705",
    }
    assert full_submit_evidence_registry_document()["entries"][-1] == (
        FULL_SUBMIT_EVIDENCE_REGISTRY[
            "jaa10-full-submit-v2-shadow-cohort-5bb09705"
        ].document()
    )
    assert len(full_submit_evidence_registry_sha256()) == 64
    with pytest.raises(TypeError):
        FULL_SUBMIT_EVIDENCE_REGISTRY["caller-path"] = object()  # type: ignore[index]


def test_admitted_full_submit_cohort_derives_all_hard_metrics() -> None:
    evaluation, metrics = _metrics_by_name()
    evaluation.verify()
    assert set(metrics) == set(HARD_QUALITY_TARGETS)
    assert all(metric.status is MetricStatus.PASS for metric in metrics.values())
    assert evaluation.registry_sha256 == full_submit_evidence_registry_sha256()
    document = evaluation.document()
    assert document["withheld_reason"] == FULL_SUBMIT_WITHHELD_REASON
    assert document["objective_satisfied"] is False
    assert document["production_certification"] == "withheld"
    assert document["certifies_slice"] is False
    assert document["live_time_separated_execution"] == "not_collected"
    assert document["external_action_capability"] is False
    assert document["real_applications_submitted"] == 0

    expected = {
        "ats_parse_success_bp": (0, 20, 10_000),
        "confirmed_without_receipt": (0, 2, 0),
        "deterministic_replay_mismatch": (0, 1, 0),
        "duplicate_submissions": (0, 2, 0),
        "ineligible_submissions": (0, 2, 0),
        "released_employer_claims_without_citations": (0, 4, 0),
        "unsupported_released_claims": (0, 4, 0),
    }
    for name, (numerator, denominator, value) in expected.items():
        metric = metrics[name]
        assert (metric.numerator, metric.denominator, metric.value) == (
            numerator,
            denominator,
            value,
        )
        assert metric.evidence_class is EvidenceClass.FIXTURE_FROZEN
        assert metric.missing_evidence_count == 0
        metric.verify()

    for name in {
        "confirmed_without_receipt",
        "duplicate_submissions",
        "ineligible_submissions",
        "released_employer_claims_without_citations",
        "unsupported_released_claims",
    }:
        assert metrics[name].evidence_item_ids == (
            "jaa10-full-submit-v2-shadow-cohort-5bb09705",
        )
        assert metrics[name].evidence_scope_id == (
            "5bb0970598505a57588a5440179a82e27d3190129ba803c963090724680665b3"
        )


def test_metrics_pass_does_not_construct_certification() -> None:
    evaluation = evaluate_full_submit_hard_metrics()
    with pytest.raises(
        CertificationCandidateError,
        match="withheld certification candidate differs",
    ):
        compile_certification_candidate(evaluation)
