"""Focused acceptance and negative controls for JAA-15 acquisition prep."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from career_automation.adapter_acquisition import (
    AUTHENTICATION_MODE,
    CAPTURE_MAX_BYTES,
    UPSTREAM_AUTHENTICATION_MODE,
    UpstreamJAA14CertificationEvidence,
    build_acquisition_registry,
    compile_acquisition_candidate,
    normalize_capture_input,
    prepare_activation_decision,
    record_adapter_evidence,
    record_blocked_opportunity,
)
from career_automation.outcome_feedback import (
    FROZEN_OUTCOME_FEEDBACK_CONTRACT,
)


NOW = datetime(2031, 5, 20, 12, tzinfo=timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _candidate(
    adapter_id: str = "ats.ashby",
    *,
    eligibility: str = "supported",
    payroll: str = "supported",
    selector_origin_adapter_id: str | None = None,
    selector_origin_adapter_version: str | None = None,
    selector_inheritance_evidence_sha256: str | None = None,
):
    return compile_acquisition_candidate(
        adapter_id=adapter_id,
        adapter_version="v2",
        source_kind="official_ats",
        official_base_url="https://jobs.example.com/",
        route_sha256=_hash(f"{adapter_id}:route"),
        schema_sha256=_hash(f"{adapter_id}:schema"),
        workflow_sha256=_hash(f"{adapter_id}:workflow"),
        rollback_sha256=_hash(f"{adapter_id}:rollback:v1"),
        selector_policy_sha256=_hash(f"{adapter_id}:selectors:v2"),
        eligibility_policy_sha256=_hash(f"{adapter_id}:eligibility:GB"),
        payroll_policy_sha256=_hash(f"{adapter_id}:payroll:GB"),
        country_context="GB",
        employer_context="employer.all",
        eligibility_context_status=eligibility,
        payroll_context_status=payroll,
        selector_origin_adapter_id=selector_origin_adapter_id,
        selector_origin_adapter_version=selector_origin_adapter_version,
        selector_inheritance_evidence_sha256=(
            selector_inheritance_evidence_sha256
        ),
    )


def _capture(candidate, *, interactions=(), when=NOW - timedelta(days=2)):
    return normalize_capture_input(
        candidate,
        route_url="https://jobs.example.com/apply?b=2&a=1",
        final_url="https://jobs.example.com/apply?a=1&b=2",
        captured_at=when,
        content_sha256=_hash("captured response"),
        byte_length=1234,
        media_type="text/html; charset=utf-8",
        status_code=200,
        redirect_chain=("https://jobs.example.com/apply?a=1&b=2",),
        interaction_requirements=interactions,
    )


def _evidence(candidate, capture, *, when=NOW - timedelta(days=1)):
    return tuple(
        record_adapter_evidence(
            candidate,
            capture,
            evidence_kind=kind,
            evidence_sha256=_hash(f"{candidate.candidate_id}:{kind}"),
            observed_at=when,
            verifier_id=f"verifier.{kind}",
            authentication_mode=AUTHENTICATION_MODE,
            manifest_receipt_sha256=_hash(f"manifest:{kind}"),
        )
        for kind in ("fixture_runtime", "independent_test", "real_runtime")
    )


def _upstream():
    return UpstreamJAA14CertificationEvidence(
        upstream_contract_sha256=(
            FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256
        ),
        promotion_evaluation_sha256=_hash("promotion evaluation"),
        certification_receipt_sha256=_hash("independent certification"),
        verifier_id="verifier.jaa14.independent",
        authentication_mode=UPSTREAM_AUTHENTICATION_MODE,
        issued_at=(NOW - timedelta(days=2)).isoformat(),
        expires_at=(NOW + timedelta(days=2)).isoformat(),
    )


def test_candidate_binds_exact_workflow_route_schema_rollback_and_context() -> None:
    candidate = _candidate()
    assert len(candidate.route_sha256) == 64
    assert len(candidate.schema_sha256) == 64
    assert len(candidate.workflow_sha256) == 64
    assert len(candidate.rollback_sha256) == 64
    assert candidate.official_base_url == "https://jobs.example.com/"
    assert candidate.activation_authority == "withheld"
    assert candidate.certifies_slice is False


def test_selector_inheritance_requires_explicit_versioned_evidence() -> None:
    with pytest.raises(ValueError, match="explicit versioned evidence"):
        _candidate(
            selector_origin_adapter_id="ats.greenhouse",
            selector_origin_adapter_version="v7",
        )
    inherited = _candidate(
        selector_origin_adapter_id="ats.greenhouse",
        selector_origin_adapter_version="v7",
        selector_inheritance_evidence_sha256=_hash("selector equivalence v7"),
    )
    assert inherited.selector_origin_adapter_version == "v7"


def test_capture_is_bounded_normalized_and_never_fetches() -> None:
    capture = _capture(_candidate())
    assert capture.route_url == "https://jobs.example.com/apply?a=1&b=2"
    assert capture.media_type == "text/html"
    assert capture.network_authority == "withheld"
    assert capture.certifies_runtime is False


def test_capture_rejects_oversize_and_official_host_escape() -> None:
    candidate = _candidate()
    with pytest.raises(ValueError, match="exceeds bound"):
        normalize_capture_input(
            candidate,
            route_url="https://jobs.example.com/apply",
            final_url="https://jobs.example.com/apply",
            captured_at=NOW,
            content_sha256=_hash("large"),
            byte_length=CAPTURE_MAX_BYTES + 1,
            media_type="text/html",
            status_code=200,
        )
    with pytest.raises(ValueError, match="exact official host"):
        normalize_capture_input(
            candidate,
            route_url="https://evil.example.net/apply",
            final_url="https://evil.example.net/apply",
            captured_at=NOW,
            content_sha256=_hash("escape"),
            byte_length=1,
            media_type="text/html",
            status_code=200,
        )


def test_evidence_is_adapter_specific_authenticated_and_content_addressed() -> None:
    candidate = _candidate()
    capture = _capture(candidate)
    evidence = _evidence(candidate, capture)
    assert {row.evidence_kind for row in evidence} == {
        "fixture_runtime",
        "independent_test",
        "real_runtime",
    }
    assert all(row.candidate_id == candidate.candidate_id for row in evidence)
    assert all(row.activation_authority == "withheld" for row in evidence)


def test_unauthenticated_and_cross_adapter_evidence_are_rejected() -> None:
    candidate = _candidate()
    capture = _capture(candidate)
    with pytest.raises(ValueError, match="unauthenticated"):
        record_adapter_evidence(
            candidate,
            capture,
            evidence_kind="real_runtime",
            evidence_sha256=_hash("runtime"),
            observed_at=NOW,
            verifier_id="verifier.runtime",
            authentication_mode="caller_asserted",
            manifest_receipt_sha256=_hash("manifest"),
        )
    other = _candidate("ats.other")
    with pytest.raises(ValueError, match="cross-adapter"):
        record_adapter_evidence(
            other,
            capture,
            evidence_kind="real_runtime",
            evidence_sha256=_hash("runtime"),
            observed_at=NOW,
            verifier_id="verifier.runtime",
            manifest_receipt_sha256=_hash("manifest"),
        )


def test_registry_is_deterministic_and_retains_blocked_opportunities() -> None:
    one = _candidate("ats.one")
    two = _candidate("ats.two")
    blocked = record_blocked_opportunity(
        one,
        opportunity_id="opportunity.42",
        official_route_sha256=_hash("route 42"),
        reason_codes=("captcha", "unsupported.payroll"),
        observed_at=NOW,
    )
    first = build_acquisition_registry((two, one), (blocked,))
    second = build_acquisition_registry((one, two), (blocked,))
    assert first.registry_id == second.registry_id
    assert first.blocked_opportunities[0].visibility == "retained_blocked"
    assert first.activation_authority == "withheld"


def test_activation_stays_withheld_without_upstream_jaa14_certification() -> None:
    candidate = _candidate()
    capture = _capture(candidate)
    registry = build_acquisition_registry((candidate,))
    decision = prepare_activation_decision(
        registry,
        candidate,
        (capture,),
        _evidence(candidate, capture),
        evaluated_at=NOW,
    )
    assert decision.decision_status == "withheld_upstream_jaa14_missing"
    assert decision.reason_codes == ("upstream_jaa14_certification_missing",)
    assert decision.activation_authority == "withheld"
    assert decision.production_certification == "withheld"


def test_valid_upstream_only_prepares_independent_review_never_activates() -> None:
    candidate = _candidate()
    capture = _capture(candidate)
    decision = prepare_activation_decision(
        build_acquisition_registry((candidate,)),
        candidate,
        (capture,),
        _evidence(candidate, capture),
        evaluated_at=NOW,
        upstream_jaa14=_upstream(),
    )
    assert (
        decision.decision_status
        == "withheld_prepared_for_independent_activation_review"
    )
    assert decision.reason_codes == ()
    assert decision.activation_authority == "withheld"
    assert decision.certifies_slice is False


@pytest.mark.parametrize("interaction", ["captcha", "login", "mfa", "payment"])
def test_hidden_or_prohibited_interactions_block_preparation(interaction: str) -> None:
    candidate = _candidate()
    capture = _capture(candidate, interactions=(interaction,))
    decision = prepare_activation_decision(
        build_acquisition_registry((candidate,)),
        candidate,
        (capture,),
        _evidence(candidate, capture),
        evaluated_at=NOW,
        upstream_jaa14=_upstream(),
    )
    assert decision.decision_status == "withheld_blocked"
    assert decision.reason_codes == (f"blocked_interaction_{interaction}",)


def test_unsupported_eligibility_and_payroll_contexts_block() -> None:
    candidate = _candidate(eligibility="unsupported", payroll="unsupported")
    capture = _capture(candidate)
    decision = prepare_activation_decision(
        build_acquisition_registry((candidate,)),
        candidate,
        (capture,),
        _evidence(candidate, capture),
        evaluated_at=NOW,
        upstream_jaa14=_upstream(),
    )
    assert decision.decision_status == "withheld_blocked"
    assert decision.reason_codes == (
        "unsupported_eligibility_context",
        "unsupported_payroll_context",
    )


def test_missing_adapter_specific_runtime_evidence_is_visible() -> None:
    candidate = _candidate()
    capture = _capture(candidate)
    evidence = _evidence(candidate, capture)[:2]
    decision = prepare_activation_decision(
        build_acquisition_registry((candidate,)),
        candidate,
        (capture,),
        evidence,
        evaluated_at=NOW,
        upstream_jaa14=_upstream(),
    )
    assert decision.decision_status == "withheld_blocked"
    assert decision.reason_codes == ("missing_real_runtime_evidence",)


def test_stale_capture_and_evidence_are_rejected_not_silently_downgraded() -> None:
    candidate = _candidate()
    stale_capture = _capture(candidate, when=NOW - timedelta(days=31))
    stale_evidence = _evidence(
        candidate,
        stale_capture,
        when=NOW - timedelta(days=30, seconds=1),
    )
    with pytest.raises(ValueError, match="stale capture"):
        prepare_activation_decision(
            build_acquisition_registry((candidate,)),
            candidate,
            (stale_capture,),
            stale_evidence,
            evaluated_at=NOW,
        )


def test_cross_adapter_evidence_reuse_fails_at_decision_boundary() -> None:
    one = _candidate("ats.one")
    two = _candidate("ats.two")
    one_capture = _capture(one)
    two_capture = _capture(two)
    with pytest.raises(ValueError, match="cross-adapter evidence reuse"):
        prepare_activation_decision(
            build_acquisition_registry((one, two)),
            one,
            (one_capture,),
            _evidence(two, two_capture),
            evaluated_at=NOW,
        )


def test_identity_and_authority_tampering_fail_closed() -> None:
    candidate = _candidate()
    with pytest.raises(ValueError, match="cannot activate"):
        replace(candidate, activation_authority="granted")
    with pytest.raises(ValueError, match="identity is invalid"):
        replace(candidate, route_sha256=_hash("tampered route"))
