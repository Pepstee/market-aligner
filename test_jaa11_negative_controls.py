"""Adversarial controls for the inert JAA-11 fixture adapter."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from career_automation.official_ats_adapter import (
    BLOCKING_SIGNALS,
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
    armed_fixture_circuit,
    assess_fixture_adapter_attempt,
)
from career_automation.release_gate import OfficialRouteBinding
from test_jaa11_independent_acceptance import _content_hash, _observation


@pytest.mark.parametrize("signal", BLOCKING_SIGNALS)
def test_unknown_or_prohibited_interaction_parks_without_evidence(
    signal: str,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    observation = replace(_observation(), blocking_signals=(signal,))
    circuit, result, evidence = assess_fixture_adapter_attempt(
        contract,
        armed_fixture_circuit(contract),
        observation,
    )
    assert circuit.state == "armed"
    assert circuit.assessed_attempts == 1
    assert result.outcome == "parked"
    assert result.reason_codes == (signal,)
    assert result.evidence_id is None
    assert result.receipt_id is None
    assert result.halts_canaries is False
    assert evidence is None


@pytest.mark.parametrize(
    ("changed", "reason"),
    (
        (
            {"observed_form_schema_sha256": "0" * 64},
            "changed_form_schema",
        ),
        (
            {"observed_selector_set_sha256": "0" * 64},
            "changed_selector_set",
        ),
        ({"workflow_sha256": "0" * 64}, "changed_workflow"),
        ({"receipt": None}, "missing_receipt"),
        ({"submit_dispatch_count": 0}, "missing_submit_dispatch"),
        ({"submit_dispatch_count": 2}, "second_submit_attempt"),
    ),
)
def test_hard_invariant_breach_trips_and_latches_circuit(
    changed: dict[str, object],
    reason: str,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    observation = replace(_observation(), **changed)
    circuit, result, evidence = assess_fixture_adapter_attempt(
        contract,
        armed_fixture_circuit(contract),
        observation,
    )
    assert circuit.state == "tripped"
    assert circuit.breach_code == reason
    assert result.outcome == "circuit_open"
    assert result.reason_codes == (reason,)
    assert result.halts_canaries is True
    assert result.evidence_id is None
    assert result.receipt_id is None
    assert evidence is None
    with pytest.raises(RuntimeError, match="circuit breaker is open"):
        assess_fixture_adapter_attempt(
            contract,
            circuit,
            _observation(),
        )


def test_hard_breach_cannot_be_masked_by_a_parking_signal() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    observation = replace(
        _observation(),
        submit_dispatch_count=2,
        blocking_signals=("captcha",),
    )
    circuit, result, evidence = assess_fixture_adapter_attempt(
        contract,
        armed_fixture_circuit(contract),
        observation,
    )
    assert circuit.state == "tripped"
    assert circuit.breach_code == "second_submit_attempt"
    assert result.outcome == "circuit_open"
    assert result.reason_codes == ("second_submit_attempt",)
    assert evidence is None


def test_fabricated_or_mismatched_receipt_trips_without_evidence() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    fabricated = replace(_observation().receipt, receipt_id="0" * 64)
    observation = replace(_observation(), receipt=fabricated)
    circuit, result, evidence = assess_fixture_adapter_attempt(
        contract,
        armed_fixture_circuit(contract),
        observation,
    )
    assert circuit.breach_code == "fabricated_receipt"
    assert result.receipt_id is None
    assert evidence is None

    mismatched = replace(
        _observation().receipt,
        application_id="different-fixture-application",
        receipt_id="0" * 64,
    )
    mismatched = replace(
        mismatched,
        receipt_id=_content_hash(
            mismatched.document(include_identity=False)
        ),
    )
    observation = replace(_observation(), receipt=mismatched)
    circuit, result, evidence = assess_fixture_adapter_attempt(
        contract,
        armed_fixture_circuit(contract),
        observation,
    )
    assert circuit.breach_code == "mismatched_receipt"
    assert result.receipt_id is None
    assert evidence is None


def test_changed_submission_proof_trips_without_receipt_claim() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    changed_proof = replace(
        _observation().submission_proof,
        submit_event_sha256="0" * 64,
    )
    observation = replace(
        _observation(),
        submission_proof=changed_proof,
    )
    circuit, result, evidence = assess_fixture_adapter_attempt(
        contract,
        armed_fixture_circuit(contract),
        observation,
    )
    assert circuit.breach_code == "changed_submission_proof"
    assert result.receipt_id is None
    assert evidence is None


def test_fixture_contract_rejects_external_or_actionable_route() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    external_url = (
        "https://apply.example/applications/"
        f"{contract.application_id}"
    )
    external_binding = OfficialRouteBinding(
        route_id=contract.route_binding.route_id,
        adapter_id=contract.adapter_id,
        adapter_version=contract.adapter_version,
        source_identity=external_url,
        route_policy_sha256=contract.route_binding.route_policy_sha256,
        verified_at=date(2030, 1, 1),
        valid_until=date(2030, 12, 31),
        allowed=True,
    )
    with pytest.raises(ValueError, match="loopback HTTP on port zero"):
        replace(
            contract,
            route_binding=external_binding,
            route_url=external_url,
        )


def test_noncanonical_contract_cannot_assess_or_arm() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    replacement = replace(
        contract,
        route_binding=replace(
            contract.route_binding,
            route_id="caller-defined-route",
        ),
    )
    with pytest.raises(ValueError, match="canonical contract"):
        armed_fixture_circuit(replacement)
    with pytest.raises(
        ValueError,
        match="canonical adapter contract",
    ):
        assess_fixture_adapter_attempt(
            replacement,
            armed_fixture_circuit(contract),
            _observation(),
        )


def test_fixture_evidence_cannot_be_relabelled_as_production() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    _circuit, result, evidence = assess_fixture_adapter_attempt(
        contract,
        armed_fixture_circuit(contract),
        _observation(),
    )
    assert evidence is not None
    with pytest.raises(ValueError, match="cannot activate or certify"):
        replace(evidence, real_canary_activation="authorized")
    with pytest.raises(ValueError, match="cannot activate or certify"):
        replace(evidence, production_certification="certified")
    with pytest.raises(ValueError, match="cannot certify"):
        replace(result, certifies_slice=True)


def test_product_module_has_no_browser_network_or_submission_capability() -> None:
    source_value = (
        __import__(
            "career_automation.official_ats_adapter",
            fromlist=[""],
        )
        .__file__
    )
    assert source_value is not None
    text = Path(source_value).read_text(encoding="utf-8")
    for forbidden in (
        "aiohttp",
        "http.client",
        "httpx",
        "playwright",
        "requests.",
        "socket",
        "subprocess",
        "urllib.request",
        "urlopen",
        "consume_release_token",
        "evaluate_and_issue",
        "locator.click",
        "page.goto",
        "certifies_slice: bool = True",
    ):
        assert forbidden not in text


def test_unknown_blocker_name_and_real_environment_fail_closed() -> None:
    with pytest.raises(ValueError, match="unknown or duplicate blocker"):
        replace(_observation(), blocking_signals=("unexpected_challenge",))
    with pytest.raises(ValueError, match="cannot claim a real environment"):
        replace(_observation(), evidence_kind="real_canary")
