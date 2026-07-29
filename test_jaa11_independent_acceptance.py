"""Positive contract controls for the inert JAA-11 fixture adapter."""

from __future__ import annotations

import hashlib
import json

from career_automation.ats_fixture import FixtureReceipt
from career_automation.browser_workflows import SubmissionProof
from career_automation.official_ats_adapter import (
    CIRCUIT_BREAKER_POLICY_SHA256,
    FIXTURE_CIRCUIT_BREAKER_POLICY,
    FIXTURE_FORM_SCHEMA,
    FIXTURE_RECEIPT_SEMANTICS,
    FIXTURE_ROUTE_POLICY,
    FIXTURE_ROUTE_URL,
    FIXTURE_SELECTOR_SET,
    FORM_SCHEMA_SHA256,
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
    RECEIPT_SEMANTICS_SHA256,
    ROUTE_POLICY_SHA256,
    SELECTOR_SET_SHA256,
    AdapterFixtureObservation,
    armed_fixture_circuit,
    assess_fixture_adapter_attempt,
)
from career_automation.shadow_certification import FROZEN_SHADOW_CONTRACT


def _content_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _proof() -> SubmissionProof:
    golden = FROZEN_SHADOW_CONTRACT
    return SubmissionProof(
        release_manifest_sha256="a" * 64,
        token_sha256="b" * 64,
        receipt_id=golden.receipt_id,
        receipt_payload_sha256=golden.receipt_payload_sha256,
        screenshot_sha256=golden.screenshot_sha256,
        field_map_sha256=golden.field_map_sha256,
        submit_event_sha256=golden.submit_event_sha256,
    )


def _receipt() -> FixtureReceipt:
    golden = FROZEN_SHADOW_CONTRACT
    receipt = FixtureReceipt(
        receipt_id=golden.receipt_id,
        application_id=golden.application_id,
        job_key=golden.job_key,
        payload_sha256=golden.receipt_payload_sha256,
    )
    receipt.verify()
    return receipt


def _observation() -> AdapterFixtureObservation:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    return AdapterFixtureObservation(
        adapter_contract_sha256=contract.contract_sha256,
        workflow_sha256=contract.workflow_sha256,
        observed_form_schema_sha256=contract.form_schema_sha256,
        observed_selector_set_sha256=contract.selector_set_sha256,
        submission_proof=_proof(),
        receipt=_receipt(),
        submit_dispatch_count=1,
    )


def test_frozen_fixture_contract_binds_exact_upstream_and_policy() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    assert contract.upstream_shadow_contract_sha256 == (
        FROZEN_SHADOW_CONTRACT.contract_sha256
    )
    assert contract.workflow_sha256 == (
        FROZEN_SHADOW_CONTRACT.workflow_sha256
    )
    assert contract.route_url == FIXTURE_ROUTE_URL
    assert contract.route_binding.source_identity == FIXTURE_ROUTE_URL
    assert contract.route_binding.route_policy_sha256 == ROUTE_POLICY_SHA256
    assert contract.environment == "fixture_only"
    assert contract.real_canary_activation == (
        "withheld_explicit_operator_approval_required"
    )
    assert contract.production_certification == "withheld"
    assert contract.certifies_slice is False
    assert contract.contract_sha256


def test_fixture_policy_hashes_are_recomputable_from_serialized_inputs() -> None:
    assert FORM_SCHEMA_SHA256 == _content_hash(dict(FIXTURE_FORM_SCHEMA))
    assert SELECTOR_SET_SHA256 == _content_hash(dict(FIXTURE_SELECTOR_SET))
    assert RECEIPT_SEMANTICS_SHA256 == _content_hash(
        dict(FIXTURE_RECEIPT_SEMANTICS)
    )
    assert CIRCUIT_BREAKER_POLICY_SHA256 == _content_hash(
        dict(FIXTURE_CIRCUIT_BREAKER_POLICY)
    )
    assert ROUTE_POLICY_SHA256 == _content_hash(dict(FIXTURE_ROUTE_POLICY))


def test_exact_fixture_submission_proof_compiles_only_with_withheld_status() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    circuit = armed_fixture_circuit(contract)
    next_circuit, result, evidence = assess_fixture_adapter_attempt(
        contract,
        circuit,
        _observation(),
    )
    assert next_circuit.state == "armed"
    assert next_circuit.assessed_attempts == 1
    assert result.outcome == "fixture_pass"
    assert result.reason_codes == ()
    assert result.halts_canaries is False
    assert evidence is not None
    evidence.verify()
    assert result.evidence_id == evidence.evidence_id
    assert result.receipt_id == evidence.receipt_id
    assert evidence.real_canary_activation == "withheld"
    assert evidence.production_certification == "withheld"
    assert evidence.evidence_kind == "fixture_only"
    assert evidence.certifies_slice is False
    assert evidence.document()["receipt_id"] == _receipt().receipt_id
    assert "real_canary_receipt" not in evidence.document()


def test_fixture_observation_and_circuit_state_are_content_addressed() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    observation = _observation()
    first = armed_fixture_circuit(contract)
    second, _result, evidence = assess_fixture_adapter_attempt(
        contract,
        first,
        observation,
    )
    assert observation.observation_sha256
    assert first.state_sha256 != second.state_sha256
    assert evidence is not None
    assert evidence.observation_sha256 == observation.observation_sha256
