"""Adversarial controls for the inert JAA-11 fixture adapter."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from career_automation.durable_circuit_store import (
    CircuitStateError,
    assess_fixture_adapter_attempt,
)
from career_automation.official_ats_adapter import (
    BLOCKING_SIGNALS,
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
)
from career_automation.release_gate import OfficialRouteBinding
from test_jaa11_independent_acceptance import (
    _content_hash,
    _observation,
    _store,
)


@pytest.mark.parametrize("signal", BLOCKING_SIGNALS)
def test_unknown_or_prohibited_interaction_parks_without_evidence(
    signal: str,
    tmp_path: Path,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    observation = replace(
        _observation(),
        blocking_signals=(signal,),
        submit_dispatch_count=0,
        receipt=None,
    )
    store = _store(tmp_path / f"{signal}.sqlite3")
    initial = store.require_armed()
    result, evidence, trip_receipt = assess_fixture_adapter_attempt(
        contract,
        store,
        observation,
    )
    assert store.require_armed() == initial
    assert result.outcome == "parked"
    assert result.reason_codes == (signal,)
    assert result.evidence_id is None
    assert result.receipt_id is None
    assert result.halts_canaries is False
    assert evidence is None
    assert trip_receipt is None


def test_blocker_cannot_relabel_a_completed_submit_as_parked(
    tmp_path: Path,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    observation = replace(
        _observation(),
        blocking_signals=("captcha",),
    )
    with pytest.raises(
        ValueError,
        match="cannot follow a completed submit dispatch",
    ):
        assess_fixture_adapter_attempt(
            contract,
            _store(tmp_path / "circuit.sqlite3"),
            observation,
        )


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
    tmp_path: Path,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    observation = replace(_observation(), **changed)
    store = _store(tmp_path / f"{reason}.sqlite3")
    result, evidence, trip_receipt = assess_fixture_adapter_attempt(
        contract,
        store,
        observation,
    )
    persisted = store.verify()
    assert persisted.state == "tripped"
    assert persisted.breach_code == reason
    assert trip_receipt is not None
    assert persisted.head_receipt_sha256 == trip_receipt.receipt_sha256
    assert result.outcome == "circuit_open"
    assert result.reason_codes == (reason,)
    assert result.halts_canaries is True
    assert result.evidence_id is None
    assert result.receipt_id is None
    assert evidence is None
    with pytest.raises(CircuitStateError, match="tripped"):
        assess_fixture_adapter_attempt(
            contract,
            store,
            _observation(),
        )


def test_hard_breach_cannot_be_masked_by_a_parking_signal(
    tmp_path: Path,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    observation = replace(
        _observation(),
        submit_dispatch_count=2,
        blocking_signals=("captcha",),
    )
    store = _store(tmp_path / "circuit.sqlite3")
    result, evidence, trip_receipt = assess_fixture_adapter_attempt(
        contract,
        store,
        observation,
    )
    assert store.verify().state == "tripped"
    assert store.verify().breach_code == "second_submit_attempt"
    assert trip_receipt is not None
    assert result.outcome == "circuit_open"
    assert result.reason_codes == ("second_submit_attempt",)
    assert evidence is None


def test_fabricated_or_mismatched_receipt_trips_without_evidence(
    tmp_path: Path,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    fabricated = replace(_observation().receipt, receipt_id="0" * 64)
    observation = replace(_observation(), receipt=fabricated)
    fabricated_store = _store(tmp_path / "fabricated.sqlite3")
    result, evidence, trip_receipt = assess_fixture_adapter_attempt(
        contract,
        fabricated_store,
        observation,
    )
    assert fabricated_store.verify().breach_code == "fabricated_receipt"
    assert trip_receipt is not None
    assert result.receipt_id is None
    assert evidence is None
    with pytest.raises(CircuitStateError, match="tripped"):
        assess_fixture_adapter_attempt(
            contract,
            fabricated_store,
            _observation(),
        )

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
    mismatched_store = _store(tmp_path / "mismatched.sqlite3")
    result, evidence, trip_receipt = assess_fixture_adapter_attempt(
        contract,
        mismatched_store,
        observation,
    )
    assert mismatched_store.verify().breach_code == "mismatched_receipt"
    assert trip_receipt is not None
    assert result.receipt_id is None
    assert evidence is None
    with pytest.raises(CircuitStateError, match="tripped"):
        assess_fixture_adapter_attempt(
            contract,
            mismatched_store,
            _observation(),
        )


def test_malformed_receipt_runtime_type_trips_as_fabricated(
    tmp_path: Path,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    malformed = replace(_observation().receipt, receipt_id=object())
    observation = replace(_observation(), receipt=malformed)
    store = _store(tmp_path / "circuit.sqlite3")
    result, evidence, trip_receipt = assess_fixture_adapter_attempt(
        contract,
        store,
        observation,
    )
    assert store.verify().state == "tripped"
    assert store.verify().breach_code == "fabricated_receipt"
    assert trip_receipt is not None
    assert result.reason_codes == ("fabricated_receipt",)
    assert result.receipt_id is None
    assert evidence is None
    with pytest.raises(CircuitStateError, match="tripped"):
        assess_fixture_adapter_attempt(contract, store, _observation())


@pytest.mark.parametrize(
    "changed",
    (
        {"release_manifest_sha256": "0" * 64},
        {"token_sha256": "0" * 64},
        {"submit_event_sha256": "0" * 64},
    ),
)
def test_changed_submission_proof_trips_without_receipt_claim(
    changed: dict[str, str],
    tmp_path: Path,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    changed_proof = replace(
        _observation().submission_proof,
        **changed,
    )
    observation = replace(
        _observation(),
        submission_proof=changed_proof,
    )
    store = _store(tmp_path / f"{next(iter(changed))}.sqlite3")
    result, evidence, trip_receipt = assess_fixture_adapter_attempt(
        contract,
        store,
        observation,
    )
    assert store.verify().breach_code == "changed_submission_proof"
    assert trip_receipt is not None
    assert result.receipt_id is None
    assert evidence is None
    with pytest.raises(CircuitStateError, match="tripped"):
        assess_fixture_adapter_attempt(contract, store, _observation())


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


def test_noncanonical_contract_cannot_assess_or_arm(
    tmp_path: Path,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    replacement = replace(
        contract,
        route_binding=replace(
            contract.route_binding,
            route_id="caller-defined-route",
        ),
    )
    with pytest.raises(
        ValueError,
        match="canonical adapter contract",
    ):
        assess_fixture_adapter_attempt(
            replacement,
            _store(tmp_path / "circuit.sqlite3"),
            _observation(),
        )


def test_adapter_identifiers_must_be_canonical_without_padding() -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    padded_id = f" {contract.adapter_id} "
    padded_binding = replace(
        contract.route_binding,
        adapter_id=padded_id,
    )
    with pytest.raises(ValueError, match="surrounding whitespace"):
        replace(
            contract,
            route_binding=padded_binding,
            adapter_id=padded_id,
        )


def test_fixture_evidence_cannot_be_relabelled_as_production(
    tmp_path: Path,
) -> None:
    contract = FROZEN_FIXTURE_ADAPTER_CONTRACT
    result, evidence, trip_receipt = assess_fixture_adapter_attempt(
        contract,
        _store(tmp_path / "circuit.sqlite3"),
        _observation(),
    )
    assert trip_receipt is None
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
        "durable_circuit_store",
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
