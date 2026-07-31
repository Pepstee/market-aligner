"""Integration controls for the fixture-only durable JAA-11 circuit path."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import career_automation.durable_circuit_store as store_module
import career_automation.official_ats_adapter as adapter_module
from career_automation.durable_circuit_store import (
    CircuitIntegrityError,
    CircuitStateError,
    DurableCircuitStore,
    assess_fixture_adapter_attempt,
)
from career_automation.official_ats_adapter import (
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
)
from test_jaa11_independent_acceptance import _observation, _store


CONTRACT_SHA256 = (
    "e4cb8ee1b416d75063bb70b72208a3554fb0ccc59998f6ff4d9ef44b3eced4e5"
)


def test_frozen_adapter_contract_hash_survives_integration_exactly() -> None:
    assert (
        FROZEN_FIXTURE_ADAPTER_CONTRACT.contract_sha256
        == CONTRACT_SHA256
    )


def test_persisted_trip_blocks_integrated_pass_in_fresh_interpreter(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = _store(path)
    store.trip(expected_version=0, breach_code="missing_receipt")

    program = """
import json
import sys
from career_automation.durable_circuit_store import (
    CircuitStateError,
    CircuitStoreIdentity,
    DurableCircuitStore,
    assess_fixture_adapter_attempt,
)
from career_automation.official_ats_adapter import (
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
)
from test_jaa11_independent_acceptance import _observation
identity = CircuitStoreIdentity(**json.loads(sys.argv[2]))
store = DurableCircuitStore.open(sys.argv[1], identity=identity)
try:
    assess_fixture_adapter_attempt(
        FROZEN_FIXTURE_ADAPTER_CONTRACT,
        store,
        _observation(),
    )
except CircuitStateError:
    refused = True
else:
    refused = False
print(json.dumps({
    "refused": refused,
    "state": store.verify().state,
    "receipts": len(store.receipts()),
}))
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(path),
            json.dumps(store.identity.document(), sort_keys=True),
        ],
        cwd=Path(__file__).parent,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == {
        "refused": True,
        "state": "tripped",
        "receipts": 2,
    }


def test_adapter_has_no_legacy_circuit_or_reverse_dependency() -> None:
    for name in (
        "AdapterCircuitBreaker",
        "armed_fixture_circuit",
        "assess_fixture_adapter_attempt",
    ):
        assert not hasattr(adapter_module, name)
    source_path = Path(adapter_module.__file__ or "")
    assert "durable_circuit_store" not in source_path.read_text(
        encoding="utf-8"
    )

    program = """
import json
import sys
import career_automation.official_ats_adapter as adapter
print(json.dumps({
    "store_loaded": "career_automation.durable_circuit_store" in sys.modules,
    "legacy": [
        hasattr(adapter, "AdapterCircuitBreaker"),
        hasattr(adapter, "armed_fixture_circuit"),
        hasattr(adapter, "assess_fixture_adapter_attempt"),
    ],
}))
"""
    completed = subprocess.run(
        [sys.executable, "-c", program],
        cwd=Path(__file__).parent,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == {
        "store_loaded": False,
        "legacy": [False, False, False],
    }


def test_concurrent_trip_during_pass_classification_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = _store(path)
    original_evaluator = store_module.evaluate_fixture_observation

    def trip_mid_assessment(contract, observation):
        contender = DurableCircuitStore.open(
            path,
            identity=store.identity,
        )
        contender.trip(
            expected_version=0,
            breach_code="changed_form_schema",
        )
        return original_evaluator(contract, observation)

    monkeypatch.setattr(
        store_module,
        "evaluate_fixture_observation",
        trip_mid_assessment,
    )
    with pytest.raises(
        CircuitStateError,
        match="changed during fixture assessment",
    ):
        assess_fixture_adapter_attempt(
            FROZEN_FIXTURE_ADAPTER_CONTRACT,
            store,
            _observation(),
        )
    snapshot = store.verify()
    assert snapshot.state == "tripped"
    assert snapshot.breach_code == "changed_form_schema"
    assert len(store.receipts()) == 2


def test_integrated_path_rejects_subclass_and_duck_typed_store(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "circuit.sqlite3")

    class StoreSubclass(DurableCircuitStore):
        pass

    subclass = StoreSubclass(store.database_path, store.identity)
    for invalid in (subclass, object()):
        with pytest.raises(TypeError, match="exact DurableCircuitStore"):
            assess_fixture_adapter_attempt(
                FROZEN_FIXTURE_ADAPTER_CONTRACT,
                invalid,
                _observation(),
            )


def test_integrated_path_rejects_cross_identity_and_replacement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = _store(path)
    wrong_contract = DurableCircuitStore(
        path,
        replace(
            store.identity,
            adapter_contract_sha256="0" * 64,
        ),
    )
    with pytest.raises(ValueError, match="different contract"):
        assess_fixture_adapter_attempt(
            FROZEN_FIXTURE_ADAPTER_CONTRACT,
            wrong_contract,
            _observation(),
        )

    wrong_instance = DurableCircuitStore(
        path,
        replace(
            store.identity,
            circuit_instance_id="different-instance",
        ),
    )
    with pytest.raises(CircuitIntegrityError):
        assess_fixture_adapter_attempt(
            FROZEN_FIXTURE_ADAPTER_CONTRACT,
            wrong_instance,
            _observation(),
        )

    replacement_path = tmp_path / "replacement.sqlite3"
    replacement = DurableCircuitStore.initialize(
        replacement_path,
        adapter_contract_sha256=CONTRACT_SHA256,
        circuit_instance_id=store.identity.circuit_instance_id,
    )
    assert (
        replacement.identity.genesis_receipt_sha256
        != store.identity.genesis_receipt_sha256
    )
    shutil.copyfile(replacement_path, path)
    with pytest.raises(CircuitIntegrityError):
        assess_fixture_adapter_attempt(
            FROZEN_FIXTURE_ADAPTER_CONTRACT,
            store,
            _observation(),
        )


def test_reset_proposal_never_restores_integrated_assessment(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "circuit.sqlite3")
    store.trip(expected_version=0, breach_code="missing_receipt")
    store.propose_reset(
        expected_version=1,
        reset_proposal_id="1" * 64,
        rationale_sha256="2" * 64,
    )
    assert store.verify().state == "tripped"
    with pytest.raises(CircuitStateError, match="tripped"):
        assess_fixture_adapter_attempt(
            FROZEN_FIXTURE_ADAPTER_CONTRACT,
            store,
            _observation(),
        )
