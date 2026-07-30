"""Positive controls for the unintegrated JAA-11 durable circuit store."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from career_automation.durable_circuit_store import (
    POLICY_VERSION,
    RESET_AUTHORITY_ANCHOR,
    CircuitStateError,
    DurableCircuitStore,
    circuit_policy_document,
)
from career_automation.official_ats_adapter import (
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
)


CONTRACT_SHA256 = FROZEN_FIXTURE_ADAPTER_CONTRACT.contract_sha256
INSTANCE_ID = "jaa11-local-fixture-circuit"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def new_store(
    path: Path,
    *,
    instance_id: str = INSTANCE_ID,
) -> DurableCircuitStore:
    return DurableCircuitStore.initialize(
        path,
        adapter_contract_sha256=CONTRACT_SHA256,
        circuit_instance_id=instance_id,
    )


def test_real_sqlite_genesis_is_armed_pinned_and_verifiable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)

    assert path.is_file()
    assert store.require_armed().state == "armed"
    assert store.verify().version == 0
    receipts = store.receipts()
    assert len(receipts) == 1
    assert receipts[0].document["event_type"] == "initialize"
    assert (
        receipts[0].receipt_sha256
        == store.identity.genesis_receipt_sha256
    )
    assert receipts[0].document["sequence"] == 0
    assert (
        receipts[0].document["previous_receipt_sha256"]
        == "genesis"
    )
    assert (
        receipts[0].document["reset_authority_anchor"]
        == RESET_AUTHORITY_ANCHOR
    )

    reopened = DurableCircuitStore.open(
        path,
        identity=store.identity,
    )
    assert reopened.require_armed() == store.require_armed()
    assert POLICY_VERSION == "jaa11.durable-trip-only-policy.v2"
    assert circuit_policy_document() == {
        "schema_version": "jaa11.durable-circuit-store.v1",
        "policy_version": POLICY_VERSION,
        "states": ["armed", "tripped"],
        "terminal_state": "tripped",
        "reset_mutation": "withheld",
        "reset_authority_anchor": RESET_AUTHORITY_ANCHOR,
        "external_action_capability": False,
        "fixture_scope_only": True,
        "whole_file_replacement_limit": (
            "detectable_only_with_pinned_instance_and_genesis"
        ),
        "filesystem_privileged_writer_limit": (
            "surgical_partial_rewrite_undetectable_no_local_mitigation"
        ),
    }


def test_trip_and_reset_proposal_form_one_verified_terminal_chain(
    tmp_path: Path,
) -> None:
    store = new_store(tmp_path / "circuit.sqlite3")

    trip = store.trip(
        expected_version=0,
        breach_code="missing_receipt",
    )
    tripped = store.verify()
    assert tripped.state == "tripped"
    assert tripped.version == 1
    assert tripped.receipt_sequence == 1
    assert tripped.head_receipt_sha256 == trip.receipt_sha256
    assert tripped.breach_code == "missing_receipt"

    proposal = store.propose_reset(
        expected_version=1,
        reset_proposal_id=digest("proposal-1"),
        rationale_sha256=digest("operator review required"),
    )
    after = store.verify()
    assert after.state == "tripped"
    assert after.version == 1
    assert after.receipt_sequence == 2
    assert after.head_receipt_sha256 == proposal.receipt_sha256
    assert after.breach_code == "missing_receipt"
    assert proposal.document["prior_state"] == "tripped"
    assert proposal.document["next_state"] == "tripped"
    assert proposal.document["prior_version"] == 1
    assert proposal.document["next_version"] == 1
    assert proposal.document["reset_mutation_performed"] is False
    assert all(
        receipt.document["policy_version"] == POLICY_VERSION
        for receipt in store.receipts()
    )
    assert [receipt.document["event_type"] for receipt in store.receipts()] == [
        "initialize",
        "trip",
        "reset_proposal",
    ]


def test_trip_survives_reopen_in_a_separate_process(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    store.trip(expected_version=0, breach_code="changed_form_schema")

    program = """
import json
import sys
from career_automation.durable_circuit_store import (
    CircuitStateError,
    CircuitStoreIdentity,
    DurableCircuitStore,
)
identity = CircuitStoreIdentity(**json.loads(sys.argv[2]))
store = DurableCircuitStore.open(sys.argv[1], identity=identity)
snapshot = store.verify()
try:
    store.require_armed()
except CircuitStateError:
    armed_refused = True
else:
    armed_refused = False
print(json.dumps({
    "state": snapshot.state,
    "version": snapshot.version,
    "armed_refused": armed_refused,
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
    observed = json.loads(completed.stdout)
    assert observed == {
        "state": "tripped",
        "version": 1,
        "armed_refused": True,
    }


def test_concurrent_trip_race_records_exactly_one_trip(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    original = new_store(path)
    barrier = Barrier(2)

    def race(reason: str) -> str:
        contender = DurableCircuitStore.open(
            path,
            identity=original.identity,
        )
        barrier.wait()
        try:
            contender.trip(expected_version=0, breach_code=reason)
        except CircuitStateError:
            return "rejected"
        return "recorded"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(
            executor.map(
                race,
                ("missing_receipt", "changed_form_schema"),
            )
        )

    assert sorted(outcomes) == ["recorded", "rejected"]
    reopened = DurableCircuitStore.open(
        path,
        identity=original.identity,
    )
    assert reopened.verify().state == "tripped"
    receipts = reopened.receipts()
    assert len(receipts) == 2
    assert [receipt.document["event_type"] for receipt in receipts] == [
        "initialize",
        "trip",
    ]
    assert receipts[1].document["breach_code"] in {
        "missing_receipt",
        "changed_form_schema",
    }


def test_fresh_store_object_cannot_shadow_persisted_trip(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    store.trip(expected_version=0, breach_code="second_submit_attempt")

    reconstructed = DurableCircuitStore.open(
        path,
        identity=store.identity,
    )
    assert reconstructed.verify().state == "tripped"
    try:
        reconstructed.require_armed()
    except CircuitStateError:
        pass
    else:
        raise AssertionError("persisted trip was incorrectly re-armed")
