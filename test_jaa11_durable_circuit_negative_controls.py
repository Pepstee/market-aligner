"""Adversarial controls for the unintegrated durable JAA-11 circuit."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation.durable_circuit_store import (
    POLICY_VERSION,
    RESET_AUTHORITY_ANCHOR,
    CircuitIntegrityError,
    CircuitStateError,
    CircuitStoreIdentity,
    DurableCircuitStore,
    StaleCircuitVersionError,
)
from career_automation.official_ats_adapter import (
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
)
from test_jaa11_durable_circuit_acceptance import (
    CONTRACT_SHA256,
    INSTANCE_ID,
    digest,
    new_store,
)


def execute(path: Path, statement: str, parameters: tuple = ()) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(statement, parameters)
        connection.commit()
    finally:
        connection.close()


def trip(store: DurableCircuitStore) -> None:
    store.trip(expected_version=0, breach_code="missing_receipt")


def test_memory_uri_existing_and_missing_paths_are_refused(
    tmp_path: Path,
) -> None:
    for path in (":memory:", "file::memory:?cache=shared"):
        with pytest.raises(ValueError, match="filesystem SQLite path"):
            DurableCircuitStore.initialize(
                path,
                adapter_contract_sha256=CONTRACT_SHA256,
                circuit_instance_id=INSTANCE_ID,
            )

    existing = tmp_path / "existing.sqlite3"
    existing.write_bytes(b"not a database")
    with pytest.raises(FileExistsError):
        new_store(existing)

    identity = CircuitStoreIdentity(
        CONTRACT_SHA256,
        INSTANCE_ID,
        digest("missing-genesis"),
    )
    with pytest.raises(CircuitIntegrityError, match="missing or replaced"):
        DurableCircuitStore.open(
            tmp_path / "missing.sqlite3",
            identity=identity,
        )


def test_only_the_canonical_fixture_contract_can_initialize(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="canonical contract"):
        DurableCircuitStore.initialize(
            tmp_path / "wrong.sqlite3",
            adapter_contract_sha256=digest("different contract"),
            circuit_instance_id=INSTANCE_ID,
        )
    assert (
        FROZEN_FIXTURE_ADAPTER_CONTRACT.contract_sha256
        == CONTRACT_SHA256
    )


def test_database_replacement_is_detected_by_pinned_genesis(
    tmp_path: Path,
) -> None:
    original_path = tmp_path / "original.sqlite3"
    replacement_path = tmp_path / "replacement.sqlite3"
    original = new_store(original_path)
    replacement = new_store(replacement_path)
    assert (
        original.identity.genesis_receipt_sha256
        != replacement.identity.genesis_receipt_sha256
    )

    shutil.copyfile(replacement_path, original_path)
    with pytest.raises(CircuitIntegrityError):
        DurableCircuitStore.open(
            original_path,
            identity=original.identity,
        )


@pytest.mark.parametrize(
    "statement",
    (
        "UPDATE circuit_state SET state = 'tripped'",
        "UPDATE circuit_state SET version = version + 10",
        "UPDATE circuit_state SET receipt_sequence = 10",
        "UPDATE circuit_state SET head_receipt_sha256 = "
        "'0000000000000000000000000000000000000000000000000000000000000000'",
    ),
)
def test_direct_state_tampering_fails_closed(
    tmp_path: Path,
    statement: str,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    execute(path, statement)
    with pytest.raises(CircuitIntegrityError):
        store.verify()
    with pytest.raises(CircuitIntegrityError):
        store.require_armed()


def test_receipt_byte_tampering_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    trip(store)
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "SELECT content_json FROM circuit_receipt WHERE sequence = 1"
        ).fetchone()
        document = json.loads(row[0])
        document["breach_code"] = "changed_form_schema"
        connection.execute(
            "UPDATE circuit_receipt SET content_json = ? WHERE sequence = 1",
            (json.dumps(document, sort_keys=True),),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(CircuitIntegrityError):
        store.verify()


def test_receipt_deletion_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    trip(store)
    execute(path, "DELETE FROM circuit_receipt WHERE sequence = 0")
    with pytest.raises(CircuitIntegrityError, match="sequence has gaps"):
        store.verify()


def test_receipt_reordering_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    trip(store)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE circuit_receipt SET sequence = sequence + 10"
        )
        connection.execute(
            "UPDATE circuit_receipt SET sequence = "
            "CASE sequence WHEN 10 THEN 1 WHEN 11 THEN 0 END"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(CircuitIntegrityError):
        store.verify()


def test_stale_version_does_not_write(tmp_path: Path) -> None:
    store = new_store(tmp_path / "circuit.sqlite3")
    before = store.verify()
    with pytest.raises(StaleCircuitVersionError):
        store.trip(
            expected_version=before.version + 1,
            breach_code="missing_receipt",
        )
    assert store.verify() == before
    assert len(store.receipts()) == 1


def test_cross_contract_and_cross_instance_open_are_refused(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    identities = (
        replace(
            store.identity,
            adapter_contract_sha256=digest("other contract"),
        ),
        replace(store.identity, circuit_instance_id="another-instance"),
    )
    for identity in identities:
        with pytest.raises(CircuitIntegrityError):
            DurableCircuitStore.open(path, identity=identity)


def test_duplicate_and_conflicting_trip_leave_original_intact(
    tmp_path: Path,
) -> None:
    store = new_store(tmp_path / "circuit.sqlite3")
    original = store.trip(
        expected_version=0,
        breach_code="missing_receipt",
    )
    before = store.verify()
    for reason in ("missing_receipt", "changed_form_schema"):
        with pytest.raises(CircuitStateError, match="already recorded"):
            store.trip(expected_version=1, breach_code=reason)
        assert store.verify() == before
        assert store.receipts()[1].receipt_sha256 == original.receipt_sha256


def test_invalid_breach_cannot_trip(tmp_path: Path) -> None:
    store = new_store(tmp_path / "circuit.sqlite3")
    with pytest.raises(ValueError, match="breach code"):
        store.trip(expected_version=0, breach_code="operator_dislikes_result")
    assert store.require_armed().version == 0
    assert len(store.receipts()) == 1


def test_reset_proposal_cannot_rearm_or_replay(tmp_path: Path) -> None:
    store = new_store(tmp_path / "circuit.sqlite3")
    trip(store)
    proposal_id = digest("reset proposal")
    proposal = store.propose_reset(
        expected_version=1,
        reset_proposal_id=proposal_id,
        rationale_sha256=digest("reviewed rationale"),
    )
    after = store.verify()
    assert after.state == "tripped"
    assert after.version == 1
    assert (
        proposal.document["reset_authority_anchor"]
        == RESET_AUTHORITY_ANCHOR
    )
    assert proposal.document["reset_mutation_performed"] is False
    with pytest.raises(CircuitStateError, match="replay"):
        store.propose_reset(
            expected_version=1,
            reset_proposal_id=proposal_id,
            rationale_sha256=digest("reviewed rationale"),
        )
    assert store.verify() == after
    assert len(store.receipts()) == 3
    assert not hasattr(store, "reset")
    with pytest.raises(TypeError):
        store.propose_reset(
            expected_version=1,
            reset_proposal_id=digest("authority substitution"),
            rationale_sha256=digest("rationale"),
            reset_authority_sha256=digest("caller supplied authority"),
        )


def test_reset_authority_substitution_in_receipt_is_detected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    trip(store)
    store.propose_reset(
        expected_version=1,
        reset_proposal_id=digest("reset proposal"),
        rationale_sha256=digest("rationale"),
    )
    connection = sqlite3.connect(path)
    try:
        row = connection.execute(
            "SELECT content_json FROM circuit_receipt WHERE sequence = 2"
        ).fetchone()
        document = json.loads(row[0])
        document["reset_authority_anchor"] = (
            "caller_supplied_self_consistent_hash"
        )
        connection.execute(
            "UPDATE circuit_receipt SET content_json = ? WHERE sequence = 2",
            (
                json.dumps(
                    document,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(CircuitIntegrityError):
        store.verify()


def test_direct_rearming_after_trip_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    trip(store)
    execute(
        path,
        "UPDATE circuit_state SET state = 'armed', breach_code = NULL",
    )
    reconstructed = DurableCircuitStore(
        path,
        store.identity,
    )
    with pytest.raises(CircuitIntegrityError):
        reconstructed.require_armed()


def test_reset_proposal_requires_current_tripped_version(
    tmp_path: Path,
) -> None:
    store = new_store(tmp_path / "circuit.sqlite3")
    with pytest.raises(CircuitStateError, match="tripped"):
        store.propose_reset(
            expected_version=0,
            reset_proposal_id=digest("premature"),
            rationale_sha256=digest("rationale"),
        )
    trip(store)
    before = store.verify()
    with pytest.raises(StaleCircuitVersionError):
        store.propose_reset(
            expected_version=0,
            reset_proposal_id=digest("stale"),
            rationale_sha256=digest("rationale"),
        )
    assert store.verify() == before


def test_v1_policy_database_is_refused_without_migration(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    store = new_store(path)
    assert POLICY_VERSION == "jaa11.durable-trip-only-policy.v2"
    v1_policy = {
        "schema_version": "jaa11.durable-circuit-store.v1",
        "policy_version": "jaa11.durable-trip-only-policy.v1",
        "states": ["armed", "tripped"],
        "terminal_state": "tripped",
        "reset_mutation": "withheld",
        "reset_authority_anchor": RESET_AUTHORITY_ANCHOR,
        "external_action_capability": False,
        "fixture_scope_only": True,
        "whole_file_replacement_limit": (
            "detectable_only_with_pinned_instance_and_genesis"
        ),
    }
    policy_json = json.dumps(
        v1_policy,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    execute(
        path,
        """
        UPDATE circuit_metadata
        SET policy_json = ?, policy_sha256 = ?
        WHERE singleton = 1
        """,
        (
            policy_json,
            hashlib.sha256(policy_json.encode("utf-8")).hexdigest(),
        ),
    )
    with pytest.raises(
        CircuitIntegrityError,
        match="policy differs",
    ):
        store.verify()
