"""Adversarial controls for the fixture-only JAA-10 observation ledger."""

from __future__ import annotations

import ast
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import career_automation.shadow_observation_ledger as ledger_module
from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    normalized_submit_event_sha256,
)
from career_automation.shadow_observation_ledger import (
    ASSESSMENT,
    CLOCK_AUTHENTICATION,
    FILESYSTEM_WRITER_LIMIT,
    MONOTONIC_WITNESS_SCOPE,
    SPAN_MEANING,
    ObservationLedgerIntegrityError,
    ObservationLedgerStateError,
    ShadowObservationLedger,
)
from test_jaa10_independent_acceptance import _observation


def _store(tmp_path: Path) -> ShadowObservationLedger:
    return ShadowObservationLedger.initialize(
        tmp_path / "shadow-observations.sqlite3",
        contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
    )


def _source_observation(identifier: str = "negative"):
    return _observation(
        identifier,
        datetime(2024, 3, 1, tzinfo=timezone.utc),
    )


def test_memory_uri_existing_and_noncanonical_contracts_are_rejected(
    tmp_path,
) -> None:
    with pytest.raises(ValueError, match="filesystem SQLite path"):
        ShadowObservationLedger.initialize(
            ":memory:",
            contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
        )
    with pytest.raises(ValueError, match="filesystem SQLite path"):
        ShadowObservationLedger.initialize(
            "file:fixture?mode=memory&cache=shared",
            contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
        )
    with pytest.raises(ValueError, match="canonical frozen contract"):
        ShadowObservationLedger.initialize(
            tmp_path / "wrong.sqlite3",
            contract_sha256="f" * 64,
        )
    existing = tmp_path / "existing.sqlite3"
    existing.touch()
    with pytest.raises(FileExistsError):
        ShadowObservationLedger.initialize(
            existing,
            contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
        )


def test_callers_cannot_supply_recording_time_or_session_identity(
    tmp_path,
) -> None:
    store = _store(tmp_path)
    session = store.begin_session()
    observation = _source_observation()

    with pytest.raises(TypeError):
        store.begin_session(session_id="caller-controlled")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        store.record_observation(
            session,
            observation,
            host_recorded_at_utc="2030-01-01T00:00:00+00:00",
        )


def test_reopened_store_rejects_stale_session_handle(tmp_path) -> None:
    store = _store(tmp_path)
    pending = store.begin_session()
    reopened = ShadowObservationLedger.open(
        store.database_path,
        identity=store.identity,
    )

    with pytest.raises(ObservationLedgerStateError, match="stale"):
        reopened.record_observation(pending, _source_observation())
    assert reopened.summary()["sessions_without_observation"] == 1


def test_one_observation_per_session_and_global_duplicate_hash(tmp_path) -> None:
    store = _store(tmp_path)
    observation = _source_observation()
    first_session = store.begin_session()
    store.record_observation(first_session, observation)

    with pytest.raises(ObservationLedgerStateError):
        store.record_observation(first_session, observation)
    second_session = store.begin_session()
    with pytest.raises(ObservationLedgerStateError):
        store.record_observation(second_session, observation)
    assert store.summary()["record_count"] == 1
    assert store.summary()["sessions_without_observation"] == 1


def test_concurrent_append_to_same_session_has_exactly_one_winner(
    tmp_path,
) -> None:
    store = _store(tmp_path)
    session = store.begin_session()
    first = _source_observation("concurrent-first")
    second = _source_observation("concurrent-second")

    def append(observation) -> str:
        try:
            store.record_observation(session, observation)
        except ObservationLedgerStateError:
            return "rejected"
        return "recorded"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(append, (first, second)))

    assert sorted(outcomes) == ["recorded", "rejected"]
    assert store.summary()["record_count"] == 1


def test_host_clock_step_back_aborts_append_without_a_partial_receipt(
    tmp_path,
    monkeypatch,
) -> None:
    store = _store(tmp_path)
    receipt_count = len(store.receipts())
    head = store.receipts()[-1].document
    earlier = (
        datetime.fromisoformat(str(head["host_recorded_at_utc"])) - timedelta(seconds=1)
    ).isoformat()
    monotonic_ns = int(head["host_monotonic_ns"]) + 1
    monkeypatch.setattr(
        ledger_module,
        "_host_time",
        lambda: (earlier, monotonic_ns),
    )

    with pytest.raises(ObservationLedgerStateError, match="moved backwards"):
        store.begin_session()

    assert len(store.receipts()) == receipt_count


def test_append_only_triggers_block_direct_update_and_delete(tmp_path) -> None:
    store = _store(tmp_path)
    connection = sqlite3.connect(store.database_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE ledger_receipt SET event_type = 'session_open'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM ledger_metadata")
    finally:
        connection.close()
    store.verify()


@pytest.mark.parametrize(
    ("table", "column", "value"),
    (
        ("ledger_receipt", "event_type", "session_open"),
        ("ledger_metadata", "policy_version", "mutated-policy"),
        ("ledger_metadata", "genesis_nonce", "f" * 64),
        ("ledger_metadata", "fixture_policy_sha256", "f" * 64),
    ),
)
def test_full_chain_verification_detects_privileged_partial_rewrite(
    tmp_path,
    table,
    column,
    value,
) -> None:
    store = _store(tmp_path)
    connection = sqlite3.connect(store.database_path)
    try:
        connection.execute("DROP TRIGGER ledger_receipt_no_update")
        connection.execute("DROP TRIGGER ledger_metadata_no_update")
        connection.execute(
            f"UPDATE {table} SET {column} = ?",
            (value,),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ObservationLedgerIntegrityError):
        store.verify()


def test_missing_or_replaced_database_fails_closed(tmp_path) -> None:
    store = _store(tmp_path)
    database = store.database_path
    moved = tmp_path / "moved.sqlite3"
    database.rename(moved)
    with pytest.raises(
        ObservationLedgerIntegrityError,
        match="missing or replaced",
    ):
        store.verify()

    database.touch()
    with pytest.raises(
        ObservationLedgerIntegrityError,
        match="missing or replaced",
    ):
        store.verify()


def test_self_consistent_alternative_lineage_is_not_canonical(tmp_path) -> None:
    store = _store(tmp_path)
    session = store.begin_session()
    observation = _source_observation()
    alternative_workflow = "f" * 64
    alternative = replace(
        observation,
        workflow_sha256=alternative_workflow,
        normalized_submit_event_sha256=normalized_submit_event_sha256(
            workflow_sha256=alternative_workflow,
            receipt_id=observation.receipt_id,
            receipt_payload_sha256=observation.receipt_payload_sha256,
            screenshot_sha256=observation.screenshot_sha256,
            field_map_sha256=observation.field_map_sha256,
        ),
    )

    with pytest.raises(ValueError, match="canonical frozen contract"):
        store.record_observation(session, alternative)
    assert store.summary()["sessions_without_observation"] == 1


def test_summary_vocabulary_cannot_be_mistaken_for_live_evidence(
    tmp_path,
) -> None:
    summary = _store(tmp_path).summary()
    serialized = repr(summary).lower()

    assert summary["assessment"] == ASSESSMENT
    assert summary["span_meaning"] == SPAN_MEANING
    assert summary["policy"]["clock_authentication"] == CLOCK_AUTHENTICATION
    assert summary["policy"]["monotonic_witness_scope"] == MONOTONIC_WITNESS_SCOPE
    assert (
        summary["policy"]["filesystem_privileged_writer_limit"]
        == FILESYSTEM_WRITER_LIMIT
    )
    assert "24 hour" not in serialized
    assert "24h" not in serialized
    assert "minimum_shadow_separation" not in serialized
    for forbidden in (
        "satisfied",
        "certified",
        "eligible",
        "accepted",
        "ratified",
        "separation_met",
    ):
        assert forbidden not in serialized
    assert summary["policy"]["metrics_evaluated"] is False


def test_cross_process_monotonic_values_are_not_compared(tmp_path) -> None:
    store = _store(tmp_path)
    parent_token = store.receipts()[0].document["process_token"]
    identity = store.identity
    child = """
import sys
from datetime import datetime, timezone
import career_automation.shadow_observation_ledger as module
from career_automation.shadow_observation_ledger import (
    ObservationLedgerIdentity,
    ShadowObservationLedger,
)
identity = ObservationLedgerIdentity(*sys.argv[2:6])
store = ShadowObservationLedger.open(sys.argv[1], identity=identity)
module._host_time = lambda: (
    datetime.now(timezone.utc).isoformat(),
    1,
)
store.begin_session()
"""
    repository_root = Path(__file__).resolve().parents[2]
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            (
                str(repository_root / "internal" / "jaa"),
                str(repository_root / "src"),
                os.environ.get("PYTHONPATH", ""),
            )
        ),
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            child,
            str(store.database_path),
            identity.contract_sha256,
            identity.ledger_instance_id,
            identity.genesis_receipt_sha256,
            identity.fixture_policy_sha256,
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    receipts = store.receipts()
    assert receipts[-1].document["host_monotonic_ns"] == 1
    assert receipts[-1].document["process_token"] != parent_token
    assert store.summary()["sessions_without_observation"] == 1


def test_module_has_no_external_action_or_browser_capability() -> None:
    source_path = Path(ledger_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )

    assert imports <= {
        "__future__",
        "career_automation",
        "dataclasses",
        "datetime",
        "hashlib",
        "json",
        "os",
        "pathlib",
        "sqlite3",
        "time",
        "types",
        "typing",
    }
    assert "playwright" not in source.lower()
    assert "browser" not in source.lower()
    assert "requests" not in source.lower()
    assert "subprocess" not in source.lower()
