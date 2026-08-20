"""Fault controls for JAA-12 local durable status evidence."""

from __future__ import annotations

import shutil
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MethodType
from typing import Callable

import pytest

from career_automation.status_evidence_store import (
    StatusEvidenceIntegrityError,
    StatusEvidenceStore,
)
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    RawStatusEvidence,
    StatusObservation,
    classify_status_evidence,
    compile_local_export_evidence,
)


APPLICATION_ID = "durability-fault-application"
JOB_KEY = "durability-fault-job"
BASE_TIME = datetime(2032, 3, 4, 12, 0, tzinfo=timezone.utc)
CONTRACT_SHA256 = FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
WAIT_SECONDS = 30


class InjectedTransactionFault(RuntimeError):
    """Sentinel raised after transactional rows have been attempted."""


def _store(path: Path) -> StatusEvidenceStore:
    return StatusEvidenceStore.initialize(
        path,
        contract_sha256=CONTRACT_SHA256,
        store_instance_id="jaa12-durability-faults",
    )


def _evidence_and_observation(
    *,
    hour: int,
    source_record_id: str,
) -> tuple[bytes, RawStatusEvidence, StatusObservation]:
    raw_bytes = b"under_review"
    evidence = compile_local_export_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        source_kind="local_portal_export",
        source_record_id=source_record_id,
        raw_export_bytes=raw_bytes,
        observed_at=BASE_TIME + timedelta(hours=hour),
    )
    observation = classify_status_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        evidence,
        explicit_status_code="under_review",
    )
    return raw_bytes, evidence, observation


def _populated_store(
    path: Path,
) -> tuple[StatusEvidenceStore, StatusObservation]:
    store = _store(path)
    raw_bytes, evidence, observation = _evidence_and_observation(
        hour=0,
        source_record_id="initial-status",
    )
    store.archive_raw_export(evidence, raw_bytes)
    store.append_observation(observation)
    return store, observation


def _overwrite_header(content: bytearray) -> None:
    content[:16] = b"X" * 16


def _truncate_half(content: bytearray) -> None:
    del content[len(content) // 2 :]


def _remove_final_page(content: bytearray) -> None:
    assert len(content) > 4096
    del content[-4096:]


@pytest.mark.parametrize(
    ("damage_name", "damage"),
    (
        ("header-overwrite", _overwrite_header),
        ("half-truncation", _truncate_half),
        ("final-page-removal", _remove_final_page),
    ),
)
def test_physical_database_damage_is_detected_fail_closed(
    tmp_path: Path,
    damage_name: str,
    damage: Callable[[bytearray], None],
) -> None:
    original_path = tmp_path / "original.sqlite3"
    store, _observation = _populated_store(original_path)
    identity = store.identity
    snapshot = store.verify()
    damaged_path = tmp_path / f"{damage_name}.sqlite3"
    shutil.copyfile(original_path, damaged_path)
    content = bytearray(damaged_path.read_bytes())
    damage(content)
    damaged_path.write_bytes(content)

    with pytest.raises(StatusEvidenceIntegrityError) as caught:
        StatusEvidenceStore.open(damaged_path, identity=identity)
    if damage_name == "header-overwrite":
        assert isinstance(caught.value.__cause__, sqlite3.DatabaseError)

    undamaged = StatusEvidenceStore.open(original_path, identity=identity)
    assert undamaged.verify() == snapshot


def test_injected_transaction_fault_rolls_back_all_attempted_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "status.sqlite3"
    store, initial_observation = _populated_store(path)
    raw_bytes, evidence, faulted_observation = _evidence_and_observation(
        hour=1,
        source_record_id="faulted-status",
    )
    store.archive_raw_export(evidence, raw_bytes)
    before_snapshot = store.verify()
    before_receipts = store.receipts()
    before_observations = store.read_observations(APPLICATION_ID, JOB_KEY)
    assert before_observations == (initial_observation,)

    def fail_before_state_commit(
        _store_value: StatusEvidenceStore,
        _connection: sqlite3.Connection,
        _snapshot: object,
    ) -> None:
        raise InjectedTransactionFault("injected before state commit")

    monkeypatch.setattr(
        StatusEvidenceStore,
        "_write_state",
        fail_before_state_commit,
    )
    with pytest.raises(
        InjectedTransactionFault,
        match="before state commit",
    ):
        store.append_observation(faulted_observation)
    monkeypatch.undo()

    reopened = StatusEvidenceStore.open(path, identity=store.identity)
    assert reopened.verify() == before_snapshot
    assert reopened.receipts() == before_receipts
    assert reopened.read_observations(
        APPLICATION_ID,
        JOB_KEY,
    ) == before_observations
    assert faulted_observation not in reopened.read_observations(
        APPLICATION_ID,
        JOB_KEY,
    )


def test_typed_read_keeps_snapshot_during_committed_wal_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "status.sqlite3"
    store, initial_observation = _populated_store(path)
    raw_bytes, evidence, appended_observation = _evidence_and_observation(
        hour=1,
        source_record_id="concurrent-status",
    )
    store.archive_raw_export(evidence, raw_bytes)

    journal_connection = sqlite3.connect(path)
    try:
        journal_mode = journal_connection.execute(
            "PRAGMA journal_mode = WAL"
        ).fetchone()
        assert journal_mode is not None
        assert journal_mode[0].lower() == "wal"
    finally:
        journal_connection.close()

    reader = StatusEvidenceStore.open(path, identity=store.identity)
    writer = StatusEvidenceStore.open(path, identity=store.identity)
    verification_complete = threading.Event()
    writer_committed = threading.Event()
    original_verify = reader._verify_connection

    def pause_after_verification(
        _reader: StatusEvidenceStore,
        connection: sqlite3.Connection,
    ):
        snapshot = original_verify(connection)
        verification_complete.set()
        assert writer_committed.wait(WAIT_SECONDS)
        return snapshot

    monkeypatch.setattr(
        reader,
        "_verify_connection",
        MethodType(pause_after_verification, reader),
    )
    read_results: list[tuple[StatusObservation, ...]] = []
    read_errors: list[BaseException] = []

    def read_in_thread() -> None:
        try:
            read_results.append(
                reader.read_observations(APPLICATION_ID, JOB_KEY)
            )
        except BaseException as exc:
            read_errors.append(exc)

    reader_thread = threading.Thread(
        target=read_in_thread,
        name="jaa12-durable-snapshot-reader",
    )
    reader_thread.start()
    try:
        assert verification_complete.wait(WAIT_SECONDS)
        writer.append_observation(appended_observation)
    finally:
        writer_committed.set()
    reader_thread.join(WAIT_SECONDS)
    assert not reader_thread.is_alive()
    if read_errors:
        raise read_errors[0]
    assert read_results == [(initial_observation,)]
    monkeypatch.undo()

    assert reader.read_observations(APPLICATION_ID, JOB_KEY) == (
        initial_observation,
        appended_observation,
    )
    final_snapshot = reader.verify()
    assert final_snapshot.observation_count == 2
    assert final_snapshot.raw_evidence_count == 2
