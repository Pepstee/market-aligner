"""Adversarial controls for the bounded JAA-12 durable evidence store."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from career_automation.status_evidence_store import (
    FROZEN_STATUS_EVIDENCE_STORE_POLICY,
    StatusEvidenceConflictError,
    StatusEvidenceIntegrityError,
    StatusEvidenceStateError,
    StatusEvidenceStore,
)
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    classify_status_evidence,
    compile_follow_up_intent,
    compile_local_export_evidence,
    compile_status_timeline,
)
from test_jaa12_status_evidence_store import (
    APPLICATION_ID,
    BASE_TIME,
    CONTRACT_SHA256,
    JOB_KEY,
    _evidence,
    _store,
)


def _populated_store(path: Path):
    store = _store(path)
    raw_bytes, evidence, observation = _evidence(
        "under_review",
        hour=0,
    )
    store.archive_raw_export(evidence, raw_bytes)
    store.append_observation(observation)
    timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        observations=(observation,),
    )
    store.register_timeline(timeline)
    intent = compile_follow_up_intent(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        timeline,
        released_application_sha256="c" * 64,
        draft_sha256="d" * 64,
    )
    return store, evidence, observation, timeline, intent


def test_archive_rejects_wrong_bytes_and_noncanonical_contract(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    raw_bytes, evidence, _observation = _evidence(
        "under_review",
        hour=0,
    )
    with pytest.raises(ValueError, match="differ from source hash"):
        store.archive_raw_export(evidence, raw_bytes + b"-tampered")
    with pytest.raises(ValueError, match="bytes are required"):
        store.archive_raw_export(evidence, b"")
    with pytest.raises(ValueError, match="canonical contract"):
        StatusEvidenceStore.initialize(
            tmp_path / "wrong.sqlite3",
            contract_sha256="0" * 64,
            store_instance_id="wrong-contract",
        )
    with pytest.raises(ValueError, match="cannot connect, send, or certify"):
        replace(
            FROZEN_STATUS_EVIDENCE_STORE_POLICY,
            message_send_authority="authorized",
        )


def test_subset_timeline_registration_fails_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    values = [
        _evidence("under_review", hour=0),
        _evidence("interview_requested", hour=1),
    ]
    for raw_bytes, evidence, observation in values:
        store.archive_raw_export(evidence, raw_bytes)
        store.append_observation(observation)
    subset = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        observations=(values[0][2],),
    )

    with pytest.raises(
        StatusEvidenceStateError,
        match="complete durable observation set",
    ):
        store.register_timeline(subset)


def test_durable_terminal_state_permanently_blocks_follow_up(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store, _evidence_1, observation_1, timeline, intent = _populated_store(
        path
    )
    store.register_follow_up_intent(intent)
    raw_2, evidence_2, observation_2 = _evidence(
        "rejected_by_employer",
        hour=1,
    )
    store.archive_raw_export(evidence_2, raw_2)
    store.append_observation(observation_2)
    terminal_timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        observations=(observation_1, observation_2),
    )
    store.register_timeline(terminal_timeline)

    with pytest.raises(
        StatusEvidenceStateError,
        match="terminal status blocks",
    ):
        store.register_follow_up_intent(intent)
    assert timeline.final_state.value == "screening"


def test_first_idempotency_identity_wins_across_timeline_updates(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store, _evidence_1, observation_1, _timeline, first_intent = (
        _populated_store(path)
    )
    store.register_follow_up_intent(first_intent)
    raw_2, evidence_2, observation_2 = _evidence(
        "under_review",
        hour=24,
    )
    store.archive_raw_export(evidence_2, raw_2)
    store.append_observation(observation_2)
    with pytest.raises(
        StatusEvidenceStateError,
        match="complete durable observation set",
    ):
        store.register_timeline(_timeline)
    updated_timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        observations=(observation_1, observation_2),
    )
    store.register_timeline(updated_timeline)
    changed_intent = compile_follow_up_intent(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        updated_timeline,
        released_application_sha256="c" * 64,
        draft_sha256="d" * 64,
    )
    assert changed_intent.idempotency_key == first_intent.idempotency_key
    assert changed_intent.intent_sha256 != first_intent.intent_sha256

    with pytest.raises(
        StatusEvidenceConflictError,
        match="already binds another intent",
    ):
        store.register_follow_up_intent(changed_intent)


@pytest.mark.parametrize(
    "tamper_kind",
    (
        "raw",
        "receipt",
        "chain",
        "row",
        "state",
        "stream",
        "timeline",
        "intent",
    ),
)
def test_tampered_content_receipt_chain_or_row_fails_closed(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    path = tmp_path / f"{tamper_kind}.sqlite3"
    store, _evidence_1, _observation_1, _timeline, _intent = (
        _populated_store(path)
    )
    if tamper_kind == "intent":
        store.register_follow_up_intent(_intent)
    connection = sqlite3.connect(path)
    if tamper_kind == "raw":
        connection.execute("DROP TRIGGER no_update_raw_export_blob")
        connection.execute(
            "UPDATE raw_export_blob SET raw_bytes = ?",
            (b"tampered",),
        )
    elif tamper_kind == "receipt":
        connection.execute("DROP TRIGGER no_update_status_store_receipt")
        connection.execute(
            """
            UPDATE status_store_receipt SET content_json = ?
            WHERE sequence = 1
            """,
            ("{}",),
        )
    elif tamper_kind == "chain":
        connection.execute("DROP TRIGGER no_update_status_store_receipt")
        connection.execute(
            """
            UPDATE status_store_receipt
            SET previous_receipt_sha256 = ?
            WHERE sequence = 1
            """,
            ("0" * 64,),
        )
    elif tamper_kind == "row":
        connection.execute("DROP TRIGGER no_update_status_observation")
        connection.execute(
            "UPDATE status_observation SET content_json = ?",
            ("{}",),
        )
    elif tamper_kind == "state":
        connection.execute(
            """
            UPDATE status_store_state
            SET head_receipt_sha256 = ?
            """,
            ("0" * 64,),
        )
    elif tamper_kind == "stream":
        connection.execute(
            """
            UPDATE status_application_stream
            SET stream_integrity_sha256 = ?
            """,
            ("0" * 64,),
        )
    elif tamper_kind == "timeline":
        connection.execute(
            "DROP TRIGGER no_update_status_timeline_registration"
        )
        connection.execute(
            """
            UPDATE status_timeline_registration
            SET content_json = ?
            """,
            ("{}",),
        )
    else:
        connection.execute(
            "DROP TRIGGER no_update_follow_up_intent_registration"
        )
        connection.execute(
            """
            UPDATE follow_up_intent_registration
            SET content_json = ?
            """,
            ("{}",),
        )
    connection.commit()
    connection.close()

    with pytest.raises(StatusEvidenceIntegrityError):
        StatusEvidenceStore.open(path, identity=store.identity)


def test_append_tables_reject_update_and_delete(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    _store_value, _evidence_1, _observation_1, _timeline, _intent = (
        _populated_store(path)
    )
    connection = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute(
            "DELETE FROM status_store_receipt WHERE sequence = 1"
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute(
            "UPDATE raw_export_blob SET byte_count = byte_count + 1"
        )
    connection.close()


def test_cross_application_and_job_timeline_isolation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    raw_bytes, evidence, observation = _evidence(
        "under_review",
        hour=0,
        application_id="other-application",
        job_key="other-job",
    )
    timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id="other-application",
        job_key="other-job",
        observations=(observation,),
    )
    store.archive_raw_export(evidence, raw_bytes)

    with pytest.raises(
        StatusEvidenceStateError,
        match="complete durable observation set",
    ):
        store.register_timeline(timeline)


def test_nonmonotonic_append_is_rejected_across_store_sessions(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    later = _evidence(
        "under_review",
        hour=2,
        source_record_id="later-status",
    )
    earlier = _evidence(
        "under_review",
        hour=1,
        source_record_id="earlier-status",
    )
    store.archive_raw_export(later[1], later[0])
    store.append_observation(later[2])
    reopened = StatusEvidenceStore.open(path, identity=store.identity)
    reopened.archive_raw_export(earlier[1], earlier[0])
    with pytest.raises(
        StatusEvidenceStateError,
        match="strictly monotonic",
    ):
        reopened.append_observation(earlier[2])


def test_naive_clock_and_unpinned_store_identity_are_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="timezone"):
        compile_local_export_evidence(
            FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
            application_id=APPLICATION_ID,
            job_key=JOB_KEY,
            source_kind="local_portal_export",
            source_record_id="naive-clock",
            raw_export_bytes=b"under_review",
            observed_at=datetime(2030, 1, 1, 12, 0),
        )
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    with pytest.raises(TypeError, match="pinned identity"):
        StatusEvidenceStore.open(path, identity="caller-asserted")
    with pytest.raises(
        StatusEvidenceIntegrityError,
        match="pinned identity",
    ):
        StatusEvidenceStore.open(
            path,
            identity=replace(
                store.identity,
                genesis_receipt_sha256="0" * 64,
            ),
        )
    with pytest.raises(ValueError, match="filesystem SQLite path"):
        StatusEvidenceStore.initialize(
            ":memory:",
            contract_sha256=CONTRACT_SHA256,
            store_instance_id="memory-store",
        )


def test_send_state_is_unrepresentable_and_module_has_no_capability(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store, _evidence_1, _observation_1, _timeline, intent = (
        _populated_store(path)
    )
    for changed in (
        {"sent_count": 1},
        {"send_authority": "authorized"},
        {"connector_authority": "mailbox"},
        {"dependency_satisfied": True},
        {"certifies_slice": True},
    ):
        with pytest.raises(ValueError, match="cannot send or certify"):
            replace(intent, **changed)
    assert all(
        "send" not in name.lower()
        for name in dir(store)
        if callable(getattr(store, name))
    )

    source_value = __import__(
        "career_automation.status_evidence_store",
        fromlist=[""],
    ).__file__
    assert source_value is not None
    text = Path(source_value).read_text(encoding="utf-8")
    for forbidden in (
        "aiohttp",
        "imaplib",
        "mailbox.",
        "playwright",
        "poplib",
        "requests.",
        "selenium",
        "smtplib",
        "socket",
        "subprocess",
        "urllib.request",
        "page.goto",
        "send_message",
        "connector_authority: str = \"authorized\"",
        "certifies_slice: bool = True",
    ):
        assert forbidden not in text


def test_observation_requires_archived_exact_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    _raw_bytes, _evidence_1, observation = _evidence(
        "under_review",
        hour=0,
    )
    with pytest.raises(
        StatusEvidenceStateError,
        match="requires exact archived raw evidence",
    ):
        store.append_observation(observation)

    changed_raw = compile_local_export_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        source_kind="local_portal_export",
        source_record_id="other-source",
        raw_export_bytes=b"under_review",
        observed_at=BASE_TIME,
    )
    changed_observation = classify_status_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        changed_raw,
        explicit_status_code="under_review",
    )
    with pytest.raises(StatusEvidenceStateError):
        store.append_observation(changed_observation)
