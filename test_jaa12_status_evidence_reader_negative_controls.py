"""Negative controls for JAA-12 durable typed status reads."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from career_automation.status_evidence_store import (
    StatusEvidenceIntegrityError,
    StatusEvidenceStore,
)
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    classify_status_evidence,
    compile_local_export_evidence,
)
from career_automation.status_store_coordinator import (
    FollowUpRegistrationRequest,
    ingest_local_export,
)


APPLICATION_ID = "reader-negative-application"
JOB_KEY = "reader-negative-job"
OBSERVED_AT = datetime(2032, 2, 3, 12, 0, tzinfo=timezone.utc)
CONTRACT_SHA256 = FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256


def _populated(path: Path):
    store = StatusEvidenceStore.initialize(
        path,
        contract_sha256=CONTRACT_SHA256,
        store_instance_id="jaa12-reader-negative",
    )
    result = ingest_local_export(
        store,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        source_kind="local_message_export",
        source_record_id="reader-negative-export",
        raw_export_bytes=b"under_review",
        observed_at=OBSERVED_AT,
        explicit_status_code="under_review",
        prior_observations=(),
        follow_up=FollowUpRegistrationRequest("c" * 64, "d" * 64),
    )
    return store, result


def test_absent_exact_identity_reads_fail_closed(
    tmp_path: Path,
) -> None:
    store = StatusEvidenceStore.initialize(
        tmp_path / "status.sqlite3",
        contract_sha256=CONTRACT_SHA256,
        store_instance_id="jaa12-reader-absent",
    )
    with pytest.raises(
        StatusEvidenceIntegrityError,
        match="timeline is absent",
    ):
        store.read_timeline("0" * 64)
    with pytest.raises(
        StatusEvidenceIntegrityError,
        match="intent is absent",
    ):
        store.read_follow_up_intent("missing-key")


def test_wrong_pinned_identity_refuses_every_read(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store, _result = _populated(path)
    wrong = replace(store.identity, genesis_receipt_sha256="0" * 64)

    with pytest.raises(StatusEvidenceIntegrityError):
        StatusEvidenceStore.open(path, identity=wrong)


@pytest.mark.parametrize(
    "tamper_kind",
    (
        "malformed_json",
        "classified_state",
        "observation_hash",
        "timeline_json",
        "policy",
    ),
)
def test_direct_sql_tamper_blocks_typed_reads(
    tmp_path: Path,
    tamper_kind: str,
) -> None:
    path = tmp_path / f"{tamper_kind}.sqlite3"
    store, result = _populated(path)
    connection = sqlite3.connect(path)
    if tamper_kind == "malformed_json":
        connection.execute("DROP TRIGGER no_update_status_observation")
        connection.execute(
            "UPDATE status_observation SET content_json = ?",
            ("{",),
        )
    elif tamper_kind == "classified_state":
        connection.execute("DROP TRIGGER no_update_status_observation")
        connection.execute(
            "UPDATE status_observation SET classified_state = ?",
            ("offer",),
        )
    elif tamper_kind == "observation_hash":
        connection.execute("DROP TRIGGER no_update_status_observation")
        connection.execute(
            "UPDATE status_observation SET observation_id = ?",
            ("0" * 64,),
        )
    elif tamper_kind == "timeline_json":
        connection.execute(
            "DROP TRIGGER no_update_status_timeline_registration"
        )
        connection.execute(
            "UPDATE status_timeline_registration SET content_json = ?",
            ("{}",),
        )
    else:
        connection.execute(
            "DROP TRIGGER no_update_status_store_metadata"
        )
        connection.execute(
            "UPDATE status_store_metadata SET policy_sha256 = ?",
            ("0" * 64,),
        )
    connection.commit()
    connection.close()

    with pytest.raises(StatusEvidenceIntegrityError):
        store.read_observations(APPLICATION_ID, JOB_KEY)
    with pytest.raises(StatusEvidenceIntegrityError):
        store.read_timeline(result.timeline.timeline_id)


def test_unregistered_timeline_is_never_synthesized(
    tmp_path: Path,
) -> None:
    store = StatusEvidenceStore.initialize(
        tmp_path / "status.sqlite3",
        contract_sha256=CONTRACT_SHA256,
        store_instance_id="jaa12-reader-prefix",
    )
    raw_bytes = b"under_review"
    evidence = compile_local_export_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        source_kind="local_message_export",
        source_record_id="prefix-only",
        raw_export_bytes=raw_bytes,
        observed_at=OBSERVED_AT,
    )
    observation = classify_status_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        evidence,
        explicit_status_code="under_review",
    )
    store.archive_raw_export(evidence, raw_bytes)
    store.append_observation(observation)

    assert store.read_observations(APPLICATION_ID, JOB_KEY) == (
        observation,
    )
    assert store.read_timelines(APPLICATION_ID, JOB_KEY) == ()
    assert store.read_follow_up_intents(APPLICATION_ID, JOB_KEY) == ()


def test_reads_do_not_append_receipts_or_change_state(
    tmp_path: Path,
) -> None:
    store, result = _populated(tmp_path / "status.sqlite3")
    snapshot = store.verify()
    receipts = store.receipts()

    assert store.read_observations(APPLICATION_ID, JOB_KEY)
    assert store.read_stream_state(APPLICATION_ID, JOB_KEY) is not None
    assert store.read_timelines(APPLICATION_ID, JOB_KEY)
    assert store.read_timeline(result.timeline.timeline_id)
    assert store.read_follow_up_intents(APPLICATION_ID, JOB_KEY)
    assert store.read_follow_up_intent(result.intent.idempotency_key)

    assert store.verify() == snapshot
    assert store.receipts() == receipts


def test_reader_sees_one_consistent_snapshot_during_reserved_writer(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store, result = _populated(path)
    writer = sqlite3.connect(path)
    writer.execute("BEGIN IMMEDIATE")
    writer.execute(
        """
        UPDATE status_store_state
        SET state_integrity_sha256 = ?
        """,
        ("0" * 64,),
    )
    try:
        assert store.read_observations(APPLICATION_ID, JOB_KEY) == (
            result.observation,
        )
        assert store.read_timeline(result.timeline.timeline_id) == (
            result.timeline
        )
    finally:
        writer.rollback()
        writer.close()
    assert store.verify().observation_count == 1


def test_collection_reads_never_cross_application_or_job(
    tmp_path: Path,
) -> None:
    store, _result = _populated(tmp_path / "status.sqlite3")

    assert store.read_observations("other", JOB_KEY) == ()
    assert store.read_observations(APPLICATION_ID, "other") == ()
    assert store.read_stream_state("other", JOB_KEY) is None
    assert store.read_timelines("other", JOB_KEY) == ()
    assert store.read_follow_up_intents(APPLICATION_ID, "other") == ()
