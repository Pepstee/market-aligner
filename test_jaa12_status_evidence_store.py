"""Positive controls for the bounded JAA-12 durable evidence store."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from career_automation.status_evidence_store import (
    FROZEN_STATUS_EVIDENCE_STORE_POLICY,
    StatusEvidenceStore,
    status_evidence_store_policy,
)
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    classify_status_evidence,
    compile_follow_up_intent,
    compile_local_export_evidence,
    compile_status_timeline,
)


APPLICATION_ID = "jaa12-durable-application"
JOB_KEY = "jaa12-durable-job"
BASE_TIME = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)
CONTRACT_SHA256 = FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256


def _store(path: Path) -> StatusEvidenceStore:
    return StatusEvidenceStore.initialize(
        path,
        contract_sha256=CONTRACT_SHA256,
        store_instance_id="jaa12-local-status-evidence",
    )


def _evidence(
    code: str,
    *,
    hour: int,
    application_id: str = APPLICATION_ID,
    job_key: str = JOB_KEY,
    source_record_id: str | None = None,
):
    raw_bytes = code.encode("utf-8")
    evidence = compile_local_export_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=application_id,
        job_key=job_key,
        source_kind="local_portal_export",
        source_record_id=(
            source_record_id or f"{application_id}:{job_key}:{hour}"
        ),
        raw_export_bytes=raw_bytes,
        observed_at=BASE_TIME + timedelta(hours=hour),
    )
    observation = classify_status_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        evidence,
        explicit_status_code=code,
    )
    return raw_bytes, evidence, observation


def test_store_identity_policy_and_genesis_survive_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)

    assert FROZEN_STATUS_EVIDENCE_STORE_POLICY.document() == (
        status_evidence_store_policy()
    )
    assert status_evidence_store_policy()["connector_authority"] == "withheld"
    assert status_evidence_store_policy()["message_send_authority"] == (
        "withheld"
    )
    assert status_evidence_store_policy()["dependency_satisfied"] is False
    assert status_evidence_store_policy()["certifies_slice"] is False
    snapshot = store.verify()
    assert snapshot.receipt_sequence == 0
    assert snapshot.observation_count == 0
    assert snapshot.intent_count == 0
    receipts = store.receipts()
    assert len(receipts) == 1
    assert receipts[0].document["event_type"] == "initialize"
    assert receipts[0].receipt_sha256 == (
        store.identity.genesis_receipt_sha256
    )

    reopened = StatusEvidenceStore.open(path, identity=store.identity)
    assert reopened.verify() == snapshot
    assert reopened.identity == store.identity


def test_raw_export_is_content_addressed_and_reauthenticated_across_sessions(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    raw_bytes = b"untrusted free text that cannot issue instructions"
    evidence = compile_local_export_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        source_kind="local_message_export",
        source_record_id="local-export-1",
        raw_export_bytes=raw_bytes,
        observed_at=BASE_TIME,
    )

    receipt = store.archive_raw_export(evidence, raw_bytes)
    assert receipt.document["event_type"] == "archive_raw_export"
    assert receipt.document["payload"]["source_sha256"] == hashlib.sha256(
        raw_bytes
    ).hexdigest()
    assert raw_bytes.decode() not in json.dumps(receipt.document)

    reopened = StatusEvidenceStore.open(path, identity=store.identity)
    assert reopened.read_raw_export(evidence) == raw_bytes
    assert reopened.archive_raw_export(evidence, raw_bytes) == receipt
    assert reopened.verify().raw_blob_count == 1
    assert reopened.verify().raw_evidence_count == 1


def test_full_timeline_and_intent_are_durable_and_idempotent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    raw_bytes, evidence, observation = _evidence("under_review", hour=0)

    store.archive_raw_export(evidence, raw_bytes)
    reopened = StatusEvidenceStore.open(path, identity=store.identity)
    observation_receipt = reopened.append_observation(observation)
    assert reopened.append_observation(observation) == observation_receipt
    assert reopened.verify().observation_count == 1
    timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        observations=(observation,),
    )
    timeline_receipt = reopened.register_timeline(timeline)
    intent = compile_follow_up_intent(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        timeline,
        released_application_sha256="c" * 64,
        draft_sha256="d" * 64,
    )
    intent_receipt = reopened.register_follow_up_intent(intent)

    final = StatusEvidenceStore.open(path, identity=store.identity)
    assert final.register_timeline(timeline) == timeline_receipt
    assert final.register_follow_up_intent(intent) == intent_receipt
    snapshot = final.verify()
    assert snapshot.receipt_sequence == 4
    assert snapshot.raw_evidence_count == 1
    assert snapshot.observation_count == 1
    assert snapshot.timeline_count == 1
    assert snapshot.intent_count == 1
    assert intent_receipt.document["payload"]["draft_sha256"] == "d" * 64
    assert (
        intent_receipt.document["payload"]["released_application_sha256"]
        == "c" * 64
    )
    assert intent_receipt.document["payload"]["dispatch_state"] == (
        "unrepresentable"
    )


def test_monotonic_observations_and_full_timeline_survive_separate_sessions(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    raw_1, evidence_1, observation_1 = _evidence(
        "under_review",
        hour=0,
    )
    raw_2, evidence_2, observation_2 = _evidence(
        "interview_requested",
        hour=24,
    )

    store.archive_raw_export(evidence_1, raw_1)
    store.append_observation(observation_1)
    second_session = StatusEvidenceStore.open(
        path,
        identity=store.identity,
    )
    second_session.archive_raw_export(evidence_2, raw_2)
    second_session.append_observation(observation_2)
    timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        observations=(observation_1, observation_2),
    )
    second_session.register_timeline(timeline)

    third_session = StatusEvidenceStore.open(
        path,
        identity=store.identity,
    )
    assert third_session.verify().observation_count == 2
    assert third_session.verify().timeline_count == 1
    assert third_session.read_raw_export(evidence_1) == raw_1
    assert third_session.read_raw_export(evidence_2) == raw_2


def test_one_content_blob_can_authenticate_multiple_evidence_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    raw_1, evidence_1, _observation_1 = _evidence(
        "under_review",
        hour=0,
        source_record_id="same-content-first",
    )
    raw_2, evidence_2, _observation_2 = _evidence(
        "under_review",
        hour=1,
        source_record_id="same-content-second",
    )
    assert raw_1 == raw_2
    assert evidence_1.source_sha256 == evidence_2.source_sha256

    store.archive_raw_export(evidence_1, raw_1)
    store.archive_raw_export(evidence_2, raw_2)
    snapshot = store.verify()
    assert snapshot.raw_blob_count == 1
    assert snapshot.raw_evidence_count == 2
    assert store.read_raw_export(evidence_1) == raw_1
    assert store.read_raw_export(evidence_2) == raw_2
