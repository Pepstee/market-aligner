"""Positive controls for the bounded JAA-12 durable coordinator."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from career_automation.status_evidence_store import StatusEvidenceStore
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    censor_status_silence,
    classify_status_evidence,
    compile_local_export_evidence,
)
from career_automation.status_store_coordinator import (
    COORDINATOR_POLICY,
    COORDINATOR_POLICY_SHA256,
    PIPELINE_ORDER,
    FollowUpRegistrationRequest,
    ingest_local_export,
    status_store_coordinator_policy,
)


APPLICATION_ID = "jaa12-coordinator-application"
JOB_KEY = "jaa12-coordinator-job"
BASE_TIME = datetime(2031, 2, 3, 12, 0, tzinfo=timezone.utc)
CONTRACT_SHA256 = FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256


def _store(path: Path) -> StatusEvidenceStore:
    return StatusEvidenceStore.initialize(
        path,
        contract_sha256=CONTRACT_SHA256,
        store_instance_id="jaa12-status-store-coordinator",
    )


def _ingest(
    store: StatusEvidenceStore,
    *,
    code: str,
    hour: int,
    prior=(),
    raw_bytes: bytes | None = None,
    source_record_id: str | None = None,
    censored_silence=(),
    follow_up: FollowUpRegistrationRequest | None = None,
):
    return ingest_local_export(
        store,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        source_kind="local_portal_export",
        source_record_id=source_record_id or f"export-{hour}",
        raw_export_bytes=(
            code.encode("utf-8") if raw_bytes is None else raw_bytes
        ),
        observed_at=BASE_TIME + timedelta(hours=hour),
        explicit_status_code=code,
        prior_observations=prior,
        censored_silence=censored_silence,
        follow_up=follow_up,
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def test_coordinator_policy_is_frozen_hash_bound_and_non_authorizing() -> None:
    policy = status_store_coordinator_policy()

    assert dict(COORDINATOR_POLICY) == policy
    assert policy["pipeline_order"] == PIPELINE_ORDER
    assert policy["partial_progress"] == "truthful_receipted_steps"
    assert policy["atomicity_across_steps"] == "absent"
    assert policy["durable_read_api"] == "absent"
    assert policy["follow_up_reference_hashes"] == (
        "caller_supplied_structural_references"
    )
    assert policy["connector_authority"] == "withheld"
    assert policy["send_authority"] == "withheld"
    assert policy["objective_satisfied"] is False
    assert policy["dependency_satisfied"] is False
    assert policy["production_certification"] == "withheld"
    assert policy["certifies_slice"] is False
    assert policy["external_action_capability"] is False
    assert hashlib.sha256(
        _canonical_json(policy).encode("utf-8")
    ).hexdigest() == COORDINATOR_POLICY_SHA256

    policy["connector_authority"] = "mutated-copy"
    assert COORDINATOR_POLICY["connector_authority"] == "withheld"


def test_full_pipeline_without_follow_up_is_receipted(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")

    result = _ingest(store, code="under_review", hour=0)

    assert result.observation.raw_evidence == result.evidence
    assert result.observation.classified_state.value == "screening"
    assert result.timeline.observations == (result.observation,)
    assert result.timeline.final_state.value == "screening"
    assert result.intent is None
    assert result.intent_receipt is None
    assert result.archive_receipt.document["sequence"] == 1
    assert result.observation_receipt.document["sequence"] == 2
    assert result.timeline_receipt.document["sequence"] == 3
    assert store.read_raw_export(result.evidence) == b"under_review"
    snapshot = store.verify()
    assert snapshot.receipt_sequence == 3
    assert snapshot.raw_evidence_count == 1
    assert snapshot.observation_count == 1
    assert snapshot.timeline_count == 1
    assert snapshot.intent_count == 0
    assert result.atomicity_across_steps == "absent"
    assert result.partial_progress == "truthful_receipted_steps"
    assert result.external_action_capability is False
    assert not hasattr(result, "dispatch_state")
    assert not hasattr(result, "sent_count")


def test_full_pipeline_with_follow_up_is_structurally_non_sendable(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    request = FollowUpRegistrationRequest(
        released_application_sha256="c" * 64,
        draft_sha256="d" * 64,
    )

    result = _ingest(
        store,
        code="under_review",
        hour=0,
        follow_up=request,
    )

    assert result.intent is not None
    assert result.intent_receipt is not None
    assert result.intent.released_application_sha256 == "c" * 64
    assert result.intent.draft_sha256 == "d" * 64
    assert result.intent.connector_authority == "withheld"
    assert result.intent.send_authority == "withheld"
    assert result.intent.sent_count == 0
    assert result.intent_receipt.document["sequence"] == 4
    assert result.intent_receipt.document["payload"]["dispatch_state"] == (
        "unrepresentable"
    )
    assert result.follow_up_reference_hashes == (
        "caller_supplied_structural_references"
    )
    assert store.verify().intent_count == 1


def test_unknown_status_abstains_and_silence_remains_censored(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    silence = censor_status_silence(
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        as_of=BASE_TIME + timedelta(hours=2),
    )

    result = _ingest(
        store,
        code="free-text-status",
        raw_bytes=b"untrusted message body",
        hour=0,
        censored_silence=(silence,),
    )

    assert result.observation.abstained is True
    assert result.observation.classified_state is None
    assert result.observation.instruction_authority is False
    assert result.observation.candidate_fact_authority is False
    assert result.timeline.final_state.value == "receipt_confirmed"
    assert result.timeline.censored_silence == (silence,)
    assert result.timeline.censored_silence[0].rejection_inferred is False
    assert store.read_raw_export(result.evidence) == (
        b"untrusted message body"
    )


def test_multiple_observations_use_the_exact_prior_typed_history(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    first = _ingest(store, code="under_review", hour=0)

    second = _ingest(
        store,
        code="interview_requested",
        hour=1,
        prior=(first.observation,),
    )

    assert second.timeline.observations == (
        first.observation,
        second.observation,
    )
    assert second.timeline.transitions == (
        ("receipt_confirmed", "screening"),
        ("screening", "interview"),
    )
    assert second.timeline.final_state.value == "interview"
    snapshot = store.verify()
    assert snapshot.raw_evidence_count == 2
    assert snapshot.observation_count == 2
    assert snapshot.timeline_count == 2


def test_identical_retry_after_reopen_returns_byte_identical_receipts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    request = FollowUpRegistrationRequest("c" * 64, "d" * 64)
    first = _ingest(
        store,
        code="under_review",
        hour=0,
        follow_up=request,
    )
    before = store.verify()

    reopened = StatusEvidenceStore.open(path, identity=store.identity)
    replay = _ingest(
        reopened,
        code="under_review",
        hour=0,
        follow_up=request,
    )

    assert replay == first
    assert reopened.verify() == before
    assert tuple(
        receipt.receipt_sha256
        for receipt in (
            replay.archive_receipt,
            replay.observation_receipt,
            replay.timeline_receipt,
            replay.intent_receipt,
        )
    ) == tuple(
        receipt.receipt_sha256
        for receipt in (
            first.archive_receipt,
            first.observation_receipt,
            first.timeline_receipt,
            first.intent_receipt,
        )
    )


def test_receipted_prefix_converges_after_simulated_crash_and_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    raw_bytes = b"under_review"
    evidence = compile_local_export_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=JOB_KEY,
        source_kind="local_portal_export",
        source_record_id="crash-prefix",
        raw_export_bytes=raw_bytes,
        observed_at=BASE_TIME,
    )
    archive_receipt = store.archive_raw_export(evidence, raw_bytes)
    observation = classify_status_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        evidence,
        explicit_status_code="under_review",
    )
    observation_receipt = store.append_observation(observation)

    reopened = StatusEvidenceStore.open(path, identity=store.identity)
    result = _ingest(
        reopened,
        code="under_review",
        hour=0,
        source_record_id="crash-prefix",
    )

    assert result.evidence == evidence
    assert result.observation == observation
    assert result.archive_receipt == archive_receipt
    assert result.observation_receipt == observation_receipt
    assert result.timeline_receipt.document["sequence"] == 3
    assert reopened.verify().receipt_sequence == 3
