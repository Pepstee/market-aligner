"""Negative controls for the bounded JAA-12 durable coordinator."""

from __future__ import annotations

import ast
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.status_evidence_store import (
    StatusEvidenceConflictError,
    StatusEvidenceIntegrityError,
    StatusEvidenceStateError,
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


APPLICATION_ID = "jaa12-coordinator-negative-application"
JOB_KEY = "jaa12-coordinator-negative-job"
BASE_TIME = datetime(2031, 3, 4, 12, 0, tzinfo=timezone.utc)
CONTRACT_SHA256 = FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256


def _store(path: Path) -> StatusEvidenceStore:
    return StatusEvidenceStore.initialize(
        path,
        contract_sha256=CONTRACT_SHA256,
        store_instance_id="jaa12-status-store-coordinator-negative",
    )


def _ingest(
    store: StatusEvidenceStore,
    *,
    code: str,
    hour: int,
    prior=(),
    raw_bytes: bytes | None = None,
    source_record_id: str | None = None,
    application_id: str = APPLICATION_ID,
    job_key: str = JOB_KEY,
    follow_up: FollowUpRegistrationRequest | None = None,
):
    return ingest_local_export(
        store,
        application_id=application_id,
        job_key=job_key,
        source_kind="local_message_export",
        source_record_id=source_record_id or f"negative-export-{hour}",
        raw_export_bytes=(
            code.encode("utf-8") if raw_bytes is None else raw_bytes
        ),
        observed_at=BASE_TIME + timedelta(hours=hour),
        explicit_status_code=code,
        prior_observations=prior,
        follow_up=follow_up,
    )


@pytest.mark.parametrize("value", ("x" * 64, "A" * 64, "0" * 63, ""))
def test_follow_up_request_rejects_noncanonical_reference_hashes(
    value: str,
) -> None:
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        FollowUpRegistrationRequest(
            released_application_sha256=value,
            draft_sha256="d" * 64,
        )
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        FollowUpRegistrationRequest(
            released_application_sha256="c" * 64,
            draft_sha256=value,
        )


def test_known_status_with_different_raw_bytes_fails_after_truthful_archive(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")

    with pytest.raises(
        ValueError,
        match="known status code differs from parsed export bytes",
    ):
        _ingest(
            store,
            code="under_review",
            raw_bytes=b"under_review altered",
            hour=0,
        )

    snapshot = store.verify()
    assert snapshot.raw_evidence_count == 1
    assert snapshot.observation_count == 0
    assert snapshot.timeline_count == 0
    assert store.receipts()[-1].document["event_type"] == (
        "archive_raw_export"
    )


def test_nonmonotonic_observation_fails_closed_without_compensation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    first = _ingest(store, code="under_review", hour=2)

    with pytest.raises(
        StatusEvidenceStateError,
        match="strictly monotonic",
    ):
        _ingest(
            store,
            code="under_review",
            hour=1,
            prior=(first.observation,),
        )

    snapshot = store.verify()
    assert snapshot.raw_evidence_count == 2
    assert snapshot.observation_count == 1
    assert snapshot.timeline_count == 1


def test_illegal_transition_fails_after_archiving_exact_source(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    first = _ingest(store, code="under_review", hour=0)

    with pytest.raises(
        StatusEvidenceStateError,
        match="transition is illegal",
    ):
        _ingest(
            store,
            code="offer",
            hour=1,
            prior=(first.observation,),
        )

    snapshot = store.verify()
    assert snapshot.raw_evidence_count == 2
    assert snapshot.observation_count == 1
    assert snapshot.timeline_count == 1


def test_terminal_observation_is_durable_but_follow_up_is_refused(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    request = FollowUpRegistrationRequest("c" * 64, "d" * 64)

    with pytest.raises(
        ValueError,
        match="follow-up policy does not permit",
    ):
        _ingest(
            store,
            code="rejected_by_employer",
            hour=0,
            follow_up=request,
        )

    snapshot = store.verify()
    assert snapshot.raw_evidence_count == 1
    assert snapshot.observation_count == 1
    assert snapshot.timeline_count == 1
    assert snapshot.intent_count == 0
    assert store.receipts()[-1].document["event_type"] == (
        "register_timeline"
    )


def test_stale_subset_history_fails_at_exact_current_timeline_gate(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    first = _ingest(store, code="under_review", hour=0)
    second = _ingest(
        store,
        code="under_review",
        hour=1,
        prior=(first.observation,),
    )

    with pytest.raises(
        StatusEvidenceStateError,
        match="complete durable observation set",
    ):
        _ingest(
            store,
            code="under_review",
            hour=2,
            prior=(first.observation,),
        )

    snapshot = store.verify()
    assert snapshot.raw_evidence_count == 3
    assert snapshot.observation_count == 3
    assert snapshot.timeline_count == 2
    assert second.timeline.observations[-1] == second.observation


def test_cross_application_prior_history_is_rejected_before_any_write(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    raw_bytes = b"under_review"
    evidence = compile_local_export_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id="other-application",
        job_key=JOB_KEY,
        source_kind="local_message_export",
        source_record_id="other-export",
        raw_export_bytes=raw_bytes,
        observed_at=BASE_TIME,
    )
    other = classify_status_evidence(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        evidence,
        explicit_status_code="under_review",
    )

    with pytest.raises(
        ValueError,
        match="different application",
    ):
        _ingest(
            store,
            code="under_review",
            hour=1,
            prior=(other,),
        )

    assert store.verify().receipt_sequence == 0
    assert store.verify().raw_evidence_count == 0


def test_first_follow_up_key_wins_when_later_intent_content_differs(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    first = _ingest(
        store,
        code="under_review",
        hour=0,
        follow_up=FollowUpRegistrationRequest("c" * 64, "d" * 64),
    )

    with pytest.raises(
        StatusEvidenceConflictError,
        match="already binds another intent",
    ):
        _ingest(
            store,
            code="under_review",
            hour=1,
            prior=(first.observation,),
            follow_up=FollowUpRegistrationRequest("c" * 64, "e" * 64),
        )

    snapshot = store.verify()
    assert snapshot.raw_evidence_count == 2
    assert snapshot.observation_count == 2
    assert snapshot.timeline_count == 2
    assert snapshot.intent_count == 1


def test_naive_time_and_mismatched_store_contract_fail_before_writes(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    with pytest.raises(ValueError, match="must include a timezone"):
        ingest_local_export(
            store,
            application_id=APPLICATION_ID,
            job_key=JOB_KEY,
            source_kind="local_message_export",
            source_record_id="naive",
            raw_export_bytes=b"under_review",
            observed_at=datetime(2031, 3, 4, 12, 0),
            explicit_status_code="under_review",
            prior_observations=(),
        )
    assert store.verify().receipt_sequence == 0

    object.__setattr__(
        store.identity,
        "contract_sha256",
        "0" * 64,
    )
    with pytest.raises(ValueError, match="different contract"):
        _ingest(store, code="under_review", hour=0)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("policy_sha256", "0" * 64),
        ("partial_progress", "hidden"),
        ("atomicity_across_steps", "all_or_nothing"),
        ("durable_read_api", "available"),
        ("follow_up_reference_hashes", "authenticated"),
        ("connector_authority", "granted"),
        ("send_authority", "granted"),
        ("objective_satisfied", True),
        ("dependency_satisfied", True),
        ("production_certification", "granted"),
        ("certifies_slice", True),
        ("external_action_capability", True),
    ),
)
def test_result_type_rejects_authority_or_claim_escalation(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    store = _store(tmp_path / f"{field}.sqlite3")
    result = _ingest(store, code="under_review", hour=0)

    with pytest.raises(ValueError, match="cannot connect, send, satisfy"):
        replace(result, **{field: value})


def test_tampered_receipt_cannot_enter_a_reconstructed_result(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    result = _ingest(store, code="under_review", hour=0)
    tampered = dict(result.archive_receipt.document)
    tampered["external_action_performed"] = True
    object.__setattr__(result.archive_receipt, "document", tampered)

    with pytest.raises(StatusEvidenceIntegrityError):
        replace(result)


def test_coordinator_source_has_no_external_capability_imports() -> None:
    path = (
        Path(__file__).parent
        / "career_automation"
        / "status_store_coordinator.py"
    )
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )

    assert imports <= {
        "__future__",
        "dataclasses",
        "datetime",
        "typing",
        "career_automation",
    }
    assert imports.isdisjoint({
        "http",
        "imaplib",
        "os",
        "pathlib",
        "poplib",
        "requests",
        "smtplib",
        "socket",
        "subprocess",
        "urllib",
    })
    assert "open(" not in source
    assert "sqlite3" not in source
    assert "dispatch_state" not in source
    assert "sent_count" not in source
