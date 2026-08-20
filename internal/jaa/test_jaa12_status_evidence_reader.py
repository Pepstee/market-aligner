"""Positive controls for JAA-12 durable typed status reads."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from career_automation.status_evidence_store import StatusEvidenceStore
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    censor_status_silence,
)
from career_automation.status_store_coordinator import (
    FollowUpRegistrationRequest,
    ingest_local_export,
)


BASE_TIME = datetime(2032, 1, 2, 12, 0, tzinfo=timezone.utc)
CONTRACT_SHA256 = FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256


def _store(path: Path, instance: str = "jaa12-reader") -> StatusEvidenceStore:
    return StatusEvidenceStore.initialize(
        path,
        contract_sha256=CONTRACT_SHA256,
        store_instance_id=instance,
    )


def _ingest(
    store: StatusEvidenceStore,
    *,
    application_id: str = "reader-application",
    job_key: str = "reader-job",
    code: str = "under_review",
    hour: int = 0,
    prior=(),
    follow_up=None,
    censored_silence=(),
):
    return ingest_local_export(
        store,
        application_id=application_id,
        job_key=job_key,
        source_kind="local_portal_export",
        source_record_id=f"{application_id}:{job_key}:{hour}",
        raw_export_bytes=code.encode(),
        observed_at=BASE_TIME + timedelta(hours=hour),
        explicit_status_code=code,
        prior_observations=prior,
        censored_silence=censored_silence,
        follow_up=follow_up,
    )


def test_full_ingest_round_trips_exact_typed_values(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    silence = censor_status_silence(
        application_id="reader-application",
        job_key="reader-job",
        as_of=BASE_TIME + timedelta(hours=1),
    )
    result = _ingest(
        store,
        follow_up=FollowUpRegistrationRequest("c" * 64, "d" * 64),
        censored_silence=(silence,),
    )

    assert store.read_observations(
        "reader-application", "reader-job"
    ) == (result.observation,)
    assert store.read_timelines(
        "reader-application", "reader-job"
    ) == (result.timeline,)
    assert store.read_timeline(result.timeline.timeline_id) == result.timeline
    assert store.read_follow_up_intents(
        "reader-application", "reader-job"
    ) == (result.intent,)
    assert store.read_follow_up_intent(
        result.intent.idempotency_key
    ) == result.intent
    state = store.read_stream_state("reader-application", "reader-job")
    assert state is not None
    assert state.observation_count == 1
    assert state.last_observed_at == result.observation.observed_at
    assert state.current_state.value == "screening"
    assert state.terminal_state is None


def test_reads_are_isolated_by_application_and_job(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    first = _ingest(store, application_id="application-a", job_key="job-a")
    second = _ingest(store, application_id="application-b", job_key="job-b")

    assert store.read_observations("application-a", "job-a") == (
        first.observation,
    )
    assert store.read_observations("application-b", "job-b") == (
        second.observation,
    )
    assert store.read_observations("application-a", "job-b") == ()
    assert store.read_timelines("application-b", "job-a") == ()
    assert store.read_follow_up_intents("application-a", "job-b") == ()


def test_historical_timelines_are_returned_in_receipt_order(
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
    third = _ingest(
        store,
        code="final_stage",
        hour=2,
        prior=(first.observation, second.observation),
    )

    assert store.read_observations(
        "reader-application", "reader-job"
    ) == (
        first.observation,
        second.observation,
        third.observation,
    )
    assert store.read_timelines(
        "reader-application", "reader-job"
    ) == (
        first.timeline,
        second.timeline,
        third.timeline,
    )
    state = store.read_stream_state("reader-application", "reader-job")
    assert state is not None
    assert state.current_state.value == "final_stage"
    assert state.observation_count == 3


def test_absent_and_truthful_partial_prefix_reads_do_not_synthesize(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "status.sqlite3")
    assert store.read_observations("absent", "absent") == ()
    assert store.read_stream_state("absent", "absent") is None
    assert store.read_timelines("absent", "absent") == ()
    assert store.read_follow_up_intents("absent", "absent") == ()

    result = _ingest(store)
    store.archive_raw_export(
        result.evidence,
        b"under_review",
    )
    assert store.read_observations(
        "reader-application", "reader-job"
    ) == (result.observation,)
    assert len(store.read_timelines("reader-application", "reader-job")) == 1


def test_typed_reads_survive_a_fresh_store_session(
    tmp_path: Path,
) -> None:
    path = tmp_path / "status.sqlite3"
    store = _store(path)
    result = _ingest(
        store,
        follow_up=FollowUpRegistrationRequest("c" * 64, "d" * 64),
    )

    reopened = StatusEvidenceStore.open(path, identity=store.identity)
    assert reopened.read_observations(
        "reader-application", "reader-job"
    ) == (result.observation,)
    assert reopened.read_timeline(result.timeline.timeline_id) == (
        result.timeline
    )
    assert reopened.read_follow_up_intent(
        result.intent.idempotency_key
    ) == result.intent
    assert reopened.verify() == store.verify()
