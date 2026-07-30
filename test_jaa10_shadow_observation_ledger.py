"""Positive controls for the fixture-only JAA-10 observation ledger."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from career_automation.shadow_certification import FROZEN_SHADOW_CONTRACT
from career_automation.shadow_observation_ledger import (
    ASSESSMENT,
    CLOCK_AUTHENTICATION,
    FILESYSTEM_WRITER_LIMIT,
    MONOTONIC_WITNESS_SCOPE,
    SPAN_MEANING,
    ShadowObservationLedger,
    ledger_policy_document,
)
from test_jaa10_independent_acceptance import _observation


def test_durable_ledger_reopens_and_preserves_host_recorded_chain(
    tmp_path,
) -> None:
    database = tmp_path / "shadow-observations.sqlite3"
    store = ShadowObservationLedger.initialize(
        database,
        contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
    )
    identity = store.identity
    source_time = datetime(2024, 1, 1, tzinfo=timezone.utc)

    first_session = store.begin_session()
    first_observation = _observation("ledger-first", source_time)
    first_receipt = store.record_observation(
        first_session,
        first_observation,
    )

    reopened = ShadowObservationLedger.open(
        database,
        identity=identity,
    )
    second_session = reopened.begin_session()
    second_observation = _observation(
        "ledger-second",
        source_time + timedelta(minutes=1),
    )
    second_receipt = reopened.record_observation(
        second_session,
        second_observation,
    )

    receipts = reopened.receipts()
    assert [receipt.document["sequence"] for receipt in receipts] == [
        1,
        2,
        3,
        4,
        5,
    ]
    assert [receipt.document["event_type"] for receipt in receipts] == [
        "genesis",
        "session_open",
        "observation_recorded",
        "session_open",
        "observation_recorded",
    ]
    assert all(
        receipt.document["contract_sha256"]
        == FROZEN_SHADOW_CONTRACT.contract_sha256
        for receipt in receipts
    )
    assert len({receipt.document["process_token"] for receipt in receipts}) == 1
    assert first_session.session_id != second_session.session_id
    assert first_receipt.receipt_sha256 != second_receipt.receipt_sha256
    assert first_receipt.document["source_observed_at"] == (
        first_observation.observed_at
    )
    assert second_receipt.document["source_observed_at"] == (
        second_observation.observed_at
    )
    assert (
        first_receipt.document["host_recorded_at_utc"]
        > first_receipt.document["source_observed_at"]
    )
    assert (
        first_receipt.document["host_recorded_at_utc"]
        < second_receipt.document["host_recorded_at_utc"]
    )
    assert (
        second_receipt.document["previous_receipt_sha256"]
        == receipts[-2].receipt_sha256
    )
    reopened.verify()


def test_summary_is_exactly_fixture_scoped_and_counts_empty_sessions(
    tmp_path,
) -> None:
    database = tmp_path / "shadow-observations.sqlite3"
    store = ShadowObservationLedger.initialize(
        database,
        contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
    )
    source_time = datetime(2024, 2, 1, tzinfo=timezone.utc)
    first_session = store.begin_session()
    store.record_observation(
        first_session,
        _observation("summary-first", source_time),
    )
    store.begin_session()

    summary = store.summary()

    assert set(summary) == {
        "record_count",
        "session_count",
        "sessions_without_observation",
        "first_observation_host_recorded_at_utc",
        "last_observation_host_recorded_at_utc",
        "recorded_wall_clock_span_seconds",
        "span_meaning",
        "assessment",
        "policy",
    }
    assert summary["record_count"] == 1
    assert summary["session_count"] == 2
    assert summary["sessions_without_observation"] == 1
    assert summary["recorded_wall_clock_span_seconds"] == 0.0
    assert summary["first_observation_host_recorded_at_utc"] == (
        summary["last_observation_host_recorded_at_utc"]
    )
    assert summary["span_meaning"] == SPAN_MEANING
    assert summary["assessment"] == ASSESSMENT
    assert summary["policy"] == ledger_policy_document()
    assert summary["policy"]["clock_authentication"] == CLOCK_AUTHENTICATION
    assert (
        summary["policy"]["monotonic_witness_scope"]
        == MONOTONIC_WITNESS_SCOPE
    )
    assert (
        summary["policy"]["filesystem_privileged_writer_limit"]
        == FILESYSTEM_WRITER_LIMIT
    )
    assert summary["policy"]["metrics_evaluated"] is False
    assert summary["policy"]["certifies_slice"] is False


def test_empty_ledger_summary_does_not_invent_observation_times(
    tmp_path,
) -> None:
    store = ShadowObservationLedger.initialize(
        tmp_path / "shadow-observations.sqlite3",
        contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
    )

    assert store.summary() == {
        "record_count": 0,
        "session_count": 0,
        "sessions_without_observation": 0,
        "first_observation_host_recorded_at_utc": None,
        "last_observation_host_recorded_at_utc": None,
        "recorded_wall_clock_span_seconds": 0.0,
        "span_meaning": SPAN_MEANING,
        "assessment": ASSESSMENT,
        "policy": ledger_policy_document(),
    }
