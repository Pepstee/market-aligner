"""Positive controls for the bounded JAA-10 same-boot cohort rehearsal."""

from datetime import datetime, timedelta, timezone

import pytest

from career_automation.shadow_certification import FROZEN_SHADOW_CONTRACT
from career_automation.shadow_elapsed_cohort import (
    CALENDAR_TIME_AUTHENTICATION,
    CLAIM,
    CONTAMINATION_POLICY,
    EVIDENCE_CLASS,
    EXTERNAL_TIME_ATTESTATION,
    HARD_TARGET_STATUS,
    KERNEL_TIME_LIMIT,
    MINIMUM_ELAPSED_NS,
    ElapsedCohortStateError,
    ElapsedTimeWitness,
    _close_with_witness,
    _open_with_witness,
    capture_elapsed_time_witness,
    verify_elapsed_cohort,
)
from career_automation.shadow_fixture_measures import (
    compile_fixture_measures_report,
)
from career_automation.shadow_observation_ledger import (
    FILESYSTEM_WRITER_LIMIT,
    ShadowObservationLedger,
)
from test_jaa10_independent_acceptance import _observation


SOURCE_REVISION = "1" * 40
SOURCE_TREE = "2" * 40
SOURCE_CONTENT = "sha256:" + ("3" * 64)


def _witness(
    boottime_ns: int,
    *,
    boot_id: str = "a" * 64,
    monotonic_ns: int | None = None,
    process_token: str = "b" * 64,
    wall_time: datetime | None = None,
) -> ElapsedTimeWitness:
    return ElapsedTimeWitness(
        boot_id,
        boottime_ns,
        boottime_ns if monotonic_ns is None else monotonic_ns,
        process_token,
        (
            wall_time
            or datetime(2024, 1, 1, tzinfo=timezone.utc)
        ).isoformat(),
    )


def _open_fixture_cohort(tmp_path):
    database = tmp_path / "shadow-observations.sqlite3"
    ledger = ShadowObservationLedger.initialize(
        database,
        contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
    )
    first = _observation(
        "elapsed-first",
        datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    ledger.record_observation(ledger.begin_session(), first)
    first_report = compile_fixture_measures_report(
        ledger,
        ledger.identity,
        (first,),
    )
    first_witness = _witness(1_000_000_000)
    opened = _open_with_witness(
        ledger,
        ledger.identity,
        first,
        first_report,
        SOURCE_REVISION,
        SOURCE_TREE,
        SOURCE_CONTENT,
        first_witness,
    )
    return database, ledger, first, first_report, opened


def _close_fixture_cohort(tmp_path, *, second_witness=None):
    (
        database,
        ledger,
        first,
        first_report,
        opened,
    ) = _open_fixture_cohort(tmp_path)
    second = _observation(
        "elapsed-second",
        datetime(2024, 1, 2, tzinfo=timezone.utc),
    )
    ledger.record_observation(ledger.begin_session(), second)
    second_report = compile_fixture_measures_report(
        ledger,
        ledger.identity,
        (first, second),
    )
    witness = second_witness or _witness(
        opened.first_witness.clock_boottime_ns
        + MINIMUM_ELAPSED_NS,
        monotonic_ns=(
            opened.first_witness.monotonic_ns + MINIMUM_ELAPSED_NS
        ),
    )
    closed = _close_with_witness(
        opened,
        ledger,
        ledger.identity,
        second,
        second_report,
        SOURCE_REVISION,
        SOURCE_TREE,
        SOURCE_CONTENT,
        witness,
    )
    return (
        database,
        ledger,
        first_report,
        second_report,
        opened,
        closed,
    )


def test_raw_kernel_witness_capture_is_typed_and_canonical() -> None:
    witness = capture_elapsed_time_witness()

    assert len(witness.boot_id_sha256) == 64
    assert witness.clock_boottime_ns >= 1
    assert witness.monotonic_ns >= 1
    assert len(witness.process_token) == 64
    assert datetime.fromisoformat(
        witness.recorded_wall_clock
    ).utcoffset() == timedelta(0)


def test_open_receipt_round_trip_binds_current_ledger_and_report(
    tmp_path,
) -> None:
    _, ledger, first, first_report, opened = _open_fixture_cohort(
        tmp_path
    )
    document = opened.document()

    assert document["state"] == "OPEN"
    assert document["evidence_class"] == EVIDENCE_CLASS
    assert document["contract_sha256"] == (
        FROZEN_SHADOW_CONTRACT.contract_sha256
    )
    assert document["first_observation_binding"][
        "observation_sha256"
    ] == first.observation_sha256
    assert document["fixture_measures_report_id"] == first_report.report_id
    assert document["first_ledger_receipt"]["receipt_sha256"] == (
        ledger.receipts()[-1].receipt_sha256
    )
    opened.verify()
    opened.verify_current(ledger, first_report)


def test_close_receipt_computes_minimum_delta_and_verifies_offline(
    tmp_path,
) -> None:
    (
        database,
        ledger,
        _,
        second_report,
        opened,
        closed,
    ) = _close_fixture_cohort(tmp_path)

    assert closed.document()["state"] == "CLOSED"
    assert closed.same_boot is True
    assert closed.elapsed_boottime_ns == MINIMUM_ELAPSED_NS
    assert closed.claim == CLAIM
    verify_elapsed_cohort(opened, closed)
    closed.verify_current(ledger, second_report)
    database.unlink()
    verify_elapsed_cohort(opened, closed)


def test_cross_process_monotonic_value_is_not_compared(tmp_path) -> None:
    different_process_witness = _witness(
        1_000_000_000 + MINIMUM_ELAPSED_NS,
        monotonic_ns=1,
        process_token="c" * 64,
    )
    _, _, _, _, opened, closed = _close_fixture_cohort(
        tmp_path,
        second_witness=different_process_witness,
    )

    assert (
        opened.first_witness.process_token
        != closed.second_witness.process_token
    )
    assert closed.second_witness.monotonic_ns == 1
    verify_elapsed_cohort(opened, closed)


def test_closed_receipt_is_noncertifying_and_locked_from_tuning(
    tmp_path,
) -> None:
    _, _, _, _, _, closed = _close_fixture_cohort(tmp_path)
    document = closed.document()

    assert document["contamination_policy"] == CONTAMINATION_POLICY
    assert document["objective_satisfied"] is False
    assert document["metrics_evaluated"] is False
    assert document["live_time_separated_execution"] == "not_collected"
    assert document["production_certification"] == "withheld"
    assert document["certifies_slice"] is False
    assert document["external_action_capability"] is False
    assert document["real_applications_submitted"] == 0
    assert document["external_time_attestation"] == (
        EXTERNAL_TIME_ATTESTATION
    )
    assert document["calendar_time_authentication"] == (
        CALENDAR_TIME_AUTHENTICATION
    )
    assert document["filesystem_privileged_writer_limit"] == (
        FILESYSTEM_WRITER_LIMIT
    )
    assert document["kernel_time_witness_limit"] == KERNEL_TIME_LIMIT
    assert all(
        row["status"] == HARD_TARGET_STATUS
        for row in document["hard_quality_targets"].values()
    )


def test_appended_head_makes_closed_receipt_stale(tmp_path) -> None:
    _, ledger, _, second_report, _, closed = _close_fixture_cohort(
        tmp_path
    )
    third = _observation(
        "elapsed-third",
        datetime(2024, 1, 3, tzinfo=timezone.utc),
    )
    ledger.record_observation(ledger.begin_session(), third)

    closed.verify()
    with pytest.raises(ElapsedCohortStateError):
        closed.verify_current(ledger, second_report)
