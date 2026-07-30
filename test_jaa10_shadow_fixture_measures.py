"""Positive controls for JAA-10 descriptive fixture measures."""

from dataclasses import replace
from datetime import datetime, timezone

from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    HARD_QUALITY_TARGETS,
    REQUIRED_ACTIONS,
)
from career_automation.shadow_fixture_measures import (
    HARD_QUALITY_STATUS,
    HARD_TARGET_STATUS,
    REPORT_SCHEMA_VERSION,
    SOURCE_TIME_AUTHORITY,
    compile_fixture_measures_report,
)
from career_automation.shadow_observation_ledger import (
    ASSESSMENT,
    CLOCK_AUTHENTICATION,
    FILESYSTEM_WRITER_LIMIT,
    MONOTONIC_WITNESS_SCOPE,
    SPAN_MEANING,
    ObservationLedgerReceipt,
    ShadowObservationLedger,
)
from test_jaa10_independent_acceptance import _observation


def _two_observation_report(tmp_path):
    database = tmp_path / "shadow-observations.sqlite3"
    ledger = ShadowObservationLedger.initialize(
        database,
        contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
    )
    first = _observation(
        "measures-first",
        datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    second_base = _observation(
        "measures-second",
        datetime(2024, 1, 3, tzinfo=timezone.utc),
    )
    second = replace(
        second_base,
        action_elapsed_ms={
            action: elapsed * 2
            for action, elapsed in second_base.action_elapsed_ms.items()
        },
        browser_launch_count=2,
        database_bytes=8192,
        screenshot_bytes=4096,
    )
    for observation in (first, second):
        session = ledger.begin_session()
        ledger.record_observation(session, observation)
    report = compile_fixture_measures_report(
        ledger,
        ledger.identity,
        (first, second),
    )
    return database, ledger, (first, second), report


def test_report_binds_verified_ledger_snapshot_and_is_current(tmp_path) -> None:
    _, ledger, observations, report = _two_observation_report(tmp_path)
    receipts = ledger.receipts()
    observation_receipts = tuple(
        row
        for row in receipts
        if row.document["event_type"] == "observation_recorded"
    )

    assert report.schema_version == REPORT_SCHEMA_VERSION
    assert report.ledger_identity == ledger.identity
    assert report.contract_sha256 == FROZEN_SHADOW_CONTRACT.contract_sha256
    assert report.receipt_count == 5
    assert tuple(
        row.receipt_sha256 for row in report.observation_receipts
    ) == tuple(row.receipt_sha256 for row in observation_receipts)
    assert report.chain_head_receipt.receipt_sha256 == (
        receipts[-1].receipt_sha256
    )
    assert tuple(
        row.document["observation_id"]
        for row in report.observation_receipts
    ) == tuple(row.observation_id for row in observations)
    assert tuple(
        row.document["observation_sha256"]
        for row in report.observation_receipts
    ) == tuple(row.observation_sha256 for row in observations)
    assert tuple(
        row.document["source_observed_at"]
        for row in report.observation_receipts
    ) == tuple(row.observed_at for row in observations)
    report.verify()
    report.verify_current(ledger)


def test_reopened_compilation_is_deterministic_and_aggregates_are_exact(
    tmp_path,
) -> None:
    database, ledger, observations, report = _two_observation_report(tmp_path)
    reopened = ShadowObservationLedger.open(
        database,
        identity=ledger.identity,
    )
    recompiled = compile_fixture_measures_report(
        reopened,
        reopened.identity,
        observations,
    )
    measures = report.document()["descriptive_fixture_measures"]
    action_measures = measures["action_elapsed_ms"]

    assert recompiled.report_id == report.report_id
    assert recompiled.document() == report.document()
    assert action_measures["grand_total"] == 198
    for index, action in enumerate(REQUIRED_ACTIONS, start=1):
        assert action_measures["per_action"][action] == {
            "total": index * 3,
            "min": index,
            "max": index * 2,
        }
    assert measures["browser_launch_count"] == {
        "per_observation": [1, 2],
        "total": 3,
    }
    assert measures["database_bytes"] == {
        "per_observation": [4096, 8192],
        "total": 12288,
        "min": 4096,
        "max": 8192,
    }
    assert measures["screenshot_bytes"] == {
        "per_observation": [2048, 4096],
        "total": 6144,
        "min": 2048,
        "max": 4096,
    }
    assert measures["model_versions"] == ["deterministic:none"]
    assert measures["prompt_versions"] == ["deterministic:none"]
    assert measures["total_model_cost_microusd"] == 0
    assert measures["interruption_totals"] == {
        "submit_click_count": 8,
        "receipt_count": 8,
    }
    for measured, observation in zip(
        measures["observations"],
        observations,
        strict=True,
    ):
        assert measured["action_elapsed_ms"] == dict(
            sorted(observation.action_elapsed_ms.items())
        )
        assert measured["model_version"] == observation.model_version
        assert measured["prompt_version"] == observation.prompt_version
        assert measured["model_cost_microusd"] == 0
        assert measured["interruptions"] == [
            row.document() for row in observation.interruptions
        ]
        assert measured["mutations"] == [
            row.document() for row in observation.mutations
        ]


def test_report_withholds_every_hard_target_and_time_claim(tmp_path) -> None:
    _, _, observations, report = _two_observation_report(tmp_path)
    document = report.document()
    measures = document["descriptive_fixture_measures"]
    host = measures["host_recording"]

    assert document["hard_quality_metric_status"] == HARD_QUALITY_STATUS
    assert set(document["hard_quality_targets"]) == set(
        HARD_QUALITY_TARGETS
    )
    assert document["hard_quality_targets"] == {
        key: {
            "target": target,
            "status": HARD_TARGET_STATUS,
        }
        for key, target in sorted(HARD_QUALITY_TARGETS.items())
    }
    assert document["metrics_evaluated"] is False
    assert document["fixture_scope_only"] is True
    assert document["live_time_separated_execution"] == "not_collected"
    assert document["production_certification"] == "withheld"
    assert document["certifies_slice"] is False
    assert document["objective_satisfied"] is False
    assert document["external_action_capability"] is False
    assert document["assessment"] == ASSESSMENT
    assert measures["source_observed_at_authority"] == SOURCE_TIME_AUTHORITY
    assert [
        row["source_observed_at"] for row in measures["observations"]
    ] == [row.observed_at for row in observations]
    assert host["span_meaning"] == SPAN_MEANING
    assert host["clock_authentication"] == CLOCK_AUTHENTICATION
    assert host["monotonic_witness_scope"] == MONOTONIC_WITNESS_SCOPE
    assert (
        host["filesystem_privileged_writer_limit"]
        == FILESYSTEM_WRITER_LIMIT
    )


def test_embedded_receipts_verify_without_the_database(tmp_path) -> None:
    database, _, _, report = _two_observation_report(tmp_path)
    embedded = [
        *report.observation_receipts,
        report.chain_head_receipt,
    ]
    database.unlink()

    report.verify()
    for receipt in embedded:
        reconstructed = ObservationLedgerReceipt(
            receipt.receipt_sha256,
            dict(receipt.document),
        )
        assert reconstructed.receipt_sha256 == receipt.receipt_sha256
