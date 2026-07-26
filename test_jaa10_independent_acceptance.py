"""Independent acceptance for the noncertifying JAA-10 shadow contract."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    HARD_QUALITY_TARGETS,
    REQUIRED_ACTIONS,
    REQUIRED_INTERRUPTION_POINTS,
    REQUIRED_MUTATION_CONTROLS,
    InterruptionObservation,
    MutationObservation,
    ShadowObservation,
    compile_withheld_shadow_evidence,
)


def _observation(
    identifier: str,
    observed_at: datetime,
) -> ShadowObservation:
    golden = FROZEN_SHADOW_CONTRACT
    return ShadowObservation(
        observation_id=identifier,
        observed_at=observed_at.isoformat(),
        workflow_sha256=golden.workflow_sha256,
        receipt_id=golden.receipt_id,
        receipt_payload_sha256=golden.receipt_payload_sha256,
        field_map_sha256=golden.field_map_sha256,
        screenshot_sha256=golden.screenshot_sha256,
        submit_event_sha256=golden.submit_event_sha256,
        action_elapsed_ms={
            action: index
            for index, action in enumerate(REQUIRED_ACTIONS, start=1)
        },
        browser_launch_count=1,
        database_bytes=4096,
        screenshot_bytes=2048,
        interruptions=tuple(
            InterruptionObservation(
                point,
                (
                    "recovered"
                    if point == "post_click_pre_checkpoint"
                    else "fail_closed"
                ),
                1 if point == "post_click_pre_checkpoint" else 0,
                1 if point == "post_click_pre_checkpoint" else 0,
            )
            for point in REQUIRED_INTERRUPTION_POINTS
        ),
        mutations=tuple(
            MutationObservation(control, True, False)
            for control in REQUIRED_MUTATION_CONTROLS
        ),
    )


def test_frozen_shadow_contract_binds_exact_accepted_jaa09_golden_set() -> None:
    golden = FROZEN_SHADOW_CONTRACT
    assert golden.baseline_revision == (
        "6e627e3ae07744e2c658a2046f0cd3121b7c2254"
    )
    assert golden.workflow_sha256 == (
        "ccd8f38596d1d31682ae126c45c61ee45fcff48df8f8650d25b6ccda8411e025"
    )
    assert golden.application_id == "jaa10-frozen-platform-engineer"
    assert golden.job_key == "jaa06-synthetic:strategy-job"
    assert golden.contract_sha256


def test_time_separated_shadow_evidence_is_content_addressed_and_withheld() -> None:
    first_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    observations = (
        _observation("shadow-001", first_time),
        _observation(
            "shadow-002",
            first_time + timedelta(hours=24),
        ),
    )
    evidence = compile_withheld_shadow_evidence(
        FROZEN_SHADOW_CONTRACT,
        observations,
    )
    evidence.verify()
    assert evidence.hard_quality_metrics == HARD_QUALITY_TARGETS
    assert evidence.production_certification == "withheld"
    assert evidence.certifies_slice is False
    assert evidence.evidence_kind == "synthetic_shadow"
    assert tuple(
        row.observation_sha256 for row in observations
    ) == evidence.observation_sha256s
    assert "receipt" not in evidence.document()
    assert "model_cost_microusd" not in evidence.document()


def test_observation_identity_changes_with_runtime_metrics() -> None:
    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    first = _observation("shadow-001", observed_at)
    changed = replace(
        first,
        database_bytes=first.database_bytes + 1,
    )
    assert first.observation_sha256 != changed.observation_sha256
