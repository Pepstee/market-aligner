"""Focused contract tests for the production-only JAA-10 cohort producer."""

from __future__ import annotations

import hashlib
import inspect
from datetime import datetime, timedelta, timezone

from career_automation.ats_fixture import FixtureReceipt
from career_automation.browser_workflows import (
    SubmissionProof,
    fixture_submit_event_sha256,
)
from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    MUTATION_TEST_NODES,
    REQUIRED_ACTIONS,
    REQUIRED_INTERRUPTION_POINTS,
    REQUIRED_MUTATION_CONTROLS,
    InterruptionObservation,
    ShadowObservation,
    normalized_submit_event_sha256,
)
from career_automation.shadow_full_submit_cohort import (
    ExecutedLoopbackObservation,
    compile_full_submit_cohort,
)
from career_automation.shadow_mutation_runtime import (
    RUNTIME_CONTROL_IDS,
    RuntimeControlReceipt,
    mutation_observations_from_runtime,
    observe_fail_closed_control,
)


REVISION = "1" * 40
TREE = "2" * 40
SOURCE_CONTENT = "sha256:" + "3" * 64


def _state() -> dict[str, object]:
    return {
        "receipt_count": 0,
        "submit_click_count": 0,
        "dispatch_state": "prepared",
        "event_count": 1,
    }


def _receipts() -> tuple[RuntimeControlReceipt, ...]:
    rows = []
    for control_id in RUNTIME_CONTROL_IDS:
        def blocked(control: str = control_id) -> None:
            raise ValueError(f"blocked:{control}")

        rows.append(
            observe_fail_closed_control(
                control_id=control_id,
                executable_identity=(
                    MUTATION_TEST_NODES.get(control_id)
                    or f"runtime-twin:{control_id}"
                ),
                operation=blocked,
                state_probe=_state,
                source_git_revision=REVISION,
                source_tree=TREE,
                source_content_revision=SOURCE_CONTENT,
            )
        )
    return tuple(rows)


def _observation(
    identifier: str,
    observed_at: datetime,
    release_manifest_sha256: str,
    runtime_receipts: tuple[RuntimeControlReceipt, ...],
) -> ShadowObservation:
    golden = FROZEN_SHADOW_CONTRACT
    run_id = f"full-submit-{identifier}"
    actual_event = fixture_submit_event_sha256(
        run_id=run_id,
        workflow_sha256=golden.workflow_sha256,
        step_id="submit",
        release_manifest_sha256=release_manifest_sha256,
        receipt_id=golden.receipt_id,
        receipt_payload_sha256=golden.receipt_payload_sha256,
        screenshot_sha256=golden.screenshot_sha256,
        field_map_sha256=golden.field_map_sha256,
    )
    return ShadowObservation(
        observation_id=identifier,
        observed_at=observed_at.isoformat(),
        run_id=run_id,
        step_id="submit",
        workflow_sha256=golden.workflow_sha256,
        durable_workflow_sha256=golden.workflow_sha256,
        release_manifest_sha256=release_manifest_sha256,
        receipt_id=golden.receipt_id,
        receipt_payload_sha256=golden.receipt_payload_sha256,
        field_map_sha256=golden.field_map_sha256,
        screenshot_sha256=golden.screenshot_sha256,
        submit_event_sha256=actual_event,
        normalized_submit_event_sha256=normalized_submit_event_sha256(
            workflow_sha256=golden.workflow_sha256,
            receipt_id=golden.receipt_id,
            receipt_payload_sha256=golden.receipt_payload_sha256,
            screenshot_sha256=golden.screenshot_sha256,
            field_map_sha256=golden.field_map_sha256,
        ),
        submission_proof=SubmissionProof(
            release_manifest_sha256=release_manifest_sha256,
            token_sha256=hashlib.sha256(f"token:{identifier}".encode()).hexdigest(),
            receipt_id=golden.receipt_id,
            receipt_payload_sha256=golden.receipt_payload_sha256,
            screenshot_sha256=golden.screenshot_sha256,
            field_map_sha256=golden.field_map_sha256,
            submit_event_sha256=actual_event,
        ),
        fixture_receipt=FixtureReceipt(
            receipt_id=golden.receipt_id,
            application_id=golden.application_id,
            job_key=golden.job_key,
            payload_sha256=golden.receipt_payload_sha256,
        ),
        action_elapsed_ms={action: 1 for action in REQUIRED_ACTIONS},
        browser_launch_count=1,
        database_bytes=4096,
        screenshot_bytes=2048,
        interruptions=tuple(
            InterruptionObservation(
                point,
                "fail_closed" if point == "post_mark_pre_click" else "recovered",
                0 if point == "post_mark_pre_click" else 1,
                0 if point == "post_mark_pre_click" else 1,
            )
            for point in REQUIRED_INTERRUPTION_POINTS
        ),
        mutations=mutation_observations_from_runtime(runtime_receipts),
    )


def test_exact_two_runtime_bound_executions_compile_but_do_not_certify() -> None:
    receipts = _receipts()
    first_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    releases = (
        hashlib.sha256(b"release:one").hexdigest(),
        hashlib.sha256(b"release:two").hexdigest(),
    )
    executions = tuple(
        ExecutedLoopbackObservation(
            _observation(
                f"observation-{index}",
                first_time + timedelta(days=index - 1),
                release,
                receipts,
            ),
            (
                {
                    "release_manifest_sha256": release,
                    "claim_id": "outcome:role",
                    "supported": True,
                    "cited": True,
                },
            ),
        )
        for index, release in enumerate(releases, 1)
    )
    cohort = compile_full_submit_cohort(
        executions,
        receipts,
        source_git_revision=REVISION,
        source_tree=TREE,
        source_content_revision=SOURCE_CONTENT,
    )
    cohort.verify()
    assert len(cohort.withheld_shadow.observations) == 2
    assert len(set(cohort.withheld_shadow.release_manifest_sha256s)) == 2
    assert tuple(row.control_id for row in receipts) == RUNTIME_CONTROL_IDS
    assert cohort.document()["derived_counts"] == {
        "successful_loopback_submissions": 2,
        "released_claims": 2,
        "released_employer_claims": 2,
        "runtime_negative_controls": len(RUNTIME_CONTROL_IDS),
    }
    assert cohort.metrics_evaluated is False
    assert cohort.production_certification == "withheld"
    assert cohort.certifies_slice is False
    assert cohort.live_time_separated_execution == "not_collected"
    assert cohort.real_applications_submitted == 0


def test_production_cohort_has_no_test_module_imports() -> None:
    from career_automation import shadow_full_submit_cohort

    source = inspect.getsource(shadow_full_submit_cohort)
    assert "from test_" not in source
    assert "import test_" not in source
    assert tuple(MUTATION_TEST_NODES) == REQUIRED_MUTATION_CONTROLS
