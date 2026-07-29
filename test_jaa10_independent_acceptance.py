"""Independent acceptance for the noncertifying JAA-10 shadow contract."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter_ns

import pytest
from playwright.sync_api import sync_playwright

from career_automation.ats_fixture import (
    FixtureReceipt,
    FixtureVacancy,
    LocalATSFixture,
)
from career_automation.browser_executor import (
    LocalBrowserExecutor,
    SubmissionIndeterminateError,
)
from career_automation.browser_workflows import (
    BrowserWorkflowStore,
    SubmissionProof,
    fixture_submit_event_sha256,
)
from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    HARD_QUALITY_TARGETS,
    MUTATION_TEST_NODES,
    REQUIRED_ACTIONS,
    REQUIRED_INTERRUPTION_POINTS,
    REQUIRED_MUTATION_CONTROLS,
    InterruptionObservation,
    MutationObservation,
    ShadowObservation,
    compile_withheld_shadow_evidence,
    normalized_submit_event_sha256,
    normalized_workflow_sha256,
)
from test_jaa08_independent_acceptance import _issued_release_inputs
from test_jaa09_independent_acceptance import (
    FORM_TOKEN,
    NONCE,
    ROOT,
    _released_browser_inputs,
)


def _observation(
    identifier: str,
    observed_at: datetime,
) -> ShadowObservation:
    golden = FROZEN_SHADOW_CONTRACT
    run_id = f"structured-{identifier}"
    step_id = "submit"
    release_manifest_sha256 = hashlib.sha256(
        f"shadow-release:{identifier}".encode()
    ).hexdigest()
    submit_event_sha256 = fixture_submit_event_sha256(
        run_id=run_id,
        workflow_sha256=golden.workflow_sha256,
        step_id=step_id,
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
        step_id=step_id,
        workflow_sha256=golden.workflow_sha256,
        durable_workflow_sha256=golden.workflow_sha256,
        release_manifest_sha256=release_manifest_sha256,
        receipt_id=golden.receipt_id,
        receipt_payload_sha256=golden.receipt_payload_sha256,
        field_map_sha256=golden.field_map_sha256,
        screenshot_sha256=golden.screenshot_sha256,
        submit_event_sha256=submit_event_sha256,
        normalized_submit_event_sha256=golden.submit_event_sha256,
        submission_proof=SubmissionProof(
            release_manifest_sha256=release_manifest_sha256,
            token_sha256=hashlib.sha256(
                f"shadow-token:{identifier}".encode()
            ).hexdigest(),
            receipt_id=golden.receipt_id,
            receipt_payload_sha256=golden.receipt_payload_sha256,
            field_map_sha256=golden.field_map_sha256,
            screenshot_sha256=golden.screenshot_sha256,
            submit_event_sha256=submit_event_sha256,
        ),
        fixture_receipt=FixtureReceipt(
            receipt_id=golden.receipt_id,
            application_id=golden.application_id,
            job_key=golden.job_key,
            payload_sha256=golden.receipt_payload_sha256,
        ),
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
                    if point != "post_mark_pre_click"
                    else "fail_closed"
                ),
                0 if point == "post_mark_pre_click" else 1,
                0 if point == "post_mark_pre_click" else 1,
            )
            for point in REQUIRED_INTERRUPTION_POINTS
        ),
        mutations=tuple(
            MutationObservation(
                control,
                MUTATION_TEST_NODES[control],
                True,
                False,
            )
            for control in REQUIRED_MUTATION_CONTROLS
        ),
    )


def _frozen_fixture_inputs(tmp_path: Path):
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        FROZEN_SHADOW_CONTRACT.application_id,
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
    return release_inputs, vacancy


def _execute_frozen_observation(
    tmp_path: Path,
    *,
    observation_id: str,
    observed_at: datetime,
    interruptions: tuple[InterruptionObservation, ...],
) -> ShadowObservation:
    release_inputs, vacancy = _frozen_fixture_inputs(tmp_path)
    with LocalATSFixture(
        vacancy,
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as fixture:
        (
            database,
            workflow,
            approvals,
            values,
            authority,
            issued,
        ) = _released_browser_inputs(
            fixture,
            tmp_path,
            release_inputs,
        )
        workflow_sha256 = normalized_workflow_sha256(workflow.to_dict())
        assert workflow_sha256 == FROZEN_SHADOW_CONTRACT.workflow_sha256
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(
            workflow,
            run_id="jaa10-frozen-run-1",
        )
        assert store.claim_run("jaa10_worker", run_id=run_id) is not None
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        elapsed: dict[str, int] = {}
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for action in workflow.actions:
                started = perf_counter_ns()
                completed = executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="jaa10_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
                elapsed[action.step_id] = (
                    perf_counter_ns() - started
                ) // 1_000_000
                assert completed is not None
            screenshot_bytes = len(page.screenshot(full_page=True))
            browser.close()
        outputs = store.checkpoint_outputs(run_id)["submit"]
        for key, expected in (
            ("field_map_sha256", FROZEN_SHADOW_CONTRACT.field_map_sha256),
            ("receipt_id", FROZEN_SHADOW_CONTRACT.receipt_id),
            (
                "receipt_payload_sha256",
                FROZEN_SHADOW_CONTRACT.receipt_payload_sha256,
            ),
            ("screenshot_sha256", FROZEN_SHADOW_CONTRACT.screenshot_sha256),
        ):
            assert outputs[key] == expected
        dispatch = store.submit_dispatch(run_id)
        assert dispatch is not None
        actual_submit_event = str(outputs["submit_event_sha256"])
        expected_actual_submit_event = fixture_submit_event_sha256(
            run_id=run_id,
            workflow_sha256=workflow.content_hash,
            step_id="submit",
            release_manifest_sha256=str(
                dispatch["release_manifest_hash"]
            ),
            receipt_id=str(outputs["receipt_id"]),
            receipt_payload_sha256=str(
                outputs["receipt_payload_sha256"]
            ),
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            field_map_sha256=str(outputs["field_map_sha256"]),
        )
        assert actual_submit_event == expected_actual_submit_event
        normalized_event = normalized_submit_event_sha256(
            workflow_sha256=workflow_sha256,
            receipt_id=str(outputs["receipt_id"]),
            receipt_payload_sha256=str(
                outputs["receipt_payload_sha256"]
            ),
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            field_map_sha256=str(outputs["field_map_sha256"]),
        )
        assert (
            normalized_event
            == FROZEN_SHADOW_CONTRACT.submit_event_sha256
        )
        return ShadowObservation(
            observation_id=observation_id,
            observed_at=observed_at.isoformat(),
            run_id=run_id,
            step_id="submit",
            workflow_sha256=workflow_sha256,
            durable_workflow_sha256=workflow.content_hash,
            release_manifest_sha256=str(
                dispatch["release_manifest_hash"]
            ),
            receipt_id=str(outputs["receipt_id"]),
            receipt_payload_sha256=str(
                outputs["receipt_payload_sha256"]
            ),
            field_map_sha256=str(outputs["field_map_sha256"]),
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            submit_event_sha256=actual_submit_event,
            normalized_submit_event_sha256=normalized_event,
            submission_proof=SubmissionProof(
                release_manifest_sha256=str(
                    dispatch["release_manifest_hash"]
                ),
                token_sha256=issued.token_sha256,
                receipt_id=str(outputs["receipt_id"]),
                receipt_payload_sha256=str(
                    outputs["receipt_payload_sha256"]
                ),
                screenshot_sha256=str(outputs["screenshot_sha256"]),
                field_map_sha256=str(outputs["field_map_sha256"]),
                submit_event_sha256=actual_submit_event,
            ),
            fixture_receipt=FixtureReceipt(
                receipt_id=str(outputs["receipt_id"]),
                application_id=FROZEN_SHADOW_CONTRACT.application_id,
                job_key=FROZEN_SHADOW_CONTRACT.job_key,
                payload_sha256=str(outputs["receipt_payload_sha256"]),
            ),
            action_elapsed_ms=elapsed,
            browser_launch_count=1,
            database_bytes=database.path.stat().st_size,
            screenshot_bytes=screenshot_bytes,
            interruptions=interruptions,
            mutations=tuple(
                MutationObservation(
                    control,
                    MUTATION_TEST_NODES[control],
                    True,
                    False,
                )
                for control in REQUIRED_MUTATION_CONTROLS
            ),
        )


def _execute_interruption(
    tmp_path: Path,
    injection_point: str,
) -> InterruptionObservation:
    release_inputs, vacancy = _frozen_fixture_inputs(tmp_path)
    with LocalATSFixture(
        vacancy,
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as fixture:
        (
            database,
            workflow,
            approvals,
            values,
            authority,
            issued,
        ) = _released_browser_inputs(
            fixture,
            tmp_path,
            release_inputs,
        )
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(
            workflow,
            run_id=f"jaa10-{injection_point}",
        )
        assert store.claim_run("jaa10_worker", run_id=run_id) is not None
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action in workflow.actions[:-1]:
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="jaa10_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            if injection_point == "post_prepare_pre_consume":
                original_consume = authority.gate.consume_release_token

                def stop_before_consume(**_kwargs):
                    raise RuntimeError("injected before consume")

                authority.gate.consume_release_token = stop_before_consume
                with pytest.raises(RuntimeError, match="before consume"):
                    executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    )
                authority.gate.consume_release_token = original_consume
                browser.close()
                assert store.submit_dispatch(run_id)["state"] == "prepared"  # type: ignore[index]
                assert fixture.receipt is None
                resumed = LocalBrowserExecutor(
                    store,
                    repository_root=ROOT,
                )
                resumed_browser = playwright.chromium.launch(headless=True)
                resumed_page = resumed_browser.new_page()
                resumed.execute_next(
                    resumed_page,
                    run_id=run_id,
                    worker_id="jaa10_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
                resumed_browser.close()
                assert fixture.receipt is not None
                result = InterruptionObservation(
                    injection_point,
                    "recovered",
                    1,
                    1,
                )
            elif injection_point == "post_consume_pre_reconcile":
                original_reconcile = store.reconcile_release_consumed

                def stop_before_reconcile(*_args, **_kwargs):
                    raise RuntimeError("injected before consumption reconcile")

                store.reconcile_release_consumed = stop_before_reconcile  # type: ignore[method-assign]
                with pytest.raises(
                    RuntimeError,
                    match="before consumption reconcile",
                ):
                    executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    )
                store.reconcile_release_consumed = original_reconcile  # type: ignore[method-assign]
                browser.close()
                assert store.submit_dispatch(run_id)["state"] == "prepared"  # type: ignore[index]
                with database.connection() as connection:
                    consumed_at = connection.execute(
                        """SELECT consumed_at FROM release_tokens
                           WHERE token_hash=?""",
                        (issued.token_sha256,),
                    ).fetchone()[0]
                assert consumed_at is not None
                assert fixture.receipt is None
                resumed = LocalBrowserExecutor(
                    store,
                    repository_root=ROOT,
                )
                resumed_browser = playwright.chromium.launch(headless=True)
                resumed_page = resumed_browser.new_page()
                resumed.execute_next(
                    resumed_page,
                    run_id=run_id,
                    worker_id="jaa10_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
                resumed_browser.close()
                assert fixture.receipt is not None
                result = InterruptionObservation(
                    injection_point,
                    "recovered",
                    1,
                    1,
                )
            elif injection_point == "post_consume_pre_click":
                original_mark = store.mark_submit_started

                def stop_before_click(*_args, **_kwargs):
                    raise RuntimeError("injected before click")

                store.mark_submit_started = stop_before_click  # type: ignore[method-assign]
                with pytest.raises(RuntimeError, match="before click"):
                    executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    )
                store.mark_submit_started = original_mark  # type: ignore[method-assign]
                browser.close()
                assert (
                    store.submit_dispatch(run_id)["state"]  # type: ignore[index]
                    == "release_consumed"
                )
                resumed = LocalBrowserExecutor(store, repository_root=ROOT)
                resumed_browser = playwright.chromium.launch(headless=True)
                resumed_page = resumed_browser.new_page()
                resumed.execute_next(
                    resumed_page,
                    run_id=run_id,
                    worker_id="jaa10_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
                resumed_browser.close()
                assert fixture.receipt is not None
                result = InterruptionObservation(
                    injection_point,
                    "recovered",
                    1,
                    1,
                )
            elif injection_point == "post_mark_pre_click":
                original_mark = store.mark_submit_started

                def stop_after_mark(*args, **kwargs):
                    original_mark(*args, **kwargs)
                    raise RuntimeError("injected after click intent")

                store.mark_submit_started = stop_after_mark  # type: ignore[method-assign]
                with pytest.raises(RuntimeError, match="after click intent"):
                    executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    )
                store.mark_submit_started = original_mark  # type: ignore[method-assign]
                browser.close()
                assert (
                    store.submit_dispatch(run_id)["state"]  # type: ignore[index]
                    == "click_started"
                )
                assert fixture.receipt is None
                resumed = LocalBrowserExecutor(
                    store,
                    repository_root=ROOT,
                )
                resumed_browser = playwright.chromium.launch(headless=True)
                resumed_page = resumed_browser.new_page()
                with pytest.raises(
                    SubmissionIndeterminateError,
                    match="no recoverable official receipt",
                ):
                    resumed.execute_next(
                        resumed_page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    )
                resumed_browser.close()
                assert fixture.receipt is None
                result = InterruptionObservation(
                    injection_point,
                    "fail_closed",
                    0,
                    0,
                )
            else:
                assert injection_point == "post_click_pre_checkpoint"
                original_complete = store.complete_step
                interrupted = False

                def stop_after_click(*args, **kwargs):
                    nonlocal interrupted
                    if kwargs.get("step_id") == "submit" and not interrupted:
                        interrupted = True
                        raise RuntimeError("injected after click")
                    return original_complete(*args, **kwargs)

                store.complete_step = stop_after_click  # type: ignore[method-assign]
                with pytest.raises(RuntimeError, match="after click"):
                    executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=authority,
                    )
                store.complete_step = original_complete  # type: ignore[method-assign]
                browser.close()
                first_receipt = fixture.receipt
                assert first_receipt is not None
                resumed = LocalBrowserExecutor(store, repository_root=ROOT)
                resumed_browser = playwright.chromium.launch(headless=True)
                resumed_page = resumed_browser.new_page()
                resumed.execute_next(
                    resumed_page,
                    run_id=run_id,
                    worker_id="jaa10_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
                resumed_browser.close()
                assert fixture.receipt is first_receipt
                dispatch = store.submit_dispatch(run_id)
                assert dispatch is not None
                assert dispatch["state"] == "receipt_recorded"
                assert dispatch["receipt_id"] == first_receipt.receipt_id
                assert (
                    dispatch["receipt_payload_hash"]
                    == first_receipt.payload_sha256
                )
                result = InterruptionObservation(
                    injection_point,
                    "recovered",
                    1,
                    1,
                )
        events = store.events(run_id)
        click_intent_count = sum(
            row["event_type"] == "submit_click_started"
            for row in events
        )
        if injection_point == "post_mark_pre_click":
            assert click_intent_count == 1
            assert result.submit_click_count == 0
        else:
            assert click_intent_count == result.submit_click_count
        return result


def test_frozen_shadow_contract_binds_exact_accepted_jaa09_golden_set() -> None:
    golden = FROZEN_SHADOW_CONTRACT
    assert golden.baseline_revision == (
        "8107f09beb3c5651850ad40a0ff8842ac2de1e47"
    )
    assert golden.workflow_sha256 == (
        "ec9329ec86534bc2a1fa37c0f12034806cdedbdd0ba472d34fc74b2ae69961da"
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
    assert evidence.hard_quality_targets == HARD_QUALITY_TARGETS
    assert evidence.metrics_evaluated is False
    assert evidence.production_certification == "withheld"
    assert evidence.certifies_slice is False
    assert evidence.evidence_kind == "synthetic_shadow"
    assert evidence.contract == FROZEN_SHADOW_CONTRACT
    assert evidence.observations == observations
    assert tuple(
        row.observation_sha256 for row in observations
    ) == evidence.observation_sha256s
    assert evidence.release_manifest_sha256s == tuple(
        row.release_manifest_sha256 for row in observations
    )
    assert "receipt" not in evidence.document()
    assert "hard_quality_metrics" not in evidence.document()
    assert "model_cost_microusd" not in evidence.document()
    assert evidence.document()["observations"] == [
        row.document() for row in observations
    ]


def test_observation_identity_changes_with_runtime_metrics() -> None:
    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    first = _observation("shadow-001", observed_at)
    changed = replace(
        first,
        database_bytes=first.database_bytes + 1,
    )
    assert first.observation_sha256 != changed.observation_sha256


def test_two_frozen_fixture_runs_with_synthetic_shadow_times_compile(
    tmp_path: Path,
) -> None:
    interruptions = tuple(
        _execute_interruption(
            tmp_path / point,
            point,
        )
        for point in REQUIRED_INTERRUPTION_POINTS
    )
    first_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    observations = (
        _execute_frozen_observation(
            tmp_path / "shadow-001",
            observation_id="executed-shadow-001",
            observed_at=first_time,
            interruptions=interruptions,
        ),
        _execute_frozen_observation(
            tmp_path / "shadow-002",
            observation_id="executed-shadow-002",
            observed_at=first_time + timedelta(days=1),
            interruptions=interruptions,
        ),
    )
    evidence = compile_withheld_shadow_evidence(
        FROZEN_SHADOW_CONTRACT,
        observations,
    )
    evidence.verify()
    assert len(
        {row.release_manifest_sha256 for row in observations}
    ) == len(observations)
    assert evidence.release_manifest_sha256s == tuple(
        row.release_manifest_sha256 for row in observations
    )
    assert evidence.production_certification == "withheld"
    assert evidence.certifies_slice is False
