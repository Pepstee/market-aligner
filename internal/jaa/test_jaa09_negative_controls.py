"""Adversarial controls for the cooperative local JAA-09 ATS fixture."""

from __future__ import annotations

import hashlib
import json
import re
import socket
import sqlite3
import inspect
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import pytest

from career_automation.ats_fixture import (
    FixtureReceipt,
    FixtureVacancy,
    LocalATSFixture,
)
from career_automation.browser_executor import (
    ConsequentialActionError,
    LocalBrowserBoundaryError,
    LocalBrowserExecutor,
    ReleaseExecutionAuthority,
    SelectorExecutionError,
    certified_final_submit_click,
)
from career_automation.application_archive import ApplicationArchiveError
from career_automation.browser_workflows import (
    ActionKind,
    ApprovalRequiredError,
    BrowserAction,
    BrowserWorkflow,
    BrowserWorkflowStore,
    ReleaseGateError,
    SelectorCandidate,
    SelectorOutcome,
    SelectorPlan,
    SelectorStrategy,
    StepResult,
    SubmissionProof,
)
from career_automation.release_gate import ReleaseGateStore
from career_automation.testing_sanity_review import fixture_pass_receipt
from playwright.sync_api import sync_playwright
from test_jaa09_independent_acceptance import (
    FORM_TOKEN,
    NONCE,
    ROOT,
    _fixture,
    _local_browser_inputs,
    _multipart,
    _review,
    _released_browser_inputs,
    _vacancy,
)
from test_jaa08_independent_acceptance import _issued_release_inputs


def test_fixture_refuses_non_loopback_bind_or_host_header() -> None:
    with pytest.raises(ValueError, match="loopback"):
        LocalATSFixture(
            _vacancy(),
            nonce=lambda: "fixture-review-nonce-00000001",
            host="0.0.0.0",
        )
    with _fixture() as fixture:
        request = Request(
            fixture.application_url,
            headers={"Host": "external.example"},
        )
        with pytest.raises(HTTPError) as captured:
            urlopen(request, timeout=5)
        assert captured.value.code == 403


def test_fixture_refuses_non_loopback_origin_header() -> None:
    with _fixture() as fixture:
        request = Request(
            fixture.application_url,
            headers={"Origin": "https://external.example"},
        )
        with pytest.raises(HTTPError) as captured:
            urlopen(request, timeout=5)
        assert captured.value.code == 403


def test_fixture_refuses_other_loopback_host_port_or_origin() -> None:
    with _fixture() as fixture:
        parsed = urlsplit(fixture.application_url)
        wrong_port = int(parsed.port) + 1
        for headers in (
            {"Host": f"{parsed.hostname}:{wrong_port}"},
            {"Origin": f"http://{parsed.hostname}:{wrong_port}"},
        ):
            request = Request(
                fixture.application_url,
                headers=headers,
            )
            with pytest.raises(HTTPError) as captured:
                urlopen(request, timeout=5)
            assert captured.value.code == 403


def test_fixture_rejects_review_without_form_authority() -> None:
    with _fixture() as fixture:
        body, content_type = _multipart()
        body = body.replace(
            f"\r\n\r\n{FORM_TOKEN}\r\n".encode(),
            b"\r\n\r\nwrong-form-token\r\n",
            1,
        )
        request = Request(
            fixture.application_url + "/review",
            data=body,
            headers={"Content-Type": content_type},
            method="POST",
        )
        with pytest.raises(HTTPError) as captured:
            urlopen(request, timeout=5)
        assert captured.value.code == 400
        assert fixture.receipt is None


def test_fixture_rejects_request_body_over_two_megabytes() -> None:
    with _fixture() as fixture:
        parsed = urlsplit(fixture.application_url)
        with socket.create_connection(
            (str(parsed.hostname), int(parsed.port)),
            timeout=5,
        ) as client:
            client.sendall(
                (
                    f"POST {parsed.path}/review HTTP/1.1\r\n"
                    f"Host: {parsed.netloc}\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    f"Content-Length: {2 * 1024 * 1024 + 1}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
            )
            response = client.recv(4096)
        assert b" 400 " in response
        assert fixture.receipt is None


def test_direct_submit_without_review_authority_produces_no_receipt() -> None:
    with _fixture() as fixture:
        request = Request(
            fixture.application_url + "/submit",
            data=b"review_nonce=not-authorised",
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as captured:
            urlopen(request, timeout=5)
        assert captured.value.code == 400
        assert fixture.receipt is None


def test_conditional_sponsorship_answer_is_mandatory() -> None:
    with _fixture() as fixture:
        body, content_type = _multipart(
            work_authorisation="needs_sponsorship",
        )
        request = Request(
            fixture.application_url + "/review",
            data=body,
            headers={"Content-Type": content_type},
            method="POST",
        )
        with pytest.raises(HTTPError) as captured:
            urlopen(request, timeout=5)
        assert captured.value.code == 400
        assert b"sponsorship_details" in captured.value.read()
        assert fixture.receipt is None


@pytest.mark.parametrize(
    ("filename", "content_type", "content"),
    (
        ("cv.txt", "text/plain", b"not a pdf"),
        ("cv.pdf", "application/pdf", b"not a pdf"),
    ),
)
def test_non_pdf_upload_is_rejected(
    filename: str,
    content_type: str,
    content: bytes,
) -> None:
    with _fixture() as fixture:
        body, multipart_type = _multipart()
        body = body.replace(b'alex-cv.pdf"', filename.encode() + b'"', 1)
        body = body.replace(
            b"Content-Type: application/pdf",
            f"Content-Type: {content_type}".encode(),
            1,
        )
        body = body.replace(
            b"%PDF-1.4\nsynthetic fixture PDF\n%%EOF\n",
            content,
            1,
        )
        request = Request(
            fixture.application_url + "/review",
            data=body,
            headers={"Content-Type": multipart_type},
            method="POST",
        )
        with pytest.raises(HTTPError) as captured:
            urlopen(request, timeout=5)
        assert captured.value.code == 400
        assert fixture.receipt is None


def test_single_upload_over_one_megabyte_is_rejected() -> None:
    with _fixture() as fixture:
        body, multipart_type = _multipart()
        body = body.replace(
            b"%PDF-1.4\nsynthetic fixture PDF\n%%EOF\n",
            b"%PDF-" + b"x" * (1024 * 1024),
            1,
        )
        request = Request(
            fixture.application_url + "/review",
            data=body,
            headers={"Content-Type": multipart_type},
            method="POST",
        )
        with pytest.raises(HTTPError) as captured:
            urlopen(request, timeout=5)
        assert captured.value.code == 400
        assert fixture.receipt is None


def test_upload_filename_paths_are_reduced_to_basename_before_hashing() -> None:
    vacancy = _vacancy()
    fixture = LocalATSFixture(
        vacancy,
        nonce=lambda: "fixture-review-nonce-00000001",
        form_token=FORM_TOKEN,
    )
    fields = {
        "fixture_token": FORM_TOKEN,
        "full_name": "Alex Example",
        "email": "alex@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
        "work_authorisation": "authorised",
        "cover_note": "Synthetic evidence.",
    }
    uploads = {
        "cv": ("..\\private\\alex-cv.pdf", "application/pdf", b"%PDF-cv"),
        "cover_letter": (
            "../../private/alex-letter.pdf",
            "application/pdf",
            b"%PDF-letter",
        ),
    }
    review = fixture.state.review(fields, uploads)
    expected = {
        "contract": "jaa09.fixture-application.v1",
        "application_id": vacancy.application_id,
        "job_key": vacancy.job_key,
        "fields": {
            key: value
            for key, value in fields.items()
            if key != "fixture_token"
        },
        "sponsorship_details": "",
        "uploads": {
            "cv": {
                "filename": "alex-cv.pdf",
                "sha256": hashlib.sha256(b"%PDF-cv").hexdigest(),
                "size_bytes": len(b"%PDF-cv"),
            },
            "cover_letter": {
                "filename": "alex-letter.pdf",
                "sha256": hashlib.sha256(b"%PDF-letter").hexdigest(),
                "size_bytes": len(b"%PDF-letter"),
            },
        },
    }
    expected_hash = hashlib.sha256(
        json.dumps(
            expected,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    assert review.payload_sha256 == expected_hash


def test_concurrent_nonce_replay_produces_exactly_one_receipt() -> None:
    fixture = LocalATSFixture(
        _vacancy(),
        nonce=lambda: "fixture-review-nonce-00000001",
        form_token=FORM_TOKEN,
    )
    review = fixture.state.review(
        {
            "fixture_token": FORM_TOKEN,
            "full_name": "Alex Example",
            "email": "alex@example.test",
            "phone": "+44 7700 900123",
            "city": "London",
            "work_authorisation": "authorised",
            "cover_note": "Synthetic evidence.",
        },
        {
            "cv": ("cv.pdf", "application/pdf", b"%PDF-cv"),
            "cover_letter": (
                "letter.pdf",
                "application/pdf",
                b"%PDF-letter",
            ),
        },
    )

    def submit():
        try:
            return fixture.state.submit(review.nonce, FORM_TOKEN)
        except FileExistsError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _value: submit(), range(2)))
    receipts = tuple(row for row in results if row is not None)
    assert len(receipts) == 1
    assert fixture.receipt is receipts[0]


def test_duplicate_submit_and_second_review_produce_no_second_receipt() -> None:
    with _fixture() as fixture:
        review = _review(fixture)
        nonce = re.search(
            r'name="review_nonce" value="([^"]+)"',
            review,
        )
        assert nonce is not None
        data = (
            f"review_nonce={nonce.group(1)}"
            f"&fixture_token={FORM_TOKEN}"
        ).encode()

        def submit() -> None:
            request = Request(
                fixture.application_url + "/submit",
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                method="POST",
            )
            with urlopen(request, timeout=5):
                pass

        submit()
        first = fixture.receipt
        assert first is not None
        with pytest.raises(HTTPError) as captured:
            submit()
        assert captured.value.code == 409
        assert fixture.receipt is first
        with pytest.raises(HTTPError) as review_error:
            _review(fixture)
        assert review_error.value.code == 409
        assert fixture.receipt is first


def test_executor_rejects_external_navigation_without_checkpoint(
    tmp_path,
) -> None:
    workflow = BrowserWorkflow(
        "external_navigation",
        (
            BrowserAction(
                "open",
                ActionKind.NAVIGATE,
                target_url="https://external.example/apply",
            ),
        ),
    )
    store = BrowserWorkflowStore(tmp_path / "browser.sqlite3")
    run_id = store.create_run(workflow)
    assert store.claim_run("local_worker", run_id=run_id) is not None
    executor = LocalBrowserExecutor(store, repository_root=ROOT)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        with pytest.raises(LocalBrowserBoundaryError, match="not loopback"):
            executor.execute_next(
                page,
                run_id=run_id,
                worker_id="local_worker",
            )
        browser.close()
    assert store.run_snapshot(run_id)["checkpoint_count"] == 0


def test_executor_records_ambiguous_selector_without_advancing(
    tmp_path,
) -> None:
    with _fixture() as fixture:
        workflow = BrowserWorkflow(
            "ambiguous_selector",
            (
                BrowserAction(
                    "open",
                    ActionKind.NAVIGATE,
                    target_url=fixture.application_url,
                ),
                BrowserAction(
                    "ambiguous",
                    ActionKind.CLICK,
                    selectors=SelectorPlan(
                        (
                            SelectorCandidate(
                                SelectorStrategy.CSS,
                                "input",
                            ),
                        )
                    ),
                ),
            ),
        )
        store = BrowserWorkflowStore(tmp_path / "browser.sqlite3")
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            executor.execute_next(
                page,
                run_id=run_id,
                worker_id="local_worker",
            )
            with pytest.raises(SelectorExecutionError):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                )
            browser.close()
        snapshot = store.run_snapshot(run_id)
        assert snapshot["checkpoint_count"] == 1
        failures = [
            row
            for row in store.events(run_id)
            if row["event_type"] == "selector_candidates_exhausted"
        ]
        assert len(failures) == 1


def test_executor_requires_exact_materialized_authority_without_advancing(
    tmp_path,
) -> None:
    with _fixture() as fixture:
        workflow, approvals, _values = _local_browser_inputs(
            fixture,
            tmp_path,
        )
        store = BrowserWorkflowStore(tmp_path / "browser.sqlite3")
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            executor.execute_next(
                page,
                run_id=run_id,
                worker_id="local_worker",
                approved_values=approvals,
            )
            with pytest.raises(ApprovalRequiredError, match="authority"):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                )
            assert page.locator("#full_name").input_value() == ""
            browser.close()
        assert store.run_snapshot(run_id)["checkpoint_count"] == 1


def test_executor_detects_upload_mutation_before_browser_materialization(
    tmp_path,
) -> None:
    with _fixture() as fixture:
        workflow, approvals, values = _local_browser_inputs(
            fixture,
            tmp_path,
        )
        store = BrowserWorkflowStore(tmp_path / "browser.sqlite3")
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action_index in range(7):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                )
            Path(values["evidence:EV_CV"].value).write_bytes(
                b"%PDF-mutated"
            )
            with pytest.raises(ValueError, match="approved bounded PDF"):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                )
            browser.close()
        assert store.run_snapshot(run_id)["checkpoint_count"] == 7


def test_click_action_cannot_disguise_final_submission(
    tmp_path,
) -> None:
    with _fixture() as fixture:
        workflow, approvals, values = _local_browser_inputs(
            fixture,
            tmp_path,
        )
        disguised = BrowserWorkflow(
            "disguised_submit",
            workflow.actions
            + (
                BrowserAction(
                    "disguised_submit",
                    ActionKind.CLICK,
                    selectors=SelectorPlan(
                        (
                            SelectorCandidate(
                                SelectorStrategy.TEST_ID,
                                "final-submit",
                            ),
                        )
                    ),
                ),
            ),
        )
        store = BrowserWorkflowStore(tmp_path / "browser.sqlite3")
        run_id = store.create_run(disguised)
        assert store.claim_run("local_worker", run_id=run_id) is not None
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action in workflow.actions:
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                )
            with pytest.raises(
                ConsequentialActionError,
                match="SUBMIT action",
            ):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                )
            browser.close()
        assert fixture.receipt is None
        assert (
            store.run_snapshot(run_id)["checkpoint_count"]
            == len(workflow.actions)
        )


def test_interruption_after_click_recovers_receipt_without_second_submit(
    tmp_path,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        "interrupted-platform-engineer",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
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
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        original_complete = store.complete_step
        interrupted = False

        def interrupt_submit(*args, **kwargs):
            nonlocal interrupted
            if kwargs.get("step_id") == "submit" and not interrupted:
                interrupted = True
                raise RuntimeError("injected post-click interruption")
            return original_complete(*args, **kwargs)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action in workflow.actions[:-1]:
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            store.complete_step = interrupt_submit  # type: ignore[method-assign]
            with pytest.raises(
                RuntimeError,
                match="post-click interruption",
            ):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            browser.close()
            first_receipt = fixture.receipt
            assert first_receipt is not None
            assert (
                store.submit_dispatch(run_id)["state"]  # type: ignore[index]
                == "click_started"
            )
            store.complete_step = original_complete  # type: ignore[method-assign]
            resumed_executor = LocalBrowserExecutor(
                store,
                repository_root=ROOT,
            )
            resumed_browser = playwright.chromium.launch(headless=True)
            resumed_page = resumed_browser.new_page()
            completed = resumed_executor.execute_next(
                resumed_page,
                run_id=run_id,
                worker_id="local_worker",
                approved_values=approvals,
                materialized_values=values,
                release_authority=authority,
            )
            resumed_browser.close()
        assert completed is not None
        assert completed.action_kind is ActionKind.SUBMIT
        assert fixture.receipt is first_receipt
        assert store.run_snapshot(run_id)["status"] == "completed"
        events = store.events(run_id)
        assert sum(
            row["event_type"] == "submit_click_started"
            for row in events
        ) == 1


@pytest.mark.parametrize(
    "interruption_point",
    (
        "post_prepare_pre_consume",
        "post_consume_pre_reconcile",
        "post_consume_pre_click",
    ),
)
def test_preclick_interruption_replays_and_submits_exactly_once(
    tmp_path,
    interruption_point: str,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        f"preclick-{interruption_point.replace('_', '-')}",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
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
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
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
            first_browser = playwright.chromium.launch(headless=True)
            first_page = first_browser.new_page()
            for _action in workflow.actions[:-1]:
                executor.execute_next(
                    first_page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            if interruption_point == "post_prepare_pre_consume":
                original = authority.gate.consume_release_token

                def interrupt(**_kwargs):
                    raise RuntimeError("injected before release consumption")

                authority.gate.consume_release_token = interrupt
            elif interruption_point == "post_consume_pre_reconcile":
                original = store.reconcile_release_consumed

                def interrupt(*_args, **_kwargs):
                    raise RuntimeError("injected before consumption reconcile")

                store.reconcile_release_consumed = interrupt  # type: ignore[method-assign]
            else:
                original = store.mark_submit_started

                def interrupt(*_args, **_kwargs):
                    raise RuntimeError("injected before click intent")

                store.mark_submit_started = interrupt  # type: ignore[method-assign]
            with pytest.raises(RuntimeError, match="injected before"):
                executor.execute_next(
                    first_page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            if interruption_point == "post_prepare_pre_consume":
                authority.gate.consume_release_token = original
                assert store.submit_dispatch(run_id)["state"] == "prepared"  # type: ignore[index]
            elif interruption_point == "post_consume_pre_reconcile":
                store.reconcile_release_consumed = original  # type: ignore[method-assign]
                assert store.submit_dispatch(run_id)["state"] == "prepared"  # type: ignore[index]
                with database.connection() as connection:
                    consumed_at = connection.execute(
                        """SELECT consumed_at FROM release_tokens
                           WHERE token_hash=?""",
                        (issued.token_sha256,),
                    ).fetchone()[0]
                assert consumed_at is not None
            else:
                store.mark_submit_started = original  # type: ignore[method-assign]
                assert (
                    store.submit_dispatch(run_id)["state"]  # type: ignore[index]
                    == "release_consumed"
                )
            first_browser.close()
            assert fixture.receipt is None

            resumed_browser = playwright.chromium.launch(headless=True)
            resumed_page = resumed_browser.new_page()
            completed = LocalBrowserExecutor(
                store,
                repository_root=ROOT,
            ).execute_next(
                resumed_page,
                run_id=run_id,
                worker_id="local_worker",
                approved_values=approvals,
                materialized_values=values,
                release_authority=authority,
            )
            resumed_browser.close()
        assert completed is not None
        assert completed.action_kind is ActionKind.SUBMIT
        assert fixture.receipt is not None
        assert store.run_snapshot(run_id)["status"] == "completed"
        assert sum(
            row["event_type"] == "submit_click_started"
            for row in store.events(run_id)
        ) == 1


def test_executor_uses_canonical_trusted_clock_when_caller_time_differs(
    tmp_path,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        "trusted-clock-divergence",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
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
        trusted_consumed_at = authority.consumed_at + timedelta(seconds=1)
        authority = replace(
            authority,
            gate=ReleaseGateStore(
                database.path,
                clock=lambda: trusted_consumed_at,
            ),
        )
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
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
            for _action in workflow.actions:
                completed = executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
                assert completed is not None
            browser.close()
        dispatch = store.submit_dispatch(run_id)
        assert dispatch is not None
        assert dispatch["state"] == "receipt_recorded"
        assert dispatch["release_consumed_at"] == (
            trusted_consumed_at.isoformat()
        )
        assert authority.consumed_at != trusted_consumed_at
        assert fixture.receipt is not None
        assert sum(
            row["event_type"] == "submit_click_started"
            for row in store.events(run_id)
        ) == 1


def test_expected_fixture_payload_normalizes_cover_note_newlines(
    tmp_path,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        "cover-note-newlines",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
    with LocalATSFixture(
        vacancy,
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as fixture:
        _, _, _, _, authority, _ = _released_browser_inputs(
            fixture,
            tmp_path,
            release_inputs,
        )

    def with_newlines(value: str):
        editable = replace(
            authority.artifacts.editable,
            answers_text=value,
            answers_sha256=hashlib.sha256(value.encode()).hexdigest(),
        )
        changed_artifacts = replace(authority.artifacts, editable=editable)
        return SimpleNamespace(
            application_id=authority.application_id,
            job_key=authority.job_key,
            contact=authority.contact,
            artifacts=changed_artifacts,
        )

    expected = LocalBrowserExecutor._expected_fixture_payload_sha256(
        with_newlines("first\nsecond\n")
    )
    assert (
        LocalBrowserExecutor._expected_fixture_payload_sha256(
            with_newlines("first\r\nsecond\r\n")
        )
        == expected
    )
    assert (
        LocalBrowserExecutor._expected_fixture_payload_sha256(
            with_newlines("first\rsecond\r")
        )
        == expected
    )


def test_post_consumption_drift_blocks_submit_before_click(
    tmp_path,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    publication = release_inputs[7]
    vacancy = FixtureVacancy(
        "post-consumption-drift",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
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
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        original_mark = store.mark_submit_started

        def interrupt_before_click(*_args, **_kwargs):
            raise RuntimeError("injected before click")

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action in workflow.actions[:-1]:
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            store.mark_submit_started = interrupt_before_click  # type: ignore[method-assign]
            with pytest.raises(RuntimeError, match="before click"):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            store.mark_submit_started = original_mark  # type: ignore[method-assign]
            dispatch = store.submit_dispatch(run_id)
            assert dispatch is not None
            assert dispatch["state"] == "release_consumed"
            target = (
                authority.artifact_root
                / publication.relative_directory
                / "cv.pdf"
            )
            target.write_bytes(target.read_bytes() + b"drift-before-click")
            with pytest.raises(ValueError, match="differs from its receipt"):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            browser.close()
    assert fixture.receipt is None
    dispatch = store.submit_dispatch(run_id)
    assert dispatch is not None
    assert dispatch["state"] == "release_consumed"
    assert not any(
        row["event_type"] == "submit_click_started"
        for row in store.events(run_id)
    )


def test_release_authority_requires_archive_receipt_and_manifest_hash(
    tmp_path,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        "archive-constructor",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
    with LocalATSFixture(vacancy, nonce=lambda: NONCE, form_token=FORM_TOKEN) as fixture:
        _, _, _, _, authority, _ = _released_browser_inputs(
            fixture, tmp_path, release_inputs
        )
    parameters = inspect.signature(ReleaseExecutionAuthority).parameters
    assert parameters["archive_receipt"].default is inspect.Parameter.empty
    assert parameters["archive_root"].default is inspect.Parameter.empty
    assert authority.archive_receipt.manifest_sha256 in authority.archive_receipt.document().values()
    with pytest.raises(TypeError, match="archive receipt"):
        replace(authority, archive_receipt=None)


def test_archive_is_reverified_after_prefill_and_immediately_before_click(
    tmp_path,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        "archive-final-recheck",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
    with LocalATSFixture(vacancy, nonce=lambda: NONCE, form_token=FORM_TOKEN) as fixture:
        database, workflow, approvals, values, authority, issued = _released_browser_inputs(
            fixture, tmp_path, release_inputs
        )
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=f"JAA08:{issued.manifest.release_manifest_sha256}",
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action in workflow.actions[:-1]:
                assert executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                ) is not None
            manifest = json.loads(
                (
                    authority.archive_root
                    / authority.archive_receipt.manifest_relative_path
                ).read_text()
            )
            digest = manifest["selected"]["form.answers"]
            archived_answer = authority.archive_root / "objects" / digest[:2] / digest
            archived_answer.write_bytes(archived_answer.read_bytes() + b"tamper")
            with pytest.raises(ApplicationArchiveError, match="hash or length mismatch"):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            browser.close()
        assert fixture.receipt is None
        assert not any(
            row["event_type"] == "submit_click_started"
            for row in store.events(run_id)
        )


def test_executor_contains_exactly_one_final_submit_click() -> None:
    source = inspect.getsource(LocalBrowserExecutor._execute_submit)
    primitive = inspect.getsource(certified_final_submit_click)
    assert source.count("certified_final_submit_click(") == 1
    assert "authority.verify_employer_facing_receipts" in primitive
    assert primitive.count("locator.click()") == 1


def test_invalid_jaa08_token_cannot_create_fixture_receipt(
    tmp_path,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        "invalid-token-platform-engineer",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
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
        replacement = (
            "0" if authority.release_token[-1] != "0" else "1"
        )
        invalid_token = authority.release_token[:-1] + replacement
        invalid_authority = replace(
            authority,
            release_token=invalid_token,
        )
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
        store.authorize_release(
            run_id,
            token=invalid_token,
            authorization_reference="JAA08:INVALID_TOKEN_CONTROL",
            idempotency_key="invalid-token-control",
        )
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action in workflow.actions[:-1]:
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=invalid_authority,
                )
            with pytest.raises(
                ReleaseGateError,
                match="not issued",
            ):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=invalid_authority,
                )
            browser.close()
        assert fixture.receipt is None
        assert store.submit_dispatch(run_id) is None
        with database.connection() as connection:
            consumed_at = connection.execute(
                """SELECT consumed_at FROM release_tokens
                   WHERE token_hash=?""",
                (issued.token_sha256,),
            ).fetchone()[0]
        assert consumed_at is None


def test_self_consistent_wrong_payload_receipt_is_not_recorded(
    tmp_path,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        "wrong-payload-receipt",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
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
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        authentic_submit = fixture.state.submit

        def fabricate_receipt(
            nonce: str,
            form_token: str,
        ) -> FixtureReceipt:
            authentic = authentic_submit(nonce, form_token)
            provisional = FixtureReceipt(
                "0" * 64,
                authentic.application_id,
                authentic.job_key,
                "0" * 64,
            )
            forged = replace(
                provisional,
                receipt_id=hashlib.sha256(
                    json.dumps(
                        provisional.document(include_identity=False),
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode()
                ).hexdigest(),
            )
            forged.verify()
            fixture.state.receipt = forged
            return forged

        fixture.state.submit = fabricate_receipt  # type: ignore[method-assign]
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            for _action in workflow.actions[:-1]:
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            with pytest.raises(
                ValueError,
                match="differs from exact JAA-08 authority",
            ):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            browser.close()
        dispatch = store.submit_dispatch(run_id)
        assert dispatch is not None
        assert dispatch["state"] == "click_started"
        assert dispatch["receipt_id"] is None
        assert "submit" not in store.checkpoint_outputs(run_id)
        assert fixture.receipt is not None
        assert fixture.receipt.payload_sha256 == "0" * 64


def test_store_rejects_rehashed_submit_event_without_durable_lineage(
    tmp_path,
) -> None:
    release_inputs = _issued_release_inputs(tmp_path)
    source = release_inputs[4]
    vacancy = FixtureVacancy(
        "rehashed-submit-event",
        source.job_key,
        source.role_title,
        source.company_name,
        source.answers[0].question,
    )
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
        run_id = store.create_run(workflow)
        assert store.claim_run("local_worker", run_id=run_id) is not None
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
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )

            authentic_complete = store.complete_step

            def rehash_event(
                *args: object,
                submission_proof: SubmissionProof | None = None,
                **kwargs: object,
            ) -> bool:
                assert submission_proof is not None
                result = kwargs["result"]
                assert isinstance(result, StepResult)
                forged_identity = "0" * 64
                forged_outputs = dict(result.outputs)
                forged_outputs["submit_event_sha256"] = forged_identity
                kwargs["result"] = StepResult(
                    forged_outputs,
                    result.selector_report,
                )
                return authentic_complete(
                    *args,
                    submission_proof=replace(
                        submission_proof,
                        submit_event_sha256=forged_identity,
                    ),
                    **kwargs,
                )

            store.complete_step = rehash_event  # type: ignore[method-assign]
            with pytest.raises(
                ReleaseGateError,
                match="differs from its durable context",
            ):
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                    release_authority=authority,
                )
            browser.close()

        dispatch = store.submit_dispatch(run_id)
        assert dispatch is not None
        assert dispatch["state"] == "click_started"
        assert dispatch["receipt_id"] is None
        assert "submit" not in store.checkpoint_outputs(run_id)


def test_one_jaa08_token_cannot_prepare_two_browser_submit_runs(
    tmp_path,
) -> None:
    (
        database,
        _strategy,
        _contact,
        _questions,
        _source,
        _artifacts,
        _artifact_root,
        _publication,
        _compilation,
        _gate,
        _route,
        issued,
    ) = _issued_release_inputs(tmp_path)
    submit = BrowserAction(
        "submit",
        ActionKind.SUBMIT,
        selectors=SelectorPlan(
            (
                SelectorCandidate(
                    SelectorStrategy.TEST_ID,
                    "final-submit",
                ),
            )
        ),
    )
    workflow = BrowserWorkflow("token_race_control", (submit,))
    store = BrowserWorkflowStore(database.path)
    first = store.create_run(workflow)
    second = store.create_run(
        workflow,
        idempotency_key="second-token-race-run",
    )
    assert store.claim_run("first_worker", run_id=first) is not None
    assert store.claim_run("second_worker", run_id=second) is not None
    for run_id, decision in (
        (first, "first-token-race-decision"),
        (second, "second-token-race-decision"),
    ):
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key=decision,
        )
    report = submit.selectors.assess(  # type: ignore[union-attr]
        (SelectorOutcome.MATCHED,)
    )
    with pytest.raises(
        sqlite3.IntegrityError,
        match="dispatch insert is invalid",
    ):
        with store.connection() as connection:
            connection.execute(
                """INSERT INTO browser_submit_dispatches(
                     run_id,step_id,action_hash,release_manifest_hash,
                     release_token_hash,field_map_hash,
                     selector_report_json,state)
                   VALUES(?,?,?,?,?,?,?,'click_started')""",
                (
                    second,
                    "submit",
                    "b" * 64,
                    issued.manifest.release_manifest_sha256,
                    issued.token_sha256,
                    "a" * 64,
                    "{}",
                ),
            )
    assert store.prepare_submit_dispatch(
        first,
        "first_worker",
        step_id="submit",
        release_token=issued.release_token,
        field_map_sha256="a" * 64,
        selector_report=report,
    )
    with pytest.raises(
        sqlite3.IntegrityError,
        match="dispatch update is invalid",
    ):
        with store.connection() as connection:
            connection.execute(
                """UPDATE browser_submit_dispatches
                   SET state='release_consumed',
                       release_consumed_at='2030-01-01T00:00:00+00:00'
                   WHERE run_id=?""",
                (first,),
            )
    with pytest.raises(
        ReleaseGateError,
        match="another submit run",
    ):
        store.prepare_submit_dispatch(
            second,
            "second_worker",
            step_id="submit",
            release_token=issued.release_token,
            field_map_sha256="a" * 64,
            selector_report=report,
        )
    with database.connection() as connection:
        consumed_at = connection.execute(
            """SELECT consumed_at FROM release_tokens
               WHERE token_hash=?""",
            (issued.token_sha256,),
        ).fetchone()[0]
    assert consumed_at is None
