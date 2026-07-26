"""Adversarial controls for the cooperative local JAA-09 ATS fixture."""

from __future__ import annotations

import hashlib
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import pytest

from career_automation.ats_fixture import LocalATSFixture
from career_automation.browser_executor import (
    ConsequentialActionError,
    LocalBrowserBoundaryError,
    LocalBrowserExecutor,
    SelectorExecutionError,
)
from career_automation.browser_workflows import (
    ActionKind,
    ApprovalRequiredError,
    BrowserAction,
    BrowserWorkflow,
    BrowserWorkflowStore,
    SelectorCandidate,
    SelectorPlan,
    SelectorStrategy,
)
from playwright.sync_api import sync_playwright
from test_jaa09_independent_acceptance import (
    FORM_TOKEN,
    ROOT,
    _fixture,
    _local_browser_inputs,
    _multipart,
    _review,
    _vacancy,
)


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
