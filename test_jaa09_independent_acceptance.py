"""Independent acceptance tests for the cooperative local JAA-09 ATS fixture."""

from __future__ import annotations

import re
import hashlib
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.request import Request, urlopen

from playwright.sync_api import sync_playwright

from career_automation.ats_fixture import (
    FixtureVacancy,
    LocalATSFixture,
)
from career_automation.browser_executor import (
    LocalBrowserExecutor,
    MaterializedValue,
)
from career_automation.browser_workflows import (
    ActionKind,
    ApprovedValue,
    BrowserAction,
    BrowserWorkflow,
    BrowserWorkflowStore,
    SelectorCandidate,
    SelectorStrategy,
    SelectorPlan,
    ValueReference,
    ValueSource,
)


PDF = b"%PDF-1.4\nsynthetic fixture PDF\n%%EOF\n"
NONCE = "fixture-review-nonce-00000001"
FORM_TOKEN = "fixture-form-token-00000000001"
ROOT = Path(__file__).resolve().parent


def _vacancy() -> FixtureVacancy:
    return FixtureVacancy(
        "platform-engineer",
        "fixture:platform-engineer",
        "Platform Engineer",
        "Example Systems Ltd",
    )


@contextmanager
def _fixture() -> Iterator[LocalATSFixture]:
    with LocalATSFixture(
        _vacancy(),
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as fixture:
        yield fixture


def _multipart(
    *,
    work_authorisation: str = "authorised",
    sponsorship_details: str = "",
) -> tuple[bytes, str]:
    boundary = "jaa09-fixture-boundary"
    fields = {
        "fixture_token": FORM_TOKEN,
        "full_name": "Alex Example",
        "email": "alex@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
        "work_authorisation": work_authorisation,
        "sponsorship_details": sponsorship_details,
        "cover_note": "Delivered a synthetic migration example.",
    }
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            (
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"'
                    "\r\n\r\n"
                ).encode(),
                value.encode(),
                b"\r\n",
            )
        )
    for name, filename in (
        ("cv", "alex-cv.pdf"),
        ("cover_letter", "alex-cover-letter.pdf"),
    ):
        chunks.extend(
            (
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{name}"; '
                    f'filename="{filename}"\r\n'
                ).encode(),
                b"Content-Type: application/pdf\r\n\r\n",
                PDF,
                b"\r\n",
            )
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _review(fixture: LocalATSFixture) -> str:
    body, content_type = _multipart()
    request = Request(
        fixture.application_url + "/review",
        data=body,
        headers={"Content-Type": content_type},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        assert response.status == 200
        return response.read().decode()


def _local_browser_inputs(
    fixture: LocalATSFixture,
    tmp_path: Path,
):
    cv = tmp_path / "cv.pdf"
    letter = tmp_path / "cover-letter.pdf"
    cv.write_bytes(b"%PDF-cv")
    letter.write_bytes(b"%PDF-letter")
    definitions = (
        ("full_name", ActionKind.FILL, "Full name", "Alex Example"),
        ("email", ActionKind.FILL, "Email address", "alex@example.test"),
        ("phone", ActionKind.FILL, "Phone number", "+44 7700 900123"),
        ("city", ActionKind.FILL, "Current city", "London"),
        (
            "work_authorisation",
            ActionKind.SELECT_OPTION,
            "UK work authorisation",
            "authorised",
        ),
        (
            "cover_note",
            ActionKind.FILL,
            "Describe one relevant delivery example.",
            "Delivered a synthetic migration example.",
        ),
        ("cv", ActionKind.UPLOAD, "CV (PDF)", cv),
        (
            "cover_letter",
            ActionKind.UPLOAD,
            "Cover letter (PDF)",
            letter,
        ),
    )
    actions: list[BrowserAction] = [
        BrowserAction(
            "open",
            ActionKind.NAVIGATE,
            target_url=fixture.application_url,
        )
    ]
    approvals: list[ApprovedValue] = []
    values: dict[str, MaterializedValue] = {}
    for identifier, kind, label, value in definitions:
        reference = ValueReference(
            ValueSource.EVIDENCE,
            f"EV_{identifier.upper()}",
        )
        candidates = (
            (
                SelectorCandidate(
                    SelectorStrategy.LABEL,
                    "Missing full-name label",
                ),
                SelectorCandidate(SelectorStrategy.CSS, "#full_name"),
            )
            if identifier == "full_name"
            else (SelectorCandidate(SelectorStrategy.LABEL, label),)
        )
        required = (
            ("field_status", "upload_sha256")
            if kind is ActionKind.UPLOAD
            else ("field_status",)
        )
        actions.append(
            BrowserAction(
                identifier,
                kind,
                selectors=SelectorPlan(candidates),
                value_reference=reference,
                required_output_keys=required,
            )
        )
        authorization = f"APPROVAL_{identifier.upper()}"
        approvals.append(ApprovedValue(reference, authorization))
        expected = (
            hashlib.sha256(value.read_bytes()).hexdigest()
            if isinstance(value, Path)
            else None
        )
        values[reference.key] = MaterializedValue(
            reference,
            authorization,
            value,
            expected,
        )
    actions.append(
        BrowserAction(
            "review",
            ActionKind.CLICK,
            selectors=SelectorPlan(
                (
                    SelectorCandidate(
                        SelectorStrategy.ROLE,
                        "button:Review application",
                    ),
                )
            ),
        )
    )
    return (
        BrowserWorkflow("local_fixture_application", tuple(actions)),
        tuple(approvals),
        values,
    )


def test_local_fixture_exposes_accessible_common_and_conditional_fields() -> None:
    with _fixture() as fixture:
        with urlopen(fixture.application_url, timeout=5) as response:
            html = response.read().decode()
            headers = response.headers
        assert response.status == 200
        for identifier in (
            "full_name",
            "email",
            "phone",
            "city",
            "work_authorisation",
            "sponsorship_details",
            "cover_note",
            "cv",
            "cover_letter",
        ):
            assert f'id="{identifier}"' in html
        assert "<label " in html
        assert "Review application" in html
        assert "Local test fixture" in html
        assert headers["Cache-Control"] == "no-store"
        assert "form-action 'self'" in headers["Content-Security-Policy"]


def test_review_then_submit_returns_one_content_addressed_official_receipt() -> None:
    with _fixture() as fixture:
        review = _review(fixture)
        assert 'data-testid="final-submit"' in review
        nonce = re.search(
            r'name="review_nonce" value="([^"]+)"',
            review,
        )
        assert nonce is not None
        request = Request(
            fixture.application_url + "/submit",
            data=(
                f"review_nonce={nonce.group(1)}"
                f"&fixture_token={FORM_TOKEN}"
            ).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            receipt_page = response.read().decode()
            assert response.status == 201
        receipt = fixture.receipt
        assert receipt is not None
        receipt.verify()
        assert receipt.receipt_id in receipt_page
        assert receipt.payload_sha256 in receipt_page
        assert 'data-testid="receipt-id"' in receipt_page
        assert receipt.certifies_slice is False
        assert "alex@example.test" not in str(receipt.document())


def test_fixture_receipt_identity_replays_exactly() -> None:
    with _fixture() as fixture:
        review = _review(fixture)
        nonce = re.search(
            r'name="review_nonce" value="([^"]+)"',
            review,
        )
        assert nonce is not None
        body = (
            f"review_nonce={nonce.group(1)}"
            f"&fixture_token={FORM_TOKEN}"
        ).encode()
        request = Request(
            fixture.application_url + "/submit",
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            method="POST",
        )
        with urlopen(request, timeout=5):
            pass
        receipt = fixture.receipt
        assert receipt is not None
        first = receipt.document()
        receipt.verify()
        assert fixture.receipt is receipt
        assert receipt.document() == first


def test_fixture_source_contains_no_external_asset_or_action_target() -> None:
    source = (
        ROOT
        / "career_automation"
        / "ats_fixture.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "requests.",
        "playwright",
        "selenium",
        "httpx",
        "https://",
        "subprocess",
    ):
        assert forbidden not in source


def test_real_browser_executor_completes_approved_local_form_without_submit(
    tmp_path: Path,
) -> None:
    with _fixture() as fixture:
        workflow, approvals, values = _local_browser_inputs(
            fixture,
            tmp_path,
        )
        store = BrowserWorkflowStore(tmp_path / "browser.sqlite3")
        run_id = store.create_run(workflow, idempotency_key="fixture-run")
        lease = store.claim_run(
            "local_worker",
            run_id=run_id,
            lease_seconds=60,
        )
        assert lease is not None
        executor = LocalBrowserExecutor(store, repository_root=ROOT)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(service_workers="block")
            page = context.new_page()
            completed = tuple(
                executor.execute_next(
                    page,
                    run_id=run_id,
                    worker_id="local_worker",
                    approved_values=approvals,
                    materialized_values=values,
                )
                for _action in workflow.actions
            )
            assert page.get_by_role(
                "heading",
                name="Review application",
            ).is_visible()
            context.close()
            browser.close()
        snapshot = store.run_snapshot(run_id)
        assert snapshot["status"] == "completed"
        assert snapshot["checkpoint_count"] == len(workflow.actions)
        assert completed[1] is not None
        assert completed[1].selector_report is not None
        assert completed[1].selector_report.recovered is True
        database_bytes = (tmp_path / "browser.sqlite3").read_bytes()
        for private_value in (
            b"Alex Example",
            b"alex@example.test",
            b"Delivered a synthetic migration example.",
        ):
            assert private_value not in database_bytes
        assert fixture.receipt is None
