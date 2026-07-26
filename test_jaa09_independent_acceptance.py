"""Independent acceptance tests for the cooperative local JAA-09 ATS fixture."""

from __future__ import annotations

import re
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.request import Request, urlopen

from career_automation.ats_fixture import (
    FixtureVacancy,
    LocalATSFixture,
)


PDF = b"%PDF-1.4\nsynthetic fixture PDF\n%%EOF\n"
NONCE = "fixture-review-nonce-00000001"


def _vacancy() -> FixtureVacancy:
    return FixtureVacancy(
        "platform-engineer",
        "fixture:platform-engineer",
        "Platform Engineer",
        "Example Systems Ltd",
    )


@contextmanager
def _fixture() -> Iterator[LocalATSFixture]:
    with LocalATSFixture(_vacancy(), nonce=lambda: NONCE) as fixture:
        yield fixture


def _multipart(
    *,
    work_authorisation: str = "authorised",
    sponsorship_details: str = "",
) -> tuple[bytes, str]:
    boundary = "jaa09-fixture-boundary"
    fields = {
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
            data=f"review_nonce={nonce.group(1)}".encode(),
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
        body = f"review_nonce={nonce.group(1)}".encode()
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
        Path(__file__).parent
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
