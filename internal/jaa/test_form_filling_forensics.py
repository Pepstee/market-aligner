from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from playwright.sync_api import Route, sync_playwright

from form_filling.ats_forensics import (
    ATSForensicReceipt,
    ATSForensicRecorder,
    redact_text,
    runtime_fingerprint,
    sanitize_url,
    verify_forensic_receipt,
)
from form_filling.provider_diagnostics import (
    ASHBY_DIAGNOSTIC_POLICY,
    WORKABLE_DIAGNOSTIC_POLICY,
    ProviderDiagnosticObservation,
    inspect_provider_page,
)


class Clock:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> str:
        self.value += 1
        return f"2026-08-20T00:00:{self.value:02d}+00:00"


def _recorder(tmp_path: Path, *, ats_name: str = "ashby") -> ATSForensicRecorder:
    return ATSForensicRecorder(
        tmp_path,
        attempt_id="synthetic-attempt-1",
        application_id="synthetic-application",
        ats_name=ats_name,
        application_url="https://jobs.ashbyhq.com/example/application?token=secret",
        runtime={"runtime_sha256": "a" * 64, "headless": True},
        release_manifest_sha256="b" * 64,
        artifact_set_sha256="c" * 64,
        clock=Clock(),
    )


def test_records_only_redacted_content_addressed_diagnostics(tmp_path: Path) -> None:
    recorder = _recorder(tmp_path)
    recorder.record_request(
        method="post",
        url="https://jobs.ashbyhq.com/api/submit?captcha=secret",
        resource_type="xhr",
        headers={
            "Authorization": "Bearer super-secret-token",
            "Cookie": "session=secret",
            "Content-Type": "application/json",
            "Origin": "https://jobs.ashbyhq.com/application?private=yes",
        },
        post_data='{"email":"candidate@example.com","phone":"+44 7000 000000"}',
    )
    recorder.record_checkpoint(
        "caller_data_is_redacted",
        email="candidate@example.com",
        nested={"authorization": "Bearer top-secret-token"},
        callback_url="https://example.com/receipt?token=private",
    )
    screenshot_hash = recorder.record_screenshot(b"synthetic-png", label="failure")
    receipt = recorder.finalize(outcome="blocked", failure_class="synthetic_block")

    verified = verify_forensic_receipt(tmp_path, receipt)
    encoded = json.dumps(verified, sort_keys=True)
    assert "candidate@example.com" not in encoded
    assert "+44 7000 000000" not in encoded
    assert "super-secret-token" not in encoded
    assert "top-secret-token" not in encoded
    assert "token=private" not in encoded
    assert "<redacted-email>" in encoded
    assert screenshot_hash in encoded
    assert verified["diagnostic_only"] is True
    assert verified["release_authority"] is False
    assert verified["submission_authority"] is False


def test_receipt_and_verifier_fail_closed_on_authority_and_path_escape(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="cannot carry"):
        ATSForensicReceipt(
            attempt_id="synthetic-attempt",
            manifest_sha256="a" * 64,
            manifest_path="manifests/synthetic-attempt.json",
            outcome="prepared",
            event_count=1,
            submission_authority=True,
        )
    with pytest.raises(ValueError, match="attempt ID"):
        ATSForensicRecorder(
            tmp_path,
            attempt_id="../../escape",
            application_id="application",
            ats_name="workable",
            application_url="https://apply.workable.com/example/j/id/apply/",
            runtime={},
        )

    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    receipt = ATSForensicReceipt(
        attempt_id="synthetic-attempt",
        manifest_sha256="a" * 64,
        manifest_path="../outside.json",
        outcome="prepared",
        event_count=1,
    )
    with pytest.raises(ValueError, match="escapes"):
        verify_forensic_receipt(root, receipt)


def test_manifest_and_screenshot_tampering_are_rejected(tmp_path: Path) -> None:
    recorder = _recorder(tmp_path)
    recorder.record_screenshot(b"original", label="pre-submit")
    receipt = recorder.finalize(outcome="prepared")
    manifest_path = tmp_path / receipt.manifest_path
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    object_path = tmp_path / document["events"][0]["payload"]["object_path"]
    object_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="screenshot object"):
        verify_forensic_receipt(tmp_path, receipt)

    object_path.write_bytes(b"original")
    document["submission_authority"] = True
    manifest_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest hash"):
        verify_forensic_receipt(tmp_path, receipt)


def test_runtime_fingerprint_hashes_environment_specific_strings() -> None:
    value = runtime_fingerprint(
        browser_name="chromium",
        browser_version="151.0",
        headless=True,
        user_agent="private user agent",
        locale="en-GB",
        viewport={"width": 1440, "height": 900},
    )
    encoded = json.dumps(value, sort_keys=True)
    assert "private user agent" not in encoded
    assert "executable" not in value
    assert len(value["executable_sha256"]) == 64
    assert len(value["runtime_sha256"]) == 64


@pytest.mark.parametrize(
    ("url", "policy", "body", "expected"),
    (
        (
            "https://apply.workable.com/example/j/ABC/apply/",
            WORKABLE_DIAGNOSTIC_POLICY,
            "<h1>Apply</h1><input value='candidate@example.com'>"
            "<button>Submit application</button>",
            "ready",
        ),
        (
            "https://jobs.ashbyhq.com/example/application",
            ASHBY_DIAGNOSTIC_POLICY,
            "<h1>Apply</h1><p>Your application submission was flagged as possible spam.</p>"
            "<button>Submit Application</button>",
            "blocked:ashby_possible_spam",
        ),
    ),
)
def test_pinned_playwright_synthetic_provider_canary_never_clicks(
    tmp_path: Path,
    url: str,
    policy,
    body: str,
    expected: str,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()

        def fulfill(route: Route) -> None:
            route.fulfill(
                status=200,
                content_type="text/html",
                body=(
                    "<!doctype html><html><body>"
                    f"{body}<script>window.submitClicks=0;"
                    "document.querySelector('button').addEventListener('click',"
                    "()=>window.submitClicks++);</script></body></html>"
                ),
            )

        page.route("**/*", fulfill)
        recorder = ATSForensicRecorder(
            tmp_path,
            attempt_id=f"{policy.provider}-synthetic-canary",
            application_id="synthetic-application",
            ats_name=policy.provider,
            application_url=url,
            runtime=runtime_fingerprint(
                browser_name="chromium",
                browser_version=browser.version,
                headless=True,
                user_agent="synthetic-user-agent",
            ),
            clock=Clock(),
        )
        recorder.attach_playwright(page)
        page.goto(url, wait_until="domcontentloaded")
        observation = inspect_provider_page(page, policy)
        recorder.record_checkpoint("provider_inspection", **observation.document())
        recorder.capture_page(page, label="synthetic-inspection")
        receipt = recorder.finalize(outcome="prepared", receipt_url=page.url)
        verified = verify_forensic_receipt(tmp_path, receipt)

        assert observation.classification == expected
        assert observation.submit_control_actionable is True
        assert observation.consequential_click_authority is False
        assert observation.submit_click_count == 0
        assert page.evaluate("window.submitClicks") == 0
        assert verified["outcome"] == "prepared"
        assert "candidate@example.com" not in json.dumps(verified)
        browser.close()


def test_provider_diagnostic_module_has_no_consequential_click_primitive() -> None:
    source = inspect.getsource(inspect_provider_page)
    assert "trial=True" in source
    assert "submit.click()" not in source
    with pytest.raises(ValueError, match="cannot authorize"):
        ProviderDiagnosticObservation(
            provider="workable",
            policy_sha256="a" * 64,
            sanitized_url="https://apply.workable.com/example/j/id/apply/",
            classification="ready",
            matched_text_sha256=None,
            submit_control_actionable=True,
            consequential_click_authority=True,
        )


def test_basic_redaction_and_url_sanitization() -> None:
    assert redact_text("candidate@example.com +44 7000 000000") == (
        "<redacted-email> <redacted-phone>"
    )
    assert sanitize_url("javascript:alert(1)") == "<invalid-or-non-http-url>"
    assert "query" not in sanitize_url("https://example.com/path?query=secret")
