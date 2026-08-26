import hashlib
import inspect
import json
from pathlib import Path

import pytest

import career_automation.provider_observation_capture as capture_module
from career_automation.provider_observation_capture import (
    COLLECTOR_IDENTITY,
    _extract_loader_value,
    _persist_capture,
    _persist_failure,
    _redact_sensitive_response,
    _mask_page_for_screenshot,
    capture_greenhouse_observation,
)


ROOT = Path(__file__).resolve().parent
APPLICATION_URL = "https://job-boards.greenhouse.io/example/jobs/1234567"


def _json_bytes(document: dict[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def test_loader_extraction_handles_real_greenhouse_field_names() -> None:
    html = (
        '<script>window.__remixContext={"confirmation_message":"Thanks \\"now\\"",'
        '"confirmationPath":"/example/jobs/1234567/confirmation",'
        '"submitPath":"https:\\/\\/boards.greenhouse.io/example/jobs/1234567"}'
        "</script>"
    )
    assert _extract_loader_value(html, "confirmation_message") == 'Thanks "now"'
    assert _extract_loader_value(html, "confirmationPath").endswith("/confirmation")
    assert _extract_loader_value(html, "submitPath").startswith("https://")


def test_primary_response_redacts_token_and_key_values() -> None:
    raw = (
        b'{"ACCESS_TOKEN":"do-not-archive","public":"kept",'
        b'"apiKey":"also-secret"}'
        b'<input type="hidden" name="csrf" value="hidden-secret">'
        b'<input type=hidden name=csrf value=unquoted-secret>'
        b' Authorization: Bearer bearer-secret'
        b' Authorization: Basic YmFkOnNlY3JldA=='
        b' password: plain-secret'
        b' {"csrf":"json-csrf-secret"}'
    )
    redacted = _redact_sensitive_response(raw)
    assert b"do-not-archive" not in redacted
    assert b"also-secret" not in redacted
    assert b"hidden-secret" not in redacted
    assert b"bearer-secret" not in redacted
    assert b"unquoted-secret" not in redacted
    assert b"YmFkOnNlY3JldA" not in redacted
    assert b"plain-secret" not in redacted
    assert b"json-csrf-secret" not in redacted
    assert b'"public":"kept"' in redacted
    assert redacted.count(b"[REDACTED]") == 8


def test_navigation_failure_is_content_addressed_with_zero_interaction(
    tmp_path: Path,
) -> None:
    failure = _persist_failure(
        archive_root=tmp_path,
        repository_root=ROOT,
        source_url=APPLICATION_URL,
        observed_at="2026-08-06T12:00:00+00:00",
        code="provider_navigation_failed",
        status=None,
        final_url=None,
        primary_response=b"",
        visible_content=b"",
        network=[],
        screenshot=None,
    )
    manifest = json.loads(failure.receipt.manifest_path.read_bytes())
    observation_sha256 = manifest["artifacts"]["observation"]
    observation = json.loads(
        (tmp_path / "objects" / observation_sha256[:2] / observation_sha256).read_bytes()
    )
    assert observation["failure"]["code"] == "provider_navigation_failed"
    assert observation["interaction"] == {
        "fields_filled": 0,
        "files_uploaded": 0,
        "submit_clicks": 0,
    }
    link_path = (
        tmp_path
        / "provider-observation-captures"
        / f"{failure.receipt.manifest_sha256}.terminal.json"
    )
    link = json.loads(link_path.read_bytes())
    terminal = (
        tmp_path / "attempts" / link["attempt_id"] / "terminal-manifest.json"
    )
    assert terminal.is_file()
    assert json.loads(terminal.read_bytes())["outcome"] == "abandoned"


def test_live_collector_clears_input_values_before_screenshot() -> None:
    source = inspect.getsource(capture_greenhouse_observation)
    assert source.index("_mask_page_for_screenshot(page)") < source.index(
        "page.screenshot(full_page=True)"
    )
    masking = inspect.getsource(_mask_page_for_screenshot)
    assert "opaqueMediaRemoved" in masking
    assert "redactedTextNodes" in masking


def test_capture_receipt_is_create_only_and_content_addressed(tmp_path: Path) -> None:
    observation = (
        ROOT
        / "career_automation"
        / "fixtures"
        / "greenhouse-success-test-observation.json"
    ).read_bytes()
    network = _json_bytes(
        {
            "schema_version": "jaa.provider-observation-network.v1",
            "events": [
                {
                    "method": "GET",
                    "resource_type": "document",
                    "status": 200,
                    "url": APPLICATION_URL,
                }
            ],
        }
    )
    form_inventory = _json_bytes(
        {
            "form_state": {
                "fields": [],
                "provider": "greenhouse",
                "schema_version": "jaa.greenhouse-form-state.v1",
                "title": "Example vacancy",
                "url": APPLICATION_URL,
            },
            "schema_version": "jaa.greenhouse-form-inventory.v1",
            "select_inventories": [],
            "title": "Example vacancy",
            "url": APPLICATION_URL,
        }
    )
    receipt = _persist_capture(
        archive_root=tmp_path,
        repository_root=ROOT,
        source_url=APPLICATION_URL,
        observed_at="2026-08-05T10:00:00+00:00",
        observation=observation,
        primary_response=b"provider response",
        visible_content=b"Example vacancy",
        network_events=network,
        screenshot=b"png fixture",
        screenshot_safety=_json_bytes(
            {
                "schema_version": "jaa.provider-screenshot-masking-proof.v1",
                "policy": "test-masked",
            }
        ),
        form_inventory=form_inventory,
    )
    manifest = json.loads(receipt.manifest_path.read_bytes())
    assert (
        receipt.manifest_sha256
        == hashlib.sha256(receipt.manifest_path.read_bytes()).hexdigest()
    )
    assert receipt.observation_sha256 == hashlib.sha256(observation).hexdigest()
    assert receipt.form_inventory == form_inventory
    assert receipt.form_inventory_sha256 == hashlib.sha256(form_inventory).hexdigest()
    assert manifest["collector_identity"] == COLLECTOR_IDENTITY
    assert manifest["source_url"] == APPLICATION_URL
    assert manifest["interaction"] == {
        "fields_filled": 0,
        "files_uploaded": 0,
        "submit_clicks": 0,
    }
    for digest in manifest["artifacts"].values():
        value = (tmp_path / "objects" / digest[:2] / digest).read_bytes()
        assert hashlib.sha256(value).hexdigest() == digest

    repeated = _persist_capture(
        archive_root=tmp_path,
        repository_root=ROOT,
        source_url=APPLICATION_URL,
        observed_at="2026-08-05T10:00:00+00:00",
        observation=observation,
        primary_response=b"provider response",
        visible_content=b"Example vacancy",
        network_events=network,
        screenshot=b"png fixture",
        screenshot_safety=_json_bytes(
            {
                "schema_version": "jaa.provider-screenshot-masking-proof.v1",
                "policy": "test-masked",
            }
        ),
        form_inventory=form_inventory,
    )
    assert repeated.manifest_sha256 == receipt.manifest_sha256


@pytest.mark.parametrize(
    ("failure_stage", "expected_code"),
    (
        ("browser_launch", "provider_browser_launch_failed"),
        ("page_create", "provider_page_create_failed"),
        ("navigation", "provider_navigation_failed"),
        ("response_body_read", "provider_response_body_read_failed"),
        ("hydration_wait", "provider_hydration_wait_failed"),
        ("visible_text_read", "provider_visible_text_read_failed"),
        ("screenshot_masking", "provider_screenshot_masking_failed"),
        ("screenshot_capture", "provider_screenshot_capture_failed"),
    ),
)
def test_every_browser_stage_failure_is_terminally_archived(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    expected_code: str,
) -> None:
    import playwright.sync_api as playwright_api

    class Response:
        status = 200

        def body(self):
            if failure_stage == "response_body_read":
                raise RuntimeError("body failed")
            return (
                b'<script>{"confirmationPath":"/example/jobs/1234567/confirmation",'
                b'"confirmation_message":"Thanks",'
                b'"submitPath":"https://boards.greenhouse.io/example/jobs/1234567"}'
                b"</script>"
            )

    class Locator:
        def inner_text(self):
            if failure_stage == "visible_text_read":
                raise RuntimeError("inner text failed")
            return "Example vacancy"

    class Page:
        url = APPLICATION_URL

        def on(self, *_args):
            return None

        def goto(self, *_args, **_kwargs):
            if failure_stage == "navigation":
                raise RuntimeError("navigation failed")
            return Response()

        def wait_for_timeout(self, _timeout):
            if failure_stage == "hydration_wait":
                raise RuntimeError("wait failed")

        def locator(self, _selector):
            return Locator()

        def evaluate(self, _script):
            if failure_stage == "screenshot_masking":
                raise RuntimeError("masking failed")
            return {
                "clearedInputs": 0,
                "opaqueMediaRemoved": 0,
                "redactedTextNodes": 0,
            }

        def screenshot(self, **_kwargs):
            if failure_stage == "screenshot_capture":
                raise RuntimeError("screenshot failed")
            return b"masked png"

    class Browser:
        def new_page(self):
            if failure_stage == "page_create":
                raise RuntimeError("page failed")
            return Page()

        def close(self):
            return None

    class Chromium:
        def launch(self, **_kwargs):
            if failure_stage == "browser_launch":
                raise RuntimeError("launch failed")
            return Browser()

    class Playwright:
        chromium = Chromium()

    class Context:
        def __enter__(self):
            return Playwright()

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(capture_module, "_capture_preflight", lambda *_args: None)
    monkeypatch.setattr(capture_module, "exact_clean_head", lambda _root: "a" * 40)
    current_source = Path(capture_module.__file__).read_bytes()
    monkeypatch.setattr(
        capture_module,
        "collector_source_identity",
        lambda *_args, **_kwargs: (
            current_source,
            hashlib.sha256(current_source).hexdigest(),
        ),
    )
    monkeypatch.setattr(playwright_api, "sync_playwright", lambda: Context())
    with pytest.raises(capture_module.ProviderObservationCaptureFailure) as caught:
        capture_greenhouse_observation(
            source_url=APPLICATION_URL,
            archive_root=tmp_path,
            repository_root=ROOT,
        )
    manifest = json.loads(caught.value.receipt.manifest_path.read_bytes())
    observation_sha256 = manifest["artifacts"]["observation"]
    observation = json.loads(
        (tmp_path / "objects" / observation_sha256[:2] / observation_sha256).read_bytes()
    )
    assert observation["failure"]["code"] == expected_code
    assert (
        tmp_path
        / "provider-observation-captures"
        / f"{caught.value.receipt.manifest_sha256}.terminal.json"
    ).is_file()
