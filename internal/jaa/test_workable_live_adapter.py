from __future__ import annotations

import hashlib
import inspect
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from playwright.sync_api import Route, sync_playwright

import career_automation.workable_live_adapter as workable_module
from career_automation.ashby_live_adapter import JAA08ReleaseAuthority
from career_automation.workable_live_adapter import (
    WorkableApplication,
    WorkableField,
    WorkableLiveAdapter,
    WorkableOneUseCircuit,
    WorkablePolicy,
    WorkableSchemaError,
    WorkableSubmissionIndeterminateError,
    WorkableUpload,
)
from form_filling.provider_diagnostics import ProviderDiagnosticObservation


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class FakeGate:
    def __init__(self, manifest: str, token_sha256: str) -> None:
        self.manifest = manifest
        self.token_sha256 = token_sha256
        self.calls = 0

    def consume_release_token(self, **_kwargs: object) -> object:
        self.calls += 1
        return SimpleNamespace(
            release_manifest_sha256=self.manifest,
            token_sha256=self.token_sha256,
        )


def _authority() -> tuple[JAA08ReleaseAuthority, FakeGate]:
    manifest = _sha(b"synthetic release manifest")
    token = f"jaa08.{manifest}.synthetic-secret"
    gate = FakeGate(manifest, _sha(token.encode()))
    return (
        JAA08ReleaseAuthority(
            gate=gate,  # type: ignore[arg-type]
            release_token=token,
            source=SimpleNamespace(
                job_key="workable:synthetic:ABC123",
                vacancy_sha256=_sha(b"vacancy"),
                content_sha256=_sha(b"application source"),
            ),  # type: ignore[arg-type]
            artifacts=SimpleNamespace(
                cv_pdf=SimpleNamespace(pdf_sha256=_sha(b"%PDF-1.4\nsynthetic approved resume\n"))
            ),  # type: ignore[arg-type]
            contact=object(),  # type: ignore[arg-type]
            questions=None,
            artifact_root=Path("/synthetic/artifacts"),
            repository_root=Path("/synthetic/repository"),
            jurisdiction="GB",
            contract_type="employee",
            consumed_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
        ),
        gate,
    )


def _policy() -> WorkablePolicy:
    return WorkablePolicy(
        tenant="synthetic",
        vacancy_id="ABC123",
        job_key="workable:synthetic:ABC123",
        fields=(
            WorkableField("full_name", "text", True, "Full name"),
            WorkableField("email", "email", True, "Email"),
            WorkableField("resume", "file", True, "Resume"),
            WorkableField("terms", "checkbox", True, "I confirm"),
        ),
    )


def _application(tmp_path: Path) -> WorkableApplication:
    resume = tmp_path / "approved.pdf"
    resume.write_bytes(b"%PDF-1.4\nsynthetic approved resume\n")
    answers = {
        "full_name": "Synthetic Candidate",
        "email": "candidate@example.test",
        "terms": True,
    }
    uploads = {"resume": WorkableUpload(resume, _sha(resume.read_bytes()))}
    provisional = WorkableApplication(b"placeholder", answers, uploads)
    package = (
        workable_module._canonical_json(
            {
                "application_source_sha256": _sha(b"application source"),
                "application_url": _policy().application_url,
                "cv_quality_receipt_sha256": _sha(b"poppler quality receipt"),
                "cv_sha256": _sha(resume.read_bytes()),
                "form_answers_sha256": provisional.answers_sha256,
                "job_key": "workable:synthetic:ABC123",
                "schema_version": "jaa.workable-application-package.v1",
                "vacancy_sha256": _sha(b"vacancy"),
            }
        )
        + "\n"
    ).encode()
    return WorkableApplication(
        application_package=package,
        answers=answers,
        uploads=uploads,
    )


def _html(*, success: bool = True) -> str:
    outcome = (
        "document.body.innerHTML='<p>Your application has been submitted successfully.</p>';"
        if success
        else "document.body.innerHTML='<p>Processing</p>';"
    )
    return f"""<!doctype html><html><body>
      <form>
        <label for="full-name">Full name</label>
        <input id="full-name" name="full_name" type="text" required>
        <label for="email">Email</label>
        <input id="email" name="email" type="email" required>
        <label for="resume">Resume</label>
        <input id="resume" name="resume" type="file" required>
        <label for="terms">I confirm</label>
        <input id="terms" name="terms" type="checkbox" required>
        <button type="submit">Submit application</button>
      </form>
      <script>
        window.submitClicks = 0;
        document.querySelector('form').addEventListener('submit', event => {{
          event.preventDefault(); window.submitClicks += 1;
          history.replaceState({{}}, '', location.pathname + '?success');
          {outcome}
        }});
      </script>
    </body></html>"""


def _install(page, policy: WorkablePolicy, *, success: bool = True) -> None:
    def fulfill(route: Route) -> None:
        route.fulfill(status=200, content_type="text/html", body=_html(success=success))

    page.route("**/*", fulfill)
    page.goto(policy.application_url, wait_until="domcontentloaded")


@pytest.fixture
def stable_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        workable_module,
        "_source_identity",
        lambda _root: (
            "a" * 40,
            (("career_automation/workable_live_adapter.py", "b" * 64),),
        ),
    )


def test_inventory_and_prefill_are_separate_and_nonconsequential(
    tmp_path: Path, stable_source: None
) -> None:
    policy = _policy()
    application = _application(tmp_path)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install(page, policy)
        adapter = WorkableLiveAdapter(
            WorkableOneUseCircuit(tmp_path / "circuit.sqlite3"), Path("/synthetic")
        )
        review = adapter.prepare_review(page, policy=policy, application=application)
        assert review.diagnostic_only is True
        assert review.consequential_click_authority is False
        assert page.locator('[name="full_name"]').input_value() == "Synthetic Candidate"
        assert page.locator('[name="resume"]').evaluate("el => el.files.length") == 1
        assert page.evaluate("window.submitClicks") == 0
        assert adapter.circuit.snapshot()["state"] == "ready"
        browser.close()


def test_certified_workable_click_is_one_use_and_hash_journaled(
    tmp_path: Path, stable_source: None
) -> None:
    policy = _policy()
    application = _application(tmp_path)
    authority, gate = _authority()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install(page, policy)
        circuit = WorkableOneUseCircuit(tmp_path / "circuit.sqlite3")
        adapter = WorkableLiveAdapter(circuit, Path("/synthetic"))
        review = adapter.prepare_review(page, policy=policy, application=application)
        receipt = adapter.submit(
            page,
            policy=policy,
            application=application,
            review=review,
            authority=authority,
        )
        assert gate.calls == 1
        assert circuit.snapshot()["state"] == "succeeded"
        assert [row["to_state"] for row in circuit.journal()] == [
            "prepared",
            "release_consumption_started",
            "release_consumed",
            "click_started",
            "succeeded",
        ]
        assert receipt.document["application_package_sha256"] == application.package_sha256
        assert page.evaluate("window.submitClicks") == 1
        browser.close()


def test_missing_success_is_indeterminate_and_never_retried(
    tmp_path: Path, stable_source: None
) -> None:
    policy = _policy()
    application = _application(tmp_path)
    authority, _gate = _authority()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install(page, policy, success=False)
        circuit = WorkableOneUseCircuit(tmp_path / "circuit.sqlite3")
        adapter = WorkableLiveAdapter(circuit, Path("/synthetic"))
        review = adapter.prepare_review(page, policy=policy, application=application)
        with pytest.raises(WorkableSubmissionIndeterminateError):
            adapter.submit(
                page,
                policy=policy,
                application=application,
                review=review,
                authority=authority,
            )
        assert page.evaluate("window.submitClicks") == 1
        assert circuit.snapshot()["state"] == "click_started"
        with pytest.raises(WorkableSubmissionIndeterminateError, match="retry is forbidden"):
            adapter.submit(
                page,
                policy=policy,
                application=application,
                review=review,
                authority=authority,
            )
        assert page.evaluate("window.submitClicks") == 1
        browser.close()


def test_diagnostic_observation_cannot_confer_workable_authority(
    tmp_path: Path, stable_source: None
) -> None:
    policy = _policy()
    application = _application(tmp_path)
    diagnostic = ProviderDiagnosticObservation(
        provider="workable",
        policy_sha256="a" * 64,
        sanitized_url=policy.application_url,
        classification="ready",
        matched_text_sha256=None,
        submit_control_actionable=True,
    )
    authority, _gate = _authority()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install(page, policy)
        adapter = WorkableLiveAdapter(
            WorkableOneUseCircuit(tmp_path / "circuit.sqlite3"), Path("/synthetic")
        )
        with pytest.raises(TypeError, match="certified review"):
            adapter.submit(
                page,
                policy=policy,
                application=application,
                review=diagnostic,  # type: ignore[arg-type]
                authority=authority,
            )
        assert page.evaluate("window.submitClicks") == 0
        browser.close()


def test_dom_drift_rejects_before_release_or_click(
    tmp_path: Path, stable_source: None
) -> None:
    policy = _policy()
    application = _application(tmp_path)
    authority, gate = _authority()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install(page, policy)
        circuit = WorkableOneUseCircuit(tmp_path / "circuit.sqlite3")
        adapter = WorkableLiveAdapter(circuit, Path("/synthetic"))
        review = adapter.prepare_review(page, policy=policy, application=application)
        page.locator("form").evaluate(
            "element => element.setAttribute('data-drift', 'true')"
        )
        with pytest.raises(WorkableSchemaError, match="binding changed"):
            adapter.submit(
                page,
                policy=policy,
                application=application,
                review=review,
                authority=authority,
            )
        assert gate.calls == 0
        assert circuit.snapshot()["state"] == "ready"
        assert page.evaluate("window.submitClicks") == 0
        browser.close()


def test_answer_drift_rejects_before_release_or_click(
    tmp_path: Path, stable_source: None
) -> None:
    policy = _policy()
    application = _application(tmp_path)
    authority, gate = _authority()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install(page, policy)
        circuit = WorkableOneUseCircuit(tmp_path / "circuit.sqlite3")
        adapter = WorkableLiveAdapter(circuit, Path("/synthetic"))
        review = adapter.prepare_review(page, policy=policy, application=application)
        page.locator('[name="full_name"]').fill("Changed Candidate")
        with pytest.raises(WorkableSchemaError, match="answer changed"):
            adapter.submit(
                page,
                policy=policy,
                application=application,
                review=review,
                authority=authority,
            )
        assert gate.calls == 0
        assert circuit.snapshot()["state"] == "ready"
        assert page.evaluate("window.submitClicks") == 0
        browser.close()


def test_package_for_another_vacancy_rejects_before_release_or_click(
    tmp_path: Path, stable_source: None
) -> None:
    policy = _policy()
    application = _application(tmp_path)
    package = json.loads(application.application_package)
    package["job_key"] = "workable:synthetic:OTHER"
    wrong = WorkableApplication(
        (workable_module._canonical_json(package) + "\n").encode(),
        application.answers,
        application.uploads,
    )
    authority, gate = _authority()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install(page, policy)
        circuit = WorkableOneUseCircuit(tmp_path / "circuit.sqlite3")
        adapter = WorkableLiveAdapter(circuit, Path("/synthetic"))
        review = adapter.prepare_review(page, policy=policy, application=wrong)
        with pytest.raises(WorkableSchemaError, match="release source differ"):
            adapter.submit(
                page,
                policy=policy,
                application=wrong,
                review=review,
                authority=authority,
            )
        assert gate.calls == 0
        assert circuit.snapshot()["state"] == "ready"
        assert page.evaluate("window.submitClicks") == 0
        browser.close()


def test_workable_source_has_one_consequential_click_and_real_clean_head() -> None:
    source = inspect.getsource(WorkableLiveAdapter.submit)
    assert source.count("submit.click()") == 1
    assert "trial=True" in source
    root = Path(__file__).resolve().parent
    head, identities = workable_module._source_identity(root)
    assert len(head) == 40
    assert identities[0][0] == "career_automation/workable_live_adapter.py"
