from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from playwright.sync_api import Route, sync_playwright

import career_automation.workable_live_adapter as workable_module
from career_automation.ashby_live_adapter import JAA08ReleaseAuthority
from career_automation.candidate_release_gate import (
    WorkableReleaseBinding,
    WorkableUploadBinding,
)
from career_automation.workable_live_adapter import (
    WorkableApplication,
    WorkableCircuitError,
    WorkableField,
    WorkableLiveAdapter,
    WorkableOneUseCircuit,
    WorkablePolicy,
    WorkableSchemaError,
    WorkableSubmissionIndeterminateError,
    WorkableUpload,
    SyntheticWorkableFixtureAdapter,
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
    page.goto(
        f"http://127.0.0.1/fixture/workable/{policy.tenant}/j/"
        f"{policy.vacancy_id}/apply/",
        wait_until="domcontentloaded",
    )
    page.evaluate("window.__JAA_WORKABLE_FIXTURE__ = true")


def _install_inventory_fixture(page, body: str) -> None:
    def fulfill(route: Route) -> None:
        route.fulfill(
            status=200,
            content_type="text/html",
            body=f"<!doctype html><html><body><form>{body}</form></body></html>",
        )

    page.route("**/*", fulfill)
    page.goto(_policy().application_url, wait_until="domcontentloaded")


@pytest.mark.parametrize(
    ("body", "expected"),
    (
        (
            '<label for="name-field">Full name</label>'
            '<input id="name-field" name="full_name" type="text" required>',
            WorkableField("full_name", "text", True, "Full name"),
        ),
        (
            '<label>Phone number<input name="phone" type="tel"></label>',
            WorkableField("phone", "tel", False, "Phone number"),
        ),
        (
            '<input name="portfolio" type="url" aria-label="Portfolio URL">',
            WorkableField("portfolio", "url", False, "Portfolio URL"),
        ),
        (
            '<span id="motivation_label">Motivation</span>'
            '<textarea name="motivation" aria-labelledby="motivation_label"></textarea>',
            WorkableField("motivation", "textarea", False, "Motivation"),
        ),
        (
            '<span id="TOKEN_label">Resume</span>'
            '<input id="input_files_input_TOKEN" type="file" required>',
            WorkableField("resume", "file", True, "Resume"),
        ),
        (
            '<span id="TOKEN_label">Resume</span>'
            '<span id="description_input_TOKEN">Choose file</span>'
            '<label for="input_files_input_TOKEN">Decorative upload icon</label>'
            '<label for="input_files_input_TOKEN">Choose file</label>'
            '<input id="input_files_input_TOKEN" type="file" required '
            'aria-labelledby="TOKEN_label description_input_TOKEN">',
            WorkableField("resume", "file", True, "Resume"),
        ),
    ),
)
def test_inventory_accepts_one_unambiguous_accessible_name_source(
    body: str, expected: WorkableField
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_inventory_fixture(page, body)
        assert WorkableLiveAdapter.inventory(page) == (expected,)
        assert WorkableLiveAdapter._control(page, expected).count() == 1
        assert page.locator("input, textarea, select").input_value() == ""
        browser.close()


@pytest.mark.parametrize(
    ("body", "reason"),
    (
        (
            '<label for="field">First label</label><label for="field">Second label</label>'
            '<input id="field" name="field" type="text">',
            "ambiguous_associated_labels",
        ),
        (
            '<span id="field_label">Primary label</span>'
            '<input id="field" name="field" type="text" '
            'aria-labelledby="field_label" aria-label="Conflicting label">',
            "conflicting_aria_names",
        ),
        (
            '<span id="duplicate">One</span><span id="duplicate">Two</span>'
            '<input name="field" type="text" aria-labelledby="duplicate">',
            "invalid_aria_labelledby",
        ),
        ('<input name="field" type="text">', "unlabeled_control"),
        (
            '<label>Visible<input name="visible" type="text"></label>'
            '<label>Trap<input name="trap" type="text" hidden></label>',
            "hidden_or_disabled_control",
        ),
        (
            '<label for="duplicate-id">One</label>'
            '<input id="duplicate-id" name="one" type="text">'
            '<label for="duplicate-id">Two</label>'
            '<input id="duplicate-id" name="two" type="text">',
            "duplicate_control_id",
        ),
        (
            '<span id="TOKEN_label">Resume</span>'
            '<span id="TOKEN_label">Other document</span>'
            '<input id="input_files_input_TOKEN" type="file">',
            "ambiguous_provider_label",
        ),
        (
            '<label for="nameless">Nameless</label>'
            '<input id="nameless" type="text">',
            "missing_stable_field_identity",
        ),
    ),
)
def test_inventory_rejects_ambiguous_unlabelled_or_hidden_controls(
    body: str, reason: str
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_inventory_fixture(page, body)
        with pytest.raises(WorkableSchemaError, match=reason):
            WorkableLiveAdapter.inventory(page)
        browser.close()


def test_inventory_rejects_duplicate_normalized_field_identity() -> None:
    body = (
        '<label>First<input name="duplicate" type="text"></label>'
        '<label>Second<input name="duplicate" type="text"></label>'
    )
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_inventory_fixture(page, body)
        with pytest.raises(WorkableSchemaError, match="duplicate field identities"):
            WorkableLiveAdapter.inventory(page)
        browser.close()


def test_accessible_name_drift_rejects_against_reviewed_policy() -> None:
    policy = WorkablePolicy(
        tenant="synthetic",
        vacancy_id="ABC123",
        job_key="workable:synthetic:ABC123",
        fields=(WorkableField("full_name", "text", True, "Full name"),),
    )
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_inventory_fixture(
            page,
            '<label for="name-field">Full name</label>'
            '<input id="name-field" name="full_name" type="text" required>'
            '<button type="submit">Submit application</button>',
        )
        page.locator('label[for="name-field"]').evaluate(
            "label => label.textContent = 'Changed name'"
        )
        with pytest.raises(WorkableSchemaError, match="inventory differs"):
            WorkableLiveAdapter._assert_schema(page, policy)
        browser.close()


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
        adapter = SyntheticWorkableFixtureAdapter(
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
        adapter = SyntheticWorkableFixtureAdapter(circuit, Path("/synthetic"))
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
        adapter = SyntheticWorkableFixtureAdapter(circuit, Path("/synthetic"))
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
        adapter = SyntheticWorkableFixtureAdapter(
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
        adapter = SyntheticWorkableFixtureAdapter(circuit, Path("/synthetic"))
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
        adapter = SyntheticWorkableFixtureAdapter(circuit, Path("/synthetic"))
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
        adapter = SyntheticWorkableFixtureAdapter(circuit, Path("/synthetic"))
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
    production = inspect.getsource(WorkableLiveAdapter.submit)
    assert "JAA08ReleaseAuthority" not in production
    source = inspect.getsource(WorkableLiveAdapter._submit)
    assert source.count("certified_final_submit_click(") == 1
    assert source.count("submit.click()") == 0
    assert "trial=True" in source
    root = Path(__file__).resolve().parent
    head, identities = workable_module._source_identity(root)
    assert len(head) == 40
    assert identities[0][0] == "career_automation/workable_live_adapter.py"


def test_crash_after_consumption_before_click_intent_is_not_replayable(
    tmp_path: Path,
) -> None:
    circuit = WorkableOneUseCircuit(tmp_path / "circuit.sqlite3")
    binding = "1" * 64
    circuit.prepare(binding)
    circuit.consumption_started(binding)
    circuit.release_consumed(binding, "2" * 64, "3" * 64)
    assert circuit.snapshot()["state"] == "release_consumed"
    receipt = circuit.reconcile_preclick_crash(
        binding, reason_code="process_crash_after_token_consumption"
    )
    assert receipt.document["disposition"] == "blocked_no_click_retry"
    assert circuit.snapshot()["state"] == "blocked"
    recovered = WorkableOneUseCircuit(circuit.path).reconciliation_receipts()
    assert recovered == (receipt,)
    with pytest.raises(WorkableCircuitError, match="no longer retryable"):
        circuit.prepare(binding)
    with pytest.raises(WorkableCircuitError, match="no longer retryable"):
        circuit.release_consumed(binding, "2" * 64, "3" * 64)
    with pytest.raises(WorkableCircuitError, match="pre-click release crash"):
        circuit.reconcile_preclick_crash(binding, reason_code="duplicate_reconcile")


def test_restart_from_prepared_is_terminally_reconciled_without_release_or_click(
    tmp_path: Path,
) -> None:
    path = tmp_path / "circuit.sqlite3"
    binding = "a" * 64
    WorkableOneUseCircuit(path).prepare(binding)
    restarted = WorkableOneUseCircuit(path)
    receipt = restarted.reconcile_preclick_crash(
        binding, reason_code="process_crash_after_prepare"
    )
    assert receipt.document["from_state"] == "prepared"
    assert receipt.document["release_manifest_sha256"] is None
    assert receipt.document["token_sha256"] is None
    assert restarted.snapshot()["state"] == "blocked"
    transitions = tuple(row["to_state"] for row in restarted.journal())
    assert transitions == ("prepared", "blocked")
    assert "release_consumption_started" not in transitions
    assert "click_started" not in transitions
    assert WorkableOneUseCircuit(path).reconciliation_receipts() == (receipt,)


def test_crash_after_click_intent_is_terminal_and_forbids_duplicate_click(
    tmp_path: Path,
) -> None:
    circuit = WorkableOneUseCircuit(tmp_path / "circuit.sqlite3")
    binding = "4" * 64
    circuit.prepare(binding)
    circuit.consumption_started(binding)
    circuit.release_consumed(binding, "5" * 64, "6" * 64)
    circuit.click_started(binding)
    assert circuit.snapshot()["state"] == "click_started"
    with pytest.raises(WorkableCircuitError, match="no longer retryable"):
        circuit.click_started(binding)
    assert [event["to_state"] for event in circuit.journal()].count("click_started") == 1


def test_route_or_binding_substitution_cannot_reuse_prepared_circuit(
    tmp_path: Path,
) -> None:
    circuit = WorkableOneUseCircuit(tmp_path / "circuit.sqlite3")
    circuit.prepare("7" * 64)
    with pytest.raises(WorkableCircuitError, match="binding changed"):
        circuit.consumption_started("8" * 64)


def test_cogna_cover_upload_must_equal_assured_cover_pdf(tmp_path: Path) -> None:
    cv = tmp_path / "cv.pdf"
    cover = tmp_path / "cover.pdf"
    unrelated = tmp_path / "unrelated.pdf"
    cv.write_bytes(b"assured-cv")
    cover.write_bytes(b"assured-cover")
    unrelated.write_bytes(b"unrelated-cover")
    policy = WorkablePolicy(
        tenant="",
        vacancy_id="847CFBC5F4",
        job_key="workable:cogna:847CFBC5F4",
        fields=(
            WorkableField("resume", "file", True, "Resume"),
            WorkableField("cover_letter", "file", True, "Cover letter"),
        ),
    )
    answers: dict[str, str | bool] = {}
    wrong_uploads = {
        "resume": WorkableUpload(cv, _sha(cv.read_bytes())),
        "cover_letter": WorkableUpload(unrelated, _sha(unrelated.read_bytes())),
    }
    provisional = WorkableApplication(b"placeholder", answers, wrong_uploads)
    upload_bindings = (
        WorkableUploadBinding("resume", "cv", _sha(cv.read_bytes()), "8" * 64),
        WorkableUploadBinding(
            "cover_letter", "cover_letter", _sha(cover.read_bytes()), "9" * 64
        ),
    )
    package = {
        "application_source_sha256": "a" * 64,
        "application_url": policy.application_url,
        "attached_roles": ["cv", "cover_letter"],
        "cover_letter_assurance_receipt_sha256": "9" * 64,
        "cover_letter_sha256": _sha(cover.read_bytes()),
        "cv_assurance_receipt_sha256": "8" * 64,
        "cv_quality_receipt_sha256": "7" * 64,
        "cv_sha256": _sha(cv.read_bytes()),
        "form_answers_sha256": provisional.answers_sha256,
        "job_key": policy.job_key,
        "schema_version": "jaa.workable-application-package.v2",
        "upload_bindings": [row.document() for row in upload_bindings],
        "vacancy_sha256": "b" * 64,
    }
    package_bytes = (workable_module._canonical_json(package) + "\n").encode()
    application = WorkableApplication(package_bytes, answers, wrong_uploads)
    binding = WorkableReleaseBinding(
        tenant="",
        vacancy_id=policy.vacancy_id,
        source_url="https://apply.workable.com/j/847CFBC5F4",
        application_url=policy.application_url,
        policy_sha256=policy.policy_sha256,
        package_sha256=application.package_sha256,
        answers_sha256=application.answers_sha256,
        inventory_sha256=policy.inventory_sha256,
        preflight_sha256="6" * 64,
        cv_pdf_sha256=_sha(cv.read_bytes()),
        cover_letter_pdf_sha256=_sha(cover.read_bytes()),
        cv_assurance_receipt_sha256="8" * 64,
        cover_letter_assurance_receipt_sha256="9" * 64,
        upload_bindings=upload_bindings,
    )

    class CandidateAuthority:
        pass

    authority = CandidateAuthority()
    authority.source = SimpleNamespace(
        job_key=policy.job_key, vacancy_sha256="b" * 64, content_sha256="a" * 64
    )
    authority.artifacts = SimpleNamespace(
        cv_pdf=SimpleNamespace(pdf_sha256=_sha(cv.read_bytes())),
        cover_letter_pdf=SimpleNamespace(pdf_sha256=_sha(cover.read_bytes())),
    )
    authority.workable_release_binding = binding
    with pytest.raises(WorkableSchemaError, match="assured PDFs"):
        WorkableLiveAdapter._assert_package(policy, application, authority)

    correct_uploads = {
        "resume": wrong_uploads["resume"],
        "cover_letter": WorkableUpload(cover, _sha(cover.read_bytes())),
    }
    correct_provisional = WorkableApplication(b"placeholder", answers, correct_uploads)
    correct_document = {
        **package,
        "form_answers_sha256": correct_provisional.answers_sha256,
    }
    correct_bytes = (
        workable_module._canonical_json(correct_document) + "\n"
    ).encode()
    correct = WorkableApplication(correct_bytes, answers, correct_uploads)
    authority.workable_release_binding = replace(
        binding,
        package_sha256=correct.package_sha256,
        answers_sha256=correct.answers_sha256,
    )
    WorkableLiveAdapter._assert_package(policy, correct, authority)
