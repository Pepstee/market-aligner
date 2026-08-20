from __future__ import annotations

import json
import inspect
import hashlib
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from playwright.sync_api import Route, sync_playwright

import career_automation.production_ats_executor as production_module
import career_automation.provider_observation_authority as observation_authority
from career_automation.application_archive import (
    VacancyArchiveIdentity,
    selected_archive_object_bytes,
)
from career_automation.browser_executor import (
    GreenhouseSuccessEvidence,
    ReleaseExecutionAuthority,
    validate_greenhouse_success_observation,
)
from career_automation.external_document_assurance import (
    IntendedVacancy,
    assert_application_artifacts,
)
from career_automation.production_ats_executor import (
    CertifiedGreenhouseSubmitExecutor,
    GmailConfirmationEvidence,
    GreenhouseSubmissionPlan,
    ProductionATSBoundaryError,
    ProductionSubmissionIndeterminate,
    canonical_non_secret_form_state,
    collect_greenhouse_form_inventory,
    is_greenhouse_auxiliary_field,
)
from career_automation.production_attempt import (
    GreenhouseAttemptRecorder,
    ProductionIdentity,
)
from career_automation.testing_sanity_review import fixture_pass_receipt
from test_jaa08_independent_acceptance import (
    _fixture_now,
    _issued_release_inputs,
)


ROOT = Path(__file__).resolve().parent
APPLICATION_ID = "1234567"
APPLICATION_URL = f"https://job-boards.greenhouse.io/example/jobs/{APPLICATION_ID}"
CONFIRMATION_URL = APPLICATION_URL + "/confirmation"


def test_only_optional_intl_phone_search_is_provider_auxiliary() -> None:
    assert is_greenhouse_auxiliary_field(
        identity="iti-0__search-input", field_type="search", required=False
    )
    assert not is_greenhouse_auxiliary_field(
        identity="iti-0__search-input", field_type="search", required=True
    )
    assert not is_greenhouse_auxiliary_field(
        identity="candidate-search-input", field_type="search", required=False
    )


def test_submit_locator_is_case_insensitive_but_exact_and_unambiguous(
    tmp_path: Path,
) -> None:
    plan = GreenhouseSubmissionPlan(
        upload_input_names={"cv": tmp_path / "cv.pdf"},
        consent_states={},
    )
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(
            '<form><button type="submit">Submit application</button></form>'
        )
        locator = CertifiedGreenhouseSubmitExecutor._submit_locator(page, plan)
        assert locator.inner_text() == "Submit application"

        page.set_content(
            '<form><button type="submit">Submit application now</button></form>'
        )
        with pytest.raises(ProductionATSBoundaryError):
            CertifiedGreenhouseSubmitExecutor._submit_locator(page, plan)

        page.set_content(
            '<form><button type="submit">Submit application</button>'
            '<button type="submit">SUBMIT APPLICATION</button></form>'
        )
        with pytest.raises(ProductionATSBoundaryError):
            CertifiedGreenhouseSubmitExecutor._submit_locator(page, plan)
        browser.close()


class _NoMatchGmailChecker:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def check_confirmation(self, **kwargs) -> GmailConfirmationEvidence:
        self.calls.append(kwargs)
        return GmailConfirmationEvidence(
            collector_identity="fixture.gmail-read-only:v1",
            checked_at=kwargs["not_after"].isoformat(),
            result="no_match",
        )


class _MatchGmailChecker(_NoMatchGmailChecker):
    def check_confirmation(self, **kwargs) -> GmailConfirmationEvidence:
        self.calls.append(kwargs)
        received_at = kwargs["not_after"].isoformat()
        return GmailConfirmationEvidence(
            collector_identity="fixture.gmail-read-only:v1",
            checked_at=received_at,
            result="match",
            matched_message_metadata=(
                {
                    "message_id_sha256": hashlib.sha256(b"message-id").hexdigest(),
                    "received_at": received_at,
                    "sender_domain": "greenhouse.io",
                    "subject_sha256": hashlib.sha256(b"subject").hexdigest(),
                },
            ),
            match_reasons=(
                "positive_confirmation",
                "provider_sender",
                "vacancy_identity",
                "post_intent_time",
            ),
        )


def _application_html(*, navigate: bool = True, include_cover: bool = True) -> str:
    navigation = (
        f"event.preventDefault(); window.location.href='{CONFIRMATION_URL}'"
        if navigate
        else "event.preventDefault()"
    )
    cover = (
        '<label>Cover letter <input name="cover_letter" type="file" required></label>'
        if include_cover
        else ""
    )
    return f"""<!doctype html>
<html><head><title>Job Application for Junior Engineer at Example</title></head>
<body><form onsubmit=\"{navigation}\">
  <label>Full name <input name=\"full_name\" required></label>
  <label>Email <input name=\"email\" type=\"email\" required></label>
  <label>Phone <input name=\"phone\" required></label>
  <label>City <input name=\"city\" required></label>
  <label>Cover note <textarea name=\"cover_note\" required></textarea></label>
  <label>CV <input name=\"resume\" type=\"file\" required></label>
  {cover}
  <label><input name=\"consent\" type=\"checkbox\" required>Application consent</label>
  <input name=\"csrf_token\" type=\"hidden\" value=\"do-not-archive-this-value\">
  <button type=\"submit\">Submit Application</button>
</form></body></html>"""


def _install_routes(page, *, navigate: bool = True, include_cover: bool = True) -> None:
    def handler(route: Route) -> None:
        if route.request.url.rstrip("/") == CONFIRMATION_URL:
            route.fulfill(
                status=200,
                content_type="text/html",
                body=(
                    "<html><head><title>Application received</title></head>"
                    "<body><h1>Thank you for applying</h1></body></html>"
                ),
            )
        else:
            route.fulfill(
                status=200,
                content_type="text/html",
                body=_application_html(navigate=navigate, include_cover=include_cover),
            )

    page.route("**/*", handler)


def _prepared_authority(
    tmp_path: Path,
    page,
    *,
    attached_roles: tuple[str, ...] = ("cv", "cover_letter"),
    success_observation_override: bytes | None = None,
):
    upload_field_names = tuple(
        (role, "resume" if role == "cv" else "cover_letter") for role in attached_roles
    )
    field_authority_names = (
        ("full_name", "contact.full_name"),
        ("email", "contact.email"),
        ("phone", "contact.phone"),
        ("city", "contact.city"),
        ("cover_note", "answers.full"),
    )
    consent_states = (("consent", True),)
    success_observation = (
        json.dumps(
            {
                "schema_version": "jaa.greenhouse-nonconsequential-canary.v1",
                "observed_at": "2026-08-05T10:00:00+00:00",
                "provider": "greenhouse",
                "request": {
                    "url": APPLICATION_URL,
                    "method": "GET",
                    "status": 200,
                },
                "provider_loader_paths": {
                    "confirmation_message": "<h1>Thank you for applying</h1>",
                    "confirmationPath": f"/example/jobs/{APPLICATION_ID}/confirmation",
                    "submitPath": f"https://boards.greenhouse.io/example/jobs/{APPLICATION_ID}",
                },
                "interaction": {
                    "fields_filled": 0,
                    "files_uploaded": 0,
                    "submit_clicks": 0,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    success_evidence = GreenhouseSuccessEvidence(
        observation_sha256=hashlib.sha256(success_observation).hexdigest(),
        observed_at="2026-08-05T10:00:00+00:00",
        confirmation_url=CONFIRMATION_URL,
        required_visible_markers=("Thank you for applying",),
    )
    inputs = _issued_release_inputs(
        tmp_path,
        route_adapter_id="greenhouse.production",
        route_adapter_version="v1",
        route_source_identity=APPLICATION_URL,
    )
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        publication,
        _compilation,
        gate,
        _route,
        issued,
    ) = inputs
    intended = IntendedVacancy(
        job_key=source.job_key,
        vacancy_sha256=source.vacancy_sha256,
        role_title=source.role_title,
        company_name=source.company_name,
    )
    document_receipts = assert_application_artifacts(
        cv_pdf_bytes=artifacts.cv_pdf.pdf_bytes,
        cover_letter_pdf_bytes=artifacts.cover_letter_pdf.pdf_bytes,
        answers_text=artifacts.editable.answers_text,
        intended_vacancy=intended,
    )
    sanity_receipt = fixture_pass_receipt(
        source=source,
        artifacts=artifacts,
        questions=questions,
        state_root=tmp_path,
    )
    vacancy = VacancyArchiveIdentity(
        job_key=source.job_key,
        vacancy_sha256=source.vacancy_sha256,
        role_title=source.role_title,
        company_name=source.company_name,
        source_url=APPLICATION_URL,
    )
    recorder = GreenhouseAttemptRecorder.create(
        archive_root=tmp_path / "application-archive",
        repository_root=ROOT,
        vacancy=vacancy,
        complete_vacancy=page.content().encode(),
        structured_vacancy={
            "job_key": source.job_key,
            "title": source.role_title,
            "company": source.company_name,
            "application_url": APPLICATION_URL,
        },
        assessment={
            "live": True,
            "eligible": True,
            "duplicate": False,
            "fit_score": 0.2,
            "queue_rank": 1,
            "scoring_inputs": {"fixture": True},
        },
    )
    recorder.record_prefill(page)
    artifact_directory = artifact_root / publication.relative_directory
    cv_path = artifact_directory / "cv.pdf"
    cover_path = artifact_directory / "cover-letter.pdf"
    page.locator('input[name="full_name"]').fill(contact.full_name)
    page.locator('input[name="email"]').fill(contact.email)
    page.locator('input[name="phone"]').fill(contact.phone)
    page.locator('input[name="city"]').fill(contact.city)
    page.locator('textarea[name="cover_note"]').fill(artifacts.editable.answers_text)
    page.locator('input[name="resume"]').set_input_files(str(cv_path))
    if "cover_letter" in attached_roles:
        page.locator('input[name="cover_letter"]').set_input_files(str(cover_path))
    page.locator('input[name="consent"]').check()
    archive_receipt = recorder.finalize_release(
        page,
        source=source,
        artifacts=artifacts,
        document_assurance_receipts=document_receipts,
        sanity_review_receipt=sanity_receipt,
        production_identity=ProductionIdentity(
            code_revision="fixture-code-revision",
            policy_identity="fixture-policy",
            configuration_identity="fixture-configuration",
        ),
        attached_roles=attached_roles,
        upload_field_names=upload_field_names,
        field_authority_names=field_authority_names,
        consent_states=consent_states,
        success_evidence=success_evidence,
        success_observation=(
            success_observation
            if success_observation_override is None
            else success_observation_override
        ),
        finalized_at=datetime.now(timezone.utc),
    )
    authority = ReleaseExecutionAuthority(
        gate=gate,
        release_token=issued.release_token,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        document_assurance_receipts=document_receipts,
        sanity_review_receipt=sanity_receipt,
        archive_receipt=archive_receipt,
        archive_root=recorder.attempt.archive.root,
        artifact_root=artifact_root,
        repository_root=ROOT,
        ats_provider="greenhouse",
        application_url=APPLICATION_URL,
        attached_roles=attached_roles,
        upload_field_names=upload_field_names,
        field_authority_names=field_authority_names,
        consent_states=consent_states,
        success_evidence=success_evidence,
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=_fixture_now(database),
        receipt_url=CONFIRMATION_URL,
        application_id=APPLICATION_ID,
        job_key=source.job_key,
    )
    plan = GreenhouseSubmissionPlan(
        upload_input_names={
            role: cv_path if role == "cv" else cover_path for role in attached_roles
        },
        consent_states={"consent": True},
        timeout_ms=1_000,
    )
    return authority, plan, recorder


def test_release_rejects_success_observation_digest_injection(
    tmp_path: Path,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        with pytest.raises(ValueError, match="success observation differs"):
            _prepared_authority(
                tmp_path,
                page,
                success_observation_override=b'{"forged":"observation"}\n',
            )
        browser.close()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ({"schema_version": "forged"}, "schema"),
        ({"observed_at": "2026-08-05T09:00:00+00:00"}, "time"),
        (
            {"request": {"url": APPLICATION_URL, "method": "POST", "status": 200}},
            "collector",
        ),
        (
            {
                "request": {
                    "url": APPLICATION_URL.replace(APPLICATION_ID, "7654321"),
                    "method": "GET",
                    "status": 200,
                }
            },
            "another vacancy",
        ),
        (
            {
                "interaction": {
                    "fields_filled": 1,
                    "files_uploaded": 0,
                    "submit_clicks": 0,
                }
            },
            "collector",
        ),
        (
            {
                "provider_loader_paths": {
                    "confirmation_message": "Thank you for applying",
                    "confirmationPath": "/example/jobs/7654321/confirmation",
                    "submitPath": f"https://boards.greenhouse.io/example/jobs/{APPLICATION_ID}",
                }
            },
            "confirmation route",
        ),
        (
            {
                "provider_loader_paths": {
                    "confirmation_message": "Thank you for applying",
                    "confirmationPath": f"/example/jobs/{APPLICATION_ID}/confirmation",
                    "submitPath": "https://boards.greenhouse.io/example/jobs/7654321",
                }
            },
            "submit route",
        ),
        (
            {
                "provider_loader_paths": {
                    "confirmation_message": "Application error",
                    "confirmationPath": f"/example/jobs/{APPLICATION_ID}/confirmation",
                    "submitPath": f"https://boards.greenhouse.io/example/jobs/{APPLICATION_ID}",
                }
            },
            "success marker",
        ),
    ),
)
def test_success_observation_provenance_bypasses_fail_closed(
    mutation: dict[str, object], message: str
) -> None:
    document = {
        "schema_version": "jaa.greenhouse-nonconsequential-canary.v1",
        "observed_at": "2026-08-05T10:00:00+00:00",
        "provider": "greenhouse",
        "request": {"url": APPLICATION_URL, "method": "GET", "status": 200},
        "provider_loader_paths": {
            "confirmation_message": "<h1>Thank you for applying</h1>",
            "confirmationPath": f"/example/jobs/{APPLICATION_ID}/confirmation",
            "submitPath": f"https://boards.greenhouse.io/example/jobs/{APPLICATION_ID}",
        },
        "interaction": {"fields_filled": 0, "files_uploaded": 0, "submit_clicks": 0},
    }
    document.update(mutation)
    value = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    evidence = GreenhouseSuccessEvidence(
        observation_sha256=hashlib.sha256(value).hexdigest(),
        observed_at="2026-08-05T10:00:00+00:00",
        confirmation_url=CONFIRMATION_URL,
        required_visible_markers=("Thank you for applying",),
    )
    with pytest.raises(ValueError, match=message):
        validate_greenhouse_success_observation(
            value,
            evidence,
            application_url=APPLICATION_URL,
            application_id=APPLICATION_ID,
            verified_at=datetime(2026, 8, 5, 12, tzinfo=timezone.utc),
        )


def test_stale_success_observation_fails_closed() -> None:
    document = {
        "schema_version": "jaa.greenhouse-nonconsequential-canary.v1",
        "observed_at": "2026-06-01T10:00:00+00:00",
        "provider": "greenhouse",
        "request": {"url": APPLICATION_URL, "method": "GET", "status": 200},
        "provider_loader_paths": {
            "confirmation_message": "Thank you for applying",
            "confirmationPath": f"/example/jobs/{APPLICATION_ID}/confirmation",
            "submitPath": f"https://boards.greenhouse.io/example/jobs/{APPLICATION_ID}",
        },
        "interaction": {"fields_filled": 0, "files_uploaded": 0, "submit_clicks": 0},
    }
    value = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    evidence = GreenhouseSuccessEvidence(
        observation_sha256=hashlib.sha256(value).hexdigest(),
        observed_at=document["observed_at"],
        confirmation_url=CONFIRMATION_URL,
        required_visible_markers=("Thank you for applying",),
    )
    with pytest.raises(ValueError, match="stale"):
        validate_greenhouse_success_observation(
            value,
            evidence,
            application_url=APPLICATION_URL,
            application_id=APPLICATION_ID,
            verified_at=datetime(2026, 8, 5, 12, tzinfo=timezone.utc),
        )


def test_authority_rehashes_archived_success_observation(
    tmp_path: Path,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, _plan, _recorder = _prepared_authority(tmp_path, page)
        forged = replace(
            authority.success_evidence,
            observation_sha256=hashlib.sha256(b"forged").hexdigest(),
        )
        with pytest.raises(ValueError, match="observation differs"):
            replace(authority, success_evidence=forged)
        browser.close()


def test_release_archives_repository_trust_receipt_for_provider_observation(
    tmp_path: Path,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, _plan, _recorder = _prepared_authority(tmp_path, page)
        receipt = json.loads(
            selected_archive_object_bytes(
                authority.archive_receipt,
                "provider.success_authority",
                root=authority.archive_root,
                repository_root=authority.repository_root,
            )
        )
        browser.close()
    assert receipt["schema_version"] == (
        "jaa.provider-observation-authority-receipt.v2"
    )
    assert receipt["collector_identity"] == (
        "jaa.repository-playwright-route-fixture.v1"
    )
    assert receipt["observation_sha256"] == (
        authority.success_evidence.observation_sha256
    )
    assert len(receipt["capture_manifest_sha256"]) == 64
    assert len(receipt["collector_source_sha256"]) == 64
    assert len(receipt["trust_policy_sha256"]) == 64


def test_certified_greenhouse_executor_records_success_and_terminal_archive(
    tmp_path: Path,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(tmp_path, page)
        receipt = CertifiedGreenhouseSubmitExecutor(
            repository_root=ROOT,
            gmail_confirmation_checker=_NoMatchGmailChecker(),
        ).execute(page, authority=authority, plan=plan)
        browser.close()
    assert receipt.provider == "greenhouse"
    assert receipt.confirmation_url == CONFIRMATION_URL
    assert receipt.provider_application_id is None
    assert receipt.confirmation_email_checked is True
    terminal = json.loads(
        (recorder.attempt.path / "terminal-manifest.json").read_text()
    )
    assert terminal["outcome"] == "submitted_success"
    assert (
        terminal["release_manifest_sha256"] == authority.archive_receipt.manifest_sha256
    )
    assert "browser.post_submit_visible_text" in terminal["selected"]
    assert "browser.redirect_http_evidence" in terminal["selected"]
    assert "submission.reconciliation" in terminal["selected"]
    assert "submission.receipt" in terminal["selected"]
    checkpoints = sorted(
        (authority.archive_root / "production-checkpoints" / "events").glob("*.json")
    )
    assert [json.loads(path.read_text())["event_type"] for path in checkpoints] == [
        "attempt_started",
        "attempt_terminal",
    ]


def test_cv_only_greenhouse_form_preserves_unattached_cover_assurance(
    tmp_path: Path,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page, include_cover=False)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(
            tmp_path, page, attached_roles=("cv",)
        )
        receipt = CertifiedGreenhouseSubmitExecutor(
            repository_root=ROOT,
            gmail_confirmation_checker=_NoMatchGmailChecker(),
        ).execute(page, authority=authority, plan=plan)
        browser.close()
    assert receipt.provider == "greenhouse"
    mapping = json.loads(
        selected_archive_object_bytes(
            authority.archive_receipt,
            "browser.upload_mapping",
            root=authority.archive_root,
            repository_root=ROOT,
        )
    )
    assert mapping["cv"]["selected_for_upload"] is True
    assert mapping["cover_letter"]["selected_for_upload"] is False
    assert (recorder.attempt.path / "terminal-manifest.json").exists()


def test_provider_success_can_defer_connector_gmail_verification(
    tmp_path: Path,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(tmp_path, page)
        receipt = CertifiedGreenhouseSubmitExecutor(
            repository_root=ROOT,
        ).execute(page, authority=authority, plan=plan)
        browser.close()
    assert receipt.confirmation_email_checked is False
    terminal = json.loads(
        (recorder.attempt.path / "terminal-manifest.json").read_text()
    )
    assert terminal["outcome"] == "submitted_success"
    reconciliation_row = next(
        row
        for row in recorder.attempt._objects(recorder.attempt._events())
        if row.role == "submission.reconciliation"
    )
    reconciliation = json.loads(
        (authority.archive_root / reconciliation_row.relative_path).read_text()
    )
    assert reconciliation["provider_state"]["success_observed"] is True
    assert reconciliation["confirmation_email"]["checked"] is False
    assert reconciliation["confirmation_email"]["result"] == (
        "deferred_connector_verification"
    )
    assert reconciliation["confirmation_email"]["verification_required"] is True


def test_human_verification_is_archived_and_never_clicked(tmp_path: Path) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(tmp_path, page)
        page.locator("body").evaluate(
            "(body) => { const frame=document.createElement('iframe'); "
            "frame.src='https://www.google.com/recaptcha/api2/bframe'; body.appendChild(frame); }"
        )
        with pytest.raises(ProductionATSBoundaryError, match="human-verification"):
            CertifiedGreenhouseSubmitExecutor(repository_root=ROOT).execute(
                page, authority=authority, plan=plan
            )
        current_url = page.url
        browser.close()
    terminal = json.loads(
        (recorder.attempt.path / "terminal-manifest.json").read_text()
    )
    assert terminal["outcome"] == "blocked"
    assert "browser.blocked_screenshot" in terminal["selected"]
    assert "browser.blocked_visible_text" in terminal["selected"]
    assert "browser.blocked_state_evidence" in terminal["selected"]
    assert "browser.redirect_http_evidence" in terminal["selected"]
    assert current_url != CONFIRMATION_URL


def test_dormant_invisible_recaptcha_widget_is_not_a_boundary(tmp_path: Path) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        page.locator("body").evaluate(
            "(body) => { const frame=document.createElement('iframe'); "
            "frame.src='https://www.google.com/recaptcha/api2/anchor'; "
            "frame.style.display='none'; body.appendChild(frame); "
            "const dormant=document.createElement('div'); "
            "dormant.dataset.sitekey='public-site-key'; "
            "dormant.style.display='none'; body.appendChild(dormant); }"
        )
        assert CertifiedGreenhouseSubmitExecutor._boundary_signals(page) == ()
        browser.close()


def test_crash_after_click_intent_recovers_without_duplicate_submit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(tmp_path, page)
        gmail = _NoMatchGmailChecker()
        executor = CertifiedGreenhouseSubmitExecutor(
            repository_root=ROOT,
            gmail_confirmation_checker=gmail,
        )
        clicks = 0

        def crash_before_click(*_args, **_kwargs) -> None:
            nonlocal clicks
            clicks += 1
            raise RuntimeError("crash between intent and click")

        monkeypatch.setattr(
            production_module,
            "certified_final_submit_click",
            crash_before_click,
        )
        with pytest.raises(RuntimeError, match="between intent and click"):
            executor.execute(page, authority=authority, plan=plan)
        monkeypatch.setattr(
            production_module,
            "certified_final_submit_click",
            lambda *_args, **_kwargs: pytest.fail("duplicate click attempted"),
        )
        with pytest.raises(
            ProductionSubmissionIndeterminate, match="prior click intent"
        ):
            executor.execute(page, authority=authority, plan=plan)
        browser.close()
    assert clicks == 1
    assert len(gmail.calls) == 1
    terminal = json.loads(
        (recorder.attempt.path / "terminal-manifest.json").read_text()
    )
    assert terminal["outcome"] == "indeterminate"


def test_post_intent_gmail_match_resolves_success_without_click_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(tmp_path, page)
        clicks = 0

        def crash_before_click(*_args, **_kwargs) -> None:
            nonlocal clicks
            clicks += 1
            raise RuntimeError("crash after durable intent")

        monkeypatch.setattr(
            production_module,
            "certified_final_submit_click",
            crash_before_click,
        )
        with pytest.raises(RuntimeError, match="durable intent"):
            CertifiedGreenhouseSubmitExecutor(repository_root=ROOT).execute(
                page, authority=authority, plan=plan
            )
        monkeypatch.setattr(
            production_module,
            "certified_final_submit_click",
            lambda *_args, **_kwargs: pytest.fail("reconciliation replayed the click"),
        )
        gmail = _MatchGmailChecker()
        receipt = CertifiedGreenhouseSubmitExecutor(
            repository_root=ROOT,
            gmail_confirmation_checker=gmail,
        ).execute(page, authority=authority, plan=plan)
        browser.close()
    assert clicks == 1
    assert len(gmail.calls) == 1
    assert receipt.confirmation_email_checked is True
    terminal = json.loads(
        (recorder.attempt.path / "terminal-manifest.json").read_text()
    )
    assert terminal["outcome"] == "submitted_success"
    assert "submission.reconciliation" in terminal["selected"]


def test_post_intent_without_gmail_checker_stays_quarantined_and_unfinalized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(tmp_path, page)
        monkeypatch.setattr(
            production_module,
            "certified_final_submit_click",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("crash")),
        )
        with pytest.raises(RuntimeError, match="crash"):
            CertifiedGreenhouseSubmitExecutor(repository_root=ROOT).execute(
                page, authority=authority, plan=plan
            )
        with pytest.raises(
            ProductionSubmissionIndeterminate,
            match="configured Gmail confirmation checker",
        ):
            CertifiedGreenhouseSubmitExecutor(repository_root=ROOT).execute(
                page, authority=authority, plan=plan
            )
        browser.close()
    roles = {row.role for row in recorder.attempt._objects(recorder.attempt._events())}
    assert "submission.click_intent" in roles
    assert not (recorder.attempt.path / "terminal-manifest.json").exists()


def test_wrong_provider_route_binding_fails_before_submit(tmp_path: Path) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, _recorder = _prepared_authority(tmp_path, page)
        with pytest.raises(ValueError, match="differs from the release archive"):
            replace(
                authority,
                application_url=APPLICATION_URL.replace("1234567", "7654321"),
                application_id="7654321",
                receipt_url=CONFIRMATION_URL.replace("1234567", "7654321"),
            )
        browser.close()


def test_hidden_anti_csrf_value_is_redacted_from_archive(tmp_path: Path) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, _plan, _recorder = _prepared_authority(tmp_path, page)
        prefill = selected_archive_object_bytes(
            authority.archive_receipt,
            "browser.pre_submit_state",
            root=authority.archive_root,
            repository_root=ROOT,
        )
        state = json.loads(prefill)
        hidden = next(
            field for field in state["fields"] if field["name"] == "csrf_token"
        )
        assert hidden["value_redacted"] is True
        assert hidden["value_present"] is True
        assert b"do-not-archive-this-value" not in prefill
        browser.close()


@pytest.mark.parametrize("drift", ["answer", "upload"])
def test_wrong_answer_or_upload_is_archived_repairably_without_click_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(tmp_path, page)
        if drift == "answer":
            page.locator('textarea[name="cover_note"]').fill("unapproved drift")
        else:
            wrong_pdf = tmp_path / "wrong.pdf"
            wrong_pdf.write_bytes(b"%PDF-1.4\nwrong\n%%EOF\n")
            page.locator('input[name="resume"]').set_input_files(str(wrong_pdf))
            plan = replace(
                plan,
                upload_input_names={
                    **plan.upload_input_names,
                    "cv": wrong_pdf,
                },
            )
        monkeypatch.setattr(
            production_module,
            "certified_final_submit_click",
            lambda *_args, **_kwargs: pytest.fail(
                "final click crossed a failed pre-submit gate"
            ),
        )
        with pytest.raises(ProductionATSBoundaryError, match="pre-submit verification"):
            CertifiedGreenhouseSubmitExecutor(repository_root=ROOT).execute(
                page, authority=authority, plan=plan
            )
        browser.close()
    assert not (recorder.attempt.path / "terminal-manifest.json").exists()
    roles = {row.role for row in recorder.attempt._objects(recorder.attempt._events())}
    assert "submission.preflight_rejection" in roles
    assert "submission.click_intent" not in roles


@pytest.mark.parametrize(
    "bypass",
    ("role_swap", "duplicate_basename", "same_name_bytes", "inaccessible", "extra"),
)
def test_browser_resident_upload_binding_rejects_adversarial_bypasses(
    tmp_path: Path,
    bypass: str,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, _recorder = _prepared_authority(tmp_path, page)
        cv_path = plan.upload_input_names["cv"]
        cover_path = plan.upload_input_names["cover_letter"]
        if bypass == "role_swap":
            page.locator('input[name="resume"]').set_input_files(str(cover_path))
            page.locator('input[name="cover_letter"]').set_input_files(str(cv_path))
        elif bypass == "duplicate_basename":
            first = tmp_path / "first" / "application.pdf"
            second = tmp_path / "second" / "application.pdf"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_bytes(cv_path.read_bytes())
            second.write_bytes(cover_path.read_bytes())
            page.locator('input[name="resume"]').set_input_files(str(first))
            page.locator('input[name="cover_letter"]').set_input_files(str(second))
            plan = replace(
                plan,
                upload_input_names={"cv": first, "cover_letter": second},
            )
        elif bypass == "same_name_bytes":
            wrong = tmp_path / "wrong" / cv_path.name
            wrong.parent.mkdir()
            original = cv_path.read_bytes()
            wrong.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            page.locator('input[name="resume"]').set_input_files(str(wrong))
        elif bypass == "inaccessible":
            page.locator('input[name="resume"]').evaluate(
                "(element) => { Object.getPrototypeOf(element.files[0]).arrayBuffer = "
                "() => Promise.reject(new Error('unavailable')); }"
            )
        else:
            page.locator("form").evaluate(
                "(form) => { const input=document.createElement('input'); "
                "input.type='file'; input.name='extra'; form.appendChild(input); }"
            )
            page.locator('input[name="extra"]').set_input_files(str(cv_path))
        with pytest.raises(ProductionATSBoundaryError):
            CertifiedGreenhouseSubmitExecutor._verify_uploads(page, plan, authority)
        browser.close()


def test_upload_verification_accepts_exact_greenhouse_replacement_ui(
    tmp_path: Path,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, _recorder = _prepared_authority(tmp_path, page)
        page.locator("form").evaluate(
            """(form) => {
              for (const input of form.querySelectorAll('input[type=file]')) input.remove();
              for (const filename of ['cv.pdf', 'cover-letter.pdf']) {
                const wrapper = document.createElement('div');
                wrapper.className = 'file-upload__filename';
                const label = document.createElement('p');
                label.textContent = filename;
                const remove = document.createElement('button');
                remove.setAttribute('aria-label', 'Remove file');
                wrapper.append(label, remove);
                form.appendChild(wrapper);
              }
            }"""
        )
        CertifiedGreenhouseSubmitExecutor._verify_uploads(page, plan, authority)
        page.locator("form").evaluate(
            """(form) => {
              const extra = document.createElement('div');
              extra.className = 'file-upload__filename';
              extra.innerHTML = '<p>extra.pdf</p><button aria-label="Remove file"></button>';
              form.appendChild(extra);
            }"""
        )
        with pytest.raises(ProductionATSBoundaryError, match="replacement upload UI"):
            CertifiedGreenhouseSubmitExecutor._verify_uploads(page, plan, authority)
        browser.close()


def test_immediate_revalidation_runs_inside_primitive_after_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(tmp_path, page)
        executor = CertifiedGreenhouseSubmitExecutor(repository_root=ROOT)
        original = executor._authoritative_revalidation
        calls = 0

        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ProductionATSBoundaryError("late upload drift")
            return original(*args, **kwargs)

        monkeypatch.setattr(executor, "_authoritative_revalidation", fail_second)
        with pytest.raises(ProductionATSBoundaryError, match="late upload drift"):
            executor.execute(page, authority=authority, plan=plan)
        assert page.url == APPLICATION_URL
        roles = {
            row.role for row in recorder.attempt._objects(recorder.attempt._events())
        }
        assert "submission.click_intent" in roles
        assert "submission.click_cancelled" in roles
        terminal = json.loads(
            (recorder.attempt.path / "terminal-manifest.json").read_text()
        )
        assert terminal["outcome"] == "gate_rejected"
        assert "browser.failed_state_evidence" in terminal["selected"]
        browser.close()


def test_exact_receipt_sanity_archive_and_upload_gates_run_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pdf_calls = 0
    sanity_calls = 0
    upload_calls = 0
    original_pdf = production_module.verify_receipt_for_pdf
    original_sanity = production_module.verify_sanity_review_receipt
    original_uploads = CertifiedGreenhouseSubmitExecutor._verify_uploads

    def counted_pdf(*args, **kwargs):
        nonlocal pdf_calls
        pdf_calls += 1
        return original_pdf(*args, **kwargs)

    def counted_sanity(*args, **kwargs):
        nonlocal sanity_calls
        sanity_calls += 1
        return original_sanity(*args, **kwargs)

    def counted_uploads(*args, **kwargs):
        nonlocal upload_calls
        upload_calls += 1
        return original_uploads(*args, **kwargs)

    monkeypatch.setattr(production_module, "verify_receipt_for_pdf", counted_pdf)
    monkeypatch.setattr(
        production_module, "verify_sanity_review_receipt", counted_sanity
    )
    monkeypatch.setattr(
        CertifiedGreenhouseSubmitExecutor,
        "_verify_uploads",
        staticmethod(counted_uploads),
    )
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, plan, _recorder = _prepared_authority(tmp_path, page)
        CertifiedGreenhouseSubmitExecutor(
            repository_root=ROOT,
            gmail_confirmation_checker=_NoMatchGmailChecker(),
        ).execute(page, authority=authority, plan=plan)
        browser.close()
    assert pdf_calls == 4
    assert sanity_calls == 2
    assert upload_calls == 2


def test_url_only_confirmation_is_indeterminate_and_archived(
    tmp_path: Path,
) -> None:
    def install_error_confirmation(page) -> None:
        def handler(route: Route) -> None:
            if route.request.url.rstrip("/") == CONFIRMATION_URL:
                route.fulfill(
                    status=200,
                    content_type="text/html",
                    body="<html><title>Error</title><body>Application failed</body></html>",
                )
            else:
                route.fulfill(
                    status=200,
                    content_type="text/html",
                    body=_application_html(),
                )

        page.route("**/*", handler)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        install_error_confirmation(page)
        page.goto(APPLICATION_URL)
        authority, plan, recorder = _prepared_authority(tmp_path, page)
        with pytest.raises(
            ProductionSubmissionIndeterminate,
            match="positive success evidence",
        ):
            gmail = _NoMatchGmailChecker()
            CertifiedGreenhouseSubmitExecutor(
                repository_root=ROOT,
                gmail_confirmation_checker=gmail,
            ).execute(page, authority=authority, plan=plan)
        browser.close()
    terminal = json.loads(
        (recorder.attempt.path / "terminal-manifest.json").read_text()
    )
    assert terminal["outcome"] == "indeterminate"
    assert "browser.post_submit_visible_text" in terminal["selected"]
    assert "browser.redirect_http_evidence" in terminal["selected"]
    assert "submission.reconciliation" in terminal["selected"]
    assert len(gmail.calls) == 1


def test_production_and_fixture_share_one_final_click_primitive() -> None:
    executor_source = inspect.getsource(CertifiedGreenhouseSubmitExecutor.execute)
    primitive_source = inspect.getsource(production_module.certified_final_submit_click)
    assert executor_source.count("certified_final_submit_click(") == 1
    assert "locator.click()" not in executor_source
    assert "authority.verify_employer_facing_receipts" in primitive_source
    assert "immediate_revalidation()" in primitive_source
    assert primitive_source.count("locator.click()") == 1
    revalidation_source = inspect.getsource(
        CertifiedGreenhouseSubmitExecutor._authoritative_revalidation
    )
    assert revalidation_source.count("verify_receipt_for_pdf(") == 2
    assert "verify_sanity_review_receipt(" in revalidation_source
    assert "authority.verify_archive_receipt(" in revalidation_source
    assert "self._verify_form_fields(" in revalidation_source
    assert "self._verify_uploads(" in revalidation_source


def test_react_combobox_selection_and_enumerable_options_are_captured() -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(
            """<form>
            <div class="select__container">
              <label for="privacy">Privacy notice confirmation</label>
              <div class="select__single-value">Yes</div>
              <select id="privacy" aria-required="true">
                <option value="">Select</option>
                <option value="yes" selected>Yes</option>
                <option value="no">No</option>
              </select>
            </div>
            </form>"""
        )
        state = json.loads(canonical_non_secret_form_state(page))
        inventory = json.loads(collect_greenhouse_form_inventory(page))
        browser.close()
    privacy = next(row for row in state["fields"] if row["id"] == "privacy")
    assert privacy["required"] is True
    assert privacy["selected_text"] == ["Yes"]
    options = inventory["select_inventories"][0]["options"]
    assert [row["text"] for row in options] == ["Select", "Yes", "No"]


def test_greenhouse_authority_rejects_nonofficial_or_mismatched_routes(
    tmp_path: Path,
) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install_routes(page)
        page.goto(APPLICATION_URL)
        authority, _plan, _recorder = _prepared_authority(tmp_path, page)
        with pytest.raises(ValueError, match="official URL"):
            replace(
                authority,
                application_url=f"https://evil.example/jobs/{APPLICATION_ID}",
            )
        with pytest.raises(ValueError, match="differs from its observed application"):
            replace(
                authority,
                receipt_url=(
                    "https://job-boards.greenhouse.io/example/jobs/999/confirmation"
                ),
            )
        browser.close()


def test_provider_authority_resolves_committed_sources_from_nested_subtree(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    subtree = repository / "internal" / "jaa"
    policy = (
        subtree
        / "career_automation"
        / "fixtures"
        / "trusted-greenhouse-success-observations.json"
    )
    policy.parent.mkdir(parents=True)
    policy_value = b'{"synthetic":"policy"}\n'
    policy.write_bytes(policy_value)
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(
        ["git", "-C", repository, "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", repository, "config", "user.name", "Synthetic Test"],
        check=True,
    )
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    subprocess.run(
        ["git", "-C", repository, "commit", "-qm", "fixture"], check=True
    )

    head = observation_authority._verify_exact_head_policy(subtree, policy_value)
    assert len(head) == 40
    assert observation_authority._git_show(
        subtree,
        "HEAD",
        "career_automation/fixtures/trusted-greenhouse-success-observations.json",
    ) == policy_value


def test_provider_authority_subtree_lookup_rejects_escape_and_dirty_head(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    subtree = repository / "internal" / "jaa"
    policy = (
        subtree
        / "career_automation"
        / "fixtures"
        / "trusted-greenhouse-success-observations.json"
    )
    policy.parent.mkdir(parents=True)
    policy_value = b'{"synthetic":"policy"}\n'
    policy.write_bytes(policy_value)
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(
        ["git", "-C", repository, "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", repository, "config", "user.name", "Synthetic Test"],
        check=True,
    )
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    subprocess.run(
        ["git", "-C", repository, "commit", "-qm", "fixture"], check=True
    )

    with pytest.raises(ValueError, match="unsafe"):
        observation_authority._git_show(subtree, "HEAD", "../outside")
    legacy_policy = (
        repository
        / "career_automation"
        / "fixtures"
        / "trusted-greenhouse-success-observations.json"
    )
    legacy_policy.parent.mkdir(parents=True)
    legacy_policy.write_bytes(b'{"different":"legacy-policy"}\n')
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    subprocess.run(
        ["git", "-C", repository, "commit", "-qm", "ambiguous fixture"],
        check=True,
    )
    with pytest.raises(ValueError, match="ambiguous"):
        observation_authority._git_show(
            subtree,
            "HEAD",
            "career_automation/fixtures/trusted-greenhouse-success-observations.json",
            allow_legacy_root=True,
        )
    (repository / "untracked.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(ValueError, match="exact clean HEAD"):
        observation_authority._verify_exact_head_policy(subtree, policy_value)
