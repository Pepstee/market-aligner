"""Opt-in, local-only diagnostic for the native preparation path."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import pytest


ACCEPTED_EVIDENCE = Path(
    "/srv/artvault/control/operator-glm/jobs/"
    "ma-synthetic-project-facts-20261001T074832Z/work/accepted-synthetic-evidence.json"
)
ACCEPTED_EVIDENCE_SHA256 = (
    "5a409c813aea87d748445a40287972bcc2897e861464d08b0265632d1aa20a72"
)
NAMED_TEST_ROOT = Path(
    "/srv/artvault/control/operator-glm/programme/canary/"
    "market-aligner-linux-verification"
)
APPLICATION_URL = "https://job-boards.greenhouse.io/example/jobs/1234567"
JOB_KEY = "greenhouse:example:1234567"
ROLE_TITLE = "Synthetic Software Engineer"
COMPANY_NAME = "Example Systems"
REQUIREMENT = "Build and test a demonstration service."
VACANCY_DESCRIPTION = (
    "Build and test a demonstration service for a synthetic software role."
)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: object) -> bytes:
    from career_automation.evidence_matching import canonical_json

    return (canonical_json(value) + "\n").encode("utf-8")


def _private_write(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    path.chmod(0o600)


def _save_result(root: Path, result: dict[str, object]) -> None:
    _private_write(root / "safe-result.json", _json_bytes(result))


def _capture_setup_failures(test_function):
    @wraps(test_function)
    def wrapped(*args, **kwargs):
        root = kwargs.get("tmp_path", args[0] if args else None)
        try:
            return test_function(*args, **kwargs)
        except Exception as error:
            if isinstance(root, Path) and root.is_dir():
                raw = str(error).encode("utf-8", errors="replace")
                if not (root / "actual-exception.txt").exists():
                    _private_write(root / "actual-exception.txt", raw)
                if not (root / "safe-result.json").exists():
                    _save_result(
                        root,
                        {
                            "diagnostic_only": True,
                            "synthetic_fixture": True,
                            "status": "setup_or_execution_exception",
                            "exception_type": type(error).__name__,
                            "exception_sha256": _sha(raw),
                            "external_network_requests": 0,
                            "external_submission": 0,
                        },
                    )
            raise

    return wrapped


def _make_fixture_contact(root: Path, monkeypatch) -> Path:
    import career_automation.candidate_contact_authority as contact_module
    from career_automation.candidate_contact_authority import (
        ATTESTATION,
        REGISTRY_ATTESTATION,
        REGISTRY_SCHEMA_VERSION,
        SCHEMA_VERSION,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_sha256 = _sha(public_raw)
    monkeypatch.setattr(
        contact_module, "ENROLLED_OPERATOR_PUBLIC_KEY_SHA256", public_sha256
    )
    key_directory = root / "keys"
    key_directory.mkdir(mode=0o700)
    public_key_path = key_directory / "fixture-public.pem"
    _private_write(
        public_key_path,
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    registry_directory = root / "contact-registry"
    registry_directory.mkdir(mode=0o700)
    monkeypatch.setenv(contact_module.PUBLIC_KEY_ENV, str(public_key_path))
    monkeypatch.setenv(contact_module.REGISTRY_ENV, str(registry_directory))

    issued_at = datetime.now(timezone.utc).isoformat()
    signed_payload = {
        "schema_version": SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_explicit_operator_attestation",
        "operator_attestation": ATTESTATION,
        "issued_at": issued_at,
        "record_id": "synthetic-contact-record",
        "record_version": 1,
        "contact": {
            "full_name": "Alex Fixture",
            "email": "alex.fixture@fixture.invalid",
            "phone": None,
            "city": "Synthetic City",
        },
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": public_sha256,
    }
    signature = base64.b64encode(
        private_key.sign(_json_bytes(signed_payload))
    ).decode("ascii")
    content_addressed = {**signed_payload, "signature_base64": signature}
    authority_sha256 = _sha(_json_bytes(content_addressed))
    authority_path = root / f"{authority_sha256}.json"
    _private_write(
        authority_path,
        _json_bytes({**content_addressed, "authority_sha256": authority_sha256}),
    )

    registry_payload = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_operator_contact_registry",
        "operator_attestation": REGISTRY_ATTESTATION,
        "issued_at": issued_at,
        "registry_id": "operator-contact-primary",
        "registry_version": 1,
        "current": {
            "record_id": signed_payload["record_id"],
            "record_version": signed_payload["record_version"],
            "authority_sha256": authority_sha256,
        },
        "revoked_authority_sha256s": [],
        "prior_registry_sha256": None,
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": public_sha256,
    }
    registry_signature = base64.b64encode(
        private_key.sign(_json_bytes(registry_payload))
    ).decode("ascii")
    registry_content = {
        **registry_payload,
        "signature_base64": registry_signature,
    }
    registry_sha256 = _sha(_json_bytes(registry_content))
    _private_write(
        registry_directory / f"{registry_sha256}.json",
        _json_bytes({**registry_content, "registry_sha256": registry_sha256}),
    )
    monkeypatch.setenv("JAA_CANDIDATE_CONTACT_AUTHORITY", str(authority_path))
    return authority_path


def _synthetic_projection(evidence_document: dict[str, object], evidence_bytes: bytes):
    rows = evidence_document.get("statements")
    if not isinstance(rows, list) or len(rows) < 8:
        raise ValueError("synthetic evidence fixture lacks its accepted fact set")
    approved_evidence = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("synthetic evidence fixture row is malformed")
        statement = row.get("statement")
        evidence_id = row.get("id")
        kind = row.get("kind")
        proof_class = row.get("proof_class")
        if (
            not isinstance(statement, str)
            or not isinstance(evidence_id, str)
            or not isinstance(kind, str)
            or proof_class != kind
        ):
            raise ValueError("synthetic evidence fixture lacks typed source bindings")
        approved_evidence.append(
            {
                "id": evidence_id,
                "statement_sha256": _sha(statement.encode("utf-8")),
                "kind": kind,
                "proof_class": proof_class,
            }
        )
    projection_body = {
        "policy_sha256": _sha(b"explicit synthetic local diagnostic policy"),
        "approved_evidence": approved_evidence,
        "source_hashes": {"approved_evidence": _sha(evidence_bytes)},
    }
    projection_sha256 = _sha(_json_bytes(projection_body))
    return {**projection_body, "projection_sha256": projection_sha256}


def _synthetic_decision(
    *,
    vacancy_sha256: str,
    projection: dict[str, object],
    evidence_document: dict[str, object],
):
    from career_automation.candidate_authority import fit_from_evidence_matrix

    rows = evidence_document["statements"]
    evidence_ids = [str(row["id"]) for row in rows[:2]]
    matrix = [
        {
            "requirement_id": "SYNTHETIC-REQ-1",
            "requirement_text": REQUIREMENT,
            "requirement_text_sha256": _sha(REQUIREMENT.encode("utf-8")),
            "classification": "essential",
            "status": "matched",
            "evidence_ids": evidence_ids,
            "suppressor_ids": [],
            "weight": "2",
        }
    ]
    return {
        "schema_version": "jaa.candidate-vacancy-decision-receipt.v1",
        "job_key": JOB_KEY,
        "role_title": ROLE_TITLE,
        "company_name": COMPANY_NAME,
        "source_url": APPLICATION_URL,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "vacancy_sha256": vacancy_sha256,
        "discovery_body_sha256": vacancy_sha256,
        "vacancy_description_sha256": _sha(VACANCY_DESCRIPTION.encode("utf-8")),
        "candidate_projection_sha256": projection["projection_sha256"],
        "decision": "eligible",
        "fit": fit_from_evidence_matrix(matrix),
        "eligibility_checks": [],
        "reasons": [],
        "missing_facts": [],
        "evidence_matrix": matrix,
    }


def _synthetic_html() -> str:
    return (
        "<!doctype html><html><head><title>"
        f"{html.escape(ROLE_TITLE)} at {html.escape(COMPANY_NAME)}"
        "</title></head><body><h1>"
        f"{html.escape(ROLE_TITLE)} at {html.escape(COMPANY_NAME)}"
        "</h1>"
        f"<p>{html.escape(VACANCY_DESCRIPTION)}</p><form>"
        '<label for="full_name">Full name</label>'
        '<input id="full_name" name="full_name" required>'
        '<label for="email">Email</label>'
        '<input id="email" name="email" type="email" required>'
        '<label for="city">City</label>'
        '<input id="city" name="city" required>'
        '<label for="resume">CV</label>'
        '<input id="resume" name="resume" type="file" required>'
        '<label for="cover_letter">Cover letter</label>'
        '<input id="cover_letter" name="cover_letter" type="file">'
        '<button type="submit">Submit Application</button>'
        "</form></body></html>"
    )


class _OneCallBackend:
    name = "codex_cli"

    def __init__(self, backend) -> None:
        self.backend = backend
        self.call_attempts = 0
        self.dispatched = 0
        self.responses = 0
        self.backend_errors = 0
        self.refused_before_dispatch = 0
        self.response_model: str | None = None

    def available(self) -> bool:
        return self.backend.available()

    def complete(self, system: str, user: str, temperature: float):
        self.call_attempts += 1
        if self.dispatched >= 1:
            self.refused_before_dispatch += 1
            from llm.client import LLMError

            raise LLMError(
                "synthetic diagnostic one-call limit: second backend dispatch refused"
            )
        self.dispatched += 1
        try:
            response = self.backend.complete(system, user, temperature)
        except Exception:
            self.backend_errors += 1
            raise
        self.responses += 1
        model = getattr(response, "model", None)
        self.response_model = model if isinstance(model, str) else None
        return response


@_capture_setup_failures
def test_native_prepare_release_one_call_local_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.environ.get("MA_RUN_NATIVE_BROWSER_DIAGNOSTIC") != "1":
        pytest.skip("opt-in native provider/browser diagnostic")
    repository_root = Path(__file__).resolve().parent
    expected_test_root = NAMED_TEST_ROOT / "internal" / "jaa"
    if repository_root != expected_test_root:
        pytest.fail("native diagnostic is admitted only in the exact named test tree")

    os.umask(0o077)
    tmp_path.chmod(0o700)
    if tmp_path.is_symlink() or not tmp_path.is_absolute():
        pytest.fail("diagnostic root must be a fresh private absolute directory")
    result: dict[str, object] = {
        "diagnostic_only": True,
        "synthetic_fixture": True,
        "production_admission": False,
        "external_network_enabled": False,
        "external_submission": False,
        "provider_model_selected": "gpt-6-luna",
        "provider_model_independently_attested": False,
        "source_url_sha256": _sha(APPLICATION_URL.encode("utf-8")),
    }
    evidence_bytes = ACCEPTED_EVIDENCE.read_bytes()
    evidence_sha256 = _sha(evidence_bytes)
    if evidence_sha256 != ACCEPTED_EVIDENCE_SHA256:
        pytest.fail("accepted synthetic evidence fixture digest differs")
    evidence_document = json.loads(evidence_bytes)
    projection = _synthetic_projection(evidence_document, evidence_bytes)
    result["approved_evidence_sha256"] = evidence_sha256
    result["candidate_projection_sha256"] = projection["projection_sha256"]

    from career_automation import candidate_contact_authority as contact_module
    from career_automation import candidate_release_gate as gate_module
    from career_automation import gutua_greenhouse_session as session_module
    from career_automation.application_archive import VacancyArchiveIdentity
    from career_automation.application_sanity_review import ApplicationSanityReviewError
    from career_automation.candidate_contact_authority import load_candidate_contact_authority
    from career_automation.production_attempt import GreenhouseAttemptRecorder
    from career_automation.production_queue import LiveVacancy, QueueItem
    from career_automation.production_runner import GeneratedRevisionSink
    from career_automation.gutua_greenhouse_session import GutuaGreenhouseSession
    from llm.client import CodexCliBackend, LLMClient

    contact_path = _make_fixture_contact(tmp_path, monkeypatch)
    contact_authority = load_candidate_contact_authority(
        contact_path, repository_root=repository_root
    )
    result["contact_authority_sha256"] = contact_authority.authority_sha256

    html_text = _synthetic_html()
    vacancy_body = html_text.encode("utf-8")
    vacancy_sha256 = _sha(vacancy_body)
    decision = _synthetic_decision(
        vacancy_sha256=vacancy_sha256,
        projection=projection,
        evidence_document=evidence_document,
    )
    decision_bytes = _json_bytes(decision)
    decision_sha256 = _sha(decision_bytes)
    result.update(
        vacancy_sha256=vacancy_sha256,
        decision_receipt_sha256=decision_sha256,
    )
    vacancy = VacancyArchiveIdentity(
        JOB_KEY, vacancy_sha256, ROLE_TITLE, COMPANY_NAME, APPLICATION_URL
    )
    live = LiveVacancy.create(
        vacancy=vacancy,
        provider="greenhouse",
        fit_score=decision["fit"],
        live=True,
        eligible=True,
        duplicate=False,
        live_verified_at=decision["observed_at"],
        scoring_inputs_sha256=decision_sha256,
    )
    item = QueueItem(live, 1, "new_attempt")
    archive_root = tmp_path / "archive"
    archive_root.mkdir(mode=0o700)
    recorder = GreenhouseAttemptRecorder.create(
        archive_root=archive_root,
        repository_root=repository_root,
        vacancy=vacancy,
        complete_vacancy=vacancy_body,
        structured_vacancy={
            "job_key": JOB_KEY,
            "source_url": APPLICATION_URL,
            "role_title": ROLE_TITLE,
            "company_name": COMPANY_NAME,
            "synthetic": True,
        },
        assessment={"synthetic": True},
    )
    result["attempt_id"] = recorder.attempt.attempt_id

    discovery_path = tmp_path / "synthetic-discovery.json"
    _private_write(discovery_path, _json_bytes({"synthetic": True}))
    authority_directory = archive_root / "candidate-authorities"
    authority_directory.mkdir(mode=0o700)
    eligibility_document = {
        "schema_version": "jaa.production-candidate-authority.v2",
        "candidate_projection": projection,
        "synthetic": True,
    }
    eligibility_bytes = _json_bytes(eligibility_document)
    eligibility_sha256 = _sha(eligibility_bytes)
    eligibility_path = authority_directory / f"{eligibility_sha256}.json"
    _private_write(eligibility_path, eligibility_bytes)

    session = object.__new__(GutuaGreenhouseSession)
    session.approved_evidence_path = ACCEPTED_EVIDENCE
    session.archive_root = archive_root
    session.repository_root = repository_root
    session.candidate_projection = projection
    session.decision_by_key = {
        JOB_KEY: {
            "job_key": JOB_KEY,
            "receipt": decision,
            "receipt_sha256": decision_sha256,
        }
    }
    session.complete_vacancy_by_key = {JOB_KEY: vacancy_body}
    session.discovery_path = discovery_path
    session.eligibility_path = eligibility_path

    duplicate_sha256 = _sha(b"synthetic local duplicate snapshot")
    monkeypatch.setattr(
        gate_module,
        "_verify_durable_candidate_authority",
        lambda *_args, **_kwargs: {
            "job_key": JOB_KEY,
            "role_title": ROLE_TITLE,
            "company_name": COMPANY_NAME,
            "vacancy_sha256": vacancy_sha256,
            "source_url": APPLICATION_URL,
            "candidate_authority_sha256": eligibility_sha256,
            "candidate_decision_receipt_sha256": decision_sha256,
            "candidate_projection_sha256": projection["projection_sha256"],
            "duplicate_snapshot_sha256": duplicate_sha256,
            "contact_authority_sha256": contact_authority.authority_sha256,
            "contact_registry_sha256": contact_authority.registry_sha256,
        },
    )
    observation = _json_bytes(
        {
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "synthetic": True,
            "provider_loader_paths": {
                "confirmation_message": "Synthetic fixture confirmation",
                "confirmationPath": "/example/jobs/1234567/confirmation",
            },
        }
    )

    class _ObservationReceipt:
        observation_sha256 = _sha(observation)

    monkeypatch.setattr(
        session_module,
        "load_provider_observation_authority",
        lambda **_kwargs: (observation, _ObservationReceipt()),
    )

    backend = _OneCallBackend(CodexCliBackend(model="gpt-6-luna"))
    class _LLMClientFactory:
        @staticmethod
        def from_config(**kwargs):
            return LLMClient(
                backend=backend,
                model="codex-cli-default",
                temperature=kwargs.get("temperature", 0),
                max_retries=1,
                cache_enabled=False,
                cache_dir=kwargs["cache_dir"],
                transport_archive_dir=kwargs["transport_archive_dir"],
                usage_log=kwargs["usage_log"],
            )

    monkeypatch.setattr(session_module, "LLMClient", _LLMClientFactory)
    review_receipts: list[object] = []
    real_review = session_module.review_application_package

    def capture_review(package, *, client):
        receipt = real_review(package, client=client)
        document = receipt.document()
        receipt_bytes = _json_bytes(document)
        recorder.add_revision(
            role="review.sanity_result",
            value=receipt_bytes,
            media_type="application/json",
            prior_sha256=None,
            approved=True,
        )
        _private_write(tmp_path / "sanity-review-receipt.json", receipt_bytes)
        review_receipts.append(receipt)
        result["sanity_receipt_sha256"] = _sha(receipt_bytes)
        result["sanity_receipt_model_identity"] = str(
            document.get("model_identity", "")
        )
        result["sanity_receipt_package_hashes_sha256"] = _sha(
            _json_bytes(document.get("package_hashes", {}))
        )
        model_result = document.get("model_result")
        findings = model_result.get("findings") if isinstance(model_result, dict) else None
        if isinstance(findings, list):
            result["sanity_finding_codes"] = sorted(
                str(row.get("code"))
                for row in findings
                if isinstance(row, dict) and isinstance(row.get("code"), str)
            )
        return receipt

    monkeypatch.setattr(session_module, "review_application_package", capture_review)
    fill_results: list[tuple[object, ...]] = []
    real_fill = GutuaGreenhouseSession._fill_supported_form

    def capture_fill(active_session, *args, **kwargs):
        fill_result = real_fill(active_session, *args, **kwargs)
        fill_results.append(fill_result)
        result["native_fill_returned"] = True
        result["uploaded_document_roles"] = sorted(str(row) for row in fill_result[0])
        return fill_result

    monkeypatch.setattr(GutuaGreenhouseSession, "_fill_supported_form", capture_fill)

    served = {"fixture_get": 0, "aborted_requests": 0, "post_attempts": 0}
    prepared = None
    error: Exception | None = None
    browser = None
    page = None
    finalized = False
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(headless=True)
                session._playwright = playwright
                session._browser = browser
                page = browser.new_page(service_workers="block")

                def route_request(route) -> None:
                    request = route.request
                    if (
                        request.url == APPLICATION_URL
                        and request.method == "GET"
                        and served["fixture_get"] == 0
                    ):
                        served["fixture_get"] += 1
                        route.fulfill(
                            status=200,
                            content_type="text/html; charset=utf-8",
                            body=html_text,
                        )
                        return
                    if request.method == "POST":
                        served["post_attempts"] += 1
                    served["aborted_requests"] += 1
                    route.abort()

                page.route("**/*", route_request)
                page.goto(APPLICATION_URL)
                recorder.record_navigation(
                    {
                        "method": "GET",
                        "status": 200,
                        "url": APPLICATION_URL,
                        "synthetic_route_fulfilled": True,
                        "network_exit": False,
                    }
                )
                recorder.record_prefill(page)
                sink = GeneratedRevisionSink(recorder)
                prepared = session.prepare_release(item, recorder, page, sink)
            except Exception as exc:
                error = exc
            finally:
                try:
                    if error is not None:
                        error_bytes = str(error).encode("utf-8", errors="replace")
                        if not (tmp_path / "actual-exception.txt").exists():
                            _private_write(tmp_path / "actual-exception.txt", error_bytes)
                        result["exception_sha256"] = _sha(error_bytes)
                        result["exception_type"] = type(error).__name__
                    if len(review_receipts) > 1:
                        result["invariant_violation"] = "multiple_sanity_receipts"
                    if error is not None and isinstance(error, ApplicationSanityReviewError):
                        raw_review = error.result
                        if raw_review is not None:
                            review_document = dict(raw_review)
                            review_bytes = _json_bytes(review_document)
                            _private_write(
                                tmp_path / "sanity-review-result.json", review_bytes
                            )
                            result["sanity_result_sha256"] = _sha(review_bytes)
                            findings = review_document.get("findings")
                            if isinstance(findings, list):
                                result["sanity_finding_codes"] = sorted(
                                    str(row.get("code"))
                                    for row in findings
                                    if isinstance(row, dict)
                                    and isinstance(row.get("code"), str)
                                )
                    reason = (
                        "synthetic_diagnostic_stopped_before_submit"
                        if prepared is not None
                        else "diagnostic_preintent_failure"
                    )
                    message = (
                        "Diagnostic ended before any submit action"
                        if error is None
                        else "Native diagnostic stopped before any submit action"
                    )
                    recorder.finalize_preintent_failure(
                        page,
                        reason_code=reason,
                        error_type=type(error).__name__ if error else "DiagnosticStop",
                        error_message=message,
                    )
                    finalized = True
                except Exception as archive_error:
                    archive_bytes = str(archive_error).encode("utf-8", errors="replace")
                    if not (tmp_path / "archive-exception.txt").exists():
                        _private_write(tmp_path / "archive-exception.txt", archive_bytes)
                    result["archive_error_type"] = type(archive_error).__name__
                    result["archive_exception_sha256"] = _sha(archive_bytes)
                if browser is not None:
                    try:
                        browser.close()
                    except Exception:
                        result["browser_close_error"] = True
    except Exception as exc:
        error = exc

    if error is not None and not (tmp_path / "actual-exception.txt").exists():
        error_bytes = str(error).encode("utf-8", errors="replace")
        _private_write(tmp_path / "actual-exception.txt", error_bytes)
        result["exception_sha256"] = _sha(error_bytes)
        result["exception_type"] = type(error).__name__

    objects = recorder.attempt._objects(recorder.attempt._events())
    roles = sorted(row.role for row in objects)
    result.update(
        provider_backend_calls=backend.call_attempts,
        provider_dispatches=backend.dispatched,
        provider_responses=backend.responses,
        provider_backend_errors=backend.backend_errors,
        provider_refused_before_dispatch=backend.refused_before_dispatch,
        provider_response_model=backend.response_model,
        fixture_gets_fulfilled=served["fixture_get"],
        intercepted_requests_aborted=served["aborted_requests"],
        intercepted_post_attempts=served["post_attempts"],
        external_network_requests=0,
        external_submission=0,
        prepared_returned=prepared is not None,
        attempt_finalized=finalized,
        terminal_archive_roles=roles,
    )
    if error is None:
        result["status"] = "prepared_no_submit"
    elif backend.refused_before_dispatch and result.get("native_fill_returned"):
        result["status"] = "stopped_after_fill_before_second_provider_dispatch"
    elif isinstance(error, ApplicationSanityReviewError) and error.result is not None:
        result["status"] = "sanity_review_blocked"
    elif isinstance(error, ApplicationSanityReviewError) and error.backend_failure is not None:
        result["status"] = "sanity_backend_failure"
    else:
        result["status"] = "native_diagnostic_failed"
    _save_result(tmp_path, result)
    print(json.dumps(result, sort_keys=True))

    assert result["provider_dispatches"] <= 1
    assert result["external_network_requests"] == 0
    assert result["intercepted_post_attempts"] == 0
    assert result["external_submission"] == 0
    assert result["attempt_id"]
    if page is not None:
        assert "submission.result" in result["terminal_archive_roles"]
        assert result["attempt_finalized"] is True
    if result["status"] == "native_diagnostic_failed":
        pytest.fail("native diagnostic failed; inspect private exception evidence")
    if result["status"] != "prepared_no_submit":
        pytest.fail(
            "native diagnostic stopped at a captured boundary; inspect safe result"
        )
    assert backend.dispatched == 1
    assert backend.responses == 1
    assert len(review_receipts) == 1
    assert result.get("native_fill_returned") is True
    assert result["attempt_finalized"] is True
    assert "submission.result" in result["terminal_archive_roles"]
