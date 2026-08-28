import json
import hashlib
import inspect
import shutil
import base64
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import career_automation.gutua_greenhouse_session as session_module
import career_automation.candidate_contact_authority as contact_module
from career_automation.gutua_greenhouse_session import GutuaGreenhouseSession
from career_automation.gutua_greenhouse_session import (
    APPROVED_CANDIDATE_SOURCE_HASHES,
    APPROVED_EVIDENCE_IDS,
    AVAILABILITY_AUTHORITY,
    CANDIDATE_POLICY_SHA256,
    CANDIDATE_SCHEMA_SHA256,
    _decision_receipt,
)
from career_automation.evidence_matching import canonical_json, content_hash
from career_automation.candidate_authority import materialize_candidate_authority
from career_automation.gmail_confirmation import GmailAPIConfirmationChecker
from career_automation.application_archive import VacancyArchiveIdentity
from career_automation.candidate_contact_authority import (
    ATTESTATION,
    REGISTRY_ATTESTATION,
    REGISTRY_SCHEMA_VERSION,
    SCHEMA_VERSION,
)
from career_automation.candidate_release_gate import CandidateAuthorityReleaseGate
from career_automation.production_attempt import GreenhouseAttemptRecorder
from career_automation.production_queue import LiveVacancy, QueueItem
from career_automation.production_runner import GeneratedRevisionSink
from career_automation.production_ats_executor import ProductionATSBoundaryError
from career_automation.testing_sanity_review import fixture_pass_receipt


PRODUCTION_DISCOVERY_PATH = Path(
    "/home/gutua/software-factory/application-artifacts/objects/39/"
    "39e60f8d278d8a07427c8bc25eff85bd357e98451cce87983d70d3d85e935f47"
)
PRODUCTION_ARCHIVE_ROOT = Path("/home/gutua/software-factory/application-artifacts")
TEST_CONTACT_PRIVATE_KEY = Ed25519PrivateKey.generate()
TEST_CONTACT_PUBLIC_RAW = TEST_CONTACT_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
TEST_CONTACT_PUBLIC_SHA256 = hashlib.sha256(TEST_CONTACT_PUBLIC_RAW).hexdigest()


@pytest.fixture(autouse=True)
def _enrol_test_contact_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    public_key_path = tmp_path / "operator-contact-public-key.pem"
    public_key_path.write_bytes(
        TEST_CONTACT_PRIVATE_KEY.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setattr(
        contact_module,
        "ENROLLED_OPERATOR_PUBLIC_KEY_SHA256",
        TEST_CONTACT_PUBLIC_SHA256,
    )
    monkeypatch.setenv(contact_module.PUBLIC_KEY_ENV, str(public_key_path))
    registry = tmp_path / "contact-registry"
    registry.mkdir()
    monkeypatch.setenv(contact_module.REGISTRY_ENV, str(registry))


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode()


def _contact_authority(directory: Path) -> Path:
    signed_payload = {
        "schema_version": SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_explicit_operator_attestation",
        "operator_attestation": ATTESTATION,
        "issued_at": "2026-08-06T00:00:00+00:00",
        "record_id": "operator-contact-primary",
        "record_version": 1,
        "contact": {
            "full_name": "Jordan Smith",
            "email": "jordan.smith@proton.me",
            "phone": "+44 7700 900123",
            "city": "London",
        },
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": TEST_CONTACT_PUBLIC_SHA256,
    }
    signature = base64.b64encode(
        TEST_CONTACT_PRIVATE_KEY.sign(_json_bytes(signed_payload))
    ).decode()
    content_addressed = {**signed_payload, "signature_base64": signature}
    digest = hashlib.sha256(_json_bytes(content_addressed)).hexdigest()
    path = directory / f"{digest}.json"
    path.write_bytes(_json_bytes({**content_addressed, "authority_sha256": digest}))
    registry_payload = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_operator_contact_registry",
        "operator_attestation": REGISTRY_ATTESTATION,
        "issued_at": signed_payload["issued_at"],
        "registry_id": "operator-contact-primary",
        "registry_version": 1,
        "current": {
            "record_id": signed_payload["record_id"],
            "record_version": signed_payload["record_version"],
            "authority_sha256": digest,
        },
        "revoked_authority_sha256s": [],
        "prior_registry_sha256": None,
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": TEST_CONTACT_PUBLIC_SHA256,
    }
    registry_signature = base64.b64encode(
        TEST_CONTACT_PRIVATE_KEY.sign(_json_bytes(registry_payload))
    ).decode()
    registry_content = {
        **registry_payload,
        "signature_base64": registry_signature,
    }
    registry_sha256 = hashlib.sha256(_json_bytes(registry_content)).hexdigest()
    (directory / "contact-registry" / f"{registry_sha256}.json").write_bytes(
        _json_bytes({**registry_content, "registry_sha256": registry_sha256})
    )
    return path


def _projection() -> dict[str, object]:
    projection: dict[str, object] = {
        "schema_version": "jaa.candidate-authority-projection.v1",
        "source_hashes": APPROVED_CANDIDATE_SOURCE_HASHES,
        "schema_sha256": CANDIDATE_SCHEMA_SHA256,
        "policy_sha256": CANDIDATE_POLICY_SHA256,
        "availability": AVAILABILITY_AUTHORITY,
        "approved_evidence": [
            {
                "id": evidence_id,
                "statement_sha256": hashlib.sha256(evidence_id.encode()).hexdigest(),
                "kind": "portfolio_artifact",
                "proof_class": "portfolio_artifact",
            }
            for evidence_id in APPROVED_EVIDENCE_IDS
        ],
        "claim_suppressors": {
            "source_sha256": APPROVED_CANDIDATE_SOURCE_HASHES[
                "negative_claim_suppressors"
            ],
            "mode": "suppress_only",
            "items": [
                {
                    "id": f"Q-{index:03d}",
                    "claim_sha256": hashlib.sha256(
                        f"claim-{index}".encode()
                    ).hexdigest(),
                    "ruling_sha256": hashlib.sha256(
                        f"ruling-{index}".encode()
                    ).hexdigest(),
                }
                for index in range(1, 11)
            ],
        },
    }
    projection["projection_sha256"] = hashlib.sha256(
        _json_bytes(projection)
    ).hexdigest()
    return projection


def _eligible_decision() -> tuple[dict[str, object], dict[str, object]]:
    vacancy = {
        "job_key": "greenhouse:graphcore:8556044002",
        "role_title": "Graduate Engineer",
        "company_name": "Example",
        "vacancy_sha256": "d" * 64,
        "source_url": ("https://job-boards.greenhouse.io/graphcore/jobs/8556044002"),
        "live_verified_at": "2026-08-05T22:55:56Z",
    }
    projection = _projection()
    checks = {
        key: {"status": "pass", "evidence_ids": ["authority:test"]}
        for key in (
            "live_deadline",
            "uk_work_right",
            "sponsorship",
            "location_attendance",
            "mandatory_credentials",
            "duplicate_replay",
        )
    }
    receipt = {
        "schema_version": "jaa.candidate-vacancy-decision-receipt.v1",
        "job_key": vacancy["job_key"],
        "role_title": "Graduate Engineer",
        "company_name": "Example",
        "vacancy_sha256": vacancy["vacancy_sha256"],
        "discovery_body_sha256": vacancy["vacancy_sha256"],
        "vacancy_description_sha256": "e" * 64,
        "database_sha256": APPROVED_CANDIDATE_SOURCE_HASHES["jobs_database"],
        "source_url": vacancy["source_url"],
        "observed_at": vacancy["live_verified_at"],
        "discovery_sha256": "f" * 64,
        "duplicate_snapshot_sha256": "a" * 64,
        "candidate_projection_sha256": projection["projection_sha256"],
        "schema_sha256": projection["schema_sha256"],
        "policy_sha256": projection["policy_sha256"],
        "source_hashes": projection["source_hashes"],
        "decision": "eligible",
        "fit": "1.000000",
        "reasons": ["all deterministic eligibility checks passed"],
        "missing_facts": [],
        "eligibility_checks": checks,
        "evidence_matrix": [
            {
                "requirement_id": "essential:python",
                "classification": "essential",
                "requirement_text": "Python experience",
                "requirement_text_sha256": hashlib.sha256(
                    b"Python experience"
                ).hexdigest(),
                "status": "matched",
                "evidence_ids": ["E-002"],
                "suppressor_ids": [],
                "weight": "2",
            }
        ],
    }
    return vacancy, {
        "receipt": receipt,
        "receipt_sha256": hashlib.sha256(_json_bytes(receipt)).hexdigest(),
        "projection": projection,
    }


def test_session_requires_explicit_external_authority_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("JAA_GREENHOUSE_DISCOVERY", raising=False)
    monkeypatch.delenv("JAA_GREENHOUSE_ELIGIBILITY", raising=False)
    with pytest.raises(ValueError, match="JAA_GREENHOUSE_DISCOVERY"):
        GutuaGreenhouseSession(SimpleNamespace(archive_root="/missing"))


def test_session_rejects_eligibility_coverage_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = tmp_path / "discovery.json"
    eligibility = tmp_path / "eligibility.json"
    discovery_document = {
        "schema_version": "jaa.greenhouse-live-discovery.v2",
        "eligibility_authority": False,
        "ranking_candidate_profile": "candidate-authority-required",
        "snapshot_sha256": "a" * 64,
        "live_pending_eligibility": [{"job_key": "greenhouse:x:123456"}],
        "observations": [],
    }
    discovery.write_bytes(_json_bytes(discovery_document))
    projection = _projection()
    eligibility.write_bytes(
        _json_bytes(
            {
                "schema_version": "jaa.production-candidate-authority.v2",
                "snapshot_sha256": "a" * 64,
                "discovery_sha256": hashlib.sha256(discovery.read_bytes()).hexdigest(),
                "duplicate_snapshot_sha256": "b" * 64,
                "candidate_projection": projection,
                "decisions": [],
            }
        )
    )
    monkeypatch.setenv("JAA_GREENHOUSE_DISCOVERY", str(discovery))
    monkeypatch.setenv("JAA_GREENHOUSE_ELIGIBILITY", str(eligibility))
    with pytest.raises(ValueError, match="exactly cover"):
        GutuaGreenhouseSession(SimpleNamespace(archive_root=tmp_path))


def test_session_rejects_legacy_empty_candidate_ranking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = tmp_path / "legacy-discovery.json"
    eligibility = tmp_path / "legacy-eligibility.json"
    discovery.write_text(
        json.dumps(
            {
                "schema_version": "jaa.greenhouse-live-discovery.v2",
                "eligibility_authority": False,
                "ranking_candidate_profile": "empty",
                "snapshot_sha256": "a" * 64,
            }
        )
    )
    eligibility.write_text(
        json.dumps(
            {
                "schema_version": "jaa.production-eligibility.v1",
                "snapshot_sha256": "a" * 64,
            }
        )
    )
    monkeypatch.setenv("JAA_GREENHOUSE_DISCOVERY", str(discovery))
    monkeypatch.setenv("JAA_GREENHOUSE_ELIGIBILITY", str(eligibility))
    with pytest.raises(ValueError, match="non-empty, receipt-bound"):
        GutuaGreenhouseSession(SimpleNamespace(archive_root=tmp_path))


def test_candidate_receipt_is_the_only_fit_and_scoring_authority() -> None:
    vacancy, authority = _eligible_decision()
    eligible, fit, scoring_sha256 = _decision_receipt(
        authority,
        vacancy=vacancy,
        projection=authority["projection"],
        discovery_sha256="f" * 64,
        vacancy_description_sha256="e" * 64,
        duplicate_snapshot_sha256="a" * 64,
    )
    assert eligible is True
    assert fit == "1.000000"
    assert scoring_sha256 == authority["receipt_sha256"]


def test_candidate_receipt_rejects_fit_or_hash_substitution() -> None:
    vacancy, authority = _eligible_decision()
    authority["receipt"]["fit"] = "0.999"
    with pytest.raises(ValueError, match="receipt hash differs"):
        _decision_receipt(
            authority,
            vacancy=vacancy,
            projection=authority["projection"],
            discovery_sha256="f" * 64,
            vacancy_description_sha256="e" * 64,
            duplicate_snapshot_sha256="a" * 64,
        )


def test_candidate_receipt_cannot_mark_commuter_fact_role_eligible() -> None:
    vacancy, authority = _eligible_decision()
    vacancy["job_key"] = "greenhouse:tripadvisor:6674829"
    vacancy["source_url"] = "https://job-boards.greenhouse.io/tripadvisor/jobs/6674829"
    authority["receipt"]["job_key"] = vacancy["job_key"]
    authority["receipt"]["source_url"] = vacancy["source_url"]
    authority["receipt_sha256"] = hashlib.sha256(
        _json_bytes(authority["receipt"])
    ).hexdigest()
    with pytest.raises(ValueError, match="bindings are incomplete"):
        _decision_receipt(
            authority,
            vacancy=vacancy,
            projection=authority["projection"],
            discovery_sha256="f" * 64,
            vacancy_description_sha256="e" * 64,
            duplicate_snapshot_sha256="a" * 64,
        )


def test_session_loads_materialized_receipts_and_ignores_legacy_fit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovery = json.loads(PRODUCTION_DISCOVERY_PATH.read_bytes())
    for observation in discovery["observations"]:
        for name in ("body_sha256", "network_evidence_sha256"):
            digest = observation[name]
            source = PRODUCTION_ARCHIVE_ROOT / "objects" / digest[:2] / digest
            target = tmp_path / "objects" / digest[:2] / digest
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    authority = materialize_candidate_authority(
        discovery_path=PRODUCTION_DISCOVERY_PATH,
        archive_root=tmp_path,
        repository_root=Path.cwd(),
    )

    class Browser:
        def new_page(self):
            return object()

        def close(self) -> None:
            pass

    class Playwright:
        chromium = SimpleNamespace(launch=lambda **_kwargs: Browser())

        def start(self):
            return self

        def stop(self) -> None:
            pass

    monkeypatch.setattr(
        "career_automation.gutua_greenhouse_session.sync_playwright",
        Playwright,
    )
    monkeypatch.setenv("JAA_GREENHOUSE_DISCOVERY", str(PRODUCTION_DISCOVERY_PATH))
    monkeypatch.setenv("JAA_GREENHOUSE_ELIGIBILITY", str(authority.authority_path))
    session = GutuaGreenhouseSession(
        SimpleNamespace(archive_root=tmp_path, repository_root=Path.cwd())
    )
    try:
        assert len(session.candidates) == 15
        assert all(
            str(candidate.vacancy.fit_score)
            == candidate.assessment["candidate_authority_receipt"]["receipt"]["fit"]
            for candidate in session.candidates
        )
        assert isinstance(
            session.gmail_confirmation_checker, GmailAPIConfirmationChecker
        )
    finally:
        session.close()


def test_session_rejects_stale_duplicate_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = materialize_candidate_authority(
        discovery_path=PRODUCTION_DISCOVERY_PATH,
        archive_root=tmp_path,
        repository_root=Path.cwd(),
    )
    monkeypatch.setenv("JAA_GREENHOUSE_DISCOVERY", str(PRODUCTION_DISCOVERY_PATH))
    monkeypatch.setenv("JAA_GREENHOUSE_ELIGIBILITY", str(authority.authority_path))
    monkeypatch.setattr(
        "career_automation.candidate_authority.archive_duplicate_snapshot",
        lambda *_args: ("f" * 64, frozenset()),
    )
    with pytest.raises(ValueError, match="deterministic current materialization"):
        GutuaGreenhouseSession(
            SimpleNamespace(archive_root=tmp_path, repository_root=Path.cwd())
        )


def test_repository_session_prepares_sink_bound_fixture_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = json.loads(
        (
            PRODUCTION_ARCHIVE_ROOT
            / "candidate-authorities"
            / "85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9.json"
        ).read_bytes()
    )
    original = next(
        row
        for row in authority["decisions"]
        if row["receipt"]["decision"] == "eligible"
    )
    application_url = "https://job-boards.greenhouse.io/example/jobs/1234567"
    html = """<html><head><title>Graduate Engineer at Example</title></head><body>
    <p>Build reliable Python data pipelines and tested cloud services for customers.</p>
    <form>
      <label>Full name <input name="full_name" required></label>
      <label>Email <input name="email" type="email" required></label>
      <label>Phone <input name="phone" required></label>
      <label>City <input name="city" required></label>
      <label>CV <input name="resume" type="file" required></label>
      <label>Cover letter <input name="cover_letter" type="file"></label>
      <label><input name="consent" type="checkbox" required>Privacy consent</label>
      <button type="submit">Submit Application</button>
    </form></body></html>"""
    vacancy_body = html.encode()
    vacancy_sha256 = hashlib.sha256(vacancy_body).hexdigest()
    decision = {
        **original["receipt"],
        "job_key": "greenhouse:example:1234567",
        "role_title": "Graduate Engineer",
        "company_name": "Example",
        "source_url": application_url,
        "vacancy_sha256": vacancy_sha256,
        "discovery_body_sha256": vacancy_sha256,
    }
    decision_row = {
        "job_key": decision["job_key"],
        "receipt": decision,
        "receipt_sha256": hashlib.sha256(_json_bytes(decision)).hexdigest(),
    }
    vacancy = VacancyArchiveIdentity(
        decision["job_key"],
        vacancy_sha256,
        "Graduate Engineer",
        "Example",
        application_url,
    )
    live = LiveVacancy.create(
        vacancy=vacancy,
        provider="greenhouse",
        fit_score=decision["fit"],
        live=True,
        eligible=True,
        duplicate=False,
        live_verified_at=datetime.now(timezone.utc).isoformat(),
        scoring_inputs_sha256=decision_row["receipt_sha256"],
    )
    item = QueueItem(live, 1, "new_attempt")
    archive_root = tmp_path / "application-archive"
    archive_root.mkdir()
    recorder = GreenhouseAttemptRecorder.create(
        archive_root=archive_root,
        repository_root=Path.cwd(),
        vacancy=vacancy,
        complete_vacancy=vacancy_body,
        structured_vacancy={"job_key": vacancy.job_key},
        assessment={"eligible": True, "fit_score": decision["fit"]},
    )
    session = object.__new__(GutuaGreenhouseSession)
    session.archive_root = archive_root
    session.repository_root = Path.cwd().resolve()
    session.candidate_projection = authority["candidate_projection"]
    session.decision_by_key = {vacancy.job_key: decision_row}
    session.complete_vacancy_by_key = {vacancy.job_key: vacancy_body}
    session.discovery_path = PRODUCTION_DISCOVERY_PATH
    session.eligibility_path = (
        PRODUCTION_ARCHIVE_ROOT
        / "candidate-authorities"
        / "85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9.json"
    )
    contact_path = _contact_authority(tmp_path)
    contact_sha256 = contact_path.stem
    monkeypatch.setattr(
        "career_automation.candidate_release_gate._verify_durable_candidate_authority",
        lambda *_args, **_kwargs: {
            "job_key": vacancy.job_key,
            "role_title": vacancy.role_title,
            "company_name": vacancy.company_name,
            "vacancy_sha256": vacancy.vacancy_sha256,
            "source_url": vacancy.source_url,
            "candidate_authority_sha256": session.eligibility_path.stem,
            "candidate_decision_receipt_sha256": decision_row["receipt_sha256"],
            "candidate_projection_sha256": authority["candidate_projection"][
                "projection_sha256"
            ],
            "duplicate_snapshot_sha256": decision["duplicate_snapshot_sha256"],
            "contact_authority_sha256": contact_sha256,
        },
    )
    monkeypatch.setenv("JAA_CANDIDATE_CONTACT_AUTHORITY", str(contact_path))
    head = "a" * 40
    monkeypatch.setattr(
        "career_automation.candidate_release_gate.exact_clean_head",
        lambda _root: head,
    )
    monkeypatch.setattr(
        "career_automation.gutua_greenhouse_session.exact_clean_head",
        lambda _root: head,
    )
    monkeypatch.setattr(
        "career_automation.provider_observation_authority.exact_clean_head",
        lambda _root: head,
    )
    assurance_complete = False
    original_assurance = session_module.assert_application_artifacts
    original_publish = session_module.publish_application_artifacts
    original_fill = GutuaGreenhouseSession._fill_supported_form

    def tracked_assurance(**kwargs):
        nonlocal assurance_complete
        result = original_assurance(**kwargs)
        assurance_complete = True
        return result

    def tracked_publish(source, artifacts, **kwargs):
        prepared_source["source"] = source
        prepared_source["artifacts"] = artifacts
        return original_publish(source, artifacts, **kwargs)

    def tracked_fill(active_session, *args, **kwargs):
        assert assurance_complete is True
        return original_fill(active_session, *args, **kwargs)

    monkeypatch.setattr(
        session_module, "assert_application_artifacts", tracked_assurance
    )
    monkeypatch.setattr(
        session_module, "publish_application_artifacts", tracked_publish
    )
    monkeypatch.setattr(GutuaGreenhouseSession, "_fill_supported_form", tracked_fill)
    monkeypatch.setattr(
        "career_automation.gutua_greenhouse_session.review_application_package",
        lambda package, client: fixture_pass_receipt(
            source=prepared_source["source"],
            artifacts=prepared_source["artifacts"],
            questions=None,
            state_root=tmp_path,
            vacancy_requirements=package.vacancy_requirements,
        ),
    )
    from playwright.sync_api import sync_playwright

    prepared_source: dict[str, object] = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.route(
            "**/*",
            lambda route: route.fulfill(
                status=200, content_type="text/html", body=html
            ),
        )
        page.goto(application_url)
        recorder.record_navigation(
            {"method": "GET", "status": 200, "url": application_url}
        )
        recorder.record_prefill(page)
        sink = GeneratedRevisionSink(recorder)
        prepared = session.prepare_release(item, recorder, page, sink)
        assert isinstance(prepared.gate, CandidateAuthorityReleaseGate)
        assert prepared.generation_authority is sink.authority
        assert prepared.attached_roles == ("cv", "cover_letter")
        assert prepared.upload_paths["cv"].read_bytes() == (
            prepared.artifacts.cv_pdf.pdf_bytes
        )
        expected_requirements = tuple(
            f"{row['requirement_id']}: {row['requirement_text']}"
            for row in decision["evidence_matrix"]
        )
        assert prepared.vacancy_requirements == expected_requirements
        assert prepared.sanity_review_receipt.vacancy_requirements_sha256 == (
            content_hash(list(expected_requirements))
        )
        assert page.locator('input[name="email"]').input_value() == (
            "jordan.smith@proton.me"
        )
        assert page.locator('input[name="consent"]').is_checked()
        from career_automation.application_archive import load_complete_attempt_view

        view = load_complete_attempt_view(
            recorder.attempt.attempt_id,
            root=recorder.attempt.archive.root,
            repository_root=recorder.attempt.archive.repository_root,
        )
        event_kinds = {
            row["payload"]["event_kind"] for row in view["evidence_events"]
        }
        assert {"navigation", "preflight", "field_filled", "field_selected", "file_uploaded", "screenshot"} <= event_kinds
        assert view["gaps"]["action_timeline"] is False
        assert "jordan.smith@proton.me" not in json.dumps(view, sort_keys=True)
        browser.close()


@pytest.mark.parametrize(
    ("extra_field", "message"),
    (
        (
            '<label><input name="work_mode" type="radio" required>Hybrid</label>',
            "radio choice requires explicit answer authority",
        ),
        (
            '<label>Years of experience <input name="years" required></label>',
            "required Greenhouse question lacks approved answer authority",
        ),
    ),
)
def test_form_preparation_rejects_unapproved_required_choices(
    tmp_path: Path,
    extra_field: str,
    message: str,
) -> None:
    artifact_directory = tmp_path / "artifacts"
    artifact_directory.mkdir()
    (artifact_directory / "cv.pdf").write_bytes(b"%PDF-fixture")
    package = SimpleNamespace(
        source=SimpleNamespace(
            contact=SimpleNamespace(
                full_name="Alex Example",
                email="alex@example.test",
                phone="+44 7700 900123",
                city="London",
            ),
            facts=(),
            style_slots=(),
            answers=(),
        ),
        artifacts=SimpleNamespace(
            editable=SimpleNamespace(answers_text=""),
        ),
    )
    session = object.__new__(GutuaGreenhouseSession)
    html = f"""<form>
      {extra_field}
      <label>CV <input name="resume" type="file" required></label>
    </form>"""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(html)
        with pytest.raises(ProductionATSBoundaryError, match=message):
            session._fill_supported_form(
                page,
                package,
                artifact_directory=artifact_directory,
            )
        browser.close()


def test_graphcore_recurring_fields_use_only_stable_candidate_authority(
    tmp_path: Path,
) -> None:
    artifact_directory = tmp_path / "artifacts"
    artifact_directory.mkdir()
    (artifact_directory / "cv.pdf").write_bytes(b"%PDF-fixture")
    package = SimpleNamespace(
        source=SimpleNamespace(
            contact=SimpleNamespace(
                full_name="Alex Example",
                email="alex@example.test",
                phone=None,
                city="London",
            ),
            facts=(),
            style_slots=(),
            answers=(),
        ),
        artifacts=SimpleNamespace(editable=SimpleNamespace(answers_text="")),
    )
    session = object.__new__(GutuaGreenhouseSession)
    html = """<form>
      <label>First Name*<input id="first_name" required></label>
      <label>Last Name*<input id="last_name" required></label>
      <label>Email*<input id="email" required></label>
      <label>Have you added your full legal name and surname (including any middle names)?*
        <select id="question_1" required><option></option><option>Yes</option><option>No</option></select>
      </label>
      <label>Do you have the legal right to work in the UK?*
        <select id="question_2" required><option></option><option>Yes</option><option>No</option></select>
      </label>
      <label>Please select your right to work status*
        <select id="question_3" required><option></option><option>EU Settled Status</option></select>
      </label>
      <label>How did you hear about this role?*<input id="question_4" required></label>
      <label>I identify my gender as*
        <select id="gender" required><option></option><option>I don't wish to answer</option></select>
      </label>
      <label>What is your ethnicity?*
        <select id="ethnicity" required><option></option><option>I don't wish to answer</option></select>
      </label>
      <label>Do you consider yourself to have a disability?*
        <select id="disability" required><option></option><option>I don't wish to answer</option></select>
      </label>
      <label>CV<input id="resume" type="file" required></label>
      <label><input name="gdpr_demographic_data_consent_given" type="checkbox" required>
        I consent to processing these demographic survey responses.</label>
    </form>"""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(html)
        vacancy_bytes = page.content().encode("utf-8")
        vacancy = VacancyArchiveIdentity(
            job_key="greenhouse:fixture:graphcore",
            vacancy_sha256=hashlib.sha256(vacancy_bytes).hexdigest(),
            role_title="Synthetic engineer",
            company_name="Fixture company",
            source_url="https://job-boards.greenhouse.io/fixture/jobs/1234567",
        )
        recorder = GreenhouseAttemptRecorder.create(
            archive_root=tmp_path / "archive",
            repository_root=Path.cwd(),
            vacancy=vacancy,
            complete_vacancy=vacancy_bytes,
            structured_vacancy={"job_key": vacancy.job_key},
            assessment={"eligible": True, "fixture_only": True},
        )
        recorder.add_revision(
            role="document.cv.final_pdf",
            value=b"%PDF-fixture",
            media_type="application/pdf",
            prior_sha256=None,
            approved=True,
        )
        recorder.record_navigation(
            {"method": "GET", "status": 200, "url": vacancy.source_url}
        )
        recorder.record_prefill(page)
        _, _, authorities, consents, _ = session._fill_supported_form(
            page,
            package,
            artifact_directory=artifact_directory,
            recorder=recorder,
        )
        assert dict(authorities) == {
            "first_name": "contact.given_name",
            "last_name": "contact.family_name",
            "email": "contact.email",
            "question_1": "candidate.legal_name_complete",
            "question_2": "candidate.uk_work_right",
            "question_3": "candidate.uk_work_status",
            "question_4": "candidate.discovery_source",
            "gender": "candidate.gender_nondisclosure",
            "ethnicity": "candidate.ethnicity_nondisclosure",
            "disability": "candidate.disability_nondisclosure",
        }
        assert page.locator("#question_3").input_value() == "EU Settled Status"
        assert page.locator("#gender").input_value() == "I don't wish to answer"
        assert dict(consents) == {"gdpr_demographic_data_consent_given": True}
        from career_automation.application_archive import load_complete_attempt_view

        view = load_complete_attempt_view(
            recorder.attempt.attempt_id,
            root=recorder.attempt.archive.root,
            repository_root=recorder.attempt.archive.repository_root,
        )
        kinds = {row["payload"]["event_kind"] for row in view["evidence_events"]}
        assert {"navigation", "preflight", "field_filled", "field_selected", "file_uploaded", "click", "screenshot"} <= kinds
        assert view["gaps"]["action_timeline"] is False
        assert "Alex Example" not in json.dumps(view, sort_keys=True)
        browser.close()


def test_ethnicity_label_never_resolves_to_contact_city() -> None:
    authority = GutuaGreenhouseSession._field_authority(
        {"id": "demographic", "name": "", "labels": ["What is your ethnicity?"]}
    )
    assert authority == "candidate.ethnicity_nondisclosure"


def test_field_locator_excludes_wrapper_with_same_identity_as_input_name() -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(
            """<form>
            <div id="consent"><input id="consent_1" name="consent" type="checkbox"></div>
            </form>"""
        )
        locator = GutuaGreenhouseSession._locator(page, "consent")
        assert locator.count() == 1
        assert locator.evaluate("element => element.tagName") == "INPUT"
        browser.close()


def test_phone_widget_country_search_is_not_treated_as_application_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_directory = tmp_path / "artifacts"
    artifact_directory.mkdir()
    (artifact_directory / "cv.pdf").write_bytes(b"%PDF-fixture")
    package = SimpleNamespace(
        source=SimpleNamespace(
            contact=SimpleNamespace(
                full_name="Alex Example",
                email="alex@example.test",
                phone=None,
                city="London",
            ),
            facts=(),
            style_slots=(),
            answers=(),
        ),
        artifacts=SimpleNamespace(editable=SimpleNamespace(answers_text="")),
    )
    inventory = {
        "form_state": {
            "fields": [
                {
                    "id": "iti-0__search-input",
                    "name": "",
                    "tag": "input",
                    "type": "search",
                    "labels": [],
                    "required": False,
                },
                {
                    "id": "resume",
                    "name": "",
                    "tag": "input",
                    "type": "file",
                    "labels": ["CV"],
                    "required": True,
                },
            ]
        },
        "select_inventories": [
            {
                "field_identity": "iti-0__search-input",
                "option_source": "dynamic_search",
                "options": [],
            }
        ],
    }
    monkeypatch.setattr(
        session_module,
        "collect_greenhouse_form_inventory",
        lambda _page: _json_bytes(inventory),
    )
    session = object.__new__(GutuaGreenhouseSession)
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(
            """<form>
            <input id="iti-0__search-input" type="search" hidden>
            <label>CV<input id="resume" type="file" required></label>
            </form>"""
        )
        _, _, authorities, _, _ = session._fill_supported_form(
            page, package, artifact_directory=artifact_directory
        )
        assert authorities == ()
        browser.close()


def test_dynamic_option_is_bound_to_its_own_controlled_listbox() -> None:
    session = object.__new__(GutuaGreenhouseSession)
    from playwright.sync_api import sync_playwright

    html = """<form>
      <input id="gender" role="combobox" aria-controls="gender-listbox">
      <div id="gender-listbox" role="listbox">
        <div role="option" hidden>I don't wish to answer</div>
        <div role="option" onclick="window.selected = 'gender'">I don't wish to answer</div>
      </div>
      <input id="ethnicity" role="combobox" aria-controls="ethnicity-listbox">
      <div id="ethnicity-listbox" role="listbox">
        <div role="option" onclick="window.selected = 'ethnicity'">I don't wish to answer</div>
      </div>
    </form>"""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(html)
        session._select_dynamic_option(
            page,
            page.locator("#gender"),
            identity="gender",
            value="I don't wish to answer",
        )
        assert page.evaluate("window.selected") == "gender"
        browser.close()


def test_concrete_preparation_uses_only_owned_candidate_generator() -> None:
    source = inspect.getsource(GutuaGreenhouseSession.prepare_release)
    assert "sink.generate_candidate_application(" in source
    assert "producer=" not in source
    assert "generate_product" not in source
