"""One synthetic receipt chain across Market Aligner, CV, JAA-08 and Workable."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import date, datetime, timezone
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest
from playwright.sync_api import sync_playwright

import career_automation.workable_live_adapter as workable_module
from career_automation.ashby_live_adapter import JAA08ReleaseAuthority
from career_automation.current_time import configured_hmac_current_time_witness
from career_automation.handoff_admission import HandoffAdmissionStore, ResolvedReference
from career_automation.market_aligner_handoff import (
    HandoffContractError,
    canonical_json_bytes,
    parse_handoff,
)
from career_automation.release_gate import (
    REQUIRED_VALIDATORS,
    OfficialRouteBinding,
    ReleaseBinding,
    ValidationReceipt,
    WorkRightBinding,
    compile_release_manifest,
    verify_release_manifest,
)
from career_automation.workable_live_adapter import (
    WorkableApplication,
    WorkableField,
    WorkableLiveAdapter,
    WorkableOneUseCircuit,
    WorkablePolicy,
    WorkableSchemaError,
    WorkableUpload,
)
from cv_generation.constraints import CVConstraintError, verify_poppler_cv_quality
from cv_generation.service import build_candidate_application_package
from test_candidate_application_factory import _inputs as candidate_inputs
from test_workable_live_adapter import _install


POPPLER_ROOT = Path("/home/gutua/software-factory/.control/poppler-26.01.0/root")
POPPLER_BIN = POPPLER_ROOT / "usr/bin"
POPPLER_LIB = POPPLER_ROOT / "usr/lib/x86_64-linux-gnu"
ADMISSION_TIME = datetime(2026, 8, 10, 10, 5, tzinfo=timezone.utc)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class _ContextAuthenticator:
    authenticator_identity_sha256 = _sha(b"walking-skeleton-context-authenticator")

    def authenticate(self, *, context_bytes: bytes, handoff_bytes: bytes, **_) -> None:
        context = json.loads(context_bytes)
        assert context["handoff_root_sha256"] == _sha(handoff_bytes)
        assert context["trust_root_id"] == "synthetic-market-root"


class _Resolver:
    resolver_identity_sha256 = _sha(b"walking-skeleton-reference-resolver")

    def __init__(self, document: dict[str, object]) -> None:
        entries = document["reference_bundle"]["value"]["entries"]
        self._entries = {
            row["metadata"]["reference_key"]: (
                base64.b64decode(row["object_base64"], validate=True),
                canonical_json_bytes(row["metadata"]),
            )
            for row in entries
        }

    def resolve(self, request) -> ResolvedReference:
        exact, metadata = self._entries[request.spec.reference_key]
        assert _sha(exact) == request.sha256
        return ResolvedReference(exact, metadata)

    def authenticate(self, *, metadata_bytes: bytes, exact_bytes: bytes, **_) -> None:
        metadata = json.loads(metadata_bytes)
        expected = self._entries[metadata["reference_key"]]
        assert (exact_bytes, metadata_bytes) == expected


def _admit(tmp_path: Path):
    fixture_bytes = files("career_automation").joinpath(
        "fixtures/market-aligner-v1-vectors.json"
    ).read_bytes()
    document = json.loads(fixture_bytes)
    handoff_bytes = base64.b64decode(
        document["handoff"]["canonical_base64"], validate=True
    )
    parsed = parse_handoff(handoff_bytes)
    context = canonical_json_bytes(
        {
            "environment": "synthetic",
            "handoff_root_sha256": parsed.root_sha256,
            "issued_at": "2026-08-10T10:04:00Z",
            "producer_commit_sha": parsed.payload["producer"]["commit_sha"],
            "producer_product": "market-aligner",
            "source_record_sha256": _sha(fixture_bytes),
            "trust_mode": "authenticated_attestation",
            "trust_proof_sha256": _sha(b"walking-skeleton-context-proof"),
            "trust_root_id": "synthetic-market-root",
        }
    )
    witness = configured_hmac_current_time_witness(
        authentication_key=b"walking-skeleton-time-key-at-least-32-bytes!",
        environment="synthetic",
        trust_root_id="synthetic-market-time-root",
        witness_identity_sha256=_sha(b"walking-skeleton-time-witness"),
        clock=lambda: ADMISSION_TIME,
        nonce_source=lambda: b"walking-skeleton-fixed-nonce",
    )
    admission = HandoffAdmissionStore(
        tmp_path / "handoff.sqlite3",
        context_authenticator=_ContextAuthenticator(),
        resolver=_Resolver(document),
        current_time_witness=witness,
    ).admit_authenticated(handoff_bytes, context)
    return admission, parsed, handoff_bytes, context


class _ManifestGate:
    def __init__(self, manifest, token: str, quality_receipt_sha256: str) -> None:
        self.manifest = manifest
        self.token = token
        self.quality_receipt_sha256 = quality_receipt_sha256
        self.calls = 0

    def consume_release_token(self, **kwargs: object) -> object:
        if self.calls or kwargs["release_token"] != self.token:
            raise ValueError("JAA-08 release token is invalid or already consumed")
        verify_release_manifest(self.manifest)
        source = kwargs["source"]
        artifacts = kwargs["artifacts"]
        binding = self.manifest.binding
        if (
            source.job_key != binding.job_key
            or source.content_sha256 != binding.application_source_sha256
            or binding.artifact_receipt_sha256
            != _sha((artifacts.cv_pdf.pdf_sha256 + self.quality_receipt_sha256).encode())
        ):
            raise ValueError("JAA-08 inputs differ from the release manifest")
        self.calls += 1
        return SimpleNamespace(
            release_manifest_sha256=self.manifest.release_manifest_sha256,
            token_sha256=_sha(self.token.encode()),
        )


def _release_manifest(package, policy: WorkablePolicy, quality):
    cv_hash = package.artifacts.cv_pdf.pdf_sha256
    binding = ReleaseBinding(
        job_key=package.source.job_key,
        candidate_identity_sha256=_sha(package.source.contact.record_id.encode()),
        vacancy_sha256=package.source.vacancy_sha256,
        vacancy_observed_at=date(2026, 8, 10),
        vacancy_valid_until=date(2026, 8, 30),
        dossier_sha256=_sha(b"synthetic employer dossier"),
        candidate_profile_sha256=_sha(b"approved candidate projection"),
        strategy_id=_sha(b"workable walking skeleton strategy"),
        strategy_document_sha256=_sha(policy.policy_sha256.encode()),
        application_source_id=package.source.source_id,
        application_source_sha256=package.source.content_sha256,
        artifact_set_sha256=_sha(
            (cv_hash + package.artifacts.cover_letter_pdf.pdf_sha256).encode()
        ),
        artifact_receipt_sha256=_sha((cv_hash + quality.receipt_sha256).encode()),
        deterministic_writer_policy_sha256=_sha(b"candidate-application-factory-v1"),
        model_receipt_sha256s=(),
        work_right=WorkRightBinding(
            "GB", "employee", "synthetic-work-right", 1, _sha(b"work-right"),
            date(2026, 1, 1), date(2027, 1, 1), True,
        ),
        official_route=OfficialRouteBinding(
            "workable-synthetic", "workable", policy.version,
            policy.application_url, policy.policy_sha256,
            date(2026, 8, 10), date(2026, 8, 30), True,
        ),
        evaluated_at=date(2026, 8, 20),
        prior_application_count=0,
    )
    receipts = tuple(
        ValidationReceipt(
            validator_id=name,
            validator_version="walking-skeleton-v1",
            validator_impl_sha256=_sha(f"{name}-implementation".encode()),
            input_sha256=binding.input_sha256,
            artifact_set_sha256=binding.artifact_set_sha256,
            decision="pass",
        )
        for name in REQUIRED_VALIDATORS
    )
    return compile_release_manifest(binding, receipts)


def test_authenticated_market_to_one_use_workable_receipt_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admission, parsed, _, _ = _admit(tmp_path)
    policy = WorkablePolicy(
        tenant="synthetic",
        vacancy_id="ABC123",
        job_key=admission.job_key,
        fields=(
            WorkableField("full_name", "text", True, "Full name"),
            WorkableField("email", "email", True, "Email"),
            WorkableField("resume", "file", True, "Resume"),
            WorkableField("terms", "checkbox", True, "I confirm"),
        ),
    )
    arguments = candidate_inputs()
    decision = json.loads(json.dumps(arguments["decision_receipt"]))
    vacancy = parsed.payload["vacancy"]
    decision.update(
        job_key=admission.job_key,
        vacancy_sha256=vacancy["vacancy_snapshot_sha256"],
        role_title=vacancy["role_title"],
        company_name=vacancy["company_name"],
        source_url=policy.application_url,
    )
    arguments.update(
        decision_receipt=decision,
        job_key=admission.job_key,
        vacancy_sha256=vacancy["vacancy_snapshot_sha256"],
        role_title=vacancy["role_title"],
        company_name=vacancy["company_name"],
        source_url=policy.application_url,
    )
    package = build_candidate_application_package(**arguments)
    cv_path = tmp_path / "approved-cv.pdf"
    cv_path.write_bytes(package.artifacts.cv_pdf.pdf_bytes)
    quality = verify_poppler_cv_quality(
        cv_path,
        expected_pdf_sha256=package.artifacts.cv_pdf.pdf_sha256,
        expected_page_count=package.artifacts.cv_pdf.page_count,
        required_text_markers=(package.source.contact.full_name, "Core Capabilities"),
        poppler_bin_dir=POPPLER_BIN,
        poppler_library_dir=POPPLER_LIB,
    )
    assert quality.release_authority is False
    assert quality.cv_pdf_sha256 == package.artifacts.cv_pdf.pdf_sha256

    manifest = _release_manifest(package, policy, quality)
    verify_release_manifest(manifest)
    token = f"jaa08.{manifest.release_manifest_sha256}.walking-skeleton-token"
    gate = _ManifestGate(manifest, token, quality.receipt_sha256)
    authority = JAA08ReleaseAuthority(
        gate=gate, release_token=token, source=package.source,
        artifacts=package.artifacts, contact=package.source.contact, questions=None,
        artifact_root=tmp_path, repository_root=Path("/synthetic/repository"),
        jurisdiction="GB", contract_type="employee",
        consumed_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
    )
    answers = {
        "full_name": package.source.contact.full_name,
        "email": package.source.contact.email,
        "terms": True,
    }
    upload = WorkableUpload(cv_path, quality.cv_pdf_sha256)
    provisional = WorkableApplication(b"placeholder", answers, {"resume": upload})
    application_document = {
        "admission_receipt_sha256": admission.verification_receipt_sha256,
        "application_source_sha256": package.source.content_sha256,
        "application_url": policy.application_url,
        "cv_quality_receipt_sha256": quality.receipt_sha256,
        "cv_sha256": quality.cv_pdf_sha256,
        "form_answers_sha256": provisional.answers_sha256,
        "handoff_root_sha256": admission.handoff_root_sha256,
        "job_key": admission.job_key,
        "schema_version": "jaa.workable-application-package.v1",
        "vacancy_sha256": package.source.vacancy_sha256,
    }
    application = WorkableApplication(
        (workable_module._canonical_json(application_document) + "\n").encode(),
        answers,
        {"resume": upload},
    )
    monkeypatch.setattr(
        workable_module,
        "_source_identity",
        lambda _root: ("a" * 40, (("career_automation/workable_live_adapter.py", "b" * 64),)),
    )
    circuit = WorkableOneUseCircuit(tmp_path / "workable.sqlite3")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install(page, policy)
        adapter = WorkableLiveAdapter(circuit, Path("/synthetic"))
        review = adapter.prepare_review(page, policy=policy, application=application)
        assert review.consequential_click_authority is False
        receipt = adapter.submit(
            page, policy=policy, application=application, review=review, authority=authority
        )
        assert page.evaluate("window.submitClicks") == 1
        browser.close()

    assert gate.calls == 1
    assert circuit.snapshot()["state"] == "succeeded"
    transitions = tuple(row["to_state"] for row in circuit.journal())
    assert transitions == (
        "prepared", "release_consumption_started", "release_consumed",
        "click_started", "succeeded",
    )
    assert receipt.document["release_manifest_sha256"] == manifest.release_manifest_sha256
    assert application.package_document()["handoff_root_sha256"] == admission.handoff_root_sha256
    assert application.package_document()["cv_quality_receipt_sha256"] == quality.receipt_sha256


def test_poppler_rejects_tampered_retained_cv(tmp_path: Path) -> None:
    path = tmp_path / "tampered.pdf"
    path.write_bytes(b"%PDF-1.4\nnot the approved bytes")
    with pytest.raises(CVConstraintError, match="approved hash"):
        verify_poppler_cv_quality(
            path,
            expected_pdf_sha256=_sha(b"approved PDF"),
            expected_page_count=1,
            required_text_markers=("Candidate",),
            poppler_bin_dir=POPPLER_BIN,
            poppler_library_dir=POPPLER_LIB,
        )


def test_workable_policy_rejects_derived_or_tampered_market_job_key() -> None:
    with pytest.raises(ValueError, match="job identity"):
        replace(
            WorkablePolicy(
                "synthetic", "ABC123", "job_opaque", (WorkableField("name", "text", True, "Name"),)
            ),
            job_key="",
        )


def test_tampered_handoff_and_release_token_are_rejected(tmp_path: Path) -> None:
    _, _, handoff_bytes, _ = _admit(tmp_path)
    changed = bytearray(handoff_bytes)
    changed[changed.index(b"Synthetic Systems Limited")] ^= 1
    with pytest.raises(HandoffContractError):
        parse_handoff(bytes(changed))

    manifest = SimpleNamespace(release_manifest_sha256=_sha(b"manifest"))
    expected = f"jaa08.{manifest.release_manifest_sha256}.expected-token"
    gate = _ManifestGate(manifest, expected, _sha(b"quality"))
    with pytest.raises(ValueError, match="invalid or already consumed"):
        gate.consume_release_token(
            release_token=f"jaa08.{manifest.release_manifest_sha256}.tampered-token"
        )
