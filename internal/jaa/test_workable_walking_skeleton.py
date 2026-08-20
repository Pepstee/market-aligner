"""One synthetic receipt chain across Market Aligner, CV, JAA-08 and Workable."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

import career_automation.application_compiler as compiler_module
import career_automation.workable_live_adapter as workable_module
import test_jaa06_independent_acceptance as jaa06_module
import test_jaa08_independent_acceptance as jaa08_module
from career_automation.application_compiler import (
    DocumentSection,
    FactAuthority,
    compile_application_source,
)
from career_automation.application_strategy import ApplicationStrategyStore
from career_automation.ashby_live_adapter import JAA08ReleaseAuthority
from career_automation.candidate_graph import CandidateGraph
from career_automation.current_time import configured_hmac_current_time_witness
from career_automation.handoff_admission import HandoffAdmissionStore, ResolvedReference
from career_automation.market_aligner_handoff import (
    HandoffContractError,
    canonical_json_bytes,
    canonical_sha256,
    parse_handoff,
)
from career_automation.release_gate import (
    ApplicationCompilationStore,
    OfficialRouteBinding,
)
from career_automation.workable_live_adapter import (
    WorkableApplication,
    WorkableField,
    WorkableLiveAdapter,
    WorkableOneUseCircuit,
    WorkablePolicy,
    WorkableUpload,
)
from cv_generation.constraints import (
    CVConstraintError,
    validate_generated_cv,
    verify_poppler_cv_quality,
)
from test_jaa08_independent_acceptance import (
    DIGEST,
    ROOT,
    _compilation_inputs,
    _release_gate,
)
from test_workable_live_adapter import _install


POPPLER_ROOT = Path("/home/gutua/software-factory/.control/poppler-26.01.0/root")
POPPLER_BIN = POPPLER_ROOT / "usr/bin"
POPPLER_LIB = POPPLER_ROOT / "usr/lib/x86_64-linux-gnu"
ADMISSION_TIME = datetime(2026, 8, 10, 10, 5, tzinfo=timezone.utc)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _market_vacancy_references(
    job_key: str,
    company_name: str,
    role_title: str,
) -> dict[str, bytes]:
    fixture = json.loads(
        files("career_automation").joinpath(
            "fixtures/market-aligner-v1-vectors.json"
        ).read_bytes()
    )
    original = {
        entry["metadata"]["reference_key"]: json.loads(
            base64.b64decode(entry["object_base64"], validate=True)
        )
        for entry in fixture["reference_bundle"]["value"]["entries"]
        if entry["metadata"]["reference_key"].startswith("vacancy.")
    }
    location = original["vacancy.location.facts"]
    location["job_key"] = job_key
    raw_listing = original["vacancy.raw_listing"]
    raw_listing.update(
        adapter="jaa06-synthetic",
        canonical_url="https://jobs.example.test/strategy-job",
        job_key=job_key,
        source_job_id="strategy-job",
    )
    requirements = original["vacancy.requirements"]
    requirements["job_key"] = job_key
    result = {
        "vacancy.location.facts": canonical_json_bytes(location),
        "vacancy.raw_listing": canonical_json_bytes(raw_listing),
        "vacancy.requirements": canonical_json_bytes(requirements),
    }
    snapshot = original["vacancy.snapshot"]
    snapshot.update(
        company_name=company_name,
        job_key=job_key,
        location_facts_sha256=_sha(result["vacancy.location.facts"]),
        raw_listing_sha256=_sha(result["vacancy.raw_listing"]),
        requirements_sha256=_sha(result["vacancy.requirements"]),
        role_title=role_title,
    )
    result["vacancy.snapshot"] = canonical_json_bytes(snapshot)
    return result


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


def _handoff_for_source(
    source,
    vacancy_snapshot_bytes: bytes,
) -> tuple[dict[str, object], bytes]:
    fixture_bytes = files("career_automation").joinpath(
        "fixtures/market-aligner-v1-vectors.json"
    ).read_bytes()
    document = json.loads(fixture_bytes)
    envelope = json.loads(
        base64.b64decode(document["handoff"]["canonical_base64"], validate=True)
    )
    payload = envelope["payload"]
    payload["job_key"] = source.job_key
    references = _market_vacancy_references(
        source.job_key,
        source.company_name,
        source.role_title,
    )
    assert _sha(vacancy_snapshot_bytes) == source.vacancy_sha256
    references["vacancy.snapshot"] = vacancy_snapshot_bytes
    payload["vacancy"].update(
        company_name=source.company_name,
        raw_listing_sha256=_sha(references["vacancy.raw_listing"]),
        requirements_sha256=_sha(references["vacancy.requirements"]),
        role_title=source.role_title,
        vacancy_snapshot_sha256=source.vacancy_sha256,
    )
    payload["vacancy"]["location"]["facts_sha256"] = _sha(
        references["vacancy.location.facts"]
    )
    payload["vacancy"]["provenance"].update(
        adapter="jaa06-synthetic",
        canonical_url="https://jobs.example.test/strategy-job",
        source_job_id="strategy-job",
    )
    expected_job_key = "job_" + canonical_sha256(
        {
            "adapter": "jaa06-synthetic",
            "canonical_url": "https://jobs.example.test/strategy-job",
            "source_job_id": "strategy-job",
        }
    )
    assert source.job_key == expected_job_key
    for entry in document["reference_bundle"]["value"]["entries"]:
        reference_key = entry["metadata"]["reference_key"]
        if reference_key in references:
            exact_bytes = references[reference_key]
            entry["object_base64"] = base64.b64encode(exact_bytes).decode()
            entry["metadata"]["object_sha256"] = _sha(exact_bytes)
        subject = entry["metadata"]["subject"]
        if "job_key" in subject:
            subject["job_key"] = source.job_key
        if "vacancy_snapshot_sha256" in subject:
            subject["vacancy_snapshot_sha256"] = source.vacancy_sha256
    envelope["payload_sha256"] = canonical_sha256(payload)
    handoff_bytes = canonical_json_bytes(envelope)
    return document, handoff_bytes


def _admit(
    tmp_path: Path,
    *,
    document: dict[str, object] | None = None,
    handoff_bytes: bytes | None = None,
):
    fixture_bytes = files("career_automation").joinpath(
        "fixtures/market-aligner-v1-vectors.json"
    ).read_bytes()
    if document is None:
        document = json.loads(fixture_bytes)
    if handoff_bytes is None:
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


def test_authenticated_market_to_one_use_workable_receipt_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_scored_job = jaa06_module.scored_job_from_payload

    def market_aligner_scored_job(payload: dict[str, object]):
        job = original_scored_job(payload)
        market_job_key = "job_" + canonical_sha256(
            {
                "adapter": payload["board"],
                "canonical_url": payload["url"],
                "source_job_id": payload["job_id"],
            }
        )
        return replace(job, key=market_job_key)

    monkeypatch.setattr(
        jaa06_module,
        "scored_job_from_payload",
        market_aligner_scored_job,
    )
    original_fit_database = jaa08_module._fit_database

    def complete_cv_fit_database(path: Path, *, matched: bool):
        return original_fit_database(
            path,
            matched=matched,
            claims=(
                (
                    "summary-delivery",
                    "Deliver reliable product engineering.",
                    "achievement",
                ),
                (
                    "automation-capability",
                    "Design controlled automation systems.",
                    "capability",
                ),
                (
                    "verified-project",
                    "Build deterministic software projects.",
                    "project",
                ),
                (
                    "education-foundation",
                    "Apply software engineering education.",
                    "education",
                ),
            ),
        )

    monkeypatch.setattr(jaa08_module, "_fit_database", complete_cv_fit_database)
    original_add_claim = CandidateGraph.add_claim
    claim_text = {
        "achievement": (
            "Built and tested a deterministic automation service with "
            "content-addressed release receipts."
        ),
        "capability": (
            "Designed evidence-bound workflow automation with deterministic "
            "validation and recovery controls."
        ),
        "project": (
            "Delivered a resumable software project with automated tests and "
            "auditable state transitions."
        ),
        "education": (
            "Completed applied software engineering study focused on reliable "
            "systems design."
        ),
    }

    def add_realistic_claim(
        self,
        claim_id: str,
        *,
        statement: str,
        claim_type: str,
        **kwargs: object,
    ) -> None:
        original_add_claim(
            self,
            claim_id,
            statement=claim_text[claim_type],
            claim_type=claim_type,
            **kwargs,
        )

    monkeypatch.setattr(CandidateGraph, "add_claim", add_realistic_claim)
    original_compile = compiler_module.ProductionApplicationCompiler.compile

    def compile_complete_cv(self, strategy_id: str, **kwargs: object):
        source = original_compile(self, strategy_id, **kwargs)
        strategy = ApplicationStrategyStore(self.path).load(
            strategy_id,
            as_of=kwargs["as_of"],
        )
        with self._connect() as connection:
            claim_types = {
                str(row["claim_id"]): str(row["claim_type"])
                for row in connection.execute(
                    "SELECT claim_id,claim_type FROM candidate_claims"
                ).fetchall()
            }
        cv_facts = tuple(row for row in source.facts if row.document_kind == "cv")
        typed = {
            row.sentence_id: claim_types[row.authority.candidate_claim_id]
            for row in cv_facts
            if isinstance(row.authority, FactAuthority)
        }
        summary = next(
            row for row in cv_facts if typed[row.sentence_id] == "achievement"
        )
        capabilities = tuple(
            row.sentence_id
            for row in cv_facts
            if typed[row.sentence_id] == "capability"
        )
        projects = tuple(
            row.sentence_id
            for row in cv_facts
            if typed[row.sentence_id] in {"achievement", "project"}
        )
        education = tuple(
            row.sentence_id
            for row in cv_facts
            if typed[row.sentence_id] == "education"
        )
        return compile_application_source(
            strategy=strategy,
            job_key=source.job_key,
            role_title=source.role_title,
            company_name=source.company_name,
            vacancy_source_identity=source.vacancy_source_identity,
            vacancy_sha256=source.vacancy_sha256,
            contact=source.contact,
            facts=source.facts,
            style_slots=source.style_slots,
            cv_sections=(
                DocumentSection(
                    "Professional Summary",
                    (summary.sentence_id,),
                    source.cv_sections[0].style_slot_ids,
                ),
                DocumentSection("Core Capabilities", capabilities),
                DocumentSection("Projects", projects),
                DocumentSection("Education", education),
            ),
            letter_sections=source.letter_sections,
            answers=source.answers,
        )

    monkeypatch.setattr(
        compiler_module.ProductionApplicationCompiler,
        "compile",
        compile_complete_cv,
    )
    (
        database,
        strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _,
    ) = _compilation_inputs(tmp_path)
    policy = WorkablePolicy(
        tenant="synthetic",
        vacancy_id="ABC123",
        job_key=source.job_key,
        fields=(
            WorkableField("full_name", "text", True, "Full name"),
            WorkableField("email", "email", True, "Email"),
            WorkableField("resume", "file", True, "Resume"),
            WorkableField("terms", "checkbox", True, "I confirm"),
        ),
    )
    with database.connection() as connection:
        vacancy_snapshot_bytes = str(
            connection.execute(
                "SELECT payload_json FROM pipeline_jobs WHERE job_key=?",
                (source.job_key,),
            ).fetchone()[0]
        ).encode()
    handoff_document, handoff_bytes = _handoff_for_source(
        source,
        vacancy_snapshot_bytes,
    )
    admission, parsed, _, _ = _admit(
        tmp_path,
        document=handoff_document,
        handoff_bytes=handoff_bytes,
    )
    assert admission.job_key == source.job_key == policy.job_key
    assert parsed.payload["vacancy"]["vacancy_snapshot_sha256"] == source.vacancy_sha256

    cv_facts = {row.sentence_id: row.text for row in source.facts}
    constraint = validate_generated_cv(
        source_id=source.source_id,
        candidate_name=contact.full_name,
        candidate_city=contact.city,
        cv_text=artifacts.editable.cv_text,
        cv_sha256=artifacts.editable.cv_sha256,
        sections={
            section.heading: tuple(cv_facts[value] for value in section.sentence_ids)
            for section in source.cv_sections
        },
        rendered_pages=artifacts.cv_pdf.rendered_lines,
    )
    assert tuple(section.heading for section in source.cv_sections) == (
        "Professional Summary",
        "Core Capabilities",
        "Projects",
        "Education",
    )
    cv_path = tmp_path / "approved-cv.pdf"
    cv_path.write_bytes(artifacts.cv_pdf.pdf_bytes)
    quality = verify_poppler_cv_quality(
        cv_path,
        expected_pdf_sha256=artifacts.cv_pdf.pdf_sha256,
        expected_page_count=artifacts.cv_pdf.page_count,
        required_text_markers=(contact.full_name, "Professional Summary"),
        poppler_bin_dir=POPPLER_BIN,
        poppler_library_dir=POPPLER_LIB,
    )
    assert quality.release_authority is False
    assert quality.cv_pdf_sha256 == artifacts.cv_pdf.pdf_sha256
    assert constraint.cv_sha256 == artifacts.editable.cv_sha256

    today = strategy.as_of
    graph = CandidateGraph(database.path)
    graph.add_record(
        "work-right-gb",
        kind="work_right",
        subject="permission",
        value={"permitted": True},
        state="fact",
        source_identity="test:operator-work-right",
        jurisdiction="GB",
        contract_type="employee",
        valid_from=today.replace(year=today.year - 1).isoformat(),
        valid_until=today.replace(year=today.year + 1).isoformat(),
    )
    graph.verify_record(
        "work-right-gb",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="test.work-right",
        policy_version="1",
        policy_hash=DIGEST,
        reason="operator-verified work-right authority",
        source_identity="test:work-right-verifier",
    )
    compilation = ApplicationCompilationStore(database.path).register(
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        as_of=today,
    )
    gate = _release_gate(database)
    gate.register_official_route(
        job_key=source.job_key,
        route=OfficialRouteBinding(
            "route:workable-synthetic",
            "workable",
            policy.version,
            policy.application_url,
            policy.policy_sha256,
            today,
            today.replace(year=today.year + 1),
            True,
        ),
    )
    def issue_after_cv_constraint(receipt):
        if (
            receipt is None
            or receipt.source_id != source.source_id
            or receipt.cv_sha256 != artifacts.editable.cv_sha256
            or receipt.passed is not True
            or receipt.release_authority is not False
        ):
            raise ValueError("exact CV constraint receipt is required before release")
        return gate.evaluate_and_issue(
            compilation_id=compilation.compilation_id,
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            jurisdiction="GB",
            contract_type="employee",
            evaluated_at=today,
        )

    with pytest.raises(ValueError, match="constraint receipt"):
        issue_after_cv_constraint(None)
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM release_tokens").fetchone()[0] == 0
    issued = issue_after_cv_constraint(constraint)
    consumed_at = datetime(today.year, today.month, today.day, 12, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="release token"):
        gate.consume_release_token(
            release_token=issued.release_token + "tampered",
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            jurisdiction="GB",
            contract_type="employee",
            consumed_at=consumed_at,
        )

    authority = JAA08ReleaseAuthority(
        gate=gate, release_token=issued.release_token, source=source,
        artifacts=artifacts, contact=contact, questions=questions,
        artifact_root=artifact_root, repository_root=ROOT,
        jurisdiction="GB", contract_type="employee",
        consumed_at=consumed_at,
    )
    answers = {
        "full_name": contact.full_name,
        "email": contact.email,
        "terms": True,
    }
    upload = WorkableUpload(cv_path, quality.cv_pdf_sha256)
    provisional = WorkableApplication(b"placeholder", answers, {"resume": upload})
    application_document = {
        "admission_receipt_sha256": admission.verification_receipt_sha256,
        "application_source_sha256": source.content_sha256,
        "application_url": policy.application_url,
        "cv_constraint_receipt_sha256": constraint.receipt_sha256,
        "cv_quality_receipt_sha256": quality.receipt_sha256,
        "cv_sha256": quality.cv_pdf_sha256,
        "form_answers_sha256": provisional.answers_sha256,
        "handoff_root_sha256": admission.handoff_root_sha256,
        "job_key": source.job_key,
        "schema_version": "jaa.workable-application-package.v1",
        "vacancy_sha256": source.vacancy_sha256,
    }
    application = WorkableApplication(
        (workable_module._canonical_json(application_document) + "\n").encode(),
        answers,
        {"resume": upload},
    )
    circuit = WorkableOneUseCircuit(tmp_path / "workable.sqlite3")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        _install(page, policy)
        adapter = WorkableLiveAdapter(circuit, ROOT)
        review = adapter.prepare_review(page, policy=policy, application=application)
        assert review.consequential_click_authority is False
        receipt = adapter.submit(
            page, policy=policy, application=application, review=review, authority=authority
        )
        assert page.evaluate("window.submitClicks") == 1
        browser.close()

    assert circuit.snapshot()["state"] == "succeeded"
    transitions = tuple(row["to_state"] for row in circuit.journal())
    assert transitions == (
        "prepared", "release_consumption_started", "release_consumed",
        "click_started", "succeeded",
    )
    assert receipt.document["release_manifest_sha256"] == issued.manifest.release_manifest_sha256
    consumed = gate.verify_consumed_release_token(
        release_token=issued.release_token,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=consumed_at,
    )
    assert consumed.release_manifest_sha256 == issued.manifest.release_manifest_sha256
    with pytest.raises(ValueError, match="already consumed"):
        gate.consume_release_token(
            release_token=issued.release_token,
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            jurisdiction="GB",
            contract_type="employee",
            consumed_at=consumed_at,
        )
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


def test_tampered_handoff_is_rejected(tmp_path: Path) -> None:
    _, _, handoff_bytes, _ = _admit(tmp_path)
    changed = bytearray(handoff_bytes)
    changed[changed.index(b"Synthetic Systems Limited")] ^= 1
    with pytest.raises(HandoffContractError):
        parse_handoff(bytes(changed))
