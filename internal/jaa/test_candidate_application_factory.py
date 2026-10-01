from __future__ import annotations

import json
import hashlib
import pickle
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation import application_compiler as application_compiler_module
from career_automation.application_compiler import CandidateContact, FactAuthority
from career_automation.application_compiler import verify_application_source
from career_automation.rendering import _letter_paragraphs, render_pdf_artifacts
from career_automation.candidate_application_factory import (
    _approved_statements,
    _evidence_document_targets,
    _fact_binding,
    _build_candidate_application_source,
    _load_approved_statements,
    _projection_evidence_sha256,
    _profile_cv_section_for_evidence,
    _select_profile_capability_fact,
    build_market_application_decision_authority,
    build_candidate_application_deployment_binding,
    build_candidate_application_package,
    materialize_candidate_application_source,
)
from career_automation.evidence_matching import canonical_json
from career_automation.candidate_contact_authority import CandidateContactAuthority
from career_automation.candidate_authority import APPROVED_EVIDENCE_PATH
from career_automation.candidate_authority import APPROVED_CANDIDATE_SOURCE_HASHES
from career_automation.production_attempt import _approved_fact_authorities
from career_automation.release_gate import cv_constraint_release_binding
from career_automation import market_aligner_preparation
from career_automation.handoff_admission import HandoffAdmissionError
from cv_generation.constraints import capability_line_eligible
from cv_generation.editorial_composition import (
    ApprovedCVClaim,
    CandidateEditorialAuthority,
    build_editorial_request,
)


PRIVATE_AUTHORITY_ROOT = (
    Path(__file__).resolve().parents[2]
    / ".market-aligner-data"
    / "authority-inputs"
)
AUTHORITY_PATH = PRIVATE_AUTHORITY_ROOT / "candidate-authorities" / (
    "85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9.json"
)
DISCOVERY_PATH = PRIVATE_AUTHORITY_ROOT / "objects" / "39" / (
    "39e60f8d278d8a07427c8bc25eff85bd357e98451cce87983d70d3d85e935f47"
)

PRIVATE_FIXTURE_REASON = (
    "requires the exact private Gigabyte candidate-authority and discovery "
    "artifacts; synthetic substitution would not test the certified binding"
)


def require_private_candidate_fixture() -> None:
    if not AUTHORITY_PATH.is_file() or not DISCOVERY_PATH.is_file():
        pytest.skip(PRIVATE_FIXTURE_REASON)


def _inputs() -> dict[str, object]:
    require_private_candidate_fixture()
    authority = json.loads(AUTHORITY_PATH.read_bytes())
    discovery = json.loads(DISCOVERY_PATH.read_bytes())
    decision = next(
        row["receipt"]
        for row in authority["decisions"]
        if row["receipt"]["decision"] == "eligible"
    )
    vacancy = next(
        row
        for row in discovery["live_pending_eligibility"]
        if row["job_key"] == decision["job_key"]
    )
    return {
        "decision_receipt": decision,
        "candidate_projection": authority["candidate_projection"],
        "job_key": vacancy["job_key"],
        "vacancy_sha256": vacancy["vacancy_sha256"],
        "source_url": vacancy["source_url"],
        "role_title": vacancy["role_title"],
        "company_name": vacancy["company_name"],
        "contact": CandidateContact(
            full_name="Alex Example",
            email="alex@example.test",
            phone="+44 7700 900123",
            city="London",
            record_id="operator-contact-primary",
            record_version=1,
            provenance_sha256="a" * 64,
        ),
    }


def _materialization_inputs(tmp_path: Path) -> dict[str, object]:
    values = _inputs()
    contact_path = tmp_path / "signed-contact.json"
    contact_path.write_bytes(b'{"fixture":"signed-contact-envelope"}\n')
    contact_path.chmod(0o600)
    contact_object_sha256 = hashlib.sha256(contact_path.read_bytes()).hexdigest()
    contact = CandidateContactAuthority(
        contact=values["contact"],
        issued_at="2026-08-21T00:00:00+00:00",
        authority_sha256=values["contact"].provenance_sha256,
        envelope_sha256=contact_object_sha256,
        registry_sha256="d" * 64,
        signer_public_key_sha256="e" * 64,
        source_path=contact_path,
    )
    binding = build_candidate_application_deployment_binding(
        application_id="app_" + "1" * 64,
        environment="synthetic",
        handoff_root_sha256="2" * 64,
        admission_receipt_sha256="3" * 64,
        current_boundary_receipt_sha256="4" * 64,
        candidate_authority_file_sha256=AUTHORITY_PATH.stem,
    )
    return {**values, "deployment_binding": binding, "contact_authority": contact}


def _integrated_decision(
    tmp_path: Path, *, ledger_count: int = 7, ledger_confidence: object = 1.0
):
    inputs = _materialization_inputs(tmp_path)
    source_job_key = "workable:cogna:847CFBC5F4"
    requirements = {
        "preferred_qualifications": ["Hands-on experimentation with emerging AI tools and models"],
        "preferred_skills": ["Modern frontend development"],
        "required_qualifications": ["Professional or personal experience working with LLM APIs"],
        "required_skills": ["Python"],
        "responsibilities": ["Design and build reusable application architectures and toolchains"],
    }
    raw_listing_bytes = b'{"fixture":"exact Workable listing"}'
    requirements_bytes = canonical_json(requirements).encode()
    assessment = {
        "decision": "pass",
        "job_key": source_job_key,
        "receipt_sha256": "5" * 64,
        "schema_version": "market-aligner.assessment-promotion-receipt.v1",
    }
    eligibility = {
        "checks": [],
        "decision": "eligible",
        "hard_gate_passed": True,
        "promotion_receipt_sha256": "5" * 64,
        "source_job_key": source_job_key,
    }
    selection = {
        "decision": "selected_for_application",
        "hard_gate_passed": True,
        "promotion_receipt_sha256": "5" * 64,
        "source_job_key": source_job_key,
    }
    encoded = [canonical_json(value).encode() for value in (assessment, eligibility, selection)]
    projection = json.loads(AUTHORITY_PATH.read_bytes())["candidate_projection"]
    all_approved = json.loads(APPROVED_EVIDENCE_PATH.read_bytes())["statements"]
    live_ids = {"E-001", "E-002", "E-008", "E-011", "E-012", "E-017", "E-018"}
    approved = [row for row in all_approved if row["id"] in live_ids][:ledger_count]
    ledger_bytes = b"".join(
        (canonical_json({
            "claim": row["statement"],
            "content_sha256": hashlib.sha256(row["statement"].encode()).hexdigest(),
            "confidence": ledger_confidence,
            "evidence_id": row["id"],
            "kind": row["kind"],
            "observed_at": None,
            "source_ref": f"authority://approved-evidence/{row['id']}",
            "status": "explicit",
        }) + "\n").encode()
        for row in approved
    )
    authority = build_market_application_decision_authority(
        deployment_binding=inputs["deployment_binding"],
        source_job_key=source_job_key,
        internal_job_key="job_" + "6" * 64,
        vacancy_snapshot_sha256="7" * 64,
        raw_listing_sha256=hashlib.sha256(raw_listing_bytes).hexdigest(),
        raw_listing_bytes=raw_listing_bytes,
        requirements_sha256=hashlib.sha256(requirements_bytes).hexdigest(),
        requirements_bytes=requirements_bytes,
        assessment_receipt_sha256=hashlib.sha256(encoded[0]).hexdigest(),
        assessment_receipt_bytes=encoded[0],
        eligibility_receipt_sha256=hashlib.sha256(encoded[1]).hexdigest(),
        eligibility_receipt_bytes=encoded[1],
        selection_receipt_sha256=hashlib.sha256(encoded[2]).hexdigest(),
        selection_receipt_bytes=encoded[2],
        candidate_projection=projection,
        candidate_authority_bytes=AUTHORITY_PATH.read_bytes(),
        evidence_ledger_sha256=hashlib.sha256(ledger_bytes).hexdigest(),
        evidence_ledger_bytes=ledger_bytes,
        source_url="https://apply.workable.com/j/847CFBC5F4",
        role_title="Software Engineer",
        company_name="Cogna",
        observed_at="2026-08-20T19:46:02+00:00",
    )
    return authority, inputs, projection


def test_integrated_market_decision_keeps_candidate_authority_vacancy_independent(
    tmp_path: Path,
) -> None:
    authority, inputs, projection = _integrated_decision(tmp_path)
    assert authority.vacancy_snapshot_sha256 != authority.raw_listing_sha256
    assert authority.evidence_matrix
    decision = authority.decision_receipt()
    materialized = materialize_candidate_application_source(
        candidate_authority_path=AUTHORITY_PATH,
        deployment_binding=inputs["deployment_binding"],
        contact_authority=inputs["contact_authority"],
        decision_receipt=decision,
        candidate_projection=projection,
        job_key=authority.source_job_key,
        vacancy_sha256=authority.raw_listing_sha256,
        source_url=authority.source_url,
        role_title=authority.role_title,
        company_name=authority.company_name,
        contact=inputs["contact"],
        market_decision_authority=authority,
    )
    assert materialized.source.vacancy_sha256 == authority.raw_listing_sha256
    assert materialized.receipt.vacancy_snapshot_sha256 == authority.vacancy_snapshot_sha256
    assert materialized.receipt.decision_authority_sha256 == authority.authority_sha256
    assert all(
        row["receipt"].get("job_key") != authority.source_job_key
        for row in json.loads(AUTHORITY_PATH.read_bytes())["decisions"]
    )


def test_integrated_market_decision_accepts_sealed_ledger_cardinality(
    tmp_path: Path,
) -> None:
    authority, _, _ = _integrated_decision(tmp_path, ledger_count=3)
    assert authority.evidence_ledger_sha256


def test_integrated_market_decision_rejects_boolean_ledger_confidence(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="evidence ledger"):
        _integrated_decision(tmp_path, ledger_confidence=True)


def test_integrated_market_decision_rejects_receipt_and_snapshot_substitution(
    tmp_path: Path,
) -> None:
    authority, inputs, projection = _integrated_decision(tmp_path)
    with pytest.raises(ValueError, match="raw listing bytes differ"):
        build_market_application_decision_authority(
            deployment_binding=inputs["deployment_binding"],
            source_job_key=authority.source_job_key,
            internal_job_key=authority.internal_job_key,
            vacancy_snapshot_sha256=authority.vacancy_snapshot_sha256,
            raw_listing_sha256=authority.raw_listing_sha256,
            raw_listing_bytes=b"substituted",
            requirements_sha256=authority.requirements_sha256,
            requirements_bytes=canonical_json({}).encode(),
            assessment_receipt_sha256=authority.assessment_receipt_sha256,
            assessment_receipt_bytes=b"{}",
            eligibility_receipt_sha256=authority.eligibility_receipt_sha256,
            eligibility_receipt_bytes=b"{}",
            selection_receipt_sha256=authority.selection_receipt_sha256,
            selection_receipt_bytes=b"{}",
            candidate_projection=projection,
            candidate_authority_bytes=AUTHORITY_PATH.read_bytes(),
            evidence_ledger_sha256=authority.evidence_ledger_sha256,
            evidence_ledger_bytes=b"substituted",
            source_url=authority.source_url,
            role_title=authority.role_title,
            company_name=authority.company_name,
            observed_at=authority.observed_at,
        )
    with pytest.raises(ValueError, match="identity"):
        materialize_candidate_application_source(
            candidate_authority_path=AUTHORITY_PATH,
            deployment_binding=inputs["deployment_binding"],
            contact_authority=inputs["contact_authority"],
            decision_receipt=authority.decision_receipt(),
            candidate_projection=projection,
            job_key=authority.source_job_key,
            vacancy_sha256=authority.raw_listing_sha256,
            source_url=authority.source_url,
            role_title=authority.role_title,
            company_name=authority.company_name,
            contact=inputs["contact"],
            market_decision_authority=replace(
                authority,
                vacancy_snapshot_sha256="8" * 64,
                authority_sha256=authority.authority_sha256,
            ),
        )
    with pytest.raises(ValueError, match="matrix policy"):
        replace(authority, matrix_policy_sha256="9" * 64)
    with pytest.raises(ValueError, match="identity"):
        replace(authority, approved_evidence_file_sha256="a" * 64)
    with pytest.raises(ValueError, match="identity"):
        replace(authority, evidence_ledger_sha256="b" * 64)
    with pytest.raises(ValueError, match="identity"):
        replace(authority, candidate_authority_file_sha256="c" * 64)


def test_builds_plain_vacancy_bound_documents_from_approved_atoms() -> None:
    package = build_candidate_application_package(**_inputs())
    assert package.source.vacancy_sha256 == _inputs()["vacancy_sha256"]
    assert package.artifacts.cv_pdf.page_count == 1
    assert package.artifacts.cover_letter_pdf.page_count == 1
    assert package.artifacts.editable.answers_text == ""
    assert package.vacancy_requirements
    rewritten = [
        fact
        for fact in package.source.facts
        if fact.text != fact.approved_source_text
    ]
    assert rewritten
    assert all(
        fact.authority.outward_text_sha256
        == hashlib.sha256(fact.text.encode()).hexdigest()
        and fact.authority.rewrite_policy_sha256
        for fact in rewritten
    )
    assert tuple(section.heading for section in package.source.cv_sections) == (
        "Professional Summary",
        "Core Capabilities",
        "Projects",
        "Education",
    )
    cv_facts = [fact for fact in package.source.facts if fact.document_kind == "cv"]
    assert len(cv_facts) >= 8
    assert len(" ".join(fact.text for fact in cv_facts).split()) >= 110
    assert len({fact.text.casefold() for fact in cv_facts}) == len(cv_facts)
    cv = package.artifacts.editable.cv_text
    assert package.source.role_title not in cv
    assert "Pepstee" in cv
    assert "709 passing automated tests" in cv
    assert "GCSE" not in cv
    assert "British Chamber" not in cv
    assert package.artifacts.editable.cover_letter_text.rstrip().endswith(
        package.source.contact.full_name
    )
    for internal_heading in (
        "Opening",
        "Evidence Match",
        "Company Fit",
        "Close",
    ):
        assert internal_heading not in package.artifacts.editable.cover_letter_text
        assert internal_heading not in package.artifacts.cover_letter_pdf.extracted_text
    employer_facts = [
        fact
        for fact in package.source.facts
        if fact.document_kind == "cover_letter" and fact.fact_kind == "employer"
    ]
    assert employer_facts
    assert all(package.source.company_name in fact.text for fact in employer_facts)
    opening = next(
        section
        for section in package.source.letter_sections
        if section.heading == "Opening"
    )
    opening_facts = [
        fact
        for fact in package.source.facts
        if fact.sentence_id in opening.sentence_ids
    ]
    opening_candidate = next(fact for fact in opening_facts if fact.fact_kind == "candidate")
    opening_employer = next(fact for fact in opening_facts if fact.fact_kind == "employer")
    assert isinstance(opening_candidate.authority, FactAuthority)
    assert isinstance(opening_employer.authority, FactAuthority)
    assert (
        opening_candidate.authority.requirement_id,
        opening_candidate.authority.candidate_claim_id,
        opening_candidate.authority.candidate_claim_version,
        opening_candidate.authority.candidate_evidence_id,
        opening_candidate.authority.candidate_evidence_version,
        opening_candidate.authority.employer_research_claim_id,
        opening_candidate.authority.employer_fact_sha256,
    ) == (
        opening_employer.authority.requirement_id,
        opening_employer.authority.candidate_claim_id,
        opening_employer.authority.candidate_claim_version,
        opening_employer.authority.candidate_evidence_id,
        opening_employer.authority.candidate_evidence_version,
        opening_employer.authority.employer_research_claim_id,
        opening_employer.authority.employer_fact_sha256,
    )
    assert len(" ".join(package.artifacts.editable.cover_letter_text.split()).split()) >= 90
    assert "The " + package.source.role_title + " position is at " + package.source.company_name + "." not in package.artifacts.editable.cover_letter_text
    assert "I am applying for this position" not in package.artifacts.editable.cover_letter_text
    assert (
        package.artifacts.editable.cover_letter_text.count(
            "I would welcome the opportunity"
        )
        == 1
    )
    assert any(
        phrase in package.artifacts.editable.cover_letter_text
        for phrase in (
            "specifically asks candidates to",
            "describes the work as",
            "calls for experience with",
            "lists this requirement",
        )
    )
    outward = (
        package.artifacts.editable.cv_text
        + package.artifacts.editable.cover_letter_text
    ).casefold()
    assert "audit" not in outward
    assert "governance" not in outward
    assert "evidence" not in outward
    assert "model provenance" not in outward
    assert "directed ai agents" not in outward
    assert "software factory" not in outward
    assert any(
        "directed AI agents" in fact.approved_source_text
        and "AI agents" not in fact.text
        for fact in rewritten
    )
    with pytest.raises(ValueError, match="exact outward authority"):
        replace(rewritten[0], text=f"{rewritten[0].text} Increased revenue by 40%.")


def test_zero_match_eligible_role_gets_truthful_profile_package_without_match_claims() -> None:
    arguments = _inputs()
    decision = json.loads(json.dumps(arguments["decision_receipt"]))
    for row in decision["evidence_matrix"]:
        row["status"] = "gap"
        row["evidence_ids"] = []
    decision["fit"] = "0.000000"
    arguments["decision_receipt"] = decision

    package = build_candidate_application_package(**arguments)
    letter = package.artifacts.editable.cover_letter_text
    assert arguments["company_name"] in letter
    assert arguments["role_title"] in letter
    assert (
        "describes the work as" in letter
        or "lists this requirement" in letter
        or "specifically asks candidates to" in letter
    )
    assert "requirements connect directly" not in letter
    assert letter.count("I would welcome") == 1
    assert len(package.vacancy_requirements) == len(decision["evidence_matrix"])
    assert package.artifacts.cv_pdf.page_count == 1
    assert package.artifacts.cover_letter_pdf.page_count == 1
    authority_kinds = {
        row["authority_kind"] for row in _approved_fact_authorities(package.source)
    }
    assert "candidate_profile" in authority_kinds
    assert "vacancy" in authority_kinds


def test_stable_profile_facts_are_bound_to_exact_candidate_projection() -> None:
    arguments = _inputs()
    projection = json.loads(json.dumps(arguments["candidate_projection"]))
    row = next(
        item for item in projection["approved_evidence"] if item["id"] == "E-001"
    )
    row["statement_sha256"] = hashlib.sha256(b"substituted").hexdigest()
    arguments["candidate_projection"] = projection
    decision = dict(arguments["decision_receipt"])
    decision["candidate_projection_sha256"] = projection["projection_sha256"]
    arguments["decision_receipt"] = decision
    with pytest.raises(ValueError, match="profile evidence differs"):
        build_candidate_application_package(**arguments)


def test_rejects_candidate_evidence_byte_substitution(tmp_path: Path) -> None:
    changed = tmp_path / "changed-evidence.json"
    changed.write_bytes(APPROVED_EVIDENCE_PATH.read_bytes() + b" ")
    with pytest.raises(ValueError, match="evidence hash differs"):
        build_candidate_application_package(**_inputs(), approved_evidence_path=changed)


def _synthetic_evidence_binding(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    statement = {
        "id": "SYNTHETIC-EVIDENCE-1",
        "kind": "verified_claim",
        "proof_class": "verified_claim",
        "statement": "Synthetic demonstration evidence.",
    }
    evidence = {"schema_version": "synthetic-evidence-test.v1", "statements": [statement]}
    evidence_bytes = (canonical_json(evidence) + "\n").encode("utf-8")
    path = tmp_path / "synthetic-approved-evidence.json"
    path.write_bytes(evidence_bytes)
    digest = hashlib.sha256(evidence_bytes).hexdigest()
    projection: dict[str, object] = {
        "schema_version": "jaa.candidate-authority-projection.v1",
        "source_hashes": {"approved_evidence": digest},
        "schema_sha256": hashlib.sha256(b"synthetic-schema").hexdigest(),
        "policy_sha256": hashlib.sha256(b"synthetic-policy").hexdigest(),
        "availability": {"status": "synthetic"},
        "approved_evidence": [
            {
                "id": statement["id"],
                "statement_sha256": hashlib.sha256(
                    statement["statement"].encode("utf-8")
                ).hexdigest(),
                "kind": statement["kind"],
                "proof_class": statement["proof_class"],
            }
        ],
        "claim_suppressors": {
            "source_sha256": hashlib.sha256(b"synthetic-suppressors").hexdigest(),
            "mode": "suppress_only",
            "items": [],
        },
    }
    projection["projection_sha256"] = hashlib.sha256(
        (canonical_json(projection) + "\n").encode("utf-8")
    ).hexdigest()
    return path, projection


def _synthetic_composition_inputs(
    tmp_path: Path,
    *,
    employment_index: int | None = None,
    additional_kind: str | None = None,
    matched_requirements: int = 2,
    duplicate_last_statement: bool = False,
    first_person_index: int | None = None,
) -> dict[str, object]:
    statements = [
        "Built a service dashboard that organised support requests by priority and showed unresolved work to operators.",
        "Implemented integration testing for incoming records, catching invalid dates early and reducing repeated manual corrections during review.",
        "Designed a searchable project catalogue with consistent metadata, making related examples easier to find and compare.",
        "Created a batch processing workflow that grouped large data sets and produced a concise, reproducible completion summary.",
        "Added accessible status indicators to a reporting page so users could distinguish queued, active, and completed tasks.",
        "Refined a deployment checklist with verified prerequisites, clear rollback steps, and a repeatable validation sequence.",
        "Developed a lightweight API adapter that normalised responses and preserved useful error details for downstream callers.",
        "Measured import performance before and after indexing, recording test conditions and explaining the observed improvement.",
    ]
    if duplicate_last_statement:
        statements[-1] = statements[0]
    if first_person_index is not None:
        statement = statements[first_person_index]
        statements[first_person_index] = f"I {statement[0].lower()}{statement[1:]}"
    evidence_rows: list[dict[str, str]] = []
    for index, text in enumerate(statements):
        kind = "portfolio_artifact"
        if index == employment_index:
            kind = "employment_record"
            text = (
                "Worked as a software engineer maintaining an internal records service, "
                "coordinating releases, and documenting dependable support practices."
            )
        elif index == 7 and additional_kind is not None:
            kind = additional_kind
            text = {
                "verified_claim": (
                    "Maintained a consistent release process with documented "
                    "acceptance checks and clear rollback decisions."
                ),
                "work_artifact": (
                    "Created a reusable project checklist with verified "
                    "prerequisites and clear completion steps."
                ),
                "test_result": (
                    "Recorded repeatable test results across representative "
                    "data batches and summarised the failures for review."
                ),
                "external_outcome": (
                    "Delivered a service update that reduced duplicate requests "
                    "and improved turnaround for partner teams."
                ),
                "credential": (
                    "Completed a course in software design, automated testing, "
                    "and data handling, with a practical assessment."
                ),
            }[additional_kind]
        evidence_rows.append(
            {
                "id": f"SYNTHETIC-PORTFOLIO-{index + 1:02d}",
                "kind": kind,
                "proof_class": kind,
                "statement": text,
            }
        )
    evidence_document = {
        "schema_version": "synthetic-evidence-test.v1",
        "statements": evidence_rows,
    }
    evidence_bytes = (canonical_json(evidence_document) + "\n").encode("utf-8")
    evidence_path = tmp_path / "synthetic-composition-evidence.json"
    evidence_path.write_bytes(evidence_bytes)
    statement_projection = [
        {
            "id": row["id"],
            "statement_sha256": hashlib.sha256(
                row["statement"].encode("utf-8")
            ).hexdigest(),
            "kind": row["kind"],
            "proof_class": row["proof_class"],
        }
        for row in evidence_rows
    ]
    candidate_projection: dict[str, object] = {
        "schema_version": "jaa.candidate-authority-projection.v1",
        "source_hashes": {
            "approved_evidence": hashlib.sha256(evidence_bytes).hexdigest(),
        },
        "schema_sha256": hashlib.sha256(b"synthetic-schema").hexdigest(),
        "policy_sha256": hashlib.sha256(b"synthetic-policy").hexdigest(),
        "availability": {"status": "synthetic"},
        "approved_evidence": statement_projection,
        "claim_suppressors": {
            "source_sha256": hashlib.sha256(b"synthetic-suppressors").hexdigest(),
            "mode": "suppress_only",
            "items": [],
        },
    }
    candidate_projection["projection_sha256"] = hashlib.sha256(
        (canonical_json(candidate_projection) + "\n").encode("utf-8")
    ).hexdigest()
    vacancy_description = b"Synthetic platform-engineering vacancy description."
    vacancy_description_sha256 = hashlib.sha256(vacancy_description).hexdigest()
    vacancy_sha256 = hashlib.sha256(b"synthetic vacancy payload").hexdigest()
    source_url = "https://boards.greenhouse.io/example/jobs/synthetic-001"
    job_key = "synthetic-job-001"
    requirements = (
        "Build reliable services for operational workflows.",
        "Maintain clear validation and reporting processes.",
    )
    evidence_matrix = [
        {
            "requirement_id": f"SYNTHETIC-REQUIREMENT-{index + 1:02d}",
            "requirement_text": text,
            "requirement_text_sha256": hashlib.sha256(
                text.encode("utf-8")
            ).hexdigest(),
            "status": "matched" if index < matched_requirements else "no_match",
            "evidence_ids": [evidence_rows[index]["id"]]
            if index < matched_requirements
            else [],
            "classification": "essential",
        }
        for index, text in enumerate(requirements)
    ]
    decision_receipt = {
        "decision": "eligible",
        "job_key": job_key,
        "role_title": "Platform Engineer",
        "company_name": "Example Systems",
        "vacancy_sha256": vacancy_sha256,
        "vacancy_description_sha256": vacancy_description_sha256,
        "source_url": source_url,
        "observed_at": "2026-10-01T07:45:00+00:00",
        "candidate_projection_sha256": candidate_projection["projection_sha256"],
        "evidence_matrix": evidence_matrix,
    }
    return {
        "decision_receipt": decision_receipt,
        "candidate_projection": candidate_projection,
        "job_key": job_key,
        "vacancy_sha256": vacancy_sha256,
        "source_url": source_url,
        "role_title": "Platform Engineer",
        "company_name": "Example Systems",
        "contact": CandidateContact(
            full_name="Synthetic Candidate",
            email="candidate@example.test",
            phone="+44 7700 900123",
            city="London",
            record_id="synthetic-contact",
            record_version=1,
            provenance_sha256="a" * 64,
        ),
        "approved_evidence_path": evidence_path,
    }


def _update_synthetic_document_targets(
    arguments: dict[str, object],
    targets_by_id: dict[str, list[str]],
    additional_rows: tuple[dict[str, object], ...] = (),
) -> None:
    evidence_path = arguments["approved_evidence_path"]
    evidence_document = json.loads(evidence_path.read_bytes())
    for row in evidence_document["statements"]:
        if row["id"] in targets_by_id:
            row["document_targets"] = targets_by_id[row["id"]]
    projection_rows = []
    for row in additional_rows:
        evidence_row = {
            "id": row["id"],
            "kind": "portfolio_artifact",
            "proof_class": "portfolio_artifact",
            "statement": row["statement"],
            "document_targets": row["document_targets"],
        }
        evidence_document["statements"].append(evidence_row)
        projection_rows.append(
            {
                "id": evidence_row["id"],
                "statement_sha256": hashlib.sha256(
                    evidence_row["statement"].encode("utf-8")
                ).hexdigest(),
                "kind": evidence_row["kind"],
                "proof_class": evidence_row["proof_class"],
            }
        )
    evidence_bytes = (canonical_json(evidence_document) + "\n").encode("utf-8")
    evidence_path.write_bytes(evidence_bytes)
    projection = json.loads(json.dumps(arguments["candidate_projection"]))
    projection["source_hashes"]["approved_evidence"] = hashlib.sha256(
        evidence_bytes
    ).hexdigest()
    projection["approved_evidence"].extend(projection_rows)
    projection.pop("projection_sha256")
    projection["projection_sha256"] = hashlib.sha256(
        (canonical_json(projection) + "\n").encode("utf-8")
    ).hexdigest()
    decision = dict(arguments["decision_receipt"])
    decision["candidate_projection_sha256"] = projection["projection_sha256"]
    arguments["candidate_projection"] = projection
    arguments["decision_receipt"] = decision


@pytest.mark.parametrize(
    ("employment_index", "expected_headings"),
    (
        (None, ("Professional Summary", "Core Capabilities", "Projects")),
        (7, ("Professional Summary", "Core Capabilities", "Projects", "Experience")),
    ),
)
def test_generation_composes_verified_nonlegacy_profile_by_evidence_kind(
    tmp_path: Path,
    employment_index: int | None,
    expected_headings: tuple[str, ...],
) -> None:
    arguments = _synthetic_composition_inputs(
        tmp_path,
        employment_index=employment_index,
    )

    built = _build_candidate_application_source(**arguments)
    source = built.source
    cv_rows = [
        row
        for section in source.cv_sections
        for sentence_id in section.sentence_ids
        for row in source.facts
        if row.sentence_id == sentence_id
    ]

    assert tuple(section.heading for section in source.cv_sections) == expected_headings
    assert len(cv_rows) == 8
    assert len(" ".join(row.text for row in cv_rows).split()) >= 110
    assert len({row.authority.candidate_evidence_id for row in cv_rows}) == 8
    assert all("SYNTHETIC-PORTFOLIO-" not in row.text for row in cv_rows)
    profile_bound = [
        row
        for row in cv_rows
        if hasattr(row.authority, "candidate_profile_hash")
    ]
    assert profile_bound
    assert all(
        row.authority.candidate_profile_hash
        == arguments["candidate_projection"]["projection_sha256"]
        for row in profile_bound
    )


def test_generic_package_relocates_verified_capability_fact_verbatim(
    tmp_path: Path,
) -> None:
    arguments = _synthetic_composition_inputs(tmp_path)
    evidence_document = json.loads(
        (tmp_path / "synthetic-composition-evidence.json").read_text()
    )
    package = build_candidate_application_package(**arguments)
    source = package.source
    capability_section = next(
        section
        for section in source.cv_sections
        if section.heading == "Core Capabilities"
    )
    assert len(capability_section.sentence_ids) == 1
    capability_fact = next(
        row
        for row in source.facts
        if row.sentence_id == capability_section.sentence_ids[0]
    )
    evidence = next(
        row
        for row in evidence_document["statements"]
        if row["id"] == capability_fact.authority.candidate_evidence_id
    )
    assert capability_line_eligible(evidence["statement"])
    assert capability_fact.text == evidence["statement"]
    assert capability_fact.approved_source_text == evidence["statement"]
    cv_sentence_ids = [
        sentence_id
        for section in source.cv_sections
        for sentence_id in section.sentence_ids
    ]
    assert len(cv_sentence_ids) == 8
    assert len(set(cv_sentence_ids)) == len(cv_sentence_ids)
    assert len({
        row.authority.candidate_evidence_id
        for row in source.facts
        if row.document_kind == "cv" and row.fact_kind == "candidate"
    }) == 8


def test_generic_first_person_rewrite_uses_verified_evidence_source_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _synthetic_composition_inputs(tmp_path, first_person_index=2)

    def reject_global_authority_lookup(_evidence_id: str) -> tuple[str, str]:
        raise AssertionError("generic rewrite attempted protected global lookup")

    monkeypatch.setattr(
        application_compiler_module,
        "_protected_approved_statement",
        reject_global_authority_lookup,
    )
    package = build_candidate_application_package(**arguments)
    fact = next(
        row
        for row in package.source.facts
        if row.authority.candidate_evidence_id == "SYNTHETIC-PORTFOLIO-03"
    )
    rewrite = fact.authority.rewrite_authority
    projected = next(
        row
        for row in arguments["candidate_projection"]["approved_evidence"]
        if row["id"] == "SYNTHETIC-PORTFOLIO-03"
    )

    assert fact.approved_source_text.startswith("I designed ")
    assert fact.text == (
        fact.approved_source_text[2].upper() + fact.approved_source_text[3:]
    )
    assert rewrite is not None
    assert rewrite.approved_evidence_source_sha256 == arguments[
        "candidate_projection"
    ]["source_hashes"]["approved_evidence"]
    assert rewrite.approved_source_text_sha256 == projected["statement_sha256"]
    assert rewrite.outward_text_sha256 == hashlib.sha256(
        fact.text.encode()
    ).hexdigest()
    verify_application_source(package.source)
    restored_package = pickle.loads(pickle.dumps(package))
    verify_application_source(restored_package.source)

    source_context = rewrite.source_context
    assert source_context is not None
    replay_receipt = replace(rewrite, source_context=None)
    application_compiler_module.verify_authenticated_outward_rewrite(
        replay_receipt,
        candidate_evidence_id=fact.authority.candidate_evidence_id,
        candidate_evidence_version=fact.authority.candidate_evidence_version,
        approved_source_text=fact.approved_source_text,
        outward_text=fact.text,
        document_kind=fact.document_kind,
        approved_evidence_source=source_context,
        candidate_profile_hash=fact.authority.candidate_profile_hash,
    )
    with pytest.raises(ValueError, match="context is missing"):
        application_compiler_module.verify_authenticated_outward_rewrite(
            replay_receipt,
            candidate_evidence_id=fact.authority.candidate_evidence_id,
            candidate_evidence_version=fact.authority.candidate_evidence_version,
            approved_source_text=fact.approved_source_text,
            outward_text=fact.text,
            document_kind=fact.document_kind,
            candidate_profile_hash=fact.authority.candidate_profile_hash,
        )

    damaged_context = object.__new__(type(source_context))
    object.__setattr__(damaged_context, "source_bytes", b"tampered")
    object.__setattr__(damaged_context, "source_sha256", source_context.source_sha256)
    object.__setattr__(
        damaged_context,
        "candidate_profile_hash",
        source_context.candidate_profile_hash,
    )
    with pytest.raises(ValueError, match="context hash differs"):
        damaged_context.statement(fact.authority.candidate_evidence_id)

    approved_statements = _approved_statements(
        Path(arguments["approved_evidence_path"]),
        expected_evidence_sha256=str(
            arguments["candidate_projection"]["source_hashes"]["approved_evidence"]
        ),
    )
    materialized_binding = _fact_binding(
        fact,
        approved_statements=approved_statements,
    )
    binding_json = canonical_json(materialized_binding)
    binding_document = json.loads(binding_json)
    assert (
        binding_document["authority"]["rewrite_authority"]
        == rewrite.document()
    )
    assert "source_bytes" not in binding_json


def test_document_targets_omission_defaults_to_both_documents(tmp_path: Path) -> None:
    path, _projection = _synthetic_evidence_binding(tmp_path)
    evidence = hashlib.sha256(path.read_bytes()).hexdigest()
    statements, _source_context = _load_approved_statements(
        path,
        expected_evidence_sha256=evidence,
    )
    assert _evidence_document_targets(statements["SYNTHETIC-EVIDENCE-1"]) == {
        "cv",
        "cover_letter",
    }


@pytest.mark.parametrize(
    "targets",
    (None, [], ["cv", "cv"], ["resume"], [1], [["cv"]], "cv"),
)
def test_document_targets_reject_malformed_metadata_at_load(
    tmp_path: Path,
    targets: object,
) -> None:
    path, _projection = _synthetic_evidence_binding(tmp_path)
    evidence_document = json.loads(path.read_bytes())
    evidence_document["statements"][0]["document_targets"] = targets
    evidence_bytes = (canonical_json(evidence_document) + "\n").encode("utf-8")
    path.write_bytes(evidence_bytes)
    with pytest.raises(ValueError, match="document targets are malformed"):
        _load_approved_statements(
            path,
            expected_evidence_sha256=hashlib.sha256(evidence_bytes).hexdigest(),
        )


@pytest.mark.parametrize(
    ("document_kind", "contradictory_target"),
    (("cv", ["cover_letter"]), ("cover_letter", ["cv"])),
)
def test_strategy_evidence_scope_conflicts_fail_closed(
    tmp_path: Path,
    document_kind: str,
    contradictory_target: list[str],
) -> None:
    arguments = _synthetic_composition_inputs(tmp_path, matched_requirements=1)
    baseline = _build_candidate_application_source(**arguments).source
    fact = next(
        row
        for row in baseline.facts
        if row.document_kind == document_kind
        and isinstance(row.authority, FactAuthority)
    )
    evidence_id = fact.authority.candidate_evidence_id
    _update_synthetic_document_targets(
        arguments,
        {evidence_id: contradictory_target},
    )
    with pytest.raises(
        ValueError,
        match="matched requirement lacks .*scoped candidate evidence",
    ):
        _build_candidate_application_source(**arguments)


def test_letter_only_evidence_stays_out_of_cv_and_keeps_strategy_pairs(
    tmp_path: Path,
) -> None:
    arguments = _synthetic_composition_inputs(tmp_path, matched_requirements=1)
    context_rows = (
        {
            "id": "SYNTHETIC-LETTER-CONTEXT-01",
            "statement": (
                "Designed a searchable delivery guide that connects verified "
                "prerequisites with clear handoff steps for project teams."
            ),
            "document_targets": ["cover_letter"],
        },
        {
            "id": "SYNTHETIC-LETTER-CONTEXT-02",
            "statement": (
                "Built a release checklist that records repeatable validation "
                "steps and explains recovery choices for maintainers."
            ),
            "document_targets": ["cover_letter"],
        },
        {
            "id": "SYNTHETIC-CV-CONTEXT-01",
            "statement": (
                "Created a service monitoring panel that groups status "
                "signals and highlights unresolved operational work."
            ),
            "document_targets": ["cv"],
        },
    )
    _update_synthetic_document_targets(arguments, {}, context_rows)
    package = build_candidate_application_package(**arguments)
    source = package.source
    facts = {row.sentence_id: row for row in source.facts}
    cv_ids = {
        sentence_id
        for section in source.cv_sections
        for sentence_id in section.sentence_ids
    }
    letter_ids = {
        sentence_id
        for section in source.letter_sections
        for sentence_id in section.sentence_ids
    }
    evidence_by_id = {
        row["id"]: row
        for row in json.loads(
            arguments["approved_evidence_path"].read_bytes()
        )["statements"]
    }
    letter_context = facts[
        next(
            sentence_id
            for sentence_id in letter_ids
            if facts[sentence_id].authority.candidate_evidence_id
            == "SYNTHETIC-LETTER-CONTEXT-01"
        )
    ]
    cv_context = facts[
        next(
            sentence_id
            for sentence_id in cv_ids
            if facts[sentence_id].authority.candidate_evidence_id
            == "SYNTHETIC-CV-CONTEXT-01"
        )
    ]
    letter_context_ids = {
        row.authority.candidate_evidence_id
        for row in source.facts
        if row.document_kind == "cover_letter"
    }
    assert letter_context.authority.candidate_evidence_id not in {
        row.authority.candidate_evidence_id
        for row in source.facts
        if row.sentence_id in cv_ids
    }
    assert "SYNTHETIC-LETTER-CONTEXT-02" in letter_context_ids
    assert "SYNTHETIC-CV-CONTEXT-01" not in letter_context_ids
    assert letter_context.text == evidence_by_id[
        "SYNTHETIC-LETTER-CONTEXT-01"
    ]["statement"]
    assert cv_context.text == evidence_by_id["SYNTHETIC-CV-CONTEXT-01"]["statement"]
    assert source.letter_sections[0].sentence_ids == (letter_context.sentence_id,)
    evidence_match = source.letter_sections[1]
    evidence_match_ids = set(evidence_match.sentence_ids)
    for employer_fact in (
        row
        for row in source.facts
        if row.document_kind == "cover_letter" and row.fact_kind == "employer"
    ):
        assert isinstance(employer_fact.authority, FactAuthority)
        sibling = next(
            row
            for row in source.facts
            if row.document_kind == "cover_letter"
            and row.fact_kind == "candidate"
            and isinstance(row.authority, FactAuthority)
            and row.authority.requirement_id == employer_fact.authority.requirement_id
            and row.authority.candidate_claim_id
            == employer_fact.authority.candidate_claim_id
            and row.authority.candidate_claim_version
            == employer_fact.authority.candidate_claim_version
            and row.authority.candidate_evidence_id
            == employer_fact.authority.candidate_evidence_id
            and row.authority.candidate_evidence_version
            == employer_fact.authority.candidate_evidence_version
            and row.authority.employer_research_claim_id
            == employer_fact.authority.employer_research_claim_id
            and row.authority.employer_fact_sha256
            == employer_fact.authority.employer_fact_sha256
        )
        assert sibling.sentence_id in evidence_match_ids
        assert employer_fact.sentence_id in evidence_match_ids
    normalized_cv = " ".join(package.artifacts.editable.cv_text.split())
    context_statements = (
        evidence_by_id["SYNTHETIC-LETTER-CONTEXT-01"]["statement"],
        evidence_by_id["SYNTHETIC-LETTER-CONTEXT-02"]["statement"],
    )
    assert all(
        " ".join(statement.split()) not in normalized_cv
        for statement in context_statements
    )
    for text in (
        package.artifacts.editable.cover_letter_text,
        package.artifacts.cover_letter_pdf.extracted_text,
    ):
        normalized_text = " ".join(text.split())
        assert all(
            normalized_text.count(" ".join(statement.split())) == 1
            for statement in context_statements
        )


def test_explicit_both_document_targets_preserve_rendered_output_order(
    tmp_path: Path,
) -> None:
    baseline_dir = tmp_path / "baseline"
    explicit_dir = tmp_path / "explicit"
    baseline_dir.mkdir()
    explicit_dir.mkdir()
    baseline_arguments = _synthetic_composition_inputs(baseline_dir)
    explicit_arguments = _synthetic_composition_inputs(explicit_dir)
    ids = {
        row["id"]
        for row in json.loads(
            explicit_arguments["approved_evidence_path"].read_bytes()
        )["statements"]
    }
    _update_synthetic_document_targets(
        explicit_arguments,
        {evidence_id: ["cv", "cover_letter"] for evidence_id in ids},
    )
    baseline = build_candidate_application_package(**baseline_arguments)
    explicit = build_candidate_application_package(**explicit_arguments)
    assert explicit.artifacts.editable.cv_text == baseline.artifacts.editable.cv_text
    assert explicit.artifacts.editable.cover_letter_text == baseline.artifacts.editable.cover_letter_text
    assert explicit.artifacts.cv_pdf.extracted_text == baseline.artifacts.cv_pdf.extracted_text
    assert explicit.artifacts.cover_letter_pdf.extracted_text == baseline.artifacts.cover_letter_pdf.extracted_text


def test_matched_document_scopes_select_exact_strategy_supports(
    tmp_path: Path,
) -> None:
    arguments = _synthetic_composition_inputs(tmp_path, matched_requirements=1)
    matched_rows = (
        {
            "id": "SYNTHETIC-MATCHED-CV-01",
            "statement": (
                "Built a monitoring dashboard that organizes service signals "
                "and highlights unresolved operational work."
            ),
            "document_targets": ["cv"],
        },
        {
            "id": "SYNTHETIC-MATCHED-LETTER-01",
            "statement": (
                "Designed a release guide that connects verified prerequisites "
                "with clear handoff steps for project teams."
            ),
            "document_targets": ["cover_letter"],
        },
    )
    _update_synthetic_document_targets(arguments, {}, matched_rows)
    decision = arguments["decision_receipt"]
    evidence_matrix = decision["evidence_matrix"]
    evidence_matrix[0]["evidence_ids"] = [
        "SYNTHETIC-MATCHED-CV-01",
        "SYNTHETIC-MATCHED-LETTER-01",
    ]

    package = build_candidate_application_package(**arguments)
    strategy_facts = [
        fact
        for fact in package.source.facts
        if isinstance(fact.authority, FactAuthority)
        and fact.authority.requirement_id == "SYNTHETIC-REQUIREMENT-01"
    ]
    cv_strategy = [fact for fact in strategy_facts if fact.document_kind == "cv"]
    letter_strategy = [
        fact
        for fact in strategy_facts
        if fact.document_kind == "cover_letter" and fact.fact_kind == "candidate"
    ]
    assert len(cv_strategy) == 1
    assert cv_strategy[0].authority.candidate_evidence_id == "SYNTHETIC-MATCHED-CV-01"
    assert len(letter_strategy) == 1
    letter_fact = letter_strategy[0]
    assert letter_fact.authority.candidate_evidence_id == "SYNTHETIC-MATCHED-LETTER-01"
    employer_siblings = [
        fact
        for fact in strategy_facts
        if fact.document_kind == "cover_letter" and fact.fact_kind == "employer"
    ]
    assert len(employer_siblings) == 1
    employer_fact = employer_siblings[0]
    assert (
        employer_fact.authority.requirement_id,
        employer_fact.authority.candidate_claim_id,
        employer_fact.authority.candidate_claim_version,
        employer_fact.authority.candidate_evidence_id,
        employer_fact.authority.candidate_evidence_version,
        employer_fact.authority.employer_research_claim_id,
        employer_fact.authority.employer_fact_sha256,
    ) == (
        letter_fact.authority.requirement_id,
        letter_fact.authority.candidate_claim_id,
        letter_fact.authority.candidate_claim_version,
        letter_fact.authority.candidate_evidence_id,
        letter_fact.authority.candidate_evidence_version,
        letter_fact.authority.employer_research_claim_id,
        letter_fact.authority.employer_fact_sha256,
    )


def test_all_letter_only_profile_facts_use_one_opening_anchor(
    tmp_path: Path,
) -> None:
    arguments = _synthetic_composition_inputs(
        tmp_path,
        matched_requirements=0,
    )
    context_rows = tuple(
        {
            "id": f"SYNTHETIC-LETTER-ONLY-{index:02d}",
            "statement": statement,
            "document_targets": ["cover_letter"],
        }
        for index, statement in enumerate(
            (
                "Designed a searchable delivery guide that connects verified prerequisites with clear handoff steps, helping project teams find implementation notes quickly.",
                "Built a release checklist that records repeatable validation steps and explains recovery choices, so maintainers can complete handoffs consistently.",
                "Created an onboarding map linking service ownership, operational checks, and escalation routes, giving contributors a concise reference during planned changes.",
            ),
            start=1,
        )
    )
    _update_synthetic_document_targets(arguments, {}, context_rows)
    package = build_candidate_application_package(**arguments)
    source = package.source
    facts = {row.sentence_id: row for row in source.facts}
    candidate_ids = {
        row.authority.candidate_evidence_id
        for row in source.facts
        if row.document_kind == "cover_letter" and row.fact_kind == "candidate"
    }
    expected_ids = {row["id"] for row in context_rows}
    assert candidate_ids == expected_ids
    assert source.letter_sections[0].sentence_ids == (
        next(
            row.sentence_id
            for row in source.facts
            if row.authority.candidate_evidence_id == "SYNTHETIC-LETTER-ONLY-01"
        ),
    )
    evidence_match_ids = set(source.letter_sections[1].sentence_ids)
    assert all(
        next(
            row.sentence_id
            for row in source.facts
            if row.authority.candidate_evidence_id == evidence_id
        )
        in evidence_match_ids
        for evidence_id in expected_ids - {"SYNTHETIC-LETTER-ONLY-01"}
    )
    assert len(candidate_ids) == len(source.letter_sections[0].sentence_ids) + sum(
        facts[sentence_id].fact_kind == "candidate"
        for sentence_id in source.letter_sections[1].sentence_ids
    )
    for fact in (
        row
        for row in source.facts
        if row.document_kind == "cover_letter" and row.fact_kind == "candidate"
    ):
        assert fact.authority.candidate_evidence_id not in {
            row.authority.candidate_evidence_id
            for row in source.facts
            if row.document_kind == "cv"
        }


@pytest.mark.parametrize(
    "evidence_kind",
    ("credential", "verified_claim", "external_outcome", "unsupported"),
)
def test_capability_selector_excludes_unapproved_evidence_kinds(
    tmp_path: Path,
    evidence_kind: str,
) -> None:
    arguments = _synthetic_composition_inputs(tmp_path, additional_kind="credential")
    source = _build_candidate_application_source(**arguments).source
    credential_fact = next(
        row
        for row in source.facts
        if row.authority.candidate_evidence_id == "SYNTHETIC-PORTFOLIO-08"
    )
    assert capability_line_eligible(credential_fact.text)
    assert _select_profile_capability_fact(
        {"Education": (credential_fact,)},
        {"SYNTHETIC-PORTFOLIO-08": evidence_kind},
    ) is None


def test_generic_section_uses_verified_kind_not_legacy_id_spelling() -> None:
    assert (
        _profile_cv_section_for_evidence(
            "E-001",
            "portfolio_artifact",
            legacy_profile=False,
        )
        == "Projects"
    )
    assert (
        _profile_cv_section_for_evidence(
            "E-001",
            "credential",
            legacy_profile=True,
        )
        == "Education"
    )


@pytest.mark.parametrize(
    ("additional_kind", "expected_heading"),
    (
        ("verified_claim", "Highlights"),
        ("work_artifact", "Projects"),
        ("test_result", "Results"),
        ("external_outcome", "Outcomes"),
        ("credential", "Education"),
    ),
)
def test_generic_factory_accepts_each_supported_evidence_kind(
    tmp_path: Path,
    additional_kind: str,
    expected_heading: str,
) -> None:
    arguments = _synthetic_composition_inputs(
        tmp_path,
        additional_kind=additional_kind,
    )

    source = _build_candidate_application_source(**arguments).source
    sentence_id = next(
        row.sentence_id
        for row in source.facts
        if row.authority.candidate_evidence_id == "SYNTHETIC-PORTFOLIO-08"
    )
    section_heading = next(
        section.heading
        for section in source.cv_sections
        if sentence_id in section.sentence_ids
    )

    assert section_heading == expected_heading


def test_generic_cover_letter_fills_two_bound_facts_without_legacy_ids(
    tmp_path: Path,
) -> None:
    arguments = _synthetic_composition_inputs(
        tmp_path,
        matched_requirements=1,
    )

    source = _build_candidate_application_source(**arguments).source
    letter_facts = [
        row
        for section in source.letter_sections
        for sentence_id in section.sentence_ids
        for row in source.facts
        if row.sentence_id == sentence_id and row.fact_kind == "candidate"
    ]
    employer_facts = [row for row in source.facts if row.fact_kind == "employer"]

    assert len(letter_facts) >= 2
    assert len({row.authority.candidate_evidence_id for row in letter_facts}) == len(
        letter_facts
    )
    assert employer_facts
    assert all(source.company_name in row.text for row in employer_facts)
    letter_slots = {
        slot.slot_id: slot.text
        for slot in source.style_slots
        if slot.document_kind == "cover_letter"
    }
    factual_text = " ".join(
        row.text
        for row in source.facts
        if row.document_kind == "cover_letter"
    )
    assert len(" ".join((*letter_slots.values(), factual_text)).split()) >= 90


def test_generic_cover_letter_has_one_bound_opening_and_renderer_signoff(
    tmp_path: Path,
) -> None:
    arguments = _synthetic_composition_inputs(
        tmp_path,
        matched_requirements=1,
    )

    package = build_candidate_application_package(**arguments)
    source = package.source
    paragraphs = _letter_paragraphs(source)
    assert tuple(section.heading for section in source.letter_sections) == (
        "Opening",
        "Evidence Match",
        "Close",
    )
    opening_section = source.letter_sections[0]
    opening_facts = [
        fact for fact in source.facts if fact.sentence_id in opening_section.sentence_ids
    ]
    assert [fact.fact_kind for fact in opening_facts] == ["candidate", "employer"]
    candidate_fact, employer_fact = opening_facts
    assert isinstance(candidate_fact.authority, FactAuthority)
    assert isinstance(employer_fact.authority, FactAuthority)
    sibling_fields = (
        "requirement_id",
        "candidate_claim_id",
        "candidate_claim_version",
        "candidate_evidence_id",
        "candidate_evidence_version",
        "employer_research_claim_id",
        "employer_fact_sha256",
    )
    assert tuple(getattr(candidate_fact.authority, key) for key in sibling_fields) == tuple(
        getattr(employer_fact.authority, key) for key in sibling_fields
    )
    letter_fact_text = " ".join(
        fact.text for fact in source.facts if fact.document_kind == "cover_letter"
    )
    letter_slot_text = " ".join(
        slot.text for slot in source.style_slots if slot.document_kind == "cover_letter"
    )
    assert len(f"{letter_fact_text} {letter_slot_text}".split()) >= 90
    assert paragraphs[-1] == f"Kind regards,\n{source.contact.full_name}"
    for text in (
        package.artifacts.editable.cover_letter_text,
        package.artifacts.cover_letter_pdf.extracted_text,
    ):
        flattened = " ".join(text.split())
        candidate_text = " ".join(candidate_fact.text.split())
        employer_text = " ".join(employer_fact.text.split())
        assert flattened.index(candidate_text) < flattened.index(employer_text)
        assert flattened.count(candidate_text) == 1
        assert flattened.count(employer_text) == 1
        assert text.casefold().count("kind regards") == 1
        assert "requirement below" not in text.casefold()
        assert "i am applying for this position" not in text.casefold()
        assert text.casefold().count("i would welcome the opportunity") == 1


def test_generic_zero_match_keeps_vacancy_fact_in_a_candidate_factual_section(
    tmp_path: Path,
) -> None:
    arguments = _synthetic_composition_inputs(
        tmp_path,
        matched_requirements=0,
    )
    package = build_candidate_application_package(**arguments)
    source = package.source
    opening = source.letter_sections[0]
    evidence_match = source.letter_sections[1]
    facts = {row.sentence_id: row for row in source.facts}
    opening_facts = [facts[sentence_id] for sentence_id in opening.sentence_ids]
    evidence_facts = [facts[sentence_id] for sentence_id in evidence_match.sentence_ids]
    assert tuple(section.heading for section in source.letter_sections) == (
        "Opening",
        "Evidence Match",
        "Close",
    )
    assert [row.fact_kind for row in opening_facts] == ["candidate"]
    assert any(row.fact_kind == "candidate" for row in evidence_facts)
    employer_facts = [row for row in evidence_facts if row.fact_kind == "employer"]
    assert employer_facts
    evidence_paragraph = " ".join(_letter_paragraphs(source)[1].split())
    assert any(
        evidence_paragraph.index(" ".join(row.text.split()))
        < evidence_paragraph.index(" ".join(employer_facts[0].text.split()))
        for row in evidence_facts
        if row.fact_kind == "candidate"
    )
    for text in (
        package.artifacts.editable.cover_letter_text,
        package.artifacts.cover_letter_pdf.extracted_text,
    ):
        flattened = " ".join(text.split())
        for fact in (*opening_facts, *evidence_facts):
            assert flattened.count(" ".join(fact.text.split())) == 1


def test_generic_profile_composition_still_rejects_duplicate_cv_facts(
    tmp_path: Path,
) -> None:
    arguments = _synthetic_composition_inputs(
        tmp_path,
        duplicate_last_statement=True,
    )

    with pytest.raises(ValueError, match="candidate CV repeats factual content"):
        _build_candidate_application_source(**arguments)


def test_generation_evidence_digest_is_resolved_from_verified_projection(
    tmp_path: Path,
) -> None:
    evidence_path, projection = _synthetic_evidence_binding(tmp_path)
    claimed = projection["projection_sha256"]
    decision = {"candidate_projection_sha256": claimed}

    expected = _projection_evidence_sha256(projection, decision)

    assert expected == hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    assert _approved_statements(
        evidence_path,
        expected_evidence_sha256=expected,
    )["SYNTHETIC-EVIDENCE-1"]["id"] == "SYNTHETIC-EVIDENCE-1"


def test_generation_projection_rejects_stale_evidence_digest_swap(
    tmp_path: Path,
) -> None:
    _evidence_path, projection = _synthetic_evidence_binding(tmp_path)
    decision = {"candidate_projection_sha256": projection["projection_sha256"]}
    source_hashes = dict(projection["source_hashes"])
    source_hashes["approved_evidence"] = hashlib.sha256(b"substituted").hexdigest()
    projection["source_hashes"] = source_hashes

    with pytest.raises(ValueError, match="projection content differs"):
        _projection_evidence_sha256(projection, decision)


def test_generation_projection_requires_receipt_hash_and_valid_evidence_digest(
    tmp_path: Path,
) -> None:
    _evidence_path, projection = _synthetic_evidence_binding(tmp_path)
    with pytest.raises(ValueError, match="projection binding differs"):
        _projection_evidence_sha256(projection, {"candidate_projection_sha256": "0" * 64})

    source_hashes = dict(projection["source_hashes"])
    source_hashes["approved_evidence"] = "A" * 64
    projection["source_hashes"] = source_hashes
    projection.pop("projection_sha256")
    projection["projection_sha256"] = hashlib.sha256(
        (canonical_json(projection) + "\n").encode("utf-8")
    ).hexdigest()
    with pytest.raises(ValueError, match="evidence digest is malformed"):
        _projection_evidence_sha256(
            projection,
            {"candidate_projection_sha256": projection["projection_sha256"]},
        )


def test_approved_statements_legacy_call_keeps_pinned_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_path, _projection = _synthetic_evidence_binding(tmp_path)
    evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    monkeypatch.setitem(
        APPROVED_CANDIDATE_SOURCE_HASHES,
        "approved_evidence",
        evidence_sha256,
    )

    assert "SYNTHETIC-EVIDENCE-1" in _approved_statements(evidence_path)
    evidence_path.write_bytes(evidence_path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="evidence hash differs"):
        _approved_statements(evidence_path)


def test_materializes_exact_authority_bound_source_without_pdf(
    monkeypatch, tmp_path: Path
) -> None:
    def reject_pdf(*args, **kwargs):
        raise AssertionError("source materialization must not render a PDF")

    monkeypatch.setattr(
        "career_automation.candidate_application_factory.render_pdf_artifacts",
        reject_pdf,
    )
    materialized = materialize_candidate_application_source(
        **_materialization_inputs(tmp_path),
        candidate_authority_path=AUTHORITY_PATH,
    )

    receipt = materialized.receipt
    assert receipt.candidate_authority_file_sha256 == AUTHORITY_PATH.stem
    assert receipt.application_source_id == materialized.source.source_id
    assert receipt.application_source_sha256 == materialized.source.content_sha256
    assert receipt.source_policy_receipt.passed is True
    assert receipt.source_policy_receipt.document()["schema_version"] == (
        "jaa.candidate-source-policy-receipt.v1"
    )
    with pytest.raises(ValueError, match="receipt identity is invalid"):
        replace(receipt.source_policy_receipt, receipt_sha256="f" * 64)
    with pytest.raises(ValueError, match="unsupported schema"):
        cv_constraint_release_binding(
            receipt_document=receipt.source_policy_receipt.document(),
            expected_policy_sha256=receipt.source_policy_receipt.policy_sha256,
            source=materialized.source,
            artifacts=None,
        )
    assert receipt.release_authority is False
    assert {row["document_kind"] for row in receipt.fact_bindings} == {
        "cv",
        "cover_letter",
    }
    assert all(row["authority"] for row in receipt.fact_bindings)
    assert all(
        row["approved_evidence_statement_sha256"]
        for row in receipt.fact_bindings
        if row["fact_kind"] == "candidate"
    )
    assert receipt.receipt_sha256 == hashlib.sha256(
        json.dumps(
            receipt.document(include_identity=False),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    cv_binding = next(
        row for row in receipt.fact_bindings if row["document_kind"] == "cv"
    )
    claims = tuple(
        SimpleNamespace(
            claim_id=row["sentence_id"],
            text=row["text"],
            text_sha256=row["text_sha256"],
            evidence_ids=tuple(row["evidence_ids"]),
            category={
                "Professional Summary": "summary",
                "Core Capabilities": "capability_domain",
                "Projects": "project",
                "Education": "education",
            }[row["section_heading"]],
        )
        for row in receipt.fact_bindings
        if row["document_kind"] == "cv"
    )
    request = SimpleNamespace(
        authority=SimpleNamespace(source_sha256=AUTHORITY_PATH.stem),
        vacancy_sha256=materialized.source.vacancy_sha256,
        role_title=materialized.source.role_title,
        company_name=materialized.source.company_name,
        approved_claims=claims,
    )
    receipt.authorize_editorial_request(request)
    with pytest.raises(ValueError, match="claim set differs"):
        receipt.authorize_editorial_request(
            SimpleNamespace(**{**request.__dict__, "approved_claims": claims[:1]})
        )
    with pytest.raises(ValueError, match="claim set differs"):
        receipt.authorize_editorial_request(
            SimpleNamespace(
                **{
                    **request.__dict__,
                    "approved_claims": (
                        SimpleNamespace(
                            **{**claims[0].__dict__, "text_sha256": "f" * 64}
                        ),
                        *claims[1:],
                    ),
                }
            )
        )


def test_materialization_rejects_authority_and_unsupported_packet_substitution(
    tmp_path: Path,
) -> None:
    require_private_candidate_fixture()
    substituted_authority = tmp_path / "authority.json"
    substituted_authority.write_bytes(AUTHORITY_PATH.read_bytes() + b" ")
    with pytest.raises(ValueError, match="authority file hash differs"):
        materialize_candidate_application_source(
            **_inputs(),
            deployment_binding=_materialization_inputs(tmp_path)["deployment_binding"],
            contact_authority=_materialization_inputs(tmp_path)["contact_authority"],
            candidate_authority_path=substituted_authority,
        )

    proposal = json.loads(APPROVED_EVIDENCE_PATH.read_bytes())
    proposal["statements"].append(
        {
            "id": "proposal-not-authority",
            "kind": "project_evidence",
            "proof_class": "project_evidence",
            "statement": "An unsupported proposed claim.",
        }
    )
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_text(json.dumps(proposal))
    with pytest.raises(ValueError, match="evidence hash differs"):
        materialize_candidate_application_source(
            **_materialization_inputs(tmp_path),
            candidate_authority_path=AUTHORITY_PATH,
            approved_evidence_path=proposal_path,
        )

    inputs = _materialization_inputs(tmp_path)
    substituted_contact = replace(
        inputs["contact_authority"], envelope_sha256="0" * 64
    )
    with pytest.raises(ValueError, match="envelope hash differs"):
        materialize_candidate_application_source(
            **{**inputs, "contact_authority": substituted_contact},
            candidate_authority_path=AUTHORITY_PATH,
        )


def test_authority_runner_requires_fresh_graph_identity_and_exact_materialization(
    monkeypatch, tmp_path: Path
) -> None:
    inputs = _materialization_inputs(tmp_path)
    materialized = materialize_candidate_application_source(
        **inputs,
        candidate_authority_path=AUTHORITY_PATH,
    )
    fact_heading = {
        sentence_id: section.heading
        for section in materialized.source.cv_sections
        for sentence_id in section.sentence_ids
    }
    categories = {
        "Professional Summary": "summary",
        "Core Capabilities": "capability_domain",
        "Projects": "project",
        "Education": "education",
    }
    claims = tuple(
        ApprovedCVClaim(
            claim_id=row["sentence_id"],
            text=row["text"],
            text_sha256=row["text_sha256"],
            evidence_ids=tuple(row["evidence_ids"]),
            category=categories[fact_heading[row["sentence_id"]]],
        )
        for row in materialized.receipt.fact_bindings
        if row["document_kind"] == "cv"
    )
    request = build_editorial_request(
        authority=CandidateEditorialAuthority(
            candidate_name=materialized.source.contact.full_name,
            candidate_city=materialized.source.contact.city,
            graduation_month_year=None,
            dissertation_title=None,
            source_sha256=AUTHORITY_PATH.stem,
        ),
        role_title=materialized.source.role_title,
        company_name=materialized.source.company_name,
        vacancy_sha256=materialized.source.vacancy_sha256,
        approved_claims=claims,
    )
    verified = SimpleNamespace(
        application_id=inputs["deployment_binding"].application_id,
        environment="synthetic",
        handoff_root_sha256=inputs["deployment_binding"].handoff_root_sha256,
        admission_receipt_sha256=(
            inputs["deployment_binding"].admission_receipt_sha256
        ),
        current_boundary_receipt_sha256=(
            inputs["deployment_binding"].current_boundary_receipt_sha256
        ),
        candidate_authority_sha256=AUTHORITY_PATH.stem,
    )

    class _Store:
        def for_boundary(self, application_id, boundary):
            assert (application_id, boundary) == (verified.application_id, "strategy")
            return verified

    captured = {"calls": 0}

    def downstream(**kwargs):
        captured["calls"] += 1
        captured.update(kwargs)
        return "prepared"

    monkeypatch.setattr(
        market_aligner_preparation,
        "_prepare_admitted_market_application",
        downstream,
    )
    result = market_aligner_preparation.prepare_admitted_market_application_from_authorities(
        admission_store=_Store(),
        application_id=verified.application_id,
        repository_root=Path(__file__).resolve().parents[1],
        data_home=tmp_path / "data-home",
        candidate_authority_path=AUTHORITY_PATH,
        contact_authority_path=inputs["contact_authority"].source_path,
        input_materializer=lambda observed, binding, contact: {
            "base_source": materialized.source,
            "request": request,
            "materialization": materialized,
        },
        environment="synthetic",
        contact_authority_loader=lambda *args, **kwargs: inputs["contact_authority"],
    )
    assert result == "prepared"
    assert captured["orchestration_arguments"]["materialization_receipt"] == (
        materialized.receipt
    )
    assert captured["calls"] == 1


    for field in ("registry_sha256", "signer_public_key_sha256"):
        substituted = replace(inputs["contact_authority"], **{field: "0" * 64})
        with pytest.raises(ValueError, match="differs from admitted candidate"):
            market_aligner_preparation.prepare_admitted_market_application_from_authorities(
                admission_store=_Store(),
                application_id=verified.application_id,
                repository_root=Path(__file__).resolve().parents[1],
                data_home=tmp_path / f"substituted-{field}",
                candidate_authority_path=AUTHORITY_PATH,
                contact_authority_path=substituted.source_path,
                input_materializer=lambda *args: {
                    "base_source": materialized.source,
                    "request": request,
                    "materialization": materialized,
                },
                environment="synthetic",
                contact_authority_loader=lambda *args, value=substituted, **kwargs: value,
            )
        assert captured["calls"] == 1

    substituted_verified = SimpleNamespace(
        **{**vars(verified), "admission_receipt_sha256": "0" * 64}
    )
    with pytest.raises(ValueError, match="differs from admitted candidate"):
        market_aligner_preparation.prepare_admitted_market_application_from_authorities(
            admission_store=SimpleNamespace(
                for_boundary=lambda *args: substituted_verified
            ),
            application_id=verified.application_id,
            repository_root=Path(__file__).resolve().parents[1],
            data_home=tmp_path / "substituted-deployment",
            candidate_authority_path=AUTHORITY_PATH,
            contact_authority_path=inputs["contact_authority"].source_path,
            input_materializer=lambda *args: {
                "base_source": materialized.source,
                "request": request,
                "materialization": materialized,
            },
            environment="synthetic",
            contact_authority_loader=lambda *args, **kwargs: inputs[
                "contact_authority"
            ],
        )
    assert captured["calls"] == 1

    production_verified = SimpleNamespace(**{
        **vars(verified),
        "environment": "production",
    })
    production_store = SimpleNamespace(
        for_boundary=lambda *args: production_verified
    )
    with pytest.raises(ValueError, match="canonical contact loader"):
        market_aligner_preparation.prepare_admitted_market_application_from_authorities(
            admission_store=production_store,
            application_id=verified.application_id,
            repository_root=Path(__file__).resolve().parents[1],
            data_home=tmp_path / "production-home",
            candidate_authority_path=AUTHORITY_PATH,
            contact_authority_path=inputs["contact_authority"].source_path,
            input_materializer=lambda *args: {},
            environment="production",
            contact_authority_loader=lambda *args, **kwargs: inputs["contact_authority"],
        )
    def forbidden_production_callable(*args):
        raise AssertionError("arbitrary production materializer was invoked")

    with pytest.raises(ValueError, match="canonical materializer"):
        market_aligner_preparation.prepare_admitted_market_application_from_authorities(
            admission_store=production_store,
            application_id=verified.application_id,
            repository_root=Path(__file__).resolve().parents[1],
            data_home=tmp_path / "production-materializer-home",
            candidate_authority_path=AUTHORITY_PATH,
            contact_authority_path=inputs["contact_authority"].source_path,
            input_materializer=forbidden_production_callable,
            environment="production",
        )

    missing_graph_identity = SimpleNamespace(**{
        key: value for key, value in vars(verified).items()
        if key != "candidate_authority_sha256"
    })
    with pytest.raises(HandoffAdmissionError, match="lacks candidate authority"):
        market_aligner_preparation.prepare_admitted_market_application_from_authorities(
            admission_store=SimpleNamespace(
                for_boundary=lambda *args: missing_graph_identity
            ),
            application_id=verified.application_id,
            repository_root=Path(__file__).resolve().parents[1],
            data_home=tmp_path / "other-home",
            candidate_authority_path=AUTHORITY_PATH,
            contact_authority_path=inputs["contact_authority"].source_path,
            input_materializer=lambda *args: {},
            environment="synthetic",
            contact_authority_loader=lambda *args, **kwargs: inputs["contact_authority"],
        )


def test_materialization_only_returns_admitted_market_context_without_writers(
    tmp_path: Path,
) -> None:
    market, inputs, projection = _integrated_decision(tmp_path)
    raw_listing = b'{"fixture":"exact Workable listing"}'
    materialized = materialize_candidate_application_source(
        candidate_authority_path=AUTHORITY_PATH,
        deployment_binding=inputs["deployment_binding"],
        contact_authority=inputs["contact_authority"],
        decision_receipt=market.decision_receipt(),
        candidate_projection=projection,
        job_key=market.source_job_key,
        vacancy_sha256=market.raw_listing_sha256,
        source_url=market.source_url,
        role_title=market.role_title,
        company_name=market.company_name,
        contact=inputs["contact"],
        market_decision_authority=market,
    )
    binding = inputs["deployment_binding"]
    verified = SimpleNamespace(
        application_id=binding.application_id,
        environment="synthetic",
        handoff_root_sha256=binding.handoff_root_sha256,
        admission_receipt_sha256=binding.admission_receipt_sha256,
        current_boundary_receipt_sha256=binding.current_boundary_receipt_sha256,
        candidate_authority_sha256=AUTHORITY_PATH.stem,
        profile_id="profile-test",
        profile_version="v1",
        candidate_intent_sha256="6" * 64,
        final_score=42.0,
        opportunity_score=0.25,
        geography_priority_rank=5,
        raw_listing_bytes=raw_listing,
        source_observed_at=market.observed_at,
    )
    store = SimpleNamespace(for_boundary=lambda _application_id, _boundary: verified)
    result = market_aligner_preparation.prepare_admitted_market_application_from_authorities(
        admission_store=store,
        application_id=verified.application_id,
        repository_root=Path(__file__).resolve().parents[1],
        data_home=tmp_path / "data-home",
        candidate_authority_path=AUTHORITY_PATH,
        contact_authority_path=inputs["contact_authority"].source_path,
        input_materializer=lambda *_args: {
            "base_source": materialized.source,
            "candidate_projection": projection,
            "decision_receipt": market.decision_receipt(),
            "market_decision_authority": market,
            "materialization": materialized,
        },
        environment="synthetic",
        contact_authority_loader=lambda *_args, **_kwargs: inputs[
            "contact_authority"
        ],
        materialization_only=True,
    )
    assert type(result) is market_aligner_preparation.MarketApplicationMaterializationContext
    assert result.application_id == binding.application_id
    assert result.materialization == materialized
    assert result.raw_listing_bytes == raw_listing
    assert result.release_authority is False


def test_rejects_noneligible_or_vacancy_swapped_decision() -> None:
    arguments = _inputs()
    decision = dict(arguments["decision_receipt"])
    decision["decision"] = "unresolved"
    arguments["decision_receipt"] = decision
    with pytest.raises(ValueError, match="decision authority differs"):
        build_candidate_application_package(**arguments)

    for field, value in (
        ("role_title", "Chief Executive Officer"),
        ("company_name", "Completely Different Employer"),
    ):
        arguments = _inputs()
        arguments[field] = value
        with pytest.raises(ValueError, match="decision authority differs"):
            build_candidate_application_package(**arguments)

    arguments = _inputs()
    arguments["vacancy_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="decision authority differs"):
        build_candidate_application_package(**arguments)
