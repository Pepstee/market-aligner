from __future__ import annotations

import json
import hashlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation.application_compiler import CandidateContact
from career_automation.candidate_application_factory import (
    build_market_application_decision_authority,
    build_candidate_application_deployment_binding,
    build_candidate_application_package,
    materialize_candidate_application_source,
)
from career_automation.evidence_matching import canonical_json
from career_automation.candidate_contact_authority import CandidateContactAuthority
from career_automation.candidate_authority import APPROVED_EVIDENCE_PATH
from career_automation.production_attempt import _approved_fact_authorities
from career_automation.release_gate import cv_constraint_release_binding
from career_automation import market_aligner_preparation
from career_automation.handoff_admission import HandoffAdmissionError
from cv_generation.editorial_composition import (
    ApprovedCVClaim,
    CandidateEditorialAuthority,
    build_editorial_request,
)


AUTHORITY_PATH = Path(
    "/home/gutua/software-factory/application-artifacts/candidate-authorities/"
    "85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9.json"
)
DISCOVERY_PATH = Path(
    "/home/gutua/software-factory/application-artifacts/objects/39/"
    "39e60f8d278d8a07427c8bc25eff85bd357e98451cce87983d70d3d85e935f47"
)


def _inputs() -> dict[str, object]:
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


def _integrated_decision(tmp_path: Path):
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
    approved = json.loads(APPROVED_EVIDENCE_PATH.read_bytes())["statements"][:7]
    ledger_bytes = b"".join(
        (canonical_json({
            "claim": row["statement"],
            "content_sha256": hashlib.sha256(row["statement"].encode()).hexdigest(),
            "evidence_id": row["id"],
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
    assert any(row["status"] == "matched" for row in authority.evidence_matrix)
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
    assert len(opening.sentence_ids) == 1
    opening_fact = next(
        fact
        for fact in employer_facts
        if fact.sentence_id == opening.sentence_ids[0]
    )
    assert package.source.role_title in opening_fact.text
    assert package.source.company_name in opening_fact.text
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
