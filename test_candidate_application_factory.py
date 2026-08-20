from __future__ import annotations

import json
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation.application_compiler import CandidateContact
from career_automation.candidate_application_factory import (
    build_candidate_application_package,
)
from career_automation.candidate_authority import APPROVED_EVIDENCE_PATH
from career_automation.production_attempt import _approved_fact_authorities


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
