"""Independent acceptance tests for the bounded JAA-07 source contract."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from career_automation.application_compiler import (
    CV_SECTION_ORDER,
    ApplicationSource,
    CandidateContact,
    DocumentSection,
    FactAuthority,
    FactualSentence,
    ModelReceipt,
    ProductionApplicationCompiler,
    StructuredAnswer,
    StyleProposal,
    StyleSlot,
    apply_style_proposal,
    compile_application_source,
    verify_application_source,
)
from career_automation.application_artifacts import (
    ARTIFACT_FILENAMES,
    load_published_artifacts,
    publish_application_artifacts,
    verify_published_application_artifacts,
)
from career_automation.application_strategy import (
    ApplicationStrategy,
    CandidateSupport,
    EmployerResearchFact,
    compile_application_strategy,
    ApplicationStrategyStore,
)
from career_automation.candidate_graph import CandidateGraph
from career_automation.evidence_matching import (
    MatchResult,
    MatchingPolicy,
    Requirement,
    content_hash,
    canonical_json,
)
from career_automation.rendering import (
    render_editable_text,
    render_pdf_artifacts,
    validate_pdf_artifact,
)
from test_jaa06_independent_acceptance import _fit_database


DIGEST = hashlib.sha256(b"jaa07-contract").hexdigest()
POLICY = MatchingPolicy()
ROOT = Path(__file__).resolve().parent
LOCKED_PACKS = (
    ROOT / "career_automation/fixtures/jaa07_locked_application_packs.json"
)


def _strategy() -> ApplicationStrategy:
    requirement = Requirement(
        "delivery",
        "claim-delivery",
        "Deliver reliable services.",
        True,
        "evidence",
        "build_evidence",
        ("portfolio_artifact",),
        9000,
        "vacancy:synthetic",
        (0, 26),
    )
    match = MatchResult(
        "delivery",
        "matched",
        ("evidence-delivery",),
        9500,
        "approved direct evidence",
        POLICY.policy_hash,
        None,
    )
    support = CandidateSupport(
        "delivery",
        "claim-delivery",
        2,
        "evidence-delivery",
        3,
        "portfolio_artifact",
        "approved",
        "evidence",
        "approved",
        "evidence",
        "approved",
        date(2035, 1, 1),
    )
    fact = EmployerResearchFact(
        "research-company",
        "company",
        "fact",
        ("source:official-company",),
        content_hash(_employer_fact_document()),
        "current",
    )
    return compile_application_strategy(
        fit_run_id=hashlib.sha256(b"fit").hexdigest(),
        dossier_hash=hashlib.sha256(b"dossier").hexdigest(),
        candidate_profile_hash=hashlib.sha256(b"profile").hexdigest(),
        requirements=(requirement,),
        match_results=(match,),
        candidate_support=(support,),
        employer_facts=(fact,),
        as_of=date(2030, 1, 2),
    )


def _employer_fact_document(
    *, text: str = "Example Ltd operates a documented service."
) -> dict[str, object]:
    return {
        "id": "research-company",
        "kind": "company",
        "classification": "fact",
        "text": text,
        "observed_at": "2030-01-02T00:00:00+00:00",
        "source_ids": ["source:official-company"],
    }


def _sentence(
    element,
    *,
    text: str,
    fact_kind: str,
    document_kind: str,
    employer_fact: dict[str, object] | None = None,
) -> FactualSentence:
    sentence_id = content_hash(
        {
            "element": element.element_id,
            "text": text,
            "fact_kind": fact_kind,
            "document_kind": document_kind,
        }
    )
    return FactualSentence(
        sentence_id,
        text,
        text,
        fact_kind,
        document_kind,
        FactAuthority.from_element(element),
        None if employer_fact is None else canonical_json(employer_fact),
    )


def _slot(document_kind: str, text: str) -> StyleSlot:
    return StyleSlot(
        content_hash({"document_kind": document_kind, "text": text}),
        document_kind,
        text,
    )


def _source() -> tuple[ApplicationSource, ApplicationStrategy]:
    strategy = _strategy()
    elements = {row.kind: row for row in strategy.elements}
    cv = _sentence(
        elements["cv_emphasis"],
        text="Delivered reliable services with tested evidence.",
        fact_kind="candidate",
        document_kind="cv",
    )
    letter_candidate = _sentence(
        elements["cover_letter_argument"],
        text="Delivered reliable services with tested evidence.",
        fact_kind="candidate",
        document_kind="cover_letter",
    )
    letter_employer = _sentence(
        elements["employer_hook"],
        text="Example Ltd operates a documented service.",
        fact_kind="employer",
        document_kind="cover_letter",
        employer_fact=_employer_fact_document(),
    )
    answer = _sentence(
        elements["structured_answer"],
        text="Delivered reliable services with tested evidence.",
        fact_kind="candidate",
        document_kind="answer",
    )
    cv_slot = _slot("cv", "Relevant evidence")
    letter_slot = _slot("cover_letter", "This work is relevant to the role.")
    answer_slot = _slot("answer", "A concise example follows.")
    source = compile_application_source(
        strategy=strategy,
        job_key="synthetic:example:engineer",
        role_title="Software Engineer",
        company_name="Example Ltd",
        vacancy_source_identity="vacancy:synthetic:example",
        vacancy_sha256=hashlib.sha256(b"vacancy").hexdigest(),
        contact=CandidateContact(
            "Alex Example",
            "alex@example.test",
            "+44 7700 900123",
            "London",
            "contact-primary",
            4,
            hashlib.sha256(b"contact-provenance").hexdigest(),
        ),
        facts=(cv, letter_candidate, letter_employer, answer),
        style_slots=(cv_slot, letter_slot, answer_slot),
        cv_sections=tuple(
            DocumentSection(
                heading,
                (cv.sentence_id,),
                (cv_slot.slot_id,) if index == 0 else (),
            )
            for index, heading in enumerate(CV_SECTION_ORDER)
        ),
        letter_sections=(
            DocumentSection(
                "Opening",
                (letter_employer.sentence_id,),
                (letter_slot.slot_id,),
            ),
            DocumentSection("Evidence Match", (letter_candidate.sentence_id,)),
            DocumentSection("Company Fit", (letter_employer.sentence_id,)),
            DocumentSection("Close", (letter_candidate.sentence_id,)),
        ),
        answers=(
            StructuredAnswer(
                "delivery-example",
                "Describe a relevant delivery example.",
                (answer.sentence_id,),
                (answer_slot.slot_id,),
            ),
        ),
    )
    return source, strategy


def test_source_is_reproducible_and_every_fact_resolves_to_strategy_authority() -> None:
    source, strategy = _source()
    verify_application_source(source)
    replay, _ = _source()
    assert replay == source
    element_by_id = {row.element_id: row for row in strategy.elements}
    for fact in source.facts:
        element = element_by_id[fact.authority.strategy_element_id]
        assert FactAuthority.from_element(element) == fact.authority
        assert fact.text == fact.approved_source_text
    assert source.certifies_slice is False
    assert source.dependency_gate == "JAA-06"


def test_editable_outputs_are_single_column_and_preserve_authoritative_values() -> None:
    source, _ = _source()
    artifacts = render_editable_text(source)
    for value in (
        "Alex Example",
        "alex@example.test",
        "+44 7700 900123",
        "London",
    ):
        assert value in artifacts.cv_text
        assert value in artifacts.cover_letter_text
    assert tuple(
        heading for heading in CV_SECTION_ORDER if heading in artifacts.cv_text
    ) == CV_SECTION_ORDER
    assert "Example Ltd operates a documented service." in artifacts.cover_letter_text
    assert "Describe a relevant delivery example." in artifacts.answers_text
    assert artifacts.cv_sha256 == hashlib.sha256(artifacts.cv_text.encode()).hexdigest()


def test_style_proposal_is_non_authoritative_atomic_and_rehashes_source() -> None:
    source, _ = _source()
    slot = next(row for row in source.style_slots if row.document_kind == "answer")
    proposed = "Here is a concise example."
    receipt = ModelReceipt(
        "test-provider",
        "style-reviewer-vone",
        DIGEST,
        hashlib.sha256(b"humanizer-policy").hexdigest(),
        hashlib.sha256(slot.text.encode()).hexdigest(),
        hashlib.sha256(proposed.encode()).hexdigest(),
    )
    proposal = StyleProposal(
        content_hash(
            {
                "contract": "jaa07.style-proposal.v1",
                "slot_id": slot.slot_id,
                "input_sha256": receipt.input_sha256,
                "output_sha256": receipt.output_sha256,
                "provider": receipt.provider,
                "model": receipt.model,
                "prompt_sha256": receipt.prompt_sha256,
                "policy_sha256": receipt.policy_sha256,
            }
        ),
        slot.slot_id,
        slot.text,
        proposed,
        receipt,
    )
    revised = apply_style_proposal(source, proposal)
    verify_application_source(revised)
    assert revised.source_id != source.source_id
    assert revised.facts == source.facts
    assert revised.contact == source.contact
    assert (
        replace(
            revised,
            style_slots=source.style_slots,
            source_id=source.source_id,
            content_sha256=source.content_sha256,
        )
        == source
    )


def test_pdf_artifacts_are_two_page_cv_one_page_letter_and_parse_exactly() -> None:
    source, _ = _source()
    artifacts = render_pdf_artifacts(source)
    assert artifacts.certifies_slice is False
    assert artifacts.cv_pdf.page_count == 2
    assert artifacts.cover_letter_pdf.page_count == 1
    assert len(artifacts.cv_pdf.pdf_bytes) > 500
    assert len(artifacts.cover_letter_pdf.pdf_bytes) > 500
    for value in (
        "Alex Example",
        "alex@example.test",
        "+44 7700 900123",
        "Delivered reliable services with tested evidence.",
    ):
        assert value in artifacts.cv_pdf.extracted_text.replace("\n", " ")
    assert (
        "Example Ltd operates a documented service."
        in artifacts.cover_letter_pdf.extracted_text.replace("\n", " ")
    )
    validate_pdf_artifact(
        artifacts.cv_pdf,
        expected_page_count=2,
        required_values=("Alex Example", "alex@example.test"),
    )
    assert artifacts.artifact_set_sha256 == render_pdf_artifacts(
        source
    ).artifact_set_sha256


def test_artifacts_publish_externally_once_with_private_exact_receipts(
    tmp_path: Path,
) -> None:
    source, _ = _source()
    artifacts = render_pdf_artifacts(source)
    root = tmp_path / "application-artifacts"
    receipt = publish_application_artifacts(
        source,
        artifacts,
        root=root,
        repository_root=ROOT,
    )
    assert receipt.certifies_slice is False
    assert receipt.artifact_set_sha256 == artifacts.artifact_set_sha256
    directory = root / receipt.relative_directory
    assert tuple(row.filename for row in receipt.files) == ARTIFACT_FILENAMES
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for row in receipt.files:
        target = directory / row.filename
        assert target.stat().st_size == row.size_bytes
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert hashlib.sha256(target.read_bytes()).hexdigest() == row.sha256
    receipt_document = json.loads(
        (directory / "receipt.json").read_text(encoding="utf-8")
    )
    assert str(ROOT) not in json.dumps(receipt_document)
    assert load_published_artifacts(
        artifacts.artifact_set_sha256,
        root=root,
        repository_root=ROOT,
    ) == receipt
    assert publish_application_artifacts(
        source,
        artifacts,
        root=root,
        repository_root=ROOT,
    ) == receipt


def test_published_artifacts_verify_without_file_changes_and_reject_absence(
    tmp_path: Path,
) -> None:
    source, _ = _source()
    artifacts = render_pdf_artifacts(source)
    root = tmp_path / "published"
    receipt = publish_application_artifacts(
        source,
        artifacts,
        root=root,
        repository_root=ROOT,
    )
    before = {
        path.relative_to(root): (path.stat().st_mtime_ns, path.read_bytes())
        for path in root.rglob("*")
        if path.is_file()
    }
    assert verify_published_application_artifacts(
        source,
        artifacts,
        root=root,
        repository_root=ROOT,
    ) == receipt
    after = {
        path.relative_to(root): (path.stat().st_mtime_ns, path.read_bytes())
        for path in root.rglob("*")
        if path.is_file()
    }
    assert after == before

    absent_root = tmp_path / "absent"
    absent_root.mkdir()
    with pytest.raises(KeyError):
        verify_published_application_artifacts(
            source,
            artifacts,
            root=absent_root,
            repository_root=ROOT,
        )


def test_production_compiler_resolves_vacancy_contact_claim_and_employer_authority(
    tmp_path: Path,
) -> None:
    database, run, requirement = _fit_database(tmp_path, matched=True)
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    )
    graph = CandidateGraph(database.path)
    contact_value = {
        "full_name": "Alex Example",
        "email": "alex@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
    }
    graph.add_record(
        "contact-primary",
        kind="fact",
        subject="contact",
        value=contact_value,
        state="fact",
        source_identity="test:verified-contact",
    )
    graph.verify_record(
        "contact-primary",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="test.contact",
        policy_version="1",
        policy_hash=DIGEST,
        reason="operator-verified contact projection",
        source_identity="test:contact-verifier",
    )
    with database.connection() as connection:
        source_hash = str(connection.execute(
            """SELECT provenance.source_hash
               FROM candidate_records record
               JOIN candidate_provenance provenance
                 ON provenance.provenance_id=record.provenance_id
               WHERE record.record_id='contact-primary' AND record.version=1"""
        ).fetchone()[0])
    source = ProductionApplicationCompiler(database.path).compile(
        strategy.strategy_id,
        as_of=date.today(),
        contact=CandidateContact(
            record_id="contact-primary",
            record_version=1,
            provenance_sha256=source_hash,
            **contact_value,
        ),
        questions={
            requirement.requirement_id: (
                "delivery-example",
                "Describe a relevant delivery example.",
            )
        },
    )
    verify_application_source(source)
    assert source.strategy_id == strategy.strategy_id
    assert source.role_title == "Engineer"
    assert source.company_name == "Example"
    assert source.vacancy_sha256
    assert {row.document_kind for row in source.facts} == {
        "cv",
        "cover_letter",
        "answer",
    }
    assert all(
        row.text == row.approved_source_text for row in source.facts
    )
    rendered = render_editable_text(source)
    for fact in source.facts:
        if fact.document_kind == "cover_letter":
            assert rendered.cover_letter_text.count(fact.text) == 1
    artifacts = render_pdf_artifacts(source)
    assert artifacts.cv_pdf.page_count == 2
    assert artifacts.cover_letter_pdf.page_count == 1


def test_production_compiler_covers_multiple_requirements_sections_and_cv_pages(
    tmp_path: Path,
) -> None:
    claim_rows = (
        ("delivery-achievement", "Deliver production services.", "achievement"),
        ("platform-skill", "Build reliable platforms.", "skill"),
        ("degree-education", "Hold a relevant degree.", "education"),
    )
    database, run, _requirement = _fit_database(
        tmp_path,
        matched=True,
        claims=claim_rows,
    )
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    )
    requirement_ids = {row[0] for row in claim_rows}
    elements_by_requirement = {
        requirement_id: {
            row.kind: row.element_id
            for row in strategy.elements
            if row.requirement_id == requirement_id
        }
        for requirement_id in requirement_ids
    }
    assert all(
        set(elements) == {
            "cv_emphasis",
            "cover_letter_argument",
            "structured_answer",
            "interview_seed",
            "objection_response",
            "employer_hook",
        }
        for elements in elements_by_requirement.values()
    )
    assert len({
        element_id
        for elements in elements_by_requirement.values()
        for element_id in elements.values()
    }) == len(requirement_ids) * 6

    graph = CandidateGraph(database.path)
    contact_value = {
        "full_name": "Alex Example",
        "email": "alex@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
    }
    graph.add_record(
        "contact-multi-requirement",
        kind="fact",
        subject="contact",
        value=contact_value,
        state="fact",
        source_identity="test:verified-contact",
    )
    graph.verify_record(
        "contact-multi-requirement",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="test.contact",
        policy_version="1",
        policy_hash=DIGEST,
        reason="operator-verified contact projection",
        source_identity="test:contact-verifier",
    )
    with database.connection() as connection:
        source_hash = str(connection.execute(
            """SELECT provenance.source_hash
               FROM candidate_records record
               JOIN candidate_provenance provenance
                 ON provenance.provenance_id=record.provenance_id
               WHERE record.record_id='contact-multi-requirement'
                 AND record.version=1"""
        ).fetchone()[0])
    source = ProductionApplicationCompiler(database.path).compile(
        strategy.strategy_id,
        as_of=date.today(),
        contact=CandidateContact(
            record_id="contact-multi-requirement",
            record_version=1,
            provenance_sha256=source_hash,
            **contact_value,
        ),
    )
    verify_application_source(source)

    sections = {row.heading: row for row in source.cv_sections}
    assert tuple(sections) == (
        "Professional Summary",
        "Experience",
        "Skills",
        "Education",
    )
    facts = {row.sentence_id: row for row in source.facts}
    assert {
        facts[sentence_id].authority.requirement_id
        for sentence_id in sections["Experience"].sentence_ids
    } == {"delivery-achievement"}
    assert {
        facts[sentence_id].authority.requirement_id
        for sentence_id in sections["Skills"].sentence_ids
    } == {"platform-skill"}
    assert {
        facts[sentence_id].authority.requirement_id
        for sentence_id in sections["Education"].sentence_ids
    } == {"degree-education"}

    artifacts = render_pdf_artifacts(source)
    assert artifacts.cv_pdf.page_count == 2
    first_page, second_page = artifacts.cv_pdf.rendered_lines
    assert "Experience" in first_page
    assert "Skills" in second_page
    assert "Education" in second_page
    for requirement_id in requirement_ids:
        assert any(
            row.authority.requirement_id == requirement_id
            and row.document_kind == "cv"
            for row in source.facts
        )


def test_twenty_locked_packs_pass_exact_noncertifying_software_metrics() -> None:
    completed = subprocess.run(
        (sys.executable, "scripts/evaluate_jaa07_locked_packs.py"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(completed.stdout)
    assert report["status"] == "SOFTWARE_CONTRACT_PASS"
    assert report["packs"] == 20
    assert set(report["metrics_bp"].values()) == {10_000}
    assert len(report["results"]) == 20
    assert all(
        set(row["checks"].values()) == {True}
        for row in report["results"]
    )
    assert report["certifies_slice"] is False
    assert report["dependency_gates"] == ["JAA-06", "JAA-05", "JAA-04"]
    assert report["live_requests"] == 0
