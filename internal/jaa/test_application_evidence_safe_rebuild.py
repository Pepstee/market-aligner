from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from career_automation.adversarial_recruiter import (
    RecruiterAssessmentPackage,
    assess_application_as_recruiter,
)
from career_automation.application_compiler import (
    DocumentSection,
    FactAuthority,
    ModelReceipt,
    ProfileFactAuthority,
    StyleProposal,
    StructuredAnswer,
    apply_style_proposal,
    compile_application_source,
)
from career_automation.application_sanity_review import canonical_form_fields
from career_automation.evidence_matching import content_hash
from career_automation.external_document_assurance import IntendedVacancy
from career_automation.rendering import render_pdf_artifacts
from career_automation.testing_adversarial_recruiter import fixture_recruiter_result
from career_automation.testing_sanity_review import FixturePassBackend
from cv_generation.adversarial_rebuild import (
    AdversarialRebuildError,
    ApplicationApprovedEvidence,
    ApplicationImprovementApplication,
    execute_application_evidence_safe_rebuild,
    plan_application_evidence_safe_rebuild,
)
from llm.client import Backend, LLMClient, LLMResponse
from test_jaa07_independent_acceptance import _slot, _source


class _RecruiterBackend(Backend):
    name = "scripted_application_rebuild_recruiter"

    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        del system, user, temperature
        result = fixture_recruiter_result()
        result["application_improvements"] = [
            {
                "rank": 1,
                "target": "cv",
                "recommendation": "Tighten the visible CV opening without adding a claim.",
                "expected_effect": "Makes the strongest existing evidence easier to scan.",
                "support_required": False,
                "outward_evidence_refs": ["cv:char:0:1"],
            },
            {
                "rank": 2,
                "target": "positioning",
                "recommendation": "Claim broader platform ownership.",
                "expected_effect": "Would address a remaining seniority concern.",
                "support_required": True,
                "outward_evidence_refs": ["job_listing:char:0:1"],
            },
        ]
        result["profile_improvements"] = [
            {
                "category": "experience",
                "recommendation": "Build evidence from a larger deployed service.",
                "time_horizon": "months",
                "expected_effect": "Addresses the remaining production-depth gap.",
            }
        ]
        return LLMResponse(text=json.dumps(result), model="rebuild-recruiter-v1")


class _EvidenceAuthority:
    authority_identity = "test.application-evidence-authority.v1"
    composition_sha256 = hashlib.sha256(
        b"test.application-evidence-composition.v1"
    ).hexdigest()

    def __init__(self, records: tuple[ApplicationApprovedEvidence, ...]) -> None:
        self.records = {(row.evidence_id, row.evidence_version): row for row in records}
        self.revoked = False

    @classmethod
    def receipt(cls, record: ApplicationApprovedEvidence) -> str:
        return content_hash(
            {
                "approved_statement_sha256": record.approved_statement_sha256,
                "authority_identity": cls.authority_identity,
                "claim_id": record.claim_id,
                "claim_version": record.claim_version,
                "evidence_id": record.evidence_id,
                "evidence_version": record.evidence_version,
                "status": record.status,
            }
        )

    def resolve_current_approved_evidence(
        self, evidence_id: str, evidence_version: int
    ) -> ApplicationApprovedEvidence:
        if self.revoked:
            raise KeyError((evidence_id, evidence_version))
        return self.records[(evidence_id, evidence_version)]

    def verify_current_approved_evidence(
        self, value: ApplicationApprovedEvidence
    ) -> None:
        if value.authority_receipt_sha256 != self.receipt(value):
            raise ValueError("application evidence receipt is untrusted")


def _client(tmp_path: Path, backend: Backend, name: str) -> LLMClient:
    return LLMClient(
        backend=backend,
        model=name,
        temperature=0,
        max_retries=1,
        cache_enabled=False,
        cache_dir=tmp_path / f"{name}-cache",
        usage_log=tmp_path / f"{name}-usage.jsonl",
    )


def _questions(source) -> dict[str, tuple[str, str]]:
    return {
        f"requirement:{index}": (answer.question_id, answer.question)
        for index, answer in enumerate(source.answers)
    }


def _base(tmp_path: Path):
    recovered, strategy = _source()
    cv_facts = tuple(row for row in recovered.facts if row.document_kind == "cv")
    letter_candidate = tuple(
        row
        for row in recovered.facts
        if row.document_kind == "cover_letter" and row.fact_kind == "candidate"
    )
    letter_employer = tuple(
        row
        for row in recovered.facts
        if row.document_kind == "cover_letter" and row.fact_kind == "employer"
    )
    answer_facts = tuple(
        row for row in recovered.facts if row.document_kind == "answer"
    )
    cv_slot = next(row for row in recovered.style_slots if row.document_kind == "cv")
    letter_slot = next(
        row for row in recovered.style_slots if row.document_kind == "cover_letter"
    )
    answer_slot = next(
        row for row in recovered.style_slots if row.document_kind == "answer"
    )
    close_slot = _slot("cover_letter", "Thank you for your consideration.")
    source = compile_application_source(
        strategy=strategy,
        job_key=recovered.job_key,
        role_title=recovered.role_title,
        company_name=recovered.company_name,
        vacancy_source_identity=recovered.vacancy_source_identity,
        vacancy_sha256=recovered.vacancy_sha256,
        contact=recovered.contact,
        facts=(*cv_facts, *letter_candidate, *letter_employer, *answer_facts),
        style_slots=(cv_slot, letter_slot, close_slot, answer_slot),
        cv_sections=(
            DocumentSection("Professional Summary", (), (cv_slot.slot_id,)),
            DocumentSection("Experience", tuple(row.sentence_id for row in cv_facts)),
        ),
        letter_sections=(
            DocumentSection("Opening", (), (letter_slot.slot_id,)),
            DocumentSection(
                "Evidence Match",
                tuple(row.sentence_id for row in letter_candidate),
            ),
            DocumentSection(
                "Company Fit",
                tuple(row.sentence_id for row in letter_employer),
            ),
            DocumentSection("Close", (), (close_slot.slot_id,)),
        ),
        answers=tuple(
            StructuredAnswer(
                answer.question_id,
                answer.question,
                tuple(row.sentence_id for row in answer_facts),
                (answer_slot.slot_id,),
            )
            for answer in recovered.answers
        ),
    )
    artifacts = render_pdf_artifacts(source)
    questions = _questions(source)
    listing = "Software Engineer\nDeliver reliable services with tested evidence.\n"
    package = RecruiterAssessmentPackage(
        listing_text=listing,
        listing_text_sha256=hashlib.sha256(listing.encode()).hexdigest(),
        cv_pdf_bytes=artifacts.cv_pdf.pdf_bytes,
        cover_letter_pdf_bytes=artifacts.cover_letter_pdf.pdf_bytes,
        form_fields=canonical_form_fields(
            questions,
            cover_note=artifacts.editable.answers_text.strip(),
        ),
        intended_vacancy=IntendedVacancy(
            job_key=source.job_key,
            vacancy_sha256=source.vacancy_sha256,
            role_title=source.role_title,
            company_name=source.company_name,
        ),
    )
    receipt = assess_application_as_recruiter(
        package,
        client=_client(tmp_path, _RecruiterBackend(), "base-recruiter"),
    )
    support = next(
        row
        for row in source.facts
        if row.document_kind == "cv"
        and isinstance(row.authority, (FactAuthority, ProfileFactAuthority))
    )
    authority = support.authority
    provisional = ApplicationApprovedEvidence(
        evidence_id=authority.candidate_evidence_id,
        evidence_version=authority.candidate_evidence_version,
        claim_id=authority.candidate_claim_id,
        claim_version=authority.candidate_claim_version,
        approved_statement=support.approved_source_text,
        approved_statement_sha256=hashlib.sha256(
            support.approved_source_text.encode()
        ).hexdigest(),
        authority_receipt_sha256="0" * 64,
    )
    record = ApplicationApprovedEvidence(
        **{
            **vars(provisional),
            "authority_receipt_sha256": _EvidenceAuthority.receipt(provisional),
        }
    )
    return (
        source,
        artifacts,
        questions,
        package,
        receipt,
        support,
        _EvidenceAuthority((record,)),
    )


def _style_rebuild(source, *, document_kind: str = "cv"):
    slot = next(row for row in source.style_slots if row.document_kind == document_kind)
    proposed_text = "Evidence relevant to this role."
    receipt = ModelReceipt(
        provider="test.writer",
        model="bounded-style-rewriter-v1",
        prompt_sha256=hashlib.sha256(b"writer-prompt").hexdigest(),
        policy_sha256=hashlib.sha256(b"writer-policy").hexdigest(),
        input_sha256=hashlib.sha256(slot.text.encode()).hexdigest(),
        output_sha256=hashlib.sha256(proposed_text.encode()).hexdigest(),
    )
    proposal_id = content_hash(
        {
            "contract": "jaa07.style-proposal.v1",
            "input_sha256": receipt.input_sha256,
            "model": receipt.model,
            "output_sha256": receipt.output_sha256,
            "policy_sha256": receipt.policy_sha256,
            "prompt_sha256": receipt.prompt_sha256,
            "provider": receipt.provider,
            "slot_id": slot.slot_id,
        }
    )
    return (
        apply_style_proposal(
            source,
            StyleProposal(
                proposal_id=proposal_id,
                slot_id=slot.slot_id,
                original_text=slot.text,
                proposed_text=proposed_text,
                receipt=receipt,
            ),
        ),
        slot.slot_id,
    )


def test_full_application_rebuild_rerenders_and_rereviews_without_release_authority(
    tmp_path: Path,
) -> None:
    source, artifacts, questions, package, receipt, support, authority = _base(tmp_path)
    proposed, slot_id = _style_rebuild(source)
    application = ApplicationImprovementApplication(
        rank=1,
        supporting_sentence_ids=(support.sentence_id,),
        new_style_slot_ids=(slot_id,),
        removed_style_slot_ids=(slot_id,),
    )
    plan = plan_application_evidence_safe_rebuild(
        base_recruiter_receipt=receipt,
        base_recruiter_package=package,
        current_source=source,
        proposed_source=proposed,
        applications=(application,),
        evidence_authority=authority,
        questions=questions,
    )
    assert plan.accepted_improvement_ranks == (1,)
    assert [(row.source, row.source_index) for row in plan.roadmap] == [
        ("application_improvement", 1),
        ("profile_improvement", 0),
    ]
    assert plan.release_authority is False

    result = execute_application_evidence_safe_rebuild(
        plan=plan,
        base_recruiter_receipt=receipt,
        base_recruiter_package=package,
        current_source=source,
        proposed_source=proposed,
        applications=(application,),
        evidence_authority=authority,
        questions=questions,
        sanity_client=_client(tmp_path, FixturePassBackend(), "sanity"),
        recruiter_client=_client(tmp_path, _RecruiterBackend(), "rebuilt-recruiter"),
    )
    assert result.source.source_id != source.source_id
    assert result.artifacts.artifact_set_sha256 != artifacts.artifact_set_sha256
    assert result.recruiter_receipt.receipt_sha256 != receipt.receipt_sha256
    assert result.invalidated_recruiter_receipt_sha256 == receipt.receipt_sha256
    assert result.sanity_package.application_source_identity == proposed.source_id
    assert result.release_authority is False


def test_roadmap_only_rebuild_cannot_execute(tmp_path: Path) -> None:
    source, _, questions, package, receipt, _, authority = _base(tmp_path)
    plan = plan_application_evidence_safe_rebuild(
        base_recruiter_receipt=receipt,
        base_recruiter_package=package,
        current_source=source,
        proposed_source=source,
        applications=(),
        evidence_authority=authority,
        questions=questions,
    )
    assert plan.accepted_improvement_ranks == ()
    assert len(plan.roadmap) == 3
    with pytest.raises(AdversarialRebuildError, match="roadmap-only"):
        execute_application_evidence_safe_rebuild(
            plan=plan,
            base_recruiter_receipt=receipt,
            base_recruiter_package=package,
            current_source=source,
            proposed_source=source,
            applications=(),
            evidence_authority=authority,
            questions=questions,
            sanity_client=_client(tmp_path, FixturePassBackend(), "sanity"),
            recruiter_client=_client(
                tmp_path, _RecruiterBackend(), "rebuilt-recruiter"
            ),
        )


def test_improvement_cannot_authorize_another_application_target(
    tmp_path: Path,
) -> None:
    source, _, questions, package, receipt, support, authority = _base(tmp_path)
    proposed, slot_id = _style_rebuild(source, document_kind="cover_letter")
    with pytest.raises(AdversarialRebuildError, match="exact target"):
        plan_application_evidence_safe_rebuild(
            base_recruiter_receipt=receipt,
            base_recruiter_package=package,
            current_source=source,
            proposed_source=proposed,
            applications=(
                ApplicationImprovementApplication(
                    rank=1,
                    supporting_sentence_ids=(support.sentence_id,),
                    new_style_slot_ids=(slot_id,),
                    removed_style_slot_ids=(slot_id,),
                ),
            ),
            evidence_authority=authority,
            questions=questions,
        )


def test_execution_revalidates_and_rejects_evidence_revocation(
    tmp_path: Path,
) -> None:
    source, _, questions, package, receipt, support, authority = _base(tmp_path)
    proposed, slot_id = _style_rebuild(source)
    application = ApplicationImprovementApplication(
        rank=1,
        supporting_sentence_ids=(support.sentence_id,),
        new_style_slot_ids=(slot_id,),
        removed_style_slot_ids=(slot_id,),
    )
    plan = plan_application_evidence_safe_rebuild(
        base_recruiter_receipt=receipt,
        base_recruiter_package=package,
        current_source=source,
        proposed_source=proposed,
        applications=(application,),
        evidence_authority=authority,
        questions=questions,
    )
    authority.revoked = True
    with pytest.raises(AdversarialRebuildError, match="unavailable or revoked"):
        execute_application_evidence_safe_rebuild(
            plan=plan,
            base_recruiter_receipt=receipt,
            base_recruiter_package=package,
            current_source=source,
            proposed_source=proposed,
            applications=(application,),
            evidence_authority=authority,
            questions=questions,
            sanity_client=_client(tmp_path, FixturePassBackend(), "sanity"),
            recruiter_client=_client(
                tmp_path, _RecruiterBackend(), "rebuilt-recruiter"
            ),
        )
