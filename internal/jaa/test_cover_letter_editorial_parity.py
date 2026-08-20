from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from career_automation.adversarial_recruiter import (
    RESULT_SCHEMA_VERSION,
    RecruiterAssessmentPackage,
    assess_application_as_recruiter,
)
from career_automation.evidence_matching import canonical_json
from career_automation.external_document_assurance import IntendedVacancy
from career_automation.rendering import _build_text_pdf
from cv_generation.adversarial_rebuild import (
    AdversarialRebuildError,
    bind_cover_letter_recruiter_improvement,
    rebuild_cover_letter_from_recruiter_assessment,
)
from cv_generation.editorial_composition import (
    ApprovedCoverLetterClaim,
    CandidateEditorialAuthority,
    CoverLetterSection,
    EditorialAtom,
    EditorialBackendResult,
    EditorialCompositionError,
    EditorialCompositionRuntime,
    EditorialStageEvidence,
    admit_cover_letter_editorial_composition,
    build_cover_letter_editorial_draft,
    build_cover_letter_editorial_request,
    cover_letter_humanizer_request_sha256,
    run_cover_letter_composition_runtime,
    validate_cover_letter_editorial_draft,
)
from llm.client import Backend, LLMClient, LLMResponse


def _claim(
    claim_id: str,
    text: str,
    fact_kind: str,
    section_heading: str,
) -> ApprovedCoverLetterClaim:
    return ApprovedCoverLetterClaim(
        claim_id=claim_id,
        text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        evidence_ids=(f"evidence:{claim_id}",),
        fact_kind=fact_kind,
        section_heading=section_heading,
    )


def _fixture():
    listing = "Example Systems needs an engineer to build reliable AI automation."
    authority = CandidateEditorialAuthority(
        candidate_name="Artiom Gutu",
        candidate_city="Birmingham, United Kingdom",
        graduation_month_year="July 2026",
        dissertation_title="Verified Systems Dissertation",
        source_sha256="a" * 64,
    )
    claims = (
        _claim(
            "candidate-primary",
            "Built an evidence-bound multi-agent orchestration system.",
            "candidate",
            "Evidence Match",
        ),
        _claim(
            "candidate-secondary",
            "Designed deterministic workflow automation with bounded authority.",
            "candidate",
            "Evidence Match",
        ),
        _claim(
            "employer-primary",
            "Example Systems is hiring for reliable AI automation.",
            "employer",
            "Company Fit",
        ),
        _claim(
            "employer-secondary",
            "Example Systems requires evidence-led engineering decisions.",
            "employer",
            "Company Fit",
        ),
    )
    request = build_cover_letter_editorial_request(
        authority=authority,
        role_title="AI Automation Engineer",
        company_name="Example Systems",
        vacancy_sha256=hashlib.sha256(listing.encode()).hexdigest(),
        approved_claims=claims,
    )
    sections = (
        CoverLetterSection(
            "Opening",
            (EditorialAtom("connective", "Dear Hiring Manager,", None),),
        ),
        CoverLetterSection(
            "Evidence Match",
            (
                EditorialAtom("connective", "My closest evidence is direct:", None),
                EditorialAtom("approved_claim", claims[0].text, claims[0].claim_id),
                EditorialAtom("approved_claim", claims[1].text, claims[1].claim_id),
            ),
        ),
        CoverLetterSection(
            "Company Fit",
            (
                EditorialAtom("connective", "The role caught my attention for a concrete reason:", None),
                EditorialAtom("approved_claim", claims[2].text, claims[2].claim_id),
                EditorialAtom("approved_claim", claims[3].text, claims[3].claim_id),
            ),
        ),
        CoverLetterSection(
            "Close",
            (
                EditorialAtom("connective", "I would welcome a conversation about the work.", None),
                EditorialAtom("connective", "Kind regards", None),
                EditorialAtom("connective", authority.candidate_name, None),
            ),
        ),
    )
    writer = build_cover_letter_editorial_draft(
        candidate_name=authority.candidate_name,
        sections=sections,
    )
    final = build_cover_letter_editorial_draft(
        candidate_name=authority.candidate_name,
        sections=(
            sections[0],
            replace(
                sections[1],
                atoms=(
                    EditorialAtom("connective", "The strongest match is practical:", None),
                    *sections[1].atoms[1:],
                ),
            ),
            *sections[2:],
        ),
    )
    return listing, request, claims, writer, final


def _evidence(request, writer, final):
    return (
        EditorialStageEvidence(
            stage="cover_letter_writer",
            environment="synthetic",
            provider="fixture-writer",
            model="fixture-v1",
            invocation_id="cover-writer-session",
            request_sha256=request.request_sha256,
            response_sha256=writer.draft_sha256,
        ),
        EditorialStageEvidence(
            stage="cover_letter_humanizer",
            environment="synthetic",
            provider="fixture-humanizer",
            model="fixture-v1",
            invocation_id="cover-humanizer-session",
            request_sha256=cover_letter_humanizer_request_sha256(request, writer),
            response_sha256=final.draft_sha256,
        ),
    )


class _Session:
    def __init__(self, adapter, invocation_id):
        self.adapter = adapter
        self.invocation_id = invocation_id

    def invoke(self, *, request_bytes):
        self.adapter.calls.append((request_bytes, self.invocation_id))
        response = canonical_json(self.adapter.draft.document()).encode()
        return EditorialBackendResult(
            response_bytes=response,
            invocation_id=self.invocation_id,
            environment=self.adapter.environment,
            provider=self.adapter.provider,
            model=self.adapter.model,
            transport_identity=self.adapter.transport_identity,
            request_sha256=hashlib.sha256(request_bytes).hexdigest(),
            response_sha256=hashlib.sha256(response).hexdigest(),
            executable_sha256="e" * 64,
        )


class _Adapter:
    def __init__(self, stage, provider, draft):
        self.stage = stage
        self.provider = provider
        self.model = "fixture-v1"
        self.draft = draft
        self.environment = "synthetic"
        self.transport_identity = f"transport:{provider}"
        self.calls = []

    def available(self):
        return True

    def open_fresh_session(self, *, invocation_id):
        return _Session(self, invocation_id)


def test_cover_letter_runtime_uses_distinct_one_shot_writer_and_humanizer() -> None:
    _, request, _, writer, final = _fixture()
    writer_adapter = _Adapter("cover_letter_writer", "writer", writer)
    humanizer_adapter = _Adapter("cover_letter_humanizer", "humanizer", final)
    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=writer_adapter,
        humanizer=humanizer_adapter,
        document_kind="cover_letter",
    )
    result = run_cover_letter_composition_runtime(request, runtime=runtime)
    assert result[:2] == (writer, final)
    assert len(writer_adapter.calls) == len(humanizer_adapter.calls) == 1
    assert writer_adapter.calls[0][1] != humanizer_adapter.calls[0][1]
    writer_request = json.loads(writer_adapter.calls[0][0])
    humanizer_request = json.loads(humanizer_adapter.calls[0][0])
    assert writer_request["stage"] == "cover_letter_writer"
    assert humanizer_request["stage"] == "cover_letter_humanizer"
    assert "approved_claim" in " ".join(writer_request["instructions"])
    assert "em dash" in " ".join(humanizer_request["instructions"])


def test_cover_letter_admission_rejects_claim_mutation_and_kolhoz_text() -> None:
    _, request, _, writer, final = _fixture()
    writer_evidence, humanizer_evidence = _evidence(request, writer, final)
    admit_cover_letter_editorial_composition(
        request=request,
        writer_draft=writer,
        final_draft=final,
        writer_evidence=writer_evidence,
        humanizer_evidence=humanizer_evidence,
    )
    changed_claim = replace(
        final.sections[1].atoms[1], text="Invented five years of production ownership."
    )
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            final.sections[0],
            replace(final.sections[1], atoms=(final.sections[1].atoms[0], changed_claim, final.sections[1].atoms[2])),
            *final.sections[2:],
        ),
    )
    with pytest.raises(EditorialCompositionError, match="changed or invented"):
        validate_cover_letter_editorial_draft(request, changed)
    kolhoz = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            replace(final.sections[0], atoms=(EditorialAtom("connective", "I am applying — with great enthusiasm.", None),)),
            *final.sections[1:],
        ),
    )
    with pytest.raises(
        EditorialCompositionError,
        match="factual claim|Humanizer policy",
    ):
        validate_cover_letter_editorial_draft(request, kolhoz)


@pytest.mark.parametrize(
    ("opening_text", "expected"),
    (
        ("Built Kubernetes clusters.", "authority-bearing content"),
        ("Example Systems is exactly where I belong.", "authority-bearing content"),
    ),
)
def test_cover_letter_rejects_authority_content_smuggled_as_connective(
    opening_text: str,
    expected: str,
) -> None:
    _, request, _, _, final = _fixture()
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            replace(
                final.sections[0],
                atoms=(EditorialAtom("connective", opening_text, None),),
            ),
            *final.sections[1:],
        ),
    )
    with pytest.raises(EditorialCompositionError, match=expected):
        validate_cover_letter_editorial_draft(request, changed)


def test_cover_letter_rejects_connective_after_exact_factual_span() -> None:
    _, request, _, _, final = _fixture()
    evidence_match = final.sections[1]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            final.sections[0],
            replace(
                evidence_match,
                atoms=(
                    *evidence_match.atoms,
                    EditorialAtom("connective", "That is the practical match.", None),
                ),
            ),
            *final.sections[2:],
        ),
    )
    with pytest.raises(EditorialCompositionError, match="cannot follow"):
        validate_cover_letter_editorial_draft(request, changed)


def _result() -> dict[str, object]:
    reaction = {
        "progression_probability_percent": 61,
        "verdict": "progress",
        "reasons": ["The application uses relevant evidence."],
    }
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "calibration_status": "uncalibrated",
        "fit_percent": 62,
        "fit_range_percent": {"low": 50, "high": 72},
        "overall_verdict": "strong_fit",
        "ats_reaction": reaction,
        "human_reaction": reaction,
        "strengths": [{"location": "cover_letter", "assessment": "Specific evidence."}],
        "risks": [{"category": "relevance", "severity": "low", "location": "cover_letter", "assessment": "Employer proof could appear sooner."}],
        "application_improvements": [
            {"target": "cover_letter", "recommendation": "Lead with the evidence-led employer fact.", "expected_effect": "Makes the company match visible sooner."},
            {"target": "cover_letter", "recommendation": "Add five years of unsupported ownership.", "expected_effect": "Would inflate seniority."},
            {"target": "cv", "recommendation": "Change the CV order.", "expected_effect": "Moves project evidence."},
        ],
        "profile_improvements": [{"category": "experience", "recommendation": "Build larger-scale evidence.", "time_horizon": "months", "expected_effect": "Strengthens future applications."}],
    }


class _Recruiter(Backend):
    name = "cover-letter-recruiter-fixture"

    def available(self):
        return True

    def complete(self, system, user, temperature):
        del system, user, temperature
        return LLMResponse(text=json.dumps(_result()), model="fixture-v1")


def test_recruiter_applies_only_bound_cover_advice_and_routes_unsupported(tmp_path) -> None:
    listing, request, _, writer, final = _fixture()
    writer_evidence, humanizer_evidence = _evidence(request, writer, final)
    _, _, editorial = admit_cover_letter_editorial_composition(
        request=request, writer_draft=writer, final_draft=final,
        writer_evidence=writer_evidence, humanizer_evidence=humanizer_evidence,
    )
    package = RecruiterAssessmentPackage(
        listing_text=listing,
        listing_text_sha256=request.vacancy_sha256,
        cv_pdf_bytes=_build_text_pdf((("Synthetic CV",),)),
        cover_letter_pdf_bytes=_build_text_pdf((tuple(atom.text for section in final.sections for atom in section.atoms),)),
        form_fields=(),
        intended_vacancy=IntendedVacancy("example:role", "b" * 64, request.role_title, request.company_name),
    )
    receipt = assess_application_as_recruiter(
        package,
        client=LLMClient(
            backend=_Recruiter(), model="fixture-v1", temperature=0, max_retries=1,
            cache_enabled=False, cache_dir=tmp_path / "cache", usage_log=tmp_path / "usage.jsonl",
        ),
    )
    binding = bind_cover_letter_recruiter_improvement(
        improvement_index=0,
        target_heading="Company Fit",
        claim_ids=("employer-secondary",),
        authority_source_sha256=request.authority.source_sha256,
        vacancy_sha256=request.vacancy_sha256,
        model_result_sha256=receipt.model_result_sha256,
        binding_source_sha256="c" * 64,
    )
    rebuilt = rebuild_cover_letter_from_recruiter_assessment(
        request=request,
        admitted_draft=final,
        editorial_receipt=editorial,
        recruiter_receipt=receipt,
        recruiter_package=package,
        bindings=(binding,),
        assessed_cover_letter_text_sha256=receipt.package_hashes["cover_letter_text_sha256"],
    )
    company = next(section for section in rebuilt.rebuilt_draft.sections if section.heading == "Company Fit")
    assert [atom.claim_id for atom in company.atoms if atom.claim_id] == [
        "employer-secondary", "employer-primary"
    ]
    assert [item.improvement_index for item in rebuilt.applied] == [0]
    assert [(item.source_index, item.reason_code) for item in rebuilt.roadmap] == [
        (1, "unsupported_by_candidate_or_vacancy_authority")
    ]
    substituted = bind_cover_letter_recruiter_improvement(
        improvement_index=0,
        target_heading="Company Fit",
        claim_ids=("employer-secondary",),
        authority_source_sha256=request.authority.source_sha256,
        vacancy_sha256="f" * 64,
        model_result_sha256=receipt.model_result_sha256,
        binding_source_sha256="c" * 64,
    )
    with pytest.raises(AdversarialRebuildError, match="different authority"):
        rebuild_cover_letter_from_recruiter_assessment(
            request=request, admitted_draft=final, editorial_receipt=editorial,
            recruiter_receipt=receipt, recruiter_package=package, bindings=(substituted,),
            assessed_cover_letter_text_sha256=receipt.package_hashes["cover_letter_text_sha256"],
        )
