from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from career_automation.adversarial_recruiter import (
    RecruiterAssessmentPackage,
    assess_application_as_recruiter,
)
from career_automation.external_document_assurance import IntendedVacancy
from career_automation.evidence_matching import content_hash
from career_automation.rendering import _build_text_pdf
from career_automation.testing_adversarial_recruiter import (
    fixture_recruiter_result,
)
from cv_generation.adversarial_rebuild import (
    AdversarialRebuildError,
    bind_recruiter_improvement,
    finalize_rebuilt_cv,
    rebuild_from_recruiter_assessment,
    render_editorial_cv_text,
)
from cv_generation.editorial_composition import (
    ApprovedCVClaim,
    CVSection,
    CandidateEditorialAuthority,
    EditorialAtom,
    EditorialStageEvidence,
    admit_editorial_composition,
    build_editorial_draft,
    build_editorial_request,
    humanizer_request_sha256,
)
from llm.client import Backend, LLMClient, LLMResponse


TITLE = (
    "SCAFAD: A Seven-Layer, Privacy-Preserving, Explainable "
    "Anomaly-Detection Pipeline for Serverless Workloads"
)


class _ScriptedRecruiter(Backend):
    name = "detached-rebuild-fixture"

    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        del system, user, temperature
        return LLMResponse(text=json.dumps(_recruiter_result()), model="fixture-v1")


def _claim(claim_id: str, text: str, category: str) -> ApprovedCVClaim:
    return ApprovedCVClaim(
        claim_id=claim_id,
        text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        evidence_ids=(f"candidate-evidence:{claim_id}",),
        category=category,
    )


def _recruiter_result() -> dict[str, object]:
    value = fixture_recruiter_result()
    value.update({
        "strengths": [
            {
                "location": "cv:projects",
                "assessment": "Relevant automation project.",
                "outward_evidence_refs": ["cv:char:0:1"],
            }
        ],
        "risks": [
            {
                "category": "skills",
                "severity": "medium",
                "location": "cv:projects",
                "assessment": "The closest project is not prominent enough.",
                "outward_evidence_refs": ["cv:char:0:1"],
            }
        ],
        "application_improvements": [
            {
                "rank": 1,
                "target": "cv",
                "recommendation": "Lead with the strongest automation project.",
                "expected_effect": "Makes the closest evidence visible sooner.",
                "support_required": False,
                "outward_evidence_refs": ["cv:char:0:1"],
            },
            {
                "rank": 2,
                "target": "cv",
                "recommendation": "Claim five years of Kubernetes ownership.",
                "expected_effect": "Would address a stated platform requirement.",
                "support_required": True,
                "outward_evidence_refs": ["job_listing:char:0:1"],
            },
        ],
        "profile_improvements": [
            {
                "category": "experience",
                "recommendation": "Build evidence of operating a larger deployed service.",
                "time_horizon": "months",
                "expected_effect": "Addresses the remaining production-depth gap.",
            }
        ],
    })
    return value


def _pdf(text: str) -> bytes:
    return _build_text_pdf((tuple(text.splitlines()),))


def _fixture(tmp_path):
    listing = "Build reliable AI automation and operate production services."
    listing_sha256 = hashlib.sha256(listing.encode()).hexdigest()
    authority = CandidateEditorialAuthority(
        candidate_name="Artiom Gutu",
        candidate_city="Birmingham, United Kingdom",
        graduation_month_year="July 2026",
        dissertation_title=TITLE,
        source_sha256="a" * 64,
        require_dissertation=True,
    )
    claims = (
        _claim(
            "summary",
            "AI systems engineer focused on reliable automation.",
            "summary",
        ),
        _claim(
            "capability",
            "AI orchestration, systems design, workflow automation and assurance.",
            "capability_domain",
        ),
        _claim(
            "project-existing",
            "Built a tested evidence-processing workflow.",
            "project",
        ),
        _claim(
            "project-strongest",
            "Built an evidence-bound multi-agent orchestration system.",
            "project",
        ),
        _claim(
            "education",
            f"First-Class BSc (Hons) Computer Science, July 2026. Dissertation: {TITLE}.",
            "education",
        ),
    )
    request = build_editorial_request(
        authority=authority,
        role_title="AI Automation Engineer",
        company_name="Example Systems",
        vacancy_sha256=listing_sha256,
        approved_claims=claims,
    )
    sections = (
        CVSection(
            "Professional Summary",
            (EditorialAtom("approved_claim", claims[0].text, claims[0].claim_id),),
        ),
        CVSection(
            "Core Capabilities",
            (EditorialAtom("approved_claim", claims[1].text, claims[1].claim_id),),
        ),
        CVSection(
            "Projects",
            (EditorialAtom("approved_claim", claims[2].text, claims[2].claim_id),),
        ),
        CVSection(
            "Education",
            (EditorialAtom("approved_claim", claims[4].text, claims[4].claim_id),),
        ),
    )
    draft = build_editorial_draft(
        candidate_name=authority.candidate_name,
        candidate_city=authority.candidate_city,
        sections=sections,
    )
    writer = EditorialStageEvidence(
        stage="resume_writer",
        environment="synthetic",
        provider="fixture-writer",
        model="fixture-v1",
        invocation_id="writer-session",
        request_sha256=request.request_sha256,
        response_sha256=draft.draft_sha256,
    )
    humanizer = EditorialStageEvidence(
        stage="humanizer",
        environment="synthetic",
        provider="fixture-humanizer",
        model="fixture-v1",
        invocation_id="humanizer-session",
        request_sha256=humanizer_request_sha256(request, draft),
        response_sha256=draft.draft_sha256,
    )
    _, _, editorial_receipt = admit_editorial_composition(
        request=request,
        writer_draft=draft,
        final_draft=draft,
        writer_evidence=writer,
        humanizer_evidence=humanizer,
    )
    package = RecruiterAssessmentPackage(
        listing_text=listing,
        listing_text_sha256=listing_sha256,
        cv_pdf_bytes=_pdf(render_editorial_cv_text(draft)),
        cover_letter_pdf_bytes=_pdf("Evidence-bound synthetic cover letter."),
        form_fields=(),
        intended_vacancy=IntendedVacancy(
            "example:ai-automation",
            hashlib.sha256(b"vacancy body").hexdigest(),
            request.role_title,
            request.company_name,
        ),
    )
    client = LLMClient(
        backend=_ScriptedRecruiter(),
        model="fixture-v1",
        temperature=0,
        max_retries=1,
        cache_enabled=False,
        cache_dir=tmp_path / "cache",
        usage_log=tmp_path / "usage.jsonl",
    )
    recruiter_receipt = assess_application_as_recruiter(package, client=client)
    binding = bind_recruiter_improvement(
        improvement_index=0,
        target_heading="Projects",
        claim_ids=("project-strongest",),
        authority_source_sha256=authority.source_sha256,
        model_result_sha256=recruiter_receipt.model_result_sha256,
        binding_source_sha256="c" * 64,
    )
    return request, draft, editorial_receipt, package, recruiter_receipt, binding


def test_applies_only_evidence_bound_improvement_and_routes_gaps(tmp_path) -> None:
    request, draft, editorial, package, recruiter, binding = _fixture(tmp_path)
    rebuilt = rebuild_from_recruiter_assessment(
        request=request,
        admitted_draft=draft,
        editorial_receipt=editorial,
        recruiter_receipt=recruiter,
        recruiter_package=package,
        bindings=(binding,),
    )

    projects = next(
        section for section in rebuilt.rebuilt_draft.sections if section.heading == "Projects"
    )
    assert [atom.claim_id for atom in projects.atoms] == [
        "project-strongest",
        "project-existing",
    ]
    assert [item.claim_ids for item in rebuilt.applied] == [("project-strongest",)]
    assert [item.reason_code for item in rebuilt.roadmap] == [
        "unsupported_by_candidate_authority",
        "profile_gap_not_current_cv_evidence",
    ]
    assert "Kubernetes" not in render_editorial_cv_text(rebuilt.rebuilt_draft)
    assert rebuilt.release_authority is False


def test_final_rebuild_runs_through_existing_cv_constraint_gate(tmp_path) -> None:
    request, draft, editorial, package, recruiter, binding = _fixture(tmp_path)
    rebuilt = rebuild_from_recruiter_assessment(
        request=request,
        admitted_draft=draft,
        editorial_receipt=editorial,
        recruiter_receipt=recruiter,
        recruiter_package=package,
        bindings=(binding,),
    )
    cv_text = render_editorial_cv_text(rebuilt.rebuilt_draft)
    finalized = finalize_rebuilt_cv(
        request=request,
        rebuild=rebuilt,
        rendered_pages=(tuple(cv_text.splitlines()),),
    )

    assert finalized.constraint_receipt.passed is True
    assert finalized.constraint_receipt.source_id == rebuilt.rebuild_sha256
    assert finalized.constraint_receipt.release_authority is False
    assert finalized.release_authority is False
    assert "Curriculum Vitae" not in finalized.cv_text
    assert "work rights" not in finalized.cv_text.casefold()


def test_unknown_claim_and_wrong_authority_bindings_fail_closed(tmp_path) -> None:
    request, draft, editorial, package, recruiter, binding = _fixture(tmp_path)
    unknown = bind_recruiter_improvement(
        improvement_index=0,
        target_heading="Projects",
        claim_ids=("invented-claim",),
        authority_source_sha256=request.authority.source_sha256,
        model_result_sha256=recruiter.model_result_sha256,
        binding_source_sha256="d" * 64,
    )
    with pytest.raises(AdversarialRebuildError, match="unapproved"):
        rebuild_from_recruiter_assessment(
            request=request,
            admitted_draft=draft,
            editorial_receipt=editorial,
            recruiter_receipt=recruiter,
            recruiter_package=package,
            bindings=(unknown,),
        )

    wrong_authority = bind_recruiter_improvement(
        improvement_index=0,
        target_heading="Projects",
        claim_ids=binding.claim_ids,
        authority_source_sha256="e" * 64,
        model_result_sha256=recruiter.model_result_sha256,
        binding_source_sha256="d" * 64,
    )
    with pytest.raises(AdversarialRebuildError, match="different authority"):
        rebuild_from_recruiter_assessment(
            request=request,
            admitted_draft=draft,
            editorial_receipt=editorial,
            recruiter_receipt=recruiter,
            recruiter_package=package,
            bindings=(wrong_authority,),
        )


def test_diagnostic_receipt_cannot_mutate_an_unadmitted_draft(tmp_path) -> None:
    request, draft, editorial, package, recruiter, binding = _fixture(tmp_path)
    with pytest.raises(ValueError, match="identity is invalid"):
        replace(editorial, final_draft_sha256="f" * 64)

    strongest = next(
        claim for claim in request.approved_claims if claim.claim_id == "project-strongest"
    )
    projects = draft.sections[2]
    unadmitted = build_editorial_draft(
        candidate_name=draft.candidate_name,
        candidate_city=draft.candidate_city,
        sections=(
            *draft.sections[:2],
            replace(
                projects,
                atoms=(
                    *projects.atoms,
                    EditorialAtom(
                        "approved_claim", strongest.text, strongest.claim_id
                    ),
                ),
            ),
            *draft.sections[3:],
        ),
    )
    with pytest.raises(AdversarialRebuildError, match="lacks its admission receipt"):
        rebuild_from_recruiter_assessment(
            request=request,
            admitted_draft=unadmitted,
            editorial_receipt=editorial,
            recruiter_receipt=recruiter,
            recruiter_package=package,
            bindings=(binding,),
        )


def test_recruiter_assessment_must_match_exact_vacancy_and_package(tmp_path) -> None:
    request, draft, editorial, package, recruiter, binding = _fixture(tmp_path)
    different_package = replace(package, cv_pdf_bytes=_pdf("Different CV"))
    with pytest.raises(ValueError, match="differs"):
        rebuild_from_recruiter_assessment(
            request=request,
            admitted_draft=draft,
            editorial_receipt=editorial,
            recruiter_receipt=recruiter,
            recruiter_package=different_package,
            bindings=(binding,),
        )

    other_package = replace(package, cv_pdf_bytes=_pdf("Artiom Gutu\nDifferent CV"))
    other_client = LLMClient(
        backend=_ScriptedRecruiter(),
        model="fixture-v1",
        temperature=0,
        max_retries=1,
        cache_enabled=False,
        cache_dir=tmp_path / "other-cache",
        usage_log=tmp_path / "other-usage.jsonl",
    )
    other_receipt = assess_application_as_recruiter(other_package, client=other_client)
    with pytest.raises(AdversarialRebuildError, match="did not inspect"):
        rebuild_from_recruiter_assessment(
            request=request,
            admitted_draft=draft,
            editorial_receipt=editorial,
            recruiter_receipt=other_receipt,
            recruiter_package=other_package,
            bindings=(),
        )

    different_request = build_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name="Another Company",
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=request.approved_claims,
    )
    writer = EditorialStageEvidence(
        stage="resume_writer",
        environment="synthetic",
        provider="fixture-writer",
        model="fixture-v1",
        invocation_id="different-writer-session",
        request_sha256=different_request.request_sha256,
        response_sha256=draft.draft_sha256,
    )
    humanizer = EditorialStageEvidence(
        stage="humanizer",
        environment="synthetic",
        provider="fixture-humanizer",
        model="fixture-v1",
        invocation_id="different-humanizer-session",
        request_sha256=humanizer_request_sha256(different_request, draft),
        response_sha256=draft.draft_sha256,
    )
    _, _, different_editorial = admit_editorial_composition(
        request=different_request,
        writer_draft=draft,
        final_draft=draft,
        writer_evidence=writer,
        humanizer_evidence=humanizer,
    )
    with pytest.raises(AdversarialRebuildError, match="another vacancy"):
        rebuild_from_recruiter_assessment(
            request=different_request,
            admitted_draft=draft,
            editorial_receipt=different_editorial,
            recruiter_receipt=recruiter,
            recruiter_package=package,
            bindings=(binding,),
        )


def test_non_cv_improvement_cannot_receive_cv_claim_binding(tmp_path) -> None:
    request, draft, editorial, package, recruiter, _ = _fixture(tmp_path)
    result = dict(recruiter.model_result)
    improvements = [dict(item) for item in result["application_improvements"]]
    improvements[0]["target"] = "cover_letter"
    result["application_improvements"] = improvements
    model_result_sha256 = content_hash(result)
    preimage = recruiter.document(include_identity=False)
    preimage["model_result"] = result
    preimage["model_result_sha256"] = model_result_sha256
    recruiter = replace(
        recruiter,
        model_result=result,
        model_result_sha256=model_result_sha256,
        receipt_sha256=content_hash(preimage),
    )
    binding = bind_recruiter_improvement(
        improvement_index=0,
        target_heading="Projects",
        claim_ids=("project-strongest",),
        authority_source_sha256=request.authority.source_sha256,
        model_result_sha256=recruiter.model_result_sha256,
        binding_source_sha256="d" * 64,
    )
    with pytest.raises(AdversarialRebuildError, match="non-CV"):
        rebuild_from_recruiter_assessment(
            request=request,
            admitted_draft=draft,
            editorial_receipt=editorial,
            recruiter_receipt=recruiter,
            recruiter_package=package,
            bindings=(binding,),
        )


def test_continuation_banner_is_still_rejected_after_rebuild(tmp_path) -> None:
    request, draft, editorial, package, recruiter, binding = _fixture(tmp_path)
    rebuilt = rebuild_from_recruiter_assessment(
        request=request,
        admitted_draft=draft,
        editorial_receipt=editorial,
        recruiter_receipt=recruiter,
        recruiter_package=package,
        bindings=(binding,),
    )
    with pytest.raises(ValueError, match="continuation pages"):
        finalize_rebuilt_cv(
            request=request,
            rebuild=rebuilt,
            rendered_pages=(
                ("Artiom Gutu", "page one"),
                ("Artiom Gutu", "page two"),
            ),
        )
