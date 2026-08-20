from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from career_automation.adversarial_recruiter import (
    RESULT_SCHEMA_VERSION,
    RecruiterAssessmentReceipt,
    assess_application_as_recruiter,
)
from career_automation.evidence_matching import content_hash
from cv_generation.adversarial_rebuild import bind_recruiter_improvement
from cv_generation.constraints import CVConstraintReceipt
from cv_generation.editorial_composition import (
    ApprovedCVClaim,
    CVSection,
    CandidateEditorialAuthority,
    EditorialAtom,
    EditorialStageEvidence,
    build_editorial_draft,
    build_editorial_request,
    humanizer_request_sha256,
)
from cv_generation.service import (
    CVCompositionServiceError,
    run_cv_composition_orchestration,
)
from llm.client import Backend, LLMClient, LLMResponse
from test_jaa07_independent_acceptance import _source


class _ScriptedRecruiterBackend(Backend):
    name = "offline-service-fixture"

    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, temperature: float) -> LLMResponse:
        del system, user, temperature
        return LLMResponse(text=json.dumps(_recruiter_result()), model="fixture-v1")


class _InjectedAssessor:
    def __init__(self, tmp_path) -> None:
        self.calls = 0
        self.client = LLMClient(
            backend=_ScriptedRecruiterBackend(),
            model="fixture-v1",
            temperature=0,
            max_retries=1,
            cache_enabled=False,
            cache_dir=tmp_path / "cache",
            usage_log=tmp_path / "usage.jsonl",
        )

    def __call__(self, package):
        self.calls += 1
        return assess_application_as_recruiter(package, client=self.client)


def _recruiter_result() -> dict[str, object]:
    reaction = {
        "progression_probability_percent": 54,
        "verdict": "borderline",
        "reasons": ["The evidence is relevant but compact."],
    }
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "calibration_status": "uncalibrated",
        "fit_percent": 53,
        "fit_range_percent": {"low": 40, "high": 65},
        "overall_verdict": "plausible_fit",
        "ats_reaction": reaction,
        "human_reaction": reaction,
        "strengths": [
            {"location": "cv:summary", "assessment": "Reliable delivery evidence."}
        ],
        "risks": [
            {
                "category": "experience",
                "severity": "medium",
                "location": "cv",
                "assessment": "The application has limited production scale detail.",
            }
        ],
        "application_improvements": [
            {
                "target": "positioning",
                "recommendation": "Keep the reliable delivery evidence prominent.",
                "expected_effect": "Preserves the clearest role match.",
            },
            {
                "target": "cv",
                "recommendation": "Add unsupported Kubernetes ownership.",
                "expected_effect": "Would address an unstated platform gap.",
            },
        ],
        "profile_improvements": [
            {
                "category": "experience",
                "recommendation": "Gather evidence from a larger deployed service.",
                "time_horizon": "months",
                "expected_effect": "Would strengthen production-depth evidence.",
            }
        ],
    }


def _claim(claim_id: str, category: str) -> ApprovedCVClaim:
    text = "Delivered reliable services with tested evidence."
    return ApprovedCVClaim(
        claim_id=claim_id,
        text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        evidence_ids=(f"evidence:{claim_id}",),
        category=category,
    )


def _fixture(tmp_path):
    base_source, _ = _source()
    listing = "Deliver reliable services for Example Ltd."
    authority = CandidateEditorialAuthority(
        candidate_name="Alex Example",
        candidate_city="London",
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256="a" * 64,
    )
    summary = _claim("summary", "summary")
    capability = _claim("capability", "capability_domain")
    request = build_editorial_request(
        authority=authority,
        role_title=base_source.role_title,
        company_name=base_source.company_name,
        vacancy_sha256=hashlib.sha256(listing.encode()).hexdigest(),
        approved_claims=(summary, capability),
    )
    draft = build_editorial_draft(
        candidate_name=authority.candidate_name,
        candidate_city=authority.candidate_city,
        sections=(
            CVSection(
                "Professional Summary",
                (EditorialAtom("approved_claim", summary.text, summary.claim_id),),
            ),
            CVSection(
                "Core Capabilities",
                (
                    EditorialAtom(
                        "approved_claim", capability.text, capability.claim_id
                    ),
                ),
            ),
        ),
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
    assessor = _InjectedAssessor(tmp_path)
    return base_source, listing, request, draft, writer, humanizer, assessor


def _binding(request, recruiter_receipt: RecruiterAssessmentReceipt):
    return bind_recruiter_improvement(
        improvement_index=0,
        target_heading="Professional Summary",
        claim_ids=("summary",),
        authority_source_sha256=request.authority.source_sha256,
        model_result_sha256=recruiter_receipt.model_result_sha256,
        binding_source_sha256="b" * 64,
    )


def test_offline_injected_service_runs_the_complete_cv_cycle(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)

    first = run_cv_composition_orchestration(
        request=request,
        writer_draft=draft,
        humanized_draft=draft,
        writer_evidence=writer,
        humanizer_evidence=humanizer,
        base_source=base,
        listing_text=listing,
        form_fields=(),
        bindings=(),
        recruiter_assessor=assessor,
        improvement_binder=lambda current_request, receipt: (
            _binding(current_request, receipt),
        ),
    )

    assert assessor.calls == 1
    assert first.editorial_receipt.release_authority is False
    assert first.initial_constraint_receipt.passed is True
    assert first.recruiter_receipt.mutation_authority is False
    assert len(first.rebuild.applied) == 1
    assert [item.reason_code for item in first.rebuild.roadmap] == [
        "unsupported_by_candidate_authority",
        "profile_gap_not_current_cv_evidence",
    ]
    assert first.final_constraint_receipt.passed is True
    assert first.final_artifacts.cv_pdf.pdf_bytes.startswith(b"%PDF-1.4\n")
    assert first.final_artifacts.cover_letter_pdf.pdf_bytes.startswith(b"%PDF-1.4\n")
    assert first.release_authority is False


def test_precomputed_receipt_path_applies_only_bound_claims(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)
    diagnostic = run_cv_composition_orchestration(
        request=request,
        writer_draft=draft,
        humanized_draft=draft,
        writer_evidence=writer,
        humanizer_evidence=humanizer,
        base_source=base,
        listing_text=listing,
        form_fields=(),
        bindings=(),
        recruiter_assessor=assessor,
    )
    replay = run_cv_composition_orchestration(
        request=request,
        writer_draft=draft,
        humanized_draft=draft,
        writer_evidence=writer,
        humanizer_evidence=humanizer,
        base_source=base,
        listing_text=listing,
        form_fields=(),
        bindings=(_binding(request, diagnostic.recruiter_receipt),),
        recruiter_receipt=diagnostic.recruiter_receipt,
    )

    assert len(replay.rebuild.applied) == 1
    assert replay.rebuild.applied[0].claim_ids == ("summary",)
    assert [item.reason_code for item in replay.rebuild.roadmap] == [
        "unsupported_by_candidate_authority",
        "profile_gap_not_current_cv_evidence",
    ]
    assert replay.final_artifacts.artifact_set_sha256
    assert replay.orchestration_sha256


def test_service_never_selects_a_provider_implicitly(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, _ = _fixture(tmp_path)
    values = {
        "request": request,
        "writer_draft": draft,
        "humanized_draft": draft,
        "writer_evidence": writer,
        "humanizer_evidence": humanizer,
        "base_source": base,
        "listing_text": listing,
        "form_fields": (),
        "bindings": (),
    }
    with pytest.raises(CVCompositionServiceError, match="exactly one"):
        run_cv_composition_orchestration(**values)
    with pytest.raises(CVCompositionServiceError, match="valid receipt"):
        run_cv_composition_orchestration(
            **values,
            recruiter_assessor=lambda package: None,
        )


def test_listing_and_canonical_artifact_authority_fail_closed(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)
    with pytest.raises(CVCompositionServiceError, match="job listing differs"):
        run_cv_composition_orchestration(
            request=request,
            writer_draft=draft,
            humanized_draft=draft,
            writer_evidence=writer,
            humanizer_evidence=humanizer,
            base_source=base,
            listing_text="Different listing",
            form_fields=(),
            bindings=(),
            recruiter_assessor=assessor,
        )

    unavailable = ApprovedCVClaim(
        claim_id="unavailable",
        text="Owned Kubernetes production for five years.",
        text_sha256=hashlib.sha256(
            b"Owned Kubernetes production for five years."
        ).hexdigest(),
        evidence_ids=("evidence:unavailable",),
        category="project",
    )
    extended = build_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(*request.approved_claims, unavailable),
    )
    extended_draft = build_editorial_draft(
        candidate_name=draft.candidate_name,
        candidate_city=draft.candidate_city,
        sections=(
            *draft.sections,
            CVSection(
                "Projects",
                (
                    EditorialAtom(
                        "approved_claim", unavailable.text, unavailable.claim_id
                    ),
                ),
            ),
        ),
    )
    extended_writer = replace(
        writer,
        request_sha256=extended.request_sha256,
        response_sha256=extended_draft.draft_sha256,
    )
    extended_humanizer = replace(
        humanizer,
        request_sha256=humanizer_request_sha256(extended, extended_draft),
        response_sha256=extended_draft.draft_sha256,
    )
    with pytest.raises(CVCompositionServiceError, match="no canonical artifact fact"):
        run_cv_composition_orchestration(
            request=extended,
            writer_draft=extended_draft,
            humanized_draft=extended_draft,
            writer_evidence=extended_writer,
            humanizer_evidence=extended_humanizer,
            base_source=base,
            listing_text=listing,
            form_fields=(),
            bindings=(),
            recruiter_assessor=assessor,
        )


def test_orchestration_receipt_is_tamper_evident_and_non_release(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)
    result = run_cv_composition_orchestration(
        request=request,
        writer_draft=draft,
        humanized_draft=draft,
        writer_evidence=writer,
        humanizer_evidence=humanizer,
        base_source=base,
        listing_text=listing,
        form_fields=(),
        bindings=(),
        recruiter_assessor=assessor,
    )
    with pytest.raises(CVCompositionServiceError, match="cannot grant"):
        replace(result, release_authority=True)
    with pytest.raises(CVCompositionServiceError, match="identity is invalid"):
        replace(result, orchestration_sha256="f" * 64)
    with pytest.raises(CVCompositionServiceError, match="out of order"):
        other_constraint = CVConstraintReceipt(
            source_id="1" * 64,
            cv_sha256="2" * 64,
            policy_sha256="3" * 64,
            receipt_sha256="4" * 64,
        )
        replace(
            result,
            final_constraint_receipt=other_constraint,
            orchestration_sha256=content_hash(
                {
                    **result.document(include_identity=False),
                    "final_constraint_receipt_sha256": (
                        other_constraint.receipt_sha256
                    ),
                }
            ),
        )
