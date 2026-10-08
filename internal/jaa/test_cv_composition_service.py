from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation.adversarial_recruiter import (
    RecruiterAssessmentReceipt,
    assess_application_as_recruiter,
)
from career_automation.application_compiler import DocumentSection, StyleSlot
from career_automation.candidate_application_factory import (
    CURRENT_RUNTIME_ENVIRONMENT,
    CandidateApplicationMaterializationReceipt,
)
from career_automation.rendering import CV_SECTION_HEADINGS, render_pdf_artifacts
from career_automation.handoff_admission import (
    HandoffAdmissionError,
    VerifiedApplicationInput,
)
from career_automation.market_aligner_preparation import (
    _prepare_admitted_market_application,
    prepare_admitted_market_application,
    prepare_admitted_market_application_from_authorities,
)
import career_automation.market_aligner_preparation as market_aligner_preparation
from career_automation.production_recruiter_assessor import (
    ProductionDetachedRecruiterAssessor,
    ProductionRecruiterAssessorError,
)
from career_automation.testing_adversarial_recruiter import (
    fixture_recruiter_result,
)
from career_automation.candidate_contact_authority import CandidateContactAuthority
from career_automation.evidence_matching import content_hash
from cv_generation.adversarial_rebuild import bind_recruiter_improvement
from cv_generation.constraints import (
    CVConstraintError,
    CVConstraintReceipt,
    CandidateSourcePolicyReceipt,
    validate_generated_cv,
)
from cv_generation.benchmark_learning import (
    CVBenchmarkEntry,
    CVBenchmarkFeatures,
    build_benchmark_manifest,
)
from cv_generation.editorial_composition import (
    ApprovedCoverLetterClaim,
    ApprovedCVClaim,
    CVSection,
    CandidateEditorialAuthority,
    CoverLetterSection,
    EditorialAtom,
    EditorialCompositionError,
    EditorialStageEvidence,
    build_cover_letter_editorial_draft,
    build_cover_letter_editorial_request,
    build_editorial_draft,
    build_editorial_request,
    COVER_LETTER_SALUTATION,
    COVER_LETTER_SIGN_OFF,
    editorial_section_policy,
    humanizer_request_sha256,
)
from cv_generation.service import (
    BASE_CV_POLICY,
    CVCompositionServiceError,
    _source_for_cover_letter_draft,
    _validate_artifact_cv,
    _reidentify_source,
    _source_for_editorial_draft,
    run_cv_composition_orchestration,
)
from llm.client import Backend, LLMClient, LLMResponse
from test_jaa07_independent_acceptance import _source


def _synthetic_current_materialization_receipt(source, monkeypatch):
    monkeypatch.setattr(
        CandidateApplicationMaterializationReceipt,
        "__post_init__",
        lambda self: None,
    )
    receipt = object.__new__(CandidateApplicationMaterializationReceipt)
    object.__setattr__(
        receipt,
        "deployment_binding",
        SimpleNamespace(environment=CURRENT_RUNTIME_ENVIRONMENT),
    )
    object.__setattr__(receipt, "application_source_id", source.source_id)
    object.__setattr__(receipt, "application_source_sha256", source.content_sha256)
    object.__setattr__(receipt, "receipt_sha256", "f" * 64)
    return receipt


def _current_cover_projection_case(monkeypatch, *, employer_text: str | None = None):
    source, _ = _source()
    candidate_fact = next(
        fact
        for fact in source.facts
        if fact.document_kind == "cover_letter" and fact.fact_kind == "candidate"
    )
    employer_fact = next(
        fact
        for fact in source.facts
        if fact.document_kind == "cover_letter" and fact.fact_kind == "employer"
    )
    authority = CandidateEditorialAuthority(
        candidate_name=source.contact.full_name,
        candidate_city=source.contact.city,
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256="a" * 64,
        current_runtime=True,
    )
    claims = (
        ApprovedCoverLetterClaim(
            claim_id=candidate_fact.sentence_id,
            text=candidate_fact.text,
            text_sha256=hashlib.sha256(candidate_fact.text.encode()).hexdigest(),
            evidence_ids=(candidate_fact.sentence_id,),
            fact_kind="candidate",
            section_heading="Evidence Match",
        ),
        ApprovedCoverLetterClaim(
            claim_id=employer_fact.sentence_id,
            text=employer_fact.text,
            text_sha256=hashlib.sha256(employer_fact.text.encode()).hexdigest(),
            evidence_ids=(employer_fact.sentence_id,),
            fact_kind="employer",
            section_heading="Company Fit",
        ),
    )
    request = build_cover_letter_editorial_request(
        authority=authority,
        role_title=source.role_title,
        company_name=source.company_name,
        vacancy_sha256=source.vacancy_sha256,
        approved_claims=claims,
    )
    sections = (
        CoverLetterSection(
            "Opening",
            (
                EditorialAtom("connective", COVER_LETTER_SALUTATION),
                EditorialAtom(
                    "connective",
                    f"I am applying for the {source.role_title} role at {source.company_name}.",
                ),
            ),
            current_runtime=True,
        ),
        CoverLetterSection(
            "Evidence Match",
            (EditorialAtom("approved_claim", candidate_fact.text, candidate_fact.sentence_id),),
            current_runtime=True,
        ),
        CoverLetterSection(
            "Company Fit",
            (
                EditorialAtom(
                    "approved_claim",
                    employer_text or employer_fact.text,
                    employer_fact.sentence_id,
                ),
            ),
            current_runtime=True,
        ),
        CoverLetterSection(
            "Close",
            (
                EditorialAtom("connective", "Thank you for considering my application."),
                EditorialAtom("connective", COVER_LETTER_SIGN_OFF),
                EditorialAtom("connective", source.contact.full_name),
            ),
            current_runtime=True,
        ),
    )
    draft = build_cover_letter_editorial_draft(
        candidate_name=source.contact.full_name,
        sections=sections,
        current_runtime=True,
    )
    receipt = _synthetic_current_materialization_receipt(source, monkeypatch)
    return source, request, draft, receipt, employer_fact


def test_current_cover_projection_keeps_unchanged_employer_fact(monkeypatch) -> None:
    source, request, draft, receipt, employer_fact = _current_cover_projection_case(
        monkeypatch
    )

    projected = _source_for_cover_letter_draft(
        base_source=source,
        request=request,
        draft=draft,
        materialization_receipt=receipt,
        materialized_source=source,
    )

    projected_employer = next(
        fact for fact in projected.facts if fact.sentence_id == employer_fact.sentence_id
    )
    assert projected_employer.text == employer_fact.approved_source_text
    assert projected_employer.pending_current_outward_draft is None


def test_current_cover_projection_rejects_changed_employer_fact(monkeypatch) -> None:
    source, request, draft, receipt, _ = _current_cover_projection_case(
        monkeypatch, employer_text="Example Ltd has a different unverified claim."
    )

    with pytest.raises(
        EditorialCompositionError, match="cover-letter draft changed or invented a claim"
    ):
        _source_for_cover_letter_draft(
            base_source=source,
            request=request,
            draft=draft,
            materialization_receipt=receipt,
            materialized_source=source,
        )


def test_current_pre_review_filters_archive_arguments_for_service_only(
    monkeypatch, tmp_path
) -> None:
    candidate_authority_bytes = b"synthetic candidate authority\n"
    candidate_authority_sha256 = hashlib.sha256(candidate_authority_bytes).hexdigest()
    contact_authority_bytes = b"synthetic contact authority\n"
    contact_authority_sha256 = hashlib.sha256(contact_authority_bytes).hexdigest()
    listing_text = "Synthetic public listing"
    request = SimpleNamespace(
        authority=SimpleNamespace(source_sha256=candidate_authority_sha256),
        vacancy_sha256=hashlib.sha256(listing_text.encode()).hexdigest(),
    )
    base_source = SimpleNamespace(
        contact=SimpleNamespace(provenance_sha256=contact_authority_sha256)
    )
    archive_values = {
        "candidate_projection": {"projection": "exact"},
        "decision_receipt": {"decision": "exact"},
        "market_decision_authority": {"authority": "exact"},
        "materialization": {"source": "exact"},
    }
    orchestration_arguments = {
        "request": request,
        "writer_draft": object(),
        "humanized_draft": object(),
        "writer_evidence": object(),
        "humanizer_evidence": object(),
        "base_source": base_source,
        "listing_text": listing_text,
        "form_fields": (),
        "bindings": (),
        "materialization_receipt": object(),
        "cover_letter_request": object(),
        "cover_letter_writer_draft": object(),
        "cover_letter_humanized_draft": object(),
        "cover_letter_writer_evidence": object(),
        "cover_letter_humanizer_evidence": object(),
        **archive_values,
    }
    service_signature = inspect.signature(run_cv_composition_orchestration)
    current_options = {
        "environment": market_aligner_preparation.CURRENT_RUNTIME_ENVIRONMENT,
        "current_runtime_pre_review": True,
    }
    with pytest.raises(TypeError, match="unexpected keyword argument 'candidate_projection'"):
        service_signature.bind(**orchestration_arguments, **current_options)

    captured: dict[str, object] = {}
    composition_result = object()
    preparation_result = object()

    def compose(**kwargs):
        service_signature.bind(**kwargs)
        captured["service_arguments"] = kwargs
        return composition_result

    def persist(**kwargs):
        captured["persistence_arguments"] = kwargs
        return preparation_result

    class _Store:
        def for_boundary(self, application_id, boundary):
            assert application_id == "app_synthetic"
            assert boundary == "strategy"
            return SimpleNamespace(
                environment=market_aligner_preparation.CURRENT_RUNTIME_ENVIRONMENT
            )

    monkeypatch.setattr(
        market_aligner_preparation, "run_cv_composition_orchestration", compose
    )
    monkeypatch.setattr(
        market_aligner_preparation, "_persist_current_runtime_drafts", persist
    )
    result = _prepare_admitted_market_application(
        admission_store=_Store(),
        application_id="app_synthetic",
        repository_root=tmp_path / "repo",
        data_home=tmp_path / "data-home",
        candidate_authority_bytes=candidate_authority_bytes,
        candidate_authority_sha256=candidate_authority_sha256,
        contact_authority_bytes=contact_authority_bytes,
        contact_authority_sha256=contact_authority_sha256,
        orchestration_arguments=orchestration_arguments,
        environment=market_aligner_preparation.CURRENT_RUNTIME_ENVIRONMENT,
        current_runtime_pre_review=True,
    )

    assert result is preparation_result
    service_arguments = captured["service_arguments"]
    assert isinstance(service_arguments, dict)
    assert not (set(archive_values) & set(service_arguments))
    assert service_arguments["materialization_receipt"] is orchestration_arguments[
        "materialization_receipt"
    ]
    assert service_arguments["environment"] == current_options["environment"]
    assert service_arguments["current_runtime_pre_review"] is True
    persistence_arguments = captured["persistence_arguments"]
    assert isinstance(persistence_arguments, dict)
    assert persistence_arguments["orchestration_arguments"] is orchestration_arguments
    for key, value in archive_values.items():
        assert persistence_arguments["orchestration_arguments"][key] is value

    unrecognized_arguments = {
        **orchestration_arguments,
        "future_service_option": object(),
    }
    with pytest.raises(
        TypeError, match="unexpected keyword argument 'future_service_option'"
    ):
        _prepare_admitted_market_application(
            admission_store=_Store(),
            application_id="app_synthetic",
            repository_root=tmp_path / "repo",
            data_home=tmp_path / "data-home",
            candidate_authority_bytes=candidate_authority_bytes,
            candidate_authority_sha256=candidate_authority_sha256,
            contact_authority_bytes=contact_authority_bytes,
            contact_authority_sha256=contact_authority_sha256,
            orchestration_arguments=unrecognized_arguments,
            environment=market_aligner_preparation.CURRENT_RUNTIME_ENVIRONMENT,
            current_runtime_pre_review=True,
        )


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
    value = fixture_recruiter_result(fit_percent=53)
    value.update({
        "strengths": [
            {
                "location": "cv:summary",
                "assessment": "Reliable delivery evidence.",
                "outward_evidence_refs": ["cv:char:0:1"],
            }
        ],
        "risks": [
            {
                "category": "experience",
                "severity": "medium",
                "location": "cv",
                "assessment": "The application has limited production scale detail.",
                "outward_evidence_refs": ["cv:char:0:1"],
            }
        ],
        "application_improvements": [
            {
                "rank": 1,
                "target": "positioning",
                "recommendation": "Keep the reliable delivery evidence prominent.",
                "expected_effect": "Preserves the clearest role match.",
                "support_required": False,
                "outward_evidence_refs": ["cv:char:0:1"],
            },
            {
                "rank": 2,
                "target": "cv",
                "recommendation": "Add unsupported Kubernetes ownership.",
                "expected_effect": "Would address an unstated platform gap.",
                "support_required": True,
                "outward_evidence_refs": ["job_listing:char:0:1"],
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
    })
    return value


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
    capability_text = "Designed deterministic workflow automation with bounded authority."
    cv_fact = next(row for row in base_source.facts if row.document_kind == "cv")
    capability_fact = replace(
        cv_fact,
        sentence_id=content_hash(
            {
                "fixture": "service-capability",
                "text": capability_text,
                "document_kind": "cv",
            }
        ),
        text=capability_text,
        approved_source_text=capability_text,
    )
    company_fit = StyleSlot(
        content_hash(
            {
                "document_kind": "cover_letter",
                "text": "The documented service focus matches my delivery priorities.",
            }
        ),
        "cover_letter",
        "The documented service focus matches my delivery priorities.",
    )
    close = StyleSlot(
        content_hash(
            {
                "document_kind": "cover_letter",
                "text": "I would welcome a conversation about the engineering challenges.",
            }
        ),
        "cover_letter",
        "I would welcome a conversation about the engineering challenges.",
    )
    base_source = _reidentify_source(
        replace(
            base_source,
            facts=(*base_source.facts, capability_fact),
            style_slots=(*base_source.style_slots, company_fit, close),
            letter_sections=(
                base_source.letter_sections[0],
                base_source.letter_sections[1],
                DocumentSection("Company Fit", (), (company_fit.slot_id,)),
                DocumentSection("Close", (), (close.slot_id,)),
            ),
        )
    )
    listing = "Deliver reliable services for Example Ltd."
    authority = CandidateEditorialAuthority(
        candidate_name="Alex Example",
        candidate_city="London",
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256="a" * 64,
    )
    summary = _claim("summary", "summary")
    capability = ApprovedCVClaim(
        claim_id="capability",
        text=capability_text,
        text_sha256=hashlib.sha256(capability_text.encode()).hexdigest(),
        evidence_ids=("evidence:capability",),
        category="capability_domain",
    )
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


@pytest.mark.parametrize(
    "heading",
    (
        "Highlights",
        "Results",
        "Outcomes",
        "Skills",
        "Certifications",
    ),
)
def test_current_renderer_projects_and_renders_policy_headings(heading, monkeypatch) -> None:
    base_source, _ = _source()
    cv_fact = next(row for row in base_source.facts if row.document_kind == "cv")
    categories = editorial_section_policy(current_runtime=True)[heading]
    assert len(categories) == 1
    category = next(iter(categories))
    authority = CandidateEditorialAuthority(
        candidate_name=base_source.contact.full_name,
        candidate_city=base_source.contact.city,
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256="a" * 64,
        current_runtime=True,
    )
    claim = ApprovedCVClaim(
        claim_id=cv_fact.sentence_id,
        text=cv_fact.text,
        text_sha256=hashlib.sha256(cv_fact.text.encode()).hexdigest(),
        evidence_ids=(f"synthetic-evidence-{heading.casefold()}",),
        category=category,
    )
    request = build_editorial_request(
        authority=authority,
        role_title=base_source.role_title,
        company_name=base_source.company_name,
        vacancy_sha256=base_source.vacancy_sha256,
        approved_claims=(claim,),
    )
    draft = build_editorial_draft(
        candidate_name=authority.candidate_name,
        candidate_city=authority.candidate_city,
        current_runtime=True,
        sections=(
            CVSection(
                heading,
                (EditorialAtom("approved_claim", cv_fact.text, claim.claim_id),),
            ),
        ),
    )

    projected = _source_for_editorial_draft(
        base_source=base_source,
        request=request,
        draft=draft,
        materialization_receipt=_synthetic_current_materialization_receipt(
            base_source, monkeypatch
        ),
    )

    assert tuple(section.heading for section in projected.cv_sections) == (heading,)
    assert projected.cv_sections[0].sentence_ids == (cv_fact.sentence_id,)
    artifacts = render_pdf_artifacts(projected)
    assert f"\n{heading}\n" in artifacts.editable.cv_text
    assert any(heading in page for page in artifacts.cv_pdf.rendered_lines)


def _current_artifact_validation_case(heading: str, monkeypatch):
    base_source, _ = _source()
    cv_fact = next(row for row in base_source.facts if row.document_kind == "cv")
    summary_text = "Synthetic summary evidence supports reliable delivery."
    section_text = "Synthetic section evidence records validated results."
    summary_fact = replace(
        cv_fact,
        sentence_id=content_hash(
            {"fixture": "current-summary-validation", "text": summary_text}
        ),
        text=summary_text,
        approved_source_text=summary_text,
    )
    section_fact = replace(
        cv_fact,
        sentence_id=content_hash(
            {"fixture": f"current-{heading.casefold()}-validation", "text": section_text}
        ),
        text=section_text,
        approved_source_text=section_text,
    )
    base_source = _reidentify_source(
        replace(base_source, facts=(*base_source.facts, summary_fact, section_fact))
    )
    authority = CandidateEditorialAuthority(
        candidate_name=base_source.contact.full_name,
        candidate_city=base_source.contact.city,
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256="a" * 64,
        current_runtime=True,
    )
    section_category = next(iter(editorial_section_policy(current_runtime=True)[heading]))
    claims = (
        ApprovedCVClaim(
            claim_id=summary_fact.sentence_id,
            text=summary_text,
            text_sha256=hashlib.sha256(summary_text.encode()).hexdigest(),
            evidence_ids=("evidence:synthetic-summary-validation",),
            category="summary",
        ),
        ApprovedCVClaim(
            claim_id=section_fact.sentence_id,
            text=section_text,
            text_sha256=hashlib.sha256(section_text.encode()).hexdigest(),
            evidence_ids=(f"evidence:{heading.casefold()}-validation",),
            category=section_category,
        ),
    )
    request = build_editorial_request(
        authority=authority,
        role_title=base_source.role_title,
        company_name=base_source.company_name,
        vacancy_sha256=hashlib.sha256(
            b"Synthetic role description for current validator."
        ).hexdigest(),
        approved_claims=claims,
    )
    draft = build_editorial_draft(
        candidate_name=authority.candidate_name,
        candidate_city=authority.candidate_city,
        current_runtime=True,
        sections=(
            CVSection(
                "Professional Summary",
                (
                    EditorialAtom(
                        "approved_claim", summary_text, summary_fact.sentence_id
                    ),
                ),
            ),
            CVSection(
                heading,
                (
                    EditorialAtom(
                        "approved_claim",
                        section_text,
                        section_fact.sentence_id,
                    ),
                ),
            ),
        ),
    )
    source = _source_for_editorial_draft(
        base_source=base_source,
        request=request,
        draft=draft,
        materialization_receipt=_synthetic_current_materialization_receipt(
            base_source, monkeypatch
        ),
    )
    artifacts = render_pdf_artifacts(source)
    return request, draft, source, artifacts


@pytest.mark.parametrize("heading", ("Skills", "Highlights", "Results", "Outcomes"))
def test_current_pre_review_cv_validator_uses_current_section_policy(
    heading, monkeypatch
) -> None:
    request, draft, source, artifacts = _current_artifact_validation_case(
        heading, monkeypatch
    )

    receipt = _validate_artifact_cv(
        request=request,
        draft=draft,
        source=source,
        artifacts=artifacts,
    )

    assert type(receipt) is CandidateSourcePolicyReceipt
    assert receipt.release_authority is False


@pytest.mark.parametrize("heading", ("Skills", "Highlights", "Results", "Outcomes"))
def test_legacy_cv_validator_keeps_current_headings_refused(heading) -> None:
    section_text = "Synthetic section evidence records validated results."
    cv_text = "Synthetic summary evidence.\nSynthetic capability evidence.\n" + section_text
    sections = {
        "Professional Summary": ("Synthetic summary evidence.",),
        "Core Capabilities": ("Synthetic capability evidence.",),
        heading: (section_text,),
    }

    with pytest.raises(CVConstraintError, match="non-standard ATS section heading"):
        validate_generated_cv(
            source_id="a" * 64,
            candidate_name="Synthetic Candidate",
            candidate_city=None,
            cv_text=cv_text,
            cv_sha256=hashlib.sha256(cv_text.encode()).hexdigest(),
            sections=sections,
            rendered_pages=(("Synthetic Candidate",),),
            policy=BASE_CV_POLICY,
        )


def test_current_cv_validator_rejects_unregistered_heading() -> None:
    cv_text = "Synthetic summary evidence.\nSynthetic unknown section evidence."
    with pytest.raises(CVConstraintError, match="non-standard ATS section heading"):
        validate_generated_cv(
            source_id="a" * 64,
            candidate_name="Synthetic Candidate",
            candidate_city=None,
            cv_text=cv_text,
            cv_sha256=hashlib.sha256(cv_text.encode()).hexdigest(),
            sections={
                "Professional Summary": ("Synthetic summary evidence.",),
                "Unregistered": ("Synthetic unknown section evidence.",),
            },
            rendered_pages=(("Synthetic Candidate",),),
            policy=BASE_CV_POLICY,
            section_policy=editorial_section_policy(current_runtime=True),
            _source_policy_only=True,
        )


def test_current_renderer_headings_do_not_expand_legacy_or_unknown_policy() -> None:
    expected_legacy_headings = frozenset(
        {
            "Professional Summary",
            "Core Capabilities",
            "Projects",
            "Education",
            "Experience",
            "Skills",
        }
    )
    assert CV_SECTION_HEADINGS == expected_legacy_headings
    assert "Highlights" not in editorial_section_policy()
    assert {
        "Highlights",
        "Results",
        "Outcomes",
        "Skills",
        "Certifications",
    } <= set(editorial_section_policy(current_runtime=True))

    atom = EditorialAtom("approved_claim", "Synthetic approved fact.", "claim")
    with pytest.raises(EditorialCompositionError, match="section heading is unsupported"):
        CVSection("Unregistered Heading", (atom,))
    with pytest.raises(EditorialCompositionError, match="editorial draft layout is invalid"):
        build_editorial_draft(
            candidate_name="Synthetic Candidate",
            candidate_city="Synthetic City",
            sections=(CVSection("Highlights", (atom,)),),
        )

    legacy_source, _ = _source()
    legacy_artifacts = render_pdf_artifacts(legacy_source)
    assert "Professional Summary" in legacy_artifacts.editable.cv_text


def _binding(request, recruiter_receipt: RecruiterAssessmentReceipt):
    return bind_recruiter_improvement(
        improvement_index=0,
        target_heading="Professional Summary",
        claim_ids=("summary",),
        authority_source_sha256=request.authority.source_sha256,
        model_result_sha256=recruiter_receipt.model_result_sha256,
        binding_source_sha256="b" * 64,
    )


def _benchmark_manifest():
    features = CVBenchmarkFeatures(10_000, 10_000, 7_500, 8_000, 10_000, 10_000, 6_000)
    entry = CVBenchmarkEntry(
        exemplar_id="fixture-licensed-uk-1",
        source_sha256="1" * 64,
        source_uri_sha256="2" * 64,
        license_id="fixture-permission",
        provenance_sha256="3" * 64,
        outcome_kind="expert_review",
        outcome_sha256="4" * 64,
        features=features,
    )
    return build_benchmark_manifest((entry,))


def test_offline_injected_service_runs_the_complete_cv_cycle(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)

    first = run_cv_composition_orchestration(
        environment="synthetic",
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
        benchmark_manifest=_benchmark_manifest(),
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
    assert first.initial_benchmark_receipt.release_authority is False
    assert first.final_benchmark_receipt.factual_authority == "candidate_evidence_only"
    assert first.initial_benchmark_receipt.manifest_sha256 == first.final_benchmark_receipt.manifest_sha256


def test_precomputed_receipt_path_applies_only_bound_claims(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)
    diagnostic = run_cv_composition_orchestration(
        environment="synthetic",
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
        environment="synthetic",
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
        "environment": "synthetic",
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


def test_production_orchestration_rejects_injected_or_precomputed_recruiter(
    tmp_path,
) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)
    values = {
        "environment": "production",
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
    with pytest.raises(CVCompositionServiceError, match="source materialization"):
        run_cv_composition_orchestration(**values, recruiter_assessor=assessor)

    synthetic = run_cv_composition_orchestration(
        **{**values, "environment": "synthetic"}, recruiter_assessor=assessor
    )
    with pytest.raises(CVCompositionServiceError, match="source materialization"):
        run_cv_composition_orchestration(
            **values, recruiter_receipt=synthetic.recruiter_receipt
        )


def test_production_assessor_requires_external_archive(tmp_path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    binary = tmp_path / "codex"
    binary.write_bytes(b"fixture binary")
    binary.chmod(0o700)
    with pytest.raises(ProductionRecruiterAssessorError, match="explicit"):
        ProductionDetachedRecruiterAssessor(
            model="gpt-5.6",
            archive_root=tmp_path / "archive",
            repository_root=repository,
            codex_binary=None,  # type: ignore[arg-type]
        )
    with pytest.raises(ProductionRecruiterAssessorError, match="outside"):
        ProductionDetachedRecruiterAssessor(
            model="gpt-5.6",
            archive_root=repository / "archive",
            repository_root=repository,
            codex_binary=str(binary),
        )


def test_production_assessor_configuration_rejects_replay_substitution(
    tmp_path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    binary_a = tmp_path / "codex-a"
    binary_b = tmp_path / "codex-b"
    binary_a.write_bytes(b"fixture binary a")
    binary_b.write_bytes(b"fixture binary b")
    binary_a.chmod(0o700)
    binary_b.chmod(0o700)

    def assessor(*, model="gpt-5.6", binary=binary_a, archive="archive-a"):
        return ProductionDetachedRecruiterAssessor(
            model=model,
            archive_root=tmp_path / archive,
            repository_root=repository,
            codex_binary=str(binary),
        )

    baseline = assessor()
    identities = {
        baseline.configuration_sha256,
        assessor(model="gpt-5.6-mini").configuration_sha256,
        assessor(binary=binary_b).configuration_sha256,
        assessor(archive="archive-b").configuration_sha256,
    }
    assert len(identities) == 4
    assert content_hash(baseline.configuration_document()) == baseline.configuration_sha256
    binary_a.write_bytes(b"substituted after configuration")
    with pytest.raises(ProductionRecruiterAssessorError, match="changed"):
        baseline.assess(None)  # type: ignore[arg-type]


def test_listing_and_canonical_artifact_authority_fail_closed(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)
    with pytest.raises(CVCompositionServiceError, match="job listing differs"):
        run_cv_composition_orchestration(
            environment="synthetic",
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
            environment="synthetic",
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
        environment="synthetic",
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


def test_admitted_market_preparation_runs_real_cv_orchestration_and_replays(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)
    candidate_bytes = b'{"synthetic":"candidate-authority"}\n'
    contact_bytes = b'{"synthetic":"contact-authority"}\n'
    candidate_sha = hashlib.sha256(candidate_bytes).hexdigest()
    contact_object_sha = hashlib.sha256(contact_bytes).hexdigest()
    contact_sha = "e" * 64
    request = build_editorial_request(
        authority=replace(request.authority, source_sha256=candidate_sha),
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=request.approved_claims,
    )
    writer = replace(writer, request_sha256=request.request_sha256)
    humanizer = replace(
        humanizer, request_sha256=humanizer_request_sha256(request, draft)
    )
    base = _reidentify_source(
        replace(base, contact=replace(base.contact, provenance_sha256=contact_sha))
    )
    verified = VerifiedApplicationInput(
        application_id="app_" + "1" * 64,
        admission_kind="market_aligner_handoff_v1",
        environment="synthetic",
        authority_scope="none",
        handoff_root_sha256="2" * 64,
        vacancy_source_identity=base.vacancy_source_identity,
        profile_id="prf_" + "3" * 32,
        profile_version="synthetic-v1",
        candidate_authority_sha256=candidate_sha,
        job_key=base.job_key,
        vacancy_snapshot_sha256=base.vacancy_sha256,
        raw_listing_sha256=hashlib.sha256(listing.encode()).hexdigest(),
        raw_listing_bytes=listing.encode(),
        requirements_sha256="4" * 64,
        requirements_bytes=b"synthetic requirements",
        canonical_url="https://jobs.example.test/42",
        company_name=base.company_name,
        role_title=base.role_title,
        location={},
        admission_receipt_sha256="5" * 64,
        current_boundary="strategy",
        current_boundary_receipt_sha256="6" * 64,
    )

    class _Store:
        calls = 0

        def for_boundary(self, application_id, boundary):
            assert application_id == verified.application_id
            assert boundary == "strategy"
            self.calls += 1
            return verified

    store = _Store()
    arguments = {
        "request": request,
        "writer_draft": draft,
        "humanized_draft": draft,
        "writer_evidence": writer,
        "humanizer_evidence": humanizer,
        "base_source": base,
        "listing_text": listing,
        "form_fields": (),
        "bindings": (),
        "recruiter_assessor": assessor,
        "improvement_binder": lambda req, receipt: (_binding(req, receipt),),
    }
    inputs = {
        "environment": "synthetic",
        "admission_store": store,
        "application_id": verified.application_id,
        "repository_root": Path(__file__).resolve().parents[1],
        "data_home": tmp_path / "external-data-home",
        "candidate_authority_bytes": candidate_bytes,
        "candidate_authority_sha256": candidate_sha,
        "contact_authority_bytes": contact_bytes,
        "contact_authority_sha256": contact_sha,
        "contact_object_sha256": contact_object_sha,
        "orchestration_arguments": arguments,
    }
    class _ProductionStore:
        def for_boundary(self, application_id, boundary):
            assert application_id == verified.application_id
            assert boundary == "strategy"
            return replace(verified, environment="production")

    with pytest.raises(HandoffAdmissionError, match="direct production preparation"):
        prepare_admitted_market_application(
            **{
                **inputs,
                "admission_store": _ProductionStore(),
                "environment": "production",
            }
        )
    with pytest.raises(HandoffAdmissionError, match="direct production preparation"):
        prepare_admitted_market_application(
            **{**inputs, "environment": "production"}
        )
    assert assessor.calls == 0
    assert store.calls == 0
    with pytest.raises(ValueError, match="contact authority exact bytes differ"):
        prepare_admitted_market_application(
            **{**inputs, "contact_object_sha256": "0" * 64}
        )
    with pytest.raises(ValueError, match="application source differs"):
        prepare_admitted_market_application(
            **{**inputs, "contact_authority_sha256": "1" * 64}
        )
    first = prepare_admitted_market_application(**inputs)
    second = prepare_admitted_market_application(**inputs)
    assert first == second
    assert first.release_authority is False
    assert store.calls == 2
    assert assessor.calls == 1
    assert (first.path / "cv.pdf").is_file()
    assert (first.path / "cover-letter.pdf").is_file()


def test_authority_runner_materializes_exact_admitted_inputs_without_provider(tmp_path) -> None:
    base, listing, request, draft, writer, humanizer, assessor = _fixture(tmp_path)
    candidate_path = tmp_path / "candidate-authority.yaml"
    contact_path = tmp_path / "contact-authority.json"
    candidate_bytes = b"schema: market-aligner.profile.v1\nprofile_id: synthetic\n"
    contact_bytes = b'{"synthetic":"signed-contact-authority"}\n'
    candidate_path.write_bytes(candidate_bytes)
    contact_path.write_bytes(contact_bytes)
    candidate_path.chmod(0o600)
    contact_path.chmod(0o600)
    candidate_sha = hashlib.sha256(candidate_bytes).hexdigest()
    contact_object_sha = hashlib.sha256(contact_bytes).hexdigest()
    contact_sha = "f" * 64
    request = build_editorial_request(
        authority=replace(request.authority, source_sha256=candidate_sha),
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=request.approved_claims,
    )
    writer = replace(writer, request_sha256=request.request_sha256)
    humanizer = replace(
        humanizer, request_sha256=humanizer_request_sha256(request, draft)
    )
    contact = replace(base.contact, provenance_sha256=contact_sha)
    base = _reidentify_source(replace(base, contact=contact))
    verified = VerifiedApplicationInput(
        application_id="app_" + "7" * 64,
        admission_kind="market_aligner_handoff_v1",
        environment="synthetic",
        authority_scope="none",
        handoff_root_sha256="8" * 64,
        vacancy_source_identity=base.vacancy_source_identity,
        profile_id="prf_" + "9" * 32,
        profile_version="synthetic-v1",
        candidate_authority_sha256=candidate_sha,
        job_key=base.job_key,
        vacancy_snapshot_sha256=base.vacancy_sha256,
        raw_listing_sha256=hashlib.sha256(listing.encode()).hexdigest(),
        raw_listing_bytes=listing.encode(),
        requirements_sha256="a" * 64,
        requirements_bytes=b"synthetic requirements",
        canonical_url="https://jobs.example.test/42",
        company_name=base.company_name,
        role_title=base.role_title,
        location={},
        admission_receipt_sha256="b" * 64,
        current_boundary="strategy",
        current_boundary_receipt_sha256="c" * 64,
    )

    class _Store:
        boundary_calls = 0

        def reference_sha256(self, application_id, reference_key):
            assert application_id == verified.application_id
            assert reference_key == "candidate_intent.authority_source"
            return candidate_sha

        def for_boundary(self, application_id, boundary):
            assert application_id == verified.application_id
            assert boundary == "strategy"
            self.boundary_calls += 1
            return SimpleNamespace(**vars(verified))

    authority = CandidateContactAuthority(
        contact=contact,
        issued_at="2026-08-21T00:00:00Z",
        authority_sha256=contact_sha,
        envelope_sha256=contact_object_sha,
        registry_sha256="d" * 64,
        signer_public_key_sha256="e" * 64,
        source_path=contact_path,
    )

    def materialize(admitted, deployment_binding, loaded_contact):
        assert admitted.candidate_authority_sha256 == candidate_sha
        assert deployment_binding.candidate_authority_file_sha256 == candidate_sha
        assert loaded_contact == authority
        return {
            "request": request,
            "writer_draft": draft,
            "humanized_draft": draft,
            "writer_evidence": writer,
            "humanizer_evidence": humanizer,
            "base_source": base,
            "listing_text": listing,
            "form_fields": (),
            "bindings": (),
            "recruiter_assessor": assessor,
            "improvement_binder": lambda req, receipt: (_binding(req, receipt),),
        }

    store = _Store()
    with pytest.raises(ValueError, match="typed candidate materialization"):
        prepare_admitted_market_application_from_authorities(
            environment="synthetic",
            admission_store=store,
            application_id=verified.application_id,
            repository_root=Path(__file__).resolve().parents[1],
            data_home=tmp_path / "external-data-home",
            candidate_authority_path=candidate_path,
            contact_authority_path=contact_path,
            input_materializer=materialize,
            contact_authority_loader=lambda *args, **kwargs: authority,
        )
    assert store.boundary_calls == 1
    assert assessor.calls == 0


def test_authority_runner_rejects_candidate_not_bound_to_handoff(tmp_path) -> None:
    candidate_path = tmp_path / "candidate-authority.yaml"
    contact_path = tmp_path / "contact-authority.json"
    candidate_path.write_bytes(b"candidate\n")
    contact_path.write_bytes(b"contact\n")
    candidate_path.chmod(0o600)
    contact_path.chmod(0o600)

    class _Store:
        def reference_sha256(self, application_id, reference_key):
            return "0" * 64

        def for_boundary(self, application_id, boundary):
            return SimpleNamespace(
                candidate_authority_sha256="0" * 64,
                environment="synthetic",
            )

    with pytest.raises(HandoffAdmissionError, match="candidate authority differs"):
        prepare_admitted_market_application_from_authorities(
            environment="synthetic",
            admission_store=_Store(),
            application_id="app_" + "1" * 64,
            repository_root=Path(__file__).resolve().parents[1],
            data_home=tmp_path / "external-data-home",
            candidate_authority_path=candidate_path,
            contact_authority_path=contact_path,
            input_materializer=lambda *args: {},
        )
