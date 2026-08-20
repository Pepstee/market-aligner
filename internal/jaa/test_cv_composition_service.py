from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation.adversarial_recruiter import (
    RESULT_SCHEMA_VERSION,
    RecruiterAssessmentReceipt,
    assess_application_as_recruiter,
)
from career_automation.application_compiler import DocumentSection, StyleSlot
from career_automation.handoff_admission import (
    HandoffAdmissionError,
    VerifiedApplicationInput,
)
from career_automation.market_aligner_preparation import (
    prepare_admitted_market_application,
    prepare_admitted_market_application_from_authorities,
)
from career_automation.candidate_contact_authority import CandidateContactAuthority
from career_automation.evidence_matching import content_hash
from cv_generation.adversarial_rebuild import bind_recruiter_improvement
from cv_generation.constraints import CVConstraintReceipt
from cv_generation.benchmark_learning import (
    CVBenchmarkEntry,
    CVBenchmarkFeatures,
    build_benchmark_manifest,
)
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
    _reidentify_source,
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
    assert store.calls == 1
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
            return verified

    authority = CandidateContactAuthority(
        contact=contact,
        issued_at="2026-08-21T00:00:00Z",
        authority_sha256=contact_sha,
        registry_sha256="d" * 64,
        source_path=contact_path,
    )

    def materialize(admitted, authority_sha256, loaded_contact):
        assert admitted == verified
        assert authority_sha256 == candidate_sha
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
    result = prepare_admitted_market_application_from_authorities(
        admission_store=store,
        application_id=verified.application_id,
        repository_root=Path(__file__).resolve().parents[1],
        data_home=tmp_path / "external-data-home",
        candidate_authority_path=candidate_path,
        contact_authority_path=contact_path,
        input_materializer=materialize,
        contact_authority_loader=lambda *args, **kwargs: authority,
    )
    assert result.release_authority is False
    assert store.boundary_calls == 1
    assert assessor.calls == 1
    assert (result.path / "cv.pdf").is_file()
    receipt = json.loads((result.path / "receipt.json").read_bytes())
    assert receipt["contact_authority_sha256"] == contact_sha
    assert receipt["contact_object_sha256"] == contact_object_sha
    assert (result.path / "objects" / contact_object_sha).read_bytes() == contact_bytes


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

    with pytest.raises(HandoffAdmissionError, match="candidate authority differs"):
        prepare_admitted_market_application_from_authorities(
            admission_store=_Store(),
            application_id="app_" + "1" * 64,
            repository_root=Path(__file__).resolve().parents[1],
            data_home=tmp_path / "external-data-home",
            candidate_authority_path=candidate_path,
            contact_authority_path=contact_path,
            input_materializer=lambda *args: {},
        )
