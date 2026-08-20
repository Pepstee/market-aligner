"""Public construction and orchestration API for the CV-generation module."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from typing import Protocol, Sequence

from career_automation.adversarial_recruiter import (
    RecruiterAssessmentPackage,
    RecruiterAssessmentReceipt,
)
from career_automation.application_compiler import (
    ApplicationSource,
    DocumentSection,
    FactualSentence,
    StyleSlot,
    verify_application_source,
)
from career_automation.candidate_application_factory import (
    CandidateApplicationPackage,
    GenerationRevisionWriter,
    build_candidate_application_package,
)
from career_automation.evidence_matching import canonical_json, content_hash
from career_automation.external_document_assurance import IntendedVacancy
from career_automation.rendering import (
    CV_SECTION_HEADINGS,
    ApplicationArtifacts,
    render_pdf_artifacts,
    verify_application_artifacts,
)

from .adversarial_rebuild import (
    EvidenceSafeRebuildResult,
    RecruiterImprovementBinding,
    rebuild_from_recruiter_assessment,
)
from .constraints import (
    CVConstraintReceipt,
    CVPopplerQualityReceipt,
    policy_for_candidate,
    validate_generated_cv,
    verify_poppler_cv_quality,
)
from .document_quality import DocumentQualityReceipt, verify_document_quality
from .benchmark_learning import (
    CVBenchmarkDiagnosticReceipt,
    CVBenchmarkManifest,
    evaluate_cv_benchmark,
)
from .editorial_composition import (
    CVEditorialDraft,
    CVEditorialRequest,
    EditorialCompositionReceipt,
    EditorialStageEvidence,
    admit_editorial_composition,
    validate_editorial_draft,
)


ORCHESTRATION_SCHEMA = "jaa.cv-composition-orchestration.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CVCompositionServiceError(ValueError):
    """The CV composition orchestration could not preserve exact authority."""


class RecruiterAssessor(Protocol):
    def __call__(
        self, package: RecruiterAssessmentPackage
    ) -> RecruiterAssessmentReceipt: ...


class ImprovementBinder(Protocol):
    def __call__(
        self,
        request: CVEditorialRequest,
        receipt: RecruiterAssessmentReceipt,
    ) -> Sequence[RecruiterImprovementBinding]: ...


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise CVCompositionServiceError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _reidentify_source(source: ApplicationSource) -> ApplicationSource:
    provisional = replace(source, source_id="0" * 64, content_sha256="0" * 64)
    content_sha256 = hashlib.sha256(
        canonical_json(provisional.document(include_identity=False)).encode()
    ).hexdigest()
    source_id = content_hash(
        {
            "contract": "jaa07.application-source.v1",
            "content_sha256": content_sha256,
            "strategy_id": source.strategy_id,
        }
    )
    identified = replace(
        provisional,
        source_id=source_id,
        content_sha256=content_sha256,
    )
    verify_application_source(identified)
    return identified


def _source_for_editorial_draft(
    *,
    base_source: ApplicationSource,
    request: CVEditorialRequest,
    draft: CVEditorialDraft,
) -> ApplicationSource:
    """Project an admitted draft onto existing authority-backed source atoms."""

    verify_application_source(base_source)
    validate_editorial_draft(request, draft)
    if (
        base_source.role_title != request.role_title
        or base_source.company_name != request.company_name
    ):
        raise CVCompositionServiceError("artifact source targets another vacancy")
    if (
        base_source.contact.full_name != draft.candidate_name
        or base_source.contact.city != draft.candidate_city
    ):
        raise CVCompositionServiceError("artifact contact differs from editorial authority")

    facts_by_text: dict[str, list[FactualSentence]] = {}
    for fact in base_source.facts:
        if fact.document_kind == "cv":
            facts_by_text.setdefault(fact.text, []).append(fact)
    style_by_text = {
        slot.text: slot
        for slot in base_source.style_slots
        if slot.document_kind == "cv"
    }
    selected_facts: dict[str, FactualSentence] = {}
    selected_slots: dict[str, StyleSlot] = {}
    sections: list[DocumentSection] = []
    for section in draft.sections:
        if section.heading not in CV_SECTION_HEADINGS:
            raise CVCompositionServiceError(
                "editorial section is unsupported by the canonical renderer"
            )
        sentence_ids: list[str] = []
        slot_ids: list[str] = []
        factual_span_seen = False
        for atom in section.atoms:
            if atom.source_kind == "connective":
                if factual_span_seen:
                    raise CVCompositionServiceError(
                        "canonical renderer requires connectives before factual spans"
                    )
                slot = style_by_text.get(atom.text)
                if slot is None:
                    slot = StyleSlot(
                        content_hash(
                            {
                                "contract": "jaa.cv-editorial-style-slot.v1",
                                "document_kind": "cv",
                                "text": atom.text,
                            }
                        ),
                        "cv",
                        atom.text,
                    )
                selected_slots[slot.slot_id] = slot
                slot_ids.append(slot.slot_id)
                continue
            factual_span_seen = True
            candidates = facts_by_text.get(atom.text, ())
            if not candidates:
                raise CVCompositionServiceError(
                    "editorial claim has no canonical artifact fact"
                )
            fact = sorted(candidates, key=lambda row: row.sentence_id)[0]
            selected_facts[fact.sentence_id] = fact
            sentence_ids.append(fact.sentence_id)
        sections.append(
            DocumentSection(
                heading=section.heading,
                sentence_ids=tuple(sentence_ids),
                style_slot_ids=tuple(slot_ids),
            )
        )

    non_cv_facts = tuple(
        fact for fact in base_source.facts if fact.document_kind != "cv"
    )
    non_cv_slots = tuple(
        slot for slot in base_source.style_slots if slot.document_kind != "cv"
    )
    projected = replace(
        base_source,
        facts=(*selected_facts.values(), *non_cv_facts),
        style_slots=(*selected_slots.values(), *non_cv_slots),
        cv_sections=tuple(sections),
    )
    return _reidentify_source(projected)


def _validate_artifact_cv(
    *,
    request: CVEditorialRequest,
    draft: CVEditorialDraft,
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
) -> CVConstraintReceipt:
    verify_application_artifacts(artifacts)
    if artifacts.source_id != source.source_id:
        raise CVCompositionServiceError("rendered artifacts target another source")
    selected = policy_for_candidate(request.authority.candidate_name)
    if selected.candidate_name is not None and (
        selected.candidate_name != request.authority.candidate_name
        or selected.required_city != request.authority.candidate_city
        or selected.required_graduation != request.authority.graduation_month_year
        or selected.required_dissertation_title != request.authority.dissertation_title
    ):
        raise CVCompositionServiceError("final CV policy differs from candidate authority")
    sections = {
        section.heading: tuple(atom.text for atom in section.atoms)
        for section in draft.sections
    }
    return validate_generated_cv(
        source_id=source.source_id,
        candidate_name=source.contact.full_name,
        candidate_city=source.contact.city,
        cv_text=artifacts.editable.cv_text,
        cv_sha256=artifacts.editable.cv_sha256,
        sections=sections,
        rendered_pages=artifacts.cv_pdf.rendered_lines,
        policy=selected,
        target_role_title=request.role_title,
    )


@dataclass(frozen=True)
class CVCompositionOrchestrationResult:
    editorial_receipt: EditorialCompositionReceipt
    initial_constraint_receipt: CVConstraintReceipt
    initial_artifacts: ApplicationArtifacts
    initial_quality_receipt: DocumentQualityReceipt
    initial_benchmark_receipt: CVBenchmarkDiagnosticReceipt | None
    recruiter_receipt: RecruiterAssessmentReceipt
    rebuild: EvidenceSafeRebuildResult
    final_constraint_receipt: CVConstraintReceipt
    final_artifacts: ApplicationArtifacts
    final_quality_receipt: DocumentQualityReceipt
    final_benchmark_receipt: CVBenchmarkDiagnosticReceipt | None
    orchestration_sha256: str
    release_authority: bool = False
    schema_version: str = ORCHESTRATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != ORCHESTRATION_SCHEMA:
            raise CVCompositionServiceError("CV orchestration schema is unsupported")
        self.editorial_receipt.__post_init__()
        self.initial_constraint_receipt.__post_init__()
        self.initial_quality_receipt.__post_init__()
        self.recruiter_receipt.__post_init__()
        self.rebuild.__post_init__()
        self.final_constraint_receipt.__post_init__()
        self.final_quality_receipt.__post_init__()
        if (self.initial_benchmark_receipt is None) != (self.final_benchmark_receipt is None):
            raise CVCompositionServiceError("CV benchmark diagnostics are incomplete")
        if self.initial_benchmark_receipt is not None:
            self.initial_benchmark_receipt.__post_init__()
            self.final_benchmark_receipt.__post_init__()
        verify_application_artifacts(self.initial_artifacts)
        verify_application_artifacts(self.final_artifacts)
        _digest(self.orchestration_sha256, "CV orchestration hash")
        if self.release_authority is not False:
            raise CVCompositionServiceError("CV orchestration cannot grant release authority")
        if (
            self.initial_constraint_receipt.source_id != self.initial_artifacts.source_id
            or self.initial_constraint_receipt.cv_sha256
            != self.initial_artifacts.editable.cv_sha256
            or self.final_constraint_receipt.source_id != self.final_artifacts.source_id
            or self.final_constraint_receipt.cv_sha256
            != self.final_artifacts.editable.cv_sha256
            or self.initial_quality_receipt.artifact_set_sha256
            != self.initial_artifacts.artifact_set_sha256
            or self.final_quality_receipt.artifact_set_sha256
            != self.final_artifacts.artifact_set_sha256
            or self.recruiter_receipt.package_hashes.get("cv_pdf_sha256")
            != self.initial_artifacts.cv_pdf.pdf_sha256
            or self.recruiter_receipt.package_hashes.get("cover_letter_pdf_sha256")
            != self.initial_artifacts.cover_letter_pdf.pdf_sha256
            or self.rebuild.recruiter_receipt_sha256
            != self.recruiter_receipt.receipt_sha256
            or self.rebuild.editorial_composition_receipt_sha256
            != self.editorial_receipt.receipt_sha256
        ):
            raise CVCompositionServiceError("CV orchestration receipts are out of order")
        if self.initial_benchmark_receipt is not None and (
            self.initial_benchmark_receipt.draft_sha256
            != self.editorial_receipt.final_draft_sha256
            or self.final_benchmark_receipt.draft_sha256
            != self.rebuild.rebuilt_draft.draft_sha256
            or self.initial_benchmark_receipt.manifest_sha256
            != self.final_benchmark_receipt.manifest_sha256
        ):
            raise CVCompositionServiceError("CV benchmark receipts are out of order")
        if self.orchestration_sha256 != content_hash(
            self.document(include_identity=False)
        ):
            raise CVCompositionServiceError("CV orchestration identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "editorial_receipt_sha256": self.editorial_receipt.receipt_sha256,
            "final_artifact_set_sha256": self.final_artifacts.artifact_set_sha256,
            "final_constraint_receipt_sha256": (
                self.final_constraint_receipt.receipt_sha256
            ),
            "final_quality_receipt_sha256": self.final_quality_receipt.receipt_sha256,
            "initial_artifact_set_sha256": self.initial_artifacts.artifact_set_sha256,
            "initial_constraint_receipt_sha256": (
                self.initial_constraint_receipt.receipt_sha256
            ),
            "initial_quality_receipt_sha256": self.initial_quality_receipt.receipt_sha256,
            "initial_benchmark_receipt_sha256": (
                self.initial_benchmark_receipt.receipt_sha256
                if self.initial_benchmark_receipt is not None else None
            ),
            "rebuild_sha256": self.rebuild.rebuild_sha256,
            "recruiter_receipt_sha256": self.recruiter_receipt.receipt_sha256,
            "final_benchmark_receipt_sha256": (
                self.final_benchmark_receipt.receipt_sha256
                if self.final_benchmark_receipt is not None else None
            ),
            "release_authority": False,
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["orchestration_sha256"] = self.orchestration_sha256
        return value


def run_cv_composition_orchestration(
    *,
    request: CVEditorialRequest,
    writer_draft: CVEditorialDraft,
    humanized_draft: CVEditorialDraft,
    writer_evidence: EditorialStageEvidence,
    humanizer_evidence: EditorialStageEvidence,
    base_source: ApplicationSource,
    listing_text: str,
    form_fields: Sequence[tuple[str, str, str]],
    bindings: Sequence[RecruiterImprovementBinding],
    recruiter_assessor: RecruiterAssessor | None = None,
    recruiter_receipt: RecruiterAssessmentReceipt | None = None,
    improvement_binder: ImprovementBinder | None = None,
    benchmark_manifest: CVBenchmarkManifest | None = None,
) -> CVCompositionOrchestrationResult:
    """Run one offline-safe CV composition, assessment and rebuild cycle."""

    if (recruiter_assessor is None) == (recruiter_receipt is None):
        raise CVCompositionServiceError(
            "provide exactly one recruiter assessor or precomputed receipt"
        )
    if improvement_binder is not None and bindings:
        raise CVCompositionServiceError(
            "provide static bindings or one post-assessment binder, not both"
        )
    listing_sha256 = hashlib.sha256(listing_text.encode()).hexdigest()
    if request.vacancy_sha256 != listing_sha256:
        raise CVCompositionServiceError("job listing differs from editorial request")
    _, _, editorial_receipt = admit_editorial_composition(
        request=request,
        writer_draft=writer_draft,
        final_draft=humanized_draft,
        writer_evidence=writer_evidence,
        humanizer_evidence=humanizer_evidence,
    )
    initial_source = _source_for_editorial_draft(
        base_source=base_source,
        request=request,
        draft=humanized_draft,
    )
    initial_artifacts = render_pdf_artifacts(initial_source)
    initial_constraint = _validate_artifact_cv(
        request=request,
        draft=humanized_draft,
        source=initial_source,
        artifacts=initial_artifacts,
    )
    initial_quality = verify_document_quality(initial_artifacts)
    initial_benchmark = (
        evaluate_cv_benchmark(
            draft=humanized_draft,
            listing_text=listing_text,
            vacancy_sha256=request.vacancy_sha256,
            manifest=benchmark_manifest,
        )
        if benchmark_manifest is not None else None
    )
    package = RecruiterAssessmentPackage(
        listing_text=listing_text,
        listing_text_sha256=listing_sha256,
        cv_pdf_bytes=initial_artifacts.cv_pdf.pdf_bytes,
        cover_letter_pdf_bytes=initial_artifacts.cover_letter_pdf.pdf_bytes,
        form_fields=tuple(form_fields),
        intended_vacancy=IntendedVacancy(
            job_key=initial_source.job_key,
            vacancy_sha256=initial_source.vacancy_sha256,
            role_title=initial_source.role_title,
            company_name=initial_source.company_name,
        ),
    )
    assessed = (
        recruiter_assessor(package)
        if recruiter_assessor is not None
        else recruiter_receipt
    )
    if not isinstance(assessed, RecruiterAssessmentReceipt):
        raise CVCompositionServiceError("recruiter assessor returned no valid receipt")
    resolved_bindings = (
        tuple(improvement_binder(request, assessed))
        if improvement_binder is not None
        else tuple(bindings)
    )
    if any(not isinstance(item, RecruiterImprovementBinding) for item in resolved_bindings):
        raise CVCompositionServiceError("improvement binder returned invalid bindings")
    rebuild = rebuild_from_recruiter_assessment(
        request=request,
        admitted_draft=humanized_draft,
        editorial_receipt=editorial_receipt,
        recruiter_receipt=assessed,
        recruiter_package=package,
        bindings=resolved_bindings,
        assessed_cv_text_sha256=initial_artifacts.cv_pdf.extracted_text_sha256,
    )
    final_source = _source_for_editorial_draft(
        base_source=base_source,
        request=request,
        draft=rebuild.rebuilt_draft,
    )
    final_artifacts = render_pdf_artifacts(final_source)
    final_constraint = _validate_artifact_cv(
        request=request,
        draft=rebuild.rebuilt_draft,
        source=final_source,
        artifacts=final_artifacts,
    )
    final_quality = verify_document_quality(final_artifacts)
    final_benchmark = (
        evaluate_cv_benchmark(
            draft=rebuild.rebuilt_draft,
            listing_text=listing_text,
            vacancy_sha256=request.vacancy_sha256,
            manifest=benchmark_manifest,
        )
        if benchmark_manifest is not None else None
    )
    values = {
        "editorial_receipt_sha256": editorial_receipt.receipt_sha256,
        "final_artifact_set_sha256": final_artifacts.artifact_set_sha256,
        "final_constraint_receipt_sha256": final_constraint.receipt_sha256,
        "final_quality_receipt_sha256": final_quality.receipt_sha256,
        "initial_artifact_set_sha256": initial_artifacts.artifact_set_sha256,
        "initial_constraint_receipt_sha256": initial_constraint.receipt_sha256,
        "initial_quality_receipt_sha256": initial_quality.receipt_sha256,
        "initial_benchmark_receipt_sha256": (
            initial_benchmark.receipt_sha256 if initial_benchmark is not None else None
        ),
        "rebuild_sha256": rebuild.rebuild_sha256,
        "recruiter_receipt_sha256": assessed.receipt_sha256,
        "final_benchmark_receipt_sha256": (
            final_benchmark.receipt_sha256 if final_benchmark is not None else None
        ),
        "release_authority": False,
        "schema_version": ORCHESTRATION_SCHEMA,
    }
    return CVCompositionOrchestrationResult(
        editorial_receipt=editorial_receipt,
        initial_constraint_receipt=initial_constraint,
        initial_artifacts=initial_artifacts,
        initial_quality_receipt=initial_quality,
        initial_benchmark_receipt=initial_benchmark,
        recruiter_receipt=assessed,
        rebuild=rebuild,
        final_constraint_receipt=final_constraint,
        final_artifacts=final_artifacts,
        final_quality_receipt=final_quality,
        final_benchmark_receipt=final_benchmark,
        orchestration_sha256=content_hash(values),
    )

__all__ = [
    "CVCompositionOrchestrationResult",
    "CVCompositionServiceError",
    "CandidateApplicationPackage",
    "CVPopplerQualityReceipt",
    "GenerationRevisionWriter",
    "ImprovementBinder",
    "RecruiterAssessor",
    "build_candidate_application_package",
    "run_cv_composition_orchestration",
    "verify_poppler_cv_quality",
]
