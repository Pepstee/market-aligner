"""Evidence-safe admission of detached recruiter improvements.

The detached recruiter is diagnostic only.  This module never treats its
recommendations as candidate facts or mutation authority.  A recommendation
can change a CV draft only through an exact binding to claims already present
in the candidate-authority-backed editorial request.  Everything else becomes
a roadmap item.

This is the useful seam recovered from the quarantined adversarial rebuild.  It
does not load deployment metadata, browsers or submission machinery.  The
full-application path below may rebuild exact CV, cover-letter and form-answer
artifacts and obtain fresh detached review receipts, but those receipts still
carry no release or mutation authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from career_automation.adversarial_recruiter import (
    RecruiterAssessmentPackage,
    RecruiterAssessmentReceipt,
    assess_application_as_recruiter,
    verify_recruiter_assessment_receipt,
)
from career_automation.application_compiler import (
    ApplicationSource,
    FactAuthority,
    FactualSentence,
    ProfileFactAuthority,
    verify_application_source,
)
from career_automation.application_sanity_review import (
    SanityReviewPackage,
    SanityReviewReceipt,
    VacancyReviewMaterial,
    canonical_form_fields,
    package_from_application,
    review_application_package,
    verify_sanity_review_receipt,
)
from career_automation.evidence_matching import content_hash
from career_automation.external_document_assurance import IntendedVacancy
from career_automation.rendering import (
    ApplicationArtifacts,
    render_pdf_artifacts,
    verify_application_artifacts,
)
from llm.client import LLMClient

from .constraints import (
    CVConstraintReceipt,
    CVPolicy,
    policy_for_candidate,
    validate_generated_cv,
)
from .editorial_composition import (
    ApprovedCVClaim,
    CVEditorialDraft,
    CVEditorialRequest,
    CVSection,
    EditorialAtom,
    EditorialCompositionReceipt,
    ApprovedCoverLetterClaim,
    CoverLetterEditorialCompositionReceipt,
    CoverLetterEditorialDraft,
    CoverLetterEditorialRequest,
    CoverLetterSection,
    build_editorial_draft,
    build_cover_letter_editorial_draft,
    validate_editorial_draft,
    validate_cover_letter_editorial_draft,
)


BINDING_SCHEMA = "jaa.cv-recruiter-improvement-binding.v1"
REBUILD_SCHEMA = "jaa.cv-evidence-safe-rebuild.v1"
COVER_LETTER_BINDING_SCHEMA = "jaa.cover-letter-recruiter-improvement-binding.v1"
COVER_LETTER_REBUILD_SCHEMA = "jaa.cover-letter-evidence-safe-rebuild.v1"
FINALIZED_SCHEMA = "jaa.cv-finalized-rebuild.v1"
APPLICATION_PLAN_SCHEMA = "jaa.application-evidence-safe-rebuild-plan.v1"
APPLICATION_RESULT_SCHEMA = "jaa.application-evidence-safe-rebuild-result.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdversarialRebuildError(ValueError):
    """Recruiter feedback could not be admitted without inventing evidence."""


def _required(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise AdversarialRebuildError(f"{label} is absent or malformed")
    return value


def _digest(value: object, label: str) -> str:
    text = _required(value, label)
    if not _SHA256.fullmatch(text):
        raise AdversarialRebuildError(f"{label} is not a lowercase SHA-256 digest")
    return text


@dataclass(frozen=True)
class RecruiterImprovementBinding:
    improvement_index: int
    target_heading: str
    claim_ids: tuple[str, ...]
    authority_source_sha256: str
    model_result_sha256: str
    binding_source_sha256: str
    binding_sha256: str
    schema_version: str = BINDING_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != BINDING_SCHEMA:
            raise AdversarialRebuildError("improvement binding schema is unsupported")
        if type(self.improvement_index) is not int or self.improvement_index < 0:
            raise AdversarialRebuildError("improvement binding index is invalid")
        _required(self.target_heading, "improvement target heading")
        if not self.claim_ids or any(
            not isinstance(value, str) or not value.strip() for value in self.claim_ids
        ):
            raise AdversarialRebuildError("improvement binding has no approved claims")
        if len(set(self.claim_ids)) != len(self.claim_ids):
            raise AdversarialRebuildError("improvement binding repeats approved claims")
        for value, label in (
            (self.authority_source_sha256, "candidate authority hash"),
            (self.model_result_sha256, "recruiter result hash"),
            (self.binding_source_sha256, "improvement binding source hash"),
            (self.binding_sha256, "improvement binding hash"),
        ):
            _digest(value, label)
        if self.binding_sha256 != content_hash(self.document(include_identity=False)):
            raise AdversarialRebuildError("improvement binding identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "authority_source_sha256": self.authority_source_sha256,
            "binding_source_sha256": self.binding_source_sha256,
            "claim_ids": list(self.claim_ids),
            "improvement_index": self.improvement_index,
            "model_result_sha256": self.model_result_sha256,
            "schema_version": self.schema_version,
            "target_heading": self.target_heading,
        }
        if include_identity:
            value["binding_sha256"] = self.binding_sha256
        return value


def bind_recruiter_improvement(
    *,
    improvement_index: int,
    target_heading: str,
    claim_ids: Sequence[str],
    authority_source_sha256: str,
    model_result_sha256: str,
    binding_source_sha256: str,
) -> RecruiterImprovementBinding:
    values = {
        "authority_source_sha256": authority_source_sha256,
        "binding_source_sha256": binding_source_sha256,
        "claim_ids": list(claim_ids),
        "improvement_index": improvement_index,
        "model_result_sha256": model_result_sha256,
        "schema_version": BINDING_SCHEMA,
        "target_heading": target_heading,
    }
    return RecruiterImprovementBinding(
        improvement_index=improvement_index,
        target_heading=target_heading,
        claim_ids=tuple(claim_ids),
        authority_source_sha256=authority_source_sha256,
        model_result_sha256=model_result_sha256,
        binding_source_sha256=binding_source_sha256,
        binding_sha256=content_hash(values),
    )


@dataclass(frozen=True)
class AppliedRecruiterImprovement:
    improvement_index: int
    recommendation: str
    target_heading: str
    claim_ids: tuple[str, ...]
    binding_sha256: str

    def __post_init__(self) -> None:
        if type(self.improvement_index) is not int or self.improvement_index < 0:
            raise AdversarialRebuildError("applied improvement index is invalid")
        _required(self.recommendation, "applied recruiter recommendation")
        _required(self.target_heading, "applied improvement target heading")
        if not self.claim_ids or len(set(self.claim_ids)) != len(self.claim_ids):
            raise AdversarialRebuildError("applied improvement claims are invalid")
        for claim_id in self.claim_ids:
            _required(claim_id, "applied improvement claim ID")
        _digest(self.binding_sha256, "applied improvement binding hash")

    def document(self) -> dict[str, object]:
        return {
            "binding_sha256": self.binding_sha256,
            "claim_ids": list(self.claim_ids),
            "improvement_index": self.improvement_index,
            "recommendation": self.recommendation,
            "target_heading": self.target_heading,
        }


@dataclass(frozen=True)
class RebuildRoadmapItem:
    source: str
    source_index: int
    category: str
    recommendation: str
    expected_effect: str
    time_horizon: str | None
    reason_code: str

    def __post_init__(self) -> None:
        if self.source not in {"application_improvement", "profile_improvement"}:
            raise AdversarialRebuildError("roadmap source is unsupported")
        if type(self.source_index) is not int or self.source_index < 0:
            raise AdversarialRebuildError("roadmap source index is invalid")
        for value, label in (
            (self.category, "roadmap category"),
            (self.recommendation, "roadmap recommendation"),
            (self.expected_effect, "roadmap expected effect"),
            (self.reason_code, "roadmap reason code"),
        ):
            _required(value, label)
        if self.time_horizon is not None:
            _required(self.time_horizon, "roadmap time horizon")

    def document(self) -> dict[str, object]:
        return {
            "category": self.category,
            "expected_effect": self.expected_effect,
            "reason_code": self.reason_code,
            "recommendation": self.recommendation,
            "source": self.source,
            "source_index": self.source_index,
            "time_horizon": self.time_horizon,
        }


@dataclass(frozen=True)
class EvidenceSafeRebuildResult:
    recruiter_receipt_sha256: str
    editorial_composition_receipt_sha256: str
    original_draft_sha256: str
    rebuilt_draft: CVEditorialDraft
    applied: tuple[AppliedRecruiterImprovement, ...]
    roadmap: tuple[RebuildRoadmapItem, ...]
    rebuild_sha256: str
    release_authority: bool = False
    schema_version: str = REBUILD_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != REBUILD_SCHEMA:
            raise AdversarialRebuildError("evidence-safe rebuild schema is unsupported")
        for value, label in (
            (self.recruiter_receipt_sha256, "recruiter receipt hash"),
            (
                self.editorial_composition_receipt_sha256,
                "editorial composition receipt hash",
            ),
            (self.original_draft_sha256, "original editorial draft hash"),
            (self.rebuild_sha256, "evidence-safe rebuild hash"),
        ):
            _digest(value, label)
        self.rebuilt_draft.__post_init__()
        for item in self.applied:
            item.__post_init__()
        for item in self.roadmap:
            item.__post_init__()
        applied_indexes = tuple(item.improvement_index for item in self.applied)
        roadmap_keys = tuple((item.source, item.source_index) for item in self.roadmap)
        roadmap_indexes = tuple(
            item.source_index
            for item in self.roadmap
            if item.source == "application_improvement"
        )
        if (
            len(set(applied_indexes)) != len(applied_indexes)
            or len(set(roadmap_keys)) != len(roadmap_keys)
            or len(set(roadmap_indexes)) != len(roadmap_indexes)
            or set(applied_indexes) & set(roadmap_indexes)
        ):
            raise AdversarialRebuildError("rebuild dispositions are duplicated")
        if self.release_authority is not False:
            raise AdversarialRebuildError("rebuild cannot grant release authority")
        if self.rebuild_sha256 != content_hash(self.document(include_identity=False)):
            raise AdversarialRebuildError("evidence-safe rebuild identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "applied": [item.document() for item in self.applied],
            "editorial_composition_receipt_sha256": (
                self.editorial_composition_receipt_sha256
            ),
            "original_draft_sha256": self.original_draft_sha256,
            "rebuilt_draft_sha256": self.rebuilt_draft.draft_sha256,
            "recruiter_receipt_sha256": self.recruiter_receipt_sha256,
            "release_authority": False,
            "roadmap": [item.document() for item in self.roadmap],
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["rebuild_sha256"] = self.rebuild_sha256
        return value


def _application_improvements(
    receipt: RecruiterAssessmentReceipt,
) -> tuple[Mapping[str, object], ...]:
    raw = receipt.model_result["application_improvements"]
    if not isinstance(raw, list) or any(not isinstance(item, Mapping) for item in raw):
        raise AdversarialRebuildError(
            "recruiter application improvements are malformed"
        )
    return tuple(raw)


def _profile_improvements(
    receipt: RecruiterAssessmentReceipt,
) -> tuple[Mapping[str, object], ...]:
    raw = receipt.model_result["profile_improvements"]
    if not isinstance(raw, list) or any(not isinstance(item, Mapping) for item in raw):
        raise AdversarialRebuildError("recruiter profile improvements are malformed")
    return tuple(raw)


def _promote_claims(
    draft: CVEditorialDraft,
    *,
    heading: str,
    claims: Sequence[ApprovedCVClaim],
) -> CVEditorialDraft:
    section_index = next(
        (
            index
            for index, section in enumerate(draft.sections)
            if section.heading == heading
        ),
        None,
    )
    if section_index is None:
        raise AdversarialRebuildError("bound improvement targets an absent CV section")
    selected_ids = tuple(claim.claim_id for claim in claims)
    sections = list(draft.sections)
    target = sections[section_index]
    claim_locations = {
        atom.claim_id: section.heading
        for section in sections
        for atom in section.atoms
        if atom.source_kind == "approved_claim"
    }
    if any(
        claim_id in claim_locations and claim_locations[claim_id] != heading
        for claim_id in selected_ids
    ):
        raise AdversarialRebuildError(
            "bound claim already belongs to another CV section"
        )

    leading_connectives: list[EditorialAtom] = []
    remaining: list[EditorialAtom] = []
    seen_claim = False
    for atom in target.atoms:
        if atom.source_kind == "connective" and not seen_claim:
            leading_connectives.append(atom)
            continue
        seen_claim = seen_claim or atom.source_kind == "approved_claim"
        if atom.claim_id not in selected_ids:
            remaining.append(atom)
    promoted = [
        EditorialAtom(
            source_kind="approved_claim", text=claim.text, claim_id=claim.claim_id
        )
        for claim in claims
    ]
    sections[section_index] = CVSection(
        heading=heading,
        atoms=tuple((*leading_connectives, *promoted, *remaining)),
    )
    return build_editorial_draft(
        candidate_name=draft.candidate_name,
        candidate_city=draft.candidate_city,
        sections=sections,
    )


def rebuild_from_recruiter_assessment(
    *,
    request: CVEditorialRequest,
    admitted_draft: CVEditorialDraft,
    editorial_receipt: EditorialCompositionReceipt,
    recruiter_receipt: RecruiterAssessmentReceipt,
    recruiter_package: RecruiterAssessmentPackage,
    bindings: Sequence[RecruiterImprovementBinding],
    assessed_cv_text_sha256: str | None = None,
    cover_letter_module_active: bool = False,
) -> EvidenceSafeRebuildResult:
    """Apply evidence-bound CV recommendations and route every gap to roadmap."""

    validate_editorial_draft(request, admitted_draft)
    editorial_receipt.__post_init__()
    if editorial_receipt.request_sha256 != request.request_sha256 or (
        editorial_receipt.final_draft_sha256 != admitted_draft.draft_sha256
    ):
        raise AdversarialRebuildError("editorial draft lacks its admission receipt")
    verify_recruiter_assessment_receipt(recruiter_receipt, recruiter_package)
    receipt_cv_text_sha256 = recruiter_receipt.package_hashes.get("cv_text_sha256")
    expected_cv_text_sha256 = (
        hashlib.sha256(
            _recruiter_extracted_cv_text(admitted_draft).encode()
        ).hexdigest()
        if assessed_cv_text_sha256 is None
        else _digest(assessed_cv_text_sha256, "assessed CV text hash")
    )
    if receipt_cv_text_sha256 != expected_cv_text_sha256:
        raise AdversarialRebuildError(
            "recruiter assessment did not inspect the admitted editorial CV"
        )
    if (
        recruiter_receipt.intended_vacancy.role_title != request.role_title
        or recruiter_receipt.intended_vacancy.company_name != request.company_name
        or recruiter_receipt.package_hashes.get("listing_text_sha256")
        != request.vacancy_sha256
    ):
        raise AdversarialRebuildError("recruiter assessment targets another vacancy")

    improvements = _application_improvements(recruiter_receipt)
    binding_by_index: dict[int, RecruiterImprovementBinding] = {}
    for binding in bindings:
        binding.__post_init__()
        if binding.improvement_index in binding_by_index:
            raise AdversarialRebuildError("duplicate binding for recruiter improvement")
        if binding.improvement_index >= len(improvements):
            raise AdversarialRebuildError("binding references an absent improvement")
        if (
            binding.authority_source_sha256 != request.authority.source_sha256
            or binding.model_result_sha256 != recruiter_receipt.model_result_sha256
        ):
            raise AdversarialRebuildError(
                "improvement binding targets different authority"
            )
        binding_by_index[binding.improvement_index] = binding

    approved = {claim.claim_id: claim for claim in request.approved_claims}
    rebuilt = admitted_draft
    applied: list[AppliedRecruiterImprovement] = []
    roadmap: list[RebuildRoadmapItem] = []
    for index, improvement in enumerate(improvements):
        target = _required(improvement.get("target"), "recruiter improvement target")
        recommendation = _required(
            improvement.get("recommendation"), "recruiter recommendation"
        )
        expected_effect = _required(
            improvement.get("expected_effect"), "recruiter expected effect"
        )
        binding = binding_by_index.get(index)
        if target == "cover_letter" and cover_letter_module_active:
            if binding is not None:
                raise AdversarialRebuildError(
                    "cover-letter advice cannot receive a CV evidence binding"
                )
            continue
        if binding is None or target not in {"cv", "positioning"}:
            if binding is not None:
                raise AdversarialRebuildError(
                    "non-CV recruiter improvement cannot receive a CV evidence binding"
                )
            roadmap.append(
                RebuildRoadmapItem(
                    source="application_improvement",
                    source_index=index,
                    category=target,
                    recommendation=recommendation,
                    expected_effect=expected_effect,
                    time_horizon=None,
                    reason_code=(
                        "outside_cv_module"
                        if target not in {"cv", "positioning"}
                        else "unsupported_by_candidate_authority"
                    ),
                )
            )
            continue
        claims: list[ApprovedCVClaim] = []
        for claim_id in binding.claim_ids:
            claim = approved.get(claim_id)
            if claim is None:
                raise AdversarialRebuildError(
                    "binding cites an unapproved candidate claim"
                )
            claims.append(claim)
        rebuilt = _promote_claims(
            rebuilt,
            heading=binding.target_heading,
            claims=claims,
        )
        validate_editorial_draft(request, rebuilt)
        applied.append(
            AppliedRecruiterImprovement(
                improvement_index=index,
                recommendation=recommendation,
                target_heading=binding.target_heading,
                claim_ids=binding.claim_ids,
                binding_sha256=binding.binding_sha256,
            )
        )

    for index, improvement in enumerate(_profile_improvements(recruiter_receipt)):
        roadmap.append(
            RebuildRoadmapItem(
                source="profile_improvement",
                source_index=index,
                category=_required(improvement.get("category"), "profile category"),
                recommendation=_required(
                    improvement.get("recommendation"), "profile recommendation"
                ),
                expected_effect=_required(
                    improvement.get("expected_effect"), "profile expected effect"
                ),
                time_horizon=_required(
                    improvement.get("time_horizon"), "profile time horizon"
                ),
                reason_code="profile_gap_not_current_cv_evidence",
            )
        )

    values = {
        "applied": [item.document() for item in applied],
        "editorial_composition_receipt_sha256": editorial_receipt.receipt_sha256,
        "original_draft_sha256": admitted_draft.draft_sha256,
        "rebuilt_draft_sha256": rebuilt.draft_sha256,
        "recruiter_receipt_sha256": recruiter_receipt.receipt_sha256,
        "release_authority": False,
        "roadmap": [item.document() for item in roadmap],
        "schema_version": REBUILD_SCHEMA,
    }
    return EvidenceSafeRebuildResult(
        recruiter_receipt_sha256=recruiter_receipt.receipt_sha256,
        editorial_composition_receipt_sha256=editorial_receipt.receipt_sha256,
        original_draft_sha256=admitted_draft.draft_sha256,
        rebuilt_draft=rebuilt,
        applied=tuple(applied),
        roadmap=tuple(roadmap),
        rebuild_sha256=content_hash(values),
    )


@dataclass(frozen=True)
class CoverLetterRecruiterImprovementBinding:
    improvement_index: int
    target_heading: str
    claim_ids: tuple[str, ...]
    authority_source_sha256: str
    vacancy_sha256: str
    model_result_sha256: str
    binding_source_sha256: str
    binding_sha256: str
    schema_version: str = COVER_LETTER_BINDING_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != COVER_LETTER_BINDING_SCHEMA:
            raise AdversarialRebuildError("cover-letter binding schema is unsupported")
        if type(self.improvement_index) is not int or self.improvement_index < 0:
            raise AdversarialRebuildError("cover-letter binding index is invalid")
        if self.target_heading not in {"Evidence Match", "Company Fit"}:
            raise AdversarialRebuildError("cover-letter binding target is unsupported")
        if not self.claim_ids or len(set(self.claim_ids)) != len(self.claim_ids):
            raise AdversarialRebuildError("cover-letter binding claims are invalid")
        for claim_id in self.claim_ids:
            _required(claim_id, "cover-letter binding claim ID")
        for value, label in (
            (self.authority_source_sha256, "cover-letter candidate authority hash"),
            (self.vacancy_sha256, "cover-letter vacancy hash"),
            (self.model_result_sha256, "cover-letter recruiter result hash"),
            (self.binding_source_sha256, "cover-letter binding source hash"),
            (self.binding_sha256, "cover-letter binding hash"),
        ):
            _digest(value, label)
        if self.binding_sha256 != content_hash(self.document(include_identity=False)):
            raise AdversarialRebuildError("cover-letter binding identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "authority_source_sha256": self.authority_source_sha256,
            "binding_source_sha256": self.binding_source_sha256,
            "claim_ids": list(self.claim_ids),
            "improvement_index": self.improvement_index,
            "model_result_sha256": self.model_result_sha256,
            "schema_version": self.schema_version,
            "target_heading": self.target_heading,
            "vacancy_sha256": self.vacancy_sha256,
        }
        if include_identity:
            value["binding_sha256"] = self.binding_sha256
        return value


def bind_cover_letter_recruiter_improvement(
    *,
    improvement_index: int,
    target_heading: str,
    claim_ids: Sequence[str],
    authority_source_sha256: str,
    vacancy_sha256: str,
    model_result_sha256: str,
    binding_source_sha256: str,
) -> CoverLetterRecruiterImprovementBinding:
    values = {
        "authority_source_sha256": authority_source_sha256,
        "binding_source_sha256": binding_source_sha256,
        "claim_ids": list(claim_ids),
        "improvement_index": improvement_index,
        "model_result_sha256": model_result_sha256,
        "schema_version": COVER_LETTER_BINDING_SCHEMA,
        "target_heading": target_heading,
        "vacancy_sha256": vacancy_sha256,
    }
    return CoverLetterRecruiterImprovementBinding(
        improvement_index=improvement_index,
        target_heading=target_heading,
        claim_ids=tuple(claim_ids),
        authority_source_sha256=authority_source_sha256,
        vacancy_sha256=vacancy_sha256,
        model_result_sha256=model_result_sha256,
        binding_source_sha256=binding_source_sha256,
        binding_sha256=content_hash(values),
    )


@dataclass(frozen=True)
class CoverLetterEvidenceSafeRebuildResult:
    recruiter_receipt_sha256: str
    editorial_composition_receipt_sha256: str
    original_draft_sha256: str
    rebuilt_draft: CoverLetterEditorialDraft
    applied: tuple[AppliedRecruiterImprovement, ...]
    roadmap: tuple[RebuildRoadmapItem, ...]
    rebuild_sha256: str
    release_authority: bool = False
    schema_version: str = COVER_LETTER_REBUILD_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != COVER_LETTER_REBUILD_SCHEMA:
            raise AdversarialRebuildError("cover-letter rebuild schema is unsupported")
        for value, label in (
            (self.recruiter_receipt_sha256, "cover-letter recruiter receipt hash"),
            (
                self.editorial_composition_receipt_sha256,
                "cover-letter composition receipt hash",
            ),
            (self.original_draft_sha256, "original cover-letter draft hash"),
            (self.rebuild_sha256, "cover-letter rebuild hash"),
        ):
            _digest(value, label)
        self.rebuilt_draft.__post_init__()
        if self.release_authority is not False:
            raise AdversarialRebuildError(
                "cover-letter rebuild cannot grant release authority"
            )
        if self.rebuild_sha256 != content_hash(self.document(include_identity=False)):
            raise AdversarialRebuildError("cover-letter rebuild identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "applied": [item.document() for item in self.applied],
            "editorial_composition_receipt_sha256": self.editorial_composition_receipt_sha256,
            "original_draft_sha256": self.original_draft_sha256,
            "rebuilt_draft_sha256": self.rebuilt_draft.draft_sha256,
            "recruiter_receipt_sha256": self.recruiter_receipt_sha256,
            "release_authority": False,
            "roadmap": [item.document() for item in self.roadmap],
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["rebuild_sha256"] = self.rebuild_sha256
        return value


def _promote_cover_letter_claims(
    draft: CoverLetterEditorialDraft,
    *,
    heading: str,
    claims: Sequence[ApprovedCoverLetterClaim],
) -> CoverLetterEditorialDraft:
    sections = list(draft.sections)
    index = next(
        (i for i, section in enumerate(sections) if section.heading == heading), None
    )
    if index is None:
        raise AdversarialRebuildError("cover-letter binding targets an absent section")
    target = sections[index]
    selected_ids = tuple(claim.claim_id for claim in claims)
    existing = {
        atom.claim_id: atom
        for atom in target.atoms
        if atom.source_kind == "approved_claim"
    }
    if any(claim_id not in existing for claim_id in selected_ids):
        raise AdversarialRebuildError(
            "cover-letter binding cannot introduce an unused claim"
        )
    promoted = tuple(existing[claim_id] for claim_id in selected_ids)
    remaining = tuple(
        atom
        for atom in target.atoms
        if atom.source_kind != "approved_claim" or atom.claim_id not in selected_ids
    )
    leading = tuple(atom for atom in remaining if atom.source_kind == "connective")
    trailing = tuple(atom for atom in remaining if atom.source_kind == "approved_claim")
    sections[index] = CoverLetterSection(heading, (*leading, *promoted, *trailing))
    return build_cover_letter_editorial_draft(
        candidate_name=draft.candidate_name, sections=sections
    )


def rebuild_cover_letter_from_recruiter_assessment(
    *,
    request: CoverLetterEditorialRequest,
    admitted_draft: CoverLetterEditorialDraft,
    editorial_receipt: CoverLetterEditorialCompositionReceipt,
    recruiter_receipt: RecruiterAssessmentReceipt,
    recruiter_package: RecruiterAssessmentPackage,
    bindings: Sequence[CoverLetterRecruiterImprovementBinding],
    assessed_cover_letter_text_sha256: str,
) -> CoverLetterEvidenceSafeRebuildResult:
    """Apply only exact authority-bound cover-letter recruiter advice."""
    validate_cover_letter_editorial_draft(request, admitted_draft)
    editorial_receipt.__post_init__()
    if (
        editorial_receipt.request_sha256 != request.request_sha256
        or editorial_receipt.final_draft_sha256 != admitted_draft.draft_sha256
    ):
        raise AdversarialRebuildError("cover-letter draft lacks its admission receipt")
    verify_recruiter_assessment_receipt(recruiter_receipt, recruiter_package)
    if recruiter_receipt.package_hashes.get("cover_letter_text_sha256") != _digest(
        assessed_cover_letter_text_sha256, "assessed cover-letter text hash"
    ):
        raise AdversarialRebuildError(
            "recruiter did not inspect the admitted cover letter"
        )
    if (
        recruiter_receipt.intended_vacancy.role_title != request.role_title
        or recruiter_receipt.intended_vacancy.company_name != request.company_name
        or recruiter_receipt.package_hashes.get("listing_text_sha256")
        != request.vacancy_sha256
    ):
        raise AdversarialRebuildError(
            "cover-letter recruiter assessment targets another vacancy"
        )
    improvements = _application_improvements(recruiter_receipt)
    binding_by_index: dict[int, CoverLetterRecruiterImprovementBinding] = {}
    for binding in bindings:
        binding.__post_init__()
        if (
            binding.improvement_index in binding_by_index
            or binding.improvement_index >= len(improvements)
        ):
            raise AdversarialRebuildError(
                "cover-letter binding index is duplicate or absent"
            )
        if (
            binding.authority_source_sha256 != request.authority.source_sha256
            or binding.vacancy_sha256 != request.vacancy_sha256
            or binding.model_result_sha256 != recruiter_receipt.model_result_sha256
            or improvements[binding.improvement_index].get("target") != "cover_letter"
        ):
            raise AdversarialRebuildError(
                "cover-letter binding targets different authority or advice"
            )
        binding_by_index[binding.improvement_index] = binding
    approved = {claim.claim_id: claim for claim in request.approved_claims}
    rebuilt = admitted_draft
    applied: list[AppliedRecruiterImprovement] = []
    roadmap: list[RebuildRoadmapItem] = []
    for index, improvement in enumerate(improvements):
        if improvement.get("target") != "cover_letter":
            continue
        recommendation = _required(
            improvement.get("recommendation"), "cover-letter recommendation"
        )
        expected_effect = _required(
            improvement.get("expected_effect"), "cover-letter expected effect"
        )
        binding = binding_by_index.get(index)
        if binding is None:
            roadmap.append(
                RebuildRoadmapItem(
                    source="application_improvement",
                    source_index=index,
                    category="cover_letter",
                    recommendation=recommendation,
                    expected_effect=expected_effect,
                    time_horizon=None,
                    reason_code="unsupported_by_candidate_or_vacancy_authority",
                )
            )
            continue
        claims = []
        for claim_id in binding.claim_ids:
            claim = approved.get(claim_id)
            if claim is None or claim.section_heading != binding.target_heading:
                raise AdversarialRebuildError(
                    "cover-letter binding cites an unapproved claim"
                )
            claims.append(claim)
        rebuilt = _promote_cover_letter_claims(
            rebuilt, heading=binding.target_heading, claims=claims
        )
        validate_cover_letter_editorial_draft(request, rebuilt)
        applied.append(
            AppliedRecruiterImprovement(
                improvement_index=index,
                recommendation=recommendation,
                target_heading=binding.target_heading,
                claim_ids=binding.claim_ids,
                binding_sha256=binding.binding_sha256,
            )
        )
    values = {
        "applied": [item.document() for item in applied],
        "editorial_composition_receipt_sha256": editorial_receipt.receipt_sha256,
        "original_draft_sha256": admitted_draft.draft_sha256,
        "rebuilt_draft_sha256": rebuilt.draft_sha256,
        "recruiter_receipt_sha256": recruiter_receipt.receipt_sha256,
        "release_authority": False,
        "roadmap": [item.document() for item in roadmap],
        "schema_version": COVER_LETTER_REBUILD_SCHEMA,
    }
    return CoverLetterEvidenceSafeRebuildResult(
        recruiter_receipt_sha256=recruiter_receipt.receipt_sha256,
        editorial_composition_receipt_sha256=editorial_receipt.receipt_sha256,
        original_draft_sha256=admitted_draft.draft_sha256,
        rebuilt_draft=rebuilt,
        applied=tuple(applied),
        roadmap=tuple(roadmap),
        rebuild_sha256=content_hash(values),
    )


def render_editorial_cv_text(draft: CVEditorialDraft) -> str:
    lines = [draft.candidate_name, draft.candidate_city, ""]
    for index, section in enumerate(draft.sections):
        if index:
            lines.append("")
        lines.append(section.heading)
        lines.extend(atom.text for atom in section.atoms)
    return "\n".join(lines) + "\n"


def _recruiter_extracted_cv_text(draft: CVEditorialDraft) -> str:
    """Canonical text expected after the repository's PDF text extraction."""

    return (
        "\n".join(
            line
            for line in render_editorial_cv_text(draft).splitlines()
            if line.strip()
        )
        + "\n"
    )


@dataclass(frozen=True)
class FinalizedRebuiltCV:
    rebuild_sha256: str
    cv_text: str
    cv_sha256: str
    constraint_receipt: CVConstraintReceipt
    receipt_sha256: str
    release_authority: bool = False
    schema_version: str = FINALIZED_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != FINALIZED_SCHEMA:
            raise AdversarialRebuildError("finalized rebuild schema is unsupported")
        _digest(self.rebuild_sha256, "finalized rebuild hash")
        _digest(self.cv_sha256, "finalized CV hash")
        _digest(self.receipt_sha256, "finalized CV receipt hash")
        if hashlib.sha256(self.cv_text.encode()).hexdigest() != self.cv_sha256:
            raise AdversarialRebuildError("finalized CV text differs from its hash")
        self.constraint_receipt.__post_init__()
        if self.release_authority is not False:
            raise AdversarialRebuildError("finalized CV cannot grant release authority")
        if self.receipt_sha256 != content_hash(self.document(include_identity=False)):
            raise AdversarialRebuildError("finalized CV receipt identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "constraint_receipt_sha256": self.constraint_receipt.receipt_sha256,
            "cv_sha256": self.cv_sha256,
            "rebuild_sha256": self.rebuild_sha256,
            "release_authority": False,
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["receipt_sha256"] = self.receipt_sha256
        return value


def finalize_rebuilt_cv(
    *,
    request: CVEditorialRequest,
    rebuild: EvidenceSafeRebuildResult,
    rendered_pages: Sequence[Sequence[str]],
    policy: CVPolicy | None = None,
) -> FinalizedRebuiltCV:
    """Run the rebuilt draft through the canonical final CV constraint gate."""

    rebuild.__post_init__()
    validate_editorial_draft(request, rebuild.rebuilt_draft)
    selected = policy or policy_for_candidate(request.authority.candidate_name)
    if selected.candidate_name is not None and (
        selected.candidate_name != request.authority.candidate_name
        or selected.required_city != request.authority.candidate_city
        or selected.required_graduation != request.authority.graduation_month_year
        or selected.required_dissertation_title != request.authority.dissertation_title
    ):
        raise AdversarialRebuildError(
            "final CV policy differs from candidate authority"
        )
    cv_text = render_editorial_cv_text(rebuild.rebuilt_draft)
    cv_sha256 = hashlib.sha256(cv_text.encode()).hexdigest()
    sections = {
        section.heading: tuple(atom.text for atom in section.atoms)
        for section in rebuild.rebuilt_draft.sections
    }
    constraint_receipt = validate_generated_cv(
        source_id=rebuild.rebuild_sha256,
        candidate_name=rebuild.rebuilt_draft.candidate_name,
        candidate_city=rebuild.rebuilt_draft.candidate_city,
        cv_text=cv_text,
        cv_sha256=cv_sha256,
        sections=sections,
        rendered_pages=rendered_pages,
        policy=selected,
        target_role_title=request.role_title,
    )
    values = {
        "constraint_receipt_sha256": constraint_receipt.receipt_sha256,
        "cv_sha256": cv_sha256,
        "rebuild_sha256": rebuild.rebuild_sha256,
        "release_authority": False,
        "schema_version": FINALIZED_SCHEMA,
    }
    return FinalizedRebuiltCV(
        rebuild_sha256=rebuild.rebuild_sha256,
        cv_text=cv_text,
        cv_sha256=cv_sha256,
        constraint_receipt=constraint_receipt,
        receipt_sha256=content_hash(values),
    )


@dataclass(frozen=True)
class ApplicationApprovedEvidence:
    """One current approved candidate fact resolved by an external authority seam.

    The statement is retained in memory for exact comparison but omitted from the
    public plan document; only its digest and authority receipt cross that boundary.
    """

    evidence_id: str
    evidence_version: int
    claim_id: str
    claim_version: int
    approved_statement: str
    approved_statement_sha256: str
    authority_receipt_sha256: str
    status: str = "approved"

    def __post_init__(self) -> None:
        for value, label in (
            (self.evidence_id, "approved evidence ID"),
            (self.claim_id, "approved claim ID"),
            (self.approved_statement, "approved evidence statement"),
        ):
            _required(value, label)
        if (
            type(self.evidence_version) is not int
            or type(self.claim_version) is not int
            or self.evidence_version < 1
            or self.claim_version < 1
            or self.status != "approved"
        ):
            raise AdversarialRebuildError(
                "approved application evidence is malformed or not current"
            )
        _digest(self.approved_statement_sha256, "approved statement hash")
        _digest(self.authority_receipt_sha256, "approved evidence receipt hash")
        if (
            hashlib.sha256(self.approved_statement.encode()).hexdigest()
            != self.approved_statement_sha256
        ):
            raise AdversarialRebuildError(
                "approved evidence statement differs from its digest"
            )

    def document(self) -> dict[str, object]:
        return {
            "approved_statement_sha256": self.approved_statement_sha256,
            "authority_receipt_sha256": self.authority_receipt_sha256,
            "claim_id": self.claim_id,
            "claim_version": self.claim_version,
            "evidence_id": self.evidence_id,
            "evidence_version": self.evidence_version,
            "status": self.status,
        }


class ApplicationEvidenceAuthority(Protocol):
    """Read-only evidence seam; never a release or mutation authority."""

    authority_identity: str
    composition_sha256: str

    def resolve_current_approved_evidence(
        self, evidence_id: str, evidence_version: int
    ) -> ApplicationApprovedEvidence: ...

    def verify_current_approved_evidence(
        self, value: ApplicationApprovedEvidence
    ) -> None: ...


@dataclass(frozen=True)
class ApplicationImprovementApplication:
    """Exact changed source atoms attributed to one recruiter improvement."""

    rank: int
    supporting_sentence_ids: tuple[str, ...] = ()
    new_sentence_ids: tuple[str, ...] = ()
    removed_sentence_ids: tuple[str, ...] = ()
    new_style_slot_ids: tuple[str, ...] = ()
    removed_style_slot_ids: tuple[str, ...] = ()
    target_question_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.rank) is not int or self.rank < 1:
            raise AdversarialRebuildError("application improvement rank is invalid")
        if not any(
            (
                self.new_sentence_ids,
                self.removed_sentence_ids,
                self.new_style_slot_ids,
                self.removed_style_slot_ids,
            )
        ):
            raise AdversarialRebuildError(
                "application improvement identifies no changed atom"
            )
        for values, label in (
            (self.supporting_sentence_ids, "supporting sentence"),
            (self.new_sentence_ids, "new sentence"),
            (self.removed_sentence_ids, "removed sentence"),
            (self.new_style_slot_ids, "new style slot"),
            (self.removed_style_slot_ids, "removed style slot"),
        ):
            if tuple(sorted(set(values))) != values:
                raise AdversarialRebuildError(
                    f"application {label} identities must be sorted unique"
                )
            for value in values:
                _digest(value, f"application {label} identity")
        if self.target_question_id is not None:
            _required(self.target_question_id, "target form question ID")

    def document(self) -> dict[str, object]:
        return {
            "new_sentence_ids": list(self.new_sentence_ids),
            "new_style_slot_ids": list(self.new_style_slot_ids),
            "rank": self.rank,
            "removed_sentence_ids": list(self.removed_sentence_ids),
            "removed_style_slot_ids": list(self.removed_style_slot_ids),
            "supporting_sentence_ids": list(self.supporting_sentence_ids),
            "target_question_id": self.target_question_id,
        }


@dataclass(frozen=True)
class ApplicationEvidenceSafePlan:
    base_recruiter_receipt_sha256: str
    base_source_id: str
    proposed_source_id: str
    evidence_authority_identity: str
    evidence_composition_sha256: str
    accepted_improvement_ranks: tuple[int, ...]
    applications: tuple[ApplicationImprovementApplication, ...]
    approved_evidence: tuple[ApplicationApprovedEvidence, ...]
    roadmap: tuple[RebuildRoadmapItem, ...]
    plan_sha256: str
    release_authority: bool = False
    schema_version: str = APPLICATION_PLAN_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != APPLICATION_PLAN_SCHEMA:
            raise AdversarialRebuildError(
                "application rebuild plan schema is unsupported"
            )
        for value, label in (
            (self.base_recruiter_receipt_sha256, "base recruiter receipt hash"),
            (self.base_source_id, "base application source ID"),
            (self.proposed_source_id, "proposed application source ID"),
            (self.evidence_composition_sha256, "evidence composition hash"),
            (self.plan_sha256, "application rebuild plan hash"),
        ):
            _digest(value, label)
        _required(self.evidence_authority_identity, "evidence authority identity")
        if self.release_authority is not False:
            raise AdversarialRebuildError(
                "application rebuild plan cannot grant release authority"
            )
        if tuple(row.rank for row in self.applications) != (
            self.accepted_improvement_ranks
        ) or tuple(sorted(set(self.accepted_improvement_ranks))) != (
            self.accepted_improvement_ranks
        ):
            raise AdversarialRebuildError(
                "application rebuild dispositions are inconsistent"
            )
        if self.accepted_improvement_ranks and not self.approved_evidence:
            raise AdversarialRebuildError(
                "accepted application rebuild lacks approved evidence"
            )
        for row in self.applications:
            row.__post_init__()
        for row in self.approved_evidence:
            row.__post_init__()
        for row in self.roadmap:
            row.__post_init__()
        if self.plan_sha256 != content_hash(self.document(include_identity=False)):
            raise AdversarialRebuildError(
                "application rebuild plan identity is invalid"
            )

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "accepted_improvement_ranks": list(self.accepted_improvement_ranks),
            "applications": [row.document() for row in self.applications],
            "approved_evidence": [row.document() for row in self.approved_evidence],
            "base_recruiter_receipt_sha256": self.base_recruiter_receipt_sha256,
            "base_source_id": self.base_source_id,
            "evidence_authority_identity": self.evidence_authority_identity,
            "evidence_composition_sha256": self.evidence_composition_sha256,
            "proposed_source_id": self.proposed_source_id,
            "release_authority": False,
            "roadmap": [row.document() for row in self.roadmap],
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["plan_sha256"] = self.plan_sha256
        return value


@dataclass(frozen=True)
class ApplicationEvidenceSafeResult:
    plan: ApplicationEvidenceSafePlan
    source: ApplicationSource
    artifacts: ApplicationArtifacts
    sanity_package: SanityReviewPackage
    sanity_receipt: SanityReviewReceipt
    recruiter_package: RecruiterAssessmentPackage
    recruiter_receipt: RecruiterAssessmentReceipt
    invalidated_recruiter_receipt_sha256: str
    result_sha256: str
    release_authority: bool = False
    schema_version: str = APPLICATION_RESULT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != APPLICATION_RESULT_SCHEMA:
            raise AdversarialRebuildError(
                "application rebuild result schema is unsupported"
            )
        self.plan.__post_init__()
        verify_application_source(self.source)
        verify_application_artifacts(self.artifacts, self.source)
        verify_sanity_review_receipt(self.sanity_receipt, self.sanity_package)
        verify_recruiter_assessment_receipt(
            self.recruiter_receipt, self.recruiter_package
        )
        for value, label in (
            (
                self.invalidated_recruiter_receipt_sha256,
                "invalidated recruiter receipt hash",
            ),
            (self.result_sha256, "application rebuild result hash"),
        ):
            _digest(value, label)
        if self.release_authority is not False:
            raise AdversarialRebuildError(
                "application rebuild result cannot grant release authority"
            )
        if (
            self.source.source_id != self.plan.proposed_source_id
            or self.sanity_package.application_source_identity != self.source.source_id
            or self.sanity_package.cv_pdf_bytes != self.artifacts.cv_pdf.pdf_bytes
            or self.sanity_package.cover_letter_pdf_bytes
            != self.artifacts.cover_letter_pdf.pdf_bytes
            or self.recruiter_package.cv_pdf_bytes != self.artifacts.cv_pdf.pdf_bytes
            or self.recruiter_package.cover_letter_pdf_bytes
            != self.artifacts.cover_letter_pdf.pdf_bytes
            or self.recruiter_package.form_fields != self.sanity_package.form_fields
            or self.invalidated_recruiter_receipt_sha256
            != self.plan.base_recruiter_receipt_sha256
            or self.recruiter_receipt.receipt_sha256
            == self.invalidated_recruiter_receipt_sha256
        ):
            raise AdversarialRebuildError(
                "application rebuild result is not transitively bound"
            )
        if self.result_sha256 != content_hash(self.document(include_identity=False)):
            raise AdversarialRebuildError(
                "application rebuild result identity is invalid"
            )

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "artifact_set_sha256": self.artifacts.artifact_set_sha256,
            "invalidated_recruiter_receipt_sha256": (
                self.invalidated_recruiter_receipt_sha256
            ),
            "new_recruiter_receipt_sha256": self.recruiter_receipt.receipt_sha256,
            "new_sanity_receipt_sha256": self.sanity_receipt.receipt_sha256,
            "new_source_id": self.source.source_id,
            "plan_sha256": self.plan.plan_sha256,
            "release_authority": False,
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["result_sha256"] = self.result_sha256
        return value


def _application_improvements_by_rank(
    receipt: RecruiterAssessmentReceipt,
) -> dict[int, Mapping[str, object]]:
    raw = receipt.model_result.get("application_improvements")
    if not isinstance(raw, list):
        raise AdversarialRebuildError(
            "recruiter assessment lacks application improvements"
        )
    return {int(row["rank"]): row for row in raw if isinstance(row, Mapping)}


def _application_fact_coordinates(
    fact: FactualSentence,
) -> tuple[str, int, str, int]:
    authority = fact.authority
    if not isinstance(authority, (FactAuthority, ProfileFactAuthority)):
        raise AdversarialRebuildError(
            "application rebuild cannot promote a new employer fact"
        )
    return (
        authority.candidate_evidence_id,
        authority.candidate_evidence_version,
        authority.candidate_claim_id,
        authority.candidate_claim_version,
    )


def _stable_application_references(
    current: Sequence[str],
    proposed: Sequence[str],
    *,
    removed: set[str],
    added: set[str],
) -> bool:
    return tuple(value for value in current if value not in removed) == tuple(
        value for value in proposed if value not in added
    )


def _validate_application_structural_delta(
    current: ApplicationSource,
    proposed: ApplicationSource,
    *,
    new_fact_ids: set[str],
    removed_fact_ids: set[str],
    new_slot_ids: set[str],
    removed_slot_ids: set[str],
) -> None:
    if not _stable_application_references(
        tuple(row.sentence_id for row in current.facts),
        tuple(row.sentence_id for row in proposed.facts),
        removed=removed_fact_ids,
        added=new_fact_ids,
    ) or not _stable_application_references(
        tuple(row.slot_id for row in current.style_slots),
        tuple(row.slot_id for row in proposed.style_slots),
        removed=removed_slot_ids,
        added=new_slot_ids,
    ):
        raise AdversarialRebuildError(
            "application rebuild reordered unchanged source atoms"
        )

    for before_rows, after_rows, label in (
        (current.cv_sections, proposed.cv_sections, "CV"),
        (current.letter_sections, proposed.letter_sections, "cover-letter"),
    ):
        before = {row.heading: row for row in before_rows}
        after = {row.heading: row for row in after_rows}
        if len(before) != len(before_rows) or len(after) != len(after_rows):
            raise AdversarialRebuildError(
                f"application rebuild has duplicate {label} sections"
            )
        for heading in set(before) | set(after):
            left = before.get(heading)
            right = after.get(heading)
            if left is None:
                assert right is not None
                if not set(right.sentence_ids).issubset(new_fact_ids) or not set(
                    right.style_slot_ids
                ).issubset(new_slot_ids):
                    raise AdversarialRebuildError(
                        f"application rebuild smuggled retained atoms into a new {label} section"
                    )
                continue
            if right is None:
                if not set(left.sentence_ids).issubset(removed_fact_ids) or not set(
                    left.style_slot_ids
                ).issubset(removed_slot_ids):
                    raise AdversarialRebuildError(
                        f"application rebuild removed a {label} section with retained atoms"
                    )
                continue
            if not _stable_application_references(
                left.sentence_ids,
                right.sentence_ids,
                removed=removed_fact_ids,
                added=new_fact_ids,
            ) or not _stable_application_references(
                left.style_slot_ids,
                right.style_slot_ids,
                removed=removed_slot_ids,
                added=new_slot_ids,
            ):
                raise AdversarialRebuildError(
                    f"application rebuild reordered unchanged {label} content"
                )

    if tuple((row.question_id, row.question) for row in current.answers) != tuple(
        (row.question_id, row.question) for row in proposed.answers
    ):
        raise AdversarialRebuildError(
            "application rebuild changed live form question identity or order"
        )
    for left, right in zip(current.answers, proposed.answers, strict=True):
        if not _stable_application_references(
            left.sentence_ids,
            right.sentence_ids,
            removed=removed_fact_ids,
            added=new_fact_ids,
        ) or not _stable_application_references(
            left.style_slot_ids,
            right.style_slot_ids,
            removed=removed_slot_ids,
            added=new_slot_ids,
        ):
            raise AdversarialRebuildError(
                "application rebuild reordered unchanged form-answer content"
            )


def _application_atoms_match_target(
    source: ApplicationSource,
    target: str,
    target_question_id: str | None,
    *,
    sentence_ids: set[str],
    slot_ids: set[str],
) -> bool:
    facts = {row.sentence_id: row for row in source.facts}
    slots = {row.slot_id: row for row in source.style_slots}
    if not sentence_ids.issubset(facts) or not slot_ids.issubset(slots):
        return False
    if target in {"cv", "cover_letter"}:
        return (
            target_question_id is None
            and all(facts[value].document_kind == target for value in sentence_ids)
            and all(slots[value].document_kind == target for value in slot_ids)
        )
    if target != "form_answer" or target_question_id is None:
        return False
    answer = next(
        (row for row in source.answers if row.question_id == target_question_id),
        None,
    )
    return (
        answer is not None
        and sentence_ids.issubset(answer.sentence_ids)
        and slot_ids.issubset(answer.style_slot_ids)
    )


def _verify_application_recruiter_base(
    *,
    receipt: RecruiterAssessmentReceipt,
    package: RecruiterAssessmentPackage,
    source: ApplicationSource,
    questions: Mapping[str, tuple[str, str]],
) -> None:
    verify_application_source(source)
    verify_recruiter_assessment_receipt(receipt, package)
    artifacts = render_pdf_artifacts(source)
    expected_vacancy = IntendedVacancy(
        job_key=source.job_key,
        vacancy_sha256=source.vacancy_sha256,
        role_title=source.role_title,
        company_name=source.company_name,
    )
    expected_fields = canonical_form_fields(
        questions,
        cover_note=artifacts.editable.answers_text.strip(),
    )
    if (
        package.cv_pdf_bytes != artifacts.cv_pdf.pdf_bytes
        or package.cover_letter_pdf_bytes != artifacts.cover_letter_pdf.pdf_bytes
        or package.form_fields != expected_fields
        or package.intended_vacancy != expected_vacancy
    ):
        raise AdversarialRebuildError(
            "recruiter assessment does not bind the exact current application source"
        )


def _resolve_application_evidence(
    authority: ApplicationEvidenceAuthority,
    fact: FactualSentence,
) -> ApplicationApprovedEvidence:
    evidence_id, evidence_version, claim_id, claim_version = (
        _application_fact_coordinates(fact)
    )
    try:
        record = authority.resolve_current_approved_evidence(
            evidence_id, evidence_version
        )
    except (KeyError, LookupError) as exc:
        raise AdversarialRebuildError(
            "current approved application evidence is unavailable or revoked"
        ) from exc
    if type(record) is not ApplicationApprovedEvidence:
        raise AdversarialRebuildError(
            "application evidence authority returned the wrong record type"
        )
    record.__post_init__()
    if authority.verify_current_approved_evidence(record) is not None:
        raise AdversarialRebuildError(
            "application evidence verification returned ambiguous status"
        )
    if (
        record.evidence_id != evidence_id
        or record.evidence_version != evidence_version
        or record.claim_id != claim_id
        or record.claim_version != claim_version
        or record.approved_statement != fact.approved_source_text
    ):
        raise AdversarialRebuildError(
            "application source atom lacks exact current approved evidence"
        )
    return record


def _revalidate_application_evidence(
    *,
    authority: ApplicationEvidenceAuthority,
    expected_identity: str,
    expected_composition_sha256: str,
    records: Sequence[ApplicationApprovedEvidence],
) -> None:
    if (
        authority.authority_identity != expected_identity
        or authority.composition_sha256 != expected_composition_sha256
    ):
        raise AdversarialRebuildError(
            "application evidence authority changed during rebuild"
        )
    for expected in records:
        try:
            current = authority.resolve_current_approved_evidence(
                expected.evidence_id,
                expected.evidence_version,
            )
        except (KeyError, LookupError) as exc:
            raise AdversarialRebuildError(
                "current approved application evidence is unavailable or revoked"
            ) from exc
        if type(current) is not ApplicationApprovedEvidence:
            raise AdversarialRebuildError(
                "application evidence authority returned the wrong record type"
            )
        current.__post_init__()
        if authority.verify_current_approved_evidence(current) is not None:
            raise AdversarialRebuildError(
                "application evidence verification returned ambiguous status"
            )
        if current != expected:
            raise AdversarialRebuildError(
                "approved application evidence changed during rebuild"
            )


def plan_application_evidence_safe_rebuild(
    *,
    base_recruiter_receipt: RecruiterAssessmentReceipt,
    base_recruiter_package: RecruiterAssessmentPackage,
    current_source: ApplicationSource,
    proposed_source: ApplicationSource,
    applications: Sequence[ApplicationImprovementApplication],
    evidence_authority: ApplicationEvidenceAuthority,
    questions: Mapping[str, tuple[str, str]],
) -> ApplicationEvidenceSafePlan:
    """Map every outward delta to current evidence or a non-outward roadmap."""

    _verify_application_recruiter_base(
        receipt=base_recruiter_receipt,
        package=base_recruiter_package,
        source=current_source,
        questions=questions,
    )
    verify_application_source(proposed_source)
    _required(evidence_authority.authority_identity, "evidence authority identity")
    _digest(evidence_authority.composition_sha256, "evidence composition hash")
    for field in (
        "strategy_id",
        "job_key",
        "role_title",
        "company_name",
        "vacancy_source_identity",
        "vacancy_sha256",
        "contact",
    ):
        if getattr(current_source, field) != getattr(proposed_source, field):
            raise AdversarialRebuildError(
                "application rebuild cannot change vacancy, strategy or candidate identity"
            )

    improvements = _application_improvements_by_rank(base_recruiter_receipt)
    applied = tuple(sorted(tuple(applications), key=lambda row: row.rank))
    if len({row.rank for row in applied}) != len(applied):
        raise AdversarialRebuildError(
            "an application improvement rank cannot be applied twice"
        )
    current_facts = {row.sentence_id: row for row in current_source.facts}
    proposed_facts = {row.sentence_id: row for row in proposed_source.facts}
    current_slots = {row.slot_id: row for row in current_source.style_slots}
    proposed_slots = {row.slot_id: row for row in proposed_source.style_slots}
    new_fact_ids = {
        identity
        for identity, row in proposed_facts.items()
        if current_facts.get(identity) != row
    }
    removed_fact_ids = {
        identity
        for identity, row in current_facts.items()
        if proposed_facts.get(identity) != row
    }
    new_slot_ids = {
        identity
        for identity, row in proposed_slots.items()
        if current_slots.get(identity) != row
    }
    removed_slot_ids = {
        identity
        for identity, row in current_slots.items()
        if proposed_slots.get(identity) != row
    }
    mapped_facts: set[str] = set()
    mapped_removed_facts: set[str] = set()
    mapped_slots: set[str] = set()
    mapped_removed_slots: set[str] = set()
    evidence: dict[tuple[str, int], ApplicationApprovedEvidence] = {}

    for application in applied:
        improvement = improvements.get(application.rank)
        if improvement is None:
            raise AdversarialRebuildError(
                "application rebuild maps an unknown improvement"
            )
        target = str(improvement["target"])
        if target == "positioning":
            raise AdversarialRebuildError(
                "positioning critique must remain a roadmap item"
            )
        if (target == "form_answer") != (application.target_question_id is not None):
            raise AdversarialRebuildError(
                "form-answer improvement lacks one exact question identity"
            )
        supporting = set(application.supporting_sentence_ids)
        added_facts = set(application.new_sentence_ids)
        removed_facts = set(application.removed_sentence_ids)
        added_slots = set(application.new_style_slot_ids)
        removed_slots = set(application.removed_style_slot_ids)
        if (
            not supporting
            or not supporting.issubset(proposed_facts)
            or not added_facts.issubset(new_fact_ids)
            or not removed_facts.issubset(removed_fact_ids)
            or not added_slots.issubset(new_slot_ids)
            or not removed_slots.issubset(removed_slot_ids)
        ):
            raise AdversarialRebuildError(
                "application rebuild maps atoms outside the proposed delta"
            )
        if (
            mapped_facts & added_facts
            or mapped_removed_facts & removed_facts
            or mapped_slots & added_slots
            or mapped_removed_slots & removed_slots
        ):
            raise AdversarialRebuildError(
                "one application atom cannot satisfy two improvements"
            )
        support_required = improvement["support_required"]
        if support_required is True and not added_facts:
            raise AdversarialRebuildError(
                "evidence-requiring improvement lacks a new factual atom"
            )
        if support_required is False and added_facts:
            raise AdversarialRebuildError(
                "style-only improvement cannot introduce factual atoms"
            )
        if not _application_atoms_match_target(
            proposed_source,
            target,
            application.target_question_id,
            sentence_ids=supporting | added_facts,
            slot_ids=added_slots,
        ) or not _application_atoms_match_target(
            current_source,
            target,
            application.target_question_id,
            sentence_ids=removed_facts,
            slot_ids=removed_slots,
        ):
            raise AdversarialRebuildError(
                "application improvement atoms differ from their exact target"
            )
        for sentence_id in sorted(supporting | added_facts):
            record = _resolve_application_evidence(
                evidence_authority, proposed_facts[sentence_id]
            )
            evidence[(record.evidence_id, record.evidence_version)] = record
        mapped_facts.update(added_facts)
        mapped_removed_facts.update(removed_facts)
        mapped_slots.update(added_slots)
        mapped_removed_slots.update(removed_slots)

    if (
        mapped_facts != new_fact_ids
        or mapped_removed_facts != removed_fact_ids
        or mapped_slots != new_slot_ids
        or mapped_removed_slots != removed_slot_ids
    ):
        raise AdversarialRebuildError(
            "every outward application atom must map to one accepted improvement"
        )
    _validate_application_structural_delta(
        current_source,
        proposed_source,
        new_fact_ids=new_fact_ids,
        removed_fact_ids=removed_fact_ids,
        new_slot_ids=new_slot_ids,
        removed_slot_ids=removed_slot_ids,
    )
    if applied and proposed_source.source_id == current_source.source_id:
        raise AdversarialRebuildError(
            "accepted application rebuild requires a new source identity"
        )
    if not applied and proposed_source.source_id != current_source.source_id:
        raise AdversarialRebuildError(
            "roadmap-only critique cannot change outward application source"
        )

    accepted = tuple(row.rank for row in applied)
    roadmap: list[RebuildRoadmapItem] = []
    for rank, improvement in sorted(improvements.items()):
        if rank in set(accepted):
            continue
        roadmap.append(
            RebuildRoadmapItem(
                source="application_improvement",
                source_index=rank - 1,
                category=str(improvement["target"]),
                recommendation=str(improvement["recommendation"]),
                expected_effect=str(improvement["expected_effect"]),
                time_horizon=None,
                reason_code="no_current_approved_evidence_mapping",
            )
        )
    profile = base_recruiter_receipt.model_result.get("profile_improvements")
    if not isinstance(profile, list):
        raise AdversarialRebuildError("recruiter assessment lacks profile improvements")
    for index, improvement in enumerate(profile):
        if not isinstance(improvement, Mapping):
            raise AdversarialRebuildError("recruiter profile improvement is malformed")
        roadmap.append(
            RebuildRoadmapItem(
                source="profile_improvement",
                source_index=index,
                category=str(improvement["category"]),
                recommendation=str(improvement["recommendation"]),
                expected_effect=str(improvement["expected_effect"]),
                time_horizon=str(improvement["time_horizon"]),
                reason_code="requires_candidate_development",
            )
        )
    records = tuple(evidence[key] for key in sorted(evidence))
    _revalidate_application_evidence(
        authority=evidence_authority,
        expected_identity=evidence_authority.authority_identity,
        expected_composition_sha256=evidence_authority.composition_sha256,
        records=records,
    )
    values = {
        "accepted_improvement_ranks": list(accepted),
        "applications": [row.document() for row in applied],
        "approved_evidence": [row.document() for row in records],
        "base_recruiter_receipt_sha256": base_recruiter_receipt.receipt_sha256,
        "base_source_id": current_source.source_id,
        "evidence_authority_identity": evidence_authority.authority_identity,
        "evidence_composition_sha256": evidence_authority.composition_sha256,
        "proposed_source_id": proposed_source.source_id,
        "release_authority": False,
        "roadmap": [row.document() for row in roadmap],
        "schema_version": APPLICATION_PLAN_SCHEMA,
    }
    return ApplicationEvidenceSafePlan(
        base_recruiter_receipt_sha256=base_recruiter_receipt.receipt_sha256,
        base_source_id=current_source.source_id,
        proposed_source_id=proposed_source.source_id,
        evidence_authority_identity=evidence_authority.authority_identity,
        evidence_composition_sha256=evidence_authority.composition_sha256,
        accepted_improvement_ranks=accepted,
        applications=applied,
        approved_evidence=records,
        roadmap=tuple(roadmap),
        plan_sha256=content_hash(values),
    )


def execute_application_evidence_safe_rebuild(
    *,
    plan: ApplicationEvidenceSafePlan,
    base_recruiter_receipt: RecruiterAssessmentReceipt,
    base_recruiter_package: RecruiterAssessmentPackage,
    current_source: ApplicationSource,
    proposed_source: ApplicationSource,
    applications: Sequence[ApplicationImprovementApplication],
    evidence_authority: ApplicationEvidenceAuthority,
    questions: Mapping[str, tuple[str, str]],
    sanity_client: LLMClient,
    recruiter_client: LLMClient,
    vacancy_requirements: Sequence[str] | None = None,
    vacancy_review_material: VacancyReviewMaterial | None = None,
) -> ApplicationEvidenceSafeResult:
    """Rerender and independently rereview a fully revalidated source delta."""

    plan.__post_init__()
    revalidated = plan_application_evidence_safe_rebuild(
        base_recruiter_receipt=base_recruiter_receipt,
        base_recruiter_package=base_recruiter_package,
        current_source=current_source,
        proposed_source=proposed_source,
        applications=applications,
        evidence_authority=evidence_authority,
        questions=questions,
    )
    if revalidated != plan:
        raise AdversarialRebuildError(
            "application rebuild plan differs from current evidence"
        )
    if not plan.accepted_improvement_ranks:
        raise AdversarialRebuildError(
            "roadmap-only critique cannot trigger an outward application rebuild"
        )
    artifacts = render_pdf_artifacts(proposed_source)
    sanity_package = package_from_application(
        source=proposed_source,
        artifacts=artifacts,
        questions=questions,
        vacancy_requirements=vacancy_requirements,
        vacancy_review_material=vacancy_review_material,
    )
    sanity_receipt = review_application_package(
        sanity_package,
        client=sanity_client,
    )
    recruiter_package = RecruiterAssessmentPackage(
        listing_text=base_recruiter_package.listing_text,
        listing_text_sha256=base_recruiter_package.listing_text_sha256,
        cv_pdf_bytes=artifacts.cv_pdf.pdf_bytes,
        cover_letter_pdf_bytes=artifacts.cover_letter_pdf.pdf_bytes,
        form_fields=sanity_package.form_fields,
        intended_vacancy=sanity_package.intended_vacancy,
    )
    recruiter_receipt = assess_application_as_recruiter(
        recruiter_package,
        client=recruiter_client,
    )
    _revalidate_application_evidence(
        authority=evidence_authority,
        expected_identity=plan.evidence_authority_identity,
        expected_composition_sha256=plan.evidence_composition_sha256,
        records=plan.approved_evidence,
    )
    values = {
        "artifact_set_sha256": artifacts.artifact_set_sha256,
        "invalidated_recruiter_receipt_sha256": (plan.base_recruiter_receipt_sha256),
        "new_recruiter_receipt_sha256": recruiter_receipt.receipt_sha256,
        "new_sanity_receipt_sha256": sanity_receipt.receipt_sha256,
        "new_source_id": proposed_source.source_id,
        "plan_sha256": plan.plan_sha256,
        "release_authority": False,
        "schema_version": APPLICATION_RESULT_SCHEMA,
    }
    return ApplicationEvidenceSafeResult(
        plan=plan,
        source=proposed_source,
        artifacts=artifacts,
        sanity_package=sanity_package,
        sanity_receipt=sanity_receipt,
        recruiter_package=recruiter_package,
        recruiter_receipt=recruiter_receipt,
        invalidated_recruiter_receipt_sha256=(plan.base_recruiter_receipt_sha256),
        result_sha256=content_hash(values),
    )


__all__ = [
    "AdversarialRebuildError",
    "ApplicationApprovedEvidence",
    "ApplicationEvidenceAuthority",
    "ApplicationEvidenceSafePlan",
    "ApplicationEvidenceSafeResult",
    "ApplicationImprovementApplication",
    "AppliedRecruiterImprovement",
    "CoverLetterEvidenceSafeRebuildResult",
    "CoverLetterRecruiterImprovementBinding",
    "EvidenceSafeRebuildResult",
    "FinalizedRebuiltCV",
    "RebuildRoadmapItem",
    "RecruiterImprovementBinding",
    "bind_cover_letter_recruiter_improvement",
    "bind_recruiter_improvement",
    "finalize_rebuilt_cv",
    "execute_application_evidence_safe_rebuild",
    "plan_application_evidence_safe_rebuild",
    "rebuild_cover_letter_from_recruiter_assessment",
    "rebuild_from_recruiter_assessment",
    "render_editorial_cv_text",
]
