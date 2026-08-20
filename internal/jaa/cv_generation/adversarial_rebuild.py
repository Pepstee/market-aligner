"""Evidence-safe admission of detached recruiter improvements.

The detached recruiter is diagnostic only.  This module never treats its
recommendations as candidate facts or mutation authority.  A recommendation
can change a CV draft only through an exact binding to claims already present
in the candidate-authority-backed editorial request.  Everything else becomes
a roadmap item.

This is the useful seam recovered from the quarantined adversarial rebuild.  It
does not load providers, deployment metadata, forms, browsers or submission
machinery.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from career_automation.adversarial_recruiter import (
    RecruiterAssessmentPackage,
    RecruiterAssessmentReceipt,
    verify_recruiter_assessment_receipt,
)
from career_automation.evidence_matching import content_hash

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
    build_editorial_draft,
    validate_editorial_draft,
)


BINDING_SCHEMA = "jaa.cv-recruiter-improvement-binding.v1"
REBUILD_SCHEMA = "jaa.cv-evidence-safe-rebuild.v1"
FINALIZED_SCHEMA = "jaa.cv-finalized-rebuild.v1"
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
        raise AdversarialRebuildError("recruiter application improvements are malformed")
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
        (index for index, section in enumerate(draft.sections) if section.heading == heading),
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
        raise AdversarialRebuildError("bound claim already belongs to another CV section")

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
        EditorialAtom(source_kind="approved_claim", text=claim.text, claim_id=claim.claim_id)
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
        hashlib.sha256(_recruiter_extracted_cv_text(admitted_draft).encode()).hexdigest()
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
            raise AdversarialRebuildError("improvement binding targets different authority")
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
                raise AdversarialRebuildError("binding cites an unapproved candidate claim")
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

    return "\n".join(
        line for line in render_editorial_cv_text(draft).splitlines() if line.strip()
    ) + "\n"


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
        raise AdversarialRebuildError("final CV policy differs from candidate authority")
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


__all__ = [
    "AdversarialRebuildError",
    "AppliedRecruiterImprovement",
    "EvidenceSafeRebuildResult",
    "FinalizedRebuiltCV",
    "RebuildRoadmapItem",
    "RecruiterImprovementBinding",
    "bind_recruiter_improvement",
    "finalize_rebuilt_cv",
    "rebuild_from_recruiter_assessment",
    "render_editorial_cv_text",
]
