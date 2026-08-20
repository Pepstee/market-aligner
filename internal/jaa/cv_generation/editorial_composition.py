"""Evidence-bound CV editorial composition and Humanizer admission.

This module is a deliberately small recovery of the useful contract from the
quarantined ``editorial_composition`` work.  It does not discover providers or
execute models.  Callers supply a writer draft, a Humanizer draft and exact
stage evidence; this boundary admits them only when every factual span is an
unchanged approved claim and every free connective is demonstrably non-factual.

The separate :mod:`cv_generation.constraints` gate still validates the final
rendered document.  This module owns the earlier editorial boundary and its
non-authoritative receipts.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from career_automation.evidence_matching import content_hash


REQUEST_SCHEMA = "jaa.cv-editorial-request.v1"
DRAFT_SCHEMA = "jaa.cv-editorial-draft.v1"
STAGE_RECEIPT_SCHEMA = "jaa.cv-editorial-stage-receipt.v1"
COMPOSITION_RECEIPT_SCHEMA = "jaa.cv-editorial-composition-receipt.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MONTH_YEAR = re.compile(
    r"^(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December) 20\d{2}$"
)
_DAY_MONTH_YEAR = re.compile(
    r"\b(?:[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?\s+"
    r"(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+20\d{2}\b",
    re.IGNORECASE,
)
_FACTUAL_CONNECTIVE = re.compile(
    r"(?:\b\d[\d,./:%+-]*\b|[%£$€]|https?://|[^@\s]+@[^@\s]+|"
    r"\b(?:I|we)\s+(?:am|are|have|had|hold|built|created|delivered|designed|"
    r"developed|implemented|led|managed|provided|shipped|tested|validated|"
    r"worked|studied|graduated)\b|"
    r"\b(?:expert|expertise|proficient|qualified|track record|years? of)\b)",
    re.IGNORECASE,
)
_FORMAT_OR_DATASTORE = re.compile(
    r"\b(?:jsonl?|ya?ml|xml|csv|sqlite|sql)\b", re.IGNORECASE
)
_WORK_RIGHTS = (
    "right to work",
    "work rights",
    "work authorisation",
    "work authorization",
    "visa status",
    "visa sponsorship",
    "sponsorship required",
    "sponsorship not required",
    "settled status",
    "pre-settled status",
)
_CONNECTIVE_AI_PATTERNS = (
    "i am writing to express",
    "i am applying",
    "pivotal",
    "showcase",
    "tapestry",
    "vibrant",
    "here is",
    "—",
    "–",
    " -- ",
)
_ALLOWED_HEADINGS = (
    "Professional Summary",
    "Core Capabilities",
    "Projects",
    "Experience",
    "Education",
    "Certifications",
)
_CATEGORY_BY_HEADING = {
    "Professional Summary": frozenset({"summary", "project", "experience", "credential"}),
    "Core Capabilities": frozenset({"capability_domain"}),
    "Projects": frozenset({"project"}),
    "Experience": frozenset({"experience"}),
    "Education": frozenset({"education", "credential"}),
    "Certifications": frozenset({"credential"}),
}


class EditorialCompositionError(ValueError):
    """An editorial draft is not admissible against candidate authority."""


def _required(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise EditorialCompositionError(f"{label} is absent or malformed")
    return value


def _digest(value: object, label: str) -> str:
    text = _required(value, label)
    if not _SHA256.fullmatch(text):
        raise EditorialCompositionError(f"{label} is not a lowercase SHA-256 digest")
    return text


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CandidateEditorialAuthority:
    candidate_name: str
    candidate_city: str
    graduation_month_year: str | None
    dissertation_title: str | None
    source_sha256: str
    require_dissertation: bool = False

    def __post_init__(self) -> None:
        _required(self.candidate_name, "candidate name")
        _required(self.candidate_city, "candidate city")
        _digest(self.source_sha256, "candidate authority source hash")
        if self.graduation_month_year is not None and not _MONTH_YEAR.fullmatch(
            self.graduation_month_year
        ):
            raise EditorialCompositionError("graduation authority must use month and year")
        if self.dissertation_title is not None:
            _required(self.dissertation_title, "dissertation authority title")
        if type(self.require_dissertation) is not bool:
            raise EditorialCompositionError("dissertation requirement must be boolean")
        if self.require_dissertation and self.dissertation_title is None:
            raise EditorialCompositionError(
                "required dissertation title is absent from candidate authority"
            )

    def document(self) -> dict[str, object]:
        return {
            "candidate_city": self.candidate_city,
            "candidate_name": self.candidate_name,
            "dissertation_title": self.dissertation_title,
            "graduation_month_year": self.graduation_month_year,
            "require_dissertation": self.require_dissertation,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class ApprovedCVClaim:
    claim_id: str
    text: str
    text_sha256: str
    evidence_ids: tuple[str, ...]
    category: str

    def __post_init__(self) -> None:
        _required(self.claim_id, "approved claim ID")
        text = _required(self.text, "approved claim text")
        _digest(self.text_sha256, "approved claim text hash")
        if _text_sha256(text) != self.text_sha256:
            raise EditorialCompositionError("approved claim differs from its retained hash")
        if not self.evidence_ids or any(
            not isinstance(value, str) or not value.strip() for value in self.evidence_ids
        ):
            raise EditorialCompositionError("approved claim lacks evidence identities")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise EditorialCompositionError("approved claim repeats evidence identities")
        if self.category not in {
            "summary",
            "capability_domain",
            "project",
            "experience",
            "education",
            "credential",
        }:
            raise EditorialCompositionError("approved claim category is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "category": self.category,
            "claim_id": self.claim_id,
            "evidence_ids": list(self.evidence_ids),
            "text": self.text,
            "text_sha256": self.text_sha256,
        }


@dataclass(frozen=True)
class CVEditorialRequest:
    authority: CandidateEditorialAuthority
    role_title: str
    company_name: str
    vacancy_sha256: str
    approved_claims: tuple[ApprovedCVClaim, ...]
    request_sha256: str
    schema_version: str = REQUEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != REQUEST_SCHEMA:
            raise EditorialCompositionError("editorial request schema is unsupported")
        self.authority.__post_init__()
        _required(self.role_title, "target role title")
        _required(self.company_name, "target company name")
        _digest(self.vacancy_sha256, "vacancy hash")
        if not self.approved_claims:
            raise EditorialCompositionError("editorial request has no approved claims")
        claim_ids = tuple(claim.claim_id for claim in self.approved_claims)
        if len(set(claim_ids)) != len(claim_ids):
            raise EditorialCompositionError("editorial request repeats claim identities")
        for claim in self.approved_claims:
            claim.__post_init__()
        _digest(self.request_sha256, "editorial request hash")
        if self.request_sha256 != content_hash(self.document(include_identity=False)):
            raise EditorialCompositionError("editorial request identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "approved_claims": [claim.document() for claim in self.approved_claims],
            "authority": self.authority.document(),
            "company_name": self.company_name,
            "role_title": self.role_title,
            "schema_version": self.schema_version,
            "vacancy_sha256": self.vacancy_sha256,
        }
        if include_identity:
            value["request_sha256"] = self.request_sha256
        return value


def build_editorial_request(
    *,
    authority: CandidateEditorialAuthority,
    role_title: str,
    company_name: str,
    vacancy_sha256: str,
    approved_claims: Sequence[ApprovedCVClaim],
) -> CVEditorialRequest:
    values = {
        "approved_claims": [claim.document() for claim in approved_claims],
        "authority": authority.document(),
        "company_name": company_name,
        "role_title": role_title,
        "schema_version": REQUEST_SCHEMA,
        "vacancy_sha256": vacancy_sha256,
    }
    return CVEditorialRequest(
        authority=authority,
        role_title=role_title,
        company_name=company_name,
        vacancy_sha256=vacancy_sha256,
        approved_claims=tuple(approved_claims),
        request_sha256=content_hash(values),
    )


@dataclass(frozen=True)
class EditorialAtom:
    source_kind: str
    text: str
    claim_id: str | None = None

    def __post_init__(self) -> None:
        if self.source_kind not in {"approved_claim", "connective"}:
            raise EditorialCompositionError("editorial atom source kind is unsupported")
        _required(self.text, "editorial atom text")
        if "\n" in self.text or "\r" in self.text:
            raise EditorialCompositionError("editorial atoms must be single-line spans")
        if self.source_kind == "approved_claim":
            _required(self.claim_id, "editorial atom claim ID")
        elif self.claim_id is not None:
            raise EditorialCompositionError("connectives cannot claim evidence")

    def document(self) -> dict[str, object]:
        return {
            "claim_id": self.claim_id,
            "source_kind": self.source_kind,
            "text": self.text,
        }


@dataclass(frozen=True)
class CVSection:
    heading: str
    atoms: tuple[EditorialAtom, ...]

    def __post_init__(self) -> None:
        if self.heading not in _ALLOWED_HEADINGS:
            raise EditorialCompositionError("CV section heading is unsupported")
        if not self.atoms:
            raise EditorialCompositionError("CV section cannot be empty")
        for atom in self.atoms:
            atom.__post_init__()

    def document(self) -> dict[str, object]:
        return {
            "atoms": [atom.document() for atom in self.atoms],
            "heading": self.heading,
        }


@dataclass(frozen=True)
class CVEditorialDraft:
    candidate_name: str
    candidate_city: str
    sections: tuple[CVSection, ...]
    draft_sha256: str
    schema_version: str = DRAFT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != DRAFT_SCHEMA:
            raise EditorialCompositionError("editorial draft schema is unsupported")
        _required(self.candidate_name, "draft candidate name")
        _required(self.candidate_city, "draft candidate city")
        if not self.sections:
            raise EditorialCompositionError("editorial draft has no sections")
        for section in self.sections:
            section.__post_init__()
        headings = tuple(section.heading for section in self.sections)
        if headings[0] != "Professional Summary":
            raise EditorialCompositionError("Professional Summary must be first")
        if "Core Capabilities" not in headings:
            raise EditorialCompositionError("Core Capabilities section is required")
        if len(set(headings)) != len(headings):
            raise EditorialCompositionError("editorial draft repeats a section")
        _digest(self.draft_sha256, "editorial draft hash")
        if self.draft_sha256 != content_hash(self.document(include_identity=False)):
            raise EditorialCompositionError("editorial draft identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "candidate_city": self.candidate_city,
            "candidate_name": self.candidate_name,
            "schema_version": self.schema_version,
            "sections": [section.document() for section in self.sections],
        }
        if include_identity:
            value["draft_sha256"] = self.draft_sha256
        return value


def build_editorial_draft(
    *,
    candidate_name: str,
    candidate_city: str,
    sections: Sequence[CVSection],
) -> CVEditorialDraft:
    values = {
        "candidate_city": candidate_city,
        "candidate_name": candidate_name,
        "schema_version": DRAFT_SCHEMA,
        "sections": [section.document() for section in sections],
    }
    return CVEditorialDraft(
        candidate_name=candidate_name,
        candidate_city=candidate_city,
        sections=tuple(sections),
        draft_sha256=content_hash(values),
    )


def _validate_connective(text: str) -> None:
    folded = text.casefold()
    if len(text.split()) > 30:
        raise EditorialCompositionError("editorial connective is too long")
    if _FACTUAL_CONNECTIVE.search(text):
        raise EditorialCompositionError("editorial connective introduced a factual claim")
    if any(pattern in folded for pattern in _CONNECTIVE_AI_PATTERNS):
        raise EditorialCompositionError("editorial connective violates Humanizer policy")


def _outward_text(draft: CVEditorialDraft) -> str:
    return "\n".join(
        (draft.candidate_name, draft.candidate_city)
        + tuple(
            value
            for section in draft.sections
            for value in (section.heading, *(atom.text for atom in section.atoms))
        )
    )


def validate_editorial_draft(
    request: CVEditorialRequest,
    draft: CVEditorialDraft,
) -> None:
    """Reject invented, altered or candidate-prohibited editorial content."""

    request.__post_init__()
    draft.__post_init__()
    authority = request.authority
    if draft.candidate_name != authority.candidate_name:
        raise EditorialCompositionError("draft candidate differs from authority")
    if draft.candidate_city != authority.candidate_city:
        raise EditorialCompositionError("draft location differs from authority")

    approved: Mapping[str, ApprovedCVClaim] = {
        claim.claim_id: claim for claim in request.approved_claims
    }
    used_claims: list[str] = []
    for section in draft.sections:
        section_claim_count = 0
        for atom in section.atoms:
            if atom.source_kind == "connective":
                _validate_connective(atom.text)
                continue
            claim = approved.get(atom.claim_id or "")
            if claim is None:
                raise EditorialCompositionError("editorial draft cites an unknown claim")
            if atom.text != claim.text:
                raise EditorialCompositionError("editorial draft changed an approved claim")
            if claim.category not in _CATEGORY_BY_HEADING[section.heading]:
                raise EditorialCompositionError("approved claim is in the wrong CV section")
            if section.heading == "Core Capabilities" and _FORMAT_OR_DATASTORE.search(
                atom.text
            ):
                raise EditorialCompositionError(
                    "formats and datastores cannot masquerade as capability domains"
                )
            used_claims.append(claim.claim_id)
            section_claim_count += 1
        if section_claim_count == 0:
            raise EditorialCompositionError("CV sections require approved factual claims")
    if len(set(used_claims)) != len(used_claims):
        raise EditorialCompositionError("editorial draft repeats an approved claim")

    outward = _outward_text(draft)
    folded = outward.casefold()
    if "curriculum vitae" in folded or re.search(r"(?mi)^\s*cv\s*$", outward):
        raise EditorialCompositionError("CV document labels are forbidden")
    if any(value in folded for value in _WORK_RIGHTS):
        raise EditorialCompositionError("work-rights declarations are forbidden in CVs")

    education = "\n".join(
        atom.text
        for section in draft.sections
        if section.heading == "Education"
        for atom in section.atoms
    )
    if _DAY_MONTH_YEAR.search(education):
        raise EditorialCompositionError("graduation dates must use month and year only")
    if authority.graduation_month_year is not None and (
        authority.graduation_month_year not in education
    ):
        raise EditorialCompositionError("authoritative graduation month and year are absent")
    dissertation_mentioned = "dissertation" in education.casefold()
    if dissertation_mentioned and authority.dissertation_title is None:
        raise EditorialCompositionError("dissertation title lacks candidate authority")
    if authority.require_dissertation and (
        authority.dissertation_title not in education
    ):
        raise EditorialCompositionError("authoritative dissertation title is absent")
    if dissertation_mentioned and authority.dissertation_title not in education:
        raise EditorialCompositionError("dissertation title differs from candidate authority")


def _validate_humanizer_change(
    writer_draft: CVEditorialDraft,
    final_draft: CVEditorialDraft,
) -> None:
    if (
        writer_draft.candidate_name != final_draft.candidate_name
        or writer_draft.candidate_city != final_draft.candidate_city
        or len(writer_draft.sections) != len(final_draft.sections)
    ):
        raise EditorialCompositionError("Humanizer changed CV structure")
    for writer_section, final_section in zip(
        writer_draft.sections, final_draft.sections, strict=True
    ):
        if (
            writer_section.heading != final_section.heading
            or len(writer_section.atoms) != len(final_section.atoms)
        ):
            raise EditorialCompositionError("Humanizer changed CV structure")
        for writer_atom, final_atom in zip(
            writer_section.atoms, final_section.atoms, strict=True
        ):
            if writer_atom.source_kind != final_atom.source_kind:
                raise EditorialCompositionError("Humanizer changed evidence structure")
            if writer_atom.source_kind == "approved_claim" and writer_atom != final_atom:
                raise EditorialCompositionError("Humanizer changed an approved factual span")
            if writer_atom.source_kind == "connective" and final_atom.claim_id is not None:
                raise EditorialCompositionError("Humanizer connective claimed evidence")


@dataclass(frozen=True)
class EditorialStageEvidence:
    stage: str
    environment: str
    provider: str
    model: str
    invocation_id: str
    request_sha256: str
    response_sha256: str

    def __post_init__(self) -> None:
        if self.stage not in {"resume_writer", "humanizer"}:
            raise EditorialCompositionError("editorial stage is unsupported")
        if self.environment not in {"production", "synthetic"}:
            raise EditorialCompositionError("editorial stage environment is unsupported")
        _required(self.provider, "editorial stage provider")
        _required(self.model, "editorial stage model")
        _required(self.invocation_id, "editorial invocation ID")
        _digest(self.request_sha256, "editorial stage request hash")
        _digest(self.response_sha256, "editorial stage response hash")


@dataclass(frozen=True)
class EditorialStageReceipt:
    stage: str
    environment: str
    provider: str
    model: str
    invocation_id_sha256: str
    request_sha256: str
    response_sha256: str
    receipt_sha256: str
    release_authority: bool = False
    schema_version: str = STAGE_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != STAGE_RECEIPT_SCHEMA:
            raise EditorialCompositionError("editorial stage receipt schema is unsupported")
        if self.stage not in {"resume_writer", "humanizer"}:
            raise EditorialCompositionError("editorial stage receipt is unsupported")
        if self.environment not in {"production", "synthetic"}:
            raise EditorialCompositionError("editorial receipt environment is unsupported")
        _required(self.provider, "editorial receipt provider")
        _required(self.model, "editorial receipt model")
        for value, label in (
            (self.invocation_id_sha256, "editorial receipt invocation hash"),
            (self.request_sha256, "editorial receipt request hash"),
            (self.response_sha256, "editorial receipt response hash"),
            (self.receipt_sha256, "editorial receipt hash"),
        ):
            _digest(value, label)
        if self.release_authority is not False:
            raise EditorialCompositionError("editorial receipts cannot grant release authority")
        if self.receipt_sha256 != content_hash(self.document(include_identity=False)):
            raise EditorialCompositionError("editorial stage receipt identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "environment": self.environment,
            "invocation_id_sha256": self.invocation_id_sha256,
            "model": self.model,
            "provider": self.provider,
            "release_authority": False,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "schema_version": self.schema_version,
            "stage": self.stage,
        }
        if include_identity:
            value["receipt_sha256"] = self.receipt_sha256
        return value


@dataclass(frozen=True)
class EditorialCompositionReceipt:
    request_sha256: str
    writer_draft_sha256: str
    final_draft_sha256: str
    writer_receipt_sha256: str
    humanizer_receipt_sha256: str
    receipt_sha256: str
    release_authority: bool = False
    schema_version: str = COMPOSITION_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != COMPOSITION_RECEIPT_SCHEMA:
            raise EditorialCompositionError(
                "editorial composition receipt schema is unsupported"
            )
        for value, label in (
            (self.request_sha256, "composition request hash"),
            (self.writer_draft_sha256, "composition writer-draft hash"),
            (self.final_draft_sha256, "composition final-draft hash"),
            (self.writer_receipt_sha256, "composition writer-receipt hash"),
            (self.humanizer_receipt_sha256, "composition Humanizer-receipt hash"),
            (self.receipt_sha256, "composition receipt hash"),
        ):
            _digest(value, label)
        if self.release_authority is not False:
            raise EditorialCompositionError(
                "composition receipts cannot grant release authority"
            )
        if self.receipt_sha256 != content_hash(self.document(include_identity=False)):
            raise EditorialCompositionError("editorial composition receipt identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "final_draft_sha256": self.final_draft_sha256,
            "humanizer_receipt_sha256": self.humanizer_receipt_sha256,
            "release_authority": False,
            "request_sha256": self.request_sha256,
            "schema_version": self.schema_version,
            "writer_draft_sha256": self.writer_draft_sha256,
            "writer_receipt_sha256": self.writer_receipt_sha256,
        }
        if include_identity:
            value["receipt_sha256"] = self.receipt_sha256
        return value


def _stage_receipt(evidence: EditorialStageEvidence) -> EditorialStageReceipt:
    values = {
        "environment": evidence.environment,
        "invocation_id_sha256": _text_sha256(evidence.invocation_id),
        "model": evidence.model,
        "provider": evidence.provider,
        "release_authority": False,
        "request_sha256": evidence.request_sha256,
        "response_sha256": evidence.response_sha256,
        "schema_version": STAGE_RECEIPT_SCHEMA,
        "stage": evidence.stage,
    }
    return EditorialStageReceipt(**values, receipt_sha256=content_hash(values))


def humanizer_request_sha256(
    request: CVEditorialRequest,
    writer_draft: CVEditorialDraft,
) -> str:
    return content_hash(
        {
            "request_sha256": request.request_sha256,
            "schema_version": "jaa.cv-humanizer-request.v1",
            "writer_draft_sha256": writer_draft.draft_sha256,
        }
    )


def admit_editorial_composition(
    *,
    request: CVEditorialRequest,
    writer_draft: CVEditorialDraft,
    final_draft: CVEditorialDraft,
    writer_evidence: EditorialStageEvidence,
    humanizer_evidence: EditorialStageEvidence,
) -> tuple[EditorialStageReceipt, EditorialStageReceipt, EditorialCompositionReceipt]:
    """Admit writer and Humanizer outputs without granting publication authority."""

    validate_editorial_draft(request, writer_draft)
    validate_editorial_draft(request, final_draft)
    _validate_humanizer_change(writer_draft, final_draft)
    writer_evidence.__post_init__()
    humanizer_evidence.__post_init__()
    if writer_evidence.stage != "resume_writer" or humanizer_evidence.stage != "humanizer":
        raise EditorialCompositionError("editorial stages are out of order")
    if writer_evidence.environment != humanizer_evidence.environment:
        raise EditorialCompositionError("editorial stages used different environments")
    if writer_evidence.invocation_id == humanizer_evidence.invocation_id:
        raise EditorialCompositionError("writer and Humanizer require distinct sessions")
    if (
        writer_evidence.request_sha256 != request.request_sha256
        or writer_evidence.response_sha256 != writer_draft.draft_sha256
        or humanizer_evidence.request_sha256
        != humanizer_request_sha256(request, writer_draft)
        or humanizer_evidence.response_sha256 != final_draft.draft_sha256
    ):
        raise EditorialCompositionError("editorial stage evidence is not bound to its input")

    writer_receipt = _stage_receipt(writer_evidence)
    humanizer_receipt = _stage_receipt(humanizer_evidence)
    values = {
        "final_draft_sha256": final_draft.draft_sha256,
        "humanizer_receipt_sha256": humanizer_receipt.receipt_sha256,
        "release_authority": False,
        "request_sha256": request.request_sha256,
        "schema_version": COMPOSITION_RECEIPT_SCHEMA,
        "writer_draft_sha256": writer_draft.draft_sha256,
        "writer_receipt_sha256": writer_receipt.receipt_sha256,
    }
    composition_receipt = EditorialCompositionReceipt(
        **values,
        receipt_sha256=content_hash(values),
    )
    return writer_receipt, humanizer_receipt, composition_receipt


__all__ = [
    "ApprovedCVClaim",
    "CVEditorialDraft",
    "CVEditorialRequest",
    "CVSection",
    "CandidateEditorialAuthority",
    "EditorialAtom",
    "EditorialCompositionError",
    "EditorialCompositionReceipt",
    "EditorialStageEvidence",
    "EditorialStageReceipt",
    "admit_editorial_composition",
    "build_editorial_draft",
    "build_editorial_request",
    "humanizer_request_sha256",
    "validate_editorial_draft",
]
