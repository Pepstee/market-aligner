"""Evidence-bound CV editorial composition and Humanizer admission.

This module is a deliberately small recovery of the useful contract from the
quarantined ``editorial_composition`` work.  It does not discover providers.
Callers may supply drafts and exact stage evidence to the admission boundary,
or run explicitly configured writer and Humanizer adapters through fresh,
one-shot sessions.  Both paths admit output only when every factual span is an
unchanged approved claim and every free connective is demonstrably non-factual.

The separate :mod:`cv_generation.constraints` gate still validates the final
rendered document.  This module owns the earlier editorial boundary and its
non-authoritative receipts.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from career_automation.evidence_matching import canonical_json, content_hash


REQUEST_SCHEMA = "jaa.cv-editorial-request.v1"
DRAFT_SCHEMA = "jaa.cv-editorial-draft.v1"
STAGE_RECEIPT_SCHEMA = "jaa.cv-editorial-stage-receipt.v2"
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
    transport_identity: str | None = None
    request_bytes_sha256: str | None = None
    response_bytes_sha256: str | None = None

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
        if (self.request_bytes_sha256 is None) != (
            self.response_bytes_sha256 is None
        ):
            raise EditorialCompositionError(
                "editorial transport byte evidence is incomplete"
            )
        if self.request_bytes_sha256 is not None:
            _required(self.transport_identity, "editorial transport identity")
            _digest(self.request_bytes_sha256, "editorial request-bytes hash")
            _digest(self.response_bytes_sha256, "editorial response-bytes hash")
        elif self.transport_identity is not None:
            raise EditorialCompositionError(
                "editorial transport identity lacks exact byte evidence"
            )


@dataclass(frozen=True)
class EditorialStageReceipt:
    stage: str
    environment: str
    provider: str
    model: str
    invocation_id_sha256: str
    request_sha256: str
    response_sha256: str
    transport_identity: str | None
    request_bytes_sha256: str | None
    response_bytes_sha256: str | None
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
        if (self.request_bytes_sha256 is None) != (
            self.response_bytes_sha256 is None
        ):
            raise EditorialCompositionError("editorial receipt byte evidence is incomplete")
        if self.request_bytes_sha256 is not None:
            _required(self.transport_identity, "editorial receipt transport identity")
            _digest(self.request_bytes_sha256, "editorial receipt request-bytes hash")
            _digest(self.response_bytes_sha256, "editorial receipt response-bytes hash")
        elif self.transport_identity is not None:
            raise EditorialCompositionError("editorial receipt transport lacks byte evidence")
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
            "request_bytes_sha256": self.request_bytes_sha256,
            "response_bytes_sha256": self.response_bytes_sha256,
            "schema_version": self.schema_version,
            "stage": self.stage,
            "transport_identity": self.transport_identity,
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
        "request_bytes_sha256": evidence.request_bytes_sha256,
        "response_bytes_sha256": evidence.response_bytes_sha256,
        "schema_version": STAGE_RECEIPT_SCHEMA,
        "stage": evidence.stage,
        "transport_identity": evidence.transport_identity,
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


@dataclass(frozen=True)
class EditorialBackendResult:
    """Exact output and observed identity from one isolated editorial call."""

    response_bytes: bytes
    invocation_id: str
    environment: str
    provider: str
    model: str
    transport_identity: str
    request_sha256: str
    response_sha256: str
    call_count: int = 1
    history_access: bool = False
    cache_access: bool = False
    tool_access: bool = False
    retrieval_access: bool = False
    filesystem_access: bool = False
    environment_access: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.response_bytes, bytes) or not self.response_bytes:
            raise EditorialCompositionError("editorial backend returned no exact bytes")
        for value, label in (
            (self.invocation_id, "editorial invocation ID"),
            (self.provider, "editorial provider"),
            (self.model, "editorial model"),
            (self.transport_identity, "editorial transport identity"),
        ):
            _required(value, label)
        if self.environment not in {"production", "synthetic"}:
            raise EditorialCompositionError("editorial backend environment is invalid")
        _digest(self.request_sha256, "editorial backend request hash")
        _digest(self.response_sha256, "editorial backend response hash")
        if type(self.call_count) is not int or self.call_count != 1:
            raise EditorialCompositionError("editorial backend session is not one-shot")
        if any(
            type(value) is not bool or value
            for value in (
                self.history_access,
                self.cache_access,
                self.tool_access,
                self.retrieval_access,
                self.filesystem_access,
                self.environment_access,
            )
        ):
            raise EditorialCompositionError(
                "editorial backend isolation is not fail-closed"
            )
        if hashlib.sha256(self.response_bytes).hexdigest() != self.response_sha256:
            raise EditorialCompositionError("editorial backend response bytes differ")


class EditorialStageSession(Protocol):
    """One invocation-scoped session returned by an editorial adapter."""

    invocation_id: str

    def invoke(self, *, request_bytes: bytes) -> EditorialBackendResult: ...


class EditorialStageAdapter(Protocol):
    """Explicit provider transport able to open a fresh one-shot session."""

    provider: str
    model: str
    transport_identity: str
    environment: str

    def available(self) -> bool: ...

    def open_fresh_session(self, *, invocation_id: str) -> EditorialStageSession: ...


@dataclass(frozen=True)
class EditorialCompositionRuntime:
    environment: str
    writer: EditorialStageAdapter
    humanizer: EditorialStageAdapter

    def __post_init__(self) -> None:
        if self.environment not in {"production", "synthetic"}:
            raise EditorialCompositionError("editorial runtime environment is unsupported")
        if self.writer is self.humanizer:
            raise EditorialCompositionError("writer and Humanizer adapters must be distinct")
        for adapter, label in ((self.writer, "writer"), (self.humanizer, "Humanizer")):
            _required(getattr(adapter, "provider", None), f"{label} provider")
            _required(getattr(adapter, "model", None), f"{label} model")
            _required(
                getattr(adapter, "transport_identity", None),
                f"{label} transport identity",
            )
            if getattr(adapter, "environment", None) != self.environment:
                raise EditorialCompositionError(
                    f"{label} adapter environment differs from runtime"
                )


def _draft_from_response(value: bytes) -> CVEditorialDraft:
    try:
        document = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EditorialCompositionError("editorial backend returned invalid JSON") from exc
    if not isinstance(document, dict) or value != canonical_json(document).encode():
        raise EditorialCompositionError("editorial backend response is not canonical JSON")
    if set(document) != {
        "candidate_city",
        "candidate_name",
        "draft_sha256",
        "schema_version",
        "sections",
    } or not isinstance(document["sections"], list):
        raise EditorialCompositionError("editorial backend draft schema differs")
    sections: list[CVSection] = []
    for section in document["sections"]:
        if not isinstance(section, dict) or set(section) != {"atoms", "heading"}:
            raise EditorialCompositionError("editorial backend section schema differs")
        atoms = section["atoms"]
        if not isinstance(atoms, list):
            raise EditorialCompositionError("editorial backend atoms are malformed")
        rows: list[EditorialAtom] = []
        for atom in atoms:
            if not isinstance(atom, dict) or set(atom) != {
                "claim_id",
                "source_kind",
                "text",
            }:
                raise EditorialCompositionError("editorial backend atom schema differs")
            rows.append(EditorialAtom(**atom))
        sections.append(CVSection(str(section["heading"]), tuple(rows)))
    return CVEditorialDraft(
        candidate_name=document["candidate_name"],
        candidate_city=document["candidate_city"],
        sections=tuple(sections),
        draft_sha256=document["draft_sha256"],
        schema_version=document["schema_version"],
    )


def run_editorial_composition_runtime(
    request: CVEditorialRequest,
    *,
    runtime: EditorialCompositionRuntime,
) -> tuple[
    CVEditorialDraft,
    CVEditorialDraft,
    EditorialStageEvidence,
    EditorialStageEvidence,
]:
    """Invoke isolated writer then Humanizer adapters and validate exact output."""

    request.__post_init__()
    runtime.__post_init__()
    if runtime.writer.available() is not True or runtime.humanizer.available() is not True:
        raise EditorialCompositionError("editorial runtime adapter is unavailable")
    writer_request = canonical_json(request.document()).encode()
    writer_invocation = secrets.token_hex(32)
    writer_session = runtime.writer.open_fresh_session(
        invocation_id=writer_invocation
    )
    if writer_session is runtime.writer or writer_session.invocation_id != writer_invocation:
        raise EditorialCompositionError("writer adapter did not open the requested session")
    writer_result = writer_session.invoke(request_bytes=writer_request)
    writer_result.__post_init__()
    if (
        writer_result.invocation_id != writer_invocation
        or writer_result.environment != runtime.environment
        or writer_result.provider != runtime.writer.provider
        or writer_result.model != runtime.writer.model
        or writer_result.transport_identity != runtime.writer.transport_identity
        or writer_result.request_sha256 != hashlib.sha256(writer_request).hexdigest()
    ):
        raise EditorialCompositionError("writer result differs from configured adapter")
    writer_draft = _draft_from_response(writer_result.response_bytes)
    validate_editorial_draft(request, writer_draft)

    humanizer_request_sha = humanizer_request_sha256(request, writer_draft)
    humanizer_request = canonical_json(
        {
            "editorial_request": request.document(),
            "humanizer_request_sha256": humanizer_request_sha,
            "schema_version": "jaa.cv-humanizer-runtime-request.v1",
            "writer_draft": writer_draft.document(),
        }
    ).encode()
    humanizer_invocation = secrets.token_hex(32)
    humanizer_session = runtime.humanizer.open_fresh_session(
        invocation_id=humanizer_invocation
    )
    if (
        humanizer_session is runtime.humanizer
        or humanizer_session is writer_session
        or humanizer_session.invocation_id != humanizer_invocation
    ):
        raise EditorialCompositionError(
            "Humanizer adapter did not open a distinct requested session"
        )
    humanizer_result = humanizer_session.invoke(request_bytes=humanizer_request)
    humanizer_result.__post_init__()
    if (
        humanizer_result.invocation_id != humanizer_invocation
        or humanizer_result.environment != runtime.environment
        or humanizer_result.provider != runtime.humanizer.provider
        or humanizer_result.model != runtime.humanizer.model
        or humanizer_result.transport_identity != runtime.humanizer.transport_identity
        or humanizer_result.request_sha256
        != hashlib.sha256(humanizer_request).hexdigest()
    ):
        raise EditorialCompositionError("Humanizer result differs from configured adapter")
    final_draft = _draft_from_response(humanizer_result.response_bytes)
    writer_evidence = EditorialStageEvidence(
        stage="resume_writer",
        environment=runtime.environment,
        provider=writer_result.provider,
        model=writer_result.model,
        invocation_id=writer_result.invocation_id,
        request_sha256=request.request_sha256,
        response_sha256=writer_draft.draft_sha256,
        transport_identity=writer_result.transport_identity,
        request_bytes_sha256=writer_result.request_sha256,
        response_bytes_sha256=writer_result.response_sha256,
    )
    humanizer_evidence = EditorialStageEvidence(
        stage="humanizer",
        environment=runtime.environment,
        provider=humanizer_result.provider,
        model=humanizer_result.model,
        invocation_id=humanizer_result.invocation_id,
        request_sha256=humanizer_request_sha,
        response_sha256=final_draft.draft_sha256,
        transport_identity=humanizer_result.transport_identity,
        request_bytes_sha256=humanizer_result.request_sha256,
        response_bytes_sha256=humanizer_result.response_sha256,
    )
    admit_editorial_composition(
        request=request,
        writer_draft=writer_draft,
        final_draft=final_draft,
        writer_evidence=writer_evidence,
        humanizer_evidence=humanizer_evidence,
    )
    return writer_draft, final_draft, writer_evidence, humanizer_evidence


__all__ = [
    "ApprovedCVClaim",
    "CVEditorialDraft",
    "CVEditorialRequest",
    "CVSection",
    "CandidateEditorialAuthority",
    "EditorialAtom",
    "EditorialCompositionError",
    "EditorialCompositionReceipt",
    "EditorialCompositionRuntime",
    "EditorialBackendResult",
    "EditorialStageAdapter",
    "EditorialStageSession",
    "EditorialStageEvidence",
    "EditorialStageReceipt",
    "admit_editorial_composition",
    "build_editorial_draft",
    "build_editorial_request",
    "humanizer_request_sha256",
    "run_editorial_composition_runtime",
    "validate_editorial_draft",
]
