"""Fail-closed, evidence-bound application source contract for JAA-07.

The compiler does not invent or paraphrase facts. Candidate and employer
statements enter the source only as exact approved atoms bound to a JAA-06
strategy element. Stylistic workers may propose changes only to explicitly
non-factual connective slots.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import Iterable, Mapping

from .application_strategy import ApplicationStrategy, StrategyElement
from .evidence_matching import canonical_json, content_hash


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
FACT_TOKEN = re.compile(
    r"(?:\b\d[\d,./:-]*\b|[%£$€]|https?://|[^@\s]+@[^@\s]+)"
)
WORD_FACT_TOKEN = re.compile(
    r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|"
    r"twelve|dozen|hundred|thousand|million|billion|percent|percentage)\b",
    re.IGNORECASE,
)
FORBIDDEN_MARKUP = (
    "<table",
    "</table",
    "<img",
    "<svg",
    "display:none",
    "visibility:hidden",
    "font-size:0",
    "opacity:0",
    "position:absolute",
    "[image:",
    "![",
)
AI_STYLE_PATTERNS = (
    "\u2014",
    "\u2013",
    "i am writing to express my interest",
    "not only",
    "it's not just",
    "pivotal",
    "vibrant",
    "tapestry",
    "showcase",
)
CV_SECTION_ORDER = (
    "Professional Summary",
    "Experience",
    "Skills",
    "Education",
)
LETTER_SECTION_ORDER = (
    "Opening",
    "Evidence Match",
    "Company Fit",
    "Close",
)
ALLOWED_FACT_KINDS = frozenset({"candidate", "employer"})
DOCUMENT_KINDS = {
    "cv": frozenset({"cv_emphasis"}),
    "cover_letter": frozenset({"cover_letter_argument", "employer_hook"}),
    "answer": frozenset({"structured_answer"}),
}


def _required(value: str, label: str) -> str:
    clean = value.strip()
    if not clean:
        raise ValueError(f"{label} is required")
    return clean


def _digest(value: str, label: str) -> str:
    if not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _safe_plain_text(value: str, label: str) -> str:
    clean = _required(value, label)
    folded = clean.casefold().replace(" ", "")
    if any(marker.replace(" ", "") in folded for marker in FORBIDDEN_MARKUP):
        raise ValueError(f"{label} contains forbidden rich or hidden content")
    if "\x00" in clean or "\r" in clean:
        raise ValueError(f"{label} must be normalized plain text")
    return clean


@dataclass(frozen=True)
class CandidateContact:
    """Versioned contact projection; no street address or sensitive fields."""

    full_name: str
    email: str
    phone: str
    city: str
    record_id: str
    record_version: int
    provenance_sha256: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.full_name, "candidate name"),
            (self.phone, "candidate phone"),
            (self.city, "candidate city"),
            (self.record_id, "contact record ID"),
        ):
            _safe_plain_text(value, label)
        if not EMAIL.fullmatch(self.email):
            raise ValueError("candidate email is invalid")
        if self.record_version < 1:
            raise ValueError("contact record version must be positive")
        _digest(self.provenance_sha256, "contact provenance hash")
        if "\n" in self.city or "," in self.city:
            raise ValueError("contact location must be city only")

    def document(self) -> dict[str, object]:
        return {
            "full_name": self.full_name,
            "email": self.email,
            "phone": self.phone,
            "city": self.city,
            "record_id": self.record_id,
            "record_version": self.record_version,
            "provenance_sha256": self.provenance_sha256,
        }


@dataclass(frozen=True)
class FactAuthority:
    """Exact authority coordinates copied from one JAA-06 element."""

    strategy_element_id: str
    requirement_id: str
    candidate_claim_id: str
    candidate_claim_version: int
    candidate_evidence_id: str
    candidate_evidence_version: int
    employer_research_claim_id: str
    employer_fact_sha256: str

    def __post_init__(self) -> None:
        _digest(self.strategy_element_id, "strategy element ID")
        _digest(self.employer_fact_sha256, "employer fact hash")
        for value, label in (
            (self.requirement_id, "requirement ID"),
            (self.candidate_claim_id, "candidate claim ID"),
            (self.candidate_evidence_id, "candidate evidence ID"),
            (self.employer_research_claim_id, "employer research claim ID"),
        ):
            _required(value, label)
        if self.candidate_claim_version < 1 or self.candidate_evidence_version < 1:
            raise ValueError("candidate authority versions must be positive")

    @classmethod
    def from_element(cls, element: StrategyElement) -> FactAuthority:
        return cls(
            element.element_id,
            element.requirement_id,
            element.candidate_claim_id,
            element.candidate_claim_version,
            element.candidate_evidence_id,
            element.candidate_evidence_version,
            element.employer_research_claim_id,
            element.employer_fact_sha256,
        )


@dataclass(frozen=True)
class FactualSentence:
    """One verbatim approved fact and its immutable source identity."""

    sentence_id: str
    text: str
    approved_source_text: str
    fact_kind: str
    document_kind: str
    authority: FactAuthority
    employer_fact_json: str | None = None

    def __post_init__(self) -> None:
        _digest(self.sentence_id, "sentence ID")
        text = _safe_plain_text(self.text, "factual sentence")
        source = _safe_plain_text(self.approved_source_text, "approved source text")
        if text != source:
            raise ValueError("factual sentence must equal its approved source text")
        if self.fact_kind not in ALLOWED_FACT_KINDS:
            raise ValueError("factual sentence kind is unsupported")
        if self.document_kind not in DOCUMENT_KINDS:
            raise ValueError("factual sentence document kind is unsupported")
        if self.fact_kind == "candidate":
            if self.employer_fact_json is not None:
                raise ValueError("candidate sentence cannot carry an employer fact")
        else:
            if self.employer_fact_json is None:
                raise ValueError("employer sentence requires its exact fact document")
            try:
                fact = json.loads(self.employer_fact_json)
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("employer fact document is not valid JSON") from exc
            if (
                not isinstance(fact, dict)
                or canonical_json(fact) != self.employer_fact_json
                or fact.get("id") != self.authority.employer_research_claim_id
                or fact.get("classification") != "fact"
                or fact.get("text") != self.text
                or not isinstance(fact.get("source_ids"), list)
                or not fact["source_ids"]
                or content_hash(fact) != self.authority.employer_fact_sha256
            ):
                raise ValueError(
                    "employer sentence does not match its exact source-backed fact"
                )

    def document(self) -> dict[str, object]:
        return {
            "sentence_id": self.sentence_id,
            "text": self.text,
            "approved_source_text": self.approved_source_text,
            "fact_kind": self.fact_kind,
            "document_kind": self.document_kind,
            "authority": vars(self.authority),
            "employer_fact_json": self.employer_fact_json,
        }


@dataclass(frozen=True)
class StyleSlot:
    """Non-factual connective prose which a critic may propose replacing."""

    slot_id: str
    document_kind: str
    text: str

    def __post_init__(self) -> None:
        _digest(self.slot_id, "style slot ID")
        if self.document_kind not in DOCUMENT_KINDS:
            raise ValueError("style slot document kind is unsupported")
        validate_style_text(self.text)

    def document(self) -> dict[str, str]:
        return {
            "slot_id": self.slot_id,
            "document_kind": self.document_kind,
            "text": self.text,
        }


@dataclass(frozen=True)
class ModelReceipt:
    provider: str
    model: str
    prompt_sha256: str
    policy_sha256: str
    input_sha256: str
    output_sha256: str

    def __post_init__(self) -> None:
        _required(self.provider, "model provider")
        _required(self.model, "model name")
        for value, label in (
            (self.prompt_sha256, "prompt hash"),
            (self.policy_sha256, "proposal policy hash"),
            (self.input_sha256, "proposal input hash"),
            (self.output_sha256, "proposal output hash"),
        ):
            _digest(value, label)


@dataclass(frozen=True)
class StyleProposal:
    proposal_id: str
    slot_id: str
    original_text: str
    proposed_text: str
    receipt: ModelReceipt

    def __post_init__(self) -> None:
        _digest(self.proposal_id, "style proposal ID")
        _digest(self.slot_id, "style proposal slot ID")
        validate_style_text(self.original_text)
        validate_style_text(self.proposed_text)
        if self.original_text == self.proposed_text:
            raise ValueError("style proposal must change its target")
        if hashlib.sha256(self.original_text.encode()).hexdigest() != self.receipt.input_sha256:
            raise ValueError("style proposal input does not match its receipt")
        if hashlib.sha256(self.proposed_text.encode()).hexdigest() != self.receipt.output_sha256:
            raise ValueError("style proposal output does not match its receipt")
        expected = content_hash(
            {
                "contract": "jaa07.style-proposal.v1",
                "slot_id": self.slot_id,
                "input_sha256": self.receipt.input_sha256,
                "output_sha256": self.receipt.output_sha256,
                "provider": self.receipt.provider,
                "model": self.receipt.model,
                "prompt_sha256": self.receipt.prompt_sha256,
                "policy_sha256": self.receipt.policy_sha256,
            }
        )
        if self.proposal_id != expected:
            raise ValueError("style proposal identity is inconsistent")


@dataclass(frozen=True)
class DocumentSection:
    heading: str
    sentence_ids: tuple[str, ...]
    style_slot_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _safe_plain_text(self.heading, "section heading")
        if not self.sentence_ids:
            raise ValueError("document sections require factual content")
        if len(set(self.sentence_ids)) != len(self.sentence_ids):
            raise ValueError("section sentence identities must be unique")


@dataclass(frozen=True)
class StructuredAnswer:
    question_id: str
    question: str
    sentence_ids: tuple[str, ...]
    style_slot_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _required(self.question_id, "question ID")
        _safe_plain_text(self.question, "portal question")
        if not self.sentence_ids:
            raise ValueError("structured answers require approved factual content")


@dataclass(frozen=True)
class ApplicationSource:
    source_id: str
    strategy_id: str
    job_key: str
    role_title: str
    company_name: str
    vacancy_source_identity: str
    vacancy_sha256: str
    contact: CandidateContact
    facts: tuple[FactualSentence, ...]
    style_slots: tuple[StyleSlot, ...]
    cv_sections: tuple[DocumentSection, ...]
    letter_sections: tuple[DocumentSection, ...]
    answers: tuple[StructuredAnswer, ...]
    content_sha256: str
    schema_version: str = "jaa07.application-source.v1"
    certifies_slice: bool = False
    dependency_gate: str = "JAA-06"

    def __post_init__(self) -> None:
        if self.schema_version != "jaa07.application-source.v1":
            raise ValueError("unsupported application source schema")
        if self.certifies_slice is not False or self.dependency_gate != "JAA-06":
            raise ValueError("offline application source cannot certify JAA-07")
        _digest(self.source_id, "application source ID")
        _digest(self.strategy_id, "application strategy ID")
        _digest(self.vacancy_sha256, "vacancy hash")
        _digest(self.content_sha256, "application source content hash")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "strategy_id": self.strategy_id,
            "job_key": self.job_key,
            "role_title": self.role_title,
            "company_name": self.company_name,
            "vacancy_source_identity": self.vacancy_source_identity,
            "vacancy_sha256": self.vacancy_sha256,
            "contact": self.contact.document(),
            "facts": [row.document() for row in self.facts],
            "style_slots": [row.document() for row in self.style_slots],
            "cv_sections": [vars(row) for row in self.cv_sections],
            "letter_sections": [vars(row) for row in self.letter_sections],
            "answers": [vars(row) for row in self.answers],
            "certifies_slice": False,
            "dependency_gate": "JAA-06",
        }
        if include_identity:
            result["source_id"] = self.source_id
            result["content_sha256"] = self.content_sha256
        return result


def validate_style_text(text: str) -> None:
    clean = _safe_plain_text(text, "style text")
    if FACT_TOKEN.search(clean) or WORD_FACT_TOKEN.search(clean):
        raise ValueError("style text cannot contain fact-like tokens")
    folded = clean.casefold()
    if any(pattern in folded for pattern in AI_STYLE_PATTERNS):
        raise ValueError("style text violates the bounded natural-language policy")


def _validate_authority(
    fact: FactualSentence,
    element_by_id: Mapping[str, StrategyElement],
) -> StrategyElement:
    element = element_by_id.get(fact.authority.strategy_element_id)
    if element is None:
        raise ValueError("factual sentence cites an unknown strategy element")
    if FactAuthority.from_element(element) != fact.authority:
        raise ValueError("factual sentence authority differs from its strategy element")
    if element.kind not in DOCUMENT_KINDS[fact.document_kind]:
        raise ValueError("factual sentence uses the wrong strategy element kind")
    if fact.fact_kind == "employer" and element.kind != "employer_hook":
        raise ValueError("employer factual sentences require an employer-hook element")
    if fact.fact_kind == "candidate" and element.kind == "employer_hook":
        raise ValueError("candidate factual sentences cannot use an employer-hook element")
    return element


def _validate_sections(
    *,
    sections: tuple[DocumentSection, ...],
    expected_headings: tuple[str, ...],
    document_kind: str,
    facts: Mapping[str, FactualSentence],
    slots: Mapping[str, StyleSlot],
) -> set[str]:
    if tuple(row.heading for row in sections) != expected_headings:
        raise ValueError(f"{document_kind} sections are not canonical")
    covered: set[str] = set()
    for section in sections:
        for sentence_id in section.sentence_ids:
            fact = facts.get(sentence_id)
            if fact is None or fact.document_kind != document_kind:
                raise ValueError(f"{document_kind} section cites invalid factual content")
            covered.add(fact.authority.requirement_id)
        for slot_id in section.style_slot_ids:
            slot = slots.get(slot_id)
            if slot is None or slot.document_kind != document_kind:
                raise ValueError(f"{document_kind} section cites an invalid style slot")
    return covered


def compile_application_source(
    *,
    strategy: ApplicationStrategy,
    job_key: str,
    role_title: str,
    company_name: str,
    vacancy_source_identity: str,
    vacancy_sha256: str,
    contact: CandidateContact,
    facts: Iterable[FactualSentence],
    style_slots: Iterable[StyleSlot],
    cv_sections: Iterable[DocumentSection],
    letter_sections: Iterable[DocumentSection],
    answers: Iterable[StructuredAnswer],
) -> ApplicationSource:
    """Compile one deterministic editable source without releasing anything."""
    if strategy.decision != "apply_now":
        raise ValueError("application source requires an apply-now strategy")
    _required(job_key, "job key")
    role = _safe_plain_text(role_title, "role title")
    company = _safe_plain_text(company_name, "company name")
    source_identity = _required(vacancy_source_identity, "vacancy source identity")
    _digest(vacancy_sha256, "vacancy hash")

    fact_rows = tuple(facts)
    slot_rows = tuple(style_slots)
    cv_rows = tuple(cv_sections)
    letter_rows = tuple(letter_sections)
    answer_rows = tuple(answers)
    fact_by_id = {row.sentence_id: row for row in fact_rows}
    slot_by_id = {row.slot_id: row for row in slot_rows}
    if len(fact_by_id) != len(fact_rows) or len(slot_by_id) != len(slot_rows):
        raise ValueError("fact and style-slot identities must be unique")

    elements = {row.element_id: row for row in strategy.elements}
    for fact in fact_rows:
        _validate_authority(fact, elements)

    required = {row.requirement_id for row in strategy.coverage}
    cv_covered = _validate_sections(
        sections=cv_rows,
        expected_headings=CV_SECTION_ORDER,
        document_kind="cv",
        facts=fact_by_id,
        slots=slot_by_id,
    )
    letter_covered = _validate_sections(
        sections=letter_rows,
        expected_headings=LETTER_SECTION_ORDER,
        document_kind="cover_letter",
        facts=fact_by_id,
        slots=slot_by_id,
    )
    if cv_covered != required or letter_covered != required:
        raise ValueError("CV and cover letter must each cover every strategy requirement")

    employer_sentences = [
        row
        for section in letter_rows
        for sentence_id in section.sentence_ids
        if (row := fact_by_id[sentence_id]).fact_kind == "employer"
    ]
    if not employer_sentences or not any(company.casefold() in row.text.casefold() for row in employer_sentences):
        raise ValueError("cover letter requires an exact company-specific employer fact")

    seen_questions: set[str] = set()
    for answer in answer_rows:
        if answer.question_id in seen_questions:
            raise ValueError("structured answer question identities must be unique")
        seen_questions.add(answer.question_id)
        for sentence_id in answer.sentence_ids:
            fact = fact_by_id.get(sentence_id)
            if fact is None or fact.document_kind != "answer":
                raise ValueError("structured answer cites invalid factual content")
        for slot_id in answer.style_slot_ids:
            slot = slot_by_id.get(slot_id)
            if slot is None or slot.document_kind != "answer":
                raise ValueError("structured answer cites an invalid style slot")

    referenced = {
        sentence_id
        for section in (*cv_rows, *letter_rows)
        for sentence_id in section.sentence_ids
    } | {
        sentence_id for answer in answer_rows for sentence_id in answer.sentence_ids
    }
    referenced_slots = {
        slot_id
        for section in (*cv_rows, *letter_rows)
        for slot_id in section.style_slot_ids
    } | {
        slot_id for answer in answer_rows for slot_id in answer.style_slot_ids
    }
    if referenced != set(fact_by_id) or referenced_slots != set(slot_by_id):
        raise ValueError("application source contains unused or missing content atoms")

    provisional = ApplicationSource(
        "0" * 64,
        strategy.strategy_id,
        job_key,
        role,
        company,
        source_identity,
        vacancy_sha256,
        contact,
        fact_rows,
        slot_rows,
        cv_rows,
        letter_rows,
        answer_rows,
        "0" * 64,
    )
    body = provisional.document(include_identity=False)
    content_sha256 = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    source_id = content_hash(
        {
            "contract": "jaa07.application-source.v1",
            "strategy_id": strategy.strategy_id,
            "content_sha256": content_sha256,
        }
    )
    return replace(
        provisional,
        source_id=source_id,
        content_sha256=content_sha256,
    )


def verify_application_source(source: ApplicationSource) -> None:
    body = source.document(include_identity=False)
    expected_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    expected_id = content_hash(
        {
            "contract": "jaa07.application-source.v1",
            "strategy_id": source.strategy_id,
            "content_sha256": expected_hash,
        }
    )
    if source.content_sha256 != expected_hash or source.source_id != expected_id:
        raise ValueError("application source identity differs from its exact content")


def apply_style_proposal(
    source: ApplicationSource,
    proposal: StyleProposal,
) -> ApplicationSource:
    """Return a new source identity; never mutate or approve a proposal."""
    verify_application_source(source)
    slots = {row.slot_id: row for row in source.style_slots}
    target = slots.get(proposal.slot_id)
    if target is None or target.text != proposal.original_text:
        raise ValueError("style proposal target does not match the exact source")
    replaced_slots = tuple(
        replace(row, text=proposal.proposed_text)
        if row.slot_id == proposal.slot_id
        else row
        for row in source.style_slots
    )
    provisional = replace(
        source,
        source_id="0" * 64,
        content_sha256="0" * 64,
        style_slots=replaced_slots,
    )
    body = provisional.document(include_identity=False)
    new_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    new_id = content_hash(
        {
            "contract": "jaa07.application-source.v1",
            "strategy_id": source.strategy_id,
            "content_sha256": new_hash,
        }
    )
    return replace(provisional, source_id=new_id, content_sha256=new_hash)
