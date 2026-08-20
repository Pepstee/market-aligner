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
import sqlite3
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Iterable, Mapping

from jaa_core.contracts import CandidateContact

from .application_strategy import (
    ApplicationStrategy,
    ApplicationStrategyStore,
    StrategyElement,
)
from .evidence_matching import canonical_json, content_hash


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
FACT_TOKEN = re.compile(r"(?:\b\d[\d,./:-]*\b|[%£$€]|https?://|[^@\s]+@[^@\s]+)")
WORD_FACT_TOKEN = re.compile(
    r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|"
    r"twelve|dozen|hundred|thousand|million|billion|percent|percentage)\b",
    re.IGNORECASE,
)
ORDINAL_FACT_TOKEN = re.compile(
    r"\b\d+(?:st|nd|rd|th)\b",
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
    "Core Capabilities",
    "Projects",
    "Education",
    "Experience",
    "Skills",
)
LETTER_SECTION_ORDER = (
    "Opening",
    "Evidence Match",
    "Company Fit",
    "Close",
)
ALLOWED_FACT_KINDS = frozenset({"candidate", "employer"})

# Operator doctrine, ratified 2026-08-07: employer-facing documents carry the
# strongest framing the approved evidence will support. A CV and a cover letter
# are a selection of positive evidence, not a balanced self-assessment. Omitting
# the unbounded set of things the candidate cannot do is not a misrepresentation;
# naming them only supplies a rejection rationale. This guard is fail-closed and
# applies to candidate claims and style text only — never to employer facts,
# which are the vacancy's own words and must survive verbatim.
#
# The counterweight lives elsewhere and is unchanged: every positive claim must
# still be entailed by approved evidence. The permitted zone is the strongest
# supported framing, which is neither fabrication nor self-deprecation.
SELF_MINIMISING_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"\bmy\s+(?:current\s+)?(?:gaps?|weaknesses|limitations)\b",
        "names the candidate's gaps",
    ),
    (
        r"\bi\s+(?:do\s+not|don't|did\s+not)\s+(?:yet\s+)?(?:have|possess|hold)\b",
        "volunteers missing experience",
    ),
    (r"\bi\s+(?:lack|am\s+lacking)\b", "volunteers a deficiency"),
    (
        r"\b(?:no|without|little|limited)\s+(?:commercial|professional|industry|direct|prior)\s+experience\b",
        "volunteers absent experience",
    ),
    (
        r"\bnot\s+yet\s+\w+(?:ed|n)\b",
        "frames the candidate's own work as not yet proven",
    ),
    (
        r"[;,]\s*(?:it|I|this|they|these|the\s+\w+)\s+(?:was|were|is|are|do|did|does|have|has|had)\s+not\b",
        "appends a negative coda to the candidate's own achievement",
    ),
    (
        r"\bI\s+did\s+not\b|\bit\s+was\s+not\b|\bthis\s+was\s+not\b",
        "negates the candidate's own claim",
    ),
    (
        r"\b(?:has|have|had)\s+not\s+(?:yet\s+)?\w+(?:ed|n)\b",
        "negates the candidate's own work",
    ),
    (
        r"\b(?:prototype|proof[- ]of[- ]concept)\b(?=[^.]*\bnot\b)",
        "hedges delivered work as a mere prototype",
    ),
    (
        r"\bweaker\s+than\b|\bless\s+experienced\s+than\b",
        "compares the candidate downward",
    ),
    (r"\bi\s+apologi[sz]e\b|\bapolog(?:y|ies)\s+for\b", "apologises to the employer"),
    (
        r"\bi\s+(?:do\s+not|don't)\s+present\b",
        "disclaims authorship of the candidate's own work",
    ),
    (r"\brather\s+than\s+being\s+presented\s+as\b", "hedges the work as unfinished"),
    (
        r"\bai[- ](?:generated|authored|written)\s+(?:code|implementation|work|content)\b",
        "discloses AI authorship",
    ),
    (
        r"\bai\s+(?:agents?|models?|assistants?)\s+(?:generate|generated|wrote|write|produced)\b",
        "discloses AI authorship",
    ),
    (r"\bevidence\s+boundar(?:y|ies)\b", "exposes internal provenance process"),
    (
        r"\bclaims\s+in\s+this\s+(?:cv|document|application)\s+are\s+limited\s+to\b",
        "narrows the candidate's own claims",
    ),
    (
        r"\boperator[- ]approved\b|\bapproved[- ]evidence\s+(?:packet|corpus)\b",
        "exposes internal process language",
    ),
    (r"\bunder\s+(?:commercial\s+)?hardening\b", "frames delivered work as unfinished"),
    (
        r"\bbut\s+(?:exposed|lacked?|failed|remained|only)\b",
        "concedes against the candidate's own achievement",
    ),
    (
        r"\bwithout\s+a\s+written\s+employment\s+contract\b",
        "volunteers an irrelevant employment caveat",
    ),
    (r"\bclient\s+(?:later\s+)?abandoned\b", "volunteers an irrelevant client outcome"),
    (
        r"\brather\s+than\s+personally\s+(?:implementing|writing|building)\b",
        "disclaims implementation ownership",
    ),
    (r"\bstill\s+required\s+(?:repair|fixing|work)\b", "volunteers unfinished work"),
    (
        r"\bnot\s+a\s+separate\s+professional\s+project\b",
        "volunteers a needless project limitation",
    ),
    (
        r"\bshould\s+not\s+be\s+presented\s+as\b",
        "instructs the employer how to discount the evidence",
    ),
)
_SELF_MINIMISING = tuple(
    (re.compile(pattern, re.IGNORECASE), reason)
    for pattern, reason in SELF_MINIMISING_PATTERNS
)


def assert_employer_facing_framing(text: str, label: str) -> None:
    """Fail closed on any employer-facing text that argues against the candidate."""
    for expression, reason in _SELF_MINIMISING:
        match = expression.search(text)
        if match is not None:
            raise ValueError(
                f"{label} {reason}: {match.group(0)!r}. Employer-facing documents "
                "carry the strongest evidence-supported framing; state capability, "
                "never its absence."
            )


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
class ProfileFactAuthority:
    """Exact approved candidate fact independent of one vacancy requirement.

    A tailored CV needs stable background facts as well as vacancy-matched
    emphasis. This authority binds each stable fact to the exact candidate
    projection and the hash of its approved source statement.
    """

    candidate_profile_hash: str
    candidate_claim_id: str
    candidate_claim_version: int
    candidate_evidence_id: str
    candidate_evidence_version: int
    candidate_evidence_sha256: str
    proof_class: str
    outward_text_sha256: str | None = None
    rewrite_policy_sha256: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.candidate_profile_hash, "candidate profile hash"),
            (self.candidate_evidence_sha256, "candidate evidence hash"),
        ):
            _digest(value, label)
        for value, label in (
            (self.candidate_claim_id, "candidate claim ID"),
            (self.candidate_evidence_id, "candidate evidence ID"),
            (self.proof_class, "candidate proof class"),
        ):
            _required(value, label)
        if self.candidate_claim_version < 1 or self.candidate_evidence_version < 1:
            raise ValueError("candidate authority versions must be positive")
        if (self.outward_text_sha256 is None) != (
            self.rewrite_policy_sha256 is None
        ):
            raise ValueError("candidate outward rewrite authority is incomplete")
        if self.outward_text_sha256 is not None:
            _digest(self.outward_text_sha256, "candidate outward text hash")
            _digest(self.rewrite_policy_sha256, "candidate rewrite policy hash")


@dataclass(frozen=True)
class VacancyFactAuthority:
    """Exact employer fact taken from the currently verified vacancy."""

    vacancy_source_identity: str
    vacancy_sha256: str
    employer_research_claim_id: str
    employer_fact_sha256: str

    def __post_init__(self) -> None:
        _required(self.vacancy_source_identity, "vacancy source identity")
        _digest(self.vacancy_sha256, "vacancy hash")
        _required(self.employer_research_claim_id, "employer research claim ID")
        _digest(self.employer_fact_sha256, "employer fact hash")


@dataclass(frozen=True)
class FactualSentence:
    """One approved fact, with any exact outward rewrite bound to its authority."""

    sentence_id: str
    text: str
    approved_source_text: str
    fact_kind: str
    document_kind: str
    authority: FactAuthority | ProfileFactAuthority | VacancyFactAuthority
    employer_fact_json: str | None = None

    def __post_init__(self) -> None:
        _digest(self.sentence_id, "sentence ID")
        text = _safe_plain_text(self.text, "factual sentence")
        source = _safe_plain_text(self.approved_source_text, "approved source text")
        if text != source:
            if (
                not isinstance(self.authority, ProfileFactAuthority)
                or self.authority.outward_text_sha256
                != hashlib.sha256(text.encode()).hexdigest()
                or self.authority.rewrite_policy_sha256 is None
            ):
                raise ValueError(
                    "factual sentence must equal its approved source text unless "
                    "it has exact outward authority"
                )
        elif isinstance(self.authority, ProfileFactAuthority) and (
            self.authority.outward_text_sha256 is not None
            or self.authority.rewrite_policy_sha256 is not None
        ):
            raise ValueError("verbatim candidate fact cannot claim rewrite authority")
        if self.fact_kind not in ALLOWED_FACT_KINDS:
            raise ValueError("factual sentence kind is unsupported")
        if self.document_kind not in DOCUMENT_KINDS:
            raise ValueError("factual sentence document kind is unsupported")
        if self.fact_kind == "candidate":
            assert_employer_facing_framing(text, "factual sentence")
            if self.employer_fact_json is not None:
                raise ValueError("candidate sentence cannot carry an employer fact")
            if (
                isinstance(self.authority, ProfileFactAuthority)
                and hashlib.sha256(source.encode()).hexdigest()
                != self.authority.candidate_evidence_sha256
            ):
                raise ValueError(
                    "profile factual sentence differs from its approved evidence hash"
                )
        else:
            if not isinstance(self.authority, (FactAuthority, VacancyFactAuthority)):
                raise ValueError("employer sentence requires strategy authority")
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
        if (
            hashlib.sha256(self.original_text.encode()).hexdigest()
            != self.receipt.input_sha256
        ):
            raise ValueError("style proposal input does not match its receipt")
        if (
            hashlib.sha256(self.proposed_text.encode()).hexdigest()
            != self.receipt.output_sha256
        ):
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
        if not self.sentence_ids and not self.style_slot_ids:
            raise ValueError("document sections require content")
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
    if (
        FACT_TOKEN.search(clean)
        or WORD_FACT_TOKEN.search(clean)
        or ORDINAL_FACT_TOKEN.search(clean)
    ):
        raise ValueError("style text cannot contain fact-like tokens")
    folded = clean.casefold()
    if any(pattern in folded for pattern in AI_STYLE_PATTERNS):
        raise ValueError("style text violates the bounded natural-language policy")
    assert_employer_facing_framing(clean, "style text")


def _validate_authority(
    fact: FactualSentence,
    element_by_id: Mapping[str, StrategyElement],
    *,
    candidate_profile_hash: str,
    vacancy_source_identity: str,
    vacancy_sha256: str,
) -> StrategyElement | None:
    if isinstance(fact.authority, ProfileFactAuthority):
        if fact.fact_kind != "candidate":
            raise ValueError("profile authority can only support candidate facts")
        if fact.authority.candidate_profile_hash != candidate_profile_hash:
            raise ValueError(
                "profile fact differs from the strategy candidate projection"
            )
        return None
    if isinstance(fact.authority, VacancyFactAuthority):
        if fact.fact_kind != "employer":
            raise ValueError("vacancy authority can only support employer facts")
        if (
            fact.authority.vacancy_source_identity != vacancy_source_identity
            or fact.authority.vacancy_sha256 != vacancy_sha256
        ):
            raise ValueError("employer fact differs from the current vacancy authority")
        return None
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
        raise ValueError(
            "candidate factual sentences cannot use an employer-hook element"
        )
    return element


def _validate_sections(
    *,
    sections: tuple[DocumentSection, ...],
    expected_headings: tuple[str, ...],
    document_kind: str,
    facts: Mapping[str, FactualSentence],
    slots: Mapping[str, StyleSlot],
) -> set[str]:
    headings = tuple(row.heading for row in sections)
    if document_kind == "cv":
        try:
            positions = tuple(expected_headings.index(value) for value in headings)
        except ValueError as exc:
            raise ValueError("cv sections are not canonical") from exc
        if (
            not headings
            or headings[0] != "Professional Summary"
            or len(set(headings)) != len(headings)
            or positions != tuple(sorted(positions))
            or len(headings) < 2
        ):
            raise ValueError("cv sections are not canonical")
    elif headings != expected_headings:
        raise ValueError(f"{document_kind} sections are not canonical")
    covered: set[str] = set()
    for section in sections:
        for sentence_id in section.sentence_ids:
            fact = facts.get(sentence_id)
            if fact is None or fact.document_kind != document_kind:
                raise ValueError(
                    f"{document_kind} section cites invalid factual content"
                )
            if isinstance(fact.authority, FactAuthority):
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
    if strategy.decision not in {"apply_now", "apply_with_known_gaps"}:
        raise ValueError("application source requires an application strategy")
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
        _validate_authority(
            fact,
            elements,
            candidate_profile_hash=strategy.candidate_profile_hash,
            vacancy_source_identity=source_identity,
            vacancy_sha256=vacancy_sha256,
        )

    required = {
        row.requirement_id for row in strategy.coverage if row.state == "covered"
    }
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
        raise ValueError(
            "CV and cover letter must each cover every strategy requirement"
        )

    employer_sentences = [
        row
        for section in letter_rows
        for sentence_id in section.sentence_ids
        if (row := fact_by_id[sentence_id]).fact_kind == "employer"
    ]
    if not employer_sentences or not any(
        company.casefold() in row.text.casefold() for row in employer_sentences
    ):
        raise ValueError(
            "cover letter requires an exact company-specific employer fact"
        )

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
    } | {sentence_id for answer in answer_rows for sentence_id in answer.sentence_ids}
    referenced_slots = {
        slot_id
        for section in (*cv_rows, *letter_rows)
        for slot_id in section.style_slot_ids
    } | {slot_id for answer in answer_rows for slot_id in answer.style_slot_ids}
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


class ProductionApplicationCompiler:
    """Resolve every source atom from current durable JAA authority."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.strategies = ApplicationStrategyStore(self.path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _sentence(
        element: StrategyElement,
        *,
        text: str,
        fact_kind: str,
        document_kind: str,
        employer_fact_json: str | None = None,
    ) -> FactualSentence:
        sentence_id = content_hash(
            {
                "contract": "jaa07.factual-sentence.v1",
                "element_id": element.element_id,
                "text": text,
                "fact_kind": fact_kind,
                "document_kind": document_kind,
            }
        )
        return FactualSentence(
            sentence_id,
            text,
            text,
            fact_kind,
            document_kind,
            FactAuthority.from_element(element),
            employer_fact_json,
        )

    @staticmethod
    def _slot(document_kind: str, purpose: str, text: str) -> StyleSlot:
        return StyleSlot(
            content_hash(
                {
                    "contract": "jaa07.deterministic-style-slot.v1",
                    "document_kind": document_kind,
                    "purpose": purpose,
                    "text": text,
                }
            ),
            document_kind,
            text,
        )

    @staticmethod
    def _contact(
        connection: sqlite3.Connection,
        contact: CandidateContact,
        as_of: date,
    ) -> None:
        row = connection.execute(
            """SELECT record.*,provenance.source_hash
               FROM candidate_records record
               JOIN candidate_provenance provenance
                 ON provenance.provenance_id=record.provenance_id
               WHERE record.record_id=? AND record.version=?
                 AND record.record_kind='fact'
                 AND record.subject='contact'
                 AND record.epistemic_state='fact'
                 AND (record.valid_from IS NULL OR record.valid_from<=?)
                 AND (record.valid_until IS NULL OR record.valid_until>=?)
                 AND NOT EXISTS(
                   SELECT 1 FROM candidate_records newer
                   WHERE newer.record_id=record.record_id
                     AND newer.version>record.version
                 )
                 AND 1=(
                   SELECT COUNT(*) FROM candidate_verification_decisions decision
                   WHERE decision.target_kind='record'
                     AND decision.target_id=record.record_id
                     AND decision.target_version=record.version
                     AND decision.decision='approved'
                 )
                 AND 1=(
                   SELECT COUNT(*) FROM candidate_verification_decisions decision
                   WHERE decision.target_kind='record'
                     AND decision.target_id=record.record_id
                     AND decision.target_version=record.version
                 )""",
            (
                contact.record_id,
                contact.record_version,
                as_of.isoformat(),
                as_of.isoformat(),
            ),
        ).fetchone()
        expected = {
            "full_name": contact.full_name,
            "email": contact.email,
            "phone": contact.phone,
            "city": contact.city,
        }
        if row is None:
            raise ValueError("contact projection lacks current verified authority")
        try:
            value = json.loads(str(row["value_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("contact authority is not valid JSON") from exc
        if (
            value != expected
            or canonical_json(value) != str(row["value_json"])
            or str(row["source_hash"]) != contact.provenance_sha256
        ):
            raise ValueError("contact projection differs from its durable authority")

    @staticmethod
    def _candidate_statement(
        connection: sqlite3.Connection,
        element: StrategyElement,
        as_of: date,
    ) -> tuple[str, str]:
        rows = connection.execute(
            """SELECT claim.statement,claim.claim_type
               FROM candidate_claims claim
               JOIN candidate_claim_edges edge
                 ON edge.claim_id=claim.claim_id
                AND edge.claim_version=claim.version
               JOIN candidate_evidence evidence
                 ON evidence.evidence_id=edge.evidence_id
                AND evidence.version=edge.evidence_version
               WHERE claim.claim_id=? AND claim.version=?
                 AND evidence.evidence_id=? AND evidence.version=?
                 AND edge.edge_type IN ('supports','demonstrated_by')
                 AND claim.approval_state='approved'
                 AND claim.epistemic_state IN ('fact','evidence')
                 AND evidence.approval_state='approved'
                 AND evidence.epistemic_state IN ('fact','evidence')
                 AND EXISTS(
                   SELECT 1 FROM candidate_verification_decisions decision
                   WHERE decision.target_kind='evidence'
                     AND decision.target_id=evidence.evidence_id
                     AND decision.target_version=evidence.version
                     AND decision.decision='approved'
                 )
                 AND (claim.valid_until IS NULL OR claim.valid_until>=?)
                 AND (evidence.valid_until IS NULL OR evidence.valid_until>=?)
                 AND NOT EXISTS(
                   SELECT 1 FROM candidate_claims newer
                   WHERE newer.claim_id=claim.claim_id
                     AND newer.version>claim.version
                 )
                 AND NOT EXISTS(
                   SELECT 1 FROM candidate_evidence newer
                   WHERE newer.evidence_id=evidence.evidence_id
                     AND newer.version>evidence.version
                 )""",
            (
                element.candidate_claim_id,
                element.candidate_claim_version,
                element.candidate_evidence_id,
                element.candidate_evidence_version,
                as_of.isoformat(),
                as_of.isoformat(),
            ),
        ).fetchall()
        if len(rows) != 1:
            raise ValueError(
                "strategy element lacks one exact current approved candidate fact"
            )
        return str(rows[0]["statement"]), str(rows[0]["claim_type"])

    @staticmethod
    def _employer_statement(
        connection: sqlite3.Connection,
        *,
        job_key: str,
        element: StrategyElement,
    ) -> tuple[str, str]:
        row = connection.execute(
            """SELECT claim_json,classification
               FROM employer_intelligence
               WHERE job_key=? AND claim_id=?""",
            (job_key, element.employer_research_claim_id),
        ).fetchone()
        if row is None or str(row["classification"]) != "fact":
            raise ValueError("strategy employer fact authority is unavailable")
        try:
            document = json.loads(str(row["claim_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("strategy employer fact is not valid JSON") from exc
        if (
            not isinstance(document, dict)
            or document.get("classification") != "fact"
            or document.get("id") != element.employer_research_claim_id
            or not isinstance(document.get("text"), str)
            or not document["text"].strip()
            or not isinstance(document.get("source_ids"), list)
            or not document["source_ids"]
            or content_hash(document) != element.employer_fact_sha256
        ):
            raise ValueError("strategy employer fact differs from exact authority")
        return str(document["text"]), canonical_json(document)

    def compile(
        self,
        strategy_id: str,
        *,
        as_of: date,
        contact: CandidateContact,
        questions: Mapping[str, tuple[str, str]] | None = None,
        cv_layout: str = "legacy",
    ) -> ApplicationSource:
        """Compile routine prose without accepting caller-authored factual text."""
        if cv_layout not in {"legacy", "four_section"}:
            raise ValueError("unsupported CV layout")
        question_rows = questions or {}
        strategy = self.strategies.load(strategy_id, as_of=as_of)
        if strategy.decision != "apply_now":
            raise ValueError("production document compilation requires apply-now")
        with self._connect() as connection:
            parent = connection.execute(
                """SELECT strategy.job_key,job.title,job.company,job.url,
                          job.payload_json,job.payload_hash
                   FROM application_strategies strategy
                   JOIN pipeline_jobs job ON job.job_key=strategy.job_key
                   WHERE strategy.strategy_id=?""",
                (strategy.strategy_id,),
            ).fetchone()
            if parent is None:
                raise ValueError("strategy vacancy identity is unavailable")
            try:
                payload = json.loads(str(parent["payload_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("strategy vacancy payload is not valid JSON") from exc
            payload_hash = hashlib.sha256(
                str(parent["payload_json"]).encode()
            ).hexdigest()
            if (
                not isinstance(payload, dict)
                or canonical_json(payload) != str(parent["payload_json"])
                or payload_hash != str(parent["payload_hash"])
                or str(payload.get("job_title") or "") != str(parent["title"])
                or str(payload.get("company") or "") != str(parent["company"])
            ):
                raise ValueError("strategy vacancy identity is inconsistent")
            self._contact(connection, contact, as_of)
            job_key = str(parent["job_key"])
            candidate_cache: dict[tuple[str, int, str, int], tuple[str, str]] = {}
            employer_cache: dict[str, tuple[str, str]] = {}
            facts: list[FactualSentence] = []
            claim_type_by_sentence: dict[str, str] = {}
            for element in strategy.elements:
                if element.kind in {
                    "cv_emphasis",
                    "cover_letter_argument",
                    "structured_answer",
                }:
                    if (
                        element.kind == "structured_answer"
                        and element.requirement_id not in question_rows
                    ):
                        continue
                    cache_key = (
                        element.candidate_claim_id,
                        element.candidate_claim_version,
                        element.candidate_evidence_id,
                        element.candidate_evidence_version,
                    )
                    if cache_key not in candidate_cache:
                        candidate_cache[cache_key] = self._candidate_statement(
                            connection,
                            element,
                            as_of,
                        )
                    text, claim_type = candidate_cache[cache_key]
                    document_kind = {
                        "cv_emphasis": "cv",
                        "cover_letter_argument": "cover_letter",
                        "structured_answer": "answer",
                    }[element.kind]
                    sentence = self._sentence(
                        element,
                        text=text,
                        fact_kind="candidate",
                        document_kind=document_kind,
                    )
                    facts.append(sentence)
                    claim_type_by_sentence[sentence.sentence_id] = claim_type
                elif element.kind == "employer_hook":
                    if element.employer_research_claim_id not in employer_cache:
                        employer_cache[element.employer_research_claim_id] = (
                            self._employer_statement(
                                connection,
                                job_key=job_key,
                                element=element,
                            )
                        )
                    text, claim_json = employer_cache[
                        element.employer_research_claim_id
                    ]
                    facts.append(
                        self._sentence(
                            element,
                            text=text,
                            fact_kind="employer",
                            document_kind="cover_letter",
                            employer_fact_json=claim_json,
                        )
                    )

        cv_facts = tuple(row for row in facts if row.document_kind == "cv")
        letter_candidate = tuple(
            row
            for row in facts
            if row.document_kind == "cover_letter" and row.fact_kind == "candidate"
        )
        letter_employer = tuple(
            row
            for row in facts
            if row.document_kind == "cover_letter" and row.fact_kind == "employer"
        )
        answer_facts = {
            row.authority.requirement_id: row
            for row in facts
            if row.document_kind == "answer"
        }
        if not cv_facts or not letter_candidate or not letter_employer:
            raise ValueError("strategy does not contain complete document authority")

        cv_slot = self._slot("cv", "summary-lead", "Relevant evidence")
        letter_open = self._slot(
            "cover_letter",
            "salutation",
            "Dear Hiring Manager",
        )
        letter_close = self._slot(
            "cover_letter",
            "signoff",
            "Kind regards",
        )
        slots: list[StyleSlot] = [cv_slot, letter_open, letter_close]
        education = tuple(
            row.sentence_id
            for row in cv_facts
            if claim_type_by_sentence.get(row.sentence_id) == "education"
        )
        capabilities = tuple(
            row.sentence_id
            for row in cv_facts
            if claim_type_by_sentence.get(row.sentence_id)
            in {"skill", "capability", "certification"}
        )
        used_special = set((*education, *capabilities))
        projects = tuple(
            row.sentence_id for row in cv_facts if row.sentence_id not in used_special
        )
        if cv_layout == "four_section":
            summary_id = (
                projects[0]
                if projects
                else capabilities[0]
                if capabilities
                else education[0]
            )
            cv_sections: list[DocumentSection] = [
                DocumentSection(
                    "Professional Summary",
                    (summary_id,),
                    (cv_slot.slot_id,),
                )
            ]
            if capabilities:
                cv_sections.append(DocumentSection("Core Capabilities", capabilities))
            if projects:
                cv_sections.append(DocumentSection("Projects", projects))
            if education:
                cv_sections.append(DocumentSection("Education", education))
        else:
            experience = projects or tuple(row.sentence_id for row in cv_facts)
            cv_sections = [
                DocumentSection(
                    "Professional Summary",
                    (cv_facts[0].sentence_id,),
                    (cv_slot.slot_id,),
                )
            ]
            if education:
                cv_sections.append(DocumentSection("Education", education))
            cv_sections.append(DocumentSection("Experience", experience))
            if capabilities:
                cv_sections.append(DocumentSection("Skills", capabilities))

        answers: list[StructuredAnswer] = []
        for requirement_id, (question_id, question_text) in sorted(
            question_rows.items()
        ):
            fact = answer_facts.get(requirement_id)
            if fact is None:
                raise ValueError("portal question lacks structured-answer authority")
            slot = self._slot(
                "answer",
                f"answer:{question_id}",
                "A relevant example follows.",
            )
            slots.append(slot)
            answers.append(
                StructuredAnswer(
                    question_id,
                    question_text,
                    (fact.sentence_id,),
                    (slot.slot_id,),
                )
            )
        return compile_application_source(
            strategy=strategy,
            job_key=job_key,
            role_title=str(parent["title"]),
            company_name=str(parent["company"]),
            vacancy_source_identity=(f"vacancy:{job_key}:{parent['payload_hash']}"),
            vacancy_sha256=str(parent["payload_hash"]),
            contact=contact,
            facts=facts,
            style_slots=slots,
            cv_sections=cv_sections,
            letter_sections=(
                DocumentSection(
                    "Opening",
                    (),
                    (letter_open.slot_id,),
                ),
                DocumentSection(
                    "Evidence Match",
                    tuple(row.sentence_id for row in letter_candidate),
                ),
                DocumentSection(
                    "Company Fit",
                    tuple(row.sentence_id for row in letter_employer),
                ),
                DocumentSection(
                    "Close",
                    (),
                    (letter_close.slot_id,),
                ),
            ),
            answers=answers,
        )
