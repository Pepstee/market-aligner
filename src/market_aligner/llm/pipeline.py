"""Receipt verification and deterministic acceptance of LLM-produced data."""

from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from market_aligner.applications.canonical import (
    ContractValidationError,
    PROFILE_ID_PATTERN,
    canonical_json_bytes,
    digest_bytes,
    require_nonempty_string,
    require_pattern,
    require_sha256,
)
from market_aligner.collectors.evidence import public_listing_bytes

from market_aligner.domain.contracts import RawPosting, Vacancy
from market_aligner.profiler.schema import EvidenceItem
from market_aligner.state.vacancies import raw_posting_content_sha256

from .contracts import (
    EvidenceAlignment,
    LLMReceipt,
    SemanticVacancyExtraction,
    VACANCY_ELIGIBILITY_FACTS_VERSION,
    VACANCY_ELIGIBILITY_FACTS_TASK,
    VacancyEligibilityFacts,
    canonical_hash,
)


def accept_extraction(
    raw: RawPosting,
    extraction: SemanticVacancyExtraction,
    receipt: LLMReceipt,
) -> Vacancy:
    if not raw.content_sha256:
        raise ValueError("raw posting requires a content hash before semantic extraction")
    if extraction.source_content_sha256 != raw.content_sha256:
        raise ValueError("extraction is bound to a different raw posting snapshot")
    if receipt.task != "semantic_vacancy_extraction":
        raise ValueError("wrong LLM receipt task")
    if receipt.output_sha256 != canonical_hash(asdict(extraction)):
        raise ValueError("LLM extraction output hash does not match its receipt")
    return Vacancy(
        board=raw.board,
        job_id=raw.job_id,
        url=raw.url,
        title=extraction.title,
        company=extraction.company,
        location=extraction.location,
        description=extraction.description,
        responsibilities=extraction.responsibilities,
        required_skills=extraction.required_skills,
        preferred_skills=extraction.preferred_skills,
        required_qualifications=extraction.required_qualifications,
        preferred_qualifications=extraction.preferred_qualifications,
        work_authorisation=extraction.work_authorisation,
        contract_type=extraction.contract_type,
        remote_policy=extraction.remote_policy,
        seniority=extraction.seniority,
        extraction_confidence=extraction.extraction_confidence,
        extraction_receipt_id=receipt.receipt_id,
        source_content_sha256=raw.content_sha256,
        extra={"unknown_fields": extraction.unknown_fields},
    )


def extraction_input(raw: RawPosting) -> dict[str, Any]:
    """Return the exact public-only LLM input identity for one retained snapshot."""

    if not raw.content_sha256:
        raise ContractValidationError("raw posting requires an exact public-content digest")
    require_sha256(raw.content_sha256, "raw posting content_sha256")
    return {
        "adapter": raw.board,
        "canonical_url": raw.url,
        "content_sha256": raw.content_sha256,
        "legacy_job_key": raw.key,
        "schema_version": "market-aligner.semantic-extraction-input.v1",
        "source_job_id": raw.job_id,
    }


def accept_subject_bound_extraction(
    raw: RawPosting,
    extraction: SemanticVacancyExtraction,
    receipt: LLMReceipt,
) -> Vacancy:
    """Accept an extraction only when its receipt binds the exact retained capture."""

    expected = extraction_input(raw)
    if receipt.input_sha256 != canonical_hash(expected):
        raise ContractValidationError("LLM extraction receipt input identity differs")
    return accept_extraction(raw, extraction, receipt)


def verified_eligibility_capture(raw: RawPosting) -> tuple[str, bytes]:
    """Validate collector identity and return privacy-checked public capture bytes."""
    exact = public_listing_bytes(raw)
    digest = raw_posting_content_sha256(raw)
    if raw.content_sha256 is not None and raw.content_sha256 != digest:
        raise ContractValidationError(
            "declared collector digest differs from the exact posting source"
        )
    return digest, exact


def vacancy_eligibility_input(raw: RawPosting) -> dict[str, Any]:
    """Bind collector identity and distinct public-capture bytes in the task input."""
    collector_digest, exact = verified_eligibility_capture(raw)
    return {
        "adapter": raw.board,
        "canonical_url": raw.url,
        "content_sha256": collector_digest,
        "public_capture_sha256": digest_bytes(exact),
        "raw_json": raw.raw_json,
        "raw_text": raw.raw_text,
        "schema_version": VACANCY_ELIGIBILITY_FACTS_VERSION,
        "source_job_id": raw.job_id,
    }


def _public_capture_text(value: object, *, key: str | None = None) -> tuple[str, ...]:
    if key is not None and key.casefold() in {
        "metadata",
        "metadata_record",
        "headers",
        "canonical_url",
        "content_sha256",
        "fetched_at",
        "job_id",
        "source_job_id",
    }:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        return tuple(
            fragment
            for child_key, child in value.items()
            if isinstance(child_key, str)
            for fragment in _public_capture_text(child, key=child_key)
        )
    if isinstance(value, (list, tuple)):
        return tuple(
            fragment
            for child in value
            for fragment in _public_capture_text(child)
        )
    return ()


_SPONSORSHIP_PATTERNS = {
    True: (
        re.compile(r"visa sponsorship is available\.?"),
        re.compile(r"we offer visa sponsorship\.?"),
        re.compile(r"we sponsor visas[.!]?"),
        re.compile(r"we do sponsor visas[.!]?"),
    ),
    False: (
        re.compile(r"visa sponsorship is not available\.?"),
        re.compile(r"we do not sponsor visas\.?"),
    ),
}
_MINIMUM_YEARS_PATTERNS = (
    re.compile(r"at least (?P<num>\d+(?:\.\d+)?) years of experience are required\.?"),
    re.compile(r"minimum (?P<num>\d+(?:\.\d+)?) years of experience\.?"),
    re.compile(
        r"a minimum of (?P<num>\d+(?:\.\d+)?) years of experience is required\.?"
    ),
)
_CONTRACT_QUOTE_PATTERNS = {
    "apprenticeship": (re.compile(r"this is an apprenticeship\.?"),),
    "contract": (re.compile(r"this is a contract position\.?"),),
    "freelance": (re.compile(r"this is a freelance role\.?"),),
    "full_time": (re.compile(r"this is a full-time role\.?"),),
    "internship": (re.compile(r"this is an internship\.?"),),
    "part_time": (re.compile(r"this is a part-time role\.?"),),
    "permanent": (re.compile(r"this is a permanent position\.?"),),
    "temporary": (re.compile(r"this is a temporary position\.?"),),
}


def quote_supports_eligibility(field: str, value: object, quote: object) -> bool:
    """Recognize only narrow, complete source statements for sensitive facts."""
    if not isinstance(field, str) or not isinstance(quote, str):
        return False
    normalized = " ".join(quote.split()).lower()
    if field == "sponsorship_available":
        if type(value) is not bool:
            return False
        return any(pattern.fullmatch(normalized) for pattern in _SPONSORSHIP_PATTERNS[value])
    if field == "minimum_years_experience":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        try:
            if not math.isfinite(value):
                return False
            expected = float(value)
        except OverflowError:
            return False
        if value < 0:
            return False
        return any(
            match is not None and float(match.group("num")) == expected
            for match in (
                pattern.fullmatch(normalized)
                for pattern in _MINIMUM_YEARS_PATTERNS
            )
        )
    if field == "contract_type" and isinstance(value, str):
        patterns = _CONTRACT_QUOTE_PATTERNS.get(value)
        return bool(patterns and any(pattern.fullmatch(normalized) for pattern in patterns))
    return False


def accept_vacancy_eligibility_facts(
    raw: RawPosting,
    facts: VacancyEligibilityFacts,
    receipt: LLMReceipt,
    *,
    inputs: Mapping[str, Any],
) -> VacancyEligibilityFacts:
    """Accept typed vacancy facts only with exact-source quote evidence."""
    collector_digest, exact = verified_eligibility_capture(raw)
    if facts.source_content_sha256 != collector_digest:
        raise ContractValidationError(
            "vacancy eligibility facts bind a different public capture"
        )
    if receipt.task != VACANCY_ELIGIBILITY_FACTS_TASK:
        raise ContractValidationError("vacancy eligibility receipt has the wrong task")
    expected_inputs = vacancy_eligibility_input(raw)
    if canonical_hash(dict(inputs)) != canonical_hash(expected_inputs):
        raise ContractValidationError("vacancy eligibility input differs from exact public source")
    if receipt.input_sha256 != canonical_hash(expected_inputs):
        raise ContractValidationError("vacancy eligibility receipt input differs")
    if receipt.output_sha256 != canonical_hash(asdict(facts)):
        raise ContractValidationError("vacancy eligibility receipt output differs")
    try:
        decoded = json.loads(exact.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = exact.decode("utf-8", errors="strict")
    if isinstance(decoded, Mapping) and decoded.get("schema_version") == (
        "market-aligner.public-listing-capture.v1"
    ):
        source_text = (
            *_public_capture_text(decoded.get("raw_text")),
            *_public_capture_text(decoded.get("raw_json")),
        )
    else:
        source_text = _public_capture_text(decoded)
    for evidence in facts.source_evidence:
        try:
            evidence.quote.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ContractValidationError(
                "vacancy eligibility quote is not valid UTF-8"
            ) from exc
        if not any(evidence.quote in fragment for fragment in source_text):
            raise ContractValidationError(
                "vacancy eligibility quote is absent from exact public content"
            )
        folded = evidence.quote.casefold()
        value = getattr(facts, evidence.field)
        if evidence.field in {"work_jurisdiction", "required_residence"}:
            if not re.search(
                rf"(?<![A-Za-z]){re.escape(value)}(?![A-Za-z])",
                evidence.quote,
                flags=re.ASCII,
            ):
                raise ContractValidationError(
                    "vacancy eligibility country code is absent from its quote"
                )
            if evidence.field == "required_residence" and not any(
                token in folded for token in ("reside", "resident", "residency")
            ):
                raise ContractValidationError(
                    "residence fact quote lacks an explicit residence term"
                )
        elif evidence.field in {
            "sponsorship_available",
            "minimum_years_experience",
            "contract_type",
        }:
            if not quote_supports_eligibility(evidence.field, value, evidence.quote):
                raise ContractValidationError(
                    "eligibility fact is not supported by the exact quote grammar"
                )
    return facts


@dataclass(frozen=True)
class EvidenceAlignmentSubject:
    """Complete immutable identity for an evidence-alignment judgement."""

    profile_id: str
    profile_version: str
    candidate_intent_sha256: str
    role_track_id: str
    job_key: str
    vacancy_snapshot_sha256: str
    requirements_sha256: str
    evidence_ledger_sha256: str
    extraction_output_sha256: str
    extraction_receipt_sha256: str

    def __post_init__(self) -> None:
        require_pattern(self.profile_id, PROFILE_ID_PATTERN, "alignment subject profile_id")
        for name in ("profile_version", "role_track_id", "job_key"):
            require_nonempty_string(getattr(self, name), f"alignment subject {name}")
        for name in (
            "candidate_intent_sha256",
            "vacancy_snapshot_sha256",
            "requirements_sha256",
            "evidence_ledger_sha256",
            "extraction_output_sha256",
            "extraction_receipt_sha256",
        ):
            require_sha256(getattr(self, name), f"alignment subject {name}")


def alignment_input(
    subject: EvidenceAlignmentSubject,
    *,
    requirements: Sequence[str],
    evidence: Mapping[str, EvidenceItem],
    selected_evidence_ids: Sequence[str],
) -> dict[str, Any]:
    """Build a bounded selected-track-only input whose hash the receipt must bind."""

    selected = tuple(selected_evidence_ids)
    if not selected or len(set(selected)) != len(selected):
        raise ContractValidationError("selected alignment evidence IDs must be unique and non-empty")
    if list(selected) != sorted(selected):
        raise ContractValidationError("selected alignment evidence IDs must be sorted")
    requirement_values = tuple(requirements)
    if not requirement_values or any(
        not isinstance(value, str) or not value for value in requirement_values
    ):
        raise ContractValidationError("alignment requirements must be non-empty strings")
    if len(set(requirement_values)) != len(requirement_values):
        raise ContractValidationError("alignment requirements must be unique")
    rows: list[dict[str, Any]] = []
    for evidence_id in selected:
        item = evidence.get(evidence_id)
        if item is None:
            raise ContractValidationError("selected track cites absent evidence")
        if item.status not in {"verified", "explicit"} or not item.content_sha256:
            raise ContractValidationError("selected track evidence is not approved and content-bound")
        require_sha256(item.content_sha256, f"evidence {evidence_id} content_sha256")
        rows.append(
            {
                "content_sha256": item.content_sha256,
                "evidence_id": item.evidence_id,
                "status": item.status,
            }
        )
    return {
        "evidence": rows,
        "requirements": list(requirement_values),
        "schema_version": "market-aligner.evidence-alignment-input.v1",
        "subject": asdict(subject),
    }


def accept_subject_bound_alignment(
    alignment: EvidenceAlignment,
    evidence: Mapping[str, EvidenceItem],
    receipt: LLMReceipt,
    *,
    subject: EvidenceAlignmentSubject,
    requirements: Sequence[str],
    selected_evidence_ids: Sequence[str],
) -> EvidenceAlignment:
    """Reject profile/track/snapshot/ledger/requirement or receipt substitution."""

    if alignment.profile_id != subject.profile_id:
        raise ContractValidationError("alignment belongs to another profile")
    if alignment.profile_version != subject.profile_version:
        raise ContractValidationError("alignment belongs to another profile revision")
    if alignment.job_key != subject.job_key:
        raise ContractValidationError("alignment belongs to another job")
    expected_input = alignment_input(
        subject,
        requirements=requirements,
        evidence=evidence,
        selected_evidence_ids=selected_evidence_ids,
    )
    if receipt.input_sha256 != canonical_hash(expected_input):
        raise ContractValidationError("LLM alignment receipt input identity differs")
    permitted = set(selected_evidence_ids)
    cited = {
        evidence_id
        for match in alignment.matches
        for evidence_id in match.evidence_ids
    }
    if not cited <= permitted:
        raise ContractValidationError("alignment cites evidence outside the selected role track")
    known_requirements = set(requirements)
    if any(match.requirement not in known_requirements for match in alignment.matches):
        raise ContractValidationError("alignment cites a requirement outside the accepted projection")
    if any(value not in known_requirements for value in alignment.missing_requirements):
        raise ContractValidationError("alignment missing-requirement set is subject-swapped")
    return accept_alignment(alignment, dict(evidence), receipt)


def llm_object_sha256(value: Any) -> str:
    """Canonical identity used by the operational corridor for LLM objects/receipts."""

    payload = asdict(value) if hasattr(value, "__dataclass_fields__") else value
    return digest_bytes(canonical_json_bytes(payload))


def accept_alignment(
    alignment: EvidenceAlignment,
    evidence: dict[str, EvidenceItem],
    receipt: LLMReceipt,
) -> EvidenceAlignment:
    alignment.validate_evidence_ids(set(evidence))
    if receipt.task != "evidence_alignment":
        raise ValueError("wrong LLM receipt task")
    if receipt.output_sha256 != canonical_hash(asdict(alignment)):
        raise ValueError("LLM alignment output hash does not match its receipt")
    return alignment
