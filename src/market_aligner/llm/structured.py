"""Deterministic extraction and evidence alignment for structured listings.

This is the non-probabilistic counterpart to the bounded semantic gateway. Every
vacancy fact is selected by an explicit RFC 6901 pointer into retained public
JSON bytes. Evidence aligns only when the complete normalised requirement text
occurs in an approved, content-bound claim. Missing facts are never guessed.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from market_aligner.applications.canonical import (
    MAX_WIRE_BYTES,
    ContractValidationError,
    require_exact_keys,
    require_nonempty_string,
    require_timestamp,
    validate_strings,
)
from market_aligner.assessment.geography import LocationFacts
from market_aligner.collectors.evidence import bind_public_listing
from market_aligner.domain.contracts import RawPosting
from market_aligner.profiler.schema import EvidenceItem

from .contracts import (
    EvidenceAlignment,
    EvidenceMatch,
    LLMReceipt,
    SemanticVacancyExtraction,
)


EXTRACTION_ALGORITHM = "market-aligner.explicit-json-pointer-extraction.v1"
ALIGNMENT_ALGORITHM = "market-aligner.exact-approved-claim-alignment.v1"

PROJECTION_FIELDS = frozenset(
    {
        "company",
        "contract_type",
        "description",
        "expires_at",
        "location",
        "minimum_years_experience",
        "posted_at",
        "preferred_qualifications",
        "preferred_skills",
        "required_qualifications",
        "required_residence",
        "required_skills",
        "requirements",
        "responsibilities",
        "seniority",
        "sponsorship_available",
        "title",
        "work_authorisation",
    }
)
_LOCATION_FIELDS = {
    "country_code",
    "locality",
    "raw_text",
    "region",
    "work_mode",
}
_POINTER = re.compile(r"^(?:/(?:[^~/]|~[01])*)+$")


def _reject_constant(value: str) -> Any:
    raise ContractValidationError(f"non-finite listing number is forbidden: {value}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractValidationError(f"duplicate public-listing JSON key: {key}")
        result[key] = value
    return result


def _public_json(raw: RawPosting) -> tuple[Mapping[str, Any], bytes]:
    if not raw.public_content_base64:
        raise ContractValidationError(
            "structured extraction requires retained public bytes"
        )
    if raw.content_sha256 is None:
        raise ContractValidationError(
            "structured extraction requires a bound content digest"
        )
    _bound, exact = bind_public_listing(raw)
    if not exact or len(exact) > MAX_WIRE_BYTES:
        raise ContractValidationError(
            "structured public listing has an invalid byte length"
        )
    try:
        value = json.loads(
            exact.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractValidationError(
            "structured public listing is not valid JSON"
        ) from exc
    if not isinstance(value, Mapping):
        raise ContractValidationError(
            "structured public listing root must be an object"
        )
    validate_strings(value, require_nfc=False, label="public_listing")
    return value, exact


def _pointer_value(document: Any, pointer: str, label: str) -> Any:
    if not isinstance(pointer, str) or _POINTER.fullmatch(pointer) is None:
        raise ContractValidationError(
            f"{label} must be a non-root RFC 6901 JSON pointer"
        )
    value = document
    for encoded in pointer.split("/")[1:]:
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(value, Mapping):
            if token not in value:
                raise ContractValidationError(
                    f"{label} does not resolve in the public listing"
                )
            value = value[token]
        elif isinstance(value, list):
            if not token.isdigit() or (token != "0" and token.startswith("0")):
                raise ContractValidationError(f"{label} has an invalid array index")
            index = int(token)
            if index >= len(value):
                raise ContractValidationError(f"{label} array index is out of range")
            value = value[index]
        else:
            raise ContractValidationError(
                f"{label} traverses a scalar public-listing value"
            )
    return value


def _text(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    result = require_nonempty_string(value, label)
    if result != result.strip():
        raise ContractValidationError(f"{label} must be trimmed")
    return result


def _possibly_empty_text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ContractValidationError(f"{label} must be a string")
    if value != value.strip():
        raise ContractValidationError(f"{label} must be trimmed")
    return value


def _strings(value: Any, label: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ContractValidationError(f"{label} must be an array of strings")
    result = tuple(_text(item, f"{label}[]") for item in value)
    if len(set(result)) != len(result):
        raise ContractValidationError(f"{label} must not repeat values")
    return result  # type: ignore[return-value]


@dataclass(frozen=True)
class StructuredVacancyFacts:
    extraction: SemanticVacancyExtraction
    extraction_receipt: LLMReceipt
    location: LocationFacts
    requirements: tuple[str, ...]
    posted_at: str | None
    expires_at: str | None
    required_residence: str | None
    sponsorship_available: bool | None
    minimum_years_experience: float | None


def extract_structured_vacancy(
    raw: RawPosting,
    pointers: Mapping[str, Any],
    *,
    receipt_inputs: Mapping[str, Any],
) -> StructuredVacancyFacts:
    """Project explicit public facts and bind the output to the retained capture."""

    require_exact_keys(pointers, PROJECTION_FIELDS, "vacancy projection")
    document, _exact = _public_json(raw)
    resolved = {
        name: _pointer_value(document, pointers[name], f"vacancy projection {name}")
        for name in sorted(PROJECTION_FIELDS)
    }
    location_value = resolved["location"]
    if not isinstance(location_value, Mapping):
        raise ContractValidationError("projected location must be an object")
    require_exact_keys(location_value, _LOCATION_FIELDS, "projected location")
    location = LocationFacts(
        country_code=_text(location_value["country_code"], "location country_code"),
        locality=_possibly_empty_text(location_value["locality"], "location locality"),
        region=_possibly_empty_text(location_value["region"], "location region"),
        raw_text=_text(location_value["raw_text"], "location raw_text"),
        work_mode=_text(location_value["work_mode"], "location work_mode"),
        evidence_basis="explicit",
        source_pointer=f"json:{pointers['location']}",
    )
    requirements = _strings(resolved["requirements"], "requirements", nonempty=True)
    posted_at = _text(resolved["posted_at"], "posted_at", nullable=True)
    expires_at = _text(resolved["expires_at"], "expires_at", nullable=True)
    if posted_at is not None:
        require_timestamp(posted_at, "posted_at", strict_profile=True)
    if expires_at is not None:
        require_timestamp(expires_at, "expires_at", strict_profile=True)
    required_residence = _text(
        resolved["required_residence"], "required_residence", nullable=True
    )
    if required_residence is not None and (
        len(required_residence) != 2 or required_residence.upper() != required_residence
    ):
        raise ContractValidationError(
            "required_residence must be an uppercase country code"
        )
    sponsorship = resolved["sponsorship_available"]
    if sponsorship is not None and not isinstance(sponsorship, bool):
        raise ContractValidationError(
            "sponsorship_available must be true, false, or null"
        )
    years = resolved["minimum_years_experience"]
    if years is not None and (
        isinstance(years, bool)
        or not isinstance(years, (int, float))
        or not math.isfinite(years)
        or years < 0
    ):
        raise ContractValidationError(
            "minimum_years_experience must be a non-negative number or null"
        )
    require_timestamp(raw.fetched_at, "raw fetched_at", strict_profile=True)
    work_authorisation = _strings(resolved["work_authorisation"], "work_authorisation")
    if any(
        len(country_code) != 2 or country_code.upper() != country_code
        for country_code in work_authorisation
    ):
        raise ContractValidationError(
            "work_authorisation entries must be uppercase two-letter country codes"
        )
    work_authorisation = tuple(sorted(work_authorisation))
    extraction = SemanticVacancyExtraction(
        source_content_sha256=raw.content_sha256,
        title=_text(resolved["title"], "title"),
        company=_text(resolved["company"], "company"),
        location=location.raw_text,
        description=_text(resolved["description"], "description"),
        responsibilities=_strings(resolved["responsibilities"], "responsibilities"),
        required_skills=_strings(resolved["required_skills"], "required_skills"),
        preferred_skills=_strings(resolved["preferred_skills"], "preferred_skills"),
        required_qualifications=_strings(
            resolved["required_qualifications"], "required_qualifications"
        ),
        preferred_qualifications=_strings(
            resolved["preferred_qualifications"], "preferred_qualifications"
        ),
        work_authorisation=work_authorisation,
        contract_type=_text(resolved["contract_type"], "contract_type"),
        seniority=_text(resolved["seniority"], "seniority"),
        remote_policy=location.work_mode,
        extraction_confidence=1.0,
    )
    receipt = LLMReceipt.bind(
        receipt_id=f"extract-{raw.content_sha256}",
        task="semantic_vacancy_extraction",
        model=EXTRACTION_ALGORITHM,
        prompt_version=EXTRACTION_ALGORITHM,
        inputs={
            "caller_inputs": dict(receipt_inputs),
            "pointers": {name: pointers[name] for name in sorted(PROJECTION_FIELDS)},
            "source_content_sha256": raw.content_sha256,
            "source_url": raw.url,
        },
        output=extraction,
        created_at=raw.fetched_at,
    )
    return StructuredVacancyFacts(
        extraction=extraction,
        extraction_receipt=receipt,
        location=location,
        requirements=requirements,
        posted_at=posted_at,
        expires_at=expires_at,
        required_residence=required_residence,
        sponsorship_available=sponsorship,
        minimum_years_experience=None if years is None else float(years),
    )


def _normalise(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", value).casefold().split())


def align_approved_evidence(
    *,
    profile_id: str,
    profile_version: str,
    job_key: str,
    requirements: Sequence[str],
    evidence: Mapping[str, EvidenceItem],
    selected_evidence_ids: Sequence[str],
    receipt_inputs: Mapping[str, Any],
    created_at: str,
) -> tuple[EvidenceAlignment, LLMReceipt]:
    """Align only complete lexical matches in approved, content-bound claims."""

    requirement_values = tuple(requirements)
    if not requirement_values:
        raise ContractValidationError(
            "alignment requires explicit vacancy requirements"
        )
    selected = tuple(selected_evidence_ids)
    if len(selected) != len(set(selected)):
        raise ContractValidationError("selected evidence ids must be unique")
    unknown = sorted(set(selected) - set(evidence))
    if unknown:
        raise ContractValidationError(f"selected evidence ids are unknown: {unknown}")
    require_timestamp(created_at, "alignment created_at", strict_profile=True)
    matches: list[EvidenceMatch] = []
    missing: list[str] = []
    strengths: list[float] = []
    for requirement in requirement_values:
        needle = _normalise(requirement)
        cited = tuple(
            evidence_id
            for evidence_id in selected
            if evidence[evidence_id].status in {"verified", "explicit"}
            and evidence[evidence_id].content_sha256
            and needle in _normalise(evidence[evidence_id].claim)
        )
        if not cited:
            missing.append(requirement)
            strengths.append(0.0)
            continue
        strength = float(max(evidence[evidence_id].confidence for evidence_id in cited))
        strengths.append(strength)
        matches.append(
            EvidenceMatch(
                requirement=requirement,
                evidence_ids=cited,
                strength=strength,
                rationale=(
                    "Exact normalised requirement text occurs in approved, "
                    "content-bound evidence claims."
                ),
            )
        )
    alignment = EvidenceAlignment(
        profile_id=profile_id,
        profile_version=profile_version,
        job_key=job_key,
        matches=tuple(matches),
        missing_requirements=tuple(missing),
        technical_alignment=float(sum(strengths) / len(strengths)),
        evidence_match=float(len(matches) / len(requirement_values)),
        confidence=1.0,
        unknowns=tuple("unmatched_requirement" for _value in missing[:1]),
    )
    receipt = LLMReceipt.bind(
        receipt_id=f"align-{job_key[4:]}",
        task="evidence_alignment",
        model=ALIGNMENT_ALGORITHM,
        prompt_version=ALIGNMENT_ALGORITHM,
        inputs={
            "caller_inputs": dict(receipt_inputs),
            "job_key": job_key,
            "profile_id": profile_id,
            "profile_version": profile_version,
            "requirements": list(requirement_values),
            "selected_evidence": [
                asdict(evidence[evidence_id]) for evidence_id in selected
            ],
        },
        output=alignment,
        created_at=created_at,
    )
    return alignment, receipt
