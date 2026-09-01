"""Deterministic geographic preference classification from normalized vacancy facts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, replace
from typing import Any, Iterable, Mapping, Sequence

from market_aligner.applications.canonical import (
    ContractValidationError,
    canonical_json_bytes,
    digest_bytes,
    require_probability,
)
from market_aligner.assessment.eligibility import EligibilityDecision
from market_aligner.assessment.scoring import ScoreResult


PREFERENCE_CATEGORIES = (
    "uk_remote",
    "uk_hybrid",
    "uk_onsite",
    "romania_remote",
    "eu_remote",
)


@dataclass(frozen=True)
class GeographicPreferencePolicy:
    order: tuple[str, ...] = PREFERENCE_CATEGORIES
    uk_markers: tuple[str, ...] = (
        "united kingdom", "great britain", "uk", "england", "scotland", "wales",
        "northern ireland", "london", "manchester", "birmingham", "wolverhampton",
        "bristol", "leeds", "liverpool", "glasgow", "edinburgh", "cardiff",
        "belfast", "oxford", "cambridge",
    )
    romania_markers: tuple[str, ...] = ("romania", "bucharest", "cluj", "iasi", "timisoara")
    eu_markers: tuple[str, ...] = (
        "european union", "europe", "eu", "eea", "emea",
    )
    remote_markers: tuple[str, ...] = ("remote", "distributed", "work from home")
    hybrid_markers: tuple[str, ...] = ("hybrid",)
    onsite_markers: tuple[str, ...] = ("on site", "onsite", "office based")

    def __post_init__(self) -> None:
        if len(self.order) != len(set(self.order)) or set(self.order) != set(PREFERENCE_CATEGORIES):
            raise ValueError("geographic preference order must contain every supported category once")
        for name in (
            "uk_markers", "romania_markers", "eu_markers", "remote_markers",
            "hybrid_markers", "onsite_markers",
        ):
            values = getattr(self, name)
            if not values or any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f"{name} must contain non-empty strings")

    @property
    def policy_hash(self) -> str:
        return _hash(asdict(self))

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, object] | None,
        *,
        default: "GeographicPreferencePolicy | None" = None,
    ) -> "GeographicPreferencePolicy":
        policy = default or cls()
        if value is None:
            return policy
        allowed = set(asdict(policy))
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown geographic preference settings: {sorted(unknown)}")
        updates: dict[str, tuple[str, ...]] = {}
        for key, raw in value.items():
            if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
                raise ValueError(f"geographic preference {key} must be a list")
            updates[key] = tuple(str(item).strip() for item in raw)
        return replace(policy, **updates)


@dataclass(frozen=True)
class GeographicPreference:
    category: str
    rank: int
    facts_sha256: str
    policy_sha256: str


def classify_geographic_preference(
    *,
    location: str,
    remote_policy: str | None,
    policy: GeographicPreferencePolicy,
) -> GeographicPreference:
    facts = {"location": location, "remote_policy": remote_policy}
    text = _normalise(" ".join(part for part in (location, remote_policy or "") if part))
    region = "other"
    if _matches(text, policy.uk_markers):
        region = "uk"
    elif _matches(text, policy.romania_markers):
        region = "romania"
    elif _matches(text, policy.eu_markers):
        region = "eu"

    mode = "unknown"
    if _matches(text, policy.hybrid_markers):
        mode = "hybrid"
    elif _matches(text, policy.onsite_markers):
        mode = "onsite"
    elif _matches(text, policy.remote_markers):
        mode = "remote"

    candidate = f"{region}_{mode}"
    category = candidate if candidate in policy.order else "unknown_other"
    rank = policy.order.index(category) if category in policy.order else len(policy.order)
    return GeographicPreference(category, rank, _hash(facts), policy.policy_hash)


def _normalise(value: str) -> str:
    return " " + re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip() + " "


def _matches(text: str, markers: Sequence[str]) -> bool:
    return any(_normalise(marker) in text for marker in markers)


def _hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


EU27_2026_08 = frozenset(
    "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split()
)
EU_REMOTE_COUNTRIES = EU27_2026_08 - {"RO"}
GEOGRAPHY_BUCKETS: Mapping[tuple[str, str], tuple[str, int]] = {
    ("GB", "remote"): ("UK_REMOTE", 1),
    ("GB", "hybrid"): ("UK_HYBRID", 2),
    ("GB", "onsite"): ("UK_ONSITE", 3),
    ("RO", "remote"): ("RO_REMOTE", 4),
}
RATIONALE_BY_BUCKET = {
    "UK_REMOTE": "geography_priority_uk_remote",
    "UK_HYBRID": "geography_priority_uk_hybrid",
    "UK_ONSITE": "geography_priority_uk_onsite",
    "RO_REMOTE": "geography_priority_ro_remote",
    "EU_REMOTE": "geography_priority_eu_remote",
}
_JSON_SOURCE_POINTER = re.compile(r"^json:(?:/(?:[^~/]|~[01])*)+$")
_TEXT_SOURCE_POINTER = re.compile(r"^text:bytes=(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$")


def _validate_source_pointer(value: str) -> None:
    """Require an inspectable JSON pointer or an end-exclusive public byte span."""

    if _JSON_SOURCE_POINTER.fullmatch(value) is not None:
        return
    text_match = _TEXT_SOURCE_POINTER.fullmatch(value)
    if text_match is not None and int(text_match.group(2)) > int(text_match.group(1)):
        return
    raise ContractValidationError(
        "location source_pointer must be json:/... or text:bytes=<start>-<end>"
    )


class SelectionBlocked(ContractValidationError):
    """A failed or unresolved hard gate prevents handoff emission."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LocationFacts:
    country_code: str
    locality: str
    region: str
    raw_text: str
    work_mode: str
    evidence_basis: str
    source_pointer: str

    def __post_init__(self) -> None:
        for name in (
            "country_code",
            "locality",
            "region",
            "raw_text",
            "work_mode",
            "evidence_basis",
            "source_pointer",
        ):
            if not isinstance(getattr(self, name), str):
                raise ContractValidationError(f"location {name} must be a string")
        if self.country_code == "UK":
            raise SelectionBlocked("location_country_invalid", "vacancy country UK must be GB")
        if len(self.country_code) != 2 or self.country_code.upper() != self.country_code:
            raise SelectionBlocked(
                "location_country_unknown", "selection requires a known uppercase two-letter country"
            )
        if self.work_mode not in {"remote", "hybrid", "onsite", "unknown"}:
            raise ContractValidationError("unsupported work mode")
        if self.evidence_basis != "explicit":
            raise SelectionBlocked(
                "work_mode_inferred", "selection requires explicit retained location/work-mode evidence"
            )
        if not self.raw_text or not self.source_pointer:
            raise SelectionBlocked(
                "location_evidence_missing", "location facts require retained text and source pointer"
            )
        _validate_source_pointer(self.source_pointer)

    def reference_payload(self, job_key: str) -> dict[str, Any]:
        return {
            "country_code": self.country_code,
            "evidence_basis": self.evidence_basis,
            "job_key": job_key,
            "locality": self.locality,
            "raw_text": self.raw_text,
            "region": self.region,
            "schema_version": "market-aligner.location-facts.v1",
            "source_pointer": self.source_pointer,
            "work_mode": self.work_mode,
        }

    def reference_bytes(self, job_key: str) -> bytes:
        return canonical_json_bytes(self.reference_payload(job_key))

    def reference_sha256(self, job_key: str) -> str:
        return digest_bytes(self.reference_bytes(job_key))


@dataclass(frozen=True)
class GeographyMatch:
    bucket: str
    priority_rank: int

    def __post_init__(self) -> None:
        expected = {
            "UK_REMOTE": 1,
            "UK_HYBRID": 2,
            "UK_ONSITE": 3,
            "RO_REMOTE": 4,
            "EU_REMOTE": 5,
        }
        if expected.get(self.bucket) != self.priority_rank:
            raise ContractValidationError("geography bucket and priority rank differ")


def classify_geography(facts: LocationFacts) -> GeographyMatch:
    if facts.work_mode == "unknown":
        raise SelectionBlocked("work_mode_unknown", "unknown work mode blocks selection")
    direct = GEOGRAPHY_BUCKETS.get((facts.country_code, facts.work_mode))
    if direct is not None:
        return GeographyMatch(*direct)
    if facts.country_code in EU_REMOTE_COUNTRIES and facts.work_mode == "remote":
        return GeographyMatch("EU_REMOTE", 5)
    if facts.country_code == "RO":
        raise SelectionBlocked(
            "romania_not_remote", "Romania is eligible only through the dedicated remote bucket"
        )
    raise SelectionBlocked(
        "geography_out_of_scope", "location/work-mode pair is outside the confirmed priority"
    )


@dataclass(frozen=True)
class SelectionPolicy:
    minimum_final: float
    minimum_fit: float
    minimum_opportunity: float
    dossier_required: bool
    maximum_vacancy_age_seconds: int
    maximum_dossier_age_seconds: int
    clock_skew_seconds: int

    def __post_init__(self) -> None:
        if not isinstance(self.dossier_required, bool):
            raise ContractValidationError("dossier_required must be a JSON boolean")
        require_probability(self.minimum_final, "minimum_final", strict_profile=True)
        require_probability(self.minimum_fit, "minimum_fit", strict_profile=True)
        require_probability(self.minimum_opportunity, "minimum_opportunity", strict_profile=True)
        for name in (
            "maximum_vacancy_age_seconds",
            "maximum_dossier_age_seconds",
            "clock_skew_seconds",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractValidationError(f"{name} must be a non-negative integer")

    def reference_payload(self) -> dict[str, Any]:
        return {
            "clock_skew_seconds": self.clock_skew_seconds,
            "dossier_required": self.dossier_required,
            "eu_set_version": "EU27_2026_08",
            "geography_priority": [
                {"bucket": "UK_REMOTE", "rank": 1},
                {"bucket": "UK_HYBRID", "rank": 2},
                {"bucket": "UK_ONSITE", "rank": 3},
                {"bucket": "RO_REMOTE", "rank": 4},
                {"bucket": "EU_REMOTE", "rank": 5},
            ],
            "maximum_dossier_age_seconds": self.maximum_dossier_age_seconds,
            "maximum_vacancy_age_seconds": self.maximum_vacancy_age_seconds,
            "minimum_final": self.minimum_final,
            "minimum_fit": self.minimum_fit,
            "minimum_opportunity": self.minimum_opportunity,
            "schema_version": "market-aligner.selection-policy.v1",
        }

    @property
    def sha256(self) -> str:
        return digest_bytes(canonical_json_bytes(self.reference_payload()))


@dataclass(frozen=True)
class SelectionDecision:
    geography_bucket: str
    geography_priority_rank: int
    rationale_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        GeographyMatch(self.geography_bucket, self.geography_priority_rank)
        if (
            not isinstance(self.rationale_codes, tuple)
            or not self.rationale_codes
            or any(not isinstance(value, str) or not value.strip() for value in self.rationale_codes)
            or tuple(sorted(set(self.rationale_codes))) != self.rationale_codes
        ):
            raise ContractValidationError(
                "selection rationale codes must be sorted unique non-empty strings"
            )

    @property
    def hard_gate_passed(self) -> bool:
        return True


def decide_selection(
    *,
    eligibility: EligibilityDecision,
    score: ScoreResult,
    geography: GeographyMatch,
    policy: SelectionPolicy,
    employer_dossier_sha256: str | None,
) -> SelectionDecision:
    if (
        eligibility.decision != "pass"
        or eligibility.reasons
        or eligibility.unknowns
    ):
        raise SelectionBlocked(
            "eligibility_not_passed", "failed or unresolved eligibility blocks selection"
        )
    final = score.final / 100.0
    if final < policy.minimum_final:
        raise SelectionBlocked("final_score_below_policy", "final score is below selection policy")
    if score.fit < policy.minimum_fit:
        raise SelectionBlocked("fit_below_policy", "fit is below selection policy")
    if score.opportunity < policy.minimum_opportunity:
        raise SelectionBlocked(
            "opportunity_below_policy", "opportunity is below selection policy"
        )
    if policy.dossier_required and employer_dossier_sha256 is None:
        raise SelectionBlocked("employer_dossier_required", "selection policy requires a dossier")
    rationale = tuple(
        sorted(
            {
                "hard_gates_passed",
                "selection_policy_passed",
                RATIONALE_BY_BUCKET[geography.bucket],
            }
        )
    )
    return SelectionDecision(geography.bucket, geography.priority_rank, rationale)


def selection_sort_key(
    geography_priority_rank: int,
    final_score: float,
    opportunity: float,
    job_key: str,
) -> tuple[int, float, float, str]:
    if geography_priority_rank not in {1, 2, 3, 4, 5}:
        raise ContractValidationError("geography priority rank must be 1..5")
    for name, value in (("final_score", final_score), ("opportunity", opportunity)):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ContractValidationError(f"{name} must be a finite number")
    if not 0.0 <= final_score <= 100.0:
        raise ContractValidationError("final_score must be in [0,100]")
    if not 0.0 <= opportunity <= 1.0:
        raise ContractValidationError("opportunity must be in [0,1]")
    if not isinstance(job_key, str) or not job_key.strip():
        raise ContractValidationError("job_key must be a non-empty string")
    return (geography_priority_rank, -final_score, -opportunity, job_key)


def rank_selected(rows: Iterable[tuple[GeographyMatch, ScoreResult]]) -> list[tuple[GeographyMatch, ScoreResult]]:
    return sorted(
        rows,
        key=lambda row: selection_sort_key(
            row[0].priority_rank,
            row[1].final,
            row[1].opportunity,
            row[1].job_key,
        ),
    )
