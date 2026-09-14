"""Strict external candidate-intent authority for selection and handoff."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from market_aligner.applications.canonical import (
    ContractValidationError,
    PROFILE_ID_PATTERN,
    canonical_json_bytes,
    deep_freeze_json,
    deep_thaw_json,
    digest_bytes,
    parse_canonical_json,
    require_exact_keys,
    require_integer,
    require_mapping,
    require_nonempty_string,
    require_pattern,
    require_sha256,
    require_sorted_unique_strings,
    require_timestamp,
    validate_strings,
)
from market_aligner.profiler.schema import CandidateProfile


CANDIDATE_INTENT_SCHEMA = "market-aligner.candidate-intent.v1"
CANONICAL_GEOGRAPHY_PRIORITY: tuple[tuple[int, str, str], ...] = (
    (1, "UK", "remote"),
    (2, "UK", "hybrid"),
    (3, "UK", "onsite"),
    (4, "RO", "remote"),
    (5, "EU", "remote"),
)
_INTENT_KEYS = {
    "authority_revision",
    "authority_source_sha256",
    "created_at",
    "geography_priority",
    "profile_id",
    "profile_version",
    "role_track_ids",
    "schema_version",
}
_GEOGRAPHY_KEYS = {"rank", "region_code", "work_mode"}


def validate_candidate_intent_payload(payload: Mapping[str, Any]) -> None:
    require_exact_keys(payload, _INTENT_KEYS, "candidate intent")
    if payload["schema_version"] != CANDIDATE_INTENT_SCHEMA:
        raise ContractValidationError("unsupported candidate-intent schema version")
    require_integer(payload["authority_revision"], "authority_revision")
    require_sha256(payload["authority_source_sha256"], "authority_source_sha256")
    require_timestamp(payload["created_at"], "created_at", strict_profile=True)
    require_pattern(payload["profile_id"], PROFILE_ID_PATTERN, "profile_id")
    profile_version = require_nonempty_string(payload["profile_version"], "profile_version")
    if profile_version != profile_version.strip():
        raise ContractValidationError("profile_version must be a trimmed string")
    role_track_ids = require_sorted_unique_strings(
        payload["role_track_ids"], "role_track_ids"
    )
    if any(value != value.strip() for value in role_track_ids):
        raise ContractValidationError("role_track_ids must contain trimmed strings")
    geography = payload["geography_priority"]
    if not isinstance(geography, list) or len(geography) != len(CANONICAL_GEOGRAPHY_PRIORITY):
        raise ContractValidationError("geography_priority must contain the exact five rows")
    actual: list[tuple[int, str, str]] = []
    for index, row_value in enumerate(geography):
        row = require_mapping(row_value, f"geography_priority[{index}]")
        require_exact_keys(row, _GEOGRAPHY_KEYS, f"geography_priority[{index}]")
        rank = require_integer(row["rank"], f"geography_priority[{index}].rank", minimum=1)
        region = require_nonempty_string(
            row["region_code"], f"geography_priority[{index}].region_code"
        )
        mode = require_nonempty_string(
            row["work_mode"], f"geography_priority[{index}].work_mode"
        )
        actual.append((rank, region, mode))
    if tuple(actual) != CANONICAL_GEOGRAPHY_PRIORITY:
        raise ContractValidationError(
            "geography_priority must be UK remote, UK hybrid, UK onsite, "
            "Romania remote, EU remote in exact rank order"
        )
    validate_strings(payload, require_nfc=True)


@dataclass(frozen=True)
class CandidateIntentDocument:
    """An exact immutable authority document and its content identity."""

    value: Mapping[str, Any]
    exact_bytes: bytes
    candidate_intent_sha256: str

    def __post_init__(self) -> None:
        """Make direct construction as strict as ``parse``.

        The wire bytes are the authority.  A caller must not be able to pair
        those bytes with a different or subsequently mutable decoded value.
        """

        parsed = require_mapping(parse_canonical_json(self.exact_bytes), "candidate intent")
        validate_candidate_intent_payload(parsed)
        if canonical_json_bytes(parsed) != self.exact_bytes:
            raise ContractValidationError(
                "candidate intent is not strict-profile canonical JSON"
            )
        if digest_bytes(self.exact_bytes) != self.candidate_intent_sha256:
            raise ContractValidationError("candidate-intent digest differs from exact bytes")
        try:
            supplied_bytes = canonical_json_bytes(deep_thaw_json(self.value))
        except (TypeError, ValueError) as exc:
            raise ContractValidationError("candidate-intent value is invalid") from exc
        if supplied_bytes != self.exact_bytes:
            raise ContractValidationError(
                "candidate-intent value differs from its exact authority bytes"
            )
        object.__setattr__(self, "value", deep_freeze_json(parsed))

    @property
    def profile_id(self) -> str:
        return str(self.value["profile_id"])

    @property
    def profile_version(self) -> str:
        return str(self.value["profile_version"])

    @property
    def role_track_ids(self) -> tuple[str, ...]:
        return tuple(self.value["role_track_ids"])

    @property
    def authority_source_sha256(self) -> str:
        return str(self.value["authority_source_sha256"])

    @classmethod
    def parse(cls, data: bytes) -> "CandidateIntentDocument":
        value = require_mapping(parse_canonical_json(data), "candidate intent")
        validate_candidate_intent_payload(value)
        if canonical_json_bytes(value) != data:
            raise ContractValidationError("candidate intent is not strict-profile canonical JSON")
        return cls(
            value=value,
            exact_bytes=data,
            candidate_intent_sha256=digest_bytes(data),
        )

    @classmethod
    def load(cls, path: str | Path) -> "CandidateIntentDocument":
        """Load an explicitly selected authority path; there is intentionally no default."""

        return cls.parse(Path(path).read_bytes())

    def require_profile(self, profile: CandidateProfile) -> None:
        if profile.profile_id != self.profile_id:
            raise ContractValidationError("candidate intent belongs to a different profile")
        if profile.version != self.profile_version:
            raise ContractValidationError("candidate intent targets a different profile version")
        missing_tracks = sorted(set(self.role_track_ids) - set(profile.tracks))
        if missing_tracks:
            raise ContractValidationError(
                f"candidate intent references unknown role tracks: {missing_tracks}"
            )


def serialize_candidate_intent(payload: Mapping[str, Any]) -> bytes:
    value = deep_thaw_json(payload)
    validate_candidate_intent_payload(value)
    return canonical_json_bytes(value)
