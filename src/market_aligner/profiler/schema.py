"""Generic profile and evidence-ledger schemas.

Validation rules are selectively adopted from the audited evidence-led profiler.
Person-specific paths, defaults, instructions, and career taxonomies are excluded.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


PROFILE_SCHEMA_VERSION = "market-aligner.profile.v1"
PROFILE_ID_PATTERN = re.compile(r"^prf_[0-9a-f]{32}$")
EVIDENCE_STATUSES = frozenset({"verified", "explicit", "inference", "unverified_current"})

_SECRET_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"api[_ -]?key\s*[=:]",
        r"secret[_ -]?access\s*[=:]",
        r"password\s*[=:]",
        r"token\s*[=:]",
        r"-----begin [a-z ]+private key-----",
        r"\b\d{8,10}:[a-z0-9_-]{20,}\b",
    )
)


def new_profile_id() -> str:
    return f"prf_{uuid.uuid4().hex}"


def validate_profile_id(profile_id: str) -> str:
    value = str(profile_id).strip()
    if not PROFILE_ID_PATTERN.fullmatch(value):
        raise ValueError("profile_id must be opaque and match prf_<32 lowercase hex characters>")
    return value


def _number(value: Any, low: float, high: float, label: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be numeric") from exc
    if not low <= result <= high:
        raise ValueError(f"{label} must be in [{low}, {high}], got {result}")
    return result


def assert_secret_free(value: Any, path: str = "root") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            assert_secret_free(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            assert_secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str):
        for pattern in _SECRET_PATTERNS:
            if pattern.search(value):
                raise ValueError(f"possible secret-bearing text at {path}")


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    kind: str
    claim: str
    source_ref: str
    status: str
    confidence: float
    observed_at: str | None = None
    content_sha256: str | None = None

    def __post_init__(self) -> None:
        if not self.evidence_id.strip() or not self.claim.strip() or not self.source_ref.strip():
            raise ValueError("evidence requires evidence_id, claim, and source_ref")
        if self.status not in EVIDENCE_STATUSES:
            raise ValueError(f"unsupported evidence status: {self.status}")
        _number(self.confidence, 0.0, 1.0, "evidence.confidence")
        assert_secret_free(asdict(self))


@dataclass(frozen=True)
class TrackProfile:
    interest: float
    demonstrated_skill: float
    confidence: float
    market_readiness: float
    evidence_ids: tuple[str, ...] = ()
    rationale: str = ""
    gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _number(self.interest, 0.0, 10.0, "track.interest")
        _number(self.demonstrated_skill, 0.0, 10.0, "track.demonstrated_skill")
        _number(self.market_readiness, 0.0, 10.0, "track.market_readiness")
        _number(self.confidence, 0.0, 1.0, "track.confidence")


@dataclass(frozen=True)
class CandidateProfile:
    profile_id: str
    version: str
    tracks: dict[str, TrackProfile]
    capabilities: dict[str, Any] = field(default_factory=dict)
    constraints: dict[str, Any] = field(default_factory=dict)
    blind_spots: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    display_label: str | None = None
    schema: str = PROFILE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_profile_id(self.profile_id)
        if self.schema != PROFILE_SCHEMA_VERSION:
            raise ValueError(f"unsupported profile schema: {self.schema}")
        if not self.version.strip():
            raise ValueError("profile version is required")
        if not self.tracks:
            raise ValueError("at least one track is required")
        assert_secret_free(asdict(self))

    def validate_evidence(self, evidence: Mapping[str, EvidenceItem]) -> None:
        missing = sorted(
            evidence_id
            for track in self.tracks.values()
            for evidence_id in track.evidence_ids
            if evidence_id not in evidence
        )
        if missing:
            raise ValueError(f"profile references missing evidence: {missing}")

    def llm_context(self, evidence: Mapping[str, EvidenceItem]) -> dict[str, Any]:
        """Return a bounded semantic-judgement context with no filesystem paths."""

        self.validate_evidence(evidence)
        used_ids = {item for track in self.tracks.values() for item in track.evidence_ids}
        context = {
            "schema": "market-aligner.profile-llm-context.v1",
            "profile_id": self.profile_id,
            "profile_version": self.version,
            "tracks": {
                name: {
                    "interest": track.interest,
                    "demonstrated_skill": track.demonstrated_skill,
                    "confidence": track.confidence,
                    "market_readiness": track.market_readiness,
                    "evidence_ids": list(track.evidence_ids),
                    "rationale": track.rationale,
                    "gaps": list(track.gaps),
                }
                for name, track in sorted(self.tracks.items())
            },
            "evidence_ledger": [
                {
                    "evidence_id": item.evidence_id,
                    "kind": item.kind,
                    "claim": item.claim,
                    "status": item.status,
                    "confidence": item.confidence,
                    "content_sha256": item.content_sha256,
                }
                for key, item in sorted(evidence.items())
                if key in used_ids
            ],
            "capabilities": self.capabilities,
            "constraints": self.constraints,
            "blind_spots": list(self.blind_spots),
            "unknowns": list(self.unknowns),
            "exclusions": list(self.exclusions),
            "instruction": (
                "Judge only from the supplied evidence. Preserve unknowns and negative evidence; "
                "do not infer seniority, qualifications, experience, work rights, or preferences."
            ),
        }
        assert_secret_free(context)
        return context
