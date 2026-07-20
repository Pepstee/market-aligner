"""Build and validate an evidence-led candidate profile.

Unlike the legacy guided-pass scorer, this module does not infer capability
from a questionnaire.  It consumes a curated evidence ledger whose claims are
traceable to the owned corpus, separates interest from demonstrated skill and
market readiness, and preserves unknowns rather than filling them with guesses.

Input:  ``profiler/data/artiom_evidence.yaml``
Output: ``profiler/data/artiom_profile.yaml``
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "profiler" / "data"
DEFAULT_EVIDENCE = DATA_DIR / "artiom_evidence.yaml"
DEFAULT_OUTPUT = DATA_DIR / "artiom_profile.yaml"

_PUBLIC_TRACK_FIELDS = (
    "interest",
    "skill",
    "confidence",
    "market_readiness",
    "rationale",
    "gaps",
)

_SECRET_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"api[_ -]?key",
        r"secret[_ -]?access",
        r"password\s*[=:]",
        r"token\s*[=:]",
        r"-----begin [a-z ]+private key-----",
        r"\b\d{8,10}:[a-z0-9_-]{20,}\b",
    )
)


@dataclass(frozen=True)
class EvidenceItem:
    id: str
    kind: str
    claim: str
    source: str
    status: str
    confidence: float


@dataclass(frozen=True)
class CareerTrack:
    interest: float
    skill: float
    confidence: float
    market_readiness: float
    evidence: tuple[str, ...]
    rationale: str
    gaps: tuple[str, ...] = ()


@dataclass(frozen=True)
class CandidateProfile:
    subject: str
    version: str
    generated_at: str
    evidence_scope: dict[str, Any]
    tracks: dict[str, CareerTrack]
    evidence: dict[str, EvidenceItem]
    capabilities: dict[str, Any]
    constraints: dict[str, Any]
    blind_spots: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()


def _number(value: Any, lo: float, hi: float, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be numeric") from exc
    if not lo <= number <= hi:
        raise ValueError(f"{label} must be in [{lo}, {hi}], got {number}")
    return number


def _assert_secret_free(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _assert_secret_free(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _assert_secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str):
        for pattern in _SECRET_PATTERNS:
            if pattern.search(value):
                raise ValueError(f"possible secret-bearing text at {path}")


def load_evidence(path: str | Path = DEFAULT_EVIDENCE) -> dict[str, Any]:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        raise ValueError("evidence document must be a mapping")
    _assert_secret_free(doc)
    return doc


def _json_safe(value: Any) -> Any:
    """Recursively convert YAML-native dates to JSON-safe ISO strings."""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(child) for child in value]
    return value


def public_llm_context_from_doc(doc: dict[str, Any]) -> dict[str, Any]:
    """Return the evidence-bounded profile that may be sent to a job LLM.

    The generated profile also contains the full evidence ledger, corpus scope,
    and source locations.  Job assessment does not need those private/audit
    fields.  It receives only track priors, bounded capability claims, gaps,
    constraints, blind spots, unknowns, and exclusions.
    """
    meta = dict(doc.get("meta") or {})
    candidate = dict(doc.get("candidate_profile") or {})
    raw_tracks = dict(candidate.get("tracks") or {})

    tracks: dict[str, dict[str, Any]] = {}
    for name, raw in raw_tracks.items():
        raw = dict(raw or {})
        tracks[str(name)] = {
            field_name: raw[field_name]
            for field_name in _PUBLIC_TRACK_FIELDS
            if field_name in raw
        }

    constraints = dict(candidate.get("constraints") or {})
    # The privacy policy controls this projection; it is not job-fit evidence.
    constraints.pop("privacy", None)

    context = {
        "subject": str(meta.get("subject") or "").strip(),
        "profile_version": str(meta.get("version") or "").strip(),
        "evidence_scope": _json_safe(dict(meta.get("evidence_scope") or {})),
        # The judge receives the complete career-relevant dossier distilled
        # from the owned corpus, not merely numeric priors. Raw private chats
        # and secret-bearing records remain excluded by policy.
        "evidence_ledger": [
            {
                key: _json_safe(item.get(key))
                for key in ("id", "kind", "claim", "source", "status", "confidence")
            }
            for item in (doc.get("evidence") or [])
            if isinstance(item, dict)
        ],
        "tracks": tracks,
        "capabilities": dict(candidate.get("capabilities") or {}),
        "constraints": constraints,
        "blind_spots": list(candidate.get("blind_spots") or []),
        "unknowns": list(candidate.get("unknowns") or []),
        "exclusions": list(candidate.get("exclusions") or []),
        "judging_instruction": (
            "Use the entire evidence ledger and its negative evidence. Judge this vacancy "
            "against Artiom's actual present proof; do not infer professional seniority from "
            "project sophistication or interest."
        ),
    }
    context = _json_safe(context)
    _assert_secret_free(context)
    return context


def load_public_llm_context(path: str | Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Load a generated profile and project it to public-safe LLM context."""
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        raise ValueError("generated profile must be a mapping")
    return public_llm_context_from_doc(doc)


def build_profile(doc: dict[str, Any]) -> CandidateProfile:
    meta = dict(doc.get("meta") or {})
    subject = str(meta.get("subject") or "").strip()
    if not subject:
        raise ValueError("meta.subject is required")

    evidence: dict[str, EvidenceItem] = {}
    for raw in doc.get("evidence", []) or []:
        item = EvidenceItem(
            id=str(raw.get("id") or "").strip(),
            kind=str(raw.get("kind") or "").strip(),
            claim=str(raw.get("claim") or "").strip(),
            source=str(raw.get("source") or "").strip(),
            status=str(raw.get("status") or "").strip(),
            confidence=_number(raw.get("confidence"), 0.0, 1.0, "evidence.confidence"),
        )
        if not item.id or not item.claim or not item.source:
            raise ValueError("every evidence item needs id, claim, and source")
        if item.id in evidence:
            raise ValueError(f"duplicate evidence id: {item.id}")
        if item.status not in {"verified", "explicit", "inference", "unverified_current"}:
            raise ValueError(f"unsupported evidence status for {item.id}: {item.status}")
        evidence[item.id] = item

    tracks: dict[str, CareerTrack] = {}
    for name, raw in (doc.get("career_tracks") or {}).items():
        refs = tuple(str(ref) for ref in (raw.get("evidence") or []))
        missing = [ref for ref in refs if ref not in evidence]
        if missing:
            raise ValueError(f"{name} references missing evidence: {missing}")
        tracks[str(name)] = CareerTrack(
            interest=_number(raw.get("interest"), 0.0, 10.0, f"{name}.interest"),
            skill=_number(raw.get("skill"), 0.0, 10.0, f"{name}.skill"),
            confidence=_number(raw.get("confidence"), 0.0, 1.0, f"{name}.confidence"),
            market_readiness=_number(
                raw.get("market_readiness"), 0.0, 10.0, f"{name}.market_readiness"
            ),
            evidence=refs,
            rationale=str(raw.get("rationale") or "").strip(),
            gaps=tuple(str(gap) for gap in (raw.get("gaps") or [])),
        )
        if not tracks[str(name)].rationale:
            raise ValueError(f"{name}.rationale is required")

    if not tracks:
        raise ValueError("at least one career track is required")

    profile = CandidateProfile(
        subject=subject,
        version=str(meta.get("version") or "").strip(),
        generated_at=str(meta.get("generated_at") or "").strip(),
        evidence_scope=dict(meta.get("evidence_scope") or {}),
        tracks=tracks,
        evidence=evidence,
        capabilities=dict(doc.get("capabilities") or {}),
        constraints=dict(doc.get("constraints") or {}),
        blind_spots=tuple(str(item) for item in (doc.get("blind_spots") or [])),
        unknowns=tuple(str(item) for item in (doc.get("unknowns") or [])),
        exclusions=tuple(str(item) for item in (doc.get("exclusions") or [])),
    )
    _assert_secret_free(asdict(profile))
    return profile


def profile_to_dict(profile: CandidateProfile) -> dict[str, Any]:
    tracks: dict[str, Any] = {}
    for name, track in profile.tracks.items():
        tracks[name] = {
            "interest": track.interest,
            "skill": track.skill,
            "confidence": track.confidence,
            "market_readiness": track.market_readiness,
            "evidence": list(track.evidence),
            "rationale": track.rationale,
            "gaps": list(track.gaps),
        }
    return {
        "meta": {
            "subject": profile.subject,
            "version": profile.version,
            "generated_at": profile.generated_at,
            "method": "evidence-led corpus synthesis; no self-rating questionnaire",
            "evidence_scope": profile.evidence_scope,
        },
        "candidate_profile": {
            "tracks": tracks,
            "blind_spots": list(profile.blind_spots),
            "capabilities": profile.capabilities,
            "constraints": profile.constraints,
            "unknowns": list(profile.unknowns),
            "exclusions": list(profile.exclusions),
        },
        "evidence": [asdict(item) for item in profile.evidence.values()],
    }


def write_profile(
    profile: CandidateProfile,
    path: str | Path = DEFAULT_OUTPUT,
    *,
    force: bool = False,
) -> Path:
    path = Path(path)
    if path.exists() and not force:
        existing = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        version = str((existing.get("meta") or {}).get("version") or "")
        if version and version != profile.version:
            raise RuntimeError(
                f"refusing to replace profile version {version!r} with {profile.version!r}; "
                "pass force=True after reviewing the evidence diff"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            profile_to_dict(profile),
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
            width=100,
        ),
        encoding="utf-8",
    )
    return path


def run(
    evidence_path: str | Path = DEFAULT_EVIDENCE,
    output_path: str | Path = DEFAULT_OUTPUT,
) -> CandidateProfile:
    profile = build_profile(load_evidence(evidence_path))
    write_profile(profile, output_path)
    return profile


if __name__ == "__main__":
    built = run()
    print(f"Wrote {DEFAULT_OUTPUT}")
    for name, track in built.tracks.items():
        print(
            f"  {name:<30} interest={track.interest:>4.1f} "
            f"skill={track.skill:>4.1f} readiness={track.market_readiness:>4.1f} "
            f"confidence={track.confidence:.2f}"
        )
