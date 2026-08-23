"""Explicit, loss-minimising importers for audited legacy profile shapes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .schema import CandidateProfile, EvidenceItem, TrackProfile, new_profile_id


def _document(path: str | Path) -> dict[str, Any]:
    value = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise ValueError("profile document must be a mapping")
    return value


def import_evidence_led(path: str | Path, profile_id: str | None = None) -> tuple[CandidateProfile, list[EvidenceItem]]:
    """Import the audited combined evidence/profile document without weakening claims."""

    source = _document(path)
    meta = dict(source.get("meta") or {})
    raw_tracks = dict(source.get("career_tracks") or {})
    evidence = [
        EvidenceItem(
            evidence_id=str(item.get("id") or "").strip(),
            kind=str(item.get("kind") or "").strip(),
            claim=str(item.get("claim") or "").strip(),
            source_ref=str(item.get("source") or "").strip(),
            status=str(item.get("status") or "").strip(),
            confidence=float(item.get("confidence")),
        )
        for item in (source.get("evidence") or [])
    ]
    tracks = {
        str(name): TrackProfile(
            interest=float(raw.get("interest")),
            demonstrated_skill=float(raw.get("skill")),
            confidence=float(raw.get("confidence")),
            market_readiness=float(raw.get("market_readiness")),
            evidence_ids=tuple(str(item) for item in (raw.get("evidence") or ())),
            rationale=str(raw.get("rationale") or "").strip(),
            gaps=tuple(str(item) for item in (raw.get("gaps") or ())),
        )
        for name, raw in raw_tracks.items()
    }
    profile = CandidateProfile(
        profile_id=profile_id or new_profile_id(),
        version=str(meta.get("version") or "legacy-import"),
        display_label=str(meta.get("subject") or "").strip() or None,
        tracks=tracks,
        capabilities=dict(source.get("capabilities") or {}),
        constraints=dict(source.get("constraints") or {}),
        blind_spots=tuple(str(item) for item in (source.get("blind_spots") or ())),
        unknowns=tuple(str(item) for item in (source.get("unknowns") or ())),
        exclusions=tuple(str(item) for item in (source.get("exclusions") or ())),
    )
    profile.validate_evidence({item.evidence_id: item for item in evidence})
    return profile, evidence


def import_guided_profile(
    path: str | Path,
    profile_id: str | None = None,
    *,
    profile_key: str = "profile",
) -> tuple[CandidateProfile, list[EvidenceItem]]:
    """Import a legacy guided profile while retaining its lack of claim evidence.

    Numeric self-assessment/probe summaries are not converted into fabricated
    evidence records.  Empty evidence references and an explicit unknown remain.
    """

    source = _document(path)
    meta = dict(source.get("meta") or {})
    block = dict(source.get(profile_key) or {})
    blind_spots = tuple(str(item) for item in (block.pop("blind_spots", ()) or ()))
    constraints = dict(source.get("constraints") or {})
    tracks = {
        str(name): TrackProfile(
            interest=float(raw.get("interest")),
            demonstrated_skill=float(raw.get("skill")),
            confidence=float(raw.get("confidence")),
            market_readiness=float(raw.get("market_readiness", 0.0)),
            evidence_ids=(),
            rationale="Imported legacy guided/probe score; requires evidence-led verification.",
            gaps=(
                "No itemised evidence ledger in the legacy source.",
                "Market readiness was not measured in the legacy source.",
            ),
        )
        for name, raw in block.items()
        if isinstance(raw, dict) and {"interest", "skill", "confidence"}.issubset(raw)
    }
    profile = CandidateProfile(
        profile_id=profile_id or new_profile_id(),
        version=str(meta.get("version") or "legacy-guided-import"),
        display_label=str(meta.get("subject") or "").strip() or None,
        tracks=tracks,
        constraints=constraints,
        blind_spots=blind_spots,
        unknowns=("Legacy profile has no itemised evidence ledger; all skills require verification.",),
    )
    return profile, []
