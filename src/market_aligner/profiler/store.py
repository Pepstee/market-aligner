"""Atomic external storage for private profiles and evidence ledgers."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from market_aligner.config import ProductPaths

from .schema import CandidateProfile, EvidenceItem, TrackProfile, validate_profile_id


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class ProfileStore:
    def __init__(self, data_home: str | Path | None = None) -> None:
        self.paths = ProductPaths.resolve(data_home).ensure()

    def directory(self, profile_id: str) -> Path:
        return self.paths.profiles / validate_profile_id(profile_id)

    def save(self, profile: CandidateProfile, evidence: list[EvidenceItem]) -> None:
        evidence_by_id = {item.evidence_id: item for item in evidence}
        if len(evidence_by_id) != len(evidence):
            raise ValueError("duplicate evidence_id")
        profile.validate_evidence(evidence_by_id)
        directory = self.directory(profile.profile_id)
        directory.mkdir(parents=True, exist_ok=True)
        profile_payload = asdict(profile)
        _atomic_text(
            directory / "profile.yaml",
            yaml.safe_dump(profile_payload, sort_keys=False, allow_unicode=True, width=100),
        )
        ledger = "".join(
            json.dumps(asdict(item), ensure_ascii=False, sort_keys=True) + "\n"
            for item in sorted(evidence, key=lambda item: item.evidence_id)
        )
        _atomic_text(directory / "evidence.jsonl", ledger)

    def load(self, profile_id: str) -> tuple[CandidateProfile, dict[str, EvidenceItem]]:
        directory = self.directory(profile_id)
        payload = yaml.safe_load((directory / "profile.yaml").read_text(encoding="utf-8")) or {}
        payload["tracks"] = {
            name: TrackProfile(**{**track, "evidence_ids": tuple(track.get("evidence_ids") or ()), "gaps": tuple(track.get("gaps") or ())})
            for name, track in (payload.get("tracks") or {}).items()
        }
        for key in ("blind_spots", "unknowns", "exclusions"):
            payload[key] = tuple(payload.get(key) or ())
        profile = CandidateProfile(**payload)
        evidence: dict[str, EvidenceItem] = {}
        with (directory / "evidence.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    item = EvidenceItem(**json.loads(line))
                    if item.evidence_id in evidence:
                        raise ValueError(f"duplicate evidence_id: {item.evidence_id}")
                    evidence[item.evidence_id] = item
        profile.validate_evidence(evidence)
        return profile, evidence

    def list_profile_ids(self) -> list[str]:
        return sorted(
            child.name
            for child in self.paths.profiles.iterdir()
            if child.is_dir() and child.joinpath("profile.yaml").is_file()
        )
