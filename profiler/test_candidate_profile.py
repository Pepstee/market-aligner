"""Standalone tests for the generic evidence-led candidate profiler."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import yaml

from profiler.candidate_profile import (
    build_profile,
    load_evidence,
    load_public_llm_context,
    profile_to_dict,
    public_llm_context_from_doc,
    write_profile,
)


def main() -> int:
    doc = {
        "meta": {"subject": "Example Candidate", "version": "test-v1"},
        "evidence": [{
            "id": "example-1", "kind": "project", "claim": "Completed a sample project",
            "source": "synthetic fixture", "status": "verified", "confidence": 1.0,
        }],
        "career_tracks": {"Example_Track": {
            "interest": 7, "skill": 6, "confidence": 0.8, "market_readiness": 5,
            "evidence": ["example-1"], "rationale": "Synthetic test rationale",
            "gaps": ["Synthetic test gap"],
        }},
        "capabilities": {"example": ["synthetic capability"]},
        "constraints": {"target_geography": "configured at runtime", "privacy": "private"},
        "blind_spots": ["Synthetic blind spot"],
        "unknowns": ["Synthetic unknown"],
        "exclusions": ["Synthetic exclusion"],
    }
    profile = build_profile(doc)

    assert profile.subject == "Example Candidate"
    assert set(profile.tracks) == {"Example_Track"}
    assert profile.evidence
    assert profile.unknowns
    assert all(track.evidence for track in profile.tracks.values())
    assert all(0 <= track.interest <= 10 for track in profile.tracks.values())
    assert all(0 <= track.skill <= 10 for track in profile.tracks.values())
    assert all(0 <= track.market_readiness <= 10 for track in profile.tracks.values())
    assert all(0 <= track.confidence <= 1 for track in profile.tracks.values())

    rendered = profile_to_dict(profile)
    assert "candidate_profile" in rendered
    assert "candidate_preferences" not in rendered
    llm_context = public_llm_context_from_doc(rendered)
    assert llm_context["subject"] == profile.subject
    assert "capabilities" in llm_context
    assert "gaps" in llm_context["tracks"]["Example_Track"]
    assert "evidence" not in llm_context
    assert "evidence" not in llm_context["tracks"]["Example_Track"]
    assert "privacy" not in llm_context["constraints"]
    assert llm_context["constraints"]["target_geography"] == "configured at runtime"
    json.dumps(llm_context)  # the rate_axes payload must always be serialisable

    with tempfile.TemporaryDirectory() as tmp:
        evidence_path = Path(tmp) / "candidate_evidence.yaml"
        evidence_path.write_text(yaml.safe_dump(doc), encoding="utf-8")
        assert load_evidence(evidence_path) == doc
        out = Path(tmp) / "candidate_profile.yaml"
        write_profile(profile, out)
        loaded = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert loaded["meta"]["subject"] == profile.subject
        assert set(loaded["candidate_profile"]["tracks"]) == set(profile.tracks)
        assert load_public_llm_context(out) == public_llm_context_from_doc(loaded)

    print(
        f"Candidate profiler PASSED — {len(profile.tracks)} tracks, "
        f"{len(profile.evidence)} evidence items, {len(profile.unknowns)} preserved unknowns"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
