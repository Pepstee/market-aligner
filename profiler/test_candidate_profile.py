"""Standalone tests for the evidence-led Artiom profiler."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import yaml

from profiler.candidate_profile import (
    DEFAULT_EVIDENCE,
    build_profile,
    load_evidence,
    load_public_llm_context,
    profile_to_dict,
    public_llm_context_from_doc,
    write_profile,
)


def main() -> int:
    doc = load_evidence(DEFAULT_EVIDENCE)
    profile = build_profile(doc)

    assert profile.subject == "Artiom Gutu"
    assert len(profile.tracks) >= 8
    assert "Agentic_AI_Engineer" in profile.tracks
    assert "Security_Detection_Engineer" in profile.tracks
    assert profile.evidence
    assert profile.unknowns
    assert all(track.evidence for track in profile.tracks.values())
    assert all(0 <= track.interest <= 10 for track in profile.tracks.values())
    assert all(0 <= track.skill <= 10 for track in profile.tracks.values())
    assert all(0 <= track.market_readiness <= 10 for track in profile.tracks.values())
    assert all(0 <= track.confidence <= 1 for track in profile.tracks.values())

    rendered = profile_to_dict(profile)
    assert "candidate_profile" in rendered
    assert "hyun_profile" not in rendered
    constraints = rendered["candidate_profile"]["constraints"]
    assert constraints["target_geography"].startswith("UK-resident search")
    assert constraints["work_authorisation_eu"].startswith("confirmed")
    assert constraints["work_authorisation_uk"].startswith("confirmed")
    assert constraints["work_authorisation_switzerland"].startswith("eligible")
    assert constraints["residence"] == "fixed in the United Kingdom; no relocation"

    llm_context = public_llm_context_from_doc(rendered)
    assert llm_context["subject"] == "Artiom Gutu"
    assert "capabilities" in llm_context
    assert "gaps" in llm_context["tracks"]["Agentic_AI_Engineer"]
    assert "evidence" not in llm_context
    assert "evidence" not in llm_context["tracks"]["Agentic_AI_Engineer"]
    assert "privacy" not in llm_context["constraints"]
    assert llm_context["constraints"]["career_deadline"] == "2026-12-31"
    json.dumps(llm_context)  # the rate_axes payload must always be serialisable

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "artiom_profile.yaml"
        write_profile(profile, out)
        loaded = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert loaded["meta"]["subject"] == "Artiom Gutu"
        assert set(loaded["candidate_profile"]["tracks"]) == set(profile.tracks)
        assert load_public_llm_context(out) == public_llm_context_from_doc(loaded)

    print(
        f"Candidate profiler PASSED — {len(profile.tracks)} tracks, "
        f"{len(profile.evidence)} evidence items, {len(profile.unknowns)} preserved unknowns"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
