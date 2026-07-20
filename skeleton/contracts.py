"""
skeleton/contracts.py — the frozen seams between modules.

These dataclasses ARE the interface. Modules (scraper, profiler, llm, reporter)
talk to each other only through these shapes, so each can be built and tested
against a fixture with the others absent.

Rule: treat these as stable. If a field must change, bump CONTRACT_VERSION and
update every module + fixture in the same change. Don't quietly reshape.

Stdlib only — no third-party deps, so any module can import it freely.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

CONTRACT_VERSION = "0.4.0"  # 0.4.0: complete requirements and vacancy-detail fields

# The ten careers under comparison. Keys are canonical and must match the
# candidate_preferences keys in config.yaml exactly.
CAREERS: tuple[str, ...] = (
    "UX_UI",
    "Spatial_VMD",
    "Exhibition",
    "Brand_Space",
    "ArchViz",
    "3D_Generalist",
    "Environment_Art",
    "XR_Spatial",
    "Technical_Artist",
    "Motion_Graphic",
)

# Generic UK AI/IT search tracks. CAREERS remains above for the guided-pass
# questionnaire scorer and its stable scoring contract.
TARGET_TRACKS: tuple[str, ...] = (
    "Agentic_AI_Engineer",
    "AI_Automation_Engineer",
    "Applied_AI_Engineer",
    "ML_MLOps_Engineer",
    "Cloud_Platform_Engineer",
    "Security_Detection_Engineer",
    "Backend_Engineer",
    "Full_Stack_Engineer",
    "Technical_Solutions_Engineer",
)


# --------------------------------------------------------------------------- #
# C1 — a discovered job URL (scraper: discover stage)
# --------------------------------------------------------------------------- #
@dataclass
class JobUrl:
    board: str            # "wanted" | "saramin" | "jobkorea" | "notefolio"
    job_id: str           # board-local id; unique within a board
    url: str
    posted_at: Optional[str] = None   # ISO date if the listing exposes one

    @property
    def key(self) -> str:
        """Global dedup / resume key."""
        return f"{self.board}:{self.job_id}"


# --------------------------------------------------------------------------- #
# C2 — a raw fetched posting (scraper: fetch stage → raw cache)
# --------------------------------------------------------------------------- #
@dataclass
class RawPosting:
    board: str
    job_id: str
    url: str
    fetched_at: str                       # ISO timestamp
    raw_text: Optional[str] = None        # for HTML-scraped boards
    raw_json: Optional[dict[str, Any]] = None   # for API/JSON boards

    @property
    def key(self) -> str:
        return f"{self.board}:{self.job_id}"


# --------------------------------------------------------------------------- #
# C3 — a structured, extracted job row (llm.extract_job + llm.rate_axes)
# Axis ratings are Optional so an un-scored row is representable.
# --------------------------------------------------------------------------- #
@dataclass
class JobRow:
    board: str
    job_id: str
    url: str
    posted_at: Optional[str] = None
    scraped_at: Optional[str] = None

    job_title: str = ""
    company: str = ""
    location: str = ""
    salary_text: str = ""
    contract_type: str = ""
    experience_required: str = ""
    sponsorship_signal: str = "unknown"
    mapped_career: str = "other"          # one of TARGET_TRACKS, or "other"
    entry_level: Optional[bool] = None
    required_software: list[str] = field(default_factory=list)  # canonical ids
    job_description: str = ""
    responsibilities: list[str] = field(default_factory=list)
    required_skills: list[str] = field(default_factory=list)
    preferred_skills: list[str] = field(default_factory=list)
    education_required: str = ""
    certifications_required: list[str] = field(default_factory=list)
    benefits: list[str] = field(default_factory=list)
    application_deadline: str = ""

    # Optional candidate lifestyle constraints:
    remote_flag: Optional[bool] = None     # True if 재택/원격/하이브리드; False if explicit office-only; None unclear
    site_intensity: Optional[float] = None # 0-10: 0 = pure desk work, 10 = constant 현장/시공/설치 presence

    # Active UK candidate-fit axes (0-10, LLM or deterministic mock produced).
    technical_alignment: Optional[float] = None
    evidence_match: Optional[float] = None
    growth_potential: Optional[float] = None

    # 0–10 axis ratings (LLM-produced; keep the arithmetic out of here)
    visualization: Optional[float] = None
    spatial_relevance: Optional[float] = None
    cs_usefulness: Optional[float] = None
    english_usefulness: Optional[float] = None
    freelance_potential: Optional[float] = None
    market_demand: Optional[float] = None
    barrier_to_entry: Optional[float] = None   # inverse axis; skeleton inverts it

    why_it_fits: str = ""
    skills_to_learn: list[str] = field(default_factory=list)

    extraction_confidence: Optional[float] = None   # 0–1
    dedup_key: str = ""                    # normalised company+title, cross-board

    @property
    def key(self) -> str:
        return f"{self.board}:{self.job_id}"


# --------------------------------------------------------------------------- #
# C4 — a scored row (skeleton.scoring; deterministic candidate-profile join)
# --------------------------------------------------------------------------- #
@dataclass
class ScoredRow:
    row: JobRow
    fit: float
    opportunity: float
    final: float

    def to_dict(self) -> dict[str, Any]:
        d = to_dict(self.row)
        d.update(fit=self.fit, opportunity=self.opportunity, final=self.final)
        return d


# --------------------------------------------------------------------------- #
# candidate_preferences — guided-pass calibration input
# --------------------------------------------------------------------------- #
@dataclass
class FieldProfile:
    interest: float           # 0–10
    skill: float              # 0–10
    confidence: float         # 0–1


@dataclass
class CandidatePreferenceProfile:
    fields: dict[str, FieldProfile] = field(default_factory=dict)  # keyed by CAREERS
    blind_spots: list[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> "CandidatePreferenceProfile":
        """Build from the ``candidate_preferences`` configuration block."""
        raw = cfg.get("candidate_preferences", {}) or {}
        blind = list(raw.get("blind_spots", []) or [])
        fields: dict[str, FieldProfile] = {}
        for name in CAREERS:
            v = raw.get(name)
            if isinstance(v, dict):
                fields[name] = FieldProfile(
                    interest=float(v.get("interest", 0) or 0),
                    skill=float(v.get("skill", 0) or 0),
                    confidence=float(v.get("confidence", 0) or 0),
                )
        return cls(fields=fields, blind_spots=blind)


@dataclass
class CandidateTrackProfile:
    interest: float
    skill: float
    confidence: float
    market_readiness: float


@dataclass
class CandidateFitProfile:
    fields: dict[str, CandidateTrackProfile] = field(default_factory=dict)
    blind_spots: list[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> "CandidateFitProfile":
        raw = cfg.get("candidate_fit_profile", {}) or {}
        blind = list(raw.get("blind_spots", []) or [])
        fields: dict[str, CandidateTrackProfile] = {}
        for name in TARGET_TRACKS:
            value = raw.get(name)
            if isinstance(value, dict):
                fields[name] = CandidateTrackProfile(
                    interest=float(value.get("interest", 0) or 0),
                    skill=float(value.get("skill", 0) or 0),
                    confidence=float(value.get("confidence", 0) or 0),
                    market_readiness=float(value.get("market_readiness", 0) or 0),
                )
        return cls(fields=fields, blind_spots=blind)


# --------------------------------------------------------------------------- #
# Generic (de)serialisation + JSONL IO — used by every module
# --------------------------------------------------------------------------- #
def to_dict(obj: Any) -> dict[str, Any]:
    return dataclasses.asdict(obj)


def from_dict(cls: type, data: dict[str, Any]) -> Any:
    """Tolerant constructor: ignores unknown keys so old fixtures still load."""
    known = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in known})


def write_jsonl(path: str | Path, rows: Iterable[Any]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            d = r if isinstance(r, dict) else to_dict(r)
            fh.write(json.dumps(d, ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path: str | Path, cls: Optional[type] = None) -> Iterator[Any]:
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            yield from_dict(cls, d) if cls else d


# --------------------------------------------------------------------------- #
# Self-test: round-trip one of each. Run: python skeleton/contracts.py
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    samples = [
        JobUrl(board="wanted", job_id="123", url="https://x/123", posted_at="2026-07-01"),
        RawPosting(board="wanted", job_id="123", url="https://x/123",
                   fetched_at="2026-07-13T09:00:00Z", raw_json={"title": "UX Designer"}),
        JobRow(board="wanted", job_id="123", url="https://x/123",
               job_title="UX Designer", company="ABC", mapped_career="UX_UI",
               entry_level=True, required_software=["figma"], visualization=8.0,
               spatial_relevance=6.0, market_demand=9.0, barrier_to_entry=3.0,
               remote_flag=True, site_intensity=0.0,
               extraction_confidence=0.9, dedup_key="abc|ux designer"),
    ]
    for s in samples:
        cls = type(s)
        assert from_dict(cls, to_dict(s)) == s, f"round-trip failed for {cls.__name__}"

    prof = CandidatePreferenceProfile.from_config(
        {"candidate_preferences": {"UX_UI": {"interest": 7, "skill": 5, "confidence": 0.4},
                          "blind_spots": ["Technical_Artist"]}}
    )
    assert prof.fields["UX_UI"].interest == 7.0
    assert prof.blind_spots == ["Technical_Artist"]

    print(f"contracts.py OK — version {CONTRACT_VERSION}, {len(CAREERS)} careers, "
          f"round-trip + profile load passed.")
