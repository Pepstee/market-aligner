"""
profiler/score_profile.py — the v1 Guided-Pass scoring key.

Reads a filled answer set and turns it into a ``CandidatePreferenceProfile``.
Both input and output are configurable ignored runtime files.

The maths is deliberately simple and deterministic — no model calls. It follows
the v1 guided-pass scoring key:

  Interest[field] (0-10):
    Interest = 10 * ( 0.5*norm(enjoy) + 0.3*norm(energy) + 0.2*rank_score )
               then +1 per forced-choice win for that field, capped at 10.
    norm(x) = (x-1)/4 ;  rank_score = (10 - rank + 1)/10.

  Skill[field] (0-10) — weight evidence over self-claim:
    Skill = 10 * ( 0.25*(C/3) + 0.45*evidence_D + 0.30*evidence_E )
    evidence_D / evidence_E in {0, 0.5, 1} = how directly D / E point at it.
    If a field has ONLY a Section-C number and no D/E evidence, cap Skill at 5
    and mark it low-confidence.

  Confidence[field]: raw Section-C value 0..3 -> {0, 0.33, 0.67, 1}.

  Blind-spot flag: raised where Confidence is low but D/E evidence is strong
    (undersells a real strength), or Confidence is high but there is no evidence
    (over-confidence).

  Uncertainty: ALL skill priors are high-uncertainty in v1.

Privacy: input and output both live under profiler/data/ and never leave it.
Deps: stdlib + pyyaml only.
"""

from __future__ import annotations

import sys
import argparse
import os
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any

import yaml

# Repo layout: profiler/score_profile.py -> repo root is parent.parent.
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skeleton"))
from contracts import CAREERS, CandidatePreferenceProfile, FieldProfile  # noqa: E402

from instrument.questions import (  # noqa: E402
    FIELD_TO_CAREER,
    FIELDS,
    section,
)

# Default IO paths (all inside profiler/data/).
DATA_DIR = _ROOT / "profiler" / "data"
DEFAULT_ANSWERS = Path(
    os.environ.get("CANDIDATE_ANSWERS_PATH", DATA_DIR / "candidate_answers.yaml")
)
DEFAULT_OUTPUT = Path(
    os.environ.get("CANDIDATE_PREFERENCES_PATH", DATA_DIR / "candidate_preferences.yaml")
)

# Confidence mapping: Section-C value 0..3 -> 0..1.
CONFIDENCE_MAP = {0: 0.0, 1: 0.33, 2: 0.67, 3: 1.0}

# Thresholds for the blind-spot flag.
LOW_CONFIDENCE = 0.33      # C <= 1  == "low confidence"
HIGH_CONFIDENCE = 0.67     # C >= 2  == "high confidence"
STRONG_EVIDENCE = 0.5      # combined D/E evidence at/above this == "strong"

# Evidence-level vocabulary (mirrors the instrument's declared levels).
EVIDENCE_LEVELS = {"none": 0.0, "indirect": 0.5, "direct": 1.0}


# --------------------------------------------------------------------------- #
# Per-field intermediate result (handy for tests / debugging).
# --------------------------------------------------------------------------- #
@dataclass
class FieldScore:
    field: str
    career: str
    interest: float
    skill: float
    confidence: float
    evidence_d: float
    evidence_e: float
    forced_choice_wins: int
    only_self_claim: bool           # C present but no D/E evidence -> capped, low-conf
    low_confidence_skill: bool      # skill prior flagged low-confidence
    blind_spot: bool
    blind_spot_reason: str = ""


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _round1(x: float) -> float:
    """Round to 1 dp for a stable, human-readable config block."""
    return round(x + 0.0, 1)


# --------------------------------------------------------------------------- #
# Signal extraction from the answer set.
# --------------------------------------------------------------------------- #
def _grid_norms(answers: dict) -> dict[str, tuple[float, float]]:
    """Section A -> per-field (norm(enjoy), norm(energy)); norm(x)=(x-1)/4."""
    a = answers.get(section("A")["answer_key"], {}) or {}
    out: dict[str, tuple[float, float]] = {}
    for f in FIELDS:
        cell = a.get(f, {}) or {}
        enjoy = float(cell.get("enjoy", 1) or 1)
        energy = float(cell.get("energy", 1) or 1)
        out[f] = ((enjoy - 1) / 4.0, (energy - 1) / 4.0)
    return out


def _forced_choice_wins(answers: dict) -> dict[str, int]:
    """Section B -> per-field count of pairs won."""
    picks = answers.get(section("B")["answer_key"], {}) or {}
    wins = {f: 0 for f in FIELDS}
    for pair in section("B")["pairs"]:
        choice = str(picks.get(str(pair["n"]), "")).strip().lower()
        if choice in ("a", "b"):
            wins[pair[choice]["field"]] += 1
    return wins


def _confidence_raw(answers: dict) -> dict[str, int]:
    """Section C -> per-field raw 0..3 value."""
    c = answers.get(section("C")["answer_key"], {}) or {}
    out = {}
    for f in FIELDS:
        v = int(c.get(f, 0) or 0)
        out[f] = _clamp_int(v, 0, 3)
    return out


def _clamp_int(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


def _rank_scores(answers: dict) -> dict[str, float]:
    """Section F -> per-field rank_score = (10 - rank + 1)/10 ; rank 1 = best."""
    order = list(answers.get(section("F")["answer_key"], []) or [])
    out = {f: 0.0 for f in FIELDS}
    for idx, f in enumerate(order):
        if f in out:
            rank = idx + 1                       # 1-based
            out[f] = (10 - rank + 1) / 10.0
    # Any field missing from the ranking scores 0 (least curious by default).
    return out


def _evidence_from_tags(entries: list, field_key: str, tag_key: str) -> dict[str, float]:
    """
    Reduce a list of tagged entries to a per-field evidence weight in {0,0.5,1}.

    entries: list of dicts. Each may carry per-field tags:
      Section D: entry["fields"] = {"F9": "direct", ...}
      Section E: entry["field"] = "F5", entry["evidence"] = "direct"
    We take the STRONGEST (max) evidence level seen for each field.
    """
    out = {f: 0.0 for f in FIELDS}
    for e in entries or []:
        if field_key == "fields":  # Section D style: a dict of field->level
            for f, level in (e.get("fields", {}) or {}).items():
                if f in out:
                    out[f] = max(out[f], EVIDENCE_LEVELS.get(str(level).lower(), 0.0))
        else:                       # Section E style: single field + evidence level
            f = e.get(field_key)
            level = e.get(tag_key, "none")
            if f in out:
                out[f] = max(out[f], EVIDENCE_LEVELS.get(str(level).lower(), 0.0))
    return out


def _evidence_d(answers: dict) -> dict[str, float]:
    return _evidence_from_tags(answers.get(section("D")["answer_key"], []) or [],
                               field_key="fields", tag_key="")


def _evidence_e(answers: dict) -> dict[str, float]:
    return _evidence_from_tags(answers.get(section("E")["answer_key"], []) or [],
                               field_key="field", tag_key="evidence")


# --------------------------------------------------------------------------- #
# The scoring itself.
# --------------------------------------------------------------------------- #
def score_answers(answers: dict) -> dict[str, FieldScore]:
    """Apply the v1 scoring key to a filled answer set -> per-field scores."""
    norms = _grid_norms(answers)
    wins = _forced_choice_wins(answers)
    conf_raw = _confidence_raw(answers)
    ranks = _rank_scores(answers)
    ev_d = _evidence_d(answers)
    ev_e = _evidence_e(answers)

    scores: dict[str, FieldScore] = {}
    for f in FIELDS:
        n_enjoy, n_energy = norms[f]
        rank_score = ranks[f]

        # --- Interest ---
        interest = 10.0 * (0.5 * n_enjoy + 0.3 * n_energy + 0.2 * rank_score)
        interest += wins[f]                          # +1 per forced-choice win
        interest = _clamp(interest, 0.0, 10.0)       # cap 10

        # --- Confidence ---
        c = conf_raw[f]
        confidence = CONFIDENCE_MAP[c]

        # --- Skill (evidence weighted over self-claim) ---
        e_d, e_e = ev_d[f], ev_e[f]
        skill = 10.0 * (0.25 * (c / 3.0) + 0.45 * e_d + 0.30 * e_e)

        only_self_claim = (c > 0) and (e_d == 0.0) and (e_e == 0.0)
        low_confidence_skill = True   # spec: ALL skill priors high-uncertainty in v1
        if only_self_claim:
            skill = min(skill, 5.0)   # cap 5 when there is no D/E evidence

        skill = _clamp(skill, 0.0, 10.0)

        # --- Blind-spot flag ---
        combined_ev = max(e_d, e_e)
        blind_spot = False
        reason = ""
        if confidence <= LOW_CONFIDENCE and combined_ev >= STRONG_EVIDENCE:
            blind_spot = True
            reason = "undersell: low self-confidence but strong D/E evidence"
        elif confidence >= HIGH_CONFIDENCE and combined_ev == 0.0:
            blind_spot = True
            reason = "over-confidence: high self-confidence but no D/E evidence"

        scores[f] = FieldScore(
            field=f,
            career=FIELD_TO_CAREER[f],
            interest=_round1(interest),
            skill=_round1(skill),
            confidence=round(confidence, 2),
            evidence_d=e_d,
            evidence_e=e_e,
            forced_choice_wins=wins[f],
            only_self_claim=only_self_claim,
            low_confidence_skill=low_confidence_skill,
            blind_spot=blind_spot,
            blind_spot_reason=reason,
        )
    return scores


def build_profile(answers: dict) -> CandidatePreferenceProfile:
    """Score answers and pack them into the generic preference contract."""
    scores = score_answers(answers)
    fields: dict[str, FieldProfile] = {}
    blind_spots: list[str] = []
    for f in FIELDS:
        s = scores[f]
        fields[s.career] = FieldProfile(
            interest=s.interest,
            skill=s.skill,
            confidence=s.confidence,
        )
        if s.blind_spot:
            blind_spots.append(s.career)
    # Emit in canonical CAREERS order.
    ordered = {c: fields[c] for c in CAREERS}
    return CandidatePreferenceProfile(fields=ordered, blind_spots=blind_spots)


# --------------------------------------------------------------------------- #
# IO.
# --------------------------------------------------------------------------- #
def load_answers(path: str | Path = DEFAULT_ANSWERS) -> dict:
    """Load a filled answer set; returns the inner `answers` mapping."""
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return doc.get("answers", {}) or {}


def profile_to_config_block(profile: CandidatePreferenceProfile) -> dict[str, Any]:
    """Render a profile as the ``candidate_preferences`` configuration block."""
    block: dict[str, Any] = {}
    for career in CAREERS:
        fp = profile.fields.get(career)
        if fp is None:
            fp = FieldProfile(interest=0.0, skill=0.0, confidence=0.0)
        block[career] = {
            "interest": fp.interest,
            "skill": fp.skill,
            "confidence": fp.confidence,
        }
    block["blind_spots"] = list(profile.blind_spots)
    return block


def write_profile(profile: CandidatePreferenceProfile, path: str | Path = DEFAULT_OUTPUT,
                  force: bool = False) -> Path:
    """Write preferences under a top-level ``candidate_preferences`` key.

    GUARD: refuses to overwrite a REAL (calibrated, non-v1) profile at the
    target path unless force=True. The live profile is real excavation data;
    scoring the SAMPLE answers must never silently clobber it.
    (Bug caught 2026-07-14 — test run overwrote the v2-excavation profile.)
    """
    path = Path(path)
    if path.exists() and not force:
        try:
            existing = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            existing_version = str((existing.get("meta") or {}).get("version", ""))
        except Exception:  # noqa: BLE001 — unreadable file: treat as precious
            existing_version = "unknown"
        if existing_version and not existing_version.startswith("v1-guided-pass"):
            raise RuntimeError(
                f"REFUSING to overwrite {path} — it holds a real profile "
                f"(version {existing_version!r}), not v1 sample output. "
                f"Pass force=True (or write elsewhere) if you really mean it."
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    block = profile_to_config_block(profile)
    doc = {
        "meta": {
            "produced_by": "profiler/score_profile.py",
            "version": "v1-guided-pass",
            "uncertainty": "high (all skill priors provisional in v1)",
        },
        "candidate_preferences": block,
    }
    path.write_text(
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False),
        encoding="utf-8",
    )
    return path


def run(answers_path: str | Path = DEFAULT_ANSWERS,
        output_path: str | Path = DEFAULT_OUTPUT) -> CandidatePreferenceProfile:
    """End-to-end: load answers, score them, and write the preferences."""
    answers = load_answers(answers_path)
    profile = build_profile(answers)
    write_profile(profile, output_path)
    return profile


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--answers", type=Path, default=DEFAULT_ANSWERS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    prof = build_profile(load_answers(args.answers))
    write_profile(prof, args.output, force=args.force)
    print(f"Wrote {args.output}")
    print("Per-field (interest / skill / confidence):")
    for career in CAREERS:
        fp = prof.fields[career]
        print(f"  {career:<16} interest={fp.interest:>4}  skill={fp.skill:>4}  confidence={fp.confidence:>4}")
    print(f"blind_spots: {prof.blind_spots}")
