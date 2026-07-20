"""
profiler/test_profiler.py — standalone self-test for the Profiler module.

Feeds the fixture answers (profiler/data/sample_answers.yaml) through the v1
scorer, writes profiler/data/hyun_profile.yaml, and asserts the contract:

  * all ten CAREERS are present in the emitted profile
  * every interest and skill sits in [0, 10]
  * every confidence sits in [0, 1]
  * blind_spots is a list (of career names, each a real CAREER)
  * the written YAML loads back via contracts.HyunProfile.from_config
  * a few known scoring behaviours hold (forced-choice wins, evidence over
    self-claim, the C-only cap, and both blind-spot directions)

Runs alone, no other module needed. Stdlib + pyyaml.
Run:  python profiler/test_profiler.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skeleton"))
sys.path.insert(0, str(_ROOT / "profiler"))

from contracts import CAREERS, HyunProfile  # noqa: E402
import score_profile as sp  # noqa: E402
from instrument.questions import FIELD_TO_CAREER  # noqa: E402


def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def main() -> int:
    answers_path = sp.DEFAULT_ANSWERS
    # NEVER write to sp.DEFAULT_OUTPUT here: that is the LIVE profile file,
    # and the real (v2-excavation) profile lives there. The self-test scores
    # the SAMPLE fixture, so it writes to a sandbox path instead.
    # (Bug caught 2026-07-14: this test used to clobber the real profile.)
    out_path = sp.DATA_DIR / "_selftest" / "hyun_profile.yaml"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    _check(answers_path.exists(), f"missing fixture: {answers_path}")

    # --- run the pipeline -------------------------------------------------
    answers = sp.load_answers(answers_path)
    profile = sp.build_profile(answers)
    written = sp.write_profile(profile, out_path)
    _check(written.exists(), "hyun_profile.yaml was not written")

    # --- contract: all ten careers present -------------------------------
    _check(set(profile.fields.keys()) == set(CAREERS),
           f"profile must contain exactly the ten CAREERS; got {set(profile.fields)}")
    _check(tuple(profile.fields.keys()) == CAREERS,
           "profile fields must be in canonical CAREERS order")

    # --- contract: ranges -------------------------------------------------
    for career, fp in profile.fields.items():
        _check(0.0 <= fp.interest <= 10.0, f"{career} interest {fp.interest} out of [0,10]")
        _check(0.0 <= fp.skill <= 10.0, f"{career} skill {fp.skill} out of [0,10]")
        _check(0.0 <= fp.confidence <= 1.0, f"{career} confidence {fp.confidence} out of [0,1]")

    # --- contract: blind_spots is a list of real careers ------------------
    _check(isinstance(profile.blind_spots, list), "blind_spots must be a list")
    for b in profile.blind_spots:
        _check(b in CAREERS, f"blind_spot '{b}' is not a known career")

    # --- it loads back through the contract from the written YAML ---------
    doc = yaml.safe_load(out_path.read_text(encoding="utf-8")) or {}
    _check("hyun_profile" in doc, "written file has no top-level hyun_profile block")
    reloaded = HyunProfile.from_config(doc)
    _check(set(reloaded.fields.keys()) == set(CAREERS),
           "reloaded profile must carry all ten CAREERS")
    _check(reloaded.blind_spots == profile.blind_spots,
           "blind_spots did not survive the YAML round-trip")
    # Field values survive the round-trip.
    for career in CAREERS:
        a, b = profile.fields[career], reloaded.fields[career]
        _check(abs(a.interest - b.interest) < 1e-9, f"{career} interest changed on reload")
        _check(abs(a.skill - b.skill) < 1e-9, f"{career} skill changed on reload")
        _check(abs(a.confidence - b.confidence) < 1e-9, f"{career} confidence changed on reload")

    # --- scoring-key behaviours (on the known fixture) --------------------
    scores = sp.score_answers(answers)

    # ArchViz (F5) is maxed: loves it, top rank, two forced-choice wins, direct D+E.
    f5 = scores["F5"]
    _check(f5.interest == 10.0, f"F5 interest should cap at 10, got {f5.interest}")
    _check(f5.skill == 10.0, f"F5 skill should be 10 (C=3 + direct D & E), got {f5.skill}")
    _check(f5.forced_choice_wins == 2, f"F5 should have 2 forced-choice wins, got {f5.forced_choice_wins}")

    # Technical_Artist (F9): low self-confidence (C=1) but strong direct D/E ->
    # evidence must lift skill well above the self-claim, and flag an undersell.
    f9 = scores["F9"]
    _check(f9.confidence <= sp.LOW_CONFIDENCE, "F9 confidence should be low")
    _check(f9.skill >= 7.0, f"F9 skill should reflect strong evidence, got {f9.skill}")
    _check(f9.blind_spot and "undersell" in f9.blind_spot_reason,
           "F9 should be flagged as an undersell blind-spot")

    # Motion_Graphic (F10): high-ish self-confidence (C=2) but no D/E evidence ->
    # skill capped at 5 (only self-claim) and flagged as over-confidence.
    f10 = scores["F10"]
    _check(f10.only_self_claim, "F10 should be self-claim only (no D/E evidence)")
    _check(f10.skill <= 5.0, f"F10 skill should be capped at 5, got {f10.skill}")
    _check(f10.blind_spot and "over-confidence" in f10.blind_spot_reason,
           "F10 should be flagged as an over-confidence blind-spot")

    # All skill priors are marked high-uncertainty (low_confidence_skill) in v1.
    _check(all(s.low_confidence_skill for s in scores.values()),
           "every v1 skill prior must be marked high-uncertainty")

    # The mapped careers of the flagged fields appear in the profile blind_spots.
    for fld in (f9, f10):
        _check(FIELD_TO_CAREER[fld.field] in profile.blind_spots,
               f"{fld.field} blind-spot missing from profile.blind_spots")

    # --- report -----------------------------------------------------------
    print("Profiler self-test PASSED")
    print(f"  fixture : {answers_path}")
    print(f"  output  : {out_path}")
    print(f"  careers : {len(profile.fields)}/10 present, all in range")
    print(f"  blind_spots: {profile.blind_spots}")
    print("  per-field (interest / skill / confidence):")
    for career in CAREERS:
        fp = profile.fields[career]
        flag = " *blind-spot*" if career in profile.blind_spots else ""
        print(f"    {career:<16} {fp.interest:>4} / {fp.skill:>4} / {fp.confidence:>4}{flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
