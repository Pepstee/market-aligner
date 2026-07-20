"""
profiler/instrument/questions.py — the v1 Guided Pass encoded as data.

This is the *instrument*: the six sections of Profiler_v1_Guided_Pass.md turned
into machine-readable question data, each with an explicit response TYPE and a
mapping onto the ten canonical CAREERS in skeleton/contracts.py.

Nothing here calls a model or touches personal data — it is a static description
of the questionnaire. The filled-in human answers live in
`profiler/data/sample_answers.yaml`; the scoring key lives in
`profiler/score_profile.py`.

Response TYPES (the vocabulary the scorer understands):
  grid          — two 1–5 ratings per row (enjoy, energy). Section A.
  forced_choice — pick exactly one of two field-tagged options. Section B.
  likert_0_3    — one integer 0..3 per field. Section C.
  text          — one free line per prompt (aptitude signal, tagged later). Section D.
  portfolio     — a list of made-things, each self-tagged to a field. Section E.
  rank          — a full ordering of all ten fields. Section F.

Stdlib only.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Import the frozen canonical career order from the skeleton contract.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "skeleton"))
from contracts import CAREERS  # noqa: E402  (frozen seam)


# --------------------------------------------------------------------------- #
# Field <-> career mapping
# The spec numbers fields F1..F10; the contract names them. This is the single
# authoritative bridge between the two. Order matches contracts.CAREERS.
# --------------------------------------------------------------------------- #
# F1 UX/UI · F2 Spatial/VMD · F3 Exhibition · F4 Brand Space · F5 ArchViz
# F6 3D Generalist · F7 Environment Artist · F8 XR/Spatial XP · F9 Technical
# Artist · F10 Motion/Graphic.
FIELDS: tuple[str, ...] = tuple(f"F{i}" for i in range(1, 11))

FIELD_TO_CAREER: dict[str, str] = {
    "F1": "UX_UI",
    "F2": "Spatial_VMD",
    "F3": "Exhibition",
    "F4": "Brand_Space",
    "F5": "ArchViz",
    "F6": "3D_Generalist",
    "F7": "Environment_Art",
    "F8": "XR_Spatial",
    "F9": "Technical_Artist",
    "F10": "Motion_Graphic",
}
CAREER_TO_FIELD: dict[str, str] = {v: k for k, v in FIELD_TO_CAREER.items()}

# Guard: the mapping must cover exactly the ten contract careers, in order.
assert tuple(FIELD_TO_CAREER.values()) == CAREERS, (
    "FIELD_TO_CAREER must match contracts.CAREERS exactly (order included)."
)


RESPONSE_TYPES: tuple[str, ...] = (
    "grid",
    "forced_choice",
    "likert_0_3",
    "text",
    "portfolio",
    "rank",
)


# --------------------------------------------------------------------------- #
# Section A — Enjoyment & energy grid  (Interest signal)
# One row per field; each row wants two 1–5 numbers: enjoy and energy.
# --------------------------------------------------------------------------- #
SECTION_A = {
    "id": "A",
    "title": "Enjoyment & energy grid",
    "signal": "interest",
    "response_type": "grid",
    "scale": {"enjoy": [1, 5], "energy": [1, 5]},  # hate->love / drained->energised
    "answer_key": "A",  # key under sample_answers.yaml -> answers[...]
    "rows": [
        {"item": "a", "field": "F1", "activity": "Wireframe an app screen and its flow"},
        {"item": "b", "field": "F2", "activity": "Style a shop window / retail display"},
        {"item": "c", "field": "F3", "activity": "Lay out how visitors move through an exhibit"},
        {"item": "d", "field": "F4", "activity": "Design a flagship-store concept for a brand"},
        {"item": "e", "field": "F5", "activity": "Make a photoreal render of a room interior"},
        {"item": "f", "field": "F6", "activity": "Model, texture and light a small scene end-to-end"},
        {"item": "g", "field": "F7", "activity": "Build a game-world outdoor environment"},
        {"item": "h", "field": "F8", "activity": "Design an AR/VR interaction done with the hands"},
        {"item": "i", "field": "F9", "activity": "Fix a slow 3D scene / build a small tool for artists"},
        {"item": "j", "field": "F10", "activity": "Animate a logo or a short poster sequence"},
    ],
}


# --------------------------------------------------------------------------- #
# Section B — Forced choice  (revealed preference)
# Pick exactly one option per pair. Each option is tagged to a field; the winner
# earns a forced-choice win (+1 to that field's Interest, capped later).
# --------------------------------------------------------------------------- #
SECTION_B = {
    "id": "B",
    "title": "Forced choice",
    "signal": "interest",
    "response_type": "forced_choice",
    "answer_key": "B",  # answers["B"] = {"1": "a"|"b", ...}
    "pairs": [
        {"n": 1, "a": {"field": "F2", "label": "style a retail display"},
                 "b": {"field": "F1", "label": "wireframe an app"}},
        {"n": 2, "a": {"field": "F5", "label": "photoreal building render"},
                 "b": {"field": "F7", "label": "game environment"}},
        {"n": 3, "a": {"field": "F10", "label": "animate a logo"},
                 "b": {"field": "F8", "label": "design a VR interaction"}},
        {"n": 4, "a": {"field": "F3", "label": "plan an exhibition path"},
                 "b": {"field": "F4", "label": "design a flagship store"}},
        {"n": 5, "a": {"field": "F6", "label": "end-to-end 3D scene"},
                 "b": {"field": "F9", "label": "fix performance / build artist tools"}},
        {"n": 6, "a": {"field": "F1", "label": "UX research + wireframes"},
                 "b": {"field": "F10", "label": "motion graphics"}},
        {"n": 7, "a": {"field": "F4", "label": "brand-space concept"},
                 "b": {"field": "F5", "label": "ArchViz render"}},
        {"n": 8, "a": {"field": "F7", "label": "environment art"},
                 "b": {"field": "F8", "label": "XR interaction"}},
    ],
}


# --------------------------------------------------------------------------- #
# Section C — Could you do it?  (confidence — a note, not proof)
# One 0..3 integer per field.
#   0 = no idea how · 1 = with a lot of learning · 2 = with a bit of practice
#   3 = I could do a decent job today
# --------------------------------------------------------------------------- #
SECTION_C = {
    "id": "C",
    "title": "Could you do it?",
    "signal": "confidence",
    "response_type": "likert_0_3",
    "scale": [0, 3],
    "answer_key": "C",  # answers["C"] = {"F1": 0..3, ...}
    "items": [
        {"field": "F1", "deliverable": "a clickable prototype"},
        {"field": "F2", "deliverable": "a styled display"},
        {"field": "F3", "deliverable": "an exhibit layout"},
        {"field": "F4", "deliverable": "a store concept board"},
        {"field": "F5", "deliverable": "a photoreal render"},
        {"field": "F6", "deliverable": "a finished 3D scene"},
        {"field": "F7", "deliverable": "a game environment"},
        {"field": "F8", "deliverable": "an AR/VR demo"},
        {"field": "F9", "deliverable": "a shader or optimisation pass"},
        {"field": "F10", "deliverable": "an animated sequence"},
    ],
}


# --------------------------------------------------------------------------- #
# Section D — What others see  (third-party aptitude — often the truest signal)
# One line each. Free text; the fields each line points at are declared in the
# answer set (which fields, and how directly), so the scorer never has to parse
# prose. evidence_D per field is derived from those tags.
# --------------------------------------------------------------------------- #
SECTION_D = {
    "id": "D",
    "title": "What others see",
    "signal": "skill_evidence",
    "response_type": "text",
    "answer_key": "D",  # answers["D"] = [{"answer": "...", "fields": {"F9": "direct"}}]
    "prompts": [
        {"n": 1, "prompt": "What do people come to you for help with?"},
        {"n": 2, "prompt": "What have you lost track of time doing?"},
        {"n": 3, "prompt": "What do you redo until it's right even when no one asked?"},
        {"n": 4, "prompt": "What have you been praised or paid for?"},
        {"n": 5, "prompt": "What do you pick up faster than people around you?"},
    ],
    # How a per-field tag on an answer maps to an evidence weight (spec: 0/0.5/1).
    "evidence_levels": {"none": 0.0, "indirect": 0.5, "direct": 1.0},
}


# --------------------------------------------------------------------------- #
# Section E — Proof of work  (revealed aptitude — rough now)
# Up to 5 made-things; each self-tagged to the field it's closest to, with how
# directly it evidences that field.
# --------------------------------------------------------------------------- #
SECTION_E = {
    "id": "E",
    "title": "Proof of work",
    "signal": "skill_evidence",
    "response_type": "portfolio",
    "answer_key": "E",  # answers["E"] = [{"what":..,"you_did":..,"field":"F5","evidence":"direct"}]
    "max_items": 5,
    "evidence_levels": {"none": 0.0, "indirect": 0.5, "direct": 1.0},
}


# --------------------------------------------------------------------------- #
# Section F — Curiosity rank  (self-model)
# A full ordering of all ten fields, most curious first. rank 1 = most curious.
# --------------------------------------------------------------------------- #
SECTION_F = {
    "id": "F",
    "title": "Curiosity rank",
    "signal": "interest",
    "response_type": "rank",
    "answer_key": "F",  # answers["F"] = ["F5","F6",...]  (10 fields, best first)
    "n_fields": len(FIELDS),
}


# Ordered list of the six sections.
SECTIONS: tuple[dict, ...] = (
    SECTION_A,
    SECTION_B,
    SECTION_C,
    SECTION_D,
    SECTION_E,
    SECTION_F,
)

# Lookup by section id ("A".."F").
_BY_ID = {s["id"]: s for s in SECTIONS}


def section(section_id: str) -> dict:
    """Return one section's encoded data by its id (A..F)."""
    return _BY_ID[section_id]


def all_fields() -> tuple[str, ...]:
    """The ten field codes F1..F10 in canonical (contract) order."""
    return FIELDS


# --------------------------------------------------------------------------- #
# Self-checks: the instrument must be internally consistent.
# --------------------------------------------------------------------------- #
def _validate() -> None:
    # Every response type used is a declared type.
    for s in SECTIONS:
        assert s["response_type"] in RESPONSE_TYPES, s

    # Section A: exactly one row per field, all ten covered.
    a_fields = [r["field"] for r in SECTION_A["rows"]]
    assert sorted(a_fields) == sorted(FIELDS), "Section A must cover all ten fields once"

    # Section B: every option references a real field.
    for p in SECTION_B["pairs"]:
        assert p["a"]["field"] in FIELDS and p["b"]["field"] in FIELDS, p

    # Section C: one item per field, all ten covered.
    c_fields = [i["field"] for i in SECTION_C["items"]]
    assert sorted(c_fields) == sorted(FIELDS), "Section C must cover all ten fields once"

    # Section F must rank all ten.
    assert SECTION_F["n_fields"] == len(FIELDS)


_validate()


if __name__ == "__main__":  # pragma: no cover
    print(f"instrument OK — {len(SECTIONS)} sections, {len(FIELDS)} fields.")
    for s in SECTIONS:
        print(f"  Section {s['id']}: {s['title']:<24} type={s['response_type']:<13} signal={s['signal']}")
    print("field -> career:")
    for f in FIELDS:
        print(f"  {f:<4} -> {FIELD_TO_CAREER[f]}")
