"""One canonical byte identity for live application form answers.

The employer review, rendered artifact set and downstream exact-package contracts
must all hash these exact ``jaa.form-answers.v1`` bytes.  Human-readable text is
only a view of this authority and never a second answer corpus.
"""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Mapping, Sequence

from .evidence_matching import canonical_json


FORM_ANSWERS_SCHEMA_VERSION = "jaa.form-answers.v1"
MAX_FORM_ANSWERS = 200
MAX_FORM_VALUE_BYTES = 8_000


def _canonical_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValueError(f"{label} must be canonical text")
    if (
        "\x00" in value
        or "\r" in value
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ValueError(f"{label} must be canonical NFC Unicode without CR or NUL")
    if len(value.encode("utf-8")) > MAX_FORM_VALUE_BYTES:
        raise ValueError(f"{label} exceeds the v1 byte limit")
    return value


def canonical_form_answers(
    rows: Sequence[tuple[str, str, str]], *, allow_empty: bool = False
) -> tuple[tuple[str, str, str], ...]:
    """Validate the exact ordered live rows with unique ``question_id`` values."""

    values = tuple(rows)
    if not allow_empty and not values:
        raise ValueError("release-compatible form answers cannot be empty")
    if len(values) > MAX_FORM_ANSWERS:
        raise ValueError("form-answer package exceeds the v1 row limit")
    checked: list[tuple[str, str, str]] = []
    for index, row in enumerate(values):
        if not isinstance(row, tuple) or len(row) != 3:
            raise ValueError("form-answer row is malformed")
        checked.append(
            (
                _canonical_text(row[0], f"form answer {index} ID"),
                _canonical_text(row[1], f"form answer {index} question"),
                _canonical_text(
                    row[2], f"form answer {index} answer", allow_empty=True
                ),
            )
        )
    result = tuple(checked)
    if len({row[0] for row in result}) != len(result):
        raise ValueError("form answer question IDs must be unique")
    if tuple(row[0] for row in result) != tuple(sorted(row[0] for row in result)):
        raise ValueError("form answers must use exact ascending question_id order")
    return result


def form_answers_document(
    rows: Sequence[tuple[str, str, str]], *, allow_empty: bool = False
) -> dict[str, object]:
    values = canonical_form_answers(rows, allow_empty=allow_empty)
    return {
        "schema_version": FORM_ANSWERS_SCHEMA_VERSION,
        "form_answers": [
            {"answer": answer, "question": question, "question_id": question_id}
            for question_id, question, answer in values
        ],
    }


def form_answers_bytes(
    rows: Sequence[tuple[str, str, str]], *, allow_empty: bool = False
) -> bytes:
    """Return the sole canonical bytes; deliberately omit a trailing newline."""

    return canonical_json(form_answers_document(rows, allow_empty=allow_empty)).encode(
        "utf-8"
    )


def form_answers_sha256(
    rows: Sequence[tuple[str, str, str]], *, allow_empty: bool = False
) -> str:
    return hashlib.sha256(form_answers_bytes(rows, allow_empty=allow_empty)).hexdigest()


def source_form_answers(
    source: object,
    questions: Mapping[str, tuple[str, str]] | None,
) -> tuple[tuple[str, str, str], ...]:
    """Resolve exact source answers against a complete live question inventory."""

    if questions is None:
        return ()
    inventory: dict[str, str] = {}
    for requirement_id, value in questions.items():
        if (
            not isinstance(requirement_id, str)
            or not isinstance(value, tuple)
            or len(value) != 2
        ):
            raise ValueError("live question inventory is malformed")
        question_id = _canonical_text(value[0], "live question ID")
        question = _canonical_text(value[1], "live question")
        if question_id in inventory:
            raise ValueError("live question inventory has duplicate IDs")
        inventory[question_id] = question
    facts = {row.sentence_id: row.text for row in getattr(source, "facts", ())}
    slots = {row.slot_id: row.text for row in getattr(source, "style_slots", ())}
    answers = tuple(getattr(source, "answers", ()))
    if tuple(inventory) != tuple(answer.question_id for answer in answers):
        raise ValueError(
            "live question inventory order differs from application source"
        )
    rows: list[tuple[str, str, str]] = []
    for answer in answers:
        expected_question = inventory.get(answer.question_id)
        if expected_question != answer.question:
            raise ValueError("application answer differs from live question inventory")
        try:
            text = "\n".join(
                [
                    *(slots[value] for value in answer.style_slot_ids),
                    *(facts[value] for value in answer.sentence_ids),
                ]
            )
        except KeyError as exc:
            raise ValueError("application answer cites missing source content") from exc
        rows.append((answer.question_id, answer.question, text))
    if set(inventory) != {row[0] for row in rows}:
        raise ValueError("live question inventory lacks exact application answers")
    return canonical_form_answers(tuple(rows), allow_empty=False)


def embedded_source_form_answers(source: object) -> tuple[tuple[str, str, str], ...]:
    """Render already inventory-bound structured answers from a source manifest."""

    facts = {row.sentence_id: row.text for row in getattr(source, "facts", ())}
    slots = {row.slot_id: row.text for row in getattr(source, "style_slots", ())}
    rows: list[tuple[str, str, str]] = []
    for answer in getattr(source, "answers", ()):
        try:
            text = "\n".join(
                [
                    *(slots[value] for value in answer.style_slot_ids),
                    *(facts[value] for value in answer.sentence_ids),
                ]
            )
        except KeyError as exc:
            raise ValueError("application answer cites missing source content") from exc
        rows.append((answer.question_id, answer.question, text))
    return canonical_form_answers(tuple(rows), allow_empty=True)


def render_form_answers_text(rows: Sequence[tuple[str, str, str]]) -> str:
    """Render a deterministic inspection view with IDs retained."""

    values = canonical_form_answers(rows, allow_empty=True)
    if not values:
        return ""
    return (
        "\n\n".join(
            f"Question ID: {question_id}\nQuestion: {question}\nAnswer: {answer}"
            for question_id, question, answer in values
        )
        + "\n"
    )


__all__ = [
    "FORM_ANSWERS_SCHEMA_VERSION",
    "canonical_form_answers",
    "embedded_source_form_answers",
    "form_answers_bytes",
    "form_answers_document",
    "form_answers_sha256",
    "render_form_answers_text",
    "source_form_answers",
]
