"""Deterministic editable-text rendering for JAA-07 application sources."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .application_compiler import ApplicationSource, verify_application_source


@dataclass(frozen=True)
class EditableArtifacts:
    cv_text: str
    cover_letter_text: str
    answers_text: str
    cv_sha256: str
    cover_letter_sha256: str
    answers_sha256: str


def _join_section(
    source: ApplicationSource,
    heading: str,
    sentence_ids: tuple[str, ...],
    style_slot_ids: tuple[str, ...],
) -> str:
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    values = [heading]
    values.extend(slots[slot_id] for slot_id in style_slot_ids)
    values.extend(facts[sentence_id] for sentence_id in sentence_ids)
    return "\n".join(values)


def render_editable_text(source: ApplicationSource) -> EditableArtifacts:
    """Render plain, single-column editable sources with stable ordering."""
    verify_application_source(source)
    contact = source.contact
    cv_header = "\n".join(
        (contact.full_name, contact.email, contact.phone, contact.city)
    )
    cv = "\n\n".join(
        (
            cv_header,
            *(
                _join_section(
                    source,
                    section.heading,
                    section.sentence_ids,
                    section.style_slot_ids,
                )
                for section in source.cv_sections
            ),
        )
    ) + "\n"
    letter_header = "\n".join(
        (
            contact.full_name,
            contact.email,
            contact.phone,
            contact.city,
            source.role_title,
            source.company_name,
        )
    )
    letter = "\n\n".join(
        (
            letter_header,
            *(
                _join_section(
                    source,
                    section.heading,
                    section.sentence_ids,
                    section.style_slot_ids,
                )
                for section in source.letter_sections
            ),
        )
    ) + "\n"
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    answers = "\n\n".join(
        "\n".join(
            (
                answer.question,
                *(slots[value] for value in answer.style_slot_ids),
                *(facts[value] for value in answer.sentence_ids),
            )
        )
        for answer in source.answers
    )
    if answers:
        answers += "\n"
    return EditableArtifacts(
        cv,
        letter,
        answers,
        hashlib.sha256(cv.encode()).hexdigest(),
        hashlib.sha256(letter.encode()).hexdigest(),
        hashlib.sha256(answers.encode()).hexdigest(),
    )
