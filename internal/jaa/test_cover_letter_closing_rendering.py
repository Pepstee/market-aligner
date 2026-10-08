from types import SimpleNamespace

from career_automation.application_compiler import (
    DocumentSection,
    StyleSlot,
    compile_application_source,
)
from career_automation.evidence_matching import content_hash
from career_automation.rendering import _letter_paragraphs
from career_automation.rendering import render_pdf_artifacts
from test_jaa07_independent_acceptance import _source as _jaa07_source


def _source(*, sections, style_slots, facts=()):
    return SimpleNamespace(
        contact=SimpleNamespace(full_name="Alex Example"),
        facts=tuple(
            SimpleNamespace(sentence_id=sentence_id, text=text)
            for sentence_id, text in facts
        ),
        style_slots=tuple(
            SimpleNamespace(slot_id=slot_id, text=text)
            for slot_id, text in style_slots.items()
        ),
        letter_sections=tuple(
            SimpleNamespace(
                sentence_ids=sentence_ids,
                style_slot_ids=style_slot_ids,
            )
            for sentence_ids, style_slot_ids in sections
        ),
    )


def test_typed_closing_slots_preserve_cta_and_fact_with_one_signature():
    source = _source(
        sections=(
            ((), ("salutation",)),
            (("closing_fact",), ("cta", "signoff", "name")),
        ),
        style_slots={
            "salutation": "Dear Hiring Manager",
            "cta": "Thank you for considering my application.",
            "signoff": "Kind regards,",
            "name": "Alex Example",
        },
        facts=(
            (
                "closing_fact",
                "I would welcome a discussion of my experience.",
            ),
        ),
    )

    assert _letter_paragraphs(source) == (
        "Dear Hiring Manager,",
        "Thank you for considering my application. "
        "I would welcome a discussion of my experience.",
        "Kind regards,\nAlex Example",
    )


def test_typed_signoff_normalizes_supported_forms_with_empty_body():
    for supplied, normalized in (
        ("Kind regards", "Kind regards,"),
        ("Kind regards,", "Kind regards,"),
        ("Sincerely", "Sincerely,"),
        ("Sincerely,", "Sincerely,"),
    ):
        source = _source(
            sections=(((), ("signoff", "name")),),
            style_slots={"signoff": supplied, "name": "Alex Example"},
        )

        assert _letter_paragraphs(source) == (
            "Dear Hiring Manager,",
            f"{normalized}\nAlex Example",
        )


def test_existing_combined_signature_slot_remains_unchanged():
    source = _source(
        sections=(
            ((), ("salutation",)),
            ((), ("closing",)),
        ),
        style_slots={
            "salutation": "Dear Hiring Manager,",
            "closing": "Sincerely,\nAlex Example",
        },
    )

    assert _letter_paragraphs(source) == (
        "Dear Hiring Manager,",
        "Sincerely,\nAlex Example",
    )


def test_default_signoff_and_legacy_single_slot_behavior_remain_unchanged():
    default_source = _source(
        sections=(((), ("salutation",)), ((), ("body",))),
        style_slots={
            "salutation": "Dear Hiring Manager,",
            "body": "Thank you for considering my application.",
        },
    )
    combined_source = _source(
        sections=(
            ((), ("salutation",)),
            ((), ("combined",)),
        ),
        style_slots={
            "salutation": "Dear Hiring Manager,",
            "combined": "Kind regards,\nAlex Example",
        },
    )

    assert _letter_paragraphs(default_source) == (
        "Dear Hiring Manager,",
        "Thank you for considering my application.",
        "Kind regards,\nAlex Example",
    )
    assert _letter_paragraphs(combined_source) == (
        "Dear Hiring Manager,",
        "Kind regards,\nAlex Example",
    )


def test_factual_name_and_signoff_phrase_are_not_removed_or_rewritten():
    factual_text = "Alex Example used the phrase Kind regards in a sample."
    source = _source(
        sections=(((), ("salutation",)), (("fact",), ())),
        style_slots={"salutation": "Dear Hiring Manager,"},
        facts=(("fact", factual_text),),
    )

    assert _letter_paragraphs(source) == (
        "Dear Hiring Manager,",
        factual_text,
        "Kind regards,\nAlex Example",
    )


def test_typed_closing_slots_reach_pdf_renderer_once():
    base_source, strategy = _jaa07_source()
    closing_slots = tuple(
        StyleSlot(
            content_hash({"document_kind": "cover_letter", "text": text}),
            "cover_letter",
            text,
        )
        for text in (
            "Thank you for considering my application.",
            "Kind regards,",
            base_source.contact.full_name,
        )
    )
    close_section = DocumentSection(
        "Close",
        base_source.letter_sections[-1].sentence_ids,
        tuple(row.slot_id for row in closing_slots),
    )
    source = compile_application_source(
        strategy=strategy,
        job_key=base_source.job_key,
        role_title=base_source.role_title,
        company_name=base_source.company_name,
        vacancy_source_identity=base_source.vacancy_source_identity,
        vacancy_sha256=base_source.vacancy_sha256,
        contact=base_source.contact,
        facts=base_source.facts,
        style_slots=(*base_source.style_slots, *closing_slots),
        cv_sections=base_source.cv_sections,
        letter_sections=(*base_source.letter_sections[:-1], close_section),
        answers=base_source.answers,
    )

    artifacts = render_pdf_artifacts(source)
    cover_text = " ".join(artifacts.cover_letter_pdf.extracted_text.split())

    assert cover_text.endswith("Kind regards, Alex Example")
    assert cover_text.count("Kind regards,") == 1
