"""Adversarial controls for JAA-07 fact, style and ATS source boundaries."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from career_automation.application_compiler import (
    CandidateContact,
    FactualSentence,
    ModelReceipt,
    StyleProposal,
    StyleSlot,
    apply_style_proposal,
    compile_application_source,
    verify_application_source,
)
from career_automation.evidence_matching import canonical_json, content_hash
from test_jaa07_independent_acceptance import (
    DIGEST,
    _employer_fact_document,
    _source,
)


def test_factual_sentence_cannot_paraphrase_or_add_an_unsupported_metric() -> None:
    source, _ = _source()
    fact = source.facts[0]
    with pytest.raises(ValueError, match="equal its approved"):
        replace(fact, text=f"{fact.text} Improved availability by 40%.")


@pytest.mark.parametrize(
    "text",
    (
        "<table><tr><td>hidden</td></tr></table>",
        '<span style="display:none">keywords</span>',
        "![profile](portrait.png)",
        "<svg>graphic</svg>",
    ),
)
def test_tables_graphics_and_hidden_text_fail(text: str) -> None:
    source, _ = _source()
    fact = source.facts[0]
    with pytest.raises(ValueError, match="forbidden rich or hidden"):
        FactualSentence(
            fact.sentence_id,
            text,
            text,
            fact.fact_kind,
            fact.document_kind,
            fact.authority,
            fact.employer_fact_json,
        )


def test_generic_wrong_company_cover_letter_fails() -> None:
    source, strategy = _source()
    with pytest.raises(ValueError, match="company-specific"):
        compile_application_source(
            strategy=strategy,
            job_key=source.job_key,
            role_title=source.role_title,
            company_name="Wrong Target Ltd",
            vacancy_source_identity=source.vacancy_source_identity,
            vacancy_sha256=source.vacancy_sha256,
            contact=source.contact,
            facts=source.facts,
            style_slots=source.style_slots,
            cv_sections=source.cv_sections,
            letter_sections=source.letter_sections,
            answers=source.answers,
        )


def test_style_critic_cannot_add_metrics_contacts_or_ai_cliches() -> None:
    for text in (
        "Improved delivery by 40 percent.",
        "Improved delivery by forty percent.",
        "Contact alex@example.test for details.",
        "This is a pivotal opportunity.",
        "Results matter — especially here.",
    ):
        with pytest.raises(ValueError, match="fact-like|natural-language"):
            StyleSlot(content_hash({"text": text}), "answer", text)


def test_style_receipt_and_exact_target_are_mandatory() -> None:
    source, _ = _source()
    slot = source.style_slots[0]
    proposed = "Evidence relevant to the role"
    bad_receipt = ModelReceipt(
        "provider",
        "critic",
        DIGEST,
        DIGEST,
        hashlib.sha256(b"different input").hexdigest(),
        hashlib.sha256(proposed.encode()).hexdigest(),
    )
    with pytest.raises(ValueError, match="input does not match"):
        StyleProposal(
            "0" * 64,
            slot.slot_id,
            slot.text,
            proposed,
            bad_receipt,
        )


def test_tampered_source_and_contact_privacy_fields_fail_closed() -> None:
    source, _ = _source()
    with pytest.raises(ValueError, match="identity differs"):
        verify_application_source(replace(source, role_title="Different Role"))
    with pytest.raises(ValueError, match="city only"):
        CandidateContact(
            "Alex Example",
            "alex@example.test",
            "+44 7700 900123",
            "London, 10 Private Street",
            "contact",
            1,
            DIGEST,
        )


def test_style_proposal_cannot_target_changed_or_unknown_source_slot() -> None:
    source, _ = _source()
    slot = source.style_slots[0]
    proposed = "Evidence relevant to this role"
    receipt = ModelReceipt(
        "provider",
        "critic",
        DIGEST,
        DIGEST,
        hashlib.sha256(slot.text.encode()).hexdigest(),
        hashlib.sha256(proposed.encode()).hexdigest(),
    )
    proposal_id = content_hash(
        {
            "contract": "jaa07.style-proposal.v1",
            "slot_id": slot.slot_id,
            "input_sha256": receipt.input_sha256,
            "output_sha256": receipt.output_sha256,
            "provider": receipt.provider,
            "model": receipt.model,
            "prompt_sha256": receipt.prompt_sha256,
            "policy_sha256": receipt.policy_sha256,
        }
    )
    proposal = StyleProposal(
        proposal_id,
        slot.slot_id,
        slot.text,
        proposed,
        receipt,
    )
    changed = replace(
        source,
        style_slots=tuple(
            replace(row, text="Changed connective prose")
            if row.slot_id == slot.slot_id
            else row
            for row in source.style_slots
        ),
    )
    with pytest.raises(ValueError, match="exact content|exact source"):
        apply_style_proposal(changed, proposal)


def test_employer_sentence_must_match_hashed_fact_not_caller_label() -> None:
    source, _ = _source()
    employer = next(row for row in source.facts if row.fact_kind == "employer")
    changed_text = "Example Ltd operates an unsupported different service."
    with pytest.raises(ValueError, match="exact source-backed fact"):
        replace(
            employer,
            text=changed_text,
            approved_source_text=changed_text,
            employer_fact_json=canonical_json(
                _employer_fact_document(text=changed_text)
            ),
        )
