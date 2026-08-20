"""Positive controls for the bounded JAA-11 operator-answer authority."""

from __future__ import annotations

import hashlib
from pathlib import Path

from career_automation.live_canary_operator_answers import (
    ANSWERS_FILE_SHA256,
    ANSWERS_RELATIVE_PATH,
    APPROVED_SALARY_FREE_TEXT,
    FROZEN_OPERATOR_ANSWERS,
    ApprovedEvidenceReference,
    OperatorAnswerRequest,
    evaluate_operator_answer,
    verify_operator_answers_document,
)


ROOT = Path(__file__).resolve().parent
SOFTWARE_FACTORY_ROOT = ROOT.parent.parent


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _document_evidence(
    topic: str,
    exact_claim: str,
) -> ApprovedEvidenceReference:
    return ApprovedEvidenceReference(
        source_kind="operator_answers_document",
        source_sha256=ANSWERS_FILE_SHA256,
        topic=topic,
        exact_claim=exact_claim,
    )


def test_exact_document_bytes_bind_to_frozen_authority() -> None:
    document_path = SOFTWARE_FACTORY_ROOT / ANSWERS_RELATIVE_PATH
    document_bytes = document_path.read_bytes()
    authority = verify_operator_answers_document(document_bytes)

    assert hashlib.sha256(document_bytes).hexdigest() == ANSWERS_FILE_SHA256
    assert authority is FROZEN_OPERATOR_ANSWERS
    assert authority.path_base == "software_factory_root"
    assert authority.relative_path == ANSWERS_RELATIVE_PATH
    assert authority.operational_release == "withheld"
    assert authority.may_submit is False
    assert authority.external_action_capability is False
    assert authority.real_applications == 0
    assert len(authority.record_sha256) == 64


def test_relocation_willingness_is_permitted_without_narrower_claim() -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="relocation",
            answer_kind="boolean",
            subtopic="willing_to_relocate",
            evidence=_document_evidence(
                "relocation",
                "willing_to_relocate",
            ),
        ),
    )
    assert decision.status == "ANSWER_PERMITTED"
    assert decision.answer is True
    assert decision.operational_release == "withheld"
    assert decision.may_submit is False
    assert decision.external_action_capability is False
    assert decision.real_applications == 0


def test_jurisdiction_specific_work_authorisation_can_be_permitted() -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="work_authorisation",
            answer_kind="boolean",
            jurisdiction="United Kingdom",
            evidence=ApprovedEvidenceReference(
                source_kind="identity_work_rights_ledger",
                source_sha256=_hash("approved-uk-work-rights-evidence"),
                topic="work_authorisation",
                exact_claim="current_work_authorisation",
                jurisdiction="United Kingdom",
            ),
        ),
    )
    assert decision.status == "ANSWER_PERMITTED"
    assert decision.answer is True
    assert decision.reasons == (
        "jurisdiction_specific_work_rights_verified",
    )


def test_explicit_current_work_authorisation_subtopic_is_permitted() -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="work_authorisation",
            answer_kind="boolean",
            subtopic="current_work_authorisation",
            jurisdiction="United Kingdom",
            evidence=ApprovedEvidenceReference(
                source_kind="identity_work_rights_ledger",
                source_sha256=_hash("approved-uk-work-rights-evidence"),
                topic="work_authorisation",
                exact_claim="current_work_authorisation",
                jurisdiction="United Kingdom",
            ),
        ),
    )
    assert decision.status == "ANSWER_PERMITTED"
    assert decision.answer is True
    assert decision.reasons == (
        "jurisdiction_specific_work_rights_verified",
    )


def test_salary_free_text_is_exact_constant_not_generated() -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="salary",
            answer_kind="free_text",
            evidence=_document_evidence(
                "salary",
                "market_competitive_statutory_minimum_free_text",
            ),
        ),
    )
    assert decision.status == "ANSWER_PERMITTED"
    assert decision.answer == APPROVED_SALARY_FREE_TEXT
    assert (
        decision.answer
        == "Flexible and open to a market-competitive package appropriate "
        "to the role; any offer must meet applicable statutory minimums."
    )


def test_explicit_salary_free_text_subtopic_is_permitted() -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="salary",
            answer_kind="free_text",
            subtopic="market_competitive_statutory_minimum_free_text",
            evidence=_document_evidence(
                "salary",
                "market_competitive_statutory_minimum_free_text",
            ),
        ),
    )
    assert decision.status == "ANSWER_PERMITTED"
    assert decision.answer == APPROVED_SALARY_FREE_TEXT
    assert decision.reasons == (
        "exact_operator_approved_salary_free_text",
    )


def test_numeric_salary_requires_floor_and_market_basis() -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="salary",
            answer_kind="numeric",
            role_location="London, United Kingdom",
            age_basis="age-21-and-over",
            hours=40,
            compensation_period="annual_gbp_minor_units",
            statutory_floor_minor_units=2_500_000,
            proposed_salary_minor_units=4_500_000,
            law_evidence_sha256=_hash("current-authoritative-uk-law"),
            market_range_evidence_sha256=_hash(
                "market-range-for-role-and-location"
            ),
        ),
    )
    assert decision.status == "ANSWER_PERMITTED"
    assert decision.answer == 4_500_000
    assert decision.reasons == (
        "numeric_salary_meets_verified_floor_and_market_basis",
    )
