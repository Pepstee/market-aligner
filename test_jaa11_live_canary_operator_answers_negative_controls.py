"""Fail-closed controls for bounded JAA-11 operator answers."""

from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation.live_canary_operator_answers import (
    ANSWERS_FILE_SHA256,
    FROZEN_OPERATOR_ANSWERS,
    ApprovedEvidenceReference,
    OperatorAnswerRequest,
    OperatorAnswersAuthority,
    evaluate_operator_answer,
    verify_operator_answers_document,
)
from test_jaa11_live_canary_operator_answers import _document_evidence, _hash


ROOT = Path(__file__).resolve().parent
MODULE = ROOT / "career_automation/live_canary_operator_answers.py"


def test_tampered_or_non_byte_document_fails_closed() -> None:
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_operator_answers_document(b"tampered")
    for value in ("text", bytearray(b"bytes"), memoryview(b"bytes"), b""):
        with pytest.raises(ValueError, match="non-empty bytes"):
            verify_operator_answers_document(value)  # type: ignore[arg-type]


def test_out_of_scope_topic_returns_no_answer() -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="desired_benefits",
            answer_kind="free_text",
        ),
    )
    assert decision.status == "OUT_OF_SCOPE"
    assert decision.answer is None
    assert decision.may_submit is False


@pytest.mark.parametrize(
    "subtopic",
    (
        "relocation_date",
        "relocation_destination",
        "self_funded_relocation",
        "relocate_before_offer",
    ),
)
def test_narrower_relocation_commitments_fail_closed(
    subtopic: str,
) -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="relocation",
            answer_kind="boolean",
            subtopic=subtopic,
            evidence=_document_evidence(
                "relocation",
                "willing_to_relocate",
            ),
        ),
    )
    assert decision.status == "FAIL_CLOSED"
    assert decision.answer is None


def test_answer_without_matching_approved_evidence_is_rejected() -> None:
    missing = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="relocation",
            answer_kind="boolean",
        ),
    )
    wrong_claim = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="salary",
            answer_kind="free_text",
            evidence=_document_evidence("salary", "current_salary"),
        ),
    )
    wrong_hash = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="relocation",
            answer_kind="boolean",
            evidence=ApprovedEvidenceReference(
                source_kind="operator_answers_document",
                source_sha256=_hash("wrong-document"),
                topic="relocation",
                exact_claim="willing_to_relocate",
            ),
        ),
    )
    assert {missing.status, wrong_claim.status, wrong_hash.status} == {
        "FAIL_CLOSED"
    }


@pytest.mark.parametrize(
    "subtopic",
    (
        "citizenship",
        "residence",
        "sponsorship",
        "permit_duration",
        "security_clearance",
        "export_control",
        "unrestricted_status",
        "permanent_status",
    ),
)
def test_work_authorisation_conflations_fail_closed(
    subtopic: str,
) -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="work_authorisation",
            answer_kind="boolean",
            subtopic=subtopic,
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
    assert decision.status == "FAIL_CLOSED"


def test_jurisdiction_mismatch_and_unverified_evidence_fail_closed() -> None:
    for evidence in (
        ApprovedEvidenceReference(
            source_kind="identity_work_rights_ledger",
            source_sha256=_hash("france"),
            topic="work_authorisation",
            exact_claim="current_work_authorisation",
            jurisdiction="France",
        ),
        ApprovedEvidenceReference(
            source_kind="identity_work_rights_ledger",
            source_sha256=_hash("uk-unverified"),
            topic="work_authorisation",
            exact_claim="current_work_authorisation",
            jurisdiction="United Kingdom",
            verified=False,
        ),
    ):
        decision = evaluate_operator_answer(
            FROZEN_OPERATOR_ANSWERS,
            OperatorAnswerRequest(
                topic="work_authorisation",
                answer_kind="boolean",
                jurisdiction="United Kingdom",
                evidence=evidence,
            ),
        )
        assert decision.status == "FAIL_CLOSED"
        assert decision.answer is None


def test_sub_statutory_floor_and_incomplete_numeric_salary_fail_closed() -> None:
    complete = OperatorAnswerRequest(
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
    )
    cases = (
        replace(complete, proposed_salary_minor_units=2_499_999),
        replace(complete, law_evidence_sha256=None),
        replace(complete, market_range_evidence_sha256=None),
        replace(complete, role_location=None),
        replace(complete, age_basis=None),
        replace(complete, hours=None),
        replace(complete, compensation_period=None),
    )
    for request in cases:
        decision = evaluate_operator_answer(
            FROZEN_OPERATOR_ANSWERS,
            request,
        )
        assert decision.status == "FAIL_CLOSED"
        assert decision.answer is None


@pytest.mark.parametrize(
    "subtopic",
    (
        "current_salary",
        "desired_benefits",
        "equity_expectations",
        "unpaid_work",
    ),
)
def test_unapproved_salary_inferences_fail_closed(subtopic: str) -> None:
    decision = evaluate_operator_answer(
        FROZEN_OPERATOR_ANSWERS,
        OperatorAnswerRequest(
            topic="salary",
            answer_kind="free_text",
            subtopic=subtopic,
            evidence=_document_evidence(
                "salary",
                "market_competitive_statutory_minimum_free_text",
            ),
        ),
    )
    assert decision.status == "FAIL_CLOSED"


def test_frozen_authority_and_decision_cannot_open_external_boundary() -> None:
    with pytest.raises(ValueError, match="differs from the frozen scope"):
        replace(FROZEN_OPERATOR_ANSWERS, operational_release="granted")
    with pytest.raises(ValueError, match="differs from the frozen scope"):
        replace(FROZEN_OPERATOR_ANSWERS, may_submit=True)
    with pytest.raises(ValueError, match="differs from the frozen scope"):
        replace(FROZEN_OPERATOR_ANSWERS, external_action_capability=True)
    with pytest.raises(ValueError, match="differs from the frozen scope"):
        replace(FROZEN_OPERATOR_ANSWERS, real_applications=1)

    shell = object.__new__(OperatorAnswersAuthority)
    for field, value in vars(FROZEN_OPERATOR_ANSWERS).items():
        object.__setattr__(shell, field, value)
    object.__setattr__(shell, "relative_path", "unaccepted.md")
    decision = evaluate_operator_answer(
        shell,
        OperatorAnswerRequest(
            topic="relocation",
            answer_kind="boolean",
        ),
    )
    assert decision.status == "FAIL_CLOSED"
    assert decision.operational_release == "withheld"
    assert decision.may_submit is False
    assert decision.external_action_capability is False
    assert decision.real_applications == 0


def test_module_import_surface_has_no_io_network_time_or_randomness() -> None:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(
                alias.name.partition(".")[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.partition(".")[0])
    assert imported_roots == {
        "__future__",
        "dataclasses",
        "hashlib",
        "json",
        "re",
        "typing",
    }
    assert ANSWERS_FILE_SHA256 == (
        "670c873479589088a078c871500fa0ae999281f583afb08047dbb95465501652"
    )
