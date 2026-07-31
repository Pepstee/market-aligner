"""Positive controls for fixture-only operator-answer composition."""

from __future__ import annotations

from pathlib import Path

from career_automation.live_canary_authority import _content_hash
from career_automation.live_canary_operator_answer_composition import (
    ANSWER_COMPOSITION_SCHEMA,
    compose_operator_answers_dry_run,
)
from career_automation.live_canary_operator_answers import (
    ANSWERS_RELATIVE_PATH,
    ApprovedEvidenceReference,
    OperatorAnswerRequest,
)
from test_jaa11_live_canary_operator_answers import _document_evidence, _hash
from test_jaa11_live_canary_operator_document_intake import _intake


ROOT = Path(__file__).resolve().parent
SOFTWARE_FACTORY_ROOT = ROOT.parent.parent


def _answers_bytes() -> bytes:
    return (SOFTWARE_FACTORY_ROOT / ANSWERS_RELATIVE_PATH).read_bytes()


def _relocation() -> OperatorAnswerRequest:
    return OperatorAnswerRequest(
        topic="relocation",
        answer_kind="boolean",
        subtopic="willing_to_relocate",
        evidence=_document_evidence("relocation", "willing_to_relocate"),
    )


def _numeric_salary() -> OperatorAnswerRequest:
    return OperatorAnswerRequest(
        topic="salary",
        answer_kind="numeric",
        role_location="London, United Kingdom",
        age_basis="age-21-and-over",
        hours=40,
        compensation_period="annual_gbp_minor_units",
        statutory_floor_minor_units=2_500_000,
        proposed_salary_minor_units=4_500_000,
        law_evidence_sha256=_hash("fixture-current-law"),
        market_range_evidence_sha256=_hash("fixture-market-range"),
    )


def _composition(*requests: OperatorAnswerRequest):
    return compose_operator_answers_dry_run(
        _intake(),
        _answers_bytes(),
        requests or (_relocation(),),
    )


def test_single_permitted_request_binds_the_intake_and_answer_bytes() -> None:
    result = _composition()
    assert result.schema_version == ANSWER_COMPOSITION_SCHEMA
    assert result.permitted_count == 1
    assert result.fail_closed_count == 0
    assert result.out_of_scope_count == 0
    assert result.all_requests_permitted is True
    assert result.items[0].decision.answer is True
    assert result.intake_sha256 == result.intake.intake_sha256
    assert result.composition_sha256 == result.intake.composition_sha256
    assert result.operator_document_sha256 == (
        result.intake.operator_document_sha256
    )
    assert result.dry_run_sha256 == result.intake.composition.dry_run_sha256
    assert result.answer_composition_sha256 == _content_hash(
        result.document(include_hash=False)
    )


def test_mixed_decisions_are_preserved_in_exact_caller_order() -> None:
    sponsorship = OperatorAnswerRequest(
        topic="work_authorisation",
        answer_kind="boolean",
        subtopic="sponsorship",
        jurisdiction="United Kingdom",
        evidence=ApprovedEvidenceReference(
            source_kind="identity_work_rights_ledger",
            source_sha256=_hash("fixture-ledger"),
            topic="work_authorisation",
            exact_claim="current_work_authorisation",
            jurisdiction="United Kingdom",
        ),
    )
    outside = OperatorAnswerRequest(topic="benefits", answer_kind="free_text")
    result = _composition(_relocation(), sponsorship, outside)
    assert [item.index for item in result.items] == [0, 1, 2]
    assert [item.decision.status for item in result.items] == [
        "ANSWER_PERMITTED",
        "FAIL_CLOSED",
        "OUT_OF_SCOPE",
    ]
    assert (result.permitted_count, result.fail_closed_count) == (1, 1)
    assert result.out_of_scope_count == 1
    assert result.all_requests_permitted is False


def test_complete_numeric_salary_fixture_is_preserved_not_reinterpreted() -> None:
    result = _composition(_numeric_salary())
    item = result.items[0]
    assert item.decision.status == "ANSWER_PERMITTED"
    assert item.decision.answer == 4_500_000
    assert result.positive_evidence_is_fixture_only is True
    assert result.answers_used_for_external_submission is False


def test_identical_inputs_are_hash_and_document_deterministic() -> None:
    first = _composition(_relocation(), _numeric_salary())
    second = _composition(_relocation(), _numeric_salary())
    assert first == second
    assert first.document() == second.document()
    assert first.answer_composition_sha256 == (
        second.answer_composition_sha256
    )
    for item in first.items:
        assert item.request_sha256 == _content_hash(item.document()["request"])
        assert item.decision_sha256 == _content_hash(
            item.document()["decision"]
        )


def test_output_keeps_every_external_boundary_closed() -> None:
    result = _composition()
    assert result.snapshot_source == "operator_supplied_document"
    assert result.acquired_by_system is False
    assert result.snapshot_is_live is False
    assert result.snapshot_is_current is False
    assert result.operational_release == "withheld"
    assert result.may_submit is False
    assert result.external_action_capability is False
    assert result.certifies_slice is False
    assert result.receipt_written is False
    assert result.real_applications == 0


def test_public_surface_is_exact() -> None:
    from career_automation import live_canary_operator_answer_composition

    assert live_canary_operator_answer_composition.__all__ == [
        "ANSWER_COMPOSITION_SCHEMA",
        "MAX_ANSWER_REQUESTS",
        "ComposedAnswerItem",
        "OperatorAnswerComposition",
        "compose_operator_answers_dry_run",
    ]
