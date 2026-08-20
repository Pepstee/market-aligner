"""Positive controls for exact-byte operator-document intake."""

from __future__ import annotations

import hashlib

from career_automation.live_canary_authority import _content_hash
from career_automation.live_canary_operator_document_intake import (
    INTAKE_SCHEMA,
    intake_operator_document_dry_run,
)
from career_automation.live_canary_operator_fixture_composition import (
    compose_operator_document_dry_run,
)
from career_automation.live_canary_snapshot_document import (
    parse_operator_snapshot_document,
)
from test_jaa11_live_canary_fixture_dry_run import _evidence
from test_jaa11_live_canary_snapshot_document import _document


def _intake(*, pretty: bool = False):
    raw = _document(pretty=pretty)
    return intake_operator_document_dry_run(
        raw,
        _evidence(21),
        submission_count=0,
        jaa11_certified=False,
    )


def test_intake_matches_the_manual_accepted_two_call_path() -> None:
    raw = _document()
    manual = compose_operator_document_dry_run(
        parse_operator_snapshot_document(raw),
        _evidence(21),
        submission_count=0,
        jaa11_certified=False,
    )
    result = intake_operator_document_dry_run(
        raw,
        _evidence(21),
        submission_count=0,
        jaa11_certified=False,
    )
    assert result.composition == manual
    assert result.composition.document() == manual.document()


def test_exact_byte_hash_and_length_are_witnessed() -> None:
    raw = _document(pretty=True)
    result = intake_operator_document_dry_run(
        raw,
        _evidence(21),
        submission_count=0,
        jaa11_certified=False,
    )
    assert result.operator_document_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.document_byte_length == len(raw)
    assert result.operator_document_sha256 == (
        result.composition.operator_document_sha256
    )


def test_intake_hash_is_recomputed_and_deterministic() -> None:
    first = _intake()
    second = _intake()
    assert first == second
    assert first.intake_sha256 == _content_hash(
        first.document(include_hash=False)
    )
    assert first.document() == second.document()


def test_output_discloses_only_the_bounded_fixture_state() -> None:
    result = _intake()
    rendered = result.document()
    assert result.schema_version == INTAKE_SCHEMA
    assert rendered["composition"] == result.composition.document()
    assert rendered["intake_sha256"] == result.intake_sha256
    assert set(rendered) - set(result.document(include_hash=False)) == {
        "intake_sha256"
    }
    assert result.snapshot_source == "operator_supplied_document"
    assert result.acquired_by_system is False
    assert result.snapshot_is_live is False
    assert result.snapshot_is_current is False
    assert result.selected_vacancy_status == (
        "operator_supplied_not_selected_for_external_use"
    )
    assert result.operational_release == "withheld"
    assert result.may_submit is False
    assert result.external_action_capability is False
    assert result.certifies_slice is False
    assert result.receipt_written is False
    assert result.real_applications == 0


def test_public_surface_is_exact() -> None:
    from career_automation import live_canary_operator_document_intake

    assert live_canary_operator_document_intake.__all__ == [
        "INTAKE_SCHEMA",
        "OperatorDocumentIntake",
        "intake_operator_document_dry_run",
    ]
