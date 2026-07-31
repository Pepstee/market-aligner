"""Positive controls for operator-document fixture-dry-run composition."""

from __future__ import annotations

import re

from career_automation.live_canary_authority import _content_hash
from career_automation.live_canary_operator_fixture_composition import (
    COMPOSITION_SCHEMA,
    compose_operator_document_dry_run,
)
from career_automation.live_canary_snapshot_document import (
    parse_operator_snapshot_document,
)
from test_jaa11_live_canary_fixture_dry_run import _evidence
from test_jaa11_live_canary_snapshot_document import _document


def _composition(*, pretty: bool = False, selected_rank: int = 21):
    document = parse_operator_snapshot_document(_document(pretty=pretty))
    return compose_operator_document_dry_run(
        document,
        _evidence(selected_rank),
        submission_count=0,
        jaa11_certified=False,
    )


def test_rank_21_composition_binds_the_complete_hash_chain() -> None:
    result = _composition()
    hashes = (
        result.operator_document_sha256,
        result.normalized_fixture_sha256,
        result.bounded_document_sha256,
        result.ranked_snapshot_sha256,
        result.selected_entry_sha256,
        result.dry_run_sha256,
        result.composition_sha256,
    )
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
    assert result.normalized_fixture_sha256 == (
        result.ranked_snapshot_sha256
    )
    assert result.normalized_fixture_sha256 == (
        result.operator_document.snapshot.snapshot_sha256
    )
    assert result.composition_sha256 == _content_hash(
        result.document(include_hash=False)
    )


def test_selection_is_delegated_and_bound_to_the_operator_snapshot() -> None:
    result = _composition()
    assert result.dry_run.selected_entry == (
        result.operator_document.snapshot.entries[20]
    )
    assert result.dry_run.selection_contract.ranked_snapshot_sha256 == (
        result.ranked_snapshot_sha256
    )
    assert result.dry_run.selection_contract.selected_entry_sha256 == (
        result.selected_entry_sha256
    )


def test_identical_compositions_are_deterministic() -> None:
    first = _composition()
    second = _composition()
    assert first == second
    assert first.document() == second.document()
    assert first.composition_sha256 == second.composition_sha256


def test_formatting_variants_preserve_only_normalized_snapshot_bindings() -> None:
    compact = _composition()
    pretty = _composition(pretty=True)
    assert compact.operator_document_sha256 != (
        pretty.operator_document_sha256
    )
    assert compact.bounded_document_sha256 != (
        pretty.bounded_document_sha256
    )
    assert compact.normalized_fixture_sha256 == (
        pretty.normalized_fixture_sha256
    )
    assert compact.ranked_snapshot_sha256 == pretty.ranked_snapshot_sha256
    assert compact.selected_entry_sha256 == pretty.selected_entry_sha256
    assert compact.dry_run_sha256 == pretty.dry_run_sha256
    assert compact.composition_sha256 != pretty.composition_sha256


def test_disclosures_round_trip_without_external_authority() -> None:
    result = _composition()
    rendered = result.document()
    without_hash = result.document(include_hash=False)
    assert result.schema_version == COMPOSITION_SCHEMA
    assert rendered["operator_document"] == (
        result.operator_document.document()
    )
    assert rendered["dry_run"] == result.dry_run.document()
    assert rendered["composition_sha256"] == result.composition_sha256
    assert set(rendered) - set(without_hash) == {"composition_sha256"}
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
