"""Positive controls for operator-supplied ranked-snapshot documents."""

from __future__ import annotations

import hashlib
import json

from career_automation.live_canary_authority import _content_hash
from career_automation.live_canary_snapshot_document import (
    DOCUMENT_SCHEMA,
    MAX_DOCUMENT_BYTES,
    parse_operator_snapshot_document,
)
from test_jaa11_live_canary_fixture_dry_run import _snapshot


def _document(
    snapshot: dict[str, object] | None = None,
    *,
    pretty: bool = False,
) -> bytes:
    return json.dumps(
        snapshot or _snapshot(21),
        ensure_ascii=False,
        indent=2 if pretty else None,
        sort_keys=pretty,
        separators=None if pretty else (",", ":"),
    ).encode("utf-8")


def test_minimal_document_is_normalized_and_hash_bound() -> None:
    raw = _document()
    result = parse_operator_snapshot_document(raw)
    assert result.operator_document_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.normalized_fixture_sha256 == result.snapshot.snapshot_sha256
    assert result.normalized_fixture_sha256 == _content_hash(_snapshot(21))
    assert result.schema_version == DOCUMENT_SCHEMA
    assert len(result.bounded_document_sha256) == 64


def test_large_document_and_exact_size_limit_are_accepted() -> None:
    large = parse_operator_snapshot_document(_document(_snapshot(200)))
    assert len(large.snapshot.entries) == 200
    compact = _document()
    exact_limit = compact + b" " * (MAX_DOCUMENT_BYTES - len(compact))
    result = parse_operator_snapshot_document(exact_limit)
    assert len(exact_limit) == MAX_DOCUMENT_BYTES
    assert len(result.snapshot.entries) == 21


def test_formatting_variants_preserve_only_normalized_hash() -> None:
    compact = _document()
    pretty = _document(pretty=True) + b"\n"
    first = parse_operator_snapshot_document(compact)
    second = parse_operator_snapshot_document(pretty)
    assert first.operator_document_sha256 != second.operator_document_sha256
    assert first.normalized_fixture_sha256 == (
        second.normalized_fixture_sha256
    )


def test_repeated_parsing_is_deterministic() -> None:
    raw = _document(pretty=True)
    assert parse_operator_snapshot_document(raw) == (
        parse_operator_snapshot_document(raw)
    )


def test_disclosures_are_nonoperational_and_round_trip() -> None:
    result = parse_operator_snapshot_document(_document())
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
    assert result.document()["bounded_document_sha256"] == (
        result.bounded_document_sha256
    )
