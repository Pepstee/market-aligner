"""Fail-closed controls for operator-supplied snapshot documents."""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
import inspect
import json

import pytest

import career_automation.live_canary_snapshot_document as document_module
from career_automation.live_canary_snapshot_document import (
    MAX_DOCUMENT_BYTES,
    parse_operator_snapshot_document,
)
from test_jaa11_live_canary_fixture_dry_run import _snapshot
from test_jaa11_live_canary_snapshot_document import _document


@pytest.mark.parametrize(
    "value",
    ("{}", bytearray(b"{}"), memoryview(b"{}"), {}, None),
)
def test_only_exact_bytes_are_accepted(value: object) -> None:
    with pytest.raises(ValueError, match="exact bytes"):
        parse_operator_snapshot_document(value)


def test_empty_oversized_and_bom_documents_fail_closed() -> None:
    with pytest.raises(ValueError, match="empty"):
        parse_operator_snapshot_document(b"")
    with pytest.raises(ValueError, match="size limit"):
        parse_operator_snapshot_document(b" " * (MAX_DOCUMENT_BYTES + 1))
    with pytest.raises(ValueError, match="BOM"):
        parse_operator_snapshot_document(b"\xef\xbb\xbf" + _document())


@pytest.mark.parametrize(
    "raw",
    (
        b"\x80",
        b"\xe2\x82",
        b"\xc0\xaf",
        b"{",
        b"{} trailing",
        b'{"ranking_algorithm":"\\ud800"}',
    ),
)
def test_invalid_encoding_json_and_surrogates_fail_closed(raw: bytes) -> None:
    with pytest.raises(ValueError):
        parse_operator_snapshot_document(raw)


@pytest.mark.parametrize(
    "raw",
    (
        b'{"schema_version":"x","schema_version":"y"}',
        (
            b'{"schema_version":"x","ranking_algorithm":"a",'
            b'"ranking_version":"v","snapshot_taken_at":"t",'
            b'"entries":[{"rank":1,"rank":1}]}'
        ),
        (
            b'{"schema_version":"x","ranking_algorithm":"a",'
            b'"ranking_version":"v","snapshot_taken_at":"t",'
            b'"entries":[],"entries":[]}'
        ),
    ),
)
def test_duplicate_keys_at_every_level_fail_closed(raw: bytes) -> None:
    with pytest.raises(ValueError, match="duplicate keys"):
        parse_operator_snapshot_document(raw)


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_nonfinite_json_constants_fail_closed(constant: str) -> None:
    raw = (
        '{"schema_version":"x","ranking_algorithm":'
        f"{constant}"
        ',"ranking_version":"v","snapshot_taken_at":"t","entries":[]}'
    ).encode()
    with pytest.raises(ValueError, match="constant"):
        parse_operator_snapshot_document(raw)


@pytest.mark.parametrize(
    "value",
    ([], "text", 1, True, None),
)
def test_nonobject_top_level_is_delegated_and_rejected(value: object) -> None:
    with pytest.raises(ValueError, match="strict object"):
        parse_operator_snapshot_document(json.dumps(value).encode())


def _entries(snapshot: dict[str, object]) -> list[dict[str, object]]:
    entries = snapshot["entries"]
    assert isinstance(entries, list)
    return entries


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_schema",
        "missing_snapshot_key",
        "unknown_snapshot_key",
        "missing_entry_key",
        "unknown_entry_key",
        "underfilled",
        "rank_gap",
        "rank_bool",
        "duplicate_identity",
        "duplicate_url",
        "http_url",
        "fragment_url",
        "credential_url",
        "uppercase_digest",
        "short_digest",
        "naive_snapshot_time",
        "noncanonical_snapshot_time",
        "retrieval_postdates_snapshot",
    ),
)
def test_snapshot_schema_failures_are_delegated(
    mutation: str,
) -> None:
    snapshot = deepcopy(_snapshot(21))
    entries = _entries(snapshot)
    if mutation == "wrong_schema":
        snapshot["schema_version"] = "wrong"
    elif mutation == "missing_snapshot_key":
        del snapshot["ranking_version"]
    elif mutation == "unknown_snapshot_key":
        snapshot["unknown"] = True
    elif mutation == "missing_entry_key":
        del entries[0]["vacancy_identity"]
    elif mutation == "unknown_entry_key":
        entries[0]["unknown"] = True
    elif mutation == "underfilled":
        snapshot["entries"] = entries[:20]
    elif mutation == "rank_gap":
        entries[1]["rank"] = 3
    elif mutation == "rank_bool":
        entries[0]["rank"] = True
    elif mutation == "duplicate_identity":
        entries[1]["vacancy_identity"] = entries[0]["vacancy_identity"]
    elif mutation == "duplicate_url":
        entries[1]["vacancy_url"] = entries[0]["vacancy_url"]
    elif mutation == "http_url":
        entries[0]["vacancy_url"] = "http://jobs.example.test/1"
    elif mutation == "fragment_url":
        entries[0]["vacancy_url"] += "#fragment"
    elif mutation == "credential_url":
        entries[0]["vacancy_url"] = "https://user@jobs.example.test/1"
    elif mutation == "uppercase_digest":
        entries[0]["vacancy_content_sha256"] = "A" * 64
    elif mutation == "short_digest":
        entries[0]["vacancy_content_sha256"] = "0" * 63
    elif mutation == "naive_snapshot_time":
        snapshot["snapshot_taken_at"] = "2026-07-31T12:00:00"
    elif mutation == "noncanonical_snapshot_time":
        snapshot["snapshot_taken_at"] = "2026-07-31T11:00:00Z"
    elif mutation == "retrieval_postdates_snapshot":
        entries[0]["vacancy_retrieved_at"] = "2026-07-31T12:01:00+01:00"
    with pytest.raises(ValueError):
        parse_operator_snapshot_document(_document(snapshot))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("operator_document_sha256", "1" * 64),
        ("normalized_fixture_sha256", "1" * 64),
        ("bounded_document_sha256", "1" * 64),
        ("snapshot_source", "live"),
        ("acquired_by_system", True),
        ("snapshot_is_live", True),
        ("snapshot_is_current", True),
        ("selected_vacancy_status", "selected"),
        ("operational_release", "released"),
        ("may_submit", True),
        ("external_action_capability", True),
        ("certifies_slice", True),
        ("receipt_written", True),
        ("real_applications", 1),
        ("schema_version", "wrong"),
    ),
)
def test_frozen_result_rejects_hash_or_boundary_tampering(
    field: str,
    value: object,
) -> None:
    result = parse_operator_snapshot_document(_document())
    with pytest.raises(ValueError):
        replace(result, **{field: value})


def test_module_has_no_external_or_selection_capability() -> None:
    source = inspect.getsource(document_module)
    tree = ast.parse(source)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert imported <= {
        "__future__",
        "hashlib",
        "json",
        "dataclasses",
        "career_automation",
    }
    assert "open(" not in source
    assert "compile_live_canary_fixture_dry_run" not in source
    assert "compile_canary_selection" not in source
    assert "evaluate_live_canary_authority" not in source
    for forbidden in (
        "os",
        "pathlib",
        "socket",
        "subprocess",
        "tempfile",
        "datetime",
        "random",
        "secrets",
    ):
        assert forbidden not in imported
