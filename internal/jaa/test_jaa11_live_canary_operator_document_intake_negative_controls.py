"""Fail-closed controls for exact-byte operator-document intake."""

from __future__ import annotations

import ast
from dataclasses import replace
import inspect

import pytest

import career_automation.live_canary_operator_document_intake as module
from career_automation.live_canary_operator_document_intake import (
    intake_operator_document_dry_run,
)
from career_automation.live_canary_snapshot_document import (
    MAX_DOCUMENT_BYTES,
)
from test_jaa11_live_canary_fixture_dry_run import _evidence
from test_jaa11_live_canary_operator_document_intake import _intake
from test_jaa11_live_canary_snapshot_document import _document


@pytest.mark.parametrize(
    "value",
    ("{}", bytearray(b"{}"), memoryview(b"{}"), None, 1),
)
def test_nonbytes_inputs_are_rejected(value: object) -> None:
    with pytest.raises(ValueError, match="exact bytes"):
        intake_operator_document_dry_run(
            value,
            _evidence(21),
            submission_count=0,
            jaa11_certified=False,
        )


@pytest.mark.parametrize(
    "raw",
    (
        b"",
        b" " * (MAX_DOCUMENT_BYTES + 1),
        b"\xef\xbb\xbf" + _document(),
        b"\x80",
        b"{",
        b'{"schema_version":"x","schema_version":"y"}',
        (
            b'{"schema_version":"x","ranking_algorithm":NaN,'
            b'"ranking_version":"v","snapshot_taken_at":"t","entries":[]}'
        ),
    ),
)
def test_parser_failures_remain_delegated(raw: bytes) -> None:
    with pytest.raises(ValueError):
        intake_operator_document_dry_run(
            raw,
            _evidence(21),
            submission_count=0,
            jaa11_certified=False,
        )


def test_invalid_evidence_remains_delegated() -> None:
    evidence = _evidence(21)
    del evidence["truth_gate_passed"]
    with pytest.raises(ValueError):
        intake_operator_document_dry_run(
            _document(),
            evidence,
            submission_count=0,
            jaa11_certified=False,
        )


@pytest.mark.parametrize(
    ("submission_count", "jaa11_certified"),
    (
        (None, False),
        (1, False),
        (0, None),
        (0, True),
    ),
)
def test_authority_failures_remain_delegated(
    submission_count: int | None,
    jaa11_certified: bool | None,
) -> None:
    with pytest.raises(ValueError, match="unavailable or ambiguous"):
        intake_operator_document_dry_run(
            _document(),
            _evidence(21),
            submission_count=submission_count,
            jaa11_certified=jaa11_certified,
        )


def test_authority_inputs_are_keyword_only() -> None:
    with pytest.raises(TypeError):
        intake_operator_document_dry_run(
            _document(),
            _evidence(21),
            0,
            False,
        )  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("operator_document_sha256", "1" * 64),
        ("composition_sha256", "1" * 64),
        ("intake_sha256", "1" * 64),
        ("document_byte_length", 0),
        ("document_byte_length", -1),
        ("document_byte_length", MAX_DOCUMENT_BYTES + 1),
        ("document_byte_length", True),
    ),
)
def test_direct_hash_and_length_forgery_fails_closed(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValueError):
        replace(_intake(), **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    (
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
def test_every_boundary_forgery_fails_closed(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="cannot open"):
        replace(_intake(), **{field: value})


def test_nonexact_composition_type_fails_closed() -> None:
    with pytest.raises(ValueError, match="exact accepted composition"):
        replace(_intake(), composition=None)  # type: ignore[arg-type]


def test_module_import_surface_is_exact() -> None:
    source = inspect.getsource(module)
    tree = ast.parse(source)
    from_imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    bare_imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert from_imports == {
        "__future__",
        "dataclasses",
        "career_automation.live_canary_authority",
        "career_automation.live_canary_snapshot_document",
        "career_automation.live_canary_operator_fixture_composition",
    }
    assert bare_imports == {"hashlib"}
    for forbidden in (
        "open(",
        "socket",
        "subprocess",
        "random",
        "datetime",
        "time.",
        "requests",
        "playwright",
        "scrap",
    ):
        assert forbidden not in source
