"""Fail-closed controls for operator-document fixture composition."""

from __future__ import annotations

import ast
from dataclasses import replace
import inspect

import pytest

import career_automation.live_canary_operator_fixture_composition as module
from career_automation.live_canary_fixture_dry_run import (
    compile_live_canary_fixture_dry_run,
)
from career_automation.live_canary_operator_fixture_composition import (
    compose_operator_document_dry_run,
)
from career_automation.live_canary_snapshot_document import (
    OperatorSnapshotDocument,
    parse_operator_snapshot_document,
)
from test_jaa11_live_canary_fixture_dry_run import (
    _dry_run,
    _evidence,
    _snapshot,
)
from test_jaa11_live_canary_operator_fixture_composition import _composition
from test_jaa11_live_canary_snapshot_document import _document


class _OperatorDocumentSubclass(OperatorSnapshotDocument):
    pass


@pytest.mark.parametrize(
    "value",
    (
        None,
        {},
        b"{}",
        _snapshot(21),
        _dry_run(_snapshot(21), _evidence(21)),
    ),
)
def test_wrong_document_types_fail_closed(value: object) -> None:
    with pytest.raises(ValueError, match="exact operator document"):
        compose_operator_document_dry_run(
            value,
            _evidence(21),
            submission_count=0,
            jaa11_certified=False,
        )


def test_operator_document_subclass_fails_closed() -> None:
    accepted = parse_operator_snapshot_document(_document())
    subclass = _OperatorDocumentSubclass(**accepted.__dict__)
    with pytest.raises(ValueError, match="exact operator document"):
        compose_operator_document_dry_run(
            subclass,
            _evidence(21),
            submission_count=0,
            jaa11_certified=False,
        )


@pytest.mark.parametrize(
    "field",
    (
        "operator_document_sha256",
        "normalized_fixture_sha256",
        "bounded_document_sha256",
        "snapshot",
    ),
)
def test_post_construction_operator_document_tampering_fails_closed(
    field: str,
) -> None:
    document = parse_operator_snapshot_document(_document())
    value: object = "1" * 64
    if field == "snapshot":
        value = parse_operator_snapshot_document(
            _document(_snapshot(22))
        ).snapshot
    object.__setattr__(document, field, value)
    with pytest.raises(ValueError):
        compose_operator_document_dry_run(
            document,
            _evidence(21),
            submission_count=0,
            jaa11_certified=False,
        )


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("missing", None),
        ("unknown", None),
        ("selected_rank", 1),
        ("selected_rank", 20),
        ("selected_rank", 22),
        ("selected_rank", True),
        ("selected_rank", 21.0),
        ("selected_rank", "21"),
    ),
)
def test_evidence_failures_remain_delegated(
    mutation: str,
    value: object,
) -> None:
    evidence = _evidence(21)
    if mutation == "missing":
        del evidence["truth_gate_passed"]
    elif mutation == "unknown":
        evidence["unknown"] = True
    else:
        evidence[mutation] = value
    document = parse_operator_snapshot_document(_document())
    with pytest.raises(ValueError):
        compose_operator_document_dry_run(
            document,
            evidence,
            submission_count=0,
            jaa11_certified=False,
        )


@pytest.mark.parametrize(
    ("submission_count", "jaa11_certified"),
    (
        (None, False),
        (-1, False),
        (False, False),
        (0.5, False),
        ("0", False),
        (1, False),
        (2, False),
        (0, None),
        (0, "false"),
        (0, True),
    ),
)
def test_authority_failures_remain_delegated(
    submission_count: object,
    jaa11_certified: object,
) -> None:
    document = parse_operator_snapshot_document(_document())
    with pytest.raises(ValueError, match="unavailable or ambiguous"):
        compose_operator_document_dry_run(
            document,
            _evidence(21),
            submission_count=submission_count,  # type: ignore[arg-type]
            jaa11_certified=jaa11_certified,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "field",
    (
        "operator_document_sha256",
        "normalized_fixture_sha256",
        "bounded_document_sha256",
        "ranked_snapshot_sha256",
        "selected_entry_sha256",
        "dry_run_sha256",
        "composition_sha256",
    ),
)
def test_direct_hash_tampering_fails_closed(field: str) -> None:
    with pytest.raises(ValueError):
        replace(_composition(), **{field: "1" * 64})


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
def test_direct_disclosure_tampering_fails_closed(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="cannot open"):
        replace(_composition(), **{field: value})


def test_dry_run_from_a_different_snapshot_breaks_the_bridge() -> None:
    other = compile_live_canary_fixture_dry_run(
        _snapshot(22),
        _evidence(21),
        submission_count=0,
        jaa11_certified=False,
    )
    with pytest.raises(ValueError, match="bridge|operator snapshot"):
        replace(_composition(), dry_run=other)


def test_wrong_dry_run_exact_type_fails_closed() -> None:
    with pytest.raises(ValueError, match="exact fixture dry run"):
        replace(_composition(), dry_run=None)  # type: ignore[arg-type]


def test_post_construction_dry_run_tampering_fails_closed() -> None:
    result = _composition()
    object.__setattr__(result.dry_run, "selected_entry_sha256", "1" * 64)
    with pytest.raises(ValueError, match="selected entry"):
        replace(result)


def test_module_surface_is_exact_and_has_no_external_capability() -> None:
    source = inspect.getsource(module)
    tree = ast.parse(source)
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert imports == {
        "__future__",
        "dataclasses",
        "career_automation.live_canary_authority",
        "career_automation.live_canary_fixture_dry_run",
        "career_automation.live_canary_snapshot_document",
    }
    assert not any(isinstance(node, ast.Import) for node in ast.walk(tree))
    assert module.__all__ == [
        "COMPOSITION_SCHEMA",
        "OperatorFixtureComposition",
        "compose_operator_document_dry_run",
    ]
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
