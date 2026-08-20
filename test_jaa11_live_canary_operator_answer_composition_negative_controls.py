"""Fail-closed controls for operator-answer composition."""

from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation.live_canary_operator_answer_composition import (
    MAX_ANSWER_REQUESTS,
    compose_operator_answers_dry_run,
)
from career_automation.live_canary_operator_answers import OperatorAnswerRequest
from test_jaa11_live_canary_operator_answer_composition import (
    _answers_bytes,
    _composition,
    _relocation,
)
from test_jaa11_live_canary_operator_document_intake import _intake


MODULE = (
    Path(__file__).resolve().parent
    / "career_automation/live_canary_operator_answer_composition.py"
)


@pytest.mark.parametrize("value", (b"", b"tampered", None, "not-bytes"))
def test_invalid_answer_document_bytes_fail_closed(value: object) -> None:
    with pytest.raises(ValueError):
        compose_operator_answers_dry_run(_intake(), value, (_relocation(),))


def test_wrong_or_tampered_intake_fails_closed() -> None:
    with pytest.raises(ValueError):
        compose_operator_answers_dry_run(
            object(), _answers_bytes(), (_relocation(),)
        )
    result = _composition()
    with pytest.raises(ValueError):
        replace(result, intake_sha256="0" * 64)


@pytest.mark.parametrize(
    "requests",
    (
        (),
        [_relocation()],
        tuple(_relocation() for _ in range(MAX_ANSWER_REQUESTS + 1)),
        (object(),),
    ),
)
def test_unbounded_or_wrong_request_collections_fail_closed(
    requests: object,
) -> None:
    with pytest.raises(ValueError):
        compose_operator_answers_dry_run(_intake(), _answers_bytes(), requests)


def test_duplicate_topic_and_subtopic_fails_the_whole_composition() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        compose_operator_answers_dry_run(
            _intake(), _answers_bytes(), (_relocation(), _relocation())
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("positive_evidence_is_fixture_only", False),
        ("snapshot_source", "system_acquired"),
        ("acquired_by_system", True),
        ("snapshot_is_live", True),
        ("snapshot_is_current", True),
        ("selected_vacancy_status", "selected"),
        ("answers_used_for_external_submission", True),
        ("operational_release", "granted"),
        ("may_submit", True),
        ("external_action_capability", True),
        ("certifies_slice", True),
        ("receipt_written", True),
        ("real_applications", 1),
        ("schema_version", "jaa11.live-canary-answer-composition.v2"),
    ),
)
def test_every_boundary_flip_is_rejected(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        replace(_composition(), **{field: value})


def test_item_hash_authority_order_and_count_tampering_is_rejected() -> None:
    result = _composition(
        _relocation(),
        OperatorAnswerRequest(topic="benefits", answer_kind="free_text"),
    )
    with pytest.raises(ValueError):
        replace(result.items[0], request_sha256="0" * 64)
    with pytest.raises(ValueError):
        replace(result.items[0], decision_sha256="0" * 64)
    with pytest.raises(ValueError):
        replace(
            result.items[0].decision,
            authority_record_sha256="0" * 64,
        )
    with pytest.raises(ValueError):
        replace(result, items=tuple(reversed(result.items)))
    with pytest.raises(ValueError):
        replace(result, permitted_count=0)
    with pytest.raises(ValueError):
        replace(result, answer_composition_sha256="0" * 64)


def test_dropped_item_without_resealed_record_is_rejected() -> None:
    result = _composition(
        _relocation(),
        OperatorAnswerRequest(topic="benefits", answer_kind="free_text"),
    )
    with pytest.raises(ValueError):
        replace(result, items=result.items[:1])


def test_module_import_surface_has_no_external_or_nondeterministic_capability() -> None:
    tree = ast.parse(MODULE.read_text())
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert not imports.intersection(
        {"asyncio", "http", "io", "os", "random", "requests", "socket", "time", "urllib"}
    )
    source = MODULE.read_text()
    for forbidden in ("open(", "subprocess", "http://", "https://"):
        assert forbidden not in source
