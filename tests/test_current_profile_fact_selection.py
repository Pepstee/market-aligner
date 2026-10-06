from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from market_aligner.llm.codex_gateway import CodexGatewayError, CodexSemanticGateway


class SelectionRunner:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.prompt = ""
        self.schema: dict[str, Any] = {}

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, kwargs))
        self.prompt = kwargs["input"]
        self.schema = json.loads(
            Path(command[command.index("--output-schema") + 1]).read_text(encoding="utf-8")
        )
        Path(command[command.index("--output-last-message") + 1]).write_text(
            json.dumps(self.response), encoding="utf-8"
        )
        events = (
            {"type": "thread.started", "thread_id": "synthetic"},
            {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "1", "type": "agent_message"}},
            {"type": "turn.completed", "usage": {}},
        )
        return subprocess.CompletedProcess(
            command, 0, stdout="\n".join(json.dumps(event) for event in events), stderr=""
        )


def _records() -> list[dict[str, str]]:
    return [
        {
            "evidence_id": "old-preference",
            "kind": "preferences",
            "status": "explicit",
            "claim": "Synthetic prior preference statement.",
        },
        {
            "evidence_id": "correction-row",
            "kind": "work_history_correction",
            "status": "explicit",
            "claim": "Synthetic correction explicitly retracting the prior preference.",
        },
        {
            "evidence_id": "project-row",
            "kind": "project",
            "status": "verified",
            "claim": "Synthetic project fact with a bounded result.",
        },
        {
            "evidence_id": "inferred-row",
            "kind": "project",
            "status": "inference",
            "claim": "Synthetic inferred fact.",
        },
    ]


def _response() -> dict[str, Any]:
    return {
        "selection": [
            {
                "evidence_id": "project-row",
                "proof_class": "work_artifact",
                "document_targets": ["cv"],
            }
        ],
        "excluded_ids": ["old-preference", "correction-row", "inferred-row"],
        "correction_assessments": [
            {
                "source_evidence_id": "correction-row",
                "relationship": "retracts",
                "affected_evidence_ids": ["old-preference"],
            }
        ],
    }


def _gateway(root: Path, response: dict[str, Any]) -> tuple[CodexSemanticGateway, SelectionRunner]:
    binary = root / "codex"
    binary.write_bytes(b"synthetic codex executable")
    runner = SelectionRunner(response)
    gateway = CodexSemanticGateway(
        model="synthetic-model",
        codex_binary=str(binary),
        environment={"HOME": str(root), "PATH": "/usr/bin"},
        runner=runner,
    )
    return gateway, runner


def test_content_correction_selects_only_source_ids_and_binds_one_call() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), _response())
        result, receipt = gateway.select_current_profile_facts(_records())

    assert result["selection"] == [
        {
            "evidence_id": "project-row",
            "proof_class": "work_artifact",
            "document_targets": ["cv"],
        }
    ]
    assert result["correction_assessments"][0]["affected_evidence_ids"] == [
        "old-preference"
    ]
    assert len(runner.calls) == 1
    assert runner.calls[0][1]["timeout"] > 0
    assert runner.schema["additionalProperties"] is False
    assert "Synthetic correction explicitly retracting the prior preference." in runner.prompt
    assert "source_ref" not in runner.prompt
    assert receipt.transport is not None
    assert receipt.transport.invocation_count == 1


@pytest.mark.parametrize(
    "required_kind",
    ["correction", "retraction", "negative_evidence", "work_history_correction"],
)
def test_required_assessment_source_ids_are_explicit_in_request(
    required_kind: str,
) -> None:
    records = [
        {
            "evidence_id": "project-row",
            "kind": "project",
            "status": "verified",
            "claim": "Synthetic project fact.",
        },
        {
            "evidence_id": "required-row",
            "kind": required_kind,
            "status": "explicit",
            "claim": "Synthetic correction record with no identifiable target.",
        },
    ]
    response = {
        "selection": [
            {
                "evidence_id": "project-row",
                "proof_class": "verified_claim",
                "document_targets": ["cv"],
            }
        ],
        "excluded_ids": ["required-row"],
        "correction_assessments": [
            {
                "source_evidence_id": "required-row",
                "relationship": "unresolved",
                "affected_evidence_ids": [],
            }
        ],
    }
    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), response)
        result, _ = gateway.select_current_profile_facts(records)

    assert result["correction_assessments"] == response["correction_assessments"]
    assert (
        '"required_correction_assessment_source_ids":["required-row"]'
        in runner.prompt
    )
    assert len(runner.calls) == 1


def test_required_assessment_source_ids_reach_dispatch_in_source_order() -> None:
    records = [
        {
            "evidence_id": "required-second",
            "kind": "retraction",
            "status": "explicit",
            "claim": "Synthetic retraction with no identifiable target.",
        },
        {
            "evidence_id": "ordinary-row",
            "kind": "project",
            "status": "verified",
            "claim": "Synthetic project fact.",
        },
        {
            "evidence_id": "required-first",
            "kind": "correction",
            "status": "explicit",
            "claim": "Synthetic correction with no identifiable target.",
        },
    ]
    response = {
        "selection": [
            {
                "evidence_id": "ordinary-row",
                "proof_class": "verified_claim",
                "document_targets": ["cv"],
            }
        ],
        "excluded_ids": ["required-second", "required-first"],
        "correction_assessments": [
            {
                "source_evidence_id": "required-second",
                "relationship": "unresolved",
                "affected_evidence_ids": [],
            },
            {
                "source_evidence_id": "required-first",
                "relationship": "unresolved",
                "affected_evidence_ids": [],
            },
        ],
    }
    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), response)
        gateway.select_current_profile_facts(records)

    assert (
        '"required_correction_assessment_source_ids":'
        '["required-second","required-first"]'
        in runner.prompt
    )
    assert len(runner.calls) == 1


def test_missing_required_assessment_still_fails_closed_with_fixed_error() -> None:
    response = _response()
    response["correction_assessments"] = []
    original_response = json.loads(json.dumps(response))
    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), response)
        with pytest.raises(CodexGatewayError) as error:
            gateway.select_current_profile_facts(_records())

    assert str(error.value) == "current profile correction assessment is incomplete"
    assert response == original_response
    assert len(runner.calls) == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["selection"].append(
            {
                "evidence_id": "correction-row",
                "proof_class": "verified_claim",
                "document_targets": ["cv"],
            }
        ),
        lambda value: value["selection"].append(
            {
                "evidence_id": "inferred-row",
                "proof_class": "verified_claim",
                "document_targets": ["cv"],
            }
        ),
        lambda value: value["correction_assessments"][0].update(
            affected_evidence_ids=["unknown-row"]
        ),
        lambda value: value["correction_assessments"].clear(),
    ],
)
def test_selection_refuses_policy_or_source_mismatch(mutate: Any) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        response = _response()
        mutate(response)
        gateway, runner = _gateway(Path(temporary), response)
        with pytest.raises(CodexGatewayError):
            gateway.select_current_profile_facts(_records())
    assert len(runner.calls) == 1


def _schema_keys(value: Any) -> set[str]:
    if type(value) is dict:
        return set(value).union(*(_schema_keys(item) for item in value.values()))
    if type(value) is list:
        return set().union(*(_schema_keys(item) for item in value))
    return set()


def test_selection_wire_schema_omits_unsupported_unique_items() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), _response())
        result, receipt = gateway.select_current_profile_facts(_records())

    assert "uniqueItems" not in _schema_keys(runner.schema)
    assert result["selection"][0]["evidence_id"] == "project-row"
    assert receipt.transport is not None and receipt.transport.invocation_count == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["selection"][0]["document_targets"].append("cv"),
        lambda value: value["excluded_ids"].append("old-preference"),
        lambda value: value["correction_assessments"][0]["affected_evidence_ids"].append(
            "old-preference"
        ),
    ],
)
def test_selection_locally_rejects_duplicate_ids_and_targets(mutate: Any) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        response = _response()
        mutate(response)
        expected = json.loads(json.dumps(response))
        gateway, runner = _gateway(Path(temporary), response)
        with pytest.raises(CodexGatewayError):
            gateway.select_current_profile_facts(_records())

    assert response == expected
    assert len(runner.calls) == 1


@pytest.mark.parametrize("oversized", [False, True])
def test_selection_refuses_unbound_or_oversized_profile_context_before_dispatch(
    oversized: bool,
) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        context = {
            "schema": "market-aligner.current-profile-selection-context.v1",
            "active_profile_sha256": "a" * 64,
            "constraints": {"limitation": "synthetic only"},
            "blind_spots": [],
            "unknowns": [],
            "exclusions": [],
        }
        if oversized:
            context["constraints"]["limitation"] = "x" * 20_000
        encoded = json.dumps(
            context, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        context_sha256 = hashlib.sha256(encoded).hexdigest()
        if not oversized:
            context_sha256 = "0" * 64
        gateway, runner = _gateway(Path(temporary), _response())
        with pytest.raises(CodexGatewayError, match="^current profile selection context is malformed$"):
            gateway.select_current_profile_facts(
                _records(),
                profile_context=context,
                profile_context_sha256=context_sha256,
            )
    assert runner.calls == []


def test_singular_preference_kind_is_never_emitted_as_a_document_fact() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        records = _records()
        records[0]["kind"] = "preference"
        response = _response()
        response["selection"].append(
            {
                "evidence_id": "old-preference",
                "proof_class": "verified_claim",
                "document_targets": ["cv"],
            }
        )
        response["excluded_ids"].remove("old-preference")
        gateway, runner = _gateway(Path(temporary), response)
        with pytest.raises(CodexGatewayError):
            gateway.select_current_profile_facts(records)
    assert len(runner.calls) == 1


def test_selection_accepts_explicit_supported_source_status() -> None:
    records = [
        {
            "evidence_id": "explicit-project",
            "kind": "project",
            "status": "explicit",
            "claim": "Synthetic explicitly stated project fact.",
        }
    ]
    response = {
        "selection": [
            {
                "evidence_id": "explicit-project",
                "proof_class": "verified_claim",
                "document_targets": ["cv"],
            }
        ],
        "excluded_ids": [],
        "correction_assessments": [],
    }
    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), response)
        result, _ = gateway.select_current_profile_facts(records)

    assert result["selection"] == response["selection"]
    assert runner.calls and len(runner.calls) == 1


@pytest.mark.parametrize(
    ("violation", "expected_reason"),
    [
        ("missing_source", "missing_source"),
        ("duplicate_id", "duplicate_id"),
        ("unsupported_status", "unsupported_status"),
        ("non_outward_kind", "non_outward_kind"),
        ("proof_class", "proof_class"),
        ("document_targets", "document_targets"),
    ],
)
def test_selection_policy_errors_are_fixed_and_non_mutating(
    violation: str,
    expected_reason: str,
) -> None:
    records = _records()
    response = _response()
    if violation == "missing_source":
        response["selection"][0]["evidence_id"] = "unknown-source"
    elif violation == "duplicate_id":
        response["selection"].append(
            {
                "evidence_id": "project-row",
                "proof_class": 7,
                "document_targets": None,
            }
        )
    elif violation == "unsupported_status":
        response["selection"].append(
            {
                "evidence_id": "inferred-row",
                "proof_class": "verified_claim",
                "document_targets": ["cv"],
            }
        )
        response["excluded_ids"].remove("inferred-row")
    elif violation == "non_outward_kind":
        response["selection"].append(
            {
                "evidence_id": "correction-row",
                "proof_class": "verified_claim",
                "document_targets": ["cv"],
            }
        )
        response["excluded_ids"].remove("correction-row")
    elif violation == "proof_class":
        response["selection"][0]["proof_class"] = "self_attested"
    else:
        response["selection"][0]["document_targets"] = None
    original_records = json.loads(json.dumps(records))
    original_response = json.loads(json.dumps(response))

    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), response)
        with pytest.raises(CodexGatewayError) as error:
            gateway.select_current_profile_facts(records)

    assert str(error.value) == (
        "current profile fact selection violates source policy: "
        f"{expected_reason}"
    )
    assert records == original_records
    assert response == original_response
    assert len(runner.calls) == 1


def test_content_correction_is_assessed_even_when_kind_is_not_a_correction_label() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        records = _records()
        records[1]["kind"] = "preferences"
        gateway, runner = _gateway(Path(temporary), _response())
        result, _ = gateway.select_current_profile_facts(records)
    assert result["excluded_ids"] == [
        "correction-row",
        "inferred-row",
        "old-preference",
    ]
    assert result["correction_assessments"][0]["source_evidence_id"] == "correction-row"
    assert len(runner.calls) == 1


@pytest.mark.parametrize(
    ("records", "selected", "excluded", "assessments", "anchors"),
    [
        (
            [
                {"evidence_id": "r1", "kind": "career_fact", "status": "explicit", "claim": "Scaled a course demo pipeline to serve millions of daily users."},
                {"evidence_id": "r2", "kind": "correction", "status": "explicit", "claim": "Correction for record r1: the course project pipeline handled a small sample dataset, not millions of daily users."},
                {"evidence_id": "r3", "kind": "career_fact", "status": "verified", "claim": "Completed a course project building a batch pipeline over a 10k-row sample dataset."},
                {"evidence_id": "r4", "kind": "career_fact", "status": "verified", "claim": "Wrote unit tests for a mock billing service during a class exercise."},
            ],
            ["r3", "r4"],
            ["r1", "r2"],
            [{"source_evidence_id": "r2", "relationship": "corrects", "affected_evidence_ids": ["r1"]}],
            ("record r1", "small sample dataset"),
        ),
        (
            [
                {"evidence_id": "a1", "kind": "career_fact", "status": "verified", "claim": "Earned a course certificate for an introductory statistics class in an earlier term."},
                {"evidence_id": "a2", "kind": "career_fact", "status": "unverified_current", "claim": "Recently stated proficiency in advanced statistics topics."},
                {"evidence_id": "a3", "kind": "career_fact", "status": "verified", "claim": "Tutored peers in basic algebra at a campus study center."},
            ],
            ["a1", "a3"],
            ["a2"],
            [],
            ("earlier term", "unverified_current"),
        ),
        (
            [
                {"evidence_id": "b1", "kind": "career_fact", "status": "explicit", "claim": "Claimed leading a five-person robotics team in a student club."},
                {"evidence_id": "b2", "kind": "retraction", "status": "explicit", "claim": "Retraction targeting record b1: the robotics team leadership claim is false and withdrawn."},
                {"evidence_id": "b3", "kind": "career_fact", "status": "verified", "claim": "Mentored two first-year students in a weekly study group."},
                {"evidence_id": "b4", "kind": "career_fact", "status": "inference", "claim": "Likely contributed to an open-source mock compiler exercise."},
            ],
            ["b3"],
            ["b1", "b2", "b4"],
            [{"source_evidence_id": "b2", "relationship": "retracts", "affected_evidence_ids": ["b1"]}],
            ("record b1", "false and withdrawn"),
        ),
        (
            [
                {"evidence_id": "c1", "kind": "career_fact", "status": "explicit", "claim": "Served as treasurer of the campus astronomy society during the autumn term."},
                {"evidence_id": "c2", "kind": "career_fact", "status": "explicit", "claim": "Never served as treasurer of the campus astronomy society, including during the autumn term."},
                {"evidence_id": "c3", "kind": "career_fact", "status": "verified", "claim": "Presented a poster on variable stars at a student symposium."},
            ],
            ["c3"],
            ["c1", "c2"],
            [],
            ("treasurer of the campus astronomy society", "Never served"),
        ),
    ],
)
def test_reviewed_correction_and_exclusion_cases(
    records: list[dict[str, str]],
    selected: list[str],
    excluded: list[str],
    assessments: list[dict[str, Any]],
    anchors: tuple[str, str],
) -> None:
    response = {
        "selection": [
            {
                "evidence_id": evidence_id,
                "proof_class": "verified_claim",
                "document_targets": ["cv"],
            }
            for evidence_id in selected
        ],
        "excluded_ids": excluded,
        "correction_assessments": assessments,
    }
    with tempfile.TemporaryDirectory() as temporary:
        gateway, runner = _gateway(Path(temporary), response)
        result, receipt = gateway.select_current_profile_facts(records)

    assert sorted(row["evidence_id"] for row in result["selection"]) == sorted(selected)
    assert result["excluded_ids"] == sorted(excluded)
    assert result["correction_assessments"] == assessments
    for anchor in anchors:
        assert anchor in runner.prompt
    assert receipt.transport is not None and receipt.transport.invocation_count == 1
