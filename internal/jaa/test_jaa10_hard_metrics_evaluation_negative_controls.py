from __future__ import annotations

import copy
import inspect
import json
import os
from pathlib import Path

import pytest
from career_automation import hard_metrics_evaluation as evaluator

from career_automation.hard_metrics_evaluation import (
    EVIDENCE_REGISTRY,
    EvidenceClass,
    EvidenceRegistryError,
    MetricIntegrityError,
    MetricStatus,
    ModelCallAccounting,
    ReceiptPublicationError,
    _derive_from_documents,
    _derive_replay_pair,
    _validate_replay_pair,
    _operator_control_root,
    _read_regular_file_once,
    _read_registry_entry,
    _repository_root,
    evaluate_hard_metrics,
    publish_hard_metrics_evaluation,
)


ROOT = Path(__file__).resolve().parent
CONTROL_ROOT = Path(
    os.environ.get("JAA_OPERATOR_CONTROL_ROOT", ROOT.parent.parent / ".control")
)
FIXTURE = ROOT / "career_automation/fixtures/jaa07_locked_application_packs.json"
REPORT = (
    CONTROL_ROOT
    / "jaa-single-codex-20260729/"
    / "jaa07-post-review-repair-evaluator.log"
)
PAIR = (
    CONTROL_ROOT
    / "jaa-single-codex-20260729/"
    / "JAA10_FROZEN_REPLAY_PAIR_PRIMARY_95caa725/replay-pair.json"
)


def _documents() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    return (
        json.loads(FIXTURE.read_bytes()),
        json.loads(REPORT.read_bytes()),
        json.loads(PAIR.read_bytes()),
    )


def test_caller_cannot_supply_evidence_path_target_or_verdict() -> None:
    assert tuple(inspect.signature(evaluate_hard_metrics).parameters) == ()
    with pytest.raises(TypeError):
        evaluate_hard_metrics(Path("/tmp/conforming-fake.json"))  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        evaluate_hard_metrics(target=0)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        evaluate_hard_metrics(verdict="PASS")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        EVIDENCE_REGISTRY["report"] = Path("/tmp/fake")  # type: ignore[index]


def test_denominator_insertion_twin_fails_closed() -> None:
    fixture, report, pair = _documents()
    inserted = dict(fixture["cases"][0])  # type: ignore[index]
    inserted["id"] = "pack-21"
    inserted["expected_artifact_set_sha256"] = "0" * 64
    fixture["cases"] = [*fixture["cases"], inserted]  # type: ignore[index]
    with pytest.raises(
        EvidenceRegistryError,
        match="denominator",
    ):
        _derive_from_documents(fixture, report, pair)


def test_omitted_report_row_and_scope_substitution_fail_closed() -> None:
    fixture, report, pair = _documents()
    report["results"] = report["results"][:-1]  # type: ignore[index]
    with pytest.raises(
        EvidenceRegistryError,
        match="denominator",
    ):
        _derive_from_documents(fixture, report, pair)

    fixture, report, pair = _documents()
    report["fixture_sha256"] = "0" * 64
    with pytest.raises(
        EvidenceRegistryError,
        match="report differs",
    ):
        _derive_from_documents(fixture, report, pair)


def test_informational_clock_cannot_enter_metric_evidence() -> None:
    fixture, report, pair = _documents()
    report["recorded_wall_clock_status"] = "informational"
    with pytest.raises(
        EvidenceRegistryError,
        match="informational",
    ):
        _derive_from_documents(fixture, report, pair)


def test_report_summary_cannot_hide_a_failed_denominator_row() -> None:
    fixture, report, pair = _documents()
    report["results"][0]["checks"]["parse_success"] = False  # type: ignore[index]
    with pytest.raises(
        EvidenceRegistryError,
        match="summary and denominator",
    ):
        _derive_from_documents(fixture, report, pair)


def test_probabilistic_accounting_requires_model_and_logical_identity() -> None:
    with pytest.raises(ValueError, match="response model"):
        ModelCallAccounting(
            provider_name="provider",
            model_id_at_call="requested",
            model_id_from_response="",
            logical_request_sha256="1" * 64,
            transport_request_sha256=None,
            response_sha256="2" * 64,
            tokens_input=0,
            tokens_output=0,
            tokens_cached_input=0,
            cost_amount_decimal=None,
            cost_currency=None,
            latency_request_start_ns=None,
            latency_first_byte_ns=None,
            latency_last_byte_ns=None,
            abstained=True,
        )
    with pytest.raises(ValueError, match="logical request"):
        ModelCallAccounting(
            provider_name="provider",
            model_id_at_call="requested",
            model_id_from_response="returned",
            logical_request_sha256="",
            transport_request_sha256=None,
            response_sha256="2" * 64,
            tokens_input=0,
            tokens_output=0,
            tokens_cached_input=0,
            cost_amount_decimal=None,
            cost_currency=None,
            latency_request_start_ns=None,
            latency_first_byte_ns=None,
            latency_last_byte_ns=None,
            abstained=True,
        )


def test_zero_denominator_cannot_be_relabelled_pass() -> None:
    evaluation = evaluate_hard_metrics()
    metric = copy.copy(
        next(
            item
            for item in evaluation.metrics
            if item.metric_name == "duplicate_submissions"
        )
    )
    object.__setattr__(metric, "status", MetricStatus.PASS)
    with pytest.raises(
        MetricIntegrityError,
        match="registry-pinned|unevaluable",
    ):
        metric.verify()


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("time_authenticated",), True),
        (("time_authenticated",), None),
        (("time_authenticated",), 0),
        (("time_authenticated",), "false"),
        (("objective_satisfied",), True),
        (("real_applications_submitted",), 1),
        (("execution_environment_sha256",), "0" * 64),
        (("replay_execution_identity", "source_tree"), "0" * 40),
        (("observation_1", "schema_version"), "wrong"),
        (("observation_1", "submission_proof", "token_sha256"), "bad"),
    ],
)
def test_replay_authority_and_nested_tamper_fails_closed(path, value) -> None:
    _, _, pair = _documents()
    target = pair
    for key in path[:-1]:
        target = target[key]  # type: ignore[index,assignment]
    target[path[-1]] = value  # type: ignore[index]
    with pytest.raises(EvidenceRegistryError):
        _validate_replay_pair(pair)


def test_replay_inventory_and_receipt_tamper_fail_closed() -> None:
    _, _, pair = _documents()
    del pair["observation_1"]["prompt_version"]  # type: ignore[index]
    with pytest.raises(EvidenceRegistryError, match="inventory"):
        _validate_replay_pair(pair)
    _, _, pair = _documents()
    pair["receipt_sha256"] = "0" * 64
    with pytest.raises(EvidenceRegistryError, match="receipt"):
        _validate_replay_pair(pair)


def test_self_consistent_replay_mismatch_derives_fail_shape() -> None:
    _, _, pair = _documents()
    pair["observation_2"]["browser_launch_count"] = 2  # type: ignore[index]
    observation = pair["observation_2"]
    pair["observation_2_sha256"] = evaluator.hashlib.sha256(
        evaluator._canonical_json(observation).encode("utf-8")
    ).hexdigest()
    projections = tuple(
        {
            key: pair[f"observation_{index}"][key]
            for key in evaluator._REPLAY_STABLE_KEYS
        }  # type: ignore[index]
        for index in (1, 2)
    )
    hashes = tuple(
        evaluator._domain_hash(
            evaluator.STABLE_PROJECTION_DOMAIN,
            {
                "stable_projection_version": evaluator.STABLE_PROJECTION_VERSION,
                "projection": projection,
            },
        )
        for projection in projections
    )
    pair["stable_field_hash_1"], pair["stable_field_hash_2"] = hashes
    pair["mismatched_stable_fields"] = list(
        evaluator._mismatched_paths(projections[0], projections[1])
    )
    pair["mismatch_count"] = 1
    core = dict(pair)
    core.pop("receipt_sha256")
    pair["receipt_sha256"] = evaluator._domain_hash(evaluator.REPLAY_PAIR_DOMAIN, core)
    mismatch_count = _derive_replay_pair(pair)
    assert mismatch_count == 1
    assert evaluator._build_replay_metric_receipt(mismatch_count).status is (
        MetricStatus.FAIL
    )


@pytest.mark.parametrize("denominator", [0, 2])
def test_replay_metric_requires_exact_one_pair_denominator(denominator: int) -> None:
    metric = copy.copy(
        next(
            item
            for item in evaluate_hard_metrics().metrics
            if item.metric_name == "deterministic_replay_mismatch"
        )
    )
    object.__setattr__(metric, "denominator", denominator)
    with pytest.raises(MetricIntegrityError):
        metric.verify()


def test_evaluator_has_no_historical_self_source_or_action_imports() -> None:
    source = inspect.getsource(evaluator)
    for forbidden in (
        "import tracked_source_revision",
        "import subprocess",
        "import playwright",
        "import socket",
        "import frozen_replay_pair_recorder",
    ):
        assert forbidden not in source


@pytest.mark.parametrize("variant", ["missing-newline", "reordered"])
def test_noncanonical_fixed_pair_bytes_fail_closed(monkeypatch, variant: str) -> None:
    original_read = evaluator._read_registry_entry
    _, _, pair = _documents()
    if variant == "missing-newline":
        payload = evaluator._canonical_json(pair).encode("utf-8")
    else:
        reversed_pair = dict(reversed(tuple(pair.items())))
        payload = (json.dumps(reversed_pair, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )

    def substituted(entry, *, repository_root, control_root):
        if entry.evidence_id == "jaa10-frozen-replay-pair-primary-v1":
            return payload
        return original_read(
            entry,
            repository_root=repository_root,
            control_root=control_root,
        )

    monkeypatch.setattr(evaluator, "_read_registry_entry", substituted)
    with pytest.raises(EvidenceRegistryError, match="canonical JSON"):
        evaluate_hard_metrics()


def test_fixture_evidence_cannot_be_promoted_to_live() -> None:
    with pytest.raises(ValueError):
        EvidenceClass("live_external_evidence")


def test_symlink_registry_input_and_output_are_rejected(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real.json"
    real.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(
        EvidenceRegistryError,
        match="opened safely",
    ):
        _read_regular_file_once(tmp_path, link.name)

    evaluation = evaluate_hard_metrics()
    destination = tmp_path / "receipt.json"
    destination.symlink_to(real)
    with pytest.raises(
        ReceiptPublicationError,
        match="exclusive",
    ):
        publish_hard_metrics_evaluation(evaluation, destination)


def test_registry_hash_substitution_is_detected() -> None:
    entry = EVIDENCE_REGISTRY["jaa07-locked-evaluation-report-v1"]
    tampered = copy.copy(entry)
    object.__setattr__(tampered, "sha256", "0" * 64)
    repository_root = _repository_root()
    with pytest.raises(EvidenceRegistryError, match="hash differs"):
        _read_registry_entry(
            tampered,
            repository_root=repository_root,
            control_root=_operator_control_root(repository_root),
        )
