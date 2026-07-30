from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path

import pytest

from career_automation.hard_metrics_evaluation import (
    EVIDENCE_REGISTRY,
    EvidenceClass,
    EvidenceRegistryError,
    MetricIntegrityError,
    MetricStatus,
    ModelCallAccounting,
    ReceiptPublicationError,
    _derive_from_documents,
    _operator_control_root,
    _read_regular_file_once,
    _read_registry_entry,
    _repository_root,
    evaluate_hard_metrics,
    publish_hard_metrics_evaluation,
)


ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "career_automation/fixtures/jaa07_locked_application_packs.json"
REPORT = (
    ROOT.parent.parent
    / ".control/jaa-single-codex-20260729/"
    / "jaa07-post-review-repair-evaluator.log"
)


def _documents() -> tuple[dict[str, object], dict[str, object]]:
    return (
        json.loads(FIXTURE.read_bytes()),
        json.loads(REPORT.read_bytes()),
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
    fixture, report = _documents()
    inserted = dict(fixture["cases"][0])  # type: ignore[index]
    inserted["id"] = "pack-21"
    inserted["expected_artifact_set_sha256"] = "0" * 64
    fixture["cases"] = [*fixture["cases"], inserted]  # type: ignore[index]
    with pytest.raises(
        EvidenceRegistryError,
        match="denominator",
    ):
        _derive_from_documents(fixture, report)


def test_omitted_report_row_and_scope_substitution_fail_closed() -> None:
    fixture, report = _documents()
    report["results"] = report["results"][:-1]  # type: ignore[index]
    with pytest.raises(
        EvidenceRegistryError,
        match="denominator",
    ):
        _derive_from_documents(fixture, report)

    fixture, report = _documents()
    report["fixture_sha256"] = "0" * 64
    with pytest.raises(
        EvidenceRegistryError,
        match="report differs",
    ):
        _derive_from_documents(fixture, report)


def test_informational_clock_cannot_enter_metric_evidence() -> None:
    fixture, report = _documents()
    report["recorded_wall_clock_status"] = "informational"
    with pytest.raises(
        EvidenceRegistryError,
        match="informational",
    ):
        _derive_from_documents(fixture, report)


def test_report_summary_cannot_hide_a_failed_denominator_row() -> None:
    fixture, report = _documents()
    report["results"][0]["checks"]["parse_success"] = False  # type: ignore[index]
    with pytest.raises(
        EvidenceRegistryError,
        match="summary and denominator",
    ):
        _derive_from_documents(fixture, report)


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
        match="only ATS parse|unevaluable",
    ):
        metric.verify()


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
