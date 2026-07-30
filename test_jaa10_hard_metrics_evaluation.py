from __future__ import annotations

import inspect
import json
import stat
from pathlib import Path

import pytest

from career_automation.hard_metrics_evaluation import (
    DETERMINISTIC_ACCOUNTING,
    EVIDENCE_REGISTRY,
    METRICS_SCHEMA_VERSION,
    EvidenceClass,
    MetricReceipt,
    MetricStatus,
    ModelCallAccounting,
    ReceiptPublicationError,
    evaluate_hard_metrics,
    evidence_registry_document,
    evidence_registry_sha256,
    publish_hard_metrics_evaluation,
)
from career_automation.shadow_certification import HARD_QUALITY_TARGETS


def _metrics_by_name():
    evaluation = evaluate_hard_metrics()
    return evaluation, {
        metric.metric_name: metric for metric in evaluation.metrics
    }


def test_authority_registry_is_fixed_and_evaluator_accepts_no_input() -> None:
    assert tuple(inspect.signature(evaluate_hard_metrics).parameters) == ()
    assert set(EVIDENCE_REGISTRY) == {
        "jaa07-locked-application-packs-v1",
        "jaa07-locked-evaluation-report-v1",
    }
    assert evidence_registry_document()["schema_version"] == (
        METRICS_SCHEMA_VERSION
    )
    assert len(evidence_registry_sha256()) == 64
    with pytest.raises(TypeError):
        EVIDENCE_REGISTRY["caller-path"] = object()  # type: ignore[index]


def test_current_registry_derives_one_fixture_pass_and_six_unevaluable() -> None:
    evaluation, metrics = _metrics_by_name()
    evaluation.verify()
    assert set(metrics) == set(HARD_QUALITY_TARGETS)
    assert evaluation.model_call_accounting == DETERMINISTIC_ACCOUNTING
    assert evaluation.document()["objective_satisfied"] is False
    assert evaluation.document()["production_certification"] == "withheld"
    assert evaluation.document()["live_time_separated_execution"] == (
        "not_collected"
    )
    assert evaluation.document()["external_action_capability"] is False
    assert evaluation.document()["real_applications_submitted"] == 0

    parse = metrics["ats_parse_success_bp"]
    assert parse.status is MetricStatus.PASS
    assert parse.target == 10_000
    assert parse.numerator == 0
    assert parse.denominator == 20
    assert parse.value == 10_000
    assert parse.unit == "basis_points"
    assert parse.evidence_class is EvidenceClass.FIXTURE_FROZEN
    assert parse.evidence_scope_id == (
        "801349f4a13a9516e928d30035cfcab00adb4f1bd2783cbaa0c8cd61a4554e59"
    )
    assert parse.missing_evidence_count == 0

    for name, metric in metrics.items():
        metric.verify()
        assert metric.document()["certifies_slice"] is False
        if name == "ats_parse_success_bp":
            continue
        assert metric.status is MetricStatus.UNEVALUABLE
        assert metric.denominator == 0
        assert metric.value is None
        assert metric.evidence_class is None
        assert metric.evidence_item_ids == ()
        assert metric.missing_evidence_count == 1


def test_model_accounting_distinguishes_logical_transport_and_unavailable() -> None:
    accounting = ModelCallAccounting(
        provider_name="provider",
        model_id_at_call="requested-model",
        model_id_from_response="returned-model",
        logical_request_sha256="1" * 64,
        transport_request_sha256=None,
        response_sha256="2" * 64,
        tokens_input=10,
        tokens_output=5,
        tokens_cached_input=3,
        cost_amount_decimal=None,
        cost_currency=None,
        latency_request_start_ns=None,
        latency_first_byte_ns=None,
        latency_last_byte_ns=None,
        abstained=False,
    )
    assert accounting.document()["transport_request_sha256"] is None
    assert accounting.document()["cost_amount_decimal"] is None
    assert accounting.document()["latency_last_byte_ns"] is None


def test_metric_receipts_cannot_be_constructed_directly() -> None:
    with pytest.raises(
        TypeError,
        match="verified evaluator",
    ):
        MetricReceipt()


def test_hard_metrics_publication_is_exclusive_and_born_read_only(
    tmp_path: Path,
) -> None:
    evaluation = evaluate_hard_metrics()
    destination = tmp_path / "hard-metrics.json"
    published_sha256 = publish_hard_metrics_evaluation(
        evaluation,
        destination,
    )
    assert len(published_sha256) == 64
    assert stat.S_IMODE(destination.stat().st_mode) == 0o444
    document = json.loads(destination.read_bytes())
    assert document == evaluation.document()
    with pytest.raises(
        ReceiptPublicationError,
        match="exclusive",
    ):
        publish_hard_metrics_evaluation(evaluation, destination)
