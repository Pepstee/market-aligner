from __future__ import annotations

import copy
import inspect
from pathlib import Path

import pytest

from career_automation.certification_candidate_compiler import (
    CandidateStatus,
    CertificationCandidateError,
    compile_certification_candidate,
    publish_certification_candidate,
)
from career_automation.hard_metrics_evaluation import (
    MetricIntegrityError,
    MetricStatus,
    ReceiptPublicationError,
    evaluate_hard_metrics,
)


def test_caller_cannot_select_candidate_verdict_or_reasons() -> None:
    parameters = tuple(
        inspect.signature(compile_certification_candidate).parameters
    )
    assert parameters == ("evaluation",)
    evaluation = evaluate_hard_metrics()
    with pytest.raises(TypeError):
        compile_certification_candidate(  # type: ignore[call-arg]
            evaluation,
            status="CERTIFICATION_CANDIDATE",
        )
    with pytest.raises(ValueError):
        CandidateStatus("CERTIFICATION_CANDIDATE")


def test_tampered_metric_cannot_enter_candidate_compilation() -> None:
    evaluation = copy.copy(evaluate_hard_metrics())
    metrics = list(evaluation.metrics)
    metric = copy.copy(metrics[1])
    object.__setattr__(metric, "status", MetricStatus.PASS)
    metrics[1] = metric
    object.__setattr__(evaluation, "metrics", tuple(metrics))
    with pytest.raises(MetricIntegrityError):
        compile_certification_candidate(evaluation)


def test_cross_evaluation_substitution_breaks_candidate_binding() -> None:
    evaluation = evaluate_hard_metrics()
    receipt = copy.copy(compile_certification_candidate(evaluation))
    object.__setattr__(
        receipt,
        "metrics_evaluation_sha256",
        "0" * 64,
    )
    with pytest.raises(
        CertificationCandidateError,
        match="differs",
    ):
        receipt.verify(evaluation)


def test_candidate_receipt_hash_tamper_fails_closed() -> None:
    evaluation = evaluate_hard_metrics()
    receipt = copy.copy(compile_certification_candidate(evaluation))
    object.__setattr__(receipt, "receipt_sha256", "0" * 64)
    with pytest.raises(
        CertificationCandidateError,
        match="hash differs",
    ):
        receipt.verify(evaluation)


def test_candidate_publication_rejects_existing_symlink(
    tmp_path: Path,
) -> None:
    evaluation = evaluate_hard_metrics()
    receipt = compile_certification_candidate(evaluation)
    target = tmp_path / "target"
    target.write_text("unchanged", encoding="utf-8")
    destination = tmp_path / "candidate.json"
    destination.symlink_to(target)
    with pytest.raises(ReceiptPublicationError, match="exclusive"):
        publish_certification_candidate(
            receipt,
            evaluation,
            destination,
        )
    assert target.read_text(encoding="utf-8") == "unchanged"
