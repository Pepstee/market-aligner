from __future__ import annotations

import copy
import inspect
import json
import os
from pathlib import Path

import pytest

from career_automation import hard_metrics_evaluation as evaluator
from career_automation.hard_metrics_evaluation import (
    FULL_SUBMIT_EVIDENCE_REGISTRY,
    EvidenceRegistryError,
    MetricIntegrityError,
    MetricStatus,
    _derive_full_submit_from_documents,
    _operator_control_root,
    _read_registry_entry,
    _repository_root,
    evaluate_full_submit_hard_metrics,
)


ROOT = Path(__file__).resolve().parent
CONTROL_ROOT = Path(
    os.environ.get("JAA_OPERATOR_CONTROL_ROOT", ROOT.parent.parent / ".control")
)
FIXTURE = (
    ROOT
    / "career_automation/fixtures/jaa07_locked_application_packs_hard_metrics_v1.json"
)
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
COHORT = (
    CONTROL_ROOT
    / "jaa-post-interval-20260803/"
    / "jaa10-full-submit-cohort-v2/evidence/cohort.json"
)


def _documents():
    return tuple(
        json.loads(path.read_bytes()) for path in (FIXTURE, REPORT, PAIR, COHORT)
    )


def _rehash_cohort(cohort: dict[str, object]) -> None:
    core = dict(cohort)
    core.pop("cohort_id")
    cohort["cohort_id"] = evaluator._plain_content_hash(core)


def test_caller_cannot_select_full_submit_evidence_or_verdict() -> None:
    assert tuple(inspect.signature(evaluate_full_submit_hard_metrics).parameters) == ()
    with pytest.raises(TypeError):
        evaluate_full_submit_hard_metrics(COHORT)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        evaluate_full_submit_hard_metrics(target=0)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        evaluate_full_submit_hard_metrics(verdict="PASS")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        evaluate_full_submit_hard_metrics(counts={})  # type: ignore[call-arg]


def test_zero_claim_denominator_cannot_be_relabelled_pass(monkeypatch) -> None:
    fixture, report, pair, cohort = _documents()
    cohort["claim_populations"] = [[], []]
    cohort["derived_counts"]["released_claims"] = 0
    cohort["derived_counts"]["released_employer_claims"] = 0
    _rehash_cohort(cohort)
    monkeypatch.setattr(evaluator, "_FULL_SUBMIT_COHORT_ID", cohort["cohort_id"])
    with pytest.raises(EvidenceRegistryError, match="claim denominator"):
        _derive_full_submit_from_documents(fixture, report, pair, cohort)


def test_omitted_runtime_receipt_and_caller_count_fail_closed(monkeypatch) -> None:
    fixture, report, pair, cohort = _documents()
    cohort["runtime_control_receipts"] = cohort["runtime_control_receipts"][:-1]
    cohort["runtime_control_receipt_sha256s"] = cohort[
        "runtime_control_receipt_sha256s"
    ][:-1]
    cohort["derived_counts"]["runtime_negative_controls"] = 27
    _rehash_cohort(cohort)
    monkeypatch.setattr(evaluator, "_FULL_SUBMIT_COHORT_ID", cohort["cohort_id"])
    with pytest.raises(EvidenceRegistryError, match="runtime denominator"):
        _derive_full_submit_from_documents(fixture, report, pair, cohort)

    fixture, report, pair, cohort = _documents()
    cohort["derived_counts"]["successful_loopback_submissions"] = 3
    _rehash_cohort(cohort)
    monkeypatch.setattr(evaluator, "_FULL_SUBMIT_COHORT_ID", cohort["cohort_id"])
    with pytest.raises(EvidenceRegistryError, match="derived denominator"):
        _derive_full_submit_from_documents(fixture, report, pair, cohort)


def test_source_time_and_registry_substitution_are_detected() -> None:
    fixture, report, pair, cohort = _documents()
    cohort["source_identity"]["tree"] = "0" * 40
    _rehash_cohort(cohort)
    with pytest.raises(EvidenceRegistryError, match="authority literal"):
        _derive_full_submit_from_documents(fixture, report, pair, cohort)

    fixture, report, pair, cohort = _documents()
    cohort["live_time_separated_execution"] = "authenticated"
    _rehash_cohort(cohort)
    with pytest.raises(EvidenceRegistryError, match="authority literal"):
        _derive_full_submit_from_documents(fixture, report, pair, cohort)

    entry = FULL_SUBMIT_EVIDENCE_REGISTRY["jaa10-full-submit-v2-shadow-cohort-5bb09705"]
    tampered = copy.copy(entry)
    object.__setattr__(tampered, "sha256", "0" * 64)
    repository_root = _repository_root()
    with pytest.raises(EvidenceRegistryError, match="hash differs"):
        _read_registry_entry(
            tampered,
            repository_root=repository_root,
            control_root=_operator_control_root(repository_root),
        )


def test_receipt_hash_outcome_kind_and_state_tamper_fail_closed(monkeypatch) -> None:
    fixture, report, pair, cohort = _documents()
    cohort["runtime_control_receipt_sha256s"][0] = "0" * 64
    _rehash_cohort(cohort)
    monkeypatch.setattr(evaluator, "_FULL_SUBMIT_COHORT_ID", cohort["cohort_id"])
    with pytest.raises(EvidenceRegistryError, match="receipt identity"):
        _derive_full_submit_from_documents(fixture, report, pair, cohort)

    fixture, report, pair, cohort = _documents()
    receipt = cohort["runtime_control_receipts"][0]
    receipt["observed_outcome"]["kind"] = "contract_rejection"
    cohort["runtime_control_receipt_sha256s"][0] = evaluator._plain_content_hash(
        receipt
    )
    _rehash_cohort(cohort)
    monkeypatch.setattr(evaluator, "_FULL_SUBMIT_COHORT_ID", cohort["cohort_id"])
    with pytest.raises(EvidenceRegistryError, match="outcome kind"):
        _derive_full_submit_from_documents(fixture, report, pair, cohort)

    fixture, report, pair, cohort = _documents()
    receipt = cohort["runtime_control_receipts"][0]
    receipt["after_state"]["receipt_count"] = 1
    cohort["runtime_control_receipt_sha256s"][0] = evaluator._plain_content_hash(
        receipt
    )
    _rehash_cohort(cohort)
    monkeypatch.setattr(evaluator, "_FULL_SUBMIT_COHORT_ID", cohort["cohort_id"])
    with pytest.raises(EvidenceRegistryError, match="changed state"):
        _derive_full_submit_from_documents(fixture, report, pair, cohort)


def test_full_submit_zero_denominator_metric_object_cannot_verify() -> None:
    metric = copy.copy(
        next(
            row
            for row in evaluate_full_submit_hard_metrics().metrics
            if row.metric_name == "duplicate_submissions"
        )
    )
    object.__setattr__(metric, "denominator", 0)
    object.__setattr__(metric, "status", MetricStatus.PASS)
    with pytest.raises(MetricIntegrityError, match="full-submit"):
        metric.verify()
