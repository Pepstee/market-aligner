"""Structurally withheld JAA-10 certification-candidate compiler.

Version one can only compile ``CERTIFICATION_WITHHELD`` from a verified local
hard-metrics evaluation.  There is no constructable candidate/certified state,
no caller-selected verdict, and no external-action capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from career_automation.hard_metrics_evaluation import (
    LIVE_EXECUTION,
    PRODUCTION_CERTIFICATION,
    HardMetricsEvaluation,
    MetricStatus,
    _domain_hash,
    _publish_canonical_receipt,
)


CANDIDATE_SCHEMA_VERSION = "jaa10.certification-candidate.v1"
CANDIDATE_DOMAIN = b"jaa10-certification-candidate-v1\0"


class CandidateStatus(str, Enum):
    CERTIFICATION_WITHHELD = "CERTIFICATION_WITHHELD"


class WithheldReason(str, Enum):
    LIVE_EVIDENCE_ABSENT = "live_evidence_absent"
    SIGNED_TIME_ABSENT = "signed_time_absent"
    METRICS_INCOMPLETE = "metrics_incomplete"


class CertificationCandidateError(RuntimeError):
    """The withheld certification-candidate receipt differs."""


_WITHHELD_REASONS = (
    WithheldReason.LIVE_EVIDENCE_ABSENT,
    WithheldReason.SIGNED_TIME_ABSENT,
    WithheldReason.METRICS_INCOMPLETE,
)


@dataclass(frozen=True, init=False)
class CertificationCandidateReceipt:
    status: CandidateStatus
    withheld_reasons: tuple[WithheldReason, ...]
    metrics_evaluation_sha256: str
    metric_receipts: tuple[tuple[str, str, str], ...]
    receipt_sha256: str

    def __init__(self) -> None:
        raise TypeError(
            "certification-candidate receipts require the verified compiler"
        )

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": CANDIDATE_SCHEMA_VERSION,
            "status": self.status.value,
            "withheld_reasons": [
                reason.value for reason in self.withheld_reasons
            ],
            "metrics_evaluation_sha256": self.metrics_evaluation_sha256,
            "metric_receipts": [
                {
                    "metric_name": name,
                    "status": status,
                    "receipt_sha256": receipt_sha256,
                }
                for name, status, receipt_sha256 in self.metric_receipts
            ],
            "objective_satisfied": False,
            "metrics_complete": False,
            "production_certification": PRODUCTION_CERTIFICATION,
            "certifies_slice": False,
            "live_time_separated_execution": LIVE_EXECUTION,
            "external_action_capability": False,
            "real_applications_submitted": 0,
        }
        if include_hash:
            document["receipt_sha256"] = self.receipt_sha256
        return document

    def verify(self, evaluation: HardMetricsEvaluation) -> None:
        if not isinstance(evaluation, HardMetricsEvaluation):
            raise TypeError(
                "candidate verification requires a hard-metrics evaluation"
            )
        evaluation.verify()
        expected_metrics = tuple(
            (
                metric.metric_name,
                metric.status.value,
                metric.receipt_sha256,
            )
            for metric in evaluation.metrics
        )
        if (
            self.status is not CandidateStatus.CERTIFICATION_WITHHELD
            or self.withheld_reasons != _WITHHELD_REASONS
            or self.metrics_evaluation_sha256
            != evaluation.evaluation_sha256
            or self.metric_receipts != expected_metrics
            or all(
                metric.status is MetricStatus.PASS
                for metric in evaluation.metrics
            )
        ):
            raise CertificationCandidateError(
                "withheld certification candidate differs"
            )
        expected_hash = _domain_hash(
            CANDIDATE_DOMAIN,
            self.document(include_hash=False),
        )
        if self.receipt_sha256 != expected_hash:
            raise CertificationCandidateError(
                "certification-candidate receipt hash differs"
            )


def compile_certification_candidate(
    evaluation: HardMetricsEvaluation,
) -> CertificationCandidateReceipt:
    """Compile the only v1 status: ``CERTIFICATION_WITHHELD``."""
    if not isinstance(evaluation, HardMetricsEvaluation):
        raise TypeError(
            "candidate compilation requires a hard-metrics evaluation"
        )
    evaluation.verify()
    receipt = object.__new__(CertificationCandidateReceipt)
    object.__setattr__(
        receipt,
        "status",
        CandidateStatus.CERTIFICATION_WITHHELD,
    )
    object.__setattr__(receipt, "withheld_reasons", _WITHHELD_REASONS)
    object.__setattr__(
        receipt,
        "metrics_evaluation_sha256",
        evaluation.evaluation_sha256,
    )
    object.__setattr__(
        receipt,
        "metric_receipts",
        tuple(
            (
                metric.metric_name,
                metric.status.value,
                metric.receipt_sha256,
            )
            for metric in evaluation.metrics
        ),
    )
    object.__setattr__(receipt, "receipt_sha256", "")
    object.__setattr__(
        receipt,
        "receipt_sha256",
        _domain_hash(
            CANDIDATE_DOMAIN,
            receipt.document(include_hash=False),
        ),
    )
    receipt.verify(evaluation)
    return receipt


def publish_certification_candidate(
    receipt: CertificationCandidateReceipt,
    evaluation: HardMetricsEvaluation,
    destination: Path,
) -> str:
    if not isinstance(receipt, CertificationCandidateReceipt):
        raise TypeError("publication requires a typed candidate receipt")
    receipt.verify(evaluation)
    return _publish_canonical_receipt(receipt.document(), destination)
