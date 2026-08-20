from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from career_automation.certification_candidate_compiler import (
    CandidateStatus,
    CertificationCandidateReceipt,
    WithheldReason,
    compile_certification_candidate,
    publish_certification_candidate,
)
from career_automation.hard_metrics_evaluation import (
    ReceiptPublicationError,
    evaluate_hard_metrics,
)


def test_compiler_can_construct_only_withheld_candidate() -> None:
    evaluation = evaluate_hard_metrics()
    receipt = compile_certification_candidate(evaluation)
    receipt.verify(evaluation)
    assert tuple(CandidateStatus) == (
        CandidateStatus.CERTIFICATION_WITHHELD,
    )
    assert receipt.status is CandidateStatus.CERTIFICATION_WITHHELD
    assert receipt.withheld_reasons == (
        WithheldReason.LIVE_EVIDENCE_ABSENT,
        WithheldReason.SIGNED_TIME_ABSENT,
        WithheldReason.METRICS_INCOMPLETE,
    )
    document = receipt.document()
    assert document["objective_satisfied"] is False
    assert document["metrics_complete"] is False
    assert document["production_certification"] == "withheld"
    assert document["certifies_slice"] is False
    assert document["live_time_separated_execution"] == "not_collected"
    assert document["external_action_capability"] is False
    assert document["real_applications_submitted"] == 0


def test_candidate_receipts_cannot_be_constructed_directly() -> None:
    with pytest.raises(TypeError, match="verified compiler"):
        CertificationCandidateReceipt()


def test_candidate_publication_is_exclusive_and_read_only(
    tmp_path: Path,
) -> None:
    evaluation = evaluate_hard_metrics()
    receipt = compile_certification_candidate(evaluation)
    destination = tmp_path / "candidate.json"
    published_sha256 = publish_certification_candidate(
        receipt,
        evaluation,
        destination,
    )
    assert len(published_sha256) == 64
    assert stat.S_IMODE(destination.stat().st_mode) == 0o444
    assert json.loads(destination.read_bytes()) == receipt.document()
    with pytest.raises(ReceiptPublicationError, match="exclusive"):
        publish_certification_candidate(
            receipt,
            evaluation,
            destination,
        )
