"""Independent gate binding the checked-in JAA-01 receipt to the current product tree."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tracked_source_revision import source_content_revision


ROOT = Path(__file__).resolve().parent
EXPECTED_COUNTS = {"pipeline_jobs": 462, "pipeline_events": 924}
MIGRATION_CONTENT_HASH = "4f2dddaab89ea49ef991ad8a4d8598c03062c4b3ecbf11f85451ab9239a8ec66"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _receipt() -> Path:
    receipts = sorted((ROOT / "runtime_evidence" / "jaa01").glob("sha256-*.json"))
    assert len(receipts) == 1, f"expected one JAA-01 receipt, found {receipts}"
    return receipts[0]


def _runtime() -> Path:
    for parent in ROOT.parents:
        candidate = parent / "state" / "runtime" / "job-application-baseline-20260720-v2"
        if candidate.is_dir():
            return candidate
    pytest.fail("frozen JAA-00 runtime is unavailable")


def _verify(document: dict[str, object], payload: bytes, receipt: Path) -> None:
    runtime = _runtime()
    baseline = runtime / "databases" / "career_pipeline.sqlite3"
    migration = runtime / "receipts" / f"migration-{MIGRATION_CONTENT_HASH}.json"
    migration_document = json.loads(migration.read_text(encoding="utf-8"))

    assert document["source_content_revision"] == source_content_revision(ROOT)
    assert document["expected_counts"] == EXPECTED_COUNTS
    assert document["observed_counts"] == {
        name: EXPECTED_COUNTS
        for name in ("baseline_before", "temporary_before_migration", "temporary_after_migration")
    }
    assert document["hashes"] == {
        "baseline_sha256_before": _sha256(baseline),
        "baseline_sha256_after": _sha256(baseline),
        "migration_receipt_file_sha256_before": _sha256(migration),
        "migration_receipt_file_sha256_after": _sha256(migration),
        "migration_receipt_content_sha256": migration_document["content_sha256"],
    }
    assert receipt.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"


def test_checked_in_receipt_is_bound_to_current_tree_and_frozen_baseline() -> None:
    receipt = _receipt()
    payload = receipt.read_bytes()
    _verify(json.loads(payload), payload, receipt)


@pytest.mark.parametrize("attack", [
    "stale-source-revision",
    "altered-database-digest",
    "altered-count",
    "tampered-receipt-content",
])
def test_checked_in_receipt_verifier_rejects_tampering(attack: str) -> None:
    receipt = _receipt()
    payload = receipt.read_bytes()
    document = json.loads(payload)
    attacked = copy.deepcopy(document)

    if attack == "stale-source-revision":
        attacked["source_content_revision"] = "sha256:" + "0" * 64
    elif attack == "altered-database-digest":
        attacked["hashes"]["baseline_sha256_after"] = "0" * 64
    elif attack == "altered-count":
        attacked["expected_counts"]["pipeline_jobs"] = 461
    else:
        payload += b"\n"

    with pytest.raises(AssertionError):
        _verify(attacked, payload, receipt)
