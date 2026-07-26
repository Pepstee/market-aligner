"""Independent gate binding the checked-in JAA-01 receipt to the current product tree."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

from tracked_source_revision import source_content_revision, source_git_revision


ROOT = Path(__file__).resolve().parent
EXPECTED_COUNTS = {"pipeline_jobs": 462, "pipeline_events": 924}
MIGRATION_CONTENT_HASH = "b38b38fc4455ce6142ca156a4eff400c5dba22ab04d64f02fce8cd332fe08971"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _receipt() -> Path:
    receipts = sorted((ROOT / "runtime_evidence" / "jaa01").glob("sha256-*.json"))
    assert len(receipts) == 1, f"expected one JAA-01 receipt, found {receipts}"
    return receipts[0]


def _runtime() -> Path:
    for parent in ROOT.parents:
        runtime = parent / "state" / "runtime"
        matches = sorted(runtime.glob(
            f"jaa00-v2-*/receipts/migration-{MIGRATION_CONTENT_HASH}.json"
        )) if runtime.is_dir() else []
        if len(matches) == 1:
            return matches[0].parents[1]
    pytest.fail("frozen JAA-00 runtime is unavailable")


def _verify(document: dict[str, object], payload: bytes, receipt: Path) -> None:
    runtime = _runtime()
    baseline = runtime / "databases" / "career_pipeline.sqlite3"
    migration = runtime / "receipts" / f"migration-{MIGRATION_CONTENT_HASH}.json"
    migration_document = json.loads(migration.read_text(encoding="utf-8"))

    assert document["source_content_revision"] == source_content_revision(ROOT)
    assert document["source_git_revision"] == source_git_revision(ROOT)
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


def test_runtime_locator_uses_current_trusted_jaa00_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "worktrees" / "candidate"
    repository.mkdir(parents=True)
    migration = (
        tmp_path / "state" / "runtime" / "jaa00-v2-test" / "receipts"
        / f"migration-{MIGRATION_CONTENT_HASH}.json"
    )
    migration.parent.mkdir(parents=True)
    migration.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", repository)

    assert _runtime() == migration.parents[1]


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
