#!/usr/bin/env python3
"""Certify JAA-01 against an operator-selected frozen SQLite baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from baseline_adoption.core import (
    LEGACY_JAA00_ADOPTION_REVISION,
    LEGACY_JAA00_CONTENT_SHA256,
    LEGACY_JAA00_RECEIPT_SHA256,
)
from career_automation.lifecycle import LifecycleReducer
from career_automation.migrations import JAA_01_MIGRATIONS
from baseline_adoption.core import AdoptionError, independent_review
from scripts.reproduce_jaa01_terra_rejection import reproduce
from tracked_source_revision import (
    TrackedSourceRevisionError,
    source_content_revision as tracked_source_content_revision,
    source_content_revision_contract,
)

EXPECTED_COUNTS = {"pipeline_jobs": 462, "pipeline_events": 924}
FORMAT = "jaa01-runtime-certification/v1"
ROOT = Path(__file__).resolve().parents[1]
class CertificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CertificationError(message)


def hash_file(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"input is not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_content_revision() -> str:
    """Return the shared tracked-source revision using this certifier's error type."""
    try:
        return tracked_source_content_revision(ROOT)
    except TrackedSourceRevisionError as exc:
        raise CertificationError(str(exc)) from exc


def readonly_observation(path: Path) -> dict[str, Any]:
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=30)
        conn.execute("PRAGMA query_only=ON")
        integrity = [str(row[0]) for row in conn.execute("PRAGMA integrity_check")]
        require(integrity == ["ok"], f"SQLite integrity_check failed for {path}")
        tables = {str(row[0]) for row in conn.execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )}
        counts = {
            name: int(conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
            for name in EXPECTED_COUNTS if name in tables
        }
        query_only = int(conn.execute("PRAGMA query_only").fetchone()[0])
    except sqlite3.Error as exc:
        raise CertificationError(f"read-only SQLite inspection failed for {path}: {exc}") from exc
    finally:
        if "conn" in locals():
            conn.close()
    return {"integrity_check": integrity, "counts": counts, "query_only": query_only}


def load_migration_receipt(path: Path) -> tuple[dict[str, Any], str]:
    digest = hash_file(path)
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        content = receipt["content"]
        content_hash = hashlib.sha256(json.dumps(
            content, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        declared = receipt["content_sha256"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise CertificationError(f"invalid migration receipt: {exc}") from exc
    require(isinstance(receipt, dict) and isinstance(content, dict) and isinstance(declared, str),
            "invalid migration receipt structure")
    require(content_hash == declared, "migration receipt content hash mismatch")
    require(path.name == f"migration-{declared}.json", "migration receipt filename is not content-addressed")
    require(declared == LEGACY_JAA00_CONTENT_SHA256,
            "migration receipt is not the independently trusted JAA-00 receipt")
    require(digest == LEGACY_JAA00_RECEIPT_SHA256,
            "migration receipt bytes do not match the independently trusted JAA-00 receipt")
    require(content.get("format") == "jaa-00-online-snapshot-receipt/v2",
            "unsupported migration receipt format")
    repository = content.get("repository")
    require(isinstance(repository, dict)
            and repository.get("label") == "canonical-repository"
            and repository.get("revision") == LEGACY_JAA00_ADOPTION_REVISION,
            "migration receipt repository provenance is not the independently trusted JAA-00 adoption")
    return receipt, digest


def require_trusted_jaa00_receipt(path: Path, baseline: Path) -> dict[str, Any]:
    """Bind JAA-01 to JAA-00's independently certified preserved snapshot."""
    try:
        receipt = path.resolve(strict=True)
        data_root = receipt.parent.parent.resolve(strict=True)
    except OSError as exc:
        raise CertificationError("independently trusted JAA-00 receipt is unavailable") from exc
    expected_baseline = data_root / "databases" / "career_pipeline.sqlite3"
    try:
        baseline_resolved = baseline.resolve(strict=True)
    except OSError as exc:
        raise CertificationError("frozen baseline database is unavailable") from exc
    require(
        baseline_resolved == expected_baseline,
        "baseline is not the independently trusted JAA-00 career-pipeline snapshot",
    )
    try:
        review = independent_review(receipt, data_root, ROOT)
    except (AdoptionError, OSError, ValueError, KeyError) as exc:
        raise CertificationError(
            "migration receipt is not independently trusted JAA-00 evidence"
        ) from exc
    require(review.get("status") == "certified", "JAA-00 independent review did not certify")
    return review


def require_unlinked_output_path(path: Path) -> None:
    """Reject an output path containing any existing symbolic-link component."""
    absolute = Path(os.path.abspath(path))
    for component in (absolute, *absolute.parents):
        require(not component.is_symlink(), f"output path must not resolve through a symlink: {path}")
    require(absolute.resolve(strict=False) == absolute,
            f"output path must not resolve through a symlink: {path}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--baseline-database", required=True)
    result.add_argument("--migration-receipt", required=True)
    result.add_argument("--evidence-directory", default="runtime_evidence/jaa01")
    return result


def certify(args: argparse.Namespace) -> Path:
    revision = source_content_revision()
    baseline = Path(args.baseline_database)
    migration_receipt = Path(args.migration_receipt)
    evidence_directory = Path(args.evidence_directory)
    require_unlinked_output_path(evidence_directory)

    baseline_hash_before = hash_file(baseline)
    receipt, receipt_file_hash_before = load_migration_receipt(migration_receipt)
    jaa00_review = require_trusted_jaa00_receipt(migration_receipt, baseline)
    frozen = receipt["content"]["databases"]["career_pipeline"]["frozen_snapshot"]
    require(frozen["sha256"] == baseline_hash_before, "baseline hash disagrees with migration receipt")
    require({name: int(frozen["table_counts"][name]) for name in EXPECTED_COUNTS} == EXPECTED_COUNTS,
            "migration receipt has unexpected frozen counts")

    baseline_before = readonly_observation(baseline)
    require(baseline_before["counts"] == EXPECTED_COUNTS, "baseline counts are not 462/924")

    with tempfile.TemporaryDirectory(prefix="jaa01-runtime-") as directory:
        migrated = Path(directory) / "career_pipeline.sqlite3"
        shutil.copyfile(baseline, migrated)
        pre_migration = readonly_observation(migrated)
        require(pre_migration["counts"] == EXPECTED_COUNTS, "temporary copy changed pre-existing counts")
        # JAA-01 evidence must remain pinned to the JAA-01 migration boundary.
        # Instantiating CareerDatabase here is incorrect once later slices extend
        # its schema: that production wrapper deliberately applies the latest
        # migrations and would make a historical JAA-01 proof certify JAA-02 (and
        # every future migration) by accident.
        lifecycle = LifecycleReducer(migrated)
        lifecycle.verify()
        post_migration = readonly_observation(migrated)
        require(post_migration["counts"] == EXPECTED_COUNTS,
                "migration changed pre-existing pipeline job/event counts")
        with sqlite3.connect(migrated) as conn:
            versions = [int(row[0]) for row in conn.execute(
                "SELECT version FROM career_schema_migrations ORDER BY version"
            )]
            receipts = int(conn.execute("SELECT COUNT(*) FROM lifecycle_transition_receipts").fetchone()[0])
        require(versions == [migration.version for migration in JAA_01_MIGRATIONS],
                "temporary copy has unexpected migration versions")
        require(receipts == 0, "frozen baseline unexpectedly gained transition receipts")

    scenario = reproduce()
    require(scenario["replay_equal"] and scenario["identical_retry_unchanged"],
            "Terra replay or retry invariant failed")

    baseline_hash_after = hash_file(baseline)
    receipt_file_hash_after = hash_file(migration_receipt)
    require(baseline_hash_after == baseline_hash_before, "baseline database changed during certification")
    require(receipt_file_hash_after == receipt_file_hash_before, "migration receipt changed during certification")
    require(readonly_observation(baseline) == baseline_before,
            "baseline read-only continuity changed during certification")

    require(source_content_revision() == revision,
            "tracked source content changed during certification")

    evidence: dict[str, Any] = {
        "format": FORMAT,
        "jaa00_trust": {
            "status": jaa00_review["status"],
            "receipt_content_sha256": receipt["content_sha256"],
            "contract": jaa00_review["receipt_provenance"]["contract"],
        },
        "source_content_revision": revision,
        "source_content_revision_contract": source_content_revision_contract(),
        "labels": {
            "baseline": "frozen-baseline:career-pipeline",
            "migration_receipt": "jaa00:migration-receipt",
            "temporary_copy": "ephemeral:migrated-career-pipeline",
        },
        "command_semantics": {
            "working_directory": "repository-root",
            "argv": [
                "python3", "scripts/certify_jaa01_runtime.py",
                "--baseline-database", "<frozen-baseline-database>",
                "--migration-receipt", "<migration-receipt>",
            ],
            "migration_target": "temporary-copy-only",
            "inputs_opened_read_only": True,
        },
        "expected_counts": EXPECTED_COUNTS,
        "observed_counts": {
            "baseline_before": baseline_before["counts"],
            "temporary_before_migration": pre_migration["counts"],
            "temporary_after_migration": post_migration["counts"],
        },
        "hashes": {
            "baseline_sha256_before": baseline_hash_before,
            "baseline_sha256_after": baseline_hash_after,
            "migration_receipt_file_sha256_before": receipt_file_hash_before,
            "migration_receipt_file_sha256_after": receipt_file_hash_after,
            "migration_receipt_content_sha256": receipt["content_sha256"],
        },
        "migration_receipt_trust": {
            "contract": "jaa-00-legacy-content-addressed-review/v1",
            "content_sha256": LEGACY_JAA00_CONTENT_SHA256,
            "file_sha256": LEGACY_JAA00_RECEIPT_SHA256,
            "adoption_revision": LEGACY_JAA00_ADOPTION_REVISION,
        },
        "migration_versions": versions,
        "baseline_integrity_check": baseline_before["integrity_check"],
        "read_only_continuity": True,
        "scenario": scenario,
    }
    payload = (json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    content_hash = hashlib.sha256(payload).hexdigest()
    evidence_directory.mkdir(parents=True, exist_ok=True)
    require_unlinked_output_path(evidence_directory)
    destination = evidence_directory / f"sha256-{content_hash}.json"
    require_unlinked_output_path(destination)
    existing = list(evidence_directory.glob("*.json"))
    require(not existing or existing == [destination],
            "refusing to retain multiple JAA-01 certification receipts")
    if destination.exists():
        require(destination.read_bytes() == payload, "content-addressed evidence file mismatch")
    else:
        destination.write_bytes(payload)
    require_unlinked_output_path(destination)
    return destination


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        destination = certify(args)
    except CertificationError as exc:
        print(f"jaa01-runtime-certification: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "certified", "receipt": destination.as_posix()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
