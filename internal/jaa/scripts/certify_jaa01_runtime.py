#!/usr/bin/env python3
"""Certify JAA-01 against an operator-selected frozen SQLite baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from career_automation.lifecycle import LifecycleReducer
from career_automation.migrations import (
    JAA00_LEGACY_BOUNDARY_SHA256,
    JAA_01_MIGRATIONS,
    legacy_boundary_digest,
)
from scripts.reproduce_jaa01_terra_rejection import reproduce
from tracked_source_revision import (
    TrackedSourceRevisionError,
    source_content_revision as tracked_source_content_revision,
    source_content_revision_contract,
    source_git_revision as tracked_source_git_revision,
    source_git_revision_contract,
)

EXPECTED_COUNTS = {"pipeline_jobs": 462, "pipeline_events": 924}
FORMAT = "jaa01-runtime-certification/v1"
ROOT = Path(__file__).resolve().parents[1]
JAA00_EVIDENCE = Path("runtime_evidence/JAA-00-online-snapshot.yaml")
JAA00_EVIDENCE_SHA256 = (
    "bf4a9726c9d0608f21fadcf2591bcc8ba92516cca9659288fc28e7b9452ed161"
)
JAA00_RECEIPT_CONTENT_SHA256 = (
    "b38b38fc4455ce6142ca156a4eff400c5dba22ab04d64f02fce8cd332fe08971"
)
JAA00_RECEIPT_FILE_SHA256 = (
    "a5c878dd91ee80a1709c5c8d17b64e9ac0486c917029a1d69e2c514db73f5357"
)
JAA00_CAREER_PIPELINE_SHA256 = (
    "6f57c4d62ea22cfd303a9481e2620cc6f747540597d9de96b5e5822abcb7b328"
)
JAA00_LEGACY_REVISION = "b7b9f4bf02b2bf5463aa40281f2b0bb34042f4b6"
JAA_SUBTREE_IMPORT_COMMIT = "cb5da012c840b65a768a9b87db56a71a81082cd0"
JAA_SUBTREE_SYNTHETIC_COMMIT = "c05fa7ab6ea17d7eca00c72d490db182a3d97ab2"
JAA_SUBTREE_SPLIT_REVISION = "d56969dd94402186aa054fd1abe6ad8f142525d2"
JAA_SUBTREE_TREE = "66082d2ca3d2c6ab21c7440ebd37dd1f892ec237"


class CertificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CertificationError(message)


def hash_file(path: Path) -> str:
    require(
        path.is_file() and not path.is_symlink(), f"input is not a regular file: {path}"
    )
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


def source_git_revision() -> str:
    """Return exact HEAD using this certifier's fail-closed error type."""
    try:
        return tracked_source_git_revision(ROOT)
    except TrackedSourceRevisionError as exc:
        raise CertificationError(str(exc)) from exc


def _git_output(*argv: str) -> str:
    completed = subprocess.run(
        ("git", *argv),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(
        completed.returncode == 0,
        f"cannot verify JAA Git lineage: {completed.stderr.strip()}",
    )
    return completed.stdout.strip()


def require_trusted_jaa00_lineage(evidence_revision: str) -> dict[str, str]:
    """Accept direct legacy ancestry or its exact, immutable subtree import."""
    prefix = _git_output("rev-parse", "--show-prefix")
    imported = subprocess.run(
        ("git", "merge-base", "--is-ancestor", JAA_SUBTREE_IMPORT_COMMIT, "HEAD"),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if prefix != "internal/jaa/" or imported.returncode != 0:
        direct = subprocess.run(
            ("git", "merge-base", "--is-ancestor", evidence_revision, "HEAD"),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if direct.returncode == 0:
            return {
                "mode": "direct-ancestor",
                "legacy_revision": evidence_revision,
            }

    require(
        evidence_revision == JAA00_LEGACY_REVISION,
        "tracked JAA-00 certification revision is not trusted legacy provenance",
    )
    require(
        imported.returncode == 0,
        "tracked JAA-00 certification revision has no trusted Market Aligner import",
    )
    require(
        prefix == "internal/jaa/",
        "trusted JAA subtree import is not running inside canonical Market Aligner",
    )
    import_record = _git_output(
        "rev-list", "--parents", "-n", "1", JAA_SUBTREE_IMPORT_COMMIT
    ).split()
    require(
        JAA_SUBTREE_SYNTHETIC_COMMIT in import_record[1:],
        "trusted JAA subtree import is missing its synthetic source parent",
    )
    synthetic_tree = _git_output(
        "rev-parse", f"{JAA_SUBTREE_SYNTHETIC_COMMIT}^{{tree}}"
    )
    imported_tree = _git_output(
        "rev-parse", f"{JAA_SUBTREE_IMPORT_COMMIT}:internal/jaa"
    )
    require(
        synthetic_tree == imported_tree == JAA_SUBTREE_TREE,
        "trusted JAA subtree import tree does not match its source snapshot",
    )
    import_message = _git_output(
        "show", "-s", "--format=%B", JAA_SUBTREE_SYNTHETIC_COMMIT
    )
    require(
        f"git-subtree-split: {JAA_SUBTREE_SPLIT_REVISION}" in import_message,
        "trusted JAA subtree import is missing its source revision binding",
    )
    return {
        "mode": "git-subtree-import",
        "legacy_revision": evidence_revision,
        "source_split_revision": JAA_SUBTREE_SPLIT_REVISION,
        "synthetic_commit": JAA_SUBTREE_SYNTHETIC_COMMIT,
        "import_commit": JAA_SUBTREE_IMPORT_COMMIT,
        "imported_tree": JAA_SUBTREE_TREE,
    }


def readonly_observation(path: Path) -> dict[str, Any]:
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=30)
        conn.execute("PRAGMA query_only=ON")
        integrity = [str(row[0]) for row in conn.execute("PRAGMA integrity_check")]
        require(integrity == ["ok"], f"SQLite integrity_check failed for {path}")
        tables = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")
        }
        counts = {
            name: int(conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
            for name in EXPECTED_COUNTS
            if name in tables
        }
        query_only = int(conn.execute("PRAGMA query_only").fetchone()[0])
    except sqlite3.Error as exc:
        raise CertificationError(
            f"read-only SQLite inspection failed for {path}: {exc}"
        ) from exc
    finally:
        if "conn" in locals():
            conn.close()
    return {"integrity_check": integrity, "counts": counts, "query_only": query_only}


def load_migration_receipt(path: Path) -> tuple[dict[str, Any], str]:
    digest = hash_file(path)
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        content = receipt["content"]
        content_hash = hashlib.sha256(
            json.dumps(
                content, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        declared = receipt["content_sha256"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise CertificationError(f"invalid migration receipt: {exc}") from exc
    require(
        isinstance(receipt, dict)
        and isinstance(content, dict)
        and isinstance(declared, str),
        "invalid migration receipt structure",
    )
    require(content_hash == declared, "migration receipt content hash mismatch")
    require(
        path.name == f"migration-{declared}.json",
        "migration receipt filename is not content-addressed",
    )
    require(
        declared == JAA00_RECEIPT_CONTENT_SHA256,
        "migration receipt is not the independently trusted JAA-00 receipt",
    )
    require(
        digest == JAA00_RECEIPT_FILE_SHA256,
        "migration receipt bytes do not match the independently trusted JAA-00 receipt",
    )
    require(
        content.get("format") == "jaa-00-online-snapshot-receipt/v2",
        "unsupported migration receipt format",
    )
    return receipt, digest


def require_trusted_jaa00_receipt(
    path: Path,
    baseline: Path,
    receipt_document: dict[str, Any],
) -> dict[str, Any]:
    """Bind JAA-01 to JAA-00's certified evidence and preserved snapshot."""
    try:
        receipt = path.resolve(strict=True)
        data_root = receipt.parent.parent.resolve(strict=True)
    except OSError as exc:
        raise CertificationError(
            "independently trusted JAA-00 receipt is unavailable"
        ) from exc
    expected_baseline = data_root / "databases" / "career_pipeline.sqlite3"
    try:
        baseline_resolved = baseline.resolve(strict=True)
    except OSError as exc:
        raise CertificationError("frozen baseline database is unavailable") from exc
    require(
        baseline_resolved == expected_baseline,
        "baseline is not the independently trusted JAA-00 career-pipeline snapshot",
    )

    evidence_path = ROOT / JAA00_EVIDENCE
    try:
        evidence_stat = evidence_path.lstat()
    except OSError as exc:
        raise CertificationError(
            "tracked JAA-00 certification evidence is unavailable"
        ) from exc
    require(
        stat.S_ISREG(evidence_stat.st_mode) and not stat.S_ISLNK(evidence_stat.st_mode),
        "tracked JAA-00 certification evidence is not a regular file",
    )

    relative_evidence = JAA00_EVIDENCE.as_posix()
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", relative_evidence],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    unchanged = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--", relative_evidence],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(
        tracked.returncode == 0 and unchanged.returncode == 0,
        "tracked JAA-00 certification evidence must be tracked and unchanged",
    )
    require(
        hash_file(evidence_path) == JAA00_EVIDENCE_SHA256,
        "tracked JAA-00 certification evidence bytes are not trusted",
    )

    try:
        import yaml

        evidence = yaml.safe_load(evidence_path.read_bytes())
        database_evidence = evidence["databases"]["career_pipeline"]
        evidence_repository = evidence["repository"]
        evidence_certification = evidence["revision_binding"]["certification"]
        receipt_content = receipt_document["content"]
        receipt_repository = receipt_content["repository"]
        receipt_certification = receipt_content["certification"]
        receipt_database = receipt_content["databases"]["career_pipeline"][
            "frozen_snapshot"
        ]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise CertificationError(
            "tracked JAA-00 certification evidence is invalid"
        ) from exc
    require(
        evidence.get("evidence") == "JAA-00:first-adopted-frozen-baseline"
        and evidence.get("publication", {}).get("verification")
        == "fail-closed-independent-review"
        and evidence.get("reconciliation", {}).get("result") == "ok",
        "tracked JAA-00 certification evidence is not independently verified",
    )
    require(
        evidence.get("receipt", {}).get("content_sha256")
        == JAA00_RECEIPT_CONTENT_SHA256,
        "tracked JAA-00 evidence does not bind the trusted receipt",
    )
    require(
        receipt_document.get("content_sha256") == JAA00_RECEIPT_CONTENT_SHA256
        and receipt_repository == evidence_repository
        and receipt_certification == evidence_certification,
        "trusted JAA-00 receipt provenance disagrees with certification evidence",
    )
    require(
        database_evidence.get("snapshot_sha256") == JAA00_CAREER_PIPELINE_SHA256
        and database_evidence.get("snapshot_sha256") == hash_file(baseline)
        and receipt_database.get("sha256") == database_evidence.get("snapshot_sha256")
        and receipt_database.get("table_counts") == database_evidence.get("counts")
        and database_evidence.get("counts", {}).get("pipeline_jobs")
        == EXPECTED_COUNTS["pipeline_jobs"]
        and database_evidence.get("counts", {}).get("pipeline_events")
        == EXPECTED_COUNTS["pipeline_events"]
        and database_evidence.get("integrity_check") == ["ok"],
        "tracked JAA-00 certification evidence does not bind the frozen baseline",
    )

    evidence_revision = evidence_repository.get("revision")
    require(
        evidence_repository.get("label") == "canonical-repository"
        and isinstance(evidence_revision, str)
        and len(evidence_revision) == 40,
        "tracked JAA-00 certification evidence has invalid repository provenance",
    )
    lineage = require_trusted_jaa00_lineage(evidence_revision)
    return {
        "status": "certified",
        "receipt_provenance": {
            "contract": "jaa-00-exact-evidence-trust-anchor/v1",
        },
        "evidence_sha256": JAA00_EVIDENCE_SHA256,
        "receipt_file_sha256": JAA00_RECEIPT_FILE_SHA256,
        "certified_revision": evidence_revision,
        "lineage": lineage,
    }


def require_unlinked_output_path(path: Path) -> None:
    """Reject an output path containing any existing symbolic-link component."""
    absolute = Path(os.path.abspath(path))
    for component in (absolute, *absolute.parents):
        require(
            not component.is_symlink(),
            f"output path must not resolve through a symlink: {path}",
        )
    require(
        absolute.resolve(strict=False) == absolute,
        f"output path must not resolve through a symlink: {path}",
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--baseline-database", required=True)
    result.add_argument("--migration-receipt", required=True)
    result.add_argument("--expected-source-commit", required=True)
    result.add_argument("--evidence-directory", default="runtime_evidence/jaa01")
    return result


def certify(args: argparse.Namespace) -> Path:
    revision = source_content_revision()
    git_revision = source_git_revision()
    require(
        args.expected_source_commit == git_revision,
        "source Git revision does not match the expected component revision",
    )
    baseline = Path(args.baseline_database)
    migration_receipt = Path(args.migration_receipt)
    evidence_directory = Path(args.evidence_directory)
    require_unlinked_output_path(evidence_directory)

    baseline_hash_before = hash_file(baseline)
    receipt, receipt_file_hash_before = load_migration_receipt(migration_receipt)
    jaa00_review = require_trusted_jaa00_receipt(migration_receipt, baseline, receipt)
    frozen = receipt["content"]["databases"]["career_pipeline"]["frozen_snapshot"]
    require(
        frozen["sha256"] == baseline_hash_before,
        "baseline hash disagrees with migration receipt",
    )
    require(
        {name: int(frozen["table_counts"][name]) for name in EXPECTED_COUNTS}
        == EXPECTED_COUNTS,
        "migration receipt has unexpected frozen counts",
    )

    baseline_before = readonly_observation(baseline)
    require(
        baseline_before["counts"] == EXPECTED_COUNTS, "baseline counts are not 462/924"
    )

    with tempfile.TemporaryDirectory(prefix="jaa01-runtime-") as directory:
        migrated = Path(directory) / "career_pipeline.sqlite3"
        shutil.copyfile(baseline, migrated)
        pre_migration = readonly_observation(migrated)
        require(
            pre_migration["counts"] == EXPECTED_COUNTS,
            "temporary copy changed pre-existing counts",
        )
        # JAA-01 evidence must remain pinned to the JAA-01 migration boundary.
        # Instantiating CareerDatabase here is incorrect once later slices extend
        # its schema: that production wrapper deliberately applies the latest
        # migrations and would make a historical JAA-01 proof certify JAA-02 (and
        # every future migration) by accident.
        lifecycle = LifecycleReducer(migrated)
        lifecycle.verify()
        post_migration = readonly_observation(migrated)
        require(
            post_migration["counts"] == EXPECTED_COUNTS,
            "migration changed pre-existing pipeline job/event counts",
        )
        with sqlite3.connect(migrated) as conn:
            versions = [
                int(row[0])
                for row in conn.execute(
                    "SELECT version FROM career_schema_migrations ORDER BY version"
                )
            ]
            receipts = int(
                conn.execute(
                    "SELECT COUNT(*) FROM lifecycle_transition_receipts"
                ).fetchone()[0]
            )
            score_receipts = int(
                conn.execute("SELECT COUNT(*) FROM score_snapshot_receipts").fetchone()[
                    0
                ]
            )
            legacy_cohort = int(
                conn.execute(
                    "SELECT COUNT(*) FROM legacy_score_snapshot_cohort"
                ).fetchone()[0]
            )
            legacy_gate_cohort = int(
                conn.execute(
                    "SELECT COUNT(*) FROM legacy_opportunity_gate_cohort"
                ).fetchone()[0]
            )
            boundary_digest = legacy_boundary_digest(conn)
        require(
            versions == [migration.version for migration in JAA_01_MIGRATIONS],
            "temporary copy has unexpected migration versions",
        )
        require(
            receipts == 0, "frozen baseline unexpectedly gained transition receipts"
        )
        require(
            score_receipts == 0, "frozen baseline unexpectedly gained score receipts"
        )
        require(
            legacy_cohort == EXPECTED_COUNTS["pipeline_jobs"],
            "frozen baseline legacy score cohort is incomplete",
        )
        require(
            legacy_gate_cohort == EXPECTED_COUNTS["pipeline_jobs"],
            "frozen baseline legacy opportunity gate cohort is incomplete",
        )
        require(
            boundary_digest == JAA00_LEGACY_BOUNDARY_SHA256,
            "migrated legacy boundary no longer matches certified JAA-00",
        )

    scenario = reproduce()
    require(
        scenario["replay_equal"] and scenario["identical_retry_unchanged"],
        "Terra replay or retry invariant failed",
    )

    baseline_hash_after = hash_file(baseline)
    receipt_file_hash_after = hash_file(migration_receipt)
    require(
        baseline_hash_after == baseline_hash_before,
        "baseline database changed during certification",
    )
    require(
        receipt_file_hash_after == receipt_file_hash_before,
        "migration receipt changed during certification",
    )
    require(
        readonly_observation(baseline) == baseline_before,
        "baseline read-only continuity changed during certification",
    )

    require(
        source_content_revision() == revision,
        "tracked source content changed during certification",
    )
    require(
        source_git_revision() == git_revision,
        "source Git revision changed during certification",
    )

    evidence: dict[str, Any] = {
        "format": FORMAT,
        "jaa00_trust": {
            "status": jaa00_review["status"],
            "receipt_content_sha256": receipt["content_sha256"],
            "contract": jaa00_review["receipt_provenance"]["contract"],
            "evidence_sha256": jaa00_review["evidence_sha256"],
            "receipt_file_sha256": jaa00_review["receipt_file_sha256"],
            "certified_revision": jaa00_review["certified_revision"],
            "lineage": jaa00_review["lineage"],
        },
        "source_content_revision": revision,
        "source_content_revision_contract": source_content_revision_contract(),
        "source_git_revision": git_revision,
        "source_git_revision_contract": source_git_revision_contract(),
        "labels": {
            "baseline": "frozen-baseline:career-pipeline",
            "migration_receipt": "jaa00:migration-receipt",
            "temporary_copy": "ephemeral:migrated-career-pipeline",
        },
        "command_semantics": {
            "working_directory": "repository-root",
            "argv": [
                "python3",
                "scripts/certify_jaa01_runtime.py",
                "--baseline-database",
                "<frozen-baseline-database>",
                "--migration-receipt",
                "<migration-receipt>",
                "--expected-source-commit",
                "<exact-source-commit>",
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
            "contract": "jaa-00-exact-evidence-trust-anchor/v1",
            "content_sha256": JAA00_RECEIPT_CONTENT_SHA256,
            "file_sha256": receipt_file_hash_before,
            "certified_revision": jaa00_review["certified_revision"],
        },
        "migration_versions": versions,
        "legacy_boundary": {
            "manifest_sha256": boundary_digest,
            "pipeline_jobs": EXPECTED_COUNTS["pipeline_jobs"],
            "pipeline_events": EXPECTED_COUNTS["pipeline_events"],
            "score_snapshot_cohort": legacy_cohort,
            "opportunity_gate_cohort": legacy_gate_cohort,
        },
        "baseline_integrity_check": baseline_before["integrity_check"],
        "read_only_continuity": True,
        "scenario": scenario,
    }
    payload = (
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    content_hash = hashlib.sha256(payload).hexdigest()
    evidence_directory.mkdir(parents=True, exist_ok=True)
    require_unlinked_output_path(evidence_directory)
    destination = evidence_directory / f"sha256-{content_hash}.json"
    require_unlinked_output_path(destination)
    existing = sorted(evidence_directory.glob("*.json"))
    for historical in existing:
        if historical == destination:
            continue
        match = re.fullmatch(r"sha256-([0-9a-f]{64})\.json", historical.name)
        require(
            match is not None
            and hashlib.sha256(historical.read_bytes()).hexdigest() == match.group(1),
            "historical JAA-01 receipt is not valid content-addressed evidence",
        )
    if destination.exists():
        require(
            destination.read_bytes() == payload,
            "content-addressed evidence file mismatch",
        )
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
    print(
        json.dumps(
            {"status": "certified", "receipt": destination.as_posix()}, sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
