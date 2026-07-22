"""Black-box adversarial certification checks for JAA-01 runtime evidence.

The tests use subprocesses and ordinary SQLite files; no certification or
lifecycle implementation function is substituted.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from career_automation.database import SCHEMA


ROOT = Path(__file__).resolve().parent
CERTIFIER = ROOT / "scripts" / "certify_jaa01_runtime.py"
REPRODUCER = ROOT / "scripts" / "reproduce_jaa01_terra_rejection.py"
MIGRATION_CONTENT_HASH = "4f2dddaab89ea49ef991ad8a4d8598c03062c4b3ecbf11f85451ab9239a8ec66"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _jaa01_receipt() -> Path:
    receipts = sorted((ROOT / "runtime_evidence" / "jaa01").glob("sha256-*.json"))
    assert len(receipts) == 1, f"expected exactly one checked-in JAA-01 receipt, found {receipts}"
    return receipts[0]


def _runtime() -> Path:
    for parent in ROOT.parents:
        candidate = parent / "state" / "runtime" / "job-application-baseline-20260720-v2"
        if candidate.is_dir():
            return candidate
    pytest.fail("frozen JAA-00 runtime is unavailable")


def _make_legacy_database(path: Path, jobs: int = 462, events: int = 924) -> None:
    """Make an on-disk pre-migration ledger with the certification's exact counts."""
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA)
        connection.executemany(
            """INSERT INTO pipeline_jobs(
                 job_key,board,job_id,url,title,company,opportunity,payload_json,payload_hash,state
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            [
                (f"legacy:{number}", "legacy", str(number), f"https://example.test/{number}",
                "Engineer", "Example", 0.8, "{}", f"{number:064x}", "opportunity_rejected")
                for number in range(jobs)
            ],
        )
        connection.commit()
        # Certification copies the frozen main database file, so make this a
        # stable legacy artifact rather than an uncheckpointed WAL view.
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.executemany(
            """INSERT INTO pipeline_events(
                 job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
               ) VALUES(?,?,?,?,?,?,?)""",
            [
                (f"legacy:{number // 2 if events <= 2 * jobs else number % jobs}",
                 "score_snapshot_imported" if number % 2 == 0 else "opportunity_gate_decided",
                 None if number % 2 == 0 else "scored",
                 "scored" if number % 2 == 0 else "opportunity_rejected",
                 "deterministic", "{}", f"legacy-event:{number}")
                for number in range(events)
            ],
        )


def _migration_receipt(path: Path, database: Path, *, counts: dict[str, int] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    frozen_counts = counts or {"pipeline_jobs": 462, "pipeline_events": 924}
    content = {
        "format": "jaa-00-online-snapshot-receipt/v2",
        "databases": {"career_pipeline": {"frozen_snapshot": {
            "sha256": _sha256(database), "table_counts": frozen_counts,
        }}},
    }
    digest = hashlib.sha256(json.dumps(
        content, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    path.write_text(json.dumps({"content": content, "content_sha256": digest}), encoding="utf-8")
    path.rename(path.with_name(f"migration-{digest}.json"))


def _receipt_for(database: Path, directory: Path) -> Path:
    provisional = directory / "receipt.json"
    _migration_receipt(provisional, database)
    return next(directory.glob("migration-*.json"))


@pytest.fixture()
def clean_certifier_root(tmp_path: Path) -> Path:
    """Run clean-tree certification checks outside this edited test checkout."""
    clone = tmp_path / "clean-certifier-repository"
    cloned = subprocess.run(
        ["git", "clone", "--no-local", str(ROOT), str(clone)],
        text=True, capture_output=True, check=False,
    )
    assert cloned.returncode == 0, cloned.stderr
    cloned_certifier = clone / CERTIFIER.relative_to(ROOT)
    shutil.copyfile(CERTIFIER, cloned_certifier)
    changed = subprocess.run(
        ["git", "diff", "--quiet", "--", str(CERTIFIER.relative_to(ROOT))], cwd=clone,
        check=False,
    )
    if changed.returncode == 1:
        for command in (
            ["git", "add", str(CERTIFIER.relative_to(ROOT))],
            ["git", "-c", "user.name=JAA-01 test", "-c", "user.email=jaa01@example.test",
             "commit", "-m", "test current JAA-01 certifier"],
        ):
            completed = subprocess.run(command, cwd=clone, text=True, capture_output=True, check=False)
            assert completed.returncode == 0, completed.stderr
    else:
        assert changed.returncode == 0
    return clone


def _run(
    database: Path, receipt: Path, evidence: Path, certifier_root: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(certifier_root / CERTIFIER.relative_to(ROOT)), "--baseline-database", str(database),
         "--migration-receipt", str(receipt), "--evidence-directory", str(evidence)],
        cwd=certifier_root, text=True, capture_output=True, check=False,
    )


def test_terra_rejection_script_observes_real_actor_states_receipts_retry_and_replay() -> None:
    result = subprocess.run([sys.executable, str(REPRODUCER)], cwd=ROOT, text=True,
                            capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed == {
        "scenario": "jaa01-terra-rejected-complete-research",
        "database": "real-temporary-sqlite-file",
        "rejected_attempt": {"events": 3, "receipts": 2, "dossiers": 0},
        "final_state": "employer_researched", "events": 5, "receipts": 3,
        "proposal_events": 1, "completion_events": 1, "completion_receipts": 1,
        "completion_receipt_binding": "event_id", "replay_equal": True,
        "identical_retry_unchanged": True,
    }


def test_runtime_certifier_writes_disposable_absolute_evidence_and_fails_closed(
    tmp_path: Path, clean_certifier_root: Path,
) -> None:
    runtime = _runtime()
    database = runtime / "databases" / "career_pipeline.sqlite3"
    receipt = runtime / "receipts" / f"migration-{MIGRATION_CONTENT_HASH}.json"
    database_hash_before = _sha256(database)
    receipt_hash_before = _sha256(receipt)
    evidence = tmp_path / "absolute-evidence"
    certified = _run(database, receipt, evidence, clean_certifier_root)
    assert certified.returncode == 0, certified.stderr
    document_path = Path(json.loads(certified.stdout)["receipt"])
    assert document_path.parent == evidence
    payload = document_path.read_text(encoding="utf-8")
    document = json.loads(payload)
    assert document_path.name == f"sha256-{hashlib.sha256(document_path.read_bytes()).hexdigest()}.json"
    assert document["expected_counts"] == {"pipeline_jobs": 462, "pipeline_events": 924}
    assert document["observed_counts"]["baseline_before"] == {"pipeline_jobs": 462, "pipeline_events": 924}
    assert document["migration_versions"] == [1]
    assert document["migration_receipt_trust"] == {
        "contract": "jaa-00-legacy-content-addressed-review/v1",
        "content_sha256": MIGRATION_CONTENT_HASH,
        "file_sha256": receipt_hash_before,
        "adoption_revision": "d74c77cac3c121cd6c09f0f8b8f64cd46014e4ec",
    }
    assert document["scenario"]["replay_equal"] is True
    assert "live_sources" not in document
    assert document["command_semantics"]["argv"] == [
        "python3", "scripts/certify_jaa01_runtime.py",
        "--baseline-database", "<frozen-baseline-database>",
        "--migration-receipt", "<migration-receipt>",
    ]
    assert str(tmp_path) not in payload
    assert not any(value.startswith("/") for value in _strings(document))
    assert _sha256(database) == database_hash_before
    assert _sha256(receipt) == receipt_hash_before

    # A conflicting pre-existing content-addressed receipt cannot be overwritten.
    document_path.write_text("{}", encoding="utf-8")
    fabricated = _run(database, receipt, evidence, clean_certifier_root)
    assert fabricated.returncode == 2
    assert "content-addressed evidence file mismatch" in fabricated.stderr
    assert document_path.read_text(encoding="utf-8") == "{}"

    changed_database = tmp_path / "changed.sqlite3"
    shutil.copyfile(database, changed_database)
    with sqlite3.connect(changed_database) as connection:
        connection.execute("PRAGMA user_version=42")
    hash_changed = _run(
        changed_database, receipt, tmp_path / "negative-hash", clean_certifier_root,
    )
    assert hash_changed.returncode == 2 and "baseline hash disagrees" in hash_changed.stderr

    fabricated_database = tmp_path / "fabricated.sqlite3"
    _make_legacy_database(fabricated_database)
    fabricated_receipt = _receipt_for(fabricated_database, tmp_path / "fabricated-receipt")
    fabricated = _run(
        fabricated_database, fabricated_receipt, tmp_path / "negative-fabricated",
        clean_certifier_root,
    )
    assert fabricated.returncode == 2
    assert "independently trusted JAA-00 receipt" in fabricated.stderr

    altered = tmp_path / "altered-receipt.json"
    altered.write_text(receipt.read_text(encoding="utf-8").replace("online", "forged", 1), encoding="utf-8")
    receipt_changed = _run(database, altered, tmp_path / "negative-receipt", clean_certifier_root)
    assert receipt_changed.returncode == 2 and "content hash mismatch" in receipt_changed.stderr

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a sqlite database")
    corrupt_result = _run(corrupt, receipt, tmp_path / "negative-corrupt", clean_certifier_root)
    assert corrupt_result.returncode == 2
    assert "baseline hash disagrees" in corrupt_result.stderr


def test_runtime_certifier_rejects_symlinked_evidence_directory_without_writing_receipt(
    tmp_path: Path, clean_certifier_root: Path,
) -> None:
    database = tmp_path / "legacy.sqlite3"
    _make_legacy_database(database)
    receipt = _receipt_for(database, tmp_path)
    actual_output = tmp_path / "actual-evidence"
    actual_output.mkdir()
    symlinked_output = tmp_path / "symlinked-evidence"
    symlinked_output.symlink_to(actual_output, target_is_directory=True)

    rejected = _run(database, receipt, symlinked_output, clean_certifier_root)

    assert rejected.returncode == 2
    assert "output path must not resolve through a symlink" in rejected.stderr
    assert list(actual_output.iterdir()) == []


def test_runtime_certifier_command_contract_rejects_mutable_live_source_input() -> None:
    completed = subprocess.run(
        [sys.executable, str(CERTIFIER), "--baseline-database", "frozen.sqlite3",
         "--migration-receipt", "migration.json", "--live-source", "raw-jobs=live.sqlite3"],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 2
    assert "unrecognized arguments: --live-source" in completed.stderr


def test_checked_in_jaa01_evidence_is_historical_content_addressed_and_path_free() -> None:
    runtime = _runtime()
    database = runtime / "databases" / "career_pipeline.sqlite3"
    receipt = runtime / "receipts" / f"migration-{MIGRATION_CONTENT_HASH}.json"
    evidence = _jaa01_receipt()
    payload = evidence.read_bytes()
    document = json.loads(payload)
    migration = json.loads(receipt.read_text(encoding="utf-8"))

    assert evidence.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    assert document["format"] == "jaa01-runtime-certification/v1"
    assert document["hashes"] == {
        "baseline_sha256_before": _sha256(database), "baseline_sha256_after": _sha256(database),
        "migration_receipt_file_sha256_before": _sha256(receipt),
        "migration_receipt_file_sha256_after": _sha256(receipt),
        "migration_receipt_content_sha256": migration["content_sha256"],
    }
    assert document["expected_counts"] == {"pipeline_jobs": 462, "pipeline_events": 924}
    assert document["observed_counts"] == {
        name: {"pipeline_jobs": 462, "pipeline_events": 924}
        for name in ("baseline_before", "temporary_before_migration", "temporary_after_migration")
    }
    assert document["scenario"]["receipts"] == 3
    assert document["scenario"]["replay_equal"] is True
    assert document["scenario"]["identical_retry_unchanged"] is True
    assert document["migration_receipt_trust"] == {
        "contract": "jaa-00-legacy-content-addressed-review/v1",
        "content_sha256": MIGRATION_CONTENT_HASH,
        "file_sha256": _sha256(receipt),
        "adoption_revision": "d74c77cac3c121cd6c09f0f8b8f64cd46014e4ec",
    }
    # A checked-in receipt records what its historical certification observed.
    # Present mutable-source state belongs exclusively to JAA-00 recertification,
    # so this test deliberately neither opens those databases nor compares hashes.
    assert str(runtime) not in payload.decode("utf-8")
    assert not any(value.startswith("/") for value in _strings(document))

def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _strings(child)]
    return []
