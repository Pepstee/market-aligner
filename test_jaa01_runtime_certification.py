"""Black-box adversarial certification checks for JAA-01 runtime evidence.

The tests use subprocesses and ordinary SQLite files; no certification or
lifecycle implementation function is substituted.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote

import pytest

from career_automation.database import SCHEMA


ROOT = Path(__file__).resolve().parent
CERTIFIER = ROOT / "scripts" / "certify_jaa01_runtime.py"
REPRODUCER = ROOT / "scripts" / "reproduce_jaa01_terra_rejection.py"
MIGRATION_CONTENT_HASH = "4f2dddaab89ea49ef991ad8a4d8598c03062c4b3ecbf11f85451ab9239a8ec66"
LIVE_SOURCE_ROOT = Path("/Users/admin/Claude/Projects/Korea Job Scraper")
LIVE_SOURCES = {
    "career-pipeline": LIVE_SOURCE_ROOT / "outputs" / "career_automation" / "career_pipeline.sqlite3",
    "raw-jobs": LIVE_SOURCE_ROOT / "scraper" / "data_overnight" / "jobs.sqlite3",
}
EXPECTED_LIVE_SOURCE_BINDINGS = {
    "career-pipeline": {
        "label": "live-source:career-pipeline",
        "sha256_before": "dd99efe519b5fcfe09cba2a0d08d18ce6ce84d570ef8649c5d250ebba03f9a8b",
        "sha256_after": "dd99efe519b5fcfe09cba2a0d08d18ce6ce84d570ef8649c5d250ebba03f9a8b",
        "integrity_check": ["ok"],
        "read_only_query_only": True,
    },
    "raw-jobs": {
        "label": "live-source:raw-jobs",
        "sha256_before": "aac9ebcb8786c71edb1a3cb8921a34515f42a88a1a4e5813f2c505c66fd23940",
        "sha256_after": "aac9ebcb8786c71edb1a3cb8921a34515f42a88a1a4e5813f2c505c66fd23940",
        "integrity_check": ["ok"],
        "read_only_query_only": True,
    },
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _readonly_integrity_check(path: Path) -> tuple[list[str], int]:
    """Observe a source independently, without importing the certifier helper."""
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        connection.execute("PRAGMA query_only=ON")
        integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
        query_only = int(connection.execute("PRAGMA query_only").fetchone()[0])
    return integrity, query_only


def _jaa01_receipt() -> Path:
    receipts = sorted((ROOT / "runtime_evidence" / "jaa01").glob("sha256-*.json"))
    assert len(receipts) == 1, f"expected exactly one checked-in JAA-01 receipt, found {receipts}"
    return receipts[0]


def _assert_exact_live_source_bindings(document: dict[str, object]) -> None:
    """Require the receipt to bind precisely the two operator-selected live files."""
    live_sources = document["live_sources"]
    assert isinstance(live_sources, dict)
    assert set(live_sources) == set(LIVE_SOURCES)
    for logical_label, path in LIVE_SOURCES.items():
        assert path.is_file() and not path.is_symlink(), path
        binding = live_sources[logical_label]
        assert isinstance(binding, dict)
        # The raw collector remains live, so its later bytes must not be used
        # to rewrite an already content-addressed receipt.  Still open and
        # hash each selected file independently to prove the named sources are
        # usable SQLite files at verification time.
        actual_hash = _sha256(path)
        integrity, query_only = _readonly_integrity_check(path)
        assert len(actual_hash) == 64 and int(actual_hash, 16) >= 0
        assert integrity == ["ok"]
        assert query_only == 1
        assert binding == EXPECTED_LIVE_SOURCE_BINDINGS[logical_label]


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


def _run(database: Path, receipt: Path, evidence: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CERTIFIER), "--baseline-database", str(database),
         "--migration-receipt", str(receipt), "--evidence-directory", str(evidence)],
        cwd=ROOT, text=True, capture_output=True, check=False,
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


def test_runtime_certifier_writes_disposable_absolute_evidence_and_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite3"
    _make_legacy_database(database)
    receipt = _receipt_for(database, tmp_path)
    evidence = tmp_path / "absolute-evidence"
    certified = _run(database, receipt, evidence)
    assert certified.returncode == 0, certified.stderr
    document_path = Path(json.loads(certified.stdout)["receipt"])
    assert document_path.parent == evidence
    payload = document_path.read_text(encoding="utf-8")
    document = json.loads(payload)
    assert document_path.name == f"sha256-{hashlib.sha256(document_path.read_bytes()).hexdigest()}.json"
    assert document["expected_counts"] == {"pipeline_jobs": 462, "pipeline_events": 924}
    assert document["observed_counts"]["baseline_before"] == {"pipeline_jobs": 462, "pipeline_events": 924}
    assert document["migration_versions"] == [1]
    assert document["scenario"]["replay_equal"] is True
    assert str(tmp_path) not in payload
    assert not any(value.startswith("/") for value in _strings(document))

    # A conflicting pre-existing content-addressed receipt cannot be overwritten.
    document_path.write_text("{}", encoding="utf-8")
    fabricated = _run(database, receipt, evidence)
    assert fabricated.returncode == 2
    assert "content-addressed evidence file mismatch" in fabricated.stderr
    assert document_path.read_text(encoding="utf-8") == "{}"

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version=42")
    hash_changed = _run(database, receipt, tmp_path / "negative-hash")
    assert hash_changed.returncode == 2 and "baseline hash disagrees" in hash_changed.stderr

    for jobs, events in ((461, 924), (462, 923)):
        wrong = tmp_path / f"wrong-{jobs}-{events}.sqlite3"
        _make_legacy_database(wrong, jobs, events)
        wrong_receipt = _receipt_for(wrong, tmp_path / f"wrong-{jobs}-{events}")
        rejected = _run(wrong, wrong_receipt, tmp_path / f"negative-{jobs}-{events}")
        assert rejected.returncode == 2
        assert ("frozen counts" in rejected.stderr or "baseline counts" in rejected.stderr)

    altered = tmp_path / "altered-receipt.json"
    altered.write_text(receipt.read_text(encoding="utf-8").replace("online", "forged", 1), encoding="utf-8")
    receipt_changed = _run(database, altered, tmp_path / "negative-receipt")
    assert receipt_changed.returncode == 2 and "content hash mismatch" in receipt_changed.stderr

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a sqlite database")
    corrupt_receipt = _receipt_for(corrupt, tmp_path / "corrupt-receipt")
    corrupt_result = _run(corrupt, corrupt_receipt, tmp_path / "negative-corrupt")
    assert corrupt_result.returncode == 2
    assert "read-only SQLite inspection failed" in corrupt_result.stderr


def test_runtime_certifier_rejects_symlinked_evidence_directory_without_writing_receipt(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.sqlite3"
    _make_legacy_database(database)
    receipt = _receipt_for(database, tmp_path)
    actual_output = tmp_path / "actual-evidence"
    actual_output.mkdir()
    symlinked_output = tmp_path / "symlinked-evidence"
    symlinked_output.symlink_to(actual_output, target_is_directory=True)

    rejected = _run(database, receipt, symlinked_output)

    assert rejected.returncode == 2
    assert "output path must not resolve through a symlink" in rejected.stderr
    assert list(actual_output.iterdir()) == []


def test_checked_in_jaa01_evidence_is_content_addressed_complete_and_path_free() -> None:
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
    _assert_exact_live_source_bindings(document)
    assert str(runtime) not in payload.decode("utf-8")
    assert not any(value.startswith("/") for value in _strings(document))


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda sources: sources.pop("raw-jobs"), id="missing-live-source"),
        pytest.param(
            lambda sources: sources.__setitem__("unexpected", deepcopy(sources["raw-jobs"])),
            id="extra-live-source",
        ),
        pytest.param(
            lambda sources: sources.__setitem__("raw_jobs", sources.pop("raw-jobs")),
            id="renamed-live-source",
        ),
        pytest.param(
            lambda sources: sources["raw-jobs"].__setitem__("sha256_after", "0" * 64),
            id="altered-live-source-binding",
        ),
    ],
)
def test_checked_in_jaa01_receipt_rejects_non_exact_live_source_bindings(mutate: object) -> None:
    document = json.loads(_jaa01_receipt().read_text(encoding="utf-8"))
    # First prove the unmodified receipt is valid.  Otherwise a stale receipt
    # could make every negative control pass for the wrong reason.
    _assert_exact_live_source_bindings(document)
    altered = deepcopy(document)
    live_sources = altered["live_sources"]
    assert isinstance(live_sources, dict)
    assert callable(mutate)
    mutate(live_sources)
    with pytest.raises(AssertionError):
        _assert_exact_live_source_bindings(altered)


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _strings(child)]
    return []
