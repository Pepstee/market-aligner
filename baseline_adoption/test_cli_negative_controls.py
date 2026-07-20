"""Black-box negative controls for JAA-00 baseline adoption.

The shipped contract points at deliberately absent production snapshots.  Each test
therefore supplies a small, independently hashed contract to a fresh CLI process;
the process still executes the public command and the real SQLite/filesystem path.
No verifier, copier, receipt, or dependency function is mocked.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _schema(path: Path) -> list[list[str | None]]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        return [list(row) for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        )]
    finally:
        connection.close()


def _contract_entry(name: str, source: Path, *, schema: list[list[str | None]] | None = None,
                    counts: dict[str, int] | None = None) -> dict[str, object]:
    actual_schema = _schema(source)
    connection = sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True)
    try:
        actual_counts = {
            row[1]: connection.execute(f'SELECT COUNT(*) FROM "{row[1]}"').fetchone()[0]
            for row in actual_schema if row[0] == "table"
        }
    finally:
        connection.close()
    return {
        "name": name,
        "source_relative": str(source.relative_to(source.parents[1])),
        "destination_relative": f"databases/{name}.sqlite3",
        "size": source.stat().st_size,
        "sha256": _sha256(source),
        "schema_sha256": hashlib.sha256(
            json.dumps(schema or actual_schema, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")).encode()
        ).hexdigest(),
        "schema_objects": len(schema or actual_schema),
        "table_counts": counts or actual_counts,
    }


def _write_snapshot(path: Path, *, table: str = "records", rows: int = 1) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute(f'CREATE TABLE "{table}" (id INTEGER PRIMARY KEY, value TEXT NOT NULL)')
        connection.executemany(f'INSERT INTO "{table}" (value) VALUES (?)',
                               [(f"fixture-{item}",) for item in range(rows)])
        connection.commit()
    finally:
        connection.close()


@pytest.fixture
def snapshots(tmp_path: Path) -> tuple[Path, list[dict[str, object]]]:
    source = tmp_path / "frozen-source"
    first = source / "inputs" / "jobs.sqlite3"
    second = source / "inputs" / "pipeline.sqlite3"
    _write_snapshot(first, rows=2)
    _write_snapshot(second, rows=3)
    return source, [_contract_entry("jobs", first), _contract_entry("pipeline", second)]


def _run_cli(source: Path, data: Path, contract: list[dict[str, object]], *command: str,
             no_site: bool = False) -> subprocess.CompletedProcess[str]:
    """Run the public CLI in a clean process with a tiny frozen contract."""
    bootstrap = """
import json
import sys
from baseline_adoption import cli, core

contract = json.loads(sys.argv[1])
core.BASELINES = tuple(core.BaselineSpec(**item) for item in contract)
raise SystemExit(cli.main(sys.argv[2:]))
"""
    arguments = [sys.executable]
    if no_site:
        arguments.append("-S")
    arguments.extend(["-c", bootstrap, json.dumps(contract), *command])
    environment = os.environ.copy()
    if not no_site:
        dependency_root = source.parent / "runtime-dependencies"
        for distribution in ("PyYAML", "requests", "openpyxl", "pypdf"):
            metadata = dependency_root / f"{distribution}-0.0-test.dist-info"
            metadata.mkdir(parents=True, exist_ok=True)
            (metadata / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 0.0-test\n")
        environment["PYTHONPATH"] = str(dependency_root) + os.pathsep + environment.get("PYTHONPATH", "")
    return subprocess.run(arguments, cwd=ROOT, text=True, capture_output=True, check=False, env=environment)


def _adopt(source: Path, data: Path, contract: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
    return _run_cli(source, data, contract, "adopt", "--source-root", str(source),
                    "--data-root", str(data), "--repository", str(ROOT),
                    "--secret-reference", "DEPLOY_TOKEN_NAME")


def _receipt(data: Path) -> Path:
    receipts = list((data / "receipts").glob("migration-*.json"))
    assert len(receipts) == 1
    return receipts[0]


def _assert_no_accepted_receipt(data: Path) -> None:
    receipt_dir = data / "receipts"
    assert not receipt_dir.exists() or not list(receipt_dir.glob("migration-*.json"))


def test_cli_adoption_certifies_exact_snapshot_and_keeps_source_read_only(
    snapshots: tuple[Path, list[dict[str, object]]], tmp_path: Path,
) -> None:
    source, contract = snapshots
    source_state = {path: (path.stat().st_mtime_ns, _sha256(path)) for path in source.rglob("*.sqlite3")}
    data = tmp_path / "runtime-data"

    result = _adopt(source, data, contract)

    assert result.returncode == 0, result.stderr
    receipt = _receipt(data)
    document = json.loads(receipt.read_text())
    canonical = json.dumps(document["content"], ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode()
    assert document["content_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert receipt.name == f"migration-{document['content_sha256']}.json"
    assert document["content"]["format"] == "jaa-00-migration-receipt/v1"
    assert {path: (path.stat().st_mtime_ns, _sha256(path)) for path in source.rglob("*.sqlite3")} == source_state
    for spec in contract:
        copy = data / str(spec["destination_relative"])
        assert copy.read_bytes() == (source / str(spec["source_relative"])).read_bytes()
        assert copy.stat().st_ino != (source / str(spec["source_relative"])).stat().st_ino

    reconcile = _run_cli(source, data, contract, "reconcile", "--receipt", str(receipt),
                         "--data-root", str(data))
    assert reconcile.returncode == 0, reconcile.stderr
    assert json.loads(reconcile.stdout)["status"] == "ok"

    manifest = _run_cli(source, data, contract, "rollback-manifest", "--receipt", str(receipt),
                        "--data-root", str(data))
    assert manifest.returncode == 0, manifest.stderr
    rendered = manifest.stdout + receipt.read_text()
    assert all(term not in rendered for term in (
        "super-secret-token", "Artiom", "Hyun", "gutu.artiom", str(source), str(data), "/Users/",
    ))
    assert {action["expected_sha256"] for action in json.loads(manifest.stdout)["actions"]} == {
        str(item["sha256"]) for item in contract
    }


def test_one_byte_change_missing_table_and_missing_row_fail_closed(
    snapshots: tuple[Path, list[dict[str, object]]], tmp_path: Path,
) -> None:
    source, contract = snapshots
    target = source / "inputs/jobs.sqlite3"
    target.write_bytes(target.read_bytes()[:-1] + bytes([target.read_bytes()[-1] ^ 1]))
    altered = _adopt(source, tmp_path / "one-byte", contract)
    assert altered.returncode == 2 and "SHA-256 mismatch" in altered.stderr
    _assert_no_accepted_receipt(tmp_path / "one-byte")

    _write_snapshot(target, table="wrong_table", rows=2)
    table_contract = [
        _contract_entry("jobs", target, schema=_schema(source / "inputs/pipeline.sqlite3"), counts={"records": 2}),
        contract[1],
    ]
    missing_table = _adopt(source, tmp_path / "missing-table", table_contract)
    assert missing_table.returncode == 2 and "schema mismatch" in missing_table.stderr
    _assert_no_accepted_receipt(tmp_path / "missing-table")

    target.unlink()
    _write_snapshot(target, rows=1)
    row_contract = [_contract_entry("jobs", target, counts={"records": 2}), contract[1]]
    missing_row = _adopt(source, tmp_path / "missing-row", row_contract)
    assert missing_row.returncode == 2 and "table count mismatch" in missing_row.stderr
    _assert_no_accepted_receipt(tmp_path / "missing-row")


def test_corruption_missing_dependency_and_receipt_tampering_fail_closed(
    snapshots: tuple[Path, list[dict[str, object]]], tmp_path: Path,
) -> None:
    source, contract = snapshots
    missing_dependency = _run_cli(source, tmp_path / "missing-dependency", contract, "adopt",
                                  "--source-root", str(source), "--data-root", str(tmp_path / "missing-dependency"),
                                  "--repository", str(ROOT), no_site=True)
    assert missing_dependency.returncode == 2 and "missing runtime dependencies" in missing_dependency.stderr
    _assert_no_accepted_receipt(tmp_path / "missing-dependency")

    data = tmp_path / "tampered"
    assert _adopt(source, data, contract).returncode == 0
    receipt = _receipt(data)
    receipt.write_text(receipt.read_text().replace("canonical-repository", "forged-repository"))
    tampered = _run_cli(source, data, contract, "reconcile", "--receipt", str(receipt), "--data-root", str(data))
    assert tampered.returncode == 2 and "receipt content hash" in tampered.stderr

    corrupt = source / "inputs/jobs.sqlite3"
    expected_schema = _schema(corrupt)
    expected_counts = {"records": 2}
    corrupt.write_bytes(b"not a sqlite database".ljust(corrupt.stat().st_size, b"!"))
    corrupt_contract = [{
        "name": "jobs", "source_relative": "inputs/jobs.sqlite3",
        "destination_relative": "databases/jobs.sqlite3", "size": corrupt.stat().st_size,
        "sha256": _sha256(corrupt),
        "schema_sha256": hashlib.sha256(json.dumps(
            expected_schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
        "schema_objects": len(expected_schema), "table_counts": expected_counts,
    }, contract[1]]
    corrupt_result = _adopt(source, tmp_path / "corrupt", corrupt_contract)
    assert corrupt_result.returncode == 2 and "SQLite verification failed" in corrupt_result.stderr
    _assert_no_accepted_receipt(tmp_path / "corrupt")


def test_destination_collision_and_idempotent_overwrite_are_rejected_atomically(
    snapshots: tuple[Path, list[dict[str, object]]], tmp_path: Path,
) -> None:
    source, contract = snapshots
    data = tmp_path / "collision"
    collision = data / "databases/pipeline.sqlite3"
    collision.parent.mkdir(parents=True)
    collision.write_bytes(b"do-not-replace")

    failed = _adopt(source, data, contract)
    assert failed.returncode == 2 and "refusing to overwrite destination" in failed.stderr
    assert collision.read_bytes() == b"do-not-replace"
    assert not (data / "databases/jobs.sqlite3").exists()
    _assert_no_accepted_receipt(data)
    assert not list(data.rglob(".adopting-*"))

    fresh = tmp_path / "fresh"
    assert _adopt(source, fresh, contract).returncode == 0
    first_receipt = _receipt(fresh)
    rerun = _adopt(source, fresh, contract)
    assert rerun.returncode == 2 and "refusing to overwrite destination" in rerun.stderr
    assert _receipt(fresh) == first_receipt


def test_cli_online_adoption_uses_backup_and_records_new_snapshot_separately(
    snapshots: tuple[Path, list[dict[str, object]]], tmp_path: Path,
) -> None:
    source, contract = snapshots
    writers = []
    try:
        for item in contract:
            path = source / str(item["source_relative"])
            writer = sqlite3.connect(path)
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("INSERT INTO records(value) VALUES ('after-historical-observation')")
            writer.commit()
            writers.append(writer)

        data = tmp_path / "online"
        result = _run_cli(
            source, data, contract, "adopt-online", "--source-root", str(source),
            "--data-root", str(data), "--repository", str(ROOT)
        )
        assert result.returncode == 0, result.stderr
        receipt = _receipt(data)
        document = json.loads(receipt.read_text())["content"]
        assert document["format"] == "jaa-00-online-snapshot-receipt/v2"
        for item in contract:
            record = document["databases"][str(item["name"])]
            assert record["historical_observation"]["observed_table_counts"] == item["table_counts"]
            assert record["frozen_snapshot"]["table_counts"]["records"] == int(
                item["table_counts"]["records"]
            ) + 1
            assert set(record["capture"]["source_identities_start"]) == {"main", "wal", "shm"}
            assert set(record["capture"]["source_identities_end"]) == {"main", "wal", "shm"}
        assert str(source) not in receipt.read_text()
        checked = _run_cli(source, data, contract, "reconcile", "--receipt", str(receipt),
                           "--data-root", str(data))
        assert checked.returncode == 0, checked.stderr
    finally:
        for writer in writers:
            writer.close()
