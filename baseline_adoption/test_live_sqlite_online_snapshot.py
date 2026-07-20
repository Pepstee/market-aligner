"""Adversarial black-box coverage for live SQLite snapshot adoption.

These tests intentionally use the public CLI in fresh processes.  The only test
setup injection is a tiny, measured baseline contract; no adoption or SQLite
verification function is replaced.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _readonly(path: Path) -> sqlite3.Connection:
    # WAL-mode databases may create sidecars even for an ordinary ``mode=ro``
    # connection.  Immutable inspection proves the artifact without changing it.
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro&immutable=1", uri=True, timeout=10)


def _live_readonly(path: Path) -> sqlite3.Connection:
    """Read the WAL view while creating the historical fixture contract."""
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=10)


def _contract(name: str, path: Path) -> dict[str, object]:
    with _live_readonly(path) as connection:
        schema = [list(row) for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        )]
        counts = {
            row[1]: connection.execute(
                'SELECT COUNT(*) FROM "' + row[1].replace('"', '""') + '"'
            ).fetchone()[0]
            for row in schema if row[0] == "table"
        }
    return {
        "name": name,
        "source_relative": str(path.relative_to(path.parents[1])),
        "destination_relative": f"databases/{name}.sqlite3",
        "size": path.stat().st_size,
        "sha256": _hash(path),
        "schema_sha256": hashlib.sha256(json.dumps(
            schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
        "schema_objects": len(schema),
        "table_counts": counts,
    }


def _make_wal_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10, isolation_level=None)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE ledger (id INTEGER PRIMARY KEY, token TEXT NOT NULL)")
    connection.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY, ledger_id INTEGER NOT NULL)")
    connection.execute("BEGIN IMMEDIATE")
    for value in range(20):
        cursor = connection.execute("INSERT INTO ledger(token) VALUES (?)", (f"seed-{value}",))
        connection.execute("INSERT INTO audit(ledger_id) VALUES (?)", (cursor.lastrowid,))
    connection.execute("COMMIT")
    assert Path(str(path) + "-wal").exists()
    assert Path(str(path) + "-shm").exists()
    return connection


def _run_cli(source: Path, data: Path, contract: list[dict[str, object]], *args: str) -> subprocess.CompletedProcess[str]:
    bootstrap = """
import json
import sys
from baseline_adoption import cli, core
core.BASELINES = tuple(core.BaselineSpec(**item) for item in json.loads(sys.argv[1]))
raise SystemExit(cli.main(sys.argv[2:]))
"""
    dependencies = source.parent / "runtime-dependencies"
    for distribution in ("PyYAML", "requests", "openpyxl", "pypdf"):
        metadata = dependencies / f"{distribution}-0.0-test.dist-info"
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.1\\nName: {distribution}\\nVersion: 0.0-test\\n"
        )
    environment = os.environ | {"PYTHONPATH": str(dependencies) + os.pathsep + os.environ.get("PYTHONPATH", "")}
    return subprocess.run(
        [sys.executable, "-c", bootstrap, json.dumps(contract), *args], cwd=ROOT,
        text=True, capture_output=True, check=False, env=environment,
    )


def _online(source: Path, data: Path, contract: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
    return _run_cli(source, data, contract, "adopt-online", "--source-root", str(source),
                    "--data-root", str(data), "--repository", str(ROOT))


def _receipt(data: Path) -> Path:
    receipts = list((data / "receipts").glob("migration-*.json"))
    assert len(receipts) == 1
    return receipts[0]


def test_online_cli_freezes_consistent_wal_snapshot_records_drift_and_reconciles(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    writers = [_make_wal_database(source / "inputs" / f"{name}.sqlite3") for name in ("jobs", "pipeline")]
    contract = [_contract(name, source / "inputs" / f"{name}.sqlite3") for name in ("jobs", "pipeline")]
    stop = threading.Event()

    def commit_pairs(path: Path) -> None:
        connection = sqlite3.connect(path, timeout=10, isolation_level=None)
        try:
            sequence = 0
            while not stop.is_set():
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute("INSERT INTO ledger(token) VALUES (?)", (f"live-{sequence}",))
                connection.execute("INSERT INTO audit(ledger_id) VALUES (?)", (cursor.lastrowid,))
                connection.execute("COMMIT")
                sequence += 1
        finally:
            connection.close()

    threads = [threading.Thread(target=commit_pairs, args=(source / "inputs" / f"{name}.sqlite3",), daemon=True)
               for name in ("jobs", "pipeline")]
    for thread in threads:
        thread.start()
    try:
        time.sleep(0.03)  # Ensure at least one committed write races the subprocess snapshot.
        data = tmp_path / "runtime-data"
        result = _online(source, data, contract)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=5)
        for writer in writers:
            writer.close()

    assert result.returncode == 0, result.stderr
    receipt = _receipt(data)
    content = json.loads(receipt.read_text())["content"]
    assert content["format"] == "jaa-00-online-snapshot-receipt/v2"
    for name in ("jobs", "pipeline"):
        record = content["databases"][name]
        assert record["capture"]["method"] == "sqlite-online-backup"
        assert record["capture"]["drift_observed"] is True
        assert "wal" in record["capture"]["changed_components"]
        copy = data / "databases" / f"{name}.sqlite3"
        with _readonly(copy) as snapshot:
            assert snapshot.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
            ledger, audit = (snapshot.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                             for table in ("ledger", "audit"))
            assert ledger == audit == record["frozen_snapshot"]["table_counts"]["ledger"]
        assert not Path(str(copy) + "-wal").exists()
        assert not Path(str(copy) + "-shm").exists()

    checked = _run_cli(source, data, contract, "reconcile", "--receipt", str(receipt), "--data-root", str(data))
    assert checked.returncode == 0, checked.stderr
    assert json.loads(checked.stdout)["status"] == "ok"

    # A receipt is self-authenticating: a changed recorded observation cannot be replayed.
    receipt.write_text(receipt.read_text().replace("canonical-repository", "forged-repository"))
    tampered = _run_cli(source, data, contract, "reconcile", "--receipt", str(receipt), "--data-root", str(data))
    assert tampered.returncode == 2
    assert "receipt content hash" in tampered.stderr


def test_direct_copy_refuses_live_wal_shm_and_online_never_overwrites_destination(tmp_path: Path) -> None:
    source = tmp_path / "source"
    writers = [_make_wal_database(source / "inputs" / f"{name}.sqlite3") for name in ("jobs", "pipeline")]
    contract = [_contract(name, source / "inputs" / f"{name}.sqlite3") for name in ("jobs", "pipeline")]
    try:
        direct_data = tmp_path / "direct-data"
        direct = _run_cli(source, direct_data, contract, "adopt", "--source-root", str(source),
                          "--data-root", str(direct_data), "--repository", str(ROOT))
        assert direct.returncode == 2
        assert "database is live or dirty" in direct.stderr
        assert not (direct_data / "databases").exists()
        assert not list(direct_data.glob("receipts/migration-*.json"))

        online_data = tmp_path / "online-data"
        sentinel = online_data / "databases" / "jobs.sqlite3"
        sentinel.parent.mkdir(parents=True)
        sentinel.write_bytes(b"must-not-be-replaced")
        collision = _online(source, online_data, contract)
        assert collision.returncode == 2
        assert "refusing to overwrite destination" in collision.stderr
        assert sentinel.read_bytes() == b"must-not-be-replaced"
        assert not list(online_data.glob("receipts/migration-*.json"))
    finally:
        for writer in writers:
            writer.close()
