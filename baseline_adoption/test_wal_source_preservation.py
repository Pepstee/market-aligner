"""Adversarial preservation tests for lawful read-only WAL adoption.

The source writer deliberately stays open: this keeps a real WAL and SHM in
place while the adoption reader obtains its snapshot.  SHM *content* is not
asserted because SQLite is entitled to update reader-lock/read-mark metadata,
but its identity and size must survive intact.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from baseline_adoption import core


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_live_wal(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = sqlite3.connect(path, isolation_level=None, timeout=10)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE ledger (id INTEGER PRIMARY KEY, token TEXT NOT NULL)")
    writer.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY, ledger_id INTEGER NOT NULL)")
    writer.execute("BEGIN IMMEDIATE")
    for number in range(5):
        row = writer.execute("INSERT INTO ledger(token) VALUES (?)", (f"seed-{number}",))
        writer.execute("INSERT INTO audit(ledger_id) VALUES (?)", (row.lastrowid,))
    writer.execute("COMMIT")
    assert Path(str(path) + "-wal").exists()
    assert Path(str(path) + "-shm").exists()
    return writer


def _source_state(path: Path, writer: sqlite3.Connection) -> dict[str, object]:
    """Capture every source property adoption is forbidden to change."""
    wal, shm = Path(str(path) + "-wal"), Path(str(path) + "-shm")
    shm_stat = shm.stat()
    schema = writer.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    rows = {
        table: writer.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
        for table in ("ledger", "audit")
    }
    return {
        "main_bytes": path.read_bytes(),
        "wal_bytes": wal.read_bytes(),
        "schema": schema,
        "rows": rows,
        # SHM bytes and mtime are intentionally excluded: reader coordination may change them.
        "shm_device_inode": (shm_stat.st_dev, shm_stat.st_ino),
        "shm_bytes": shm_stat.st_size,
    }


def _assert_source_preserved(path: Path, writer: sqlite3.Connection, before: dict[str, object]) -> None:
    wal, shm = Path(str(path) + "-wal"), Path(str(path) + "-shm")
    assert path.read_bytes() == before["main_bytes"]
    assert wal.read_bytes() == before["wal_bytes"]
    assert shm.exists(), "the source SHM must remain present"
    assert (shm.stat().st_dev, shm.stat().st_ino) == before["shm_device_inode"], (
        "the source SHM must not be deleted or replaced"
    )
    assert shm.stat().st_size == before["shm_bytes"], "the source SHM must not be truncated"
    assert writer.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall() == before["schema"]
    assert {
        table: writer.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
        for table in ("ledger", "audit")
    } == before["rows"]


def _spec(name: str, source_root: Path, path: Path) -> core.BaselineSpec:
    # The frozen historical contract is observed before opening the preservation window.
    with closing(core._readonly_connection(path)) as reader:
        schema = core._schema_rows(reader)
        tables = [row[1] for row in schema if row[0] == "table"]
        counts = {table: reader.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] for table in tables}
    return core.BaselineSpec(
        name=name,
        source_relative=str(path.relative_to(source_root)),
        destination_relative=f"databases/{name}.sqlite3",
        size=path.stat().st_size,
        sha256=_digest(path),
        schema_sha256=hashlib.sha256(core._canonical_bytes(schema)).hexdigest(),
        schema_objects=len(schema),
        table_counts=counts,
    )


def test_online_adoption_preserves_quiescent_wal_source_and_repeated_reconcile_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    paths = [source / "inputs" / f"{name}.sqlite3" for name in ("jobs", "pipeline")]
    writers = [_make_live_wal(path) for path in paths]
    try:
        specs = tuple(_spec(name, source, path) for name, path in zip(("jobs", "pipeline"), paths))
        before = {path: _source_state(path, writer) for path, writer in zip(paths, writers)}
        monkeypatch.setattr(core, "BASELINES", specs)
        monkeypatch.setattr(core, "_runtime_versions", lambda: {"python": "test"})
        monkeypatch.setattr(core, "_repository_revision", lambda _: "a" * 40)

        data = tmp_path / "runtime-data"
        receipt = core.adopt_online(source, data, repository=tmp_path / "repository")

        for path, writer in zip(paths, writers):
            _assert_source_preserved(path, writer, before[path])
        for _ in range(2):
            assert core.reconcile(receipt, data)["status"] == "ok"
            assert core.rollback_manifest(receipt, data)["format"] == "jaa-00-rollback-manifest/v1"
            assert not list((data / "databases").glob("*.sqlite3-wal"))
            assert not list((data / "databases").glob("*.sqlite3-shm"))
    finally:
        for writer in writers:
            writer.close()


def test_online_backup_failure_preserves_wal_source_and_removes_only_temporary_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source" / "inputs" / "jobs.sqlite3"
    writer = _make_live_wal(source)
    try:
        spec = _spec("jobs", source.parents[1], source)
        before = _source_state(source, writer)
        destination = tmp_path / "runtime-data" / spec.destination_relative
        monkeypatch.setattr(core, "_inspect_database", lambda _: (_ for _ in ()).throw(
            core.AdoptionError("injected inspection failure")
        ))

        with pytest.raises(core.AdoptionError, match="injected inspection failure"):
            core._atomic_online_backup(source, destination, spec)

        _assert_source_preserved(source, writer, before)
        assert not destination.exists()
        assert not list(destination.parent.glob(".snapshotting-*"))
        assert not list(destination.parent.glob(".snapshotting-*-wal"))
        assert not list(destination.parent.glob(".snapshotting-*-shm"))
    finally:
        writer.close()


def test_adoption_read_connection_rejects_sql_writes_journal_changes_and_checkpoints(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    writer = _make_live_wal(source)
    try:
        before = _source_state(source, writer)
        with closing(core._readonly_connection(source)) as adoption_connection:
            assert adoption_connection.execute("PRAGMA query_only").fetchone() == (1,)
            for statement in (
                "INSERT INTO ledger(token) VALUES ('forbidden')",
                "PRAGMA journal_mode=DELETE",
                "PRAGMA wal_checkpoint(TRUNCATE)",
            ):
                with pytest.raises(sqlite3.OperationalError):
                    adoption_connection.execute(statement)
        _assert_source_preserved(source, writer, before)
    finally:
        writer.close()
