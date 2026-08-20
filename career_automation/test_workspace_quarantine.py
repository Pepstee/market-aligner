from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from career_automation.workspace_quarantine import (
    immutable_sqlite_connection,
    quarantine_workspace,
    verify_workspace_inventory,
)


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "failed-workspace"
    nested = root / "research"
    nested.mkdir(parents=True)
    database = nested / "queue.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
        connection.execute("INSERT INTO evidence VALUES('preserved')")
    (nested / "raw.bin").write_bytes(b"exact source bytes")
    return root, database


def test_quarantine_is_recursive_durable_and_immutable_sqlite_is_readable(
    tmp_path: Path,
) -> None:
    root, database = _workspace(tmp_path)
    inventory = quarantine_workspace(root)

    assert not stat.S_IMODE(root.stat().st_mode) & 0o222
    assert all(
        not stat.S_IMODE(path.stat().st_mode) & 0o222
        for path in root.rglob("*")
    )
    with immutable_sqlite_connection(database) as connection:
        assert connection.execute("SELECT value FROM evidence").fetchone()[0] == "preserved"
    verify_workspace_inventory(root, inventory)


def test_ordinary_read_only_sqlite_cannot_create_sidecars(
    tmp_path: Path,
) -> None:
    root, database = _workspace(tmp_path)
    quarantine_workspace(root)

    try:
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
            connection.execute("SELECT count(*) FROM evidence").fetchone()
    except sqlite3.OperationalError:
        pass

    assert not database.with_name(database.name + "-wal").exists()
    assert not database.with_name(database.name + "-shm").exists()


def test_write_create_delete_fail_and_chmod_delta_is_detected(
    tmp_path: Path,
) -> None:
    root, database = _workspace(tmp_path)
    raw = root / "research" / "raw.bin"
    inventory = quarantine_workspace(root)

    with pytest.raises(PermissionError):
        raw.write_bytes(b"tampered")
    with pytest.raises(PermissionError):
        (root / "research" / "new.bin").write_bytes(b"created")
    with pytest.raises(PermissionError):
        raw.unlink()

    # A file owner can always chmod on POSIX without an elevated immutable
    # filesystem flag; the inventory makes that metadata tamper fail closed.
    os.chmod(raw, stat.S_IMODE(raw.stat().st_mode) | stat.S_IWUSR)
    with pytest.raises(ValueError, match="inventory changed"):
        verify_workspace_inventory(root, inventory)
