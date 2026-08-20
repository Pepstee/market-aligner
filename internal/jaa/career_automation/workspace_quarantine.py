"""Durable, inventory-bound quarantine for failed external workspaces."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any
from urllib.parse import quote


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode()


def workspace_inventory(root: str | Path) -> dict[str, Any]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("quarantine root must be a directory")
    records: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda row: row.relative_to(root).as_posix()):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("quarantine contains an unsupported filesystem entry")
        metadata = path.stat()
        body = path.read_bytes() if path.is_file() else None
        records.append({
            "path": path.relative_to(root).as_posix(),
            "kind": "file" if body is not None else "directory",
            "bytes": len(body) if body is not None else metadata.st_size,
            "mode": stat.S_IMODE(metadata.st_mode),
            "mtime_ns": metadata.st_mtime_ns,
            "sha256": hashlib.sha256(body).hexdigest() if body is not None else None,
        })
    return {
        "schema_version": "jaa.workspace-quarantine-inventory.v1",
        "records": records,
        "records_sha256": hashlib.sha256(_canonical(records)).hexdigest(),
    }


def verify_workspace_inventory(root: str | Path, expected: dict[str, Any]) -> None:
    current = workspace_inventory(root)
    if current != expected:
        raise ValueError("quarantined workspace inventory changed")


def _fsync(path: Path) -> None:
    flags = os.O_RDONLY | (os.O_DIRECTORY if path.is_dir() else 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def quarantine_workspace(root: str | Path) -> dict[str, Any]:
    """Remove every write bit depth-first and return the durable inventory."""
    root = Path(root).resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("quarantine root must be a real directory")
    entries = sorted(
        root.rglob("*"),
        key=lambda row: len(row.relative_to(root).parts),
        reverse=True,
    )
    for path in entries:
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("quarantine contains an unsupported filesystem entry")
        os.chmod(path, stat.S_IMODE(path.stat().st_mode) & ~0o222)
        _fsync(path)
    os.chmod(root, stat.S_IMODE(root.stat().st_mode) & ~0o222)
    _fsync(root)
    _fsync(root.parent)
    inventory = workspace_inventory(root)
    if any(int(row["mode"]) & 0o222 for row in inventory["records"]):
        raise RuntimeError("quarantine retained a writable descendant")
    return inventory


def immutable_sqlite_connection(path: str | Path) -> sqlite3.Connection:
    path = Path(path).resolve()
    if not path.is_file() or path.is_symlink():
        raise ValueError("immutable SQLite inspection requires a regular file")
    uri = f"file:{quote(str(path))}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.execute("PRAGMA query_only=ON")
    return connection
