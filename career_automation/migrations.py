"""Small checksum-verified SQLite migration registry.

This keeps schema evolution explicit and replayable without adopting a remote
database platform.  Each migration is a tuple of single SQLite statements so
the whole version and its ledger entry share one transaction.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.version < 1 or not self.name.strip() or not self.statements:
            raise ValueError("migration requires a positive version, name and statements")
        if any(not statement.strip() for statement in self.statements):
            raise ValueError("migration statements cannot be empty")

    @property
    def checksum(self) -> str:
        body = json.dumps(
            {"version": self.version, "name": self.name, "statements": self.statements},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


class MigrationRunner:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS career_schema_migrations(
                     version INTEGER PRIMARY KEY,
                     name TEXT NOT NULL,
                     checksum TEXT NOT NULL,
                     applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                   )"""
            )
            conn.commit()
        finally:
            conn.close()

    def apply(self, migrations: tuple[Migration, ...]) -> tuple[int, ...]:
        versions = [migration.version for migration in migrations]
        if versions != sorted(versions) or len(versions) != len(set(versions)):
            raise ValueError("migrations must be uniquely versioned in ascending order")
        applied_now: list[int] = []
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            for migration in migrations:
                existing = conn.execute(
                    "SELECT name,checksum FROM career_schema_migrations WHERE version=?",
                    (migration.version,),
                ).fetchone()
                if existing is not None:
                    if existing["name"] != migration.name or existing["checksum"] != migration.checksum:
                        raise RuntimeError(
                            f"applied migration {migration.version} was modified after deployment"
                        )
                    continue
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for statement in migration.statements:
                        conn.execute(statement)
                    conn.execute(
                        """INSERT INTO career_schema_migrations(version,name,checksum)
                           VALUES(?,?,?)""",
                        (migration.version, migration.name, migration.checksum),
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                applied_now.append(migration.version)
        finally:
            conn.close()
        return tuple(applied_now)
