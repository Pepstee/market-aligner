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
        conn.execute("PRAGMA foreign_keys=ON")
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


JAA_01_MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        1,
        "jaa_01_lifecycle_transition_receipts",
        (
            """CREATE TABLE IF NOT EXISTS pipeline_jobs(
                 job_key TEXT PRIMARY KEY,
                 board TEXT NOT NULL,
                 job_id TEXT NOT NULL,
                 url TEXT NOT NULL,
                 title TEXT NOT NULL,
                 company TEXT NOT NULL,
                 fit REAL,
                 opportunity REAL NOT NULL CHECK(opportunity >= 0 AND opportunity <= 1),
                 final_score REAL,
                 extraction_confidence REAL,
                 payload_json TEXT NOT NULL,
                 payload_hash TEXT NOT NULL,
                 state TEXT NOT NULL,
                 opportunity_decision TEXT CHECK(opportunity_decision IN ('pass','reject')),
                 opportunity_reason TEXT,
                 policy_hash TEXT,
                 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
               )""",
            """CREATE INDEX IF NOT EXISTS pipeline_jobs_state
                 ON pipeline_jobs(state)""",
            """CREATE INDEX IF NOT EXISTS pipeline_jobs_opportunity
                 ON pipeline_jobs(opportunity DESC)""",
            """CREATE TABLE IF NOT EXISTS pipeline_events(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 job_key TEXT NOT NULL REFERENCES pipeline_jobs(job_key) ON DELETE CASCADE,
                 event_type TEXT NOT NULL,
                 from_state TEXT,
                 to_state TEXT,
                 actor_kind TEXT NOT NULL
                   CHECK(actor_kind IN ('deterministic','probabilistic','external')),
                 payload_json TEXT NOT NULL DEFAULT '{}',
                 idempotency_key TEXT NOT NULL UNIQUE,
                 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
               )""",
            """CREATE INDEX IF NOT EXISTS pipeline_events_job
                 ON pipeline_events(job_key,id)""",
            """CREATE TABLE lifecycle_transition_receipts(
                 receipt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_id INTEGER NOT NULL UNIQUE
                   REFERENCES pipeline_events(id) ON DELETE RESTRICT,
                 job_key TEXT NOT NULL
                   REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
                 from_state TEXT NOT NULL CHECK(length(trim(from_state)) > 0),
                 to_state TEXT NOT NULL CHECK(length(trim(to_state)) > 0),
                 policy_id TEXT NOT NULL CHECK(length(trim(policy_id)) > 0),
                 policy_version TEXT NOT NULL CHECK(length(trim(policy_version)) > 0),
                 policy_hash TEXT NOT NULL
                   CHECK(length(policy_hash) = 64
                     AND policy_hash NOT GLOB '*[^0-9a-f]*'),
                 model_provider TEXT,
                 model_id TEXT,
                 model_version TEXT,
                 input_hash TEXT NOT NULL
                   CHECK(length(input_hash) = 64
                     AND input_hash NOT GLOB '*[^0-9a-f]*'),
                 output_hash TEXT NOT NULL
                   CHECK(length(output_hash) = 64
                     AND output_hash NOT GLOB '*[^0-9a-f]*'),
                 idempotency_key TEXT NOT NULL UNIQUE
                   CHECK(length(trim(idempotency_key)) > 0),
                 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 CHECK(from_state <> to_state),
                 CHECK(
                   (model_provider IS NULL AND model_id IS NULL AND model_version IS NULL)
                   OR
                   (model_provider IS NOT NULL
                     AND model_id IS NOT NULL
                     AND model_version IS NOT NULL
                     AND length(trim(model_provider)) > 0
                     AND length(trim(model_id)) > 0
                     AND length(trim(model_version)) > 0)
                 ),
                 UNIQUE(
                   job_key, from_state, to_state, policy_id, policy_version,
                   policy_hash, input_hash
                 )
               )""",
            """CREATE INDEX lifecycle_transition_receipts_job_event
                 ON lifecycle_transition_receipts(job_key,event_id)""",
            """CREATE INDEX lifecycle_transition_receipts_policy
                 ON lifecycle_transition_receipts(policy_id,policy_version,policy_hash)""",
            """CREATE TRIGGER lifecycle_transition_receipt_matches_event
                 BEFORE INSERT ON lifecycle_transition_receipts
                 BEGIN
                   SELECT CASE WHEN NOT EXISTS(
                     SELECT 1 FROM pipeline_events AS event
                     WHERE event.id = NEW.event_id
                       AND event.job_key = NEW.job_key
                       AND event.from_state IS NEW.from_state
                       AND event.to_state IS NEW.to_state
                       AND event.idempotency_key = NEW.idempotency_key
                   ) THEN RAISE(ABORT, 'transition receipt does not match event') END;
                 END""",
            """CREATE TRIGGER lifecycle_transition_receipt_immutable_update
                 BEFORE UPDATE ON lifecycle_transition_receipts
                 BEGIN
                   SELECT RAISE(ABORT, 'transition receipts are immutable');
                 END""",
            """CREATE TRIGGER lifecycle_transition_receipt_immutable_delete
                 BEFORE DELETE ON lifecycle_transition_receipts
                 BEGIN
                   SELECT RAISE(ABORT, 'transition receipts are immutable');
                 END""",
        ),
    ),
)


def apply_jaa_01_migrations(path: str | Path) -> tuple[int, ...]:
    """Apply the canonical JAA-01 schema to a configured SQLite database."""
    return MigrationRunner(path).apply(JAA_01_MIGRATIONS)
