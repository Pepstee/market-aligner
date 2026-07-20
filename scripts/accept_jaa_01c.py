#!/usr/bin/env python3
"""Deterministic executable acceptance for the JAA-01 lifecycle runtime."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

# The acceptance contract runs this file from the repository root.  Prefer
# that checkout over any separately installed distribution of the package.
sys.path.insert(0, str(Path.cwd()))

from career_automation.database import CareerDatabase, SCHEMA
from career_automation.lifecycle import (
    InvalidTransition,
    LedgerDivergence,
    LifecycleReducer,
    PolicyIdentity,
    canonical_hash,
)
from career_automation.models import PipelineState


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="jaa-01c-") as temporary:
        database = Path(temporary) / "legacy.sqlite3"
        conn = sqlite3.connect(database)
        try:
            conn.executescript(SCHEMA)
            conn.execute(
                """INSERT INTO pipeline_jobs(
                     job_key,board,job_id,url,title,company,opportunity,payload_json,payload_hash,state
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                ("legacy:1", "legacy", "1", "https://example.invalid/jobs/1", "Engineer",
                 "Example", 0.75, "{}", canonical_hash({}), PipelineState.DISCOVERED.value),
            )
            conn.execute(
                """INSERT INTO pipeline_events(
                     job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?,?)""",
                ("legacy:1", "score_snapshot_imported", None, PipelineState.DISCOVERED.value,
                 "deterministic", "{}", "legacy-root"),
            )
            conn.commit()
        finally:
            conn.close()

        CareerDatabase(database)
        conn = sqlite3.connect(database)
        try:
            require(conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 1,
                    "migration did not preserve the legacy job")
            require(conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == 1,
                    "migration did not preserve the legacy event")
            require(conn.execute("SELECT COUNT(*) FROM career_schema_migrations").fetchone()[0] == 1,
                    "canonical migration was not recorded")
        finally:
            conn.close()

        reducer = LifecycleReducer(database)
        policy = PolicyIdentity("acceptance", "1", canonical_hash({"policy": "acceptance"}))
        transition = dict(
            job_key="legacy:1", to_state=PipelineState.FETCHED, policy=policy,
            inputs={"job_key": "legacy:1"}, outputs={"accepted": True},
            idempotency_key="acceptance-transition-1",
        )
        first = reducer.commit(**transition)
        second = reducer.commit(**transition)
        require(first.receipt_id == second.receipt_id, "transition was not idempotent")
        try:
            reducer.commit(**{**transition, "to_state": PipelineState.ELIGIBLE,
                              "idempotency_key": "acceptance-illegal"})
        except InvalidTransition:
            pass
        else:
            raise AssertionError("out-of-order transition was accepted")
        require(reducer.replay() == {"legacy:1": PipelineState.FETCHED}, "replay was incorrect")

        conn = sqlite3.connect(database)
        try:
            checksum = conn.execute(
                "SELECT checksum FROM career_schema_migrations WHERE version=1"
            ).fetchone()[0]
            conn.execute("UPDATE career_schema_migrations SET checksum=? WHERE version=1", ("0" * 64,))
            conn.commit()
        finally:
            conn.close()
        try:
            CareerDatabase(database)
        except RuntimeError:
            pass
        else:
            raise AssertionError("migration checksum divergence was not detected")

        conn = sqlite3.connect(database)
        try:
            conn.execute("UPDATE career_schema_migrations SET checksum=? WHERE version=1", (checksum,))
            conn.execute("UPDATE pipeline_jobs SET state=? WHERE job_key=?",
                         (PipelineState.NORMALISED.value, "legacy:1"))
            conn.commit()
        finally:
            conn.close()
        try:
            reducer.verify()
        except LedgerDivergence:
            pass
        else:
            raise AssertionError("materialised-state divergence was not detected")

    print("JAA-01C acceptance passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
