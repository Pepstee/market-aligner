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

from career_automation.database import CareerDatabase
from career_automation.lifecycle import (
    InvalidTransition,
    LedgerDivergence,
    LifecycleReducer,
    PolicyIdentity,
    canonical_hash,
)
from career_automation.models import PipelineState, ScoredJob
from career_automation.migrations import JAA_01_MIGRATIONS


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="jaa-01c-") as temporary:
        database = Path(temporary) / "current.sqlite3"
        store = CareerDatabase(database)
        payload = {"job_key": "current:1"}
        store.upsert_scored_job(ScoredJob(
            key="current:1", board="acceptance", job_id="1",
            url="https://example.invalid/jobs/1", title="Engineer", company="Example",
            fit=0.8, opportunity=0.75, final_score=75.0,
            extraction_confidence=0.9, payload=payload,
            payload_hash=canonical_hash(payload),
        ))
        conn = sqlite3.connect(database)
        try:
            require(conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 1,
                    "current score writer did not persist the job")
            require(conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == 1,
                    "current score writer did not persist the import event")
            jaa01_ledger = conn.execute(
                "SELECT version,name,checksum FROM career_schema_migrations "
                "WHERE version IN ({}) ORDER BY version".format(
                    ",".join("?" for _ in JAA_01_MIGRATIONS)
                ),
                tuple(migration.version for migration in JAA_01_MIGRATIONS),
            ).fetchall()
            require(
                jaa01_ledger == [
                    (migration.version, migration.name, migration.checksum)
                    for migration in JAA_01_MIGRATIONS
                ],
                "canonical JAA-01 migration identity was not recorded",
            )
        finally:
            conn.close()

        reducer = LifecycleReducer(database)
        policy = PolicyIdentity("acceptance", "1", canonical_hash({"policy": "acceptance"}))
        transition = dict(
            job_key="current:1", to_state=PipelineState.EMPLOYER_RESEARCH_QUEUED,
            policy=policy, inputs={"job_key": "current:1"}, outputs={"accepted": True},
            idempotency_key="acceptance-transition-1",
        )
        first = reducer.commit(**transition)
        second = reducer.commit(**transition)
        require(first.receipt_id == second.receipt_id, "transition was not idempotent")
        try:
            reducer.commit(**{**transition, "to_state": PipelineState.RELEASED,
                              "idempotency_key": "acceptance-illegal"})
        except InvalidTransition:
            pass
        else:
            raise AssertionError("out-of-order transition was accepted")
        require(
            reducer.replay() == {
                "current:1": PipelineState.EMPLOYER_RESEARCH_QUEUED,
            },
            "replay was incorrect",
        )

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
                         (PipelineState.EMPLOYER_RESEARCHED.value, "current:1"))
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
