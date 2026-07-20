"""SQLite event ledger and materialised career-pipeline state."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .migrations import apply_jaa_02_migrations
from .lifecycle import (
    LifecycleReducer,
    ModelIdentity,
    PolicyIdentity,
    canonical_hash,
)
from .models import ActorKind, PipelineState, ResearchTask, ScoredJob


RESEARCH_LEASE_POLICY = PolicyIdentity(
    "career.research-lease", "1",
    canonical_hash({"rule": "lease queued work; advance only queued jobs"}),
)
RESEARCH_COMPLETION_POLICY = PolicyIdentity(
    "career.research-completion-validation", "1",
    canonical_hash({
        "rules": [
            "lease owner must match",
            "at least one public source is required",
            "every claim cites known source IDs",
        ]
    }),
)


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=30000;

CREATE TABLE IF NOT EXISTS pipeline_jobs (
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
);
CREATE INDEX IF NOT EXISTS pipeline_jobs_state ON pipeline_jobs(state);
CREATE INDEX IF NOT EXISTS pipeline_jobs_opportunity ON pipeline_jobs(opportunity DESC);

CREATE TABLE IF NOT EXISTS pipeline_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_key TEXT NOT NULL REFERENCES pipeline_jobs(job_key) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  from_state TEXT,
  to_state TEXT,
  actor_kind TEXT NOT NULL CHECK(actor_kind IN ('deterministic','probabilistic','external')),
  payload_json TEXT NOT NULL DEFAULT '{}',
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS pipeline_events_job ON pipeline_events(job_key,id);

CREATE TABLE IF NOT EXISTS employer_research_queue (
  job_key TEXT PRIMARY KEY REFERENCES pipeline_jobs(job_key) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','leased','completed','failed')),
  priority INTEGER NOT NULL,
  research_depth TEXT NOT NULL DEFAULT 'reconnaissance',
  attempts INTEGER NOT NULL DEFAULT 0,
  available_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  lease_owner TEXT,
  lease_until TEXT,
  last_error TEXT,
  queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS employer_research_ready
  ON employer_research_queue(status,available_at,priority DESC);

CREATE TABLE IF NOT EXISTS employer_dossiers (
  job_key TEXT PRIMARY KEY REFERENCES pipeline_jobs(job_key) ON DELETE CASCADE,
  dossier_json TEXT NOT NULL,
  dossier_hash TEXT NOT NULL,
  worker_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS research_requires_opportunity_pass
BEFORE INSERT ON employer_research_queue
WHEN COALESCE((SELECT opportunity_decision FROM pipeline_jobs WHERE job_key=NEW.job_key),'') != 'pass'
BEGIN
  SELECT RAISE(ABORT, 'employer research requires a passed opportunity gate');
END;

CREATE TRIGGER IF NOT EXISTS research_update_requires_opportunity_pass
BEFORE UPDATE ON employer_research_queue
WHEN COALESCE((SELECT opportunity_decision FROM pipeline_jobs WHERE job_key=NEW.job_key),'') != 'pass'
BEGIN
  SELECT RAISE(ABORT, 'employer research requires a passed opportunity gate');
END;
"""


class CareerDatabase:
    """Durable control plane kept separate from the live scraper database."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # The canonical lifecycle migration uses CREATE IF NOT EXISTS for the
        # deployed jobs/event tables, so existing ledgers are retained while
        # new databases receive the same schema and migration identity.
        apply_jaa_02_migrations(self.path)
        with self.connection() as conn:
            conn.executescript(SCHEMA)
        self.lifecycle = LifecycleReducer(self.path)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Return a connection that is always closed after the block."""
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def upsert_scored_job(self, job: ScoredJob) -> bool:
        """Store one score snapshot and emit one import event per content hash."""
        with self.transaction(immediate=True) as conn:
            existed = conn.execute(
                "SELECT 1 FROM pipeline_jobs WHERE job_key=?", (job.key,)
            ).fetchone() is not None
            conn.execute(
                """INSERT INTO pipeline_jobs(
                     job_key,board,job_id,url,title,company,fit,opportunity,final_score,
                     extraction_confidence,payload_json,payload_hash,state
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(job_key) DO UPDATE SET
                     board=excluded.board,job_id=excluded.job_id,url=excluded.url,
                     title=excluded.title,company=excluded.company,fit=excluded.fit,
                     opportunity=excluded.opportunity,final_score=excluded.final_score,
                     extraction_confidence=excluded.extraction_confidence,
                     payload_json=excluded.payload_json,payload_hash=excluded.payload_hash,
                     updated_at=CURRENT_TIMESTAMP""",
                (
                    job.key, job.board, job.job_id, job.url, job.title, job.company,
                    job.fit, job.opportunity, job.final_score, job.extraction_confidence,
                    json.dumps(job.payload, ensure_ascii=False, sort_keys=True),
                    job.payload_hash, PipelineState.SCORED.value,
                ),
            )
            conn.execute(
                """INSERT OR IGNORE INTO pipeline_events(
                     job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    job.key, "score_snapshot_imported", None, PipelineState.SCORED.value,
                    ActorKind.DETERMINISTIC.value,
                    json.dumps({"payload_hash": job.payload_hash}, sort_keys=True),
                    f"score-import:{job.key}:{job.payload_hash}",
                ),
            )
        return not existed

    def scored_jobs(self) -> list[sqlite3.Row]:
        with self.connection() as conn:
            return conn.execute(
                "SELECT * FROM pipeline_jobs ORDER BY opportunity DESC,job_key"
            ).fetchall()

    def apply_opportunity_result(
        self,
        *,
        job_key: str,
        passed: bool,
        reason: str,
        policy_hash: str,
        priority: int | None,
    ) -> None:
        """Atomically materialise the gate and its research-queue consequence."""
        decision = "pass" if passed else "reject"
        target = (
            PipelineState.EMPLOYER_RESEARCH_QUEUED.value
            if passed else PipelineState.OPPORTUNITY_REJECTED.value
        )
        if passed and priority is None:
            raise ValueError("passed opportunity requires research priority")
        policy = PolicyIdentity("career.opportunity-gate", "1", policy_hash)
        with self.transaction(immediate=True) as conn:
            current = conn.execute(
                "SELECT state,payload_hash FROM pipeline_jobs WHERE job_key=?", (job_key,)
            ).fetchone()
            if current is None:
                raise KeyError(job_key)
            event_key = f"opportunity-gate:{job_key}:{current['payload_hash']}:{policy_hash}"
            self.lifecycle.commit_in_transaction(
                conn,
                job_key=job_key,
                to_state=PipelineState(target),
                policy=policy,
                inputs={"payload_hash": current["payload_hash"]},
                outputs={
                    "decision": decision,
                    "reason": reason,
                    "priority": priority,
                },
                idempotency_key=event_key,
            )
            if current["state"] in {
                PipelineState.EMPLOYER_RESEARCHING.value,
                PipelineState.EMPLOYER_RESEARCHED.value,
            }:
                return
            conn.execute(
                """UPDATE pipeline_jobs SET opportunity_decision=?,
                     opportunity_reason=?,updated_at=CURRENT_TIMESTAMP
                   WHERE job_key=?""",
                (decision, reason, job_key),
            )
            if passed:
                conn.execute(
                    """INSERT INTO employer_research_queue(job_key,priority)
                       VALUES(?,?) ON CONFLICT(job_key) DO UPDATE SET
                       priority=excluded.priority,updated_at=CURRENT_TIMESTAMP""",
                    (job_key, priority),
                )
            else:
                conn.execute(
                    "DELETE FROM employer_research_queue WHERE job_key=? AND status='queued'",
                    (job_key,),
                )

    def enqueue_research(self, job_key: str, priority: int) -> None:
        """Public queue method; the database trigger enforces gate ordering."""
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO employer_research_queue(job_key,priority) VALUES(?,?)",
                (job_key, priority),
            )

    def list_research_queue(self, limit: int = 100) -> list[ResearchTask]:
        with self.connection() as conn:
            rows = conn.execute(
                """SELECT q.job_key,j.title,j.company,j.url,j.opportunity,q.priority,
                          q.research_depth,q.attempts
                   FROM employer_research_queue q
                   JOIN pipeline_jobs j ON j.job_key=q.job_key
                   WHERE q.status='queued' AND q.available_at<=CURRENT_TIMESTAMP
                   ORDER BY q.priority DESC,j.opportunity DESC,q.queued_at
                   LIMIT ?""",
                (limit,),
            ).fetchall()
        return [ResearchTask(**dict(row)) for row in rows]

    def claim_research(self, worker_id: str, lease_seconds: int = 900) -> ResearchTask | None:
        """Lease the highest-priority research job without double dispatch."""
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=max(1, lease_seconds))
        with self.transaction(immediate=True) as conn:
            row = conn.execute(
                """SELECT q.job_key,j.title,j.company,j.url,j.opportunity,q.priority,
                          q.research_depth,q.attempts,q.status,j.state
                   FROM employer_research_queue q
                   JOIN pipeline_jobs j ON j.job_key=q.job_key
                   WHERE (q.status='queued' AND q.available_at<=CURRENT_TIMESTAMP)
                      OR (q.status='leased' AND q.lease_until<CURRENT_TIMESTAMP)
                   ORDER BY q.priority DESC,j.opportunity DESC,q.queued_at LIMIT 1"""
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                """UPDATE employer_research_queue SET status='leased',attempts=attempts+1,
                     lease_owner=?,lease_until=?,updated_at=CURRENT_TIMESTAMP WHERE job_key=?""",
                (worker_id, lease_until.isoformat(), row["job_key"]),
            )
            if row["state"] == PipelineState.EMPLOYER_RESEARCH_QUEUED.value:
                attempt = int(row["attempts"]) + 1
                self.lifecycle.commit_in_transaction(
                    conn,
                    job_key=row["job_key"],
                    to_state=PipelineState.EMPLOYER_RESEARCHING,
                    policy=RESEARCH_LEASE_POLICY,
                    inputs={"queue_status": row["status"], "attempt": attempt},
                    outputs={
                        "worker_id": worker_id,
                        "lease_until": lease_until.isoformat(),
                    },
                    idempotency_key=f"research-lease:{row['job_key']}:{attempt}",
                )
            task = dict(row)
            task.pop("status")
            task.pop("state")
            task["attempts"] = int(task["attempts"]) + 1
            return ResearchTask(**task)

    def complete_research(
        self,
        *,
        job_key: str,
        worker_id: str,
        dossier: dict[str, Any],
        dossier_hash: str,
    ) -> None:
        """Persist a provenance-validated probabilistic research result."""
        sources = dossier.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ValueError("employer dossier requires at least one public source")
        source_ids = {str(source.get("id")) for source in sources if isinstance(source, dict)}
        for claim in dossier.get("claims", []):
            if not isinstance(claim, dict):
                raise ValueError("dossier claims must be objects")
            cited = {str(value) for value in claim.get("source_ids", [])}
            if not cited or not cited.issubset(source_ids):
                raise ValueError("every dossier claim must cite known source IDs")
        model = self._dossier_model(dossier)
        observation = {
            "dossier": dossier,
            "dossier_hash": dossier_hash,
            "source_ids": sorted(source_ids),
            "worker_id": worker_id,
        }
        proposal_key = f"research-observation:{job_key}:{dossier_hash}"
        transition_key = f"research-complete:{job_key}:{dossier_hash}"
        with self.transaction(immediate=True) as conn:
            queue = conn.execute(
                """SELECT q.status,q.lease_owner,d.worker_id AS dossier_worker
                   FROM employer_research_queue q
                   LEFT JOIN employer_dossiers d ON d.job_key=q.job_key
                   WHERE q.job_key=?""",
                (job_key,),
            ).fetchone()
            is_owner = queue is not None and (
                (queue["status"] == "leased" and queue["lease_owner"] == worker_id)
                or (queue["status"] == "completed" and queue["dossier_worker"] == worker_id)
            )
            if not is_owner:
                raise RuntimeError("research task is not leased by this worker")
            self.lifecycle.record_proposal_in_transaction(
                conn,
                job_key=job_key,
                proposed_state=PipelineState.EMPLOYER_RESEARCHED,
                actor=ActorKind.PROBABILISTIC,
                observation=observation,
                idempotency_key=proposal_key,
                model=model,
            )
            self.lifecycle.commit_in_transaction(
                conn,
                job_key=job_key,
                to_state=PipelineState.EMPLOYER_RESEARCHED,
                policy=RESEARCH_COMPLETION_POLICY,
                inputs=observation,
                outputs={"validated": True, "queue_status": "completed"},
                idempotency_key=transition_key,
                model=model,
            )
            conn.execute(
                """INSERT INTO employer_dossiers(job_key,dossier_json,dossier_hash,worker_id)
                   VALUES(?,?,?,?) ON CONFLICT(job_key) DO UPDATE SET
                   dossier_json=excluded.dossier_json,dossier_hash=excluded.dossier_hash,
                   worker_id=excluded.worker_id,created_at=CURRENT_TIMESTAMP""",
                (job_key, json.dumps(dossier, ensure_ascii=False, sort_keys=True), dossier_hash, worker_id),
            )
            conn.execute(
                """UPDATE employer_research_queue SET status='completed',lease_owner=NULL,
                     lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE job_key=?""",
                (job_key,),
            )

    @staticmethod
    def _dossier_model(dossier: dict[str, Any]) -> ModelIdentity | None:
        value = dossier.get("model")
        if not isinstance(value, dict):
            return None
        provider = value.get("provider")
        model_id = value.get("model_id", value.get("id"))
        version = value.get("version")
        if all(isinstance(item, str) and item.strip()
               for item in (provider, model_id, version)):
            return ModelIdentity(provider, model_id, version)
        return None

    def stats(self) -> dict[str, int]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT state,COUNT(*) AS n FROM pipeline_jobs GROUP BY state"
            ).fetchall()
            result = {str(row["state"]): int(row["n"]) for row in rows}
            result["total"] = int(conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0])
            result["research_queued"] = int(conn.execute(
                "SELECT COUNT(*) FROM employer_research_queue WHERE status='queued'"
            ).fetchone()[0])
            result["research_leased"] = int(conn.execute(
                "SELECT COUNT(*) FROM employer_research_queue WHERE status='leased'"
            ).fetchone()[0])
        return result
