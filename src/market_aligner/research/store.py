"""Profile-aware assessment state and deterministic employer-research queue."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from market_aligner.assessment.scoring import ScoreResult
from market_aligner.profiler.schema import validate_profile_id

from .models import ResearchDossier, ResearchTask


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=30000;

CREATE TABLE IF NOT EXISTS assessments (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  url TEXT NOT NULL,
  title TEXT NOT NULL,
  company TEXT NOT NULL,
  opportunity REAL NOT NULL CHECK(opportunity >= 0 AND opportunity <= 1),
  fit REAL NOT NULL CHECK(fit >= 0 AND fit <= 1),
  final_score REAL NOT NULL CHECK(final_score >= 0 AND final_score <= 100),
  fit_status TEXT NOT NULL CHECK(fit_status IN ('uncalibrated')),
  extraction_confidence REAL,
  score_payload_json TEXT NOT NULL,
  score_payload_hash TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'scored',
  opportunity_decision TEXT CHECK(opportunity_decision IN ('pass','reject')),
  opportunity_reason TEXT,
  policy_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key)
);
CREATE INDEX IF NOT EXISTS assessments_rank
  ON assessments(profile_id,opportunity DESC,final_score DESC);

CREATE TABLE IF NOT EXISTS assessment_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_kind TEXT NOT NULL CHECK(actor_kind IN ('deterministic','probabilistic','external')),
  payload_json TEXT NOT NULL DEFAULT '{}',
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(profile_id,job_key) REFERENCES assessments(profile_id,job_key) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS employer_research_queue (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','leased','completed','failed')),
  priority INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  available_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  lease_owner TEXT,
  lease_until TEXT,
  last_error TEXT,
  queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key),
  FOREIGN KEY(profile_id,job_key) REFERENCES assessments(profile_id,job_key) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS employer_dossiers (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  dossier_json TEXT NOT NULL,
  dossier_hash TEXT NOT NULL,
  worker_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key),
  FOREIGN KEY(profile_id,job_key) REFERENCES assessments(profile_id,job_key) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS research_requires_opportunity_pass
BEFORE INSERT ON employer_research_queue
WHEN COALESCE((SELECT opportunity_decision FROM assessments
               WHERE profile_id=NEW.profile_id AND job_key=NEW.job_key),'') != 'pass'
BEGIN
  SELECT RAISE(ABORT, 'employer research requires a passed opportunity gate');
END;
"""


class AssessmentStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def upsert_score(
        self,
        result: ScoreResult,
        *,
        url: str,
        title: str,
        company: str,
        extraction_confidence: float | None,
    ) -> None:
        validate_profile_id(result.profile_id)
        payload = json.dumps(asdict(result), ensure_ascii=False, sort_keys=True, default=str)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self.transaction() as connection:
            connection.execute(
                """INSERT INTO assessments(
                     profile_id,job_key,url,title,company,opportunity,fit,final_score,fit_status,
                     extraction_confidence,score_payload_json,score_payload_hash
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(profile_id,job_key) DO UPDATE SET
                     url=excluded.url,title=excluded.title,company=excluded.company,
                     opportunity=excluded.opportunity,fit=excluded.fit,
                     final_score=excluded.final_score,fit_status=excluded.fit_status,
                     extraction_confidence=excluded.extraction_confidence,
                     score_payload_json=excluded.score_payload_json,
                     score_payload_hash=excluded.score_payload_hash,updated_at=CURRENT_TIMESTAMP""",
                (
                    result.profile_id,
                    result.job_key,
                    url,
                    title,
                    company,
                    result.opportunity,
                    result.fit,
                    result.final,
                    result.fit_status.value,
                    extraction_confidence,
                    payload,
                    digest,
                ),
            )
            connection.execute(
                """INSERT OR IGNORE INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    result.profile_id,
                    result.job_key,
                    "score_snapshot_imported",
                    "deterministic",
                    json.dumps({"score_payload_hash": digest}, sort_keys=True),
                    f"score:{result.profile_id}:{result.job_key}:{digest}",
                ),
            )

    def assessment(self, profile_id: str, job_key: str) -> sqlite3.Row:
        validate_profile_id(profile_id)
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM assessments WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
        if row is None:
            raise KeyError((profile_id, job_key))
        return row

    def ranked(self, profile_id: str) -> list[sqlite3.Row]:
        validate_profile_id(profile_id)
        with self.connection() as connection:
            return connection.execute(
                """SELECT * FROM assessments WHERE profile_id=?
                   ORDER BY final_score DESC,opportunity DESC,job_key""",
                (profile_id,),
            ).fetchall()

    def apply_opportunity_gate(
        self,
        *,
        profile_id: str,
        job_key: str,
        passed: bool,
        reason: str,
        policy_hash: str,
        priority: int | None,
    ) -> None:
        decision = "pass" if passed else "reject"
        state = "employer_research_queued" if passed else "opportunity_rejected"
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT score_payload_hash FROM assessments WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
            if current is None:
                raise KeyError((profile_id, job_key))
            if passed and priority is None:
                raise ValueError("passed opportunity requires research priority")
            connection.execute(
                """UPDATE assessments SET state=?,opportunity_decision=?,opportunity_reason=?,
                     policy_hash=?,updated_at=CURRENT_TIMESTAMP WHERE profile_id=? AND job_key=?""",
                (state, decision, reason, policy_hash, profile_id, job_key),
            )
            event_key = (
                f"opportunity:{profile_id}:{job_key}:{current['score_payload_hash']}:{policy_hash}"
            )
            connection.execute(
                """INSERT OR IGNORE INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    "opportunity_gate_decided",
                    "deterministic",
                    json.dumps({"decision": decision, "reason": reason}, sort_keys=True),
                    event_key,
                ),
            )
            if passed:
                connection.execute(
                    """INSERT INTO employer_research_queue(profile_id,job_key,priority)
                       VALUES(?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                       priority=excluded.priority,updated_at=CURRENT_TIMESTAMP""",
                    (profile_id, job_key, priority),
                )
            else:
                connection.execute(
                    """DELETE FROM employer_research_queue
                       WHERE profile_id=? AND job_key=? AND status='queued'""",
                    (profile_id, job_key),
                )

    def enqueue_research(self, profile_id: str, job_key: str, priority: int) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO employer_research_queue(profile_id,job_key,priority) VALUES(?,?,?)",
                (profile_id, job_key, priority),
            )

    def claim_research(self, worker_id: str, lease_seconds: int = 900) -> ResearchTask | None:
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=max(1, lease_seconds))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT q.profile_id,q.job_key,a.title,a.company,a.url,a.opportunity,
                          q.priority,q.attempts
                   FROM employer_research_queue q JOIN assessments a
                     ON a.profile_id=q.profile_id AND a.job_key=q.job_key
                   WHERE (q.status='queued' AND q.available_at<=CURRENT_TIMESTAMP)
                      OR (q.status='leased' AND q.lease_until<CURRENT_TIMESTAMP)
                   ORDER BY q.priority DESC,a.opportunity DESC,q.queued_at LIMIT 1"""
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """UPDATE employer_research_queue SET status='leased',attempts=attempts+1,
                     lease_owner=?,lease_until=?,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                (worker_id, lease_until.isoformat(), row["profile_id"], row["job_key"]),
            )
            return ResearchTask(**dict(row))

    def complete_research(self, dossier: ResearchDossier, worker_id: str) -> str:
        dossier.validate()
        payload = json.dumps(asdict(dossier), ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self.transaction() as connection:
            lease = connection.execute(
                """SELECT lease_owner,status FROM employer_research_queue
                   WHERE profile_id=? AND job_key=?""",
                (dossier.profile_id, dossier.job_key),
            ).fetchone()
            if lease is None or lease["status"] != "leased" or lease["lease_owner"] != worker_id:
                raise RuntimeError("research completion requires the active lease")
            connection.execute(
                """INSERT INTO employer_dossiers(profile_id,job_key,dossier_json,dossier_hash,worker_id)
                   VALUES(?,?,?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                   dossier_json=excluded.dossier_json,dossier_hash=excluded.dossier_hash,
                   worker_id=excluded.worker_id,created_at=CURRENT_TIMESTAMP""",
                (dossier.profile_id, dossier.job_key, payload, digest, worker_id),
            )
            connection.execute(
                """UPDATE employer_research_queue SET status='completed',lease_owner=NULL,
                     lease_until=NULL,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                (dossier.profile_id, dossier.job_key),
            )
            connection.execute(
                """UPDATE assessments SET state='employer_researched',updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                (dossier.profile_id, dossier.job_key),
            )
        return digest
