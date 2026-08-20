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
    LEGAL_TRANSITIONS,
    IdempotencyConflict,
    LifecycleReducer,
    ModelIdentity,
    OPPORTUNITY1_POLICY_ID,
    OPPORTUNITY1_POLICY_VERSION,
    OPPORTUNITY1_ROUTING_POLICY_ID,
    POST_RESEARCH_STATES,
    PolicyIdentity,
    RESEARCH_COMPLETION_OUTPUT,
    RESEARCH_COMPLETION_POLICY_HASH,
    RESEARCH_COMPLETION_POLICY_ID,
    RESEARCH_COMPLETION_POLICY_IDENTITIES,
    RESEARCH_COMPLETION_POLICY_VERSION,
    canonical_hash,
    canonical_json,
    score_snapshot_import_binding,
)
from .models import ActorKind, PipelineState, ResearchTask, ScoredJob


RESEARCH_LEASE_POLICY = PolicyIdentity(
    "career.research-lease", "1",
    canonical_hash({"rule": "lease queued work; advance only queued jobs"}),
)
RESEARCH_COMPLETION_POLICY = PolicyIdentity(
    RESEARCH_COMPLETION_POLICY_ID,
    RESEARCH_COMPLETION_POLICY_VERSION,
    RESEARCH_COMPLETION_POLICY_HASH,
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

CREATE TABLE IF NOT EXISTS employer_intelligence (
  job_key TEXT NOT NULL REFERENCES employer_dossiers(job_key) ON DELETE CASCADE,
  claim_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('company','role','product','hiring','operational_health')),
  classification TEXT NOT NULL CHECK(classification IN ('fact','inference','hypothesis')),
  claim_json TEXT NOT NULL,
  PRIMARY KEY(job_key,claim_id)
);
CREATE TABLE IF NOT EXISTS employer_intelligence_edges (
  job_key TEXT NOT NULL,
  from_claim_id TEXT NOT NULL,
  to_claim_id TEXT NOT NULL,
  relation TEXT NOT NULL CHECK(relation IN ('supports','qualifies','contradicts','depends_on')),
  PRIMARY KEY(job_key,from_claim_id,to_claim_id,relation),
  FOREIGN KEY(job_key,from_claim_id) REFERENCES employer_intelligence(job_key,claim_id),
  FOREIGN KEY(job_key,to_claim_id) REFERENCES employer_intelligence(job_key,claim_id)
);
CREATE TABLE IF NOT EXISTS opportunity_reassessments (
  job_key TEXT PRIMARY KEY REFERENCES employer_dossiers(job_key) ON DELETE CASCADE,
  opportunity0_score_bp INTEGER NOT NULL CHECK(opportunity0_score_bp BETWEEN 0 AND 10000),
  opportunity1_score_bp INTEGER NOT NULL CHECK(opportunity1_score_bp BETWEEN 0 AND 10000),
  decision TEXT NOT NULL CHECK(decision IN ('pass','reject')),
  changes_json TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
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
        """Store one immutable score snapshot, making identical retries idempotent."""
        if not isinstance(job.payload, dict):
            raise ValueError("score snapshot payload must be a JSON object")
        if (not isinstance(job.payload_hash, str)
                or len(job.payload_hash) != 64
                or any(char not in "0123456789abcdef" for char in job.payload_hash)):
            raise ValueError("score snapshot payload_hash must be a lowercase SHA-256 digest")
        if canonical_hash(job.payload) != job.payload_hash:
            raise ValueError("score snapshot payload_hash does not match canonical payload")
        payload_json = canonical_json(job.payload)
        event_payload_json, event_key, event_binding_hash = score_snapshot_import_binding(
            job_key=job.key, board=job.board, job_id=job.job_id, url=job.url,
            title=job.title, company=job.company, fit=job.fit,
            opportunity=job.opportunity, final_score=job.final_score,
            extraction_confidence=job.extraction_confidence,
            payload_hash=job.payload_hash,
        )
        snapshot = (
            job.board, job.job_id, job.url, job.title, job.company, job.fit,
            job.opportunity, job.final_score, job.extraction_confidence,
            payload_json, job.payload_hash,
        )
        with self.transaction(immediate=True) as conn:
            existing = conn.execute(
                """SELECT board,job_id,url,title,company,fit,opportunity,final_score,
                          extraction_confidence,payload_json,payload_hash
                   FROM pipeline_jobs WHERE job_key=?""",
                (job.key,),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != snapshot:
                    raise IdempotencyConflict(
                        "job key was reused with a changed score snapshot; "
                        "versioned score updates require an explicit ledger event"
                    )
                event = conn.execute(
                    """SELECT id,job_key,event_type,from_state,to_state,actor_kind,
                              payload_json,idempotency_key
                       FROM pipeline_events WHERE idempotency_key=?""",
                    (event_key,),
                ).fetchone()
                expected_event = (
                    job.key, "score_snapshot_imported", None,
                    PipelineState.SCORED.value, ActorKind.DETERMINISTIC.value,
                    event_payload_json, event_key,
                )
                if event is None or tuple(event)[1:] != expected_event:
                    raise IdempotencyConflict(
                        "existing score snapshot has no matching immutable import event"
                    )
                receipt = conn.execute(
                    """SELECT event_id,job_key,binding_json,binding_hash,idempotency_key
                       FROM score_snapshot_receipts WHERE job_key=?""",
                    (job.key,),
                ).fetchone()
                expected_receipt = (
                    int(event["id"]), job.key, event_payload_json,
                    event_binding_hash, event_key,
                )
                if receipt is None or tuple(receipt) != expected_receipt:
                    raise IdempotencyConflict(
                        "existing score snapshot has no matching immutable receipt"
                    )
                return False
            conn.execute(
                """INSERT INTO pipeline_jobs(
                     job_key,board,job_id,url,title,company,fit,opportunity,final_score,
                     extraction_confidence,payload_json,payload_hash,state
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job.key, job.board, job.job_id, job.url, job.title, job.company,
                    job.fit, job.opportunity, job.final_score, job.extraction_confidence,
                    payload_json,
                    job.payload_hash, PipelineState.SCORED.value,
                ),
            )
            event = conn.execute(
                """INSERT INTO pipeline_events(
                     job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    job.key, "score_snapshot_imported", None, PipelineState.SCORED.value,
                    ActorKind.DETERMINISTIC.value, event_payload_json, event_key,
                ),
            )
            conn.execute(
                """INSERT INTO score_snapshot_receipts(
                     event_id,job_key,binding_json,binding_hash,idempotency_key
                   ) VALUES(?,?,?,?,?)""",
                (
                    event.lastrowid, job.key, event_payload_json,
                    event_binding_hash, event_key,
                ),
            )
        return True

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
            event_key = (
                f"opportunity-gate:{job_key}:{current['payload_hash']}:{policy_hash}"
            )
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
                     opportunity_reason=?,policy_hash=?,updated_at=CURRENT_TIMESTAMP
                   WHERE job_key=?""",
                (decision, reason, policy_hash, job_key),
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
                   WHERE q.status='queued' AND julianday(q.available_at)<=julianday('now')
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
                   WHERE j.opportunity_decision='pass' AND (
                         (q.status='queued' AND julianday(q.available_at)<=julianday('now'))
                      OR (q.status='leased' AND julianday(q.lease_until)<julianday('now')))
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

    def record_research_failure(self, *, job_key: str, worker_id: str, error: str) -> None:
        """Make a failed lease explicitly retryable without creating a receipt.

        The row remains leased to retain the failed attempt's ownership audit.
        Stable-workspace resumption explicitly requeues such leases on the next
        invocation, while this invocation can continue draining other rows.
        """
        detail = str(error).strip() or "research retrieval failed"
        with self.transaction(immediate=True) as conn:
            changed = conn.execute(
                """UPDATE employer_research_queue
                   SET last_error=?,updated_at=CURRENT_TIMESTAMP
                   WHERE job_key=? AND status='leased' AND lease_owner=?""",
                (detail, job_key, worker_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("research failure is not held by this lease owner")

    def complete_research(
        self,
        *,
        job_key: str,
        worker_id: str,
        dossier: dict[str, Any],
        dossier_hash: str,
    ) -> None:
        """Persist a provenance-validated probabilistic research result."""
        from .employer_research import RawResponseCache, validate_dossier
        if dossier.get("job_key") != job_key:
            raise ValueError("dossier job identity does not match the research task")
        if canonical_hash(dossier) != dossier_hash:
            raise ValueError("dossier hash does not match canonical content")
        strict = dossier.get("schema_version") in {
            "jaa04.dossier.v1", "jaa04.dossier.v2",
            "jaa04.dossier.v3", "jaa04.dossier.v4",
        }
        if strict:
            cache_root = dossier.get("raw_cache_root")
            if not isinstance(cache_root, str) or not cache_root:
                raise ValueError("dossier must identify its raw response cache")
            validate_dossier(dossier, RawResponseCache(cache_root))
        sources = dossier.get("sources")
        if not isinstance(sources, list) or not sources:
            raise ValueError("employer dossier requires at least one public source")
        source_ids = {str(source.get("id")) for source in sources if isinstance(source, dict)}
        for claim in dossier.get("claims", []):
            cited = {str(value) for value in claim.get("source_ids", [])} if isinstance(claim, dict) else set()
            unsupported = (isinstance(claim, dict)
                           and claim.get("outcome") in {"unknown", "abstained"})
            if (not cited and not unsupported) or not cited.issubset(source_ids):
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
                """SELECT q.status,q.lease_owner,q.lease_until,d.worker_id AS dossier_worker
                   FROM employer_research_queue q
                   LEFT JOIN employer_dossiers d ON d.job_key=q.job_key
                   WHERE q.job_key=?""",
                (job_key,),
            ).fetchone()
            lease_is_current = False
            if queue is not None and queue["lease_until"]:
                lease_is_current = datetime.fromisoformat(
                    str(queue["lease_until"]).replace("Z", "+00:00")
                ) >= datetime.now(timezone.utc)
            is_owner = queue is not None and (
                (queue["status"] == "leased" and queue["lease_owner"] == worker_id
                 and lease_is_current)
                or (queue["status"] == "completed" and queue["dossier_worker"] == worker_id)
            )
            if not is_owner:
                raise RuntimeError("research task is not leased by this worker")
            if queue["status"] == "completed":
                completed = self._post_research_dossier_in_transaction(conn, job_key)
                if completed is None:
                    raise RuntimeError("completed research state is missing its dossier")
                stored_dossier, stored_hash = completed
                if stored_hash != dossier_hash or stored_dossier != dossier:
                    raise IdempotencyConflict(
                        "research completion retry differs from durable state"
                    )
                return
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
                outputs=RESEARCH_COMPLETION_OUTPUT,
                idempotency_key=transition_key,
                model=model,
            )
            existing = conn.execute(
                "SELECT dossier_hash FROM employer_dossiers WHERE job_key=?", (job_key,)
            ).fetchone()
            if existing is not None and existing["dossier_hash"] != dossier_hash:
                raise RuntimeError("dossier completion is immutable and at-most-once")
            conn.execute(
                """INSERT OR IGNORE INTO employer_dossiers(job_key,dossier_json,dossier_hash,worker_id)
                   VALUES(?,?,?,?)""",
                (job_key, json.dumps(dossier, ensure_ascii=False, sort_keys=True), dossier_hash, worker_id),
            )
            if strict:
                for claim in dossier["claims"]:
                    if claim.get("outcome") in {"unknown", "abstained"}:
                        # The outcome remains durable in dossier_json; it is
                        # deliberately absent from the positive-claim index.
                        continue
                    conn.execute(
                        """INSERT OR IGNORE INTO employer_intelligence
                           (job_key,claim_id,kind,classification,claim_json) VALUES(?,?,?,?,?)""",
                        (job_key, claim["id"], claim["kind"], claim["classification"],
                         json.dumps(claim, ensure_ascii=False, sort_keys=True)),
                    )
                for edge in dossier.get("edges", []):
                    conn.execute(
                        """INSERT OR IGNORE INTO employer_intelligence_edges
                           (job_key,from_claim_id,to_claim_id,relation) VALUES(?,?,?,?)""",
                        (job_key, edge["from_claim_id"], edge["to_claim_id"], edge["relation"]),
                    )
            conn.execute(
                """UPDATE employer_research_queue SET status='completed',lease_owner=NULL,
                     lease_until=NULL,updated_at=CURRENT_TIMESTAMP WHERE job_key=?""",
                (job_key,),
            )

    def completed_research(self, job_key: str) -> tuple[dict[str, Any], str] | None:
        """Return only a durably completed, research-state dossier."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT state FROM pipeline_jobs WHERE job_key=?",
                (job_key,),
            ).fetchone()
            if row is None or row["state"] != PipelineState.EMPLOYER_RESEARCHED.value:
                return None
            return self._post_research_dossier_in_transaction(conn, job_key)

    def _post_research_dossier_in_transaction(
        self, conn: sqlite3.Connection, job_key: str,
    ) -> tuple[dict[str, Any], str] | None:
        """Validate the complete research seam using the caller's transaction."""
        job = conn.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?", (job_key,),
        ).fetchone()
        queue = conn.execute(
            "SELECT status FROM employer_research_queue WHERE job_key=?", (job_key,),
        ).fetchone()
        rows = conn.execute(
            "SELECT dossier_json,dossier_hash,worker_id FROM employer_dossiers WHERE job_key=?",
            (job_key,),
        ).fetchall()
        research_completion_receipts = conn.execute(
            """SELECT policy_version,policy_hash,input_hash,output_hash,idempotency_key,
                      model_provider,model_id,model_version
               FROM lifecycle_transition_receipts
               WHERE job_key=? AND from_state=? AND to_state=? AND policy_id=?""",
            (job_key, PipelineState.EMPLOYER_RESEARCHING.value,
             PipelineState.EMPLOYER_RESEARCHED.value,
             RESEARCH_COMPLETION_POLICY.policy_id),
        ).fetchall()
        present = (job is not None, queue is not None, bool(rows))
        if not any(present):
            return None
        if (not all(present) or len(rows) != 1
                or len(research_completion_receipts) != 1):
            raise RuntimeError("post-research dossier state is incomplete or duplicated")
        if queue["status"] != "completed" or str(job["state"]) not in POST_RESEARCH_STATES:
            raise RuntimeError("dossier is not in a completed post-research lifecycle state")
        row = rows[0]
        try:
            dossier = json.loads(row["dossier_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("completed dossier is not valid JSON") from exc
        dossier_hash = str(row["dossier_hash"])
        if (not isinstance(dossier, dict) or dossier.get("job_key") != job_key
                or canonical_hash(dossier) != dossier_hash):
            raise RuntimeError("completed dossier identity or hash is invalid")
        research_proposals = conn.execute(
            """SELECT from_state,to_state,actor_kind,payload_json,idempotency_key
               FROM pipeline_events
               WHERE job_key=? AND event_type='lifecycle_transition_proposed'
                 AND idempotency_key=?""",
            (job_key, f"research-observation:{job_key}:{dossier_hash}"),
        ).fetchall()
        if len(research_proposals) != 1:
            raise RuntimeError("completed dossier has no unique research proposal")
        sources = dossier.get("sources")
        if not isinstance(sources, list) or not sources:
            raise RuntimeError("completed dossier source identity is invalid")
        source_ids = sorted({str(source.get("id")) for source in sources
                             if isinstance(source, dict)})
        observation = {"dossier": dossier, "dossier_hash": dossier_hash,
                       "source_ids": source_ids, "worker_id": str(row["worker_id"])}
        receipt = research_completion_receipts[0]
        model = self._dossier_model(dossier)
        try:
            proposal = json.loads(research_proposals[0]["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("completed dossier proposal is invalid") from exc
        expected_model = None if model is None else {
            "provider": model.provider,
            "model_id": model.model_id,
            "version": model.version,
        }
        if ((str(receipt["policy_version"]), str(receipt["policy_hash"]))
                not in RESEARCH_COMPLETION_POLICY_IDENTITIES
                or canonical_hash(observation) != str(receipt["input_hash"])
                or canonical_hash(RESEARCH_COMPLETION_OUTPUT)
                != str(receipt["output_hash"])
                or str(receipt["idempotency_key"])
                != f"research-complete:{job_key}:{dossier_hash}"
                or (
                    receipt["model_provider"], receipt["model_id"],
                    receipt["model_version"],
                ) != (
                    None if model is None else model.provider,
                    None if model is None else model.model_id,
                    None if model is None else model.version,
                )
                or not isinstance(proposal, dict)
                or set(proposal) != {
                    "proposed_state", "observation", "observation_hash", "model",
                }
                or research_proposals[0]["payload_json"] != canonical_json(proposal)
                or research_proposals[0]["from_state"]
                != PipelineState.EMPLOYER_RESEARCHING.value
                or research_proposals[0]["to_state"] is not None
                or research_proposals[0]["actor_kind"]
                != ActorKind.PROBABILISTIC.value
                or proposal.get("proposed_state")
                != PipelineState.EMPLOYER_RESEARCHED.value
                or proposal.get("observation") != observation
                or proposal.get("observation_hash") != canonical_hash(observation)
                or proposal.get("model") != expected_model
                or str(research_proposals[0]["idempotency_key"])
                != f"research-observation:{job_key}:{dossier_hash}"):
            raise RuntimeError("completed dossier does not match its immutable receipt")
        return dossier, dossier_hash

    def post_research_dossier(self, job_key: str) -> tuple[dict[str, Any], str] | None:
        """Read an immutable dossier at research completion or any successor.

        This is deliberately separate from :meth:`completed_research`, which is
        the exact-state gate used before Opportunity-1.  Partial or contradictory
        durable state is an error rather than an absent dossier.
        """
        with self.connection() as conn:
            return self._post_research_dossier_in_transaction(conn, job_key)

    def opportunity1_reassessment(self, job_key: str, *,
                                  expected_dossier_hash: str | None = None) -> dict[str, Any] | None:
        """Recover and validate the one durable Opportunity-1 decision."""
        completed = self.post_research_dossier(job_key)
        if completed is None:
            return None
        dossier, dossier_hash = completed
        if expected_dossier_hash is not None and dossier_hash != expected_dossier_hash:
            raise RuntimeError("Opportunity-1 reassessment is bound to a different dossier")
        with self.connection() as conn:
            lifecycle_state = conn.execute(
                "SELECT state FROM pipeline_jobs WHERE job_key=?", (job_key,),
            ).fetchone()
            rows = conn.execute(
                """SELECT r.opportunity0_score_bp,r.opportunity1_score_bp,r.decision,
                          r.changes_json,r.policy_hash,j.opportunity,j.state
                   FROM opportunity_reassessments r
                   JOIN pipeline_jobs j ON j.job_key=r.job_key WHERE r.job_key=?""",
                (job_key,),
            ).fetchall()
            opportunity1_receipts = conn.execute(
                """SELECT input_hash,output_hash,policy_hash
                   FROM lifecycle_transition_receipts
                   WHERE job_key=? AND from_state=? AND to_state=? AND policy_id=?""",
                (job_key, PipelineState.EMPLOYER_RESEARCHED.value,
                 PipelineState.OPPORTUNITY_1_ASSESSED.value,
                 OPPORTUNITY1_POLICY_ID),
            ).fetchall()
        if (len(rows) == 0 and len(opportunity1_receipts) == 0
                and lifecycle_state is not None
                and str(lifecycle_state["state"])
                == PipelineState.EMPLOYER_RESEARCHED.value):
            return None
        if len(rows) != 1 or len(opportunity1_receipts) != 1:
            raise RuntimeError("Opportunity-1 reassessment or receipt is absent or duplicated")
        row = rows[0]
        if str(row["state"]) == PipelineState.EMPLOYER_RESEARCHED.value:
            raise RuntimeError("Opportunity-1 reassessment exists before lifecycle advancement")
        try:
            changes = json.loads(row["changes_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Opportunity-1 changes are not valid JSON") from exc
        if not isinstance(changes, list):
            raise ValueError("Opportunity-1 changes must be a list")
        from dataclasses import asdict
        from .opportunity1 import reassess_opportunity1
        original = round(float(row["opportunity"]) * 10_000)
        signals = []
        dossier_claim_ids = {str(claim.get("id")) for claim in dossier.get("claims", [])}
        for change in changes:
            if not isinstance(change, dict) or str(change.get("claim_id")) not in dossier_claim_ids:
                raise RuntimeError("Opportunity-1 change does not match the completed dossier")
            signals.append(change)
        expected = asdict(reassess_opportunity1(original, signals))
        expected["changes"] = list(expected["changes"])
        expected_inputs = {
            "opportunity0_score_bp": original,
            "dossier_hash": dossier_hash,
            "signals": changes,
        }
        opportunity1_receipt = opportunity1_receipts[0]
        if (int(row["opportunity0_score_bp"]) != original
                or int(row["opportunity1_score_bp"]) != expected["score_bp"]
                or str(row["decision"]) != expected["decision"]
                or changes != expected["changes"]
                or str(row["policy_hash"]) != expected["policy_hash"]
                or str(opportunity1_receipt["policy_hash"]) != expected["policy_hash"]
                or str(opportunity1_receipt["input_hash"]) != canonical_hash(expected_inputs)
                or str(opportunity1_receipt["output_hash"]) != canonical_hash(expected)):
            raise RuntimeError("Opportunity-1 reassessment is inconsistent")
        return {**expected, "dossier_hash": dossier_hash}

    def apply_opportunity1(self, *, job_key: str, signals: list[dict[str, Any]],
                           expected_dossier_hash: str | None = None) -> dict[str, Any]:
        """Reassess after a completed dossier; exact retries return the durable result."""
        from dataclasses import asdict
        from .opportunity1 import reassess_opportunity1

        with self.transaction(immediate=True) as conn:
            completed = self._post_research_dossier_in_transaction(conn, job_key)
            if completed is None:
                raise RuntimeError("Opportunity-1 requires completed employer research")
            dossier, dossier_hash = completed
            row = conn.execute(
                "SELECT opportunity,state FROM pipeline_jobs WHERE job_key=?", (job_key,),
            ).fetchone()
            if row is None:
                raise RuntimeError("Opportunity-1 requires completed employer research")
            if (expected_dossier_hash is not None
                    and dossier_hash != expected_dossier_hash):
                raise RuntimeError("completed research changed before Opportunity-1")
            dossier_claim_ids = {
                str(claim.get("id")) for claim in dossier.get("claims", [])
                if isinstance(claim, dict) and claim.get("id") is not None
            }
            if any(
                not isinstance(signal, dict)
                or str(signal.get("claim_id")) not in dossier_claim_ids
                for signal in signals
            ):
                raise ValueError(
                    "Opportunity-1 signals must reference the completed dossier"
                )
            result = reassess_opportunity1(round(float(row["opportunity"]) * 10_000), signals)
            output = asdict(result)
            ordered_signals = list(output["changes"])
            output["changes"] = ordered_signals
            key = f"opportunity-1:{job_key}:{dossier_hash}:{result.policy_hash}"
            target = (PipelineState.FIT_ASSESSED if result.decision == "pass"
                      else PipelineState.OPPORTUNITY_REJECTED_AFTER_RESEARCH)
            current_state = PipelineState(row["state"])
            pending, target_closure = [target], set()
            while pending:
                state = pending.pop()
                if state in target_closure:
                    continue
                target_closure.add(state)
                pending.extend(LEGAL_TRANSITIONS[state])
            existing = conn.execute(
                """SELECT job_key,opportunity0_score_bp,opportunity1_score_bp,
                          decision,changes_json,policy_hash
                   FROM opportunity_reassessments WHERE job_key=?""",
                (job_key,),
            ).fetchone()
            fresh = current_state is PipelineState.EMPLOYER_RESEARCHED
            if (fresh and existing is not None) or (
                    not fresh and (current_state not in target_closure or existing is None)):
                raise RuntimeError("Opportunity-1 durable state is incomplete or inconsistent")
            self.lifecycle.commit_in_transaction(
                conn, job_key=job_key, to_state=PipelineState.OPPORTUNITY_1_ASSESSED,
                policy=PolicyIdentity(
                    OPPORTUNITY1_POLICY_ID,
                    OPPORTUNITY1_POLICY_VERSION,
                    result.policy_hash,
                ),
                inputs={"opportunity0_score_bp": result.opportunity0_score_bp,
                        "dossier_hash": dossier_hash, "signals": ordered_signals},
                outputs=output, idempotency_key=key,
            )
            expected_reassessment = (
                job_key, result.opportunity0_score_bp, result.score_bp, result.decision,
                json.dumps(ordered_signals, sort_keys=True), result.policy_hash,
            )
            if fresh:
                conn.execute(
                    """INSERT INTO opportunity_reassessments
                       (job_key,opportunity0_score_bp,opportunity1_score_bp,decision,
                        changes_json,policy_hash)
                       VALUES(?,?,?,?,?,?)""",
                    expected_reassessment,
                )
            else:
                if tuple(existing) != expected_reassessment:
                    raise IdempotencyConflict(
                        "Opportunity-1 retry differs from the durable reassessment"
                    )
            self.lifecycle.commit_in_transaction(
                conn, job_key=job_key, to_state=target,
                policy=PolicyIdentity(
                    OPPORTUNITY1_ROUTING_POLICY_ID,
                    OPPORTUNITY1_POLICY_VERSION,
                    result.policy_hash,
                ),
                inputs=output, outputs={"decision": result.decision},
                idempotency_key=key + ":route",
            )
            return output

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
