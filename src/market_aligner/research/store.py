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

CREATE TABLE IF NOT EXISTS assessment_promotions (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  track TEXT NOT NULL,
  authority_sha256 TEXT NOT NULL,
  source_content_sha256 TEXT NOT NULL,
  processing_config_sha256 TEXT NOT NULL,
  processing_receipt_sha256 TEXT NOT NULL,
  processing_result_sha256 TEXT NOT NULL,
  score_payload_hash TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  receipt_bytes BLOB NOT NULL,
  receipt_sha256 TEXT NOT NULL UNIQUE,
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

    def promote_processing_gate(
        self,
        *,
        profile_id: str,
        job_key: str,
        score: dict[str, object],
        policy_hash: str,
        processing_receipt_sha256: str,
        processing_result_sha256: str,
        source_content_sha256: str,
        authority_sha256: str,
        processing_config_sha256: str,
        track: str,
        receipt_bytes: bytes,
        receipt_sha256: str,
    ) -> bool:
        """Atomically bind one current processing result to the handoff gate."""

        try:
            receipt = json.loads(receipt_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("processing promotion receipt is invalid JSON") from exc
        canonical = json.dumps(
            receipt,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        body = dict(receipt) if isinstance(receipt, dict) else {}
        body.pop("receipt_sha256", None)
        expected_receipt_sha = hashlib.sha256(
            json.dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        policy = receipt.get("policy") if isinstance(receipt, dict) else None
        binding = receipt.get("binding") if isinstance(receipt, dict) else None
        if (
            receipt_bytes != canonical
            or receipt.get("schema_version")
            != "market-aligner.assessment-promotion-receipt.v1"
            or receipt.get("decision") != "pass"
            or receipt.get("profile_id") != profile_id
            or receipt.get("job_key") != job_key
            or receipt.get("policy_sha256") != policy_hash
            or receipt.get("receipt_sha256") != receipt_sha256
            or receipt_sha256 != expected_receipt_sha
            or not isinstance(policy, dict)
            or hashlib.sha256(
                json.dumps(
                    policy,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest()
            != policy_hash
            or not isinstance(binding, dict)
            or hashlib.sha256(
                json.dumps(
                    binding,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest()
            != receipt.get("binding_sha256")
            or binding.get("processing_receipt_sha256")
            != processing_receipt_sha256
            or binding.get("processing_result_sha256") != processing_result_sha256
            or binding.get("source_content_sha256") != source_content_sha256
            or binding.get("evidence_authority_sha256") != authority_sha256
            or binding.get("processing_config_sha256")
            != processing_config_sha256
            or binding.get("track") != track
        ):
            raise ValueError("processing promotion receipt bindings differ")
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT * FROM assessments WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
            if current is None:
                raise KeyError((profile_id, job_key))
            if receipt.get("score_payload_hash") != current["score_payload_hash"]:
                raise ValueError("processing promotion score receipt differs")
            expected = {
                "fit": current["fit"],
                "opportunity": current["opportunity"],
                "final": current["final_score"],
                "fit_status": current["fit_status"],
            }
            if any(score.get(key) != value for key, value in expected.items()):
                raise ValueError("processing promotion score differs from assessment state")
            research_priority = 1_000_000 + round(
                float(current["opportunity"]) * 100_000
            )
            existing = connection.execute(
                "SELECT * FROM assessment_promotions WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
            if existing is not None:
                if (
                    existing["receipt_sha256"] != receipt_sha256
                    or bytes(existing["receipt_bytes"]) != receipt_bytes
                    or current["opportunity_decision"] != "pass"
                    or current["policy_hash"] != policy_hash
                ):
                    raise ValueError("processing promotion conflicts with sealed prior promotion")
                connection.execute(
                    """INSERT INTO employer_research_queue(profile_id,job_key,priority)
                       VALUES(?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                       priority=excluded.priority,updated_at=CURRENT_TIMESTAMP""",
                    (profile_id, job_key, research_priority),
                )
                return False
            connection.execute(
                """INSERT INTO assessment_promotions(
                     profile_id,job_key,track,authority_sha256,source_content_sha256,
                     processing_config_sha256,processing_receipt_sha256,
                     processing_result_sha256,score_payload_hash,policy_hash,
                     receipt_bytes,receipt_sha256
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    track,
                    authority_sha256,
                    source_content_sha256,
                    processing_config_sha256,
                    processing_receipt_sha256,
                    processing_result_sha256,
                    current["score_payload_hash"],
                    policy_hash,
                    sqlite3.Binary(receipt_bytes),
                    receipt_sha256,
                ),
            )
            connection.execute(
                """UPDATE assessments SET state='opportunity_promoted',
                     opportunity_decision='pass',opportunity_reason=?,policy_hash=?,
                     updated_at=CURRENT_TIMESTAMP WHERE profile_id=? AND job_key=?""",
                (
                    f"processing-promotion:{receipt_sha256}",
                    policy_hash,
                    profile_id,
                    job_key,
                ),
            )
            connection.execute(
                """INSERT INTO employer_research_queue(profile_id,job_key,priority)
                   VALUES(?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                   priority=excluded.priority,updated_at=CURRENT_TIMESTAMP""",
                (profile_id, job_key, research_priority),
            )
            connection.execute(
                """INSERT INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    "processing_assessment_promoted",
                    "deterministic",
                    json.dumps(
                        {
                            "policy_hash": policy_hash,
                            "processing_receipt_sha256": processing_receipt_sha256,
                            "processing_result_sha256": processing_result_sha256,
                            "receipt_sha256": receipt_sha256,
                        },
                        sort_keys=True,
                    ),
                    f"processing-promotion:{profile_id}:{job_key}:{receipt_sha256}",
                ),
            )
            return True

    def processing_promotion(self, profile_id: str, job_key: str) -> sqlite3.Row:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM assessment_promotions WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            ).fetchone()
        if row is None:
            raise KeyError((profile_id, job_key))
        return row

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

    def fail_research(
        self,
        profile_id: str,
        job_key: str,
        worker_id: str,
        error: str,
        *,
        retry_seconds: int = 300,
    ) -> None:
        available_at = datetime.now(timezone.utc) + timedelta(seconds=max(1, retry_seconds))
        with self.transaction() as connection:
            lease = connection.execute(
                """SELECT lease_owner,status FROM employer_research_queue
                   WHERE profile_id=? AND job_key=?""",
                (profile_id, job_key),
            ).fetchone()
            if lease is None or lease["status"] != "leased" or lease["lease_owner"] != worker_id:
                raise RuntimeError("research failure requires the active lease")
            connection.execute(
                """UPDATE employer_research_queue SET status='queued',lease_owner=NULL,
                     lease_until=NULL,last_error=?,available_at=?,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                (error[:2000], available_at.isoformat(), profile_id, job_key),
            )
