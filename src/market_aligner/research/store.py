"""Profile-aware assessment state and deterministic employer-research queue."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from market_aligner.assessment.scoring import ScoreResult
from market_aligner.profiler.schema import validate_profile_id
from market_aligner.state.vacancies import (
    JobDatabase,
)

from .models import (
    RESEARCH_ARCHIVE_ROOT_POLICY_SHA256,
    ResearchDossier,
    ResearchEvidenceBinding,
    ResearchTask,
    research_refresh_bridge_sha256,
    research_refresh_preserves_source_authority,
)


_BYTE_SELECTOR = re.compile(r"^bytes:(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$")


def _vacancy_snapshot_sha256(values: dict[str, Any]) -> str | None:
    if (
        values.get("source_content_sha256") is None
        or values.get("promotion_receipt_sha256") is None
    ):
        return None
    return hashlib.sha256(
        json.dumps(
            {
                "company": values["company"],
                "job_key": values["job_key"],
                "promotion_receipt_sha256": values["promotion_receipt_sha256"],
                "schema_version": "market-aligner.research-vacancy-snapshot.v1",
                "source_content_sha256": values["source_content_sha256"],
                "title": values["title"],
                "url": values["url"],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


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

CREATE TRIGGER IF NOT EXISTS immutable_collection_refresh_event_update
BEFORE UPDATE ON assessment_events
WHEN OLD.event_type='employer_research_collection_refresh_queued'
  OR NEW.event_type='employer_research_collection_refresh_queued'
BEGIN
  SELECT RAISE(ABORT, 'collection refresh assessment events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS immutable_collection_refresh_event_delete
BEFORE DELETE ON assessment_events
WHEN OLD.event_type='employer_research_collection_refresh_queued'
BEGIN
  SELECT RAISE(ABORT, 'collection refresh assessment events are immutable');
END;

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
  refresh_event_id INTEGER,
  refresh_bridge_sha256 TEXT,
  queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key),
  FOREIGN KEY(profile_id,job_key) REFERENCES assessments(profile_id,job_key) ON DELETE CASCADE,
  FOREIGN KEY(refresh_event_id) REFERENCES assessment_events(id) ON DELETE RESTRICT
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

CREATE TABLE IF NOT EXISTS employer_research_evidence (
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  dossier_hash TEXT NOT NULL,
  source_content_sha256 TEXT NOT NULL,
  vacancy_snapshot_sha256 TEXT NOT NULL,
  promotion_receipt_sha256 TEXT NOT NULL,
  canonical_vacancy_object_sha256 TEXT NOT NULL,
  semantic_receipt_sha256 TEXT NOT NULL,
  receipt_file_sha256 TEXT NOT NULL,
  archive_root_identity TEXT NOT NULL,
  archive_root_policy_sha256 TEXT NOT NULL,
  receipt_relative_path TEXT NOT NULL,
  schema_version TEXT NOT NULL CHECK(schema_version='market-aligner.research-store-binding.v2'),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(profile_id,job_key),
  FOREIGN KEY(profile_id,job_key) REFERENCES employer_dossiers(profile_id,job_key)
    ON DELETE CASCADE
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

_REFRESH_QUEUE_IMMUTABILITY_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS immutable_leased_refresh_bridge
BEFORE UPDATE ON employer_research_queue
WHEN OLD.status='leased' AND OLD.refresh_event_id IS NOT NULL
 AND (NEW.refresh_event_id IS NOT OLD.refresh_event_id
      OR NEW.refresh_bridge_sha256 IS NOT OLD.refresh_bridge_sha256)
BEGIN
  SELECT RAISE(ABORT, 'leased research refresh bridge is immutable');
END;
"""


class AssessmentStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.data_home = (
            self.path.parent.parent
            if self.path.parent.name == "state"
            else self.path.parent
        ).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.executescript(SCHEMA)
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(employer_research_queue)"
                )
            }
            if "refresh_event_id" not in columns:
                connection.execute(
                    "ALTER TABLE employer_research_queue ADD COLUMN "
                    "refresh_event_id INTEGER REFERENCES assessment_events(id) "
                    "ON DELETE RESTRICT"
                )
            if "refresh_bridge_sha256" not in columns:
                connection.execute(
                    "ALTER TABLE employer_research_queue ADD COLUMN "
                    "refresh_bridge_sha256 TEXT"
                )
            connection.executescript(_REFRESH_QUEUE_IMMUTABILITY_TRIGGER)

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
                       priority=excluded.priority,refresh_event_id=NULL,
                       refresh_bridge_sha256=NULL,
                       updated_at=CURRENT_TIMESTAMP""",
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
                       priority=excluded.priority,refresh_event_id=NULL,
                       refresh_bridge_sha256=NULL,
                       updated_at=CURRENT_TIMESTAMP""",
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
                   priority=excluded.priority,refresh_event_id=NULL,
                   refresh_bridge_sha256=NULL,
                   updated_at=CURRENT_TIMESTAMP""",
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

    def claim_research(
        self,
        worker_id: str,
        lease_seconds: int = 900,
        *,
        profile_id: str | None = None,
        job_key: str | None = None,
        require_refresh_bridge: bool = False,
        _preview_without_lease: bool = False,
    ) -> ResearchTask | None:
        if (profile_id is None) != (job_key is None):
            raise ValueError("research claim scope requires both profile_id and job_key")
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=max(1, lease_seconds))
        with self.transaction() as connection:
            scope = ""
            parameters: tuple[object, ...] = ()
            if profile_id is not None and job_key is not None:
                scope = " AND q.profile_id=? AND q.job_key=?"
                parameters = (profile_id, job_key)
            if require_refresh_bridge:
                scope += (
                    " AND q.refresh_event_id IS NOT NULL"
                    " AND q.refresh_bridge_sha256 IS NOT NULL"
                    " AND e.id=q.refresh_event_id"
                    " AND e.event_type='employer_research_collection_refresh_queued'"
                )
            row = connection.execute(
                """SELECT q.profile_id,q.job_key,a.title,a.company,a.url,a.opportunity,
                          q.priority,q.attempts,p.source_content_sha256,
                          p.receipt_sha256 AS promotion_receipt_sha256,
                          q.refresh_event_id,q.refresh_bridge_sha256,
                          e.event_type AS refresh_event_type,
                          e.actor_kind AS refresh_actor_kind,
                          e.payload_json AS refresh_payload_json,
                          e.idempotency_key AS refresh_event_idempotency_key,
                          d.dossier_hash AS refresh_current_dossier_hash,
                          d.dossier_json AS refresh_current_dossier_json
                   FROM employer_research_queue q JOIN assessments a
                     ON a.profile_id=q.profile_id AND a.job_key=q.job_key
                   LEFT JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   LEFT JOIN assessment_events e
                     ON e.id=q.refresh_event_id
                    AND e.profile_id=q.profile_id AND e.job_key=q.job_key
                   LEFT JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   WHERE ((q.status='queued' AND datetime(q.available_at)<=CURRENT_TIMESTAMP)
                      OR (q.status='leased' AND datetime(q.lease_until)<CURRENT_TIMESTAMP))"""
                + scope
                + " ORDER BY q.priority DESC,a.opportunity DESC,q.queued_at LIMIT 1",
                parameters,
            ).fetchone()
            if row is None:
                return None
            if not _preview_without_lease:
                connection.execute(
                    """UPDATE employer_research_queue SET status='leased',attempts=attempts+1,
                         lease_owner=?,lease_until=?,updated_at=CURRENT_TIMESTAMP
                       WHERE profile_id=? AND job_key=?""",
                    (worker_id, lease_until.isoformat(), row["profile_id"], row["job_key"]),
                )
            values = dict(row)
            refresh_event_id = values.pop("refresh_event_id")
            refresh_event_type = values.pop("refresh_event_type")
            refresh_actor_kind = values.pop("refresh_actor_kind")
            refresh_payload_json = values.pop("refresh_payload_json")
            refresh_event_idempotency_key = values.pop(
                "refresh_event_idempotency_key"
            )
            refresh_current_dossier_hash = values.pop(
                "refresh_current_dossier_hash"
            )
            refresh_current_dossier_json = values.pop(
                "refresh_current_dossier_json"
            )
            refresh_values = {
                "refresh_event_id": refresh_event_id,
                "refresh_event_idempotency_key": None,
                "refresh_receipt_sha256": None,
                "refresh_receipt_file_sha256": None,
                "refresh_transition_sha256": None,
                "refresh_id": None,
                "refresh_context_sha256": None,
                "refresh_operation_id": None,
                "refresh_legacy_content_sha256": None,
                "refresh_canonical_content_sha256": None,
                "refresh_raw_object_sha256": None,
                "refresh_fetched_at": None,
                "refresh_promotion_receipt_sha256": None,
                "refresh_prior_dossier_sha256": None,
            }
            if refresh_event_id is not None:
                try:
                    payload = json.loads(str(refresh_payload_json))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError("research refresh event payload is invalid") from exc
                expected_keys = {
                    "collection_context_sha256",
                    "collection_operation_id",
                    "collection_receipt_file_sha256",
                    "collection_receipt_sha256",
                    "collection_refresh_id",
                    "collection_transition_sha256",
                    "new_fetched_at",
                    "new_raw_object_sha256",
                    "old_canonical_content_sha256",
                    "old_collector_content_sha256",
                    "prior_dossier_hash",
                    "promotion_receipt_sha256",
                    "refresh_bridge_sha256",
                    "source_content_sha256",
                }
                if (
                    refresh_event_type
                    != "employer_research_collection_refresh_queued"
                    or refresh_actor_kind != "deterministic"
                    or not isinstance(payload, dict)
                    or set(payload) != expected_keys
                    or payload["source_content_sha256"]
                    != values["source_content_sha256"]
                    or not research_refresh_preserves_source_authority(
                        source_content_sha256=values["source_content_sha256"],
                        old_collector_content_sha256=payload[
                            "old_collector_content_sha256"
                        ],
                        old_canonical_content_sha256=payload[
                            "old_canonical_content_sha256"
                        ],
                    )
                    or payload["promotion_receipt_sha256"]
                    != values["promotion_receipt_sha256"]
                    or refresh_event_idempotency_key
                    != (
                        f"research-collection-refresh:{values['profile_id']}:"
                        f"{values['job_key']}:"
                        f"{payload['collection_transition_sha256']}"
                    )
                    or payload["prior_dossier_hash"]
                    != refresh_current_dossier_hash
                    or not isinstance(refresh_current_dossier_json, str)
                    or hashlib.sha256(
                        refresh_current_dossier_json.encode("utf-8")
                    ).hexdigest()
                    != refresh_current_dossier_hash
                    or payload["refresh_bridge_sha256"]
                    != values["refresh_bridge_sha256"]
                    or research_refresh_bridge_sha256(
                        event_type=str(refresh_event_type),
                        actor_kind=str(refresh_actor_kind),
                        idempotency_key=str(refresh_event_idempotency_key),
                        payload=payload,
                    )
                    != values["refresh_bridge_sha256"]
                ):
                    raise ValueError("research refresh event differs from promotion")
                refresh_values.update(
                    refresh_event_idempotency_key=refresh_event_idempotency_key,
                    refresh_receipt_sha256=payload["collection_receipt_sha256"],
                    refresh_receipt_file_sha256=payload[
                        "collection_receipt_file_sha256"
                    ],
                    refresh_transition_sha256=payload[
                        "collection_transition_sha256"
                    ],
                    refresh_id=payload["collection_refresh_id"],
                    refresh_context_sha256=payload["collection_context_sha256"],
                    refresh_operation_id=payload["collection_operation_id"],
                    refresh_legacy_content_sha256=payload[
                        "old_collector_content_sha256"
                    ],
                    refresh_canonical_content_sha256=payload[
                        "old_canonical_content_sha256"
                    ],
                    refresh_raw_object_sha256=payload["new_raw_object_sha256"],
                    refresh_fetched_at=payload["new_fetched_at"],
                    refresh_promotion_receipt_sha256=payload[
                        "promotion_receipt_sha256"
                    ],
                    refresh_prior_dossier_sha256=payload["prior_dossier_hash"],
                )
            values["vacancy_snapshot_sha256"] = _vacancy_snapshot_sha256(values)
            values.update(refresh_values)
            return ResearchTask(**values)

    def preview_refresh_research(
        self, profile_id: str, job_key: str
    ) -> ResearchTask | None:
        """Resolve one exact available refresh task without changing its lease."""

        return self.claim_research(
            "selector-review-preview",
            profile_id=profile_id,
            job_key=job_key,
            require_refresh_bridge=True,
            _preview_without_lease=True,
        )

    def _has_current_v2_evidence(self, row: sqlite3.Row) -> bool:
        try:
            document = json.loads(row["dossier_json"])
            expected_snapshot = _vacancy_snapshot_sha256(dict(row))
            if (
                not isinstance(document, dict)
                or document.get("schema_version")
                != "market-aligner.employer-dossier.v2"
                or hashlib.sha256(row["dossier_json"].encode("utf-8")).hexdigest()
                != row["dossier_hash"]
                or row["evidence_dossier_hash"] != row["dossier_hash"]
                or row["evidence_schema_version"]
                != "market-aligner.research-store-binding.v2"
                or row["evidence_source_content_sha256"]
                != row["source_content_sha256"]
                or row["evidence_vacancy_snapshot_sha256"] != expected_snapshot
                or row["evidence_promotion_receipt_sha256"]
                != row["promotion_receipt_sha256"]
                or document.get("source_content_sha256")
                != row["source_content_sha256"]
                or document.get("vacancy_snapshot_sha256") != expected_snapshot
                or document.get("promotion_receipt_sha256")
                != row["promotion_receipt_sha256"]
                or document.get("canonical_vacancy_object_sha256")
                != row["canonical_vacancy_object_sha256"]
            ):
                return False
            binding = ResearchEvidenceBinding(
                row["evidence_dossier_hash"],
                row["evidence_source_content_sha256"],
                row["evidence_vacancy_snapshot_sha256"],
                row["evidence_promotion_receipt_sha256"],
                row["canonical_vacancy_object_sha256"],
                row["semantic_receipt_sha256"],
                row["receipt_file_sha256"],
                row["archive_root_identity"],
                row["archive_root_policy_sha256"],
                row["receipt_relative_path"],
                row["evidence_schema_version"],
            )
            binding.validate()
            root = (self.data_home / binding.archive_root_identity).resolve()
            if self.data_home not in root.parents or root.is_symlink():
                return False
            receipt_path = root / binding.receipt_relative_path
            object_path = root / "objects" / binding.canonical_vacancy_object_sha256
            if (
                receipt_path.is_symlink()
                or object_path.is_symlink()
                or not receipt_path.is_file()
                or not object_path.is_file()
            ):
                return False
            receipt_bytes = receipt_path.read_bytes()
            object_bytes = object_path.read_bytes()
            if (
                hashlib.sha256(receipt_bytes).hexdigest()
                != binding.receipt_file_sha256
                or hashlib.sha256(object_bytes).hexdigest()
                != binding.canonical_vacancy_object_sha256
            ):
                return False
            receipt = json.loads(receipt_bytes)
            semantic_body = dict(receipt)
            semantic = semantic_body.pop("semantic_receipt_sha256", None)
            if (
                receipt_bytes
                != json.dumps(
                    receipt,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                or semantic != binding.semantic_receipt_sha256
                or hashlib.sha256(
                    json.dumps(
                        semantic_body,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
                != semantic
                or receipt.get("schema_version")
                != "market-aligner.public-research-materialization.v2"
                or receipt.get("dossier_sha256") != row["dossier_hash"]
            ):
                return False
            citations = document.get("citations")
            claims = document.get("claims")
            if (
                not isinstance(citations, list)
                or len(citations) != 1
                or citations[0].get("source_kind") != "canonical_vacancy"
                or citations[0].get("content_sha256")
                != binding.canonical_vacancy_object_sha256
                or not isinstance(claims, list)
                or not claims
            ):
                return False
            citation_id = citations[0].get("citation_id")
            for claim in claims:
                supports = claim.get("supports")
                if not isinstance(supports, list) or not supports:
                    return False
                for support in supports:
                    match = _BYTE_SELECTOR.fullmatch(str(support.get("selector", "")))
                    if match is None or support.get("citation_id") != citation_id:
                        return False
                    start, end = int(match.group(1)), int(match.group(2))
                    selected = object_bytes[start:end]
                    if (
                        end > len(object_bytes)
                        or hashlib.sha256(selected).hexdigest()
                        != support.get("excerpt_sha256")
                        or selected.decode("utf-8") != support.get("excerpt")
                        or " ".join(str(claim.get("claim", "")).split())
                        != " ".join(str(support.get("excerpt", "")).split())
                    ):
                        return False
            return True
        except (KeyError, TypeError, ValueError, OSError, UnicodeError, json.JSONDecodeError):
            return False

    def refresh_completed_research_if_needed(
        self,
        profile_id: str,
        job_key: str,
        *,
        collection_refresh_receipt_path: str | Path | None = None,
        collection_config_path: str | Path | None = None,
    ) -> bool:
        """Requeue invalid v2 evidence or admit one exact unchanged refresh."""

        validate_profile_id(profile_id)
        if (collection_refresh_receipt_path is None) != (collection_config_path is None):
            raise ValueError(
                "collection refresh admission requires both receipt and bound config"
        )
        if collection_refresh_receipt_path is not None:
            assert collection_config_path is not None
            return self._requeue_from_unchanged_collection_refresh(
                profile_id,
                job_key,
                receipt_path=Path(collection_refresh_receipt_path),
                config_path=Path(collection_config_path),
            )
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT q.status,q.job_key,a.title,a.company,a.url,
                          p.source_content_sha256,
                          p.receipt_sha256 AS promotion_receipt_sha256,
                          d.dossier_json,d.dossier_hash,
                          e.dossier_hash AS evidence_dossier_hash,
                          e.source_content_sha256 AS evidence_source_content_sha256,
                          e.vacancy_snapshot_sha256 AS evidence_vacancy_snapshot_sha256,
                          e.promotion_receipt_sha256 AS evidence_promotion_receipt_sha256,
                          e.canonical_vacancy_object_sha256,
                          e.semantic_receipt_sha256,e.receipt_file_sha256,
                          e.archive_root_identity,e.archive_root_policy_sha256,
                          e.receipt_relative_path,
                          e.schema_version AS evidence_schema_version
                   FROM employer_research_queue q JOIN assessments a
                     ON a.profile_id=q.profile_id AND a.job_key=q.job_key
                   LEFT JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   LEFT JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   LEFT JOIN employer_research_evidence e
                     ON e.profile_id=q.profile_id AND e.job_key=q.job_key
                   WHERE q.profile_id=? AND q.job_key=?""",
                (profile_id, job_key),
            ).fetchone()
            if row is None:
                raise KeyError((profile_id, job_key))
            if row["status"] != "completed" or self._has_current_v2_evidence(row):
                return False
            connection.execute(
                """UPDATE employer_research_queue SET status='queued',available_at=CURRENT_TIMESTAMP,
                     lease_owner=NULL,lease_until=NULL,last_error=?,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=?""",
                ("completed research lacks valid current v2 evidence", profile_id, job_key),
            )
            connection.execute(
                "DELETE FROM employer_research_evidence WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            )
            connection.execute(
                """UPDATE assessments SET state='employer_research_queued',
                     updated_at=CURRENT_TIMESTAMP WHERE profile_id=? AND job_key=?""",
                (profile_id, job_key),
            )
            connection.execute(
                """INSERT OR IGNORE INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    "employer_research_v2_refresh_queued",
                    "deterministic",
                    json.dumps(
                        {
                            "prior_dossier_hash": row["dossier_hash"],
                            "promotion_receipt_sha256": row[
                                "promotion_receipt_sha256"
                            ],
                            "reason": "missing_or_invalid_current_v2_evidence",
                        },
                        sort_keys=True,
                    ),
                    (
                        f"research-v2-refresh:{profile_id}:{job_key}:"
                        f"{row['dossier_hash']}:{row['promotion_receipt_sha256']}"
                    ),
                ),
            )
            return True

    def _has_current_v2_refresh_chain(
        self, row: sqlite3.Row, *, collector_content_sha256: str
    ) -> bool:
        """Verify that current v2 evidence terminates at the prior refresh event."""

        if row["status"] != "completed" or not self._has_current_v2_evidence(row):
            return False
        try:
            payload = json.loads(str(row["prior_refresh_payload_json"]))
            prior_event_id = row["prior_refresh_event_id"]
            event_key = (
                f"research-collection-refresh:{row['profile_id']}:{row['job_key']}:"
                f"{payload.get('collection_transition_sha256')}"
            )
            root = (self.data_home / row["archive_root_identity"]).resolve()
            object_bytes = (
                root / "objects" / row["canonical_vacancy_object_sha256"]
            ).read_bytes()
            envelope = json.loads(object_bytes)
            if (
                not isinstance(payload, dict)
                or not isinstance(envelope, dict)
                or hashlib.sha256(object_bytes).hexdigest()
                != row["canonical_vacancy_object_sha256"]
                or object_bytes
                != json.dumps(
                    envelope,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                or row["prior_refresh_event_type"]
                != "employer_research_collection_refresh_queued"
                or row["prior_refresh_actor_kind"] != "deterministic"
                or row["prior_refresh_idempotency_key"] != event_key
                or payload.get("refresh_bridge_sha256")
                != row["prior_refresh_bridge_sha256"]
                or research_refresh_bridge_sha256(
                    event_type=str(row["prior_refresh_event_type"]),
                    actor_kind=str(row["prior_refresh_actor_kind"]),
                    idempotency_key=str(row["prior_refresh_idempotency_key"]),
                    payload=payload,
                )
                != row["prior_refresh_bridge_sha256"]
                or payload.get("source_content_sha256") != row["source_content_sha256"]
                or payload.get("promotion_receipt_sha256")
                != row["promotion_receipt_sha256"]
                or not research_refresh_preserves_source_authority(
                    source_content_sha256=row["source_content_sha256"],
                    old_collector_content_sha256=payload.get(
                        "old_collector_content_sha256"
                    ),
                    old_canonical_content_sha256=payload.get(
                        "old_canonical_content_sha256"
                    ),
                )
                or payload.get("old_canonical_content_sha256")
                != collector_content_sha256
                or envelope.get("schema_version")
                != "market-aligner.canonical-collector-vacancy.v2"
                or envelope.get("authority_source_content_sha256")
                != row["source_content_sha256"]
                or envelope.get("canonical_current_content_sha256")
                != collector_content_sha256
                or envelope.get("collection_refresh_event_id") != prior_event_id
                or envelope.get("collection_refresh_context_sha256")
                != payload.get("collection_context_sha256")
                or envelope.get("collection_refresh_operation_id")
                != payload.get("collection_operation_id")
                or envelope.get("collection_refresh_receipt_file_sha256")
                != payload.get("collection_receipt_file_sha256")
                or envelope.get("collection_refresh_receipt_sha256")
                != payload.get("collection_receipt_sha256")
                or envelope.get("collection_refresh_id")
                != payload.get("collection_refresh_id")
                or envelope.get("collection_refresh_transition_sha256")
                != payload.get("collection_transition_sha256")
                or envelope.get("collection_refresh_raw_object_sha256")
                != payload.get("new_raw_object_sha256")
                or envelope.get("fetched_at") != payload.get("new_fetched_at")
                or envelope.get("job_key") != row["job_key"]
                or envelope.get("promotion_receipt_sha256")
                != row["promotion_receipt_sha256"]
            ):
                return False
            return True
        except (
            KeyError,
            TypeError,
            ValueError,
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            return False

    def _requeue_from_unchanged_collection_refresh(
        self,
        profile_id: str,
        job_key: str,
        *,
        receipt_path: Path,
        config_path: Path,
    ) -> bool:
        """Atomically bind a locked collector snapshot to the research requeue."""

        resolved_collector = JobDatabase.resolve_vacancy_refresh_collector(
            self.data_home, receipt_path, config_path
        )
        collector_database = resolved_collector.database
        expected_collector = resolved_collector.path
        supplied_collector = collector_database.path.absolute()
        if (
            collector_database.data_home != self.data_home.absolute()
            or supplied_collector != expected_collector
            or self.data_home not in supplied_collector.parents
        ):
            raise ValueError("collector database is outside the assessment data home")
        connection = self.connect()
        try:
            connection.execute("ATTACH DATABASE ? AS collector", (str(expected_collector),))
            attached = {
                str(row[1]): Path(str(row[2])).absolute()
                for row in connection.execute("PRAGMA database_list")
            }
            if attached.get("collector") != expected_collector:
                raise ValueError("attached collector database identity differs")
            # BEGIN IMMEDIATE reserves both the assessment and attached collector
            # databases.  No collector writer can change the row between exact
            # verification and the assessment-side commit.
            connection.execute("BEGIN IMMEDIATE")
            resolved_collector.verify_open_connection(
                connection, schema="collector"
            )
            verified = collector_database.verify_vacancy_refresh_receipt(
                receipt_path,
                job_key=job_key,
                connection=connection,
                schema="collector",
            )
            row = connection.execute(
                """SELECT q.status,q.profile_id,q.job_key,q.refresh_event_id
                          AS prior_refresh_event_id,q.refresh_bridge_sha256
                          AS prior_refresh_bridge_sha256,
                          a.state,a.title,a.company,a.url,
                          p.source_content_sha256,
                          p.receipt_sha256 AS promotion_receipt_sha256,
                          d.dossier_json,d.dossier_hash,
                          pe.event_type AS prior_refresh_event_type,
                          pe.actor_kind AS prior_refresh_actor_kind,
                          pe.payload_json AS prior_refresh_payload_json,
                          pe.idempotency_key AS prior_refresh_idempotency_key,
                          e.dossier_hash AS evidence_dossier_hash,
                          e.source_content_sha256 AS evidence_source_content_sha256,
                          e.vacancy_snapshot_sha256
                          AS evidence_vacancy_snapshot_sha256,
                          e.promotion_receipt_sha256
                          AS evidence_promotion_receipt_sha256,
                          e.canonical_vacancy_object_sha256,
                          e.semantic_receipt_sha256,e.receipt_file_sha256,
                          e.archive_root_identity,e.archive_root_policy_sha256,
                          e.receipt_relative_path,
                          e.schema_version AS evidence_schema_version
                   FROM employer_research_queue q JOIN assessments a
                     ON a.profile_id=q.profile_id AND a.job_key=q.job_key
                   LEFT JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   LEFT JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   LEFT JOIN employer_research_evidence e
                     ON e.profile_id=q.profile_id AND e.job_key=q.job_key
                   LEFT JOIN assessment_events pe
                     ON pe.id=q.refresh_event_id
                    AND pe.profile_id=q.profile_id AND pe.job_key=q.job_key
                   WHERE q.profile_id=? AND q.job_key=?""",
                (profile_id, job_key),
            ).fetchone()
            if row is None:
                raise KeyError((profile_id, job_key))
            if (
                verified.changed
                or verified.old_canonical_content_sha256
                != verified.new_content_sha256
            ):
                raise ValueError(
                    "changed vacancy content requires assessment promotion supersession"
                )
            promotion_source = row["source_content_sha256"]
            if promotion_source is None:
                raise ValueError("refresh lacks a current assessment promotion")
            event_key = (
                f"research-collection-refresh:{profile_id}:{job_key}:"
                f"{verified.transition_sha256}"
            )
            existing_event = connection.execute(
                """SELECT id,event_type,actor_kind,payload_json
                   FROM assessment_events WHERE idempotency_key=?""",
                (event_key,),
            ).fetchone()
            if (
                existing_event is None
                and promotion_source != verified.old_content_sha256
                and not self._has_current_v2_refresh_chain(
                    row, collector_content_sha256=verified.old_content_sha256
                )
            ):
                raise ValueError(
                    "refresh content lacks current assessment promotion ancestry"
                )
            payload = {
                "collection_context_sha256": verified.context_sha256,
                "collection_operation_id": verified.operation_id,
                "collection_receipt_file_sha256": verified.receipt_file_sha256,
                "collection_receipt_sha256": verified.receipt_sha256,
                "collection_refresh_id": verified.refresh_id,
                "collection_transition_sha256": verified.transition_sha256,
                "new_fetched_at": verified.new_fetched_at,
                "new_raw_object_sha256": verified.new_raw_object_sha256,
                "old_canonical_content_sha256": (
                    verified.old_canonical_content_sha256
                ),
                "old_collector_content_sha256": verified.old_content_sha256,
                "prior_dossier_hash": row["dossier_hash"],
                "promotion_receipt_sha256": row["promotion_receipt_sha256"],
                "source_content_sha256": promotion_source,
            }
            bridge_sha256 = research_refresh_bridge_sha256(
                event_type="employer_research_collection_refresh_queued",
                actor_kind="deterministic",
                idempotency_key=event_key,
                payload=payload,
            )
            payload["refresh_bridge_sha256"] = bridge_sha256
            if existing_event is not None:
                queue_event = connection.execute(
                    """SELECT refresh_event_id FROM employer_research_queue
                       WHERE profile_id=? AND job_key=?""",
                    (profile_id, job_key),
                ).fetchone()
                try:
                    existing_payload = json.loads(existing_event["payload_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        "collection refresh replay event is invalid"
                    ) from exc
                prior_hash = (
                    existing_payload.get("prior_dossier_hash")
                    if isinstance(existing_payload, dict)
                    else None
                )
                replay_payload = dict(payload)
                replay_payload["prior_dossier_hash"] = prior_hash
                replay_payload["refresh_bridge_sha256"] = (
                    research_refresh_bridge_sha256(
                        event_type=(
                            "employer_research_collection_refresh_queued"
                        ),
                        actor_kind="deterministic",
                        idempotency_key=event_key,
                        payload=replay_payload,
                    )
                )
                if (
                    existing_event["event_type"]
                    != "employer_research_collection_refresh_queued"
                    or existing_event["actor_kind"] != "deterministic"
                    or not isinstance(prior_hash, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", prior_hash)
                    or existing_event["payload_json"]
                    != json.dumps(
                        replay_payload, sort_keys=True, separators=(",", ":")
                    )
                    or queue_event is None
                    or queue_event["refresh_event_id"] != existing_event["id"]
                ):
                    raise ValueError("collection refresh replay binding differs")
                connection.rollback()
                return False
            if row["status"] != "completed":
                raise ValueError(
                    "collection refresh can requeue only completed employer research"
                )

            cursor = connection.execute(
                """INSERT INTO assessment_events(
                     profile_id,job_key,event_type,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    profile_id,
                    job_key,
                    "employer_research_collection_refresh_queued",
                    "deterministic",
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    event_key,
                ),
            )
            refresh_event_id = int(cursor.lastrowid)
            updated = connection.execute(
                """UPDATE employer_research_queue SET status='queued',
                     available_at=CURRENT_TIMESTAMP,lease_owner=NULL,lease_until=NULL,
                     last_error=?,refresh_event_id=?,refresh_bridge_sha256=?,
                     updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND job_key=? AND status='completed'""",
                (
                    "canonical vacancy fetched_at changed under unchanged content",
                    refresh_event_id,
                    bridge_sha256,
                    profile_id,
                    job_key,
                ),
            )
            if updated.rowcount != 1:
                raise ValueError("research refresh queue transition raced")
            connection.execute(
                "DELETE FROM employer_research_evidence WHERE profile_id=? AND job_key=?",
                (profile_id, job_key),
            )
            connection.execute(
                """UPDATE assessments SET state='employer_research_queued',
                     updated_at=CURRENT_TIMESTAMP WHERE profile_id=? AND job_key=?""",
                (profile_id, job_key),
            )
            # A second call through the same canonical verifier occurs while the
            # collector reservation is still held and before assessment commit.
            revalidated = collector_database.verify_vacancy_refresh_receipt(
                receipt_path,
                job_key=job_key,
                connection=connection,
                schema="collector",
            )
            if revalidated != verified:
                raise ValueError("collector refresh changed during assessment admission")
            resolved_collector.verify_open_connection(
                connection, schema="collector"
            )
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete_research(
        self,
        dossier: ResearchDossier,
        worker_id: str,
        evidence: ResearchEvidenceBinding | None = None,
    ) -> str:
        dossier.validate()
        payload = json.dumps(asdict(dossier), ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        receipt_bytes: bytes | None = None
        if dossier.schema_version == "market-aligner.employer-dossier.v2":
            if evidence is None:
                raise ValueError("v2 research completion requires archive evidence")
            evidence.validate()
            if (
                evidence.dossier_sha256 != digest
                or evidence.source_content_sha256 != dossier.source_content_sha256
                or evidence.vacancy_snapshot_sha256 != dossier.vacancy_snapshot_sha256
                or evidence.promotion_receipt_sha256 != dossier.promotion_receipt_sha256
                or evidence.canonical_vacancy_object_sha256
                != dossier.canonical_vacancy_object_sha256
            ):
                raise ValueError("research archive evidence differs from dossier bindings")
            if (
                evidence.archive_root_policy_sha256
                != RESEARCH_ARCHIVE_ROOT_POLICY_SHA256
            ):
                raise ValueError("research archive root policy differs")
            root = (self.data_home / evidence.archive_root_identity).resolve()
            if self.data_home not in root.parents:
                raise ValueError("research archive root escapes protected data home")
            receipt_path = root / evidence.receipt_relative_path
            if root.is_symlink() or receipt_path.is_symlink() or not receipt_path.is_file():
                raise ValueError("research archive receipt path is unsafe")
            receipt_bytes = receipt_path.read_bytes()
            if hashlib.sha256(receipt_bytes).hexdigest() != evidence.receipt_file_sha256:
                raise ValueError("research archive exact receipt file differs")
            try:
                receipt = json.loads(receipt_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("research archive receipt is invalid JSON") from exc
            body = dict(receipt) if isinstance(receipt, dict) else {}
            semantic = body.pop("semantic_receipt_sha256", None)
            semantic_digest = hashlib.sha256(
                json.dumps(
                    body,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            if (
                receipt_bytes
                != json.dumps(
                    receipt,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                or semantic != evidence.semantic_receipt_sha256
                or semantic_digest != semantic
                or receipt.get("schema_version")
                != "market-aligner.public-research-materialization.v2"
                or receipt.get("dossier_sha256") != digest
                or receipt.get("source_content_sha256")
                != dossier.source_content_sha256
                or receipt.get("vacancy_snapshot_sha256")
                != dossier.vacancy_snapshot_sha256
                or receipt.get("promotion_receipt_sha256")
                != dossier.promotion_receipt_sha256
                or receipt.get("canonical_vacancy_object_sha256")
                != dossier.canonical_vacancy_object_sha256
            ):
                raise ValueError("research archive semantic receipt differs")
        elif evidence is not None:
            raise ValueError("legacy dossier cannot claim v2 archive evidence")
        with self.transaction() as connection:
            lease = connection.execute(
                """SELECT q.lease_owner,q.status,q.refresh_event_id,
                          q.refresh_bridge_sha256,
                          e.event_type,e.actor_kind,e.payload_json,e.idempotency_key,
                          d.dossier_hash AS current_dossier_hash,
                          d.dossier_json AS current_dossier_json,
                          p.source_content_sha256,
                          p.receipt_sha256 AS current_promotion_receipt_sha256
                   FROM employer_research_queue q
                   LEFT JOIN assessment_events e
                     ON e.id=q.refresh_event_id
                    AND e.profile_id=q.profile_id AND e.job_key=q.job_key
                   LEFT JOIN employer_dossiers d
                     ON d.profile_id=q.profile_id AND d.job_key=q.job_key
                   LEFT JOIN assessment_promotions p
                     ON p.profile_id=q.profile_id AND p.job_key=q.job_key
                   WHERE q.profile_id=? AND q.job_key=?""",
                (dossier.profile_id, dossier.job_key),
            ).fetchone()
            if lease is None or lease["status"] != "leased" or lease["lease_owner"] != worker_id:
                raise RuntimeError("research completion requires the active lease")
            if lease["refresh_event_id"] is not None:
                try:
                    refresh_payload = json.loads(str(lease["payload_json"]))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        "research completion refresh event is invalid"
                    ) from exc
                if (
                    lease["event_type"]
                    != "employer_research_collection_refresh_queued"
                    or lease["actor_kind"] != "deterministic"
                    or not isinstance(refresh_payload, dict)
                    or lease["idempotency_key"]
                    != (
                        f"research-collection-refresh:{dossier.profile_id}:"
                        f"{dossier.job_key}:"
                        f"{refresh_payload.get('collection_transition_sha256')}"
                    )
                    or refresh_payload.get("prior_dossier_hash")
                    != lease["current_dossier_hash"]
                    or not isinstance(lease["current_dossier_json"], str)
                    or hashlib.sha256(
                        lease["current_dossier_json"].encode("utf-8")
                    ).hexdigest()
                    != lease["current_dossier_hash"]
                    or refresh_payload.get("source_content_sha256")
                    != dossier.source_content_sha256
                    or not research_refresh_preserves_source_authority(
                        source_content_sha256=lease["source_content_sha256"],
                        old_collector_content_sha256=refresh_payload.get(
                            "old_collector_content_sha256"
                        ),
                        old_canonical_content_sha256=refresh_payload.get(
                            "old_canonical_content_sha256"
                        ),
                    )
                    or refresh_payload.get("promotion_receipt_sha256")
                    != dossier.promotion_receipt_sha256
                    or lease["current_promotion_receipt_sha256"]
                    != dossier.promotion_receipt_sha256
                    or refresh_payload.get("refresh_bridge_sha256")
                    != lease["refresh_bridge_sha256"]
                    or research_refresh_bridge_sha256(
                        event_type=str(lease["event_type"]),
                        actor_kind=str(lease["actor_kind"]),
                        idempotency_key=str(lease["idempotency_key"]),
                        payload=refresh_payload,
                    )
                    != lease["refresh_bridge_sha256"]
                ):
                    raise ValueError(
                        "research completion refresh authority differs"
                    )
            connection.execute(
                """INSERT INTO employer_dossiers(profile_id,job_key,dossier_json,dossier_hash,worker_id)
                   VALUES(?,?,?,?,?) ON CONFLICT(profile_id,job_key) DO UPDATE SET
                   dossier_json=excluded.dossier_json,dossier_hash=excluded.dossier_hash,
                   worker_id=excluded.worker_id,created_at=CURRENT_TIMESTAMP""",
                (dossier.profile_id, dossier.job_key, payload, digest, worker_id),
            )
            if evidence is not None:
                connection.execute(
                    """INSERT INTO employer_research_evidence(
                         profile_id,job_key,dossier_hash,source_content_sha256,
                         vacancy_snapshot_sha256,promotion_receipt_sha256,
                         canonical_vacancy_object_sha256,
                         semantic_receipt_sha256,receipt_file_sha256,
                         archive_root_identity,archive_root_policy_sha256,
                         receipt_relative_path,schema_version
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(profile_id,job_key)
                       DO UPDATE SET dossier_hash=excluded.dossier_hash,
                         source_content_sha256=excluded.source_content_sha256,
                         vacancy_snapshot_sha256=excluded.vacancy_snapshot_sha256,
                         promotion_receipt_sha256=excluded.promotion_receipt_sha256,
                         canonical_vacancy_object_sha256=excluded.canonical_vacancy_object_sha256,
                         semantic_receipt_sha256=excluded.semantic_receipt_sha256,
                         receipt_file_sha256=excluded.receipt_file_sha256,
                         archive_root_identity=excluded.archive_root_identity,
                         archive_root_policy_sha256=excluded.archive_root_policy_sha256,
                         receipt_relative_path=excluded.receipt_relative_path,
                         schema_version=excluded.schema_version,
                         created_at=CURRENT_TIMESTAMP""",
                    (
                        dossier.profile_id,
                        dossier.job_key,
                        digest,
                        evidence.source_content_sha256,
                        evidence.vacancy_snapshot_sha256,
                        evidence.promotion_receipt_sha256,
                        evidence.canonical_vacancy_object_sha256,
                        evidence.semantic_receipt_sha256,
                        evidence.receipt_file_sha256,
                        evidence.archive_root_identity,
                        evidence.archive_root_policy_sha256,
                        evidence.receipt_relative_path,
                        evidence.schema_version,
                    ),
                )
            else:
                connection.execute(
                    "DELETE FROM employer_research_evidence WHERE profile_id=? AND job_key=?",
                    (dossier.profile_id, dossier.job_key),
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

    def research_evidence(self, profile_id: str, job_key: str) -> sqlite3.Row:
        """Return a v2 dossier and its reconciled archive binding only."""

        with self.connection() as connection:
            row = connection.execute(
                """SELECT d.dossier_json,d.dossier_hash,e.*
                   FROM employer_dossiers d JOIN employer_research_evidence e
                     ON e.profile_id=d.profile_id AND e.job_key=d.job_key
                   WHERE d.profile_id=? AND d.job_key=?
                     AND d.dossier_hash=e.dossier_hash""",
                (profile_id, job_key),
            ).fetchone()
        if row is None:
            raise KeyError((profile_id, job_key))
        return row

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
