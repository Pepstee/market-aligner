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


_JAA_01_BASE_MIGRATIONS: tuple[Migration, ...] = (
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


_JAA_02_BASE_MIGRATIONS: tuple[Migration, ...] = _JAA_01_BASE_MIGRATIONS + (
    Migration(
        2,
        "jaa_02_candidate_fact_evidence_claim_graph",
        (
            """CREATE TABLE candidate_provenance(
                 provenance_id TEXT PRIMARY KEY,
                 source_identity TEXT NOT NULL CHECK(length(trim(source_identity)) > 0),
                 source_kind TEXT NOT NULL,
                 source_hash TEXT NOT NULL CHECK(length(source_hash)=64),
                 source_locator TEXT,
                 observed_at TEXT NOT NULL,
                 imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 metadata_json TEXT NOT NULL DEFAULT '{}'
               )""",
            """CREATE TABLE candidate_records(
                 record_id TEXT NOT NULL,
                 version INTEGER NOT NULL CHECK(version > 0),
                 record_kind TEXT NOT NULL CHECK(record_kind IN
                   ('fact','constraint','preference','work_right')),
                 subject TEXT NOT NULL,
                 value_json TEXT NOT NULL,
                 epistemic_state TEXT NOT NULL CHECK(epistemic_state IN
                   ('fact','evidence','inference','unknown','expired','disputed','unverified')),
                 jurisdiction TEXT,
                 contract_type TEXT,
                 valid_from TEXT,
                 valid_until TEXT,
                 supersedes_version INTEGER,
                 provenance_id TEXT NOT NULL REFERENCES candidate_provenance(provenance_id),
                 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY(record_id,version),
                 FOREIGN KEY(record_id,supersedes_version)
                   REFERENCES candidate_records(record_id,version)
               )""",
            """CREATE INDEX candidate_records_release_lookup ON candidate_records(
                 record_kind,subject,epistemic_state,jurisdiction,contract_type,valid_until)""",
            """CREATE TABLE candidate_evidence(
                 evidence_id TEXT NOT NULL,
                 version INTEGER NOT NULL CHECK(version > 0),
                 evidence_kind TEXT NOT NULL,
                 statement TEXT NOT NULL CHECK(length(trim(statement)) > 0),
                 source_identity TEXT NOT NULL CHECK(length(trim(source_identity)) > 0),
                 epistemic_state TEXT NOT NULL CHECK(epistemic_state IN
                   ('fact','evidence','inference','unknown','expired','disputed','unverified')),
                 approval_state TEXT NOT NULL DEFAULT 'pending' CHECK(approval_state IN
                   ('pending','approved','rejected','quarantined')),
                 negative INTEGER NOT NULL DEFAULT 0 CHECK(negative IN (0,1)),
                 confidence REAL CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
                 valid_until TEXT,
                 content_hash TEXT NOT NULL CHECK(length(content_hash)=64),
                 provenance_id TEXT NOT NULL REFERENCES candidate_provenance(provenance_id),
                 discovered_by TEXT,
                 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY(evidence_id,version)
               )""",
            """CREATE TABLE candidate_claims(
                 claim_id TEXT NOT NULL,
                 version INTEGER NOT NULL CHECK(version > 0),
                 claim_type TEXT NOT NULL,
                 statement TEXT NOT NULL CHECK(length(trim(statement)) > 0),
                 epistemic_state TEXT NOT NULL CHECK(epistemic_state IN
                   ('fact','evidence','inference','unknown','expired','disputed','unverified')),
                 approval_state TEXT NOT NULL DEFAULT 'pending' CHECK(approval_state IN
                   ('pending','approved','rejected','quarantined')),
                 valid_until TEXT,
                 provenance_id TEXT NOT NULL REFERENCES candidate_provenance(provenance_id),
                 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY(claim_id,version)
               )""",
            """CREATE TABLE candidate_artefacts(
                 artefact_id TEXT NOT NULL,
                 version INTEGER NOT NULL CHECK(version > 0),
                 artefact_type TEXT NOT NULL,
                 source_identity TEXT NOT NULL,
                 content_hash TEXT NOT NULL CHECK(length(content_hash)=64),
                 provenance_id TEXT NOT NULL REFERENCES candidate_provenance(provenance_id),
                 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY(artefact_id,version)
               )""",
            """CREATE TABLE candidate_claim_edges(
                 edge_id TEXT PRIMARY KEY,
                 claim_id TEXT NOT NULL,
                 claim_version INTEGER NOT NULL,
                 edge_type TEXT NOT NULL CHECK(edge_type IN
                   ('supports','contradicts','derived_from','demonstrated_by','documented_in')),
                 evidence_id TEXT,
                 evidence_version INTEGER,
                 artefact_id TEXT,
                 artefact_version INTEGER,
                 provenance_id TEXT NOT NULL REFERENCES candidate_provenance(provenance_id),
                 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(claim_id,claim_version) REFERENCES candidate_claims(claim_id,version),
                 FOREIGN KEY(evidence_id,evidence_version)
                   REFERENCES candidate_evidence(evidence_id,version),
                 FOREIGN KEY(artefact_id,artefact_version)
                   REFERENCES candidate_artefacts(artefact_id,version),
                 CHECK((evidence_id IS NOT NULL AND evidence_version IS NOT NULL
                         AND artefact_id IS NULL AND artefact_version IS NULL)
                    OR (artefact_id IS NOT NULL AND artefact_version IS NOT NULL
                         AND evidence_id IS NULL AND evidence_version IS NULL))
               )""",
            """CREATE INDEX candidate_claim_edges_claim
                 ON candidate_claim_edges(claim_id,claim_version,edge_type)""",
            """CREATE TABLE candidate_verification_decisions(
                 decision_id TEXT PRIMARY KEY,
                 target_kind TEXT NOT NULL CHECK(target_kind IN ('record','evidence','claim')),
                 target_id TEXT NOT NULL,
                 target_version INTEGER NOT NULL,
                 decision TEXT NOT NULL CHECK(decision IN ('approved','rejected','abstained')),
                 verifier_kind TEXT NOT NULL CHECK(verifier_kind IN ('deterministic','configured','human')),
                 policy_id TEXT NOT NULL,
                 policy_version TEXT NOT NULL,
                 policy_hash TEXT NOT NULL CHECK(length(policy_hash)=64),
                 reason TEXT NOT NULL,
                 provenance_id TEXT NOT NULL REFERENCES candidate_provenance(provenance_id),
                 decided_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
               )""",
            """CREATE TABLE candidate_quarantine(
                 quarantine_id TEXT PRIMARY KEY,
                 target_kind TEXT NOT NULL,
                 target_id TEXT NOT NULL,
                 target_version INTEGER NOT NULL,
                 reason_code TEXT NOT NULL,
                 matched_pattern TEXT,
                 content_hash TEXT NOT NULL CHECK(length(content_hash)=64),
                 provenance_id TEXT NOT NULL REFERENCES candidate_provenance(provenance_id),
                 quarantined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 UNIQUE(target_kind,target_id,target_version)
               )""",
            """CREATE TRIGGER approved_claim_requires_approved_evidence_insert
                 BEFORE INSERT ON candidate_claims WHEN NEW.approval_state='approved'
                 BEGIN SELECT RAISE(ABORT,'approved claim requires approved evidence'); END""",
            """CREATE TRIGGER approved_evidence_requires_verification_insert
                 BEFORE INSERT ON candidate_evidence WHEN NEW.approval_state='approved'
                 BEGIN SELECT RAISE(ABORT,'approved evidence requires verification'); END""",
            """CREATE TRIGGER approved_evidence_requires_verification_update
                 BEFORE UPDATE OF approval_state ON candidate_evidence
                 WHEN NEW.approval_state='approved' AND OLD.approval_state<>'approved'
                   AND NOT EXISTS(
                     SELECT 1 FROM candidate_verification_decisions decision
                     WHERE decision.target_kind='evidence'
                       AND decision.target_id=NEW.evidence_id
                       AND decision.target_version=NEW.version
                       AND decision.decision='approved'
                   )
                 BEGIN SELECT RAISE(ABORT,'approved evidence requires verification'); END""",
            """CREATE TRIGGER approved_claim_requires_approved_evidence_update
                 BEFORE UPDATE OF approval_state ON candidate_claims
                 WHEN NEW.approval_state='approved' AND NOT EXISTS(
                   SELECT 1 FROM candidate_claim_edges edge
                   JOIN candidate_evidence evidence
                     ON evidence.evidence_id=edge.evidence_id
                    AND evidence.version=edge.evidence_version
                   WHERE edge.claim_id=NEW.claim_id AND edge.claim_version=NEW.version
                     AND edge.edge_type IN ('supports','demonstrated_by')
                     AND evidence.approval_state='approved'
                     AND evidence.epistemic_state IN ('fact','evidence')
                     AND (evidence.valid_until IS NULL OR evidence.valid_until >= date('now'))
                 ) BEGIN SELECT RAISE(ABORT,'approved claim requires approved evidence'); END""",
            """CREATE TRIGGER approved_evidence_cannot_be_degraded
                 BEFORE UPDATE OF approval_state,epistemic_state,valid_until ON candidate_evidence
                 WHEN EXISTS(
                   SELECT 1 FROM candidate_claim_edges edge
                   JOIN candidate_claims claim ON claim.claim_id=edge.claim_id
                     AND claim.version=edge.claim_version
                   WHERE edge.evidence_id=OLD.evidence_id AND edge.evidence_version=OLD.version
                     AND claim.approval_state='approved'
                 ) AND (NEW.approval_state<>'approved'
                   OR NEW.epistemic_state NOT IN ('fact','evidence')
                   OR (NEW.valid_until IS NOT NULL AND NEW.valid_until < date('now')))
                 BEGIN SELECT RAISE(ABORT,'evidence supports an approved claim'); END""",
        ),
    ),
)


_SCORE_SNAPSHOT_RECEIPT_MIGRATION = Migration(
    3,
    "jaa_01_immutable_score_snapshot_receipts",
    (
        """CREATE TABLE score_snapshot_receipts(
             receipt_id INTEGER PRIMARY KEY AUTOINCREMENT,
             event_id INTEGER NOT NULL UNIQUE
               REFERENCES pipeline_events(id) ON DELETE RESTRICT,
             job_key TEXT NOT NULL UNIQUE
               REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
             binding_json TEXT NOT NULL,
             binding_hash TEXT NOT NULL
               CHECK(length(binding_hash) = 64
                 AND binding_hash NOT GLOB '*[^0-9a-f]*'),
             idempotency_key TEXT NOT NULL UNIQUE
               CHECK(length(trim(idempotency_key)) > 0),
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
           )""",
        """CREATE TRIGGER score_snapshot_receipt_matches_event
             BEFORE INSERT ON score_snapshot_receipts
             BEGIN
               SELECT CASE WHEN NOT EXISTS(
                 SELECT 1 FROM pipeline_events AS event
                 WHERE event.id = NEW.event_id
                   AND event.job_key = NEW.job_key
                   AND event.event_type = 'score_snapshot_imported'
                   AND event.from_state IS NULL
                   AND event.to_state = 'scored'
                   AND event.actor_kind = 'deterministic'
                   AND event.payload_json = NEW.binding_json
                   AND event.idempotency_key = NEW.idempotency_key
               ) THEN RAISE(ABORT, 'score snapshot receipt does not match event') END;
             END""",
        """CREATE TRIGGER score_snapshot_receipt_immutable_update
             BEFORE UPDATE ON score_snapshot_receipts
             BEGIN
               SELECT RAISE(ABORT, 'score snapshot receipts are immutable');
             END""",
        """CREATE TRIGGER score_snapshot_receipt_immutable_delete
             BEFORE DELETE ON score_snapshot_receipts
             BEGIN
               SELECT RAISE(ABORT, 'score snapshot receipts are immutable');
             END""",
        """CREATE TABLE legacy_score_snapshot_cohort(
             event_id INTEGER PRIMARY KEY
               REFERENCES pipeline_events(id) ON DELETE RESTRICT,
             job_key TEXT NOT NULL UNIQUE
               REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
             board TEXT NOT NULL,
             job_id TEXT NOT NULL,
             url TEXT NOT NULL,
             title TEXT NOT NULL,
             company TEXT NOT NULL,
             fit_value,
             fit_storage_class TEXT NOT NULL,
             opportunity_value,
             opportunity_storage_class TEXT NOT NULL,
             final_score_value,
             final_score_storage_class TEXT NOT NULL,
             extraction_confidence_value,
             extraction_confidence_storage_class TEXT NOT NULL,
             payload_json TEXT NOT NULL,
             payload_hash TEXT NOT NULL
               CHECK(length(payload_hash) = 64
                 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
             binding_json TEXT NOT NULL,
             idempotency_key TEXT NOT NULL UNIQUE
               CHECK(length(trim(idempotency_key)) > 0),
             admitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
           )""",
        """INSERT INTO legacy_score_snapshot_cohort(
             event_id,job_key,board,job_id,url,title,company,
             fit_value,fit_storage_class,
             opportunity_value,opportunity_storage_class,
             final_score_value,final_score_storage_class,
             extraction_confidence_value,extraction_confidence_storage_class,
             payload_json,payload_hash,binding_json,idempotency_key
           )
           SELECT event.id,event.job_key,job.board,job.job_id,job.url,job.title,
                  job.company,job.fit,typeof(job.fit),job.opportunity,
                  typeof(job.opportunity),job.final_score,typeof(job.final_score),
                  job.extraction_confidence,typeof(job.extraction_confidence),
                  job.payload_json,job.payload_hash,event.payload_json,event.idempotency_key
           FROM pipeline_events AS event
           JOIN pipeline_jobs AS job ON job.job_key=event.job_key
           WHERE event.event_type='score_snapshot_imported'
             AND event.from_state IS NULL
             AND event.to_state='scored'
             AND event.actor_kind='deterministic'""",
        """CREATE TRIGGER legacy_score_snapshot_cohort_immutable_insert
             BEFORE INSERT ON legacy_score_snapshot_cohort
             BEGIN
               SELECT RAISE(ABORT, 'legacy score snapshot cohort is immutable');
             END""",
        """CREATE TRIGGER legacy_score_snapshot_cohort_immutable_update
             BEFORE UPDATE ON legacy_score_snapshot_cohort
             BEGIN
               SELECT RAISE(ABORT, 'legacy score snapshot cohort is immutable');
             END""",
        """CREATE TRIGGER legacy_score_snapshot_cohort_immutable_delete
             BEFORE DELETE ON legacy_score_snapshot_cohort
             BEGIN
               SELECT RAISE(ABORT, 'legacy score snapshot cohort is immutable');
             END""",
    ),
)


# Migration 2 was already allocated to JAA-02 before the independent JAA-01
# review required an immutable score-import receipt. Public sets remain ordered
# and checksummed while each slice applies only the schema it owns.
JAA_01_MIGRATIONS: tuple[Migration, ...] = (
    *_JAA_01_BASE_MIGRATIONS,
    _SCORE_SNAPSHOT_RECEIPT_MIGRATION,
)
JAA_02_MIGRATIONS: tuple[Migration, ...] = (
    *_JAA_02_BASE_MIGRATIONS,
    _SCORE_SNAPSHOT_RECEIPT_MIGRATION,
)


def apply_jaa_01_migrations(path: str | Path) -> tuple[int, ...]:
    """Apply the canonical JAA-01 schema to a configured SQLite database."""
    return MigrationRunner(path).apply(JAA_01_MIGRATIONS)


def apply_jaa_02_migrations(path: str | Path) -> tuple[int, ...]:
    """Apply JAA-01 and the forward-only canonical candidate graph schema."""
    return MigrationRunner(path).apply(JAA_02_MIGRATIONS)
