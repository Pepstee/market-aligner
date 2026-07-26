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


JAA00_LEGACY_BOUNDARY_JOB_COUNT = 462
JAA00_LEGACY_BOUNDARY_EVENT_COUNT = 924
JAA00_LEGACY_BOUNDARY_SHA256 = (
    "83c7b9f7531d3cae083db0781fb2a134b62b0a900d560112bcfce8f886dcbc47"
)
JAA01_INSTALLED_SCHEMA_SHA256 = frozenset({
    # A new JAA database created directly by migration 1 + migration 3.
    "ffa6c27b41d3fbeedfba02beb135da6ad70d75349569f5b73e76f282d38a4695",
    # The independently certified JAA-00 database after migration 1 + migration 3.
    # Its core table DDL is semantically identical but retains the original formatting.
    "a4404b143438e91926265aecfbaddb525254c3bec851cf142911a32a67473926",
})
_JAA01_SCHEMA_TABLES = (
    "pipeline_jobs",
    "pipeline_events",
    "lifecycle_transition_receipts",
    "score_snapshot_receipts",
    "legacy_score_snapshot_cohort",
    "legacy_opportunity_gate_cohort",
)
_JAA05_SCHEMA_TABLES = (
    "fit_assessment_runs",
    "vacancy_requirements",
    "evidence_match_assessments",
    "candidate_gaps",
    "improvement_tasks",
    "improvement_evidence_candidates",
)
JAA05_INSTALLED_SCHEMA_SHA256 = (
    "4631b04e9930e883529eebe3c4926392f877baa8ec316512f79b0e79515979e3"
)


def _boundary_digest(jobs: list[sqlite3.Row], events: list[sqlite3.Row]) -> str:
    document = json.dumps(
        {
            "jobs": [list(row) for row in jobs],
            "events": [list(row) for row in events],
        },
        ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"jaa00-legacy-boundary-v1\0" + document).hexdigest()


def legacy_boundary_digest(conn: sqlite3.Connection) -> str:
    jobs = conn.execute(
        """SELECT job_key,board,job_id,url,title,company,
                  fit,typeof(fit),opportunity,typeof(opportunity),
                  final_score,typeof(final_score),
                  extraction_confidence,typeof(extraction_confidence),
                  payload_json,payload_hash,state,opportunity_decision,
                  opportunity_reason,policy_hash
           FROM pipeline_jobs ORDER BY job_key"""
    ).fetchall()
    events = conn.execute(
        """SELECT id,job_key,event_type,from_state,to_state,actor_kind,
                  payload_json,idempotency_key
           FROM pipeline_events ORDER BY id"""
    ).fetchall()
    return _boundary_digest(jobs, events)


def legacy_cohort_boundary_digest(conn: sqlite3.Connection) -> str:
    """Reconstruct JAA-00 from immutable cohort membership, excluding later rows."""
    jobs = conn.execute(
        """SELECT job.job_key,job.board,job.job_id,job.url,job.title,job.company,
                  job.fit,typeof(job.fit),job.opportunity,typeof(job.opportunity),
                  job.final_score,typeof(job.final_score),
                  job.extraction_confidence,typeof(job.extraction_confidence),
                  job.payload_json,job.payload_hash,job.state,
                  job.opportunity_decision,job.opportunity_reason,job.policy_hash
           FROM pipeline_jobs AS job
           JOIN legacy_score_snapshot_cohort AS cohort
             ON cohort.job_key=job.job_key
           ORDER BY job.job_key"""
    ).fetchall()
    events = conn.execute(
        """SELECT event.id,event.job_key,event.event_type,event.from_state,
                  event.to_state,event.actor_kind,event.payload_json,event.idempotency_key
           FROM pipeline_events AS event
           WHERE event.id IN (
             SELECT event_id FROM legacy_score_snapshot_cohort
             UNION
             SELECT event_id FROM legacy_opportunity_gate_cohort
           )
           ORDER BY event.id"""
    ).fetchall()
    return _boundary_digest(jobs, events)


def jaa01_installed_schema_digest(conn: sqlite3.Connection) -> str:
    """Hash every installed schema object capable of affecting JAA-01 tables."""
    placeholders = ",".join("?" for _ in _JAA01_SCHEMA_TABLES)
    rows = conn.execute(
        f"""SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL
              AND (name='career_schema_migrations' OR tbl_name IN ({placeholders}))
            ORDER BY type,name""",
        _JAA01_SCHEMA_TABLES,
    ).fetchall()
    document = json.dumps(
        [list(row) for row in rows],
        ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"jaa01-installed-schema-v1\0" + document).hexdigest()


def verify_jaa01_installed_schema(conn: sqlite3.Connection) -> str:
    """Refuse missing, altered, or extra DDL despite plausible migration-ledger rows."""
    digest = jaa01_installed_schema_digest(conn)
    if digest not in JAA01_INSTALLED_SCHEMA_SHA256:
        raise RuntimeError(
            "installed JAA-01 schema or trigger set does not match the certified contract"
        )
    return digest


def jaa05_installed_schema_digest(conn: sqlite3.Connection) -> str:
    """Hash every table, index and trigger owned by the JAA-05 migration."""
    placeholders = ",".join("?" for _ in _JAA05_SCHEMA_TABLES)
    rows = conn.execute(
        f"""SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL AND tbl_name IN ({placeholders})
            ORDER BY type,name""",
        _JAA05_SCHEMA_TABLES,
    ).fetchall()
    document = json.dumps(
        [list(row) for row in rows],
        ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"jaa05-installed-schema-v1\0" + document).hexdigest()


def verify_jaa05_installed_schema(conn: sqlite3.Connection) -> str:
    digest = jaa05_installed_schema_digest(conn)
    if digest != JAA05_INSTALLED_SCHEMA_SHA256:
        raise RuntimeError(
            "installed JAA-05 schema or trigger set does not match the checked contract"
        )
    return digest


def _verify_jaa00_legacy_boundary(conn: sqlite3.Connection) -> None:
    """Admit legacy rows only from the exact independently certified JAA-00 ledger."""
    job_count = int(conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0])
    event_count = int(conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0])
    if job_count == 0 and event_count == 0:
        return
    if (
        job_count != JAA00_LEGACY_BOUNDARY_JOB_COUNT
        or event_count != JAA00_LEGACY_BOUNDARY_EVENT_COUNT
        or legacy_boundary_digest(conn) != JAA00_LEGACY_BOUNDARY_SHA256
    ):
        raise RuntimeError(
            "legacy lifecycle rows do not match the certified JAA-00 boundary"
        )


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
                    if (
                        migration.version == 3
                        and migration.name == "jaa_01_immutable_score_snapshot_receipts"
                    ):
                        _verify_jaa00_legacy_boundary(conn)
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
        """CREATE TABLE legacy_opportunity_gate_cohort(
             event_id INTEGER PRIMARY KEY
               REFERENCES pipeline_events(id) ON DELETE RESTRICT,
             job_key TEXT NOT NULL UNIQUE
               REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
             payload_hash TEXT NOT NULL
               CHECK(length(payload_hash) = 64
                 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
             from_state TEXT NOT NULL,
             to_state TEXT NOT NULL,
             actor_kind TEXT NOT NULL,
             binding_json TEXT NOT NULL,
             idempotency_key TEXT NOT NULL UNIQUE
               CHECK(length(trim(idempotency_key)) > 0),
             admitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
           )""",
        """INSERT INTO legacy_opportunity_gate_cohort(
             event_id,job_key,payload_hash,from_state,to_state,actor_kind,
             binding_json,idempotency_key
           )
           SELECT event.id,event.job_key,job.payload_hash,event.from_state,
                  event.to_state,event.actor_kind,event.payload_json,event.idempotency_key
           FROM pipeline_events AS event
           JOIN pipeline_jobs AS job ON job.job_key=event.job_key
           WHERE event.event_type='opportunity_gate_decided'""",
        """CREATE TRIGGER legacy_opportunity_gate_cohort_immutable_insert
             BEFORE INSERT ON legacy_opportunity_gate_cohort
             BEGIN
               SELECT RAISE(ABORT, 'legacy opportunity gate cohort is immutable');
             END""",
        """CREATE TRIGGER legacy_opportunity_gate_cohort_immutable_update
             BEFORE UPDATE ON legacy_opportunity_gate_cohort
             BEGIN
               SELECT RAISE(ABORT, 'legacy opportunity gate cohort is immutable');
             END""",
        """CREATE TRIGGER legacy_opportunity_gate_cohort_immutable_delete
             BEFORE DELETE ON legacy_opportunity_gate_cohort
             BEGIN
               SELECT RAISE(ABORT, 'legacy opportunity gate cohort is immutable');
             END""",
    ),
)


_JAA_05_EVIDENCE_MATCHING_MIGRATION = Migration(
    4,
    "jaa_05_evidence_matches_gaps_and_improvement_tasks",
    (
        """CREATE TABLE fit_assessment_runs(
             run_id TEXT PRIMARY KEY
               CHECK(length(run_id)=64 AND run_id NOT GLOB '*[^0-9a-f]*'),
             job_key TEXT NOT NULL
               REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
             as_of TEXT NOT NULL
               CHECK(date(as_of) IS NOT NULL AND date(as_of)=as_of),
             status TEXT NOT NULL
               CHECK(status IN ('ready','gap_identified','blocked')),
             requirements_hash TEXT NOT NULL
               CHECK(length(requirements_hash)=64
                 AND requirements_hash NOT GLOB '*[^0-9a-f]*'),
             candidate_profile_hash TEXT NOT NULL
               CHECK(length(candidate_profile_hash)=64
                 AND candidate_profile_hash NOT GLOB '*[^0-9a-f]*'),
             match_policy_hash TEXT NOT NULL
               CHECK(length(match_policy_hash)=64
                 AND match_policy_hash NOT GLOB '*[^0-9a-f]*'),
             gap_policy_hash TEXT NOT NULL
               CHECK(length(gap_policy_hash)=64
                 AND gap_policy_hash NOT GLOB '*[^0-9a-f]*'),
             results_hash TEXT NOT NULL
               CHECK(length(results_hash)=64
                 AND results_hash NOT GLOB '*[^0-9a-f]*'),
             plan_hash TEXT NOT NULL
               CHECK(length(plan_hash)=64
                 AND plan_hash NOT GLOB '*[^0-9a-f]*'),
             document_json TEXT NOT NULL,
             document_hash TEXT NOT NULL
               CHECK(length(document_hash)=64
                 AND document_hash NOT GLOB '*[^0-9a-f]*'),
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
             UNIQUE(
               job_key,as_of,requirements_hash,candidate_profile_hash,
               match_policy_hash,gap_policy_hash
             )
           )""",
        """CREATE TABLE vacancy_requirements(
             run_id TEXT NOT NULL
               REFERENCES fit_assessment_runs(run_id) ON DELETE RESTRICT,
             requirement_id TEXT NOT NULL,
             criterion TEXT NOT NULL,
             requirement_text TEXT NOT NULL,
             essential INTEGER NOT NULL CHECK(essential IN (0,1)),
             gap_kind TEXT NOT NULL CHECK(gap_kind IN
               ('presentation','retrieval','knowledge','execution',
                'evidence','experience','credential','structural')),
             bridge_policy TEXT NOT NULL CHECK(bridge_policy IN
               ('present','retrieve','learn_and_test','execute_and_verify',
                'build_evidence','gain_experience','earn_credential',
                'fatal','unbridgeable')),
             accepted_proof_classes_json TEXT NOT NULL,
             opportunity_weight_bp INTEGER NOT NULL
               CHECK(opportunity_weight_bp BETWEEN 1 AND 10000),
             source_identity TEXT NOT NULL,
             source_start INTEGER NOT NULL CHECK(source_start >= 0),
             source_end INTEGER NOT NULL CHECK(source_end > source_start),
             PRIMARY KEY(run_id,requirement_id)
           )""",
        """CREATE TABLE evidence_match_assessments(
             assessment_id TEXT PRIMARY KEY
               CHECK(length(assessment_id)=64
                 AND assessment_id NOT GLOB '*[^0-9a-f]*'),
             run_id TEXT NOT NULL,
             requirement_id TEXT NOT NULL,
             decision TEXT NOT NULL
               CHECK(decision IN ('matched','no_match','abstain')),
             evidence_ids_json TEXT NOT NULL,
             confidence_bp INTEGER NOT NULL CHECK(confidence_bp BETWEEN 0 AND 10000),
             reason TEXT NOT NULL,
             policy_hash TEXT NOT NULL
               CHECK(length(policy_hash)=64
                 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
             proposal_hash TEXT
               CHECK(proposal_hash IS NULL OR
                 (length(proposal_hash)=64
                  AND proposal_hash NOT GLOB '*[^0-9a-f]*')),
             provider TEXT,
             model TEXT,
             prompt_hash TEXT,
             input_hash TEXT,
             UNIQUE(run_id,requirement_id),
             UNIQUE(run_id,requirement_id,assessment_id),
             FOREIGN KEY(run_id,requirement_id)
               REFERENCES vacancy_requirements(run_id,requirement_id)
               ON DELETE RESTRICT,
             CHECK(
               (proposal_hash IS NULL AND provider IS NULL AND model IS NULL
                 AND prompt_hash IS NULL AND input_hash IS NULL)
               OR
               (proposal_hash IS NOT NULL
                 AND provider IS NOT NULL
                 AND model IS NOT NULL
                 AND prompt_hash IS NOT NULL
                 AND input_hash IS NOT NULL
                 AND length(trim(provider)) > 0
                 AND length(trim(model)) > 0
                 AND length(prompt_hash)=64
                 AND prompt_hash NOT GLOB '*[^0-9a-f]*'
                 AND length(input_hash)=64
                 AND input_hash NOT GLOB '*[^0-9a-f]*')
             )
           )""",
        """CREATE TABLE candidate_gaps(
             gap_id TEXT NOT NULL,
             run_id TEXT NOT NULL,
             requirement_id TEXT NOT NULL,
             match_assessment_id TEXT NOT NULL
               REFERENCES evidence_match_assessments(assessment_id)
               ON DELETE RESTRICT,
             gap_kind TEXT NOT NULL CHECK(gap_kind IN
               ('presentation','retrieval','knowledge','execution',
                'evidence','experience','credential','structural')),
             status TEXT NOT NULL CHECK(status IN ('unknown','confirmed')),
             blocking INTEGER NOT NULL CHECK(blocking IN (0,1)),
             reason TEXT NOT NULL,
             PRIMARY KEY(run_id,gap_id),
             UNIQUE(run_id,requirement_id),
             FOREIGN KEY(run_id,requirement_id,match_assessment_id)
               REFERENCES evidence_match_assessments(
                 run_id,requirement_id,assessment_id
               )
               ON DELETE RESTRICT
           )""",
        """CREATE TABLE improvement_tasks(
             task_id TEXT NOT NULL,
             run_id TEXT NOT NULL,
             gap_id TEXT NOT NULL,
             requirement_id TEXT NOT NULL,
             action_kind TEXT NOT NULL,
             opportunity_weight_bp INTEGER NOT NULL
               CHECK(opportunity_weight_bp BETWEEN 1 AND 10000),
             reuse_value_bp INTEGER NOT NULL
               CHECK(reuse_value_bp BETWEEN 1 AND 10000),
             cost_units INTEGER NOT NULL CHECK(cost_units > 0),
             priority_score INTEGER NOT NULL CHECK(priority_score >= 0),
             verification_json TEXT NOT NULL,
             state TEXT NOT NULL DEFAULT 'pending' CHECK(state='pending'),
             PRIMARY KEY(run_id,task_id),
             UNIQUE(run_id,requirement_id),
             FOREIGN KEY(run_id,requirement_id)
               REFERENCES vacancy_requirements(run_id,requirement_id)
               ON DELETE RESTRICT,
             FOREIGN KEY(run_id,gap_id)
               REFERENCES candidate_gaps(run_id,gap_id)
               ON DELETE RESTRICT
           )""",
        """CREATE TABLE improvement_evidence_candidates(
             promotion_id TEXT PRIMARY KEY
               CHECK(length(promotion_id)=64
                 AND promotion_id NOT GLOB '*[^0-9a-f]*'),
             run_id TEXT NOT NULL,
             task_id TEXT NOT NULL,
             proof_class TEXT NOT NULL CHECK(proof_class IN
               ('verified_claim','work_artifact','test_result',
                'external_outcome','employment_record','credential',
                'portfolio_artifact')),
             artifact_sha256 TEXT NOT NULL
               CHECK(length(artifact_sha256)=64
                 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'),
             verification_method TEXT NOT NULL,
             verifier_kind TEXT NOT NULL
               CHECK(verifier_kind IN ('deterministic','configured','human','external')),
             external_outcome_id TEXT,
             approval_state TEXT NOT NULL CHECK(approval_state='pending'),
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
             UNIQUE(run_id,task_id,artifact_sha256),
             FOREIGN KEY(run_id,task_id)
               REFERENCES improvement_tasks(run_id,task_id) ON DELETE RESTRICT
           )""",
        """CREATE TRIGGER fit_assessment_runs_immutable_update
             BEFORE UPDATE ON fit_assessment_runs
             BEGIN SELECT RAISE(ABORT,'fit assessment runs are immutable'); END""",
        """CREATE TRIGGER fit_assessment_runs_immutable_delete
             BEFORE DELETE ON fit_assessment_runs
             BEGIN SELECT RAISE(ABORT,'fit assessment runs are immutable'); END""",
        """CREATE TRIGGER vacancy_requirements_immutable_update
             BEFORE UPDATE ON vacancy_requirements
             BEGIN SELECT RAISE(ABORT,'vacancy requirements are immutable'); END""",
        """CREATE TRIGGER vacancy_requirements_immutable_delete
             BEFORE DELETE ON vacancy_requirements
             BEGIN SELECT RAISE(ABORT,'vacancy requirements are immutable'); END""",
        """CREATE TRIGGER evidence_match_assessments_immutable_update
             BEFORE UPDATE ON evidence_match_assessments
             BEGIN SELECT RAISE(ABORT,'evidence matches are immutable'); END""",
        """CREATE TRIGGER evidence_match_assessments_immutable_delete
             BEFORE DELETE ON evidence_match_assessments
             BEGIN SELECT RAISE(ABORT,'evidence matches are immutable'); END""",
        """CREATE TRIGGER candidate_gaps_immutable_update
             BEFORE UPDATE ON candidate_gaps
             BEGIN SELECT RAISE(ABORT,'candidate gaps are immutable'); END""",
        """CREATE TRIGGER candidate_gaps_immutable_delete
             BEFORE DELETE ON candidate_gaps
             BEGIN SELECT RAISE(ABORT,'candidate gaps are immutable'); END""",
        """CREATE TRIGGER improvement_tasks_immutable_update
             BEFORE UPDATE ON improvement_tasks
             BEGIN SELECT RAISE(ABORT,'improvement tasks are immutable'); END""",
        """CREATE TRIGGER improvement_tasks_immutable_delete
             BEFORE DELETE ON improvement_tasks
             BEGIN SELECT RAISE(ABORT,'improvement tasks are immutable'); END""",
        """CREATE TRIGGER improvement_evidence_candidates_immutable_update
             BEFORE UPDATE ON improvement_evidence_candidates
             BEGIN SELECT RAISE(ABORT,'improvement evidence is immutable'); END""",
        """CREATE TRIGGER improvement_evidence_candidates_immutable_delete
             BEFORE DELETE ON improvement_evidence_candidates
             BEGIN SELECT RAISE(ABORT,'improvement evidence is immutable'); END""",
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
JAA_05_MIGRATIONS: tuple[Migration, ...] = (
    *JAA_02_MIGRATIONS,
    _JAA_05_EVIDENCE_MATCHING_MIGRATION,
)


def apply_jaa_01_migrations(path: str | Path) -> tuple[int, ...]:
    """Apply the canonical JAA-01 schema to a configured SQLite database."""
    applied = MigrationRunner(path).apply(JAA_01_MIGRATIONS)
    with sqlite3.connect(path) as conn:
        verify_jaa01_installed_schema(conn)
    return applied


def apply_jaa_02_migrations(path: str | Path) -> tuple[int, ...]:
    """Apply JAA-01 and the forward-only canonical candidate graph schema."""
    applied = MigrationRunner(path).apply(JAA_02_MIGRATIONS)
    with sqlite3.connect(path) as conn:
        verify_jaa01_installed_schema(conn)
    return applied


def apply_jaa_05_migrations(path: str | Path) -> tuple[int, ...]:
    """Apply the candidate graph plus immutable fit-assessment schema."""
    applied = MigrationRunner(path).apply(JAA_05_MIGRATIONS)
    with sqlite3.connect(path) as conn:
        verify_jaa01_installed_schema(conn)
        verify_jaa05_installed_schema(conn)
    return applied
