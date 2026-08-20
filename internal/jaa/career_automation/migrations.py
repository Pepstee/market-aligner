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
    "improvement_task_activations",
    "gap_verification_receipts",
)
_JAA06_SCHEMA_TABLES = (
    "application_strategies",
    "strategy_requirement_coverage",
    "strategy_elements",
)
_JAA08_SCHEMA_TABLES = (
    "application_compilations",
    "official_application_routes",
    "release_gate_attempts",
    "release_manifests",
    "release_validation_receipts",
    "release_tokens",
)
_JAA_OPERATIONAL_SCHEMA_TABLES = (
    "application_admissions",
    "application_admission_references",
    "application_forward_validations",
)
_JAA_OPERATIONAL_SUBMISSION_SCHEMA_TABLES = (
    "authenticated_time_evidence",
    "exact_package_authority_grants",
    "exact_package_authority_uses",
    "submission_attempts",
    "jaa_events",
    "jaa_event_receipts",
    "jaa_event_outbox",
    "unsupported_route_handoffs",
)
_JAA_OPERATIONAL_ROLLOVER_SCHEMA_TABLES = (
    "release_rollover_operations",
)
_JAA_OPERATIONAL_RECONCILIATION_SCHEMA_TABLES = (
    "exact_package_reconciliation_receipts",
)
JAA05_INSTALLED_SCHEMA_SHA256 = (
    "3c4e4fe4d934b2995d8ccde907c59bfb9abc56615c193d081e6b07ca0f341dda"
)
JAA06_INSTALLED_SCHEMA_SHA256 = (
    "77d1d8ae29d5d77c48800f751b25d4e4d50598b9dd71576c42aeb6436b4a2bd1"
)
JAA08_INSTALLED_SCHEMA_SHA256 = (
    "bee5bc40d1933d412f2424a7bea5418664bc2698fcc808e99e59a1988290e09c"
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


def jaa06_installed_schema_digest(conn: sqlite3.Connection) -> str:
    """Hash every table, index and trigger owned by the JAA-06 migration."""
    placeholders = ",".join("?" for _ in _JAA06_SCHEMA_TABLES)
    rows = conn.execute(
        f"""SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL AND tbl_name IN ({placeholders})
            ORDER BY type,name""",
        _JAA06_SCHEMA_TABLES,
    ).fetchall()
    document = json.dumps(
        [list(row) for row in rows],
        ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"jaa06-installed-schema-v1\0" + document).hexdigest()


def verify_jaa06_installed_schema(conn: sqlite3.Connection) -> str:
    digest = jaa06_installed_schema_digest(conn)
    if digest != JAA06_INSTALLED_SCHEMA_SHA256:
        raise RuntimeError(
            "installed JAA-06 schema or trigger set does not match the checked contract"
        )
    return digest


def jaa08_installed_schema_digest(conn: sqlite3.Connection) -> str:
    """Hash every table, index and trigger owned by the JAA-08 migration."""
    placeholders = ",".join("?" for _ in _JAA08_SCHEMA_TABLES)
    rows = conn.execute(
        f"""SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL AND tbl_name IN ({placeholders})
            ORDER BY type,name""",
        _JAA08_SCHEMA_TABLES,
    ).fetchall()
    document = json.dumps(
        [list(row) for row in rows],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"jaa08-installed-schema-v1\0" + document).hexdigest()


def verify_jaa08_installed_schema(conn: sqlite3.Connection) -> str:
    digest = jaa08_installed_schema_digest(conn)
    if digest != JAA08_INSTALLED_SCHEMA_SHA256:
        raise RuntimeError(
            "installed JAA-08 schema or trigger set does not match the checked contract"
        )
    return digest


def jaa_operational_installed_schema_digest(conn: sqlite3.Connection) -> str:
    """Hash every table, index and trigger owned by operational admission."""
    placeholders = ",".join("?" for _ in _JAA_OPERATIONAL_SCHEMA_TABLES)
    rows = conn.execute(
        f"""SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL AND tbl_name IN ({placeholders})
            ORDER BY type,name""",
        _JAA_OPERATIONAL_SCHEMA_TABLES,
    ).fetchall()
    document = json.dumps(
        [list(row) for row in rows],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"jaa-operational-installed-schema-v1\0" + document).hexdigest()


def verify_jaa_operational_installed_schema(conn: sqlite3.Connection) -> str:
    """Compare installed operational DDL with a clean application of migration 9."""
    actual = jaa_operational_installed_schema_digest(conn)
    witness = sqlite3.connect(":memory:")
    try:
        witness.execute("PRAGMA foreign_keys=ON")
        for statement in _JAA_OPERATIONAL_HANDOFF_MIGRATION.statements:
            witness.execute(statement)
        expected = jaa_operational_installed_schema_digest(witness)
    finally:
        witness.close()
    if actual != expected:
        raise RuntimeError(
            "installed JAA operational admission schema differs from migration 9"
        )
    return actual


def jaa_operational_submission_schema_digest(conn: sqlite3.Connection) -> str:
    placeholders = ",".join("?" for _ in _JAA_OPERATIONAL_SUBMISSION_SCHEMA_TABLES)
    rows = conn.execute(
        f"""SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL AND tbl_name IN ({placeholders})
            ORDER BY type,name""",
        _JAA_OPERATIONAL_SUBMISSION_SCHEMA_TABLES,
    ).fetchall()
    document = json.dumps(
        [list(row) for row in rows],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"jaa-operational-submission-schema-v1\0" + document).hexdigest()


def verify_jaa_operational_submission_schema(conn: sqlite3.Connection) -> str:
    actual = jaa_operational_submission_schema_digest(conn)
    witness = sqlite3.connect(":memory:")
    try:
        witness.execute("PRAGMA foreign_keys=ON")
        for statement in _JAA_OPERATIONAL_SUBMISSION_MIGRATION.statements:
            witness.execute(statement)
        for statement in _JAA_OPERATIONAL_REVIEW_RELEASE_JOIN_MIGRATION.statements:
            witness.execute(statement)
        expected = jaa_operational_submission_schema_digest(witness)
    finally:
        witness.close()
    if actual != expected:
        raise RuntimeError("installed JAA operational submission schema differs")
    return actual


def jaa_operational_rollover_schema_digest(conn: sqlite3.Connection) -> str:
    """Hash the durable O-14 coordinator table, indexes and guards."""

    placeholders = ",".join("?" for _ in _JAA_OPERATIONAL_ROLLOVER_SCHEMA_TABLES)
    rows = conn.execute(
        f"""SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL AND tbl_name IN ({placeholders})
            ORDER BY type,name""",
        _JAA_OPERATIONAL_ROLLOVER_SCHEMA_TABLES,
    ).fetchall()
    document = json.dumps(
        [list(row) for row in rows],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(b"jaa-operational-rollover-schema-v1\0" + document).hexdigest()


def verify_jaa_operational_rollover_schema(conn: sqlite3.Connection) -> str:
    """Compare installed O-14 DDL with a clean application of migration 11."""

    actual = jaa_operational_rollover_schema_digest(conn)
    witness = sqlite3.connect(":memory:")
    try:
        witness.execute("PRAGMA foreign_keys=ON")
        for statement in _JAA_OPERATIONAL_ROLLOVER_MIGRATION.statements:
            witness.execute(statement)
        expected = jaa_operational_rollover_schema_digest(witness)
    finally:
        witness.close()
    if actual != expected:
        raise RuntimeError("installed JAA operational rollover schema differs")
    return actual


def jaa_operational_reconciliation_schema_digest(conn: sqlite3.Connection) -> str:
    """Hash exact reconciliation-byte storage and its immutability guards."""

    placeholders = ",".join(
        "?" for _ in _JAA_OPERATIONAL_RECONCILIATION_SCHEMA_TABLES
    )
    rows = conn.execute(
        f"""SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL AND tbl_name IN ({placeholders})
            ORDER BY type,name""",
        _JAA_OPERATIONAL_RECONCILIATION_SCHEMA_TABLES,
    ).fetchall()
    document = json.dumps(
        [list(row) for row in rows],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(
        b"jaa-operational-reconciliation-schema-v1\0" + document
    ).hexdigest()


def verify_jaa_operational_reconciliation_schema(conn: sqlite3.Connection) -> str:
    actual = jaa_operational_reconciliation_schema_digest(conn)
    witness = sqlite3.connect(":memory:")
    try:
        witness.execute("PRAGMA foreign_keys=ON")
        for statement in _JAA_OPERATIONAL_RECONCILIATION_MIGRATION.statements:
            witness.execute(statement)
        expected = jaa_operational_reconciliation_schema_digest(witness)
    finally:
        witness.close()
    if actual != expected:
        raise RuntimeError("installed JAA reconciliation receipt schema differs")
    return actual


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


_JAA_05_GAP_VERIFICATION_MIGRATION = Migration(
    5,
    "jaa_05_gap_recovery_graph_approval",
    (
        """ALTER TABLE improvement_evidence_candidates
             ADD COLUMN executor_identity TEXT
             CHECK(executor_identity IS NULL OR length(trim(executor_identity)) > 0)""",
        """CREATE TABLE improvement_task_activations(
             activation_id TEXT PRIMARY KEY
               CHECK(length(activation_id)=64
                 AND activation_id NOT GLOB '*[^0-9a-f]*'),
             run_id TEXT NOT NULL,
             task_id TEXT NOT NULL,
             job_key TEXT NOT NULL
               REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
             target_state TEXT NOT NULL CHECK(target_state IN
               ('gap_recovery','learning','evidence_building')),
             executor_identity TEXT NOT NULL
               CHECK(length(trim(executor_identity)) > 0),
             policy_hash TEXT NOT NULL
               CHECK(length(policy_hash)=64
                 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
             UNIQUE(run_id),
             UNIQUE(run_id,task_id),
             FOREIGN KEY(run_id,task_id)
               REFERENCES improvement_tasks(run_id,task_id) ON DELETE RESTRICT
           )""",
        """CREATE TABLE gap_verification_receipts(
             verification_id TEXT PRIMARY KEY
               CHECK(length(verification_id)=64
                 AND verification_id NOT GLOB '*[^0-9a-f]*'),
             activation_id TEXT NOT NULL UNIQUE
               REFERENCES improvement_task_activations(activation_id)
               ON DELETE RESTRICT,
             promotion_id TEXT NOT NULL UNIQUE
               REFERENCES improvement_evidence_candidates(promotion_id)
               ON DELETE RESTRICT,
             evidence_id TEXT NOT NULL,
             evidence_version INTEGER NOT NULL,
             claim_id TEXT NOT NULL,
             claim_version INTEGER NOT NULL,
             artefact_id TEXT NOT NULL,
             artefact_version INTEGER NOT NULL,
             verification_decision_id TEXT NOT NULL UNIQUE
               REFERENCES candidate_verification_decisions(decision_id)
               ON DELETE RESTRICT,
             verifier_identity TEXT NOT NULL
               CHECK(length(trim(verifier_identity)) > 0),
             verified_as_of TEXT NOT NULL
               CHECK(length(verified_as_of)=10),
             policy_hash TEXT NOT NULL
               CHECK(length(policy_hash)=64
                 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
             FOREIGN KEY(evidence_id,evidence_version)
               REFERENCES candidate_evidence(evidence_id,version)
               ON DELETE RESTRICT,
             FOREIGN KEY(claim_id,claim_version)
               REFERENCES candidate_claims(claim_id,version)
               ON DELETE RESTRICT,
             FOREIGN KEY(artefact_id,artefact_version)
               REFERENCES candidate_artefacts(artefact_id,version)
               ON DELETE RESTRICT
           )""",
        """CREATE TRIGGER improvement_task_activations_immutable_update
             BEFORE UPDATE ON improvement_task_activations
             BEGIN SELECT RAISE(ABORT,'task activations are immutable'); END""",
        """CREATE TRIGGER improvement_task_activations_immutable_delete
             BEFORE DELETE ON improvement_task_activations
             BEGIN SELECT RAISE(ABORT,'task activations are immutable'); END""",
        """CREATE TRIGGER gap_verification_receipts_immutable_update
             BEFORE UPDATE ON gap_verification_receipts
             BEGIN SELECT RAISE(ABORT,'gap verification receipts are immutable'); END""",
        """CREATE TRIGGER gap_verification_receipts_immutable_delete
             BEFORE DELETE ON gap_verification_receipts
             BEGIN SELECT RAISE(ABORT,'gap verification receipts are immutable'); END""",
    ),
)


_JAA_05_FIT_REASSESSMENT_MIGRATION = Migration(
    6,
    "jaa_05_fit_reassessment_lineage",
    (
        """ALTER TABLE fit_assessment_runs
             ADD COLUMN predecessor_run_id TEXT
             REFERENCES fit_assessment_runs(run_id) ON DELETE RESTRICT""",
        """CREATE UNIQUE INDEX fit_assessment_runs_one_successor
             ON fit_assessment_runs(predecessor_run_id)
             WHERE predecessor_run_id IS NOT NULL""",
    ),
)


_JAA_06_APPLICATION_STRATEGY_MIGRATION = Migration(
    7,
    "jaa_06_application_strategies",
    (
        """CREATE TABLE application_strategies(
             strategy_id TEXT PRIMARY KEY
               CHECK(length(strategy_id)=64
                 AND strategy_id NOT GLOB '*[^0-9a-f]*'),
             job_key TEXT NOT NULL
               REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
             fit_run_id TEXT NOT NULL UNIQUE
               REFERENCES fit_assessment_runs(run_id) ON DELETE RESTRICT,
             dossier_hash TEXT NOT NULL
               CHECK(length(dossier_hash)=64
                 AND dossier_hash NOT GLOB '*[^0-9a-f]*'),
             candidate_profile_hash TEXT NOT NULL
               CHECK(length(candidate_profile_hash)=64
                 AND candidate_profile_hash NOT GLOB '*[^0-9a-f]*'),
             as_of TEXT NOT NULL
               CHECK(date(as_of) IS NOT NULL AND date(as_of)=as_of),
             decision TEXT NOT NULL
               CHECK(decision IN
                 ('apply_now','close_gap_first','reject_candidacy')),
             input_hash TEXT NOT NULL
               CHECK(length(input_hash)=64
                 AND input_hash NOT GLOB '*[^0-9a-f]*'),
             policy_hash TEXT NOT NULL
               CHECK(length(policy_hash)=64
                 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
             document_json TEXT NOT NULL,
             document_hash TEXT NOT NULL
               CHECK(length(document_hash)=64
                 AND document_hash NOT GLOB '*[^0-9a-f]*'),
             lifecycle_receipt_id INTEGER UNIQUE
               REFERENCES lifecycle_transition_receipts(receipt_id)
               ON DELETE RESTRICT,
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
             UNIQUE(strategy_id,fit_run_id),
             UNIQUE(strategy_id,job_key,fit_run_id),
             CHECK(
               (decision='apply_now' AND lifecycle_receipt_id IS NOT NULL)
               OR
               (decision<>'apply_now' AND lifecycle_receipt_id IS NULL)
             )
           )""",
        """CREATE TABLE strategy_requirement_coverage(
             strategy_id TEXT NOT NULL
               REFERENCES application_strategies(strategy_id)
               ON DELETE RESTRICT,
             fit_run_id TEXT NOT NULL,
             requirement_id TEXT NOT NULL,
             coverage_state TEXT NOT NULL
               CHECK(coverage_state IN
                 ('covered','absent','release_blocking')),
             candidate_claim_ids_json TEXT NOT NULL,
             candidate_evidence_ids_json TEXT NOT NULL,
             reason_code TEXT NOT NULL,
             PRIMARY KEY(strategy_id,requirement_id),
             FOREIGN KEY(strategy_id,fit_run_id)
               REFERENCES application_strategies(strategy_id,fit_run_id)
               ON DELETE RESTRICT,
             FOREIGN KEY(fit_run_id,requirement_id)
               REFERENCES vacancy_requirements(run_id,requirement_id)
               ON DELETE RESTRICT
           )""",
        """CREATE TABLE strategy_elements(
             element_id TEXT PRIMARY KEY
               CHECK(length(element_id)=64
                 AND element_id NOT GLOB '*[^0-9a-f]*'),
             strategy_id TEXT NOT NULL
               REFERENCES application_strategies(strategy_id)
               ON DELETE RESTRICT,
             job_key TEXT NOT NULL,
             fit_run_id TEXT NOT NULL,
             element_kind TEXT NOT NULL
               CHECK(element_kind IN
                 ('cv_emphasis','cover_letter_argument','structured_answer',
                  'interview_seed','objection_response','employer_hook')),
             requirement_id TEXT NOT NULL,
             candidate_claim_id TEXT NOT NULL,
             candidate_claim_version INTEGER NOT NULL,
             candidate_evidence_id TEXT NOT NULL,
             candidate_evidence_version INTEGER NOT NULL,
             research_claim_id TEXT NOT NULL,
             employer_fact_hash TEXT NOT NULL
               CHECK(length(employer_fact_hash)=64
                 AND employer_fact_hash NOT GLOB '*[^0-9a-f]*'),
             directive TEXT NOT NULL,
             UNIQUE(strategy_id,element_kind,requirement_id),
             FOREIGN KEY(strategy_id,job_key,fit_run_id)
               REFERENCES application_strategies(
                 strategy_id,job_key,fit_run_id
               )
               ON DELETE RESTRICT,
             FOREIGN KEY(fit_run_id,requirement_id)
               REFERENCES vacancy_requirements(run_id,requirement_id)
               ON DELETE RESTRICT,
             FOREIGN KEY(candidate_claim_id,candidate_claim_version)
               REFERENCES candidate_claims(claim_id,version)
               ON DELETE RESTRICT,
             FOREIGN KEY(candidate_evidence_id,candidate_evidence_version)
               REFERENCES candidate_evidence(evidence_id,version)
               ON DELETE RESTRICT,
             FOREIGN KEY(job_key,research_claim_id)
               REFERENCES employer_intelligence(job_key,claim_id)
               ON DELETE RESTRICT
           )""",
        """CREATE TRIGGER application_strategies_immutable_update
             BEFORE UPDATE ON application_strategies
             BEGIN SELECT RAISE(ABORT,'application strategies are immutable'); END""",
        """CREATE TRIGGER application_strategies_immutable_delete
             BEFORE DELETE ON application_strategies
             BEGIN SELECT RAISE(ABORT,'application strategies are immutable'); END""",
        """CREATE TRIGGER strategy_requirement_coverage_immutable_update
             BEFORE UPDATE ON strategy_requirement_coverage
             BEGIN SELECT RAISE(ABORT,'strategy coverage is immutable'); END""",
        """CREATE TRIGGER strategy_requirement_coverage_immutable_delete
             BEFORE DELETE ON strategy_requirement_coverage
             BEGIN SELECT RAISE(ABORT,'strategy coverage is immutable'); END""",
        """CREATE TRIGGER strategy_elements_immutable_update
             BEFORE UPDATE ON strategy_elements
             BEGIN SELECT RAISE(ABORT,'strategy elements are immutable'); END""",
        """CREATE TRIGGER strategy_elements_immutable_delete
             BEFORE DELETE ON strategy_elements
             BEGIN SELECT RAISE(ABORT,'strategy elements are immutable'); END""",
    ),
)


_JAA_08_RELEASE_GATE_MIGRATION = Migration(
    8,
    "jaa_08_release_gate",
    (
        """CREATE TABLE application_compilations(
             compilation_id TEXT PRIMARY KEY
               CHECK(length(compilation_id)=64
                 AND compilation_id NOT GLOB '*[^0-9a-f]*'),
             job_key TEXT NOT NULL
               REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
             strategy_id TEXT NOT NULL UNIQUE
               REFERENCES application_strategies(strategy_id)
               ON DELETE RESTRICT,
             application_source_id TEXT NOT NULL UNIQUE
               CHECK(length(application_source_id)=64
                 AND application_source_id NOT GLOB '*[^0-9a-f]*'),
             application_source_hash TEXT NOT NULL
               CHECK(length(application_source_hash)=64
                 AND application_source_hash NOT GLOB '*[^0-9a-f]*'),
             artifact_set_hash TEXT NOT NULL UNIQUE
               CHECK(length(artifact_set_hash)=64
                 AND artifact_set_hash NOT GLOB '*[^0-9a-f]*'),
             artifact_receipt_hash TEXT NOT NULL UNIQUE
               CHECK(length(artifact_receipt_hash)=64
                 AND artifact_receipt_hash NOT GLOB '*[^0-9a-f]*'),
             artifact_relative_directory TEXT NOT NULL
               CHECK(length(artifact_relative_directory)=64
                 AND artifact_relative_directory NOT GLOB '*[^0-9a-f]*'),
             contact_record_id TEXT NOT NULL,
             contact_record_version INTEGER NOT NULL,
             questions_hash TEXT NOT NULL
               CHECK(length(questions_hash)=64
                 AND questions_hash NOT GLOB '*[^0-9a-f]*'),
             compilation_document_json TEXT NOT NULL,
             lifecycle_receipt_id INTEGER NOT NULL UNIQUE
               REFERENCES lifecycle_transition_receipts(receipt_id)
               ON DELETE RESTRICT,
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
             UNIQUE(compilation_id,job_key,strategy_id),
             FOREIGN KEY(contact_record_id,contact_record_version)
               REFERENCES candidate_records(record_id,version)
               ON DELETE RESTRICT,
             CHECK(artifact_relative_directory=artifact_set_hash)
           )""",
        """CREATE TABLE official_application_routes(
             route_id TEXT PRIMARY KEY,
             job_key TEXT NOT NULL
               REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
             adapter_id TEXT NOT NULL,
             adapter_version TEXT NOT NULL,
             source_identity TEXT NOT NULL,
             route_policy_hash TEXT NOT NULL
               CHECK(length(route_policy_hash)=64
                 AND route_policy_hash NOT GLOB '*[^0-9a-f]*'),
             verified_at TEXT NOT NULL
               CHECK(date(verified_at)=verified_at),
             valid_until TEXT NOT NULL
               CHECK(date(valid_until)=valid_until
                 AND valid_until>=verified_at),
             allowed INTEGER NOT NULL CHECK(allowed IN (0,1)),
             route_document_json TEXT NOT NULL,
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
           )""",
        """CREATE UNIQUE INDEX official_application_routes_one_allowed
             ON official_application_routes(job_key)
             WHERE allowed=1""",
        """CREATE TABLE release_gate_attempts(
             attempt_id TEXT PRIMARY KEY
               CHECK(length(attempt_id)=64
                 AND attempt_id NOT GLOB '*[^0-9a-f]*'),
             compilation_id TEXT NOT NULL
               REFERENCES application_compilations(compilation_id)
               ON DELETE RESTRICT,
             evaluated_at TEXT NOT NULL CHECK(date(evaluated_at)=evaluated_at),
             input_hash TEXT NOT NULL
               CHECK(length(input_hash)=64
                 AND input_hash NOT GLOB '*[^0-9a-f]*'),
             verdict TEXT NOT NULL CHECK(verdict IN ('pass','block')),
             finding_codes_json TEXT NOT NULL,
             lifecycle_receipt_id INTEGER NOT NULL UNIQUE
               REFERENCES lifecycle_transition_receipts(receipt_id)
               ON DELETE RESTRICT,
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
           )""",
        """CREATE TABLE release_manifests(
             release_manifest_hash TEXT PRIMARY KEY
               CHECK(length(release_manifest_hash)=64
                 AND release_manifest_hash NOT GLOB '*[^0-9a-f]*'),
             attempt_id TEXT NOT NULL UNIQUE
               REFERENCES release_gate_attempts(attempt_id)
               ON DELETE RESTRICT,
             compilation_id TEXT NOT NULL UNIQUE
               REFERENCES application_compilations(compilation_id)
               ON DELETE RESTRICT,
             job_key TEXT NOT NULL
               REFERENCES pipeline_jobs(job_key) ON DELETE RESTRICT,
             candidate_identity_hash TEXT NOT NULL,
             input_hash TEXT NOT NULL,
             artifact_set_hash TEXT NOT NULL,
             manifest_document_json TEXT NOT NULL,
             created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
             UNIQUE(job_key,candidate_identity_hash)
           )""",
        """CREATE TABLE release_validation_receipts(
             release_manifest_hash TEXT NOT NULL
               REFERENCES release_manifests(release_manifest_hash)
               ON DELETE RESTRICT,
             validator_id TEXT NOT NULL CHECK(validator_id IN
               ('authority','truth','eligibility','freshness','consistency',
                'ats','duplicate','official_route')),
             validator_version TEXT NOT NULL,
             validator_impl_hash TEXT NOT NULL,
             input_hash TEXT NOT NULL,
             artifact_set_hash TEXT NOT NULL,
             decision TEXT NOT NULL CHECK(decision='pass'),
             receipt_document_json TEXT NOT NULL,
             PRIMARY KEY(release_manifest_hash,validator_id),
             UNIQUE(release_manifest_hash,validator_impl_hash)
           )""",
        """CREATE TABLE release_tokens(
             token_hash TEXT PRIMARY KEY
               CHECK(length(token_hash)=64
                 AND token_hash NOT GLOB '*[^0-9a-f]*'),
             release_manifest_hash TEXT NOT NULL UNIQUE
               REFERENCES release_manifests(release_manifest_hash)
               ON DELETE RESTRICT,
             issued_at TEXT NOT NULL,
             consumed_at TEXT,
             CHECK(consumed_at IS NULL OR consumed_at>=issued_at)
           )""",
        """CREATE TRIGGER application_compilations_immutable_update
             BEFORE UPDATE ON application_compilations
             BEGIN SELECT RAISE(ABORT,'application compilations are immutable'); END""",
        """CREATE TRIGGER application_compilations_immutable_delete
             BEFORE DELETE ON application_compilations
             BEGIN SELECT RAISE(ABORT,'application compilations are immutable'); END""",
        """CREATE TRIGGER official_application_routes_immutable_update
             BEFORE UPDATE ON official_application_routes
             BEGIN SELECT RAISE(ABORT,'official routes are immutable'); END""",
        """CREATE TRIGGER official_application_routes_immutable_delete
             BEFORE DELETE ON official_application_routes
             BEGIN SELECT RAISE(ABORT,'official routes are immutable'); END""",
        """CREATE TRIGGER release_gate_attempts_immutable_update
             BEFORE UPDATE ON release_gate_attempts
             BEGIN SELECT RAISE(ABORT,'release attempts are immutable'); END""",
        """CREATE TRIGGER release_gate_attempts_immutable_delete
             BEFORE DELETE ON release_gate_attempts
             BEGIN SELECT RAISE(ABORT,'release attempts are immutable'); END""",
        """CREATE TRIGGER release_manifests_immutable_update
             BEFORE UPDATE ON release_manifests
             BEGIN SELECT RAISE(ABORT,'release manifests are immutable'); END""",
        """CREATE TRIGGER release_manifests_immutable_delete
             BEFORE DELETE ON release_manifests
             BEGIN SELECT RAISE(ABORT,'release manifests are immutable'); END""",
        """CREATE TRIGGER release_validation_receipts_immutable_update
             BEFORE UPDATE ON release_validation_receipts
             BEGIN SELECT RAISE(ABORT,'release validations are immutable'); END""",
        """CREATE TRIGGER release_validation_receipts_immutable_delete
             BEFORE DELETE ON release_validation_receipts
             BEGIN SELECT RAISE(ABORT,'release validations are immutable'); END""",
        """CREATE TRIGGER release_tokens_guard_update
             BEFORE UPDATE ON release_tokens
             WHEN NEW.token_hash<>OLD.token_hash
               OR NEW.release_manifest_hash<>OLD.release_manifest_hash
               OR NEW.issued_at<>OLD.issued_at
               OR OLD.consumed_at IS NOT NULL
               OR NEW.consumed_at IS NULL
             BEGIN SELECT RAISE(ABORT,'release token update is invalid'); END""",
        """CREATE TRIGGER release_tokens_require_complete_validations
             BEFORE INSERT ON release_tokens
             WHEN (
               SELECT COUNT(DISTINCT validator_id)
               FROM release_validation_receipts
               WHERE release_manifest_hash=NEW.release_manifest_hash
             )<>8
             BEGIN SELECT RAISE(ABORT,'release token requires all validators'); END""",
        """CREATE TRIGGER release_tokens_immutable_delete
             BEFORE DELETE ON release_tokens
             BEGIN SELECT RAISE(ABORT,'release tokens are immutable'); END""",
    ),
)


_JAA_OPERATIONAL_HANDOFF_MIGRATION = Migration(
    9,
    "jaa_operational_market_aligner_handoff_v1",
    (
        """CREATE TABLE application_admissions(
             application_id TEXT PRIMARY KEY
               CHECK(length(trim(application_id))>0),
             admission_kind TEXT NOT NULL CHECK(admission_kind IN
               ('market_aligner_handoff_v1','base_v1_compatibility',
                'legacy_scored_jsonl')),
             environment TEXT NOT NULL CHECK(environment IN
               ('production','synthetic','legacy')),
             authority_scope TEXT NOT NULL CHECK(authority_scope IN
               ('production','synthetic','none')),
             emission_profile TEXT CHECK(emission_profile IS NULL OR
               emission_profile IN ('strict_v1','base_v1_compatibility')),
             logical_identity_json TEXT,
             logical_identity_sha256 TEXT UNIQUE
               CHECK(logical_identity_sha256 IS NULL OR
                 (length(logical_identity_sha256)=64
                  AND logical_identity_sha256 NOT GLOB '*[^0-9a-f]*')),
             trust_mode TEXT NOT NULL CHECK(trust_mode IN
               ('protected_local_outbox','authenticated_attestation','synthetic_direct',
                'legacy_scored_jsonl')),
             trust_root_id TEXT NOT NULL CHECK(length(trim(trust_root_id))>0),
             admission_context_bytes BLOB,
             admission_context_sha256 TEXT UNIQUE,
             context_authenticator_sha256 TEXT,
             admitted_at TEXT NOT NULL CHECK(length(admitted_at)=20),
             producer_product TEXT,
             producer_commit_sha TEXT,
             profile_id TEXT,
             profile_version TEXT,
             job_key TEXT NOT NULL CHECK(length(trim(job_key)) > 0),
             handoff_root_sha256 TEXT UNIQUE,
             payload_sha256 TEXT,
             vacancy_snapshot_sha256 TEXT,
             original_bytes BLOB NOT NULL CHECK(typeof(original_bytes)='blob'),
             original_bytes_sha256 TEXT NOT NULL
               CHECK(length(original_bytes_sha256)=64
                 AND original_bytes_sha256 NOT GLOB '*[^0-9a-f]*'),
             verification_receipt_bytes BLOB NOT NULL
               CHECK(typeof(verification_receipt_bytes)='blob'),
             verification_receipt_sha256 TEXT NOT NULL UNIQUE
               CHECK(length(verification_receipt_sha256)=64
                 AND verification_receipt_sha256 NOT GLOB '*[^0-9a-f]*'),
             vacancy_source_identity TEXT NOT NULL UNIQUE,
             reference_count INTEGER NOT NULL CHECK(reference_count>=0),
             sealed INTEGER NOT NULL DEFAULT 0 CHECK(sealed IN (0,1)),
             CHECK(
               (
                 admission_kind IN
                   ('market_aligner_handoff_v1','base_v1_compatibility')
                 AND application_id='app_' || logical_identity_sha256
                 AND logical_identity_json IS NOT NULL
                 AND profile_id IS NOT NULL AND length(trim(profile_id))>0
                 AND profile_version IS NOT NULL AND length(trim(profile_version))>0
                 AND producer_product='market-aligner'
                 AND producer_commit_sha IS NOT NULL AND length(producer_commit_sha)=40
                 AND handoff_root_sha256 IS NOT NULL
                 AND length(handoff_root_sha256)=64
                 AND handoff_root_sha256 NOT GLOB '*[^0-9a-f]*'
                 AND payload_sha256 IS NOT NULL
                 AND length(payload_sha256)=64
                 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
                 AND vacancy_snapshot_sha256 IS NOT NULL
                 AND length(vacancy_snapshot_sha256)=64
                 AND vacancy_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
                 AND original_bytes_sha256=handoff_root_sha256
                 AND vacancy_source_identity=
                   'market-aligner-handoff:' || handoff_root_sha256
                 AND reference_count>0
                 AND (
                   (trust_mode IN
                      ('protected_local_outbox','authenticated_attestation')
                    AND admission_context_bytes IS NOT NULL
                    AND admission_context_sha256 IS NOT NULL
                    AND context_authenticator_sha256 IS NOT NULL)
                   OR (environment='synthetic' AND authority_scope='none'
                       AND trust_mode='synthetic_direct'
                       AND admission_context_bytes IS NULL
                       AND admission_context_sha256 IS NULL
                       AND context_authenticator_sha256 IS NULL)
                 )
                 AND ((admission_kind='market_aligner_handoff_v1'
                       AND emission_profile='strict_v1'
                       AND ((trust_mode='synthetic_direct' AND authority_scope='none')
                            OR (trust_mode<>'synthetic_direct'
                                AND authority_scope=environment)))
                      OR (admission_kind='base_v1_compatibility'
                          AND emission_profile='base_v1_compatibility'
                          AND authority_scope='none'))
               ) OR (
                 admission_kind='legacy_scored_jsonl'
                 AND application_id='legacy_' || original_bytes_sha256
                 AND emission_profile IS NULL
                 AND logical_identity_json IS NULL
                 AND logical_identity_sha256 IS NULL
                 AND environment='legacy' AND authority_scope='none'
                 AND trust_mode='legacy_scored_jsonl'
                 AND trust_root_id='legacy_scored_jsonl'
                 AND admission_context_bytes IS NULL
                 AND admission_context_sha256 IS NULL
                 AND context_authenticator_sha256 IS NULL
                 AND producer_product IS NULL AND producer_commit_sha IS NULL
                 AND profile_id IS NULL AND profile_version IS NULL
                 AND handoff_root_sha256 IS NULL AND payload_sha256 IS NULL
                 AND vacancy_snapshot_sha256 IS NULL
                 AND vacancy_source_identity=
                   'legacy-scored-jsonl:' || original_bytes_sha256
                 AND reference_count=0
               )
             )
           )""",
        """CREATE TABLE application_admission_references(
             application_id TEXT NOT NULL
               REFERENCES application_admissions(application_id)
               ON DELETE RESTRICT,
             reference_key TEXT NOT NULL CHECK(length(trim(reference_key))>0),
             reference_kind TEXT NOT NULL CHECK(length(trim(reference_kind))>0),
             referenced_sha256 TEXT NOT NULL
               CHECK(length(referenced_sha256)=64
                 AND referenced_sha256 NOT GLOB '*[^0-9a-f]*'),
             resolved_bytes_sha256 TEXT NOT NULL
               CHECK(length(resolved_bytes_sha256)=64
                 AND resolved_bytes_sha256 NOT GLOB '*[^0-9a-f]*'),
             byte_length INTEGER NOT NULL CHECK(byte_length>=0),
             type_id TEXT NOT NULL CHECK(length(trim(type_id))>0),
             schema_version TEXT NOT NULL CHECK(length(trim(schema_version))>0),
             issuer_id TEXT NOT NULL CHECK(length(trim(issuer_id))>0),
             subject_json TEXT NOT NULL,
             issued_at TEXT NOT NULL CHECK(length(issued_at)=20),
             valid_until TEXT CHECK(valid_until IS NULL OR length(valid_until)=20),
             freshness_class TEXT NOT NULL CHECK(freshness_class IN
               ('immutable','active_revision','valid_interval','policy_interval',
                'vacancy_age','dossier_age')),
             metadata_bytes BLOB NOT NULL CHECK(typeof(metadata_bytes)='blob'),
             metadata_sha256 TEXT NOT NULL
               CHECK(length(metadata_sha256)=64
                 AND metadata_sha256 NOT GLOB '*[^0-9a-f]*'),
             resolver_identity_sha256 TEXT NOT NULL
               CHECK(length(resolver_identity_sha256)=64
                 AND resolver_identity_sha256 NOT GLOB '*[^0-9a-f]*'),
             trust_root_id TEXT NOT NULL CHECK(length(trim(trust_root_id))>0),
             trust_proof_sha256 TEXT NOT NULL
               CHECK(length(trust_proof_sha256)=64
                 AND trust_proof_sha256 NOT GLOB '*[^0-9a-f]*'),
             PRIMARY KEY(application_id,reference_key),
             CHECK(referenced_sha256=resolved_bytes_sha256),
             CHECK((freshness_class='immutable' AND valid_until IS NULL) OR
                   (freshness_class<>'immutable' AND valid_until IS NOT NULL))
           )""",
        """CREATE TABLE application_forward_validations(
             validation_sha256 TEXT PRIMARY KEY
               CHECK(length(validation_sha256)=64
                 AND validation_sha256 NOT GLOB '*[^0-9a-f]*'),
             application_id TEXT NOT NULL
               REFERENCES application_admissions(application_id) ON DELETE RESTRICT,
             boundary TEXT NOT NULL CHECK(boundary IN
               ('strategy','review','release_readiness','authority','executor')),
             evaluated_at TEXT NOT NULL CHECK(length(evaluated_at)=20),
             receipt_bytes BLOB NOT NULL CHECK(typeof(receipt_bytes)='blob'),
             reference_count INTEGER NOT NULL CHECK(reference_count>0),
             UNIQUE(application_id,boundary,evaluated_at)
           )""",
        """CREATE TRIGGER application_admission_reference_unsealed_insert
             BEFORE INSERT ON application_admission_references
             WHEN COALESCE((
               SELECT sealed FROM application_admissions
               WHERE application_id=NEW.application_id
             ),1)<>0
             BEGIN
               SELECT RAISE(ABORT,'admission references require an unsealed admission');
             END""",
        """CREATE TRIGGER application_admission_seal_guard
             BEFORE UPDATE ON application_admissions
             WHEN NOT (
               OLD.sealed=0 AND NEW.sealed=1
               AND NEW.application_id=OLD.application_id
               AND NEW.logical_identity_sha256 IS OLD.logical_identity_sha256
               AND NEW.admission_kind=OLD.admission_kind
               AND NEW.environment=OLD.environment
               AND NEW.authority_scope=OLD.authority_scope
               AND NEW.emission_profile IS OLD.emission_profile
               AND NEW.logical_identity_json IS OLD.logical_identity_json
               AND NEW.trust_mode=OLD.trust_mode
               AND NEW.trust_root_id=OLD.trust_root_id
               AND NEW.admission_context_bytes IS OLD.admission_context_bytes
               AND NEW.admission_context_sha256 IS OLD.admission_context_sha256
               AND NEW.context_authenticator_sha256 IS OLD.context_authenticator_sha256
               AND NEW.admitted_at=OLD.admitted_at
               AND NEW.producer_product IS OLD.producer_product
               AND NEW.producer_commit_sha IS OLD.producer_commit_sha
               AND NEW.profile_id IS OLD.profile_id
               AND NEW.profile_version IS OLD.profile_version
               AND NEW.job_key=OLD.job_key
               AND NEW.handoff_root_sha256 IS OLD.handoff_root_sha256
               AND NEW.payload_sha256 IS OLD.payload_sha256
               AND NEW.vacancy_snapshot_sha256 IS OLD.vacancy_snapshot_sha256
               AND NEW.original_bytes=OLD.original_bytes
               AND NEW.original_bytes_sha256=OLD.original_bytes_sha256
               AND NEW.verification_receipt_bytes=OLD.verification_receipt_bytes
               AND NEW.verification_receipt_sha256=OLD.verification_receipt_sha256
               AND NEW.vacancy_source_identity=OLD.vacancy_source_identity
               AND NEW.reference_count=OLD.reference_count
               AND NEW.reference_count=(
                 SELECT COUNT(*) FROM application_admission_references
                 WHERE application_id=OLD.application_id
               )
             )
             BEGIN SELECT RAISE(ABORT,'application admission update is invalid'); END""",
        """CREATE TRIGGER application_admission_immutable_delete
             BEFORE DELETE ON application_admissions
             BEGIN SELECT RAISE(ABORT,'application admissions are immutable'); END""",
        """CREATE TRIGGER application_admission_reference_immutable_update
             BEFORE UPDATE ON application_admission_references
             BEGIN SELECT RAISE(ABORT,'admission references are immutable'); END""",
        """CREATE TRIGGER application_admission_reference_immutable_delete
             BEFORE DELETE ON application_admission_references
             BEGIN SELECT RAISE(ABORT,'admission references are immutable'); END""",
        """CREATE TRIGGER application_forward_validation_immutable_update
             BEFORE UPDATE ON application_forward_validations
             BEGIN SELECT RAISE(ABORT,'forward validations are immutable'); END""",
        """CREATE TRIGGER application_forward_validation_immutable_delete
             BEFORE DELETE ON application_forward_validations
             BEGIN SELECT RAISE(ABORT,'forward validations are immutable'); END""",
    ),
)


_JAA_OPERATIONAL_SUBMISSION_MIGRATION = Migration(
    10,
    "jaa_operational_exact_package_authority_and_events_v1",
    (
        """CREATE TABLE authenticated_time_evidence(
             receipt_sha256 TEXT PRIMARY KEY
               CHECK(length(receipt_sha256)=64
                 AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'),
             receipt_bytes BLOB NOT NULL CHECK(typeof(receipt_bytes)='blob'),
             environment TEXT NOT NULL CHECK(environment IN ('synthetic','production')),
             purpose TEXT NOT NULL CHECK(purpose IN
               ('handoff_admission','forward_boundary','review_material',
                'authority_grant','click_reservation','reconciliation',
                'route_handoff','phase_event')),
             subject_sha256 TEXT NOT NULL
               CHECK(length(subject_sha256)=64
                 AND subject_sha256 NOT GLOB '*[^0-9a-f]*'),
             evaluated_at TEXT NOT NULL CHECK(length(evaluated_at)=20),
             witness_identity_sha256 TEXT NOT NULL
               CHECK(length(witness_identity_sha256)=64
                 AND witness_identity_sha256 NOT GLOB '*[^0-9a-f]*'),
             trust_root_id TEXT NOT NULL CHECK(length(trim(trust_root_id))>0),
             consumer_kind TEXT NOT NULL CHECK(consumer_kind IN
               ('admission','forward_validation','review_request',
                'authority_grant','submission_attempt','reconciliation',
                'route_handoff','phase_event')),
             consumer_id TEXT NOT NULL CHECK(length(trim(consumer_id))>0),
             UNIQUE(consumer_kind,consumer_id)
           )""",
        """CREATE TABLE exact_package_authority_grants(
             authority_id TEXT PRIMARY KEY CHECK(length(trim(authority_id))>0),
             grant_sha256 TEXT NOT NULL UNIQUE
               CHECK(length(grant_sha256)=64 AND grant_sha256 NOT GLOB '*[^0-9a-f]*'),
             grant_bytes BLOB NOT NULL CHECK(typeof(grant_bytes)='blob'),
             application_id TEXT NOT NULL
               REFERENCES application_admissions(application_id) ON DELETE RESTRICT,
             handoff_root_sha256 TEXT NOT NULL,
             application_source_identity TEXT NOT NULL,
             artifact_set_sha256 TEXT NOT NULL,
             cv_pdf_sha256 TEXT NOT NULL,
             cover_letter_pdf_sha256 TEXT NOT NULL,
             form_answers_sha256 TEXT NOT NULL,
             form_package_sha256 TEXT NOT NULL,
             inventory_sha256 TEXT NOT NULL,
             employer_assessment_receipt_sha256 TEXT NOT NULL,
             operator_approval_receipt_sha256 TEXT NOT NULL,
             legal_consent_receipt_sha256 TEXT NOT NULL,
             issuer_trust_receipt_sha256 TEXT NOT NULL,
             approval_subject_bytes BLOB NOT NULL
               CHECK(typeof(approval_subject_bytes)='blob'),
             approval_subject_sha256 TEXT NOT NULL UNIQUE
               CHECK(length(approval_subject_sha256)=64
                 AND approval_subject_sha256 NOT GLOB '*[^0-9a-f]*'),
             employer_review_runtime_bytes BLOB NOT NULL
               CHECK(typeof(employer_review_runtime_bytes)='blob'),
             employer_review_runtime_sha256 TEXT NOT NULL
               CHECK(length(employer_review_runtime_sha256)=64
                 AND employer_review_runtime_sha256 NOT GLOB '*[^0-9a-f]*'),
             environment TEXT NOT NULL CHECK(environment='synthetic'),
             provider TEXT NOT NULL CHECK(provider='greenhouse'),
             route_id TEXT NOT NULL CHECK(length(trim(route_id))>0),
             route_origin TEXT NOT NULL CHECK(length(trim(route_origin))>0),
             page_url TEXT NOT NULL CHECK(length(trim(page_url))>0),
             form_action TEXT NOT NULL CHECK(length(trim(form_action))>0),
             form_method TEXT NOT NULL CHECK(form_method='post'),
             form_enctype TEXT NOT NULL CHECK(form_enctype='multipart/form-data'),
             submit_control_fingerprint_sha256 TEXT NOT NULL
               CHECK(length(submit_control_fingerprint_sha256)=64
                 AND submit_control_fingerprint_sha256 NOT GLOB '*[^0-9a-f]*'),
             browser_runtime_identity_sha256 TEXT NOT NULL
               CHECK(length(browser_runtime_identity_sha256)=64
                 AND browser_runtime_identity_sha256 NOT GLOB '*[^0-9a-f]*'),
             grant_time_receipt_sha256 TEXT NOT NULL UNIQUE
               REFERENCES authenticated_time_evidence(receipt_sha256) ON DELETE RESTRICT,
             issued_at TEXT NOT NULL CHECK(length(issued_at)=20),
             expires_at TEXT NOT NULL CHECK(length(expires_at)=20),
             CHECK(expires_at>issued_at)
           )""",
        """CREATE TABLE exact_package_authority_uses(
             authority_id TEXT PRIMARY KEY
               REFERENCES exact_package_authority_grants(authority_id) ON DELETE RESTRICT,
             grant_sha256 TEXT NOT NULL UNIQUE,
             use_record_bytes BLOB NOT NULL CHECK(typeof(use_record_bytes)='blob'),
             use_record_sha256 TEXT NOT NULL UNIQUE
               CHECK(length(use_record_sha256)=64
                 AND use_record_sha256 NOT GLOB '*[^0-9a-f]*'),
             state TEXT NOT NULL CHECK(state IN
               ('pending','click_intent_recorded','reconciled','revoked')),
             version INTEGER NOT NULL CHECK(version IN (1,2,3)),
             attempt_id TEXT UNIQUE,
             click_intent_sha256 TEXT UNIQUE,
             reconciliation_receipt_sha256 TEXT,
             reconciliation_time_receipt_sha256 TEXT UNIQUE
               REFERENCES authenticated_time_evidence(receipt_sha256) ON DELETE RESTRICT,
             reconciliation_state TEXT CHECK(reconciliation_state IS NULL OR
               reconciliation_state IN ('positive','ambiguous','negative','unknown')),
             revocation_reason TEXT,
             revoked_at TEXT,
             updated_at TEXT NOT NULL CHECK(length(updated_at)=20),
             CHECK(
               (state='pending' AND version=1 AND attempt_id IS NULL
                AND click_intent_sha256 IS NULL
                AND reconciliation_receipt_sha256 IS NULL
                AND reconciliation_time_receipt_sha256 IS NULL
                AND reconciliation_state IS NULL
                AND revocation_reason IS NULL AND revoked_at IS NULL)
               OR
               (state='click_intent_recorded' AND version=2
                AND attempt_id IS NOT NULL AND click_intent_sha256 IS NOT NULL
                AND reconciliation_receipt_sha256 IS NULL
                AND reconciliation_time_receipt_sha256 IS NULL
                AND reconciliation_state IS NULL
                AND revocation_reason IS NULL AND revoked_at IS NULL)
               OR
               (state='reconciled' AND version=3
                AND attempt_id IS NOT NULL AND click_intent_sha256 IS NOT NULL
                AND reconciliation_receipt_sha256 IS NOT NULL
                AND reconciliation_time_receipt_sha256 IS NOT NULL
                AND reconciliation_state IS NOT NULL
                AND revocation_reason IS NULL AND revoked_at IS NULL)
               OR
               (state='revoked' AND version=2 AND attempt_id IS NULL
                AND click_intent_sha256 IS NULL
                AND reconciliation_receipt_sha256 IS NULL
                AND reconciliation_time_receipt_sha256 IS NULL
                AND reconciliation_state IS NULL
                AND revocation_reason IS NOT NULL AND revoked_at IS NOT NULL)
             )
           )""",
        """CREATE TABLE submission_attempts(
             attempt_id TEXT PRIMARY KEY CHECK(length(trim(attempt_id))>0),
             authority_id TEXT NOT NULL
               REFERENCES exact_package_authority_grants(authority_id) ON DELETE RESTRICT,
             grant_sha256 TEXT NOT NULL UNIQUE,
             authority_use_version INTEGER NOT NULL CHECK(authority_use_version=2),
             click_intent_bytes BLOB NOT NULL CHECK(typeof(click_intent_bytes)='blob'),
             click_intent_sha256 TEXT NOT NULL UNIQUE,
             application_id TEXT NOT NULL,
             handoff_root_sha256 TEXT NOT NULL,
             artifact_set_sha256 TEXT NOT NULL,
             form_answers_sha256 TEXT NOT NULL,
             form_submission_bytes BLOB NOT NULL
               CHECK(typeof(form_submission_bytes)='blob'),
             form_submission_sha256 TEXT NOT NULL UNIQUE
               CHECK(length(form_submission_sha256)=64
                 AND form_submission_sha256 NOT GLOB '*[^0-9a-f]*'),
             provider TEXT NOT NULL CHECK(provider='greenhouse'),
             route_id TEXT NOT NULL,
             route_origin TEXT NOT NULL,
             environment TEXT NOT NULL CHECK(environment='synthetic'),
             page_url TEXT NOT NULL,
             form_action TEXT NOT NULL,
             form_method TEXT NOT NULL CHECK(form_method='post'),
             form_enctype TEXT NOT NULL CHECK(form_enctype='multipart/form-data'),
             submit_control_fingerprint_sha256 TEXT NOT NULL,
             browser_runtime_identity_sha256 TEXT NOT NULL,
             time_receipt_sha256 TEXT NOT NULL UNIQUE
               REFERENCES authenticated_time_evidence(receipt_sha256) ON DELETE RESTRICT,
             recorded_at TEXT NOT NULL CHECK(length(recorded_at)=20)
           )""",
        """CREATE TABLE jaa_events(
             event_id TEXT PRIMARY KEY CHECK(length(trim(event_id))>0),
             application_id TEXT NOT NULL
               REFERENCES application_admissions(application_id) ON DELETE RESTRICT,
             handoff_root_sha256 TEXT NOT NULL,
             event_type TEXT NOT NULL CHECK(event_type IN
               ('strategy_started','artifacts_ready','release_blocked','release_ready',
                'submission_authorized','submission_attempted','receipt_captured',
                'status_changed','outcome_recorded')),
             transition_sequence INTEGER NOT NULL CHECK(transition_sequence>0),
             detail_bytes BLOB NOT NULL CHECK(typeof(detail_bytes)='blob'),
             detail_sha256 TEXT NOT NULL,
             envelope_bytes BLOB NOT NULL CHECK(typeof(envelope_bytes)='blob'),
             envelope_root_sha256 TEXT NOT NULL UNIQUE,
             occurred_at TEXT NOT NULL CHECK(length(occurred_at)=20),
             UNIQUE(application_id,handoff_root_sha256,transition_sequence)
           )""",
        """CREATE TABLE jaa_event_receipts(
             object_sha256 TEXT PRIMARY KEY
               CHECK(length(object_sha256)=64
                 AND object_sha256 NOT GLOB '*[^0-9a-f]*'),
             exact_bytes BLOB NOT NULL CHECK(typeof(exact_bytes)='blob'),
             event_id TEXT NOT NULL UNIQUE
               REFERENCES jaa_events(event_id) ON DELETE RESTRICT,
             environment TEXT NOT NULL CHECK(environment IN ('synthetic','production')),
             reference_key TEXT NOT NULL CHECK(reference_key IN
               ('event.state_receipt','event.outcome_receipt')),
             type_id TEXT NOT NULL CHECK(type_id IN
               ('provider_state_receipt','application_outcome_receipt')),
             schema_version TEXT NOT NULL CHECK(schema_version IN
               ('jaa.provider-state-receipt.v1','jaa.application-outcome-receipt.v1')),
             subject_json TEXT NOT NULL CHECK(length(subject_json)>2),
             issued_at TEXT NOT NULL CHECK(length(issued_at)=20),
             valid_until TEXT CHECK(valid_until IS NULL),
             issuer_id TEXT NOT NULL CHECK(length(trim(issuer_id))>0),
             metadata_bytes BLOB NOT NULL CHECK(typeof(metadata_bytes)='blob'),
             metadata_sha256 TEXT NOT NULL UNIQUE
               CHECK(length(metadata_sha256)=64
                 AND metadata_sha256 NOT GLOB '*[^0-9a-f]*'),
             resolver_identity_sha256 TEXT NOT NULL
               CHECK(length(resolver_identity_sha256)=64
                 AND resolver_identity_sha256 NOT GLOB '*[^0-9a-f]*'),
             trust_root_id TEXT NOT NULL CHECK(length(trim(trust_root_id))>0),
             trust_proof_sha256 TEXT NOT NULL
               CHECK(length(trust_proof_sha256)=64
                 AND trust_proof_sha256 NOT GLOB '*[^0-9a-f]*'),
             occurred_at TEXT NOT NULL CHECK(length(occurred_at)=20),
             CHECK(issued_at<=occurred_at),
             CHECK(
               (reference_key='event.state_receipt'
                AND type_id='provider_state_receipt'
                AND schema_version='jaa.provider-state-receipt.v1')
               OR
               (reference_key='event.outcome_receipt'
                AND type_id='application_outcome_receipt'
                AND schema_version='jaa.application-outcome-receipt.v1')
             )
           )""",
        """CREATE TABLE jaa_event_outbox(
             event_id TEXT PRIMARY KEY
               REFERENCES jaa_events(event_id) ON DELETE RESTRICT,
             state TEXT NOT NULL CHECK(state IN ('pending','delivered')),
             delivery_attempts INTEGER NOT NULL DEFAULT 0 CHECK(delivery_attempts>=0),
             delivered_at TEXT,
             CHECK((state='pending' AND delivered_at IS NULL) OR
                   (state='delivered' AND delivered_at IS NOT NULL))
           )""",
        """CREATE TABLE unsupported_route_handoffs(
             handoff_sha256 TEXT PRIMARY KEY
               CHECK(length(handoff_sha256)=64
                 AND handoff_sha256 NOT GLOB '*[^0-9a-f]*'),
             handoff_bytes BLOB NOT NULL CHECK(typeof(handoff_bytes)='blob'),
             application_id TEXT,
             classification TEXT NOT NULL CHECK(classification IN
               ('unsupported_provider_or_widget','login','mfa','captcha',
                'terms_or_rate_limit','consent_missing_or_changed','dom_drift',
                'post_click_reconciliation')),
             browser_use_permitted INTEGER NOT NULL CHECK(browser_use_permitted IN (0,1)),
             time_receipt_sha256 TEXT NOT NULL UNIQUE
               REFERENCES authenticated_time_evidence(receipt_sha256) ON DELETE RESTRICT,
             created_at TEXT NOT NULL CHECK(length(created_at)=20),
             CHECK(browser_use_permitted=0 OR classification='unsupported_provider_or_widget')
           )""",
        """CREATE TRIGGER exact_package_grant_immutable_update
             BEFORE UPDATE ON exact_package_authority_grants
             BEGIN SELECT RAISE(ABORT,'exact-package grants are immutable'); END""",
        """CREATE TRIGGER authenticated_time_evidence_immutable_update
             BEFORE UPDATE ON authenticated_time_evidence
             BEGIN SELECT RAISE(ABORT,'authenticated time evidence is immutable'); END""",
        """CREATE TRIGGER authenticated_time_evidence_immutable_delete
             BEFORE DELETE ON authenticated_time_evidence
             BEGIN SELECT RAISE(ABORT,'authenticated time evidence is immutable'); END""",
        """CREATE TRIGGER exact_package_grant_immutable_delete
             BEFORE DELETE ON exact_package_authority_grants
             BEGIN SELECT RAISE(ABORT,'exact-package grants are immutable'); END""",
        """CREATE TRIGGER exact_package_use_transition_guard
             BEFORE UPDATE ON exact_package_authority_uses
             WHEN NOT (
               NEW.authority_id=OLD.authority_id AND NEW.grant_sha256=OLD.grant_sha256
               AND (
                 (OLD.state='pending' AND OLD.version=1
                  AND NEW.state='click_intent_recorded' AND NEW.version=2)
                 OR
                 (OLD.state='pending' AND OLD.version=1
                  AND NEW.state='revoked' AND NEW.version=2)
                 OR
                 (OLD.state='click_intent_recorded' AND OLD.version=2
                  AND NEW.state='reconciled' AND NEW.version=3)
               )
             )
             BEGIN SELECT RAISE(ABORT,'authority use transition is invalid'); END""",
        """CREATE TRIGGER exact_package_use_immutable_delete
             BEFORE DELETE ON exact_package_authority_uses
             BEGIN SELECT RAISE(ABORT,'authority use records cannot be deleted'); END""",
        """CREATE TRIGGER submission_attempt_immutable_update
             BEFORE UPDATE ON submission_attempts
             BEGIN SELECT RAISE(ABORT,'submission attempts are immutable'); END""",
        """CREATE TRIGGER submission_attempt_immutable_delete
             BEFORE DELETE ON submission_attempts
             BEGIN SELECT RAISE(ABORT,'submission attempts are immutable'); END""",
        """CREATE TRIGGER jaa_event_immutable_update
             BEFORE UPDATE ON jaa_events
             BEGIN SELECT RAISE(ABORT,'JAA events are immutable'); END""",
        """CREATE TRIGGER jaa_event_immutable_delete
             BEFORE DELETE ON jaa_events
             BEGIN SELECT RAISE(ABORT,'JAA events are immutable'); END""",
        """CREATE TRIGGER jaa_event_receipt_immutable_update
             BEFORE UPDATE ON jaa_event_receipts
             BEGIN SELECT RAISE(ABORT,'JAA event receipts are immutable'); END""",
        """CREATE TRIGGER jaa_event_receipt_immutable_delete
             BEFORE DELETE ON jaa_event_receipts
             BEGIN SELECT RAISE(ABORT,'JAA event receipts are immutable'); END""",
        """CREATE TRIGGER unsupported_route_handoff_immutable_update
             BEFORE UPDATE ON unsupported_route_handoffs
             BEGIN SELECT RAISE(ABORT,'route handoffs are immutable'); END""",
        """CREATE TRIGGER unsupported_route_handoff_immutable_delete
             BEFORE DELETE ON unsupported_route_handoffs
             BEGIN SELECT RAISE(ABORT,'route handoffs are immutable'); END""",
    ),
)


_JAA_OPERATIONAL_ROLLOVER_MIGRATION = Migration(
    11,
    "jaa_operational_release_rollover_v1",
    (
        """CREATE TABLE release_rollover_operations(
             operation_id TEXT PRIMARY KEY
               CHECK(length(operation_id)=69
                 AND substr(operation_id,1,5)='roll_'
                 AND substr(operation_id,6) NOT GLOB '*[^0-9a-f]*'),
             request_bytes BLOB NOT NULL CHECK(typeof(request_bytes)='blob'),
             request_sha256 TEXT NOT NULL UNIQUE
               CHECK(length(request_sha256)=64
                 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
             old_application_id TEXT NOT NULL
               REFERENCES application_admissions(application_id) ON DELETE RESTRICT,
             old_authority_id TEXT NOT NULL UNIQUE
               REFERENCES exact_package_authority_grants(authority_id) ON DELETE RESTRICT,
             old_grant_sha256 TEXT NOT NULL
               CHECK(length(old_grant_sha256)=64
                 AND old_grant_sha256 NOT GLOB '*[^0-9a-f]*'),
             old_archive_attempt_id TEXT NOT NULL CHECK(length(trim(old_archive_attempt_id))>0),
             old_archive_receipt_sha256 TEXT NOT NULL
               CHECK(length(old_archive_receipt_sha256)=64
                 AND old_archive_receipt_sha256 NOT GLOB '*[^0-9a-f]*'),
             fresh_archive_attempt_id TEXT NOT NULL UNIQUE
               CHECK(length(trim(fresh_archive_attempt_id))>0),
             requested_selection_sha256 TEXT NOT NULL
               CHECK(length(requested_selection_sha256)=64
                 AND requested_selection_sha256 NOT GLOB '*[^0-9a-f]*'),
             builder_identity_sha256 TEXT NOT NULL
               CHECK(length(builder_identity_sha256)=64
                 AND builder_identity_sha256 NOT GLOB '*[^0-9a-f]*'),
             route_id TEXT NOT NULL CHECK(length(trim(route_id))>0),
             state TEXT NOT NULL CHECK(state IN
               ('planned','candidate_built','built','grant_issued','reconciled')),
             build_bytes BLOB,
             build_sha256 TEXT UNIQUE,
             fresh_application_id TEXT
               REFERENCES application_admissions(application_id) ON DELETE RESTRICT,
             review_validation_sha256 TEXT UNIQUE
               REFERENCES application_forward_validations(validation_sha256)
               ON DELETE RESTRICT,
             fresh_archive_receipt_sha256 TEXT UNIQUE,
             operator_approval_bytes BLOB,
             operator_approval_sha256 TEXT UNIQUE,
             fresh_authority_id TEXT UNIQUE
               REFERENCES exact_package_authority_grants(authority_id) ON DELETE RESTRICT,
             fresh_grant_sha256 TEXT UNIQUE,
             submission_attempt_id TEXT UNIQUE,
             external_receipt_sha256 TEXT UNIQUE,
             reconciliation_state TEXT,
             post_count INTEGER,
             failure_count INTEGER NOT NULL DEFAULT 0 CHECK(failure_count>=0),
             last_error_code TEXT CHECK(last_error_code IS NULL OR
               (length(trim(last_error_code))>0 AND last_error_code=trim(last_error_code))),
             CHECK(build_bytes IS NULL OR typeof(build_bytes)='blob'),
             CHECK(build_sha256 IS NULL OR
               (length(build_sha256)=64 AND build_sha256 NOT GLOB '*[^0-9a-f]*')),
             CHECK(fresh_archive_receipt_sha256 IS NULL OR
               (length(fresh_archive_receipt_sha256)=64
                 AND fresh_archive_receipt_sha256 NOT GLOB '*[^0-9a-f]*')),
             CHECK(operator_approval_bytes IS NULL OR
               typeof(operator_approval_bytes)='blob'),
             CHECK(operator_approval_sha256 IS NULL OR
               (length(operator_approval_sha256)=64
                 AND operator_approval_sha256 NOT GLOB '*[^0-9a-f]*')),
             CHECK(fresh_grant_sha256 IS NULL OR
               (length(fresh_grant_sha256)=64
                 AND fresh_grant_sha256 NOT GLOB '*[^0-9a-f]*')),
             CHECK(external_receipt_sha256 IS NULL OR
               (length(external_receipt_sha256)=64
                 AND external_receipt_sha256 NOT GLOB '*[^0-9a-f]*')),
             CHECK(
               (state='planned'
                AND build_bytes IS NULL AND build_sha256 IS NULL
                AND fresh_application_id IS NULL
                AND review_validation_sha256 IS NULL
                AND fresh_archive_receipt_sha256 IS NULL
                AND operator_approval_bytes IS NULL
                AND operator_approval_sha256 IS NULL
                AND fresh_authority_id IS NULL AND fresh_grant_sha256 IS NULL
                AND submission_attempt_id IS NULL AND external_receipt_sha256 IS NULL
                AND reconciliation_state IS NULL AND post_count IS NULL)
               OR
               (state='candidate_built'
                AND build_bytes IS NOT NULL AND build_sha256 IS NOT NULL
                AND fresh_application_id IS NOT NULL
                AND review_validation_sha256 IS NOT NULL
                AND fresh_archive_receipt_sha256 IS NULL
                AND operator_approval_bytes IS NULL
                AND operator_approval_sha256 IS NULL
                AND fresh_authority_id IS NULL AND fresh_grant_sha256 IS NULL
                AND submission_attempt_id IS NULL AND external_receipt_sha256 IS NULL
                AND reconciliation_state IS NULL AND post_count IS NULL)
               OR
               (state='built'
                AND build_bytes IS NOT NULL AND build_sha256 IS NOT NULL
                AND fresh_application_id IS NOT NULL
                AND review_validation_sha256 IS NOT NULL
                AND fresh_archive_receipt_sha256 IS NOT NULL
                AND ((operator_approval_bytes IS NULL
                      AND operator_approval_sha256 IS NULL)
                     OR (operator_approval_bytes IS NOT NULL
                         AND operator_approval_sha256 IS NOT NULL))
                AND fresh_authority_id IS NULL AND fresh_grant_sha256 IS NULL
                AND submission_attempt_id IS NULL AND external_receipt_sha256 IS NULL
                AND reconciliation_state IS NULL AND post_count IS NULL)
               OR
               (state='grant_issued'
                AND build_bytes IS NOT NULL AND build_sha256 IS NOT NULL
                AND fresh_application_id IS NOT NULL
                AND review_validation_sha256 IS NOT NULL
                AND fresh_archive_receipt_sha256 IS NOT NULL
                AND operator_approval_bytes IS NOT NULL
                AND operator_approval_sha256 IS NOT NULL
                AND fresh_authority_id IS NOT NULL AND fresh_grant_sha256 IS NOT NULL
                AND submission_attempt_id IS NULL AND external_receipt_sha256 IS NULL
                AND reconciliation_state IS NULL AND post_count IS NULL)
               OR
               (state='reconciled'
                AND build_bytes IS NOT NULL AND build_sha256 IS NOT NULL
                AND fresh_application_id IS NOT NULL
                AND review_validation_sha256 IS NOT NULL
                AND fresh_archive_receipt_sha256 IS NOT NULL
                AND operator_approval_bytes IS NOT NULL
                AND operator_approval_sha256 IS NOT NULL
                AND fresh_authority_id IS NOT NULL AND fresh_grant_sha256 IS NOT NULL
                AND submission_attempt_id IS NOT NULL
                AND external_receipt_sha256 IS NOT NULL
                AND reconciliation_state='positive' AND post_count=1)
             ),
             CHECK(state='planned' OR last_error_code IS NULL)
           )""",
        """CREATE INDEX release_rollover_by_state
             ON release_rollover_operations(state,operation_id)""",
        """CREATE TRIGGER release_rollover_initial_identity_immutable
             BEFORE UPDATE ON release_rollover_operations
             WHEN NEW.operation_id<>OLD.operation_id
               OR NEW.request_bytes<>OLD.request_bytes
               OR NEW.request_sha256<>OLD.request_sha256
               OR NEW.old_application_id<>OLD.old_application_id
               OR NEW.old_authority_id<>OLD.old_authority_id
               OR NEW.old_grant_sha256<>OLD.old_grant_sha256
               OR NEW.old_archive_attempt_id<>OLD.old_archive_attempt_id
               OR NEW.old_archive_receipt_sha256<>OLD.old_archive_receipt_sha256
               OR NEW.fresh_archive_attempt_id<>OLD.fresh_archive_attempt_id
               OR NEW.requested_selection_sha256<>OLD.requested_selection_sha256
               OR NEW.builder_identity_sha256<>OLD.builder_identity_sha256
               OR NEW.route_id<>OLD.route_id
             BEGIN SELECT RAISE(ABORT,'rollover request identity is immutable'); END""",
        """CREATE TRIGGER release_rollover_evidence_immutable
             BEFORE UPDATE ON release_rollover_operations
             WHEN (OLD.build_bytes IS NOT NULL AND
                    (NEW.build_bytes IS NOT OLD.build_bytes
                     OR NEW.build_sha256 IS NOT OLD.build_sha256
                     OR NEW.fresh_application_id IS NOT OLD.fresh_application_id
                     OR NEW.review_validation_sha256 IS NOT
                        OLD.review_validation_sha256))
               OR (OLD.fresh_archive_receipt_sha256 IS NOT NULL AND
                    NEW.fresh_archive_receipt_sha256 IS NOT
                      OLD.fresh_archive_receipt_sha256)
               OR (OLD.operator_approval_bytes IS NOT NULL AND
                    (NEW.operator_approval_bytes IS NOT OLD.operator_approval_bytes
                     OR NEW.operator_approval_sha256 IS NOT
                        OLD.operator_approval_sha256))
               OR (OLD.fresh_authority_id IS NOT NULL AND
                    (NEW.fresh_authority_id IS NOT OLD.fresh_authority_id
                     OR NEW.fresh_grant_sha256 IS NOT OLD.fresh_grant_sha256))
               OR (OLD.submission_attempt_id IS NOT NULL AND
                    (NEW.submission_attempt_id IS NOT OLD.submission_attempt_id
                     OR NEW.external_receipt_sha256 IS NOT
                        OLD.external_receipt_sha256
                     OR NEW.reconciliation_state IS NOT OLD.reconciliation_state
                     OR NEW.post_count IS NOT OLD.post_count))
             BEGIN SELECT RAISE(ABORT,'rollover evidence is immutable once recorded'); END""",
        """CREATE TRIGGER release_rollover_transition_guard
             BEFORE UPDATE ON release_rollover_operations
             WHEN NOT (
               NEW.state=OLD.state
               OR (OLD.state='planned' AND NEW.state='candidate_built')
               OR (OLD.state='candidate_built' AND NEW.state='built')
               OR (OLD.state='built' AND NEW.state='grant_issued')
               OR (OLD.state='grant_issued' AND NEW.state='reconciled')
             )
               OR NEW.failure_count<OLD.failure_count
               OR (NEW.failure_count<>OLD.failure_count AND NOT
                    (OLD.state='planned' AND NEW.state='planned'))
             BEGIN SELECT RAISE(ABORT,'rollover state transition is invalid'); END""",
        """CREATE TRIGGER release_rollover_immutable_delete
             BEFORE DELETE ON release_rollover_operations
             BEGIN SELECT RAISE(ABORT,'rollover operations cannot be deleted'); END""",
    ),
)


_JAA_OPERATIONAL_RECONCILIATION_MIGRATION = Migration(
    12,
    "jaa_operational_exact_reconciliation_receipts_v1",
    (
        """CREATE TABLE exact_package_reconciliation_receipts(
             authority_id TEXT PRIMARY KEY
               REFERENCES exact_package_authority_uses(authority_id) ON DELETE RESTRICT,
             attempt_id TEXT NOT NULL UNIQUE
               REFERENCES submission_attempts(attempt_id) ON DELETE RESTRICT,
             grant_sha256 TEXT NOT NULL UNIQUE
               CHECK(length(grant_sha256)=64
                 AND grant_sha256 NOT GLOB '*[^0-9a-f]*'),
             receipt_bytes BLOB NOT NULL CHECK(typeof(receipt_bytes)='blob'),
             receipt_sha256 TEXT NOT NULL UNIQUE
               CHECK(length(receipt_sha256)=64
                 AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'),
             reconciliation_state TEXT NOT NULL CHECK(reconciliation_state IN
               ('positive','ambiguous','negative','unknown')),
             time_receipt_sha256 TEXT NOT NULL UNIQUE
               REFERENCES authenticated_time_evidence(receipt_sha256) ON DELETE RESTRICT,
             recorded_at TEXT NOT NULL CHECK(length(recorded_at)=20)
           )""",
        """CREATE TRIGGER exact_reconciliation_receipt_immutable_update
             BEFORE UPDATE ON exact_package_reconciliation_receipts
             BEGIN SELECT RAISE(ABORT,'reconciliation receipts are immutable'); END""",
        """CREATE TRIGGER exact_reconciliation_receipt_immutable_delete
             BEFORE DELETE ON exact_package_reconciliation_receipts
             BEGIN SELECT RAISE(ABORT,'reconciliation receipts are immutable'); END""",
    ),
)


_JAA_OPERATIONAL_REVIEW_RELEASE_JOIN_MIGRATION = Migration(
    13,
    "jaa_operational_employer_review_release_join_v1",
    (
        """ALTER TABLE exact_package_authority_grants
             ADD COLUMN employer_review_release_verification_bytes BLOB""",
        """ALTER TABLE exact_package_authority_grants
             ADD COLUMN employer_review_release_verification_sha256 TEXT""",
        """ALTER TABLE exact_package_authority_uses
             ADD COLUMN employer_review_release_verification_sha256 TEXT""",
        """ALTER TABLE submission_attempts
             ADD COLUMN employer_review_release_verification_bytes BLOB""",
        """ALTER TABLE submission_attempts
             ADD COLUMN employer_review_release_verification_sha256 TEXT""",
        """CREATE TRIGGER exact_package_review_grant_required_insert
             BEFORE INSERT ON exact_package_authority_grants
             WHEN typeof(NEW.employer_review_release_verification_bytes)<>'blob'
               OR NEW.employer_review_release_verification_sha256 IS NULL
               OR length(NEW.employer_review_release_verification_sha256)<>64
               OR NEW.employer_review_release_verification_sha256
                    GLOB '*[^0-9a-f]*'
             BEGIN SELECT RAISE(ABORT,
               'grant requires exact employer-review release verification'); END""",
        """CREATE TRIGGER exact_package_review_use_required_insert
             BEFORE INSERT ON exact_package_authority_uses
             WHEN NOT (
               (NEW.state IN ('pending','revoked')
                AND NEW.employer_review_release_verification_sha256 IS NULL)
               OR
               (NEW.state IN ('click_intent_recorded','reconciled')
                AND NEW.employer_review_release_verification_sha256 IS NOT NULL
                AND length(NEW.employer_review_release_verification_sha256)=64
                AND NEW.employer_review_release_verification_sha256
                      NOT GLOB '*[^0-9a-f]*')
             )
             BEGIN SELECT RAISE(ABORT,
               'authority use review-verification binding is invalid'); END""",
        """CREATE TRIGGER exact_package_review_use_required_update
             BEFORE UPDATE ON exact_package_authority_uses
             WHEN NOT (
               (OLD.state='pending' AND OLD.version=1
                AND NEW.state='revoked' AND NEW.version=2
                AND OLD.employer_review_release_verification_sha256 IS NULL
                AND NEW.employer_review_release_verification_sha256 IS NULL)
               OR
               (OLD.state='pending' AND OLD.version=1
                AND NEW.state='click_intent_recorded' AND NEW.version=2
                AND OLD.employer_review_release_verification_sha256 IS NULL
                AND NEW.employer_review_release_verification_sha256 IS NOT NULL
                AND length(NEW.employer_review_release_verification_sha256)=64
                AND NEW.employer_review_release_verification_sha256
                      NOT GLOB '*[^0-9a-f]*')
               OR
               (OLD.state='click_intent_recorded' AND OLD.version=2
                AND NEW.state='reconciled' AND NEW.version=3
                AND OLD.employer_review_release_verification_sha256 IS NOT NULL
                AND NEW.employer_review_release_verification_sha256
                      =OLD.employer_review_release_verification_sha256)
             )
             BEGIN SELECT RAISE(ABORT,
               'authority use review-verification binding is invalid'); END""",
        """CREATE TRIGGER submission_attempt_review_verification_required_insert
             BEFORE INSERT ON submission_attempts
             WHEN typeof(NEW.employer_review_release_verification_bytes)<>'blob'
               OR NEW.employer_review_release_verification_sha256 IS NULL
               OR length(NEW.employer_review_release_verification_sha256)<>64
               OR NEW.employer_review_release_verification_sha256
                    GLOB '*[^0-9a-f]*'
             BEGIN SELECT RAISE(ABORT,
               'submission attempt requires fresh review verification'); END""",
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
    _JAA_05_GAP_VERIFICATION_MIGRATION,
    _JAA_05_FIT_REASSESSMENT_MIGRATION,
)
JAA_06_MIGRATIONS: tuple[Migration, ...] = (
    *JAA_05_MIGRATIONS,
    _JAA_06_APPLICATION_STRATEGY_MIGRATION,
)
JAA_08_MIGRATIONS: tuple[Migration, ...] = (
    *JAA_06_MIGRATIONS,
    _JAA_08_RELEASE_GATE_MIGRATION,
)
JAA_OPERATIONAL_MIGRATIONS: tuple[Migration, ...] = (
    *JAA_08_MIGRATIONS,
    _JAA_OPERATIONAL_HANDOFF_MIGRATION,
    _JAA_OPERATIONAL_SUBMISSION_MIGRATION,
    _JAA_OPERATIONAL_ROLLOVER_MIGRATION,
    _JAA_OPERATIONAL_RECONCILIATION_MIGRATION,
    _JAA_OPERATIONAL_REVIEW_RELEASE_JOIN_MIGRATION,
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


def apply_jaa_06_migrations(path: str | Path) -> tuple[int, ...]:
    applied = MigrationRunner(path).apply(JAA_06_MIGRATIONS)
    with sqlite3.connect(path) as connection:
        verify_jaa06_installed_schema(connection)
    return applied


def apply_jaa_08_migrations(path: str | Path) -> tuple[int, ...]:
    applied = MigrationRunner(path).apply(JAA_08_MIGRATIONS)
    with sqlite3.connect(path) as connection:
        verify_jaa08_installed_schema(connection)
    return applied


def apply_jaa_operational_migrations(path: str | Path) -> tuple[int, ...]:
    """Apply the complete JAA schema plus strict handoff-admission storage."""
    applied = MigrationRunner(path).apply(JAA_OPERATIONAL_MIGRATIONS)
    with sqlite3.connect(path) as connection:
        verify_jaa08_installed_schema(connection)
        verify_jaa_operational_installed_schema(connection)
        verify_jaa_operational_submission_schema(connection)
        verify_jaa_operational_rollover_schema(connection)
        verify_jaa_operational_reconciliation_schema(connection)
    return applied
