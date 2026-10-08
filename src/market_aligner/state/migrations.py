"""Small checksum-verified SQLite migration registry.

This keeps schema evolution explicit and replayable without adopting a remote
database platform.  Each migration is a tuple of single SQLite statements so
the whole version and its ledger entry share one transaction.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

LEDGER_DDL = (
    "CREATE TABLE IF NOT EXISTS market_aligner_schema_migrations("
    "version INTEGER PRIMARY KEY,"
    "name TEXT NOT NULL,"
    "checksum TEXT NOT NULL,"
    "applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
)

_ALIAS_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_TABLE_PATTERN = re.compile(
    r"^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)(\s*[A-Za-z][A-Za-z0-9_\s]*)?$",
    re.IGNORECASE | re.DOTALL,
)


def _qualified_alias(alias: str) -> str:
    if not isinstance(alias, str) or not _ALIAS_PATTERN.fullmatch(alias):
        raise ValueError(f"schema alias must match {_ALIAS_PATTERN.pattern}: {alias!r}")
    return alias


class MigrationCompatibilityError(RuntimeError):
    """An existing schema/ledger does not match the expected canonical form."""


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


def _table_sql(connection: sqlite3.Connection, alias: str, table: str) -> str | None:
    row = connection.execute(
        f"SELECT sql FROM {alias}.sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return None if row is None else str(row[0])


def apply_on(
    connection: sqlite3.Connection,
    migrations: tuple[Migration, ...],
    schema_alias: str = "main",
) -> tuple[int, ...]:
    """Apply migrations on the CALLER's connection inside the caller's transaction.

    The caller owns connect/BEGIN/COMMIT and journal mode; this seam never
    begins, commits, connects, or creates directories. Every ledger operation
    is qualified to the already validated ``schema_alias``. Ledger creation,
    compatibility verification, migration DDL, and ledger INSERT all occur in
    the caller's outer transaction so injected failures roll back completely.
    """
    versions = [migration.version for migration in migrations]
    if versions != sorted(versions) or len(versions) != len(set(versions)):
        raise ValueError("migrations must be uniquely versioned in ascending order")
    applied_now: list[int] = []
    _qualified_alias(schema_alias)
    ledger = f"{schema_alias}.market_aligner_schema_migrations"
    existing_ledger_sql = _table_sql(connection, schema_alias, "market_aligner_schema_migrations")
    if existing_ledger_sql is not None:
        normalised = " ".join(existing_ledger_sql.split())
        expected = " ".join(
            LEDGER_DDL.replace("CREATE TABLE IF NOT EXISTS ", "CREATE TABLE ").split()
        )
        if normalised != expected:
            raise MigrationCompatibilityError(
                "existing migration ledger is not compatible with the canonical DDL"
            )
    else:
        connection.execute(
            LEDGER_DDL.replace(
                "CREATE TABLE IF NOT EXISTS market_aligner_schema_migrations",
                f"CREATE TABLE IF NOT EXISTS {schema_alias}.market_aligner_schema_migrations",
            )
        )
    for migration in migrations:
        existing = connection.execute(
            f"SELECT name,checksum FROM {ledger} WHERE version=?", (migration.version,)
        ).fetchone()
        if existing is not None:
            recorded_name = existing[0] if not isinstance(existing, sqlite3.Row) else existing["name"]
            recorded_checksum = (
                existing[1] if not isinstance(existing, sqlite3.Row) else existing["checksum"]
            )
            if recorded_name != migration.name or recorded_checksum != migration.checksum:
                raise MigrationCompatibilityError(
                    f"applied migration {migration.version} was modified after deployment"
                )
            for statement in migration.statements:
                _verify_or_apply_table(connection, schema_alias, statement, expect_only=True)
            continue
        for statement in migration.statements:
            _verify_or_apply_table(connection, schema_alias, statement, expect_only=False)
        connection.execute(
            f"INSERT INTO {ledger}(version,name,checksum) VALUES(?,?,?)",
            (migration.version, migration.name, migration.checksum),
        )
        applied_now.append(migration.version)
    return tuple(applied_now)


def _expected_facts(name: str) -> dict[str, tuple] | None:
    """Canonical independent facts for contract-owned tables (by name).

    Columns are exact (order/type/notnull/pk); unique index coverage is the
    exact set of column-tuples that must carry UNIQUE constraints; the
    foreign-key fact is the exact (table, from, to, on_delete) list. CHECK
    constraints have no pragma and are guaranteed by byte-exact DDL equality.
    """
    if name != "processing_receipts":
        return None
    columns = (
        ("operation_id", "TEXT", 1, 1),
        ("profile_id", "TEXT", 1, 0),
        ("job_key", "TEXT", 1, 0),
        ("track", "TEXT", 1, 0),
        ("binding_sha256", "TEXT", 1, 0),
        ("envelope_file_sha256", "TEXT", 1, 0),
        ("envelope_semantic_sha256", "TEXT", 1, 0),
        ("normalized_sha256", "TEXT", 1, 0),
        ("assessment_payload_hash", "TEXT", 1, 0),
        ("event_id", "INTEGER", 1, 0),
        ("receipt_self_hash", "TEXT", 1, 0),
        ("receipt_file_sha256", "TEXT", 1, 0),
        ("receipt_bytes", "BLOB", 1, 0),
        ("created_at", "TEXT", 1, 0),
    )
    uniques = (
        ("binding_sha256",),
        ("receipt_file_sha256",),
        ("profile_id", "job_key"),
    )
    foreign_keys = (("assessment_events", "event_id", "id", "RESTRICT"),)
    return {"columns": columns, "uniques": uniques, "foreign_keys": foreign_keys}


def _verify_table_facts(connection: sqlite3.Connection, alias: str, name: str) -> None:
    facts = _expected_facts(name)
    if facts is None and name == "eligibility_receipts":
        facts = ELIGIBILITY_EXPECTED_FACTS
    if facts is None:
        return
    info_rows = connection.execute(f"PRAGMA {alias}.table_info({name})").fetchall()
    observed_columns = []
    for row in info_rows:
        _cid, column_name, column_type, notnull, _default, pk = (
            row[0], row[1], row[2], row[3], row[4], row[5],
        )
        observed_columns.append((column_name, (column_type or "").upper(), int(notnull), int(pk)))
    if tuple(observed_columns) != facts["columns"]:
        raise MigrationCompatibilityError(
            f"table {name} columns do not match the canonical contract facts"
        )
    indexes = connection.execute(f"PRAGMA {alias}.index_list({name})").fetchall()
    unique_sets: set[tuple[str, ...]] = set()
    for index_row in indexes:
        # Row shapes vary by sqlite3 version; find origin/unique positionally
        # via the header-free PRAGMA layout: seq,name,unique,origin,partial.
        unique_flag = index_row[2]
        origin = index_row[3]
        if not unique_flag or origin == "pk":
            continue
        index_name = index_row[1]
        columns = tuple(
            info_row[2]
            for info_row in connection.execute(
                f"PRAGMA {alias}.index_info({index_name})"
            ).fetchall()
        )
        unique_sets.add(columns)
    if unique_sets != {tuple(item) for item in facts["uniques"]}:
        raise MigrationCompatibilityError(
            f"table {name} unique-index facts do not match the canonical contract"
        )
    foreign_keys = connection.execute(
        f"PRAGMA {alias}.foreign_key_list({name})"
    ).fetchall()
    observed_fks = tuple(
        (row[2], row[3], row[4], row[6]) for row in foreign_keys
    )
    if observed_fks != facts["foreign_keys"]:
        raise MigrationCompatibilityError(
            f"table {name} foreign-key facts do not match the canonical contract"
        )


def _verify_or_apply_table(
    connection: sqlite3.Connection,
    alias: str,
    statement: str,
    *,
    expect_only: bool,
) -> None:
    """Execute one CREATE TABLE DDL in the validated alias or verify it exactly.

    The table name and trailing table options (e.g. ``STRICT``) are parsed
    robustly; creation runs qualified into ``alias`` while verification reads
    the UNQUALIFIED text SQLite records in sqlite_master. Byte-exact DDL
    equality carries every CHECK constraint; pragma facts independently verify
    columns, unique indexes, and foreign keys for contract-owned tables.
    """
    _qualified_alias(alias)
    compact = " ".join(statement.strip().split())
    if not compact.upper().startswith("CREATE TABLE"):
        connection.execute(statement)
        return
    match = _TABLE_PATTERN.match(compact)
    if match is None:
        raise ValueError(f"migration DDL is not a plain CREATE TABLE: {statement[:60]!r}")
    name = match.group(1)
    body = match.group(2)
    suffix = (match.group(3) or "").strip()
    expected_unqualified = " ".join(f"CREATE TABLE {name}({body}){suffix}".split())
    existing = _table_sql(connection, alias, name)
    if existing is None:
        if expect_only:
            raise MigrationCompatibilityError(
                f"ledger records {name} but the table is absent"
            )
        qualified = f"CREATE TABLE {alias}.{name}({body}){suffix}"
        connection.execute(" ".join(qualified.split()))
        created = _table_sql(connection, alias, name)
        if created is None:
            raise MigrationCompatibilityError(
                f"table {name} was not created in schema alias {alias}"
            )
        stored = " ".join(created.split())
        if stored != expected_unqualified:
            raise MigrationCompatibilityError(f"table {name} did not take the canonical DDL")
        _verify_table_facts(connection, alias, name)
        return
    stored = " ".join(existing.split())
    if stored != expected_unqualified:
        raise MigrationCompatibilityError(
            f"existing table {name} does not match the canonical DDL"
        )
    _verify_table_facts(connection, alias, name)


class MigrationRunner:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS market_aligner_schema_migrations(
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
        try:
            for migration in migrations:
                existing = conn.execute(
                    "SELECT name,checksum FROM market_aligner_schema_migrations WHERE version=?",
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
                        """INSERT INTO market_aligner_schema_migrations(version,name,checksum)
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


FIT001_RECEIPTS_DDL = (
    "CREATE TABLE processing_receipts("
    "operation_id TEXT PRIMARY KEY,"
    "profile_id TEXT NOT NULL,"
    "job_key TEXT NOT NULL,"
    "track TEXT NOT NULL,"
    "binding_sha256 TEXT NOT NULL UNIQUE,"
    "envelope_file_sha256 TEXT NOT NULL,"
    "envelope_semantic_sha256 TEXT NOT NULL,"
    "normalized_sha256 TEXT NOT NULL,"
    "assessment_payload_hash TEXT NOT NULL,"
    "event_id INTEGER NOT NULL,"
    "receipt_self_hash TEXT NOT NULL,"
    "receipt_file_sha256 TEXT NOT NULL UNIQUE,"
    "receipt_bytes BLOB NOT NULL,"
    "created_at TEXT NOT NULL,"
    "UNIQUE(profile_id,job_key),"
    "FOREIGN KEY(event_id) REFERENCES assessment_events(id) ON DELETE RESTRICT,"
    "CHECK(length(operation_id) BETWEEN 8 AND 64),"
    "CHECK(length(profile_id)=36),"
    "CHECK(length(job_key) BETWEEN 3 AND 256),"
    "CHECK(length(track) BETWEEN 1 AND 128),"
    "CHECK(length(binding_sha256)=64 AND binding_sha256 NOT GLOB '*[^0-9a-f]*'),"
    "CHECK(length(envelope_file_sha256)=64 AND envelope_file_sha256 NOT GLOB '*[^0-9a-f]*'),"
    "CHECK(length(envelope_semantic_sha256)=64 AND envelope_semantic_sha256 NOT GLOB '*[^0-9a-f]*'),"
    "CHECK(length(normalized_sha256)=64 AND normalized_sha256 NOT GLOB '*[^0-9a-f]*'),"
    "CHECK(length(assessment_payload_hash)=64 AND assessment_payload_hash NOT GLOB '*[^0-9a-f]*'),"
    "CHECK(event_id>0),"
    "CHECK(length(receipt_self_hash)=64 AND receipt_self_hash NOT GLOB '*[^0-9a-f]*'),"
    "CHECK(length(receipt_file_sha256)=64 AND receipt_file_sha256 NOT GLOB '*[^0-9a-f]*'),"
    "CHECK(length(receipt_bytes) BETWEEN 3 AND 4194304),"
    "CHECK(length(created_at) BETWEEN 20 AND 64)"
    ") STRICT"
)

FIT001_PROCESSING_RECEIPTS = Migration(
    version=1,
    name="fit001_processing_receipts_v1",
    statements=(FIT001_RECEIPTS_DDL,),
)
ELIGIBILITY_RECEIPTS_DDL = (
    "CREATE TABLE eligibility_receipts(operation_id TEXT PRIMARY KEY,fit_operation_id TEXT NOT NULL UNIQUE,profile_id TEXT NOT NULL,job_key TEXT NOT NULL,track TEXT NOT NULL,binding_sha256 TEXT NOT NULL UNIQUE,envelope_file_sha256 TEXT NOT NULL,envelope_semantic_sha256 TEXT NOT NULL,fit_receipt_self_hash TEXT NOT NULL,fit_receipt_file_sha256 TEXT NOT NULL,fit_binding_sha256 TEXT NOT NULL,fit_event_id INTEGER NOT NULL,fit_event_payload_sha256 TEXT NOT NULL,fit_raw_snapshot_sha256 TEXT NOT NULL,fit_profile_context_sha256 TEXT NOT NULL,fit_extraction_output_sha256 TEXT NOT NULL,fit_alignment_output_sha256 TEXT NOT NULL,fit_normalized_json_sha256 TEXT NOT NULL,fit_assessment_payload_hash TEXT NOT NULL,candidate_facts_sha256 TEXT NOT NULL,vacancy_facts_sha256 TEXT NOT NULL,decision_policy_sha256 TEXT NOT NULL,decision_input_sha256 TEXT NOT NULL,iso_jurisdiction_set_sha256 TEXT NOT NULL,decision TEXT NOT NULL CHECK(decision IN ('pass','review','reject')),reasons_json TEXT NOT NULL,unknowns_json TEXT NOT NULL,event_id INTEGER NOT NULL,event_payload_sha256 TEXT NOT NULL,receipt_self_hash TEXT NOT NULL,receipt_file_sha256 TEXT NOT NULL UNIQUE,receipt_bytes BLOB NOT NULL,eligibility_authority INTEGER NOT NULL CHECK(eligibility_authority=(decision='pass')),research_authority INTEGER NOT NULL CHECK(research_authority=0),application_authority INTEGER NOT NULL CHECK(application_authority=0),release_authority INTEGER NOT NULL CHECK(release_authority=0),submission_authority INTEGER NOT NULL CHECK(submission_authority=0),created_at TEXT NOT NULL,UNIQUE(profile_id,job_key),FOREIGN KEY(fit_operation_id) REFERENCES processing_receipts(operation_id) ON DELETE RESTRICT,FOREIGN KEY(fit_event_id) REFERENCES assessment_events(id) ON DELETE RESTRICT,FOREIGN KEY(event_id) REFERENCES assessment_events(id) ON DELETE RESTRICT,CHECK(length(binding_sha256)=64 AND binding_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(envelope_file_sha256)=64 AND envelope_file_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(envelope_semantic_sha256)=64 AND envelope_semantic_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_receipt_self_hash)=64 AND fit_receipt_self_hash NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_receipt_file_sha256)=64 AND fit_receipt_file_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_binding_sha256)=64 AND fit_binding_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_event_payload_sha256)=64 AND fit_event_payload_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_raw_snapshot_sha256)=64 AND fit_raw_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_profile_context_sha256)=64 AND fit_profile_context_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_extraction_output_sha256)=64 AND fit_extraction_output_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_alignment_output_sha256)=64 AND fit_alignment_output_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_normalized_json_sha256)=64 AND fit_normalized_json_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_assessment_payload_hash)=64 AND fit_assessment_payload_hash NOT GLOB '*[^0-9a-f]*'),CHECK(length(candidate_facts_sha256)=64 AND candidate_facts_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(vacancy_facts_sha256)=64 AND vacancy_facts_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(decision_policy_sha256)=64 AND decision_policy_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(decision_input_sha256)=64 AND decision_input_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(iso_jurisdiction_set_sha256)=64 AND iso_jurisdiction_set_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(event_payload_sha256)=64 AND event_payload_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(receipt_self_hash)=64 AND receipt_self_hash NOT GLOB '*[^0-9a-f]*'),CHECK(length(receipt_file_sha256)=64 AND receipt_file_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(operation_id) BETWEEN 8 AND 64),CHECK(length(fit_operation_id) BETWEEN 8 AND 64),CHECK(length(profile_id)=36),CHECK(length(job_key) BETWEEN 3 AND 256),CHECK(length(track) BETWEEN 1 AND 128),CHECK(fit_event_id>0),CHECK(event_id>0),CHECK(length(reasons_json) BETWEEN 2 AND 65536),CHECK(length(unknowns_json) BETWEEN 2 AND 65536),CHECK(length(receipt_bytes) BETWEEN 3 AND 8388608),CHECK(length(created_at) BETWEEN 20 AND 64)) STRICT"
)

ELIGIBILITY_ELIGIBILITY_RECEIPTS = Migration(
    version=2,
    name="eligibility001_eligibility_receipts_v1",
    statements=(ELIGIBILITY_RECEIPTS_DDL,),
)


ELIGIBILITY_EXPECTED_FACTS = {
    "columns": (
        ("operation_id", "TEXT", 1, 1),
        ("fit_operation_id", "TEXT", 1, 0),
        ("profile_id", "TEXT", 1, 0),
        ("job_key", "TEXT", 1, 0),
        ("track", "TEXT", 1, 0),
        ("binding_sha256", "TEXT", 1, 0),
        ("envelope_file_sha256", "TEXT", 1, 0),
        ("envelope_semantic_sha256", "TEXT", 1, 0),
        ("fit_receipt_self_hash", "TEXT", 1, 0),
        ("fit_receipt_file_sha256", "TEXT", 1, 0),
        ("fit_binding_sha256", "TEXT", 1, 0),
        ("fit_event_id", "INTEGER", 1, 0),
        ("fit_event_payload_sha256", "TEXT", 1, 0),
        ("fit_raw_snapshot_sha256", "TEXT", 1, 0),
        ("fit_profile_context_sha256", "TEXT", 1, 0),
        ("fit_extraction_output_sha256", "TEXT", 1, 0),
        ("fit_alignment_output_sha256", "TEXT", 1, 0),
        ("fit_normalized_json_sha256", "TEXT", 1, 0),
        ("fit_assessment_payload_hash", "TEXT", 1, 0),
        ("candidate_facts_sha256", "TEXT", 1, 0),
        ("vacancy_facts_sha256", "TEXT", 1, 0),
        ("decision_policy_sha256", "TEXT", 1, 0),
        ("decision_input_sha256", "TEXT", 1, 0),
        ("iso_jurisdiction_set_sha256", "TEXT", 1, 0),
        ("decision", "TEXT", 1, 0),
        ("reasons_json", "TEXT", 1, 0),
        ("unknowns_json", "TEXT", 1, 0),
        ("event_id", "INTEGER", 1, 0),
        ("event_payload_sha256", "TEXT", 1, 0),
        ("receipt_self_hash", "TEXT", 1, 0),
        ("receipt_file_sha256", "TEXT", 1, 0),
        ("receipt_bytes", "BLOB", 1, 0),
        ("eligibility_authority", "INTEGER", 1, 0),
        ("research_authority", "INTEGER", 1, 0),
        ("application_authority", "INTEGER", 1, 0),
        ("release_authority", "INTEGER", 1, 0),
        ("submission_authority", "INTEGER", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "uniques": (
        ("binding_sha256",),
        ("fit_operation_id",),
        ("profile_id", "job_key"),
        ("receipt_file_sha256",),
    ),
    "foreign_keys": (
        ("assessment_events", "event_id", "id", "RESTRICT"),
        ("assessment_events", "fit_event_id", "id", "RESTRICT"),
        ("processing_receipts", "fit_operation_id", "operation_id",
         "RESTRICT"),
    ),
}
