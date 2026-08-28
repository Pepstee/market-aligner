from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from market_aligner.state.migrations import (
    ELIGIBILITY_ELIGIBILITY_RECEIPTS,
    ELIGIBILITY_EXPECTED_FACTS,
    FIT001_PROCESSING_RECEIPTS,
    FIT001_PROCESSING_RECEIPTS as _FIT001,
    Migration,
    MigrationCompatibilityError,
    MigrationRunner,
    apply_on,
)


class MigrationRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "career.sqlite3"
        self.runner = MigrationRunner(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_migrations_are_ordered_idempotent_and_checksummed(self) -> None:
        migrations = (
            Migration(1, "create_items", ("CREATE TABLE items(id TEXT PRIMARY KEY)",)),
            Migration(2, "add_name", ("ALTER TABLE items ADD COLUMN name TEXT",)),
        )
        self.assertEqual(self.runner.apply(migrations), (1, 2))
        self.assertEqual(self.runner.apply(migrations), ())
        changed = (
            Migration(1, "create_items", ("CREATE TABLE items(id INTEGER PRIMARY KEY)",)),
        )
        with self.assertRaisesRegex(RuntimeError, "modified"):
            self.runner.apply(changed)

    def test_failed_migration_rolls_back_statements_and_ledger(self) -> None:
        broken = Migration(
            1,
            "broken",
            ("CREATE TABLE temporary_value(id TEXT)", "INSERT INTO missing_table VALUES(1)"),
        )
        with self.assertRaises(sqlite3.OperationalError):
            self.runner.apply((broken,))
        conn = sqlite3.connect(self.path)
        try:
            table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='temporary_value'"
            ).fetchone()
            ledger = conn.execute(
                "SELECT COUNT(*) FROM market_aligner_schema_migrations"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertIsNone(table)
        self.assertEqual(ledger, 0)

    def test_registry_must_be_strictly_ascending(self) -> None:
        with self.assertRaisesRegex(ValueError, "ascending"):
            self.runner.apply((
                Migration(2, "second", ("SELECT 1",)),
                Migration(1, "first", ("SELECT 1",)),
            ))


class ApplyOnSeamTests(unittest.TestCase):
    """Caller-owned transactional seam tests (FIT-001 §14)."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.main_path = Path(self.temporary.name).resolve() / "assessments.sqlite3"
        self.vacancy_path = Path(self.temporary.name).resolve() / "vacancies.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _connect_with_alias(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.main_path)
        connection.execute("CREATE TABLE assessment_events(id INTEGER PRIMARY KEY)")
        connection.commit()
        connection.execute("ATTACH DATABASE ? AS vacancy", (str(self.vacancy_path),))
        return connection

    def test_fit_ddl_and_checksum_are_canonical(self) -> None:
        self.assertEqual(
            "19c0307b99175dbbfbd69ef64807a9b172c5e6abf3fa6bb117b5f43b21ce163f",
            FIT001_PROCESSING_RECEIPTS.checksum,
        )
        document = (
            Path(__file__).resolve().parent.parent
            / "docs"
            / "processing"
            / "FIT-001_PROCESS_ONE_CONTRACT.md"
        )
        contract_sql = [
            line[4:]
            for line in document.read_text(encoding="utf-8").splitlines()
            if line.startswith("    CREATE TABLE processing_receipts")
        ][0]
        self.assertEqual(FIT001_PROCESSING_RECEIPTS.statements[0], contract_sql)

    def test_absent_ledger_bootstrap_creates_both_in_attached_alias_only(self) -> None:
        connection = self._connect_with_alias()
        try:
            connection.execute("BEGIN IMMEDIATE")
            applied = apply_on(
                connection, (FIT001_PROCESSING_RECEIPTS,), schema_alias="vacancy"
            )
            self.assertEqual((1,), applied)
            vacancy_tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM vacancy.sqlite_master WHERE type='table'"
                ).fetchall()
            }
            main_tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM main.sqlite_master WHERE type='table'"
                ).fetchall()
            }
            # BOTH the receipt table and the ledger live in the attached alias.
            self.assertIn("processing_receipts", vacancy_tables)
            self.assertIn("market_aligner_schema_migrations", vacancy_tables)
            # And neither leaked into main.
            self.assertNotIn("processing_receipts", main_tables)
            self.assertNotIn("market_aligner_schema_migrations", main_tables)
            connection.execute("ROLLBACK")
        finally:
            connection.close()

    def test_exact_compatible_replay_is_idempotent(self) -> None:
        connection = self._connect_with_alias()
        try:
            connection.execute("BEGIN IMMEDIATE")
            first = apply_on(connection, (FIT001_PROCESSING_RECEIPTS,), schema_alias="vacancy")
            connection.execute("COMMIT")
            self.assertEqual((1,), first)
            connection.execute("BEGIN IMMEDIATE")
            again = apply_on(connection, (FIT001_PROCESSING_RECEIPTS,), schema_alias="vacancy")
            connection.execute("COMMIT")
            self.assertEqual((), again)
        finally:
            connection.close()

    def test_mismatched_existing_table_refuses(self) -> None:
        connection = self._connect_with_alias()
        try:
            connection.execute("CREATE TABLE vacancy.processing_receipts(operation_id TEXT)")
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(MigrationCompatibilityError):
                apply_on(connection, (FIT001_PROCESSING_RECEIPTS,), schema_alias="vacancy")
            connection.execute("ROLLBACK")
        finally:
            connection.close()

    def test_caller_owned_rollback_removes_ledger_and_table(self) -> None:
        """One caller BEGIN; the seam must not begin/commit inside itself."""
        connection = self._connect_with_alias()
        try:
            connection.execute("BEGIN IMMEDIATE")
            inside = connection.execute("PRAGMA vacancy.journal_mode").fetchone()
            self.assertIsNotNone(inside)
            before_in_transaction = connection.in_transaction
            self.assertTrue(before_in_transaction)
            apply_on(connection, (FIT001_PROCESSING_RECEIPTS,), schema_alias="vacancy")
            # Still the caller's single transaction — no nested commit happened.
            self.assertTrue(connection.in_transaction)
            connection.execute("ROLLBACK")
            vacancy_tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM vacancy.sqlite_master WHERE type='table'"
                ).fetchall()
            }
            self.assertNotIn("processing_receipts", vacancy_tables)
            self.assertNotIn("market_aligner_schema_migrations", vacancy_tables)
        finally:
            connection.close()

    def test_invalid_alias_refuses_closed(self) -> None:
        connection = self._connect_with_alias()
        try:
            for alias in ("main; DROP TABLE x", 'vacancy--', 'v"', "", "has space"):
                with self.assertRaises(ValueError):
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        apply_on(
                            connection, (FIT001_PROCESSING_RECEIPTS,), schema_alias=alias
                        )
                    finally:
                        connection.execute("ROLLBACK")
        finally:
            connection.close()


# ==========================================================================
# ELIGIBILITY-001 migration v2 contract (accepted document, section 17)
# ==========================================================================

_ELIG_CKSUM = "58c47ff2441edd52f235962e61b189b1ec8c1ed5e3bc081e9305983df944f17d"


class EligibilityMigrationV2Tests(unittest.TestCase):
    def test_checksum_and_shape(self):
        self.assertEqual(ELIGIBILITY_ELIGIBILITY_RECEIPTS.version, 2)
        self.assertEqual(ELIGIBILITY_ELIGIBILITY_RECEIPTS.name,
                         "eligibility001_eligibility_receipts_v1")
        self.assertEqual(len(ELIGIBILITY_ELIGIBILITY_RECEIPTS.statements), 1)
        ddl = ELIGIBILITY_ELIGIBILITY_RECEIPTS.statements[0]
        self.assertTrue(ddl.endswith(") STRICT"))
        self.assertNotIn("\n", ddl)
        self.assertEqual(len(ddl), 4190)
        body = json.dumps(
            {"version": 2, "name": "eligibility001_eligibility_receipts_v1",
             "statements": [ddl]},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(hashlib.sha256(body.encode("utf-8")).hexdigest(),
                         _ELIG_CKSUM)
        self.assertIn(
            "CHECK(decision IN ('pass','review','reject'))", ddl)
        self.assertIn(
            "CHECK(eligibility_authority=(decision='pass'))", ddl)
        for fragment in (
            "UNIQUE(profile_id,job_key)",
            "FOREIGN KEY(fit_operation_id) REFERENCES "
            "processing_receipts(operation_id) ON DELETE RESTRICT",
            "FOREIGN KEY(fit_event_id) REFERENCES assessment_events(id) "
            "ON DELETE RESTRICT",
            "FOREIGN KEY(event_id) REFERENCES assessment_events(id) "
            "ON DELETE RESTRICT",
            "event_payload_sha256 TEXT NOT NULL",
            "CHECK(length(receipt_bytes) BETWEEN 3 AND 8388608)",
        ):
            self.assertIn(fragment, ddl)

    def test_expected_facts(self):
        facts = ELIGIBILITY_EXPECTED_FACTS
        self.assertEqual(len(facts["columns"]), 38)
        self.assertEqual(facts["columns"][0],
                         ("operation_id", "TEXT", 1, 1))
        self.assertEqual(set(facts["uniques"]),
                         {("fit_operation_id",), ("binding_sha256",),
                          ("receipt_file_sha256",), ("profile_id", "job_key")})
        self.assertEqual(
            facts["foreign_keys"],
            (("assessment_events", "event_id", "id", "RESTRICT"),
             ("assessment_events", "fit_event_id", "id", "RESTRICT"),
             ("processing_receipts", "fit_operation_id",
              "operation_id", "RESTRICT")))

    def _prepare_v1(self, connection):
        # Bootstrap exactly like production: the owner creates the ledger and
        # the FIT table itself so sqlite_master holds the canonical form.
        apply_on(connection, (_FIT001,))
        connection.commit()

    def test_apply_creates_only_v2_when_v1_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "a.sqlite3")
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS market_aligner_schema_migrations("
                    "version INTEGER PRIMARY KEY,name TEXT NOT NULL,"
                    "checksum TEXT NOT NULL,"
                    "applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
                self._prepare_v1(conn)
                conn.commit()
                applied = apply_on(conn, (_FIT001,
                                          ELIGIBILITY_ELIGIBILITY_RECEIPTS))
                conn.commit()
                self.assertEqual(applied, (2,))
                rows = conn.execute(
                    "SELECT version FROM market_aligner_schema_migrations"
                    " ORDER BY version").fetchall()
                self.assertEqual(rows, [(1,), (2,)])
                cols = conn.execute(
                    "SELECT COUNT(*) FROM pragma_table_info"
                    "('eligibility_receipts')").fetchone()[0]
                self.assertEqual(cols, 38)
                # verify-only replay applies nothing new
                self.assertEqual(
                    apply_on(conn, (_FIT001, ELIGIBILITY_ELIGIBILITY_RECEIPTS)),
                    ())
            finally:
                conn.close()

    def test_outer_rollback_removes_v2_table_ledger_row_and_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "a.sqlite3")
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS market_aligner_schema_migrations("
                    "version INTEGER PRIMARY KEY,name TEXT NOT NULL,"
                    "checksum TEXT NOT NULL,"
                    "applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
                conn.execute("CREATE TABLE assessment_events("
                             "id INTEGER PRIMARY KEY AUTOINCREMENT)")
                self._prepare_v1(conn)
                FH = "f" * 64
                conn.execute(
                    "INSERT INTO assessment_events(id) VALUES(1)")
                conn.execute(
                    "INSERT INTO processing_receipts(operation_id,profile_id,"
                    "job_key,track,binding_sha256,envelope_file_sha256,"
                    "envelope_semantic_sha256,normalized_sha256,"
                    "assessment_payload_hash,event_id,receipt_self_hash,"
                    "receipt_file_sha256,receipt_bytes,created_at)"
                    " VALUES(:operation_id,:profile_id,:job_key,:track,"
                    ":binding_sha256,:envelope_file_sha256,"
                    ":envelope_semantic_sha256,:normalized_sha256,"
                    ":assessment_payload_hash,1,:receipt_self_hash,"
                    ":receipt_file_sha256,:receipt_bytes,:created_at)",
                    {"operation_id": "fit-op-ok-00001",
                     "profile_id": "prf_" + "b" * 32,
                     "job_key": "board:1", "track": "backend",
                     "binding_sha256": FH, "envelope_file_sha256": FH,
                     "envelope_semantic_sha256": FH,
                     "normalized_sha256": FH,
                     "assessment_payload_hash": FH,
                     "receipt_self_hash": FH,
                     "receipt_file_sha256": FH,
                     "receipt_bytes": b"xyz",
                     "created_at": "2026-01-01T00:00:00.000000Z"})
                conn.commit()
                H = "a" * 64
                conn.execute("BEGIN IMMEDIATE")
                apply_on(conn, (_FIT001, ELIGIBILITY_ELIGIBILITY_RECEIPTS))
                conn.execute(
                    "INSERT INTO eligibility_receipts(operation_id,"
                    "fit_operation_id,profile_id,job_key,track,binding_sha256,"
                    "envelope_file_sha256,envelope_semantic_sha256,"
                    "fit_receipt_self_hash,fit_receipt_file_sha256,"
                    "fit_binding_sha256,fit_event_id,fit_event_payload_sha256,"
                    "fit_raw_snapshot_sha256,fit_profile_context_sha256,"
                    "fit_extraction_output_sha256,fit_alignment_output_sha256,"
                    "fit_normalized_json_sha256,fit_assessment_payload_hash,"
                    "candidate_facts_sha256,vacancy_facts_sha256,"
                    "decision_policy_sha256,decision_input_sha256,"
                    "iso_jurisdiction_set_sha256,decision,reasons_json,"
                    "unknowns_json,event_id,event_payload_sha256,"
                    "receipt_self_hash,receipt_file_sha256,receipt_bytes,"
                    "eligibility_authority,research_authority,"
                    "application_authority,release_authority,"
                    "submission_authority,created_at) VALUES("
                    + ",".join(["?"] * 38) + ")",
                    ("op-eligible-01", "fit-op-ok-00001",
                     "prf_" + "b" * 32, "board:1", "backend", H, H, H,
                     H, H, H, 1, H, H, H, H, H, H, H, H, H, H, H, H,
                     "pass", "[]", "[]", 1, "7" * 64, "d" * 64,
                     "e" * 64, b"xyz", 1, 0, 0, 0, 0,
                     "2026-08-26T00:00:00.000000Z"))
                conn.execute("ROLLBACK")
                gone = conn.execute(
                    "SELECT name FROM sqlite_master WHERE name="
                    "'eligibility_receipts'").fetchall()
                self.assertEqual(gone, [])
                ledger = conn.execute(
                    "SELECT version FROM market_aligner_schema_migrations"
                    ).fetchall()
                self.assertEqual(ledger, [(1,)])
            finally:
                conn.close()

    def test_v1_mismatch_refuses_before_anything(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "a.sqlite3")
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS market_aligner_schema_migrations("
                    "version INTEGER PRIMARY KEY,name TEXT NOT NULL,"
                    "checksum TEXT NOT NULL,"
                    "applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
                conn.execute(
                    "INSERT INTO market_aligner_schema_migrations(version,name,"
                    "checksum) VALUES(1,'tampered','deadbeef')")
                conn.commit()
                with self.assertRaises(MigrationCompatibilityError):
                    apply_on(conn, (_FIT001,
                                    ELIGIBILITY_ELIGIBILITY_RECEIPTS))
                self.assertIsNone(conn.execute(
                    "SELECT name FROM sqlite_master WHERE name="
                    "'eligibility_receipts'").fetchone())
            finally:
                conn.close()

    def test_decision_and_authority_checks_enforced_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "a.sqlite3")
            try:
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("CREATE TABLE assessment_events("
                             "id INTEGER PRIMARY KEY AUTOINCREMENT)")
                conn.execute("CREATE TABLE processing_receipts("
                             "operation_id TEXT PRIMARY KEY)")
                conn.execute("INSERT INTO assessment_events VALUES(1)")
                conn.execute("INSERT INTO assessment_events VALUES(2)")
                conn.execute("INSERT INTO processing_receipts(operation_id) VALUES"
                             "('fit-op-ok-00001')")
                apply_on(conn, (ELIGIBILITY_ELIGIBILITY_RECEIPTS,))
                conn.commit()
                H = "a" * 64
                names = ("operation_id,fit_operation_id,profile_id,job_key,"
                         "track,binding_sha256,envelope_file_sha256,"
                         "envelope_semantic_sha256,fit_receipt_self_hash,"
                         "fit_receipt_file_sha256,fit_binding_sha256,"
                         "fit_event_id,fit_event_payload_sha256,"
                         "fit_raw_snapshot_sha256,fit_profile_context_sha256,"
                         "fit_extraction_output_sha256,"
                         "fit_alignment_output_sha256,"
                         "fit_normalized_json_sha256,"
                         "fit_assessment_payload_hash,candidate_facts_sha256,"
                         "vacancy_facts_sha256,decision_policy_sha256,"
                         "decision_input_sha256,iso_jurisdiction_set_sha256,"
                         "reasons_json,unknowns_json,event_id,"
                         "event_payload_sha256,receipt_self_hash,"
                         "receipt_file_sha256,receipt_bytes,research_authority,"
                         "application_authority,release_authority,"
                         "submission_authority,created_at")
                q = (f"INSERT INTO eligibility_receipts({names},decision,"
                     f"eligibility_authority) SELECT "
                     + ",".join(":" + n.strip() for n in names.split(","))

                     + ",:decision,:eligibility_authority")
                params = {
                    "operation_id": "op-eligible-01", "fit_operation_id":
                        "fit-op-ok-00001",
                    "profile_id": "prf_" + "b" * 32, "job_key": "board:1",
                    "track": "backend", "binding_sha256": H,
                    "envelope_file_sha256": H, "envelope_semantic_sha256": H,
                    "fit_receipt_self_hash": H, "fit_receipt_file_sha256": H,
                    "fit_binding_sha256": H, "fit_event_id": 1,
                    "fit_event_payload_sha256": H, "fit_raw_snapshot_sha256": H,
                    "fit_profile_context_sha256": H,
                    "fit_extraction_output_sha256": H,
                    "fit_alignment_output_sha256": H,
                    "fit_normalized_json_sha256": H,
                    "fit_assessment_payload_hash": H,
                    "candidate_facts_sha256": H, "vacancy_facts_sha256": H,
                    "decision_policy_sha256": H, "decision_input_sha256": H,
                    "iso_jurisdiction_set_sha256": H, "reasons_json": "[]",
                    "unknowns_json": "[]", "event_id": 2,
                    "event_payload_sha256": "7" * 64,
                    "receipt_self_hash": "d" * 64,
                    "receipt_file_sha256": "e" * 64, "receipt_bytes": b"xyz",
                    "research_authority": 0, "application_authority": 0,
                    "release_authority": 0, "submission_authority": 0,
                    "created_at": "2026-08-26T00:00:00.000000Z",
                }
                conn.execute(q, {**params, "decision": "pass",
                                 "eligibility_authority": 1})
                with self.assertRaises(sqlite3.IntegrityError):
                    bad = dict(params, operation_id="op-eligible-02",
                               receipt_file_sha256="f" * 64,
                               binding_sha256="f" * 64,
                               profile_id="prf_" + "c" * 32)
                    conn.execute(q, {**bad, "decision": "review",
                                     "eligibility_authority": 1})
                with self.assertRaises(sqlite3.IntegrityError):
                    bad = dict(params, operation_id="op-eligible-03",
                               receipt_file_sha256="0" * 64,
                               binding_sha256="0" * 64,
                               profile_id="prf_" + "d" * 32)
                    conn.execute(q, {**bad, "decision": "pass",
                                     "eligibility_authority": 0})
                with self.assertRaisesRegex(sqlite3.IntegrityError,
                                            "fit_operation_id"):
                    bad = dict(params, operation_id="op-eligible-04",
                               receipt_file_sha256="1" * 64,
                               binding_sha256="1" * 64,
                               profile_id="prf_" + "e" * 32)
                    conn.execute(q, {**bad, "decision": "reject",
                                     "eligibility_authority": 0})
                with self.assertRaisesRegex(sqlite3.IntegrityError,
                                            "FOREIGN KEY"):
                    bad = dict(params, operation_id="op-eligible-05",
                               receipt_file_sha256="2" * 64,
                               binding_sha256="2" * 64,
                               profile_id="prf_" + "f" * 32,
                               fit_operation_id="op-no-such-fit-02",
                               fit_event_id=99)
                    conn.execute(q, {**bad, "decision": "reject",
                                     "eligibility_authority": 0})
                with self.assertRaisesRegex(sqlite3.IntegrityError,
                                            "FOREIGN KEY"):
                    bad = dict(params, operation_id="op-eligible-06",
                               receipt_file_sha256="3" * 64,
                               binding_sha256="3" * 64,
                               profile_id="prf_" + "0" * 32,
                               fit_operation_id="op-no-such-fit-03",
                               event_id=98)
                    conn.execute(q, {**bad, "decision": "reject",
                                     "eligibility_authority": 0})
                with self.assertRaisesRegex(sqlite3.IntegrityError,
                                            "FOREIGN KEY"):
                    bad = dict(params, operation_id="op-eligible-07",
                               receipt_file_sha256="4" * 64,
                               binding_sha256="4" * 64,
                               profile_id="prf_" + "1" * 32,
                               fit_operation_id="op-no-such-fit")
                    conn.execute(q, {**bad, "decision": "reject",
                                     "eligibility_authority": 0})
            finally:
                conn.close()

    def test_generic_event_seam_accepts_eligibility_decided(self):
        from market_aligner.research.store import (
            AssessmentStore, cas_processing_event,
            classify_processing_score_event, plan_processing_event,
        )
        with tempfile.TemporaryDirectory() as tmp:
            store = AssessmentStore(Path(tmp) / "a.sqlite3")
            conn = store.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO assessments(profile_id,job_key,url,title,"
                    "company,opportunity,fit,final_score,fit_status,"
                    "score_payload_json,score_payload_hash)"
                    " VALUES('prf_'||?,'board:1','u','t','c',0.5,0.5,50.0,"
                    "'uncalibrated','{}','hash')", ("1" * 32,))
                plan = plan_processing_event(
                    conn, profile_id="prf_" + "1" * 32, job_key="board:1",
                    event_type="eligibility_decided", actor_kind="deterministic",
                    payload_json="{}", idempotency_key="k-" + "x" * 180,
                    created_at="2026-08-26T00:00:00.000000Z", event_id=1)
                self.assertEqual(plan.action, "insert")
                outcome = cas_processing_event(
                    conn, profile_id="prf_" + "1" * 32, job_key="board:1",
                    event_type="eligibility_decided", actor_kind="deterministic",
                    payload_json="{}", idempotency_key="k-" + "x" * 180,
                    created_at="2026-08-26T00:00:00.000000Z", event_id=1)
                self.assertEqual(outcome.action, "insert")
                classification = classify_processing_score_event(
                    conn, profile_id="prf_" + "1" * 32, job_key="board:1",
                    event_type="eligibility_decided")
                self.assertEqual((classification.action,
                                  classification.count), ("existing", 1))
                with self.assertRaisesRegex(Exception, "closed contracted"):
                    plan_processing_event(
                        conn, profile_id="prf_" + "1" * 32,
                        job_key="board:1", event_type="other",
                        actor_kind="deterministic", payload_json="{}",
                        idempotency_key="k", created_at="x", event_id=1)
                conn.rollback()
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
