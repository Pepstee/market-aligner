from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from market_aligner.state.migrations import (
    FIT001_PROCESSING_RECEIPTS,
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


if __name__ == "__main__":
    unittest.main()
