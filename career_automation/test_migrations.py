from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from career_automation.migrations import Migration, MigrationRunner


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
            ledger = conn.execute("SELECT COUNT(*) FROM career_schema_migrations").fetchone()[0]
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


if __name__ == "__main__":
    unittest.main()
