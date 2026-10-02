from __future__ import annotations

import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = REPOSITORY_ROOT / "docs" / "migration" / "ledger.jsonl"


class MigrationLedgerTests(unittest.TestCase):
    def test_ledger_entries_are_unique_complete_and_provenance_bound(self) -> None:
        entries = [
            json.loads(line)
            for line in LEDGER_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

        self.assertGreaterEqual(len(entries), 24)
        entry_ids = [entry["entry_id"] for entry in entries]
        self.assertEqual(len(entry_ids), len(set(entry_ids)))

        allowed = {"adopted", "deferred", "archived", "tombstone-pending", "deleted"}
        for entry in entries:
            self.assertIn(entry["disposition"], allowed)
            self.assertEqual(entry["status"], entry["disposition"])
            self.assertTrue(entry["subsystem"])
            self.assertTrue(entry["source_id"])
            self.assertTrue(entry["verification"])
            if entry["disposition"] == "adopted":
                provenance = entry["source_sha256"]
                self.assertIsInstance(provenance, str)
                self.assertTrue(provenance)
                self.assertNotIn("pending", provenance.lower())

    def test_only_operator_authorized_mac_source_roots_are_marked_deleted(self) -> None:
        entries = [
            json.loads(line)
            for line in LEDGER_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

        deleted = [entry for entry in entries if entry["disposition"] == "deleted"]
        self.assertEqual(["ma-0296"], [entry["entry_id"] for entry in deleted])
        self.assertEqual("deleted", deleted[0]["status"])
        self.assertEqual("/Users/admin/Projects/market-aligner", deleted[0]["target"])
        self.assertNotIn("tombstoned", {entry["disposition"] for entry in entries})


if __name__ == "__main__":
    unittest.main()
