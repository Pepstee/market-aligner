from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from market_aligner.collectors.adapters.base import load_adapter
from market_aligner.collectors.engine import Collector
from market_aligner.domain.contracts import JobUrl, RawPosting
from market_aligner.state.vacancies import JobDatabase


FIXTURES = Path(__file__).parent / "fixtures"


class CollectionTests(unittest.TestCase):
    def test_audited_fixture_adapters_retain_contract(self) -> None:
        for board in ("wanted", "saramin", "jobkorea", "notefolio"):
            adapter = load_adapter(board, fixture_dir=FIXTURES)
            rows = list(adapter.discover([], live=False))
            self.assertGreater(len(rows), 0, board)
            raw = adapter.fetch(rows[0], live=False)
            self.assertEqual(rows[0].key, raw.key)
            self.assertTrue(raw.raw_json is not None or raw.raw_text is not None)

    def test_database_resumes_pending_and_imports_legacy_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = JobDatabase(root / "state" / "vacancies.sqlite3")
            row = JobUrl("board", "1", "https://example.test/1")
            self.assertTrue(database.upsert_discovered(row))
            self.assertEqual({"board"}, database.boards_with_pending_discoveries(["board"]))
            database.store_raw(
                RawPosting("board", "1", row.url, "2026-08-01T00:00:00Z", raw_text="complete")
            )
            self.assertTrue(database.has_raw(row.key))
            self.assertEqual(set(), database.boards_with_pending_discoveries(["board"]))

            urls = root / "legacy" / "urls.jsonl"
            database.export_urls(urls)
            imported = JobDatabase(root / "state" / "imported.sqlite3")
            added, fetched = imported.import_existing(urls, root / "missing-cache")
            self.assertEqual((1, 0), (added, fetched))

    def test_collector_has_no_result_cap_and_persists_all_discoveries(self) -> None:
        class BulkAdapter:
            board = "bulk"

            def discover(self, _terms, live=False):
                self.assert_live = live
                for index in range(301):
                    yield JobUrl("bulk", str(index), f"https://example.test/{index}")

            def fetch(self, row, live=False):
                return RawPosting(row.board, row.job_id, row.url, "2026-08-01T00:00:00Z", raw_text="x")

        with tempfile.TemporaryDirectory() as temporary:
            config = {
                "boards": {"enabled": ["bulk"]},
                "collection": {"source_workers": 1, "fetch_workers": 8},
                "bulk": {"minimum_poll_minutes": 0},
            }
            collector = Collector(config, Path(temporary), log=lambda _message: None)
            with mock.patch("market_aligner.collectors.engine.load_adapter", return_value=BulkAdapter()):
                result = collector.cycle()
            self.assertEqual(301, result["seen"])
            self.assertEqual(301, result["new"])
            self.assertEqual(301, result["fetched"])
            self.assertEqual(301, collector.db.stats()["postings"])


if __name__ == "__main__":
    unittest.main()
