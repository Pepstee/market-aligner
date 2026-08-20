from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import yaml

from market_aligner.cli import build_parser, main
from market_aligner.collectors.adapters.base import load_adapter
from market_aligner.collectors.engine import Collector
from market_aligner.domain.contracts import JobUrl, RawPosting
from market_aligner.service.api import CollectionService
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

    def test_service_resumes_interrupted_fetch_and_emits_hash_bound_receipts(self) -> None:
        attempts = {"2": 0}

        class InterruptedAdapter:
            board = "injected"

            def discover(self, _terms, live=False):
                self.assert_live = live
                yield JobUrl("injected", "1", "https://example.test/1")
                yield JobUrl("injected", "2", "https://example.test/2")

            def fetch(self, row, live=False):
                if row.job_id == "2":
                    attempts["2"] += 1
                    if attempts["2"] == 1:
                        raise RuntimeError("injected interruption")
                return RawPosting(
                    row.board,
                    row.job_id,
                    row.url,
                    "2026-08-20T00:00:00Z",
                    raw_text=f"posting {row.job_id}",
                )

        def adapter_loader(_board, **_kwargs):
            return InterruptedAdapter()

        def collector_factory(config, root, log=print):
            return Collector(config, root, log=log, adapter_loader=adapter_loader)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base.yaml"
            base.write_text(
                yaml.safe_dump(
                    {
                        "boards": {"enabled": ["injected"]},
                        "collection": {"fetch_workers": 1, "source_workers": 1},
                        "io": {
                            "database": "state/vacancies.sqlite3",
                            "job_urls": "state/job_urls.jsonl",
                            "raw_cache": "raw/vacancies",
                        },
                        "search_terms": ["automation"],
                    }
                ),
                encoding="utf-8",
            )
            config = root / "collect.yaml"
            config.write_text(
                yaml.safe_dump(
                    {
                        "extends": "base.yaml",
                        "injected": {"minimum_poll_minutes": 60},
                    }
                ),
                encoding="utf-8",
            )
            now = lambda: datetime(2026, 8, 20, tzinfo=timezone.utc)
            service = CollectionService(root, collector_factory=collector_factory, now=now)

            first = service.collect(
                config, once=True, hours=0, poll_minutes=1, log=lambda _message: None
            )
            self.assertEqual(
                {"seen": 2, "new": 2, "fetched": 1, "errors": 1}, first["totals"]
            )
            self.assertFalse(first["application_authority"])
            self.assertEqual("collection_only", first["authority_scope"])
            self.assertTrue(Path(first["receipt_path"]).is_file())

            second = service.collect(
                config, once=True, hours=0, poll_minutes=1, log=lambda _message: None
            )
            self.assertEqual(
                {"seen": 2, "new": 0, "fetched": 1, "errors": 0}, second["totals"]
            )
            self.assertEqual(first["config_sha256"], second["config_sha256"])
            self.assertEqual(first["source_sha256"], second["source_sha256"])
            self.assertNotEqual(first["state_sha256"], second["state_sha256"])
            database = JobDatabase(root / "state" / "vacancies.sqlite3")
            self.assertEqual(2, database.stats()["fetched"])
            stored = json.loads(Path(second["receipt_path"]).read_text(encoding="utf-8"))
            self.assertNotIn("receipt_path", stored)
            self.assertEqual(second["receipt_sha256"], stored["receipt_sha256"])

    def test_partial_source_failure_preserves_every_yielded_discovery(self) -> None:
        class PartialAdapter:
            board = "partial"

            def discover(self, _terms, live=False):
                yield JobUrl("partial", "a", "https://example.test/a")
                yield JobUrl("partial", "b", "https://example.test/b")
                raise RuntimeError("source ended after page two")

            def fetch(self, row, live=False):
                return RawPosting(
                    row.board,
                    row.job_id,
                    row.url,
                    "2026-08-20T00:00:00Z",
                    raw_text=row.job_id,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            collector = Collector(
                {
                    "boards": {"enabled": ["partial"]},
                    "collection": {"fetch_workers": 1, "source_workers": 1},
                    "partial": {"minimum_poll_minutes": 0},
                },
                root,
                log=lambda _message: None,
                adapter_loader=lambda _board, **_kwargs: PartialAdapter(),
            )
            result = collector.cycle()
            self.assertEqual(
                {"seen": 2, "new": 2, "fetched": 2, "errors": 1, "database_total": 2},
                result,
            )
            state = collector.db.collection_state()
            self.assertEqual(["a", "b"], [row["job_id"] for row in state["postings"]])
            self.assertIn("source ended after page two", state["sources"][0]["last_error"])

    def test_collect_cli_requires_explicit_bounded_mode(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["collect", "--config", "collect.yaml"])
        parsed = parser.parse_args(
            ["collect", "--config", "collect.yaml", "--once", "--poll-minutes", "2"]
        )
        self.assertTrue(parsed.once)
        self.assertIsNone(parsed.hours)

    def test_collection_service_rejects_unbounded_run_and_data_home_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "collect.yaml"
            config.write_text(
                yaml.safe_dump(
                    {
                        "boards": {"enabled": ["injected"]},
                        "io": {"database": "../outside.sqlite3"},
                    }
                ),
                encoding="utf-8",
            )
            service = CollectionService(root)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                service.collect(
                    config, once=False, hours=0, poll_minutes=1, log=lambda _message: None
                )
            with self.assertRaisesRegex(ValueError, r"\(0,24\]"):
                service.collect(
                    config, once=False, hours=25, poll_minutes=1, log=lambda _message: None
                )
            with self.assertRaisesRegex(ValueError, "external data home"):
                service.collect(
                    config, once=True, hours=0, poll_minutes=1, log=lambda _message: None
                )

    def test_collect_cli_emits_one_machine_readable_receipt(self) -> None:
        receipt = {
            "application_authority": False,
            "authority_scope": "collection_only",
            "receipt_sha256": "a" * 64,
        }
        output = io.StringIO()
        with mock.patch("market_aligner.cli.CollectionService") as service_type:
            service_type.return_value.collect.return_value = receipt
            with redirect_stdout(output):
                result = main(
                    [
                        "collect",
                        "--config",
                        "collect.yaml",
                        "--once",
                        "--poll-minutes",
                        "3",
                        "--data-home",
                        "/tmp/external-market-data",
                    ]
                )
        self.assertEqual(0, result)
        self.assertEqual(receipt, json.loads(output.getvalue()))
        service_type.assert_called_once_with(Path("/tmp/external-market-data"))
        service_type.return_value.collect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
