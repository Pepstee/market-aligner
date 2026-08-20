from __future__ import annotations

import io
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import yaml

from market_aligner.cli import build_parser, main
from market_aligner.collectors.adapters.base import load_adapter
from market_aligner.collectors.adapters.workable import WorkableAdapter
from market_aligner.collectors.engine import Collector
from market_aligner.domain.contracts import JobUrl, RawPosting, write_jsonl
from market_aligner.service.api import CollectionService
from market_aligner.state.vacancies import (
    JobDatabase,
    VacancyRefreshConflict,
    VacancyRefreshIndeterminate,
)


FIXTURES = Path(__file__).parent / "fixtures"


class CollectionTests(unittest.TestCase):
    def _refresh_fixture(
        self,
        root: Path,
        adapter: object,
    ) -> tuple[Path, JobDatabase, str, dict[str, int], object]:
        config = root / "collect.yaml"
        config.write_text(
            yaml.safe_dump(
                {
                    "boards": {"enabled": ["injected"]},
                    "collection": {"fetch_workers": 1, "source_workers": 1},
                    "injected": {"tenant": "official-test"},
                    "io": {
                        "database": "state/vacancies.sqlite3",
                        "job_urls": "state/job_urls.jsonl",
                        "raw_cache": "raw/vacancies",
                    },
                    "search_terms": [],
                }
            ),
            encoding="utf-8",
        )
        database = JobDatabase(root / "state" / "vacancies.sqlite3")
        job = JobUrl("injected", "tenant:1", "https://example.test/jobs/1")
        database.upsert_discovered(job)
        old_raw = RawPosting(
            job.board,
            job.job_id,
            job.url,
            "2026-08-20T00:00:00Z",
            raw_text="old official bytes",
        )
        database.store_raw(old_raw)
        write_jsonl(root / "raw" / "vacancies" / "injected" / "tenant_1.json", [old_raw])
        _job, old_hash, _fetched_at = database.fetched_posting(job.key)
        calls = {"fetch": 0}

        def adapter_loader(board, *, config):
            self.assertEqual("injected", board)
            self.assertEqual({"tenant": "official-test"}, config)
            return adapter

        def collector_factory(loaded_config, data_home, log=print):
            return Collector(
                loaded_config,
                data_home,
                log=log,
                adapter_loader=adapter_loader,
            )

        adapter.calls = calls
        adapter.database = database
        return config, database, old_hash, calls, collector_factory

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

    def test_exact_refresh_changes_one_vacancy_and_emits_old_new_receipt(self) -> None:
        class ChangedAdapter:
            board = "injected"

            def owns(self, job):
                return job.key == "injected:tenant:1"

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                self.live = live
                return RawPosting(
                    job.board,
                    job.job_id,
                    job.url,
                    "2026-08-20T01:00:00Z",
                    raw_text="new official bytes",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = ChangedAdapter()
            config, database, old_hash, calls, factory = self._refresh_fixture(root, adapter)
            service = CollectionService(
                root,
                collector_factory=factory,
                now=lambda: datetime(2026, 8, 20, 1, tzinfo=timezone.utc),
            )
            receipt = service.refresh_vacancy(
                config,
                job_key="injected:tenant:1",
                expected_content_sha256=old_hash,
                operation_id="changed-refresh",
                log=lambda _message: None,
            )
            self.assertEqual(1, calls["fetch"])
            self.assertTrue(adapter.live)
            self.assertTrue(receipt["changed"])
            self.assertEqual(old_hash, receipt["old_content_sha256"])
            self.assertNotEqual(old_hash, receipt["new_content_sha256"])
            self.assertEqual(1, receipt["official_fetch_count"])
            _job, current_hash, fetched_at = database.fetched_posting("injected:tenant:1")
            self.assertEqual(receipt["new_content_sha256"], current_hash)
            self.assertEqual("2026-08-20T01:00:00Z", fetched_at)
            stored = json.loads(Path(receipt["receipt_path"]).read_text(encoding="utf-8"))
            self.assertEqual(receipt["receipt_sha256"], stored["receipt_sha256"])
            raw_cache = root / receipt["raw_cache_path"]
            self.assertTrue(raw_cache.is_file())
            self.assertEqual(
                receipt["raw_cache_file_sha256"],
                hashlib.sha256(raw_cache.read_bytes()).hexdigest(),
            )
            with self.assertRaisesRegex(ValueError, "already bound"):
                service.refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256="b" * 64,
                    operation_id="changed-refresh",
                    log=lambda _message: None,
                )
            self.assertEqual(1, calls["fetch"])

            database.store_raw(
                RawPosting(
                    "injected",
                    "tenant:1",
                    "https://example.test/jobs/1",
                    "2026-08-20T01:30:00Z",
                    raw_text="later authoritative refresh",
                )
            )
            cache_before_replay = raw_cache.read_bytes()
            with self.assertRaisesRegex(VacancyRefreshConflict, "superseded"):
                service.refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="changed-refresh",
                    log=lambda _message: None,
                )
            self.assertEqual(cache_before_replay, raw_cache.read_bytes())
            self.assertEqual(1, calls["fetch"])

    def test_exact_refresh_records_unchanged_official_content(self) -> None:
        class UnchangedAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                return RawPosting(
                    job.board,
                    job.job_id,
                    job.url,
                    "2026-08-20T02:00:00Z",
                    raw_text="old official bytes",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = UnchangedAdapter()
            config, database, old_hash, calls, factory = self._refresh_fixture(root, adapter)
            receipt = CollectionService(root, collector_factory=factory).refresh_vacancy(
                config,
                job_key="injected:tenant:1",
                expected_content_sha256=old_hash,
                operation_id="unchanged-refresh",
                log=lambda _message: None,
            )
            self.assertEqual(1, calls["fetch"])
            self.assertFalse(receipt["changed"])
            self.assertEqual(old_hash, receipt["new_content_sha256"])
            self.assertEqual(
                "2026-08-20T02:00:00Z",
                database.fetched_posting("injected:tenant:1")[2],
            )

    def test_exact_refresh_loses_cas_race_without_overwriting_winner(self) -> None:
        class RacingAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                self.database.store_raw(
                    RawPosting(
                        job.board,
                        job.job_id,
                        job.url,
                        "2026-08-20T03:00:00Z",
                        raw_text="concurrent winner",
                    )
                )
                return RawPosting(
                    job.board,
                    job.job_id,
                    job.url,
                    "2026-08-20T03:01:00Z",
                    raw_text="losing refresh",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = RacingAdapter()
            config, database, old_hash, calls, factory = self._refresh_fixture(root, adapter)
            with self.assertRaises(VacancyRefreshConflict):
                CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="racing-refresh",
                    log=lambda _message: None,
                )
            self.assertEqual(1, calls["fetch"])
            self.assertNotEqual(old_hash, database.fetched_posting("injected:tenant:1")[1])
            self.assertFalse((root / "state" / "collection-refresh-receipts").exists())
            self.assertIn(
                b"old official bytes",
                (root / "raw" / "vacancies" / "injected" / "tenant_1.json").read_bytes(),
            )

    def test_exact_refresh_fetch_error_preserves_existing_good_state(self) -> None:
        class ErrorAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, _job, live=False):
                self.calls["fetch"] += 1
                raise RuntimeError("official source unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = ErrorAdapter()
            config, database, old_hash, calls, factory = self._refresh_fixture(root, adapter)
            with self.assertRaisesRegex(RuntimeError, "official source unavailable"):
                CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="error-refresh",
                    log=lambda _message: None,
                )
            self.assertEqual(1, calls["fetch"])
            self.assertEqual(old_hash, database.fetched_posting("injected:tenant:1")[1])
            self.assertFalse((root / "state" / "collection-refresh-receipts").exists())

    def test_exact_refresh_never_refetches_an_unresolved_fetch_window(self) -> None:
        class ReturnedAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                return RawPosting(
                    job.board,
                    job.job_id,
                    job.url,
                    "2026-08-20T03:30:00Z",
                    raw_text="response returned before process loss",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = ReturnedAdapter()
            config, database, old_hash, calls, factory = self._refresh_fixture(root, adapter)

            def crash_factory(loaded_config, data_home, log=print):
                collector = factory(loaded_config, data_home, log=log)

                def inject(point):
                    if point == "after_fetch_before_persist":
                        raise RuntimeError("lost-after-official-return")

                collector.crash_injector = inject
                return collector

            with self.assertRaisesRegex(RuntimeError, "lost-after-official-return"):
                CollectionService(root, collector_factory=crash_factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="irreducible-window",
                    log=lambda _message: None,
                )
            self.assertEqual(1, calls["fetch"])
            with sqlite3.connect(root / "state" / "vacancies.sqlite3") as conn:
                status = conn.execute(
                    "SELECT status FROM vacancy_refreshes WHERE operation_id=?",
                    ("irreducible-window",),
                ).fetchone()[0]
            self.assertEqual("fetch_started", status)

            with self.assertRaisesRegex(VacancyRefreshIndeterminate, "indeterminate"):
                CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="irreducible-window",
                    log=lambda _message: None,
                )
            self.assertEqual(1, calls["fetch"])
            with sqlite3.connect(root / "state" / "vacancies.sqlite3") as conn:
                status = conn.execute(
                    "SELECT status FROM vacancy_refreshes WHERE operation_id=?",
                    ("irreducible-window",),
                ).fetchone()[0]
            self.assertEqual("indeterminate", status)

            with self.assertRaisesRegex(VacancyRefreshIndeterminate, "reconciliation"):
                CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="new-operation-is-still-blocked",
                    log=lambda _message: None,
                )
            self.assertEqual(1, calls["fetch"])
            self.assertEqual(old_hash, database.fetched_posting("injected:tenant:1")[1])
            self.assertFalse((root / "state" / "collection-refresh-receipts").exists())

    def test_exact_refresh_replay_rejects_journal_and_object_tampering(self) -> None:
        class StableAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                return RawPosting(
                    job.board,
                    job.job_id,
                    job.url,
                    "2026-08-20T03:45:00Z",
                    raw_text="sealed exact official response",
                )

        database_mutations = {
            "context": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET context_json=? WHERE operation_id=?",
                (json.dumps({"substituted": True}), "tamper-refresh"),
            ),
            "old-bytes": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET old_raw_bytes=? WHERE operation_id=?",
                (b'{"substituted":true}\n', "tamper-refresh"),
            ),
            "old-object-hash": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET old_object_sha256=? WHERE operation_id=?",
                ("a" * 64, "tamper-refresh"),
            ),
            "new-bytes": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET new_raw_bytes=? WHERE operation_id=?",
                (b'{"substituted":true}\n', "tamper-refresh"),
            ),
            "new-content-hash": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET new_content_sha256=? WHERE operation_id=?",
                ("b" * 64, "tamper-refresh"),
            ),
            "new-object-hash": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET new_object_sha256=? WHERE operation_id=?",
                ("f" * 64, "tamper-refresh"),
            ),
            "basis-hash": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET receipt_basis_sha256=? WHERE operation_id=?",
                ("e" * 64, "tamper-refresh"),
            ),
            "transition-hash": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET transition_sha256=? WHERE operation_id=?",
                ("d" * 64, "tamper-refresh"),
            ),
            "status": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET status='fetched' WHERE operation_id=?",
                ("tamper-refresh",),
            ),
            "receipt-basis": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET receipt_basis_json=json_set(receipt_basis_json, '$.state_sha256', ?) WHERE operation_id=?",
                ("c" * 64, "tamper-refresh"),
            ),
        }

        def corrupt_object(_conn, receipt, root):
            (root / receipt["new_raw_object_path"]).write_bytes(b"substituted object bytes")

        mutations = {**database_mutations, "object-bytes": corrupt_object}
        for label, mutate in mutations.items():
            with self.subTest(tamper=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                adapter = StableAdapter()
                config, _database, old_hash, calls, factory = self._refresh_fixture(root, adapter)
                service = CollectionService(root, collector_factory=factory)
                receipt = service.refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="tamper-refresh",
                    log=lambda _message: None,
                )
                receipt_path = Path(receipt["receipt_path"])
                receipt_before = receipt_path.read_bytes()
                cache_path = root / receipt["raw_cache_path"]
                cache_before = cache_path.read_bytes()
                with sqlite3.connect(root / "state" / "vacancies.sqlite3") as conn:
                    mutate(conn, receipt, root)
                    conn.commit()

                with self.assertRaises(VacancyRefreshConflict):
                    service.refresh_vacancy(
                        config,
                        job_key="injected:tenant:1",
                        expected_content_sha256=old_hash,
                        operation_id="tamper-refresh",
                        log=lambda _message: None,
                    )
                self.assertEqual(1, calls["fetch"])
                self.assertEqual(receipt_before, receipt_path.read_bytes())
                self.assertEqual(cache_before, cache_path.read_bytes())

    def test_exact_refresh_recovers_every_crash_boundary_without_refetch(self) -> None:
        class RecoverableAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                return RawPosting(
                    job.board,
                    job.job_id,
                    job.url,
                    "2026-08-20T04:00:00Z",
                    raw_text="recoverable new official bytes",
                )

        for crash_point in (
            "before_object",
            "after_object_pre_cas",
            "after_cas_pre_cache",
            "after_cache_pre_receipt",
        ):
            with self.subTest(crash_point=crash_point), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                adapter = RecoverableAdapter()
                config, database, old_hash, calls, factory = self._refresh_fixture(root, adapter)
                old_cache = root / "raw" / "vacancies" / "injected" / "tenant_1.json"
                exact_old_bytes = old_cache.read_bytes()

                def crash_factory(loaded_config, data_home, log=print):
                    collector = factory(loaded_config, data_home, log=log)

                    def inject(point):
                        if point == crash_point:
                            raise RuntimeError(f"crash:{point}")

                    collector.crash_injector = inject
                    return collector

                operation_id = f"recovery-{crash_point}"
                with self.assertRaisesRegex(RuntimeError, f"crash:{crash_point}"):
                    CollectionService(root, collector_factory=crash_factory).refresh_vacancy(
                        config,
                        job_key="injected:tenant:1",
                        expected_content_sha256=old_hash,
                        operation_id=operation_id,
                        log=lambda _message: None,
                    )
                self.assertEqual(1, calls["fetch"])
                self.assertFalse(
                    (root / "state" / "collection-refresh-receipts").exists()
                )

                receipt = CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id=operation_id,
                    log=lambda _message: None,
                )
                self.assertEqual(1, calls["fetch"])
                self.assertEqual("market-aligner.vacancy-refresh-receipt.v2", receipt["schema_version"])
                self.assertEqual(operation_id, receipt["operation_id"])
                self.assertTrue(receipt["changed"])
                old_object = root / receipt["old_raw_object_path"]
                new_object = root / receipt["new_raw_object_path"]
                self.assertEqual(exact_old_bytes, old_object.read_bytes())
                self.assertEqual(
                    receipt["old_raw_object_sha256"],
                    hashlib.sha256(old_object.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    receipt["new_raw_object_sha256"],
                    hashlib.sha256(new_object.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    receipt["new_content_sha256"],
                    database.fetched_posting("injected:tenant:1")[1],
                )

                replay = CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id=operation_id,
                    log=lambda _message: None,
                )
                self.assertEqual(receipt["receipt_sha256"], replay["receipt_sha256"])
                self.assertEqual(1, calls["fetch"])

    def test_workable_exact_fetch_is_one_config_owned_official_request(self) -> None:
        adapter = WorkableAdapter(config={"companies": {"cogna": "Cogna"}})
        job = JobUrl(
            "workable",
            "cogna:847CFBC5F4",
            "https://apply.workable.com/j/847CFBC5F4",
        )
        payload = {
            "name": "Cogna",
            "jobs": [
                {
                    "shortcode": "847CFBC5F4",
                    "title": "Software Engineer",
                    "description": "Build reliable software.",
                    "url": job.url,
                }
            ],
        }
        with mock.patch(
            "market_aligner.collectors.adapters.workable.http_get_json",
            return_value=payload,
        ) as official_get:
            raw = adapter.fetch(job, live=True)
        self.assertEqual(job.key, raw.key)
        self.assertEqual("Cogna", raw.raw_json["company"])
        official_get.assert_called_once()
        self.assertEqual(1, official_get.call_args.kwargs["attempts"])
        with mock.patch(
            "market_aligner.collectors.adapters.workable.http_get_json"
        ) as forbidden_get:
            with self.assertRaisesRegex(ValueError, "does not own"):
                adapter.fetch(
                    JobUrl("workable", "other:847CFBC5F4", job.url),
                    live=True,
                )
        forbidden_get.assert_not_called()

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
        refresh = parser.parse_args(
            [
                "refresh-vacancy",
                "--config",
                "collect.yaml",
                "--job-key",
                "workable:cogna:847CFBC5F4",
                "--expected-content-sha256",
                "a" * 64,
                "--operation-id",
                "cogna-refresh-20260820T180000Z",
            ]
        )
        self.assertEqual("workable:cogna:847CFBC5F4", refresh.job_key)

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
