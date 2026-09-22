from __future__ import annotations

import io
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import yaml

from market_aligner.cli import build_parser, main
from market_aligner.collectors.adapters.base import load_adapter
from market_aligner.collectors.adapters.uk_common import (
    _EU27_2026_08_REMOTE_MARKERS,
    uk_or_eligible_remote,
)
from market_aligner.collectors.adapters.workable import WorkableAdapter
from market_aligner.collectors.engine import Collector
from market_aligner.domain.contracts import JobUrl, RawPosting, write_jsonl
from market_aligner.service.api import CollectionService
from market_aligner.state.vacancies import (
    JobDatabase,
    VacancyRefreshConflict,
    VacancyRefreshIndeterminate,
    raw_posting_bytes,
    raw_posting_content_sha256,
)


FIXTURES = Path(__file__).parent / "fixtures"


class CollectionTests(unittest.TestCase):
    def test_eu27_country_markers_are_remote_discovery_recall_only(self) -> None:
        for marker in _EU27_2026_08_REMOTE_MARKERS:
            country = marker.strip()
            with self.subTest(country=country):
                self.assertTrue(uk_or_eligible_remote(country, remote=True))
                self.assertFalse(uk_or_eligible_remote(country, remote=False))
        self.assertFalse(uk_or_eligible_remote("Norway", remote=True))

    def test_fresh_vacancy_database_is_owner_private_under_common_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "vacancies.sqlite3"
            previous = os.umask(0o022)
            try:
                JobDatabase(path)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_raw_snapshot_history_is_append_only_and_current_head_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = JobDatabase(Path(temporary) / "state" / "vacancies.sqlite3")
            job = JobUrl("board", "snapshot-1", "https://example.test/snapshot-1")
            database.upsert_discovered(job)
            first = RawPosting(
                job.board,
                job.job_id,
                job.url,
                "2026-08-20T00:00:00Z",
                raw_json={"version": 1},
            )
            second = RawPosting(
                job.board,
                job.job_id,
                job.url,
                "2026-08-21T00:00:00Z",
                raw_json={"version": 2},
            )
            first_hash = raw_posting_content_sha256(first)
            second_hash = raw_posting_content_sha256(second)

            database.store_raw(first)
            self.assertEqual(
                raw_posting_bytes(first), database.raw_snapshot(job.key, first_hash)
            )
            self.assertEqual(first, database.load_current_raw_snapshot(job.key))
            database.store_raw(second)

            self.assertEqual(first, database.load_raw_snapshot(job.key, first_hash))
            self.assertEqual(second, database.load_raw_snapshot(job.key, second_hash))
            self.assertEqual(second, database.load_current_raw_snapshot(job.key))
            with database.connect() as connection:
                self.assertEqual(
                    2,
                    connection.execute(
                        "SELECT COUNT(*) FROM posting_raw_snapshots WHERE job_key=?",
                        (job.key,),
                    ).fetchone()[0],
                )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "UPDATE posting_raw_snapshots SET fetched_at='changed' WHERE job_key=?",
                        (job.key,),
                    )

    def test_trusted_discovery_creates_immutable_release_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = JobDatabase(Path(temporary) / "state" / "vacancies.sqlite3")
            job = JobUrl(
                "board",
                "release-1",
                "https://example.test/release-1",
                discovered_at="2026-08-20T00:00:00Z",
            )
            raw = RawPosting(
                job.board,
                job.job_id,
                job.url,
                "2026-08-20T00:01:00Z",
                raw_text="exact public vacancy",
                content_type="text/html",
                http_status=200,
            )
            database.upsert_discovered(job, release_trusted=True)
            database.store_raw(raw, release_trusted=True)

            content_sha256 = raw_posting_content_sha256(raw)
            capture = database.listing_release_capture(job.key, content_sha256)
            self.assertEqual(job.discovered_at, capture.discovered_at)
            self.assertEqual(raw.fetched_at, capture.fetched_at)
            self.assertEqual(content_sha256, capture.content_sha256)
            self.assertEqual(
                hashlib.sha256(raw_posting_bytes(raw)).hexdigest(),
                capture.raw_object_sha256,
            )
            self.assertEqual(
                capture.provenance_sha256,
                hashlib.sha256(capture.exact_provenance_bytes).hexdigest(),
            )
            self.assertIsNone(
                database.release_capture_block(
                    job.key, content_sha256, capture.raw_object_sha256
                )
            )
            with database.connect() as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        """UPDATE posting_release_captures
                           SET fetched_at='changed' WHERE provenance_sha256=?""",
                        (capture.provenance_sha256,),
                    )
            with database.connect() as connection, connection:
                connection.execute("DELETE FROM postings WHERE key=?", (job.key,))
                self.assertEqual(
                    [], connection.execute("PRAGMA foreign_key_check").fetchall()
                )
                self.assertEqual(
                    1,
                    connection.execute(
                        """SELECT COUNT(*) FROM posting_discovery_observations
                           WHERE job_key=?""",
                        (job.key,),
                    ).fetchone()[0],
                )

    def test_untrusted_or_unstamped_discovery_cannot_create_release_capture(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = JobDatabase(Path(temporary) / "state" / "vacancies.sqlite3")
            job = JobUrl("board", "untrusted-1", "https://example.test/untrusted-1")
            with self.assertRaisesRegex(ValueError, "explicit collection timestamp"):
                database.upsert_discovered(job, release_trusted=True)

            database.upsert_discovered(job)
            raw = RawPosting(
                job.board,
                job.job_id,
                job.url,
                "2026-08-20T00:01:00Z",
                raw_text="legacy public vacancy",
            )
            with self.assertRaisesRegex(ValueError, "trusted discovery"):
                database.store_raw(raw, release_trusted=True)
            database.store_raw(raw)
            content_sha256 = raw_posting_content_sha256(raw)
            object_sha256 = hashlib.sha256(raw_posting_bytes(raw)).hexdigest()
            with self.assertRaises(KeyError):
                database.listing_release_capture(job.key, content_sha256)
            block = database.release_capture_block(
                job.key, content_sha256, object_sha256
            )
            self.assertIsNotNone(block)
            assert block is not None
            self.assertEqual(
                "snapshot_without_trusted_discovery_provenance",
                block["reason_code"],
            )

    def test_legacy_fetched_row_is_blocked_until_exact_snapshot_is_recaptured(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "vacancies.sqlite3"
            database = JobDatabase(path)
            job = JobUrl("board", "legacy-1", "https://example.test/legacy-1")
            database.upsert_discovered(job)
            legacy = RawPosting(
                job.board,
                job.job_id,
                job.url,
                "2026-08-20T00:00:00Z",
                raw_text="legacy bytes",
            )
            with database.connect() as connection, connection:
                connection.execute(
                    """UPDATE postings SET fetched_at=?,raw_text=?,content_hash=?,
                         fetch_status='fetched' WHERE key=?""",
                    (
                        legacy.fetched_at,
                        legacy.raw_text,
                        raw_posting_content_sha256(legacy),
                        job.key,
                    ),
                )

            reopened = JobDatabase(path)
            block = reopened.snapshot_migration_block(job.key)
            self.assertIsNotNone(block)
            assert block is not None
            self.assertEqual(
                "legacy_fetched_without_immutable_raw_snapshot",
                block["reason_code"],
            )
            with self.assertRaises(KeyError):
                reopened.load_current_raw_snapshot(job.key)

            reopened.store_raw(legacy)
            self.assertIsNone(reopened.snapshot_migration_block(job.key))
            self.assertEqual(legacy, reopened.load_current_raw_snapshot(job.key))

    _LEGACY_REFRESH_SCHEMA = """
    CREATE TABLE vacancy_refreshes (
      refresh_id TEXT PRIMARY KEY,
      operation_id TEXT NOT NULL UNIQUE,
      context_sha256 TEXT NOT NULL,
      job_key TEXT NOT NULL,
      expected_content_sha256 TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('intent','fetched','object_ready','committed')),
      started_at TEXT NOT NULL,
      old_content_sha256 TEXT NOT NULL,
      old_fetched_at TEXT NOT NULL,
      old_raw_bytes BLOB NOT NULL,
      old_object_sha256 TEXT NOT NULL,
      new_content_sha256 TEXT,
      new_fetched_at TEXT,
      new_raw_bytes BLOB,
      new_object_sha256 TEXT,
      receipt_basis_json TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(job_key) REFERENCES postings(key) ON DELETE RESTRICT
    )
    """

    _V2_REFRESH_SCHEMA = """
    CREATE TABLE vacancy_refreshes (
      refresh_id TEXT PRIMARY KEY,
      operation_id TEXT NOT NULL UNIQUE,
      context_sha256 TEXT NOT NULL,
      context_json TEXT NOT NULL,
      job_key TEXT NOT NULL,
      expected_content_sha256 TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN (
        'intent','fetch_started','indeterminate','fetched','object_ready','committed'
      )),
      started_at TEXT NOT NULL,
      old_content_sha256 TEXT NOT NULL,
      old_fetched_at TEXT NOT NULL,
      old_raw_bytes BLOB NOT NULL,
      old_object_sha256 TEXT NOT NULL,
      new_content_sha256 TEXT,
      new_fetched_at TEXT,
      new_raw_bytes BLOB,
      new_object_sha256 TEXT,
      receipt_basis_json TEXT,
      receipt_basis_sha256 TEXT,
      transition_sha256 TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(job_key) REFERENCES postings(key) ON DELETE RESTRICT
    )
    """

    @staticmethod
    def _canonical_hash(value: object) -> str:
        return hashlib.sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

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
        write_jsonl(
            root / "raw" / "vacancies" / "injected" / "tenant_1.json", [old_raw]
        )
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

    def _install_legacy_refresh(
        self,
        root: Path,
        config: Path,
        database: JobDatabase,
        old_hash: str,
        *,
        status: str | None,
    ) -> dict[str, object]:
        with sqlite3.connect(database.path) as conn:
            conn.execute("DROP TABLE vacancy_refreshes")
            conn.execute("DROP TABLE vacancy_refresh_migration_quarantine")
            conn.execute(self._LEGACY_REFRESH_SCHEMA)
            if status is None:
                conn.commit()
                return {}
        old_path = root / "raw" / "vacancies" / "injected" / "tenant_1.json"
        old_bytes = old_path.read_bytes()
        old_raw = RawPosting(
            "injected",
            "tenant:1",
            "https://example.test/jobs/1",
            "2026-08-20T00:00:00Z",
            raw_text="old official bytes",
        )
        self.assertEqual(old_bytes, raw_posting_bytes(old_raw))
        new_raw = RawPosting(
            "injected",
            "tenant:1",
            "https://example.test/jobs/1",
            "2026-08-20T05:00:00Z",
            raw_text="legacy fetched official bytes",
        )
        new_bytes = raw_posting_bytes(new_raw)
        new_content = raw_posting_content_sha256(new_raw)
        old_object = hashlib.sha256(old_bytes).hexdigest()
        new_object = hashlib.sha256(new_bytes).hexdigest()
        operation_id = f"legacy-{status}"
        loaded_config = yaml.safe_load(config.read_text(encoding="utf-8"))
        config_sha = self._canonical_hash(loaded_config)
        source_sha = self._canonical_hash(
            {
                "adapter": "injected",
                "adapter_config": loaded_config["injected"],
                "job_key": "injected:tenant:1",
            }
        )
        context = {
            "config_sha256": config_sha,
            "expected_content_sha256": old_hash,
            "job_key": "injected:tenant:1",
            "operation_id": operation_id,
            "schema_version": "market-aligner.vacancy-refresh-context.v1",
            "source_sha256": source_sha,
        }
        context_sha = self._canonical_hash(context)
        refresh_id = self._canonical_hash(
            {
                "context_sha256": context_sha,
                "schema_version": "market-aligner.vacancy-refresh-id.v1",
            }
        )
        receipt = None
        if status == "committed":
            basis = {
                "adapter": "injected",
                "application_authority": False,
                "authority_scope": "collection_only",
                "changed": True,
                "config_sha256": config_sha,
                "context_sha256": context_sha,
                "expected_old_content_sha256": old_hash,
                "fallback_engine": None,
                "finished_at": "2026-08-20T05:01:00Z",
                "job_key": "injected:tenant:1",
                "new_content_sha256": new_content,
                "new_fetched_at": new_raw.fetched_at,
                "new_raw_object_path": str(
                    Path("state")
                    / "collection-refresh-objects"
                    / new_object[:2]
                    / new_object
                ),
                "new_raw_object_sha256": new_object,
                "official_fetch_count": 1,
                "old_content_sha256": old_hash,
                "old_fetched_at": old_raw.fetched_at,
                "old_raw_object_path": str(
                    Path("state")
                    / "collection-refresh-objects"
                    / old_object[:2]
                    / old_object
                ),
                "old_raw_object_sha256": old_object,
                "operation_id": operation_id,
                "raw_cache_file_sha256": new_object,
                "raw_cache_path": "raw/vacancies/injected/tenant_1.json",
                "refresh_id": refresh_id,
                "schema_version": "market-aligner.vacancy-refresh-receipt.v2",
                "source_sha256": source_sha,
                "started_at": "2026-08-20T04:59:00Z",
                "state_sha256": "9" * 64,
            }
            receipt = {**basis, "transition_sha256": self._canonical_hash(basis)}
            database.store_raw(new_raw)
        new_fields = (
            (new_content, new_raw.fetched_at, new_bytes, new_object)
            if status in ("fetched", "object_ready", "committed")
            else (None, None, None, None)
        )
        with sqlite3.connect(database.path) as conn:
            conn.execute(
                """INSERT INTO vacancy_refreshes(
                     refresh_id,operation_id,context_sha256,job_key,
                     expected_content_sha256,status,started_at,old_content_sha256,
                     old_fetched_at,old_raw_bytes,old_object_sha256,
                     new_content_sha256,new_fetched_at,new_raw_bytes,new_object_sha256,
                     receipt_basis_json,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    refresh_id,
                    operation_id,
                    context_sha,
                    "injected:tenant:1",
                    old_hash,
                    status,
                    "2026-08-20T04:59:00Z",
                    old_hash,
                    old_raw.fetched_at,
                    old_bytes,
                    old_object,
                    *new_fields,
                    None
                    if receipt is None
                    else json.dumps(receipt, sort_keys=True, separators=(",", ":")),
                    "2026-08-20 04:59:00",
                    "2026-08-20 05:01:00",
                ),
            )
            conn.commit()
        for digest, value in ((old_object, old_bytes), (new_object, new_bytes)):
            if digest == new_object and status not in ("object_ready", "committed"):
                continue
            object_path = (
                root / "state" / "collection-refresh-objects" / digest[:2] / digest
            )
            object_path.parent.mkdir(parents=True, exist_ok=True)
            object_path.write_bytes(value)
            object_path.chmod(0o600)
        return {
            "context_sha256": context_sha,
            "new_bytes": new_bytes,
            "old_bytes": old_bytes,
            "operation_id": operation_id,
            "refresh_id": refresh_id,
        }

    def _downgrade_refresh_to_v2(
        self,
        database: JobDatabase,
        operation_id: str,
        *,
        status: str,
        corrupt_old_bytes: bool = False,
    ) -> None:
        with sqlite3.connect(database.path) as conn:
            conn.row_factory = sqlite3.Row
            row = dict(
                conn.execute(
                    "SELECT * FROM vacancy_refreshes WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
            )
            if status in ("intent", "fetch_started", "indeterminate"):
                for key in (
                    "new_content_sha256",
                    "new_fetched_at",
                    "new_raw_bytes",
                    "new_object_sha256",
                ):
                    row[key] = None
            row["status"] = status
            if status != "committed":
                old_payload = json.loads(bytes(row["old_raw_bytes"]).decode("utf-8"))
                conn.execute(
                    """UPDATE postings SET url=?,fetched_at=?,raw_text=?,raw_json=?,
                         content_hash=?,fetch_status='fetched',fetch_error=NULL WHERE key=?""",
                    (
                        old_payload["url"],
                        old_payload["fetched_at"],
                        old_payload.get("raw_text"),
                        None
                        if old_payload.get("raw_json") is None
                        else json.dumps(old_payload["raw_json"], ensure_ascii=False),
                        row["old_content_sha256"],
                        row["job_key"],
                    ),
                )
            receipt_json = None
            receipt_basis_sha256 = None
            transition_sha256 = None
            if status == "committed":
                basis = json.loads(row["receipt_basis_json"])
                basis.pop("old_canonical_content_sha256")
                basis.pop("receipt_basis_sha256")
                basis.pop("transition_sha256")
                basis["schema_version"] = "market-aligner.vacancy-refresh-receipt.v2"
                receipt_basis_sha256 = self._canonical_hash(basis)
                transition = {
                    "context_sha256": row["context_sha256"],
                    "expected_content_sha256": row["expected_content_sha256"],
                    "job_key": row["job_key"],
                    "new_content_sha256": row["new_content_sha256"],
                    "new_fetched_at": row["new_fetched_at"],
                    "new_raw_object_sha256": row["new_object_sha256"],
                    "old_content_sha256": row["old_content_sha256"],
                    "old_fetched_at": row["old_fetched_at"],
                    "old_raw_object_sha256": row["old_object_sha256"],
                    "operation_id": row["operation_id"],
                    "receipt_basis_sha256": receipt_basis_sha256,
                    "refresh_id": row["refresh_id"],
                    "schema_version": "market-aligner.vacancy-refresh-transition.v1",
                    "started_at": row["started_at"],
                    "status": "committed",
                }
                transition_sha256 = self._canonical_hash(transition)
                receipt_json = json.dumps(
                    {
                        **basis,
                        "receipt_basis_sha256": receipt_basis_sha256,
                        "transition_sha256": transition_sha256,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            old_bytes = (
                b'{"substituted":true}\n' if corrupt_old_bytes else row["old_raw_bytes"]
            )
            conn.execute("DROP TABLE vacancy_refreshes")
            conn.execute("DROP TABLE vacancy_refresh_migration_quarantine")
            conn.execute(self._V2_REFRESH_SCHEMA)
            conn.execute(
                """INSERT INTO vacancy_refreshes(
                     refresh_id,operation_id,context_sha256,context_json,job_key,
                     expected_content_sha256,status,started_at,old_content_sha256,
                     old_fetched_at,old_raw_bytes,old_object_sha256,new_content_sha256,
                     new_fetched_at,new_raw_bytes,new_object_sha256,receipt_basis_json,
                     receipt_basis_sha256,transition_sha256,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row["refresh_id"],
                    row["operation_id"],
                    row["context_sha256"],
                    row["context_json"],
                    row["job_key"],
                    row["expected_content_sha256"],
                    row["status"],
                    row["started_at"],
                    row["old_content_sha256"],
                    row["old_fetched_at"],
                    old_bytes,
                    row["old_object_sha256"],
                    row["new_content_sha256"],
                    row["new_fetched_at"],
                    row["new_raw_bytes"],
                    row["new_object_sha256"],
                    receipt_json,
                    receipt_basis_sha256,
                    transition_sha256,
                    row["created_at"],
                    row["updated_at"],
                ),
            )

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
            self.assertEqual(
                {"board"}, database.boards_with_pending_discoveries(["board"])
            )
            database.store_raw(
                RawPosting(
                    "board", "1", row.url, "2026-08-01T00:00:00Z", raw_text="complete"
                )
            )
            self.assertTrue(database.has_raw(row.key))
            self.assertEqual(set(), database.boards_with_pending_discoveries(["board"]))

            urls = root / "legacy" / "urls.jsonl"
            database.export_urls(urls)
            imported = JobDatabase(root / "state" / "imported.sqlite3")
            added, fetched = imported.import_existing(urls, root / "missing-cache")
            self.assertEqual((1, 0), (added, fetched))

    def test_empty_v2_refresh_schema_migrates_with_archive(self) -> None:
        class Adapter:
            board = "injected"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _config, database, _old_hash, _calls, _factory = self._refresh_fixture(
                root, Adapter()
            )
            with sqlite3.connect(database.path) as conn:
                conn.execute("DROP TABLE vacancy_refreshes")
                conn.execute("DROP TABLE vacancy_refresh_migration_quarantine")
                conn.execute(self._V2_REFRESH_SCHEMA)
            JobDatabase(database.path)
            with sqlite3.connect(database.path) as conn:
                columns = [
                    row[1]
                    for row in conn.execute("PRAGMA table_info(vacancy_refreshes)")
                ]
                self.assertIn("old_canonical_content_sha256", columns)
                self.assertEqual(
                    0,
                    conn.execute(
                        "SELECT COUNT(*) FROM vacancy_refreshes_v2"
                    ).fetchone()[0],
                )

    def test_v2_committed_refresh_migrates_and_replays(self) -> None:
        class Adapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                return RawPosting(
                    job.board,
                    job.job_id,
                    job.url,
                    "2026-08-20T01:00:00Z",
                    raw_text="v2 new bytes",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = Adapter()
            config, database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
            service = CollectionService(root, collector_factory=factory)
            service.refresh_vacancy(
                config,
                job_key="injected:tenant:1",
                expected_content_sha256=old_hash,
                operation_id="v2-committed",
                log=lambda _message: None,
            )
            self._downgrade_refresh_to_v2(database, "v2-committed", status="committed")
            reopened = JobDatabase(database.path)
            with sqlite3.connect(database.path) as conn:
                self.assertEqual(
                    1,
                    conn.execute(
                        "SELECT COUNT(*) FROM vacancy_refreshes_v2"
                    ).fetchone()[0],
                )
            context_sha = (
                sqlite3.connect(database.path)
                .execute(
                    "SELECT context_sha256 FROM vacancy_refreshes WHERE operation_id='v2-committed'"
                )
                .fetchone()[0]
            )
            transition = reopened.refresh_transition(
                "v2-committed", context_sha256=context_sha
            )
            self.assertEqual(
                "market-aligner.vacancy-refresh-receipt.v3",
                transition["receipt_basis"]["schema_version"],
            )
            self.assertEqual(
                "market-aligner.vacancy-refresh-v2-to-v3.v1",
                transition["receipt_basis"]["journal_migration"],
            )
            replay = service.refresh_vacancy(
                config,
                job_key="injected:tenant:1",
                expected_content_sha256=old_hash,
                operation_id="v2-committed",
                log=lambda _message: None,
            )
            self.assertEqual(
                "market-aligner.vacancy-refresh-receipt.v3", replay["schema_version"]
            )
            self.assertEqual(1, calls["fetch"])

    def test_v2_inflight_refresh_migrates_and_resumes_without_refetch(self) -> None:
        class Adapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                return RawPosting(
                    job.board,
                    job.job_id,
                    job.url,
                    "2026-08-20T01:00:00Z",
                    raw_text="v2 fetched bytes",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = Adapter()
            config, database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
            CollectionService(root, collector_factory=factory).refresh_vacancy(
                config,
                job_key="injected:tenant:1",
                expected_content_sha256=old_hash,
                operation_id="v2-fetched",
                log=lambda _message: None,
            )
            self._downgrade_refresh_to_v2(database, "v2-fetched", status="fetched")
            JobDatabase(database.path)
            receipt = CollectionService(
                root, collector_factory=factory
            ).refresh_vacancy(
                config,
                job_key="injected:tenant:1",
                expected_content_sha256=old_hash,
                operation_id="v2-fetched",
                log=lambda _message: None,
            )
            self.assertEqual(
                "market-aligner.vacancy-refresh-receipt.v3", receipt["schema_version"]
            )
            self.assertEqual(1, calls["fetch"])

    def test_invalid_v2_refresh_is_archived_and_quarantined(self) -> None:
        class Adapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                return RawPosting(
                    job.board,
                    job.job_id,
                    job.url,
                    "2026-08-20T01:00:00Z",
                    raw_text="v2 bytes",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = Adapter()
            config, database, old_hash, _calls, factory = self._refresh_fixture(
                root, adapter
            )
            CollectionService(root, collector_factory=factory).refresh_vacancy(
                config,
                job_key="injected:tenant:1",
                expected_content_sha256=old_hash,
                operation_id="v2-invalid",
                log=lambda _message: None,
            )
            self._downgrade_refresh_to_v2(
                database, "v2-invalid", status="committed", corrupt_old_bytes=True
            )
            reopened = JobDatabase(database.path)
            with sqlite3.connect(database.path) as conn:
                self.assertEqual(
                    1,
                    conn.execute(
                        "SELECT COUNT(*) FROM vacancy_refreshes_v2"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    1,
                    conn.execute(
                        "SELECT COUNT(*) FROM vacancy_refresh_migration_quarantine"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    0,
                    conn.execute("SELECT COUNT(*) FROM vacancy_refreshes").fetchone()[
                        0
                    ],
                )
                context_sha = conn.execute(
                    "SELECT context_sha256 FROM vacancy_refreshes_v2 WHERE operation_id='v2-invalid'"
                ).fetchone()[0]
            with self.assertRaises(VacancyRefreshIndeterminate):
                reopened.refresh_transition("v2-invalid", context_sha256=context_sha)

    def test_empty_036d_refresh_schema_migrates_explicitly(self) -> None:
        class Adapter:
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, database, old_hash, _calls, _factory = self._refresh_fixture(
                root, Adapter()
            )
            self._install_legacy_refresh(root, config, database, old_hash, status=None)
            JobDatabase(database.path)
            with sqlite3.connect(database.path) as conn:
                columns = tuple(
                    row[1]
                    for row in conn.execute("PRAGMA table_info(vacancy_refreshes)")
                )
                archived = conn.execute(
                    "SELECT COUNT(*) FROM vacancy_refreshes_legacy_036d"
                ).fetchone()[0]
            self.assertIn("context_json", columns)
            self.assertIn("receipt_basis_sha256", columns)
            self.assertEqual(0, archived)

    def test_036d_inflight_refreshes_are_preserved_and_fail_closed(self) -> None:
        class ForbiddenAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, _job, live=False):
                self.calls["fetch"] += 1
                raise AssertionError("quarantined legacy transition must never refetch")

        for legacy_status in ("intent", "fetched", "object_ready"):
            with (
                self.subTest(status=legacy_status),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                adapter = ForbiddenAdapter()
                config, database, old_hash, calls, factory = self._refresh_fixture(
                    root, adapter
                )
                legacy = self._install_legacy_refresh(
                    root, config, database, old_hash, status=legacy_status
                )
                reopened = JobDatabase(database.path)
                with sqlite3.connect(database.path) as conn:
                    current_count = conn.execute(
                        "SELECT COUNT(*) FROM vacancy_refreshes"
                    ).fetchone()[0]
                    archived = conn.execute(
                        """SELECT status,old_raw_bytes,new_raw_bytes
                           FROM vacancy_refreshes_legacy_036d WHERE operation_id=?""",
                        (legacy["operation_id"],),
                    ).fetchone()
                    quarantine = conn.execute(
                        """SELECT legacy_status,legacy_row_sha256,reason
                           FROM vacancy_refresh_migration_quarantine WHERE operation_id=?""",
                        (legacy["operation_id"],),
                    ).fetchone()
                self.assertEqual(0, current_count)
                self.assertEqual(legacy_status, archived[0])
                self.assertEqual(legacy["old_bytes"], archived[1])
                if legacy_status != "intent":
                    self.assertEqual(legacy["new_bytes"], archived[2])
                self.assertEqual(legacy_status, quarantine[0])
                self.assertEqual(64, len(quarantine[1]))
                self.assertIn("explicit reconciliation", quarantine[2])
                with self.assertRaises(VacancyRefreshIndeterminate):
                    reopened.refresh_transition(
                        str(legacy["operation_id"]),
                        context_sha256=str(legacy["context_sha256"]),
                    )
                with self.assertRaises(VacancyRefreshIndeterminate):
                    CollectionService(root, collector_factory=factory).refresh_vacancy(
                        config,
                        job_key="injected:tenant:1",
                        expected_content_sha256=old_hash,
                        operation_id=f"replacement-{legacy_status}",
                        log=lambda _message: None,
                    )
                self.assertEqual(0, calls["fetch"])

    def test_036d_completed_refresh_is_verified_projected_and_replayable(self) -> None:
        class ForbiddenAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, _job, live=False):
                self.calls["fetch"] += 1
                raise AssertionError("completed legacy transition must never refetch")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = ForbiddenAdapter()
            config, database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
            legacy = self._install_legacy_refresh(
                root, config, database, old_hash, status="committed"
            )
            reopened = JobDatabase(database.path)
            transition = reopened.refresh_transition(
                str(legacy["operation_id"]),
                context_sha256=str(legacy["context_sha256"]),
            )
            self.assertIsNotNone(transition)
            self.assertEqual("committed", transition["status"])
            self.assertEqual(
                "market-aligner.vacancy-refresh-036d-to-current.v1",
                transition["receipt_basis"]["journal_migration"],
            )
            with sqlite3.connect(database.path) as conn:
                archived = conn.execute(
                    """SELECT old_raw_bytes,new_raw_bytes,receipt_basis_json
                       FROM vacancy_refreshes_legacy_036d WHERE operation_id=?""",
                    (legacy["operation_id"],),
                ).fetchone()
                quarantined = conn.execute(
                    "SELECT COUNT(*) FROM vacancy_refresh_migration_quarantine"
                ).fetchone()[0]
            self.assertEqual(legacy["old_bytes"], archived[0])
            self.assertEqual(legacy["new_bytes"], archived[1])
            self.assertIsNotNone(archived[2])
            self.assertEqual(0, quarantined)
            receipt = CollectionService(
                root, collector_factory=factory
            ).refresh_vacancy(
                config,
                job_key="injected:tenant:1",
                expected_content_sha256=old_hash,
                operation_id=str(legacy["operation_id"]),
                log=lambda _message: None,
            )
            self.assertEqual(0, calls["fetch"])
            self.assertEqual(
                transition["transition_sha256"], receipt["transition_sha256"]
            )

    def test_quarantined_036d_archive_tampering_is_rejected_on_reopen(self) -> None:
        class Adapter:
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, database, old_hash, _calls, _factory = self._refresh_fixture(
                root, Adapter()
            )
            self._install_legacy_refresh(
                root, config, database, old_hash, status="fetched"
            )
            JobDatabase(database.path)
            with sqlite3.connect(database.path) as conn:
                conn.execute(
                    """UPDATE vacancy_refreshes_legacy_036d SET old_raw_bytes=?
                       WHERE operation_id='legacy-fetched'""",
                    (b"substituted archived bytes",),
                )
                conn.commit()
            with self.assertRaisesRegex(
                VacancyRefreshConflict, "legacy refresh row identity differs"
            ):
                JobDatabase(database.path)

    def test_036d_disposition_orphan_duplicate_and_projection_substitution_fail_closed(
        self,
    ) -> None:
        class ForbiddenAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, _job, live=False):
                self.calls["fetch"] += 1
                raise AssertionError(
                    "invalid legacy disposition must block before fetch"
                )

        for corruption in ("orphan", "duplicate", "projection", "archive"):
            with (
                self.subTest(corruption=corruption),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                adapter = ForbiddenAdapter()
                config, database, old_hash, calls, _factory = self._refresh_fixture(
                    root, adapter
                )
                legacy_status = "intent" if corruption == "orphan" else "committed"
                legacy = self._install_legacy_refresh(
                    root, config, database, old_hash, status=legacy_status
                )
                reopened = JobDatabase(database.path)
                with sqlite3.connect(database.path) as conn:
                    if corruption == "orphan":
                        conn.execute(
                            "DELETE FROM vacancy_refresh_migration_quarantine WHERE operation_id=?",
                            (legacy["operation_id"],),
                        )
                    elif corruption == "duplicate":
                        archived = conn.execute(
                            """SELECT refresh_id,job_key,expected_content_sha256,status
                               FROM vacancy_refreshes_legacy_036d WHERE operation_id=?""",
                            (legacy["operation_id"],),
                        ).fetchone()
                        receipt = json.loads(
                            conn.execute(
                                "SELECT receipt_basis_json FROM vacancy_refreshes WHERE operation_id=?",
                                (legacy["operation_id"],),
                            ).fetchone()[0]
                        )
                        conn.execute(
                            """INSERT INTO vacancy_refresh_migration_quarantine(
                                 operation_id,refresh_id,job_key,expected_content_sha256,
                                 legacy_status,legacy_table,legacy_row_sha256,reason
                               ) VALUES(?,?,?,?,?,'vacancy_refreshes_legacy_036d',?,?)""",
                            (
                                legacy["operation_id"],
                                archived[0],
                                archived[1],
                                archived[2],
                                archived[3],
                                receipt["legacy_archive_row_sha256"],
                                "injected duplicate disposition",
                            ),
                        )
                    elif corruption == "archive":
                        conn.execute(
                            """UPDATE vacancy_refreshes_legacy_036d SET old_raw_bytes=?
                               WHERE operation_id=?""",
                            (b"substituted archive", legacy["operation_id"]),
                        )
                    else:
                        row = conn.execute(
                            """SELECT context_sha256,expected_content_sha256,job_key,
                                      new_content_sha256,new_fetched_at,new_object_sha256,
                                      old_content_sha256,old_fetched_at,old_object_sha256,
                                      operation_id,refresh_id,started_at,receipt_basis_json
                               FROM vacancy_refreshes WHERE operation_id=?""",
                            (legacy["operation_id"],),
                        ).fetchone()
                        receipt = json.loads(row[12])
                        receipt.pop("receipt_basis_sha256")
                        receipt.pop("transition_sha256")
                        receipt["legacy_archive_row_sha256"] = "f" * 64
                        basis_sha = self._canonical_hash(receipt)
                        transition_document = {
                            "context_sha256": row[0],
                            "expected_content_sha256": row[1],
                            "job_key": row[2],
                            "new_content_sha256": row[3],
                            "new_fetched_at": row[4],
                            "new_raw_object_sha256": row[5],
                            "old_content_sha256": row[6],
                            "old_fetched_at": row[7],
                            "old_raw_object_sha256": row[8],
                            "operation_id": row[9],
                            "receipt_basis_sha256": basis_sha,
                            "refresh_id": row[10],
                            "schema_version": "market-aligner.vacancy-refresh-transition.v1",
                            "started_at": row[11],
                            "status": "committed",
                        }
                        transition_sha = self._canonical_hash(transition_document)
                        resealed = {
                            **receipt,
                            "receipt_basis_sha256": basis_sha,
                            "transition_sha256": transition_sha,
                        }
                        conn.execute(
                            """UPDATE vacancy_refreshes SET receipt_basis_json=?,
                                 receipt_basis_sha256=?,transition_sha256=?
                               WHERE operation_id=?""",
                            (
                                json.dumps(
                                    resealed, sort_keys=True, separators=(",", ":")
                                ),
                                basis_sha,
                                transition_sha,
                                legacy["operation_id"],
                            ),
                        )
                    conn.commit()

                if corruption == "orphan":
                    context = {
                        "config_sha256": "1" * 64,
                        "expected_content_sha256": old_hash,
                        "job_key": "injected:tenant:1",
                        "operation_id": "blocked-after-quarantine-deletion",
                        "schema_version": "market-aligner.vacancy-refresh-context.v1",
                        "source_sha256": "2" * 64,
                    }
                    context_sha = self._canonical_hash(context)
                    refresh_id = self._canonical_hash(
                        {
                            "context_sha256": context_sha,
                            "schema_version": "market-aligner.vacancy-refresh-id.v1",
                        }
                    )
                    with self.assertRaisesRegex(
                        VacancyRefreshConflict, "exactly one current or quarantine"
                    ):
                        reopened.begin_vacancy_refresh(
                            refresh_id=refresh_id,
                            operation_id="blocked-after-quarantine-deletion",
                            context_sha256=context_sha,
                            context_document=context,
                            job_key="injected:tenant:1",
                            expected_content_sha256=old_hash,
                            started_at="2026-08-21T00:00:00Z",
                            old_raw_bytes=legacy["old_bytes"],
                        )
                else:
                    with self.assertRaises(VacancyRefreshConflict):
                        JobDatabase(database.path)
                self.assertEqual(0, calls["fetch"])

    def test_refresh_objects_reject_symlinked_directory_and_object(self) -> None:
        class Adapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, _job, live=False):
                self.calls["fetch"] += 1
                raise AssertionError("unsafe object path must fail before network")

        for attack in ("directory", "object", "hardlink"):
            with (
                self.subTest(attack=attack),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                adapter = Adapter()
                config, _database, old_hash, calls, factory = self._refresh_fixture(
                    root, adapter
                )
                old_cache = root / "raw" / "vacancies" / "injected" / "tenant_1.json"
                old_object = hashlib.sha256(old_cache.read_bytes()).hexdigest()
                objects = root / "state" / "collection-refresh-objects"
                outside = root / "outside"
                outside.mkdir()
                if attack == "directory":
                    objects.symlink_to(outside, target_is_directory=True)
                else:
                    bucket = objects / old_object[:2]
                    bucket.mkdir(parents=True)
                    target = outside / "target"
                    target.write_bytes(old_cache.read_bytes())
                    target.chmod(0o600)
                    if attack == "object":
                        (bucket / old_object).symlink_to(target)
                    else:
                        (bucket / old_object).hardlink_to(target)
                with self.assertRaises(VacancyRefreshConflict):
                    CollectionService(root, collector_factory=factory).refresh_vacancy(
                        config,
                        job_key="injected:tenant:1",
                        expected_content_sha256=old_hash,
                        operation_id=f"unsafe-{attack}",
                        log=lambda _message: None,
                    )
                self.assertEqual(0, calls["fetch"])

    def test_collector_has_no_result_cap_and_persists_all_discoveries(self) -> None:
        class BulkAdapter:
            board = "bulk"

            def discover(self, _terms, live=False):
                self.assert_live = live
                for index in range(301):
                    yield JobUrl("bulk", str(index), f"https://example.test/{index}")

            def fetch(self, row, live=False):
                return RawPosting(
                    row.board,
                    row.job_id,
                    row.url,
                    row.discovered_at or "2026-08-01T00:00:00Z",
                    raw_text="x",
                )

        with tempfile.TemporaryDirectory() as temporary:
            config = {
                "boards": {"enabled": ["bulk"]},
                "collection": {"source_workers": 1, "fetch_workers": 8},
                "bulk": {"minimum_poll_minutes": 0},
            }
            collector = Collector(config, Path(temporary), log=lambda _message: None)
            with mock.patch(
                "market_aligner.collectors.engine.load_adapter",
                return_value=BulkAdapter(),
            ):
                result = collector.cycle()
            self.assertEqual(301, result["seen"])
            self.assertEqual(301, result["new"])
            self.assertEqual(301, result["fetched"])
            self.assertEqual(301, collector.db.stats()["postings"])

    def test_service_resumes_interrupted_fetch_and_emits_hash_bound_receipts(
        self,
    ) -> None:
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
                    row.discovered_at or "2026-08-20T00:00:00Z",
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

            def now() -> datetime:
                return datetime(2026, 8, 20, tzinfo=timezone.utc)

            service = CollectionService(
                root, collector_factory=collector_factory, now=now
            )

            first = service.collect(
                config,
                once=True,
                hours=0,
                poll_minutes=1,
                operation_id="collect-fixture-0001",
                log=lambda _message: None,
            )
            self.assertEqual(
                {"seen": 2, "new": 2, "fetched": 1, "errors": 1}, first["totals"]
            )
            self.assertFalse(first["application_authority"])
            self.assertEqual("collection_only", first["authority_scope"])
            self.assertTrue(Path(first["receipt_path"]).is_file())

            second = service.collect(
                config,
                once=True,
                hours=0,
                poll_minutes=1,
                operation_id="collect-fixture-0002",
                log=lambda _message: None,
            )
            self.assertEqual(
                {"seen": 2, "new": 0, "fetched": 1, "errors": 0}, second["totals"]
            )
            self.assertEqual(first["config_sha256"], second["config_sha256"])
            self.assertEqual(first["source_sha256"], second["source_sha256"])
            self.assertNotEqual(first["state_sha256"], second["state_sha256"])
            attempts_before_replay = dict(attempts)
            replay = service.collect(
                config,
                once=True,
                hours=0,
                poll_minutes=1,
                operation_id="collect-fixture-0002",
                log=lambda _message: None,
            )
            self.assertTrue(replay["replayed"])
            self.assertEqual("completed", replay["disposition"])
            self.assertEqual(attempts_before_replay, attempts)
            database = JobDatabase(root / "state" / "vacancies.sqlite3")
            self.assertEqual(2, database.stats()["fetched"])
            stored = json.loads(
                Path(second["receipt_path"]).read_text(encoding="utf-8")
            )
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
            config, database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
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
            _job, current_hash, fetched_at = database.fetched_posting(
                "injected:tenant:1"
            )
            self.assertEqual(receipt["new_content_sha256"], current_hash)
            self.assertEqual("2026-08-20T01:00:00Z", fetched_at)
            stored = json.loads(
                Path(receipt["receipt_path"]).read_text(encoding="utf-8")
            )
            self.assertEqual(receipt["receipt_sha256"], stored["receipt_sha256"])
            raw_cache = root / receipt["raw_cache_path"]
            self.assertTrue(raw_cache.is_file())
            self.assertEqual(
                receipt["raw_cache_file_sha256"],
                hashlib.sha256(raw_cache.read_bytes()).hexdigest(),
            )
            for object_key in ("old_raw_object_path", "new_raw_object_path"):
                object_path = root / receipt[object_key]
                self.assertEqual(0o600, object_path.stat().st_mode & 0o777)
                self.assertEqual(1, object_path.stat().st_nlink)
                self.assertEqual(0o700, object_path.parent.stat().st_mode & 0o777)
            self.assertEqual(
                0o700,
                (root / "state" / "collection-refresh-objects").stat().st_mode & 0o777,
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
            config, database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
            receipt = CollectionService(
                root, collector_factory=factory
            ).refresh_vacancy(
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

    def test_exact_refresh_bridges_legacy_json_order_without_false_change(self) -> None:
        class JsonAdapter:
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
                    raw_json={"z": 1, "a": {"y": 2, "b": 3}},
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = JsonAdapter()
            config, database, _old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
            old = RawPosting(
                "injected",
                "tenant:1",
                "https://example.test/jobs/1",
                "2026-08-20T00:00:00Z",
                raw_json={"z": 1, "a": {"y": 2, "b": 3}},
            )
            database.store_raw(old)
            old_cache = root / "raw" / "vacancies" / "injected" / "tenant_1.json"
            write_jsonl(old_cache, [old])
            exact_old_bytes = old_cache.read_bytes()
            _job, legacy_hash, _fetched_at = database.fetched_posting(old.key)
            cache_payload = json.loads(exact_old_bytes)
            canonical_hash = raw_posting_content_sha256(
                RawPosting(
                    old.board,
                    old.job_id,
                    old.url,
                    old.fetched_at,
                    raw_json=cache_payload["raw_json"],
                )
            )
            self.assertNotEqual(legacy_hash, canonical_hash)

            receipt = CollectionService(
                root, collector_factory=factory
            ).refresh_vacancy(
                config,
                job_key=old.key,
                expected_content_sha256=legacy_hash,
                operation_id="legacy-json-order",
                log=lambda _message: None,
            )
            self.assertEqual(1, calls["fetch"])
            self.assertFalse(receipt["changed"])
            self.assertEqual(legacy_hash, receipt["old_content_sha256"])
            self.assertEqual(canonical_hash, receipt["old_canonical_content_sha256"])
            self.assertEqual(canonical_hash, receipt["new_content_sha256"])
            self.assertEqual(
                exact_old_bytes, (root / receipt["old_raw_object_path"]).read_bytes()
            )

    def test_exact_refresh_rejects_cache_semantic_mismatch_before_fetch(self) -> None:
        class NeverAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                raise AssertionError("fetch must not run")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = NeverAdapter()
            config, _database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
            write_jsonl(
                root / "raw" / "vacancies" / "injected" / "tenant_1.json",
                [
                    RawPosting(
                        "injected",
                        "tenant:1",
                        "https://example.test/jobs/1",
                        "2026-08-20T00:00:00Z",
                        raw_text="substituted bytes",
                    )
                ],
            )
            with self.assertRaisesRegex(ValueError, "differs semantically"):
                CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="semantic-mismatch",
                    log=lambda _message: None,
                )
            self.assertEqual(0, calls["fetch"])

    def test_exact_refresh_semantic_bridge_is_json_type_strict(self) -> None:
        class NeverAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                raise AssertionError("fetch must not run")

        cases = (
            ("bool-int", {"value": True}, {"value": 1}),
            ("int-float", {"value": 1}, {"value": 1.0}),
            (
                "nested-bool-int",
                {"items": [{"value": False}]},
                {"items": [{"value": 0}]},
            ),
            ("list-int-float", {"items": [1, 2]}, {"items": [1.0, 2]}),
        )
        for label, database_json, cache_json in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                adapter = NeverAdapter()
                config, database, _old_hash, calls, factory = self._refresh_fixture(
                    root, adapter
                )
                database_raw = RawPosting(
                    "injected",
                    "tenant:1",
                    "https://example.test/jobs/1",
                    "2026-08-20T00:00:00Z",
                    raw_json=database_json,
                )
                database.store_raw(database_raw)
                write_jsonl(
                    root / "raw" / "vacancies" / "injected" / "tenant_1.json",
                    [
                        RawPosting(
                            database_raw.board,
                            database_raw.job_id,
                            database_raw.url,
                            database_raw.fetched_at,
                            raw_json=cache_json,
                        )
                    ],
                )
                old_hash = database.fetched_posting(database_raw.key)[1]
                with self.assertRaisesRegex(ValueError, "differs semantically"):
                    CollectionService(root, collector_factory=factory).refresh_vacancy(
                        config,
                        job_key=database_raw.key,
                        expected_content_sha256=old_hash,
                        operation_id=f"type-strict-{label}",
                        log=lambda _message: None,
                    )
                self.assertEqual(0, calls["fetch"])

    def test_exact_refresh_rejects_nonfinite_json_before_fetch(self) -> None:
        class NeverAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                raise AssertionError("fetch must not run")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = NeverAdapter()
            config, _database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
            write_jsonl(
                root / "raw" / "vacancies" / "injected" / "tenant_1.json",
                [
                    RawPosting(
                        "injected",
                        "tenant:1",
                        "https://example.test/jobs/1",
                        "2026-08-20T00:00:00Z",
                        raw_json={"value": float("nan")},
                    )
                ],
            )
            with self.assertRaisesRegex(ValueError, "not valid UTF-8 JSON"):
                CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="nonfinite-json",
                    log=lambda _message: None,
                )
            self.assertEqual(0, calls["fetch"])

    def test_exact_refresh_rejects_legacy_db_text_identity_mismatch(self) -> None:
        class NeverAdapter:
            board = "injected"

            def owns(self, _job):
                return True

            def fetch(self, job, live=False):
                self.calls["fetch"] += 1
                raise AssertionError("fetch must not run")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = NeverAdapter()
            config, database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
            with sqlite3.connect(database.path) as conn:
                conn.execute(
                    "UPDATE postings SET raw_text=? WHERE key=?",
                    ("same authority was silently changed", "injected:tenant:1"),
                )
            with self.assertRaisesRegex(VacancyRefreshConflict, "legacy identity"):
                CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="db-text-mismatch",
                    log=lambda _message: None,
                )
            self.assertEqual(0, calls["fetch"])

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
            config, database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
            with self.assertRaises(VacancyRefreshConflict):
                CollectionService(root, collector_factory=factory).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id="racing-refresh",
                    log=lambda _message: None,
                )
            self.assertEqual(1, calls["fetch"])
            self.assertNotEqual(
                old_hash, database.fetched_posting("injected:tenant:1")[1]
            )
            self.assertFalse((root / "state" / "collection-refresh-receipts").exists())
            self.assertIn(
                b"old official bytes",
                (
                    root / "raw" / "vacancies" / "injected" / "tenant_1.json"
                ).read_bytes(),
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
            config, database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )
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
            config, database, old_hash, calls, factory = self._refresh_fixture(
                root, adapter
            )

            def crash_factory(loaded_config, data_home, log=print):
                collector = factory(loaded_config, data_home, log=log)

                def inject(point):
                    if point == "after_fetch_before_persist":
                        raise RuntimeError("lost-after-official-return")

                collector.crash_injector = inject
                return collector

            with self.assertRaisesRegex(RuntimeError, "lost-after-official-return"):
                CollectionService(
                    root, collector_factory=crash_factory
                ).refresh_vacancy(
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

        def substitute_bool_for_integer(conn, _receipt, _root):
            conn.row_factory = sqlite3.Row
            row = dict(
                conn.execute(
                    "SELECT * FROM vacancy_refreshes WHERE operation_id=?",
                    ("tamper-refresh",),
                ).fetchone()
            )
            basis = json.loads(row["receipt_basis_json"])
            basis.pop("receipt_basis_sha256")
            basis.pop("transition_sha256")
            basis["official_fetch_count"] = True
            basis_sha256 = self._canonical_hash(basis)
            transition = {
                "context_sha256": row["context_sha256"],
                "expected_content_sha256": row["expected_content_sha256"],
                "job_key": row["job_key"],
                "new_content_sha256": row["new_content_sha256"],
                "new_fetched_at": row["new_fetched_at"],
                "new_raw_object_sha256": row["new_object_sha256"],
                "old_canonical_content_sha256": row["old_canonical_content_sha256"],
                "old_content_sha256": row["old_content_sha256"],
                "old_fetched_at": row["old_fetched_at"],
                "old_raw_object_sha256": row["old_object_sha256"],
                "operation_id": row["operation_id"],
                "receipt_basis_sha256": basis_sha256,
                "refresh_id": row["refresh_id"],
                "schema_version": "market-aligner.vacancy-refresh-transition.v2",
                "started_at": row["started_at"],
                "status": "committed",
            }
            transition_sha256 = self._canonical_hash(transition)
            sealed = {
                **basis,
                "receipt_basis_sha256": basis_sha256,
                "transition_sha256": transition_sha256,
            }
            conn.execute(
                """UPDATE vacancy_refreshes SET receipt_basis_json=?,
                     receipt_basis_sha256=?,transition_sha256=? WHERE operation_id=?""",
                (
                    json.dumps(sealed, sort_keys=True, separators=(",", ":")),
                    basis_sha256,
                    transition_sha256,
                    "tamper-refresh",
                ),
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
            "old-canonical-content-hash": lambda conn, _receipt, _root: conn.execute(
                "UPDATE vacancy_refreshes SET old_canonical_content_sha256=? WHERE operation_id=?",
                ("9" * 64, "tamper-refresh"),
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
            "bool-for-integer-with-valid-seals": substitute_bool_for_integer,
        }

        def corrupt_object(_conn, receipt, root):
            (root / receipt["new_raw_object_path"]).write_bytes(
                b"substituted object bytes"
            )

        mutations = {**database_mutations, "object-bytes": corrupt_object}
        for label, mutate in mutations.items():
            with self.subTest(tamper=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                adapter = StableAdapter()
                config, _database, old_hash, calls, factory = self._refresh_fixture(
                    root, adapter
                )
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
            with (
                self.subTest(crash_point=crash_point),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                adapter = RecoverableAdapter()
                config, database, old_hash, calls, factory = self._refresh_fixture(
                    root, adapter
                )
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
                    CollectionService(
                        root, collector_factory=crash_factory
                    ).refresh_vacancy(
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

                receipt = CollectionService(
                    root, collector_factory=factory
                ).refresh_vacancy(
                    config,
                    job_key="injected:tenant:1",
                    expected_content_sha256=old_hash,
                    operation_id=operation_id,
                    log=lambda _message: None,
                )
                self.assertEqual(1, calls["fetch"])
                self.assertEqual(
                    "market-aligner.vacancy-refresh-receipt.v3",
                    receipt["schema_version"],
                )
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

                replay = CollectionService(
                    root, collector_factory=factory
                ).refresh_vacancy(
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
                    row.discovered_at or "2026-08-20T00:00:00Z",
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
            self.assertIn(
                "source ended after page two", state["sources"][0]["last_error"]
            )

    def test_collect_cli_requires_explicit_bounded_mode(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["collect", "--config", "collect.yaml"])
        parsed = parser.parse_args(
            [
                "collect",
                "--config",
                "collect.yaml",
                "--once",
                "--poll-minutes",
                "2",
                "--operation-id",
                "collect-fixture-cli",
            ]
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

    def test_collection_service_rejects_unbounded_run_and_data_home_escape(
        self,
    ) -> None:
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
                    config,
                    once=False,
                    hours=0,
                    poll_minutes=1,
                    operation_id="collect-invalid-0001",
                    log=lambda _message: None,
                )
            with self.assertRaisesRegex(ValueError, r"\(0,24\]"):
                service.collect(
                    config,
                    once=False,
                    hours=25,
                    poll_minutes=1,
                    operation_id="collect-invalid-0002",
                    log=lambda _message: None,
                )
            with self.assertRaisesRegex(ValueError, "external data home"):
                service.collect(
                    config,
                    once=True,
                    hours=0,
                    poll_minutes=1,
                    operation_id="collect-invalid-0003",
                    log=lambda _message: None,
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
                        "--operation-id",
                        "collect-fixture-cli-run",
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


def test_discovery_only_persists_without_fetch_and_resumes(tmp_path):
    calls = []

    class Adapter:
        def discover(self, _terms, live=False):
            yield JobUrl("injected", "one", "https://example.test/one")

        def fetch(self, row, live=False):
            calls.append(row.key)
            return RawPosting(row.board, row.job_id, row.url,
                              datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), raw_text="synthetic posting")

    cfg = {"boards": {"enabled": ["injected"]},
           "collection": {"discover_only": True, "source_workers": 1, "fetch_workers": 1}}
    kwargs = {"log": lambda _: None, "adapter_loader": lambda *a, **kw: Adapter()}
    discovery = Collector(cfg, tmp_path, **kwargs)
    result = discovery.cycle()
    assert result["new"] == 1 and result["fetched"] == 0
    assert calls == []
    assert discovery.urls_path.is_file()
    assert discovery.db.boards_with_pending_discoveries(["injected"]) == {"injected"}
    assert discovery.cycle()["fetched"] == 0
    assert calls == []
    resumed = Collector({**cfg, "collection": {"source_workers": 1, "fetch_workers": 1}},
                        tmp_path, **kwargs)
    assert resumed.cycle()["fetched"] == 1
    assert len(calls) == 1
    assert resumed.db.boards_with_pending_discoveries(["injected"]) == set()


def test_discovery_only_rejects_nonboolean_before_creating_state(tmp_path):
    import pytest
    for index, value in enumerate(["false", "true", 0, 1, None, [], {}]):
        root = tmp_path / str(index)
        with pytest.raises(ValueError, match="discover_only"):
            Collector({"boards": {"enabled": ["injected"]},
                       "collection": {"discover_only": value}}, root)
        assert not root.exists()


def test_saved_trusted_url_fetched_when_not_rediscovered(tmp_path):
    calls = []

    class Adapter:
        def __init__(self):
            self.runs = 0

        def discover(self, _terms, live=False):
            self.runs += 1
            if self.runs == 1:
                yield JobUrl("injected", "one", "https://example.test/one")

        def fetch(self, row, live=False):
            calls.append(row.key)
            return RawPosting(row.board, row.job_id, row.url,
                              datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), raw_text="synthetic posting")

    adapter = Adapter()
    kwargs = {"log": lambda _: None, "adapter_loader": lambda *a, **kw: adapter}
    discovery = Collector({"boards": {"enabled": ["injected"]},
                           "collection": {"discover_only": True,
                                          "source_workers": 1, "fetch_workers": 1}},
                          tmp_path, **kwargs)
    assert discovery.cycle()["fetched"] == 0

    resume = Collector({"boards": {"enabled": ["injected"]},
                        "collection": {"source_workers": 1, "fetch_workers": 1}},
                       tmp_path, **kwargs)
    result = resume.cycle()
    assert result["seen"] == 0 and result["fetched"] == 1
    assert len(calls) == 1
    assert resume.db.pending_discoveries(["injected"]) == []


def test_untrusted_imported_row_is_never_fetched(tmp_path):
    calls = []

    class Adapter:
        def discover(self, _terms, live=False):
            return iter(())

        def fetch(self, row, live=False):
            calls.append(row.key)
            return RawPosting(row.board, row.job_id, row.url,
                              datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), raw_text="synthetic posting")

    collector = Collector({"boards": {"enabled": ["injected"]},
                           "collection": {"source_workers": 1, "fetch_workers": 1}},
                          tmp_path, log=lambda _: None,
                          adapter_loader=lambda *a, **kw: Adapter())
    collector.db.upsert_discovered(JobUrl("injected", "one", "https://example.test/one"))
    assert collector.db.pending_discoveries(["injected"]) == []
    result = collector.cycle()
    assert result["fetched"] == 0
    assert calls == []


def test_saved_pending_selection_requires_exact_trust_and_board(tmp_path):
    db = JobDatabase(tmp_path / "state.sqlite3")
    trusted = JobUrl("injected", "one", "https://example.test/one",
                     discovered_at="2026-09-21T00:00:00Z")
    db.upsert_discovered(trusted, release_trusted=True)
    assert [row.key for row in db.pending_discoveries(["injected"])] == [trusted.key]
    assert db.pending_discoveries([]) == []
    assert db.pending_discoveries(["disabled"]) == []
    db.upsert_discovered(JobUrl("injected", "one", "https://example.test/changed"))
    assert db.pending_discoveries(["injected"]) == []


def test_deadline_preserves_pending_and_resumes_real_collector(tmp_path):
    clock = [0.0]
    calls = []

    class Adapter:
        def discover(self, _terms, live=False):
            for n in range(3):
                yield JobUrl("injected", str(n), f"https://example.test/{n}")

        def fetch(self, row, live=False):
            calls.append(row.key)
            clock[0] += 30
            return RawPosting(row.board, row.job_id, row.url,
                              datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), raw_text="synthetic listing")

    cfg = {"boards": {"enabled": ["injected"]},
           "collection": {"source_workers": 1, "fetch_workers": 1}}
    collector = Collector(cfg, tmp_path, log=lambda _: None,
                          adapter_loader=lambda *a, **kw: Adapter(),
                          monotonic=lambda: clock[0])
    cycles = collector.run(hours=25 / 3600)
    assert len(cycles) == 1
    assert cycles[0]["fetched"] == 1
    assert cycles[0]["errors"] == 0
    assert cycles[0]["database_total"] == 3
    assert len(collector.db.pending_discoveries(["injected"])) == 2
    assert collector.cycle()["fetched"] == 2
    assert len(calls) == len(set(calls)) == 3
    assert collector.db.pending_discoveries(["injected"]) == []


def test_discovery_deadline_preserves_response_crossing_deadline(tmp_path):
    clock = [0.0]
    yielded = []

    class Adapter:
        def discover(self, _terms, live=False):
            for n in range(5):
                clock[0] += 10
                yielded.append(n)
                yield JobUrl("injected", str(n), f"https://example.test/{n}")

        def fetch(self, row, live=False):
            raise AssertionError("deadline must prevent detail fetch")

    collector = Collector({"boards": {"enabled": ["injected"]}}, tmp_path,
                          log=lambda _: None, monotonic=lambda: clock[0],
                          adapter_loader=lambda *a, **kw: Adapter())
    result = collector.cycle(deadline=25)
    assert yielded == [0, 1, 2]
    assert result["seen"] == result["database_total"] == 3
    assert result["fetched"] == result["errors"] == 0


def test_run_does_not_start_new_discovery_after_window_sleep(tmp_path):
    clock = [0.0]
    calls = []

    class Adapter:
        def discover(self, _terms, live=False):
            calls.append("discover")
            return iter(())

    def sleep(seconds):
        clock[0] += seconds

    collector = Collector({"boards": {"enabled": ["injected"]}}, tmp_path,
                          log=lambda _: None, monotonic=lambda: clock[0], sleeper=sleep,
                          adapter_loader=lambda *a, **kw: Adapter())
    assert len(collector.run(hours=10 / 3600)) == 1
    assert calls == ["discover"]
    assert collector.cycle(deadline=clock[0])["seen"] == 0
    assert calls == ["discover"]


def test_collector_delay_and_deadline_resume(tmp_path):
    clock = [0.0]
    starts = []
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    class Adapter:
        def discover(self, _terms, live=False):
            for n in range(3):
                yield JobUrl("injected", str(n), f"https://example.test/{n}")

        def fetch(self, row, live=False):
            starts.append(clock[0])
            return RawPosting(row.board, row.job_id, row.url,
                              datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                              raw_text="synthetic listing")

    collector = Collector({"boards": {"enabled": ["injected"]},
                           "collection": {"delay_seconds": 5, "fetch_workers": 1}},
                          tmp_path, log=lambda _: None, monotonic=lambda: clock[0],
                          sleeper=sleep, adapter_loader=lambda *a, **kw: Adapter())
    result = collector.cycle(deadline=7)
    assert result["fetched"] == 2 and result["errors"] == 0
    assert starts == [0, 5] and sleeps == [5, 2]
    assert len(collector.db.pending_discoveries(["injected"])) == 1
    assert collector.cycle()["fetched"] == 1
    assert starts == [0, 5, 10]


def test_collector_delay_rejects_invalid_before_creating_state(tmp_path):
    import pytest
    for n, value in enumerate([True, False, -1, float("nan"), float("inf"), "5", None]):
        root = tmp_path / str(n)
        with pytest.raises(ValueError, match="delay_seconds"):
            Collector({"boards": {"enabled": ["injected"]},
                       "collection": {"delay_seconds": value}}, root)
        assert not root.exists()


def test_collector_delay_keeps_boards_independent(tmp_path):
    clock = [0.0]
    starts = {}

    def sleep(seconds):
        clock[0] += seconds

    class Adapter:
        def __init__(self, board):
            self.board = board

        def discover(self, _terms, live=False):
            for n in range(2):
                yield JobUrl(self.board, str(n), f"https://example.test/{self.board}/{n}")

        def fetch(self, row, live=False):
            starts.setdefault(row.board, []).append(clock[0])
            return RawPosting(row.board, row.job_id, row.url,
                              datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                              raw_text="synthetic listing")

    collector = Collector({"boards": {"enabled": ["a", "b"]},
                           "collection": {"delay_seconds": 5, "source_workers": 1,
                                          "fetch_workers": 1}},
                          tmp_path, log=lambda _: None, monotonic=lambda: clock[0],
                          sleeper=sleep, adapter_loader=lambda board, **kw: Adapter(board))
    assert collector.cycle()["fetched"] == 4
    assert starts == {"a": [0, 5], "b": [0, 5]}


def test_offline_collection_status_real_cli(tmp_path):
    data = tmp_path / "data"
    cfg = tmp_path / "collection.yaml"
    cfg.write_text(yaml.safe_dump({"boards": {"enabled": ["a", "b", "c"]}}))
    db_path = data / "state" / "vacancies.sqlite3"
    db = JobDatabase(db_path)
    for board, ids in [("a", range(3)), ("b", range(1))]:
        for n in ids:
            job = JobUrl(board, str(n), f"https://example.test/{board}/{n}")
            db.upsert_discovered(job)
            if n == 0:
                db.store_raw(RawPosting(board, str(n), job.url,
                                        "2026-01-01T00:00:00Z", raw_text="synthetic listing"))
            elif n == 1:
                db.record_error(job.key, "fetch_error")
    before = hashlib.sha256(db_path.read_bytes()).hexdigest()
    output = io.StringIO()
    with mock.patch("market_aligner.collectors.engine.load_adapter", side_effect=AssertionError("network forbidden")):
        with redirect_stdout(output):
            rc = main(["collect-status", "--config", str(cfg), "--data-home", str(data)])
    assert rc == 0
    status = json.loads(output.getvalue())
    rows = {r["board"]: r for r in status["boards"]}
    assert rows["a"] == {"board": "a", "discovered": 3, "fetched": 1,
                         "failed": 1, "pending": 1, "state": "partial"}
    assert rows["b"]["state"] == "complete"
    assert rows["c"]["discovered"] == 0
    assert hashlib.sha256(db_path.read_bytes()).hexdigest() == before


def test_offline_collection_status_absent_database(tmp_path):
    data = tmp_path / "absent"
    cfg = tmp_path / "collection.yaml"
    cfg.write_text(yaml.safe_dump({"boards": {"enabled": ["a"]}}))
    output = io.StringIO()
    with redirect_stdout(output):
        rc = main(["collect-status", "--config", str(cfg), "--data-home", str(data)])
    assert rc == 1 and not data.exists()
    status = json.loads(output.getvalue())
    assert status == {"exists": False, "boards": [
        {"board": "a", "discovered": 0, "fetched": 0, "failed": 0,
         "pending": 0, "state": "not_started"}]}


def test_preflight_missing_browser_dependency_fails_without_mutation(tmp_path):
    root = tmp_path / "not-created"
    with mock.patch("market_aligner.collectors.engine.importlib.util.find_spec",
                    side_effect=lambda name: None if name == "playwright" else object()):
        report = Collector.preflight(root, {"boards": {"enabled": ["jobkorea"]}})
    assert not report["ok"] and not root.exists()
    assert any(c["name"] == "dependency:playwright" and not c["ok"] for c in report["checks"])


def test_preflight_credential_presence_never_echoes_value(tmp_path):
    cfg = {"boards": {"enabled": ["saramin"]},
           "saramin": {"access_key_env": "MA_SYNTHETIC_PREFLIGHT_KEY"}}
    with mock.patch.dict(os.environ, {"MA_SYNTHETIC_PREFLIGHT_KEY": "synthetic-secret-never-echo"}):
        report = Collector.preflight(tmp_path / "not-created", cfg)
    check = next(c for c in report["checks"] if c["name"].startswith("credential:"))
    assert check["ok"] and check["detail"] == "set"
    assert "synthetic-secret-never-echo" not in json.dumps(report)
    assert not (tmp_path / "not-created").exists()


def test_preflight_cli_low_disk_and_invalid_shapes(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({"boards": {"enabled": ["wanted"]}}))
    root = tmp_path / "not-created"
    output = io.StringIO()
    with mock.patch("market_aligner.collectors.engine.shutil.disk_usage", return_value=mock.Mock(free=1024)):
        with redirect_stdout(output):
            assert main(["collect-preflight", "--config", str(cfg), "--data-home", str(root)]) == 2
    report = json.loads(output.getvalue())
    assert not report["ok"]
    assert next(c for c in report["checks"] if c["name"] == "disk-free")["ok"] is False
    assert not root.exists()
    with mock.patch("market_aligner.collectors.engine.importlib.util.find_spec") as lookup:
        with __import__("pytest").raises(ValueError):
            Collector.preflight(root, {"boards": {"enabled": []}})
        lookup.assert_not_called()


def test_target_collection_preserves_existing_and_deduplicates(tmp_path):
    calls = []
    cfg = {"boards": {"enabled": ["injected"]},
           "collection": {"target_per_board": 2, "fetch_workers": 1}}

    class Adapter:
        def discover(self, _terms, live=False):
            calls.append("discover")
            for n in [0, 0, 1, 2]:
                yield JobUrl("injected", str(n), f"https://example.test/{n}")

        def fetch(self, row, live=False):
            calls.append(row.key)
            return RawPosting(row.board, row.job_id, row.url,
                              datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                              raw_text="synthetic listing")

    collector = Collector({**cfg, "collection": {**cfg["collection"], "discover_only": True}},
                          tmp_path, log=lambda _: None,
                          adapter_loader=lambda *a, **kw: Adapter())
    first = collector.cycle()
    assert first["database_total"] == 2 and first["fetched"] == 0
    resumed = Collector(cfg, tmp_path, log=lambda _: None,
                        adapter_loader=lambda *a, **kw: Adapter())
    assert resumed.cycle()["fetched"] == 2
    assert len(calls) == 3  # discovery + exactly two distinct detail fetches
    # A smaller subsequent target never truncates saved inventory or raw files.
    smaller = Collector({**cfg, "collection": {"target_per_board": 1}}, tmp_path,
                        log=lambda _: None, adapter_loader=lambda *a, **kw: Adapter())
    assert smaller.cycle()["database_total"] == 2
    assert len(calls) == 3
    assert len(list(collector.raw_cache.rglob("*.json"))) == 2


def test_target_config_and_discovery_depth_are_bounded_and_copied(tmp_path):
    import pytest
    for n, value in enumerate([True, -1, 1.5, "2", None]):
        root = tmp_path / str(n)
        with pytest.raises(ValueError, match="target_per_board"):
            Collector({"boards": {"enabled": ["wanted"]},
                       "collection": {"target_per_board": value}}, root)
        assert not root.exists()
    cfg = {"boards": {"enabled": ["wanted", "jobkorea", "notefolio"]},
           "collection": {"target_per_board": 500},
           "wanted": {"list_limit": 20, "max_pages": 1}}
    collector = Collector(cfg, tmp_path / "valid", log=lambda _: None)
    assert collector._board_config("wanted")["max_pages"] == 30
    assert collector._board_config("jobkorea")["max_pages"] == 8
    assert collector._board_config("notefolio")["max_scrolls"] == 100
    assert cfg["wanted"]["max_pages"] == 1
    assert "jobkorea" not in cfg and "notefolio" not in cfg


def _browser_discovery_canary(tmp_path):
    from market_aligner.collectors.adapters.jobkorea import JobKoreaAdapter
    from market_aligner.collectors.adapters.notefolio import NotefolioAdapter

    jobkorea = tmp_path / "jobkorea.html"
    jobkorea.write_text('''<!doctype html><meta charset="utf-8"><main></main><script>
const page = new URLSearchParams(location.search).get('Page_No') || '1';
for (const [id,sc,text] of [[page==='1'?'100':'200','630','Designer 신입'],['900','630','Senior 경력'],['800','551','Promoted 신입']]) {
const div=document.createElement('div');div.className='w-full';
const a=document.createElement('a');a.className='max-w-[700px]';a.href='https://example.test/Recruit/GI_Read/'+id+'?sc='+sc;a.innerText=text;div.appendChild(a);document.querySelector('main').appendChild(div);
}</script>''')
    cfg = {"search_url": jobkorea.as_uri() + "?kw={kw}", "max_pages": 2,
           "rate_limit_seconds": 0, "entry_only": True}
    entry = list(JobKoreaAdapter(config=cfg).discover(["graphic design"], live=True))
    organic = list(JobKoreaAdapter(config={**cfg, "entry_only": False}).discover(["graphic design"], live=True))
    assert [r.job_id for r in entry] == ["100", "200"]
    assert [r.job_id for r in organic] == ["100", "900", "200"]

    notefolio = tmp_path / "notefolio.html"
    notefolio.write_text('''<!doctype html><meta charset="utf-8"><body style="height:3000px">
<a href="https://notefolio.net/recruit/fallback-id">Legacy anchor</a>
<a class="banner-link" href="https://example.test/jobs/one?utm_source=synthetic">External one</a>
<a class="banner-link" href="javascript:void(0)">Invalid link</a>
<script>
if(new URLSearchParams(location.search).get('search')==='embedded')
window.__NEXT_DATA__={props:{pageProps:{results:[{id:'embedded-id',created_at:'2026-01-01'}]}}};
window.addEventListener('scroll',()=>{if(document.querySelector('#extra'))return;
const a=document.createElement('a');a.id='extra';a.className='banner-link';a.href='https://example.test/jobs/two?ref=synthetic';a.innerText='External two';document.body.appendChild(a);});
</script></body>''')
    rows = list(NotefolioAdapter(config={"recruit_url": notefolio.as_uri(),
                                         "max_scrolls": 5, "scroll_wait_ms": 250}).discover(
                                             ["embedded", "fallback"], live=True))
    ids = {r.job_id for r in rows}
    assert {"embedded-id", "fallback-id"} <= ids
    assert len(rows) == 4 and len(ids) == 4
    assert any(r.url == "https://example.test/jobs/one?utm_source=synthetic" for r in rows)
    assert any(r.url == "https://example.test/jobs/two?ref=synthetic" for r in rows)
    assert next(r for r in rows if r.job_id == "embedded-id").posted_at == "2026-01-01"
    return {"jobkorea_entry": [r.job_id for r in entry],
            "jobkorea_organic": [r.job_id for r in organic],
            "notefolio": [{"key": r.key, "url": r.url} for r in rows]}


def test_browser_discovery_union_with_real_chromium(tmp_path):
    import pytest
    if os.environ.get("MARKET_ALIGNER_BROWSER_CANARY") != "1":
        pytest.skip("Set MARKET_ALIGNER_BROWSER_CANARY=1 with installed Playwright Chromium")
    _browser_discovery_canary(tmp_path)


def _browser_detail_canary(tmp_path):
    import pytest
    from market_aligner.collectors.adapters.jobkorea import JobKoreaAdapter
    from market_aligner.collectors.adapters.notefolio import NotefolioAdapter

    results = {}
    cases = [
        ("jobkorea", "main", "<main>" + "Design responsibilities. " * 20 + "</main>"),
        ("jobkorea", "historical", '<div class="detailArea">' + "Old responsibilities. " * 20 + "</div>"),
        ("notefolio", "embedded", '<script>window.__NEXT_DATA__={props:{pageProps:{recruit:{description:"Embedded role"}}}}</script>'),
        ("notefolio", "short", "<main>Short role description</main>"),
        ("notefolio", "rendered", '<title>Rendered role</title><article>' + "Rendered duties. " * 30 + "</article>"),
    ]
    for board, label, content in cases:
        path = tmp_path / f"{board}-{label}.html"
        path.write_text("<!doctype html><meta charset=utf-8>" + content)
        cls = JobKoreaAdapter if board == "jobkorea" else NotefolioAdapter
        row = cls().fetch(JobUrl(board, label, path.as_uri()), live=True)
        assert row.board == board and row.job_id == label and row.url == path.as_uri()
        if board == "jobkorea":
            assert "responsibilities" in row.raw_text
            assert row.raw_json["source"] == "playwright"
        elif label == "embedded":
            assert row.raw_json["description"] == "Embedded role"
        elif label == "short":
            assert row.raw_json["description_text"] == "Short role description"
        else:
            assert "Rendered duties" in row.raw_text
            assert row.raw_json["rendered_title"] == "Rendered role"
        results[f"{board}-{label}"] = {"raw_text": row.raw_text, "raw_json": row.raw_json}

    for board, content in [("jobkorea", "<main></main>"),
                           ("notefolio", '<script>window.__NEXT_DATA__={props:{pageProps:{recruit:{id:"only-id"}}}}</script>')]:
        path = tmp_path / f"{board}-missing.html"
        path.write_text(content)
        cls = JobKoreaAdapter if board == "jobkorea" else NotefolioAdapter
        with pytest.raises(RuntimeError, match="detail body missing"):
            cls().fetch(JobUrl(board, "missing", path.as_uri()), live=True)
        results[f"{board}-missing"] = "rejected"
    return results


def test_browser_detail_union_with_real_chromium(tmp_path):
    import pytest
    if os.environ.get("MARKET_ALIGNER_BROWSER_CANARY") != "1":
        pytest.skip("Set MARKET_ALIGNER_BROWSER_CANARY=1 with installed Playwright Chromium")
    _browser_detail_canary(tmp_path)
