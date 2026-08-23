"""INGEST-001 acceptance coverage.

The positive tests traverse a fixture adapter through the real Collector
persistence path (canonical ``Collector.cycle`` -> ``JobDatabase`` -> raw
cache), not through argument mocks. Only the adapter seam is substituted,
mirroring the established pattern in :mod:`tests.test_collection`.
"""

from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from market_aligner.cli import main
from market_aligner.collectors.adapters.base import Adapter
from market_aligner.collectors.engine import Collector
from market_aligner.state.operations import (
    INGEST_CYCLE_KIND,
    OperationJournal,
    content_sha256,
    derive_operation_id,
    make_record,
)
from market_aligner.state.vacancies import JobDatabase


class KillDuringCycle(BaseException):
    """Simulates abrupt process death; cannot be caught by ``except Exception``."""


FIXTURE_BOARDS = (
    {"id": "1", "title": "Platform Engineer", "company": "Example"},
    {"id": "2", "title": "Data Engineer", "company": "Example"},
    {"id": "3", "title": "QA Engineer", "company": "Example"},
)


class FixtureBoard(Adapter):
    board = "fixtureboard"

    def __init__(self, fixture_dir=None, config=None, calls=None, fail_ids=()):
        super().__init__(fixture_dir=fixture_dir, config=config)
        self.calls = calls if calls is not None else []
        self.fail_ids = frozenset(fail_ids)

    def discover(self, search_terms, live=False):
        self.calls.append(("discover", tuple(search_terms)))
        yield from super().discover(search_terms, live=False)

    def fetch(self, job_url, live=False):
        self.calls.append(("fetch", job_url.job_id))
        if job_url.job_id in self.fail_ids:
            raise RuntimeError(f"provider refused {job_url.job_id}")
        return super().fetch(job_url, live=False)


def _write_workspace(root: Path) -> Path:
    fixtures = root / "fixtures"
    (fixtures / "fixtureboard").mkdir(parents=True)
    (fixtures / "fixtureboard_listing.json").write_text(json.dumps(FIXTURE_BOARDS), encoding="utf-8")
    for entry in FIXTURE_BOARDS:
        detail = {"title": entry["title"], "body": f"detail {entry['id']}"}
        (fixtures / "fixtureboard" / f"{entry['id']}.json").write_text(
            json.dumps(detail), encoding="utf-8"
        )
    config = root / "collection.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "boards": {"enabled": ["fixtureboard"]},
                "search_terms": ["engineer"],
                "collection": {"source_workers": 1, "fetch_workers": 2},
                "fixtureboard": {"minimum_poll_minutes": 0},
            }
        ),
        encoding="utf-8",
    )
    return config


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _json_out(text: str) -> dict:
    return json.loads(text)


def _stderr_json(text: str) -> dict:
    lines = [line for line in text.splitlines() if line.strip().startswith("{")]
    return json.loads(lines[-1])


def _db_counts(root: Path) -> tuple[int, int]:
    with contextlib.closing(sqlite3.connect(root / "state" / "vacancies.sqlite3")) as conn:
        total = conn.execute("SELECT COUNT(*) FROM postings").fetchone()[0]
        fetched = conn.execute(
            "SELECT COUNT(*) FROM postings WHERE fetch_status='fetched'"
        ).fetchone()[0]
    return total, fetched


class IngestCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name).resolve()
        self.config_path = _write_workspace(self.root)
        self.argv = ["ingest", "--config", str(self.config_path), "--data-home", str(self.root)]
        self.journal = OperationJournal(self.root / "state" / "operations")

    def _operation_id(self, cfg_path: Path | None = None) -> str:
        from market_aligner.config_loader import load_config

        cfg = load_config(cfg_path or self.config_path)
        scope = sorted(str(b) for b in cfg["boards"]["enabled"])
        return derive_operation_id(INGEST_CYCLE_KIND, content_sha256(cfg), scope)

    def _patched(self, calls: list, fail_ids=()):
        fixture_dir = self.root / "fixtures"
        return mock.patch(
            "market_aligner.collectors.engine.load_adapter",
            side_effect=lambda board, config=None: FixtureBoard(
                fixture_dir=fixture_dir, config=config, calls=calls, fail_ids=fail_ids
            ),
        )

    # -- 1. positive traversal through real persistence ---------------------
    def test_ingest_runs_one_cycle_through_real_collector_persistence(self) -> None:
        calls: list = []
        with self._patched(calls):
            code, out, err = _run(self.argv)
        self.assertEqual(0, code)
        payload = _json_out(out)
        operation_id = self._operation_id()
        self.assertEqual(operation_id, payload["operation_id"])
        self.assertEqual("completed", payload["disposition"])
        self.assertEqual("ok", payload["status"])
        self.assertEqual(["fixtureboard"], payload["source_scope"])
        self.assertEqual(str(self.config_path), payload["config_source"])
        self.assertEqual(str(self.root), payload["data_home"])
        self.assertEqual(
            {"seen": 3, "new": 3, "fetched": 3, "errors": 0, "database_total": 3},
            payload["result"],
        )
        self.assertEqual(
            [("discover", ("engineer",)), ("fetch", "1"), ("fetch", "2"), ("fetch", "3")],
            calls,
        )
        self.assertTrue((self.root / "state" / "vacancies.sqlite3").is_file())
        for entry in FIXTURE_BOARDS:
            self.assertTrue(
                (self.root / "raw" / "vacancies" / "fixtureboard" / f"{entry['id']}.json").is_file()
            )
        record = self.journal.load(operation_id)
        self.assertEqual("completed", record["disposition"])
        self.assertEqual(payload["result"], record["result"])
        self.assertEqual(f"{operation_id}:completed", record["receipt_id"])
        self.assertIsNotNone(record["finished_at"])
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))

    # -- 2. exact replay refusal without any provider access -----------------
    def test_replay_refuses_and_never_fetches_again(self) -> None:
        calls: list = []
        with self._patched(calls):
            first_code, first_out, _err = _run(self.argv)
        self.assertEqual(0, first_code)
        journal_bytes = self.journal.path(self._operation_id()).read_bytes()
        database_bytes = (self.root / "state" / "vacancies.sqlite3").read_bytes()
        calls_snapshot = list(calls)

        with self._patched(calls):
            code, out, err = _run(self.argv)

        self.assertEqual(2, code)
        self.assertEqual("", out.strip())
        refusal = _stderr_json(err)
        self.assertEqual("replay_terminal", refusal["reason"])
        self.assertIn("second provider fetch", refusal["detail"])
        self.assertEqual(list(calls_snapshot), list(calls))
        self.assertEqual(journal_bytes, self.journal.path(self._operation_id()).read_bytes())
        self.assertNotEqual(database_bytes, b"")
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))

    # -- 3. partial provider failure keeps every good row --------------------
    def test_partial_provider_failure_preserves_last_good_state(self) -> None:
        calls: list = []
        with self._patched(calls, fail_ids={"2"}):
            code, out, _err = _run(self.argv)
        self.assertEqual(0, code)
        payload = _json_out(out)
        self.assertEqual(1, payload["result"]["errors"])
        self.assertEqual(2, payload["result"]["fetched"])
        record = self.journal.load(self._operation_id())
        self.assertEqual("completed", record["disposition"])
        self.assertEqual(1, record["result"]["errors"])
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 2), (total, fetched))
        with contextlib.closing(
            sqlite3.connect(self.root / "state" / "vacancies.sqlite3")
        ) as conn:
            status, error = conn.execute(
                "SELECT fetch_status, fetch_error FROM postings WHERE key='fixtureboard:2'"
            ).fetchone()
        self.assertEqual("error", status)
        self.assertIn("provider refused 2", error)
        self.assertTrue((self.root / "raw" / "vacancies" / "fixtureboard" / "1.json").is_file())
        self.assertFalse((self.root / "raw" / "vacancies" / "fixtureboard" / "2.json").exists())

        before_calls = list(calls)
        with self._patched(calls):
            replay_code, _out, replay_err = _run(self.argv)
        self.assertEqual(2, replay_code)
        self.assertEqual("replay_terminal", _stderr_json(replay_err)["reason"])
        self.assertEqual(before_calls, calls)

    # -- 4. hard cycle failure writes failed receipt, preserves good state ---
    def test_hard_cycle_failure_preserves_state_and_refuses_retry(self) -> None:
        calls: list = []

        def failing_export(self_db, path):
            raise RuntimeError("simulated export crash")

        with self._patched(calls), mock.patch.object(
            JobDatabase, "export_urls", autospec=True, side_effect=failing_export
        ):
            code, out, err = _run(self.argv)
        self.assertEqual(2, code)
        refusal = _stderr_json(err)
        self.assertEqual("provider_failure", refusal["reason"])
        self.assertIn("simulated export crash", refusal["detail"])
        record = self.journal.load(self._operation_id())
        self.assertEqual("failed", record["disposition"])
        self.assertIn("simulated export crash", record["error"])
        self.assertIsNone(record["result"])
        # Everything persisted before the crash survives untouched.
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))
        raw_files = sorted(
            path.name for path in (self.root / "raw" / "vacancies" / "fixtureboard").iterdir()
        )
        self.assertEqual(["1.json", "2.json", "3.json"], raw_files)
        failed_bytes = self.journal.path(self._operation_id()).read_bytes()

        with self._patched(calls):
            retry_code, retry_out, retry_err = _run(self.argv)
        self.assertEqual(2, retry_code)
        self.assertEqual("", retry_out.strip())
        self.assertEqual("replay_terminal", _stderr_json(retry_err)["reason"])
        self.assertEqual(failed_bytes, self.journal.path(self._operation_id()).read_bytes())

    # -- 5. interrupted run becomes indeterminate and fails closed -----------
    def test_interrupted_run_is_marked_indeterminate_and_fails_closed(self)-> None:
        calls: list = []
        original_cycle = Collector.cycle

        def die_after_real_cycle(instance):
            original_cycle(instance)
            raise KillDuringCycle()

        with self.assertRaises(KillDuringCycle), self._patched(calls), mock.patch.object(
            Collector, "cycle", autospec=True, side_effect=die_after_real_cycle
        ):
            _run(self.argv)

        operation_id = self._operation_id()
        crashed = self.journal.load(operation_id)
        self.assertEqual("in_flight", crashed["disposition"])
        self.assertGreater(len(calls), 0)  # providers really were contacted
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))

        with self._patched(calls):
            code, out, err = _run(self.argv)
        self.assertEqual(2, code)
        self.assertEqual("", out.strip())
        self.assertEqual("indeterminate_state", _stderr_json(err)["reason"])
        marked = self.journal.load(operation_id)
        self.assertEqual("indeterminate", marked["disposition"])
        self.assertIn("unknowable", marked["note"])
        self.assertIsNotNone(marked["resolved_at"])

        calls_after_marking = list(calls)
        with self._patched(calls):
            again_code, _out, again_err = _run(self.argv)
        self.assertEqual(2, again_code)
        self.assertEqual("indeterminate_state", _stderr_json(again_err)["reason"])
        self.assertEqual(calls_after_marking, calls)

    # -- 6. substitution/tamper matrix ---------------------------------------
    def test_tampered_result_is_rejected(self) -> None:
        calls: list = []
        with self._patched(calls):
            _code, _out, _err = _run(self.argv)
        path = self.journal.path(self._operation_id())
        forged = json.loads(path.read_text(encoding="utf-8"))
        forged["result"]["fetched"] = 99
        path.write_text(json.dumps(forged), encoding="utf-8")
        with self._patched(calls):
            code, _out, err = _run(self.argv)
        self.assertEqual(2, code)
        self.assertEqual("tampered_receipt", _stderr_json(err)["reason"])

    def test_consistent_config_substitution_is_rejected(self) -> None:
        calls: list = []
        with self._patched(calls):
            _code, _out, _err = _run(self.argv)
        other_config = self.root / "other.yaml"
        other_config.write_text(
            yaml.safe_dump({"boards": {"enabled": ["fixtureboard"]}, "search_terms": ["other"]}),
            encoding="utf-8",
        )
        from market_aligner.config_loader import load_config

        other_cfg = load_config(other_config)
        forged = make_record(
            operation_id=self._operation_id(),
            kind=INGEST_CYCLE_KIND,
            config_sha256=content_sha256(other_cfg),
            config_source=str(other_config),
            data_home=str(self.root),
            source_scope=["fixtureboard"],
            disposition="completed",
            result={"seen": 0, "new": 0, "fetched": 0, "errors": 0, "database_total": 3},
        )
        self.journal.update(forged)
        with self._patched(calls):
            code, _out, err = _run(self.argv)
        self.assertEqual(2, code)
        self.assertEqual("config_substitution", _stderr_json(err)["reason"])

    def test_operation_substitution_is_rejected(self) -> None:
        calls: list = []
        with self._patched(calls):
            _code, _out, _err = _run(self.argv)
        completed = json.loads(self.journal.path(self._operation_id()).read_text(encoding="utf-8"))
        other_config = self.root / "other.yaml"
        other_config.write_text(
            yaml.safe_dump({"boards": {"enabled": ["fixtureboard"]}, "search_terms": ["other"]}),
            encoding="utf-8",
        )
        from market_aligner.config_loader import load_config

        other_cfg = load_config(other_config)
        other_id = derive_operation_id(
            INGEST_CYCLE_KIND, content_sha256(other_cfg), ["fixtureboard"]
        )
        misplaced = dict(completed)
        misplaced["schema"] = completed["schema"]
        self.journal.path(other_id).write_text(json.dumps(misplaced), encoding="utf-8")
        argv = ["ingest", "--config", str(other_config), "--data-home", str(self.root)]
        with self._patched(calls):
            code, _out, err = _run(argv)
        self.assertEqual(2, code)
        self.assertEqual("operation_substitution", _stderr_json(err)["reason"])

    # -- 7. existing CLI behaviour unchanged ---------------------------------
    def test_profiles_and_assess_cli_behaviour_unchanged(self) -> None:
        home = self.root / "clihome"
        create_out = io.StringIO()
        with contextlib.redirect_stdout(create_out):
            self.assertEqual(
                0,
                main(
                    [
                        "profiles",
                        "create-synthetic",
                        "--profile-id",
                        "prf_" + "a1" * 16,
                        "--data-home",
                        str(home),
                    ]
                ),
            )
        created = json.loads(create_out.getvalue())
        self.assertEqual("prf_" + "a1" * 16, created["profile_id"])
        self.assertEqual("synthetic-v1", created["version"])

        list_out = io.StringIO()
        with contextlib.redirect_stdout(list_out):
            self.assertEqual(0, main(["profiles", "list", "--data-home", str(home)]))
        self.assertEqual({"profile_ids": ["prf_" + "a1" * 16]}, json.loads(list_out.getvalue()))

        show_out = io.StringIO()
        with contextlib.redirect_stdout(show_out):
            self.assertEqual(
                0, main(["profiles", "show", "prf_" + "a1" * 16, "--data-home", str(home)])
            )
        shown = json.loads(show_out.getvalue())
        self.assertEqual("prf_" + "a1" * 16, shown["profile_id"])
        self.assertEqual(0, shown["evidence_items"])
        self.assertNotIn("display_label", shown)

        request = self.root / "request.json"
        request.write_text(
            json.dumps(
                {
                    "job_key": "fixtureboard:1",
                    "track": "example_track",
                    "url": "https://fixture.example/jobs/1",
                    "title": "Engineer",
                    "company": "Example",
                    "extraction_confidence": 0.9,
                    "axes": {
                        "technical_alignment": 8,
                        "evidence_match": 7,
                        "market_demand": 8,
                        "barrier_to_entry": 2,
                        "growth_potential": 8,
                    },
                }
            ),
            encoding="utf-8",
        )
        assess_out = io.StringIO()
        with contextlib.redirect_stdout(assess_out):
            self.assertEqual(
                0,
                main(
                    [
                        "assess",
                        "--profile-id",
                        "prf_" + "a1" * 16,
                        "--request",
                        str(request),
                        "--data-home",
                        str(home),
                    ]
                ),
            )
        assessed = json.loads(assess_out.getvalue())
        self.assertEqual("prf_" + "a1" * 16, assessed["profile_id"])
        self.assertEqual("uncalibrated", assessed["fit_status"])
        self.assertNotIn("opportunity_gate", assessed)


if __name__ == "__main__":
    unittest.main()
