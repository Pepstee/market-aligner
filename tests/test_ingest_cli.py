"""INGEST-001 R2 acceptance coverage.

The positive tests traverse a fixture adapter through the real Collector
persistence path (canonical ``Collector.cycle`` -> ``JobDatabase`` -> raw
cache), not through argument mocks. Only the adapter seam is substituted,
mirroring the established pattern in :mod:`tests.test_collection`.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

import yaml

from market_aligner.cli import main
from market_aligner.config_loader import closure_identity, snapshot_config
from market_aligner.collectors.adapters.base import Adapter
from market_aligner.collectors.engine import Collector, bounded_relative_path
from market_aligner.state.operations import (
    INGEST_CYCLE_KIND,
    normalized_error,
    OperationJournal,
    OperationRefused,
    canonical_json,
    content_sha256,
    make_record,
    new_owner_id,
)
from market_aligner.state.vacancies import JobDatabase


class KillDuringCycle(BaseException):
    """Simulates abrupt process death; cannot be caught by ``except Exception``."""


FIXTURE_BOARDS = (
    {"id": "1", "title": "Platform Engineer", "company": "Example"},
    {"id": "2", "title": "Data Engineer", "company": "Example"},
    {"id": "3", "title": "QA Engineer", "company": "Example"},
)

SECOND_BOARD = "secondboard"
SECOND_BOARD_ROWS = ({"id": "9", "title": "Systems Engineer", "company": "Other"},)


class FixtureBoard(Adapter):
    def __init__(
        self,
        board_name="fixtureboard",
        fixture_dir=None,
        config=None,
        calls=None,
        fail_ids=(),
        guard=None,
        failure_text="provider refused {job_id}",
    ):
        self.board = board_name
        super().__init__(fixture_dir=fixture_dir, config=config)
        self.calls = calls if calls is not None else []
        self.fail_ids = frozenset(fail_ids)
        self.guard = guard or nullcontext()
        self.failure_text = failure_text

    def discover(self, search_terms, live=False):
        with self.guard:
            self.calls.append(("discover", self.board, tuple(search_terms)))
            rows = list(super().discover(search_terms, live=False))
        yield from rows

    def fetch(self, job_url, live=False):
        with self.guard:
            self.calls.append(("fetch", self.board, job_url.job_id))
            if job_url.job_id in self.fail_ids:
                raise RuntimeError(
                    self.failure_text.format(job_id=job_url.job_id, board=self.board)
                )
            return super().fetch(job_url, live=False)


class OverlapGuard:
    """Fails when provider calls of two different operations overlap.

    Active calls are tracked as per-operation reference counts: parallel
    fetches inside one operation each increment and decrement dict[tag], so an
    operation stays visible until its LAST provider call returns. A violation
    is recorded exactly when a call enters while any other tag has a positive
    count.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active: dict[str, int] = {}
        self.violations = 0
        self.local = threading.local()

    def _tag(self):
        return getattr(self.local, "tag", None)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self.active)

    def __enter__(self) -> "OverlapGuard":
        tag = self._tag()
        with self._lock:
            for other, count in self.active.items():
                if other != tag and count > 0:
                    self.violations += 1
                    break
            self.active[tag] = self.active.get(tag, 0) + 1
        return self

    def __exit__(self, *_exc) -> None:
        tag = self._tag()
        with self._lock:
            count = self.active.get(tag, 0)
            if count <= 1:
                self.active.pop(tag, None)
            else:
                self.active[tag] = count - 1


def _write_board_fixtures(root: Path, board: str, entries) -> None:
    fixtures = root / "fixtures"
    (fixtures / board).mkdir(parents=True, exist_ok=True)
    (fixtures / f"{board}_listing.json").write_text(json.dumps(entries), encoding="utf-8")
    for entry in entries:
        detail = {"title": entry["title"], "body": f"detail {entry['id']}"}
        (fixtures / board / f"{entry['id']}.json").write_text(
            json.dumps(detail), encoding="utf-8"
        )


def _write_workspace(root: Path) -> Path:
    _write_board_fixtures(root, "fixtureboard", FIXTURE_BOARDS)
    _write_board_fixtures(root, SECOND_BOARD, SECOND_BOARD_ROWS)
    config = root / "collection.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "boards": {"enabled": ["fixtureboard"]},
                "search_terms": ["engineer"],
                "collection": {"source_workers": 1, "fetch_workers": 2},
                "fixtureboard": {"minimum_poll_minutes": 0.5},
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


def _rehashed(record: dict, **overrides) -> dict:
    """A consistently re-forged record: valid digests, attacker-chosen fields."""
    forged = {**record, **overrides}
    forged.pop("record_sha256", None)
    body = {key: value for key, value in forged.items() if key != "receipt_id"}
    forged["receipt_id"] = content_sha256(body)
    forged["record_sha256"] = content_sha256(forged)
    return forged


class IngestCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name).resolve()
        self.config_path = _write_workspace(self.root)
        state = self.root / "state"
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        self.journal_root = state / "operations"
        self.journal = OperationJournal(self.journal_root)

    def _argv(self, operation_id: str, config_path: Path | None = None) -> list[str]:
        return [
            "ingest",
            "--operation-id",
            operation_id,
            "--config",
            str(config_path or self.config_path),
            "--data-home",
            str(self.root),
        ]

    def _patched(self, calls: list, fail_ids=(), guard: OverlapGuard | None = None,
                 failure_text="provider refused {job_id}"):
        fixture_dir = self.root / "fixtures"
        return mock.patch(
            "market_aligner.collectors.engine.load_adapter",
            side_effect=lambda board, config=None: FixtureBoard(
                board_name=board,
                fixture_dir=fixture_dir,
                config=config,
                calls=calls,
                fail_ids=fail_ids,
                guard=guard,
                failure_text=failure_text,
            ),
        )

    # -- command surface ------------------------------------------------------
    def test_operation_id_is_required_and_bounded(self) -> None:
        calls: list = []
        with self._patched(calls):
            with self.assertRaises(SystemExit) as caught:
                _run(["ingest", "--config", str(self.config_path)])
        self.assertEqual(2, caught.exception.code)
        for bad in ("short", "has space", "with:colon", "with/slash"):
            code, _out, err = _run(self._argv(bad))
            self.assertEqual(2, code)
            self.assertEqual("invalid_operation_id", _stderr_json(err)["reason"])
        self.assertEqual([], calls)

    # -- positive lifecycle ----------------------------------------------------
    def test_first_run_traverses_real_collector_persistence(self) -> None:
        calls: list = []
        with self._patched(calls):
            code, out, _err = _run(self._argv("op-first-run"))
        self.assertEqual(0, code)
        payload = _json_out(out)
        self.assertEqual("ok", payload["status"])
        self.assertFalse(payload["replayed"])
        self.assertEqual("op-first-run", payload["operation_id"])
        self.assertEqual("completed", payload["disposition"])
        self.assertEqual(["fixtureboard"], payload["source_scope"])
        self.assertEqual(str(self.config_path), payload["config_source"])
        self.assertTrue(payload["config_file_sha256"])
        self.assertEqual(str(self.root), payload["data_home"])
        self.assertEqual(
            {"seen": 3, "new": 3, "fetched": 3, "errors": 0, "database_total": 3},
            payload["result"],
        )
        self.assertEqual(("discover", "fixtureboard", ("engineer",)), calls[0])
        self.assertEqual(
            ["1", "2", "3"],
            sorted(call[2] for call in calls[1:] if call[0] == "fetch"),
        )
        self.assertTrue((self.root / "state" / "vacancies.sqlite3").is_file())
        for entry in FIXTURE_BOARDS:
            self.assertTrue(
                (self.root / "raw" / "vacancies" / "fixtureboard" / f"{entry['id']}.json").is_file()
            )
        record = self.journal.load("op-first-run")
        self.assertEqual("completed", record["disposition"])
        self.assertEqual(payload["result"], record["result"])
        self.assertEqual(payload["receipt_id"], record["receipt_id"])
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))

    def test_new_operation_id_same_config_runs_second_cycle(self) -> None:
        calls: list = []
        with self._patched(calls):
            first_code, first_out, _err = _run(self._argv("op-alpha"))
            with contextlib.closing(
                sqlite3.connect(self.root / "state" / "vacancies.sqlite3")
            ) as conn:
                conn.execute("DELETE FROM source_state")
                conn.commit()
            second_code, second_out, _err = _run(self._argv("op-gamma"))
        self.assertEqual(0, first_code)
        self.assertEqual(0, second_code)
        second = _json_out(second_out)
        self.assertEqual("ok", second["status"])
        self.assertEqual(
            {"seen": 3, "new": 0, "fetched": 0, "errors": 0, "database_total": 3},
            second["result"],
        )
        self.assertNotEqual(
            json.loads(first_out)["operation_id"], second["operation_id"]
        )
        records = sorted(path.name for path in self.journal_root.glob("*.json"))
        self.assertEqual(["op-alpha.json", "op-gamma.json"], records)
        self.assertEqual(2, sum(1 for call in calls if call[0] == "discover"))

    def test_completed_replay_returns_canonical_receipt_with_zero_calls(self) -> None:
        calls: list = []
        with self._patched(calls):
            _code, first_out, _err = _run(self._argv("op-replay"))
            snapshot = (self.journal.record_path("op-replay")).read_bytes()
            calls_after_run = list(calls)
            code, out, err = _run(self._argv("op-replay"))
        self.assertEqual(0, code)
        payload = _json_out(out)
        original = _json_out(first_out)
        self.assertEqual("replayed", payload["status"])
        self.assertTrue(payload["replayed"])
        self.assertEqual(original["result"], payload["result"])
        self.assertEqual(original["receipt_id"], payload["receipt_id"])
        self.assertEqual(calls_after_run, calls)
        self.assertEqual(snapshot, self.journal.record_path("op-replay").read_bytes())
        self.assertEqual("", err.strip())

    # -- binding substitutions on the same operation id -------------------------
    def test_same_id_binding_substitutions_are_rejected_before_provider(self) -> None:
        calls: list = []
        with self._patched(calls):
            _code, _out, _err = _run(self._argv("op-bound"))

        original_config = self.config_path.read_text(encoding="utf-8")
        moved = self.root / "moved-collection.yaml"
        moved.write_text(original_config, encoding="utf-8")

        completed = json.loads(self.journal.record_path("op-bound").read_text(encoding="utf-8"))
        prior_bytes = self.journal.record_path("op-bound").read_bytes()
        forged_semantic = _rehashed(completed, config_sha256=content_sha256({"forged": True}))
        forged_scope = _rehashed(completed, source_scope=["other-board"])
        forged_home = _rehashed(completed, data_home="/somewhere/else")
        cases = [
            ("binding_config_source", self._argv("op-bound", moved), None),
            ("binding_config_sha256", self._argv("op-bound"), forged_semantic),
            ("binding_source_scope", self._argv("op-bound"), forged_scope),
            ("binding_data_home", self._argv("op-bound"), forged_home),
        ]
        for expected_reason, argv, forged in cases:
            with self.subTest(reason=expected_reason):
                if forged is not None:
                    current = self.journal.record_path("op-bound").read_bytes()
                    self.journal.cas_replace(
                        forged, expected_prior_bytes=current, operation_id="op-bound"
                    )
                with self._patched(calls):
                    code, out, err = _run(argv)
                self.assertEqual(2, code)
                self.assertEqual("", out.strip())
                self.assertEqual(expected_reason, _stderr_json(err)["reason"])
                self.journal.cas_replace(
                    completed,
                    expected_prior_bytes=self.journal.record_path("op-bound").read_bytes(),
                    operation_id="op-bound",
                )
        # Editing the configuration file itself changes its byte identity.
        edited = yaml.safe_load(original_config)
        edited["search_terms"] = ["different"]
        self.config_path.write_text(yaml.safe_dump(edited), encoding="utf-8")
        with self._patched(calls):
            code, _out, err = _run(self._argv("op-bound"))
        self.assertEqual(2, code)
        self.assertEqual("binding_config_file_sha256", _stderr_json(err)["reason"])
        self.config_path.write_text(original_config, encoding="utf-8")
        calls_snapshot = list(calls)
        for _expected_reason, argv, _forged in cases:
            with self._patched(calls):
                _code, _out, _err = _run(argv)
        self.assertEqual(calls_snapshot, calls)

    # -- live owner versus contender ---------------------------------------------
    def _kill_owner_mid_cycle(self, operation_id: str, calls: list) -> None:
        original_cycle = Collector.cycle

        def die_after_real_cycle(instance):
            original_cycle(instance)
            raise KillDuringCycle()

        with self.assertRaises(KillDuringCycle), self._patched(calls), mock.patch.object(
            Collector, "cycle", autospec=True, side_effect=die_after_real_cycle
        ):
            _run(self._argv(operation_id))

    def test_contender_leaves_live_owner_record_untouched(self) -> None:
        calls: list = []
        self._kill_owner_mid_cycle("op-owner", calls)
        record_path = self.journal.record_path("op-owner")
        crashed_bytes = record_path.read_bytes()
        crashed = json.loads(crashed_bytes.decode("utf-8"))
        self.assertEqual("in_flight", crashed["disposition"])
        calls_at_crash = list(calls)
        self.assertGreater(len(calls_at_crash), 0)

        with self._patched(calls):
            code, out, err = _run(self._argv("op-owner"))
        self.assertEqual(2, code)
        self.assertEqual("", out.strip())
        refusal = _stderr_json(err)
        self.assertEqual("in_progress", refusal["reason"])
        self.assertEqual(crashed["owner_id"], refusal["owner_id"])
        self.assertEqual(crashed_bytes, record_path.read_bytes())
        self.assertEqual(calls_at_crash, calls)
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))

    def test_unresolved_owner_blocks_new_same_scope_operations(self) -> None:
        calls: list = []
        self._kill_owner_mid_cycle("op-stuck", calls)
        calls_at_crash = list(calls)

        with self._patched(calls):
            code, out, err = _run(self._argv("op-follower"))
        self.assertEqual(2, code)
        self.assertEqual("", out.strip())
        refusal = _stderr_json(err)
        self.assertEqual("scope_blocked", refusal["reason"])
        self.assertEqual(
            ["op-stuck"],
            [blocker["operation_id"] for blocker in refusal["blocked_by"]],
        )
        self.assertEqual(calls_at_crash, calls)
        self.assertFalse(self.journal.record_path("op-follower").exists())

        blockers = self.journal.scan_unresolved_scope_blockers(str(self.root), ["fixtureboard"])
        self.assertEqual(["op-stuck"], [item["operation_id"] for item in blockers])
        self.assertEqual(
            [], self.journal.scan_unresolved_scope_blockers(str(self.root), ["other-board"])
        )

    def test_concurrent_new_ids_on_one_scope_never_overlap_providers(self) -> None:
        calls: list = []
        guard = OverlapGuard()
        outcomes: dict[str, tuple[int, str, str]] = {}
        lock = threading.Lock()

        # Contenders run in real threads against the canonical handler through
        # its injected capture streams: nothing touches the process-global
        # sys.stdout/sys.stderr, so per-contender attribution stays exact.
        from market_aligner.cli import _ingest_command, build_parser

        def contender(operation_id: str) -> None:
            guard.local.tag = operation_id
            args = build_parser().parse_args(self._argv(operation_id))
            out, err = io.StringIO(), io.StringIO()
            code = _ingest_command(args, out=out, err=err)
            with lock:
                outcomes[operation_id] = (code, out.getvalue(), err.getvalue())

        threads = [
            threading.Thread(target=contender, args=(name,))
            for name in ("op-concurrent-a", "op-concurrent-b")
        ]
        with self._patched(calls, guard=guard):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual({0}, {code for code, _out, _err in outcomes.values()})
        ok_payloads = {}
        for operation_id, (code, out, err) in outcomes.items():
            # Progress logs are fine on the contender's own captured stderr;
            # a refusal JSON there would mean an unexpected contender loss.
            self.assertFalse(
                [line for line in err.splitlines() if line.strip().startswith(chr(123))],
                operation_id,
            )
            lines = [line for line in out.splitlines() if line.strip()]
            self.assertEqual(1, len(lines), operation_id)
            payload = json.loads(lines[0])
            self.assertEqual("ok", payload["status"])
            ok_payloads[operation_id] = payload
        # Serialized execution: exactly one run ever sees fresh postings; the
        # other observes the first one's rows and fetches nothing.
        fresh = [
            payload
            for payload in ok_payloads.values()
            if payload["result"]["new"] == 3 and payload["result"]["fetched"] == 3
        ]
        self.assertEqual(1, len(fresh))
        for payload in ok_payloads.values():
            result = payload["result"]
            if result["fetched"] == 0:
                self.assertEqual(
                    {"seen": 0, "new": 0, "fetched": 0, "errors": 0, "database_total": 3},
                    result,
                )
        self.assertEqual(0, guard.violations)
        completed = sorted(
            path.stem
            for path in self.journal_root.glob("*.json")
            if json.loads(path.read_text(encoding="utf-8"))["disposition"] == "completed"
        )
        self.assertEqual(sorted(ok_payloads), completed)

    # -- data-home boundary -------------------------------------------------------
    def test_path_escape_matrix_refuses_with_zero_adapter_calls(self) -> None:
        escape_configs = {
            "absolute_database": (
                "path_escape",
                {"io": {"database": "/private/tmp/escape.sqlite3"}},
            ),
            "upward_raw_cache": ("path_escape", {"io": {"raw_cache": "../outside-cache"}}),
            "deep_upward_urls": ("path_escape", {"io": {"job_urls": "state/../../urls.jsonl"}}),
            "scalar_legacy_roots": (
                "invalid_config_shape",
                {"io": {"raw_cache_roots": "legacy"}},
            ),
            "nonstring_legacy_roots": (
                "invalid_config_shape",
                {"io": {"raw_cache_roots": [7]}},
            ),
            "absolute_runtime_root": (
                "path_escape",
                {"scrapling": {"enabled": False, "runtime_root": "/abs"}},
            ),
            "scalar_boards": ("invalid_config_shape", {"boards": "fixtureboard"}),
            "boolean_enabled": ("invalid_config_shape", {"boards": {"enabled": True}}),
            "empty_enabled": ("invalid_config_shape", {"boards": {"enabled": []}}),
            "duplicate_boards": (
                "invalid_config_shape",
                {"boards": {"enabled": ["fixtureboard", "fixtureboard"]}},
            ),
            "nonstring_board": (
                "invalid_config_shape",
                {"boards": {"enabled": ["fixtureboard", 7]}},
            ),
            "scalar_io": ("invalid_config_shape", {"io": 1}),
            "null_io_is_mapping": None,  # positive control: io:null behaves as {}
            "scalar_collection": ("invalid_config_shape", {"collection": ["fast"]}),
            "scalar_scrapling": ("invalid_config_shape", {"scrapling": "off"}),
            "board_config_not_mapping": (
                "invalid_config_shape",
                {"fixtureboard": "turbo"},
            ),
        }
        calls: list = []
        for index, (name, case) in enumerate(escape_configs.items()):
            if case is None:
                continue
            expected_reason, override = case
            with self.subTest(case=name):
                cfg = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
                cfg.update(override)
                escaping = self.root / f"escape-{index}.yaml"
                escaping.write_text(yaml.safe_dump(cfg), encoding="utf-8")
                operation_id = f"op-escape-{index}"
                fresh_home = self.root / f"fresh-home-{index}"
                self.assertFalse(fresh_home.exists())
                argv = [
                    "ingest",
                    "--operation-id",
                    operation_id,
                    "--config",
                    str(escaping),
                    "--data-home",
                    str(fresh_home),
                ]
                with self._patched(calls):
                    code, out, err = _run(argv)
                self.assertEqual(2, code)
                self.assertEqual("", out.strip())
                self.assertEqual(expected_reason, _stderr_json(err)["reason"])
                self.assertFalse(self.journal.record_path(operation_id).exists())
                # A fresh supplied data home must remain absent after refusal.
                self.assertFalse(fresh_home.exists(), name)
        self.assertEqual([], calls)
        self.assertFalse(Path("/private/tmp/escape.sqlite3").exists())
        self.assertFalse((self.root.parent / "outside-cache").exists())

    def test_null_io_behaves_as_empty_mapping(self) -> None:
        cfg = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        cfg["io"] = None
        tolerant = self.root / "io-null.yaml"
        tolerant.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        calls: list = []
        with self._patched(calls):
            code, out, _err = _run(self._argv("op-io-null", tolerant))
        self.assertEqual(0, code)
        self.assertEqual("ok", _json_out(out)["status"])

    def test_symlink_component_escape_is_rejected(self) -> None:
        outside = tempfile.mkdtemp(prefix="outside-symlink-")
        self.addCleanup(lambda: os.rmdir(outside))
        link = self.root / "link-out"
        os.symlink(Path(outside), link)
        cfg = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        cfg["io"] = {"raw_cache": "link-out/cache"}
        escaping = self.root / "symlink-escape.yaml"
        escaping.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        calls: list = []
        with self._patched(calls):
            code, _out, err = _run(self._argv("op-symlink-escape", escaping))
        self.assertEqual(2, code)
        self.assertEqual("path_escape", _stderr_json(err)["reason"])
        self.assertEqual([], calls)
        self.assertFalse((Path(outside) / "cache").exists())

    def test_bounded_relative_path_seam_direct_matrix(self) -> None:
        root = self.root
        self.assertEqual(
            root / "state" / "vacancies.sqlite3",
            bounded_relative_path(root, "state/vacancies.sqlite3", "field"),
        )
        for bad in ("/abs/value", "../up", "a/../../b"):
            with self.assertRaisesRegex(ValueError, "escape:"):
                bounded_relative_path(root, bad, "field")
        with self.assertRaisesRegex(ValueError, "shape:"):
            bounded_relative_path(root, "", "field")
        link = root / "dir-link"
        os.symlink(root.parent, link)
        with self.assertRaisesRegex(ValueError, "symlink"):
            bounded_relative_path(root, "dir-link/x", "field")
        valid = {
            "boards": {"enabled": ["fixtureboard"]},
            "collection": {},
            "scrapling": {},
        }
        with self.assertRaisesRegex(ValueError, "raw_cache_roots must be a JSON list"):
            Collector.plan(root, {**valid, "io": {"raw_cache_roots": "scalar"}})
        with self.assertRaisesRegex(ValueError, "relative path string"):
            Collector.plan(root, {**valid, "io": {"raw_cache_roots": [42]}})
        with self.assertRaisesRegex(ValueError, "boards.enabled must be a nonempty list"):
            Collector.plan(root, {**valid, "boards": {"enabled": True}})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            Collector.plan(root, {**valid, "boards": {"enabled": ["a", "a"]}})
        resolved = Collector.bounded_paths(
            root,
            {
                "boards": {"enabled": ["fixtureboard"]},
                "io": None,
                "collection": None,
                "scrapling": None,
            },
        )
        self.assertEqual(root / "state" / "vacancies.sqlite3", resolved["database"])
        self.assertIsNone(resolved["raw_cache_roots"])

    # -- journal substitution resistance ------------------------------------------
    def test_strict_schema_rejects_consistently_rehashed_substitutions(self) -> None:
        calls: list = []
        with self._patched(calls):
            _code, run_out, _err = _run(self._argv("op-strict"))
        good = json.loads(self.journal.record_path("op-strict").read_text(encoding="utf-8"))
        path = self.journal.record_path("op-strict")

        def write(record: dict) -> None:
            path.write_text(canonical_json(record), encoding="utf-8")

        cases = [
            ("tampered_receipt", _rehashed(good, extraneous="field")),
            ("invalid_result", _rehashed(good, result={**good["result"], "seen": 1.5})),
            ("invalid_result", _rehashed(good, result={**good["result"], "errors": True})),
            ("invalid_result", _rehashed(good, result={"seen": 1})),
            ("invalid_state", _rehashed(good, finished_at=None)),
            ("invalid_state", _rehashed(good, disposition="failed", error=None, result=None)),
            ("invalid_timestamp", _rehashed(good, started_at="not-a-timestamp")),
            ("tampered_receipt", _rehashed(good, source_scope=["zzz", "aaa"])),
        ]
        for expected_reason, forged in cases:
            with self.subTest(reason=expected_reason, fields=sorted(set(forged) ^ set(good))):
                write(forged)
                with self.assertRaises(OperationRefused) as caught:
                    self.journal.load("op-strict")
                self.assertEqual(expected_reason, caught.exception.reason)
                with self._patched(calls):
                    code, _out, err = _run(self._argv("op-strict"))
                self.assertEqual(2, code)
                refusal = _stderr_json(err)
                self.assertIn(refusal["reason"], {expected_reason, "unreadable_journal"})
        write(good)
        duplicated = canonical_json(good).replace(
            '{"', '{"config_source":"dup","config_source":"' + good["config_source"] + '",', 1
        )
        path.write_text(duplicated, encoding="utf-8")
        with self.assertRaises(OperationRefused) as caught:
            self.journal.load("op-strict")
        self.assertEqual("unreadable_journal", caught.exception.reason)

    def test_journal_root_symlink_and_permission_substitutions_fail_closed(self) -> None:
        calls: list = []
        with self._patched(calls):
            _code, _out, _err = _run(self._argv("op-safety"))
        record_path = self.journal.record_path("op-safety")
        replay_argv = self._argv("op-safety")

        os.chmod(record_path, 0o644)
        with self._patched(calls):
            code, _out, err = _run(replay_argv)
        self.assertEqual(2, code)
        self.assertEqual("unsafe_journal_file", _stderr_json(err)["reason"])
        os.chmod(record_path, 0o600)
        with self._patched(calls):
            code, out, _err = _run(replay_argv)
        self.assertEqual(0, code)
        self.assertEqual("replayed", _json_out(out)["status"])

        hardlink = self.journal_root / "hardlink.json"
        os.link(record_path, hardlink)
        try:
            with self.assertRaises(OperationRefused) as caught:
                self.journal.load("op-safety")
            self.assertEqual("unsafe_journal_file", caught.exception.reason)
        finally:
            hardlink.unlink()

        substitute = self.root / "substitute-journal"
        substitute.mkdir(mode=0o700)
        os.rename(self.journal_root, self.root / "operations-real")
        os.symlink(substitute, self.journal_root)
        try:
            with self.assertRaises(OperationRefused) as caught:
                OperationJournal(self.journal_root)
            self.assertEqual("unsafe_journal_root", caught.exception.reason)
            with self._patched(calls):
                code, _out, err = _run(self._argv("op-any-new"))
            self.assertEqual(2, code)
            self.assertEqual("unsafe_journal_root", _stderr_json(err)["reason"])
        finally:
            os.unlink(self.journal_root)
            os.rename(self.root / "operations-real", self.journal_root)

        board_lock = self.journal.board_lock_path(str(self.root), "fixtureboard")
        lock_descriptor = self.journal._open_lock(board_lock)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        OperationJournal.release_locks([lock_descriptor])
        os.chmod(board_lock, 0o664)
        with self.assertRaises(OperationRefused) as caught:
            self.journal.acquire_board_locks(str(self.root), ["fixtureboard"])
        self.assertEqual("unsafe_journal_file", caught.exception.reason)
        os.chmod(board_lock, 0o600)

    # -- durability and crash injection -------------------------------------------
    def test_fsync_directory_seam_invoked_for_claims_and_publications(self) -> None:
        calls: list = []
        with mock.patch(
            "market_aligner.state.operations.fsync_directory",
            side_effect=lambda path: calls.append(str(path)),
        ):
            with self._patched([]):
                code, _out, _err = _run(self._argv("op-durable"))
        self.assertEqual(0, code)
        self.assertGreaterEqual(len(calls), 2, calls)

    def test_owner_seal_conflict_leaves_foreign_bytes_untouched(self) -> None:
        calls: list = []

        real_cycle = Collector.cycle
        record_path = self.journal.record_path("op-seal-guard")

        def cycle_then_interfere(instance):
            outcome = real_cycle(instance)
            _merged, identities = snapshot_config(self.config_path)
            foreign = make_record(
                operation_id="op-seal-guard",
                kind=INGEST_CYCLE_KIND,
                config_source=str(self.config_path),
                config_file_sha256=closure_identity(identities),
                config_sha256=content_sha256(
                    yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
                ),
                source_scope=["fixtureboard"],
                data_home=str(self.root),
                disposition="in_flight",
                owner_id=new_owner_id(),
            )
            record_path.write_text(canonical_json(foreign), encoding="utf-8")
            return outcome

        with self._patched(calls), mock.patch.object(
            Collector, "cycle", autospec=True, side_effect=cycle_then_interfere
        ):
            code, _out, err = _run(self._argv("op-seal-guard"))
        self.assertEqual(2, code)
        refusal = _stderr_json(err)
        self.assertEqual("seal_conflict", refusal["reason"])
        foreign_now = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual("in_flight", foreign_now["disposition"])
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))
        with self._patched(calls):
            retry_code, _out, retry_err = _run(self._argv("op-seal-guard"))
        self.assertEqual(2, retry_code)
        self.assertEqual("in_progress", _stderr_json(retry_err)["reason"])

    def test_partial_provider_failure_completes_and_preserves_state(self) -> None:
        calls: list = []
        with self._patched(calls, fail_ids={"2"}):
            code, out, _err = _run(self._argv("op-partial"))
        self.assertEqual(0, code)
        payload = _json_out(out)
        self.assertEqual(1, payload["result"]["errors"])
        self.assertEqual(2, payload["result"]["fetched"])
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

        calls_snapshot = list(calls)
        with self._patched(calls):
            replay_code, replay_out, _err = _run(self._argv("op-partial"))
        self.assertEqual(0, replay_code)
        self.assertEqual("replayed", _json_out(replay_out)["status"])
        self.assertEqual(calls_snapshot, calls)

    def test_failed_terminal_receipt_preserves_good_state_and_replays(self) -> None:
        calls: list = []

        def failing_export(_self, _path):
            raise RuntimeError("simulated export crash")

        with self._patched(calls), mock.patch.object(
            JobDatabase, "export_urls", autospec=True, side_effect=failing_export
        ):
            code, _out, err = _run(self._argv("op-crashfail"))
        self.assertEqual(2, code)
        refusal = _stderr_json(err)
        self.assertEqual("provider_failure", refusal["reason"])
        self.assertIn("simulated export crash", refusal["detail"])
        record = self.journal.load("op-crashfail")
        self.assertEqual("failed", record["disposition"])
        self.assertIn("simulated export crash", record["error"])
        self.assertIsNone(record["result"])
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))
        raw_files = sorted(
            path.name for path in (self.root / "raw" / "vacancies" / "fixtureboard").iterdir()
        )
        self.assertEqual(["1.json", "2.json", "3.json"], raw_files)
        failed_bytes = self.journal.record_path("op-crashfail").read_bytes()

        with self._patched(calls):
            replay_code, replay_out, _err = _run(self._argv("op-crashfail"))
        self.assertEqual(2, replay_code)
        replay = _json_out(replay_out)
        self.assertEqual("replayed", replay["status"])
        self.assertTrue(replay["replayed"])
        self.assertEqual("failed", replay["disposition"])
        self.assertEqual(failed_bytes, self.journal.record_path("op-crashfail").read_bytes())

        # A terminal failure closes only its own id; a different id may run a
        # later cycle against unchanged configuration.
        calls_snapshot = list(calls)
        with contextlib.closing(
            sqlite3.connect(self.root / "state" / "vacancies.sqlite3")
        ) as conn:
            conn.execute("DELETE FROM source_state")
            conn.commit()
        with self._patched(calls):
            later_code, later_out, _err = _run(self._argv("op-after-crash"))
        self.assertEqual(0, later_code)
        self.assertEqual(
            {"seen": 3, "new": 0, "fetched": 0, "errors": 0, "database_total": 3},
            _json_out(later_out)["result"],
        )
        self.assertGreater(len(calls), len(calls_snapshot))

    # -- mandatory R2 amendment tests ---------------------------------------------
    def test_overlap_guard_reference_counting(self) -> None:
        guard = OverlapGuard()
        guard.local.tag = "op-a"
        guard.__enter__()
        guard.__enter__()  # second parallel provider call of the same operation
        # First call returns: operation A must stay visible with one active call.
        guard.__exit__()
        self.assertEqual({"op-a": 1}, guard.snapshot())
        self.assertEqual(0, guard.violations)
        # A different operation entering now is detected and prevented.
        guard.local.tag = "op-b"
        guard.__enter__()
        self.assertEqual(1, guard.violations)
        guard.__exit__()
        guard.local.tag = "op-a"
        guard.__exit__()
        self.assertEqual({}, guard.snapshot())
        self.assertEqual(1, guard.violations)

    def test_simultaneous_same_id_replays_after_lock_wait(self) -> None:
        calls: list = []
        guard = OverlapGuard()
        outcomes: list[tuple[int, str, str]] = []
        lock = threading.Lock()
        from market_aligner.cli import _ingest_command, build_parser

        def contender(operation_id: str) -> None:
            guard.local.tag = f"{operation_id}:{threading.get_ident()}"
            args = build_parser().parse_args(self._argv(operation_id))
            out, err = io.StringIO(), io.StringIO()
            code = _ingest_command(args, out=out, err=err)
            with lock:
                outcomes.append((code, out.getvalue(), err.getvalue()))

        threads = [
            threading.Thread(target=contender, args=("op-twins",)),
            threading.Thread(target=contender, args=("op-twins",)),
        ]
        with self._patched(calls, guard=guard):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        payloads: dict[str, dict] = {}
        refused: list[dict] = []
        for _code, out, err in outcomes:
            for line in out.splitlines():
                if line.strip():
                    payload = json.loads(line)
                    payloads[payload["status"]] = payload
            for line in err.splitlines():
                if line.strip().startswith("{"):
                    refused.append(json.loads(line))
        # Deterministic post-wait behavior is truthful terminal replay; an
        # immediate live refusal (observed before waiting) is also acceptable.
        if "replayed" in payloads:
            winner = payloads["ok"]
            loser = payloads["replayed"]
            self.assertTrue(loser["replayed"])
            self.assertEqual("completed", loser["disposition"])
            self.assertEqual(winner["receipt_id"], loser["receipt_id"])
            self.assertEqual(winner["result"], loser["result"])
        else:
            self.assertEqual(["in_progress"], [item["reason"] for item in refused])
        # Exactly one provider cycle regardless of which outcome the twin took.
        self.assertEqual(1, sum(1 for call in calls if call[0] == "discover"))
        record = json.loads(self.journal.record_path("op-twins").read_text(encoding="utf-8"))
        self.assertEqual("completed", record["disposition"])
        self.assertEqual(payloads["ok"]["receipt_id"], record["receipt_id"])
        self.assertEqual(0, guard.violations)

    def _write_board_config(self, name: str, boards: list[str]) -> Path:
        cfg = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        cfg["boards"] = {"enabled": boards}
        path = self.root / f"{name}.yaml"
        path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        return path

    def test_intersecting_scopes_serialize_and_block_on_unresolved(self) -> None:
        full_config = self._write_board_config("full", ["fixtureboard", SECOND_BOARD])
        sub_config = self._write_board_config("sub", ["fixtureboard"])
        disjoint_config = self._write_board_config("disjoint", [SECOND_BOARD])
        calls: list = []
        guard = OverlapGuard()
        outcomes: dict[str, int] = {}
        lock = threading.Lock()
        from market_aligner.cli import _ingest_command, build_parser

        def contender(operation_id: str, config_path: Path) -> None:
            guard.local.tag = operation_id
            argv = [
                "ingest",
                "--operation-id",
                operation_id,
                "--config",
                str(config_path),
                "--data-home",
                str(self.root),
            ]
            args = build_parser().parse_args(argv)
            out, err = io.StringIO(), io.StringIO()
            code = _ingest_command(args, out=out, err=err)
            with lock:
                outcomes[operation_id] = code

        with self._patched(calls, guard=guard):
            threads = [
                threading.Thread(target=contender, args=("op-superset", full_config)),
                threading.Thread(target=contender, args=("op-subset", sub_config)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual({0}, set(outcomes.values()))
        self.assertEqual(0, guard.violations)
        total, fetched = _db_counts(self.root)
        self.assertEqual((4, 4), (total, fetched))

        # An unresolved subset owner blocks a superset newcomer on the shared
        # board; a truly disjoint scope stays runnable.
        original_cycle = Collector.cycle

        def die_then_raise(instance):
            original_cycle(instance)
            raise KillDuringCycle()

        with self.assertRaises(KillDuringCycle), self._patched(calls), mock.patch.object(
            Collector, "cycle", autospec=True, side_effect=die_then_raise
        ):
            _run(self._argv("op-stuck-subset", sub_config))
        stuck_calls = len(calls)

        with self._patched(calls):
            blocked_code, _out, blocked_err = _run(self._argv("op-wants-full", full_config))
        self.assertEqual(2, blocked_code)
        refusal = _stderr_json(blocked_err)
        self.assertEqual("scope_blocked", refusal["reason"])
        self.assertIn("fixtureboard", refusal["blocked_by"][0]["intersecting_boards"])

        with self._patched(calls):
            with contextlib.closing(
                sqlite3.connect(self.root / "state" / "vacancies.sqlite3")
            ) as conn:
                conn.execute("DELETE FROM source_state WHERE board=?", (SECOND_BOARD,))
                conn.commit()
            disjoint_code, disjoint_out, _err = _run(
                self._argv("op-disjoint-ok", disjoint_config)
            )
        self.assertEqual(0, disjoint_code)
        # Re-discovery of an already-fetched board resumes without refetching.
        self.assertEqual(
            {"seen": 1, "new": 0, "fetched": 0, "errors": 0, "database_total": 4},
            _json_out(disjoint_out)["result"],
        )
        del stuck_calls

    def test_snapshot_config_binds_extends_closure_and_midload_mutation(self) -> None:
        base = self.root / "snapshot-base.yaml"
        child = self.root / "snapshot-child.yaml"
        base.write_text(
            yaml.safe_dump(
                {
                    "boards": {"enabled": ["fixtureboard"]},
                    "search_terms": ["engineer"],
                    "fixtureboard": {"minimum_poll_minutes": 0.5},
                    "collection": {"fetch_workers": 4},
                }
            ),
            encoding="utf-8",
        )
        child.write_text(
            yaml.safe_dump(
                {"extends": "snapshot-base.yaml", "collection": {"fetch_workers": 8}}
            ),
            encoding="utf-8",
        )
        merged, identities = snapshot_config(child)
        self.assertEqual(8, merged["collection"]["fetch_workers"])
        self.assertEqual(2, len(identities))
        closure = closure_identity(identities)
        self.assertEqual(64, len(closure))

        real_reader = __import__("market_aligner.config_loader", fromlist=["_read_verified"]
                                 )._read_verified
        reads: dict[str, int] = {}

        def mutating_reader(path: Path) -> bytes:
            data = real_reader(path)
            if path.name == "snapshot-base.yaml":
                reads[path.name] = reads.get(path.name, 0) + 1
                if reads[path.name] >= 2:
                    return data.replace(b"4", b"9")
            return data

        with self.assertRaisesRegex(ValueError, "changed during load"):
            snapshot_config(child, reader=mutating_reader)

        # A dependency change after sealing rejects the same operation id.
        calls: list = []
        with self._patched(calls):
            first_code, _out, _err = _run(self._argv("op-depbound", child))
        self.assertEqual(0, first_code)
        base.write_text(
            yaml.safe_dump(
                {
                    "boards": {"enabled": ["fixtureboard"]},
                    "search_terms": ["engineer"],
                    "fixtureboard": {"minimum_poll_minutes": 0.5},
                    "collection": {"fetch_workers": 6},
                }
            ),
            encoding="utf-8",
        )
        with self._patched(calls):
            code, _out, err = _run(self._argv("op-depbound", child))
        self.assertEqual(2, code)
        self.assertEqual("binding_config_file_sha256", _stderr_json(err)["reason"])

    def test_broken_symlinks_and_constructor_races_fail_closed(self) -> None:
        broken_record = self.journal.record_path("op-broken")
        os.symlink(self.root / "does-not-exist", broken_record)
        with self.assertRaises(OperationRefused) as caught:
            self.journal.load("op-broken")
        self.assertEqual("unsafe_journal_file", caught.exception.reason)
        calls: list = []
        with self._patched(calls):
            code, _out, err = _run(self._argv("op-broken"))
        self.assertEqual(2, code)
        self.assertEqual("unsafe_journal_file", _stderr_json(err)["reason"])
        self.assertEqual([], calls)
        broken_record.unlink()

        missing_target = self.root / "no-such-lock-target"
        os.symlink(missing_target, self.journal.board_lock_path(str(self.root), "fixtureboard"))
        try:
            with self.assertRaises(OperationRefused) as caught:
                self.journal.acquire_board_locks(str(self.root), ["fixtureboard"])
            self.assertEqual("unsafe_journal_file", caught.exception.reason)
        finally:
            os.unlink(self.journal.board_lock_path(str(self.root), "fixtureboard"))

        raced_root = self.root / "state" / "raced-journal"
        errors: list[BaseException] = []
        barrier = threading.Barrier(2)

        def build() -> None:
            barrier.wait()
            try:
                OperationJournal(raced_root)
            except BaseException as exc:  # pragma: no cover - only on failure
                errors.append(exc)

        builders = [threading.Thread(target=build) for _ in range(2)]
        for builder in builders:
            builder.start()
        for builder in builders:
            builder.join()
        self.assertEqual([], errors)
        self.assertTrue(raced_root.is_dir() and not raced_root.is_symlink())

    def test_partial_claim_publication_failure_permits_retry(self) -> None:
        calls: list = []
        final = self.journal.record_path("op-partialclaim")
        with self._patched(calls), mock.patch.object(
            os, "link", side_effect=OSError("publication interrupted")
        ):
            code, _out, err = _run(self._argv("op-partialclaim"))
        self.assertEqual(2, code)
        refusal = _stderr_json(err)
        self.assertEqual("claim_publication_failed", refusal["reason"])
        self.assertFalse(os.path.lexists(final))
        self.assertEqual([], calls)
        temps = list(self.journal_root.glob(".claim-op-partialclaim-*"))
        self.assertEqual([], temps)

        with self._patched(calls):
            retry_code, retry_out, _err = _run(self._argv("op-partialclaim"))
        self.assertEqual(0, retry_code)
        self.assertEqual("ok", _json_out(retry_out)["status"])
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))

    def test_staged_claim_temp_is_repaired_not_treated_as_absence(self) -> None:
        operation_id = "op-stagedclaim"
        staged_record = make_record(
            operation_id=operation_id,
            kind=INGEST_CYCLE_KIND,
            config_source=str(self.config_path),
            config_file_sha256=closure_identity(snapshot_config(self.config_path)[1]),
            config_sha256=content_sha256(
                yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
            ),
            source_scope=["fixtureboard"],
            data_home=str(self.root),
            disposition="in_flight",
            owner_id=new_owner_id(),
        )
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".claim-{operation_id}-", dir=self.journal_root
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(staged_record).encode("utf-8"))
        final = self.journal.record_path(operation_id)
        os.link(temporary, final)
        self.assertEqual(2, os.lstat(final).st_nlink)

        loaded = self.journal.load(operation_id)
        self.assertEqual("in_flight", loaded["disposition"])
        self.assertEqual(1, os.lstat(final).st_nlink)
        self.assertEqual([], list(self.journal_root.glob(f".claim-{operation_id}-*")))

        calls: list = []
        with self._patched(calls):
            code, _out, err = _run(self._argv(operation_id))
        self.assertEqual(2, code)
        self.assertEqual("in_progress", _stderr_json(err)["reason"])
        self.assertEqual([], calls)

    def test_long_unicode_provider_failure_seals_failed_and_replays(self) -> None:
        failure_text = ("é" * 2500 + "\U0001F4A5" * 1000 + " provider exploded")
        calls: list = []

        def failing_export(_self, _path):
            raise RuntimeError(failure_text)

        with self._patched(calls), mock.patch.object(
            JobDatabase, "export_urls", autospec=True, side_effect=failing_export
        ):
            code, _out, err = _run(self._argv("op-unicode"))
        self.assertEqual(2, code)
        refusal = _stderr_json(err)
        self.assertEqual("provider_failure", refusal["reason"])
        record = self.journal.load("op-unicode")
        self.assertEqual("failed", record["disposition"])
        self.assertLessEqual(len(record["error"]), 1024)
        self.assertIn("[sha256=", record["error"])
        expected = normalized_error(RuntimeError(failure_text))
        self.assertEqual(expected, record["error"])
        total, fetched = _db_counts(self.root)
        self.assertEqual((3, 3), (total, fetched))
        failed_bytes = self.journal.record_path("op-unicode").read_bytes()

        calls_snapshot = list(calls)
        with self._patched(calls):
            replay_code, replay_out, _err = _run(self._argv("op-unicode"))
        self.assertEqual(2, replay_code)
        replay = _json_out(replay_out)
        self.assertEqual("replayed", replay["status"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(record["error"], replay["error"])
        self.assertEqual(calls_snapshot, calls)
        self.assertEqual(failed_bytes, self.journal.record_path("op-unicode").read_bytes())

    # -- existing CLI behaviour unchanged -------------------------------------------
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


if __name__ == "__main__":
    unittest.main()
