"""INGEST-001 R2 acceptance coverage.

The positive tests traverse a fixture adapter through the real Collector
persistence path (canonical ``Collector.cycle`` -> ``JobDatabase`` -> raw
cache), not through argument mocks. Only the adapter seam is substituted,
mirroring the established pattern in :mod:`tests.test_collection`.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import threading
import time
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
        operation_tag="untagged",
        failure_text="provider refused {job_id}",
        registered_tags=None,
        tagged_calls=None,
        delay=0.0,
    ):
        self.board = board_name
        super().__init__(fixture_dir=fixture_dir, config=config)
        self.calls = calls if calls is not None else []
        self.fail_ids = frozenset(fail_ids)
        self.guard = guard
        # The operation tag is captured at adapter construction and passed
        # explicitly into the guard: Collector executes discover/fetch inside
        # its own thread pools, so thread-locals would lose the identity.
        self.operation_tag = operation_tag
        if registered_tags is not None:
            registered_tags.append(operation_tag)
        self.tagged_calls = tagged_calls if tagged_calls is not None else []
        # A bounded provider delay keeps each explicit-tag guard section open
        # long enough that any lost board-lock serialization would necessarily
        # overlap and increment violations instead of passing vacuously.
        self.delay = delay
        self.failure_text = failure_text

    def _record(self, kind, detail):
        self.calls.append((kind, self.board, detail))
        self.tagged_calls.append((self.operation_tag, kind, self.board, detail))

    def discover(self, search_terms, live=False):
        with (
            self.guard.enter(self.operation_tag)
            if self.guard is not None
            else contextlib.nullcontext()
        ):
            self._record("discover", tuple(search_terms))
            if self.delay:
                time.sleep(self.delay)
            rows = list(super().discover(search_terms, live=False))
        yield from rows

    def fetch(self, job_url, live=False):
        with (
            self.guard.enter(self.operation_tag)
            if self.guard is not None
            else contextlib.nullcontext()
        ):
            self._record("fetch", job_url.job_id)
            if self.delay:
                time.sleep(self.delay)
            if job_url.job_id in self.fail_ids:
                raise RuntimeError(
                    self.failure_text.format(job_id=job_url.job_id, board=self.board)
                )
            return super().fetch(job_url, live=False)


class OverlapGuard:
    """Fails when provider calls of two different operations overlap.

    Active calls are tracked as explicit per-operation reference counts:
    parallel fetches inside one operation each increment and decrement
    ``active[tag]``, so an operation stays visible until its LAST provider
    call returns. A violation is recorded exactly when a call enters while
    any other tag has a positive count. The tag is captured when each adapter
    is constructed and passed explicitly to :meth:`enter`, because Collector
    runs discover/fetch inside its own thread pools where thread-locals from
    the contender thread are invisible.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active: dict[str, int] = {}
        self.violations = 0

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self.active)

    @contextlib.contextmanager
    def enter(self, tag: str):
        with self._lock:
            for other, count in self.active.items():
                if other != tag and count > 0:
                    self.violations += 1
                    break
            self.active[tag] = self.active.get(tag, 0) + 1
        try:
            yield
        finally:
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


def _discovers_by_board_tag(tagged_calls: list[tuple]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for tag, kind, board, _detail in tagged_calls:
        if kind != "discover":
            continue
        counts.setdefault(tag, {})
        counts[tag][board] = counts[tag].get(board, 0) + 1
    return counts


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
                 failure_text="provider refused {job_id}", operation_tag="untagged"):
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
                operation_tag=operation_tag,
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
        # ONE shared patch covers the whole concurrent run; the factory reads
        # an immutable per-operation tag embedded in each contender's distinct
        # config file. A shared deterministic source_due=True seam forces BOTH
        # contenders provider-eligible after serialization, and the bounded
        # provider delay keeps every explicit-tag guard section open long
        # enough that losing board-lock serialization would necessarily overlap
        # delayed sections and increment violations instead of passing vacuously.
        from market_aligner.cli import _ingest_command, build_parser
        fixture_dir = self.root / "fixtures"
        adapter_tags: list[str] = []
        tagged_calls: list[tuple] = []
        contenders = (
            ("op-concurrent-a", self._write_board_config(
                "conc-a", ["fixtureboard"], operation_tag="op-concurrent-a")),
            ("op-concurrent-b", self._write_board_config(
                "conc-b", ["fixtureboard"], operation_tag="op-concurrent-b")),
        )

        def factory(board, config=None):
            tag = str((config or {}).get("operation_tag") or f"unmarked:{board}")
            return FixtureBoard(
                board_name=board,
                fixture_dir=fixture_dir,
                config=config,
                calls=calls,
                guard=guard,
                operation_tag=tag,
                registered_tags=adapter_tags,
                tagged_calls=tagged_calls,
                delay=0.03,
            )

        def contender(operation_id: str, config_path: Path) -> None:
            args = build_parser().parse_args([
                "ingest", "--operation-id", operation_id,
                "--config", str(config_path), "--data-home", str(self.root),
            ])
            out, err = io.StringIO(), io.StringIO()
            code = _ingest_command(args, out=out, err=err)
            with lock:
                outcomes[operation_id] = (code, out.getvalue(), err.getvalue())

        threads = [
            threading.Thread(target=contender, args=pair) for pair in contenders
        ]
        with mock.patch(
            "market_aligner.collectors.engine.load_adapter", side_effect=factory
        ), mock.patch.object(JobDatabase, "source_due", autospec=True, return_value=True):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        # Both exact contenders constructed real adapters and both reached the
        # shared board's discover sequentially under their own distinct tags.
        self.assertEqual({"op-concurrent-a", "op-concurrent-b"}, set(adapter_tags))
        discovers_by_tag: dict[str, int] = {}
        for tag, kind, _board, _detail in tagged_calls:
            if kind == "discover":
                discovers_by_tag[tag] = discovers_by_tag.get(tag, 0) + 1
        self.assertEqual({"op-concurrent-a": 1, "op-concurrent-b": 1}, discovers_by_tag)
        self.assertEqual(0, guard.violations)

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
        # forced-due loser re-discovers the same rows and fetches nothing.
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
                    {"seen": 3, "new": 0, "fetched": 0, "errors": 0, "database_total": 3},
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
        with guard.enter("op-a"):
            with guard.enter("op-a"):  # second parallel call of the same operation
                self.assertEqual({"op-a": 2}, guard.snapshot())
            # First call returned: A stays visible with one active call.
            self.assertEqual({"op-a": 1}, guard.snapshot())
            self.assertEqual(0, guard.violations)
            # A different adapter tag entering now is detected and prevented.
            with guard.enter("op-b"):
                self.assertEqual(1, guard.violations)
                self.assertEqual({"op-a": 1, "op-b": 1}, guard.snapshot())
        # Parallel same-tag calls never count as cross-operation overlap even
        # when they interleave with another tag's sequential calls; a genuinely
        # different tag entering while another is active still counts exactly.
        first_violations = guard.violations
        with guard.enter("op-c"):
            with guard.enter("op-c"):
                self.assertEqual(guard.snapshot()["op-c"], 2)
                self.assertEqual(first_violations, guard.violations)
            self.assertEqual(1, guard.snapshot()["op-c"])
            with guard.enter("op-b"):
                self.assertEqual(first_violations + 1, guard.violations)
        self.assertEqual({}, guard.snapshot())
        self.assertEqual(first_violations + 1, guard.violations)

    def test_simultaneous_same_id_replays_after_lock_wait(self) -> None:
        calls: list = []
        guard = OverlapGuard()
        outcomes: list[tuple[int, str, str]] = []
        lock = threading.Lock()
        from market_aligner.cli import _ingest_command, build_parser
        fixture_dir = self.root / "fixtures"
        twin_config = self._write_board_config(
            "twins", ["fixtureboard"], operation_tag="op-twins"
        )
        adapter_tags: list[str] = []
        tagged_calls: list[tuple] = []

        def factory(board, config=None):
            tag = str((config or {}).get("operation_tag") or f"unmarked:{board}")
            return FixtureBoard(
                board_name=board,
                fixture_dir=fixture_dir,
                config=config,
                calls=calls,
                guard=guard,
                operation_tag=tag,
                registered_tags=adapter_tags,
                tagged_calls=tagged_calls,
                delay=0.03,
            )

        def contender(operation_id: str) -> None:
            args = build_parser().parse_args([
                "ingest", "--operation-id", operation_id,
                "--config", str(twin_config), "--data-home", str(self.root),
            ])
            out, err = io.StringIO(), io.StringIO()
            code = _ingest_command(args, out=out, err=err)
            with lock:
                outcomes.append((code, out.getvalue(), err.getvalue()))

        threads = [
            threading.Thread(target=contender, args=("op-twins",)),
            threading.Thread(target=contender, args=("op-twins",)),
        ]
        with mock.patch(
            "market_aligner.collectors.engine.load_adapter", side_effect=factory
        ), mock.patch.object(JobDatabase, "source_due", autospec=True, return_value=True):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        # Same-ID contenders intentionally share exactly one immutable tag and
        # execute exactly one external cycle in total.
        self.assertEqual({"op-twins"}, set(adapter_tags))
        self.assertEqual(1, sum(1 for call in tagged_calls if call[1] == "discover"))

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

    def _write_board_config(
        self, name: str, boards: list[str], operation_tag: str | None = None
    ) -> Path:
        cfg = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        cfg["boards"] = {"enabled": boards}
        for board in boards:
            section = dict(cfg.get(board) or {})
            if operation_tag is not None:
                # Immutable per-operation marker read by the shared adapter
                # factory; distinct files carry distinct tags while same-ID
                # twins share one file and therefore one tag.
                section["operation_tag"] = operation_tag
            cfg[board] = section
        path = self.root / f"{name}.yaml"
        path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        return path

    def test_intersecting_scopes_serialize_and_block_on_unresolved(self) -> None:
        calls: list = []
        guard = OverlapGuard()
        outcomes: dict[str, int] = {}
        lock = threading.Lock()
        adapter_tags: list[str] = []
        tagged_calls: list[tuple] = []
        from market_aligner.cli import _ingest_command, build_parser
        fixture_dir = self.root / "fixtures"
        full_config = self._write_board_config(
            "full", ["fixtureboard", SECOND_BOARD], operation_tag="op-superset"
        )
        sub_config = self._write_board_config(
            "sub", ["fixtureboard"], operation_tag="op-subset"
        )
        disjoint_config = self._write_board_config(
            "disjoint", [SECOND_BOARD], operation_tag="op-disjoint"
        )

        def factory(board, config=None):
            tag = str((config or {}).get("operation_tag") or f"unmarked:{board}")
            return FixtureBoard(
                board_name=board,
                fixture_dir=fixture_dir,
                config=config,
                calls=calls,
                guard=guard,
                operation_tag=tag,
                registered_tags=adapter_tags,
                tagged_calls=tagged_calls,
                delay=0.03,
            )

        def contender(operation_id: str, config_path: Path) -> None:
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

        threads = [
            threading.Thread(target=contender, args=("op-superset", full_config)),
            threading.Thread(target=contender, args=("op-subset", sub_config)),
        ]
        with mock.patch(
            "market_aligner.collectors.engine.load_adapter", side_effect=factory
        ), mock.patch.object(JobDatabase, "source_due", autospec=True, return_value=True):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual({0}, set(outcomes.values()))
        self.assertEqual(0, guard.violations)
        # Both operations reach the shared board provider sequentially with
        # distinct explicit tags; the superset also covers its extra board.
        self.assertEqual({"op-superset", "op-subset"}, set(adapter_tags))
        shared_discovers = {
            tag: count
            for tag, count in _discovers_by_board_tag(tagged_calls).items()
            if tag in {"op-superset", "op-subset"} and "fixtureboard" in count
        }
        self.assertEqual(2, len(shared_discovers))
        for tag, boards in shared_discovers.items():
            self.assertGreaterEqual(boards.get("fixtureboard", 0), 1, tag)
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

    # -- lock substitution refusals before provider -----------------------------
    def test_preexisting_board_lock_substitutions_fail_closed(self) -> None:
        board_lock = self.journal.board_lock_path(str(self.root), "fixtureboard")

        def scenario(mode_or_link):
            if mode_or_link == "broken":
                os.symlink(self.root / "no-target", board_lock)
            else:
                board_lock.write_text("")
                os.chmod(board_lock, mode_or_link)
            try:
                calls: list = []
                with self._patched(calls):
                    code, out, err = _run(self._argv("op-boardlock"))
                self.assertEqual(2, code)
                self.assertEqual("", out.strip())
                self.assertEqual("unsafe_journal_file", _stderr_json(err)["reason"])
                self.assertEqual([], calls)
                # The unsafe entry itself is preserved for inspection.
                self.assertTrue(os.path.lexists(board_lock))
            finally:
                if os.path.lexists(board_lock) and not (
                    board_lock.is_symlink() is False and board_lock.stat().st_nlink > 1
                ):
                    pass
                os.remove(board_lock) if os.path.lexists(board_lock) else None
                self.assertFalse(os.path.lexists(board_lock))

        scenario(0o664)
        scenario("broken")

    def test_preexisting_operation_lock_substitutions_fail_before_provider(self) -> None:
        operation_id = "op-lockguard"
        op_lock = self.journal._lock_path(operation_id)

        def scenario(kind):
            if kind == "symlink":
                os.symlink(self.root / "no-target", op_lock)
            elif kind == "hardlink":
                witness = self.journal_root / "witness.txt"
                witness.write_text("shared", encoding="utf-8")
                os.link(witness, op_lock)
            else:
                op_lock.write_text("")
                os.chmod(op_lock, kind)
            try:
                calls: list = []
                with self._patched(calls):
                    code, out, err = _run(self._argv(operation_id))
                self.assertEqual(2, code)
                self.assertEqual("", out.strip())
                refusal = _stderr_json(err)
                self.assertEqual("unsafe_journal_file", refusal["reason"])
                self.assertEqual(operation_id, refusal["operation_id"])
                # No claim exists yet: the structured refusal must not assert
                # an in_flight disposition it never reached.
                self.assertIsNone(refusal["disposition"])
                self.assertEqual([], calls)
                self.assertFalse(os.path.lexists(self.journal.record_path(operation_id)))
                self.assertTrue(os.path.lexists(op_lock))
            finally:
                if os.path.lexists(op_lock):
                    os.unlink(op_lock)

        scenario(0o644)
        scenario(0o664)
        scenario("symlink")
        scenario("hardlink")

    def test_same_id_disjoint_scopes_return_precise_binding_refusal(self) -> None:
        config_a = self._write_board_config(
            "race-a", ["fixtureboard"], operation_tag="op-racepair"
        )
        config_b = self._write_board_config(
            "race-b", [SECOND_BOARD], operation_tag="op-racepair"
        )
        calls: list = []
        adapter_tags: list[str] = []
        tagged_calls: list[tuple] = []
        from market_aligner.cli import _ingest_command, build_parser
        fixture_dir = self.root / "fixtures"

        def factory(board, config=None):
            tag = str((config or {}).get("operation_tag") or f"unmarked:{board}")
            return FixtureBoard(
                board_name=board,
                fixture_dir=fixture_dir,
                config=config,
                calls=calls,
                guard=None,
                operation_tag=tag,
                registered_tags=adapter_tags,
                tagged_calls=tagged_calls,
            )

        results: list[tuple[int, str, str]] = []
        start = threading.Barrier(2)

        def contender(config_path: Path) -> None:
            args = build_parser().parse_args([
                "ingest", "--operation-id", "op-racepair",
                "--config", str(config_path), "--data-home", str(self.root),
            ])
            out, err = io.StringIO(), io.StringIO()
            start.wait()
            code = _ingest_command(args, out=out, err=err)
            results.append((code, out.getvalue(), err.getvalue()))

        threads = [
            threading.Thread(target=contender, args=(config_a,)),
            threading.Thread(target=contender, args=(config_b,)),
        ]
        with mock.patch(
            "market_aligner.collectors.engine.load_adapter", side_effect=factory
        ):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        codes = sorted(code for code, _out, _err in results)
        self.assertEqual([0, 2], codes)
        ok_payloads = [
            json.loads(line)
            for _code, out, _err in results
            for line in out.splitlines()
            if line.strip()
        ]
        self.assertEqual(1, len(ok_payloads))
        winner_scope = set(ok_payloads[0]["source_scope"])
        loser_reasons = [
            json.loads(line)["reason"]
            for _code, _out, err in results
            for line in err.splitlines()
            if line.strip().startswith("{")
        ]
        # The loser reports exactly the scope substitution: source_scope is
        # checked before the config identity fields, so a disjoint-scope twin
        # is never masked by its wholesale configuration difference and never
        # degrades to a generic in_progress.
        self.assertEqual(1, len(loser_reasons))
        self.assertEqual(["binding_source_scope"], loser_reasons)
        # Zero second provider access: every contacted board belongs only to
        # the winner's scope; the loser's disjoint board was never touched.
        touched_boards = {board for _tag, kind, board, _d in tagged_calls}
        self.assertTrue(touched_boards.issubset(winner_scope), touched_boards)
        record = json.loads(self.journal.record_path("op-racepair").read_text(encoding="utf-8"))
        self.assertEqual(sorted(winner_scope), record["source_scope"])
        self.assertEqual("completed", record["disposition"])

    def test_reversed_enabled_order_canonicalizes_scope_deterministically(self) -> None:
        reversed_config = self._write_board_config(
            "reversed", [SECOND_BOARD, "fixtureboard"], operation_tag="op-reversed"
        )
        calls: list = []
        with mock.patch.object(JobDatabase, "source_due", autospec=True, return_value=True):
            with self._patched(calls):
                first_code, first_out, _err = _run(
                    self._argv("op-rev-first", reversed_config)
                )
                second_code, second_out, _err = _run(
                    self._argv("op-rev-second", reversed_config)
                )
        self.assertEqual(0, first_code)
        self.assertEqual(0, second_code)
        for payload in (_json_out(first_out), _json_out(second_out)):
            # Canonicalization happens exactly once in Collector.plan: the
            # reversed configured order binds as sorted unique scope.
            self.assertEqual(
                ["fixtureboard", SECOND_BOARD], payload["source_scope"], payload
            )
        self.assertEqual(4, _json_out(first_out)["result"]["seen"])
        first_result = _json_out(first_out)["result"]
        second_result = _json_out(second_out)["result"]
        self.assertEqual(4, first_result["new"])
        self.assertEqual(0, second_result["new"])
        discovers = [call for call in calls if call[0] == "discover"]
        self.assertEqual(
            {"fixtureboard": 2, SECOND_BOARD: 2},
            {
                board: sum(1 for call in discovers if call[1] == board)
                for board in {call[1] for call in discovers}
            },
        )

    # -- R5 publication-window race authority -------------------------------------
    def _race_pair_configs(self, prefix: str, tag: str):
        config_a = self._write_board_config(
            f"{prefix}-a", ["fixtureboard"], operation_tag=f"{tag}-a"
        )
        config_b = self._write_board_config(
            f"{prefix}-b", [SECOND_BOARD], operation_tag=f"{tag}-b"
        )
        return config_a, config_b

    def test_link_before_unlink_window_blocks_loser_then_exact_scope(self) -> None:
        operation_id = "op-linkwin"
        config_a, config_b = self._race_pair_configs("linkwin", "op-linkwin")
        calls: list = []
        tagged_calls: list[tuple] = []
        results: dict[str, tuple[int, str, str]] = {}
        lock = threading.Lock()
        linked = threading.Event()
        proceed = threading.Event()
        real_unlink = os.unlink
        state = {"gated": False}

        # Publication barrier: the first staging-temp unlink of the publisher
        # stalls after os.link, holding the transient two-link window open.
        def gated_unlink(path, *args, **kwargs):
            if f".claim-{operation_id}-" in str(path) and not state["gated"]:
                state["gated"] = True
                linked.set()
                proceed.wait(10)
            return real_unlink(path, *args, **kwargs)

        from market_aligner.cli import _ingest_command, build_parser
        fixture_dir = self.root / "fixtures"
        adapter_tags: list[str] = []

        def factory(board, config=None):
            tag = str((config or {}).get("operation_tag") or f"unmarked:{board}")
            return FixtureBoard(
                board_name=board,
                fixture_dir=fixture_dir,
                config=config,
                calls=calls,
                guard=None,
                operation_tag=tag,
                registered_tags=adapter_tags,
                tagged_calls=tagged_calls,
            )

        def contender(label: str, config_path: Path) -> None:
            args = build_parser().parse_args([
                "ingest", "--operation-id", operation_id,
                "--config", str(config_path), "--data-home", str(self.root),
            ])
            out, err = io.StringIO(), io.StringIO()
            code = _ingest_command(args, out=out, err=err)
            with lock:
                results[label] = (code, out.getvalue(), err.getvalue())

        winner_thread = threading.Thread(
            target=contender, args=("winner", config_a)
        )
        loser_thread = threading.Thread(
            target=contender, args=("loser", config_b)
        )

        final = self.journal.record_path(operation_id)
        with mock.patch(
            "market_aligner.collectors.engine.load_adapter", side_effect=factory
        ), mock.patch(
            "market_aligner.state.operations.os.unlink", side_effect=gated_unlink
        ), mock.patch.object(
            JobDatabase, "source_due", autospec=True, return_value=True
        ):
            winner_thread.start()
            self.assertTrue(linked.wait(10), "publisher never reached two-link window")
            self.assertEqual(2, os.lstat(final).st_nlink)

            # The loser waits for publication authority; nothing is mutated.
            loser_thread.start()
            loser_thread.join(0.6)
            self.assertTrue(loser_thread.is_alive(), "loser must wait for authority")
            self.assertEqual(1, len(list(self.journal_root.glob(f".claim-{operation_id}-*"))))
            self.assertEqual(2, os.lstat(final).st_nlink)

            proceed.set()
            winner_thread.join(30)
            loser_thread.join(30)
            self.assertFalse(winner_thread.is_alive())
            self.assertFalse(loser_thread.is_alive())

        code_a, out_a, err_a = results["winner"]
        code_b, out_b, err_b = results["loser"]
        self.assertEqual(0, code_a)
        self.assertEqual(2, code_b)
        payload = json.loads(out_a)
        self.assertEqual("ok", payload["status"])
        self.assertEqual(3, payload["result"]["fetched"])
        self.assertNotIn("claim_publication_failed", err_a)
        self.assertNotIn("unsafe_journal_file", err_a)
        refusal = json.loads(
            [line for line in err_b.splitlines() if line.strip().startswith("{")][-1]
        )
        self.assertEqual("binding_source_scope", refusal["reason"])
        self.assertNotIn("unsafe_journal_file", err_b)
        self.assertNotIn("claim_publication_failed", err_b)
        self.assertEqual("", out_b.strip())
        self.assertEqual([], list(self.journal_root.glob(f".claim-{operation_id}-*")))
        record = json.loads(final.read_text(encoding="utf-8"))
        self.assertEqual("completed", record["disposition"])
        self.assertEqual(payload["receipt_id"], record["receipt_id"])
        # Provider evidence: only the winning scope ran, exactly one cycle.
        self.assertEqual({"op-linkwin-a"}, set(adapter_tags))
        self.assertEqual(1, sum(1 for call in tagged_calls if call[1] == "discover"))

    def test_settlement_rejects_foreign_and_composite_residue_without_mutation(self) -> None:
        base_record = make_record(
            operation_id="op-residue",
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
        payload = canonical_json(base_record).encode("utf-8")

        # Foreign hardlink only (nlink=2, no matching claim temp), free lock:
        # settlement refuses without mutating either extra link.
        descriptor, foreign = tempfile.mkstemp(
            prefix="foreign-", dir=self.journal_root
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        final = self.journal.record_path("op-residue")
        os.link(foreign, final)
        try:
            with self.assertRaises(OperationRefused) as caught:
                self.journal._settled_record_bytes("op-residue", final)
            self.assertIn("unresolved additional links", str(caught.exception))
            self.assertEqual(2, os.lstat(final).st_nlink)
            self.assertTrue(os.path.lexists(foreign))
        finally:
            os.unlink(foreign)
            os.unlink(final)

        # Composite residue: own exact temp + final + foreign hardlink starts
        # at nlink=3 and must reject WITHOUT removing either extra link.
        descriptor, own_temp = tempfile.mkstemp(
            prefix=f".claim-op-residue-", dir=self.journal_root
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        os.link(own_temp, final)
        foreign2 = self.journal_root / "foreign-hardlink"
        os.link(own_temp, foreign2)
        self.assertEqual(3, os.lstat(final).st_nlink)
        try:
            held = self.journal.open_operation_lock("op-residue")
            with self.assertRaises(OperationRefused) as caught:
                self.journal._settled_record_bytes(
                    "op-residue", final, operation_lock_fd=held
                )
            self.assertIn("nlink=3", str(caught.exception))
            self.assertEqual(3, os.lstat(final).st_nlink)
            self.assertTrue(os.path.lexists(own_temp))
            self.assertTrue(os.path.lexists(foreign2))
            OperationJournal.release_locks([held])
        finally:
            for entry in (final, foreign2, own_temp):
                if os.path.lexists(entry):
                    os.unlink(entry)

        # Excess matching temps: two names sharing the published inode refuse.
        descriptor, temp_one = tempfile.mkstemp(
            prefix=f".claim-op-excess-", dir=self.journal_root
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        temp_two = self.journal_root / ".claim-op-excess-second"
        os.link(temp_one, temp_two)
        final_excess = self.journal.record_path("op-excess")
        os.link(temp_one, final_excess)
        try:
            with self.assertRaises(OperationRefused) as caught:
                self.journal._settled_record_bytes("op-excess", final_excess)
            self.assertIn("matching_temps=2", str(caught.exception))
            self.assertEqual(3, os.lstat(final_excess).st_nlink)
        finally:
            for entry in (final_excess, temp_two, temp_one):
                if os.path.lexists(entry):
                    os.unlink(entry)

    def test_live_publisher_holds_authority_reader_waits_then_rejects(self) -> None:
        # Foreign hardlink final while a live owner demonstrably holds the
        # typed lock: a reader blocks without mutating, and only after the
        # lock is released does it fail closed on the uncleanable residue.
        operation_id = "op-heldforeign"
        staged = make_record(
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
        payload = canonical_json(staged).encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".claim-{operation_id}-x", dir=self.journal_root
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        final = self.journal.record_path(operation_id)
        foreign = self.journal_root / f"{operation_id}-foreign"
        os.link(temporary, final)   # publisher window shape...
        os.link(temporary, foreign)  # ...plus a foreign third name? nlink counts names.
        os.unlink(temporary)         # leave final+foreign exactly two links, no temp
        self.assertEqual(2, os.lstat(final).st_nlink)

        held = self.journal.open_operation_lock(operation_id)
        outcome: list = []

        def reader() -> None:
            try:
                outcome.append(self.journal.load(operation_id))
            except BaseException as exc:
                outcome.append(exc)

        reader_thread = threading.Thread(target=reader)
        reader_thread.start()
        reader_thread.join(0.6)
        self.assertTrue(reader_thread.is_alive(), "reader must wait for authority")
        self.assertEqual(2, os.lstat(final).st_nlink)
        self.assertTrue(os.path.lexists(foreign))
        OperationJournal.release_locks([held])
        reader_thread.join(10)
        self.assertFalse(reader_thread.is_alive())
        self.assertEqual(1, len(outcome))
        self.assertIsInstance(outcome[0], OperationRefused)
        self.assertEqual("unsafe_journal_file", outcome[0].reason)
        self.assertEqual(2, os.lstat(final).st_nlink)
        for entry in (final, foreign):
            if os.path.lexists(entry):
                os.unlink(entry)

    def test_dead_owner_composite_temp_settles_to_single_link(self) -> None:
        # Genuine dead post-link owner: exact own temp + final (nlink=2),
        # free lock -> settlement removes the temp and strict read succeeds.
        operation_id = "op-deadowner"
        staged = make_record(
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
        payload = canonical_json(staged).encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".claim-{operation_id}-", dir=self.journal_root
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
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

    def test_operation_lock_freedom_is_thread_accurate(self) -> None:
        descriptor = self.journal.open_operation_lock("op-freecheck")
        try:
            held_results: list[bool] = []

            def probe() -> None:
                held_results.append(self.journal._operation_lock_is_free("op-freecheck"))

            probe_thread = threading.Thread(target=probe)
            probe_thread.start()
            probe_thread.join(10)
            self.assertEqual([False], held_results)
        finally:
            OperationJournal.release_locks([descriptor])
        self.assertTrue(self.journal._operation_lock_is_free("op-freecheck"))

    def test_abandoned_publication_settles_only_after_owner_release(self) -> None:
        from market_aligner.state.operations import fsync_directory

        operation_id = "op-abandon"
        staged = make_record(
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
        payload = canonical_json(staged).encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".claim-{operation_id}-", dir=self.journal_root
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        final = self.journal.record_path(operation_id)
        os.link(temporary, final)
        self.assertEqual(2, os.lstat(final).st_nlink)

        # While the owner holds the authority lock, a concurrent reader must
        # block without ever parsing or mutating the two-link publication.
        held = self.journal.open_operation_lock(operation_id)
        started = threading.Event()
        observed: dict = {}

        def reader() -> None:
            started.set()
            try:
                observed["record"] = self.journal.load(operation_id)
            except BaseException as exc:
                observed["error"] = exc

        worker = threading.Thread(target=reader)
        worker.start()
        self.assertTrue(started.wait(5))
        time.sleep(0.25)
        self.assertNotIn("record", observed)
        self.assertNotIn("error", observed)
        self.assertEqual(2, os.lstat(final).st_nlink)
        self.assertNotEqual([], list(self.journal_root.glob(f".claim-{operation_id}-*")))

        # The owner finishes its publication (removes the staging temp) and
        # only then releases authority; the parked reader completes exactly.
        os.unlink(temporary)
        fsync_directory(self.journal_root)
        OperationJournal.release_locks([held])
        worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertNotIn("error", observed)
        self.assertEqual("in_flight", observed["record"]["disposition"])
        self.assertEqual(1, os.lstat(final).st_nlink)
        self.assertEqual([], list(self.journal_root.glob(f".claim-{operation_id}-*")))

    def test_supplied_authority_fd_rejects_wrong_closed_unheld_and_substituted(self) -> None:
        operation_id = "op-fdproof"
        record = make_record(
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
        self.journal.claim(record)
        path = self.journal.record_path(operation_id)
        lock_path = Path(self.journal._lock_path(operation_id))
        # Seed then RELEASE the canonical lock file so the unheld/closed
        # negatives run against a genuinely free authority, not an anchor.
        seeding_fd = self.journal.open_operation_lock(operation_id)
        OperationJournal.release_locks([seeding_fd])

        def refuse(fd: int) -> OperationRefused:
            with self.assertRaises(OperationRefused) as caught:
                self.journal._settled_record_bytes(operation_id, path, operation_lock_fd=fd)
            return caught.exception

        # Unrelated regular file: correct shape, wrong identity.
        unrelated_fd, unrelated_name = tempfile.mkstemp(dir=self.root)
        try:
            refusal = refuse(unrelated_fd)
            self.assertEqual("unsafe_journal_file", refusal.reason)
            self.assertIn("not this operation's lock", str(refusal))
        finally:
            os.close(unrelated_fd)
            os.unlink(unrelated_name)

        # Another operation's genuine held lock fd: still refused.
        other_fd = self.journal.open_operation_lock("op-wronglock")
        try:
            refusal = refuse(other_fd)
            self.assertEqual("unsafe_journal_file", refusal.reason)
        finally:
            OperationJournal.release_locks([other_fd])

        # Closed descriptor: raw EBADF is translated to a structured refusal.
        closed_fd = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC)
        os.close(closed_fd)
        refusal = refuse(closed_fd)
        self.assertEqual("unsafe_journal_file", refusal.reason)

        # Correct canonical path but never flocked: unheld fds grant nothing.
        plain_fd = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC)
        try:
            refusal = refuse(plain_fd)
            self.assertEqual("unsafe_journal_file", refusal.reason)
            self.assertIn("does not hold", str(refusal))
        finally:
            os.close(plain_fd)

        # Substituted lock file: the held fd refers to the ORIGINAL inode.
        substituted_fd = self.journal.open_operation_lock(operation_id)
        original_ino = os.fstat(substituted_fd).st_ino
        lock_path.unlink()
        replacement_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(replacement_fd)
        try:
            self.assertNotEqual(original_ino, os.lstat(lock_path).st_ino)
            refusal = refuse(substituted_fd)
            self.assertEqual("unsafe_journal_file", refusal.reason)
            # The unlinked original inode fails verification outright.
            self.assertIn("single-link (nlink=0)", str(refusal))
        finally:
            OperationJournal.release_locks([substituted_fd])
            os.unlink(lock_path)

        # The genuine held fd remains authoritative for settlement reads.
        genuine_fd = self.journal.open_operation_lock(operation_id)
        try:
            settled_bytes = self.journal._settled_record_bytes(
                operation_id, path, operation_lock_fd=genuine_fd
            )
            self.assertEqual(record["operation_id"], json.loads(settled_bytes)["operation_id"])
        finally:
            OperationJournal.release_locks([genuine_fd])

    def test_shared_lock_fds_never_upgrade_to_settlement_authority(self) -> None:
        from market_aligner.state.operations import fsync_directory

        def shared_fd_for(op: str) -> int:
            fd = os.open(
                self.journal._lock_path(op), os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return fd

        def seed_lock(op: str) -> None:
            # Materialize the canonical lock file, then release it so the
            # negatives run against a genuinely free authority.
            seeding = self.journal.open_operation_lock(op)
            OperationJournal.release_locks([seeding])

        def free_sh_probe(op: str) -> bool:
            probe = os.open(
                self.journal._lock_path(op), os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
                fcntl.flock(probe, fcntl.LOCK_UN)
                return True
            except OSError:
                return False
            finally:
                os.close(probe)

        base = dict(
            kind=INGEST_CYCLE_KIND,
            config_source=str(self.config_path),
            config_file_sha256=closure_identity(snapshot_config(self.config_path)[1]),
            config_sha256=content_sha256(
                yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
            ),
            source_scope=["fixtureboard"],
            data_home=str(self.root),
            owner_id=new_owner_id(),
        )

        # --- nlink1 read path: a merely-shared supplied fd is refused. ---
        op1 = "op-sh-read"
        record1 = make_record(operation_id=op1, disposition="in_flight", **base)
        self.journal.claim(record1)
        seed_lock(op1)
        path1 = self.journal.record_path(op1)
        before_bytes = path1.read_bytes()
        sh1 = shared_fd_for(op1)
        try:
            with self.assertRaises(OperationRefused) as caught:
                self.journal._settled_record_bytes(op1, path1, operation_lock_fd=sh1)
            self.assertEqual("unsafe_journal_file", caught.exception.reason)
            self.assertIn("does not hold the exclusive operation lock", str(caught.exception))
            self.assertEqual(before_bytes, path1.read_bytes())
            self.assertTrue(free_sh_probe(op1))
        finally:
            fcntl.flock(sh1, fcntl.LOCK_UN)
            os.close(sh1)

        # --- nlink2 settlement path: shared fd refused, residue untouched. ---
        op2 = "op-sh-settle"
        record2 = make_record(operation_id=op2, disposition="in_flight", **base)
        payload2 = canonical_json(record2).encode("utf-8")
        descriptor, temp2 = tempfile.mkstemp(prefix=f".claim-{op2}-", dir=self.journal_root)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload2)
        final2 = self.journal.record_path(op2)
        seed_lock(op2)
        os.link(temp2, final2)
        self.assertEqual(2, os.lstat(final2).st_nlink)
        sh2 = shared_fd_for(op2)
        try:
            with self.assertRaises(OperationRefused) as caught:
                self.journal._settled_record_bytes(op2, final2, operation_lock_fd=sh2)
            self.assertEqual("unsafe_journal_file", caught.exception.reason)
            self.assertIn("does not hold the exclusive operation lock", str(caught.exception))
            self.assertEqual(2, os.lstat(final2).st_nlink)
            self.assertNotEqual([], list(self.journal_root.glob(f".claim-{op2}-*")))
            self.assertEqual(payload2, Path(temp2).read_bytes())
            self.assertTrue(free_sh_probe(op2))
        finally:
            fcntl.flock(sh2, fcntl.LOCK_UN)
            os.close(sh2)

        # --- CAS seam: a shared supplied fd refuses before any read/mutation. ---
        op3 = "op-sh-cas"
        record3 = make_record(operation_id=op3, disposition="in_flight", **base)
        prior3 = canonical_json(record3).encode("utf-8")
        descriptor, temp3 = tempfile.mkstemp(prefix=f".claim-{op3}-", dir=self.journal_root)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(prior3)
        final3 = self.journal.record_path(op3)
        seed_lock(op3)
        os.link(temp3, final3)
        sealed3 = make_record(
            operation_id=op3,
            disposition="completed",
            started_at=record3["started_at"],
            finished_at=record3["started_at"],
            result={"seen": 1, "new": 0, "fetched": 0, "errors": 0, "database_total": 1},
            **{**base, "owner_id": record3["owner_id"]},
        )
        sh3 = shared_fd_for(op3)
        try:
            with self.assertRaises(OperationRefused) as caught:
                self.journal.cas_replace(sealed3, prior3, operation_id=op3, operation_lock_fd=sh3)
            self.assertEqual("unsafe_journal_file", caught.exception.reason)
            self.assertIn("does not hold the exclusive operation lock", str(caught.exception))
            # Nothing changed: claim temp bytes/links and final are intact.
            self.assertEqual(2, os.lstat(final3).st_nlink)
            self.assertNotEqual([], list(self.journal_root.glob(f".claim-{op3}-*")))
            self.assertEqual(prior3, Path(temp3).read_bytes())
            self.assertEqual(prior3, final3.read_bytes())
            self.assertTrue(free_sh_probe(op3))
        finally:
            fcntl.flock(sh3, fcntl.LOCK_UN)
            os.close(sh3)
            for entry in (final3, temp3):
                if os.path.lexists(entry):
                    os.unlink(entry)
            fsync_directory(self.journal_root)

    def test_probe_errno_strictness_never_masks_contention_or_skips_blockers(self) -> None:
        import market_aligner.state.operations as operations_module

        real_flock = operations_module.fcntl.flock
        base = dict(
            kind=INGEST_CYCLE_KIND,
            config_source=str(self.config_path),
            config_file_sha256=closure_identity(snapshot_config(self.config_path)[1]),
            config_sha256=content_sha256(
                yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
            ),
            source_scope=["fixtureboard"],
            data_home=str(self.root),
            owner_id=new_owner_id(),
        )

        def free_sh_probe(op: str) -> bool:
            probe = os.open(
                self.journal._lock_path(op), os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                real_flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
                real_flock(probe, fcntl.LOCK_UN)
                return True
            except OSError:
                return False
            finally:
                os.close(probe)

        def first_flock_raises(errno_value: int):
            state = {"raised": False}

            def flaky(fd, request, *args, **kwargs):
                if not state["raised"]:
                    state["raised"] = True
                    raise OSError(errno_value, "injected failure")
                return real_flock(fd, request, *args, **kwargs)

            return flaky

        # Supplied canonical fd is UNHELD; R8 misread an injected EINTR on the
        # first shared probe as contention and accepted the unheld fd as
        # authority. R9 must refuse structurally for EINTR and EIO alike.
        # The independent SH observation happens INSIDE the supplied-fd
        # lifetime: an illegitimate EX upgrade would block the probe while
        # the fd is open, and closing first would silently release it.
        op1 = "op-eintr-auth"
        record1 = make_record(operation_id=op1, disposition="in_flight", **base)
        self.journal.claim(record1)
        path1 = self.journal.record_path(op1)
        before_bytes = path1.read_bytes()
        seeding = self.journal.open_operation_lock(op1)
        OperationJournal.release_locks([seeding])

        for injected_errno in (errno.EINTR, errno.EIO):
            unheld_fd = os.open(
                self.journal._lock_path(op1), os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                with mock.patch.object(
                    operations_module.fcntl, "flock", first_flock_raises(injected_errno)
                ):
                    with self.assertRaises(OperationRefused) as caught:
                        self.journal._settled_record_bytes(
                            op1, path1, operation_lock_fd=unheld_fd
                        )
                self.assertEqual("unsafe_journal_file", caught.exception.reason)
                self.assertIn("without lock contention", str(caught.exception))
                # Observed BEFORE any unlock/close of the supplied fd.
                self.assertTrue(free_sh_probe(op1))
                self.assertEqual(before_bytes, path1.read_bytes())
            finally:
                os.close(unheld_fd)

        # Same falsifier against exact nlink2 final + matching claim-temp
        # state: refusal must leave residue untouched with the supplied fd
        # still open and independently SH-probeable.
        op3 = "op-eintr-residue"
        record3 = make_record(operation_id=op3, disposition="in_flight", **base)
        payload3 = canonical_json(record3).encode("utf-8")
        descriptor3, temp3 = tempfile.mkstemp(prefix=f".claim-{op3}-", dir=self.journal_root)
        with os.fdopen(descriptor3, "wb") as handle:
            handle.write(payload3)
        final3 = self.journal.record_path(op3)
        os.link(temp3, final3)
        seeding3 = self.journal.open_operation_lock(op3)
        OperationJournal.release_locks([seeding3])
        try:
            for injected_errno in (errno.EINTR, errno.EIO):
                unheld_fd = os.open(
                    self.journal._lock_path(op3), os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
                )
                try:
                    with mock.patch.object(
                        operations_module.fcntl,
                        "flock",
                        first_flock_raises(injected_errno),
                    ):
                        with self.assertRaises(OperationRefused) as caught:
                            self.journal._settled_record_bytes(
                                op3, final3, operation_lock_fd=unheld_fd
                            )
                    self.assertEqual("unsafe_journal_file", caught.exception.reason)
                    self.assertIn("without lock contention", str(caught.exception))
                    # In-lifetime observations: no upgrade happened and the
                    # two-link residue was not mutated or settled.
                    self.assertTrue(free_sh_probe(op3))
                    self.assertEqual(2, os.lstat(final3).st_nlink)
                    self.assertNotEqual([], list(self.journal_root.glob(f".claim-{op3}-*")))
                    self.assertEqual(payload3, Path(temp3).read_bytes())
                    self.assertEqual(payload3, final3.read_bytes())
                finally:
                    os.close(unheld_fd)
        finally:
            for entry in (final3, temp3):
                if os.path.lexists(entry):
                    os.unlink(entry)
            operations_module.fsync_directory(self.journal_root)

        # wait=False seam: EINTR/EIO must refuse, never silently skip as if a
        # live publisher held the lock.
        for scan_mode in ("direct", "scope_scan"):
            op2 = f"op-{scan_mode}-eintr"
            record2 = make_record(operation_id=op2, disposition="in_flight", **base)
            payload2 = canonical_json(record2).encode("utf-8")
            descriptor, temp2 = tempfile.mkstemp(
                prefix=f".claim-{op2}-", dir=self.journal_root
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload2)
            final2 = self.journal.record_path(op2)
            os.link(temp2, final2)
            self.assertEqual(2, os.lstat(final2).st_nlink)

            for injected_errno in (errno.EINTR, errno.EIO):
                with mock.patch.object(
                    operations_module.fcntl, "flock", first_flock_raises(injected_errno)
                ):
                    if scan_mode == "direct":
                        with self.assertRaises(OperationRefused) as caught:
                            self.journal._settled_record_bytes(op2, final2, wait=False)
                    else:
                        with self.assertRaises(OperationRefused) as caught:
                            self.journal.scan_unresolved_scope_blockers(
                                str(self.root), ["fixtureboard"]
                            )
                self.assertEqual("unsafe_journal_file", caught.exception.reason)
                self.assertIn("could not acquire publication authority", str(caught.exception))
                # The unresolved blocker survived untouched — it was refused,
                # not skipped or settled.
                self.assertEqual(2, os.lstat(final2).st_nlink)
                self.assertNotEqual([], list(self.journal_root.glob(f".claim-{op2}-*")))
                self.assertEqual(payload2, Path(temp2).read_bytes())

            os.unlink(temp2)
            os.unlink(final2)
            operations_module.fsync_directory(self.journal_root)

    def test_cas_replace_without_supplied_fd_settles_exact_residue_without_deadlock(
        self,
    ) -> None:
        from market_aligner.cli import _ingest_command, build_parser  # noqa: F401
        from market_aligner.state.operations import fsync_directory

        operation_id = "op-casresidue"
        staged = make_record(
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
        prior_bytes = canonical_json(staged).encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".claim-{operation_id}-", dir=self.journal_root
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(prior_bytes)
        final = self.journal.record_path(operation_id)
        os.link(temporary, final)
        self.assertEqual(2, os.lstat(final).st_nlink)

        sealed = make_record(
            operation_id=operation_id,
            kind=INGEST_CYCLE_KIND,
            config_source=str(self.config_path),
            config_file_sha256=closure_identity(snapshot_config(self.config_path)[1]),
            config_sha256=content_sha256(
                yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
            ),
            source_scope=["fixtureboard"],
            data_home=str(self.root),
            disposition="completed",
            owner_id=staged["owner_id"],
            started_at=staged["started_at"],
            finished_at=staged["started_at"],
            result={"seen": 1, "new": 0, "fetched": 0, "errors": 0, "database_total": 1},
        )
        # No supplied fd: cas_replace acquires its own lock and passes THAT
        # acquired descriptor into settlement; re-locking itself would hang.
        self.journal.cas_replace(sealed, prior_bytes, operation_id=operation_id)

        self.assertEqual(1, os.lstat(final).st_nlink)
        self.assertEqual([], list(self.journal_root.glob(f".claim-{operation_id}-*")))
        on_disk = json.loads(final.read_text(encoding="utf-8"))
        self.assertEqual("completed", on_disk["disposition"])

    def test_settlement_lstat_races_refuse_structurally_without_mutation(self) -> None:
        import market_aligner.state.operations as operations_module
        from market_aligner.state.operations import fsync_directory

        operation_id = "op-lsttrace"
        staged = make_record(
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
        payload = canonical_json(staged).encode("utf-8")

        def stage_residue() -> tuple[Path, Path]:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".claim-{operation_id}-", dir=self.journal_root
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
            final = self.journal.record_path(operation_id)
            os.link(temporary, final)
            return final, Path(temporary)

        real_lstat = operations_module.os.lstat

        # Race 1: the final record disappears before the initial lstat.
        missing = self.journal.record_path("op-lsttrace-missing")
        with mock.patch.object(
            operations_module.os, "lstat", side_effect=OSError("vanished")
        ):
            with self.assertRaises(OperationRefused) as caught:
                self.journal._settled_record_bytes(operation_id, missing)
        self.assertEqual("unsafe_journal_file", caught.exception.reason)

        # Race 2: the matching candidate vanishes between glob and lstat.
        final, temporary = stage_residue()
        calls = {"n": 0}

        def flaky_candidate(target, *args, **kwargs):
            result = real_lstat(target, *args, **kwargs)
            if Path(target).name.startswith(".claim-") and calls["n"] == 0:
                calls["n"] += 1
                raise OSError("candidate raced away")
            return result

        held = self.journal.open_operation_lock(operation_id)
        try:
            with mock.patch.object(operations_module.os, "lstat", flaky_candidate):
                with self.assertRaises(OperationRefused) as caught:
                    self.journal._settled_record_bytes(
                        operation_id, final, operation_lock_fd=held
                    )
            self.assertEqual("unsafe_journal_file", caught.exception.reason)
            self.assertIn("not statable", str(caught.exception))
            # No mutation happened despite the race.
            self.assertEqual(2, os.lstat(final).st_nlink)
            self.assertNotEqual([], list(self.journal_root.glob(f".claim-{operation_id}-*")))
        finally:
            OperationJournal.release_locks([held])
            # Deterministic cleanup so the next stage starts from a clean root.
            os.unlink(temporary)
            os.unlink(final)
            fsync_directory(self.journal_root)
        self.assertEqual([], list(self.journal_root.glob(f".claim-{operation_id}-*")))

        # Race 3: the final vanishes after the temp was already unlinked —
        # the revalidation lstat (third final lstat: seam entry, settle entry,
        # post-unlink) is also structured, never raw.
        final2, temporary2 = stage_residue()
        final_stats = {"n": 0}

        def vanish_after_unlink(target, *args, **kwargs):
            result = real_lstat(target, *args, **kwargs)
            if Path(target) == final2:
                final_stats["n"] += 1
                if final_stats["n"] >= 3:
                    raise FileNotFoundError("final replaced mid-settlement")
            return result

        held2 = self.journal.open_operation_lock(operation_id)
        try:
            with mock.patch.object(operations_module.os, "lstat", vanish_after_unlink):
                with self.assertRaises(OperationRefused) as caught:
                    self.journal._settled_record_bytes(
                        operation_id, final2, operation_lock_fd=held2
                    )
            self.assertEqual("unsafe_journal_file", caught.exception.reason)
            self.assertIn("final replaced mid-settlement", str(caught.exception))
            # The intended branch was reached: the matching temp was already
            # removed by settlement before the post-unlink revalidation died.
            self.assertGreaterEqual(final_stats["n"], 3)
            self.assertFalse(os.path.lexists(temporary2))
            self.assertTrue(os.path.lexists(final2))
        finally:
            OperationJournal.release_locks([held2])
            # Deterministic cleanup of whatever residue survived the mocks.
            if os.path.lexists(temporary2):
                os.unlink(temporary2)
            if os.path.lexists(final2):
                os.unlink(final2)
            fsync_directory(self.journal_root)
        self.assertEqual([], list(self.journal_root.glob(f".claim-{operation_id}-*")))

    def test_high_count_same_id_disjoint_stress_keeps_exact_refusals(self) -> None:
        from market_aligner.cli import _ingest_command, build_parser
        fixture_dir = self.root / "fixtures"
        races = 100
        total_commands = 0
        for race_index in range(races):
            operation_id = f"op-racepair-{race_index}"
            config_a, config_b = self._race_pair_configs(
                f"race{race_index}", operation_id
            )
            calls: list = []
            tagged_calls: list[tuple] = []
            results: dict[str, tuple[int, str, str]] = {}
            failures: list[BaseException] = []
            lock = threading.Lock()
            adapter_tags: list[str] = []

            def factory(board, config=None):
                tag = str((config or {}).get("operation_tag") or f"unmarked:{board}")
                return FixtureBoard(
                    board_name=board,
                    fixture_dir=fixture_dir,
                    config=config,
                    calls=calls,
                    operation_tag=tag,
                    registered_tags=adapter_tags,
                    tagged_calls=tagged_calls,
                )

            def contender(label: str, config_path: Path) -> None:
                try:
                    args = build_parser().parse_args([
                        "ingest", "--operation-id", operation_id,
                        "--config", str(config_path),
                        "--data-home", str(self.root),
                    ])
                    out, err = io.StringIO(), io.StringIO()
                    code = _ingest_command(args, out=out, err=err)
                    with lock:
                        results[label] = (code, out.getvalue(), err.getvalue())
                except BaseException as exc:  # explicit capture, never silent
                    with lock:
                        failures.append(exc)

            winner_thread = threading.Thread(
                target=contender, args=("winner", config_a)
            )
            loser_thread = threading.Thread(
                target=contender, args=("loser", config_b)
            )
            with mock.patch(
                "market_aligner.collectors.engine.load_adapter", side_effect=factory
            ), mock.patch.object(
                JobDatabase, "source_due", autospec=True, return_value=True
            ):
                winner_thread.start()
                loser_thread.start()
                winner_thread.join(30)
                loser_thread.join(30)

            # Explicit thread-failure authority.
            self.assertEqual([], failures, race_index)
            self.assertFalse(winner_thread.is_alive(), race_index)
            self.assertFalse(loser_thread.is_alive(), race_index)
            total_commands += 2

            codes = sorted(code for code, _out, _err in results.values())
            self.assertEqual([0, 2], codes, race_index)
            # Do not assume which contender wins: identify by exit code.
            ok_payloads = [
                json.loads(out)
                for code, out, _err in results.values()
                if code == 0
            ]
            refusals = [
                json.loads(
                    [
                        line
                        for line in err.splitlines()
                        if line.strip().startswith("{")
                    ][-1]
                )
                for code, _out, err in results.values()
                if code == 2
            ]
            self.assertEqual(1, len(ok_payloads))
            self.assertEqual(1, len(refusals))
            refusal = refusals[0]
            self.assertEqual("binding_source_scope", refusal["reason"], race_index)
            for _code, _out, err in results.values():
                self.assertNotIn("unsafe_journal_file", err, race_index)
                self.assertNotIn("claim_publication_failed", err, race_index)
            payload = ok_payloads[0]
            self.assertEqual("ok", payload["status"], race_index)
            record = json.loads(
                self.journal.record_path(operation_id).read_text(encoding="utf-8")
            )
            self.assertEqual("completed", record["disposition"])
            self.assertEqual(payload["receipt_id"], record["receipt_id"])
            # Exactly one provider cycle, and the actual adapter instance tag
            # plus the single discovered board must correspond exactly to the
            # successful payload's scope — no subset-only weakening.
            ok_label = next(
                label
                for label, (code, _out, _err) in results.items()
                if code == 0
            )
            expected_tag = (
                f"{operation_id}-a" if ok_label == "winner" else f"{operation_id}-b"
            )
            self.assertEqual({expected_tag}, set(adapter_tags), race_index)
            discovers = [
                (tag, board)
                for tag, kind, board, _detail in tagged_calls
                if kind == "discover"
            ]
            self.assertEqual(1, len(discovers), race_index)
            discover_tag, discover_board = discovers[0]
            self.assertEqual(expected_tag, discover_tag, race_index)
            touched = {call[2] for call in tagged_calls}
            self.assertEqual(set(payload["source_scope"]), touched, race_index)
            self.assertEqual([discover_board], sorted(touched), race_index)
            self.assertEqual(
                [], list(self.journal_root.glob(f".claim-{operation_id}-*"))
            )
            # Reset per-race accumulators for the next independent race.
            calls.clear()
            tagged_calls.clear()
            adapter_tags.clear()
            results.clear()
        print(f"stress races executed: {races}; commands: {total_commands}")

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
