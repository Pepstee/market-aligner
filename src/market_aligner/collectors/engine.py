"""Uncapped parallel collector. No LLM or scoring code is imported here."""

from __future__ import annotations

import json
import hashlib
import os
import tempfile
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from market_aligner.domain.contracts import JobUrl, RawPosting, write_jsonl
from market_aligner.collectors.adapters.base import SourceUnavailable, load_adapter
from market_aligner.state.vacancies import (
    JobDatabase,
    VacancyRefreshConflict,
    raw_posting_bytes,
    raw_posting_content_sha256,
    raw_posting_from_bytes,
)
from market_aligner.collectors.scrapling_client import ScraplingClient, ScraplingFetchError


def _raw_path(base: Path, row: RawPosting) -> Path:
    safe = row.job_id.replace("/", "_").replace(":", "_")
    return base / row.board / f"{safe}.json"


def _save_raw(base: Path, row: RawPosting) -> None:
    destination = _raw_path(base, row)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    temporary_path = Path(temporary)
    try:
        write_jsonl(temporary_path, [row])
        os.replace(temporary_path, destination)
    finally:
        temporary_path.unlink(missing_ok=True)


def _write_durable_bytes(path: Path, value: bytes) -> None:
    """Atomically materialize exact bytes and fsync file plus parent directory."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != value:
            raise ValueError(f"content-addressed object differs at {path}")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        _fsync_directory_chain(path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def _replace_durable_bytes(path: Path, value: bytes) -> None:
    """Atomically replace convenience materialization and fsync its directory."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        _fsync_directory_chain(path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def _fsync_directory_chain(path: Path) -> None:
    """Persist newly created directory entries through the external data root."""

    current = path.absolute()
    for directory in (current, *current.parents):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if directory == directory.parent:
            break


class Collector:
    """Uncapped parallel collector with durable resume state and fair fetching."""

    def __init__(
        self,
        cfg: dict[str, Any],
        data_root: Path,
        log=print,
        *,
        adapter_loader=None,
        sleeper=time.sleep,
        monotonic=time.monotonic,
        crash_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.cfg, self.root, self.log = cfg, Path(data_root), log
        self.adapter_loader = adapter_loader
        self.sleeper = sleeper
        self.monotonic = monotonic
        self.crash_injector = crash_injector or (lambda _point: None)
        io = cfg.get("io", {}) or {}
        self.urls_path = self.root / io.get("job_urls", "state/job_urls.jsonl")
        self.raw_cache = self.root / io.get("raw_cache", "raw/vacancies")
        self.db = JobDatabase(self.root / io.get("database", "state/vacancies.sqlite3"))
        self.terms = list(cfg.get("search_terms") or [])
        boards = cfg.get("boards", {}) or {}
        self.boards = list(boards.get("enabled") or [])
        collection = cfg.get("collection", {}) or {}
        self.source_workers = int(collection.get("source_workers", len(self.boards) or 1))
        self.fetch_workers = int(collection.get("fetch_workers", 12))
        scrapling = dict(cfg.get("scrapling", {}) or {})
        runtime_setting = Path(scrapling.get("runtime_root") or ".")
        runtime_root = runtime_setting if runtime_setting.is_absolute() else self.root / runtime_setting
        self.scrapling = (
            ScraplingClient(runtime_root, scrapling) if scrapling.get("enabled", False) else None
        )

    def _save_scrapling_failure(self, row: JobUrl, attempts: tuple[dict[str, Any], ...]) -> Path:
        safe = row.job_id.replace("/", "_").replace(":", "_")
        path = self.raw_cache / "_scrapling_failures" / row.board / f"{safe}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "board": row.board,
            "job_id": row.job_id,
            "url": row.url,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "attempts": list(attempts),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _fetch_row(self, adapter: Any, row: JobUrl) -> tuple[RawPosting, str | None]:
        try:
            return adapter.fetch(row, True), None
        except Exception as adapter_error:
            if self.scrapling is None:
                raise
            try:
                result = self.scrapling.fetch_with_chain(row.url)
            except ScraplingFetchError as scrapling_error:
                failure_path = self._save_scrapling_failure(row, scrapling_error.attempts)
                raise RuntimeError(
                    f"adapter failed ({adapter_error!r}); full Scrapling chain failed; "
                    f"complete attempts saved to {failure_path}"
                ) from scrapling_error
            raw = RawPosting(
                board=row.board,
                job_id=row.job_id,
                url=str(result.response.get("url") or row.url),
                fetched_at=datetime.now(timezone.utc).isoformat(),
                raw_text=str(result.response.get("text") or ""),
                raw_json={
                    "_collector": {
                        "primary_adapter_error": repr(adapter_error),
                        "fallback": "scrapling-full",
                        "selected_engine": result.engine,
                    },
                    "_scrapling": {
                        "attempts": list(result.attempts),
                    },
                },
            )
            return raw, result.engine

    def migrate_existing(self) -> None:
        configured = list(((self.cfg.get("io") or {}).get("raw_cache_roots") or ()))
        roots = [self.root / str(path) for path in configured] if configured else [self.raw_cache]
        added, fetched = self.db.import_existing_roots(self.urls_path, roots)
        if added or fetched:
            self.log(f"[migrate] preserved {added} discovered and {fetched} fetched legacy rows")

    def _discover_board(self, board: str) -> tuple[str, Any, list[JobUrl], Exception | None]:
        adapter_loader = self.adapter_loader or load_adapter
        adapter = adapter_loader(board, config=dict(self.cfg.get(board, {}) or {}))
        rows: list[JobUrl] = []
        try:
            for row in adapter.discover(self.terms, live=True):
                rows.append(row)
        except SourceUnavailable:
            raise
        except Exception as exc:  # preserve pages yielded before a late failure
            return board, adapter, rows, exc
        return board, adapter, rows, None

    def refresh_vacancy(
        self,
        job_key: str,
        *,
        expected_content_sha256: str,
        operation_id: str,
        refresh_id: str,
        context_sha256: str,
        started_at: str,
        receipt_context: Mapping[str, object],
        finished_at: Callable[[], str],
    ) -> dict[str, object]:
        """Journal, fetch once, CAS, and reconcile one exact vacancy refresh."""

        transition = self.db.refresh_transition(
            operation_id,
            context_sha256=context_sha256,
        )
        if transition is None:
            job, observed_content_sha256, _old_fetched_at = self.db.fetched_posting(job_key)
            if observed_content_sha256 != expected_content_sha256:
                raise ValueError(
                    f"expected content identity does not match current vacancy: {job_key}"
                )
            if job.board not in self.boards:
                raise ValueError(
                    f"vacancy board is not enabled by collection config: {job.board}"
                )
            old_path = _raw_path(self.raw_cache, RawPosting(
                job.board, job.job_id, job.url, _old_fetched_at
            ))
            if not old_path.is_file():
                raise FileNotFoundError(
                    f"exact old raw-cache response is unavailable: {old_path}"
                )
            old_raw_bytes = old_path.read_bytes()
            old_raw = raw_posting_from_bytes(old_raw_bytes)
            if (
                old_raw.key != job_key
                or raw_posting_content_sha256(old_raw) != expected_content_sha256
            ):
                raise ValueError("old raw-cache response differs from SQLite vacancy")
            transition = self.db.begin_vacancy_refresh(
                refresh_id=refresh_id,
                operation_id=operation_id,
                context_sha256=context_sha256,
                job_key=job_key,
                expected_content_sha256=expected_content_sha256,
                started_at=started_at,
                old_raw_bytes=old_raw_bytes,
            )

        old_object_sha256 = str(transition["old_object_sha256"])
        old_object_path = (
            self.root / "state" / "collection-refresh-objects"
            / old_object_sha256[:2] / old_object_sha256
        )
        _write_durable_bytes(old_object_path, bytes(transition["old_raw_bytes"]))

        if transition["status"] == "intent":
            old_raw = raw_posting_from_bytes(bytes(transition["old_raw_bytes"]))
            job = JobUrl(old_raw.board, old_raw.job_id, old_raw.url)
            if job.board not in self.boards:
                raise ValueError(
                    f"vacancy board is not enabled by collection config: {job.board}"
                )
            adapter_loader = self.adapter_loader or load_adapter
            adapter_config = dict(self.cfg.get(job.board, {}) or {})
            adapter = adapter_loader(job.board, config=adapter_config)
            owns = getattr(adapter, "owns", None)
            if not callable(owns) or not owns(job):
                raise ValueError(
                    f"configured adapter does not own exact vacancy key: {job_key}"
                )
            raw = adapter.fetch(job, True)
            if raw.key != job_key or raw.board != job.board or raw.job_id != job.job_id:
                raise ValueError(f"adapter returned a different vacancy identity: {raw.key}")
            self.db.record_vacancy_refresh_fetch(
                refresh_id,
                new_raw_bytes=raw_posting_bytes(raw),
            )
            transition = self.db.refresh_transition(
                operation_id, context_sha256=context_sha256
            )
            assert transition is not None

        if transition["status"] == "fetched":
            self.crash_injector("before_object")
            new_raw_bytes = bytes(transition["new_raw_bytes"])
            new_object_sha256 = str(transition["new_object_sha256"])
            new_object_path = (
                self.root / "state" / "collection-refresh-objects"
                / new_object_sha256[:2] / new_object_sha256
            )
            _write_durable_bytes(new_object_path, new_raw_bytes)
            self.db.mark_vacancy_refresh_object_ready(
                refresh_id,
                object_sha256=new_object_sha256,
            )
            transition = self.db.refresh_transition(
                operation_id, context_sha256=context_sha256
            )
            assert transition is not None

        if transition["status"] == "object_ready":
            self.crash_injector("after_object_pre_cas")
            new_object_sha256 = str(transition["new_object_sha256"])
            journalled_new = raw_posting_from_bytes(bytes(transition["new_raw_bytes"]))
            raw_cache_path = _raw_path(self.raw_cache, journalled_new)
            basis = {
                **dict(receipt_context),
                "finished_at": finished_at(),
                "started_at": str(transition["started_at"]),
                "new_raw_object_path": str(
                    Path("state") / "collection-refresh-objects"
                    / new_object_sha256[:2] / new_object_sha256
                ),
                "old_raw_object_path": str(
                    Path("state") / "collection-refresh-objects"
                    / old_object_sha256[:2] / old_object_sha256
                ),
                "raw_cache_file_sha256": new_object_sha256,
                "raw_cache_path": str(raw_cache_path.relative_to(self.root)),
            }
            sealed = self.db.seal_vacancy_refresh(
                refresh_id,
                receipt_basis=basis,
            )
            transition = self.db.refresh_transition(
                operation_id, context_sha256=context_sha256
            )
            assert transition is not None and transition["status"] == "committed"
            self.crash_injector("after_cas_pre_cache")
        else:
            sealed_value = transition.get("receipt_basis")
            if transition["status"] != "committed" or not isinstance(sealed_value, dict):
                raise VacancyRefreshConflict("refresh journal has no recoverable terminal state")
            sealed = sealed_value

        new_raw_bytes = bytes(transition["new_raw_bytes"])
        new_raw = raw_posting_from_bytes(new_raw_bytes)
        _current_job, current_content, current_fetched_at = self.db.fetched_posting(job_key)
        if (
            current_content != transition["new_content_sha256"]
            or current_fetched_at != transition["new_fetched_at"]
        ):
            raise VacancyRefreshConflict("committed refresh has been superseded")
        raw_path = _raw_path(self.raw_cache, new_raw)
        _replace_durable_bytes(raw_path, new_raw_bytes)
        self.crash_injector("after_cache_pre_receipt")
        return {**sealed, "raw_cache_path_absolute": str(raw_path)}

    def cycle(self) -> dict[str, int]:
        adapters: dict[str, Any] = {}
        fetch_queue: list[tuple[Any, JobUrl]] = []
        pending_by_board: dict[str, deque[tuple[Any, JobUrl]]] = {}
        discovered = new = errors = 0
        pending = self.db.boards_with_pending_discoveries(self.boards)
        due = [b for b in self.boards if b in pending or self.db.source_due(
            b, float((self.cfg.get(b, {}) or {}).get("minimum_poll_minutes", 15) or 15)
        )]
        if not due:
            self.log("[cycle] no source is due yet")
            return {"seen": 0, "new": 0, "fetched": 0, "errors": 0,
                    "database_total": self.db.stats()["postings"]}
        fetched = 0
        with (
            ThreadPoolExecutor(max_workers=max(1, self.source_workers)) as source_pool,
            ThreadPoolExecutor(max_workers=max(1, self.fetch_workers)) as fetch_pool,
        ):
            futures = {source_pool.submit(self._discover_board, b): b for b in due}
            fetch_futures: dict[Any, JobUrl] = {}
            for future in as_completed(futures):
                board = futures[future]
                try:
                    _, adapter, rows, discovery_error = future.result()
                    adapters[board] = adapter
                    discovered += len(rows)
                    for row in rows:
                        is_new = self.db.upsert_discovered(row)
                        new += int(is_new)
                        if not self.db.has_raw(row.key):
                            pending_by_board.setdefault(board, deque()).append((adapter, row))
                    self.db.mark_source(board, repr(discovery_error) if discovery_error else None)
                    self.log(
                        f"[discover] {board}: {len(rows)} current matches, "
                        f"{len(pending_by_board.get(board, ()))} to fetch"
                    )
                    if discovery_error:
                        errors += 1
                        self.log(f"[discover] {board} ended early after preserving {len(rows)} matches: {discovery_error}")
                except SourceUnavailable as exc:
                    self.db.mark_source(board, str(exc))
                    self.log(f"[discover] {exc}")
                except Exception as exc:  # keep other boards alive
                    errors += 1
                    self.db.mark_source(board, repr(exc))
                    self.log(f"[discover] {board} failed: {exc}")

            # Round-robin the per-board queues before submission. A board with
            # thousands of matches must not occupy the executor's entire FIFO
            # queue while smaller direct national sources wait behind it.
            active = list(pending_by_board)
            while active:
                next_active: list[str] = []
                for board in active:
                    queue = pending_by_board[board]
                    if queue:
                        fetch_queue.append(queue.popleft())
                    if queue:
                        next_active.append(board)
                active = next_active
            for adapter, row in fetch_queue:
                fetch_futures[fetch_pool.submit(self._fetch_row, adapter, row)] = row

            for future in as_completed(fetch_futures):
                row = fetch_futures[future]
                try:
                    raw, fallback_engine = future.result()
                    self.db.store_raw(raw)
                    _save_raw(self.raw_cache, raw)
                    fetched += 1
                    if fallback_engine:
                        self.log(f"[fetch] {row.key} recovered by Scrapling {fallback_engine}")
                    if fetched % 25 == 0:
                        self.log(f"[fetch] {fetched}/{len(fetch_queue)} stored")
                except Exception as exc:
                    errors += 1
                    self.db.record_error(row.key, repr(exc))
                    self.log(f"[fetch] {row.key} failed: {exc}")
        total = self.db.export_urls(self.urls_path)
        result = {"seen": discovered, "new": new, "fetched": fetched, "errors": errors, "database_total": total}
        self.log(f"[cycle] {result}")
        return result

    def run(
        self, hours: float = 0, poll_minutes: float = 15, once: bool = False
    ) -> list[dict[str, int]]:
        if once == (hours > 0):
            raise ValueError("collector requires exactly one of once=True or hours>0")
        if poll_minutes <= 0:
            raise ValueError("poll interval must be positive")
        self.migrate_existing()
        started = self.monotonic()
        deadline = started + hours * 3600 if hours > 0 else None
        cycles: list[dict[str, int]] = []
        while True:
            cycles.append(self.cycle())
            if once:
                return cycles
            assert deadline is not None
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                return cycles
            self.sleeper(min(max(1, poll_minutes * 60), remaining))
