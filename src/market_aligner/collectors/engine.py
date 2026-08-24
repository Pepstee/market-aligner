"""Uncapped parallel collector. No LLM or scoring code is imported here."""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from market_aligner.domain.contracts import JobUrl, RawPosting, write_jsonl
from market_aligner.collectors.adapters.base import SourceUnavailable, load_adapter
from market_aligner.state.vacancies import JobDatabase
from market_aligner.collectors.scrapling_client import ScraplingClient, ScraplingFetchError


def _raw_path(base: Path, row: RawPosting) -> Path:
    safe = row.job_id.replace("/", "_").replace(":", "_")
    return base / row.board / f"{safe}.json"


def bounded_relative_path(root: Path, value: Any, field: str) -> Path:
    """Resolve one configured path strictly inside ``root``; canonical seam.

    Rejects absolute values, any upward ``..`` traversal and existing symlink
    components that would escape the data home. Used for every consequential
    configured collector location so a configuration cannot make collection
    state land outside the operator's explicit data home.
    """
    if isinstance(value, Path):
        candidate = str(value)
    elif isinstance(value, str):
        candidate = value
    else:
        raise ValueError(f"shape: {field} must be a path string")
    if not candidate:
        raise ValueError(f"shape: {field} must not be empty")
    relative = Path(candidate)
    if relative.is_absolute():
        raise ValueError(
            f"escape: {field} must stay inside the data home; got absolute {candidate!r}"
        )
    if any(part == ".." for part in relative.parts):
        raise ValueError(
            f"escape: {field} must not traverse outside the data home: {candidate!r}"
        )
    current = Path(os.path.realpath(root))
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(
                f"escape: {field} escapes the data home via symlink component {part!r}: "
                f"{candidate!r}"
            )
    return current


def _shape(condition: bool, message: str) -> None:
    """Raise a stable typed-shape error for malformed configuration."""
    if not condition:
        raise ValueError(f"shape: {message}")


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


class Collector:
    """Uncapped parallel collector with durable resume state and fair fetching."""

    def __init__(self, cfg: dict[str, Any], data_root: Path, log=print) -> None:
        self.cfg, self.root, self.log = cfg, Path(data_root), log
        plan = self.plan(self.root, cfg)
        self.urls_path = plan["job_urls"]
        self.raw_cache = plan["raw_cache"]
        self.db = JobDatabase(plan["database"])
        self.raw_cache_roots = plan["raw_cache_roots"]
        self.terms = list(cfg.get("search_terms") or [])
        self.boards = plan["boards"]
        collection = plan["collection"]
        self.source_workers = int(collection.get("source_workers", len(self.boards) or 1))
        self.fetch_workers = int(collection.get("fetch_workers", 12))
        scrapling = plan["scrapling"]
        self.scrapling = (
            ScraplingClient(plan["runtime_root"], scrapling)
            if scrapling.get("enabled", False)
            else None
        )

    @staticmethod
    def plan(root: Path, cfg: dict[str, Any]) -> dict[str, Any]:
        """Validate configuration shapes and bound every consequential path.

        Shared by :meth:`__init__` and preflight callers so malformed shapes
        and data-home escapes are refused once, in the canonical collector
        seam, before any journal, directory creation or provider access.
        Shape errors carry a ``shape:`` prefix; boundary violations carry
        ``escape:`` so callers can emit stable structured refusals.
        """
        root = Path(root)
        _shape(isinstance(cfg, dict), "configuration root must be a mapping")
        io = cfg.get("io")
        if io is None:
            io = {}
        _shape(isinstance(io, dict), "io must be a mapping")
        collection = cfg.get("collection")
        if collection is None:
            collection = {}
        _shape(isinstance(collection, dict), "collection must be a mapping")

        boards_cfg = cfg.get("boards")
        _shape(isinstance(boards_cfg, dict), "boards must be a mapping")
        enabled = boards_cfg.get("enabled")
        _shape(
            isinstance(enabled, list) and not isinstance(enabled, (str, bytes)) and bool(enabled),
            "boards.enabled must be a nonempty list",
        )
        for index, board in enumerate(enabled):
            _shape(
                isinstance(board, str) and bool(board.strip()) and len(board) <= 128,
                f"boards.enabled[{index}] must be a bounded nonempty string",
            )
        _shape(
            len(set(enabled)) == len(enabled),
            "boards.enabled must not contain duplicate boards",
        )

        legacy_roots = io.get("raw_cache_roots")
        if legacy_roots is None or legacy_roots == []:
            raw_cache_roots = None
        else:
            _shape(
                isinstance(legacy_roots, list) and not isinstance(legacy_roots, (str, bytes)),
                "io.raw_cache_roots must be a JSON list of relative path strings",
            )
            for index, entry in enumerate(legacy_roots):
                _shape(
                    isinstance(entry, str) and bool(entry),
                    f"io.raw_cache_roots[{index}] must be a non-empty relative path string",
                )
            raw_cache_roots = [
                bounded_relative_path(root, entry, f"io.raw_cache_roots[{index}]")
                for index, entry in enumerate(legacy_roots)
            ]

        scrapling = cfg.get("scrapling")
        if scrapling is None:
            scrapling = {}
        _shape(isinstance(scrapling, dict), "scrapling must be a mapping")
        runtime_root_value = scrapling.get("runtime_root")
        runtime_root = (
            bounded_relative_path(root, runtime_root_value, "scrapling.runtime_root")
            if runtime_root_value
            else root
        )

        for board in enabled:
            board_config = cfg.get(board)
            _shape(
                board_config is None or isinstance(board_config, dict),
                f"configuration for enabled board {board!r} must be a mapping",
            )

        return {
            "job_urls": bounded_relative_path(
                root, io.get("job_urls", "state/job_urls.jsonl"), "io.job_urls"
            ),
            "raw_cache": bounded_relative_path(
                root, io.get("raw_cache", "raw/vacancies"), "io.raw_cache"
            ),
            "database": bounded_relative_path(
                root, io.get("database", "state/vacancies.sqlite3"), "io.database"
            ),
            "raw_cache_roots": raw_cache_roots,
            "runtime_root": runtime_root,
            # Canonical source scope: sorted unique, produced exactly once here
            # and consumed unchanged by CLI bindings, per-board locks, journal
            # receipts and the collector's own board loop.
            "boards": sorted({str(board) for board in enabled}),
            "collection": collection,
            "scrapling": scrapling,
        }

    @staticmethod
    def bounded_paths(root: Path, cfg: dict[str, Any]) -> dict[str, Any]:
        """Backward-compatible view over :meth:`plan` (paths only)."""
        return Collector.plan(root, cfg)

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
        roots = self.raw_cache_roots if self.raw_cache_roots else [self.raw_cache]
        added, fetched = self.db.import_existing_roots(self.urls_path, roots)
        if added or fetched:
            self.log(f"[migrate] preserved {added} discovered and {fetched} fetched legacy rows")

    def _discover_board(self, board: str) -> tuple[str, Any, list[JobUrl], Exception | None]:
        adapter = load_adapter(board, config=dict(self.cfg.get(board, {}) or {}))
        rows: list[JobUrl] = []
        try:
            for row in adapter.discover(self.terms, live=True):
                rows.append(row)
        except SourceUnavailable:
            raise
        except Exception as exc:  # preserve pages yielded before a late failure
            return board, adapter, rows, exc
        return board, adapter, rows, None

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

    def run(self, hours: float = 0, poll_minutes: float = 15, once: bool = False) -> None:
        self.migrate_existing()
        started = time.monotonic()
        while True:
            self.cycle()
            if once or (hours > 0 and time.monotonic() - started >= hours * 3600):
                return
            time.sleep(max(1, poll_minutes * 60))
