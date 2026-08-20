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

    def __init__(
        self,
        cfg: dict[str, Any],
        data_root: Path,
        log=print,
        *,
        adapter_loader=None,
        sleeper=time.sleep,
        monotonic=time.monotonic,
    ) -> None:
        self.cfg, self.root, self.log = cfg, Path(data_root), log
        self.adapter_loader = adapter_loader
        self.sleeper = sleeper
        self.monotonic = monotonic
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
