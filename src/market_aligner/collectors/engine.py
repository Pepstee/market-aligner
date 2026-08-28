"""Uncapped parallel collector. No LLM or scoring code is imported here."""

from __future__ import annotations

import json
import hashlib
import os
import secrets
import stat
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
    VacancyRefreshIndeterminate,
    raw_posting_bytes,
    raw_posting_content_sha256,
    raw_posting_from_bytes,
)
from market_aligner.collectors.scrapling_client import ScraplingClient, ScraplingFetchError


def bounded_relative_path(root: Path, value: Any, field: str) -> Path:
    """Resolve one configured path strictly inside ``root``."""
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


def _open_absolute_directory_no_symlinks(path: Path) -> int:
    """Open every absolute path component with O_NOFOLLOW."""

    absolute = path.absolute()
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_private_directory(parent: int, name: str, *, create: bool) -> int:
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
    except FileNotFoundError:
        if not create:
            raise VacancyRefreshConflict(f"refresh object directory is unavailable: {name}")
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        try:
            descriptor = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
        except OSError as exc:
            raise VacancyRefreshConflict(
                f"refresh object directory is unsafe: {name}"
            ) from exc
    except OSError as exc:
        raise VacancyRefreshConflict(
            f"refresh object directory is unsafe: {name}"
        ) from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        os.close(descriptor)
        raise VacancyRefreshConflict(f"refresh object directory ownership differs: {name}")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        try:
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
        except OSError as exc:
            os.close(descriptor)
            raise VacancyRefreshConflict(
                f"refresh object directory cannot be made private: {name}"
            ) from exc
    return descriptor


def _open_refresh_object_bucket(root: Path, digest: str, *, create: bool) -> int:
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise VacancyRefreshConflict("refresh object filename is not a SHA-256")
    try:
        root_descriptor = _open_absolute_directory_no_symlinks(root)
    except OSError as exc:
        raise VacancyRefreshConflict("external data root contains a symlink or is unavailable") from exc
    descriptors = [root_descriptor]
    try:
        state = os.open(
            "state", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
        descriptors.append(state)
        objects = _open_private_directory(state, "collection-refresh-objects", create=create)
        descriptors.append(objects)
        bucket = _open_private_directory(objects, digest[:2], create=create)
        descriptors.append(bucket)
        return os.dup(bucket)
    except VacancyRefreshConflict:
        raise
    except OSError as exc:
        raise VacancyRefreshConflict("refresh object ancestor is unsafe") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_checked_object(descriptor: int, digest: str) -> bytes:
    try:
        handle = os.open(
            digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor
        )
    except OSError as exc:
        raise VacancyRefreshConflict("refresh response object is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(handle)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise VacancyRefreshConflict("refresh response object metadata is unsafe")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(handle, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        value = b"".join(chunks)
    finally:
        os.close(handle)
    if hashlib.sha256(value).hexdigest() != digest:
        raise VacancyRefreshConflict("refresh response object hash differs from filename")
    return value


def _write_refresh_object(root: Path, digest: str, value: bytes) -> None:
    """Write an owner-private CAS object through descriptor-relative operations."""

    if hashlib.sha256(value).hexdigest() != digest:
        raise VacancyRefreshConflict("refresh response bytes differ from object filename")
    bucket = _open_refresh_object_bucket(root, digest, create=True)
    temporary = f".{digest}.{secrets.token_hex(12)}.tmp"
    try:
        try:
            existing = _read_checked_object(bucket, digest)
        except VacancyRefreshConflict as exc:
            try:
                os.stat(digest, dir_fd=bucket, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise exc
        else:
            if existing != value:
                raise VacancyRefreshConflict("content-addressed refresh object differs")
            return
        handle = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=bucket,
        )
        try:
            view = memoryview(value)
            while view:
                written = os.write(handle, view)
                view = view[written:]
            os.fsync(handle)
        finally:
            os.close(handle)
        os.replace(temporary, digest, src_dir_fd=bucket, dst_dir_fd=bucket)
        os.fsync(bucket)
        if _read_checked_object(bucket, digest) != value:
            raise VacancyRefreshConflict("materialized refresh object differs")
    finally:
        try:
            os.unlink(temporary, dir_fd=bucket)
        except FileNotFoundError:
            pass
        os.close(bucket)


def _read_refresh_object(root: Path, digest: str) -> bytes:
    bucket = _open_refresh_object_bucket(root, digest, create=False)
    try:
        return _read_checked_object(bucket, digest)
    finally:
        os.close(bucket)


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


def _verify_refresh_objects(root: Path, transition: Mapping[str, object]) -> None:
    """Verify journal bytes, content-address filenames, and sealed path claims."""

    old_sha = str(transition["old_object_sha256"])
    old_path = Path("state") / "collection-refresh-objects" / old_sha[:2] / old_sha
    old_bytes = _read_refresh_object(root, old_sha)
    if old_bytes != transition["old_raw_bytes"] or hashlib.sha256(old_bytes).hexdigest() != old_sha:
        raise VacancyRefreshConflict("journalled old response object bytes differ")

    if transition["status"] in ("object_ready", "committed"):
        new_sha = str(transition["new_object_sha256"])
        new_bytes = _read_refresh_object(root, new_sha)
        if (
            new_bytes != transition["new_raw_bytes"]
            or hashlib.sha256(new_bytes).hexdigest() != new_sha
        ):
            raise VacancyRefreshConflict("journalled new response object bytes differ")
    if transition["status"] == "committed":
        receipt = transition["receipt_basis"]
        if not isinstance(receipt, dict):
            raise VacancyRefreshConflict("committed refresh lacks a receipt basis")
        if receipt.get("old_raw_object_path") != str(old_path):
            raise VacancyRefreshConflict("sealed old response object path differs")
        new_sha = str(transition["new_object_sha256"])
        expected_new = str(
            Path("state") / "collection-refresh-objects" / new_sha[:2] / new_sha
        )
        if receipt.get("new_raw_object_path") != expected_new:
            raise VacancyRefreshConflict("sealed new response object path differs")


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
        operation_context: Mapping[str, object],
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
            if old_raw.key != job_key:
                raise ValueError("old raw-cache response differs from SQLite vacancy")
            transition = self.db.begin_vacancy_refresh(
                refresh_id=refresh_id,
                operation_id=operation_id,
                context_sha256=context_sha256,
                context_document=operation_context,
                job_key=job_key,
                expected_content_sha256=expected_content_sha256,
                started_at=started_at,
                old_raw_bytes=old_raw_bytes,
            )

        old_object_sha256 = str(transition["old_object_sha256"])
        _write_refresh_object(
            self.root, old_object_sha256, bytes(transition["old_raw_bytes"])
        )
        _verify_refresh_objects(self.root, transition)

        fetch_claimed = False
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
            self.db.start_vacancy_refresh_fetch(refresh_id)
            transition = self.db.refresh_transition(
                operation_id, context_sha256=context_sha256
            )
            assert transition is not None and transition["status"] == "fetch_started"
            _verify_refresh_objects(self.root, transition)
            fetch_claimed = True

        if transition["status"] == "fetch_started":
            if not fetch_claimed:
                self.db.mark_vacancy_refresh_indeterminate(refresh_id)
                raise VacancyRefreshIndeterminate(
                    "official fetch outcome is indeterminate; automatic refetch is forbidden"
                )
            try:
                raw = adapter.fetch(job, True)
            except BaseException:
                self.db.mark_vacancy_refresh_indeterminate(refresh_id)
                raise
            # External I/O and SQLite cannot share one atomic transaction. A
            # crash here leaves fetch_started, and replay must fail closed.
            self.crash_injector("after_fetch_before_persist")
            if raw.key != job_key or raw.board != job.board or raw.job_id != job.job_id:
                self.db.mark_vacancy_refresh_indeterminate(refresh_id)
                raise ValueError(f"adapter returned a different vacancy identity: {raw.key}")
            self.db.record_vacancy_refresh_fetch(
                refresh_id,
                new_raw_bytes=raw_posting_bytes(raw),
            )
            transition = self.db.refresh_transition(
                operation_id, context_sha256=context_sha256
            )
            assert transition is not None
            _verify_refresh_objects(self.root, transition)

        if transition["status"] == "indeterminate":
            raise VacancyRefreshIndeterminate(
                "official fetch outcome is indeterminate; automatic refetch is forbidden"
            )

        if transition["status"] == "fetched":
            self.crash_injector("before_object")
            new_raw_bytes = bytes(transition["new_raw_bytes"])
            new_object_sha256 = str(transition["new_object_sha256"])
            _write_refresh_object(self.root, new_object_sha256, new_raw_bytes)
            self.db.mark_vacancy_refresh_object_ready(
                refresh_id,
                object_sha256=new_object_sha256,
            )
            transition = self.db.refresh_transition(
                operation_id, context_sha256=context_sha256
            )
            assert transition is not None
            _verify_refresh_objects(self.root, transition)

        if transition["status"] == "object_ready":
            _verify_refresh_objects(self.root, transition)
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
            _verify_refresh_objects(self.root, transition)
            self.crash_injector("after_cas_pre_cache")
        else:
            sealed_value = transition.get("receipt_basis")
            if transition["status"] != "committed" or not isinstance(sealed_value, dict):
                raise VacancyRefreshConflict("refresh journal has no recoverable terminal state")
            sealed = sealed_value
            _verify_refresh_objects(self.root, transition)

        new_raw_bytes = bytes(transition["new_raw_bytes"])
        new_raw = raw_posting_from_bytes(new_raw_bytes)
        _current_job, current_content, current_fetched_at = self.db.fetched_posting(job_key)
        if (
            current_content != transition["new_content_sha256"]
            or current_fetched_at != transition["new_fetched_at"]
        ):
            raise VacancyRefreshConflict("committed refresh has been superseded")
        raw_path = _raw_path(self.raw_cache, new_raw)
        if sealed.get("raw_cache_path") != str(raw_path.relative_to(self.root)):
            raise VacancyRefreshConflict("sealed raw-cache path differs from vacancy identity")
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
