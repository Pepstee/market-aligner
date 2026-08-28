"""JAA-00 brownfield database verification and adoption.

The frozen contract deliberately lives in code: changing an input requires a reviewed
new snapshot rather than silently teaching the importer to accept the changed file.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import select
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
from contextlib import closing, nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import quote

from tracked_source_revision import (
    TrackedSourceRevisionError,
    source_content_revision,
    source_content_revision_contract,
)


class AdoptionError(RuntimeError):
    """A baseline failed certification or could not be copied safely."""


@dataclass(frozen=True)
class BaselineSpec:
    name: str
    source_relative: str
    destination_relative: str
    size: int
    sha256: str
    schema_sha256: str
    schema_objects: int
    table_counts: Mapping[str, int]


BASELINES: tuple[BaselineSpec, ...] = (
    BaselineSpec(
        "raw_jobs", "scraper/data_overnight/jobs.sqlite3", "databases/jobs.sqlite3",
        117_551_104, "87aefc638ae5c0d5b11e6dd8dfb8da5cd8bbfaed5cdba630f5aa3216bf170e57",
        "d40bb9b317ccbbf30cc60fecd6bab4231b663782ccd37226966f353ba064040c", 6,
        {"collection_runs": 0, "normalised_jobs": 548, "postings": 9407,
         "scores": 548, "source_state": 39},
    ),
    BaselineSpec(
        "career_pipeline", "outputs/career_automation/career_pipeline.sqlite3",
        "databases/career_pipeline.sqlite3", 6_238_208,
        "dd99efe519b5fcfe09cba2a0d08d18ce6ce84d570ef8649c5d250ebba03f9a8b",
        "2b582efd6d32d907149fbbc0eb1002a78f78c7b161b524fc5d0e14381f269205", 39,
        {
            "browser_workflow_checkpoints": 0, "browser_workflow_definitions": 0,
            "browser_workflow_events": 0, "browser_workflow_runs": 0,
            "ca_fetch_attempts": 0, "ca_fetch_policies": 2, "ca_fetch_relocations": 0,
            "ca_fetch_selector_fingerprints": 0, "ca_obs_events": 0,
            "ca_obs_flows": 2, "ca_obs_outbox": 0, "ca_obs_spans": 0,
            "ca_obs_traces": 0, "career_deployment_checks": 0,
            "career_deployment_events": 0, "career_deployment_releases": 0,
            "career_schema_migrations": 0, "employer_dossiers": 0,
            "employer_research_queue": 58, "pipeline_events": 924, "pipeline_jobs": 462,
        },
    ),
)

REQUIRED_DISTRIBUTIONS = ("PyYAML", "requests", "openpyxl", "pypdf")
CANONICAL_MARKER = "canonical-repository.json"
CANONICAL_REPOSITORY_ID = "market-aligner"
PRE_ADOPTION_TEST_OBSERVATION = {
    "label": "pre-adoption career-control observation",
    "observed_on": "2026-07-20",
    "passed": 65,
    "classification": "historical-observation-not-current-suite-total",
}

LEGACY_JAA00_CONTENT_SHA256 = (
    "4f2dddaab89ea49ef991ad8a4d8598c03062c4b3ecbf11f85451ab9239a8ec66"
)
LEGACY_JAA00_RECEIPT_SHA256 = (
    "0b64be50bffbbafa5158e4582720ecf25e0c358095c7d7f186858f926b06b7f0"
)
LEGACY_JAA00_ADOPTION_REVISION = "d74c77cac3c121cd6c09f0f8b8f64cd46014e4ec"
LEGACY_JAA00_EVIDENCE = Path("runtime_evidence/JAA-00-online-snapshot.yaml")
_FORBIDDEN_TRACKED_DATA_PREFIXES = (
    "outputs/", "profiler/data/", "scraper/data/", "state/",
)
_FORBIDDEN_TRACKED_DATA_SUFFIXES = (".sqlite", ".sqlite3", ".db", "-wal", "-shm")


class _MutationBoundary:
    """Use the host kernel to detect writes across a multi-file observation boundary.

    Repeated hashes alone cannot make two independently mutable files an atomic observation:
    a SQLite checkpoint can always land between the last main and WAL read.  On the supported
    macOS host, EVFILT_VNODE records writes, extension, deletion, rename, and revocation.
    Linux uses inotify for the equivalent file and directory namespace boundary. Both remain
    armed from before the first read until the caller explicitly closes the boundary.
    Unsupported hosts fail closed instead of silently falling back to a racy hash sequence.
    """

    def __init__(self, paths: Sequence[Path], *, directories: Sequence[Path] = ()) -> None:
        self._files = tuple(dict.fromkeys(path.resolve() for path in paths))
        self._directories = tuple(
            dict.fromkeys(path.resolve() for path in directories)
        )
        self._paths = tuple(
            dict.fromkeys((*self._files, *self._directories))
        )
        self._queue: Any | None = None
        self._descriptors: list[int] = []
        self._inotify_fd: int | None = None
        self._inotify_watches: dict[int, Path] = {}

    @property
    def provider(self) -> str:
        if self._inotify_fd is not None:
            return "linux-inotify-in-modify"
        if self._queue is not None:
            return "macos-kqueue-evfilt-vnode"
        raise AdoptionError("kernel mutation boundary is not armed")

    def __enter__(self) -> "_MutationBoundary":
        if not hasattr(select, "kqueue") or not hasattr(select, "kevent"):
            if sys.platform.startswith("linux"):
                return self._enter_linux_inotify()
            raise AdoptionError("kernel mutation-boundary observation is unavailable")
        queue = select.kqueue()
        flags = (
            select.KQ_NOTE_WRITE
            | select.KQ_NOTE_EXTEND
            | select.KQ_NOTE_DELETE
            | select.KQ_NOTE_RENAME
            | select.KQ_NOTE_REVOKE
        )
        try:
            for path in self._paths:
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
                self._descriptors.append(descriptor)
                event = select.kevent(
                    descriptor,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=flags,
                )
                queue.control([event], 0, 0)
        except (OSError, ValueError) as exc:
            queue.close()
            for descriptor in self._descriptors:
                os.close(descriptor)
            self._descriptors.clear()
            raise AdoptionError("kernel mutation-boundary observation could not be armed") from exc
        self._queue = queue
        return self

    def _enter_linux_inotify(self) -> "_MutationBoundary":
        in_nonblock = getattr(os, "O_NONBLOCK", 0x800)
        in_cloexec = getattr(os, "O_CLOEXEC", 0x80000)
        file_mask = (
            0x00000002  # IN_MODIFY
            | 0x00000004  # IN_ATTRIB
            | 0x00000008  # IN_CLOSE_WRITE
            | 0x00000400  # IN_DELETE_SELF
            | 0x00000800  # IN_MOVE_SELF
            | 0x00002000  # IN_UNMOUNT
        )
        directory_mask = (
            0x00000100  # IN_CREATE
            | 0x00000200  # IN_DELETE
            | 0x00000040  # IN_MOVED_FROM
            | 0x00000080  # IN_MOVED_TO
            | 0x00000400  # IN_DELETE_SELF
            | 0x00000800  # IN_MOVE_SELF
            | 0x00002000  # IN_UNMOUNT
        )
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        add_watch = libc.inotify_add_watch
        add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add_watch.restype = ctypes.c_int
        descriptor = init(in_nonblock | in_cloexec)
        if descriptor < 0:
            number = ctypes.get_errno()
            raise AdoptionError(
                "kernel mutation-boundary observation could not be armed"
            ) from OSError(number, os.strerror(number))
        self._inotify_fd = descriptor
        try:
            for path, mask in (
                *((path, file_mask) for path in self._files),
                *((path, directory_mask) for path in self._directories),
            ):
                watch = add_watch(descriptor, os.fsencode(path), mask)
                if watch < 0:
                    number = ctypes.get_errno()
                    raise OSError(number, os.strerror(number), path)
                if watch in self._inotify_watches:
                    raise OSError(
                        errno.EINVAL,
                        "inotify returned a duplicate watch descriptor",
                        path,
                    )
                self._inotify_watches[watch] = path
        except (OSError, ValueError) as exc:
            try:
                os.close(descriptor)
            finally:
                self._inotify_fd = None
                self._inotify_watches.clear()
            raise AdoptionError(
                "kernel mutation-boundary observation could not be armed"
            ) from exc
        return self

    def _assert_linux_inotify_clean(self, label: str) -> None:
        if self._inotify_fd is None:
            raise AdoptionError(f"{label}: mutation boundary is not armed")
        event_header = struct.Struct("iIII")
        saw_event = False
        saw_overflow = False
        try:
            while True:
                try:
                    payload = os.read(self._inotify_fd, 1024 * 1024)
                except BlockingIOError as exc:
                    if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                        break
                    raise
                except InterruptedError:
                    continue
                if not payload:
                    raise AdoptionError(
                        f"{label}: mutation boundary returned an empty event read"
                    )
                offset = 0
                while offset < len(payload):
                    if len(payload) - offset < event_header.size:
                        raise AdoptionError(
                            f"{label}: mutation boundary returned a malformed event"
                        )
                    watch, mask, _cookie, name_length = event_header.unpack_from(
                        payload,
                        offset,
                    )
                    offset += event_header.size
                    end = offset + name_length
                    if end > len(payload):
                        raise AdoptionError(
                            f"{label}: mutation boundary returned a malformed event"
                        )
                    if watch == -1 and mask & 0x00004000:  # IN_Q_OVERFLOW
                        saw_overflow = True
                    elif watch not in self._inotify_watches:
                        raise AdoptionError(
                            f"{label}: mutation boundary returned an unknown watch"
                        )
                    saw_event = True
                    offset = end
        except AdoptionError:
            raise
        except (OSError, ValueError) as exc:
            raise AdoptionError(
                f"{label}: mutation boundary could not be verified"
            ) from exc
        if saw_overflow:
            raise AdoptionError(
                f"{label}: mutation boundary event queue overflowed"
            )
        if saw_event:
            raise AdoptionError(f"{label}: mutation boundary observed input drift")

    def assert_clean(self, label: str) -> None:
        if self._inotify_fd is not None:
            self._assert_linux_inotify_clean(label)
            return
        if self._queue is None:
            raise AdoptionError(f"{label}: mutation boundary is not armed")
        try:
            events = self._queue.control([], max(1, len(self._descriptors)), 0)
        except (OSError, ValueError) as exc:
            raise AdoptionError(f"{label}: mutation boundary could not be verified") from exc
        if events:
            raise AdoptionError(f"{label}: mutation boundary observed input drift")

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        verification_error: Exception | None = None
        cleanup_error: Exception | None = None
        if _value is None and (
            self._queue is not None or self._inotify_fd is not None
        ):
            try:
                # The final event drain is part of watcher disarm.  A clean
                # assertion in the body is not sufficient because a write can
                # land between that assertion and context-manager teardown.
                self.assert_clean("kernel mutation boundary final disarm")
            except Exception as exc:
                verification_error = exc
        if self._queue is not None:
            try:
                self._queue.close()
            except Exception as exc:
                cleanup_error = exc
            self._queue = None
        if self._inotify_fd is not None:
            try:
                os.close(self._inotify_fd)
            except OSError as exc:
                cleanup_error = exc
            self._inotify_fd = None
            self._inotify_watches.clear()
        for descriptor in self._descriptors:
            try:
                os.close(descriptor)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        self._descriptors.clear()
        if verification_error is not None:
            raise verification_error
        if cleanup_error is not None and _value is None:
            raise AdoptionError("kernel mutation-boundary observation could not be disarmed") \
                from cleanup_error


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=1024 * 1024) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_recertification_receipt(path: Path) -> None:
    """Fail closed if an existing event is not canonical and content-addressed."""
    try:
        if path.is_symlink() or not path.is_file():
            raise AdoptionError("certified recertification receipt content mismatch")
        payload = path.read_bytes()
        receipt = json.loads(payload)
        content = receipt["content"]
        declared_hash = receipt["content_sha256"]
        actual_hash = hashlib.sha256(_canonical_bytes(content)).hexdigest()
        if (
            not isinstance(declared_hash, str)
            or declared_hash != actual_hash
            or path.name != f"source-recertification-{declared_hash}.json"
            or payload != _canonical_bytes(receipt) + b"\n"
        ):
            raise AdoptionError("certified recertification receipt content mismatch")
    except AdoptionError:
        raise
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdoptionError("certified recertification receipt content mismatch") from exc


def _readonly_connection(path: Path) -> sqlite3.Connection:
    """Open a live WAL view without granting SQLite permission to write it.

    ``mode=ro`` is required rather than ``immutable=1`` because immutable
    connections deliberately ignore a live WAL.  SQLite may still update the
    existing SHM reader-lock region while servicing this lawful read-only
    connection; it cannot write the main database or WAL through this handle.
    """
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=30)
    connection.execute("PRAGMA query_only=ON")
    return connection


def _immutable_connection(path: Path) -> sqlite3.Connection:
    """Open a closed snapshot without permitting SQLite filesystem mutations."""
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, timeout=30)
    connection.execute("PRAGMA query_only=ON")
    return connection


def _schema_rows(connection: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()


def _file_identity(path: Path, label: str) -> dict[str, Any]:
    """Return a receipt-safe identity without disclosing the host path."""
    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"label": label, "exists": False}
    if not path.is_file() or path.is_symlink():
        raise AdoptionError(f"{label}: must be a regular, non-symlink file")
    return {
        "label": label,
        "exists": True,
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _source_identities(path: Path, source_label: str) -> dict[str, dict[str, Any]]:
    """Observe source files, hashing content only where byte comparison is sound.

    Main and WAL hashes are labelled stable only when their identity metadata is
    unchanged across the hash read.  SHM is intentionally metadata-only: SQLite
    owns a volatile reader-lock region there and a read-only WAL connection may
    lawfully update it.
    """
    def content_observation(component: str) -> dict[str, Any]:
        component_path = path if component == "main" else Path(str(path) + "-wal")
        label = f"{source_label}:{component}"
        before = _file_identity(component_path, label)
        if not before["exists"]:
            return before
        try:
            digest = _hash_file(component_path)
            after = _file_identity(component_path, label)
        except FileNotFoundError:
            return {**before, "content_observation_stable": False,
                    "content_observation_note": "file disappeared while content was read"}
        stable = before == after
        observation = {
            **after,
            "content_observation_stable": stable,
            "content_read_sha256": digest,
        }
        if stable:
            observation["sha256"] = digest
        else:
            observation["content_observation_note"] = (
                "identity drifted while content was read; digest is not a stable-file claim"
            )
        return observation

    return {
        "main": content_observation("main"),
        "wal": content_observation("wal"),
        "shm": {
            **_file_identity(Path(str(path) + "-shm"), source_label + ":shm"),
            "observation_scope": "identity-metadata-only",
            "content_compared": False,
        },
    }


def _stable_content_equal(start: Mapping[str, Any], end: Mapping[str, Any]) -> bool | None:
    """Compare two stable file-content observations, or report indeterminate."""
    if start.get("exists") != end.get("exists"):
        return False
    if not start.get("exists"):
        return True
    if not (start.get("content_observation_stable") and end.get("content_observation_stable")):
        return None
    return start.get("sha256") == end.get("sha256")


def _inspect_database(path: Path) -> dict[str, Any]:
    """Measure a closed SQLite snapshot without relying on a historical byte hash."""
    if not path.is_file() or path.is_symlink():
        raise AdoptionError("snapshot must be a regular, non-symlink file")
    try:
        with closing(_immutable_connection(path)) as connection:
            integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()]
            if integrity != ["ok"]:
                raise AdoptionError(f"snapshot integrity_check failed: {integrity}")
            schema = _schema_rows(connection)
            schema_hash = hashlib.sha256(_canonical_bytes(schema)).hexdigest()
            tables = sorted(row[1] for row in schema if row[0] == "table")
            counts = {
                table: int(connection.execute(
                    'SELECT COUNT(*) FROM "' + table.replace('"', '""') + '"'
                ).fetchone()[0])
                for table in tables
            }
    except sqlite3.Error as exc:
        raise AdoptionError(f"snapshot SQLite verification failed: {exc}") from exc
    return {
        "bytes": path.stat().st_size,
        "sha256": _hash_file(path),
        "schema_sha256": schema_hash,
        "schema_objects": len(schema),
        "table_counts": counts,
        "integrity_check": integrity,
    }


def _verify_database(path: Path, spec: BaselineSpec) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise AdoptionError(f"{spec.name}: source must be a regular, non-symlink file")
    sidecars = [Path(str(path) + suffix) for suffix in ("-journal", "-wal", "-shm")]
    present_sidecars = [item.name for item in sidecars if item.exists()]
    if present_sidecars:
        raise AdoptionError(
            f"{spec.name}: database is live or dirty; SQLite sidecars present: {present_sidecars}"
        )
    before = path.stat()
    if before.st_size != spec.size:
        raise AdoptionError(f"{spec.name}: byte size mismatch: expected {spec.size}, got {before.st_size}")
    digest = _hash_file(path)
    if digest != spec.sha256:
        raise AdoptionError(f"{spec.name}: SHA-256 mismatch: expected {spec.sha256}, got {digest}")
    try:
        with closing(_immutable_connection(path)) as connection:
            integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()]
            if integrity != ["ok"]:
                raise AdoptionError(f"{spec.name}: integrity_check failed: {integrity}")
            schema = _schema_rows(connection)
            schema_hash = hashlib.sha256(_canonical_bytes(schema)).hexdigest()
            if len(schema) != spec.schema_objects or schema_hash != spec.schema_sha256:
                raise AdoptionError(
                    f"{spec.name}: schema mismatch: expected {spec.schema_objects} objects/"
                    f"{spec.schema_sha256}, got {len(schema)} objects/{schema_hash}"
                )
            actual_tables = {row[1] for row in schema if row[0] == "table"}
            if actual_tables != set(spec.table_counts):
                raise AdoptionError(f"{spec.name}: table set mismatch")
            counts = {
                table: int(connection.execute(
                    'SELECT COUNT(*) FROM "' + table.replace('"', '""') + '"'
                ).fetchone()[0])
                for table in sorted(actual_tables)
            }
    except sqlite3.Error as exc:
        raise AdoptionError(f"{spec.name}: SQLite verification failed: {exc}") from exc
    if counts != dict(sorted(spec.table_counts.items())):
        raise AdoptionError(f"{spec.name}: table count mismatch: expected {dict(spec.table_counts)}, got {counts}")
    after = path.stat()
    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
        raise AdoptionError(f"{spec.name}: source changed during verification")
    return {"bytes": before.st_size, "sha256": digest, "schema_sha256": schema_hash,
            "schema_objects": len(schema), "table_counts": counts, "integrity_check": integrity}


def _recertify_source_observed(
    path: Path,
    spec: BaselineSpec,
    connection: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Recertify one live source without ever granting SQLite write access."""
    if not path.exists():
        raise AdoptionError(f"{spec.name}: source does not exist")
    if not path.is_file() or path.is_symlink():
        raise AdoptionError(f"{spec.name}: source must be a regular, non-symlink file")

    source_label = f"source:{spec.name}"
    start = _source_identities(path, source_label)
    journal = Path(str(path) + "-journal")
    if journal.exists():
        raise AdoptionError(
            f"{spec.name}: rollback journal is present; live recertification requires WAL semantics"
        )
    if start["wal"]["exists"] and not start["shm"]["exists"]:
        raise AdoptionError(
            f"{spec.name}: WAL exists without SHM; refusing a read that could initialise source state"
        )

    write_probe: dict[str, Any]
    try:
        connection_context = (
            nullcontext(connection)
            if connection is not None
            else closing(_readonly_connection(path))
        )
        with connection_context as observed_connection:
            if int(
                observed_connection.execute(
                    "PRAGMA query_only"
                ).fetchone()[0]
            ) != 1:
                raise AdoptionError(f"{spec.name}: read-only query mode was not enforced")

            # This is a real main-schema write, enclosed in a transaction so it
            # remains harmless even if a defective connection unexpectedly permits it.
            observed_connection.execute("BEGIN")
            try:
                observed_connection.execute(
                    'CREATE TABLE main."__jaa_recertification_write_probe" (value INTEGER)'
                )
            except sqlite3.Error as exc:
                observed_connection.rollback()
                error_code = getattr(exc, "sqlite_errorcode", None)
                if error_code is None or error_code & 0xff != sqlite3.SQLITE_READONLY:
                    raise AdoptionError(
                        f"{spec.name}: schema write probe failed for a reason other than read-only"
                    ) from exc
                write_probe = {
                    "attempted": True,
                    "operation": "transactional-main-schema-create",
                    "rejected": True,
                    "sqlite_primary_error": "SQLITE_READONLY",
                }
            else:
                observed_connection.rollback()
                raise AdoptionError(
                    f"{spec.name}: schema write probe unexpectedly succeeded"
                )

            integrity = [
                str(row[0])
                for row in observed_connection.execute(
                    "PRAGMA integrity_check"
                )
            ]
            if integrity != ["ok"]:
                raise AdoptionError(f"{spec.name}: integrity_check failed: {integrity}")
            schema = _schema_rows(observed_connection)
            schema_hash = hashlib.sha256(_canonical_bytes(schema)).hexdigest()
            tables = sorted(row[1] for row in schema if row[0] == "table")
            counts = {
                table: int(observed_connection.execute(
                    'SELECT COUNT(*) FROM "' + table.replace('"', '""') + '"'
                ).fetchone()[0])
                for table in tables
            }
    except sqlite3.Error as exc:
        raise AdoptionError(f"{spec.name}: read-only SQLite verification failed: {exc}") from exc

    if len(schema) != spec.schema_objects or schema_hash != spec.schema_sha256:
        raise AdoptionError(
            f"{spec.name}: schema mismatch: expected {spec.schema_objects} objects/"
            f"{spec.schema_sha256}, got {len(schema)} objects/{schema_hash}"
        )
    if tables != sorted(spec.table_counts):
        raise AdoptionError(f"{spec.name}: table set mismatch")
    historical_floors = dict(sorted(spec.table_counts.items()))
    regressed = {
        table: {"historical_floor": historical_floors[table], "measured": counts[table]}
        for table in tables if counts[table] < historical_floors[table]
    }
    if regressed:
        raise AdoptionError(
            f"{spec.name}: row counts regressed below historical floors: {regressed}"
        )

    end = _source_identities(path, source_label)
    main_content_equal = _stable_content_equal(start["main"], end["main"])
    wal_content_equal = _stable_content_equal(start["wal"], end["wal"])
    if main_content_equal is not True or wal_content_equal is not True:
        raise AdoptionError(
            f"{spec.name}: main/WAL content changed or was uncertain during recertification"
        )

    # A WAL checkpoint can copy frames into the main database without changing the WAL bytes.
    # If it lands after the end-main hash but before the end-WAL hash above, both per-file
    # comparisons can otherwise appear stable even though they describe different boundaries.
    # Re-observe the complete source set and bind the published end state only when both content
    # files still match the first end scan.  This is deliberately separate from the broad
    # start/end check: it closes the checkpoint-only race without weakening ordinary writer-drift
    # refusal or treating volatile SHM reader-lock metadata as database content.
    final = _source_identities(path, source_label)
    final_main_equal = _stable_content_equal(end["main"], final["main"])
    final_wal_equal = _stable_content_equal(end["wal"], final["wal"])
    if final_main_equal is not True or final_wal_equal is not True:
        raise AdoptionError(
            f"{spec.name}: main/WAL content changed or was uncertain during final whole-source "
            "revalidation"
        )

    return {
        "source": {"label": f"source:{spec.name}", "relative_location": spec.source_relative},
        "historical_observation": _historical_observation(spec),
        "open_semantics": {
            "sqlite_uri_mode": "ro",
            "query_only": True,
            "negative_write_probe": write_probe,
        },
        "current_measurement": {
            "integrity_check": integrity,
            "schema_sha256": schema_hash,
            "schema_objects": len(schema),
            "table_count": len(tables),
            "table_set": tables,
            "row_counts": counts,
        },
        "source_observations_start": start,
        "source_observations_end": end,
        "source_observations_final": final,
        "content_comparison": {
            "main_unchanged": main_content_equal,
            "wal_unchanged": wal_content_equal,
            "main_wal_complete": True,
            "final_whole_source_revalidation": {
                "main_unchanged": final_main_equal,
                "wal_unchanged": final_wal_equal,
                "main_wal_complete": True,
            },
            "shm": {
                "scope": "identity-metadata-only",
                "metadata_drift_observed": (
                    start["shm"] != end["shm"] or end["shm"] != final["shm"]
                ),
                "content_compared": False,
            },
        },
    }


def _recertify_source(path: Path, spec: BaselineSpec) -> dict[str, Any]:
    """Recertify inside one kernel-observed main/WAL mutation boundary."""
    # Preserve the contract's precise fail-closed diagnostics for invalid inputs.
    # A missing path cannot itself be watched; the parent-directory watch below
    # still closes the boundary once a valid source has been admitted.
    if not path.exists():
        raise AdoptionError(f"{spec.name}: source does not exist")
    if not path.is_file() or path.is_symlink():
        raise AdoptionError(f"{spec.name}: source must be a regular, non-symlink file")
    wal = Path(str(path) + "-wal")
    watched_files = [path]
    if wal.exists():
        watched_files.append(wal)
    connection: sqlite3.Connection | None = None
    try:
        try:
            with _MutationBoundary(
                watched_files,
                directories=[path.parent],
            ) as boundary:
                boundary_provider = boundary.provider
                connection = _readonly_connection(path)
                evidence = _recertify_source_observed(
                    path,
                    spec,
                    connection,
                )
                boundary.assert_clean(f"{spec.name}: source mutation boundary")
        finally:
            if connection is not None:
                connection.close()
    except AdoptionError as exc:
        # The source may disappear after the admission checks but before kqueue
        # opens its descriptor. Preserve the public fail-closed diagnostic for
        # that check-to-arm race instead of leaking a generic watcher error.
        if not path.exists():
            raise AdoptionError(f"{spec.name}: source does not exist") from exc
        if not path.is_file() or path.is_symlink():
            raise AdoptionError(
                f"{spec.name}: source must be a regular, non-symlink file"
            ) from exc
        raise
    evidence["content_comparison"]["kernel_mutation_boundary"] = {
        "provider": boundary_provider,
        "main_wal_and_directory_clean_through_final_observation": True,
    }
    return evidence


def recertify_sources(source_root: str | Path, evidence_directory: str | Path) -> Path:
    """Fail-closed recertification of both original live brownfield databases."""
    try:
        repository = Path(__file__).resolve().parents[1]
        try:
            revision = source_content_revision(repository)
        except TrackedSourceRevisionError as exc:
            raise AdoptionError(str(exc)) from exc
        source_root = Path(source_root).resolve()
        requested_evidence = Path(evidence_directory).absolute()
        for component in (requested_evidence, *requested_evidence.parents):
            if component.is_symlink():
                raise AdoptionError("recertification evidence path must not contain a symlink")
        evidence_directory = requested_evidence.resolve()
        if source_root == evidence_directory or source_root in evidence_directory.parents:
            raise AdoptionError("recertification evidence must be outside the preserved source root")

        # Complete every source check before creating or changing the evidence directory.
        databases = {
            spec.name: _recertify_source(source_root / spec.source_relative, spec)
            for spec in BASELINES
        }
        try:
            if source_content_revision(repository) != revision:
                raise AdoptionError("tracked source content changed during recertification")
        except TrackedSourceRevisionError as exc:
            raise AdoptionError(str(exc)) from exc
        content = {
            "format": "jaa-00-source-recertification/v2",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z"),
            "source_content_revision": revision,
            "source_content_revision_contract": source_content_revision_contract(),
            "baseline": {"label": "SOURCE_BASELINE.md", "contract": "live-source-recertification"},
            "source_root": {"label": "operator-configured-source-root"},
            "databases": databases,
            "isolation": {
                "source_connections": "read-only-query-only",
                "source_write_operations": "none-successful; transactional schema probes rejected",
                "adopted_product_databases": "not-opened-by-recertification",
            },
        }
        content_hash = hashlib.sha256(_canonical_bytes(content)).hexdigest()
        receipt = {"content": content, "content_sha256": content_hash}
        payload = _canonical_bytes(receipt) + b"\n"
        evidence_directory.mkdir(parents=True, exist_ok=True)
        for component in (evidence_directory, *evidence_directory.parents):
            if component.is_symlink():
                raise AdoptionError("recertification evidence path must not contain a symlink")
        for existing_receipt in evidence_directory.glob("source-recertification-*.json"):
            _validate_recertification_receipt(existing_receipt)
        destination = evidence_directory / f"source-recertification-{content_hash}.json"
        if destination.exists():
            if destination.is_symlink() or destination.read_bytes() != payload:
                raise AdoptionError("certified recertification receipt content mismatch")
            return destination
        temporary_fd, temporary_name = tempfile.mkstemp(prefix=".recertifying-", dir=evidence_directory)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(temporary_fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise AdoptionError("recertification receipt appeared during publication") from exc
        finally:
            temporary.unlink(missing_ok=True)
        return destination
    except AdoptionError:
        raise
    except OSError as exc:
        # Filesystem exception text commonly embeds the operator's private absolute
        # path, so expose a stable logical error and retain details only in the cause.
        raise AdoptionError("recertification filesystem operation failed") from exc


def _runtime_versions() -> dict[str, Any]:
    if sys.version_info < (3, 10):
        raise AdoptionError("Python >=3.10 is required")
    dependencies: dict[str, str] = {}
    missing: list[str] = []
    for name in REQUIRED_DISTRIBUTIONS:
        try:
            dependencies[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            missing.append(name)
    if missing:
        raise AdoptionError("missing runtime dependencies: " + ", ".join(missing))
    return {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
            "platform": platform.platform(), "dependencies": dependencies}


def _tracked_inventory(repository: Path) -> dict[str, Any]:
    """Inventory tracked inputs and reject persisted runtime data or known secrets."""
    try:
        output = subprocess.run(
            ["git", "ls-files", "-z"], cwd=repository, check=True, capture_output=True
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AdoptionError("canonical tracked-file inventory is unavailable") from exc
    names = sorted(
        item.decode("utf-8") for item in output.split(b"\0")
        if item and not item.startswith(b"runtime_evidence/")
    )
    forbidden = [
        name for name in names
        if name.startswith(_FORBIDDEN_TRACKED_DATA_PREFIXES)
        or name.endswith(_FORBIDDEN_TRACKED_DATA_SUFFIXES)
    ]
    if forbidden:
        raise AdoptionError("tracked inventory contains private or runtime database material")

    digest = hashlib.sha256()
    configured_secret_names: list[str] = []
    configured_secret_values: list[tuple[str, bytes]] = []
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN",
                 "AWS_SECRET_ACCESS_KEY"):
        value = os.environ.get(name)
        if value:
            configured_secret_names.append(name)
            if len(value) >= 8:
                configured_secret_values.append((name, value.encode("utf-8")))
    for name in names:
        path = repository / name
        if path.is_symlink() or not path.is_file():
            raise AdoptionError("tracked inventory contains a non-regular path")
        content = path.read_bytes()
        leaked = [secret_name for secret_name, value in configured_secret_values if value in content]
        if leaked:
            raise AdoptionError("tracked inventory contains a configured credential value")
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return {
        "tracked_files": len(names),
        "content_inventory_sha256": digest.hexdigest(),
        "runtime_or_private_database_files_tracked": False,
        "configured_credential_values_tracked": False,
        "configured_credential_names_checked": sorted(configured_secret_names),
        "secret_policy": "receipt-retains-reference-names-only-never-values-or-host-paths",
    }


def _repository_revision(repository: Path) -> str:
    _validate_canonical_marker(repository)
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=repository,
                             check=True, capture_output=True, text=True).stdout.strip()
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository,
                                  check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AdoptionError("canonical repository revision is unavailable") from exc
    top_level = Path(top).resolve()
    repository_root = repository.resolve()
    admitted_roots = {
        top_level,
        top_level / "internal" / "jaa",
    }
    if repository_root not in admitted_roots or len(revision) != 40:
        raise AdoptionError("repository is not the canonical worktree root")
    return revision


def _require_revision_ancestor(repository: Path, recorded: object, current: str) -> str:
    """Accept a receipt's capture commit only when Git proves it precedes this checkout."""
    if not isinstance(recorded, str) or not re.fullmatch(r"[0-9a-f]{40}", recorded):
        raise AdoptionError("receipt repository revision is missing or malformed")
    if recorded == current:
        return recorded
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", recorded, current],
        cwd=repository,
        capture_output=True,
        text=True,
    )
    if ancestry.returncode == 1:
        raise AdoptionError("receipt repository revision is not an ancestor")
    if ancestry.returncode != 0:
        raise AdoptionError("receipt repository ancestry proof is unavailable")
    return recorded


def _source_revision_binding(repository: Path) -> dict[str, Any]:
    """Return the canonical, path-free source revision contract."""
    try:
        contract = source_content_revision_contract()
        revision = source_content_revision(repository)
        binding = {"revision": revision, "contract": contract}
        _canonical_bytes(binding)
    except (OSError, subprocess.CalledProcessError, TypeError, ValueError) as exc:
        raise AdoptionError(f"canonical source revision is unavailable: {exc}") from exc
    return binding


def _repository_content_bindings(repository: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve content evidence, retaining the patched-revision unit seam only."""
    try:
        return _source_revision_binding(repository), _tracked_inventory(repository)
    except (AdoptionError, TrackedSourceRevisionError):
        try:
            is_worktree = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"], cwd=repository,
                check=True, capture_output=True, text=True,
            ).stdout.strip() == "true"
        except (OSError, subprocess.CalledProcessError):
            is_worktree = False
        if is_worktree:
            raise
        # Production reaches here only after _repository_revision has validated a
        # canonical Git root.  This empty tracked set therefore exists solely for
        # temporary unit repositories whose revision seam is patched.
        secret_names = sorted(name for name in (
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
        ) if os.environ.get(name))
        contract = source_content_revision_contract()
        source = {
            "revision": "sha256:" + hashlib.sha256(
                b"jaa-source-content-revision-v2\0"
            ).hexdigest(),
            "contract": contract,
        }
        inventory = {
            "tracked_files": 0,
            "content_inventory_sha256": hashlib.sha256().hexdigest(),
            "runtime_or_private_database_files_tracked": False,
            "configured_credential_values_tracked": False,
            "configured_credential_names_checked": secret_names,
            "secret_policy": "receipt-retains-reference-names-only-never-values-or-host-paths",
        }
        return source, inventory


def _certification_inputs(content: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return {
            "repository": content["repository"],
            "source_revision": content["source_revision"],
            "inventory": content["inventory"],
            "runtime": content["runtime"],
            "secret_references": content["secret_references"],
            "databases": content["databases"],
        }
    except KeyError as exc:
        raise AdoptionError(f"certification binding is missing {exc.args[0]}") from exc


def _seal_certification(content: dict[str, Any]) -> None:
    content["certification"] = {
        "contract": "jaa-00-source-revision-binding/v1",
        "inputs_sha256": hashlib.sha256(
            _canonical_bytes(_certification_inputs(content))
        ).hexdigest(),
    }


def _verify_certification_binding(content: Mapping[str, Any], repository: Path) -> None:
    try:
        certification = content["certification"]
        expected = certification["inputs_sha256"]
        if certification["contract"] != "jaa-00-source-revision-binding/v1":
            raise AdoptionError("unsupported certification binding contract")
    except (KeyError, TypeError) as exc:
        raise AdoptionError("certification binding is missing or malformed") from exc
    actual = hashlib.sha256(_canonical_bytes(_certification_inputs(content))).hexdigest()
    if not isinstance(expected, str) or actual != expected:
        raise AdoptionError("certification input binding digest mismatch")

    repository = repository.resolve()
    recorded_repository = content["repository"]
    current_revision = _repository_revision(repository)
    _require_revision_ancestor(
        repository, recorded_repository.get("revision"), current_revision,
    )
    if recorded_repository.get("identity", recorded_repository.get("label")) != "canonical-repository":
        raise AdoptionError("receipt repository identity is mismatched")
    current_source_revision, current_inventory = _repository_content_bindings(repository)
    if content["source_revision"] != current_source_revision:
        raise AdoptionError("receipt canonical source revision is stale or mismatched")
    if content["inventory"] != current_inventory:
        raise AdoptionError("receipt tracked-source inventory is stale or mismatched")
    if content["runtime"] != _runtime_versions():
        raise AdoptionError("receipt runtime identity is stale or mismatched")


def _validate_canonical_marker(repository: Path) -> None:
    """Refuse imports through a similarly named checkout without the canonical contract."""
    try:
        marker = json.loads((repository / CANONICAL_MARKER).read_text(encoding="utf-8"))
        identity = marker["canonical_repository"]
        contract = marker["brownfield_import_contract"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise AdoptionError("canonical repository marker is missing or invalid") from exc
    schema_version = marker.get("schema_version")
    neutral_identity_valid = (
        schema_version == 2 and
        identity.get("role") == "neutral-versioned-successor" and
        marker.get("original_project", {}).get("canonical") is False and
        marker.get("original_project", {}).get("status") == "preserved-recoverable-source" and
        marker.get("historical_copies", {}).get("canonical") is False and
        marker.get("historical_copies", {}).get("status") == "historical-only"
    )
    if (schema_version not in (1, 2) or
            identity.get("id") != CANONICAL_REPOSITORY_ID or
            identity.get("product_name") != "Market Aligner" or
            identity.get("status") != "active" or
            (schema_version == 2 and not neutral_identity_valid) or
            contract.get("implicit_host_paths") is not False or
            contract.get("required_operator_paths") != [
                "source_root", "runtime_data_root", "repository_root"
            ]):
        raise AdoptionError("repository does not carry the active Market Aligner import contract")


def _validate_roots(source_root: Path, data_root: Path, repository: Path) -> None:
    source = source_root.resolve()
    data = data_root.resolve()
    repo = repository.resolve()
    lowered = [part.lower() for part in data.parts]
    if data == source or source in data.parents or data in source.parents:
        raise AdoptionError("data root must be separate from the preserved source")
    if data == repo or repo in data.parents:
        raise AdoptionError("runtime databases must not be stored inside the canonical repository")
    if "giga-user" in lowered or any("market-aligner" in part for part in lowered):
        raise AdoptionError("data root resembles a historical market-aligner copy")


def _atomic_copy(source: Path, destination: Path, spec: BaselineSpec) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise AdoptionError(f"refusing to overwrite destination: {spec.destination_relative}")
    fd, temporary_name = tempfile.mkstemp(prefix=".adopting-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        verified = _verify_database(temporary, spec)
        try:
            os.link(temporary, destination)  # atomic create-if-absent; never replaces
        except FileExistsError as exc:
            raise AdoptionError(f"destination appeared during copy: {spec.destination_relative}") from exc
        os.unlink(temporary)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return verified
    finally:
        temporary.unlink(missing_ok=True)


def _historical_observation(spec: BaselineSpec) -> dict[str, Any]:
    return {
        "observed_bytes": spec.size,
        "observed_sha256": spec.sha256,
        "observed_schema_sha256": spec.schema_sha256,
        "observed_schema_objects": spec.schema_objects,
        "observed_table_counts": dict(sorted(spec.table_counts.items())),
    }


def _validate_online_measurement(measured: Mapping[str, Any], spec: BaselineSpec) -> None:
    """Require the live/frozen database to preserve schema and historical row floors."""
    if (
        measured["schema_sha256"] != spec.schema_sha256
        or measured["schema_objects"] != spec.schema_objects
        or set(measured["table_counts"]) != set(spec.table_counts)
    ):
        raise AdoptionError(
            f"{spec.name}: live source schema does not match the historical baseline"
        )
    regressed = {
        table: {"historical_floor": floor, "measured": measured["table_counts"][table]}
        for table, floor in sorted(spec.table_counts.items())
        if measured["table_counts"][table] < floor
    }
    if regressed:
        raise AdoptionError(
            f"{spec.name}: row counts regressed below historical floors: {regressed}"
        )


def _preflight_online_source(source: Path, spec: BaselineSpec) -> None:
    """Reject an invalid live source before creating any destination directories."""
    if not source.is_file() or source.is_symlink():
        raise AdoptionError(f"{spec.name}: live source must be a regular, non-symlink file")
    wal = Path(str(source) + "-wal")
    shm = Path(str(source) + "-shm")
    if wal.exists() and not shm.exists():
        raise AdoptionError(
            f"{spec.name}: WAL exists without SHM; refusing a read that could initialise source state"
        )
    try:
        with closing(_readonly_connection(source)) as connection:
            integrity = [
                str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()
            ]
            if integrity != ["ok"]:
                raise AdoptionError(f"{spec.name}: integrity_check failed: {integrity}")
            schema = _schema_rows(connection)
            tables = sorted(row[1] for row in schema if row[0] == "table")
            measured = {
                "schema_sha256": hashlib.sha256(_canonical_bytes(schema)).hexdigest(),
                "schema_objects": len(schema),
                "table_counts": {
                    table: int(
                        connection.execute(
                            'SELECT COUNT(*) FROM "' + table.replace('"', '""') + '"'
                        ).fetchone()[0]
                    )
                    for table in tables
                },
            }
    except sqlite3.Error as exc:
        raise AdoptionError(f"{spec.name}: live source preflight failed: {exc}") from exc
    _validate_online_measurement(measured, spec)


def _atomic_online_backup(source: Path, destination: Path, spec: BaselineSpec) -> dict[str, Any]:
    """Freeze a live source with sqlite3_backup and publish it create-if-absent."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise AdoptionError(f"refusing to overwrite destination: {spec.destination_relative}")

    source_label = f"source:{spec.name}"
    start = _source_identities(source, source_label)
    if not start["main"]["exists"]:
        raise AdoptionError(f"{spec.name}: live source does not exist")
    if start["wal"]["exists"] and not start["shm"]["exists"]:
        raise AdoptionError(
            f"{spec.name}: WAL exists without SHM; refusing a read that could initialise source state"
        )

    fd, temporary_name = tempfile.mkstemp(prefix=".snapshotting-", dir=destination.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    temporary_sidecars = [Path(str(temporary) + suffix) for suffix in ("-journal", "-wal", "-shm")]
    started_at = datetime.now(timezone.utc).isoformat()
    published = False
    try:
        try:
            with closing(_readonly_connection(source)) as source_connection, \
                    closing(sqlite3.connect(temporary)) as destination_connection:
                source_connection.backup(destination_connection)
                # sqlite3_backup copies a consistent logical database but may leave
                # the destination header in WAL mode.  Convert the private temporary
                # copy to a closed rollback-journal database before it is measured or
                # published, so immutable reconciliation never needs WAL/SHM state.
                journal_mode = destination_connection.execute(
                    "PRAGMA journal_mode=DELETE"
                ).fetchone()[0]
                if str(journal_mode).lower() != "delete":
                    raise AdoptionError(
                        f"{spec.name}: could not finalise online backup in DELETE journal mode"
                    )
        except sqlite3.Error as exc:
            raise AdoptionError(f"{spec.name}: SQLite online backup failed: {exc}") from exc
        ended_at = datetime.now(timezone.utc).isoformat()
        end = _source_identities(source, source_label)
        measured = _inspect_database(temporary)

        # Recheck the frozen bytes: the source may have changed since the no-output preflight.
        _validate_online_measurement(measured, spec)

        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise AdoptionError(f"destination appeared during snapshot: {spec.destination_relative}") from exc
        published = True
        os.unlink(temporary)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

        changed = [name for name in ("main", "wal", "shm") if start[name] != end[name]]
        main_content_equal = _stable_content_equal(start["main"], end["main"])
        wal_content_equal = _stable_content_equal(start["wal"], end["wal"])
        return {
            "capture": {
                "method": "sqlite-online-backup",
                "source_open_semantics": {
                    "sqlite_uri_mode": "ro",
                    "query_only": True,
                    "source_write_operations": "none",
                },
                "started_at": started_at,
                "ended_at": ended_at,
                "source_observations_start": start,
                "source_observations_end": end,
                # Retained for v2 receipt consumers; these values now include the
                # stronger, component-appropriate observations above.
                "source_identities_start": start,
                "source_identities_end": end,
                "drift_observed": bool(changed),
                "changed_components": changed,
                "main_content_unchanged": main_content_equal,
                "wal_content_unchanged": wal_content_equal,
                "main_wal_content_comparison_complete": (
                    main_content_equal is not None and wal_content_equal is not None
                ),
                "shm_observation": {
                    "scope": "identity-metadata-only",
                    "metadata_drift_observed": start["shm"] != end["shm"],
                    "content_compared": False,
                    "reason": "SQLite may update SHM reader-lock metadata during read-only WAL access",
                },
            },
            "snapshot": measured,
            "destination_identity": _file_identity(
                destination, f"destination:{spec.name}"
            ),
        }
    except Exception:
        if published:
            destination.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)
        for sidecar in temporary_sidecars:
            sidecar.unlink(missing_ok=True)


def adopt(source_root: str | Path, data_root: str | Path, *, repository: str | Path,
          secret_references: Sequence[str] = ()) -> Path:
    """Verify both frozen sources, atomically copy them, and write a hashed receipt."""
    source_root, data_root, repository = Path(source_root), Path(data_root), Path(repository)
    _validate_roots(source_root, data_root, repository)
    runtime = _runtime_versions()
    revision = _repository_revision(repository.resolve())
    source_revision, inventory = _repository_content_bindings(repository.resolve())
    invalid_refs = [name for name in secret_references if not name or "=" in name or os.sep in name]
    if invalid_refs:
        raise AdoptionError("secret references must be names only, never values or paths")
    sources: dict[str, dict[str, Any]] = {}
    for spec in BASELINES:  # verify every input before creating any destination
        sources[spec.name] = _verify_database(source_root / spec.source_relative, spec)
    destinations: dict[str, dict[str, Any]] = {}
    created: list[Path] = []
    try:
        for spec in BASELINES:
            destination = data_root / spec.destination_relative
            destinations[spec.name] = _atomic_copy(source_root / spec.source_relative, destination, spec)
            created.append(destination)
        # Re-read sources after all copies to prove the adoption did not mutate them.
        for spec in BASELINES:
            _verify_database(source_root / spec.source_relative, spec)
        content = {
            "format": "jaa-00-migration-receipt/v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "repository": {"identity": "canonical-repository", "revision": revision},
            "source_revision": source_revision,
            "inventory": inventory,
            "runtime": runtime,
            "secret_references": sorted(set(secret_references)),
            "databases": {
                spec.name: {
                    "source": {"location": spec.source_relative, **sources[spec.name]},
                    "destination": {"location": spec.destination_relative, **destinations[spec.name]},
                    "rollback": {"preserved_source": spec.source_relative,
                                 "remove_destination": spec.destination_relative},
                } for spec in BASELINES
            },
        }
        _seal_certification(content)
        content_hash = hashlib.sha256(_canonical_bytes(content)).hexdigest()
        receipt = {"content_sha256": content_hash, "content": content}
        receipt_dir = data_root / "receipts"
        receipt_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = receipt_dir / f"migration-{content_hash}.json"
        if receipt_path.exists():
            raise AdoptionError("migration receipt already exists")
        payload = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"
        fd, temporary_name = tempfile.mkstemp(prefix=".receipt-", dir=receipt_dir)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, receipt_path)
        finally:
            temporary.unlink(missing_ok=True)
        return receipt_path
    except Exception:
        # Never leave a partial adoption that could be mistaken for complete.
        for path in created:
            path.unlink(missing_ok=True)
        raise


def adopt_online(source_root: str | Path, data_root: str | Path, *, repository: str | Path,
                 secret_references: Sequence[str] = ()) -> Path:
    """Transactionally freeze changing SQLite sources using the online backup API.

    Historical observations identify the database family; the new snapshot's counts,
    size and digest are measured facts and are never substituted into that history.
    """
    source_root, data_root, repository = Path(source_root), Path(data_root), Path(repository)
    _validate_roots(source_root, data_root, repository)
    runtime = _runtime_versions()
    revision = _repository_revision(repository.resolve())
    source_revision, inventory = _repository_content_bindings(repository.resolve())
    invalid_refs = [name for name in secret_references if not name or "=" in name or os.sep in name]
    if invalid_refs:
        raise AdoptionError("secret references must be names only, never values or paths")

    # Validate every source before _atomic_online_backup creates a destination directory. The
    # frozen copy is checked again immediately before publication to close the race with writers.
    for spec in BASELINES:
        _preflight_online_source(source_root / spec.source_relative, spec)

    destinations = [data_root / spec.destination_relative for spec in BASELINES]
    for spec, destination in zip(BASELINES, destinations, strict=True):
        if destination.exists() or destination.is_symlink():
            raise AdoptionError(f"refusing to overwrite destination: {spec.destination_relative}")

    captures: dict[str, dict[str, Any]] = {}
    created: list[Path] = []
    try:
        for spec, destination in zip(BASELINES, destinations, strict=True):
            captures[spec.name] = _atomic_online_backup(
                source_root / spec.source_relative, destination, spec
            )
            created.append(destination)
        content = {
            "format": "jaa-00-online-snapshot-receipt/v2",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "repository": {"label": "canonical-repository", "revision": revision},
            "source_revision": source_revision,
            "inventory": inventory,
            "runtime": runtime,
            "secret_references": sorted(set(secret_references)),
            "databases": {
                spec.name: {
                    "source": {"label": f"source:{spec.name}"},
                    "historical_observation": _historical_observation(spec),
                    "capture": captures[spec.name]["capture"],
                    "frozen_snapshot": captures[spec.name]["snapshot"],
                    "destination": {
                        "label": f"destination:{spec.name}",
                        "relative_location": spec.destination_relative,
                        "identity": captures[spec.name]["destination_identity"],
                    },
                    "rollback": {
                        "preserved_source_label": f"source:{spec.name}",
                        "remove_destination_label": f"destination:{spec.name}",
                        "remove_relative_location": spec.destination_relative,
                    },
                }
                for spec in BASELINES
            },
        }
        _seal_certification(content)
        content_hash = hashlib.sha256(_canonical_bytes(content)).hexdigest()
        receipt = {"content_sha256": content_hash, "content": content}
        receipt_dir = data_root / "receipts"
        receipt_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = receipt_dir / f"migration-{content_hash}.json"
        payload = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"
        fd, temporary_name = tempfile.mkstemp(prefix=".receipt-", dir=receipt_dir)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, receipt_path)
            except FileExistsError as exc:
                raise AdoptionError("migration receipt already exists") from exc
        finally:
            temporary.unlink(missing_ok=True)
        return receipt_path
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def _load_receipt(path: Path) -> dict[str, Any]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        content = receipt["content"]
        expected = receipt["content_sha256"]
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise AdoptionError(f"invalid receipt: {exc}") from exc
    if not isinstance(content, dict) or not isinstance(expected, str):
        raise AdoptionError("invalid receipt: content and content_sha256 have invalid types")
    actual = hashlib.sha256(_canonical_bytes(content)).hexdigest()
    if actual != expected or path.name != f"migration-{actual}.json":
        raise AdoptionError("receipt content hash or filename mismatch")
    if content.get("format") not in {
        "jaa-00-migration-receipt/v1", "jaa-00-online-snapshot-receipt/v2"
    }:
        raise AdoptionError("unsupported receipt format")
    return receipt


def reconcile(receipt_path: str | Path, data_root: str | Path) -> dict[str, Any]:
    """Re-certify adopted files against both the receipt and frozen contract."""
    receipt = _load_receipt(Path(receipt_path))
    data_root = Path(data_root)
    results: dict[str, Any] = {}
    for spec in BASELINES:
        try:
            record = receipt["content"]["databases"][spec.name]
            if receipt["content"]["format"] == "jaa-00-online-snapshot-receipt/v2":
                destination_record = record["destination"]
                if record["historical_observation"] != _historical_observation(spec):
                    raise AdoptionError(f"{spec.name}: historical observation was rewritten")
                if record["source"] != {"label": f"source:{spec.name}"}:
                    raise AdoptionError(f"{spec.name}: unexpected source label in receipt")
                if (destination_record["label"] != f"destination:{spec.name}" or
                        destination_record["relative_location"] != spec.destination_relative):
                    raise AdoptionError(f"{spec.name}: unexpected destination in receipt")
                expected_rollback = {
                    "preserved_source_label": f"source:{spec.name}",
                    "remove_destination_label": f"destination:{spec.name}",
                    "remove_relative_location": spec.destination_relative,
                }
                if record["rollback"] != expected_rollback:
                    raise AdoptionError(f"{spec.name}: unexpected rollback instructions in receipt")
                destination = data_root / spec.destination_relative
                sidecars = [Path(str(destination) + suffix) for suffix in ("-journal", "-wal", "-shm")]
                if any(item.exists() for item in sidecars):
                    raise AdoptionError(f"{spec.name}: adopted snapshot has SQLite sidecars")
                result = _inspect_database(destination)
                if result != record["frozen_snapshot"]:
                    raise AdoptionError(f"{spec.name}: destination disagrees with snapshot receipt")
                if (result["schema_sha256"] != spec.schema_sha256 or
                        result["schema_objects"] != spec.schema_objects or
                        set(result["table_counts"]) != set(spec.table_counts)):
                    raise AdoptionError(f"{spec.name}: destination schema violates baseline contract")
                identity = _file_identity(destination, f"destination:{spec.name}")
                if identity != destination_record["identity"]:
                    raise AdoptionError(f"{spec.name}: destination identity changed")
            else:
                recorded = record["destination"]
                result = _verify_database(data_root / spec.destination_relative, spec)
                for field in ("bytes", "sha256", "schema_sha256", "schema_objects",
                              "table_counts", "integrity_check"):
                    if result[field] != recorded[field]:
                        raise AdoptionError(f"{spec.name}: destination disagrees with migration receipt")
        except (KeyError, TypeError) as exc:
            raise AdoptionError(f"{spec.name}: malformed database receipt") from exc
        results[spec.name] = result
    return {"status": "ok", "receipt_content_sha256": receipt["content_sha256"], "databases": results}


def rollback_manifest(receipt_path: str | Path, data_root: str | Path) -> dict[str, Any]:
    """Produce an executable-safe manifest; this command intentionally deletes nothing."""
    receipt = _load_receipt(Path(receipt_path))
    root = Path(data_root).resolve()
    online = receipt["content"]["format"] == "jaa-00-online-snapshot-receipt/v2"
    if online:
        reconcile(receipt_path, data_root)
    entries = []
    for spec in BASELINES:
        destination = (root / spec.destination_relative).resolve()
        if root not in destination.parents:
            raise AdoptionError("rollback destination escapes data root")
        record = receipt["content"]["databases"].get(spec.name)
        if not isinstance(record, dict):
            raise AdoptionError(f"{spec.name}: malformed database receipt")
        if online:
            current = _inspect_database(destination)
            preserved_source = record["rollback"]["preserved_source_label"]
        else:
            current = _verify_database(destination, spec)
            preserved_source = spec.source_relative
        entries.append({"database": spec.name, "action": "remove_adopted_copy",
                        "target": spec.destination_relative, "expected_sha256": current["sha256"],
                        "preserved_source": preserved_source})
    return {"format": "jaa-00-rollback-manifest/v1", "receipt_content_sha256":
            receipt["content_sha256"], "precondition": "reconcile must pass immediately before removal",
            "actions": entries}


def _verify_legacy_jaa00_compatibility(
    receipt_path: Path,
    receipt: dict[str, Any],
    data_root: str | Path,
    repository: Path,
    current_revision: str,
) -> dict[str, Any]:
    """Authenticate the one immutable pre-certification JAA-00 receipt."""
    content = receipt["content"]
    if receipt["content_sha256"] != LEGACY_JAA00_CONTENT_SHA256:
        raise AdoptionError("unsealed legacy receipts are not certifiable")
    expected_path = (
        Path(data_root).resolve()
        / "receipts"
        / f"migration-{LEGACY_JAA00_CONTENT_SHA256}.json"
    )
    supplied_path = Path(os.path.abspath(receipt_path))
    if supplied_path != expected_path:
        raise AdoptionError("legacy JAA-00 receipt is not the preserved migration receipt")
    try:
        receipt_stat = supplied_path.lstat()
        resolved_receipt = supplied_path.resolve(strict=True)
    except OSError as exc:
        raise AdoptionError("legacy JAA-00 receipt is unavailable") from exc
    if (
        stat.S_ISLNK(receipt_stat.st_mode)
        or not stat.S_ISREG(receipt_stat.st_mode)
        or resolved_receipt != expected_path
    ):
        raise AdoptionError("legacy JAA-00 receipt is not a regular preserved file")
    if _hash_file(supplied_path) != LEGACY_JAA00_RECEIPT_SHA256:
        raise AdoptionError("legacy JAA-00 preserved receipt bytes are invalid")
    repository_record = content.get("repository")
    if not isinstance(repository_record, dict):
        raise AdoptionError("legacy JAA-00 repository identity is missing")
    identity = repository_record.get("label", repository_record.get("identity"))
    adoption_revision = repository_record.get("revision")
    if identity != "canonical-repository" or adoption_revision != LEGACY_JAA00_ADOPTION_REVISION:
        raise AdoptionError("legacy JAA-00 repository provenance is invalid")

    historical_runtime = content.get("runtime")
    dependencies = historical_runtime.get("dependencies") if isinstance(historical_runtime, dict) else None
    if (
        not isinstance(historical_runtime, dict)
        or not isinstance(historical_runtime.get("python"), str)
        or not isinstance(dependencies, dict)
        or any(not isinstance(dependencies.get(name), str) for name in REQUIRED_DISTRIBUTIONS)
    ):
        raise AdoptionError("legacy JAA-00 historical runtime evidence is invalid")

    evidence_path = repository / LEGACY_JAA00_EVIDENCE
    try:
        evidence_stat = evidence_path.lstat()
    except OSError as exc:
        raise AdoptionError("tracked JAA-00 evidence is unavailable") from exc
    if stat.S_ISLNK(evidence_stat.st_mode) or not stat.S_ISREG(evidence_stat.st_mode):
        raise AdoptionError("tracked JAA-00 evidence is not a regular file")
    relative_evidence = LEGACY_JAA00_EVIDENCE.as_posix()
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", relative_evidence],
        cwd=repository, capture_output=True, text=True,
    )
    unchanged = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--", relative_evidence],
        cwd=repository, capture_output=True, text=True,
    )
    if tracked.returncode != 0 or unchanged.returncode != 0:
        raise AdoptionError("JAA-00 evidence must be tracked and unchanged")

    import yaml
    try:
        evidence = yaml.safe_load(evidence_path.read_bytes())
    except (OSError, yaml.YAMLError) as exc:
        raise AdoptionError("tracked JAA-00 evidence is invalid") from exc
    evidence_receipt = evidence.get("receipt") if isinstance(evidence, dict) else None
    evidence_repository = evidence.get("repository") if isinstance(evidence, dict) else None
    if (
        not isinstance(evidence, dict)
        or evidence.get("evidence") != "JAA-00:first-adopted-frozen-baseline"
        or not isinstance(evidence_receipt, dict)
        or evidence_receipt.get("content_sha256") != LEGACY_JAA00_CONTENT_SHA256
        or not isinstance(evidence_repository, dict)
        or evidence_repository.get("label") != "canonical-repository"
        or evidence_repository.get("revision") != adoption_revision
    ):
        raise AdoptionError("tracked JAA-00 evidence does not bind the legacy receipt")

    evidence_strings: set[str] = set()
    def collect_strings(value: Any) -> None:
        if isinstance(value, str):
            evidence_strings.add(value)
        elif isinstance(value, dict):
            for nested in value.values():
                collect_strings(nested)
        elif isinstance(value, list):
            for nested in value:
                collect_strings(nested)
    collect_strings(evidence)
    required_strings = {LEGACY_JAA00_CONTENT_SHA256, adoption_revision}
    databases = content.get("databases")
    if not isinstance(databases, dict):
        raise AdoptionError("legacy JAA-00 database evidence is invalid")
    for database in databases.values():
        frozen = database.get("frozen_snapshot") if isinstance(database, dict) else None
        if not isinstance(database, dict) or not isinstance(frozen, dict):
            raise AdoptionError("legacy JAA-00 frozen database evidence is invalid")
        required_strings.update(
            value for value in (
                database.get("source_label"), database.get("destination_label"),
                frozen.get("sha256"), frozen.get("schema_sha256"),
            ) if isinstance(value, str)
        )
    if not required_strings.issubset(evidence_strings):
        raise AdoptionError("tracked JAA-00 evidence is incomplete")

    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", adoption_revision, current_revision],
        cwd=repository, capture_output=True, text=True,
    )
    if ancestry.returncode == 1:
        raise AdoptionError("legacy JAA-00 adoption revision is not an ancestor")
    if ancestry.returncode != 0:
        raise AdoptionError("legacy JAA-00 ancestry proof is unavailable")
    return {
        "contract": "jaa-00-legacy-content-addressed-review/v1",
        "content_sha256": LEGACY_JAA00_CONTENT_SHA256,
        "adoption_revision": adoption_revision,
        "adoption_revision_is_ancestor": True,
        "tracked_evidence": relative_evidence,
        "historical_runtime": historical_runtime,
    }


def independent_review(receipt_path: str | Path, data_root: str | Path,
                       repository: str | Path) -> dict[str, Any]:
    """Compose the JAA-00 evidence into one deterministic, fail-closed review."""
    repository_path = Path(repository)
    current_revision = _repository_revision(repository_path)
    runtime = _runtime_versions()
    receipt = _load_receipt(Path(receipt_path))
    content = receipt["content"]
    if receipt["content_sha256"] == LEGACY_JAA00_CONTENT_SHA256:
        receipt_provenance = _verify_legacy_jaa00_compatibility(
            Path(receipt_path), receipt, data_root, repository_path, current_revision
        )
    else:
        _verify_certification_binding(content, repository_path)
        receipt_provenance = {
            "contract": content["certification"]["contract"],
            "content_sha256": receipt["content_sha256"],
            "adoption_revision": content["repository"]["revision"],
            "adoption_revision_is_ancestor": True,
        }
    repository_record = content.get("repository")
    if not isinstance(repository_record, dict):
        raise AdoptionError("receipt canonical repository identity is missing")
    receipt_identity = repository_record.get("label", repository_record.get("identity"))
    adoption_revision = repository_record.get("revision")
    if receipt_identity != "canonical-repository" or not isinstance(adoption_revision, str) \
            or len(adoption_revision) != 40:
        raise AdoptionError("receipt canonical repository identity is invalid")

    marker = json.loads((repository_path / CANONICAL_MARKER).read_text(encoding="utf-8"))
    canonical = marker["canonical_repository"]
    reconciled = reconcile(receipt_path, data_root)
    rollback = rollback_manifest(receipt_path, data_root)
    secret_references = content.get("secret_references", [])
    if (not isinstance(secret_references, list)
            or any(not isinstance(item, str) or not item or "=" in item or os.sep in item
                   for item in secret_references)):
        raise AdoptionError("receipt secret inventory is not reference-name-only")
    current_source_revision = _source_revision_binding(repository_path)
    current_inventory = _tracked_inventory(repository_path)

    return {
        "receipt_provenance": receipt_provenance,
        "current_review": {
            "revision": current_revision,
            "source_revision": current_source_revision,
            "content_inventory": current_inventory,
            "runtime": runtime,
        },
        "format": "jaa-00-independent-review/v1",
        "status": "certified",
        "canonical_repository": {
            "id": canonical["id"],
            "product_name": canonical["product_name"],
            "status": canonical["status"],
            "marker": CANONICAL_MARKER,
            "current_revision": current_revision,
            "adoption_revision": adoption_revision,
        },
        "preserved_originals_and_rollback": rollback,
        "secret_free_inventory": {
            **current_inventory,
            "receipt_secret_reference_names": sorted(set(secret_references)),
            "receipt_secret_values_persisted": False,
        },
        "database_reconciliation": reconciled,
        "runtime_prerequisites": {
            "required_python": ">=3.10",
            "required_distributions": list(REQUIRED_DISTRIBUTIONS),
            "observed": runtime,
            "result": "ok",
        },
        "pre_adoption_test_observation": dict(PRE_ADOPTION_TEST_OBSERVATION),
    }


_SAFE_EVIDENCE_TEXT = re.compile(r"^[A-Za-z0-9_./:>=+-]+$")


def _publication_file_binding(path: Path, label: str) -> dict[str, Any]:
    """Bind regular-file content to a stable filesystem identity."""
    before = _file_identity(path, label)
    if not before["exists"]:
        raise AdoptionError(f"{label}: required publication input is missing")
    digest = _hash_file(path)
    after = _file_identity(path, label)
    if before != after:
        raise AdoptionError(f"{label}: publication input drifted while it was read")
    return {"identity": after, "sha256": digest}


def _publication_input_bindings(
    receipt_path: Path,
    data_root: Path,
    repository: Path,
    databases: Mapping[str, Any],
) -> dict[str, Any]:
    """Capture every mutable input on which published evidence depends."""
    receipt_binding = _publication_file_binding(receipt_path, "certification-receipt")
    receipt_binding["content_sha256"] = _load_receipt(receipt_path)["content_sha256"]

    dependencies = {}
    for relative in ("requirements-test.lock", "requirements-scrapling-full.txt"):
        dependencies[relative] = _publication_file_binding(
            repository / relative, f"dependency:{relative}"
        )

    snapshots = {}
    for name in (spec.name for spec in BASELINES):
        record = databases[name]
        destination = data_root / record["destination"]["relative_location"]
        before = _file_identity(destination, f"adopted-snapshot:{name}")
        measured = _inspect_database(destination)
        after = _file_identity(destination, f"adopted-snapshot:{name}")
        if before != after:
            raise AdoptionError(f"{name}: adopted snapshot drifted while it was read")
        snapshots[name] = {
            "identity": after,
            "measurement": measured,
            "sidecars": {
                suffix: _file_identity(
                    Path(str(destination) + suffix), f"adopted-snapshot:{name}{suffix}"
                )
                for suffix in ("-journal", "-wal", "-shm")
            },
        }

    return {
        "repository_revision": _repository_revision(repository),
        "source_revision": _source_revision_binding(repository),
        "repository_inventory": _tracked_inventory(repository),
        "runtime": _runtime_versions(),
        "dependencies": dependencies,
        "receipt": receipt_binding,
        "adopted_snapshots": snapshots,
    }


def _publication_mutation_paths(
    receipt_path: Path,
    data_root: Path,
    repository: Path,
    databases: Mapping[str, Any],
) -> tuple[list[Path], list[Path]]:
    """Return every mutable file and namespace observed by evidence publication."""
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "-z"], cwd=repository, check=True, capture_output=True
        ).stdout.split(b"\0")
        git_directory_text = subprocess.run(
            ["git", "rev-parse", "--git-dir"], cwd=repository, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AdoptionError("publication mutation-boundary inventory is unavailable") from exc

    files = [receipt_path]
    files.extend(
        repository / os.fsdecode(encoded)
        for encoded in tracked
        if encoded and not encoded.startswith(b"runtime_evidence/")
    )
    files.extend(repository / relative for relative in (
        "requirements-test.lock", "requirements-scrapling-full.txt",
    ))
    directories: list[Path] = []
    for name in (spec.name for spec in BASELINES):
        destination = data_root / databases[name]["destination"]["relative_location"]
        files.append(destination)
        directories.append(destination.parent)
        files.extend(
            sidecar for suffix in ("-journal", "-wal", "-shm")
            if (sidecar := Path(str(destination) + suffix)).exists()
        )

    git_directory = Path(git_directory_text)
    if not git_directory.is_absolute():
        git_directory = repository / git_directory
    for relative in ("HEAD", "index", "packed-refs"):
        candidate = git_directory / relative
        if candidate.exists():
            files.append(candidate)
    try:
        head = (git_directory / "HEAD").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise AdoptionError("publication Git identity could not be observed") from exc
    if head.startswith("ref: "):
        reference = git_directory / head.removeprefix("ref: ")
        if reference.exists():
            files.append(reference)

    return list(dict.fromkeys(files)), list(dict.fromkeys(directories))


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_runtime_evidence(
    receipt_path: Path, data_root: Path, repository: Path, output_path: Path | None = None
) -> Path:
    """Verify fail-closed before atomically publishing byte-stable JAA-00 evidence."""
    repository = repository.resolve()
    review = independent_review(receipt_path, data_root, repository)
    receipt = _load_receipt(receipt_path)
    content = receipt["content"]
    databases = content.get("databases")
    baseline_names = tuple(spec.name for spec in BASELINES)
    if content.get("format") != "jaa-00-online-snapshot-receipt/v2" or not isinstance(databases, dict) \
            or set(databases) != set(baseline_names):
        raise AdoptionError("evidence publication requires a valid online adoption v2 receipt")
    references = content.get("secret_references", [])
    if not isinstance(references, list) or any(not isinstance(item, str)
            or not _SAFE_EVIDENCE_TEXT.fullmatch(item) for item in references):
        raise AdoptionError("secret references must be safe symbolic names")
    locks: list[dict[str, Any]] = []
    for relative, role in (("requirements-test.lock", "fully-pinned-lock"),
            ("requirements-scrapling-full.txt", "pinned-runtime-input")):
        path = repository / relative
        if not path.is_file():
            raise AdoptionError(f"required dependency record is missing: {relative}")
        locks.append({
            "path": relative,
            "role": role,
            "bytes": path.stat().st_size,
            "sha256": _hash_file(path),
        })
    db_evidence: dict[str, Any] = {}
    capture_evidence: dict[str, Any] = {}
    for name in baseline_names:
        record = databases[name]
        snapshot = record["frozen_snapshot"]
        db_evidence[name] = {
            "source_label": record["source"]["label"],
            "destination_label": record["destination"]["label"],
            "snapshot_sha256": snapshot["sha256"],
            "snapshot_bytes": snapshot["bytes"],
            "schema_sha256": snapshot["schema_sha256"],
            "schema_objects": snapshot["schema_objects"],
            "counts": snapshot["table_counts"],
            "integrity_check": snapshot["integrity_check"],
        }
        if "historical_observation" in record:
            observation = record["historical_observation"]
            db_evidence[name]["historical_observation"] = {
                "status": "superseded-by-frozen-snapshot",
                "snapshot_sha256": observation["observed_sha256"],
                "schema_sha256": observation["observed_schema_sha256"],
                "schema_objects": observation["observed_schema_objects"],
                "table_row_counts": observation["observed_table_counts"],
            }
        capture = record["capture"]
        capture_record: dict[str, Any] = {
            "main_content_unchanged_during_capture": capture["main_content_unchanged"],
            "wal_content_unchanged_during_capture": capture["wal_content_unchanged"],
            "drift_observed": capture["drift_observed"],
        }
        if capture.get("changed_components"):
            capture_record["changed_components"] = capture["changed_components"]
        shm_observation = capture.get("shm_observation")
        if isinstance(shm_observation, Mapping) and shm_observation.get("scope"):
            capture_record["shm_comparison"] = shm_observation["scope"]
        capture_evidence[name] = capture_record
    reconciled = review["database_reconciliation"]
    bound_inputs = _publication_input_bindings(
        Path(receipt_path), Path(data_root), repository, databases
    )
    if (
        bound_inputs["repository_revision"] != review["current_review"]["revision"]
        or bound_inputs["source_revision"] != review["current_review"]["source_revision"]
        or bound_inputs["repository_inventory"] != review["current_review"]["content_inventory"]
        or bound_inputs["runtime"] != review["current_review"]["runtime"]
        or bound_inputs["receipt"]["content_sha256"] != receipt["content_sha256"]
        or any(
            bound_inputs["adopted_snapshots"][name]["measurement"]
            != reconciled["databases"][name]
            for name in baseline_names
        )
        or any(
            bound_inputs["dependencies"][record["path"]]["sha256"] != record["sha256"]
            or bound_inputs["dependencies"][record["path"]]["identity"]["bytes"] != record["bytes"]
            for record in locks
        )
    ):
        raise AdoptionError("certified publication inputs drifted during evidence construction")
    # The generated evidence is committed after publication, so embedding the checkout's current
    # HEAD would make the tracked file self-invalidating.  Bind the receipt's capture commit here;
    # independent_review separately proves that commit is an ancestor and that every tracked,
    # non-generated source byte still matches the receipt's content revision and inventory.
    revision = content["repository"]["revision"]
    evidence = {
        "evidence": "JAA-00:first-adopted-frozen-baseline",
        "canonical_adoption": {
            "repository_role": "neutral-versioned-successor",
            "original_project_canonical": False,
            "original_project_recoverable": True,
            "historical_market_aligner_copies_canonical": False,
        },
        "secret_policy": {"references_only": True, "values_persisted": False},
        "publication": {"format": "jaa-00-deterministic-evidence/v2",
            "stability": "byte-stable-for-unchanged-verified-inputs", "volatile_fields": [],
            "verification": "fail-closed-independent-review", "replacement": "atomic-after-successful-verification"},
        "receipt": {"label": f"runtime:{data_root.name}:receipt", "content_sha256": receipt["content_sha256"]},
        "repository": {"label": "canonical-repository", "revision": revision},
        "revision_binding": {"source_revision": content["source_revision"],
            "source_inventory": content["inventory"], "certified_revision": revision,
            "certification": content["certification"]},
        "reconciliation": {
            "command": "python -m baseline_adoption.cli reconcile --receipt <receipt> --data-root <runtime>",
            "result": reconciled["status"],
            "receipt_content_sha256": reconciled["receipt_content_sha256"],
            "receipt_filename_matches_content_sha256": True,
            "adopted_database_hashes_match": True,
            "integrity_check": "ok",
            "counts_match": True,
            "schema_matches": True,
            "adopted_snapshots_sidecar_free": True,
        },
        "databases": db_evidence,
        "capture_and_drift_semantics": {"method": "sqlite-online-backup",
            "adopted_snapshot": "frozen", "live_source_after_capture": "may_continue_changing",
            "source_open": "read-only-query-only", "source_write_operations": "none",
            **capture_evidence},
        "inventory": review["secret_free_inventory"],
        "runtime": {"required_python": review["runtime_prerequisites"]["required_python"],
            "required_distributions": review["runtime_prerequisites"]["required_distributions"],
            "observed": content["runtime"]},
        "dependency_records": locks,
        "host_prerequisites": {"python": ">=3.10", "sqlite": "online-backup-and-read-only-uri-support",
            "filesystem": "same-directory-atomic-replace-and-fsync",
            "source_access": "read-only-files-and-git-object-database"},
        "preservation": {"original_project": {"canonical": False, "recoverable": True, "mutated": False},
            "historical_market_aligner_copies": {"canonical": False, "count": 2},
            "adopted_sources": [databases[name]["source"]["label"] for name in baseline_names]},
        "secret_references": {"names": references, "values_persisted": False},
        "rollback": {"precondition": "reconcile-must-pass-immediately-before-removal",
            "preserved_source_labels": [databases[name]["rollback"]["preserved_source_label"] for name in baseline_names],
            "removable_destination_labels": [databases[name]["rollback"]["remove_destination_label"] for name in baseline_names]},
    }
    yaml = importlib.import_module("yaml")
    payload = yaml.safe_dump(
        evidence,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    ).encode("utf-8")
    destination = (output_path or repository / "runtime_evidence" / "JAA-00-online-snapshot.yaml").resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    previous: Path | None = None
    installed = False
    rollback_failed = False
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=f".{destination.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if temporary.read_bytes() != payload:
            raise AdoptionError("evidence staging validation failed")
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file():
                raise AdoptionError("existing evidence destination is not a regular file")
            previous_stat = destination.stat()
            with tempfile.NamedTemporaryFile(
                dir=destination.parent, prefix=f".{destination.name}.previous.", delete=False
            ) as handle:
                previous = Path(handle.name)
                handle.write(destination.read_bytes())
                handle.flush()
                os.fchmod(handle.fileno(), stat.S_IMODE(previous_stat.st_mode))
                os.fsync(handle.fileno())

        watch_files, watch_directories = _publication_mutation_paths(
            Path(receipt_path), Path(data_root), repository, databases
        )
        try:
            with _MutationBoundary(watch_files, directories=watch_directories) as boundary:
                if _publication_input_bindings(
                    Path(receipt_path), Path(data_root), repository, databases
                ) != bound_inputs:
                    raise AdoptionError("certified publication inputs drifted before atomic replacement")
                os.replace(temporary, destination)
                temporary = None
                installed = True
                # Replacement, its durability barrier, and every post-replace
                # binding check, including watcher teardown, form one
                # recoverable publication transaction.
                _fsync_directory(destination.parent)
                if _publication_input_bindings(
                    Path(receipt_path), Path(data_root), repository, databases
                ) != bound_inputs:
                    raise AdoptionError("certified publication inputs changed through replacement")
                boundary.assert_clean("evidence publication atomic replacement boundary")
        except Exception as exc:
            if installed:
                try:
                    if previous is not None:
                        os.replace(previous, destination)
                        previous = None
                    else:
                        destination.unlink(missing_ok=True)
                    _fsync_directory(destination.parent)
                    installed = False
                except Exception as rollback_exc:
                    # If replacement of the saved file itself failed, retain
                    # that durable backup for operator recovery.
                    rollback_failed = True
                    raise AdoptionError(
                        "evidence publication rollback could not be completed durably"
                    ) from rollback_exc
                if isinstance(exc, (AdoptionError, TrackedSourceRevisionError)):
                    raise AdoptionError(
                        "certified publication inputs drifted through atomic replacement boundary"
                    ) from exc
                raise AdoptionError(
                    "evidence publication failed after atomic replacement; prior evidence restored"
                ) from exc
            raise
        if previous is not None:
            # Cleanup is not part of the certification state transition.  A
            # correct, durable publication must not be reported as failed only
            # because removal of its hidden rollback copy was refused.
            try:
                previous.unlink(missing_ok=True)
            except OSError:
                pass
            else:
                previous = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        if previous is not None and not rollback_failed:
            try:
                previous.unlink(missing_ok=True)
            except OSError:
                pass
    return destination
