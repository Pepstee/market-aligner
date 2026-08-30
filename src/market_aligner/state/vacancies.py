"""Persistent, append-preserving storage for the collection pipeline."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Mapping

from market_aligner.domain.contracts import (
    JobUrl,
    RawPosting,
    from_dict,
    read_jsonl,
    to_dict,
    write_jsonl,
)
from market_aligner.collectors.evidence import (
    public_listing_bytes,
    validate_public_listing_url,
)
from market_aligner.config_loader import load_config
from market_aligner.config import owner_private_umask
from market_aligner.state.importers import iter_raw_cache_roots


LEGACY_PROCESSING_CONFIG_SHA256 = "0" * 64
POSTING_READ_COLUMNS = (
    "key",
    "board",
    "job_id",
    "url",
    "posted_at",
    "fetched_at",
    "raw_text",
    "raw_json",
    "content_hash",
    "fetch_status",
)


def _reject_nonfinite_json(token: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {token}")


def _strict_json_loads(value: str | bytes | bytearray) -> object:
    return json.loads(value, parse_constant=_reject_nonfinite_json)


class VacancyRefreshConflict(RuntimeError):
    """The exact fetched vacancy changed before a guarded refresh committed."""


class VacancyRefreshIndeterminate(VacancyRefreshConflict):
    """An official fetch may have occurred but no exact response was persisted."""


@dataclass(frozen=True)
class VerifiedVacancyRefreshReceipt:
    """Exact, non-authoritative evidence for one committed collector refresh."""

    job_key: str
    changed: bool
    old_content_sha256: str
    old_canonical_content_sha256: str
    new_content_sha256: str
    old_fetched_at: str
    new_fetched_at: str
    operation_id: str
    refresh_id: str
    context_sha256: str
    transition_sha256: str
    receipt_sha256: str
    receipt_file_sha256: str
    receipt_path: Path
    new_raw_object_sha256: str


@dataclass(frozen=True)
class ResolvedVacancyRefreshCollector:
    """Receipt-bound collector path and the inode pinned during resolution."""

    database: "JobDatabase"
    path: Path
    data_home: Path
    st_dev: int
    st_ino: int
    directory_chain: tuple[tuple[Path, int, int], ...]

    def verify_open_connection(
        self, connection: sqlite3.Connection, *, schema: str = "main"
    ) -> None:
        if schema not in {"main", "collector"}:
            raise VacancyRefreshConflict("collector connection schema is unsupported")
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise VacancyRefreshConflict(
                "configured collector database identity is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_dev != self.st_dev
            or metadata.st_ino != self.st_ino
            or self.path == self.data_home
            or self.data_home not in self.path.parents
        ):
            raise VacancyRefreshConflict(
                "configured collector database inode differs from resolution"
            )
        for directory, expected_dev, expected_ino in self.directory_chain:
            try:
                current = directory.lstat()
            except OSError as exc:
                raise VacancyRefreshConflict(
                    "configured collector database ancestry is unavailable"
                ) from exc
            if (
                not stat.S_ISDIR(current.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or current.st_dev != expected_dev
                or current.st_ino != expected_ino
            ):
                raise VacancyRefreshConflict(
                    "configured collector database ancestry differs from resolution"
                )
        paths = {
            str(row[1]): Path(str(row[2])).absolute()
            for row in connection.execute("PRAGMA database_list")
        }
        opened = paths.get(schema)
        if opened != self.path:
            raise VacancyRefreshConflict(
                "open collector connection path differs from configuration"
            )


@dataclass(frozen=True)
class _LoadedVacancyRefreshReceipt:
    path: Path
    exact_bytes: bytes
    document: dict[str, object]
    sealed_body: dict[str, object]
    receipt_sha256: str


def _read_exact_private_file(path: Path, *, label: str) -> bytes:
    """Read an owner-private regular file without following its final symlink."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise VacancyRefreshConflict(f"{label} is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise VacancyRefreshConflict(f"{label} metadata is unsafe")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_vacancy_refresh_receipt(
    data_home: Path, receipt_path: str | Path
) -> _LoadedVacancyRefreshReceipt:
    expected_directory = data_home / "state" / "collection-refresh-receipts"
    supplied = Path(receipt_path)
    absolute = supplied if supplied.is_absolute() else supplied.absolute()
    if absolute.parent != expected_directory or absolute.name in {"", ".", ".."}:
        raise VacancyRefreshConflict(
            "refresh receipt path is outside the canonical external data home"
        )
    for directory in (data_home, data_home / "state", expected_directory):
        try:
            metadata = directory.lstat()
        except OSError as exc:
            raise VacancyRefreshConflict(
                "refresh receipt ancestor is unavailable"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise VacancyRefreshConflict("refresh receipt ancestor is unsafe")
    receipt_bytes = _read_exact_private_file(absolute, label="refresh receipt")
    try:
        receipt = _strict_json_loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise VacancyRefreshConflict("refresh receipt is not canonical JSON") from exc
    if not isinstance(receipt, dict):
        raise VacancyRefreshConflict("refresh receipt is not an object")
    canonical_receipt = json.dumps(
        receipt,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if canonical_receipt != receipt_bytes:
        raise VacancyRefreshConflict("refresh receipt bytes are not canonical")
    body = dict(receipt)
    receipt_sha256 = body.pop("receipt_sha256", None)
    if not isinstance(receipt_sha256, str) or _canonical_hash(body) != receipt_sha256:
        raise VacancyRefreshConflict("refresh receipt identity differs")
    if absolute.name != f"{receipt_sha256}.json":
        raise VacancyRefreshConflict("refresh receipt filename differs from identity")
    return _LoadedVacancyRefreshReceipt(
        absolute, receipt_bytes, receipt, body, receipt_sha256
    )


def raw_posting_content_sha256(row: RawPosting) -> str:
    """Return the existing collector content identity for a raw posting."""

    if row.public_content_base64 is not None:
        exact_public_bytes = public_listing_bytes(row)
        digest = hashlib.sha256(exact_public_bytes).hexdigest()
        if row.content_sha256 is not None and row.content_sha256 != digest:
            raise ValueError("raw posting digest differs from exact public bytes")
        return digest
    raw_json = json.dumps(row.raw_json, ensure_ascii=False) if row.raw_json is not None else None
    material = (row.raw_text or "") + (raw_json or "")
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def raw_posting_bytes(row: RawPosting) -> bytes:
    """Serialize the exact collector C2 response stored in raw-cache objects."""

    return (
        json.dumps(to_dict(row), ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
    ).encode(
        "utf-8"
    )


def raw_posting_from_bytes(value: bytes) -> RawPosting:
    """Validate and decode one exact collector C2 response object."""

    try:
        text = value.decode("utf-8")
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) != 1:
            raise ValueError("raw response object must contain exactly one JSON record")
        payload = _strict_json_loads(lines[0])
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("raw response object is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("raw response object must be a JSON object")
    try:
        row = from_dict(RawPosting, payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("raw response object does not satisfy the collector schema") from exc
    if raw_posting_bytes(row) != value:
        raise ValueError("raw response object is not in canonical collector encoding")
    return row


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=30000;
CREATE TABLE IF NOT EXISTS postings (
  key TEXT PRIMARY KEY, board TEXT NOT NULL, job_id TEXT NOT NULL, url TEXT NOT NULL,
  posted_at TEXT, first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, fetched_at TEXT,
  raw_text TEXT, raw_json TEXT, content_hash TEXT, fetch_status TEXT NOT NULL DEFAULT 'discovered',
  fetch_error TEXT
);
CREATE INDEX IF NOT EXISTS postings_board_status ON postings(board, fetch_status);
CREATE TABLE IF NOT EXISTS normalised_jobs (
  key TEXT PRIMARY KEY, normalized_json TEXT NOT NULL, normalized_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scores (
  key TEXT PRIMARY KEY, score_json TEXT NOT NULL, scored_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS source_state (
  board TEXT PRIMARY KEY, last_polled_at TEXT, last_error TEXT
);
CREATE TABLE IF NOT EXISTS collection_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TEXT, discovered INTEGER NOT NULL DEFAULT 0, fetched INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS posting_raw_snapshots (
  job_key TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  object_sha256 TEXT NOT NULL,
  exact_raw_bytes BLOB NOT NULL,
  fetched_at TEXT NOT NULL,
  recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(job_key,object_sha256),
  UNIQUE(job_key,content_sha256,object_sha256)
);
CREATE TABLE IF NOT EXISTS posting_raw_snapshot_heads (
  job_key TEXT PRIMARY KEY,
  content_sha256 TEXT NOT NULL,
  object_sha256 TEXT NOT NULL,
  FOREIGN KEY(job_key,content_sha256,object_sha256)
    REFERENCES posting_raw_snapshots(job_key,content_sha256,object_sha256)
    ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS posting_raw_snapshot_migration_blocks (
  job_key TEXT PRIMARY KEY,
  reason_code TEXT NOT NULL,
  legacy_content_hash TEXT,
  detected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER IF NOT EXISTS posting_raw_snapshots_no_update
  BEFORE UPDATE ON posting_raw_snapshots
  BEGIN SELECT RAISE(ABORT,'raw posting snapshots are immutable'); END;
CREATE TRIGGER IF NOT EXISTS posting_raw_snapshots_no_delete
  BEFORE DELETE ON posting_raw_snapshots
  BEGIN SELECT RAISE(ABORT,'raw posting snapshots are immutable'); END;
CREATE TRIGGER IF NOT EXISTS posting_raw_snapshot_migration_blocks_no_update
  BEFORE UPDATE ON posting_raw_snapshot_migration_blocks
  BEGIN SELECT RAISE(ABORT,'raw snapshot migration blocks are immutable'); END;
CREATE TRIGGER IF NOT EXISTS posting_raw_snapshot_migration_blocks_no_delete
  BEFORE DELETE ON posting_raw_snapshot_migration_blocks
  BEGIN SELECT RAISE(ABORT,'raw snapshot migration blocks are immutable'); END;
CREATE TABLE IF NOT EXISTS processing_jobs (
  profile_id TEXT NOT NULL,
  track TEXT NOT NULL,
  job_key TEXT NOT NULL,
  authority_sha256 TEXT NOT NULL,
  source_content_sha256 TEXT NOT NULL,
  processing_config_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('leased','completed','failed')),
  lease_owner TEXT,
  lease_until REAL,
  result_json TEXT,
  error TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(
    profile_id,track,job_key,authority_sha256,source_content_sha256,
    processing_config_sha256
  ),
  FOREIGN KEY(job_key) REFERENCES postings(key) ON DELETE CASCADE
);
"""


VACANCY_REFRESH_SCHEMA = """
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
  old_canonical_content_sha256 TEXT NOT NULL,
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
);
"""


VACANCY_REFRESH_QUARANTINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS vacancy_refresh_migration_quarantine (
  operation_id TEXT PRIMARY KEY,
  refresh_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  expected_content_sha256 TEXT NOT NULL,
  legacy_status TEXT NOT NULL,
  legacy_table TEXT NOT NULL,
  legacy_row_sha256 TEXT NOT NULL,
  reason TEXT NOT NULL,
  quarantined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


LEGACY_VACANCY_REFRESH_COLUMNS = (
    "refresh_id", "operation_id", "context_sha256", "job_key",
    "expected_content_sha256", "status", "started_at", "old_content_sha256",
    "old_fetched_at", "old_raw_bytes", "old_object_sha256",
    "new_content_sha256", "new_fetched_at", "new_raw_bytes",
    "new_object_sha256", "receipt_basis_json", "created_at", "updated_at",
)

V2_VACANCY_REFRESH_COLUMNS = (
    "refresh_id", "operation_id", "context_sha256", "context_json", "job_key",
    "expected_content_sha256", "status", "started_at", "old_content_sha256",
    "old_fetched_at", "old_raw_bytes", "old_object_sha256",
    "new_content_sha256", "new_fetched_at", "new_raw_bytes",
    "new_object_sha256", "receipt_basis_json", "receipt_basis_sha256",
    "transition_sha256", "created_at", "updated_at",
)

CURRENT_VACANCY_REFRESH_COLUMNS = (
    "refresh_id", "operation_id", "context_sha256", "context_json", "job_key",
    "expected_content_sha256", "status", "started_at", "old_content_sha256",
    "old_canonical_content_sha256", "old_fetched_at", "old_raw_bytes",
    "old_object_sha256", "new_content_sha256", "new_fetched_at", "new_raw_bytes",
    "new_object_sha256", "receipt_basis_json", "receipt_basis_sha256",
    "transition_sha256", "created_at", "updated_at",
)


def _canonical_hash(value: object) -> str:
    encoded = _canonical_json_bytes(value)
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _authority_equal(left: object, right: object) -> bool:
    """Compare JSON authorities without Python's bool/int/float coercion."""

    if isinstance(left, bytes) or isinstance(right, bytes):
        return type(left) is type(right) and left == right
    try:
        return _canonical_json_bytes(left) == _canonical_json_bytes(right)
    except (TypeError, ValueError):
        return False


_REFRESH_SELECT = """refresh_id,operation_id,context_sha256,context_json,job_key,
expected_content_sha256,status,started_at,old_content_sha256,
old_canonical_content_sha256,old_fetched_at,old_raw_bytes,old_object_sha256,
new_content_sha256,new_fetched_at,new_raw_bytes,
new_object_sha256,receipt_basis_json,receipt_basis_sha256,transition_sha256"""


def _refresh_transition_document(value: Mapping[str, object]) -> dict[str, object]:
    return {
        "context_sha256": value["context_sha256"],
        "expected_content_sha256": value["expected_content_sha256"],
        "job_key": value["job_key"],
        "new_content_sha256": value["new_content_sha256"],
        "new_fetched_at": value["new_fetched_at"],
        "new_raw_object_sha256": value["new_object_sha256"],
        "old_content_sha256": value["old_content_sha256"],
        "old_canonical_content_sha256": value["old_canonical_content_sha256"],
        "old_fetched_at": value["old_fetched_at"],
        "old_raw_object_sha256": value["old_object_sha256"],
        "operation_id": value["operation_id"],
        "receipt_basis_sha256": value["receipt_basis_sha256"],
        "refresh_id": value["refresh_id"],
        "schema_version": "market-aligner.vacancy-refresh-transition.v2",
        "started_at": value["started_at"],
        "status": value["status"],
    }


def _refresh_transition_from_row(row: sqlite3.Row | tuple[object, ...]) -> dict[str, object]:
    try:
        context = _strict_json_loads(str(row[3]))
        receipt_basis = None if row[17] is None else _strict_json_loads(str(row[17]))
    except (json.JSONDecodeError, ValueError) as exc:
        raise VacancyRefreshConflict("refresh journal JSON is invalid") from exc
    value: dict[str, object] = {
        "refresh_id": str(row[0]),
        "operation_id": str(row[1]),
        "context_sha256": str(row[2]),
        "context": context,
        "job_key": str(row[4]),
        "expected_content_sha256": str(row[5]),
        "status": str(row[6]),
        "started_at": str(row[7]),
        "old_content_sha256": str(row[8]),
        "old_canonical_content_sha256": str(row[9]),
        "old_fetched_at": str(row[10]),
        "old_raw_bytes": bytes(row[11]),
        "old_object_sha256": str(row[12]),
        "new_content_sha256": None if row[13] is None else str(row[13]),
        "new_fetched_at": None if row[14] is None else str(row[14]),
        "new_raw_bytes": None if row[15] is None else bytes(row[15]),
        "new_object_sha256": None if row[16] is None else str(row[16]),
        "receipt_basis": receipt_basis,
        "receipt_basis_sha256": None if row[18] is None else str(row[18]),
        "transition_sha256": None if row[19] is None else str(row[19]),
    }
    _validate_refresh_transition(value)
    return value


def _validate_refresh_transition(value: Mapping[str, object]) -> None:
    context = value["context"]
    if not isinstance(context, dict):
        raise VacancyRefreshConflict("refresh operation context is not an object")
    if _canonical_hash(context) != value["context_sha256"]:
        raise VacancyRefreshConflict("refresh operation context identity differs")
    exact_context_fields = {
        "expected_content_sha256": value["expected_content_sha256"],
        "job_key": value["job_key"],
        "operation_id": value["operation_id"],
        "schema_version": "market-aligner.vacancy-refresh-context.v1",
    }
    if any(
        not _authority_equal(context.get(key), expected)
        for key, expected in exact_context_fields.items()
    ):
        raise VacancyRefreshConflict("refresh operation context differs from journal")
    for key in ("config_sha256", "source_sha256"):
        identity = context.get(key)
        if not isinstance(identity, str) or len(identity) != 64 or any(
            character not in "0123456789abcdef" for character in identity
        ):
            raise VacancyRefreshConflict(f"refresh operation {key} is not a SHA-256")
    expected_refresh_id = _canonical_hash(
        {
            "context_sha256": value["context_sha256"],
            "schema_version": "market-aligner.vacancy-refresh-id.v1",
        }
    )
    if value["refresh_id"] != expected_refresh_id:
        raise VacancyRefreshConflict("refresh identity differs from operation context")
    old_bytes = bytes(value["old_raw_bytes"])
    try:
        old_raw = raw_posting_from_bytes(old_bytes)
    except ValueError as exc:
        raise VacancyRefreshConflict("journalled old response bytes are invalid") from exc
    if old_raw.key != value["job_key"]:
        raise VacancyRefreshConflict("journalled old response has another vacancy identity")
    if hashlib.sha256(old_bytes).hexdigest() != value["old_object_sha256"]:
        raise VacancyRefreshConflict("journalled old response object hash differs")
    if (
        raw_posting_content_sha256(old_raw) != value["old_canonical_content_sha256"]
        or value["old_content_sha256"] != value["expected_content_sha256"]
        or old_raw.fetched_at != value["old_fetched_at"]
    ):
        raise VacancyRefreshConflict("journalled old response content identity differs")

    status = str(value["status"])
    empty_new = ("intent", "fetch_started", "indeterminate")
    complete_new = ("fetched", "object_ready", "committed")
    if status not in (*empty_new, *complete_new):
        raise VacancyRefreshConflict("refresh journal has an invalid status")
    new_fields = (
        value["new_content_sha256"],
        value["new_fetched_at"],
        value["new_raw_bytes"],
        value["new_object_sha256"],
    )
    if status in empty_new and any(item is not None for item in new_fields):
        raise VacancyRefreshConflict("pre-fetch refresh journal contains response material")
    if status in complete_new:
        if any(item is None for item in new_fields):
            raise VacancyRefreshConflict("post-fetch refresh journal lacks response material")
        new_bytes = bytes(value["new_raw_bytes"])
        try:
            new_raw = raw_posting_from_bytes(new_bytes)
        except ValueError as exc:
            raise VacancyRefreshConflict("journalled new response bytes are invalid") from exc
        if new_raw.key != value["job_key"]:
            raise VacancyRefreshConflict("journalled new response has another vacancy identity")
        if hashlib.sha256(new_bytes).hexdigest() != value["new_object_sha256"]:
            raise VacancyRefreshConflict("journalled new response object hash differs")
        if (
            raw_posting_content_sha256(new_raw) != value["new_content_sha256"]
            or new_raw.fetched_at != value["new_fetched_at"]
        ):
            raise VacancyRefreshConflict("journalled new response content identity differs")

    receipt_fields = (
        value["receipt_basis"],
        value["receipt_basis_sha256"],
        value["transition_sha256"],
    )
    if status != "committed" and any(item is not None for item in receipt_fields):
        raise VacancyRefreshConflict("uncommitted refresh journal contains receipt authority")
    if status == "committed":
        if any(item is None for item in receipt_fields):
            raise VacancyRefreshConflict("committed refresh journal lacks receipt authority")
        receipt = value["receipt_basis"]
        if not isinstance(receipt, dict):
            raise VacancyRefreshConflict("sealed receipt basis is not an object")
        unsealed = dict(receipt)
        stored_basis_sha256 = unsealed.pop("receipt_basis_sha256", None)
        stored_transition_sha256 = unsealed.pop("transition_sha256", None)
        recomputed_basis_sha256 = _canonical_hash(unsealed)
        if (
            stored_basis_sha256 != recomputed_basis_sha256
            or value["receipt_basis_sha256"] != recomputed_basis_sha256
        ):
            raise VacancyRefreshConflict("sealed receipt-basis identity differs")
        transition_value = {**value, "receipt_basis_sha256": recomputed_basis_sha256}
        recomputed_transition_sha256 = _canonical_hash(
            _refresh_transition_document(transition_value)
        )
        if (
            stored_transition_sha256 != recomputed_transition_sha256
            or value["transition_sha256"] != recomputed_transition_sha256
        ):
            raise VacancyRefreshConflict("sealed refresh transition identity differs")
        exact_receipt_fields = {
            "adapter": str(value["job_key"]).split(":", 1)[0],
            "application_authority": False,
            "authority_scope": "collection_only",
            "config_sha256": context["config_sha256"],
            "context_sha256": value["context_sha256"],
            "expected_old_content_sha256": value["expected_content_sha256"],
            "job_key": value["job_key"],
            "new_content_sha256": value["new_content_sha256"],
            "new_fetched_at": value["new_fetched_at"],
            "new_raw_object_path": str(
                Path("state") / "collection-refresh-objects"
                / str(value["new_object_sha256"])[:2]
                / str(value["new_object_sha256"])
            ),
            "new_raw_object_sha256": value["new_object_sha256"],
            "old_content_sha256": value["old_content_sha256"],
            "old_canonical_content_sha256": value["old_canonical_content_sha256"],
            "old_fetched_at": value["old_fetched_at"],
            "old_raw_object_path": str(
                Path("state") / "collection-refresh-objects"
                / str(value["old_object_sha256"])[:2]
                / str(value["old_object_sha256"])
            ),
            "old_raw_object_sha256": value["old_object_sha256"],
            "operation_id": value["operation_id"],
            "official_fetch_count": 1,
            "raw_cache_file_sha256": value["new_object_sha256"],
            "refresh_id": value["refresh_id"],
            "schema_version": "market-aligner.vacancy-refresh-receipt.v3",
            "source_sha256": context["source_sha256"],
            "started_at": value["started_at"],
        }
        if any(
            not _authority_equal(receipt.get(key), expected)
            for key, expected in exact_receipt_fields.items()
        ):
            raise VacancyRefreshConflict("sealed receipt basis differs from journal authorities")


def _legacy_row_identity(value: Mapping[str, object]) -> str:
    material: dict[str, object] = {}
    for key in LEGACY_VACANCY_REFRESH_COLUMNS:
        item = value[key]
        if isinstance(item, bytes):
            material[key] = {
                "sha256": hashlib.sha256(item).hexdigest(),
                "size": len(item),
            }
        else:
            material[key] = item
    return _canonical_hash(material)


def _v2_row_identity(value: Mapping[str, object]) -> str:
    material: dict[str, object] = {}
    for key in V2_VACANCY_REFRESH_COLUMNS:
        item = value[key]
        if isinstance(item, bytes):
            material[key] = {"sha256": hashlib.sha256(item).hexdigest(), "size": len(item)}
        else:
            material[key] = item
    return _canonical_hash(material)


def _v2_transition_document(value: Mapping[str, object]) -> dict[str, object]:
    return {
        "context_sha256": value["context_sha256"],
        "expected_content_sha256": value["expected_content_sha256"],
        "job_key": value["job_key"],
        "new_content_sha256": value["new_content_sha256"],
        "new_fetched_at": value["new_fetched_at"],
        "new_raw_object_sha256": value["new_object_sha256"],
        "old_content_sha256": value["old_content_sha256"],
        "old_fetched_at": value["old_fetched_at"],
        "old_raw_object_sha256": value["old_object_sha256"],
        "operation_id": value["operation_id"],
        "receipt_basis_sha256": value["receipt_basis_sha256"],
        "refresh_id": value["refresh_id"],
        "schema_version": "market-aligner.vacancy-refresh-transition.v1",
        "started_at": value["started_at"],
        "status": value["status"],
    }


def _convert_v2_refresh(value: Mapping[str, object]) -> dict[str, object]:
    """Validate one v2 row and project it without discarding its authority."""

    try:
        context = _strict_json_loads(str(value["context_json"]))
        receipt = (
            None
            if value["receipt_basis_json"] is None
            else _strict_json_loads(str(value["receipt_basis_json"]))
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise VacancyRefreshConflict("v2 refresh JSON is invalid") from exc
    if not isinstance(context, dict) or _canonical_hash(context) != value["context_sha256"]:
        raise VacancyRefreshConflict("v2 refresh context identity differs")
    old_bytes = bytes(value["old_raw_bytes"])
    old_raw = raw_posting_from_bytes(old_bytes)
    old_canonical = raw_posting_content_sha256(old_raw)
    if (
        old_raw.key != value["job_key"]
        or old_raw.fetched_at != value["old_fetched_at"]
        or hashlib.sha256(old_bytes).hexdigest() != value["old_object_sha256"]
        or old_canonical != value["old_content_sha256"]
        or value["old_content_sha256"] != value["expected_content_sha256"]
    ):
        raise VacancyRefreshConflict("v2 old response authorities differ")
    status = str(value["status"])
    empty_new = ("intent", "fetch_started", "indeterminate")
    complete_new = ("fetched", "object_ready", "committed")
    new_fields = (
        value["new_content_sha256"], value["new_fetched_at"],
        value["new_raw_bytes"], value["new_object_sha256"],
    )
    if status not in (*empty_new, *complete_new):
        raise VacancyRefreshConflict("v2 refresh status is invalid")
    if status in empty_new and any(item is not None for item in new_fields):
        raise VacancyRefreshConflict("v2 pre-fetch row contains response material")
    if status in complete_new:
        if any(item is None for item in new_fields):
            raise VacancyRefreshConflict("v2 post-fetch row lacks response material")
        new_bytes = bytes(value["new_raw_bytes"])
        new_raw = raw_posting_from_bytes(new_bytes)
        if (
            new_raw.key != value["job_key"]
            or new_raw.fetched_at != value["new_fetched_at"]
            or hashlib.sha256(new_bytes).hexdigest() != value["new_object_sha256"]
            or raw_posting_content_sha256(new_raw) != value["new_content_sha256"]
        ):
            raise VacancyRefreshConflict("v2 new response authorities differ")
    receipt_fields = (
        receipt, value["receipt_basis_sha256"], value["transition_sha256"]
    )
    if status != "committed" and any(item is not None for item in receipt_fields):
        raise VacancyRefreshConflict("v2 uncommitted row contains receipt authority")
    legacy_receipt_sha256 = None
    legacy_transition_sha256 = None
    if status == "committed":
        if any(item is None for item in receipt_fields) or not isinstance(receipt, dict):
            raise VacancyRefreshConflict("v2 committed row lacks receipt authority")
        unsealed = dict(receipt)
        legacy_receipt_sha256 = unsealed.pop("receipt_basis_sha256", None)
        legacy_transition_sha256 = unsealed.pop("transition_sha256", None)
        if (
            _canonical_hash(unsealed) != legacy_receipt_sha256
            or value["receipt_basis_sha256"] != legacy_receipt_sha256
        ):
            raise VacancyRefreshConflict("v2 receipt identity differs")
        projected = dict(value)
        projected["receipt_basis_sha256"] = legacy_receipt_sha256
        if (
            _canonical_hash(_v2_transition_document(projected))
            != legacy_transition_sha256
            or value["transition_sha256"] != legacy_transition_sha256
        ):
            raise VacancyRefreshConflict("v2 transition identity differs")

    current: dict[str, object] = {
        "refresh_id": value["refresh_id"],
        "operation_id": value["operation_id"],
        "context_sha256": value["context_sha256"],
        "context": context,
        "job_key": value["job_key"],
        "expected_content_sha256": value["expected_content_sha256"],
        "status": status,
        "started_at": value["started_at"],
        "old_content_sha256": value["old_content_sha256"],
        "old_canonical_content_sha256": old_canonical,
        "old_fetched_at": value["old_fetched_at"],
        "old_raw_bytes": old_bytes,
        "old_object_sha256": value["old_object_sha256"],
        "new_content_sha256": value["new_content_sha256"],
        "new_fetched_at": value["new_fetched_at"],
        "new_raw_bytes": value["new_raw_bytes"],
        "new_object_sha256": value["new_object_sha256"],
        "receipt_basis": None,
        "receipt_basis_sha256": None,
        "transition_sha256": None,
    }
    if status == "committed":
        assert isinstance(receipt, dict)
        basis = dict(receipt)
        basis.pop("receipt_basis_sha256", None)
        basis.pop("transition_sha256", None)
        basis.update({
            "changed": value["new_content_sha256"] != old_canonical,
            "journal_migration": "market-aligner.vacancy-refresh-v2-to-v3.v1",
            "old_canonical_content_sha256": old_canonical,
            "schema_version": "market-aligner.vacancy-refresh-receipt.v3",
            "v2_archive_row_sha256": _v2_row_identity(value),
            "v2_receipt_basis_sha256": legacy_receipt_sha256,
            "v2_transition_sha256": legacy_transition_sha256,
        })
        receipt_basis_sha256 = _canonical_hash(basis)
        current["receipt_basis_sha256"] = receipt_basis_sha256
        transition_sha256 = _canonical_hash(_refresh_transition_document(current))
        current["receipt_basis"] = {
            **basis,
            "receipt_basis_sha256": receipt_basis_sha256,
            "transition_sha256": transition_sha256,
        }
        current["transition_sha256"] = transition_sha256
    _validate_refresh_transition(current)
    return current


def _convert_legacy_committed_refresh(value: Mapping[str, object]) -> dict[str, object]:
    """Validate and project one exact 036d committed row into the current schema."""

    if value["status"] != "committed" or value["receipt_basis_json"] is None:
        raise VacancyRefreshConflict("legacy refresh is not a completed transition")
    try:
        legacy_receipt = _strict_json_loads(str(value["receipt_basis_json"]))
    except (json.JSONDecodeError, ValueError) as exc:
        raise VacancyRefreshConflict("legacy receipt basis is invalid JSON") from exc
    if not isinstance(legacy_receipt, dict):
        raise VacancyRefreshConflict("legacy receipt basis is not an object")
    legacy_basis = dict(legacy_receipt)
    legacy_transition_sha256 = legacy_basis.pop("transition_sha256", None)
    if (
        not isinstance(legacy_transition_sha256, str)
        or _canonical_hash(legacy_basis) != legacy_transition_sha256
    ):
        raise VacancyRefreshConflict("legacy transition identity differs")
    context = {
        "config_sha256": legacy_basis.get("config_sha256"),
        "expected_content_sha256": value["expected_content_sha256"],
        "job_key": value["job_key"],
        "operation_id": value["operation_id"],
        "schema_version": "market-aligner.vacancy-refresh-context.v1",
        "source_sha256": legacy_basis.get("source_sha256"),
    }
    if _canonical_hash(context) != value["context_sha256"]:
        raise VacancyRefreshConflict("legacy operation context cannot be reconstructed")
    old_bytes = bytes(value["old_raw_bytes"])
    new_bytes = bytes(value["new_raw_bytes"])
    old_raw = raw_posting_from_bytes(old_bytes)
    new_raw = raw_posting_from_bytes(new_bytes)
    exact = {
        "context_sha256": value["context_sha256"],
        "expected_old_content_sha256": value["expected_content_sha256"],
        "job_key": value["job_key"],
        "new_content_sha256": value["new_content_sha256"],
        "new_fetched_at": value["new_fetched_at"],
        "new_raw_object_sha256": value["new_object_sha256"],
        "old_content_sha256": value["old_content_sha256"],
        "old_fetched_at": value["old_fetched_at"],
        "old_raw_object_sha256": value["old_object_sha256"],
        "operation_id": value["operation_id"],
        "refresh_id": value["refresh_id"],
    }
    if any(
        not _authority_equal(legacy_basis.get(key), expected)
        for key, expected in exact.items()
    ):
        raise VacancyRefreshConflict("legacy receipt differs from journal authorities")
    if (
        old_raw.key != value["job_key"]
        or new_raw.key != value["job_key"]
        or hashlib.sha256(old_bytes).hexdigest() != value["old_object_sha256"]
        or hashlib.sha256(new_bytes).hexdigest() != value["new_object_sha256"]
        or raw_posting_content_sha256(old_raw) != value["old_content_sha256"]
        or raw_posting_content_sha256(new_raw) != value["new_content_sha256"]
        or old_raw.fetched_at != value["old_fetched_at"]
        or new_raw.fetched_at != value["new_fetched_at"]
    ):
        raise VacancyRefreshConflict("legacy raw response authorities differ")
    basis = {
        **legacy_basis,
        "changed": value["new_content_sha256"] != value["old_content_sha256"],
        "journal_migration": "market-aligner.vacancy-refresh-036d-to-current.v1",
        "legacy_archive_row_sha256": _legacy_row_identity(value),
        "legacy_transition_sha256": legacy_transition_sha256,
        "old_canonical_content_sha256": value["old_content_sha256"],
        "schema_version": "market-aligner.vacancy-refresh-receipt.v3",
    }
    receipt_basis_sha256 = _canonical_hash(basis)
    transition: dict[str, object] = {
        "refresh_id": value["refresh_id"],
        "operation_id": value["operation_id"],
        "context_sha256": value["context_sha256"],
        "context": context,
        "job_key": value["job_key"],
        "expected_content_sha256": value["expected_content_sha256"],
        "status": "committed",
        "started_at": value["started_at"],
        "old_content_sha256": value["old_content_sha256"],
        "old_canonical_content_sha256": value["old_content_sha256"],
        "old_fetched_at": value["old_fetched_at"],
        "old_raw_bytes": old_bytes,
        "old_object_sha256": value["old_object_sha256"],
        "new_content_sha256": value["new_content_sha256"],
        "new_fetched_at": value["new_fetched_at"],
        "new_raw_bytes": new_bytes,
        "new_object_sha256": value["new_object_sha256"],
        "receipt_basis_sha256": receipt_basis_sha256,
    }
    transition_sha256 = _canonical_hash(_refresh_transition_document(transition))
    receipt = {
        **basis,
        "receipt_basis_sha256": receipt_basis_sha256,
        "transition_sha256": transition_sha256,
    }
    transition.update({
        "receipt_basis": receipt,
        "transition_sha256": transition_sha256,
    })
    _validate_refresh_transition(transition)
    return transition


def _verify_quarantined_legacy_row(
    conn: sqlite3.Connection,
    quarantine: tuple[object, ...],
) -> dict[str, object]:
    operation_id, refresh_id, job_key, expected, legacy_status, legacy_table, row_sha256 = map(
        str, quarantine
    )
    if legacy_table == "vacancy_refreshes_legacy_036d":
        columns = LEGACY_VACANCY_REFRESH_COLUMNS
        identity = _legacy_row_identity
    elif legacy_table == "vacancy_refreshes_v2":
        columns = V2_VACANCY_REFRESH_COLUMNS
        identity = _v2_row_identity
    else:
        raise VacancyRefreshConflict("quarantined refresh archive type is unsupported")
    archive = conn.execute(
        f"SELECT {','.join(columns)} FROM {legacy_table} WHERE operation_id=?",
        (operation_id,),
    ).fetchone()
    if archive is None:
        raise VacancyRefreshConflict("quarantined legacy refresh archive row is unavailable")
    legacy = dict(zip(columns, archive, strict=True))
    exact = {
        "refresh_id": refresh_id,
        "job_key": job_key,
        "expected_content_sha256": expected,
        "status": legacy_status,
    }
    if any(str(legacy[key]) != value for key, value in exact.items()):
        raise VacancyRefreshConflict("quarantined legacy refresh metadata differs")
    if identity(legacy) != row_sha256:
        raise VacancyRefreshConflict("quarantined legacy refresh row identity differs")
    return legacy


def _validate_legacy_dispositions(
    conn: sqlite3.Connection,
    *,
    job_key: str | None = None,
) -> None:
    archive_exists = conn.execute(
        """SELECT 1 FROM sqlite_master WHERE type='table'
           AND name='vacancy_refreshes_legacy_036d'"""
    ).fetchone() is not None
    clause = " WHERE job_key=?" if job_key is not None else ""
    arguments: tuple[object, ...] = (job_key,) if job_key is not None else ()
    quarantined = conn.execute(
        """SELECT operation_id,refresh_id,job_key,expected_content_sha256,
                  legacy_status,legacy_table,legacy_row_sha256
           FROM vacancy_refresh_migration_quarantine""" + clause,
        arguments,
    ).fetchall()
    quarantine_by_operation = {str(row[0]): row for row in quarantined}
    if len(quarantine_by_operation) != len(quarantined):
        raise VacancyRefreshConflict("legacy refresh has duplicate quarantine dispositions")
    for row in quarantined:
        _verify_quarantined_legacy_row(conn, row)

    current_rows = conn.execute(
        f"SELECT {_REFRESH_SELECT} FROM vacancy_refreshes"
        + (" WHERE job_key=?" if job_key is not None else ""),
        arguments,
    ).fetchall()
    current_by_operation = {str(row[1]): row for row in current_rows}
    if len(current_by_operation) != len(current_rows):
        raise VacancyRefreshConflict("legacy refresh has duplicate current dispositions")

    archived_rows: list[tuple[object, ...]] = []
    if archive_exists:
        archived_rows = conn.execute(
            f"SELECT {','.join(LEGACY_VACANCY_REFRESH_COLUMNS)} "
            "FROM vacancy_refreshes_legacy_036d" + clause,
            arguments,
        ).fetchall()
    archive_by_operation = {
        str(row[1]): dict(zip(LEGACY_VACANCY_REFRESH_COLUMNS, row, strict=True))
        for row in archived_rows
    }
    if len(archive_by_operation) != len(archived_rows):
        raise VacancyRefreshConflict("legacy refresh archive has duplicate operations")

    for operation_id, legacy in archive_by_operation.items():
        current_row = current_by_operation.get(operation_id)
        quarantine_row = quarantine_by_operation.get(operation_id)
        if (current_row is None) == (quarantine_row is None):
            raise VacancyRefreshConflict(
                "legacy refresh must have exactly one current or quarantine disposition"
            )
        if quarantine_row is not None:
            _verify_quarantined_legacy_row(conn, quarantine_row)
            continue
        assert current_row is not None
        try:
            expected = _convert_legacy_committed_refresh(legacy)
        except (TypeError, ValueError, VacancyRefreshConflict) as exc:
            raise VacancyRefreshConflict(
                "legacy refresh current disposition is not representable"
            ) from exc
        current = _refresh_transition_from_row(current_row)
        for key in (
            "refresh_id", "operation_id", "context_sha256", "context", "job_key",
            "expected_content_sha256", "status", "started_at", "old_content_sha256",
            "old_canonical_content_sha256", "old_fetched_at", "old_raw_bytes",
            "old_object_sha256",
            "new_content_sha256", "new_fetched_at", "new_raw_bytes",
            "new_object_sha256", "receipt_basis", "receipt_basis_sha256",
            "transition_sha256",
        ):
            if not _authority_equal(current[key], expected[key]):
                raise VacancyRefreshConflict(
                    "legacy refresh current disposition differs from archived authority"
                )

    v2_archive_exists = conn.execute(
        """SELECT 1 FROM sqlite_master WHERE type='table'
           AND name='vacancy_refreshes_v2'"""
    ).fetchone() is not None
    v2_rows: list[tuple[object, ...]] = []
    if v2_archive_exists:
        v2_rows = conn.execute(
            f"SELECT {','.join(V2_VACANCY_REFRESH_COLUMNS)} FROM vacancy_refreshes_v2"
            + clause,
            arguments,
        ).fetchall()
    for row in v2_rows:
        archived = dict(zip(V2_VACANCY_REFRESH_COLUMNS, row, strict=True))
        operation_id = str(archived["operation_id"])
        current_row = current_by_operation.get(operation_id)
        quarantine_row = quarantine_by_operation.get(operation_id)
        if (current_row is None) == (quarantine_row is None):
            raise VacancyRefreshConflict(
                "v2 refresh must have exactly one current or quarantine disposition"
            )
        try:
            expected = _convert_v2_refresh(archived)
        except (TypeError, ValueError, VacancyRefreshConflict):
            if quarantine_row is None:
                raise VacancyRefreshConflict(
                    "invalid v2 refresh was not quarantined"
                )
            _verify_quarantined_legacy_row(conn, quarantine_row)
            continue
        if quarantine_row is not None:
            raise VacancyRefreshConflict("representable v2 refresh was quarantined")
        assert current_row is not None
        current = _refresh_transition_from_row(current_row)
        immutable_keys = (
            "refresh_id", "operation_id", "context_sha256", "context", "job_key",
            "expected_content_sha256", "status", "started_at", "old_content_sha256",
            "old_canonical_content_sha256", "old_fetched_at", "old_raw_bytes",
            "old_object_sha256",
        )
        for key in immutable_keys:
            if key == "status":
                continue
            if not _authority_equal(current[key], expected[key]):
                raise VacancyRefreshConflict(
                    "v2 refresh current disposition differs from archived authority"
                )
        allowed_progressions = {
            "intent": {"intent", "fetch_started", "indeterminate", "fetched", "object_ready", "committed"},
            "fetch_started": {"fetch_started", "indeterminate"},
            "indeterminate": {"indeterminate"},
            "fetched": {"fetched", "object_ready", "committed"},
            "object_ready": {"object_ready", "committed"},
            "committed": {"committed"},
        }
        if current["status"] not in allowed_progressions[expected["status"]]:
            raise VacancyRefreshConflict("v2 refresh disposition regressed or forked")
        if expected["status"] in ("fetched", "object_ready", "committed"):
            for key in (
                "new_content_sha256", "new_fetched_at", "new_raw_bytes",
                "new_object_sha256",
            ):
                if not _authority_equal(current[key], expected[key]):
                    raise VacancyRefreshConflict(
                        "v2 fetched response differs from archived authority"
                    )
        if expected["status"] == "committed":
            for key in ("receipt_basis", "receipt_basis_sha256", "transition_sha256"):
                if not _authority_equal(current[key], expected[key]):
                    raise VacancyRefreshConflict(
                        "v2 committed receipt differs from archived authority"
                    )

    for operation_id, row in current_by_operation.items():
        current = _refresh_transition_from_row(row)
        receipt = current.get("receipt_basis")
        if (
            isinstance(receipt, dict)
            and receipt.get("journal_migration")
            == "market-aligner.vacancy-refresh-036d-to-current.v1"
            and operation_id not in archive_by_operation
        ):
            raise VacancyRefreshConflict(
                "migrated vacancy refresh has no archived legacy authority"
            )


def _insert_migrated_refresh(
    conn: sqlite3.Connection,
    current: Mapping[str, object],
    *,
    created_at: object,
    updated_at: object,
) -> None:
    receipt = current["receipt_basis"]
    conn.execute(
        """INSERT INTO vacancy_refreshes(
             refresh_id,operation_id,context_sha256,context_json,
             job_key,expected_content_sha256,status,started_at,
             old_content_sha256,old_canonical_content_sha256,
             old_fetched_at,old_raw_bytes,old_object_sha256,
             new_content_sha256,new_fetched_at,new_raw_bytes,new_object_sha256,
             receipt_basis_json,receipt_basis_sha256,transition_sha256,
             created_at,updated_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            current["refresh_id"], current["operation_id"],
            current["context_sha256"], json.dumps(
                current["context"], ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ), current["job_key"], current["expected_content_sha256"],
            current["status"], current["started_at"], current["old_content_sha256"],
            current["old_canonical_content_sha256"], current["old_fetched_at"],
            current["old_raw_bytes"], current["old_object_sha256"],
            current["new_content_sha256"], current["new_fetched_at"],
            current["new_raw_bytes"], current["new_object_sha256"],
            None if receipt is None else json.dumps(
                receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                allow_nan=False,
            ), current["receipt_basis_sha256"], current["transition_sha256"],
            created_at, updated_at,
        ),
    )


class ProjectionConflict(RuntimeError):
    """An immutable projection exists with non-exact process-owned fields."""

def cas_normalized_job(
    connection: sqlite3.Connection,
    *,
    key: str,
    normalized_json: str,
    normalized_at: str,
) -> str:
    """Insert-absent/reuse-exact CAS on the caller's transaction.

    Returns ``"inserted"`` when the key is absent (explicit ``normalized_at``
    supplied — never a table default) and ``"reused"`` only when the stored
    ``normalized_json`` is byte-exact. Any other existing row raises
    :class:`ProjectionConflict`. There is no UPDATE path.
    """
    schema = "vacancy.normalised_jobs"
    row = connection.execute(
        f"SELECT normalized_json FROM {schema} WHERE key=?", (key,)
    ).fetchone()
    if row is None:
        connection.execute(
            f"INSERT INTO {schema}(key,normalized_json,normalized_at) VALUES(?,?,?)",
            (key, normalized_json, normalized_at),
        )
        return "inserted"
    if row[0] != normalized_json:
        raise ProjectionConflict(
            "normalised_jobs projection differs from the accepted vacancy"
        )
    return "reused"

def read_normalized_job(
    connection: sqlite3.Connection, *, key: str
) -> tuple[str, str] | None:
    """Read ``(normalized_json, normalized_at)`` for one key, or None."""
    row = connection.execute(
        "SELECT normalized_json,normalized_at FROM vacancy.normalised_jobs WHERE key=?",
        (key,),
    ).fetchone()
    return None if row is None else (row[0], row[1])

def read_posting(
    connection: sqlite3.Connection, *, key: str, schema: str = "main"
) -> sqlite3.Row | None:
    """Read the exact current posting row for one key, or None.

    ``schema`` defaults to the literal ``"main"`` and may only ever be
    ``"main"`` or ``"vacancy"``, so the statement can never silently
    resolve an unqualified name against a different attached database.
    The projection is the exact explicit column list in
    :data:`POSTING_READ_COLUMNS`, and ``sqlite3.Row`` is set on the
    cursor only, never on the connection's row factory.
    """

    if schema not in ("main", "vacancy"):
        raise ValueError("schema must be the literal 'main' or 'vacancy'")
    columns = ",".join(POSTING_READ_COLUMNS)
    cursor = connection.execute(
        f"SELECT {columns} FROM {schema}.postings WHERE key=?", (key,)
    )
    cursor.row_factory = sqlite3.Row
    return cursor.fetchone()


class JobDatabase:
    def __init__(self, path: str | Path, *, data_home: str | Path | None = None) -> None:
        self.path = Path(path)
        self.data_home = (
            Path(data_home).absolute()
            if data_home is not None
            else self.path.parent.parent.absolute()
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with owner_private_umask(), closing(self.connect()) as conn, conn:
            conn.executescript(SCHEMA)
            conn.execute(
                """INSERT OR IGNORE INTO posting_raw_snapshot_migration_blocks(
                     job_key,reason_code,legacy_content_hash
                   )
                   SELECT p.key,'legacy_fetched_without_immutable_raw_snapshot',
                          p.content_hash
                   FROM postings p
                   WHERE p.fetch_status='fetched'
                     AND NOT EXISTS(
                       SELECT 1 FROM posting_raw_snapshot_heads h
                       WHERE h.job_key=p.key
                     )"""
            )
            self._migrate_vacancy_refresh_schema(conn)
            self._validate_vacancy_refresh_rows(conn)
            self._migrate_processing_identity(conn)

    @classmethod
    def resolve_vacancy_refresh_collector(
        cls,
        data_home: str | Path,
        receipt_path: str | Path,
        config_path: str | Path,
    ) -> ResolvedVacancyRefreshCollector:
        """Resolve the collector DB only through the receipt-bound full config."""

        root = Path(data_home).absolute()
        loaded_receipt = _load_vacancy_refresh_receipt(root, receipt_path)
        config = load_config(config_path)
        if _canonical_hash(config) != loaded_receipt.document.get("config_sha256"):
            raise VacancyRefreshConflict(
                "collection config identity differs from refresh receipt"
            )
        io = config.get("io")
        if not isinstance(io, dict):
            raise VacancyRefreshConflict("collection config has no io mapping")
        database_value = io.get("database")
        if not isinstance(database_value, str) or not database_value.strip():
            raise VacancyRefreshConflict("collection config has no database path")
        relative = Path(database_value)
        if relative.is_absolute() or ".." in relative.parts:
            raise VacancyRefreshConflict(
                "collection config database must remain below the external data home"
            )
        database = (root / relative).absolute()
        if database == root or root not in database.parents:
            raise VacancyRefreshConflict(
                "collection config database escaped the external data home"
            )
        board = str(loaded_receipt.document.get("adapter", ""))
        job_key = str(loaded_receipt.document.get("job_key", ""))
        boards = config.get("boards")
        enabled = boards.get("enabled") if isinstance(boards, dict) else None
        if (
            not board
            or not job_key.startswith(f"{board}:")
            or not isinstance(enabled, list)
            or board not in enabled
        ):
            raise VacancyRefreshConflict(
                "collection config does not own the receipt vacancy"
            )
        source_sha256 = _canonical_hash(
            {
                "adapter": board,
                "adapter_config": config.get(board, {}) or {},
                "job_key": job_key,
            }
        )
        if source_sha256 != loaded_receipt.document.get("source_sha256"):
            raise VacancyRefreshConflict(
                "collection config adapter identity differs from refresh receipt"
            )
        directory_chain: list[tuple[Path, int, int]] = []
        current = root
        try:
            root_metadata = current.lstat()
        except OSError as exc:
            raise VacancyRefreshConflict(
                "external data home is unavailable"
            ) from exc
        if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
            raise VacancyRefreshConflict("external data home is unsafe")
        directory_chain.append(
            (current, int(root_metadata.st_dev), int(root_metadata.st_ino))
        )
        for component in relative.parts[:-1]:
            current = current / component
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise VacancyRefreshConflict(
                    "configured collector database ancestor is unavailable"
                ) from exc
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise VacancyRefreshConflict(
                    "configured collector database ancestor is unsafe"
                )
            directory_chain.append(
                (current, int(metadata.st_dev), int(metadata.st_ino))
            )
        try:
            metadata = database.lstat()
        except OSError as exc:
            raise VacancyRefreshConflict(
                "configured collector database is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise VacancyRefreshConflict("configured collector database is unsafe")
        collector = cls(database, data_home=root)
        return ResolvedVacancyRefreshCollector(
            database=collector,
            path=database,
            data_home=root,
            st_dev=int(metadata.st_dev),
            st_ino=int(metadata.st_ino),
            directory_chain=tuple(directory_chain),
        )

    @staticmethod
    def _validate_vacancy_refresh_rows(conn: sqlite3.Connection) -> None:
        for row in conn.execute(f"SELECT {_REFRESH_SELECT} FROM vacancy_refreshes"):
            _refresh_transition_from_row(row)
        _validate_legacy_dispositions(conn)

    @staticmethod
    def _migrate_vacancy_refresh_schema(conn: sqlite3.Connection) -> None:
        """Detect 036d journals explicitly; preserve, project, or quarantine each row."""

        table = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='vacancy_refreshes'"
        ).fetchone()
        conn.execute(VACANCY_REFRESH_QUARANTINE_SCHEMA)
        if table is None:
            conn.execute(VACANCY_REFRESH_SCHEMA)
            return
        columns = tuple(
            str(row[1]) for row in conn.execute("PRAGMA table_info(vacancy_refreshes)")
        )
        if columns == CURRENT_VACANCY_REFRESH_COLUMNS:
            sql = str(table[0] or "")
            if "fetch_started" not in sql or "indeterminate" not in sql:
                raise VacancyRefreshConflict("vacancy refresh schema has an unknown status contract")
            return
        if columns == V2_VACANCY_REFRESH_COLUMNS:
            archive = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                ("vacancy_refreshes_v2",),
            ).fetchone()
            if archive is not None:
                raise VacancyRefreshConflict("v2 vacancy refresh archive already exists")
            conn.execute("ALTER TABLE vacancy_refreshes RENAME TO vacancy_refreshes_v2")
            conn.execute(VACANCY_REFRESH_SCHEMA)
            rows = conn.execute(
                f"SELECT {','.join(V2_VACANCY_REFRESH_COLUMNS)} "
                "FROM vacancy_refreshes_v2 ORDER BY operation_id"
            ).fetchall()
            for row in rows:
                v2 = dict(zip(V2_VACANCY_REFRESH_COLUMNS, row, strict=True))
                try:
                    current = _convert_v2_refresh(v2)
                except (TypeError, ValueError, VacancyRefreshConflict) as exc:
                    conn.execute(
                        """INSERT INTO vacancy_refresh_migration_quarantine(
                             operation_id,refresh_id,job_key,expected_content_sha256,
                             legacy_status,legacy_table,legacy_row_sha256,reason
                           ) VALUES(?,?,?,?,?,'vacancy_refreshes_v2',?,?)""",
                        (
                            v2["operation_id"], v2["refresh_id"], v2["job_key"],
                            v2["expected_content_sha256"], v2["status"],
                            _v2_row_identity(v2),
                            f"v2 row is not exactly representable: {exc}",
                        ),
                    )
                else:
                    _insert_migrated_refresh(
                        conn, current, created_at=v2["created_at"],
                        updated_at=v2["updated_at"],
                    )
            return
        if columns != LEGACY_VACANCY_REFRESH_COLUMNS:
            raise VacancyRefreshConflict("vacancy refresh schema version is unsupported")
        archive = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            ("vacancy_refreshes_legacy_036d",),
        ).fetchone()
        if archive is not None:
            raise VacancyRefreshConflict("legacy vacancy refresh archive already exists")
        conn.execute("ALTER TABLE vacancy_refreshes RENAME TO vacancy_refreshes_legacy_036d")
        conn.execute(VACANCY_REFRESH_SCHEMA)
        selected = ",".join(LEGACY_VACANCY_REFRESH_COLUMNS)
        rows = conn.execute(
            f"SELECT {selected} FROM vacancy_refreshes_legacy_036d ORDER BY operation_id"
        ).fetchall()
        for row in rows:
            legacy = dict(zip(LEGACY_VACANCY_REFRESH_COLUMNS, row, strict=True))
            reason = f"legacy in-flight status requires explicit reconciliation: {legacy['status']}"
            if legacy["status"] == "committed":
                try:
                    current = _convert_legacy_committed_refresh(legacy)
                except (TypeError, ValueError, VacancyRefreshConflict) as exc:
                    reason = f"legacy completed row is not exactly representable: {exc}"
                else:
                    _insert_migrated_refresh(
                        conn, current, created_at=legacy["created_at"],
                        updated_at=legacy["updated_at"],
                    )
                    continue
            conn.execute(
                """INSERT INTO vacancy_refresh_migration_quarantine(
                     operation_id,refresh_id,job_key,expected_content_sha256,
                     legacy_status,legacy_table,legacy_row_sha256,reason
                   ) VALUES(?,?,?,?,?,'vacancy_refreshes_legacy_036d',?,?)""",
                (
                    legacy["operation_id"], legacy["refresh_id"], legacy["job_key"],
                    legacy["expected_content_sha256"], legacy["status"],
                    _legacy_row_identity(legacy), reason,
                ),
            )

    @staticmethod
    def _migrate_processing_identity(conn: sqlite3.Connection) -> None:
        """Bind legacy processing rows to an explicit, non-current config identity.

        SQLite cannot extend a primary key in place.  Existing v1 rows are copied
        intact under a reserved digest.  They remain available as semantic cache,
        but no current-config report or resume query can mistake them for a fresh
        decision.
        """

        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(processing_jobs)")
        }
        if "processing_config_sha256" in columns:
            conn.execute(
                """CREATE INDEX IF NOT EXISTS processing_jobs_resume ON processing_jobs(
                     profile_id,track,authority_sha256,processing_config_sha256,
                     status,lease_until
                   )"""
            )
            return
        conn.execute("DROP INDEX IF EXISTS processing_jobs_resume")
        conn.execute("ALTER TABLE processing_jobs RENAME TO processing_jobs_v1")
        conn.execute(
            """CREATE TABLE processing_jobs (
                 profile_id TEXT NOT NULL,
                 track TEXT NOT NULL,
                 job_key TEXT NOT NULL,
                 authority_sha256 TEXT NOT NULL,
                 source_content_sha256 TEXT NOT NULL,
                 processing_config_sha256 TEXT NOT NULL,
                 status TEXT NOT NULL CHECK(status IN ('leased','completed','failed')),
                 lease_owner TEXT,
                 lease_until REAL,
                 result_json TEXT,
                 error TEXT,
                 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                 PRIMARY KEY(
                   profile_id,track,job_key,authority_sha256,source_content_sha256,
                   processing_config_sha256
                 ),
                 FOREIGN KEY(job_key) REFERENCES postings(key) ON DELETE CASCADE
               )"""
        )
        conn.execute(
            """INSERT INTO processing_jobs(
                 profile_id,track,job_key,authority_sha256,source_content_sha256,
                 processing_config_sha256,status,lease_owner,lease_until,result_json,
                 error,updated_at
               )
               SELECT profile_id,track,job_key,authority_sha256,source_content_sha256,
                      ?,status,lease_owner,lease_until,result_json,error,updated_at
               FROM processing_jobs_v1""",
            (LEGACY_PROCESSING_CONFIG_SHA256,),
        )
        conn.execute("DROP TABLE processing_jobs_v1")
        conn.execute(
            """CREATE INDEX processing_jobs_resume ON processing_jobs(
                 profile_id,track,authority_sha256,processing_config_sha256,
                 status,lease_until
               )"""
        )

    def connect(self) -> sqlite3.Connection:
        with owner_private_umask():
            conn = sqlite3.connect(self.path, timeout=30)
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def upsert_discovered(self, row: JobUrl) -> bool:
        validate_public_listing_url(row.url)
        with closing(self.connect()) as conn, conn:
            existed = conn.execute("SELECT 1 FROM postings WHERE key=?", (row.key,)).fetchone()
            conn.execute(
                """INSERT INTO postings(key,board,job_id,url,posted_at) VALUES(?,?,?,?,?)
                   ON CONFLICT(key) DO UPDATE SET url=excluded.url,
                     posted_at=COALESCE(excluded.posted_at,postings.posted_at),
                     last_seen_at=CURRENT_TIMESTAMP""",
                (row.key, row.board, row.job_id, row.url, row.posted_at),
            )
        return existed is None

    def has_raw(self, key: str) -> bool:
        with closing(self.connect()) as conn, conn:
            return conn.execute(
                "SELECT 1 FROM postings WHERE key=? AND fetch_status='fetched'", (key,)
            ).fetchone() is not None

    @staticmethod
    def _record_raw_snapshot(
        conn: sqlite3.Connection,
        row: RawPosting,
        *,
        content_sha256: str,
        exact_raw_bytes: bytes | None = None,
    ) -> str:
        """Append one exact canonical raw object and advance its mutable head."""

        exact = raw_posting_bytes(row) if exact_raw_bytes is None else exact_raw_bytes
        decoded = raw_posting_from_bytes(exact)
        if decoded.key != row.key or raw_posting_content_sha256(row) != content_sha256:
            raise ValueError("raw snapshot identity differs from the posting")
        object_sha256 = hashlib.sha256(exact).hexdigest()
        conn.execute(
            """INSERT OR IGNORE INTO posting_raw_snapshots(
                 job_key,content_sha256,object_sha256,exact_raw_bytes,fetched_at
               ) VALUES(?,?,?,?,?)""",
            (row.key, content_sha256, object_sha256, exact, decoded.fetched_at),
        )
        stored = conn.execute(
            """SELECT content_sha256,exact_raw_bytes,fetched_at
               FROM posting_raw_snapshots WHERE job_key=? AND object_sha256=?""",
            (row.key, object_sha256),
        ).fetchone()
        if (
            stored is None
            or stored[0] != content_sha256
            or bytes(stored[1]) != exact
            or stored[2] != decoded.fetched_at
        ):
            raise ValueError("raw snapshot identity conflicts with preserved bytes")
        conn.execute(
            """INSERT INTO posting_raw_snapshot_heads(
                 job_key,content_sha256,object_sha256
               ) VALUES(?,?,?)
               ON CONFLICT(job_key) DO UPDATE SET
                 content_sha256=excluded.content_sha256,
                 object_sha256=excluded.object_sha256""",
            (row.key, content_sha256, object_sha256),
        )
        return object_sha256

    def store_raw(self, row: RawPosting) -> None:
        # Scan every persistence representation, including legacy raw_text/raw_json
        # rows that do not carry the newer exact-byte field, before any state change.
        public_listing_bytes(row)
        raw_json = json.dumps(row.raw_json, ensure_ascii=False) if row.raw_json is not None else None
        digest = raw_posting_content_sha256(row)
        with closing(self.connect()) as conn, conn:
            cursor = conn.execute(
                """UPDATE postings SET fetched_at=?,raw_text=?,raw_json=?,content_hash=?,
                   fetch_status='fetched',fetch_error=NULL WHERE key=?""",
                (row.fetched_at, row.raw_text, raw_json, digest, row.key),
            )
            if cursor.rowcount == 1:
                self._record_raw_snapshot(conn, row, content_sha256=digest)

    def snapshot_migration_block(self, job_key: str) -> sqlite3.Row | None:
        """Return an active block for a fetched row lacking exact replay bytes."""

        with closing(self.connect()) as conn:
            cursor = conn.execute(
                """SELECT b.job_key,b.reason_code,b.legacy_content_hash,b.detected_at
                   FROM posting_raw_snapshot_migration_blocks b
                   WHERE b.job_key=? AND NOT EXISTS(
                     SELECT 1 FROM posting_raw_snapshot_heads h
                     WHERE h.job_key=b.job_key
                   )""",
                (job_key,),
            )
            cursor.row_factory = sqlite3.Row
            return cursor.fetchone()

    def raw_snapshot(self, job_key: str, content_sha256: str) -> bytes:
        """Return preserved canonical raw bytes for one semantic content identity."""

        with closing(self.connect()) as conn:
            row = conn.execute(
                """SELECT s.exact_raw_bytes
                   FROM posting_raw_snapshots s
                   LEFT JOIN posting_raw_snapshot_heads h
                     ON h.job_key=s.job_key AND h.object_sha256=s.object_sha256
                   WHERE s.job_key=? AND s.content_sha256=?
                   ORDER BY (h.job_key IS NOT NULL) DESC,
                            s.fetched_at DESC,s.recorded_at DESC,s.object_sha256 DESC
                   LIMIT 1""",
                (job_key, content_sha256),
            ).fetchone()
        if row is None:
            raise KeyError((job_key, content_sha256))
        return bytes(row[0])

    def load_raw_snapshot(self, job_key: str, content_sha256: str) -> RawPosting:
        """Rehydrate a preserved raw object by canonical vacancy/content identity."""

        raw = raw_posting_from_bytes(self.raw_snapshot(job_key, content_sha256))
        if raw.key != job_key:
            raise ValueError("preserved raw snapshot no longer matches its identity")
        return raw

    def load_current_raw_snapshot(self, job_key: str) -> RawPosting:
        """Rehydrate the exact raw object selected by the current snapshot head."""

        with closing(self.connect()) as conn:
            row = conn.execute(
                """SELECT s.content_sha256,s.exact_raw_bytes
                   FROM posting_raw_snapshot_heads h
                   JOIN posting_raw_snapshots s
                     ON s.job_key=h.job_key
                    AND s.content_sha256=h.content_sha256
                    AND s.object_sha256=h.object_sha256
                   WHERE h.job_key=?""",
                (job_key,),
            ).fetchone()
        if row is None:
            raise KeyError(job_key)
        raw = raw_posting_from_bytes(bytes(row[1]))
        if raw.key != job_key:
            raise ValueError("current raw snapshot head differs from preserved bytes")
        return raw

    def fetched_posting(self, key: str) -> tuple[JobUrl, str, str]:
        """Load one existing fetched row and its guarded refresh identity."""

        with closing(self.connect()) as conn:
            row = conn.execute(
                """SELECT board,job_id,url,posted_at,content_hash,fetched_at,fetch_status
                   FROM postings WHERE key=?""",
                (key,),
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown vacancy key: {key}")
        if row[6] != "fetched" or not row[4] or not row[5]:
            raise ValueError(f"vacancy is not an existing fetched row: {key}")
        job = JobUrl(board=str(row[0]), job_id=str(row[1]), url=str(row[2]), posted_at=row[3])
        if job.key != key:
            raise ValueError(f"stored vacancy identity does not match key: {key}")
        return job, str(row[4]), str(row[5])

    def verify_vacancy_refresh_receipt(
        self,
        receipt_path: str | Path,
        *,
        job_key: str,
        connection: sqlite3.Connection | None = None,
        schema: str = "main",
    ) -> VerifiedVacancyRefreshReceipt:
        """Verify one exact external receipt against its journal, CAS, and current row.

        A caller may supply a connection with this collector database attached as
        ``collector``.  That seam lets another SQLite store hold a write-reserving
        transaction over both databases while this method performs the canonical
        collector revalidation.
        """

        if schema not in {"main", "collector"}:
            raise ValueError("collector verification schema is unsupported")
        if not job_key or ":" not in job_key:
            raise ValueError("refresh receipt requires a board-qualified job key")
        data_home = self.data_home
        loaded_receipt = _load_vacancy_refresh_receipt(data_home, receipt_path)
        absolute = loaded_receipt.path
        receipt_bytes = loaded_receipt.exact_bytes
        receipt = loaded_receipt.document
        body = loaded_receipt.sealed_body
        receipt_sha256 = loaded_receipt.receipt_sha256
        if (
            receipt.get("schema_version")
            != "market-aligner.vacancy-refresh-receipt.v3"
            or receipt.get("job_key") != job_key
            or receipt.get("application_authority") is not False
            or receipt.get("authority_scope") != "collection_only"
            or type(receipt.get("changed")) is not bool
        ):
            raise VacancyRefreshConflict("refresh receipt authority or vacancy differs")

        owns_connection = connection is None
        collector_connection = self.connect() if connection is None else connection
        prefix = "" if schema == "main" else "collector."
        try:
            if schema == "main":
                _validate_legacy_dispositions(collector_connection, job_key=job_key)
            row = collector_connection.execute(
                f"SELECT {_REFRESH_SELECT} FROM {prefix}vacancy_refreshes "
                "WHERE operation_id=?",
                (receipt.get("operation_id"),),
            ).fetchone()
            if row is None:
                raise VacancyRefreshConflict("refresh receipt has no exact journal")
            transition = _refresh_transition_from_row(row)
            if transition["job_key"] != job_key or transition["status"] != "committed":
                raise VacancyRefreshConflict("refresh journal is not the committed vacancy")
            sealed = transition.get("receipt_basis")
            if not isinstance(sealed, dict) or not _authority_equal(body, sealed):
                raise VacancyRefreshConflict("refresh receipt differs from sealed journal")
            posting = collector_connection.execute(
                f"""SELECT board,job_id,url,fetched_at,raw_text,raw_json,
                           content_hash,fetch_status
                    FROM {prefix}postings WHERE key=?""",
                (job_key,),
            ).fetchone()
            if posting is None or posting[7] != "fetched":
                raise VacancyRefreshConflict("refresh vacancy is not currently fetched")
            try:
                raw_json = None if posting[5] is None else _strict_json_loads(str(posting[5]))
            except (json.JSONDecodeError, ValueError) as exc:
                raise VacancyRefreshConflict("current collector raw JSON is invalid") from exc
            current_raw = RawPosting(
                board=str(posting[0]),
                job_id=str(posting[1]),
                url=str(posting[2]),
                fetched_at=str(posting[3]),
                raw_text=posting[4],
                raw_json=raw_json,
            )
            if (
                current_raw.key != job_key
                or posting[6] != transition["new_content_sha256"]
                or raw_posting_content_sha256(current_raw)
                != transition["new_content_sha256"]
                or raw_posting_bytes(current_raw) != transition["new_raw_bytes"]
            ):
                raise VacancyRefreshConflict(
                    "current collector row differs from the sealed refresh"
                )
        finally:
            if owns_connection:
                collector_connection.close()

        # Reuse the collector's accepted descriptor-relative CAS verifier; this
        # avoids a second serialization or object-integrity implementation.
        from market_aligner.collectors.engine import _verify_refresh_objects

        _verify_refresh_objects(data_home, transition)
        return VerifiedVacancyRefreshReceipt(
            job_key=job_key,
            changed=bool(receipt["changed"]),
            old_content_sha256=str(receipt["old_content_sha256"]),
            old_canonical_content_sha256=str(
                receipt["old_canonical_content_sha256"]
            ),
            new_content_sha256=str(receipt["new_content_sha256"]),
            old_fetched_at=str(receipt["old_fetched_at"]),
            new_fetched_at=str(receipt["new_fetched_at"]),
            operation_id=str(receipt["operation_id"]),
            refresh_id=str(receipt["refresh_id"]),
            context_sha256=str(receipt["context_sha256"]),
            transition_sha256=str(receipt["transition_sha256"]),
            receipt_sha256=receipt_sha256,
            receipt_file_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
            receipt_path=absolute,
            new_raw_object_sha256=str(receipt["new_raw_object_sha256"]),
        )

    def refresh_transition(
        self,
        operation_id: str,
        *,
        context_sha256: str,
    ) -> dict[str, object] | None:
        """Load one exact refresh journal, rejecting operation-ID substitution."""

        with closing(self.connect()) as conn:
            _validate_legacy_dispositions(conn)
            row = conn.execute(
                f"SELECT {_REFRESH_SELECT} FROM vacancy_refreshes WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            quarantined = conn.execute(
                """SELECT operation_id,refresh_id,job_key,expected_content_sha256,
                          legacy_status,legacy_table,legacy_row_sha256,reason
                   FROM vacancy_refresh_migration_quarantine
                   WHERE operation_id=?""",
                (operation_id,),
            ).fetchone()
            if row is None and quarantined is not None:
                legacy = _verify_quarantined_legacy_row(conn, quarantined[:7])
                if legacy["context_sha256"] != context_sha256:
                    raise ValueError("refresh operation ID is already bound to another context")
        if row is None:
            if quarantined is not None:
                raise VacancyRefreshIndeterminate(
                    f"legacy vacancy refresh is quarantined ({quarantined[4]}): "
                    f"{quarantined[7]}"
                )
            return None
        if row[2] != context_sha256:
            raise ValueError("refresh operation ID is already bound to another context")
        return _refresh_transition_from_row(row)

    def begin_vacancy_refresh(
        self,
        *,
        refresh_id: str,
        operation_id: str,
        context_sha256: str,
        context_document: Mapping[str, object],
        job_key: str,
        expected_content_sha256: str,
        started_at: str,
        old_raw_bytes: bytes,
    ) -> dict[str, object]:
        """Persist an exact old-response intent before any official refetch."""

        for label, value in (
            ("refresh", refresh_id),
            ("context", context_sha256),
            ("expected content", expected_content_sha256),
        ):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError(f"{label} identity must be lowercase SHA-256")
        old_raw = raw_posting_from_bytes(old_raw_bytes)
        canonical_context = json.loads(json.dumps(
            dict(context_document),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ))
        if _canonical_hash(canonical_context) != context_sha256:
            raise ValueError("refresh operation context bytes differ from its identity")
        if old_raw.key != job_key:
            raise ValueError("old raw-cache response differs from refresh vacancy")
        old_object_sha256 = hashlib.sha256(old_raw_bytes).hexdigest()
        old_canonical_content_sha256 = raw_posting_content_sha256(old_raw)
        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            _validate_legacy_dispositions(conn, job_key=job_key)
            existing = conn.execute(
                "SELECT context_sha256 FROM vacancy_refreshes WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if existing is not None:
                conn.rollback()
                if existing[0] != context_sha256:
                    raise ValueError("refresh operation ID is already bound to another context")
                loaded = self.refresh_transition(
                    operation_id, context_sha256=context_sha256
                )
                assert loaded is not None
                return loaded
            blocked = conn.execute(
                """SELECT operation_id,status FROM vacancy_refreshes
                   WHERE job_key=?
                     AND status IN (
                       'intent','fetch_started','indeterminate','fetched','object_ready'
                     )
                   ORDER BY created_at,operation_id LIMIT 1""",
                (job_key,),
            ).fetchone()
            quarantined = conn.execute(
                """SELECT operation_id,refresh_id,job_key,expected_content_sha256,
                          legacy_status,legacy_table,legacy_row_sha256
                   FROM vacancy_refresh_migration_quarantine
                   WHERE job_key=?
                   ORDER BY quarantined_at,operation_id LIMIT 1""",
                (job_key,),
            ).fetchone()
            if quarantined is not None:
                _verify_quarantined_legacy_row(conn, quarantined)
                conn.rollback()
                raise VacancyRefreshIndeterminate(
                    "a legacy vacancy refresh is quarantined and requires explicit "
                    f"reconciliation: {quarantined[0]} ({quarantined[4]})"
                )
            if blocked is not None:
                conn.rollback()
                if blocked[1] in ("fetch_started", "indeterminate"):
                    raise VacancyRefreshIndeterminate(
                        "a prior official fetch is indeterminate and requires explicit "
                        f"reconciliation: {blocked[0]}"
                    )
                raise VacancyRefreshConflict(
                    f"a prior vacancy refresh is still active: {blocked[0]}"
                )
            current = conn.execute(
                """SELECT content_hash,fetched_at,fetch_status,url,raw_text,raw_json
                   FROM postings WHERE key=?""",
                (job_key,),
            ).fetchone()
            if current is None:
                conn.rollback()
                raise KeyError(f"unknown vacancy key: {job_key}")
            if current[2] != "fetched" or current[0] != expected_content_sha256:
                conn.rollback()
                raise VacancyRefreshConflict(
                    f"vacancy differs from refresh intent: {job_key}"
                )
            stored_material = (current[4] or "") + (current[5] or "")
            if hashlib.sha256(stored_material.encode("utf-8")).hexdigest() != current[0]:
                conn.rollback()
                raise VacancyRefreshConflict(
                    "stored vacancy content bytes differ from its legacy identity"
                )
            try:
                stored_raw_json = None if current[5] is None else _strict_json_loads(current[5])
            except (json.JSONDecodeError, ValueError) as exc:
                conn.rollback()
                raise VacancyRefreshConflict("stored vacancy raw JSON is invalid") from exc
            if (
                old_raw.url != current[3]
                or old_raw.raw_text != current[4]
                or not _authority_equal(old_raw.raw_json, stored_raw_json)
                or old_raw.fetched_at != current[1]
            ):
                conn.rollback()
                raise ValueError(
                    "old raw-cache response differs semantically from SQLite vacancy"
                )
            conn.execute(
                """INSERT INTO vacancy_refreshes(
                     refresh_id,operation_id,context_sha256,context_json,job_key,
                     expected_content_sha256,status,started_at,
                     old_content_sha256,old_canonical_content_sha256,
                     old_fetched_at,old_raw_bytes,
                     old_object_sha256
                   ) VALUES(?,?,?,?,?,?,'intent',?,?,?,?,?,?)""",
                (
                    refresh_id,
                    operation_id,
                    context_sha256,
                    json.dumps(canonical_context, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False),
                    job_key,
                    expected_content_sha256,
                    started_at,
                    expected_content_sha256,
                    old_canonical_content_sha256,
                    str(current[1]),
                    old_raw_bytes,
                    old_object_sha256,
                ),
            )
            conn.commit()
        loaded = self.refresh_transition(operation_id, context_sha256=context_sha256)
        assert loaded is not None
        return loaded

    def start_vacancy_refresh_fetch(self, refresh_id: str) -> None:
        """Durably enter the irreducible official-fetch window before I/O."""

        with closing(self.connect()) as conn, conn:
            _validate_legacy_dispositions(conn)
            row = conn.execute(
                f"SELECT {_REFRESH_SELECT} FROM vacancy_refreshes WHERE refresh_id=?",
                (refresh_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown vacancy refresh: {refresh_id}")
            transition = _refresh_transition_from_row(row)
            if transition["status"] != "intent":
                raise VacancyRefreshConflict("refresh fetch window was already entered")
            cursor = conn.execute(
                """UPDATE vacancy_refreshes SET status='fetch_started',
                     updated_at=CURRENT_TIMESTAMP
                   WHERE refresh_id=? AND status='intent'""",
                (refresh_id,),
            )
            if cursor.rowcount != 1:
                raise VacancyRefreshConflict("refresh fetch window was claimed concurrently")

    def mark_vacancy_refresh_indeterminate(self, refresh_id: str) -> None:
        """Seal an unresolved fetch window so it can never auto-refetch."""

        with closing(self.connect()) as conn, conn:
            _validate_legacy_dispositions(conn)
            row = conn.execute(
                f"SELECT {_REFRESH_SELECT} FROM vacancy_refreshes WHERE refresh_id=?",
                (refresh_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown vacancy refresh: {refresh_id}")
            transition = _refresh_transition_from_row(row)
            if transition["status"] == "indeterminate":
                return
            if transition["status"] != "fetch_started":
                raise VacancyRefreshConflict("only an unresolved fetch can be indeterminate")
            conn.execute(
                """UPDATE vacancy_refreshes SET status='indeterminate',
                     updated_at=CURRENT_TIMESTAMP
                   WHERE refresh_id=? AND status='fetch_started'""",
                (refresh_id,),
            )

    def record_vacancy_refresh_fetch(
        self,
        refresh_id: str,
        *,
        new_raw_bytes: bytes,
    ) -> None:
        """Journal fetched bytes before any content-object or posting update."""

        new_raw = raw_posting_from_bytes(new_raw_bytes)
        new_content_sha256 = raw_posting_content_sha256(new_raw)
        new_object_sha256 = hashlib.sha256(new_raw_bytes).hexdigest()
        with closing(self.connect()) as conn, conn:
            _validate_legacy_dispositions(conn)
            current = conn.execute(
                f"SELECT {_REFRESH_SELECT} FROM vacancy_refreshes WHERE refresh_id=?",
                (refresh_id,),
            ).fetchone()
            if current is None:
                raise KeyError(f"unknown vacancy refresh: {refresh_id}")
            transition = _refresh_transition_from_row(current)
            if transition["job_key"] != new_raw.key:
                raise ValueError("fetched response differs from refresh vacancy")
            if transition["status"] != "fetch_started":
                if (
                    transition["new_raw_bytes"] != new_raw_bytes
                    or transition["new_object_sha256"] != new_object_sha256
                ):
                    raise VacancyRefreshConflict("refresh fetch bytes were substituted")
                return
            conn.execute(
                """UPDATE vacancy_refreshes SET status='fetched',
                     new_content_sha256=?,new_fetched_at=?,new_raw_bytes=?,
                     new_object_sha256=?,updated_at=CURRENT_TIMESTAMP
                   WHERE refresh_id=? AND status='fetch_started'""",
                (
                    new_content_sha256,
                    new_raw.fetched_at,
                    new_raw_bytes,
                    new_object_sha256,
                    refresh_id,
                ),
            )

    def mark_vacancy_refresh_object_ready(
        self,
        refresh_id: str,
        *,
        object_sha256: str,
    ) -> None:
        """Record that the journalled new response has a durable CAS object."""

        with closing(self.connect()) as conn, conn:
            _validate_legacy_dispositions(conn)
            row = conn.execute(
                f"SELECT {_REFRESH_SELECT} FROM vacancy_refreshes WHERE refresh_id=?",
                (refresh_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown vacancy refresh: {refresh_id}")
            transition = _refresh_transition_from_row(row)
            if transition["new_object_sha256"] != object_sha256:
                raise VacancyRefreshConflict("refresh object identity was substituted")
            if transition["status"] in ("object_ready", "committed"):
                return
            if transition["status"] != "fetched":
                raise VacancyRefreshConflict("refresh object cannot precede fetched bytes")
            conn.execute(
                """UPDATE vacancy_refreshes SET status='object_ready',
                     updated_at=CURRENT_TIMESTAMP
                   WHERE refresh_id=? AND status='fetched'""",
                (refresh_id,),
            )

    def seal_vacancy_refresh(
        self,
        refresh_id: str,
        *,
        receipt_basis: Mapping[str, object],
    ) -> dict[str, object]:
        """CAS the posting and seal its replayable receipt basis atomically."""

        with closing(self.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            _validate_legacy_dispositions(conn)
            row = conn.execute(
                f"SELECT {_REFRESH_SELECT} FROM vacancy_refreshes WHERE refresh_id=?",
                (refresh_id,),
            ).fetchone()
            if row is None:
                conn.rollback()
                raise KeyError(f"unknown vacancy refresh: {refresh_id}")
            transition = _refresh_transition_from_row(row)
            if transition["status"] == "committed":
                conn.rollback()
                receipt = transition["receipt_basis"]
                assert isinstance(receipt, dict)
                return receipt
            if transition["status"] != "object_ready":
                conn.rollback()
                raise VacancyRefreshConflict("refresh object is not ready for CAS")
            new_raw_bytes = bytes(transition["new_raw_bytes"])
            new_raw = raw_posting_from_bytes(new_raw_bytes)
            current = conn.execute(
                "SELECT content_hash,fetch_status FROM postings WHERE key=?",
                (transition["job_key"],),
            ).fetchone()
            if (
                current is None
                or current[1] != "fetched"
                or current[0] != transition["expected_content_sha256"]
            ):
                conn.rollback()
                raise VacancyRefreshConflict(
                    f"vacancy changed before refresh commit: {transition['job_key']}"
                )
            raw_json = (
                json.dumps(new_raw.raw_json, ensure_ascii=False)
                if new_raw.raw_json is not None
                else None
            )
            cursor = conn.execute(
                """UPDATE postings SET url=?,fetched_at=?,raw_text=?,raw_json=?,
                     content_hash=?,fetch_status='fetched',fetch_error=NULL
                   WHERE key=? AND fetch_status='fetched' AND content_hash=?""",
                (
                    new_raw.url,
                    new_raw.fetched_at,
                    new_raw.raw_text,
                    raw_json,
                    transition["new_content_sha256"],
                    transition["job_key"],
                    transition["expected_content_sha256"],
                ),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                raise VacancyRefreshConflict(
                    f"vacancy changed before refresh commit: {transition['job_key']}"
                )
            self._record_raw_snapshot(
                conn,
                new_raw,
                content_sha256=str(transition["new_content_sha256"]),
                exact_raw_bytes=new_raw_bytes,
            )
            state = self._collection_state_from_connection(conn)
            basis = {
                **dict(receipt_basis),
                "changed": (
                    transition["new_content_sha256"]
                    != transition["old_canonical_content_sha256"]
                ),
                "new_content_sha256": transition["new_content_sha256"],
                "new_fetched_at": transition["new_fetched_at"],
                "new_raw_object_sha256": transition["new_object_sha256"],
                "old_content_sha256": transition["old_content_sha256"],
                "old_canonical_content_sha256": transition[
                    "old_canonical_content_sha256"
                ],
                "old_fetched_at": transition["old_fetched_at"],
                "old_raw_object_sha256": transition["old_object_sha256"],
                "state_sha256": _canonical_hash(state),
            }
            receipt_basis_sha256 = _canonical_hash(basis)
            transition_value = {
                **transition,
                "receipt_basis_sha256": receipt_basis_sha256,
                "status": "committed",
            }
            transition_sha256 = _canonical_hash(
                _refresh_transition_document(transition_value)
            )
            basis = {
                **basis,
                "receipt_basis_sha256": receipt_basis_sha256,
                "transition_sha256": transition_sha256,
            }
            encoded = json.dumps(
                basis,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            conn.execute(
                """UPDATE vacancy_refreshes SET status='committed',
                     receipt_basis_json=?,receipt_basis_sha256=?,transition_sha256=?,
                     updated_at=CURRENT_TIMESTAMP
                   WHERE refresh_id=? AND status='object_ready'""",
                (encoded, receipt_basis_sha256, transition_sha256, refresh_id),
            )
            committed = {
                **transition,
                "status": "committed",
                "receipt_basis": basis,
                "receipt_basis_sha256": receipt_basis_sha256,
                "transition_sha256": transition_sha256,
            }
            _validate_refresh_transition(committed)
            conn.commit()
        return basis

    def record_error(self, key: str, message: str) -> None:
        with closing(self.connect()) as conn, conn:
            conn.execute("UPDATE postings SET fetch_status='error',fetch_error=? WHERE key=?",
                         (message[:2000], key))

    def mark_source(self, board: str, error: str | None = None) -> None:
        with closing(self.connect()) as conn, conn:
            conn.execute(
                """INSERT INTO source_state(board,last_polled_at,last_error)
                   VALUES(?,CURRENT_TIMESTAMP,?) ON CONFLICT(board) DO UPDATE SET
                   last_polled_at=CURRENT_TIMESTAMP,last_error=excluded.last_error""",
                (board, error),
            )

    def source_due(self, board: str, minimum_minutes: float) -> bool:
        with closing(self.connect()) as conn, conn:
            row = conn.execute("SELECT last_polled_at FROM source_state WHERE board=?", (board,)).fetchone()
        if not row or not row[0]:
            return True
        last = datetime.fromisoformat(str(row[0])).replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - last).total_seconds() >= minimum_minutes * 60

    def boards_with_pending_discoveries(self, boards: Iterable[str]) -> set[str]:
        """Boards whose discovered URLs still need their complete detail page.

        This makes a killed/interrupted cycle resumable immediately instead of
        stranding URLs until the source's normal polling interval elapses.
        """
        selected = [str(board) for board in boards]
        if not selected:
            return set()
        placeholders = ",".join("?" for _ in selected)
        with closing(self.connect()) as conn, conn:
            rows = conn.execute(
                f"SELECT DISTINCT board FROM postings WHERE fetch_status!='fetched' "
                f"AND board IN ({placeholders})",
                selected,
            ).fetchall()
        return {str(row[0]) for row in rows}

    def export_urls(self, path: str | Path) -> int:
        with closing(self.connect()) as conn, conn:
            rows = [JobUrl(board=r[0], job_id=r[1], url=r[2], posted_at=r[3]) for r in
                    conn.execute("SELECT board,job_id,url,posted_at FROM postings ORDER BY first_seen_at,key")]
        return write_jsonl(path, rows)

    def import_existing(self, urls_path: str | Path, raw_cache: str | Path) -> tuple[int, int]:
        return self.import_existing_roots(urls_path, [raw_cache])

    def import_existing_roots(
        self,
        urls_path: str | Path,
        raw_cache_roots: Iterable[str | Path],
    ) -> tuple[int, int]:
        urls = Path(urls_path)
        added = fetched = 0
        if urls.exists():
            for row in read_jsonl(urls, JobUrl):
                added += int(self.upsert_discovered(row))
        for row in iter_raw_cache_roots(raw_cache_roots):
            if not self.has_raw(row.key):
                if self.upsert_discovered(JobUrl(row.board, row.job_id, row.url)):
                    added += 1
                self.store_raw(row)
                fetched += 1
        return added, fetched

    def sync_jsonl(self, path: str | Path, table: str, json_column: str) -> int:
        if table not in {"normalised_jobs", "scores"}:
            raise ValueError(table)
        source = Path(path)
        if not source.exists():
            return 0
        count = 0
        with closing(self.connect()) as conn, conn:
            for row in read_jsonl(source):
                key = f"{row.get('board')}:{row.get('job_id')}"
                conn.execute(
                    f"INSERT INTO {table}(key,{json_column}) VALUES(?,?) "
                    f"ON CONFLICT(key) DO UPDATE SET {json_column}=excluded.{json_column}",
                    (key, json.dumps(row, ensure_ascii=False)),
                )
                count += 1
        return count

    def stats(self) -> dict[str, int]:
        with closing(self.connect()) as conn, conn:
            total = conn.execute("SELECT COUNT(*) FROM postings").fetchone()[0]
            fetched = conn.execute("SELECT COUNT(*) FROM postings WHERE fetch_status='fetched'").fetchone()[0]
            normalized = conn.execute("SELECT COUNT(*) FROM normalised_jobs").fetchone()[0]
            scored = conn.execute("SELECT COUNT(*) FROM scores").fetchone()[0]
        return {"postings": total, "fetched": fetched, "normalized": normalized, "scored": scored}

    def collection_state(self) -> dict[str, object]:
        """Return a deterministic projection of resumable collection state."""

        with closing(self.connect()) as conn:
            return self._collection_state_from_connection(conn)

    @staticmethod
    def _collection_state_from_connection(
        conn: sqlite3.Connection,
    ) -> dict[str, object]:
        postings = [
            {
                "board": row[0],
                "job_id": row[1],
                "url": row[2],
                "content_hash": row[3],
                "fetch_status": row[4],
                "fetch_error": row[5],
            }
            for row in conn.execute(
                """SELECT board,job_id,url,content_hash,fetch_status,fetch_error
                   FROM postings ORDER BY board,job_id"""
            )
        ]
        sources = [
            {
                "board": row[0],
                "last_polled_at": row[1],
                "last_error": row[2],
            }
            for row in conn.execute(
                """SELECT board,last_polled_at,last_error
                   FROM source_state ORDER BY board"""
            )
        ]
        return {
            "postings": postings,
            "schema_version": "market-aligner.collection-state.v1",
            "sources": sources,
        }

    def promote_fetched_from(
        self,
        source_path: str | Path,
        *,
        config_sha256: str,
        job_key: str | None = None,
    ) -> dict[str, object]:
        """Atomically copy a verified collector snapshot into canonical processing state."""

        source = Path(source_path).expanduser().resolve()
        target = self.path.expanduser().resolve()
        if len(config_sha256) != 64:
            raise ValueError("promotion config hash must be SHA-256")
        if job_key is not None and (not job_key or ":" not in job_key):
            raise ValueError("promotion job key must be board-qualified")
        if not source.is_file():
            raise FileNotFoundError(f"collector database does not exist: {source}")

        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=30)) as src:
            src.execute("PRAGMA query_only=ON")
            src.execute("BEGIN")
            columns = {str(row[1]) for row in src.execute("PRAGMA table_info(postings)")}
            required = {
                "key", "board", "job_id", "url", "posted_at", "first_seen_at",
                "last_seen_at", "fetched_at", "raw_text", "raw_json", "content_hash",
                "fetch_status", "fetch_error",
            }
            if not required <= columns:
                raise ValueError(
                    f"collector postings schema missing columns: {sorted(required - columns)}"
                )
            schema = [
                {"name": row[1], "sql": row[3], "table": row[2], "type": row[0]}
                for row in src.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master "
                    "WHERE sql IS NOT NULL ORDER BY type,name"
                )
            ]
            key_where = " WHERE key=?" if job_key is not None else ""
            key_params: tuple[object, ...] = (job_key,) if job_key is not None else ()
            status_counts = {
                str(row[0]): int(row[1])
                for row in src.execute(
                    f"SELECT fetch_status,COUNT(*) FROM postings{key_where} "
                    "GROUP BY fetch_status",
                    key_params,
                )
            }
            rows = [
                {
                    "key": row[0],
                    "board": row[1],
                    "job_id": row[2],
                    "url": row[3],
                    "posted_at": row[4],
                    "first_seen_at": row[5],
                    "last_seen_at": row[6],
                    "fetched_at": row[7],
                    "raw_text": row[8],
                    "raw_json": row[9],
                    "content_hash": row[10],
                }
                for row in src.execute(
                    """SELECT key,board,job_id,url,posted_at,first_seen_at,last_seen_at,
                              fetched_at,raw_text,raw_json,content_hash
                       FROM postings WHERE fetch_status='fetched' AND content_hash IS NOT NULL
                       """ + (" AND key=?" if job_key is not None else "") + " ORDER BY key",
                    key_params,
                )
            ]
            if job_key is not None and sum(status_counts.values()) != 1:
                raise KeyError(f"collector database has no exact vacancy: {job_key}")
            if job_key is not None and not rows:
                raise ValueError(f"exact collector vacancy is not fetched: {job_key}")
            for row in rows:
                if row["key"] != f"{row['board']}:{row['job_id']}":
                    raise ValueError(f"collector row has inconsistent identity: {row['key']}")
                if row["raw_json"] is not None and not isinstance(json.loads(row["raw_json"]), dict):
                    raise ValueError(f"collector raw JSON must be an object: {row['key']}")
                material = str(row["raw_text"] or "") + str(row["raw_json"] or "")
                digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
                if digest != row["content_hash"]:
                    raise ValueError(f"collector content hash mismatch: {row['key']}")
            src.commit()

        schema_sha256 = _canonical_hash(schema)
        content_sha256 = _canonical_hash(rows)
        path_sha256 = hashlib.sha256(str(source).encode("utf-8")).hexdigest()
        source_db_sha256 = _canonical_hash(
            {
                "content_sha256": content_sha256,
                "path_sha256": path_sha256,
                "schema_sha256": schema_sha256,
            }
        )
        imported = updated = unchanged = 0
        if source == target:
            unchanged = len(rows)
        else:
            with closing(self.connect()) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                for row in rows:
                    existing = conn.execute(
                        "SELECT content_hash FROM postings WHERE key=?", (row["key"],)
                    ).fetchone()
                    if existing is None:
                        imported += 1
                    elif existing[0] == row["content_hash"]:
                        unchanged += 1
                    else:
                        updated += 1
                    conn.execute(
                        """INSERT INTO postings(
                             key,board,job_id,url,posted_at,first_seen_at,last_seen_at,fetched_at,
                             raw_text,raw_json,content_hash,fetch_status,fetch_error
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,'fetched',NULL)
                           ON CONFLICT(key) DO UPDATE SET
                             board=excluded.board,job_id=excluded.job_id,url=excluded.url,
                             posted_at=COALESCE(excluded.posted_at,postings.posted_at),
                             last_seen_at=excluded.last_seen_at,fetched_at=excluded.fetched_at,
                             raw_text=excluded.raw_text,raw_json=excluded.raw_json,
                             content_hash=excluded.content_hash,fetch_status='fetched',fetch_error=NULL""",
                        (
                            row["key"], row["board"], row["job_id"], row["url"],
                            row["posted_at"], row["first_seen_at"], row["last_seen_at"],
                            row["fetched_at"], row["raw_text"], row["raw_json"],
                            row["content_hash"],
                        ),
                    )
        result: dict[str, object] = {
            "application_authority": False,
            "authority_scope": "state_promotion_only",
            "config_sha256": config_sha256,
            "eligible_fetched": len(rows),
            "excluded_discovered": status_counts.get("discovered", 0),
            "excluded_error": status_counts.get("error", 0),
            "imported": imported,
            "schema_version": "market-aligner.collection-promotion.v1",
            "source_content_sha256": content_sha256,
            "source_db_sha256": source_db_sha256,
            "source_path_sha256": path_sha256,
            "source_schema_sha256": schema_sha256,
            "source_total": sum(status_counts.values()),
            "unchanged": unchanged,
            "updated": updated,
        }
        if job_key is not None:
            result["job_key"] = job_key
        return result

    def claim_fetched_for_processing(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        worker_id: str,
        limit: int,
        lease_seconds: int = 900,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
        exact_job_key: str | None = None,
    ) -> list[RawPosting]:
        """Atomically lease one shard of current fetched snapshots."""

        if limit <= 0 or lease_seconds <= 0:
            raise ValueError("processing shard and lease must be positive")
        now = time.time()
        lease_until = now + lease_seconds
        scope_sql, scope_params = _processing_scope_sql(
            include_boards=include_boards,
            exclude_boards=exclude_boards,
            max_total=max_total,
            exact_job_key=exact_job_key,
        )
        claimed: list[RawPosting] = []
        with closing(self.connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                f"""WITH scoped AS ({scope_sql})
                   SELECT p.key,p.board,p.job_id,p.url,p.fetched_at,p.raw_text,
                          p.raw_json,p.content_hash
                   FROM scoped p
                   LEFT JOIN processing_jobs q
                     ON q.profile_id=? AND q.track=? AND q.job_key=p.key
                    AND q.authority_sha256=? AND q.source_content_sha256=p.content_hash
                    AND q.processing_config_sha256=?
                   WHERE p.fetch_status='fetched' AND p.content_hash IS NOT NULL
                     AND (q.status IS NULL OR q.status='failed'
                          OR (q.status='leased' AND q.lease_until<?))
                   ORDER BY p.key LIMIT ?""",
                (
                    *scope_params, profile_id, track, authority_sha256,
                    processing_config_sha256, now, limit,
                ),
            ).fetchall()
            for row in rows:
                conn.execute(
                    """INSERT INTO processing_jobs(
                         profile_id,track,job_key,authority_sha256,source_content_sha256,
                         processing_config_sha256,status,lease_owner,lease_until,
                         result_json,error
                       ) VALUES(?,?,?,?,?,?,'leased',?,?,NULL,NULL)
                       ON CONFLICT(
                         profile_id,track,job_key,authority_sha256,source_content_sha256,
                         processing_config_sha256
                       )
                       DO UPDATE SET status='leased',lease_owner=excluded.lease_owner,
                         lease_until=excluded.lease_until,result_json=NULL,error=NULL,
                         updated_at=CURRENT_TIMESTAMP""",
                    (
                        profile_id,
                        track,
                        row[0],
                        authority_sha256,
                        row[7],
                        processing_config_sha256,
                        worker_id,
                        lease_until,
                    ),
                )
                claimed.append(
                    RawPosting(
                        board=row[1],
                        job_id=row[2],
                        url=row[3],
                        fetched_at=row[4] or "",
                        raw_text=row[5],
                        raw_json=json.loads(row[6]) if row[6] else None,
                        content_sha256=row[7],
                    )
                )
        return claimed

    def complete_processing(
        self,
        *,
        profile_id: str,
        track: str,
        job_key: str,
        authority_sha256: str,
        source_content_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        worker_id: str,
        result: dict[str, object],
    ) -> None:
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with closing(self.connect()) as conn, conn:
            cursor = conn.execute(
                """UPDATE processing_jobs SET status='completed',lease_owner=NULL,
                     lease_until=NULL,result_json=?,error=NULL,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND track=? AND job_key=? AND authority_sha256=?
                     AND source_content_sha256=? AND processing_config_sha256=?
                     AND status='leased' AND lease_owner=?""",
                (
                    payload,
                    profile_id,
                    track,
                    job_key,
                    authority_sha256,
                    source_content_sha256,
                    processing_config_sha256,
                    worker_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("processing completion requires the active shard lease")

    def fail_processing(
        self,
        *,
        profile_id: str,
        track: str,
        job_key: str,
        authority_sha256: str,
        source_content_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        worker_id: str,
        error: str,
    ) -> None:
        with closing(self.connect()) as conn, conn:
            cursor = conn.execute(
                """UPDATE processing_jobs SET status='failed',lease_owner=NULL,
                     lease_until=NULL,result_json=NULL,error=?,updated_at=CURRENT_TIMESTAMP
                   WHERE profile_id=? AND track=? AND job_key=? AND authority_sha256=?
                     AND source_content_sha256=? AND processing_config_sha256=?
                     AND status='leased' AND lease_owner=?""",
                (
                    error[:2000],
                    profile_id,
                    track,
                    job_key,
                    authority_sha256,
                    source_content_sha256,
                    processing_config_sha256,
                    worker_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("processing failure requires the active shard lease")

    def completed_processing(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
        exact_job_key: str | None = None,
    ) -> list[dict[str, object]]:
        scope_sql, scope_params = _processing_scope_sql(
            include_boards=include_boards,
            exclude_boards=exclude_boards,
            max_total=max_total,
            exact_job_key=exact_job_key,
        )
        with closing(self.connect()) as conn:
            rows = conn.execute(
                f"""WITH scoped AS ({scope_sql})
                   SELECT q.result_json FROM processing_jobs q
                   JOIN scoped p ON p.key=q.job_key
                    AND p.content_hash=q.source_content_sha256
                   WHERE q.profile_id=? AND q.track=? AND q.authority_sha256=?
                     AND q.processing_config_sha256=?
                     AND q.status='completed' AND q.result_json IS NOT NULL
                   ORDER BY q.job_key""",
                (
                    *scope_params, profile_id, track, authority_sha256,
                    processing_config_sha256,
                ),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def processing_scope_counts(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
        exact_job_key: str | None = None,
    ) -> dict[str, int]:
        """Return exact current-snapshot counts without changing excluded rows."""

        includes = tuple(include_boards)
        excludes = tuple(exclude_boards)
        scope_sql, scope_params = _processing_scope_sql(
            include_boards=includes,
            exclude_boards=excludes,
            max_total=max_total,
            exact_job_key=exact_job_key,
        )
        board_where, board_params = _processing_board_where(includes, excludes)
        now = time.time()
        with closing(self.connect()) as conn:
            fetched_total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM postings WHERE fetch_status='fetched' "
                    "AND content_hash IS NOT NULL"
                ).fetchone()[0]
            )
            board_eligible = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM postings p WHERE {board_where}", board_params
                ).fetchone()[0]
            )
            row = conn.execute(
                f"""WITH scoped AS ({scope_sql})
                    SELECT COUNT(*),
                      SUM(CASE WHEN q.status='completed' THEN 1 ELSE 0 END),
                      SUM(CASE WHEN q.status='leased' AND q.lease_until>=? THEN 1 ELSE 0 END),
                      SUM(CASE WHEN q.status='failed' THEN 1 ELSE 0 END),
                      SUM(CASE WHEN q.status IS NULL OR q.status='failed'
                                OR (q.status='leased' AND q.lease_until<?) THEN 1 ELSE 0 END)
                    FROM scoped p LEFT JOIN processing_jobs q
                     ON q.profile_id=? AND q.track=? AND q.job_key=p.key
                     AND q.authority_sha256=? AND q.source_content_sha256=p.content_hash
                     AND q.processing_config_sha256=?""",
                (
                    *scope_params, now, now, profile_id, track, authority_sha256,
                    processing_config_sha256,
                ),
            ).fetchone()
        scoped = int(row[0] or 0)
        return {
            "available": int(row[4] or 0),
            "board_eligible": board_eligible,
            "completed": int(row[1] or 0),
            "excluded_by_board": fetched_total - board_eligible,
            "excluded_by_limit": board_eligible - scoped,
            "failed": int(row[3] or 0),
            "fetched_total": fetched_total,
            "leased": int(row[2] or 0),
            "scope_eligible": scoped,
        }

    @contextmanager
    def processing_report_snapshot(
        self,
        *,
        profile_id: str,
        track: str,
        authority_sha256: str,
        processing_config_sha256: str = LEGACY_PROCESSING_CONFIG_SHA256,
        include_boards: Iterable[str] = (),
        exclude_boards: Iterable[str] = (),
        max_total: int | None = None,
        exact_job_key: str | None = None,
    ) -> Iterator[list[dict[str, object]]]:
        """Serialize canonical report snapshots across concurrent processing shards."""

        scope_sql, scope_params = _processing_scope_sql(
            include_boards=include_boards,
            exclude_boards=exclude_boards,
            max_total=max_total,
            exact_job_key=exact_job_key,
        )
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                rows = conn.execute(
                    f"""WITH scoped AS ({scope_sql})
                       SELECT q.result_json FROM processing_jobs q
                       JOIN scoped p ON p.key=q.job_key
                        AND p.content_hash=q.source_content_sha256
                       WHERE q.profile_id=? AND q.track=? AND q.authority_sha256=?
                         AND q.processing_config_sha256=?
                         AND q.status='completed' AND q.result_json IS NOT NULL
                       ORDER BY q.job_key""",
                    (
                        *scope_params, profile_id, track, authority_sha256,
                        processing_config_sha256,
                    ),
                ).fetchall()
                yield [json.loads(row[0]) for row in rows]
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    def reusable_processing_result(
        self,
        *,
        profile_id: str,
        track: str,
        job_key: str,
        authority_sha256: str,
        source_content_sha256: str,
        processing_config_sha256: str,
    ) -> dict[str, object] | None:
        """Return a prior exact-evidence result from another config identity.

        The caller must re-run all deterministic policy decisions.  This method
        only avoids repeating already accepted semantic extraction/alignment.
        """

        with closing(self.connect()) as conn:
            row = conn.execute(
                """SELECT result_json FROM processing_jobs
                   WHERE profile_id=? AND track=? AND job_key=?
                     AND authority_sha256=? AND source_content_sha256=?
                     AND processing_config_sha256!=?
                     AND status='completed' AND result_json IS NOT NULL
                   ORDER BY updated_at DESC, processing_config_sha256 DESC LIMIT 1""",
                (
                    profile_id, track, job_key, authority_sha256,
                    source_content_sha256, processing_config_sha256,
                ),
            ).fetchone()
        return None if row is None else json.loads(row[0])


def _processing_board_where(
    include_boards: Iterable[str],
    exclude_boards: Iterable[str],
    exact_job_key: str | None = None,
) -> tuple[str, tuple[object, ...]]:
    includes = tuple(sorted(set(include_boards)))
    excludes = tuple(sorted(set(exclude_boards)))
    conditions = ["p.fetch_status='fetched'", "p.content_hash IS NOT NULL"]
    params: list[object] = []
    if includes:
        conditions.append(f"p.board IN ({','.join('?' for _ in includes)})")
        params.extend(includes)
    if excludes:
        conditions.append(f"p.board NOT IN ({','.join('?' for _ in excludes)})")
        params.extend(excludes)
    if exact_job_key is not None:
        if not exact_job_key or ":" not in exact_job_key:
            raise ValueError("exact processing job key must be board-qualified")
        conditions.append("p.key=?")
        params.append(exact_job_key)
    return " AND ".join(conditions), tuple(params)


def _processing_scope_sql(
    *,
    include_boards: Iterable[str],
    exclude_boards: Iterable[str],
    max_total: int | None,
    exact_job_key: str | None = None,
) -> tuple[str, tuple[object, ...]]:
    if max_total is not None and max_total <= 0:
        raise ValueError("processing max_total must be positive when set")
    where, params = _processing_board_where(
        include_boards, exclude_boards, exact_job_key
    )
    return (
        f"SELECT p.* FROM postings p WHERE {where} ORDER BY p.key LIMIT ?",
        (*params, -1 if max_total is None else max_total),
    )
