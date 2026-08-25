"""Private exact-byte evidence and append-only issue records for canary runs.

Credential-bearing diagnostics are deliberately preserved exactly. They remain outside
Git in owner-private storage, every byte is content-addressed, and each technical or
quality issue is recorded in an append-only SQLite index. This module has no browser,
network, release, click, submission, or provider-success authority.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "jaa.canary-forensic-evidence.v1"
EVENT_SCHEMA_VERSION = "jaa.canary-forensic-event.v1"
MAX_SOURCE_BYTES = 64 * 1024 * 1024
ARTIFACT_FILENAME = "evidence.bin"
RECEIPT_FILENAME = "receipt.json"
INDEX_FILENAME = "forensic-index.sqlite3"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


class CanaryForensicEvidenceError(RuntimeError):
    """Exact canary evidence or its append-only index failed verification."""


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_document(value: object) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _token(value: str, label: str) -> str:
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _bounded_text(value: str, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
    ):
        raise ValueError(f"{label} is invalid")
    return value


POLICY_DOCUMENT = {
    "schema_version": SCHEMA_VERSION,
    "maximum_source_bytes": MAX_SOURCE_BYTES,
    "accepted_source": "single-link current-UID regular file",
    "archive": "content-addressed exact bytes outside Git",
    "archive_file_mode": "0600",
    "archive_directory_mode": "0700",
    "credential_policy": "retain exact local bytes; never emit them in reports",
    "index": "append-only technical failure and quality evidence",
    "instruction_authority": False,
    "provider_success_authority": False,
    "submission_authority": False,
}
POLICY_SHA256 = _sha256_document(POLICY_DOCUMENT)


@dataclass(frozen=True)
class CanaryForensicEvidenceReceipt:
    receipt_sha256: str
    source_locator_sha256: str
    exact_sha256: str
    exact_size_bytes: int
    source_mode: int
    media_type: str
    archive_directory: str
    policy_sha256: str = POLICY_SHA256
    schema_version: str = SCHEMA_VERSION
    exact_bytes_retained: bool = True
    credentials_may_be_present: bool = True
    owner_private: bool = True
    certifies_provider_success: bool = False
    submission_authority: bool = False

    def __post_init__(self) -> None:
        for value, label in (
            (self.receipt_sha256, "receipt hash"),
            (self.source_locator_sha256, "source locator hash"),
            (self.exact_sha256, "exact evidence hash"),
            (self.policy_sha256, "policy hash"),
        ):
            _digest(value, label)
        if self.archive_directory != self.receipt_sha256:
            raise ValueError("forensic archive directory must equal receipt identity")
        if (
            not isinstance(self.exact_size_bytes, int)
            or isinstance(self.exact_size_bytes, bool)
            or not 1 <= self.exact_size_bytes <= MAX_SOURCE_BYTES
        ):
            raise ValueError("exact evidence size is invalid")
        if not isinstance(self.source_mode, int) or not 0 <= self.source_mode <= 0o7777:
            raise ValueError("source mode is invalid")
        _bounded_text(self.media_type, "media type", 255)
        if (
            self.schema_version != SCHEMA_VERSION
            or self.policy_sha256 != POLICY_SHA256
            or self.exact_bytes_retained is not True
            or self.credentials_may_be_present is not True
            or self.owner_private is not True
            or self.certifies_provider_success is not False
            or self.submission_authority is not False
        ):
            raise ValueError("forensic evidence truth boundary is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": self.schema_version,
            "source_locator_sha256": self.source_locator_sha256,
            "exact_sha256": self.exact_sha256,
            "exact_size_bytes": self.exact_size_bytes,
            "source_mode": self.source_mode,
            "media_type": self.media_type,
            "policy_sha256": self.policy_sha256,
            "exact_bytes_retained": True,
            "credentials_may_be_present": True,
            "owner_private": True,
            "certifies_provider_success": False,
            "submission_authority": False,
        }
        if include_identity:
            document["receipt_sha256"] = self.receipt_sha256
            document["archive_directory"] = self.archive_directory
        return document


@dataclass(frozen=True)
class CanaryForensicEvent:
    sequence: int
    event_sha256: str
    recorded_at: str
    cycle_id: str
    stage: str
    issue_code: str
    summary: str
    technical_detail: str
    evidence_receipt_sha256: str
    exact_evidence_sha256: str
    schema_version: str = EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 1
        ):
            raise ValueError("forensic event sequence is invalid")
        _digest(self.event_sha256, "forensic event hash")
        _digest(self.evidence_receipt_sha256, "forensic evidence receipt hash")
        _digest(self.exact_evidence_sha256, "exact forensic evidence hash")
        if not isinstance(self.recorded_at, str) or not RFC3339_UTC.fullmatch(
            self.recorded_at
        ):
            raise ValueError("forensic event time must be RFC3339 UTC")
        _token(self.cycle_id, "cycle ID")
        _token(self.stage, "canary stage")
        _token(self.issue_code, "issue code")
        _bounded_text(self.summary, "event summary", 4_096)
        _bounded_text(self.technical_detail, "event technical detail", 65_536)
        if self.schema_version != EVENT_SCHEMA_VERSION:
            raise ValueError("forensic event schema is invalid")


def _event_document(
    *,
    recorded_at: str,
    cycle_id: str,
    stage: str,
    issue_code: str,
    summary: str,
    technical_detail: str,
    receipt: CanaryForensicEvidenceReceipt,
) -> dict[str, str]:
    document = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "recorded_at": recorded_at,
        "cycle_id": cycle_id,
        "stage": stage,
        "issue_code": issue_code,
        "summary": summary,
        "technical_detail": technical_detail,
        "evidence_receipt_sha256": receipt.receipt_sha256,
        "exact_evidence_sha256": receipt.exact_sha256,
    }
    CanaryForensicEvent(sequence=1, event_sha256="0" * 64, **document)
    return document


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _private_root(root: str | Path, repository_root: str | Path, *, create: bool) -> Path:
    repository = Path(repository_root).resolve(strict=True)
    if not repository.is_dir():
        raise CanaryForensicEvidenceError("repository root is invalid")
    candidate = Path(root)
    if candidate.exists() and candidate.is_symlink():
        raise CanaryForensicEvidenceError("forensic root cannot be a symlink")
    parent = candidate.parent.resolve(strict=True)
    resolved = parent / candidate.name
    if _overlaps(resolved, repository):
        raise CanaryForensicEvidenceError("forensic evidence must remain outside Git")
    if create and not resolved.exists():
        resolved.mkdir(mode=0o700)
        os.chmod(resolved, 0o700)
    try:
        entry = os.lstat(resolved)
    except FileNotFoundError as exc:
        raise CanaryForensicEvidenceError("forensic root is absent") from exc
    if (
        not stat.S_ISDIR(entry.st_mode)
        or entry.st_uid != os.getuid()
        or stat.S_IMODE(entry.st_mode) != 0o700
        or resolved.resolve(strict=True) != resolved
    ):
        raise CanaryForensicEvidenceError("forensic root must be current-UID mode 0700")
    return resolved


def _read_descriptor_exact(descriptor: int, metadata: os.stat_result) -> bytes:
    body = bytearray()
    while len(body) < metadata.st_size:
        chunk = os.read(descriptor, min(1024 * 1024, metadata.st_size - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    if len(body) != metadata.st_size or os.read(descriptor, 1):
        raise CanaryForensicEvidenceError("forensic file changed during read")
    return bytes(body)


def _read_source(path: str | Path) -> tuple[Path, bytes, os.stat_result]:
    source = Path(path)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_SOURCE_BYTES
        ):
            raise CanaryForensicEvidenceError("forensic source file is unsafe or oversized")
        body = _read_descriptor_exact(descriptor, before)
        after = os.fstat(descriptor)
        entry = os.lstat(source)
        identity = (before.st_dev, before.st_ino, before.st_size)
        if identity != (after.st_dev, after.st_ino, after.st_size) or identity != (
            entry.st_dev,
            entry.st_ino,
            entry.st_size,
        ):
            raise CanaryForensicEvidenceError("forensic source changed during read")
        return source, body, before
    finally:
        os.close(descriptor)


def _write_private(path: Path, body: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(body)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _make_receipt(
    source: Path,
    source_bytes: bytes,
    source_metadata: os.stat_result,
    media_type: str,
) -> CanaryForensicEvidenceReceipt:
    core = {
        "schema_version": SCHEMA_VERSION,
        "source_locator_sha256": _sha256_bytes(str(source.absolute()).encode("utf-8")),
        "exact_sha256": _sha256_bytes(source_bytes),
        "exact_size_bytes": len(source_bytes),
        "source_mode": stat.S_IMODE(source_metadata.st_mode),
        "media_type": _bounded_text(media_type, "media type", 255),
        "policy_sha256": POLICY_SHA256,
        "exact_bytes_retained": True,
        "credentials_may_be_present": True,
        "owner_private": True,
        "certifies_provider_success": False,
        "submission_authority": False,
    }
    identity = _sha256_document(core)
    return CanaryForensicEvidenceReceipt(
        receipt_sha256=identity,
        archive_directory=identity,
        source_locator_sha256=str(core["source_locator_sha256"]),
        exact_sha256=str(core["exact_sha256"]),
        exact_size_bytes=int(core["exact_size_bytes"]),
        source_mode=int(core["source_mode"]),
        media_type=str(core["media_type"]),
    )


def _read_private_archive_file(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise CanaryForensicEvidenceError("forensic archive file is unsafe")
        body = _read_descriptor_exact(descriptor, before)
        after = os.fstat(descriptor)
        entry = os.lstat(path)
        identity = (before.st_dev, before.st_ino, before.st_size)
        if identity != (after.st_dev, after.st_ino, after.st_size) or identity != (
            entry.st_dev,
            entry.st_ino,
            entry.st_size,
        ):
            raise CanaryForensicEvidenceError("forensic archive file identity changed")
        return body
    finally:
        os.close(descriptor)


def _receipt_from_bytes(receipt_bytes: bytes) -> CanaryForensicEvidenceReceipt:
    try:
        document = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanaryForensicEvidenceError("forensic receipt is invalid JSON") from exc
    expected = {
        "archive_directory",
        "certifies_provider_success",
        "credentials_may_be_present",
        "exact_bytes_retained",
        "exact_sha256",
        "exact_size_bytes",
        "media_type",
        "owner_private",
        "policy_sha256",
        "receipt_sha256",
        "schema_version",
        "source_locator_sha256",
        "source_mode",
        "submission_authority",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise CanaryForensicEvidenceError("forensic receipt schema differs")
    try:
        receipt = CanaryForensicEvidenceReceipt(
            receipt_sha256=document["receipt_sha256"],
            source_locator_sha256=document["source_locator_sha256"],
            exact_sha256=document["exact_sha256"],
            exact_size_bytes=document["exact_size_bytes"],
            source_mode=document["source_mode"],
            media_type=document["media_type"],
            archive_directory=document["archive_directory"],
            policy_sha256=document["policy_sha256"],
            schema_version=document["schema_version"],
            exact_bytes_retained=document["exact_bytes_retained"],
            credentials_may_be_present=document["credentials_may_be_present"],
            owner_private=document["owner_private"],
            certifies_provider_success=document["certifies_provider_success"],
            submission_authority=document["submission_authority"],
        )
    except (TypeError, ValueError) as exc:
        raise CanaryForensicEvidenceError("forensic receipt fields are invalid") from exc
    if _canonical_json(document).encode("utf-8") + b"\n" != receipt_bytes:
        raise CanaryForensicEvidenceError("forensic receipt bytes are noncanonical")
    if _sha256_document(receipt.document(include_identity=False)) != receipt.receipt_sha256:
        raise CanaryForensicEvidenceError("forensic receipt self-hash differs")
    return receipt


def verify_exact_canary_evidence(
    root: str | Path,
    repository_root: str | Path,
    receipt_sha256: str,
) -> tuple[CanaryForensicEvidenceReceipt, bytes]:
    _digest(receipt_sha256, "forensic receipt identity")
    archive_root = _private_root(root, repository_root, create=False)
    directory = archive_root / receipt_sha256
    try:
        directory_entry = os.lstat(directory)
    except FileNotFoundError as exc:
        raise CanaryForensicEvidenceError("forensic archive directory is absent") from exc
    if (
        not stat.S_ISDIR(directory_entry.st_mode)
        or directory_entry.st_uid != os.getuid()
        or stat.S_IMODE(directory_entry.st_mode) != 0o700
    ):
        raise CanaryForensicEvidenceError("forensic archive directory is unsafe")
    if {path.name for path in directory.iterdir()} != {ARTIFACT_FILENAME, RECEIPT_FILENAME}:
        raise CanaryForensicEvidenceError("forensic archive inventory differs")
    artifact = _read_private_archive_file(directory / ARTIFACT_FILENAME)
    receipt_bytes = _read_private_archive_file(directory / RECEIPT_FILENAME)
    receipt = _receipt_from_bytes(receipt_bytes)
    if (
        receipt.receipt_sha256 != receipt_sha256
        or receipt.archive_directory != directory.name
        or receipt.exact_size_bytes != len(artifact)
        or receipt.exact_sha256 != _sha256_bytes(artifact)
    ):
        raise CanaryForensicEvidenceError("forensic archive identity differs")
    return receipt, artifact


def archive_exact_canary_evidence(
    source_path: str | Path,
    *,
    root: str | Path,
    repository_root: str | Path,
    media_type: str = "application/octet-stream",
) -> CanaryForensicEvidenceReceipt:
    """Publish exact source bytes privately; exact replay verifies every byte."""
    source, source_bytes, source_metadata = _read_source(source_path)
    receipt = _make_receipt(source, source_bytes, source_metadata, media_type)
    archive_root = _private_root(root, repository_root, create=True)
    destination = archive_root / receipt.archive_directory
    if destination.exists():
        existing, artifact = verify_exact_canary_evidence(
            archive_root, repository_root, receipt.receipt_sha256
        )
        if existing != receipt or artifact != source_bytes:
            raise CanaryForensicEvidenceError("forensic replay differs")
        return existing
    stage = Path(tempfile.mkdtemp(prefix=".jaa-canary-forensic-", dir=archive_root))
    try:
        os.chmod(stage, 0o700)
        _write_private(stage / ARTIFACT_FILENAME, source_bytes)
        _write_private(
            stage / RECEIPT_FILENAME,
            _canonical_json(receipt.document()).encode("utf-8") + b"\n",
        )
        directory_descriptor = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        try:
            os.rename(stage, destination)
        except OSError as exc:
            if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY} or not destination.is_dir():
                raise
        root_descriptor = os.open(archive_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(root_descriptor)
        finally:
            os.close(root_descriptor)
        verified, artifact = verify_exact_canary_evidence(
            archive_root, repository_root, receipt.receipt_sha256
        )
        if verified != receipt or artifact != source_bytes:
            raise CanaryForensicEvidenceError("published forensic evidence differs")
        return verified
    finally:
        if stage.exists():
            shutil.rmtree(stage)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS canary_forensic_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_sha256 TEXT NOT NULL UNIQUE CHECK(length(event_sha256) = 64),
    recorded_at TEXT NOT NULL,
    cycle_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    issue_code TEXT NOT NULL,
    summary TEXT NOT NULL,
    technical_detail TEXT NOT NULL,
    evidence_receipt_sha256 TEXT NOT NULL CHECK(length(evidence_receipt_sha256) = 64),
    exact_evidence_sha256 TEXT NOT NULL CHECK(length(exact_evidence_sha256) = 64),
    schema_version TEXT NOT NULL CHECK(schema_version = 'jaa.canary-forensic-event.v1')
);
CREATE TRIGGER IF NOT EXISTS canary_forensic_events_no_update
BEFORE UPDATE ON canary_forensic_events BEGIN
    SELECT RAISE(ABORT, 'canary forensic events are immutable');
END;
CREATE TRIGGER IF NOT EXISTS canary_forensic_events_no_delete
BEFORE DELETE ON canary_forensic_events BEGIN
    SELECT RAISE(ABORT, 'canary forensic events are immutable');
END;
"""


def _open_index(root: Path) -> sqlite3.Connection:
    path = root / INDEX_FILENAME
    try:
        entry = os.lstat(path)
    except FileNotFoundError:
        entry = None
    if entry is not None:
        if (
            not stat.S_ISREG(entry.st_mode)
            or entry.st_uid != os.getuid()
            or entry.st_nlink != 1
            or stat.S_IMODE(entry.st_mode) != 0o600
        ):
            raise CanaryForensicEvidenceError("forensic index is unsafe")
    connection = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    try:
        os.chmod(path, 0o600)
        journal_mode = str(
            connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        ).lower()
        connection.execute("PRAGMA synchronous=FULL")
        synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        if journal_mode != "delete" or synchronous != 2:
            raise CanaryForensicEvidenceError("forensic index durability mode differs")
        connection.executescript("BEGIN IMMEDIATE;" + SCHEMA_SQL + "COMMIT;")
        return connection
    except Exception:
        connection.close()
        raise


def _row_for_event(connection: sqlite3.Connection, event_sha256: str) -> tuple[object, ...]:
    row = connection.execute(
        "SELECT sequence, event_sha256, recorded_at, cycle_id, stage, issue_code, "
        "summary, technical_detail, evidence_receipt_sha256, exact_evidence_sha256, "
        "schema_version FROM canary_forensic_events WHERE event_sha256 = ?",
        (event_sha256,),
    ).fetchone()
    if row is None:
        raise CanaryForensicEvidenceError("forensic event publication is absent")
    return row


def record_canary_forensic_event(
    source_path: str | Path,
    *,
    root: str | Path,
    repository_root: str | Path,
    recorded_at: str,
    cycle_id: str,
    stage: str,
    issue_code: str,
    summary: str,
    technical_detail: str,
    media_type: str = "application/octet-stream",
) -> CanaryForensicEvent:
    """Archive evidence and append one immutable technical or quality event."""
    if not isinstance(recorded_at, str) or not RFC3339_UTC.fullmatch(recorded_at):
        raise ValueError("forensic event time must be RFC3339 UTC")
    _token(cycle_id, "cycle ID")
    _token(stage, "canary stage")
    _token(issue_code, "issue code")
    _bounded_text(summary, "event summary", 4_096)
    _bounded_text(technical_detail, "event technical detail", 65_536)
    receipt = archive_exact_canary_evidence(
        source_path,
        root=root,
        repository_root=repository_root,
        media_type=media_type,
    )
    document = _event_document(
        recorded_at=recorded_at,
        cycle_id=cycle_id,
        stage=stage,
        issue_code=issue_code,
        summary=summary,
        technical_detail=technical_detail,
        receipt=receipt,
    )
    event_sha256 = _sha256_document(document)
    archive_root = _private_root(root, repository_root, create=True)
    connection = _open_index(archive_root)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute(
            "SELECT 1 FROM canary_forensic_events WHERE event_sha256 = ?",
            (event_sha256,),
        ).fetchone() is None:
            connection.execute(
                "INSERT INTO canary_forensic_events "
                "(event_sha256, recorded_at, cycle_id, stage, issue_code, summary, "
                "technical_detail, evidence_receipt_sha256, exact_evidence_sha256, schema_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_sha256,
                    document["recorded_at"],
                    document["cycle_id"],
                    document["stage"],
                    document["issue_code"],
                    document["summary"],
                    document["technical_detail"],
                    document["evidence_receipt_sha256"],
                    document["exact_evidence_sha256"],
                    document["schema_version"],
                ),
            )
        row = _row_for_event(connection, event_sha256)
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return CanaryForensicEvent(*row)


def list_canary_forensic_events(
    *, root: str | Path, repository_root: str | Path
) -> tuple[CanaryForensicEvent, ...]:
    """Read the append-only issue history in durable sequence order."""
    archive_root = _private_root(root, repository_root, create=False)
    connection = _open_index(archive_root)
    try:
        rows = connection.execute(
            "SELECT sequence, event_sha256, recorded_at, cycle_id, stage, issue_code, "
            "summary, technical_detail, evidence_receipt_sha256, exact_evidence_sha256, "
            "schema_version FROM canary_forensic_events ORDER BY sequence"
        ).fetchall()
    finally:
        connection.close()
    return tuple(CanaryForensicEvent(*row) for row in rows)
