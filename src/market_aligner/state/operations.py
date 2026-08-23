"""Durable, content-bound operation receipts for bounded collection cycles.

This journal is deliberately distinct from every other receipt in the product:
LLM receipts bind prompt/output values inside one process invocation, fetch
control binds individual sidecar fetch attempts, and vacancy storage binds
posting content. None of them can answer "has this exact configured operation
already reached a terminal outcome?" across processes. That cross-run identity
is what bounded collection commands need before they may touch a provider
again, so it owns one small lifecycle here.

Truthfulness rules enforced by this module:

* An operation is identified by content: the semantic SHA-256 of the fully
  merged configuration plus the explicit source scope. Identical content always
  yields the identical operation id; different content can never reuse an id.
* A run claims its operation with an exclusive ``in_flight`` record before any
  provider access. A later invocation that finds ``in_flight`` (a killed or a
  concurrent run) transitions it to ``indeterminate`` and refuses to proceed:
  whether the interrupted run already contacted providers is unknowable, so the
  command fails closed instead of claiming exactly-once behaviour.
* Terminal dispositions (``completed``, ``failed``) are final. Replaying a
  terminal operation is refused before any provider access, because discovery
  itself is a provider fetch and cannot be made exactly-once.
* Every record carries ``record_sha256`` over its own canonical body plus a
  derived ``receipt_id``; unreadable, retouched or substituted records are
  rejected before anything runs.
* Records live entirely under the external data home; nothing here deletes or
  rewrites provider data, so the last good database and raw cache survive every
  failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


OPERATION_SCHEMA = "market-aligner.operation-journal.v1"
INGEST_CYCLE_KIND = "ingest-cycle"

_TERMINAL_DISPOSITIONS = frozenset({"completed", "failed"})
_DISPOSITIONS = _TERMINAL_DISPOSITIONS | {"in_flight", "indeterminate"}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

_REQUIRED_FIELDS = (
    "schema",
    "operation_id",
    "kind",
    "config_sha256",
    "config_source",
    "data_home",
    "source_scope",
    "disposition",
    "started_at",
    "finished_at",
    "resolved_at",
    "result",
    "error",
    "note",
    "receipt_id",
    "record_sha256",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def derive_operation_id(kind: str, config_sha256: str, source_scope: Iterable[str]) -> str:
    """Bind operation identity to kind, config semantics and source scope."""
    scope = [str(board) for board in source_scope]
    return content_sha256(
        {
            "contract": OPERATION_SCHEMA,
            "kind": kind,
            "config_sha256": config_sha256,
            "source_scope": scope,
        }
    )


def receipt_identity(operation_id: str, disposition: str) -> str:
    return f"{operation_id}:{disposition}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class OperationRefused(RuntimeError):
    """A bounded operation was refused before or without provider access."""

    def __init__(
        self,
        reason: str,
        detail: str,
        *,
        operation_id: str | None = None,
        disposition: str | None = None,
    ) -> None:
        super().__init__(detail)
        self.reason = reason
        self.payload: dict[str, Any] = {
            "reason": reason,
            "detail": detail,
            "operation_id": operation_id,
            "disposition": disposition,
        }


def make_record(
    *,
    operation_id: str,
    kind: str,
    config_sha256: str,
    config_source: str,
    data_home: str,
    source_scope: Iterable[str],
    disposition: str,
    started_at: str | None = None,
    finished_at: str | None = None,
    resolved_at: str | None = None,
    result: dict[str, Any] | None = None,
    error: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    if disposition not in _DISPOSITIONS:
        raise ValueError(f"unknown disposition: {disposition}")
    if not _HEX64.fullmatch(operation_id):
        raise ValueError("operation_id must be a lowercase SHA-256 digest")
    record: dict[str, Any] = {
        "schema": OPERATION_SCHEMA,
        "operation_id": operation_id,
        "kind": kind,
        "config_sha256": config_sha256,
        "config_source": config_source,
        "data_home": data_home,
        "source_scope": [str(board) for board in source_scope],
        "disposition": disposition,
        "started_at": started_at or utc_now(),
        "finished_at": finished_at,
        "resolved_at": resolved_at,
        "result": result,
        "error": error,
        "note": note,
    }
    record["receipt_id"] = receipt_identity(record["operation_id"], disposition)
    record["record_sha256"] = content_sha256(record)
    return record


def verify_record(raw: Any) -> dict[str, Any]:
    """Reject unreadable, tampered or substituted records before any work."""
    if not isinstance(raw, dict):
        raise OperationRefused("tampered_receipt", "journal record is not an object")
    missing = [field for field in _REQUIRED_FIELDS if field not in raw]
    if missing:
        raise OperationRefused(
            "tampered_receipt", f"journal record is missing fields: {sorted(missing)}"
        )
    if raw["schema"] != OPERATION_SCHEMA:
        raise OperationRefused("tampered_receipt", "unsupported journal schema")
    if raw["disposition"] not in _DISPOSITIONS:
        raise OperationRefused(
            "tampered_receipt", f"unknown disposition: {raw['disposition']!r}"
        )
    if not isinstance(raw["operation_id"], str) or not _HEX64.fullmatch(raw["operation_id"]):
        raise OperationRefused("tampered_receipt", "operation_id is not a SHA-256 digest")
    expected_receipt = receipt_identity(raw["operation_id"], raw["disposition"])
    if raw["receipt_id"] != expected_receipt:
        raise OperationRefused(
            "receipt_substitution",
            f"receipt_id does not match operation and disposition; expected {expected_receipt}",
            operation_id=raw["operation_id"],
            disposition=raw["disposition"],
        )
    body = {key: value for key, value in raw.items() if key != "record_sha256"}
    if content_sha256(body) != raw["record_sha256"]:
        raise OperationRefused(
            "tampered_receipt",
            "journal content hash does not match its bound fields",
            operation_id=raw["operation_id"],
            disposition=raw["disposition"],
        )
    return raw


class OperationJournal:
    """File-per-operation receipt store beneath the external state directory."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, operation_id: str) -> Path:
        return self.root / f"{operation_id}.json"

    def load(self, operation_id: str) -> dict[str, Any] | None:
        path = self.path(operation_id)
        if not path.exists():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OperationRefused(
                "unreadable_journal", f"journal record {path.name} is unreadable: {exc}"
            ) from exc
        record = verify_record(raw)
        if record["operation_id"] != operation_id:
            raise OperationRefused(
                "operation_substitution",
                "journal record identity does not match its file name",
                operation_id=operation_id,
                disposition=record["disposition"],
            )
        return record

    def claim(self, record: dict[str, Any]) -> bool:
        """Exclusively create the in_flight record; False when already claimed."""
        verify_record(record)
        path = self.path(record["operation_id"])
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(canonical_json(record))
            handle.flush()
            os.fsync(handle.fileno())
        return True

    def update(self, record: dict[str, Any]) -> dict[str, Any]:
        """Atomically replace a record this run owns, rebinding its digest."""
        verify_record(record)
        destination = self.path(record["operation_id"])
        descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=self.root)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(canonical_json(record))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return record
