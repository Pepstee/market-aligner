"""Durable, content-bound operation receipts for bounded collection cycles.

This journal is deliberately distinct from every other receipt in the product:
LLM receipts bind prompt/output values inside one process invocation, fetch
control binds individual sidecar fetch attempts, and vacancy storage binds
posting content. None of them can answer across processes whether this exact,
operator-declared operation already reached a terminal outcome, so it owns one
small lifecycle here.

Truthfulness rules enforced by this module:

* Operation identity is an explicit, bounded opaque ``--operation-id`` supplied
  by the operator. The journal keys records by it and binds each record to the
  exact resolved configuration path, configuration file identity (SHA-256 of
  the raw file bytes), semantic SHA-256 of the fully merged configuration,
  canonical sorted source scope and exact resolved data home. The same ID with
  any changed binding is rejected before provider access; a different ID may
  run a later cycle against unchanged configuration.
* A scope-level exclusive lock spans blocker scan, claim, cycle and seal, so
  two different operation IDs for the same exact data home and source scope can
  never enter providers concurrently.
* A run claims its operation with an exclusive ``in_flight`` record carrying a
  random owner id before any provider access. Only that owner may seal a
  terminal outcome, through an expected-prior compare-and-set under an
  exclusive per-operation lock. Contenders never mutate anything: they receive
  a fail-closed ``in_progress`` refusal with unchanged bytes and zero provider
  calls. Death is never inferred from rediscovery.
* An unresolved (``in_flight``) or ``indeterminate`` external call stays
  fail-closed forever in this slice: it blocks new same-scope operations until
  a separately typed, evidence-bound authority contract exists. This module
  deliberately provides no reconciliation capability.
* Terminal dispositions are final. Replaying a terminal operation returns its
  recorded canonical receipt with ``replayed=true`` after reopening and
  re-verifying every binding — never a second provider fetch.
* Records are strict: an exact field set, duplicate-key rejection, typed
  fields, validated timestamps and state combinations, and canonical scope and
  result shapes. Consistently rehashed unknown-field or invalid-state
  substitutions are still rejected.
* Persistence is crash-durable and substitution-resistant: owner-private
  ``0700`` real directories (no symlinked roots or parents), ``0600``
  single-link regular files opened with ``O_NOFOLLOW`` and checked for exact
  mode, owner and link count, file plus parent-directory fsync on create and
  publish, atomic create-or-exact claims, and CAS terminalisation, so no
  partial final receipt can ever exist.

Honest integrity boundary: owner-private 0700 directories, 0600 single-link
files and unkeyed SHA-256 binding provide canonical identity and detect
accidental or noncoherent corruption. They do NOT authenticate evidence
against a malicious same-UID writer that rewrites content and recomputes every
public hash; this journal is not cryptographic authority and not complete
substitution resistance. Root-owned or signature-backed admission is a
separately governed future authority slice.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


OPERATION_SCHEMA = "market-aligner.operation-journal.v2"
INGEST_CYCLE_KIND = "ingest-cycle"

_TERMINAL_DISPOSITIONS = frozenset({"completed", "failed"})
_UNRESOLVED_DISPOSITIONS = frozenset({"in_flight", "indeterminate"})
_DISPOSITIONS = _TERMINAL_DISPOSITIONS | _UNRESOLVED_DISPOSITIONS

_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OWNER_ID = re.compile(r"^[0-9a-f]{32}$")

_RESULT_KEYS = frozenset({"seen", "new", "fetched", "errors", "database_total"})

_FIELDS = (
    "schema",
    "operation_id",
    "kind",
    "config_source",
    "config_file_sha256",
    "config_sha256",
    "source_scope",
    "data_home",
    "disposition",
    "owner_id",
    "started_at",
    "finished_at",
    "resolved_at",
    "result",
    "error",
    "note",
    "receipt_id",
    "record_sha256",
)
_FIELD_SET = frozenset(_FIELDS)

_MAX_TEXT = 4096
_MAX_SCOPE_ITEMS = 64
_MAX_SCOPE_ITEM = 128


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


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
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.reason = reason
        self.payload: dict[str, Any] = {
            "reason": reason,
            "detail": detail,
            "operation_id": operation_id,
            "disposition": disposition,
        }
        if extra:
            self.payload.update(extra)


class SealConflict(OperationRefused):
    """The on-disk bytes stopped matching this owner's expected prior record."""


def validate_operation_id(value: Any) -> str:
    if not isinstance(value, str) or not _OPERATION_ID.fullmatch(value):
        raise OperationRefused(
            "invalid_operation_id",
            "operation-id must match [A-Za-z0-9][A-Za-z0-9._-]{7,63} and must not "
            "contain ':' or '/'",
        )
    return value


def new_owner_id() -> str:
    return os.urandom(16).hex()


_ERROR_SUMMARY_LIMIT = 600
_ERROR_FIELD_LIMIT = 1024


def normalized_error(exc: BaseException) -> str:
    """Bounded deterministic provider-error binding.

    Keeps a stable short summary plus the SHA-256 of the COMPLETE original
    representation, so even a 5,000-character Unicode failure stays inside
    receipt field bounds without discarding its full identity.
    """
    original = f"{type(exc).__name__}: {exc}"
    digest = hashlib.sha256(original.encode("utf-8", "replace")).hexdigest()
    if len(original) > _ERROR_SUMMARY_LIMIT:
        original = original[:_ERROR_SUMMARY_LIMIT].encode("utf-8", "ignore").decode(
            "utf-8", "ignore"
        )
        original = f"{original}…[truncated]"
    message = f"{type(exc).__name__}: {original.split(': ', 1)[-1]} [sha256={digest}]"
    return message[:_ERROR_FIELD_LIMIT]


def fsync_directory(path: Path) -> None:
    """Durably publish directory entries; patchable seam for tests."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise OperationRefused("invalid_timestamp", f"{field} must be a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise OperationRefused("invalid_timestamp", f"{field} is not ISO-8601: {exc}") from exc
    if parsed.tzinfo is None:
        raise OperationRefused("invalid_timestamp", f"{field} must carry a timezone")
    return parsed


def _require_str(record: dict[str, Any], field: str) -> None:
    value = record[field]
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT:
        raise OperationRefused(
            "tampered_receipt", f"{field} must be a bounded non-empty string"
        )


def _require_hex64(record: dict[str, Any], field: str) -> None:
    value = record[field]
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise OperationRefused("tampered_receipt", f"{field} must be a lowercase SHA-256 digest")


def _require_scope(record: dict[str, Any]) -> None:
    scope = record["source_scope"]
    if (
        not isinstance(scope, list)
        or not scope
        or len(scope) > _MAX_SCOPE_ITEMS
        or any(
            not isinstance(item, str) or not item or len(item) > _MAX_SCOPE_ITEM
            for item in scope
        )
        or scope != sorted(set(scope))
    ):
        raise OperationRefused(
            "tampered_receipt",
            "source_scope must be a sorted list of unique bounded board strings",
        )


def _require_result(result: Any) -> None:
    if result is None:
        return
    if not isinstance(result, dict) or set(result) != _RESULT_KEYS:
        raise OperationRefused(
            "invalid_result",
            "result must hold exactly the canonical cycle counters "
            f"{sorted(_RESULT_KEYS)}",
        )
    for key, value in result.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise OperationRefused(
                "invalid_result", f"result.{key} must be a non-negative integer"
            )


def make_record(
    *,
    operation_id: str,
    kind: str,
    config_source: str,
    config_file_sha256: str,
    config_sha256: str,
    source_scope: list[str],
    data_home: str,
    disposition: str,
    owner_id: str,
    started_at: str | None = None,
    finished_at: str | None = None,
    resolved_at: str | None = None,
    result: dict[str, int] | None = None,
    error: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    if disposition not in _DISPOSITIONS:
        raise ValueError(f"unknown disposition: {disposition}")
    validate_operation_id(operation_id)
    record: dict[str, Any] = {
        "schema": OPERATION_SCHEMA,
        "operation_id": operation_id,
        "kind": kind,
        "config_source": config_source,
        "config_file_sha256": config_file_sha256,
        "config_sha256": config_sha256,
        "source_scope": [str(board) for board in source_scope],
        "data_home": data_home,
        "disposition": disposition,
        "owner_id": owner_id,
        "started_at": started_at or utc_now(),
        "finished_at": finished_at,
        "resolved_at": resolved_at,
        "result": result,
        "error": error,
        "note": note,
    }
    # Receipt identity is the SHA-256 of the canonical semantic body: every
    # bound fact except the identity fields themselves.
    record["receipt_id"] = content_sha256(record)
    record["record_sha256"] = content_sha256(record)
    return record


def verify_record(raw: Any) -> dict[str, Any]:
    """Reject unreadable-shaped, tampered or substituted records before work.

    Verification is structural and type-strict: unknown fields, duplicate JSON
    keys, wrong types, invalid state combinations and consistently rehashed
    substitutions of such fields all fail here.
    """
    if not isinstance(raw, dict):
        raise OperationRefused("tampered_receipt", "journal record is not an object")
    missing = sorted(_FIELD_SET - set(raw))
    unknown = sorted(set(raw) - _FIELD_SET)
    if missing or unknown:
        raise OperationRefused(
            "tampered_receipt",
            f"journal record field set mismatch; missing={missing} unknown={unknown}",
        )
    if raw["schema"] != OPERATION_SCHEMA:
        raise OperationRefused("tampered_receipt", "unsupported journal schema")
    validate_operation_id(raw["operation_id"])
    _require_str(raw, "kind")
    for field in ("config_source", "config_file_sha256", "config_sha256", "data_home"):
        _require_str(raw, field)
    _require_hex64(raw, "config_file_sha256")
    _require_hex64(raw, "config_sha256")
    _require_scope(raw)
    disposition = raw["disposition"]
    if disposition not in _DISPOSITIONS:
        raise OperationRefused("tampered_receipt", f"unknown disposition: {disposition!r}")
    owner_id = raw["owner_id"]
    if not isinstance(owner_id, str) or not _OWNER_ID.fullmatch(owner_id):
        raise OperationRefused("tampered_receipt", "owner_id must be 32 lowercase hex characters")

    started = _parse_timestamp(raw["started_at"], "started_at")
    finished = resolved = None
    if raw["finished_at"] is not None:
        finished = _parse_timestamp(raw["finished_at"], "finished_at")
    if raw["resolved_at"] is not None:
        resolved = _parse_timestamp(raw["resolved_at"], "resolved_at")

    result = raw["result"]
    error = raw["error"]
    note = raw["note"]
    _require_result(result)
    if error is not None and (not isinstance(error, str) or not error or len(error) > _MAX_TEXT):
        raise OperationRefused("tampered_receipt", "error must be a bounded non-empty string")
    if note is not None and (not isinstance(note, str) or not note or len(note) > _MAX_TEXT):
        raise OperationRefused("tampered_receipt", "note must be a bounded non-empty string")

    if disposition == "in_flight":
        if finished is not None or resolved is not None or result is not None or error is not None:
            raise OperationRefused("invalid_state", "in_flight records carry no terminal fields")
    elif disposition == "completed":
        if finished is None or resolved is not None or result is None or error is not None:
            raise OperationRefused(
                "invalid_state",
                "completed records require finished_at and result and no error/resolved_at",
            )
    elif disposition == "failed":
        if finished is None or resolved is not None or result is not None or error is None:
            raise OperationRefused(
                "invalid_state",
                "failed records require finished_at and error and no result/resolved_at",
            )
    else:  # indeterminate
        if resolved is None or finished is not None or result is not None or error is not None:
            raise OperationRefused("invalid_state", "indeterminate records require resolved_at only")
        if note is None:
            raise OperationRefused("invalid_state", "indeterminate records require a note")

    if finished is not None and finished < started:
        raise OperationRefused("invalid_state", "finished_at precedes started_at")
    if resolved is not None and resolved < started:
        raise OperationRefused("invalid_state", "resolved_at precedes started_at")

    expected_receipt = content_sha256(
        {key: raw[key] for key in _FIELDS if key not in ("receipt_id", "record_sha256")}
    )
    if raw["receipt_id"] != expected_receipt:
        raise OperationRefused(
            "receipt_substitution",
            "receipt_id is not the SHA-256 of the canonical semantic body",
            operation_id=raw["operation_id"],
            disposition=disposition,
        )
    stored_digest = raw["record_sha256"]
    if not isinstance(stored_digest, str) or not _HEX64.fullmatch(stored_digest):
        raise OperationRefused("tampered_receipt", "record_sha256 must be a lowercase SHA-256 digest")
    body = {key: value for key, value in raw.items() if key != "record_sha256"}
    if content_sha256(body) != stored_digest:
        raise OperationRefused(
            "tampered_receipt",
            "journal content hash does not match its bound fields",
            operation_id=raw["operation_id"],
            disposition=disposition,
        )
    return raw


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError(f"duplicate JSON key: {key}")
        mapping[key] = value
    return mapping


def _verify_regular_file(info: os.stat_result, name: str) -> None:
    """Exact owner, mode and single-link enforcement for journal files.

    Record bytes are parsed only when the final entry is provably a single
    link; transient publication windows are handled by the authority-based
    settlement seam, never by lenient verification.
    """
    if not stat.S_ISREG(info.st_mode):
        raise OperationRefused("unsafe_journal_file", f"{name} must be a regular file")
    if info.st_nlink != 1:
        raise OperationRefused(
            "unsafe_journal_file",
            f"{name} must be a single-link file without hardlinks "
            f"(nlink={info.st_nlink})",
        )
    if info.st_uid != os.getuid():
        raise OperationRefused("unsafe_journal_file", f"{name} must be owned by the current user")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise OperationRefused(
            "unsafe_journal_file", f"{name} must have exactly 0600 permissions"
        )


def _verify_directory(path: Path, expected_mode: int, name: str, *, allow_missing: bool) -> None:
    """Real, un-substituted, owner-private directory enforcement."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return
        raise OperationRefused("unsafe_journal_root", f"{name} does not exist") from None
    except OSError as exc:
        raise OperationRefused("unsafe_journal_root", f"{name}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise OperationRefused(
            "unsafe_journal_root", f"{name} must be a real directory, not a symlink"
        )
    if not stat.S_ISDIR(info.st_mode):
        raise OperationRefused("unsafe_journal_root", f"{name} must be a directory")
    if info.st_uid != os.getuid():
        raise OperationRefused("unsafe_journal_root", f"{name} must be owned by the current user")
    if stat.S_IMODE(info.st_mode) != expected_mode:
        raise OperationRefused(
            "unsafe_journal_root", f"{name} must have exactly {oct(expected_mode)} permissions"
        )


def read_record_bytes(path: Path) -> bytes:
    """Open one record strictly: nofollow, single link, exact owner and mode.

    There is deliberately no lenient mode: bytes of a multi-link final are
    never parsed. Publication windows are resolved by the authority-based
    settlement seam before this function is called.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise OperationRefused("unsafe_journal_file", f"cannot open {path.name}: {exc}") from exc
    try:
        _verify_regular_file(os.fstat(descriptor), path.name)
        with os.fdopen(descriptor, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise OperationRefused("unreadable_journal", f"{path.name}: {exc}") from exc


def parse_record(raw_bytes: bytes, expected_operation_id: str, name: str) -> dict[str, Any]:
    try:
        raw = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise OperationRefused(
            "unreadable_journal", f"journal record {name} is unreadable: {exc}"
        ) from exc
    record = verify_record(raw)
    if record["operation_id"] != expected_operation_id:
        raise OperationRefused(
            "operation_substitution",
            "journal record identity does not match its file name",
            operation_id=expected_operation_id,
            disposition=record["disposition"],
        )
    return record


def board_lock_digest(data_home: str, board: str) -> str:
    return content_sha256({"board": str(board), "data_home": data_home})[:32]


class OperationJournal:
    """File-per-operation receipt store beneath the external state directory."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        parent = self.root.parent
        if os.path.lexists(parent):
            _verify_directory(parent, 0o700, f"{parent.name} (journal parent)", allow_missing=False)
        if os.path.lexists(self.root):
            _verify_directory(self.root, 0o700, "journal root", allow_missing=False)
        else:
            try:
                self.root.mkdir(mode=0o700)
                self.root.chmod(0o700)
            except FileExistsError:  # concurrent constructor race
                pass
        self._verify_root()

    def _verify_root(self) -> None:
        _verify_directory(self.root, 0o700, "journal root", allow_missing=False)
        _verify_directory(
            self.root.parent,
            0o700,
            f"{self.root.parent.name} (journal parent)",
            allow_missing=False,
        )

    # -- paths -------------------------------------------------------------- #
    def record_path(self, operation_id: str) -> Path:
        return self.root / f"{operation_id}.json"

    def _lock_path(self, operation_id: str) -> Path:
        return self.root / f"{operation_id}.lock"

    def board_lock_path(self, data_home: str, board: str) -> Path:
        return self.root / f"board-{board_lock_digest(data_home, str(board))}.lock"

    def _temp_prefix(self, operation_id: str) -> str:
        return f".claim-{operation_id}-"

    # -- durable primitives -------------------------------------------------- #
    def _publish(self, path: Path, payload: bytes) -> None:
        """Atomically install payload at path, fsyncing file and parent."""
        descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=self.root)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _verify_regular_file(os.lstat(temporary), Path(temporary).name)
            os.replace(temporary, path)
            temporary = None
            fsync_directory(self.root)
        finally:
            if temporary is not None:
                os.unlink(temporary)

    def _open_lock(self, path: Path) -> int:
        """Open (or exclusively create) a 0600 single-link lock file."""
        try:
            try:
                descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            except FileNotFoundError:
                try:
                    descriptor = os.open(
                        path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                    )
                    os.fchmod(descriptor, 0o600)
                    fsync_directory(self.root)
                except FileExistsError:
                    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        except OSError as exc:
            raise OperationRefused(
                "unsafe_journal_file", f"lock {path.name} is not usable: {exc}"
            ) from exc
        try:
            _verify_regular_file(os.fstat(descriptor), path.name)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _locked(self, operation_id: str) -> int:
        descriptor = self._open_lock(self._lock_path(operation_id))
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor

    def acquire_board_locks(self, data_home: str, source_scope: list[str]) -> list[int]:
        """Lock every board of the scope and hold them all through the run.

        ``source_scope`` arrives already canonically ordered from
        :meth:`market_aligner.collectors.Collector.plan`, so acquisition order
        is deterministic and deadlock-free across subset/superset scopes. On
        any failure every already-bound lock is released while an unsafe entry
        itself is left untouched for structured inspection.
        """
        self._verify_root()
        descriptors: list[int] = []
        try:
            for board in source_scope:
                descriptor = self._open_lock(self.board_lock_path(data_home, board))
                descriptors.append(descriptor)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            return descriptors
        except BaseException:
            self.release_locks(descriptors)
            raise

    def open_operation_lock(self, operation_id: str) -> int:
        """Open, verify and exclusively hold this operation's own lock.

        Called before any claim or provider access so a substituted
        (06xx-mode, symlinked or hardlinked) lock fails closed with zero
        provider calls and cannot strand an in_flight claim. The returned
        descriptor stays held through claim/cycle/seal and is reused by
        :meth:`cas_replace`, avoiding self-deadlock.
        """
        return self._locked(operation_id)

    @staticmethod
    def release_locks(descriptors: list[int]) -> None:
        for descriptor in reversed(descriptors):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    # -- lifecycle ------------------------------------------------------------ #
    def load(
        self, operation_id: str, *, operation_lock_fd: int | None = None
    ) -> dict[str, Any] | None:
        """Reopen, verify and return the current record, or None if absent.

        Broken symlinks are not absence: ``lexists`` gates the read so a
        substituted entry fails closed instead of looking missing. A final
        with more than one link is never parsed: the reader waits for and
        acquires the exact typed operation lock (unless it already holds it
        via ``operation_lock_fd``), settles an exactly-shaped abandoned
        publication under that authority, and only then performs a strict
        single-link read. Anything else fails closed.
        """
        self._verify_root()
        path = self.record_path(operation_id)
        if not os.path.lexists(path):
            return None
        raw_bytes = self._settled_record_bytes(
            operation_id, path, operation_lock_fd=operation_lock_fd
        )
        return parse_record(raw_bytes, operation_id, path.name)

    def _verify_supplied_authority(self, operation_id: str, fd: int) -> None:
        """Fail closed unless fd IS this operation's exclusively-held lock.

        The descriptor must be a 0600 single-link regular file owned by the
        current user, dev+ino-equal to the lstat of the canonical operation
        lock path (symlinks never qualify), and it must already hold the
        exclusive flock on its own open description. Re-running LOCK_EX|NB on
        an already-held description is idempotent; anything unheld or
        contended refuses.
        """
        expected = self._lock_path(operation_id)
        try:
            expected_info = os.lstat(expected)
            info = os.fstat(fd)
        except OSError as exc:
            raise OperationRefused(
                "unsafe_journal_file",
                f"supplied authority fd is not verifiable against the operation "
                f"lock {expected.name}: {exc}",
            ) from exc
        if not stat.S_ISREG(info.st_mode):
            raise OperationRefused(
                "unsafe_journal_file", "supplied authority fd must be a regular file"
            )
        if info.st_nlink != 1:
            raise OperationRefused(
                "unsafe_journal_file",
                f"supplied authority fd must be single-link (nlink={info.st_nlink})",
            )
        if info.st_uid != os.getuid():
            raise OperationRefused(
                "unsafe_journal_file", "supplied authority fd must be owned by the current user"
            )
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise OperationRefused(
                "unsafe_journal_file",
                f"supplied authority fd must have exactly 0600 permissions "
                f"(got {oct(stat.S_IMODE(info.st_mode))})",
            )
        if (info.st_dev, info.st_ino) != (expected_info.st_dev, expected_info.st_ino):
            raise OperationRefused(
                "unsafe_journal_file",
                "supplied authority fd is not this operation's lock file",
            )
        # Prove the supplied description ALREADY holds the exclusive flock.
        # A second descriptor must fail to acquire (something holds it), and
        # re-locking the supplied fd must succeed idempotently (it is the
        # holder). A fresh unheld fd would let both checks pass/fail in a way
        # that betrays it: the probe acquires freely, so authority is denied
        # before any read or mutation.
        try:
            probe = os.open(expected, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise OperationRefused(
                "unsafe_journal_file",
                f"operation lock {expected.name} is not probeable: {exc}",
            ) from exc
        try:
            held_by_anyone = False
            try:
                probe_info = os.fstat(probe)
                if (probe_info.st_dev, probe_info.st_ino) != (
                    expected_info.st_dev,
                    expected_info.st_ino,
                ):
                    raise OperationRefused(
                        "unsafe_journal_file",
                        "operation lock changed identity while probing authority",
                    )
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(probe, fcntl.LOCK_UN)
            except OperationRefused:
                raise
            except OSError:
                # Contention is only trusted once the probe descriptor is
                # proven to reference the very same canonical inode.
                held_by_anyone = True
        finally:
            os.close(probe)
        if not held_by_anyone:
            raise OperationRefused(
                "unsafe_journal_file",
                "supplied authority fd does not hold the exclusive operation lock",
            )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise OperationRefused(
                "unsafe_journal_file",
                f"supplied authority fd does not hold the exclusive operation lock: {exc}",
            ) from exc

    def _operation_lock_is_free(self, operation_id: str) -> bool:
        """Non-blocking liveness probe for tests and diagnostics.

        Settlement authority is holding the lock itself, never the mere
        observation that it happens to be free at probe time.
        """
        descriptor = self._open_lock(self._lock_path(operation_id))
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError:
                return False
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _settle_abandoned_publication(self, final: Path) -> None:
        """Complete cleanup under held authority, with an exact pre-state.

        Allowed only when the current pre-state is EXACTLY nlink==2 with
        EXACTLY ONE matching same-inode claim temp; then unlink that temp,
        fsync the parent and revalidate the SAME final inode back to a single
        link. Any other shape — nlink>2, foreign hardlinks, missing or excess
        matching temps — is refused without mutating either extra link.
        """
        try:
            info = os.lstat(final)
        except OSError as exc:
            raise OperationRefused(
                "unsafe_journal_file",
                f"final record {final.name} vanished during settlement: {exc}",
            ) from exc
        if info.st_nlink == 1:
            return
        matches = []
        for candidate in sorted(self.root.glob(self._temp_prefix(final.stem) + "*")):
            try:
                candidate_info = os.lstat(candidate)
            except OSError as exc:
                raise OperationRefused(
                    "unsafe_journal_file",
                    f"candidate residue {candidate.name} is not statable: {exc}",
                ) from exc
            if (
                candidate_info.st_dev == info.st_dev
                and candidate_info.st_ino == info.st_ino
                and stat.S_ISREG(candidate_info.st_mode)
            ):
                matches.append(candidate)
        if info.st_nlink != 2 or len(matches) != 1:
            raise OperationRefused(
                "unsafe_journal_file",
                f"{final.name} has unresolved additional links "
                f"(nlink={info.st_nlink}, matching_temps={len(matches)}); "
                "refusing without mutation",
            )
        try:
            os.unlink(matches[0])
        except OSError as exc:
            raise OperationRefused(
                "unsafe_journal_file",
                f"matching residue {matches[0].name} could not be removed: {exc}",
            ) from exc
        try:
            fsync_directory(self.root)
        except OSError as exc:
            raise OperationRefused(
                "unsafe_journal_file",
                f"journal directory could not be fsynced after settlement: {exc}",
            ) from exc
        try:
            settled = os.lstat(final)
        except OSError as exc:
            raise OperationRefused(
                "unsafe_journal_file",
                f"settled final {final.name} is not statable: {exc}",
            ) from exc
        if settled.st_ino != info.st_ino or settled.st_nlink != 1:
            raise OperationRefused(
                "unsafe_journal_file",
                f"{final.name} did not settle to a single link",
            )

    def _settled_record_bytes(
        self,
        operation_id: str,
        path: Path,
        *,
        operation_lock_fd: int | None = None,
        wait: bool = True,
    ) -> bytes | None:
        """Authority-based settlement then a strict single-link read.

        Any supplied ``operation_lock_fd`` is verified as this exact
        operation's owned, held, 0600, single-link canonical lock BEFORE any
        read path is taken — wrong, closed, missing, symlinked, substituted
        or unrelated descriptors refuse without reading or mutating anything.
        Supplied authority prevents self-deadlock; exactly one release happens
        for a lock this method acquires itself. With ``wait=False`` a live
        publisher yields a ``None`` result instead of blocking (scope-scan
        skip). Multi-link bytes are never parsed: settlement requires the
        exact pre-state of nlink==2 with exactly one matching same-inode temp.
        """
        if operation_lock_fd is not None:
            self._verify_supplied_authority(operation_id, operation_lock_fd)
        try:
            single = os.lstat(path).st_nlink == 1
        except OSError as exc:
            raise OperationRefused(
                "unsafe_journal_file",
                f"final record {path.name} is not statable: {exc}",
            ) from exc
        if single:
            return read_record_bytes(path)
        owned_here = False
        fd = operation_lock_fd
        if fd is None:
            descriptor = self._open_lock(self._lock_path(operation_id))
            try:
                flags = fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB
                fcntl.flock(descriptor, flags)
            except OSError as exc:
                os.close(descriptor)
                if not wait:
                    return None  # live publisher holds the authority lock
                raise OperationRefused(
                    "unsafe_journal_file",
                    f"could not acquire publication authority for {path.name}: {exc}",
                ) from exc
            fd = descriptor
            owned_here = True
        try:
            self._settle_abandoned_publication(path)
            return read_record_bytes(path)
        finally:
            if owned_here:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def claim(self, record: dict[str, Any]) -> bool:
        """Publish the owner's in_flight claim atomically; False if taken.

        The payload is written completely into a private 0600 temp, fsynced,
        then published by true no-replace ``os.link`` plus parent fsync. The
        staging temp belongs to this publisher alone and is removed by it;
        concurrent readers never parse multi-link bytes: they wait for and
        acquire this exact operation lock and then settle only an
        exact-shaped abandoned publication. A short write, kill or
        pre-publication failure leaves no final record, performs zero provider
        calls and permits a same-ID retry; post-publication residue is settled
        only under that acquired authority, never by inference.
        """
        self._verify_root()
        verify_record(record)
        payload = canonical_json(record).encode("utf-8")
        final = self.record_path(record["operation_id"])
        if os.path.lexists(final):
            return False
        descriptor, temporary = tempfile.mkstemp(
            prefix=self._temp_prefix(record["operation_id"]), dir=self.root
        )
        temporary_path: str | None = temporary
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _verify_regular_file(os.lstat(temporary), Path(temporary).name)
            try:
                os.link(temporary, final)
            except FileExistsError:
                return False
            os.unlink(temporary)
            temporary_path = None
            fsync_directory(self.root)
            return True
        finally:
            if temporary_path is not None:
                os.unlink(temporary_path)

    def cas_replace(
        self,
        record: dict[str, Any],
        expected_prior_bytes: bytes,
        *,
        operation_id: str,
        operation_lock_fd: int | None = None,
    ) -> None:
        """Owner-only compare-and-set publish under the held operation lock.

        The on-disk record must still be byte-for-byte the owner's expected
        prior record; otherwise nothing is written and :class:`SealConflict`
        fails closed. When ``operation_lock_fd`` is supplied it must already
        be held exclusively (opened via :meth:`open_operation_lock`) and is
        reused instead of re-locking, which would self-deadlock. Without a
        supplied fd this method acquires the lock itself and passes that
        acquired descriptor to the settlement seam, so the prior-bytes read
        never re-locks and never parses multi-link bytes.
        """
        self._verify_root()
        verify_record(record)
        payload = canonical_json(record).encode("utf-8")
        if operation_lock_fd is not None:
            # Caller-owned: never unlocked or closed here; the single outer
            # finally in the command handler releases it exactly once.
            lock = operation_lock_fd
        else:
            lock = self._locked(operation_id)
        try:
            path = self.record_path(operation_id)
            if not path.exists():
                raise SealConflict(
                    "seal_conflict",
                    "on-disk record disappeared; refusing to overwrite",
                    operation_id=operation_id,
                    disposition=record["disposition"],
                )
            # Coherent authority seam: settle an exactly-shaped abandoned
            # publication under THIS held lock, then strict single-link read.
            current_bytes = self._settled_record_bytes(
                operation_id, path, operation_lock_fd=lock
            )
            if current_bytes != expected_prior_bytes:
                raise SealConflict(
                    "seal_conflict",
                    "on-disk record no longer matches this owner's claimed state; "
                    "refusing to overwrite",
                    operation_id=operation_id,
                    disposition=record["disposition"],
                )
            self._publish(path, payload)
        finally:
            if operation_lock_fd is None:
                fcntl.flock(lock, fcntl.LOCK_UN)
                os.close(lock)

    def scan_unresolved_scope_blockers(
        self, data_home: str, source_scope: list[str], *, exclude_operation_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Unresolved/indeterminate calls whose boards intersect this scope."""
        self._verify_root()
        wanted = {str(board) for board in source_scope}
        blockers: list[dict[str, Any]] = []
        for path in sorted(self.root.glob("*.json")):
            candidate = path.name[: -len(".json")]
            if candidate == exclude_operation_id:
                continue
            raw_bytes = self._settled_record_bytes(candidate, path, wait=False)
            if raw_bytes is None:
                continue  # live publisher of another scope; never parsed
            record = parse_record(raw_bytes, candidate, path.name)
            if (
                record["data_home"] == data_home
                and wanted & set(record["source_scope"])
                and record["disposition"] in _UNRESOLVED_DISPOSITIONS
            ):
                blockers.append(
                    {
                        "operation_id": record["operation_id"],
                        "disposition": record["disposition"],
                        "owner_id": record["owner_id"],
                        "started_at": record["started_at"],
                        "intersecting_boards": sorted(
                            wanted & set(record["source_scope"])
                        ),
                    }
                )
        return blockers
