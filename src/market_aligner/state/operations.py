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
    """Exact owner, mode and link-count enforcement for journal files."""
    if not stat.S_ISREG(info.st_mode):
        raise OperationRefused("unsafe_journal_file", f"{name} must be a regular file")
    if info.st_nlink != 1:
        raise OperationRefused(
            "unsafe_journal_file", f"{name} must be a single-link file (no hardlinks)"
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
    """Open one record strictly: nofollow, single link, exact owner and mode."""
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
        """Lock every board of the scope in canonical order and hold them all.

        Different operation ids serialize on every intersecting board; sorted
        acquisition order prevents deadlock across subset/superset scopes.
        """
        self._verify_root()
        descriptors: list[int] = []
        try:
            for board in sorted(str(board) for board in source_scope):
                descriptor = self._open_lock(self.board_lock_path(data_home, board))
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                descriptors.append(descriptor)
        except BaseException:
            self.release_locks(descriptors)
            raise
        return descriptors

    @staticmethod
    def release_locks(descriptors: list[int]) -> None:
        for descriptor in reversed(descriptors):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    # -- lifecycle ------------------------------------------------------------ #
    def load(self, operation_id: str) -> dict[str, Any] | None:
        """Reopen, verify and return the current record, or None if absent.

        Broken symlinks are not absence: ``lexists`` gates the read so a
        substituted entry fails closed instead of looking missing.
        """
        self._verify_root()
        path = self.record_path(operation_id)
        if not os.path.lexists(path):
            return None
        # A crash between no-replace publication and staging cleanup leaves a
        # complete receipt with a same-inode temp; finish that deterministic
        # repair before verification. Foreign hardlinks never match and are
        # rejected below.
        self._repair_own_claim_temp(path)
        raw_bytes = read_record_bytes(path)
        return parse_record(raw_bytes, operation_id, path.name)

    def _repair_own_claim_temp(self, final: Path) -> None:
        """Finish an interrupted link publication owned by this record.

        A crash between ``os.link`` and ``unlink`` leaves a complete final
        receipt with two links plus its identical-inode staging temp. The
        inode match proves ownership so removing it is deterministic repair;
        foreign hardlinks never match and stay rejected.
        """
        info = os.lstat(final)
        if info.st_nlink == 1:
            return
        for candidate in sorted(self.root.glob(self._temp_prefix(final.stem) + "*")):
            candidate_info = os.lstat(candidate)
            if (
                candidate_info.st_dev == info.st_dev
                and candidate_info.st_ino == info.st_ino
                and stat.S_ISREG(candidate_info.st_mode)
            ):
                os.unlink(candidate)
                fsync_directory(self.root)
                if os.lstat(final).st_nlink != 1:
                    continue
                return
        raise OperationRefused(
            "unsafe_journal_file",
            f"{final.name} has unexpected additional links",
        )

    def claim(self, record: dict[str, Any]) -> bool:
        """Publish the owner's in_flight claim atomically; False if taken.

        The payload is written completely into a private 0600 temp, fsynced,
        then published by true no-replace ``os.link`` plus parent fsync. A
        short write, kill or pre-publication failure leaves no final record,
        performs zero provider calls and permits a same-ID retry.
        """
        self._verify_root()
        verify_record(record)
        payload = canonical_json(record).encode("utf-8")
        final = self.record_path(record["operation_id"])
        if os.path.lexists(final):
            self._repair_own_claim_temp(final)
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
    ) -> None:
        """Owner-only compare-and-set publish under an exclusive lock.

        The on-disk record must still be byte-for-byte the owner's expected
        prior record; otherwise nothing is written and :class:`SealConflict`
        fails closed.
        """
        self._verify_root()
        verify_record(record)
        payload = canonical_json(record).encode("utf-8")
        lock = self._locked(operation_id)
        try:
            path = self.record_path(operation_id)
            if not path.exists() or read_record_bytes(path) != expected_prior_bytes:
                raise SealConflict(
                    "seal_conflict",
                    "on-disk record no longer matches this owner's claimed state; "
                    "refusing to overwrite",
                    operation_id=operation_id,
                    disposition=record["disposition"],
                )
            self._publish(path, payload)
        finally:
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
            raw_bytes = read_record_bytes(path)
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
