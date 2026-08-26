"""FIT-001 evidence-bound process-one core.

Authority: docs/processing/FIT-001_PROCESS_ONE_CONTRACT.md (accepted R11E).

One public deterministic admission path over the canonical owners:

- snapshot_config / closure_identity / Collector.plan own configuration
  closure identity and collector database resolution;
- JobDatabase owns postings and normalised_jobs; ProfileStore /
  CandidateProfile own profile+evidence validation and llm_context; the LLM
  contracts and accept_extraction/accept_alignment own imported validation;
- score / ScoringParams / ScoreResult own deterministic scoring;
- AssessmentStore owns assessments and assessment events;
  state/migrations.apply_on remains the sole schema-evolution owner.

This module adds no provider, model, network, browser, JAA, research,
release, application, or submission authority. Every receipt states the six
false authorities plus unauthenticated imported time/model policy.

Phase flow (contract sections 3 and 20, R11D/R11E):

1. Common reasons 1-5 before any SQLite open: operation id, strict envelope
   path/bytes/schema, CLI identity, configuration plan, staged/derived
   database pathname/identity through retained descriptors. Current raw/
   profile/evidence authorities are deliberately not opened here.
2. Exact existing read view (URI mode=rw, SELECT/read-only PRAGMA only)
   for historical receipt classification; no journal-mode change, BEGIN,
   DDL, or DML on this path.
3. A proven exact self-validating receipt whose staged candidate binding is
   exact returns sealed stored bytes without opening profile material; a
   changed staged binding terminates reason 6.
4. Otherwise definitive absence or a provisionally incompatible receipt
   store continues: raw (7), committed profile snapshot acquired and held
   through COMMIT (8), extraction/alignment/scoring (9-13), projection
   conflict (14); a retained provisional incompatibility reports
   atomic_mode_unavailable only at reason 15 after earlier reasons pass.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from market_aligner.assessment.scoring import (
    AssessmentAxes,
    FitStatus,
    ScoreResult,
    ScoringParams,
)
from market_aligner.assessment.scoring import (
    score as deterministic_score,
)
from market_aligner.collectors.engine import Collector
from market_aligner.config import open_existing_private_data_root, owner_private_lock
from market_aligner.config_loader import closure_identity, snapshot_config
from market_aligner.domain.contracts import RawPosting
from market_aligner.llm.contracts import (
    EvidenceAlignment,
    EvidenceMatch,
    LLMReceipt,
    SemanticVacancyExtraction,
    canonical_hash,
)
from market_aligner.llm.pipeline import accept_alignment, accept_extraction
from market_aligner.profiler.schema import validate_profile_id
from market_aligner.profiler.store import CoherentProfileSnapshot, ProfileStore
from market_aligner.research.store import (
    ScoreInsertPlan,
    ScoreReadPlan,
    ScoreReusePlan,
    canonical_score_payload,
    cas_accepted_score,
    cas_processing_event,
    classify_accepted_score,
    classify_processing_score_event,
    plan_accepted_score,
    plan_processing_event,
    require_rfc3339_timestamp,
)
from market_aligner.state.migrations import (
    ELIGIBILITY_ELIGIBILITY_RECEIPTS,
    ELIGIBILITY_RECEIPTS_DDL,
    FIT001_PROCESSING_RECEIPTS,
    FIT001_RECEIPTS_DDL,
    LEDGER_DDL,
    MigrationCompatibilityError,
    apply_on,
)
from market_aligner.state.vacancies import (
    POSTING_READ_COLUMNS,
    ProjectionConflict,
    cas_normalized_job,
    read_normalized_job,
    read_posting,
)

# --------------------------------------------------------------------------
# Stable refusal reasons in contracted precedence order (section 20).
# --------------------------------------------------------------------------

REASON_OPERATION_ID = "invalid_operation_id"
REASON_ENVELOPE_PATH = "unsafe_processing_envelope_path"
REASON_ENVELOPE_BYTES = "invalid_processing_envelope_bytes"
REASON_CLI_IDENTITY = "binding_cli_identity"
REASON_CONFIG_DATABASE = "binding_config_database"
REASON_EXISTING_RECEIPT = "binding_existing_receipt"
REASON_RAW_SNAPSHOT = "binding_raw_snapshot"
REASON_PROFILE_EVIDENCE = "binding_profile_evidence_context"
REASON_EXTRACTION = "binding_extraction"
REASON_ALIGNMENT = "binding_alignment"
REASON_SCORING_PARAMS = "binding_scoring_parameters"
REASON_OPPORTUNITY_POLICY = "binding_opportunity_policy"
REASON_SCORE_RESULT = "binding_score_result"
REASON_PROJECTION_CONFLICT = "projection_conflict"
REASON_ATOMIC_MODE = "atomic_mode_unavailable"
REASON_ATOMIC_BUSY = "atomic_busy"
REASON_STORAGE_FULL = "storage_full"
REASON_STORAGE_IO_ERROR = "storage_io_error"
REASON_INTERRUPTED = "interrupted"
REASON_RECOVERY_INCOHERENT = "recovery_incoherent"

ENVELOPE_SCHEMA_VERSION = "market-aligner.processing-envelope.v1"
BINDING_SCHEMA_VERSION = "market-aligner.processing-binding.v1"
EVENT_SCHEMA_VERSION = "market-aligner.processing-score-event.v1"
RECEIPT_SCHEMA_VERSION = "market-aligner.processing-receipt.v1"
EXTRACTION_INPUT_SCHEMA_VERSION = "market-aligner.semantic-vacancy-extraction-input.v1"
ALIGNMENT_INPUT_SCHEMA_VERSION = "market-aligner.evidence-alignment-input.v1"
LLM_CONTRACT_VERSION = "market-aligner.llm.v1"

MAX_ENVELOPE_BYTES = 4_000_000
MAX_RECEIPT_BYTES = 4_194_304
MAX_CONFIG_FILE_BYTES = 1_048_576
MAX_CONFIG_TOTAL_BYTES = 8_388_608
MAX_EVENT_ID = 9_223_372_036_854_775_807

OPPORTUNITY_POLICY_BODY = (
    '{"application_authority":false,"barrier_to_entry":10,"growth_potential":0,'
    '"market_demand":0,"research_authority":false,'
    '"schema_version":"market-aligner.fit001-unknown-opportunity-policy.v1"}'
)
OPPORTUNITY_POLICY_SHA256 = hashlib.sha256(OPPORTUNITY_POLICY_BODY.encode("utf-8")).hexdigest()

OPERATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ProcessingRefused(RuntimeError):
    """A stable contracted refusal carrying exactly one stable reason."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


class _Interrupted(BaseException):
    """Raised by installed catchable SIGINT/SIGTERM handlers."""


# --------------------------------------------------------------------------
# Deterministic fault seams for this acceptance campaign only.
# --------------------------------------------------------------------------

_FAULTS: dict[str, BaseException] = {}
_FAULT_LOCK = threading.Lock()


def install_fault(boundary: str, exc: BaseException) -> None:
    with _FAULT_LOCK:
        _FAULTS[boundary] = exc


def clear_faults() -> None:
    with _FAULT_LOCK:
        _FAULTS.clear()


def _maybe_fault(boundary: str) -> None:
    with _FAULT_LOCK:
        action = _FAULTS.pop(boundary, None)
    if action is None:
        return
    if callable(action) and not isinstance(action, BaseException):
        action()
        return
    raise action


# --------------------------------------------------------------------------
# Canonical bytes primitives (section 5).
# --------------------------------------------------------------------------

def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _DuplicateKey(ValueError):
    pass


class _NonfiniteConstant(ValueError):
    pass


def strict_json_loads(raw: bytes | str) -> Any:
    """Strict JSON decode rejecting duplicate keys and nonfinite constants."""

    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKey(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def constant(name: str) -> None:
        raise _NonfiniteConstant(f"nonfinite JSON constant {name}")

    try:
        return json.loads(text, object_pairs_hook=pairs_hook, parse_constant=constant)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON document: {exc}") from exc


# --------------------------------------------------------------------------
# Primitive validation rules (section 7).
# --------------------------------------------------------------------------

def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def reject_controls(value: str, *, prose: bool, label: str) -> None:
    for character in value:
        code = ord(character)
        if prose and code in (0x09, 0x0A, 0x0D):
            continue
        if code < 0x20 or code == 0x7F:
            raise ValueError(f"{label} rejects control character U+{code:04X}")


def plain_string(value: Any, label: str, low: int, high: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if not low <= len(value) <= high:
        raise ValueError(f"{label} must be {low}..{high} code points, got {len(value)}")
    reject_controls(value, prose=False, label=label)
    return value


def prose_string(value: Any, label: str, low: int, high: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if not low <= len(value) <= high:
        raise ValueError(f"{label} must be {low}..{high} code points, got {len(value)}")
    reject_controls(value, prose=True, label=label)
    return value


def sha256_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be 64 lowercase hex characters")
    return value


def path_value(value: Any, label: str) -> str:
    result = plain_string(value, label, 1, 4096)
    if not os.path.isabs(result) or os.path.normpath(result) != result:
        raise ValueError(f"{label} must be an absolute normalized path")
    return result


_RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?"
    r"(?:[Zz]|[+-](\d{2}):(\d{2}))$"
)


def rfc3339_value(value: Any, label: str) -> str:
    """Bounded RFC3339 date-time lexical form only.

    Rejects space separators, basic format, missing zone, date-only
    strings, offsets outside 00..23 hours / 00..59 minutes; then proves
    calendar validity and timezone awareness via ``datetime.fromisoformat``.
    """

    if not isinstance(value, str):
        raise ValueError(f"{label} must be an RFC3339 date-time string")
    if not 20 <= len(value) <= 64:
        raise ValueError(f"{label} must be 20..64 characters")
    reject_controls(value, prose=False, label=label)
    match = _RFC3339_PATTERN.fullmatch(value)
    if not match:
        raise ValueError(
            f"{label} must be RFC3339 YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)"
        )
    offset_hour, offset_minute = match.group(2), match.group(3)
    if offset_hour is not None and offset_minute is not None:
        if int(offset_hour) > 23 or int(offset_minute) > 59:
            raise ValueError(f"{label} carries an out-of-range UTC offset")
    normalized = value[:-1] + "+00:00" if value[-1] in ("Z", "z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{label} must parse as RFC3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must carry an explicit timezone offset")
    return value


def operation_id_value(value: Any) -> str:
    if not isinstance(value, str) or not OPERATION_ID_PATTERN.fullmatch(value):
        raise ValueError("operation_id must match ^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
    return value


def job_key_value(value: Any) -> str:
    key = plain_string(value, "job_key", 3, 256)
    board, separator, job_id = key.partition(":")
    if not separator or not board or not job_id or ":" in job_id:
        raise ValueError("job_key must be exact board:job identity")
    if len(board) > 128 or len(job_id) > 256:
        raise ValueError("board/job segments exceed bounded lengths")
    return key


def unit_number(value: Any, label: str) -> float:
    if not _is_number(value):
        raise ValueError(f"{label} must be a finite number")
    try:
        result = float(value)
    except OverflowError as exc:
        raise ValueError(f"{label} must be a finite number") from exc
    if not math.isfinite(result):
        raise ValueError(f"{label} must be a finite number")
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{label} must be in [0,1]")
    return result


def exact_keys(payload: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    present = set(payload)
    missing = sorted(expected - present)
    unknown = sorted(present - expected)
    if missing or unknown:
        raise ValueError(f"{label} key set mismatch; missing={missing} unknown={unknown}")
    return payload


def bounded_json_nodes(value: Any, label: str, *, max_nodes: int, max_depth: int) -> None:
    """Count every container/scalar node; enforce node count and depth."""

    counter = 0

    def visit(node: Any, depth: int) -> None:
        nonlocal counter
        if depth > max_depth:
            raise ValueError(f"{label} nesting exceeds depth {max_depth}")
        counter += 1
        if counter > max_nodes:
            raise ValueError(f"{label} exceeds {max_nodes} JSON nodes")
        if isinstance(node, dict):
            for child in node.values():
                visit(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                visit(child, depth + 1)

    visit(value, 1)


# --------------------------------------------------------------------------
# Retained descriptor authority (sections 3, 5, 13).
# --------------------------------------------------------------------------

def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
    )


def _require_private_dir(info: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} must be a real directory")
    if info.st_uid != os.getuid():
        raise ValueError(f"{label} must be owned by the current UID")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f"{label} must have mode exactly 0700")


def _require_private_leaf(info: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{label} must be a regular file")
    if info.st_uid != os.getuid():
        raise ValueError(f"{label} must be owned by the current UID")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(f"{label} must have mode exactly 0600")
    if info.st_nlink != 1:
        raise ValueError(f"{label} must have exactly one link")


class _RetainedDirectory:
    """O_DIRECTORY|O_NOFOLLOW directory descriptor bound to its name entry.

    The raw descriptor becomes owned (``self.fd``) immediately after
    ``os.open`` returns, so every later raising validation closes it through
    ``close()``; no validation failure can leak the descriptor.
    """

    def __init__(
        self,
        parent: "_RetainedDirectory | None",
        name: str | None,
        *,
        at: str | None = None,
        require_private: bool = True,
    ) -> None:
        self.label = at or name or "?"
        self.fd = -1
        self.name_entry: tuple[int, int, int, int, int] | None = None
        self.initial: tuple[int, int, int, int, int] | None = None
        self._parent = parent
        self._name = name
        try:
            if parent is None:
                assert name is None and at is not None
                raw = os.open(at, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            else:
                raw = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent.fd
                )
            self.fd = raw
            info = os.fstat(self.fd)
            if require_private:
                _require_private_dir(info, self.label)
            self.initial = _identity(info)
            if parent is not None and name is not None:
                entry = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
                if require_private:
                    _require_private_dir(entry, self.label)
                self.name_entry = _identity(entry)
            # Post-construction consistency: the retained descriptor must
            # still be the opened-name inode with identical strict metadata.
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def revalidate(self) -> None:
        assert self.initial is not None
        current = os.fstat(self.fd)
        if _identity(current) != self.initial:
            raise ValueError(f"retained directory drifted: {self.label}")
        if not stat.S_ISDIR(current.st_mode):
            raise ValueError(f"retained directory type drift: {self.label}")
        if self.name_entry is not None:
            assert self._parent is not None and self._name is not None
            entry = os.stat(self._name, dir_fd=self._parent.fd, follow_symlinks=False)
            if _identity(entry) != self.name_entry:
                raise ValueError(f"name entry drifted for {self.label}")
            if (entry.st_dev, entry.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError(f"opened-name substitution for {self.label}")

    def close(self) -> None:
        if self.fd >= 0:
            with contextlib.suppress(OSError):
                os.close(self.fd)
            self.fd = -1


class _RetainedLeafContentError(ValueError):
    """Typed retained-leaf content/size failure.

    Covers maximum overflow, EOF before the stated size, growth or extra
    bytes beyond the stated size, size change between pre-stat and open,
    and retained size drift. Name/inode/type/uid/mode/nlink/open
    substitution remains an untyped authority error.
    """


class _RetainedLeaf:
    """Retained regular-file descriptor plus parent-relative name entry.

    The raw descriptor becomes owned immediately after ``os.open``. The
    initial fstat bounds the content BEFORE any allocation; the bounded
    stable ``os.pread`` loop reads at most ``maximum + 1`` bytes at a fixed
    offset and requires the exact initial ``st_size``; a final fstat and a
    parent-relative name-entry stat must still name the retained inode with
    identical strict metadata.
    """

    def __init__(
        self,
        parent: _RetainedDirectory,
        name: str,
        *,
        maximum: int,
        prestat: os.stat_result | None = None,
    ) -> None:
        self.parent = parent
        self.label = name
        self.fd = -1
        try:
            entry = (
                prestat
                if prestat is not None
                else os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            )
            _require_private_leaf(entry, name)
            raw = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent.fd)
            self.fd = raw
            info = os.fstat(self.fd)
            _require_private_leaf(info, name)
            if (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino):
                raise ValueError(f"{name} was substituted between lstat and open")
            if info.st_size > maximum:
                raise _RetainedLeafContentError(
                    f"{name} exceeds {maximum} bytes"
                )
            if info.st_size != entry.st_size:
                raise _RetainedLeafContentError(
                    f"{name} changed size between pre-stat and open "
                    f"({entry.st_size} -> {info.st_size})"
                )
            self.identity = _identity(info)
            self.name_entry = _identity(entry)
            expected_size = info.st_size
            chunks = bytearray()
            offset = 0
            while len(chunks) < expected_size:
                chunk = os.pread(self.fd, min(65536, maximum + 1 - len(chunks)), offset)
                if not chunk:
                    raise _RetainedLeafContentError(
                        f"{name} ended at {len(chunks)} of {expected_size} bytes "
                        "(EOF before the initially stated size)"
                    )
                chunks.extend(chunk)
                offset += len(chunk)
                if len(chunks) > maximum or len(chunks) > expected_size:
                    raise _RetainedLeafContentError(
                        f"{name} grew past its stated size"
                    )
            if os.pread(self.fd, 1, offset) not in (b"",):
                raise _RetainedLeafContentError(
                    f"{name} carries bytes beyond its stated size"
                )
            self.data = bytes(chunks)
            # Post-read proof: retained descriptor identity+size exact and
            # the parent-relative name still names this inode/metadata.
            self.revalidate(parent)
        except BaseException:
            self.close()
            raise

    def revalidate(self, parent: _RetainedDirectory) -> None:
        current = os.fstat(self.fd)
        if _identity(current) != self.identity:
            raise ValueError(f"retained leaf drifted: {self.label}")
        if current.st_size != len(self.data):
            raise _RetainedLeafContentError(
                f"retained leaf size drift: {self.label}"
            )
        chunks = bytearray()
        offset = 0
        expected_size = len(self.data)
        while len(chunks) < expected_size:
            chunk = os.pread(
                self.fd,
                min(65536, expected_size - len(chunks)),
                offset,
            )
            if not chunk:
                raise _RetainedLeafContentError(
                    f"retained leaf ended during revalidation: {self.label}"
                )
            chunks.extend(chunk)
            offset += len(chunk)
        if os.pread(self.fd, 1, offset) != b"":
            raise _RetainedLeafContentError(
                f"retained leaf grew during revalidation: {self.label}"
            )
        if bytes(chunks) != self.data:
            raise _RetainedLeafContentError(
                f"retained leaf content drift: {self.label}"
            )
        entry = os.stat(self.label, dir_fd=parent.fd, follow_symlinks=False)
        if _identity(entry) != self.name_entry:
            raise ValueError(f"name entry drifted for leaf {self.label}")
        if (entry.st_dev, entry.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError(f"opened-name substitution for leaf {self.label}")

    def close(self) -> None:
        if self.fd >= 0:
            with contextlib.suppress(OSError):
                os.close(self.fd)
            self.fd = -1


class _DescriptorSet:
    """Owns every retained directory/leaf descriptor until completion.

    ``root`` wraps the frozen canonical ``config.RetainedPrivateChain``
    seam and is always closed LAST, after all processing-owned descendants;
    directory levels already close deepest-first among themselves.
    """

    def __init__(self) -> None:
        self.root: "_CanonicalRoot | None" = None
        self.directories: list[_RetainedDirectory] = []
        self.leaves: list[_RetainedLeaf] = []
        self.db_leaves: list[_RetainedDatabaseLeaf] = []
        self.state_level: _RetainedDirectory | None = None
        self.inbox_level: _RetainedDirectory | None = None

    def attach_root(self, root: "_CanonicalRoot") -> None:
        if self.root is not None:
            raise ValueError("a canonical root is already attached")
        self.root = root

    def push_directory(self, level: _RetainedDirectory) -> _RetainedDirectory:
        self.directories.append(level)
        return level

    def push_leaf(self, leaf: _RetainedLeaf) -> _RetainedLeaf:
        self.leaves.append(leaf)
        return leaf

    def revalidate_directories(self) -> None:
        for level in self.directories:
            level.revalidate()
        if self.root is not None:
            self.root.revalidate()

    def revalidate_leaves(self) -> None:
        for leaf in self.leaves:
            try:
                leaf.revalidate(leaf.parent)
            except _RetainedLeafContentError as exc:
                raise ProcessingRefused(
                    REASON_ENVELOPE_BYTES,
                    f"retained processing envelope content drifted: {exc}",
                ) from exc
            except (OSError, ValueError) as exc:
                raise ProcessingRefused(
                    REASON_ENVELOPE_PATH,
                    f"retained processing envelope authority drifted: {exc}",
                ) from exc

    def close(self) -> None:
        for db_leaf in self.db_leaves:
            if db_leaf.fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(db_leaf.fd)
                db_leaf.fd = -1
        self.db_leaves.clear()
        for leaf in self.leaves:
            leaf.close()
        self.leaves.clear()
        for level in reversed(self.directories):
            level.close()
        self.directories.clear()
        root = self.root
        self.root = None
        if root is not None:
            root.close()

    def __enter__(self) -> "_DescriptorSet":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


class _CanonicalRoot:
    """Minimal owned adapter over the frozen canonical data-root seam.

    Delegates every platform concern (raw lexical validation, Darwin
    trusted-hop handling, pre-audit identity snapshot, retained
    openat/O_NOFOLLOW walk, strict ownership/mode proof, locator-only
    ancestor identity) to ``config.open_existing_private_data_root``. No
    alias or realpath logic lives in this module.
    """

    def __init__(self, data_home: Path) -> None:
        self._chain = open_existing_private_data_root(str(data_home))

    @property
    def fd(self) -> int:
        return self._chain.deepest_fd

    def revalidate(self) -> None:
        self._chain.revalidate()

    def close(self) -> None:
        self._chain.close()


def _open_chain_to(path: Path, descriptors: _DescriptorSet) -> _CanonicalRoot:
    """Anchor the private authority through the canonical frozen seam only.

    A non-fresh ``descriptors`` (root already attached) refuses BEFORE any
    descriptor is opened. Ownership transfer is part of the guarded
    transaction: on any exception the freshly opened root is closed and
    nothing is attached; pre-existing caller ownership is never touched.
    """

    if descriptors.root is not None:
        raise ValueError("a canonical root is already attached to this set")
    root = _CanonicalRoot(path)
    try:
        root.revalidate()
        descriptors.attach_root(root)
    except BaseException:
        root.close()
        raise
    return root


def open_processing_authority(
    data_home: Path, descriptors: _DescriptorSet
) -> tuple[_CanonicalRoot, _RetainedDirectory, _RetainedDirectory]:
    """Atomically retain data_home (canonical seam) + state + inbox 0700.

    A non-fresh ``descriptors`` refuses before anything opens. Every level
    opened here transfers into the set inside one guarded transaction; any
    failure closes only the objects THIS call opened and leaves both
    ``descriptors`` and any pre-existing caller ownership untouched.
    """

    if descriptors.root is not None or descriptors.directories or descriptors.leaves:
        raise ValueError("descriptor set is not fresh")
    root = _CanonicalRoot(data_home)
    levels: list[_RetainedDirectory] = []
    try:
        root.revalidate()
        current: Any = root
        for name in ("state", "processing-inbox"):
            level = _RetainedDirectory(current, name, require_private=True)
            levels.append(level)
            current = level
        descriptors.attach_root(root)
        descriptors.directories.extend(levels)
        descriptors.state_level = levels[0]
        descriptors.inbox_level = levels[1]
    except BaseException:
        for level in reversed(levels):
            level.close()
        root.close()
        raise
    return root, levels[0], levels[1]


def _retain_relative(
    base: Any, relatives: list[tuple[str, bool]], descriptors: _DescriptorSet
) -> _RetainedDirectory:
    """Open consecutive children below ``base``; bool marks privacy.

    Registration into ``descriptors`` is part of the guarded transaction;
    if opening OR registration fails, every level opened by this call is
    closed and nothing is registered.
    """

    current = base
    opened: list[_RetainedDirectory] = []
    try:
        for name, private in relatives:
            level = _RetainedDirectory(current, name, require_private=private)
            opened.append(level)
            current = level
        descriptors.directories.extend(opened)
    except BaseException:
        for level in reversed(opened):
            level.close()
        raise
    return current


# --------------------------------------------------------------------------
# Retained processing-envelope authority (section 5).
# --------------------------------------------------------------------------

ENVELOPE_FILENAME_PATTERN = re.compile(r"^[0-9a-f]{64}\.json$")
ENVELOPE_TOP_LEVEL_KEYS = {
    "schema_version",
    "operation_id",
    "job_key",
    "profile_id",
    "profile_version",
    "track",
    "config",
    "databases",
    "raw",
    "profile",
    "extraction",
    "alignment",
    "scoring",
}

CONFIG_BINDING_KEYS = {
    "source_path",
    "source_file_sha256",
    "closure_files",
    "closure_sha256",
    "semantic_sha256",
}
DATABASE_IDENTITY_KEYS = {"path", "dev", "ino", "uid", "mode", "nlink"}
RAW_BINDING_KEYS = {"source_content_sha256", "raw_snapshot_sha256"}
PROFILE_BINDING_KEYS = {
    "profile_file_sha256",
    "evidence_file_sha256",
    "profile_sha256",
    "evidence_ledger_sha256",
    "profile_context_sha256",
}
EXTRACTION_BINDING_KEYS = {"output", "receipt"}
ALIGNMENT_BINDING_KEYS = {"output", "receipt"}
SCORING_BINDING_KEYS = {
    "parameters_sha256",
    "opportunity_policy_sha256",
    "expected_score",
}
LLM_RECEIPT_KEYS = {
    "receipt_id",
    "task",
    "model",
    "prompt_version",
    "input_sha256",
    "output_sha256",
    "created_at",
    "contract_version",
}


def validate_envelope_name(name: str) -> str:
    """One direct inbox child only; every alternate spelling refuses."""

    if not isinstance(name, str) or not name:
        raise ProcessingRefused(REASON_ENVELOPE_PATH, "envelope name must be a string")
    if name in (".", "..") or "/" in name or "\0" in name:
        raise ProcessingRefused(
            REASON_ENVELOPE_PATH,
            "envelope must be one direct lexical child of the processing inbox",
        )
    if os.path.isabs(name) or os.path.normpath(name) != name:
        raise ProcessingRefused(
            REASON_ENVELOPE_PATH, "absolute or alternate path spellings reject"
        )
    if not ENVELOPE_FILENAME_PATTERN.fullmatch(name):
        raise ProcessingRefused(
            REASON_ENVELOPE_PATH,
            "envelope leaf must be named <envelope_file_sha256>.json",
        )
    return name


def load_envelope_authority(
    data_home: Path, envelope_name: str
) -> tuple[_DescriptorSet, dict[str, Any], str, str]:
    """Retain root/state/inbox plus the exact envelope leaf; parse strictly.

    Returns ``(descriptors, payload, envelope_file_sha256,
    envelope_semantic_sha256)``. Every descriptor stays owned by the caller
    until completion; any failure closes everything this call opened.
    """

    validate_envelope_name(envelope_name)
    descriptors = _DescriptorSet()
    try:
        try:
            _root, _state, inbox = open_processing_authority(data_home, descriptors)
        except (OSError, ValueError) as exc:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE,
                f"data-home processing authority refused: {exc}",
            ) from exc
        try:
            info = os.stat(envelope_name, dir_fd=inbox.fd, follow_symlinks=False)
        except OSError as exc:
            raise ProcessingRefused(
                REASON_ENVELOPE_PATH,
                f"processing envelope leaf is not addressable: {exc}",
            ) from exc
        try:
            _require_private_leaf(info, "processing envelope")
        except ValueError as exc:
            raise ProcessingRefused(REASON_ENVELOPE_PATH, str(exc)) from exc
        _maybe_fault("after_envelope_prestat")
        if info.st_size > MAX_ENVELOPE_BYTES:
            raise ProcessingRefused(
                REASON_ENVELOPE_BYTES,
                f"processing envelope exceeds {MAX_ENVELOPE_BYTES} bytes",
            )
        try:
            leaf = descriptors.push_leaf(
                _RetainedLeaf(
                    inbox,
                    envelope_name,
                    maximum=MAX_ENVELOPE_BYTES,
                    prestat=info,
                )
            )
        except _RetainedLeafContentError as exc:
            raise ProcessingRefused(
                REASON_ENVELOPE_BYTES,
                f"processing envelope content refused: {exc}",
            ) from exc
        except (OSError, ValueError) as exc:
            raise ProcessingRefused(
                REASON_ENVELOPE_PATH,
                f"envelope leaf authority refused: {exc}",
            ) from exc
        raw_bytes = leaf.data
        if not raw_bytes:
            raise ValueError("processing envelope is empty")
        payload = strict_json_loads(raw_bytes)
        exact_keys(payload, ENVELOPE_TOP_LEVEL_KEYS, "processing envelope")
        try:
            canonical = canonical_json(payload).encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("envelope contains unencodable Unicode") from exc
        expected_bytes = canonical + b"\n"
        if raw_bytes != expected_bytes:
            raise ValueError(
                "envelope bytes are not canonical JSON followed by exactly one LF"
            )
        file_sha = sha256_hex(raw_bytes)
        semantic_sha = sha256_hex(canonical)
        if envelope_name != f"{file_sha}.json":
            raise ValueError("filename does not bind the exact envelope bytes")
        if payload.get("schema_version") != ENVELOPE_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {ENVELOPE_SCHEMA_VERSION!r}")
        return descriptors, payload, file_sha, semantic_sha
    except BaseException:
        descriptors.close()
        raise


# --------------------------------------------------------------------------
# Envelope binding schema validation (sections 8 and 9).
# --------------------------------------------------------------------------

def validate_config_binding(node: Any) -> dict[str, Any]:
    binding = exact_keys(node, CONFIG_BINDING_KEYS, "config binding")
    source_path = path_value(binding["source_path"], "config.source_path")
    sha256_value(binding["source_file_sha256"], "config.source_file_sha256")
    closure_files = binding["closure_files"]
    if not isinstance(closure_files, dict):
        raise ValueError("config.closure_files must be an object")
    if not 1 <= len(closure_files) <= 64:
        raise ValueError("config.closure_files must hold 1..64 entries")
    for key, value in closure_files.items():
        path_value(key, "config.closure_files key")
        sha256_value(value, "config.closure_files value")
    if closure_files.get(source_path) != binding["source_file_sha256"]:
        raise ValueError("closure_files must contain source_path exactly once")
    computed_closure = sha256_hex(canonical_json(closure_files).encode("utf-8"))
    if computed_closure != sha256_value(binding["closure_sha256"], "config.closure_sha256"):
        raise ValueError("closure_sha256 does not bind closure_files")
    sha256_value(binding["semantic_sha256"], "config.semantic_sha256")
    return binding


def validate_database_identity(node: Any, label: str) -> dict[str, Any]:
    identity = exact_keys(node, DATABASE_IDENTITY_KEYS, label)
    path_value(identity["path"], f"{label}.path")
    dev = identity["dev"]
    ino = identity["ino"]
    uid = identity["uid"]
    mode = identity["mode"]
    nlink = identity["nlink"]
    if not _is_int(dev) or dev < 0:
        raise ValueError(f"{label}.dev must be an integer >= 0")
    if not _is_int(ino) or ino <= 0:
        raise ValueError(f"{label}.ino must be an integer > 0")
    if not _is_int(uid) or uid != os.getuid():
        raise ValueError(f"{label}.uid must be exactly the current UID")
    if not _is_int(mode) or mode != 0o600:
        raise ValueError(f"{label}.mode must be exactly 0600 (384)")
    if not _is_int(nlink) or nlink != 1:
        raise ValueError(f"{label}.nlink must be exactly 1")
    return identity


def validate_database_bindings(
    node: Any,
    expected_assessments_path: str | None,
    expected_vacancy_path: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    bindings = exact_keys(node, {"assessments", "vacancy"}, "database bindings")
    assessments = validate_database_identity(bindings["assessments"], "database.assessments")
    vacancy = validate_database_identity(bindings["vacancy"], "database.vacancy")
    if expected_assessments_path is not None and (
        assessments["path"] != expected_assessments_path
    ):
        raise ValueError("assessments.path is not data_home/state/assessments.sqlite3")
    if expected_vacancy_path is not None and vacancy["path"] != expected_vacancy_path:
        raise ValueError("vacancy.path is not the collector-planned database")
    if assessments["dev"] != vacancy["dev"]:
        raise ValueError("both databases must share one filesystem device")
    if assessments["ino"] == vacancy["ino"]:
        raise ValueError("the two database identities must have distinct inodes")
    return assessments, vacancy


def validate_llm_receipt(node: Any, *, label: str) -> dict[str, Any]:
    """Reason-3 structural receipt mirror: closed keys/bounds/format only.

    Task authority, input binding, and output binding are semantic and are
    enforced at reasons 9/10 through the owner constructors and the accept
    functions, never here.
    """

    receipt = exact_keys(node, LLM_RECEIPT_KEYS, label)
    plain_string(receipt["receipt_id"], f"{label}.receipt_id", 1, 256)
    plain_string(receipt["task"], f"{label}.task", 1, 64)
    plain_string(receipt["model"], f"{label}.model", 1, 256)
    plain_string(receipt["prompt_version"], f"{label}.prompt_version", 1, 256)
    sha256_value(receipt["input_sha256"], f"{label}.input_sha256")
    sha256_value(receipt["output_sha256"], f"{label}.output_sha256")
    rfc3339_value(receipt["created_at"], f"{label}.created_at")
    if receipt["contract_version"] != LLM_CONTRACT_VERSION:
        raise ValueError(f"{label}.contract_version must be {LLM_CONTRACT_VERSION!r}")
    return receipt


def validate_extraction_binding(node: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    binding = exact_keys(node, EXTRACTION_BINDING_KEYS, "extraction binding")
    if not isinstance(binding["output"], dict):
        raise ValueError("extraction.output must be a JSON object")
    receipt = validate_llm_receipt(binding["receipt"], label="extraction.receipt")
    return binding["output"], receipt


def validate_alignment_binding(node: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    binding = exact_keys(node, ALIGNMENT_BINDING_KEYS, "alignment binding")
    if not isinstance(binding["output"], dict):
        raise ValueError("alignment.output must be a JSON object")
    receipt = validate_llm_receipt(binding["receipt"], label="alignment.receipt")
    return binding["output"], receipt


def validate_profile_binding(node: Any) -> dict[str, Any]:
    binding = exact_keys(node, PROFILE_BINDING_KEYS, "profile binding")
    for field in sorted(PROFILE_BINDING_KEYS):
        sha256_value(binding[field], f"profile.{field}")
    return binding


def validate_scoring_binding(node: Any) -> dict[str, Any]:
    """Reason-3 structure only: closed keys, SHA formats, numeric bounds.

    ScoringParams equality, the fixed policy body, and every expected-score
    identity/value relation are semantic authorities enforced at reasons
    11/12/13.
    """

    binding = exact_keys(node, SCORING_BINDING_KEYS, "scoring binding")
    sha256_value(binding["parameters_sha256"], "scoring.parameters_sha256")
    sha256_value(
        binding["opportunity_policy_sha256"],
        "scoring.opportunity_policy_sha256",
    )
    validate_score_result_shape(binding["expected_score"])
    return binding


SCORE_RESULT_KEYS = {
    "profile_id",
    "job_key",
    "track",
    "fit",
    "opportunity",
    "final",
    "fit_status",
    "parameters_hash",
    "fit_subscores",
    "opportunity_subscores",
}
FIT_SUBSCORE_KEYS = {
    "interest",
    "demonstrated_skill",
    "market_readiness",
    "technical_alignment",
    "evidence_match",
}
OPPORTUNITY_SUBSCORE_KEYS = {
    "market_demand",
    "accessibility",
    "growth_potential",
}


def validate_score_result_shape(node: Any) -> None:
    result = exact_keys(node, SCORE_RESULT_KEYS, "expected score result")
    _canonical_profile_id(result["profile_id"], "score.profile_id")
    job_key_value(result["job_key"])
    plain_string(result["track"], "score.track", 1, 128)
    unit_number(result["fit"], "score.fit")
    unit_number(result["opportunity"], "score.opportunity")
    final = result["final"]
    if not _is_number(final) or not math.isfinite(float(final)):
        raise ValueError("score.final must be a finite number")
    if not 0.0 <= float(final) <= 100.0:
        raise ValueError("score.final must be in [0,100]")
    plain_string(result["fit_status"], "score.fit_status", 1, 32)
    sha256_value(result["parameters_hash"], "score.parameters_hash")
    for label, expected_keys in (
        ("fit_subscores", FIT_SUBSCORE_KEYS),
        ("opportunity_subscores", OPPORTUNITY_SUBSCORE_KEYS),
    ):
        subscores = exact_keys(result[label], expected_keys, f"score.{label}")
        for key in sorted(expected_keys):
            unit_number(subscores[key], f"score.{label}.{key}")


def validate_raw_binding(node: Any) -> dict[str, Any]:
    binding = exact_keys(node, RAW_BINDING_KEYS, "raw binding")
    sha256_value(binding["source_content_sha256"], "raw.source_content_sha256")
    sha256_value(binding["raw_snapshot_sha256"], "raw.raw_snapshot_sha256")
    return binding


# --------------------------------------------------------------------------
# Semantic raw posting shape (factored for the later admission phase; this
# increment performs NO SQLite reads).
# --------------------------------------------------------------------------

SEMANTIC_POSTING_KEYS = {
    "job_key",
    "board",
    "job_id",
    "url",
    "posted_at",
    "fetched_at",
    "raw_text",
    "raw_json",
    "fetch_status",
}


MAX_RAW_TEXT_BYTES = 4_000_000
MAX_RAW_JSON_NODES = 100_000
MAX_RAW_JSON_DEPTH = 64


def _reject_json_controls(node: Any, label: str, *, depth: int) -> None:
    """Ordinary (non-prose) control rejection over every key and string."""

    if depth > MAX_RAW_JSON_DEPTH:
        raise ValueError(f"{label} nesting exceeds depth {MAX_RAW_JSON_DEPTH}")
    if isinstance(node, str):
        reject_controls(node, prose=False, label=label)
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                raise ValueError(f"{label} object keys must be strings")
            reject_controls(key, prose=False, label=f"{label} key")
            _reject_json_controls(value, f"{label}.{key}", depth=depth + 1)
        return
    if isinstance(node, list):
        for index, element in enumerate(node):
            _reject_json_controls(element, f"{label}[{index}]", depth=depth + 1)
        return
    if node is None or isinstance(node, (bool, int)):
        return
    if isinstance(node, float):
        if not math.isfinite(node):
            raise ValueError(f"{label} must be a finite JSON number")
        return
    raise ValueError(f"{label} holds an unsupported JSON value type")


def validate_semantic_posting_shape(node: Any) -> dict[str, Any]:
    """Mirror of the section-9 semantic snapshot exactly.

    ``raw_json`` here is the SEMANTIC snapshot value: null or an already
    parsed JSON object, bounded to 100,000 nodes / depth 64, with every
    nested key and string control-checked. Legacy stored TEXT parsing and
    legacy hash computation belong to the later database admission phase,
    never to this shape check.
    """

    posting = exact_keys(node, SEMANTIC_POSTING_KEYS, "semantic raw posting")
    job_key_value(posting["job_key"])
    plain_string(posting["board"], "posting.board", 1, 128)
    plain_string(posting["job_id"], "posting.job_id", 1, 256)
    plain_string(posting["url"], "posting.url", 1, 4096)
    posted_at = posting["posted_at"]
    if posted_at is not None:
        rfc3339_value(posted_at, "posting.posted_at")
    rfc3339_value(posting["fetched_at"], "posting.fetched_at")
    raw_text = posting["raw_text"]
    if raw_text is not None:
        prose_string(raw_text, "posting.raw_text", 0, MAX_RAW_TEXT_BYTES)
    raw_json = posting["raw_json"]
    if raw_json is not None:
        if not isinstance(raw_json, dict):
            raise ValueError("posting.raw_json must be a parsed JSON object or null")
        bounded_json_nodes(
            raw_json,
            "posting.raw_json",
            max_nodes=MAX_RAW_JSON_NODES,
            max_depth=MAX_RAW_JSON_DEPTH,
        )
        _reject_json_controls(raw_json, "posting.raw_json", depth=0)
    if posting["fetch_status"] != "fetched":
        raise ValueError('posting.fetch_status must be exactly "fetched"')
    return posting


# --------------------------------------------------------------------------
# Extraction output schema (exact SemanticVacancyExtraction mirror).
# --------------------------------------------------------------------------

EXTRACTION_OUTPUT_KEYS = {
    "source_content_sha256",
    "title",
    "company",
    "location",
    "description",
    "responsibilities",
    "required_skills",
    "preferred_skills",
    "required_qualifications",
    "preferred_qualifications",
    "work_authorisation",
    "contract_type",
    "seniority",
    "remote_policy",
    "extraction_confidence",
    "unknown_fields",
    "contract_version",
}
EXTRACTION_ARRAY_FIELDS = (
    "responsibilities",
    "required_skills",
    "preferred_skills",
    "required_qualifications",
    "preferred_qualifications",
    "work_authorisation",
)


def _string_array(
    node: Any,
    label: str,
    *,
    max_items: int,
    item_low: int,
    item_high: int,
    prose: bool,
) -> None:
    if not isinstance(node, list):
        raise ValueError(f"{label} must be an array")
    if len(node) > max_items:
        raise ValueError(f"{label} must hold at most {max_items} items")
    validator = prose_string if prose else plain_string
    seen: set[str] | None = set() if label.endswith("evidence_ids") else None
    for index, element in enumerate(node):
        validator(element, f"{label}[{index}]", item_low, item_high)
        if seen is not None:
            if element in seen:
                raise ValueError(f"{label} must hold unique evidence ids")
            seen.add(element)


def validate_extraction_output(node: Any) -> dict[str, Any]:
    output = exact_keys(node, EXTRACTION_OUTPUT_KEYS, "extraction output")
    sha256_value(output["source_content_sha256"], "extraction.source_content_sha256")
    plain_string(output["title"], "extraction.title", 1, 4096)
    plain_string(output["company"], "extraction.company", 0, 4096)
    plain_string(output["location"], "extraction.location", 0, 4096)
    prose_string(output["description"], "extraction.description", 1, 1_000_000)
    for field in EXTRACTION_ARRAY_FIELDS:
        _string_array(
            output[field],
            f"extraction.{field}",
            max_items=512,
            item_low=1,
            item_high=8192,
            prose=True,
        )
    plain_string(output["contract_type"], "extraction.contract_type", 0, 256)
    plain_string(output["seniority"], "extraction.seniority", 0, 256)
    plain_string(output["remote_policy"], "extraction.remote_policy", 0, 256)
    unit_number(output["extraction_confidence"], "extraction.extraction_confidence")
    _string_array(
        output["unknown_fields"],
        "extraction.unknown_fields",
        max_items=256,
        item_low=1,
        item_high=256,
        prose=True,
    )
    if output["contract_version"] != LLM_CONTRACT_VERSION:
        raise ValueError("extraction.contract_version must be market-aligner.llm.v1")
    return output


# --------------------------------------------------------------------------
# Alignment output schema (exact EvidenceAlignment/EvidenceMatch mirror).
# --------------------------------------------------------------------------

ALIGNMENT_OUTPUT_KEYS = {
    "profile_id",
    "profile_version",
    "job_key",
    "matches",
    "missing_requirements",
    "technical_alignment",
    "evidence_match",
    "confidence",
    "unknowns",
    "contract_version",
}
EVIDENCE_MATCH_KEYS = {"requirement", "evidence_ids", "strength", "rationale"}


def validate_evidence_match(node: Any, index: int) -> dict[str, Any]:
    match = exact_keys(node, EVIDENCE_MATCH_KEYS, f"alignment.matches[{index}]")
    prose_string(match["requirement"], f"matches[{index}].requirement", 1, 8192)
    _string_array(
        match["evidence_ids"],
        f"matches[{index}].evidence_ids",
        max_items=256,
        item_low=1,
        item_high=256,
        prose=False,
    )
    unit_number(match["strength"], f"matches[{index}].strength")
    prose_string(match["rationale"], f"matches[{index}].rationale", 1, 8192)
    return match


def _canonical_profile_id(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    canonical = validate_profile_id(value)
    if canonical != value:
        raise ValueError(
            f"{label} must be exactly canonical prf_<32 lowercase hex characters>"
        )
    return canonical


def validate_alignment_output(node: Any) -> dict[str, Any]:
    output = exact_keys(node, ALIGNMENT_OUTPUT_KEYS, "alignment output")
    _canonical_profile_id(output["profile_id"], "alignment.profile_id")
    plain_string(output["profile_version"], "alignment.profile_version", 1, 128)
    job_key_value(output["job_key"])
    matches = output["matches"]
    if not isinstance(matches, list) or len(matches) > 512:
        raise ValueError("alignment.matches must be an array of at most 512 items")
    for index, match in enumerate(matches):
        validate_evidence_match(match, index)
    _string_array(
        output["missing_requirements"],
        "alignment.missing_requirements",
        max_items=512,
        item_low=1,
        item_high=8192,
        prose=True,
    )
    unit_number(output["technical_alignment"], "alignment.technical_alignment")
    unit_number(output["evidence_match"], "alignment.evidence_match")
    unit_number(output["confidence"], "alignment.confidence")
    _string_array(
        output["unknowns"],
        "alignment.unknowns",
        max_items=256,
        item_low=1,
        item_high=8192,
        prose=True,
    )
    if output["contract_version"] != LLM_CONTRACT_VERSION:
        raise ValueError("alignment.contract_version must be market-aligner.llm.v1")
    return output


def bind_receipt_to_output(receipt: dict[str, Any], output: Any, label: str) -> None:
    """The receipt's output_sha256 must bind the exact canonical output."""

    canonical_output = canonical_json(output).encode("utf-8")
    if sha256_hex(canonical_output) != receipt["output_sha256"]:
        raise ValueError(f"{label}.receipt.output_sha256 does not bind {label}.output")


# --------------------------------------------------------------------------
# Closed envelope schema orchestration (sections 8 through 10).
# --------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class DatabaseFacts:
    """Complete exact DatabaseIdentity preserved for later binding."""

    path: str
    dev: int
    ino: int
    uid: int
    mode: int
    nlink: int

    def as_identity(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "dev": self.dev,
            "ino": self.ino,
            "uid": self.uid,
            "mode": self.mode,
            "nlink": self.nlink,
        }


@dataclasses.dataclass(frozen=True)
class RawBindingFacts:
    source_content_sha256: str
    raw_snapshot_sha256: str


@dataclasses.dataclass(frozen=True)
class RawSnapshotFacts:
    """Immutable admitted raw snapshot: primitives and bytes only.

    Built once from the exact current ``vacancy.postings`` row at reason 7.
    The parsed semantic JSON object is deliberately NOT exposed; later
    stages consume the validated primitives plus the canonical bytes and
    hashes so nothing mutable can escape the admission lease.
    """

    job_key: str
    board: str
    job_id: str
    url: str
    posted_at: str | None
    fetched_at: str
    fetch_status: str
    raw_text: str | None
    raw_json_text: str | None
    source_content_sha256: str
    raw_snapshot_sha256: str
    semantic_canonical: bytes


@dataclasses.dataclass(frozen=True)
class ExtractionFacts:
    """Reason-3 structural extraction mirror: types preserved, owners absent.

    ``output_structural`` is an immutable nested-tuple mirror of the staged
    output preserving exact JSON primitive types (int stays int, float stays
    float). No ``SemanticVacancyExtraction`` exists here; that semantic
    owner is constructed only at reason 9 where its nonblank owner rules
    are enforced and mapped to ``binding_extraction``.
    """

    output_structural: tuple[tuple[str, Any], ...]
    output_canonical: bytes
    receipt: LLMReceipt


@dataclasses.dataclass(frozen=True)
class AlignmentFacts:
    """Reason-3 structural alignment mirror (see :class:`ExtractionFacts`).

    ``EvidenceMatch``/``EvidenceAlignment`` construction happens only at
    reason 10, mapped to ``binding_alignment``.
    """

    output_structural: tuple[tuple[str, Any], ...]
    output_canonical: bytes
    receipt: LLMReceipt


@dataclasses.dataclass(frozen=True)
class ExpectedScoreFacts:
    profile_id: str
    job_key: str
    track: str
    fit: float
    opportunity: float
    final: float
    fit_status: str
    parameters_hash: str
    fit_subscores: tuple[tuple[str, float], ...]
    opportunity_subscores: tuple[tuple[str, float], ...]


@dataclasses.dataclass(frozen=True)
class EnvelopeFacts:
    """Immutable accepted facts extracted from one validated envelope.

    Every field is a primitive, bytes, or immutable nested tuple; no
    dict/list/frozenset and no semantic owner dataclass is reachable, so no
    nested mutation is possible. ``extraction``/``alignment`` carry only the
    type-preserving structural mirrors plus canonical bytes; owner
    dataclasses are constructed at reasons 9/10.
    """

    envelope_file_sha256: str
    envelope_semantic_sha256: str
    envelope_semantic_bytes: bytes
    operation_id: str
    job_key: str
    profile_id: str
    profile_version: str
    track: str
    config_source_path: str
    config_source_file_sha256: str
    config_closure_files: tuple[tuple[str, str], ...]
    config_closure_sha256: str
    config_semantic_sha256: str
    assessments: DatabaseFacts
    vacancy: DatabaseFacts
    raw: RawBindingFacts
    profile_binding_shas: tuple[tuple[str, str], ...]
    extraction: ExtractionFacts
    alignment: AlignmentFacts
    scoring_parameters_sha256: str
    scoring_opportunity_policy_sha256: str
    expected_score: ExpectedScoreFacts
    expected_score_canonical: bytes


_IMMUTABLE_PRIMITIVES = (str, int, float, bool, bytes, type(None))


def _assert_fully_immutable(node: Any, label: str) -> None:
    if isinstance(node, _IMMUTABLE_PRIMITIVES):
        return
    if isinstance(node, tuple):
        for element in node:
            _assert_fully_immutable(element, label)
        return
    if dataclasses.is_dataclass(node) and not isinstance(node, type):
        for field in dataclasses.fields(node):
            _assert_fully_immutable(
                getattr(node, field.name), f"{label}.{field.name}"
            )
        return
    raise TypeError(f"{label} exposes a mutable {type(node).__name__}")


def _freeze_structure(node: Any) -> Any:
    """Immutable type-preserving mirror: lists/dicts become nested tuples."""

    if isinstance(node, list):
        return tuple(_freeze_structure(element) for element in node)
    if isinstance(node, dict):
        return tuple(
            sorted((key, _freeze_structure(value)) for key, value in node.items())
        )
    if isinstance(node, _IMMUTABLE_PRIMITIVES):
        return node
    raise TypeError(f"cannot freeze a mutable {type(node).__name__}")


def _extraction_from_structural(
    structural: tuple[tuple[str, Any], ...],
) -> SemanticVacancyExtraction:
    """Reason-9 semantic owner construction (nonblank rules enforced here)."""

    node = dict(structural)
    return SemanticVacancyExtraction(
        source_content_sha256=node["source_content_sha256"],
        title=node["title"],
        company=node["company"],
        location=node["location"],
        description=node["description"],
        responsibilities=tuple(node["responsibilities"]),
        required_skills=tuple(node["required_skills"]),
        preferred_skills=tuple(node["preferred_skills"]),
        required_qualifications=tuple(node["required_qualifications"]),
        preferred_qualifications=tuple(node["preferred_qualifications"]),
        work_authorisation=tuple(node["work_authorisation"]),
        contract_type=node["contract_type"],
        seniority=node["seniority"],
        remote_policy=node["remote_policy"],
        extraction_confidence=node["extraction_confidence"],
        unknown_fields=tuple(node["unknown_fields"]),
        contract_version=node["contract_version"],
    )


def _alignment_from_structural(
    structural: tuple[tuple[str, Any], ...],
) -> EvidenceAlignment:
    """Reason-10 semantic owner construction (owner rules enforced here)."""

    node = dict(structural)
    matches = tuple(
        EvidenceMatch(
            requirement=match_node["requirement"],
            evidence_ids=tuple(match_node["evidence_ids"]),
            strength=match_node["strength"],
            rationale=match_node["rationale"],
        )
        for match in node["matches"]
        for match_node in (dict(match),)
    )
    return EvidenceAlignment(
        profile_id=node["profile_id"],
        profile_version=node["profile_version"],
        job_key=node["job_key"],
        matches=matches,
        missing_requirements=tuple(node["missing_requirements"]),
        technical_alignment=node["technical_alignment"],
        evidence_match=node["evidence_match"],
        confidence=node["confidence"],
        unknowns=tuple(node["unknowns"]),
        contract_version=node["contract_version"],
    )


def compose_envelope_facts(
    payload: Any,
    *,
    envelope_file_sha256: str,
    expected_assessments_path: str | None,
    expected_vacancy_path: str | None,
) -> EnvelopeFacts:
    """Validate the full closed schema and return immutable facts.

    Pure validation and construction over the already-parsed envelope: no
    descriptor, database, profile, raw store, provider, or model access.
    The caller passes the file hash of the exact retained envelope bytes so
    both hashes are linked to those bytes and to the filename binding made
    by load_envelope_authority.
    """

    if not isinstance(payload, dict):
        raise ValueError("processing envelope must be a JSON object")
    exact_keys(payload, ENVELOPE_TOP_LEVEL_KEYS, "processing envelope")
    if payload["schema_version"] != ENVELOPE_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {ENVELOPE_SCHEMA_VERSION!r}")
    operation_id = operation_id_value(payload["operation_id"])
    job_key = job_key_value(payload["job_key"])
    profile_id = _canonical_profile_id(payload["profile_id"], "envelope.profile_id")
    profile_version = plain_string(
        payload["profile_version"], "envelope.profile_version", 1, 128
    )
    track = plain_string(payload["track"], "envelope.track", 1, 128)

    config_binding = validate_config_binding(payload["config"])
    raw_node = validate_raw_binding(payload["raw"])
    profile_node = validate_profile_binding(payload["profile"])

    assessments_node, vacancy_node = validate_database_bindings(
        payload["databases"],
        expected_assessments_path,
        expected_vacancy_path,
    )

    extraction_output, extraction_receipt = validate_extraction_binding(
        payload["extraction"]
    )
    validate_extraction_output(extraction_output)
    extraction_structural = _freeze_structure(extraction_output)
    try:
        extraction_canonical = canonical_json(extraction_output).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("extraction output contains unencodable Unicode") from exc

    alignment_output, alignment_receipt = validate_alignment_binding(
        payload["alignment"]
    )
    validate_alignment_output(alignment_output)
    alignment_structural = _freeze_structure(alignment_output)
    try:
        alignment_canonical = canonical_json(alignment_output).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("alignment output contains unencodable Unicode") from exc

    # Scoring structure only: identities, parameters, policy, and exact
    # score semantics are reasons 11-13.
    scoring_binding = validate_scoring_binding(payload["scoring"])
    expected_score = scoring_binding["expected_score"]

    try:
        semantic_bytes = canonical_json(payload).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("envelope contains unencodable Unicode") from exc

    # The loaded-file binding proof runs LAST so invalid-field errors keep
    # their own stage; a fully valid payload with an arbitrary file hash
    # still refuses here.
    sha256_value(envelope_file_sha256, "envelope.envelope_file_sha256")
    if (
        hashlib.sha256(semantic_bytes + b"\n").hexdigest()
        != envelope_file_sha256
    ):
        raise ValueError(
            "envelope_file_sha256 must equal SHA-256 of the exact canonical "
            "envelope bytes plus one LF"
        )

    facts = EnvelopeFacts(
        envelope_file_sha256=envelope_file_sha256,
        envelope_semantic_sha256=hashlib.sha256(semantic_bytes).hexdigest(),
        envelope_semantic_bytes=semantic_bytes,
        operation_id=operation_id,
        job_key=job_key,
        profile_id=profile_id,
        profile_version=profile_version,
        track=track,
        config_source_path=config_binding["source_path"],
        config_source_file_sha256=config_binding["source_file_sha256"],
        config_closure_files=tuple(sorted(config_binding["closure_files"].items())),
        config_closure_sha256=config_binding["closure_sha256"],
        config_semantic_sha256=config_binding["semantic_sha256"],
        assessments=DatabaseFacts(
            path=assessments_node["path"],
            dev=int(assessments_node["dev"]),
            ino=int(assessments_node["ino"]),
            uid=int(assessments_node["uid"]),
            mode=int(assessments_node["mode"]),
            nlink=int(assessments_node["nlink"]),
        ),
        vacancy=DatabaseFacts(
            path=vacancy_node["path"],
            dev=int(vacancy_node["dev"]),
            ino=int(vacancy_node["ino"]),
            uid=int(vacancy_node["uid"]),
            mode=int(vacancy_node["mode"]),
            nlink=int(vacancy_node["nlink"]),
        ),
        raw=RawBindingFacts(
            source_content_sha256=raw_node["source_content_sha256"],
            raw_snapshot_sha256=raw_node["raw_snapshot_sha256"],
        ),
        profile_binding_shas=tuple(sorted(profile_node.items())),
        extraction=ExtractionFacts(
            output_structural=extraction_structural,
            output_canonical=extraction_canonical,
            receipt=LLMReceipt(**extraction_receipt),
        ),
        alignment=AlignmentFacts(
            output_structural=alignment_structural,
            output_canonical=alignment_canonical,
            receipt=LLMReceipt(**alignment_receipt),
        ),
        scoring_parameters_sha256=scoring_binding["parameters_sha256"],
        scoring_opportunity_policy_sha256=scoring_binding[
            "opportunity_policy_sha256"
        ],
        expected_score=ExpectedScoreFacts(
            profile_id=expected_score["profile_id"],
            job_key=expected_score["job_key"],
            track=expected_score["track"],
            fit=float(expected_score["fit"]),
            opportunity=float(expected_score["opportunity"]),
            final=float(expected_score["final"]),
            fit_status=expected_score["fit_status"],
            parameters_hash=expected_score["parameters_hash"],
            fit_subscores=tuple(
                sorted((k, float(v)) for k, v in expected_score["fit_subscores"].items())
            ),
            opportunity_subscores=tuple(
                sorted(
                    (k, float(v))
                    for k, v in expected_score["opportunity_subscores"].items()
                )
            ),
        ),
        expected_score_canonical=canonical_json(expected_score).encode("utf-8"),
    )
    _assert_fully_immutable(facts, "facts")
    return facts


# --------------------------------------------------------------------------
# PART 3A: provider-free read-only common/replay path (reasons 1-6).
# --------------------------------------------------------------------------

PROCESSING_BINDING_SCHEMA = "market-aligner.processing-binding.v1"
RECEIPT_SCHEMA = "market-aligner.processing-receipt.v1"
EVENT_TYPE_PROCESSING_SCORE_ACCEPTED = "processing_score_accepted"

BINDING_TOP_LEVEL_KEYS = {
    "schema_version",
    "operation_id",
    "job_key",
    "profile_id",
    "profile_version",
    "track",
    "envelope_file_sha256",
    "envelope_semantic_sha256",
    "config",
    "databases",
    "raw",
    "profile",
    "extraction",
    "alignment",
    "scoring",
}
RECEIPT_TOP_LEVEL_KEYS = {
    "schema_version",
    "operation_id",
    "job_key",
    "profile_id",
    "profile_version",
    "track",
    "binding_sha256",
    "envelope_file_sha256",
    "envelope_semantic_sha256",
    "config",
    "databases",
    "raw",
    "profile",
    "extraction",
    "alignment",
    "scoring",
    "normalised_projection",
    "assessment_projection",
    "assessment_event",
    "created_at",
    "time_authenticated",
    "imported_model_policy_authenticated",
    "imported_time_authenticated",
    "research_authority",
    "application_authority",
    "release_authority",
    "submission_authority",
    "self_hash",
}
NORMALISED_PROJECTION_KEYS = {"job_key", "normalized_json_sha256", "normalized_at"}
ASSESSMENT_PROJECTION_KEYS = {
    "profile_id",
    "job_key",
    "score_payload_hash",
    "state",
    "created_at",
    "updated_at",
}
ASSESSMENT_EVENT_PROJECTION_KEYS = {
    "id",
    "event_type",
    "actor_kind",
    "payload_sha256",
    "idempotency_key",
    "created_at",
}
_RECEIPT_FALSE_FLAGS = (
    "time_authenticated",
    "imported_model_policy_authenticated",
    "imported_time_authenticated",
    "research_authority",
    "application_authority",
    "release_authority",
    "submission_authority",
)

RECEIPT_MAX_BYTES = 4_194_304
_SQLITE_MAX_INT = 9223372036854775807

_RECEIPT_STORE_COMPATIBLE = "receipt_store_compatible"

DISPOSITION_DEFINITIVE_ABSENCE = "definitive_absence"
DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY = "provisional_atomic_incompatibility"
DISPOSITION_EXACT_REPLAY = "exact_replay"
DISPOSITION_EXISTING_RECEIPT_MISMATCH = "existing_receipt_mismatch"


@dataclasses.dataclass(frozen=True)
class ReplayClassification:
    disposition: str
    stored_receipt_bytes: bytes | None
    detail: str


def build_processing_binding(
    payload: dict[str, Any], *, envelope_file_sha256: str
) -> tuple[dict[str, Any], str]:
    """Build the exact processing-binding.v1 object and its SHA-256."""

    binding = {
        "schema_version": PROCESSING_BINDING_SCHEMA,
        "operation_id": payload["operation_id"],
        "job_key": payload["job_key"],
        "profile_id": payload["profile_id"],
        "profile_version": payload["profile_version"],
        "track": payload["track"],
        "envelope_file_sha256": envelope_file_sha256,
        "envelope_semantic_sha256": sha256_hex(
            canonical_json(payload).encode("utf-8")
        ),
        "config": copy.deepcopy(payload["config"]),
        "databases": copy.deepcopy(payload["databases"]),
        "raw": copy.deepcopy(payload["raw"]),
        "profile": copy.deepcopy(payload["profile"]),
        "extraction": copy.deepcopy(payload["extraction"]),
        "alignment": copy.deepcopy(payload["alignment"]),
        "scoring": copy.deepcopy(payload["scoring"]),
    }
    exact_keys(binding, BINDING_TOP_LEVEL_KEYS, "processing binding")
    return binding, sha256_hex(canonical_json(binding).encode("utf-8"))


def build_processing_binding_from_facts(
    facts: EnvelopeFacts,
) -> tuple[dict[str, Any], str]:
    """Derive the staged binding ONLY from immutable EnvelopeFacts bytes.

    The caller-mutable payload is never trusted: the accepted semantic
    bytes are strict-parsed again here, so the derived candidate binds the
    exact validated sections.
    """

    validated = strict_json_loads(bytes(facts.envelope_semantic_bytes))
    return build_processing_binding(
        validated, envelope_file_sha256=facts.envelope_file_sha256
    )


PROCESSING_EVENT_PAYLOAD_KEYS = {
    "schema_version",
    "operation_id",
    "profile_id",
    "job_key",
    "track",
    "binding_sha256",
    "envelope_file_sha256",
    "raw_snapshot_sha256",
    "profile_context_sha256",
    "extraction_input_sha256",
    "extraction_output_sha256",
    "extraction_receipt_id",
    "alignment_input_sha256",
    "alignment_output_sha256",
    "alignment_receipt_id",
    "normalized_json_sha256",
    "assessment_payload_hash",
    "parameters_sha256",
    "opportunity_policy_sha256",
    "score_result_sha256",
}


def build_processing_event_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the exact flat processing-score-event.v1 payload."""

    extraction_receipt = receipt["extraction"]["receipt"]
    alignment_receipt = receipt["alignment"]["receipt"]
    payload = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "operation_id": receipt["operation_id"],
        "profile_id": receipt["profile_id"],
        "job_key": receipt["job_key"],
        "track": receipt["track"],
        "binding_sha256": receipt["binding_sha256"],
        "envelope_file_sha256": receipt["envelope_file_sha256"],
        "raw_snapshot_sha256": receipt["raw"]["raw_snapshot_sha256"],
        "profile_context_sha256": receipt["profile"]["profile_context_sha256"],
        "extraction_input_sha256": extraction_receipt["input_sha256"],
        "extraction_output_sha256": extraction_receipt["output_sha256"],
        "extraction_receipt_id": extraction_receipt["receipt_id"],
        "alignment_input_sha256": alignment_receipt["input_sha256"],
        "alignment_output_sha256": alignment_receipt["output_sha256"],
        "alignment_receipt_id": alignment_receipt["receipt_id"],
        "normalized_json_sha256": receipt["normalised_projection"][
            "normalized_json_sha256"
        ],
        "assessment_payload_hash": receipt["assessment_projection"][
            "score_payload_hash"
        ],
        "parameters_sha256": receipt["scoring"]["parameters_sha256"],
        "opportunity_policy_sha256": receipt["scoring"][
            "opportunity_policy_sha256"
        ],
        "score_result_sha256": sha256_hex(
            canonical_json(receipt["scoring"]["expected_score"]).encode("utf-8")
        ),
    }
    exact_keys(
        payload, PROCESSING_EVENT_PAYLOAD_KEYS, "processing event payload"
    )
    return payload


def receipt_self_hash(receipt_without_self: dict[str, Any]) -> str:
    canonical = canonical_json(receipt_without_self).encode("utf-8")
    return sha256_hex(canonical)


def sealed_receipt_bytes(complete_receipt: dict[str, Any]) -> bytes:
    return canonical_json(complete_receipt).encode("utf-8") + b"\n"


def expected_idempotency_key(
    profile_id: str, job_key: str, event_payload_sha256: str
) -> str:
    job_key_sha = hashlib.sha256(job_key.encode("utf-8")).hexdigest()
    return f"processing-score:{profile_id}:{job_key_sha}:{event_payload_sha256}"


def parse_processing_receipt(raw_bytes: bytes) -> dict[str, Any]:
    """Strict closed parser proving canonical byte identity and self hash."""

    if not isinstance(raw_bytes, bytes) or len(raw_bytes) < 3:
        raise ValueError("receipt bytes must be at least 3 bytes")
    if len(raw_bytes) > RECEIPT_MAX_BYTES:
        raise ValueError(f"receipt bytes exceed {RECEIPT_MAX_BYTES}")
    receipt = strict_json_loads(raw_bytes)
    exact_keys(receipt, RECEIPT_TOP_LEVEL_KEYS, "processing receipt")
    if raw_bytes != sealed_receipt_bytes(receipt):
        raise ValueError("receipt bytes are not canonical JSON plus one LF")
    if receipt["schema_version"] != RECEIPT_SCHEMA:
        raise ValueError(f"schema_version must be {RECEIPT_SCHEMA!r}")
    sha256_value(receipt["binding_sha256"], "receipt.binding_sha256")
    sha256_value(
        receipt["envelope_file_sha256"], "receipt.envelope_file_sha256"
    )
    sha256_value(
        receipt["envelope_semantic_sha256"], "receipt.envelope_semantic_sha256"
    )
    operation_id_value(receipt["operation_id"])
    plain_string(receipt["profile_version"], "receipt.profile_version", 1, 128)
    plain_string(receipt["track"], "receipt.track", 1, 128)
    for flag in _RECEIPT_FALSE_FLAGS:
        if receipt[flag] is not False:
            raise ValueError(f"receipt authority flag {flag} must be exactly false")
    exact_keys(
        receipt["normalised_projection"],
        NORMALISED_PROJECTION_KEYS,
        "receipt.normalised_projection",
    )
    job_key_value(receipt["normalised_projection"]["job_key"])
    sha256_value(
        receipt["normalised_projection"]["normalized_json_sha256"],
        "receipt.normalised_projection.normalized_json_sha256",
    )
    rfc3339_value(
        receipt["normalised_projection"]["normalized_at"],
        "receipt.normalised_projection.normalized_at",
    )
    if receipt["normalised_projection"]["job_key"] != receipt["job_key"]:
        raise ValueError("normalised projection job_key disagrees with the receipt")
    exact_keys(
        receipt["assessment_projection"],
        ASSESSMENT_PROJECTION_KEYS,
        "receipt.assessment_projection",
    )
    _canonical_profile_id(
        receipt["assessment_projection"]["profile_id"],
        "receipt.assessment_projection.profile_id",
    )
    job_key_value(receipt["assessment_projection"]["job_key"])
    sha256_value(
        receipt["assessment_projection"]["score_payload_hash"],
        "receipt.assessment_projection.score_payload_hash",
    )
    if receipt["assessment_projection"]["state"] != "scored":
        raise ValueError('receipt assessment state must be exactly "scored"')
    rfc3339_value(
        receipt["assessment_projection"]["created_at"],
        "receipt.assessment_projection.created_at",
    )
    rfc3339_value(
        receipt["assessment_projection"]["updated_at"],
        "receipt.assessment_projection.updated_at",
    )
    if receipt["assessment_projection"]["profile_id"] != receipt["profile_id"]:
        raise ValueError("assessment projection profile disagrees with the receipt")
    if receipt["assessment_projection"]["job_key"] != receipt["job_key"]:
        raise ValueError("assessment projection job_key disagrees with the receipt")
    event = receipt["assessment_event"]
    exact_keys(event, ASSESSMENT_EVENT_PROJECTION_KEYS, "receipt.assessment_event")
    if not _is_int(event["id"]) or event["id"] <= 0:
        raise ValueError("receipt assessment_event.id must be an integer > 0")
    if event["id"] > _SQLITE_MAX_INT:
        raise ValueError("receipt assessment_event.id exceeds SQLite maximum")
    if event["event_type"] != EVENT_TYPE_PROCESSING_SCORE_ACCEPTED:
        raise ValueError("receipt event_type must be processing_score_accepted")
    if event["actor_kind"] != "deterministic":
        raise ValueError('receipt actor_kind must be exactly "deterministic"')
    sha256_value(event["payload_sha256"], "receipt.assessment_event.payload_sha256")
    idem = event["idempotency_key"]
    if not isinstance(idem, str) or not idem.isascii():
        raise ValueError("receipt idempotency_key must be an ASCII string")
    if len(idem.encode("utf-8")) != 183:
        raise ValueError("receipt idempotency_key must be exactly 183 UTF-8 bytes")
    if not idem.startswith("processing-score:"):
        raise ValueError("receipt idempotency_key must use the contracted prefix")
    rfc3339_value(event["created_at"], "receipt.assessment_event.created_at")
    rfc3339_value(receipt["created_at"], "receipt.created_at")
    # Only receipt.created_at and event.created_at are newly-owned common
    # instants; assessment created_at/updated_at may be historical reused
    # values that differ from the new accepted instant.
    if event["created_at"] != receipt["created_at"]:
        raise ValueError(
            "event.created_at must equal receipt.created_at"
        )
    job_key_value(receipt["job_key"])
    _canonical_profile_id(receipt["profile_id"], "receipt.profile_id")

    claimed_self = receipt["self_hash"]
    sha256_value(claimed_self, "receipt.self_hash")
    without_self = {k: v for k, v in receipt.items() if k != "self_hash"}
    if receipt_self_hash(without_self) != claimed_self:
        raise ValueError("receipt self_hash does not bind the complete receipt")

    expected_idem = expected_idempotency_key(
        receipt["profile_id"], receipt["job_key"], event["payload_sha256"]
    )
    if idem != expected_idem:
        raise ValueError(
            "receipt idempotency_key does not follow the contracted formula"
        )
    return receipt


def reconstruct_receipt_envelope_facts(receipt: dict[str, Any]) -> EnvelopeFacts:
    """Reconstruct and fully validate the sealed envelope behind a receipt."""

    rebuilt = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "operation_id": receipt["operation_id"],
        "job_key": receipt["job_key"],
        "profile_id": receipt["profile_id"],
        "profile_version": receipt["profile_version"],
        "track": receipt["track"],
        "config": receipt["config"],
        "databases": receipt["databases"],
        "raw": receipt["raw"],
        "profile": receipt["profile"],
        "extraction": receipt["extraction"],
        "alignment": receipt["alignment"],
        "scoring": receipt["scoring"],
    }
    databases = rebuilt["databases"]
    if not isinstance(databases, dict) or set(databases) != {"assessments", "vacancy"}:
        raise ValueError("receipt databases node is not closed DatabaseBindings")
    assessments_node = databases.get("assessments")
    vacancy_node = databases.get("vacancy")
    if not isinstance(assessments_node, dict) or not isinstance(vacancy_node, dict):
        raise ValueError("receipt database identities are malformed")
    assessments_path = assessments_node.get("path")
    vacancy_path = vacancy_node.get("path")
    if not isinstance(assessments_path, str) or not isinstance(vacancy_path, str):
        raise ValueError("receipt database paths must be strings")
    return compose_envelope_facts(
        rebuilt,
        envelope_file_sha256=receipt["envelope_file_sha256"],
        expected_assessments_path=assessments_path,
        expected_vacancy_path=vacancy_path,
    )


def _self_validating_receipt(row_bytes: bytes) -> tuple[Any, EnvelopeFacts]:
    """Independently prove the stored receipt seals a complete envelope."""

    parsed = parse_processing_receipt(row_bytes)
    receipt_facts = reconstruct_receipt_envelope_facts(parsed)
    if (
        parsed["envelope_semantic_sha256"]
        != receipt_facts.envelope_semantic_sha256
    ):
        raise ValueError(
            "receipt envelope_semantic_sha256 disagrees with its reconstructed envelope"
        )
    _binding_object, reconstructed_binding_sha = build_processing_binding_from_facts(
        receipt_facts
    )
    if reconstructed_binding_sha != parsed["binding_sha256"]:
        raise ValueError(
            "receipt binding hash does not bind its own reconstructed envelope"
        )
    event_payload = build_processing_event_payload(parsed)
    if (
        sha256_hex(canonical_json(event_payload).encode("utf-8"))
        != parsed["assessment_event"]["payload_sha256"]
    ):
        raise ValueError(
            "receipt assessment_event.payload_sha256 does not bind its rebuilt payload"
        )
    return parsed, receipt_facts


class _RetainedDatabaseLeaf:
    """Owned O_RDONLY|O_NOFOLLOW database leaf bound to its parent name.

    Ownership registers into the caller's DescriptorSet immediately after
    ``os.open`` and BEFORE any validation, so no failure can leak the
    descriptor. Every authority proof is fstat/dir_fd based; no pathname-
    following stat ever decides authority.
    """

    def __init__(
        self,
        parent: Any,
        name: str,
        expected_identity: tuple[int, int, int, int, int],
        label: str,
        owner: _DescriptorSet,
        *,
        absolute_path: str,
    ) -> None:
        self.parent = parent
        self.name = name
        self.label = label
        self._absolute_path = absolute_path
        self.fd = -1
        raw = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent.fd)
        self.fd = raw
        owner.db_leaves.append(self)
        try:
            info = os.fstat(self.fd)
            _require_private_leaf(info, f"{label} database leaf")
            if (
                isinstance(info.st_size, bool)
                or not isinstance(info.st_size, int)
                or info.st_size < 0
            ):
                raise ProcessingRefused(
                    REASON_CONFIG_DATABASE,
                    f"{label} database has invalid size authority",
                )
            self.identity = _identity(info)
            self.size = info.st_size
            if self.identity != tuple(expected_identity):
                raise ProcessingRefused(
                    REASON_CONFIG_DATABASE,
                    f"{label} database differs from its staged binding identity",
                )
            self.revalidate()
        except BaseException:
            self.close(owner)
            raise

    @property
    def path(self) -> str:
        return self._absolute_path

    def revalidate(self, *, allow_size_change: bool = False) -> None:
        current = os.fstat(self.fd)
        if _identity(current) != self.identity:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE,
                f"{self.label} database leaf drifted while retained",
            )
        if not allow_size_change and current.st_size != self.size:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE,
                f"{self.label} database descriptor size drifted while retained",
            )
        try:
            entry = os.stat(
                self.name, dir_fd=self.parent.fd, follow_symlinks=False
            )
        except OSError as exc:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE,
                f"{self.label} database name entry became unstatable",
            ) from exc
        if _identity(entry) != self.identity:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE,
                f"{self.label} database name entry was substituted",
            )
        if not allow_size_change and entry.st_size != self.size:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE,
                f"{self.label} database name-entry size drifted while retained",
            )

    def accept_recovered_size(self) -> None:
        """Rebase only the byte-size fact after SQLite recovery.

        Rollback-journal recovery may legitimately change a database file's
        size.  It must never change which file the staged pathname denotes.
        This method therefore accepts a new size only while the retained fd
        and its descriptor-relative name entry still have the exact staged
        dev/inode/uid/mode/nlink identity and report one identical,
        nonnegative size.  Every later check is strict against that recovered
        size.
        """

        current = os.fstat(self.fd)
        try:
            entry = os.stat(
                self.name, dir_fd=self.parent.fd, follow_symlinks=False
            )
        except OSError as exc:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                f"{self.label} recovered database name is unstatable",
            ) from exc
        if _identity(current) != self.identity or _identity(entry) != self.identity:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                f"{self.label} recovered database identity was substituted",
            )
        if (
            type(current.st_size) is not int
            or type(entry.st_size) is not int
            or current.st_size < 0
            or entry.st_size < 0
            or current.st_size != entry.st_size
        ):
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                f"{self.label} recovered database size is incoherent",
            )
        self.size = current.st_size
        self.revalidate()

    def close(self, owner: _DescriptorSet) -> None:
        try:
            owner.db_leaves.remove(self)
        except ValueError:
            pass
        if self.fd >= 0:
            with contextlib.suppress(OSError):
                os.close(self.fd)
            self.fd = -1


def _assert_chain_intact(
    descriptors: "_DescriptorSet",
    pinned_assessments: "_RetainedDatabaseLeaf",
    pinned_vacancy: "_RetainedDatabaseLeaf",
    *,
    allow_sidecar_parent_nlink_churn: bool = False,
    allow_database_size_change: bool = False,
) -> None:
    """Prove every retained ancestor plus both leaves still agree."""

    try:
        if allow_sidecar_parent_nlink_churn:
            sidecar_parents = {
                id(pinned_assessments.parent),
                id(pinned_vacancy.parent),
            }
            for level in descriptors.directories:
                if id(level) not in sidecar_parents:
                    level.revalidate()
                    continue
                current = os.fstat(level.fd)
                if (
                    level.initial is None
                    or _identity(current)[:4] != level.initial[:4]
                    or not stat.S_ISDIR(current.st_mode)
                ):
                    raise ValueError(
                        f"retained sidecar parent drifted: {level.label}"
                    )
                if level.name_entry is not None:
                    assert level._parent is not None and level._name is not None
                    entry = os.stat(
                        level._name,
                        dir_fd=level._parent.fd,
                        follow_symlinks=False,
                    )
                    if _identity(entry)[:4] != level.name_entry[:4]:
                        raise ValueError(
                            f"sidecar parent name entry drifted: {level.label}"
                        )
                    if (entry.st_dev, entry.st_ino) != (
                        current.st_dev,
                        current.st_ino,
                    ):
                        raise ValueError(
                            f"sidecar parent name was substituted: {level.label}"
                        )
            if descriptors.root is not None:
                descriptors.root.revalidate()
        else:
            descriptors.revalidate_directories()
        descriptors.revalidate_leaves()
        pinned_assessments.revalidate(
            allow_size_change=allow_database_size_change
        )
        pinned_vacancy.revalidate(
            allow_size_change=allow_database_size_change
        )
    except ProcessingRefused:
        raise
    except (OSError, ValueError) as exc:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, f"retained database authority broke: {exc}"
        ) from exc


def _verify_live_config_binding(
    data_home: Path, facts: EnvelopeFacts
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Recompute the sole live configuration and collector-plan authority."""

    try:
        merged, identities = snapshot_config(facts.config_source_path)
    except ValueError as exc:
        raise ProcessingRefused(REASON_CONFIG_DATABASE, str(exc)) from exc
    if identities != dict(facts.config_closure_files):
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, "live configuration closure differs from staging"
        )
    if closure_identity(identities) != closure_identity(
        dict(facts.config_closure_files)
    ):
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, "live closure identity differs from staging"
        )
    source_sha = identities.get(facts.config_source_path)
    if source_sha != facts.config_source_file_sha256:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, "live configuration source file drifted"
        )
    semantic_now = sha256_hex(canonical_json(merged).encode("utf-8"))
    if semantic_now != facts.config_semantic_sha256:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, "semantic configuration drifted from staging"
        )
    try:
        plan = Collector.plan(Path(data_home), merged)
    except ValueError as exc:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, f"collector plan refused: {exc}"
        ) from exc
    if str(plan["database"]) != facts.vacancy.path:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, "planned collector database is not the staged path"
        )
    return merged, plan


def admit_config_and_databases(
    data_home: Path, facts: EnvelopeFacts, descriptors: _DescriptorSet
) -> dict[str, Any]:
    """Reasons 4-5 pre-SQLite: live config closure, collector plan, pins.

    Reuses snapshot_config/closure_identity/Collector.plan unchanged. The
    authority levels retained by load_envelope_authority are reused; the
    existing databases are pinned through owned O_RDONLY|O_NOFOLLOW
    descriptors, never created, and every unsafe path maps to reason 5.
    """

    if descriptors.root is None or descriptors.state_level is None:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, "envelope authority was not retained"
        )
    merged, plan = _verify_live_config_binding(data_home, facts)

    root = descriptors.root
    state_level = descriptors.state_level

    def relative_parts(path: str, label: str) -> tuple[str, ...]:
        try:
            rel = Path(path).relative_to(Path(data_home))
        except ValueError as exc:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE, f"{label} database escapes data_home"
            ) from exc
        if not rel.parts or ".." in rel.parts:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE, f"{label} database path is unsafe"
            )
        return rel.parts

    canonical_assessments = str(Path(data_home) / "state" / "assessments.sqlite3")
    if facts.assessments.path != canonical_assessments:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE,
            "staged assessments path is not the canonical data_home/state/assessments.sqlite3",
        )
    try:
        assessments_parts = relative_parts(facts.assessments.path, "assessments")
        if assessments_parts[0] != "state" or len(assessments_parts) != 2:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE,
                "assessments database must be exactly data_home/state/assessments.sqlite3",
            )
        current: Any = state_level
        for part in assessments_parts[1:-1]:
            level = _RetainedDirectory(current, part, require_private=True)
            current = descriptors.push_directory(level)
        pinned_assessments = _RetainedDatabaseLeaf(
            current,
            assessments_parts[-1],
            (
                facts.assessments.dev,
                facts.assessments.ino,
                facts.assessments.uid,
                facts.assessments.mode,
                facts.assessments.nlink,
            ),
            "assessments",
            descriptors,
            absolute_path=facts.assessments.path,
        )

        vacancy_parts = relative_parts(facts.vacancy.path, "vacancy")
        current = root
        for index, part in enumerate(vacancy_parts[:-1]):
            if index == 0 and part == "state":
                current = state_level
                continue
            level = _RetainedDirectory(current, part, require_private=True)
            current = descriptors.push_directory(level)
        pinned_vacancy = _RetainedDatabaseLeaf(
            current,
            vacancy_parts[-1],
            (
                facts.vacancy.dev,
                facts.vacancy.ino,
                facts.vacancy.uid,
                facts.vacancy.mode,
                facts.vacancy.nlink,
            ),
            "vacancy",
            descriptors,
            absolute_path=facts.vacancy.path,
        )
    except ProcessingRefused:
        raise
    except (OSError, ValueError) as exc:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, f"database authority refused: {exc}"
        ) from exc

    if pinned_assessments.identity[0] != pinned_vacancy.identity[0]:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, "databases must share one filesystem device"
        )
    if pinned_assessments.identity[1] == pinned_vacancy.identity[1]:
        raise ProcessingRefused(
            REASON_CONFIG_DATABASE, "databases must have distinct inodes"
        )
    _maybe_fault("after_database_pin")
    return {
        "plan": plan,
        "merged_config": merged,
        "assessments": pinned_assessments,
        "vacancy": pinned_vacancy,
    }


def map_sqlite_read_error(exc: BaseException) -> ProcessingRefused:
    """Map read-view SQLite failures onto stable atomic outcomes."""

    code = getattr(exc, "sqlite_errorcode", None)
    base = code & 0xFF if isinstance(code, int) else None
    if base in (5, 6):
        reason = REASON_ATOMIC_BUSY
    elif base == 13:
        reason = REASON_STORAGE_FULL
    elif base == 10:
        reason = REASON_STORAGE_IO_ERROR
    elif base == 9:
        reason = REASON_INTERRUPTED
    else:
        reason = REASON_ATOMIC_MODE
    detail = getattr(exc, "sqlite_errorname", None) or repr(exc)
    return ProcessingRefused(reason, f"read view failure: {detail}")


def _sqlite_file_uri(path: Path) -> str:
    """Deterministic POSIX SQLite ``file://`` URI for one absolute path.

    The input must be a :class:`~pathlib.Path` and absolute. The exact
    filesystem bytes (``os.fsencode``) are percent-encoded bytewise: only
    ASCII A-Z / a-z / 0-9 and ``/ - . _ ~`` stay literal, every other byte
    becomes an uppercase ``%HH`` escape. NUL bytes refuse before any
    filesystem or SQLite access. No network/urllib machinery is involved.
    """

    if not isinstance(path, Path):
        raise ValueError("sqlite file URI input must be a pathlib.Path")
    if not path.is_absolute():
        raise ValueError("sqlite file URI input must be an absolute path")
    encoded_path = os.fsencode(path)
    if b"\x00" in encoded_path:
        raise ValueError("sqlite file URI input must not contain NUL bytes")
    safe = frozenset(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b"abcdefghijklmnopqrstuvwxyz"
        b"0123456789/-._~"
    )
    out = bytearray(b"file://")
    for byte in encoded_path:
        if byte in safe:
            out.append(byte)
        else:
            out += b"%%%02X" % byte
    return out.decode("ascii")


def _open_read_view(
    descriptors: "_DescriptorSet",
    pinned_assessments: _RetainedDatabaseLeaf,
    pinned_vacancy: _RetainedDatabaseLeaf,
    *,
    allow_database_size_change: bool = False,
):
    """Open main mode=rw plus ATTACH vacancy; strictly read-only inspection."""

    connection = None
    try:
        main_uri = _sqlite_file_uri(Path(pinned_assessments.path)) + "?mode=rw"
        vacancy_uri = _sqlite_file_uri(Path(pinned_vacancy.path)) + "?mode=rw"
        _assert_chain_intact(descriptors, pinned_assessments, pinned_vacancy)
        connection = sqlite3.connect(main_uri, uri=True, timeout=0.05)
        connection.execute("PRAGMA query_only=ON")
        _assert_chain_intact(
            descriptors,
            pinned_assessments,
            pinned_vacancy,
            allow_sidecar_parent_nlink_churn=True,
            allow_database_size_change=allow_database_size_change,
        )
        connection.execute(
            "ATTACH DATABASE ? AS vacancy",
            (vacancy_uri,),
        )
        _verify_transaction_connection(
            connection,
            descriptors,
            pinned_assessments,
            pinned_vacancy,
            allow_database_size_change=allow_database_size_change,
        )
        return connection
    except sqlite3.Error as exc:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        raise map_sqlite_read_error(exc) from exc
    except BaseException:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        raise


def _verify_transaction_connection(
    connection: sqlite3.Connection,
    descriptors: "_DescriptorSet",
    pinned_assessments: _RetainedDatabaseLeaf,
    pinned_vacancy: _RetainedDatabaseLeaf,
    *,
    allow_database_size_change: bool = False,
) -> None:
    """Bind both SQLite aliases to the retained exact pathname authorities."""

    try:
        listed = connection.execute("PRAGMA database_list").fetchall()
    except sqlite3.Error as exc:
        raise map_sqlite_read_error(exc) from exc
    if type(listed) is not list or len(listed) != 2:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "database_list does not contain exactly two aliases",
        )
    names: dict[str, str] = {}
    for row in listed:
        if (
            type(row) is not tuple
            or len(row) != 3
            or type(row[0]) is not int
            or type(row[1]) is not str
            or type(row[2]) is not str
            or row[1] in names
        ):
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"database_list row is malformed: {row!r}",
            )
        names[row[1]] = row[2]
    expected = {
        "main": pinned_assessments.path,
        "vacancy": pinned_vacancy.path,
    }
    if names != expected:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "database_list aliases differ from the retained exact paths",
        )
    _assert_chain_intact(
        descriptors,
        pinned_assessments,
        pinned_vacancy,
        allow_sidecar_parent_nlink_churn=True,
        allow_database_size_change=allow_database_size_change,
    )


def _normalized_sql(sql: Any) -> str:
    if not isinstance(sql, str):
        return ""
    normalized = " ".join(sql.split())
    # SQLite stores a trailing STRICT table option adjacent to the closing
    # parenthesis even when the canonical migration source contains a space.
    return re.sub(r"\)\s+STRICT$", ")STRICT", normalized)


def _inspect_receipt_store(connection) -> ReplayClassification:
    """Three-way store inspection ahead of any operation lookup."""

    rows = connection.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' "
        "AND name IN ('market_aligner_schema_migrations','processing_receipts')"
    ).fetchall()
    present = {name: _normalized_sql(sql) for name, sql in rows}
    ledger_present = "market_aligner_schema_migrations" in present
    table_present = "processing_receipts" in present

    def provisional(detail: str) -> ReplayClassification:
        return ReplayClassification(
            DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY, None, detail
        )

    if not ledger_present and not table_present:
        return ReplayClassification(
            DISPOSITION_DEFINITIVE_ABSENCE,
            None,
            "migration ledger and processing_receipts absent; bootstrap eligible",
        )
    if table_present and not ledger_present:
        return provisional("processing_receipts exists without its migration ledger")
    if ledger_present and not table_present:
        return provisional("migration ledger exists without processing_receipts")
    canonical_ledger_sql = " ".join(
        LEDGER_DDL.replace("CREATE TABLE IF NOT EXISTS ", "CREATE TABLE ").split()
    )
    if present["market_aligner_schema_migrations"] != canonical_ledger_sql:
        return provisional("ledger DDL is not the canonical migration ledger")
    ledger_rows = connection.execute(
        "SELECT version, name, checksum FROM market_aligner_schema_migrations"
    ).fetchall()
    expected_ledger_row = (
        FIT001_PROCESSING_RECEIPTS.version,
        FIT001_PROCESSING_RECEIPTS.name,
        FIT001_PROCESSING_RECEIPTS.checksum,
    )
    if ledger_rows != [expected_ledger_row]:
        return provisional(
            "migration ledger rows are not exactly the FIT-001 migration"
        )
    if present["processing_receipts"] != _normalized_sql(FIT001_RECEIPTS_DDL):
        return provisional("processing_receipts DDL is not canonical")
    index_rows = connection.execute(
        "PRAGMA index_list(processing_receipts)"
    ).fetchall()
    actual_uniques: set[tuple[str, ...]] = set()
    for row in index_rows:
        unique, origin, partial = row[2], row[3], row[4]
        if not unique or partial or origin not in ("pk", "u", "c"):
            continue
        columns = tuple(
            info[2]
            for info in connection.execute(
                f"PRAGMA index_info({row[1]!r})"
            ).fetchall()
        )
        actual_uniques.add(columns)
    expected_uniques = {
        ("operation_id",),
        ("binding_sha256",),
        ("receipt_file_sha256",),
        ("profile_id", "job_key"),
    }
    if actual_uniques != expected_uniques:
        return provisional(
            "processing_receipts unique index facts are not exactly contracted"
        )
    foreign_keys = connection.execute(
        "PRAGMA foreign_key_list(processing_receipts)"
    ).fetchall()
    expected_fk = [
        (0, 0, "assessment_events", "event_id", "id", "NO ACTION", "RESTRICT", "NONE")
    ]
    if list(map(tuple, foreign_keys)) != expected_fk:
        return provisional(
            "processing_receipts foreign key facts are not exactly contracted"
        )
    return ReplayClassification(_RECEIPT_STORE_COMPATIBLE, None, "store compatible")


_ROW_TEXT_COLUMNS = (
    "operation_id",
    "profile_id",
    "job_key",
    "track",
    "binding_sha256",
    "envelope_file_sha256",
    "envelope_semantic_sha256",
    "normalized_sha256",
    "assessment_payload_hash",
    "receipt_self_hash",
    "receipt_file_sha256",
    "created_at",
)


def _classify_replay(
    connection,
    facts: EnvelopeFacts,
    binding_sha: str,
    descriptors: "_DescriptorSet",
    pinned_assessments: "_RetainedDatabaseLeaf",
    pinned_vacancy: "_RetainedDatabaseLeaf",
    *,
    allow_sidecar_parent_nlink_churn: bool = False,
    allow_database_size_change: bool = False,
) -> ReplayClassification:
    try:
        _assert_chain_intact(
            descriptors,
            pinned_assessments,
            pinned_vacancy,
            allow_sidecar_parent_nlink_churn=allow_sidecar_parent_nlink_churn,
            allow_database_size_change=allow_database_size_change,
        )
        store_state = _inspect_receipt_store(connection)
        if store_state.disposition != _RECEIPT_STORE_COMPATIBLE:
            return store_state
        row = connection.execute(
            "SELECT operation_id,profile_id,job_key,track,binding_sha256,"
            "envelope_file_sha256,envelope_semantic_sha256,normalized_sha256,"
            "assessment_payload_hash,event_id,receipt_self_hash,"
            "receipt_file_sha256,receipt_bytes,created_at "
            "FROM processing_receipts WHERE operation_id = ?",
            (facts.operation_id,),
        ).fetchone()
    except (KeyboardInterrupt, _Interrupted) as exc:
        raise ProcessingRefused(REASON_INTERRUPTED, "read view interrupted") from exc
    except sqlite3.Error as exc:
        raise map_sqlite_read_error(exc) from exc
    if row is None:
        return ReplayClassification(
            DISPOSITION_DEFINITIVE_ABSENCE,
            None,
            "no receipt for this operation in a compatible store",
        )

    def provisional(detail: str) -> ReplayClassification:
        return ReplayClassification(
            DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY, None, detail
        )

    (
        row_operation,
        row_profile,
        row_job_key,
        row_track,
        row_binding,
        row_envelope_file,
        row_envelope_semantic,
        row_normalized,
        row_assessment_payload,
        row_event_id,
        row_self_hash,
        row_file_hash,
        row_bytes,
        row_created_at,
    ) = row
    for value, column in zip(
        (
            row_operation,
            row_profile,
            row_job_key,
            row_track,
            row_binding,
            row_envelope_file,
            row_envelope_semantic,
            row_normalized,
            row_assessment_payload,
            row_self_hash,
            row_file_hash,
            row_created_at,
        ),
        _ROW_TEXT_COLUMNS,
    ):
        if not isinstance(value, str):
            return provisional(f"row column {column} is not TEXT")
    if not _is_int(row_event_id):
        return provisional("row column event_id is not INTEGER")
    if not isinstance(row_bytes, bytes):
        return provisional("stored receipt is not a BLOB")
    try:
        parsed, _receipt_facts = _self_validating_receipt(row_bytes)
    except ValueError as exc:
        return provisional(f"stored receipt fails independent validation: {exc}")

    row_pairs = (
        (parsed["operation_id"], row_operation, "operation"),
        (parsed["profile_id"], row_profile, "profile"),
        (parsed["job_key"], row_job_key, "job_key"),
        (parsed["track"], row_track, "track"),
        (parsed["binding_sha256"], row_binding, "binding hash"),
        (parsed["envelope_file_sha256"], row_envelope_file, "envelope file hash"),
        (
            parsed["envelope_semantic_sha256"],
            row_envelope_semantic,
            "envelope semantic hash",
        ),
        (
            parsed["normalised_projection"]["normalized_json_sha256"],
            row_normalized,
            "normalized hash",
        ),
        (
            parsed["assessment_projection"]["score_payload_hash"],
            row_assessment_payload,
            "assessment hash",
        ),
        (parsed["assessment_event"]["id"], row_event_id, "event id"),
        (parsed["self_hash"], row_self_hash, "self hash"),
        (parsed["created_at"], row_created_at, "created_at"),
    )
    for parsed_value, stored_value, label in row_pairs:
        if parsed_value != stored_value:
            return provisional(f"{label} disagrees between receipt and row")
    if sha256_hex(row_bytes) != row_file_hash:
        return provisional("receipt_file_sha256 does not bind the stored bytes")

    if parsed["binding_sha256"] == binding_sha:
        exact_fields = (
            ("profile_id", facts.profile_id),
            ("job_key", facts.job_key),
            ("profile_version", facts.profile_version),
            ("track", facts.track),
            ("envelope_file_sha256", facts.envelope_file_sha256),
            ("envelope_semantic_sha256", facts.envelope_semantic_sha256),
        )
        mismatches = [
            field for field, expected in exact_fields if parsed[field] != expected
        ]
        if mismatches:
            return provisional(
                "receipt fields disagree with staged facts: " + ",".join(mismatches)
            )
        return ReplayClassification(DISPOSITION_EXACT_REPLAY, row_bytes, "sealed replay")
    return ReplayClassification(
        DISPOSITION_EXISTING_RECEIPT_MISMATCH,
        None,
        "self-validating receipt carries a different staged processing binding",
    )


# --------------------------------------------------------------------------
# Part 3B1: raw snapshot admission at reason 7 (read-only continuation).
# --------------------------------------------------------------------------

_POSTING_COLUMN_TYPES: dict[str, frozenset[type]] = {
    "key": frozenset({str}),
    "board": frozenset({str}),
    "job_id": frozenset({str}),
    "url": frozenset({str}),
    "posted_at": frozenset({str, type(None)}),
    "fetched_at": frozenset({str}),
    "raw_text": frozenset({str, type(None)}),
    "raw_json": frozenset({str, type(None)}),
    "content_hash": frozenset({str}),
    "fetch_status": frozenset({str}),
}

_LOWERCASE_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")


def _posting_row_proof(row: sqlite3.Row) -> tuple[tuple[str, Any], ...]:
    return tuple((type(value).__name__, value) for value in tuple(row))


def _raw_snapshot_from_row(
    row: sqlite3.Row | None, facts: EnvelopeFacts
) -> RawSnapshotFacts:
    """Pure validator: exact current posting row -> immutable raw facts.

    Raises ``ValueError`` on every contract violation; the callers map all
    of them to reason 7. The stored raw_json TEXT is strictly parsed with
    duplicate-key and nonfinite rejection and is never reserialized into
    the legacy source hash; the semantic snapshot is validated through
    :func:`validate_semantic_posting_shape` and hashed canonically.
    """

    if row is None:
        raise ValueError("current posting row is missing")
    values = tuple(row)
    for column, value in zip(POSTING_READ_COLUMNS, values):
        if type(value) not in _POSTING_COLUMN_TYPES[column]:
            raise ValueError(
                f"posting column {column} has primitive type "
                f"{type(value).__name__}"
            )
    (
        key,
        board,
        job_id,
        url,
        posted_at,
        fetched_at,
        raw_text,
        raw_json_text,
        content_hash,
        fetch_status,
    ) = values
    staged_job_key = facts.job_key
    if key != staged_job_key or key != f"{board}:{job_id}":
        raise ValueError(
            "posting identity does not bind board, job_id, and the staged job key"
        )
    if fetch_status != "fetched":
        raise ValueError('posting fetch_status must be exactly "fetched"')
    parsed_raw_json: Any = None
    if raw_json_text is not None:
        parsed = strict_json_loads(raw_json_text)
        if parsed is not None and not isinstance(parsed, dict):
            raise ValueError(
                "stored raw_json TEXT must strict-parse to null or an object"
            )
        parsed_raw_json = parsed
    semantic = {
        "job_key": staged_job_key,
        "board": board,
        "job_id": job_id,
        "url": url,
        "posted_at": posted_at,
        "fetched_at": fetched_at,
        "raw_text": raw_text,
        "raw_json": parsed_raw_json,
        "fetch_status": fetch_status,
    }
    posting = validate_semantic_posting_shape(semantic)
    material = (raw_text or "") + (raw_json_text or "")
    computed_source = sha256_hex(material.encode("utf-8"))
    if not _LOWERCASE_SHA_RE.fullmatch(content_hash):
        raise ValueError(
            "stored content_hash must be a lowercase SHA-256 hex string"
        )
    if content_hash != computed_source:
        raise ValueError(
            "stored content_hash does not equal the recomputed legacy source hash"
        )
    if content_hash != facts.raw.source_content_sha256:
        raise ValueError(
            "stored content_hash does not equal the staged raw source binding"
        )
    canonical = canonical_json(posting).encode("utf-8")
    snapshot_sha256 = sha256_hex(canonical)
    if snapshot_sha256 != facts.raw.raw_snapshot_sha256:
        raise ValueError(
            "raw snapshot hash does not equal the staged raw_snapshot_sha256"
        )
    return RawSnapshotFacts(
        job_key=staged_job_key,
        board=board,
        job_id=job_id,
        url=url,
        posted_at=posted_at,
        fetched_at=fetched_at,
        fetch_status=fetch_status,
        raw_text=raw_text,
        raw_json_text=raw_json_text,
        source_content_sha256=computed_source,
        raw_snapshot_sha256=snapshot_sha256,
        semantic_canonical=canonical,
    )


def _raw_snapshot_proof(facts: RawSnapshotFacts) -> tuple[Any, ...]:
    return (
        facts.job_key,
        facts.board,
        facts.job_id,
        facts.url,
        facts.posted_at,
        facts.fetched_at,
        facts.fetch_status,
        facts.raw_text,
        facts.raw_json_text,
        facts.source_content_sha256,
        facts.raw_snapshot_sha256,
        facts.semantic_canonical,
    )


class _AdmissionLease:
    """Context-owned admission scope for one read-only run.

    The read view connection and every retained descriptor are owned here
    exactly once; they can neither escape the lease nor leak past its
    exit. Continuing stages receive this lease only.
    """

    def __init__(self, descriptors: _DescriptorSet) -> None:
        self.descriptors = descriptors
        self.assessments: _RetainedDatabaseLeaf | None = None
        self.vacancy: _RetainedDatabaseLeaf | None = None
        self.connection: sqlite3.Connection | None = None
        self.facts: EnvelopeFacts | None = None
        self.binding_sha256: str | None = None
        self.provisional_detail: str | None = None
        self.raw: RawSnapshotFacts | None = None
        self.sqlite_opened = False

    def bind(
        self,
        admission: dict[str, "_RetainedDatabaseLeaf"],
        facts: EnvelopeFacts,
        binding_sha256: str,
    ) -> None:
        self.assessments = admission["assessments"]
        self.vacancy = admission["vacancy"]
        self.facts = facts
        self.binding_sha256 = binding_sha256

    def open_view(self, *, allow_database_size_change: bool = False) -> None:
        assert self.assessments is not None and self.vacancy is not None
        self.connection = _open_read_view(
            self.descriptors,
            self.assessments,
            self.vacancy,
            allow_database_size_change=allow_database_size_change,
        )
        self.sqlite_opened = True

    def revalidate_chain(
        self, *, allow_database_size_change: bool = False
    ) -> None:
        if self.assessments is None or self.vacancy is None:
            raise RuntimeError("admission lease is not bound to databases")
        _assert_chain_intact(
            self.descriptors,
            self.assessments,
            self.vacancy,
            allow_sidecar_parent_nlink_churn=self.sqlite_opened,
            allow_database_size_change=allow_database_size_change,
        )

    def _proved_vacancy_select(
        self, *, allow_database_size_change: bool = False
    ) -> sqlite3.Row | None:
        assert self.connection is not None and self.facts is not None
        self.revalidate_chain(
            allow_database_size_change=allow_database_size_change
        )
        try:
            row = read_posting(
                self.connection, schema="vacancy", key=self.facts.job_key
            )
        except sqlite3.Error as exc:
            raise map_sqlite_read_error(exc) from exc
        self.revalidate_chain(
            allow_database_size_change=allow_database_size_change
        )
        return row

    def admit_raw_snapshot(self) -> RawSnapshotFacts:
        assert self.facts is not None
        row = self._proved_vacancy_select()
        try:
            admitted = _raw_snapshot_from_row(row, self.facts)
        except ValueError as exc:
            raise ProcessingRefused(
                REASON_RAW_SNAPSHOT, f"raw snapshot refused: {exc}"
            ) from exc
        _maybe_fault("after_raw_read")
        reread = self._proved_vacancy_select()
        if (
            reread is None
            or _posting_row_proof(reread) != _posting_row_proof(row)
        ):
            raise ProcessingRefused(
                REASON_RAW_SNAPSHOT,
                "current raw posting drifted between read and immediate reread",
            )
        try:
            confirmed = _raw_snapshot_from_row(reread, self.facts)
        except ValueError as exc:
            raise ProcessingRefused(
                REASON_RAW_SNAPSHOT, f"raw snapshot refused on reread: {exc}"
            ) from exc
        if _raw_snapshot_proof(confirmed) != _raw_snapshot_proof(admitted):
            raise ProcessingRefused(
                REASON_RAW_SNAPSHOT,
                "raw snapshot drifted between read and immediate reread",
            )
        self.raw = admitted
        return admitted

    def revalidate_raw(
        self, *, allow_database_size_change: bool = False
    ) -> None:
        """Repeat the exact chain-proved read and proof for later stages."""

        if self.raw is None or self.facts is None:
            raise RuntimeError("raw snapshot has not been admitted yet")
        row = self._proved_vacancy_select(
            allow_database_size_change=allow_database_size_change
        )
        try:
            current = _raw_snapshot_from_row(row, self.facts)
        except ValueError as exc:
            raise ProcessingRefused(
                REASON_RAW_SNAPSHOT,
                f"raw snapshot no longer validates: {exc}",
            ) from exc
        if _raw_snapshot_proof(current) != _raw_snapshot_proof(self.raw):
            raise ProcessingRefused(
                REASON_RAW_SNAPSHOT,
                "raw snapshot drifted from its admitted state",
            )

    def close(self) -> None:
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None
        for leaf in list(self.descriptors.db_leaves):
            leaf.close(self.descriptors)
        self.descriptors.close()

    def __enter__(self) -> "_AdmissionLease":
        return self

    def __exit__(self, *_exc_info: Any) -> bool:
        self.close()
        return False


def run_read_only_replay(
    data_home: Path,
    envelope_name: str,
    *,
    supplied_operation_id: str,
    supplied_config_path: str,
    supplied_profile_id: str,
    supplied_job_key: str,
    supplied_track: str,
) -> ReplayClassification:
    """Reasons 1-6 read-only common/replay path; writes nothing anywhere.

    An exact self-validating stored receipt returns its sealed bytes, a
    reason 6 mismatch refuses, and definitive absence or a retained
    provisional is returned unchanged. This entry point never reads the
    current raw posting; see :func:`open_current_raw_admission`.
    """

    common = None
    try:
        common = _reasons_one_to_six(
            data_home,
            envelope_name,
            supplied_operation_id=supplied_operation_id,
            supplied_config_path=supplied_config_path,
            supplied_profile_id=supplied_profile_id,
            supplied_job_key=supplied_job_key,
            supplied_track=supplied_track,
        )
        if (
            common.classification.disposition
            == DISPOSITION_EXISTING_RECEIPT_MISMATCH
        ):
            raise ProcessingRefused(
                REASON_EXISTING_RECEIPT, common.classification.detail
            )
        return common.classification
    finally:
        if common is not None:
            common.lease.close()


@dataclasses.dataclass
class _CommonReplay:
    """Everything reasons 1-6 proved plus the live admission lease."""

    lease: _AdmissionLease
    classification: ReplayClassification


def _validate_supplied_process_identity(
    *,
    envelope_name: str,
    supplied_operation_id: str,
    supplied_config_path: str,
    supplied_profile_id: str,
    supplied_job_key: str,
    supplied_track: str,
) -> None:
    """Apply stable reasons 1-3 without opening filesystem or SQLite state."""

    try:
        operation_id_value(supplied_operation_id)
    except ValueError as exc:
        raise ProcessingRefused(REASON_OPERATION_ID, str(exc)) from exc
    try:
        validate_envelope_name(envelope_name)
    except ValueError as exc:
        raise ProcessingRefused(REASON_ENVELOPE_PATH, str(exc)) from exc
    try:
        path_value(supplied_config_path, "supplied configuration path")
        _canonical_profile_id(supplied_profile_id, "supplied profile id")
        job_key_value(supplied_job_key)
        plain_string(supplied_track, "supplied track", 1, 128)
    except ValueError as exc:
        raise ProcessingRefused(
            REASON_CLI_IDENTITY, f"malformed supplied identity: {exc}"
        ) from exc


def _reasons_one_to_six(
    data_home: Path,
    envelope_name: str,
    *,
    supplied_operation_id: str,
    supplied_config_path: str,
    supplied_profile_id: str,
    supplied_job_key: str,
    supplied_track: str,
) -> _CommonReplay:
    """Shared private setup/classification run exactly once per call.

    Performs the staged refusal stages (reasons 1-5), opens the read view
    through the admission lease, classifies the stored receipt (reason 6
    evidence), and returns with every resource still open; lifecycle
    ownership belongs to the caller.
    """

    _validate_supplied_process_identity(
        envelope_name=envelope_name,
        supplied_operation_id=supplied_operation_id,
        supplied_config_path=supplied_config_path,
        supplied_profile_id=supplied_profile_id,
        supplied_job_key=supplied_job_key,
        supplied_track=supplied_track,
    )
    try:
        descriptors, payload, file_sha, _semantic = load_envelope_authority(
            data_home, envelope_name
        )
    except ProcessingRefused:
        raise
    except (ValueError, KeyError, TypeError) as exc:
        raise ProcessingRefused(
            REASON_ENVELOPE_BYTES, f"processing envelope refused: {exc}"
        ) from exc
    lease = _AdmissionLease(descriptors)
    try:
        try:
            facts = compose_envelope_facts(
                payload,
                envelope_file_sha256=file_sha,
                expected_assessments_path=None,
                expected_vacancy_path=None,
            )
        except ProcessingRefused:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise ProcessingRefused(
                REASON_ENVELOPE_BYTES, f"processing envelope refused: {exc}"
            ) from exc
        identity_pairs = (
            (supplied_operation_id, facts.operation_id, "operation id"),
            (supplied_config_path, facts.config_source_path, "configuration path"),
            (supplied_profile_id, facts.profile_id, "profile id"),
            (supplied_job_key, facts.job_key, "job key"),
            (supplied_track, facts.track, "track"),
        )
        for supplied, expected, label in identity_pairs:
            if supplied != expected:
                raise ProcessingRefused(
                    REASON_CLI_IDENTITY,
                    f"supplied CLI {label} does not equal the staged binding",
                )
        admission = admit_config_and_databases(data_home, facts, descriptors)
        _staged_binding, binding_sha = build_processing_binding_from_facts(facts)
        lease.bind(admission, facts, binding_sha)
        lease.revalidate_chain()
        assert lease.assessments is not None and lease.vacancy is not None
        recovery_journal_present = False
        for database in (lease.assessments, lease.vacancy):
            journal_name = database.name + "-journal"
            try:
                journal_info = os.stat(
                    journal_name,
                    dir_fd=database.parent.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"cannot classify pre-open {journal_name}: {exc}",
                ) from exc
            try:
                _require_private_leaf(
                    journal_info,
                    f"pre-open SQLite journal {journal_name}",
                )
            except ValueError as exc:
                raise ProcessingRefused(REASON_ATOMIC_MODE, str(exc)) from exc
            recovery_journal_present = True
        # Opening an exact pinned rollback-journal database may perform
        # SQLite's legitimate recovery from an abruptly terminated prior
        # invocation.  Identity, ownership, mode, and link count remain
        # immutable; only the byte size may change during that open.  Rebase
        # the retained sizes only after SQLite has opened both exact inodes,
        # then require a strictly clean journal/master-journal epoch before
        # replay classification or any later semantic admission.
        lease.open_view(allow_database_size_change=True)
        assert lease.connection is not None
        _verify_transaction_connection(
            lease.connection,
            descriptors,
            lease.assessments,
            lease.vacancy,
            allow_database_size_change=True,
        )
        if recovery_journal_present:
            lease.connection.execute("PRAGMA query_only=OFF")
            lease.connection.execute("PRAGMA foreign_keys=ON")
            lease.connection.execute("PRAGMA busy_timeout=30000")
            try:
                for alias in ("main", "vacancy"):
                    if lease.connection.execute(
                        f"PRAGMA {alias}.journal_mode=DELETE"
                    ).fetchall() != [("delete",)]:
                        raise ProcessingRefused(
                            REASON_RECOVERY_INCOHERENT,
                            f"{alias} startup recovery did not enter DELETE mode",
                        )
                    lease.connection.execute(f"PRAGMA {alias}.synchronous=FULL")
                lease.connection.execute("BEGIN IMMEDIATE")
                for alias in ("main", "vacancy"):
                    if lease.connection.execute(
                        f"PRAGMA {alias}.quick_check"
                    ).fetchall() != [("ok",)]:
                        raise ProcessingRefused(
                            REASON_RECOVERY_INCOHERENT,
                            f"{alias} startup recovery quick_check did not return ok",
                        )
                    if lease.connection.execute(
                        f"PRAGMA {alias}.foreign_key_check"
                    ).fetchall() != []:
                        raise ProcessingRefused(
                            REASON_RECOVERY_INCOHERENT,
                            f"{alias} startup recovery found foreign-key violations",
                        )
                lease.connection.rollback()
            except BaseException:
                if lease.connection.in_transaction:
                    with contextlib.suppress(sqlite3.Error):
                        lease.connection.rollback()
                raise
            lease.connection.execute("PRAGMA query_only=ON")
        lease.assessments.accept_recovered_size()
        lease.vacancy.accept_recovered_size()
        _verify_transaction_connection(
            lease.connection,
            descriptors,
            lease.assessments,
            lease.vacancy,
        )
        if recovery_journal_present:
            _require_clean_recovery_epoch(
                _stabilize_filesystem_epoch(
                    descriptors, lease.assessments, lease.vacancy
                )
            )
        classification = _classify_replay(
            lease.connection,
            facts,
            binding_sha,
            descriptors,
            lease.assessments,
            lease.vacancy,
            allow_sidecar_parent_nlink_churn=True,
        )
        lease.revalidate_chain()
    except BaseException:
        lease.close()
        raise
    return _CommonReplay(lease=lease, classification=classification)


@contextlib.contextmanager
def open_current_raw_admission(
    data_home: Path,
    envelope_name: str,
    *,
    supplied_operation_id: str,
    supplied_config_path: str,
    supplied_profile_id: str,
    supplied_job_key: str,
    supplied_track: str,
) -> Iterator[Any]:
    """Yield the reason 7 raw admission continuation of reasons 1-6.

    Runs the shared private reasons-1-6 helper once. An exact replay has
    already closed every common resource before yielding the sealed
    ``ReplayClassification`` and never invokes ``read_posting``; a reason
    6 mismatch closes and refuses without any raw read. Definitive absence
    or a retained provisional continues inside this context: the live
    :class:`_AdmissionLease` is yielded only after the raw snapshot is
    admitted, carrying immutable :class:`RawSnapshotFacts`, the retained
    prior provisional detail, and ``revalidate_raw()``; the connection and
    descriptors stay open until context exit and close exactly there.
    """

    common = _reasons_one_to_six(
        data_home,
        envelope_name,
        supplied_operation_id=supplied_operation_id,
        supplied_config_path=supplied_config_path,
        supplied_profile_id=supplied_profile_id,
        supplied_job_key=supplied_job_key,
        supplied_track=supplied_track,
    )
    try:
        classification = common.classification
        if classification.disposition == DISPOSITION_EXACT_REPLAY:
            common.lease.close()
            yield classification
            return
        if (
            classification.disposition
            == DISPOSITION_EXISTING_RECEIPT_MISMATCH
        ):
            common.lease.close()
            raise ProcessingRefused(REASON_EXISTING_RECEIPT, classification.detail)
        if (
            classification.disposition
            == DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY
        ):
            common.lease.provisional_detail = classification.detail
        raw_facts = common.lease.admit_raw_snapshot()
        assert raw_facts is not None and common.lease.raw is not None
        yield common.lease
    finally:
        common.lease.close()

# ==========================================================================
# Part 3B2: reasons 8-13 provider-free semantic admission continuation.
# ==========================================================================

def _profile_authority_refused(exc: BaseException) -> ProcessingRefused:
    return ProcessingRefused(
        REASON_PROFILE_EVIDENCE,
        f"profile/evidence/context authority refused: {exc}",
    )


def _verify_profile_authority(
    facts: EnvelopeFacts, snapshot: "CoherentProfileSnapshot"
) -> None:
    """Reason 8: exact profile/version/selected-track plus five hashes."""

    staged = dict(facts.profile_binding_shas)
    live = snapshot.hashes
    for key in sorted(staged):
        if staged[key] != live.get(key):
            raise ValueError(
                f"staged profile binding {key} differs from the admitted "
                "committed generation"
            )
    if snapshot.manifest is None or snapshot.manifest.get("state") != "committed":
        raise ValueError("a committed generation manifest is required")
    if facts.profile_version != snapshot.profile.version:
        raise ValueError(
            "staged profile_version differs from the admitted profile version"
        )
    if facts.track not in snapshot.profile.tracks:
        raise ValueError(
            f"selected track {facts.track!r} does not exist in the admitted profile"
        )


def _admit_extraction_stage(
    facts: EnvelopeFacts, raw_facts: RawSnapshotFacts
) -> dict[str, Any]:
    """Reason 9: extraction input binding, owner construction, acceptance."""

    parsed_raw_json: Any = None
    if raw_facts.raw_json_text is not None:
        parsed_raw_json = strict_json_loads(raw_facts.raw_json_text)
    input_node = {
        "schema_version": EXTRACTION_INPUT_SCHEMA_VERSION,
        "job_key": raw_facts.job_key,
        "board": raw_facts.board,
        "job_id": raw_facts.job_id,
        "url": raw_facts.url,
        "fetched_at": raw_facts.fetched_at,
        "source_content_sha256": raw_facts.source_content_sha256,
        "raw_snapshot_sha256": raw_facts.raw_snapshot_sha256,
        "raw_text": raw_facts.raw_text,
        "raw_json": parsed_raw_json,
    }
    input_sha256 = canonical_hash(input_node)
    receipt = facts.extraction.receipt
    try:
        if input_sha256 != receipt.input_sha256:
            raise ValueError(
                "extraction input hash differs from the admitted raw snapshot"
            )
        output = _extraction_from_structural(facts.extraction.output_structural)
        if output.source_content_sha256 != raw_facts.source_content_sha256:
            raise ValueError(
                "extraction.source_content_sha256 must bind the admitted raw source"
            )
        posting = RawPosting(
            board=raw_facts.board,
            job_id=raw_facts.job_id,
            url=raw_facts.url,
            fetched_at=raw_facts.fetched_at,
            raw_text=raw_facts.raw_text,
            raw_json=parsed_raw_json,
            content_sha256=raw_facts.source_content_sha256,
        )
        vacancy = accept_extraction(posting, output, receipt)
    except (ValueError, KeyError, TypeError) as exc:
        raise ProcessingRefused(
            REASON_EXTRACTION, f"semantic extraction refused: {exc}"
        ) from exc
    normalized_vacancy_bytes = json.dumps(
        asdict(vacancy),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return {
        "vacancy": vacancy,
        "extraction_input_sha256": input_sha256,
        "extraction_output_sha256": receipt.output_sha256,
        "extraction_receipt_provenance": (
            receipt.receipt_id,
            receipt.model,
            receipt.prompt_version,
            receipt.created_at,
        ),
        "normalized_vacancy_bytes": normalized_vacancy_bytes,
        "normalized_json_sha256": hashlib.sha256(normalized_vacancy_bytes).hexdigest(),
    }


def _admit_alignment_stage(
    facts: EnvelopeFacts,
    snapshot: "CoherentProfileSnapshot",
    vacancy: Any,
) -> dict[str, Any]:
    """Reason 10: alignment input binding and selected-track acceptance."""

    track_profile = snapshot.profile.tracks[facts.track]
    selected_evidence = {
        evidence_id: snapshot.evidence[evidence_id]
        for evidence_id in track_profile.evidence_ids
    }
    input_node = {
        "schema_version": ALIGNMENT_INPUT_SCHEMA_VERSION,
        "job_key": facts.job_key,
        "profile_id": facts.profile_id,
        "profile_version": facts.profile_version,
        "track": facts.track,
        "vacancy": asdict(vacancy),
        "profile_context": snapshot.context,
        "profile_context_sha256": snapshot.hashes["profile_context_sha256"],
    }
    input_sha256 = canonical_hash(input_node)
    receipt = facts.alignment.receipt
    try:
        if input_sha256 != receipt.input_sha256:
            raise ValueError(
                "alignment input hash differs from the admitted profile context"
            )
        alignment = _alignment_from_structural(facts.alignment.output_structural)
        if alignment.profile_id != facts.profile_id:
            raise ValueError(
                "alignment.profile_id must equal the envelope profile_id"
            )
        if alignment.profile_version != facts.profile_version:
            raise ValueError(
                "alignment.profile_version must equal the envelope version"
            )
        if alignment.job_key != facts.job_key:
            raise ValueError("alignment.job_key must equal the envelope job_key")
        accepted = accept_alignment(alignment, selected_evidence, receipt)
    except (ValueError, KeyError, TypeError) as exc:
        raise ProcessingRefused(
            REASON_ALIGNMENT, f"semantic alignment refused: {exc}"
        ) from exc
    return {
        "accepted_alignment": accepted,
        "alignment_input_sha256": input_sha256,
        "alignment_output_sha256": receipt.output_sha256,
        "alignment_receipt_provenance": (
            receipt.receipt_id,
            receipt.model,
            receipt.prompt_version,
            receipt.created_at,
        ),
    }


def _admit_parameter_stage(facts: EnvelopeFacts) -> None:
    """Reason 11: BOTH staged hashes bind the sole live ScoringParams."""

    live = ScoringParams().parameters_hash
    if facts.scoring_parameters_sha256 != live:
        raise ProcessingRefused(
            REASON_SCORING_PARAMS,
            "scoring.parameters_sha256 differs from the sole ScoringParams object",
        )
    if facts.expected_score.parameters_hash != live:
        raise ProcessingRefused(
            REASON_SCORING_PARAMS,
            "expected_score.parameters_hash differs from the sole ScoringParams object",
        )


def _admit_policy_stage(facts: EnvelopeFacts) -> None:
    """Reason 12: the fixed unknown-opportunity policy body/hash."""

    if facts.scoring_opportunity_policy_sha256 != OPPORTUNITY_POLICY_SHA256:
        raise ProcessingRefused(
            REASON_OPPORTUNITY_POLICY,
            "opportunity policy differs from the fixed contracted policy",
        )


def _type_exact_number_equal(staged: Any, recomputed: Any) -> bool:
    """Numeric identity that keeps int and float distinct (0 != 0.0)."""

    if isinstance(staged, bool) or isinstance(recomputed, bool):
        return type(staged) is type(recomputed) and staged == recomputed
    if isinstance(staged, (int, float)) and isinstance(recomputed, (int, float)):
        return type(staged) is type(recomputed) and staged == recomputed
    return staged == recomputed


def _admit_score_stage(
    facts: EnvelopeFacts, profile: Any, accepted_alignment: Any
) -> dict[str, Any]:
    """Reason 13: fixed axes plus exact typed/byte ScoreResult identity."""

    axes = AssessmentAxes(
        technical_alignment=accepted_alignment.technical_alignment * 10,
        evidence_match=accepted_alignment.evidence_match * 10,
        market_demand=0,
        barrier_to_entry=10,
        growth_potential=0,
    )
    recomputed = deterministic_score(
        profile, facts.job_key, facts.track, axes, ScoringParams()
    )
    try:
        staged = strict_json_loads(facts.expected_score_canonical.decode("utf-8"))
        recomputed_node = asdict(recomputed)
        identities = (
            ("profile_id", facts.profile_id),
            ("job_key", facts.job_key),
            ("track", facts.track),
            ("parameters_hash", facts.scoring_parameters_sha256),
            (
                "fit_status",
                FitStatus.UNCALIBRATED.value,
            ),
        )
        for field, expected in identities:
            if staged[field] != expected:
                raise ValueError(
                    f"expected score {field} differs from the exact admission"
                )
        for field in ("fit", "opportunity", "final"):
            if not _type_exact_number_equal(staged[field], recomputed_node[field]):
                raise ValueError(
                    f"expected score {field} value or primitive type differs"
                )
        for subscores_key in ("fit_subscores", "opportunity_subscores"):
            staged_subscores = staged[subscores_key]
            recomputed_subscores = recomputed_node[subscores_key]
            if set(staged_subscores) != set(recomputed_subscores):
                raise ValueError(
                    f"expected score {subscores_key} keys differ from the "
                    "exact admission"
                )
            for key in sorted(recomputed_subscores):
                if not _type_exact_number_equal(
                    staged_subscores[key], recomputed_subscores[key]
                ):
                    raise ValueError(
                        f"expected score {subscores_key}.{key} value or "
                        "primitive type differs"
                    )
    except ProcessingRefused:
        raise
    except (ValueError, KeyError, TypeError) as exc:
        raise ProcessingRefused(
            REASON_SCORE_RESULT,
            f"staged expected score differs from the exact admission: {exc}",
        ) from exc
    recomputed_bytes = canonical_json(asdict(recomputed)).encode("utf-8")
    if recomputed_bytes != facts.expected_score_canonical:
        raise ProcessingRefused(
            REASON_SCORE_RESULT,
            "staged expected score bytes differ from the exact recomputed "
            "ScoreResult",
        )
    return {
        "score_result_bytes": recomputed_bytes,
        "score_result_sha256": hashlib.sha256(recomputed_bytes).hexdigest(),
        "parameters_sha256": facts.scoring_parameters_sha256,
        "opportunity_policy_sha256": facts.scoring_opportunity_policy_sha256,
    }


class SemanticAdmissionView:
    """Immutable public surface of reasons 7-13 for later stages.

    Exposes only primitives, bytes, tuples, frozen raw facts, provenance
    quadruples, and :meth:`revalidate_all`. The profile snapshot and the
    admission lease are held privately until context exit and are never
    exposed; no Vacancy/ScoreResult/profile/evidence dict escapes.
    """

    __slots__ = (
        "_lease",
        "_snapshot",
        "_sealed",
        "raw",
        "provisional_detail",
        "profile_binding_shas",
        "extraction_input_sha256",
        "extraction_output_sha256",
        "extraction_receipt_provenance",
        "alignment_input_sha256",
        "alignment_output_sha256",
        "alignment_receipt_provenance",
        "normalized_vacancy_bytes",
        "normalized_json_sha256",
        "parameters_sha256",
        "opportunity_policy_sha256",
        "score_result_bytes",
        "score_result_sha256",
    )

    def __init__(
        self,
        lease: _AdmissionLease,
        snapshot: Any,
        *,
        raw: RawSnapshotFacts,
        provisional_detail: str | None,
        profile_binding_shas: tuple[tuple[str, str], ...],
        **public: Any,
    ) -> None:
        for name, value in (
            ("raw", raw),
            ("provisional_detail", provisional_detail),
            ("profile_binding_shas", profile_binding_shas),
        ):
            object.__setattr__(self, name, value)
        for name, value in public.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_lease", lease)
        object.__setattr__(self, "_snapshot", snapshot)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("semantic admission view is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("semantic admission view is immutable")

    def __getattribute__(self, name: str) -> Any:
        if name in ("_lease", "_snapshot", "_sealed", "_release"):
            raise AttributeError(
                f"semantic admission view hides {name!r} from normal access"
            )
        return object.__getattribute__(self, name)

    def revalidate_all(self) -> None:
        """Combined later revalidation: raw first, then profile authority."""

        lease = object.__getattribute__(self, "_lease")
        snapshot = object.__getattribute__(self, "_snapshot")
        assert lease is not None and snapshot is not None
        lease.revalidate_raw()
        try:
            snapshot.revalidate()
        except ProcessingRefused:
            raise
        except (ValueError, OSError) as exc:
            raise _profile_authority_refused(exc) from exc

    def _release(self) -> None:
        try:
            snapshot = object.__getattribute__(self, "_snapshot")
        except AttributeError:
            return
        if snapshot is not None:
            snapshot.close()
            object.__setattr__(self, "_snapshot", None)


def _admit_semantic_continuation(
    data_home: Path, lease: _AdmissionLease
) -> SemanticAdmissionView:
    """Run reasons 8-13 over an admitted raw lease; snapshot held privately."""

    facts = lease.facts
    assert facts is not None and lease.raw is not None
    # Raw first, before anything else on the semantic path.
    lease.revalidate_raw()
    snapshot = None
    try:
        try:
            store = ProfileStore.open_existing(Path(data_home))
            snapshot = store.coherent_snapshot(
                facts.profile_id, require_committed_generation=True
            )
        except (ValueError, KeyError, TypeError, OSError) as exc:
            raise _profile_authority_refused(exc) from exc
        try:
            _verify_profile_authority(facts, snapshot)
        except ProcessingRefused:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise _profile_authority_refused(exc) from exc

        def checkpoint() -> None:
            lease.revalidate_raw()
            try:
                snapshot.revalidate()
            except (ValueError, OSError) as exc:
                raise _profile_authority_refused(exc) from exc

        checkpoint()
        admitted = _admit_extraction_stage(facts, lease.raw)
        vacancy = admitted.pop("vacancy")
        admitted.update(_admit_alignment_stage(facts, snapshot, vacancy))
        accepted_alignment = admitted.pop("accepted_alignment")
        _admit_parameter_stage(facts)
        _admit_policy_stage(facts)
        admitted.update(_admit_score_stage(facts, snapshot.profile, accepted_alignment))
        checkpoint()
        return SemanticAdmissionView(
            lease,
            snapshot,
            raw=lease.raw,
            provisional_detail=lease.provisional_detail,
            profile_binding_shas=facts.profile_binding_shas,
            **admitted,
        )
    except BaseException:
        if snapshot is not None:
            snapshot.close()
        raise


@contextlib.contextmanager
def continue_current_semantic_admission(
    data_home: Path,
    envelope_name: str,
    *,
    supplied_operation_id: str,
    supplied_config_path: str,
    supplied_profile_id: str,
    supplied_job_key: str,
    supplied_track: str,
) -> Iterator[Any]:
    """Provider-free reasons 8-13 continuation of the raw admission context.

    Exact replays yield the sealed ``ReplayClassification`` unchanged and a
    reason 6 mismatch refuses exactly as in :func:`open_current_raw_admission`;
    in both terminal cases the profile store, both accept functions, and the
    scoring engine run zero times. Only definitive absence or a retained
    provisional continues into reason 8 and onward, yielding an immutable
    :class:`SemanticAdmissionView` whose snapshot is released exactly at
    context exit.
    """

    with open_current_raw_admission(
        data_home,
        envelope_name,
        supplied_operation_id=supplied_operation_id,
        supplied_config_path=supplied_config_path,
        supplied_profile_id=supplied_profile_id,
        supplied_job_key=supplied_job_key,
        supplied_track=supplied_track,
    ) as continuation:
        if isinstance(continuation, ReplayClassification):
            yield continuation
            return
        view = _admit_semantic_continuation(data_home, continuation)
        try:
            yield view
        finally:
            object.__getattribute__(view, "_release")()


# ==========================================================================
# Part-3C C2-A R1A: pure rollback-journal grammar primitives.
# ==========================================================================

_JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"


@dataclasses.dataclass(frozen=True)
class _RollbackHeader:
    candidate: bool
    n_rec: int | None
    checksum_init: int | None
    initial_db_size: int | None
    sector_size: int | None
    page_size: int | None


def _parse_rollback_header(header: bytes, *, file_size: int) -> _RollbackHeader:
    """Pure parser for one 28-byte SQLite rollback journal header.

    All integers are big-endian. Exact offsets:
      magic[0:8], nRec[8:12], checksum_init[12:16],
      initial_db_size[16:20], sector_size[20:24], page_size[24:28].

    Candidate only when file_size > 512, len(header)==28, exact magic,
    and sector_size/page_size are each a power of two in [512, 65536].
    """
    if isinstance(file_size, bool) or not isinstance(file_size, int) \
            or not 0 <= file_size <= 2**63 - 1:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"file_size must be an integer in [0, 2^63), got {type(file_size).__name__}",
        )
    if not isinstance(header, bytes):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"header must be bytes, got {type(header).__name__}",
        )
    if file_size <= 512 or len(header) != 28 or header[:8] != _JOURNAL_MAGIC:
        return _RollbackHeader(False, None, None, None, None, None)
    n_rec = int.from_bytes(header[8:12], "big")
    checksum_init = int.from_bytes(header[12:16], "big")
    initial_db_size = int.from_bytes(header[16:20], "big")
    sector_size = int.from_bytes(header[20:24], "big")
    page_size = int.from_bytes(header[24:28], "big")

    def pow2(v):
        return 512 <= v <= 65536 and v > 0 and v & (v - 1) == 0

    if not pow2(sector_size) or not pow2(page_size):
        return _RollbackHeader(False, None, None, None, None, None)
    return _RollbackHeader(
        True, n_rec, checksum_init,
        initial_db_size, sector_size, page_size)




def _sqlite_master_checksum(path_bytes: Any) -> int:
    """Signed-int8 sum of each byte, modulo 2^32."""
    if not isinstance(path_bytes, bytes):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"path_bytes must be bytes, got {type(path_bytes).__name__}",
        )
    total = 0
    for b in path_bytes:
        total += b if b < 128 else b - 256
    return total % (2 ** 32)


@dataclasses.dataclass(frozen=True)
class _PointerTail:
    kind: str  # exactly "none" or "valid"
    pathname_bytes: bytes | None

    def __post_init__(self) -> None:
        if self.kind not in ("none", "valid"):
            raise ValueError(f"kind must be 'none' or 'valid', got {self.kind!r}")
        if self.kind == "none" and self.pathname_bytes is not None:
            raise ValueError("pathname_bytes must be None when kind is none")
        if self.kind == "valid":
            if not isinstance(self.pathname_bytes, bytes) or len(self.pathname_bytes) == 0:
                raise ValueError(
                    "pathname_bytes must be nonempty bytes when kind is valid"
                )


def _parse_master_pointer(
    *,
    journal_size: int,
    page_size: int,
    path_max: int,
    tail16: bytes,
    special_and_path: bytes | None,
) -> _PointerTail:
    """Pure parser for the master-journal pointer at a journal tail.

    ``tail16`` is the final 16 bytes:
      [pathname_length BE32][checksum BE32][magic8].
    ``special_and_path`` is the exact ``[PAGER_SJ_PGNO4][pathname n]``
    supplied by the caller from a bounded pread (4+n bytes).

    Absent magic / zero length / length > path_max /
    journal_size < 20+n / checksum mismatch -> kind "none".
    Wrong PAGER_SJ_PGNO -> reason15. Valid -> pathname bytes.
    """
    read_length = _master_pointer_read_length(
        journal_size=journal_size,
        page_size=page_size,
        path_max=path_max,
        tail16=tail16,
    )
    none = _PointerTail("none", None)
    if read_length is None:
        return none
    stored_checksum = int.from_bytes(tail16[4:8], "big")
    if special_and_path is None:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "special_and_path is required for plausible pointer suffix",
        )
    if not isinstance(special_and_path, bytes):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"special_and_path must be bytes, got {type(special_and_path).__name__}",
        )
    if len(special_and_path) != read_length:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"special_and_path must be exactly {read_length} bytes, "
            f"got {len(special_and_path)}",
        )
    computed_checksum = _sqlite_master_checksum(
        special_and_path[4:]
    )
    if computed_checksum != stored_checksum:
        return none
    sj_pgno = int.from_bytes(special_and_path[:4], "big")
    expected_sj = (0x40000000 // page_size) + 1
    if sj_pgno != expected_sj:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"PAGER_SJ_PGNO mismatch: expected {expected_sj}, "
            f"got {sj_pgno}",
        )
    pathname = special_and_path[4:]
    if b"\x00" in pathname:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "checksum-valid pathname contains NUL byte",
        )
    return _PointerTail("valid", pathname)


def _master_pointer_read_length(
    *,
    journal_size: int,
    page_size: int,
    path_max: int,
    tail16: bytes,
) -> int | None:
    """Return the one bounded pointer read length, or no-read eligibility.

    This is the shared eligibility owner used by both the pure parser and
    retained filesystem observation. It deliberately cannot authenticate a
    checksum or PAGER_SJ_PGNO until the returned ``4 + pathname_len`` bytes
    have been read.
    """

    if not isinstance(page_size, int) or isinstance(page_size, bool):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"page_size must be an integer without bool, got {type(page_size).__name__}",
        )
    if page_size <= 0 or page_size > 2**31 - 1 \
            or page_size & (page_size - 1) != 0 \
            or not 512 <= page_size <= 65536:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE, f"invalid page_size {page_size}"
        )
    if not isinstance(tail16, bytes) or len(tail16) != 16:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"tail16 must be exactly 16 bytes of type bytes, "
            f"got {type(tail16).__name__} len={len(tail16) if hasattr(tail16, '__len__') else '?'}",
        )
    if isinstance(journal_size, bool) or not isinstance(journal_size, int) \
            or not 0 <= journal_size <= 2**63 - 1:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"journal_size must be an integer in [0, 2^63), "
            f"got {type(journal_size).__name__}",
        )
    if isinstance(path_max, bool) or not isinstance(path_max, int) \
            or not 1 <= path_max <= 2**31 - 1:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"path_max must be an integer in [1, 2^31), "
            f"got {type(path_max).__name__}",
        )
    if journal_size <= 512:
        return None
    pathname_len = int.from_bytes(tail16[0:4], "big")
    magic8 = tail16[8:16]
    if magic8 != _JOURNAL_MAGIC or pathname_len == 0:
        return None
    if pathname_len > path_max:
        return None
    record_size = 20 + pathname_len
    if journal_size < record_size:
        return None
    return 4 + pathname_len


# --------------------------------------------------------------------------
# Pair-local recognized SQLite sidecar ownership (C2-A phase 1).
# --------------------------------------------------------------------------

_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")
_SIDECAR_FD_SLOTS = ("_fd0", "_fd1", "_fd2", "_fd3", "_fd4", "_fd5")
_SIDECAR_DATABASES = ("assessments", "vacancy")
_MAX_PRIVATE_PATH_MAX = 1_048_576


class _SidecarChurn(Exception):
    """A safe private SQLite sidecar epoch changed and must be resampled."""


@dataclasses.dataclass(frozen=True)
class _SidecarObservation:
    database: str
    name: str
    suffix: str
    present: bool
    identity: tuple[int, int, int, int, int] | None
    size: int | None


@dataclasses.dataclass(frozen=True)
class _JournalObservation:
    """FD-free bounded facts for one exact retained rollback journal."""

    database: str
    state: str  # exactly absent, noncandidate, or candidate
    size: int | None
    prefix: bytes
    header: _RollbackHeader | None
    tail16: bytes | None
    pointer: _PointerTail | None
    pointer_path: str | None


def _authorize_master_pointer_path(
    pathname_bytes: bytes,
    main_database_leaf: _RetainedDatabaseLeaf,
) -> str:
    """Validate a pointer against the retained main DB parent only."""

    pathname = _decode_canonical_absolute_path(
        pathname_bytes, "master-journal pointer pathname"
    )
    candidate = Path(pathname)
    expected_parent = str(Path(main_database_leaf.path).parent)
    if str(candidate.parent) != expected_parent or not candidate.name:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "master-journal pointer is not a direct child of the retained "
            "main database parent",
        )
    return pathname


def _decode_canonical_absolute_path(pathname_bytes: bytes, label: str) -> str:
    """Strict UTF-8, round-trip-safe, canonical absolute lexical path."""

    if not isinstance(pathname_bytes, bytes) or not pathname_bytes:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"{label} must be nonempty bytes",
        )
    if b"\x00" in pathname_bytes:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"{label} contains NUL",
        )
    try:
        pathname = pathname_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"{label} is not strict UTF-8",
        ) from exc
    if pathname.encode("utf-8", "strict") != pathname_bytes:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"{label} does not round-trip",
        )
    components = pathname.split("/")
    if (
        not pathname.startswith("/")
        or len(components) < 2
        or components[0] != ""
        or any(component in ("", ".", "..") for component in components[1:])
    ):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"{label} is not canonical absolute spelling",
        )
    candidate = Path(pathname)
    if (
        not candidate.is_absolute()
        or os.path.normpath(pathname) != pathname
        or str(candidate) != pathname
    ):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"{label} carries a lexical alias",
        )
    return pathname


def _require_private_sidecar(
    info: os.stat_result,
    label: str,
    *,
    allow_unlinked: bool = False,
) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE, f"{label} is not a regular file"
        )
    if info.st_uid != os.getuid():
        raise ProcessingRefused(
            REASON_ATOMIC_MODE, f"{label} is not owned by the current UID"
        )
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE, f"{label} is not mode exactly 0600"
        )
    allowed_links = (0, 1) if allow_unlinked else (1,)
    if info.st_nlink not in allowed_links:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE, f"{label} does not have exactly one link"
        )


def _sidecar_path_max(parent_fd: int, label: str) -> int:
    try:
        value = os.fpathconf(parent_fd, "PC_PATH_MAX")
    except (OSError, ValueError) as exc:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"{label} parent PC_PATH_MAX is unavailable: {exc}",
        ) from exc
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > _MAX_PRIVATE_PATH_MAX
    ):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"{label} parent PC_PATH_MAX is outside 1..{_MAX_PRIVATE_PATH_MAX}",
        )
    return value


def _sidecar_open_flags() -> int:
    nonblock = getattr(os, "O_NONBLOCK", None)
    if (
        isinstance(nonblock, bool)
        or not isinstance(nonblock, int)
        or nonblock <= 0
    ):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "recognized SQLite sidecars require O_NONBLOCK",
        )
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | nonblock


class _SidecarPairCapture:
    """Own one exact observation of the six recognized SQLite sidecars."""

    __slots__ = (
        "_records",
        "_path_maxima",
        "_descriptors",
        "_assessments",
        "_vacancy",
        "_closed",
        "_terminal_refusal",
        "_fd0",
        "_fd1",
        "_fd2",
        "_fd3",
        "_fd4",
        "_fd5",
    )

    def __init__(
        self,
        descriptors: _DescriptorSet,
        assessments: _RetainedDatabaseLeaf,
        vacancy: _RetainedDatabaseLeaf,
    ) -> None:
        self._records: tuple[_SidecarObservation, ...] = ()
        self._path_maxima: tuple[int, int] = ()
        self._descriptors = descriptors
        self._assessments = assessments
        self._vacancy = vacancy
        self._closed = False
        self._terminal_refusal: ProcessingRefused | None = None
        self._fd0 = -1
        self._fd1 = -1
        self._fd2 = -1
        self._fd3 = -1
        self._fd4 = -1
        self._fd5 = -1
        try:
            _assert_chain_intact(
                descriptors,
                assessments,
                vacancy,
                allow_sidecar_parent_nlink_churn=True,
            )
            self._path_maxima = (
                _sidecar_path_max(assessments.parent.fd, "assessments"),
                _sidecar_path_max(vacancy.parent.fd, "vacancy"),
            )
            records: tuple[_SidecarObservation, ...] = ()
            index = 0
            for database, leaf in (
                ("assessments", assessments),
                ("vacancy", vacancy),
            ):
                for suffix in _SIDECAR_SUFFIXES:
                    name = leaf.name + suffix
                    try:
                        before = os.stat(
                            name,
                            dir_fd=leaf.parent.fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        records += (
                            _SidecarObservation(
                                database=database,
                                name=name,
                                suffix=suffix,
                                present=False,
                                identity=None,
                                size=None,
                            ),
                        )
                        index += 1
                        continue

                    _require_private_sidecar(
                        before, f"{database} {name} pre-open"
                    )
                    try:
                        raw = os.open(
                            name,
                            _sidecar_open_flags(),
                            dir_fd=leaf.parent.fd,
                        )
                    except FileNotFoundError as exc:
                        raise _SidecarChurn(
                            f"{database} {name} disappeared before open"
                        ) from exc
                    # The fixed slot becomes the sole owner before any
                    # fallible validation of the newly opened descriptor.
                    setattr(self, _SIDECAR_FD_SLOTS[index], raw)
                    opened = os.fstat(raw)
                    try:
                        after = os.stat(
                            name,
                            dir_fd=leaf.parent.fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError as exc:
                        raise _SidecarChurn(
                            f"{database} {name} disappeared after open"
                        ) from exc
                    for phase, info in (
                        ("pre-open", before),
                        ("opened", opened),
                        ("final name entry", after),
                    ):
                        _require_private_sidecar(
                            info, f"{database} {name} {phase}"
                        )
                    expected = (_identity(before), before.st_size)
                    if (_identity(opened), opened.st_size) != expected:
                        raise _SidecarChurn(
                            f"{database} {name} changed between lstat and open"
                        )
                    if (_identity(after), after.st_size) != expected:
                        raise _SidecarChurn(
                            f"{database} {name} name entry changed after open"
                        )
                    records += (
                        _SidecarObservation(
                            database=database,
                            name=name,
                            suffix=suffix,
                            present=True,
                            identity=expected[0],
                            size=expected[1],
                        ),
                    )
                    index += 1
            _assert_chain_intact(
                descriptors,
                assessments,
                vacancy,
                allow_sidecar_parent_nlink_churn=True,
            )
            self._records = records
        except BaseException as exc:
            try:
                self.close()
            except ProcessingRefused as cleanup_exc:
                raise cleanup_exc from exc
            if isinstance(exc, ProcessingRefused):
                raise
            if isinstance(exc, (OSError, ValueError)):
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"recognized SQLite sidecar authority refused: {exc}",
                ) from exc
            raise

    @property
    def records(self) -> tuple[_SidecarObservation, ...]:
        return self._records

    @property
    def path_maxima(self) -> tuple[int, int]:
        return self._path_maxima

    def _record_index(self, database: str, suffix: str) -> int:
        if database not in _SIDECAR_DATABASES or suffix not in _SIDECAR_SUFFIXES:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                "bounded sidecar read requested an unknown database or suffix",
            )
        return (
            _SIDECAR_DATABASES.index(database) * len(_SIDECAR_SUFFIXES)
            + _SIDECAR_SUFFIXES.index(suffix)
        )

    def revalidate(self) -> None:
        if self._terminal_refusal is not None:
            raise self._terminal_refusal
        if self._closed:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE, "sidecar capture is already closed"
            )
        _assert_chain_intact(
            self._descriptors,
            self._assessments,
            self._vacancy,
            allow_sidecar_parent_nlink_churn=True,
        )
        try:
            for index, record in enumerate(self._records):
                leaf = (
                    self._assessments
                    if record.database == "assessments"
                    else self._vacancy
                )
                try:
                    entry = os.stat(
                        record.name,
                        dir_fd=leaf.parent.fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    if record.present:
                        raise _SidecarChurn(
                            f"{record.database} {record.name} disappeared"
                        )
                    continue
                except OSError as exc:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"{record.database} {record.name} is unstatable: {exc}",
                    ) from exc
                _require_private_sidecar(
                    entry, f"{record.database} {record.name} name entry"
                )
                if not record.present:
                    raise _SidecarChurn(
                        f"{record.database} {record.name} appeared"
                    )
                fd = getattr(self, _SIDECAR_FD_SLOTS[index])
                if fd < 0:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"{record.database} {record.name} lost its retained fd",
                    )
                try:
                    opened = os.fstat(fd)
                except OSError as exc:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"{record.database} {record.name} retained fd "
                        f"is unstatable: {exc}",
                    ) from exc
                _require_private_sidecar(
                    opened,
                    f"{record.database} {record.name} retained fd",
                    allow_unlinked=True,
                )
                expected = (record.identity, record.size)
                if (_identity(opened), opened.st_size) != expected:
                    raise _SidecarChurn(
                        f"{record.database} {record.name} retained file changed"
                    )
                if (_identity(entry), entry.st_size) != expected:
                    raise _SidecarChurn(
                        f"{record.database} {record.name} name entry changed"
                    )
        finally:
            _assert_chain_intact(
                self._descriptors,
                self._assessments,
                self._vacancy,
                allow_sidecar_parent_nlink_churn=True,
            )

    def observe_journals(self) -> tuple[_JournalObservation, ...]:
        """Return bounded FD-free facts for the two retained journals.

        This phase deliberately stops before opening a pointer-named master,
        pairing master contents, epoch stabilization, or deciding hot/cold
        recovery disposition.
        """

        self.revalidate()
        try:
            for record in self._records:
                if record.suffix in ("-wal", "-shm") and record.present:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"{record.database} {record.suffix} is present during "
                        "rollback-journal observation",
                    )

            observations: tuple[_JournalObservation, ...] = ()
            for database in _SIDECAR_DATABASES:
                record = self._records[
                    self._record_index(database, "-journal")
                ]
                if not record.present:
                    observations += (
                        _JournalObservation(
                            database=database,
                            state="absent",
                            size=None,
                            prefix=b"",
                            header=None,
                            tail16=None,
                            pointer=None,
                            pointer_path=None,
                        ),
                    )
                    continue

                assert record.size is not None
                prefix = self._pread_journal_prefix(database)
                header = _parse_rollback_header(
                    prefix, file_size=record.size
                )
                if not header.candidate:
                    observations += (
                        _JournalObservation(
                            database=database,
                            state="noncandidate",
                            size=record.size,
                            prefix=prefix,
                            header=header,
                            tail16=None,
                            pointer=None,
                            pointer_path=None,
                        ),
                    )
                    continue

                assert header.page_size is not None
                tail16 = self._pread_exact(
                    database,
                    "-journal",
                    purpose="tail",
                    offset=record.size - 16,
                    length=16,
                )
                path_max = self._path_maxima[
                    _SIDECAR_DATABASES.index(database)
                ]
                read_length = _master_pointer_read_length(
                    journal_size=record.size,
                    page_size=header.page_size,
                    path_max=path_max,
                    tail16=tail16,
                )
                special_and_path = None
                if read_length is not None:
                    special_and_path = self._pread_exact(
                        database,
                        "-journal",
                        purpose="pointer",
                        offset=record.size - 16 - read_length,
                        length=read_length,
                    )
                pointer = _parse_master_pointer(
                    journal_size=record.size,
                    page_size=header.page_size,
                    path_max=path_max,
                    tail16=tail16,
                    special_and_path=special_and_path,
                )
                pointer_path = None
                if pointer.kind == "valid":
                    assert pointer.pathname_bytes is not None
                    pointer_path = _authorize_master_pointer_path(
                        pointer.pathname_bytes, self._assessments
                    )
                observations += (
                    _JournalObservation(
                        database=database,
                        state="candidate",
                        size=record.size,
                        prefix=prefix,
                        header=header,
                        tail16=tail16,
                        pointer=pointer,
                        pointer_path=pointer_path,
                    ),
                )
            return observations
        finally:
            self.revalidate()

    def _pread_journal_prefix(self, database: str) -> bytes:
        """Read at most the fixed 28-byte header prefix from one journal."""

        index = self._record_index(database, "-journal")
        record = self._records[index]
        if not record.present or record.size is None:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                "journal prefix read requires a retained present journal",
            )
        self.revalidate()
        fd = getattr(self, _SIDECAR_FD_SLOTS[index])
        length = min(record.size, 28)
        chunks = bytearray()
        try:
            while len(chunks) < length:
                remaining = length - len(chunks)
                try:
                    chunk = os.pread(fd, remaining, len(chunks))
                except OSError as exc:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"bounded journal prefix read failed: {exc}",
                    ) from exc
                if not isinstance(chunk, bytes):
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        "bounded journal prefix read returned non-bytes",
                    )
                if not chunk:
                    raise _SidecarChurn(
                        "bounded journal prefix read ended early"
                    )
                if len(chunk) > remaining:
                    raise _SidecarChurn(
                        "bounded journal prefix read exceeded its request"
                    )
                chunks.extend(chunk)
            if record.size <= 28:
                try:
                    extra = os.pread(fd, 1, length)
                except OSError as exc:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"bounded journal prefix EOF proof failed: {exc}",
                    ) from exc
                if extra != b"":
                    raise _SidecarChurn(
                        "bounded journal prefix has extra bytes"
                    )
        finally:
            self.revalidate()
        return bytes(chunks)

    def _pread_exact(
        self,
        database: str,
        suffix: str,
        *,
        purpose: str,
        offset: int,
        length: int,
    ) -> bytes:
        index = self._record_index(database, suffix)
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or isinstance(length, bool)
            or not isinstance(length, int)
            or offset < 0
            or length <= 0
        ):
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                "bounded sidecar read offset/length is invalid",
            )
        record = self._records[index]
        if not record.present or record.size is None:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                "bounded sidecar read requires a retained present sidecar",
            )
        if purpose == "header":
            valid_shape = offset == 0 and length == 28
        elif purpose == "tail":
            valid_shape = (
                length == 16
                and record.size >= 16
                and offset == record.size - 16
            )
        elif purpose == "pointer":
            path_max = self._path_maxima[
                _SIDECAR_DATABASES.index(database)
            ]
            valid_shape = (
                4 <= length <= path_max + 4
                and offset >= 28
                and offset + length == record.size - 16
            )
        else:
            valid_shape = False
        if not valid_shape:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                "bounded sidecar read does not match header/tail/pointer shape",
            )
        self.revalidate()
        fd = getattr(self, _SIDECAR_FD_SLOTS[index])
        chunks = bytearray()
        try:
            while len(chunks) < length:
                remaining = length - len(chunks)
                try:
                    chunk = os.pread(fd, remaining, offset + len(chunks))
                except OSError as exc:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"bounded sidecar read failed: {exc}",
                    ) from exc
                if not isinstance(chunk, bytes):
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        "bounded sidecar read returned a non-bytes result",
                    )
                if not chunk:
                    raise _SidecarChurn("bounded sidecar read ended early")
                if len(chunk) > remaining:
                    raise _SidecarChurn(
                        "bounded sidecar read exceeded its request"
                    )
                chunks.extend(chunk)
            if purpose == "tail":
                try:
                    extra = os.pread(fd, 1, offset + length)
                except OSError as exc:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"bounded sidecar EOF proof failed: {exc}",
                    ) from exc
                if extra != b"":
                    raise _SidecarChurn(
                        "bounded sidecar tail has extra bytes"
                    )
        finally:
            self.revalidate()
        return bytes(chunks)

    def close(self) -> None:
        if self._terminal_refusal is not None:
            raise self._terminal_refusal
        if self._closed:
            return
        self._closed = True
        failures: tuple[str, ...] = ()
        owned_fds = tuple(
            fd
            for slot in _SIDECAR_FD_SLOTS
            if (fd := getattr(self, slot)) >= 0
        )
        for slot in _SIDECAR_FD_SLOTS:
            setattr(self, slot, -1)
        # All descriptor authority is cleared before the first close because
        # a failed POSIX close leaves reuse of that numeric fd ambiguous.
        for fd in owned_fds:
            try:
                os.close(fd)
            except OSError as exc:
                failures += (f"fd {fd}: {exc}",)
        if failures:
            refusal = ProcessingRefused(
                REASON_ATOMIC_MODE,
                "recognized SQLite sidecar close outcome is ambiguous: "
                + "; ".join(failures),
            )
            self._terminal_refusal = refusal
            raise refusal


@dataclasses.dataclass(frozen=True)
class _MasterJournalObservation:
    """FD-free retained master-journal facts."""

    state: str  # exactly none or retained
    path: str | None
    size: int | None
    entries: tuple[str, ...]
    content: bytes


def _master_journal_size_limit(path_max: int) -> int:
    if (
        isinstance(path_max, bool)
        or not isinstance(path_max, int)
        or path_max <= 0
        or path_max > (_SQLITE_MAX_INT // 2) - 1
    ):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "main-parent PATH_MAX cannot safely bound a master journal",
        )
    return 2 * (path_max + 1)


def _parse_master_journal_content(
    content: bytes,
    *,
    assessments_journal_path: str,
    vacancy_journal_path: str,
) -> tuple[str, str]:
    """Parse exactly two NUL-terminated canonical journal pathnames."""

    if not isinstance(content, bytes):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "master-journal content must be exact bytes",
        )
    parts = content.split(b"\x00")
    if len(parts) != 3 or parts[-1] != b"" or not parts[0] or not parts[1]:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "master journal must contain exactly two nonempty NUL-terminated paths",
        )
    entries = (
        _decode_canonical_absolute_path(parts[0], "master journal entry 1"),
        _decode_canonical_absolute_path(parts[1], "master journal entry 2"),
    )
    if entries[0] == entries[1]:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "master journal entries must be distinct",
        )
    expected = {assessments_journal_path, vacancy_journal_path}
    if set(entries) != expected:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "master journal entries do not name the exact retained journals",
        )
    return entries


class _MasterJournalCapture:
    """Retain one pointer-authorized master leaf without epoch decisions."""

    __slots__ = (
        "_sidecars",
        "_journals",
        "_fd",
        "_closed",
        "_terminal_refusal",
        "_name",
        "_identity",
        "_size",
        "_fact",
    )

    def __init__(
        self,
        sidecars: _SidecarPairCapture,
        journals: tuple[_JournalObservation, ...],
    ) -> None:
        self._sidecars = sidecars
        self._journals = journals
        self._fd = -1
        self._closed = False
        self._terminal_refusal: ProcessingRefused | None = None
        self._name: str | None = None
        self._identity: tuple[int, int, int, int, int] | None = None
        self._size: int | None = None
        self._fact = _MasterJournalObservation(
            state="none", path=None, size=None, entries=(), content=b""
        )
        try:
            pointer_path = self._validated_pointer_path()
            self._require_current_journals()
            if pointer_path is None:
                return

            main_parent = sidecars._assessments.parent
            name = Path(pointer_path).name
            try:
                before = os.stat(
                    name,
                    dir_fd=main_parent.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError as exc:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    "pointer-authorized master journal is missing",
                ) from exc
            _require_private_sidecar(before, "master journal pre-open")
            size_limit = _master_journal_size_limit(
                sidecars.path_maxima[0]
            )
            if before.st_size < 0 or before.st_size > size_limit:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"master journal exceeds its {size_limit}-byte bound",
                )
            raw = os.open(
                name,
                _sidecar_open_flags(),
                dir_fd=main_parent.fd,
            )
            self._fd = raw
            opened = os.fstat(raw)
            after = os.stat(
                name,
                dir_fd=main_parent.fd,
                follow_symlinks=False,
            )
            for phase, info in (
                ("pre-open", before),
                ("opened", opened),
                ("final name entry", after),
            ):
                _require_private_sidecar(
                    info, f"master journal {phase}"
                )
                if info.st_size < 0 or info.st_size > size_limit:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"master journal {phase} exceeds its size bound",
                    )
            expected = (_identity(before), before.st_size)
            if (_identity(opened), opened.st_size) != expected:
                raise _SidecarChurn(
                    "master journal changed between lstat and open"
                )
            if (_identity(after), after.st_size) != expected:
                raise _SidecarChurn(
                    "master journal name entry changed after open"
                )
            self._name = name
            self._identity = expected[0]
            self._size = expected[1]
            content = self._read_exact()
            entries = _parse_master_journal_content(
                content,
                assessments_journal_path=(
                    sidecars._assessments.path + "-journal"
                ),
                vacancy_journal_path=sidecars._vacancy.path + "-journal",
            )
            self.revalidate()
            self._fact = _MasterJournalObservation(
                state="retained",
                path=pointer_path,
                size=expected[1],
                entries=entries,
                content=content,
            )
        except BaseException as exc:
            try:
                self.close()
            except ProcessingRefused as cleanup_exc:
                raise cleanup_exc from exc
            if isinstance(exc, (ProcessingRefused, _SidecarChurn)):
                raise
            if isinstance(exc, (OSError, ValueError)):
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"master-journal authority refused: {exc}",
                ) from exc
            raise

    @property
    def fact(self) -> _MasterJournalObservation:
        return self._fact

    @property
    def identity(self) -> tuple[int, int, int, int, int] | None:
        """Return the retained inode identity without exposing its fd."""

        return self._identity

    def _validated_pointer_path(self) -> str | None:
        if (
            not isinstance(self._journals, tuple)
            or len(self._journals) != 2
            or tuple(fact.database for fact in self._journals)
            != _SIDECAR_DATABASES
        ):
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                "master capture requires exact assessments/vacancy observations",
            )
        valid_paths: tuple[str, ...] = ()
        for fact in self._journals:
            pointer = fact.pointer
            if pointer is not None and pointer.kind == "valid":
                if (
                    fact.state != "candidate"
                    or fact.header is None
                    or not fact.header.candidate
                    or not isinstance(fact.pointer_path, str)
                ):
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"{fact.database} pointer observation is incoherent",
                    )
                valid_paths += (fact.pointer_path,)
            elif fact.pointer_path is not None:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"{fact.database} carries a path without a valid pointer",
                )
        if not valid_paths:
            return None
        if len(valid_paths) != 2 or valid_paths[0] != valid_paths[1]:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                "both journals must carry one identical valid master pointer",
            )
        return valid_paths[0]

    def _require_current_journals(self) -> None:
        current = self._sidecars.observe_journals()
        if current != self._journals:
            raise _SidecarChurn(
                "journal observations changed during master capture"
            )

    def revalidate(self) -> None:
        if self._terminal_refusal is not None:
            raise self._terminal_refusal
        if self._closed:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                "master-journal capture is already closed",
            )
        self._require_current_journals()
        if self._fd < 0:
            return
        assert self._name is not None
        assert self._identity is not None
        assert self._size is not None
        parent = self._sidecars._assessments.parent
        try:
            entry = os.stat(
                self._name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as exc:
            raise _SidecarChurn("master journal disappeared") from exc
        except OSError as exc:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"master journal name entry is unstatable: {exc}",
            ) from exc
        _require_private_sidecar(entry, "master journal name entry")
        try:
            opened = os.fstat(self._fd)
        except OSError as exc:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"master journal retained fd is unstatable: {exc}",
            ) from exc
        _require_private_sidecar(
            opened,
            "master journal retained fd",
            allow_unlinked=True,
        )
        expected = (self._identity, self._size)
        if (_identity(entry), entry.st_size) != expected:
            raise _SidecarChurn("master journal name entry changed")
        if (_identity(opened), opened.st_size) != expected:
            raise _SidecarChurn("master journal retained file changed")

    def _read_exact(self) -> bytes:
        assert self._size is not None
        self.revalidate()
        chunks = bytearray()
        try:
            while len(chunks) < self._size:
                remaining = self._size - len(chunks)
                try:
                    chunk = os.pread(
                        self._fd,
                        min(65_536, remaining),
                        len(chunks),
                    )
                except OSError as exc:
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        f"bounded master-journal read failed: {exc}",
                    ) from exc
                if not isinstance(chunk, bytes):
                    raise ProcessingRefused(
                        REASON_ATOMIC_MODE,
                        "bounded master-journal read returned non-bytes",
                    )
                if not chunk:
                    raise _SidecarChurn(
                        "bounded master-journal read ended early"
                    )
                if len(chunk) > remaining:
                    raise _SidecarChurn(
                        "bounded master-journal read exceeded its request"
                    )
                chunks.extend(chunk)
            try:
                extra = os.pread(self._fd, 1, self._size)
            except OSError as exc:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"bounded master-journal EOF proof failed: {exc}",
                ) from exc
            if extra != b"":
                raise _SidecarChurn(
                    "bounded master-journal read found extra bytes"
                )
        finally:
            self.revalidate()
        return bytes(chunks)

    def close(self) -> None:
        if self._terminal_refusal is not None:
            raise self._terminal_refusal
        if self._closed:
            return
        self._closed = True
        fd = self._fd
        self._fd = -1
        if fd < 0:
            return
        try:
            os.close(fd)
        except OSError as exc:
            refusal = ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"master-journal close outcome is ambiguous for fd {fd}: {exc}",
            )
            self._terminal_refusal = refusal
            raise refusal


@dataclasses.dataclass(frozen=True)
class _FilesystemEpochFacts:
    """Descriptor-free exact facts from one complete sidecar epoch."""

    sidecars: tuple[_SidecarObservation, ...]
    path_maxima: tuple[int, int]
    journals: tuple[_JournalObservation, ...]
    master: _MasterJournalObservation
    master_identity: tuple[int, int, int, int, int] | None


def _close_filesystem_epoch_owners(
    master: _MasterJournalCapture | None,
    sidecars: _SidecarPairCapture | None,
    primary: BaseException | None,
) -> None:
    """Close one epoch deepest-first without concealing ambiguity."""

    failures: tuple[str, ...] = ()
    for label, owner in (("master", master), ("sidecars", sidecars)):
        if owner is None:
            continue
        try:
            owner.close()
        except BaseException as exc:
            failures += (f"{label}: {exc}",)
    if failures:
        refusal = ProcessingRefused(
            REASON_ATOMIC_MODE,
            "filesystem epoch close outcome is ambiguous: " + "; ".join(failures),
        )
        if primary is not None:
            raise refusal from primary
        raise refusal
    if primary is not None:
        raise primary


def _capture_filesystem_epoch(
    descriptors: _DescriptorSet,
    assessments: _RetainedDatabaseLeaf,
    vacancy: _RetainedDatabaseLeaf,
) -> _FilesystemEpochFacts:
    """Capture, prove, freeze, and close one complete filesystem epoch."""

    sidecars: _SidecarPairCapture | None = None
    master: _MasterJournalCapture | None = None
    facts: _FilesystemEpochFacts | None = None
    primary: BaseException | None = None
    try:
        _assert_chain_intact(
            descriptors,
            assessments,
            vacancy,
            allow_sidecar_parent_nlink_churn=True,
        )
        sidecars = _SidecarPairCapture(descriptors, assessments, vacancy)
        journals = sidecars.observe_journals()
        master = _MasterJournalCapture(sidecars, journals)
        master.revalidate()
        sidecars.revalidate()
        if sidecars.observe_journals() != journals:
            raise _SidecarChurn("journal observations changed before epoch publication")
        master.revalidate()
        sidecars.revalidate()
        _assert_chain_intact(
            descriptors,
            assessments,
            vacancy,
            allow_sidecar_parent_nlink_churn=True,
        )
        # This is deliberately the final fallible authority read before the
        # descriptor-free facts are published. It also re-proves the journal
        # observations and sidecar chains before checking the retained master
        # descriptor and name entry.
        master.revalidate()
        facts = _FilesystemEpochFacts(
            sidecars=sidecars.records,
            path_maxima=sidecars.path_maxima,
            journals=journals,
            master=master.fact,
            master_identity=master.identity,
        )
    except BaseException as exc:
        primary = exc
    _close_filesystem_epoch_owners(master, sidecars, primary)
    assert facts is not None
    return facts


def _filesystem_epoch_deadline_refusal() -> ProcessingRefused:
    return ProcessingRefused(
        REASON_ATOMIC_MODE,
        "filesystem epoch did not stabilize before the fixed 30-second deadline",
    )


def _stabilize_filesystem_epoch(
    descriptors: _DescriptorSet,
    assessments: _RetainedDatabaseLeaf,
    vacancy: _RetainedDatabaseLeaf,
) -> _FilesystemEpochFacts:
    """Require two identical complete epochs under one fixed deadline."""

    deadline = time.monotonic() + 30.0
    while True:
        try:
            first = _capture_filesystem_epoch(descriptors, assessments, vacancy)
            if time.monotonic() >= deadline:
                raise _filesystem_epoch_deadline_refusal()
            second = _capture_filesystem_epoch(descriptors, assessments, vacancy)
        except _SidecarChurn:
            if time.monotonic() >= deadline:
                raise _filesystem_epoch_deadline_refusal()
            continue
        if time.monotonic() >= deadline:
            raise _filesystem_epoch_deadline_refusal()
        if first == second:
            return second


# ==========================================================================
# Part-3C C2 Increment 1: PRAGMA admission + reason-14 plan + staged score.
# ==========================================================================

def setup_transaction_sqlite(connection: sqlite3.Connection) -> None:
    """Attach-mode PRAGMA admission on an already-open connection.

    Requires exact attached aliases ``main`` and ``vacancy``. Checkpoints
    existing WAL, sets journal_mode/synchronous/foreign_keys/busy_timeout,
    and reads back every result. No connect, attach, BEGIN, COMMIT,
    ROLLBACK, DDL, DML, timestamp, or close.
    """

    def _rows(query: str) -> list[tuple[Any, ...]]:
        rows = connection.execute(query).fetchall()
        if not isinstance(rows, list):
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"PRAGMA {query!r} returned a non-list result",
            )
        return rows

    def _single_value(query: str, expected: Any) -> None:
        rows = _rows(query)
        if len(rows) != 1 or type(rows[0]) is not tuple or len(rows[0]) != 1:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"PRAGMA {query!r} returned the wrong row shape: {rows!r}",
            )
        value = rows[0][0]
        if type(value) is not type(expected) or value != expected:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"PRAGMA {query!r} reported {value!r} "
                f"({type(value).__name__}), expected {expected!r} "
                f"({type(expected).__name__})",
            )

    def _database_list_check() -> None:
        try:
            listed = _rows("PRAGMA database_list")
        except sqlite3.Error as exc:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"database_list query failed: {exc}",
            ) from exc
        if len(listed) != 2:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"attached aliases must be exactly two (main+vacancy), "
                f"got {len(listed)}",
            )
        aliases: list[str] = []
        for row in listed:
            if (
                type(row) is not tuple
                or len(row) != 3
                or type(row[0]) is not int
                or type(row[1]) is not str
                or type(row[2]) is not str
            ):
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"database_list row has wrong shape: {row!r}",
                )
            aliases.append(row[1])
        if aliases != ["main", "vacancy"]:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"attached aliases must be exactly main and vacancy, got {aliases}",
            )

    _database_list_check()
    try:
        for alias in ("main", "vacancy"):
            ckpt_rows = _rows(f"PRAGMA {alias}.wal_checkpoint(TRUNCATE)")
            if (
                len(ckpt_rows) != 1
                or type(ckpt_rows[0]) is not tuple
                or len(ckpt_rows[0]) != 3
                or any(type(value) is not int for value in ckpt_rows[0])
            ):
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"wal_checkpoint row shape mismatch: {ckpt_rows!r}",
                )
            busy, log_frames, checkpointed_frames = ckpt_rows[0]
            if busy != 0:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"wal_checkpoint busy result for {alias}: {busy}",
                )
            if log_frames < -1 or checkpointed_frames < -1:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"wal_checkpoint frame counts are invalid: {ckpt_rows[0]!r}",
                )
            _single_value(f"PRAGMA {alias}.journal_mode=DELETE", "delete")
            _single_value(f"PRAGMA {alias}.journal_mode", "delete")
            connection.execute(f"PRAGMA {alias}.synchronous=FULL")
            _single_value(f"PRAGMA {alias}.synchronous", 2)
        connection.execute("PRAGMA foreign_keys=ON")
        _single_value("PRAGMA foreign_keys", 1)
        connection.execute("PRAGMA busy_timeout=30000")
        _single_value("PRAGMA busy_timeout", 30000)
        _database_list_check()
    except sqlite3.Error as exc:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE, f"SQLite setup error: {exc}"
        ) from exc


@dataclasses.dataclass(frozen=True)
class _Reason14Plan:
    normalized_action: str  # "insert" or "reuse"
    normalized_json: str
    normalized_at: str
    normalized_json_sha256: str
    score_plan: ScoreReadPlan
    score_payload_hash: str
    event_action: str  # always "insert_required"
    url: str
    title: str
    company: str
    extraction_confidence: float | None


def plan_reason14_projections(
    connection: sqlite3.Connection,
    *,
    result_obj: ScoreResult,
    url: str,
    title: str,
    company: str,
    extraction_confidence: float | None,
    job_key: str,
    profile_id: str,
    normalized_json: str,
    normalized_json_sha256: str,
    accepted_at: str,
) -> "_Reason14Plan":
    """Read-only reason-14 planning through canonical owner classifiers.

    Validates accepted_at strictly BEFORE any SQL. Performs no DDL/DML/
    transaction/time generation. Absent normalized row plans insert with
    accepted_at; exact bytes preserve stored RFC3339 normalized_at;
    changed bytes map ProjectionConflict to projection_conflict.
    Calls the canonical plan_accepted_score once, preserving its
    ScoreReadPlan and durable timestamps. Any existing event refuses.
    """
    try:
        require_rfc3339_timestamp(accepted_at, "accepted_at")
        if type(result_obj) is not ScoreResult:
            raise TypeError("result_obj must be the exact ScoreResult type")
        if type(normalized_json) is not str:
            raise TypeError("normalized_json must be exact text")
        if (
            type(normalized_json_sha256) is not str
            or SHA256_PATTERN.fullmatch(normalized_json_sha256) is None
        ):
            raise ValueError("normalized_json_sha256 must be a lowercase SHA-256")
        if result_obj.profile_id != profile_id or result_obj.job_key != job_key:
            raise ValueError("score projection identity differs from reason-14 identity")
        computed_hash = hashlib.sha256(normalized_json.encode("utf-8")).hexdigest()
    except (ProjectionConflict, TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"reason-14 input is invalid: {exc}",
        ) from exc
    if computed_hash != normalized_json_sha256:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "normalized_json_sha256 differs from the exact normalized_json bytes",
        )

    try:
        existing_norm = read_normalized_job(connection, key=job_key)
        if existing_norm is None:
            norm_at = accepted_at
            normalized_action = "insert"
        else:
            if (
                type(existing_norm) is not tuple
                or len(existing_norm) != 2
                or type(existing_norm[0]) is not str
                or type(existing_norm[1]) is not str
            ):
                raise ProjectionConflict("normalized projection row is malformed")
            stored_json, norm_at = existing_norm
            require_rfc3339_timestamp(norm_at, "stored normalized_at")
            if stored_json != normalized_json:
                raise ProjectionConflict("normalized projection bytes differ")
            normalized_action = "reuse"

        score_plan = plan_accepted_score(
            connection,
            result=result_obj,
            url=url,
            title=title,
            company=company,
            extraction_confidence=extraction_confidence,
            accepted_at=accepted_at,
        )
        events = classify_processing_score_event(
            connection, profile_id=profile_id, job_key=job_key
        )
        if events.action != "insert_required" or events.count != 0:
            raise ProjectionConflict(
                f"processing_score_accepted events already exist ({events.count})"
            )
    except sqlite3.Error:
        raise
    except (ProjectionConflict, TypeError, ValueError, KeyError) as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"reason-14 projection conflict: {exc}",
        ) from exc

    _, score_payload_hash = canonical_score_payload(result_obj)

    return _Reason14Plan(
        normalized_action=normalized_action,
        normalized_json=normalized_json,
        normalized_at=norm_at,
        normalized_json_sha256=normalized_json_sha256,
        score_plan=score_plan,
        score_payload_hash=score_payload_hash,
        event_action="insert_required",
        url=url,
        title=title,
        company=company,
        extraction_confidence=extraction_confidence,
    )

def result_from_staged(facts: EnvelopeFacts) -> ScoreResult:
    """Pure reconstruction of ScoreResult from staged canonical bytes.

    Strict-parses the exact stored bytes, validates shape, verifies
    canonical bytes match, and checks type-exact field equality against
    facts.expected_score before returning.
    """
    try:
        parsed = strict_json_loads(
            facts.expected_score_canonical.decode("utf-8"))
        validate_score_result_shape(parsed)
        recomputed = canonical_json(parsed).encode("utf-8")
        if recomputed != facts.expected_score_canonical:
            raise ProcessingRefused(
                REASON_SCORE_RESULT,
                "staged expected score canonical bytes drifted",
            )
        expected = facts.expected_score
        for field in (
            "profile_id",
            "job_key",
            "track",
            "fit_status",
            "parameters_hash",
        ):
            staged_value = parsed[field]
            expected_value = getattr(expected, field)
            if type(staged_value) is not type(expected_value) or staged_value != expected_value:
                raise ProcessingRefused(
                    REASON_SCORE_RESULT,
                    f"expected score {field} identity drifted",
                )
        for field in ("fit", "opportunity", "final"):
            if not _type_exact_number_equal(
                parsed[field], getattr(expected, field)
            ):
                raise ProcessingRefused(
                    REASON_SCORE_RESULT,
                    f"expected score {field} value or primitive type drifted",
                )
        for key in ("fit_subscores", "opportunity_subscores"):
            staged_subscores = parsed[key]
            expected_subscores = dict(getattr(expected, key))
            if set(staged_subscores) != set(expected_subscores):
                raise ProcessingRefused(
                    REASON_SCORE_RESULT,
                    f"expected score {key} keys drifted",
                )
            for sub_key in sorted(expected_subscores):
                if not _type_exact_number_equal(
                    staged_subscores[sub_key], expected_subscores[sub_key]
                ):
                    raise ProcessingRefused(
                        REASON_SCORE_RESULT,
                        f"expected score {key}.{sub_key} value or primitive type drifted",
                    )
    except ProcessingRefused:
        raise
    except (ValueError, KeyError, TypeError) as exc:
        raise ProcessingRefused(
            REASON_SCORE_RESULT,
            f"staged score reconstruction failed: {exc}",
        ) from exc

    return ScoreResult(
        profile_id=parsed["profile_id"],
        job_key=parsed["job_key"],
        track=parsed["track"],
        fit=parsed["fit"],
        opportunity=parsed["opportunity"],
        final=parsed["final"],
        fit_status=FitStatus(parsed["fit_status"]),
        parameters_hash=parsed["parameters_hash"],
        fit_subscores=dict(parsed["fit_subscores"]),
        opportunity_subscores=dict(parsed["opportunity_subscores"]),
    )


# ==========================================================================
# Part-3C C2 Increment 2: prospective event ID and receipt/event plan.
# ==========================================================================

def _prospective_event_id(connection: sqlite3.Connection) -> int:
    """Read-only prospective event ID from a BEGIN-IMMEDIATE connection.

    Reads sqlite_sequence.seq for assessment_events (when the ledger
    exists) and MAX(assessment_events.id). Absent values are zero.
    Computes max+1. Refuses > signed64 max with REASON_ATOMIC_MODE.
    SQL errors propagate for later stable storage classification.
    No DDL/DML/time/transaction control.
    """
    def _rows(sql: str) -> list[tuple[Any, ...]]:
        rows = connection.execute(sql).fetchall()
        if type(rows) is not list:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"prospective event query returned non-list rows: {rows!r}",
            )
        return rows

    sequence_table = _rows(
        "SELECT name FROM main.sqlite_master "
        "WHERE type='table' AND name='sqlite_sequence'"
    )
    if sequence_table == []:
        sequence_exists = False
    elif (
        len(sequence_table) == 1
        and type(sequence_table[0]) is tuple
        and len(sequence_table[0]) == 1
        and type(sequence_table[0][0]) is str
        and sequence_table[0][0] == "sqlite_sequence"
    ):
        sequence_exists = True
    else:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"sqlite_sequence catalogue result is malformed: {sequence_table!r}",
        )

    seq = 0
    if sequence_exists:
        sequence_rows = _rows(
            "SELECT seq FROM main.sqlite_sequence "
            "WHERE name='assessment_events'"
        )
        if len(sequence_rows) > 1:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"assessment_events has multiple sqlite_sequence rows: "
                f"{sequence_rows!r}",
            )
        if sequence_rows:
            row = sequence_rows[0]
            if type(row) is not tuple or len(row) != 1:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"sqlite_sequence row is malformed: {row!r}",
                )
            value = row[0]
            if type(value) is not int or not 0 <= value <= MAX_EVENT_ID:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    f"sqlite_sequence.seq is invalid: {value!r}",
                )
            seq = value

    maximum_rows = _rows("SELECT MAX(id) FROM main.assessment_events")
    if (
        len(maximum_rows) != 1
        or type(maximum_rows[0]) is not tuple
        or len(maximum_rows[0]) != 1
    ):
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"MAX(assessment_events.id) result is malformed: {maximum_rows!r}",
        )
    maximum_value = maximum_rows[0][0]
    if maximum_value is None:
        max_id = 0
    elif type(maximum_value) is int and 0 <= maximum_value <= MAX_EVENT_ID:
        max_id = maximum_value
    else:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"MAX(assessment_events.id) is invalid: {maximum_value!r}",
        )
    prospective = max(seq, max_id) + 1
    if prospective > MAX_EVENT_ID:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"prospective event id {prospective} exceeds signed64 maximum",
        )
    return prospective


@dataclasses.dataclass(frozen=True)
class _ProspectivePlan:
    """Frozen immutable prospective-event/receipt execution plan."""

    sealed_bytes: bytes
    receipt_file_sha256: str
    receipt_self_hash: str
    binding_sha256: str
    event_payload_json: str
    event_payload_sha256: str
    idempotency_key: str
    accepted_at: str
    event_id: int
    facts: EnvelopeFacts
    reason14: _Reason14Plan


def _enforce_receipt_size(sealed_bytes: bytes) -> bytes:
    """Apply the exact inclusive processing-receipt byte ceiling."""

    if type(sealed_bytes) is not bytes:
        raise TypeError("sealed receipt must be exact bytes")
    if len(sealed_bytes) > MAX_RECEIPT_BYTES:
        raise ProcessingRefused(
            REASON_ENVELOPE_BYTES,
            f"sealed receipt is {len(sealed_bytes)} bytes; maximum is "
            f"{MAX_RECEIPT_BYTES}",
        )
    return sealed_bytes


def build_prospective_plan(
    *,
    facts: EnvelopeFacts,
    reason14: "_Reason14Plan",
    accepted_at: str,
    prospective_event_id: int,
) -> "_ProspectivePlan":
    """Pure builder assembling the exact receipt and event plan.

    Validates types/RFC3339/event range. Rebuilds the binding from facts.
    Constructs the flat event payload, canonical bytes/hash, fixed-width
    Unicode-safe idempotency key, exact projections, all false authority
    flags, self_hash, canonical stored bytes+LF and file SHA.
    Assessment insert uses accepted_at; reuse preserves ScoreReusePlan
    created_at/updated_at. Normalized reuse preserves normalized_at.
    Receipt.created_at == event.created_at == accepted_at.
    Strictly self-validates the finished receipt; len <= 4194304;
    oversize maps to REASON_ENVELOPE_BYTES before any write.
    """
    try:
        if type(facts) is not EnvelopeFacts:
            raise TypeError("facts must be the exact EnvelopeFacts type")
        if type(reason14) is not _Reason14Plan:
            raise TypeError("reason14 must be the exact _Reason14Plan type")
        _assert_fully_immutable(facts, "facts")
        _assert_fully_immutable(reason14, "reason14")
        rfc3339_value(accepted_at, "accepted_at")
    except (TypeError, ValueError) as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"prospective plan inputs are invalid: {exc}",
        ) from exc
    if isinstance(prospective_event_id, bool) or not isinstance(
        prospective_event_id, int
    ) or prospective_event_id <= 0:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"prospective_event_id must be a positive integer, got "
            f"{prospective_event_id!r}",
        )
    if prospective_event_id > MAX_EVENT_ID:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "prospective_event_id exceeds signed64 maximum",
        )

    binding, binding_sha256 = build_processing_binding_from_facts(facts)

    if reason14.normalized_action not in ("insert", "reuse"):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"unknown normalized projection action {reason14.normalized_action!r}",
        )
    try:
        if type(reason14.normalized_json) is not str:
            raise ValueError("reason14.normalized_json must be exact text")
        rfc3339_value(reason14.normalized_at, "reason14.normalized_at")
        sha256_value(
            reason14.normalized_json_sha256,
            "reason14.normalized_json_sha256",
        )
        sha256_value(reason14.score_payload_hash, "reason14.score_payload_hash")
    except ValueError as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"prospective projection plan is malformed: {exc}",
        ) from exc
    if (
        hashlib.sha256(reason14.normalized_json.encode("utf-8")).hexdigest()
        != reason14.normalized_json_sha256
    ):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "reason-14 normalized bytes differ from their SHA-256",
        )
    if reason14.event_action != "insert_required":
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"event action must be insert_required, got {reason14.event_action!r}",
        )
    if type(reason14.score_plan) is not ScoreReadPlan:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "score plan must be the exact ScoreReadPlan type",
        )
    staged_result = result_from_staged(facts)
    _score_payload_json, staged_score_payload_hash = canonical_score_payload(
        staged_result
    )
    if reason14.score_payload_hash != staged_score_payload_hash:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "reason-14 score payload hash differs from the staged score",
        )
    if (
        reason14.normalized_action == "insert"
        and reason14.normalized_at != accepted_at
    ):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "insert normalized timestamp differs from accepted_at",
        )

    # Determine assessment timestamps from the reason14 plan.
    if reason14.score_plan.action == "reuse":
        if (
            reason14.score_plan.insert is not None
            or type(reason14.score_plan.reuse) is not ScoreReusePlan
        ):
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                "reuse score plan has an invalid shape",
            )
        sc_created = reason14.score_plan.reuse.created_at
        sc_updated = reason14.score_plan.reuse.updated_at
        try:
            require_rfc3339_timestamp(sc_created, "reused assessment created_at")
            require_rfc3339_timestamp(sc_updated, "reused assessment updated_at")
        except ProjectionConflict as exc:
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                f"reused score timestamps are invalid: {exc}",
            ) from exc
        if reason14.score_plan.reuse.score_payload_hash != reason14.score_payload_hash:
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                "reused score payload hash differs from reason-14",
            )
        if (
            reason14.score_plan.reuse.profile_id != facts.profile_id
            or reason14.score_plan.reuse.job_key != facts.job_key
        ):
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                "reused score projection identity differs from the envelope",
            )
    elif reason14.score_plan.action == "insert":
        if (
            reason14.score_plan.reuse is not None
            or type(reason14.score_plan.insert) is not ScoreInsertPlan
            or reason14.score_plan.insert.created_at != accepted_at
            or reason14.score_plan.insert.score_payload_hash
            != reason14.score_payload_hash
        ):
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                "insert score plan has an invalid shape",
            )
        if (
            reason14.score_plan.insert.profile_id != facts.profile_id
            or reason14.score_plan.insert.job_key != facts.job_key
        ):
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                "insert score projection identity differs from the envelope",
            )
        sc_created = accepted_at
        sc_updated = accepted_at
    else:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"unknown score plan action {reason14.score_plan.action!r}",
        )

    # Normalized timestamp already validated in the reason14 plan.
    norm_at = reason14.normalized_at

    # Build the complete receipt dict.
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "operation_id": binding["operation_id"],
        "job_key": binding["job_key"],
        "profile_id": binding["profile_id"],
        "profile_version": binding["profile_version"],
        "track": binding["track"],
        "binding_sha256": binding_sha256,
        "envelope_file_sha256": facts.envelope_file_sha256,
        "envelope_semantic_sha256": facts.envelope_semantic_sha256,
        "config": copy.deepcopy(binding["config"]),
        "databases": copy.deepcopy(binding["databases"]),
        "raw": copy.deepcopy(binding["raw"]),
        "profile": copy.deepcopy(binding["profile"]),
        "extraction": copy.deepcopy(binding["extraction"]),
        "alignment": copy.deepcopy(binding["alignment"]),
        "scoring": copy.deepcopy(binding["scoring"]),
        "normalised_projection": {
            "job_key": binding["job_key"],
            "normalized_json_sha256": reason14.normalized_json_sha256,
            "normalized_at": norm_at,
        },
        "assessment_projection": {
            "profile_id": binding["profile_id"],
            "job_key": binding["job_key"],
            "score_payload_hash": reason14.score_payload_hash,
            "state": "scored",
            "created_at": sc_created,
            "updated_at": sc_updated,
        },
    }
    for flag in _RECEIPT_FALSE_FLAGS:
        receipt[flag] = False
    receipt["assessment_event"] = {
        "id": prospective_event_id,
        "event_type": EVENT_TYPE_PROCESSING_SCORE_ACCEPTED,
        "actor_kind": "deterministic",
        "payload_sha256": "",
        "created_at": accepted_at,
    }

    event_payload = build_processing_event_payload(receipt)
    event_payload_json = canonical_json(event_payload)
    event_payload_sha = hashlib.sha256(
        event_payload_json.encode("utf-8")
    ).hexdigest()
    receipt["assessment_event"]["payload_sha256"] = event_payload_sha
    idem_key = expected_idempotency_key(
        binding["profile_id"], binding["job_key"], event_payload_sha
    )
    receipt["assessment_event"]["idempotency_key"] = idem_key

    receipt["created_at"] = accepted_at
    receipt["self_hash"] = receipt_self_hash(
        {k: v for k, v in receipt.items() if k != "self_hash"}
    )
    sealed = _enforce_receipt_size(sealed_receipt_bytes(receipt))

    # Self-validate the finished receipt.
    reparsed, reparsed_facts = _self_validating_receipt(sealed)
    if reparsed["self_hash"] != receipt["self_hash"]:
        raise ProcessingRefused(
            REASON_ENVELOPE_BYTES,
            "self-validating receipt returned a different self hash",
        )
    if reparsed_facts != facts:
        raise ProcessingRefused(
            REASON_ENVELOPE_BYTES,
            "self-validating receipt reconstructed different envelope facts",
        )

    receipt_file_sha256 = hashlib.sha256(sealed).hexdigest()

    plan = _ProspectivePlan(
        sealed_bytes=sealed,
        receipt_file_sha256=receipt_file_sha256,
        receipt_self_hash=receipt["self_hash"],
        binding_sha256=binding_sha256,
        event_payload_json=event_payload_json,
        event_payload_sha256=event_payload_sha,
        idempotency_key=idem_key,
        accepted_at=accepted_at,
        event_id=prospective_event_id,
        facts=facts,
        reason14=reason14,
    )
    _assert_fully_immutable(plan, "prospective_plan")
    return plan


@dataclasses.dataclass(frozen=True)
class _TransactionApplyOutcome:
    """Immutable exact result of the caller-owned transaction body."""

    sealed_bytes: bytes
    receipt_file_sha256: str
    receipt_self_hash: str
    binding_sha256: str
    event_id: int
    accepted_at: str
    normalized_action: str
    score_action: str


_PROCESSING_RECEIPT_ROW_COLUMNS = (
    "operation_id",
    "profile_id",
    "job_key",
    "track",
    "binding_sha256",
    "envelope_file_sha256",
    "envelope_semantic_sha256",
    "normalized_sha256",
    "assessment_payload_hash",
    "event_id",
    "receipt_self_hash",
    "receipt_file_sha256",
    "receipt_bytes",
    "created_at",
)


def _processing_receipt_row_values(plan: _ProspectivePlan) -> tuple[Any, ...]:
    """Return the exact storage row represented by one immutable plan."""

    try:
        receipt, receipt_facts = _self_validating_receipt(plan.sealed_bytes)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"prospective receipt is not self-validating: {exc}",
        ) from exc
    if receipt_facts != plan.facts:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "prospective receipt reconstructs different envelope facts",
        )
    return (
        receipt["operation_id"],
        receipt["profile_id"],
        receipt["job_key"],
        receipt["track"],
        plan.binding_sha256,
        receipt["envelope_file_sha256"],
        receipt["envelope_semantic_sha256"],
        plan.reason14.normalized_json_sha256,
        plan.reason14.score_payload_hash,
        plan.event_id,
        plan.receipt_self_hash,
        plan.receipt_file_sha256,
        plan.sealed_bytes,
        plan.accepted_at,
    )


def apply_transaction_plan(
    connection: sqlite3.Connection,
    plan: _ProspectivePlan,
) -> _TransactionApplyOutcome:
    """Apply one exact FIT plan inside the caller's active transaction.

    This seam owns neither connection setup nor transaction control.  It
    applies the canonical migration and projection owners, writes the sealed
    receipt last, and rereads every exact durable identity before returning.
    SQLite storage errors propagate for the outer stable-outcome classifier.
    """

    if type(plan) is not _ProspectivePlan:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "transaction plan must be the exact _ProspectivePlan type",
        )
    try:
        _assert_fully_immutable(plan, "transaction_plan")
    except TypeError as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"transaction plan is mutable: {exc}",
        ) from exc
    if getattr(connection, "in_transaction", False) is not True:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "transaction plan requires an active caller-owned transaction",
        )

    receipt, _receipt_facts = _self_validating_receipt(plan.sealed_bytes)
    row_values = _processing_receipt_row_values(plan)

    try:
        apply_on(connection, (FIT001_PROCESSING_RECEIPTS,), "main")
    except MigrationCompatibilityError as exc:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"FIT migration is incompatible: {exc}",
        ) from exc
    _maybe_fault("after_migration_apply")

    try:
        normalized_action = cas_normalized_job(
            connection,
            key=plan.facts.job_key,
            normalized_json=plan.reason14.normalized_json,
            normalized_at=plan.reason14.normalized_at,
        )
    except ProjectionConflict as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"normalized projection conflict: {exc}",
        ) from exc
    expected_normalized_action = {
        "insert": "inserted",
        "reuse": "reused",
    }[plan.reason14.normalized_action]
    if normalized_action != expected_normalized_action:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "normalized CAS action differs from its read plan",
        )
    _maybe_fault("after_normalized_cas")

    staged_result = result_from_staged(plan.facts)
    try:
        score_outcome = cas_accepted_score(
            connection,
            result=staged_result,
            url=plan.reason14.url,
            title=plan.reason14.title,
            company=plan.reason14.company,
            extraction_confidence=plan.reason14.extraction_confidence,
            accepted_at=plan.accepted_at,
        )
    except ProjectionConflict as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"assessment projection conflict: {exc}",
        ) from exc
    if (
        score_outcome.action != plan.reason14.score_plan.action
        or score_outcome.plan != plan.reason14.score_plan
        or score_outcome.projection is None
        or score_outcome.projection.score_payload_hash
        != plan.reason14.score_payload_hash
        or score_outcome.projection.created_at
        != receipt["assessment_projection"]["created_at"]
        or score_outcome.projection.updated_at
        != receipt["assessment_projection"]["updated_at"]
    ):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "assessment CAS result differs from its exact read plan",
        )
    _maybe_fault("after_assessment_cas")

    try:
        event_outcome = cas_processing_event(
            connection,
            profile_id=plan.facts.profile_id,
            job_key=plan.facts.job_key,
            event_type=EVENT_TYPE_PROCESSING_SCORE_ACCEPTED,
            actor_kind="deterministic",
            payload_json=plan.event_payload_json,
            idempotency_key=plan.idempotency_key,
            created_at=plan.accepted_at,
            event_id=plan.event_id,
        )
    except ProjectionConflict as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"processing event conflict: {exc}",
        ) from exc
    event_projection = event_outcome.projection
    if (
        event_outcome.action != "insert"
        or event_projection is None
        or event_projection.event_id != plan.event_id
        or event_projection.profile_id != plan.facts.profile_id
        or event_projection.job_key != plan.facts.job_key
        or event_projection.payload_json != plan.event_payload_json
        or event_projection.idempotency_key != plan.idempotency_key
        or event_projection.created_at != plan.accepted_at
    ):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "processing event insert differs from its exact plan",
        )
    _maybe_fault("after_event_insert")

    placeholders = ",".join("?" for _ in _PROCESSING_RECEIPT_ROW_COLUMNS)
    columns = ",".join(_PROCESSING_RECEIPT_ROW_COLUMNS)
    try:
        cursor = connection.execute(
            f"INSERT INTO main.processing_receipts({columns}) "
            f"VALUES({placeholders})",
            row_values,
        )
    except sqlite3.IntegrityError as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"processing receipt integrity conflict: {exc}",
        ) from exc
    if cursor.rowcount != 1:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"processing receipt insert affected {cursor.rowcount!r} rows",
        )
    _maybe_fault("after_receipt_insert")

    stored_row = connection.execute(
        f"SELECT {columns} FROM main.processing_receipts WHERE operation_id=?",
        (plan.facts.operation_id,),
    ).fetchall()
    if (
        type(stored_row) is not list
        or len(stored_row) != 1
        or type(stored_row[0]) is not tuple
        or stored_row[0] != row_values
    ):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "processing receipt reread differs from the exact inserted row",
        )
    try:
        reread_receipt, reread_facts = _self_validating_receipt(stored_row[0][12])
    except ValueError as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"stored receipt reread is invalid: {exc}",
        ) from exc
    if reread_receipt != receipt or reread_facts != plan.facts:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "stored receipt reread reconstructs different authority",
        )

    normalized_reread = read_normalized_job(
        connection, key=plan.facts.job_key
    )
    if normalized_reread != (
        plan.reason14.normalized_json,
        plan.reason14.normalized_at,
    ):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "normalized projection final reread differs from the plan",
        )
    try:
        score_reread = cas_accepted_score(
            connection,
            result=staged_result,
            url=plan.reason14.url,
            title=plan.reason14.title,
            company=plan.reason14.company,
            extraction_confidence=plan.reason14.extraction_confidence,
            accepted_at=plan.accepted_at,
        )
        event_reread = cas_processing_event(
            connection,
            profile_id=plan.facts.profile_id,
            job_key=plan.facts.job_key,
            event_type=EVENT_TYPE_PROCESSING_SCORE_ACCEPTED,
            actor_kind="deterministic",
            payload_json=plan.event_payload_json,
            idempotency_key=plan.idempotency_key,
            created_at=plan.accepted_at,
            event_id=plan.event_id,
        )
    except ProjectionConflict as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"final projection reread conflict: {exc}",
        ) from exc
    if (
        score_reread.action != "reuse"
        or score_reread.projection != score_outcome.projection
        or event_reread.action != "reuse"
        or event_reread.projection != event_projection
    ):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "final canonical reread differs from the inserted projections",
        )
    _maybe_fault("after_transaction_reread")

    outcome = _TransactionApplyOutcome(
        sealed_bytes=plan.sealed_bytes,
        receipt_file_sha256=plan.receipt_file_sha256,
        receipt_self_hash=plan.receipt_self_hash,
        binding_sha256=plan.binding_sha256,
        event_id=plan.event_id,
        accepted_at=plan.accepted_at,
        normalized_action=plan.reason14.normalized_action,
        score_action=plan.reason14.score_plan.action,
    )
    _assert_fully_immutable(outcome, "transaction_outcome")
    return outcome


RECOVERY_DURABLE_COMPLETE = "complete"
RECOVERY_DURABLE_EMPTY = "empty"
RECOVERY_DURABLE_INCOHERENT = "incoherent"


@dataclasses.dataclass(frozen=True)
class RecoveredTransactionClassification:
    """Exact durable truth for one prospective FIT transaction."""

    disposition: str
    stored_receipt_bytes: bytes | None
    detail: str


def classify_recovered_transaction(
    connection: sqlite3.Connection,
    plan: _ProspectivePlan,
) -> RecoveredTransactionClassification:
    """Classify durable FIT truth on one caller-owned attached connection.

    The caller owns recovery, database identity, the attached read snapshot,
    quick/FK checks, and connection lifetime.  This seam performs only exact
    reads.  It never connects, ATTACHes, migrates, repairs, starts or ends a
    transaction, changes journal mode, or writes.  SQLite errors propagate
    for the outer stable error mapper.

    A complete result requires the exact receipt row plus exact normalized,
    assessment, and sole processing-event projections.  An empty result
    permits only the projections that the pre-transaction plan proved were
    already reusable; every operation-owned insert must remain absent.  Any
    other durable shape is incoherent.
    """

    if type(plan) is not _ProspectivePlan:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "recovery plan must be the exact _ProspectivePlan type",
        )
    try:
        _assert_fully_immutable(plan, "recovery_plan")
        expected_receipt_row = _processing_receipt_row_values(plan)
    except ProcessingRefused:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"recovery plan is invalid: {exc}",
        ) from exc

    def incoherent(detail: str) -> RecoveredTransactionClassification:
        return RecoveredTransactionClassification(
            RECOVERY_DURABLE_INCOHERENT,
            None,
            detail,
        )

    try:
        store = _inspect_receipt_store(connection)
    except sqlite3.Error:
        raise
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        return incoherent(f"processing receipt store is malformed: {exc}")
    if store.disposition == DISPOSITION_DEFINITIVE_ABSENCE:
        receipt_rows: list[tuple[Any, ...]] = []
    elif store.disposition == _RECEIPT_STORE_COMPATIBLE:
        columns = ",".join(_PROCESSING_RECEIPT_ROW_COLUMNS)
        receipt_rows = connection.execute(
            f"SELECT {columns} FROM main.processing_receipts "
            "WHERE operation_id=?",
            (plan.facts.operation_id,),
        ).fetchall()
        if type(receipt_rows) is not list or any(
            type(row) is not tuple for row in receipt_rows
        ):
            return incoherent("processing receipt query returned malformed rows")
        if len(receipt_rows) > 1:
            return incoherent("multiple processing receipts exist for the operation")
    else:
        return incoherent(f"processing receipt store is ambiguous: {store.detail}")

    try:
        normalized = read_normalized_job(
            connection,
            key=plan.facts.job_key,
        )
        score = classify_accepted_score(
            connection,
            result=result_from_staged(plan.facts),
            url=plan.reason14.url,
            title=plan.reason14.title,
            company=plan.reason14.company,
            extraction_confidence=plan.reason14.extraction_confidence,
        )
        event_family = classify_processing_score_event(
            connection,
            profile_id=plan.facts.profile_id,
            job_key=plan.facts.job_key,
        )
        event_id_rows = connection.execute(
            "SELECT id,profile_id,job_key,event_type,actor_kind,payload_json,"
            "idempotency_key,created_at FROM main.assessment_events WHERE id=?",
            (plan.event_id,),
        ).fetchall()
        if type(event_id_rows) is not list or any(
            type(row) is not tuple for row in event_id_rows
        ):
            return incoherent("event-id query returned malformed rows")
    except (ProjectionConflict, ProcessingRefused, TypeError, ValueError) as exc:
        return incoherent(f"durable projection validation failed: {exc}")

    expected_normalized = (
        plan.reason14.normalized_json,
        plan.reason14.normalized_at,
    )
    if receipt_rows:
        if receipt_rows != [expected_receipt_row]:
            return incoherent("stored processing receipt differs from the plan")
        if normalized != expected_normalized:
            return incoherent("normalized projection differs from the receipt")
        if score.action != "reuse" or score.projection is None:
            return incoherent("assessment projection required by receipt is absent")
        receipt = parse_processing_receipt(plan.sealed_bytes)
        if (
            score.projection.score_payload_hash
            != plan.reason14.score_payload_hash
            or score.projection.created_at
            != receipt["assessment_projection"]["created_at"]
            or score.projection.updated_at
            != receipt["assessment_projection"]["updated_at"]
        ):
            return incoherent("assessment projection differs from the receipt")
        try:
            event = plan_processing_event(
                connection,
                profile_id=plan.facts.profile_id,
                job_key=plan.facts.job_key,
                event_type=EVENT_TYPE_PROCESSING_SCORE_ACCEPTED,
                actor_kind="deterministic",
                payload_json=plan.event_payload_json,
                idempotency_key=plan.idempotency_key,
                created_at=plan.accepted_at,
                event_id=plan.event_id,
            )
        except (ProjectionConflict, TypeError, ValueError) as exc:
            return incoherent(f"processing event differs from the receipt: {exc}")
        if (
            event.action != "reuse"
            or event.reused_event_id != plan.event_id
            or event_family.action != "existing"
            or event_family.count != 1
            or len(event_id_rows) != 1
        ):
            return incoherent("processing event cardinality differs from the receipt")
        return RecoveredTransactionClassification(
            RECOVERY_DURABLE_COMPLETE,
            plan.sealed_bytes,
            "exact receipt and projection graph recovered",
        )

    if plan.reason14.normalized_action == "insert":
        normalized_empty = normalized is None
    else:
        normalized_empty = normalized == expected_normalized
    if plan.reason14.score_plan.action == "insert":
        score_empty = score.action == "insert_required" and score.projection is None
    else:
        reuse = plan.reason14.score_plan.reuse
        score_empty = (
            type(reuse) is ScoreReusePlan
            and score.action == "reuse"
            and score.projection is not None
            and score.projection.score_payload_hash == reuse.score_payload_hash
            and score.projection.created_at == reuse.created_at
            and score.projection.updated_at == reuse.updated_at
        )
    event_empty = (
        event_family.action == "insert_required"
        and event_family.count == 0
        and event_id_rows == []
    )
    if normalized_empty and score_empty and event_empty:
        return RecoveredTransactionClassification(
            RECOVERY_DURABLE_EMPTY,
            None,
            "no operation-owned durable projection exists",
        )
    return incoherent("partial or substituted FIT projection graph exists")


def verify_recovered_connection(
    connection: sqlite3.Connection,
    plan: _ProspectivePlan,
) -> RecoveredTransactionClassification:
    """Verify one already-recovered, attached, caller-locked snapshot.

    The caller must own an active transaction on the exact retained main and
    vacancy databases.  This seam owns no connection, ATTACH, transaction,
    migration, journal-mode change, repair, or DML.  It proves exact aliases,
    quick checks, foreign-key checks, and repeats those database checks around
    the pure durable-graph classifier.  SQLite errors propagate for the outer
    stable mapper; malformed or inconsistent durable facts are
    ``recovery_incoherent``.
    """

    if getattr(connection, "in_transaction", False) is not True:
        raise ProcessingRefused(
            REASON_RECOVERY_INCOHERENT,
            "recovery verification requires an active caller-owned transaction",
        )

    def rows(sql: str) -> list[tuple[Any, ...]]:
        result = connection.execute(sql).fetchall()
        if type(result) is not list or any(type(row) is not tuple for row in result):
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                f"recovery query {sql!r} returned malformed rows",
            )
        return result

    def verify_databases() -> None:
        listed = rows("PRAGMA database_list")
        if len(listed) != 2:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                "recovery connection does not contain exactly two databases",
            )
        aliases: list[str] = []
        paths: list[str] = []
        for row in listed:
            if (
                len(row) != 3
                or type(row[0]) is not int
                or type(row[1]) is not str
                or type(row[2]) is not str
                or not row[2]
            ):
                raise ProcessingRefused(
                    REASON_RECOVERY_INCOHERENT,
                    f"recovery database_list row is malformed: {row!r}",
                )
            aliases.append(row[1])
            paths.append(row[2])
        if aliases != ["main", "vacancy"] or paths[0] == paths[1]:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                "recovery database aliases or paths are not exact and distinct",
            )
        for alias in aliases:
            quick = rows(f"PRAGMA {alias}.quick_check")
            if quick != [("ok",)]:
                raise ProcessingRefused(
                    REASON_RECOVERY_INCOHERENT,
                    f"{alias} quick_check did not return exact ok: {quick!r}",
                )
            foreign = rows(f"PRAGMA {alias}.foreign_key_check")
            if foreign != []:
                raise ProcessingRefused(
                    REASON_RECOVERY_INCOHERENT,
                    f"{alias} foreign_key_check found violations: {foreign!r}",
                )

    verify_databases()
    classification = classify_recovered_transaction(connection, plan)
    verify_databases()
    return classification


def _open_recovery_admission(
    data_home: Path,
    envelope_name: str,
    plan: _ProspectivePlan,
) -> _AdmissionLease:
    """Freshly bind the exact envelope/config/databases for recovery only.

    Recovery deliberately does not reopen mutable raw/profile/evidence
    authorities.  It re-admits the immutable processing envelope and live
    config/database identities, requires them to reconstruct the exact frozen
    transaction plan, and opens SQLite in recovery-tolerant mode while every
    pathname and inode descriptor remains retained.
    """

    if type(plan) is not _ProspectivePlan:
        raise ProcessingRefused(
            REASON_RECOVERY_INCOHERENT,
            "recovery requires the exact prospective transaction plan",
        )
    try:
        _assert_fully_immutable(plan, "recovery_plan")
    except TypeError as exc:
        raise ProcessingRefused(
            REASON_RECOVERY_INCOHERENT,
            f"recovery plan is mutable: {exc}",
        ) from exc
    _validate_supplied_process_identity(
        envelope_name=envelope_name,
        supplied_operation_id=plan.facts.operation_id,
        supplied_config_path=plan.facts.config_source_path,
        supplied_profile_id=plan.facts.profile_id,
        supplied_job_key=plan.facts.job_key,
        supplied_track=plan.facts.track,
    )
    try:
        descriptors, payload, file_sha, _semantic = load_envelope_authority(
            data_home, envelope_name
        )
    except ProcessingRefused:
        raise
    except (ValueError, KeyError, TypeError) as exc:
        raise ProcessingRefused(
            REASON_RECOVERY_INCOHERENT,
            f"recovery envelope could not be reconstructed: {exc}",
        ) from exc
    lease = _AdmissionLease(descriptors)
    try:
        facts = compose_envelope_facts(
            payload,
            envelope_file_sha256=file_sha,
            expected_assessments_path=None,
            expected_vacancy_path=None,
        )
        if facts != plan.facts:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                "recovery envelope facts differ from the attempted transaction",
            )
        admission = admit_config_and_databases(data_home, facts, descriptors)
        _binding, binding_sha256 = build_processing_binding_from_facts(facts)
        if binding_sha256 != plan.binding_sha256:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                "recovery binding differs from the attempted transaction",
            )
        lease.bind(admission, facts, binding_sha256)
        lease.revalidate_chain()
        lease.open_view(allow_database_size_change=True)
        lease.revalidate_chain(allow_database_size_change=True)
        return lease
    except BaseException:
        lease.close()
        raise


def _require_clean_recovery_epoch(facts: _FilesystemEpochFacts) -> None:
    """Require SQLite-clean rollback-journal disposition after recovery."""

    clean_noncandidate_databases = frozenset(
        journal.database
        for journal in facts.journals
        if journal.state == "noncandidate"
    )
    remaining_sidecars = tuple(
        observation
        for observation in facts.sidecars
        if observation.present
        and not (
            observation.suffix == "-journal"
            and observation.database in clean_noncandidate_databases
        )
    )
    remaining_journals = tuple(
        journal for journal in facts.journals if journal.state == "candidate"
    )
    master_remains = (
        facts.master.state != "none"
        or facts.master.path is not None
        or facts.master.size is not None
        or facts.master.entries != ()
        or facts.master.content != b""
        or facts.master_identity is not None
    )
    if remaining_sidecars or remaining_journals or master_remains:
        raise ProcessingRefused(
            REASON_RECOVERY_INCOHERENT,
            "SQLite recovery artifacts remain after the defined recovery step: "
            f"sidecars={remaining_sidecars!r}, journals={remaining_journals!r}, "
            f"master={facts.master!r}",
        )


def recover_process_one_durable_truth(
    data_home: Path,
    envelope_name: str,
    plan: _ProspectivePlan,
) -> RecoveredTransactionClassification:
    """Reopen SQLite and classify one attempted FIT transaction durably.

    The caller must still hold the outer process-one serialization scope and
    must have closed the original admission lease first.  This function owns
    one fresh retained admission lease and one attached SQLite connection.  It
    permits SQLite's legitimate rollback-journal recovery, locks one exact
    attached snapshot, runs integrity/FK and durable-graph verification twice,
    rebases only recovered byte sizes, proves a clean journal epoch, and
    returns exact complete/empty truth.  It performs no application DDL/DML
    and never reopens current raw/profile/evidence authorities.
    """

    lease: _AdmissionLease | None = None
    primary: BaseException | None = None
    classification: RecoveredTransactionClassification | None = None
    try:
        lease = _open_recovery_admission(data_home, envelope_name, plan)
        connection = lease.connection
        assessments = lease.assessments
        vacancy = lease.vacancy
        assert connection is not None
        assert assessments is not None and vacancy is not None
        _maybe_fault("after_recovery_open")

        connection.execute("PRAGMA query_only=OFF")
        if connection.execute("PRAGMA query_only").fetchall() != [(0,)]:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                "recovery connection did not leave query-only mode",
            )
        connection.execute("PRAGMA foreign_keys=ON")
        if connection.execute("PRAGMA foreign_keys").fetchall() != [(1,)]:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                "recovery connection did not enable foreign keys",
            )
        connection.execute("PRAGMA busy_timeout=30000")
        if connection.execute("PRAGMA busy_timeout").fetchall() != [(30000,)]:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                "recovery connection did not install the fixed busy timeout",
            )
        for alias in ("main", "vacancy"):
            if connection.execute(
                f"PRAGMA {alias}.journal_mode"
            ).fetchall() != [("delete",)]:
                raise ProcessingRefused(
                    REASON_RECOVERY_INCOHERENT,
                    f"{alias} recovery journal mode is not exact delete",
                )
            connection.execute(f"PRAGMA {alias}.synchronous=FULL")
            if connection.execute(
                f"PRAGMA {alias}.synchronous"
            ).fetchall() != [(2,)]:
                raise ProcessingRefused(
                    REASON_RECOVERY_INCOHERENT,
                    f"{alias} recovery synchronous mode is not exact FULL",
                )

        _verify_transaction_connection(
            connection,
            lease.descriptors,
            assessments,
            vacancy,
            allow_database_size_change=True,
        )
        connection.execute("BEGIN IMMEDIATE")
        _maybe_fault("after_recovery_begin")
        _verify_transaction_connection(
            connection,
            lease.descriptors,
            assessments,
            vacancy,
            allow_database_size_change=True,
        )
        first = verify_recovered_connection(connection, plan)
        _maybe_fault("after_recovery_first_verify")
        assessments.accept_recovered_size()
        vacancy.accept_recovered_size()
        _verify_transaction_connection(
            connection,
            lease.descriptors,
            assessments,
            vacancy,
        )
        _require_clean_recovery_epoch(
            _stabilize_filesystem_epoch(
                lease.descriptors, assessments, vacancy
            )
        )
        _maybe_fault("before_recovery_second_verify")
        second = verify_recovered_connection(connection, plan)
        _maybe_fault("after_recovery_second_verify")
        if second != first:
            raise ProcessingRefused(
                REASON_RECOVERY_INCOHERENT,
                "durable transaction classification changed inside one snapshot",
            )
        connection.rollback()
        _maybe_fault("after_recovery_rollback")
        _verify_transaction_connection(
            connection,
            lease.descriptors,
            assessments,
            vacancy,
        )
        _require_clean_recovery_epoch(
            _stabilize_filesystem_epoch(
                lease.descriptors, assessments, vacancy
            )
        )
        classification = second
    except (KeyboardInterrupt, _Interrupted) as exc:
        primary = ProcessingRefused(
            REASON_INTERRUPTED, "recovery verification was interrupted"
        )
        primary.__cause__ = exc
    except sqlite3.Error as exc:
        primary = map_sqlite_read_error(exc)
        primary.__cause__ = exc
    except ProcessingRefused as exc:
        primary = exc
    except (OSError, ValueError, TypeError) as exc:
        primary = ProcessingRefused(
            REASON_RECOVERY_INCOHERENT,
            f"recovery verification is incoherent: {exc}",
        )
        primary.__cause__ = exc
    except Exception as exc:
        primary = ProcessingRefused(
            REASON_RECOVERY_INCOHERENT,
            f"recovery verification failed unexpectedly: {exc}",
        )
        primary.__cause__ = exc
    finally:
        if lease is not None:
            connection = lease.connection
            if connection is not None and connection.in_transaction:
                try:
                    connection.rollback()
                except sqlite3.Error as exc:
                    if primary is None:
                        primary = ProcessingRefused(
                            REASON_RECOVERY_INCOHERENT,
                            f"recovery rollback outcome is ambiguous: {exc}",
                        )
            lease.close()
    if primary is not None:
        raise primary
    assert classification is not None
    return classification


# ==========================================================================
# Part-3C C2 Increment 4: retained-authority transaction coordinator.
# ==========================================================================

_REASON14_PREFLIGHT_TIMESTAMP = "1970-01-01T00:00:00.000000Z"


def _reason14_plan_from_view(
    connection: sqlite3.Connection,
    view: SemanticAdmissionView,
    facts: EnvelopeFacts,
    *,
    accepted_at: str,
) -> _Reason14Plan:
    """Plan reason 14 from the exact immutable semantic-admission output."""

    try:
        normalized_json = view.normalized_vacancy_bytes.decode("utf-8")
        normalized = strict_json_loads(normalized_json)
        if type(normalized) is not dict:
            raise ValueError("normalized vacancy must decode to an object")
        url = normalized["url"]
        title = normalized["title"]
        company = normalized["company"]
        extraction_confidence = normalized["extraction_confidence"]
        if any(type(value) is not str for value in (url, title, company)):
            raise ValueError("normalized vacancy text identities are malformed")
        if extraction_confidence is not None and type(
            extraction_confidence
        ) is not float:
            raise ValueError("normalized extraction_confidence is malformed")
    except (KeyError, TypeError, UnicodeDecodeError, ValueError) as exc:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            f"normalized vacancy cannot feed reason 14: {exc}",
        ) from exc
    return plan_reason14_projections(
        connection,
        result_obj=result_from_staged(facts),
        url=url,
        title=title,
        company=company,
        extraction_confidence=extraction_confidence,
        job_key=facts.job_key,
        profile_id=facts.profile_id,
        normalized_json=normalized_json,
        normalized_json_sha256=view.normalized_json_sha256,
        accepted_at=accepted_at,
    )


def _assert_reason14_replan_equivalent(
    preflight: _Reason14Plan,
    transaction: _Reason14Plan,
    *,
    accepted_at: str,
) -> None:
    """Allow only the contracted absent-row timestamp to change at BEGIN."""

    if type(preflight) is not _Reason14Plan or type(transaction) is not _Reason14Plan:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "reason-14 replanning returned a noncanonical plan",
        )
    stable_fields = (
        "normalized_action",
        "normalized_json",
        "normalized_json_sha256",
        "score_payload_hash",
        "event_action",
        "url",
        "title",
        "company",
        "extraction_confidence",
    )
    for field in stable_fields:
        if getattr(preflight, field) != getattr(transaction, field):
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                f"reason-14 {field} changed between preflight and transaction",
            )
    if preflight.normalized_action == "reuse":
        if preflight.normalized_at != transaction.normalized_at:
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                "reused normalized timestamp changed during replanning",
            )
    elif (
        preflight.normalized_action != "insert"
        or preflight.normalized_at != _REASON14_PREFLIGHT_TIMESTAMP
        or transaction.normalized_at != accepted_at
    ):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "insert normalized timestamp transition is not contracted",
        )
    if preflight.score_plan.action != transaction.score_plan.action:
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "score projection action changed during replanning",
        )
    if preflight.score_plan.action == "reuse":
        if preflight.score_plan != transaction.score_plan:
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                "reused score projection changed during replanning",
            )
        return
    pre_insert = preflight.score_plan.insert
    tx_insert = transaction.score_plan.insert
    if (
        preflight.score_plan.action != "insert"
        or type(pre_insert) is not ScoreInsertPlan
        or type(tx_insert) is not ScoreInsertPlan
        or preflight.score_plan.reuse is not None
        or transaction.score_plan.reuse is not None
        or pre_insert.created_at != _REASON14_PREFLIGHT_TIMESTAMP
        or tx_insert.created_at != accepted_at
        or dataclasses.replace(pre_insert, created_at=accepted_at) != tx_insert
    ):
        raise ProcessingRefused(
            REASON_PROJECTION_CONFLICT,
            "insert score projection changed beyond accepted_at",
        )


def _revalidate_semantic_transaction_authority(
    data_home: Path,
    view: SemanticAdmissionView,
    *,
    allow_database_size_change: bool,
) -> None:
    """Recheck config, SQLite identity, raw posting, and profile generation."""

    lease = object.__getattribute__(view, "_lease")
    snapshot = object.__getattribute__(view, "_snapshot")
    facts = lease.facts
    assert facts is not None
    assert lease.connection is not None
    assert lease.assessments is not None and lease.vacancy is not None
    _verify_live_config_binding(data_home, facts)
    _verify_transaction_connection(
        lease.connection,
        lease.descriptors,
        lease.assessments,
        lease.vacancy,
        allow_database_size_change=allow_database_size_change,
    )
    lease.revalidate_raw(
        allow_database_size_change=allow_database_size_change
    )
    try:
        snapshot.revalidate()
    except ProcessingRefused:
        raise
    except (ValueError, OSError) as exc:
        raise _profile_authority_refused(exc) from exc


def _commit_process_one(
    data_home: Path,
    view: SemanticAdmissionView,
    facts: EnvelopeFacts,
    connection: sqlite3.Connection,
    lease: _AdmissionLease,
    preflight_reason14: _Reason14Plan,
    recovery_plan_out: list[_ProspectivePlan] | None = None,
) -> bytes:
    """Serialize setup and apply one exact new-operation transaction."""

    assert lease.assessments is not None and lease.vacancy is not None
    _revalidate_semantic_transaction_authority(
        data_home,
        view,
        allow_database_size_change=False,
    )
    locked_replay = _classify_replay(
        connection,
        facts,
        lease.binding_sha256 or "",
        lease.descriptors,
        lease.assessments,
        lease.vacancy,
        allow_sidecar_parent_nlink_churn=True,
    )
    if locked_replay.disposition == DISPOSITION_EXACT_REPLAY:
        assert locked_replay.stored_receipt_bytes is not None
        return locked_replay.stored_receipt_bytes
    if locked_replay.disposition == DISPOSITION_EXISTING_RECEIPT_MISMATCH:
        raise ProcessingRefused(
            REASON_EXISTING_RECEIPT,
            locked_replay.detail,
        )
    connection.execute("PRAGMA query_only=OFF")
    query_only = connection.execute("PRAGMA query_only").fetchall()
    if query_only != [(0,)]:
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"query_only did not switch off exactly: {query_only!r}",
        )
    setup_transaction_sqlite(connection)
    _revalidate_semantic_transaction_authority(
        data_home,
        view,
        allow_database_size_change=True,
    )
    _maybe_fault("before_process_one_begin")
    connection.execute("BEGIN IMMEDIATE")
    try:
        _maybe_fault("after_process_one_begin")
        in_transaction = _classify_replay(
            connection,
            facts,
            lease.binding_sha256 or "",
            lease.descriptors,
            lease.assessments,
            lease.vacancy,
            allow_sidecar_parent_nlink_churn=True,
            allow_database_size_change=True,
        )
        if in_transaction.disposition == DISPOSITION_EXACT_REPLAY:
            assert in_transaction.stored_receipt_bytes is not None
            connection.rollback()
            return in_transaction.stored_receipt_bytes
        if in_transaction.disposition == DISPOSITION_EXISTING_RECEIPT_MISMATCH:
            raise ProcessingRefused(
                REASON_EXISTING_RECEIPT,
                in_transaction.detail,
            )
        if in_transaction.disposition not in {
            DISPOSITION_DEFINITIVE_ABSENCE,
            DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY,
        }:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"transaction replay state is invalid: {in_transaction.detail}",
            )
        _revalidate_semantic_transaction_authority(
            data_home,
            view,
            allow_database_size_change=True,
        )
        _maybe_fault("after_process_one_transaction_recheck")
        accepted_at = datetime.now(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        transaction_reason14 = _reason14_plan_from_view(
            connection,
            view,
            facts,
            accepted_at=accepted_at,
        )
        _assert_reason14_replan_equivalent(
            preflight_reason14,
            transaction_reason14,
            accepted_at=accepted_at,
        )
        prospective = build_prospective_plan(
            facts=facts,
            reason14=transaction_reason14,
            accepted_at=accepted_at,
            prospective_event_id=_prospective_event_id(connection),
        )
        if recovery_plan_out is not None:
            if recovery_plan_out:
                raise RuntimeError("recovery plan output was already populated")
            recovery_plan_out.append(prospective)
        outcome = apply_transaction_plan(connection, prospective)
        if outcome.sealed_bytes != prospective.sealed_bytes:
            raise ProcessingRefused(
                REASON_PROJECTION_CONFLICT,
                "transaction outcome bytes differ from the prospective receipt",
            )
        _revalidate_semantic_transaction_authority(
            data_home,
            view,
            allow_database_size_change=True,
        )
        _maybe_fault("before_process_one_commit")
        connection.commit()
        _maybe_fault("after_process_one_commit")
        return outcome.sealed_bytes
    except BaseException:
        if connection.in_transaction:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
        raise


@contextlib.contextmanager
def _process_one_serialization_scope(data_home: Path) -> Iterator[None]:
    """Hold the one process-one mutex before any admission authority opens.

    The canonical config owner retains the data-home chain.  This scope opens
    only its direct ``state`` child and binds the directory's stable
    dev/inode/owner/mode identity; directory link count is deliberately not a
    security identity because SQLite creates and removes sidecars there and
    APFS reflects that in ``st_nlink``.  A process-global cooperating lock is
    held for thread exclusion and ``flock`` on the retained state descriptor
    provides cross-process exclusion.  Nothing is created.
    """

    thread_lock = owner_private_lock()
    thread_lock.acquire()
    chain = None
    state_fd = -1
    file_locked = False
    try:
        try:
            chain = open_existing_private_data_root(str(data_home))
            root_fd = chain.deepest_fd
            named = os.stat("state", dir_fd=root_fd, follow_symlinks=False)
            _require_private_dir(named, "process-one state directory")
            state_fd = os.open(
                "state",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
            opened = os.fstat(state_fd)
            _require_private_dir(opened, "retained process-one state directory")
            stable_identity = (
                opened.st_dev,
                opened.st_ino,
                opened.st_uid,
                stat.S_IMODE(opened.st_mode),
            )
            named_identity = (
                named.st_dev,
                named.st_ino,
                named.st_uid,
                stat.S_IMODE(named.st_mode),
            )
            if stable_identity != named_identity:
                raise ValueError(
                    "process-one state directory was substituted during open"
                )
        except (OSError, ValueError) as exc:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE,
                f"process-one serialization authority refused: {exc}",
            ) from exc
        try:
            fcntl.flock(state_fd, fcntl.LOCK_EX)
            file_locked = True
        except OSError as exc:
            raise ProcessingRefused(
                REASON_ATOMIC_MODE,
                f"process-one serialization lock failed: {exc}",
            ) from exc
        try:
            chain.revalidate()
            reopened = os.fstat(state_fd)
            renamed = os.stat("state", dir_fd=chain.deepest_fd, follow_symlinks=False)
            _require_private_dir(reopened, "retained process-one state directory")
            _require_private_dir(renamed, "process-one state directory name")
            if (
                reopened.st_dev,
                reopened.st_ino,
                reopened.st_uid,
                stat.S_IMODE(reopened.st_mode),
            ) != stable_identity or (
                renamed.st_dev,
                renamed.st_ino,
                renamed.st_uid,
                stat.S_IMODE(renamed.st_mode),
            ) != stable_identity:
                raise ProcessingRefused(
                    REASON_CONFIG_DATABASE,
                    "process-one state directory changed while waiting for its lock",
                )
        except ProcessingRefused:
            raise
        except (OSError, ValueError) as exc:
            raise ProcessingRefused(
                REASON_CONFIG_DATABASE,
                f"process-one serialization authority drifted: {exc}",
            ) from exc
        yield
    finally:
        if file_locked and state_fd >= 0:
            with contextlib.suppress(OSError):
                fcntl.flock(state_fd, fcntl.LOCK_UN)
        if state_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(state_fd)
        if chain is not None:
            chain.close()
        thread_lock.release()


def _process_one_under_scope(
    data_home: Path,
    envelope_name: str,
    *,
    supplied_operation_id: str,
    supplied_config_path: str,
    supplied_profile_id: str,
    supplied_job_key: str,
    supplied_track: str,
) -> bytes:
    """Run one provider-free FIT operation and return exact stored bytes.

    This is the sole public deterministic processing path.  Any failure after
    the exact prospective plan exists closes the original authorities and is
    resolved only by the fresh durable-truth recovery verifier.
    """

    common: _CommonReplay | None = None
    lease: _AdmissionLease | None = None
    view: SemanticAdmissionView | None = None
    recovery_plan_out: list[_ProspectivePlan] = []
    result: bytes | None = None
    caught: BaseException | None = None
    try:
        common = _reasons_one_to_six(
            data_home,
            envelope_name,
            supplied_operation_id=supplied_operation_id,
            supplied_config_path=supplied_config_path,
            supplied_profile_id=supplied_profile_id,
            supplied_job_key=supplied_job_key,
            supplied_track=supplied_track,
        )
        lease = common.lease
        classification = common.classification
        if classification.disposition == DISPOSITION_EXACT_REPLAY:
            assert classification.stored_receipt_bytes is not None
            result = classification.stored_receipt_bytes
        else:
            if (
                classification.disposition
                == DISPOSITION_EXISTING_RECEIPT_MISMATCH
            ):
                raise ProcessingRefused(
                    REASON_EXISTING_RECEIPT,
                    classification.detail,
                )
            if (
                classification.disposition
                == DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY
            ):
                lease.provisional_detail = classification.detail

            lease.admit_raw_snapshot()
            view = _admit_semantic_continuation(data_home, lease)
            facts = lease.facts
            connection = lease.connection
            assert facts is not None and connection is not None
            assert lease.assessments is not None and lease.vacancy is not None

            preflight_reason14 = _reason14_plan_from_view(
                connection,
                view,
                facts,
                accepted_at=_REASON14_PREFLIGHT_TIMESTAMP,
            )
            if view.provisional_detail is not None:
                raise ProcessingRefused(
                    REASON_ATOMIC_MODE,
                    view.provisional_detail,
                )

            result = _commit_process_one(
                data_home,
                view,
                facts,
                connection,
                lease,
                preflight_reason14,
                recovery_plan_out,
            )
    except BaseException as exc:
        caught = exc
    finally:
        cleanup_error: BaseException | None = None
        try:
            if view is not None:
                object.__getattribute__(view, "_release")()
        except BaseException as exc:
            cleanup_error = exc
        finally:
            try:
                if lease is not None:
                    lease.close()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if caught is None and cleanup_error is not None:
            caught = cleanup_error

    if caught is None:
        assert result is not None
        return result
    if isinstance(caught, (SystemExit, GeneratorExit)):
        raise caught
    if not recovery_plan_out:
        if isinstance(caught, ProcessingRefused):
            raise caught
        if isinstance(caught, (KeyboardInterrupt, _Interrupted)):
            raise ProcessingRefused(
                REASON_INTERRUPTED, "process-one admission was interrupted"
            ) from caught
        if isinstance(caught, sqlite3.Error):
            raise map_sqlite_read_error(caught) from caught
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"process-one failed before any prospective write plan: {caught}",
        ) from caught
    recovered = recover_process_one_durable_truth(
        data_home, envelope_name, recovery_plan_out[0]
    )
    if recovered.disposition == RECOVERY_DURABLE_COMPLETE:
        assert recovered.stored_receipt_bytes is not None
        return recovered.stored_receipt_bytes
    if recovered.disposition == RECOVERY_DURABLE_INCOHERENT:
        raise ProcessingRefused(
            REASON_RECOVERY_INCOHERENT,
            recovered.detail,
        ) from caught
    if recovered.disposition != RECOVERY_DURABLE_EMPTY:
        raise ProcessingRefused(
            REASON_RECOVERY_INCOHERENT,
            f"recovery returned unknown disposition {recovered.disposition!r}",
        ) from caught
    if isinstance(caught, ProcessingRefused):
        raise caught
    if isinstance(caught, (KeyboardInterrupt, _Interrupted)):
        raise ProcessingRefused(
            REASON_INTERRUPTED, "process-one transaction was interrupted"
        ) from caught
    if isinstance(caught, sqlite3.Error):
        raise map_sqlite_read_error(caught) from caught
    raise ProcessingRefused(
        REASON_ATOMIC_MODE,
        f"process-one transaction failed before durable commit: {caught}",
    ) from caught


def process_one(
    data_home: Path,
    envelope_name: str,
    *,
    supplied_operation_id: str,
    supplied_config_path: str,
    supplied_profile_id: str,
    supplied_job_key: str,
    supplied_track: str,
) -> bytes:
    """Run one serialized provider-free FIT operation, returning exact bytes."""

    _validate_supplied_process_identity(
        envelope_name=envelope_name,
        supplied_operation_id=supplied_operation_id,
        supplied_config_path=supplied_config_path,
        supplied_profile_id=supplied_profile_id,
        supplied_job_key=supplied_job_key,
        supplied_track=supplied_track,
    )
    with _process_one_serialization_scope(data_home):
        return _process_one_under_scope(
            data_home,
            envelope_name,
            supplied_operation_id=supplied_operation_id,
            supplied_config_path=supplied_config_path,
            supplied_profile_id=supplied_profile_id,
            supplied_job_key=supplied_job_key,
            supplied_track=supplied_track,
        )


# ==========================================================================
# ELIGIBILITY-001: evidence-bound eligibility decision admission.
#
# Authority: docs/eligibility/
# ELIGIBILITY-001_EVIDENCE_BOUND_DECISION_CONTRACT.md
# (accepted, SHA-256 cea1b0f8b024d1322cf5a9eff52cfb2938cf68608b30ae7da38ef35e
# d529d349).  One public deterministic provider-free path: eligibility_one().
# Every frozen constant below is embedded verbatim from the accepted contract.
# ==========================================================================

ELIGIBILITY_ENVELOPE_SCHEMA_VERSION = "market-aligner.eligibility-envelope.v1"
ELIGIBILITY_BINDING_SCHEMA_VERSION = "market-aligner.eligibility-binding.v1"
ELIGIBILITY_EVENT_SCHEMA_VERSION = "market-aligner.eligibility-decided-event.v1"
ELIGIBILITY_RECEIPT_SCHEMA_VERSION = "market-aligner.eligibility-receipt.v1"
EVENT_TYPE_ELIGIBILITY_DECIDED = "eligibility_decided"

MAX_ELIGIBILITY_ENVELOPE_BYTES = 1_048_576
MAX_ELIGIBILITY_RECEIPT_BYTES = 8_388_608
MAX_ELIGIBILITY_JSON_NODES = 10_000
MAX_ELIGIBILITY_JSON_DEPTH = 32

ISO_JURISDICTION_SET_SHA256 = (
    "bad3b0ab6d1073f237d176df4d3ec9297269c1c13c73f714c0736a87912b1523")
CONTRACT_TYPE_ENUM_SHA256 = (
    "8deddcbc79b7fbe7bd577e5a13c39d4a2ee20419fa33e023cb31eccf46f33ff2")
ELIGIBILITY_DECISION_POLICY_SHA256 = (
    "12dbb06cc16277aed00007f46eaf132fa54fb89cf211c53c7283e48c06bcb581")
ELIGIBILITY_DECISION_POLICY_BODY = json.dumps(
    {
        "application_authority": False,
        "decision_tokens": ["pass", "review", "reject"],
        "iso_jurisdiction_set_sha256": ISO_JURISDICTION_SET_SHA256,
        "release_authority": False,
        "research_authority": False,
        "schema_version":
            "market-aligner.eligibility001-fixed-decision-policy.v1",
        "submission_authority": False,
    },
    ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
assert len(ELIGIBILITY_DECISION_POLICY_BODY.encode("utf-8")) == 329
assert hashlib.sha256(
    ELIGIBILITY_DECISION_POLICY_BODY.encode("utf-8")).hexdigest() == \
    ELIGIBILITY_DECISION_POLICY_SHA256

_ISO_MEMBER_CODES = (
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ "
    "BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ "
    "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ "
    "DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR "
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY "
    "HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP "
    "KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY "
    "MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ "
    "NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS "
    "PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR "
    "SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ "
    "UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW").split()
_ISO_JURISDICTIONS = frozenset(_ISO_MEMBER_CODES)
assert len(_ISO_JURISDICTIONS) == 249
assert hashlib.sha256(json.dumps(
    sorted(_ISO_JURISDICTIONS), separators=(",", ":")).encode()).hexdigest() \
    == ISO_JURISDICTION_SET_SHA256

_CONTRACT_TYPES = frozenset((
    "apprenticeship", "contract", "freelance", "full_time", "internship",
    "part_time", "permanent", "temporary"))
assert hashlib.sha256(json.dumps(
    sorted(_CONTRACT_TYPES), separators=(",", ":")).encode()).hexdigest() == \
    CONTRACT_TYPE_ENUM_SHA256

MAX_CANDIDATE_REF_BYTES = 2359
MAX_TOTAL_CANDIDATE_REFS = 256
MAX_AUTHORISED_JURISDICTIONS = 249
MAX_EXCLUDED_CONTRACT_TYPES = 8

ELIGIBILITY_REASON_OPERATION_ID = "invalid_operation_id"
ELIGIBILITY_REASON_ENVELOPE_PATH = "unsafe_eligibility_envelope_path"
ELIGIBILITY_REASON_ENVELOPE_BYTES = "invalid_eligibility_envelope_bytes"
ELIGIBILITY_REASON_CLI_IDENTITY = "binding_cli_identity"
ELIGIBILITY_REASON_CONFIG_DATABASE = "binding_config_database"
ELIGIBILITY_REASON_EXISTING_RECEIPT = "binding_eligibility_receipt"
ELIGIBILITY_REASON_FIT_RECEIPT = "binding_fit_receipt"
ELIGIBILITY_REASON_CANDIDATE_EVIDENCE = "binding_candidate_evidence_context"
ELIGIBILITY_REASON_VACANCY_FACTS = "binding_vacancy_facts"
ELIGIBILITY_REASON_POLICY = "binding_eligibility_policy"
ELIGIBILITY_REASON_DECISION_RECONSTRUCTION = "binding_decision_reconstruction"
ELIGIBILITY_REASON_TARGET_CONFLICT = "eligibility_target_conflict"

_ELIGIBILITY_ENVELOPE_TOP_LEVEL_KEYS = {
    "schema_version", "eligibility_operation_id", "fit_operation_id",
    "job_key", "profile_id", "profile_version", "track",
    "fit_receipt_self_hash", "fit_receipt_file_sha256", "decision_policy",
    "config", "databases", "candidate_facts", "vacancy_facts"}
_CANDIDATE_REF_KEYS = {"evidence_id", "kind", "status", "claim_sha256",
                       "source_ref_sha256", "content_sha256"}
_CANDIDATE_FACTS_KEYS = {"authorised_jurisdictions", "current_residence",
                         "requires_sponsorship", "maximum_years_required",
                         "excluded_contract_types"}
_SELECTOR_KEYS = {"extraction_field", "item_index", "selected_type",
                  "selected_value", "selected_value_sha256"}
_VACANCY_FACTS_KEYS = {"work_jurisdiction", "required_residence",
                       "sponsorship_available", "minimum_years_required",
                       "contract_type"}
_ELIGIBILITY_BINDING_KEYS = {
    "schema_version", "operation_id", "fit_operation_id", "job_key",
    "profile_id", "profile_version", "track", "envelope_file_sha256",
    "envelope_semantic_sha256", "fit_receipt_self_hash",
    "fit_receipt_file_sha256", "decision_policy_sha256", "config",
    "databases", "candidate_facts", "vacancy_facts"}
_ELIGIBILITY_DECISION_INPUT_KEYS = {
    "authorised_jurisdictions", "contract_type", "current_residence",
    "excluded_contract_types", "maximum_years_required",
    "minimum_years_experience", "requires_sponsorship", "required_residence",
    "sponsorship_available", "work_jurisdiction"}
_ELIGIBILITY_EVENT_PAYLOAD_KEYS = {
    "schema_version", "operation_id", "fit_operation_id", "profile_id",
    "job_key", "track", "binding_sha256", "envelope_file_sha256",
    "fit_receipt_self_hash", "fit_receipt_file_sha256",
    "fit_assessment_event_id", "fit_event_payload_sha256",
    "fit_normalized_json_sha256", "candidate_facts_sha256",
    "vacancy_facts_sha256", "decision_policy_sha256",
    "decision_input_sha256", "iso_jurisdiction_set_sha256", "decision",
    "reasons", "unknowns"}
assert len(_ELIGIBILITY_EVENT_PAYLOAD_KEYS) == 21
_ELIGIBILITY_EVENT_NODE_KEYS = {"id", "event_type", "actor_kind",
                                "payload_sha256", "idempotency_key",
                                "created_at"}
_ELIGIBILITY_RECEIPT_TOP_LEVEL_KEYS = {
    "schema_version", "operation_id", "fit_operation_id", "job_key",
    "profile_id", "profile_version", "track", "binding_sha256",
    "envelope_file_sha256", "envelope_semantic_sha256", "config", "databases",
    "fit_receipt", "fit_receipt_self_hash", "fit_receipt_file_sha256",
    "fit_binding_sha256", "fit_assessment_event_id",
    "fit_event_payload_sha256", "fit_raw_snapshot_sha256",
    "fit_profile_context_sha256", "fit_extraction_output_sha256",
    "fit_alignment_output_sha256", "fit_normalized_json_sha256",
    "fit_assessment_payload_hash", "candidate_facts", "vacancy_facts",
    "candidate_facts_sha256", "vacancy_facts_sha256",
    "decision_policy_sha256", "decision_input_sha256",
    "iso_jurisdiction_set_sha256", "decision_input", "decision", "reasons",
    "unknowns", "eligibility_event", "created_at", "time_authenticated",
    "imported_model_policy_authenticated", "imported_time_authenticated",
    "research_authority", "application_authority", "release_authority",
    "submission_authority", "eligibility_authority", "self_hash"}
assert len(_ELIGIBILITY_RECEIPT_TOP_LEVEL_KEYS) == 46
_ELIGIBILITY_FALSE_FLAGS = (
    "time_authenticated", "imported_model_policy_authenticated",
    "imported_time_authenticated", "research_authority",
    "application_authority", "release_authority", "submission_authority")
_FIT_SCALAR_PROJECTIONS = (
    ("fit_binding_sha256", ("binding_sha256",)),
    ("fit_event_payload_sha256", ("assessment_event", "payload_sha256")),
    ("fit_raw_snapshot_sha256", ("raw", "raw_snapshot_sha256")),
    ("fit_profile_context_sha256", ("profile", "profile_context_sha256")),
    ("fit_extraction_output_sha256", ("extraction", "receipt", "output_sha256")),
    ("fit_alignment_output_sha256", ("alignment", "receipt", "output_sha256")),
    ("fit_normalized_json_sha256",
     ("normalised_projection", "normalized_json_sha256")),
    ("fit_assessment_payload_hash",
     ("assessment_projection", "score_payload_hash")))


def _is_blank_character(character: str) -> bool:
    if character in " \t\n\v\f\r":
        return True
    import unicodedata
    return unicodedata.category(character) == "Zs"


def _is_nonblank(text: str) -> bool:
    return any(not _is_blank_character(ch) for ch in text)


def _require_iso_member(value: Any, label: str) -> str:
    if not isinstance(value, str) or value not in _ISO_JURISDICTIONS:
        raise ValueError(f"{label} must be an exact uppercase ISO-3166-1 "
                         "alpha-2 member")
    return value


def _require_enum_member(value: Any, label: str) -> str:
    if not isinstance(value, str) or value not in _CONTRACT_TYPES:
        raise ValueError(f"{label} must be an exact lowercase contract-type "
                         "enum member")
    return value


def _validate_candidate_ref(node: Any, seen_ids: set[str],
                            label: str) -> dict[str, Any]:
    ref = exact_keys(node, _CANDIDATE_REF_KEYS, label)
    evidence_id = plain_string(ref["evidence_id"], f"{label}.evidence_id",
                               1, 256)
    if evidence_id in seen_ids:
        raise ValueError(f"{label}.evidence_id duplicates an earlier id in "
                         "its refs array")
    seen_ids.add(evidence_id)
    plain_string(ref["kind"], f"{label}.kind", 1, 256)
    status = plain_string(ref["status"], f"{label}.status", 1, 32)
    if status not in ("verified", "explicit", "inference",
                      "unverified_current"):
        raise ValueError(f"{label}.status is not a committed evidence status")
    sha256_value(ref["claim_sha256"], f"{label}.claim_sha256")
    sha256_value(ref["source_ref_sha256"], f"{label}.source_ref_sha256")
    if not isinstance(ref["content_sha256"], str):
        raise ValueError(f"{label}.content_sha256 is required (never null)")
    sha256_value(ref["content_sha256"], f"{label}.content_sha256")
    canonical = canonical_json(ref).encode("utf-8")
    if len(canonical) > MAX_CANDIDATE_REF_BYTES:
        raise ValueError(f"{label} serializes to {len(canonical)} bytes; "
                         f"maximum is {MAX_CANDIDATE_REF_BYTES}")
    return ref


def _refs_array(node: dict[str, Any], label: str) -> list[Any]:
    refs = node.get("refs")
    if not isinstance(refs, list) or not refs:
        raise ValueError(f"{label}.refs must be a nonempty array of exact "
                         "CandidateEvidenceRef objects")
    return refs


def _refs_gate(refs: list[Any]) -> bool:
    return all(ref["status"] in ("verified", "explicit") for ref in refs)


class _CandidateRefBudget:
    """Global ref-count budget; evidence_id uniqueness stays PER ARRAY."""

    def __init__(self) -> None:
        self._count = 0

    def take(self, raw_refs: list[Any], label: str) -> list[dict[str, Any]]:
        seen_in_array: set[str] = set()
        parsed: list[dict[str, Any]] = []
        for i, ref in enumerate(raw_refs):
            parsed.append(_validate_candidate_ref(
                ref, seen_in_array, f"{label}[{i}]"))
        self._count += len(parsed)
        if self._count > MAX_TOTAL_CANDIDATE_REFS:
            raise ValueError("candidate_facts exceed the total ref budget")
        return parsed


@dataclasses.dataclass(frozen=True)
class CandidateFactsAdmission:
    staged_canonical: bytes
    effective: dict[str, Any]
    status_downgraded: bool


def admit_candidate_facts(payload: Any) -> CandidateFactsAdmission:
    """Validate staged candidate facts and derive the effective decision view.

    Scalar facts use the whole-fact status rule; array facts are
    ALL-OR-NOTHING across their outer refs AND every member ref.  A downgrade
    yields UNKNOWN (JSON null downstream), never an empty array, and adds
    exactly one ``candidate_evidence_status_unverified`` token after dedup.
    """
    node = exact_keys(payload, _CANDIDATE_FACTS_KEYS, "candidate_facts")
    budget = _CandidateRefBudget()
    effective: dict[str, Any] = {}
    downgraded = False

    def admit_wrapper(wrapper, label, value_check):
        nonlocal downgraded
        if wrapper is None:
            return None
        if not isinstance(wrapper, dict) or set(wrapper) != {"refs", "value"}:
            raise ValueError(f"candidate_facts.{label} must be null or an "
                             "exact refs/value object")
        outer = budget.take(_refs_array(wrapper, label),
                            f"candidate_facts.{label}.refs")
        value_check(wrapper["value"], f"candidate_facts.{label}.value")
        ok = _refs_gate(outer)
        return ok

    auth = node["authorised_jurisdictions"]
    if auth is None:
        effective["authorised_jurisdictions"] = None
    else:
        if not isinstance(auth, dict) or set(auth) != {"refs", "value"}:
            raise ValueError("candidate_facts.authorised_jurisdictions must "
                             "be null or an exact refs/value object")
        outer = budget.take(_refs_array(auth, "authorised_jurisdictions"),
                            "authorised_jurisdictions.refs")
        members = auth["value"]
        if not isinstance(members, list):
            raise ValueError("authorised_jurisdictions.value must be an array")
        if len(members) > MAX_AUTHORISED_JURISDICTIONS:
            raise ValueError("authorised_jurisdictions exceeds its maximum")
        seen_values: set[str] = set()
        members_ok = True
        for i, entry in enumerate(members):
            if not isinstance(entry, dict) or set(entry) != {"refs", "value"}:
                raise ValueError("authorised_jurisdictions.value entries must "
                                 "be exact refs/value objects")
            mrefs = budget.take(
                _refs_array(entry, f"authorised_jurisdictions.value[{i}]"),
                f"authorised_jurisdictions.value[{i}].refs")
            value = _require_iso_member(
                entry["value"],
                f"authorised_jurisdictions.value[{i}].value")
            if value in seen_values:
                raise ValueError("authorised_jurisdictions values must be "
                                 "unique after exact comparison")
            seen_values.add(value)
            members_ok = members_ok and _refs_gate(mrefs)
        outer_ok = _refs_gate(outer)
        if outer_ok and members_ok:
            effective["authorised_jurisdictions"] = sorted(seen_values)
        else:
            effective["authorised_jurisdictions"] = None
            downgraded = True

    residence = node["current_residence"]
    if residence is None:
        effective["current_residence"] = None
    else:
        if (not isinstance(residence, dict)
                or set(residence) != {"refs", "value"}):
            raise ValueError("candidate_facts.current_residence must be null "
                             "or an exact refs/value object")
        outer = budget.take(_refs_array(residence, "current_residence"),
                            "current_residence.refs")
        _require_iso_member(residence["value"],
                            "candidate_facts.current_residence.value")
        if _refs_gate(outer):
            effective["current_residence"] = residence["value"]
        else:
            effective["current_residence"] = None
            downgraded = True

    sponsorship = node["requires_sponsorship"]
    if sponsorship is None:
        effective["requires_sponsorship"] = None
    else:
        if (not isinstance(sponsorship, dict)
                or set(sponsorship) != {"refs", "value"}):
            raise ValueError("candidate_facts.requires_sponsorship must be "
                             "null or an exact refs/value object")
        outer = budget.take(_refs_array(sponsorship, "requires_sponsorship"),
                            "requires_sponsorship.refs")
        if not isinstance(sponsorship["value"], bool):
            raise ValueError("candidate_facts.requires_sponsorship.value must "
                             "be a boolean")
        if _refs_gate(outer):
            effective["requires_sponsorship"] = sponsorship["value"]
        else:
            effective["requires_sponsorship"] = None
            downgraded = True

    years = node["maximum_years_required"]
    if years is None:
        effective["maximum_years_required"] = None
    else:
        if not isinstance(years, dict) or set(years) != {"refs", "value"}:
            raise ValueError("candidate_facts.maximum_years_required must be "
                             "null or an exact refs/value object")
        outer = budget.take(_refs_array(years, "maximum_years_required"),
                            "maximum_years_required.refs")
        value = years["value"]
        if (not _is_number(value) or not math.isfinite(float(value))
                or float(value) < 0):
            raise ValueError("candidate_facts.maximum_years_required.value "
                             "must be a finite number >= 0")
        if _refs_gate(outer):
            effective["maximum_years_required"] = value
        else:
            effective["maximum_years_required"] = None
            downgraded = True

    exclusions = node["excluded_contract_types"]
    if exclusions is None:
        effective["excluded_contract_types"] = None
    else:
        if (not isinstance(exclusions, dict)
                or set(exclusions) != {"refs", "value"}):
            raise ValueError("candidate_facts.excluded_contract_types must be "
                             "null or an exact refs/value object")
        outer = budget.take(_refs_array(exclusions, "excluded_contract_types"),
                            "excluded_contract_types.refs")
        members = exclusions["value"]
        if not isinstance(members, list):
            raise ValueError("excluded_contract_types.value must be an array")
        if len(members) > MAX_EXCLUDED_CONTRACT_TYPES:
            raise ValueError("excluded_contract_types exceeds its maximum")
        seen_values: set[str] = set()
        members_ok = True
        for i, entry in enumerate(members):
            if not isinstance(entry, dict) or set(entry) != {"refs", "value"}:
                raise ValueError("excluded_contract_types.value entries must "
                                 "be exact refs/value objects")
            mrefs = budget.take(
                _refs_array(entry, f"excluded_contract_types.value[{i}]"),
                f"excluded_contract_types.value[{i}].refs")
            value = _require_enum_member(
                entry["value"],
                f"excluded_contract_types.value[{i}].value")
            if value in seen_values:
                raise ValueError("excluded_contract_types values must be "
                                 "unique after exact comparison")
            seen_values.add(value)
            members_ok = members_ok and _refs_gate(mrefs)
        outer_ok = _refs_gate(outer)
        if outer_ok and members_ok:
            effective["excluded_contract_types"] = sorted(seen_values)
        else:
            effective["excluded_contract_types"] = None
            downgraded = True

    return CandidateFactsAdmission(
        staged_canonical=canonical_json(node).encode("utf-8"),
        effective=effective,
        status_downgraded=downgraded)


_SELECTOR_COMBINATIONS = {
    "work_jurisdiction":
        {("work_authorisation", "scalar_string")},
    "sponsorship_available":
        {("work_authorisation", "string_list")},
    "required_residence": {("location", "scalar_string")},
    "contract_type": {("contract_type", "scalar_string")},
    "minimum_years_required": {("description", "scalar_string"),
                               ("required_qualifications", "scalar_string")},
}
_ALLOWED_EXTRACTION_FIELDS = frozenset(
    field for combos in _SELECTOR_COMBINATIONS.values()
    for field, _ in combos)
_ELEMENT_LIST_FIELDS = frozenset(("work_authorisation",
                                  "required_qualifications"))


def admit_vacancy_facts(payload: Any,
                        extraction: dict[str, Any]) -> dict[str, Any]:
    """Validate staged vacancy facts against the committed extraction."""
    node = exact_keys(payload, _VACANCY_FACTS_KEYS, "vacancy_facts")

    def check_iso(v, lbl):
        _require_iso_member(v, lbl)

    def check_bool(v, lbl):
        if not isinstance(v, bool):
            raise ValueError(lbl + " must be a boolean")

    def check_enum(v, lbl):
        _require_enum_member(v, lbl)

    def check_years(v, lbl):
        if not _is_number(v) or not math.isfinite(float(v)) or float(v) < 0:
            raise ValueError(lbl + " must be a finite number >= 0")

    validators = {"work_jurisdiction": check_iso,
                  "required_residence": check_iso,
                  "sponsorship_available": check_bool,
                  "minimum_years_required": check_years,
                  "contract_type": check_enum}
    effective: dict[str, Any] = {}
    for fact in sorted(_VACANCY_FACTS_KEYS):
        entry = node[fact]
        if entry is None:
            effective[fact] = None
            continue
        if not isinstance(entry, dict) or set(entry) != {"selector", "value"}:
            raise ValueError(f"vacancy_facts.{fact} must be null or an exact "
                             "selector/value object")
        sel = exact_keys(entry["selector"],
                         _SELECTOR_KEYS, f"vacancy_facts.{fact}.selector")
        field = plain_string(sel["extraction_field"],
                             f"vacancy_facts.{fact}.selector.extraction_field",
                             1, 64)
        if field not in _ALLOWED_EXTRACTION_FIELDS:
            raise ValueError(
                f"vacancy_facts.{fact}: extraction_field is prohibited")
        allowed = _SELECTOR_COMBINATIONS[fact]
        stype = plain_string(sel["selected_type"],
                             f"vacancy_facts.{fact}.selector.selected_type",
                             1, 16)
        if stype not in ("scalar_string", "string_list"):
            raise ValueError("selected_type must be a closed token")
        if (field, stype) not in allowed:
            raise ValueError(
                f"vacancy_facts.{fact}: field/type combination is not "
                "permitted for this fact")
        idx = sel["item_index"]
        if stype == "string_list":
            if idx is not None:
                raise ValueError("whole-list selection requires null "
                                 "item_index")
            raw = sel["selected_value"]
            target = extraction[field]
            if not isinstance(target, (list, tuple)):
                target = list(target)
            if not isinstance(raw, list):
                raise ValueError("selected_value must mirror the list")
            if len(raw) != len(target) or raw != list(target):
                raise ValueError("selected_value does not mirror the "
                                 "committed list byte-for-byte")
            if len(raw) == 0 or any(not _is_nonblank(item) for item in raw):
                raise ValueError("a non-null sponsorship fact requires a "
                                 "nonempty list of nonblank elements")
        elif field in _ELEMENT_LIST_FIELDS:
            if not _is_int(idx):
                raise ValueError("element selection requires an integer "
                                 "item_index")
            target_list = extraction[field]
            if not 0 <= idx < len(target_list):
                raise ValueError("item_index out of range")
            raw = sel["selected_value"]
            if not isinstance(raw, str) or raw != target_list[idx]:
                raise ValueError("selected_value does not mirror the "
                                 "committed element byte-for-byte")
            if not _is_nonblank(raw):
                raise ValueError("the selected element must contain at least "
                                 "one nonblank code point")
        else:
            if idx is not None:
                raise ValueError("scalar selection requires null item_index")
            raw = sel["selected_value"]
            if not isinstance(raw, str) or raw != extraction[field]:
                raise ValueError("selected_value does not mirror the "
                                 "committed scalar byte-for-byte")
            if not _is_nonblank(raw):
                raise ValueError("the selected string must contain at least "
                                 "one nonblank code point")
        digest = sha256_hex(canonical_json(raw).encode("utf-8"))
        given = sha256_value(sel["selected_value_sha256"],
                             f"vacancy_facts.{fact}.selector."
                             "selected_value_sha256")
        if digest != given:
            raise ValueError("selected_value_sha256 does not bind the exact "
                             "selected value")
        validators[fact](entry["value"], f"vacancy_facts.{fact}.value")
        effective[fact] = entry["value"]
    return effective


@dataclasses.dataclass(frozen=True)
class EligibilityEnvelopeFacts:
    """Immutable accepted facts from one validated eligibility envelope."""

    envelope_file_sha256: str
    envelope_semantic_sha256: str
    envelope_semantic_bytes: bytes
    operation_id: str
    fit_operation_id: str
    job_key: str
    profile_id: str
    profile_version: str
    track: str
    fit_receipt_self_hash: str
    fit_receipt_file_sha256: str
    decision_policy_sha256: str
    config_source_path: str
    config_source_file_sha256: str
    config_closure_files: tuple[tuple[str, str], ...]
    config_closure_sha256: str
    config_semantic_sha256: str
    assessments: DatabaseFacts
    vacancy: DatabaseFacts
    candidate_facts_staged: tuple
    vacancy_facts_staged: tuple
    candidate_facts_canonical: bytes
    vacancy_facts_canonical: bytes


def compose_eligibility_envelope_facts(
    payload: Any, *, envelope_file_sha256: str,
    expected_assessments_path: str | None,
    expected_vacancy_path: str | None,
) -> EligibilityEnvelopeFacts:
    """Validate the closed eligibility schema; return immutable facts."""
    if not isinstance(payload, dict):
        raise ValueError("eligibility envelope must be a JSON object")
    exact_keys(payload, _ELIGIBILITY_ENVELOPE_TOP_LEVEL_KEYS,
               "eligibility envelope")
    if payload["schema_version"] != ELIGIBILITY_ENVELOPE_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be "
                         f"{ELIGIBILITY_ENVELOPE_SCHEMA_VERSION!r}")
    operation_id = operation_id_value(payload["eligibility_operation_id"])
    fit_operation_id = operation_id_value(payload["fit_operation_id"])
    job_key = job_key_value(payload["job_key"])
    profile_id = _canonical_profile_id(payload["profile_id"],
                                       "envelope.profile_id")
    profile_version = plain_string(payload["profile_version"],
                                   "envelope.profile_version", 1, 128)
    track = plain_string(payload["track"], "envelope.track", 1, 128)
    fit_self = sha256_value(payload["fit_receipt_self_hash"],
                            "envelope.fit_receipt_self_hash")
    fit_file = sha256_value(payload["fit_receipt_file_sha256"],
                            "envelope.fit_receipt_file_sha256")
    policy_node = exact_keys(payload["decision_policy"],
                             {"decision_policy_sha256"}, "decision_policy")
    policy_sha = sha256_value(policy_node["decision_policy_sha256"],
                              "decision_policy.decision_policy_sha256")
    if policy_sha != ELIGIBILITY_DECISION_POLICY_SHA256:
        raise ProcessingRefused(ELIGIBILITY_REASON_POLICY,
                                "decision_policy differs from the fixed "
                                "contracted policy body")
    bounded_json_nodes(payload, "eligibility envelope",
                       max_nodes=MAX_ELIGIBILITY_JSON_NODES,
                       max_depth=MAX_ELIGIBILITY_JSON_DEPTH)
    config_binding = validate_config_binding(payload["config"])
    assessments_node, vacancy_node = validate_database_bindings(
        payload["databases"], expected_assessments_path,
        expected_vacancy_path)
    try:
        semantic_bytes = canonical_json(payload).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("envelope contains unencodable Unicode") from exc
    sha256_value(envelope_file_sha256, "envelope.envelope_file_sha256")
    if hashlib.sha256(semantic_bytes + b"\n").hexdigest() != \
            envelope_file_sha256:
        raise ValueError("envelope_file_sha256 must equal SHA-256 of the "
                         "exact canonical envelope bytes plus one LF")
    facts = EligibilityEnvelopeFacts(
        envelope_file_sha256=envelope_file_sha256,
        envelope_semantic_sha256=sha256_hex(semantic_bytes),
        envelope_semantic_bytes=semantic_bytes,
        operation_id=operation_id,
        fit_operation_id=fit_operation_id,
        job_key=job_key,
        profile_id=profile_id,
        profile_version=profile_version,
        track=track,
        fit_receipt_self_hash=fit_self,
        fit_receipt_file_sha256=fit_file,
        decision_policy_sha256=policy_sha,
        config_source_path=config_binding["source_path"],
        config_source_file_sha256=config_binding["source_file_sha256"],
        config_closure_files=tuple(sorted(
            config_binding["closure_files"].items())),
        config_closure_sha256=config_binding["closure_sha256"],
        config_semantic_sha256=config_binding["semantic_sha256"],
        assessments=DatabaseFacts(
            path=assessments_node["path"], dev=int(assessments_node["dev"]),
            ino=int(assessments_node["ino"]), uid=int(assessments_node["uid"]),
            mode=int(assessments_node["mode"]),
            nlink=int(assessments_node["nlink"])),
        vacancy=DatabaseFacts(
            path=vacancy_node["path"], dev=int(vacancy_node["dev"]),
            ino=int(vacancy_node["ino"]), uid=int(vacancy_node["uid"]),
            mode=int(vacancy_node["mode"]), nlink=int(vacancy_node["nlink"])),
        candidate_facts_staged=_freeze_structure(payload["candidate_facts"]),
        vacancy_facts_staged=_freeze_structure(payload["vacancy_facts"]),
        candidate_facts_canonical=canonical_json(
            payload["candidate_facts"]).encode("utf-8"),
        vacancy_facts_canonical=canonical_json(
            payload["vacancy_facts"]).encode("utf-8"),
    )
    _assert_fully_immutable(facts, "eligibility_facts")
    return facts


def validate_eligibility_envelope_name(envelope_name: str) -> str:
    """Eligibility lexical gate: identical grammar to the FIT envelope name,
    but every lexical refusal maps to the ELIGIBILITY path reason (contract
    section 13 row 2), never to the FIT processing-path token."""
    try:
        return validate_envelope_name(envelope_name)
    except ProcessingRefused as exc:
        if exc.reason == REASON_ENVELOPE_PATH:
            raise ProcessingRefused(ELIGIBILITY_REASON_ENVELOPE_PATH,
                                    exc.detail) from exc
        raise


def load_eligibility_envelope_authority(
    data_home: Path, envelope_name: str
) -> tuple[_DescriptorSet, dict[str, Any], str]:
    """Retain root/state/eligibility-inbox plus the exact leaf; parse."""
    validate_eligibility_envelope_name(envelope_name)
    descriptors = _DescriptorSet()
    try:
        try:
            root_fd_chain = open_existing_private_data_root(str(data_home))
        except (OSError, ValueError) as exc:
            raise ProcessingRefused(
                ELIGIBILITY_REASON_CONFIG_DATABASE,
                f"data-home authority refused: {exc}") from exc
        root = _CanonicalRoot.__new__(_CanonicalRoot)
        root._chain = root_fd_chain
        levels: list[_RetainedDirectory] = []
        try:
            root.revalidate()
            state_level = _RetainedDirectory(root, "state",
                                             require_private=True)
            levels.append(state_level)
            inbox_level = _RetainedDirectory(state_level,
                                             "eligibility-inbox",
                                             require_private=True)
            levels.append(inbox_level)
            descriptors.attach_root(root)
            descriptors.directories.extend(levels)
            descriptors.state_level = state_level
            descriptors.inbox_level = inbox_level
        except BaseException:
            for level in reversed(levels):
                level.close()
            root.close()
            raise
        try:
            info = os.stat(envelope_name, dir_fd=inbox_level.fd,
                           follow_symlinks=False)
            _require_private_leaf(info, "eligibility envelope")
        except (OSError, ValueError) as exc:
            raise ProcessingRefused(ELIGIBILITY_REASON_ENVELOPE_PATH,
                                    str(exc)) from exc
        if info.st_size > MAX_ELIGIBILITY_ENVELOPE_BYTES:
            raise ProcessingRefused(
                ELIGIBILITY_REASON_ENVELOPE_BYTES,
                f"eligibility envelope exceeds "
                f"{MAX_ELIGIBILITY_ENVELOPE_BYTES} bytes")
        try:
            leaf = descriptors.push_leaf(_RetainedLeaf(
                inbox_level, envelope_name,
                maximum=MAX_ELIGIBILITY_ENVELOPE_BYTES, prestat=info))
        except _RetainedLeafContentError as exc:
            raise ProcessingRefused(ELIGIBILITY_REASON_ENVELOPE_BYTES,
                                    str(exc)) from exc
        except (OSError, ValueError) as exc:
            raise ProcessingRefused(ELIGIBILITY_REASON_ENVELOPE_PATH,
                                    str(exc)) from exc
        try:
            payload = strict_json_loads(leaf.data)
            exact_keys(payload, _ELIGIBILITY_ENVELOPE_TOP_LEVEL_KEYS,
                       "eligibility envelope")
        except ValueError as exc:
            raise ProcessingRefused(
                ELIGIBILITY_REASON_ENVELOPE_BYTES,
                f"eligibility envelope refused: {exc}") from exc
        canonical = canonical_json(payload).encode("utf-8")
        if leaf.data != canonical + b"\n":
            raise ProcessingRefused(
                ELIGIBILITY_REASON_ENVELOPE_BYTES,
                "envelope bytes are not canonical JSON followed by exactly "
                "one LF")
        file_sha = sha256_hex(leaf.data)
        if envelope_name != f"{file_sha}.json":
            raise ProcessingRefused(
                ELIGIBILITY_REASON_ENVELOPE_BYTES,
                "filename does not bind the exact envelope bytes")
        if payload.get("schema_version") != \
                ELIGIBILITY_ENVELOPE_SCHEMA_VERSION:
            raise ProcessingRefused(
                ELIGIBILITY_REASON_ENVELOPE_BYTES,
                f"schema_version must be "
                f"{ELIGIBILITY_ENVELOPE_SCHEMA_VERSION!r}")
        return descriptors, payload, file_sha
    except BaseException:
        descriptors.close()
        raise




def build_eligibility_binding(
    facts: EligibilityEnvelopeFacts, payload: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    binding = {
        "schema_version": ELIGIBILITY_BINDING_SCHEMA_VERSION,
        "operation_id": facts.operation_id,
        "fit_operation_id": facts.fit_operation_id,
        "job_key": facts.job_key,
        "profile_id": facts.profile_id,
        "profile_version": facts.profile_version,
        "track": facts.track,
        "envelope_file_sha256": facts.envelope_file_sha256,
        "envelope_semantic_sha256": facts.envelope_semantic_sha256,
        "fit_receipt_self_hash": facts.fit_receipt_self_hash,
        "fit_receipt_file_sha256": facts.fit_receipt_file_sha256,
        "decision_policy_sha256": facts.decision_policy_sha256,
        "config": copy.deepcopy(payload["config"]),
        "databases": copy.deepcopy(payload["databases"]),
        "candidate_facts": copy.deepcopy(payload["candidate_facts"]),
        "vacancy_facts": copy.deepcopy(payload["vacancy_facts"]),
    }
    exact_keys(binding, _ELIGIBILITY_BINDING_KEYS, "eligibility binding")
    return binding, sha256_hex(canonical_json(binding).encode("utf-8"))


def rebuild_eligibility_event_payload(
        receipt: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "schema_version": ELIGIBILITY_EVENT_SCHEMA_VERSION,
        "operation_id": receipt["operation_id"],
        "fit_operation_id": receipt["fit_operation_id"],
        "profile_id": receipt["profile_id"],
        "job_key": receipt["job_key"],
        "track": receipt["track"],
        "binding_sha256": receipt["binding_sha256"],
        "envelope_file_sha256": receipt["envelope_file_sha256"],
        "fit_receipt_self_hash": receipt["fit_receipt_self_hash"],
        "fit_receipt_file_sha256": receipt["fit_receipt_file_sha256"],
        "fit_assessment_event_id": receipt["fit_assessment_event_id"],
        "fit_event_payload_sha256": receipt["fit_event_payload_sha256"],
        "fit_normalized_json_sha256": receipt["fit_normalized_json_sha256"],
        "candidate_facts_sha256": receipt["candidate_facts_sha256"],
        "vacancy_facts_sha256": receipt["vacancy_facts_sha256"],
        "decision_policy_sha256": receipt["decision_policy_sha256"],
        "decision_input_sha256": receipt["decision_input_sha256"],
        "iso_jurisdiction_set_sha256": receipt["iso_jurisdiction_set_sha256"],
        "decision": receipt["decision"],
        "reasons": receipt["reasons"],
        "unknowns": receipt["unknowns"],
    }
    exact_keys(payload, _ELIGIBILITY_EVENT_PAYLOAD_KEYS,
               "eligibility event payload")
    return payload


def parse_eligibility_receipt(raw_bytes: bytes) -> dict[str, Any]:
    """Strict closed parser proving canonical identity and every binding."""
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) < 3:
        raise ValueError("receipt bytes must be at least 3 bytes")
    if len(raw_bytes) > MAX_ELIGIBILITY_RECEIPT_BYTES:
        raise ValueError(f"receipt bytes exceed "
                         f"{MAX_ELIGIBILITY_RECEIPT_BYTES}")
    receipt = strict_json_loads(raw_bytes)
    exact_keys(receipt, _ELIGIBILITY_RECEIPT_TOP_LEVEL_KEYS,
               "eligibility receipt")
    if raw_bytes != canonical_json(receipt).encode("utf-8") + b"\n":
        raise ValueError("receipt bytes are not canonical JSON plus one LF")
    if receipt["schema_version"] != ELIGIBILITY_RECEIPT_SCHEMA_VERSION:
        raise ValueError(
            f"schema_version must be {ELIGIBILITY_RECEIPT_SCHEMA_VERSION!r}")
    for flag in _ELIGIBILITY_FALSE_FLAGS:
        if receipt[flag] is not False:
            raise ValueError(f"authority flag {flag} must be exactly false")
    if receipt["eligibility_authority"] is not (receipt["decision"] == "pass"):
        raise ValueError("eligibility_authority must equal "
                         "(decision == 'pass')")
    operation_id_value(receipt["operation_id"])
    operation_id_value(receipt["fit_operation_id"])
    job_key_value(receipt["job_key"])
    _canonical_profile_id(receipt["profile_id"], "receipt.profile_id")
    plain_string(receipt["profile_version"], "receipt.profile_version", 1, 128)
    plain_string(receipt["track"], "receipt.track", 1, 128)
    if receipt["decision"] not in ("pass", "review", "reject"):
        raise ValueError("decision must be a closed decision token")
    for field in ("binding_sha256", "envelope_file_sha256",
                  "envelope_semantic_sha256", "fit_receipt_self_hash",
                  "fit_receipt_file_sha256", "fit_binding_sha256",
                  "fit_event_payload_sha256", "fit_raw_snapshot_sha256",
                  "fit_profile_context_sha256",
                  "fit_extraction_output_sha256",
                  "fit_alignment_output_sha256", "fit_normalized_json_sha256",
                  "fit_assessment_payload_hash", "candidate_facts_sha256",
                  "vacancy_facts_sha256", "decision_policy_sha256",
                  "decision_input_sha256", "iso_jurisdiction_set_sha256"):
        sha256_value(receipt[field], f"receipt.{field}")
    if not isinstance(receipt["reasons"], list) or not isinstance(
            receipt["unknowns"], list):
        raise ValueError("reasons/unknowns must be arrays")
    fit_sealed = canonical_json(receipt["fit_receipt"]).encode("utf-8") + b"\n"
    fit_parsed = parse_processing_receipt(fit_sealed)
    if fit_parsed["self_hash"] != receipt["fit_receipt_self_hash"]:
        raise ValueError("embedded FIT self_hash disagrees")
    if fit_parsed["binding_sha256"] != receipt["fit_binding_sha256"]:
        raise ValueError("embedded FIT binding disagrees")
    event = fit_parsed["assessment_event"]
    if event["id"] != receipt["fit_assessment_event_id"]:
        raise ValueError("embedded FIT event id disagrees")
    if event["payload_sha256"] != receipt["fit_event_payload_sha256"]:
        raise ValueError("embedded FIT event payload disagrees")
    if (fit_parsed["normalised_projection"]["normalized_json_sha256"]
            != receipt["fit_normalized_json_sha256"]):
        raise ValueError("embedded FIT normalized hash disagrees")
    for column, path in _FIT_SCALAR_PROJECTIONS:
        node: Any = fit_parsed
        for part in path:
            node = node[part]
        if node != receipt[column]:
            raise ValueError(f"receipt.{column} disagrees with the embedded "
                             "FIT receipt")
    for identity in ("profile_id", "profile_version", "job_key", "track"):
        if receipt[identity] != fit_parsed[identity]:
            raise ValueError(f"receipt.{identity} differs from the embedded "
                             "FIT receipt")
    if receipt["config"] != fit_parsed["config"]:
        raise ValueError("receipt.config differs from the embedded FIT graph")
    if receipt["databases"] != fit_parsed["databases"]:
        raise ValueError("receipt.databases differs from the embedded FIT "
                         "graph")
    event_node = exact_keys(receipt["eligibility_event"],
                            _ELIGIBILITY_EVENT_NODE_KEYS,
                            "receipt.eligibility_event")
    if event_node["event_type"] != EVENT_TYPE_ELIGIBILITY_DECIDED:
        raise ValueError("eligibility_event.event_type must be exactly "
                         "eligibility_decided")
    if event_node["actor_kind"] != "deterministic":
        raise ValueError("eligibility_event.actor_kind must be deterministic")
    if not _is_int(event_node["id"]) or event_node["id"] <= 0:
        raise ValueError("eligibility_event.id must be a positive integer")
    rfc3339_value(event_node["created_at"], "eligibility_event.created_at")
    rfc3339_value(receipt["created_at"], "receipt.created_at")
    if event_node["created_at"] != receipt["created_at"]:
        raise ValueError("eligibility_event.created_at must equal the single "
                         "operation timestamp")
    rebuilt = rebuild_eligibility_event_payload(receipt)
    payload_sha = sha256_hex(canonical_json(rebuilt).encode("utf-8"))
    if payload_sha != event_node["payload_sha256"]:
        raise ValueError("eligibility_event.payload_sha256 does not bind the "
                         "rebuilt payload")
    job_key_sha = hashlib.sha256(receipt["job_key"].encode("utf-8")).hexdigest()
    idem = ("eligibility-decided:" + receipt["profile_id"] + ":"
            + job_key_sha + ":" + payload_sha)
    if event_node["idempotency_key"] != idem:
        raise ValueError("eligibility_event.idempotency_key does not follow "
                         "the contracted formula")
    claimed = receipt["self_hash"]
    sha256_value(claimed, "receipt.self_hash")
    without_self = {k: v for k, v in receipt.items() if k != "self_hash"}
    if sha256_hex(canonical_json(without_self).encode("utf-8")) != claimed:
        raise ValueError("receipt self_hash does not bind the complete receipt")
    return receipt


# ==========================================================================
# ELIGIBILITY-001 part 2: store inspection, S1-S5 binding, replay,
# transaction, recovery, and the public coordinator.
# ==========================================================================

_ELIGIBILITY_RECEIPT_ROW_COLUMNS = (
    "operation_id", "fit_operation_id", "profile_id", "job_key", "track",
    "binding_sha256", "envelope_file_sha256", "envelope_semantic_sha256",
    "fit_receipt_self_hash", "fit_receipt_file_sha256", "fit_binding_sha256",
    "fit_event_id", "fit_event_payload_sha256", "fit_raw_snapshot_sha256",
    "fit_profile_context_sha256", "fit_extraction_output_sha256",
    "fit_alignment_output_sha256", "fit_normalized_json_sha256",
    "fit_assessment_payload_hash", "candidate_facts_sha256",
    "vacancy_facts_sha256", "decision_policy_sha256", "decision_input_sha256",
    "iso_jurisdiction_set_sha256", "decision", "reasons_json",
    "unknowns_json", "event_id", "event_payload_sha256",
    "receipt_self_hash", "receipt_file_sha256", "receipt_bytes",
    "eligibility_authority", "research_authority", "application_authority",
    "release_authority", "submission_authority", "created_at")
assert len(_ELIGIBILITY_RECEIPT_ROW_COLUMNS) == 38
_ELIGIBILITY_SENTINEL_TIMESTAMP = "1970-01-01T00:00:00.000000Z"
_ELIG_IDX = {name: i for i, name in enumerate(_ELIGIBILITY_RECEIPT_ROW_COLUMNS)}
_ELIG_VOLATILE_IDX = frozenset((
    _ELIG_IDX["created_at"], _ELIG_IDX["event_id"],
    _ELIG_IDX["receipt_self_hash"], _ELIG_IDX["receipt_file_sha256"],
    _ELIG_IDX["receipt_bytes"]))


def _inspect_eligibility_store(
    connection: sqlite3.Connection, fit_operation_id: str,
    operation_id: str,
) -> ReplayClassification:
    """Read-only store-state machine (accepted contract 14.5 S1-S3)."""

    def provisional(detail: str) -> ReplayClassification:
        return ReplayClassification(
            DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY, None, detail)

    rows = connection.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' AND name IN "
        "('market_aligner_schema_migrations','processing_receipts',"
        "'assessment_events','assessments','eligibility_receipts')").fetchall()
    present = {name: _normalized_sql(sql) for name, sql in rows}
    for required in ("market_aligner_schema_migrations", "processing_receipts",
                     "assessment_events", "assessments"):
        if required not in present:
            raise ProcessingRefused(
                ELIGIBILITY_REASON_FIT_RECEIPT,
                f"required table {required} is absent; no bootstrap path")
    canonical_ledger = " ".join(
        LEDGER_DDL.replace("CREATE TABLE IF NOT EXISTS ",
                           "CREATE TABLE ").split())
    if present["market_aligner_schema_migrations"] != canonical_ledger:
        return provisional("migration ledger is not the canonical ledger")
    ledger_rows = connection.execute(
        "SELECT version, name, checksum FROM market_aligner_schema_migrations"
        " ORDER BY version").fetchall()
    v1 = (_FIT_VERSION, _FIT_NAME, _FIT_CHECKSUM)
    v2 = (_ELIG_VERSION, _ELIG_NAME, _ELIG_CHECKSUM)
    versions = tuple(tuple(row) for row in ledger_rows)
    if versions == (v1,):
        with_v2 = False
    elif versions == (v1, v2):
        with_v2 = True
    else:
        return provisional("migration ledger rows are not exactly [v1] or "
                           "[v1, v2]")
    if present["processing_receipts"] != _normalized_sql(FIT001_RECEIPTS_DDL):
        return provisional("processing_receipts DDL is not canonical")
    if not with_v2:
        if "eligibility_receipts" in present:
            return provisional("eligibility_receipts exists without its "
                               "ledger row")
        return _fit_row_present_or_refuse(connection, fit_operation_id,
                                          "compatible store without "
                                          "eligibility receipts")
    if present["eligibility_receipts"] != \
            _normalized_sql(ELIGIBILITY_RECEIPTS_DDL):
        return provisional("eligibility_receipts DDL is not canonical")
    actual_uniques: set[tuple[str, ...]] = set()
    for row in connection.execute(
            "PRAGMA index_list(eligibility_receipts)").fetchall():
        unique, origin, partial = row[2], row[3], row[4]
        if not unique or partial or origin not in ("pk", "u", "c"):
            continue
        columns = tuple(info[2] for info in connection.execute(
            f"PRAGMA index_info({row[1]!r})").fetchall())
        actual_uniques.add(columns)
    expected_uniques = {("operation_id",), ("fit_operation_id",),
                        ("binding_sha256",), ("receipt_file_sha256",),
                        ("profile_id", "job_key")}
    if actual_uniques != expected_uniques:
        return provisional("eligibility_receipts unique facts are not exact")
    foreign_keys = connection.execute(
        "PRAGMA foreign_key_list(eligibility_receipts)").fetchall()
    expected_fks = [
        (0, 0, "assessment_events", "event_id", "id", "NO ACTION", "RESTRICT",
         "NONE"),
        (1, 0, "assessment_events", "fit_event_id", "id", "NO ACTION",
         "RESTRICT", "NONE"),
        (2, 0, "processing_receipts", "fit_operation_id", "operation_id",
         "NO ACTION", "RESTRICT", "NONE")]
    if list(map(tuple, foreign_keys)) != expected_fks:
        return provisional("eligibility_receipts foreign-key facts are not "
                           "exact")
    conflict = connection.execute(
        "SELECT operation_id FROM eligibility_receipts WHERE "
        "fit_operation_id=? AND operation_id<>?",
        (fit_operation_id, operation_id)).fetchone()
    if conflict is not None:
        raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                "another operation already targets this FIT "
                                "receipt")
    return _fit_row_present_or_refuse(connection, fit_operation_id,
                                      "compatible store")


_FIT_VERSION = 1
_FIT_NAME = "fit001_processing_receipts_v1"
_FIT_CHECKSUM = FIT001_PROCESSING_RECEIPTS.checksum
_ELIG_VERSION = ELIGIBILITY_ELIGIBILITY_RECEIPTS.version
_ELIG_NAME = ELIGIBILITY_ELIGIBILITY_RECEIPTS.name
_ELIG_CHECKSUM = ELIGIBILITY_ELIGIBILITY_RECEIPTS.checksum


def _fit_row_present_or_refuse(connection: sqlite3.Connection,
                               fit_operation_id: str, ok_detail: str
                               ) -> ReplayClassification:
    row = connection.execute(
        "SELECT operation_id FROM processing_receipts WHERE operation_id=?",
        (fit_operation_id,)).fetchone()
    if row is None:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_FIT_RECEIPT,
            "no processing receipt for the referenced fit_operation_id")
    return ReplayClassification(DISPOSITION_DEFINITIVE_ABSENCE, None,
                                ok_detail)


def bind_fit_authority(
    connection: sqlite3.Connection, facts: EligibilityEnvelopeFacts,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """S4/S5: parse and FULLY self-validate the referenced FIT receipt.

    _self_validating_receipt recomputes the embedded envelope's semantic
    hash and staged binding from the sealed bytes; the proven FIT
    EnvelopeFacts remain local proof.  Current-raw admission lives in
    _validate_current_raw_against_fit so exact historical replay and
    recovery stay independent of mutable current raw.
    """
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name="
        "'processing_receipts'").fetchone()
    if table is None:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "processing_receipts is absent; no bootstrap "
                                "path exists")
    scalar_columns = (
        "operation_id", "profile_id", "job_key", "track",
        "binding_sha256", "envelope_file_sha256", "envelope_semantic_sha256",
        "normalized_sha256", "assessment_payload_hash", "receipt_self_hash",
        "receipt_file_sha256", "created_at", "receipt_bytes")
    row = connection.execute(
        f"SELECT {','.join(scalar_columns)} FROM processing_receipts"
        " WHERE operation_id=?", (facts.fit_operation_id,)).fetchone()
    if row is None:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "referenced FIT receipt row is absent")
    stored = dict(zip(scalar_columns, row))
    (stored_op, stored_profile, stored_job, stored_track, stored_self,
     stored_file, stored_bytes) = (stored["operation_id"],
                                   stored["profile_id"],
                                   stored["job_key"], stored["track"],
                                   stored["receipt_self_hash"],
                                   stored["receipt_file_sha256"],
                                   stored["receipt_bytes"])
    for value, label in ((stored_op, "operation_id"),
                         (stored_profile, "profile_id"),
                         (stored_job, "job_key"), (stored_track, "track"),
                         (stored_self, "receipt_self_hash"),
                         (stored_file, "receipt_file_sha256")):
        if not isinstance(value, str):
            raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                    f"stored FIT column {label} is not TEXT")
    if not isinstance(stored_bytes, bytes):
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "stored FIT receipt is not a BLOB")
    try:
        parsed, fit_envelope_facts = _self_validating_receipt(stored_bytes)
    except ValueError as exc:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                f"stored FIT receipt fails full "
                                f"self-validation: {exc}") from exc
    if parsed["envelope_semantic_sha256"] != fit_envelope_facts.envelope_semantic_sha256:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "proven FIT envelope semantic hash drifted")
    embedded_sealed = canonical_json(parsed).encode("utf-8") + b"\n"
    if embedded_sealed != stored_bytes:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "embedded FIT receipt does not re-seal "
                                "byte-exactly to its stored BLOB")
    scalar_expectations = (
        ("operation_id", "operation_id"),
        ("profile_id", "profile_id"),
        ("job_key", "job_key"),
        ("track", "track"),
        ("binding_sha256", "binding_sha256"),
        ("envelope_file_sha256", "envelope_file_sha256"),
        ("envelope_semantic_sha256", "envelope_semantic_sha256"),
        ("normalized_sha256",
         ("normalised_projection", "normalized_json_sha256")),
        ("assessment_payload_hash",
         ("assessment_projection", "score_payload_hash")),
    )
    for column, source in scalar_expectations:
        expected = (parsed[source] if isinstance(source, str)
                    else parsed[source[0]][source[1]])
        if stored[column] != expected:
            raise ProcessingRefused(
                ELIGIBILITY_REASON_FIT_RECEIPT,
                f"stored FIT column {column} differs from the sealed "
                "receipt")
    if stored["created_at"] != parsed["created_at"]:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "stored FIT created_at differs from the "
                                "sealed receipt")
    if parsed["self_hash"] != stored_self:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "stored FIT self hash disagrees with its row")
    if parsed["self_hash"] != facts.fit_receipt_self_hash:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "staged fit_receipt_self_hash differs from "
                                "the stored FIT receipt")
    file_hash = sha256_hex(stored_bytes)
    if file_hash != stored_file:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "stored FIT file hash disagrees with its row")
    if file_hash != facts.fit_receipt_file_sha256:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "staged fit_receipt_file_sha256 differs from "
                                "the stored FIT receipt")
    event_node = parsed["assessment_event"]
    event_row = connection.execute(
        "SELECT id, event_type, actor_kind, payload_json, idempotency_key,"
        " created_at, profile_id, job_key FROM assessment_events WHERE id=?",
        (event_node["id"],),
    ).fetchone()
    if event_row is None:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "the FIT assessment event row is absent")
    expected_event_identity = (
        event_node["id"],
        event_node["event_type"],
        event_node["actor_kind"],
        event_node["idempotency_key"],
        event_node["created_at"],
        parsed["profile_id"],
        parsed["job_key"],
    )
    observed_event_identity = (
        event_row[0],
        event_row[1],
        event_row[2],
        event_row[4],
        event_row[5],
        event_row[6],
        event_row[7],
    )
    if observed_event_identity != expected_event_identity:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_FIT_RECEIPT,
            "the FIT event identity differs from the sealed receipt",
        )
    if sha256_hex(event_row[3].encode("utf-8")) != event_node["payload_sha256"]:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_FIT_RECEIPT,
            "the FIT event payload bytes differ from its sealed hash",
        )
    projection = parsed["normalised_projection"]
    normalized = read_normalized_job(connection, key=parsed["job_key"])
    if (
        normalized is None
        or sha256_hex(normalized[0].encode("utf-8"))
        != projection["normalized_json_sha256"]
        or normalized[1] != projection["normalized_at"]
    ):
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "the normalized projection behind the FIT "
                                "receipt drifted or is absent")
    assessment_projection = parsed["assessment_projection"]
    score_row = connection.execute(
        "SELECT profile_id, job_key, score_payload_hash, state, created_at, "
        "updated_at FROM "
        "assessments WHERE profile_id=? AND job_key=?",
        (parsed["profile_id"], parsed["job_key"])).fetchone()
    if score_row is None:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "the assessment row behind the FIT receipt is "
                                "absent")
    expected_score_row = (parsed["profile_id"], parsed["job_key"],
                          assessment_projection["score_payload_hash"],
                          "scored",
                          assessment_projection["created_at"],
                          assessment_projection["updated_at"])
    if tuple(score_row) != expected_score_row:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                "the assessment row disagrees with the FIT "
                                "projection")

    for column, staged in (("operation_id", facts.fit_operation_id),
                           ("profile_id", facts.profile_id),
                           ("job_key", facts.job_key),
                           ("track", facts.track)):
        if parsed[column] != staged:
            raise ProcessingRefused(
                ELIGIBILITY_REASON_FIT_RECEIPT,
                f"anti-relabelling: staged {column} differs from the FIT "
                "receipt")
    if parsed["profile_version"] != facts.profile_version:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_FIT_RECEIPT,
            "anti-relabelling: staged profile_version differs from the FIT "
            "receipt")
    if payload["config"] != parsed["config"]:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_FIT_RECEIPT,
            "anti-relabelling: staged config node differs from the FIT "
            "receipt config node")
    if payload["databases"] != parsed["databases"]:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_FIT_RECEIPT,
            "anti-relabelling: staged databases node differs from the FIT "
            "receipt databases node")
    return parsed
def _validate_current_raw_against_fit(
    connection: sqlite3.Connection, fit_parsed: dict[str, Any],
) -> None:
    """Admit the CURRENT vacancy posting against the proven FIT receipt.

    Reads the current posting row twice via the exact POSTING_READ_COLUMNS
    projection, runs _raw_snapshot_from_row on BOTH rows with the FIT
    EnvelopeFacts reconstructed from the sealed receipt, and requires the
    two immutable raw-snapshot proofs to be immediately equal.  Any shape,
    fetch-status, legacy-source-hash, or snapshot-hash divergence maps to
    stable reason 7 (contract 14.5 S4 / 14.8 step 4).  Exact historical
    replay and recovery never call this helper.
    """
    try:
        fit_envelope_facts = reconstruct_receipt_envelope_facts(fit_parsed)
        projection = ",".join(POSTING_READ_COLUMNS)
        first = connection.execute(
            f"SELECT {projection} FROM vacancy.postings WHERE key=?",
            (fit_envelope_facts.job_key,)).fetchone()
        if first is None:
            raise ValueError("current posting row is absent")
        admitted = _raw_snapshot_from_row(first, fit_envelope_facts)
        second = connection.execute(
            f"SELECT {projection} FROM vacancy.postings WHERE key=?",
            (fit_envelope_facts.job_key,)).fetchone()
        if second is None:
            raise ValueError("current posting row vanished on reread")
        confirmed = _raw_snapshot_from_row(second, fit_envelope_facts)
    except ProcessingRefused:
        raise
    except ValueError as exc:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_FIT_RECEIPT,
            f"current raw posting refused against the sealed FIT "
            f"receipt: {exc}") from exc
    if _raw_snapshot_proof(admitted) != _raw_snapshot_proof(confirmed):
        raise ProcessingRefused(
            ELIGIBILITY_REASON_FIT_RECEIPT,
            "current raw posting drifted between read and immediate "
            "reread")



def _eligibility_table_exists(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND "
        "name='eligibility_receipts'").fetchone()
    return row is not None



def _sha_of_canonical(value: Any) -> str:
    return sha256_hex(canonical_json(value).encode("utf-8"))


def _cj_list(values: list[str]) -> str:
    return canonical_json(values)


def _classify_own_receipt(
    connection: sqlite3.Connection, facts: EligibilityEnvelopeFacts,
    binding_sha256: str,
) -> ReplayClassification | None:
    """Own-receipt classification; None means definitive absence."""
    exists = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND "
        "name='eligibility_receipts'").fetchone()
    if exists is None:
        return None
    columns = ",".join(_ELIGIBILITY_RECEIPT_ROW_COLUMNS)
    row = connection.execute(
        f"SELECT {columns} FROM eligibility_receipts WHERE operation_id=?",
        (facts.operation_id,)).fetchone()
    if row is None:
        return None
    if type(row) is not tuple or len(row) != 38:
        raise ProcessingRefused(ELIGIBILITY_REASON_EXISTING_RECEIPT,
                                "stored row shape is not the closed 38-column"
                                " contract")
    stored = dict(zip(_ELIGIBILITY_RECEIPT_ROW_COLUMNS, row))
    stored_bytes = stored["receipt_bytes"]
    integer_columns = ("event_id", "fit_event_id",
                       "fit_assessment_event_id", "eligibility_authority",
                       "research_authority", "application_authority",
                       "release_authority", "submission_authority")
    for column in _ELIGIBILITY_RECEIPT_ROW_COLUMNS:
        value = stored[column]
        if column == "receipt_bytes":
            continue
        if column in integer_columns:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ProcessingRefused(
                    ELIGIBILITY_REASON_EXISTING_RECEIPT,
                    f"stored column {column} must be an INTEGER without bool")
        elif not isinstance(value, str):
            raise ProcessingRefused(ELIGIBILITY_REASON_EXISTING_RECEIPT,
                                    f"stored column {column} must be TEXT")
    if not isinstance(stored_bytes, bytes):
        raise ProcessingRefused(ELIGIBILITY_REASON_EXISTING_RECEIPT,
                                "stored receipt is not a BLOB")
    try:
        parsed = parse_eligibility_receipt(stored_bytes)
    except ValueError as exc:
        raise ProcessingRefused(ELIGIBILITY_REASON_EXISTING_RECEIPT,
                                f"stored receipt fails validation: {exc}")
    derived = {
        "operation_id": parsed["operation_id"],
        "fit_operation_id": parsed["fit_operation_id"],
        "profile_id": parsed["profile_id"],
        "job_key": parsed["job_key"],
        "track": parsed["track"],
        "binding_sha256": parsed["binding_sha256"],
        "envelope_file_sha256": parsed["envelope_file_sha256"],
        "envelope_semantic_sha256": parsed["envelope_semantic_sha256"],
        "fit_receipt_self_hash": parsed["fit_receipt_self_hash"],
        "fit_receipt_file_sha256": parsed["fit_receipt_file_sha256"],
        "receipt_file_sha256": sha256_hex(stored_bytes),
        "fit_binding_sha256": parsed["fit_binding_sha256"],
        "fit_event_id": parsed["fit_assessment_event_id"],
        "fit_event_payload_sha256":
            parsed["fit_event_payload_sha256"],
        "fit_raw_snapshot_sha256": parsed["fit_raw_snapshot_sha256"],
        "fit_profile_context_sha256":
            parsed["fit_profile_context_sha256"],
        "fit_extraction_output_sha256":
            parsed["fit_extraction_output_sha256"],
        "fit_alignment_output_sha256":
            parsed["fit_alignment_output_sha256"],
        "fit_normalized_json_sha256":
            parsed["fit_normalized_json_sha256"],
        "fit_assessment_payload_hash":
            parsed["fit_assessment_payload_hash"],
        "candidate_facts_sha256": _sha_of_canonical(
            parsed["candidate_facts"]),
        "vacancy_facts_sha256": _sha_of_canonical(
            parsed["vacancy_facts"]),
        "decision_policy_sha256": parsed["decision_policy_sha256"],
        "decision_input_sha256": parsed["decision_input_sha256"],
        "iso_jurisdiction_set_sha256":
            parsed["iso_jurisdiction_set_sha256"],
        "decision": parsed["decision"],
        "reasons_json": _cj_list(parsed["reasons"]),
        "unknowns_json": _cj_list(parsed["unknowns"]),
        "event_id": parsed["eligibility_event"]["id"],
        "event_payload_sha256":
            parsed["eligibility_event"]["payload_sha256"],
        "receipt_self_hash": parsed["self_hash"],
        "created_at": parsed["created_at"],
        "eligibility_authority": 1 if parsed["decision"] == "pass" else 0,
        "research_authority": 0, "application_authority": 0,
        "release_authority": 0, "submission_authority": 0,
    }
    mismatches = [column for column, want in derived.items()
                  if stored[column] != want]
    if mismatches:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_EXISTING_RECEIPT,
            "stored eligibility columns differ from the sealed receipt: "
            + ",".join(sorted(mismatches)))
    if parsed["binding_sha256"] != binding_sha256:
        raise ProcessingRefused(ELIGIBILITY_REASON_EXISTING_RECEIPT,
                                "stored receipt carries a different staged "
                                "binding")
    node = parsed["eligibility_event"]
    event_row = connection.execute(
        "SELECT id, event_type, actor_kind, payload_json, idempotency_key,"
        " created_at, profile_id, job_key FROM assessment_events WHERE id=?",
        (node["id"],)).fetchone()
    if event_row is None:
        raise ProcessingRefused(ELIGIBILITY_REASON_EXISTING_RECEIPT,
                                "the bound eligibility_decided event row is "
                                "absent")
    rebuilt = rebuild_eligibility_event_payload(parsed)
    payload_json = canonical_json(rebuilt)
    payload_sha = sha256_hex(payload_json.encode("utf-8"))
    if payload_sha != node["payload_sha256"]:
        raise ProcessingRefused(ELIGIBILITY_REASON_EXISTING_RECEIPT,
                                "the sealed event node does not bind the "
                                "rebuilt payload")
    expected_event = (node["id"], EVENT_TYPE_ELIGIBILITY_DECIDED,
                      "deterministic", payload_json,
                      node["idempotency_key"], parsed["created_at"],
                      parsed["profile_id"], parsed["job_key"])
    if tuple(event_row) != expected_event:
        raise ProcessingRefused(ELIGIBILITY_REASON_EXISTING_RECEIPT,
                                "the bound eligibility_decided event row "
                                "drifted")
    return ReplayClassification(DISPOSITION_EXACT_REPLAY, stored_bytes,
                                "sealed replay")


def reconstruct_decision_view(facts: EligibilityEnvelopeFacts,
                              fit_parsed: dict[str, Any]
                              ) -> dict[str, Any]:
    """Validate both staged fact families and rebuild the decision view."""
    from market_aligner.assessment.eligibility import (
        EligibilityInput, EligibilityPolicy, assess_eligibility)
    staged_candidate = strict_json_loads(
        facts.candidate_facts_canonical.decode("utf-8"))
    try:
        admission = admit_candidate_facts(staged_candidate)
    except ValueError as exc:
        raise ProcessingRefused(ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                                f"candidate facts refused: {exc}") from exc
    extraction = strict_json_loads(json.dumps(
        fit_parsed["extraction"]["output"], ensure_ascii=False,
        sort_keys=True, separators=(",", ":")))
    try:
        validate_extraction_output(extraction)
        staged_vacancy = strict_json_loads(
            facts.vacancy_facts_canonical.decode("utf-8"))
        vacancy_effective = admit_vacancy_facts(staged_vacancy, extraction)
    except ValueError as exc:
        raise ProcessingRefused(ELIGIBILITY_REASON_VACANCY_FACTS,
                                f"vacancy facts refused: {exc}") from exc
    eff = admission.effective
    policy = EligibilityPolicy(
        authorised_jurisdictions=(None if eff["authorised_jurisdictions"]
                                  is None else
                                  frozenset(eff["authorised_jurisdictions"])),
        current_residence=eff["current_residence"],
        requires_sponsorship=eff["requires_sponsorship"],
        maximum_years_required=eff["maximum_years_required"],
        excluded_contract_types=(None if eff["excluded_contract_types"]
                                 is None else
                                 frozenset(eff["excluded_contract_types"])))
    dec_input = EligibilityInput(
        work_jurisdiction=vacancy_effective["work_jurisdiction"],
        required_residence=vacancy_effective["required_residence"],
        sponsorship_available=vacancy_effective["sponsorship_available"],
        minimum_years_experience=vacancy_effective["minimum_years_required"],
        contract_type=vacancy_effective["contract_type"])
    outcome = assess_eligibility(dec_input, policy)
    reasons = sorted(set(outcome.reasons))
    unknowns = sorted(set(outcome.unknowns))
    if admission.status_downgraded:
        unknowns.append("candidate_evidence_status_unverified")
        unknowns = sorted(set(unknowns))
    final_decision = ("reject" if reasons
                      else ("review" if unknowns else "pass"))
    decision_input = {
        "authorised_jurisdictions": eff["authorised_jurisdictions"],
        "contract_type": dec_input.contract_type,
        "current_residence": eff["current_residence"],
        "excluded_contract_types": eff["excluded_contract_types"],
        "maximum_years_required": eff["maximum_years_required"],
        "minimum_years_experience": dec_input.minimum_years_experience,
        "requires_sponsorship": eff["requires_sponsorship"],
        "required_residence": dec_input.required_residence,
        "sponsorship_available": dec_input.sponsorship_available,
        "work_jurisdiction": dec_input.work_jurisdiction,
    }
    exact_keys(decision_input, _ELIGIBILITY_DECISION_INPUT_KEYS,
               "decision_input")
    return {
        "decision_input": decision_input,
        "decision_input_sha256": sha256_hex(
            canonical_json(decision_input).encode("utf-8")),
        "decision": final_decision,
        "reasons": reasons,
        "unknowns": unknowns,
    }


@dataclasses.dataclass(frozen=True)
class EligibilityProspectivePlan:
    sealed_bytes: bytes
    receipt_file_sha256: str
    receipt_self_hash: str
    binding_sha256: str
    event_payload_json: str
    event_payload_sha256: str
    idempotency_key: str
    accepted_at: str
    event_id: int
    facts: EligibilityEnvelopeFacts
    receipt_row_values: tuple


def build_eligibility_prospective_plan(
    *, facts: EligibilityEnvelopeFacts, payload: dict[str, Any],
    binding_sha256: str, decision_view: dict[str, Any], accepted_at: str,
    prospective_event_id: int, fit_parsed: dict[str, Any],
) -> EligibilityProspectivePlan:
    rfc3339_value(accepted_at, "accepted_at")
    if (not _is_int(prospective_event_id) or prospective_event_id <= 0
            or prospective_event_id > MAX_EVENT_ID):
        raise ProcessingRefused(REASON_ATOMIC_MODE,
                                "prospective event id out of range")
    candidate_sha = sha256_hex(facts.candidate_facts_canonical)
    vacancy_sha = sha256_hex(facts.vacancy_facts_canonical)
    event_payload = {
        "schema_version": ELIGIBILITY_EVENT_SCHEMA_VERSION,
        "operation_id": facts.operation_id,
        "fit_operation_id": facts.fit_operation_id,
        "profile_id": facts.profile_id,
        "job_key": facts.job_key,
        "track": facts.track,
        "binding_sha256": binding_sha256,
        "envelope_file_sha256": facts.envelope_file_sha256,
        "fit_receipt_self_hash": facts.fit_receipt_self_hash,
        "fit_receipt_file_sha256": facts.fit_receipt_file_sha256,
        "fit_assessment_event_id": fit_parsed["assessment_event"]["id"],
        "fit_event_payload_sha256":
            fit_parsed["assessment_event"]["payload_sha256"],
        "fit_normalized_json_sha256":
            fit_parsed["normalised_projection"]["normalized_json_sha256"],
        "candidate_facts_sha256": candidate_sha,
        "vacancy_facts_sha256": vacancy_sha,
        "decision_policy_sha256": facts.decision_policy_sha256,
        "decision_input_sha256": decision_view["decision_input_sha256"],
        "iso_jurisdiction_set_sha256": ISO_JURISDICTION_SET_SHA256,
        "decision": decision_view["decision"],
        "reasons": decision_view["reasons"],
        "unknowns": decision_view["unknowns"],
    }
    exact_keys(event_payload, _ELIGIBILITY_EVENT_PAYLOAD_KEYS,
               "prospective event payload")
    event_payload_json = canonical_json(event_payload)
    event_payload_sha256 = sha256_hex(event_payload_json.encode("utf-8"))
    job_key_sha = hashlib.sha256(facts.job_key.encode("utf-8")).hexdigest()
    idempotency_key = ("eligibility-decided:" + facts.profile_id + ":"
                       + job_key_sha + ":" + event_payload_sha256)
    if len(idempotency_key.encode("utf-8")) != 186 or not idempotency_key.isascii():
        raise ProcessingRefused(REASON_PROJECTION_CONFLICT,
                                "idempotency key width/formula drifted")
    eligibility_event = {
        "id": prospective_event_id,
        "event_type": EVENT_TYPE_ELIGIBILITY_DECIDED,
        "actor_kind": "deterministic",
        "payload_sha256": event_payload_sha256,
        "idempotency_key": idempotency_key,
        "created_at": accepted_at,
    }
    receipt: dict[str, Any] = {
        "schema_version": ELIGIBILITY_RECEIPT_SCHEMA_VERSION,
        "operation_id": facts.operation_id,
        "fit_operation_id": facts.fit_operation_id,
        "job_key": facts.job_key,
        "profile_id": facts.profile_id,
        "profile_version": facts.profile_version,
        "track": facts.track,
        "binding_sha256": binding_sha256,
        "envelope_file_sha256": facts.envelope_file_sha256,
        "envelope_semantic_sha256": facts.envelope_semantic_sha256,
        "config": payload["config"],
        "databases": payload["databases"],
        "fit_receipt": fit_parsed,
        "fit_receipt_self_hash": facts.fit_receipt_self_hash,
        "fit_receipt_file_sha256": facts.fit_receipt_file_sha256,
        "fit_binding_sha256": fit_parsed["binding_sha256"],
        "fit_assessment_event_id": fit_parsed["assessment_event"]["id"],
        "fit_event_payload_sha256":
            fit_parsed["assessment_event"]["payload_sha256"],
        "fit_raw_snapshot_sha256": fit_parsed["raw"]["raw_snapshot_sha256"],
        "fit_profile_context_sha256":
            fit_parsed["profile"]["profile_context_sha256"],
        "fit_extraction_output_sha256":
            fit_parsed["extraction"]["receipt"]["output_sha256"],
        "fit_alignment_output_sha256":
            fit_parsed["alignment"]["receipt"]["output_sha256"],
        "fit_normalized_json_sha256":
            fit_parsed["normalised_projection"]["normalized_json_sha256"],
        "fit_assessment_payload_hash":
            fit_parsed["assessment_projection"]["score_payload_hash"],
        "candidate_facts": payload["candidate_facts"],
        "vacancy_facts": payload["vacancy_facts"],
        "candidate_facts_sha256": candidate_sha,
        "vacancy_facts_sha256": vacancy_sha,
        "decision_policy_sha256": facts.decision_policy_sha256,
        "decision_input_sha256": decision_view["decision_input_sha256"],
        "iso_jurisdiction_set_sha256": ISO_JURISDICTION_SET_SHA256,
        "decision_input": decision_view["decision_input"],
        "decision": decision_view["decision"],
        "reasons": decision_view["reasons"],
        "unknowns": decision_view["unknowns"],
        "eligibility_event": eligibility_event,
        "created_at": accepted_at,
        "time_authenticated": False,
        "imported_model_policy_authenticated": False,
        "imported_time_authenticated": False,
        "research_authority": False,
        "application_authority": False,
        "release_authority": False,
        "submission_authority": False,
        "eligibility_authority": decision_view["decision"] == "pass",
    }
    receipt["self_hash"] = sha256_hex(
        canonical_json(receipt).encode("utf-8"))
    sealed_bytes = canonical_json(receipt).encode("utf-8") + b"\n"
    if len(sealed_bytes) > MAX_ELIGIBILITY_RECEIPT_BYTES:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_ENVELOPE_BYTES,
            f"sealed receipt is {len(sealed_bytes)} bytes; maximum is "
            f"{MAX_ELIGIBILITY_RECEIPT_BYTES}")
    validated = parse_eligibility_receipt(sealed_bytes)
    row_values: list[Any] = []
    for column in _ELIGIBILITY_RECEIPT_ROW_COLUMNS:
        if column == "receipt_bytes":
            row_values.append(sealed_bytes)
        elif column == "eligibility_authority":
            row_values.append(1 if validated["eligibility_authority"] else 0)
        elif column in _ELIGIBILITY_FALSE_FLAGS:
            row_values.append(0)
        elif column == "reasons_json":
            row_values.append(canonical_json(validated["reasons"]))
        elif column == "unknowns_json":
            row_values.append(canonical_json(validated["unknowns"]))
        elif column == "fit_event_id":
            row_values.append(validated["fit_assessment_event_id"])
        elif column == "event_id":
            row_values.append(validated["eligibility_event"]["id"])
        elif column == "event_payload_sha256":
            row_values.append(validated["eligibility_event"][
                "payload_sha256"])
        elif column == "receipt_self_hash":
            row_values.append(validated["self_hash"])
        elif column == "receipt_file_sha256":
            row_values.append(sha256_hex(sealed_bytes))
        else:
            row_values.append(validated[column])
    return EligibilityProspectivePlan(
        sealed_bytes=sealed_bytes,
        receipt_file_sha256=sha256_hex(sealed_bytes),
        receipt_self_hash=receipt["self_hash"],
        binding_sha256=binding_sha256,
        event_payload_json=event_payload_json,
        event_payload_sha256=event_payload_sha256,
        idempotency_key=idempotency_key,
        accepted_at=accepted_at,
        event_id=prospective_event_id,
        facts=facts,
        receipt_row_values=tuple(row_values))


def apply_eligibility_transaction_plan(
    connection: sqlite3.Connection, plan: EligibilityProspectivePlan,
) -> bytes:
    """Apply one exact eligibility plan inside the caller's transaction."""
    if getattr(connection, "in_transaction", False) is not True:
        raise ProcessingRefused(REASON_ATOMIC_MODE,
                                "requires an active caller-owned transaction")
    try:
        apply_on(connection, (FIT001_PROCESSING_RECEIPTS,
                              ELIGIBILITY_ELIGIBILITY_RECEIPTS), "main")
    except MigrationCompatibilityError as exc:
        raise ProcessingRefused(REASON_ATOMIC_MODE,
                                f"migration incompatible: {exc}") from exc
    _maybe_fault("elig_after_migration_apply")

    events_before = classify_processing_score_event(
        connection, profile_id=plan.facts.profile_id,
        job_key=plan.facts.job_key,
        event_type=EVENT_TYPE_ELIGIBILITY_DECIDED)
    if events_before.action != "insert_required":
        raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                "an eligibility_decided event already exists "
                                "for this profile/job")
    try:
        event_outcome = cas_processing_event(
            connection, profile_id=plan.facts.profile_id,
            job_key=plan.facts.job_key,
            event_type=EVENT_TYPE_ELIGIBILITY_DECIDED,
            actor_kind="deterministic",
            payload_json=plan.event_payload_json,
            idempotency_key=plan.idempotency_key,
            created_at=plan.accepted_at, event_id=plan.event_id)
    except ProjectionConflict as exc:
        raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                f"event insert conflict: {exc}") from exc
    projection = event_outcome.projection
    if (event_outcome.action != "insert" or projection is None
            or projection.event_id != plan.event_id
            or projection.payload_json != plan.event_payload_json
            or projection.idempotency_key != plan.idempotency_key
            or projection.created_at != plan.accepted_at):
        raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                "event insert differs from its exact plan")
    _maybe_fault("elig_after_event_insert")

    columns = ",".join(_ELIGIBILITY_RECEIPT_ROW_COLUMNS)
    placeholders = ",".join("?" for _ in _ELIGIBILITY_RECEIPT_ROW_COLUMNS)
    try:
        cursor = connection.execute(
            f"INSERT INTO main.eligibility_receipts({columns}) "
            f"VALUES({placeholders})", plan.receipt_row_values)
    except sqlite3.IntegrityError as exc:
        raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                f"receipt integrity conflict: {exc}") from exc
    if cursor.rowcount != 1:
        raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                "receipt insert affected multiple rows")
    _maybe_fault("elig_after_receipt_insert")
    stored = connection.execute(
        f"SELECT {columns} FROM main.eligibility_receipts WHERE "
        f"operation_id=?", (plan.facts.operation_id,)).fetchall()
    if (type(stored) is not list or len(stored) != 1
            or type(stored[0]) is not tuple
            or stored[0] != plan.receipt_row_values):
        raise ProcessingRefused(REASON_PROJECTION_CONFLICT,
                                "receipt reread differs from inserted row")
    try:
        reparsed = parse_eligibility_receipt(stored[0][_ELIG_IDX[
            "receipt_bytes"]])
    except ValueError as exc:
        raise ProcessingRefused(REASON_PROJECTION_CONFLICT,
                                f"stored receipt reread invalid: {exc}") from \
            exc
    if reparsed["self_hash"] != plan.receipt_self_hash or \
            sha256_hex(plan.sealed_bytes) != plan.receipt_file_sha256:
        raise ProcessingRefused(REASON_PROJECTION_CONFLICT,
                                "stored receipt hashes drifted")
    _maybe_fault("elig_pre_commit")
    return plan.sealed_bytes


def recover_eligibility_durable_truth(
    data_home: Path, envelope_name: str, plan: EligibilityProspectivePlan,
) -> RecoveredTransactionClassification:
    """Fresh reopen through SQLite recovery, then durable-truth classify."""
    lease: _AdmissionLease | None = None
    primary: ProcessingRefused | None = None
    classification: RecoveredTransactionClassification | None = None
    try:
        descriptors, reload_payload, reload_sha = \
            load_eligibility_envelope_authority(data_home, envelope_name)
        lease = _AdmissionLease(descriptors)
        try:
            facts = compose_eligibility_envelope_facts(
                reload_payload, envelope_file_sha256=reload_sha,
                expected_assessments_path=None, expected_vacancy_path=None)
            if facts != plan.facts:
                raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                        "recovery envelope facts differ from "
                                        "the attempted transaction")
            admission = admit_config_and_databases(data_home, facts,
                                                   descriptors)
            lease.bind(admission, facts, plan.binding_sha256)
            lease.revalidate_chain()
            lease.open_view(allow_database_size_change=True)
            conn = lease.connection
            assert conn is not None and lease.assessments is not None \
                and lease.vacancy is not None
            conn.execute("PRAGMA query_only=OFF")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            for alias in ("main", "vacancy"):
                mode = conn.execute(f"PRAGMA {alias}.journal_mode").fetchall()
                if mode != [("delete",)]:
                    raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                            f"{alias} journal mode is not "
                                            "delete")
                conn.execute(f"PRAGMA {alias}.synchronous=FULL")
                sync = conn.execute(f"PRAGMA {alias}.synchronous").fetchall()
                if sync != [(2,)]:
                    raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                            f"{alias} synchronous is not FULL")
            _verify_transaction_connection(
                conn, descriptors, lease.assessments, lease.vacancy,
                allow_database_size_change=True)
            conn.execute("BEGIN IMMEDIATE")

            def verify_once() -> RecoveredTransactionClassification:
                listed = conn.execute("PRAGMA database_list").fetchall()
                if len(listed) != 2:
                    raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                            "recovery aliases are not exactly "
                                            "two")
                for alias in ("main", "vacancy"):
                    quick = conn.execute(f"PRAGMA {alias}.quick_check"
                                         ).fetchall()
                    if quick != [("ok",)]:
                        raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                                f"{alias} quick_check failed")
                    fkrows = conn.execute(
                        f"PRAGMA {alias}.foreign_key_check").fetchall()
                    if fkrows != []:
                        raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                                f"{alias} foreign_key_check "
                                                "found violations")
                return classify_eligibility_durable_graph(conn, plan)

            first = verify_once()
            lease.assessments.accept_recovered_size()
            lease.vacancy.accept_recovered_size()
            _require_clean_recovery_epoch(_stabilize_filesystem_epoch(
                descriptors, lease.assessments, lease.vacancy))
            second = verify_once()
            if second != first:
                raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                        "durable classification changed "
                                        "inside one snapshot")
            classification = second
            conn.rollback()
        except BaseException:
            raise
    except (KeyboardInterrupt, _Interrupted) as exc:
        primary = ProcessingRefused(REASON_INTERRUPTED,
                                    "recovery was interrupted")
        primary.__cause__ = exc
    except sqlite3.Error as exc:
        primary = map_sqlite_read_error(exc)
        primary.__cause__ = exc
    except ProcessingRefused as exc:
        primary = exc
    finally:
        if lease is not None:
            if (lease.connection is not None
                    and lease.connection.in_transaction):
                with contextlib.suppress(sqlite3.Error):
                    lease.connection.rollback()
            lease.close()
    if primary is not None:
        raise primary
    assert classification is not None
    return classification


def classify_eligibility_durable_graph(
    connection: sqlite3.Connection, plan: EligibilityProspectivePlan,
) -> RecoveredTransactionClassification:
    def incoherent(detail: str) -> RecoveredTransactionClassification:
        return RecoveredTransactionClassification(RECOVERY_DURABLE_INCOHERENT,
                                                  None, detail)

    if not _eligibility_table_exists(connection):
        event_probe = connection.execute(
            "SELECT COUNT(*) FROM assessment_events WHERE event_type=?",
            (EVENT_TYPE_ELIGIBILITY_DECIDED,)).fetchone()[0]
        if event_probe:
            return incoherent("eligibility event exists without its receipt")
        return RecoveredTransactionClassification(
            RECOVERY_DURABLE_EMPTY, None,
            "eligibility store absent; nothing persisted")
    ledger_rows = connection.execute(
        "SELECT version FROM market_aligner_schema_migrations ORDER BY "
        "version").fetchall()
    versions = tuple(row[0] for row in ledger_rows)
    if versions not in ((1,), (1, 2)):
        return incoherent("migration ledger is not [v1] or [v1, v2]")
    event_rows = connection.execute(
        "SELECT id, event_type, actor_kind, payload_json, idempotency_key,"
        " created_at FROM assessment_events WHERE profile_id=? AND job_key=?"
        " AND event_type=?", (plan.facts.profile_id, plan.facts.job_key,
                              EVENT_TYPE_ELIGIBILITY_DECIDED)).fetchall()
    receipt_rows = connection.execute(
        "SELECT receipt_bytes FROM eligibility_receipts WHERE operation_id=?",
        (plan.facts.operation_id,)).fetchall()
    if not event_rows and not receipt_rows:
        if versions == (1,) or versions == (1, 2):
            return RecoveredTransactionClassification(
                RECOVERY_DURABLE_EMPTY, None,
                "v1 intact and no own eligibility projection exists")
        return incoherent("migration ledger is neither [v1] nor [v1, v2] "
                          "with an empty own graph")
    if len(event_rows) > 1 or len(receipt_rows) > 1:
        return incoherent("multiple eligibility projections exist")
    if versions != (1, 2):
        return incoherent("a complete eligibility graph requires ledger "
                          "exactly [v1, v2]")
    if len(event_rows) != 1 or len(receipt_rows) != 1:
        return incoherent("partial eligibility projection graph exists")
    stored_row = connection.execute(
        "SELECT " + ",".join(_ELIGIBILITY_RECEIPT_ROW_COLUMNS) +
        " FROM eligibility_receipts WHERE operation_id=?",
        (plan.facts.operation_id,)).fetchone()
    if type(stored_row) is not tuple or len(stored_row) != 38:
        return incoherent("stored receipt row is not the closed 38-column "
                          "shape")
    if tuple(stored_row) != plan.receipt_row_values:
        return incoherent("stored 38-column row differs from the exact "
                          "prospective plan")
    event = event_rows[0]
    stored_bytes = receipt_rows[0][0]
    if not isinstance(stored_bytes, bytes):
        return incoherent("stored receipt is not a BLOB")
    try:
        parsed = parse_eligibility_receipt(stored_bytes)
    except ValueError as exc:
        return incoherent(f"stored receipt fails validation: {exc}")
    node = parsed["eligibility_event"]
    if (event[0] != node["id"] or event[1] != EVENT_TYPE_ELIGIBILITY_DECIDED
            or event[2] != "deterministic" or event[3] != plan.event_payload_json
            or event[4] != plan.idempotency_key or event[5] != node["created_at"]):
        return incoherent("stored event does not match the embedded "
                          "eligibility_event node")
    if stored_bytes != plan.sealed_bytes:
        return incoherent("stored receipt bytes differ from the prospective "
                          "plan")
    fit_row = connection.execute(
        "SELECT receipt_bytes FROM processing_receipts WHERE operation_id=?",
        (plan.facts.fit_operation_id,)).fetchone()
    embedded_fit_sealed = canonical_json(parsed["fit_receipt"]).encode(
        "utf-8") + b"\n"
    if fit_row is None or fit_row[0] != embedded_fit_sealed:
        return incoherent("embedded FIT receipt does not match its stored row")
    # Full immutable-graph revalidation through the sole owners, using a
    # payload reconstructed EXACTLY from the sealed eligibility receipt.
    reconstructed_payload = {
        "schema_version": ELIGIBILITY_ENVELOPE_SCHEMA_VERSION,
        "eligibility_operation_id": parsed["operation_id"],
        "fit_operation_id": parsed["fit_operation_id"],
        "job_key": parsed["job_key"],
        "profile_id": parsed["profile_id"],
        "profile_version": parsed["profile_version"],
        "track": parsed["track"],
        "fit_receipt_self_hash": parsed["fit_receipt_self_hash"],
        "fit_receipt_file_sha256": parsed["fit_receipt_file_sha256"],
        "decision_policy": {"decision_policy_sha256":
                            parsed["decision_policy_sha256"]},
        "config": parsed["config"],
        "databases": parsed["databases"],
        "candidate_facts": parsed["candidate_facts"],
        "vacancy_facts": parsed["vacancy_facts"],
    }
    try:
        store_state = _inspect_eligibility_store(
            connection, parsed["fit_operation_id"], parsed["operation_id"])
        if store_state.disposition != DISPOSITION_DEFINITIVE_ABSENCE:
            return incoherent("locked store classification is not definitive "
                              "absence for the committed operation: "
                              + store_state.detail)
        bind_fit_authority(connection,
                           compose_eligibility_envelope_facts(
                               reconstructed_payload,
                               envelope_file_sha256=sha256_hex(
                                   canonical_json(reconstructed_payload)
                                   .encode("utf-8") + b"\n"),
                               expected_assessments_path=None,
                               expected_vacancy_path=None),
                           reconstructed_payload)
    except ProcessingRefused as exc:
        return incoherent(f"FIT immutable graph failed recovery "
                          f"revalidation ({exc.reason}): {exc.detail}")
    return RecoveredTransactionClassification(RECOVERY_DURABLE_COMPLETE,
                                              stored_bytes,
                                              "exact complete graph")


def _validate_supplied_eligibility_identity(
    *, supplied_operation_id: str, supplied_fit_operation_id: str,
    supplied_config_path: str, supplied_profile_id: str,
    supplied_job_key: str, supplied_track: str,
) -> None:
    """Lexical validation only; equality is compared at reason 4."""
    try:
        operation_id_value(supplied_operation_id)
    except ValueError as exc:
        raise ProcessingRefused(ELIGIBILITY_REASON_OPERATION_ID,
                                str(exc)) from exc
    try:
        operation_id_value(supplied_fit_operation_id)
        path_value(supplied_config_path, "supplied configuration path")
        _canonical_profile_id(supplied_profile_id, "supplied profile id")
        job_key_value(supplied_job_key)
        plain_string(supplied_track, "supplied track", 1, 128)
    except ValueError as exc:
        raise ProcessingRefused(ELIGIBILITY_REASON_CLI_IDENTITY,
                                f"malformed supplied identity: {exc}") from exc


def eligibility_one(
    data_home: Path,
    envelope_name: str,
    *,
    supplied_operation_id: str,
    supplied_fit_operation_id: str,
    supplied_config_path: str,
    supplied_profile_id: str,
    supplied_job_key: str,
    supplied_track: str,
) -> bytes:
    """Run one serialized provider-free eligibility operation."""
    _validate_supplied_eligibility_identity(
        supplied_operation_id=supplied_operation_id,
        supplied_fit_operation_id=supplied_fit_operation_id,
        supplied_config_path=supplied_config_path,
        supplied_profile_id=supplied_profile_id,
        supplied_job_key=supplied_job_key,
        supplied_track=supplied_track)
    with _process_one_serialization_scope(data_home):
        return _eligibility_one_under_scope(
            data_home, envelope_name,
            supplied_operation_id=supplied_operation_id,
            supplied_fit_operation_id=supplied_fit_operation_id,
            supplied_config_path=supplied_config_path,
            supplied_profile_id=supplied_profile_id,
            supplied_job_key=supplied_job_key,
            supplied_track=supplied_track)


def _eligibility_one_under_scope(
    data_home: Path, envelope_name: str, *, supplied_operation_id: str,
    supplied_fit_operation_id: str, supplied_config_path: str,
    supplied_profile_id: str, supplied_job_key: str, supplied_track: str,
) -> bytes:
    descriptors: _DescriptorSet | None = None
    lease: _AdmissionLease | None = None
    result: bytes | None = None
    caught: BaseException | None = None
    plan_holder: list[tuple[EligibilityProspectivePlan, dict[str, Any]]] = []
    try:
        validate_eligibility_envelope_name(envelope_name)
        descriptors, payload, file_sha = load_eligibility_envelope_authority(
            data_home, envelope_name)
        try:
            facts = compose_eligibility_envelope_facts(
                payload, envelope_file_sha256=file_sha,
                expected_assessments_path=None, expected_vacancy_path=None)
        except ProcessingRefused:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise ProcessingRefused(ELIGIBILITY_REASON_ENVELOPE_BYTES,
                                    f"eligibility envelope refused: "
                                    f"{exc}") from exc
        for supplied, expected, label in (
                (supplied_operation_id, facts.operation_id,
                 "operation id"),
                (supplied_fit_operation_id, facts.fit_operation_id,
                 "fit operation id"),
                (supplied_config_path, facts.config_source_path,
                 "configuration path"),
                (supplied_profile_id, facts.profile_id, "profile id"),
                (supplied_job_key, facts.job_key, "job key"),
                (supplied_track, facts.track, "track")):
            if supplied != expected:
                raise ProcessingRefused(
                    ELIGIBILITY_REASON_CLI_IDENTITY,
                    f"supplied {label} does not equal the staged binding")
        canonical_assessments = str(Path(data_home) / "state"
                                    / "assessments.sqlite3")
        if facts.assessments.path != canonical_assessments:
            raise ProcessingRefused(
                ELIGIBILITY_REASON_CONFIG_DATABASE,
                "staged assessments path is not the canonical "
                "state/assessments.sqlite3")
        merged, collector_plan = _verify_live_config_binding(data_home, facts)
        if str(collector_plan["database"]) != facts.vacancy.path:
            raise ProcessingRefused(
                ELIGIBILITY_REASON_CONFIG_DATABASE,
                "planned collector database differs from the staged vacancy "
                "path")
        admission = admit_config_and_databases(data_home, facts, descriptors)
        lease = _AdmissionLease(descriptors)
        lease.bind(admission, facts, "")
        lease.revalidate_chain()
        journal_present = False
        for database in (lease.assessments, lease.vacancy):
            journal_name = database.name + "-journal"
            try:
                journal_info = os.stat(journal_name,
                                       dir_fd=database.parent.fd,
                                       follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ProcessingRefused(REASON_ATOMIC_MODE,
                                        f"cannot classify pre-open "
                                        f"{journal_name}: {exc}") from exc
            _require_private_leaf(journal_info, journal_name)
            journal_present = True
        lease.open_view(allow_database_size_change=True)
        conn = lease.connection
        assert conn is not None
        _verify_transaction_connection(conn, descriptors, lease.assessments,
                                       lease.vacancy,
                                       allow_database_size_change=True)
        if journal_present:
            conn.execute("PRAGMA query_only=OFF")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            for alias in ("main", "vacancy"):
                if conn.execute(f"PRAGMA {alias}.journal_mode=DELETE"
                                ).fetchall() != [("delete",)]:
                    raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                            "startup recovery did not enter "
                                            "DELETE mode")
                conn.execute(f"PRAGMA {alias}.synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            for alias in ("main", "vacancy"):
                if conn.execute(f"PRAGMA {alias}.quick_check"
                                ).fetchall() != [("ok",)]:
                    raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                            "startup quick_check failed")
                if conn.execute(f"PRAGMA {alias}.foreign_key_check"
                                ).fetchall() != []:
                    raise ProcessingRefused(REASON_RECOVERY_INCOHERENT,
                                            "startup FK violations found")
            conn.rollback()
            conn.execute("PRAGMA query_only=ON")
        lease.assessments.accept_recovered_size()
        lease.vacancy.accept_recovered_size()

        # S1-S3 sole historical classifier on the public path (before replay
        # and before any new admission); hard refusals leave zero writes.
        store_state = _inspect_eligibility_store(
            conn, facts.fit_operation_id, facts.operation_id)
        if store_state.disposition ==                 DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY:
            provisional_detail = store_state.detail
        else:
            provisional_detail = None
        lease.provisional_detail = provisional_detail

        fit_parsed = bind_fit_authority(conn, facts, payload)

        _binding_object, binding_sha = build_eligibility_binding(facts,
                                                                 payload)
        own_classification = _classify_own_receipt(conn, facts, binding_sha)
        if own_classification is not None:
            assert own_classification.stored_receipt_bytes is not None
            result = own_classification.stored_receipt_bytes
        else:
            # S4 on the NEW-operation path: full current-raw admission
            # bound to the sealed FIT receipt (exact historical replay and
            # recovery never reach this line).
            _validate_current_raw_against_fit(conn, fit_parsed)
            profile_store = ProfileStore.open_existing(Path(data_home))
            snapshot = profile_store.coherent_snapshot(
                facts.profile_id, require_committed_generation=True)
            staged_profile_binding = dict(fit_parsed["profile"])
            for key in ("profile_file_sha256", "evidence_file_sha256",
                        "profile_sha256", "evidence_ledger_sha256",
                        "profile_context_sha256"):
                if staged_profile_binding.get(key) != snapshot.hashes.get(key):
                    raise ProcessingRefused(
                        ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                        f"committed generation hash {key} differs from the "
                        "embedded FIT receipt profile binding")
            if (snapshot.manifest is None
                    or snapshot.manifest.get("state") != "committed"):
                raise ProcessingRefused(
                    ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                    "a committed generation manifest is required")
            if facts.profile_version != snapshot.profile.version:
                raise ProcessingRefused(
                    ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                    "staged profile_version differs from the committed "
                    "generation")
            if facts.track not in snapshot.profile.tracks:
                raise ProcessingRefused(
                    ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                    f"selected track {facts.track!r} does not exist in the "
                    "committed profile")

            def walk_refs(node):  # noqa: ANN202
                if isinstance(node, dict):
                    if "refs" in node and isinstance(node["refs"], list):
                        for ref in node["refs"]:
                            evidence_id = ref.get("evidence_id")
                            item = snapshot.evidence.get(evidence_id)
                            if item is None:
                                raise ProcessingRefused(
                                    ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                                    f"cited evidence id {evidence_id!r} is "
                                    "not in the committed ledger")
                            if ref.get("kind") != item.kind or ref.get(
                                    "status") != item.status:
                                raise ProcessingRefused(
                                    ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                                    f"cited ref {evidence_id!r} kind/status "
                                    "differs from the committed ledger")
                            claim_sha = sha256_hex(item.claim.encode("utf-8"))
                            source_sha = sha256_hex(
                                item.source_ref.encode("utf-8"))
                            if (ref.get("claim_sha256") != claim_sha
                                    or ref.get("source_ref_sha256")
                                    != source_sha):
                                raise ProcessingRefused(
                                    ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                                    f"cited ref {evidence_id!r} hashes differ "
                                    "from the committed ledger")
                            if item.content_sha256 is None or ref.get(
                                    "content_sha256") != item.content_sha256:
                                raise ProcessingRefused(
                                    ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                                    f"cited ref {evidence_id!r} "
                                    "content_sha256 must be non-null and "
                                    "equal the committed item")
                    for value in node.values():
                        walk_refs(value)
                elif isinstance(node, list):
                    for entry in node:
                        walk_refs(entry)

            walk_refs(payload["candidate_facts"])

            decision_view = reconstruct_decision_view(facts, fit_parsed)
            preflight_plan = build_eligibility_prospective_plan(
                facts=facts, payload=payload, binding_sha256=binding_sha,
                decision_view=decision_view,
                accepted_at=_ELIGIBILITY_SENTINEL_TIMESTAMP,
                prospective_event_id=_prospective_event_id(conn),
                fit_parsed=fit_parsed)
            del preflight_plan
            if lease.provisional_detail is not None:
                raise ProcessingRefused(REASON_ATOMIC_MODE,
                                        lease.provisional_detail)
            result = _commit_eligibility_one(
                data_home, lease, facts, payload, fit_parsed, decision_view,
                binding_sha, plan_holder, snapshot)
    except BaseException as exc:
        caught = exc
    finally:
        if lease is not None:
            lease.close()
        elif descriptors is not None:
            descriptors.close()
    if caught is None:
        assert result is not None
        return result
    if isinstance(caught, SystemExit):
        raise caught
    if not plan_holder:
        if isinstance(caught, ProcessingRefused):
            raise caught
        if isinstance(caught, (KeyboardInterrupt, _Interrupted)):
            raise ProcessingRefused(REASON_INTERRUPTED,
                                    "eligibility admission was interrupted") \
                from caught
        if isinstance(caught, sqlite3.Error):
            raise map_sqlite_read_error(caught) from caught
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            f"eligibility failed before any prospective write plan: "
            f"{caught}") from caught
    plan, payload_for_recovery = plan_holder[0]
    recovered = recover_eligibility_durable_truth(data_home, envelope_name,
                                                  plan)
    del payload_for_recovery
    if recovered.disposition == RECOVERY_DURABLE_COMPLETE:
        assert recovered.stored_receipt_bytes is not None
        return recovered.stored_receipt_bytes
    if recovered.disposition == RECOVERY_DURABLE_EMPTY:
        if isinstance(caught, ProcessingRefused):
            raise caught
        if isinstance(caught, (KeyboardInterrupt, _Interrupted)):
            raise ProcessingRefused(
                REASON_INTERRUPTED,
                "eligibility transaction was interrupted") from caught
        if isinstance(caught, sqlite3.Error):
            raise map_sqlite_read_error(caught) from caught
        raise ProcessingRefused(
            REASON_ATOMIC_MODE,
            "eligibility transaction failed before durable commit: "
            f"{caught}") from caught
    raise ProcessingRefused(REASON_RECOVERY_INCOHERENT, recovered.detail)


def _reverify_locked_eligibility_authority(
    data_home: Path, facts: EligibilityEnvelopeFacts,
    payload: dict[str, Any], snapshot: Any,
    connection: sqlite3.Connection, lease: "_AdmissionLease", *,
    label: str, expect_fit: dict[str, Any] | None = None,
    cited_walk: Any = None,
) -> dict[str, Any]:
    """Repeat every contracted mutable-authority check under the lock."""

    assert lease.connection is not None and lease.assessments is not None         and lease.vacancy is not None
    merged, collector_plan = _verify_live_config_binding(data_home, facts)
    if str(collector_plan["database"]) != facts.vacancy.path:
        raise ProcessingRefused(
            ELIGIBILITY_REASON_CONFIG_DATABASE,
            f"{label}: planned collector database differs from the staged "
            "vacancy path")
    try:
        snapshot.revalidate()
    except ProcessingRefused:
        raise
    except (ValueError, OSError) as exc:
        raise ProcessingRefused(ELIGIBILITY_REASON_CANDIDATE_EVIDENCE,
                                f"{label}: committed generation drifted: "
                                f"{exc}") from exc
    if cited_walk is not None:
        cited_walk(payload["candidate_facts"])
    refetched = bind_fit_authority(connection, facts, payload)
    _validate_current_raw_against_fit(connection, refetched)
    if expect_fit is not None and refetched != expect_fit:
        raise ProcessingRefused(ELIGIBILITY_REASON_FIT_RECEIPT,
                                f"{label}: the bound FIT graph changed")
    return refetched


def _commit_eligibility_one(
    data_home: Path, lease: _AdmissionLease, facts: EligibilityEnvelopeFacts,
    payload: dict[str, Any], fit_parsed: dict[str, Any],
    decision_view: dict[str, Any], binding_sha: str,
    plan_holder: list[tuple[EligibilityProspectivePlan, dict[str, Any]]],
    snapshot: Any,
) -> bytes:
    assert lease.connection is not None and lease.assessments is not None \
        and lease.vacancy is not None
    connection = lease.connection

    def revalidate_authority(*, allow_db_change: bool) -> None:
        _verify_transaction_connection(
            connection, lease.descriptors, lease.assessments, lease.vacancy,
            allow_database_size_change=allow_db_change)

    revalidate_authority(allow_db_change=False)
    conflict = connection.execute(
        "SELECT operation_id FROM eligibility_receipts WHERE "
        "fit_operation_id=? AND operation_id<>?",
        (facts.fit_operation_id, facts.operation_id)).fetchone()         if _eligibility_table_exists(connection) else None
    if conflict is not None:
        raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                "another operation already targets this FIT "
                                "receipt")
    own = _classify_own_receipt(connection, facts, binding_sha)
    if own is not None:
        assert own.stored_receipt_bytes is not None
        return own.stored_receipt_bytes
    events_before = classify_processing_score_event(
        connection, profile_id=facts.profile_id, job_key=facts.job_key,
        event_type=EVENT_TYPE_ELIGIBILITY_DECIDED)
    if events_before.action != "insert_required":
        raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                "an eligibility_decided event already exists "
                                "for this profile/job")
    connection.execute("PRAGMA query_only=OFF")
    setup_transaction_sqlite(connection)
    revalidate_authority(allow_db_change=True)
    # Contract 14.8 step 4: full config/database/raw/profile/FIT recheck
    # after SQLite setup and BEFORE BEGIN (not descriptor-only).
    _reverify_locked_eligibility_authority(
        data_home, facts, payload, snapshot, connection,
        lease, label="pre_begin", expect_fit=fit_parsed)
    _maybe_fault("elig_lock_inject")
    connection.execute("BEGIN IMMEDIATE")
    try:
        locked_store = _inspect_eligibility_store(
            connection, facts.fit_operation_id, facts.operation_id)
        if locked_store.disposition ==                 DISPOSITION_PROVISIONAL_ATOMIC_INCOMPATIBILITY:
            raise ProcessingRefused(REASON_ATOMIC_MODE,
                                    locked_store.detail)
        conflict_again = connection.execute(
            "SELECT operation_id FROM eligibility_receipts WHERE "
            "fit_operation_id=? AND operation_id<>?",
            (facts.fit_operation_id, facts.operation_id)).fetchone()             if _eligibility_table_exists(connection) else None
        if conflict_again is not None:
            raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                    "another operation won this FIT target "
                                    "under lock")
        events_under_lock = classify_processing_score_event(
            connection, profile_id=facts.profile_id, job_key=facts.job_key,
            event_type=EVENT_TYPE_ELIGIBILITY_DECIDED)
        if events_under_lock.action != "insert_required":
            raise ProcessingRefused(ELIGIBILITY_REASON_TARGET_CONFLICT,
                                    "an eligibility_decided event already "
                                    "exists for this profile/job")
        own_again = _classify_own_receipt(connection, facts, binding_sha)
        if own_again is not None:
            connection.rollback()
            assert own_again.stored_receipt_bytes is not None
            return own_again.stored_receipt_bytes
        revalidate_authority(allow_db_change=True)
        refetched = _reverify_locked_eligibility_authority(
            data_home, facts, payload, snapshot, connection,
            lease, label="under_lock")
        accepted_at = datetime.now(timezone.utc).isoformat(
            timespec="microseconds").replace("+00:00", "Z")
        transaction_plan = build_eligibility_prospective_plan(
            facts=facts, payload=payload, binding_sha256=binding_sha,
            decision_view=decision_view, accepted_at=accepted_at,
            prospective_event_id=_prospective_event_id(connection),
            fit_parsed=refetched)
        sealed_plan = build_eligibility_prospective_plan(
            facts=facts, payload=payload, binding_sha256=binding_sha,
            decision_view=decision_view,
            accepted_at=_ELIGIBILITY_SENTINEL_TIMESTAMP,
            prospective_event_id=transaction_plan.event_id,
            fit_parsed=refetched)
        for column, idx in _ELIG_IDX.items():
            if idx in _ELIG_VOLATILE_IDX:
                continue
            if sealed_plan.receipt_row_values[idx] != \
                    transaction_plan.receipt_row_values[idx]:
                raise ProcessingRefused(
                    ELIGIBILITY_REASON_DECISION_RECONSTRUCTION,
                    f"transaction plan column {column} changed between "
                    "preflight and transaction")
        plan_holder.append((transaction_plan, payload))
        outcome = apply_eligibility_transaction_plan(connection,
                                                     transaction_plan)
        _maybe_fault("elig_pre_commit_inject")
        _reverify_locked_eligibility_authority(
            data_home, facts, payload, snapshot, connection,
            lease, label="pre_commit", expect_fit=refetched)
        revalidate_authority(allow_db_change=True)
        connection.commit()
        return outcome
    except BaseException:
        if connection.in_transaction:
            with contextlib.suppress(sqlite3.Error):
                connection.rollback()
        raise
