"""Deterministic control and audit records around the full Scrapling runtime.

The actual network, browser, stealth, session and spider capabilities live in
the pinned Scrapling sidecar.  This module does not reimplement or reduce them;
it records which engine was selected, immutable response evidence and adaptive
selector decisions while deterministic downstream scoring remains unchanged.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


_HASH = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")


def _require_hash(value: str, name: str) -> None:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


class FetchPolicyError(RuntimeError):
    """A fetch record conflicts with immutable policy or existing history."""


class FetchEngine(str, Enum):
    DIRECT_ADAPTER = "direct_adapter"
    PUBLIC_HTTP = "public_http"
    DYNAMIC_BROWSER = "dynamic_browser"
    STEALTH_BROWSER = "stealth_browser"


class FetchOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    TRANSIENT_FAILURE = "transient_failure"
    INCOMPLETE_CONTENT = "incomplete_content"
    JAVASCRIPT_REQUIRED = "javascript_required"
    INVALID_CONTENT = "invalid_content"
    NOT_FOUND_OR_EXPIRED = "not_found_or_expired"
    ACCESS_DENIED = "access_denied"
    AUTHENTICATION_REQUIRED = "authentication_required"
    CAPTCHA_REQUIRED = "captcha_required"
    ROBOTS_DISALLOWED = "robots_disallowed"
    AUTOMATION_PROHIBITED = "automation_prohibited"
    POLICY_DENIED = "policy_denied"


class FetchAction(str, Enum):
    RUN = "run"
    RETRY = "retry"
    ESCALATE = "escalate"
    ACCEPT = "accept"
    BLOCK = "block"
    EXHAUST = "exhaust"


_TERMINAL_OUTCOMES = frozenset({
    FetchOutcome.NOT_FOUND_OR_EXPIRED,
    FetchOutcome.ACCESS_DENIED,
    FetchOutcome.AUTHENTICATION_REQUIRED,
    FetchOutcome.CAPTCHA_REQUIRED,
    FetchOutcome.ROBOTS_DISALLOWED,
    FetchOutcome.AUTOMATION_PROHIBITED,
    FetchOutcome.POLICY_DENIED,
})

_ESCALATABLE_OUTCOMES = frozenset({
    FetchOutcome.TRANSIENT_FAILURE,
    FetchOutcome.INCOMPLETE_CONTENT,
    FetchOutcome.JAVASCRIPT_REQUIRED,
    FetchOutcome.INVALID_CONTENT,
})


@dataclass(frozen=True)
class FetchStage:
    engine: FetchEngine
    max_attempts: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not isinstance(self.engine, FetchEngine):
            raise TypeError("engine must be a FetchEngine")
        if not isinstance(self.max_attempts, int) or not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be between 1 and 10")
        if not isinstance(self.timeout_seconds, (int, float)) or not math.isfinite(
            self.timeout_seconds
        ) or not 0 < self.timeout_seconds <= 300:
            raise ValueError("timeout_seconds must be finite and between 0 and 300")

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine.value,
            "max_attempts": self.max_attempts,
            "timeout_seconds": float(self.timeout_seconds),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FetchStage":
        return cls(
            FetchEngine(str(value["engine"])),
            int(value["max_attempts"]),
            float(value["timeout_seconds"]),
        )


@dataclass(frozen=True)
class FetchPolicy:
    policy_id: str
    version: str
    stages: tuple[FetchStage, ...]
    require_raw_snapshot: bool = True

    def __post_init__(self) -> None:
        _require_identifier(self.policy_id, "policy_id")
        _require_identifier(self.version, "version")
        object.__setattr__(self, "stages", tuple(self.stages))
        if not self.stages:
            raise ValueError("fetch policy requires at least one stage")
        if not all(isinstance(stage, FetchStage) for stage in self.stages):
            raise TypeError("stages must contain FetchStage values")
        engines = tuple(stage.engine for stage in self.stages)
        if len(set(engines)) != len(engines):
            raise ValueError("fetch policy cannot repeat an engine")
        expected = (
            FetchEngine.DIRECT_ADAPTER,
            FetchEngine.PUBLIC_HTTP,
            FetchEngine.DYNAMIC_BROWSER,
            FetchEngine.STEALTH_BROWSER,
        )
        positions = tuple(expected.index(engine) for engine in engines)
        if positions != tuple(sorted(positions)):
            raise ValueError("fetch engines must progress from direct to browser")

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "stages": [stage.to_dict() for stage in self.stages],
            "require_raw_snapshot": self.require_raw_snapshot,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FetchPolicy":
        return cls(
            policy_id=str(value["policy_id"]),
            version=str(value["version"]),
            stages=tuple(FetchStage.from_dict(row) for row in value["stages"]),
            require_raw_snapshot=bool(value.get("require_raw_snapshot", True)),
        )

    @property
    def content_hash(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


def default_job_fetch_policy() -> FetchPolicy:
    """Return the non-evasive, content-addressed vacancy fetch policy."""
    return FetchPolicy(
        policy_id="career.job_fetch",
        version="3.0.0",
        stages=(
            FetchStage(FetchEngine.DIRECT_ADAPTER, 2, 30),
            FetchStage(FetchEngine.PUBLIC_HTTP, 2, 45),
            FetchStage(FetchEngine.DYNAMIC_BROWSER, 1, 90),
        ),
    )


@dataclass(frozen=True)
class FetchAttempt:
    attempt_id: str
    resource_key: str
    policy_hash: str
    sequence_no: int
    stage_index: int
    engine: FetchEngine
    requested_url: str
    final_url: str | None
    started_at: str
    elapsed_ms: int
    outcome: FetchOutcome
    status_code: int | None = None
    response_bytes: int = 0
    content_sha256: str | None = None
    raw_snapshot_ref: str | None = None
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("attempt_id", "resource_key"):
            _require_identifier(str(getattr(self, name)), name)
        _require_hash(self.policy_hash, "policy_hash")
        if not isinstance(self.sequence_no, int) or self.sequence_no < 1:
            raise ValueError("sequence_no must be a positive integer")
        if not isinstance(self.stage_index, int) or self.stage_index < 0:
            raise ValueError("stage_index must be non-negative")
        if not isinstance(self.engine, FetchEngine):
            raise TypeError("engine must be a FetchEngine")
        if not isinstance(self.outcome, FetchOutcome):
            raise TypeError("outcome must be a FetchOutcome")
        if not isinstance(self.requested_url, str) or not self.requested_url:
            raise ValueError("requested_url must be non-empty")
        if self.final_url is not None and not self.final_url:
            raise ValueError("final_url cannot be empty")
        if not isinstance(self.started_at, str) or not self.started_at:
            raise ValueError("started_at must be non-empty")
        if not isinstance(self.elapsed_ms, int) or self.elapsed_ms < 0:
            raise ValueError("elapsed_ms must be a non-negative integer")
        if self.status_code is not None and not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be between 100 and 599")
        if not isinstance(self.response_bytes, int) or self.response_bytes < 0:
            raise ValueError("response_bytes must be non-negative")
        if self.content_sha256 is not None:
            _require_hash(self.content_sha256, "content_sha256")
        if self.raw_snapshot_ref is not None:
            _require_identifier(self.raw_snapshot_ref, "raw_snapshot_ref")
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        if any(not isinstance(row, str) or not row or len(row) > 512 for row in self.diagnostics):
            raise ValueError("diagnostics must contain bounded non-empty strings")
        if self.outcome is FetchOutcome.SUCCEEDED:
            if self.content_sha256 is None or self.raw_snapshot_ref is None:
                raise ValueError("successful fetch requires content hash and raw snapshot reference")
            if self.status_code is not None and not 200 <= self.status_code <= 299:
                raise ValueError("successful HTTP fetch requires a 2xx status")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "resource_key": self.resource_key,
            "policy_hash": self.policy_hash,
            "sequence_no": self.sequence_no,
            "stage_index": self.stage_index,
            "engine": self.engine.value,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "started_at": self.started_at,
            "elapsed_ms": self.elapsed_ms,
            "outcome": self.outcome.value,
            "status_code": self.status_code,
            "response_bytes": self.response_bytes,
            "content_sha256": self.content_sha256,
            "raw_snapshot_ref": self.raw_snapshot_ref,
            "diagnostics": list(self.diagnostics),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FetchAttempt":
        return cls(
            attempt_id=str(value["attempt_id"]),
            resource_key=str(value["resource_key"]),
            policy_hash=str(value["policy_hash"]),
            sequence_no=int(value["sequence_no"]),
            stage_index=int(value["stage_index"]),
            engine=FetchEngine(str(value["engine"])),
            requested_url=str(value["requested_url"]),
            final_url=str(value["final_url"]) if value.get("final_url") is not None else None,
            started_at=str(value["started_at"]),
            elapsed_ms=int(value["elapsed_ms"]),
            outcome=FetchOutcome(str(value["outcome"])),
            status_code=int(value["status_code"]) if value.get("status_code") is not None else None,
            response_bytes=int(value.get("response_bytes", 0)),
            content_sha256=(
                str(value["content_sha256"]) if value.get("content_sha256") is not None else None
            ),
            raw_snapshot_ref=(
                str(value["raw_snapshot_ref"]) if value.get("raw_snapshot_ref") is not None else None
            ),
            diagnostics=tuple(str(row) for row in value.get("diagnostics", ())),
        )

    @property
    def record_hash(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class FetchDecision:
    action: FetchAction
    reason: str
    engine: FetchEngine | None = None
    stage_index: int | None = None
    attempt_number: int | None = None


class FetchEscalationMachine:
    """Pure state machine; it never performs network or browser work."""

    def __init__(self, policy: FetchPolicy) -> None:
        self.policy = policy

    def decide(self, attempts: Sequence[FetchAttempt]) -> FetchDecision:
        rows = tuple(attempts)
        self._validate_history(rows)
        if not rows:
            return self._run(FetchAction.RUN, 0, 1, "start with the cheapest configured engine")

        latest = rows[-1]
        if latest.outcome is FetchOutcome.SUCCEEDED:
            return FetchDecision(FetchAction.ACCEPT, "immutable raw snapshot captured")
        if latest.outcome in _TERMINAL_OUTCOMES:
            return FetchDecision(FetchAction.BLOCK, f"terminal policy state: {latest.outcome.value}")

        stage = self.policy.stages[latest.stage_index]
        used = sum(1 for row in rows if row.stage_index == latest.stage_index)
        if latest.outcome is FetchOutcome.TRANSIENT_FAILURE and used < stage.max_attempts:
            return self._run(FetchAction.RETRY, latest.stage_index, used + 1, "bounded transient retry")

        if latest.outcome not in _ESCALATABLE_OUTCOMES:
            return FetchDecision(FetchAction.BLOCK, f"unclassified outcome: {latest.outcome.value}")

        next_stage = latest.stage_index + 1
        if next_stage >= len(self.policy.stages):
            return FetchDecision(FetchAction.EXHAUST, "all permitted fetch engines exhausted")
        return self._run(
            FetchAction.ESCALATE,
            next_stage,
            1,
            f"{latest.outcome.value} permits one-way escalation",
        )

    def _run(
        self, action: FetchAction, stage_index: int, attempt_number: int, reason: str
    ) -> FetchDecision:
        return FetchDecision(
            action=action,
            reason=reason,
            engine=self.policy.stages[stage_index].engine,
            stage_index=stage_index,
            attempt_number=attempt_number,
        )

    def _validate_history(self, attempts: tuple[FetchAttempt, ...]) -> None:
        stage_counts: dict[int, int] = {}
        for index, attempt in enumerate(attempts, start=1):
            if attempt.policy_hash != self.policy.content_hash:
                raise FetchPolicyError("attempt belongs to a different fetch policy")
            if attempt.sequence_no != index:
                raise FetchPolicyError("attempt history is not contiguous")
            if attempt.stage_index >= len(self.policy.stages):
                raise FetchPolicyError("attempt references an unknown policy stage")
            if self.policy.stages[attempt.stage_index].engine is not attempt.engine:
                raise FetchPolicyError("attempt engine does not match its policy stage")
            if index > 1 and attempt.stage_index < attempts[index - 2].stage_index:
                raise FetchPolicyError("fetch history cannot move back to a cheaper stage")
            if index > 1 and attempt.stage_index > attempts[index - 2].stage_index + 1:
                raise FetchPolicyError("fetch history cannot skip a configured stage")
            stage_counts[attempt.stage_index] = stage_counts.get(attempt.stage_index, 0) + 1
            if stage_counts[attempt.stage_index] > self.policy.stages[
                attempt.stage_index
            ].max_attempts:
                raise FetchPolicyError("fetch history exceeds a stage retry limit")
        if len({row.resource_key for row in attempts}) > 1:
            raise FetchPolicyError("attempt history mixes resource keys")


def _normalise_text(value: str) -> str:
    return " ".join(value.casefold().split())[:2048]


@dataclass(frozen=True)
class ElementFingerprint:
    locator_key: str
    tag: str
    attributes: tuple[tuple[str, str], ...] = ()
    text: str = ""
    ancestor_tags: tuple[str, ...] = ()
    sibling_tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.locator_key, "locator_key")
        if not isinstance(self.tag, str) or not self.tag.strip():
            raise ValueError("tag must be non-empty")
        attrs = tuple(sorted((str(k).casefold(), str(v).strip()) for k, v in self.attributes))
        if len(attrs) != len({key for key, _ in attrs}):
            raise ValueError("fingerprint attributes cannot repeat keys")
        if any(not key or not value or len(key) > 128 or len(value) > 1024 for key, value in attrs):
            raise ValueError("fingerprint attributes must be bounded and non-empty")
        object.__setattr__(self, "tag", self.tag.casefold().strip())
        object.__setattr__(self, "attributes", attrs)
        object.__setattr__(self, "text", _normalise_text(self.text))
        object.__setattr__(self, "ancestor_tags", tuple(str(v).casefold() for v in self.ancestor_tags[:16]))
        object.__setattr__(self, "sibling_tags", tuple(str(v).casefold() for v in self.sibling_tags[:32]))

    def to_dict(self) -> dict[str, Any]:
        return {
            "locator_key": self.locator_key,
            "tag": self.tag,
            "attributes": [list(row) for row in self.attributes],
            "text": self.text,
            "ancestor_tags": list(self.ancestor_tags),
            "sibling_tags": list(self.sibling_tags),
        }

    @property
    def content_hash(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


class RelocationStatus(str, Enum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class RelocationPolicy:
    minimum_score: float = 0.78
    minimum_margin: float = 0.10
    maximum_candidates: int = 2000

    def __post_init__(self) -> None:
        if not 0 <= self.minimum_score <= 1:
            raise ValueError("minimum_score must be between zero and one")
        if not 0 <= self.minimum_margin <= 1:
            raise ValueError("minimum_margin must be between zero and one")
        if not 1 <= self.maximum_candidates <= 10000:
            raise ValueError("maximum_candidates must be between 1 and 10000")


@dataclass(frozen=True)
class RelocationDecision:
    source_fingerprint_hash: str
    status: RelocationStatus
    selected_locator_key: str | None
    top_score: float
    runner_up_score: float | None
    candidate_scores: tuple[tuple[str, float], ...]

    def __post_init__(self) -> None:
        _require_hash(self.source_fingerprint_hash, "source_fingerprint_hash")
        if not isinstance(self.status, RelocationStatus):
            raise TypeError("status must be a RelocationStatus")
        if self.selected_locator_key is not None:
            _require_identifier(self.selected_locator_key, "selected_locator_key")
        if self.status is RelocationStatus.MATCHED and self.selected_locator_key is None:
            raise ValueError("matched relocation requires a selected locator")
        if self.status is not RelocationStatus.MATCHED and self.selected_locator_key is not None:
            raise ValueError("non-matched relocation cannot select a locator")
        if not 0 <= self.top_score <= 1:
            raise ValueError("top_score must be between zero and one")
        if self.runner_up_score is not None and not 0 <= self.runner_up_score <= 1:
            raise ValueError("runner_up_score must be between zero and one")
        object.__setattr__(self, "candidate_scores", tuple(self.candidate_scores))
        if len({key for key, _ in self.candidate_scores}) != len(self.candidate_scores):
            raise ValueError("candidate_scores cannot repeat locator keys")
        for key, score in self.candidate_scores:
            _require_identifier(key, "candidate locator key")
            if not 0 <= score <= 1:
                raise ValueError("candidate score must be between zero and one")
        if self.selected_locator_key is not None and self.selected_locator_key not in {
            key for key, _ in self.candidate_scores
        }:
            raise ValueError("selected locator must appear in candidate_scores")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_fingerprint_hash": self.source_fingerprint_hash,
            "status": self.status.value,
            "selected_locator_key": self.selected_locator_key,
            "top_score": self.top_score,
            "runner_up_score": self.runner_up_score,
            "candidate_scores": [list(row) for row in self.candidate_scores],
        }

    @property
    def content_hash(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


def _attribute_similarity(
    source: tuple[tuple[str, str], ...], candidate: tuple[tuple[str, str], ...]
) -> float:
    left, right = dict(source), dict(candidate)
    keys = set(left) | set(right)
    if not keys:
        return 1.0
    total = 0.0
    for key in keys:
        if key not in left or key not in right:
            continue
        total += SequenceMatcher(None, left[key].casefold(), right[key].casefold()).ratio()
    return total / len(keys)


def fingerprint_similarity(source: ElementFingerprint, candidate: ElementFingerprint) -> float:
    """Return a deterministic 0..1 similarity score with explicit weights."""
    components = [(0.18, float(source.tag == candidate.tag))]
    if source.attributes:
        components.append((0.42, _attribute_similarity(source.attributes, candidate.attributes)))
    if source.text:
        components.append((0.20, SequenceMatcher(None, source.text, candidate.text).ratio()))
    if source.ancestor_tags:
        components.append((
            0.12, SequenceMatcher(None, source.ancestor_tags, candidate.ancestor_tags).ratio()
        ))
    if source.sibling_tags:
        components.append((
            0.08, SequenceMatcher(None, source.sibling_tags, candidate.sibling_tags).ratio()
        ))
    total_weight = sum(weight for weight, _ in components)
    return round(sum(weight * score for weight, score in components) / total_weight, 6)


def relocate_fingerprint(
    source: ElementFingerprint,
    candidates: Sequence[ElementFingerprint],
    policy: RelocationPolicy = RelocationPolicy(),
) -> RelocationDecision:
    """Choose only a unique, high-confidence candidate; never mutate selectors."""
    rows = tuple(candidates)
    available_signals = sum(bool(value) for value in (
        source.tag,
        source.attributes,
        source.text,
        source.ancestor_tags,
        source.sibling_tags,
    ))
    if available_signals < 3:
        raise ValueError("source fingerprint has insufficient independent signals")
    if len(rows) > policy.maximum_candidates:
        raise ValueError("candidate limit exceeded")
    if len({row.locator_key for row in rows}) != len(rows):
        raise ValueError("candidate locator keys must be unique")
    scored = tuple(sorted(
        ((row.locator_key, fingerprint_similarity(source, row)) for row in rows),
        key=lambda row: (-row[1], row[0]),
    ))
    top = scored[0][1] if scored else 0.0
    runner = scored[1][1] if len(scored) > 1 else None
    if not scored or top < policy.minimum_score:
        status, selected = RelocationStatus.NO_MATCH, None
    elif runner is not None and top - runner < policy.minimum_margin:
        status, selected = RelocationStatus.AMBIGUOUS, None
    else:
        status, selected = RelocationStatus.MATCHED, scored[0][0]
    return RelocationDecision(
        source_fingerprint_hash=source.content_hash,
        status=status,
        selected_locator_key=selected,
        top_score=top,
        runner_up_score=runner,
        candidate_scores=scored,
    )


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=30000;

CREATE TABLE IF NOT EXISTS ca_fetch_policies (
  policy_hash TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  definition_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ca_fetch_attempts (
  attempt_id TEXT PRIMARY KEY,
  resource_key TEXT NOT NULL,
  policy_hash TEXT NOT NULL REFERENCES ca_fetch_policies(policy_hash),
  sequence_no INTEGER NOT NULL,
  stage_index INTEGER NOT NULL,
  engine TEXT NOT NULL,
  outcome TEXT NOT NULL,
  record_json TEXT NOT NULL,
  record_hash TEXT NOT NULL,
  UNIQUE(resource_key, policy_hash, sequence_no)
);
CREATE INDEX IF NOT EXISTS ca_fetch_attempts_resource
  ON ca_fetch_attempts(resource_key,policy_hash,sequence_no);

CREATE TABLE IF NOT EXISTS ca_fetch_selector_fingerprints (
  fingerprint_hash TEXT PRIMARY KEY,
  site_host TEXT NOT NULL,
  workflow_hash TEXT NOT NULL,
  step_id TEXT NOT NULL,
  fingerprint_version TEXT NOT NULL,
  fingerprint_json TEXT NOT NULL,
  UNIQUE(site_host,workflow_hash,step_id,fingerprint_version)
);

CREATE TABLE IF NOT EXISTS ca_fetch_relocations (
  decision_hash TEXT PRIMARY KEY,
  source_fingerprint_hash TEXT NOT NULL REFERENCES ca_fetch_selector_fingerprints(fingerprint_hash),
  observed_snapshot_hash TEXT NOT NULL,
  decision_json TEXT NOT NULL
);
"""


class FetchControlStore:
    """Immutable SQLite ledger for fetch attempts and selector-drift decisions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.executescript(_SCHEMA)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def register_policy(self, policy: FetchPolicy) -> bool:
        definition = _canonical_json(policy.to_dict())
        with self.connection() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO ca_fetch_policies VALUES(?,?,?,?)",
                (policy.content_hash, policy.policy_id, policy.version, definition),
            )
            if cursor.rowcount == 1:
                return True
            row = connection.execute(
                "SELECT definition_json FROM ca_fetch_policies WHERE policy_hash=?",
                (policy.content_hash,),
            ).fetchone()
            if row is None or row["definition_json"] != definition:
                raise FetchPolicyError("fetch policy hash collision")
            return False

    def record_attempt(self, attempt: FetchAttempt) -> bool:
        payload = _canonical_json(attempt.to_dict())
        with self.connection() as connection:
            policy_row = connection.execute(
                "SELECT definition_json FROM ca_fetch_policies WHERE policy_hash=?",
                (attempt.policy_hash,),
            ).fetchone()
            if policy_row is None:
                raise FetchPolicyError("fetch policy must be registered first")
            policy = FetchPolicy.from_dict(json.loads(policy_row["definition_json"]))
            if attempt.stage_index >= len(policy.stages) or policy.stages[
                attempt.stage_index
            ].engine is not attempt.engine:
                raise FetchPolicyError("attempt does not match its registered policy stage")
            existing = connection.execute(
                "SELECT record_hash FROM ca_fetch_attempts WHERE attempt_id=?",
                (attempt.attempt_id,),
            ).fetchone()
            if existing is not None:
                if existing["record_hash"] != attempt.record_hash:
                    raise FetchPolicyError("attempt identity reused with different content")
                return False
            next_no = connection.execute(
                """SELECT COALESCE(MAX(sequence_no),0)+1
                   FROM ca_fetch_attempts WHERE resource_key=? AND policy_hash=?""",
                (attempt.resource_key, attempt.policy_hash),
            ).fetchone()[0]
            if attempt.sequence_no != next_no:
                raise FetchPolicyError("attempt sequence is not contiguous")
            history_rows = connection.execute(
                """SELECT record_json FROM ca_fetch_attempts
                   WHERE resource_key=? AND policy_hash=? ORDER BY sequence_no""",
                (attempt.resource_key, attempt.policy_hash),
            ).fetchall()
            history = tuple(
                FetchAttempt.from_dict(json.loads(row["record_json"]))
                for row in history_rows
            )
            decision = FetchEscalationMachine(policy).decide(history)
            if decision.action not in {
                FetchAction.RUN,
                FetchAction.RETRY,
                FetchAction.ESCALATE,
            } or decision.stage_index != attempt.stage_index or decision.engine is not attempt.engine:
                raise FetchPolicyError("attempt is not authorized by the current fetch decision")
            connection.execute(
                """INSERT INTO ca_fetch_attempts(
                     attempt_id,resource_key,policy_hash,sequence_no,stage_index,
                     engine,outcome,record_json,record_hash
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    attempt.attempt_id,
                    attempt.resource_key,
                    attempt.policy_hash,
                    attempt.sequence_no,
                    attempt.stage_index,
                    attempt.engine.value,
                    attempt.outcome.value,
                    payload,
                    attempt.record_hash,
                ),
            )
            return True

    def attempts(self, resource_key: str, policy_hash: str) -> tuple[FetchAttempt, ...]:
        _require_identifier(resource_key, "resource_key")
        _require_hash(policy_hash, "policy_hash")
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT record_json FROM ca_fetch_attempts
                   WHERE resource_key=? AND policy_hash=? ORDER BY sequence_no""",
                (resource_key, policy_hash),
            ).fetchall()
        return tuple(FetchAttempt.from_dict(json.loads(row["record_json"])) for row in rows)

    def register_fingerprint(
        self,
        *,
        site_host: str,
        workflow_hash: str,
        step_id: str,
        version: str,
        fingerprint: ElementFingerprint,
    ) -> bool:
        for name, value in (("site_host", site_host), ("step_id", step_id), ("version", version)):
            _require_identifier(value, name)
        _require_hash(workflow_hash, "workflow_hash")
        payload = _canonical_json(fingerprint.to_dict())
        with self.connection() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO ca_fetch_selector_fingerprints(
                     fingerprint_hash,site_host,workflow_hash,step_id,
                     fingerprint_version,fingerprint_json
                   ) VALUES(?,?,?,?,?,?)""",
                (fingerprint.content_hash, site_host, workflow_hash, step_id, version, payload),
            )
            if cursor.rowcount == 1:
                return True
            row = connection.execute(
                """SELECT site_host,workflow_hash,step_id,fingerprint_version,
                          fingerprint_json FROM ca_fetch_selector_fingerprints
                   WHERE fingerprint_hash=?""",
                (fingerprint.content_hash,),
            ).fetchone()
            if row is None:
                raise FetchPolicyError("fingerprint identity reused with different content")
            expected = (site_host, workflow_hash, step_id, version, payload)
            actual = (
                row["site_host"],
                row["workflow_hash"],
                row["step_id"],
                row["fingerprint_version"],
                row["fingerprint_json"],
            )
            if actual != expected:
                raise FetchPolicyError("fingerprint content reused across a different registration")
            return False

    def record_relocation(
        self, decision: RelocationDecision, *, observed_snapshot_hash: str
    ) -> bool:
        _require_hash(observed_snapshot_hash, "observed_snapshot_hash")
        payload = _canonical_json(decision.to_dict())
        with self.connection() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO ca_fetch_relocations VALUES(?,?,?,?)",
                (
                    decision.content_hash,
                    decision.source_fingerprint_hash,
                    observed_snapshot_hash,
                    payload,
                ),
            )
            if cursor.rowcount == 1:
                return True
            row = connection.execute(
                "SELECT decision_json,observed_snapshot_hash FROM ca_fetch_relocations WHERE decision_hash=?",
                (decision.content_hash,),
            ).fetchone()
            if row is None or row["decision_json"] != payload or row[
                "observed_snapshot_hash"
            ] != observed_snapshot_hash:
                raise FetchPolicyError("relocation identity reused with different content")
            return False


__all__ = [
    "ElementFingerprint",
    "FetchAction",
    "FetchAttempt",
    "FetchControlStore",
    "FetchDecision",
    "FetchEngine",
    "FetchEscalationMachine",
    "FetchOutcome",
    "FetchPolicy",
    "FetchPolicyError",
    "FetchStage",
    "RelocationDecision",
    "RelocationPolicy",
    "RelocationStatus",
    "default_job_fetch_policy",
    "fingerprint_similarity",
    "relocate_fingerprint",
]
