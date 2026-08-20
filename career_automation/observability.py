"""Versioned workflow definitions, operation telemetry, and a durable outbox.

The module deliberately uses only the Python standard library.  It can point at the
same SQLite file as :mod:`career_automation.database`; every table is namespaced with
``ca_obs_`` so the observability lifecycle remains independent of pipeline state.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMPONENT_KINDS = frozenset({"deterministic", "probabilistic", "external"})
_OPERATION_STATUSES = frozenset(
    {"queued", "running", "succeeded", "failed", "cancelled", "skipped"}
)
_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled", "skipped"})
_OUTBOX_STATUSES = frozenset({"queued", "leased", "acked", "dead"})


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _require_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(
            f"{field_name} must be 1-255 characters using letters, numbers, . _ : / or -"
        )
    return value


def _require_text(value: str, field_name: str, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be non-empty")
    if len(value) > maximum:
        raise ValueError(f"{field_name} exceeds {maximum} characters")
    return value


def _require_hash(value: str | None, field_name: str, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _validate_json(value: Any, path: str = "$") -> None:
    """Reject values whose JSON representation would be lossy or non-portable."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string object key")
            _validate_json(item, f"{path}.{key}")
        return
    raise ValueError(f"{path} contains non-JSON value {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Serialize JSON data in the canonical form used for identity and provenance."""
    _validate_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def hash_payload(value: Any) -> str:
    """Return a deterministic SHA-256 digest for a JSON-compatible value."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _json_copy(value: Any) -> Any:
    return json.loads(canonical_json(value))


@dataclass(frozen=True)
class ComponentContract:
    """Serializable input/output and side-effect contract for one component type."""

    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    side_effects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.input_schema, Mapping) or not isinstance(
            self.output_schema, Mapping
        ):
            raise ValueError("component schemas must be mappings")
        _validate_json(dict(self.input_schema), "$.input_schema")
        _validate_json(dict(self.output_schema), "$.output_schema")
        for side_effect in self.side_effects:
            _require_identifier(side_effect, "side_effect")

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_schema": _json_copy(dict(self.input_schema)),
            "output_schema": _json_copy(dict(self.output_schema)),
            "side_effects": list(self.side_effects),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ComponentContract":
        return cls(
            input_schema=dict(value.get("input_schema", {})),
            output_schema=dict(value.get("output_schema", {})),
            side_effects=tuple(value.get("side_effects", ())),
        )


@dataclass(frozen=True)
class ComponentDefinition:
    """A pinned component implementation and its runtime configuration."""

    component_id: str
    component_type: str
    version: str
    kind: str
    contract: ComponentContract
    configuration: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_identifier(self.component_id, "component_id")
        _require_identifier(self.component_type, "component_type")
        _require_text(self.version, "component version", maximum=128)
        if self.kind not in _COMPONENT_KINDS:
            raise ValueError(f"component kind must be one of {sorted(_COMPONENT_KINDS)}")
        if not isinstance(self.contract, ComponentContract):
            raise ValueError("contract must be a ComponentContract")
        if not isinstance(self.configuration, Mapping):
            raise ValueError("component configuration must be a mapping")
        _validate_json(dict(self.configuration), "$.configuration")

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "component_type": self.component_type,
            "version": self.version,
            "kind": self.kind,
            "contract": self.contract.to_dict(),
            "configuration": _json_copy(dict(self.configuration)),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ComponentDefinition":
        contract = value.get("contract")
        if not isinstance(contract, Mapping):
            raise ValueError("component contract must be an object")
        return cls(
            component_id=str(value.get("component_id", "")),
            component_type=str(value.get("component_type", "")),
            version=str(value.get("version", "")),
            kind=str(value.get("kind", "")),
            contract=ComponentContract.from_dict(contract),
            configuration=dict(value.get("configuration", {})),
        )


@dataclass(frozen=True)
class FlowStep:
    """One invocation in a directed acyclic workflow."""

    step_id: str
    component_id: str
    depends_on: tuple[str, ...] = ()
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_identifier(self.step_id, "step_id")
        _require_identifier(self.component_id, "component_id")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError(f"step {self.step_id!r} contains duplicate dependencies")
        for dependency in self.depends_on:
            _require_identifier(dependency, "dependency")
        if not isinstance(self.parameters, Mapping):
            raise ValueError("step parameters must be a mapping")
        _validate_json(dict(self.parameters), "$.parameters")

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "component_id": self.component_id,
            "depends_on": list(self.depends_on),
            "parameters": _json_copy(dict(self.parameters)),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FlowStep":
        return cls(
            step_id=str(value.get("step_id", "")),
            component_id=str(value.get("component_id", "")),
            depends_on=tuple(value.get("depends_on", ())),
            parameters=dict(value.get("parameters", {})),
        )


@dataclass(frozen=True)
class FlowDefinition:
    """Content-addressed, serializable definition of an executable DAG."""

    flow_id: str
    version: str
    components: tuple[ComponentDefinition, ...]
    steps: tuple[FlowStep, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_identifier(self.flow_id, "flow_id")
        _require_text(self.version, "flow version", maximum=128)
        if not self.components:
            raise ValueError("a flow requires at least one component")
        if not self.steps:
            raise ValueError("a flow requires at least one step")
        component_ids = [component.component_id for component in self.components]
        step_ids = [step.step_id for step in self.steps]
        if len(set(component_ids)) != len(component_ids):
            raise ValueError("component IDs must be unique within a flow")
        if len(set(step_ids)) != len(step_ids):
            raise ValueError("step IDs must be unique within a flow")
        known_components = set(component_ids)
        known_steps = set(step_ids)
        dependencies: dict[str, tuple[str, ...]] = {}
        for step in self.steps:
            if step.component_id not in known_components:
                raise ValueError(
                    f"step {step.step_id!r} references unknown component {step.component_id!r}"
                )
            unknown = set(step.depends_on) - known_steps
            if unknown:
                raise ValueError(
                    f"step {step.step_id!r} has unknown dependencies {sorted(unknown)}"
                )
            if step.step_id in step.depends_on:
                raise ValueError(f"step {step.step_id!r} cannot depend on itself")
            dependencies[step.step_id] = step.depends_on
        self._reject_cycles(dependencies)
        if not isinstance(self.metadata, Mapping):
            raise ValueError("flow metadata must be a mapping")
        _validate_json(dict(self.metadata), "$.metadata")

    @staticmethod
    def _reject_cycles(dependencies: Mapping[str, Sequence[str]]) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(step_id: str) -> None:
            if step_id in visiting:
                raise ValueError(f"flow contains a dependency cycle involving {step_id!r}")
            if step_id in visited:
                return
            visiting.add(step_id)
            for dependency in dependencies[step_id]:
                visit(dependency)
            visiting.remove(step_id)
            visited.add(step_id)

        for step_id in dependencies:
            visit(step_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "version": self.version,
            "components": [component.to_dict() for component in self.components],
            "steps": [step.to_dict() for step in self.steps],
            "metadata": _json_copy(dict(self.metadata)),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FlowDefinition":
        raw_components = value.get("components")
        raw_steps = value.get("steps")
        if not isinstance(raw_components, list) or not isinstance(raw_steps, list):
            raise ValueError("flow components and steps must be arrays")
        return cls(
            flow_id=str(value.get("flow_id", "")),
            version=str(value.get("version", "")),
            components=tuple(ComponentDefinition.from_dict(item) for item in raw_components),
            steps=tuple(FlowStep.from_dict(item) for item in raw_steps),
            metadata=dict(value.get("metadata", {})),
        )

    @classmethod
    def from_json(cls, value: str) -> "FlowDefinition":
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid flow JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("flow JSON must contain an object")
        return cls.from_dict(parsed)


def _validate_operation(
    *,
    operation: str,
    status: str,
    input_hash: str,
    output_hash: str | None,
    model_version: str | None,
    prompt_version: str | None,
    profile_version: str | None,
    started_at: datetime,
    ended_at: datetime | None,
    latency_ms: int | None,
    cost_usd: float,
    error_type: str | None,
) -> None:
    _require_identifier(operation, "operation")
    if status not in _OPERATION_STATUSES:
        raise ValueError(f"status must be one of {sorted(_OPERATION_STATUSES)}")
    _require_hash(input_hash, "input_hash")
    _require_hash(output_hash, "output_hash", optional=True)
    for name, version in (
        ("model_version", model_version),
        ("prompt_version", prompt_version),
        ("profile_version", profile_version),
    ):
        if version is not None:
            _require_text(version, name, maximum=255)
    start = _require_utc(started_at, "started_at")
    if ended_at is not None and _require_utc(ended_at, "ended_at") < start:
        raise ValueError("ended_at cannot precede started_at")
    if latency_ms is not None and (not isinstance(latency_ms, int) or latency_ms < 0):
        raise ValueError("latency_ms must be a non-negative integer")
    if not isinstance(cost_usd, (int, float)) or not math.isfinite(cost_usd) or cost_usd < 0:
        raise ValueError("cost_usd must be a finite non-negative number")
    if status == "succeeded" and error_type is not None:
        raise ValueError("a succeeded operation cannot have an error type")


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat() if value is not None else None


@dataclass(frozen=True)
class OperationTrace:
    """Top-level provenance and performance record for one flow execution."""

    trace_id: str
    flow_hash: str
    operation: str
    status: str
    input_hash: str
    output_hash: str | None = None
    model_version: str | None = None
    prompt_version: str | None = None
    profile_version: str | None = None
    started_at: datetime = field(default_factory=utc_now)
    ended_at: datetime | None = None
    latency_ms: int | None = None
    cost_usd: float = 0.0
    error_type: str | None = None
    error_message: str | None = None
    job_key: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_identifier(self.trace_id, "trace_id")
        _require_hash(self.flow_hash, "flow_hash")
        _validate_operation(
            operation=self.operation,
            status=self.status,
            input_hash=self.input_hash,
            output_hash=self.output_hash,
            model_version=self.model_version,
            prompt_version=self.prompt_version,
            profile_version=self.profile_version,
            started_at=self.started_at,
            ended_at=self.ended_at,
            latency_ms=self.latency_ms,
            cost_usd=self.cost_usd,
            error_type=self.error_type,
        )
        if self.error_type is not None:
            _require_identifier(self.error_type, "error_type")
        if self.error_message is not None and len(self.error_message) > 8192:
            raise ValueError("error_message exceeds 8192 characters")
        if self.job_key is not None:
            _require_identifier(self.job_key, "job_key")
        if not isinstance(self.metadata, Mapping):
            raise ValueError("trace metadata must be a mapping")
        _validate_json(dict(self.metadata), "$.metadata")

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "flow_hash": self.flow_hash,
            "operation": self.operation,
            "status": self.status,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "model_version": self.model_version,
            "prompt_version": self.prompt_version,
            "profile_version": self.profile_version,
            "started_at": _iso(self.started_at),
            "ended_at": _iso(self.ended_at),
            "latency_ms": self.latency_ms,
            "cost_usd": float(self.cost_usd),
            "error_type": self.error_type,
            "error_message": self.error_message,
            "job_key": self.job_key,
            "metadata": _json_copy(dict(self.metadata)),
        }


@dataclass(frozen=True)
class SpanRecord:
    """One component invocation within an operation trace."""

    span_id: str
    trace_id: str
    component_id: str
    component_version: str
    operation: str
    status: str
    input_hash: str
    idempotency_key: str
    output_hash: str | None = None
    model_version: str | None = None
    prompt_version: str | None = None
    profile_version: str | None = None
    started_at: datetime = field(default_factory=utc_now)
    ended_at: datetime | None = None
    latency_ms: int | None = None
    cost_usd: float = 0.0
    error_type: str | None = None
    error_message: str | None = None
    parent_span_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_identifier(self.span_id, "span_id")
        _require_identifier(self.trace_id, "trace_id")
        _require_identifier(self.component_id, "component_id")
        _require_text(self.component_version, "component_version", maximum=128)
        _require_identifier(self.idempotency_key, "idempotency_key")
        if self.parent_span_id is not None:
            _require_identifier(self.parent_span_id, "parent_span_id")
            if self.parent_span_id == self.span_id:
                raise ValueError("a span cannot be its own parent")
        _validate_operation(
            operation=self.operation,
            status=self.status,
            input_hash=self.input_hash,
            output_hash=self.output_hash,
            model_version=self.model_version,
            prompt_version=self.prompt_version,
            profile_version=self.profile_version,
            started_at=self.started_at,
            ended_at=self.ended_at,
            latency_ms=self.latency_ms,
            cost_usd=self.cost_usd,
            error_type=self.error_type,
        )
        if self.error_type is not None:
            _require_identifier(self.error_type, "error_type")
        if self.error_message is not None and len(self.error_message) > 8192:
            raise ValueError("error_message exceeds 8192 characters")
        if not isinstance(self.metadata, Mapping):
            raise ValueError("span metadata must be a mapping")
        _validate_json(dict(self.metadata), "$.metadata")

    def to_dict(self) -> dict[str, Any]:
        return {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "component_id": self.component_id,
            "component_version": self.component_version,
            "operation": self.operation,
            "status": self.status,
            "input_hash": self.input_hash,
            "idempotency_key": self.idempotency_key,
            "output_hash": self.output_hash,
            "model_version": self.model_version,
            "prompt_version": self.prompt_version,
            "profile_version": self.profile_version,
            "started_at": _iso(self.started_at),
            "ended_at": _iso(self.ended_at),
            "latency_ms": self.latency_ms,
            "cost_usd": float(self.cost_usd),
            "error_type": self.error_type,
            "error_message": self.error_message,
            "parent_span_id": self.parent_span_id,
            "metadata": _json_copy(dict(self.metadata)),
        }


@dataclass(frozen=True)
class TraceEvent:
    """Append-only event attached to a trace, with explicit replay identity."""

    trace_id: str
    event_type: str
    payload: Mapping[str, Any]
    idempotency_key: str
    span_id: str | None = None
    occurred_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        _require_identifier(self.trace_id, "trace_id")
        _require_identifier(self.event_type, "event_type")
        _require_identifier(self.idempotency_key, "idempotency_key")
        if self.span_id is not None:
            _require_identifier(self.span_id, "span_id")
        if not isinstance(self.payload, Mapping):
            raise ValueError("event payload must be a mapping")
        _validate_json(dict(self.payload), "$.payload")
        _require_utc(self.occurred_at, "occurred_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "event_type": self.event_type,
            "payload": _json_copy(dict(self.payload)),
            "idempotency_key": self.idempotency_key,
            "occurred_at": _iso(self.occurred_at),
        }


@dataclass(frozen=True)
class OutboxMessage:
    """A durable message and, when leased, its acknowledgement receipt."""

    message_id: int
    trace_id: str
    event_type: str
    payload: dict[str, Any]
    idempotency_key: str
    status: str
    attempts: int
    max_attempts: int
    available_at: datetime
    lease_owner: str | None
    lease_until: datetime | None
    lease_token: str | None
    last_error: str | None

    def __post_init__(self) -> None:
        if self.status not in _OUTBOX_STATUSES:
            raise ValueError("invalid outbox status")


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=30000;

CREATE TABLE IF NOT EXISTS ca_obs_flows (
  flow_hash TEXT PRIMARY KEY,
  flow_id TEXT NOT NULL,
  flow_version TEXT NOT NULL,
  definition_json TEXT NOT NULL,
  registered_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ca_obs_flows_identity
  ON ca_obs_flows(flow_id,flow_version);

CREATE TABLE IF NOT EXISTS ca_obs_traces (
  trace_id TEXT PRIMARY KEY,
  flow_hash TEXT NOT NULL REFERENCES ca_obs_flows(flow_hash),
  operation TEXT NOT NULL,
  status TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  output_hash TEXT,
  model_version TEXT,
  prompt_version TEXT,
  profile_version TEXT,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  latency_ms INTEGER,
  cost_usd REAL NOT NULL,
  error_type TEXT,
  error_message TEXT,
  job_key TEXT,
  metadata_json TEXT NOT NULL,
  record_hash TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ca_obs_traces_status
  ON ca_obs_traces(status,started_at);
CREATE INDEX IF NOT EXISTS ca_obs_traces_job
  ON ca_obs_traces(job_key,started_at);

CREATE TABLE IF NOT EXISTS ca_obs_spans (
  span_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL REFERENCES ca_obs_traces(trace_id) ON DELETE CASCADE,
  parent_span_id TEXT,
  component_id TEXT NOT NULL,
  component_version TEXT NOT NULL,
  operation TEXT NOT NULL,
  status TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  output_hash TEXT,
  model_version TEXT,
  prompt_version TEXT,
  profile_version TEXT,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  latency_ms INTEGER,
  cost_usd REAL NOT NULL,
  error_type TEXT,
  error_message TEXT,
  metadata_json TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  record_hash TEXT NOT NULL,
  FOREIGN KEY(parent_span_id) REFERENCES ca_obs_spans(span_id)
);
CREATE INDEX IF NOT EXISTS ca_obs_spans_trace
  ON ca_obs_spans(trace_id,started_at);

CREATE TABLE IF NOT EXISTS ca_obs_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  trace_id TEXT NOT NULL REFERENCES ca_obs_traces(trace_id) ON DELETE CASCADE,
  span_id TEXT,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  occurred_at TEXT NOT NULL,
  record_hash TEXT NOT NULL,
  FOREIGN KEY(span_id) REFERENCES ca_obs_spans(span_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ca_obs_events_trace
  ON ca_obs_events(trace_id,event_id);

CREATE TABLE IF NOT EXISTS ca_obs_outbox (
  message_id INTEGER PRIMARY KEY AUTOINCREMENT,
  trace_id TEXT NOT NULL REFERENCES ca_obs_traces(trace_id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('queued','leased','acked','dead')),
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL,
  available_at REAL NOT NULL,
  lease_owner TEXT,
  lease_until REAL,
  lease_token TEXT,
  last_error TEXT,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  acknowledged_at REAL
);
CREATE INDEX IF NOT EXISTS ca_obs_outbox_ready
  ON ca_obs_outbox(status,available_at,message_id);
"""


class ObservabilityStore:
    """SQLite repository for flow provenance, traces, and reliable dispatch."""

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

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def register_flow(self, flow: FlowDefinition) -> bool:
        """Persist a definition once; content identity makes re-registration safe."""
        definition = flow.to_json()
        with self.connection() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO ca_obs_flows(
                     flow_hash,flow_id,flow_version,definition_json,registered_at
                   ) VALUES(?,?,?,?,?)""",
                (flow.content_hash, flow.flow_id, flow.version, definition, _iso(utc_now())),
            )
            if cursor.rowcount == 1:
                return True
            row = connection.execute(
                "SELECT definition_json FROM ca_obs_flows WHERE flow_hash=?",
                (flow.content_hash,),
            ).fetchone()
            if row is None or row["definition_json"] != definition:
                raise RuntimeError("flow hash collision detected")
            return False

    def write_trace(self, trace: OperationTrace) -> bool:
        """Insert an operation trace, rejecting identity reuse with different data."""
        value = trace.to_dict()
        record_hash = hash_payload(value)
        with self.connection() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO ca_obs_traces(
                     trace_id,flow_hash,operation,status,input_hash,output_hash,
                     model_version,prompt_version,profile_version,started_at,ended_at,
                     latency_ms,cost_usd,error_type,error_message,job_key,metadata_json,
                     record_hash,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    trace.trace_id,
                    trace.flow_hash,
                    trace.operation,
                    trace.status,
                    trace.input_hash,
                    trace.output_hash,
                    trace.model_version,
                    trace.prompt_version,
                    trace.profile_version,
                    _iso(trace.started_at),
                    _iso(trace.ended_at),
                    trace.latency_ms,
                    float(trace.cost_usd),
                    trace.error_type,
                    trace.error_message,
                    trace.job_key,
                    canonical_json(dict(trace.metadata)),
                    record_hash,
                    _iso(utc_now()),
                ),
            )
            if cursor.rowcount == 1:
                return True
            row = connection.execute(
                "SELECT record_hash FROM ca_obs_traces WHERE trace_id=?",
                (trace.trace_id,),
            ).fetchone()
            if row is None or row["record_hash"] != record_hash:
                raise ValueError("trace_id already exists with different content")
            return False

    def finish_trace(
        self,
        trace_id: str,
        *,
        status: str,
        output_hash: str | None,
        ended_at: datetime,
        latency_ms: int,
        cost_usd: float,
        error_type: str | None = None,
        error_message: str | None = None,
    ) -> bool:
        """Atomically move a running trace to an immutable terminal result."""
        _require_identifier(trace_id, "trace_id")
        if status not in _TERMINAL_STATUSES:
            raise ValueError("finish_trace requires a terminal status")
        with self.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM ca_obs_traces WHERE trace_id=?", (trace_id,)
            ).fetchone()
            if row is None:
                raise KeyError(trace_id)
            metadata = json.loads(row["metadata_json"])
            candidate = OperationTrace(
                trace_id=trace_id,
                flow_hash=row["flow_hash"],
                operation=row["operation"],
                status=status,
                input_hash=row["input_hash"],
                output_hash=output_hash,
                model_version=row["model_version"],
                prompt_version=row["prompt_version"],
                profile_version=row["profile_version"],
                started_at=datetime.fromisoformat(row["started_at"]),
                ended_at=ended_at,
                latency_ms=latency_ms,
                cost_usd=cost_usd,
                error_type=error_type,
                error_message=error_message,
                job_key=row["job_key"],
                metadata=metadata,
            )
            record_hash = hash_payload(candidate.to_dict())
            if row["status"] in _TERMINAL_STATUSES:
                if row["record_hash"] != record_hash:
                    raise ValueError("trace already finished with a different result")
                return False
            if row["status"] not in {"queued", "running"}:
                raise ValueError(f"trace cannot finish from status {row['status']!r}")
            connection.execute(
                """UPDATE ca_obs_traces SET status=?,output_hash=?,ended_at=?,latency_ms=?,
                     cost_usd=?,error_type=?,error_message=?,record_hash=?,updated_at=?
                   WHERE trace_id=?""",
                (
                    status,
                    output_hash,
                    _iso(ended_at),
                    latency_ms,
                    float(cost_usd),
                    error_type,
                    error_message,
                    record_hash,
                    _iso(utc_now()),
                    trace_id,
                ),
            )
            return True

    def write_span(self, span: SpanRecord) -> bool:
        """Append a span once; conflicting replay identities fail loudly."""
        record_hash = hash_payload(span.to_dict())
        with self.connection() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO ca_obs_spans(
                     span_id,trace_id,parent_span_id,component_id,component_version,
                     operation,status,input_hash,output_hash,model_version,prompt_version,
                     profile_version,started_at,ended_at,latency_ms,cost_usd,error_type,
                     error_message,metadata_json,idempotency_key,record_hash
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    span.span_id,
                    span.trace_id,
                    span.parent_span_id,
                    span.component_id,
                    span.component_version,
                    span.operation,
                    span.status,
                    span.input_hash,
                    span.output_hash,
                    span.model_version,
                    span.prompt_version,
                    span.profile_version,
                    _iso(span.started_at),
                    _iso(span.ended_at),
                    span.latency_ms,
                    float(span.cost_usd),
                    span.error_type,
                    span.error_message,
                    canonical_json(dict(span.metadata)),
                    span.idempotency_key,
                    record_hash,
                ),
            )
            if cursor.rowcount == 1:
                return True
            row = connection.execute(
                """SELECT span_id,idempotency_key,record_hash FROM ca_obs_spans
                   WHERE span_id=? OR idempotency_key=?""",
                (span.span_id, span.idempotency_key),
            ).fetchone()
            if (
                row is None
                or row["span_id"] != span.span_id
                or row["idempotency_key"] != span.idempotency_key
                or row["record_hash"] != record_hash
            ):
                raise ValueError("span identity already exists with different content")
            return False

    def write_event(self, event: TraceEvent) -> bool:
        """Append an idempotent structured event."""
        record_hash = hash_payload(event.to_dict())
        payload_json = canonical_json(dict(event.payload))
        with self.connection() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO ca_obs_events(
                     trace_id,span_id,event_type,payload_json,payload_hash,
                     idempotency_key,occurred_at,record_hash
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    event.trace_id,
                    event.span_id,
                    event.event_type,
                    payload_json,
                    hash_payload(dict(event.payload)),
                    event.idempotency_key,
                    _iso(event.occurred_at),
                    record_hash,
                ),
            )
            if cursor.rowcount == 1:
                return True
            row = connection.execute(
                "SELECT record_hash FROM ca_obs_events WHERE idempotency_key=?",
                (event.idempotency_key,),
            ).fetchone()
            if row is None or row["record_hash"] != record_hash:
                raise ValueError("event idempotency_key already exists with different content")
            return False

    def enqueue_outbox(
        self,
        *,
        trace_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        max_attempts: int = 8,
        available_at: datetime | None = None,
    ) -> bool:
        """Durably enqueue a message before attempting any external delivery."""
        _require_identifier(trace_id, "trace_id")
        _require_identifier(event_type, "event_type")
        _require_identifier(idempotency_key, "idempotency_key")
        if not isinstance(payload, Mapping):
            raise ValueError("outbox payload must be a mapping")
        payload_json = canonical_json(dict(payload))
        payload_hash = hash_payload(dict(payload))
        if not isinstance(max_attempts, int) or max_attempts < 1 or max_attempts > 10_000:
            raise ValueError("max_attempts must be between 1 and 10000")
        ready = _require_utc(available_at or utc_now(), "available_at").timestamp()
        now = utc_now().timestamp()
        identity_hash = hash_payload(
            {
                "trace_id": trace_id,
                "event_type": event_type,
                "payload_hash": payload_hash,
                "max_attempts": max_attempts,
            }
        )
        with self.connection() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO ca_obs_outbox(
                     trace_id,event_type,payload_json,payload_hash,idempotency_key,status,
                     attempts,max_attempts,available_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,'queued',0,?,?,?,?)""",
                (
                    trace_id,
                    event_type,
                    payload_json,
                    payload_hash,
                    idempotency_key,
                    max_attempts,
                    ready,
                    now,
                    now,
                ),
            )
            if cursor.rowcount == 1:
                return True
            row = connection.execute(
                """SELECT trace_id,event_type,payload_hash,max_attempts
                   FROM ca_obs_outbox WHERE idempotency_key=?""",
                (idempotency_key,),
            ).fetchone()
            if row is None:
                raise RuntimeError("outbox insert was ignored without an identity conflict")
            existing_hash = hash_payload(
                {
                    "trace_id": row["trace_id"],
                    "event_type": row["event_type"],
                    "payload_hash": row["payload_hash"],
                    "max_attempts": row["max_attempts"],
                }
            )
            if existing_hash != identity_hash:
                raise ValueError("outbox idempotency_key already exists with different content")
            return False

    def claim_outbox(
        self,
        worker_id: str,
        *,
        lease_seconds: float = 60.0,
        now: datetime | None = None,
    ) -> OutboxMessage | None:
        """Claim one ready message, recovering any expired lease transactionally."""
        _require_identifier(worker_id, "worker_id")
        if not isinstance(lease_seconds, (int, float)) or not math.isfinite(lease_seconds):
            raise ValueError("lease_seconds must be finite")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        claimed_at = _require_utc(now or utc_now(), "now").timestamp()
        lease_until = claimed_at + float(lease_seconds)
        lease_token = secrets.token_urlsafe(24)
        with self.transaction(immediate=True) as connection:
            # A worker may disappear on its final permitted delivery attempt.  Move
            # that expired receipt to the retained dead-letter state rather than
            # leaving it permanently leased and therefore invisible.
            connection.execute(
                """UPDATE ca_obs_outbox SET status='dead',lease_owner=NULL,
                     lease_until=NULL,lease_token=NULL,
                     last_error=COALESCE(last_error,'lease expired after maximum attempts'),
                     updated_at=?
                   WHERE status='leased' AND lease_until<=? AND attempts>=max_attempts""",
                (claimed_at, claimed_at),
            )
            row = connection.execute(
                """SELECT * FROM ca_obs_outbox
                   WHERE attempts < max_attempts AND (
                     (status='queued' AND available_at<=?) OR
                     (status='leased' AND lease_until<=?)
                   )
                   ORDER BY available_at,message_id LIMIT 1""",
                (claimed_at, claimed_at),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """UPDATE ca_obs_outbox SET status='leased',attempts=attempts+1,
                     lease_owner=?,lease_until=?,lease_token=?,updated_at=?
                   WHERE message_id=?""",
                (worker_id, lease_until, lease_token, claimed_at, row["message_id"]),
            )
            updated = connection.execute(
                "SELECT * FROM ca_obs_outbox WHERE message_id=?", (row["message_id"],)
            ).fetchone()
            assert updated is not None
            return self._message_from_row(updated)

    def ack_outbox(
        self,
        message_id: int,
        *,
        worker_id: str,
        lease_token: str,
        now: datetime | None = None,
    ) -> bool:
        """Acknowledge a delivery without deleting its durable audit record."""
        acknowledged_at = _require_utc(now or utc_now(), "now").timestamp()
        with self.transaction(immediate=True) as connection:
            row = self._leased_message(
                connection,
                message_id,
                worker_id,
                lease_token,
                allow_acked=True,
            )
            if row["status"] == "acked":
                return False
            connection.execute(
                """UPDATE ca_obs_outbox SET status='acked',lease_owner=NULL,
                     lease_until=NULL,lease_token=NULL,acknowledged_at=?,updated_at=?
                   WHERE message_id=?""",
                (acknowledged_at, acknowledged_at, message_id),
            )
            return True

    def fail_outbox(
        self,
        message_id: int,
        *,
        worker_id: str,
        lease_token: str,
        error: str,
        base_delay_seconds: float = 5.0,
        maximum_delay_seconds: float = 3600.0,
        now: datetime | None = None,
    ) -> OutboxMessage:
        """Record failure and schedule an exponential retry, or retain it as dead."""
        _require_text(error, "error", maximum=8192)
        for name, value in (
            ("base_delay_seconds", base_delay_seconds),
            ("maximum_delay_seconds", maximum_delay_seconds),
        ):
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and non-negative")
        if maximum_delay_seconds < base_delay_seconds:
            raise ValueError("maximum_delay_seconds cannot be smaller than base delay")
        failed_at = _require_utc(now or utc_now(), "now").timestamp()
        with self.transaction(immediate=True) as connection:
            row = self._leased_message(connection, message_id, worker_id, lease_token)
            attempts = int(row["attempts"])
            dead = attempts >= int(row["max_attempts"])
            base_delay = float(base_delay_seconds)
            maximum_delay = float(maximum_delay_seconds)
            exponent = max(0, attempts - 1)
            if base_delay == 0.0:
                delay = 0.0
            else:
                saturation_exponent = math.ceil(
                    math.log2(maximum_delay) - math.log2(base_delay)
                )
                delay = (
                    maximum_delay
                    if exponent >= saturation_exponent
                    else min(maximum_delay, math.ldexp(base_delay, exponent))
                )
            available_at = failed_at if dead else failed_at + delay
            connection.execute(
                """UPDATE ca_obs_outbox SET status=?,available_at=?,lease_owner=NULL,
                     lease_until=NULL,lease_token=NULL,last_error=?,updated_at=?
                   WHERE message_id=?""",
                (
                    "dead" if dead else "queued",
                    available_at,
                    error,
                    failed_at,
                    message_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM ca_obs_outbox WHERE message_id=?", (message_id,)
            ).fetchone()
            assert updated is not None
            return self._message_from_row(updated)

    def requeue_dead(
        self,
        message_id: int,
        *,
        max_attempts: int | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Explicitly revive a retained dead message after operator intervention."""
        ready = _require_utc(now or utc_now(), "now").timestamp()
        if max_attempts is not None and (
            not isinstance(max_attempts, int) or max_attempts < 1 or max_attempts > 10_000
        ):
            raise ValueError("max_attempts must be between 1 and 10000")
        with self.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT status,max_attempts,attempts FROM ca_obs_outbox WHERE message_id=?",
                (message_id,),
            ).fetchone()
            if row is None:
                raise KeyError(message_id)
            if row["status"] != "dead":
                return False
            new_maximum = max_attempts or max(int(row["max_attempts"]), int(row["attempts"]) + 1)
            connection.execute(
                """UPDATE ca_obs_outbox SET status='queued',max_attempts=?,available_at=?,
                     lease_owner=NULL,lease_until=NULL,lease_token=NULL,updated_at=?
                   WHERE message_id=?""",
                (new_maximum, ready, ready, message_id),
            )
            return True

    def outbox_message(self, message_id: int) -> OutboxMessage:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM ca_obs_outbox WHERE message_id=?", (message_id,)
            ).fetchone()
            if row is None:
                raise KeyError(message_id)
            return self._message_from_row(row)

    @staticmethod
    def _leased_message(
        connection: sqlite3.Connection,
        message_id: int,
        worker_id: str,
        lease_token: str,
        *,
        allow_acked: bool = False,
    ) -> sqlite3.Row:
        _require_identifier(worker_id, "worker_id")
        _require_text(lease_token, "lease_token", maximum=512)
        row = connection.execute(
            "SELECT * FROM ca_obs_outbox WHERE message_id=?", (message_id,)
        ).fetchone()
        if row is None:
            raise KeyError(message_id)
        if row["status"] == "acked" and allow_acked:
            return row
        if (
            row["status"] != "leased"
            or row["lease_owner"] != worker_id
            or row["lease_token"] != lease_token
        ):
            raise RuntimeError("outbox message is not held by this lease receipt")
        return row

    @staticmethod
    def _message_from_row(row: sqlite3.Row) -> OutboxMessage:
        def timestamp(value: float | None) -> datetime | None:
            return datetime.fromtimestamp(value, timezone.utc) if value is not None else None

        available_at = timestamp(row["available_at"])
        assert available_at is not None
        return OutboxMessage(
            message_id=int(row["message_id"]),
            trace_id=str(row["trace_id"]),
            event_type=str(row["event_type"]),
            payload=json.loads(row["payload_json"]),
            idempotency_key=str(row["idempotency_key"]),
            status=str(row["status"]),
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
            available_at=available_at,
            lease_owner=row["lease_owner"],
            lease_until=timestamp(row["lease_until"]),
            lease_token=row["lease_token"],
            last_error=row["last_error"],
        )


__all__ = [
    "ComponentContract",
    "ComponentDefinition",
    "FlowDefinition",
    "FlowStep",
    "ObservabilityStore",
    "OperationTrace",
    "OutboxMessage",
    "SpanRecord",
    "TraceEvent",
    "canonical_json",
    "hash_payload",
    "utc_now",
]
