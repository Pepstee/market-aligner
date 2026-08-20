"""Restart-safe local JAA-16 operations supervisor.

This module executes only injected, explicitly marked *local probes*.  It has
no network client, provider SDK, browser, process launcher, queue writer,
deployment path, alert sender, or release authority.  Its purpose is to make
the local control-plane mechanics executable and observable without turning a
local acceptance slice into authority for consequential work.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Sequence

from career_automation.release_certification import (
    REQUIRED_PRIOR_SLICES,
    REQUIRED_RELEASE_EVIDENCE,
    DistributionScan,
    PriorSliceCertification,
    ReleaseEvidenceReference,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
FAILURE_KINDS = (
    "crash",
    "quota",
    "network",
    "stale_source",
    "model_failure",
    "restart",
)
FALLBACK_FAILURES = frozenset({"quota", "network", "model_failure"})
ALERT_CLASS = MappingProxyType(
    {
        "quota": "weather",
        "network": "weather",
        "stale_source": "weather",
        "backpressure": "blocked_work",
        "provider_exhausted": "blocked_work",
        "unsafe_resume": "product_defect",
        "lost_lease": "product_defect",
        "schema_drift": "product_defect",
        "duplicate_consequential_dispatch": "product_defect",
        "ledger_integrity": "product_defect",
    }
)
ZERO_HASH = "0" * 64


class OperationsLiveError(RuntimeError):
    """Base class for fail-closed local operations failures."""


class LedgerIntegrityError(OperationsLiveError):
    """The append-only event chain is invalid."""


class ConsequentialDispatchError(OperationsLiveError):
    """A caller attempted to use the local supervisor for external action."""


class BackpressureError(OperationsLiveError):
    """A schedule cannot run while its source queue is above policy."""


class BudgetExhaustedError(OperationsLiveError):
    """The capability budget cannot cover another attempt."""


class ProviderExhaustedError(OperationsLiveError):
    """Every tested local route failed; no success was fabricated."""


class SchemaDriftError(OperationsLiveError):
    """A route result changed the required schema or verification ladder."""


class LeaseError(OperationsLiveError):
    """A lease is missing, lost, active elsewhere, or unsafe to recover."""


class UnsafeResumeError(OperationsLiveError):
    """Pause state or unresolved work makes resume unsafe."""


class InjectedFailure(OperationsLiveError):
    """A deterministic acceptance drill interrupted local work."""

    def __init__(self, kind: str) -> None:
        super().__init__(f"injected {kind} failure")
        self.kind = kind


class LocalProbeFailure(OperationsLiveError):
    """A marked local probe reported an expected route failure."""

    def __init__(self, kind: str, detail: str = "local probe failed") -> None:
        if kind not in FALLBACK_FAILURES:
            raise ValueError("local probe failure kind is unsupported")
        super().__init__(detail)
        self.kind = kind


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} is not a safe normalized identifier")
    return value


def _aware(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{label} must include a timezone")
    return value


def _utc(value: datetime) -> str:
    return (
        _aware(value, "time")
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise LedgerIntegrityError("event time is invalid") from exc
    return _aware(parsed, "event time")


@dataclass(frozen=True)
class ScheduleSpec:
    schedule_id: str
    capability: str
    workflow_sha256: str
    first_due_at: datetime
    cadence_seconds: int
    queue_high_watermark: int
    queue_hard_stop: int
    resume_below: int
    lease_seconds: int = 300
    schema_version: str = "jaa16.live-schedule.v1"

    def __post_init__(self) -> None:
        _identifier(self.schedule_id, "schedule ID")
        _identifier(self.capability, "schedule capability")
        _digest(self.workflow_sha256, "schedule workflow hash")
        _aware(self.first_due_at, "first due time")
        for value, label in (
            (self.cadence_seconds, "cadence"),
            (self.lease_seconds, "lease duration"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{label} must be a positive integer")
        if (
            isinstance(self.resume_below, bool)
            or isinstance(self.queue_high_watermark, bool)
            or isinstance(self.queue_hard_stop, bool)
            or not all(
                isinstance(value, int)
                for value in (
                    self.resume_below,
                    self.queue_high_watermark,
                    self.queue_hard_stop,
                )
            )
            or not 0 <= self.resume_below < self.queue_high_watermark
            or self.queue_high_watermark >= self.queue_hard_stop
        ):
            raise ValueError("queue thresholds are invalid")
        if self.schema_version != "jaa16.live-schedule.v1":
            raise ValueError("schedule schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "schedule_id": self.schedule_id,
            "capability": self.capability,
            "workflow_sha256": self.workflow_sha256,
            "first_due_at": _utc(self.first_due_at),
            "cadence_seconds": self.cadence_seconds,
            "queue_high_watermark": self.queue_high_watermark,
            "queue_hard_stop": self.queue_hard_stop,
            "resume_below": self.resume_below,
            "lease_seconds": self.lease_seconds,
            "consequential_dispatch_authority": False,
        }

    @property
    def spec_sha256(self) -> str:
        return _hash(self.document())


@dataclass(frozen=True)
class CapabilityBudget:
    capability: str
    max_attempts_per_utc_day: int
    max_tokens_per_utc_day: int
    max_cost_microusd_per_utc_day: int

    def __post_init__(self) -> None:
        _identifier(self.capability, "budget capability")
        for value, label in (
            (self.max_attempts_per_utc_day, "attempt budget"),
            (self.max_tokens_per_utc_day, "token budget"),
            (self.max_cost_microusd_per_utc_day, "cost budget"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{label} must be a positive integer")

    def document(self) -> dict[str, object]:
        return {
            "capability": self.capability,
            "max_attempts_per_utc_day": self.max_attempts_per_utc_day,
            "max_tokens_per_utc_day": self.max_tokens_per_utc_day,
            "max_cost_microusd_per_utc_day": self.max_cost_microusd_per_utc_day,
        }


@dataclass(frozen=True)
class RuntimeRoute:
    route_id: str
    capability: str
    priority: int
    output_schema_sha256: str
    policy_sha256: str
    verification_rungs: tuple[str, ...]
    tested_evidence_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.route_id, "route ID")
        _identifier(self.capability, "route capability")
        for value, label in (
            (self.output_schema_sha256, "route output schema hash"),
            (self.policy_sha256, "route policy hash"),
            (self.tested_evidence_sha256, "route test evidence hash"),
        ):
            _digest(value, label)
        if (
            isinstance(self.priority, bool)
            or not isinstance(self.priority, int)
            or self.priority < 1
        ):
            raise ValueError("route priority must be a positive integer")
        normalized = tuple(sorted(set(self.verification_rungs)))
        if not normalized or normalized != self.verification_rungs:
            raise ValueError("verification rungs must be unique and sorted")
        for rung in normalized:
            _identifier(rung, "verification rung")

    def document(self) -> dict[str, object]:
        return {
            "route_id": self.route_id,
            "capability": self.capability,
            "priority": self.priority,
            "output_schema_sha256": self.output_schema_sha256,
            "policy_sha256": self.policy_sha256,
            "verification_rungs": self.verification_rungs,
            "tested_evidence_sha256": self.tested_evidence_sha256,
            "external_execution_authority": False,
        }


@dataclass(frozen=True)
class WorkRequest:
    work_id: str
    input_sha256: str
    payload: Mapping[str, object]
    consequential: bool = False

    def __post_init__(self) -> None:
        _identifier(self.work_id, "work ID")
        _digest(self.input_sha256, "work input hash")
        try:
            normalized = json.loads(_canonical_json(dict(self.payload)))
        except (TypeError, ValueError) as exc:
            raise ValueError("work payload must be canonical JSON data") from exc
        object.__setattr__(self, "payload", MappingProxyType(normalized))
        if type(self.consequential) is not bool:
            raise ValueError("work consequence marker must be Boolean")

    @property
    def idempotency_key(self) -> str:
        return _hash(
            {
                "schema_version": "jaa16.local-work-key.v1",
                "work_id": self.work_id,
                "input_sha256": self.input_sha256,
                "payload": dict(self.payload),
                "consequential": self.consequential,
            }
        )


@dataclass(frozen=True)
class LocalProbeResult:
    route_id: str
    success: bool
    output: Mapping[str, object] | None
    output_schema_sha256: str
    verification_rungs: tuple[str, ...]
    tokens_used: int
    cost_microusd: int

    def __post_init__(self) -> None:
        _identifier(self.route_id, "result route ID")
        _digest(self.output_schema_sha256, "result schema hash")
        if type(self.success) is not bool:
            raise ValueError("probe success must be Boolean")
        if self.success and not isinstance(self.output, Mapping):
            raise ValueError("successful probe requires JSON-object output")
        if not self.success and self.output is not None:
            raise ValueError("failed probe cannot carry output")
        if self.output is not None:
            object.__setattr__(
                self,
                "output",
                MappingProxyType(json.loads(_canonical_json(dict(self.output)))),
            )
        for value, label in (
            (self.tokens_used, "tokens used"),
            (self.cost_microusd, "cost used"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{label} must be non-negative")


@dataclass(frozen=True)
class ExecutionReceipt:
    schedule_id: str
    capability: str
    run_key: str
    idempotency_key: str
    route_id: str
    output_sha256: str
    event_sha256: str
    completed_at: str
    external_action: bool = False
    consequential_queue_mutated: bool = False
    certifies_slice: bool = False


@dataclass(frozen=True)
class LocalAlert:
    signal: str
    classification: str
    detail_sha256: str
    event_sha256: str
    created_at: str
    send_authority: bool = False


@dataclass(frozen=True)
class LocalReport:
    report_kind: str
    period_start: str
    period_end: str
    event_counts: Mapping[str, int]
    ledger_head_sha256: str
    report_sha256: str
    send_authority: bool = False
    certifies_slice: bool = False


@dataclass(frozen=True)
class BackupVerification:
    backup_id: str
    source_sha256: str
    backup_sha256: str
    manifest_sha256: str
    bound_ledger_head_sha256: str
    restore_verified: bool
    verification_event_sha256: str
    release_evidence_authority: bool = False


@dataclass(frozen=True)
class ReleaseBoundaryAssessment:
    exact_prior_certificates: bool
    exact_release_evidence: bool
    clean_bound_distribution: bool
    eligible_for_independent_review: bool
    reason_codes: tuple[str, ...]
    release_authority: bool = False
    deployment_authority: bool = False
    report_send_authority: bool = False
    entitlement_authority: bool = False
    production_certification: bool = False
    certifies_slice: bool = False


class OperationsEventLedger:
    """Content-addressed append-only SQLite event chain."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self.verify()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS operations_events (
                    sequence_no INTEGER PRIMARY KEY,
                    observed_at TEXT NOT NULL,
                    event_kind TEXT NOT NULL,
                    schedule_id TEXT,
                    capability TEXT,
                    run_key TEXT,
                    idempotency_key TEXT,
                    payload_json TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS operations_event_scope
                    ON operations_events(schedule_id, event_kind, sequence_no);
                CREATE INDEX IF NOT EXISTS operations_event_work
                    ON operations_events(idempotency_key, event_kind, sequence_no);
                CREATE TRIGGER IF NOT EXISTS operations_events_no_update
                BEFORE UPDATE ON operations_events
                BEGIN SELECT RAISE(ABORT, 'operations ledger is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS operations_events_no_delete
                BEFORE DELETE ON operations_events
                BEGIN SELECT RAISE(ABORT, 'operations ledger is immutable'); END;
                """
            )

    @staticmethod
    def _body(row: Mapping[str, object]) -> dict[str, object]:
        return {
            "schema_version": "jaa16.operations-event.v1",
            "sequence_no": row["sequence_no"],
            "observed_at": row["observed_at"],
            "event_kind": row["event_kind"],
            "schedule_id": row["schedule_id"],
            "capability": row["capability"],
            "run_key": row["run_key"],
            "idempotency_key": row["idempotency_key"],
            "payload": json.loads(str(row["payload_json"])),
            "previous_sha256": row["previous_sha256"],
        }

    def verify(self) -> str:
        previous = ZERO_HASH
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM operations_events ORDER BY sequence_no"
            ).fetchall()
        for expected, row in enumerate(rows, start=1):
            if row["sequence_no"] != expected or row["previous_sha256"] != previous:
                raise LedgerIntegrityError("operations event chain is discontinuous")
            try:
                _parse_time(row["observed_at"])
                body = self._body(row)
            except (ValueError, json.JSONDecodeError) as exc:
                raise LedgerIntegrityError("operations event is malformed") from exc
            event_hash = _hash(body)
            if row["event_sha256"] != event_hash:
                raise LedgerIntegrityError("operations event content hash is invalid")
            previous = event_hash
        return previous

    @property
    def head_sha256(self) -> str:
        return self.verify()

    def append(
        self,
        *,
        observed_at: datetime,
        event_kind: str,
        payload: Mapping[str, object],
        schedule_id: str | None = None,
        capability: str | None = None,
        run_key: str | None = None,
        idempotency_key: str | None = None,
    ) -> str:
        _aware(observed_at, "event time")
        _identifier(event_kind, "event kind")
        for value, label in (
            (schedule_id, "event schedule ID"),
            (capability, "event capability"),
            (run_key, "event run key"),
        ):
            if value is not None:
                _identifier(value, label)
        if idempotency_key is not None:
            _digest(idempotency_key, "event idempotency key")
        payload_json = _canonical_json(dict(payload))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            last = connection.execute(
                "SELECT sequence_no,event_sha256 FROM operations_events "
                "ORDER BY sequence_no DESC LIMIT 1"
            ).fetchone()
            sequence = 1 if last is None else int(last["sequence_no"]) + 1
            previous = ZERO_HASH if last is None else str(last["event_sha256"])
            body = {
                "schema_version": "jaa16.operations-event.v1",
                "sequence_no": sequence,
                "observed_at": _utc(observed_at),
                "event_kind": event_kind,
                "schedule_id": schedule_id,
                "capability": capability,
                "run_key": run_key,
                "idempotency_key": idempotency_key,
                "payload": json.loads(payload_json),
                "previous_sha256": previous,
            }
            event_hash = _hash(body)
            connection.execute(
                "INSERT INTO operations_events VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    sequence,
                    body["observed_at"],
                    event_kind,
                    schedule_id,
                    capability,
                    run_key,
                    idempotency_key,
                    payload_json,
                    previous,
                    event_hash,
                ),
            )
        self.verify()
        return event_hash

    def rows(self) -> tuple[sqlite3.Row, ...]:
        self.verify()
        with self._connect() as connection:
            return tuple(
                connection.execute(
                    "SELECT * FROM operations_events ORDER BY sequence_no"
                ).fetchall()
            )


class OperationsSupervisor:
    """Deterministic local scheduler and supervisor over an event ledger."""

    def __init__(
        self,
        path: Path,
        *,
        schedules: Sequence[ScheduleSpec],
        budgets: Sequence[CapabilityBudget],
        routes: Sequence[RuntimeRoute],
        initialized_at: datetime,
    ) -> None:
        self.ledger = OperationsEventLedger(path)
        self.schedules = {row.schedule_id: row for row in schedules}
        self.budgets = {row.capability: row for row in budgets}
        self.routes: dict[str, tuple[RuntimeRoute, ...]] = {}
        if not self.schedules or len(self.schedules) != len(tuple(schedules)):
            raise ValueError("schedules must be non-empty and unique")
        if not self.budgets or len(self.budgets) != len(tuple(budgets)):
            raise ValueError("capability budgets must be non-empty and unique")
        grouped: dict[str, list[RuntimeRoute]] = {}
        for route in routes:
            grouped.setdefault(route.capability, []).append(route)
        for capability, rows in grouped.items():
            ordered = tuple(sorted(rows, key=lambda row: row.priority))
            if len(ordered) < 2 or tuple(row.priority for row in ordered) != tuple(
                range(1, len(ordered) + 1)
            ):
                raise ValueError(
                    "each capability requires tested primary and fallback routes"
                )
            anchor = ordered[0]
            if any(
                row.output_schema_sha256 != anchor.output_schema_sha256
                or row.policy_sha256 != anchor.policy_sha256
                or row.verification_rungs != anchor.verification_rungs
                for row in ordered
            ):
                raise SchemaDriftError(
                    "provider fallback changes schema, policy or verification rungs"
                )
            self.routes[capability] = ordered
        needed = {row.capability for row in schedules}
        if needed - self.budgets.keys() or needed - self.routes.keys():
            raise ValueError(
                "every scheduled capability requires a budget and route set"
            )
        self._register_configuration(_aware(initialized_at, "initialization time"))

    def _register_configuration(self, now: datetime) -> None:
        existing = [
            json.loads(row["payload_json"])
            for row in self.ledger.rows()
            if row["event_kind"] == "configuration_registered"
        ]
        document = {
            "schedules": [
                self.schedules[key].document() for key in sorted(self.schedules)
            ],
            "budgets": [self.budgets[key].document() for key in sorted(self.budgets)],
            "routes": [
                row.document()
                for capability in sorted(self.routes)
                for row in self.routes[capability]
            ],
            "external_execution_authority": False,
            "deployment_authority": False,
            "report_send_authority": False,
            "production_certification": False,
        }
        config_hash = _hash(document)
        document["configuration_sha256"] = config_hash
        if existing:
            if len(existing) != 1 or _canonical_json(existing[0]) != _canonical_json(
                document
            ):
                raise LedgerIntegrityError(
                    "runtime configuration differs after restart"
                )
            return
        self.ledger.append(
            observed_at=now,
            event_kind="configuration_registered",
            payload=document,
        )

    def _events(self, *, schedule_id: str | None = None) -> list[sqlite3.Row]:
        rows = list(self.ledger.rows())
        if schedule_id is not None:
            rows = [row for row in rows if row["schedule_id"] == schedule_id]
        return rows

    def _last(self, schedule_id: str, kinds: set[str]) -> sqlite3.Row | None:
        rows = [
            row
            for row in self._events(schedule_id=schedule_id)
            if row["event_kind"] in kinds
        ]
        return None if not rows else rows[-1]

    def is_paused(self, schedule_id: str) -> bool:
        self._schedule(schedule_id)
        last = self._last(schedule_id, {"schedule_paused", "schedule_resumed"})
        return last is not None and last["event_kind"] == "schedule_paused"

    def _schedule(self, schedule_id: str) -> ScheduleSpec:
        try:
            return self.schedules[schedule_id]
        except KeyError as exc:
            raise ValueError("unknown schedule") from exc

    def next_due_at(self, schedule_id: str) -> datetime:
        spec = self._schedule(schedule_id)
        completed = self._last(schedule_id, {"run_completed"})
        if completed is None:
            return spec.first_due_at
        return _parse_time(completed["observed_at"]) + timedelta(
            seconds=spec.cadence_seconds
        )

    def _emit_alert(
        self,
        *,
        signal: str,
        detail: Mapping[str, object],
        now: datetime,
        schedule_id: str | None = None,
        capability: str | None = None,
    ) -> LocalAlert:
        if signal not in ALERT_CLASS:
            raise ValueError("unsupported alert signal")
        detail_hash = _hash(dict(detail))
        event_hash = self.ledger.append(
            observed_at=now,
            event_kind="local_alert",
            schedule_id=schedule_id,
            capability=capability,
            payload={
                "signal": signal,
                "classification": ALERT_CLASS[signal],
                "detail_sha256": detail_hash,
                "send_authority": False,
            },
        )
        return LocalAlert(
            signal=signal,
            classification=ALERT_CLASS[signal],
            detail_sha256=detail_hash,
            event_sha256=event_hash,
            created_at=_utc(now),
        )

    def pause(
        self,
        schedule_id: str,
        *,
        reason: str,
        now: datetime,
    ) -> str:
        spec = self._schedule(schedule_id)
        if self.is_paused(schedule_id):
            last = self._last(schedule_id, {"schedule_paused"})
            assert last is not None
            return str(last["event_sha256"])
        _identifier(reason, "pause reason")
        return self.ledger.append(
            observed_at=now,
            event_kind="schedule_paused",
            schedule_id=schedule_id,
            capability=spec.capability,
            payload={"reason": reason, "automatic": True},
        )

    def resume(
        self,
        schedule_id: str,
        *,
        expected_pause_sha256: str,
        resolution_sha256: str,
        queue_depth: int,
        now: datetime,
    ) -> str:
        spec = self._schedule(schedule_id)
        _digest(expected_pause_sha256, "expected pause hash")
        _digest(resolution_sha256, "resume resolution hash")
        last = self._last(schedule_id, {"schedule_paused", "schedule_resumed"})
        if (
            last is None
            or last["event_kind"] != "schedule_paused"
            or last["event_sha256"] != expected_pause_sha256
            or isinstance(queue_depth, bool)
            or not isinstance(queue_depth, int)
            or not 0 <= queue_depth < spec.resume_below
            or self._uncertain_leases(schedule_id)
        ):
            self._emit_alert(
                signal="unsafe_resume",
                detail={"schedule_id": schedule_id},
                now=now,
                schedule_id=schedule_id,
                capability=spec.capability,
            )
            raise UnsafeResumeError("pause, queue, or lease state makes resume unsafe")
        self.ledger.append(
            observed_at=now,
            event_kind="incident_resolved",
            schedule_id=schedule_id,
            capability=spec.capability,
            payload={
                "pause_event_sha256": expected_pause_sha256,
                "resolution_sha256": resolution_sha256,
            },
        )
        return self.ledger.append(
            observed_at=now,
            event_kind="schedule_resumed",
            schedule_id=schedule_id,
            capability=spec.capability,
            payload={"pause_event_sha256": expected_pause_sha256},
        )

    def _uncertain_leases(self, schedule_id: str) -> tuple[str, ...]:
        state: dict[str, str] = {}
        for row in self._events(schedule_id=schedule_id):
            run_key = row["run_key"]
            if run_key is None:
                continue
            if row["event_kind"] in {"lease_acquired", "probe_started"}:
                state[run_key] = row["event_kind"]
            elif row["event_kind"] in {
                "run_completed",
                "run_failed",
                "lease_recovered",
                "lease_abandoned_safe",
            }:
                state.pop(run_key, None)
        return tuple(sorted(state))

    def _usage(self, capability: str, now: datetime) -> tuple[int, int, int]:
        day = now.astimezone(timezone.utc).date()
        attempts = tokens = cost = 0
        for row in self.ledger.rows():
            if (
                row["event_kind"] != "budget_consumed"
                or row["capability"] != capability
            ):
                continue
            if _parse_time(row["observed_at"]).astimezone(timezone.utc).date() != day:
                continue
            payload = json.loads(row["payload_json"])
            attempts += int(payload["attempts"])
            tokens += int(payload["tokens"])
            cost += int(payload["cost_microusd"])
        return attempts, tokens, cost

    def _assert_budget(self, capability: str, now: datetime) -> None:
        used = self._usage(capability, now)
        budget = self.budgets[capability]
        if (
            used[0] >= budget.max_attempts_per_utc_day
            or used[1] >= budget.max_tokens_per_utc_day
            or used[2] >= budget.max_cost_microusd_per_utc_day
        ):
            raise BudgetExhaustedError("capability budget is exhausted")

    def _consume_budget(
        self,
        *,
        capability: str,
        tokens: int,
        cost_microusd: int,
        run_key: str,
        idempotency_key: str,
        now: datetime,
    ) -> None:
        budget = self.budgets[capability]
        used = self._usage(capability, now)
        future = (used[0] + 1, used[1] + tokens, used[2] + cost_microusd)
        if (
            future[0] > budget.max_attempts_per_utc_day
            or future[1] > budget.max_tokens_per_utc_day
            or future[2] > budget.max_cost_microusd_per_utc_day
        ):
            raise BudgetExhaustedError("route result exceeds capability budget")
        self.ledger.append(
            observed_at=now,
            event_kind="budget_consumed",
            capability=capability,
            run_key=run_key,
            idempotency_key=idempotency_key,
            payload={
                "attempts": 1,
                "tokens": tokens,
                "cost_microusd": cost_microusd,
            },
        )

    def _completed(self, idempotency_key: str) -> ExecutionReceipt | None:
        for row in reversed(self.ledger.rows()):
            if (
                row["event_kind"] != "run_completed"
                or row["idempotency_key"] != idempotency_key
            ):
                continue
            payload = json.loads(row["payload_json"])
            return ExecutionReceipt(
                schedule_id=row["schedule_id"],
                capability=row["capability"],
                run_key=row["run_key"],
                idempotency_key=idempotency_key,
                route_id=payload["route_id"],
                output_sha256=payload["output_sha256"],
                event_sha256=row["event_sha256"],
                completed_at=row["observed_at"],
            )
        return None

    def _acquire_lease(
        self,
        *,
        spec: ScheduleSpec,
        request: WorkRequest,
        owner_id: str,
        now: datetime,
    ) -> tuple[str, str]:
        _identifier(owner_id, "lease owner")
        run_key = f"run:{request.idempotency_key[:32]}"
        relevant = [
            row
            for row in self.ledger.rows()
            if row["idempotency_key"] == request.idempotency_key
        ]
        if relevant:
            last = relevant[-1]
            if last["event_kind"] in {"lease_acquired", "probe_started"}:
                payload = json.loads(last["payload_json"])
                expires_at = _parse_time(payload["lease_expires_at"])
                if now < expires_at:
                    raise LeaseError("work already has an active lease")
                if any(row["event_kind"] == "probe_started" for row in relevant):
                    self.pause(spec.schedule_id, reason="lost_lease", now=now)
                    self._emit_alert(
                        signal="lost_lease",
                        detail={"run_key": run_key},
                        now=now,
                        schedule_id=spec.schedule_id,
                        capability=spec.capability,
                    )
                    raise LeaseError(
                        "expired lease crossed an uncertain probe boundary"
                    )
                self.ledger.append(
                    observed_at=now,
                    event_kind="lease_recovered",
                    schedule_id=spec.schedule_id,
                    capability=spec.capability,
                    run_key=run_key,
                    idempotency_key=request.idempotency_key,
                    payload={"prior_lease_event_sha256": last["event_sha256"]},
                )
        expires = now + timedelta(seconds=spec.lease_seconds)
        lease_hash = self.ledger.append(
            observed_at=now,
            event_kind="lease_acquired",
            schedule_id=spec.schedule_id,
            capability=spec.capability,
            run_key=run_key,
            idempotency_key=request.idempotency_key,
            payload={
                "owner_id": owner_id,
                "lease_expires_at": _utc(expires),
                "work_id": request.work_id,
                "input_sha256": request.input_sha256,
            },
        )
        return run_key, lease_hash

    @staticmethod
    def _validate_probe(
        probe: object,
    ) -> Callable[[WorkRequest, RuntimeRoute], LocalProbeResult]:
        if (
            not callable(probe)
            or getattr(probe, "__jaa_local_probe__", False) is not True
        ):
            raise ConsequentialDispatchError(
                "runtime route requires an explicitly marked local-only probe"
            )
        return probe

    def run_due(
        self,
        schedule_id: str,
        *,
        request: WorkRequest,
        queue_depth: int,
        probes: Mapping[str, Callable[[WorkRequest, RuntimeRoute], LocalProbeResult]],
        owner_id: str,
        now: datetime,
        injected_failure: str | None = None,
    ) -> ExecutionReceipt | None:
        now = _aware(now, "run time")
        spec = self._schedule(schedule_id)
        if request.consequential:
            self._emit_alert(
                signal="duplicate_consequential_dispatch",
                detail={"work_id": request.work_id},
                now=now,
                schedule_id=schedule_id,
                capability=spec.capability,
            )
            raise ConsequentialDispatchError(
                "local supervisor has no consequential dispatch authority"
            )
        cached = self._completed(request.idempotency_key)
        if cached is not None:
            return cached
        if self.is_paused(schedule_id):
            raise UnsafeResumeError("schedule is paused")
        if (
            isinstance(queue_depth, bool)
            or not isinstance(queue_depth, int)
            or queue_depth < 0
        ):
            raise ValueError("queue depth must be a non-negative integer")
        if queue_depth >= spec.queue_hard_stop:
            self.pause(schedule_id, reason="backpressure", now=now)
            self._emit_alert(
                signal="backpressure",
                detail={"queue_depth": queue_depth, "hard_stop": spec.queue_hard_stop},
                now=now,
                schedule_id=schedule_id,
                capability=spec.capability,
            )
            raise BackpressureError("queue reached the hard stop")
        if queue_depth >= spec.queue_high_watermark:
            self.ledger.append(
                observed_at=now,
                event_kind="run_deferred",
                schedule_id=schedule_id,
                capability=spec.capability,
                idempotency_key=request.idempotency_key,
                payload={"reason": "backpressure", "queue_depth": queue_depth},
            )
            return None
        if now < self.next_due_at(schedule_id):
            return None
        if injected_failure is not None and injected_failure not in FAILURE_KINDS:
            raise ValueError("unsupported injected failure drill")
        self._assert_budget(spec.capability, now)
        run_key, lease_hash = self._acquire_lease(
            spec=spec,
            request=request,
            owner_id=owner_id,
            now=now,
        )
        if injected_failure in {"crash", "restart"}:
            self.ledger.append(
                observed_at=now,
                event_kind="drill_observed",
                schedule_id=schedule_id,
                capability=spec.capability,
                run_key=run_key,
                idempotency_key=request.idempotency_key,
                payload={
                    "failure_kind": injected_failure,
                    "injection_point": "after_lease_before_probe",
                    "no_consequential_action": True,
                },
            )
            raise InjectedFailure(injected_failure)
        if injected_failure == "stale_source":
            self.pause(schedule_id, reason="stale_source", now=now)
            self._emit_alert(
                signal="stale_source",
                detail={"input_sha256": request.input_sha256},
                now=now,
                schedule_id=schedule_id,
                capability=spec.capability,
            )
            self.ledger.append(
                observed_at=now,
                event_kind="run_failed",
                schedule_id=schedule_id,
                capability=spec.capability,
                run_key=run_key,
                idempotency_key=request.idempotency_key,
                payload={"reason": "stale_source", "lease_sha256": lease_hash},
            )
            raise InjectedFailure("stale_source")

        failure_kinds: list[str] = []
        for index, route in enumerate(self.routes[spec.capability]):
            self._assert_budget(spec.capability, now)
            probe = self._validate_probe(probes.get(route.route_id))
            self.ledger.append(
                observed_at=now,
                event_kind="probe_started",
                schedule_id=schedule_id,
                capability=spec.capability,
                run_key=run_key,
                idempotency_key=request.idempotency_key,
                payload={
                    "route_id": route.route_id,
                    "lease_expires_at": _utc(
                        now + timedelta(seconds=spec.lease_seconds)
                    ),
                    "external_execution_authority": False,
                },
            )
            forced = (
                injected_failure
                if index == 0 and injected_failure in FALLBACK_FAILURES
                else None
            )
            try:
                if forced is not None:
                    raise LocalProbeFailure(forced, f"injected {forced}")
                result = probe(request, route)
            except LocalProbeFailure as exc:
                failure_kinds.append(exc.kind)
                self._consume_budget(
                    capability=spec.capability,
                    tokens=0,
                    cost_microusd=0,
                    run_key=run_key,
                    idempotency_key=request.idempotency_key,
                    now=now,
                )
                self.ledger.append(
                    observed_at=now,
                    event_kind="route_failed",
                    schedule_id=schedule_id,
                    capability=spec.capability,
                    run_key=run_key,
                    idempotency_key=request.idempotency_key,
                    payload={"route_id": route.route_id, "failure_kind": exc.kind},
                )
                continue
            if (
                not isinstance(result, LocalProbeResult)
                or result.route_id != route.route_id
            ):
                raise SchemaDriftError("probe returned an unbound result")
            self._consume_budget(
                capability=spec.capability,
                tokens=result.tokens_used,
                cost_microusd=result.cost_microusd,
                run_key=run_key,
                idempotency_key=request.idempotency_key,
                now=now,
            )
            if (
                result.output_schema_sha256 != route.output_schema_sha256
                or result.verification_rungs != route.verification_rungs
            ):
                self.pause(schedule_id, reason="schema_drift", now=now)
                self._emit_alert(
                    signal="schema_drift",
                    detail={"route_id": route.route_id},
                    now=now,
                    schedule_id=schedule_id,
                    capability=spec.capability,
                )
                raise SchemaDriftError(
                    "fallback result changed schema or verification rungs"
                )
            if not result.success:
                failure_kinds.append("model_failure")
                self.ledger.append(
                    observed_at=now,
                    event_kind="route_failed",
                    schedule_id=schedule_id,
                    capability=spec.capability,
                    run_key=run_key,
                    idempotency_key=request.idempotency_key,
                    payload={
                        "route_id": route.route_id,
                        "failure_kind": "model_failure",
                    },
                )
                continue
            assert result.output is not None
            output_sha = _hash(dict(result.output))
            completed_hash = self.ledger.append(
                observed_at=now,
                event_kind="run_completed",
                schedule_id=schedule_id,
                capability=spec.capability,
                run_key=run_key,
                idempotency_key=request.idempotency_key,
                payload={
                    "route_id": route.route_id,
                    "output_sha256": output_sha,
                    "fallback_used": index > 0,
                    "external_action": False,
                    "consequential_queue_mutated": False,
                },
            )
            if injected_failure in FALLBACK_FAILURES:
                self.ledger.append(
                    observed_at=now,
                    event_kind="drill_observed",
                    schedule_id=schedule_id,
                    capability=spec.capability,
                    run_key=run_key,
                    idempotency_key=request.idempotency_key,
                    payload={
                        "failure_kind": injected_failure,
                        "fallback_preserved_schema": True,
                        "no_consequential_action": True,
                    },
                )
            return ExecutionReceipt(
                schedule_id=schedule_id,
                capability=spec.capability,
                run_key=run_key,
                idempotency_key=request.idempotency_key,
                route_id=route.route_id,
                output_sha256=output_sha,
                event_sha256=completed_hash,
                completed_at=_utc(now),
            )
        self.ledger.append(
            observed_at=now,
            event_kind="run_failed",
            schedule_id=schedule_id,
            capability=spec.capability,
            run_key=run_key,
            idempotency_key=request.idempotency_key,
            payload={"reason": "provider_exhausted", "failures": failure_kinds},
        )
        self.pause(schedule_id, reason="provider_exhausted", now=now)
        self._emit_alert(
            signal="provider_exhausted",
            detail={"failure_kinds": failure_kinds},
            now=now,
            schedule_id=schedule_id,
            capability=spec.capability,
        )
        raise ProviderExhaustedError("all tested local routes failed")

    def restart(self, *, now: datetime) -> tuple[str, ...]:
        """Verify replay and safely abandon only pre-probe expired leases."""

        now = _aware(now, "restart time")
        self.ledger.verify()
        recovered: list[str] = []
        by_run: dict[str, list[sqlite3.Row]] = {}
        for row in self.ledger.rows():
            if row["run_key"] is not None:
                by_run.setdefault(row["run_key"], []).append(row)
        for run_key, rows in by_run.items():
            terminal = any(
                row["event_kind"] in {"run_completed", "run_failed"} for row in rows
            )
            if terminal:
                continue
            lease = next(
                (
                    row
                    for row in reversed(rows)
                    if row["event_kind"] == "lease_acquired"
                ),
                None,
            )
            if lease is None:
                raise LedgerIntegrityError("run has no lease event")
            payload = json.loads(lease["payload_json"])
            if now < _parse_time(payload["lease_expires_at"]):
                continue
            if any(row["event_kind"] == "probe_started" for row in rows):
                schedule_id = lease["schedule_id"]
                self.pause(schedule_id, reason="lost_lease", now=now)
                self._emit_alert(
                    signal="lost_lease",
                    detail={"run_key": run_key},
                    now=now,
                    schedule_id=schedule_id,
                    capability=lease["capability"],
                )
                raise LeaseError("restart found an uncertain expired probe lease")
            self.ledger.append(
                observed_at=now,
                event_kind="lease_abandoned_safe",
                schedule_id=lease["schedule_id"],
                capability=lease["capability"],
                run_key=run_key,
                idempotency_key=lease["idempotency_key"],
                payload={"expired_lease_sha256": lease["event_sha256"]},
            )
            recovered.append(run_key)
        self.ledger.append(
            observed_at=now,
            event_kind="supervisor_restarted",
            payload={"safe_expired_leases": sorted(recovered)},
        )
        return tuple(sorted(recovered))

    def compile_local_report(
        self,
        *,
        report_kind: str,
        period_start: datetime,
        period_end: datetime,
        now: datetime,
    ) -> LocalReport:
        if report_kind not in {"daily_operations", "weekly_outcomes"}:
            raise ValueError("unsupported local report kind")
        start = _aware(period_start, "report start")
        end = _aware(period_end, "report end")
        if end <= start or now < end:
            raise ValueError("report period must be closed and ordered")
        counts: dict[str, int] = {}
        for row in self.ledger.rows():
            observed = _parse_time(row["observed_at"])
            if start <= observed < end:
                counts[row["event_kind"]] = counts.get(row["event_kind"], 0) + 1
        ordered = dict(sorted(counts.items()))
        body = {
            "schema_version": "jaa16.local-report.v1",
            "report_kind": report_kind,
            "period_start": _utc(start),
            "period_end": _utc(end),
            "event_counts": ordered,
            "ledger_head_sha256": self.ledger.head_sha256,
            "send_authority": False,
            "certifies_slice": False,
        }
        report_sha = _hash(body)
        self.ledger.append(
            observed_at=now,
            event_kind="local_report_compiled",
            payload={"report_sha256": report_sha, **body},
        )
        return LocalReport(
            report_kind=report_kind,
            period_start=_utc(start),
            period_end=_utc(end),
            event_counts=MappingProxyType(ordered),
            ledger_head_sha256=body["ledger_head_sha256"],
            report_sha256=report_sha,
        )

    def record_backup(
        self,
        *,
        backup_id: str,
        source_sha256: str,
        backup_sha256: str,
        manifest_sha256: str,
        bound_ledger_head_sha256: str,
        clean: bool,
        now: datetime,
    ) -> str:
        _identifier(backup_id, "backup ID")
        for value, label in (
            (source_sha256, "backup source hash"),
            (backup_sha256, "backup artifact hash"),
            (manifest_sha256, "backup manifest hash"),
            (bound_ledger_head_sha256, "backup ledger head"),
        ):
            _digest(value, label)
        if clean is not True or bound_ledger_head_sha256 != self.ledger.head_sha256:
            raise ValueError("backup is dirty or not bound to the current ledger head")
        if any(
            json.loads(row["payload_json"]).get("backup_id") == backup_id
            for row in self.ledger.rows()
            if row["event_kind"] == "backup_recorded"
        ):
            raise ValueError("backup ID already exists")
        return self.ledger.append(
            observed_at=now,
            event_kind="backup_recorded",
            payload={
                "backup_id": backup_id,
                "source_sha256": source_sha256,
                "backup_sha256": backup_sha256,
                "manifest_sha256": manifest_sha256,
                "bound_ledger_head_sha256": bound_ledger_head_sha256,
                "clean": True,
                "release_evidence_authority": False,
            },
        )

    def verify_restore(
        self,
        *,
        backup_id: str,
        restored_source_sha256: str,
        restore_manifest_sha256: str,
        now: datetime,
    ) -> BackupVerification:
        _identifier(backup_id, "backup ID")
        _digest(restored_source_sha256, "restored source hash")
        _digest(restore_manifest_sha256, "restore manifest hash")
        matches = [
            row
            for row in self.ledger.rows()
            if row["event_kind"] == "backup_recorded"
            and json.loads(row["payload_json"]).get("backup_id") == backup_id
        ]
        if len(matches) != 1:
            raise ValueError("restore requires one exact bound backup")
        backup = json.loads(matches[0]["payload_json"])
        if (
            backup.get("clean") is not True
            or restored_source_sha256 != backup["source_sha256"]
        ):
            raise ValueError("restore does not reproduce the clean bound source")
        event_hash = self.ledger.append(
            observed_at=now,
            event_kind="restore_verified",
            payload={
                "backup_id": backup_id,
                "backup_event_sha256": matches[0]["event_sha256"],
                "restored_source_sha256": restored_source_sha256,
                "restore_manifest_sha256": restore_manifest_sha256,
                "release_evidence_authority": False,
            },
        )
        return BackupVerification(
            backup_id=backup_id,
            source_sha256=backup["source_sha256"],
            backup_sha256=backup["backup_sha256"],
            manifest_sha256=backup["manifest_sha256"],
            bound_ledger_head_sha256=backup["bound_ledger_head_sha256"],
            restore_verified=True,
            verification_event_sha256=event_hash,
        )


def assess_release_boundary(
    *,
    prior_certifications: Sequence[PriorSliceCertification],
    release_evidence: Sequence[ReleaseEvidenceReference],
    distribution_scan: DistributionScan,
    artifact_version: str,
    artifact_sha256: str,
) -> ReleaseBoundaryAssessment:
    """Validate exact evidence, but never mint release or certification authority."""

    _identifier(artifact_version, "artifact version")
    _digest(artifact_sha256, "artifact hash")
    if not isinstance(distribution_scan, DistributionScan):
        raise TypeError("release boundary requires a typed distribution scan")
    distribution_scan.verify()
    for row in prior_certifications:
        if not isinstance(row, PriorSliceCertification):
            raise TypeError("prior certifications must be typed")
        row.verify()
    for row in release_evidence:
        if not isinstance(row, ReleaseEvidenceReference):
            raise TypeError("release evidence must be typed")
        row.verify()
    prior_ids = [row.slice_id for row in prior_certifications]
    evidence_kinds = [row.evidence_kind for row in release_evidence]
    exact_prior = tuple(sorted(prior_ids)) == REQUIRED_PRIOR_SLICES and len(
        prior_ids
    ) == len(set(prior_ids))
    exact_evidence = (
        tuple(sorted(evidence_kinds)) == tuple(sorted(REQUIRED_RELEASE_EVIDENCE))
        and len(evidence_kinds) == len(set(evidence_kinds))
        and all(
            row.independently_verified and row.artifact_version == artifact_version
            for row in release_evidence
        )
    )
    clean_distribution = (
        distribution_scan.is_clean
        and distribution_scan.artifact_version == artifact_version
        and distribution_scan.artifact_sha256 == artifact_sha256
    )
    reasons: list[str] = []
    if not exact_prior:
        reasons.append("missing_or_duplicate_prior_slice_certification")
    if not exact_evidence:
        reasons.append("missing_unverified_or_unbound_release_evidence")
    if not clean_distribution:
        reasons.append("dirty_or_unbound_distribution")
    return ReleaseBoundaryAssessment(
        exact_prior_certificates=exact_prior,
        exact_release_evidence=exact_evidence,
        clean_bound_distribution=clean_distribution,
        eligible_for_independent_review=not reasons,
        reason_codes=tuple(reasons),
    )
