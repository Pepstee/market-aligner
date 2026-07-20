"""Deterministic version-0.1 lifecycle reducer and ledger verification.

Workers may record observations and transition proposals here, but only
``LifecycleReducer.commit`` changes materialised job state.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .migrations import apply_jaa_01_migrations
from .models import ActorKind, PipelineState


class LifecycleError(RuntimeError):
    """Base class for rejected lifecycle operations."""


class InvalidTransition(LifecycleError):
    pass


class IdempotencyConflict(LifecycleError):
    pass


class LedgerDivergence(LifecycleError):
    pass


@dataclass(frozen=True)
class PolicyIdentity:
    policy_id: str
    version: str
    sha256: str


@dataclass(frozen=True)
class ModelIdentity:
    provider: str
    model_id: str
    version: str


@dataclass(frozen=True)
class TransitionReceipt:
    receipt_id: int
    event_id: int
    job_key: str
    from_state: PipelineState
    to_state: PipelineState
    policy: PolicyIdentity
    model: ModelIdentity | None
    input_hash: str
    output_hash: str
    idempotency_key: str
    created_at: str


def canonical_json(value: Any) -> str:
    """Return the one accepted JSON representation for hashed lifecycle data."""
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("lifecycle content must be finite JSON data") from exc


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


# One graph is authoritative. Legacy SCORED is the deployed equivalent of the
# Opportunity-0 assessment boundary and the three research states are retained.
LEGAL_TRANSITIONS: Mapping[PipelineState, frozenset[PipelineState]] = {
    PipelineState.DISCOVERED: frozenset({PipelineState.FETCHED}),
    PipelineState.FETCHED: frozenset({PipelineState.NORMALISED}),
    PipelineState.NORMALISED: frozenset({PipelineState.VIABILITY_REJECTED, PipelineState.ELIGIBLE}),
    PipelineState.ELIGIBLE: frozenset({PipelineState.OPPORTUNITY_0_ASSESSED, PipelineState.SCORED}),
    PipelineState.OPPORTUNITY_0_ASSESSED: frozenset({PipelineState.OPPORTUNITY_REJECTED, PipelineState.EMPLOYER_RESEARCH_QUEUED}),
    PipelineState.SCORED: frozenset({PipelineState.OPPORTUNITY_REJECTED, PipelineState.EMPLOYER_RESEARCH_QUEUED}),
    PipelineState.EMPLOYER_RESEARCH_QUEUED: frozenset({PipelineState.EMPLOYER_RESEARCHING}),
    PipelineState.EMPLOYER_RESEARCHING: frozenset({PipelineState.EMPLOYER_RESEARCHED}),
    PipelineState.EMPLOYER_RESEARCHED: frozenset({PipelineState.OPPORTUNITY_1_ASSESSED}),
    PipelineState.OPPORTUNITY_1_ASSESSED: frozenset({PipelineState.OPPORTUNITY_REJECTED_AFTER_RESEARCH, PipelineState.FIT_ASSESSED}),
    PipelineState.FIT_ASSESSED: frozenset({PipelineState.CANDIDATE_REJECTED, PipelineState.GAP_IDENTIFIED, PipelineState.STRATEGY_READY}),
    PipelineState.GAP_IDENTIFIED: frozenset({PipelineState.GAP_RECOVERY, PipelineState.LEARNING, PipelineState.EVIDENCE_BUILDING}),
    PipelineState.GAP_RECOVERY: frozenset({PipelineState.GAP_VERIFIED}),
    PipelineState.LEARNING: frozenset({PipelineState.GAP_VERIFIED}),
    PipelineState.EVIDENCE_BUILDING: frozenset({PipelineState.GAP_VERIFIED}),
    PipelineState.GAP_VERIFIED: frozenset({PipelineState.FIT_REASSESSED}),
    PipelineState.FIT_REASSESSED: frozenset({PipelineState.CANDIDATE_REJECTED, PipelineState.GAP_IDENTIFIED, PipelineState.STRATEGY_READY}),
    PipelineState.STRATEGY_READY: frozenset({PipelineState.APPLICATION_COMPILED}),
    PipelineState.APPLICATION_COMPILED: frozenset({PipelineState.RELEASE_BLOCKED, PipelineState.RELEASED}),
    PipelineState.RELEASE_BLOCKED: frozenset({PipelineState.APPLICATION_COMPILED}),
    PipelineState.RELEASED: frozenset({PipelineState.SUBMISSION_QUEUED}),
    PipelineState.SUBMISSION_QUEUED: frozenset({PipelineState.SUBMISSION_BLOCKED, PipelineState.SUBMITTED}),
    PipelineState.SUBMISSION_BLOCKED: frozenset({PipelineState.SUBMISSION_QUEUED}),
    PipelineState.SUBMITTED: frozenset({PipelineState.RECEIPT_CONFIRMED}),
    PipelineState.RECEIPT_CONFIRMED: frozenset({PipelineState.SCREENING, PipelineState.REJECTED, PipelineState.WITHDRAWN, PipelineState.EXPIRED}),
    PipelineState.SCREENING: frozenset({PipelineState.INTERVIEW, PipelineState.REJECTED, PipelineState.WITHDRAWN, PipelineState.EXPIRED}),
    PipelineState.INTERVIEW: frozenset({PipelineState.FINAL_STAGE, PipelineState.REJECTED, PipelineState.WITHDRAWN, PipelineState.EXPIRED}),
    PipelineState.FINAL_STAGE: frozenset({PipelineState.OFFER, PipelineState.REJECTED, PipelineState.WITHDRAWN, PipelineState.EXPIRED}),
    PipelineState.OFFER: frozenset({PipelineState.ACCEPTED, PipelineState.DECLINED, PipelineState.WITHDRAWN, PipelineState.EXPIRED}),
    **{state: frozenset() for state in (
        PipelineState.VIABILITY_REJECTED, PipelineState.OPPORTUNITY_REJECTED,
        PipelineState.OPPORTUNITY_REJECTED_AFTER_RESEARCH, PipelineState.CANDIDATE_REJECTED,
        PipelineState.ACCEPTED, PipelineState.DECLINED, PipelineState.REJECTED,
        PipelineState.WITHDRAWN, PipelineState.EXPIRED,
    )},
}

if set(LEGAL_TRANSITIONS) != set(PipelineState):
    raise RuntimeError("lifecycle graph does not cover the complete state vocabulary")


_LEGACY_EVENT_TYPES = {
    "score_snapshot_imported", "opportunity_gate_decided",
    "employer_research_leased", "employer_research_completed",
}


class LifecycleReducer:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        apply_jaa_01_migrations(self.path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @staticmethod
    def _required(value: str, label: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string")
        return value

    @staticmethod
    def _digest(value: str, label: str) -> str:
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError(f"{label} must be a lowercase SHA-256 digest")
        return value

    def record_proposal(
        self, *, job_key: str, proposed_state: PipelineState, actor: ActorKind,
        observation: Any, idempotency_key: str, model: ModelIdentity | None = None,
    ) -> int:
        """Append a non-mutating observation/proposal and return its event id."""
        if not isinstance(proposed_state, PipelineState):
            raise ValueError("proposed_state must be a PipelineState")
        if actor not in {ActorKind.PROBABILISTIC, ActorKind.EXTERNAL}:
            raise ValueError("transition proposals must come from a probabilistic or external actor")
        self._required(job_key, "job_key")
        self._required(idempotency_key, "idempotency_key")
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            event_id = self.record_proposal_in_transaction(
                conn, job_key=job_key, proposed_state=proposed_state, actor=actor,
                observation=observation, idempotency_key=idempotency_key, model=model,
            )
            conn.commit()
            return event_id
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def record_proposal_in_transaction(
        self, conn: sqlite3.Connection, *, job_key: str,
        proposed_state: PipelineState, actor: ActorKind, observation: Any,
        idempotency_key: str, model: ModelIdentity | None = None,
    ) -> int:
        """Record a proposal using the caller's active transaction."""
        if not isinstance(proposed_state, PipelineState):
            raise ValueError("proposed_state must be a PipelineState")
        if actor not in {ActorKind.PROBABILISTIC, ActorKind.EXTERNAL}:
            raise ValueError("transition proposals must come from a probabilistic or external actor")
        self._required(job_key, "job_key")
        self._required(idempotency_key, "idempotency_key")
        if model is not None and not isinstance(model, ModelIdentity):
            raise ValueError("model must be a ModelIdentity or None")
        payload = {
            "proposed_state": proposed_state.value,
            "observation": observation,
            "observation_hash": canonical_hash(observation),
            "model": None if model is None else {
                "provider": model.provider, "model_id": model.model_id,
                "version": model.version,
            },
        }
        payload_json = canonical_json(payload)
        existing = conn.execute(
            "SELECT * FROM pipeline_events WHERE idempotency_key=?",
            (idempotency_key,),
        ).fetchone()
        if existing is not None:
            if (existing["event_type"] != "lifecycle_transition_proposed"
                    or existing["job_key"] != job_key
                    or existing["payload_json"] != payload_json
                    or existing["actor_kind"] != actor.value):
                raise IdempotencyConflict(
                    "idempotency key was reused with different proposal content"
                )
            return int(existing["id"])
        current = conn.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?", (job_key,),
        ).fetchone()
        if current is None:
            raise KeyError(job_key)
        cursor = conn.execute(
            """INSERT INTO pipeline_events(
                   job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
                 ) VALUES(?,?,?,?,?,?,?)""",
            (job_key, "lifecycle_transition_proposed", current["state"], None,
             actor.value, payload_json, idempotency_key),
        )
        return int(cursor.lastrowid)

    def commit(
        self, *, job_key: str, to_state: PipelineState, policy: PolicyIdentity,
        inputs: Any, outputs: Any, idempotency_key: str,
        model: ModelIdentity | None = None,
    ) -> TransitionReceipt:
        """Atomically append an event and receipt and advance materialised state."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            receipt = self.commit_in_transaction(
                conn, job_key=job_key, to_state=to_state, policy=policy,
                inputs=inputs, outputs=outputs, idempotency_key=idempotency_key,
                model=model,
            )
            conn.commit()
            return receipt
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def commit_in_transaction(
        self, conn: sqlite3.Connection, *, job_key: str,
        to_state: PipelineState, policy: PolicyIdentity, inputs: Any,
        outputs: Any, idempotency_key: str,
        model: ModelIdentity | None = None,
    ) -> TransitionReceipt:
        """Commit through the reducer on the caller's active SQLite transaction."""
        if not isinstance(to_state, PipelineState):
            raise ValueError("to_state must be a PipelineState")
        if not isinstance(policy, PolicyIdentity):
            raise ValueError("policy must be a PolicyIdentity")
        if model is not None and not isinstance(model, ModelIdentity):
            raise ValueError("model must be a ModelIdentity or None")
        self._required(job_key, "job_key")
        self._required(idempotency_key, "idempotency_key")
        self._required(policy.policy_id, "policy_id")
        self._required(policy.version, "policy_version")
        self._digest(policy.sha256, "policy_hash")
        if model is not None:
            self._required(model.provider, "model_provider")
            self._required(model.model_id, "model_id")
            self._required(model.version, "model_version")
        input_hash, output_hash = canonical_hash(inputs), canonical_hash(outputs)
        binding = {
            "policy": {"id": policy.policy_id, "version": policy.version,
                       "sha256": policy.sha256},
            "model": None if model is None else {
                "provider": model.provider, "id": model.model_id,
                "version": model.version,
            },
            "input_hash": input_hash, "output_hash": output_hash,
        }
        payload_json = canonical_json(binding)
        existing = conn.execute(
                """SELECT r.*,e.event_type,e.actor_kind,e.payload_json AS event_payload
                   FROM lifecycle_transition_receipts r JOIN pipeline_events e ON e.id=r.event_id
                   WHERE r.idempotency_key=?""", (idempotency_key,),
        ).fetchone()
        if existing is not None:
            expected = (job_key, to_state.value, policy.policy_id, policy.version,
                        policy.sha256, input_hash, output_hash,
                        model.provider if model else None,
                        model.model_id if model else None,
                        model.version if model else None, payload_json)
            actual = (existing["job_key"], existing["to_state"],
                      existing["policy_id"], existing["policy_version"],
                      existing["policy_hash"], existing["input_hash"],
                      existing["output_hash"], existing["model_provider"],
                      existing["model_id"], existing["model_version"],
                      existing["event_payload"])
            if actual != expected:
                raise IdempotencyConflict(
                    "idempotency key was reused with different transition content"
                )
            return self._receipt(existing)
        if conn.execute(
            "SELECT 1 FROM pipeline_events WHERE idempotency_key=?",
            (idempotency_key,),
        ).fetchone():
            raise IdempotencyConflict(
                "idempotency key is already used by a non-transition event"
            )
        current = conn.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?", (job_key,),
        ).fetchone()
        if current is None:
            raise KeyError(job_key)
        try:
            from_state = PipelineState(current["state"])
        except ValueError as exc:
            raise InvalidTransition(
                f"unknown current state {current['state']!r}"
            ) from exc
        if to_state not in LEGAL_TRANSITIONS[from_state]:
            raise InvalidTransition(
                f"illegal or out-of-order transition: {from_state.value} -> {to_state.value}"
            )
        event = conn.execute(
            """INSERT INTO pipeline_events(
                 job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
               ) VALUES(?,?,?,?,?,?,?)""",
            (job_key, "lifecycle_transition_committed", from_state.value,
             to_state.value, ActorKind.DETERMINISTIC.value, payload_json,
             idempotency_key),
        )
        receipt = conn.execute(
            """INSERT INTO lifecycle_transition_receipts(
                 event_id,job_key,from_state,to_state,policy_id,policy_version,policy_hash,
                 model_provider,model_id,model_version,input_hash,output_hash,idempotency_key)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *""",
            (event.lastrowid, job_key, from_state.value, to_state.value,
             policy.policy_id, policy.version, policy.sha256,
             model.provider if model else None, model.model_id if model else None,
             model.version if model else None, input_hash, output_hash,
             idempotency_key),
        ).fetchone()
        changed = conn.execute(
            """UPDATE pipeline_jobs
               SET state=?,policy_hash=?,updated_at=CURRENT_TIMESTAMP
               WHERE job_key=? AND state=?""",
            (to_state.value, policy.sha256, job_key, from_state.value),
        ).rowcount
        if changed != 1:
            raise InvalidTransition("job state changed concurrently")
        return self._receipt(receipt)

    @staticmethod
    def _receipt(row: sqlite3.Row) -> TransitionReceipt:
        model = None if row["model_provider"] is None else ModelIdentity(row["model_provider"], row["model_id"], row["model_version"])
        return TransitionReceipt(int(row["receipt_id"]), int(row["event_id"]), row["job_key"],
            PipelineState(row["from_state"]), PipelineState(row["to_state"]),
            PolicyIdentity(row["policy_id"], row["policy_version"], row["policy_hash"]), model,
            row["input_hash"], row["output_hash"], row["idempotency_key"], row["created_at"])

    def replay(self) -> dict[str, PipelineState]:
        """Reconstruct all job states, rejecting invalid order or receipt tampering."""
        conn = self._connect()
        try:
            jobs = {row["job_key"]: row["state"] for row in conn.execute("SELECT job_key,state FROM pipeline_jobs")}
            replayed: dict[str, PipelineState] = {}
            events = conn.execute("SELECT * FROM pipeline_events ORDER BY id").fetchall()
            for event in events:
                if event["to_state"] is None:
                    continue
                try:
                    target = PipelineState(event["to_state"])
                    source = None if event["from_state"] is None else PipelineState(event["from_state"])
                except ValueError as exc:
                    raise LedgerDivergence(f"event {event['id']} contains an unknown state") from exc
                prior = replayed.get(event["job_key"])
                if source is None:
                    if prior is not None or target not in {PipelineState.DISCOVERED, PipelineState.SCORED}:
                        raise LedgerDivergence(f"event {event['id']} is an impossible root transition")
                elif prior != source or target not in LEGAL_TRANSITIONS[source]:
                    raise LedgerDivergence(f"event {event['id']} is out of order or illegal")
                if event["event_type"] == "lifecycle_transition_committed":
                    self._verify_receipt(conn, event)
                elif event["event_type"] not in _LEGACY_EVENT_TYPES:
                    raise LedgerDivergence(f"event {event['id']} changes state without reducer authority")
                replayed[event["job_key"]] = target
            if set(replayed) != set(jobs):
                missing = sorted(set(jobs) - set(replayed))
                raise LedgerDivergence(f"jobs have no replayable state history: {missing}")
            for key, state in jobs.items():
                if replayed[key].value != state:
                    raise LedgerDivergence(f"materialised state diverges for {key}")
            return replayed
        finally:
            conn.close()

    @staticmethod
    def _verify_receipt(conn: sqlite3.Connection, event: sqlite3.Row) -> None:
        receipt = conn.execute("SELECT * FROM lifecycle_transition_receipts WHERE event_id=?", (event["id"],)).fetchone()
        if receipt is None:
            raise LedgerDivergence(f"event {event['id']} has no transition receipt")
        try:
            payload = json.loads(event["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise LedgerDivergence(f"event {event['id']} has malformed binding data") from exc
        model = payload.get("model")
        expected = (event["job_key"], event["from_state"], event["to_state"], event["idempotency_key"],
                    payload.get("policy", {}).get("id"), payload.get("policy", {}).get("version"), payload.get("policy", {}).get("sha256"),
                    payload.get("input_hash"), payload.get("output_hash"),
                    None if model is None else model.get("provider"), None if model is None else model.get("id"), None if model is None else model.get("version"))
        actual = (receipt["job_key"], receipt["from_state"], receipt["to_state"], receipt["idempotency_key"],
                  receipt["policy_id"], receipt["policy_version"], receipt["policy_hash"], receipt["input_hash"], receipt["output_hash"],
                  receipt["model_provider"], receipt["model_id"], receipt["model_version"])
        if actual != expected or event["actor_kind"] != ActorKind.DETERMINISTIC.value or event["payload_json"] != canonical_json(payload):
            raise LedgerDivergence(f"event {event['id']} has a tampered receipt identity")

    def verify(self) -> None:
        self.replay()
