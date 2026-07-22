"""Deterministic version-0.1 lifecycle reducer and ledger verification.

Workers may record observations and transition proposals here, but only
``LifecycleReducer.commit`` changes materialised job state.
"""

from __future__ import annotations

import hashlib
import json
import math
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


def _require_unambiguous_json_keys(value: Any, active: set[int] | None = None) -> None:
    """Reject object-key coercion and circular containers before serialisation."""
    if not isinstance(value, (dict, list, tuple)):
        return
    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        raise ValueError("lifecycle content must not contain circular data")
    active.add(identity)
    try:
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("lifecycle JSON object keys must be strings")
            children = value.values()
        else:
            children = value
        for child in children:
            _require_unambiguous_json_keys(child, active)
    finally:
        active.remove(identity)


def canonical_json(value: Any) -> str:
    """Return the one accepted JSON representation for hashed lifecycle data."""
    _require_unambiguous_json_keys(value)
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("lifecycle content must be finite JSON data") from exc


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


_SCORE_SNAPSHOT_STRING_FIELDS = (
    "job_key", "board", "job_id", "url", "title", "company", "payload_hash",
)
_SCORE_SNAPSHOT_NUMERIC_FIELDS = (
    "fit", "opportunity", "final_score", "extraction_confidence",
)


def _score_number_identity(value: int | float | None, name: str) -> dict[str, str] | None:
    """Preserve Python numeric type and signed zero across SQLite REAL coercion."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"score snapshot {name} must be a finite number")
    if not math.isfinite(value):
        raise ValueError(f"score snapshot {name} must be a finite number")
    if isinstance(value, int):
        return {"type": "int", "value": str(value)}
    return {"type": "float", "value": value.hex()}


def score_snapshot_import_binding(
    *, job_key: str, board: str, job_id: str, url: str, title: str,
    company: str, fit: int | float | None, opportunity: int | float,
    final_score: int | float | None, extraction_confidence: int | float | None,
    payload_hash: str,
) -> tuple[str, str, str]:
    """Return exact event bytes, key and hash for one immutable score import."""
    snapshot: dict[str, Any] = {
        "job_key": job_key,
        "board": board,
        "job_id": job_id,
        "url": url,
        "title": title,
        "company": company,
        "fit": _score_number_identity(fit, "fit"),
        "opportunity": _score_number_identity(opportunity, "opportunity"),
        "final_score": _score_number_identity(final_score, "final_score"),
        "extraction_confidence": _score_number_identity(
            extraction_confidence, "extraction_confidence"
        ),
        "payload_hash": payload_hash,
    }
    binding = {
        "format": "score-snapshot-import/v2",
        "snapshot": snapshot,
        "snapshot_hash": canonical_hash(snapshot),
    }
    payload_json = canonical_json(binding)
    binding_hash = canonical_hash(binding)
    return payload_json, f"score-import-v2:{job_key}:{binding_hash}", binding_hash


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
}
_LEGACY_OPPORTUNITY_POLICY_SUFFIX = "b38a8ff32e7d74ce"
_LEGACY_GATE_PAYLOADS = {
    PipelineState.EMPLOYER_RESEARCH_QUEUED: {
        "decision": "pass",
        "reason": "opportunity_warrants_employer_reconnaissance",
    },
    PipelineState.OPPORTUNITY_REJECTED: {
        "decision": "reject",
        "reason": "below_opportunity_threshold",
    },
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
            job_rows = conn.execute("SELECT * FROM pipeline_jobs").fetchall()
            for row in job_rows:
                self._verify_materialised_payload(row)
            job_by_key = {row["job_key"]: row for row in job_rows}
            jobs = {row["job_key"]: row["state"] for row in job_rows}
            materialised_policy = {row["job_key"]: row["policy_hash"] for row in job_rows}
            replayed: dict[str, PipelineState] = {}
            replayed_policy: dict[str, str | None] = {}
            verified_receipt_events: set[int] = set()
            verified_score_receipt_events: set[int] = set()
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
                    replayed_policy[event["job_key"]] = self._verify_receipt(conn, event)
                    verified_receipt_events.add(int(event["id"]))
                elif event["event_type"] in _LEGACY_EVENT_TYPES:
                    job_row = job_by_key.get(event["job_key"])
                    if job_row is None:
                        raise LedgerDivergence(
                            f"event {event['id']} references an unknown job"
                        )
                    policy_hash, score_receipt = self._verify_legacy_event(
                        conn, event, job_row,
                    )
                    replayed_policy[event["job_key"]] = policy_hash
                    if score_receipt:
                        verified_score_receipt_events.add(int(event["id"]))
                else:
                    raise LedgerDivergence(f"event {event['id']} changes state without reducer authority")
                replayed[event["job_key"]] = target
            receipt_events = {
                int(row[0]) for row in conn.execute(
                    "SELECT event_id FROM lifecycle_transition_receipts"
                )
            }
            if receipt_events != verified_receipt_events:
                raise LedgerDivergence(
                    "transition receipt ledger contains an unowned transition receipt"
                )
            score_receipt_events = {
                int(row[0]) for row in conn.execute(
                    "SELECT event_id FROM score_snapshot_receipts"
                )
            }
            if score_receipt_events != verified_score_receipt_events:
                raise LedgerDivergence(
                    "score snapshot receipt ledger contains an unowned receipt"
                )
            if set(replayed) != set(jobs):
                missing = sorted(set(jobs) - set(replayed))
                raise LedgerDivergence(f"jobs have no replayable state history: {missing}")
            for key, state in jobs.items():
                if replayed[key].value != state:
                    raise LedgerDivergence(f"materialised state diverges for {key}")
                if replayed_policy.get(key) != materialised_policy[key]:
                    raise LedgerDivergence(
                        f"materialised policy identity diverges for {key}"
                    )
            return replayed
        finally:
            conn.close()

    @staticmethod
    def _verify_materialised_payload(job: sqlite3.Row) -> None:
        """Bind stored job content to its digest under an explicit legacy seam."""
        rejected = f"job {job['job_key']} payload content diverges from payload_hash"
        try:
            payload = json.loads(job["payload_json"])
            if not isinstance(payload, dict):
                raise ValueError("score payload is not an object")
            canonical = canonical_json(payload)
            legacy = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            payload_hash = job["payload_hash"]
            if (job["payload_json"] not in {canonical, legacy}
                    or not isinstance(payload_hash, str)
                    or canonical_hash(payload) != payload_hash):
                raise ValueError("score payload identity mismatch")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LedgerDivergence(rejected) from exc

    @staticmethod
    def _verify_legacy_event(
        conn: sqlite3.Connection, event: sqlite3.Row, job: sqlite3.Row,
    ) -> tuple[str | None, bool]:
        """Authenticate the only two receiptless shapes in the frozen JAA-00 ledger."""
        rejected = f"event {event['id']} is not an exact deterministic historical event"
        job_payload_hash = job["payload_hash"]
        if (event["actor_kind"] != ActorKind.DETERMINISTIC.value
                or not isinstance(job_payload_hash, str)
                or len(job_payload_hash) != 64
                or any(char not in "0123456789abcdef" for char in job_payload_hash)):
            raise LedgerDivergence(rejected)

        event_type = event["event_type"]
        if event_type == "score_snapshot_imported":
            policy_hash = None
            expected_payload = {"payload_hash": job_payload_hash}
            legacy_expected = (
                None,
                PipelineState.SCORED.value,
                json.dumps(expected_payload, sort_keys=True),
                f"score-import:{event['job_key']}:{job_payload_hash}",
            )
            actual = (
                event["from_state"], event["to_state"],
                event["payload_json"], event["idempotency_key"],
            )
            if actual != legacy_expected:
                LifecycleReducer._verify_current_score_import(
                    conn, event, job, rejected
                )
                return policy_hash, True
            return policy_hash, False
        elif event_type == "opportunity_gate_decided":
            policy_hash = _LEGACY_OPPORTUNITY_POLICY_SUFFIX
            try:
                target = PipelineState(event["to_state"])
                expected_payload = _LEGACY_GATE_PAYLOADS[target]
            except (ValueError, KeyError) as exc:
                raise LedgerDivergence(rejected) from exc
            expected = (
                PipelineState.SCORED.value,
                target.value,
                json.dumps(expected_payload, sort_keys=True),
                f"opportunity-gate:{event['job_key']}:{job_payload_hash}:"
                f"{_LEGACY_OPPORTUNITY_POLICY_SUFFIX}",
            )
        else:  # Defensive if the compatibility set changes without this verifier.
            raise LedgerDivergence(rejected)

        actual = (
            event["from_state"], event["to_state"],
            event["payload_json"], event["idempotency_key"],
        )
        if actual != expected:
            raise LedgerDivergence(rejected)
        return policy_hash, False

    @staticmethod
    def _verify_current_score_import(
        conn: sqlite3.Connection, event: sqlite3.Row, job: sqlite3.Row,
        rejected: str,
    ) -> None:
        """Verify the exact v2 score-import binding used by current writers."""
        try:
            binding = json.loads(event["payload_json"])
            if (not isinstance(binding, dict)
                    or set(binding) != {"format", "snapshot", "snapshot_hash"}
                    or binding["format"] != "score-snapshot-import/v2"):
                raise ValueError("invalid score binding shape")
            snapshot = binding["snapshot"]
            expected_fields = set(_SCORE_SNAPSHOT_STRING_FIELDS) | set(
                _SCORE_SNAPSHOT_NUMERIC_FIELDS
            )
            if not isinstance(snapshot, dict) or set(snapshot) != expected_fields:
                raise ValueError("invalid score snapshot shape")
            if (event["payload_json"] != canonical_json(binding)
                    or binding["snapshot_hash"] != canonical_hash(snapshot)
                    or event["idempotency_key"] != (
                        f"score-import-v2:{event['job_key']}:{canonical_hash(binding)}"
                    )):
                raise ValueError("score binding identity mismatch")
            receipt = conn.execute(
                """SELECT event_id,job_key,binding_json,binding_hash,idempotency_key
                   FROM score_snapshot_receipts WHERE event_id=?""",
                (event["id"],),
            ).fetchone()
            expected_receipt = (
                int(event["id"]), event["job_key"], event["payload_json"],
                canonical_hash(binding), event["idempotency_key"],
            )
            if receipt is None or tuple(receipt) != expected_receipt:
                raise ValueError("score snapshot receipt identity mismatch")
            for field in _SCORE_SNAPSHOT_STRING_FIELDS:
                actual = event["job_key"] if field == "job_key" else job[field]
                if snapshot[field] != actual:
                    raise ValueError("score snapshot metadata mismatch")
            for field in _SCORE_SNAPSHOT_NUMERIC_FIELDS:
                if not LifecycleReducer._score_number_matches(snapshot[field], job[field]):
                    raise ValueError("score snapshot numeric metadata mismatch")
            if (event["from_state"] is not None
                    or event["to_state"] != PipelineState.SCORED.value):
                raise ValueError("invalid score root transition")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LedgerDivergence(f"{rejected}: {exc}") from exc

    @staticmethod
    def _score_number_matches(identity: Any, stored: Any) -> bool:
        if stored is None:
            return identity is None
        if not isinstance(identity, dict) or set(identity) != {"type", "value"}:
            return False
        kind, encoded = identity["type"], identity["value"]
        if not isinstance(encoded, str):
            return False
        try:
            if kind == "int":
                decoded = int(encoded)
                if str(decoded) != encoded:
                    return False
            elif kind == "float":
                decoded = float.fromhex(encoded)
                if not math.isfinite(decoded) or decoded.hex() != encoded:
                    return False
            else:
                return False
        except ValueError:
            return False
        return decoded == stored

    @staticmethod
    def _verify_receipt(conn: sqlite3.Connection, event: sqlite3.Row) -> str:
        receipt = conn.execute("SELECT * FROM lifecycle_transition_receipts WHERE event_id=?", (event["id"],)).fetchone()
        if receipt is None:
            raise LedgerDivergence(f"event {event['id']} has no transition receipt")
        try:
            payload = json.loads(event["payload_json"])
            if (not isinstance(payload, dict)
                    or set(payload) != {"policy", "model", "input_hash", "output_hash"}):
                raise ValueError("invalid transition binding shape")
            policy = payload["policy"]
            if (not isinstance(policy, dict)
                    or set(policy) != {"id", "version", "sha256"}):
                raise ValueError("invalid policy binding shape")
            model = payload["model"]
            if (model is not None
                    and (not isinstance(model, dict)
                         or set(model) != {"provider", "id", "version"})):
                raise ValueError("invalid model binding shape")
            if event["payload_json"] != canonical_json(payload):
                raise ValueError("transition binding is not canonical")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LedgerDivergence(f"event {event['id']} has malformed binding data") from exc
        expected = (event["job_key"], event["from_state"], event["to_state"], event["idempotency_key"],
                    policy["id"], policy["version"], policy["sha256"],
                    payload["input_hash"], payload["output_hash"],
                    None if model is None else model["provider"], None if model is None else model["id"], None if model is None else model["version"])
        actual = (receipt["job_key"], receipt["from_state"], receipt["to_state"], receipt["idempotency_key"],
                  receipt["policy_id"], receipt["policy_version"], receipt["policy_hash"], receipt["input_hash"], receipt["output_hash"],
                  receipt["model_provider"], receipt["model_id"], receipt["model_version"])
        if actual != expected or event["actor_kind"] != ActorKind.DETERMINISTIC.value:
            raise LedgerDivergence(f"event {event['id']} has a tampered receipt identity")
        return str(receipt["policy_hash"])

    def verify(self) -> None:
        self.replay()
