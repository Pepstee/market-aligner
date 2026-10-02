"""Transactional receiver for exact JAA events, recovered from retained lineage.

This distinct receiving lifecycle reuses Market's projector and AssessmentStore.
JAA's outgoing event tables remain separate. A configured binding resolver is
mandatory; this module does not manufacture receipt authentication.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any

from market_aligner.applications.canonical import (
    ContractValidationError,
    canonical_json_bytes,
    digest_bytes,
    parse_canonical_json,
    require_exact_keys,
    require_mapping,
)
from market_aligner.applications.events import (
    EventBindingResolver,
    EventProjectionState,
    EventProjector,
    VerifiedEventReference,
    parse_event_v1,
)
from market_aligner.applications.handoff import parse_handoff_v1
from market_aligner.research.store import AssessmentStore


_STATE_KEYS = {field.name for field in fields(EventProjectionState)}


@dataclass(frozen=True)
class DurableEventResult:
    state: EventProjectionState
    replayed: bool


def _state_bytes(state: EventProjectionState) -> bytes:
    return canonical_json_bytes(
        {"projection": asdict(state), "schema_version": "market-aligner.event-projection.v1"}
    )


def _parse_state(data: bytes) -> EventProjectionState:
    value = require_mapping(parse_canonical_json(data), "event projection")
    require_exact_keys(value, {"projection", "schema_version"}, "event projection")
    if value["schema_version"] != "market-aligner.event-projection.v1":
        raise ContractValidationError("unsupported event projection schema")
    projection = require_mapping(value["projection"], "event projection state")
    state_value = dict(projection)
    added_state_keys = {"strategy_id", "strategy_application_source_identity"}
    legacy_keys = _STATE_KEYS - added_state_keys
    if set(state_value) == legacy_keys:
        state_value["strategy_id"] = None
        state_value["strategy_application_source_identity"] = None
    else:
        require_exact_keys(state_value, _STATE_KEYS, "event projection state")
    state = EventProjectionState(**state_value)
    if isinstance(state.last_sequence, bool) or not isinstance(state.last_sequence, int):
        raise ContractValidationError("stored event sequence is invalid")
    if not isinstance(state.terminal, bool):
        raise ContractValidationError("stored event terminal flag is invalid")
    return state


class DurableEventConsumer:
    def __init__(self, store: AssessmentStore, binding_resolver: EventBindingResolver) -> None:
        if binding_resolver is None:
            raise TypeError("event consumption requires a binding resolver")
        self.store = store
        self.binding_resolver = binding_resolver

    @staticmethod
    def _persist_reference(connection, reference: VerifiedEventReference) -> str:
        object_sha = digest_bytes(reference.exact_bytes)
        connection.execute(
            "INSERT OR IGNORE INTO v1_reference_objects VALUES(?,?)",
            (object_sha, reference.exact_bytes),
        )
        object_row = connection.execute(
            "SELECT exact_bytes FROM v1_reference_objects WHERE object_sha256=?", (object_sha,)
        ).fetchone()
        if object_row is None or bytes(object_row["exact_bytes"]) != reference.exact_bytes:
            raise ContractValidationError("event reference object identity conflicts")
        metadata = dict(reference.metadata)
        metadata_bytes = canonical_json_bytes(metadata)
        metadata_sha = digest_bytes(metadata_bytes)
        connection.execute(
            """INSERT OR IGNORE INTO v1_reference_resolutions(
                 metadata_sha256,object_sha256,reference_key,type_id,schema_version,
                 subject_bytes,issuer_id,trust_root_id,trust_proof_sha256,issued_at,
                 valid_until,exact_metadata_bytes
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                metadata_sha,
                object_sha,
                metadata["reference_key"],
                metadata["type_id"],
                metadata["schema_version"],
                canonical_json_bytes(metadata["subject"]),
                metadata["issuer_id"],
                metadata["trust_root_id"],
                metadata["trust_proof_sha256"],
                metadata["issued_at"],
                metadata["valid_until"],
                metadata_bytes,
            ),
        )
        metadata_row = connection.execute(
            """SELECT exact_metadata_bytes FROM v1_reference_resolutions
               WHERE metadata_sha256=?""",
            (metadata_sha,),
        ).fetchone()
        if metadata_row is None or bytes(metadata_row["exact_metadata_bytes"]) != metadata_bytes:
            raise ContractValidationError("event reference metadata identity conflicts")
        return metadata_sha

    def consume(self, envelope_bytes: bytes, detail_bytes: bytes) -> DurableEventResult:
        event = parse_event_v1(envelope_bytes, detail_bytes)
        with self.store.transaction() as connection:
            existing = connection.execute(
                """SELECT envelope_exact_bytes,detail_exact_bytes,application_id,handoff_root_sha256
                   FROM v1_event_inbox WHERE event_id=?""",
                (event.event_id,),
            ).fetchone()
            if existing is not None:
                if (
                    bytes(existing["envelope_exact_bytes"]) != envelope_bytes
                    or bytes(existing["detail_exact_bytes"]) != detail_bytes
                ):
                    raise ContractValidationError("same event_id has different exact bytes")
                projection = connection.execute(
                    "SELECT state_bytes FROM v1_event_projection WHERE application_id=? AND handoff_root_sha256=?",
                    (existing["application_id"], existing["handoff_root_sha256"]),
                ).fetchone()
                if projection is None:
                    raise ContractValidationError("replayed event has no durable projection")
                return DurableEventResult(_parse_state(bytes(projection["state_bytes"])), True)

            published = connection.execute(
                "SELECT handoff_exact_bytes FROM published_application_handoffs "
                "WHERE application_id=? AND handoff_root_sha256=?",
                (event.payload["application_id"], event.payload["handoff_root_sha256"]),
            ).fetchall()
            if not published:
                raise ContractValidationError("event has no matching published handoff")
            exact_handoff = bytes(published[0]["handoff_exact_bytes"])
            if any(bytes(row["handoff_exact_bytes"]) != exact_handoff for row in published):
                raise ContractValidationError("published handoff identities conflict")
            handoff = parse_handoff_v1(exact_handoff)
            if (handoff.application_id != event.payload["application_id"]
                    or handoff.root_sha256 != event.payload["handoff_root_sha256"]):
                raise ContractValidationError("published handoff binding differs")
            projection_row = connection.execute(
                "SELECT state_bytes FROM v1_event_projection WHERE application_id=? AND handoff_root_sha256=?",
                (handoff.application_id, handoff.root_sha256),
            ).fetchone()
            initial_state = (
                EventProjectionState()
                if projection_row is None
                else _parse_state(bytes(projection_row["state_bytes"]))
            )
            result = EventProjector(
                handoff, self.binding_resolver, initial_state=initial_state
            ).consume(event)
            try:
                connection.execute(
                    """INSERT INTO v1_event_inbox VALUES(
                         ?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP
                       )""",
                    (
                        event.event_id,
                        handoff.application_id,
                        handoff.root_sha256,
                        event.transition_sequence,
                        event.payload["event_type"],
                        event.payload["occurred_at"],
                        envelope_bytes,
                        detail_bytes,
                        event.root_sha256,
                    ),
                )
            except Exception as exc:
                raise ContractValidationError("event sequence conflicts with durable history") from exc
            for reference in result.verified_references:
                metadata_sha = self._persist_reference(connection, reference)
                connection.execute(
                    "INSERT INTO v1_event_references VALUES(?,?,?)",
                    (event.event_id, reference.reference_key, metadata_sha),
                )
            projection_bytes = _state_bytes(result.state)
            connection.execute(
                """INSERT INTO v1_event_projection(
                     application_id,handoff_root_sha256,state_bytes,last_sequence,last_event_id,terminal
                   ) VALUES(?,?,?,?,?,?)
                   ON CONFLICT(application_id,handoff_root_sha256) DO UPDATE SET
                     state_bytes=excluded.state_bytes,
                     last_sequence=excluded.last_sequence,
                     last_event_id=excluded.last_event_id,
                     terminal=excluded.terminal,
                     updated_at=CURRENT_TIMESTAMP""",
                (
                    handoff.application_id,
                    handoff.root_sha256,
                    projection_bytes,
                    result.state.last_sequence,
                    event.event_id,
                    int(result.state.terminal),
                ),
            )
            return DurableEventResult(result.state, False)

    def state(
        self, application_id: str, handoff_root_sha256: str | None = None
    ) -> EventProjectionState:
        with self.store.connection() as connection:
            if handoff_root_sha256 is None:
                rows = connection.execute(
                    "SELECT state_bytes FROM v1_event_projection WHERE application_id=?",
                    (application_id,),
                ).fetchall()
                if len(rows) > 1:
                    raise ContractValidationError("multiple event roots require an explicit handoff root")
                row = rows[0] if rows else None
            else:
                row = connection.execute(
                    "SELECT state_bytes FROM v1_event_projection WHERE application_id=? AND handoff_root_sha256=?",
                    (application_id, handoff_root_sha256),
                ).fetchone()
        if row is None:
            return EventProjectionState()
        return _parse_state(bytes(row["state_bytes"]))
