"""Registry-v1.1 reverse resolver evidence for JAA state/outcome events."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Protocol, Sequence

from market_aligner.applications.canonical import (
    ContractValidationError,
    MAX_SAFE_INTEGER,
    canonical_json_bytes,
    parse_canonical_json,
)


STATE_REFERENCE_KEY = "event.state_receipt"
OUTCOME_REFERENCE_KEY = "event.outcome_receipt"
STATE_TYPE_ID = "provider_state_receipt"
OUTCOME_TYPE_ID = "application_outcome_receipt"
STATE_SCHEMA = "jaa.provider-state-receipt.v1"
OUTCOME_SCHEMA = "jaa.application-outcome-receipt.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^evt_[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class EventReceiptError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class EventReceiptEvidence:
    """Exact opaque receipt bytes plus canonical authenticated resolver metadata."""

    exact_bytes: bytes
    metadata_bytes: bytes
    environment: str
    resolver_identity_sha256: str

    def __post_init__(self) -> None:
        if type(self.exact_bytes) is not bytes or not self.exact_bytes:
            raise EventReceiptError(
                "receipt_bytes", "event receipt exact bytes are required"
            )
        if type(self.metadata_bytes) is not bytes or not self.metadata_bytes:
            raise EventReceiptError(
                "receipt_metadata", "event receipt metadata is required"
            )
        if self.environment not in {"synthetic", "production"}:
            raise EventReceiptError(
                "receipt_environment", "event receipt environment is invalid"
            )
        if not _SHA256.fullmatch(self.resolver_identity_sha256):
            raise EventReceiptError(
                "receipt_resolver", "event receipt resolver identity is invalid"
            )

    @property
    def object_sha256(self) -> str:
        return hashlib.sha256(self.exact_bytes).hexdigest()

    @property
    def metadata_sha256(self) -> str:
        return hashlib.sha256(self.metadata_bytes).hexdigest()


@dataclass(frozen=True)
class ValidatedEventReceipt:
    evidence: EventReceiptEvidence
    reference_key: str
    type_id: str
    schema_version: str
    subject: Mapping[str, object]
    issued_at: str
    issuer_id: str
    trust_root_id: str
    trust_proof_sha256: str


@dataclass(frozen=True)
class EventReceiptReference:
    """Trusted event-derived identity for one reverse receipt reference."""

    event_id: str
    event_type: str
    transition_sequence: int
    occurred_at: str
    kind: str
    object_sha256: str
    expected_subject: Mapping[str, object]

    def __post_init__(self) -> None:
        _validate_registry_binding_fields(
            event_id=self.event_id,
            event_type=self.event_type,
            transition_sequence=self.transition_sequence,
            occurred_at=self.occurred_at,
            kind=self.kind,
            object_sha256=self.object_sha256,
        )
        if type(self.expected_subject) is not dict:
            raise EventReceiptError(
                "receipt_subject",
                "event-derived receipt subject must be an exact dict",
            )


@dataclass(frozen=True)
class EventReceiptRegistryEntry:
    """One published receipt bound to its exact event, sequence and instant."""

    event_id: str
    event_type: str
    transition_sequence: int
    occurred_at: str
    kind: str
    object_sha256: str
    metadata_sha256: str
    declared_subject: Mapping[str, object]
    evidence: EventReceiptEvidence

    def __post_init__(self) -> None:
        _validate_registry_binding_fields(
            event_id=self.event_id,
            event_type=self.event_type,
            transition_sequence=self.transition_sequence,
            occurred_at=self.occurred_at,
            kind=self.kind,
            object_sha256=self.object_sha256,
        )
        if type(self.evidence) is not EventReceiptEvidence:
            raise EventReceiptError(
                "receipt_registry",
                "event receipt registry evidence has the wrong type",
            )
        if not isinstance(self.metadata_sha256, str) or not _SHA256.fullmatch(
            self.metadata_sha256
        ):
            raise EventReceiptError(
                "receipt_substitution",
                "event receipt metadata digest is invalid",
            )
        if type(self.declared_subject) is not dict:
            raise EventReceiptError(
                "receipt_subject",
                "published event receipt subject must be an exact dict",
            )


class EventReceiptAuthenticator(Protocol):
    event_resolver_identity_sha256: str

    def authenticate_event_receipt(
        self,
        *,
        exact_bytes: bytes,
        metadata_bytes: bytes,
        environment: str,
        expected_subject: Mapping[str, object],
        occurred_at: str,
    ) -> None:
        """Authenticate JAA outbox trust state for one exact reverse receipt."""


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise EventReceiptError("receipt_time", f"{label} must be whole-second UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EventReceiptError(
            "receipt_time", f"{label} is not a real instant"
        ) from exc
    if parsed.tzinfo != timezone.utc:
        raise EventReceiptError("receipt_time", f"{label} must be UTC")
    return parsed


def _validate_registry_binding_fields(
    *,
    event_id: object,
    event_type: object,
    transition_sequence: object,
    occurred_at: object,
    kind: object,
    object_sha256: object,
) -> None:
    if not isinstance(event_id, str) or not _EVENT_ID.fullmatch(event_id):
        raise EventReceiptError("receipt_event", "event receipt event ID is invalid")
    expected_event_type = {
        "state": "status_changed",
        "outcome": "outcome_recorded",
    }.get(kind)
    if expected_event_type is None:
        raise EventReceiptError("receipt_kind", "event receipt kind is invalid")
    if event_type != expected_event_type:
        raise EventReceiptError(
            "receipt_event",
            "event receipt kind and event type differ",
        )
    if (
        type(transition_sequence) is not int
        or not 0 < transition_sequence <= MAX_SAFE_INTEGER
    ):
        raise EventReceiptError(
            "receipt_sequence",
            "event receipt transition sequence is invalid",
        )
    _parse_time(occurred_at, "event receipt occurred_at binding")
    if not isinstance(object_sha256, str) or not _SHA256.fullmatch(object_sha256):
        raise EventReceiptError(
            "receipt_substitution",
            "event receipt object digest is invalid",
        )


def validate_event_receipt(
    evidence: EventReceiptEvidence,
    *,
    kind: str,
    expected_subject: Mapping[str, object],
    occurred_at: str,
    authenticator: EventReceiptAuthenticator,
) -> ValidatedEventReceipt:
    """Validate exact registry metadata and configured trust before persistence."""

    if kind == "state":
        reference_key, type_id, schema_version = (
            STATE_REFERENCE_KEY,
            STATE_TYPE_ID,
            STATE_SCHEMA,
        )
    elif kind == "outcome":
        reference_key, type_id, schema_version = (
            OUTCOME_REFERENCE_KEY,
            OUTCOME_TYPE_ID,
            OUTCOME_SCHEMA,
        )
    else:
        raise EventReceiptError("receipt_kind", "event receipt kind is invalid")
    if not isinstance(expected_subject, dict):
        raise EventReceiptError(
            "receipt_subject", "expected event receipt subject must be a dict"
        )
    expected_resolver = getattr(authenticator, "event_resolver_identity_sha256", None)
    if expected_resolver != evidence.resolver_identity_sha256:
        raise EventReceiptError(
            "receipt_resolver", "configured reverse resolver identity differs"
        )
    try:
        metadata = parse_canonical_json(evidence.metadata_bytes)
    except ContractValidationError as exc:
        raise EventReceiptError("receipt_metadata", str(exc)) from exc
    expected_keys = {
        "issued_at",
        "issuer_id",
        "object_sha256",
        "reference_key",
        "schema_version",
        "subject",
        "trust_proof_sha256",
        "trust_root_id",
        "type_id",
        "valid_until",
    }
    if type(metadata) is not dict or set(metadata) != expected_keys:
        raise EventReceiptError(
            "receipt_metadata", "event receipt metadata keys differ"
        )
    exact = {
        "object_sha256": evidence.object_sha256,
        "reference_key": reference_key,
        "schema_version": schema_version,
        "subject": dict(expected_subject),
        "type_id": type_id,
        "valid_until": None,
    }
    if any(metadata.get(key) != value for key, value in exact.items()):
        raise EventReceiptError(
            "receipt_substitution", "event receipt registry binding differs"
        )
    issued_at = metadata.get("issued_at")
    if _parse_time(issued_at, "event receipt issued_at") > _parse_time(
        occurred_at, "event occurred_at"
    ):
        raise EventReceiptError(
            "receipt_future", "event receipt was issued after its event"
        )
    for key in ("issuer_id", "trust_root_id"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value or value != value.strip():
            raise EventReceiptError(
                "receipt_metadata", f"event receipt {key} is invalid"
            )
    proof = metadata.get("trust_proof_sha256")
    if not isinstance(proof, str) or not _SHA256.fullmatch(proof):
        raise EventReceiptError(
            "receipt_metadata", "event receipt trust proof is invalid"
        )
    try:
        authenticator.authenticate_event_receipt(
            exact_bytes=evidence.exact_bytes,
            metadata_bytes=evidence.metadata_bytes,
            environment=evidence.environment,
            expected_subject=dict(expected_subject),
            occurred_at=occurred_at,
        )
    except EventReceiptError:
        raise
    except Exception as exc:
        raise EventReceiptError(
            "receipt_authentication", "event receipt proof is not trusted"
        ) from exc
    return ValidatedEventReceipt(
        evidence=evidence,
        reference_key=reference_key,
        type_id=type_id,
        schema_version=schema_version,
        subject=dict(expected_subject),
        issued_at=str(issued_at),
        issuer_id=str(metadata["issuer_id"]),
        trust_root_id=str(metadata["trust_root_id"]),
        trust_proof_sha256=str(proof),
    )


def validate_event_receipt_registry(
    references: Sequence[EventReceiptReference],
    entries: Sequence[EventReceiptRegistryEntry],
    *,
    authenticator: EventReceiptAuthenticator,
) -> tuple[ValidatedEventReceipt, ...]:
    """Validate complete one-to-one reverse-receipt coverage for an event stream.

    ``references`` must be derived from already-validated event identities and
    details. Published entries are then matched by event ID and object digest;
    receipt kind is deliberately not unique because one stream may contain many
    state transitions.
    """

    trusted: list[EventReceiptReference] = []
    references_by_event: dict[str, EventReceiptReference] = {}
    referenced_objects: set[str] = set()
    for reference in references:
        if type(reference) is not EventReceiptReference:
            raise EventReceiptError(
                "receipt_registry",
                "event-derived receipt reference has the wrong type",
            )
        if reference.event_id in references_by_event:
            raise EventReceiptError(
                "receipt_duplicate",
                "event-derived receipt reference repeats an event ID",
            )
        if reference.object_sha256 in referenced_objects:
            raise EventReceiptError(
                "receipt_duplicate",
                "event-derived receipt reference repeats an object digest",
            )
        references_by_event[reference.event_id] = reference
        referenced_objects.add(reference.object_sha256)
        trusted.append(reference)

    entries_by_event: dict[str, EventReceiptRegistryEntry] = {}
    published_objects: set[str] = set()
    for entry in entries:
        if type(entry) is not EventReceiptRegistryEntry:
            raise EventReceiptError(
                "receipt_registry",
                "published event receipt entry has the wrong type",
            )
        if (
            entry.event_id in entries_by_event
            or entry.object_sha256 in published_objects
        ):
            raise EventReceiptError(
                "receipt_duplicate",
                "published event receipt repeats an event ID or object digest",
            )
        if entry.event_id not in references_by_event:
            raise EventReceiptError(
                "receipt_event",
                "published reverse receipt names an unreferenced event",
            )
        entries_by_event[entry.event_id] = entry
        published_objects.add(entry.object_sha256)

    missing = [
        reference.event_id
        for reference in trusted
        if reference.event_id not in entries_by_event
    ]
    if missing:
        raise EventReceiptError(
            "receipt_missing",
            "one or more referenced events have no reverse receipt",
        )

    validated: list[ValidatedEventReceipt] = []
    for reference in trusted:
        entry = entries_by_event[reference.event_id]
        if entry.event_type != reference.event_type or entry.kind != reference.kind:
            raise EventReceiptError(
                "receipt_event",
                "published reverse receipt event binding differs",
            )
        if entry.transition_sequence != reference.transition_sequence:
            raise EventReceiptError(
                "receipt_sequence",
                "published reverse receipt sequence differs from its event",
            )
        if entry.occurred_at != reference.occurred_at:
            raise EventReceiptError(
                "receipt_time_binding",
                "published reverse receipt instant differs from its event",
            )
        if (
            entry.object_sha256 != reference.object_sha256
            or entry.evidence.object_sha256 != entry.object_sha256
            or entry.metadata_sha256 != entry.evidence.metadata_sha256
            or entry.declared_subject != reference.expected_subject
        ):
            raise EventReceiptError(
                "receipt_substitution",
                "published reverse receipt object differs from its event reference",
            )
        validated.append(
            validate_event_receipt(
                entry.evidence,
                kind=reference.kind,
                expected_subject=reference.expected_subject,
                occurred_at=reference.occurred_at,
                authenticator=authenticator,
            )
        )
    return tuple(validated)


def build_event_receipt_metadata(
    *,
    exact_bytes: bytes,
    issued_at: str,
    issuer_id: str,
    kind: str,
    subject: Mapping[str, object],
    trust_proof_sha256: str,
    trust_root_id: str,
) -> bytes:
    """Canonical synthetic/provider helper; authentication remains adapter-owned."""

    if kind == "state":
        reference_key, type_id, schema_version = (
            STATE_REFERENCE_KEY,
            STATE_TYPE_ID,
            STATE_SCHEMA,
        )
    elif kind == "outcome":
        reference_key, type_id, schema_version = (
            OUTCOME_REFERENCE_KEY,
            OUTCOME_TYPE_ID,
            OUTCOME_SCHEMA,
        )
    else:
        raise EventReceiptError("receipt_kind", "event receipt kind is invalid")
    return canonical_json_bytes(
        {
            "issued_at": issued_at,
            "issuer_id": issuer_id,
            "object_sha256": hashlib.sha256(exact_bytes).hexdigest(),
            "reference_key": reference_key,
            "schema_version": schema_version,
            "subject": dict(subject),
            "trust_proof_sha256": trust_proof_sha256,
            "trust_root_id": trust_root_id,
            "type_id": type_id,
            "valid_until": None,
        }
    )


__all__ = [
    "EventReceiptAuthenticator",
    "EventReceiptError",
    "EventReceiptEvidence",
    "EventReceiptReference",
    "EventReceiptRegistryEntry",
    "ValidatedEventReceipt",
    "build_event_receipt_metadata",
    "validate_event_receipt",
    "validate_event_receipt_registry",
]
