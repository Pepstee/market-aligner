"""Strict JAA event v1 codec and Market-owned fail-closed projection."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping, Protocol

from market_aligner.applications.canonical import (
    APPLICATION_ID_PATTERN,
    ContractValidationError,
    EVENT_ID_PATTERN,
    JOB_KEY_PATTERN,
    PROFILE_ID_PATTERN,
    canonical_json_bytes,
    deep_freeze_json,
    deep_thaw_json,
    digest_bytes,
    parse_canonical_json,
    require_exact_keys,
    require_integer,
    require_mapping,
    require_nonempty_string,
    require_pattern,
    require_sha256,
    require_sorted_unique_strings,
    require_timestamp,
    validate_strings,
)
from market_aligner.applications.handoff import (
    BASE_COMPATIBILITY_PROFILE,
    STRICT_PROFILE,
    HandoffEnvelope,
)


JAA_EVENT_VERSION = "market-aligner.jaa-event.v1"
APPLICATION_EVENTS = frozenset(
    {
        "strategy_started",
        "artifacts_ready",
        "release_blocked",
        "release_ready",
        "submission_authorized",
        "submission_attempted",
        "receipt_captured",
        "status_changed",
        "outcome_recorded",
    }
)
_ENVELOPE_KEYS = {"payload", "payload_sha256", "schema_version"}
_EVENT_KEYS = {
    "application_id",
    "event_id",
    "event_type",
    "external_receipt_sha256",
    "handoff_root_sha256",
    "job_key",
    "occurred_at",
    "operator_approval_sha256",
    "payload_sha256",
    "profile_id",
}
_DETAIL_KEYS: Mapping[str, set[str]] = {
    "strategy_started": {
        "application_source_identity",
        "schema_version",
        "strategy_id",
        "transition_sequence",
    },
    "artifacts_ready": {
        "answers_sha256",
        "application_source_identity",
        "artifact_set_sha256",
        "cover_letter_pdf_sha256",
        "cv_pdf_sha256",
        "schema_version",
        "transition_sequence",
    },
    "release_blocked": {
        "application_source_identity",
        "block_codes",
        "schema_version",
        "transition_sequence",
    },
    "release_ready": {
        "answers_sha256",
        "application_source_identity",
        "artifact_set_sha256",
        "cover_letter_pdf_sha256",
        "cv_pdf_sha256",
        "employer_assessment_receipt_sha256",
        "schema_version",
        "transition_sequence",
    },
    "submission_authorized": {
        "application_source_identity",
        "artifact_set_sha256",
        "authority_id",
        "authority_use_version",
        "employer_assessment_receipt_sha256",
        "grant_sha256",
        "legal_consent_receipt_sha256",
        "operator_approval_receipt_sha256",
        "provider",
        "route_id",
        "schema_version",
        "transition_sequence",
    },
    "submission_attempted": {
        "attempt_id",
        "authority_id",
        "authority_use_version",
        "click_intent_sha256",
        "grant_sha256",
        "provider",
        "route_id",
        "schema_version",
        "transition_sequence",
    },
    "receipt_captured": {
        "attempt_id",
        "authority_use_version",
        "external_receipt_sha256",
        "grant_sha256",
        "reconciliation_state",
        "schema_version",
        "transition_sequence",
    },
    "status_changed": {
        "new_state",
        "previous_state",
        "schema_version",
        "state_receipt_sha256",
        "transition_sequence",
    },
    "outcome_recorded": {
        "outcome_code",
        "outcome_receipt_sha256",
        "schema_version",
        "transition_sequence",
    },
}
_DIGEST_FIELDS: Mapping[str, tuple[str, ...]] = {
    "strategy_started": ("strategy_id",),
    "artifacts_ready": (
        "answers_sha256",
        "application_source_identity",
        "artifact_set_sha256",
        "cover_letter_pdf_sha256",
        "cv_pdf_sha256",
    ),
    "release_blocked": ("application_source_identity",),
    "release_ready": (
        "answers_sha256",
        "application_source_identity",
        "artifact_set_sha256",
        "cover_letter_pdf_sha256",
        "cv_pdf_sha256",
        "employer_assessment_receipt_sha256",
    ),
    "submission_authorized": (
        "application_source_identity",
        "artifact_set_sha256",
        "employer_assessment_receipt_sha256",
        "grant_sha256",
        "legal_consent_receipt_sha256",
        "operator_approval_receipt_sha256",
    ),
    "submission_attempted": ("click_intent_sha256", "grant_sha256"),
    "receipt_captured": ("external_receipt_sha256", "grant_sha256"),
    "status_changed": ("state_receipt_sha256",),
    "outcome_recorded": ("outcome_receipt_sha256",),
}
PROVIDER_STATES = frozenset(
    {
        "submitted_unconfirmed",
        "submitted_confirmed",
        "under_review",
        "interview",
        "rejected",
        "withdrawn",
        "offer",
        "closed_no_decision",
    }
)
TERMINAL_STATES = frozenset({"rejected", "withdrawn", "offer", "closed_no_decision"})
LEGAL_STATUS_CHANGES: Mapping[str, frozenset[str]] = {
    "submitted_unconfirmed": frozenset(
        {"submitted_confirmed", "under_review", "interview", *TERMINAL_STATES}
    ),
    "submitted_confirmed": frozenset({"under_review", "interview", *TERMINAL_STATES}),
    "under_review": frozenset({"interview", *TERMINAL_STATES}),
    "interview": TERMINAL_STATES,
}
OUTCOME_CODES = frozenset({"submission_failed", *TERMINAL_STATES})


def validate_event_detail(
    detail: Mapping[str, Any], event_type: str, *, strict_profile: bool = True
) -> None:
    if event_type not in APPLICATION_EVENTS:
        raise ContractValidationError("unsupported application event type")
    require_exact_keys(detail, _DETAIL_KEYS[event_type], f"{event_type} detail")
    if detail["schema_version"] != f"jaa.event-detail.{event_type}.v1":
        raise ContractValidationError("event detail schema does not match event type")
    require_integer(detail["transition_sequence"], "transition_sequence", minimum=1)
    for field in _DIGEST_FIELDS[event_type]:
        require_sha256(detail[field], f"{event_type}.{field}")

    if event_type == "strategy_started":
        require_sha256(
            detail["application_source_identity"],
            "strategy_started.application_source_identity",
            nullable=True,
        )
    elif event_type == "release_blocked":
        require_sorted_unique_strings(detail["block_codes"], "release_blocked.block_codes", code_values=True)
    elif event_type == "submission_authorized":
        authority_id = require_nonempty_string(detail["authority_id"], "authority_id")
        if strict_profile and authority_id != authority_id.strip():
            raise ContractValidationError("authority_id must be a trimmed string")
        if detail["authority_use_version"] != 1:
            raise ContractValidationError("submission_authorized authority_use_version must be 1")
        if detail["provider"] != "greenhouse":
            raise ContractValidationError("unsupported submission provider")
        route_id = require_nonempty_string(detail["route_id"], "route_id")
        if strict_profile and route_id != route_id.strip():
            raise ContractValidationError("route_id must be a trimmed string")
    elif event_type == "submission_attempted":
        for name in ("attempt_id", "authority_id", "route_id"):
            text = require_nonempty_string(detail[name], name)
            if strict_profile and text != text.strip():
                raise ContractValidationError(f"{name} must be a trimmed string")
        if detail["authority_use_version"] != 2:
            raise ContractValidationError("submission_attempted authority_use_version must be 2")
        if detail["provider"] != "greenhouse":
            raise ContractValidationError("unsupported submission provider")
    elif event_type == "receipt_captured":
        attempt_id = require_nonempty_string(detail["attempt_id"], "attempt_id")
        if strict_profile and attempt_id != attempt_id.strip():
            raise ContractValidationError("attempt_id must be a trimmed string")
        if detail["authority_use_version"] != 3:
            raise ContractValidationError("receipt_captured authority_use_version must be 3")
        if detail["reconciliation_state"] not in {"positive", "ambiguous", "negative", "unknown"}:
            raise ContractValidationError("unsupported reconciliation state")
    elif event_type == "status_changed":
        if detail["previous_state"] not in PROVIDER_STATES or detail["new_state"] not in PROVIDER_STATES:
            raise ContractValidationError("status_changed contains an unknown provider state")
    elif event_type == "outcome_recorded":
        if detail["outcome_code"] not in OUTCOME_CODES:
            raise ContractValidationError("outcome_recorded contains an unknown outcome")
    validate_strings(detail, require_nfc=strict_profile)


def event_id_for(
    event_payload: Mapping[str, Any],
    detail: Mapping[str, Any],
    *,
    strict_strings: bool = True,
) -> str:
    preimage = {
        "application_id": event_payload["application_id"],
        "detail_sha256": event_payload["payload_sha256"],
        "event_type": event_payload["event_type"],
        "handoff_root_sha256": event_payload["handoff_root_sha256"],
        "transition_sequence": detail["transition_sequence"],
    }
    return "evt_" + digest_bytes(
        canonical_json_bytes(preimage, strict_strings=strict_strings)
    )


def validate_event_payload(
    payload: Mapping[str, Any], detail: Mapping[str, Any], *, strict_profile: bool
) -> None:
    require_exact_keys(payload, _EVENT_KEYS, "event payload")
    require_pattern(payload["application_id"], APPLICATION_ID_PATTERN, "application_id")
    require_pattern(payload["event_id"], EVENT_ID_PATTERN, "event_id")
    require_pattern(payload["profile_id"], PROFILE_ID_PATTERN, "profile_id")
    require_pattern(payload["job_key"], JOB_KEY_PATTERN, "job_key")
    require_sha256(payload["handoff_root_sha256"], "handoff_root_sha256")
    require_sha256(payload["payload_sha256"], "event detail payload_sha256")
    require_timestamp(payload["occurred_at"], "occurred_at", strict_profile=strict_profile)
    event_type = payload["event_type"]
    if event_type not in APPLICATION_EVENTS:
        raise ContractValidationError("unsupported event type")
    validate_event_detail(detail, str(event_type), strict_profile=strict_profile)
    detail_bytes = canonical_json_bytes(detail, strict_strings=strict_profile)
    if digest_bytes(detail_bytes) != payload["payload_sha256"]:
        raise ContractValidationError("event detail digest differs from event payload")
    operator = payload["operator_approval_sha256"]
    external = payload["external_receipt_sha256"]
    require_sha256(operator, "operator_approval_sha256", nullable=True)
    require_sha256(external, "external_receipt_sha256", nullable=True)
    if event_type == "submission_authorized":
        if operator != detail["operator_approval_receipt_sha256"] or external is not None:
            raise ContractValidationError("submission_authorized duplicated receipt differs")
    elif event_type == "receipt_captured":
        if external != detail["external_receipt_sha256"] or operator is not None:
            raise ContractValidationError("receipt_captured duplicated receipt differs")
    elif operator is not None or external is not None:
        raise ContractValidationError("event carries a receipt field outside its one allowed type")
    if payload["event_id"] != event_id_for(
        payload, detail, strict_strings=strict_profile
    ):
        raise ContractValidationError("event_id does not match its deterministic preimage")
    validate_strings(payload, require_nfc=strict_profile)


@dataclass(frozen=True)
class EventEnvelope:
    payload: Mapping[str, Any]
    detail: Mapping[str, Any]
    exact_bytes: bytes
    exact_detail_bytes: bytes
    envelope_payload_sha256: str
    root_sha256: str
    emission_profile: str

    @property
    def event_id(self) -> str:
        return str(self.payload["event_id"])

    @property
    def transition_sequence(self) -> int:
        return int(self.detail["transition_sequence"])


def encode_event_v1(payload: Mapping[str, Any], detail: Mapping[str, Any]) -> EventEnvelope:
    payload_value = deep_thaw_json(payload)
    detail_value = deep_thaw_json(detail)
    validate_event_payload(payload_value, detail_value, strict_profile=True)
    payload_bytes = canonical_json_bytes(payload_value)
    payload_sha = digest_bytes(payload_bytes)
    envelope = {
        "payload": payload_value,
        "payload_sha256": payload_sha,
        "schema_version": JAA_EVENT_VERSION,
    }
    exact_bytes = canonical_json_bytes(envelope)
    detail_bytes = canonical_json_bytes(detail_value)
    return EventEnvelope(
        deep_freeze_json(payload_value),
        deep_freeze_json(detail_value),
        exact_bytes,
        detail_bytes,
        payload_sha,
        digest_bytes(exact_bytes),
        STRICT_PROFILE,
    )


def parse_event_v1(data: bytes, detail_bytes: bytes) -> EventEnvelope:
    envelope = require_mapping(parse_canonical_json(data), "event envelope")
    require_exact_keys(envelope, _ENVELOPE_KEYS, "event envelope")
    if envelope["schema_version"] != JAA_EVENT_VERSION:
        raise ContractValidationError("unsupported event envelope schema")
    require_sha256(envelope["payload_sha256"], "event envelope payload_sha256")
    payload = require_mapping(envelope["payload"], "event payload")
    payload_bytes = canonical_json_bytes(payload, strict_strings=False)
    if digest_bytes(payload_bytes) != envelope["payload_sha256"]:
        raise ContractValidationError("event envelope payload digest differs")
    detail = require_mapping(parse_canonical_json(detail_bytes), "event detail")
    validate_event_payload(payload, detail, strict_profile=False)
    emission_profile = BASE_COMPATIBILITY_PROFILE
    try:
        validate_event_payload(payload, detail, strict_profile=True)
    except ContractValidationError:
        pass
    else:
        emission_profile = STRICT_PROFILE
    return EventEnvelope(
        deep_freeze_json(payload),
        deep_freeze_json(detail),
        data,
        detail_bytes,
        str(envelope["payload_sha256"]),
        digest_bytes(data),
        emission_profile,
    )


@dataclass(frozen=True)
class EventBindingContext:
    handoff_root_sha256: str
    application_id: str
    profile_id: str
    job_key: str
    strategy_id: str | None
    answers_sha256: str | None
    application_source_identity: str | None
    artifact_set_sha256: str | None
    cv_pdf_sha256: str | None
    cover_letter_pdf_sha256: str | None
    employer_assessment_receipt_sha256: str | None
    legal_consent_receipt_sha256: str | None
    operator_approval_receipt_sha256: str | None
    grant_sha256: str | None
    authority_id: str | None
    authority_use_version: int | None
    click_intent_sha256: str | None
    attempt_id: str | None
    provider: str | None
    route_id: str | None
    external_receipt_sha256: str | None


@dataclass(frozen=True)
class VerifiedEventReference:
    reference_key: str
    exact_bytes: bytes
    metadata: Mapping[str, Any]


class EventBindingResolver(Protocol):
    def validate(
        self,
        *,
        event_type: str,
        detail: Mapping[str, Any],
        expected: EventBindingContext,
        occurred_at: str,
    ) -> tuple[VerifiedEventReference, ...] | None: ...


@dataclass(frozen=True)
class EventProjectionState:
    last_sequence: int = 0
    last_event_type: str | None = None
    strategy_id: str | None = None
    strategy_application_source_identity: str | None = None
    answers_sha256: str | None = None
    application_source_identity: str | None = None
    artifact_set_sha256: str | None = None
    cv_pdf_sha256: str | None = None
    cover_letter_pdf_sha256: str | None = None
    employer_assessment_receipt_sha256: str | None = None
    legal_consent_receipt_sha256: str | None = None
    operator_approval_receipt_sha256: str | None = None
    grant_sha256: str | None = None
    authority_id: str | None = None
    authority_use_version: int | None = None
    click_intent_sha256: str | None = None
    attempt_id: str | None = None
    provider: str | None = None
    route_id: str | None = None
    external_receipt_sha256: str | None = None
    reconciliation_state: str | None = None
    provider_status: str | None = None
    state_receipt_sha256: str | None = None
    outcome_receipt_sha256: str | None = None
    outcome_code: str | None = None
    last_occurred_at: str | None = None
    terminal: bool = False


@dataclass(frozen=True)
class EventProjectionResult:
    state: EventProjectionState
    replayed: bool
    verified_references: tuple[VerifiedEventReference, ...] = ()


class EventProjector:
    """Consume one application's exact event stream without inventing JAA state."""

    def __init__(
        self,
        handoff: HandoffEnvelope,
        binding_resolver: EventBindingResolver,
        *,
        initial_state: EventProjectionState | None = None,
    ) -> None:
        self.handoff = handoff
        self.binding_resolver = binding_resolver
        self.state = initial_state or EventProjectionState()
        self._events: dict[str, tuple[bytes, bytes]] = {}

    def _require_next_type(self, event_type: str, detail: Mapping[str, Any]) -> None:
        previous = self.state.last_event_type
        allowed: set[str]
        if previous is None:
            allowed = {"strategy_started"}
        elif previous == "strategy_started":
            allowed = {"artifacts_ready"}
        elif previous == "artifacts_ready":
            allowed = {"release_ready", "release_blocked"}
        elif previous == "release_blocked":
            allowed = {"strategy_started"}
        elif previous == "release_ready":
            allowed = {"submission_authorized", "release_blocked"}
        elif previous == "submission_authorized":
            allowed = {"submission_attempted", "release_blocked"}
        elif previous == "submission_attempted":
            allowed = {"receipt_captured"}
        elif previous == "receipt_captured":
            allowed = (
                {"outcome_recorded"}
                if self.state.reconciliation_state == "negative"
                else {"status_changed"}
            )
        elif previous == "status_changed":
            allowed = {"outcome_recorded"} if self.state.provider_status in TERMINAL_STATES else {"status_changed"}
        else:
            allowed = set()
        if event_type not in allowed:
            raise ContractValidationError(
                f"event automaton forbids {event_type} after {previous or 'none'}"
            )

        if event_type == "status_changed":
            previous_state = str(detail["previous_state"])
            new_state = str(detail["new_state"])
            if previous_state != self.state.provider_status:
                raise ContractValidationError("status_changed previous_state differs from projection")
            if new_state not in LEGAL_STATUS_CHANGES.get(previous_state, frozenset()):
                raise ContractValidationError("illegal provider status transition")
        elif event_type == "outcome_recorded":
            outcome = str(detail["outcome_code"])
            if self.state.reconciliation_state == "negative":
                if outcome != "submission_failed":
                    raise ContractValidationError("negative reconciliation requires submission_failed")
            elif self.state.provider_status not in TERMINAL_STATES or outcome != self.state.provider_status:
                raise ContractValidationError("outcome does not match current terminal provider status")

    def consume(self, event: EventEnvelope) -> EventProjectionResult:
        existing = self._events.get(event.event_id)
        if existing is not None:
            if existing != (event.exact_bytes, event.exact_detail_bytes):
                raise ContractValidationError("same event_id has different exact bytes")
            return EventProjectionResult(self.state, True)
        payload = event.payload
        if payload["handoff_root_sha256"] != self.handoff.root_sha256:
            raise ContractValidationError("event handoff root swap")
        if payload["application_id"] != self.handoff.application_id:
            raise ContractValidationError("event application identity swap")
        if payload["profile_id"] != self.handoff.payload["profile_id"]:
            raise ContractValidationError("event profile swap")
        if payload["job_key"] != self.handoff.payload["job_key"]:
            raise ContractValidationError("event job swap")
        if event.transition_sequence != self.state.last_sequence + 1:
            raise ContractValidationError("event sequence is non-incrementing or contains a gap")
        event_type = str(payload["event_type"])
        self._require_next_type(event_type, event.detail)

        strategy_id = self.state.strategy_id
        strategy_application_source = self.state.strategy_application_source_identity
        answers = self.state.answers_sha256
        application_source = self.state.application_source_identity
        artifact_set = self.state.artifact_set_sha256
        cv_pdf = self.state.cv_pdf_sha256
        cover_letter_pdf = self.state.cover_letter_pdf_sha256
        employer_review = self.state.employer_assessment_receipt_sha256
        legal_consent = self.state.legal_consent_receipt_sha256
        operator_approval = self.state.operator_approval_receipt_sha256
        grant = self.state.grant_sha256
        authority_id = self.state.authority_id
        authority_use_version = self.state.authority_use_version
        click_intent = self.state.click_intent_sha256
        attempt = self.state.attempt_id
        provider = self.state.provider
        route_id = self.state.route_id
        external = self.state.external_receipt_sha256
        if event_type == "strategy_started":
            next_strategy = str(event.detail["strategy_id"])
            if strategy_id is not None and next_strategy == strategy_id:
                raise ContractValidationError(
                    "restart must use a new strategy identity"
                )
            next_strategy_application_source = event.detail[
                "application_source_identity"
            ]
            if (
                next_strategy_application_source is not None
                and application_source is not None
                and next_strategy_application_source == application_source
            ):
                raise ContractValidationError(
                    "restart strategy cannot reuse the prior application-source identity"
                )
            strategy_id = next_strategy
            strategy_application_source = next_strategy_application_source
        elif event_type == "artifacts_ready":
            if (
                strategy_application_source is not None
                and event.detail["application_source_identity"]
                != strategy_application_source
            ):
                raise ContractValidationError(
                    "artifacts_ready application source differs from strategy"
                )
            if (
                application_source is not None
                and event.detail["application_source_identity"] == application_source
            ):
                raise ContractValidationError(
                    "restart must use a new application-source identity"
                )
            if artifact_set is not None and event.detail["artifact_set_sha256"] == artifact_set:
                raise ContractValidationError("restart must use a new artifact set")
            answers = str(event.detail["answers_sha256"])
            application_source = str(event.detail["application_source_identity"])
            artifact_set = str(event.detail["artifact_set_sha256"])
            cv_pdf = str(event.detail["cv_pdf_sha256"])
            cover_letter_pdf = str(event.detail["cover_letter_pdf_sha256"])
        elif event_type == "release_blocked":
            if application_source is None or event.detail["application_source_identity"] != application_source:
                raise ContractValidationError("release_blocked application-source substitution")
        elif event_type == "release_ready":
            if answers is None or event.detail["answers_sha256"] != answers:
                raise ContractValidationError("release_ready answer corpus substitution")
            if artifact_set is None or event.detail["artifact_set_sha256"] != artifact_set:
                raise ContractValidationError("release_ready artifact set substitution")
            for field, expected_value in (
                ("application_source_identity", application_source),
                ("cv_pdf_sha256", cv_pdf),
                ("cover_letter_pdf_sha256", cover_letter_pdf),
            ):
                if expected_value is None or event.detail[field] != expected_value:
                    raise ContractValidationError(f"release_ready {field} substitution")
            next_employer_review = str(
                event.detail["employer_assessment_receipt_sha256"]
            )
            if employer_review is not None and next_employer_review == employer_review:
                raise ContractValidationError(
                    "restart must use a new employer-review receipt"
                )
            employer_review = next_employer_review
        elif event_type == "submission_authorized":
            if artifact_set is None or event.detail["artifact_set_sha256"] != artifact_set:
                raise ContractValidationError("submission_authorized artifact set substitution")
            if application_source is None or event.detail["application_source_identity"] != application_source:
                raise ContractValidationError("submission_authorized application-source substitution")
            if employer_review is None or event.detail["employer_assessment_receipt_sha256"] != employer_review:
                raise ContractValidationError("submission_authorized review-receipt substitution")
            grant = str(event.detail["grant_sha256"])
            authority_id = str(event.detail["authority_id"])
            authority_use_version = int(event.detail["authority_use_version"])
            legal_consent = str(event.detail["legal_consent_receipt_sha256"])
            operator_approval = str(event.detail["operator_approval_receipt_sha256"])
            provider = str(event.detail["provider"])
            route_id = str(event.detail["route_id"])
        elif event_type == "submission_attempted":
            if grant is None or event.detail["grant_sha256"] != grant:
                raise ContractValidationError("submission_attempted grant substitution")
            if authority_id is None or event.detail["authority_id"] != authority_id:
                raise ContractValidationError("submission_attempted authority substitution")
            if provider is None or event.detail["provider"] != provider or event.detail["route_id"] != route_id:
                raise ContractValidationError("submission_attempted route substitution")
            attempt = str(event.detail["attempt_id"])
            authority_use_version = int(event.detail["authority_use_version"])
            click_intent = str(event.detail["click_intent_sha256"])
        elif event_type == "receipt_captured":
            if grant is None or event.detail["grant_sha256"] != grant:
                raise ContractValidationError("receipt_captured grant substitution")
            if attempt is None or event.detail["attempt_id"] != attempt:
                raise ContractValidationError("receipt_captured attempt substitution")
            external = str(event.detail["external_receipt_sha256"])
            authority_use_version = int(event.detail["authority_use_version"])

        expected = EventBindingContext(
            handoff_root_sha256=self.handoff.root_sha256,
            application_id=self.handoff.application_id,
            profile_id=str(self.handoff.payload["profile_id"]),
            job_key=str(self.handoff.payload["job_key"]),
            strategy_id=strategy_id,
            answers_sha256=answers,
            application_source_identity=application_source,
            artifact_set_sha256=artifact_set,
            cv_pdf_sha256=cv_pdf,
            cover_letter_pdf_sha256=cover_letter_pdf,
            employer_assessment_receipt_sha256=employer_review,
            legal_consent_receipt_sha256=legal_consent,
            operator_approval_receipt_sha256=operator_approval,
            grant_sha256=grant,
            authority_id=authority_id,
            authority_use_version=authority_use_version,
            click_intent_sha256=click_intent,
            attempt_id=attempt,
            provider=provider,
            route_id=route_id,
            external_receipt_sha256=external,
        )
        verified_references = self.binding_resolver.validate(
            event_type=event_type,
            detail=event.detail,
            expected=expected,
            occurred_at=str(payload["occurred_at"]),
        ) or ()

        next_state = replace(
            self.state,
            last_sequence=event.transition_sequence,
            last_event_type=event_type,
            strategy_id=strategy_id,
            strategy_application_source_identity=strategy_application_source,
            answers_sha256=answers,
            application_source_identity=application_source,
            artifact_set_sha256=artifact_set,
            cv_pdf_sha256=cv_pdf,
            cover_letter_pdf_sha256=cover_letter_pdf,
            employer_assessment_receipt_sha256=employer_review,
            legal_consent_receipt_sha256=legal_consent,
            operator_approval_receipt_sha256=operator_approval,
            grant_sha256=grant,
            authority_id=authority_id,
            authority_use_version=authority_use_version,
            click_intent_sha256=click_intent,
            attempt_id=attempt,
            provider=provider,
            route_id=route_id,
            external_receipt_sha256=external,
            last_occurred_at=str(payload["occurred_at"]),
        )
        if event_type == "receipt_captured":
            reconciliation = str(event.detail["reconciliation_state"])
            provider_status = {
                "positive": "submitted_confirmed",
                "ambiguous": "submitted_unconfirmed",
                "unknown": "submitted_unconfirmed",
                "negative": "submission_failed_terminal",
            }[reconciliation]
            next_state = replace(
                next_state,
                reconciliation_state=reconciliation,
                provider_status=provider_status,
            )
        elif event_type == "status_changed":
            next_state = replace(
                next_state,
                provider_status=str(event.detail["new_state"]),
                state_receipt_sha256=str(event.detail["state_receipt_sha256"]),
            )
        elif event_type == "outcome_recorded":
            next_state = replace(
                next_state,
                outcome_receipt_sha256=str(event.detail["outcome_receipt_sha256"]),
                outcome_code=str(event.detail["outcome_code"]),
                terminal=True,
            )
        self._events[event.event_id] = (event.exact_bytes, event.exact_detail_bytes)
        self.state = next_state
        return EventProjectionResult(next_state, False, tuple(verified_references))
