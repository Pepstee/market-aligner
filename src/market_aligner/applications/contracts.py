"""Market-owned v1 boundary for the internal JAA subsystem."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from .events import (
    APPLICATION_EVENTS,
    JAA_EVENT_VERSION,
    EventEnvelope,
    EventProjector,
    encode_event_v1,
    event_id_for,
    parse_event_v1,
)
from .handoff import (
    BASE_COMPATIBILITY_PROFILE,
    JAA_HANDOFF_VERSION,
    STRICT_PROFILE,
    HandoffEnvelope,
    HandoffReplayIndex,
    application_id_for,
    encode_handoff_v1,
    job_key_for,
    logical_handoff_tuple,
    parse_handoff_v1,
)
from .legacy_v0 import LegacyV0ApplicationEvent, LegacyV0ApplicationHandoff


# Import compatibility only. These v0 values are inspection records and never
# confer v1 admission or release authority.
ApplicationEvent = LegacyV0ApplicationEvent
ApplicationHandoff = LegacyV0ApplicationHandoff


def handoff_payload(handoff: ApplicationHandoff) -> Mapping[str, Any]:
    """Return the retained v0 inspection mapping without promoting it to v1."""

    return handoff.__dict__


class JAAClient(Protocol):
    """Internal-JAA adapter supplied only after the protected handoff is sealed."""

    def create_application(self, handoff: HandoffEnvelope) -> str: ...

    def events(self, application_id: str, after: str | None = None) -> list[EventEnvelope]: ...

    def acknowledge(self, event: EventEnvelope) -> None: ...


__all__ = [
    "APPLICATION_EVENTS",
    "ApplicationEvent",
    "ApplicationHandoff",
    "BASE_COMPATIBILITY_PROFILE",
    "EventEnvelope",
    "EventProjector",
    "HandoffEnvelope",
    "HandoffReplayIndex",
    "JAAClient",
    "JAA_EVENT_VERSION",
    "JAA_HANDOFF_VERSION",
    "STRICT_PROFILE",
    "application_id_for",
    "encode_event_v1",
    "encode_handoff_v1",
    "event_id_for",
    "handoff_payload",
    "job_key_for",
    "logical_handoff_tuple",
    "parse_event_v1",
    "parse_handoff_v1",
]
