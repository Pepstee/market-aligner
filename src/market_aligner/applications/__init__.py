"""Versioned Market Aligner contracts for its internal JAA subsystem.

The public symbols are loaded lazily so lower-level canonical helpers do not create
an assessment/application import cycle.
"""

from __future__ import annotations

from typing import Any


__all__ = [
    "ApplicationEvent",
    "ApplicationHandoff",
    "EventEnvelope",
    "EventProjector",
    "HandoffEnvelope",
    "HandoffReplayIndex",
    "JAAClient",
    "encode_event_v1",
    "encode_handoff_v1",
    "parse_event_v1",
    "parse_handoff_v1",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from . import contracts

        return getattr(contracts, name)
    raise AttributeError(name)
