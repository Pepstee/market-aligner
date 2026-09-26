"""Versioned Market Aligner contracts for its internal JAA subsystem.

The public symbols are loaded lazily so lower-level canonical helpers do not create
an assessment/application import cycle.
"""

from __future__ import annotations

from typing import Any


_CONTRACT_EXPORTS = [
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

# Historical public JAA diagnostics surface (donor __init__ blob 2d1e23da).
# Owners live in .jaa; each name is resolved lazily to keep import cycles out
# of contract consumers that never touch the diagnostics surface.
_JAA_EXPORTS = frozenset(
    {
        "ApplicationSource",
        "ATSForensicLearningEvent",
        "ATSForensicReceipt",
        "ATSForensicRecorder",
        "AtsFieldOption",
        "AtsFixturePreSubmitAuthority",
        "AtsFormInventory",
        "AtsObservationAcceptance",
        "AtsObservationAcceptanceReceipt",
        "AtsObservationAuthority",
        "AtsObservedField",
        "AtsPreSubmitField",
        "AtsReadOnlyObservation",
        "CaptureBackend",
        "FixtureCaptureBackend",
        "MARKET_OBSERVATION_KEY_ID",
        "MARKET_OBSERVATION_PUBLIC_DER_SHA256",
        "SanityReviewReceipt",
        "capture_or_recover",
        "compile_fixture_pre_submit_plan",
        "execute_fixture_pre_submit_or_recover",
        "list_canary_learning_events",
        "load_forensic_receipt",
        "market_observation_consumption_root_sha256",
        "observe_ats_form_or_recover",
        "prepare_from_market",
        "record_canary_learning_event",
        "verify_and_consume_market_observation_acceptance",
        "verify_canary_learning_event",
    }
)

__all__ = [*_CONTRACT_EXPORTS, *sorted(_JAA_EXPORTS)]


def __getattr__(name: str) -> Any:
    if name in _CONTRACT_EXPORTS:
        from . import contracts

        return getattr(contracts, name)
    if name in _JAA_EXPORTS:
        from . import jaa

        return getattr(jaa, name)
    raise AttributeError(name)
