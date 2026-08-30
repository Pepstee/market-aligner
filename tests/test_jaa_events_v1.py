"""Adversarial contract tests for the recovered Market-owned JAA event stream."""

from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

import pytest

from market_aligner.applications.canonical import (
    ContractValidationError,
    canonical_json_bytes,
    digest_bytes,
)
from market_aligner.applications.events import (
    EventProjector,
    VerifiedEventReference,
    encode_event_v1,
    event_id_for,
    parse_event_v1,
)
from market_aligner.applications.handoff import parse_handoff_v1
from market_aligner.applications.legacy_v0 import (
    LegacyV0ApplicationHandoff,
    parse_legacy_v0_handoff_for_inspection,
)


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "internal"
    / "jaa"
    / "career_automation"
    / "fixtures"
    / "market-aligner-v1-vectors.json"
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _handoff():
    document = json.loads(FIXTURE.read_bytes())
    return parse_handoff_v1(
        base64.b64decode(document["handoff"]["canonical_base64"], validate=True)
    )


def _event(
    handoff,
    event_type: str,
    detail: Mapping[str, Any],
    *,
    operator_approval_sha256: str | None = None,
    external_receipt_sha256: str | None = None,
):
    detail_value = deepcopy(dict(detail))
    payload = {
        "application_id": handoff.application_id,
        "event_id": "evt_" + "0" * 64,
        "event_type": event_type,
        "external_receipt_sha256": external_receipt_sha256,
        "handoff_root_sha256": handoff.root_sha256,
        "job_key": handoff.payload["job_key"],
        "occurred_at": "2026-08-10T10:10:00Z",
        "operator_approval_sha256": operator_approval_sha256,
        "payload_sha256": digest_bytes(canonical_json_bytes(detail_value)),
        "profile_id": handoff.payload["profile_id"],
    }
    payload["event_id"] = event_id_for(payload, detail_value)
    return encode_event_v1(payload, detail_value)


def _successful_events(handoff, *, reconciliation: str = "positive"):
    answers = _digest("form-answers")
    source = _digest("application-source")
    artifact = _digest("artifact-set")
    grant = _digest("grant")
    operator = _digest("operator-approval")
    external = _digest("external-receipt")
    rows = [
        _event(
            handoff,
            "strategy_started",
            {
                "application_source_identity": None,
                "schema_version": "jaa.event-detail.strategy_started.v1",
                "strategy_id": _digest("strategy"),
                "transition_sequence": 1,
            },
        ),
        _event(
            handoff,
            "artifacts_ready",
            {
                "answers_sha256": answers,
                "application_source_identity": source,
                "artifact_set_sha256": artifact,
                "cover_letter_pdf_sha256": _digest("cover"),
                "cv_pdf_sha256": _digest("cv"),
                "schema_version": "jaa.event-detail.artifacts_ready.v1",
                "transition_sequence": 2,
            },
        ),
        _event(
            handoff,
            "release_ready",
            {
                "answers_sha256": answers,
                "application_source_identity": source,
                "artifact_set_sha256": artifact,
                "cover_letter_pdf_sha256": _digest("cover"),
                "cv_pdf_sha256": _digest("cv"),
                "employer_assessment_receipt_sha256": _digest("employer-review"),
                "schema_version": "jaa.event-detail.release_ready.v1",
                "transition_sequence": 3,
            },
        ),
        _event(
            handoff,
            "submission_authorized",
            {
                "application_source_identity": source,
                "artifact_set_sha256": artifact,
                "authority_id": "authority-synthetic-1",
                "authority_use_version": 1,
                "employer_assessment_receipt_sha256": _digest("employer-review"),
                "grant_sha256": grant,
                "legal_consent_receipt_sha256": _digest("legal-consent"),
                "operator_approval_receipt_sha256": operator,
                "provider": "greenhouse",
                "route_id": "synthetic-greenhouse",
                "schema_version": "jaa.event-detail.submission_authorized.v1",
                "transition_sequence": 4,
            },
            operator_approval_sha256=operator,
        ),
        _event(
            handoff,
            "submission_attempted",
            {
                "attempt_id": "attempt-synthetic-1",
                "authority_id": "authority-synthetic-1",
                "authority_use_version": 2,
                "click_intent_sha256": _digest("click-intent"),
                "grant_sha256": grant,
                "provider": "greenhouse",
                "route_id": "synthetic-greenhouse",
                "schema_version": "jaa.event-detail.submission_attempted.v1",
                "transition_sequence": 5,
            },
        ),
        _event(
            handoff,
            "receipt_captured",
            {
                "attempt_id": "attempt-synthetic-1",
                "authority_use_version": 3,
                "external_receipt_sha256": external,
                "grant_sha256": grant,
                "reconciliation_state": reconciliation,
                "schema_version": "jaa.event-detail.receipt_captured.v1",
                "transition_sequence": 6,
            },
            external_receipt_sha256=external,
        ),
    ]
    if reconciliation != "negative":
        rows.extend(
            [
                _event(
                    handoff,
                    "status_changed",
                    {
                        "new_state": "offer",
                        "previous_state": "submitted_confirmed",
                        "schema_version": "jaa.event-detail.status_changed.v1",
                        "state_receipt_sha256": _digest("state-receipt"),
                        "transition_sequence": 7,
                    },
                ),
                _event(
                    handoff,
                    "outcome_recorded",
                    {
                        "outcome_code": "offer",
                        "outcome_receipt_sha256": _digest("outcome-receipt"),
                        "schema_version": "jaa.event-detail.outcome_recorded.v1",
                        "transition_sequence": 8,
                    },
                ),
            ]
        )
    return rows


class _Resolver:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def validate(self, *, event_type, detail, expected, occurred_at):
        del detail
        self.calls.append(event_type)
        if event_type in {
            "submission_authorized",
            "submission_attempted",
            "receipt_captured",
            "status_changed",
            "outcome_recorded",
        } and expected.answers_sha256 is None:
            raise ContractValidationError("later event lost answer-corpus binding")
        exact = canonical_json_bytes(
            {
                "application_id": expected.application_id,
                "event_type": event_type,
                "occurred_at": occurred_at,
            }
        )
        return (
            VerifiedEventReference(
                "event.synthetic-test-binding",
                exact,
                {"object_sha256": digest_bytes(exact)},
            ),
        )


def test_full_v1_stream_is_bound_projected_terminal_and_replay_safe() -> None:
    handoff = _handoff()
    resolver = _Resolver()
    projector = EventProjector(handoff, resolver)
    events = _successful_events(handoff)

    for event in events:
        result = projector.consume(event)
        assert result.replayed is False
        assert result.verified_references[0].reference_key == "event.synthetic-test-binding"

    assert projector.state.terminal is True
    assert projector.state.outcome_code == "offer"
    assert projector.state.provider_status == "offer"
    assert projector.state.last_sequence == 8
    replay = projector.consume(events[0])
    assert replay.replayed is True
    assert replay.state == projector.state
    assert resolver.calls == [event.payload["event_type"] for event in events]


def test_v1_codec_round_trips_exact_bytes_and_rejects_detail_substitution() -> None:
    event = _successful_events(_handoff())[0]
    reparsed = parse_event_v1(event.exact_bytes, event.exact_detail_bytes)
    assert reparsed == event
    detail = json.loads(event.exact_detail_bytes)
    detail["strategy_id"] = _digest("substituted-strategy")
    with pytest.raises(ContractValidationError, match="detail digest differs"):
        parse_event_v1(event.exact_bytes, canonical_json_bytes(detail))


def test_projection_rejects_sequence_gap_and_handoff_swap() -> None:
    handoff = _handoff()
    event = _successful_events(handoff)[0]
    gap_detail = dict(event.detail)
    gap_detail["transition_sequence"] = 2
    with pytest.raises(ContractValidationError, match="sequence"):
        EventProjector(handoff, _Resolver()).consume(
            _event(handoff, "strategy_started", gap_detail)
        )

    swapped_payload = dict(event.payload)
    swapped_payload["handoff_root_sha256"] = _digest("other-handoff")
    swapped_payload["event_id"] = event_id_for(swapped_payload, event.detail)
    swapped = encode_event_v1(swapped_payload, event.detail)
    with pytest.raises(ContractValidationError, match="handoff root swap"):
        EventProjector(handoff, _Resolver()).consume(swapped)


def test_projection_rejects_artifact_substitution() -> None:
    handoff = _handoff()
    projector = EventProjector(handoff, _Resolver())
    events = _successful_events(handoff)
    projector.consume(events[0])
    projector.consume(events[1])
    detail = dict(events[2].detail)
    detail["artifact_set_sha256"] = _digest("substituted-artifacts")
    with pytest.raises(ContractValidationError, match="artifact set substitution"):
        projector.consume(_event(handoff, "release_ready", detail))


def test_negative_reconciliation_allows_only_submission_failed_outcome() -> None:
    handoff = _handoff()
    projector = EventProjector(handoff, _Resolver())
    for event in _successful_events(handoff, reconciliation="negative"):
        projector.consume(event)
    wrong = _event(
        handoff,
        "outcome_recorded",
        {
            "outcome_code": "rejected",
            "outcome_receipt_sha256": _digest("wrong-outcome"),
            "schema_version": "jaa.event-detail.outcome_recorded.v1",
            "transition_sequence": 7,
        },
    )
    with pytest.raises(ContractValidationError, match="submission_failed"):
        projector.consume(wrong)

    correct = _event(
        handoff,
        "outcome_recorded",
        {
            "outcome_code": "submission_failed",
            "outcome_receipt_sha256": _digest("failed-outcome"),
            "schema_version": "jaa.event-detail.outcome_recorded.v1",
            "transition_sequence": 7,
        },
    )
    assert projector.consume(correct).state.terminal is True


def test_v0_is_retained_for_inspection_but_release_blocked() -> None:
    handoff = LegacyV0ApplicationHandoff(
        profile_id="prf_" + "0" * 32,
        profile_version="historical-v0",
        job_key="historical:1",
        vacancy_snapshot_sha256=_digest("vacancy"),
        evidence_ledger_sha256=_digest("ledger"),
        eligibility_receipt_sha256=_digest("eligibility"),
        assessment_receipt_sha256=_digest("assessment"),
        employer_dossier_sha256=None,
        fit_status="uncalibrated",
        fit=0.5,
        opportunity=0.5,
        created_at="2026-08-01T00:00:00Z",
    )
    inspection = parse_legacy_v0_handoff_for_inspection(handoff.__dict__)
    assert inspection.admission_kind == "legacy_v0"
    assert inspection.verified_v1 is False
    assert inspection.release_blocked is True
