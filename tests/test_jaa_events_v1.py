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
    occurred_at: str = "2026-08-10T10:10:00Z",
):
    detail_value = deepcopy(dict(detail))
    payload = {
        "application_id": handoff.application_id,
        "event_id": "evt_" + "0" * 64,
        "event_type": event_type,
        "external_receipt_sha256": external_receipt_sha256,
        "handoff_root_sha256": handoff.root_sha256,
        "job_key": handoff.payload["job_key"],
        "occurred_at": occurred_at,
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


class _DurableSyntheticResolver(_Resolver):
    """Storage-test metadata only, never a production trust adapter."""

    def validate(self, *, event_type, detail, expected, occurred_at):
        references = super().validate(event_type=event_type, detail=detail,
                                      expected=expected, occurred_at=occurred_at)
        return tuple(VerifiedEventReference(r.reference_key, r.exact_bytes, {
            **r.metadata, "reference_key": r.reference_key,
            "type_id": "synthetic_test_binding", "schema_version": "synthetic.v1",
            "subject": {"application_id": expected.application_id,
                        "handoff_root_sha256": expected.handoff_root_sha256},
            "issuer_id": "synthetic", "trust_root_id": "synthetic",
            "trust_proof_sha256": _digest("synthetic-proof"),
            "issued_at": occurred_at, "valid_until": None,
        }) for r in references)


def _register_synthetic_handoff(store, handoff):
    basis = {"schema_version": "market-aligner.production-handoff-execution.v2",
             "application_id": handoff.application_id,
             "handoff_root_sha256": handoff.root_sha256,
             "release_token_issued": False, "submission_authority": False}
    receipt = canonical_json_bytes({**basis, "semantic_receipt_sha256":
                                    digest_bytes(canonical_json_bytes(basis))})
    store._record_published_handoff(handoff.exact_bytes, receipt)


def test_durable_receiver_restarts_replays_and_rolls_back(tmp_path):
    from market_aligner.research.store import AssessmentStore
    from market_aligner.service.event_consumer import DurableEventConsumer

    store = AssessmentStore(tmp_path / "assessments.sqlite3")
    handoff = _handoff()
    events = _successful_events(handoff)
    consumer = DurableEventConsumer(store, _DurableSyntheticResolver())
    with pytest.raises(ContractValidationError, match="published handoff"):
        consumer.consume(events[0].exact_bytes, events[0].exact_detail_bytes)
    _register_synthetic_handoff(store, handoff)
    for event in events[:4]:
        consumer.consume(event.exact_bytes, event.exact_detail_bytes)
    reopened = AssessmentStore(store.path)
    consumer = DurableEventConsumer(reopened, _DurableSyntheticResolver())
    for event in events[4:]:
        consumer.consume(event.exact_bytes, event.exact_detail_bytes)
    result = consumer.consume(events[0].exact_bytes, events[0].exact_detail_bytes)
    assert result.replayed and result.state.terminal and result.state.outcome_code == "offer"
    assert consumer.state(handoff.application_id, handoff.root_sha256) == result.state
    assert consumer.state(handoff.application_id) == result.state
    with reopened.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM v1_event_inbox").fetchone()[0] == 8
        assert connection.execute("SELECT COUNT(*) FROM v1_event_references").fetchone()[0] == 8

    other = AssessmentStore(tmp_path / "rollback.sqlite3")
    _register_synthetic_handoff(other, handoff)
    with other.connection() as connection:
        connection.execute("CREATE TRIGGER reject_reference BEFORE INSERT ON v1_event_references "
                           "BEGIN SELECT RAISE(ABORT, 'injected reference failure'); END")
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError, match="injected reference failure"):
        DurableEventConsumer(other, _DurableSyntheticResolver()).consume(
            events[0].exact_bytes, events[0].exact_detail_bytes)
    with other.connection() as connection:
        for table in ("v1_event_inbox", "v1_event_projection", "v1_reference_objects",
                      "v1_reference_resolutions", "v1_event_references"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_durable_receiver_keeps_application_roots_separate(tmp_path):
    from market_aligner.applications.handoff import encode_handoff_v1
    from market_aligner.research.store import AssessmentStore
    from market_aligner.service.event_consumer import DurableEventConsumer

    first = _handoff()
    payload = deepcopy(dict(first.payload))
    from datetime import datetime, timedelta
    payload["created_at"] = (datetime.fromisoformat(payload["created_at"].replace("Z", "+00:00"))
                             + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    second = encode_handoff_v1(payload)
    assert first.application_id == second.application_id
    assert first.root_sha256 != second.root_sha256
    store = AssessmentStore(tmp_path / "assessments.sqlite3")
    for handoff in (first, second):
        _register_synthetic_handoff(store, handoff)
    consumer = DurableEventConsumer(store, _DurableSyntheticResolver())
    for handoff, count in ((first, 2), (second, 1)):
        for event in _successful_events(handoff)[:count]:
            consumer.consume(event.exact_bytes, event.exact_detail_bytes)
    assert consumer.state(first.application_id, first.root_sha256).last_sequence == 2
    assert consumer.state(second.application_id, second.root_sha256).last_sequence == 1
    with pytest.raises(ContractValidationError, match="explicit handoff root"):
        consumer.state(first.application_id)
    with store.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM v1_event_inbox").fetchone()[0] == 3


class _SyntheticJAAReceiptAdapter:
    """Test-only evidence provider and authenticator, explicitly non-production."""

    event_resolver_identity_sha256 = _digest("bridge-test-resolver")

    def __init__(self, *, fail_auth=False, swap_package=False, omit_package=False):
        self.fail_auth = fail_auth
        self.swap_package = swap_package
        self.omit_package = omit_package
        self.authenticated = []

    def _evidence(self, kind, subject, occurred_at, exact):
        from career_automation.event_receipts import EventReceiptEvidence, build_event_receipt_metadata
        return EventReceiptEvidence(exact, build_event_receipt_metadata(
            exact_bytes=exact, kind=kind, subject=subject, issued_at=occurred_at,
            issuer_id="synthetic", trust_root_id="synthetic",
            trust_proof_sha256=_digest("bridge-test-proof")),
            "synthetic", self.event_resolver_identity_sha256)

    def validate(self, *, event_type, detail, expected, occurred_at):
        if event_type in {"strategy_started", "release_blocked"} or self.omit_package:
            return None
        answers = (detail["answers_sha256"] if event_type in {"artifacts_ready", "release_ready"}
                   else expected.answers_sha256)
        subject = {"application_id": expected.application_id, "event_type": event_type,
                   "form_answers_sha256": _digest("swapped") if self.swap_package else answers,
                   "handoff_root_sha256": expected.handoff_root_sha256}
        return self._evidence("package", subject, occurred_at,
                              canonical_json_bytes({"synthetic-package": subject}))

    def resolve(self, *, reference_key, object_sha256, expected_subject, evaluated_at):
        kind = "state" if reference_key == "event.state_receipt" else "outcome"
        return self._evidence(kind, expected_subject, evaluated_at, f"{kind}-receipt".encode())

    def authenticate_event_receipt(self, **values):
        if self.fail_auth:
            raise ValueError("synthetic untrusted proof")
        self.authenticated.append(values)


def test_jaa_binding_bridge_authenticates_package_and_reverse_receipts(tmp_path):
    from career_automation.event_receipts import JAAEventReceiptBindingResolver, EventReceiptError
    from market_aligner.research.store import AssessmentStore
    from market_aligner.service.event_consumer import DurableEventConsumer

    handoff = _handoff()
    events = _successful_events(handoff)
    adapter = _SyntheticJAAReceiptAdapter()
    store = AssessmentStore(tmp_path / "assessments.sqlite3")
    _register_synthetic_handoff(store, handoff)
    consumer = DurableEventConsumer(store, JAAEventReceiptBindingResolver(
        adapter, additional_validator=adapter))
    for event in events:
        consumer.consume(event.exact_bytes, event.exact_detail_bytes)
    assert consumer.state(handoff.application_id).outcome_code == "offer"
    assert len(adapter.authenticated) == 9
    with store.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM v1_event_references").fetchone()[0] == 9
    for options, code in [({"omit_package": True}, "receipt_package"),
                          ({"swap_package": True}, "receipt_substitution"),
                          ({"fail_auth": True}, "receipt_authentication")]:
        isolated = AssessmentStore(tmp_path / (code + ".sqlite3"))
        _register_synthetic_handoff(isolated, handoff)
        failed = _SyntheticJAAReceiptAdapter(**options)
        receiver = DurableEventConsumer(isolated, JAAEventReceiptBindingResolver(
            failed, additional_validator=failed))
        receiver.consume(events[0].exact_bytes, events[0].exact_detail_bytes)
        with pytest.raises(EventReceiptError, match=code):
            receiver.consume(events[1].exact_bytes, events[1].exact_detail_bytes)
        assert receiver.state(handoff.application_id).last_sequence == 1
        with isolated.connection() as connection:
            assert connection.execute("SELECT COUNT(*) FROM v1_event_inbox").fetchone()[0] == 1


@pytest.mark.parametrize("mode", ["wrong_digest", "wrong_subject", "future"])
def test_jaa_binding_bridge_rejects_reverse_receipt_substitution(tmp_path, mode):
    from dataclasses import replace
    from datetime import datetime, timedelta
    from career_automation.event_receipts import JAAEventReceiptBindingResolver, EventReceiptError
    from market_aligner.research.store import AssessmentStore
    from market_aligner.service.event_consumer import DurableEventConsumer

    class Adapter(_SyntheticJAAReceiptAdapter):
        def resolve(self, **kwargs):
            evidence = super().resolve(**kwargs)
            if mode == "wrong_digest":
                return replace(evidence, exact_bytes=b"substituted")
            metadata = json.loads(evidence.metadata_bytes)
            if mode == "wrong_subject":
                metadata["subject"]["grant_sha256"] = _digest("wrong-grant")
            else:
                metadata["issued_at"] = (
                    datetime.fromisoformat(metadata["issued_at"].replace("Z", "+00:00"))
                    + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
            return replace(evidence, metadata_bytes=canonical_json_bytes(metadata))

    handoff = _handoff()
    events = _successful_events(handoff)
    store = AssessmentStore(tmp_path / "assessments.sqlite3")
    _register_synthetic_handoff(store, handoff)
    adapter = Adapter()
    consumer = DurableEventConsumer(store, JAAEventReceiptBindingResolver(
        adapter, additional_validator=adapter))
    for event in events[:6]:
        consumer.consume(event.exact_bytes, event.exact_detail_bytes)
    with pytest.raises(EventReceiptError):
        consumer.consume(events[6].exact_bytes, events[6].exact_detail_bytes)
    assert consumer.state(handoff.application_id).last_sequence == 6
    with store.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM v1_event_inbox").fetchone()[0] == 6
        assert connection.execute("SELECT COUNT(*) FROM v1_event_references").fetchone()[0] == 5


def _golden_corpus():
    from scripts.generate_jaa_event_golden import build_corpus, DEFAULT_OUTPUT
    exact = build_corpus()
    assert DEFAULT_OUTPUT.read_bytes() == exact
    return json.loads(exact)


def _golden_events(rows):
    for row in rows:
        exact = base64.b64decode(row["envelope_base64"], validate=True)
        detail = base64.b64decode(row["detail_base64"], validate=True)
        assert digest_bytes(exact) == row["envelope_root_sha256"]
        assert digest_bytes(detail) == row["detail_sha256"]
        event = parse_event_v1(exact, detail)
        assert event.event_id == row["event_id"]
        assert event.transition_sequence == row["transition_sequence"]
        yield event


def test_golden_streams_replay_restart_and_preserve_every_donor_negative(subtests):
    document = _golden_corpus()
    events = list(_golden_events(document["events"]))
    assert len(events) == 9
    projector = EventProjector(_handoff(), _Resolver())
    for event in events:
        projector.consume(event)
    assert projector.state.terminal and projector.state.outcome_code == "rejected"
    assert [event.detail["new_state"] for event in events if event.payload["event_type"] == "status_changed"] == ["under_review", "rejected"]
    blocked = EventProjector(_handoff(), _Resolver())
    for event in _golden_events(document["release_blocked_branch"]):
        blocked.consume(event)
    assert blocked.state.last_sequence == 6
    assert blocked.state.last_event_type == "release_blocked"
    assert not blocked.state.terminal
    assert digest_bytes(base64.b64decode(document["form_answers"]["canonical_base64"], validate=True)) == events[1].detail["answers_sha256"]
    vectors = document["negative_vectors"]
    assert len(vectors) == 26 and len({v["id"] for v in vectors}) == 26
    for vector in vectors:
        if vector["kind"] == "reverse_receipt_registry":
            continue
        with subtests.test(vector=vector["id"]):
            state = EventProjector(_handoff(), _Resolver())
            for prior in events[:vector.get("prior_sequence", 0)]:
                state.consume(prior)
            with pytest.raises(ContractValidationError):
                if vector["kind"] == "event_identity":
                    payload = dict(events[0].payload)
                    payload.update(vector["value"])
                    payload["event_id"] = event_id_for(payload, events[0].detail)
                    state.consume(encode_event_v1(payload, events[0].detail))
                else:
                    detail = vector["value"]
                    event_type = detail["schema_version"].removeprefix("jaa.event-detail.").removesuffix(".v1")
                    event = _event(_handoff(), event_type, detail,
                        occurred_at=vector.get("occurred_at", "2026-08-10T12:00:00Z"),
                        operator_approval_sha256=detail.get("operator_approval_receipt_sha256"),
                        external_receipt_sha256=detail.get("external_receipt_sha256"))
                    if "event_id" in vector:
                        assert event.event_id == vector["event_id"]
                    state.consume(event)


def test_golden_reverse_receipts_authenticate_and_every_registry_mutation_refuses(subtests):
    from career_automation.event_receipts import (
        EventReceiptError, EventReceiptEvidence, EventReceiptReference,
        EventReceiptRegistryEntry, validate_event_receipt_registry,
    )
    document = _golden_corpus()
    events = list(_golden_events(document["events"]))
    chain = {"application_id": events[0].payload["application_id"],
             "handoff_root_sha256": events[0].payload["handoff_root_sha256"],
             "grant_sha256": events[3].detail["grant_sha256"],
             "attempt_id": events[4].detail["attempt_id"],
             "external_receipt_sha256": events[5].detail["external_receipt_sha256"]}
    references = []
    for event in events[6:]:
        state = event.payload["event_type"] == "status_changed"
        subject = {**chain, **({"previous_state": event.detail["previous_state"], "new_state": event.detail["new_state"]}
                              if state else {"outcome_code": event.detail["outcome_code"]})}
        references.append(EventReceiptReference(event.event_id, str(event.payload["event_type"]),
            event.transition_sequence, str(event.payload["occurred_at"]), "state" if state else "outcome",
            str(event.detail["state_receipt_sha256" if state else "outcome_receipt_sha256"]), subject))
    approved = {(row["exact_base64"], row["metadata_base64"]) for row in document["reverse_receipts"]}
    class SyntheticAuthenticator:
        event_resolver_identity_sha256 = document["reverse_receipts"][0]["resolver_identity_sha256"]
        def authenticate_event_receipt(self, **values):
            assert values["environment"] == "synthetic"
            assert (base64.b64encode(values["exact_bytes"]).decode(), base64.b64encode(values["metadata_bytes"]).decode()) in approved
    def registry(rows):
        return [EventReceiptRegistryEntry(row["event_id"], row["event_type"], row["transition_sequence"],
            row["occurred_at"], row["kind"], row["object_sha256"], row["metadata_sha256"], row["subject"],
            EventReceiptEvidence(base64.b64decode(row["exact_base64"], validate=True),
                base64.b64decode(row["metadata_base64"], validate=True), "synthetic", row["resolver_identity_sha256"]))
            for row in rows]
    assert len(validate_event_receipt_registry(references, registry(document["reverse_receipts"]), authenticator=SyntheticAuthenticator())) == 3
    for vector in document["negative_vectors"]:
        if vector["kind"] != "reverse_receipt_registry":
            continue
        with subtests.test(vector=vector["id"]):
            with pytest.raises(EventReceiptError) as rejected:
                validate_event_receipt_registry(references, registry(vector["value"]), authenticator=SyntheticAuthenticator())
            assert rejected.value.code == vector["expected_error"]


def test_golden_cli_is_deterministic_and_check_is_read_only(tmp_path):
    import os
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[1]
    script = root / "internal/jaa/scripts/generate_jaa_event_golden.py"
    env = {**os.environ, "PYTHONPATH": os.pathsep.join((str(root / "src"), str(root / "internal/jaa")))}
    output = tmp_path / "golden.json"
    command = [sys.executable, str(script), "--output", str(output)]
    first = subprocess.run(command, env=env, capture_output=True, text=True, check=True, timeout=20)
    exact = output.read_bytes()
    second = subprocess.run(command, env=env, capture_output=True, text=True, check=True, timeout=20)
    assert output.read_bytes() == exact and first.stdout == second.stdout
    assert first.stdout.strip() == digest_bytes(exact)
    subprocess.run(command + ["--check"], env=env, capture_output=True, check=True, timeout=20)
    output.write_bytes(exact + b"\n")
    stale = subprocess.run(command + ["--check"], env=env, capture_output=True, text=True, timeout=20)
    assert stale.returncode != 0 and "stale" in stale.stderr
    assert output.read_bytes() == exact + b"\n"
