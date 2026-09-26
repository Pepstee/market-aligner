"""Adversarial coverage for the internal-JAA reverse event-receipt registry."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from career_automation.event_receipts import (
    EventReceiptError,
    EventReceiptEvidence,
    EventReceiptReference,
    EventReceiptRegistryEntry,
    build_event_receipt_metadata,
    validate_event_receipt,
    validate_event_receipt_registry,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


class _Authenticator:
    event_resolver_identity_sha256 = _digest("resolver")

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[dict[str, object]] = []

    def authenticate_event_receipt(self, **values: object) -> None:
        self.calls.append(dict(values))
        if self.fail:
            raise RuntimeError("synthetic trust failure")


def _pair(
    kind: str,
    sequence: int,
    *,
    event_label: str | None = None,
    object_label: str | None = None,
    issued_at: str = "2026-08-01T00:00:00Z",
    occurred_at: str = "2026-08-01T00:00:01Z",
):
    event_type = {"state": "status_changed", "outcome": "outcome_recorded"}[kind]
    event_id = "evt_" + _digest(event_label or f"{kind}-{sequence}")
    exact_bytes = (object_label or f"{kind}-receipt-{sequence}").encode()
    subject = {
        "application_id": "app_" + _digest("application"),
        "event_type": event_type,
        "transition_sequence": sequence,
    }
    metadata_bytes = build_event_receipt_metadata(
        exact_bytes=exact_bytes,
        issued_at=issued_at,
        issuer_id="synthetic-issuer",
        kind=kind,
        subject=subject,
        trust_proof_sha256=_digest("trust-proof"),
        trust_root_id="synthetic-root",
    )
    evidence = EventReceiptEvidence(
        exact_bytes=exact_bytes,
        metadata_bytes=metadata_bytes,
        environment="synthetic",
        resolver_identity_sha256=_digest("resolver"),
    )
    reference = EventReceiptReference(
        event_id=event_id,
        event_type=event_type,
        transition_sequence=sequence,
        occurred_at=occurred_at,
        kind=kind,
        object_sha256=evidence.object_sha256,
        expected_subject=subject,
    )
    entry = EventReceiptRegistryEntry(
        event_id=event_id,
        event_type=event_type,
        transition_sequence=sequence,
        occurred_at=occurred_at,
        kind=kind,
        object_sha256=evidence.object_sha256,
        metadata_sha256=evidence.metadata_sha256,
        declared_subject=subject,
        evidence=evidence,
    )
    return reference, entry


def test_complete_registry_authenticates_each_exact_event_receipt() -> None:
    state = _pair("state", 7)
    outcome = _pair("outcome", 8)
    authenticator = _Authenticator()

    validated = validate_event_receipt_registry(
        [state[0], outcome[0]],
        [outcome[1], state[1]],
        authenticator=authenticator,
    )

    assert [receipt.reference_key for receipt in validated] == [
        "event.state_receipt",
        "event.outcome_receipt",
    ]
    assert len(authenticator.calls) == 2


def test_registry_rejects_missing_or_unreferenced_receipts() -> None:
    reference, entry = _pair("state", 7)
    with pytest.raises(EventReceiptError, match="receipt_missing"):
        validate_event_receipt_registry([reference], [], authenticator=_Authenticator())
    with pytest.raises(EventReceiptError, match="receipt_event"):
        validate_event_receipt_registry([], [entry], authenticator=_Authenticator())


def test_registry_rejects_duplicate_event_and_object_identities() -> None:
    first_reference, first_entry = _pair("state", 7)
    duplicate_reference, duplicate_entry = _pair(
        "state", 8, event_label="state-7", object_label="state-receipt-7"
    )
    with pytest.raises(EventReceiptError, match="receipt_duplicate"):
        validate_event_receipt_registry(
            [first_reference, duplicate_reference],
            [first_entry],
            authenticator=_Authenticator(),
        )
    with pytest.raises(EventReceiptError, match="receipt_duplicate"):
        validate_event_receipt_registry(
            [first_reference],
            [first_entry, duplicate_entry],
            authenticator=_Authenticator(),
        )


def test_registry_rejects_event_sequence_time_subject_and_digest_substitution() -> None:
    reference, entry = _pair("state", 7)
    substitutions = (
        replace(entry, transition_sequence=8),
        replace(entry, occurred_at="2026-08-01T00:00:02Z"),
        replace(entry, declared_subject={"substituted": True}),
        replace(entry, metadata_sha256=_digest("substituted-metadata")),
    )
    for substituted in substitutions:
        with pytest.raises(EventReceiptError):
            validate_event_receipt_registry(
                [reference], [substituted], authenticator=_Authenticator()
            )


def test_receipt_validation_rejects_future_noncanonical_and_wrong_resolver() -> None:
    reference, entry = _pair(
        "state",
        7,
        issued_at="2026-08-01T00:00:02Z",
        occurred_at="2026-08-01T00:00:01Z",
    )
    with pytest.raises(EventReceiptError, match="receipt_future"):
        validate_event_receipt(
            entry.evidence,
            kind=reference.kind,
            expected_subject=reference.expected_subject,
            occurred_at=reference.occurred_at,
            authenticator=_Authenticator(),
        )

    noncanonical = replace(
        entry.evidence,
        metadata_bytes=entry.evidence.metadata_bytes + b"\n",
    )
    with pytest.raises(EventReceiptError, match="receipt_metadata"):
        validate_event_receipt(
            noncanonical,
            kind=reference.kind,
            expected_subject=reference.expected_subject,
            occurred_at="2026-08-01T00:00:03Z",
            authenticator=_Authenticator(),
        )

    wrong_resolver = replace(entry.evidence, resolver_identity_sha256=_digest("other"))
    with pytest.raises(EventReceiptError, match="receipt_resolver"):
        validate_event_receipt(
            wrong_resolver,
            kind=reference.kind,
            expected_subject=reference.expected_subject,
            occurred_at="2026-08-01T00:00:03Z",
            authenticator=_Authenticator(),
        )


def test_authenticator_failure_is_fail_closed_and_event_kind_is_exact() -> None:
    reference, entry = _pair("outcome", 8)
    with pytest.raises(EventReceiptError, match="receipt_authentication"):
        validate_event_receipt(
            entry.evidence,
            kind=reference.kind,
            expected_subject=reference.expected_subject,
            occurred_at=reference.occurred_at,
            authenticator=_Authenticator(fail=True),
        )
    with pytest.raises(EventReceiptError, match="kind and event type differ"):
        replace(reference, event_type="status_changed")
    with pytest.raises(EventReceiptError, match="transition sequence is invalid"):
        replace(reference, transition_sequence=2**53)
