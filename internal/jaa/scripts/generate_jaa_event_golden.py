#!/usr/bin/env python3
"""Generate the deterministic JAA event/reverse-receipt golden corpus."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from career_automation.event_receipts import build_event_receipt_metadata
from market_aligner.applications.canonical import canonical_json_bytes, digest_bytes
from market_aligner.applications.events import (
    EventBindingContext,
    EventProjector,
    VerifiedEventReference,
    encode_event_v1,
    event_id_for,
)
from market_aligner.applications.handoff import HandoffEnvelope, parse_handoff_v1


ROOT = Path(__file__).resolve().parents[1]
MARKET_PATH = ROOT / "career_automation/fixtures/market-aligner-v1-vectors.json"
DEFAULT_OUTPUT = ROOT / "career_automation/fixtures/jaa-event-golden-corpus-v1.json"
MARKET_SOURCE_COMMIT = "411621b9f522c8d7809573388fb39ca2bf7278b6"
MARKET_FIXTURE_SHA256 = (
    "421d39504c4828c928389d5c30c2147fb7c01249b299972a11e204e956350160"
)
RESOLVER_IDENTITY_SHA256 = hashlib.sha256(
    b"jaa.event-golden-reverse-resolver.v1"
).hexdigest()


class _GoldenBindingResolver:
    """Clearly synthetic resolver exercising EventProjector's binding protocol."""

    def validate(
        self,
        *,
        event_type: str,
        detail: dict[str, object],
        expected: EventBindingContext,
        occurred_at: str,
    ) -> tuple[VerifiedEventReference, ...]:
        exact = canonical_json_bytes(
            {
                "application_id": expected.application_id,
                "event_type": event_type,
                "occurred_at": occurred_at,
                "transition_sequence": detail["transition_sequence"],
            }
        )
        return (
            VerifiedEventReference(
                "event.jaa-golden-synthetic-binding.v1",
                exact,
                {"object_sha256": digest_bytes(exact)},
            ),
        )


def _encode_event(
    identity: HandoffEnvelope,
    event_type: str,
    detail: dict[str, object],
    *,
    occurred_at: str,
):
    operator = (
        detail.get("operator_approval_receipt_sha256")
        if event_type == "submission_authorized"
        else None
    )
    external = (
        detail.get("external_receipt_sha256")
        if event_type == "receipt_captured"
        else None
    )
    payload = {
        "application_id": identity.application_id,
        "event_id": "evt_" + "0" * 64,
        "event_type": event_type,
        "external_receipt_sha256": external,
        "handoff_root_sha256": identity.root_sha256,
        "job_key": identity.payload["job_key"],
        "occurred_at": occurred_at,
        "operator_approval_sha256": operator,
        "payload_sha256": digest_bytes(canonical_json_bytes(detail)),
        "profile_id": identity.payload["profile_id"],
    }
    payload["event_id"] = event_id_for(payload, detail)
    return encode_event_v1(payload, detail)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _digest(label: str) -> str:
    return _sha(("jaa-event-golden:" + label).encode("utf-8"))


def _receipt(
    *,
    kind: str,
    subject: dict[str, object],
    issued_at: str,
) -> tuple[bytes, bytes]:
    exact = canonical_json_bytes(
        {
            **subject,
            "observed_at": issued_at,
            "provider": "greenhouse",
            "schema_version": f"jaa.golden-{kind}-observation.v1",
        }
    )
    proof = _sha(
        b"jaa.event-golden-reverse-proof.v1\0"
        + exact
        + canonical_json_bytes(subject)
    )
    metadata = build_event_receipt_metadata(
        exact_bytes=exact,
        issued_at=issued_at,
        issuer_id="jaa.synthetic-greenhouse-golden.v1",
        kind=kind,
        subject=subject,
        trust_proof_sha256=proof,
        trust_root_id="jaa-event-golden-root-v1",
    )
    return exact, metadata


def build_corpus() -> bytes:
    market_bytes = MARKET_PATH.read_bytes()
    if _sha(market_bytes) != MARKET_FIXTURE_SHA256:
        raise RuntimeError("Market fixture differs from the frozen producer vector")
    market = json.loads(market_bytes)
    handoff = market["handoff"]
    handoff_bytes = base64.b64decode(handoff["canonical_base64"], validate=True)
    if _sha(handoff_bytes) != handoff["root_sha256"]:
        raise RuntimeError("Market handoff root differs from its exact bytes")
    handoff_envelope = parse_handoff_v1(handoff_bytes)

    identity = handoff_envelope

    form_answers_bytes = canonical_json_bytes(
        {
            "answers": [
                {
                    "answer": "Synthetic Candidate",
                    "question": "Candidate name",
                    "question_id": "candidate_name",
                }
            ],
            "schema_version": "jaa.form-answers.v1",
        }
    )
    answers_sha256 = _sha(form_answers_bytes)
    old_source = _digest("application-source-old")
    source = _digest("application-source-fresh")
    old_artifacts = _digest("artifact-set-old")
    artifacts = _digest("artifact-set-fresh")
    cv_sha256 = _digest("cv-pdf-fresh")
    cover_sha256 = _digest("cover-letter-pdf-fresh")
    assessment_sha256 = _digest("employer-assessment-fresh")
    grant_sha256 = _digest("exact-package-grant")
    legal_sha256 = _digest("legal-consent-receipt")
    approval_sha256 = _digest("operator-approval-receipt")
    click_sha256 = _digest("click-intent")
    external_sha256 = _digest("external-submission-receipt")
    authority_id = "auth_golden_exact_package_v1"
    attempt_id = "attempt_golden_exact_post_v1"
    route_id = "greenhouse.synthetic.v1"

    under_review_state_subject = {
        "application_id": identity.application_id,
        "attempt_id": attempt_id,
        "external_receipt_sha256": external_sha256,
        "grant_sha256": grant_sha256,
        "handoff_root_sha256": identity.root_sha256,
        "new_state": "under_review",
        "previous_state": "submitted_confirmed",
    }
    under_review_state_exact, under_review_state_metadata = _receipt(
        kind="state",
        subject=under_review_state_subject,
        issued_at="2026-08-10T10:12:00Z",
    )
    rejected_state_subject = {
        "application_id": identity.application_id,
        "attempt_id": attempt_id,
        "external_receipt_sha256": external_sha256,
        "grant_sha256": grant_sha256,
        "handoff_root_sha256": identity.root_sha256,
        "new_state": "rejected",
        "previous_state": "under_review",
    }
    rejected_state_exact, rejected_state_metadata = _receipt(
        kind="state",
        subject=rejected_state_subject,
        issued_at="2026-08-10T10:15:00Z",
    )
    outcome_subject = {
        "application_id": identity.application_id,
        "attempt_id": attempt_id,
        "external_receipt_sha256": external_sha256,
        "grant_sha256": grant_sha256,
        "handoff_root_sha256": identity.root_sha256,
        "outcome_code": "rejected",
    }
    outcome_exact, outcome_metadata = _receipt(
        kind="outcome",
        subject=outcome_subject,
        issued_at="2026-08-10T10:16:00Z",
    )

    rows: list[tuple[str, dict[str, object], str]] = [
        (
            "strategy_started",
            {"application_source_identity": None, "strategy_id": _digest("strategy-fresh")},
            "2026-08-10T10:06:00Z",
        ),
        (
            "artifacts_ready",
            {
                "answers_sha256": answers_sha256,
                "application_source_identity": source,
                "artifact_set_sha256": artifacts,
                "cover_letter_pdf_sha256": cover_sha256,
                "cv_pdf_sha256": cv_sha256,
            },
            "2026-08-10T10:07:00Z",
        ),
        (
            "release_ready",
            {
                "answers_sha256": answers_sha256,
                "application_source_identity": source,
                "artifact_set_sha256": artifacts,
                "cover_letter_pdf_sha256": cover_sha256,
                "cv_pdf_sha256": cv_sha256,
                "employer_assessment_receipt_sha256": assessment_sha256,
            },
            "2026-08-10T10:08:00Z",
        ),
        (
            "submission_authorized",
            {
                "application_source_identity": source,
                "artifact_set_sha256": artifacts,
                "authority_id": authority_id,
                "authority_use_version": 1,
                "employer_assessment_receipt_sha256": assessment_sha256,
                "grant_sha256": grant_sha256,
                "legal_consent_receipt_sha256": legal_sha256,
                "operator_approval_receipt_sha256": approval_sha256,
                "provider": "greenhouse",
                "route_id": route_id,
            },
            "2026-08-10T10:09:00Z",
        ),
        (
            "submission_attempted",
            {
                "attempt_id": attempt_id,
                "authority_id": authority_id,
                "authority_use_version": 2,
                "click_intent_sha256": click_sha256,
                "grant_sha256": grant_sha256,
                "provider": "greenhouse",
                "route_id": route_id,
            },
            "2026-08-10T10:10:00Z",
        ),
        (
            "receipt_captured",
            {
                "attempt_id": attempt_id,
                "authority_use_version": 3,
                "external_receipt_sha256": external_sha256,
                "grant_sha256": grant_sha256,
                "reconciliation_state": "positive",
            },
            "2026-08-10T10:11:00Z",
        ),
        (
            "status_changed",
            {
                "new_state": "under_review",
                "previous_state": "submitted_confirmed",
                "state_receipt_sha256": _sha(under_review_state_exact),
            },
            "2026-08-10T10:12:00Z",
        ),
        (
            "status_changed",
            {
                "new_state": "rejected",
                "previous_state": "under_review",
                "state_receipt_sha256": _sha(rejected_state_exact),
            },
            "2026-08-10T10:15:00Z",
        ),
        (
            "outcome_recorded",
            {
                "outcome_code": "rejected",
                "outcome_receipt_sha256": _sha(outcome_exact),
            },
            "2026-08-10T10:16:00Z",
        ),
    ]
    blocked_rows: list[tuple[str, dict[str, object], str]] = [
        (
            "strategy_started",
            {"application_source_identity": None, "strategy_id": _digest("strategy-old")},
            "2026-08-10T10:06:00Z",
        ),
        (
            "artifacts_ready",
            {
                "answers_sha256": answers_sha256,
                "application_source_identity": old_source,
                "artifact_set_sha256": old_artifacts,
                "cover_letter_pdf_sha256": _digest("cover-letter-pdf-old"),
                "cv_pdf_sha256": _digest("cv-pdf-old"),
            },
            "2026-08-10T10:07:00Z",
        ),
        (
            "release_blocked",
            {
                "application_source_identity": old_source,
                "block_codes": ["exact_package_rebuild_required"],
            },
            "2026-08-10T10:08:00Z",
        ),
        (
            "strategy_started",
            {
                "application_source_identity": None,
                "strategy_id": _digest("strategy-restart"),
            },
            "2026-08-10T10:09:00Z",
        ),
        (
            "artifacts_ready",
            {
                "answers_sha256": answers_sha256,
                "application_source_identity": source,
                "artifact_set_sha256": artifacts,
                "cover_letter_pdf_sha256": cover_sha256,
                "cv_pdf_sha256": cv_sha256,
            },
            "2026-08-10T10:10:00Z",
        ),
        (
            "release_blocked",
            {
                "application_source_identity": source,
                "block_codes": ["operator_reapproval_required"],
            },
            "2026-08-10T10:11:00Z",
        ),
    ]

    def encode_rows(
        candidate_rows: list[tuple[str, dict[str, object], str]],
    ) -> tuple[EventProjector, list[dict[str, object]], list[dict[str, object]]]:
        projector = EventProjector(handoff_envelope, _GoldenBindingResolver())
        encoded: list[dict[str, object]] = []
        details: list[dict[str, object]] = []
        for sequence, (event_type, fields, occurred_at) in enumerate(
            candidate_rows, start=1
        ):
            detail = {
                **fields,
                "schema_version": f"jaa.event-detail.{event_type}.v1",
                "transition_sequence": sequence,
            }
            event = _encode_event(identity, event_type, detail, occurred_at=occurred_at)
            projector.consume(event)
            details.append(detail)
            encoded.append(
                {
                    "detail_base64": _b64(event.exact_detail_bytes),
                    "detail_sha256": digest_bytes(event.exact_detail_bytes),
                    "envelope_base64": _b64(event.exact_bytes),
                    "envelope_root_sha256": event.root_sha256,
                    "event_id": event.event_id,
                    "event_type": event_type,
                    "occurred_at": occurred_at,
                    "transition_sequence": event.transition_sequence,
                }
            )
        return projector, encoded, details

    stream, events, built_details = encode_rows(rows)
    blocked_stream, blocked_events, _blocked_details = encode_rows(blocked_rows)
    if (
        not stream.state.terminal
        or blocked_stream.state.last_event_type != "release_blocked"
    ):
        raise RuntimeError("golden event streams did not reach their expected states")

    def reverse_receipt_row(
        *,
        event_index: int,
        kind: str,
        exact: bytes,
        metadata: bytes,
        subject: dict[str, object],
    ) -> dict[str, object]:
        event = events[event_index]
        detail = built_details[event_index]
        detail_key = (
            "state_receipt_sha256" if kind == "state" else "outcome_receipt_sha256"
        )
        if detail.get(detail_key) != _sha(exact):
            raise RuntimeError("reverse receipt differs from its event detail reference")
        return {
            "environment": "synthetic",
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "exact_base64": _b64(exact),
            "kind": kind,
            "metadata_base64": _b64(metadata),
            "metadata_sha256": _sha(metadata),
            "object_sha256": _sha(exact),
            "occurred_at": event["occurred_at"],
            "resolver_identity_sha256": RESOLVER_IDENTITY_SHA256,
            "subject": subject,
            "transition_sequence": event["transition_sequence"],
        }

    reverse_receipts = [
        reverse_receipt_row(
            event_index=6,
            kind="state",
            exact=under_review_state_exact,
            metadata=under_review_state_metadata,
            subject=under_review_state_subject,
        ),
        reverse_receipt_row(
            event_index=7,
            kind="state",
            exact=rejected_state_exact,
            metadata=rejected_state_metadata,
            subject=rejected_state_subject,
        ),
        reverse_receipt_row(
            event_index=8,
            kind="outcome",
            exact=outcome_exact,
            metadata=outcome_metadata,
            subject=outcome_subject,
        ),
    ]

    def registry_copy() -> list[dict[str, object]]:
        return copy.deepcopy(reverse_receipts)

    def mutate_registry_metadata(
        rows_to_mutate: list[dict[str, object]],
        index: int,
        *,
        metadata_updates: dict[str, object] | None = None,
        subject_updates: dict[str, object] | None = None,
        replacement_subject: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        row = rows_to_mutate[index]
        metadata = json.loads(base64.b64decode(row["metadata_base64"], validate=True))
        if metadata_updates:
            metadata.update(metadata_updates)
        subject = dict(metadata["subject"])
        if replacement_subject is not None:
            subject = dict(replacement_subject)
        if subject_updates:
            subject.update(subject_updates)
        metadata["subject"] = subject
        metadata_bytes = canonical_json_bytes(metadata)
        row["metadata_base64"] = _b64(metadata_bytes)
        row["metadata_sha256"] = _sha(metadata_bytes)
        row["subject"] = subject
        return rows_to_mutate

    def event_negative(
        *,
        vector_id: str,
        expected_error: str,
        prior_sequence: int,
        event_type: str,
        detail: dict[str, object],
        occurred_at: str,
    ) -> dict[str, object]:
        rebuilt = _encode_event(identity, event_type, detail, occurred_at=occurred_at)
        return {
            "event_id": rebuilt.event_id,
            "event_type": event_type,
            "expected_error": expected_error,
            "id": vector_id,
            "kind": "event_record",
            "occurred_at": occurred_at,
            "prior_sequence": prior_sequence,
            "value": detail,
        }

    missing_registry = registry_copy()
    del missing_registry[0]
    duplicate_registry = registry_copy()
    duplicate_registry.append(copy.deepcopy(duplicate_registry[0]))
    wrong_event_registry = registry_copy()
    wrong_event_registry[0]["event_id"] = events[0]["event_id"]
    wrong_sequence_registry = registry_copy()
    wrong_sequence_registry[0]["transition_sequence"] = 8
    wrong_occurred_at_registry = registry_copy()
    wrong_occurred_at_registry[0]["occurred_at"] = "2026-08-10T10:13:00Z"
    previous_state_registry = mutate_registry_metadata(
        registry_copy(),
        0,
        subject_updates={"previous_state": "under_review"},
    )
    new_state_registry = mutate_registry_metadata(
        registry_copy(),
        0,
        subject_updates={"new_state": "rejected"},
    )
    attempt_registry = mutate_registry_metadata(
        registry_copy(),
        0,
        subject_updates={"attempt_id": "attempt_golden_swapped_v1"},
    )
    grant_registry = mutate_registry_metadata(
        registry_copy(),
        0,
        subject_updates={"grant_sha256": "f" * 64},
    )
    external_receipt_registry = mutate_registry_metadata(
        registry_copy(),
        0,
        subject_updates={"external_receipt_sha256": "e" * 64},
    )
    subject_swap_registry = registry_copy()
    first_state_subject = dict(subject_swap_registry[0]["subject"])
    second_state_subject = dict(subject_swap_registry[1]["subject"])
    mutate_registry_metadata(
        subject_swap_registry,
        0,
        replacement_subject=second_state_subject,
    )
    mutate_registry_metadata(
        subject_swap_registry,
        1,
        replacement_subject=first_state_subject,
    )
    application_registry = mutate_registry_metadata(
        registry_copy(),
        0,
        subject_updates={"application_id": "app_" + "f" * 64},
    )
    type_registry = mutate_registry_metadata(
        registry_copy(),
        0,
        metadata_updates={"type_id": "application_outcome_receipt"},
    )
    exact_registry = registry_copy()
    exact_registry[0]["exact_base64"] = _b64(under_review_state_exact + b"\n")
    outcome_registry = mutate_registry_metadata(
        registry_copy(),
        2,
        subject_updates={"outcome_code": "offer"},
    )

    negatives = [
        {
            "expected_error": "identity",
            "id": "legacy_private_job_identity",
            "kind": "event_identity",
            "value": {
                "application_id": identity.application_id,
                "handoff_root_sha256": identity.root_sha256,
                "job_key": "greenhouse:synthetic:123",
                "profile_id": identity.payload["profile_id"],
            },
        },
        {
            "expected_error": "chain_substitution",
            "id": "release_ready_answers_substitution",
            "kind": "event_detail",
            "prior_sequence": 2,
            "value": {**built_details[2], "answers_sha256": "f" * 64},
        },
        {
            "expected_error": "sequence",
            "id": "zero_transition_sequence",
            "kind": "event_detail",
            "prior_sequence": 0,
            "value": {
                **built_details[0],
                "transition_sequence": 0,
            },
        },
        {
            "expected_error": "sequence",
            "id": "negative_transition_sequence",
            "kind": "event_detail",
            "prior_sequence": 0,
            "value": {
                **built_details[0],
                "transition_sequence": -1,
            },
        },
        event_negative(
            vector_id="first_transition_sequence_99",
            expected_error="sequence",
            prior_sequence=0,
            event_type="strategy_started",
            detail={**built_details[0], "transition_sequence": 99},
            occurred_at="2026-08-10T11:00:00Z",
        ),
        event_negative(
            vector_id="skipped_transition_sequence",
            expected_error="sequence",
            prior_sequence=2,
            event_type="release_ready",
            detail={**built_details[2], "transition_sequence": 4},
            occurred_at="2026-08-10T11:01:00Z",
        ),
        event_negative(
            vector_id="repeated_transition_sequence",
            expected_error="sequence",
            prior_sequence=2,
            event_type="release_ready",
            detail={**built_details[2], "transition_sequence": 2},
            occurred_at="2026-08-10T11:02:00Z",
        ),
        event_negative(
            vector_id="decreasing_transition_sequence",
            expected_error="sequence",
            prior_sequence=3,
            event_type="submission_authorized",
            detail={**built_details[3], "transition_sequence": 2},
            occurred_at="2026-08-10T11:03:00Z",
        ),
        event_negative(
            vector_id="contiguous_but_illegal_predecessor",
            expected_error="illegal_predecessor",
            prior_sequence=1,
            event_type="release_ready",
            detail={**built_details[2], "transition_sequence": 2},
            occurred_at="2026-08-10T11:04:00Z",
        ),
        {
            "expected_error": "post_terminal",
            "id": "post_terminal_status",
            "kind": "event_detail",
            "prior_sequence": 9,
            "value": {
                **built_details[7],
                "transition_sequence": 10,
            },
        },
        {
            "expected_error": "outcome",
            "id": "outcome_state_substitution",
            "kind": "event_detail",
            "prior_sequence": 8,
            "value": {**built_details[8], "outcome_code": "offer"},
        },
        {
            "expected_error": "receipt_missing",
            "id": "reverse_receipt_missing_transition",
            "kind": "reverse_receipt_registry",
            "value": missing_registry,
        },
        {
            "expected_error": "receipt_duplicate",
            "id": "reverse_receipt_duplicate_transition",
            "kind": "reverse_receipt_registry",
            "value": duplicate_registry,
        },
        {
            "expected_error": "receipt_event",
            "id": "reverse_receipt_wrong_event",
            "kind": "reverse_receipt_registry",
            "value": wrong_event_registry,
        },
        {
            "expected_error": "receipt_sequence",
            "id": "reverse_receipt_sequence_swap",
            "kind": "reverse_receipt_registry",
            "value": wrong_sequence_registry,
        },
        {
            "expected_error": "receipt_time_binding",
            "id": "reverse_receipt_occurred_at_swap",
            "kind": "reverse_receipt_registry",
            "value": wrong_occurred_at_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "state_subject_previous_state_swap",
            "kind": "reverse_receipt_registry",
            "value": previous_state_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "state_subject_new_state_swap",
            "kind": "reverse_receipt_registry",
            "value": new_state_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "state_subject_attempt_swap",
            "kind": "reverse_receipt_registry",
            "value": attempt_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "state_subject_grant_swap",
            "kind": "reverse_receipt_registry",
            "value": grant_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "state_subject_external_receipt_swap",
            "kind": "reverse_receipt_registry",
            "value": external_receipt_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "state_subject_cross_event_swap",
            "kind": "reverse_receipt_registry",
            "value": subject_swap_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "state_subject_application_swap",
            "kind": "reverse_receipt_registry",
            "value": application_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "state_registry_type_swap",
            "kind": "reverse_receipt_registry",
            "value": type_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "state_exact_bytes_swap",
            "kind": "reverse_receipt_registry",
            "value": exact_registry,
        },
        {
            "expected_error": "receipt_substitution",
            "id": "outcome_subject_code_swap",
            "kind": "reverse_receipt_registry",
            "value": outcome_registry,
        },
    ]
    document = {
        "bindings": {
            "answers_sha256": answers_sha256,
            "application_source_identity": source,
            "artifact_set_sha256": artifacts,
            "authority_id": authority_id,
            "attempt_id": attempt_id,
            "cover_letter_pdf_sha256": cover_sha256,
            "cv_pdf_sha256": cv_sha256,
            "employer_assessment_receipt_sha256": assessment_sha256,
            "external_receipt_sha256": external_sha256,
            "grant_sha256": grant_sha256,
            "operator_approval_receipt_sha256": approval_sha256,
            "route_id": route_id,
        },
        "events": events,
        "release_blocked_branch": blocked_events,
        "form_answers": {
            "canonical_base64": _b64(form_answers_bytes),
            "schema_version": "jaa.form-answers.v1",
            "sha256": answers_sha256,
        },
        "identity": {
            "application_id": identity.application_id,
            "handoff_root_sha256": identity.root_sha256,
            "job_key": identity.payload["job_key"],
            "profile_id": identity.payload["profile_id"],
        },
        "market_source": {
            "fixture_path": "tests/fixtures/contracts/market-aligner-v1-vectors.json",
            "fixture_sha256": MARKET_FIXTURE_SHA256,
            "producer_commit": MARKET_SOURCE_COMMIT,
        },
        "negative_vectors": negatives,
        "reverse_receipts": reverse_receipts,
        "schema_version": "jaa.event-golden-corpus.v2",
    }
    return canonical_json_bytes(document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = build_corpus()
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != expected:
            raise SystemExit("JAA event golden corpus is missing or stale")
        print(_sha(expected))
        return 0
    args.output.write_bytes(expected)
    print(_sha(expected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
