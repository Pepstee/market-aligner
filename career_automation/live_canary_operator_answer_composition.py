"""Bind bounded operator answers to one accepted fixture-only intake."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from career_automation.live_canary_authority import _content_hash, _digest
from career_automation.live_canary_operator_answers import (
    ANSWERS_FILE_SHA256,
    FROZEN_OPERATOR_ANSWERS,
    ApprovedEvidenceReference,
    OperatorAnswerDecision,
    OperatorAnswerRequest,
    evaluate_operator_answer,
    verify_operator_answers_document,
)
from career_automation.live_canary_operator_document_intake import (
    OperatorDocumentIntake,
)


ANSWER_COMPOSITION_SCHEMA = (
    "jaa11.live-canary-operator-answer-composition.v1"
)
MAX_ANSWER_REQUESTS = 8


def _evidence_document(
    evidence: ApprovedEvidenceReference | None,
) -> dict[str, object] | None:
    if evidence is None:
        return None
    return {
        "source_kind": evidence.source_kind,
        "source_sha256": evidence.source_sha256,
        "topic": evidence.topic,
        "exact_claim": evidence.exact_claim,
        "jurisdiction": evidence.jurisdiction,
        "verified": evidence.verified,
    }


def _request_document(request: OperatorAnswerRequest) -> dict[str, object]:
    return {
        "topic": request.topic,
        "answer_kind": request.answer_kind,
        "subtopic": request.subtopic,
        "jurisdiction": request.jurisdiction,
        "evidence": _evidence_document(request.evidence),
        "role_location": request.role_location,
        "age_basis": request.age_basis,
        "hours": request.hours,
        "compensation_period": request.compensation_period,
        "statutory_floor_minor_units": (
            request.statutory_floor_minor_units
        ),
        "proposed_salary_minor_units": request.proposed_salary_minor_units,
        "law_evidence_sha256": request.law_evidence_sha256,
        "market_range_evidence_sha256": (
            request.market_range_evidence_sha256
        ),
    }


def _decision_document(
    decision: OperatorAnswerDecision,
) -> dict[str, object]:
    return {
        "status": decision.status,
        "topic": decision.topic,
        "answer": decision.answer,
        "reasons": list(decision.reasons),
        "authority_record_sha256": decision.authority_record_sha256,
        "operational_release": decision.operational_release,
        "may_submit": decision.may_submit,
        "external_action_capability": decision.external_action_capability,
        "real_applications": decision.real_applications,
    }


@dataclass(frozen=True)
class ComposedAnswerItem:
    index: int
    request: OperatorAnswerRequest
    decision: OperatorAnswerDecision
    request_sha256: str
    decision_sha256: str

    def __post_init__(self) -> None:
        if type(self.index) is not int or self.index < 0:
            raise ValueError("answer item index is invalid")
        if type(self.request) is not OperatorAnswerRequest:
            raise ValueError("answer item requires an exact request")
        if type(self.decision) is not OperatorAnswerDecision:
            raise ValueError("answer item requires an exact decision")
        _digest(self.request_sha256, "answer request hash")
        _digest(self.decision_sha256, "answer decision hash")
        expected_decision = evaluate_operator_answer(
            FROZEN_OPERATOR_ANSWERS,
            self.request,
        )
        if self.decision != expected_decision:
            raise ValueError("answer decision does not match its request")
        if self.request_sha256 != _content_hash(
            _request_document(self.request)
        ):
            raise ValueError("answer request hash is invalid")
        if self.decision_sha256 != _content_hash(
            _decision_document(self.decision)
        ):
            raise ValueError("answer decision hash is invalid")

    def document(self) -> dict[str, object]:
        return {
            "index": self.index,
            "request": _request_document(self.request),
            "request_sha256": self.request_sha256,
            "decision": _decision_document(self.decision),
            "decision_sha256": self.decision_sha256,
        }


@dataclass(frozen=True)
class OperatorAnswerComposition:
    intake: OperatorDocumentIntake
    items: tuple[ComposedAnswerItem, ...]
    intake_sha256: str
    composition_sha256: str
    operator_document_sha256: str
    dry_run_sha256: str
    selected_entry_sha256: str
    answers_document_sha256: str
    authority_record_sha256: str
    permitted_count: int
    fail_closed_count: int
    out_of_scope_count: int
    all_requests_permitted: bool
    answer_composition_sha256: str
    positive_evidence_is_fixture_only: bool = True
    snapshot_source: str = "operator_supplied_document"
    acquired_by_system: bool = False
    snapshot_is_live: bool = False
    snapshot_is_current: bool = False
    selected_vacancy_status: str = (
        "operator_supplied_not_selected_for_external_use"
    )
    answers_used_for_external_submission: bool = False
    operational_release: str = "withheld"
    may_submit: bool = False
    external_action_capability: bool = False
    certifies_slice: bool = False
    receipt_written: bool = False
    real_applications: int = 0
    schema_version: str = ANSWER_COMPOSITION_SCHEMA

    def __post_init__(self) -> None:
        if type(self.intake) is not OperatorDocumentIntake:
            raise ValueError("answer composition requires the exact intake")
        if type(self.items) is not tuple or not (
            1 <= len(self.items) <= MAX_ANSWER_REQUESTS
        ):
            raise ValueError("answer item tuple is outside the bound")
        if any(type(item) is not ComposedAnswerItem for item in self.items):
            raise ValueError("answer composition item type is invalid")
        if tuple(item.index for item in self.items) != tuple(
            range(len(self.items))
        ):
            raise ValueError("answer composition order is invalid")
        identities = tuple(
            (item.request.topic, item.request.subtopic) for item in self.items
        )
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate answer topic and subtopic")
        for value, label in (
            (self.intake_sha256, "intake hash"),
            (self.composition_sha256, "fixture composition hash"),
            (self.operator_document_sha256, "operator document hash"),
            (self.dry_run_sha256, "dry-run hash"),
            (self.selected_entry_sha256, "selected entry hash"),
            (self.answers_document_sha256, "answers document hash"),
            (self.authority_record_sha256, "answer authority hash"),
            (self.answer_composition_sha256, "answer composition hash"),
        ):
            _digest(value, label)
        intake = self.intake
        composition = intake.composition
        if not (
            self.intake_sha256
            == intake.intake_sha256
            == _content_hash(intake.document(include_hash=False))
        ):
            raise ValueError("intake hash binding is invalid")
        if not (
            self.composition_sha256
            == intake.composition_sha256
            == composition.composition_sha256
        ):
            raise ValueError("fixture composition binding is invalid")
        if not (
            self.operator_document_sha256
            == intake.operator_document_sha256
            == composition.operator_document_sha256
        ):
            raise ValueError("snapshot document binding is invalid")
        if not (
            self.dry_run_sha256
            == composition.dry_run_sha256
            == composition.dry_run.dry_run_sha256
        ):
            raise ValueError("dry-run binding is invalid")
        if not (
            self.selected_entry_sha256
            == composition.selected_entry_sha256
            == composition.dry_run.selected_entry_sha256
        ):
            raise ValueError("selected-entry binding is invalid")
        if self.answers_document_sha256 != ANSWERS_FILE_SHA256:
            raise ValueError("answers document binding is invalid")
        if self.authority_record_sha256 != (
            FROZEN_OPERATOR_ANSWERS.record_sha256
        ) or any(
            item.decision.authority_record_sha256
            != self.authority_record_sha256
            for item in self.items
        ):
            raise ValueError("answer authority binding is invalid")
        counts = (
            sum(item.decision.status == "ANSWER_PERMITTED" for item in self.items),
            sum(item.decision.status == "FAIL_CLOSED" for item in self.items),
            sum(item.decision.status == "OUT_OF_SCOPE" for item in self.items),
        )
        if counts != (
            self.permitted_count,
            self.fail_closed_count,
            self.out_of_scope_count,
        ) or sum(counts) != len(self.items):
            raise ValueError("answer decision counts are invalid")
        if self.all_requests_permitted is not (
            self.permitted_count == len(self.items)
        ):
            raise ValueError("all-permitted marker is invalid")
        expected_boundary = (
            True,
            "operator_supplied_document",
            False,
            False,
            False,
            "operator_supplied_not_selected_for_external_use",
            False,
            "withheld",
            False,
            False,
            False,
            False,
            0,
            ANSWER_COMPOSITION_SCHEMA,
        )
        actual_boundary = (
            self.positive_evidence_is_fixture_only,
            self.snapshot_source,
            self.acquired_by_system,
            self.snapshot_is_live,
            self.snapshot_is_current,
            self.selected_vacancy_status,
            self.answers_used_for_external_submission,
            self.operational_release,
            self.may_submit,
            self.external_action_capability,
            self.certifies_slice,
            self.receipt_written,
            self.real_applications,
            self.schema_version,
        )
        if actual_boundary != expected_boundary:
            raise ValueError("answer composition cannot open a boundary")
        if self.answer_composition_sha256 != _content_hash(
            self.document(include_hash=False)
        ):
            raise ValueError("answer composition hash is invalid")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "intake": self.intake.document(),
            "intake_sha256": self.intake_sha256,
            "composition_sha256": self.composition_sha256,
            "operator_document_sha256": self.operator_document_sha256,
            "dry_run_sha256": self.dry_run_sha256,
            "selected_entry_sha256": self.selected_entry_sha256,
            "answers_document_sha256": self.answers_document_sha256,
            "authority_record_sha256": self.authority_record_sha256,
            "items": [item.document() for item in self.items],
            "permitted_count": self.permitted_count,
            "fail_closed_count": self.fail_closed_count,
            "out_of_scope_count": self.out_of_scope_count,
            "all_requests_permitted": self.all_requests_permitted,
            "positive_evidence_is_fixture_only": (
                self.positive_evidence_is_fixture_only
            ),
            "snapshot_source": self.snapshot_source,
            "acquired_by_system": self.acquired_by_system,
            "snapshot_is_live": self.snapshot_is_live,
            "snapshot_is_current": self.snapshot_is_current,
            "selected_vacancy_status": self.selected_vacancy_status,
            "answers_used_for_external_submission": (
                self.answers_used_for_external_submission
            ),
            "operational_release": self.operational_release,
            "may_submit": self.may_submit,
            "external_action_capability": self.external_action_capability,
            "certifies_slice": self.certifies_slice,
            "receipt_written": self.receipt_written,
            "real_applications": self.real_applications,
        }
        if include_hash:
            result["answer_composition_sha256"] = (
                self.answer_composition_sha256
            )
        return result


def compose_operator_answers_dry_run(
    intake: object,
    answers_document_bytes: object,
    requests: object,
) -> OperatorAnswerComposition:
    """Bind bounded answer decisions to one fixture-only operator intake."""
    if type(intake) is not OperatorDocumentIntake:
        raise ValueError("answer composition requires an exact intake")
    authority = verify_operator_answers_document(answers_document_bytes)  # type: ignore[arg-type]
    if type(requests) is not tuple or not (
        1 <= len(requests) <= MAX_ANSWER_REQUESTS
    ):
        raise ValueError("answer requests are outside the bounded tuple")
    if any(type(request) is not OperatorAnswerRequest for request in requests):
        raise ValueError("answer request type is invalid")
    identities = tuple((request.topic, request.subtopic) for request in requests)
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate answer topic and subtopic")
    items = tuple(
        ComposedAnswerItem(
            index=index,
            request=request,
            decision=(decision := evaluate_operator_answer(authority, request)),
            request_sha256=_content_hash(_request_document(request)),
            decision_sha256=_content_hash(_decision_document(decision)),
        )
        for index, request in enumerate(requests)
    )
    statuses = tuple(item.decision.status for item in items)
    fields: dict[str, object] = {
        "intake": intake,
        "items": items,
        "intake_sha256": intake.intake_sha256,
        "composition_sha256": intake.composition_sha256,
        "operator_document_sha256": intake.operator_document_sha256,
        "dry_run_sha256": intake.composition.dry_run_sha256,
        "selected_entry_sha256": intake.composition.selected_entry_sha256,
        "answers_document_sha256": hashlib.sha256(
            answers_document_bytes  # type: ignore[arg-type]
        ).hexdigest(),
        "authority_record_sha256": authority.record_sha256,
        "permitted_count": statuses.count("ANSWER_PERMITTED"),
        "fail_closed_count": statuses.count("FAIL_CLOSED"),
        "out_of_scope_count": statuses.count("OUT_OF_SCOPE"),
        "all_requests_permitted": all(
            status == "ANSWER_PERMITTED" for status in statuses
        ),
        "positive_evidence_is_fixture_only": True,
        "snapshot_source": "operator_supplied_document",
        "acquired_by_system": False,
        "snapshot_is_live": False,
        "snapshot_is_current": False,
        "selected_vacancy_status": (
            "operator_supplied_not_selected_for_external_use"
        ),
        "answers_used_for_external_submission": False,
        "operational_release": "withheld",
        "may_submit": False,
        "external_action_capability": False,
        "certifies_slice": False,
        "receipt_written": False,
        "real_applications": 0,
        "schema_version": ANSWER_COMPOSITION_SCHEMA,
    }
    preimage = dict(fields)
    preimage["intake"] = intake.document()
    preimage["items"] = [item.document() for item in items]
    fields["answer_composition_sha256"] = _content_hash(preimage)
    return OperatorAnswerComposition(**fields)  # type: ignore[arg-type]


__all__ = [
    "ANSWER_COMPOSITION_SCHEMA",
    "MAX_ANSWER_REQUESTS",
    "ComposedAnswerItem",
    "OperatorAnswerComposition",
    "compose_operator_answers_dry_run",
]
