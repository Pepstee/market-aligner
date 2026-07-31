"""Pure-data authority for bounded JAA-11 operator application answers.

The module binds caller-supplied bytes to the operator's approved answer
document and evaluates only relocation, work-authorisation, and salary
requests.  It performs no filesystem, browser, network, release, or
submission action.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Literal


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
ANSWERS_PATH_BASE = "software_factory_root"
ANSWERS_RELATIVE_PATH = (
    "giga-user/reports/JAA_OPERATOR_APPLICATION_ANSWERS_2026-07-31.md"
)
ANSWERS_FILE_SHA256 = (
    "670c873479589088a078c871500fa0ae999281f583afb08047dbb95465501652"
)
APPROVED_SALARY_FREE_TEXT = (
    "Flexible and open to a market-competitive package appropriate to the "
    "role; any offer must meet applicable statutory minimums."
)
ANSWER_TOPICS = ("relocation", "work_authorisation", "salary")
RELOCATION_NARROWER_COMMITMENTS = (
    "relocation_date",
    "relocation_destination",
    "self_funded_relocation",
    "relocate_before_offer",
)
WORK_AUTHORISATION_FAIL_CLOSED_TOPICS = (
    "citizenship",
    "residence",
    "sponsorship",
    "permit_duration",
    "security_clearance",
    "export_control",
    "unrestricted_status",
    "permanent_status",
)
WORK_AUTHORISATION_ACCEPTED_SUBTOPICS = ("current_work_authorisation",)
SALARY_FAIL_CLOSED_TOPICS = (
    "current_salary",
    "desired_benefits",
    "equity_expectations",
    "unpaid_work",
)
SALARY_FREE_TEXT_ACCEPTED_SUBTOPICS = (
    "market_competitive_statutory_minimum_free_text",
)

AnswerStatus = Literal["ANSWER_PERMITTED", "FAIL_CLOSED", "OUT_OF_SCOPE"]


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and HEX_64.fullmatch(value) is not None


def _clean_text(value: object) -> str | None:
    if not isinstance(value, str) or not value or value.strip() != value:
        return None
    return value


@dataclass(frozen=True)
class OperatorAnswersAuthority:
    path_base: str
    relative_path: str
    answers_file_sha256: str
    topics: tuple[str, ...]
    relocation_willing: bool
    relocation_narrower_commitments: tuple[str, ...]
    work_authorisation_requires_jurisdiction_evidence: bool
    work_authorisation_fail_closed_topics: tuple[str, ...]
    salary_free_text: str
    salary_requires_statutory_floor: bool
    salary_avoids_minimum_wage_anchoring: bool
    salary_fail_closed_topics: tuple[str, ...]
    operational_release: str = "withheld"
    may_submit: bool = False
    external_action_capability: bool = False
    real_applications: int = 0
    schema_version: str = "jaa11.operator-application-answers.v1"

    def __post_init__(self) -> None:
        expected = (
            ANSWERS_PATH_BASE,
            ANSWERS_RELATIVE_PATH,
            ANSWERS_FILE_SHA256,
            ANSWER_TOPICS,
            True,
            RELOCATION_NARROWER_COMMITMENTS,
            True,
            WORK_AUTHORISATION_FAIL_CLOSED_TOPICS,
            APPROVED_SALARY_FREE_TEXT,
            True,
            True,
            SALARY_FAIL_CLOSED_TOPICS,
            "withheld",
            False,
            False,
            0,
            "jaa11.operator-application-answers.v1",
        )
        actual = (
            self.path_base,
            self.relative_path,
            self.answers_file_sha256,
            self.topics,
            self.relocation_willing,
            self.relocation_narrower_commitments,
            self.work_authorisation_requires_jurisdiction_evidence,
            self.work_authorisation_fail_closed_topics,
            self.salary_free_text,
            self.salary_requires_statutory_floor,
            self.salary_avoids_minimum_wage_anchoring,
            self.salary_fail_closed_topics,
            self.operational_release,
            self.may_submit,
            self.external_action_capability,
            self.real_applications,
            self.schema_version,
        )
        if actual != expected:
            raise ValueError(
                "operator answers authority differs from the frozen scope"
            )

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "answers_document": {
                "path_base": self.path_base,
                "relative_path": self.relative_path,
                "sha256": self.answers_file_sha256,
            },
            "topics": list(self.topics),
            "relocation": {
                "willing": self.relocation_willing,
                "narrower_commitments_fail_closed": list(
                    self.relocation_narrower_commitments
                ),
            },
            "work_authorisation": {
                "jurisdiction_evidence_required": (
                    self.work_authorisation_requires_jurisdiction_evidence
                ),
                "fail_closed_topics": list(
                    self.work_authorisation_fail_closed_topics
                ),
            },
            "salary": {
                "approved_free_text": self.salary_free_text,
                "statutory_floor_required": (
                    self.salary_requires_statutory_floor
                ),
                "minimum_wage_anchoring_avoided": (
                    self.salary_avoids_minimum_wage_anchoring
                ),
                "fail_closed_topics": list(
                    self.salary_fail_closed_topics
                ),
            },
            "operational_release": self.operational_release,
            "may_submit": self.may_submit,
            "external_action_capability": self.external_action_capability,
            "real_applications": self.real_applications,
        }

    @property
    def record_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_OPERATOR_ANSWERS = OperatorAnswersAuthority(
    path_base=ANSWERS_PATH_BASE,
    relative_path=ANSWERS_RELATIVE_PATH,
    answers_file_sha256=ANSWERS_FILE_SHA256,
    topics=ANSWER_TOPICS,
    relocation_willing=True,
    relocation_narrower_commitments=RELOCATION_NARROWER_COMMITMENTS,
    work_authorisation_requires_jurisdiction_evidence=True,
    work_authorisation_fail_closed_topics=(
        WORK_AUTHORISATION_FAIL_CLOSED_TOPICS
    ),
    salary_free_text=APPROVED_SALARY_FREE_TEXT,
    salary_requires_statutory_floor=True,
    salary_avoids_minimum_wage_anchoring=True,
    salary_fail_closed_topics=SALARY_FAIL_CLOSED_TOPICS,
)


@dataclass(frozen=True)
class ApprovedEvidenceReference:
    source_kind: str
    source_sha256: str
    topic: str
    exact_claim: str
    jurisdiction: str | None = None
    verified: bool = True

    def __post_init__(self) -> None:
        if _clean_text(self.source_kind) is None:
            raise ValueError("evidence source kind is required")
        if not _is_sha256(self.source_sha256):
            raise ValueError("evidence source hash must be a lowercase SHA-256")
        if _clean_text(self.topic) is None:
            raise ValueError("evidence topic is required")
        if _clean_text(self.exact_claim) is None:
            raise ValueError("evidence exact claim is required")
        if self.jurisdiction is not None and (
            _clean_text(self.jurisdiction) is None
        ):
            raise ValueError("evidence jurisdiction must be canonical text")
        if type(self.verified) is not bool:
            raise ValueError("evidence verification state must be boolean")


@dataclass(frozen=True)
class OperatorAnswerRequest:
    topic: str
    answer_kind: str
    subtopic: str | None = None
    jurisdiction: str | None = None
    evidence: ApprovedEvidenceReference | None = None
    role_location: str | None = None
    age_basis: str | None = None
    hours: int | None = None
    compensation_period: str | None = None
    statutory_floor_minor_units: int | None = None
    proposed_salary_minor_units: int | None = None
    law_evidence_sha256: str | None = None
    market_range_evidence_sha256: str | None = None


@dataclass(frozen=True)
class OperatorAnswerDecision:
    status: AnswerStatus
    topic: str
    answer: bool | str | int | None
    reasons: tuple[str, ...]
    authority_record_sha256: str
    operational_release: str = "withheld"
    may_submit: bool = False
    external_action_capability: bool = False
    real_applications: int = 0

    def __post_init__(self) -> None:
        if self.status not in {
            "ANSWER_PERMITTED",
            "FAIL_CLOSED",
            "OUT_OF_SCOPE",
        }:
            raise ValueError("unknown answer decision status")
        if self.authority_record_sha256 != (
            FROZEN_OPERATOR_ANSWERS.record_sha256
        ):
            raise ValueError("decision uses an unaccepted answer authority")
        if (
            self.operational_release != "withheld"
            or self.may_submit is not False
            or self.external_action_capability is not False
            or self.real_applications != 0
        ):
            raise ValueError("answer decision cannot grant external authority")
        if self.status != "ANSWER_PERMITTED" and self.answer is not None:
            raise ValueError("withheld decisions cannot carry an answer")
        if not self.reasons:
            raise ValueError("answer decision requires a reason")


def verify_operator_answers_document(
    document_bytes: bytes,
) -> OperatorAnswersAuthority:
    """Bind exact caller-supplied bytes to the frozen operator document."""
    if type(document_bytes) is not bytes or not document_bytes:
        raise ValueError("operator answers document must be non-empty bytes")
    digest = hashlib.sha256(document_bytes).hexdigest()
    if digest != ANSWERS_FILE_SHA256:
        raise ValueError("operator answers document hash mismatch")
    return FROZEN_OPERATOR_ANSWERS


def _decision(
    status: AnswerStatus,
    topic: str,
    reason: str,
    *,
    answer: bool | str | int | None = None,
) -> OperatorAnswerDecision:
    return OperatorAnswerDecision(
        status=status,
        topic=topic,
        answer=answer,
        reasons=(reason,),
        authority_record_sha256=FROZEN_OPERATOR_ANSWERS.record_sha256,
    )


def _matches_operator_document(
    evidence: ApprovedEvidenceReference | None,
    *,
    topic: str,
    exact_claim: str,
) -> bool:
    return (
        evidence is not None
        and evidence.verified is True
        and evidence.source_kind == "operator_answers_document"
        and evidence.source_sha256 == ANSWERS_FILE_SHA256
        and evidence.topic == topic
        and evidence.exact_claim == exact_claim
        and evidence.jurisdiction is None
    )


def _evaluate_relocation(
    request: OperatorAnswerRequest,
) -> OperatorAnswerDecision:
    if request.subtopic in RELOCATION_NARROWER_COMMITMENTS:
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "narrower_relocation_commitment_requires_operator_input",
        )
    if request.subtopic not in {None, "willing_to_relocate"}:
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "relocation_claim_not_approved",
        )
    if request.answer_kind != "boolean" or not _matches_operator_document(
        request.evidence,
        topic="relocation",
        exact_claim="willing_to_relocate",
    ):
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "matching_relocation_evidence_required",
        )
    return _decision(
        "ANSWER_PERMITTED",
        request.topic,
        "operator_approved_relocation_willingness",
        answer=True,
    )


def _evaluate_work_authorisation(
    request: OperatorAnswerRequest,
) -> OperatorAnswerDecision:
    if request.subtopic in WORK_AUTHORISATION_FAIL_CLOSED_TOPICS:
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "work_authorisation_topic_cannot_be_inferred",
        )
    if request.subtopic not in {
        None,
        *WORK_AUTHORISATION_ACCEPTED_SUBTOPICS,
    }:
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "work_authorisation_claim_not_approved",
        )
    jurisdiction = _clean_text(request.jurisdiction)
    evidence = request.evidence
    if (
        request.answer_kind != "boolean"
        or jurisdiction is None
        or evidence is None
        or evidence.verified is not True
        or evidence.source_kind != "identity_work_rights_ledger"
        or evidence.topic != "work_authorisation"
        or evidence.exact_claim != "current_work_authorisation"
        or evidence.jurisdiction != jurisdiction
    ):
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "exact_jurisdiction_work_rights_evidence_required",
        )
    return _decision(
        "ANSWER_PERMITTED",
        request.topic,
        "jurisdiction_specific_work_rights_verified",
        answer=True,
    )


def _salary_numeric_inputs_are_complete(
    request: OperatorAnswerRequest,
) -> bool:
    return (
        _clean_text(request.role_location) is not None
        and _clean_text(request.age_basis) is not None
        and type(request.hours) is int
        and request.hours > 0
        and _clean_text(request.compensation_period) is not None
        and type(request.statutory_floor_minor_units) is int
        and request.statutory_floor_minor_units >= 0
        and type(request.proposed_salary_minor_units) is int
        and request.proposed_salary_minor_units
        >= request.statutory_floor_minor_units
        and _is_sha256(request.law_evidence_sha256)
        and _is_sha256(request.market_range_evidence_sha256)
    )


def _evaluate_salary(
    request: OperatorAnswerRequest,
) -> OperatorAnswerDecision:
    if request.subtopic in SALARY_FAIL_CLOSED_TOPICS:
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "salary_topic_cannot_be_inferred",
        )
    if request.answer_kind == "free_text":
        if request.subtopic not in {
            None,
            *SALARY_FREE_TEXT_ACCEPTED_SUBTOPICS,
        }:
            return _decision(
                "FAIL_CLOSED",
                request.topic,
                "salary_claim_not_approved",
            )
        if not _matches_operator_document(
            request.evidence,
            topic="salary",
            exact_claim="market_competitive_statutory_minimum_free_text",
        ):
            return _decision(
                "FAIL_CLOSED",
                request.topic,
                "matching_salary_evidence_required",
            )
        return _decision(
            "ANSWER_PERMITTED",
            request.topic,
            "exact_operator_approved_salary_free_text",
            answer=APPROVED_SALARY_FREE_TEXT,
        )
    if request.answer_kind != "numeric":
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "unsupported_salary_answer_kind",
        )
    if request.subtopic is not None:
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "salary_claim_not_approved",
        )
    if not _salary_numeric_inputs_are_complete(request):
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "complete_law_location_age_hours_period_and_market_inputs_required",
        )
    return _decision(
        "ANSWER_PERMITTED",
        request.topic,
        "numeric_salary_meets_verified_floor_and_market_basis",
        answer=request.proposed_salary_minor_units,
    )


def evaluate_operator_answer(
    authority: OperatorAnswersAuthority,
    request: OperatorAnswerRequest,
) -> OperatorAnswerDecision:
    """Evaluate one bounded answer request without granting release."""
    if authority != FROZEN_OPERATOR_ANSWERS:
        return _decision(
            "FAIL_CLOSED",
            request.topic,
            "unaccepted_operator_answers_authority",
        )
    if request.topic not in ANSWER_TOPICS:
        return _decision(
            "OUT_OF_SCOPE",
            request.topic,
            "topic_outside_operator_answers_authority",
        )
    if request.topic == "relocation":
        return _evaluate_relocation(request)
    if request.topic == "work_authorisation":
        return _evaluate_work_authorisation(request)
    return _evaluate_salary(request)
