"""Inert interview preparation and communication contract for JAA-13.

The module binds approved application facts to local preparation plans, marks
local debrief bytes as unverified, and creates non-sendable draft plans. It
does not retrieve sources, promote facts, render a message, or perform an
external action.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from types import MappingProxyType
from typing import Iterable, Mapping

from .application_compiler import (
    ApplicationSource,
    FactualSentence,
    validate_style_text,
    verify_application_source,
)
from .employer_research import FRESHNESS_DAYS, PROTECTED_FIELDS
from .models import IntelligenceKind, PipelineState
from .status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    StatusTimeline,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
INTERVIEW_STATES = (
    PipelineState.INTERVIEW,
    PipelineState.FINAL_STAGE,
    PipelineState.OFFER,
)
HUMANIZER_FORBIDDEN = (
    "\u2014",
    "\u2013",
    " -- ",
    "delve",
    "pivotal",
    "showcase",
    "tapestry",
    "i hope this helps",
    "let me know",
    "not only",
    "it's not just",
)
PREPARATION_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa13.interview-preparation-policy.v1",
    "candidate_authority": "exact_approved_application_fact",
    "employer_authority": "exact_current_cited_application_fact",
    "stale_evidence": "refresh_required_but_not_authorized",
    "private_person_inference": False,
})
DEBRIEF_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa13.local-debrief-policy.v1",
    "retention": "content_addressed_reference_only",
    "assertion_status": "unverified_operator_statement",
    "candidate_fact_authority": False,
    "employer_fact_authority": False,
})
DRAFT_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa13.follow-up-draft-plan-policy.v1",
    "factual_atoms": "exact_preparation_authority_only",
    "debrief_fact_authority": False,
    "operator_confirmation_required": True,
    "truth_release_authority": "withheld",
    "connector_authority": "withheld",
    "send_authority": "withheld",
})


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


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _required(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    if value != value.strip():
        raise ValueError(f"{label} must not contain surrounding whitespace")
    return value


def _aware(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{label} must include a timezone")
    return value


def _natural_connective(value: str) -> str:
    validate_style_text(value)
    folded = value.casefold()
    if any(pattern in folded for pattern in HUMANIZER_FORBIDDEN):
        raise ValueError("draft connective violates the natural-language policy")
    return value


PREPARATION_POLICY_SHA256 = _content_hash(dict(PREPARATION_POLICY))
DEBRIEF_POLICY_SHA256 = _content_hash(dict(DEBRIEF_POLICY))
DRAFT_POLICY_SHA256 = _content_hash(dict(DRAFT_POLICY))


@dataclass(frozen=True)
class InterviewCommunicationContract:
    upstream_status_contract_sha256: str
    preparation_policy_sha256: str
    debrief_policy_sha256: str
    draft_policy_sha256: str
    source_refresh_authority: str = "withheld"
    private_person_inference: bool = False
    candidate_fact_mutation_authority: bool = False
    connector_authority: str = "withheld"
    message_send_authority: str = "withheld"
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa13.local-interview-communication-contract.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (self.upstream_status_contract_sha256, "upstream status hash"),
            (self.preparation_policy_sha256, "preparation policy hash"),
            (self.debrief_policy_sha256, "debrief policy hash"),
            (self.draft_policy_sha256, "draft policy hash"),
        ):
            _digest(value, label)
        expected = (
            FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256,
            PREPARATION_POLICY_SHA256,
            DEBRIEF_POLICY_SHA256,
            DRAFT_POLICY_SHA256,
        )
        actual = (
            self.upstream_status_contract_sha256,
            self.preparation_policy_sha256,
            self.debrief_policy_sha256,
            self.draft_policy_sha256,
        )
        if actual != expected:
            raise ValueError("interview contract differs from accepted policies")
        if (
            self.source_refresh_authority != "withheld"
            or self.private_person_inference is not False
            or self.candidate_fact_mutation_authority is not False
            or self.connector_authority != "withheld"
            or self.message_send_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError("local interview contract cannot act or certify")
        if self.schema_version != (
            "jaa13.local-interview-communication-contract.v1"
        ):
            raise ValueError("interview contract schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "upstream_status_contract_sha256": (
                self.upstream_status_contract_sha256
            ),
            "preparation_policy_sha256": self.preparation_policy_sha256,
            "debrief_policy_sha256": self.debrief_policy_sha256,
            "draft_policy_sha256": self.draft_policy_sha256,
            "source_refresh_authority": "withheld",
            "private_person_inference": False,
            "candidate_fact_mutation_authority": False,
            "connector_authority": "withheld",
            "message_send_authority": "withheld",
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_INTERVIEW_COMMUNICATION_CONTRACT = InterviewCommunicationContract(
    upstream_status_contract_sha256=(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
    ),
    preparation_policy_sha256=PREPARATION_POLICY_SHA256,
    debrief_policy_sha256=DEBRIEF_POLICY_SHA256,
    draft_policy_sha256=DRAFT_POLICY_SHA256,
)


@dataclass(frozen=True)
class CandidateStoryAuthority:
    sentence_id: str
    approved_text_sha256: str
    requirement_id: str
    candidate_claim_id: str
    candidate_claim_version: int
    candidate_evidence_id: str
    candidate_evidence_version: int

    def __post_init__(self) -> None:
        for value, label in (
            (self.sentence_id, "story sentence ID"),
            (self.approved_text_sha256, "story text hash"),
        ):
            _digest(value, label)
        for value, label in (
            (self.requirement_id, "story requirement ID"),
            (self.candidate_claim_id, "story claim ID"),
            (self.candidate_evidence_id, "story evidence ID"),
        ):
            _required(value, label)
        if self.candidate_claim_version < 1 or self.candidate_evidence_version < 1:
            raise ValueError("story authority versions must be positive")

    def document(self) -> dict[str, object]:
        return vars(self)


@dataclass(frozen=True)
class EmployerGuidanceAuthority:
    sentence_id: str
    approved_text_sha256: str
    employer_claim_id: str
    employer_fact_sha256: str
    intelligence_kind: str
    source_ids: tuple[str, ...]
    observed_at: str
    freshness_deadline: str
    freshness_status: str = "current"
    private_person_inference: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_ids", tuple(self.source_ids))
        for value, label in (
            (self.sentence_id, "employer sentence ID"),
            (self.approved_text_sha256, "employer text hash"),
            (self.employer_fact_sha256, "employer fact hash"),
        ):
            _digest(value, label)
        _required(self.employer_claim_id, "employer claim ID")
        kind = IntelligenceKind(self.intelligence_kind)
        if (
            not self.source_ids
            or len(self.source_ids) != len(set(self.source_ids))
            or not all(
                isinstance(value, str) and value.strip()
                for value in self.source_ids
            )
        ):
            raise ValueError("employer guidance requires unique source IDs")
        if self.freshness_status != "current":
            raise ValueError("interview guidance requires current evidence")
        if self.private_person_inference is not False:
            raise ValueError("private-person inference is forbidden")
        observed = datetime.fromisoformat(self.observed_at)
        deadline = date.fromisoformat(self.freshness_deadline)
        _aware(observed, "employer guidance observation time")
        expected_deadline = observed.date() + timedelta(
            days=FRESHNESS_DAYS[kind]
        )
        if deadline != expected_deadline:
            raise ValueError(
                "employer guidance freshness deadline differs from policy"
            )

    def document(self) -> dict[str, object]:
        return {
            **vars(self),
            "source_ids": self.source_ids,
        }


@dataclass(frozen=True)
class PreparationItem:
    item_id: str
    kind: str
    prompt: str
    authority_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "authority_ids", tuple(self.authority_ids))
        _digest(self.item_id, "preparation item ID")
        if self.kind not in {
            "candidate_story",
            "likely_objection",
            "technical_drill",
            "candidate_question",
        }:
            raise ValueError("preparation item kind is unsupported")
        validate_style_text(self.prompt)
        if not self.authority_ids or len(self.authority_ids) != len(
            set(self.authority_ids)
        ):
            raise ValueError("preparation item requires unique authority")
        expected = _content_hash({
            "kind": self.kind,
            "prompt": self.prompt,
            "authority_ids": self.authority_ids,
        })
        if self.item_id != expected:
            raise ValueError("preparation item differs from exact content")

    def document(self) -> dict[str, object]:
        return {
            "item_id": self.item_id,
            "kind": self.kind,
            "prompt": self.prompt,
            "authority_ids": self.authority_ids,
        }


@dataclass(frozen=True)
class InterviewPreparationPack:
    contract_sha256: str
    application_id: str
    job_key: str
    released_application_sha256: str
    application_source_id: str
    application_source_content_sha256: str
    timeline_id: str
    as_of: str
    candidate_authorities: tuple[CandidateStoryAuthority, ...]
    employer_authorities: tuple[EmployerGuidanceAuthority, ...]
    items: tuple[PreparationItem, ...]
    pack_id: str
    source_refresh_authority: str = "withheld"
    private_person_inference: bool = False
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa13.interview-preparation-pack.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "candidate_authorities",
            tuple(self.candidate_authorities),
        )
        object.__setattr__(
            self,
            "employer_authorities",
            tuple(self.employer_authorities),
        )
        object.__setattr__(self, "items", tuple(self.items))
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "released_application_sha256": self.released_application_sha256,
            "application_source_id": self.application_source_id,
            "application_source_content_sha256": (
                self.application_source_content_sha256
            ),
            "timeline_id": self.timeline_id,
            "as_of": self.as_of,
            "candidate_authorities": tuple(
                row.document() for row in self.candidate_authorities
            ),
            "employer_authorities": tuple(
                row.document() for row in self.employer_authorities
            ),
            "items": tuple(row.document() for row in self.items),
            "source_refresh_authority": "withheld",
            "private_person_inference": False,
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["pack_id"] = self.pack_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "preparation contract hash"),
            (
                self.released_application_sha256,
                "released application hash",
            ),
            (self.application_source_id, "application source ID"),
            (
                self.application_source_content_sha256,
                "application source content hash",
            ),
            (self.timeline_id, "status timeline ID"),
            (self.pack_id, "preparation pack ID"),
        ):
            _digest(value, label)
        _required(self.application_id, "preparation application ID")
        _required(self.job_key, "preparation job key")
        as_of = date.fromisoformat(self.as_of)
        if (
            self.contract_sha256
            != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT.contract_sha256
        ):
            raise ValueError("preparation pack binds a different contract")
        candidate_ids = tuple(
            row.sentence_id for row in self.candidate_authorities
        )
        employer_ids = tuple(
            row.sentence_id for row in self.employer_authorities
        )
        if (
            not candidate_ids
            or not employer_ids
            or len(candidate_ids) != len(set(candidate_ids))
            or len(employer_ids) != len(set(employer_ids))
        ):
            raise ValueError("preparation authority must be non-empty and unique")
        for row in self.employer_authorities:
            observed = datetime.fromisoformat(row.observed_at)
            deadline = date.fromisoformat(row.freshness_deadline)
            if observed.date() > as_of:
                raise ValueError(
                    "future employer evidence cannot guide preparation"
                )
            if as_of > deadline:
                raise ValueError(
                    "employer guidance is stale; source refresh is required"
                )
        allowed = set(candidate_ids) | set(employer_ids)
        item_ids = tuple(row.item_id for row in self.items)
        if not item_ids or len(item_ids) != len(set(item_ids)):
            raise ValueError("preparation items must be non-empty and unique")
        if any(not set(row.authority_ids).issubset(allowed) for row in self.items):
            raise ValueError("preparation item cites unknown authority")
        if {row.kind for row in self.items} != {
            "candidate_story",
            "likely_objection",
            "technical_drill",
            "candidate_question",
        }:
            raise ValueError("preparation pack must cover every item kind")
        if (
            self.source_refresh_authority != "withheld"
            or self.private_person_inference is not False
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError("local preparation pack cannot act or certify")
        if self.schema_version != "jaa13.interview-preparation-pack.v1":
            raise ValueError("preparation pack schema is unsupported")
        if self.pack_id != _content_hash(self.document(include_identity=False)):
            raise ValueError("preparation pack differs from exact content")


def _candidate_authority(fact: FactualSentence) -> CandidateStoryAuthority:
    if fact.fact_kind != "candidate":
        raise ValueError("interview story requires a candidate fact")
    authority = fact.authority
    return CandidateStoryAuthority(
        sentence_id=fact.sentence_id,
        approved_text_sha256=hashlib.sha256(
            fact.approved_source_text.encode()
        ).hexdigest(),
        requirement_id=authority.requirement_id,
        candidate_claim_id=authority.candidate_claim_id,
        candidate_claim_version=authority.candidate_claim_version,
        candidate_evidence_id=authority.candidate_evidence_id,
        candidate_evidence_version=authority.candidate_evidence_version,
    )


def _employer_authority(
    fact: FactualSentence,
    *,
    as_of: date,
) -> EmployerGuidanceAuthority:
    if fact.fact_kind != "employer" or fact.employer_fact_json is None:
        raise ValueError("interview guidance requires an employer fact")
    try:
        document = json.loads(fact.employer_fact_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("employer guidance fact is malformed") from exc
    if (
        not isinstance(document, dict)
        or document.get("classification") != "fact"
        or document.get("id") != fact.authority.employer_research_claim_id
        or document.get("text") != fact.approved_source_text
        or PROTECTED_FIELDS.intersection(document)
        or document.get("subject_type") == "private_person"
    ):
        raise ValueError("employer guidance lacks safe exact fact authority")
    try:
        kind = IntelligenceKind(document.get("kind"))
        observed = datetime.fromisoformat(str(document.get("observed_at")))
    except (TypeError, ValueError) as exc:
        raise ValueError("employer guidance lacks typed freshness evidence") from exc
    _aware(observed, "employer guidance observation time")
    source_ids = document.get("source_ids")
    if (
        not isinstance(source_ids, list)
        or not source_ids
        or not all(isinstance(value, str) and value.strip() for value in source_ids)
    ):
        raise ValueError("employer guidance requires cited source IDs")
    deadline = observed.date() + timedelta(days=FRESHNESS_DAYS[kind])
    if observed.date() > as_of:
        raise ValueError("future employer evidence cannot guide preparation")
    if as_of > deadline:
        raise ValueError("employer guidance is stale; source refresh is required")
    return EmployerGuidanceAuthority(
        sentence_id=fact.sentence_id,
        approved_text_sha256=hashlib.sha256(
            fact.approved_source_text.encode()
        ).hexdigest(),
        employer_claim_id=fact.authority.employer_research_claim_id,
        employer_fact_sha256=fact.authority.employer_fact_sha256,
        intelligence_kind=kind.value,
        source_ids=tuple(source_ids),
        observed_at=observed.isoformat(),
        freshness_deadline=deadline.isoformat(),
    )


def _item(kind: str, prompt: str, authority_ids: tuple[str, ...]) -> PreparationItem:
    body = {
        "kind": kind,
        "prompt": prompt,
        "authority_ids": authority_ids,
    }
    return PreparationItem(_content_hash(body), kind, prompt, authority_ids)


def compile_interview_preparation_pack(
    contract: InterviewCommunicationContract,
    *,
    application_id: str,
    released_application_sha256: str,
    source: ApplicationSource,
    timeline: StatusTimeline,
    as_of: date,
    candidate_sentence_ids: Iterable[str],
    employer_sentence_ids: Iterable[str],
) -> InterviewPreparationPack:
    if contract != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT:
        raise ValueError("preparation requires the canonical contract")
    if not isinstance(source, ApplicationSource):
        raise TypeError("preparation requires an ApplicationSource")
    if not isinstance(timeline, StatusTimeline):
        raise TypeError("preparation requires a StatusTimeline")
    verify_application_source(source)
    timeline.verify()
    _required(application_id, "preparation application ID")
    _digest(released_application_sha256, "released application hash")
    if (
        timeline.application_id != application_id
        or timeline.job_key != source.job_key
    ):
        raise ValueError("preparation inputs identify a different application")
    if timeline.final_state not in INTERVIEW_STATES:
        raise ValueError("interview preparation requires an interview-stage timeline")
    fact_by_id = {row.sentence_id: row for row in source.facts}
    candidate_ids = tuple(candidate_sentence_ids)
    employer_ids = tuple(employer_sentence_ids)
    if (
        not candidate_ids
        or not employer_ids
        or len(candidate_ids) != len(set(candidate_ids))
        or len(employer_ids) != len(set(employer_ids))
    ):
        raise ValueError("preparation selections must be non-empty and unique")
    try:
        candidate = tuple(
            _candidate_authority(fact_by_id[value]) for value in candidate_ids
        )
        employer = tuple(
            _employer_authority(fact_by_id[value], as_of=as_of)
            for value in employer_ids
        )
    except KeyError as exc:
        raise ValueError("preparation selection cites an unknown fact") from exc
    candidate_authority_ids = tuple(row.sentence_id for row in candidate)
    employer_authority_ids = tuple(row.sentence_id for row in employer)
    items = (
        _item(
            "candidate_story",
            "Explain this approved evidence in its original terms.",
            candidate_authority_ids,
        ),
        _item(
            "likely_objection",
            "Prepare for questions about the supported requirement.",
            candidate_authority_ids,
        ),
        _item(
            "technical_drill",
            "Describe the decisions behind this approved evidence.",
            candidate_authority_ids,
        ),
        _item(
            "candidate_question",
            "Ask how this documented company fact affects the role.",
            employer_authority_ids,
        ),
    )
    body = {
        "schema_version": "jaa13.interview-preparation-pack.v1",
        "contract_sha256": contract.contract_sha256,
        "application_id": application_id,
        "job_key": source.job_key,
        "released_application_sha256": released_application_sha256,
        "application_source_id": source.source_id,
        "application_source_content_sha256": source.content_sha256,
        "timeline_id": timeline.timeline_id,
        "as_of": as_of.isoformat(),
        "candidate_authorities": tuple(row.document() for row in candidate),
        "employer_authorities": tuple(row.document() for row in employer),
        "items": tuple(row.document() for row in items),
        "source_refresh_authority": "withheld",
        "private_person_inference": False,
        "dependency_satisfied": False,
        "production_certification": "withheld",
        "certifies_slice": False,
    }
    return InterviewPreparationPack(
        contract_sha256=contract.contract_sha256,
        application_id=application_id,
        job_key=source.job_key,
        released_application_sha256=released_application_sha256,
        application_source_id=source.source_id,
        application_source_content_sha256=source.content_sha256,
        timeline_id=timeline.timeline_id,
        as_of=as_of.isoformat(),
        candidate_authorities=candidate,
        employer_authorities=employer,
        items=items,
        pack_id=_content_hash(body),
    )


@dataclass(frozen=True)
class LocalDebriefEvidence:
    contract_sha256: str
    application_id: str
    job_key: str
    timeline_id: str
    source_record_id: str
    source_sha256: str
    recorded_at: str
    evidence_id: str
    retention: str = "content_addressed_reference_only"
    assertion_status: str = "unverified_operator_statement"
    candidate_fact_authority: bool = False
    employer_fact_authority: bool = False
    dependency_satisfied: bool = False
    schema_version: str = "jaa13.local-debrief-evidence.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "timeline_id": self.timeline_id,
            "source_record_id": self.source_record_id,
            "source_sha256": self.source_sha256,
            "recorded_at": self.recorded_at,
            "retention": "content_addressed_reference_only",
            "assertion_status": "unverified_operator_statement",
            "candidate_fact_authority": False,
            "employer_fact_authority": False,
            "dependency_satisfied": False,
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "debrief contract hash"),
            (self.timeline_id, "debrief timeline ID"),
            (self.source_sha256, "debrief source hash"),
            (self.evidence_id, "debrief evidence ID"),
        ):
            _digest(value, label)
        _required(self.application_id, "debrief application ID")
        _required(self.job_key, "debrief job key")
        _required(self.source_record_id, "debrief source record ID")
        _aware(datetime.fromisoformat(self.recorded_at), "debrief recorded time")
        if (
            self.contract_sha256
            != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT.contract_sha256
        ):
            raise ValueError("debrief evidence binds a different contract")
        if (
            self.retention != "content_addressed_reference_only"
            or self.assertion_status != "unverified_operator_statement"
            or self.candidate_fact_authority is not False
            or self.employer_fact_authority is not False
            or self.dependency_satisfied is not False
        ):
            raise ValueError("local debrief cannot become fact authority")
        if self.schema_version != "jaa13.local-debrief-evidence.v1":
            raise ValueError("debrief evidence schema is unsupported")
        if self.evidence_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("debrief evidence differs from exact content")


def compile_local_debrief_evidence(
    contract: InterviewCommunicationContract,
    timeline: StatusTimeline,
    *,
    source_record_id: str,
    raw_debrief_bytes: bytes,
    recorded_at: datetime,
) -> LocalDebriefEvidence:
    if contract != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT:
        raise ValueError("debrief requires the canonical contract")
    if not isinstance(timeline, StatusTimeline):
        raise TypeError("debrief requires a StatusTimeline")
    timeline.verify()
    if timeline.final_state not in INTERVIEW_STATES:
        raise ValueError("debrief requires an interview-stage timeline")
    _required(source_record_id, "debrief source record ID")
    if not isinstance(raw_debrief_bytes, bytes) or not raw_debrief_bytes:
        raise ValueError("local debrief bytes are required")
    _aware(recorded_at, "debrief recorded time")
    body = {
        "schema_version": "jaa13.local-debrief-evidence.v1",
        "contract_sha256": contract.contract_sha256,
        "application_id": timeline.application_id,
        "job_key": timeline.job_key,
        "timeline_id": timeline.timeline_id,
        "source_record_id": source_record_id,
        "source_sha256": hashlib.sha256(raw_debrief_bytes).hexdigest(),
        "recorded_at": recorded_at.isoformat(),
        "retention": "content_addressed_reference_only",
        "assertion_status": "unverified_operator_statement",
        "candidate_fact_authority": False,
        "employer_fact_authority": False,
        "dependency_satisfied": False,
    }
    return LocalDebriefEvidence(
        contract_sha256=contract.contract_sha256,
        application_id=timeline.application_id,
        job_key=timeline.job_key,
        timeline_id=timeline.timeline_id,
        source_record_id=source_record_id,
        source_sha256=str(body["source_sha256"]),
        recorded_at=recorded_at.isoformat(),
        evidence_id=_content_hash(body),
    )


@dataclass(frozen=True)
class FollowUpDraftPlan:
    contract_sha256: str
    preparation_pack_id: str
    debrief_evidence_id: str
    application_id: str
    job_key: str
    factual_authority_ids: tuple[str, ...]
    connective_text: tuple[str, ...]
    draft_plan_id: str
    debrief_fact_authority: bool = False
    operator_confirmation_required: bool = True
    truth_release_authority: str = "withheld"
    connector_authority: str = "withheld"
    send_authority: str = "withheld"
    sent_count: int = 0
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa13.follow-up-draft-plan.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "factual_authority_ids",
            tuple(self.factual_authority_ids),
        )
        object.__setattr__(
            self,
            "connective_text",
            tuple(self.connective_text),
        )
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "preparation_pack_id": self.preparation_pack_id,
            "debrief_evidence_id": self.debrief_evidence_id,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "factual_authority_ids": self.factual_authority_ids,
            "connective_text": self.connective_text,
            "debrief_fact_authority": False,
            "operator_confirmation_required": True,
            "truth_release_authority": "withheld",
            "connector_authority": "withheld",
            "send_authority": "withheld",
            "sent_count": 0,
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["draft_plan_id"] = self.draft_plan_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "draft contract hash"),
            (self.preparation_pack_id, "preparation pack ID"),
            (self.debrief_evidence_id, "debrief evidence ID"),
            (self.draft_plan_id, "draft plan ID"),
        ):
            _digest(value, label)
        _required(self.application_id, "draft application ID")
        _required(self.job_key, "draft job key")
        if (
            self.contract_sha256
            != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT.contract_sha256
        ):
            raise ValueError("draft plan binds a different contract")
        if (
            not self.factual_authority_ids
            or len(self.factual_authority_ids)
            != len(set(self.factual_authority_ids))
            or not self.connective_text
        ):
            raise ValueError("draft plan requires unique facts and connective text")
        for value in self.connective_text:
            _natural_connective(value)
        if (
            self.debrief_fact_authority is not False
            or self.operator_confirmation_required is not True
            or self.truth_release_authority != "withheld"
            or self.connector_authority != "withheld"
            or self.send_authority != "withheld"
            or self.sent_count != 0
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError("draft plan cannot claim truth release or send")
        if self.schema_version != "jaa13.follow-up-draft-plan.v1":
            raise ValueError("draft plan schema is unsupported")
        if self.draft_plan_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("draft plan differs from exact content")


def compile_follow_up_draft_plan(
    contract: InterviewCommunicationContract,
    preparation: InterviewPreparationPack,
    debrief: LocalDebriefEvidence,
    *,
    factual_authority_ids: Iterable[str],
    connective_text: Iterable[str],
) -> FollowUpDraftPlan:
    if contract != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT:
        raise ValueError("draft plan requires the canonical contract")
    if not isinstance(preparation, InterviewPreparationPack):
        raise TypeError("draft plan requires an InterviewPreparationPack")
    if not isinstance(debrief, LocalDebriefEvidence):
        raise TypeError("draft plan requires LocalDebriefEvidence")
    preparation.verify()
    debrief.verify()
    if (
        preparation.contract_sha256 != contract.contract_sha256
        or debrief.contract_sha256 != contract.contract_sha256
        or preparation.application_id != debrief.application_id
        or preparation.job_key != debrief.job_key
        or preparation.timeline_id != debrief.timeline_id
    ):
        raise ValueError("draft plan inputs identify different authority")
    selected = tuple(factual_authority_ids)
    connectives = tuple(connective_text)
    allowed = {
        row.sentence_id for row in preparation.candidate_authorities
    } | {
        row.sentence_id for row in preparation.employer_authorities
    }
    if (
        not selected
        or len(selected) != len(set(selected))
        or not set(selected).issubset(allowed)
    ):
        raise ValueError("draft plan cites unknown or duplicate fact authority")
    if not connectives:
        raise ValueError("draft plan requires connective text")
    for value in connectives:
        _natural_connective(value)
    body = {
        "schema_version": "jaa13.follow-up-draft-plan.v1",
        "contract_sha256": contract.contract_sha256,
        "preparation_pack_id": preparation.pack_id,
        "debrief_evidence_id": debrief.evidence_id,
        "application_id": preparation.application_id,
        "job_key": preparation.job_key,
        "factual_authority_ids": selected,
        "connective_text": connectives,
        "debrief_fact_authority": False,
        "operator_confirmation_required": True,
        "truth_release_authority": "withheld",
        "connector_authority": "withheld",
        "send_authority": "withheld",
        "sent_count": 0,
        "dependency_satisfied": False,
        "production_certification": "withheld",
        "certifies_slice": False,
    }
    return FollowUpDraftPlan(
        contract_sha256=contract.contract_sha256,
        preparation_pack_id=preparation.pack_id,
        debrief_evidence_id=debrief.evidence_id,
        application_id=preparation.application_id,
        job_key=preparation.job_key,
        factual_authority_ids=selected,
        connective_text=connectives,
        draft_plan_id=_content_hash(body),
    )
