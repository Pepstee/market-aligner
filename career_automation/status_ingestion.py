"""Pure local-export status contract for dependency-withheld JAA-12 work.

The module hashes caller-supplied export bytes, classifies explicit status
codes, compiles deterministic timelines and creates non-sendable follow-up
intents. It has no mailbox, portal, browser, network or message capability.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Mapping

from career_automation.lifecycle import LEGAL_TRANSITIONS
from career_automation.models import PipelineState
from career_automation.official_ats_adapter import (
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
LOCAL_EXPORT_SOURCE_KINDS = (
    "local_message_export",
    "local_portal_export",
)
EXPLICIT_STATUS_CODES: Mapping[str, PipelineState] = MappingProxyType({
    "accepted": PipelineState.ACCEPTED,
    "application_received": PipelineState.RECEIPT_CONFIRMED,
    "declined_by_candidate": PipelineState.DECLINED,
    "expired": PipelineState.EXPIRED,
    "final_stage": PipelineState.FINAL_STAGE,
    "interview_requested": PipelineState.INTERVIEW,
    "offer": PipelineState.OFFER,
    "rejected_by_employer": PipelineState.REJECTED,
    "under_review": PipelineState.SCREENING,
    "withdrawn_by_candidate": PipelineState.WITHDRAWN,
})
POST_RECEIPT_STATES = (
    PipelineState.RECEIPT_CONFIRMED,
    PipelineState.SCREENING,
    PipelineState.INTERVIEW,
    PipelineState.FINAL_STAGE,
    PipelineState.OFFER,
    PipelineState.ACCEPTED,
    PipelineState.DECLINED,
    PipelineState.REJECTED,
    PipelineState.WITHDRAWN,
    PipelineState.EXPIRED,
)
TERMINAL_STATUS_STATES = (
    PipelineState.ACCEPTED,
    PipelineState.DECLINED,
    PipelineState.REJECTED,
    PipelineState.WITHDRAWN,
    PipelineState.EXPIRED,
)
CLASSIFIER_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa12.explicit-status-classifier.v2",
    "codes": tuple(
        (key, value.value)
        for key, value in EXPLICIT_STATUS_CODES.items()
    ),
    "raw_export_binding": "exact_utf8_token",
    "unknown_code": "abstain",
    "silence": "censored",
    "free_text_instruction_authority": False,
    "candidate_fact_authority": False,
})
FOLLOW_UP_POLICY_DOCUMENT: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa12.follow-up-policy.v1",
    "delay_seconds": 7 * 24 * 60 * 60,
    "eligible_states": (
        PipelineState.RECEIPT_CONFIRMED.value,
        PipelineState.SCREENING.value,
    ),
    "max_sends": 1,
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
        raise ValueError(
            f"{label} must not contain surrounding whitespace"
        )
    return value


def _aware(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{label} must include a timezone")
    return value


def _parsed_status_code(raw_export_bytes: bytes) -> str | None:
    try:
        text = raw_export_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None
    if text in EXPLICIT_STATUS_CODES:
        return text
    return None


def _transition_policy_document() -> dict[str, tuple[str, ...]]:
    return {
        state.value: tuple(
            sorted(target.value for target in LEGAL_TRANSITIONS[state])
        )
        for state in POST_RECEIPT_STATES
    }


CLASSIFIER_POLICY_SHA256 = _content_hash(dict(CLASSIFIER_POLICY))
POST_RECEIPT_TRANSITIONS_SHA256 = _content_hash(
    _transition_policy_document()
)
FOLLOW_UP_POLICY_SHA256 = _content_hash(dict(FOLLOW_UP_POLICY_DOCUMENT))


@dataclass(frozen=True)
class LocalExportStatusContract:
    upstream_fixture_contract_sha256: str
    classifier_policy_sha256: str
    transition_policy_sha256: str
    follow_up_policy_sha256: str
    connector_authority: str = "withheld"
    mailbox_access: str = "withheld"
    portal_access: str = "withheld"
    message_send_authority: str = "withheld"
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa12.local-export-status-contract.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (
                self.upstream_fixture_contract_sha256,
                "upstream fixture contract hash",
            ),
            (self.classifier_policy_sha256, "classifier policy hash"),
            (self.transition_policy_sha256, "transition policy hash"),
            (self.follow_up_policy_sha256, "follow-up policy hash"),
        ):
            _digest(value, label)
        expected = (
            FROZEN_FIXTURE_ADAPTER_CONTRACT.contract_sha256,
            CLASSIFIER_POLICY_SHA256,
            POST_RECEIPT_TRANSITIONS_SHA256,
            FOLLOW_UP_POLICY_SHA256,
        )
        actual = (
            self.upstream_fixture_contract_sha256,
            self.classifier_policy_sha256,
            self.transition_policy_sha256,
            self.follow_up_policy_sha256,
        )
        if actual != expected:
            raise ValueError(
                "local status contract differs from accepted policies"
            )
        if (
            self.connector_authority != "withheld"
            or self.mailbox_access != "withheld"
            or self.portal_access != "withheld"
            or self.message_send_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError(
                "local status contract cannot access or certify JAA-12"
            )
        if (
            self.schema_version
            != "jaa12.local-export-status-contract.v1"
        ):
            raise ValueError("local status contract schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "upstream_fixture_contract_sha256": (
                self.upstream_fixture_contract_sha256
            ),
            "classifier_policy_sha256": self.classifier_policy_sha256,
            "transition_policy_sha256": self.transition_policy_sha256,
            "follow_up_policy_sha256": self.follow_up_policy_sha256,
            "source_kinds": LOCAL_EXPORT_SOURCE_KINDS,
            "connector_authority": "withheld",
            "mailbox_access": "withheld",
            "portal_access": "withheld",
            "message_send_authority": "withheld",
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_LOCAL_EXPORT_STATUS_CONTRACT = LocalExportStatusContract(
    upstream_fixture_contract_sha256=(
        FROZEN_FIXTURE_ADAPTER_CONTRACT.contract_sha256
    ),
    classifier_policy_sha256=CLASSIFIER_POLICY_SHA256,
    transition_policy_sha256=POST_RECEIPT_TRANSITIONS_SHA256,
    follow_up_policy_sha256=FOLLOW_UP_POLICY_SHA256,
)


@dataclass(frozen=True)
class RawStatusEvidence:
    contract_sha256: str
    application_id: str
    job_key: str
    source_kind: str
    source_record_id: str
    source_sha256: str
    parsed_status_code: str | None
    observed_at: str
    evidence_id: str
    source_reference_kind: str = "content_addressed_local_export"
    untrusted_content: bool = True
    instruction_authority: bool = False
    candidate_fact_authority: bool = False
    schema_version: str = "jaa12.raw-status-evidence.v2"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "source_kind": self.source_kind,
            "source_record_id": self.source_record_id,
            "source_sha256": self.source_sha256,
            "parsed_status_code": self.parsed_status_code,
            "observed_at": self.observed_at,
            "source_reference_kind": "content_addressed_local_export",
            "untrusted_content": True,
            "instruction_authority": False,
            "candidate_fact_authority": False,
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        _digest(self.contract_sha256, "raw evidence contract hash")
        if (
            self.contract_sha256
            != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
        ):
            raise ValueError("raw evidence binds a different status contract")
        _digest(self.source_sha256, "raw export hash")
        for value, label in (
            (self.application_id, "raw evidence application ID"),
            (self.job_key, "raw evidence job key"),
            (self.source_record_id, "raw evidence source record ID"),
        ):
            _required(value, label)
        if self.source_kind not in LOCAL_EXPORT_SOURCE_KINDS:
            raise ValueError("raw status source must be a local export")
        if (
            self.parsed_status_code is not None
            and self.parsed_status_code not in EXPLICIT_STATUS_CODES
        ):
            raise ValueError(
                "raw status evidence has an unsupported parsed code"
            )
        if (
            self.parsed_status_code is not None
            and hashlib.sha256(
                self.parsed_status_code.encode()
            ).hexdigest()
            != self.source_sha256
        ):
            raise ValueError(
                "parsed status code differs from exact export bytes"
            )
        try:
            observed = datetime.fromisoformat(self.observed_at)
        except (TypeError, ValueError) as exc:
            raise ValueError("raw evidence time is invalid") from exc
        _aware(observed, "raw evidence time")
        if (
            self.source_reference_kind
            != "content_addressed_local_export"
            or self.untrusted_content is not True
            or self.instruction_authority is not False
            or self.candidate_fact_authority is not False
        ):
            raise ValueError(
                "raw status evidence cannot carry instruction authority"
            )
        if self.schema_version != "jaa12.raw-status-evidence.v2":
            raise ValueError("raw status evidence schema is unsupported")
        expected = _content_hash(self.document(include_identity=False))
        if self.evidence_id != expected:
            raise ValueError(
                "raw status evidence differs from its exact content"
            )


def compile_local_export_evidence(
    contract: LocalExportStatusContract,
    *,
    application_id: str,
    job_key: str,
    source_kind: str,
    source_record_id: str,
    raw_export_bytes: bytes,
    observed_at: datetime,
) -> RawStatusEvidence:
    if contract != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT:
        raise ValueError(
            "status evidence requires the canonical local contract"
        )
    if not isinstance(raw_export_bytes, bytes) or not raw_export_bytes:
        raise ValueError("raw local export bytes are required")
    _aware(observed_at, "raw export observation time")
    parsed_status_code = _parsed_status_code(raw_export_bytes)
    body = {
        "schema_version": "jaa12.raw-status-evidence.v2",
        "contract_sha256": contract.contract_sha256,
        "application_id": application_id,
        "job_key": job_key,
        "source_kind": source_kind,
        "source_record_id": source_record_id,
        "source_sha256": hashlib.sha256(raw_export_bytes).hexdigest(),
        "parsed_status_code": parsed_status_code,
        "observed_at": observed_at.isoformat(),
        "source_reference_kind": "content_addressed_local_export",
        "untrusted_content": True,
        "instruction_authority": False,
        "candidate_fact_authority": False,
    }
    return RawStatusEvidence(
        contract_sha256=contract.contract_sha256,
        application_id=application_id,
        job_key=job_key,
        source_kind=source_kind,
        source_record_id=source_record_id,
        source_sha256=str(body["source_sha256"]),
        parsed_status_code=parsed_status_code,
        observed_at=observed_at.isoformat(),
        evidence_id=_content_hash(body),
    )


@dataclass(frozen=True)
class StatusObservation:
    raw_evidence: RawStatusEvidence
    application_id: str
    job_key: str
    raw_evidence_id: str
    source_sha256: str
    source_record_id: str
    observed_at: str
    explicit_status_code: str
    classified_state: PipelineState | None
    confidence_bp: int
    abstained: bool
    classifier_policy_sha256: str
    observation_id: str
    instruction_authority: bool = False
    candidate_fact_authority: bool = False
    schema_version: str = "jaa12.status-observation.v2"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "raw_evidence": self.raw_evidence.document(),
            "application_id": self.application_id,
            "job_key": self.job_key,
            "raw_evidence_id": self.raw_evidence_id,
            "source_sha256": self.source_sha256,
            "source_record_id": self.source_record_id,
            "observed_at": self.observed_at,
            "explicit_status_code": self.explicit_status_code,
            "classified_state": (
                None
                if self.classified_state is None
                else self.classified_state.value
            ),
            "confidence_bp": self.confidence_bp,
            "abstained": self.abstained,
            "classifier_policy_sha256": self.classifier_policy_sha256,
            "instruction_authority": False,
            "candidate_fact_authority": False,
        }
        if include_identity:
            result["observation_id"] = self.observation_id
        return result

    def verify(self) -> None:
        if not isinstance(self.raw_evidence, RawStatusEvidence):
            raise TypeError(
                "status observation requires typed raw evidence"
            )
        self.raw_evidence.verify()
        for value, label in (
            (self.raw_evidence_id, "status raw evidence identity"),
            (self.source_sha256, "status source hash"),
            (self.classifier_policy_sha256, "status classifier hash"),
        ):
            _digest(value, label)
        _required(self.application_id, "status application ID")
        _required(self.job_key, "status job key")
        _required(self.source_record_id, "status source record ID")
        if (
            self.raw_evidence.evidence_id != self.raw_evidence_id
            or self.raw_evidence.application_id != self.application_id
            or self.raw_evidence.job_key != self.job_key
            or self.raw_evidence.source_sha256 != self.source_sha256
            or self.raw_evidence.source_record_id
            != self.source_record_id
            or self.raw_evidence.observed_at != self.observed_at
        ):
            raise ValueError(
                "status observation differs from its typed raw evidence"
            )
        if not isinstance(self.explicit_status_code, str):
            raise ValueError("explicit status code must be text")
        try:
            observed = datetime.fromisoformat(self.observed_at)
        except (TypeError, ValueError) as exc:
            raise ValueError("status observation time is invalid") from exc
        _aware(observed, "status observation time")
        expected_state = EXPLICIT_STATUS_CODES.get(
            self.explicit_status_code
        )
        if (
            expected_state is not None
            and self.raw_evidence.parsed_status_code
            != self.explicit_status_code
        ):
            raise ValueError(
                "known status code differs from parsed export bytes"
            )
        if expected_state is None:
            if (
                self.classified_state is not None
                or self.confidence_bp != 0
                or self.abstained is not True
            ):
                raise ValueError("unknown status code must abstain")
        elif (
            self.classified_state is not expected_state
            or self.confidence_bp != 10_000
            or self.abstained is not False
        ):
            raise ValueError(
                "explicit status observation differs from policy"
            )
        if self.classifier_policy_sha256 != CLASSIFIER_POLICY_SHA256:
            raise ValueError(
                "status observation binds a different classifier"
            )
        if (
            self.instruction_authority is not False
            or self.candidate_fact_authority is not False
        ):
            raise ValueError(
                "status observation cannot alter instructions or facts"
            )
        if self.schema_version != "jaa12.status-observation.v2":
            raise ValueError("status observation schema is unsupported")
        expected = _content_hash(self.document(include_identity=False))
        if self.observation_id != expected:
            raise ValueError(
                "status observation differs from its exact content"
            )


def classify_status_evidence(
    contract: LocalExportStatusContract,
    evidence: RawStatusEvidence,
    *,
    explicit_status_code: str,
) -> StatusObservation:
    if contract != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT:
        raise ValueError(
            "status classification requires the canonical contract"
        )
    if not isinstance(evidence, RawStatusEvidence):
        raise TypeError(
            "status classification requires RawStatusEvidence"
        )
    evidence.verify()
    if evidence.contract_sha256 != contract.contract_sha256:
        raise ValueError("raw evidence binds a different status contract")
    if not isinstance(explicit_status_code, str):
        raise ValueError("explicit status code must be text")
    state = EXPLICIT_STATUS_CODES.get(explicit_status_code)
    if (
        state is not None
        and evidence.parsed_status_code != explicit_status_code
    ):
        raise ValueError(
            "known status code differs from parsed export bytes"
        )
    body = {
        "schema_version": "jaa12.status-observation.v2",
        "raw_evidence": evidence.document(),
        "application_id": evidence.application_id,
        "job_key": evidence.job_key,
        "raw_evidence_id": evidence.evidence_id,
        "source_sha256": evidence.source_sha256,
        "source_record_id": evidence.source_record_id,
        "observed_at": evidence.observed_at,
        "explicit_status_code": explicit_status_code,
        "classified_state": None if state is None else state.value,
        "confidence_bp": 0 if state is None else 10_000,
        "abstained": state is None,
        "classifier_policy_sha256": CLASSIFIER_POLICY_SHA256,
        "instruction_authority": False,
        "candidate_fact_authority": False,
    }
    return StatusObservation(
        raw_evidence=evidence,
        application_id=evidence.application_id,
        job_key=evidence.job_key,
        raw_evidence_id=evidence.evidence_id,
        source_sha256=evidence.source_sha256,
        source_record_id=evidence.source_record_id,
        observed_at=evidence.observed_at,
        explicit_status_code=explicit_status_code,
        classified_state=state,
        confidence_bp=0 if state is None else 10_000,
        abstained=state is None,
        classifier_policy_sha256=CLASSIFIER_POLICY_SHA256,
        observation_id=_content_hash(body),
    )


@dataclass(frozen=True)
class CensoredSilence:
    application_id: str
    job_key: str
    as_of: str
    reason: str = "no_source_evidence"
    classified_state: PipelineState | None = None
    rejection_inferred: bool = False
    schema_version: str = "jaa12.censored-silence.v1"

    def __post_init__(self) -> None:
        _required(self.application_id, "censored application ID")
        _required(self.job_key, "censored job key")
        try:
            as_of = datetime.fromisoformat(self.as_of)
        except (TypeError, ValueError) as exc:
            raise ValueError("censor time is invalid") from exc
        _aware(as_of, "censor time")
        if (
            self.reason != "no_source_evidence"
            or self.classified_state is not None
            or self.rejection_inferred is not False
        ):
            raise ValueError("silence must remain censored without a state")
        if self.schema_version != "jaa12.censored-silence.v1":
            raise ValueError("censored silence schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "as_of": self.as_of,
            "reason": "no_source_evidence",
            "classified_state": None,
            "rejection_inferred": False,
        }


def censor_status_silence(
    *,
    application_id: str,
    job_key: str,
    as_of: datetime,
) -> CensoredSilence:
    _aware(as_of, "censor time")
    return CensoredSilence(
        application_id=application_id,
        job_key=job_key,
        as_of=as_of.isoformat(),
    )


@dataclass(frozen=True)
class StatusTimeline:
    contract_sha256: str
    application_id: str
    job_key: str
    baseline_state: PipelineState
    observations: tuple[StatusObservation, ...]
    transitions: tuple[tuple[str, str], ...]
    censored_silence: tuple[CensoredSilence, ...]
    final_state: PipelineState
    timeline_id: str
    dependency_satisfied: bool = False
    connector_evidence: str = "absent"
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa12.status-timeline.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "observations",
            tuple(self.observations),
        )
        object.__setattr__(
            self,
            "transitions",
            tuple(tuple(row) for row in self.transitions),
        )
        object.__setattr__(
            self,
            "censored_silence",
            tuple(self.censored_silence),
        )
        self.verify()

    @property
    def observation_ids(self) -> tuple[str, ...]:
        return tuple(row.observation_id for row in self.observations)

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(row.raw_evidence_id for row in self.observations)

    @property
    def source_record_ids(self) -> tuple[str, ...]:
        return tuple(row.source_record_id for row in self.observations)

    @property
    def observed_at(self) -> tuple[str, ...]:
        return tuple(row.observed_at for row in self.observations)

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "baseline_state": self.baseline_state.value,
            "observations": tuple(
                row.document() for row in self.observations
            ),
            "transitions": self.transitions,
            "censored_silence": tuple(
                row.document() for row in self.censored_silence
            ),
            "final_state": self.final_state.value,
            "dependency_satisfied": False,
            "connector_evidence": "absent",
            "production_certification": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["timeline_id"] = self.timeline_id
        return result

    def verify(self) -> None:
        _digest(self.contract_sha256, "timeline contract hash")
        if (
            self.contract_sha256
            != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
        ):
            raise ValueError("timeline binds a different status contract")
        if not all(
            isinstance(row, StatusObservation)
            for row in self.observations
        ):
            raise TypeError("status timeline observations must be typed")
        for row in self.observations:
            row.verify()
            if (
                row.application_id != self.application_id
                or row.job_key != self.job_key
            ):
                raise ValueError(
                    "status observation belongs to a different application"
                )
        for value in (*self.observation_ids, *self.evidence_ids):
            _digest(value, "timeline evidence identity")
        _required(self.application_id, "timeline application ID")
        _required(self.job_key, "timeline job key")
        if (
            len(self.observation_ids) != len(set(self.observation_ids))
            or len(self.evidence_ids) != len(set(self.evidence_ids))
            or len(self.source_record_ids)
            != len(set(self.source_record_ids))
            or len(self.observation_ids) != len(self.evidence_ids)
            or len(self.observation_ids) != len(self.source_record_ids)
            or len(self.observation_ids) != len(self.observed_at)
        ):
            raise ValueError("status timeline evidence must be deduplicated")
        parsed_times: list[datetime] = []
        for value in self.observed_at:
            try:
                parsed = datetime.fromisoformat(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "status timeline observation time is invalid"
                ) from exc
            parsed_times.append(
                _aware(parsed, "status timeline observation time")
            )
        if len(parsed_times) != len(set(parsed_times)):
            raise ValueError(
                "status timeline observation times must be unique and ordered"
            )
        if tuple(sorted(parsed_times)) != tuple(parsed_times):
            raise ValueError(
                "status timeline observation times must be ordered"
            )
        if self.baseline_state is not PipelineState.RECEIPT_CONFIRMED:
            raise ValueError(
                "local status timeline must start from confirmed receipt"
            )
        if self.final_state not in POST_RECEIPT_STATES:
            raise ValueError("status timeline final state is unsupported")
        if not all(
            isinstance(row, CensoredSilence)
            for row in self.censored_silence
        ):
            raise TypeError(
                "status timeline censor records must be typed"
            )
        if any(
            row.application_id != self.application_id
            or row.job_key != self.job_key
            for row in self.censored_silence
        ):
            raise ValueError(
                "status timeline censor belongs to a different application"
            )
        current = self.baseline_state
        expected_transitions: list[tuple[str, str]] = []
        for row in self.observations:
            target = row.classified_state
            if target is None or target is current:
                continue
            if target not in LEGAL_TRANSITIONS[current]:
                raise ValueError(
                    "status timeline transition is illegal or out of order"
                )
            expected_transitions.append((current.value, target.value))
            current = target
        if tuple(expected_transitions) != self.transitions:
            raise ValueError(
                "status timeline transitions differ from observations"
            )
        if current is not self.final_state:
            raise ValueError(
                "status timeline final state differs from observations"
            )
        if (
            self.dependency_satisfied is not False
            or self.connector_evidence != "absent"
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError(
                "local status timeline cannot satisfy or certify JAA-12"
            )
        if self.schema_version != "jaa12.status-timeline.v1":
            raise ValueError("status timeline schema is unsupported")
        expected = _content_hash(self.document(include_identity=False))
        if self.timeline_id != expected:
            raise ValueError("status timeline differs from exact content")


def compile_status_timeline(
    contract: LocalExportStatusContract,
    *,
    application_id: str,
    job_key: str,
    observations: tuple[StatusObservation, ...],
    censored_silence: tuple[CensoredSilence, ...] = (),
) -> StatusTimeline:
    if contract != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT:
        raise ValueError("status timeline requires the canonical contract")
    if not all(
        isinstance(row, StatusObservation) for row in observations
    ):
        raise TypeError("status timeline requires typed observations")
    if not all(
        isinstance(row, CensoredSilence) for row in censored_silence
    ):
        raise TypeError("status timeline requires typed censor records")
    if (
        len({row.observation_id for row in observations})
        != len(observations)
        or len({row.raw_evidence_id for row in observations})
        != len(observations)
    ):
        raise ValueError("status observations must be deduplicated")
    observation_times = tuple(
        datetime.fromisoformat(row.observed_at) for row in observations
    )
    if len(observation_times) != len(set(observation_times)):
        raise ValueError(
            "status observations must be chronologically unique and ordered"
        )
    if tuple(sorted(observation_times)) != observation_times:
        raise ValueError("status observations must be chronologically ordered")
    for row in observations:
        row.verify()
        if row.application_id != application_id or row.job_key != job_key:
            raise ValueError(
                "status observation belongs to a different application"
            )
    censor_times = tuple(
        datetime.fromisoformat(row.as_of) for row in censored_silence
    )
    if tuple(sorted(censor_times)) != censor_times:
        raise ValueError("censored status records must be ordered")
    for row in censored_silence:
        if row.application_id != application_id or row.job_key != job_key:
            raise ValueError(
                "censored status belongs to a different application"
            )

    current = PipelineState.RECEIPT_CONFIRMED
    transitions: list[tuple[str, str]] = []
    for row in observations:
        target = row.classified_state
        if target is None or target is current:
            continue
        if target not in LEGAL_TRANSITIONS[current]:
            raise ValueError(
                "status observation is illegal or out of lifecycle order"
            )
        transitions.append((current.value, target.value))
        current = target
    body = {
        "schema_version": "jaa12.status-timeline.v1",
        "contract_sha256": contract.contract_sha256,
        "application_id": application_id,
        "job_key": job_key,
        "baseline_state": PipelineState.RECEIPT_CONFIRMED.value,
        "observations": tuple(row.document() for row in observations),
        "transitions": tuple(transitions),
        "censored_silence": tuple(
            row.document() for row in censored_silence
        ),
        "final_state": current.value,
        "dependency_satisfied": False,
        "connector_evidence": "absent",
        "production_certification": "withheld",
        "certifies_slice": False,
    }
    return StatusTimeline(
        contract_sha256=contract.contract_sha256,
        application_id=application_id,
        job_key=job_key,
        baseline_state=PipelineState.RECEIPT_CONFIRMED,
        observations=observations,
        transitions=tuple(body["transitions"]),
        censored_silence=censored_silence,
        final_state=current,
        timeline_id=_content_hash(body),
    )


@dataclass(frozen=True)
class FollowUpIntent:
    contract_sha256: str
    timeline_id: str
    application_id: str
    job_key: str
    released_application_sha256: str
    draft_sha256: str
    last_observed_at: str
    due_at: str
    policy_sha256: str
    idempotency_key: str
    max_sends: int = 1
    sent_count: int = 0
    connector_authority: str = "withheld"
    send_authority: str = "withheld"
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa12.follow-up-intent.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (self.contract_sha256, "follow-up contract hash"),
            (self.timeline_id, "follow-up timeline identity"),
            (
                self.released_application_sha256,
                "released application hash",
            ),
            (self.draft_sha256, "follow-up draft hash"),
            (self.policy_sha256, "follow-up policy hash"),
        ):
            _digest(value, label)
        _required(self.application_id, "follow-up application ID")
        _required(self.job_key, "follow-up job key")
        try:
            due_at = datetime.fromisoformat(self.due_at)
            last_observed_at = datetime.fromisoformat(
                self.last_observed_at
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("follow-up schedule time is invalid") from exc
        _aware(due_at, "follow-up due time")
        _aware(last_observed_at, "follow-up last observation time")
        expected_due_at = last_observed_at + timedelta(
            seconds=int(FOLLOW_UP_POLICY_DOCUMENT["delay_seconds"])
        )
        if due_at != expected_due_at:
            raise ValueError(
                "follow-up due time differs from the bound observation"
            )
        expected_key = (
            f"follow-up:{self.application_id}:"
            f"{self.timeline_id}:{self.policy_sha256}"
        )
        if self.idempotency_key != expected_key:
            raise ValueError("follow-up idempotency key is inconsistent")
        if (
            self.max_sends != 1
            or self.sent_count != 0
            or self.connector_authority != "withheld"
            or self.send_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError(
                "local follow-up intent cannot send or certify a message"
            )
        if self.policy_sha256 != FOLLOW_UP_POLICY_SHA256:
            raise ValueError("follow-up intent binds a different policy")
        if self.schema_version != "jaa12.follow-up-intent.v1":
            raise ValueError("follow-up intent schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "timeline_id": self.timeline_id,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "released_application_sha256": (
                self.released_application_sha256
            ),
            "draft_sha256": self.draft_sha256,
            "last_observed_at": self.last_observed_at,
            "due_at": self.due_at,
            "policy_sha256": self.policy_sha256,
            "idempotency_key": self.idempotency_key,
            "max_sends": 1,
            "sent_count": 0,
            "connector_authority": "withheld",
            "send_authority": "withheld",
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }

    @property
    def intent_sha256(self) -> str:
        return _content_hash(self.document())


def compile_follow_up_intent(
    contract: LocalExportStatusContract,
    timeline: StatusTimeline,
    *,
    released_application_sha256: str,
    draft_sha256: str,
) -> FollowUpIntent:
    if contract != FROZEN_LOCAL_EXPORT_STATUS_CONTRACT:
        raise ValueError("follow-up intent requires the canonical contract")
    if not isinstance(timeline, StatusTimeline):
        raise TypeError("follow-up intent requires a StatusTimeline")
    timeline.verify()
    if timeline.contract_sha256 != contract.contract_sha256:
        raise ValueError("follow-up timeline binds a different contract")
    if timeline.final_state not in {
        PipelineState.RECEIPT_CONFIRMED,
        PipelineState.SCREENING,
    }:
        raise ValueError(
            "follow-up policy does not permit the current application state"
        )
    _digest(
        released_application_sha256,
        "released application hash",
    )
    _digest(draft_sha256, "follow-up draft hash")
    if not timeline.observed_at:
        raise ValueError(
            "follow-up requires source-backed status evidence"
        )
    last_observed_at = datetime.fromisoformat(timeline.observed_at[-1])
    due_at = last_observed_at + timedelta(
        seconds=int(FOLLOW_UP_POLICY_DOCUMENT["delay_seconds"])
    )
    key = (
        f"follow-up:{timeline.application_id}:"
        f"{timeline.timeline_id}:{FOLLOW_UP_POLICY_SHA256}"
    )
    return FollowUpIntent(
        contract_sha256=contract.contract_sha256,
        timeline_id=timeline.timeline_id,
        application_id=timeline.application_id,
        job_key=timeline.job_key,
        released_application_sha256=released_application_sha256,
        draft_sha256=draft_sha256,
        last_observed_at=last_observed_at.isoformat(),
        due_at=due_at.isoformat(),
        policy_sha256=FOLLOW_UP_POLICY_SHA256,
        idempotency_key=key,
    )
