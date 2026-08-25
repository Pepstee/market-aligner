"""Declarative, resumable browser-workflow control plane.

This module deliberately does not drive a browser.  It stores versioned recorded
workflows, leases them to an external executor, validates ordered selector reports,
and checkpoints every completed action.  Form values are references to approved
evidence or placeholders; materialised answers never belong in a workflow spec.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Collection, Iterator, Mapping, Sequence

from career_automation.canary_forensic_evidence import (
    CanaryForensicEvidenceError,
    verify_exact_canary_evidence,
)


_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _canonical_json(value: Any) -> str:
    """Return the single canonical representation used for hashes and storage."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_sha256(value: str | None, field_name: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{field_name} must be lowercase SHA-256")


def _require_text(value: str, field_name: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{field_name} must be non-empty UTF-8 text within {maximum} bytes")
    if "\x00" in value:
        raise ValueError(f"{field_name} cannot contain NUL")


def fixture_submit_event_sha256(
    *,
    run_id: str,
    workflow_sha256: str,
    step_id: str,
    release_manifest_sha256: str,
    receipt_id: str,
    receipt_payload_sha256: str,
    screenshot_sha256: str,
    field_map_sha256: str,
) -> str:
    """Bind one local fixture submit event to its complete durable context."""
    return _sha256(
        _canonical_json(
            {
                "contract": "jaa09.fixture-submit-event.v1",
                "run_id": run_id,
                "workflow_hash": workflow_sha256,
                "step_id": step_id,
                "release_manifest_sha256": release_manifest_sha256,
                "receipt_id": receipt_id,
                "receipt_payload_sha256": receipt_payload_sha256,
                "screenshot_sha256": screenshot_sha256,
                "field_map_sha256": field_map_sha256,
            }
        )
    )


class WorkflowError(RuntimeError):
    """Base error for workflow validation or execution state violations."""


class LeaseError(WorkflowError):
    """The caller does not own a live lease for the run."""


class ApprovalRequiredError(WorkflowError):
    """A referenced value has not been explicitly approved."""


class ReleaseGateError(WorkflowError):
    """A final submit action has not passed its release gate."""


class IdempotencyConflictError(WorkflowError):
    """A completed immutable operation was repeated with different content."""


class ActionKind(str, Enum):
    NAVIGATE = "navigate"
    CLICK = "click"
    FILL = "fill"
    SELECT_OPTION = "select_option"
    UPLOAD = "upload"
    ASSERT = "assert"
    EXTRACT = "extract"
    SUBMIT = "submit"


class SelectorStrategy(str, Enum):
    ROLE = "role"
    LABEL = "label"
    TEST_ID = "test_id"
    CSS = "css"
    XPATH = "xpath"
    TEXT = "text"


class SelectorOutcome(str, Enum):
    MATCHED = "matched"
    NOT_FOUND = "not_found"
    NOT_VISIBLE = "not_visible"
    AMBIGUOUS = "ambiguous"


class ValueSource(str, Enum):
    EVIDENCE = "evidence"
    PLACEHOLDER = "placeholder"


class CanaryStage(str, Enum):
    OFFICIAL_ROUTE = "official_route"
    ELIGIBILITY = "eligibility"
    ATS_INVENTORY = "ats_inventory"
    APPLICATION_PACKAGE = "application_package"
    PREFLIGHT_REVIEW = "preflight_review"
    RELEASE = "release"
    SUBMIT = "submit"
    PROVIDER_CONFIRMATION = "provider_confirmation"
    POST_SUBMISSION_REVIEW = "post_submission_review"


class CanaryOutcomeKind(str, Enum):
    PROVIDER_CONFIRMED_SUBMISSION = "provider_confirmed_submission"
    VACANCY_CLOSED = "vacancy_closed"
    INELIGIBLE = "ineligible"
    UNSUPPORTED_ATS = "unsupported_ats"
    SCHEMA_DRIFT = "schema_drift"
    BOT_CHALLENGE = "bot_challenge"
    SPAM_FILTER_REFUSAL = "spam_filter_refusal"
    AUTHENTICATION_REQUIRED = "authentication_required"
    OPERATOR_ANSWER_REQUIRED = "operator_answer_required"
    TECHNICAL_FAILURE = "technical_failure"
    OUTCOME_UNKNOWN = "outcome_unknown"
    CANCELLED = "cancelled"


class QualityIssueSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class QualityReviewDisposition(str, Enum):
    ACCEPTED = "accepted"
    NEEDS_REMEDIATION = "needs_remediation"
    NOT_SUBMITTED = "not_submitted"


@dataclass(frozen=True)
class SelectorCandidate:
    """One selector candidate. Position in ``SelectorPlan`` is significant."""

    strategy: SelectorStrategy
    query: str

    def __post_init__(self) -> None:
        if not isinstance(self.strategy, SelectorStrategy):
            raise TypeError("selector strategy must be a SelectorStrategy")
        if not isinstance(self.query, str) or not self.query.strip():
            raise ValueError("selector query must be non-empty")

    def to_dict(self) -> dict[str, str]:
        return {"strategy": self.strategy.value, "query": self.query}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SelectorCandidate":
        return cls(SelectorStrategy(str(value["strategy"])), str(value["query"]))


@dataclass(frozen=True)
class SelectorAttempt:
    index: int
    candidate: SelectorCandidate
    outcome: SelectorOutcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "candidate": self.candidate.to_dict(),
            "outcome": self.outcome.value,
        }


@dataclass(frozen=True)
class SelectorRecoveryReport:
    """Deterministically derived report of trying candidates in declared order."""

    plan_hash: str
    attempts: tuple[SelectorAttempt, ...]
    selected_index: int | None
    candidate_count: int

    @property
    def succeeded(self) -> bool:
        return self.selected_index is not None

    @property
    def recovered(self) -> bool:
        return self.selected_index is not None and self.selected_index > 0

    @property
    def exhausted(self) -> bool:
        return not self.succeeded and len(self.attempts) == self.candidate_count

    @property
    def failure_codes(self) -> tuple[str, ...]:
        return tuple(attempt.outcome.value for attempt in self.attempts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_hash": self.plan_hash,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "selected_index": self.selected_index,
            "candidate_count": self.candidate_count,
            "succeeded": self.succeeded,
            "recovered": self.recovered,
            "exhausted": self.exhausted,
            "failure_codes": list(self.failure_codes),
        }


@dataclass(frozen=True)
class SelectorPlan:
    """An ordered primary selector followed by deterministic recovery candidates."""

    candidates: tuple[SelectorCandidate, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidates", tuple(self.candidates))
        if not self.candidates:
            raise ValueError("selector plan requires at least one candidate")
        if not all(isinstance(candidate, SelectorCandidate) for candidate in self.candidates):
            raise TypeError("selector candidates must be SelectorCandidate instances")
        canonical = [_canonical_json(candidate.to_dict()) for candidate in self.candidates]
        if len(canonical) != len(set(canonical)):
            raise ValueError("selector plan cannot contain duplicate candidates")

    @property
    def content_hash(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))

    def to_dict(self) -> dict[str, Any]:
        return {"candidates": [candidate.to_dict() for candidate in self.candidates]}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SelectorPlan":
        return cls(tuple(SelectorCandidate.from_dict(item) for item in value["candidates"]))

    def assess(self, outcomes: Sequence[SelectorOutcome]) -> SelectorRecoveryReport:
        """Associate outcomes with candidates, rejecting out-of-order reporting."""
        attempted = tuple(outcomes)
        if not attempted:
            raise ValueError("selector report requires at least one attempt")
        if len(attempted) > len(self.candidates):
            raise ValueError("selector report has more outcomes than candidates")
        if not all(isinstance(outcome, SelectorOutcome) for outcome in attempted):
            raise TypeError("selector outcomes must be SelectorOutcome instances")
        matched = [index for index, outcome in enumerate(attempted) if outcome is SelectorOutcome.MATCHED]
        if len(matched) > 1:
            raise ValueError("selector report cannot contain multiple matches")
        if matched and matched[0] != len(attempted) - 1:
            raise ValueError("selector attempts must stop at the first match")
        attempts = tuple(
            SelectorAttempt(index, self.candidates[index], outcome)
            for index, outcome in enumerate(attempted)
        )
        return SelectorRecoveryReport(
            plan_hash=self.content_hash,
            attempts=attempts,
            selected_index=matched[0] if matched else None,
            candidate_count=len(self.candidates),
        )


@dataclass(frozen=True)
class ValueReference:
    """Identifier of a value in the external, verified evidence ledger."""

    source: ValueSource
    reference_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, ValueSource):
            raise TypeError("value source must be a ValueSource")
        if not isinstance(self.reference_id, str) or not _IDENTIFIER.fullmatch(self.reference_id):
            raise ValueError("reference_id must be an identifier, never a materialised answer")

    @property
    def key(self) -> str:
        return f"{self.source.value}:{self.reference_id}"

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source.value, "reference_id": self.reference_id}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ValueReference":
        return cls(ValueSource(str(value["source"])), str(value["reference_id"]))


@dataclass(frozen=True)
class ApprovedValue:
    """Approval proof supplied at dispatch; it contains no materialised value."""

    reference: ValueReference
    authorization_reference: str

    def __post_init__(self) -> None:
        if not isinstance(self.reference, ValueReference):
            raise TypeError("approved value must wrap a ValueReference")
        if not isinstance(self.authorization_reference, str) or not _IDENTIFIER.fullmatch(
            self.authorization_reference
        ):
            raise ValueError("authorization_reference must identify a durable approval")


@dataclass(frozen=True)
class BrowserAction:
    """A declarative instruction for an external browser executor."""

    step_id: str
    kind: ActionKind
    selectors: SelectorPlan | None = None
    value_reference: ValueReference | None = None
    target_url: str | None = None
    required_output_keys: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "required_output_keys", tuple(self.required_output_keys))
        if not isinstance(self.step_id, str) or not _IDENTIFIER.fullmatch(self.step_id):
            raise ValueError("step_id must be a stable identifier")
        if not isinstance(self.kind, ActionKind):
            raise TypeError("action kind must be an ActionKind")
        if self.selectors is not None and not isinstance(self.selectors, SelectorPlan):
            raise TypeError("selectors must be a SelectorPlan")
        if self.value_reference is not None and not isinstance(self.value_reference, ValueReference):
            raise TypeError("form values must be ValueReference objects, never raw values")
        if len(set(self.required_output_keys)) != len(self.required_output_keys):
            raise ValueError("required output keys must be unique")
        if any(not _IDENTIFIER.fullmatch(key) for key in self.required_output_keys):
            raise ValueError("required output keys must be stable identifiers")

        selector_kinds = {
            ActionKind.CLICK,
            ActionKind.FILL,
            ActionKind.SELECT_OPTION,
            ActionKind.UPLOAD,
            ActionKind.ASSERT,
            ActionKind.EXTRACT,
            ActionKind.SUBMIT,
        }
        value_kinds = {ActionKind.FILL, ActionKind.SELECT_OPTION, ActionKind.UPLOAD}
        if self.kind in selector_kinds and self.selectors is None:
            raise ValueError(f"{self.kind.value} action requires a selector plan")
        if self.kind is ActionKind.NAVIGATE:
            if not isinstance(self.target_url, str) or not self.target_url.strip():
                raise ValueError("navigate action requires target_url")
        elif self.target_url is not None:
            raise ValueError("target_url is only valid for navigate actions")
        if self.kind in value_kinds and self.value_reference is None:
            raise ValueError(f"{self.kind.value} action requires a value reference")
        if self.kind not in value_kinds and self.value_reference is not None:
            raise ValueError("only form-value actions may have a value reference")

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "kind": self.kind.value,
            "selectors": self.selectors.to_dict() if self.selectors else None,
            "value_reference": self.value_reference.to_dict() if self.value_reference else None,
            "target_url": self.target_url,
            "required_output_keys": list(self.required_output_keys),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrowserAction":
        selectors = value.get("selectors")
        reference = value.get("value_reference")
        return cls(
            step_id=str(value["step_id"]),
            kind=ActionKind(str(value["kind"])),
            selectors=SelectorPlan.from_dict(selectors) if selectors else None,
            value_reference=ValueReference.from_dict(reference) if reference else None,
            target_url=value.get("target_url"),
            required_output_keys=tuple(value.get("required_output_keys", ())),
        )


@dataclass(frozen=True)
class BrowserWorkflow:
    """Immutable workflow whose content hash is its executable version."""

    name: str
    actions: tuple[BrowserAction, ...]
    schema_version: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "actions", tuple(self.actions))
        if not isinstance(self.name, str) or not _IDENTIFIER.fullmatch(self.name):
            raise ValueError("workflow name must be a stable identifier")
        if self.schema_version != 1:
            raise ValueError("unsupported browser workflow schema version")
        if not self.actions or not all(isinstance(action, BrowserAction) for action in self.actions):
            raise ValueError("workflow requires typed browser actions")
        step_ids = [action.step_id for action in self.actions]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("workflow step IDs must be unique")
        submit_indexes = [index for index, action in enumerate(self.actions) if action.kind is ActionKind.SUBMIT]
        if submit_indexes and submit_indexes != [len(self.actions) - 1]:
            raise ValueError("a workflow may have one submit action and it must be final")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "actions": [action.to_dict() for action in self.actions],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrowserWorkflow":
        return cls(
            name=str(value["name"]),
            actions=tuple(BrowserAction.from_dict(item) for item in value["actions"]),
            schema_version=int(value["schema_version"]),
        )

    @property
    def canonical_json(self) -> str:
        return _canonical_json(self.to_dict())

    @property
    def content_hash(self) -> str:
        return _sha256(self.canonical_json)

    @property
    def version(self) -> str:
        return f"bw{self.schema_version}-{self.content_hash[:16]}"


@dataclass(frozen=True)
class LeasedRun:
    run_id: str
    workflow_hash: str
    worker_id: str
    lease_attempt: int
    lease_until_epoch: float


@dataclass(frozen=True)
class PendingAction:
    run_id: str
    workflow_hash: str
    action_index: int
    action: BrowserAction
    prior_outputs: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class StepResult:
    outputs: Mapping[str, Any] = field(default_factory=dict)
    selector_report: SelectorRecoveryReport | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outputs, Mapping):
            raise TypeError("step outputs must be a mapping")
        if any(not isinstance(key, str) for key in self.outputs):
            raise TypeError("step output keys must be strings")
        _canonical_json(dict(self.outputs))
        if self.selector_report is not None and not isinstance(
            self.selector_report, SelectorRecoveryReport
        ):
            raise TypeError("selector_report must be a SelectorRecoveryReport")


@dataclass(frozen=True)
class SubmissionProof:
    release_manifest_sha256: str
    token_sha256: str
    receipt_id: str
    receipt_payload_sha256: str
    screenshot_sha256: str
    field_map_sha256: str
    submit_event_sha256: str

    def __post_init__(self) -> None:
        for value in (
            self.release_manifest_sha256,
            self.token_sha256,
            self.receipt_id,
            self.receipt_payload_sha256,
            self.screenshot_sha256,
            self.field_map_sha256,
            self.submit_event_sha256,
        ):
            if not isinstance(value, str) or not re.fullmatch(
                r"[0-9a-f]{64}",
                value,
            ):
                raise ValueError(
                    "submission proof identities must be lowercase SHA-256"
                )


@dataclass(frozen=True)
class CanaryEvidenceArtifact:
    """Content identity of exact private evidence retained outside the workflow DB."""

    kind: str
    path: str
    sha256: str
    size_bytes: int
    media_type: str
    forensic_receipt_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not _IDENTIFIER.fullmatch(self.kind):
            raise ValueError("artifact kind must be a stable identifier")
        _require_text(self.path, "artifact path", maximum=4096)
        _require_sha256(self.sha256, "artifact sha256")
        _require_sha256(
            self.forensic_receipt_sha256,
            "artifact forensic_receipt_sha256",
        )
        if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool) or self.size_bytes < 0:
            raise ValueError("artifact size_bytes must be a non-negative integer")
        _require_text(self.media_type, "artifact media_type", maximum=256)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "forensic_receipt_sha256": self.forensic_receipt_sha256,
        }


@dataclass(frozen=True)
class CanaryTerminalObservation:
    """Immutable terminal provider/application observation for one canary."""

    observed_at: str
    stage: CanaryStage
    outcome: CanaryOutcomeKind
    ats: str
    official_url: str
    job_key: str
    vacancy_sha256: str
    reason_code: str
    summary: str
    technical_detail: str
    applicant_data_exposed: bool
    final_click_attempted: bool
    provider_confirmed: bool
    provider_receipt_sha256: str | None
    provider_screenshot_sha256: str | None
    artifacts: tuple[CanaryEvidenceArtifact, ...]
    next_engineering_action: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if not isinstance(self.observed_at, str) or not _RFC3339_UTC.fullmatch(self.observed_at):
            raise ValueError("observed_at must be second-precision RFC3339 UTC")
        if not isinstance(self.stage, CanaryStage):
            raise TypeError("stage must be CanaryStage")
        if not isinstance(self.outcome, CanaryOutcomeKind):
            raise TypeError("outcome must be CanaryOutcomeKind")
        _require_text(self.ats, "ats", maximum=128)
        if not isinstance(self.official_url, str) or not re.fullmatch(r"https://[^\s\x00]+", self.official_url):
            raise ValueError("official_url must be an HTTPS URL")
        _require_text(self.job_key, "job_key", maximum=512)
        _require_sha256(self.vacancy_sha256, "vacancy_sha256")
        if not isinstance(self.reason_code, str) or not _IDENTIFIER.fullmatch(self.reason_code):
            raise ValueError("reason_code must be a stable identifier")
        _require_text(self.summary, "summary", maximum=8192)
        _require_text(self.technical_detail, "technical_detail", maximum=32768)
        _require_text(self.next_engineering_action, "next_engineering_action", maximum=8192)
        for field_name in (
            "applicant_data_exposed",
            "final_click_attempted",
            "provider_confirmed",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be bool")
        _require_sha256(
            self.provider_receipt_sha256,
            "provider_receipt_sha256",
            nullable=True,
        )
        _require_sha256(
            self.provider_screenshot_sha256,
            "provider_screenshot_sha256",
            nullable=True,
        )
        if not self.artifacts or not all(
            isinstance(artifact, CanaryEvidenceArtifact) for artifact in self.artifacts
        ):
            raise ValueError("terminal observation requires typed evidence artifacts")
        artifact_keys = [(artifact.kind, artifact.sha256) for artifact in self.artifacts]
        if len(artifact_keys) != len(set(artifact_keys)):
            raise ValueError("terminal evidence artifacts must be unique")
        successful = self.outcome is CanaryOutcomeKind.PROVIDER_CONFIRMED_SUBMISSION
        if successful != self.provider_confirmed:
            raise ValueError("provider-confirmed outcome and flag must agree")
        if successful and (
            not self.final_click_attempted
            or self.provider_receipt_sha256 is None
            or self.provider_screenshot_sha256 is None
        ):
            raise ValueError("provider-confirmed submission requires click, receipt and screenshot")
        if not successful and self.provider_receipt_sha256 is not None:
            raise ValueError("non-success outcome cannot claim a provider receipt")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "jaa.browser-canary-terminal-observation.v1",
            "observed_at": self.observed_at,
            "stage": self.stage.value,
            "outcome": self.outcome.value,
            "ats": self.ats,
            "official_url": self.official_url,
            "job_key": self.job_key,
            "vacancy_sha256": self.vacancy_sha256,
            "reason_code": self.reason_code,
            "summary": self.summary,
            "technical_detail": self.technical_detail,
            "applicant_data_exposed": self.applicant_data_exposed,
            "final_click_attempted": self.final_click_attempted,
            "provider_confirmed": self.provider_confirmed,
            "provider_receipt_sha256": self.provider_receipt_sha256,
            "provider_screenshot_sha256": self.provider_screenshot_sha256,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "next_engineering_action": self.next_engineering_action,
        }

    @property
    def content_sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class ApplicationQualityIssue:
    code: str
    severity: QualityIssueSeverity
    category: str
    release_blocking: bool
    enforceable_by_code: bool
    summary: str
    evidence: str
    remediation: str

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not _IDENTIFIER.fullmatch(self.code):
            raise ValueError("quality issue code must be a stable identifier")
        if not isinstance(self.severity, QualityIssueSeverity):
            raise TypeError("quality issue severity must be typed")
        if not isinstance(self.category, str) or not _IDENTIFIER.fullmatch(self.category):
            raise ValueError("quality issue category must be a stable identifier")
        if not isinstance(self.release_blocking, bool) or not isinstance(self.enforceable_by_code, bool):
            raise TypeError("quality issue flags must be bool")
        _require_text(self.summary, "quality issue summary", maximum=4096)
        _require_text(self.evidence, "quality issue evidence", maximum=16384)
        _require_text(self.remediation, "quality issue remediation", maximum=8192)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "category": self.category,
            "release_blocking": self.release_blocking,
            "enforceable_by_code": self.enforceable_by_code,
            "summary": self.summary,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class ApplicationPreflightQualityReview:
    """Exact pre-release quality authority for one prepared application."""

    reviewed_at: str
    vacancy_sha256: str
    candidate_authority_sha256: str
    application_source_sha256: str
    artifact_receipt_sha256: str
    cv_sha256: str
    cover_letter_sha256: str | None
    field_answers_sha256: str
    form_inventory_sha256: str
    quality_policy_sha256: str
    reviewer_receipt_sha256: str
    disposition: QualityReviewDisposition
    factual_accuracy_score: int
    role_targeting_score: int
    natural_voice_score: int
    cross_application_consistency_score: int
    evidence_capture_score: int
    technical_execution_score: int
    cover_letter_shingle_sha256s: tuple[str, ...]
    maximum_prior_similarity_bp: int
    ats_answer_authority_verified: bool
    issues: tuple[ApplicationQualityIssue, ...]
    summary: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "issues", tuple(self.issues))
        object.__setattr__(
            self,
            "cover_letter_shingle_sha256s",
            tuple(self.cover_letter_shingle_sha256s),
        )
        if not isinstance(self.reviewed_at, str) or not _RFC3339_UTC.fullmatch(self.reviewed_at):
            raise ValueError("reviewed_at must be second-precision RFC3339 UTC")
        for field_name in (
            "vacancy_sha256",
            "candidate_authority_sha256",
            "application_source_sha256",
            "artifact_receipt_sha256",
            "cv_sha256",
            "field_answers_sha256",
            "form_inventory_sha256",
            "quality_policy_sha256",
            "reviewer_receipt_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name)
        _require_sha256(
            self.cover_letter_sha256,
            "cover_letter_sha256",
            nullable=True,
        )
        if self.disposition not in {
            QualityReviewDisposition.ACCEPTED,
            QualityReviewDisposition.NEEDS_REMEDIATION,
        }:
            raise ValueError("preflight review disposition is unsupported")
        for field_name in (
            "factual_accuracy_score",
            "role_targeting_score",
            "natural_voice_score",
            "cross_application_consistency_score",
            "evidence_capture_score",
            "technical_execution_score",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10:
                raise ValueError(f"{field_name} must be an integer from 0 to 10")
        if not all(isinstance(issue, ApplicationQualityIssue) for issue in self.issues):
            raise TypeError("preflight issues must be ApplicationQualityIssue")
        if (
            len(self.cover_letter_shingle_sha256s) > 8192
            or tuple(sorted(set(self.cover_letter_shingle_sha256s)))
            != self.cover_letter_shingle_sha256s
        ):
            raise ValueError("cover-letter shingle identities must be unique and ordered")
        for value in self.cover_letter_shingle_sha256s:
            _require_sha256(value, "cover-letter shingle hash")
        if (
            not isinstance(self.maximum_prior_similarity_bp, int)
            or isinstance(self.maximum_prior_similarity_bp, bool)
            or not 0 <= self.maximum_prior_similarity_bp <= 10_000
        ):
            raise ValueError("maximum prior similarity must be basis points")
        if not isinstance(self.ats_answer_authority_verified, bool):
            raise TypeError("ATS answer-authority verification must be bool")
        issue_codes = [issue.code for issue in self.issues]
        if len(issue_codes) != len(set(issue_codes)):
            raise ValueError("preflight issue codes must be unique")
        if self.disposition is QualityReviewDisposition.ACCEPTED:
            exact_scores = (
                self.factual_accuracy_score,
                self.cross_application_consistency_score,
                self.evidence_capture_score,
                self.technical_execution_score,
            )
            if exact_scores != (10, 10, 10, 10):
                raise ValueError("accepted preflight requires exact deterministic quality scores")
            if self.role_targeting_score < 6 or self.natural_voice_score < 6:
                raise ValueError("accepted preflight fails minimum targeting or natural-voice score")
            if any(issue.release_blocking for issue in self.issues):
                raise ValueError("accepted preflight cannot contain a release-blocking issue")
            if not self.ats_answer_authority_verified:
                raise ValueError("accepted preflight requires exact ATS answer authority")
        _require_text(self.summary, "preflight quality summary", maximum=16384)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "jaa.application-preflight-quality-review.v2",
            "reviewed_at": self.reviewed_at,
            "vacancy_sha256": self.vacancy_sha256,
            "candidate_authority_sha256": self.candidate_authority_sha256,
            "application_source_sha256": self.application_source_sha256,
            "artifact_receipt_sha256": self.artifact_receipt_sha256,
            "cv_sha256": self.cv_sha256,
            "cover_letter_sha256": self.cover_letter_sha256,
            "field_answers_sha256": self.field_answers_sha256,
            "form_inventory_sha256": self.form_inventory_sha256,
            "quality_policy_sha256": self.quality_policy_sha256,
            "reviewer_receipt_sha256": self.reviewer_receipt_sha256,
            "disposition": self.disposition.value,
            "scores": {
                "factual_accuracy": self.factual_accuracy_score,
                "role_targeting": self.role_targeting_score,
                "natural_voice": self.natural_voice_score,
                "cross_application_consistency": self.cross_application_consistency_score,
                "evidence_capture": self.evidence_capture_score,
                "technical_execution": self.technical_execution_score,
            },
            "cover_letter_shingle_sha256s": list(
                self.cover_letter_shingle_sha256s
            ),
            "maximum_prior_similarity_bp": self.maximum_prior_similarity_bp,
            "ats_answer_authority_verified": self.ats_answer_authority_verified,
            "issues": [issue.to_dict() for issue in self.issues],
            "summary": self.summary,
        }

    @property
    def content_sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class ApplicationQualityReview:
    """Exact post-terminal review required before another canary may start."""

    reviewed_at: str
    terminal_observation_sha256: str
    disposition: QualityReviewDisposition
    factual_accuracy_score: int | None
    role_targeting_score: int | None
    natural_voice_score: int | None
    evidence_capture_score: int
    technical_execution_score: int
    application_source_sha256: str | None
    artifact_receipt_sha256: str | None
    cv_sha256: str | None
    cover_letter_sha256: str | None
    field_answers_sha256: str | None
    form_inventory_sha256: str | None
    provider_receipt_sha256: str | None
    issues: tuple[ApplicationQualityIssue, ...]
    summary: str
    next_cycle_decision: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "issues", tuple(self.issues))
        if not isinstance(self.reviewed_at, str) or not _RFC3339_UTC.fullmatch(self.reviewed_at):
            raise ValueError("reviewed_at must be second-precision RFC3339 UTC")
        _require_sha256(self.terminal_observation_sha256, "terminal_observation_sha256")
        if not isinstance(self.disposition, QualityReviewDisposition):
            raise TypeError("quality review disposition must be typed")
        for field_name in (
            "factual_accuracy_score",
            "role_targeting_score",
            "natural_voice_score",
        ):
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10
            ):
                raise ValueError(f"{field_name} must be null or an integer from 0 to 10")
        for field_name in ("evidence_capture_score", "technical_execution_score"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10:
                raise ValueError(f"{field_name} must be an integer from 0 to 10")
        for field_name in (
            "application_source_sha256",
            "artifact_receipt_sha256",
            "cv_sha256",
            "cover_letter_sha256",
            "field_answers_sha256",
            "form_inventory_sha256",
            "provider_receipt_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name, nullable=True)
        if not all(isinstance(issue, ApplicationQualityIssue) for issue in self.issues):
            raise TypeError("quality review issues must be ApplicationQualityIssue")
        issue_codes = [issue.code for issue in self.issues]
        if len(issue_codes) != len(set(issue_codes)):
            raise ValueError("quality review issue codes must be unique")
        if self.disposition is QualityReviewDisposition.ACCEPTED and any(
            issue.release_blocking for issue in self.issues
        ):
            raise ValueError("accepted review cannot contain a release-blocking issue")
        _require_text(self.summary, "quality review summary", maximum=16384)
        _require_text(self.next_cycle_decision, "next_cycle_decision", maximum=8192)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "jaa.application-quality-review.v1",
            "reviewed_at": self.reviewed_at,
            "terminal_observation_sha256": self.terminal_observation_sha256,
            "disposition": self.disposition.value,
            "scores": {
                "factual_accuracy": self.factual_accuracy_score,
                "role_targeting": self.role_targeting_score,
                "natural_voice": self.natural_voice_score,
                "evidence_capture": self.evidence_capture_score,
                "technical_execution": self.technical_execution_score,
            },
            "application_source_sha256": self.application_source_sha256,
            "artifact_receipt_sha256": self.artifact_receipt_sha256,
            "cv_sha256": self.cv_sha256,
            "cover_letter_sha256": self.cover_letter_sha256,
            "field_answers_sha256": self.field_answers_sha256,
            "form_inventory_sha256": self.form_inventory_sha256,
            "provider_receipt_sha256": self.provider_receipt_sha256,
            "issues": [issue.to_dict() for issue in self.issues],
            "summary": self.summary,
            "next_cycle_decision": self.next_cycle_decision,
        }

    @property
    def content_sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=30000;

CREATE TABLE IF NOT EXISTS browser_workflow_definitions (
  content_hash TEXT PRIMARY KEY,
  workflow_name TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  version TEXT NOT NULL,
  definition_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS browser_workflow_runs (
  run_id TEXT PRIMARY KEY,
  workflow_hash TEXT NOT NULL REFERENCES browser_workflow_definitions(content_hash),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK(status IN ('queued','leased','completed','failed','cancelled')),
  lease_owner TEXT,
  lease_until_epoch REAL,
  lease_attempts INTEGER NOT NULL DEFAULT 0,
  release_gate_hash TEXT,
  release_authorization_reference TEXT,
  release_gate_used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS browser_workflow_runs_ready
  ON browser_workflow_runs(status,lease_until_epoch,created_at);

CREATE TABLE IF NOT EXISTS browser_workflow_checkpoints (
  run_id TEXT NOT NULL REFERENCES browser_workflow_runs(run_id),
  action_index INTEGER NOT NULL,
  step_id TEXT NOT NULL,
  action_hash TEXT NOT NULL,
  output_json TEXT NOT NULL,
  selector_report_json TEXT,
  completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(run_id,action_index),
  UNIQUE(run_id,step_id)
);

CREATE TABLE IF NOT EXISTS browser_workflow_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES browser_workflow_runs(run_id),
  step_id TEXT,
  event_type TEXT NOT NULL,
  actor_kind TEXT NOT NULL DEFAULT 'deterministic',
  payload_json TEXT NOT NULL DEFAULT '{}',
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS browser_workflow_events_run
  ON browser_workflow_events(run_id,id);

CREATE TABLE IF NOT EXISTS browser_submit_dispatches (
  run_id TEXT PRIMARY KEY REFERENCES browser_workflow_runs(run_id),
  step_id TEXT NOT NULL,
  action_hash TEXT NOT NULL,
  release_manifest_hash TEXT NOT NULL,
  release_token_hash TEXT NOT NULL UNIQUE
    REFERENCES release_tokens(token_hash) ON DELETE RESTRICT,
  field_map_hash TEXT NOT NULL,
  selector_report_json TEXT NOT NULL,
  state TEXT NOT NULL
    CHECK(state IN ('prepared','release_consumed','click_started','receipt_recorded')),
  release_consumed_at TEXT,
  receipt_id TEXT,
  receipt_payload_hash TEXT,
  screenshot_hash TEXT,
  submit_event_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS browser_canary_runs (
  run_id TEXT PRIMARY KEY REFERENCES browser_workflow_runs(run_id) ON DELETE RESTRICT,
  profile_id TEXT NOT NULL,
  job_key TEXT NOT NULL,
  vacancy_rank INTEGER NOT NULL CHECK(vacancy_rank>0),
  vacancy_sha256 TEXT NOT NULL CHECK(length(vacancy_sha256)=64),
  state TEXT NOT NULL CHECK(state IN ('active','terminal','reviewed')),
  terminal_observation_sha256 TEXT,
  quality_review_sha256 TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK(
    (state='active' AND terminal_observation_sha256 IS NULL AND quality_review_sha256 IS NULL)
    OR (state='terminal' AND terminal_observation_sha256 IS NOT NULL AND quality_review_sha256 IS NULL)
    OR (state='reviewed' AND terminal_observation_sha256 IS NOT NULL AND quality_review_sha256 IS NOT NULL)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS browser_canary_one_active
  ON browser_canary_runs((1)) WHERE state='active';
CREATE UNIQUE INDEX IF NOT EXISTS browser_canary_identity
  ON browser_canary_runs(profile_id,job_key,vacancy_sha256);

CREATE TABLE IF NOT EXISTS browser_canary_terminal_observations (
  observation_sha256 TEXT PRIMARY KEY CHECK(length(observation_sha256)=64),
  run_id TEXT NOT NULL UNIQUE REFERENCES browser_canary_runs(run_id) ON DELETE RESTRICT,
  document_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS browser_application_preflight_quality_reviews (
  review_sha256 TEXT PRIMARY KEY CHECK(length(review_sha256)=64),
  run_id TEXT NOT NULL REFERENCES browser_canary_runs(run_id) ON DELETE RESTRICT,
  document_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS browser_application_preflight_quality_reviews_run
  ON browser_application_preflight_quality_reviews(run_id);

CREATE TABLE IF NOT EXISTS browser_application_quality_reviews (
  review_sha256 TEXT PRIMARY KEY CHECK(length(review_sha256)=64),
  run_id TEXT NOT NULL UNIQUE REFERENCES browser_canary_runs(run_id) ON DELETE RESTRICT,
  terminal_observation_sha256 TEXT NOT NULL
    REFERENCES browser_canary_terminal_observations(observation_sha256) ON DELETE RESTRICT,
  document_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS browser_submit_dispatches_guard_insert
BEFORE INSERT ON browser_submit_dispatches
WHEN NEW.state<>'prepared'
  OR NEW.release_consumed_at IS NOT NULL
  OR NEW.receipt_id IS NOT NULL
  OR NEW.receipt_payload_hash IS NOT NULL
  OR NEW.screenshot_hash IS NOT NULL
  OR NEW.submit_event_hash IS NOT NULL
  OR NOT EXISTS (
    SELECT 1 FROM release_tokens
    WHERE token_hash=NEW.release_token_hash
      AND release_manifest_hash=NEW.release_manifest_hash
      AND consumed_at IS NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'browser submit dispatch insert is invalid');
END;

CREATE TRIGGER IF NOT EXISTS browser_canary_runs_guard_update
BEFORE UPDATE ON browser_canary_runs
WHEN NEW.run_id<>OLD.run_id
  OR NEW.profile_id<>OLD.profile_id
  OR NEW.job_key<>OLD.job_key
  OR NEW.vacancy_rank<>OLD.vacancy_rank
  OR NEW.vacancy_sha256<>OLD.vacancy_sha256
  OR NEW.created_at<>OLD.created_at
  OR NOT (
    (OLD.state='active' AND NEW.state='terminal'
      AND OLD.terminal_observation_sha256 IS NULL
      AND NEW.terminal_observation_sha256 IS NOT NULL
      AND NEW.quality_review_sha256 IS NULL)
    OR (OLD.state='terminal' AND NEW.state='reviewed'
      AND NEW.terminal_observation_sha256=OLD.terminal_observation_sha256
      AND OLD.quality_review_sha256 IS NULL
      AND NEW.quality_review_sha256 IS NOT NULL)
  )
BEGIN
  SELECT RAISE(ABORT, 'browser canary transition is invalid');
END;

CREATE TRIGGER IF NOT EXISTS browser_canary_runs_immutable_delete
BEFORE DELETE ON browser_canary_runs
BEGIN
  SELECT RAISE(ABORT, 'browser canary runs are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_canary_terminal_immutable_update
BEFORE UPDATE ON browser_canary_terminal_observations
BEGIN
  SELECT RAISE(ABORT, 'browser canary terminal observations are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_canary_terminal_immutable_delete
BEFORE DELETE ON browser_canary_terminal_observations
BEGIN
  SELECT RAISE(ABORT, 'browser canary terminal observations are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_application_preflight_reviews_immutable_update
BEFORE UPDATE ON browser_application_preflight_quality_reviews
BEGIN
  SELECT RAISE(ABORT, 'browser application preflight quality reviews are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_application_preflight_reviews_immutable_delete
BEFORE DELETE ON browser_application_preflight_quality_reviews
BEGIN
  SELECT RAISE(ABORT, 'browser application preflight quality reviews are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_application_quality_reviews_immutable_update
BEFORE UPDATE ON browser_application_quality_reviews
BEGIN
  SELECT RAISE(ABORT, 'browser application quality reviews are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_application_quality_reviews_immutable_delete
BEFORE DELETE ON browser_application_quality_reviews
BEGIN
  SELECT RAISE(ABORT, 'browser application quality reviews are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_submit_dispatches_guard_update
BEFORE UPDATE ON browser_submit_dispatches
WHEN NEW.run_id<>OLD.run_id
  OR NEW.step_id<>OLD.step_id
  OR NEW.action_hash<>OLD.action_hash
  OR NEW.release_manifest_hash<>OLD.release_manifest_hash
  OR NEW.release_token_hash<>OLD.release_token_hash
  OR NEW.field_map_hash<>OLD.field_map_hash
  OR NEW.selector_report_json<>OLD.selector_report_json
  OR (
    OLD.state='prepared'
    AND (
      NEW.state<>'release_consumed'
      OR NEW.release_consumed_at IS NULL
      OR NEW.release_consumed_at IS NOT (
        SELECT consumed_at FROM release_tokens
        WHERE token_hash=OLD.release_token_hash
      )
      OR NEW.receipt_id IS NOT NULL
      OR NEW.receipt_payload_hash IS NOT NULL
      OR NEW.screenshot_hash IS NOT NULL
      OR NEW.submit_event_hash IS NOT NULL
    )
  )
  OR (
    OLD.state='release_consumed'
    AND (
      NEW.state<>'click_started'
      OR NEW.release_consumed_at IS NOT OLD.release_consumed_at
      OR NEW.receipt_id IS NOT NULL
      OR NEW.receipt_payload_hash IS NOT NULL
      OR NEW.screenshot_hash IS NOT NULL
      OR NEW.submit_event_hash IS NOT NULL
    )
  )
  OR (
    OLD.state='click_started'
    AND (
      NEW.state<>'receipt_recorded'
      OR NEW.release_consumed_at IS NOT OLD.release_consumed_at
      OR NEW.receipt_id IS NULL
      OR NEW.receipt_payload_hash IS NULL
      OR NEW.screenshot_hash IS NULL
      OR NEW.submit_event_hash IS NULL
    )
  )
  OR NOT (
    (OLD.state='prepared' AND NEW.state='release_consumed')
    OR (OLD.state='release_consumed' AND NEW.state='click_started')
    OR (OLD.state='click_started' AND NEW.state='receipt_recorded')
  )
BEGIN
  SELECT RAISE(ABORT, 'browser submit dispatch update is invalid');
END;

CREATE TRIGGER IF NOT EXISTS browser_submit_dispatches_immutable_delete
BEFORE DELETE ON browser_submit_dispatches
BEGIN
  SELECT RAISE(ABORT, 'browser submit dispatches are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_workflow_definitions_immutable_update
BEFORE UPDATE ON browser_workflow_definitions
BEGIN
  SELECT RAISE(ABORT, 'browser workflow definitions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_workflow_definitions_immutable_delete
BEFORE DELETE ON browser_workflow_definitions
BEGIN
  SELECT RAISE(ABORT, 'browser workflow definitions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_workflow_checkpoints_immutable_update
BEFORE UPDATE ON browser_workflow_checkpoints
BEGIN
  SELECT RAISE(ABORT, 'browser workflow checkpoints are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_workflow_checkpoints_immutable_delete
BEFORE DELETE ON browser_workflow_checkpoints
BEGIN
  SELECT RAISE(ABORT, 'browser workflow checkpoints are immutable');
END;

CREATE TRIGGER IF NOT EXISTS browser_workflow_events_no_update
BEFORE UPDATE ON browser_workflow_events
BEGIN
  SELECT RAISE(ABORT, 'browser workflow events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS browser_workflow_events_no_delete
BEFORE DELETE ON browser_workflow_events
BEGIN
  SELECT RAISE(ABORT, 'browser workflow events are append-only');
END;
"""


class BrowserWorkflowStore:
    """SQLite repository and scheduler for external browser executors."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] = time.time,
        forensic_evidence_root: str | Path | None = None,
        repository_root: str | Path | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._forensic_evidence_root = (
            Path(forensic_evidence_root) if forensic_evidence_root is not None else None
        )
        self._repository_root = Path(repository_root) if repository_root is not None else None
        if (self._forensic_evidence_root is None) != (self._repository_root is None):
            raise ValueError("forensic evidence root and repository root must be configured together")
        with self.connection() as conn:
            conn.executescript(SCHEMA)

    def _verify_canary_evidence_artifacts(
        self, artifacts: tuple[CanaryEvidenceArtifact, ...]
    ) -> None:
        if self._forensic_evidence_root is None or self._repository_root is None:
            raise WorkflowError("canary terminal evidence requires the private forensic archive")
        for artifact in artifacts:
            try:
                receipt, exact_bytes = verify_exact_canary_evidence(
                    self._forensic_evidence_root,
                    self._repository_root,
                    artifact.forensic_receipt_sha256,
                )
            except (CanaryForensicEvidenceError, OSError, ValueError) as exc:
                raise WorkflowError("canary terminal forensic evidence is invalid") from exc
            nominal_path = Path(artifact.path)
            if not nominal_path.is_absolute():
                nominal_path = self._repository_root / nominal_path
            source_locator_sha256 = hashlib.sha256(
                str(nominal_path.absolute()).encode("utf-8")
            ).hexdigest()
            if (
                receipt.source_locator_sha256 != source_locator_sha256
                or receipt.exact_sha256 != artifact.sha256
                or receipt.exact_size_bytes != artifact.size_bytes
                or receipt.media_type != artifact.media_type
                or len(exact_bytes) != artifact.size_bytes
            ):
                raise WorkflowError("canary terminal artifact differs from forensic receipt")

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _insert_event(
        conn: sqlite3.Connection,
        *,
        run_id: str,
        event_type: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
        step_id: str | None = None,
        actor_kind: str = "deterministic",
    ) -> bool:
        payload_json = _canonical_json(dict(payload))
        result = conn.execute(
            """INSERT OR IGNORE INTO browser_workflow_events(
                 run_id,step_id,event_type,actor_kind,payload_json,idempotency_key
               ) VALUES(?,?,?,?,?,?)""",
            (run_id, step_id, event_type, actor_kind, payload_json, idempotency_key),
        )
        if result.rowcount == 1:
            return True
        prior = conn.execute(
            """SELECT run_id,step_id,event_type,actor_kind,payload_json
               FROM browser_workflow_events WHERE idempotency_key=?""",
            (idempotency_key,),
        ).fetchone()
        expected = (run_id, step_id, event_type, actor_kind, payload_json)
        actual = tuple(prior) if prior is not None else None
        if actual != expected:
            raise IdempotencyConflictError("event idempotency key reused with different content")
        return False

    @staticmethod
    def _register(conn: sqlite3.Connection, workflow: BrowserWorkflow) -> bool:
        result = conn.execute(
            """INSERT OR IGNORE INTO browser_workflow_definitions(
                 content_hash,workflow_name,schema_version,version,definition_json
               ) VALUES(?,?,?,?,?)""",
            (
                workflow.content_hash,
                workflow.name,
                workflow.schema_version,
                workflow.version,
                workflow.canonical_json,
            ),
        )
        return result.rowcount == 1

    def register_workflow(self, workflow: BrowserWorkflow) -> bool:
        with self.transaction() as conn:
            return self._register(conn, workflow)

    @staticmethod
    def _load_workflow(conn: sqlite3.Connection, content_hash: str) -> BrowserWorkflow:
        row = conn.execute(
            "SELECT definition_json FROM browser_workflow_definitions WHERE content_hash=?",
            (content_hash,),
        ).fetchone()
        if row is None:
            raise KeyError(content_hash)
        workflow = BrowserWorkflow.from_dict(json.loads(row["definition_json"]))
        if workflow.content_hash != content_hash:
            raise WorkflowError("stored workflow content hash mismatch")
        return workflow

    def create_run(
        self,
        workflow: BrowserWorkflow,
        *,
        run_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> str:
        """Create one queued run; a supplied key makes retries return the same run."""
        event_key = f"browser-run-created:{idempotency_key}" if idempotency_key else None
        with self.transaction() as conn:
            self._register(conn, workflow)
            if event_key:
                prior = conn.execute(
                    "SELECT run_id,payload_json FROM browser_workflow_events WHERE idempotency_key=?",
                    (event_key,),
                ).fetchone()
                if prior is not None:
                    payload = json.loads(prior["payload_json"])
                    if payload.get("workflow_hash") != workflow.content_hash:
                        raise IdempotencyConflictError(
                            "run creation key reused for another workflow version"
                        )
                    return str(prior["run_id"])
            selected_id = run_id or str(uuid.uuid4())
            existing = conn.execute(
                "SELECT workflow_hash FROM browser_workflow_runs WHERE run_id=?", (selected_id,)
            ).fetchone()
            if existing is not None:
                if existing["workflow_hash"] != workflow.content_hash:
                    raise IdempotencyConflictError("run ID already belongs to another workflow")
                return selected_id
            conn.execute(
                "INSERT INTO browser_workflow_runs(run_id,workflow_hash) VALUES(?,?)",
                (selected_id, workflow.content_hash),
            )
            self._insert_event(
                conn,
                run_id=selected_id,
                event_type="run_created",
                idempotency_key=event_key or f"browser-run-created:{selected_id}",
                payload={"workflow_hash": workflow.content_hash, "version": workflow.version},
            )
            return selected_id

    @staticmethod
    def _assert_previous_canary_review_allows_progress(conn: sqlite3.Connection) -> None:
        pending = conn.execute(
            "SELECT run_id FROM browser_canary_runs WHERE state='terminal' LIMIT 1"
        ).fetchone()
        if pending is not None:
            raise WorkflowError(
                f"canary {pending['run_id']} requires a sealed quality review before progression"
            )
        latest = conn.execute(
            """SELECT r.document_json
               FROM browser_canary_runs c
               JOIN browser_application_quality_reviews r
                 ON r.review_sha256=c.quality_review_sha256
               WHERE c.state='reviewed'
               ORDER BY c.rowid DESC LIMIT 1"""
        ).fetchone()
        if latest is None:
            return
        try:
            document = json.loads(str(latest["document_json"]))
            blocked = document["disposition"] == QualityReviewDisposition.NEEDS_REMEDIATION.value
            blocked = blocked or any(
                bool(issue["release_blocking"]) for issue in document["issues"]
            )
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise WorkflowError("stored canary quality review is invalid") from exc
        if blocked:
            raise WorkflowError("previous canary has unresolved release-blocking quality issues")

    def create_canary_run(
        self,
        workflow: BrowserWorkflow,
        *,
        profile_id: str,
        job_key: str,
        vacancy_rank: int,
        vacancy_sha256: str,
        idempotency_key: str,
        run_id: str | None = None,
    ) -> str:
        """Create the sole active canary after the prior terminal review is admitted."""
        if self._forensic_evidence_root is None or self._repository_root is None:
            raise WorkflowError("canary runs require the private forensic archive")
        if not isinstance(profile_id, str) or not _IDENTIFIER.fullmatch(profile_id):
            raise ValueError("profile_id must be a stable identifier")
        _require_text(job_key, "job_key", maximum=512)
        if not isinstance(vacancy_rank, int) or isinstance(vacancy_rank, bool) or vacancy_rank < 1:
            raise ValueError("vacancy_rank must be a positive integer")
        _require_sha256(vacancy_sha256, "vacancy_sha256")
        if not isinstance(idempotency_key, str) or not _IDENTIFIER.fullmatch(idempotency_key):
            raise ValueError("canary idempotency_key must be a stable identifier")
        event_key = f"browser-canary-created:{idempotency_key}"
        with self.transaction() as conn:
            prior = conn.execute(
                """SELECT e.run_id,e.payload_json,c.profile_id,c.job_key,c.vacancy_rank,
                          c.vacancy_sha256,r.workflow_hash
                   FROM browser_workflow_events e
                   JOIN browser_canary_runs c ON c.run_id=e.run_id
                   JOIN browser_workflow_runs r ON r.run_id=e.run_id
                   WHERE e.idempotency_key=?""",
                (event_key,),
            ).fetchone()
            if prior is not None:
                expected = (
                    profile_id,
                    job_key,
                    vacancy_rank,
                    vacancy_sha256,
                    workflow.content_hash,
                )
                actual = (
                    str(prior["profile_id"]),
                    str(prior["job_key"]),
                    int(prior["vacancy_rank"]),
                    str(prior["vacancy_sha256"]),
                    str(prior["workflow_hash"]),
                )
                if actual != expected:
                    raise IdempotencyConflictError(
                        "canary creation key reused with different authority"
                    )
                return str(prior["run_id"])
            active = conn.execute(
                "SELECT run_id FROM browser_canary_runs WHERE state='active'"
            ).fetchone()
            if active is not None:
                raise WorkflowError(f"canary {active['run_id']} is already active")
            self._assert_previous_canary_review_allows_progress(conn)
            previous = conn.execute(
                """SELECT vacancy_rank FROM browser_canary_runs
                   WHERE state='reviewed' ORDER BY rowid DESC LIMIT 1"""
            ).fetchone()
            if previous is not None and vacancy_rank >= int(previous["vacancy_rank"]):
                raise WorkflowError(
                    "next canary must move upward from the previously reviewed worst-first rank"
                )
            self._register(conn, workflow)
            selected_id = run_id or str(uuid.uuid4())
            if conn.execute(
                "SELECT 1 FROM browser_workflow_runs WHERE run_id=?", (selected_id,)
            ).fetchone() is not None:
                raise IdempotencyConflictError("run ID already exists")
            conn.execute(
                "INSERT INTO browser_workflow_runs(run_id,workflow_hash) VALUES(?,?)",
                (selected_id, workflow.content_hash),
            )
            conn.execute(
                """INSERT INTO browser_canary_runs(
                     run_id,profile_id,job_key,vacancy_rank,vacancy_sha256,state
                   ) VALUES(?,?,?,?,?,'active')""",
                (selected_id, profile_id, job_key, vacancy_rank, vacancy_sha256),
            )
            self._insert_event(
                conn,
                run_id=selected_id,
                event_type="canary_created",
                idempotency_key=event_key,
                payload={
                    "profile_id": profile_id,
                    "job_key": job_key,
                    "vacancy_rank": vacancy_rank,
                    "vacancy_sha256": vacancy_sha256,
                    "workflow_hash": workflow.content_hash,
                },
            )
            return selected_id

    def record_application_preflight_quality_review(
        self,
        run_id: str,
        quality_input: object,
    ) -> bool:
        """Recompute and append a package review from exact application evidence."""
        from .application_quality import (
            ApplicationQualityInput,
            build_deterministic_preflight_quality_review,
        )

        if not isinstance(quality_input, ApplicationQualityInput):
            raise TypeError("quality input must be ApplicationQualityInput")
        with self.transaction() as conn:
            canary = conn.execute(
                """SELECT c.*,r.release_gate_hash
                   FROM browser_canary_runs c
                   JOIN browser_workflow_runs r ON r.run_id=c.run_id
                   WHERE c.run_id=?""",
                (run_id,),
            ).fetchone()
            if canary is None:
                raise KeyError(run_id)
            if str(canary["state"]) != "active":
                raise WorkflowError("preflight quality review requires an active canary")
            if canary["release_gate_hash"] is not None:
                raise WorkflowError("preflight quality review cannot change after release authorization")
            if str(canary["vacancy_sha256"]) != quality_input.source.vacancy_sha256:
                raise WorkflowError("preflight quality review differs from canary vacancy")
            if str(canary["job_key"]) != quality_input.source.job_key:
                raise WorkflowError("preflight quality review differs from canary job")
            prior_shingles: list[tuple[str, ...]] = []
            for row in conn.execute(
                """SELECT q.document_json
                   FROM browser_application_preflight_quality_reviews q
                   WHERE q.run_id<>? ORDER BY q.rowid""",
                (run_id,),
            ).fetchall():
                try:
                    prior_document = json.loads(str(row["document_json"]))
                    if (
                        prior_document.get("schema_version")
                        != "jaa.application-preflight-quality-review.v2"
                    ):
                        continue
                    values = prior_document["cover_letter_shingle_sha256s"]
                    if not isinstance(values, list) or any(
                        not isinstance(value, str) or _SHA256.fullmatch(value) is None
                        for value in values
                    ):
                        raise ValueError
                    prior_shingles.append(tuple(values))
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise WorkflowError("prior preflight quality evidence is invalid") from exc
            review = build_deterministic_preflight_quality_review(
                quality_input,
                prior_cover_letter_shingles=prior_shingles,
            )
            document_json = _canonical_json(review.to_dict())
            review_sha256 = review.content_sha256
            if review_sha256 != _sha256(document_json):
                raise WorkflowError("preflight quality review identity is inconsistent")
            existing = conn.execute(
                """SELECT run_id,document_json
                   FROM browser_application_preflight_quality_reviews
                   WHERE review_sha256=?""",
                (review_sha256,),
            ).fetchone()
            if existing is not None:
                if str(existing["run_id"]) == run_id and str(existing["document_json"]) == document_json:
                    return False
                raise IdempotencyConflictError("preflight review identity belongs to different content")
            conn.execute(
                """INSERT INTO browser_application_preflight_quality_reviews(
                     review_sha256,run_id,document_json
                   ) VALUES(?,?,?)""",
                (review_sha256, run_id, document_json),
            )
            self._insert_event(
                conn,
                run_id=run_id,
                event_type="application_preflight_quality_review_recorded",
                idempotency_key=f"browser-application-preflight-quality-review:{review_sha256}",
                payload={
                    "review_sha256": review_sha256,
                    "application_source_sha256": review.application_source_sha256,
                    "artifact_receipt_sha256": review.artifact_receipt_sha256,
                    "field_answers_sha256": review.field_answers_sha256,
                    "form_inventory_sha256": review.form_inventory_sha256,
                    "quality_policy_sha256": review.quality_policy_sha256,
                    "reviewer_receipt_sha256": review.reviewer_receipt_sha256,
                    "disposition": review.disposition.value,
                    "release_blocking_issue_count": sum(
                        issue.release_blocking for issue in review.issues
                    ),
                },
                actor_kind="deterministic",
            )
            return True

    def claim_run(
        self,
        worker_id: str,
        *,
        lease_seconds: int = 900,
        run_id: str | None = None,
    ) -> LeasedRun | None:
        if not _IDENTIFIER.fullmatch(worker_id):
            raise ValueError("worker_id must be a stable identifier")
        now = float(self._clock())
        lease_until = now + max(1, int(lease_seconds))
        with self.transaction() as conn:
            if run_id is not None:
                row = conn.execute(
                    "SELECT * FROM browser_workflow_runs WHERE run_id=?", (run_id,)
                ).fetchone()
            else:
                row = conn.execute(
                    """SELECT * FROM browser_workflow_runs
                       WHERE status='queued'
                          OR (status='leased' AND COALESCE(lease_until_epoch,0)<?)
                       ORDER BY created_at,run_id LIMIT 1""",
                    (now,),
                ).fetchone()
            if row is None:
                return None
            if (
                row["status"] == "leased"
                and row["lease_owner"] == worker_id
                and float(row["lease_until_epoch"] or 0) >= now
            ):
                return LeasedRun(
                    str(row["run_id"]),
                    str(row["workflow_hash"]),
                    worker_id,
                    int(row["lease_attempts"]),
                    float(row["lease_until_epoch"]),
                )
            eligible = row["status"] == "queued" or (
                row["status"] == "leased" and float(row["lease_until_epoch"] or 0) < now
            )
            if not eligible:
                return None
            attempt = int(row["lease_attempts"]) + 1
            conn.execute(
                """UPDATE browser_workflow_runs SET status='leased',lease_owner=?,
                     lease_until_epoch=?,lease_attempts=?,updated_at=CURRENT_TIMESTAMP
                   WHERE run_id=?""",
                (worker_id, lease_until, attempt, row["run_id"]),
            )
            self._insert_event(
                conn,
                run_id=str(row["run_id"]),
                event_type="run_leased",
                idempotency_key=f"browser-run-leased:{row['run_id']}:{attempt}",
                payload={
                    "worker_id": worker_id,
                    "lease_attempt": attempt,
                    "lease_until_epoch": lease_until,
                    "resumed": attempt > 1,
                },
            )
            return LeasedRun(
                str(row["run_id"]), str(row["workflow_hash"]), worker_id, attempt, lease_until
            )

    def heartbeat(self, run_id: str, worker_id: str, *, lease_seconds: int = 900) -> float:
        now = float(self._clock())
        lease_until = now + max(1, int(lease_seconds))
        with self.transaction() as conn:
            row = self._require_live_lease(conn, run_id, worker_id, now)
            conn.execute(
                """UPDATE browser_workflow_runs SET lease_until_epoch=?,updated_at=CURRENT_TIMESTAMP
                   WHERE run_id=?""",
                (lease_until, run_id),
            )
            self._insert_event(
                conn,
                run_id=run_id,
                event_type="lease_renewed",
                idempotency_key=f"browser-lease-renewed:{run_id}:{row['lease_attempts']}:{lease_until}",
                payload={"worker_id": worker_id, "lease_until_epoch": lease_until},
            )
        return lease_until

    @staticmethod
    def _release_hash(run_id: str, token: str) -> str:
        if not isinstance(token, str) or len(token) < 16:
            raise ValueError("release-gate token must contain at least 16 characters")
        return _sha256(f"{run_id}\0{token}")

    def authorize_release(
        self,
        run_id: str,
        *,
        token: str,
        authorization_reference: str,
        idempotency_key: str,
    ) -> bool:
        """Arm a one-use submit gate without persisting the plaintext token."""
        if not _IDENTIFIER.fullmatch(authorization_reference):
            raise ValueError("authorization_reference must be a stable identifier")
        if not idempotency_key:
            raise ValueError("release authorization requires an idempotency key")
        token_hash = self._release_hash(run_id, token)
        event_key = f"browser-release-authorized:{run_id}:{idempotency_key}"
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT status,release_gate_used_at FROM browser_workflow_runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise KeyError(run_id)
            prior = conn.execute(
                "SELECT payload_json FROM browser_workflow_events WHERE idempotency_key=?",
                (event_key,),
            ).fetchone()
            if prior is not None:
                payload = json.loads(prior["payload_json"])
                if payload.get("release_gate_hash") != token_hash:
                    raise IdempotencyConflictError("release authorization key reused with another token")
                return False
            canary = conn.execute(
                "SELECT * FROM browser_canary_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if canary is not None:
                from .application_quality import QUALITY_POLICY_SHA256

                if str(canary["state"]) != "active":
                    raise ReleaseGateError("only an active canary may receive release authority")
                preflight = conn.execute(
                    """SELECT review_sha256,document_json
                       FROM browser_application_preflight_quality_reviews
                       WHERE run_id=? ORDER BY rowid DESC LIMIT 1""",
                    (run_id,),
                ).fetchone()
                if preflight is None:
                    raise ReleaseGateError("canary release requires a preflight quality review")
                try:
                    preflight_document = json.loads(str(preflight["document_json"]))
                    expected_preflight_sha256 = _sha256(
                        _canonical_json(preflight_document)
                    )
                    release_blocking = any(
                        bool(issue["release_blocking"])
                        for issue in preflight_document["issues"]
                    )
                    scores = preflight_document["scores"]
                except (KeyError, TypeError, json.JSONDecodeError) as exc:
                    raise ReleaseGateError("preflight quality review is invalid") from exc
                if (
                    str(preflight["review_sha256"]) != expected_preflight_sha256
                    or preflight_document.get("schema_version")
                    != "jaa.application-preflight-quality-review.v2"
                    or preflight_document.get("vacancy_sha256")
                    != str(canary["vacancy_sha256"])
                    or preflight_document.get("quality_policy_sha256")
                    != QUALITY_POLICY_SHA256
                    or preflight_document.get("ats_answer_authority_verified")
                    is not True
                    or preflight_document.get("disposition")
                    != QualityReviewDisposition.ACCEPTED.value
                    or not isinstance(scores, dict)
                    or tuple(
                        scores.get(value)
                        for value in (
                            "factual_accuracy",
                            "cross_application_consistency",
                            "evidence_capture",
                            "technical_execution",
                        )
                    )
                    != (10, 10, 10, 10)
                    or not isinstance(scores.get("role_targeting"), int)
                    or scores["role_targeting"] < 6
                    or not isinstance(scores.get("natural_voice"), int)
                    or scores["natural_voice"] < 6
                    or release_blocking
                ):
                    raise ReleaseGateError("latest preflight quality review does not admit release")
            if row["status"] in {"completed", "failed", "cancelled"} or row["release_gate_used_at"]:
                raise ReleaseGateError("run cannot be authorized for submission")
            conn.execute(
                """UPDATE browser_workflow_runs SET release_gate_hash=?,
                     release_authorization_reference=?,updated_at=CURRENT_TIMESTAMP WHERE run_id=?""",
                (token_hash, authorization_reference, run_id),
            )
            return self._insert_event(
                conn,
                run_id=run_id,
                event_type="release_authorized",
                idempotency_key=event_key,
                payload={
                    "authorization_reference": authorization_reference,
                    "release_gate_hash": token_hash,
                },
            )

    def prepare_submit_dispatch(
        self,
        run_id: str,
        worker_id: str,
        *,
        step_id: str,
        release_token: str,
        field_map_sha256: str,
        selector_report: SelectorRecoveryReport,
    ) -> bool:
        """Bind a pending submit to one currently unconsumed JAA-08 token."""
        if not re.fullmatch(r"[0-9a-f]{64}", field_map_sha256):
            raise ValueError("field-map identity must be lowercase SHA-256")
        token_parts = release_token.split(".")
        if (
            len(token_parts) != 3
            or token_parts[0] != "jaa08"
            or not re.fullmatch(r"[0-9a-f]{64}", token_parts[1])
        ):
            raise ReleaseGateError("release token format is invalid")
        token_sha256 = hashlib.sha256(release_token.encode()).hexdigest()
        now = float(self._clock())
        with self.transaction() as conn:
            run = self._require_live_lease(conn, run_id, worker_id, now)
            self._assert_release_token(run, run_id, release_token)
            workflow = self._load_workflow(
                conn,
                str(run["workflow_hash"]),
            )
            checkpoints = self._checkpoint_rows(conn, run_id)
            next_index = len(checkpoints)
            if next_index >= len(workflow.actions):
                raise WorkflowError("submit dispatch has no pending action")
            action = workflow.actions[next_index]
            if (
                action.step_id != step_id
                or action.kind is not ActionKind.SUBMIT
            ):
                raise WorkflowError(
                    "submit dispatch is not for the next pending action"
                )
            action_hash = _sha256(_canonical_json(action.to_dict()))
            self._validate_selector_report(
                action,
                selector_report,
                require_success=True,
            )
            selector_report_json = _canonical_json(
                selector_report.to_dict()
            )
            prior = conn.execute(
                "SELECT * FROM browser_submit_dispatches WHERE run_id=?",
                (run_id,),
            ).fetchone()
            expected = (
                step_id,
                action_hash,
                token_parts[1],
                token_sha256,
                field_map_sha256,
                selector_report_json,
            )
            token = conn.execute(
                """SELECT release_manifest_hash,consumed_at
                   FROM release_tokens WHERE token_hash=?""",
                (token_sha256,),
            ).fetchone()
            if (
                token is None
                or str(token["release_manifest_hash"]) != token_parts[1]
            ):
                raise ReleaseGateError(
                    "release token is not issued by the JAA-08 gate"
                )
            if prior is not None:
                actual = (
                    str(prior["step_id"]),
                    str(prior["action_hash"]),
                    str(prior["release_manifest_hash"]),
                    str(prior["release_token_hash"]),
                    str(prior["field_map_hash"]),
                    str(prior["selector_report_json"]),
                )
                if actual != expected:
                    raise IdempotencyConflictError(
                        "submit dispatch cannot be rebound"
                    )
                return False
            if token["consumed_at"] is not None:
                raise ReleaseGateError(
                    "release token was consumed before submit preparation"
                )
            competing = conn.execute(
                """SELECT run_id FROM browser_submit_dispatches
                   WHERE release_token_hash=?""",
                (token_sha256,),
            ).fetchone()
            if (
                competing is not None
                and str(competing["run_id"]) != run_id
            ):
                raise ReleaseGateError(
                    "release token is already bound to another submit run"
                )
            conn.execute(
                """INSERT INTO browser_submit_dispatches(
                     run_id,step_id,action_hash,release_manifest_hash,
                     release_token_hash,field_map_hash,selector_report_json,
                     state)
                   VALUES(?,?,?,?,?,?,?,'prepared')""",
                (run_id, *expected),
            )
            return self._insert_event(
                conn,
                run_id=run_id,
                step_id=step_id,
                event_type="submit_dispatch_prepared",
                idempotency_key=f"browser-submit-prepared:{run_id}",
                payload={
                    "action_hash": action_hash,
                    "release_manifest_hash": token_parts[1],
                    "release_token_hash": token_sha256,
                    "field_map_hash": field_map_sha256,
                },
            )

    def reconcile_release_consumed(
        self,
        run_id: str,
        worker_id: str,
        *,
        release_token: str,
    ) -> bool:
        """Record exact JAA-08 consumption after observing its canonical row."""
        token_sha256 = hashlib.sha256(release_token.encode()).hexdigest()
        now = float(self._clock())
        with self.transaction() as conn:
            run = self._require_live_lease(conn, run_id, worker_id, now)
            self._assert_release_token(run, run_id, release_token)
            dispatch = conn.execute(
                "SELECT * FROM browser_submit_dispatches WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if (
                dispatch is None
                or str(dispatch["release_token_hash"]) != token_sha256
            ):
                raise ReleaseGateError("submit dispatch is absent or invalid")
            token = conn.execute(
                """SELECT release_manifest_hash,consumed_at
                   FROM release_tokens WHERE token_hash=?""",
                (token_sha256,),
            ).fetchone()
            if (
                token is None
                or token["consumed_at"] is None
                or str(token["release_manifest_hash"])
                != str(dispatch["release_manifest_hash"])
            ):
                raise ReleaseGateError(
                    "canonical JAA-08 token consumption is absent"
                )
            if str(dispatch["state"]) != "prepared":
                return False
            conn.execute(
                """UPDATE browser_submit_dispatches
                   SET state='release_consumed',release_consumed_at=?,
                       updated_at=CURRENT_TIMESTAMP
                   WHERE run_id=?""",
                (str(token["consumed_at"]), run_id),
            )
            return self._insert_event(
                conn,
                run_id=run_id,
                step_id=str(dispatch["step_id"]),
                event_type="jaa08_release_consumed",
                idempotency_key=f"browser-jaa08-consumed:{run_id}",
                payload={
                    "release_manifest_hash": str(
                        dispatch["release_manifest_hash"]
                    ),
                    "release_token_hash": token_sha256,
                    "consumed_at": str(token["consumed_at"]),
                },
            )

    def mark_submit_started(
        self,
        run_id: str,
        worker_id: str,
        *,
        release_token: str,
    ) -> bool:
        """Persist click intent before the one permitted fixture action."""
        token_sha256 = hashlib.sha256(release_token.encode()).hexdigest()
        now = float(self._clock())
        with self.transaction() as conn:
            run = self._require_live_lease(conn, run_id, worker_id, now)
            self._assert_release_token(run, run_id, release_token)
            dispatch = conn.execute(
                "SELECT * FROM browser_submit_dispatches WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if (
                dispatch is None
                or str(dispatch["release_token_hash"]) != token_sha256
            ):
                raise ReleaseGateError("submit dispatch is absent or invalid")
            state = str(dispatch["state"])
            if state == "click_started":
                return False
            if state != "release_consumed":
                raise WorkflowError(
                    "submit click requires consumed release authority"
                )
            conn.execute(
                """UPDATE browser_submit_dispatches
                   SET state='click_started',updated_at=CURRENT_TIMESTAMP
                   WHERE run_id=?""",
                (run_id,),
            )
            return self._insert_event(
                conn,
                run_id=run_id,
                step_id=str(dispatch["step_id"]),
                event_type="submit_click_started",
                idempotency_key=f"browser-submit-click-started:{run_id}",
                payload={
                    "release_manifest_hash": str(
                        dispatch["release_manifest_hash"]
                    ),
                    "release_token_hash": token_sha256,
                },
                actor_kind="external",
            )

    def submit_dispatch(self, run_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM browser_submit_dispatches WHERE run_id=?",
                (run_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _require_live_lease(
        conn: sqlite3.Connection, run_id: str, worker_id: str, now: float
    ) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM browser_workflow_runs WHERE run_id=?", (run_id,)
        ).fetchone()
        if row is None:
            raise KeyError(run_id)
        if (
            row["status"] != "leased"
            or row["lease_owner"] != worker_id
            or float(row["lease_until_epoch"] or 0) < now
        ):
            raise LeaseError("worker does not own a live run lease")
        return row

    @staticmethod
    def _checkpoint_rows(conn: sqlite3.Connection, run_id: str) -> list[sqlite3.Row]:
        return conn.execute(
            """SELECT * FROM browser_workflow_checkpoints
               WHERE run_id=? ORDER BY action_index""",
            (run_id,),
        ).fetchall()

    @staticmethod
    def _assert_approved(
        action: BrowserAction, approved_values: Collection[ApprovedValue]
    ) -> None:
        if action.value_reference is None:
            return
        if not any(
            isinstance(approval, ApprovedValue)
            and approval.reference == action.value_reference
            for approval in approved_values
        ):
            raise ApprovalRequiredError(
                f"step {action.step_id} requires approved {action.value_reference.key}"
            )

    def _assert_release_token(
        self, row: sqlite3.Row, run_id: str, token: str | None
    ) -> None:
        if token is None:
            raise ReleaseGateError("final submit requires a release-gate token")
        expected = row["release_gate_hash"]
        if not expected or expected != self._release_hash(run_id, token):
            raise ReleaseGateError("release-gate token is absent or invalid")
        if row["release_gate_used_at"]:
            raise ReleaseGateError("release-gate token has already been consumed")

    def next_action(
        self,
        run_id: str,
        worker_id: str,
        *,
        approved_values: Collection[ApprovedValue] = (),
        release_gate_token: str | None = None,
    ) -> PendingAction | None:
        """Return only the first uncheckpointed action; no browser operation occurs here."""
        now = float(self._clock())
        with self.connection() as conn:
            row = self._require_live_lease(conn, run_id, worker_id, now)
            workflow = self._load_workflow(conn, str(row["workflow_hash"]))
            checkpoints = self._checkpoint_rows(conn, run_id)
            completed = {int(checkpoint["action_index"]) for checkpoint in checkpoints}
            next_index = next(
                (index for index in range(len(workflow.actions)) if index not in completed), None
            )
            if next_index is None:
                return None
            action = workflow.actions[next_index]
            self._assert_approved(action, approved_values)
            if action.kind is ActionKind.SUBMIT:
                self._assert_release_token(row, run_id, release_gate_token)
            prior_outputs = {
                str(checkpoint["step_id"]): json.loads(checkpoint["output_json"])
                for checkpoint in checkpoints
            }
            return PendingAction(
                run_id=run_id,
                workflow_hash=workflow.content_hash,
                action_index=next_index,
                action=action,
                prior_outputs=prior_outputs,
            )

    @staticmethod
    def _validate_selector_report(
        action: BrowserAction,
        report: SelectorRecoveryReport | None,
        *,
        require_success: bool,
    ) -> None:
        if action.selectors is None:
            if report is not None:
                raise WorkflowError("selector-free action cannot have a selector report")
            return
        if report is None:
            raise WorkflowError("selector action requires a selector report")
        if report.plan_hash != action.selectors.content_hash:
            raise WorkflowError("selector report belongs to a different selector plan")
        if require_success and not report.succeeded:
            raise WorkflowError("completed selector action requires a matched selector")
        if not require_success and (report.succeeded or not report.exhausted):
            raise WorkflowError("selector failure must report every candidate exhausted")

    def record_selector_failure(
        self,
        run_id: str,
        worker_id: str,
        *,
        step_id: str,
        report: SelectorRecoveryReport,
        idempotency_key: str,
    ) -> bool:
        """Append an idempotent failure report without advancing the checkpoint."""
        if not idempotency_key:
            raise ValueError("selector failure requires an idempotency key")
        now = float(self._clock())
        with self.transaction() as conn:
            row = self._require_live_lease(conn, run_id, worker_id, now)
            workflow = self._load_workflow(conn, str(row["workflow_hash"]))
            checkpoints = self._checkpoint_rows(conn, run_id)
            completed = {int(checkpoint["action_index"]) for checkpoint in checkpoints}
            next_index = next(index for index in range(len(workflow.actions)) if index not in completed)
            action = workflow.actions[next_index]
            if action.step_id != step_id:
                raise WorkflowError("selector failure is not for the next pending step")
            self._validate_selector_report(action, report, require_success=False)
            return self._insert_event(
                conn,
                run_id=run_id,
                step_id=step_id,
                event_type="selector_candidates_exhausted",
                idempotency_key=f"browser-selector-failure:{run_id}:{step_id}:{idempotency_key}",
                payload={"report": report.to_dict(), "lease_attempt": row["lease_attempts"]},
                actor_kind="external",
            )

    def complete_step(
        self,
        run_id: str,
        worker_id: str,
        *,
        step_id: str,
        result: StepResult,
        approved_values: Collection[ApprovedValue] = (),
        release_gate_token: str | None = None,
        submission_proof: SubmissionProof | None = None,
    ) -> bool:
        """Atomically checkpoint one step and advance, or return False for an exact retry."""
        if not isinstance(result, StepResult):
            raise TypeError("result must be a StepResult")
        output_json = _canonical_json(dict(result.outputs))
        report_json = (
            _canonical_json(result.selector_report.to_dict()) if result.selector_report else None
        )
        now = float(self._clock())
        with self.transaction() as conn:
            run = conn.execute(
                "SELECT * FROM browser_workflow_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if run is None:
                raise KeyError(run_id)
            workflow = self._load_workflow(conn, str(run["workflow_hash"]))
            matching = [
                (index, action)
                for index, action in enumerate(workflow.actions)
                if action.step_id == step_id
            ]
            if not matching:
                raise KeyError(step_id)
            action_index, action = matching[0]
            action_hash = _sha256(_canonical_json(action.to_dict()))
            existing = conn.execute(
                """SELECT action_hash,output_json,selector_report_json
                   FROM browser_workflow_checkpoints WHERE run_id=? AND action_index=?""",
                (run_id, action_index),
            ).fetchone()
            if existing is not None:
                if (
                    existing["action_hash"] == action_hash
                    and existing["output_json"] == output_json
                    and existing["selector_report_json"] == report_json
                ):
                    return False
                raise IdempotencyConflictError("completed step cannot be overwritten")

            run = self._require_live_lease(conn, run_id, worker_id, now)
            checkpoints = self._checkpoint_rows(conn, run_id)
            completed = {int(checkpoint["action_index"]) for checkpoint in checkpoints}
            next_index = next(index for index in range(len(workflow.actions)) if index not in completed)
            if action_index != next_index:
                raise WorkflowError("steps must complete in declared order")
            self._assert_approved(action, approved_values)
            missing_outputs = set(action.required_output_keys) - set(result.outputs)
            if missing_outputs:
                raise WorkflowError(f"step is missing required outputs: {sorted(missing_outputs)}")
            self._validate_selector_report(action, result.selector_report, require_success=True)
            if action.kind is ActionKind.SUBMIT:
                self._assert_release_token(run, run_id, release_gate_token)
                if submission_proof is None:
                    raise ReleaseGateError(
                        "final submit requires a canonical submission proof"
                    )
                dispatch = conn.execute(
                    """SELECT * FROM browser_submit_dispatches
                       WHERE run_id=?""",
                    (run_id,),
                ).fetchone()
                if (
                    dispatch is None
                    or str(dispatch["state"]) != "click_started"
                    or str(dispatch["step_id"]) != step_id
                    or str(dispatch["release_manifest_hash"])
                    != submission_proof.release_manifest_sha256
                    or str(dispatch["release_token_hash"])
                    != submission_proof.token_sha256
                    or str(dispatch["field_map_hash"])
                    != submission_proof.field_map_sha256
                ):
                    raise ReleaseGateError(
                        "submission proof differs from its durable dispatch"
                    )
                proof_outputs = {
                    "receipt_id": submission_proof.receipt_id,
                    "receipt_payload_sha256": (
                        submission_proof.receipt_payload_sha256
                    ),
                    "screenshot_sha256": (
                        submission_proof.screenshot_sha256
                    ),
                    "field_map_sha256": submission_proof.field_map_sha256,
                    "submit_event_sha256": (
                        submission_proof.submit_event_sha256
                    ),
                }
                if dict(result.outputs) != proof_outputs:
                    raise ReleaseGateError(
                        "submission outputs differ from their proof"
                    )
                expected_submit_event_sha256 = fixture_submit_event_sha256(
                    run_id=str(run["run_id"]),
                    workflow_sha256=str(run["workflow_hash"]),
                    step_id=step_id,
                    release_manifest_sha256=(
                        submission_proof.release_manifest_sha256
                    ),
                    receipt_id=submission_proof.receipt_id,
                    receipt_payload_sha256=(
                        submission_proof.receipt_payload_sha256
                    ),
                    screenshot_sha256=submission_proof.screenshot_sha256,
                    field_map_sha256=submission_proof.field_map_sha256,
                )
                if (
                    submission_proof.submit_event_sha256
                    != expected_submit_event_sha256
                ):
                    raise ReleaseGateError(
                        "submission event identity differs from its durable context"
                    )
            elif submission_proof is not None:
                raise WorkflowError(
                    "submission proof is valid only for a submit action"
                )

            conn.execute(
                """INSERT INTO browser_workflow_checkpoints(
                     run_id,action_index,step_id,action_hash,output_json,selector_report_json
                   ) VALUES(?,?,?,?,?,?)""",
                (run_id, action_index, step_id, action_hash, output_json, report_json),
            )
            self._insert_event(
                conn,
                run_id=run_id,
                step_id=step_id,
                event_type="step_completed",
                idempotency_key=f"browser-step-completed:{run_id}:{step_id}",
                payload={
                    "action_index": action_index,
                    "action_kind": action.kind.value,
                    "action_hash": action_hash,
                    "output_hash": _sha256(output_json),
                    "selector_recovered": bool(
                        result.selector_report and result.selector_report.recovered
                    ),
                },
                actor_kind="external",
            )
            is_final = action_index == len(workflow.actions) - 1
            if action.kind is ActionKind.SUBMIT:
                assert submission_proof is not None
                updated = conn.execute(
                    """UPDATE browser_submit_dispatches
                       SET state='receipt_recorded',receipt_id=?,
                           receipt_payload_hash=?,screenshot_hash=?,
                           submit_event_hash=?,updated_at=CURRENT_TIMESTAMP
                       WHERE run_id=? AND state='click_started'""",
                    (
                        submission_proof.receipt_id,
                        submission_proof.receipt_payload_sha256,
                        submission_proof.screenshot_sha256,
                        submission_proof.submit_event_sha256,
                        run_id,
                    ),
                ).rowcount
                if updated != 1:
                    raise ReleaseGateError(
                        "submission dispatch lost its receipt lease"
                    )
                conn.execute(
                    """UPDATE browser_workflow_runs SET release_gate_used_at=CURRENT_TIMESTAMP
                       WHERE run_id=?""",
                    (run_id,),
                )
                self._insert_event(
                    conn,
                    run_id=run_id,
                    step_id=step_id,
                    event_type="release_gate_consumed",
                    idempotency_key=f"browser-release-consumed:{run_id}",
                    payload={
                        "authorization_reference": run["release_authorization_reference"]
                    },
                )
            if is_final:
                conn.execute(
                    """UPDATE browser_workflow_runs SET status='completed',lease_owner=NULL,
                         lease_until_epoch=NULL,updated_at=CURRENT_TIMESTAMP WHERE run_id=?""",
                    (run_id,),
                )
                self._insert_event(
                    conn,
                    run_id=run_id,
                    event_type="run_completed",
                    idempotency_key=f"browser-run-completed:{run_id}",
                    payload={"checkpoint_count": len(workflow.actions)},
                )
            else:
                conn.execute(
                    "UPDATE browser_workflow_runs SET updated_at=CURRENT_TIMESTAMP WHERE run_id=?",
                    (run_id,),
                )
            return True

    def record_canary_terminal_observation(
        self,
        run_id: str,
        observation: CanaryTerminalObservation,
    ) -> bool:
        """Seal one terminal outcome; a final click is never success without provider proof."""
        if not isinstance(observation, CanaryTerminalObservation):
            raise TypeError("observation must be CanaryTerminalObservation")
        self._verify_canary_evidence_artifacts(observation.artifacts)
        document_json = _canonical_json(observation.to_dict())
        observation_sha256 = observation.content_sha256
        if observation_sha256 != _sha256(document_json):
            raise WorkflowError("terminal observation identity is inconsistent")
        with self.transaction() as conn:
            canary = conn.execute(
                "SELECT * FROM browser_canary_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if canary is None:
                raise KeyError(run_id)
            existing = conn.execute(
                """SELECT observation_sha256,document_json
                   FROM browser_canary_terminal_observations WHERE run_id=?""",
                (run_id,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["observation_sha256"]) == observation_sha256
                    and str(existing["document_json"]) == document_json
                ):
                    return False
                raise IdempotencyConflictError("terminal canary observation cannot be overwritten")
            if str(canary["state"]) != "active":
                raise WorkflowError("only an active canary may become terminal")
            if (
                str(canary["job_key"]) != observation.job_key
                or str(canary["vacancy_sha256"]) != observation.vacancy_sha256
            ):
                raise WorkflowError("terminal observation differs from canary vacancy authority")
            run = conn.execute(
                "SELECT * FROM browser_workflow_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if run is None:
                raise KeyError(run_id)
            dispatch = conn.execute(
                "SELECT * FROM browser_submit_dispatches WHERE run_id=?", (run_id,)
            ).fetchone()
            artifact_hashes = {artifact.sha256 for artifact in observation.artifacts}
            if observation.provider_screenshot_sha256 is not None and (
                observation.provider_screenshot_sha256 not in artifact_hashes
            ):
                raise WorkflowError("provider screenshot is absent from terminal evidence")
            if observation.provider_receipt_sha256 is not None and (
                observation.provider_receipt_sha256 not in artifact_hashes
            ):
                raise WorkflowError("provider receipt is absent from terminal evidence")
            if observation.provider_confirmed:
                if str(run["status"]) != "completed":
                    raise WorkflowError("provider-confirmed canary must be a completed workflow")
                if (
                    dispatch is None
                    or str(dispatch["state"]) != "receipt_recorded"
                    or str(dispatch["receipt_payload_hash"])
                    != observation.provider_receipt_sha256
                    or str(dispatch["screenshot_hash"])
                    != observation.provider_screenshot_sha256
                ):
                    raise WorkflowError("provider-confirmed outcome differs from submit receipt")
            else:
                if dispatch is not None and str(dispatch["state"]) == "receipt_recorded":
                    raise WorkflowError("recorded provider receipt cannot be relabelled as failure")
                if observation.final_click_attempted and (
                    dispatch is None or str(dispatch["state"]) != "click_started"
                ):
                    raise WorkflowError("final-click failure lacks a durable submit dispatch")
                if not observation.final_click_attempted and dispatch is not None and (
                    str(dispatch["state"]) in {"click_started", "receipt_recorded"}
                ):
                    raise WorkflowError("terminal observation omits a durable final-click attempt")
            conn.execute(
                """INSERT INTO browser_canary_terminal_observations(
                     observation_sha256,run_id,document_json
                   ) VALUES(?,?,?)""",
                (observation_sha256, run_id, document_json),
            )
            conn.execute(
                """UPDATE browser_canary_runs
                   SET state='terminal',terminal_observation_sha256=?,
                       updated_at=CURRENT_TIMESTAMP WHERE run_id=?""",
                (observation_sha256, run_id),
            )
            if not observation.provider_confirmed:
                status = (
                    "cancelled"
                    if observation.outcome is CanaryOutcomeKind.CANCELLED
                    else "failed"
                )
                conn.execute(
                    """UPDATE browser_workflow_runs
                       SET status=?,lease_owner=NULL,lease_until_epoch=NULL,
                           updated_at=CURRENT_TIMESTAMP WHERE run_id=?""",
                    (status, run_id),
                )
            self._insert_event(
                conn,
                run_id=run_id,
                event_type="canary_terminal_observation_recorded",
                idempotency_key=f"browser-canary-terminal:{run_id}",
                payload={
                    "observation_sha256": observation_sha256,
                    "stage": observation.stage.value,
                    "outcome": observation.outcome.value,
                    "provider_confirmed": observation.provider_confirmed,
                    "final_click_attempted": observation.final_click_attempted,
                },
                actor_kind="external",
            )
            return True

    def record_application_quality_review(
        self,
        run_id: str,
        review: ApplicationQualityReview,
    ) -> bool:
        """Seal the post-terminal quality review that controls next-canary admission."""
        if not isinstance(review, ApplicationQualityReview):
            raise TypeError("review must be ApplicationQualityReview")
        document_json = _canonical_json(review.to_dict())
        review_sha256 = review.content_sha256
        if review_sha256 != _sha256(document_json):
            raise WorkflowError("quality review identity is inconsistent")
        with self.transaction() as conn:
            canary = conn.execute(
                "SELECT * FROM browser_canary_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if canary is None:
                raise KeyError(run_id)
            existing = conn.execute(
                """SELECT review_sha256,document_json
                   FROM browser_application_quality_reviews WHERE run_id=?""",
                (run_id,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["review_sha256"]) == review_sha256
                    and str(existing["document_json"]) == document_json
                ):
                    return False
                raise IdempotencyConflictError("application quality review cannot be overwritten")
            if str(canary["state"]) != "terminal":
                raise WorkflowError("quality review requires a terminal canary")
            if str(canary["terminal_observation_sha256"]) != review.terminal_observation_sha256:
                raise WorkflowError("quality review differs from terminal observation")
            terminal_row = conn.execute(
                """SELECT document_json FROM browser_canary_terminal_observations
                   WHERE observation_sha256=? AND run_id=?""",
                (review.terminal_observation_sha256, run_id),
            ).fetchone()
            if terminal_row is None:
                raise WorkflowError("terminal observation authority is absent")
            try:
                terminal = json.loads(str(terminal_row["document_json"]))
            except json.JSONDecodeError as exc:
                raise WorkflowError("terminal observation is invalid JSON") from exc
            successful = bool(terminal.get("provider_confirmed"))
            if successful:
                required_hashes = (
                    review.application_source_sha256,
                    review.artifact_receipt_sha256,
                    review.cv_sha256,
                    review.field_answers_sha256,
                    review.form_inventory_sha256,
                    review.provider_receipt_sha256,
                )
                if any(value is None for value in required_hashes):
                    raise WorkflowError("submitted application review lacks exact content authority")
                if any(
                    value is None
                    for value in (
                        review.factual_accuracy_score,
                        review.role_targeting_score,
                        review.natural_voice_score,
                    )
                ):
                    raise WorkflowError("submitted application review lacks quality scores")
                if review.provider_receipt_sha256 != terminal.get("provider_receipt_sha256"):
                    raise WorkflowError("quality review differs from provider receipt")
                if review.disposition is QualityReviewDisposition.NOT_SUBMITTED:
                    raise WorkflowError("submitted application cannot be reviewed as not submitted")
            else:
                if review.disposition is not QualityReviewDisposition.NOT_SUBMITTED:
                    raise WorkflowError("non-submitted canary requires not_submitted review disposition")
                if review.provider_receipt_sha256 is not None:
                    raise WorkflowError("non-submitted review cannot claim a provider receipt")
            conn.execute(
                """INSERT INTO browser_application_quality_reviews(
                     review_sha256,run_id,terminal_observation_sha256,document_json
                   ) VALUES(?,?,?,?)""",
                (
                    review_sha256,
                    run_id,
                    review.terminal_observation_sha256,
                    document_json,
                ),
            )
            conn.execute(
                """UPDATE browser_canary_runs
                   SET state='reviewed',quality_review_sha256=?,updated_at=CURRENT_TIMESTAMP
                   WHERE run_id=?""",
                (review_sha256, run_id),
            )
            self._insert_event(
                conn,
                run_id=run_id,
                event_type="application_quality_review_recorded",
                idempotency_key=f"browser-application-quality-review:{run_id}",
                payload={
                    "review_sha256": review_sha256,
                    "terminal_observation_sha256": review.terminal_observation_sha256,
                    "disposition": review.disposition.value,
                    "release_blocking_issue_count": sum(
                        issue.release_blocking for issue in review.issues
                    ),
                },
                actor_kind="reviewer",
            )
            return True

    def canary_snapshot(self, run_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            canary = conn.execute(
                "SELECT * FROM browser_canary_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if canary is None:
                raise KeyError(run_id)
            result = dict(canary)
            terminal = conn.execute(
                """SELECT document_json FROM browser_canary_terminal_observations
                   WHERE run_id=?""",
                (run_id,),
            ).fetchone()
            review = conn.execute(
                """SELECT document_json FROM browser_application_quality_reviews
                   WHERE run_id=?""",
                (run_id,),
            ).fetchone()
            preflight = conn.execute(
                """SELECT document_json FROM browser_application_preflight_quality_reviews
                   WHERE run_id=? ORDER BY rowid DESC LIMIT 1""",
                (run_id,),
            ).fetchone()
        result["terminal_observation"] = (
            json.loads(str(terminal["document_json"])) if terminal is not None else None
        )
        result["quality_review"] = (
            json.loads(str(review["document_json"])) if review is not None else None
        )
        result["latest_preflight_quality_review"] = (
            json.loads(str(preflight["document_json"])) if preflight is not None else None
        )
        return result

    def checkpoint_outputs(self, run_id: str) -> dict[str, dict[str, Any]]:
        with self.connection() as conn:
            rows = self._checkpoint_rows(conn, run_id)
        return {str(row["step_id"]): json.loads(row["output_json"]) for row in rows}

    def replay_prefix(
        self,
        run_id: str,
        *,
        before_action_index: int,
    ) -> tuple[tuple[BrowserAction, StepResult], ...]:
        """Load and authenticate a contiguous checkpoint prefix for page replay."""
        if before_action_index < 1:
            raise WorkflowError("browser replay requires a checkpoint prefix")
        with self.connection() as conn:
            run = conn.execute(
                "SELECT workflow_hash FROM browser_workflow_runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise KeyError(run_id)
            workflow = self._load_workflow(
                conn,
                str(run["workflow_hash"]),
            )
            rows = self._checkpoint_rows(conn, run_id)
        indexes = tuple(int(row["action_index"]) for row in rows)
        if indexes != tuple(range(before_action_index)):
            raise WorkflowError(
                "browser replay checkpoints are not one contiguous prefix"
            )
        replay: list[tuple[BrowserAction, StepResult]] = []
        for row in rows:
            action = workflow.actions[int(row["action_index"])]
            action_hash = _sha256(_canonical_json(action.to_dict()))
            if (
                str(row["step_id"]) != action.step_id
                or str(row["action_hash"]) != action_hash
            ):
                raise WorkflowError(
                    "browser replay checkpoint differs from its workflow"
                )
            try:
                outputs = json.loads(str(row["output_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise WorkflowError(
                    "browser replay output is invalid JSON"
                ) from exc
            if (
                not isinstance(outputs, dict)
                or _canonical_json(outputs) != str(row["output_json"])
            ):
                raise WorkflowError("browser replay output is not canonical")
            report: SelectorRecoveryReport | None = None
            if row["selector_report_json"] is not None:
                if action.selectors is None:
                    raise WorkflowError(
                        "selector-free replay checkpoint has a report"
                    )
                try:
                    report_document = json.loads(
                        str(row["selector_report_json"])
                    )
                    outcomes = tuple(
                        SelectorOutcome(str(attempt["outcome"]))
                        for attempt in report_document["attempts"]
                    )
                except (
                    KeyError,
                    TypeError,
                    json.JSONDecodeError,
                    ValueError,
                ) as exc:
                    raise WorkflowError(
                        "browser replay selector report is invalid"
                    ) from exc
                report = action.selectors.assess(outcomes)
                if (
                    report.to_dict() != report_document
                    or _canonical_json(report_document)
                    != str(row["selector_report_json"])
                ):
                    raise WorkflowError(
                        "browser replay selector report is inconsistent"
                    )
            self._validate_selector_report(
                action,
                report,
                require_success=True,
            )
            replay.append((action, StepResult(outputs, report)))
        return tuple(replay)

    def run_snapshot(self, run_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM browser_workflow_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if row is None:
                raise KeyError(run_id)
            result = dict(row)
            result["checkpoint_count"] = conn.execute(
                "SELECT COUNT(*) FROM browser_workflow_checkpoints WHERE run_id=?", (run_id,)
            ).fetchone()[0]
            return result

    def events(self, run_id: str) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """SELECT * FROM browser_workflow_events
                   WHERE run_id=? ORDER BY id""",
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]
