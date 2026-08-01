"""Provisional versioned JAA interface; contains no protected implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from market_aligner.profiler.schema import validate_profile_id


JAA_HANDOFF_VERSION = "market-aligner.jaa-handoff.v0"
JAA_EVENT_VERSION = "market-aligner.jaa-event.v0"

APPLICATION_EVENTS = frozenset(
    {
        "strategy_started",
        "artifacts_ready",
        "release_blocked",
        "release_ready",
        "submission_authorized",
        "submission_attempted",
        "receipt_captured",
        "status_changed",
        "outcome_recorded",
    }
)


def _sha256(value: str | None, label: str, *, required: bool = True) -> None:
    if value is None and not required:
        return
    if value is None or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class ApplicationHandoff:
    profile_id: str
    profile_version: str
    job_key: str
    vacancy_snapshot_sha256: str
    evidence_ledger_sha256: str
    eligibility_receipt_sha256: str
    assessment_receipt_sha256: str
    employer_dossier_sha256: str | None
    fit_status: str
    fit: float
    opportunity: float
    created_at: str
    schema_version: str = JAA_HANDOFF_VERSION

    def __post_init__(self) -> None:
        validate_profile_id(self.profile_id)
        if self.schema_version != JAA_HANDOFF_VERSION:
            raise ValueError("unsupported provisional JAA handoff version")
        for name in (
            "vacancy_snapshot_sha256",
            "evidence_ledger_sha256",
            "eligibility_receipt_sha256",
            "assessment_receipt_sha256",
        ):
            _sha256(getattr(self, name), name)
        _sha256(self.employer_dossier_sha256, "employer_dossier_sha256", required=False)
        if self.fit_status != "uncalibrated":
            raise ValueError("pre-calibration handoffs must say fit_status=uncalibrated")
        for name in ("fit", "opportunity"):
            if not 0 <= float(getattr(self, name)) <= 1:
                raise ValueError(f"{name} must be in [0,1]")


@dataclass(frozen=True)
class ApplicationEvent:
    application_id: str
    profile_id: str
    job_key: str
    event_type: str
    occurred_at: str
    idempotency_key: str
    payload_sha256: str
    external_receipt_sha256: str | None = None
    operator_approval_sha256: str | None = None
    schema_version: str = JAA_EVENT_VERSION

    def __post_init__(self) -> None:
        validate_profile_id(self.profile_id)
        if self.schema_version != JAA_EVENT_VERSION:
            raise ValueError("unsupported provisional JAA event version")
        if self.event_type not in APPLICATION_EVENTS:
            raise ValueError(f"unsupported application event: {self.event_type}")
        _sha256(self.payload_sha256, "payload_sha256")
        _sha256(self.external_receipt_sha256, "external_receipt_sha256", required=False)
        _sha256(self.operator_approval_sha256, "operator_approval_sha256", required=False)
        if self.event_type == "submission_authorized" and self.operator_approval_sha256 is None:
            raise ValueError("submission authorization requires an operator approval receipt")
        if self.event_type == "receipt_captured" and self.external_receipt_sha256 is None:
            raise ValueError("receipt_captured requires the external receipt hash")


class JAAClient(Protocol):
    """Adapter implemented only after a sealed upstream contract is reconciled."""

    def create_application(self, handoff: ApplicationHandoff) -> str: ...

    def events(self, application_id: str, after: str | None = None) -> list[ApplicationEvent]: ...

    def acknowledge(self, event: ApplicationEvent) -> None: ...


def handoff_payload(handoff: ApplicationHandoff) -> Mapping[str, Any]:
    return handoff.__dict__
