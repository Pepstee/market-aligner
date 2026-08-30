"""Explicitly release-blocked inspection adapter for provisional v0 records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from market_aligner.applications.canonical import ContractValidationError, require_sha256
from market_aligner.profiler.schema import validate_profile_id


LEGACY_JAA_HANDOFF_VERSION = "market-aligner.jaa-handoff.v0"
LEGACY_JAA_EVENT_VERSION = "market-aligner.jaa-event.v0"
LEGACY_APPLICATION_EVENTS = frozenset(
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


@dataclass(frozen=True)
class LegacyV0ApplicationHandoff:
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
    schema_version: str = LEGACY_JAA_HANDOFF_VERSION

    def __post_init__(self) -> None:
        validate_profile_id(self.profile_id)
        if self.schema_version != LEGACY_JAA_HANDOFF_VERSION:
            raise ContractValidationError("legacy adapter accepts only jaa-handoff.v0")
        for name in (
            "vacancy_snapshot_sha256",
            "evidence_ledger_sha256",
            "eligibility_receipt_sha256",
            "assessment_receipt_sha256",
        ):
            require_sha256(getattr(self, name), name)
        require_sha256(
            self.employer_dossier_sha256, "employer_dossier_sha256", nullable=True
        )
        if self.fit_status != "uncalibrated":
            raise ContractValidationError("legacy fit must remain uncalibrated")
        for name in ("fit", "opportunity"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
                raise ContractValidationError(f"legacy {name} must be in [0,1]")

    @property
    def admission_kind(self) -> str:
        return "legacy_v0"

    @property
    def verified_v1(self) -> bool:
        return False

    @property
    def release_blocked(self) -> bool:
        return True


@dataclass(frozen=True)
class LegacyV0ApplicationEvent:
    application_id: str
    profile_id: str
    job_key: str
    event_type: str
    occurred_at: str
    idempotency_key: str
    payload_sha256: str
    external_receipt_sha256: str | None = None
    operator_approval_sha256: str | None = None
    schema_version: str = LEGACY_JAA_EVENT_VERSION

    def __post_init__(self) -> None:
        validate_profile_id(self.profile_id)
        if self.schema_version != LEGACY_JAA_EVENT_VERSION:
            raise ContractValidationError("legacy adapter accepts only jaa-event.v0")
        if self.event_type not in LEGACY_APPLICATION_EVENTS:
            raise ContractValidationError("unsupported legacy application event")
        require_sha256(self.payload_sha256, "payload_sha256")
        require_sha256(
            self.external_receipt_sha256, "external_receipt_sha256", nullable=True
        )
        require_sha256(
            self.operator_approval_sha256, "operator_approval_sha256", nullable=True
        )
        if (
            self.event_type == "submission_authorized"
            and self.operator_approval_sha256 is None
        ):
            raise ContractValidationError(
                "legacy submission authorization requires an operator approval receipt"
            )
        if (
            self.event_type == "receipt_captured"
            and self.external_receipt_sha256 is None
        ):
            raise ContractValidationError(
                "legacy receipt_captured requires an external receipt hash"
            )


@dataclass(frozen=True)
class LegacyV0Inspection:
    handoff: LegacyV0ApplicationHandoff
    admission_kind: str = "legacy_v0"
    verified_v1: bool = False
    release_blocked: bool = True


def parse_legacy_v0_handoff_for_inspection(
    payload: Mapping[str, Any],
) -> LegacyV0Inspection:
    """Parse a v0 mapping for inspection only; no v0-to-v1 promotion exists."""

    expected = set(LegacyV0ApplicationHandoff.__dataclass_fields__)
    actual = set(payload)
    if actual != expected:
        raise ContractValidationError(
            f"legacy v0 keys differ; missing={sorted(expected-actual)}, extra={sorted(actual-expected)}"
        )
    return LegacyV0Inspection(LegacyV0ApplicationHandoff(**dict(payload)))
