"""Deterministic JAA-16 release-readiness contracts.

This module can describe and assess a candidate for independent review.  It
cannot install, distribute, activate, release, deploy or certify anything.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime

from career_automation.operations import (
    FROZEN_OPERATIONS_CONTRACT,
    DrillSuiteAssessment,
    OperationsPlan,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_PRIOR_SLICES = tuple(f"JAA-{number:02d}" for number in range(16))
REQUIRED_RELEASE_EVIDENCE = (
    "actual_machine_walking_skeleton",
    "accessibility",
    "backup",
    "clean_mac_install",
    "commercial_documentation",
    "distributable_package",
    "entitlement_seam",
    "licensing",
    "local_first_onboarding",
    "operator_activation_runbook",
    "privacy_controls",
    "provider_fallback",
    "runtime_failure_drills",
    "uninstall",
    "upgrade",
    "weekly_and_daily_reports",
)
PRE_JAA16_MANIFEST_SHA256 = (
    "7e201c01de15d50ed7b6f2b4d0760f0d023302cdb7290a57b34f2079a4101ace"
)
RELEASE_REASON_ORDER = (
    "missing_prior_slice_certification",
    "duplicate_prior_slice_certification",
    "missing_release_evidence",
    "duplicate_release_evidence",
    "unverified_release_evidence",
    "operations_plan_dependency_unsatisfied",
    "drill_suite_failed",
    "drill_runtime_not_independently_verified",
    "distributable_contamination",
)


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
    if not isinstance(value, str):
        raise ValueError(f"{label} is required")
    clean = value.strip()
    if not clean or clean != value:
        raise ValueError(
            f"{label} is required without surrounding whitespace"
        )
    return clean


def _aware(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"{label} must be timezone-aware")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


def _aware_iso(value: str, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an aware ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an aware ISO timestamp") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.isoformat() != value
    ):
        raise ValueError(f"{label} must use canonical aware ISO form")
    return parsed


@dataclass(frozen=True)
class ReleaseCertificationContract:
    operations_contract_sha256: str
    pre_slice_manifest_sha256: str
    required_prior_slices: tuple[str, ...]
    required_release_evidence: tuple[str, ...]
    release_authority: str = "withheld"
    distribution_authority: str = "withheld"
    entitlement_activation_authority: str = "withheld"
    production_certification: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa16.release-certification-contract.v1"

    def __post_init__(self) -> None:
        if (
            self.operations_contract_sha256
            != FROZEN_OPERATIONS_CONTRACT.contract_sha256
            or self.pre_slice_manifest_sha256
            != PRE_JAA16_MANIFEST_SHA256
            or self.required_prior_slices != REQUIRED_PRIOR_SLICES
            or self.required_release_evidence != REQUIRED_RELEASE_EVIDENCE
            or self.release_authority != "withheld"
            or self.distribution_authority != "withheld"
            or self.entitlement_activation_authority != "withheld"
            or self.production_certification != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version
            != "jaa16.release-certification-contract.v1"
        ):
            raise ValueError("local release contract cannot release or certify")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "operations_contract_sha256": self.operations_contract_sha256,
            "pre_slice_manifest_sha256": self.pre_slice_manifest_sha256,
            "required_prior_slices": self.required_prior_slices,
            "required_release_evidence": self.required_release_evidence,
            "release_authority": "withheld",
            "distribution_authority": "withheld",
            "entitlement_activation_authority": "withheld",
            "production_certification": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_RELEASE_CERTIFICATION_CONTRACT = ReleaseCertificationContract(
    operations_contract_sha256=FROZEN_OPERATIONS_CONTRACT.contract_sha256,
    pre_slice_manifest_sha256=PRE_JAA16_MANIFEST_SHA256,
    required_prior_slices=REQUIRED_PRIOR_SLICES,
    required_release_evidence=REQUIRED_RELEASE_EVIDENCE,
)


@dataclass(frozen=True)
class PriorSliceCertification:
    contract_sha256: str
    slice_id: str
    source_git_revision: str
    source_tree_sha256: str
    source_content_revision: str
    receipt_sha256: str
    independent_ruling_sha256: str
    certification_status: str
    certification_id: str
    schema_version: str = "jaa16.prior-slice-certification.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "slice_id": self.slice_id,
            "source_git_revision": self.source_git_revision,
            "source_tree_sha256": self.source_tree_sha256,
            "source_content_revision": self.source_content_revision,
            "receipt_sha256": self.receipt_sha256,
            "independent_ruling_sha256": self.independent_ruling_sha256,
            "certification_status": self.certification_status,
        }
        if include_identity:
            result["certification_id"] = self.certification_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "prior-slice contract hash"),
            (self.source_git_revision, "prior-slice Git revision"),
            (self.source_tree_sha256, "prior-slice tree hash"),
            (self.source_content_revision, "prior-slice content revision"),
            (self.receipt_sha256, "prior-slice receipt hash"),
            (
                self.independent_ruling_sha256,
                "prior-slice independent ruling hash",
            ),
            (self.certification_id, "prior-slice certification ID"),
        ):
            _digest(value, label)
        if (
            self.contract_sha256
            != FROZEN_RELEASE_CERTIFICATION_CONTRACT.contract_sha256
            or self.slice_id not in REQUIRED_PRIOR_SLICES
            or self.certification_status != "independently_certified"
            or self.schema_version != "jaa16.prior-slice-certification.v1"
        ):
            raise ValueError("prior slice lacks exact independent certification")
        if self.certification_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("prior-slice certification identity is invalid")


def record_prior_slice_certification(
    contract: ReleaseCertificationContract,
    *,
    slice_id: str,
    source_git_revision: str,
    source_tree_sha256: str,
    source_content_revision: str,
    receipt_sha256: str,
    independent_ruling_sha256: str,
    certification_status: str,
) -> PriorSliceCertification:
    if contract != FROZEN_RELEASE_CERTIFICATION_CONTRACT:
        raise ValueError("prior slice requires the canonical release contract")
    body = {
        "schema_version": "jaa16.prior-slice-certification.v1",
        "contract_sha256": contract.contract_sha256,
        "slice_id": slice_id,
        "source_git_revision": source_git_revision,
        "source_tree_sha256": source_tree_sha256,
        "source_content_revision": source_content_revision,
        "receipt_sha256": receipt_sha256,
        "independent_ruling_sha256": independent_ruling_sha256,
        "certification_status": certification_status,
    }
    return PriorSliceCertification(
        **body,
        certification_id=_content_hash(body),
    )


@dataclass(frozen=True)
class ReleaseEvidenceReference:
    contract_sha256: str
    evidence_kind: str
    artifact_version: str
    environment: str
    evidence_sha256: str
    observed_at: str
    independently_verified: bool
    evidence_id: str
    schema_version: str = "jaa16.release-evidence-reference.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "evidence_kind": self.evidence_kind,
            "artifact_version": self.artifact_version,
            "environment": self.environment,
            "evidence_sha256": self.evidence_sha256,
            "observed_at": self.observed_at,
            "independently_verified": self.independently_verified,
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "release evidence contract hash"),
            (self.evidence_sha256, "release evidence hash"),
            (self.evidence_id, "release evidence ID"),
        ):
            _digest(value, label)
        for value, label in (
            (self.artifact_version, "artifact version"),
            (self.environment, "release evidence environment"),
        ):
            _required(value, label)
        _aware_iso(self.observed_at, "release evidence time")
        if (
            self.contract_sha256
            != FROZEN_RELEASE_CERTIFICATION_CONTRACT.contract_sha256
            or self.evidence_kind not in REQUIRED_RELEASE_EVIDENCE
            or type(self.independently_verified) is not bool
            or self.schema_version != "jaa16.release-evidence-reference.v1"
        ):
            raise ValueError("release evidence reference is invalid")
        if self.evidence_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("release evidence identity is invalid")


def record_release_evidence_reference(
    contract: ReleaseCertificationContract,
    *,
    evidence_kind: str,
    artifact_version: str,
    environment: str,
    evidence_sha256: str,
    observed_at: datetime,
    independently_verified: bool,
) -> ReleaseEvidenceReference:
    if contract != FROZEN_RELEASE_CERTIFICATION_CONTRACT:
        raise ValueError("evidence requires the canonical release contract")
    observed = _aware(observed_at, "release evidence time")
    body = {
        "schema_version": "jaa16.release-evidence-reference.v1",
        "contract_sha256": contract.contract_sha256,
        "evidence_kind": evidence_kind,
        "artifact_version": artifact_version,
        "environment": environment,
        "evidence_sha256": evidence_sha256,
        "observed_at": observed.isoformat(),
        "independently_verified": independently_verified,
    }
    return ReleaseEvidenceReference(**body, evidence_id=_content_hash(body))


@dataclass(frozen=True)
class DistributionScan:
    contract_sha256: str
    artifact_version: str
    artifact_sha256: str
    person_specific_items: int
    test_data_items: int
    claim_items: int
    credential_items: int
    host_path_items: int
    scanner_report_sha256: str
    scanned_at: str
    scan_id: str
    schema_version: str = "jaa16.distribution-scan.v1"

    def __post_init__(self) -> None:
        self.verify()

    @property
    def is_clean(self) -> bool:
        return not any((
            self.person_specific_items,
            self.test_data_items,
            self.claim_items,
            self.credential_items,
            self.host_path_items,
        ))

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "artifact_version": self.artifact_version,
            "artifact_sha256": self.artifact_sha256,
            "person_specific_items": self.person_specific_items,
            "test_data_items": self.test_data_items,
            "claim_items": self.claim_items,
            "credential_items": self.credential_items,
            "host_path_items": self.host_path_items,
            "scanner_report_sha256": self.scanner_report_sha256,
            "scanned_at": self.scanned_at,
        }
        if include_identity:
            result["scan_id"] = self.scan_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "distribution-scan contract hash"),
            (self.artifact_sha256, "distribution artifact hash"),
            (self.scanner_report_sha256, "scanner report hash"),
            (self.scan_id, "distribution scan ID"),
        ):
            _digest(value, label)
        _required(self.artifact_version, "distribution artifact version")
        for value in (
            self.person_specific_items,
            self.test_data_items,
            self.claim_items,
            self.credential_items,
            self.host_path_items,
        ):
            if type(value) is not int or value < 0:
                raise ValueError("distribution counts must be non-negative")
        _aware_iso(self.scanned_at, "distribution scan time")
        if (
            self.contract_sha256
            != FROZEN_RELEASE_CERTIFICATION_CONTRACT.contract_sha256
            or self.schema_version != "jaa16.distribution-scan.v1"
        ):
            raise ValueError("distribution scan contract is invalid")
        if self.scan_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("distribution scan identity is invalid")


def record_distribution_scan(
    contract: ReleaseCertificationContract,
    *,
    artifact_version: str,
    artifact_sha256: str,
    person_specific_items: int,
    test_data_items: int,
    claim_items: int,
    credential_items: int,
    host_path_items: int,
    scanner_report_sha256: str,
    scanned_at: datetime,
) -> DistributionScan:
    if contract != FROZEN_RELEASE_CERTIFICATION_CONTRACT:
        raise ValueError("scan requires the canonical release contract")
    observed = _aware(scanned_at, "distribution scan time")
    body = {
        "schema_version": "jaa16.distribution-scan.v1",
        "contract_sha256": contract.contract_sha256,
        "artifact_version": artifact_version,
        "artifact_sha256": artifact_sha256,
        "person_specific_items": person_specific_items,
        "test_data_items": test_data_items,
        "claim_items": claim_items,
        "credential_items": credential_items,
        "host_path_items": host_path_items,
        "scanner_report_sha256": scanner_report_sha256,
        "scanned_at": observed.isoformat(),
    }
    return DistributionScan(**body, scan_id=_content_hash(body))


@dataclass(frozen=True)
class ReleaseCandidate:
    contract_sha256: str
    artifact_version: str
    artifact_sha256: str
    operations_plan: OperationsPlan
    drill_assessment: DrillSuiteAssessment
    prior_certifications: tuple[PriorSliceCertification, ...]
    release_evidence: tuple[ReleaseEvidenceReference, ...]
    distribution_scan: DistributionScan
    candidate_id: str
    release_authority: str = "withheld"
    distribution_authority: str = "withheld"
    entitlement_activation_authority: str = "withheld"
    schema_version: str = "jaa16.release-candidate.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "artifact_version": self.artifact_version,
            "artifact_sha256": self.artifact_sha256,
            "operations_plan": self.operations_plan.document(),
            "drill_assessment": self.drill_assessment.document(),
            "prior_certifications": tuple(
                row.document() for row in self.prior_certifications
            ),
            "release_evidence": tuple(
                row.document() for row in self.release_evidence
            ),
            "distribution_scan": self.distribution_scan.document(),
            "release_authority": "withheld",
            "distribution_authority": "withheld",
            "entitlement_activation_authority": "withheld",
        }
        if include_identity:
            result["candidate_id"] = self.candidate_id
        return result

    def verify(self) -> None:
        _digest(self.contract_sha256, "candidate contract hash")
        _digest(self.artifact_sha256, "candidate artifact hash")
        _digest(self.candidate_id, "release candidate ID")
        _required(self.artifact_version, "candidate artifact version")
        if not isinstance(self.operations_plan, OperationsPlan):
            raise TypeError("candidate requires a typed operations plan")
        if not isinstance(self.drill_assessment, DrillSuiteAssessment):
            raise TypeError("candidate requires a typed drill assessment")
        if not isinstance(self.distribution_scan, DistributionScan):
            raise TypeError("candidate requires a typed distribution scan")
        if not all(
            isinstance(row, PriorSliceCertification)
            for row in self.prior_certifications
        ):
            raise TypeError("candidate requires typed prior certifications")
        if not all(
            isinstance(row, ReleaseEvidenceReference)
            for row in self.release_evidence
        ):
            raise TypeError("candidate requires typed release evidence")
        self.operations_plan.verify()
        self.drill_assessment.verify()
        self.distribution_scan.verify()
        for row in self.prior_certifications:
            row.verify()
        for row in self.release_evidence:
            row.verify()
        if (
            self.drill_assessment.plan_id != self.operations_plan.plan_id
            or self.distribution_scan.artifact_version
            != self.artifact_version
            or self.distribution_scan.artifact_sha256 != self.artifact_sha256
        ):
            raise ValueError("release candidate mixes plan or artifact inputs")
        if (
            self.contract_sha256
            != FROZEN_RELEASE_CERTIFICATION_CONTRACT.contract_sha256
            or self.release_authority != "withheld"
            or self.distribution_authority != "withheld"
            or self.entitlement_activation_authority != "withheld"
            or self.schema_version != "jaa16.release-candidate.v1"
        ):
            raise ValueError("local release candidate cannot release")
        if self.candidate_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("release candidate identity is invalid")


def compile_release_candidate(
    contract: ReleaseCertificationContract,
    *,
    artifact_version: str,
    artifact_sha256: str,
    operations_plan: OperationsPlan,
    drill_assessment: DrillSuiteAssessment,
    prior_certifications: tuple[PriorSliceCertification, ...],
    release_evidence: tuple[ReleaseEvidenceReference, ...],
    distribution_scan: DistributionScan,
) -> ReleaseCandidate:
    if contract != FROZEN_RELEASE_CERTIFICATION_CONTRACT:
        raise ValueError("candidate requires the canonical release contract")
    ordered_prior = tuple(
        sorted(prior_certifications, key=lambda row: row.slice_id)
    )
    ordered_evidence = tuple(
        sorted(release_evidence, key=lambda row: row.evidence_kind)
    )
    body = {
        "schema_version": "jaa16.release-candidate.v1",
        "contract_sha256": contract.contract_sha256,
        "artifact_version": artifact_version,
        "artifact_sha256": artifact_sha256,
        "operations_plan": operations_plan.document(),
        "drill_assessment": drill_assessment.document(),
        "prior_certifications": tuple(
            row.document() for row in ordered_prior
        ),
        "release_evidence": tuple(
            row.document() for row in ordered_evidence
        ),
        "distribution_scan": distribution_scan.document(),
        "release_authority": "withheld",
        "distribution_authority": "withheld",
        "entitlement_activation_authority": "withheld",
    }
    return ReleaseCandidate(
        contract_sha256=contract.contract_sha256,
        artifact_version=artifact_version,
        artifact_sha256=artifact_sha256,
        operations_plan=operations_plan,
        drill_assessment=drill_assessment,
        prior_certifications=ordered_prior,
        release_evidence=ordered_evidence,
        distribution_scan=distribution_scan,
        candidate_id=_content_hash(body),
    )


@dataclass(frozen=True)
class ReleaseAssessment:
    candidate: ReleaseCandidate
    contract_sha256: str
    candidate_id: str
    reason_codes: tuple[str, ...]
    eligible_for_independent_release_review: bool
    release_certificate_id: None
    released: bool
    assessment_id: str
    release_authority: str = "withheld"
    distribution_authority: str = "withheld"
    entitlement_activation_authority: str = "withheld"
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa16.release-assessment.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result = {
            "schema_version": self.schema_version,
            "candidate": self.candidate.document(),
            "contract_sha256": self.contract_sha256,
            "candidate_id": self.candidate_id,
            "reason_codes": self.reason_codes,
            "eligible_for_independent_release_review": (
                self.eligible_for_independent_release_review
            ),
            "release_certificate_id": None,
            "released": False,
            "release_authority": "withheld",
            "distribution_authority": "withheld",
            "entitlement_activation_authority": "withheld",
            "production_certification": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["assessment_id"] = self.assessment_id
        return result

    def verify(self) -> None:
        derived = _expected_release_assessment_fields(self.candidate)
        _digest(self.contract_sha256, "release-assessment contract hash")
        _digest(self.candidate_id, "assessed candidate ID")
        _digest(self.assessment_id, "release assessment ID")
        expected_reasons = tuple(
            reason
            for reason in RELEASE_REASON_ORDER
            if reason in self.reason_codes
        )
        if expected_reasons != self.reason_codes:
            raise ValueError("release-assessment reasons are invalid")
        if (
            type(self.eligible_for_independent_release_review) is not bool
            or self.eligible_for_independent_release_review
            is not (not self.reason_codes)
            or self.release_certificate_id is not None
            or self.released is not False
            or self.contract_sha256
            != FROZEN_RELEASE_CERTIFICATION_CONTRACT.contract_sha256
            or self.release_authority != "withheld"
            or self.distribution_authority != "withheld"
            or self.entitlement_activation_authority != "withheld"
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
            or self.schema_version != "jaa16.release-assessment.v1"
        ):
            raise ValueError("local release assessment cannot release or certify")
        if {key: getattr(self, key) for key in derived} != derived:
            raise ValueError(
                "release assessment differs from its typed candidate"
            )
        if self.assessment_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("release assessment identity is invalid")


def _expected_release_assessment_fields(
    candidate: ReleaseCandidate,
) -> dict[str, object]:
    if not isinstance(candidate, ReleaseCandidate):
        raise TypeError("assessment requires a typed release candidate")
    candidate.verify()
    reasons: list[str] = []
    prior_ids = tuple(row.slice_id for row in candidate.prior_certifications)
    evidence_kinds = tuple(
        row.evidence_kind for row in candidate.release_evidence
    )
    if set(prior_ids) != set(REQUIRED_PRIOR_SLICES):
        reasons.append("missing_prior_slice_certification")
    if len(prior_ids) != len(set(prior_ids)):
        reasons.append("duplicate_prior_slice_certification")
    if set(evidence_kinds) != set(REQUIRED_RELEASE_EVIDENCE):
        reasons.append("missing_release_evidence")
    if len(evidence_kinds) != len(set(evidence_kinds)):
        reasons.append("duplicate_release_evidence")
    if any(
        not row.independently_verified for row in candidate.release_evidence
    ):
        reasons.append("unverified_release_evidence")
    if not candidate.operations_plan.dependency_satisfied:
        reasons.append("operations_plan_dependency_unsatisfied")
    if not candidate.drill_assessment.eligible_for_independent_runtime_review:
        reasons.append("drill_suite_failed")
    drill_evidence = {
        row.evidence_kind: row
        for row in candidate.release_evidence
    }.get("runtime_failure_drills")
    if drill_evidence is None or not drill_evidence.independently_verified:
        reasons.append("drill_runtime_not_independently_verified")
    if not candidate.distribution_scan.is_clean:
        reasons.append("distributable_contamination")
    reason_codes = tuple(
        reason for reason in RELEASE_REASON_ORDER if reason in reasons
    )
    return {
        "contract_sha256": FROZEN_RELEASE_CERTIFICATION_CONTRACT.contract_sha256,
        "candidate_id": candidate.candidate_id,
        "reason_codes": reason_codes,
        "eligible_for_independent_release_review": not reason_codes,
        "release_certificate_id": None,
        "released": False,
    }


def assess_release_candidate(
    contract: ReleaseCertificationContract,
    candidate: ReleaseCandidate,
) -> ReleaseAssessment:
    if contract != FROZEN_RELEASE_CERTIFICATION_CONTRACT:
        raise ValueError("assessment requires the canonical release contract")
    if not isinstance(candidate, ReleaseCandidate):
        raise TypeError("assessment requires a typed release candidate")
    candidate.verify()
    reasons: list[str] = []
    prior_ids = tuple(row.slice_id for row in candidate.prior_certifications)
    evidence_kinds = tuple(
        row.evidence_kind for row in candidate.release_evidence
    )
    if set(prior_ids) != set(REQUIRED_PRIOR_SLICES):
        reasons.append("missing_prior_slice_certification")
    if len(prior_ids) != len(set(prior_ids)):
        reasons.append("duplicate_prior_slice_certification")
    if set(evidence_kinds) != set(REQUIRED_RELEASE_EVIDENCE):
        reasons.append("missing_release_evidence")
    if len(evidence_kinds) != len(set(evidence_kinds)):
        reasons.append("duplicate_release_evidence")
    if any(
        not row.independently_verified for row in candidate.release_evidence
    ):
        reasons.append("unverified_release_evidence")
    if not candidate.operations_plan.dependency_satisfied:
        reasons.append("operations_plan_dependency_unsatisfied")
    if not candidate.drill_assessment.eligible_for_independent_runtime_review:
        reasons.append("drill_suite_failed")
    drill_evidence = {
        row.evidence_kind: row
        for row in candidate.release_evidence
    }.get("runtime_failure_drills")
    if drill_evidence is None or not drill_evidence.independently_verified:
        reasons.append("drill_runtime_not_independently_verified")
    if not candidate.distribution_scan.is_clean:
        reasons.append("distributable_contamination")
    reason_codes = tuple(
        reason for reason in RELEASE_REASON_ORDER if reason in reasons
    )
    body = {
        "schema_version": "jaa16.release-assessment.v1",
        "candidate": candidate.document(),
        "contract_sha256": contract.contract_sha256,
        "candidate_id": candidate.candidate_id,
        "reason_codes": reason_codes,
        "eligible_for_independent_release_review": not reason_codes,
        "release_certificate_id": None,
        "released": False,
        "release_authority": "withheld",
        "distribution_authority": "withheld",
        "entitlement_activation_authority": "withheld",
        "production_certification": "withheld",
        "certifies_slice": False,
    }
    return ReleaseAssessment(
        candidate=candidate,
        contract_sha256=contract.contract_sha256,
        candidate_id=candidate.candidate_id,
        reason_codes=reason_codes,
        eligible_for_independent_release_review=not reason_codes,
        release_certificate_id=None,
        released=False,
        assessment_id=_content_hash(body),
    )
