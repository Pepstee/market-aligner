"""Deterministic, content-addressed JAA-08 release manifest contract.

This module can emit verdict data only. It has no browser, network, portal,
message, upload or submission capability.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from datetime import date
from typing import Iterable

from .evidence_matching import canonical_json


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_VALIDATORS = (
    "authority",
    "truth",
    "eligibility",
    "freshness",
    "consistency",
    "ats",
    "duplicate",
    "official_route",
)


def _required(value: str, label: str) -> str:
    clean = value.strip()
    if not clean:
        raise ValueError(f"{label} is required")
    return clean


def _digest(value: str, label: str) -> str:
    if not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class WorkRightBinding:
    jurisdiction: str
    contract_type: str
    record_id: str
    record_version: int
    verification_sha256: str
    valid_from: date
    valid_until: date
    permitted: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.jurisdiction, "work-right jurisdiction"),
            (self.contract_type, "work-right contract type"),
            (self.record_id, "work-right record ID"),
        ):
            _required(value, label)
        if self.record_version < 1:
            raise ValueError("work-right record version must be positive")
        _digest(self.verification_sha256, "work-right verification hash")
        if self.valid_until < self.valid_from:
            raise ValueError("work-right validity interval is invalid")

    def document(self) -> dict[str, object]:
        return {
            "jurisdiction": self.jurisdiction,
            "contract_type": self.contract_type,
            "record_id": self.record_id,
            "record_version": self.record_version,
            "verification_sha256": self.verification_sha256,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "permitted": self.permitted,
        }


@dataclass(frozen=True)
class OfficialRouteBinding:
    route_id: str
    adapter_id: str
    adapter_version: str
    source_identity: str
    route_policy_sha256: str
    verified_at: date
    valid_until: date
    allowed: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.route_id, "official route ID"),
            (self.adapter_id, "official route adapter ID"),
            (self.adapter_version, "official route adapter version"),
            (self.source_identity, "official route source identity"),
        ):
            _required(value, label)
        _digest(self.route_policy_sha256, "official route policy hash")
        if self.valid_until < self.verified_at:
            raise ValueError("official route validity interval is invalid")

    def document(self) -> dict[str, object]:
        return {
            "route_id": self.route_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "source_identity": self.source_identity,
            "route_policy_sha256": self.route_policy_sha256,
            "verified_at": self.verified_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "allowed": self.allowed,
        }


@dataclass(frozen=True)
class ReleaseBinding:
    """Exact release inputs; ``job_key`` is an opaque handle, not a digest."""

    job_key: str
    candidate_identity_sha256: str
    vacancy_sha256: str
    vacancy_observed_at: date
    vacancy_valid_until: date
    dossier_sha256: str
    candidate_profile_sha256: str
    strategy_id: str
    strategy_document_sha256: str
    application_source_id: str
    application_source_sha256: str
    artifact_set_sha256: str
    artifact_receipt_sha256: str
    deterministic_writer_policy_sha256: str
    model_receipt_sha256s: tuple[str, ...]
    work_right: WorkRightBinding
    official_route: OfficialRouteBinding
    evaluated_at: date
    prior_application_count: int

    def __post_init__(self) -> None:
        _required(self.job_key, "release job key")
        for value, label in (
            (self.candidate_identity_sha256, "candidate identity hash"),
            (self.vacancy_sha256, "vacancy hash"),
            (self.dossier_sha256, "dossier hash"),
            (self.candidate_profile_sha256, "candidate profile hash"),
            (self.strategy_id, "strategy ID"),
            (self.strategy_document_sha256, "strategy document hash"),
            (self.application_source_id, "application source ID"),
            (self.application_source_sha256, "application source hash"),
            (self.artifact_set_sha256, "artifact-set hash"),
            (self.artifact_receipt_sha256, "artifact receipt hash"),
            (
                self.deterministic_writer_policy_sha256,
                "deterministic writer policy hash",
            ),
        ):
            _digest(value, label)
        if (
            len(set(self.model_receipt_sha256s))
            != len(self.model_receipt_sha256s)
        ):
            raise ValueError("model receipt hashes must be unique")
        for value in self.model_receipt_sha256s:
            _digest(value, "model receipt hash")
        if self.vacancy_valid_until < self.vacancy_observed_at:
            raise ValueError("vacancy validity interval is invalid")
        if self.prior_application_count < 0:
            raise ValueError("prior application count cannot be negative")

    def document(self) -> dict[str, object]:
        return {
            "job_key": self.job_key,
            "candidate_identity_sha256": self.candidate_identity_sha256,
            "vacancy_sha256": self.vacancy_sha256,
            "vacancy_observed_at": self.vacancy_observed_at.isoformat(),
            "vacancy_valid_until": self.vacancy_valid_until.isoformat(),
            "dossier_sha256": self.dossier_sha256,
            "candidate_profile_sha256": self.candidate_profile_sha256,
            "strategy_id": self.strategy_id,
            "strategy_document_sha256": self.strategy_document_sha256,
            "application_source_id": self.application_source_id,
            "application_source_sha256": self.application_source_sha256,
            "artifact_set_sha256": self.artifact_set_sha256,
            "artifact_receipt_sha256": self.artifact_receipt_sha256,
            "deterministic_writer_policy_sha256": (
                self.deterministic_writer_policy_sha256
            ),
            "model_receipt_sha256s": self.model_receipt_sha256s,
            "work_right": self.work_right.document(),
            "official_route": self.official_route.document(),
            "evaluated_at": self.evaluated_at.isoformat(),
            "prior_application_count": self.prior_application_count,
        }

    @property
    def input_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json(self.document()).encode()
        ).hexdigest()


@dataclass(frozen=True)
class ValidationReceipt:
    validator_id: str
    validator_version: str
    validator_impl_sha256: str
    input_sha256: str
    artifact_set_sha256: str
    decision: str
    finding_codes: tuple[str, ...] = ()
    authority_kind: str = "deterministic"

    def __post_init__(self) -> None:
        if self.validator_id not in REQUIRED_VALIDATORS:
            raise ValueError("release validator ID is unsupported")
        if self.authority_kind != "deterministic":
            raise ValueError("only deterministic validators have release authority")
        _required(self.validator_version, "release validator version")
        for value, label in (
            (self.validator_impl_sha256, "validator implementation hash"),
            (self.input_sha256, "validator input hash"),
            (self.artifact_set_sha256, "validator artifact-set hash"),
        ):
            _digest(value, label)
        if self.decision not in {"pass", "block"}:
            raise ValueError("release validation decision is invalid")
        if self.decision == "pass" and self.finding_codes:
            raise ValueError("passing validator receipt cannot retain findings")
        if self.decision == "block" and not self.finding_codes:
            raise ValueError("blocking validator receipt requires findings")
        if (
            len(set(self.finding_codes)) != len(self.finding_codes)
            or any(not value.strip() for value in self.finding_codes)
        ):
            raise ValueError("validator findings must be unique reason codes")

    def document(self) -> dict[str, object]:
        return {
            "validator_id": self.validator_id,
            "validator_version": self.validator_version,
            "validator_impl_sha256": self.validator_impl_sha256,
            "input_sha256": self.input_sha256,
            "artifact_set_sha256": self.artifact_set_sha256,
            "decision": self.decision,
            "finding_codes": self.finding_codes,
            "authority_kind": self.authority_kind,
        }


@dataclass(frozen=True)
class ReleaseManifest:
    release_manifest_sha256: str
    input_sha256: str
    binding: ReleaseBinding
    validations: tuple[ValidationReceipt, ...]
    verdict: str
    schema_version: str = "jaa08.release-manifest.v1"
    certifies_slice: bool = False
    dependency_gate: str = "JAA-07"

    def __post_init__(self) -> None:
        if self.schema_version != "jaa08.release-manifest.v1":
            raise ValueError("unsupported release manifest schema")
        if self.certifies_slice is not False or self.dependency_gate != "JAA-07":
            raise ValueError("offline release manifest cannot certify JAA-08")
        _digest(self.release_manifest_sha256, "release manifest hash")
        _digest(self.input_sha256, "release manifest input hash")
        if self.verdict != "pass":
            raise ValueError("only passing inputs can produce a release manifest")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "input_sha256": self.input_sha256,
            "binding": self.binding.document(),
            "validations": [row.document() for row in self.validations],
            "verdict": self.verdict,
            "certifies_slice": False,
            "dependency_gate": "JAA-07",
        }
        if include_identity:
            result["release_manifest_sha256"] = self.release_manifest_sha256
        return result


def _deterministic_preconditions(binding: ReleaseBinding) -> None:
    if binding.evaluated_at < binding.vacancy_observed_at:
        raise ValueError("release evaluation predates the vacancy observation")
    if binding.evaluated_at > binding.vacancy_valid_until:
        raise ValueError("vacancy is stale at release evaluation")
    work_right = binding.work_right
    if (
        not work_right.permitted
        or binding.evaluated_at < work_right.valid_from
        or binding.evaluated_at > work_right.valid_until
    ):
        raise ValueError("current work right does not permit this release")
    route = binding.official_route
    if (
        not route.allowed
        or binding.evaluated_at < route.verified_at
        or binding.evaluated_at > route.valid_until
    ):
        raise ValueError("no current allowed official application route")
    if binding.prior_application_count:
        raise ValueError("duplicate application identity blocks release")


def compile_release_manifest(
    binding: ReleaseBinding,
    validations: Iterable[ValidationReceipt],
) -> ReleaseManifest:
    """Compile a pass verdict only when every deterministic gate agrees."""
    _deterministic_preconditions(binding)
    rows = tuple(validations)
    if tuple(row.validator_id for row in rows) != REQUIRED_VALIDATORS:
        raise ValueError("release validations are missing, duplicated or unordered")
    if len({row.validator_impl_sha256 for row in rows}) != len(rows):
        raise ValueError("release validators must have independent implementations")
    if any(
        row.input_sha256 != binding.input_sha256
        or row.artifact_set_sha256 != binding.artifact_set_sha256
        for row in rows
    ):
        raise ValueError("release validator receipt binds different inputs")
    blocked = tuple(
        finding
        for row in rows
        if row.decision != "pass"
        for finding in row.finding_codes
    )
    if blocked:
        raise ValueError(f"release validation blocked: {blocked}")
    provisional = ReleaseManifest(
        "0" * 64,
        binding.input_sha256,
        binding,
        rows,
        "pass",
    )
    manifest_hash = hashlib.sha256(
        canonical_json(provisional.document(include_identity=False)).encode()
    ).hexdigest()
    return replace(provisional, release_manifest_sha256=manifest_hash)


def verify_release_manifest(manifest: ReleaseManifest) -> None:
    if manifest.input_sha256 != manifest.binding.input_sha256:
        raise ValueError("release manifest input identity is inconsistent")
    expected = hashlib.sha256(
        canonical_json(manifest.document(include_identity=False)).encode()
    ).hexdigest()
    if manifest.release_manifest_sha256 != expected:
        raise ValueError("release manifest differs from its exact content")
    replay = compile_release_manifest(manifest.binding, manifest.validations)
    if replay != manifest:
        raise ValueError("release manifest deterministic replay differs")
