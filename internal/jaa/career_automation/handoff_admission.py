"""Authenticated, typed and atomic Market Aligner handoff admission.

The wire digest proves integrity only.  Production trust is supplied by a
configured context authenticator and a configured typed resolver; direct bytes
are available solely through the explicitly named synthetic-test entry point.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from .current_time import (
    AuthenticatedCurrentTimeWitness,
    AuthenticatedTimeEvidence,
    CurrentTimeWitnessError,
    obtain_current_time,
    validate_current_time_witness_configuration,
)
from .engine import scored_job_from_payload
from .market_aligner_handoff import (
    CANDIDATE_INTENT_SCHEMA,
    CONTRACT_BUNDLE_SHA256,
    HANDOFF_SCHEMA,
    MAX_SAFE_INTEGER,
    MAX_WIRE_BYTES,
    HandoffContractError,
    ParsedHandoff,
    canonical_json_bytes,
    decode_canonical_json,
    parse_handoff,
)
from .migrations import apply_jaa_operational_migrations

VERIFICATION_SCHEMA = "jaa.market-aligner-handoff-verification.v1"
FORWARD_VALIDATION_SCHEMA = "jaa.market-aligner-forward-validation.v1"
LEGACY_VERIFICATION_SCHEMA = "jaa.legacy-scored-jsonl-admission.v1"
ADMISSION_KIND_V1 = "market_aligner_handoff_v1"
ADMISSION_KIND_COMPATIBILITY = "base_v1_compatibility"
ADMISSION_KIND_LEGACY = "legacy_scored_jsonl"
AUTHENTICATED_TRUST_MODES = frozenset(
    {"protected_local_outbox", "authenticated_attestation"}
)
BOUNDARIES = frozenset(
    {"strategy", "review", "release_readiness", "authority", "executor"}
)
RELEASE_BOUNDARIES = frozenset({"release_readiness", "authority", "executor"})

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PROFILE = re.compile(r"^prf_[0-9a-f]{32}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_GEOGRAPHY = (
    {"rank": 1, "region_code": "UK", "work_mode": "remote"},
    {"rank": 2, "region_code": "UK", "work_mode": "hybrid"},
    {"rank": 3, "region_code": "UK", "work_mode": "onsite"},
    {"rank": 4, "region_code": "RO", "work_mode": "remote"},
    {"rank": 5, "region_code": "EU", "work_mode": "remote"},
)


class HandoffAdmissionError(ValueError):
    """Stable fail-closed taxonomy for trust, replay and persistence failures."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        pointer: str = "$",
        reference_key: str | None = None,
    ) -> None:
        prefix = f"{code} at {pointer}"
        if reference_key is not None:
            prefix += f" [{reference_key}]"
        super().__init__(f"{prefix}: {message}")
        self.code = code
        self.message = message
        self.pointer = pointer
        self.reference_key = reference_key


@dataclass(frozen=True)
class ReferenceSpec:
    reference_key: str
    type_id: str
    schema_version: str
    subject_keys: tuple[str, ...]
    freshness_class: str


REFERENCE_REGISTRY: Mapping[str, ReferenceSpec] = {
    "candidate_intent": ReferenceSpec(
        "candidate_intent",
        "candidate_intent",
        CANDIDATE_INTENT_SCHEMA,
        ("profile_id", "profile_version"),
        "active_revision",
    ),
    "candidate_intent.authority_source": ReferenceSpec(
        "candidate_intent.authority_source",
        "candidate_authority_source",
        "market-aligner.candidate-authority-source.v1",
        ("profile_id", "profile_version"),
        "valid_interval",
    ),
    "evidence_ledger": ReferenceSpec(
        "evidence_ledger",
        "evidence_ledger",
        "market-aligner.evidence-ledger.v1",
        ("profile_id", "profile_version"),
        "active_revision",
    ),
    "eligibility.receipt": ReferenceSpec(
        "eligibility.receipt",
        "eligibility_receipt",
        "market-aligner.eligibility-receipt.v1",
        ("profile_id", "profile_version", "job_key", "vacancy_snapshot_sha256"),
        "valid_interval",
    ),
    "assessment.receipt": ReferenceSpec(
        "assessment.receipt",
        "assessment_receipt",
        "market-aligner.assessment-receipt.v1",
        ("profile_id", "profile_version", "job_key", "vacancy_snapshot_sha256"),
        "valid_interval",
    ),
    "assessment.scoring_parameters": ReferenceSpec(
        "assessment.scoring_parameters",
        "scoring_parameters",
        "market-aligner.scoring-parameters.v1",
        (),
        "immutable",
    ),
    "vacancy.location.facts": ReferenceSpec(
        "vacancy.location.facts",
        "location_facts",
        "market-aligner.location-facts.v1",
        ("job_key", "vacancy_snapshot_sha256"),
        "vacancy_age",
    ),
    "vacancy.raw_listing": ReferenceSpec(
        "vacancy.raw_listing",
        "raw_listing",
        "market-aligner.raw-listing-evidence.v1",
        ("job_key", "vacancy_snapshot_sha256"),
        "vacancy_age",
    ),
    "vacancy.requirements": ReferenceSpec(
        "vacancy.requirements",
        "requirement_projection",
        "market-aligner.requirement-projection.v1",
        ("job_key", "vacancy_snapshot_sha256"),
        "vacancy_age",
    ),
    "vacancy.snapshot": ReferenceSpec(
        "vacancy.snapshot",
        "vacancy_snapshot",
        "market-aligner.vacancy-snapshot.v1",
        ("job_key", "vacancy_snapshot_sha256"),
        "vacancy_age",
    ),
    "selection.policy": ReferenceSpec(
        "selection.policy",
        "selection_policy",
        "market-aligner.selection-policy.v1",
        (),
        "policy_interval",
    ),
    "selection.receipt": ReferenceSpec(
        "selection.receipt",
        "selection_receipt",
        "market-aligner.selection-receipt.v1",
        ("profile_id", "profile_version", "job_key", "vacancy_snapshot_sha256"),
        "valid_interval",
    ),
    "employer_dossier": ReferenceSpec(
        "employer_dossier",
        "employer_dossier",
        "market-aligner.employer-dossier.v1",
        ("job_key", "vacancy_snapshot_sha256"),
        "dossier_age",
    ),
}


@dataclass(frozen=True)
class SelectionPolicyRules:
    clock_skew_seconds: int
    maximum_vacancy_age_seconds: int
    maximum_dossier_age_seconds: int
    employer_dossier_required: bool

    def __post_init__(self) -> None:
        values = (
            self.clock_skew_seconds,
            self.maximum_vacancy_age_seconds,
            self.maximum_dossier_age_seconds,
        )
        if any(
            type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER
            for value in values
        ):
            raise ValueError(
                "selection-policy intervals must be safe non-negative integers"
            )
        if type(self.employer_dossier_required) is not bool:
            raise ValueError("selection-policy dossier requirement must be boolean")

    def document(self) -> dict[str, object]:
        return {
            "clock_skew_seconds": self.clock_skew_seconds,
            "employer_dossier_required": self.employer_dossier_required,
            "maximum_dossier_age_seconds": self.maximum_dossier_age_seconds,
            "maximum_vacancy_age_seconds": self.maximum_vacancy_age_seconds,
        }


@dataclass(frozen=True)
class ReferenceRequest:
    sha256: str
    spec: ReferenceSpec
    expected_subject: Mapping[str, str]
    handoff_created_at: str
    evaluated_at: str


@dataclass(frozen=True)
class ResolvedReference:
    """A resolver returns only exact object bytes plus exact registry metadata."""

    exact_bytes: bytes
    metadata_bytes: bytes


class AdmissionContextAuthenticator(Protocol):
    authenticator_identity_sha256: str

    def authenticate(
        self,
        *,
        context_bytes: bytes,
        handoff_bytes: bytes,
        evaluated_at: str,
    ) -> None:
        """Authenticate the configured trust root/proof and producer allowlist."""


class TrustedHandoffResolver(Protocol):
    resolver_identity_sha256: str

    def resolve(self, request: ReferenceRequest) -> ResolvedReference:
        """Resolve through a configured protected store."""

    def authenticate(
        self,
        *,
        metadata_bytes: bytes,
        exact_bytes: bytes,
        admission_context_bytes: bytes | None,
        evaluated_at: str,
    ) -> None:
        """Authenticate the metadata trust proof against configured state."""


class ProtectedLocalOutbox:
    """Concrete no-secret trust adapter for one pinned MA outbox bundle.

    Integrity comes from content addressing; authority comes from the consumer
    configuration pinning the exact source-record digest and producer commit,
    plus a private local directory inaccessible to group/other writers.
    """

    def __init__(
        self,
        bundle_path: str | Path,
        *,
        repository_root: str | Path,
        expected_source_record_sha256: str,
        allowed_producer_commits: frozenset[str],
        bundle_descriptor: int | None = None,
    ) -> None:
        supplied_bundle = Path(bundle_path)
        self._bundle_descriptor = (
            None if bundle_descriptor is None else os.dup(bundle_descriptor)
        )
        if self._bundle_descriptor is None:
            self.bundle_path = supplied_bundle.resolve(strict=True)
        else:
            metadata = os.fstat(self._bundle_descriptor)
            current = supplied_bundle.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_dev != current.st_dev
                or metadata.st_ino != current.st_ino
            ):
                os.close(self._bundle_descriptor)
                self._bundle_descriptor = None
                raise HandoffAdmissionError(
                    "outbox_permissions", "pinned bundle identity differs"
                )
            self.bundle_path = supplied_bundle.absolute()
        repository = Path(repository_root).resolve(strict=True)
        if repository == self.bundle_path or repository in self.bundle_path.parents:
            raise HandoffAdmissionError(
                "outbox_location",
                "protected handoff bundle must be outside the repository",
            )
        _digest(expected_source_record_sha256, "expected source record")
        if not allowed_producer_commits or any(
            not _COMMIT.fullmatch(value) for value in allowed_producer_commits
        ):
            raise HandoffAdmissionError(
                "outbox_configuration", "producer commit allowlist is invalid"
            )
        self.expected_source_record_sha256 = expected_source_record_sha256
        self.allowed_producer_commits = allowed_producer_commits
        self._assert_private_tree()
        self._manifest_bytes = self._read("manifest.json")
        self._manifest = self._decode(self._manifest_bytes, "outbox manifest")
        if (
            set(self._manifest)
            != {
                "context_sha256",
                "handoff_root_sha256",
                "schema_version",
                "source_record_sha256",
            }
            or self._manifest.get("schema_version")
            != "market-aligner.protected-handoff-bundle.v1"
        ):
            raise HandoffAdmissionError(
                "outbox_manifest", "outbox manifest schema differs"
            )
        self._source_record_bytes = self._read("source-record.json")
        if (
            hashlib.sha256(self._source_record_bytes).hexdigest()
            != expected_source_record_sha256
        ):
            raise HandoffAdmissionError(
                "outbox_pin", "source record differs from configured pin"
            )
        self._source_record = self._decode(
            self._source_record_bytes, "outbox source record"
        )
        if self._manifest.get("source_record_sha256") != expected_source_record_sha256:
            raise HandoffAdmissionError("outbox_pin", "manifest source record differs")
        if (
            self._source_record.get("producer_commit_sha")
            not in allowed_producer_commits
        ):
            raise HandoffAdmissionError(
                "outbox_producer", "producer commit is not allowed"
            )
        rows = self._source_record.get("entries")
        if not isinstance(rows, list) or not rows:
            raise HandoffAdmissionError(
                "outbox_manifest", "source record has no entries"
            )
        self._entries = {
            str(row["reference_key"]): dict(row)
            for row in rows
            if isinstance(row, dict)
            and set(row) == {"metadata_sha256", "object_sha256", "reference_key"}
        }
        if len(self._entries) != len(rows):
            raise HandoffAdmissionError(
                "outbox_manifest", "source record entries are ambiguous"
            )
        identity = {
            "allowed_producer_commits": sorted(allowed_producer_commits),
            "source_record_sha256": expected_source_record_sha256,
            "trust_root_id": self._source_record.get("trust_root_id"),
        }
        self.authenticator_identity_sha256 = hashlib.sha256(
            canonical_json_bytes({"kind": "protected-local-outbox-context", **identity})
        ).hexdigest()
        self.resolver_identity_sha256 = hashlib.sha256(
            canonical_json_bytes(
                {"kind": "protected-local-outbox-resolver", **identity}
            )
        ).hexdigest()

    @staticmethod
    def _decode(value: bytes, label: str) -> dict[str, Any]:
        try:
            document = decode_canonical_json(value, label=label)
        except HandoffContractError as exc:
            raise HandoffAdmissionError("outbox_bytes", exc.message) from exc
        if type(document) is not dict:
            raise HandoffAdmissionError("outbox_schema", f"{label} must be an object")
        return document

    def close(self) -> None:
        if self._bundle_descriptor is not None:
            os.close(self._bundle_descriptor)
            self._bundle_descriptor = None

    def _assert_private_tree(self) -> None:
        if self._bundle_descriptor is not None:
            metadata = os.fstat(self._bundle_descriptor)
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise HandoffAdmissionError(
                    "outbox_permissions", "pinned bundle is not private"
                )
            return
        current = self.bundle_path
        while True:
            metadata = current.lstat()
            if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise HandoffAdmissionError(
                    "outbox_permissions", "outbox path is not a real directory"
                )
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise HandoffAdmissionError(
                    "outbox_permissions", "outbox is group/other writable"
                )
            if current == current.parent:
                break
            # The bundle and its content-addressed parent are the protected
            # boundary; generic ancestors such as /tmp are outside that boundary.
            if current.name == "bundles":
                break
            current = current.parent

    def _read(self, relative: str) -> bytes:
        if self._bundle_descriptor is not None:
            parts = Path(relative).parts
            if not parts or len(parts) > 2 or ".." in parts:
                raise HandoffAdmissionError(
                    "outbox_permissions", "outbox relative path is invalid"
                )
            parent_descriptor = os.dup(self._bundle_descriptor)
            try:
                if len(parts) == 2:
                    next_descriptor = os.open(
                        parts[0],
                        os.O_RDONLY
                        | os.O_DIRECTORY
                        | os.O_CLOEXEC
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent_descriptor,
                    )
                    os.close(parent_descriptor)
                    parent_descriptor = next_descriptor
                    category = os.fstat(parent_descriptor)
                    if (
                        category.st_uid != os.geteuid()
                        or stat.S_IMODE(category.st_mode) != 0o700
                    ):
                        raise HandoffAdmissionError(
                            "outbox_permissions", "outbox category is not private"
                        )
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                descriptor = os.open(parts[-1], flags, dir_fd=parent_descriptor)
            except OSError as exc:
                raise HandoffAdmissionError(
                    "outbox_missing", f"outbox object is absent: {relative}"
                ) from exc
            finally:
                os.close(parent_descriptor)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise HandoffAdmissionError(
                        "outbox_permissions", "outbox file is not private"
                    )
                chunks: list[bytes] = []
                remaining = MAX_WIRE_BYTES + 1
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 65536))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                value = b"".join(chunks)
                if not value or len(value) > MAX_WIRE_BYTES:
                    raise HandoffAdmissionError(
                        "outbox_bytes", "outbox file size is invalid"
                    )
                return value
            finally:
                os.close(descriptor)
        path = self.bundle_path / relative
        if path.is_symlink():
            raise HandoffAdmissionError(
                "outbox_permissions", "outbox files cannot be symlinks"
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise HandoffAdmissionError(
                "outbox_missing", f"outbox object is absent: {relative}"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise HandoffAdmissionError(
                    "outbox_permissions", "outbox file is not private"
                )
            value = os.read(descriptor, MAX_WIRE_BYTES + 1)
            if not value or len(value) > MAX_WIRE_BYTES:
                raise HandoffAdmissionError(
                    "outbox_bytes", "outbox file size is invalid"
                )
            return value
        finally:
            os.close(descriptor)

    @property
    def handoff_bytes(self) -> bytes:
        value = self._read("handoff.json")
        if hashlib.sha256(value).hexdigest() != self._manifest["handoff_root_sha256"]:
            raise HandoffAdmissionError(
                "outbox_handoff", "handoff differs from manifest"
            )
        return value

    @property
    def context_bytes(self) -> bytes:
        value = self._read("context.json")
        if hashlib.sha256(value).hexdigest() != self._manifest["context_sha256"]:
            raise HandoffAdmissionError(
                "outbox_context", "context differs from manifest"
            )
        return value

    def authenticate(
        self,
        *,
        context_bytes: bytes | None = None,
        handoff_bytes: bytes | None = None,
        metadata_bytes: bytes | None = None,
        exact_bytes: bytes | None = None,
        admission_context_bytes: bytes | None = None,
        evaluated_at: str,
    ) -> None:
        del evaluated_at
        if context_bytes is not None and handoff_bytes is not None:
            if (
                context_bytes != self.context_bytes
                or handoff_bytes != self.handoff_bytes
            ):
                raise HandoffAdmissionError(
                    "outbox_context", "admission bytes differ from pinned bundle"
                )
            context = self._decode(context_bytes, "outbox context")
            basis = dict(context)
            proof = basis.pop("trust_proof_sha256", None)
            if (
                context.get("source_record_sha256")
                != self.expected_source_record_sha256
                or context.get("producer_commit_sha")
                not in self.allowed_producer_commits
                or proof != hashlib.sha256(canonical_json_bytes(basis)).hexdigest()
            ):
                raise HandoffAdmissionError("outbox_context", "context proof differs")
            return
        if (
            metadata_bytes is None
            or exact_bytes is None
            or admission_context_bytes is None
        ):
            raise HandoffAdmissionError(
                "outbox_authentication", "authentication inputs are incomplete"
            )
        metadata = self._decode(metadata_bytes, "outbox reference metadata")
        context = self._decode(admission_context_bytes, "outbox context")
        basis = dict(metadata)
        proof = basis.pop("trust_proof_sha256", None)
        basis.update(
            {
                "handoff_root_sha256": context["handoff_root_sha256"],
                "producer_commit_sha": context["producer_commit_sha"],
            }
        )
        if (
            hashlib.sha256(exact_bytes).hexdigest() != metadata.get("object_sha256")
            or proof != hashlib.sha256(canonical_json_bytes(basis)).hexdigest()
        ):
            raise HandoffAdmissionError("outbox_reference", "reference proof differs")

    def resolve(self, request: ReferenceRequest) -> ResolvedReference:
        try:
            row = self._entries[request.spec.reference_key]
        except KeyError as exc:
            raise FileNotFoundError(request.spec.reference_key) from exc
        if row["object_sha256"] != request.sha256:
            raise HandoffAdmissionError(
                "outbox_reference", "reference object digest differs"
            )
        exact = self._read(f"objects/{row['object_sha256']}")
        metadata = self._read(f"metadata/{row['metadata_sha256']}")
        if hashlib.sha256(metadata).hexdigest() != row["metadata_sha256"]:
            raise HandoffAdmissionError(
                "outbox_reference", "reference metadata digest differs"
            )
        return ResolvedReference(exact, metadata)


@dataclass(frozen=True)
class VerifiedReference:
    reference_key: str
    type_id: str
    schema_version: str
    referenced_sha256: str
    resolved_bytes_sha256: str
    byte_length: int
    subject: Mapping[str, str]
    issued_at: str
    valid_until: str | None
    freshness_class: str
    issuer_id: str
    trust_root_id: str
    trust_proof_sha256: str
    metadata_bytes: bytes
    metadata_sha256: str
    resolver_identity_sha256: str

    def document(self) -> dict[str, object]:
        return {
            "byte_length": self.byte_length,
            "freshness_class": self.freshness_class,
            "issued_at": self.issued_at,
            "issuer_id": self.issuer_id,
            "metadata_sha256": self.metadata_sha256,
            "reference_key": self.reference_key,
            "referenced_sha256": self.referenced_sha256,
            "resolved_bytes_sha256": self.resolved_bytes_sha256,
            "resolver_identity_sha256": self.resolver_identity_sha256,
            "schema_version": self.schema_version,
            "subject": dict(self.subject),
            "trust_proof_sha256": self.trust_proof_sha256,
            "trust_root_id": self.trust_root_id,
            "type_id": self.type_id,
            "valid_until": self.valid_until,
        }


@dataclass(frozen=True)
class VerifiedGraph:
    references: tuple[VerifiedReference, ...]
    objects: Mapping[str, bytes]
    policy_rules: SelectionPolicyRules
    candidate_authority_sha256: str


@dataclass(frozen=True)
class HandoffAdmission:
    application_id: str
    admission_kind: str
    environment: str
    authority_scope: str
    emission_profile: str | None
    handoff_root_sha256: str | None
    job_key: str
    profile_id: str | None
    profile_version: str | None
    vacancy_source_identity: str
    verification_receipt_sha256: str
    created: bool

    @property
    def release_capable(self) -> bool:
        return self.admission_kind == ADMISSION_KIND_V1 and self.authority_scope in {
            "production",
            "synthetic",
        }


@dataclass(frozen=True)
class VerifiedApplicationInput:
    application_id: str
    admission_kind: str
    environment: str
    authority_scope: str
    handoff_root_sha256: str
    vacancy_source_identity: str
    profile_id: str
    profile_version: str
    candidate_authority_sha256: str
    job_key: str
    vacancy_snapshot_sha256: str
    raw_listing_sha256: str
    raw_listing_bytes: bytes
    requirements_sha256: str
    requirements_bytes: bytes
    canonical_url: str
    company_name: str
    role_title: str
    location: Mapping[str, object]
    admission_receipt_sha256: str
    current_boundary: str
    current_boundary_receipt_sha256: str
    source_job_key: str = ""
    source_observed_at: str = ""
    assessment_receipt_sha256: str = ""
    assessment_receipt_bytes: bytes = b""
    eligibility_receipt_sha256: str = ""
    eligibility_receipt_bytes: bytes = b""
    selection_receipt_sha256: str = ""
    selection_receipt_bytes: bytes = b""


def _verified_market_decision_references(
    graph: VerifiedGraph, handoff: ParsedHandoff
) -> dict[str, object]:
    """Project exact MA decision objects from the freshly verified graph."""

    exact = {
        "assessment": graph.objects["assessment.receipt"],
        "eligibility": graph.objects["eligibility.receipt"],
        "selection": graph.objects["selection.receipt"],
    }
    try:
        documents = {name: json.loads(value) for name, value in exact.items()}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoffAdmissionError(
            "market_decision_object", "verified Market decision object is not JSON"
        ) from exc
    assessment = documents["assessment"]
    eligibility = documents["eligibility"]
    selection = documents["selection"]
    integrated_shape = (
        isinstance(assessment, dict)
        and assessment.get("schema_version")
        == "market-aligner.assessment-promotion-receipt.v1"
    )
    source_keys = (
        assessment.get("job_key") if isinstance(assessment, dict) else None,
        eligibility.get("source_job_key") if isinstance(eligibility, dict) else None,
        selection.get("source_job_key") if isinstance(selection, dict) else None,
    )
    if not integrated_shape:
        source_keys = (None, None, None)
    if all(value is None for value in source_keys):
        source_job_key = ""
    elif (
        not all(isinstance(value, str) and value for value in source_keys)
        or len(set(source_keys)) != 1
    ):
        raise HandoffAdmissionError(
            "market_decision_job_key",
            "verified Market decision objects disagree on source job key",
        )
    else:
        source_job_key = str(source_keys[0])
    payload = handoff.payload
    vacancy = payload["vacancy"]
    provenance = vacancy["provenance"]
    return {
        "assessment_receipt_bytes": exact["assessment"],
        "assessment_receipt_sha256": payload["assessment"]["assessment_receipt_sha256"],
        "eligibility_receipt_bytes": exact["eligibility"],
        "eligibility_receipt_sha256": payload["eligibility"]["eligibility_receipt_sha256"],
        "selection_receipt_bytes": exact["selection"],
        "selection_receipt_sha256": payload["selection"]["selection_receipt_sha256"],
        "source_job_key": source_job_key,
        "source_observed_at": str(provenance.get("observed_at", "")),
    }


@dataclass(frozen=True)
class VerifiedDownstreamResult:
    application_id: str
    vacancy_source_identity: str
    application_source_identity: str
    artifact_set_sha256: str
    cv_pdf_sha256: str
    cover_letter_pdf_sha256: str
    form_answers_sha256: str
    employer_assessment_receipt_sha256: str


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise HandoffAdmissionError(
            "invalid_digest", f"{label} must be lowercase SHA-256"
        )
    return value


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise HandoffAdmissionError(
            "invalid_identity", f"{label} must be non-empty and trimmed"
        )
    return value


def _timestamp(value: object, label: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise HandoffAdmissionError(
            "invalid_timestamp", f"{label} must be whole-second UTC"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise HandoffAdmissionError(
            "invalid_timestamp", f"{label} is not a real instant"
        ) from exc
    return value, parsed


def _handoff_timestamp(value: object, label: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", value
    ):
        raise HandoffAdmissionError(
            "invalid_timestamp", f"{label} must be RFC 3339 UTC"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise HandoffAdmissionError(
            "invalid_timestamp", f"{label} is not a real instant"
        ) from exc
    return value, parsed


def _evaluation_time(value: datetime | None) -> tuple[str, datetime]:
    evaluated = value or datetime.now(timezone.utc).replace(microsecond=0)
    if evaluated.tzinfo is None or evaluated.utcoffset() is None:
        raise HandoffAdmissionError(
            "invalid_timestamp", "evaluation time must be timezone-aware"
        )
    evaluated = evaluated.astimezone(timezone.utc)
    if evaluated.microsecond:
        raise HandoffAdmissionError(
            "invalid_timestamp", "evaluation time must be whole-second"
        )
    return evaluated.strftime("%Y-%m-%dT%H:%M:%SZ"), evaluated


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise HandoffAdmissionError(
            "schema_mismatch", f"{label} must contain exactly {sorted(keys)}"
        )
    return value


def _context_document(
    context_bytes: bytes,
    handoff: ParsedHandoff,
    authenticator: AdmissionContextAuthenticator,
    evaluated_at: str,
) -> tuple[dict[str, Any], str, str]:
    try:
        decoded_context = decode_canonical_json(
            context_bytes, label="admission context"
        )
    except HandoffContractError as exc:
        raise HandoffAdmissionError(
            "context_bytes", exc.message, pointer=exc.pointer
        ) from exc
    document = _exact_mapping(
        decoded_context,
        {
            "environment",
            "handoff_root_sha256",
            "issued_at",
            "producer_commit_sha",
            "producer_product",
            "source_record_sha256",
            "trust_mode",
            "trust_proof_sha256",
            "trust_root_id",
        },
        "admission context",
    )
    if document["environment"] not in {"production", "synthetic"}:
        raise HandoffAdmissionError(
            "context_environment", "context environment is unsupported"
        )
    if document["trust_mode"] not in AUTHENTICATED_TRUST_MODES:
        raise HandoffAdmissionError(
            "context_trust_mode", "context trust mode is unsupported"
        )
    if document["producer_product"] != "market-aligner":
        raise HandoffAdmissionError(
            "context_producer", "context producer must be market-aligner"
        )
    if not isinstance(document["producer_commit_sha"], str) or not _COMMIT.fullmatch(
        document["producer_commit_sha"]
    ):
        raise HandoffAdmissionError(
            "context_producer", "context producer commit is malformed"
        )
    for key in ("handoff_root_sha256", "source_record_sha256", "trust_proof_sha256"):
        _digest(document[key], f"context {key}")
    _identity(document["trust_root_id"], "context trust root")
    _, issued = _timestamp(document["issued_at"], "context issued_at")
    _, admitted = _timestamp(evaluated_at, "admission time")
    if issued > admitted:
        raise HandoffAdmissionError(
            "context_future", "context was issued after admission"
        )
    if document["handoff_root_sha256"] != handoff.root_sha256:
        raise HandoffAdmissionError(
            "context_root_swap", "context binds a different handoff root"
        )
    if (
        document["producer_product"] != handoff.payload["producer"]["product"]
        or document["producer_commit_sha"] != handoff.payload["producer"]["commit_sha"]
    ):
        raise HandoffAdmissionError(
            "context_producer_swap", "context producer differs from handoff"
        )
    authenticator_identity = _digest(
        getattr(authenticator, "authenticator_identity_sha256", None),
        "context authenticator identity",
    )
    try:
        authenticator.authenticate(
            context_bytes=context_bytes,
            handoff_bytes=handoff.original_bytes,
            evaluated_at=evaluated_at,
        )
    except HandoffAdmissionError:
        raise
    except Exception as exc:
        raise HandoffAdmissionError(
            "context_authentication_failed",
            "configured context authenticator rejected the proof",
        ) from exc
    return document, hashlib.sha256(context_bytes).hexdigest(), authenticator_identity


def _candidate_intent(exact_bytes: bytes, handoff: ParsedHandoff) -> str:
    try:
        decoded_intent = decode_canonical_json(exact_bytes, label="candidate intent")
    except HandoffContractError as exc:
        raise HandoffAdmissionError(
            "candidate_intent_bytes",
            exc.message,
            pointer=exc.pointer,
            reference_key="candidate_intent",
        ) from exc
    document = _exact_mapping(
        decoded_intent,
        {
            "authority_revision",
            "authority_source_sha256",
            "created_at",
            "geography_priority",
            "profile_id",
            "profile_version",
            "role_track_ids",
            "schema_version",
        },
        "candidate intent",
    )
    if document["schema_version"] != CANDIDATE_INTENT_SCHEMA:
        raise HandoffAdmissionError(
            "candidate_intent_schema", "candidate intent version differs"
        )
    if (
        type(document["authority_revision"]) is not int
        or not 1 <= document["authority_revision"] <= MAX_SAFE_INTEGER
    ):
        raise HandoffAdmissionError(
            "candidate_intent_revision", "authority revision is invalid"
        )
    _handoff_timestamp(document["created_at"], "candidate intent created_at")
    if tuple(document["geography_priority"]) != _GEOGRAPHY:
        raise HandoffAdmissionError(
            "candidate_intent_geography", "normative geography order differs"
        )
    if (
        document["profile_id"] != handoff.payload["profile_id"]
        or document["profile_version"] != handoff.payload["profile_version"]
    ):
        raise HandoffAdmissionError("profile_swap", "candidate intent profile differs")
    roles = document["role_track_ids"]
    if (
        type(roles) is not list
        or not roles
        or any(
            not isinstance(row, str) or not row or row != row.strip() for row in roles
        )
        or roles != sorted(set(roles))
    ):
        raise HandoffAdmissionError(
            "candidate_intent_roles", "role tracks are not sorted unique IDs"
        )
    return _digest(document["authority_source_sha256"], "candidate authority source")


def _reference_requests(
    handoff: ParsedHandoff, evaluated_at: str
) -> list[ReferenceRequest]:
    payload = handoff.payload
    vacancy = payload["vacancy"]
    snapshot = vacancy["vacancy_snapshot_sha256"]
    values = {
        "profile_id": payload["profile_id"],
        "profile_version": payload["profile_version"],
        "job_key": payload["job_key"],
        "vacancy_snapshot_sha256": snapshot,
    }

    def request(
        key: str, digest: str, *, spec: ReferenceSpec | None = None
    ) -> ReferenceRequest:
        chosen = spec or REFERENCE_REGISTRY[key]
        return ReferenceRequest(
            sha256=digest,
            spec=chosen,
            expected_subject={name: values[name] for name in chosen.subject_keys},
            handoff_created_at=payload["created_at"],
            evaluated_at=evaluated_at,
        )

    rows = [
        request("candidate_intent", payload["candidate_intent_sha256"]),
        request("evidence_ledger", payload["evidence_ledger_sha256"]),
        request(
            "eligibility.receipt", payload["eligibility"]["eligibility_receipt_sha256"]
        ),
        request(
            "assessment.receipt", payload["assessment"]["assessment_receipt_sha256"]
        ),
        request(
            "assessment.scoring_parameters",
            payload["assessment"]["scoring_parameters_sha256"],
        ),
        request("vacancy.location.facts", vacancy["location"]["facts_sha256"]),
        request("vacancy.raw_listing", vacancy["raw_listing_sha256"]),
        request("vacancy.requirements", vacancy["requirements_sha256"]),
        request("vacancy.snapshot", snapshot),
        request("selection.policy", payload["selection"]["selection_policy_sha256"]),
        request("selection.receipt", payload["selection"]["selection_receipt_sha256"]),
    ]
    evidence_spec = ReferenceSpec(
        "",
        "eligibility_evidence",
        "market-aligner.eligibility-evidence.v1",
        ("profile_id", "profile_version", "job_key", "vacancy_snapshot_sha256"),
        "valid_interval",
    )
    for check in payload["eligibility"]["checks"]:
        key = f"eligibility.checks/{check['code']}/evidence"
        rows.append(
            request(
                key,
                check["evidence_sha256"],
                spec=ReferenceSpec(
                    key,
                    evidence_spec.type_id,
                    evidence_spec.schema_version,
                    evidence_spec.subject_keys,
                    evidence_spec.freshness_class,
                ),
            )
        )
    if payload["employer_dossier_sha256"] is not None:
        rows.append(request("employer_dossier", payload["employer_dossier_sha256"]))
    return sorted(rows, key=lambda row: row.spec.reference_key)


def _verify_resolution(
    resolver: TrustedHandoffResolver,
    request: ReferenceRequest,
    *,
    context_bytes: bytes | None,
    context_trust_root_id: str,
    authenticate: bool,
) -> tuple[VerifiedReference, bytes]:
    resolver_identity = _digest(
        getattr(resolver, "resolver_identity_sha256", None), "resolver identity"
    )
    try:
        resolved = resolver.resolve(request)
    except (FileNotFoundError, KeyError) as exc:
        raise HandoffAdmissionError(
            "missing_reference",
            "resolver could not resolve the referenced digest",
            reference_key=request.spec.reference_key,
        ) from exc
    except HandoffAdmissionError:
        raise
    except Exception as exc:
        raise HandoffAdmissionError(
            "resolver_failure",
            "resolver failed before returning typed evidence",
            reference_key=request.spec.reference_key,
        ) from exc
    if not isinstance(resolved, ResolvedReference):
        raise HandoffAdmissionError(
            "resolver_contract",
            "resolver returned the wrong result type",
            reference_key=request.spec.reference_key,
        )
    if (
        type(resolved.exact_bytes) is not bytes
        or not resolved.exact_bytes
        or len(resolved.exact_bytes) > MAX_WIRE_BYTES
    ):
        raise HandoffAdmissionError(
            "resolver_contract",
            "resolved object bytes are invalid",
            reference_key=request.spec.reference_key,
        )
    resolved_digest = hashlib.sha256(resolved.exact_bytes).hexdigest()
    if resolved_digest != request.sha256:
        raise HandoffAdmissionError(
            "digest_substitution",
            "resolved bytes differ from the referenced digest",
            reference_key=request.spec.reference_key,
        )
    try:
        decoded_metadata = decode_canonical_json(
            resolved.metadata_bytes, label="resolver metadata"
        )
    except HandoffContractError as exc:
        raise HandoffAdmissionError(
            "reference_metadata_bytes",
            exc.message,
            pointer=exc.pointer,
            reference_key=request.spec.reference_key,
        ) from exc
    metadata = _exact_mapping(
        decoded_metadata,
        {
            "issued_at",
            "issuer_id",
            "object_sha256",
            "reference_key",
            "schema_version",
            "subject",
            "trust_proof_sha256",
            "trust_root_id",
            "type_id",
            "valid_until",
        },
        "resolver metadata",
    )
    spec = request.spec
    accepted_schema_versions = {spec.schema_version}
    if spec.reference_key == "employer_dossier":
        # Registry v1.1 introduced this reference at dossier v1. Production
        # research v2 is an additive, source-bound evidence contract under the
        # same reference key and type; preserve exact metadata truth for both.
        accepted_schema_versions.add("market-aligner.employer-dossier.v2")
    exact_values = {
        "reference_key": spec.reference_key,
        "type_id": spec.type_id,
        "object_sha256": request.sha256,
        "trust_root_id": context_trust_root_id,
    }
    for key, expected in exact_values.items():
        if metadata[key] != expected:
            code = (
                "reference_trust_root_swap"
                if key == "trust_root_id"
                else "reference_type_mismatch"
            )
            raise HandoffAdmissionError(
                code,
                f"metadata {key} differs from the registry/request",
                reference_key=spec.reference_key,
            )
    if metadata["schema_version"] not in accepted_schema_versions:
        raise HandoffAdmissionError(
            "reference_type_mismatch",
            "metadata schema_version differs from the registry/request",
            reference_key=spec.reference_key,
        )
    if type(metadata["subject"]) is not dict or metadata["subject"] != dict(
        request.expected_subject
    ):
        raise HandoffAdmissionError(
            "reference_subject_swap",
            "metadata subject differs from the handoff",
            reference_key=spec.reference_key,
        )
    issuer = _identity(metadata["issuer_id"], "resolver issuer")
    proof = _digest(metadata["trust_proof_sha256"], "resolver trust proof")
    issued_at, issued = _timestamp(metadata["issued_at"], "resolver issued_at")
    _, handoff_time = _handoff_timestamp(
        request.handoff_created_at, "handoff created_at"
    )
    _, evaluated = _timestamp(request.evaluated_at, "resolver evaluation time")
    valid_until: str | None
    if spec.freshness_class == "immutable":
        if metadata["valid_until"] is not None:
            raise HandoffAdmissionError(
                "reference_validity",
                "immutable reference must have null valid_until",
                reference_key=spec.reference_key,
            )
        valid_until = None
        if issued > handoff_time or issued > evaluated:
            raise HandoffAdmissionError(
                "reference_future",
                "immutable reference was issued after use",
                reference_key=spec.reference_key,
            )
    else:
        if metadata["valid_until"] is None:
            raise HandoffAdmissionError(
                "reference_validity",
                "freshness-bound reference lacks valid_until",
                reference_key=spec.reference_key,
            )
        valid_until, valid = _timestamp(metadata["valid_until"], "resolver valid_until")
        if not (issued <= handoff_time < valid and issued <= evaluated < valid):
            raise HandoffAdmissionError(
                "stale_reference",
                "reference is not current at handoff and evaluation",
                reference_key=spec.reference_key,
            )
    if authenticate:
        try:
            resolver.authenticate(
                metadata_bytes=resolved.metadata_bytes,
                exact_bytes=resolved.exact_bytes,
                admission_context_bytes=context_bytes,
                evaluated_at=request.evaluated_at,
            )
        except HandoffAdmissionError:
            raise
        except Exception as exc:
            raise HandoffAdmissionError(
                "reference_authentication_failed",
                "configured resolver rejected the metadata trust proof",
                reference_key=spec.reference_key,
            ) from exc
    metadata_sha256 = hashlib.sha256(resolved.metadata_bytes).hexdigest()
    return (
        VerifiedReference(
            reference_key=spec.reference_key,
            type_id=spec.type_id,
            schema_version=str(metadata["schema_version"]),
            referenced_sha256=request.sha256,
            resolved_bytes_sha256=resolved_digest,
            byte_length=len(resolved.exact_bytes),
            subject=dict(request.expected_subject),
            issued_at=issued_at,
            valid_until=valid_until,
            freshness_class=spec.freshness_class,
            issuer_id=issuer,
            trust_root_id=context_trust_root_id,
            trust_proof_sha256=proof,
            metadata_bytes=resolved.metadata_bytes,
            metadata_sha256=metadata_sha256,
            resolver_identity_sha256=resolver_identity,
        ),
        resolved.exact_bytes,
    )


def _verify_graph(
    handoff: ParsedHandoff,
    resolver: TrustedHandoffResolver,
    *,
    context_bytes: bytes | None,
    context_trust_root_id: str,
    evaluated_at: str,
    authenticate: bool,
    consumer_policy_rules: SelectionPolicyRules,
) -> VerifiedGraph:
    references: list[VerifiedReference] = []
    objects: dict[str, bytes] = {}
    for request in _reference_requests(handoff, evaluated_at):
        proof, exact_bytes = _verify_resolution(
            resolver,
            request,
            context_bytes=context_bytes,
            context_trust_root_id=context_trust_root_id,
            authenticate=authenticate,
        )
        references.append(proof)
        objects[proof.reference_key] = exact_bytes
    authority_source_sha256 = _candidate_intent(objects["candidate_intent"], handoff)
    values = {
        "profile_id": handoff.payload["profile_id"],
        "profile_version": handoff.payload["profile_version"],
    }
    authority_spec = REFERENCE_REGISTRY["candidate_intent.authority_source"]
    authority_request = ReferenceRequest(
        sha256=authority_source_sha256,
        spec=authority_spec,
        expected_subject=values,
        handoff_created_at=handoff.payload["created_at"],
        evaluated_at=evaluated_at,
    )
    authority_proof, authority_bytes = _verify_resolution(
        resolver,
        authority_request,
        context_bytes=context_bytes,
        context_trust_root_id=context_trust_root_id,
        authenticate=authenticate,
    )
    references.append(authority_proof)
    objects[authority_proof.reference_key] = authority_bytes
    # The protected selection-policy object remains opaque under registry v1.1.
    # Consumer currentness/skew settings are separately configured and recorded;
    # they are not inferred from Market-owned inner bytes.
    rules = consumer_policy_rules
    if (
        rules.employer_dossier_required
        and handoff.payload["employer_dossier_sha256"] is None
    ):
        raise HandoffAdmissionError(
            "missing_dossier", "selection policy requires a current employer dossier"
        )
    _, created = _handoff_timestamp(handoff.payload["created_at"], "handoff created_at")
    _, evaluated = _timestamp(evaluated_at, "evaluation time")
    if created.timestamp() > evaluated.timestamp() + rules.clock_skew_seconds:
        raise HandoffAdmissionError(
            "handoff_future", "handoff creation exceeds the protected policy clock skew"
        )
    references.sort(key=lambda row: row.reference_key)
    return VerifiedGraph(tuple(references), objects, rules, authority_source_sha256)


def _verification_receipt(
    handoff: ParsedHandoff,
    graph: VerifiedGraph,
    *,
    admitted_at: str,
    context_sha256: str | None,
    context_authenticator_sha256: str | None,
    environment: str,
    authority_scope: str,
    trust_mode: str,
    trust_root_id: str,
    current_time_receipt_sha256: str | None,
) -> bytes:
    return canonical_json_bytes(
        {
            "admission_context_sha256": context_sha256,
            "admission_kind": (
                ADMISSION_KIND_V1
                if handoff.strict_profile
                else ADMISSION_KIND_COMPATIBILITY
            ),
            "admitted_at": admitted_at,
            "authority_scope": authority_scope,
            "consumer_contract_bundle_sha256": list(CONTRACT_BUNDLE_SHA256),
            "context_authenticator_sha256": context_authenticator_sha256,
            "current_time_receipt_sha256": current_time_receipt_sha256,
            "emission_profile": handoff.emission_profile,
            "environment": environment,
            "handoff_root_sha256": handoff.root_sha256,
            "payload_sha256": handoff.payload_sha256,
            "references": [row.document() for row in graph.references],
            "schema_version": VERIFICATION_SCHEMA,
            "consumer_freshness_policy": graph.policy_rules.document(),
            "trust_mode": trust_mode,
            "trust_root_id": trust_root_id,
        }
    )


class HandoffAdmissionStore:
    """Immutable SQLite admission store with root-first replay semantics."""

    def __init__(
        self,
        database: str | Path,
        *,
        context_authenticator: AdmissionContextAuthenticator | None = None,
        resolver: TrustedHandoffResolver | None = None,
        consumer_policy_rules: SelectionPolicyRules | None = None,
        current_time_witness: AuthenticatedCurrentTimeWitness | None = None,
        maximum_clock_skew_seconds: int = 300,
    ) -> None:
        self.database = Path(database)
        if current_time_witness is not None:
            validate_current_time_witness_configuration(
                current_time_witness,
                environment=getattr(current_time_witness, "environment", ""),
            )
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.context_authenticator = context_authenticator
        self.resolver = resolver
        self.current_time_witness = current_time_witness
        if (
            type(maximum_clock_skew_seconds) is not int
            or maximum_clock_skew_seconds < 0
        ):
            raise ValueError("maximum clock skew is invalid")
        self.maximum_clock_skew_seconds = maximum_clock_skew_seconds
        self.consumer_policy_rules = consumer_policy_rules or SelectionPolicyRules(
            300, 21_600, 86_400, False
        )
        if not isinstance(self.consumer_policy_rules, SelectionPolicyRules):
            raise ValueError("consumer freshness policy is invalid")
        apply_jaa_operational_migrations(self.database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _time_subject(document: Mapping[str, object]) -> str:
        return hashlib.sha256(canonical_json_bytes(dict(document))).hexdigest()

    @staticmethod
    def _insert_time_evidence_tx(
        connection: sqlite3.Connection,
        evidence: AuthenticatedTimeEvidence,
        *,
        consumer_kind: str,
        consumer_id: str,
    ) -> None:
        try:
            connection.execute(
                """INSERT INTO authenticated_time_evidence(
                     receipt_sha256,receipt_bytes,environment,purpose,subject_sha256,
                     evaluated_at,witness_identity_sha256,trust_root_id,
                     consumer_kind,consumer_id
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence.receipt_sha256,
                    sqlite3.Binary(evidence.receipt_bytes),
                    evidence.environment,
                    evidence.purpose,
                    evidence.subject_sha256,
                    evidence.evaluated_at,
                    evidence.witness_identity_sha256,
                    evidence.trust_root_id,
                    consumer_kind,
                    consumer_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HandoffAdmissionError(
                "time_replay",
                "authenticated current-time evidence was already consumed",
            ) from exc

    def _root_replay(self, raw: bytes) -> HandoffAdmission | None:
        if type(raw) is not bytes or not raw or len(raw) > MAX_WIRE_BYTES:
            return None
        root = hashlib.sha256(raw).hexdigest()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM application_admissions WHERE handoff_root_sha256=?",
                (root,),
            ).fetchone()
        if row is None:
            return None
        if bytes(row["original_bytes"]) != raw:
            raise HandoffAdmissionError(
                "hash_collision", "stored root has different exact bytes"
            )
        return self._stored_result(row, created=False)

    def admit_authenticated(
        self,
        raw: bytes,
        context_bytes: bytes,
    ) -> HandoffAdmission:
        """Admit through the configured production/synthetic authenticated gateway."""
        replay = self._root_replay(raw)
        if replay is not None:
            return replay
        if (
            self.context_authenticator is None
            or self.resolver is None
            or type(self.current_time_witness) is not AuthenticatedCurrentTimeWitness
        ):
            raise HandoffAdmissionError(
                "trust_not_configured",
                "authenticated admission requires context, resolver and current-time trust",
            )
        try:
            handoff = parse_handoff(raw)
        except HandoffContractError as exc:
            raise HandoffAdmissionError(
                exc.code, exc.message, pointer=exc.pointer
            ) from exc
        time_subject = self._time_subject(
            {
                "admission_context_sha256": hashlib.sha256(context_bytes).hexdigest(),
                "handoff_root_sha256": handoff.root_sha256,
                "schema_version": "jaa.handoff-admission-time-subject.v1",
            }
        )
        try:
            time_evidence = obtain_current_time(
                self.current_time_witness,
                environment=self.current_time_witness.environment,
                purpose="handoff_admission",
                subject_sha256=time_subject,
                maximum_clock_skew_seconds=self.maximum_clock_skew_seconds,
            )
        except CurrentTimeWitnessError as exc:
            raise HandoffAdmissionError(exc.code, exc.message) from exc
        admitted_at = time_evidence.evaluated_at
        context, context_sha256, authenticator_identity = _context_document(
            context_bytes,
            handoff,
            self.context_authenticator,
            admitted_at,
        )
        if context["environment"] != time_evidence.environment:
            raise HandoffAdmissionError(
                "time_environment",
                "admission context and current-time environment differ",
            )
        graph = _verify_graph(
            handoff,
            self.resolver,
            context_bytes=context_bytes,
            context_trust_root_id=context["trust_root_id"],
            evaluated_at=admitted_at,
            authenticate=True,
            consumer_policy_rules=self.consumer_policy_rules,
        )
        environment = str(context["environment"])
        authority_scope = environment if handoff.strict_profile else "none"
        receipt = _verification_receipt(
            handoff,
            graph,
            admitted_at=admitted_at,
            context_sha256=context_sha256,
            context_authenticator_sha256=authenticator_identity,
            environment=environment,
            authority_scope=authority_scope,
            trust_mode=str(context["trust_mode"]),
            trust_root_id=str(context["trust_root_id"]),
            current_time_receipt_sha256=time_evidence.receipt_sha256,
        )
        return self._persist_handoff(
            handoff,
            graph,
            admitted_at=admitted_at,
            environment=environment,
            authority_scope=authority_scope,
            trust_mode=str(context["trust_mode"]),
            trust_root_id=str(context["trust_root_id"]),
            context_bytes=context_bytes,
            context_sha256=context_sha256,
            context_authenticator_sha256=authenticator_identity,
            verification_receipt=receipt,
            time_evidence=time_evidence,
        )

    def admit_synthetic_direct_for_test(
        self,
        raw: bytes,
        resolver: TrustedHandoffResolver,
        *,
        evaluated_at: datetime | None = None,
    ) -> HandoffAdmission:
        """Admit untrusted fixture bytes without granting release authority."""
        replay = self._root_replay(raw)
        if replay is not None:
            return replay
        admitted_at, _ = _evaluation_time(evaluated_at)
        try:
            handoff = parse_handoff(raw)
        except HandoffContractError as exc:
            raise HandoffAdmissionError(
                exc.code, exc.message, pointer=exc.pointer
            ) from exc
        trust_root_id = _identity(
            getattr(resolver, "synthetic_trust_root_id", None),
            "synthetic resolver trust root",
        )
        if not trust_root_id.startswith("synthetic-"):
            raise HandoffAdmissionError(
                "synthetic_trust_root",
                "direct fixture resolver must use a synthetic-* trust root",
            )
        graph = _verify_graph(
            handoff,
            resolver,
            context_bytes=None,
            context_trust_root_id=trust_root_id,
            evaluated_at=admitted_at,
            authenticate=False,
            consumer_policy_rules=self.consumer_policy_rules,
        )
        receipt = _verification_receipt(
            handoff,
            graph,
            admitted_at=admitted_at,
            context_sha256=None,
            context_authenticator_sha256=None,
            environment="synthetic",
            authority_scope="none",
            trust_mode="synthetic_direct",
            trust_root_id=trust_root_id,
            current_time_receipt_sha256=None,
        )
        return self._persist_handoff(
            handoff,
            graph,
            admitted_at=admitted_at,
            environment="synthetic",
            authority_scope="none",
            trust_mode="synthetic_direct",
            trust_root_id=trust_root_id,
            context_bytes=None,
            context_sha256=None,
            context_authenticator_sha256=None,
            verification_receipt=receipt,
            time_evidence=None,
        )

    def _persist_handoff(
        self,
        handoff: ParsedHandoff,
        graph: VerifiedGraph,
        *,
        admitted_at: str,
        environment: str,
        authority_scope: str,
        trust_mode: str,
        trust_root_id: str,
        context_bytes: bytes | None,
        context_sha256: str | None,
        context_authenticator_sha256: str | None,
        verification_receipt: bytes,
        time_evidence: AuthenticatedTimeEvidence | None,
    ) -> HandoffAdmission:
        payload = handoff.payload
        logical_json = canonical_json_bytes(handoff.logical_identity_document).decode(
            "utf-8"
        )
        admission_kind = (
            ADMISSION_KIND_V1
            if handoff.strict_profile
            else ADMISSION_KIND_COMPATIBILITY
        )
        receipt_sha256 = hashlib.sha256(verification_receipt).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing_root = connection.execute(
                "SELECT * FROM application_admissions WHERE handoff_root_sha256=?",
                (handoff.root_sha256,),
            ).fetchone()
            if existing_root is not None:
                if bytes(existing_root["original_bytes"]) != handoff.original_bytes:
                    raise HandoffAdmissionError(
                        "hash_collision", "root collision changed exact bytes"
                    )
                connection.commit()
                return self._stored_result(existing_root, created=False)
            conflict = connection.execute(
                """SELECT application_id,handoff_root_sha256
                   FROM application_admissions
                   WHERE logical_identity_sha256=? OR application_id=?""",
                (handoff.logical_identity_sha256, handoff.application_id),
            ).fetchone()
            if conflict is not None:
                raise HandoffAdmissionError(
                    "replay_conflict",
                    "same logical tuple/application ID already has a different root",
                )
            if time_evidence is not None:
                self._insert_time_evidence_tx(
                    connection,
                    time_evidence,
                    consumer_kind="admission",
                    consumer_id=handoff.application_id,
                )
            connection.execute(
                """INSERT INTO application_admissions(
                     application_id,admission_kind,environment,authority_scope,
                     emission_profile,logical_identity_json,logical_identity_sha256,
                     trust_mode,trust_root_id,admission_context_bytes,
                     admission_context_sha256,context_authenticator_sha256,admitted_at,
                     producer_product,producer_commit_sha,profile_id,profile_version,
                     job_key,handoff_root_sha256,payload_sha256,vacancy_snapshot_sha256,
                     original_bytes,original_bytes_sha256,verification_receipt_bytes,
                     verification_receipt_sha256,vacancy_source_identity,reference_count,sealed
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (
                    handoff.application_id,
                    admission_kind,
                    environment,
                    authority_scope,
                    handoff.emission_profile,
                    logical_json,
                    handoff.logical_identity_sha256,
                    trust_mode,
                    trust_root_id,
                    None if context_bytes is None else sqlite3.Binary(context_bytes),
                    context_sha256,
                    context_authenticator_sha256,
                    admitted_at,
                    payload["producer"]["product"],
                    payload["producer"]["commit_sha"],
                    payload["profile_id"],
                    payload["profile_version"],
                    payload["job_key"],
                    handoff.root_sha256,
                    handoff.payload_sha256,
                    payload["vacancy"]["vacancy_snapshot_sha256"],
                    sqlite3.Binary(handoff.original_bytes),
                    handoff.root_sha256,
                    sqlite3.Binary(verification_receipt),
                    receipt_sha256,
                    handoff.vacancy_source_identity,
                    len(graph.references),
                ),
            )
            for reference in graph.references:
                connection.execute(
                    """INSERT INTO application_admission_references(
                         application_id,reference_key,reference_kind,
                         referenced_sha256,resolved_bytes_sha256,byte_length,type_id,
                         schema_version,issuer_id,subject_json,issued_at,valid_until,
                         freshness_class,metadata_bytes,metadata_sha256,
                         resolver_identity_sha256,trust_root_id,trust_proof_sha256
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        handoff.application_id,
                        reference.reference_key,
                        reference.type_id,
                        reference.referenced_sha256,
                        reference.resolved_bytes_sha256,
                        reference.byte_length,
                        reference.type_id,
                        reference.schema_version,
                        reference.issuer_id,
                        canonical_json_bytes(reference.subject).decode("utf-8"),
                        reference.issued_at,
                        reference.valid_until,
                        reference.freshness_class,
                        sqlite3.Binary(reference.metadata_bytes),
                        reference.metadata_sha256,
                        reference.resolver_identity_sha256,
                        reference.trust_root_id,
                        reference.trust_proof_sha256,
                    ),
                )
            if (
                connection.execute(
                    "UPDATE application_admissions SET sealed=1 WHERE application_id=?",
                    (handoff.application_id,),
                ).rowcount
                != 1
            ):
                raise HandoffAdmissionError(
                    "persistence_failure", "admission could not be sealed"
                )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM application_admissions WHERE application_id=?",
                (handoff.application_id,),
            ).fetchone()
            assert row is not None
            return self._stored_result(row, created=True)
        except HandoffAdmissionError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            winner = self._root_replay(handoff.original_bytes)
            if winner is not None:
                return winner
            raise HandoffAdmissionError(
                "persistence_conflict",
                "concurrent admission won with conflicting immutable identity",
            ) from exc
        finally:
            connection.close()

    def admit_legacy_scored_jsonl(self, exact_line_bytes: bytes) -> HandoffAdmission:
        """Persist one exact legacy score row without fabricating v1 provenance."""
        if (
            type(exact_line_bytes) is not bytes
            or not exact_line_bytes
            or len(exact_line_bytes) > MAX_WIRE_BYTES
        ):
            raise HandoffAdmissionError(
                "legacy_wire", "legacy score row must be non-empty exact bytes"
            )
        body = (
            exact_line_bytes[:-1]
            if exact_line_bytes.endswith(b"\n")
            else exact_line_bytes
        )
        if b"\n" in body or b"\r" in body:
            raise HandoffAdmissionError(
                "legacy_wire", "legacy adapter accepts exactly one JSONL row"
            )
        try:
            payload = decode_canonical_json(body, label="legacy scored JSONL row")
        except HandoffContractError as exc:
            raise HandoffAdmissionError(
                exc.code, exc.message, pointer=exc.pointer
            ) from exc
        if type(payload) is not dict:
            raise HandoffAdmissionError(
                "legacy_schema", "legacy score row must be an object"
            )
        if payload.get("schema_version") == HANDOFF_SCHEMA or set(payload) == {
            "payload",
            "payload_sha256",
            "schema_version",
        }:
            raise HandoffAdmissionError(
                "legacy_masquerade", "v1-shaped bytes cannot use legacy admission"
            )
        try:
            job = scored_job_from_payload(payload)
        except (TypeError, ValueError) as exc:
            raise HandoffAdmissionError("legacy_schema", str(exc)) from exc
        original_sha256 = hashlib.sha256(exact_line_bytes).hexdigest()
        application_id = f"legacy_{original_sha256}"
        receipt = canonical_json_bytes(
            {
                "admission_kind": ADMISSION_KIND_LEGACY,
                "application_id": application_id,
                "authority_scope": "none",
                "job_key": job.key,
                "original_bytes_sha256": original_sha256,
                "schema_version": LEGACY_VERIFICATION_SCHEMA,
            }
        )
        receipt_sha256 = hashlib.sha256(receipt).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM application_admissions WHERE application_id=?",
                (application_id,),
            ).fetchone()
            if existing is not None:
                if bytes(existing["original_bytes"]) != exact_line_bytes:
                    raise HandoffAdmissionError(
                        "hash_collision", "legacy digest collision changed bytes"
                    )
                connection.commit()
                return self._stored_result(existing, created=False)
            connection.execute(
                """INSERT INTO application_admissions(
                     application_id,admission_kind,environment,authority_scope,
                     emission_profile,logical_identity_json,logical_identity_sha256,
                     trust_mode,trust_root_id,admission_context_bytes,
                     admission_context_sha256,context_authenticator_sha256,admitted_at,
                     producer_product,producer_commit_sha,profile_id,profile_version,
                     job_key,handoff_root_sha256,payload_sha256,vacancy_snapshot_sha256,
                     original_bytes,original_bytes_sha256,verification_receipt_bytes,
                     verification_receipt_sha256,vacancy_source_identity,reference_count,sealed
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    application_id,
                    ADMISSION_KIND_LEGACY,
                    "legacy",
                    "none",
                    None,
                    None,
                    None,
                    "legacy_scored_jsonl",
                    "legacy_scored_jsonl",
                    None,
                    None,
                    None,
                    "1970-01-01T00:00:00Z",
                    None,
                    None,
                    None,
                    None,
                    job.key,
                    None,
                    None,
                    None,
                    sqlite3.Binary(exact_line_bytes),
                    original_sha256,
                    sqlite3.Binary(receipt),
                    receipt_sha256,
                    f"legacy-scored-jsonl:{original_sha256}",
                    0,
                ),
            )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM application_admissions WHERE application_id=?",
                (application_id,),
            ).fetchone()
            assert row is not None
            return self._stored_result(row, created=True)
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise HandoffAdmissionError(
                "persistence_conflict", "legacy admission conflicts"
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _stored_result(row: sqlite3.Row, *, created: bool) -> HandoffAdmission:
        return HandoffAdmission(
            application_id=str(row["application_id"]),
            admission_kind=str(row["admission_kind"]),
            environment=str(row["environment"]),
            authority_scope=str(row["authority_scope"]),
            emission_profile=(
                None
                if row["emission_profile"] is None
                else str(row["emission_profile"])
            ),
            handoff_root_sha256=(
                None
                if row["handoff_root_sha256"] is None
                else str(row["handoff_root_sha256"])
            ),
            job_key=str(row["job_key"]),
            profile_id=None if row["profile_id"] is None else str(row["profile_id"]),
            profile_version=(
                None if row["profile_version"] is None else str(row["profile_version"])
            ),
            vacancy_source_identity=str(row["vacancy_source_identity"]),
            verification_receipt_sha256=str(row["verification_receipt_sha256"]),
            created=created,
        )

    def get(self, application_id: str) -> HandoffAdmission:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM application_admissions WHERE application_id=?",
                (application_id,),
            ).fetchone()
        if row is None:
            raise HandoffAdmissionError(
                "admission_missing", "application admission does not exist"
            )
        return self._stored_result(row, created=False)

    def reference_sha256(self, application_id: str, reference_key: str) -> str:
        """Return one sealed admitted reference identity without exposing its bytes."""

        if reference_key not in REFERENCE_REGISTRY:
            raise HandoffAdmissionError(
                "reference_unknown", "admitted reference key is unsupported"
            )
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT reference.referenced_sha256
                   FROM application_admission_references reference
                   JOIN application_admissions admission
                     ON admission.application_id=reference.application_id
                   WHERE reference.application_id=? AND reference.reference_key=?
                     AND admission.admission_kind=? AND admission.sealed=1""",
                (application_id, reference_key, ADMISSION_KIND_V1),
            ).fetchall()
        if len(rows) != 1:
            raise HandoffAdmissionError(
                "reference_missing", "sealed admitted reference is unavailable"
            )
        return _digest(rows[0]["referenced_sha256"], "admitted reference")

    def verify_stored(self, application_id: str) -> HandoffAdmission:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM application_admissions WHERE application_id=?",
                (application_id,),
            ).fetchone()
            if row is None:
                raise HandoffAdmissionError(
                    "admission_missing", "application admission does not exist"
                )
            receipt_bytes = bytes(row["verification_receipt_bytes"])
            if (
                hashlib.sha256(receipt_bytes).hexdigest()
                != row["verification_receipt_sha256"]
            ):
                raise HandoffAdmissionError(
                    "stored_verification_invalid", "receipt digest differs"
                )
            receipt = decode_canonical_json(
                receipt_bytes, label="stored verification receipt"
            )
            if row["admission_kind"] == ADMISSION_KIND_LEGACY:
                if receipt.get("schema_version") != LEGACY_VERIFICATION_SCHEMA:
                    raise HandoffAdmissionError(
                        "stored_verification_invalid", "legacy receipt version differs"
                    )
                return self._stored_result(row, created=False)
            handoff = parse_handoff(bytes(row["original_bytes"]))
            expected = {
                "application_id": handoff.application_id,
                "logical_identity_json": canonical_json_bytes(
                    handoff.logical_identity_document
                ).decode("utf-8"),
                "logical_identity_sha256": handoff.logical_identity_sha256,
                "handoff_root_sha256": handoff.root_sha256,
                "payload_sha256": handoff.payload_sha256,
                "vacancy_source_identity": handoff.vacancy_source_identity,
                "sealed": 1,
            }
            if any(row[key] != value for key, value in expected.items()):
                raise HandoffAdmissionError(
                    "stored_verification_invalid", "stored handoff binding differs"
                )
            if (
                receipt.get("schema_version") != VERIFICATION_SCHEMA
                or receipt.get("handoff_root_sha256") != handoff.root_sha256
            ):
                raise HandoffAdmissionError(
                    "stored_verification_invalid", "verification receipt root differs"
                )
            reference_rows = connection.execute(
                """SELECT reference_key,metadata_bytes,metadata_sha256
                   FROM application_admission_references
                   WHERE application_id=? ORDER BY reference_key""",
                (application_id,),
            ).fetchall()
            if len(reference_rows) != row["reference_count"]:
                raise HandoffAdmissionError(
                    "stored_verification_invalid", "reference set is incomplete"
                )
            receipt_references = receipt.get("references")
            if not isinstance(receipt_references, list):
                raise HandoffAdmissionError(
                    "stored_verification_invalid", "receipt references are malformed"
                )
            receipt_metadata = {
                str(item["reference_key"]): str(item["metadata_sha256"])
                for item in receipt_references
                if isinstance(item, dict)
            }
            for reference in reference_rows:
                metadata_bytes = bytes(reference["metadata_bytes"])
                digest = hashlib.sha256(metadata_bytes).hexdigest()
                if (
                    digest != reference["metadata_sha256"]
                    or receipt_metadata.get(reference["reference_key"]) != digest
                ):
                    raise HandoffAdmissionError(
                        "stored_verification_invalid",
                        "reference metadata evidence differs",
                    )
            return self._stored_result(row, created=False)
        except HandoffContractError as exc:
            raise HandoffAdmissionError(
                "stored_verification_invalid", exc.message
            ) from exc
        finally:
            connection.close()

    def for_boundary(
        self,
        application_id: str,
        boundary: str,
    ) -> VerifiedApplicationInput:
        """Re-resolve references using fresh authenticated current-time evidence."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT admission_kind,environment,verification_receipt_sha256
                   FROM application_admissions WHERE application_id=?""",
                (application_id,),
            ).fetchone()
            if row is None:
                raise HandoffAdmissionError(
                    "admission_missing", "application admission does not exist"
                )
            if row["admission_kind"] == ADMISSION_KIND_LEGACY:
                raise HandoffAdmissionError(
                    "legacy_release_blocked", "legacy admission cannot progress"
                )
            if type(self.current_time_witness) is not AuthenticatedCurrentTimeWitness:
                raise HandoffAdmissionError(
                    "time_witness",
                    "forward boundary requires configured current-time trust",
                )
            subject_sha256 = self._time_subject(
                {
                    "admission_receipt_sha256": row["verification_receipt_sha256"],
                    "application_id": application_id,
                    "boundary": boundary,
                    "schema_version": "jaa.forward-boundary-time-subject.v1",
                }
            )
            try:
                time_evidence = obtain_current_time(
                    self.current_time_witness,
                    environment=str(row["environment"]),
                    purpose="forward_boundary",
                    subject_sha256=subject_sha256,
                    maximum_clock_skew_seconds=self.maximum_clock_skew_seconds,
                )
            except CurrentTimeWitnessError as exc:
                raise HandoffAdmissionError(exc.code, exc.message) from exc
            result = self._for_boundary_tx(
                connection,
                application_id,
                boundary,
                time_evidence=time_evidence,
                evaluated_at_for_test=None,
            )
            self._insert_time_evidence_tx(
                connection,
                time_evidence,
                consumer_kind="forward_validation",
                consumer_id=(
                    f"{application_id}:{boundary}:{time_evidence.receipt_sha256}"
                ),
            )
            connection.commit()
            return result
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def for_boundary_at_for_test(
        self,
        application_id: str,
        boundary: str,
        *,
        evaluated_at: datetime,
    ) -> VerifiedApplicationInput:
        """Deterministic synthetic-only seam; never use for production currentness."""

        if not isinstance(evaluated_at, datetime):
            raise HandoffAdmissionError(
                "boundary_time", "test boundary time is invalid"
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT environment,trust_root_id FROM application_admissions
                   WHERE application_id=?""",
                (application_id,),
            ).fetchone()
            if (
                row is None
                or row["environment"] != "synthetic"
                or not str(row["trust_root_id"]).startswith("synthetic-")
            ):
                raise HandoffAdmissionError(
                    "boundary_time",
                    "explicit boundary time is restricted to synthetic tests",
                )
            result = self._for_boundary_tx(
                connection,
                application_id,
                boundary,
                time_evidence=None,
                evaluated_at_for_test=evaluated_at,
            )
            connection.commit()
            return result
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def for_boundary_in_transaction(
        self,
        connection: sqlite3.Connection,
        application_id: str,
        boundary: str,
        *,
        time_evidence: AuthenticatedTimeEvidence,
        expected_time_purpose: str,
        expected_time_subject_sha256: str,
    ) -> VerifiedApplicationInput:
        """Revalidate with evidence already authenticated by this store's witness."""

        if (
            not isinstance(connection, sqlite3.Connection)
            or not connection.in_transaction
        ):
            raise HandoffAdmissionError(
                "boundary_transaction", "an active SQLite transaction is required"
            )
        database_rows = connection.execute("PRAGMA database_list").fetchall()
        main_path = next(
            (str(row[2]) for row in database_rows if str(row[1]) == "main"), ""
        )
        if not main_path or Path(main_path).resolve() != self.database.resolve():
            raise HandoffAdmissionError(
                "boundary_transaction", "boundary transaction uses a different database"
            )
        if type(self.current_time_witness) is not AuthenticatedCurrentTimeWitness:
            raise HandoffAdmissionError(
                "time_witness", "atomic boundary lacks configured current-time trust"
            )
        permitted_bindings = {
            ("review", "review_material"),
            ("review", "phase_event"),
            ("strategy", "phase_event"),
            ("release_readiness", "phase_event"),
            ("authority", "authority_grant"),
            ("executor", "click_reservation"),
        }
        if (boundary, expected_time_purpose) not in permitted_bindings:
            raise HandoffAdmissionError(
                "time_purpose", "time evidence purpose cannot authorize this boundary"
            )
        _digest(expected_time_subject_sha256, "expected time subject")
        if (
            time_evidence.purpose != expected_time_purpose
            or time_evidence.subject_sha256 != expected_time_subject_sha256
        ):
            raise HandoffAdmissionError(
                "time_substitution",
                "boundary time purpose or subject differs from the consumer preimage",
            )
        try:
            self.current_time_witness.assert_consumed(
                time_evidence,
                purpose=expected_time_purpose,
                subject_sha256=expected_time_subject_sha256,
                maximum_clock_skew_seconds=self.maximum_clock_skew_seconds,
            )
        except CurrentTimeWitnessError as exc:
            raise HandoffAdmissionError(exc.code, exc.message) from exc
        row = connection.execute(
            "SELECT environment FROM application_admissions WHERE application_id=?",
            (application_id,),
        ).fetchone()
        if row is None:
            raise HandoffAdmissionError(
                "admission_missing", "application admission does not exist"
            )
        if str(row["environment"]) != time_evidence.environment:
            raise HandoffAdmissionError(
                "time_environment", "boundary time environment differs from admission"
            )
        return self._for_boundary_tx(
            connection,
            application_id,
            boundary,
            time_evidence=time_evidence,
            evaluated_at_for_test=None,
        )

    def reuse_boundary_validation_in_transaction(
        self,
        connection: sqlite3.Connection,
        application_id: str,
        boundary: str,
        *,
        validation_sha256: str,
        time_evidence: AuthenticatedTimeEvidence,
        expected_time_purpose: str,
        expected_time_subject_sha256: str,
    ) -> VerifiedApplicationInput:
        """Carry one authenticated forward validation into an atomic consumer.

        This does not mint a second boundary receipt.  It proves the immutable
        receipt, its original authenticated time evidence and its exact
        admission/reference graph, then re-resolves that same graph at the
        consumer's authenticated instant so stale evidence fails closed.
        """

        if (
            not isinstance(connection, sqlite3.Connection)
            or not connection.in_transaction
        ):
            raise HandoffAdmissionError(
                "boundary_transaction", "an active SQLite transaction is required"
            )
        database_rows = connection.execute("PRAGMA database_list").fetchall()
        main_path = next(
            (str(row[2]) for row in database_rows if str(row[1]) == "main"), ""
        )
        if not main_path or Path(main_path).resolve() != self.database.resolve():
            raise HandoffAdmissionError(
                "boundary_transaction", "boundary transaction uses a different database"
            )
        _digest(validation_sha256, "forward validation")
        _digest(expected_time_subject_sha256, "expected time subject")
        if expected_time_purpose != "phase_event":
            raise HandoffAdmissionError(
                "time_purpose",
                "reused review validation requires a phase-event consumer",
            )
        if (
            time_evidence.purpose != expected_time_purpose
            or time_evidence.subject_sha256 != expected_time_subject_sha256
        ):
            raise HandoffAdmissionError(
                "time_substitution",
                "boundary consumer time purpose or subject differs",
            )
        try:
            self.current_time_witness.assert_consumed(
                time_evidence,
                purpose=expected_time_purpose,
                subject_sha256=expected_time_subject_sha256,
                maximum_clock_skew_seconds=self.maximum_clock_skew_seconds,
            )
        except (AttributeError, CurrentTimeWitnessError) as exc:
            raise HandoffAdmissionError(
                "time_witness", "boundary consumer time is untrusted"
            ) from exc

        validation = connection.execute(
            """SELECT application_id,boundary,evaluated_at,receipt_bytes,reference_count
               FROM application_forward_validations WHERE validation_sha256=?""",
            (validation_sha256,),
        ).fetchone()
        if validation is None:
            raise HandoffAdmissionError(
                "forward_validation_missing",
                "carried boundary validation does not exist",
            )
        receipt_bytes = bytes(validation["receipt_bytes"])
        if hashlib.sha256(receipt_bytes).hexdigest() != validation_sha256:
            raise HandoffAdmissionError(
                "forward_validation_corrupt", "carried boundary receipt digest differs"
            )
        try:
            receipt = decode_canonical_json(
                receipt_bytes,
                label="carried forward-boundary validation",
            )
        except HandoffContractError as exc:
            raise HandoffAdmissionError(
                "forward_validation_corrupt", exc.message
            ) from exc
        expected_receipt_keys = {
            "admission_receipt_sha256",
            "application_id",
            "boundary",
            "consumer_freshness_policy",
            "evaluated_at",
            "handoff_root_sha256",
            "references",
            "schema_version",
            "time_receipt_sha256",
        }
        if type(receipt) is not dict or set(receipt) != expected_receipt_keys:
            raise HandoffAdmissionError(
                "forward_validation_corrupt", "carried boundary receipt keys differ"
            )
        if (
            validation["application_id"] != application_id
            or validation["boundary"] != boundary
            or validation["evaluated_at"] != receipt["evaluated_at"]
            or receipt["application_id"] != application_id
            or receipt["boundary"] != boundary
            or receipt["schema_version"] != FORWARD_VALIDATION_SCHEMA
            or type(receipt["references"]) is not list
            or len(receipt["references"]) != validation["reference_count"]
        ):
            raise HandoffAdmissionError(
                "forward_validation_substitution", "carried boundary identity differs"
            )
        _validated_at, validation_instant = _timestamp(
            receipt["evaluated_at"], "forward validation evaluated_at"
        )
        _consumer_at, consumer_instant = _timestamp(
            time_evidence.evaluated_at, "boundary consumer evaluated_at"
        )
        if validation_instant > consumer_instant:
            raise HandoffAdmissionError(
                "forward_validation_future",
                "carried boundary validation is future-dated",
            )

        admission = connection.execute(
            "SELECT * FROM application_admissions WHERE application_id=?",
            (application_id,),
        ).fetchone()
        if admission is None or admission["admission_kind"] == ADMISSION_KIND_LEGACY:
            raise HandoffAdmissionError(
                "admission_missing", "carried boundary admission is unavailable"
            )
        if (
            receipt["admission_receipt_sha256"]
            != admission["verification_receipt_sha256"]
            or str(admission["environment"]) != time_evidence.environment
        ):
            raise HandoffAdmissionError(
                "forward_validation_substitution",
                "carried admission or environment differs",
            )
        original_time_sha256 = receipt["time_receipt_sha256"]
        _digest(original_time_sha256, "forward validation time receipt")
        original_time = connection.execute(
            """SELECT * FROM authenticated_time_evidence
               WHERE receipt_sha256=?""",
            (original_time_sha256,),
        ).fetchone()
        expected_original_subject = self._time_subject(
            {
                "admission_receipt_sha256": admission["verification_receipt_sha256"],
                "application_id": application_id,
                "boundary": boundary,
                "schema_version": "jaa.forward-boundary-time-subject.v1",
            }
        )
        if (
            original_time is None
            or hashlib.sha256(bytes(original_time["receipt_bytes"])).hexdigest()
            != original_time_sha256
            or original_time["environment"] != admission["environment"]
            or original_time["purpose"] != "forward_boundary"
            or original_time["subject_sha256"] != expected_original_subject
            or original_time["evaluated_at"] != receipt["evaluated_at"]
            or original_time["consumer_kind"] != "forward_validation"
            or original_time["consumer_id"]
            != f"{application_id}:{boundary}:{original_time_sha256}"
        ):
            raise HandoffAdmissionError(
                "forward_validation_time",
                "carried validation lacks exact time provenance",
            )
        if self.resolver is None:
            raise HandoffAdmissionError(
                "trust_not_configured",
                "carried boundary validation requires resolver trust",
            )
        try:
            handoff = parse_handoff(bytes(admission["original_bytes"]))
            graph = _verify_graph(
                handoff,
                self.resolver,
                context_bytes=(
                    None
                    if admission["admission_context_bytes"] is None
                    else bytes(admission["admission_context_bytes"])
                ),
                context_trust_root_id=str(admission["trust_root_id"]),
                evaluated_at=time_evidence.evaluated_at,
                authenticate=admission["trust_mode"] != "synthetic_direct",
                consumer_policy_rules=self.consumer_policy_rules,
            )
        except HandoffContractError as exc:
            raise HandoffAdmissionError("stored_handoff_invalid", exc.message) from exc
        if (
            handoff.root_sha256 != receipt["handoff_root_sha256"]
            or [reference.document() for reference in graph.references]
            != receipt["references"]
            or graph.policy_rules.document() != receipt["consumer_freshness_policy"]
        ):
            raise HandoffAdmissionError(
                "forward_validation_substitution",
                "current reference graph differs from carried validation",
            )
        vacancy = handoff.payload["vacancy"]
        market = _verified_market_decision_references(graph, handoff)
        return VerifiedApplicationInput(
            application_id=application_id,
            admission_kind=str(admission["admission_kind"]),
            environment=str(admission["environment"]),
            authority_scope=str(admission["authority_scope"]),
            handoff_root_sha256=handoff.root_sha256,
            vacancy_source_identity=handoff.vacancy_source_identity,
            profile_id=handoff.payload["profile_id"],
            profile_version=handoff.payload["profile_version"],
            candidate_authority_sha256=graph.candidate_authority_sha256,
            job_key=handoff.payload["job_key"],
            vacancy_snapshot_sha256=vacancy["vacancy_snapshot_sha256"],
            raw_listing_sha256=vacancy["raw_listing_sha256"],
            raw_listing_bytes=graph.objects["vacancy.raw_listing"],
            requirements_sha256=vacancy["requirements_sha256"],
            requirements_bytes=graph.objects["vacancy.requirements"],
            canonical_url=vacancy["provenance"]["canonical_url"],
            company_name=vacancy["company_name"],
            role_title=vacancy["role_title"],
            location=dict(vacancy["location"]),
            admission_receipt_sha256=str(admission["verification_receipt_sha256"]),
            current_boundary=boundary,
            current_boundary_receipt_sha256=validation_sha256,
            **market,
        )

    def _for_boundary_tx(
        self,
        connection: sqlite3.Connection,
        application_id: str,
        boundary: str,
        *,
        time_evidence: AuthenticatedTimeEvidence | None,
        evaluated_at_for_test: datetime | None,
    ) -> VerifiedApplicationInput:
        if boundary not in BOUNDARIES:
            raise HandoffAdmissionError(
                "boundary_unknown", "forward boundary is unsupported"
            )
        if time_evidence is None and evaluated_at_for_test is None:
            raise HandoffAdmissionError(
                "boundary_time",
                "atomic authority validation requires authenticated time",
            )
        if time_evidence is not None and evaluated_at_for_test is not None:
            raise HandoffAdmissionError(
                "boundary_time", "boundary cannot combine authenticated and test time"
            )
        if time_evidence is not None:
            evaluated_text = time_evidence.evaluated_at
            time_receipt_sha256 = time_evidence.receipt_sha256
        else:
            evaluated_text, _ = _evaluation_time(evaluated_at_for_test)
            time_receipt_sha256 = None
        row = connection.execute(
            "SELECT * FROM application_admissions WHERE application_id=?",
            (application_id,),
        ).fetchone()
        if row is None:
            raise HandoffAdmissionError(
                "admission_missing", "application admission does not exist"
            )
        kind = str(row["admission_kind"])
        if kind == ADMISSION_KIND_LEGACY:
            raise HandoffAdmissionError(
                "legacy_release_blocked", "legacy admission cannot progress"
            )
        if self.resolver is None:
            raise HandoffAdmissionError(
                "trust_not_configured", "forward validation requires resolver"
            )
        if boundary in RELEASE_BOUNDARIES and (
            kind != ADMISSION_KIND_V1 or row["authority_scope"] == "none"
        ):
            raise HandoffAdmissionError(
                "release_blocked_admission",
                "compatibility/direct admission cannot enter release",
            )
        try:
            handoff = parse_handoff(bytes(row["original_bytes"]))
        except HandoffContractError as exc:
            raise HandoffAdmissionError(
                "stored_handoff_invalid", exc.message, pointer=exc.pointer
            ) from exc
        context_bytes = (
            None
            if row["admission_context_bytes"] is None
            else bytes(row["admission_context_bytes"])
        )
        graph = _verify_graph(
            handoff,
            self.resolver,
            context_bytes=context_bytes,
            context_trust_root_id=str(row["trust_root_id"]),
            evaluated_at=evaluated_text,
            authenticate=row["trust_mode"] != "synthetic_direct",
            consumer_policy_rules=self.consumer_policy_rules,
        )
        receipt = canonical_json_bytes(
            {
                "admission_receipt_sha256": row["verification_receipt_sha256"],
                "application_id": application_id,
                "boundary": boundary,
                "evaluated_at": evaluated_text,
                "handoff_root_sha256": handoff.root_sha256,
                "references": [reference.document() for reference in graph.references],
                "schema_version": FORWARD_VALIDATION_SCHEMA,
                "time_receipt_sha256": time_receipt_sha256,
                "consumer_freshness_policy": graph.policy_rules.document(),
            }
        )
        receipt_sha256 = hashlib.sha256(receipt).hexdigest()
        connection.execute(
            """INSERT OR IGNORE INTO application_forward_validations(
                 validation_sha256,application_id,boundary,evaluated_at,
                 receipt_bytes,reference_count
               ) VALUES(?,?,?,?,?,?)""",
            (
                receipt_sha256,
                application_id,
                boundary,
                evaluated_text,
                sqlite3.Binary(receipt),
                len(graph.references),
            ),
        )
        existing = connection.execute(
            """SELECT validation_sha256,receipt_bytes
               FROM application_forward_validations
               WHERE validation_sha256=?""",
            (receipt_sha256,),
        ).fetchone()
        if (
            existing is None
            or existing["validation_sha256"] != receipt_sha256
            or bytes(existing["receipt_bytes"]) != receipt
        ):
            raise HandoffAdmissionError(
                "forward_validation_conflict", "stored exact boundary evidence differs"
            )
        vacancy = handoff.payload["vacancy"]
        market = _verified_market_decision_references(graph, handoff)
        return VerifiedApplicationInput(
            application_id=application_id,
            admission_kind=kind,
            environment=str(row["environment"]),
            authority_scope=str(row["authority_scope"]),
            handoff_root_sha256=handoff.root_sha256,
            vacancy_source_identity=handoff.vacancy_source_identity,
            profile_id=handoff.payload["profile_id"],
            profile_version=handoff.payload["profile_version"],
            candidate_authority_sha256=graph.candidate_authority_sha256,
            job_key=handoff.payload["job_key"],
            vacancy_snapshot_sha256=vacancy["vacancy_snapshot_sha256"],
            raw_listing_sha256=vacancy["raw_listing_sha256"],
            raw_listing_bytes=graph.objects["vacancy.raw_listing"],
            requirements_sha256=vacancy["requirements_sha256"],
            requirements_bytes=graph.objects["vacancy.requirements"],
            canonical_url=vacancy["provenance"]["canonical_url"],
            company_name=vacancy["company_name"],
            role_title=vacancy["role_title"],
            location=dict(vacancy["location"]),
            admission_receipt_sha256=str(row["verification_receipt_sha256"]),
            current_boundary=boundary,
            current_boundary_receipt_sha256=receipt_sha256,
            **market,
        )


def validate_downstream_result(
    source: VerifiedApplicationInput,
    result: Mapping[str, object],
) -> VerifiedDownstreamResult:
    """Validate a strict factory/reviewer stub without owning its semantics."""
    expected_keys = {
        "application_id",
        "application_source_identity",
        "artifact_set_sha256",
        "cover_letter_pdf_sha256",
        "cv_pdf_sha256",
        "employer_assessment_receipt_sha256",
        "form_answers_sha256",
        "job_key",
        "vacancy_snapshot_sha256",
        "vacancy_source_identity",
    }
    if type(result) is not dict or set(result) != expected_keys:
        raise HandoffAdmissionError(
            "downstream_schema", "factory/reviewer result keys differ"
        )
    exact = {
        "application_id": source.application_id,
        "job_key": source.job_key,
        "vacancy_snapshot_sha256": source.vacancy_snapshot_sha256,
        "vacancy_source_identity": source.vacancy_source_identity,
    }
    for key, expected in exact.items():
        if result[key] != expected:
            raise HandoffAdmissionError(
                "downstream_substitution", f"downstream {key} differs"
            )
    digests = {
        key: _digest(result[key], f"downstream {key}")
        for key in (
            "application_source_identity",
            "artifact_set_sha256",
            "cover_letter_pdf_sha256",
            "cv_pdf_sha256",
            "employer_assessment_receipt_sha256",
            "form_answers_sha256",
        )
    }
    return VerifiedDownstreamResult(
        application_id=source.application_id,
        vacancy_source_identity=source.vacancy_source_identity,
        application_source_identity=digests["application_source_identity"],
        artifact_set_sha256=digests["artifact_set_sha256"],
        cv_pdf_sha256=digests["cv_pdf_sha256"],
        cover_letter_pdf_sha256=digests["cover_letter_pdf_sha256"],
        form_answers_sha256=digests["form_answers_sha256"],
        employer_assessment_receipt_sha256=digests[
            "employer_assessment_receipt_sha256"
        ],
    )


__all__ = [
    "ADMISSION_KIND_COMPATIBILITY",
    "ADMISSION_KIND_LEGACY",
    "ADMISSION_KIND_V1",
    "REFERENCE_REGISTRY",
    "AdmissionContextAuthenticator",
    "HandoffAdmission",
    "HandoffAdmissionError",
    "HandoffAdmissionStore",
    "ProtectedLocalOutbox",
    "ReferenceRequest",
    "ResolvedReference",
    "SelectionPolicyRules",
    "TrustedHandoffResolver",
    "VerifiedApplicationInput",
    "VerifiedDownstreamResult",
    "validate_downstream_result",
]
