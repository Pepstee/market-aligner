"""Deterministic employer-facing package from approved candidate authority."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, fields
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from market_aligner.llm.contracts import canonical_hash
from market_aligner.profiler.schema import EvidenceItem

from .application_compiler import (
    ApplicationSource,
    ApprovedEvidenceSourceContext,
    CandidateContact,
    DocumentSection,
    EXACT_OUTWARD_PROFILE_REWRITES as OUTWARD_PROFILE_REWRITES,
    FactAuthority,
    FactualSentence,
    ProfileFactAuthority,
    StyleSlot,
    VacancyFactAuthority,
    approved_candidate_outward_text,
    compile_application_source,
    resolve_authenticated_outward_rewrite,
)
from .application_strategy import (
    CandidateSupport,
    EmployerResearchFact,
    compile_application_strategy,
)
from .candidate_authority import (
    APPROVED_CANDIDATE_SOURCE_HASHES,
    APPROVED_EVIDENCE_PATH,
    CANONICAL_REQUIREMENTS_MATRIX_POLICY_SHA256,
    compile_canonical_requirements_evidence_matrix,
)
from .candidate_contact_authority import (
    CandidateContactAuthority,
    CurrentContactProvenance,
)
from .evidence_matching import (
    PROOF_CLASSES,
    MatchResult,
    Requirement,
    canonical_json,
    content_hash,
)
from .external_document_assurance import (
    ExternalDocumentAssuranceError,
    assert_employer_facing_text,
)
from .rendering import (
    ApplicationArtifacts,
    EditableArtifacts,
    render_editable_text,
    render_pdf_artifacts,
)
from cv_generation.constraints import (
    CVConstraintReceipt,
    CandidateSourcePolicyReceipt,
    PreEditorialSourceEnvelopeReceipt,
    _REJECTION_SIGNAL,
    capability_line_eligible,
    validate_candidate_source_policy,
    validate_generated_cv,
    validate_pre_editorial_source,
)


PROFILE_CV_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Professional Summary", ("E-013",)),
    ("Core Capabilities", ("E-012",)),
    (
        "Projects",
        (
            "E-011",
            "E-014",
            "E-015",
            "E-016",
            "E-017",
        ),
    ),
    ("Education", ("E-001", "E-002")),
)
PROFILE_LETTER_EVIDENCE_PRIORITY = (
    "E-011",
    "E-002",
)
PROFILE_CV_GENERIC_SECTION_BY_PROOF_CLASS = {
    "verified_claim": "Highlights",
    "work_artifact": "Projects",
    "test_result": "Results",
    "external_outcome": "Outcomes",
    "employment_record": "Experience",
    "credential": "Education",
    "portfolio_artifact": "Projects",
}
PROFILE_CV_SECTION_ORDER = (
    "Professional Summary",
    "Core Capabilities",
    "Projects",
    "Education",
    "Experience",
    "Skills",
    "Highlights",
    "Results",
    "Outcomes",
)
_CAPABILITY_EVIDENCE_PROOF_CLASSES = frozenset(
    {"portfolio_artifact", "work_artifact", "test_result", "employment_record"}
)
_PROFILE_CV_LEGACY_SECTION_BY_EVIDENCE_ID = {
    evidence_id: heading
    for heading, evidence_ids in PROFILE_CV_SECTIONS
    for evidence_id in evidence_ids
}
MINIMUM_CV_FACTS = 8
MINIMUM_CV_WORDS = 110
MINIMUM_LETTER_CANDIDATE_FACTS = 2
MINIMUM_LETTER_WORDS = 90
CURRENT_RUNTIME_ENVIRONMENT = "current_runtime"
CURRENT_RUNTIME_DEPLOYMENT_BINDING_SCHEMA = (
    "jaa.candidate-application-deployment-binding.current-runtime.v1"
)
CURRENT_RUNTIME_DECISION_AUTHORITY_SCHEMA = (
    "jaa.market-application-decision-authority.current-runtime.v1"
)
CURRENT_RUNTIME_MATERIALIZATION_RECEIPT_SCHEMA = (
    "jaa.candidate-application-materialization-receipt.current-runtime.v1"
)
_CURRENT_PACKET_SHA256 = re.compile(r"[0-9a-f]{64}")
_MATCH_POLICY_BINDING_INVALID = "match_policy_binding_invalid"
_EVIDENCE_PACKET_BINDING_INVALID = "candidate evidence binding differs"


def resolve_evidence_packet(
    *,
    current_runtime: bool,
    pinned_bytes: bytes | None,
    expected_sha256: object,
    legacy_read,
) -> bytes:
    try:
        if type(current_runtime) is not bool:
            raise TypeError("mode")
        if type(expected_sha256) is not str or _CURRENT_PACKET_SHA256.fullmatch(
            expected_sha256
        ) is None:
            raise TypeError("hash")
        if current_runtime:
            if type(pinned_bytes) is not bytes or not pinned_bytes:
                raise TypeError("bytes")
            data = pinned_bytes
        else:
            if pinned_bytes is not None:
                raise TypeError("pinned")
            if not callable(legacy_read):
                raise TypeError("reader")
            data = legacy_read()
            if type(data) is not bytes or not data:
                raise TypeError("bytes")
        if _sha256(data) != expected_sha256:
            raise ValueError("hash mismatch")
    except Exception:
        raise ValueError(_EVIDENCE_PACKET_BINDING_INVALID) from None
    return data


def resolve_match_policy(
    projection: object,
    *,
    current_runtime: bool = False,
    current_matrix_policy_sha256: object = None,
) -> str:
    """Select the existing policy identity for the active authority mode."""
    if type(current_runtime) is not bool or type(projection) is not dict:
        raise ValueError(_MATCH_POLICY_BINDING_INVALID)
    if any(type(key) is not str for key in projection):
        raise ValueError(_MATCH_POLICY_BINDING_INVALID)
    if current_runtime:
        selected = current_matrix_policy_sha256
        if selected is None:
            raise ValueError(_MATCH_POLICY_BINDING_INVALID)
    else:
        if current_matrix_policy_sha256 is not None:
            raise ValueError(_MATCH_POLICY_BINDING_INVALID)
        if "policy_sha256" not in projection:
            raise ValueError(_MATCH_POLICY_BINDING_INVALID)
        selected = projection["policy_sha256"]
    if (
        type(selected) is not str
        or len(selected) != 64
        or any(character not in "0123456789abcdef" for character in selected)
    ):
        raise ValueError(_MATCH_POLICY_BINDING_INVALID)
    return selected


def match_selected_packet(
    ledger_ids: object,
    projection_rows: object,
    packet_rows: object,
) -> tuple[dict[str, object], ...]:
    invalid = "current candidate evidence packet differs from projection"

    def exact_text(value: object) -> bool:
        return type(value) is str and bool(value)

    def exact_row(value: object, fields: set[str]) -> bool:
        return (
            type(value) is dict
            and all(type(key) is str for key in value)
            and set(value) == fields
        )

    if type(ledger_ids) is not list or not ledger_ids:
        raise ValueError(invalid)
    ledger: set[str] = set()
    for evidence_id in ledger_ids:
        if not exact_text(evidence_id) or evidence_id in ledger:
            raise ValueError(invalid)
        ledger.add(evidence_id)

    if type(projection_rows) is not list or not projection_rows:
        raise ValueError(invalid)
    projection_by_id: dict[str, dict[str, object]] = {}
    for row in projection_rows:
        if not exact_row(
            row, {"id", "kind", "proof_class", "statement_sha256"}
        ):
            raise ValueError(invalid)
        evidence_id = row["id"]
        digest = row["statement_sha256"]
        if (
            not exact_text(evidence_id)
            or evidence_id in projection_by_id
            or not exact_text(row["kind"])
            or not exact_text(row["proof_class"])
            or not exact_text(digest)
            or _CURRENT_PACKET_SHA256.fullmatch(digest) is None
        ):
            raise ValueError(invalid)
        projection_by_id[evidence_id] = row

    if type(packet_rows) is not list or not packet_rows:
        raise ValueError(invalid)
    packet_by_id: dict[str, dict[str, object]] = {}
    for row in packet_rows:
        if not exact_row(
            row,
            {"id", "kind", "proof_class", "statement", "document_targets"},
        ):
            raise ValueError(invalid)
        evidence_id = row["id"]
        targets = row["document_targets"]
        if (
            not exact_text(evidence_id)
            or evidence_id in packet_by_id
            or not exact_text(row["kind"])
            or not exact_text(row["proof_class"])
            or not exact_text(row["statement"])
            or type(targets) is not list
            or not targets
            or any(
                type(target) is not str
                or target not in _DOCUMENT_TARGETS
                for target in targets
            )
            or len(set(targets)) != len(targets)
        ):
            raise ValueError(invalid)
        packet_by_id[evidence_id] = row

    if set(projection_by_id) != set(packet_by_id) or not set(packet_by_id) <= ledger:
        raise ValueError(invalid)

    selected: list[dict[str, object]] = []
    for evidence_id, projection in projection_by_id.items():
        packet = packet_by_id[evidence_id]
        try:
            statement_sha256 = hashlib.sha256(
                packet["statement"].encode("utf-8")
            ).hexdigest()
        except UnicodeEncodeError:
            raise ValueError(invalid) from None
        if (
            projection["kind"] != packet["kind"]
            or projection["proof_class"] != packet["proof_class"]
            or projection["statement_sha256"] != statement_sha256
        ):
            raise ValueError(invalid)
        selected.append(copy.deepcopy(packet))
    return tuple(selected)


@dataclass(frozen=True)
class CandidateApplicationPackage:
    source: ApplicationSource
    artifacts: ApplicationArtifacts
    vacancy_requirements: tuple[str, ...]
    materialized_source: ApplicationSource | None = None
    source_policy_receipt: CandidateSourcePolicyReceipt | None = None
    current_runtime_materialization: CandidateApplicationMaterialization | None = field(
        default=None, repr=False
    )
    current_runtime_decision_authority: MarketApplicationDecisionAuthority | None = field(
        default=None, repr=False
    )


@dataclass(frozen=True)
class CandidateApplicationDeploymentBinding:
    application_id: str
    environment: str
    handoff_root_sha256: str
    admission_receipt_sha256: str
    current_boundary_receipt_sha256: str
    candidate_authority_file_sha256: str
    binding_sha256: str
    schema_version: str = "jaa.candidate-application-deployment-binding.v1"

    def __post_init__(self) -> None:
        expected_schema = (
            CURRENT_RUNTIME_DEPLOYMENT_BINDING_SCHEMA
            if self.environment == CURRENT_RUNTIME_ENVIRONMENT
            else "jaa.candidate-application-deployment-binding.v1"
        )
        if (
            not self.application_id.startswith("app_")
            or self.environment not in {
                "production",
                "synthetic",
                CURRENT_RUNTIME_ENVIRONMENT,
            }
            or self.schema_version != expected_schema
        ):
            raise ValueError("candidate deployment binding scope is invalid")
        for value in (
            self.handoff_root_sha256,
            self.admission_receipt_sha256,
            self.current_boundary_receipt_sha256,
            self.candidate_authority_file_sha256,
            self.binding_sha256,
        ):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("candidate deployment binding hash is invalid")
        if self.binding_sha256 != content_hash(self.document(include_identity=False)):
            raise ValueError("candidate deployment binding identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "admission_receipt_sha256": self.admission_receipt_sha256,
            "application_id": self.application_id,
            "candidate_authority_file_sha256": self.candidate_authority_file_sha256,
            "current_boundary_receipt_sha256": self.current_boundary_receipt_sha256,
            "environment": self.environment,
            "handoff_root_sha256": self.handoff_root_sha256,
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["binding_sha256"] = self.binding_sha256
        return value


def build_candidate_application_deployment_binding(
    *,
    application_id: str,
    environment: str,
    handoff_root_sha256: str,
    admission_receipt_sha256: str,
    current_boundary_receipt_sha256: str,
    candidate_authority_file_sha256: str,
) -> CandidateApplicationDeploymentBinding:
    schema_version = (
        CURRENT_RUNTIME_DEPLOYMENT_BINDING_SCHEMA
        if environment == CURRENT_RUNTIME_ENVIRONMENT
        else "jaa.candidate-application-deployment-binding.v1"
    )
    body = {
        "admission_receipt_sha256": admission_receipt_sha256,
        "application_id": application_id,
        "candidate_authority_file_sha256": candidate_authority_file_sha256,
        "current_boundary_receipt_sha256": current_boundary_receipt_sha256,
        "environment": environment,
        "handoff_root_sha256": handoff_root_sha256,
        "schema_version": schema_version,
    }
    return CandidateApplicationDeploymentBinding(
        application_id=application_id,
        environment=environment,
        handoff_root_sha256=handoff_root_sha256,
        admission_receipt_sha256=admission_receipt_sha256,
        current_boundary_receipt_sha256=current_boundary_receipt_sha256,
        candidate_authority_file_sha256=candidate_authority_file_sha256,
        binding_sha256=content_hash(body),
        schema_version=schema_version,
    )


@dataclass(frozen=True)
class MarketApplicationDecisionAuthority:
    """Exact MA eligibility plus conservative JAA evidence selection.

    Market Aligner remains the authority for whether the vacancy may proceed.
    JAA only projects the already approved candidate evidence against the exact
    admitted requirement object.  This avoids mutating the candidate evidence
    authority with vacancy-specific decisions.
    """

    application_id: str
    environment: str
    handoff_root_sha256: str
    admission_receipt_sha256: str
    current_boundary_receipt_sha256: str
    source_job_key: str
    internal_job_key: str
    vacancy_snapshot_sha256: str
    raw_listing_sha256: str
    requirements_sha256: str
    assessment_receipt_sha256: str
    eligibility_receipt_sha256: str
    selection_receipt_sha256: str
    candidate_projection_sha256: str
    candidate_authority_file_sha256: str
    candidate_authority_object_sha256: str
    evidence_ledger_sha256: str
    approved_evidence_file_sha256: str
    approved_evidence_object_sha256: str
    evidence_projection_sha256: str
    matrix_policy_sha256: str
    evidence_matrix_sha256: str
    evidence_matrix: tuple[Mapping[str, object], ...]
    source_url: str
    role_title: str
    company_name: str
    observed_at: str
    authority_sha256: str
    schema_version: str = "jaa.market-application-decision-authority.v1"
    release_authority: bool = False

    def __post_init__(self) -> None:
        if (
            not self.application_id.startswith("app_")
            or self.environment
            not in {"production", "synthetic", CURRENT_RUNTIME_ENVIRONMENT}
            or self.schema_version
            != (
                CURRENT_RUNTIME_DECISION_AUTHORITY_SCHEMA
                if self.environment == CURRENT_RUNTIME_ENVIRONMENT
                else "jaa.market-application-decision-authority.v1"
            )
            or not self.source_job_key
            or not self.internal_job_key
            or not self.source_url
            or not self.role_title
            or not self.company_name
            or not self.observed_at
            or not self.evidence_matrix
            or self.release_authority is not False
        ):
            raise ValueError("market application decision authority is malformed")
        for value in (
            self.handoff_root_sha256,
            self.admission_receipt_sha256,
            self.current_boundary_receipt_sha256,
            self.vacancy_snapshot_sha256,
            self.raw_listing_sha256,
            self.requirements_sha256,
            self.assessment_receipt_sha256,
            self.eligibility_receipt_sha256,
            self.selection_receipt_sha256,
            self.candidate_projection_sha256,
            self.candidate_authority_file_sha256,
            self.candidate_authority_object_sha256,
            self.evidence_ledger_sha256,
            self.approved_evidence_file_sha256,
            self.approved_evidence_object_sha256,
            self.evidence_projection_sha256,
            self.matrix_policy_sha256,
            self.evidence_matrix_sha256,
            self.authority_sha256,
        ):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("market application decision hash is invalid")
        if self.evidence_matrix_sha256 != content_hash(
            [dict(row) for row in self.evidence_matrix]
        ):
            raise ValueError("market application evidence matrix identity is invalid")
        if self.matrix_policy_sha256 != CANONICAL_REQUIREMENTS_MATRIX_POLICY_SHA256:
            raise ValueError("market application matrix policy identity is invalid")
        if self.authority_sha256 != content_hash(self.document(include_identity=False)):
            raise ValueError("market application decision identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "admission_receipt_sha256": self.admission_receipt_sha256,
            "application_id": self.application_id,
            "assessment_receipt_sha256": self.assessment_receipt_sha256,
            "approved_evidence_file_sha256": self.approved_evidence_file_sha256,
            "approved_evidence_object_sha256": self.approved_evidence_object_sha256,
            "candidate_projection_sha256": self.candidate_projection_sha256,
            "candidate_authority_file_sha256": self.candidate_authority_file_sha256,
            "candidate_authority_object_sha256": self.candidate_authority_object_sha256,
            "company_name": self.company_name,
            "current_boundary_receipt_sha256": self.current_boundary_receipt_sha256,
            "eligibility_receipt_sha256": self.eligibility_receipt_sha256,
            "evidence_ledger_sha256": self.evidence_ledger_sha256,
            "environment": self.environment,
            "evidence_matrix": [dict(row) for row in self.evidence_matrix],
            "evidence_matrix_sha256": self.evidence_matrix_sha256,
            "evidence_projection_sha256": self.evidence_projection_sha256,
            "handoff_root_sha256": self.handoff_root_sha256,
            "internal_job_key": self.internal_job_key,
            "matrix_policy_sha256": self.matrix_policy_sha256,
            "observed_at": self.observed_at,
            "raw_listing_sha256": self.raw_listing_sha256,
            "release_authority": False,
            "requirements_sha256": self.requirements_sha256,
            "role_title": self.role_title,
            "schema_version": self.schema_version,
            "selection_receipt_sha256": self.selection_receipt_sha256,
            "source_job_key": self.source_job_key,
            "source_url": self.source_url,
            "vacancy_snapshot_sha256": self.vacancy_snapshot_sha256,
        }
        if include_identity:
            value["authority_sha256"] = self.authority_sha256
        return value

    def decision_receipt(self) -> dict[str, object]:
        """Return the legacy-shaped deterministic input consumed by the compiler."""
        return {
            "candidate_projection_sha256": self.candidate_projection_sha256,
            "company_name": self.company_name,
            "decision": "eligible",
            "evidence_matrix": [dict(row) for row in self.evidence_matrix],
            "job_key": self.source_job_key,
            "observed_at": self.observed_at,
            "role_title": self.role_title,
            "source_url": self.source_url,
            "vacancy_description_sha256": self.requirements_sha256,
            "vacancy_sha256": self.raw_listing_sha256,
            "vacancy_snapshot_sha256": self.vacancy_snapshot_sha256,
        }


def build_market_application_decision_authority(
    *,
    deployment_binding: CandidateApplicationDeploymentBinding,
    source_job_key: str,
    internal_job_key: str,
    vacancy_snapshot_sha256: str,
    raw_listing_sha256: str,
    raw_listing_bytes: bytes,
    requirements_sha256: str,
    requirements_bytes: bytes,
    assessment_receipt_sha256: str,
    assessment_receipt_bytes: bytes,
    eligibility_receipt_sha256: str,
    eligibility_receipt_bytes: bytes,
    selection_receipt_sha256: str,
    selection_receipt_bytes: bytes,
    candidate_projection: Mapping[str, object],
    candidate_authority_bytes: bytes,
    evidence_ledger_sha256: str,
    evidence_ledger_bytes: bytes,
    source_url: str,
    role_title: str,
    company_name: str,
    observed_at: str,
    approved_evidence_path: Path = APPROVED_EVIDENCE_PATH,
    approved_evidence_bytes: bytes | None = None,
) -> MarketApplicationDecisionAuthority:
    """Compile an exact integrated decision from a freshly verified MA graph."""

    deployment_binding.__post_init__()
    exact = (
        (raw_listing_sha256, raw_listing_bytes, "raw listing"),
        (requirements_sha256, requirements_bytes, "requirements"),
        (assessment_receipt_sha256, assessment_receipt_bytes, "assessment"),
        (eligibility_receipt_sha256, eligibility_receipt_bytes, "eligibility"),
        (selection_receipt_sha256, selection_receipt_bytes, "selection"),
        (deployment_binding.candidate_authority_file_sha256, candidate_authority_bytes, "candidate authority"),
        (evidence_ledger_sha256, evidence_ledger_bytes, "evidence ledger"),
    )
    for expected, value, label in exact:
        if _sha256(value) != expected:
            raise ValueError(f"market application {label} bytes differ")
    try:
        assessment = json.loads(assessment_receipt_bytes)
        eligibility = json.loads(eligibility_receipt_bytes)
        selection = json.loads(selection_receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("market application decision object is not JSON") from exc
    promotion = assessment.get("receipt_sha256") if isinstance(assessment, dict) else None
    if (
        not isinstance(assessment, dict)
        or assessment.get("schema_version")
        != "market-aligner.assessment-promotion-receipt.v1"
        or assessment.get("decision") != "pass"
        or assessment.get("job_key") != source_job_key
        or not isinstance(promotion, str)
        or not isinstance(eligibility, dict)
        or set(eligibility)
        != {"checks", "decision", "hard_gate_passed", "promotion_receipt_sha256", "source_job_key"}
        or eligibility.get("decision") != "eligible"
        or eligibility.get("hard_gate_passed") is not True
        or eligibility.get("promotion_receipt_sha256") != promotion
        or eligibility.get("source_job_key") != source_job_key
        or not isinstance(selection, dict)
        or selection.get("decision") != "selected_for_application"
        or selection.get("hard_gate_passed") is not True
        or selection.get("promotion_receipt_sha256") != promotion
        or selection.get("source_job_key") != source_job_key
    ):
        raise ValueError("market application eligibility authority differs")
    projection_sha256 = candidate_projection.get("projection_sha256")
    if not isinstance(projection_sha256, str):
        raise ValueError("market application candidate projection is malformed")
    try:
        candidate_authority_document = json.loads(candidate_authority_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("market application candidate authority is not JSON") from exc
    if (
        not isinstance(candidate_authority_document, dict)
        or candidate_authority_document.get("candidate_projection")
        != dict(candidate_projection)
    ):
        raise ValueError("market application candidate evidence authority differs")
    current_runtime = deployment_binding.environment == CURRENT_RUNTIME_ENVIRONMENT
    current_profile_ledger_sha256: str | None = None
    if current_runtime:
        profile_binding = candidate_authority_document.get("profile_binding")
        if (
            not isinstance(profile_binding, dict)
            or type(profile_binding.get("evidence_ledger_sha256")) is not str
            or _CURRENT_PACKET_SHA256.fullmatch(
                profile_binding["evidence_ledger_sha256"]
            ) is None
        ):
            raise ValueError("market application current profile ledger binding differs")
        current_profile_ledger_sha256 = profile_binding["evidence_ledger_sha256"]
    expected_evidence_sha256 = None
    if current_runtime:
        expected_evidence_sha256 = _projection_evidence_sha256(
            candidate_projection,
            {"candidate_projection_sha256": projection_sha256},
        )
    approved_statements, approved_evidence_source = _load_approved_statements(
        approved_evidence_path,
        expected_evidence_sha256=expected_evidence_sha256,
        current_runtime=current_runtime,
        approved_evidence_bytes=approved_evidence_bytes,
    )
    evidence_bytes = approved_evidence_source.source_bytes
    evidence_document = json.loads(evidence_bytes)
    try:
        ledger_rows = [json.loads(line) for line in evidence_ledger_bytes.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("market application evidence ledger is not JSON") from exc
    if not ledger_rows or any(not isinstance(row, dict) for row in ledger_rows):
        raise ValueError("market application candidate evidence authority differs")
    projected_rows = candidate_projection.get("approved_evidence")
    if current_runtime:
        try:
            current_evidence_items = [EvidenceItem(**row) for row in ledger_rows]
        except (AttributeError, TypeError, ValueError):
            raise ValueError("market application current evidence ledger differs") from None
        if (
            canonical_hash([asdict(item) for item in current_evidence_items])
            != current_profile_ledger_sha256
        ):
            raise ValueError("market application current profile ledger binding differs")
        packet_rows = evidence_document.get("statements")
        ledger_evidence = match_selected_packet(
            [item.evidence_id for item in current_evidence_items],
            projected_rows,
            packet_rows,
        )
    else:
        projected = {
            str(row["id"]): (str(row["statement_sha256"]), str(row["kind"]))
            for row in projected_rows
            if isinstance(row, Mapping)
        } if isinstance(projected_rows, list) else {}
        ledger_ids: set[str] = set()
        ledger_order: list[str] = []
        for row in ledger_rows:
            evidence_id = row.get("evidence_id")
            claim = row.get("claim")
            if (
                set(row)
                != {
                    "claim", "confidence", "content_sha256", "evidence_id", "kind",
                    "observed_at", "source_ref", "status",
                }
                or not isinstance(evidence_id, str)
                or evidence_id in ledger_ids
                or not isinstance(claim, str)
                or _sha256(claim.encode()) != row.get("content_sha256")
                or projected.get(evidence_id)
                != (row.get("content_sha256"), row.get("kind"))
                or type(row.get("confidence")) is not float
                or row.get("confidence") != 1.0
                or row.get("observed_at") is not None
                or row.get("source_ref") != f"authority://approved-evidence/{evidence_id}"
                or row.get("status") != "explicit"
            ):
                raise ValueError("market application evidence ledger differs from candidate projection")
            ledger_ids.add(evidence_id)
            ledger_order.append(evidence_id)
        ledger_evidence = tuple(
            approved_statements[evidence_id] for evidence_id in ledger_order
        )
    compiled = compile_canonical_requirements_evidence_matrix(
        requirements_bytes, ledger_evidence
    )
    if compiled["requirements_sha256"] != requirements_sha256:
        raise ValueError("market application requirement authority differs")
    matrix = tuple(dict(row) for row in compiled["matrix"])
    values = {
        "admission_receipt_sha256": deployment_binding.admission_receipt_sha256,
        "application_id": deployment_binding.application_id,
        "assessment_receipt_sha256": assessment_receipt_sha256,
        "approved_evidence_file_sha256": _sha256(evidence_bytes),
        "approved_evidence_object_sha256": content_hash(evidence_document),
        "candidate_projection_sha256": projection_sha256,
        "candidate_authority_file_sha256": deployment_binding.candidate_authority_file_sha256,
        "candidate_authority_object_sha256": content_hash(candidate_authority_document),
        "company_name": company_name,
        "current_boundary_receipt_sha256": deployment_binding.current_boundary_receipt_sha256,
        "eligibility_receipt_sha256": eligibility_receipt_sha256,
        "environment": deployment_binding.environment,
        "evidence_ledger_sha256": evidence_ledger_sha256,
        "evidence_matrix": [dict(row) for row in matrix],
        "evidence_matrix_sha256": content_hash([dict(row) for row in matrix]),
        "evidence_projection_sha256": str(compiled["evidence_projection_sha256"]),
        "handoff_root_sha256": deployment_binding.handoff_root_sha256,
        "internal_job_key": internal_job_key,
        "matrix_policy_sha256": str(compiled["matrix_policy_sha256"]),
        "observed_at": observed_at,
        "raw_listing_sha256": raw_listing_sha256,
        "release_authority": False,
        "requirements_sha256": requirements_sha256,
        "role_title": role_title,
        "schema_version": (
            CURRENT_RUNTIME_DECISION_AUTHORITY_SCHEMA
            if deployment_binding.environment == CURRENT_RUNTIME_ENVIRONMENT
            else "jaa.market-application-decision-authority.v1"
        ),
        "selection_receipt_sha256": selection_receipt_sha256,
        "source_job_key": source_job_key,
        "source_url": source_url,
        "vacancy_snapshot_sha256": vacancy_snapshot_sha256,
    }
    return MarketApplicationDecisionAuthority(
        application_id=deployment_binding.application_id,
        environment=deployment_binding.environment,
        handoff_root_sha256=deployment_binding.handoff_root_sha256,
        admission_receipt_sha256=deployment_binding.admission_receipt_sha256,
        current_boundary_receipt_sha256=deployment_binding.current_boundary_receipt_sha256,
        source_job_key=source_job_key,
        internal_job_key=internal_job_key,
        vacancy_snapshot_sha256=vacancy_snapshot_sha256,
        raw_listing_sha256=raw_listing_sha256,
        requirements_sha256=requirements_sha256,
        assessment_receipt_sha256=assessment_receipt_sha256,
        eligibility_receipt_sha256=eligibility_receipt_sha256,
        selection_receipt_sha256=selection_receipt_sha256,
        candidate_projection_sha256=projection_sha256,
        candidate_authority_file_sha256=deployment_binding.candidate_authority_file_sha256,
        candidate_authority_object_sha256=content_hash(candidate_authority_document),
        evidence_ledger_sha256=evidence_ledger_sha256,
        approved_evidence_file_sha256=_sha256(evidence_bytes),
        approved_evidence_object_sha256=content_hash(evidence_document),
        evidence_projection_sha256=str(compiled["evidence_projection_sha256"]),
        matrix_policy_sha256=str(compiled["matrix_policy_sha256"]),
        evidence_matrix_sha256=str(values["evidence_matrix_sha256"]),
        evidence_matrix=matrix,
        source_url=source_url,
        role_title=role_title,
        company_name=company_name,
        observed_at=observed_at,
        authority_sha256=content_hash(values),
        schema_version=str(values["schema_version"]),
    )


@dataclass(frozen=True)
class CandidateApplicationMaterializationReceipt:
    """Non-release proof that exact authorities produced one application source."""

    candidate_authority_file_sha256: str
    candidate_authority_object_sha256: str
    candidate_projection_sha256: str
    deployment_binding: CandidateApplicationDeploymentBinding
    contact_authority_sha256: str | None
    contact_envelope_sha256: str | None
    contact_registry_sha256: str | None
    contact_signer_public_key_sha256: str | None
    cv_claim_set_sha256: str
    approved_evidence_file_sha256: str
    approved_evidence_object_sha256: str
    decision_receipt_sha256: str
    vacancy_sha256: str
    vacancy_snapshot_sha256: str
    decision_authority_schema: str
    decision_authority_sha256: str
    job_key: str
    role_title: str
    company_name: str
    source_url: str
    application_source_id: str
    application_source_sha256: str
    fact_bindings: tuple[Mapping[str, object], ...]
    style_bindings: tuple[Mapping[str, object], ...]
    source_policy_receipt: CandidateSourcePolicyReceipt | PreEditorialSourceEnvelopeReceipt
    receipt_sha256: str
    schema_version: str = "jaa.candidate-application-materialization-receipt.v3"
    release_authority: bool = False
    contact_provenance_sha256: str | None = None
    contact_provenance_schema: str | None = None
    contact_source_hashes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        current_runtime = (
            self.deployment_binding.environment == CURRENT_RUNTIME_ENVIRONMENT
        )
        for value in (
            self.candidate_authority_file_sha256,
            self.candidate_authority_object_sha256,
            self.candidate_projection_sha256,
            self.cv_claim_set_sha256,
            self.approved_evidence_file_sha256,
            self.approved_evidence_object_sha256,
            self.decision_receipt_sha256,
            self.vacancy_sha256,
            self.vacancy_snapshot_sha256,
            self.decision_authority_sha256,
            self.application_source_id,
            self.application_source_sha256,
            self.receipt_sha256,
        ):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("materialization receipt identity is not SHA-256")
        if current_runtime:
            if (
                any(
                    value is not None
                    for value in (
                        self.contact_authority_sha256,
                        self.contact_envelope_sha256,
                        self.contact_registry_sha256,
                        self.contact_signer_public_key_sha256,
                    )
                )
                or type(self.contact_provenance_sha256) is not str
                or len(self.contact_provenance_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.contact_provenance_sha256)
                or self.contact_provenance_schema != "current-contact-provenance-v1"
                or not self.contact_source_hashes
                or self.contact_source_hashes != tuple(sorted(set(self.contact_source_hashes)))
                or any(
                    type(value) is not str
                    or len(value) != 64
                    or any(c not in "0123456789abcdef" for c in value)
                    for value in self.contact_source_hashes
                )
            ):
                raise ValueError("current materialization contact provenance is malformed")
        elif (
            self.contact_provenance_sha256 is not None
            or self.contact_provenance_schema is not None
            or self.contact_source_hashes
            or any(
                type(value) is not str
                or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
                for value in (
                    self.contact_authority_sha256,
                    self.contact_envelope_sha256,
                    self.contact_registry_sha256,
                    self.contact_signer_public_key_sha256,
                )
            )
        ):
            raise ValueError("legacy materialization contact authority is malformed")
        if (
            not self.job_key
            or not self.role_title
            or not self.company_name
            or not self.source_url
            or not self.decision_authority_schema
            or not self.fact_bindings
            or self.release_authority is not False
            or self.schema_version
            != (
                CURRENT_RUNTIME_MATERIALIZATION_RECEIPT_SCHEMA
                if self.deployment_binding.environment == CURRENT_RUNTIME_ENVIRONMENT
                else "jaa.candidate-application-materialization-receipt.v3"
            )
        ):
            raise ValueError("materialization receipt authority is malformed")
        if current_runtime:
            if type(self.source_policy_receipt) is not PreEditorialSourceEnvelopeReceipt:
                raise ValueError("current source envelope receipt type is invalid")
        elif not isinstance(self.source_policy_receipt, CandidateSourcePolicyReceipt):
            raise ValueError("materialization source policy receipt type is invalid")
        self.source_policy_receipt.__post_init__()
        if not isinstance(self.deployment_binding, CandidateApplicationDeploymentBinding):
            raise ValueError("materialization deployment binding type is invalid")
        self.deployment_binding.__post_init__()
        if (
            self.deployment_binding.candidate_authority_file_sha256
            != self.candidate_authority_file_sha256
        ):
            raise ValueError("materialization candidate authority is not admitted")
        cv_claim_rows = [
            dict(row)
            for row in self.fact_bindings
            if row.get("document_kind") == "cv"
        ]
        if self.cv_claim_set_sha256 != content_hash(cv_claim_rows):
            raise ValueError("materialization CV claim-set identity is invalid")
        if self.receipt_sha256 != content_hash(self.document(include_identity=False)):
            raise ValueError("materialization receipt identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "application_source_id": self.application_source_id,
            "application_source_sha256": self.application_source_sha256,
            "approved_evidence_file_sha256": self.approved_evidence_file_sha256,
            "approved_evidence_object_sha256": self.approved_evidence_object_sha256,
            "candidate_authority_file_sha256": self.candidate_authority_file_sha256,
            "candidate_authority_object_sha256": self.candidate_authority_object_sha256,
            "candidate_projection_sha256": self.candidate_projection_sha256,
            "contact_authority_sha256": self.contact_authority_sha256,
            "contact_envelope_sha256": self.contact_envelope_sha256,
            "contact_registry_sha256": self.contact_registry_sha256,
            "contact_signer_public_key_sha256": (
                self.contact_signer_public_key_sha256
            ),
            "cv_claim_set_sha256": self.cv_claim_set_sha256,
            "deployment_binding": self.deployment_binding.document(),
            "source_policy_receipt": self.source_policy_receipt.document(),
            "decision_receipt_sha256": self.decision_receipt_sha256,
            "decision_authority_schema": self.decision_authority_schema,
            "decision_authority_sha256": self.decision_authority_sha256,
            "fact_bindings": [dict(row) for row in self.fact_bindings],
            "job_key": self.job_key,
            "role_title": self.role_title,
            "company_name": self.company_name,
            "source_url": self.source_url,
            "release_authority": False,
            "schema_version": self.schema_version,
            "style_bindings": [dict(row) for row in self.style_bindings],
            "vacancy_sha256": self.vacancy_sha256,
            "vacancy_snapshot_sha256": self.vacancy_snapshot_sha256,
        }
        if self.deployment_binding.environment == CURRENT_RUNTIME_ENVIRONMENT:
            value.update(
                {
                    "contact_provenance_sha256": self.contact_provenance_sha256,
                    "contact_provenance_schema": self.contact_provenance_schema,
                    "contact_source_hashes": list(self.contact_source_hashes),
                }
            )
        if include_identity:
            value["receipt_sha256"] = self.receipt_sha256
        return value

    def authorize_editorial_request(self, request: object) -> None:
        """Fail closed unless an editorial request exactly projects this receipt."""
        authority = getattr(request, "authority", None)
        if getattr(authority, "source_sha256", None) != self.candidate_authority_file_sha256:
            raise ValueError("editorial request candidate authority differs")
        current_runtime = (
            self.deployment_binding.environment == CURRENT_RUNTIME_ENVIRONMENT
        )
        request_current_runtime = getattr(authority, "current_runtime", False)
        if (
            type(request_current_runtime) is not bool
            or request_current_runtime is not current_runtime
        ):
            raise ValueError("editorial request runtime mode differs from materialization")
        if getattr(request, "vacancy_sha256", None) != self.vacancy_sha256:
            raise ValueError("editorial request vacancy authority differs")
        if (
            getattr(request, "role_title", None) != self.role_title
            or getattr(request, "company_name", None) != self.company_name
        ):
            raise ValueError("editorial request vacancy identity differs")
        document_kind = getattr(request, "document_kind", "cv")
        if document_kind not in {"cv", "cover_letter"}:
            raise ValueError("editorial request document kind is unsupported")
        bindings = {
            str(row["sentence_id"]): row
            for row in self.fact_bindings
            if row.get("document_kind") == document_kind
        }
        if current_runtime and document_kind == "cv":
            accepted_bindings, _ = partition_current_cv_claim_bindings(
                tuple(dict(row) for row in self.fact_bindings)
            )
            bindings = {
                row["sentence_id"]: row for row in accepted_bindings
            }
        claims = getattr(request, "approved_claims", ())
        if not claims:
            raise ValueError("editorial request has no materialized claims")
        if document_kind == "cv":
            from cv_generation.editorial_composition import category_for_source_heading

            request_rows = {
                claim.claim_id: {
                    "category": claim.category,
                    "evidence_ids": tuple(claim.evidence_ids),
                    "text": claim.text,
                    "text_sha256": claim.text_sha256,
                }
                for claim in claims
            }
            expected_rows = {
                sentence_id: {
                    "category": category_for_source_heading(
                        binding["section_heading"], current_runtime=current_runtime
                    ),
                    "evidence_ids": tuple(binding["evidence_ids"]),
                    "text": binding["text"],
                    "text_sha256": binding["text_sha256"],
                }
                for sentence_id, binding in bindings.items()
            }
        else:
            request_rows = {
                claim.claim_id: {
                    "evidence_ids": tuple(claim.evidence_ids),
                    "fact_kind": claim.fact_kind,
                    "section_heading": claim.section_heading,
                    "text": claim.text,
                    "text_sha256": claim.text_sha256,
                }
                for claim in claims
            }
            expected_rows = {
                sentence_id: {
                    "evidence_ids": tuple(binding["evidence_ids"]),
                    "fact_kind": binding["fact_kind"],
                    "section_heading": binding["section_heading"],
                    "text": binding["text"],
                    "text_sha256": binding["text_sha256"],
                }
                for sentence_id, binding in bindings.items()
            }
        if request_rows != expected_rows:
            raise ValueError("editorial request claim set differs from materialization")
        for claim in claims:
            binding = bindings.get(claim.claim_id)
            if (
                binding is None
                or binding["text_sha256"] != claim.text_sha256
                or binding["text"] != claim.text
                or tuple(binding["evidence_ids"]) != tuple(claim.evidence_ids)
            ):
                raise ValueError("editorial request claim differs from materialization")


@dataclass(frozen=True)
class CandidateApplicationMaterialization:
    source: ApplicationSource
    editable: EditableArtifacts
    vacancy_requirements: tuple[str, ...]
    receipt: CandidateApplicationMaterializationReceipt


@dataclass(frozen=True)
class _CandidateApplicationSourceBuild:
    source: ApplicationSource
    vacancy_requirements: tuple[str, ...]


class GenerationRevisionWriter(Protocol):
    """Durable sink called synchronously as each production value is created."""

    def __call__(
        self,
        *,
        role: str,
        value: bytes,
        media_type: str,
        prior_sha256: str | None = None,
        approved: bool = True,
        rejection_codes: tuple[str, ...] = (),
    ) -> object: ...


def _projection_evidence_sha256(
    candidate_projection: Mapping[str, object],
    decision_receipt: Mapping[str, object],
) -> str:
    claimed = candidate_projection.get("projection_sha256")
    if (
        not isinstance(claimed, str)
        or len(claimed) != 64
        or any(character not in "0123456789abcdef" for character in claimed)
        or decision_receipt.get("candidate_projection_sha256") != claimed
    ):
        raise ValueError("application factory candidate projection binding differs")
    projection_body = {
        key: value
        for key, value in candidate_projection.items()
        if key != "projection_sha256"
    }
    try:
        computed = _sha256((canonical_json(projection_body) + "\n").encode("utf-8"))
    except (TypeError, ValueError):
        raise ValueError("application factory candidate projection is malformed") from None
    if computed != claimed:
        raise ValueError("application factory candidate projection content differs")
    source_hashes = candidate_projection.get("source_hashes")
    expected = (
        source_hashes.get("approved_evidence")
        if isinstance(source_hashes, Mapping)
        else None
    )
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise ValueError("application factory candidate evidence digest is malformed")
    return expected


def _approved_statements(
    path: Path,
    *,
    expected_evidence_sha256: str | None = None,
    current_runtime: bool = False,
    approved_evidence_bytes: bytes | None = None,
) -> dict[str, dict[str, object]]:
    statements, _source_context = _load_approved_statements(
        path,
        expected_evidence_sha256=expected_evidence_sha256,
        current_runtime=current_runtime,
        approved_evidence_bytes=approved_evidence_bytes,
    )
    return statements


def _load_approved_statements(
    path: Path,
    *,
    expected_evidence_sha256: str | None = None,
    current_runtime: bool = False,
    approved_evidence_bytes: bytes | None = None,
) -> tuple[dict[str, dict[str, object]], ApprovedEvidenceSourceContext]:
    if expected_evidence_sha256 is None:
        expected = (
            ""
            if current_runtime
            else APPROVED_CANDIDATE_SOURCE_HASHES["approved_evidence"]
        )
    else:
        expected = expected_evidence_sha256
    value = resolve_evidence_packet(
        current_runtime=current_runtime,
        pinned_bytes=approved_evidence_bytes,
        expected_sha256=expected,
        legacy_read=path.read_bytes,
    )
    source_context = ApprovedEvidenceSourceContext(value, expected)
    document = json.loads(value)
    rows = document.get("statements")
    if not isinstance(rows, list):
        raise ValueError("application factory candidate evidence is malformed")
    result = {str(row["id"]): dict(row) for row in rows if isinstance(row, Mapping)}
    if len(result) != len(rows):
        raise ValueError("application factory candidate evidence is ambiguous")
    for row in result.values():
        _evidence_document_targets(row)
    return result, source_context


_DOCUMENT_TARGETS = frozenset({"cv", "cover_letter"})


def _evidence_document_targets(evidence: Mapping[str, object]) -> frozenset[str]:
    if "document_targets" not in evidence:
        return _DOCUMENT_TARGETS
    raw = evidence["document_targets"]
    if (
        not isinstance(raw, list)
        or not raw
        or any(not isinstance(value, str) or value not in _DOCUMENT_TARGETS for value in raw)
        or len(set(raw)) != len(raw)
    ):
        raise ValueError("candidate evidence document targets are malformed")
    return frozenset(raw)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


_CV_BINDING_DOCUMENT_KINDS = ("cv", "cover_letter")
_CV_BINDING_REQUIRED_FIELDS = ("document_kind", "sentence_id", "text", "text_sha256")
_INTERNAL_ONLY_CV_BINDING_REASON = "internal_evidence_only"


def _partition_cv_bindings_fail(message: str) -> None:
    raise ValueError("partition_cv_claim_bindings: " + message)


def partition_cv_claim_bindings(
    rows: object,
    *,
    prohibited_text: Callable[[str], bool],
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, str], ...]]:
    if not callable(prohibited_text):
        _partition_cv_bindings_fail("prohibited_text must be callable")
    if not isinstance(rows, (tuple, list)):
        _partition_cv_bindings_fail("rows must be a tuple or list")

    seen_sentence_ids: set[str] = set()
    cv_positions: list[int] = []
    for position, row in enumerate(rows):
        if type(row) is not dict:
            _partition_cv_bindings_fail(f"row {position} must be an exact dict")
        for field_name in _CV_BINDING_REQUIRED_FIELDS:
            if field_name not in row:
                _partition_cv_bindings_fail(
                    f"row {position} is missing required field {field_name!r}"
                )
        document_kind = row["document_kind"]
        if (
            type(document_kind) is not str
            or document_kind not in _CV_BINDING_DOCUMENT_KINDS
        ):
            _partition_cv_bindings_fail(f"row {position} has invalid document_kind")
        sentence_id = row["sentence_id"]
        if type(sentence_id) is not str or not sentence_id:
            _partition_cv_bindings_fail(f"row {position} has invalid sentence_id")
        text = row["text"]
        if type(text) is not str or not text:
            _partition_cv_bindings_fail(f"row {position} has invalid text")
        text_sha256 = row["text_sha256"]
        if type(text_sha256) is not str:
            _partition_cv_bindings_fail(f"row {position} has invalid text_sha256 type")
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if text_sha256 != expected:
            _partition_cv_bindings_fail(
                f"row {position} text_sha256 does not match exact UTF-8 text"
            )
        if sentence_id in seen_sentence_ids:
            _partition_cv_bindings_fail(f"duplicate sentence_id {sentence_id!r}")
        seen_sentence_ids.add(sentence_id)
        if document_kind == "cv":
            cv_positions.append(position)

    accepted: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for position in cv_positions:
        row = rows[position]
        verdict = prohibited_text(row["text"])
        if type(verdict) is not bool:
            _partition_cv_bindings_fail(
                f"callback returned non-bool for row {position}"
            )
        if verdict is True:
            excluded.append(
                {
                    "sentence_id": row["sentence_id"],
                    "text_sha256": row["text_sha256"],
                    "reason": _INTERNAL_ONLY_CV_BINDING_REASON,
                }
            )
        else:
            accepted.append(row)

    if not accepted:
        _partition_cv_bindings_fail(
            "no accepted CV rows; empty outward document is prohibited"
        )
    return tuple(accepted), tuple(excluded)


def partition_current_cv_claim_bindings(
    rows: object,
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, str], ...]]:
    return partition_cv_claim_bindings(
        rows,
        prohibited_text=lambda text: _REJECTION_SIGNAL.search(text) is not None,
    )


def _candidate_statement_is_outward_safe(
    value: str,
    *,
    current_runtime: bool = False,
) -> bool:
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or type(current_runtime) is not bool
    ):
        return False
    if current_runtime:
        return True
    folded = value.casefold()
    internal_markers = (
        "ai-assisted",
        "ai agents",
        "approved evidence",
        "audit",
        "evidence",
        "governance",
        "model provenance",
        "prompt",
        "software factory",
    )
    return not any(marker in folded for marker in internal_markers)


def _outward_profile_text(
    evidence: Mapping[str, object],
    *,
    document_kind: str | None = None,
    current_runtime: bool = False,
) -> str:
    evidence_id = str(evidence["id"])
    return approved_candidate_outward_text(
        evidence_id,
        str(evidence["statement"]),
        document_kind=document_kind or "cv",
        current_runtime=current_runtime,
    )


def _employer_document(
    claim_id: str,
    text: str,
    *,
    source_identity: str,
) -> dict[str, object]:
    return {
        "id": claim_id,
        "kind": "role",
        "classification": "fact",
        "text": text,
        "source_ids": [source_identity],
    }


def _employer_requirement_statement(
    *,
    company_name: str,
    role_title: str,
    requirement_text: str,
) -> str:
    """Render an exact captured requirement as normal employer-facing prose."""
    requirement = requirement_text.strip().rstrip(".")
    words = requirement.split(maxsplit=1)
    if words and words[0].casefold() in {
        "be",
        "build",
        "demonstrate",
        "develop",
        "have",
        "know",
        "possess",
        "understand",
        "use",
        "work",
    }:
        predicate = words[0].casefold()
        if len(words) == 2:
            predicate = f"{predicate} {words[1]}"
        return (
            f"For the {role_title} position, {company_name} specifically asks "
            f"candidates to {predicate}."
        )
    if words and words[0].casefold().endswith("ing"):
        return (
            f"For the {role_title} position, {company_name} describes the work "
            f"as {requirement[0].casefold() + requirement[1:]}."
        )
    if requirement.casefold().startswith("experience with "):
        return (
            f"The {role_title} position at {company_name} calls for "
            f"{requirement[0].casefold() + requirement[1:]}."
        )
    return (
        f"The {role_title} position at {company_name} lists this requirement: "
        f"{requirement}."
    )


def _sentence(
    element,
    *,
    text: str,
    fact_kind: str,
    document_kind: str,
    employer_fact_json: str | None = None,
) -> FactualSentence:
    return FactualSentence(
        content_hash(
            {
                "contract": "jaa07.factual-sentence.v1",
                "element_id": element.element_id,
                "text": text,
                "fact_kind": fact_kind,
                "document_kind": document_kind,
            }
        ),
        text,
        text,
        fact_kind,
        document_kind,
        FactAuthority.from_element(element),
        employer_fact_json,
    )


def _profile_sentence(
    *,
    evidence: Mapping[str, object],
    candidate_profile_hash: str,
    statement_sha256: str,
    document_kind: str,
    approved_evidence_source: ApprovedEvidenceSourceContext | None = None,
    current_runtime: bool = False,
) -> FactualSentence:
    evidence_id = str(evidence["id"])
    approved_source_text = str(evidence["statement"])
    text = _outward_profile_text(
        evidence,
        document_kind=document_kind,
        current_runtime=current_runtime,
    )
    rewritten = text != approved_source_text
    rewrite_authority = (
        resolve_authenticated_outward_rewrite(
            candidate_evidence_id=evidence_id,
            candidate_evidence_version=1,
            approved_source_text=approved_source_text,
            outward_text=text,
            document_kind=document_kind,
            approved_evidence_source=approved_evidence_source,
            candidate_profile_hash=candidate_profile_hash,
            current_runtime=current_runtime,
        )
        if rewritten
        else None
    )
    authority = ProfileFactAuthority(
        candidate_profile_hash=candidate_profile_hash,
        candidate_claim_id=f"approved-claim:{evidence_id}",
        candidate_claim_version=1,
        candidate_evidence_id=evidence_id,
        candidate_evidence_version=1,
        candidate_evidence_sha256=statement_sha256,
        proof_class=str(evidence["proof_class"]),
        rewrite_authority=rewrite_authority,
    )
    return FactualSentence(
        content_hash(
            {
                "contract": "jaa07.profile-factual-sentence.v1",
                "candidate_profile_hash": candidate_profile_hash,
                "candidate_evidence_id": evidence_id,
                "candidate_evidence_sha256": statement_sha256,
                "text": text,
                "document_kind": document_kind,
            }
        ),
        text,
        approved_source_text,
        "candidate",
        document_kind,
        authority,
    )


def _slot(document_kind: str, purpose: str, text: str) -> StyleSlot:
    return StyleSlot(
        content_hash(
            {
                "contract": "jaa07.deterministic-style-slot.v1",
                "document_kind": document_kind,
                "purpose": purpose,
                "text": text,
            }
        ),
        document_kind,
        text,
    )


def _profile_cv_section_for_evidence(
    evidence_id: str,
    proof_class: str,
    *,
    legacy_profile: bool,
) -> str:
    legacy_heading = (
        _PROFILE_CV_LEGACY_SECTION_BY_EVIDENCE_ID.get(evidence_id)
        if legacy_profile
        else None
    )
    if legacy_heading is not None:
        return legacy_heading
    heading = PROFILE_CV_GENERIC_SECTION_BY_PROOF_CLASS.get(proof_class)
    if heading is None:
        raise ValueError("candidate CV evidence kind has no truthful section")
    return heading


def _profile_cv_section_for_fact(
    fact: FactualSentence,
    evidence_kinds: Mapping[str, str],
    *,
    legacy_profile: bool,
) -> str:
    evidence_id = getattr(fact.authority, "candidate_evidence_id", None)
    if fact.fact_kind != "candidate" or not isinstance(evidence_id, str):
        raise ValueError("candidate CV fact lacks bound profile authority")
    proof_class = evidence_kinds.get(evidence_id)
    if not isinstance(proof_class, str):
        raise ValueError("candidate CV fact lacks bound evidence kind")
    return _profile_cv_section_for_evidence(
        evidence_id,
        proof_class,
        legacy_profile=legacy_profile,
    )


def _select_profile_capability_fact(
    sections: Mapping[str, Sequence[FactualSentence]],
    evidence_kinds: Mapping[str, str],
) -> FactualSentence | None:
    for heading in PROFILE_CV_SECTION_ORDER:
        if heading in {"Professional Summary", "Core Capabilities"}:
            continue
        for fact in sections.get(heading, ()):
            evidence_id = getattr(fact.authority, "candidate_evidence_id", None)
            if (
                fact.fact_kind != "candidate"
                or not isinstance(evidence_id, str)
                or evidence_kinds.get(evidence_id)
                not in _CAPABILITY_EVIDENCE_PROOF_CLASSES
                or not capability_line_eligible(fact.text)
            ):
                continue
            return fact
    return None


def _fact_candidate_evidence_id(fact: object) -> str | None:
    evidence_id = getattr(fact, "evidence_id", None)
    if not isinstance(evidence_id, str):
        evidence_id = getattr(
            getattr(fact, "authority", None), "candidate_evidence_id", None
        )
    return evidence_id if isinstance(evidence_id, str) else None


def _populate_fallback_profile_summary(
    sections: dict[str, list[FactualSentence]],
    *,
    heading_order: Sequence[str],
    legacy_profile: bool,
    evidence_kinds: Mapping[str, str] | None = None,
) -> dict[str, list[FactualSentence]]:
    summary_heading = "Professional Summary"
    capability_heading = "Core Capabilities"
    if sections.get(summary_heading):
        return sections

    locations = [
        (heading, fact)
        for heading in heading_order
        if heading != summary_heading
        and (legacy_profile or heading != capability_heading)
        for fact in sections.get(heading, ())
    ]
    if not locations:
        return sections

    capability_fact = (
        _select_profile_capability_fact(sections, evidence_kinds or {})
        if not legacy_profile and not sections.get(capability_heading)
        else None
    )
    capability_sentence_id = (
        capability_fact.sentence_id if capability_fact is not None else None
    )
    fallback_locations = [
        location
        for location in locations
        if location[1].sentence_id != capability_sentence_id
    ]
    if not fallback_locations:
        return sections

    selected_locations = [fallback_locations[0]]
    if not legacy_profile:
        first_heading, first_fact = selected_locations[0]
        first_evidence_id = _fact_candidate_evidence_id(first_fact)
        distinct_facts = [
            location
            for location in fallback_locations[1:]
            if first_evidence_id is not None
            and _fact_candidate_evidence_id(location[1]) is not None
            and _fact_candidate_evidence_id(location[1]) != first_evidence_id
        ]
        complementary_fact = next(
            (
                location
                for location in distinct_facts
                if location[0] != first_heading
            ),
            None,
        )
        if complementary_fact is None:
            complementary_fact = next(
                (
                    location
                    for location in distinct_facts
                    if location[0] == first_heading
                ),
                None,
            )
        selection_limit = min(2, max(1, len(locations) - 2)) if capability_fact else 2
        if complementary_fact is not None and selection_limit > 1:
            selected_locations.append(complementary_fact)

    selected_facts = [fact for _, fact in selected_locations]
    selected_sentence_ids = [fact.sentence_id for fact in selected_facts]
    if len(selected_sentence_ids) != len(set(selected_sentence_ids)) or any(
        sum(
            fact.sentence_id == sentence_id
            for rows in sections.values()
            for fact in rows
        )
        != 1
        for sentence_id in selected_sentence_ids
    ):
        raise ValueError("candidate summary fact identity is ambiguous")

    selected_ids = set(selected_sentence_ids)
    for heading, rows in tuple(sections.items()):
        remaining = [fact for fact in rows if fact.sentence_id not in selected_ids]
        if remaining:
            sections[heading] = remaining
        else:
            sections.pop(heading)
    sections[summary_heading] = selected_facts
    return sections


def _assert_package_quality(
    source: ApplicationSource,
    *,
    evidence_kinds: Mapping[str, str],
    legacy_profile: bool,
) -> None:
    facts = {row.sentence_id: row for row in source.facts}
    cv_rows = [
        facts[sentence_id]
        for section in source.cv_sections
        for sentence_id in section.sentence_ids
    ]
    letter_rows = [
        facts[sentence_id]
        for section in source.letter_sections
        for sentence_id in section.sentence_ids
    ]
    cv_texts = [row.text.casefold().strip() for row in cv_rows]
    letter_texts = [row.text.casefold().strip() for row in letter_rows]
    slots = {row.slot_id: row for row in source.style_slots}
    letter_slot_texts = [
        slots[slot_id].text.casefold().strip()
        for section in source.letter_sections
        for slot_id in section.style_slot_ids
    ]
    if (
        len(cv_rows) < MINIMUM_CV_FACTS
        or len(" ".join(cv_texts).split()) < MINIMUM_CV_WORDS
    ):
        raise ValueError("candidate CV is too sparse for employer submission")
    if len(cv_texts) != len(set(cv_texts)):
        raise ValueError("candidate CV repeats factual content")
    overview_section_names = {"Professional Summary", "Core Capabilities"}
    overview_sentence_ids = {
        sentence_id
        for section in source.cv_sections
        if section.heading in overview_section_names
        for sentence_id in section.sentence_ids
    }
    expected_headings = {
        _profile_cv_section_for_fact(
            row,
            evidence_kinds,
            legacy_profile=legacy_profile,
        )
        for row in cv_rows
        if row.sentence_id not in overview_sentence_ids
    }
    actual_heading_order = tuple(section.heading for section in source.cv_sections)
    summary_section = next(
        (
            section
            for section in source.cv_sections
            if section.heading == "Professional Summary"
        ),
        None,
    )
    if summary_section is not None:
        expected_headings.add("Professional Summary")
    capability_sections = [
        section
        for section in source.cv_sections
        if section.heading == "Core Capabilities"
    ]
    if len(capability_sections) > 1:
        raise ValueError("candidate CV has ambiguous capability sections")
    if capability_sections:
        capability_section = capability_sections[0]
        if not capability_section.sentence_ids:
            raise ValueError("candidate CV capability section is empty")
        expected_headings.add("Core Capabilities")
        if not legacy_profile:
            if len(capability_section.sentence_ids) != 1:
                raise ValueError("candidate CV capability section is not a single relocation")
            capability_sentence_id = capability_section.sentence_ids[0]
            capability_fact = facts.get(capability_sentence_id)
            evidence_id = (
                getattr(capability_fact.authority, "candidate_evidence_id", None)
                if capability_fact is not None
                else None
            )
            if (
                capability_fact is None
                or capability_fact.fact_kind != "candidate"
                or sum(row.sentence_id == capability_sentence_id for row in cv_rows) != 1
                or not isinstance(evidence_id, str)
                or evidence_kinds.get(evidence_id)
                not in _CAPABILITY_EVIDENCE_PROOF_CLASSES
                or not capability_line_eligible(capability_fact.text)
            ):
                raise ValueError("candidate CV capability section lacks verified evidence")
    expected_heading_order = tuple(
        heading
        for heading in PROFILE_CV_SECTION_ORDER
        if heading in expected_headings
    )
    if (
        actual_heading_order != expected_heading_order
        or len(actual_heading_order) != len(set(actual_heading_order))
        or any(
            _profile_cv_section_for_fact(
                facts[sentence_id],
                evidence_kinds,
                legacy_profile=legacy_profile,
            )
            != section.heading
            for section in source.cv_sections
            if section.heading != "Professional Summary"
            and not (section.heading == "Core Capabilities" and not legacy_profile)
            for sentence_id in section.sentence_ids
        )
        or (
            summary_section is not None
            and not legacy_profile
            and len(summary_section.sentence_ids) not in {1, 2}
        )
    ):
        raise ValueError("candidate CV sections differ from bound evidence kinds")
    candidate_letter = [row for row in letter_rows if row.fact_kind == "candidate"]
    employer_letter = [row for row in letter_rows if row.fact_kind == "employer"]
    if (
        len(candidate_letter) < MINIMUM_LETTER_CANDIDATE_FACTS
        or not employer_letter
        or len(" ".join((*letter_slot_texts, *letter_texts)).split())
        < MINIMUM_LETTER_WORDS
    ):
        raise ValueError("candidate cover letter is too sparse for employer submission")
    if len(letter_texts) != len(set(letter_texts)):
        raise ValueError("candidate cover letter repeats factual content")
    if any(
        source.company_name.casefold() not in row.text.casefold()
        for row in employer_letter
    ):
        raise ValueError("candidate cover letter lacks company-bound vacancy context")


def _build_candidate_application_source(
    *,
    decision_receipt: Mapping[str, object],
    candidate_projection: Mapping[str, object],
    job_key: str,
    vacancy_sha256: str,
    source_url: str,
    role_title: str,
    company_name: str,
    contact: CandidateContact,
    current_runtime: bool = False,
    current_matrix_policy_sha256: str | None = None,
    approved_evidence_path: Path = APPROVED_EVIDENCE_PATH,
    approved_evidence_bytes: bytes | None = None,
    revision_writer: GenerationRevisionWriter | None = None,
) -> _CandidateApplicationSourceBuild:
    """Build a plain UK CV and letter using verbatim approved factual atoms."""
    if revision_writer is not None:
        revision_writer(
            role="generation.inputs",
            value=(
                canonical_json(
                    {
                        "schema_version": "jaa.candidate-generation-inputs.v1",
                        "decision_receipt": dict(decision_receipt),
                        "candidate_projection": dict(candidate_projection),
                        "job_key": job_key,
                        "vacancy_sha256": vacancy_sha256,
                        "source_url": source_url,
                        "role_title": role_title,
                        "company_name": company_name,
                    }
                )
                + "\n"
            ).encode(),
            media_type="application/json",
        )
    if (
        decision_receipt.get("decision") != "eligible"
        or decision_receipt.get("job_key") != job_key
        or decision_receipt.get("role_title") != role_title
        or decision_receipt.get("company_name") != company_name
        or decision_receipt.get("vacancy_sha256") != vacancy_sha256
        or decision_receipt.get("source_url") != source_url
    ):
        raise ValueError("application factory decision authority differs")
    expected_evidence_sha256 = _projection_evidence_sha256(
        candidate_projection,
        decision_receipt,
    )
    matrix = decision_receipt.get("evidence_matrix")
    if not isinstance(matrix, list) or not matrix:
        raise ValueError("application factory requires an evidence matrix")
    all_requirements: list[str] = []
    matched_rows: list[Mapping[str, object]] = []
    for row in matrix:
        if (
            not isinstance(row, Mapping)
            or not isinstance(row.get("requirement_id"), str)
            or not isinstance(row.get("requirement_text"), str)
            or not row["requirement_text"].strip()
            or _sha256(str(row["requirement_text"]).encode())
            != row.get("requirement_text_sha256")
        ):
            raise ValueError("application factory requirement authority is malformed")
        all_requirements.append(f"{row['requirement_id']}: {row['requirement_text']}")
        if row.get("status") == "matched":
            matched_rows.append(row)
    statements, approved_evidence_source = _load_approved_statements(
        approved_evidence_path,
        expected_evidence_sha256=expected_evidence_sha256,
        current_runtime=current_runtime,
        approved_evidence_bytes=approved_evidence_bytes,
    )
    projection_rows = candidate_projection.get("approved_evidence")
    if not isinstance(projection_rows, list):
        raise ValueError("candidate projection evidence is malformed")
    projection_by_id = {
        str(row["id"]): dict(row)
        for row in projection_rows
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    if len(projection_by_id) != len(projection_rows):
        raise ValueError("candidate projection evidence is ambiguous")
    legacy_profile = (
        expected_evidence_sha256
        == APPROVED_CANDIDATE_SOURCE_HASHES["approved_evidence"]
    )
    match_policy_sha256 = resolve_match_policy(
        candidate_projection,
        current_runtime=current_runtime,
        current_matrix_policy_sha256=current_matrix_policy_sha256,
    )
    verified_evidence_kinds: dict[str, str] = {}
    requirements: list[Requirement] = []
    matches: list[MatchResult] = []
    supports: list[CandidateSupport] = []
    selected_rows: list[Mapping[str, object]] = []
    eligible_matched_rows: list[tuple[Mapping[str, object], tuple[str, ...]]] = []
    matched_document_targets: dict[str, frozenset[str]] = {}
    source_identity = f"vacancy:{job_key}:{vacancy_sha256}"
    for row in matched_rows:
        evidence_ids = row.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids:
            raise ValueError("matched requirement lacks approved evidence")
        eligible_evidence_ids: list[str] = []
        for candidate_id in sorted(str(value) for value in evidence_ids):
            candidate = statements.get(candidate_id)
            if candidate is None or candidate_id in OUTWARD_PROFILE_REWRITES:
                continue
            outward_text = _outward_profile_text(
                candidate,
                current_runtime=current_runtime,
            )
            if not _candidate_statement_is_outward_safe(
                outward_text,
                current_runtime=current_runtime,
            ):
                continue
            try:
                for document_kind in ("cv", "cover_letter"):
                    assert_employer_facing_text(
                        outward_text,
                        document_kind=document_kind,
                    )
            except ExternalDocumentAssuranceError:
                continue
            projected = projection_by_id.get(candidate_id)
            if (
                projected is None
                or candidate.get("proof_class") != candidate.get("kind")
                or (
                    "kind" in projected
                    and projected.get("kind") != candidate.get("kind")
                )
                or (
                    "proof_class" in projected
                    and projected.get("proof_class") != candidate.get("proof_class")
                )
                or _sha256(str(candidate["statement"]).encode())
                != projected.get("statement_sha256")
            ):
                raise ValueError("matched evidence differs from candidate projection")
            eligible_evidence_ids.append(candidate_id)
        if not eligible_evidence_ids:
            continue
        eligible_evidence_ids = list(dict.fromkeys(eligible_evidence_ids))
        eligible_matched_rows.append((row, tuple(eligible_evidence_ids)))
        for evidence_id in eligible_evidence_ids:
            matched_document_targets[evidence_id] = _evidence_document_targets(
                statements[evidence_id]
            )
    use_document_scoped_support = any(
        targets != _DOCUMENT_TARGETS
        for targets in matched_document_targets.values()
    )
    candidate_document_targets = (
        {
            evidence_id: tuple(sorted(targets))
            for evidence_id, targets in matched_document_targets.items()
        }
        if use_document_scoped_support
        else None
    )
    for row, eligible_evidence_ids in eligible_matched_rows:
        selected_evidence_ids = (
            eligible_evidence_ids
            if use_document_scoped_support
            else eligible_evidence_ids[:1]
        )
        for evidence_id in selected_evidence_ids:
            verified_evidence_kinds[evidence_id] = str(
                statements[evidence_id]["proof_class"]
            )
        requirement_id = str(row["requirement_id"])
        claim_id = (
            f"approved-claim:{requirement_id}"
            if use_document_scoped_support
            else f"approved-claim:{selected_evidence_ids[0]}"
        )
        requirement_text = str(row["requirement_text"])
        accepted_proof_classes = tuple(
            sorted(
                {
                    str(statements[evidence_id]["proof_class"])
                    for evidence_id in selected_evidence_ids
                }
            )
        )
        requirement = Requirement(
            requirement_id,
            claim_id,
            requirement_text,
            row.get("classification") == "essential",
            "evidence",
            "build_evidence",
            accepted_proof_classes,
            10_000,
            source_identity,
            (0, len(requirement_text)),
        )
        requirements.append(requirement)
        matches.append(
            MatchResult(
                requirement_id,
                "matched",
                selected_evidence_ids,
                10_000,
                "Exact operator-approved evidence matched by candidate authority.",
                match_policy_sha256,
                None,
            )
        )
        supports.extend(
            CandidateSupport(
                requirement_id,
                claim_id,
                1,
                evidence_id,
                1,
                str(statements[evidence_id]["proof_class"]),
                "approved",
                "evidence",
                "approved",
                "evidence",
                "approved",
                None,
            )
            for evidence_id in selected_evidence_ids
        )
        selected_rows.append(row)
    selected_requirement_ids = {
        str(row["requirement_id"]) for row in selected_rows
    }
    for row in matrix:
        requirement_id = str(row["requirement_id"])
        if requirement_id in selected_requirement_ids:
            continue
        requirement_text = str(row["requirement_text"])
        requirements.append(
            Requirement(
                requirement_id,
                f"uncovered:{requirement_id}",
                requirement_text,
                row.get("classification") == "essential",
                "evidence",
                "build_evidence",
                tuple(sorted(PROOF_CLASSES)),
                10_000,
                source_identity,
                (0, len(requirement_text)),
            )
        )
        matches.append(
            MatchResult(
                requirement_id,
                "no_match",
                (),
                10_000,
                "No exact employer-safe approved evidence matched this requirement.",
                match_policy_sha256,
                None,
            )
        )
    employer_context_rows = selected_rows or [matrix[0]]
    employer_documents = [
        _employer_document(
            f"vacancy-requirement:{row['requirement_id']}",
            _employer_requirement_statement(
                company_name=company_name,
                role_title=role_title,
                requirement_text=str(row["requirement_text"]),
            ),
            source_identity=source_identity,
        )
        for row in employer_context_rows
    ]
    vacancy_context_document = employer_documents[0]
    employer_facts = tuple(
        EmployerResearchFact(
            str(document["id"]),
            "role",
            "fact",
            tuple(str(value) for value in document["source_ids"]),
            content_hash(document),
            "current",
        )
        for document in employer_documents
    )
    try:
        as_of = datetime.fromisoformat(
            str(decision_receipt["observed_at"]).replace("Z", "+00:00")
        ).date()
    except (KeyError, ValueError) as exc:
        raise ValueError("application factory observation time is invalid") from exc
    if not isinstance(as_of, date):
        raise ValueError("application factory observation date is invalid")
    strategy = compile_application_strategy(
        fit_run_id=_sha256((canonical_json(dict(decision_receipt)) + "\n").encode()),
        dossier_hash=str(decision_receipt["vacancy_description_sha256"]),
        candidate_profile_hash=str(candidate_projection["projection_sha256"]),
        requirements=requirements,
        match_results=matches,
        candidate_support=supports,
        employer_facts=employer_facts,
        as_of=as_of,
        candidate_document_targets=candidate_document_targets,
        permit_eligible_gap_application=True,
    )
    employer_by_id = {str(document["id"]): document for document in employer_documents}
    strategy_cv: list[FactualSentence] = []
    strategy_letter: list[FactualSentence] = []
    letter_employer: list[FactualSentence] = []
    for element in strategy.elements:
        if element.kind in {"cv_emphasis", "cover_letter_argument"}:
            document_kind = "cv" if element.kind == "cv_emphasis" else "cover_letter"
            evidence = statements[element.candidate_evidence_id]
            if document_kind not in _evidence_document_targets(evidence):
                raise ValueError(
                    "strategy evidence contradicts its candidate document scope"
                )
            sentence = _sentence(
                element,
                text=str(evidence["statement"]),
                fact_kind="candidate",
                document_kind=document_kind,
            )
            (strategy_cv if document_kind == "cv" else strategy_letter).append(sentence)
        elif element.kind == "employer_hook":
            document = employer_by_id[element.employer_research_claim_id]
            letter_employer.append(
                _sentence(
                    element,
                    text=str(document["text"]),
                    fact_kind="employer",
                    document_kind="cover_letter",
                    employer_fact_json=canonical_json(document),
                )
            )
    if not letter_employer:
        vacancy_fact_sha256 = content_hash(vacancy_context_document)
        vacancy_authority = VacancyFactAuthority(
            vacancy_source_identity=source_identity,
            vacancy_sha256=vacancy_sha256,
            employer_research_claim_id=str(vacancy_context_document["id"]),
            employer_fact_sha256=vacancy_fact_sha256,
        )

        vacancy_text = str(vacancy_context_document["text"])
        letter_employer.append(
            FactualSentence(
                content_hash(
                    {
                        "contract": "jaa07.vacancy-factual-sentence.v1",
                        "vacancy_source_identity": source_identity,
                        "vacancy_sha256": vacancy_sha256,
                        "employer_fact_sha256": vacancy_fact_sha256,
                        "text": vacancy_text,
                    }
                ),
                vacancy_text,
                vacancy_text,
                "employer",
                "cover_letter",
                vacancy_authority,
                canonical_json(vacancy_context_document),
            )
        )

    def profile_fact(
        evidence_id: str,
        document_kind: str,
    ) -> FactualSentence | None:
        evidence = statements.get(evidence_id)
        projected = projection_by_id.get(evidence_id)
        statement = evidence.get("statement") if evidence is not None else None
        if (
            evidence is None
            or projected is None
            or not isinstance(statement, str)
            or evidence.get("proof_class") != evidence.get("kind")
            or (
                "kind" in projected
                and projected.get("kind") != evidence.get("kind")
            )
            or (
                "proof_class" in projected
                and projected.get("proof_class") != evidence.get("proof_class")
            )
            or _sha256(statement.encode())
            != projected.get("statement_sha256")
        ):
            raise ValueError("profile evidence differs from candidate authority")
        if document_kind not in _evidence_document_targets(evidence):
            return None
        verified_evidence_kinds[evidence_id] = str(evidence["proof_class"])
        try:
            outward_text = _outward_profile_text(
                evidence,
                document_kind=document_kind,
                current_runtime=current_runtime,
            )
            if not _candidate_statement_is_outward_safe(
                outward_text,
                current_runtime=current_runtime,
            ):
                return None
            assert_employer_facing_text(
                outward_text,
                document_kind=document_kind,
            )
        except ExternalDocumentAssuranceError:
            return None
        return _profile_sentence(
            evidence=evidence,
            candidate_profile_hash=str(candidate_projection["projection_sha256"]),
            statement_sha256=str(projected["statement_sha256"]),
            document_kind=document_kind,
            approved_evidence_source=approved_evidence_source,
            current_runtime=current_runtime,
        )

    strategy_cv_by_evidence: dict[str, list[FactualSentence]] = {}
    for fact in strategy_cv:
        strategy_cv_by_evidence.setdefault(
            fact.authority.candidate_evidence_id, []
        ).append(fact)
    cv_sections_by_heading: dict[str, list[FactualSentence]] = (
        {heading: [] for heading, _ in PROFILE_CV_SECTIONS}
        if legacy_profile
        else {}
    )
    used_strategy_ids: set[str] = set()
    placed_cv_evidence_ids: set[str] = set()
    for heading, evidence_ids in (
        PROFILE_CV_SECTIONS if legacy_profile else ()
    ):
        for evidence_id in evidence_ids:
            matched = strategy_cv_by_evidence.get(evidence_id, [])
            if matched:
                cv_sections_by_heading[heading].extend(matched)
                used_strategy_ids.update(row.sentence_id for row in matched)
                placed_cv_evidence_ids.add(evidence_id)
                # Strategy atoms must remain verbatim to preserve requirement
                # coverage.  Candidate-ratified education presentation is an
                # additional exact-authority projection, never a mutation of
                # that strategy atom.
                if evidence_id in {"E-001", "E-002"}:
                    projected_fact = profile_fact(evidence_id, "cv")
                    if projected_fact is not None and all(
                        row.text != projected_fact.text for row in matched
                    ):
                        cv_sections_by_heading[heading].append(projected_fact)
                        placed_cv_evidence_ids.add(evidence_id)
            elif evidence_id in projection_by_id:
                projected_fact = profile_fact(evidence_id, "cv")
                if projected_fact is not None:
                    cv_sections_by_heading[heading].append(projected_fact)
                    placed_cv_evidence_ids.add(evidence_id)
    for fact in strategy_cv:
        if fact.sentence_id in used_strategy_ids:
            continue
        evidence_id = fact.authority.candidate_evidence_id
        evidence = statements[evidence_id]
        heading = _profile_cv_section_for_evidence(
            evidence_id,
            str(evidence["proof_class"]),
            legacy_profile=legacy_profile,
        )
        cv_sections_by_heading.setdefault(heading, []).append(fact)
        placed_cv_evidence_ids.add(evidence_id)

    for row in projection_rows:
        evidence_id = str(row["id"])
        if evidence_id in placed_cv_evidence_ids:
            continue
        projected_fact = profile_fact(evidence_id, "cv")
        if projected_fact is None:
            continue
        evidence = statements[evidence_id]
        heading = _profile_cv_section_for_evidence(
            evidence_id,
            str(evidence["proof_class"]),
            legacy_profile=legacy_profile,
        )
        cv_sections_by_heading.setdefault(heading, []).append(projected_fact)
        placed_cv_evidence_ids.add(evidence_id)

    _populate_fallback_profile_summary(
        cv_sections_by_heading,
        heading_order=PROFILE_CV_SECTION_ORDER,
        legacy_profile=legacy_profile,
        evidence_kinds=verified_evidence_kinds,
    )

    if not legacy_profile and not cv_sections_by_heading.get("Core Capabilities"):
        capability_fact = _select_profile_capability_fact(
            cv_sections_by_heading,
            verified_evidence_kinds,
        )
        if capability_fact is not None:
            capability_sentence_id = capability_fact.sentence_id
            occurrences = sum(
                row.sentence_id == capability_sentence_id
                for rows in cv_sections_by_heading.values()
                for row in rows
            )
            if occurrences != 1:
                raise ValueError("candidate CV capability fact is ambiguous")
            relocated_sections: dict[str, list[FactualSentence]] = {}
            for heading, rows in cv_sections_by_heading.items():
                if heading in {"Professional Summary", "Core Capabilities"}:
                    relocated_sections[heading] = list(rows)
                    continue
                remaining = [
                    row for row in rows if row.sentence_id != capability_sentence_id
                ]
                if remaining:
                    relocated_sections[heading] = remaining
            if any(
                rows
                for heading, rows in relocated_sections.items()
                if heading not in {"Professional Summary", "Core Capabilities"}
            ):
                cv_sections_by_heading.clear()
                cv_sections_by_heading.update(relocated_sections)
                cv_sections_by_heading["Core Capabilities"] = [capability_fact]

    letter_candidate = list(strategy_letter)
    letter_evidence_ids = {
        row.authority.candidate_evidence_id for row in letter_candidate
    }
    letter_candidate_texts = {
        row.text.casefold().strip() for row in letter_candidate
    }
    letter_opening_text = "Dear Hiring Manager,"
    letter_close_text = (
        "I would welcome the opportunity to discuss this work in more detail and "
        "how I could contribute to the team."
    )

    def letter_has_content_floor() -> bool:
        factual_text = " ".join(
            (
                letter_opening_text,
                *(row.text for row in (*letter_candidate, *letter_employer)),
                letter_close_text,
            )
        )
        return (
            len(letter_candidate) >= MINIMUM_LETTER_CANDIDATE_FACTS
            and len(letter_evidence_ids) >= MINIMUM_LETTER_CANDIDATE_FACTS
            and len(factual_text.split()) >= MINIMUM_LETTER_WORDS
        )

    letter_profile_evidence_ids = tuple(str(row["id"]) for row in projection_rows)
    legacy_letter_priority = (
        PROFILE_LETTER_EVIDENCE_PRIORITY if legacy_profile else ()
    )
    for evidence_id in letter_profile_evidence_ids:
        if (
            evidence_id in letter_evidence_ids
            or evidence_id not in projection_by_id
            or evidence_id not in statements
            or _evidence_document_targets(statements[evidence_id])
            != {"cover_letter"}
        ):
            continue
        projected_fact = profile_fact(evidence_id, "cover_letter")
        if projected_fact is None:
            continue
        if projected_fact.text.casefold().strip() in letter_candidate_texts:
            continue
        letter_candidate.append(projected_fact)
        letter_evidence_ids.add(evidence_id)
        letter_candidate_texts.add(projected_fact.text.casefold().strip())

    for evidence_id in (
        *legacy_letter_priority,
        *letter_profile_evidence_ids,
    ):
        if letter_has_content_floor():
            break
        if evidence_id in letter_evidence_ids or evidence_id not in projection_by_id:
            continue
        projected_fact = profile_fact(evidence_id, "cover_letter")
        if projected_fact is None:
            continue
        if projected_fact.text.casefold().strip() in letter_candidate_texts:
            continue
        letter_candidate.append(projected_fact)
        letter_evidence_ids.add(evidence_id)
        letter_candidate_texts.add(projected_fact.text.casefold().strip())

    def strategy_sibling_key(fact: FactualSentence) -> tuple[object, ...] | None:
        authority = fact.authority
        if not isinstance(authority, FactAuthority):
            return None
        return (
            authority.requirement_id,
            authority.candidate_claim_id,
            authority.candidate_claim_version,
            authority.candidate_evidence_id,
            authority.candidate_evidence_version,
            authority.employer_research_claim_id,
            authority.employer_fact_sha256,
        )

    candidates_by_sibling: dict[tuple[object, ...], list[FactualSentence]] = {}
    for fact in letter_candidate:
        sibling = strategy_sibling_key(fact)
        if sibling is not None:
            candidates_by_sibling.setdefault(sibling, []).append(fact)
    employers_by_sibling: dict[tuple[object, ...], list[FactualSentence]] = {}
    unbound_employer_facts: list[FactualSentence] = []
    for fact in letter_employer:
        sibling = strategy_sibling_key(fact)
        if sibling is None:
            unbound_employer_facts.append(fact)
        else:
            employers_by_sibling.setdefault(sibling, []).append(fact)
            if sibling not in candidates_by_sibling:
                raise ValueError(
                    "cover letter employer fact lacks an exact candidate sibling"
                )
    sibling_order = tuple(employers_by_sibling)
    paired_groups = tuple(
        (
            *candidates_by_sibling[sibling],
            *employers_by_sibling[sibling],
        )
        for sibling in sibling_order
    )
    paired_candidate_ids = {
        fact.sentence_id
        for sibling in sibling_order
        for fact in candidates_by_sibling[sibling]
    }
    letter_only_facts = [
        fact
        for fact in letter_candidate
        if fact.sentence_id not in paired_candidate_ids
        and _evidence_document_targets(
            statements[fact.authority.candidate_evidence_id]
        )
        == {"cover_letter"}
    ]
    letter_only_ids = {fact.sentence_id for fact in letter_only_facts}
    if letter_only_facts:
        opening_facts = (letter_only_facts[0],)
        evidence_match_facts = [
            fact for group in paired_groups for fact in group
        ]
        evidence_match_facts.extend(
            fact
            for fact in letter_candidate
            if fact.sentence_id not in paired_candidate_ids
            and fact.sentence_id not in letter_only_ids
        )
        evidence_match_facts.extend(letter_only_facts[1:])
    elif paired_groups:
        opening_facts = paired_groups[0]
        evidence_match_facts = [
            fact for group in paired_groups[1:] for fact in group
        ]
        evidence_match_facts.extend(
            fact
            for fact in letter_candidate
            if fact.sentence_id not in paired_candidate_ids
        )
    else:
        opening_facts = (letter_candidate[0],)
        evidence_match_facts = [
            fact
            for fact in letter_candidate
            if fact.sentence_id != opening_facts[0].sentence_id
        ]
    evidence_match_facts.extend(unbound_employer_facts)

    letter_open = _slot("cover_letter", "salutation", letter_opening_text)
    letter_close = _slot(
        "cover_letter",
        "close",
        letter_close_text,
    )
    cv_sections = tuple(
        DocumentSection(
            heading,
            tuple(row.sentence_id for row in cv_sections_by_heading[heading]),
        )
        for heading in PROFILE_CV_SECTION_ORDER
        if cv_sections_by_heading.get(heading)
    )
    facts = [
        *(
            row
            for section in cv_sections
            for row in cv_sections_by_heading[section.heading]
        ),
        *letter_candidate,
        *letter_employer,
    ]
    source = compile_application_source(
        strategy=strategy,
        job_key=job_key,
        role_title=role_title,
        company_name=company_name,
        vacancy_source_identity=source_identity,
        vacancy_sha256=vacancy_sha256,
        contact=contact,
        facts=facts,
        style_slots=(letter_open, letter_close),
        cv_sections=cv_sections,
        letter_sections=(
            DocumentSection(
                "Opening",
                tuple(row.sentence_id for row in opening_facts),
                (letter_open.slot_id,),
            ),
            DocumentSection(
                "Evidence Match",
                tuple(row.sentence_id for row in evidence_match_facts),
            ),
            DocumentSection(
                "Close",
                (),
                (letter_close.slot_id,),
            ),
        ),
        answers=(),
    )
    _assert_package_quality(
        source,
        evidence_kinds=verified_evidence_kinds,
        legacy_profile=legacy_profile,
    )
    if revision_writer is not None:
        revision_writer(
            role="document.source_inputs",
            value=(canonical_json(source.document()) + "\n").encode(),
            media_type="application/json",
        )
    return _CandidateApplicationSourceBuild(source, tuple(all_requirements))


def _constraint_receipt(
    source: ApplicationSource,
    editable: EditableArtifacts,
    *,
    rendered_pages: tuple[tuple[str, ...], ...],
) -> CVConstraintReceipt:
    cv_facts = {row.sentence_id: row.text for row in source.facts}
    return validate_generated_cv(
        source_id=source.source_id,
        candidate_name=source.contact.full_name,
        candidate_city=source.contact.city,
        cv_text=editable.cv_text,
        cv_sha256=editable.cv_sha256,
        sections={
            section.heading: tuple(cv_facts[value] for value in section.sentence_ids)
            for section in source.cv_sections
        },
        rendered_pages=rendered_pages,
        target_role_title=source.role_title,
    )


def _source_policy_receipt(
    source: ApplicationSource,
    editable: EditableArtifacts,
    *,
    allow_missing_city: bool = False,
    current_runtime: bool = False,
) -> CandidateSourcePolicyReceipt | PreEditorialSourceEnvelopeReceipt:
    cv_facts = {row.sentence_id: row.text for row in source.facts}
    sections = {
        section.heading: tuple(cv_facts[value] for value in section.sentence_ids)
        for section in source.cv_sections
    }
    if current_runtime:
        return PreEditorialSourceEnvelopeReceipt.from_document(
            validate_pre_editorial_source(
                source_id=source.source_id,
                cv_text=editable.cv_text,
                cv_sha256=editable.cv_sha256,
                sections=sections,
            )
        )
    return validate_candidate_source_policy(
        source_id=source.source_id,
        candidate_name=source.contact.full_name,
        candidate_city=source.contact.city,
        cv_text=editable.cv_text,
        cv_sha256=editable.cv_sha256,
        sections=sections,
        rendered_pages=(tuple(editable.cv_text.splitlines()),),
        allow_missing_city=allow_missing_city,
        target_role_title=source.role_title,
    )


def build_candidate_application_package(
    *,
    decision_receipt: Mapping[str, object],
    candidate_projection: Mapping[str, object],
    job_key: str,
    vacancy_sha256: str,
    source_url: str,
    role_title: str,
    company_name: str,
    contact: CandidateContact,
    approved_evidence_path: Path = APPROVED_EVIDENCE_PATH,
    revision_writer: GenerationRevisionWriter | None = None,
) -> CandidateApplicationPackage:
    """Build the canonical application source, then render its PDF artifacts."""
    built = _build_candidate_application_source(
        decision_receipt=decision_receipt,
        candidate_projection=candidate_projection,
        job_key=job_key,
        vacancy_sha256=vacancy_sha256,
        source_url=source_url,
        role_title=role_title,
        company_name=company_name,
        contact=contact,
        approved_evidence_path=approved_evidence_path,
        revision_writer=revision_writer,
    )
    source = built.source
    artifacts = render_pdf_artifacts(source)
    constraint_receipt = _constraint_receipt(
        source,
        artifacts.editable,
        rendered_pages=artifacts.cv_pdf.rendered_lines,
    )
    if revision_writer is not None:
        revision_writer(
            role="document.cv.constraints",
            value=(canonical_json(constraint_receipt.document()) + "\n").encode(),
            media_type="application/json",
        )
        for role, value, media_type in (
            ("document.cv.source", artifacts.editable.cv_text.encode(), "text/plain"),
            ("document.cv.final_pdf", artifacts.cv_pdf.pdf_bytes, "application/pdf"),
            (
                "document.cover_letter.source",
                artifacts.editable.cover_letter_text.encode(),
                "text/plain",
            ),
            (
                "document.cover_letter.final_pdf",
                artifacts.cover_letter_pdf.pdf_bytes,
                "application/pdf",
            ),
            ("form.answers", artifacts.editable.answers_text.encode(), "text/plain"),
        ):
            revision_writer(role=role, value=value, media_type=media_type)
    return CandidateApplicationPackage(
        source=source,
        artifacts=artifacts,
        vacancy_requirements=built.vacancy_requirements,
    )


def _authority_document(
    *,
    path: Path,
    expected_file_sha256: str,
    decision_receipt: Mapping[str, object],
    candidate_projection: Mapping[str, object],
    require_embedded_decision: bool = True,
    exact_bytes: bytes | None = None,
) -> tuple[dict[str, object], str]:
    authority_bytes = path.read_bytes() if exact_bytes is None else exact_bytes
    if _sha256(authority_bytes) != expected_file_sha256:
        raise ValueError("candidate authority file hash differs")
    value = json.loads(authority_bytes)
    if not isinstance(value, dict) or value.get("schema_version") != (
        "jaa.production-candidate-authority.v2"
    ):
        raise ValueError("candidate authority object is malformed")
    if value.get("candidate_projection") != dict(candidate_projection):
        raise ValueError("candidate projection differs from exact authority")
    if not require_embedded_decision:
        return value, _sha256((canonical_json(dict(decision_receipt)) + "\n").encode())
    rows = value.get("decisions")
    matches = (
        [
            row
            for row in rows
            if isinstance(row, Mapping)
            and row.get("receipt") == dict(decision_receipt)
        ]
        if isinstance(rows, list)
        else []
    )
    if len(matches) != 1:
        raise ValueError("decision receipt differs from exact candidate authority")
    expected_receipt_sha256 = _sha256(
        (canonical_json(dict(decision_receipt)) + "\n").encode()
    )
    if matches[0].get("receipt_sha256") != expected_receipt_sha256:
        raise ValueError("candidate authority decision receipt identity is invalid")
    return value, str(matches[0]["receipt_sha256"])


def _fact_binding(
    fact: FactualSentence,
    *,
    approved_statements: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    authority = {}
    for authority_field in fields(fact.authority):
        value = getattr(fact.authority, authority_field.name)
        if authority_field.name == "rewrite_authority" and value is not None:
            value = value.document()
        authority[authority_field.name] = value
    evidence_ids: tuple[str, ...]
    approved_evidence_statement_sha256: str | None = None
    if fact.fact_kind == "candidate":
        evidence_id = str(authority["candidate_evidence_id"])
        statement = approved_statements.get(evidence_id)
        if statement is None:
            raise ValueError("candidate fact lacks approved packet authority")
        approved_evidence_statement_sha256 = _sha256(
            str(statement["statement"]).encode()
        )
        if approved_evidence_statement_sha256 != _sha256(
            fact.approved_source_text.encode()
        ):
            raise ValueError("candidate fact differs from approved packet statement")
        evidence_ids = (evidence_id,)
    else:
        evidence_ids = (str(authority["employer_research_claim_id"]),)
    return {
        "approved_source_text_sha256": _sha256(fact.approved_source_text.encode()),
        "approved_evidence_statement_sha256": approved_evidence_statement_sha256,
        "authority": authority,
        "authority_kind": type(fact.authority).__name__,
        "document_kind": fact.document_kind,
        "evidence_ids": list(evidence_ids),
        "fact_kind": fact.fact_kind,
        "sentence_id": fact.sentence_id,
        "text": fact.text,
        "text_sha256": _sha256(fact.text.encode()),
    }


def materialize_candidate_application_source(
    *,
    candidate_authority_path: Path,
    deployment_binding: CandidateApplicationDeploymentBinding,
    contact_authority: CandidateContactAuthority | None,
    decision_receipt: Mapping[str, object],
    candidate_projection: Mapping[str, object],
    job_key: str,
    vacancy_sha256: str,
    source_url: str,
    role_title: str,
    company_name: str,
    contact: CandidateContact,
    approved_evidence_path: Path = APPROVED_EVIDENCE_PATH,
    revision_writer: GenerationRevisionWriter | None = None,
    market_decision_authority: MarketApplicationDecisionAuthority | None = None,
    candidate_authority_bytes: bytes | None = None,
    contact_authority_bytes: bytes | None = None,
    contact_provenance: CurrentContactProvenance | None = None,
    approved_evidence_bytes: bytes | None = None,
) -> CandidateApplicationMaterialization:
    """Materialize exact source authority without rendering or release authority."""
    deployment_binding.__post_init__()
    current_runtime = deployment_binding.environment == CURRENT_RUNTIME_ENVIRONMENT
    if not current_runtime and contact.city is None:
        raise ValueError("legacy application contact requires an explicit city")
    if current_runtime:
        if (
            contact_authority is not None
            or type(contact_provenance) is not CurrentContactProvenance
            or contact_authority_bytes is not None
        ):
            raise ValueError("current application requires current contact provenance")
        contact_provenance.__post_init__()
        if contact != contact_provenance.contact:
            raise ValueError("application contact differs from current provenance")
        contact_authority_sha256 = None
        contact_envelope_sha256 = None
        contact_registry_sha256 = None
        contact_signer_public_key_sha256 = None
        current_contact_document = contact_provenance.document()
        current_contact_provenance_sha256 = contact_provenance.sha256
        current_contact_provenance_schema = str(
            current_contact_document["schema_version"]
        )
        current_contact_source_hashes = contact_provenance.source_hashes
    else:
        if (
            type(contact_authority) is not CandidateContactAuthority
            or contact_provenance is not None
        ):
            raise ValueError("legacy application requires signed contact authority")
        if contact != contact_authority.contact:
            raise ValueError("application contact differs from signed operator authority")
        contact_bytes = (
            contact_authority.source_path.read_bytes()
            if contact_authority_bytes is None
            else contact_authority_bytes
        )
        if _sha256(contact_bytes) != contact_authority.envelope_sha256:
            raise ValueError("signed contact authority envelope hash differs")
        contact_authority_sha256 = contact_authority.authority_sha256
        contact_envelope_sha256 = contact_authority.envelope_sha256
        contact_registry_sha256 = contact_authority.registry_sha256
        contact_signer_public_key_sha256 = contact_authority.signer_public_key_sha256
        current_contact_provenance_sha256 = None
        current_contact_provenance_schema = None
        current_contact_source_hashes = ()
    if market_decision_authority is not None:
        market_decision_authority.__post_init__()
        if (
            market_decision_authority.application_id != deployment_binding.application_id
            or market_decision_authority.environment != deployment_binding.environment
            or market_decision_authority.handoff_root_sha256
            != deployment_binding.handoff_root_sha256
            or market_decision_authority.admission_receipt_sha256
            != deployment_binding.admission_receipt_sha256
            or market_decision_authority.current_boundary_receipt_sha256
            != deployment_binding.current_boundary_receipt_sha256
            or market_decision_authority.source_job_key != job_key
            or market_decision_authority.raw_listing_sha256 != vacancy_sha256
            or market_decision_authority.source_url != source_url
            or market_decision_authority.role_title != role_title
            or market_decision_authority.company_name != company_name
            or market_decision_authority.candidate_projection_sha256
            != candidate_projection.get("projection_sha256")
            or market_decision_authority.decision_receipt() != dict(decision_receipt)
        ):
            raise ValueError("integrated market decision differs from application")
    authority, decision_sha256 = _authority_document(
        path=candidate_authority_path,
        expected_file_sha256=deployment_binding.candidate_authority_file_sha256,
        decision_receipt=decision_receipt,
        candidate_projection=candidate_projection,
        require_embedded_decision=market_decision_authority is None,
        exact_bytes=candidate_authority_bytes,
    )
    expected_source_evidence_sha256 = (
        _projection_evidence_sha256(candidate_projection, decision_receipt)
        if current_runtime
        else APPROVED_CANDIDATE_SOURCE_HASHES["approved_evidence"]
    )
    _, approved_evidence_source = _load_approved_statements(
        approved_evidence_path,
        expected_evidence_sha256=expected_source_evidence_sha256,
        current_runtime=current_runtime,
        approved_evidence_bytes=approved_evidence_bytes,
    )
    evidence_bytes = approved_evidence_source.source_bytes
    evidence_document = json.loads(evidence_bytes)
    if current_runtime and type(market_decision_authority) is not MarketApplicationDecisionAuthority:
        raise ValueError("current application requires authenticated matrix policy")
    built = _build_candidate_application_source(
        decision_receipt=decision_receipt,
        candidate_projection=candidate_projection,
        job_key=job_key,
        vacancy_sha256=vacancy_sha256,
        source_url=source_url,
        role_title=role_title,
        company_name=company_name,
        contact=contact,
        current_runtime=current_runtime,
        current_matrix_policy_sha256=(
            market_decision_authority.matrix_policy_sha256
            if current_runtime
            else None
        ),
        approved_evidence_path=approved_evidence_path,
        approved_evidence_bytes=approved_evidence_bytes,
        revision_writer=revision_writer,
    )
    source = built.source
    editable = render_editable_text(source)
    source_policy = _source_policy_receipt(
        source,
        editable,
        allow_missing_city=current_runtime and contact.city is None,
        current_runtime=current_runtime,
    )
    approved_statements = {
        str(row["id"]): row
        for row in evidence_document["statements"]
        if isinstance(row, Mapping)
    }
    section_by_sentence_id = {
        sentence_id: section.heading
        for section in source.cv_sections
        for sentence_id in section.sentence_ids
    }
    fact_bindings = tuple(
        {
            **_fact_binding(fact, approved_statements=approved_statements),
            "section_heading": (
                section_by_sentence_id[fact.sentence_id]
                if fact.document_kind == "cv"
                else next(
                    section.heading
                    for section in source.letter_sections
                    if fact.sentence_id in section.sentence_ids
                )
            ),
        }
        for fact in source.facts
    )
    cv_claim_set_sha256 = content_hash(
        [dict(row) for row in fact_bindings if row["document_kind"] == "cv"]
    )
    style_bindings = tuple(
        {
            "document_kind": slot.document_kind,
            "slot_id": slot.slot_id,
            "text_sha256": _sha256(slot.text.encode()),
        }
        for slot in source.style_slots
    )
    contact_receipt_fields = {
        "contact_authority_sha256": contact_authority_sha256,
        "contact_envelope_sha256": contact_envelope_sha256,
        "contact_registry_sha256": contact_registry_sha256,
        "contact_signer_public_key_sha256": contact_signer_public_key_sha256,
    }
    if current_runtime:
        contact_receipt_fields.update(
            {
                "contact_provenance_sha256": current_contact_provenance_sha256,
                "contact_provenance_schema": current_contact_provenance_schema,
                "contact_source_hashes": list(current_contact_source_hashes),
            }
        )
    body = {
        "application_source_id": source.source_id,
        "application_source_sha256": source.content_sha256,
        "approved_evidence_file_sha256": _sha256(evidence_bytes),
        "approved_evidence_object_sha256": content_hash(evidence_document),
        "candidate_authority_file_sha256": (
            deployment_binding.candidate_authority_file_sha256
        ),
        "candidate_authority_object_sha256": content_hash(authority),
        "candidate_projection_sha256": str(candidate_projection["projection_sha256"]),
        **contact_receipt_fields,
        "cv_claim_set_sha256": cv_claim_set_sha256,
        "deployment_binding": deployment_binding.document(),
        "source_policy_receipt": source_policy.document(),
        "decision_receipt_sha256": decision_sha256,
        "decision_authority_schema": (
            market_decision_authority.schema_version
            if market_decision_authority is not None
            else "jaa.production-candidate-authority.v2"
        ),
        "decision_authority_sha256": (
            market_decision_authority.authority_sha256
            if market_decision_authority is not None
            else content_hash(authority)
        ),
        "fact_bindings": [dict(row) for row in fact_bindings],
        "job_key": job_key,
        "role_title": role_title,
        "company_name": company_name,
        "source_url": source_url,
        "release_authority": False,
        "schema_version": (
            CURRENT_RUNTIME_MATERIALIZATION_RECEIPT_SCHEMA
            if deployment_binding.environment == CURRENT_RUNTIME_ENVIRONMENT
            else "jaa.candidate-application-materialization-receipt.v3"
        ),
        "style_bindings": [dict(row) for row in style_bindings],
        "vacancy_sha256": vacancy_sha256,
        "vacancy_snapshot_sha256": (
            market_decision_authority.vacancy_snapshot_sha256
            if market_decision_authority is not None
            else vacancy_sha256
        ),
    }
    receipt = CandidateApplicationMaterializationReceipt(
        candidate_authority_file_sha256=(
            deployment_binding.candidate_authority_file_sha256
        ),
        candidate_authority_object_sha256=content_hash(authority),
        candidate_projection_sha256=str(candidate_projection["projection_sha256"]),
        deployment_binding=deployment_binding,
        contact_authority_sha256=contact_authority_sha256,
        contact_envelope_sha256=contact_envelope_sha256,
        contact_registry_sha256=contact_registry_sha256,
        contact_signer_public_key_sha256=contact_signer_public_key_sha256,
        cv_claim_set_sha256=cv_claim_set_sha256,
        approved_evidence_file_sha256=_sha256(evidence_bytes),
        approved_evidence_object_sha256=content_hash(evidence_document),
        decision_receipt_sha256=decision_sha256,
        vacancy_sha256=vacancy_sha256,
        vacancy_snapshot_sha256=(
            market_decision_authority.vacancy_snapshot_sha256
            if market_decision_authority is not None
            else vacancy_sha256
        ),
        decision_authority_schema=(
            market_decision_authority.schema_version
            if market_decision_authority is not None
            else "jaa.production-candidate-authority.v2"
        ),
        decision_authority_sha256=(
            market_decision_authority.authority_sha256
            if market_decision_authority is not None
            else content_hash(authority)
        ),
        job_key=job_key,
        role_title=role_title,
        company_name=company_name,
        source_url=source_url,
        application_source_id=source.source_id,
        application_source_sha256=source.content_sha256,
        fact_bindings=fact_bindings,
        style_bindings=style_bindings,
        source_policy_receipt=source_policy,
        receipt_sha256=content_hash(body),
        schema_version=str(body["schema_version"]),
        contact_provenance_sha256=current_contact_provenance_sha256,
        contact_provenance_schema=current_contact_provenance_schema,
        contact_source_hashes=current_contact_source_hashes,
    )
    receipt.__post_init__()
    if revision_writer is not None:
        revision_writer(
            role="document.source_materialization_receipt",
            value=(canonical_json(receipt.document()) + "\n").encode(),
            media_type="application/json",
        )
    return CandidateApplicationMaterialization(
        source=source,
        editable=editable,
        vacancy_requirements=built.vacancy_requirements,
        receipt=receipt,
    )


__all__ = [
    "CandidateApplicationMaterialization",
    "CandidateApplicationMaterializationReceipt",
    "CandidateApplicationDeploymentBinding",
    "CandidateApplicationPackage",
    "MarketApplicationDecisionAuthority",
    "build_market_application_decision_authority",
    "build_candidate_application_package",
    "build_candidate_application_deployment_binding",
    "resolve_match_policy",
    "materialize_candidate_application_source",
]
