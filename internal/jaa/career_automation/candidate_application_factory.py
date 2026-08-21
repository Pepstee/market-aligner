"""Deterministic employer-facing package from approved candidate authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Mapping, Protocol

from .application_compiler import (
    ApplicationSource,
    CandidateContact,
    DocumentSection,
    FactAuthority,
    FactualSentence,
    ProfileFactAuthority,
    StyleSlot,
    VacancyFactAuthority,
    compile_application_source,
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
from .candidate_contact_authority import CandidateContactAuthority
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
    validate_candidate_source_policy,
    validate_generated_cv,
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
MINIMUM_CV_FACTS = 8
MINIMUM_CV_WORDS = 110
MINIMUM_LETTER_CANDIDATE_FACTS = 2
MINIMUM_LETTER_WORDS = 90
OUTWARD_PROFILE_REWRITES: Mapping[str, str] = {
    "E-001": (
        "First-Class BSc (Hons) Computer Science, Birmingham Newman "
        "University, July 2026."
    ),
    "E-002": (
        "Dissertation: SCAFAD: A Seven-Layer, Privacy-Preserving, Explainable "
        "Anomaly-Detection Pipeline for Serverless Workloads."
    ),
    "E-011": (
        "I led the end-to-end development of Market Aligner, covering its "
        "collectors, validation, caching, SQLite persistence, retries and resumability."
    ),
    "E-013": (
        "My GitHub portfolio is available under the username Pepstee, with work "
        "covering orchestration, SCAFAD and delivered software projects."
    ),
    "E-012": (
        "I architect and operate a multi-agent orchestration platform, owning "
        "requirements, system architecture, evaluation gates and acceptance decisions."
    ),
    "E-014": (
        "I provided product direction and validated the working Dubbing Studio MVP."
    ),
    "E-015": (
        "Dubbing Studio has 709 passing automated tests and a real command-line "
        "synthesis check that produced a timeline-correct WAV."
    ),
    "E-016": (
        "Built Learning Accelerator, a tested system for LLM-assisted question "
        "generation, spaced repetition, review sessions, persistence and analytics."
    ),
    "E-017": (
        "The public scafad-delta repository contains the SCAFAD implementation."
    ),
    "E-018": (
        "An earlier public orchestrator repository documents the development of "
        "my orchestration architecture."
    ),
}
OUTWARD_LETTER_REWRITES: Mapping[str, str] = {
    "E-011": (
        "In Market Aligner, I led work on collectors, validation, caching, "
        "SQLite persistence, retries and resumability."
    ),
}
OUTWARD_REWRITE_POLICY_SHA256 = content_hash(
    {
        "schema_version": "jaa.candidate-outward-rewrite-policy.v1",
        "mode": "exact_allowlist",
        "rewrites": dict(OUTWARD_PROFILE_REWRITES),
        "letter_rewrites": dict(OUTWARD_LETTER_REWRITES),
    }
)


@dataclass(frozen=True)
class CandidateApplicationPackage:
    source: ApplicationSource
    artifacts: ApplicationArtifacts
    vacancy_requirements: tuple[str, ...]


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
        if not self.application_id.startswith("app_") or self.environment not in {
            "production",
            "synthetic",
        }:
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
    body = {
        "admission_receipt_sha256": admission_receipt_sha256,
        "application_id": application_id,
        "candidate_authority_file_sha256": candidate_authority_file_sha256,
        "current_boundary_receipt_sha256": current_boundary_receipt_sha256,
        "environment": environment,
        "handoff_root_sha256": handoff_root_sha256,
        "schema_version": "jaa.candidate-application-deployment-binding.v1",
    }
    return CandidateApplicationDeploymentBinding(
        application_id=application_id,
        environment=environment,
        handoff_root_sha256=handoff_root_sha256,
        admission_receipt_sha256=admission_receipt_sha256,
        current_boundary_receipt_sha256=current_boundary_receipt_sha256,
        candidate_authority_file_sha256=candidate_authority_file_sha256,
        binding_sha256=content_hash(body),
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
            or self.environment not in {"production", "synthetic"}
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
    evidence_bytes = approved_evidence_path.read_bytes()
    evidence_document = json.loads(evidence_bytes)
    evidence = tuple(_approved_statements(approved_evidence_path).values())
    compiled = compile_canonical_requirements_evidence_matrix(
        requirements_bytes, evidence
    )
    if compiled["requirements_sha256"] != requirements_sha256:
        raise ValueError("market application requirement authority differs")
    matrix = tuple(dict(row) for row in compiled["matrix"])
    projection_sha256 = candidate_projection.get("projection_sha256")
    if not isinstance(projection_sha256, str):
        raise ValueError("market application candidate projection is malformed")
    try:
        candidate_authority_document = json.loads(candidate_authority_bytes)
        ledger_rows = [json.loads(line) for line in evidence_ledger_bytes.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("market application candidate evidence is not JSON") from exc
    if (
        not isinstance(candidate_authority_document, dict)
        or candidate_authority_document.get("candidate_projection")
        != dict(candidate_projection)
        or len(ledger_rows) != 7
        or any(not isinstance(row, dict) for row in ledger_rows)
    ):
        raise ValueError("market application candidate evidence authority differs")
    projected_rows = candidate_projection.get("approved_evidence")
    projected = {
        str(row["id"]): str(row["statement_sha256"])
        for row in projected_rows
        if isinstance(row, Mapping)
    } if isinstance(projected_rows, list) else {}
    ledger_ids: set[str] = set()
    for row in ledger_rows:
        evidence_id = row.get("evidence_id")
        claim = row.get("claim")
        if (
            not isinstance(evidence_id, str)
            or evidence_id in ledger_ids
            or not isinstance(claim, str)
            or _sha256(claim.encode()) != row.get("content_sha256")
            or projected.get(evidence_id) != row.get("content_sha256")
        ):
            raise ValueError("market application evidence ledger differs from candidate projection")
        ledger_ids.add(evidence_id)
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
        "schema_version": "jaa.market-application-decision-authority.v1",
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
    )


@dataclass(frozen=True)
class CandidateApplicationMaterializationReceipt:
    """Non-release proof that exact authorities produced one application source."""

    candidate_authority_file_sha256: str
    candidate_authority_object_sha256: str
    candidate_projection_sha256: str
    deployment_binding: CandidateApplicationDeploymentBinding
    contact_authority_sha256: str
    contact_envelope_sha256: str
    contact_registry_sha256: str
    contact_signer_public_key_sha256: str
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
    source_policy_receipt: CandidateSourcePolicyReceipt
    receipt_sha256: str
    schema_version: str = "jaa.candidate-application-materialization-receipt.v3"
    release_authority: bool = False

    def __post_init__(self) -> None:
        for value in (
            self.candidate_authority_file_sha256,
            self.candidate_authority_object_sha256,
            self.candidate_projection_sha256,
            self.contact_authority_sha256,
            self.contact_envelope_sha256,
            self.contact_registry_sha256,
            self.contact_signer_public_key_sha256,
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
        if (
            not self.job_key
            or not self.role_title
            or not self.company_name
            or not self.source_url
            or not self.decision_authority_schema
            or not self.fact_bindings
            or self.release_authority is not False
        ):
            raise ValueError("materialization receipt authority is malformed")
        if not isinstance(self.source_policy_receipt, CandidateSourcePolicyReceipt):
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
        if include_identity:
            value["receipt_sha256"] = self.receipt_sha256
        return value

    def authorize_editorial_request(self, request: object) -> None:
        """Fail closed unless an editorial request exactly projects this receipt."""
        if getattr(getattr(request, "authority", None), "source_sha256", None) != (
            self.candidate_authority_file_sha256
        ):
            raise ValueError("editorial request candidate authority differs")
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
        claims = getattr(request, "approved_claims", ())
        if not claims:
            raise ValueError("editorial request has no materialized claims")
        if document_kind == "cv":
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
                    "category": {
                        "Professional Summary": "summary",
                        "Core Capabilities": "capability_domain",
                        "Projects": "project",
                        "Experience": "experience",
                        "Education": "education",
                    }[str(binding["section_heading"])],
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


def _approved_statements(path: Path) -> dict[str, dict[str, object]]:
    value = path.read_bytes()
    if _sha256(value) != APPROVED_CANDIDATE_SOURCE_HASHES["approved_evidence"]:
        raise ValueError("application factory candidate evidence hash differs")
    document = json.loads(value)
    rows = document.get("statements")
    if not isinstance(rows, list):
        raise ValueError("application factory candidate evidence is malformed")
    result = {str(row["id"]): dict(row) for row in rows if isinstance(row, Mapping)}
    if len(result) != len(rows):
        raise ValueError("application factory candidate evidence is ambiguous")
    return result


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _candidate_statement_is_outward_safe(value: str) -> bool:
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
) -> str:
    evidence_id = str(evidence["id"])
    if document_kind == "cover_letter" and evidence_id in OUTWARD_LETTER_REWRITES:
        return OUTWARD_LETTER_REWRITES[evidence_id]
    return OUTWARD_PROFILE_REWRITES.get(evidence_id, str(evidence["statement"]))


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
) -> FactualSentence:
    evidence_id = str(evidence["id"])
    approved_source_text = str(evidence["statement"])
    text = _outward_profile_text(evidence, document_kind=document_kind)
    rewritten = text != approved_source_text
    authority = ProfileFactAuthority(
        candidate_profile_hash=candidate_profile_hash,
        candidate_claim_id=f"approved-claim:{evidence_id}",
        candidate_claim_version=1,
        candidate_evidence_id=evidence_id,
        candidate_evidence_version=1,
        candidate_evidence_sha256=statement_sha256,
        proof_class=str(evidence["proof_class"]),
        outward_text_sha256=_sha256(text.encode()) if rewritten else None,
        rewrite_policy_sha256=(
            OUTWARD_REWRITE_POLICY_SHA256 if rewritten else None
        ),
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


def _assert_package_quality(source: ApplicationSource) -> None:
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
    if tuple(section.heading for section in source.cv_sections) != tuple(
        heading for heading, _ in PROFILE_CV_SECTIONS
    ):
        raise ValueError("candidate CV lacks the complete graduate profile structure")
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
    approved_evidence_path: Path = APPROVED_EVIDENCE_PATH,
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
        or decision_receipt.get("candidate_projection_sha256")
        != candidate_projection.get("projection_sha256")
    ):
        raise ValueError("application factory decision authority differs")
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
    statements = _approved_statements(approved_evidence_path)
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
    requirements: list[Requirement] = []
    matches: list[MatchResult] = []
    supports: list[CandidateSupport] = []
    selected_rows: list[Mapping[str, object]] = []
    source_identity = f"vacancy:{job_key}:{vacancy_sha256}"
    for row in matched_rows:
        evidence_ids = row.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids:
            raise ValueError("matched requirement lacks approved evidence")
        evidence_id = ""
        for candidate_id in sorted(str(value) for value in evidence_ids):
            candidate = statements.get(candidate_id)
            if candidate is None or candidate_id in OUTWARD_PROFILE_REWRITES:
                continue
            outward_text = _outward_profile_text(candidate)
            if not _candidate_statement_is_outward_safe(outward_text):
                continue
            try:
                for document_kind in ("cv", "cover_letter"):
                    assert_employer_facing_text(
                        outward_text,
                        document_kind=document_kind,
                    )
            except ExternalDocumentAssuranceError:
                continue
            evidence_id = candidate_id
            break
        if not evidence_id:
            continue
        evidence = statements.get(evidence_id)
        projected = projection_by_id.get(evidence_id)
        if (
            evidence is None
            or projected is None
            or evidence.get("proof_class") != evidence.get("kind")
            or _sha256(str(evidence["statement"]).encode())
            != projected.get("statement_sha256")
        ):
            raise ValueError("matched evidence differs from candidate projection")
        requirement_id = str(row["requirement_id"])
        claim_id = f"approved-claim:{evidence_id}"
        requirement_text = str(row["requirement_text"])
        requirement = Requirement(
            requirement_id,
            claim_id,
            requirement_text,
            row.get("classification") == "essential",
            "evidence",
            "build_evidence",
            (str(evidence["proof_class"]),),
            10_000,
            source_identity,
            (0, len(requirement_text)),
        )
        requirements.append(requirement)
        matches.append(
            MatchResult(
                requirement_id,
                "matched",
                (evidence_id,),
                10_000,
                "Exact operator-approved evidence matched by candidate authority.",
                str(candidate_projection["policy_sha256"]),
                None,
            )
        )
        supports.append(
            CandidateSupport(
                requirement_id,
                claim_id,
                1,
                evidence_id,
                1,
                str(evidence["proof_class"]),
                "approved",
                "evidence",
                "approved",
                "evidence",
                "approved",
                None,
            )
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
                str(candidate_projection["policy_sha256"]),
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

    opening_document = _employer_document(
        f"vacancy-role-identity:{job_key}",
        f"The {role_title} position is at {company_name}.",
        source_identity=source_identity,
    )
    opening_fact_sha256 = content_hash(opening_document)
    opening_text = str(opening_document["text"])
    opening_employer = FactualSentence(
        content_hash(
            {
                "contract": "jaa07.vacancy-role-factual-sentence.v1",
                "employer_fact_sha256": opening_fact_sha256,
                "text": opening_text,
                "vacancy_sha256": vacancy_sha256,
                "vacancy_source_identity": source_identity,
            }
        ),
        opening_text,
        opening_text,
        "employer",
        "cover_letter",
        VacancyFactAuthority(
            vacancy_source_identity=source_identity,
            vacancy_sha256=vacancy_sha256,
            employer_research_claim_id=str(opening_document["id"]),
            employer_fact_sha256=opening_fact_sha256,
        ),
        canonical_json(opening_document),
    )

    def profile_fact(evidence_id: str, document_kind: str) -> FactualSentence:
        evidence = statements.get(evidence_id)
        projected = projection_by_id.get(evidence_id)
        outward_text = (
            _outward_profile_text(evidence, document_kind=document_kind)
            if evidence is not None
            else ""
        )
        if (
            evidence is None
            or projected is None
            or evidence.get("proof_class") != evidence.get("kind")
            or not _candidate_statement_is_outward_safe(outward_text)
            or _sha256(str(evidence.get("statement", "")).encode())
            != projected.get("statement_sha256")
        ):
            raise ValueError("profile evidence differs from candidate authority")
        assert_employer_facing_text(
            outward_text,
            document_kind=document_kind,
        )
        return _profile_sentence(
            evidence=evidence,
            candidate_profile_hash=str(candidate_projection["projection_sha256"]),
            statement_sha256=str(projected["statement_sha256"]),
            document_kind=document_kind,
        )

    strategy_cv_by_evidence: dict[str, list[FactualSentence]] = {}
    for fact in strategy_cv:
        strategy_cv_by_evidence.setdefault(
            fact.authority.candidate_evidence_id, []
        ).append(fact)
    cv_sections_by_heading: dict[str, list[FactualSentence]] = {
        heading: [] for heading, _ in PROFILE_CV_SECTIONS
    }
    used_strategy_ids: set[str] = set()
    for heading, evidence_ids in PROFILE_CV_SECTIONS:
        for evidence_id in evidence_ids:
            matched = strategy_cv_by_evidence.get(evidence_id, [])
            if matched:
                cv_sections_by_heading[heading].extend(matched)
                used_strategy_ids.update(row.sentence_id for row in matched)
                # Strategy atoms must remain verbatim to preserve requirement
                # coverage.  Candidate-ratified education presentation is an
                # additional exact-authority projection, never a mutation of
                # that strategy atom.
                if evidence_id in {"E-001", "E-002"}:
                    projected_fact = profile_fact(evidence_id, "cv")
                    if all(row.text != projected_fact.text for row in matched):
                        cv_sections_by_heading[heading].append(projected_fact)
            else:
                cv_sections_by_heading[heading].append(profile_fact(evidence_id, "cv"))
    for fact in strategy_cv:
        if fact.sentence_id in used_strategy_ids:
            continue
        evidence = statements[fact.authority.candidate_evidence_id]
        if evidence["kind"] == "credential":
            heading = "Education"
        elif evidence["kind"] == "employment_record":
            heading = "Experience"
        else:
            heading = "Projects"
        cv_sections_by_heading[heading].append(fact)

    letter_candidate = list(strategy_letter)
    letter_evidence_ids = {
        row.authority.candidate_evidence_id for row in letter_candidate
    }
    for evidence_id in PROFILE_LETTER_EVIDENCE_PRIORITY:
        if evidence_id in letter_evidence_ids:
            continue
        letter_candidate.append(profile_fact(evidence_id, "cover_letter"))
        letter_evidence_ids.add(evidence_id)
        if len(letter_candidate) >= 2:
            break

    letter_open = _slot("cover_letter", "salutation", "Dear Hiring Manager,")
    letter_intent = _slot(
        "cover_letter",
        "opening-intent",
        (
            f"I am applying for the {role_title} position at {company_name}. "
            "I want to build and operate dependable software systems, and this "
            "opportunity is closely aligned with that direction."
        ),
    )
    letter_evidence_lead = _slot(
        "cover_letter",
        "evidence-lead",
        "My strongest relevant work comes from systems I have built and evaluated.",
    )
    letter_company_lead = _slot(
        "cover_letter",
        "company-lead",
        (
            "The closest direct overlap with the role is the requirement below."
            if selected_rows
            else "The role description gives clear context for my application."
        ),
    )
    letter_close = _slot(
        "cover_letter",
        "close",
        "I would welcome the opportunity to discuss this work in more detail and "
        "how I could contribute to the team.",
    )
    letter_signoff = _slot("cover_letter", "signoff", "Kind regards")
    letter_signature = _slot(
        "cover_letter",
        "signature",
        contact.full_name,
    )
    cv_sections = tuple(
        DocumentSection(
            heading,
            tuple(row.sentence_id for row in cv_sections_by_heading[heading]),
        )
        for heading, _ in PROFILE_CV_SECTIONS
    )
    facts = [
        *(row for section in cv_sections_by_heading.values() for row in section),
        *letter_candidate,
        opening_employer,
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
        style_slots=(
            letter_open,
            letter_intent,
            letter_evidence_lead,
            letter_company_lead,
            letter_close,
            letter_signoff,
            letter_signature,
        ),
        cv_sections=cv_sections,
        letter_sections=(
            DocumentSection(
                "Opening",
                (opening_employer.sentence_id,),
                (letter_open.slot_id, letter_intent.slot_id),
            ),
            DocumentSection(
                "Evidence Match",
                tuple(row.sentence_id for row in letter_candidate),
                (letter_evidence_lead.slot_id,),
            ),
            DocumentSection(
                "Company Fit",
                tuple(row.sentence_id for row in letter_employer),
                (letter_company_lead.slot_id,),
            ),
            DocumentSection(
                "Close",
                (),
                (
                    letter_close.slot_id,
                    letter_signoff.slot_id,
                    letter_signature.slot_id,
                ),
            ),
        ),
        answers=(),
    )
    _assert_package_quality(source)
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
) -> CandidateSourcePolicyReceipt:
    cv_facts = {row.sentence_id: row.text for row in source.facts}
    return validate_candidate_source_policy(
        source_id=source.source_id,
        candidate_name=source.contact.full_name,
        candidate_city=source.contact.city,
        cv_text=editable.cv_text,
        cv_sha256=editable.cv_sha256,
        sections={
            section.heading: tuple(cv_facts[value] for value in section.sentence_ids)
            for section in source.cv_sections
        },
        rendered_pages=(tuple(editable.cv_text.splitlines()),),
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
) -> tuple[dict[str, object], str]:
    authority_bytes = path.read_bytes()
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
    authority = asdict(fact.authority)
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
    contact_authority: CandidateContactAuthority,
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
) -> CandidateApplicationMaterialization:
    """Materialize exact source authority without rendering or release authority."""
    deployment_binding.__post_init__()
    if contact != contact_authority.contact:
        raise ValueError("application contact differs from signed operator authority")
    contact_bytes = contact_authority.source_path.read_bytes()
    if _sha256(contact_bytes) != contact_authority.envelope_sha256:
        raise ValueError("signed contact authority envelope hash differs")
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
    )
    evidence_bytes = approved_evidence_path.read_bytes()
    if _sha256(evidence_bytes) != APPROVED_CANDIDATE_SOURCE_HASHES["approved_evidence"]:
        raise ValueError("application factory candidate evidence hash differs")
    evidence_document = json.loads(evidence_bytes)
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
    editable = render_editable_text(source)
    source_policy = _source_policy_receipt(source, editable)
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
        "contact_authority_sha256": contact_authority.authority_sha256,
        "contact_envelope_sha256": contact_authority.envelope_sha256,
        "contact_registry_sha256": contact_authority.registry_sha256,
        "contact_signer_public_key_sha256": (
            contact_authority.signer_public_key_sha256
        ),
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
        "schema_version": "jaa.candidate-application-materialization-receipt.v3",
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
        contact_authority_sha256=contact_authority.authority_sha256,
        contact_envelope_sha256=contact_authority.envelope_sha256,
        contact_registry_sha256=contact_authority.registry_sha256,
        contact_signer_public_key_sha256=(
            contact_authority.signer_public_key_sha256
        ),
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
    "materialize_candidate_application_source",
]
