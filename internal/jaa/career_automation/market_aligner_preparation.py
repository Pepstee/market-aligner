"""Canonical MA-to-JAA CV preparation coordinator.

This is deliberately not another handoff format.  It consumes the admitted v1
handoff, pins the exact candidate/contact authorities, invokes the existing CV
composition orchestration, and can only emit a non-release preparation bundle.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from cv_generation.constraints import policy_for_candidate
from cv_generation.service import (
    CVCompositionOrchestrationResult,
    run_cv_composition_orchestration,
)

from .evidence_matching import canonical_json, content_hash
from .candidate_contact_authority import (
    CandidateContactAuthority,
    CandidateContactResourceLease,
    load_candidate_contact_authority,
)
from .candidate_application_factory import (
    CandidateApplicationMaterialization,
    CandidateApplicationMaterializationReceipt,
    CandidateApplicationDeploymentBinding,
    build_candidate_application_deployment_binding,
    build_market_application_decision_authority,
    materialize_candidate_application_source,
)
from cv_generation.editorial_composition import (
    ApprovedCoverLetterClaim,
    ApprovedCVClaim,
    CandidateEditorialAuthority,
    EditorialCompositionRuntime,
    build_cover_letter_editorial_request,
    build_editorial_request,
    run_cover_letter_composition_runtime,
    run_editorial_composition_runtime,
)
from .handoff_admission import (
    HandoffAdmissionError,
    HandoffAdmissionStore,
    VerifiedApplicationInput,
)


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode()


def _candidate_editorial_authority(
    *, candidate_name: str, candidate_city: str, source_sha256: str
) -> CandidateEditorialAuthority:
    """Project the canonical candidate-specific CV policy into editorial authority."""

    policy = policy_for_candidate(candidate_name)
    return CandidateEditorialAuthority(
        candidate_name=candidate_name,
        candidate_city=candidate_city,
        graduation_month_year=policy.required_graduation,
        dissertation_title=policy.required_dissertation_title,
        source_sha256=source_sha256,
        require_dissertation=policy.required_dissertation_title is not None,
    )


def _private_external_root(
    path: Path,
    repository_root: Path,
    *,
    descriptor: int | None = None,
) -> Path:
    if descriptor is not None:
        if not os.path.isdir(f"/proc/self/fd/{descriptor}"):
            raise ValueError("preparation output lease is not a directory")
        return Path(f"/proc/self/fd/{descriptor}")
    root = path.resolve()
    repository = repository_root.resolve(strict=True)
    if repository == root or repository in root.parents:
        raise ValueError("preparation data home must be outside the repository")
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root


def _write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != value:
            raise ValueError("content-addressed preparation replay differs")
        return
    with path.open("xb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def _input_document(value: object) -> object:
    document = getattr(value, "document", None)
    if callable(document):
        return document()
    if hasattr(value, "__dict__"):
        return vars(value)
    return value


def _read_private(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError("stored preparation files cannot be symlinks")
    metadata = path.stat()
    if not path.is_file() or metadata.st_mode & 0o077:
        raise ValueError("stored preparation file is not private")
    return path.read_bytes()


@dataclass(frozen=True)
class MarketApplicationPreparation:
    preparation_id: str
    path: Path
    receipt_sha256: str
    orchestration_sha256: str
    recruiter_receipt_sha256: str | None = None
    recruiter_transport_receipt_sha256: str | None = None
    recruiter_archive_manifest_sha256: str | None = None
    recruiter_assessor_configuration_sha256: str | None = None
    recruiter_archive_root: str | None = None
    recruiter_archive_manifest_relative_path: str | None = None
    release_authority: bool = False


class PreparationInputMaterializer(Protocol):
    """Build typed CV inputs from an exact admitted job and exact authorities."""

    def __call__(
        self,
        verified: VerifiedApplicationInput,
        deployment_binding: CandidateApplicationDeploymentBinding,
        contact_authority: CandidateContactAuthority,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class CanonicalPreparationInputMaterializer:
    """Pure authority compiler used before any production provider is available."""

    candidate_authority_path: Path
    decision_receipt: Mapping[str, object] | None = None
    candidate_projection: Mapping[str, object] | None = None
    job_key: str | None = None
    vacancy_sha256: str | None = None
    source_url: str | None = None
    role_title: str | None = None
    company_name: str | None = None
    candidate_authority_bytes: bytes | None = None
    contact_authority_bytes: bytes | None = None

    def __call__(
        self,
        verified: VerifiedApplicationInput,
        deployment_binding: CandidateApplicationDeploymentBinding,
        contact_authority: CandidateContactAuthority,
    ) -> Mapping[str, Any]:
        candidate_path = (
            self.candidate_authority_path.resolve(strict=True)
            if self.candidate_authority_bytes is None
            else self.candidate_authority_path
        )
        authority_bytes = (
            candidate_path.read_bytes()
            if self.candidate_authority_bytes is None
            else self.candidate_authority_bytes
        )
        authority_document = json.loads(authority_bytes)
        projection = authority_document.get("candidate_projection")
        if not isinstance(projection, Mapping):
            raise ValueError("canonical materializer candidate projection is malformed")
        integrated = bool(
            verified.source_job_key
            and verified.assessment_receipt_bytes
            and verified.eligibility_receipt_bytes
            and verified.selection_receipt_bytes
        )
        if integrated:
            if any(
                value is not None
                for value in (
                    self.decision_receipt,
                    self.candidate_projection,
                    self.job_key,
                    self.vacancy_sha256,
                    self.source_url,
                    self.role_title,
                    self.company_name,
                )
            ):
                raise ValueError("admitted materializer rejects caller vacancy authority")
            market_authority = build_market_application_decision_authority(
                deployment_binding=deployment_binding,
                source_job_key=verified.source_job_key,
                internal_job_key=verified.job_key,
                vacancy_snapshot_sha256=verified.vacancy_snapshot_sha256,
                raw_listing_sha256=verified.raw_listing_sha256,
                raw_listing_bytes=verified.raw_listing_bytes,
                requirements_sha256=verified.requirements_sha256,
                requirements_bytes=verified.requirements_bytes,
                assessment_receipt_sha256=verified.assessment_receipt_sha256,
                assessment_receipt_bytes=verified.assessment_receipt_bytes,
                eligibility_receipt_sha256=verified.eligibility_receipt_sha256,
                eligibility_receipt_bytes=verified.eligibility_receipt_bytes,
                selection_receipt_sha256=verified.selection_receipt_sha256,
                selection_receipt_bytes=verified.selection_receipt_bytes,
                candidate_projection=projection,
                candidate_authority_bytes=verified.candidate_authority_bytes,
                evidence_ledger_sha256=verified.evidence_ledger_sha256,
                evidence_ledger_bytes=verified.evidence_ledger_bytes,
                source_url=verified.canonical_url,
                role_title=verified.role_title,
                company_name=verified.company_name,
                observed_at=verified.source_observed_at,
            )
            decision = market_authority.decision_receipt()
            source_job_key = market_authority.source_job_key
            raw_listing_sha256 = market_authority.raw_listing_sha256
            source_url = market_authority.source_url
            role_title = market_authority.role_title
            company_name = market_authority.company_name
        else:
            if (
                self.decision_receipt is None
                or self.candidate_projection is None
                or self.job_key is None
                or self.vacancy_sha256 is None
                or self.source_url is None
                or self.role_title is None
                or self.company_name is None
            ):
                raise ValueError("legacy materializer vacancy authority is incomplete")
            if (
                verified.job_key != self.job_key
                or verified.raw_listing_sha256 != self.vacancy_sha256
                or verified.role_title != self.role_title
                or verified.company_name != self.company_name
                or verified.canonical_url != self.source_url
            ):
                raise ValueError("canonical materializer vacancy differs from admission")
            market_authority = None
            decision = self.decision_receipt
            projection = self.candidate_projection
            source_job_key = self.job_key
            raw_listing_sha256 = self.vacancy_sha256
            source_url = self.source_url
            role_title = self.role_title
            company_name = self.company_name
        materialization = materialize_candidate_application_source(
            candidate_authority_path=candidate_path,
            deployment_binding=deployment_binding,
            contact_authority=contact_authority,
            decision_receipt=decision,
            candidate_projection=projection,
            job_key=source_job_key,
            vacancy_sha256=raw_listing_sha256,
            source_url=source_url,
            role_title=role_title,
            company_name=company_name,
            contact=contact_authority.contact,
            market_decision_authority=market_authority,
            candidate_authority_bytes=self.candidate_authority_bytes,
            contact_authority_bytes=self.contact_authority_bytes,
        )
        heading_by_id = {
            sentence_id: section.heading
            for section in materialization.source.cv_sections
            for sentence_id in section.sentence_ids
        }
        categories = {
            "Professional Summary": "summary",
            "Core Capabilities": "capability_domain",
            "Projects": "project",
            "Experience": "experience",
            "Education": "education",
        }
        claims = tuple(
            ApprovedCVClaim(
                claim_id=str(row["sentence_id"]),
                text=str(row["text"]),
                text_sha256=str(row["text_sha256"]),
                evidence_ids=tuple(str(value) for value in row["evidence_ids"]),
                category=categories[heading_by_id[str(row["sentence_id"])]],
            )
            for row in materialization.receipt.fact_bindings
            if row["document_kind"] == "cv"
        )
        request = build_editorial_request(
            authority=_candidate_editorial_authority(
                candidate_name=contact_authority.contact.full_name,
                candidate_city=contact_authority.contact.city,
                source_sha256=deployment_binding.candidate_authority_file_sha256,
            ),
            role_title=role_title,
            company_name=company_name,
            vacancy_sha256=raw_listing_sha256,
            approved_claims=claims,
        )
        cover_claims = tuple(
            ApprovedCoverLetterClaim(
                claim_id=str(row["sentence_id"]),
                text=str(row["text"]),
                text_sha256=str(row["text_sha256"]),
                evidence_ids=tuple(str(value) for value in row["evidence_ids"]),
                fact_kind=str(row["fact_kind"]),
                section_heading=str(row["section_heading"]),
            )
            for row in materialization.receipt.fact_bindings
            if row["document_kind"] == "cover_letter"
        )
        cover_request = build_cover_letter_editorial_request(
            authority=request.authority,
            role_title=role_title,
            company_name=company_name,
            vacancy_sha256=raw_listing_sha256,
            approved_claims=cover_claims,
        )
        listing_text = verified.raw_listing_bytes.decode("utf-8")
        if hashlib.sha256(listing_text.encode()).hexdigest() != raw_listing_sha256:
            raise ValueError("canonical materializer listing differs from vacancy")
        return {
            "base_source": materialization.source,
            "listing_text": listing_text,
            "materialization": materialization,
            "request": request,
            "cover_letter_request": cover_request,
        }


class _VerifiedBoundary:
    """Carry one freshly verified boundary into the canonical preparation service."""

    def __init__(self, verified: VerifiedApplicationInput) -> None:
        self.verified = verified

    def for_boundary(self, application_id: str, boundary: str) -> VerifiedApplicationInput:
        if application_id != self.verified.application_id or boundary != "strategy":
            raise HandoffAdmissionError(
                "preparation_boundary", "prepared input requested another boundary"
            )
        return self.verified


def prepare_admitted_market_application_from_authorities(
    *,
    admission_store: HandoffAdmissionStore,
    application_id: str,
    repository_root: Path,
    data_home: Path,
    candidate_authority_path: Path,
    contact_authority_path: Path,
    input_materializer: PreparationInputMaterializer,
    environment: str,
    editorial_runtime: EditorialCompositionRuntime | None = None,
    cover_letter_editorial_runtime: EditorialCompositionRuntime | None = None,
    orchestration_extras: Mapping[str, Any] | None = None,
    contact_authority_loader: Callable[..., CandidateContactAuthority] = (
        load_candidate_contact_authority
    ),
    candidate_authority_bytes: bytes | None = None,
    contact_resource_lease: CandidateContactResourceLease | None = None,
    output_root_descriptor: int | None = None,
) -> MarketApplicationPreparation:
    """Materialize one real preparation from admitted and operator authority.

    Provider-backed writing remains outside this function. The materializer
    returns typed, evidence-bound editorial inputs. Production recruiter
    execution is separately constrained by the orchestration boundary.
    """

    repository = repository_root.resolve(strict=True)
    verified = admission_store.for_boundary(application_id, "strategy")
    if verified.environment != environment:
        raise HandoffAdmissionError(
            "preparation_environment",
            "requested preparation environment differs from admitted environment",
        )
    if environment == "production" and (
        contact_authority_loader is not load_candidate_contact_authority
    ):
        raise ValueError("production preparation requires canonical contact loader")
    if environment == "production" and (
        type(input_materializer) is not CanonicalPreparationInputMaterializer
        or type(editorial_runtime) is not EditorialCompositionRuntime
        or type(cover_letter_editorial_runtime) is not EditorialCompositionRuntime
        or editorial_runtime.document_kind != "cv"
        or cover_letter_editorial_runtime.document_kind != "cover_letter"
    ):
        raise ValueError(
            "production preparation requires canonical materializer and editorial runtime"
        )
    candidate_path = (
        candidate_authority_path.resolve(strict=True)
        if candidate_authority_bytes is None
        else candidate_authority_path
    )
    if not candidate_path.is_absolute():
        raise ValueError("candidate authority path must be absolute")
    if environment == "production" and (
        (
            input_materializer.candidate_authority_path.resolve(strict=True)
            if input_materializer.candidate_authority_bytes is None
            else input_materializer.candidate_authority_path
        )
        != candidate_path
        or input_materializer.candidate_authority_bytes != candidate_authority_bytes
        or input_materializer.contact_authority_bytes
        != (
            contact_resource_lease.authority_bytes
            if contact_resource_lease is not None
            else None
        )
    ):
        raise ValueError("production materializer targets another candidate authority")
    contact_path = (
        contact_authority_path.resolve(strict=True)
        if contact_resource_lease is None
        else contact_authority_path
    )
    if not contact_path.is_absolute():
        raise ValueError("contact authority path must be absolute")
    for label, path in (("candidate", candidate_path), ("contact", contact_path)):
        if repository == path or repository in path.parents:
            raise ValueError(f"{label} authority must be outside the repository")
    candidate_bytes = (
        _read_private(candidate_path)
        if candidate_authority_bytes is None
        else candidate_authority_bytes
    )
    candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
    admitted_candidate_sha256 = getattr(
        verified, "candidate_authority_sha256", None
    )
    if not isinstance(admitted_candidate_sha256, str):
        raise HandoffAdmissionError(
            "preparation_candidate_authority",
            "freshly verified handoff lacks candidate authority identity",
        )
    if candidate_sha256 != admitted_candidate_sha256:
        raise HandoffAdmissionError(
            "preparation_candidate_authority",
            "candidate authority differs from admitted handoff",
        )
    contact_authority = contact_authority_loader(
        contact_path,
        repository_root=repository,
        resource_lease=contact_resource_lease,
    )
    contact_bytes = (
        _read_private(contact_path)
        if contact_resource_lease is None
        else contact_resource_lease.authority_bytes
    )
    contact_object_sha256 = hashlib.sha256(contact_bytes).hexdigest()

    deployment_binding = build_candidate_application_deployment_binding(
        application_id=verified.application_id,
        environment=verified.environment,
        handoff_root_sha256=verified.handoff_root_sha256,
        admission_receipt_sha256=verified.admission_receipt_sha256,
        current_boundary_receipt_sha256=(
            verified.current_boundary_receipt_sha256
        ),
        candidate_authority_file_sha256=candidate_sha256,
    )
    if environment == "production" and (
        candidate_authority_bytes is None
        or type(contact_resource_lease) is not CandidateContactResourceLease
    ):
        raise ValueError("production preparation requires exact resource leases")
    arguments = dict(input_materializer(verified, deployment_binding, contact_authority))
    source = arguments.get("base_source")
    request = arguments.get("request")
    cover_letter_request = arguments.get("cover_letter_request")
    materialization = arguments.get("materialization")
    if source is None:
        raise ValueError("preparation materializer omitted the application source")
    if request is None or (environment == "production" and cover_letter_request is None):
        raise ValueError("preparation materializer omitted an editorial request")
    if not isinstance(materialization, CandidateApplicationMaterialization):
        raise ValueError("preparation requires typed candidate materialization")
    receipt = materialization.receipt
    if not isinstance(receipt, CandidateApplicationMaterializationReceipt):
        raise ValueError("preparation materialization receipt type differs")
    receipt.__post_init__()
    if (
        receipt.deployment_binding != deployment_binding
        or receipt.candidate_authority_file_sha256 != candidate_sha256
        or receipt.contact_authority_sha256 != contact_authority.authority_sha256
        or receipt.contact_envelope_sha256 != contact_object_sha256
        or receipt.contact_registry_sha256 != contact_authority.registry_sha256
        or receipt.contact_signer_public_key_sha256
        != contact_authority.signer_public_key_sha256
        or materialization.source != source
        or receipt.application_source_id != source.source_id
        or receipt.application_source_sha256 != source.content_sha256
    ):
        raise ValueError("materialization differs from admitted candidate authorities")
    if source.contact != contact_authority.contact:
        raise ValueError("materialized application contact differs from operator authority")
    if request.authority.source_sha256 != candidate_sha256:
        raise ValueError("materialized editorial request differs from candidate authority")
    receipt.authorize_editorial_request(request)
    if cover_letter_request is not None:
        receipt.authorize_editorial_request(cover_letter_request)
    arguments["materialization_receipt"] = receipt
    if environment == "production":
        assert editorial_runtime is not None
        assert cover_letter_editorial_runtime is not None
        reserved = {
            "base_source",
            "humanized_draft",
            "humanizer_evidence",
            "listing_text",
            "materialization",
            "materialization_receipt",
            "request",
            "cover_letter_request",
            "cover_letter_writer_draft",
            "cover_letter_humanized_draft",
            "cover_letter_writer_evidence",
            "cover_letter_humanizer_evidence",
            "writer_draft",
            "writer_evidence",
        }
        extras = dict(orchestration_extras or {})
        if reserved & set(extras):
            raise ValueError("production orchestration extras override authority inputs")
        (
            writer_draft,
            humanized_draft,
            writer_evidence,
            humanizer_evidence,
        ) = run_editorial_composition_runtime(
            request,
            runtime=editorial_runtime,
            materialization_receipt=receipt,
        )
        (
            cover_writer_draft,
            cover_humanized_draft,
            cover_writer_evidence,
            cover_humanizer_evidence,
        ) = run_cover_letter_composition_runtime(
            cover_letter_request,
            runtime=cover_letter_editorial_runtime,
            materialization_receipt=receipt,
        )
        arguments.update(extras)
        arguments.update(
            {
                "writer_draft": writer_draft,
                "humanized_draft": humanized_draft,
                "writer_evidence": writer_evidence,
                "humanizer_evidence": humanizer_evidence,
                "cover_letter_writer_draft": cover_writer_draft,
                "cover_letter_humanized_draft": cover_humanized_draft,
                "cover_letter_writer_evidence": cover_writer_evidence,
                "cover_letter_humanizer_evidence": cover_humanizer_evidence,
            }
        )
    elif (
        editorial_runtime is not None
        or cover_letter_editorial_runtime is not None
        or orchestration_extras is not None
    ):
        raise ValueError(
            "synthetic preparation receives complete injected orchestration inputs"
        )
    return _prepare_admitted_market_application(
        admission_store=_VerifiedBoundary(verified),
        application_id=application_id,
        repository_root=repository,
        data_home=data_home,
        candidate_authority_bytes=candidate_bytes,
        candidate_authority_sha256=candidate_sha256,
        contact_authority_bytes=contact_bytes,
        contact_authority_sha256=contact_authority.authority_sha256,
        contact_object_sha256=contact_object_sha256,
        orchestration_arguments=arguments,
        environment=environment,
        output_root_descriptor=output_root_descriptor,
    )


def prepare_admitted_market_application(
    *,
    admission_store: HandoffAdmissionStore,
    application_id: str,
    repository_root: Path,
    data_home: Path,
    candidate_authority_bytes: bytes,
    candidate_authority_sha256: str,
    contact_authority_bytes: bytes,
    contact_authority_sha256: str,
    contact_object_sha256: str | None = None,
    orchestration_arguments: Mapping[str, Any],
    environment: str,
) -> MarketApplicationPreparation:
    """Prepare one synthetic application through the compatibility entry point.

    Production must enter through
    :func:`prepare_admitted_market_application_from_authorities`, which resolves
    and verifies the signed candidate/contact authority graph before delegating
    to the private preparation implementation.
    """

    if environment != "synthetic":
        raise HandoffAdmissionError(
            "preparation_entry_point",
            "direct production preparation is forbidden; use the authority wrapper",
        )
    return _prepare_admitted_market_application(
        admission_store=admission_store,
        application_id=application_id,
        repository_root=repository_root,
        data_home=data_home,
        candidate_authority_bytes=candidate_authority_bytes,
        candidate_authority_sha256=candidate_authority_sha256,
        contact_authority_bytes=contact_authority_bytes,
        contact_authority_sha256=contact_authority_sha256,
        contact_object_sha256=contact_object_sha256,
        orchestration_arguments=orchestration_arguments,
        environment=environment,
    )


def _prepare_admitted_market_application(
    *,
    admission_store: HandoffAdmissionStore,
    application_id: str,
    repository_root: Path,
    data_home: Path,
    candidate_authority_bytes: bytes,
    candidate_authority_sha256: str,
    contact_authority_bytes: bytes,
    contact_authority_sha256: str,
    contact_object_sha256: str | None = None,
    orchestration_arguments: Mapping[str, Any],
    environment: str,
    output_root_descriptor: int | None = None,
) -> MarketApplicationPreparation:
    """Prepare one admitted application; never authorize upload or submission."""

    exact_contact_sha256 = contact_object_sha256 or contact_authority_sha256
    for label, value, digest in (
        ("candidate", candidate_authority_bytes, candidate_authority_sha256),
        ("contact", contact_authority_bytes, exact_contact_sha256),
    ):
        if not value or hashlib.sha256(value).hexdigest() != digest:
            raise ValueError(f"{label} authority exact bytes differ from their digest")
    request = orchestration_arguments.get("request")
    base_source = orchestration_arguments.get("base_source")
    writer_draft = orchestration_arguments.get("writer_draft")
    humanized_draft = orchestration_arguments.get("humanized_draft")
    if any(
        value is None
        for value in (request, base_source, writer_draft, humanized_draft)
    ):
        raise ValueError("CV orchestration inputs are incomplete")
    if request.authority.source_sha256 != candidate_authority_sha256:
        raise ValueError("editorial request differs from candidate authority")
    if base_source.contact.provenance_sha256 != contact_authority_sha256:
        raise ValueError("application source differs from contact authority")
    listing_sha256 = hashlib.sha256(
        orchestration_arguments["listing_text"].encode()
    ).hexdigest()
    if listing_sha256 != request.vacancy_sha256:
        raise ValueError("editorial request differs from exact listing")
    verified = admission_store.for_boundary(application_id, "strategy")
    if verified.environment != environment:
        raise HandoffAdmissionError(
            "preparation_environment",
            "requested preparation environment differs from admitted environment",
        )
    if environment not in {"production", "synthetic"}:
        raise HandoffAdmissionError(
            "preparation_environment", "admitted environment is unsupported"
        )
    assessor = orchestration_arguments.get("production_recruiter_assessor")
    if environment == "production":
        from .production_recruiter_assessor import ProductionDetachedRecruiterAssessor

        if (
            type(assessor) is not ProductionDetachedRecruiterAssessor
            or orchestration_arguments.get("recruiter_assessor") is not None
            or orchestration_arguments.get("recruiter_receipt") is not None
        ):
            raise ValueError(
                "production preparation requires the typed detached recruiter assessor"
            )
        assessor_identity = assessor.configuration_sha256
        if content_hash(assessor.configuration_document()) != assessor_identity:
            raise ValueError("production recruiter configuration identity differs")
    else:
        if assessor is not None:
            raise ValueError(
                "synthetic preparation cannot use the production recruiter assessor"
            )
        synthetic_assessor = orchestration_arguments.get("recruiter_assessor")
        assessor_identity = (
            None
            if synthetic_assessor is None
            else f"{synthetic_assessor.__class__.__module__}."
            f"{synthetic_assessor.__class__.__qualname__}"
        )
    input_identity = {
        "application_id": application_id,
        "base_source_identity": base_source.source_id,
        "bindings_sha256": content_hash(
            [_input_document(value) for value in orchestration_arguments.get("bindings", ())]
        ),
        "candidate_authority_sha256": candidate_authority_sha256,
        "contact_authority_sha256": contact_authority_sha256,
        "contact_object_sha256": exact_contact_sha256,
        "environment": environment,
        "form_fields_sha256": content_hash(
            list(orchestration_arguments.get("form_fields", ()))
        ),
        "humanizer_evidence_sha256": content_hash(
            _input_document(orchestration_arguments.get("humanizer_evidence"))
        ),
        "humanized_draft_sha256": humanized_draft.draft_sha256,
        "listing_sha256": listing_sha256,
        "recruiter_assessor_identity": assessor_identity,
        "recruiter_receipt_sha256": getattr(
            orchestration_arguments.get("recruiter_receipt"),
            "receipt_sha256",
            None,
        ),
        "request_sha256": request.request_sha256,
        "schema_version": "jaa.market-application-preparation-input.v3",
        "writer_evidence_sha256": content_hash(
            _input_document(orchestration_arguments.get("writer_evidence"))
        ),
        "writer_draft_sha256": writer_draft.draft_sha256,
    }
    preparation_id = content_hash(input_identity)
    root = _private_external_root(
        data_home,
        repository_root,
        descriptor=output_root_descriptor,
    )
    destination = root / "preparations" / preparation_id
    canonical_destination = data_home / "preparations" / preparation_id
    receipt_path = destination / "receipt.json"
    if receipt_path.exists():
        receipt_bytes = _read_private(receipt_path)
        try:
            receipt = json.loads(receipt_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("stored preparation receipt is invalid JSON") from exc
        schema_version = receipt.get("schema_version")
        expected_keys = {
            "admission_receipt_sha256",
            "application_id",
            "candidate_authority_sha256",
            "contact_authority_sha256",
            "cover_letter_pdf_sha256",
            "current_boundary_receipt_sha256",
            "cv_pdf_sha256",
            "handoff_root_sha256",
            "orchestration_sha256",
            "preparation_id",
            "release_authority",
            "schema_version",
        }
        if schema_version != "jaa.market-application-preparation.v3":
            raise ValueError("stored preparation receipt schema differs")
        expected_keys.update(
            {
                "contact_object_sha256",
                "environment",
                "recruiter_archive_manifest_sha256",
                "recruiter_archive_manifest_relative_path",
                "recruiter_archive_receipt",
                "recruiter_archive_root",
                "recruiter_assessor_configuration",
                "recruiter_assessor_configuration_sha256",
                "recruiter_receipt_sha256",
                "recruiter_transport_receipt_sha256",
            }
        )
        stored_contact_object_sha256 = str(
            receipt.get("contact_object_sha256", receipt.get("contact_authority_sha256"))
        )
        if receipt_bytes != _json_bytes(receipt) or set(receipt) != expected_keys:
            raise ValueError("stored preparation receipt schema differs")
        if (
            receipt.get("preparation_id") != preparation_id
            or receipt.get("application_id") != application_id
            or receipt.get("candidate_authority_sha256")
            != candidate_authority_sha256
            or receipt.get("contact_authority_sha256") != contact_authority_sha256
            or receipt.get("release_authority") is not False
            or receipt.get("environment") != environment
            or (
                environment == "production"
                and (
                    receipt.get("recruiter_transport_receipt_sha256") is None
                    or receipt.get("recruiter_archive_manifest_sha256") is None
                    or receipt.get("recruiter_assessor_configuration_sha256")
                    != assessor_identity
                    or receipt.get("recruiter_assessor_configuration")
                    != assessor.configuration_document()
                    or content_hash(receipt.get("recruiter_assessor_configuration"))
                    != assessor_identity
                    or receipt.get("recruiter_archive_root")
                    != str(assessor.archive_root)
                    or not receipt.get("recruiter_archive_manifest_relative_path")
                    or not isinstance(receipt.get("recruiter_archive_receipt"), dict)
                )
            )
            or (
                environment == "synthetic"
                and (
                    receipt.get("recruiter_transport_receipt_sha256") is not None
                    or receipt.get("recruiter_archive_manifest_sha256") is not None
                    or receipt.get("recruiter_assessor_configuration_sha256") is not None
                    or receipt.get("recruiter_assessor_configuration") is not None
                    or receipt.get("recruiter_archive_root") is not None
                    or receipt.get("recruiter_archive_manifest_relative_path") is not None
                    or receipt.get("recruiter_archive_receipt") is not None
                )
            )
            or stored_contact_object_sha256 != exact_contact_sha256
            or hashlib.sha256(_read_private(destination / "cv.pdf")).hexdigest()
            != receipt.get("cv_pdf_sha256")
            or hashlib.sha256(
                _read_private(destination / "cover-letter.pdf")
            ).hexdigest()
            != receipt.get("cover_letter_pdf_sha256")
            or hashlib.sha256(
                _read_private(destination / "objects" / candidate_authority_sha256)
            ).hexdigest()
            != candidate_authority_sha256
            or hashlib.sha256(
                _read_private(destination / "objects" / stored_contact_object_sha256)
            ).hexdigest()
            != stored_contact_object_sha256
        ):
            raise ValueError("stored preparation replay is invalid")
        if environment == "production":
            from .adversarial_recruiter_archive import (
                RecruiterDiagnosticArchiveReceipt,
                verify_recruiter_diagnostic_archive,
            )

            try:
                archived = RecruiterDiagnosticArchiveReceipt(
                    **dict(receipt["recruiter_archive_receipt"])
                )
                replayed = verify_recruiter_diagnostic_archive(
                    archived, root=Path(str(receipt["recruiter_archive_root"]))
                )
            except (TypeError, ValueError) as exc:
                raise ValueError("stored recruiter archive replay is invalid") from exc
            if (
                archived.manifest_sha256
                != receipt["recruiter_archive_manifest_sha256"]
                or archived.manifest_relative_path
                != receipt["recruiter_archive_manifest_relative_path"]
                or replayed.assessment.receipt_sha256
                != receipt["recruiter_receipt_sha256"]
                or replayed.transport.receipt_sha256
                != receipt["recruiter_transport_receipt_sha256"]
            ):
                raise ValueError("stored recruiter archive replay differs")
        return MarketApplicationPreparation(
            preparation_id,
            canonical_destination,
            hashlib.sha256(receipt_bytes).hexdigest(),
            str(receipt["orchestration_sha256"]),
            str(receipt["recruiter_receipt_sha256"]),
            (
                str(receipt["recruiter_transport_receipt_sha256"])
                if receipt["recruiter_transport_receipt_sha256"] is not None else None
            ),
            (
                str(receipt["recruiter_archive_manifest_sha256"])
                if receipt["recruiter_archive_manifest_sha256"] is not None else None
            ),
            (
                str(receipt["recruiter_assessor_configuration_sha256"])
                if receipt["recruiter_assessor_configuration_sha256"] is not None else None
            ),
            (
                str(receipt["recruiter_archive_root"])
                if receipt["recruiter_archive_root"] is not None else None
            ),
            (
                str(receipt["recruiter_archive_manifest_relative_path"])
                if receipt["recruiter_archive_manifest_relative_path"] is not None else None
            ),
        )
    exact = {
        "job_key": (base_source.job_key, verified.source_job_key or verified.job_key),
        "role_title": (base_source.role_title, verified.role_title),
        "company_name": (base_source.company_name, verified.company_name),
        "vacancy_sha256": (
            base_source.vacancy_sha256,
            (
                verified.raw_listing_sha256
                if environment == "production" or verified.source_job_key
                else verified.vacancy_snapshot_sha256
            ),
        ),
    }
    if any(left != right for left, right in exact.values()):
        raise HandoffAdmissionError(
            "preparation_substitution", "CV source differs from admitted handoff"
        )
    if request.vacancy_sha256 != verified.raw_listing_sha256:
        raise HandoffAdmissionError(
            "preparation_listing", "CV request differs from admitted raw listing"
        )
    result: CVCompositionOrchestrationResult = run_cv_composition_orchestration(
        **dict(orchestration_arguments), environment=environment
    )
    if result.release_authority:
        raise RuntimeError("CV preparation unexpectedly acquired release authority")
    temporary = Path(tempfile.mkdtemp(prefix=".preparation-", dir=root))
    os.chmod(temporary, 0o700)
    try:
        _write(
            temporary / "objects" / candidate_authority_sha256,
            candidate_authority_bytes,
        )
        _write(
            temporary / "objects" / exact_contact_sha256,
            contact_authority_bytes,
        )
        _write(temporary / "cv.pdf", result.final_artifacts.cv_pdf.pdf_bytes)
        _write(
            temporary / "cover-letter.pdf",
            result.final_artifacts.cover_letter_pdf.pdf_bytes,
        )
        receipt = {
            "admission_receipt_sha256": verified.admission_receipt_sha256,
            "application_id": application_id,
            "candidate_authority_sha256": candidate_authority_sha256,
            "contact_authority_sha256": contact_authority_sha256,
            "contact_object_sha256": exact_contact_sha256,
            "cv_pdf_sha256": result.final_artifacts.cv_pdf.pdf_sha256,
            "cover_letter_pdf_sha256": result.final_artifacts.cover_letter_pdf.pdf_sha256,
            "current_boundary_receipt_sha256": verified.current_boundary_receipt_sha256,
            "handoff_root_sha256": verified.handoff_root_sha256,
            "environment": environment,
            "orchestration_sha256": result.orchestration_sha256,
            "preparation_id": preparation_id,
            "recruiter_archive_manifest_sha256": (
                result.recruiter_archive_receipt.manifest_sha256
                if result.recruiter_archive_receipt is not None else None
            ),
            "recruiter_archive_manifest_relative_path": (
                result.recruiter_archive_manifest_relative_path
            ),
            "recruiter_archive_receipt": (
                asdict(result.recruiter_archive_receipt)
                if result.recruiter_archive_receipt is not None else None
            ),
            "recruiter_archive_root": result.recruiter_archive_root,
            "recruiter_assessor_configuration": (
                assessor.configuration_document()
                if environment == "production" else None
            ),
            "recruiter_assessor_configuration_sha256": (
                result.recruiter_assessor_configuration_sha256
            ),
            "recruiter_receipt_sha256": result.recruiter_receipt.receipt_sha256,
            "recruiter_transport_receipt_sha256": (
                result.recruiter_transport_receipt.receipt_sha256
                if result.recruiter_transport_receipt is not None else None
            ),
            "release_authority": False,
            "schema_version": "jaa.market-application-preparation.v3",
        }
        receipt_bytes = _json_bytes(receipt)
        _write(temporary / "receipt.json", receipt_bytes)
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(destination.parent, 0o700)
        os.replace(temporary, destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return MarketApplicationPreparation(
        preparation_id,
        canonical_destination,
        hashlib.sha256(receipt_bytes).hexdigest(),
        result.orchestration_sha256,
        result.recruiter_receipt.receipt_sha256,
        (
            result.recruiter_transport_receipt.receipt_sha256
            if result.recruiter_transport_receipt is not None else None
        ),
        (
            result.recruiter_archive_receipt.manifest_sha256
            if result.recruiter_archive_receipt is not None else None
        ),
        result.recruiter_assessor_configuration_sha256,
        result.recruiter_archive_root,
        result.recruiter_archive_manifest_relative_path,
    )


__all__ = [
    "CanonicalPreparationInputMaterializer",
    "MarketApplicationPreparation",
    "PreparationInputMaterializer",
    "prepare_admitted_market_application",
    "prepare_admitted_market_application_from_authorities",
]
