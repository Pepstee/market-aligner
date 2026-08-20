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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from cv_generation.service import (
    CVCompositionOrchestrationResult,
    run_cv_composition_orchestration,
)

from .evidence_matching import canonical_json, content_hash
from .candidate_contact_authority import (
    CandidateContactAuthority,
    load_candidate_contact_authority,
)
from .handoff_admission import (
    HandoffAdmissionError,
    HandoffAdmissionStore,
    VerifiedApplicationInput,
)


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode()


def _private_external_root(path: Path, repository_root: Path) -> Path:
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
    release_authority: bool = False


class PreparationInputMaterializer(Protocol):
    """Build typed CV inputs from an exact admitted job and exact authorities."""

    def __call__(
        self,
        verified: VerifiedApplicationInput,
        candidate_authority_sha256: str,
        contact_authority: CandidateContactAuthority,
    ) -> Mapping[str, Any]: ...


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
    contact_authority_loader: Callable[..., CandidateContactAuthority] = (
        load_candidate_contact_authority
    ),
) -> MarketApplicationPreparation:
    """Materialize one real preparation from admitted and operator authority.

    Provider-backed writing remains outside this function.  The injected
    materializer must return the already typed, evidence-bound editorial
    request/drafts and recruiter assessor used by the existing orchestration.
    """

    repository = repository_root.resolve(strict=True)
    candidate_path = candidate_authority_path.resolve(strict=True)
    contact_path = contact_authority_path.resolve(strict=True)
    for label, path in (("candidate", candidate_path), ("contact", contact_path)):
        if repository == path or repository in path.parents:
            raise ValueError(f"{label} authority must be outside the repository")
    candidate_bytes = _read_private(candidate_path)
    candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
    admitted_candidate_sha256 = admission_store.reference_sha256(
        application_id, "candidate_intent.authority_source"
    )
    if candidate_sha256 != admitted_candidate_sha256:
        raise HandoffAdmissionError(
            "preparation_candidate_authority",
            "candidate authority differs from admitted handoff",
        )
    contact_authority = contact_authority_loader(
        contact_path,
        repository_root=repository,
    )
    contact_bytes = _read_private(contact_path)
    contact_sha256 = hashlib.sha256(contact_bytes).hexdigest()
    if contact_authority.authority_sha256 != contact_sha256:
        raise ValueError("loaded contact authority differs from exact file bytes")

    verified = admission_store.for_boundary(application_id, "strategy")
    arguments = dict(
        input_materializer(verified, candidate_sha256, contact_authority)
    )
    source = arguments.get("base_source")
    request = arguments.get("request")
    if source is None or source.contact != contact_authority.contact:
        raise ValueError("materialized application contact differs from operator authority")
    if request is None or request.authority.source_sha256 != candidate_sha256:
        raise ValueError("materialized editorial request differs from candidate authority")
    return prepare_admitted_market_application(
        admission_store=_VerifiedBoundary(verified),
        application_id=application_id,
        repository_root=repository,
        data_home=data_home,
        candidate_authority_bytes=candidate_bytes,
        candidate_authority_sha256=candidate_sha256,
        contact_authority_bytes=contact_bytes,
        contact_authority_sha256=contact_sha256,
        orchestration_arguments=arguments,
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
    orchestration_arguments: Mapping[str, Any],
) -> MarketApplicationPreparation:
    """Prepare one admitted application; never authorize upload or submission."""

    for label, value, digest in (
        ("candidate", candidate_authority_bytes, candidate_authority_sha256),
        ("contact", contact_authority_bytes, contact_authority_sha256),
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
    assessor = orchestration_arguments.get("recruiter_assessor")
    assessor_identity = None
    if assessor is not None:
        assessor_identity = (
            f"{assessor.__class__.__module__}.{assessor.__class__.__qualname__}"
        )
    input_identity = {
        "application_id": application_id,
        "base_source_identity": base_source.source_id,
        "bindings_sha256": content_hash(
            [_input_document(value) for value in orchestration_arguments.get("bindings", ())]
        ),
        "candidate_authority_sha256": candidate_authority_sha256,
        "contact_authority_sha256": contact_authority_sha256,
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
        "schema_version": "jaa.market-application-preparation-input.v1",
        "writer_evidence_sha256": content_hash(
            _input_document(orchestration_arguments.get("writer_evidence"))
        ),
        "writer_draft_sha256": writer_draft.draft_sha256,
    }
    preparation_id = content_hash(input_identity)
    root = _private_external_root(data_home, repository_root)
    destination = root / "preparations" / preparation_id
    receipt_path = destination / "receipt.json"
    if receipt_path.exists():
        receipt_bytes = _read_private(receipt_path)
        try:
            receipt = json.loads(receipt_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("stored preparation receipt is invalid JSON") from exc
        if receipt_bytes != _json_bytes(receipt) or set(receipt) != {
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
        }:
            raise ValueError("stored preparation receipt schema differs")
        if (
            receipt.get("preparation_id") != preparation_id
            or receipt.get("application_id") != application_id
            or receipt.get("candidate_authority_sha256")
            != candidate_authority_sha256
            or receipt.get("contact_authority_sha256") != contact_authority_sha256
            or receipt.get("release_authority") is not False
            or receipt.get("schema_version")
            != "jaa.market-application-preparation.v1"
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
                _read_private(destination / "objects" / contact_authority_sha256)
            ).hexdigest()
            != contact_authority_sha256
        ):
            raise ValueError("stored preparation replay is invalid")
        return MarketApplicationPreparation(
            preparation_id,
            destination,
            hashlib.sha256(receipt_bytes).hexdigest(),
            str(receipt["orchestration_sha256"]),
        )
    verified = admission_store.for_boundary(application_id, "strategy")
    exact = {
        "job_key": (base_source.job_key, verified.job_key),
        "role_title": (base_source.role_title, verified.role_title),
        "company_name": (base_source.company_name, verified.company_name),
        "vacancy_snapshot_sha256": (
            base_source.vacancy_sha256,
            verified.vacancy_snapshot_sha256,
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
        **dict(orchestration_arguments)
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
            temporary / "objects" / contact_authority_sha256,
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
            "cv_pdf_sha256": result.final_artifacts.cv_pdf.pdf_sha256,
            "cover_letter_pdf_sha256": result.final_artifacts.cover_letter_pdf.pdf_sha256,
            "current_boundary_receipt_sha256": verified.current_boundary_receipt_sha256,
            "handoff_root_sha256": verified.handoff_root_sha256,
            "orchestration_sha256": result.orchestration_sha256,
            "preparation_id": preparation_id,
            "release_authority": False,
            "schema_version": "jaa.market-application-preparation.v1",
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
        destination,
        hashlib.sha256(receipt_bytes).hexdigest(),
        result.orchestration_sha256,
    )


__all__ = [
    "MarketApplicationPreparation",
    "PreparationInputMaterializer",
    "prepare_admitted_market_application",
    "prepare_admitted_market_application_from_authorities",
]
