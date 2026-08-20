"""Explicit fixture-only construction of complete release archive receipts."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime
from typing import Mapping

from .application_archive import (
    RELEASE_REQUIRED_ROLES,
    ApplicationArchive,
    ApplicationArchiveReceipt,
    VacancyArchiveIdentity,
    release_upload_mapping_bytes,
)
from .application_compiler import ApplicationSource
from .application_sanity_review import SanityReviewReceipt
from .evidence_matching import canonical_json
from .external_document_assurance import ExternalDocumentAssuranceReceipt
from .rendering import ApplicationArtifacts


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def fixture_release_archive_receipt(
    *,
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
    questions: Mapping[str, tuple[str, str]] | None,
    document_assurance_receipts: tuple[
        ExternalDocumentAssuranceReceipt,
        ExternalDocumentAssuranceReceipt,
    ],
    sanity_review_receipt: SanityReviewReceipt,
    artifact_root: Path,
    repository_root: Path,
    finalized_at: datetime,
) -> tuple[ApplicationArchiveReceipt, Path]:
    """Archive exact fixture authority without pretending it is production evidence."""
    archive_root = artifact_root / "application-archive"
    archive = ApplicationArchive(archive_root, repository_root=repository_root)
    vacancy = VacancyArchiveIdentity(
        job_key=source.job_key,
        vacancy_sha256=source.vacancy_sha256,
        role_title=source.role_title,
        company_name=source.company_name,
        source_url=f"https://fixture.invalid/jobs/{source.job_key}",
    )
    attempt = archive.create_attempt(vacancy)
    approved_claims = [
        {
            "candidate_claim_id": fact.authority.candidate_claim_id,
            "candidate_claim_version": fact.authority.candidate_claim_version,
            "candidate_evidence_id": fact.authority.candidate_evidence_id,
            "candidate_evidence_version": fact.authority.candidate_evidence_version,
        }
        for fact in source.facts
    ]
    question_document = {
        key: {"question": value[0], "answer": value[1]}
        for key, value in sorted((questions or {}).items())
    }
    payloads: dict[str, tuple[bytes, str]] = {
        "vacancy.source_identity": (
            _json_bytes(
                {
                    "vacancy_source_identity": source.vacancy_source_identity,
                    "source_url": vacancy.source_url,
                }
            ),
            "application/json",
        ),
        "vacancy.capture": (_json_bytes(source.document()), "application/json"),
        "vacancy.structured": (_json_bytes(source.document()), "application/json"),
        "vacancy.assessment": (
            _json_bytes(
                {
                    "eligibility": "fixture_only",
                    "fit_score": 0,
                    "queue_rank": 0,
                    "scoring_inputs": [],
                }
            ),
            "application/json",
        ),
        "document.cv.source": (artifacts.editable.cv_text.encode(), "text/plain"),
        "document.source_inputs": (_json_bytes(source.document()), "application/json"),
        "document.cv.final_pdf": (artifacts.cv_pdf.pdf_bytes, "application/pdf"),
        "document.cv.extracted_text": (
            artifacts.cv_pdf.extracted_text.encode(),
            "text/plain",
        ),
        "document.cover_letter.source": (
            artifacts.editable.cover_letter_text.encode(),
            "text/plain",
        ),
        "document.cover_letter.final_pdf": (
            artifacts.cover_letter_pdf.pdf_bytes,
            "application/pdf",
        ),
        "document.cover_letter.extracted_text": (
            artifacts.cover_letter_pdf.extracted_text.encode(),
            "text/plain",
        ),
        "form.questions": (_json_bytes(question_document), "application/json"),
        "form.answers": (artifacts.editable.answers_text.encode(), "text/plain"),
        "form.approved_field_mapping": (
            _json_bytes(
                {
                    "schema_version": "jaa.fixture-approved-form-mapping.v1",
                    "fields": [],
                    "consents": [],
                }
            ),
            "application/json",
        ),
        "evidence.approved_claim_ids": (_json_bytes(approved_claims), "application/json"),
        "assurance.cv.receipt": (
            _json_bytes(document_assurance_receipts[0].document()),
            "application/json",
        ),
        "assurance.cover_letter.receipt": (
            _json_bytes(document_assurance_receipts[1].document()),
            "application/json",
        ),
        "assurance.semantic.receipt": (
            _json_bytes(sanity_review_receipt.document()),
            "application/json",
        ),
        "browser.prefill_snapshot": (
            _json_bytes({"environment": "loopback_fixture", "fields": question_document}),
            "application/json",
        ),
        "browser.pre_submit_screenshot": (
            b"fixture screenshot evidence, not a production image",
            "application/octet-stream",
        ),
        "browser.pre_submit_state": (
            _json_bytes(
                {
                    "environment": "loopback_fixture",
                    "page_title": "Fixture application",
                    "provider": "jaa-loopback",
                }
            ),
            "application/json",
        ),
        "browser.upload_mapping": (
            release_upload_mapping_bytes(
                artifacts.cv_pdf.pdf_sha256,
                artifacts.cover_letter_pdf.pdf_sha256,
            ),
            "application/json",
        ),
        "provider.success_semantics": (
            _json_bytes(
                {
                    "schema_version": "jaa.fixture-success-semantics.v1",
                    "provider": "jaa_loopback",
                }
            ),
            "application/json",
        ),
        "provider.success_observation": (
            _json_bytes(
                {
                    "schema_version": "jaa.fixture-success-observation.v1",
                    "provider": "jaa_loopback",
                }
            ),
            "application/json",
        ),
        "provider.success_authority": (
            _json_bytes(
                {
                    "schema_version": "jaa.fixture-provider-authority.v1",
                    "provider": "jaa_loopback",
                    "environment": "fixture_only",
                }
            ),
            "application/json",
        ),
        "production.identities": (
            _json_bytes(
                {
                    "environment": "fixture_only",
                    "code_contract": "JAA-09",
                    "semantic_receipt": sanity_review_receipt.receipt_sha256,
                }
            ),
            "application/json",
        ),
    }
    if set(payloads) != RELEASE_REQUIRED_ROLES:
        raise AssertionError("fixture archive payload inventory drifted")
    selected: dict[str, str] = {}
    for role in sorted(payloads):
        value, media_type = payloads[role]
        row = attempt.add_artifact(
            role,
            value,
            media_type=media_type,
            disposition="approved",
            metadata={"environment": "fixture_only"},
        )
        selected[role] = row.sha256
    return (
        attempt.finalize_release(
            selected=selected,
            finalized_at=finalized_at.isoformat(),
        ),
        archive.root,
    )


__all__ = ["fixture_release_archive_receipt"]
