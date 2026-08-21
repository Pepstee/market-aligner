"""Candidate-receipt extension of the shared certified release authority."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .application_sanity_review import SanityReviewPackage, package_from_application
from .browser_executor import ReleaseExecutionAuthority
from .candidate_release_gate import CandidateAuthorityReleaseGate, WorkableReleaseBinding


@dataclass(frozen=True)
class CandidateReleaseExecutionAuthority(ReleaseExecutionAuthority):
    """Bind full candidate-decision requirements without changing the collector."""

    vacancy_requirements: tuple[str, ...]
    workable_release_binding: WorkableReleaseBinding | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.gate, CandidateAuthorityReleaseGate):
            raise TypeError("candidate release requires the candidate authority gate")
        if self.gate.vacancy_requirements != self.vacancy_requirements:
            raise ValueError(
                "release vacancy requirements differ from candidate gate authority"
            )
        super().__post_init__()
        if self.ats_provider == "workable":
            binding = self.workable_release_binding
            expected_roles = (
                ()
                if type(binding) is not WorkableReleaseBinding
                else tuple(row.document_kind for row in binding.upload_bindings)
            )
            expected_fields = (
                ()
                if type(binding) is not WorkableReleaseBinding
                else tuple(
                    (row.document_kind, row.field_name)
                    for row in binding.upload_bindings
                )
            )
            if (type(binding) is not WorkableReleaseBinding
                    or self.application_url != binding.application_url
                    or self.artifacts.cv_pdf.pdf_sha256 != binding.cv_pdf_sha256
                    or self.artifacts.cover_letter_pdf.pdf_sha256 != binding.cover_letter_pdf_sha256
                    or self.document_assurance_receipts[0].receipt_sha256 != binding.cv_assurance_receipt_sha256
                    or self.document_assurance_receipts[1].receipt_sha256 != binding.cover_letter_assurance_receipt_sha256
                    or self.attached_roles != expected_roles
                    or self.upload_field_names != expected_fields):
                raise ValueError("candidate Workable execution binding is incomplete")
        elif self.workable_release_binding is not None:
            raise ValueError("Workable binding cannot authorize another provider")

    @property
    def release_manifest_sha256(self) -> str:
        return self.release_token.split(".")[1]

    @property
    def token_sha256(self) -> str:
        return hashlib.sha256(self.release_token.encode()).hexdigest()

    def consume(self) -> object:
        return self.gate.consume_release_token(
            release_token=self.release_token,
            source=self.source,
            artifacts=self.artifacts,
            contact=self.contact,
            questions=self.questions,
            artifact_root=self.artifact_root,
            repository_root=self.repository_root,
            jurisdiction=self.jurisdiction,
            contract_type=self.contract_type,
            consumed_at=self.consumed_at,
        )

    def sanity_review_package(self) -> SanityReviewPackage:
        return package_from_application(
            source=self.source,
            artifacts=self.artifacts,
            questions=self.questions,
            vacancy_requirements=self.vacancy_requirements,
        )


__all__ = ["CandidateReleaseExecutionAuthority"]
