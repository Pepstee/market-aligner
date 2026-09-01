"""Candidate-receipt extension of the shared certified release authority."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from .application_sanity_review import (
    SanityReviewPackage,
    VacancyReviewMaterial,
    package_from_application,
)
from .application_quality import (
    ApplicationQualityInput,
    build_deterministic_preflight_quality_review,
)
from .application_quality_contracts import (
    ApplicationPreflightQualityReview,
    QualityReviewDisposition,
)
from .ats_application_authority import (
    AtsApplicationAuthority,
    verify_ats_application_authority,
)
from .application_archive import selected_archive_hashes
from .evidence_matching import canonical_json
from .browser_executor import ReleaseExecutionAuthority
from .candidate_release_gate import (
    CandidateAuthorityReleaseGate,
    WorkableReleaseBinding,
)


@dataclass(frozen=True)
class CandidateReleaseExecutionAuthority(ReleaseExecutionAuthority):
    """Bind full candidate-decision requirements without changing the collector."""

    vacancy_requirements: tuple[str, ...]
    ats_application_authority: AtsApplicationAuthority
    quality_input: ApplicationQualityInput
    quality_review: ApplicationPreflightQualityReview
    workable_release_binding: WorkableReleaseBinding | None = None
    vacancy_review_material: VacancyReviewMaterial = field(kw_only=True)

    def __post_init__(self) -> None:
        if not isinstance(self.gate, CandidateAuthorityReleaseGate):
            raise TypeError("candidate release requires the candidate authority gate")
        self.vacancy_review_material.__post_init__()
        if (
            self.vacancy_review_material.raw_listing_sha256
            != self.source.vacancy_sha256
        ):
            raise ValueError("candidate review listing differs from application source")
        if self.gate.vacancy_requirements != self.vacancy_requirements:
            raise ValueError(
                "release vacancy requirements differ from candidate gate authority"
            )
        if (
            self.quality_input.ats_application_authority
            != self.ats_application_authority
        ):
            raise ValueError("quality input differs from exact ATS authority")
        verify_ats_application_authority(
            self.ats_application_authority,
            candidate_authority_sha256=(self.quality_input.candidate_authority_sha256),
            source=self.source,
            artifacts=self.artifacts,
            publication_receipt=self.quality_input.publication_receipt,
        )
        if (
            build_deterministic_preflight_quality_review(self.quality_input)
            != self.quality_review
            or self.quality_review.disposition is not QualityReviewDisposition.ACCEPTED
        ):
            raise ValueError("candidate release lacks accepted deterministic quality")
        super().__post_init__()
        selected = selected_archive_hashes(
            self.archive_receipt,
            root=self.archive_root,
            repository_root=self.repository_root,
        )
        required = {
            "assurance.ats_application_authority": hashlib.sha256(
                (
                    canonical_json(self.ats_application_authority.document()) + "\n"
                ).encode()
            ).hexdigest(),
            "assurance.ats_inventory": self.ats_application_authority.inventory_sha256,
            "assurance.ats_answers": self.ats_application_authority.answer_sha256,
            "assurance.application_quality": hashlib.sha256(
                (canonical_json(self.quality_review.to_dict()) + "\n").encode()
            ).hexdigest(),
        }
        required.update(
            {
                f"assurance.editorial.{row.skill_name.replace('-', '_')}": hashlib.sha256(
                    (canonical_json(row.to_dict()) + "\n").encode()
                ).hexdigest()
                for row in self.quality_input.editorial_skill_reviews
            }
        )
        if any(selected.get(role) != digest for role, digest in required.items()):
            raise ValueError("candidate release archive lacks exact quality authority")
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
            if (
                type(binding) is not WorkableReleaseBinding
                or self.application_url != binding.application_url
                or self.artifacts.cv_pdf.pdf_sha256 != binding.cv_pdf_sha256
                or self.artifacts.cover_letter_pdf.pdf_sha256
                != binding.cover_letter_pdf_sha256
                or self.document_assurance_receipts[0].receipt_sha256
                != binding.cv_assurance_receipt_sha256
                or self.document_assurance_receipts[1].receipt_sha256
                != binding.cover_letter_assurance_receipt_sha256
                or self.attached_roles != expected_roles
                or self.upload_field_names != expected_fields
            ):
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
            vacancy_review_material=self.vacancy_review_material,
        )

    def verify_employer_facing_receipts(
        self, *, verified_at: datetime | None = None
    ) -> None:
        """Recompute deterministic quality immediately before certified click."""
        if (
            build_deterministic_preflight_quality_review(self.quality_input)
            != self.quality_review
            or self.quality_review.disposition is not QualityReviewDisposition.ACCEPTED
        ):
            raise ValueError("candidate release quality authority no longer verifies")
        super().verify_employer_facing_receipts(verified_at=verified_at)


__all__ = ["CandidateReleaseExecutionAuthority"]
