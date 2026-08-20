"""Production-only detached recruiter execution and diagnostic admission."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .adversarial_recruiter import (
    POLICY_SHA256,
    PROMPT_SHA256,
    SCHEMA_SHA256,
    RecruiterAssessmentPackage,
    RecruiterAssessmentReceipt,
    verify_recruiter_assessment_receipt,
)
from .adversarial_recruiter_archive import (
    ARCHIVE_RECEIPT_SCHEMA_VERSION,
    ARCHIVE_SCHEMA_VERSION,
    RecruiterDiagnosticArchiveReceipt,
    archive_recruiter_diagnostic,
    verify_recruiter_diagnostic_archive,
)
from .adversarial_recruiter_runtime import (
    PROVIDER_IDENTITY,
    RUNTIME_SCHEMA_VERSION,
    DetachedTransportReceipt,
    run_detached_recruiter_assessment,
)
from .evidence_matching import content_hash


class ProductionRecruiterAssessorError(ValueError):
    """The production recruiter boundary was unsafe or internally inconsistent."""


@dataclass(frozen=True)
class ProductionRecruiterAssessment:
    assessment: RecruiterAssessmentReceipt
    transport: DetachedTransportReceipt
    archive: RecruiterDiagnosticArchiveReceipt
    assessor_configuration_sha256: str
    archive_root: Path

    def __post_init__(self) -> None:
        self.assessment.__post_init__()
        self.transport.__post_init__()
        self.archive.__post_init__()
        if (
            self.assessment.receipt_sha256
            != self.archive.assessment_receipt_sha256
            or self.transport.receipt_sha256
            != self.archive.transport_receipt_sha256
            or dict(self.assessment.package_hashes)
            != dict(self.archive.package_hashes)
            or self.archive_root.is_symlink()
            or not self.archive_root.is_absolute()
        ):
            raise ProductionRecruiterAssessorError(
                "production recruiter receipt chain differs"
            )


class ProductionDetachedRecruiterAssessor:
    """Single-use production seam around the existing detached Codex runtime."""

    environment = "production"

    def __init__(
        self,
        *,
        model: str,
        archive_root: Path,
        repository_root: Path,
        cli_timeout_seconds: float = 120.0,
        codex_binary: str,
    ) -> None:
        if not model.strip():
            raise ProductionRecruiterAssessorError(
                "production recruiter requires an explicit model"
            )
        repository = repository_root.resolve(strict=True)
        archive = archive_root.resolve()
        if archive == repository or repository in archive.parents:
            raise ProductionRecruiterAssessorError(
                "production recruiter archive must be outside the repository"
            )
        if not isinstance(codex_binary, str) or not codex_binary:
            raise ProductionRecruiterAssessorError(
                "production recruiter requires an explicit Codex executable"
            )
        binary_path = Path(codex_binary)
        if (
            not binary_path.is_absolute()
            or binary_path.is_symlink()
            or not binary_path.is_file()
            or not stat.S_ISREG(binary_path.stat().st_mode)
            or not os.access(binary_path, os.X_OK)
        ):
            raise ProductionRecruiterAssessorError(
                "production recruiter requires an explicit regular Codex executable"
            )
        binary = binary_path.resolve(strict=True)
        if binary == repository or repository in binary.parents:
            raise ProductionRecruiterAssessorError(
                "production recruiter executable must be outside the repository"
            )
        binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.model = model.strip()
        self.archive_root = archive
        self.cli_timeout_seconds = float(cli_timeout_seconds)
        if not 1 <= self.cli_timeout_seconds <= 600:
            raise ProductionRecruiterAssessorError(
                "production recruiter timeout is outside policy"
            )
        self.codex_binary = str(binary)
        self._configuration = {
            "archive_manifest_schema": ARCHIVE_SCHEMA_VERSION,
            "archive_receipt_schema": ARCHIVE_RECEIPT_SCHEMA_VERSION,
            "archive_root": str(archive),
            "archive_root_sha256": content_hash({"absolute_path": str(archive)}),
            "binary_path": str(binary),
            "binary_sha256": binary_sha256,
            "cli_timeout_seconds": self.cli_timeout_seconds,
            "environment": "production",
            "model": self.model,
            "model_sha256": content_hash({"model": self.model}),
            "policy_sha256": POLICY_SHA256,
            "prompt_sha256": PROMPT_SHA256,
            "provider_identity": PROVIDER_IDENTITY,
            "runtime_schema": RUNTIME_SCHEMA_VERSION,
            "schema_sha256": SCHEMA_SHA256,
            "schema_version": "jaa.production-detached-recruiter-config.v1",
        }
        self.configuration_sha256 = content_hash(self._configuration)
        self._used = False

    def configuration_document(self) -> dict[str, object]:
        return dict(self._configuration)

    def assess(
        self, package: RecruiterAssessmentPackage
    ) -> ProductionRecruiterAssessment:
        if self._used:
            raise ProductionRecruiterAssessorError(
                "production recruiter assessor is single-use"
            )
        self._used = True
        binary_path = Path(self.codex_binary)
        if (
            binary_path.is_symlink()
            or not binary_path.is_file()
            or hashlib.sha256(binary_path.read_bytes()).hexdigest()
            != self._configuration["binary_sha256"]
        ):
            raise ProductionRecruiterAssessorError(
                "production recruiter executable changed after configuration"
            )
        run = run_detached_recruiter_assessment(
            package,
            model=self.model,
            cli_timeout_seconds=self.cli_timeout_seconds,
            codex_binary=self.codex_binary,
        )
        if not isinstance(run.transport, DetachedTransportReceipt):
            raise ProductionRecruiterAssessorError(
                "production recruiter produced no detached transport receipt"
            )
        if (
            run.transport.binary_sha256 != self._configuration["binary_sha256"]
            or run.transport.model_identity != self.model
            or run.transport.provider_identity != PROVIDER_IDENTITY
        ):
            raise ProductionRecruiterAssessorError(
                "detached recruiter transport differs from production configuration"
            )
        verify_recruiter_assessment_receipt(run.assessment, package)
        archived = archive_recruiter_diagnostic(
            run.assessment, run.transport, root=self.archive_root
        )
        replayed = verify_recruiter_diagnostic_archive(
            archived, root=self.archive_root
        )
        if (
            replayed.assessment.document() != run.assessment.document()
            or replayed.transport.document() != run.transport.document()
        ):
            raise ProductionRecruiterAssessorError(
                "offline recruiter archive replay differs from the live diagnostic"
            )
        return ProductionRecruiterAssessment(
            assessment=run.assessment,
            transport=run.transport,
            archive=archived,
            assessor_configuration_sha256=self.configuration_sha256,
            archive_root=self.archive_root,
        )


__all__ = [
    "ProductionDetachedRecruiterAssessor",
    "ProductionRecruiterAssessment",
    "ProductionRecruiterAssessorError",
]
