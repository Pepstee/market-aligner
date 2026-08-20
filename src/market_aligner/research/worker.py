"""Leased research worker; concrete providers run only after the opportunity gate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .models import (
    RESEARCH_ARCHIVE_ROOT_POLICY_SHA256,
    ResearchDossier,
    ResearchEvidenceBinding,
    ResearchTask,
)
from .store import AssessmentStore


class ResearchProvider(Protocol):
    def research(self, task: ResearchTask) -> ResearchDossier: ...


@dataclass(frozen=True)
class ResearchRun:
    status: str
    profile_id: str | None = None
    job_key: str | None = None
    dossier_sha256: str | None = None
    error: str | None = None


class ResearchWorker:
    def __init__(
        self,
        store: AssessmentStore,
        provider: ResearchProvider,
        worker_id: str,
    ) -> None:
        self.store = store
        self.provider = provider
        self.worker_id = worker_id

    def run_one(
        self,
        *,
        profile_id: str | None = None,
        job_key: str | None = None,
        require_refresh_bridge: bool = False,
    ) -> ResearchRun:
        task = self.store.claim_research(
            self.worker_id,
            profile_id=profile_id,
            job_key=job_key,
            require_refresh_bridge=require_refresh_bridge,
        )
        if task is None:
            return ResearchRun("idle")
        try:
            dossier = self.provider.research(task)
            if dossier.profile_id != task.profile_id or dossier.job_key != task.job_key:
                raise ValueError("research provider returned a dossier for a different task")
            evidence = None
            if dossier.schema_version == "market-aligner.employer-dossier.v2":
                materialization = getattr(self.provider, "last_materialization", None)
                if materialization is None:
                    raise ValueError("v2 research provider returned no archive materialization")
                relative = materialization.receipt_path.relative_to(
                    materialization.archive_root
                )
                archive_identity = materialization.archive_root.relative_to(
                    self.store.data_home
                )
                evidence = ResearchEvidenceBinding(
                    dossier_sha256=materialization.dossier_sha256,
                    source_content_sha256=dossier.source_content_sha256 or "",
                    vacancy_snapshot_sha256=dossier.vacancy_snapshot_sha256 or "",
                    promotion_receipt_sha256=dossier.promotion_receipt_sha256 or "",
                    canonical_vacancy_object_sha256=(
                        dossier.canonical_vacancy_object_sha256 or ""
                    ),
                    semantic_receipt_sha256=(
                        materialization.semantic_receipt_sha256
                    ),
                    receipt_file_sha256=materialization.receipt_file_sha256,
                    archive_root_identity=archive_identity.as_posix(),
                    archive_root_policy_sha256=(
                        RESEARCH_ARCHIVE_ROOT_POLICY_SHA256
                    ),
                    receipt_relative_path=relative.as_posix(),
                )
            digest = self.store.complete_research(
                dossier, self.worker_id, evidence=evidence
            )
            return ResearchRun("completed", task.profile_id, task.job_key, digest)
        except Exception as exc:
            self.store.fail_research(
                task.profile_id,
                task.job_key,
                self.worker_id,
                f"{type(exc).__name__}: {exc}",
            )
            return ResearchRun("retry_scheduled", task.profile_id, task.job_key, error=str(exc))
