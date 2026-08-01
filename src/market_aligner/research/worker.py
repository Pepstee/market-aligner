"""Leased research worker; concrete providers run only after the opportunity gate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .models import ResearchDossier, ResearchTask
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

    def run_one(self) -> ResearchRun:
        task = self.store.claim_research(self.worker_id)
        if task is None:
            return ResearchRun("idle")
        try:
            dossier = self.provider.research(task)
            if dossier.profile_id != task.profile_id or dossier.job_key != task.job_key:
                raise ValueError("research provider returned a dossier for a different task")
            digest = self.store.complete_research(dossier, self.worker_id)
            return ResearchRun("completed", task.profile_id, task.job_key, digest)
        except Exception as exc:
            self.store.fail_research(
                task.profile_id,
                task.job_key,
                self.worker_id,
                f"{type(exc).__name__}: {exc}",
            )
            return ResearchRun("retry_scheduled", task.profile_id, task.job_key, error=str(exc))
