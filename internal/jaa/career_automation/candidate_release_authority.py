"""Candidate-receipt extension of the shared certified release authority."""

from __future__ import annotations

from dataclasses import dataclass

from .application_sanity_review import SanityReviewPackage, package_from_application
from .browser_executor import ReleaseExecutionAuthority
from .candidate_release_gate import CandidateAuthorityReleaseGate


@dataclass(frozen=True)
class CandidateReleaseExecutionAuthority(ReleaseExecutionAuthority):
    """Bind full candidate-decision requirements without changing the collector."""

    vacancy_requirements: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.gate, CandidateAuthorityReleaseGate):
            raise TypeError("candidate release requires the candidate authority gate")
        if self.gate.vacancy_requirements != self.vacancy_requirements:
            raise ValueError(
                "release vacancy requirements differ from candidate gate authority"
            )
        super().__post_init__()

    def sanity_review_package(self) -> SanityReviewPackage:
        return package_from_application(
            source=self.source,
            artifacts=self.artifacts,
            questions=self.questions,
            vacancy_requirements=self.vacancy_requirements,
        )


__all__ = ["CandidateReleaseExecutionAuthority"]
