"""Public construction API for the CV-generation module."""

from career_automation.candidate_application_factory import (
    CandidateApplicationPackage,
    GenerationRevisionWriter,
    build_candidate_application_package,
)

__all__ = [
    "CandidateApplicationPackage",
    "GenerationRevisionWriter",
    "build_candidate_application_package",
]
