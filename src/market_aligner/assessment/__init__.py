"""Eligibility, opportunity, evidence alignment, fit, and calibration boundaries."""

from .eligibility import EligibilityDecision, EligibilityInput, EligibilityPolicy, assess_eligibility
from .scoring import FitStatus, ScoreResult, ScoringParams, score

__all__ = [
    "EligibilityDecision",
    "EligibilityInput",
    "EligibilityPolicy",
    "FitStatus",
    "ScoreResult",
    "ScoringParams",
    "assess_eligibility",
    "score",
]
