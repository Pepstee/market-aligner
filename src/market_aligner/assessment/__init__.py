"""Eligibility, opportunity, evidence alignment, fit, and calibration boundaries."""

from .eligibility import EligibilityDecision, EligibilityInput, EligibilityPolicy, assess_eligibility
from .geography import (
    GeographyMatch,
    LocationFacts,
    SelectionBlocked,
    SelectionDecision,
    SelectionPolicy,
    classify_geography,
    decide_selection,
    rank_selected,
    selection_sort_key,
)
from .scoring import FitStatus, ScoreResult, ScoringParams, score

__all__ = [
    "EligibilityDecision",
    "EligibilityInput",
    "EligibilityPolicy",
    "FitStatus",
    "GeographyMatch",
    "LocationFacts",
    "ScoreResult",
    "ScoringParams",
    "SelectionBlocked",
    "SelectionDecision",
    "SelectionPolicy",
    "assess_eligibility",
    "classify_geography",
    "decide_selection",
    "rank_selected",
    "score",
    "selection_sort_key",
]
