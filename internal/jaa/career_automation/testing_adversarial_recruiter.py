"""Hermetic result fixture for the detached recruiter diagnostic only.

This lives separately from ``testing_sanity_review`` because the recruiter
assessment is non-authoritative diagnostic output, while final sanity can block
release. Recombining their fixtures would recreate the recovered boundary error.
"""

from __future__ import annotations

from .adversarial_recruiter import RESULT_SCHEMA_VERSION


def fixture_recruiter_result(
    *,
    fit_percent: int = 52,
    fit_low: int = 40,
    fit_high: int = 65,
    overall_verdict: str = "plausible_fit",
) -> dict[str, object]:
    """Return a fresh, complete v2 diagnostic result for hermetic tests."""

    ats_reaction = {
        "progression_probability_percent": 60,
        "verdict": "borderline",
        "reasons": ["Relevant evidence is present but deliberately limited."],
    }
    recruiter_reaction = {
        "progression_probability_percent": 50,
        "verdict": "borderline",
        "reasons": ["The visible evidence supports consideration, with gaps."],
    }
    hiring_manager_reaction = {
        "progression_probability_percent": 40,
        "verdict": "borderline",
        "reasons": ["Role-depth evidence remains incomplete."],
    }
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "calibration_status": "uncalibrated",
        "fit_percent": fit_percent,
        "fit_range_percent": {"low": fit_low, "high": fit_high},
        "stage_progression_percent": {
            "ats_screen": 60,
            "recruiter_screen": 50,
            "hiring_manager_review": 40,
            "interview_invitation": 30,
        },
        "overall_verdict": overall_verdict,
        "ats_reaction": ats_reaction,
        "human_reaction": recruiter_reaction,
        "hiring_manager_reaction": hiring_manager_reaction,
        "strengths": [
            {
                "location": "cv:projects",
                "assessment": "Relevant project evidence.",
                "outward_evidence_refs": ["cv:char:0:1"],
            }
        ],
        "risks": [
            {
                "category": "experience",
                "severity": "medium",
                "location": "cv:experience",
                "assessment": "Comparable production depth is not fully demonstrated.",
                "outward_evidence_refs": ["cv:char:0:1"],
            }
        ],
        "evidence_gaps": [
            {
                "requirement": "production depth",
                "impact": "medium",
                "explanation": "The employer-visible package contains limited scale evidence.",
            }
        ],
        "uncertainty_drivers": ["No calibrated outcome history is available."],
        "application_improvements": [
            {
                "rank": 1,
                "target": "cv",
                "recommendation": "Lead with the closest role-relevant evidence.",
                "expected_effect": "Makes relevance visible during screening.",
                "support_required": False,
                "outward_evidence_refs": ["cv:char:0:1"],
            }
        ],
        "profile_improvements": [
            {
                "category": "experience",
                "recommendation": "Build evidence of operating a deployed service.",
                "time_horizon": "months",
                "expected_effect": "Addresses the largest evidence gap.",
            }
        ],
    }


__all__ = ["fixture_recruiter_result"]
