"""Contracts for the employer-facing framing guard.

Operator doctrine ratified 2026-08-07: a CV and a cover letter are a selection
of positive evidence, not a balanced self-assessment. The guard is fail-closed
on candidate claims and style text, and must never touch employer facts.
"""

from __future__ import annotations

import pytest

from career_automation.application_compiler import (
    assert_employer_facing_framing,
    validate_style_text,
)

# Verbatim from documents that actually reached employers.
REAL_MINIMISING = (
    "I do not present the AI-generated implementation as code that I personally hand-wrote.",
    "Evidence boundary: project implementation used substantial AI-generated code under my direction.",
    "My current gaps are product-specific Zscaler knowledge and commercial cybersecurity pre-sales.",
    "I do not yet have professional experience selling enterprise cybersecurity products.",
    "AI agents generate substantial implementation code; the current generation remains under "
    "commercial hardening rather than being presented as finished production software.",
    "V1 proved unattended multi-agent coordination but exposed the limits of prose-only rules.",
    "I apologise for lacking commercial experience and may be weaker than other applicants.",
    "Claims in this CV are limited to the operator-approved evidence packet.",
    "I worked there without a written employment contract.",
    "The client later abandoned the project.",
    "I validated the result rather than personally implementing every component.",
    "The web acceptance script still required repair.",
    "This is not a separate professional project.",
    "The repository should not be presented as the current production release.",
)

# Strong, evidence-supported claims that must survive untouched.
LEGITIMATE = (
    "Designed and operated a multi-source job-intelligence pipeline with 18 API and feed adapters.",
    "The verified V3 suite reached 3,482 passing tests with four skips and no failures.",
    "Own the requirements, architecture, model routing, governance and acceptance decisions.",
    "Engineered telemetry collection, graph-based analysis, adversarial testing and explainability.",
    "Founded and registered a UK company, defined its service model and recruited its first teacher.",
    "Prospected cold, handled objections and closed face-to-face with unfamiliar customers.",
    "Built a behavioural anomaly-detection system for serverless workloads on AWS Lambda.",
)


@pytest.mark.parametrize("text", REAL_MINIMISING)
def test_real_minimising_text_is_rejected(text: str) -> None:
    with pytest.raises(ValueError):
        assert_employer_facing_framing(text, "factual sentence")


@pytest.mark.parametrize("text", LEGITIMATE)
def test_strong_supported_claims_are_accepted(text: str) -> None:
    assert_employer_facing_framing(text, "factual sentence") is None


@pytest.mark.parametrize("text", REAL_MINIMISING)
def test_style_text_is_guarded_too(text: str) -> None:
    with pytest.raises(ValueError):
        validate_style_text(text)


def test_rejection_explains_itself_and_quotes_the_offending_span() -> None:
    with pytest.raises(ValueError) as excinfo:
        assert_employer_facing_framing("My current gaps are commercial delivery.", "factual sentence")
    message = str(excinfo.value)
    assert "My current gaps" in message
    assert "never its absence" in message
