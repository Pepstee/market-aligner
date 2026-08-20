from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from cv_generation.constraints import (
    ARTIOM_GUTU_CV_POLICY,
    CVConstraintError,
    validate_generated_cv,
)


SOURCE_ID = "a" * 64
TITLE = (
    "SCAFAD: A Seven-Layer, Privacy-Preserving, Explainable "
    "Anomaly-Detection Pipeline for Serverless Workloads"
)


def _valid(**changes: object):
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": (
            "AI orchestration, systems design, workflow automation and assurance.",
        ),
        "Projects": ("Built and evaluated reliable automation systems.",),
        "Education": (
            "First-Class BSc (Hons) Computer Science, Birmingham Newman "
            "University, July 2026.",
            f"Dissertation: {TITLE}.",
        ),
    }
    cv_text = (
        "Artiom Gutu\nartiom@example.test | Birmingham, United Kingdom\n\n"
        + "\n\n".join(
            f"{heading}\n" + "\n".join(values)
            for heading, values in sections.items()
        )
        + "\n"
    )
    values: dict[str, object] = {
        "source_id": SOURCE_ID,
        "candidate_name": "Artiom Gutu",
        "candidate_city": "Birmingham, United Kingdom",
        "cv_text": cv_text,
        "cv_sha256": hashlib.sha256(cv_text.encode()).hexdigest(),
        "sections": sections,
        "rendered_pages": (tuple(cv_text.splitlines()),),
        "policy": ARTIOM_GUTU_CV_POLICY,
    }
    values.update(changes)
    if "cv_text" in changes and "cv_sha256" not in changes:
        values["cv_sha256"] = hashlib.sha256(str(values["cv_text"]).encode()).hexdigest()
    return validate_generated_cv(**values)


def test_candidate_policy_accepts_the_ratified_cv_contract() -> None:
    receipt = _valid()
    assert receipt.passed is True
    assert receipt.release_authority is False
    assert receipt.policy_sha256 == ARTIOM_GUTU_CV_POLICY.policy_sha256


@pytest.mark.parametrize(
    ("addition", "message"),
    (
        ("\nCurriculum Vitae\n", "document labels"),
        ("\nCV\n", "document labels"),
        ("\nRight to work in the UK\n", "work-rights"),
    ),
)
def test_forbids_amateur_labels_and_application_declarations(
    addition: str, message: str
) -> None:
    with pytest.raises(CVConstraintError, match=message):
        _valid(cv_text=_base_text() + addition)


def _base_text() -> str:
    return str(_valid.__defaults__) if False else (
        "Artiom Gutu\nartiom@example.test | Birmingham, United Kingdom\n\n"
        "Professional Summary\nAI systems engineer.\n\n"
        "Core Capabilities\nAI orchestration, systems design, workflow automation "
        "and assurance.\n\nProjects\nBuilt and evaluated reliable automation systems.\n\n"
        "Education\nFirst-Class BSc (Hons) Computer Science, Birmingham Newman "
        f"University, July 2026.\nDissertation: {TITLE}.\n"
    )


def test_forbids_day_level_graduation_dates() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, 2 July 2026. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="month and year"):
        _valid(sections=sections)


@pytest.mark.parametrize("city", ("Wolverhampton", "London"))
def test_candidate_location_is_birmingham(city: str) -> None:
    with pytest.raises(CVConstraintError, match="location differs"):
        _valid(candidate_city=city)


def test_requires_the_real_dissertation_title() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation.",),
        "Education": ("BSc Computer Science, July 2026. SCAFAD dissertation.",),
    }
    with pytest.raises(CVConstraintError, match="canonical dissertation title"):
        _valid(sections=sections)


def test_formats_and_datastores_cannot_masquerade_as_skills() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("AI orchestration, JSON, SQLite",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="cannot be listed as skills"):
        _valid(sections=sections)


def test_continuation_page_cannot_repeat_candidate_banner() -> None:
    with pytest.raises(CVConstraintError, match="continuation pages"):
        _valid(rendered_pages=(("Artiom Gutu", "page one"), ("Artiom Gutu", "page two")))


def test_receipt_hash_tampering_is_rejected() -> None:
    receipt = _valid()
    with pytest.raises(ValueError, match="hashes"):
        replace(receipt, receipt_sha256="not-a-hash")


@pytest.mark.parametrize(
    "addition",
    (
        "\nHonesty note: this CV was AI-generated.\n",
        "\nBuilt with AI agents under an internal review process.\n",
        "\nMissing skill: Kubernetes.\n",
        "\nI am not experienced with production systems.\n",
    ),
)
def test_forbids_volunteered_rejection_signals(addition: str) -> None:
    with pytest.raises(CVConstraintError, match="rejection signals"):
        _valid(cv_text=_base_text() + addition)


@pytest.mark.parametrize(
    "detail",
    (
        "Nine GCSEs.",
        "DHL operative, 2022.",
        "Earlier front-end website project.",
    ),
)
def test_forbids_stale_or_irrelevant_candidate_detail(detail: str) -> None:
    with pytest.raises(CVConstraintError, match="stale or irrelevant"):
        _valid(cv_text=_base_text() + "\n" + detail)


def test_target_role_cannot_be_presented_as_current_identity() -> None:
    sections = {
        "Professional Summary": ("Junior AI Engineer",),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="current identity"):
        _valid(sections=sections, target_role_title="Junior AI Engineer")


def test_tools_must_support_a_capability_not_replace_one() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("Python, Docker, GitHub, AWS Lambda",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="support a capability"):
        _valid(sections=sections)


def test_tools_are_allowed_as_supporting_experience() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("Workflow automation and systems integration using Python and Docker.",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
    }
    assert _valid(sections=sections).passed is True


@pytest.mark.parametrize(
    "sections",
    (
        {
            "Core Capabilities": ("AI orchestration.",),
            "Professional Summary": ("AI systems engineer.",),
            "Projects": ("Built reliable automation.",),
            "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
        },
        {
            "Professional Summary": ("AI systems engineer.",),
            "Projects": ("Built reliable automation.",),
            "Core Capabilities": ("AI orchestration.",),
            "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
        },
    ),
)
def test_requires_restrained_ats_hierarchy(sections) -> None:
    with pytest.raises(CVConstraintError, match="hierarchy|precede"):
        _valid(sections=sections)
