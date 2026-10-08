from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from cv_generation.constraints import (
    ARTIOM_GUTU_CV_POLICY,
    CVConstraintError,
    validate_generated_cv,
    validate_pre_editorial_source,
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
        "Artiom Gutu\nartiom@example.test | Birmingham\n\n"
        + "\n\n".join(
            f"{heading}\n" + "\n".join(values)
            for heading, values in sections.items()
        )
        + "\n"
    )
    values: dict[str, object] = {
        "source_id": SOURCE_ID,
        "candidate_name": "Artiom Gutu",
        "candidate_city": "Birmingham",
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
        "Artiom Gutu\nartiom@example.test | Birmingham\n\n"
        "Professional Summary\nAI systems engineer.\n\n"
        "Core Capabilities\nAI orchestration, systems design, workflow automation "
        "and assurance.\n\nProjects\nBuilt and evaluated reliable automation systems.\n\n"
        "Education\nFirst-Class BSc (Hons) Computer Science, Birmingham Newman "
        f"University, July 2026.\nDissertation: {TITLE}.\n"
    )


def _pre_editorial_source(text: str = "This sample device has limited endurance."):
    cv_text = f"Core Capabilities\n{text}\n"
    return {
        "source_id": SOURCE_ID,
        "cv_text": cv_text,
        "cv_sha256": hashlib.sha256(cv_text.encode("utf-8")).hexdigest(),
        "sections": {"Core Capabilities": (text,)},
    }


def test_pre_editorial_source_receipt_preserves_limits_without_style_claims() -> None:
    receipt = validate_pre_editorial_source(**_pre_editorial_source())

    assert receipt["schema_version"] == "pre-editorial-source-envelope.v1"
    assert receipt["validation_scope"] == "source_integrity_only"
    assert receipt["passed"] is True
    assert receipt["release_authority"] is False
    assert receipt["final_style_validated"] is False
    assert "limited endurance" not in receipt
    assert len(receipt["sections_sha256"]) == 64
    assert len(receipt["policy_sha256"]) == 64
    assert len(receipt["receipt_sha256"]) == 64


def test_pre_editorial_receipt_is_deterministic_and_binds_section_order() -> None:
    values = _pre_editorial_source("Café evidence remains qualified.")
    first = validate_pre_editorial_source(**values)
    repeated = validate_pre_editorial_source(**values)
    reordered = validate_pre_editorial_source(
        source_id=SOURCE_ID,
        cv_text="First line.\nSecond line.\n",
        cv_sha256=hashlib.sha256(b"First line.\nSecond line.\n").hexdigest(),
        sections={"Second": ("Second line.",), "First": ("First line.",)},
    )
    ordered = validate_pre_editorial_source(
        source_id=SOURCE_ID,
        cv_text="First line.\nSecond line.\n",
        cv_sha256=hashlib.sha256(b"First line.\nSecond line.\n").hexdigest(),
        sections={"First": ("First line.",), "Second": ("Second line.",)},
    )

    assert first == repeated
    assert reordered["sections_sha256"] != ordered["sections_sha256"]
    assert reordered["receipt_sha256"] != ordered["receipt_sha256"]


@pytest.mark.parametrize(
    "changes",
    (
        {"source_id": "A" * 64},
        {"cv_sha256": "A" * 64},
        {"cv_sha256": "0" * 64},
        {"cv_text": ""},
        {"cv_text": "not utf-8: \ud800"},
        {"cv_text": "contains\x00nul"},
    ),
)
def test_pre_editorial_source_rejects_invalid_or_mismatched_source(changes) -> None:
    values = _pre_editorial_source()
    values.update(changes)
    with pytest.raises(ValueError, match="^pre-editorial source envelope"):
        validate_pre_editorial_source(**values)


@pytest.mark.parametrize(
    "sections",
    (
        {},
        {" Core Capabilities": ("Line.",)},
        {"Core\nCapabilities": ("Line.",)},
        {"Core Capabilities": []},
        {"Core Capabilities": ()},
        {"Core Capabilities": ("Absent line.",)},
        {"Core Capabilities": ("Line.\nOther.",)},
    ),
)
def test_pre_editorial_source_rejects_malformed_sections(sections) -> None:
    cv_text = "Core Capabilities\nLine.\n"
    with pytest.raises(ValueError, match="^pre-editorial source envelope"):
        validate_pre_editorial_source(
            source_id=SOURCE_ID,
            cv_text=cv_text,
            cv_sha256=hashlib.sha256(cv_text.encode()).hexdigest(),
            sections=sections,
        )


def test_pre_editorial_source_rejects_surrogates_and_accepts_unicode() -> None:
    valid = _pre_editorial_source("Café experience is bounded.")
    assert validate_pre_editorial_source(**valid)["passed"] is True

    values = _pre_editorial_source()
    values["sections"] = {"Bad\ud800": ("This sample device has limited endurance.",)}
    with pytest.raises(ValueError, match="^pre-editorial source envelope input is invalid$"):
        validate_pre_editorial_source(**values)


def test_pre_editorial_source_does_not_mutate_sections() -> None:
    values = _pre_editorial_source()
    original = {key: tuple(lines) for key, lines in values["sections"].items()}

    validate_pre_editorial_source(**values)

    assert values["sections"] == original


def test_pre_editorial_source_rejects_string_container_and_line_subclasses() -> None:
    class TextSubclass(str):
        pass

    class DictSubclass(dict):
        pass

    class TupleSubclass(tuple):
        pass

    source = _pre_editorial_source()
    cases = (
        {**source, "source_id": TextSubclass(SOURCE_ID)},
        {**source, "cv_text": TextSubclass(source["cv_text"])},
        {**source, "sections": DictSubclass(source["sections"])},
        {
            **source,
            "sections": {
                "Core Capabilities": TupleSubclass(source["sections"]["Core Capabilities"])
            },
        },
        {
            **source,
            "sections": {
                TextSubclass("Core Capabilities"): source["sections"]["Core Capabilities"]
            },
        },
        {
            **source,
            "sections": {
                "Core Capabilities": (
                    TextSubclass(source["sections"]["Core Capabilities"][0]),
                )
            },
        },
    )

    for values in cases:
        with pytest.raises(ValueError, match="^pre-editorial source envelope"):
            validate_pre_editorial_source(**values)


def test_pre_editorial_integrity_receipt_does_not_replace_final_cv_gate() -> None:
    text = "AI-generated"
    integrity = validate_pre_editorial_source(**_pre_editorial_source(text))

    assert integrity["passed"] is True
    with pytest.raises(CVConstraintError, match="rejection signals"):
        _valid(cv_text=_base_text() + "\nAI-generated\n")


def test_forbids_day_level_graduation_dates() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, 2 July 2026. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="month and year"):
        _valid(sections=sections)


@pytest.mark.parametrize(
    "city",
    (
        "Wolverhampton",
        "Wolverhampton, United Kingdom",
        "London",
        "Birmingham, United Kingdom",
    ),
)
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


@pytest.mark.parametrize(
    "addition",
    (
        "\nEligible to work in the UK.\n",
        "\nVisa not required.\n",
        "\nNo sponsorship needed.\n",
        "\nUnrestricted employment in the United Kingdom.\n",
        "\nI do not require sponsorship.\n",
        "\nPermission to work in the UK.\n",
    ),
)
def test_work_rights_paraphrases_cannot_bypass_policy(addition: str) -> None:
    with pytest.raises(CVConstraintError, match="work-rights"):
        _valid(cv_text=_base_text() + addition)


@pytest.mark.parametrize("label", ("Résumé", "Curriculum-Vitae", "Curriculum‑Vitae", "Curriculum Vitæ", "C.V.", "Artiom Gutu - Résumé"))
def test_polished_document_labels_remain_forbidden(label: str) -> None:
    with pytest.raises(CVConstraintError, match="document labels"):
        _valid(cv_text=label + "\n" + _base_text())


@pytest.mark.parametrize(
    "summary",
    (
        "Junior AI Engineer focused on automation.",
        "Junior AI Engineer with strong systems skills.",
    ),
)
def test_target_role_identity_paraphrases_are_rejected(summary: str) -> None:
    sections = {
        "Professional Summary": (summary,),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="current identity"):
        _valid(sections=sections, target_role_title="Junior AI Engineer")


@pytest.mark.parametrize(
    "addition",
    (
        "\nAgent-assisted implementation with human review.\n",
        "\nDeveloped using coding agents.\n",
        "\nLLM-produced project code.\n",
    ),
)
def test_euphemistic_ai_disclosures_are_rejected(addition: str) -> None:
    with pytest.raises(CVConstraintError, match="rejection signals"):
        _valid(cv_text=_base_text() + addition)


def test_tool_salad_cannot_hide_behind_capability_label() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("Engineering: Python | Docker | GitHub | AWS Lambda",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="support a capability"):
        _valid(sections=sections)


@pytest.mark.parametrize("summary", ("Motivated professional.", "Results-driven engineer."))
def test_generic_summary_filler_is_rejected(summary: str) -> None:
    sections = {
        "Professional Summary": (summary,),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="generic professional-summary"):
        _valid(sections=sections)


def test_old_role_without_year_is_still_irrelevant() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation.",),
        "Experience": ("Translator and interpreter for a charity.",),
        "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="irrelevant historic experience"):
        _valid(sections=sections)


def test_old_year_is_rejected_only_when_used_as_experience() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation using a dataset spanning 2022 to 2026.",),
        "Education": (f"BSc Computer Science, July 2026. Dissertation: {TITLE}.",),
    }
    assert _valid(sections=sections).passed is True
    sections["Experience"] = ("Customer-service assistant, 2022.",)
    with pytest.raises(CVConstraintError, match="irrelevant historic experience"):
        _valid(sections=sections)


def test_generic_dissertation_line_cannot_hide_beside_real_title() -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation.",),
        "Education": (
            "BSc Computer Science, July 2026.",
            "Dissertation: anomaly detection in the cloud.",
            f"Dissertation: {TITLE}.",
        ),
    }
    with pytest.raises(CVConstraintError, match="generic or alternate dissertation"):
        _valid(sections=sections)


@pytest.mark.parametrize("date", ("2nd July 2026", "02/07/2026"))
def test_day_level_date_variants_are_rejected(date: str) -> None:
    sections = {
        "Professional Summary": ("AI systems engineer.",),
        "Core Capabilities": ("AI orchestration and systems design.",),
        "Projects": ("Built reliable automation.",),
        "Education": (f"BSc Computer Science, {date}. Dissertation: {TITLE}.",),
    }
    with pytest.raises(CVConstraintError, match="month and year"):
        _valid(sections=sections)


def test_conflicting_location_cannot_hide_beside_birmingham() -> None:
    with pytest.raises(CVConstraintError, match="conflicting candidate location"):
        _valid(cv_text=_base_text() + "\nBased in Wolverhampton.\n")
