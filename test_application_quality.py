from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation.application_artifacts import publish_application_artifacts
from career_automation.application_compiler import (
    ApplicationSource,
    DocumentSection,
    StructuredAnswer,
    compile_application_source,
)
from career_automation.application_quality import (
    ApplicationQualityInput,
    QUALITY_POLICY_SHA256,
    build_deterministic_preflight_quality_review,
)
from career_automation.browser_workflows import QualityReviewDisposition
from career_automation.rendering import render_pdf_artifacts
from test_jaa07_independent_acceptance import _sentence, _slot, _source


def _quality_source(
    *,
    job_key: str | None = None,
    vacancy_sha256: str | None = None,
    role_lead: str = "The Software Engineer role matches this evidence.",
    second_fact_text: str = "Built observable services with repeatable verification.",
    sensitive_answer: bool = False,
) -> ApplicationSource:
    base, strategy = _source()
    elements = {row.kind: row for row in strategy.elements}
    cv_facts = [
        row for row in base.facts if row.document_kind == "cv"
    ]
    letter_candidate = next(
        row
        for row in base.facts
        if row.document_kind == "cover_letter" and row.fact_kind == "candidate"
    )
    letter_employer = next(
        row
        for row in base.facts
        if row.document_kind == "cover_letter" and row.fact_kind == "employer"
    )
    answer_fact = next(row for row in base.facts if row.document_kind == "answer")
    second_cv = _sentence(
        elements["cv_emphasis"],
        text=second_fact_text,
        fact_kind="candidate",
        document_kind="cv",
    )
    second_letter = _sentence(
        elements["cover_letter_argument"],
        text=second_fact_text,
        fact_kind="candidate",
        document_kind="cover_letter",
    )
    cv_slot = next(row for row in base.style_slots if row.document_kind == "cv")
    answer_slot = next(
        row for row in base.style_slots if row.document_kind == "answer"
    )
    role_slot = _slot("cover_letter", role_lead)
    cv_sections = tuple(
        DocumentSection(
            row.heading,
            (
                (*row.sentence_ids, second_cv.sentence_id)
                if row.heading == "Experience"
                else row.sentence_ids
            ),
            row.style_slot_ids,
        )
        for row in base.cv_sections
    )
    return compile_application_source(
        strategy=strategy,
        job_key=job_key or base.job_key,
        role_title=base.role_title,
        company_name=base.company_name,
        vacancy_source_identity=base.vacancy_source_identity,
        vacancy_sha256=vacancy_sha256 or base.vacancy_sha256,
        contact=base.contact,
        facts=(
            *cv_facts,
            second_cv,
            letter_candidate,
            second_letter,
            letter_employer,
            answer_fact,
        ),
        style_slots=(cv_slot, role_slot, answer_slot),
        cv_sections=cv_sections,
        letter_sections=(
            DocumentSection(
                "Opening",
                (letter_employer.sentence_id,),
                (role_slot.slot_id,),
            ),
            DocumentSection(
                "Evidence Match",
                (letter_candidate.sentence_id, second_letter.sentence_id),
            ),
            DocumentSection("Company Fit", (letter_employer.sentence_id,)),
            DocumentSection("Close", (letter_candidate.sentence_id,)),
        ),
        answers=(
            StructuredAnswer(
                "delivery-example",
                (
                    "Do you require visa sponsorship?"
                    if sensitive_answer
                    else "Describe a relevant delivery example."
                ),
                (answer_fact.sentence_id,),
                (answer_slot.slot_id,),
            ),
        ),
    )


def _quality_input(tmp_path: Path, source: ApplicationSource) -> ApplicationQualityInput:
    tmp_path.mkdir(parents=True, exist_ok=True)
    artifacts = render_pdf_artifacts(source)
    receipt = publish_application_artifacts(
        source,
        artifacts,
        root=tmp_path / "artifacts",
        repository_root=Path(__file__).resolve().parent,
    )
    return ApplicationQualityInput(
        reviewed_at="2026-08-26T12:00:00Z",
        candidate_authority_sha256=hashlib.sha256(b"candidate-authority").hexdigest(),
        source=source,
        artifacts=artifacts,
        publication_receipt=receipt,
        field_answers_bytes=artifacts.editable.answers_text.encode(),
        form_inventory_bytes=b'{"fields":[],"schema_version":"test.inventory.v1"}\n',
    )


def _codes(review) -> set[str]:
    return {row.code for row in review.issues}


def test_natural_exact_pack_passes_document_policy_with_typed_ats_authority(
    tmp_path: Path,
) -> None:
    review = build_deterministic_preflight_quality_review(
        _quality_input(tmp_path, _quality_source()),
        ats_answer_authority_verified=True,
    )
    assert review.disposition is QualityReviewDisposition.ACCEPTED
    assert review.quality_policy_sha256 == QUALITY_POLICY_SHA256
    assert review.role_targeting_score == 10
    assert review.natural_voice_score == 10
    assert review.cross_application_consistency_score == 10
    assert review.evidence_capture_score == 10
    assert review.ats_answer_authority_verified is True
    assert review.issues == ()


def test_missing_ats_mapping_is_retained_as_a_release_blocker(tmp_path: Path) -> None:
    review = build_deterministic_preflight_quality_review(
        _quality_input(tmp_path, _quality_source())
    )
    assert review.disposition is QualityReviewDisposition.NEEDS_REMEDIATION
    assert _codes(review) == {"ats_answer_authority_missing"}
    assert review.evidence_capture_score == 8


@pytest.mark.parametrize(
    ("source", "expected_code"),
    (
        (
            lambda: _quality_source(
                role_lead="I am excited to apply for the Software Engineer role."
            ),
            "generic_or_ai_prose",
        ),
        (
            lambda: _quality_source(
                second_fact_text="I am currently completing verified engineering work."
            ),
            "stale_education_claim",
        ),
        (lambda: _quality_source(sensitive_answer=True), "sensitive_answer_uses_style_prose"),
    ),
)
def test_deterministic_prose_and_factual_consistency_issues_block_release(
    tmp_path: Path,
    source,
    expected_code: str,
) -> None:
    review = build_deterministic_preflight_quality_review(
        _quality_input(tmp_path, source()),
        ats_answer_authority_verified=True,
    )
    assert review.disposition is QualityReviewDisposition.NEEDS_REMEDIATION
    assert expected_code in _codes(review)


def test_prior_letter_similarity_cannot_be_omitted_from_the_result(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    first = build_deterministic_preflight_quality_review(
        quality_input,
        ats_answer_authority_verified=True,
    )
    repeated = build_deterministic_preflight_quality_review(
        quality_input,
        prior_cover_letter_shingles=(first.cover_letter_shingle_sha256s,),
        ats_answer_authority_verified=True,
    )
    assert repeated.maximum_prior_similarity_bp == 10_000
    assert "prior_cover_letter_too_similar" in _codes(repeated)
    assert repeated.disposition is QualityReviewDisposition.NEEDS_REMEDIATION


def test_artifact_source_receipt_and_answer_substitution_fail_before_review(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    with pytest.raises(ValueError, match="artifact"):
        build_deterministic_preflight_quality_review(
            replace(
                quality_input,
                artifacts=replace(
                    quality_input.artifacts,
                    editable=replace(
                        quality_input.artifacts.editable,
                        cover_letter_text="substituted\n",
                        cover_letter_sha256=hashlib.sha256(b"substituted\n").hexdigest(),
                    ),
                ),
            )
        )
    with pytest.raises(ValueError, match="publication receipt"):
        build_deterministic_preflight_quality_review(
            replace(
                quality_input,
                publication_receipt=replace(
                    quality_input.publication_receipt,
                    receipt_sha256="0" * 64,
                ),
            )
        )
    with pytest.raises(ValueError, match="field answers"):
        build_deterministic_preflight_quality_review(
            replace(quality_input, field_answers_bytes=b"substituted\n")
        )
