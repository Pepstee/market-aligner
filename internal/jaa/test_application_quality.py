from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from unittest import mock

import pytest

from llm.client import LLMClient, MockBackend

import career_automation.application_quality as application_quality
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
    build_editorial_skill_review_receipt,
    build_deterministic_preflight_quality_review,
    run_pinned_editorial_skill_reviews,
)
from career_automation.ats_application_authority import (
    AtsFieldPlan,
    AtsFormInventory,
    AtsObservedField,
    build_ats_application_authority,
)
from career_automation.application_quality_contracts import (
    ApplicationQualityIssue,
    QualityIssueSeverity,
    QualityReviewDisposition,
)
from career_automation.rendering import render_pdf_artifacts
from test_jaa07_independent_acceptance import _sentence, _slot, _source


class _FixtureCodexBackend(MockBackend):
    name = "codex_cli"

    def complete(self, system: str, user: str, temperature: float):
        response = super().complete(system, user, temperature)
        response.model = "codex-default"
        return response


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


def _quality_input_with_ats(
    tmp_path: Path,
    source: ApplicationSource,
) -> ApplicationQualityInput:
    quality_input = _quality_input(tmp_path, source)
    inventory = AtsFormInventory(
        provider="fixture",
        application_url="https://jobs.example.test/application/quality",
        captured_at=quality_input.reviewed_at,
        page_snapshot_sha256="1" * 64,
        screenshot_sha256s=("2" * 64,),
        fields=(
            AtsObservedField("full_name", "text", "Full name", True, True),
            AtsObservedField(
                "delivery",
                "textarea",
                "Describe a relevant delivery example",
                True,
                True,
            ),
            AtsObservedField("cv", "file", "CV", True, True),
            AtsObservedField(
                "robot_check",
                "hidden",
                "",
                False,
                False,
                automation_role="honeypot",
            ),
        ),
    )
    authority = build_ats_application_authority(
        reviewed_at=quality_input.reviewed_at,
        candidate_authority_sha256=quality_input.candidate_authority_sha256,
        source=source,
        artifacts=quality_input.artifacts,
        publication_receipt=quality_input.publication_receipt,
        inventory=inventory,
        reviewed_inventory=replace(
            inventory,
            captured_at="2026-08-26T12:00:00Z",
            page_snapshot_sha256="3" * 64,
            screenshot_sha256s=("4" * 64,),
            fields=(
                replace(
                    inventory.fields[0],
                    current_value=source.contact.full_name,
                ),
                replace(
                    inventory.fields[1],
                    current_value=(
                        "A concise example follows.\n"
                        "Delivered reliable services with tested evidence."
                    ),
                ),
                replace(
                    inventory.fields[2],
                    current_value=quality_input.artifacts.cv_pdf.pdf_sha256,
                ),
                inventory.fields[3],
            ),
        ),
        plans=(
            AtsFieldPlan("full_name", "fill", "contact.full_name"),
            AtsFieldPlan("delivery", "fill", "answer.delivery-example"),
            AtsFieldPlan("cv", "upload", "artifact.cv"),
            AtsFieldPlan("robot_check", "omit", "none"),
        ),
    )
    return _with_editorial_reviews(replace(
        quality_input,
        field_answers_bytes=authority.answer_bytes,
        form_inventory_bytes=authority.inventory_bytes,
        ats_application_authority=authority,
    ))


def _with_editorial_reviews(
    quality_input: ApplicationQualityInput,
) -> ApplicationQualityInput:
    first = build_editorial_skill_review_receipt(
        quality_input,
        skill_name="resume-cover-letter",
        provider="codex_cli",
        model="codex-default",
    )
    second = build_editorial_skill_review_receipt(
        quality_input,
        skill_name="humanizer",
        provider="codex_cli",
        model="codex-default",
    )
    return replace(quality_input, editorial_skill_reviews=(first, second))


def _codes(review) -> set[str]:
    return {row.code for row in review.issues}


def test_natural_exact_pack_passes_document_policy_with_typed_ats_authority(
    tmp_path: Path,
) -> None:
    review = build_deterministic_preflight_quality_review(
        _quality_input_with_ats(tmp_path, _quality_source()),
    )
    assert review.disposition is QualityReviewDisposition.ACCEPTED
    assert review.quality_policy_sha256 == QUALITY_POLICY_SHA256
    assert review.role_targeting_score == 10
    assert review.natural_voice_score == 10
    assert review.cross_application_consistency_score == 10
    assert review.evidence_capture_score == 10
    assert review.ats_answer_authority_verified is True
    assert review.editorial_skill_reviews_verified is True
    assert len(review.editorial_skill_review_sha256s) == 2
    assert review.issues == ()


def test_missing_ats_mapping_is_retained_as_a_release_blocker(tmp_path: Path) -> None:
    review = build_deterministic_preflight_quality_review(
        _with_editorial_reviews(_quality_input(tmp_path, _quality_source()))
    )
    assert review.disposition is QualityReviewDisposition.NEEDS_REMEDIATION
    assert _codes(review) == {"ats_answer_authority_missing"}
    assert review.evidence_capture_score == 8


def test_missing_editorial_skill_reviews_are_detailed_release_blockers(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input_with_ats(tmp_path, _quality_source())
    review = build_deterministic_preflight_quality_review(
        replace(quality_input, editorial_skill_reviews=())
    )
    assert review.disposition is QualityReviewDisposition.NEEDS_REMEDIATION
    assert _codes(review) == {
        "resume_cover_letter_review_missing",
        "humanizer_review_missing",
    }
    assert review.editorial_skill_reviews_verified is False


def test_editorial_skill_review_order_input_and_identity_are_fail_closed(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input_with_ats(tmp_path, _quality_source())
    first, second = quality_input.editorial_skill_reviews
    with pytest.raises(ValueError, match="required order"):
        build_deterministic_preflight_quality_review(
            replace(quality_input, editorial_skill_reviews=(second, first))
        )
    foreign_first = build_editorial_skill_review_receipt(
        replace(quality_input, candidate_authority_sha256="e" * 64),
        skill_name="resume-cover-letter",
        provider="codex_cli",
        model="codex-default",
    )
    with pytest.raises(ValueError, match="exact application pack"):
        build_deterministic_preflight_quality_review(
            replace(
                quality_input,
                editorial_skill_reviews=(foreign_first, second),
            )
        )
    with pytest.raises(ValueError, match="skill identity"):
        replace(first, skill_version="substituted")
    with pytest.raises(ValueError, match="receipt identity"):
        replace(first, receipt_sha256="f" * 64)


def test_blocking_skill_findings_remain_detailed_in_the_preflight_review(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input_with_ats(tmp_path, _quality_source())
    _, humanizer = quality_input.editorial_skill_reviews
    finding = ApplicationQualityIssue(
        code="resume_role_evidence_is_weak",
        severity=QualityIssueSeverity.ERROR,
        category="editorial_skill",
        release_blocking=True,
        enforceable_by_code=True,
        summary="The CV does not foreground the strongest exact role evidence.",
        evidence="The pinned resume review found the approved evidence too deeply nested.",
        remediation="Reorder the approved evidence and obtain both fresh skill receipts.",
    )
    resume_review = build_editorial_skill_review_receipt(
        quality_input,
        skill_name="resume-cover-letter",
        provider="codex_cli",
        model="codex-default",
        decision="block",
        findings=(finding,),
    )
    review = build_deterministic_preflight_quality_review(
        replace(
            quality_input,
            editorial_skill_reviews=(resume_review, humanizer),
        )
    )
    assert review.disposition is QualityReviewDisposition.NEEDS_REMEDIATION
    assert _codes(review) == {finding.code}
    assert review.issues[0].evidence == finding.evidence
    assert review.editorial_skill_reviews_verified is False


def _runtime_client(tmp_path: Path, backend: MockBackend) -> LLMClient:
    return LLMClient(
        backend=backend,
        model="codex-cli-default",
        temperature=0.0,
        max_retries=1,
        cache_enabled=False,
        cache_dir=tmp_path / "cache",
        usage_log=tmp_path / "usage.jsonl",
    )


def test_pinned_editorial_runtime_calls_both_skills_in_order_and_admits_pass(
    tmp_path: Path,
) -> None:
    backend = _FixtureCodexBackend()
    backend.register(
        "editorial_skill_resume_cover_letter_review",
        lambda _payload: {"decision": "pass", "findings": []},
    )
    backend.register(
        "editorial_skill_humanizer_review",
        lambda _payload: {"decision": "pass", "findings": []},
    )
    quality_input = _quality_input_with_ats(tmp_path / "pack", _quality_source())
    quality_input = replace(quality_input, editorial_skill_reviews=())
    with mock.patch.object(
        application_quality,
        "_load_pinned_skill_document",
        side_effect=lambda name, _sha256: f"# {name}\nExact fixture skill.\n".encode(),
    ) as loader:
        reviewed = run_pinned_editorial_skill_reviews(
            quality_input,
            client=_runtime_client(tmp_path, backend),
        )
    assert backend.call_count == 2
    assert [row.skill_name for row in reviewed.editorial_skill_reviews] == [
        "resume-cover-letter",
        "humanizer",
    ]
    assert loader.call_args_list == [
        mock.call(
            "resume-cover-letter",
            "adaa35a36ae0bfa6b1ce14104aebcbfe8a51c65434087056facf4f8f45217b96",
        ),
        mock.call(
            "humanizer",
            "243aecdafecb5e11c2d45e2e088b7876e3f6eee34aa50c53f624d8468039afa8",
        ),
    ]
    review = build_deterministic_preflight_quality_review(reviewed)
    assert review.disposition is QualityReviewDisposition.ACCEPTED
    assert review.editorial_skill_reviews_verified is True


def test_pinned_editorial_runtime_persists_model_findings_as_release_blockers(
    tmp_path: Path,
) -> None:
    backend = _FixtureCodexBackend()
    backend.register(
        "editorial_skill_resume_cover_letter_review",
        lambda _payload: {"decision": "pass", "findings": []},
    )
    backend.register(
        "editorial_skill_humanizer_review",
        lambda _payload: {
            "decision": "block",
            "findings": [
                {
                    "code": "generic_transition",
                    "summary": "The closing transition sounds generic.",
                    "evidence": "The final paragraph uses a reusable transition.",
                    "remediation": "Recompose that connective without changing factual atoms.",
                }
            ],
        },
    )
    quality_input = _quality_input_with_ats(tmp_path / "pack", _quality_source())
    quality_input = replace(quality_input, editorial_skill_reviews=())
    with mock.patch.object(
        application_quality,
        "_load_pinned_skill_document",
        return_value=b"# Exact fixture skill\n",
    ):
        reviewed = run_pinned_editorial_skill_reviews(
            quality_input,
            client=_runtime_client(tmp_path, backend),
        )
    review = build_deterministic_preflight_quality_review(reviewed)
    assert review.disposition is QualityReviewDisposition.NEEDS_REMEDIATION
    assert _codes(review) == {"humanizer.generic_transition"}
    assert review.issues[0].evidence == (
        "The final paragraph uses a reusable transition."
    )


def test_pinned_editorial_runtime_rejects_unreviewed_or_malformed_model_claims(
    tmp_path: Path,
) -> None:
    unreviewed = replace(
        _quality_input_with_ats(tmp_path / "wrong-runtime", _quality_source()),
        editorial_skill_reviews=(),
    )
    with pytest.raises(ValueError, match="runtime differs from pinned policy"):
        run_pinned_editorial_skill_reviews(
            unreviewed,
            client=_runtime_client(tmp_path / "wrong-client", MockBackend()),
        )
    backend = _FixtureCodexBackend()
    backend.register(
        "editorial_skill_resume_cover_letter_review",
        lambda _payload: {
            "decision": "pass",
            "findings": [
                {
                    "code": "contradiction",
                    "summary": "A finding cannot accompany pass.",
                    "evidence": "The response contradicts itself.",
                    "remediation": "Return a truthful blocking decision.",
                }
            ],
        },
    )
    quality_input = replace(
        _quality_input_with_ats(tmp_path / "pack", _quality_source()),
        editorial_skill_reviews=(),
    )
    with mock.patch.object(
        application_quality,
        "_load_pinned_skill_document",
        return_value=b"# Exact fixture skill\n",
    ):
        with pytest.raises(ValueError, match="passing editorial skill response"):
            run_pinned_editorial_skill_reviews(
                quality_input,
                client=_runtime_client(tmp_path, backend),
            )
    with pytest.raises(ValueError, match="unreviewed exact pack"):
        run_pinned_editorial_skill_reviews(
            _quality_input_with_ats(tmp_path / "reviewed", _quality_source()),
            client=_runtime_client(tmp_path / "second", _FixtureCodexBackend()),
        )


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
        _quality_input_with_ats(tmp_path, source()),
    )
    assert review.disposition is QualityReviewDisposition.NEEDS_REMEDIATION
    assert expected_code in _codes(review)


def test_prior_letter_similarity_cannot_be_omitted_from_the_result(tmp_path: Path) -> None:
    quality_input = _quality_input_with_ats(tmp_path, _quality_source())
    first = build_deterministic_preflight_quality_review(quality_input)
    repeated = build_deterministic_preflight_quality_review(
        quality_input,
        prior_cover_letter_shingles=(first.cover_letter_shingle_sha256s,),
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

    ats_input = _quality_input_with_ats(tmp_path / "ats", _quality_source())
    with pytest.raises(ValueError, match="exact ATS authority"):
        build_deterministic_preflight_quality_review(
            replace(ats_input, field_answers_bytes=b"substituted\n")
        )
    with pytest.raises(ValueError, match="exact ATS authority"):
        build_deterministic_preflight_quality_review(
            replace(ats_input, form_inventory_bytes=b"substituted\n")
        )
