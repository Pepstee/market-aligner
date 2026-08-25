"""Deterministic pre-release quality assessment for exact JAA application packs."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable

from .application_artifacts import (
    PublishedArtifactReceipt,
    verify_application_artifact_receipt,
)
from .application_compiler import ApplicationSource, verify_application_source
from .ats_application_authority import (
    AtsApplicationAuthority,
    verify_ats_application_authority,
)
from .browser_workflows import (
    ApplicationPreflightQualityReview,
    ApplicationQualityIssue,
    QualityIssueSeverity,
    QualityReviewDisposition,
)
from .evidence_matching import canonical_json, content_hash
from .rendering import (
    ApplicationArtifacts,
    render_pdf_artifacts,
    verify_application_artifacts,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WORD = re.compile(r"[a-z0-9]+(?:'[a-z0-9]+)?")
_INTERNAL_HEADINGS = frozenset({"Opening", "Evidence Match", "Company Fit", "Close"})
_GENERIC_OR_AI_PATTERNS = (
    "\u2014",
    "\u2013",
    "i am writing to express my interest",
    "i am excited to apply",
    "i was thrilled to discover",
    "not only",
    "it's not just",
    "delve",
    "pivotal",
    "vibrant",
    "tapestry",
    "showcase",
)
_STALE_EDUCATION_PATTERNS = (
    "currently completing",
    "currently studying",
    "currently pursuing",
    "currently enrolled",
    "i am completing",
    "i'm completing",
    "i am studying",
    "i'm studying",
    "i am pursuing",
    "i'm pursuing",
)
_SENSITIVE_QUESTION_MARKERS = (
    "salary",
    "compensation",
    "work right",
    "right to work",
    "visa",
    "sponsor",
    "relocat",
    "remote",
    "hybrid",
    "office",
    "graduat",
    "currently enrolled",
    "years of experience",
    "how many years",
)
_MAX_CAPTURE_BYTES = 4_194_304
_SIMILARITY_BLOCK_BP = 4_500

QUALITY_POLICY = {
    "schema_version": "jaa.deterministic-application-quality-policy.v1",
    "cover_letter": {
        "substantive_paragraphs": [3, 4],
        "maximum_words": 500,
        "maximum_characters": 3_500,
        "minimum_distinct_candidate_facts": 2,
        "requires_company_fact": True,
        "requires_exact_role_reference": True,
        "requires_salutation": "Dear Hiring Manager,",
        "requires_signoff": "Kind regards, plus candidate name",
    },
    "cv": {
        "minimum_distinct_candidate_facts": 2,
        "section_order": [
            "Professional Summary",
            "Experience",
            "Skills",
            "Education",
        ],
    },
    "prior_letter_similarity": {
        "shingle_words": 5,
        "release_block_basis_points": _SIMILARITY_BLOCK_BP,
    },
    "sensitive_answers": "approved factual sentences only; no style slots",
    "ats_authority": "required before acceptance",
    "generic_or_ai_patterns": list(_GENERIC_OR_AI_PATTERNS),
    "stale_education_patterns": list(_STALE_EDUCATION_PATTERNS),
}
QUALITY_POLICY_SHA256 = content_hash(QUALITY_POLICY)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _captured_bytes(value: bytes, label: str, *, allow_empty: bool) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{label} must be exact bytes")
    if len(value) > _MAX_CAPTURE_BYTES:
        raise ValueError(f"{label} exceeds the bounded capture size")
    if not allow_empty and not value:
        raise ValueError(f"{label} cannot be empty")
    try:
        value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be UTF-8") from exc
    return value


def _shingle_hashes(text: str) -> tuple[str, ...]:
    words = _WORD.findall(text.casefold())
    shingles = {
        " ".join(words[index : index + 5])
        for index in range(max(0, len(words) - 4))
    }
    return tuple(sorted(hashlib.sha256(row.encode()).hexdigest() for row in shingles))


def _similarity_bp(first: Iterable[str], second: Iterable[str]) -> int:
    left = set(first)
    right = set(second)
    if not left or not right:
        return 0
    return len(left & right) * 10_000 // len(left | right)


@dataclass(frozen=True)
class ApplicationQualityInput:
    """Exact application objects assessed by the workflow store, not caller scores."""

    reviewed_at: str
    candidate_authority_sha256: str
    source: ApplicationSource
    artifacts: ApplicationArtifacts
    publication_receipt: PublishedArtifactReceipt
    field_answers_bytes: bytes
    form_inventory_bytes: bytes
    ats_application_authority: AtsApplicationAuthority | None = None

    def __post_init__(self) -> None:
        _require_digest(self.candidate_authority_sha256, "candidate authority hash")
        if not isinstance(self.source, ApplicationSource):
            raise TypeError("quality input application source must be typed")
        if not isinstance(self.artifacts, ApplicationArtifacts):
            raise TypeError("quality input artifacts must be typed")
        if not isinstance(self.publication_receipt, PublishedArtifactReceipt):
            raise TypeError("quality input publication receipt must be typed")
        if self.ats_application_authority is not None and type(
            self.ats_application_authority
        ) is not AtsApplicationAuthority:
            raise TypeError("quality input ATS authority must use the exact type")
        _captured_bytes(self.field_answers_bytes, "field answers", allow_empty=True)
        _captured_bytes(self.form_inventory_bytes, "form inventory", allow_empty=False)


def _issue(
    code: str,
    *,
    summary: str,
    evidence: str,
    remediation: str,
    category: str = "document_quality",
    severity: QualityIssueSeverity = QualityIssueSeverity.ERROR,
) -> ApplicationQualityIssue:
    return ApplicationQualityIssue(
        code=code,
        severity=severity,
        category=category,
        release_blocking=True,
        enforceable_by_code=True,
        summary=summary,
        evidence=evidence,
        remediation=remediation,
    )


def _letter_blocks(text: str) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    blocks = tuple(row.strip() for row in text.strip().split("\n\n") if row.strip())
    if len(blocks) < 2:
        return "", (), ()
    body = blocks[1:]
    substantive = body
    if substantive and substantive[0].casefold().startswith("dear "):
        substantive = substantive[1:]
    if substantive and substantive[-1].casefold().startswith(
        ("kind regards", "sincerely")
    ):
        substantive = substantive[:-1]
    return "\n\n".join(body), body, substantive


def build_deterministic_preflight_quality_review(
    quality_input: ApplicationQualityInput,
    *,
    prior_cover_letter_shingles: Iterable[Iterable[str]] = (),
) -> ApplicationPreflightQualityReview:
    """Recompute quality from exact source/artifact evidence with no score inputs."""
    if not isinstance(quality_input, ApplicationQualityInput):
        raise TypeError("quality input must be ApplicationQualityInput")
    source = quality_input.source
    artifacts = quality_input.artifacts
    verify_application_source(source)
    verify_application_artifacts(artifacts)
    if render_pdf_artifacts(source) != artifacts:
        raise ValueError("application artifacts differ from canonical rendering")
    verify_application_artifact_receipt(
        source,
        artifacts,
        quality_input.publication_receipt,
    )
    field_answers = _captured_bytes(
        quality_input.field_answers_bytes,
        "field answers",
        allow_empty=True,
    )
    inventory = _captured_bytes(
        quality_input.form_inventory_bytes,
        "form inventory",
        allow_empty=False,
    )
    authority = quality_input.ats_application_authority
    if authority is None:
        if field_answers != artifacts.editable.answers_text.encode("utf-8"):
            raise ValueError("captured field answers differ from the application source")
        ats_answer_authority_verified = False
    else:
        verify_ats_application_authority(
            authority,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=source,
            artifacts=artifacts,
            publication_receipt=quality_input.publication_receipt,
        )
        if field_answers != authority.answer_bytes:
            raise ValueError("captured field answers differ from exact ATS authority")
        if inventory != authority.inventory_bytes:
            raise ValueError("captured form inventory differs from exact ATS authority")
        ats_answer_authority_verified = True

    issues: list[ApplicationQualityIssue] = []
    letter_text = artifacts.editable.cover_letter_text
    letter_body, body_blocks, substantive = _letter_blocks(letter_text)
    body_folded = letter_body.casefold()
    body_words = _WORD.findall(letter_body)
    exact_lines = {line.strip() for line in letter_body.splitlines() if line.strip()}
    if exact_lines & _INTERNAL_HEADINGS:
        issues.append(
            _issue(
                "internal_cover_heading",
                summary="The employer-facing cover letter exposes an internal section label.",
                evidence="At least one compiler-only letter heading appears as an output line.",
                remediation="Render approved letter atoms as prose paragraphs without internal labels.",
            )
        )
    if not body_blocks or body_blocks[0] != "Dear Hiring Manager,":
        issues.append(
            _issue(
                "cover_salutation_missing",
                summary="The cover letter lacks the exact approved salutation.",
                evidence="The first employer-facing body block is not `Dear Hiring Manager,`.",
                remediation="Re-render with the deterministic UK salutation.",
            )
        )
    signoff = f"Kind regards,\n{source.contact.full_name}"
    if not body_blocks or body_blocks[-1] != signoff:
        issues.append(
            _issue(
                "cover_signoff_missing",
                summary="The cover letter lacks the exact candidate-bound sign-off.",
                evidence="The last body block is not the approved sign-off plus candidate name.",
                remediation="Re-render with the deterministic UK sign-off.",
            )
        )
    if not 3 <= len(substantive) <= 4:
        issues.append(
            _issue(
                "cover_paragraph_contract",
                summary="The cover letter is not a natural three- or four-paragraph letter.",
                evidence=f"Observed {len(substantive)} substantive paragraphs.",
                remediation="Recompose the approved atoms into three or four substantive paragraphs.",
            )
        )
    if len(body_words) > 500 or len(letter_body) > 3_500:
        issues.append(
            _issue(
                "cover_length_exceeded",
                summary="The cover letter exceeds the deterministic UK one-page proxy.",
                evidence=f"Observed {len(body_words)} words and {len(letter_body)} characters.",
                remediation="Shorten connective prose without changing approved factual atoms.",
            )
        )
    candidate_letter_facts = {
        row.text
        for row in source.facts
        if row.document_kind == "cover_letter" and row.fact_kind == "candidate"
    }
    employer_letter_facts = {
        row.text
        for row in source.facts
        if row.document_kind == "cover_letter" and row.fact_kind == "employer"
    }
    if len(candidate_letter_facts) < 2:
        issues.append(
            _issue(
                "cover_evidence_too_thin",
                summary="The cover letter does not contain enough distinct candidate evidence.",
                evidence=f"Observed {len(candidate_letter_facts)} distinct candidate facts.",
                remediation="Select at least two role-relevant approved candidate facts.",
                category="role_targeting",
            )
        )
    if not any(source.company_name.casefold() in row.casefold() for row in employer_letter_facts):
        issues.append(
            _issue(
                "company_specific_fact_missing",
                summary="The cover letter lacks an exact company-specific employer fact.",
                evidence="No approved employer fact names the target company.",
                remediation="Use a cited employer fact selected by the application strategy.",
                category="role_targeting",
            )
        )
    if source.role_title.casefold() not in body_folded:
        issues.append(
            _issue(
                "role_reference_missing",
                summary="The cover letter does not name the exact target role.",
                evidence="The employer-facing body lacks the authority-bound role title.",
                remediation="Add the exact role title through an approved employer-facing atom.",
                category="role_targeting",
            )
        )
    cv_candidate_facts = {
        row.text
        for row in source.facts
        if row.document_kind == "cv" and row.fact_kind == "candidate"
    }
    if len(cv_candidate_facts) < 2:
        issues.append(
            _issue(
                "cv_evidence_too_thin",
                summary="The CV contains too little distinct approved evidence.",
                evidence=f"Observed {len(cv_candidate_facts)} distinct candidate facts.",
                remediation="Select at least two distinct approved facts for the tailored CV.",
                category="role_targeting",
            )
        )
    combined = "\n".join(
        (
            artifacts.editable.cv_text,
            artifacts.editable.cover_letter_text,
            artifacts.editable.answers_text,
        )
    ).casefold()
    found_patterns = tuple(pattern for pattern in _GENERIC_OR_AI_PATTERNS if pattern in combined)
    if found_patterns:
        issues.append(
            _issue(
                "generic_or_ai_prose",
                summary="The application contains bounded generic or AI-pattern prose.",
                evidence="Matched policy patterns: " + ", ".join(found_patterns),
                remediation="Replace the connective prose while preserving exact factual atoms.",
                category="natural_voice",
            )
        )
    stale_patterns = tuple(pattern for pattern in _STALE_EDUCATION_PATTERNS if pattern in combined)
    if stale_patterns:
        issues.append(
            _issue(
                "stale_education_claim",
                summary="The application describes completed education as still in progress.",
                evidence="Matched stale chronology patterns: " + ", ".join(stale_patterns),
                remediation="Regenerate from the current education authority before release.",
                category="factual_consistency",
            )
        )
    sensitive_style_questions = tuple(
        answer.question_id
        for answer in source.answers
        if answer.style_slot_ids
        and any(marker in answer.question.casefold() for marker in _SENSITIVE_QUESTION_MARKERS)
    )
    if sensitive_style_questions:
        issues.append(
            _issue(
                "sensitive_answer_uses_style_prose",
                summary="A sensitive employer answer contains non-authoritative connective prose.",
                evidence="Affected question IDs: " + ", ".join(sensitive_style_questions),
                remediation="Answer sensitive fields only from exact approved factual atoms.",
                category="factual_consistency",
            )
        )

    shingles = _shingle_hashes(letter_body)
    maximum_similarity_bp = max(
        (_similarity_bp(shingles, prior) for prior in prior_cover_letter_shingles),
        default=0,
    )
    if maximum_similarity_bp >= _SIMILARITY_BLOCK_BP:
        issues.append(
            _issue(
                "prior_cover_letter_too_similar",
                summary="The cover letter is too similar to a prior reviewed application.",
                evidence=f"Maximum five-word shingle similarity is {maximum_similarity_bp} basis points.",
                remediation="Recompose role- and company-specific prose before release.",
                category="cross_application_consistency",
            )
        )
    if not ats_answer_authority_verified:
        issues.append(
            _issue(
                "ats_answer_authority_missing",
                summary="Captured form inventory and answers lack a closed ATS mapping authority.",
                evidence="Exact bytes are retained, but field-to-source semantics are not yet certified.",
                remediation="Build and verify the exact inventory, answer and correction authority.",
                category="ats_execution",
            )
        )

    codes = {row.code for row in issues}
    targeting = 10 if not codes & {
        "cover_evidence_too_thin",
        "company_specific_fact_missing",
        "role_reference_missing",
        "cv_evidence_too_thin",
    } else 4
    natural_voice = 10 if not codes & {
        "internal_cover_heading",
        "cover_salutation_missing",
        "cover_signoff_missing",
        "cover_paragraph_contract",
        "cover_length_exceeded",
        "generic_or_ai_prose",
    } else 4
    consistency = 10 if not codes & {
        "stale_education_claim",
        "sensitive_answer_uses_style_prose",
        "prior_cover_letter_too_similar",
    } else 0
    evidence_capture = 10 if ats_answer_authority_verified else 8
    disposition = (
        QualityReviewDisposition.ACCEPTED
        if not any(row.release_blocking for row in issues)
        else QualityReviewDisposition.NEEDS_REMEDIATION
    )
    issue_rows = tuple(sorted(issues, key=lambda row: row.code))
    assessment_body = {
        "schema_version": "jaa.deterministic-application-quality-assessment.v1",
        "reviewed_at": quality_input.reviewed_at,
        "vacancy_sha256": source.vacancy_sha256,
        "candidate_authority_sha256": quality_input.candidate_authority_sha256,
        "application_source_sha256": source.source_id,
        "artifact_receipt_sha256": quality_input.publication_receipt.receipt_sha256,
        "cv_sha256": artifacts.cv_pdf.pdf_sha256,
        "cover_letter_sha256": artifacts.cover_letter_pdf.pdf_sha256,
        "field_answers_sha256": _sha256_bytes(field_answers),
        "form_inventory_sha256": _sha256_bytes(inventory),
        "quality_policy_sha256": QUALITY_POLICY_SHA256,
        "cover_letter_shingle_sha256s": list(shingles),
        "maximum_prior_similarity_bp": maximum_similarity_bp,
        "ats_answer_authority_verified": ats_answer_authority_verified,
        "scores": {
            "factual_accuracy": 10,
            "role_targeting": targeting,
            "natural_voice": natural_voice,
            "cross_application_consistency": consistency,
            "evidence_capture": evidence_capture,
            "technical_execution": 10,
        },
        "issues": [row.to_dict() for row in issue_rows],
        "disposition": disposition.value,
    }
    reviewer_receipt_sha256 = hashlib.sha256(
        canonical_json(assessment_body).encode()
    ).hexdigest()
    return ApplicationPreflightQualityReview(
        reviewed_at=quality_input.reviewed_at,
        vacancy_sha256=source.vacancy_sha256,
        candidate_authority_sha256=quality_input.candidate_authority_sha256,
        application_source_sha256=source.source_id,
        artifact_receipt_sha256=quality_input.publication_receipt.receipt_sha256,
        cv_sha256=artifacts.cv_pdf.pdf_sha256,
        cover_letter_sha256=artifacts.cover_letter_pdf.pdf_sha256,
        field_answers_sha256=_sha256_bytes(field_answers),
        form_inventory_sha256=_sha256_bytes(inventory),
        quality_policy_sha256=QUALITY_POLICY_SHA256,
        reviewer_receipt_sha256=reviewer_receipt_sha256,
        disposition=disposition,
        factual_accuracy_score=10,
        role_targeting_score=targeting,
        natural_voice_score=natural_voice,
        cross_application_consistency_score=consistency,
        evidence_capture_score=evidence_capture,
        technical_execution_score=10,
        cover_letter_shingle_sha256s=shingles,
        maximum_prior_similarity_bp=maximum_similarity_bp,
        ats_answer_authority_verified=ats_answer_authority_verified,
        issues=issue_rows,
        summary=(
            "The exact application pack passed every deterministic quality gate."
            if disposition is QualityReviewDisposition.ACCEPTED
            else "The exact application pack is retained but cannot receive release authority."
        ),
    )
