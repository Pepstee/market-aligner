"""Typed contracts for deterministic pre-release application quality."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_sha256(value: str | None, field_name: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{field_name} must be lowercase SHA-256")


def _require_text(value: str, field_name: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{field_name} must be non-empty UTF-8 text within {maximum} bytes")
    if "\\x00" in value:
        raise ValueError(f"{field_name} cannot contain NUL")


class QualityIssueSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class QualityReviewDisposition(str, Enum):
    ACCEPTED = "accepted"
    NEEDS_REMEDIATION = "needs_remediation"
    NOT_SUBMITTED = "not_submitted"


@dataclass(frozen=True)
class ApplicationQualityIssue:
    code: str
    severity: QualityIssueSeverity
    category: str
    release_blocking: bool
    enforceable_by_code: bool
    summary: str
    evidence: str
    remediation: str

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not _IDENTIFIER.fullmatch(self.code):
            raise ValueError("quality issue code must be a stable identifier")
        if not isinstance(self.severity, QualityIssueSeverity):
            raise TypeError("quality issue severity must be typed")
        if not isinstance(self.category, str) or not _IDENTIFIER.fullmatch(self.category):
            raise ValueError("quality issue category must be a stable identifier")
        if not isinstance(self.release_blocking, bool) or not isinstance(self.enforceable_by_code, bool):
            raise TypeError("quality issue flags must be bool")
        _require_text(self.summary, "quality issue summary", maximum=4096)
        _require_text(self.evidence, "quality issue evidence", maximum=16384)
        _require_text(self.remediation, "quality issue remediation", maximum=8192)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "category": self.category,
            "release_blocking": self.release_blocking,
            "enforceable_by_code": self.enforceable_by_code,
            "summary": self.summary,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class ApplicationPreflightQualityReview:
    """Exact pre-release quality authority for one prepared application."""

    reviewed_at: str
    vacancy_sha256: str
    candidate_authority_sha256: str
    application_source_sha256: str
    artifact_receipt_sha256: str
    cv_sha256: str
    cover_letter_sha256: str | None
    field_answers_sha256: str
    form_inventory_sha256: str
    quality_policy_sha256: str
    reviewer_receipt_sha256: str
    disposition: QualityReviewDisposition
    factual_accuracy_score: int
    role_targeting_score: int
    natural_voice_score: int
    cross_application_consistency_score: int
    evidence_capture_score: int
    technical_execution_score: int
    cover_letter_shingle_sha256s: tuple[str, ...]
    maximum_prior_similarity_bp: int
    ats_answer_authority_verified: bool
    editorial_skill_review_sha256s: tuple[str, ...]
    editorial_skill_reviews_verified: bool
    issues: tuple[ApplicationQualityIssue, ...]
    summary: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "issues", tuple(self.issues))
        object.__setattr__(
            self,
            "cover_letter_shingle_sha256s",
            tuple(self.cover_letter_shingle_sha256s),
        )
        object.__setattr__(
            self,
            "editorial_skill_review_sha256s",
            tuple(self.editorial_skill_review_sha256s),
        )
        if not isinstance(self.reviewed_at, str) or not _RFC3339_UTC.fullmatch(self.reviewed_at):
            raise ValueError("reviewed_at must be second-precision RFC3339 UTC")
        for field_name in (
            "vacancy_sha256",
            "candidate_authority_sha256",
            "application_source_sha256",
            "artifact_receipt_sha256",
            "cv_sha256",
            "field_answers_sha256",
            "form_inventory_sha256",
            "quality_policy_sha256",
            "reviewer_receipt_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name)
        _require_sha256(
            self.cover_letter_sha256,
            "cover_letter_sha256",
            nullable=True,
        )
        if self.disposition not in {
            QualityReviewDisposition.ACCEPTED,
            QualityReviewDisposition.NEEDS_REMEDIATION,
        }:
            raise ValueError("preflight review disposition is unsupported")
        for field_name in (
            "factual_accuracy_score",
            "role_targeting_score",
            "natural_voice_score",
            "cross_application_consistency_score",
            "evidence_capture_score",
            "technical_execution_score",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10:
                raise ValueError(f"{field_name} must be an integer from 0 to 10")
        if not all(isinstance(issue, ApplicationQualityIssue) for issue in self.issues):
            raise TypeError("preflight issues must be ApplicationQualityIssue")
        if (
            len(self.cover_letter_shingle_sha256s) > 8192
            or tuple(sorted(set(self.cover_letter_shingle_sha256s)))
            != self.cover_letter_shingle_sha256s
        ):
            raise ValueError("cover-letter shingle identities must be unique and ordered")
        for value in self.cover_letter_shingle_sha256s:
            _require_sha256(value, "cover-letter shingle hash")
        if (
            not isinstance(self.maximum_prior_similarity_bp, int)
            or isinstance(self.maximum_prior_similarity_bp, bool)
            or not 0 <= self.maximum_prior_similarity_bp <= 10_000
        ):
            raise ValueError("maximum prior similarity must be basis points")
        if not isinstance(self.ats_answer_authority_verified, bool):
            raise TypeError("ATS answer-authority verification must be bool")
        if not isinstance(self.editorial_skill_reviews_verified, bool):
            raise TypeError("editorial skill review verification must be bool")
        if len(self.editorial_skill_review_sha256s) not in {0, 2}:
            raise ValueError("editorial skill review identities must be empty or complete")
        for value in self.editorial_skill_review_sha256s:
            _require_sha256(value, "editorial skill review hash")
        if len(set(self.editorial_skill_review_sha256s)) != len(
            self.editorial_skill_review_sha256s
        ):
            raise ValueError("editorial skill review identities must be unique")
        issue_codes = [issue.code for issue in self.issues]
        if len(issue_codes) != len(set(issue_codes)):
            raise ValueError("preflight issue codes must be unique")
        if self.disposition is QualityReviewDisposition.ACCEPTED:
            exact_scores = (
                self.factual_accuracy_score,
                self.cross_application_consistency_score,
                self.evidence_capture_score,
                self.technical_execution_score,
            )
            if exact_scores != (10, 10, 10, 10):
                raise ValueError("accepted preflight requires exact deterministic quality scores")
            if self.role_targeting_score < 6 or self.natural_voice_score < 6:
                raise ValueError("accepted preflight fails minimum targeting or natural-voice score")
            if any(issue.release_blocking for issue in self.issues):
                raise ValueError("accepted preflight cannot contain a release-blocking issue")
            if not self.ats_answer_authority_verified:
                raise ValueError("accepted preflight requires exact ATS answer authority")
            if (
                not self.editorial_skill_reviews_verified
                or len(self.editorial_skill_review_sha256s) != 2
            ):
                raise ValueError("accepted preflight requires exact editorial skill reviews")
        _require_text(self.summary, "preflight quality summary", maximum=16384)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "jaa.application-preflight-quality-review.v3",
            "reviewed_at": self.reviewed_at,
            "vacancy_sha256": self.vacancy_sha256,
            "candidate_authority_sha256": self.candidate_authority_sha256,
            "application_source_sha256": self.application_source_sha256,
            "artifact_receipt_sha256": self.artifact_receipt_sha256,
            "cv_sha256": self.cv_sha256,
            "cover_letter_sha256": self.cover_letter_sha256,
            "field_answers_sha256": self.field_answers_sha256,
            "form_inventory_sha256": self.form_inventory_sha256,
            "quality_policy_sha256": self.quality_policy_sha256,
            "reviewer_receipt_sha256": self.reviewer_receipt_sha256,
            "disposition": self.disposition.value,
            "scores": {
                "factual_accuracy": self.factual_accuracy_score,
                "role_targeting": self.role_targeting_score,
                "natural_voice": self.natural_voice_score,
                "cross_application_consistency": self.cross_application_consistency_score,
                "evidence_capture": self.evidence_capture_score,
                "technical_execution": self.technical_execution_score,
            },
            "cover_letter_shingle_sha256s": list(
                self.cover_letter_shingle_sha256s
            ),
            "maximum_prior_similarity_bp": self.maximum_prior_similarity_bp,
            "ats_answer_authority_verified": self.ats_answer_authority_verified,
            "editorial_skill_review_sha256s": list(
                self.editorial_skill_review_sha256s
            ),
            "editorial_skill_reviews_verified": self.editorial_skill_reviews_verified,
            "issues": [issue.to_dict() for issue in self.issues],
            "summary": self.summary,
        }

    @property
    def content_sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


__all__ = [
    "ApplicationPreflightQualityReview",
    "ApplicationQualityIssue",
    "QualityIssueSeverity",
    "QualityReviewDisposition",
]
