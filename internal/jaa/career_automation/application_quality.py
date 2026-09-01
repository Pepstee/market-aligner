"""Deterministic pre-release quality assessment for exact JAA application packs."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from dataclasses import replace as dataclass_replace
from pathlib import Path
from typing import Any, Iterable

from llm.client import LLMClient

from .application_artifacts import (
    PublishedArtifactReceipt,
    verify_application_artifact_receipt,
)
from .application_compiler import ApplicationSource, verify_application_source
from .ats_application_authority import (
    AtsApplicationAuthority,
    verify_ats_application_authority,
)
from .application_quality_contracts import (
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
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
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
_MAX_SKILL_BYTES = 131_072
_EDITORIAL_FINDING_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_EDITORIAL_RUNTIME_PROVIDER = "codex_cli"
_EDITORIAL_RUNTIME_CONFIGURED_MODEL = "codex-cli-default"
_EDITORIAL_RUNTIME_MODEL = "codex-default"
_EDITORIAL_SKILL_POLICIES = (
    (
        "resume-cover-letter",
        "content-addressed",
        "adaa35a36ae0bfa6b1ce14104aebcbfe8a51c65434087056facf4f8f45217b96",
    ),
    (
        "humanizer",
        "2.8.2",
        "243aecdafecb5e11c2d45e2e088b7876e3f6eee34aa50c53f624d8468039afa8",
    ),
)
_EDITORIAL_REVIEW_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["decision", "findings"],
    "properties": {
        "decision": {"type": "string", "enum": ["pass", "block"]},
        "findings": {
            "type": "array",
            "maxItems": 32,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["code", "summary", "evidence", "remediation"],
                "properties": {
                    "code": {
                        "type": "string",
                        "pattern": "^[a-z][a-z0-9_]{0,63}$",
                    },
                    "summary": {"type": "string", "maxLength": 4096},
                    "evidence": {"type": "string", "maxLength": 16384},
                    "remediation": {"type": "string", "maxLength": 8192},
                },
            },
        },
    },
}

QUALITY_POLICY = {
    "schema_version": "jaa.deterministic-application-quality-policy.v2",
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
    "editorial_skill_reviews": [
        {
            "skill_name": name,
            "skill_version": version,
            "skill_sha256": skill_sha256,
        }
        for name, version, skill_sha256 in _EDITORIAL_SKILL_POLICIES
    ],
    "editorial_skill_runtime": {
        "provider": _EDITORIAL_RUNTIME_PROVIDER,
        "configured_model": _EDITORIAL_RUNTIME_CONFIGURED_MODEL,
        "model": _EDITORIAL_RUNTIME_MODEL,
    },
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


def _editorial_review_input_body(
    *,
    candidate_authority_sha256: str,
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
    publication_receipt: PublishedArtifactReceipt,
    field_answers_bytes: bytes,
    form_inventory_bytes: bytes,
) -> dict[str, Any]:
    return {
        "schema_version": "jaa.editorial-skill-review-input.v1",
        "candidate_authority_sha256": candidate_authority_sha256,
        "application_source_sha256": source.source_id,
        "vacancy_sha256": source.vacancy_sha256,
        "artifact_set_sha256": artifacts.artifact_set_sha256,
        "artifact_receipt_sha256": publication_receipt.receipt_sha256,
        "cv_editable_sha256": artifacts.editable.cv_sha256,
        "cover_letter_editable_sha256": artifacts.editable.cover_letter_sha256,
        "answers_editable_sha256": artifacts.editable.answers_sha256,
        "cv_pdf_sha256": artifacts.cv_pdf.pdf_sha256,
        "cover_letter_pdf_sha256": artifacts.cover_letter_pdf.pdf_sha256,
        "field_answers_sha256": _sha256_bytes(field_answers_bytes),
        "form_inventory_sha256": _sha256_bytes(form_inventory_bytes),
    }


def _open_directory_component(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISDIR(status.st_mode):
            raise ValueError("editorial skill ancestry is not a directory")
        if status.st_uid not in {0, os.getuid()} or status.st_mode & 0o022:
            raise ValueError("editorial skill ancestry is not trusted")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _stable_stat_identity(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_gid,
        status.st_nlink,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _load_pinned_skill_document(skill_name: str, skill_sha256: str) -> bytes:
    """Read one installed skill through a no-follow descriptor chain."""
    codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    path = codex_home / "skills" / skill_name / "SKILL.md"
    absolute = path.absolute()
    descriptors: list[int] = []
    current = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    descriptors.append(current)
    try:
        for component in absolute.parts[1:-1]:
            current = _open_directory_component(current, component)
            descriptors.append(current)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(absolute.name, flags, dir_fd=current)
        descriptors.append(file_descriptor)
        status = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_nlink != 1
            or status.st_mode & 0o022
            or status.st_size < 1
            or status.st_size > _MAX_SKILL_BYTES
        ):
            raise ValueError("editorial skill file is not an exact trusted authority")
        chunks: list[bytes] = []
        remaining = status.st_size
        offset = 0
        while remaining:
            chunk = os.pread(file_descriptor, min(65_536, remaining), offset)
            if not chunk:
                raise ValueError("editorial skill file changed during bounded read")
            chunks.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if _stable_stat_identity(os.fstat(file_descriptor)) != _stable_stat_identity(
            status
        ):
            raise ValueError("editorial skill file changed during bounded read")
        if hashlib.sha256(payload).hexdigest() != skill_sha256:
            raise ValueError("editorial skill bytes differ from pinned policy")
        payload.decode("utf-8", errors="strict")
        return payload
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _editorial_skill_system_prompt(skill_name: str, skill_document: bytes) -> str:
    return (
        f"[[task:editorial_skill_{skill_name.replace('-', '_')}_review]]\n"
        "Execute the exact pinned skill document below as a review of the supplied "
        "final application pack. Do not edit files, browse, add facts, infer missing "
        "qualifications, or rewrite the application. Return pass only when no concrete "
        "skill-defined issue remains. Otherwise return detailed findings whose evidence "
        "identifies the exact text problem without adding new candidate claims.\n\n"
        "PINNED SKILL DOCUMENT:\n"
        + skill_document.decode("utf-8", errors="strict")
    )


def _editorial_skill_user_payload(
    quality_input: ApplicationQualityInput,
    *,
    skill_name: str,
) -> str:
    source = quality_input.source
    artifacts = quality_input.artifacts
    return canonical_json(
        {
            "schema_version": "jaa.editorial-skill-runtime-request.v1",
            "skill_name": skill_name,
            "review_input_sha256": editorial_review_input_sha256(quality_input),
            "role_title": source.role_title,
            "company_name": source.company_name,
            "approved_facts": [
                {
                    "document_kind": row.document_kind,
                    "fact_kind": row.fact_kind,
                    "text": row.text,
                }
                for row in source.facts
            ],
            "final_application": {
                "cv": artifacts.editable.cv_text,
                "cover_letter": artifacts.editable.cover_letter_text,
                "field_answers": quality_input.field_answers_bytes.decode(
                    "utf-8", errors="strict"
                ),
            },
        }
    )


def _issues_from_skill_result(
    *,
    skill_name: str,
    result: dict[str, Any],
) -> tuple[str, tuple[ApplicationQualityIssue, ...]]:
    if set(result) != {"decision", "findings"}:
        raise ValueError("editorial skill response has unknown or missing fields")
    decision = result["decision"]
    rows = result["findings"]
    if decision not in {"pass", "block"} or not isinstance(rows, list):
        raise ValueError("editorial skill response has invalid decision data")
    if len(rows) > 32:
        raise ValueError("editorial skill response contains too many findings")
    findings: list[ApplicationQualityIssue] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "code",
            "summary",
            "evidence",
            "remediation",
        }:
            raise ValueError("editorial skill finding has unknown or missing fields")
        code = row["code"]
        if not isinstance(code, str) or _EDITORIAL_FINDING_CODE.fullmatch(code) is None:
            raise ValueError("editorial skill finding code is invalid")
        findings.append(
            _issue(
                f"{skill_name.replace('-', '_')}.{code}",
                summary=row["summary"],
                evidence=row["evidence"],
                remediation=row["remediation"],
                category="editorial_skill",
            )
        )
    if decision == "pass" and findings:
        raise ValueError("passing editorial skill response contains findings")
    if decision == "block" and not findings:
        raise ValueError("blocking editorial skill response lacks findings")
    codes = tuple(row.code for row in findings)
    if len(codes) != len(set(codes)):
        raise ValueError("editorial skill response contains duplicate findings")
    return decision, tuple(findings)


def run_pinned_editorial_skill_reviews(
    quality_input: ApplicationQualityInput,
    *,
    client: LLMClient | None = None,
) -> ApplicationQualityInput:
    """Actually run both installed skills and return the pack with exact receipts."""
    if not isinstance(quality_input, ApplicationQualityInput):
        raise TypeError("quality input must be ApplicationQualityInput")
    if quality_input.editorial_skill_reviews:
        raise ValueError("editorial skill runtime requires an unreviewed exact pack")
    runtime_client = client if client is not None else LLMClient.from_config()
    if type(runtime_client) is not LLMClient:
        raise TypeError("editorial skill runtime requires the exact LLM client")
    if (
        runtime_client.backend.name != _EDITORIAL_RUNTIME_PROVIDER
        or runtime_client.model != _EDITORIAL_RUNTIME_CONFIGURED_MODEL
    ):
        raise ValueError("editorial skill runtime differs from pinned policy")
    receipts: list[EditorialSkillReviewReceipt] = []
    for skill_name, _version, skill_sha256 in _EDITORIAL_SKILL_POLICIES:
        skill_document = _load_pinned_skill_document(skill_name, skill_sha256)
        result, response = runtime_client.complete_json_with_response(
            _editorial_skill_system_prompt(skill_name, skill_document),
            _editorial_skill_user_payload(quality_input, skill_name=skill_name),
            schema=_EDITORIAL_REVIEW_RESPONSE_SCHEMA,
            task=f"editorial_skill_{skill_name.replace('-', '_')}_review",
        )
        decision, findings = _issues_from_skill_result(
            skill_name=skill_name,
            result=result,
        )
        receipts.append(
            build_editorial_skill_review_receipt(
                quality_input,
                skill_name=skill_name,
                provider=runtime_client.backend.name,
                model=response.model,
                decision=decision,
                findings=findings,
            )
        )
    return dataclass_replace(
        quality_input,
        editorial_skill_reviews=tuple(receipts),
    )


def editorial_review_input_sha256(
    quality_input: ApplicationQualityInput,
) -> str:
    """Bind both skill reviews to the exact final application pack."""
    if not isinstance(quality_input, ApplicationQualityInput):
        raise TypeError("quality input must be ApplicationQualityInput")
    body = _editorial_review_input_body(
        candidate_authority_sha256=quality_input.candidate_authority_sha256,
        source=quality_input.source,
        artifacts=quality_input.artifacts,
        publication_receipt=quality_input.publication_receipt,
        field_answers_bytes=quality_input.field_answers_bytes,
        form_inventory_bytes=quality_input.form_inventory_bytes,
    )
    return hashlib.sha256(canonical_json(body).encode()).hexdigest()


@dataclass(frozen=True)
class EditorialSkillReviewReceipt:
    """Operator-recorded proof that one pinned editorial skill reviewed an exact pack."""

    reviewed_at: str
    skill_name: str
    skill_version: str
    skill_sha256: str
    provider: str
    model: str
    input_sha256: str
    decision: str
    findings: tuple[ApplicationQualityIssue, ...]
    receipt_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        if not isinstance(self.reviewed_at, str) or not _RFC3339_UTC.fullmatch(
            self.reviewed_at
        ):
            raise ValueError("editorial review time must be second-precision RFC3339 UTC")
        policy = next(
            (row for row in _EDITORIAL_SKILL_POLICIES if row[0] == self.skill_name),
            None,
        )
        if policy is None or (self.skill_version, self.skill_sha256) != policy[1:]:
            raise ValueError("editorial review skill identity differs from pinned policy")
        for value, label in (
            (self.skill_sha256, "editorial skill hash"),
            (self.input_sha256, "editorial review input hash"),
            (self.receipt_sha256, "editorial review receipt hash"),
        ):
            _require_digest(value, label)
        for value, label in ((self.provider, "provider"), (self.model, "model")):
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"editorial review {label} must be bounded text")
        if (
            self.provider != _EDITORIAL_RUNTIME_PROVIDER
            or self.model != _EDITORIAL_RUNTIME_MODEL
        ):
            raise ValueError("editorial review runtime differs from pinned policy")
        if self.decision not in {"pass", "block"}:
            raise ValueError("editorial review decision is unsupported")
        if not all(type(row) is ApplicationQualityIssue for row in self.findings):
            raise TypeError("editorial review findings must use the exact issue type")
        if self.decision == "pass" and self.findings:
            raise ValueError("passing editorial review cannot contain findings")
        if self.decision == "block" and not self.findings:
            raise ValueError("blocking editorial review requires detailed findings")
        if any(not row.release_blocking for row in self.findings):
            raise ValueError("editorial review findings must block release")
        if self.receipt_sha256 != self.content_sha256:
            raise ValueError("editorial review receipt identity is inconsistent")

    def to_dict(self, *, include_receipt_sha256: bool = True) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schema_version": "jaa.editorial-skill-review-receipt.v1",
            "reviewed_at": self.reviewed_at,
            "skill_name": self.skill_name,
            "skill_version": self.skill_version,
            "skill_sha256": self.skill_sha256,
            "provider": self.provider,
            "model": self.model,
            "input_sha256": self.input_sha256,
            "decision": self.decision,
            "findings": [row.to_dict() for row in self.findings],
        }
        if include_receipt_sha256:
            body["receipt_sha256"] = self.receipt_sha256
        return body

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json(self.to_dict(include_receipt_sha256=False)).encode()
        ).hexdigest()


def build_editorial_skill_review_receipt(
    quality_input: ApplicationQualityInput,
    *,
    skill_name: str,
    provider: str,
    model: str,
    decision: str = "pass",
    findings: Iterable[ApplicationQualityIssue] = (),
) -> EditorialSkillReviewReceipt:
    """Create a content-addressed receipt after the named skill has actually run."""
    policy = next((row for row in _EDITORIAL_SKILL_POLICIES if row[0] == skill_name), None)
    if policy is None:
        raise ValueError("editorial skill is not admitted by policy")
    exact_findings = tuple(findings)
    body = {
        "schema_version": "jaa.editorial-skill-review-receipt.v1",
        "reviewed_at": quality_input.reviewed_at,
        "skill_name": skill_name,
        "skill_version": policy[1],
        "skill_sha256": policy[2],
        "provider": provider,
        "model": model,
        "input_sha256": editorial_review_input_sha256(quality_input),
        "decision": decision,
        "findings": [row.to_dict() for row in exact_findings],
    }
    return EditorialSkillReviewReceipt(
        reviewed_at=body["reviewed_at"],
        skill_name=skill_name,
        skill_version=policy[1],
        skill_sha256=policy[2],
        provider=provider,
        model=model,
        input_sha256=body["input_sha256"],
        decision=decision,
        findings=exact_findings,
        receipt_sha256=hashlib.sha256(canonical_json(body).encode()).hexdigest(),
    )


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
    editorial_skill_reviews: tuple[EditorialSkillReviewReceipt, ...] = ()

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
        object.__setattr__(self, "editorial_skill_reviews", tuple(self.editorial_skill_reviews))
        if not all(
            type(row) is EditorialSkillReviewReceipt
            for row in self.editorial_skill_reviews
        ):
            raise TypeError("quality input editorial reviews must use the exact receipt type")
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
    review_input_sha256 = editorial_review_input_sha256(quality_input)
    editorial_reviews = quality_input.editorial_skill_reviews
    expected_names = tuple(row[0] for row in _EDITORIAL_SKILL_POLICIES)
    observed_names = tuple(row.skill_name for row in editorial_reviews)
    if len(observed_names) != len(set(observed_names)):
        raise ValueError("editorial skill review names must be unique")
    if observed_names != tuple(name for name in expected_names if name in observed_names):
        raise ValueError("editorial skill reviews differ from the required order")
    if any(row.input_sha256 != review_input_sha256 for row in editorial_reviews):
        raise ValueError("editorial skill review differs from the exact application pack")
    for name in expected_names:
        if name not in observed_names:
            issues.append(
                _issue(
                    f"{name.replace('-', '_')}_review_missing",
                    summary=f"The exact application pack lacks a {name} skill review.",
                    evidence="No content-addressed review receipt is bound to the final pack.",
                    remediation=f"Run the pinned {name} skill and attach its exact review receipt.",
                    category="editorial_skill",
                )
            )
    for receipt in editorial_reviews:
        if receipt.decision == "block":
            issues.extend(receipt.findings)
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
        "schema_version": "jaa.deterministic-application-quality-assessment.v2",
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
        "editorial_skill_review_sha256s": [
            row.receipt_sha256 for row in editorial_reviews
        ],
        "editorial_skill_reviews_verified": observed_names == expected_names
        and all(row.decision == "pass" for row in editorial_reviews),
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
        editorial_skill_review_sha256s=tuple(
            row.receipt_sha256 for row in editorial_reviews
        ),
        editorial_skill_reviews_verified=observed_names == expected_names
        and all(row.decision == "pass" for row in editorial_reviews),
        issues=issue_rows,
        summary=(
            "The exact application pack passed every deterministic quality gate."
            if disposition is QualityReviewDisposition.ACCEPTED
            else "The exact application pack is retained but cannot receive release authority."
        ),
    )
