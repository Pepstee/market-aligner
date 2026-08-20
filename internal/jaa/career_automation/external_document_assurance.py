"""Deterministic, fail-closed assurance for employer-facing documents.

The evidence ledger may contain candid provenance, limitations, control-plane
terminology and model-authorship notes.  Those facts remain authoritative for
claim selection, but they are not automatically suitable as outward-facing
copy.  This module is the hard boundary between private evidence and bytes
that may be uploaded to an employer.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .evidence_matching import canonical_json, content_hash


POLICY_SCHEMA = "jaa.external-document-assurance.v1"
RECEIPT_SCHEMA = "jaa.external-document-assurance-receipt.v1"
SUPPORTED_DOCUMENT_KINDS = frozenset({"cv", "cover_letter", "answer"})
MAX_EXTERNAL_PDF_BYTES = 5 * 1024 * 1024
PERMANENT_QUARANTINED_DOCUMENTS: tuple[tuple[str, str], ...] = (
    (
        "3dd13ba9709c7679152f2fc938c4495e2631796712f724f56ab0c82bb34aa0d2",
        "2026-08-05 internal-governance and model-provenance leakage incident",
    ),
)
_PERMANENT_QUARANTINE_BY_HASH = dict(PERMANENT_QUARANTINED_DOCUMENTS)

# A deliberately small, auditable confusable set covering Latin characters in
# the control vocabulary below.  NFKC handles compatibility glyphs; these are
# the common Greek/Cyrillic lookalikes that NFKC intentionally leaves alone.
_CONFUSABLES = str.maketrans(
    {
        "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h",
        "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o",
        "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
        "α": "a", "ε": "e", "ι": "i", "κ": "k", "ο": "o",
        "ρ": "p", "τ": "t", "υ": "y", "χ": "x",
        "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m",
        "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t",
        "Х": "x", "а": "a", "е": "e", "о": "o", "р": "p",
        "с": "c", "х": "x", "і": "i", "ј": "j",
    }
)


@dataclass(frozen=True)
class AssuranceRule:
    code: str
    pattern: str
    rationale: str
    document_kinds: tuple[str, ...] = ("cv", "cover_letter", "answer")

    def document(self) -> dict[str, object]:
        return {
            "code": self.code,
            "pattern": self.pattern,
            "rationale": self.rationale,
            "document_kinds": self.document_kinds,
        }


# These rules describe classes of private-control leakage, not just the exact
# sentence from the 2026-08-05 incident.  Keep the expressions narrow enough
# that legitimate descriptions of AI engineering remain possible.
ASSURANCE_RULES: tuple[AssuranceRule, ...] = (
    AssuranceRule(
        "internal.evidence_boundary",
        r"\bevidence\s+boundar(?:y|ies)\b",
        "private evidence-boundary terminology reached external prose",
    ),
    AssuranceRule(
        "internal.operator_approval",
        r"\boperator[\s-]+approved\b",
        "private operator-approval terminology reached external prose",
    ),
    AssuranceRule(
        "internal.evidence_record",
        r"\b(?:approved|authoritative|private|internal)\s+evidence\s+(?:ledger|record|packet)\b",
        "private evidence-store terminology reached external prose",
    ),
    AssuranceRule(
        "internal.jaa_control_plane",
        r"\b(?:jaa[\s-]?\d{1,2}|release\s+manifest|artifact[\s-]+set\s+(?:hash|identity)|application\s+source\s+(?:hash|identity)|content[\s-]+addressed\s+(?:receipt|evidence))\b",
        "JAA control-plane vocabulary reached external prose",
    ),
    AssuranceRule(
        "internal.audit_governance",
        r"\b(?:internal|private|operator|model)\s+(?:audit|governance|provenance)(?:\s+(?:note|record|trail|manifest|receipt|policy))?\b|\b(?:audit|governance|provenance)\s+(?:note|record|manifest|receipt|hash|sha(?:-?256)?)\b",
        "private audit, governance or provenance vocabulary reached external prose",
    ),
    AssuranceRule(
        "internal.model_provenance",
        r"\b(?:model|llm|ai)\s+(?:authorship|provenance|receipt|disclosure)\b|\b(?:prompt|policy|model|input|output)\s+sha(?:-?256)?\b",
        "private model provenance or policy identity reached external prose",
    ),
    AssuranceRule(
        "authorship.ai_generated_implementation",
        r"\b(?:ai(?:\s+agents?)?|agents?|llms?|language\s+models?)[\s-]+(?:generated|wrote|authored|produced)\b.{0,120}\b(?:code|implementation|content|document|cv|resume)\b",
        "an internal model-authorship disclosure reached external prose",
    ),
    AssuranceRule(
        "authorship.defensive_disclaimer",
        r"\bi\s+(?:do\s+not|don't)\s+(?:claim|present)\b.{0,180}\b(?:wrote|written|hand[\s-]?wrote|authored|implemented|code)\b|\bi\s+(?:directed|supervised|prompted)\b.{0,120}\b(?:rather\s+than|instead\s+of)\b.{0,80}\b(?:wrote|authored|implemented|coded)\b",
        "defensive authorship disclaimer weakens or meta-describes the application",
    ),
    AssuranceRule(
        "claims.scope_disclaimer",
        r"\bclaims?\s+(?:in|on)\s+this\s+(?:cv|resume|application|document)\b.{0,160}\b(?:limited|approved|evidence|record)\b",
        "a private claim-scope disclaimer reached external prose",
    ),
    AssuranceRule(
        "experience.self_disqualification",
        r"\bthis\s+(?:was|is)\b.{0,160}\bnot\s+(?:a\s+)?professional\b.{0,100}\b(?:employment|experience|role|work)\b",
        "the document contains an unnecessary self-disqualifying disclaimer",
    ),
    AssuranceRule(
        "prompt.control_leakage",
        r"\b(?:system\s+prompt|developer\s+message|ignore\s+(?:all\s+)?previous\s+instructions|you\s+are\s+chatgpt|as\s+an\s+ai(?:\s+language\s+model)?)\b",
        "prompt or model-control language reached external prose",
    ),
    AssuranceRule(
        "draft.internal_marker",
        r"\b(?:lorem\s+ipsum|draft\s+only|not\s+for\s+submission|internal\s+use\s+only|test\s+fixture|dummy\s+candidate)\b",
        "draft or test-only content reached the submission artifact",
    ),
    AssuranceRule(
        "draft.placeholder",
        r"(?:\{\{[^{}]{1,120}\}\}|<<[^<>]{1,120}>>|\[(?:insert|todo|tbd|placeholder)[^\]]{0,120}\])",
        "an unresolved template placeholder reached external prose",
    ),
)


ASSURANCE_POLICY_SHA256 = hashlib.sha256(
    canonical_json(
        {
            "schema_version": POLICY_SCHEMA,
            "normalization": (
                "NFKC+casefold+format-removal+audited-confusables+"
                "whitespace-collapse"
            ),
            "pdf_parser": "pypdf-strict",
            "empty_text_policy": "block",
            "permanent_quarantine": [
                {"document_sha256": digest, "reason": reason}
                for digest, reason in PERMANENT_QUARANTINED_DOCUMENTS
            ],
            "rules": [rule.document() for rule in ASSURANCE_RULES],
        }
    ).encode()
).hexdigest()


@dataclass(frozen=True)
class AssuranceFinding:
    code: str
    rationale: str
    start: int
    end: int
    excerpt: str

    def document(self) -> dict[str, object]:
        return {
            "code": self.code,
            "rationale": self.rationale,
            "start": self.start,
            "end": self.end,
            "excerpt": self.excerpt,
        }


class ExternalDocumentAssuranceError(ValueError):
    """Employer-facing content failed one or more deterministic rules."""

    def __init__(self, findings: Sequence[AssuranceFinding]) -> None:
        self.findings = tuple(findings)
        codes = ",".join(finding.code for finding in self.findings)
        super().__init__(f"external-document assurance blocked: {codes}")


@dataclass(frozen=True)
class InspectedPdf:
    """Content inspection result without release authority."""

    document_kind: str
    document_sha256: str
    extracted_text_sha256: str
    page_count: int

    def __post_init__(self) -> None:
        _document_kind(self.document_kind)
        for value, label in (
            (self.document_sha256, "document hash"),
            (self.extracted_text_sha256, "extracted-text hash"),
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError(f"{label} must be lowercase SHA-256")
        if self.page_count < 1:
            raise ValueError("inspected PDF must contain a page")


@dataclass(frozen=True)
class IntendedVacancy:
    job_key: str
    vacancy_sha256: str
    role_title: str
    company_name: str

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (self.job_key, self.role_title, self.company_name)
        ):
            raise ValueError("intended vacancy binding is incomplete")
        if not re.fullmatch(r"[0-9a-f]{64}", self.vacancy_sha256):
            raise ValueError("intended vacancy hash must be lowercase SHA-256")

    @property
    def intent_sha256(self) -> str:
        return content_hash(
            {
                "contract": "jaa.external-document-intent.v1",
                **self.document(),
            }
        )

    def document(self) -> dict[str, str]:
        return {
            "job_key": self.job_key,
            "vacancy_sha256": self.vacancy_sha256,
            "role_title": self.role_title,
            "company_name": self.company_name,
        }


@dataclass(frozen=True)
class ExternalDocumentAssuranceReceipt:
    document_kind: str
    intended_vacancy: IntendedVacancy
    intent_sha256: str
    document_sha256: str
    extracted_text_sha256: str
    policy_sha256: str
    page_count: int
    verdict: str
    finding_codes: tuple[str, ...]
    receipt_sha256: str
    schema_version: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA:
            raise ValueError("unsupported external-document assurance receipt")
        _document_kind(self.document_kind)
        if not isinstance(self.intended_vacancy, IntendedVacancy):
            raise ValueError("assurance receipt lacks an intended vacancy")
        for value, label in (
            (self.intent_sha256, "intent hash"),
            (self.document_sha256, "document hash"),
            (self.extracted_text_sha256, "extracted-text hash"),
            (self.policy_sha256, "policy hash"),
            (self.receipt_sha256, "receipt hash"),
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError(f"{label} must be lowercase SHA-256")
        if self.policy_sha256 != ASSURANCE_POLICY_SHA256:
            raise ValueError("assurance receipt cites a different policy")
        if self.intent_sha256 != self.intended_vacancy.intent_sha256:
            raise ValueError("assurance receipt vacancy binding is invalid")
        if self.page_count < 0:
            raise ValueError("assurance page count cannot be negative")
        if self.verdict != "pass" or self.finding_codes:
            raise ValueError("only finding-free assurance may produce a receipt")
        if self.receipt_sha256 != content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("external-document assurance receipt hash is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "document_kind": self.document_kind,
            "intended_vacancy": self.intended_vacancy.document(),
            "intent_sha256": self.intent_sha256,
            "document_sha256": self.document_sha256,
            "extracted_text_sha256": self.extracted_text_sha256,
            "policy_sha256": self.policy_sha256,
            "page_count": self.page_count,
            "verdict": self.verdict,
            "finding_codes": self.finding_codes,
        }
        if include_identity:
            result["receipt_sha256"] = self.receipt_sha256
        return result


def _document_kind(value: str) -> str:
    if value not in SUPPORTED_DOCUMENT_KINDS:
        raise ValueError("unsupported employer-facing document kind")
    return value


def _normalized_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = "".join(
        character
        for character in normalized
        if unicodedata.category(character) != "Cf"
    )
    return " ".join(normalized.translate(_CONFUSABLES).split())


def _excerpt(text: str, start: int, end: int) -> str:
    left = max(0, start - 60)
    right = min(len(text), end + 60)
    return text[left:right].strip()


def scan_employer_facing_text(
    text: str,
    *,
    document_kind: str,
) -> tuple[AssuranceFinding, ...]:
    """Return ordered deterministic findings for outward-facing text."""
    kind = _document_kind(document_kind)
    if not isinstance(text, str):
        raise TypeError("employer-facing content must be text")
    normalized = _normalized_text(text)
    if not normalized:
        return (
            AssuranceFinding(
                "document.empty_text",
                "document extraction produced no reviewable text",
                0,
                0,
                "",
            ),
        )
    findings: list[AssuranceFinding] = []
    for rule in ASSURANCE_RULES:
        if kind not in rule.document_kinds:
            continue
        match = re.search(rule.pattern, normalized, flags=re.IGNORECASE | re.DOTALL)
        if match is None:
            continue
        findings.append(
            AssuranceFinding(
                rule.code,
                rule.rationale,
                match.start(),
                match.end(),
                _excerpt(normalized, match.start(), match.end()),
            )
        )
    return tuple(findings)


def assert_employer_facing_text(text: str, *, document_kind: str) -> None:
    findings = scan_employer_facing_text(text, document_kind=document_kind)
    if findings:
        raise ExternalDocumentAssuranceError(findings)


def _extract_pdf_text(pdf_bytes: bytes) -> tuple[str, int]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - packaging contract
        raise RuntimeError("the pinned pypdf runtime is required") from exc
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)
        if reader.is_encrypted:
            raise ValueError("encrypted PDFs cannot pass external assurance")
        text = "\n".join((page.extract_text() or "").rstrip() for page in reader.pages)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("PDF cannot be parsed for external-document assurance") from exc
    if not reader.pages:
        raise ValueError("PDF contains no pages")
    return text + ("\n" if text else ""), len(reader.pages)


def assure_pdf_bytes(
    pdf_bytes: bytes,
    *,
    document_kind: str,
    intended_vacancy: IntendedVacancy,
) -> ExternalDocumentAssuranceReceipt:
    """Verify exact PDF bytes and return a hash-bound PASS receipt."""
    inspected = inspect_pdf_bytes(pdf_bytes, document_kind=document_kind)
    kind = inspected.document_kind
    document_sha256 = inspected.document_sha256
    extracted_text_sha256 = inspected.extracted_text_sha256
    page_count = inspected.page_count
    preimage = {
        "schema_version": RECEIPT_SCHEMA,
        "document_kind": kind,
        "intended_vacancy": intended_vacancy.document(),
        "intent_sha256": intended_vacancy.intent_sha256,
        "document_sha256": document_sha256,
        "extracted_text_sha256": extracted_text_sha256,
        "policy_sha256": ASSURANCE_POLICY_SHA256,
        "page_count": page_count,
        "verdict": "pass",
        "finding_codes": (),
    }
    return ExternalDocumentAssuranceReceipt(
        document_kind=kind,
        intended_vacancy=intended_vacancy,
        intent_sha256=intended_vacancy.intent_sha256,
        document_sha256=document_sha256,
        extracted_text_sha256=extracted_text_sha256,
        policy_sha256=ASSURANCE_POLICY_SHA256,
        page_count=page_count,
        verdict="pass",
        finding_codes=(),
        receipt_sha256=content_hash(preimage),
    )


def inspect_pdf_bytes(
    pdf_bytes: bytes,
    *,
    document_kind: str,
) -> InspectedPdf:
    """Inspect exact final PDF bytes without granting release authority."""
    kind = _document_kind(document_kind)
    if not isinstance(pdf_bytes, bytes):
        raise TypeError("PDF assurance requires exact bytes")
    if not pdf_bytes.startswith(b"%PDF-"):
        raise ValueError("external document is not a PDF")
    if len(pdf_bytes) > MAX_EXTERNAL_PDF_BYTES:
        raise ValueError("external PDF exceeds the bounded assurance size")
    document_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    quarantine_reason = _PERMANENT_QUARANTINE_BY_HASH.get(document_sha256)
    if quarantine_reason is not None:
        raise ExternalDocumentAssuranceError(
            (
                AssuranceFinding(
                    "quarantine.permanent_document_hash",
                    quarantine_reason,
                    0,
                    0,
                    document_sha256,
                ),
            )
        )
    extracted_text, page_count = _extract_pdf_text(pdf_bytes)
    assert_employer_facing_text(extracted_text, document_kind=kind)
    extracted_text_sha256 = hashlib.sha256(extracted_text.encode()).hexdigest()
    return InspectedPdf(
        document_kind=kind,
        document_sha256=document_sha256,
        extracted_text_sha256=extracted_text_sha256,
        page_count=page_count,
    )


def assure_pdf_path(
    path: str | Path,
    *,
    document_kind: str,
    intended_vacancy: IntendedVacancy,
) -> ExternalDocumentAssuranceReceipt:
    """Read one regular non-symlink PDF and assure its exact bytes."""
    candidate = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover - supported production is POSIX
        raise RuntimeError("runtime lacks non-symlink file-open assurance")
    flags |= nofollow
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise ValueError("external document is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("external document must be a regular file")
        if metadata.st_size > MAX_EXTERNAL_PDF_BYTES:
            raise ValueError("external PDF exceeds the bounded assurance size")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            pdf_bytes = handle.read(MAX_EXTERNAL_PDF_BYTES + 1)
        final_metadata = os.fstat(descriptor)
        if (
            len(pdf_bytes) != metadata.st_size
            or final_metadata.st_size != metadata.st_size
            or final_metadata.st_mtime_ns != metadata.st_mtime_ns
            or final_metadata.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise ValueError("external document changed while being read")
        return assure_pdf_bytes(
            pdf_bytes,
            document_kind=document_kind,
            intended_vacancy=intended_vacancy,
        )
    finally:
        os.close(descriptor)


def verify_receipt_for_pdf(
    receipt: ExternalDocumentAssuranceReceipt,
    pdf_bytes: bytes,
    *,
    intended_vacancy: IntendedVacancy,
) -> None:
    """Re-run policy and reject byte, text, parser or policy drift."""
    current = assure_pdf_bytes(
        pdf_bytes,
        document_kind=receipt.document_kind,
        intended_vacancy=intended_vacancy,
    )
    if current != receipt:
        raise ValueError("external document differs from its assurance receipt")


def assert_application_artifacts(
    *,
    cv_pdf_bytes: bytes,
    cover_letter_pdf_bytes: bytes,
    answers_text: str,
    intended_vacancy: IntendedVacancy,
) -> tuple[ExternalDocumentAssuranceReceipt, ExternalDocumentAssuranceReceipt]:
    """Assure every outward-facing component of one application."""
    cv_receipt = assure_pdf_bytes(
        cv_pdf_bytes,
        document_kind="cv",
        intended_vacancy=intended_vacancy,
    )
    letter_receipt = assure_pdf_bytes(
        cover_letter_pdf_bytes,
        document_kind="cover_letter",
        intended_vacancy=intended_vacancy,
    )
    if answers_text.strip():
        assert_employer_facing_text(answers_text, document_kind="answer")
    return cv_receipt, letter_receipt


def _atomic_write_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = canonical_json(document) + "\n"
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _failure_document(error: ExternalDocumentAssuranceError) -> dict[str, object]:
    return {
        "schema_version": POLICY_SCHEMA,
        "verdict": "block",
        "policy_sha256": ASSURANCE_POLICY_SHA256,
        "finding_codes": tuple(finding.code for finding in error.findings),
        "findings": [finding.document() for finding in error.findings],
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed assurance for a CV or cover-letter PDF.",
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument(
        "--kind",
        required=True,
        choices=("cv", "cover_letter"),
    )
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--job-key", required=True)
    parser.add_argument("--vacancy-sha256", required=True)
    parser.add_argument("--role-title", required=True)
    parser.add_argument("--company-name", required=True)
    arguments = parser.parse_args(tuple(argv) if argv is not None else None)
    intended_vacancy = IntendedVacancy(
        job_key=arguments.job_key,
        vacancy_sha256=arguments.vacancy_sha256,
        role_title=arguments.role_title,
        company_name=arguments.company_name,
    )
    try:
        receipt = assure_pdf_path(
            arguments.input,
            document_kind=arguments.kind,
            intended_vacancy=intended_vacancy,
        )
    except ExternalDocumentAssuranceError as error:
        print(canonical_json(_failure_document(error)), file=sys.stderr)
        return 2
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(
            canonical_json(
                {
                    "schema_version": POLICY_SCHEMA,
                    "verdict": "block",
                    "policy_sha256": ASSURANCE_POLICY_SHA256,
                    "finding_codes": ("document.unverifiable",),
                    "error": str(error),
                }
            ),
            file=sys.stderr,
        )
        return 2
    if arguments.receipt is not None:
        _atomic_write_json(arguments.receipt, receipt.document())
    print(canonical_json(receipt.document()))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI boundary
    raise SystemExit(main())


__all__ = [
    "ASSURANCE_POLICY_SHA256",
    "ASSURANCE_RULES",
    "AssuranceFinding",
    "ExternalDocumentAssuranceError",
    "ExternalDocumentAssuranceReceipt",
    "InspectedPdf",
    "IntendedVacancy",
    "PERMANENT_QUARANTINED_DOCUMENTS",
    "assert_application_artifacts",
    "assert_employer_facing_text",
    "assure_pdf_bytes",
    "assure_pdf_path",
    "inspect_pdf_bytes",
    "scan_employer_facing_text",
    "verify_receipt_for_pdf",
]
