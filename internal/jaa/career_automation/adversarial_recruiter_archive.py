"""Create-only archive for detached recruiter diagnostics.

This is intentionally separate from :mod:`application_archive`: that archive
is a consequential release ledger with submission-required roles.  A detached
recruiter assessment has a different lifecycle and must never become release
evidence merely because it was persisted.

Only the already-validated recruiter receipt is stored.  The CV, cover letter,
listing, and form answers are represented exclusively by the exact hashes in
that receipt, avoiding a second raw copy of candidate PII.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .adversarial_recruiter import (
    RECEIPT_SCHEMA_VERSION,
    RecruiterAssessmentReceipt,
)
from .adversarial_recruiter_runtime import (
    RUNTIME_SCHEMA_VERSION,
    DetachedRecruiterRun,
    DetachedTransportReceipt,
)
from .evidence_matching import canonical_json, content_hash
from .external_document_assurance import IntendedVacancy


ARCHIVE_SCHEMA_VERSION = "jaa.adversarial-recruiter-archive.v2"
ARCHIVE_RECEIPT_SCHEMA_VERSION = "jaa.adversarial-recruiter-archive-receipt.v2"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_HASH_KEYS = frozenset(
    {
        "listing_text_sha256",
        "cv_pdf_sha256",
        "cv_text_sha256",
        "cover_letter_pdf_sha256",
        "cover_letter_text_sha256",
        "form_fields_sha256",
    }
)


class RecruiterDiagnosticArchiveError(ValueError):
    """The diagnostic archive is unsafe, incomplete, or has been altered."""


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise RecruiterDiagnosticArchiveError(f"{label} is not lowercase SHA-256")
    return value


def _package_hashes(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != PACKAGE_HASH_KEYS:
        raise RecruiterDiagnosticArchiveError("archived package hashes are incomplete")
    return {str(key): _digest(item, f"package hash {key}") for key, item in value.items()}


def _safe_root(root: Path, *, create: bool) -> Path:
    candidate = Path(root)
    if not candidate.is_absolute():
        raise RecruiterDiagnosticArchiveError("diagnostic archive root must be absolute")
    if candidate.exists():
        if candidate.is_symlink() or not candidate.is_dir():
            raise RecruiterDiagnosticArchiveError("diagnostic archive root is unsafe")
    elif create:
        candidate.mkdir(mode=0o700, parents=True)
    else:
        raise RecruiterDiagnosticArchiveError("diagnostic archive root is unavailable")
    return candidate.resolve(strict=True)


def _safe_path(root: Path, relative: str) -> Path:
    value = Path(relative)
    if value.is_absolute() or ".." in value.parts or str(value) != relative:
        raise RecruiterDiagnosticArchiveError("diagnostic archive path is invalid")
    candidate = root / value
    current = root
    for part in value.parts[:-1]:
        current = current / part
        if current.exists() and current.is_symlink():
            raise RecruiterDiagnosticArchiveError("diagnostic archive path uses a symlink")
    if candidate.exists() and candidate.is_symlink():
        raise RecruiterDiagnosticArchiveError("diagnostic archive path uses a symlink")
    return candidate


def _regular_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise RecruiterDiagnosticArchiveError("diagnostic archive object is not regular")
    return path.read_bytes()


def _create_or_verify(root: Path, relative: str, value: bytes) -> Path:
    path = _safe_path(root, relative)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = _safe_path(root, relative)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o400)
    except FileExistsError:
        if _regular_bytes(path) != value:
            raise RecruiterDiagnosticArchiveError(
                "existing diagnostic archive object differs"
            )
        return path
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o400)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    if _regular_bytes(path) != value:
        raise RecruiterDiagnosticArchiveError("diagnostic archive write changed")
    return path


def _strict_json(value: bytes, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise RecruiterDiagnosticArchiveError(f"duplicate key in {label}")
            result[key] = item
        return result

    try:
        result = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                RecruiterDiagnosticArchiveError(f"non-finite value in {label}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecruiterDiagnosticArchiveError(f"{label} is invalid JSON") from exc
    if not isinstance(result, dict) or _json_bytes(result) != value:
        raise RecruiterDiagnosticArchiveError(f"{label} is not canonical JSON")
    return result


def _validated_transport(receipt: DetachedTransportReceipt) -> DetachedTransportReceipt:
    if not isinstance(receipt, DetachedTransportReceipt):
        raise TypeError("diagnostic archive requires a DetachedTransportReceipt")
    try:
        receipt.__post_init__()
    except ValueError as exc:
        raise RecruiterDiagnosticArchiveError("transport receipt validation failed") from exc
    if receipt.schema_version != RUNTIME_SCHEMA_VERSION:
        raise RecruiterDiagnosticArchiveError("transport receipt schema is stale")
    for value, label in (
        (receipt.provider_sha256, "transport provider hash"),
        (receipt.model_sha256, "transport model hash"),
        (receipt.transport_sha256, "transport policy hash"),
        (receipt.request_sha256, "transport request hash"),
        (receipt.response_sha256, "transport response hash"),
        (receipt.binary_sha256, "transport binary hash"),
        (receipt.receipt_sha256, "transport receipt hash"),
    ):
        _digest(value, label)
    if not receipt.provider_identity or not receipt.model_identity:
        raise RecruiterDiagnosticArchiveError("transport identity is incomplete")
    if receipt.provider_sha256 != content_hash({"provider": receipt.provider_identity}):
        raise RecruiterDiagnosticArchiveError("transport provider identity differs")
    if receipt.model_sha256 != content_hash({"model": receipt.model_identity}):
        raise RecruiterDiagnosticArchiveError("transport model identity differs")
    return receipt


def _transport_from_document(document: Mapping[str, object]) -> DetachedTransportReceipt:
    expected = {
        "schema_version", "provider_identity", "provider_sha256", "model_identity",
        "model_sha256", "transport_sha256", "request_sha256", "response_sha256",
        "binary_sha256", "invocation_count", "cache_enabled", "history_enabled",
        "tools_enabled", "retrieval_enabled", "receipt_sha256",
    }
    if set(document) != expected or any(
        document.get(key) is not False
        for key in ("cache_enabled", "history_enabled", "tools_enabled", "retrieval_enabled")
    ):
        raise RecruiterDiagnosticArchiveError("transport receipt shape is invalid")
    try:
        return _validated_transport(
            DetachedTransportReceipt(
                provider_identity=str(document["provider_identity"]),
                provider_sha256=str(document["provider_sha256"]),
                model_identity=str(document["model_identity"]),
                model_sha256=str(document["model_sha256"]),
                transport_sha256=str(document["transport_sha256"]),
                request_sha256=str(document["request_sha256"]),
                response_sha256=str(document["response_sha256"]),
                binary_sha256=str(document["binary_sha256"]),
                invocation_count=document["invocation_count"],
                receipt_sha256=str(document["receipt_sha256"]),
                schema_version=str(document["schema_version"]),
            )
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, RecruiterDiagnosticArchiveError):
            raise
        raise RecruiterDiagnosticArchiveError("transport receipt validation failed") from exc


def _assessment_from_document(document: Mapping[str, object]) -> RecruiterAssessmentReceipt:
    expected = {
        "schema_version", "package_hashes", "intended_vacancy",
        "vacancy_intent_sha256", "prompt_sha256", "schema_sha256",
        "policy_sha256", "backend_identity", "model_identity", "model_result",
        "model_result_sha256", "release_authority", "mutation_authority",
        "receipt_sha256",
    }
    if set(document) != expected or document.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise RecruiterDiagnosticArchiveError("assessment receipt shape is invalid")
    vacancy = document.get("intended_vacancy")
    result = document.get("model_result")
    if not isinstance(vacancy, Mapping) or set(vacancy) != {
        "job_key", "vacancy_sha256", "role_title", "company_name"
    } or not isinstance(result, Mapping):
        raise RecruiterDiagnosticArchiveError("assessment receipt content is invalid")
    try:
        intended = IntendedVacancy(
            job_key=str(vacancy["job_key"]),
            vacancy_sha256=str(vacancy["vacancy_sha256"]),
            role_title=str(vacancy["role_title"]),
            company_name=str(vacancy["company_name"]),
        )
        if document.get("vacancy_intent_sha256") != intended.intent_sha256:
            raise RecruiterDiagnosticArchiveError("vacancy intent hash differs")
        return RecruiterAssessmentReceipt(
            package_hashes=_package_hashes(document["package_hashes"]),
            intended_vacancy=intended,
            prompt_sha256=str(document["prompt_sha256"]),
            schema_sha256=str(document["schema_sha256"]),
            policy_sha256=str(document["policy_sha256"]),
            backend_identity=str(document["backend_identity"]),
            model_identity=str(document["model_identity"]),
            model_result=dict(result),
            model_result_sha256=str(document["model_result_sha256"]),
            receipt_sha256=str(document["receipt_sha256"]),
            release_authority=document["release_authority"],
            mutation_authority=document["mutation_authority"],
            schema_version=str(document["schema_version"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, RecruiterDiagnosticArchiveError):
            raise
        raise RecruiterDiagnosticArchiveError("assessment receipt validation failed") from exc


@dataclass(frozen=True)
class RecruiterDiagnosticArchiveReceipt:
    assessment_receipt_sha256: str
    model_result_sha256: str
    package_hashes: Mapping[str, str]
    transport_receipt_sha256: str
    transport_sha256: str
    request_sha256: str
    response_sha256: str
    binary_sha256: str
    provider_sha256: str
    model_sha256: str
    assessment_object_sha256: str
    transport_object_sha256: str
    manifest_sha256: str
    manifest_relative_path: str
    diagnostic_only: bool = True
    release_authority: bool = False
    mutation_authority: bool = False
    submission_authority: bool = False
    schema_version: str = ARCHIVE_RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for value, label in (
            (self.assessment_receipt_sha256, "assessment receipt hash"),
            (self.model_result_sha256, "model result hash"),
            (self.assessment_object_sha256, "assessment object hash"),
            (self.transport_receipt_sha256, "transport receipt hash"),
            (self.transport_sha256, "transport policy hash"),
            (self.request_sha256, "transport request hash"),
            (self.response_sha256, "transport response hash"),
            (self.binary_sha256, "transport binary hash"),
            (self.provider_sha256, "transport provider hash"),
            (self.model_sha256, "transport model hash"),
            (self.transport_object_sha256, "transport object hash"),
            (self.manifest_sha256, "manifest hash"),
        ):
            _digest(value, label)
        _package_hashes(self.package_hashes)
        if self.manifest_relative_path != f"manifests/{self.manifest_sha256}.json":
            raise RecruiterDiagnosticArchiveError("manifest path is not content-addressed")
        if self.diagnostic_only is not True or any(
            (self.release_authority, self.mutation_authority, self.submission_authority)
        ):
            raise RecruiterDiagnosticArchiveError("diagnostic archive cannot carry authority")


def archive_recruiter_diagnostic(
    receipt: RecruiterAssessmentReceipt,
    transport: DetachedTransportReceipt,
    *,
    root: Path,
) -> RecruiterDiagnosticArchiveReceipt:
    """Persist one validated assessment and its detached transport evidence."""
    if not isinstance(receipt, RecruiterAssessmentReceipt):
        raise TypeError("diagnostic archive requires a RecruiterAssessmentReceipt")
    receipt.__post_init__()
    transport = _validated_transport(transport)
    if receipt.model_identity != transport.model_identity:
        raise RecruiterDiagnosticArchiveError("assessment and transport models differ")
    package_hashes = _package_hashes(receipt.package_hashes)
    archive_root = _safe_root(root, create=True)
    assessment_bytes = _json_bytes(receipt.document())
    object_sha256 = _sha256(assessment_bytes)
    transport_bytes = _json_bytes(transport.document())
    transport_object_sha256 = _sha256(transport_bytes)
    _create_or_verify(
        archive_root,
        f"objects/{object_sha256[:2]}/{object_sha256}.json",
        assessment_bytes,
    )
    _create_or_verify(
        archive_root,
        f"objects/{transport_object_sha256[:2]}/{transport_object_sha256}.json",
        transport_bytes,
    )
    manifest = {
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "diagnostic_only": True,
        "release_authority": False,
        "mutation_authority": False,
        "submission_authority": False,
        "assessment_receipt_sha256": receipt.receipt_sha256,
        "assessment_object_sha256": object_sha256,
        "model_result_sha256": receipt.model_result_sha256,
        "package_hashes": package_hashes,
        "transport_receipt_sha256": transport.receipt_sha256,
        "transport_object_sha256": transport_object_sha256,
        "transport_sha256": transport.transport_sha256,
        "request_sha256": transport.request_sha256,
        "response_sha256": transport.response_sha256,
        "binary_sha256": transport.binary_sha256,
        "provider_sha256": transport.provider_sha256,
        "model_sha256": transport.model_sha256,
    }
    manifest_bytes = _json_bytes(manifest)
    manifest_sha256 = _sha256(manifest_bytes)
    relative = f"manifests/{manifest_sha256}.json"
    _create_or_verify(archive_root, relative, manifest_bytes)
    archived = RecruiterDiagnosticArchiveReceipt(
        assessment_receipt_sha256=receipt.receipt_sha256,
        model_result_sha256=receipt.model_result_sha256,
        package_hashes=package_hashes,
        transport_receipt_sha256=transport.receipt_sha256,
        transport_sha256=transport.transport_sha256,
        request_sha256=transport.request_sha256,
        response_sha256=transport.response_sha256,
        binary_sha256=transport.binary_sha256,
        provider_sha256=transport.provider_sha256,
        model_sha256=transport.model_sha256,
        assessment_object_sha256=object_sha256,
        transport_object_sha256=transport_object_sha256,
        manifest_sha256=manifest_sha256,
        manifest_relative_path=relative,
    )
    verify_recruiter_diagnostic_archive(archived, root=archive_root)
    return archived


def verify_recruiter_diagnostic_archive(
    receipt: RecruiterDiagnosticArchiveReceipt, *, root: Path
) -> DetachedRecruiterRun:
    """Verify and replay an archive using only local bytes, without a provider."""
    receipt.__post_init__()
    archive_root = _safe_root(root, create=False)
    manifest_bytes = _regular_bytes(_safe_path(archive_root, receipt.manifest_relative_path))
    if _sha256(manifest_bytes) != receipt.manifest_sha256:
        raise RecruiterDiagnosticArchiveError("diagnostic manifest hash differs")
    manifest = _strict_json(manifest_bytes, "diagnostic manifest")
    expected_manifest = {
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "diagnostic_only": True,
        "release_authority": False,
        "mutation_authority": False,
        "submission_authority": False,
        "assessment_receipt_sha256": receipt.assessment_receipt_sha256,
        "assessment_object_sha256": receipt.assessment_object_sha256,
        "model_result_sha256": receipt.model_result_sha256,
        "package_hashes": dict(receipt.package_hashes),
        "transport_receipt_sha256": receipt.transport_receipt_sha256,
        "transport_object_sha256": receipt.transport_object_sha256,
        "transport_sha256": receipt.transport_sha256,
        "request_sha256": receipt.request_sha256,
        "response_sha256": receipt.response_sha256,
        "binary_sha256": receipt.binary_sha256,
        "provider_sha256": receipt.provider_sha256,
        "model_sha256": receipt.model_sha256,
    }
    if manifest != expected_manifest:
        raise RecruiterDiagnosticArchiveError("diagnostic manifest differs from receipt")
    object_path = _safe_path(
        archive_root,
        f"objects/{receipt.assessment_object_sha256[:2]}/"
        f"{receipt.assessment_object_sha256}.json",
    )
    assessment_bytes = _regular_bytes(object_path)
    if _sha256(assessment_bytes) != receipt.assessment_object_sha256:
        raise RecruiterDiagnosticArchiveError("assessment object hash differs")
    assessment = _assessment_from_document(
        _strict_json(assessment_bytes, "assessment receipt")
    )
    transport_path = _safe_path(
        archive_root,
        f"objects/{receipt.transport_object_sha256[:2]}/"
        f"{receipt.transport_object_sha256}.json",
    )
    transport_bytes = _regular_bytes(transport_path)
    if _sha256(transport_bytes) != receipt.transport_object_sha256:
        raise RecruiterDiagnosticArchiveError("transport object hash differs")
    transport = _transport_from_document(
        _strict_json(transport_bytes, "transport receipt")
    )
    if (
        assessment.receipt_sha256 != receipt.assessment_receipt_sha256
        or assessment.model_result_sha256 != receipt.model_result_sha256
        or dict(assessment.package_hashes) != dict(receipt.package_hashes)
        or transport.receipt_sha256 != receipt.transport_receipt_sha256
        or transport.transport_sha256 != receipt.transport_sha256
        or transport.request_sha256 != receipt.request_sha256
        or transport.response_sha256 != receipt.response_sha256
        or transport.binary_sha256 != receipt.binary_sha256
        or transport.provider_sha256 != receipt.provider_sha256
        or transport.model_sha256 != receipt.model_sha256
        or assessment.model_identity != transport.model_identity
    ):
        raise RecruiterDiagnosticArchiveError("assessment hashes differ from manifest")
    return DetachedRecruiterRun(assessment=assessment, transport=transport)


__all__ = [
    "ARCHIVE_RECEIPT_SCHEMA_VERSION",
    "ARCHIVE_SCHEMA_VERSION",
    "RecruiterDiagnosticArchiveError",
    "RecruiterDiagnosticArchiveReceipt",
    "archive_recruiter_diagnostic",
    "verify_recruiter_diagnostic_archive",
]
