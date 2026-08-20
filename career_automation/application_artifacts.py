"""External-only, content-addressed publication for JAA-07 artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .application_compiler import ApplicationSource, verify_application_source
from .evidence_matching import canonical_json
from .rendering import (
    ApplicationArtifacts,
    validate_pdf_artifact,
    verify_application_artifacts,
)


ARTIFACT_FILENAMES = (
    "application-source.json",
    "cv.txt",
    "cover-letter.txt",
    "answers.txt",
    "cv.pdf",
    "cv.extracted.txt",
    "cover-letter.pdf",
    "cover-letter.extracted.txt",
)


@dataclass(frozen=True)
class ArtifactFileReceipt:
    filename: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if self.filename not in ARTIFACT_FILENAMES:
            raise ValueError("artifact receipt filename is unsupported")
        if len(self.sha256) != 64 or any(
            value not in "0123456789abcdef" for value in self.sha256
        ):
            raise ValueError("artifact receipt hash must be lowercase SHA-256")
        if self.size_bytes < 0:
            raise ValueError("artifact receipt size cannot be negative")


@dataclass(frozen=True)
class PublishedArtifactReceipt:
    artifact_set_sha256: str
    source_id: str
    relative_directory: str
    files: tuple[ArtifactFileReceipt, ...]
    receipt_sha256: str
    schema_version: str = "jaa07.artifact-publication.v1"
    certifies_slice: bool = False

    def __post_init__(self) -> None:
        for value, label in (
            (self.artifact_set_sha256, "artifact-set hash"),
            (self.source_id, "source ID"),
            (self.receipt_sha256, "publication receipt hash"),
        ):
            if len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                raise ValueError(f"{label} must be lowercase SHA-256")
        if self.relative_directory != self.artifact_set_sha256:
            raise ValueError("artifact publication directory must be content-addressed")
        if tuple(row.filename for row in self.files) != ARTIFACT_FILENAMES or len(
            {row.filename for row in self.files}
        ) != len(self.files):
            raise ValueError("artifact publication file inventory is incomplete")
        if self.certifies_slice is not False:
            raise ValueError("artifact publication cannot certify JAA-07")

    def document(self, *, include_receipt_hash: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "artifact_set_sha256": self.artifact_set_sha256,
            "source_id": self.source_id,
            "relative_directory": self.relative_directory,
            "files": [vars(row) for row in self.files],
            "certifies_slice": False,
        }
        if include_receipt_hash:
            result["receipt_sha256"] = self.receipt_sha256
        return result


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _external_root(
    root: str | Path,
    repository_root: str | Path,
    *,
    create: bool,
) -> Path:
    candidate = Path(root)
    repository = Path(repository_root).resolve(strict=True)
    if not repository.is_dir():
        raise ValueError("repository root must be a directory")
    if candidate.exists() and candidate.is_symlink():
        raise ValueError("artifact root cannot be a symlink")
    parent = candidate.parent.resolve(strict=True)
    resolved = parent / candidate.name
    if _overlaps(resolved, repository):
        raise ValueError("application artifacts must remain outside the repository")
    if create:
        resolved.mkdir(mode=0o700, exist_ok=True)
    elif not resolved.is_dir():
        raise KeyError(str(resolved))
    if resolved.is_symlink() or resolved.resolve(strict=True) != resolved:
        raise ValueError("artifact root cannot resolve through a symlink")
    os.chmod(resolved, 0o700)
    return resolved


def _artifact_payloads(
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
) -> Mapping[str, bytes]:
    verify_application_source(source)
    if artifacts.source_id != source.source_id:
        raise ValueError("rendered artifacts cite a different application source")
    verify_application_artifacts(artifacts)
    cv_facts = tuple(row.text for row in source.facts if row.document_kind == "cv")
    letter_facts = tuple(
        row.text for row in source.facts if row.document_kind == "cover_letter"
    )
    validate_pdf_artifact(
        artifacts.cv_pdf,
        expected_page_count=artifacts.cv_pdf.page_count,
        required_values=tuple(
            value
            for value in (
                source.contact.full_name,
                source.contact.email,
                source.contact.phone,
                source.contact.city,
                *cv_facts,
            )
            if value is not None
        ),
    )
    validate_pdf_artifact(
        artifacts.cover_letter_pdf,
        expected_page_count=1,
        required_values=tuple(
            value
            for value in (
                source.contact.full_name,
                source.contact.email,
                source.contact.phone,
                source.contact.city,
                source.role_title,
                source.company_name,
                *letter_facts,
            )
            if value is not None
        ),
    )
    return {
        "application-source.json": (
            canonical_json(source.document()).encode("utf-8") + b"\n"
        ),
        "cv.txt": artifacts.editable.cv_text.encode("utf-8"),
        "cover-letter.txt": artifacts.editable.cover_letter_text.encode("utf-8"),
        "answers.txt": artifacts.editable.answers_text.encode("utf-8"),
        "cv.pdf": artifacts.cv_pdf.pdf_bytes,
        "cv.extracted.txt": artifacts.cv_pdf.extracted_text.encode("utf-8"),
        "cover-letter.pdf": artifacts.cover_letter_pdf.pdf_bytes,
        "cover-letter.extracted.txt": (
            artifacts.cover_letter_pdf.extracted_text.encode("utf-8")
        ),
    }


def _receipt(
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
    payloads: Mapping[str, bytes],
) -> PublishedArtifactReceipt:
    files = tuple(
        ArtifactFileReceipt(
            filename,
            hashlib.sha256(payloads[filename]).hexdigest(),
            len(payloads[filename]),
        )
        for filename in ARTIFACT_FILENAMES
    )
    provisional = PublishedArtifactReceipt(
        artifacts.artifact_set_sha256,
        source.source_id,
        artifacts.artifact_set_sha256,
        files,
        "0" * 64,
    )
    receipt_hash = hashlib.sha256(
        canonical_json(provisional.document(include_receipt_hash=False)).encode()
    ).hexdigest()
    return PublishedArtifactReceipt(
        provisional.artifact_set_sha256,
        provisional.source_id,
        provisional.relative_directory,
        provisional.files,
        receipt_hash,
    )


def _read_receipt(directory: Path) -> PublishedArtifactReceipt:
    receipt_path = directory / "receipt.json"
    if receipt_path.is_symlink():
        raise ValueError("artifact receipt cannot be a symlink")
    try:
        document = json.loads(receipt_path.read_text(encoding="utf-8"))
        files = tuple(
            ArtifactFileReceipt(
                str(row["filename"]),
                str(row["sha256"]),
                int(row["size_bytes"]),
            )
            for row in document["files"]
        )
        receipt = PublishedArtifactReceipt(
            str(document["artifact_set_sha256"]),
            str(document["source_id"]),
            str(document["relative_directory"]),
            files,
            str(document["receipt_sha256"]),
            str(document["schema_version"]),
            bool(document["certifies_slice"]),
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("artifact publication receipt is invalid") from exc
    expected = hashlib.sha256(
        canonical_json(receipt.document(include_receipt_hash=False)).encode()
    ).hexdigest()
    if receipt.receipt_sha256 != expected or canonical_json(document) != canonical_json(
        receipt.document()
    ):
        raise ValueError("artifact publication receipt identity is inconsistent")
    for row in receipt.files:
        target = directory / row.filename
        if target.is_symlink() or not target.is_file():
            raise ValueError("artifact publication file is missing or unsafe")
        value = target.read_bytes()
        if (
            len(value) != row.size_bytes
            or hashlib.sha256(value).hexdigest() != row.sha256
        ):
            raise ValueError("published application artifact differs from its receipt")
    return receipt


def publish_application_artifacts(
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
    *,
    root: str | Path,
    repository_root: str | Path,
) -> PublishedArtifactReceipt:
    """Publish once outside Git; exact retries verify rather than overwrite."""
    publication_root = _external_root(root, repository_root, create=True)
    payloads = _artifact_payloads(source, artifacts)
    receipt = _receipt(source, artifacts, payloads)
    destination = publication_root / receipt.relative_directory
    if destination.exists():
        if destination.is_symlink():
            raise ValueError("artifact publication directory cannot be a symlink")
        existing = _read_receipt(destination)
        if existing != receipt:
            raise ValueError("artifact-set identity already has different content")
        return existing
    stage = Path(tempfile.mkdtemp(prefix=".jaa07-", dir=publication_root))
    try:
        os.chmod(stage, 0o700)
        for filename in ARTIFACT_FILENAMES:
            target = stage / filename
            target.write_bytes(payloads[filename])
            os.chmod(target, 0o600)
        receipt_path = stage / "receipt.json"
        receipt_path.write_text(
            canonical_json(receipt.document()) + "\n",
            encoding="utf-8",
        )
        os.chmod(receipt_path, 0o600)
        try:
            os.replace(stage, destination)
        except OSError:
            if not destination.is_dir():
                raise
            existing = _read_receipt(destination)
            if existing != receipt:
                raise ValueError(
                    "concurrent artifact publication has different content"
                )
        return _read_receipt(destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def load_published_artifacts(
    artifact_set_sha256: str,
    *,
    root: str | Path,
    repository_root: str | Path,
) -> PublishedArtifactReceipt:
    publication_root = _external_root(root, repository_root, create=False)
    if len(artifact_set_sha256) != 64 or any(
        value not in "0123456789abcdef" for value in artifact_set_sha256
    ):
        raise ValueError("artifact-set hash must be lowercase SHA-256")
    directory = publication_root / artifact_set_sha256
    if directory.is_symlink() or not directory.is_dir():
        raise KeyError(artifact_set_sha256)
    return _read_receipt(directory)


def verify_published_application_artifacts(
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
    *,
    root: str | Path,
    repository_root: str | Path,
) -> PublishedArtifactReceipt:
    """Re-hash an existing publication without creating or overwriting it."""
    payloads = _artifact_payloads(source, artifacts)
    expected = _receipt(source, artifacts, payloads)
    actual = load_published_artifacts(
        artifacts.artifact_set_sha256,
        root=root,
        repository_root=repository_root,
    )
    if actual != expected:
        raise ValueError("published artifact receipt differs from exact artifacts")
    return actual
