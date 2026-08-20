"""Create-only archive for non-consequential candidate-package previews.

Preview generation preserves every observed byte without creating an ATS
attempt or affecting duplicate/submission state. Each value is written to the
shared content-addressed object namespace immediately, mirrored under a
human-readable run view, and bound into a hash-chained event ledger. A ready
manifest requires the exact PDFs plus deterministic and semantic PASS receipts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .evidence_matching import canonical_json
from .external_document_assurance import IntendedVacancy


PREVIEW_SCHEMA = "jaa.application-preview.v1"
EVENT_SCHEMA = "jaa.application-preview-event.v1"
MANIFEST_SCHEMA = "jaa.application-preview-manifest.v1"
PREVIEW_ID = re.compile(r"^jaa-preview-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
ROLE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
READY_ROLES = frozenset(
    {
        "candidate.authority",
        "candidate.contact_authority",
        "evidence.approved_packet",
        "generation.inputs",
        "document.source_inputs",
        "document.cv.source",
        "document.cv.final_pdf",
        "document.cv.extracted_text",
        "document.cover_letter.source",
        "document.cover_letter.final_pdf",
        "document.cover_letter.extracted_text",
        "form.answers",
        "publication.receipt",
        "assurance.cv.receipt",
        "assurance.cover_letter.receipt",
        "assurance.semantic.receipt",
    }
)
_EXTENSIONS = {
    "application/json": ".json",
    "application/pdf": ".pdf",
    "text/plain": ".txt",
    "image/png": ".png",
}
_PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


class ApplicationPreviewError(ValueError):
    """The preview ledger is unsafe, incomplete, or internally inconsistent."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_create(path: Path, value: bytes, *, mode: int = 0o400) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, mode)
        _fsync_directory(path.parent)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def _regular_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ApplicationPreviewError("preview path is not a regular file")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ApplicationPreviewError("preview path is not a regular file")
    return path.read_bytes()


@dataclass(frozen=True)
class PreviewArtifact:
    sequence: int
    role: str
    sha256: str
    media_type: str
    byte_length: int
    object_relative_path: str
    view_relative_path: str
    disposition: str

    def document(self) -> dict[str, object]:
        return vars(self)


@dataclass(frozen=True)
class ApplicationPreviewReceipt:
    preview_id: str
    status: str
    vacancy: IntendedVacancy
    manifest_sha256: str
    manifest_relative_path: str
    event_head_sha256: str
    artifact_count: int

    def __post_init__(self) -> None:
        if not PREVIEW_ID.fullmatch(self.preview_id):
            raise ValueError("preview receipt ID is invalid")
        if self.status not in {"ready", "blocked", "error"}:
            raise ValueError("preview receipt status is invalid")
        if not HEX_64.fullmatch(self.manifest_sha256):
            raise ValueError("preview manifest hash is invalid")
        if not HEX_64.fullmatch(self.event_head_sha256):
            raise ValueError("preview event head is invalid")
        if self.artifact_count < 1:
            raise ValueError("preview receipt has no artifacts")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": PREVIEW_SCHEMA,
            "preview_id": self.preview_id,
            "status": self.status,
            "vacancy": self.vacancy.document(),
            "manifest_sha256": self.manifest_sha256,
            "manifest_relative_path": self.manifest_relative_path,
            "event_head_sha256": self.event_head_sha256,
            "artifact_count": self.artifact_count,
        }


class ApplicationPreviewArchive:
    """Durable preview ledger that cannot grant submission authority."""

    def __init__(
        self,
        *,
        root: str | Path,
        repository_root: str | Path,
        vacancy: IntendedVacancy,
        candidate_authority_sha256: str,
        contact_authority_sha256: str,
        preview_id: str | None = None,
        created_at: str | None = None,
    ) -> None:
        configured = Path(root)
        if not configured.is_absolute():
            raise ApplicationPreviewError("preview archive root must be absolute")
        repository = Path(repository_root).resolve(strict=True)
        parent = configured.parent.resolve(strict=True)
        resolved = parent / configured.name
        if (
            resolved.is_symlink()
            or repository == resolved
            or repository in resolved.parents
            or resolved in repository.parents
        ):
            raise ApplicationPreviewError("preview archive must be outside the repository")
        resolved.mkdir(mode=0o700, exist_ok=True)
        os.chmod(resolved, 0o700)
        for digest, label in (
            (candidate_authority_sha256, "candidate authority"),
            (contact_authority_sha256, "contact authority"),
        ):
            if not HEX_64.fullmatch(digest):
                raise ApplicationPreviewError(f"{label} hash is invalid")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        identity = preview_id or f"jaa-preview-{stamp}-{uuid.uuid4().hex[:16]}"
        if not PREVIEW_ID.fullmatch(identity):
            raise ApplicationPreviewError("preview identity is invalid")
        self.root = resolved
        self.repository_root = repository
        self.vacancy = vacancy
        self.candidate_authority_sha256 = candidate_authority_sha256
        self.contact_authority_sha256 = contact_authority_sha256
        self.preview_id = identity
        self.path = self.root / "application-previews" / "runs" / identity
        try:
            self.path.mkdir(mode=0o700, parents=True)
        except FileExistsError as exc:
            raise ApplicationPreviewError("preview identity already exists") from exc
        (self.path / "events").mkdir(mode=0o700)
        (self.path / "artifacts").mkdir(mode=0o700)
        for path in (
            self.root / "objects",
            self.root / "application-previews" / "manifests",
        ):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._append_event(
            "preview_created",
            {
                "vacancy": vacancy.document(),
                "candidate_authority_sha256": candidate_authority_sha256,
                "contact_authority_sha256": contact_authority_sha256,
                "created_at": created_at or _utc_now(),
                "consequential_authority": False,
            },
            occurred_at=created_at,
        )

    def _event_paths(self) -> tuple[Path, ...]:
        paths = tuple(sorted((self.path / "events").iterdir()))
        for index, path in enumerate(paths, start=1):
            if (
                path.is_symlink()
                or not path.is_file()
                or path.name != f"{index:08d}.json"
            ):
                raise ApplicationPreviewError("preview event ledger is not contiguous")
        return paths

    def _events(self) -> tuple[dict[str, object], ...]:
        previous = "0" * 64
        events: list[dict[str, object]] = []
        for index, path in enumerate(self._event_paths(), start=1):
            raw = _regular_bytes(path)
            try:
                document = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ApplicationPreviewError("preview event is invalid JSON") from exc
            unsigned = dict(document)
            identity = unsigned.pop("event_sha256", None)
            if (
                raw != _json_bytes(document)
                or document.get("schema_version") != EVENT_SCHEMA
                or document.get("preview_id") != self.preview_id
                or document.get("sequence") != index
                or document.get("previous_event_sha256") != previous
                or identity != _sha256(_json_bytes(unsigned))
            ):
                raise ApplicationPreviewError("preview event chain is invalid")
            previous = str(identity)
            events.append(document)
        return tuple(events)

    def _append_event(
        self,
        event_type: str,
        payload: Mapping[str, object],
        *,
        occurred_at: str | None = None,
    ) -> dict[str, object]:
        events = self._events()
        sequence = len(events) + 1
        unsigned = {
            "schema_version": EVENT_SCHEMA,
            "preview_id": self.preview_id,
            "sequence": sequence,
            "event_type": event_type,
            "occurred_at": occurred_at or _utc_now(),
            "previous_event_sha256": (
                str(events[-1]["event_sha256"]) if events else "0" * 64
            ),
            "payload": dict(payload),
        }
        document = {**unsigned, "event_sha256": _sha256(_json_bytes(unsigned))}
        _atomic_create(
            self.path / "events" / f"{sequence:08d}.json",
            _json_bytes(document),
        )
        return document

    def add_artifact(
        self,
        *,
        role: str,
        value: bytes,
        media_type: str,
        disposition: str = "observed",
    ) -> PreviewArtifact:
        if (self.path / "receipt.json").exists():
            raise ApplicationPreviewError("finalized preview is immutable")
        if not ROLE.fullmatch(role) or not MEDIA_TYPE.fullmatch(media_type):
            raise ApplicationPreviewError("preview role or media type is invalid")
        if not isinstance(value, bytes):
            raise TypeError("preview artifacts require exact bytes")
        if _PRIVATE_KEY.search(value):
            raise ApplicationPreviewError("private keys cannot enter preview archives")
        digest = _sha256(value)
        object_path = self.root / "objects" / digest[:2] / digest
        object_path.parent.mkdir(mode=0o700, exist_ok=True)
        try:
            _atomic_create(object_path, value)
        except FileExistsError:
            if _regular_bytes(object_path) != value:
                raise ApplicationPreviewError("content-addressed object collision")
        if _sha256(_regular_bytes(object_path)) != digest:
            raise ApplicationPreviewError("preview object verification failed")
        sequence = len(self._events())
        extension = _EXTENSIONS.get(media_type, ".bin")
        view_name = f"{sequence:03d}-{role}{extension}"
        view_path = self.path / "artifacts" / view_name
        _atomic_create(view_path, value)
        event = self._append_event(
            "artifact_archived",
            {
                "role": role,
                "sha256": digest,
                "media_type": media_type,
                "byte_length": len(value),
                "object_relative_path": str(object_path.relative_to(self.root)),
                "view_relative_path": str(view_path.relative_to(self.root)),
                "disposition": disposition,
            },
        )
        return PreviewArtifact(
            int(event["sequence"]),
            role,
            digest,
            media_type,
            len(value),
            str(object_path.relative_to(self.root)),
            str(view_path.relative_to(self.root)),
            disposition,
        )

    def revision_writer(
        self,
        *,
        role: str,
        value: bytes,
        media_type: str,
        prior_sha256: str | None = None,
        approved: bool = True,
        rejection_codes: tuple[str, ...] = (),
    ) -> PreviewArtifact:
        if prior_sha256 is not None and not HEX_64.fullmatch(prior_sha256):
            raise ApplicationPreviewError("preview revision lineage is invalid")
        if approved and rejection_codes:
            raise ApplicationPreviewError(
                "approved preview revision has rejection codes"
            )
        return self.add_artifact(
            role=role,
            value=value,
            media_type=media_type,
            disposition="approved" if approved else "rejected",
        )

    def _artifacts(self) -> tuple[PreviewArtifact, ...]:
        values: list[PreviewArtifact] = []
        for event in self._events():
            if event["event_type"] != "artifact_archived":
                continue
            payload = event["payload"]
            if not isinstance(payload, Mapping):
                raise ApplicationPreviewError("preview artifact event is malformed")
            artifact = PreviewArtifact(
                int(event["sequence"]),
                str(payload["role"]),
                str(payload["sha256"]),
                str(payload["media_type"]),
                int(payload["byte_length"]),
                str(payload["object_relative_path"]),
                str(payload["view_relative_path"]),
                str(payload["disposition"]),
            )
            object_value = _regular_bytes(self.root / artifact.object_relative_path)
            view_value = _regular_bytes(self.root / artifact.view_relative_path)
            if object_value != view_value or _sha256(object_value) != artifact.sha256:
                raise ApplicationPreviewError(
                    "preview artifact differs from its ledger"
                )
            values.append(artifact)
        return tuple(values)

    def finalize(
        self,
        *,
        status: str,
        reason_code: str | None = None,
    ) -> ApplicationPreviewReceipt:
        if status not in {"ready", "blocked", "error"}:
            raise ApplicationPreviewError("preview status is invalid")
        artifacts = self._artifacts()
        roles = {row.role for row in artifacts if row.disposition == "approved"}
        if status == "ready" and not READY_ROLES <= roles:
            missing = sorted(READY_ROLES - roles)
            raise ApplicationPreviewError(
                "ready preview is missing roles: " + ", ".join(missing)
            )
        if status != "ready" and not reason_code:
            raise ApplicationPreviewError("non-ready preview requires a reason code")
        events = self._events()
        manifest = {
            "schema_version": MANIFEST_SCHEMA,
            "preview_id": self.preview_id,
            "status": status,
            "reason_code": reason_code,
            "vacancy": self.vacancy.document(),
            "candidate_authority_sha256": self.candidate_authority_sha256,
            "contact_authority_sha256": self.contact_authority_sha256,
            "event_head_sha256": events[-1]["event_sha256"],
            "artifacts": [row.document() for row in artifacts],
            "consequential_authority": False,
        }
        manifest_value = _json_bytes(manifest)
        manifest_sha256 = _sha256(manifest_value)
        manifest_path = (
            self.root
            / "application-previews"
            / "manifests"
            / f"{manifest_sha256}.json"
        )
        try:
            _atomic_create(manifest_path, manifest_value)
        except FileExistsError:
            if _regular_bytes(manifest_path) != manifest_value:
                raise ApplicationPreviewError("preview manifest collision")
        receipt = ApplicationPreviewReceipt(
            self.preview_id,
            status,
            self.vacancy,
            manifest_sha256,
            str(manifest_path.relative_to(self.root)),
            str(events[-1]["event_sha256"]),
            len(artifacts),
        )
        _atomic_create(self.path / "receipt.json", _json_bytes(receipt.document()))
        return receipt


__all__ = [
    "ApplicationPreviewArchive",
    "ApplicationPreviewError",
    "ApplicationPreviewReceipt",
    "PreviewArtifact",
    "READY_ROLES",
]
