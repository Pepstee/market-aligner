from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from career_automation.application_preview import (
    ApplicationPreviewArchive,
    ApplicationPreviewError,
    READY_ROLES,
)
from career_automation.external_document_assurance import IntendedVacancy


def _vacancy() -> IntendedVacancy:
    return IntendedVacancy(
        "greenhouse:example:123",
        hashlib.sha256(b"vacancy").hexdigest(),
        "Software Engineer",
        "Example Ltd",
    )


def _archive(tmp_path: Path) -> ApplicationPreviewArchive:
    repository = tmp_path / "repo"
    repository.mkdir()
    return ApplicationPreviewArchive(
        root=tmp_path / "archive",
        repository_root=repository,
        vacancy=_vacancy(),
        candidate_authority_sha256="a" * 64,
        contact_authority_sha256="b" * 64,
        preview_id="jaa-preview-20260810T000000Z-0123456789abcdef",
        created_at="2026-08-10T00:00:00Z",
    )


def test_preview_archives_exact_bytes_in_object_view_and_event_chain(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)
    artifact = archive.add_artifact(
        role="document.cv.final_pdf",
        value=b"%PDF-exact",
        media_type="application/pdf",
        disposition="approved",
    )
    assert (archive.root / artifact.object_relative_path).read_bytes() == b"%PDF-exact"
    assert (archive.root / artifact.view_relative_path).read_bytes() == b"%PDF-exact"
    events = archive._events()
    assert [row["event_type"] for row in events] == [
        "preview_created",
        "artifact_archived",
    ]
    assert events[1]["previous_event_sha256"] == events[0]["event_sha256"]


def test_ready_preview_requires_every_assurance_and_generation_role(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)
    archive.add_artifact(
        role="document.cv.final_pdf",
        value=b"%PDF",
        media_type="application/pdf",
    )
    with pytest.raises(ApplicationPreviewError, match="missing roles"):
        archive.finalize(status="ready")


def test_complete_ready_preview_is_content_addressed_and_immutable(
    tmp_path: Path,
) -> None:
    archive = _archive(tmp_path)
    for index, role in enumerate(sorted(READY_ROLES), start=1):
        media_type = (
            "application/pdf" if role.endswith("final_pdf") else "application/json"
        )
        archive.add_artifact(
            role=role,
            value=f"value-{index}".encode(),
            media_type=media_type,
            disposition="approved",
        )
    receipt = archive.finalize(status="ready")
    manifest_path = archive.root / receipt.manifest_relative_path
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == receipt.manifest_sha256
    document = json.loads(manifest_path.read_bytes())
    assert document["vacancy"] == _vacancy().document()
    assert document["consequential_authority"] is False
    with pytest.raises(ApplicationPreviewError, match="immutable"):
        archive.add_artifact(
            role="late.value",
            value=b"late",
            media_type="text/plain",
        )


def test_blocked_preview_preserves_failure_without_ready_roles(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    archive.add_artifact(
        role="preview.failure",
        value=b"failure",
        media_type="text/plain",
        disposition="rejected",
    )
    receipt = archive.finalize(
        status="blocked",
        reason_code="review.material_finding",
    )
    assert receipt.status == "blocked"


def test_private_key_material_is_rejected(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    with pytest.raises(ApplicationPreviewError, match="private keys"):
        archive.add_artifact(
            role="unsafe.secret",
            value=b"-----BEGIN PRIVATE KEY-----\nsecret",
            media_type="text/plain",
        )
