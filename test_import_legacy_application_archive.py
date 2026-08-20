from __future__ import annotations

import json
from pathlib import Path

from career_automation.application_archive import ApplicationArchive
from career_automation.production_queue import ProductionCheckpointLedger
from scripts.import_legacy_application_archive import import_directory


ROOT = Path(__file__).resolve().parent


def _write_record(directory: Path, document: dict[str, object]) -> None:
    directory.mkdir(parents=True)
    (directory / "application_record.json").write_text(
        json.dumps(document), encoding="utf-8"
    )


def test_legacy_import_is_terminal_content_addressed_and_idempotent(
    tmp_path: Path,
) -> None:
    source = tmp_path / "applications" / "legacy-example"
    _write_record(
        source,
        {
            "vacancy_id": "123",
            "employer": "Example",
            "role_title": "Engineer",
            "official_application_url": "https://example.test/jobs/123",
            "status": "submitted",
            "submitted_at": "2026-08-04T10:00:00Z",
            "receipt_evidence": "receipt.png",
            "success_screenshot_sha256": "a" * 64,
        },
    )
    (source / "receipt.png").write_bytes(b"receipt image")
    (source / "request.txt").write_text(
        "Authorization: Bearer definitely-secret-value", encoding="utf-8"
    )
    archive = ApplicationArchive(tmp_path / "archive", repository_root=ROOT)
    ledger = ProductionCheckpointLedger(archive)

    first = import_directory(source, archive=archive, ledger=ledger)
    second = import_directory(source, archive=archive, ledger=ledger)

    assert first["verified"] is True
    assert first["outcome"] == "historical_submitted_success"
    assert first["imported"] is True
    assert second["verified"] is True
    assert second["imported"] is False
    assert len(archive.query()) == 1
    assert len(ledger.verify()) == 2
    attempt = archive.open_attempt(str(first["attempt_id"]))
    objects = attempt._objects(attempt._events())
    exclusion = next(
        row for row in objects if row.role == "legacy.secret_exclusion_receipt"
    )
    assert exclusion.sha256
    assert b"definitely-secret-value" not in b"".join(
        path.read_bytes()
        for path in (archive.root / "objects").rglob("*")
        if path.is_file()
    )


def test_legacy_non_submit_status_is_archived_as_blocked(tmp_path: Path) -> None:
    source = tmp_path / "applications" / "blocked-example"
    _write_record(
        source,
        {
            "application_id": "blocked-example",
            "employer": "Example",
            "role": "Engineer",
            "job_url": "https://example.test/jobs/blocked",
            "status": "blocked_human_verification",
            "safe_next_action": "Manual CAPTCHA handoff only",
        },
    )
    archive = ApplicationArchive(tmp_path / "archive", repository_root=ROOT)
    result = import_directory(
        source,
        archive=archive,
        ledger=ProductionCheckpointLedger(archive),
    )

    assert result["verified"] is True
    assert result["outcome"] == "blocked"
    assert result["imported"] is True
