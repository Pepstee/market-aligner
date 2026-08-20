#!/usr/bin/env python3
"""Import legacy JAA application directories into the append-only archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
from datetime import datetime, timezone
from pathlib import Path

from career_automation.application_archive import (
    ApplicationArchive,
    ApplicationArchiveError,
    VacancyArchiveIdentity,
    _scan_secret_bytes,
    verify_complete_attempt,
)
from career_automation.evidence_matching import canonical_json
from career_automation.production_queue import ProductionCheckpointLedger


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _timestamp(record: dict[str, object], record_path: Path) -> str:
    for key in (
        "submitted_at_utc",
        "submitted_at",
        "last_checked_at_utc",
        "observed_at_utc",
    ):
        value = record.get(key)
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is not None and parsed.utcoffset() is not None:
                return parsed.astimezone(timezone.utc).isoformat()
    return datetime.fromtimestamp(
        record_path.stat().st_mtime, tz=timezone.utc
    ).isoformat()


def _attempt_id(application_id: str, record_bytes: bytes, created_at: str) -> str:
    stamp = datetime.fromisoformat(created_at).astimezone(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    suffix = hashlib.sha256(application_id.encode() + b"\0" + record_bytes).hexdigest()[:16]
    return f"jaa-{stamp}-{suffix}"


def _media_type(path: Path) -> str:
    if path.suffix.casefold() == ".md":
        return "text/markdown"
    if path.suffix.casefold() in {".yaml", ".yml"}:
        return "application/yaml"
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def _artifact_role(path: Path) -> str:
    name = path.name.casefold()
    if name == "application_record.json":
        return "legacy.application_record"
    if path.suffix.casefold() == ".pdf":
        return "legacy.document.pdf"
    if path.suffix.casefold() == ".png":
        if "confirm" in name or "receipt" in name or "success" in name:
            return "legacy.provider.receipt_screenshot"
        if "pre-submit" in name:
            return "legacy.browser.pre_submit_screenshot"
        return "legacy.browser.screenshot"
    return "legacy.application_artifact"


def _source_url(record: dict[str, object]) -> str:
    for key in (
        "job_url",
        "official_vacancy_url",
        "official_application_url",
        "official_url",
        "ranked_source_url",
        "source_url",
        "application_url",
        "confirmation_url",
        "url",
    ):
        value = record.get(key)
        if isinstance(value, str) and value.startswith(("https://", "http://")):
            return value
    vacancy = record.get("vacancy")
    if isinstance(vacancy, dict):
        for key in (
            "official_application_url",
            "official_url",
            "market_aligner_source_url",
            "job_url",
        ):
            value = vacancy.get(key)
            if isinstance(value, str) and value.startswith(("https://", "http://")):
                return value
    raise ValueError("legacy record lacks a public source URL")


def _has_confirmation(record: dict[str, object]) -> bool:
    website = record.get("website_receipt")
    email = record.get("gmail_confirmation")
    explicit = bool(
        isinstance(website, dict) and website.get("present") is True
        or isinstance(email, dict) and email.get("present") is True
    )
    if explicit:
        return True
    for key in ("receipt", "authoritative_receipt"):
        if isinstance(record.get(key), dict) and record[key]:
            return True
    if isinstance(record.get("receipt_evidence"), str) and record.get(
        "success_screenshot_sha256"
    ):
        return True
    if isinstance(record.get("success_receipt_sha256"), str):
        return True
    release = record.get("release")
    return bool(
        isinstance(release, dict)
        and any("receipt" in str(key).casefold() for key in release)
    )


def _application_identity(directory: Path, record: dict[str, object]) -> str:
    for key in ("application_id", "vacancy_id"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return directory.name


def _role_title(directory: Path, record: dict[str, object]) -> str:
    for key in ("role", "role_title"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    vacancy = record.get("vacancy")
    if isinstance(vacancy, dict):
        value = vacancy.get("title")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return directory.name


def _company_name(record: dict[str, object]) -> str:
    value = record.get("employer")
    if isinstance(value, str) and value.strip():
        return value.strip()
    vacancy = record.get("vacancy")
    if isinstance(vacancy, dict):
        value = vacancy.get("company")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "Unknown employer"


def import_directory(
    directory: Path,
    *,
    archive: ApplicationArchive,
    ledger: ProductionCheckpointLedger,
) -> dict[str, object]:
    record_path = directory / "application_record.json"
    record_bytes = record_path.read_bytes()
    record = json.loads(record_bytes)
    application_id = _application_identity(directory, record)
    job_key = f"legacy:{directory.name}"
    _scan_secret_bytes(record_bytes, "application/json")
    created_at = _timestamp(record, record_path)
    vacancy = VacancyArchiveIdentity(
        job_key=job_key,
        vacancy_sha256=hashlib.sha256(record_bytes).hexdigest(),
        role_title=_role_title(directory, record),
        company_name=_company_name(record),
        source_url=_source_url(record),
    )
    submitted = str(record.get("status") or "unknown") == "submitted"
    if submitted and not _has_confirmation(record):
        raise ApplicationArchiveError(
            "legacy submitted record lacks provider or email confirmation evidence"
        )
    source_artifacts: list[tuple[str, bytes, str, str]] = []
    rejected_files: list[dict[str, str]] = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ApplicationArchiveError("legacy application contains an unsafe path")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ApplicationArchiveError("legacy application contains an unsafe path")
        value = path.read_bytes()
        relative = path.relative_to(directory).as_posix()
        media_type = _media_type(path)
        try:
            _scan_secret_bytes(value, media_type)
        except ApplicationArchiveError as exc:
            if "secret-like value" not in str(exc):
                raise
            rejected_files.append(
                {
                    "source_relative_path": relative,
                    "sha256": hashlib.sha256(value).hexdigest(),
                    "reason": "secret_like_bytes_excluded",
                }
            )
            continue
        source_artifacts.append((_artifact_role(path), value, media_type, relative))
    existing = archive.query(job_key=job_key)
    if len(existing) > 1:
        raise ApplicationArchiveError("legacy application has duplicate imports")
    if existing and existing[0]["terminal_finalized"]:
        return {
            **verify_complete_attempt(
                str(existing[0]["attempt_id"]),
                root=archive.root,
                repository_root=archive.repository_root,
            ),
            "imported": False,
        }
    if existing:
        attempt = archive.open_attempt(str(existing[0]["attempt_id"]))
        if attempt.vacancy != vacancy:
            raise ApplicationArchiveError("legacy import identity changed during resume")
        checkpoint_rows = ledger.verify()
        matching = [
            row for row in checkpoint_rows if row["attempt_id"] == attempt.attempt_id
        ]
        if len(matching) != 1 or matching[0]["event_type"] != "attempt_started":
            raise ApplicationArchiveError("legacy import checkpoint cannot be resumed")
    else:
        attempt = archive.create_attempt(
            vacancy,
            attempt_id=_attempt_id(application_id, record_bytes, created_at),
            created_at=created_at,
        )
        ledger.record_attempt_started(attempt.attempt_id)
    selected: dict[str, str] = {}

    def add(role: str, value: bytes, media_type: str, **metadata: object):
        row = attempt.add_artifact(
            role,
            value,
            media_type=media_type,
            disposition="observed",
            metadata={"legacy_import": True, **metadata},
            created_at=created_at,
        )
        selected[role] = row.sha256
        return row

    add("vacancy.source_identity", _json_bytes(vacancy.document()), "application/json")
    add("vacancy.capture", record_bytes, "application/json")
    add("vacancy.structured", record_bytes, "application/json")
    add(
        "vacancy.assessment",
        _json_bytes(
            {
                "legacy_status": record.get("status"),
                "market_aligner_rank": record.get("market_aligner_rank"),
                "attempts": record.get("attempts"),
            }
        ),
        "application/json",
    )
    for role, value, media_type, relative in source_artifacts:
        add(
            role,
            value,
            media_type,
            source_relative_path=relative,
        )
    if rejected_files:
        add(
            "legacy.secret_exclusion_receipt",
            _json_bytes({"excluded": rejected_files}),
            "application/json",
        )
    status = str(record.get("status") or "unknown")
    add("submission.result", record_bytes, "application/json")
    add(
        "browser.redirect_http_evidence",
        _json_bytes(
            {
                "schema_version": "jaa.browser-http-evidence.v1",
                "events": [],
                "availability": "not_preserved_in_legacy_record",
            }
        ),
        "application/json",
    )
    if submitted:
        add("provider.confirmation_evidence", record_bytes, "application/json")
        outcome = "historical_submitted_success"
        required = (
            "vacancy.source_identity",
            "vacancy.capture",
            "submission.result",
            "provider.confirmation_evidence",
            "browser.redirect_http_evidence",
        )
    else:
        add(
            "technical.boundary",
            _json_bytes(
                {
                    "classification": status,
                    "description": record.get("gate")
                    or record.get("last_confirmed_state")
                    or record.get("safe_next_action"),
                    "future_queue": "legacy_blocked_or_gated",
                    "secret_value": None,
                }
            ),
            "application/json",
        )
        add("browser.blocked_state_evidence", record_bytes, "application/json")
        outcome = "blocked"
        required = (
            "vacancy.source_identity",
            "vacancy.capture",
            "submission.result",
            "technical.boundary",
            "browser.blocked_state_evidence",
            "browser.redirect_http_evidence",
        )
    terminal_sha256 = attempt.finalize_terminal(
        outcome=outcome,
        selected={role: selected[role] for role in required},
        finalized_at=created_at,
    )
    ledger.record_attempt_terminal(attempt.attempt_id)
    return {
        **verify_complete_attempt(
            attempt.attempt_id,
            root=archive.root,
            repository_root=archive.repository_root,
        ),
        "terminal_manifest_sha256": terminal_sha256,
        "imported": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--applications-root", type=Path, required=True)
    arguments = parser.parse_args()
    archive = ApplicationArchive(
        arguments.archive_root,
        repository_root=arguments.repository_root,
    )
    ledger = ProductionCheckpointLedger(archive)
    results = []
    for record_path in sorted(arguments.applications_root.glob("*/application_record.json")):
        results.append(
            import_directory(record_path.parent, archive=archive, ledger=ledger)
        )
    summary = {
        "schema_version": "jaa.legacy-application-import.v1",
        "application_count": len(results),
        "imported_count": sum(row["imported"] is True for row in results),
        "verified_count": sum(row["verified"] is True for row in results),
        "outcomes": {
            outcome: sum(row["outcome"] == outcome for row in results)
            for outcome in sorted({str(row["outcome"]) for row in results})
        },
        "terminal_manifest_sha256s": sorted(
            str(row["terminal_manifest_sha256"])
            for row in results
            if row.get("terminal_manifest_sha256")
        ),
    }
    print(canonical_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
