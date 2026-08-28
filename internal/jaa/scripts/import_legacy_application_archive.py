#!/usr/bin/env python3
"""Import legacy JAA application directories into the append-only archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
from collections.abc import Mapping
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


LEGACY_EVIDENCE_CATEGORIES = (
    "attempt_timeline",
    "job_source",
    "form_inventory",
    "entered_values",
    "documents",
    "action_timeline",
    "browser_evidence",
    "terminal_confirmation",
    "manifest_recovery",
)


def _walk_keys(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            result.add(str(key).casefold())
            result.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            result.update(_walk_keys(child))
    return result


def _path_value(value: Mapping[str, object], path: str) -> object | None:
    current: object = value
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _path_present(value: Mapping[str, object], path: str) -> bool:
    return _path_value(value, path) not in (None, "", False, (), [], {})


def _leaf_paths(value: object, prefix: str = "") -> set[str]:
    result: set[str] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = f"{prefix}.{key}".strip(".").casefold()
            result.update(_leaf_paths(child, path))
    elif isinstance(value, list):
        if value:
            result.add(prefix + "[]")
        for child in value:
            result.update(_leaf_paths(child, prefix + "[]"))
    elif value not in (None, "", False):
        result.add(prefix)
    return result


def classify_legacy_application_record(record_path: Path) -> dict[str, object]:
    """Classify evidence presence without returning private record values."""
    raw = record_path.read_bytes()
    result: dict[str, object] = {
        "record_sha256": hashlib.sha256(raw).hexdigest(),
        "byte_length": len(raw),
    }
    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        result["categories"] = {
            name: "MALFORMED" for name in LEGACY_EVIDENCE_CATEGORIES
        }
        return result
    if not isinstance(record, dict):
        result["categories"] = {
            name: "MALFORMED" for name in LEGACY_EVIDENCE_CATEGORIES
        }
        return result
    keys = _walk_keys(record)
    leaf_paths = _leaf_paths(record)

    def has(*names: str) -> bool:
        return all(name in keys for name in names)

    def any_key(*names: str) -> bool:
        return any(name in keys for name in names)

    entered_value_paths = (
        "answers",
        "preserved_answers",
        "submitted_answers",
        "verified_answers",
        "captured_answers",
        "form.questions_and_answers",
        "application_package.form_answers",
    )
    private_document_paths = (
        "submitted_cv.path",
        "submitted_cover_letter.path",
        "application_package.cv_path",
        "application_package.cover_letter_path",
        "known_packet.cv_path",
        "cv_path",
        "documents.cv.path",
        "prepared_cover_letter.path",
        "prepared_materials.cv",
        "prepared_materials.cover_letter",
        "materials.resume",
        "documents.cv.bytes",
        "cover_letter",
        "application_package.cover_letter",
        "documents",
    )
    private_documents = any(
        _path_present(record, path) for path in private_document_paths
    )
    document_hashes = any(
        "sha256" in path
        and any(token in path for token in ("cv", "resume", "cover", "document"))
        for path in leaf_paths
    )
    private_browser_evidence = any(
        "sha256" not in path
        and (
            "screenshot" in path
            or path.startswith("evidence.network_evidence")
            or path.startswith("authoritative_receipt.network_evidence")
            or path == "evidence.console_log"
        )
        for path in leaf_paths
    )
    browser_hashes = any(
        "sha256" in path
        and any(
            token in path
            for token in ("screenshot", "network", "console", "dom", "receipt")
        )
        for path in leaf_paths
    )
    terminal_evidence_keys = {
        "website_receipt",
        "gmail_confirmation",
        "authoritative_receipt",
        "receipt_evidence",
        "email_receipt",
        "gmail_receipt",
        "gmail_post_submission_confirmation",
        "receipt",
        "release",
        "submission",
    }
    terminal_evidence = any(
        key in record and record[key] not in (None, "", False, [], {})
        for key in terminal_evidence_keys
    ) or any(
        record.get(key) is False
        for key in ("website_receipt", "gmail_confirmation")
    )
    explicit_confirmation = any(
        _path_value(record, path) is True
        for path in (
            "website_receipt.present",
            "gmail_confirmation.present",
            "email_receipt.present",
            "gmail_receipt.present_at_certification_time",
        )
    ) or any(
        _path_present(record, path)
        for path in (
            "website_receipt.confirmation_url",
            "confirmation_url",
            "success_receipt_sha256",
            "receipt.website",
            "submission.receipt",
            "release.receipt_files",
            "authoritative_receipt",
            "receipt_evidence",
        )
    )
    explicit_no_confirmation = any(
        _path_value(record, path) is False
        for path in (
            "website_receipt.present",
            "gmail_confirmation.present",
            "email_receipt.present",
            "gmail_receipt.present_at_certification_time",
        )
    )
    status = record.get("status")
    submitted_status = status in {"submitted", "submitted_by_operator"}
    if submitted_status:
        terminal_class = "PRESENT" if explicit_confirmation else "MALFORMED"
    elif status == "closed":
        terminal_class = "MISSING"
    elif terminal_evidence and explicit_no_confirmation and status != "closed":
        terminal_class = "PRESENT"
    elif terminal_evidence:
        terminal_class = "MALFORMED"
    else:
        terminal_class = "MISSING"

    result["categories"] = {
        "attempt_timeline": (
            "PRESENT" if has("attempt_id", "events", "occurred_at") else "MISSING"
        ),
        "job_source": (
            "PRESENT"
            if has(
                "job_key",
                "source_url",
                "ats",
                "repository_commit",
                "repository_tree",
            )
            else "MISSING"
        ),
        "form_inventory": (
            "PRESENT"
            if has("form_inventory", "field_id", "type", "required", "options")
            else "HASH_ONLY"
            if any_key("form_inventory_sha256", "success_dom_sha256")
            else "MISSING"
        ),
        "entered_values": (
            "PRESENT"
            if has("entered_values", "provenance")
            else "PRIVATE_PRESENT"
            if any(_path_present(record, path) for path in entered_value_paths)
            else "HASH_ONLY"
            if any_key("answers_sha256", "value_sha256")
            else "MISSING"
        ),
        "documents": (
            "PRESENT"
            if has(
                "cv_sha256",
                "cover_letter_sha256",
                "cv_extracted_text",
                "cover_letter_extracted_text",
                "document_role",
            )
            else "PRIVATE_PRESENT"
            if private_documents
            else "HASH_ONLY"
            if document_hashes
            else "MISSING"
        ),
        "action_timeline": (
            "PRESENT"
            if has(
                "fill",
                "upload",
                "click",
                "navigation",
                "request",
                "response",
                "occurred_at",
            )
            else "MISSING"
        ),
        "browser_evidence": (
            "PRESENT"
            if has("screenshot", "network", "console")
            else "PRIVATE_PRESENT"
            if private_browser_evidence
            else "HASH_ONLY"
            if browser_hashes
            else "MISSING"
        ),
        "terminal_confirmation": terminal_class,
        "manifest_recovery": (
            "PRESENT"
            if has("manifest_sha256", "human_view", "recovery")
            else "MISSING"
        ),
    }
    return result


def audit_legacy_application_records(applications_root: Path) -> dict[str, object]:
    rows = []
    for path in sorted(applications_root.glob("*/application_record.json")):
        row = classify_legacy_application_record(path)
        row["record_path_sha256"] = hashlib.sha256(
            path.relative_to(applications_root).as_posix().encode("utf-8")
        ).hexdigest()
        rows.append(row)
    counts = {
        category: {
            value: sum(
                row["categories"][category] == value for row in rows
            )
            for value in (
                "PRESENT",
                "HASH_ONLY",
                "PRIVATE_PRESENT",
                "MISSING",
                "MALFORMED",
            )
        }
        for category in LEGACY_EVIDENCE_CATEGORIES
    }
    return {
        "schema_version": "jaa.legacy-application-evidence-gap-audit.v1",
        "record_count": len(rows),
        "counts": counts,
        "records": rows,
    }


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
