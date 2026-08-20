#!/usr/bin/env python3
"""Archive exact files from a non-consequential or failed observation."""

from __future__ import annotations

import argparse
import hashlib
import mimetypes
from pathlib import Path
from typing import Sequence

from career_automation.application_archive import (
    ApplicationArchive,
    ApplicationArchiveError,
    VacancyArchiveIdentity,
    verify_complete_attempt,
)
from career_automation.evidence_matching import canonical_json
from career_automation.production_queue import ProductionCheckpointLedger


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def archive_observation(
    *,
    repository_root: Path,
    archive_root: Path,
    job_key: str,
    role_title: str,
    company_name: str,
    source_url: str,
    classification: str,
    files: Sequence[Path],
    network_evidence: Path | None = None,
    boundary_description: str = "Historical non-consequential observation bundle.",
    future_queue: str = "provider_observation",
) -> dict[str, object]:
    if not files:
        raise ValueError("at least one observation file is required")
    inventory = []
    values = []
    for source in files:
        resolved = source.resolve(strict=True)
        if source.is_symlink() or not resolved.is_file():
            raise ApplicationArchiveError("observation source is not a regular file")
        value = resolved.read_bytes()
        digest = hashlib.sha256(value).hexdigest()
        inventory.append(
            {
                "filename": resolved.name,
                "sha256": digest,
                "byte_length": len(value),
            }
        )
        values.append((resolved, value, digest))
    network_value = None
    if network_evidence is not None:
        network_path = network_evidence.resolve(strict=True)
        if network_evidence.is_symlink() or not network_path.is_file():
            raise ApplicationArchiveError("network evidence is not a regular file")
        network_value = network_path.read_bytes()
    bundle = _json_bytes(
        {
            "schema_version": "jaa.observation-bundle.v1",
            "classification": classification,
            "files": inventory,
        }
    )
    vacancy = VacancyArchiveIdentity(
        job_key=job_key,
        vacancy_sha256=hashlib.sha256(bundle).hexdigest(),
        role_title=role_title,
        company_name=company_name,
        source_url=source_url,
    )
    archive = ApplicationArchive(archive_root, repository_root=repository_root)
    existing = archive.query(job_key=job_key)
    if existing:
        if len(existing) != 1 or not existing[0]["terminal_finalized"]:
            raise ApplicationArchiveError("observation archive cannot be resumed safely")
        return {
            **verify_complete_attempt(
                str(existing[0]["attempt_id"]),
                root=archive.root,
                repository_root=archive.repository_root,
            ),
            "imported": False,
        }
    attempt = archive.create_attempt(vacancy)
    ledger = ProductionCheckpointLedger(archive)
    ledger.record_attempt_started(attempt.attempt_id)
    selected = {}

    def add(role: str, value: bytes, media_type: str, **metadata: object):
        row = attempt.add_artifact(
            role,
            value,
            media_type=media_type,
            disposition="observed",
            metadata=metadata,
        )
        selected[role] = row.sha256

    add("vacancy.source_identity", _json_bytes(vacancy.document()), "application/json")
    add("vacancy.capture", bundle, "application/json")
    add("vacancy.structured", bundle, "application/json")
    add(
        "vacancy.assessment",
        _json_bytes({"non_consequential": True, "classification": classification}),
        "application/json",
    )
    for index, (source, value, digest) in enumerate(values, start=1):
        add(
            f"observation.file.{index:04d}",
            value,
            mimetypes.guess_type(source.name)[0] or "application/octet-stream",
            filename=source.name,
            source_sha256=digest,
        )
    add("browser.blocked_state_evidence", bundle, "application/json")
    add(
        "browser.redirect_http_evidence",
        network_value
        if network_value is not None
        else _json_bytes(
            {
                "schema_version": "jaa.browser-http-evidence.v1",
                "events": [],
                "availability": "not_preserved_in_legacy_record",
            }
        ),
        "application/json",
    )
    add(
        "technical.boundary",
        _json_bytes(
            {
                "classification": classification,
                "description": boundary_description,
                "future_queue": future_queue,
                "secret_value": None,
            }
        ),
        "application/json",
    )
    add(
        "submission.result",
        _json_bytes(
            {
                "state": "blocked",
                "reason": classification,
                "submit_clicks": 0,
            }
        ),
        "application/json",
    )
    required = (
        "vacancy.source_identity",
        "vacancy.capture",
        "technical.boundary",
        "submission.result",
        "browser.blocked_state_evidence",
        "browser.redirect_http_evidence",
    )
    terminal_sha256 = attempt.finalize_terminal(
        outcome="blocked",
        selected={role: selected[role] for role in required},
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--job-key", required=True)
    parser.add_argument("--role-title", required=True)
    parser.add_argument("--company-name", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--classification", required=True)
    parser.add_argument("--file", type=Path, action="append", required=True)
    parser.add_argument("--network-evidence", type=Path)
    parser.add_argument(
        "--boundary-description",
        default="Historical non-consequential observation bundle.",
    )
    parser.add_argument("--future-queue", default="provider_observation")
    arguments = parser.parse_args(argv)
    print(
        canonical_json(
            archive_observation(
                repository_root=arguments.repository_root,
                archive_root=arguments.archive_root,
                job_key=arguments.job_key,
                role_title=arguments.role_title,
                company_name=arguments.company_name,
                source_url=arguments.source_url,
                classification=arguments.classification,
                files=tuple(arguments.file),
                network_evidence=arguments.network_evidence,
                boundary_description=arguments.boundary_description,
                future_queue=arguments.future_queue,
            )
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
