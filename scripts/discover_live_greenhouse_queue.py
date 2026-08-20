#!/usr/bin/env python3
"""Fetch, archive and classify current Greenhouse vacancies without interaction."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from scrapling.fetchers import AsyncFetcher

from career_automation.application_archive import (
    ApplicationArchive,
    VacancyArchiveIdentity,
    verify_complete_attempt,
)
from career_automation.evidence_matching import canonical_json
from career_automation.greenhouse_live_discovery import (
    classify_greenhouse_response,
)
from career_automation.production_queue import (
    LiveVacancy,
    ProductionCheckpointLedger,
    build_ascending_queue,
    prior_attempts_from_archive,
)


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_output(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            if path.read_bytes() != value:
                raise FileExistsError(
                    f"refusing to replace differing queue output: {path}"
                )
        else:
            os.link(temporary, path, follow_symlinks=False)
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _candidate(entry: dict[str, object], observed_at: str) -> LiveVacancy:
    score = _json_bytes(entry)
    return LiveVacancy.create(
        vacancy=VacancyArchiveIdentity(
            job_key=str(entry["key"]),
            vacancy_sha256=str(entry["raw_sha256"]),
            role_title=str(entry["job_title"]).strip(),
            company_name=str(entry["company"]).strip(),
            source_url=str(entry["url"]),
        ),
        provider="greenhouse",
        fit_score=entry["fit"],
        live=True,
        eligible=True,
        duplicate=False,
        live_verified_at=observed_at,
        scoring_inputs_sha256=hashlib.sha256(score).hexdigest(),
    )


async def _fetch_one(entry: dict[str, object], semaphore: asyncio.Semaphore):
    url = str(entry["url"])
    async with semaphore:
        try:
            response = await AsyncFetcher.get(
                url,
                timeout=30,
                retries=1,
                follow_redirects=True,
                stealthy_headers=False,
            )
        except Exception as exc:  # network failures are evidence, not fatal queue state
            return {
                "entry": entry,
                "body": _json_bytes(
                    {
                        "error_type": type(exc).__name__,
                        "message": str(exc),
                        "url": url,
                    }
                ),
                "status": None,
                "final_url": url,
                "events": [],
                "availability": "no_response_event_observed_after_listener_started",
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
        history = []
        previous_url = None
        for row in response.history:
            history_status = getattr(row, "status", None)
            if history_status is None:
                history_status = getattr(row, "status_code", None)
            history_url = getattr(row, "url", None)
            if not isinstance(history_status, int) or not history_url:
                continue
            history.append(
                {
                    "url": str(history_url),
                    "status": history_status,
                    "method": "GET",
                    "redirected_from": previous_url,
                }
            )
            previous_url = str(history_url)
        history.append(
            {
                "url": str(response.url),
                "status": int(response.status),
                "method": "GET",
                "redirected_from": previous_url,
            }
        )
        return {
            "entry": entry,
            "body": bytes(response.body),
            "status": int(response.status),
            "final_url": str(response.url),
            "events": history,
            "availability": "observed",
            "error": None,
        }


async def _fetch_all(entries: list[dict[str, object]], concurrency: int):
    semaphore = asyncio.Semaphore(concurrency)
    return await asyncio.gather(*(_fetch_one(row, semaphore) for row in entries))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--refresh-cohort",
        type=Path,
        default=None,
        help="prior canonical discovery whose pending job keys bound this refresh",
    )
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument(
        "--retry-repairable-preclick-blocks",
        action="store_true",
        help=(
            "refresh vacancies whose only prior terminal state is a certified "
            "pre-click human-verification block"
        ),
    )
    arguments = parser.parse_args(argv)
    if not 1 <= arguments.concurrency <= 4:
        parser.error("--concurrency must be between 1 and 4")

    repository_root = arguments.repository_root.resolve(strict=True)
    snapshot_path = arguments.snapshot.resolve(strict=True)
    snapshot_bytes = snapshot_path.read_bytes()
    snapshot_sha256 = hashlib.sha256(snapshot_bytes).hexdigest()
    snapshot = json.loads(snapshot_bytes)
    entries = [
        row
        for row in snapshot["entries"]
        if isinstance(row, dict) and row.get("board") == "greenhouse"
    ]
    refresh_cohort_sha256 = None
    if arguments.refresh_cohort is not None:
        cohort_path = arguments.refresh_cohort.resolve(strict=True)
        cohort_bytes = cohort_path.read_bytes()
        cohort = json.loads(cohort_bytes)
        pending = cohort.get("live_pending_eligibility")
        if (
            cohort_bytes != _json_bytes(cohort)
            or cohort.get("schema_version") != "jaa.greenhouse-live-discovery.v2"
            or not isinstance(pending, list)
            or not pending
        ):
            raise ValueError("refresh cohort is not a canonical live discovery")
        cohort_keys = {
            str(row["job_key"])
            for row in pending
            if isinstance(row, dict) and isinstance(row.get("job_key"), str)
        }
        if len(cohort_keys) != len(pending):
            raise ValueError("refresh cohort contains duplicate or malformed job keys")
        entries = [row for row in entries if row.get("key") in cohort_keys]
        if {str(row.get("key")) for row in entries} != cohort_keys:
            raise ValueError(
                "source snapshot does not contain the complete refresh cohort"
            )
        refresh_cohort_sha256 = hashlib.sha256(cohort_bytes).hexdigest()
    observed_at = _utc_now()
    archive = ApplicationArchive(
        arguments.archive_root,
        repository_root=repository_root,
    )
    prior = prior_attempts_from_archive(archive)
    preliminary = build_ascending_queue(
        (_candidate(row, observed_at) for row in entries),
        prior_attempts=prior,
        as_of=datetime.fromisoformat(observed_at.replace("Z", "+00:00")),
        retry_repairable_preclick_blocks=(arguments.retry_repairable_preclick_blocks),
    )
    eligible_keys = {row.vacancy.vacancy.job_key for row in preliminary.ready}
    fetch_entries = [row for row in entries if row["key"] in eligible_keys]

    stamp = observed_at.replace("-", "").replace(":", "").replace("+00:00", "Z")
    attempt = archive.create_attempt(
        VacancyArchiveIdentity(
            job_key=f"observation:greenhouse-live-queue:{snapshot_sha256[:16]}:{stamp}",
            vacancy_sha256=snapshot_sha256,
            role_title="Read-only Greenhouse live queue discovery",
            company_name="JAA local operations",
            source_url=f"https://local.invalid/greenhouse-live-queue/{snapshot_sha256}",
        )
    )
    ledger = ProductionCheckpointLedger(archive)
    ledger.record_attempt_started(attempt.attempt_id)
    archived: dict[str, str] = {}

    def add(role: str, value: bytes, media_type: str, **metadata: object) -> str:
        row = attempt.add_artifact(
            role,
            value,
            media_type=media_type,
            disposition="observed",
            metadata=metadata,
        )
        archived[role] = row.sha256
        return row.sha256

    source_identity = _json_bytes(attempt.vacancy.document())
    add("vacancy.source_identity", source_identity, "application/json")
    add(
        "observation.source_snapshot",
        snapshot_bytes,
        "application/json",
        source_sha256=snapshot_sha256,
    )
    fetched = asyncio.run(_fetch_all(fetch_entries, arguments.concurrency))
    live_candidates: list[LiveVacancy] = []
    observations = []
    for index, result in enumerate(fetched, start=1):
        entry = result["entry"]
        body = result["body"]
        body_sha256 = hashlib.sha256(body).hexdigest()
        response_role = f"observation.response.{index:04d}"
        add(
            response_role,
            body,
            "text/html" if result["status"] is not None else "application/json",
            source_url=str(entry["url"]),
            response_status=result["status"],
        )
        network = {
            "schema_version": "jaa.browser-http-evidence.v1",
            "events": result["events"],
            "availability": result["availability"],
        }
        add(
            f"observation.network.{index:04d}",
            _json_bytes(network),
            "application/json",
        )
        if result["status"] is None:
            verdict = {
                "live": False,
                "reason": "network_fetch_failed",
                "active_markers": [],
                "closed_markers": [],
                "title_bound": False,
                "requisition_bound": False,
            }
        else:
            verdict = classify_greenhouse_response(
                requested_url=str(entry["url"]),
                final_url=str(result["final_url"]),
                status=int(result["status"]),
                body=body,
                expected_title=str(entry["job_title"]).strip(),
            ).document()
        observation = {
            "job_key": entry["key"],
            "fit": entry["fit"],
            "role_title": str(entry["job_title"]).strip(),
            "company_name": str(entry["company"]).strip(),
            "requested_url": entry["url"],
            "final_url": result["final_url"],
            "status": result["status"],
            "body_sha256": body_sha256,
            "network_evidence_sha256": archived[f"observation.network.{index:04d}"],
            "error": result["error"],
            "verdict": verdict,
        }
        observations.append(observation)
        if verdict["live"] is True:
            live_candidates.append(
                LiveVacancy.create(
                    vacancy=VacancyArchiveIdentity(
                        job_key=str(entry["key"]),
                        vacancy_sha256=body_sha256,
                        role_title=str(entry["job_title"]).strip(),
                        company_name=str(entry["company"]).strip(),
                        source_url=str(entry["url"]),
                    ),
                    provider="greenhouse",
                    fit_score=entry["fit"],
                    live=True,
                    eligible=True,
                    duplicate=False,
                    live_verified_at=observed_at,
                    scoring_inputs_sha256=hashlib.sha256(
                        _json_bytes(entry)
                    ).hexdigest(),
                )
            )

    live_queue = build_ascending_queue(
        live_candidates,
        prior_attempts=prior,
        as_of=datetime.fromisoformat(observed_at.replace("Z", "+00:00")),
        retry_repairable_preclick_blocks=(arguments.retry_repairable_preclick_blocks),
    )
    queue_document = {
        "schema_version": "jaa.greenhouse-live-discovery.v2",
        "observed_at": observed_at,
        "snapshot_sha256": snapshot_sha256,
        "refresh_cohort_sha256": refresh_cohort_sha256,
        "ranking_candidate_profile": snapshot.get("candidate_prior_profile"),
        "eligibility_authority": False,
        "eligibility_note": (
            "The imported ranking is an uncalibrated vacancy/opportunity ordering "
            "with an empty candidate profile. Live records require a separate "
            "candidate-evidence eligibility decision before production admission."
        ),
        "archive_attempt_id": attempt.attempt_id,
        "interaction": {"fields_filled": 0, "files_uploaded": 0, "submit_clicks": 0},
        "preexisting_exclusions": [
            {
                "job_key": row.vacancy.vacancy.job_key,
                "reason": row.reason,
            }
            for row in preliminary.excluded
        ],
        "observations": observations,
        "live_pending_eligibility": [
            {
                "live_order": row.queue_rank,
                "job_key": row.vacancy.vacancy.job_key,
                "fit": str(row.vacancy.fit_score),
                "role_title": row.vacancy.vacancy.role_title,
                "company_name": row.vacancy.vacancy.company_name,
                "source_url": row.vacancy.vacancy.source_url,
                "vacancy_sha256": row.vacancy.vacancy.vacancy_sha256,
                "scoring_inputs_sha256": row.vacancy.scoring_inputs_sha256,
                "live_verified_at": row.vacancy.live_verified_at,
                "eligibility_status": "pending_candidate_evidence_assessment",
            }
            for row in live_queue.ready
        ],
    }
    queue_bytes = _json_bytes(queue_document)
    add("vacancy.capture", queue_bytes, "application/json")
    add("vacancy.structured", queue_bytes, "application/json")
    add(
        "vacancy.assessment",
        _json_bytes(
            {
                "classification": "read_only_live_queue_discovery",
                "fetched_count": len(fetched),
                "live_count": len(live_queue.ready),
                "preexisting_exclusion_count": len(preliminary.excluded),
            }
        ),
        "application/json",
    )
    add("observation.queue_manifest", queue_bytes, "application/json")
    add(
        "submission.result",
        _json_bytes(
            {
                "state": "abandoned",
                "reason": "read_only_discovery_complete",
                "submit_clicks": 0,
            }
        ),
        "application/json",
    )
    terminal_sha256 = attempt.finalize_terminal(
        outcome="abandoned",
        selected=archived,
        finalized_at=observed_at,
    )
    ledger.record_attempt_terminal(attempt.attempt_id)
    verification = verify_complete_attempt(
        attempt.attempt_id,
        root=archive.root,
        repository_root=repository_root,
    )
    _atomic_output(arguments.output.resolve(), queue_bytes)
    print(
        canonical_json(
            {
                **verification,
                "attempt_id": attempt.attempt_id,
                "fetched_count": len(fetched),
                "live_count": len(live_queue.ready),
                "output": str(arguments.output.resolve()),
                "queue_sha256": hashlib.sha256(queue_bytes).hexdigest(),
                "terminal_manifest_sha256": terminal_sha256,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
