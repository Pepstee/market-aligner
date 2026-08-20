#!/usr/bin/env python3
"""Fetch and archive selected ranked vacancy sources without interaction."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Sequence

from career_automation.application_archive import (
    ApplicationArchive,
    ApplicationArchiveError,
    VacancyArchiveIdentity,
    verify_complete_attempt,
)
from career_automation.evidence_matching import canonical_json
from career_automation.live_vacancy_discovery import (
    AuthorityDestinationResponse,
    bind_authority_destinations,
    classify_live_vacancy_response,
)
from career_automation.production_queue import ProductionCheckpointLedger


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_output(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
                raise FileExistsError(f"refusing to replace differing output: {path}")
        else:
            os.link(temporary, path, follow_symlinks=False)
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)


async def _fetch(
    entry: dict[str, object], semaphore: asyncio.Semaphore, session: Any
):
    async with semaphore:
        try:
            response = await session.get(str(entry["url"]))
        except Exception as exc:
            return entry, None, str(entry["url"]), _json_bytes({
                "error_type": type(exc).__name__, "message": str(exc),
                "url": entry["url"],
            }), [], {"type": type(exc).__name__, "message": str(exc)}
        events = []
        previous = None
        for row in (*response.history, response):
            status = getattr(row, "status", getattr(row, "status_code", None))
            url = getattr(row, "url", None)
            if isinstance(status, int) and url:
                events.append({"url": str(url), "status": status, "method": "GET", "redirected_from": previous})
                previous = str(url)
        return entry, int(response.status), str(response.url), bytes(response.body), events, None


async def _all(entries: list[dict[str, object]], concurrency: int, session: Any):
    semaphore = asyncio.Semaphore(concurrency)
    return await asyncio.gather(
        *(_fetch(row, semaphore, session) for row in entries)
    )


async def _crawl(
    entries: list[dict[str, object]],
    concurrency: int,
    *,
    session_factory: Any = None,
):
    """Fetch sources, then all discovered native ATS destinations in one session."""
    if session_factory is None:
        from scrapling.fetchers import FetcherSession

        session_factory = FetcherSession
    async with session_factory(
        timeout=30,
        retries=1,
        follow_redirects="safe",
        stealthy_headers=False,
    ) as session:
        source_results = await _all(entries, concurrency, session)
        destination_entries: list[dict[str, object]] = []
        for source_index, (
            entry,
            status,
            final_url,
            body,
            _events,
            _error,
        ) in enumerate(source_results, 1):
            if status is None:
                continue
            verdict = classify_live_vacancy_response(
                requested_url=str(entry["url"]),
                final_url=final_url,
                status=status,
                body=body,
                expected_title=str(entry["job_title"]).strip(),
            )
            if verdict.reason != "live_source_requires_ats_destination_fetch":
                continue
            destination_entries.extend(
                {
                    "url": url,
                    "source_index": source_index,
                }
                for url in verdict.authority_candidates
            )
        destination_results = await _all(
            destination_entries, concurrency, session
        )
    return source_results, destination_results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--job-key", action="append", default=[])
    parser.add_argument("--fit-less-than")
    parser.add_argument("--exclude-board", action="append", default=[])
    parser.add_argument("--concurrency", type=int, default=3)
    args = parser.parse_args(argv)
    if not 1 <= args.concurrency <= 4:
        parser.error("--concurrency must be between 1 and 4")
    repository_root = args.repository_root.resolve(strict=True)
    snapshot_bytes = args.snapshot.resolve(strict=True).read_bytes()
    snapshot = json.loads(snapshot_bytes)
    by_key = {str(row["key"]): row for row in snapshot["entries"]}
    if bool(args.job_key) == bool(args.fit_less_than):
        parser.error("supply exactly one of --job-key or --fit-less-than")
    if args.job_key:
        requested = list(dict.fromkeys(args.job_key))
        if len(requested) != len(args.job_key) or any(key not in by_key for key in requested):
            parser.error("job keys must be unique members of the ranked snapshot")
        entries = [by_key[key] for key in requested]
    else:
        try:
            fit_limit = Decimal(args.fit_less_than)
        except (InvalidOperation, ValueError) as exc:
            parser.error(f"--fit-less-than must be a finite decimal: {exc}")
        if not fit_limit.is_finite():
            parser.error("--fit-less-than must be a finite decimal")
        excluded_boards = set(args.exclude_board)
        entries = [
            row for row in snapshot["entries"]
            if Decimal(str(row["fit"])) < fit_limit
            and str(row["board"]) not in excluded_boards
        ]
    entries.sort(key=lambda row: (Decimal(str(row["fit"])), str(row["key"])))
    if not entries:
        parser.error("selection contains no ranked vacancies")
    observed_at = _now()
    snapshot_sha = hashlib.sha256(snapshot_bytes).hexdigest()
    archive = ApplicationArchive(args.archive_root, repository_root=repository_root)
    attempt = archive.create_attempt(VacancyArchiveIdentity(
        job_key=f"observation:multi-provider-live:{snapshot_sha[:16]}:{observed_at}",
        vacancy_sha256=snapshot_sha,
        role_title="Read-only multi-provider live vacancy discovery",
        company_name="JAA local operations",
        source_url=f"https://local.invalid/multi-provider-live/{snapshot_sha}",
    ))
    ledger = ProductionCheckpointLedger(archive)
    ledger.record_attempt_started(attempt.attempt_id)
    selected: dict[str, str] = {}
    def add(role: str, value: bytes, media: str, **metadata: object) -> str:
        row = attempt.add_artifact(role, value, media_type=media, disposition="observed", metadata=metadata)
        selected[role] = row.sha256
        return row.sha256
    add("vacancy.source_identity", _json_bytes(attempt.vacancy.document()), "application/json")
    add("observation.source_snapshot", snapshot_bytes, "application/json", source_sha256=snapshot_sha)
    source_results, all_destination_results = asyncio.run(
        _crawl(entries, args.concurrency)
    )
    destinations_by_source: dict[int, list[tuple[object, ...]]] = {}
    for result in all_destination_results:
        source_index = int(result[0]["source_index"])
        destinations_by_source.setdefault(source_index, []).append(result)

    def archive_response(
        role: str,
        body: bytes,
        *,
        status: int | None,
        source_url: object,
    ) -> tuple[str, str, bool]:
        original_sha = hashlib.sha256(body).hexdigest()
        omitted = False
        try:
            archived_sha = add(
                role,
                body,
                "text/html" if status is not None else "application/json",
                source_url=source_url,
                response_status=status,
            )
        except ApplicationArchiveError as exc:
            if "secret-like value" not in str(exc):
                raise
            omitted = True
            archived_sha = add(
                role,
                _json_bytes(
                    {
                        "schema_version": "jaa.secret-safe-response-omission.v1",
                        "original_body_sha256": original_sha,
                        "original_byte_length": len(body),
                        "reason": "archive_secret_scanner_rejected_raw_response",
                    }
                ),
                "application/json",
                source_url=source_url,
                response_status=status,
            )
        return original_sha, archived_sha, omitted

    observations = []
    for index, (entry, status, final_url, body, events, error) in enumerate(
        source_results, 1
    ):
        original_body_sha, archived_body_sha, response_omitted = archive_response(
            f"observation.response.{index:04d}",
            body,
            status=status,
            source_url=entry["url"],
        )
        network = {"schema_version": "jaa.browser-http-evidence.v1", "events": events, "availability": "observed" if events else "no_response_event_observed_after_listener_started"}
        network_sha = add(f"observation.network.{index:04d}", _json_bytes(network), "application/json")
        source_verdict = (None
            if status is None else classify_live_vacancy_response(
                requested_url=str(entry["url"]), final_url=final_url,
                status=status, body=body, expected_title=str(entry["job_title"]).strip(),
            ))
        destination_archives = []
        if (
            source_verdict is not None
            and source_verdict.reason == "live_source_requires_ats_destination_fetch"
            and source_verdict.authority_candidates
        ):
            destination_results = destinations_by_source.get(index, [])
            destination_responses = []
            for destination_index, (
                destination_entry,
                destination_status,
                destination_final_url,
                destination_body,
                destination_events,
                destination_error,
            ) in enumerate(destination_results, 1):
                (
                    destination_body_sha,
                    destination_response_sha,
                    destination_response_omitted,
                ) = archive_response(
                    f"observation.destination_response.{index:04d}.{destination_index:04d}",
                    destination_body,
                    status=destination_status,
                    source_url=destination_entry["url"],
                )
                destination_network = {
                    "schema_version": "jaa.browser-http-evidence.v1",
                    "events": destination_events,
                    "availability": (
                        "observed"
                        if destination_events
                        else "no_response_event_observed_after_listener_started"
                    ),
                }
                destination_network_sha = add(
                    f"observation.destination_network.{index:04d}.{destination_index:04d}",
                    _json_bytes(destination_network),
                    "application/json",
                )
                destination_archives.append(
                    {
                        "requested_url": destination_entry["url"],
                        "final_url": destination_final_url,
                        "status": destination_status,
                        "body_sha256": destination_body_sha,
                        "archived_response_sha256": destination_response_sha,
                        "raw_response_omitted_for_secret_safety": destination_response_omitted,
                        "network_evidence_sha256": destination_network_sha,
                        "error": destination_error,
                    }
                )
                if destination_status is not None and not destination_response_omitted:
                    destination_responses.append(
                        AuthorityDestinationResponse(
                            requested_url=str(destination_entry["url"]),
                            final_url=destination_final_url,
                            status=destination_status,
                            body=destination_body,
                            response_artifact_sha256=destination_response_sha,
                            network_evidence_sha256=destination_network_sha,
                        )
                    )
            if response_omitted or archived_body_sha != source_verdict.source_body_sha256:
                source_verdict = replace(
                    source_verdict,
                    live=False,
                    reason="source_response_artifact_unavailable",
                    authority_urls=(),
                    authority_providers=(),
                )
            elif len(destination_responses) == len(
                source_verdict.authority_candidates
            ):
                source_verdict = bind_authority_destinations(
                    source_verdict,
                    responses=tuple(destination_responses),
                    expected_title=str(entry["job_title"]).strip(),
                    expected_company=str(entry["company"]).strip(),
                )
            else:
                source_verdict = replace(
                    source_verdict,
                    live=False,
                    reason="ats_destination_fetch_or_archive_incomplete",
                    authority_urls=(),
                    authority_providers=(),
                )
        verdict = (
            {
                "live": False,
                "reason": "network_fetch_failed",
                "title_bound": False,
                "active_markers": [],
                "closed_markers": [],
                "authority_urls": [],
                "authority_providers": [],
                "authority_candidates": [],
                "destination_evidence": [],
                "source_final_url": final_url,
                "source_body_sha256": original_body_sha,
            }
            if source_verdict is None
            else source_verdict.document()
        )
        observations.append({
            "job_key": entry["key"], "board": entry["board"], "fit": entry["fit"],
            "rank": entry["rank"], "entry_level": entry["entry_level"],
            "role_title": str(entry["job_title"]).strip(), "company_name": str(entry["company"]).strip(),
            "location": entry["location"], "requested_url": entry["url"], "final_url": final_url,
            "status": status, "body_sha256": original_body_sha,
            "archived_response_sha256": archived_body_sha,
            "raw_response_omitted_for_secret_safety": response_omitted,
            "network_evidence_sha256": network_sha,
            "error": error, "verdict": verdict,
            "authority_destination_archives": destination_archives,
        })
    document = {
        "schema_version": "jaa.multi-provider-live-discovery.v1", "observed_at": observed_at,
        "snapshot_sha256": snapshot_sha, "archive_attempt_id": attempt.attempt_id,
        "interaction": {"fields_filled": 0, "files_uploaded": 0, "submit_clicks": 0},
        "observations": observations,
    }
    value = _json_bytes(document)
    add("vacancy.capture", value, "application/json")
    add("vacancy.structured", value, "application/json")
    add("vacancy.assessment", _json_bytes({"classification": "read_only_multi_provider_discovery", "fetched_count": len(observations)}), "application/json")
    add("observation.queue_manifest", value, "application/json")
    add("submission.result", _json_bytes({"state": "abandoned", "reason": "read_only_discovery_complete", "submit_clicks": 0}), "application/json")
    terminal = attempt.finalize_terminal(outcome="abandoned", selected=selected, finalized_at=observed_at)
    ledger.record_attempt_terminal(attempt.attempt_id)
    verification = verify_complete_attempt(attempt.attempt_id, root=archive.root, repository_root=repository_root)
    output = args.output.resolve()
    _atomic_output(output, value)
    print(canonical_json({**verification, "attempt_id": attempt.attempt_id, "output": str(output), "output_sha256": hashlib.sha256(value).hexdigest(), "terminal_manifest_sha256": terminal}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
