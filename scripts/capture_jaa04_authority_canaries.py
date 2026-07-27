#!/usr/bin/env python3
"""Capture exactly three typed JAA-04 ATS canaries through the production sidecar."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.employer_research import (  # noqa: E402
    LIVE_ATS_AUTHORITY_CANARIES, PortableAuthorityRetriever,
    PublicRetrievalExhausted, RawResponseCache, ScraplingPublicRetriever,
)
from career_automation.public_access import (  # noqa: E402
    PublicAccessPolicy,
    replay_access_receipt,
)
from tracked_source_revision import source_git_revision  # noqa: E402


def _canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def _validate_output_paths(destination: Path, failure_quarantine: Path) -> None:
    if destination == failure_quarantine:
        raise RuntimeError("canary destination and failure quarantine must differ")
    if destination in failure_quarantine.parents or failure_quarantine in destination.parents:
        raise RuntimeError("canary destination and failure quarantine must be separate")
    if destination.exists():
        raise RuntimeError("canary destination already exists")
    if failure_quarantine.exists():
        raise RuntimeError("canary failure quarantine already exists")


def _fsync_directory(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _quarantine_failure(
    stage: Path,
    failure_quarantine: Path,
    *,
    destination: Path,
    access_policy: PublicAccessPolicy,
    command: list[str],
    progress: list[dict[str, object]],
    failing_job_key: str | None,
    failure: BaseException,
) -> None:
    manifest = {
        "schema_version": "jaa04.canary-failure-quarantine.v1",
        "classification": "failure_quarantine",
        "accepted": False,
        "inadmissible_as": ["canary_acceptance", "admission_evidence", "dossier_corpus"],
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": source_git_revision(ROOT),
        "access_policy_sha256": access_policy.policy_sha256,
        "command": command,
        "success_destination": str(destination),
        "failure_quarantine": str(failure_quarantine),
        "canary_progress": progress,
        "failing_job_key": failing_job_key,
        "exception_type": type(failure).__name__,
        "exception_message": str(failure),
    }
    if isinstance(failure, PublicRetrievalExhausted):
        manifest["retrieval_attempts"] = [
            attempt.as_dict()
            for attempt in failure.attempts
        ]
    manifest_path = stage / "canary-failure-manifest.json"
    manifest_path.write_bytes(_canonical(manifest))
    os.chmod(manifest_path, 0o600)
    with manifest_path.open("rb") as stream:
        os.fsync(stream.fileno())
    _fsync_directory(stage)
    os.rename(stage, failure_quarantine / "stage")
    _fsync_directory(failure_quarantine)
    _fsync_directory(destination.parent)


def capture(
    destination: Path,
    access_policy: PublicAccessPolicy,
    *,
    failure_quarantine: Path,
    command: list[str],
) -> None:
    """Publish a replayable three-canary directory, never a dossier corpus."""
    destination = destination.resolve()
    failure_quarantine = failure_quarantine.resolve()
    _validate_output_paths(destination, failure_quarantine)
    destination.parent.mkdir(parents=True, exist_ok=True)
    failure_quarantine.parent.mkdir(parents=True, exist_ok=True)
    if (
        os.stat(destination.parent).st_dev
        != os.stat(failure_quarantine.parent).st_dev
    ):
        raise RuntimeError(
            "canary destination and failure quarantine must share a filesystem"
        )
    failure_quarantine.mkdir(mode=0o700)
    stage = Path(tempfile.mkdtemp(prefix="jaa04-canaries-", dir=destination.parent))
    os.chmod(stage, 0o700)
    progress = [
        {"job_key": record.job_key, "status": "pending"}
        for record in LIVE_ATS_AUTHORITY_CANARIES
    ]
    failing_job_key: str | None = None
    try:
        cache = RawResponseCache(stage / ".raw")
        transport = ScraplingPublicRetriever(
            cache,
            root=ROOT,
            access_policy=access_policy,
        )
        retriever = PortableAuthorityRetriever(cache, retriever=transport)
        for index, record in enumerate(LIVE_ATS_AUTHORITY_CANARIES):
            failing_job_key = record.job_key
            progress[index]["status"] = "started"
            task = SimpleNamespace(job_key=record.job_key, company=record.company,
                                   title=record.title, url=record.admitted_url)
            citations, plan = retriever.retrieve_plan(task)
            captures = []
            for citation in citations:
                raw = cache.resolve(citation.raw_response_ref, citation.content_sha256)
                content_urls = tuple(dict.fromkeys((
                    citation.requested_url or citation.url,
                    *(str(item["url"]) for item in citation.redirect_history),
                    citation.url,
                )))
                replay_access_receipt(
                    citation.access_receipt,
                    cache,
                    content_urls=content_urls,
                    content_retrieved_at=citation.retrieved_at,
                    policies={access_policy.policy_sha256: access_policy},
                )
                capture_row = vars(citation).copy()
                capture_row.update({
                    "sidecar_raw_response_ref": citation.raw_response_ref,
                    "raw_response_ref": "embedded:raw_response_base64",
                    "raw_response_encoding": "base64",
                    "raw_response_base64": base64.b64encode(raw).decode("ascii"),
                })
                captures.append(capture_row)
            artifact = {
                "schema_version": "jaa04.typed-authority-canary.v1",
                "admitted_record": vars(record),
                "captures": captures,
                "source_plan": plan,
            }
            filename = record.job_key.split(":", 1)[0] + ".json"
            (stage / filename).write_bytes(_canonical(artifact))
            progress[index].update({
                "status": "completed",
                "artifact": filename,
                "capture_count": len(captures),
            })
            failing_job_key = None
        files = sorted(path.name for path in stage.iterdir() if path.is_file())
        if files != ["ashby.json", "greenhouse.json", "workable.json"]:
            raise RuntimeError("canary capture must produce exactly three artifacts")
        if not (stage / ".raw" / "sha256").is_dir():
            raise RuntimeError("canary capture lacks its replayable raw response store")
        failure_quarantine.rmdir()
        os.rename(stage, destination)
    except BaseException as exc:
        try:
            if not failure_quarantine.exists():
                failure_quarantine.mkdir(mode=0o700)
            _quarantine_failure(
                stage,
                failure_quarantine,
                destination=destination,
                access_policy=access_policy,
                command=command,
                progress=progress,
                failing_job_key=failing_job_key,
                failure=exc,
            )
        except BaseException as quarantine_error:
            preserved = (
                failure_quarantine / "stage"
                if (failure_quarantine / "stage").exists()
                else stage
            )
            exc.add_note(
                "canary failure quarantine also failed: "
                f"{type(quarantine_error).__name__}: {quarantine_error}; "
                f"failure stage preserved at {preserved}"
            )
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--failure-quarantine", type=Path, required=True)
    parser.add_argument("--access-policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        access_policy = PublicAccessPolicy.load(args.access_policy.resolve())
        capture(
            args.destination.resolve(),
            access_policy,
            failure_quarantine=args.failure_quarantine.resolve(),
            command=[
                str(Path(sys.executable).resolve()),
                str(Path(__file__).resolve()),
                *sys.argv[1:],
            ],
        )
    except Exception as exc:
        print(f"JAA-04 authority canaries: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "SUCCESS", "artifacts": 3,
                      "destination": str(args.destination)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
