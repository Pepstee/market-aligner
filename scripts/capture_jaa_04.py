#!/usr/bin/env python3
"""Acquire a JAA-04 corpus from an Opportunity-0 queue snapshot.

The authority plan locates sources; it is never evidence.  Every accepted byte
is obtained by the production reconnaissance worker and is validated before an
atomic, content-addressed corpus is published.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.database import CareerDatabase  # noqa: E402
from career_automation.corpus_publication import sha256_file, write_inventory  # noqa: E402
from career_automation.employer_research import (  # noqa: E402
    EmployerResearchWorker, Opportunity1Coordinator, PortableAuthorityRetriever, RawResponseCache,
    ScraplingPublicRetriever, content_hash, load_frozen_dossiers,
)
from career_automation.engine import OpportunityGate  # noqa: E402
from career_automation.models import ScoredJob  # noqa: E402
from tracked_source_revision import source_content_revision  # noqa: E402

CORPUS_SIZE = 30


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def _revision() -> str:
    result = subprocess.run(("git", "rev-parse", "HEAD^{commit}"), cwd=ROOT,
                            text=True, capture_output=True, check=True)
    return result.stdout.strip()


def _admitted(connection: sqlite3.Connection) -> dict[str, dict[str, str]]:
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        """SELECT j.job_key,j.url,j.company,j.title
           FROM employer_research_queue q JOIN pipeline_jobs j USING(job_key)
           WHERE j.opportunity_decision='pass' ORDER BY j.job_key"""
    ).fetchall()
    if len(rows) < CORPUS_SIZE:
        raise RuntimeError(f"Opportunity-0 queue must contain at least {CORPUS_SIZE} admitted vacancies")
    return {str(row["job_key"]): dict(row) for row in rows}


def _admitted_input(path: Path) -> dict[str, dict[str, str]]:
    if path.suffix.casefold() != ".json":
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as source:
            return _admitted(source)
    payload = json.loads(path.read_text(encoding="utf-8"))
    records = payload.get("records")
    if not isinstance(records, list) or len(records) < CORPUS_SIZE:
        raise RuntimeError("admitted queue JSON must contain at least 30 records")
    if content_hash(records) != payload.get("records_hash"):
        raise RuntimeError("admitted queue JSON hash mismatch")
    return {str(row["job_key"]): {"job_key": str(row["job_key"]), "url": str(row["url"]),
                                  "company": str(row["company"]), "title": str(row["title"]),
                                  "payload_hash": str(row["payload_hash"])} for row in records}


def capture(database_path: Path, destination: Path, *, workspace: Path | None = None,
            maximum_routes: int = 12, timeout_seconds: int = 45) -> None:
    if destination.exists():
        raise RuntimeError("capture destination already exists")
    if not database_path.is_file():
        raise RuntimeError("frozen Opportunity-0 database snapshot is missing")
    admitted = _admitted_input(database_path)
    selected = set(sorted(admitted)[:CORPUS_SIZE])
    records = [admitted[key] for key in sorted(selected)]

    destination.parent.mkdir(parents=True, exist_ok=True)
    workspace = (workspace or destination.with_name(f".{destination.name}.inflight")).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    work_db = workspace / "queue.sqlite3"
    state_path = workspace / "acquisition_state.json"
    snapshot_sha256 = hashlib.sha256(database_path.read_bytes()).hexdigest()
    state = {"schema_version": "jaa04.acquisition-state.v1", "queue_snapshot_sha256": snapshot_sha256,
             "selected_job_keys": sorted(selected), "status": "in_flight"}
    if state_path.exists():
        if json.loads(state_path.read_text(encoding="utf-8")) != state:
            raise RuntimeError("in-flight workspace belongs to a different admitted cohort")
    else:
        state_path.write_bytes(canonical(state))
    if not work_db.exists():
        if database_path.suffix.casefold() != ".json":
            shutil.copyfile(database_path, work_db)
        else:
            database = CareerDatabase(work_db)
            OpportunityGate(database).bootstrap([
                ScoredJob(key=record["job_key"], board="jaa04", job_id=record["job_key"],
                          url=record["url"], title=record["title"], company=record["company"],
                          fit=None, opportunity=.9, final_score=None, extraction_confidence=1.0,
                          payload={}, payload_hash=record["payload_hash"])
                for record in records
            ])
    stage: Path | None = None
    try:
        with sqlite3.connect(work_db) as connection:
            placeholders = ",".join("?" for _ in selected)
            connection.execute(
                f"DELETE FROM employer_research_queue WHERE job_key NOT IN ({placeholders})",
                tuple(sorted(selected)),
            )
            # A process interruption leaves a visible lease. Explicit resume
            # makes it claimable without waiting while completed rows remain
            # immutable and are never processed twice.
            connection.execute(
                "UPDATE employer_research_queue SET lease_until='1970-01-01T00:00:00+00:00' "
                "WHERE status='leased'"
            )
        cache = RawResponseCache(workspace / "raw")
        # Increment A keeps exact canaries as its default contract. Production
        # acquisition is queue-bound instead: all admitted records may proceed,
        # while the same byte, authority, purpose and temporal validators remain.
        transport = ScraplingPublicRetriever(cache, timeout_seconds=timeout_seconds, root=ROOT)
        retriever = PortableAuthorityRetriever(cache, retriever=transport,
                                               maximum_routes=maximum_routes,
                                               exact_canaries=False)
        database = CareerDatabase(work_db)
        worker = EmployerResearchWorker(database, "jaa04-corpus-acquisition", cache,
                                        retriever=retriever)
        coordinator = Opportunity1Coordinator(database, worker)
        while (result := coordinator.run_once()) is not None:
            pass
        with sqlite3.connect(work_db) as connection:
            connection.row_factory = sqlite3.Row
            placeholders = ",".join("?" for _ in selected)
            queue_rows = connection.execute(
                f"""SELECT job_key,status,attempts,last_error,lease_owner,lease_until
                    FROM employer_research_queue WHERE job_key IN ({placeholders})
                    ORDER BY job_key""",
                tuple(sorted(selected)),
            ).fetchall()
        states = {str(row["job_key"]): str(row["status"]) for row in queue_rows}
        incomplete = {key: states.get(key, "missing") for key in sorted(selected)
                      if states.get(key) != "completed"}
        if incomplete:
            details = []
            by_key = {str(row["job_key"]): row for row in queue_rows}
            for key, status in incomplete.items():
                row = by_key.get(key)
                suffix = ""
                if row is not None:
                    suffix = (f" attempts={row['attempts']}"
                              f" lease_owner={row['lease_owner'] or '-'}"
                              f" lease_until={row['lease_until'] or '-'}"
                              f" error={row['last_error'] or '-'}")
                details.append(f"{key}:{status}{suffix}")
            raise RuntimeError(
                "research queue did not drain; retry with the same workspace: " + "; ".join(details)
            )
        completed = {key for key in selected if database.completed_research(key) is not None}
        if completed != selected or len(completed) != CORPUS_SIZE:
            raise RuntimeError("production worker did not complete the selected admitted cohort")

        dossiers = []
        manifest_records = []
        for record in records:
            job_key = str(record["job_key"])
            result = database.completed_research(job_key)
            if result is None:
                raise RuntimeError(f"missing completed dossier for {job_key}")
            dossier, _ = result
            dossier["raw_cache_root"] = "raw"
            dossier_hash = content_hash(dossier)
            dossiers.append(dossier)
            manifest_records.append({
                "job_key": job_key, "vacancy_url": record["url"],
                "company": record["company"], "role": record["title"],
                "dossier_hash": dossier_hash,
                "admitted_payload_hash": record.get("payload_hash"),
                "content_sha256": dossier["sources"][0]["content_sha256"],
                "source_ids": [source["id"] for source in dossier["sources"]],
                "capture_identities": [
                    {"url": source["url"], "sha256": source["content_sha256"]}
                    for source in dossier["sources"]
                ],
            })
        envelope = {"schema_version": "jaa04.frozen-dossiers.v4", "dossiers": dossiers,
                    "dossiers_hash": content_hash(dossiers)}
        manifest = {"schema_version": "jaa04.research-manifest.v4",
                    "opportunity0_queue_size": len(admitted),
                    "records": manifest_records,
                    "records_hash": content_hash(manifest_records)}
        stage = Path(tempfile.mkdtemp(prefix="jaa04-complete-", dir=destination.parent))
        (stage / "frozen_dossiers.json").write_bytes(canonical(envelope))
        (stage / "research_manifest.json").write_bytes(canonical(manifest))
        shutil.copytree(workspace / "raw", stage / "raw", copy_function=os.link)
        staged_cache = RawResponseCache(stage / "raw")
        validated = load_frozen_dossiers(stage / "frozen_dossiers.json", staged_cache, strict_corpus=True)
        if len(validated) != CORPUS_SIZE:
            raise RuntimeError("publication requires exactly 30 validated dossiers")
        # Capture uniqueness is a corpus admission rule, not merely a retrieval
        # optimisation. URL aliases and repeated bodies cannot masquerade as
        # independently acquired authority.
        identities: set[tuple[str, str]] = set()
        body_hashes: set[str] = set()
        source_ids: set[str] = set()
        for dossier in validated:
            for source in dossier["sources"]:
                identity = (str(source["url"]), str(source["content_sha256"]))
                if (identity in identities or source["content_sha256"] in body_hashes
                        or source["id"] in source_ids):
                    raise RuntimeError("duplicated authority capture in staged corpus")
                identities.add(identity)
                body_hashes.add(str(source["content_sha256"]))
                source_ids.add(str(source["id"]))
        files = sorted(path for path in (stage / "raw").rglob("*") if path.is_file())
        corpus_hash = hashlib.sha256(b"".join(
            path.relative_to(stage).as_posix().encode() + b"\0" + path.read_bytes()
            for path in files)).hexdigest()
        inventory_path = write_inventory(stage)
        receipt = {
            "schema_version": "jaa04.capture-receipt.v4", "status": "SUCCESS",
            "captured_count": CORPUS_SIZE,
            "source_count": sum(len(row["sources"]) for row in dossiers),
            "queue_snapshot_sha256": snapshot_sha256,
            "discovery_mode": "typed-ats-and-official-route-validation",
            "manifest_sha256": hashlib.sha256((stage / "research_manifest.json").read_bytes()).hexdigest(),
            "dossiers_sha256": hashlib.sha256((stage / "frozen_dossiers.json").read_bytes()).hexdigest(),
            "raw_corpus_sha256": corpus_hash, "source_revision": _revision(),
            "source_content_revision": source_content_revision(ROOT),
            "inventory_sha256": sha256_file(inventory_path),
        }
        (stage / "capture_receipt.json").write_bytes(canonical(receipt))
        os.rename(stage, destination)
        stage = None
    except BaseException:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-snapshot", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True,
                        help="stable external in-flight queue and content-addressed byte store")
    parser.add_argument("--maximum-routes", type=int, default=12)
    parser.add_argument("--timeout-seconds", type=int, default=45)
    args = parser.parse_args()
    try:
        if args.maximum_routes < 1 or args.timeout_seconds < 1:
            raise ValueError("retrieval limits must be positive")
        capture(args.queue_snapshot.resolve(), args.destination.resolve(), workspace=args.workspace.resolve(),
                maximum_routes=args.maximum_routes, timeout_seconds=args.timeout_seconds)
    except Exception as exc:
        print(f"JAA-04 capture: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "SUCCESS", "capture": str(args.destination)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
