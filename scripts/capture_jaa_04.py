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
from career_automation.employer_research import (  # noqa: E402
    EmployerResearchWorker, Opportunity1Coordinator, PortableAuthorityRetriever, RawResponseCache,
    content_hash, load_frozen_dossiers,
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


def capture(database_path: Path, destination: Path) -> None:
    if destination.exists():
        raise RuntimeError("capture destination already exists")
    if not database_path.is_file():
        raise RuntimeError("frozen Opportunity-0 database snapshot is missing")
    admitted = _admitted_input(database_path)
    selected = set(sorted(admitted)[:CORPUS_SIZE])
    records = [admitted[key] for key in sorted(selected)]

    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="jaa04-acquisition-", dir=destination.parent))
    work_db = stage / "queue.sqlite3"
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
    try:
        with sqlite3.connect(work_db) as connection:
            placeholders = ",".join("?" for _ in selected)
            connection.execute(
                f"DELETE FROM employer_research_queue WHERE job_key NOT IN ({placeholders})",
                tuple(sorted(selected)),
            )
        cache = RawResponseCache(stage / "raw")
        retriever = PortableAuthorityRetriever(cache)
        database = CareerDatabase(work_db)
        worker = EmployerResearchWorker(database, "jaa04-corpus-acquisition", cache,
                                        retriever=retriever)
        completed: list[str] = []
        coordinator = Opportunity1Coordinator(database, worker)
        while (result := coordinator.run_once()) is not None:
            completed.append(str(result["job_key"]))
        if set(completed) != selected or len(completed) != CORPUS_SIZE:
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
                "source_ids": [source["id"] for source in dossier["sources"]],
            })
        envelope = {"schema_version": "jaa04.frozen-dossiers.v4", "dossiers": dossiers,
                    "dossiers_hash": content_hash(dossiers)}
        manifest = {"schema_version": "jaa04.research-manifest.v4",
                    "opportunity0_queue_size": len(admitted),
                    "records": manifest_records,
                    "records_hash": content_hash(manifest_records)}
        (stage / "frozen_dossiers.json").write_bytes(canonical(envelope))
        (stage / "research_manifest.json").write_bytes(canonical(manifest))
        load_frozen_dossiers(stage / "frozen_dossiers.json", cache, strict_corpus=True)
        files = sorted(path for path in (stage / "raw").rglob("*") if path.is_file())
        corpus_hash = hashlib.sha256(b"".join(
            path.relative_to(stage).as_posix().encode() + b"\0" + path.read_bytes()
            for path in files)).hexdigest()
        receipt = {
            "schema_version": "jaa04.capture-receipt.v4", "status": "SUCCESS",
            "captured_count": CORPUS_SIZE,
            "source_count": sum(len(row["sources"]) for row in dossiers),
            "queue_snapshot_sha256": hashlib.sha256(database_path.read_bytes()).hexdigest(),
            "discovery_mode": "vacancy-seeded-published-links",
            "manifest_sha256": hashlib.sha256((stage / "research_manifest.json").read_bytes()).hexdigest(),
            "dossiers_sha256": hashlib.sha256((stage / "frozen_dossiers.json").read_bytes()).hexdigest(),
            "raw_corpus_sha256": corpus_hash, "source_revision": _revision(),
            "source_content_revision": source_content_revision(ROOT),
        }
        (stage / "capture_receipt.json").write_bytes(canonical(receipt))
        work_db.unlink()
        for suffix in ("-wal", "-shm"):
            candidate = Path(str(work_db) + suffix)
            if candidate.exists():
                candidate.unlink()
        os.rename(stage, destination)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-snapshot", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        capture(args.queue_snapshot.resolve(), args.destination.resolve())
    except Exception as exc:
        print(f"JAA-04 capture: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "SUCCESS", "capture": str(args.destination)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
