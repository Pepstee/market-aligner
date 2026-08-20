#!/usr/bin/env python3
"""Exercise the production Opportunity-1 coordinator over the frozen corpus."""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from career_automation.database import CareerDatabase
from career_automation.employer_research import (Opportunity1Coordinator, RawResponseCache,
                                                  content_hash, load_frozen_dossiers)
from career_automation.engine import OpportunityGate
from career_automation.lifecycle import canonical_hash
from career_automation.models import ScoredJob
from career_automation.public_access import PublicAccessPolicy


class FrozenCorpusWorker:
    def __init__(self, database: CareerDatabase, dossiers: dict[str, dict], cache: RawResponseCache) -> None:
        self.database, self.dossiers, self.cache = database, dossiers, cache

    def run_once(self) -> str | None:
        task = self.database.claim_research("jaa04-certification")
        if task is None:
            return None
        dossier = dict(self.dossiers[task.job_key])
        dossier["raw_cache_root"] = str(self.cache.root)
        self.database.complete_research(job_key=task.job_key, worker_id="jaa04-certification",
                                        dossier=dossier, dossier_hash=content_hash(dossier))
        return task.job_key


def _access_policy(capture: Path, path: Path) -> PublicAccessPolicy:
    envelope = json.loads((capture / "frozen_dossiers.json").read_text(encoding="utf-8"))
    retrieved = [
        datetime.fromisoformat(str(source["retrieved_at"]).replace("Z", "+00:00"))
        for dossier in envelope.get("dossiers", [])
        for source in dossier.get("sources", [])
    ]
    if not retrieved or any(value.tzinfo is None for value in retrieved):
        raise ValueError("capture has no timezone-aware retrieval identity")
    return PublicAccessPolicy.load(
        path,
        now=max(value.astimezone(timezone.utc) for value in retrieved),
    )


def exercise(capture: Path, access_policy_path: Path) -> None:
    cache = RawResponseCache(capture / "raw")
    policy = _access_policy(capture, access_policy_path)
    dossiers = load_frozen_dossiers(
        capture / "frozen_dossiers.json",
        cache,
        strict_corpus=True,
        access_policies={policy.policy_sha256: policy},
    )
    with tempfile.TemporaryDirectory(prefix="jaa04-opportunity1-") as temporary:
        database = CareerDatabase(Path(temporary) / "coordination.sqlite3")
        jobs = [ScoredJob(
            key=row["job_key"], board="jaa04", job_id=row["job_key"],
            url=row["sources"][0]["url"], title="certified vacancy", company="certified employer",
            fit=None, opportunity=.9, final_score=None, extraction_confidence=1.0,
            payload={"job_key": row["job_key"]},
            payload_hash=canonical_hash({"job_key": row["job_key"]}),
        ) for row in dossiers]
        summary = OpportunityGate(database).bootstrap(jobs)
        if summary.queued != len(dossiers):
            raise RuntimeError("frozen dossiers did not enter the production research queue")
        coordinator = Opportunity1Coordinator(
            database, FrozenCorpusWorker(database, {row["job_key"]: row for row in dossiers}, cache)
        )
        completed = 0
        while coordinator.run_once() is not None:
            completed += 1
        if completed != len(dossiers):
            raise RuntimeError("production Opportunity-1 coordination did not consume the corpus")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--access-policy", type=Path, required=True)
    args = parser.parse_args()
    exercise(args.capture.resolve(), args.access_policy.resolve())
    print("JAA-04 Opportunity-1 coordination: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
