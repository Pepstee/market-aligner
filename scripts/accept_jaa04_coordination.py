#!/usr/bin/env python3
"""Exercise the production Opportunity-1 coordinator over the frozen corpus."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from career_automation.database import CareerDatabase
from career_automation.employer_research import (Opportunity1Coordinator, RawResponseCache,
                                                  content_hash, load_frozen_dossiers)
from career_automation.engine import OpportunityGate
from career_automation.lifecycle import canonical_hash
from career_automation.models import ScoredJob


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


def exercise(capture: Path) -> None:
    cache = RawResponseCache(capture / "raw")
    dossiers = load_frozen_dossiers(capture / "frozen_dossiers.json", cache, strict_corpus=True)
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
    parser.add_argument("--capture", type=Path,
                        default=ROOT / "career_automation/fixtures/jaa04_capture")
    args = parser.parse_args()
    exercise(args.capture.resolve())
    print("JAA-04 Opportunity-1 coordination: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
