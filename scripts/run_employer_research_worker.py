#!/usr/bin/env python3
"""Run the source-controlled employer reconnaissance queue worker."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.database import CareerDatabase  # noqa: E402
from career_automation.employer_research import (  # noqa: E402
    EmployerResearchWorker, Opportunity1Coordinator, RawResponseCache,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--lease-seconds", type=int, default=900)
    parser.add_argument("--max-jobs", type=int, default=1)
    parser.add_argument("--coordinate-opportunity1", action="store_true")
    args = parser.parse_args()
    database = CareerDatabase(args.database)
    worker = EmployerResearchWorker(database, args.worker_id,
                                    RawResponseCache(args.cache),
                                    lease_seconds=args.lease_seconds)
    runner = Opportunity1Coordinator(database, worker) if args.coordinate_opportunity1 else worker
    completed = []
    try:
        for _ in range(max(1, args.max_jobs)):
            result = runner.run_once()
            if result is None:
                break
            completed.append(result if isinstance(result, str) else result)
    except Exception as exc:
        print(f"employer research worker failed closed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"completed": completed, "worker_id": args.worker_id}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
