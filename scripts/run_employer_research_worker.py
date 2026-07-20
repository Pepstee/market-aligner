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
from career_automation.employer_research import EmployerResearchWorker, RawResponseCache  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--lease-seconds", type=int, default=900)
    parser.add_argument("--max-jobs", type=int, default=1)
    args = parser.parse_args()
    worker = EmployerResearchWorker(CareerDatabase(args.database), args.worker_id,
                                    RawResponseCache(args.cache),
                                    lease_seconds=args.lease_seconds)
    completed = []
    try:
        for _ in range(max(1, args.max_jobs)):
            job_key = worker.run_once()
            if job_key is None:
                break
            completed.append(job_key)
    except Exception as exc:
        print(f"employer research worker failed closed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"completed": completed, "worker_id": args.worker_id}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
