#!/usr/bin/env python3
"""Advance the autonomous career control plane without touching scraper state."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation import CareerDatabase, OpportunityGate, OpportunityPolicy
from career_automation.engine import read_scored_jsonl


DEFAULT_DB = ROOT / "outputs" / "career_automation" / "career_pipeline.sqlite3"
DEFAULT_SCORED = ROOT / "skeleton" / "data_overnight" / "jobs_scored.jsonl"


def _database(value: str) -> CareerDatabase:
    path = Path(value)
    return CareerDatabase(path if path.is_absolute() else ROOT / path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    sub = parser.add_subparsers(dest="command", required=True)

    bootstrap = sub.add_parser("bootstrap", help="import scores and apply Opportunity gate")
    bootstrap.add_argument("--scored", default=str(DEFAULT_SCORED))
    bootstrap.add_argument("--minimum-opportunity", type=float, default=0.55)
    bootstrap.add_argument("--minimum-confidence", type=float, default=0.70)
    bootstrap.add_argument("--high-priority-opportunity", type=float, default=0.75)

    sub.add_parser("status", help="show materialised pipeline counts")

    queue = sub.add_parser("research-queue", help="show admitted employer-research tasks")
    queue.add_argument("--limit", type=int, default=20)

    claim = sub.add_parser("claim-research", help="lease one task to a research worker")
    claim.add_argument("--worker", required=True)
    claim.add_argument("--lease-seconds", type=int, default=900)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    database = _database(args.database)
    if args.command == "bootstrap":
        policy = OpportunityPolicy(
            minimum_opportunity=args.minimum_opportunity,
            minimum_extraction_confidence=args.minimum_confidence,
            high_priority_opportunity=args.high_priority_opportunity,
        )
        scored = Path(args.scored)
        if not scored.is_absolute():
            scored = ROOT / scored
        summary = OpportunityGate(database, policy).bootstrap(read_scored_jsonl(scored))
        print(json.dumps(summary.__dict__, sort_keys=True))
        return
    if args.command == "status":
        print(json.dumps(database.stats(), sort_keys=True))
        return
    if args.command == "research-queue":
        for task in database.list_research_queue(limit=max(1, args.limit)):
            print(json.dumps(task.__dict__, ensure_ascii=False, sort_keys=True))
        return
    if args.command == "claim-research":
        task = database.claim_research(args.worker, max(1, args.lease_seconds))
        print(json.dumps(task.__dict__ if task else None, ensure_ascii=False, sort_keys=True))
        return
    raise AssertionError(args.command)


if __name__ == "__main__":
    main()
