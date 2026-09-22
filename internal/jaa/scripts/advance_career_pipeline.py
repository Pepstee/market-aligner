#!/usr/bin/env python3
"""Advance the autonomous career control plane without touching scraper state."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation import CareerDatabase  # noqa: E402


DEFAULT_DB = ROOT / "outputs" / "career_automation" / "career_pipeline.sqlite3"


def _database(value: str) -> CareerDatabase:
    path = Path(value)
    return CareerDatabase(path if path.is_absolute() else ROOT / path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "bootstrap",
        help="disabled legacy command; use jaa-handoff admission",
    )

    sub.add_parser("status", help="show materialised pipeline counts")

    queue = sub.add_parser("research-queue", help="show admitted employer-research tasks")
    queue.add_argument("--limit", type=int, default=20)

    claim = sub.add_parser("claim-research", help="lease one task to a research worker")
    claim.add_argument("--worker", required=True)
    claim.add_argument("--lease-seconds", type=int, default=900)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "bootstrap":
        raise SystemExit(
            "direct scored-JSONL bootstrap is disabled; use "
            "`jaa-handoff admit-legacy-scored-jsonl --database ... FILE`, whose "
            "admissions are durably labelled and release-blocked"
        )
    database = _database(args.database)
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
