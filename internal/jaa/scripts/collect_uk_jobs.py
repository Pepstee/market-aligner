#!/usr/bin/env python3
"""CLI for the uncapped collector."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "skeleton")]

from scraper.collector import Collector
from skeleton.run import load_config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="skeleton/config.overnight.yaml")
    parser.add_argument("--hours", type=float, default=0, help="0 means run until stopped")
    parser.add_argument("--poll-minutes", type=float, default=15)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--boards", nargs="+", default=None,
        help="optional enabled-board override for a targeted parallel collector",
    )
    args = parser.parse_args()
    cfg = load_config(ROOT / args.config)
    if args.boards:
        cfg.setdefault("boards", {})["enabled"] = list(dict.fromkeys(args.boards))
    Collector(cfg, ROOT, log=lambda s: print(s, flush=True)).run(
        hours=args.hours, poll_minutes=args.poll_minutes, once=args.once
    )


if __name__ == "__main__":
    main()
