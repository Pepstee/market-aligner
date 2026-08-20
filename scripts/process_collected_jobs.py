#!/usr/bin/env python3
"""Run the LLM and reporting phases after deterministic collection has stopped."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "skeleton")]

from scraper.database import JobDatabase
from skeleton.run import Paths, RunContext, load_config, stage_extract, stage_report, stage_score


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="skeleton/config.overnight.yaml")
    parser.add_argument("--force-extract", action="store_true",
                        help="redo every LLM extraction (needed after a schema/profile change)")
    args = parser.parse_args()
    cfg = load_config(ROOT / args.config)
    paths = Paths.build(ROOT, cfg)

    # Always rebuild the deterministic, auditable input set before any model
    # call. The raw database remains untouched; only viable unique keys cross
    # this boundary.
    prepare = [
        sys.executable, str(ROOT / "scripts" / "prepare_jobs_for_llm.py"),
        "--config", args.config,
    ]
    subprocess.run(prepare, cwd=ROOT, check=True)

    extract_ctx = RunContext(cfg=cfg, paths=paths, force=args.force_extract)
    stage_extract(extract_ctx)
    score_ctx = RunContext(cfg=cfg, paths=paths, force=True)
    stage_score(score_ctx)
    stage_report(score_ctx)

    io = cfg.get("io", {}) or {}
    db = JobDatabase(ROOT / io.get("database", "scraper/data/jobs.sqlite3"))
    normalized = db.sync_jsonl(paths.jobs, "normalised_jobs", "normalized_json")
    scored = db.sync_jsonl(paths.jobs_scored, "scores", "score_json")
    print(f"[database] synced normalized={normalized}, scored={scored}; stats={db.stats()}", flush=True)


if __name__ == "__main__":
    main()
