#!/usr/bin/env python3
"""Build the auditable, deterministic input set for one-by-one LLM judging."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "skeleton")]

from contracts import JobUrl, write_jsonl
from scraper.viability import evaluate, vacancy_from_db_row
from skeleton.run import load_config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="skeleton/config.overnight.yaml")
    parser.add_argument("--no-link-check", action="store_true")
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()
    cfg = load_config(ROOT / args.config)
    io = dict(cfg.get("io", {}) or {})
    db_path = ROOT / io.get("database", "scraper/data/jobs.sqlite3")
    manifest = ROOT / io.get("viability_manifest", "scraper/data/viability.jsonl")
    selected_path = ROOT / io.get("processing_job_urls", "scraper/data/viable_job_urls.jsonl")

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT key,board,job_id,url,posted_at,raw_text,raw_json FROM postings "
            "WHERE fetch_status='fetched' ORDER BY first_seen_at,key"
        ).fetchall()
    vacancies = [vacancy_from_db_row(row) for row in rows]
    decisions = evaluate(
        vacancies, check_links=not args.no_link_check, workers=args.workers, timeout=args.timeout,
    )
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w", encoding="utf-8") as handle:
        for decision in decisions:
            handle.write(json.dumps(decision.to_dict(), ensure_ascii=False) + "\n")

    selected = [
        JobUrl(d.board, d.job_id, d.url, next(v.posted_at for v in vacancies if v.key == d.key) or None)
        for d in decisions if d.decision == "include"
    ]
    write_jsonl(selected_path, selected)
    reasons = Counter(d.reason for d in decisions)
    print(f"[prepare] raw={len(vacancies)} viable_unique={len(selected)} excluded={len(vacancies)-len(selected)}")
    for reason, count in reasons.most_common():
        print(f"[prepare] {reason}: {count}")
    print(f"[prepare] manifest={manifest}")
    print(f"[prepare] llm_input={selected_path}")


if __name__ == "__main__":
    main()
