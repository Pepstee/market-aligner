#!/usr/bin/env python3
"""Measure cold browser startup against one reusable preparation browser."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from playwright.sync_api import sync_playwright


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--applications", type=int, default=3)
    args = parser.parse_args()
    if not 2 <= args.applications <= 20:
        raise ValueError("benchmark application count must be between 2 and 20")
    target = "data:text/html,<title>JAA preparation</title><input name=q>"
    with sync_playwright() as runtime:
        cold_samples = []
        for _ in range(args.applications):
            started = time.perf_counter_ns()
            browser = runtime.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(target, wait_until="domcontentloaded")
            page.locator("input").fill("prepared")
            browser.close()
            cold_samples.append((time.perf_counter_ns() - started) / 1_000_000)

        started = time.perf_counter_ns()
        browser = runtime.chromium.launch(headless=True)
        warm_samples = []
        for _ in range(args.applications):
            item_started = time.perf_counter_ns()
            page = browser.new_page()
            page.goto(target, wait_until="domcontentloaded")
            page.locator("input").fill("prepared")
            page.close()
            warm_samples.append((time.perf_counter_ns() - item_started) / 1_000_000)
        browser.close()
        warm_total = (time.perf_counter_ns() - started) / 1_000_000
    cold_total = sum(cold_samples)
    result = {
        "schema_version": "jaa.throughput-benchmark.v1",
        "applications": args.applications,
        "before": {
            "strategy": "fresh_browser_per_application",
            "samples_ms": cold_samples,
            "total_ms": cold_total,
            "median_ms": statistics.median(cold_samples),
        },
        "after": {
            "strategy": "one_warm_browser_separate_preparation_pages",
            "samples_ms_excluding_one_startup": warm_samples,
            "total_ms_including_one_startup": warm_total,
            "median_page_ms": statistics.median(warm_samples),
        },
        "speedup": cold_total / warm_total,
        "assurance_change": "none",
        "final_submit_policy": "serialized_and_recomputed_per_application",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
