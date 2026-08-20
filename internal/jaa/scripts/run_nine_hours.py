"""Compatibility wrapper: collect first, then run the LLM/reporting phase once."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv/bin/python"
COLLECTOR = ROOT / "scripts/collect_uk_jobs.py"
PROCESSOR = ROOT / "scripts/process_collected_jobs.py"


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="skeleton/config.overnight.yaml")
    parser.add_argument("--hours", type=float, default=9.0)
    parser.add_argument("--interval-minutes", type=float, default=30.0)
    args = parser.parse_args()

    config = (ROOT / args.config).resolve() if not Path(args.config).is_absolute() else Path(args.config)
    collect = [str(PYTHON), str(COLLECTOR), "--config", str(config),
               "--hours", str(args.hours), "--poll-minutes", str(args.interval_minutes)]
    print(f"[{stamp()}] starting uncapped collection", flush=True)
    rc = subprocess.run(collect, cwd=ROOT).returncode
    if rc:
        return rc
    print(f"[{stamp()}] collection complete; starting LLM normalization and ranking", flush=True)
    return subprocess.run([str(PYTHON), str(PROCESSOR), "--config", str(config)], cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
