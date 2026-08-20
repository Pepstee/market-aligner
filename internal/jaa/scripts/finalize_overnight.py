"""Wait for parallel board runs, merge their C3 rows, then score/report once."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PID_FILES = [ROOT / "outputs/overnight.pid", ROOT / "outputs/additional.pid"]
INPUTS = [ROOT / "scraper/data/jobs.jsonl", ROOT / "scraper/data_additional/jobs.jsonl"]
COMBINED = ROOT / "scraper/data/jobs_combined.jsonl"


def running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def wait_for_runs() -> None:
    for pid_file in PID_FILES:
        if not pid_file.exists():
            raise RuntimeError(f"missing PID file: {pid_file}")
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        print(f"waiting for PID {pid} ({pid_file.name})", flush=True)
        while running(pid):
            time.sleep(30)


def merge_rows() -> int:
    rows: dict[str, dict] = {}
    for path in INPUTS:
        if not path.exists():
            raise RuntimeError(f"run finished without expected jobs file: {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            identity = str(row.get("dedup_key") or "").strip().casefold()
            if not identity:
                identity = f"{row.get('company','')}|{row.get('job_title','')}".casefold()
            current = rows.get(identity)
            if current is None or float(row.get("extraction_confidence") or 0) > float(
                current.get("extraction_confidence") or 0
            ):
                rows[identity] = row
    COMBINED.parent.mkdir(parents=True, exist_ok=True)
    COMBINED.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows.values()),
        encoding="utf-8",
    )
    return len(rows)


def main() -> int:
    wait_for_runs()
    count = merge_rows()
    print(f"merged {count} unique jobs -> {COMBINED}", flush=True)
    cmd = [
        str(ROOT / ".venv/bin/python"),
        str(ROOT / "skeleton/run.py"),
        "score",
        "report",
        "--force",
        "--fixture",
        str(COMBINED),
    ]
    completed = subprocess.run(cmd, cwd=ROOT)
    if completed.returncode:
        raise RuntimeError(f"combined score/report failed with exit {completed.returncode}")
    print("combined morning ranking complete", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
