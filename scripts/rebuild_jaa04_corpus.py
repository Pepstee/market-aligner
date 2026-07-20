#!/usr/bin/env python3
"""Atomically replace JAA-04 with a newly acquired authentic corpus."""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from pathlib import Path

from capture_jaa_04 import ROOT, capture

DESTINATION = ROOT / "career_automation/fixtures/jaa04_capture"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-snapshot", type=Path, required=True)
    parser.add_argument("--authority-plan", type=Path, required=True)
    args = parser.parse_args()
    fresh = Path(tempfile.mkdtemp(prefix="jaa04-authentic-", dir=DESTINATION.parent))
    fresh.rmdir()
    previous = DESTINATION.with_name(DESTINATION.name + ".previous")
    try:
        capture(args.queue_snapshot.resolve(), args.authority_plan.resolve(), fresh)
        if previous.exists():
            raise RuntimeError("previous corpus recovery directory already exists")
        if DESTINATION.exists():
            os.rename(DESTINATION, previous)
        try:
            os.rename(fresh, DESTINATION)
        except BaseException:
            if previous.exists():
                os.rename(previous, DESTINATION)
            raise
        if previous.exists():
            shutil.rmtree(previous)
    except BaseException:
        shutil.rmtree(fresh, ignore_errors=True)
        raise
    print("JAA-04 authentic corpus rebuild: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
