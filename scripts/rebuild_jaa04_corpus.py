#!/usr/bin/env python3
"""Rebuild JAA-04 only by retrieving every canonical public source again."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.capture_jaa_04 import capture  # noqa: E402

PLAN = ROOT / "career_automation/fixtures/jaa04_capture_plan.json"
DESTINATION = ROOT / "career_automation/fixtures/jaa04_capture"


def main() -> int:
    parent = DESTINATION.parent
    fresh = Path(tempfile.mkdtemp(prefix="jaa04-authentic-", dir=parent))
    fresh.rmdir()  # capture deliberately requires a destination that does not exist
    try:
        capture(PLAN, fresh)
        previous = DESTINATION.with_name(DESTINATION.name + ".previous")
        if previous.exists():
            shutil.rmtree(previous)
        os.rename(DESTINATION, previous)
        try:
            os.rename(fresh, DESTINATION)
        except BaseException:
            os.rename(previous, DESTINATION)
            raise
        shutil.rmtree(previous)
    except BaseException:
        shutil.rmtree(fresh, ignore_errors=True)
        raise
    print("JAA-04 authentic corpus rebuild: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
