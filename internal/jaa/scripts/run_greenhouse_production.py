#!/usr/bin/env python3
"""Invoke the certified ascending-fit Greenhouse production runner."""

import sys
from pathlib import Path

JAA_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(JAA_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from career_automation.production_runner import main


if __name__ == "__main__":
    raise SystemExit(main())
