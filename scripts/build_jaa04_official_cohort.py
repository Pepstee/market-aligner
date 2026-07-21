#!/usr/bin/env python3
"""Source-tree entry point for the production official-cohort command."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.official_cohort import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
