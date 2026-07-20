#!/usr/bin/env python3
"""Run the independently declared root acceptance workflow."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMANDS = (
    (sys.executable, "scripts/run_acceptance.py"),
    (sys.executable, "scripts/accept_jaa_02.py"),
    (sys.executable, "scripts/accept_jaa02_receipt.py"),
    (sys.executable, "scripts/accept_jaa_03.py"),
    (sys.executable, "scripts/accept_jaa04_coordination.py"),
    (sys.executable, "scripts/accept_jaa_04.py"),
)


def main() -> int:
    for command in COMMANDS:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode:
            return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
