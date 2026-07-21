#!/usr/bin/env python3
"""Run the independently declared root acceptance workflow."""

from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMANDS = (
    (sys.executable, "scripts/run_acceptance.py"),
    (sys.executable, "scripts/accept_jaa_02.py"),
    (sys.executable, "scripts/accept_jaa02_receipt.py"),
    (sys.executable, "scripts/accept_jaa03_receipt.py"),
    (sys.executable, "scripts/accept_jaa04_coordination.py"),
)


def main() -> int:
    commands = list(SOURCE_COMMANDS)
    corpus = os.environ.get("JAA04_CORPUS")
    if corpus:
        command = [sys.executable, "scripts/accept_jaa_04.py", "--capture", corpus]
        if receipt := os.environ.get("JAA04_RECEIPTS"):
            command.extend(("--receipt", receipt))
        commands.append(tuple(command))
    else:
        print("JAA-04 corpus certification: NOT RUN (set JAA04_CORPUS to an external corpus path)")
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode:
            return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
