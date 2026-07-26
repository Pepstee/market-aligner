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
    (sys.executable, "scripts/accept_jaa04_policy_serialization.py"),
)


def main() -> int:
    for command in SOURCE_COMMANDS:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode:
            return completed.returncode

    corpus = os.environ.get("JAA04_CORPUS")
    if not corpus:
        print(
            "JAA-04 corpus certification: BLOCKED "
            "(set JAA04_CORPUS to an external published corpus path)",
            file=sys.stderr,
        )
        return 3
    access_policy = os.environ.get("JAA04_ACCESS_POLICY")
    if not access_policy:
        print(
            "JAA-04 corpus certification: BLOCKED "
            "(set JAA04_ACCESS_POLICY to the operator-reviewed policy path)",
            file=sys.stderr,
        )
        return 3

    command = [
        sys.executable,
        "scripts/accept_jaa_04.py",
        "--capture",
        corpus,
        "--access-policy",
        access_policy,
    ]
    coordination = subprocess.run(
        (
            sys.executable,
            "scripts/accept_jaa04_coordination.py",
            "--capture",
            corpus,
            "--access-policy",
            access_policy,
        ),
        cwd=ROOT,
        check=False,
    )
    if coordination.returncode:
        return coordination.returncode
    if receipt := os.environ.get("JAA04_RECEIPTS"):
        command.extend(("--receipt", receipt))
    return subprocess.run(command, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
