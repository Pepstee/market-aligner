#!/usr/bin/env python3
"""Run commercial acceptance from portable private runtime configuration."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from acceptance_runtime import RuntimeConfigurationError, default_config_path, load_runtime_config


ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--config", type=Path, help="explicit private config path")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        config = load_runtime_config(args.config if args.config is not None else default_config_path())
    except RuntimeConfigurationError as exc:
        print(f"commercial-acceptance: ERROR: {exc}", file=sys.stderr)
        return 2

    commands = (
        (sys.executable, "-m", "baseline_adoption.cli", "recertify-sources",
         "--source-root", config["original_source_root"], "--evidence-directory",
         config["recertification_evidence_directory"]),
        (sys.executable, "scripts/accept_jaa_01c.py"),
        (sys.executable, "-m", "pytest", "-q",
         "career_automation/test_jaa_01e_lifecycle_no_bypass.py"),
        (sys.executable, "scripts/reproduce_jaa01_terra_rejection.py"),
        (sys.executable, "-m", "pytest", "-q"),
    )
    for command in commands:
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode:
            return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
