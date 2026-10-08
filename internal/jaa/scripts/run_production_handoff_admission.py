#!/usr/bin/env python3
"""Admit one fixed-outbox Market execution receipt into production JAA."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

JAA_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(JAA_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from career_automation.market_aligner_handoff import canonical_json_bytes
from career_automation.production_handoff_admission_runner import (
    run_production_handoff_admission,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-receipt", required=True)
    parser.add_argument("--current-runtime-config-path")
    parser.add_argument("--current-runtime-config-sha256")
    parser.add_argument("--current-runtime-private-root")
    args = parser.parse_args(argv)
    inputs = {"execution_receipt_path": args.execution_receipt}
    if any(
        value is not None
        for value in (
            args.current_runtime_config_path,
            args.current_runtime_config_sha256,
            args.current_runtime_private_root,
        )
    ):
        inputs.update(
            {
                "current_runtime_config_path": args.current_runtime_config_path,
                "current_runtime_config_sha256": args.current_runtime_config_sha256,
                "current_runtime_private_root": args.current_runtime_private_root,
            }
        )
    receipt = run_production_handoff_admission(**inputs)
    sys.stdout.buffer.write(canonical_json_bytes(receipt.document()) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
