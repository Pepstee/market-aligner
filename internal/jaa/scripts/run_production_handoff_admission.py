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
    args = parser.parse_args(argv)
    receipt = run_production_handoff_admission(
        execution_receipt_path=args.execution_receipt
    )
    sys.stdout.buffer.write(canonical_json_bytes(receipt.document()) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
