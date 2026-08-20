#!/usr/bin/env python3
"""Minimal operator surface for the fixed production Market handoff lifecycle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

JAA_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(JAA_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from career_automation.market_aligner_handoff import canonical_json_bytes
from career_automation.production_handoff_runner import (
    run_production_handoff,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--track", required=True)
    parser.add_argument("--source-job-key", required=True)
    args = parser.parse_args(argv)
    receipt = run_production_handoff(
        profile_id=args.profile_id,
        track=args.track,
        source_job_key=args.source_job_key,
    )
    sys.stdout.buffer.write(canonical_json_bytes(receipt.document()) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
