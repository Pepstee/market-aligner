#!/usr/bin/env python3
"""Atomically replace JAA-04 with a newly acquired authentic corpus."""

from __future__ import annotations

import argparse
import shutil
import tempfile
from pathlib import Path

from capture_jaa_04 import ROOT, capture
from career_automation.corpus_publication import publish_by_pointer, validate_inventory
from career_automation.employer_research import RawResponseCache, load_frozen_dossiers

DESTINATION = ROOT / "career_automation/fixtures/jaa04_capture"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue-snapshot", type=Path, required=True)
    parser.add_argument("--maximum-routes", type=int, default=12)
    parser.add_argument("--timeout-seconds", type=int, default=45)
    args = parser.parse_args()
    fresh = Path(tempfile.mkdtemp(prefix="jaa04-authentic-", dir=DESTINATION.parent))
    fresh.rmdir()
    try:
        if args.maximum_routes < 1 or args.timeout_seconds < 1:
            raise ValueError("retrieval limits must be positive")
        capture(args.queue_snapshot.resolve(), fresh,
                maximum_routes=args.maximum_routes, timeout_seconds=args.timeout_seconds)
        def validate(path: Path) -> None:
            validate_inventory(path)
            dossiers = load_frozen_dossiers(path / "frozen_dossiers.json",
                                             RawResponseCache(path / "raw"), strict_corpus=True)
            if len(dossiers) != 30:
                raise RuntimeError("atomic publication requires exactly 30 dossiers")
        publish_by_pointer(fresh, DESTINATION, validate)
    except BaseException:
        shutil.rmtree(fresh, ignore_errors=True)
        raise
    print("JAA-04 authentic corpus rebuild: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
