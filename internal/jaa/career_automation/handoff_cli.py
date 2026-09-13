"""Inspect v1 handoffs and operate the explicitly legacy-only admission path."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .handoff_admission import HandoffAdmissionStore
from .market_aligner_handoff import parse_handoff


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="validate and describe exact v1 bytes")
    inspect.add_argument("handoff", type=Path)
    legacy = sub.add_parser(
        "admit-legacy-scored-jsonl",
        help="persist legacy score rows as permanently release-blocked evidence",
    )
    legacy.add_argument("--database", type=Path, required=True)
    legacy.add_argument("scored_jsonl", type=Path)
    verify = sub.add_parser("verify-stored", help="verify immutable admission evidence")
    verify.add_argument("--database", type=Path, required=True)
    verify.add_argument("application_id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "inspect":
        handoff = parse_handoff(args.handoff.read_bytes())
        print(
            json.dumps(
                {
                    "application_id": handoff.application_id,
                    "emission_profile": handoff.emission_profile,
                    "handoff_root_sha256": handoff.root_sha256,
                    "job_key": handoff.payload["job_key"],
                    "payload_sha256": handoff.payload_sha256,
                    "vacancy_source_identity": handoff.vacancy_source_identity,
                },
                sort_keys=True,
            )
        )
        return 0
    store = HandoffAdmissionStore(args.database)
    if args.command == "admit-legacy-scored-jsonl":
        count = 0
        with args.scored_jsonl.open("rb") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    store.admit_legacy_scored_jsonl(line)
                except ValueError as exc:
                    raise SystemExit(f"{args.scored_jsonl}:{line_number}: {exc}") from exc
                count += 1
        print(json.dumps({"admission_kind": "legacy_scored_jsonl", "admitted": count}, sort_keys=True))
        return 0
    if args.command == "verify-stored":
        admission = store.verify_stored(args.application_id)
        print(json.dumps(admission.__dict__, sort_keys=True))
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
