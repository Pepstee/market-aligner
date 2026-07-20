"""Command-line interface for verified JAA-00 baseline adoption."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import AdoptionError, adopt, reconcile, rollback_manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jaa-baseline", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    adoption = sub.add_parser("adopt", help="verify and atomically adopt both locked databases")
    adoption.add_argument("--source-root", required=True)
    adoption.add_argument("--data-root", required=True)
    adoption.add_argument("--repository", default=str(Path(__file__).resolve().parents[1]))
    adoption.add_argument("--secret-reference", action="append", default=[], metavar="NAME")
    for name in ("reconcile", "rollback-manifest"):
        command = sub.add_parser(name)
        command.add_argument("--receipt", required=True)
        command.add_argument("--data-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "adopt":
            result = {"status": "adopted", "receipt": str(adopt(
                args.source_root, args.data_root, repository=args.repository,
                secret_references=args.secret_reference))}
        elif args.command == "reconcile":
            result = reconcile(args.receipt, args.data_root)
        else:
            result = rollback_manifest(args.receipt, args.data_root)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except AdoptionError as exc:
        print(f"jaa-baseline: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
