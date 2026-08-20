#!/usr/bin/env python3
"""Provision preparation-only contact and current-time authority on Gigabyte."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.authority_provisioning import (  # noqa: E402
    provision_contact_authority,
    provision_current_time,
)
from career_automation.evidence_matching import canonical_json  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    contact = subparsers.add_parser("contact")
    contact.add_argument("--candidate-authority", type=Path, required=True)
    contact.add_argument("--candidate-authority-sha256", required=True)
    contact.add_argument("--output-root", type=Path, required=True)
    contact.add_argument("--repository-root", type=Path, default=ROOT)
    time_parser = subparsers.add_parser("time")
    time_parser.add_argument("--output-root", type=Path, required=True)
    time_parser.add_argument("--repository-root", type=Path, default=ROOT)
    time_parser.add_argument("--subject-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.operation == "contact":
            result = provision_contact_authority(
                candidate_authority_path=arguments.candidate_authority,
                candidate_authority_sha256=arguments.candidate_authority_sha256,
                output_root=arguments.output_root,
                repository_root=arguments.repository_root,
            )
        else:
            result = provision_current_time(
                output_root=arguments.output_root,
                repository_root=arguments.repository_root,
                subject_sha256=arguments.subject_sha256,
            )
    except (OSError, ValueError) as exc:
        print(f"provisioning refused: {exc}", file=sys.stderr)
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
