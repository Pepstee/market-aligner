#!/usr/bin/env python3
"""Run one fixed-root non-release production preparation."""

from __future__ import annotations

import argparse

from career_automation.evidence_matching import canonical_json
from career_automation.production_preparation_runner import run_production_preparation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--application-id", required=True)
    arguments = parser.parse_args()
    result = run_production_preparation(application_id=arguments.application_id)
    print(canonical_json({
        "application_id": arguments.application_id,
        "path": str(result.path),
        "preparation_id": result.preparation_id,
        "receipt_sha256": result.receipt_sha256,
        "release_authority": False,
        "schema_version": "jaa.production-application-preparation-cli.v1",
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
