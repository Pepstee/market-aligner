#!/usr/bin/env python3
"""Run one fixed-root non-release production preparation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

JAA_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(JAA_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from career_automation.evidence_matching import canonical_json
from career_automation.production_preparation_runner import (
    run_production_market_pre_review,
    run_production_preparation,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--current-runtime-config")
    parser.add_argument("--current-runtime-config-sha256")
    parser.add_argument("--current-runtime-private-root")
    parser.add_argument("--current-recovery-manifest-relative-path")
    arguments = parser.parse_args(argv)
    current_values = (
        arguments.current_runtime_config,
        arguments.current_runtime_config_sha256,
        arguments.current_runtime_private_root,
        arguments.current_recovery_manifest_relative_path,
    )
    if any(value is not None for value in current_values):
        if not all(value is not None for value in current_values):
            parser.error("current runtime options must be supplied together")
        result = run_production_market_pre_review(
            application_id=arguments.application_id,
            current_runtime_config_path=arguments.current_runtime_config,
            current_runtime_config_sha256=arguments.current_runtime_config_sha256,
            current_runtime_private_root=arguments.current_runtime_private_root,
            current_recovery_manifest_relative_path=(
                arguments.current_recovery_manifest_relative_path
            ),
        )
        result_schema = "jaa.market-application-pre-review-cli.v1"
    else:
        result = run_production_preparation(application_id=arguments.application_id)
        result_schema = "jaa.production-application-preparation-cli.v1"
    output = {
        "application_id": arguments.application_id,
        "path": str(result.path),
        "preparation_id": result.preparation_id,
        "receipt_sha256": result.receipt_sha256,
        "release_authority": False,
        "schema_version": result_schema,
    }
    if result.review_status is not None:
        output["review_status"] = result.review_status
    print(canonical_json(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
