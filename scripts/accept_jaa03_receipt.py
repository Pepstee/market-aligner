#!/usr/bin/env python3
"""Validate immutable JAA-03 runtime evidence without whole-repository invalidation."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.opportunity_calibration import (  # noqa: E402
    DECISION_RULE_VERSION,
    LOCKED_METRICS,
    LOCKED_SET,
    LOCKED_SET_ID,
    CalibrationPolicy,
)
from scripts.accept_jaa_03 import (  # noqa: E402
    AcceptanceError,
    FORMAT,
    run_acceptance,
    validate_existing_receipts,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def validate() -> Path:
    receipts = validate_existing_receipts()
    require(len(receipts) == 1, f"expected exactly one JAA-03 receipt, found {len(receipts)}")
    path, document = receipts[0]
    require(document.get("format") == FORMAT and document.get("status") == "PASS",
            "unsupported JAA-03 receipt")
    require(document.get("runtime") == {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
    }, "JAA-03 runtime identity mismatch")
    require(document.get("runtime_inputs") == {
        "locked_set_file_sha256": _sha256(LOCKED_SET),
        "locked_metrics_file_sha256": _sha256(LOCKED_METRICS),
    }, "JAA-03 locked runtime inputs changed")
    policy = CalibrationPolicy()
    require(document.get("configuration") == {
        "locked_set_id": LOCKED_SET_ID,
        "decision_rule_version": DECISION_RULE_VERSION,
        "policy": {
            "minimum_confidence_bp": policy.minimum_confidence_bp,
            "minimum_opportunity_bp": policy.minimum_opportunity_bp,
            "weights": list(policy.weights),
        },
        "policy_hash": policy.policy_hash,
    }, "JAA-03 calibration configuration changed")
    require(document.get("acceptance_result") == run_acceptance(),
            "JAA-03 acceptance result no longer replays")
    recorded_revision = document.get("source_content_revision")
    require(isinstance(recorded_revision, str) and recorded_revision.startswith("sha256:")
            and len(recorded_revision) == 71,
            "invalid historical JAA-03 source revision")
    return path


def main() -> int:
    try:
        receipt = validate()
    except (AcceptanceError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"jaa03-receipt-acceptance: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "receipt": receipt.relative_to(ROOT).as_posix(),
        "status": "accepted",
        "scope": "historical-runtime-evidence",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
