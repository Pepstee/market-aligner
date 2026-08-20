#!/usr/bin/env python3
"""Exercise the production JAA-04 policy producer/consumer JSON boundary."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.opportunity_calibration import (  # noqa: E402
    CalibrationPolicy, calibration_policy_from_json, calibration_policy_json,
)


def main() -> int:
    current = CalibrationPolicy()
    encoded = json.dumps(calibration_policy_json(current), sort_keys=True)
    decoded = calibration_policy_from_json(json.loads(encoded))
    if decoded != current or decoded.policy_hash != current.policy_hash:
        raise RuntimeError("JAA-04 policy changed across its production JSON boundary")

    invalid = [
        {"minimum_confidence_bp": 7500, "minimum_opportunity_bp": 5500},
        {**calibration_policy_json(current), "unknown": 1},
        {**calibration_policy_json(current), "minimum_confidence_bp": True},
        {**calibration_policy_json(current), "weights": [45, 35, "20"]},
    ]
    for value in invalid:
        try:
            calibration_policy_from_json(value)
        except ValueError:
            continue
        raise RuntimeError("non-canonical JAA-04 policy was accepted")
    print("JAA-04 policy serialization: SUCCESS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
