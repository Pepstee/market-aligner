#!/usr/bin/env python3
"""Separate, offline JAA-03 acceptance program."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.opportunity_calibration import (  # noqa: E402
    LOCKED_METRICS, Confidence, Opportunity0Input, decide_opportunity0,
    evaluate_locked_set, load_locked_set,
)


def main() -> int:
    records, locked_hash = load_locked_set()
    metrics = evaluate_locked_set(records)
    expected = json.loads(LOCKED_METRICS.read_text(encoding="utf-8"))
    assert expected["locked_set_hash"] == locked_hash
    assert expected["metrics"] == metrics

    attractive = Opportunity0Input.from_mapping({
        "market_demand_bp": 10_000, "role_quality_bp": 10_000, "accessibility_bp": 10_000,
    })
    high = Confidence(10_000, 10_000, 10_000, 10_000)
    for reason in ("expired", "inaccessible", "ineligible", "implausibly_senior"):
        rejected = decide_opportunity0(attractive, high, viability_reason=reason)
        assert (rejected.decision, rejected.reason) == ("reject", reason)
    abstained = decide_opportunity0(attractive, Confidence(10_000, 10_000, 7_499, 10_000))
    assert (abstained.decision, abstained.reason, abstained.score_bp) == (
        "abstain", "low_confidence_extraction", None,
    )
    try:
        Opportunity0Input.from_mapping({
            "market_demand_bp": 0, "role_quality_bp": 0, "accessibility_bp": 0,
            "candidate_fit": 1.0, "interest": 1.0,
        })
    except ValueError:
        pass
    else:
        raise AssertionError("candidate Fit rescued Opportunity-0")
    assert evaluate_locked_set(records) == evaluate_locked_set(records)
    print("JAA-03 acceptance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
