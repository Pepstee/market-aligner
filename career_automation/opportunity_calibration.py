"""JAA-03 locked-set calibration and candidate-independent Opportunity-0.

All score arithmetic uses integer basis points.  Candidate Fit and interest are
deliberately not members of the input contract, so they cannot affect admission.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


LOCKED_SET = Path(__file__).with_name("fixtures") / "jaa03_vacancies.json"
LOCKED_METRICS = Path(__file__).with_name("fixtures") / "jaa03_locked_metrics.json"
ALLOWED_REASONS = {
    "viable", "expired", "inaccessible", "ineligible", "implausibly_senior",
    "low_confidence_extraction", "below_opportunity_threshold",
}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def content_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class Confidence:
    viability_bp: int
    eligibility_bp: int
    requirements_bp: int
    opportunity_bp: int

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or not 0 <= value <= 10_000:
                raise ValueError(f"{name} must be integer basis points")


@dataclass(frozen=True)
class Opportunity0Input:
    market_demand_bp: int
    role_quality_bp: int
    accessibility_bp: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Opportunity0Input":
        forbidden = {"fit", "candidate_fit", "interest", "candidate_interest"} & value.keys()
        if forbidden:
            raise ValueError("Opportunity-0 cannot consume candidate Fit or interest")
        unknown = set(value) - {"market_demand_bp", "role_quality_bp", "accessibility_bp"}
        if unknown:
            raise ValueError(f"unknown Opportunity-0 fields: {sorted(unknown)}")
        return cls(**value)

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or not 0 <= value <= 10_000:
                raise ValueError(f"{name} must be integer basis points")


@dataclass(frozen=True)
class CalibrationPolicy:
    minimum_confidence_bp: int = 7_500
    minimum_opportunity_bp: int = 5_500
    weights: tuple[int, int, int] = (45, 35, 20)

    def __post_init__(self) -> None:
        if sum(self.weights) != 100 or any(w < 0 for w in self.weights):
            raise ValueError("Opportunity-0 weights must be non-negative and total 100")
        if not 0 <= self.minimum_confidence_bp <= 10_000:
            raise ValueError("invalid confidence threshold")
        if not 0 <= self.minimum_opportunity_bp <= 10_000:
            raise ValueError("invalid opportunity threshold")

    @property
    def policy_hash(self) -> str:
        return content_hash(vars(self))


@dataclass(frozen=True)
class Opportunity0Decision:
    decision: str
    reason: str
    score_bp: int | None
    policy_hash: str


def opportunity_score(value: Opportunity0Input, policy: CalibrationPolicy) -> int:
    """Exact, cross-platform half-up rounding of a weighted integer mean."""
    terms = (value.market_demand_bp, value.role_quality_bp, value.accessibility_bp)
    numerator = sum(component * weight for component, weight in zip(terms, policy.weights))
    return (numerator + 50) // 100


def decide_opportunity0(
    value: Opportunity0Input,
    confidence: Confidence,
    *,
    viability_reason: str = "viable",
    policy: CalibrationPolicy | None = None,
) -> Opportunity0Decision:
    policy = policy or CalibrationPolicy()
    if viability_reason not in ALLOWED_REASONS:
        raise ValueError("unknown viability reason")
    if viability_reason != "viable":
        return Opportunity0Decision("reject", viability_reason, None, policy.policy_hash)
    if min(vars(confidence).values()) < policy.minimum_confidence_bp:
        return Opportunity0Decision("abstain", "low_confidence_extraction", None, policy.policy_hash)
    score = opportunity_score(value, policy)
    if score < policy.minimum_opportunity_bp:
        return Opportunity0Decision("reject", "below_opportunity_threshold", score, policy.policy_hash)
    return Opportunity0Decision("pass", "viable", score, policy.policy_hash)


def load_locked_set(path: Path = LOCKED_SET) -> tuple[list[dict[str, Any]], str]:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    records = envelope["records"]
    if envelope.get("schema_version") != "jaa03.locked-set.v1" or len(records) != 100:
        raise ValueError("JAA-03 set must contain exactly 100 v1 records")
    if content_hash(records) != envelope.get("records_hash"):
        raise ValueError("JAA-03 locked-set hash mismatch")
    for row in records:
        text = row["vacancy"]["text"]
        if content_hash(row["vacancy"]) != row["content_hash"]:
            raise ValueError(f"content hash mismatch: {row['id']}")
        spans = row["labels"]["source_spans"]
        required = {"viability", "eligibility", "requirements", "opportunity0"}
        if {span["task"] for span in spans} != required:
            raise ValueError(f"missing source-span task: {row['id']}")
        for span in spans:
            if text[span["start"]:span["end"]] != span["text"]:
                raise ValueError(f"invalid source span: {row['id']}")
    return records, envelope["records_hash"]


def evaluate_locked_set(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Replay gold-labelled decisions and publish deterministic metrics/slices."""
    totals: dict[str, list[int]] = {"overall": [0, 0]}
    for row in records:
        expected = row["labels"]["opportunity0_decision"]
        got = decide_opportunity0(
            Opportunity0Input.from_mapping(row["opportunity0"]),
            Confidence(**row["confidence"]),
            viability_reason=row["labels"]["viability_reason"],
        )
        correct = int(got.decision == expected["decision"] and got.reason == expected["reason"])
        totals["overall"][0] += correct
        totals["overall"][1] += 1
        for dimension in ("source", "role_family", "geography"):
            key = f"{dimension}:{row[dimension]}"
            bucket = totals.setdefault(key, [0, 0])
            bucket[0] += correct
            bucket[1] += 1
    slices = {
        key: {"correct": value[0], "count": value[1], "accuracy_bp": value[0] * 10_000 // value[1]}
        for key, value in sorted(totals.items())
    }
    return {"schema_version": "jaa03.metrics.v1", "count": len(records), "slices": slices}
