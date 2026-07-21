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
LOCKED_SET_ID = "JAA-03-reviewed-historical-calibration-2026-07-20"
DECISION_RULE_VERSION = "jaa03.gold-decision-rules.v1"
# Independent trust anchor for the reviewed set.  This is deliberately outside
# the attacker-rehashable JSON envelope.  It commits to the identity, policy,
# canonical vacancy inputs, and all expected labels.
LOCKED_SET_AUTHORITY_HASH = "sha256:b1f4b1386903b1f9de437fcccde21872f449f70ea63d374aed4229b87b588d4e"
ALLOWED_REASONS = {
    "viable", "expired", "inaccessible", "ineligible", "implausibly_senior",
    "low_confidence_extraction", "below_opportunity_threshold",
}
_POLICY_HASH_PREFIX = "sha256:"


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
        if (type(self.minimum_confidence_bp) is not int
                or type(self.minimum_opportunity_bp) is not int
                or type(self.weights) is not tuple
                or len(self.weights) != 3
                or any(type(weight) is not int for weight in self.weights)):
            raise ValueError("Opportunity-0 policy parameters have invalid types")
        if sum(self.weights) != 100 or any(w < 0 for w in self.weights):
            raise ValueError("Opportunity-0 weights must be non-negative and total 100")
        if not 0 <= self.minimum_confidence_bp <= 10_000:
            raise ValueError("invalid confidence threshold")
        if not 0 <= self.minimum_opportunity_bp <= 10_000:
            raise ValueError("invalid opportunity threshold")

    @property
    def policy_hash(self) -> str:
        return content_hash(vars(self))


def calibration_policy_digest(policy_hash: str, policy: CalibrationPolicy) -> str:
    """Validate a JAA-03 identity and return its lifecycle-compatible digest.

    JAA-03 owns the prefixed identity.  The lifecycle ledger deliberately owns a
    different, digest-only contract, so conversion is confined to this boundary.
    """
    if (not isinstance(policy_hash, str)
            or not policy_hash.startswith(_POLICY_HASH_PREFIX)
            or len(policy_hash) != len(_POLICY_HASH_PREFIX) + 64):
        raise ValueError("JAA-03 policy hash must be sha256:<64 lowercase hex>")
    digest = policy_hash[len(_POLICY_HASH_PREFIX):]
    if any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("JAA-03 policy hash must be sha256:<64 lowercase hex>")
    if policy_hash != policy.policy_hash:
        raise ValueError("JAA-03 policy hash does not match the typed CalibrationPolicy")
    return digest


def calibration_policy_json(policy: CalibrationPolicy) -> dict[str, Any]:
    """Return the one canonical, JSON-native representation of a policy."""
    return {
        "minimum_confidence_bp": policy.minimum_confidence_bp,
        "minimum_opportunity_bp": policy.minimum_opportunity_bp,
        "weights": list(policy.weights),
    }


def calibration_policy_from_json(value: Any) -> CalibrationPolicy:
    """Decode canonical JSON policy parameters without accepting coercions."""
    required = {"minimum_confidence_bp", "minimum_opportunity_bp", "weights"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("Opportunity-0 policy parameters have unknown or missing fields")
    weights = value["weights"]
    if (type(value["minimum_confidence_bp"]) is not int
            or type(value["minimum_opportunity_bp"]) is not int
            or not isinstance(weights, list) or len(weights) != 3
            or any(type(weight) is not int for weight in weights)):
        raise ValueError("Opportunity-0 policy parameters are not canonical JSON types")
    return CalibrationPolicy(
        minimum_confidence_bp=value["minimum_confidence_bp"],
        minimum_opportunity_bp=value["minimum_opportunity_bp"],
        weights=tuple(weights),
    )


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


_REASON_MARKERS = {
    "viable": "Applications are open and the vacancy is accessible.",
    "expired": "The application deadline expired on 2026-06-01.",
    "inaccessible": "The employer vacancy page is inaccessible.",
    "ineligible": "Applicants must be resident outside the United Kingdom.",
    "implausibly_senior": "This principal role requires ten years of experience.",
    "low_confidence_extraction": "The copied requirements are incomplete and uncertain.",
    "below_opportunity_threshold": "This is a short unpaid role with limited market demand.",
}


def derive_gold_labels(row: Mapping[str, Any]) -> dict[str, Any]:
    """Derive reviewed gold labels solely from canonical inputs and v1 rules."""
    text = row["vacancy"]["text"]
    matches = [reason for reason, marker in _REASON_MARKERS.items() if marker in text]
    if len(matches) != 1:
        raise ValueError(f"canonical reason is not unambiguous: {row.get('id', '<unknown>')}")
    reason = matches[0]
    role_location = f"{str(row['role_family']).title()} role in {row['geography']}."
    requirement = "Essential requirement: Python."
    opportunity = text[text.index("Market evidence:"):]
    spans = []
    for task, needle in (
        ("viability", _REASON_MARKERS[reason]),
        ("eligibility", role_location),
        ("requirements", requirement),
        ("opportunity0", opportunity),
    ):
        start = text.index(needle)
        spans.append({"task": task, "start": start, "end": start + len(needle), "text": needle})
    derived = decide_opportunity0(
        Opportunity0Input.from_mapping(row["opportunity0"]),
        Confidence(**row["confidence"]),
        viability_reason=reason if reason in {
            "expired", "inaccessible", "ineligible", "implausibly_senior"
        } else "viable",
    )
    return {
        "viability": reason not in {"expired", "inaccessible", "implausibly_senior"},
        "eligibility": reason != "ineligible",
        "requirements": [{"text": "Python", "essential": True}],
        "viability_reason": (
            reason if reason in {"expired", "inaccessible", "ineligible", "implausibly_senior"}
            else "viable"
        ),
        "opportunity0_decision": {"decision": derived.decision, "reason": derived.reason},
        "source_spans": spans,
    }


def locked_set_authority_document(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Return the immutable commitment domain; never includes envelope hashes."""
    return {
        "domain": "jaa03-locked-set-authority-v1",
        "locked_set_id": envelope.get("locked_set_id"),
        "decision_rule_version": envelope.get("decision_rule_version"),
        "policy": vars(CalibrationPolicy()),
        "schema_version": envelope.get("schema_version"),
        "frozen_at": envelope.get("frozen_at"),
        "stratification": envelope.get("stratification"),
        "records": envelope.get("records"),
    }


def load_locked_set(path: Path = LOCKED_SET) -> tuple[list[dict[str, Any]], str]:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    records = envelope["records"]
    if envelope.get("schema_version") != "jaa03.locked-set.v1" or len(records) != 100:
        raise ValueError("JAA-03 set must contain exactly 100 v1 records")
    if envelope.get("locked_set_id") != LOCKED_SET_ID:
        raise ValueError("JAA-03 locked-set identity mismatch")
    if envelope.get("decision_rule_version") != DECISION_RULE_VERSION:
        raise ValueError("JAA-03 decision-rule version mismatch")
    if content_hash(records) != envelope.get("records_hash"):
        raise ValueError("JAA-03 locked-set hash mismatch")
    if content_hash(locked_set_authority_document(envelope)) != LOCKED_SET_AUTHORITY_HASH:
        raise ValueError("JAA-03 locked-set authority mismatch")
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
        if row["labels"] != derive_gold_labels(row):
            raise ValueError(f"gold decision derivation mismatch: {row['id']}")
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
