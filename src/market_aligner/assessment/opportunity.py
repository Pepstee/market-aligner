"""Deterministic opportunity admission before employer research."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from market_aligner.research.store import AssessmentStore


@dataclass(frozen=True)
class OpportunityPolicy:
    minimum_opportunity: float = 0.55
    minimum_extraction_confidence: float = 0.70
    high_priority_opportunity: float = 0.75

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if not 0 <= float(value) <= 1:
                raise ValueError(f"{name} must be in [0,1]")
        if self.high_priority_opportunity < self.minimum_opportunity:
            raise ValueError("high-priority threshold cannot be below admission threshold")

    @property
    def policy_hash(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class OpportunityDecision:
    passed: bool
    reason: str
    priority: int | None


def decide(row: object, policy: OpportunityPolicy | None = None) -> OpportunityDecision:
    policy = policy or OpportunityPolicy()
    opportunity = float(row["opportunity"])  # type: ignore[index]
    confidence = row["extraction_confidence"]  # type: ignore[index]
    if confidence is None or float(confidence) < policy.minimum_extraction_confidence:
        return OpportunityDecision(False, "insufficient_extraction_confidence", None)
    if opportunity < policy.minimum_opportunity:
        return OpportunityDecision(False, "below_opportunity_threshold", None)
    tier = 2 if opportunity >= policy.high_priority_opportunity else 1
    return OpportunityDecision(
        True,
        "opportunity_warrants_employer_reconnaissance",
        tier * 1_000_000 + round(opportunity * 100_000),
    )


def apply_gate(
    store: AssessmentStore,
    profile_id: str,
    job_key: str,
    policy: OpportunityPolicy | None = None,
) -> OpportunityDecision:
    policy = policy or OpportunityPolicy()
    decision = decide(store.assessment(profile_id, job_key), policy)
    store.apply_opportunity_gate(
        profile_id=profile_id,
        job_key=job_key,
        passed=decision.passed,
        reason=decision.reason,
        policy_hash=policy.policy_hash,
        priority=decision.priority,
    )
    return decision
