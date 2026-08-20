"""Deterministic, candidate-independent Opportunity-1 reassessment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .employer_research import content_hash


@dataclass(frozen=True)
class Opportunity1Policy:
    minimum_score_bp: int = 5500
    maximum_adjustment_bp: int = 3000

    @property
    def policy_hash(self) -> str:
        return content_hash(vars(self))


@dataclass(frozen=True)
class ScoreChange:
    claim_id: str
    reason: str
    delta_bp: int


@dataclass(frozen=True)
class Opportunity1Decision:
    opportunity0_score_bp: int
    score_bp: int
    decision: str
    changes: tuple[ScoreChange, ...]
    policy_hash: str


def reassess_opportunity1(opportunity0_score_bp: int, signals: Sequence[Mapping[str, object]], *, policy: Opportunity1Policy | None = None) -> Opportunity1Decision:
    policy = policy or Opportunity1Policy()
    if not 0 <= opportunity0_score_bp <= 10_000:
        raise ValueError("Opportunity-0 score must be basis points")
    changes = []
    seen = set()
    for signal in sorted(signals, key=lambda row: str(row.get("claim_id", ""))):
        claim_id, reason = str(signal.get("claim_id", "")), str(signal.get("reason", ""))
        delta = signal.get("delta_bp")
        if not claim_id or claim_id in seen or not reason or not isinstance(delta, int):
            raise ValueError("each unique signal requires claim_id, reason and integer delta_bp")
        if abs(delta) > policy.maximum_adjustment_bp:
            raise ValueError("signal adjustment exceeds policy")
        seen.add(claim_id)
        changes.append(ScoreChange(claim_id, reason, delta))
    score = max(0, min(10_000, opportunity0_score_bp + sum(row.delta_bp for row in changes)))
    return Opportunity1Decision(opportunity0_score_bp, score, "pass" if score >= policy.minimum_score_bp else "reject", tuple(changes), policy.policy_hash)
