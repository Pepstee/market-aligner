"""Deterministic opportunity admission before employer research."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Mapping

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


_PRE_PROFILE_ALLOWED_REASONS = frozenset(
    {
        "viable",
        "expired",
        "inaccessible",
        "ineligible",
        "implausibly_senior",
        "low_confidence_extraction",
        "below_opportunity_threshold",
    }
)


def _basis_points(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 10_000:
        raise ValueError(f"{label} must be integer basis points")
    return value


@dataclass(frozen=True)
class PreProfileOpportunityInput:
    """Candidate-independent Market opportunity signals.

    This deliberately precedes profile scoring: candidate fit and interest are
    rejected at the input boundary so collection triage cannot be influenced by
    private candidate data.
    """

    market_demand_bp: int
    role_quality_bp: int
    accessibility_bp: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "PreProfileOpportunityInput":
        forbidden = {"fit", "candidate_fit", "interest", "candidate_interest"} & set(value)
        if forbidden:
            raise ValueError("pre-profile opportunity cannot consume candidate fit or interest")
        required = {"market_demand_bp", "role_quality_bp", "accessibility_bp"}
        if set(value) != required:
            raise ValueError("pre-profile opportunity fields are unknown or incomplete")
        return cls(**dict(value))

    def __post_init__(self) -> None:
        for label, value in vars(self).items():
            _basis_points(value, label)


@dataclass(frozen=True)
class PreProfileOpportunityConfidence:
    viability_bp: int
    eligibility_bp: int
    requirements_bp: int
    opportunity_bp: int

    def __post_init__(self) -> None:
        for label, value in vars(self).items():
            _basis_points(value, label)


@dataclass(frozen=True)
class PreProfileOpportunityPolicy:
    minimum_confidence_bp: int = 7_500
    minimum_opportunity_bp: int = 5_500
    weights: tuple[int, int, int] = (45, 35, 20)

    def __post_init__(self) -> None:
        _basis_points(self.minimum_confidence_bp, "minimum_confidence_bp")
        _basis_points(self.minimum_opportunity_bp, "minimum_opportunity_bp")
        if (
            type(self.weights) is not tuple
            or len(self.weights) != 3
            or any(type(weight) is not int or weight < 0 for weight in self.weights)
            or sum(self.weights) != 100
        ):
            raise ValueError(
                "pre-profile opportunity weights must be non-negative integers totaling 100"
            )

    @property
    def policy_hash(self) -> str:
        return "sha256:" + hashlib.sha256(
            json.dumps(self.document(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def document(self) -> dict[str, object]:
        return {
            "minimum_confidence_bp": self.minimum_confidence_bp,
            "minimum_opportunity_bp": self.minimum_opportunity_bp,
            "weights": list(self.weights),
        }

    @classmethod
    def from_document(cls, value: object) -> "PreProfileOpportunityPolicy":
        if not isinstance(value, dict) or set(value) != {
            "minimum_confidence_bp",
            "minimum_opportunity_bp",
            "weights",
        }:
            raise ValueError("pre-profile opportunity policy fields are unknown or incomplete")
        weights = value["weights"]
        if not isinstance(weights, list):
            raise ValueError("pre-profile opportunity policy weights must be a JSON list")
        return cls(
            minimum_confidence_bp=value["minimum_confidence_bp"],
            minimum_opportunity_bp=value["minimum_opportunity_bp"],
            weights=tuple(weights),
        )


@dataclass(frozen=True)
class PreProfileOpportunityDecision:
    decision: str
    reason: str
    score_bp: int | None
    policy_hash: str


def pre_profile_opportunity_score(
    value: PreProfileOpportunityInput,
    policy: PreProfileOpportunityPolicy,
) -> int:
    """Return the cross-platform half-up weighted score in basis points."""
    terms = (value.market_demand_bp, value.role_quality_bp, value.accessibility_bp)
    return (
        sum(component * weight for component, weight in zip(terms, policy.weights)) + 50
    ) // 100


def decide_pre_profile_opportunity(
    value: PreProfileOpportunityInput,
    confidence: PreProfileOpportunityConfidence,
    *,
    viability_reason: str = "viable",
    policy: PreProfileOpportunityPolicy | None = None,
) -> PreProfileOpportunityDecision:
    """Gate a collected vacancy before any profile-bound assessment exists."""
    policy = policy or PreProfileOpportunityPolicy()
    if viability_reason not in _PRE_PROFILE_ALLOWED_REASONS:
        raise ValueError("unknown pre-profile viability reason")
    if viability_reason != "viable":
        return PreProfileOpportunityDecision("reject", viability_reason, None, policy.policy_hash)
    if min(vars(confidence).values()) < policy.minimum_confidence_bp:
        return PreProfileOpportunityDecision(
            "abstain", "low_confidence_extraction", None, policy.policy_hash
        )
    score_bp = pre_profile_opportunity_score(value, policy)
    if score_bp < policy.minimum_opportunity_bp:
        return PreProfileOpportunityDecision(
            "reject", "below_opportunity_threshold", score_bp, policy.policy_hash
        )
    return PreProfileOpportunityDecision("pass", "viable", score_bp, policy.policy_hash)


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
