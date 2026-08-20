"""Deterministic opportunity admission before employer research."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from market_aligner.domain.contracts import Vacancy
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
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class OpportunityDecision:
    passed: bool
    reason: str
    priority: int | None


@dataclass(frozen=True)
class OpportunityAxisPolicy:
    """Explicit vacancy-fact proxy policy; it does not claim labour-market calibration."""

    market_base: float = 4.0
    market_per_required_skill: float = 0.35
    market_per_responsibility: float = 0.15
    market_permanent_bonus: float = 0.5
    barrier_base: float = 2.0
    barrier_per_required_skill: float = 0.2
    barrier_per_required_qualification: float = 0.6
    barrier_per_work_authorisation_constraint: float = 0.4
    growth_base: float = 4.0
    growth_per_explicit_signal: float = 0.6
    growth_permanent_bonus: float = 0.5
    growth_entry_bonus: float = 0.5
    seniority_barriers: tuple[tuple[str, float], ...] = (
        ("intern", 1.0),
        ("apprentice", 1.0),
        ("graduate", 1.5),
        ("entry", 1.5),
        ("junior", 2.5),
        ("mid", 5.0),
        ("senior", 7.5),
        ("lead", 8.5),
        ("principal", 9.0),
        ("manager", 8.0),
        ("director", 9.5),
    )
    growth_signals: tuple[str, ...] = (
        "career development",
        "career progression",
        "certification",
        "learning budget",
        "mentoring",
        "mentorship",
        "professional development",
        "training",
    )

    @property
    def policy_hash(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class OpportunityAxisDerivation:
    market_demand: float
    barrier_to_entry: float
    growth_potential: float
    facts_sha256: str
    policy_sha256: str
    signals: tuple[str, ...]


def derive_opportunity_axes(
    vacancy: Vacancy, policy: OpportunityAxisPolicy | None = None
) -> OpportunityAxisDerivation:
    """Derive bounded job-specific proxies exclusively from normalized vacancy facts."""

    policy = policy or OpportunityAxisPolicy()
    required_skills = tuple(value.strip() for value in vacancy.required_skills if value.strip())
    responsibilities = tuple(value.strip() for value in vacancy.responsibilities if value.strip())
    qualifications = tuple(
        value.strip() for value in vacancy.required_qualifications if value.strip()
    )
    work_constraints = tuple(
        value.strip() for value in vacancy.work_authorisation if value.strip()
    )
    contract = vacancy.contract_type.strip().casefold()
    seniority = vacancy.seniority.strip().casefold()
    text = "\n".join(
        (
            vacancy.title,
            vacancy.description,
            *vacancy.responsibilities,
            *vacancy.preferred_qualifications,
        )
    ).casefold()
    permanent = any(token in contract for token in ("permanent", "full-time", "full time"))

    market = (
        policy.market_base
        + min(len(required_skills), 8) * policy.market_per_required_skill
        + min(len(responsibilities), 8) * policy.market_per_responsibility
        + (policy.market_permanent_bonus if permanent else 0.0)
    )
    matched_seniority = next(
        ((label, value) for label, value in policy.seniority_barriers if label in seniority),
        ("unknown", 5.0),
    )
    barrier = (
        max(policy.barrier_base, matched_seniority[1])
        + min(len(required_skills), 10) * policy.barrier_per_required_skill
        + min(len(qualifications), 5) * policy.barrier_per_required_qualification
        + min(len(work_constraints), 3) * policy.barrier_per_work_authorisation_constraint
    )
    explicit_growth = tuple(signal for signal in policy.growth_signals if signal in text)
    entry = matched_seniority[0] in {"intern", "apprentice", "graduate", "entry", "junior"}
    growth = (
        policy.growth_base
        + min(len(explicit_growth), 5) * policy.growth_per_explicit_signal
        + (policy.growth_permanent_bonus if permanent else 0.0)
        + (policy.growth_entry_bonus if entry else 0.0)
    )
    facts_payload = asdict(vacancy)
    facts_sha256 = hashlib.sha256(
        json.dumps(facts_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    signals = (
        f"required_skills:{len(required_skills)}",
        f"responsibilities:{len(responsibilities)}",
        f"required_qualifications:{len(qualifications)}",
        f"work_authorisation_constraints:{len(work_constraints)}",
        f"contract_permanent:{str(permanent).lower()}",
        f"seniority:{matched_seniority[0]}",
        *(f"explicit_growth:{value}" for value in explicit_growth),
    )
    return OpportunityAxisDerivation(
        market_demand=min(10.0, max(0.0, market)),
        barrier_to_entry=min(10.0, max(0.0, barrier)),
        growth_potential=min(10.0, max(0.0, growth)),
        facts_sha256=facts_sha256,
        policy_sha256=policy.policy_hash,
        signals=signals,
    )


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
