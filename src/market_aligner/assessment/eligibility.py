"""Deterministic hard-eligibility checks over explicit structured facts.

ELIGIBILITY-001 decision owner (accepted contract:
docs/eligibility/ELIGIBILITY-001_EVIDENCE_BOUND_DECISION_CONTRACT.md, section 11).

Inputs arrive as exact canonical values (uppercase ISO members, lowercase
contract-enum members); the coordinator refuses anything else before this owner
runs. Comparisons are therefore exact — the historical casefold/strip
normalization was removed by authorized repair T5.

Authorized typed repairs (contract section 11):
T1  EligibilityPolicy.authorised_jurisdictions / excluded_contract_types are
    ``frozenset[str] | None`` so UNKNOWN (None) and KNOWN-EMPTY (frozenset())
    stay distinct end-to-end.
T2  Route-based work-authorisation/sponsorship evaluation per the authoritative
    J-table; no premature work_authorisation_mismatch before a viable
    sponsorship route is evaluated.
T3  Exclusion-dimension UNKNOWN handling (review token when exclusions are
    unknown but the vacancy contract is stated).
T4  Experience-ceiling direction: gate on the stated vacancy minimum.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EligibilityPolicy:
    # T1: UNKNOWN (None) versus KNOWN-EMPTY (empty frozenset) stay distinct.
    authorised_jurisdictions: frozenset[str] | None = None
    current_residence: str | None = None
    requires_sponsorship: bool | None = None
    maximum_years_required: float | None = None
    excluded_contract_types: frozenset[str] | None = None


@dataclass(frozen=True)
class EligibilityInput:
    work_jurisdiction: str | None = None
    required_residence: str | None = None
    sponsorship_available: bool | None = None
    minimum_years_experience: float | None = None
    contract_type: str | None = None


@dataclass(frozen=True)
class EligibilityDecision:
    decision: str
    reasons: tuple[str, ...]
    unknowns: tuple[str, ...]


def assess_eligibility(facts: EligibilityInput, policy: EligibilityPolicy) -> EligibilityDecision:
    """Pure decision owner over exact canonical values (contract section 11)."""
    rejects: list[str] = []
    unknowns: list[str] = []

    jur = facts.work_jurisdiction
    auth = policy.authorised_jurisdictions
    rs = policy.requires_sponsorship
    sa = facts.sponsorship_available

    if jur is None:
        unknowns.append("work_jurisdiction_unknown")
    elif auth is not None and jur in auth:
        pass  # exact independently-authorized match satisfies; sponsorship irrelevant
    elif auth is not None:  # KNOWN set without the member (incl. KNOWN-EMPTY)
        if rs is True:
            if sa is True:
                pass
            elif sa is False:
                rejects.append("sponsorship_unavailable")
            else:
                unknowns.append("sponsorship_availability_unknown")
        elif rs is False:
            rejects.append("work_authorisation_mismatch")
        else:
            unknowns.append("sponsorship_requirement_unknown")
    else:  # UNKNOWN authorisations
        if rs is True:
            if sa is True:
                pass  # proven need authorizes the same true-availability route
            elif sa is False:
                rejects.append("sponsorship_unavailable")
            else:
                unknowns.append("sponsorship_availability_unknown")
        elif rs is False:
            unknowns.append("authorised_jurisdictions_unknown")  # never mismatch here
        else:
            unknowns.append("authorised_jurisdictions_unknown")
            unknowns.append("sponsorship_requirement_unknown")

    req = facts.required_residence
    cur = policy.current_residence
    if req and cur and req != cur:
        rejects.append("residence_requirement_mismatch")
    elif req and not cur:
        unknowns.append("candidate_residence_unknown")

    if facts.minimum_years_experience is not None:  # T4: gate on stated minimum
        if policy.maximum_years_required is None:
            unknowns.append("maximum_experience_ceiling_unknown")
        elif facts.minimum_years_experience > policy.maximum_years_required:
            rejects.append("experience_requirement_exceeds_policy")

    ct = facts.contract_type
    excluded = policy.excluded_contract_types  # T3: frozenset | None
    if ct is None:
        pass  # absent vacancy contract: no dimension, no unknown
    elif excluded is not None:
        if ct in excluded:
            rejects.append("excluded_contract_type")
        # known set without it (including KNOWN-EMPTY) satisfies
    else:
        unknowns.append("excluded_contract_types_unknown")

    if rejects:
        return EligibilityDecision(
            "reject", tuple(sorted(set(rejects))), tuple(sorted(set(unknowns)))
        )
    if unknowns:
        return EligibilityDecision("review", (), tuple(sorted(set(unknowns))))
    return EligibilityDecision("pass", (), ())
