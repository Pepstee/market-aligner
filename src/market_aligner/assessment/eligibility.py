"""Deterministic hard-eligibility checks over explicit structured facts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EligibilityPolicy:
    authorised_jurisdictions: frozenset[str]
    current_residence: str | None = None
    requires_sponsorship: bool | None = None
    maximum_years_required: float | None = None
    excluded_contract_types: frozenset[str] = frozenset()


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


def _normal(value: str | None) -> str | None:
    return value.casefold().strip() if value else None


def assess_eligibility(facts: EligibilityInput, policy: EligibilityPolicy) -> EligibilityDecision:
    rejects: list[str] = []
    unknowns: list[str] = []
    jurisdiction = _normal(facts.work_jurisdiction)
    authorised = {_normal(item) for item in policy.authorised_jurisdictions}
    if jurisdiction is None:
        unknowns.append("work_jurisdiction_unknown")
    elif authorised and jurisdiction not in authorised:
        rejects.append("work_authorisation_mismatch")

    required_residence = _normal(facts.required_residence)
    current_residence = _normal(policy.current_residence)
    if required_residence and current_residence and required_residence != current_residence:
        rejects.append("residence_requirement_mismatch")
    elif required_residence and not current_residence:
        unknowns.append("candidate_residence_unknown")

    if policy.requires_sponsorship is True:
        if facts.sponsorship_available is False:
            rejects.append("sponsorship_unavailable")
        elif facts.sponsorship_available is None:
            unknowns.append("sponsorship_availability_unknown")

    if policy.maximum_years_required is not None:
        if facts.minimum_years_experience is None:
            unknowns.append("minimum_experience_unknown")
        elif facts.minimum_years_experience > policy.maximum_years_required:
            rejects.append("experience_requirement_exceeds_policy")

    contract = _normal(facts.contract_type)
    excluded = {_normal(item) for item in policy.excluded_contract_types}
    if contract and contract in excluded:
        rejects.append("excluded_contract_type")

    if rejects:
        return EligibilityDecision("reject", tuple(sorted(set(rejects))), tuple(sorted(set(unknowns))))
    if unknowns:
        return EligibilityDecision("review", (), tuple(sorted(set(unknowns))))
    return EligibilityDecision("pass", (), ())
