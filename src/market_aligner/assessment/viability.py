"""Profile-independent deterministic checks over vacancy state."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from datetime import date, datetime, timedelta, timezone
from typing import Mapping, Sequence

from market_aligner.domain.contracts import Vacancy


@dataclass(frozen=True)
class ViabilityPolicy:
    maximum_age_days: int = 365
    require_complete_description: bool = True


@dataclass(frozen=True)
class ViabilityDecision:
    job_key: str
    decision: str
    reason: str
    http_status: int | None = None


@dataclass(frozen=True)
class FirstJobScopePolicy:
    entry_title_patterns: tuple[str, ...] = (
        r"\bjunior\b", r"\bgraduate\b", r"\bentry[ -]level\b", r"\btrainee\b",
        r"\bapprentice\b",
    )
    adjacent_title_patterns: tuple[str, ...] = (
        r"\bengineer\b", r"\bdeveloper\b", r"\banalyst\b", r"\bconsultant\b",
        r"\bspecialist\b", r"\btechnician\b", r"\bcoordinator\b",
    )
    senior_title_patterns: tuple[str, ...] = (
        r"\bsenior\b", r"\bsr\.?(?=\s|$)", r"\bprincipal\b", r"\bstaff\b",
        r"\bdirector\b",
        r"\blead\b.*\b(engineer|engineering|developer|architect|platform|software|technical|data|automation)\b",
        r"\b(engineer|engineering|developer|architect|platform|software|technical|data|automation)\b.*\blead\b",
    )
    clearance_requirement_patterns: tuple[str, ...] = (
        r"\bsecurity clearance\b.*\b(required|eligible|eligibility|must|needed)\b",
        r"\b(required|must|need|eligible|eligibility)\b.*\bsecurity clearance\b",
        r"\b(sc|dv|nato)\s+(cleared|clearance)\b",
        r"\b(already|currently|must)\s+(holds?|holding|held)\b.{0,80}\bsecurity clearance\b",
        r"\balready[- ]held\b.{0,80}\bsecurity clearance\b",
    )
    citizenship_residence_requirement_patterns: tuple[str, ...] = (
        r"\b(uk|british)\s+(citizens?|citizenship)\b",
        r"\b\d+\s+years?(?:'|’)?\s+(continuous\s+)?(uk\s+)?residen(?:ce|cy)\b",
        r"\bresiden(?:t|ce|cy)\s+in\s+(the\s+)?uk\b.{0,40}\b\d+\s+years?\b",
    )

    def __post_init__(self) -> None:
        for name, patterns in asdict(self).items():
            if not patterns or any(not str(pattern).strip() for pattern in patterns):
                raise ValueError(f"first-job {name} must contain non-empty patterns")
            for pattern in patterns:
                re.compile(pattern, re.IGNORECASE)

    @property
    def policy_hash(self) -> str:
        return _hash(asdict(self))

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, object] | None,
        *,
        default: "FirstJobScopePolicy | None" = None,
    ) -> "FirstJobScopePolicy":
        policy = default or cls()
        if value is None:
            return policy
        unknown = set(value) - set(asdict(policy))
        if unknown:
            raise ValueError(f"unknown first-job scope settings: {sorted(unknown)}")
        updates: dict[str, tuple[str, ...]] = {}
        for key, raw in value.items():
            if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
                raise ValueError(f"first-job scope {key} must be a list")
            updates[key] = tuple(str(item) for item in raw)
        return replace(policy, **updates)


@dataclass(frozen=True)
class FirstJobScopeDecision:
    job_key: str
    decision: str
    reason: str
    matched_pattern: str | None
    facts_sha256: str
    policy_sha256: str


def parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def assess_viability(
    vacancy: Vacancy,
    policy: ViabilityPolicy | None = None,
    *,
    today: date | None = None,
    http_status: int | None = None,
) -> ViabilityDecision:
    policy = policy or ViabilityPolicy()
    today = today or datetime.now(timezone.utc).date()
    if http_status in (404, 410):
        return ViabilityDecision(vacancy.key, "exclude", "inaccessible_or_removed", http_status)
    expiry = parse_date(vacancy.expires_at)
    if expiry and expiry < today:
        return ViabilityDecision(vacancy.key, "exclude", "expired", http_status)
    posted = parse_date(vacancy.posted_at)
    if posted and posted < today - timedelta(days=policy.maximum_age_days):
        return ViabilityDecision(vacancy.key, "exclude", "stale_posting", http_status)
    if not vacancy.url.startswith(("https://", "http://")):
        return ViabilityDecision(vacancy.key, "exclude", "missing_or_invalid_url", http_status)
    if not vacancy.title.strip():
        return ViabilityDecision(vacancy.key, "exclude", "missing_title", http_status)
    if policy.require_complete_description and not vacancy.description.strip():
        return ViabilityDecision(vacancy.key, "exclude", "missing_complete_description", http_status)
    return ViabilityDecision(vacancy.key, "include", "viable", http_status)


def assess_first_job_scope(
    vacancy: Vacancy,
    policy: FirstJobScopePolicy | None = None,
) -> FirstJobScopeDecision:
    """Gate only explicit title/requirement facts before evidence alignment."""

    policy = policy or FirstJobScopePolicy()
    facts = {
        "required_qualifications": vacancy.required_qualifications,
        "title": vacancy.title,
        "work_authorisation": vacancy.work_authorisation,
    }
    facts_sha256 = _hash(facts)
    title = vacancy.title.strip()
    requirements = "\n".join(
        (title, *vacancy.required_qualifications, *vacancy.work_authorisation)
    )
    for pattern in policy.clearance_requirement_patterns:
        if re.search(pattern, requirements, re.IGNORECASE):
            return FirstJobScopeDecision(
                vacancy.key, "exclude", "explicit_clearance_barrier", pattern,
                facts_sha256, policy.policy_hash,
            )
    for pattern in policy.citizenship_residence_requirement_patterns:
        if re.search(pattern, requirements, re.IGNORECASE):
            return FirstJobScopeDecision(
                vacancy.key, "exclude", "explicit_citizenship_or_residence_barrier",
                pattern, facts_sha256, policy.policy_hash,
            )
    for pattern in policy.senior_title_patterns:
        if re.search(pattern, title, re.IGNORECASE):
            return FirstJobScopeDecision(
                vacancy.key, "exclude", "explicit_senior_title", pattern,
                facts_sha256, policy.policy_hash,
            )
    for pattern in policy.entry_title_patterns:
        if re.search(pattern, title, re.IGNORECASE):
            return FirstJobScopeDecision(
                vacancy.key, "include", "explicit_entry_title", pattern,
                facts_sha256, policy.policy_hash,
            )
    for pattern in policy.adjacent_title_patterns:
        if re.search(pattern, title, re.IGNORECASE):
            return FirstJobScopeDecision(
                vacancy.key, "include", "configured_adjacent_role", pattern,
                facts_sha256, policy.policy_hash,
            )
    return FirstJobScopeDecision(
        vacancy.key, "park", "first_job_scope_unknown", None,
        facts_sha256, policy.policy_hash,
    )


def _hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
