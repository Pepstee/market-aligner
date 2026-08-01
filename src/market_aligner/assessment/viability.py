"""Profile-independent deterministic checks over vacancy state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

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
