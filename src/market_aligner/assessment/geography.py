"""Deterministic geographic preference classification from normalized vacancy facts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from typing import Mapping, Sequence


PREFERENCE_CATEGORIES = (
    "uk_remote",
    "uk_hybrid",
    "uk_onsite",
    "romania_remote",
    "eu_remote",
)


@dataclass(frozen=True)
class GeographicPreferencePolicy:
    order: tuple[str, ...] = PREFERENCE_CATEGORIES
    uk_markers: tuple[str, ...] = (
        "united kingdom", "great britain", "uk", "england", "scotland", "wales",
        "northern ireland", "london", "manchester", "birmingham", "wolverhampton",
        "bristol", "leeds", "liverpool", "glasgow", "edinburgh", "cardiff",
        "belfast", "oxford", "cambridge",
    )
    romania_markers: tuple[str, ...] = ("romania", "bucharest", "cluj", "iasi", "timisoara")
    eu_markers: tuple[str, ...] = (
        "european union", "europe", "eu", "eea", "emea",
    )
    remote_markers: tuple[str, ...] = ("remote", "distributed", "work from home")
    hybrid_markers: tuple[str, ...] = ("hybrid",)
    onsite_markers: tuple[str, ...] = ("on site", "onsite", "office based")

    def __post_init__(self) -> None:
        if len(self.order) != len(set(self.order)) or set(self.order) != set(PREFERENCE_CATEGORIES):
            raise ValueError("geographic preference order must contain every supported category once")
        for name in (
            "uk_markers", "romania_markers", "eu_markers", "remote_markers",
            "hybrid_markers", "onsite_markers",
        ):
            values = getattr(self, name)
            if not values or any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f"{name} must contain non-empty strings")

    @property
    def policy_hash(self) -> str:
        return _hash(asdict(self))

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, object] | None,
        *,
        default: "GeographicPreferencePolicy | None" = None,
    ) -> "GeographicPreferencePolicy":
        policy = default or cls()
        if value is None:
            return policy
        allowed = set(asdict(policy))
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown geographic preference settings: {sorted(unknown)}")
        updates: dict[str, tuple[str, ...]] = {}
        for key, raw in value.items():
            if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
                raise ValueError(f"geographic preference {key} must be a list")
            updates[key] = tuple(str(item).strip() for item in raw)
        return replace(policy, **updates)


@dataclass(frozen=True)
class GeographicPreference:
    category: str
    rank: int
    facts_sha256: str
    policy_sha256: str


def classify_geographic_preference(
    *,
    location: str,
    remote_policy: str | None,
    policy: GeographicPreferencePolicy,
) -> GeographicPreference:
    facts = {"location": location, "remote_policy": remote_policy}
    text = _normalise(" ".join(part for part in (location, remote_policy or "") if part))
    region = "other"
    if _matches(text, policy.uk_markers):
        region = "uk"
    elif _matches(text, policy.romania_markers):
        region = "romania"
    elif _matches(text, policy.eu_markers):
        region = "eu"

    mode = "unknown"
    if _matches(text, policy.hybrid_markers):
        mode = "hybrid"
    elif _matches(text, policy.onsite_markers):
        mode = "onsite"
    elif _matches(text, policy.remote_markers):
        mode = "remote"

    candidate = f"{region}_{mode}"
    category = candidate if candidate in policy.order else "unknown_other"
    rank = policy.order.index(category) if category in policy.order else len(policy.order)
    return GeographicPreference(category, rank, _hash(facts), policy.policy_hash)


def _normalise(value: str) -> str:
    return " " + re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip() + " "


def _matches(text: str, markers: Sequence[str]) -> bool:
    return any(_normalise(marker) in text for marker in markers)


def _hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
