"""Pure deterministic scoring selectively adapted from the audited engine."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Mapping, Sequence

from market_aligner.applications.canonical import (
    ContractValidationError, deep_freeze_json, require_sha256,
)
from market_aligner.profiler.schema import CandidateProfile, TrackProfile


class FitStatus(str, Enum):
    UNCALIBRATED = "uncalibrated"


@dataclass(frozen=True)
class ScoringParams:
    mean_p: float = 0.0
    epsilon: float = 0.05
    blend: float = 0.6
    fit_weights: tuple[tuple[str, float], ...] = (
        ("interest", 0.2),
        ("demonstrated_skill", 0.2),
        ("market_readiness", 0.2),
        ("technical_alignment", 0.2),
        ("evidence_match", 0.2),
    )
    opportunity_weights: tuple[tuple[str, float], ...] = (
        ("market_demand", 0.35),
        ("accessibility", 0.35),
        ("growth_potential", 0.3),
    )

    def __post_init__(self) -> None:
        if (
            isinstance(self.mean_p, bool)
            or not isinstance(self.mean_p, (int, float))
            or not math.isfinite(self.mean_p)
        ):
            raise ValueError("mean_p must be a finite number")
        if (
            isinstance(self.epsilon, bool)
            or not isinstance(self.epsilon, (int, float))
            or not math.isfinite(self.epsilon)
            or not 0 <= self.epsilon < 1
        ):
            raise ValueError("epsilon must be a number in [0,1)")
        if self.epsilon == 0.0 and self.mean_p < 1e-9:
            raise ValueError(
                "epsilon must be positive when mean_p uses a geometric or negative-power mean"
            )
        if (
            isinstance(self.blend, bool)
            or not isinstance(self.blend, (int, float))
            or not math.isfinite(self.blend)
            or not 0 <= self.blend <= 1
        ):
            raise ValueError("blend must be a number in [0,1]")
        for group_name, weights in (
            ("fit_weights", self.fit_weights),
            ("opportunity_weights", self.opportunity_weights),
        ):
            if not isinstance(weights, tuple) or any(
                not isinstance(entry, tuple) or len(entry) != 2 for entry in weights
            ):
                raise ValueError(f"{group_name} must be a tuple of name/number pairs")
            for code, value in weights:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(value)
                    or value < 0
                    or not isinstance(code, str)
                    or not code
                ):
                    raise ValueError(f"{group_name} entries require non-negative finite weights")
            if len(weights) != len({code for code, _ in weights}):
                raise ValueError(f"{group_name} cannot repeat component names")
        if {code for code, _ in self.fit_weights} != {
            "interest",
            "demonstrated_skill",
            "market_readiness",
            "technical_alignment",
            "evidence_match",
        }:
            raise ValueError("fit_weights must contain every v1 fit component exactly once")
        if {code for code, _ in self.opportunity_weights} != {
            "market_demand",
            "accessibility",
            "growth_potential",
        }:
            raise ValueError(
                "opportunity_weights must contain every v1 opportunity component exactly once"
            )
        _normalise_weights(dict(self.fit_weights))
        _normalise_weights(dict(self.opportunity_weights))

    @property
    def parameters_hash(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AssessmentAxes:
    technical_alignment: float
    evidence_match: float
    market_demand: float
    barrier_to_entry: float
    growth_potential: float

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or not 0 <= value <= 10):
                raise ValueError(f"{name} must be in [0,10]")


@dataclass(frozen=True)
class ScoreResult:
    profile_id: str
    job_key: str
    track: str
    fit: float
    opportunity: float
    final: float
    fit_status: FitStatus
    parameters_hash: str
    fit_subscores: Mapping[str, float]
    opportunity_subscores: Mapping[str, float]

    def __post_init__(self) -> None:
        for name in ("profile_id", "job_key", "track"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ContractValidationError(f"score {name} must be a non-empty string")
        for name, low, high in (
            ("fit", 0.0, 1.0),
            ("opportunity", 0.0, 1.0),
            ("final", 0.0, 100.0),
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not low <= value <= high
                or not math.isfinite(value)
            ):
                raise ContractValidationError(f"score {name} must be finite and in [{low},{high}]")
        if not isinstance(self.fit_status, FitStatus):
            raise ContractValidationError("score fit_status must be a FitStatus")
        require_sha256(self.parameters_hash, "score parameters_hash")
        for name in ("fit_subscores", "opportunity_subscores"):
            mapping = getattr(self, name)
            if not isinstance(mapping, Mapping) or not mapping:
                raise ContractValidationError(f"score {name} must be a non-empty mapping")
            copied: dict[str, float] = {}
            for key, value in mapping.items():
                if not isinstance(key, str) or not key.strip():
                    raise ContractValidationError(f"score {name} keys must be non-empty strings")
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not 0.0 <= value <= 1.0
                    or not math.isfinite(value)
                ):
                    raise ContractValidationError(
                        f"score {name}.{key} must be finite and in [0,1]"
                    )
                copied[key] = value
            object.__setattr__(self, name, deep_freeze_json(dict(sorted(copied.items()))))


def _normalise_weights(weights: Mapping[str, float]) -> dict[str, float]:
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) or value < 0 for value in weights.values()):
        raise ValueError("weights must be finite non-negative numbers")
    selected = {name: float(value) for name, value in weights.items() if value != 0}
    total = sum(selected.values())
    if not math.isfinite(total) or total <= 0:
        raise ValueError("weights must sum to a positive number")
    return {name: value / total for name, value in selected.items()}


def _floor(value: float, epsilon: float) -> float:
    number = float(value)
    if math.isnan(number):
        number = 0.0
    return min(1.0, max(epsilon, number))


def power_mean(values: Sequence[float], weights: Sequence[float], p: float, epsilon: float) -> float:
    if len(values) != len(weights) or not values:
        raise ValueError("values and weights must be non-empty and have equal length")
    if (isinstance(p, bool) or not isinstance(p, (int, float)) or not math.isfinite(p)
            or isinstance(epsilon, bool) or not isinstance(epsilon, (int, float))
            or not math.isfinite(epsilon) or not 0 <= epsilon < 1):
        raise ValueError("power mean p and epsilon must be finite numbers in range")
    if epsilon == 0 and p < 1e-9:
        raise ValueError("epsilon must be positive for geometric or negative-power means")
    normalised = _normalise_weights({str(index): value for index, value in enumerate(weights)})
    selected_weights = list(normalised.values())
    selected_values = [_floor(values[int(index)], epsilon) for index in normalised]
    if abs(p) < 1e-9:
        return math.exp(
            sum(weight * math.log(value) for weight, value in zip(selected_weights, selected_values))
        )
    return sum(
        weight * value**p for weight, value in zip(selected_weights, selected_values)
    ) ** (1.0 / p)


def _unit(value: float) -> float:
    return min(1.0, max(0.0, float(value) / 10.0))


def _track(profile: CandidateProfile, name: str) -> TrackProfile:
    return profile.tracks.get(name) or TrackProfile(
        interest=0,
        demonstrated_skill=0,
        confidence=0,
        market_readiness=0,
        rationale="No track evidence is available.",
    )


def _weighted_mean(subscores: Mapping[str, float], weights: Mapping[str, float], params: ScoringParams) -> float:
    normalised = _normalise_weights({key: value for key, value in weights.items() if key in subscores})
    keys = list(normalised)
    return power_mean(
        [subscores[key] for key in keys],
        [normalised[key] for key in keys],
        params.mean_p,
        params.epsilon,
    )


def score(
    profile: CandidateProfile,
    job_key: str,
    track_name: str,
    axes: AssessmentAxes,
    params: ScoringParams | None = None,
) -> ScoreResult:
    params = params or ScoringParams()
    track = _track(profile, track_name)
    fit_subscores = {
        "interest": _unit(track.interest),
        "demonstrated_skill": _unit(track.demonstrated_skill),
        "market_readiness": _unit(track.market_readiness),
        "technical_alignment": _unit(axes.technical_alignment),
        "evidence_match": _unit(axes.evidence_match),
    }
    opportunity_subscores = {
        "market_demand": _unit(axes.market_demand),
        "accessibility": 1.0 - _unit(axes.barrier_to_entry),
        "growth_potential": _unit(axes.growth_potential),
    }
    fit = _weighted_mean(fit_subscores, dict(params.fit_weights), params)
    opportunity = _weighted_mean(
        opportunity_subscores,
        dict(params.opportunity_weights),
        params,
    )
    final = 100 * (params.blend * fit + (1 - params.blend) * opportunity)
    return ScoreResult(
        profile_id=profile.profile_id,
        job_key=job_key,
        track=track_name,
        fit=fit,
        opportunity=opportunity,
        final=final,
        fit_status=FitStatus.UNCALIBRATED,
        parameters_hash=params.parameters_hash,
        fit_subscores=fit_subscores,
        opportunity_subscores=opportunity_subscores,
    )


def aggregate_track(scores: Sequence[ScoreResult], entry_level_keys: frozenset[str]) -> float:
    if not scores:
        return 0.0
    top_fits = sorted((item.fit for item in scores), reverse=True)[:10]
    entry_count = sum(item.job_key in entry_level_keys for item in scores)
    return statistics.median(top_fits) * math.log(1 + entry_count)
