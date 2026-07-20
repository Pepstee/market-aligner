"""
skeleton/scoring.py — the deterministic scoring maths (Build-Spec §5).

This is the ONLY place scraper data (a C3 JobRow's LLM-rated axes) meets
profiler data (Artiom's evidence-led CandidateFitProfile). It joins them
with pure, reproducible arithmetic — no LLM calls, no I/O, no globals — so a
weight change re-scores instantly and identically run-to-run.

The maths, verbatim from Build-Spec §5:

    normalise each sub-score to 0–1;  accessibility = 1 - barrier/10
    M_p(scores, weights) = ( Σ wᵢ · sᵢ^p )^(1/p),   Σwᵢ = 1
        p = 0  → geometric mean = exp( Σ wᵢ · ln(max(sᵢ, ε)) )
    ε floor (config: scoring.epsilon) so one weak factor hurts but can't zero a row.

    Fit         = M_p(interest, skill, readiness, technical alignment, evidence match)
    Opportunity = M_p(market demand, accessibility, growth potential)
    Final       = 100 · ( blend·Fit + (1-blend)·Opportunity )

    interest & skill_alignment are Hyun's 0–10 priors for the row's
    mapped_career (constant within a field); the rest come from the posting.

Field-level aggregation (the actual "which field" decision):

    field_score(career) = median(top-10 Fit of career's jobs)
                          · log(1 + count_entry_level_postings(career))

Plus a ±20% sensitivity helper that reports whether the top field is robust.

All knobs (mean_p, epsilon, weights, blend) are READ from config — nothing is
hardcoded (AGENT_PROTOCOL: config.yaml is a stub; read values, don't bake them).

Stdlib only.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

# Import the frozen contracts. Works from repo root (skeleton on path) or when
# skeleton/ is itself on sys.path.
try:  # pragma: no cover - import shim
    from skeleton.contracts import (
        JobRow, ScoredRow, CandidateFitProfile, CandidateTrackProfile, TARGET_TRACKS,
    )
except ImportError:  # pragma: no cover - import shim
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from contracts import (  # type: ignore
        JobRow, ScoredRow, CandidateFitProfile, CandidateTrackProfile, TARGET_TRACKS,
    )


# --------------------------------------------------------------------------- #
# Scoring parameters — a small frozen bundle read out of config.yaml.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ScoringParams:
    """The scoring knobs, normalised and validated once from config."""

    mean_p: float
    epsilon: float
    fit_weights: dict[str, float]
    opportunity_weights: dict[str, float]
    blend: float

    @classmethod
    def from_config(cls, cfg: Mapping[str, Any]) -> "ScoringParams":
        s = dict((cfg or {}).get("scoring", {}) or {})
        mean_p = float(s.get("mean_p", 0.0))
        epsilon = float(s.get("epsilon", 0.05))
        blend = float(s.get("fit_opportunity_blend", 0.6))
        fit_w = _normalise_weights(s.get("fit_weights") or {})
        opp_w = _normalise_weights(s.get("opportunity_weights") or {})
        if not fit_w:
            fit_w = _normalise_weights(
                {"interest": 1, "skill_alignment": 1, "market_readiness": 1,
                 "technical_alignment": 1, "evidence_match": 1}
            )
        if not opp_w:
            opp_w = _normalise_weights(
                {"market_demand": 1, "accessibility": 1, "growth_potential": 1}
            )
        if not (0.0 <= epsilon < 1.0):
            raise ValueError(f"epsilon must be in [0,1); got {epsilon}")
        if not (0.0 <= blend <= 1.0):
            raise ValueError(f"fit_opportunity_blend must be in [0,1]; got {blend}")
        return cls(
            mean_p=mean_p,
            epsilon=epsilon,
            fit_weights=fit_w,
            opportunity_weights=opp_w,
            blend=blend,
        )


def _normalise_weights(weights: Mapping[str, Any]) -> dict[str, float]:
    """Coerce to floats and renormalise to sum 1. Empty in → empty out."""
    w = {k: float(v) for k, v in (weights or {}).items() if float(v) != 0.0}
    total = sum(w.values())
    if total <= 0:
        return {}
    return {k: v / total for k, v in w.items()}


def load_params(config_path: str | Path = "skeleton/config.yaml") -> ScoringParams:
    """Read scoring knobs from config.yaml. Requires PyYAML."""
    import yaml

    cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    return ScoringParams.from_config(cfg)


# --------------------------------------------------------------------------- #
# The power mean — the heart of §5.
# --------------------------------------------------------------------------- #
def power_mean(
    values: Sequence[float],
    weights: Sequence[float],
    p: float,
    epsilon: float,
) -> float:
    """Weighted power (generalised) mean of `values` in [0,1].

        p != 0:  ( Σ wᵢ · sᵢ^p )^(1/p)
        p == 0:  exp( Σ wᵢ · ln sᵢ )      (geometric mean, the limit p→0)

    Each value is floored at `epsilon` before it enters the mean, so a single
    weak (or zero) factor drags the result down hard but cannot collapse the
    whole thing to zero. Weights are renormalised defensively to sum to 1.
    """
    if len(values) != len(weights):
        raise ValueError("values and weights must be the same length")
    if not values:
        raise ValueError("power_mean needs at least one value")

    wsum = sum(weights)
    if wsum <= 0:
        raise ValueError("weights must sum to a positive number")
    w = [wi / wsum for wi in weights]
    s = [_floor(v, epsilon) for v in values]

    if abs(p) < 1e-9:
        # Geometric mean via logs — numerically stable, exact p→0 limit.
        return math.exp(sum(wi * math.log(si) for wi, si in zip(w, s)))

    acc = sum(wi * (si ** p) for wi, si in zip(w, s))
    # acc is a positive weighted mean of positive numbers → safe to root.
    return acc ** (1.0 / p)


def _floor(v: float, epsilon: float) -> float:
    """Clamp a raw 0–1 value into [epsilon, 1]."""
    try:
        x = float(v)
    except (TypeError, ValueError):
        x = 0.0
    if math.isnan(x):
        x = 0.0
    if x < epsilon:
        return epsilon
    if x > 1.0:
        return 1.0
    return x


# --------------------------------------------------------------------------- #
# Sub-score extraction — normalise a JobRow's axes + Hyun's priors to 0–1.
# --------------------------------------------------------------------------- #
def _n10(value: Optional[float]) -> float:
    """Normalise a 0–10 axis rating to 0–1. Missing → 0 (then ε-floored)."""
    if value is None:
        return 0.0
    return max(0.0, min(1.0, float(value) / 10.0))


def accessibility(barrier_to_entry: Optional[float]) -> float:
    """accessibility = 1 - barrier/10  (invert the barrier axis, §5)."""
    if barrier_to_entry is None:
        # No barrier signal → neutral-ish accessibility (mid). ε-floor applies later.
        return 0.5
    return max(0.0, min(1.0, 1.0 - float(barrier_to_entry) / 10.0))


def _profile_for(profile: CandidateFitProfile, career: str) -> CandidateTrackProfile:
    """Artiom's evidence-led priors for the row's mapped track.

    Unknown / `other` career → zeros (row can't claim personal fit it lacks a
    prior for). ε-floor keeps it from zero-collapsing Fit entirely.
    """
    fp = (profile.fields or {}).get(career)
    if fp is None:
        return CandidateTrackProfile(
            interest=0.0, skill=0.0, confidence=0.0, market_readiness=0.0
        )
    return fp


def fit_subscores(row: JobRow, profile: CandidateFitProfile) -> dict[str, float]:
    """Personal priors plus posting-specific evidence, normalised to 0–1."""
    fp = _profile_for(profile, row.mapped_career)
    return {
        "interest": _n10(fp.interest),
        "skill_alignment": _n10(fp.skill),
        "market_readiness": _n10(fp.market_readiness),
        "technical_alignment": _n10(row.technical_alignment),
        "evidence_match": _n10(row.evidence_match),
    }


def opportunity_subscores(row: JobRow) -> dict[str, float]:
    """The three Opportunity axes, each normalised to 0–1."""
    return {
        "market_demand": _n10(row.market_demand),
        "accessibility": accessibility(row.barrier_to_entry),
        "growth_potential": _n10(row.growth_potential),
    }


def _aligned(subscores: Mapping[str, float], weights: Mapping[str, float]) -> tuple[list[float], list[float]]:
    """Pair sub-scores with their weights in a stable, matching order.

    Only axes present in both the sub-scores and the weight table participate;
    weights are renormalised over the participating axes so the mean stays a
    proper weighted mean even if config omits an axis.
    """
    keys = [k for k in weights if k in subscores]
    if not keys:
        raise ValueError("no overlapping axes between sub-scores and weights")
    vals = [subscores[k] for k in keys]
    ws = [weights[k] for k in keys]
    return vals, ws


# --------------------------------------------------------------------------- #
# The two axes + the final score — Build-Spec §5.
# --------------------------------------------------------------------------- #
def fit_score(row: JobRow, profile: CandidateFitProfile, params: ScoringParams) -> float:
    subs = fit_subscores(row, profile)
    vals, ws = _aligned(subs, params.fit_weights)
    return power_mean(vals, ws, params.mean_p, params.epsilon)


def opportunity_score(row: JobRow, params: ScoringParams) -> float:
    subs = opportunity_subscores(row)
    vals, ws = _aligned(subs, params.opportunity_weights)
    return power_mean(vals, ws, params.mean_p, params.epsilon)


def score_row(row: JobRow, profile: CandidateFitProfile, params: ScoringParams) -> ScoredRow:
    """Join a C3 JobRow with Hyun's priors → a C4 ScoredRow.

    Final = 100 · ( blend·Fit + (1-blend)·Opportunity ).
    Fit and Opportunity are kept on the 0–1 scale in the ScoredRow so the
    scatter plot reads naturally; only `final` is scaled to 0–100.
    """
    fit = fit_score(row, profile, params)
    opp = opportunity_score(row, params)
    final = 100.0 * (params.blend * fit + (1.0 - params.blend) * opp)
    return ScoredRow(row=row, fit=fit, opportunity=opp, final=final)


def score_rows(
    rows: Iterable[JobRow],
    profile: CandidateFitProfile,
    params: ScoringParams,
) -> list[ScoredRow]:
    """Score many rows, sorted by Final descending (ready for the reporter)."""
    scored = [score_row(r, profile, params) for r in rows]
    scored.sort(key=lambda sr: sr.final, reverse=True)
    return scored


# --------------------------------------------------------------------------- #
# Field-level aggregation — the actual "which field" decision, §5.
# --------------------------------------------------------------------------- #
@dataclass
class FieldScore:
    career: str
    field_score: float
    n_jobs: int
    n_entry_level: int
    median_top_fit: float


def _entry_count(scored: Sequence[ScoredRow]) -> int:
    return sum(1 for sr in scored if sr.row.entry_level is True)


def field_score(scored_for_career: Sequence[ScoredRow]) -> float:
    """field_score(career) = median(top-10 Fit) · log(1 + entry_count).

    `top-10 Fit` = the 10 highest Fit values among that career's postings
    (fewer than 10 → use them all). The log term rewards fields with real
    entry-level volume without letting a flood of postings dominate.
    """
    if not scored_for_career:
        return 0.0
    top_fits = sorted((sr.fit for sr in scored_for_career), reverse=True)[:10]
    median_top = statistics.median(top_fits)
    entry_n = _entry_count(scored_for_career)
    return median_top * math.log(1.0 + entry_n)


def aggregate_fields(scored: Sequence[ScoredRow]) -> list[FieldScore]:
    """Group scored rows by mapped_career and compute each field's score.

    Returns one FieldScore per career that has at least one posting, sorted by
    field_score descending. `other` / unmapped careers are included so the
    reporter can show where volume landed, but they read as their own bucket.
    """
    by_career: dict[str, list[ScoredRow]] = {}
    for sr in scored:
        by_career.setdefault(sr.row.mapped_career or "other", []).append(sr)

    out: list[FieldScore] = []
    for career, group in by_career.items():
        top_fits = sorted((sr.fit for sr in group), reverse=True)[:10]
        out.append(
            FieldScore(
                career=career,
                field_score=field_score(group),
                n_jobs=len(group),
                n_entry_level=_entry_count(group),
                median_top_fit=statistics.median(top_fits) if top_fits else 0.0,
            )
        )
    out.sort(key=lambda fs: fs.field_score, reverse=True)
    return out


# --------------------------------------------------------------------------- #
# Sensitivity — is the top field robust to ±delta weight perturbations? (§5)
# --------------------------------------------------------------------------- #
@dataclass
class SensitivityReport:
    baseline_top: Optional[str]
    stable: bool
    n_variants: int
    n_agreeing: int
    disagreeing_tops: dict[str, int]  # career -> how many perturbations crowned it

    def summary(self) -> str:
        if self.baseline_top is None:
            return "sensitivity: no fields to rank"
        pct = 100.0 * self.n_agreeing / self.n_variants if self.n_variants else 0.0
        verdict = "STABLE" if self.stable else "NOT robust"
        extra = ""
        if self.disagreeing_tops:
            others = ", ".join(f"{k}×{v}" for k, v in sorted(self.disagreeing_tops.items()))
            extra = f"; challengers: {others}"
        return (
            f"sensitivity: top field '{self.baseline_top}' — {verdict} "
            f"({self.n_agreeing}/{self.n_variants} perturbations agree, {pct:.0f}%){extra}"
        )


def _perturb_weights(weights: Mapping[str, float], delta: float) -> list[dict[str, float]]:
    """Every ±delta single-axis perturbation of a weight table (then renormalised)."""
    variants: list[dict[str, float]] = []
    for axis in weights:
        for sign in (+1.0, -1.0):
            bumped = dict(weights)
            bumped[axis] = max(0.0, bumped[axis] * (1.0 + sign * delta))
            norm = _normalise_weights(bumped)
            if norm:
                variants.append(norm)
    return variants


def sensitivity(
    rows: Sequence[JobRow],
    profile: CandidateFitProfile,
    params: ScoringParams,
    delta: float = 0.2,
) -> SensitivityReport:
    """Does the winning FIELD survive ±delta (default ±20%) weight changes?

    Re-scores all rows under every single-axis ±delta perturbation of both the
    Fit and Opportunity weight tables, re-aggregates fields each time, and
    checks whether the top field stays the same. Reports the agreement rate and
    which fields challenge the winner — divergence is the signal to distrust the
    ranking (Meta_Plan: "if not, the winner isn't robust").
    """
    baseline = aggregate_fields(score_rows(rows, profile, params))
    baseline_top = baseline[0].career if baseline else None

    variants: list[ScoringParams] = []
    for fw in [params.fit_weights, *_perturb_weights(params.fit_weights, delta)]:
        for ow in [params.opportunity_weights, *_perturb_weights(params.opportunity_weights, delta)]:
            if fw is params.fit_weights and ow is params.opportunity_weights:
                continue  # skip the unperturbed baseline itself
            variants.append(
                ScoringParams(
                    mean_p=params.mean_p,
                    epsilon=params.epsilon,
                    fit_weights=fw,
                    opportunity_weights=ow,
                    blend=params.blend,
                )
            )

    agreeing = 0
    challengers: dict[str, int] = {}
    for vp in variants:
        agg = aggregate_fields(score_rows(rows, profile, vp))
        top = agg[0].career if agg else None
        if top == baseline_top:
            agreeing += 1
        elif top is not None:
            challengers[top] = challengers.get(top, 0) + 1

    n = len(variants)
    # "Stable" = the top field survives the large majority of perturbations.
    stable = bool(baseline_top) and n > 0 and (agreeing / n) >= 0.9
    return SensitivityReport(
        baseline_top=baseline_top,
        stable=stable,
        n_variants=n,
        n_agreeing=agreeing,
        disagreeing_tops=challengers,
    )


# --------------------------------------------------------------------------- #
# Self-test: run `python skeleton/scoring.py`
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    prof = CandidateFitProfile(
        fields={
            "AI_Automation_Engineer": CandidateTrackProfile(
                interest=9.5, skill=8.0, confidence=0.85, market_readiness=7.5
            ),
        }
    )
    params = ScoringParams.from_config(
        {
            "scoring": {
                "mean_p": 0.0,
                "epsilon": 0.05,
                "fit_weights": {
                    "interest": 0.20,
                    "skill_alignment": 0.20,
                    "market_readiness": 0.20,
                    "technical_alignment": 0.20,
                    "evidence_match": 0.20,
                },
                "opportunity_weights": {
                    "market_demand": 0.35,
                    "accessibility": 0.35,
                    "growth_potential": 0.30,
                },
                "fit_opportunity_blend": 0.6,
            }
        }
    )
    r = JobRow(
        board="greenhouse", job_id="1", url="https://x/1",
        mapped_career="AI_Automation_Engineer", entry_level=True,
        technical_alignment=8.0, evidence_match=8.0, growth_potential=8.0,
        market_demand=8.0, barrier_to_entry=3.0,
    )
    sr = score_row(r, prof, params)
    assert 0.0 <= sr.fit <= 1.0 and 0.0 <= sr.opportunity <= 1.0
    assert 0.0 <= sr.final <= 100.0
    print(f"scoring.py OK — fit={sr.fit:.3f} opp={sr.opportunity:.3f} final={sr.final:.1f}")
