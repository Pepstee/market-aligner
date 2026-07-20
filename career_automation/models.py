"""Stable contracts for the autonomous career pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ActorKind(str, Enum):
    """Which kind of component produced an event or assessment."""

    DETERMINISTIC = "deterministic"
    PROBABILISTIC = "probabilistic"
    EXTERNAL = "external"


class PipelineState(str, Enum):
    """Materialised states implemented by the first control-plane slice."""

    SCORED = "scored"
    OPPORTUNITY_REJECTED = "opportunity_rejected"
    EMPLOYER_RESEARCH_QUEUED = "employer_research_queued"
    EMPLOYER_RESEARCHING = "employer_researching"
    EMPLOYER_RESEARCHED = "employer_researched"


class OpportunityDecision(str, Enum):
    PASS = "pass"
    REJECT = "reject"


@dataclass(frozen=True)
class ScoredJob:
    key: str
    board: str
    job_id: str
    url: str
    title: str
    company: str
    fit: float | None
    opportunity: float
    final_score: float | None
    extraction_confidence: float | None
    payload: dict[str, Any]
    payload_hash: str


@dataclass(frozen=True)
class GateResult:
    job_key: str
    decision: OpportunityDecision
    reason: str
    opportunity: float
    research_priority: int | None


@dataclass(frozen=True)
class GateSummary:
    imported: int
    passed: int
    rejected: int
    queued: int


@dataclass(frozen=True)
class ResearchTask:
    job_key: str
    title: str
    company: str
    url: str
    opportunity: float
    priority: int
    research_depth: str
    attempts: int
