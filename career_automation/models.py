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
    """Version 0.1 lifecycle vocabulary (including the five legacy states)."""

    DISCOVERED = "discovered"
    FETCHED = "fetched"
    NORMALISED = "normalised"
    VIABILITY_REJECTED = "viability_rejected"
    ELIGIBLE = "eligible"
    OPPORTUNITY_0_ASSESSED = "opportunity_0_assessed"
    SCORED = "scored"
    OPPORTUNITY_REJECTED = "opportunity_rejected"
    EMPLOYER_RESEARCH_QUEUED = "employer_research_queued"
    EMPLOYER_RESEARCHING = "employer_researching"
    EMPLOYER_RESEARCHED = "employer_researched"
    OPPORTUNITY_1_ASSESSED = "opportunity_1_assessed"
    OPPORTUNITY_REJECTED_AFTER_RESEARCH = "opportunity_rejected_after_research"
    FIT_ASSESSED = "fit_assessed"
    CANDIDATE_REJECTED = "candidate_rejected"
    GAP_IDENTIFIED = "gap_identified"
    GAP_RECOVERY = "gap_recovery"
    LEARNING = "learning"
    EVIDENCE_BUILDING = "evidence_building"
    GAP_VERIFIED = "gap_verified"
    FIT_REASSESSED = "fit_reassessed"
    STRATEGY_READY = "strategy_ready"
    APPLICATION_COMPILED = "application_compiled"
    RELEASE_BLOCKED = "release_blocked"
    RELEASED = "released"
    SUBMISSION_QUEUED = "submission_queued"
    SUBMISSION_BLOCKED = "submission_blocked"
    SUBMITTED = "submitted"
    RECEIPT_CONFIRMED = "receipt_confirmed"
    SCREENING = "screening"
    INTERVIEW = "interview"
    FINAL_STAGE = "final_stage"
    OFFER = "offer"
    ACCEPTED = "accepted"
    DECLINED = "declined"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"


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
