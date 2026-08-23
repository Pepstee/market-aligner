"""In-process service API shared by CLI and future local transports."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from market_aligner.assessment.opportunity import OpportunityDecision, apply_gate
from market_aligner.assessment.scoring import AssessmentAxes, ScoreResult, ScoringParams, score
from market_aligner.profiler.store import ProfileStore
from market_aligner.research.store import AssessmentStore


@dataclass(frozen=True)
class AssessmentRequest:
    profile_id: str
    job_key: str
    track: str
    url: str
    title: str
    company: str
    extraction_confidence: float
    axes: AssessmentAxes


class MarketAlignerService:
    def __init__(self, data_home: str | Path | None = None) -> None:
        self.profiles = ProfileStore(data_home)
        self.assessments = AssessmentStore(self.profiles.paths.state / "assessments.sqlite3")

    def assess(
        self,
        request: AssessmentRequest,
        params: ScoringParams | None = None,
    ) -> ScoreResult:
        profile, _evidence = self.profiles.load(request.profile_id)
        result = score(profile, request.job_key, request.track, request.axes, params)
        self.assessments.upsert_score(
            result,
            url=request.url,
            title=request.title,
            company=request.company,
            extraction_confidence=request.extraction_confidence,
        )
        return result

    def gate(self, profile_id: str, job_key: str) -> OpportunityDecision:
        return apply_gate(self.assessments, profile_id, job_key)
