"""In-process service API shared by CLI and future local transports."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from market_aligner.assessment.opportunity import OpportunityDecision, apply_gate
from market_aligner.assessment.scoring import (
    AssessmentAxes,
    ScoreResult,
    ScoringParams,
    score,
)
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

    @staticmethod
    def process_one(
        data_home: Path,
        envelope_name: str,
        *,
        supplied_operation_id: str,
        supplied_config_path: str,
        supplied_profile_id: str,
        supplied_job_key: str,
        supplied_track: str,
    ) -> bytes:
        """Run FIT-001 without constructing the mutating legacy service.

        The processing owner performs its own lazy retained admission over
        the already-existing stores.  Keeping this as a static service seam
        prevents ``MarketAlignerService.__init__`` from creating directories,
        schema, or WAL state during the side-effect-free preflight.
        """

        from market_aligner.processing import process_one

        return process_one(
            data_home,
            envelope_name,
            supplied_operation_id=supplied_operation_id,
            supplied_config_path=supplied_config_path,
            supplied_profile_id=supplied_profile_id,
            supplied_job_key=supplied_job_key,
            supplied_track=supplied_track,
        )
