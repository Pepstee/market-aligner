"""Score import and deterministic Opportunity-gate orchestration."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .database import CareerDatabase
from .models import GateResult, GateSummary, OpportunityDecision, ScoredJob


def _optional_unit(value: Any, name: str) -> float | None:
    if value in (None, ""):
        return None
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be in [0,1], got {result}")
    return result


def scored_job_from_payload(payload: dict[str, Any]) -> ScoredJob:
    """Validate one current `jobs_scored.jsonl` record."""
    board = str(payload.get("board") or "").strip()
    job_id = str(payload.get("job_id") or "").strip()
    if not board or not job_id:
        raise ValueError("scored job requires board and job_id")
    opportunity = _optional_unit(payload.get("opportunity"), "opportunity")
    if opportunity is None:
        raise ValueError(f"{board}:{job_id} has no Opportunity score")
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return ScoredJob(
        key=f"{board}:{job_id}",
        board=board,
        job_id=job_id,
        url=str(payload.get("url") or ""),
        title=str(payload.get("job_title") or ""),
        company=str(payload.get("company") or ""),
        fit=_optional_unit(payload.get("fit"), "fit"),
        opportunity=opportunity,
        final_score=float(payload["final"]) if payload.get("final") not in (None, "") else None,
        extraction_confidence=_optional_unit(
            payload.get("extraction_confidence"), "extraction_confidence"
        ),
        payload=payload,
        payload_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    )


def read_scored_jsonl(path: str | Path) -> Iterable[ScoredJob]:
    source = Path(path)
    with source.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise ValueError("row is not an object")
                yield scored_job_from_payload(payload)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(f"{source}:{line_number}: {exc}") from exc


@dataclass(frozen=True)
class OpportunityPolicy:
    """Deterministic admission policy over a precomputed Opportunity score.

    Fit and candidate evidence are intentionally absent. The research gate is
    deciding whether the opportunity warrants employer investigation, not yet
    whether this candidate should apply.
    """

    minimum_opportunity: float = 0.55
    minimum_extraction_confidence: float = 0.70
    high_priority_opportunity: float = 0.75

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"{name} must be in [0,1]")
        if self.high_priority_opportunity < self.minimum_opportunity:
            raise ValueError("high-priority threshold cannot be below admission threshold")

    @property
    def policy_hash(self) -> str:
        body = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


class OpportunityGate:
    def __init__(self, database: CareerDatabase, policy: OpportunityPolicy | None = None) -> None:
        self.database = database
        self.policy = policy or OpportunityPolicy()

    def import_jobs(self, jobs: Iterable[ScoredJob]) -> int:
        count = 0
        for job in jobs:
            self.database.upsert_scored_job(job)
            count += 1
        return count

    def decide(self, row: Any) -> GateResult:
        opportunity = float(row["opportunity"])
        confidence = row["extraction_confidence"]
        if confidence is None or float(confidence) < self.policy.minimum_extraction_confidence:
            return GateResult(
                job_key=str(row["job_key"]), decision=OpportunityDecision.REJECT,
                reason="insufficient_extraction_confidence", opportunity=opportunity,
                research_priority=None,
            )
        if opportunity < self.policy.minimum_opportunity:
            return GateResult(
                job_key=str(row["job_key"]), decision=OpportunityDecision.REJECT,
                reason="below_opportunity_threshold", opportunity=opportunity,
                research_priority=None,
            )
        tier = 2 if opportunity >= self.policy.high_priority_opportunity else 1
        # Opportunity alone determines research order. Fit is intentionally not
        # included because candidate assessment belongs after employer recon.
        priority = tier * 1_000_000 + round(opportunity * 100_000)
        return GateResult(
            job_key=str(row["job_key"]), decision=OpportunityDecision.PASS,
            reason="opportunity_warrants_employer_reconnaissance",
            opportunity=opportunity, research_priority=priority,
        )

    def apply(self) -> tuple[int, int]:
        passed = rejected = 0
        for row in self.database.scored_jobs():
            result = self.decide(row)
            is_pass = result.decision is OpportunityDecision.PASS
            self.database.apply_opportunity_result(
                job_key=result.job_key,
                passed=is_pass,
                reason=result.reason,
                policy_hash=self.policy.policy_hash,
                priority=result.research_priority,
            )
            passed += int(is_pass)
            rejected += int(not is_pass)
        return passed, rejected

    def bootstrap(self, jobs: Iterable[ScoredJob]) -> GateSummary:
        imported = self.import_jobs(jobs)
        passed, rejected = self.apply()
        queued = len(self.database.list_research_queue(limit=1_000_000))
        return GateSummary(imported=imported, passed=passed, rejected=rejected, queued=queued)
