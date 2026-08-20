"""Resumable deterministic processing from fetched evidence to ranked reports."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from market_aligner.assessment.opportunity import (
    OpportunityAxisPolicy,
    derive_opportunity_axes,
)
from market_aligner.assessment.scoring import AssessmentAxes, FitStatus, ScoreResult, score
from market_aligner.assessment.viability import assess_viability
from market_aligner.config import ProductPaths
from market_aligner.config_loader import load_config
from market_aligner.domain.contracts import Vacancy
from market_aligner.llm.contracts import EvidenceAlignment, LLMGateway, LLMReceipt, canonical_hash
from market_aligner.llm.pipeline import accept_alignment, accept_extraction
from market_aligner.normalisation.records import vacancy_shell_from_raw
from market_aligner.profiler.store import ProfileStore
from market_aligner.reporting.reports import RankedVacancy, write_reports
from market_aligner.research.store import AssessmentStore
from market_aligner.state.vacancies import JobDatabase


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _receipt(receipt: LLMReceipt, *, task: str, inputs: Mapping[str, Any]) -> None:
    if receipt.task != task:
        raise ValueError(f"semantic worker returned wrong task for {task}")
    if not all(
        isinstance(value, str) and value.strip()
        for value in (
            receipt.receipt_id,
            receipt.model,
            receipt.prompt_version,
            receipt.created_at,
        )
    ):
        raise ValueError("semantic worker receipt is partially bound")
    if receipt.input_sha256 != canonical_hash(dict(inputs)):
        raise ValueError("semantic worker input hash differs from exact context")
    if len(receipt.output_sha256) != 64:
        raise ValueError("semantic worker output hash is invalid")


def _processing_config(config: dict[str, Any]) -> dict[str, Any]:
    value = config.get("processing") or {}
    if not isinstance(value, dict):
        raise ValueError("processing config must be an object")
    shard_size = int(value.get("shard_size", 25))
    lease_seconds = int(value.get("lease_seconds", 900))
    if not 1 <= shard_size <= 1000 or not 1 <= lease_seconds <= 86400:
        raise ValueError("processing shard or lease is outside the safe bound")
    return {
        "lease_seconds": lease_seconds,
        "shard_size": shard_size,
    }


def _ranked(result_rows: list[dict[str, object]]) -> list[RankedVacancy]:
    ranked: list[RankedVacancy] = []
    for result in result_rows:
        if not result.get("included"):
            continue
        vacancy_value = dict(result["vacancy"])  # type: ignore[arg-type]
        for key in (
            "responsibilities",
            "required_skills",
            "preferred_skills",
            "required_qualifications",
            "preferred_qualifications",
            "work_authorisation",
        ):
            vacancy_value[key] = tuple(vacancy_value.get(key) or ())
        vacancy = Vacancy(**vacancy_value)
        score_value = dict(result["score"])  # type: ignore[arg-type]
        score_value["fit_status"] = FitStatus(score_value["fit_status"])
        score = ScoreResult(**score_value)
        ranked.append(RankedVacancy(vacancy, score))
    return ranked


class ProcessingService:
    """One shard per invocation; repeated invocations resume until no work remains."""

    def __init__(
        self,
        data_home: str | Path | None,
        semantic_worker: LLMGateway,
        *,
        opportunity_policy: OpportunityAxisPolicy | None = None,
    ) -> None:
        self.paths = ProductPaths.resolve(data_home).ensure()
        self.worker = semantic_worker
        self.opportunity_policy = opportunity_policy or OpportunityAxisPolicy()
        self.profiles = ProfileStore(self.paths.root)
        self.jobs = JobDatabase(self.paths.state / "vacancies.sqlite3")
        self.assessments = AssessmentStore(self.paths.state / "assessments.sqlite3")

    def process(
        self,
        config_path: str | Path,
        *,
        profile_id: str,
        track: str,
        worker_id: str,
    ) -> dict[str, object]:
        if not worker_id.strip():
            raise ValueError("processing worker ID is required")
        config = load_config(config_path)
        processing = _processing_config(config)
        profile, evidence = self.profiles.load(profile_id)
        if track not in profile.tracks:
            raise ValueError(f"profile has no track named {track!r}")
        authority_document = {
            "evidence": [asdict(evidence[key]) for key in sorted(evidence)],
            "profile": asdict(profile),
        }
        profile_context = profile.llm_context(evidence)
        authority_sha256 = _sha256(authority_document)
        config_sha256 = _sha256(
            {"opportunity_policy": asdict(self.opportunity_policy), "processing": processing}
        )
        claimed = self.jobs.claim_fetched_for_processing(
            profile_id=profile_id,
            track=track,
            authority_sha256=authority_sha256,
            worker_id=worker_id,
            limit=processing["shard_size"],
            lease_seconds=processing["lease_seconds"],
        )
        completed = rejected = errors = 0
        for raw in claimed:
            try:
                shell = vacancy_shell_from_raw(raw)
                raw_context = {
                    "board": raw.board,
                    "content_sha256": raw.content_sha256,
                    "deterministic_shell": asdict(shell),
                    "fetched_at": raw.fetched_at,
                    "job_id": raw.job_id,
                    "raw_json": raw.raw_json,
                    "raw_text": raw.raw_text,
                    "url": raw.url,
                }
                extraction, extraction_receipt = self.worker.extract_vacancy(raw_context)
                _receipt(
                    extraction_receipt,
                    task="semantic_vacancy_extraction",
                    inputs=raw_context,
                )
                vacancy = accept_extraction(raw, extraction, extraction_receipt)
                viability = assess_viability(vacancy)
                if viability.decision != "include":
                    result: dict[str, object] = {
                        "included": False,
                        "viability": asdict(viability),
                        "vacancy": asdict(vacancy),
                    }
                    rejected += 1
                else:
                    alignment_context = {
                        "evidence_authority_sha256": authority_sha256,
                        "profile": profile_context,
                        "track": track,
                        "vacancy": asdict(vacancy),
                    }
                    alignment, alignment_receipt = self.worker.align_evidence(alignment_context)
                    _receipt(
                        alignment_receipt,
                        task="evidence_alignment",
                        inputs=alignment_context,
                    )
                    if (
                        alignment.profile_id != profile.profile_id
                        or alignment.profile_version != profile.version
                        or alignment.job_key != vacancy.key
                    ):
                        raise ValueError("evidence alignment identity differs from exact authorities")
                    accepted: EvidenceAlignment = accept_alignment(
                        alignment, evidence, alignment_receipt
                    )
                    opportunity = derive_opportunity_axes(vacancy, self.opportunity_policy)
                    axes = AssessmentAxes(
                        technical_alignment=accepted.technical_alignment * 10,
                        evidence_match=accepted.evidence_match * 10,
                        market_demand=opportunity.market_demand,
                        barrier_to_entry=opportunity.barrier_to_entry,
                        growth_potential=opportunity.growth_potential,
                    )
                    score_result = score(profile, vacancy.key, track, axes)
                    self.assessments.upsert_score(
                        score_result,
                        url=vacancy.url,
                        title=vacancy.title,
                        company=vacancy.company,
                        extraction_confidence=vacancy.extraction_confidence,
                    )
                    result = {
                        "alignment_receipt": asdict(alignment_receipt),
                        "extraction_receipt": asdict(extraction_receipt),
                        "included": True,
                        "opportunity_axes": asdict(opportunity),
                        "score": {**asdict(score_result), "fit_status": score_result.fit_status.value},
                        "vacancy": asdict(vacancy),
                        "viability": asdict(viability),
                    }
                    completed += 1
                self.jobs.complete_processing(
                    profile_id=profile_id,
                    track=track,
                    job_key=raw.key,
                    authority_sha256=authority_sha256,
                    source_content_sha256=str(raw.content_sha256),
                    worker_id=worker_id,
                    result=result,
                )
            except Exception as exc:
                errors += 1
                self.jobs.fail_processing(
                    profile_id=profile_id,
                    track=track,
                    job_key=raw.key,
                    authority_sha256=authority_sha256,
                    source_content_sha256=str(raw.content_sha256),
                    worker_id=worker_id,
                    error=repr(exc),
                )

        with self.jobs.processing_report_snapshot(
            profile_id=profile_id, track=track, authority_sha256=authority_sha256
        ) as result_rows:
            ranked = _ranked(result_rows)
            report_paths = write_reports(profile_id, ranked, self.paths.outputs / "reports")
            report_hashes = {
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in asdict(report_paths).items()
            }
            report_values = {name: str(path) for name, path in asdict(report_paths).items()}
        body: dict[str, object] = {
            "application_authority": False,
            "authority_scope": "processing_only",
            "config_sha256": config_sha256,
            "errors": errors,
            "evidence_authority_sha256": authority_sha256,
            "included": completed,
            "job_specific_opportunity_axes": True,
            "opportunity_policy_sha256": self.opportunity_policy.policy_hash,
            "profile_id": profile_id,
            "ranked_count": len(ranked),
            "rejected": rejected,
            "report_hashes": report_hashes,
            "schema_version": "market-aligner.processing-run-receipt.v1",
            "shard_claimed": len(claimed),
            "track": track,
            "worker_id": worker_id,
        }
        body["state_sha256"] = _sha256(result_rows)
        receipt_sha256 = _sha256(body)
        receipt = {**body, "receipt_sha256": receipt_sha256}
        receipt_path = self.paths.state / "processing-receipts" / f"{receipt_sha256}.json"
        _atomic_json(receipt_path, receipt)
        return {**receipt, "receipt_path": str(receipt_path), "reports": report_values}
