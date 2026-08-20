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
from market_aligner.assessment.viability import (
    FirstJobScopePolicy,
    assess_first_job_scope,
    assess_viability,
)
from market_aligner.assessment.geography import (
    GeographicPreferencePolicy,
    classify_geographic_preference,
)
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
    max_total_value = value.get("max_total")
    max_total = None if max_total_value is None else int(max_total_value)
    if not 1 <= shard_size <= 1000 or not 1 <= lease_seconds <= 86400:
        raise ValueError("processing shard or lease is outside the safe bound")
    if max_total is not None and max_total <= 0:
        raise ValueError("processing max_total must be positive when set")
    include_boards = _board_filter(value.get("include_boards"), "include_boards")
    exclude_boards = _board_filter(value.get("exclude_boards"), "exclude_boards")
    if set(include_boards) & set(exclude_boards):
        raise ValueError("processing board include/exclude filters overlap")
    geographic = value.get("geographic_preference")
    if geographic is not None and not isinstance(geographic, dict):
        raise ValueError("processing geographic_preference must be an object")
    first_job_scope = value.get("first_job_scope")
    if first_job_scope is not None and not isinstance(first_job_scope, dict):
        raise ValueError("processing first_job_scope must be an object")
    return {
        "exclude_boards": exclude_boards,
        "first_job_scope": first_job_scope,
        "geographic_preference": geographic,
        "include_boards": include_boards,
        "lease_seconds": lease_seconds,
        "max_total": max_total,
        "shard_size": shard_size,
    }


def _board_filter(value: object, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"processing {name} must be a list of board names")
    normalized = tuple(sorted({item.strip() for item in value if item.strip()}))
    if len(normalized) != len(value):
        raise ValueError(f"processing {name} contains blanks or duplicates")
    return normalized


def _collector_database(paths: ProductPaths, config: dict[str, Any]) -> tuple[Path, str]:
    io = config.get("io") or {}
    if not isinstance(io, dict):
        raise ValueError("io config must be an object")
    relative = Path(str(io.get("database", "state/vacancies.sqlite3")))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("io.database must stay below the external data home")
    source = (paths.root / relative).resolve()
    try:
        source.relative_to(paths.root)
    except ValueError as exc:
        raise ValueError("io.database must stay below the external data home") from exc
    return source, relative.as_posix()


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
        preference = dict(result.get("geographic_preference") or {})
        ranked.append(
            RankedVacancy(
                vacancy,
                score,
                preference_classification=str(preference.get("category", "unknown_other")),
                preference_rank=int(preference.get("rank", 999)),
            )
        )
    return ranked


_VACANCY_SEQUENCE_FIELDS = (
    "responsibilities", "required_skills", "preferred_skills",
    "required_qualifications", "preferred_qualifications", "work_authorisation",
)


def _cached_vacancy(
    prior: Mapping[str, object] | None,
    *,
    job_key: str,
    source_content_sha256: str,
) -> Vacancy | None:
    """Replay only an exact-content accepted vacancy from processing state."""

    if not prior or not isinstance(prior.get("vacancy"), Mapping):
        return None
    value = dict(prior["vacancy"])  # type: ignore[arg-type]
    for key in _VACANCY_SEQUENCE_FIELDS:
        value[key] = tuple(value.get(key) or ())
    vacancy = Vacancy(**value)
    if vacancy.key != job_key or vacancy.source_content_sha256 != source_content_sha256:
        raise ValueError("cached semantic vacancy differs from exact posting evidence")
    return vacancy


def _cached_alignment_axes(prior: Mapping[str, object] | None) -> tuple[float, float] | None:
    """Recover authority-bound alignment axes from an accepted prior score."""

    if not prior or prior.get("included") is not True:
        return None
    score_value = prior.get("score")
    if not isinstance(score_value, Mapping):
        return None
    subscores = score_value.get("fit_subscores")
    if not isinstance(subscores, Mapping):
        return None
    technical = float(subscores.get("technical_alignment", -1))
    evidence_match = float(subscores.get("evidence_match", -1))
    if not 0 <= technical <= 1 or not 0 <= evidence_match <= 1:
        raise ValueError("cached evidence alignment axes are outside [0,1]")
    return technical * 10, evidence_match * 10


class ProcessingService:
    """One shard per invocation; repeated invocations resume until no work remains."""

    def __init__(
        self,
        data_home: str | Path | None,
        semantic_worker: LLMGateway,
        *,
        opportunity_policy: OpportunityAxisPolicy | None = None,
        geographic_policy: GeographicPreferencePolicy | None = None,
        first_job_policy: FirstJobScopePolicy | None = None,
    ) -> None:
        self.paths = ProductPaths.resolve(data_home).ensure()
        self.worker = semantic_worker
        self.opportunity_policy = opportunity_policy or OpportunityAxisPolicy()
        self.geographic_policy = geographic_policy or GeographicPreferencePolicy()
        self.first_job_policy = first_job_policy or FirstJobScopePolicy()
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
        job_key: str | None = None,
    ) -> dict[str, object]:
        if not worker_id.strip():
            raise ValueError("processing worker ID is required")
        if job_key is not None and (not job_key or ":" not in job_key):
            raise ValueError("exact processing job key must be board-qualified")
        config = load_config(config_path)
        processing = _processing_config(config)
        collector_database, collector_database_relative = _collector_database(self.paths, config)
        promotion_config_sha256 = _sha256(
            {
                "loaded_config": config,
                "source_database": collector_database_relative,
                "target_database": "state/vacancies.sqlite3",
            }
        )
        promotion_body = self.jobs.promote_fetched_from(
            collector_database,
            config_sha256=promotion_config_sha256,
            job_key=job_key,
        )
        promotion_receipt_sha256 = _sha256(promotion_body)
        promotion = {**promotion_body, "receipt_sha256": promotion_receipt_sha256}
        promotion_receipt_path = (
            self.paths.state / "promotion-receipts" / f"{promotion_receipt_sha256}.json"
        )
        _atomic_json(promotion_receipt_path, promotion)
        geographic_policy = GeographicPreferencePolicy.from_mapping(
            processing["geographic_preference"],
            default=self.geographic_policy,
        )
        first_job_policy = FirstJobScopePolicy.from_mapping(
            processing["first_job_scope"],
            default=self.first_job_policy,
        )
        scope = {
            "exclude_boards": processing["exclude_boards"],
            "include_boards": processing["include_boards"],
            "max_total": processing["max_total"],
        }
        if job_key is not None:
            scope["job_key"] = job_key
        scope_sha256 = _sha256(scope)
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
            {
                "geographic_preference_policy": asdict(geographic_policy),
                "first_job_scope_policy": asdict(first_job_policy),
                "loaded_config": config,
                "opportunity_policy": asdict(self.opportunity_policy),
            }
        )
        report_scope = {
            "evidence_authority_sha256": authority_sha256,
            "processing_config_sha256": config_sha256,
            "profile_id": profile_id,
            "schema_version": "market-aligner.processing-report-scope.v1",
            "scope": scope,
            "scope_sha256": scope_sha256,
            "track": track,
        }
        report_namespace_sha256 = _sha256(report_scope)
        report_namespace = f"scope_{report_namespace_sha256}"
        claimed = self.jobs.claim_fetched_for_processing(
            profile_id=profile_id,
            track=track,
            authority_sha256=authority_sha256,
            processing_config_sha256=config_sha256,
            worker_id=worker_id,
            limit=processing["shard_size"],
            lease_seconds=processing["lease_seconds"],
            include_boards=processing["include_boards"],
            exclude_boards=processing["exclude_boards"],
            max_total=processing["max_total"],
            exact_job_key=job_key,
        )
        completed = rejected = parked = errors = 0
        extraction_reuses = alignment_reuses = 0
        for raw in claimed:
            try:
                source_content_sha256 = str(raw.content_sha256)
                prior = self.jobs.reusable_processing_result(
                    profile_id=profile_id,
                    track=track,
                    job_key=raw.key,
                    authority_sha256=authority_sha256,
                    source_content_sha256=source_content_sha256,
                    processing_config_sha256=config_sha256,
                )
                vacancy = _cached_vacancy(
                    prior,
                    job_key=raw.key,
                    source_content_sha256=source_content_sha256,
                )
                extraction_receipt_value: object | None = None
                if vacancy is not None:
                    extraction_reuses += 1
                    extraction_receipt_value = prior.get("extraction_receipt") if prior else None
                else:
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
                    extraction_receipt_value = asdict(extraction_receipt)
                geographic_preference = classify_geographic_preference(
                    location=vacancy.location,
                    remote_policy=vacancy.remote_policy,
                    policy=geographic_policy,
                )
                viability = assess_viability(vacancy)
                first_job_scope = assess_first_job_scope(vacancy, first_job_policy)
                if viability.decision != "include" or first_job_scope.decision != "include":
                    result: dict[str, object] = {
                        "first_job_scope": asdict(first_job_scope),
                        "included": False,
                        "geographic_preference": asdict(geographic_preference),
                        "viability": asdict(viability),
                        "vacancy": asdict(vacancy),
                    }
                    if extraction_receipt_value is not None:
                        result["extraction_receipt"] = extraction_receipt_value
                    if viability.decision != "include" or first_job_scope.decision == "exclude":
                        rejected += 1
                    else:
                        parked += 1
                else:
                    reused_axes = _cached_alignment_axes(prior)
                    alignment_receipt_value: object | None = None
                    if reused_axes is not None:
                        technical_alignment, evidence_match = reused_axes
                        alignment_reuses += 1
                        alignment_receipt_value = (
                            prior.get("alignment_receipt") if prior else None
                        )
                    else:
                        alignment_context = {
                            "evidence_authority_sha256": authority_sha256,
                            "profile": profile_context,
                            "track": track,
                            "vacancy": asdict(vacancy),
                        }
                        alignment, alignment_receipt = self.worker.align_evidence(
                            alignment_context
                        )
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
                            raise ValueError(
                                "evidence alignment identity differs from exact authorities"
                            )
                        accepted: EvidenceAlignment = accept_alignment(
                            alignment, evidence, alignment_receipt
                        )
                        technical_alignment = accepted.technical_alignment * 10
                        evidence_match = accepted.evidence_match * 10
                        alignment_receipt_value = asdict(alignment_receipt)
                    opportunity = derive_opportunity_axes(vacancy, self.opportunity_policy)
                    axes = AssessmentAxes(
                        technical_alignment=technical_alignment,
                        evidence_match=evidence_match,
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
                        "first_job_scope": asdict(first_job_scope),
                        "geographic_preference": asdict(geographic_preference),
                        "included": True,
                        "opportunity_axes": asdict(opportunity),
                        "score": {**asdict(score_result), "fit_status": score_result.fit_status.value},
                        "vacancy": asdict(vacancy),
                        "viability": asdict(viability),
                    }
                    if alignment_receipt_value is not None:
                        result["alignment_receipt"] = alignment_receipt_value
                    if extraction_receipt_value is not None:
                        result["extraction_receipt"] = extraction_receipt_value
                    completed += 1
                result["processing_config_sha256"] = config_sha256
                if prior is not None:
                    result["semantic_cache"] = {
                        "prior_result_sha256": _sha256(prior),
                        "source_content_sha256": source_content_sha256,
                    }
                self.jobs.complete_processing(
                    profile_id=profile_id,
                    track=track,
                    job_key=raw.key,
                    authority_sha256=authority_sha256,
                    source_content_sha256=str(raw.content_sha256),
                    processing_config_sha256=config_sha256,
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
                    processing_config_sha256=config_sha256,
                    worker_id=worker_id,
                    error=repr(exc),
                )

        with self.jobs.processing_report_snapshot(
            profile_id=profile_id,
            track=track,
            authority_sha256=authority_sha256,
            processing_config_sha256=config_sha256,
            include_boards=processing["include_boards"],
            exclude_boards=processing["exclude_boards"],
            max_total=processing["max_total"],
            exact_job_key=job_key,
        ) as result_rows:
            ranked = _ranked(result_rows)
            report_paths = write_reports(
                profile_id,
                ranked,
                self.paths.outputs / "reports",
                namespace=report_namespace,
            )
            report_hashes = {
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in asdict(report_paths).items()
            }
            report_values = {name: str(path) for name, path in asdict(report_paths).items()}
        scope_counts = self.jobs.processing_scope_counts(
            profile_id=profile_id,
            track=track,
            authority_sha256=authority_sha256,
            processing_config_sha256=config_sha256,
            include_boards=processing["include_boards"],
            exclude_boards=processing["exclude_boards"],
            max_total=processing["max_total"],
            exact_job_key=job_key,
        )
        body: dict[str, object] = {
            "application_authority": False,
            "authority_scope": "processing_only",
            "config_sha256": config_sha256,
            "errors": errors,
            "evidence_authority_sha256": authority_sha256,
            "evidence_alignments_reused": alignment_reuses,
            "geographic_preference_policy_sha256": geographic_policy.policy_hash,
            "first_job_scope_policy_sha256": first_job_policy.policy_hash,
            "included": completed,
            "job_specific_opportunity_axes": True,
            "opportunity_policy_sha256": self.opportunity_policy.policy_hash,
            "parked": parked,
            "profile_id": profile_id,
            "promotion": promotion,
            "promotion_receipt_path": str(promotion_receipt_path),
            "promotion_sha256": promotion_receipt_sha256,
            "ranked_count": len(ranked),
            "rejected": rejected,
            "report_hashes": report_hashes,
            "report_namespace_sha256": report_namespace_sha256,
            "report_scope": report_scope,
            "schema_version": "market-aligner.processing-run-receipt.v1",
            "shard_claimed": len(claimed),
            "scope": scope,
            "scope_counts": scope_counts,
            "scope_sha256": scope_sha256,
            "semantic_extractions_reused": extraction_reuses,
            "track": track,
            "worker_id": worker_id,
        }
        body["state_sha256"] = _sha256(result_rows)
        receipt_sha256 = _sha256(body)
        receipt = {**body, "receipt_sha256": receipt_sha256}
        receipt_path = self.paths.state / "processing-receipts" / f"{receipt_sha256}.json"
        _atomic_json(receipt_path, receipt)
        return {**receipt, "receipt_path": str(receipt_path), "reports": report_values}
