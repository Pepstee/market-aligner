"""Receipt verification and deterministic acceptance of LLM-produced data."""

from __future__ import annotations

from dataclasses import asdict

from market_aligner.domain.contracts import RawPosting, Vacancy
from market_aligner.profiler.schema import EvidenceItem

from .contracts import EvidenceAlignment, LLMReceipt, SemanticVacancyExtraction, canonical_hash


def accept_extraction(
    raw: RawPosting,
    extraction: SemanticVacancyExtraction,
    receipt: LLMReceipt,
) -> Vacancy:
    if not raw.content_sha256:
        raise ValueError("raw posting requires a content hash before semantic extraction")
    if extraction.source_content_sha256 != raw.content_sha256:
        raise ValueError("extraction is bound to a different raw posting snapshot")
    if receipt.task != "semantic_vacancy_extraction":
        raise ValueError("wrong LLM receipt task")
    if receipt.output_sha256 != canonical_hash(asdict(extraction)):
        raise ValueError("LLM extraction output hash does not match its receipt")
    return Vacancy(
        board=raw.board,
        job_id=raw.job_id,
        url=raw.url,
        title=extraction.title,
        company=extraction.company,
        location=extraction.location,
        description=extraction.description,
        responsibilities=extraction.responsibilities,
        required_skills=extraction.required_skills,
        preferred_skills=extraction.preferred_skills,
        required_qualifications=extraction.required_qualifications,
        preferred_qualifications=extraction.preferred_qualifications,
        work_authorisation=extraction.work_authorisation,
        contract_type=extraction.contract_type,
        remote_policy=extraction.remote_policy,
        seniority=extraction.seniority,
        extraction_confidence=extraction.extraction_confidence,
        extraction_receipt_id=receipt.receipt_id,
        source_content_sha256=raw.content_sha256,
        extra={"unknown_fields": extraction.unknown_fields},
    )


def accept_alignment(
    alignment: EvidenceAlignment,
    evidence: dict[str, EvidenceItem],
    receipt: LLMReceipt,
) -> EvidenceAlignment:
    alignment.validate_evidence_ids(set(evidence))
    if receipt.task != "evidence_alignment":
        raise ValueError("wrong LLM receipt task")
    if receipt.output_sha256 != canonical_hash(asdict(alignment)):
        raise ValueError("LLM alignment output hash does not match its receipt")
    return alignment
