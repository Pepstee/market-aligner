"""Versioned schemas for bounded probabilistic work."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Protocol


LLM_CONTRACT_VERSION = "market-aligner.llm.v1"


def _unit(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a JSON number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    if not 0 <= result <= 1:
        raise ValueError(f"{name} must be in [0,1]")
    return result


def canonical_hash(value: Mapping[str, Any] | list[Any]) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SemanticVacancyExtraction:
    source_content_sha256: str
    title: str
    company: str
    location: str
    description: str
    responsibilities: tuple[str, ...]
    required_skills: tuple[str, ...]
    preferred_skills: tuple[str, ...]
    required_qualifications: tuple[str, ...]
    preferred_qualifications: tuple[str, ...]
    work_authorisation: tuple[str, ...]
    contract_type: str
    seniority: str
    remote_policy: str
    extraction_confidence: float
    unknown_fields: tuple[str, ...] = ()
    contract_version: str = LLM_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.contract_version != LLM_CONTRACT_VERSION:
            raise ValueError("unsupported LLM contract version")
        if not isinstance(self.source_content_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.source_content_sha256
        ):
            raise ValueError("source_content_sha256 must bind extraction to raw evidence")
        for name in (
            "title",
            "company",
            "location",
            "description",
            "contract_type",
            "seniority",
            "remote_policy",
        ):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"{name} must be a string")
        for name in (
            "responsibilities",
            "required_skills",
            "preferred_skills",
            "required_qualifications",
            "preferred_qualifications",
            "work_authorisation",
            "unknown_fields",
        ):
            value = getattr(self, name)
            if not isinstance(value, tuple) or any(not isinstance(item, str) for item in value):
                raise TypeError(f"{name} must be a tuple of strings")
        if (
            any(
                len(value) != 2 or value.upper() != value
                for value in self.work_authorisation
            )
            or tuple(sorted(set(self.work_authorisation)))
            != self.work_authorisation
        ):
            raise TypeError(
                "work_authorisation must be sorted unique uppercase two-letter "
                "country codes"
            )
        if not self.title.strip() or not self.description.strip():
            raise ValueError("title and complete description are required")
        _unit(self.extraction_confidence, "extraction_confidence")


@dataclass(frozen=True)
class EvidenceMatch:
    requirement: str
    evidence_ids: tuple[str, ...]
    strength: float
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.requirement, str) or not isinstance(self.rationale, str):
            raise TypeError("evidence match requirement and rationale must be strings")
        if not isinstance(self.evidence_ids, tuple) or any(
            not isinstance(value, str) for value in self.evidence_ids
        ):
            raise TypeError("evidence match IDs must be a tuple of strings")
        if not self.requirement.strip() or not self.rationale.strip():
            raise ValueError("evidence match requires requirement and rationale")
        _unit(self.strength, "strength")


@dataclass(frozen=True)
class EvidenceAlignment:
    def __post_init__(self) -> None:
        if self.contract_version != LLM_CONTRACT_VERSION:
            raise ValueError("unsupported LLM contract version")
        for name in ("profile_id", "profile_version", "job_key"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise TypeError(f"alignment {name} must be a non-empty string")
        if not isinstance(self.matches, tuple) or any(
            not isinstance(value, EvidenceMatch) for value in self.matches
        ):
            raise TypeError("alignment matches must be a tuple of EvidenceMatch")
        for name in ("missing_requirements", "unknowns"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or any(not isinstance(item, str) for item in value):
                raise TypeError(f"alignment {name} must be a tuple of strings")
        _unit(self.technical_alignment, "technical_alignment")
        _unit(self.evidence_match, "evidence_match")
        _unit(self.confidence, "confidence")

    profile_id: str
    profile_version: str
    job_key: str
    matches: tuple[EvidenceMatch, ...]
    missing_requirements: tuple[str, ...]
    technical_alignment: float
    evidence_match: float
    confidence: float
    unknowns: tuple[str, ...] = ()
    contract_version: str = LLM_CONTRACT_VERSION

    def validate_evidence_ids(self, known_ids: set[str]) -> None:
        invented = sorted(
            evidence_id
            for match in self.matches
            for evidence_id in match.evidence_ids
            if evidence_id not in known_ids
        )
        if invented:
            raise ValueError(f"alignment cites unknown evidence ids: {invented}")
        _unit(self.technical_alignment, "technical_alignment")
        _unit(self.evidence_match, "evidence_match")
        _unit(self.confidence, "confidence")


@dataclass(frozen=True)
class LLMTransportReceipt:
    provider_identity: str
    provider_sha256: str
    model_identity: str
    model_sha256: str
    transport_sha256: str
    request_sha256: str
    response_sha256: str
    binary_sha256: str
    invocation_count: int
    receipt_sha256: str
    schema_version: str = "market-aligner.llm-transport.v1"

    def __post_init__(self) -> None:
        if not self.provider_identity.strip() or not self.model_identity.strip():
            raise ValueError("transport provider and model identities are required")
        if self.invocation_count != 1:
            raise ValueError("semantic transport requires exactly one invocation")
        for name in (
            "provider_sha256",
            "model_sha256",
            "transport_sha256",
            "request_sha256",
            "response_sha256",
            "binary_sha256",
            "receipt_sha256",
        ):
            value = getattr(self, name)
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        document = asdict(self)
        observed = document.pop("receipt_sha256")
        if observed != canonical_hash(document):
            raise ValueError("transport receipt hash differs from its exact document")


@dataclass(frozen=True)
class LLMReceipt:
    def __post_init__(self) -> None:
        if self.contract_version != LLM_CONTRACT_VERSION:
            raise ValueError("unsupported LLM contract version")
        for name in ("receipt_id", "task", "model", "prompt_version", "created_at"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise TypeError(f"LLM receipt {name} must be a non-empty string")
        for name in ("input_sha256", "output_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError(f"LLM receipt {name} must be a lowercase SHA-256")

    receipt_id: str
    task: str
    model: str
    prompt_version: str
    input_sha256: str
    output_sha256: str
    created_at: str
    transport: LLMTransportReceipt | None = None
    contract_version: str = LLM_CONTRACT_VERSION

    @classmethod
    def bind(
        cls,
        *,
        receipt_id: str,
        task: str,
        model: str,
        prompt_version: str,
        inputs: Mapping[str, Any],
        output: Any,
        created_at: str,
        transport: LLMTransportReceipt | None = None,
    ) -> "LLMReceipt":
        output_payload = asdict(output) if hasattr(output, "__dataclass_fields__") else output
        return cls(
            receipt_id=receipt_id,
            task=task,
            model=model,
            prompt_version=prompt_version,
            input_sha256=canonical_hash(dict(inputs)),
            output_sha256=canonical_hash(output_payload),
            created_at=created_at,
            transport=transport,
        )


class LLMGateway(Protocol):
    def extract_vacancy(self, raw_context: Mapping[str, Any]) -> tuple[SemanticVacancyExtraction, LLMReceipt]: ...

    def align_evidence(self, context: Mapping[str, Any]) -> tuple[EvidenceAlignment, LLMReceipt]: ...
