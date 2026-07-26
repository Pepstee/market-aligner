"""Deterministic, evidence-linked application strategy contract for JAA-06.

The compiler produces machine instructions rather than application prose.
Every actionable element is bound to an atomic vacancy requirement, one
approved candidate claim/evidence version and one current source-backed
employer fact.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from typing import Iterable, Mapping

from .evidence_matching import (
    FACTUAL_STATES,
    PROOF_CLASSES,
    MatchResult,
    Requirement,
    canonical_json,
    content_hash,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
PLAN_DECISIONS = frozenset({"apply_now", "close_gap_first", "reject_candidacy"})
COVERAGE_STATES = frozenset({"covered", "absent", "release_blocking"})
ELEMENT_KINDS = (
    "cv_emphasis",
    "cover_letter_argument",
    "structured_answer",
    "interview_seed",
    "objection_response",
    "employer_hook",
)
DIRECTIVES: Mapping[str, str] = {
    "cv_emphasis": "surface_approved_proof",
    "cover_letter_argument": "connect_proof_to_employer_fact",
    "structured_answer": "answer_from_approved_proof",
    "interview_seed": "prepare_verifiable_example",
    "objection_response": "address_requirement_with_proof",
    "employer_hook": "use_source_backed_employer_context",
}
RESEARCH_KIND_PRIORITY = {
    "role": 0,
    "product": 1,
    "company": 2,
    "hiring": 3,
    "operational_health": 4,
}


def _required(value: str, label: str) -> str:
    result = value.strip()
    if not result:
        raise ValueError(f"{label} is required")
    return result


def _digest(value: str, label: str) -> str:
    if not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class CandidateSupport:
    requirement_id: str
    claim_id: str
    claim_version: int
    evidence_id: str
    evidence_version: int
    proof_class: str
    claim_approval_state: str
    claim_epistemic_state: str
    evidence_approval_state: str
    evidence_epistemic_state: str
    verification_decision: str
    valid_until: date | None

    def __post_init__(self) -> None:
        for value, label in (
            (self.requirement_id, "support requirement ID"),
            (self.claim_id, "candidate claim ID"),
            (self.evidence_id, "candidate evidence ID"),
        ):
            _required(value, label)
        if self.claim_version < 1 or self.evidence_version < 1:
            raise ValueError("candidate claim and evidence versions must be positive")
        if self.proof_class not in PROOF_CLASSES:
            raise ValueError("candidate support proof class is unsupported")
        if (
            self.claim_approval_state != "approved"
            or self.claim_epistemic_state not in FACTUAL_STATES
        ):
            raise ValueError("strategy support requires an approved factual candidate claim")
        if (
            self.evidence_approval_state != "approved"
            or self.evidence_epistemic_state not in FACTUAL_STATES
            or self.verification_decision != "approved"
        ):
            raise ValueError(
                "strategy support requires independently approved factual evidence"
            )


@dataclass(frozen=True)
class EmployerResearchFact:
    claim_id: str
    kind: str
    classification: str
    source_ids: tuple[str, ...]
    content_sha256: str
    freshness_classification: str

    def __post_init__(self) -> None:
        _required(self.claim_id, "employer research claim ID")
        if self.kind not in RESEARCH_KIND_PRIORITY:
            raise ValueError("employer research kind is unsupported")
        if self.classification != "fact":
            raise ValueError("employer hypotheses or inferences cannot be strategy facts")
        if (
            not self.source_ids
            or len(set(self.source_ids)) != len(self.source_ids)
            or any(not value.strip() for value in self.source_ids)
        ):
            raise ValueError("employer fact requires exact source identities")
        _digest(self.content_sha256, "employer fact content hash")
        if self.freshness_classification != "current":
            raise ValueError("employer strategy facts must be current")


@dataclass(frozen=True)
class RequirementCoverage:
    requirement_id: str
    state: str
    candidate_claim_ids: tuple[str, ...]
    candidate_evidence_ids: tuple[str, ...]
    reason_code: str

    def __post_init__(self) -> None:
        if self.state not in COVERAGE_STATES:
            raise ValueError("requirement coverage state is invalid")
        if self.state == "covered":
            if not self.candidate_claim_ids or not self.candidate_evidence_ids:
                raise ValueError("covered requirements require claim and evidence IDs")
        elif self.candidate_claim_ids or self.candidate_evidence_ids:
            raise ValueError("absent requirements cannot cite positive candidate support")


@dataclass(frozen=True)
class StrategyElement:
    element_id: str
    kind: str
    requirement_id: str
    candidate_claim_id: str
    candidate_claim_version: int
    candidate_evidence_id: str
    candidate_evidence_version: int
    employer_research_claim_id: str
    employer_fact_sha256: str
    directive: str

    def __post_init__(self) -> None:
        _digest(self.element_id, "strategy element ID")
        if self.kind not in ELEMENT_KINDS or self.directive != DIRECTIVES[self.kind]:
            raise ValueError("strategy element kind and directive are inconsistent")
        for value, label in (
            (self.requirement_id, "strategy requirement ID"),
            (self.candidate_claim_id, "strategy candidate claim ID"),
            (self.candidate_evidence_id, "strategy candidate evidence ID"),
            (self.employer_research_claim_id, "strategy research claim ID"),
        ):
            _required(value, label)
        if self.candidate_claim_version < 1 or self.candidate_evidence_version < 1:
            raise ValueError("strategy candidate versions must be positive")
        _digest(self.employer_fact_sha256, "strategy employer fact hash")


@dataclass(frozen=True)
class ApplicationStrategy:
    strategy_id: str
    fit_run_id: str
    dossier_hash: str
    candidate_profile_hash: str
    as_of: date
    decision: str
    coverage: tuple[RequirementCoverage, ...]
    elements: tuple[StrategyElement, ...]
    input_sha256: str
    policy_sha256: str
    document_sha256: str
    schema_version: str = "jaa06.application-strategy.v1"
    certifies_slice: bool = False
    dependency_gate: str = "JAA-05"

    def __post_init__(self) -> None:
        if self.schema_version != "jaa06.application-strategy.v1":
            raise ValueError("unsupported application strategy schema")
        if self.certifies_slice is not False or self.dependency_gate != "JAA-05":
            raise ValueError("offline strategy cannot certify JAA-06")
        if self.decision not in PLAN_DECISIONS:
            raise ValueError("application strategy decision is invalid")
        for value, label in (
            (self.strategy_id, "strategy ID"),
            (self.fit_run_id, "fit run ID"),
            (self.dossier_hash, "dossier hash"),
            (self.candidate_profile_hash, "candidate profile hash"),
            (self.input_sha256, "strategy input hash"),
            (self.policy_sha256, "strategy policy hash"),
            (self.document_sha256, "strategy document hash"),
        ):
            _digest(value, label)
        requirement_ids = [row.requirement_id for row in self.coverage]
        if not requirement_ids or len(requirement_ids) != len(set(requirement_ids)):
            raise ValueError("strategy coverage must contain unique requirements")
        if self.decision == "apply_now":
            if any(row.state != "covered" for row in self.coverage):
                raise ValueError("apply-now strategy must cover every requirement")
            expected = len(self.coverage) * len(ELEMENT_KINDS)
            if len(self.elements) != expected:
                raise ValueError("apply-now strategy has incomplete document directives")
        elif self.elements:
            raise ValueError("non-apply strategy cannot emit application directives")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "strategy_id": self.strategy_id,
            "fit_run_id": self.fit_run_id,
            "dossier_hash": self.dossier_hash,
            "candidate_profile_hash": self.candidate_profile_hash,
            "as_of": self.as_of.isoformat(),
            "decision": self.decision,
            "coverage": [
                {
                    "requirement_id": row.requirement_id,
                    "state": row.state,
                    "candidate_claim_ids": row.candidate_claim_ids,
                    "candidate_evidence_ids": row.candidate_evidence_ids,
                    "reason_code": row.reason_code,
                }
                for row in self.coverage
            ],
            "elements": [
                {
                    "element_id": row.element_id,
                    "kind": row.kind,
                    "requirement_id": row.requirement_id,
                    "candidate_claim_id": row.candidate_claim_id,
                    "candidate_claim_version": row.candidate_claim_version,
                    "candidate_evidence_id": row.candidate_evidence_id,
                    "candidate_evidence_version": row.candidate_evidence_version,
                    "employer_research_claim_id": row.employer_research_claim_id,
                    "employer_fact_sha256": row.employer_fact_sha256,
                    "directive": row.directive,
                }
                for row in self.elements
            ],
            "input_sha256": self.input_sha256,
            "policy_sha256": self.policy_sha256,
            "document_sha256": self.document_sha256,
            "certifies_slice": self.certifies_slice,
            "dependency_gate": self.dependency_gate,
        }


def _requirement_document(requirement: Requirement) -> dict[str, object]:
    return {
        "requirement_id": requirement.requirement_id,
        "criterion": requirement.criterion,
        "text_sha256": hashlib.sha256(requirement.text.encode("utf-8")).hexdigest(),
        "essential": requirement.essential,
        "gap_kind": requirement.gap_kind,
        "accepted_proof_classes": requirement.accepted_proof_classes,
        "source_identity": requirement.source_identity,
        "source_span": requirement.source_span,
    }


def _result_document(result: MatchResult) -> dict[str, object]:
    return {
        "requirement_id": result.requirement_id,
        "decision": result.decision,
        "evidence_ids": result.evidence_ids,
        "confidence_bp": result.confidence_bp,
        "policy_sha256": result.policy_sha256,
        "proposal_sha256": result.proposal_sha256,
    }


def compile_application_strategy(
    *,
    fit_run_id: str,
    dossier_hash: str,
    candidate_profile_hash: str,
    requirements: Iterable[Requirement],
    match_results: Iterable[MatchResult],
    candidate_support: Iterable[CandidateSupport],
    employer_facts: Iterable[EmployerResearchFact],
    as_of: date,
) -> ApplicationStrategy:
    """Compile one canonical plan without writing prose or promoting evidence."""
    _digest(fit_run_id, "fit run ID")
    _digest(dossier_hash, "dossier hash")
    _digest(candidate_profile_hash, "candidate profile hash")
    requirement_rows = tuple(sorted(requirements, key=lambda row: row.requirement_id))
    result_rows = tuple(sorted(match_results, key=lambda row: row.requirement_id))
    support_rows = tuple(sorted(
        candidate_support,
        key=lambda row: (
            row.requirement_id,
            row.claim_id,
            row.claim_version,
            row.evidence_id,
            row.evidence_version,
        ),
    ))
    fact_rows = tuple(sorted(
        employer_facts,
        key=lambda row: (RESEARCH_KIND_PRIORITY[row.kind], row.claim_id),
    ))
    requirement_by_id = {row.requirement_id: row for row in requirement_rows}
    result_by_id = {row.requirement_id: row for row in result_rows}
    if (
        not requirement_rows
        or len(requirement_by_id) != len(requirement_rows)
        or len(result_by_id) != len(result_rows)
        or set(result_by_id) != set(requirement_by_id)
    ):
        raise ValueError("strategy requirements and fit results must align exactly")
    result_policy_hashes = {row.policy_sha256 for row in result_rows}
    if len(result_policy_hashes) != 1:
        raise ValueError("strategy fit results must use one exact matching policy")
    _digest(next(iter(result_policy_hashes)), "fit result policy hash")
    support_by_key = {
        (row.requirement_id, row.evidence_id): row
        for row in support_rows
    }
    if len(support_by_key) != len(support_rows):
        raise ValueError("candidate support identities must be unique")
    expected_support_keys = {
        (result.requirement_id, evidence_id)
        for result in result_rows
        if result.decision == "matched"
        for evidence_id in result.evidence_ids
    }
    if set(support_by_key) != expected_support_keys:
        raise ValueError("candidate support must align exactly with matched evidence")
    coverage: list[RequirementCoverage] = []
    for requirement in requirement_rows:
        result = result_by_id[requirement.requirement_id]
        relevant = tuple(
            support_by_key[(requirement.requirement_id, evidence_id)]
            for evidence_id in result.evidence_ids
            if (requirement.requirement_id, evidence_id) in support_by_key
        )
        if result.decision == "matched":
            if (
                len(relevant) != len(result.evidence_ids)
                or not relevant
                or any(
                    row.claim_id != requirement.criterion
                    or row.proof_class not in requirement.accepted_proof_classes
                    or row.valid_until is not None and row.valid_until < as_of
                    for row in relevant
                )
            ):
                raise ValueError(
                    "matched requirement lacks exact current approved candidate support"
                )
            coverage.append(RequirementCoverage(
                requirement.requirement_id,
                "covered",
                tuple(sorted({row.claim_id for row in relevant})),
                tuple(sorted(result.evidence_ids)),
                "approved_evidence_match",
            ))
        else:
            coverage.append(RequirementCoverage(
                requirement.requirement_id,
                "release_blocking" if requirement.essential else "absent",
                (),
                (),
                "essential_requirement_uncovered"
                if requirement.essential
                else "optional_requirement_absent",
            ))
    structural_block = any(
        result_by_id[row.requirement_id].decision != "matched"
        and row.essential
        and row.gap_kind == "structural"
        for row in requirement_rows
    )
    decision = (
        "reject_candidacy"
        if structural_block
        else "close_gap_first"
        if any(row.state != "covered" for row in coverage)
        else "apply_now"
    )
    if decision == "apply_now" and not fact_rows:
        raise ValueError("apply-now strategy requires current source-backed employer facts")
    support_document = [
        {
            **{
                key: value
                for key, value in vars(row).items()
                if key != "valid_until"
            },
            "valid_until": row.valid_until.isoformat() if row.valid_until else None,
        }
        for row in support_rows
    ]
    fact_document = [
        {
            **vars(row),
            "source_ids": tuple(sorted(row.source_ids)),
        }
        for row in fact_rows
    ]
    policy_sha256 = content_hash({
        "contract": "jaa06.application-strategy-policy.v1",
        "element_kinds": ELEMENT_KINDS,
        "directives": dict(DIRECTIVES),
        "research_kind_priority": RESEARCH_KIND_PRIORITY,
        "directive_evidence_selection": "lexicographic_first",
        "decisions": sorted(PLAN_DECISIONS),
        "coverage_states": sorted(COVERAGE_STATES),
    })
    input_sha256 = content_hash({
        "fit_run_id": fit_run_id,
        "dossier_hash": dossier_hash,
        "candidate_profile_hash": candidate_profile_hash,
        "as_of": as_of.isoformat(),
        "requirements": [_requirement_document(row) for row in requirement_rows],
        "results": [_result_document(row) for row in result_rows],
        "candidate_support": support_document,
        "employer_facts": fact_document,
    })
    elements: list[StrategyElement] = []
    if decision == "apply_now":
        for index, requirement in enumerate(requirement_rows):
            result = result_by_id[requirement.requirement_id]
            # Coverage retains every match; one stable representative keeps
            # each document directive atomic and independently traceable.
            support = support_by_key[
                (requirement.requirement_id, sorted(result.evidence_ids)[0])
            ]
            fact = fact_rows[index % len(fact_rows)]
            for kind in ELEMENT_KINDS:
                element_identity = {
                    "fit_run_id": fit_run_id,
                    "kind": kind,
                    "requirement_id": requirement.requirement_id,
                    "candidate_claim": (support.claim_id, support.claim_version),
                    "candidate_evidence": (
                        support.evidence_id,
                        support.evidence_version,
                    ),
                    "research_claim_id": fact.claim_id,
                    "employer_fact_sha256": fact.content_sha256,
                    "directive": DIRECTIVES[kind],
                    "policy_sha256": policy_sha256,
                }
                elements.append(StrategyElement(
                    content_hash(element_identity),
                    kind,
                    requirement.requirement_id,
                    support.claim_id,
                    support.claim_version,
                    support.evidence_id,
                    support.evidence_version,
                    fact.claim_id,
                    fact.content_sha256,
                    DIRECTIVES[kind],
                ))
    body = {
        "schema_version": "jaa06.application-strategy.v1",
        "fit_run_id": fit_run_id,
        "dossier_hash": dossier_hash,
        "candidate_profile_hash": candidate_profile_hash,
        "as_of": as_of.isoformat(),
        "decision": decision,
        "coverage": [vars(row) for row in coverage],
        "elements": [vars(row) for row in elements],
        "input_sha256": input_sha256,
        "policy_sha256": policy_sha256,
        "certifies_slice": False,
        "dependency_gate": "JAA-05",
    }
    document_sha256 = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    strategy_id = content_hash({
        "contract": "jaa06.application-strategy.v1",
        "document_sha256": document_sha256,
    })
    return ApplicationStrategy(
        strategy_id,
        fit_run_id,
        dossier_hash,
        candidate_profile_hash,
        as_of,
        decision,
        tuple(coverage),
        tuple(elements),
        input_sha256,
        policy_sha256,
        document_sha256,
    )
