"""Deterministic, evidence-linked application strategy contract for JAA-06.

The compiler produces machine instructions rather than application prose.
Every actionable element is bound to an atomic vacancy requirement, one
approved candidate claim/evidence version and one current source-backed
employer fact.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Iterable, Mapping

from .database import CareerDatabase
from .evidence_matching import (
    FACTUAL_STATES,
    PROOF_CLASSES,
    InferenceReceipt,
    MatchResult,
    Requirement,
    candidate_graph_evidence,
    canonical_json,
    content_hash,
    evidence_projection_hash,
)
from .employer_research import FRESHNESS_DAYS
from .lifecycle import LifecycleReducer, PolicyIdentity
from .migrations import apply_jaa_06_migrations
from .models import IntelligenceKind, PipelineState


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


def verify_strategy_identity(strategy: ApplicationStrategy) -> None:
    """Recompute both strategy hashes from the public immutable document."""
    body = strategy.document()
    body.pop("strategy_id")
    body.pop("document_sha256")
    expected_document_hash = hashlib.sha256(
        canonical_json(body).encode("utf-8")
    ).hexdigest()
    expected_strategy_id = content_hash({
        "contract": "jaa06.application-strategy.v1",
        "document_sha256": expected_document_hash,
    })
    if (
        strategy.document_sha256 != expected_document_hash
        or strategy.strategy_id != expected_strategy_id
    ):
        raise ValueError("application strategy identity does not match its exact document")


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


class ApplicationStrategyStore:
    """Derive, persist and route one exact strategy from JAA-02/04/05 state."""

    POLICY_ID = "career.application-strategy"
    POLICY_VERSION = "1"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        apply_jaa_06_migrations(self.path)
        self.lifecycle = LifecycleReducer(self.path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _requirements(
        connection: sqlite3.Connection,
        fit_run_id: str,
    ) -> tuple[Requirement, ...]:
        rows = connection.execute(
            """SELECT * FROM vacancy_requirements
               WHERE run_id=? ORDER BY requirement_id""",
            (fit_run_id,),
        ).fetchall()
        return tuple(
            Requirement(
                str(row["requirement_id"]),
                str(row["criterion"]),
                str(row["requirement_text"]),
                bool(row["essential"]),
                str(row["gap_kind"]),
                str(row["bridge_policy"]),
                tuple(json.loads(str(row["accepted_proof_classes_json"]))),
                int(row["opportunity_weight_bp"]),
                str(row["source_identity"]),
                (int(row["source_start"]), int(row["source_end"])),
            )
            for row in rows
        )

    @staticmethod
    def _results(
        connection: sqlite3.Connection,
        fit_run_id: str,
        candidate_profile_hash: str,
    ) -> tuple[MatchResult, ...]:
        rows = connection.execute(
            """SELECT * FROM evidence_match_assessments
               WHERE run_id=? ORDER BY requirement_id""",
            (fit_run_id,),
        ).fetchall()
        results = []
        for row in rows:
            receipt = (
                None
                if row["proposal_hash"] is None
                else InferenceReceipt(
                    str(row["provider"]),
                    str(row["model"]),
                    str(row["prompt_hash"]),
                    str(row["policy_hash"]),
                    candidate_profile_hash,
                    str(row["input_hash"]),
                )
            )
            results.append(MatchResult(
                str(row["requirement_id"]),
                str(row["decision"]),
                tuple(json.loads(str(row["evidence_ids_json"]))),
                int(row["confidence_bp"]),
                str(row["reason"]),
                str(row["policy_hash"]),
                None if row["proposal_hash"] is None else str(row["proposal_hash"]),
                receipt,
            ))
        return tuple(results)

    @staticmethod
    def _candidate_support(
        connection: sqlite3.Connection,
        requirements: tuple[Requirement, ...],
        results: tuple[MatchResult, ...],
        evidence_rows: tuple[object, ...],
        as_of: date,
    ) -> tuple[CandidateSupport, ...]:
        requirement_by_id = {row.requirement_id: row for row in requirements}
        evidence_by_id = {
            str(getattr(row, "evidence_id")): row
            for row in evidence_rows
        }
        supports: list[CandidateSupport] = []
        for result in results:
            if result.decision != "matched":
                continue
            requirement = requirement_by_id[result.requirement_id]
            for evidence_id in result.evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None:
                    raise ValueError(
                        "fit evidence is not current in the candidate graph"
                    )
                claim_rows = connection.execute(
                    """SELECT claim.claim_id,claim.version,
                              claim.approval_state,claim.epistemic_state
                       FROM candidate_claims claim
                       JOIN candidate_claim_edges edge
                         ON edge.claim_id=claim.claim_id
                        AND edge.claim_version=claim.version
                       WHERE claim.claim_id=?
                         AND edge.evidence_id=? AND edge.evidence_version=?
                         AND edge.edge_type IN ('supports','demonstrated_by')
                         AND claim.approval_state='approved'
                         AND claim.epistemic_state IN ('fact','evidence')
                         AND (claim.valid_until IS NULL OR claim.valid_until>=?)
                         AND NOT EXISTS(
                           SELECT 1 FROM candidate_claims newer
                           WHERE newer.claim_id=claim.claim_id
                             AND newer.version>claim.version
                         )""",
                    (
                        requirement.criterion,
                        evidence_id,
                        int(getattr(evidence, "version")),
                        as_of.isoformat(),
                    ),
                ).fetchall()
                if len(claim_rows) != 1:
                    raise ValueError(
                        "fit evidence lacks one exact current approved candidate claim"
                    )
                claim = claim_rows[0]
                supports.append(CandidateSupport(
                    result.requirement_id,
                    str(claim["claim_id"]),
                    int(claim["version"]),
                    evidence_id,
                    int(getattr(evidence, "version")),
                    str(getattr(evidence, "proof_class")),
                    str(claim["approval_state"]),
                    str(claim["epistemic_state"]),
                    str(getattr(evidence, "approval_state")),
                    str(getattr(evidence, "epistemic_state")),
                    str(getattr(evidence, "verification_decision")),
                    getattr(evidence, "valid_until"),
                ))
        return tuple(supports)

    @staticmethod
    def _employer_facts(
        connection: sqlite3.Connection,
        *,
        job_key: str,
        dossier: Mapping[str, object],
        as_of: date,
    ) -> tuple[EmployerResearchFact, ...]:
        dossier_claims = {
            str(row.get("id")): row
            for row in dossier.get("claims", [])
            if isinstance(row, Mapping)
        }
        rows = connection.execute(
            """SELECT claim_id,kind,classification,claim_json
               FROM employer_intelligence
               WHERE job_key=? AND classification='fact'
               ORDER BY kind,claim_id""",
            (job_key,),
        ).fetchall()
        facts: list[EmployerResearchFact] = []
        for row in rows:
            try:
                claim = json.loads(str(row["claim_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("employer fact is not valid JSON") from exc
            claim_id = str(row["claim_id"])
            if (
                not isinstance(claim, dict)
                or dossier_claims.get(claim_id) != claim
                or claim.get("classification") != "fact"
                or claim.get("kind") != row["kind"]
            ):
                raise ValueError("employer fact differs from the durable dossier")
            source_ids = claim.get("source_ids")
            if not isinstance(source_ids, list) or not source_ids:
                raise ValueError("employer fact has no dossier source identity")
            observed = claim.get("observed_at") or claim.get("source_captured_at")
            if not isinstance(observed, str):
                continue
            try:
                observed_date = datetime.fromisoformat(
                    observed.replace("Z", "+00:00")
                ).date()
            except ValueError as exc:
                raise ValueError("employer fact observation date is invalid") from exc
            kind = IntelligenceKind(str(row["kind"]))
            age = (as_of - observed_date).days
            if age < 0 or age > FRESHNESS_DAYS[kind]:
                continue
            facts.append(EmployerResearchFact(
                claim_id,
                kind.value,
                str(row["classification"]),
                tuple(str(value) for value in source_ids),
                content_hash(claim),
                "current",
            ))
        return tuple(facts)

    def compile_and_record(
        self,
        *,
        fit_run_id: str,
        as_of: date,
    ) -> ApplicationStrategy:
        """Compile from durable upstream authority and commit one exact result."""
        database = CareerDatabase(self.path)
        with self._connect() as connection:
            fit = connection.execute(
                """SELECT run.*,job.state AS job_state
                   FROM fit_assessment_runs run
                   JOIN pipeline_jobs job ON job.job_key=run.job_key
                   WHERE run.run_id=?""",
                (fit_run_id,),
            ).fetchone()
            if fit is None:
                raise KeyError(fit_run_id)
            if connection.execute(
                """SELECT 1 FROM fit_assessment_runs
                   WHERE predecessor_run_id=?""",
                (fit_run_id,),
            ).fetchone() is not None:
                raise ValueError("application strategy requires the latest fit run")
            if as_of < date.fromisoformat(str(fit["as_of"])):
                raise ValueError("strategy date cannot predate the fit run")
            requirements = self._requirements(connection, fit_run_id)
            results = self._results(
                connection,
                fit_run_id,
                str(fit["candidate_profile_hash"]),
            )
        dossier_result = database.post_research_dossier(str(fit["job_key"]))
        if dossier_result is None:
            raise ValueError("application strategy requires a durable employer dossier")
        dossier, dossier_hash = dossier_result
        opportunity = database.opportunity1_reassessment(
            str(fit["job_key"]),
            expected_dossier_hash=dossier_hash,
        )
        if opportunity is None or opportunity["decision"] != "pass":
            raise ValueError("application strategy requires a passed Opportunity-1")
        evidence = candidate_graph_evidence(self.path, as_of=as_of)
        if evidence_projection_hash(evidence) != str(fit["candidate_profile_hash"]):
            raise ValueError("candidate graph changed after the fit run")
        with self._connect() as connection:
            supports = self._candidate_support(
                connection,
                requirements,
                results,
                evidence,
                as_of,
            )
            facts = self._employer_facts(
                connection,
                job_key=str(fit["job_key"]),
                dossier=dossier,
                as_of=as_of,
            )
        strategy = compile_application_strategy(
            fit_run_id=fit_run_id,
            dossier_hash=dossier_hash,
            candidate_profile_hash=str(fit["candidate_profile_hash"]),
            requirements=requirements,
            match_results=results,
            candidate_support=supports,
            employer_facts=facts,
            as_of=as_of,
        )
        expected_decision = {
            "ready": "apply_now",
            "gap_identified": "close_gap_first",
            "blocked": "reject_candidacy",
        }[str(fit["status"])]
        if strategy.decision != expected_decision:
            raise ValueError("strategy decision conflicts with durable fit status")
        return self._record(
            strategy,
            job_key=str(fit["job_key"]),
            predecessor_run_id=(
                None
                if fit["predecessor_run_id"] is None
                else str(fit["predecessor_run_id"])
            ),
        )

    def _record(
        self,
        strategy: ApplicationStrategy,
        *,
        job_key: str,
        predecessor_run_id: str | None,
    ) -> ApplicationStrategy:
        verify_strategy_identity(strategy)
        document_json = canonical_json(strategy.document())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT run.status,run.document_hash,job.state AS job_state,
                          dossier.dossier_hash,reassessment.decision AS opportunity_decision
                   FROM fit_assessment_runs run
                   JOIN pipeline_jobs job ON job.job_key=run.job_key
                   JOIN employer_dossiers dossier ON dossier.job_key=run.job_key
                   JOIN opportunity_reassessments reassessment
                     ON reassessment.job_key=run.job_key
                   WHERE run.run_id=? AND run.job_key=?""",
                (strategy.fit_run_id, job_key),
            ).fetchone()
            if row is None:
                raise ValueError("strategy upstream identities do not resolve")
            if (
                str(row["dossier_hash"]) != strategy.dossier_hash
                or str(row["opportunity_decision"]) != "pass"
            ):
                raise ValueError("strategy upstream authority changed before commit")
            expected_state = {
                "apply_now": (
                    PipelineState.FIT_REASSESSED
                    if predecessor_run_id is not None
                    else PipelineState.FIT_ASSESSED
                ),
                "close_gap_first": PipelineState.GAP_IDENTIFIED,
                "reject_candidacy": PipelineState.CANDIDATE_REJECTED,
            }[strategy.decision]
            existing = connection.execute(
                "SELECT * FROM application_strategies WHERE fit_run_id=?",
                (strategy.fit_run_id,),
            ).fetchone()
            lifecycle_receipt_id = None
            if strategy.decision == "apply_now":
                transition = self.lifecycle.commit_in_transaction(
                    connection,
                    job_key=job_key,
                    to_state=PipelineState.STRATEGY_READY,
                    policy=PolicyIdentity(
                        self.POLICY_ID,
                        self.POLICY_VERSION,
                        strategy.policy_sha256,
                    ),
                    inputs={
                        "strategy_id": strategy.strategy_id,
                        "fit_run_id": strategy.fit_run_id,
                        "dossier_hash": strategy.dossier_hash,
                        "candidate_profile_hash": strategy.candidate_profile_hash,
                        "input_sha256": strategy.input_sha256,
                        "document_sha256": strategy.document_sha256,
                    },
                    outputs={
                        "decision": strategy.decision,
                        "coverage": len(strategy.coverage),
                        "elements": len(strategy.elements),
                    },
                    idempotency_key=(
                        f"application-strategy:{job_key}:{strategy.fit_run_id}"
                    ),
                )
                lifecycle_receipt_id = transition.receipt_id
            elif existing is None and str(row["job_state"]) != expected_state.value:
                raise ValueError("strategy decision is out of lifecycle order")
            expected = (
                strategy.strategy_id,
                job_key,
                strategy.fit_run_id,
                strategy.dossier_hash,
                strategy.candidate_profile_hash,
                strategy.as_of.isoformat(),
                strategy.decision,
                strategy.input_sha256,
                strategy.policy_sha256,
                document_json,
                strategy.document_sha256,
                lifecycle_receipt_id,
            )
            if existing is not None:
                actual = tuple(existing[key] for key in (
                    "strategy_id",
                    "job_key",
                    "fit_run_id",
                    "dossier_hash",
                    "candidate_profile_hash",
                    "as_of",
                    "decision",
                    "input_hash",
                    "policy_hash",
                    "document_json",
                    "document_hash",
                    "lifecycle_receipt_id",
                ))
                if actual != expected:
                    raise ValueError("fit run already has a different application strategy")
                stored_coverage = connection.execute(
                    """SELECT fit_run_id,requirement_id,coverage_state,
                              candidate_claim_ids_json,
                              candidate_evidence_ids_json,reason_code
                       FROM strategy_requirement_coverage
                       WHERE strategy_id=? ORDER BY requirement_id""",
                    (strategy.strategy_id,),
                ).fetchall()
                expected_coverage = tuple(
                    (
                        strategy.fit_run_id,
                        row.requirement_id,
                        row.state,
                        canonical_json(row.candidate_claim_ids),
                        canonical_json(row.candidate_evidence_ids),
                        row.reason_code,
                    )
                    for row in strategy.coverage
                )
                stored_elements = connection.execute(
                    """SELECT element_id,job_key,fit_run_id,element_kind,
                              requirement_id,candidate_claim_id,
                              candidate_claim_version,candidate_evidence_id,
                              candidate_evidence_version,research_claim_id,
                              employer_fact_hash,directive
                       FROM strategy_elements WHERE strategy_id=?
                       ORDER BY requirement_id,
                         CASE element_kind
                           WHEN 'cv_emphasis' THEN 0
                           WHEN 'cover_letter_argument' THEN 1
                           WHEN 'structured_answer' THEN 2
                           WHEN 'interview_seed' THEN 3
                           WHEN 'objection_response' THEN 4
                           WHEN 'employer_hook' THEN 5
                         END""",
                    (strategy.strategy_id,),
                ).fetchall()
                expected_elements = tuple(
                    (
                        row.element_id,
                        job_key,
                        strategy.fit_run_id,
                        row.kind,
                        row.requirement_id,
                        row.candidate_claim_id,
                        row.candidate_claim_version,
                        row.candidate_evidence_id,
                        row.candidate_evidence_version,
                        row.employer_research_claim_id,
                        row.employer_fact_sha256,
                        row.directive,
                    )
                    for row in strategy.elements
                )
                if (
                    tuple(tuple(row) for row in stored_coverage)
                    != expected_coverage
                    or tuple(tuple(row) for row in stored_elements)
                    != expected_elements
                ):
                    raise ValueError(
                        "stored application strategy children differ from its document"
                    )
            else:
                connection.execute(
                    """INSERT INTO application_strategies(
                         strategy_id,job_key,fit_run_id,dossier_hash,
                         candidate_profile_hash,as_of,decision,input_hash,
                         policy_hash,document_json,document_hash,
                         lifecycle_receipt_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    expected,
                )
                for coverage in strategy.coverage:
                    connection.execute(
                        """INSERT INTO strategy_requirement_coverage(
                             strategy_id,fit_run_id,requirement_id,
                             coverage_state,candidate_claim_ids_json,
                             candidate_evidence_ids_json,reason_code)
                           VALUES(?,?,?,?,?,?,?)""",
                        (
                            strategy.strategy_id,
                            strategy.fit_run_id,
                            coverage.requirement_id,
                            coverage.state,
                            canonical_json(coverage.candidate_claim_ids),
                            canonical_json(coverage.candidate_evidence_ids),
                            coverage.reason_code,
                        ),
                    )
                for element in strategy.elements:
                    connection.execute(
                        """INSERT INTO strategy_elements(
                             element_id,strategy_id,job_key,fit_run_id,
                             element_kind,requirement_id,candidate_claim_id,
                             candidate_claim_version,candidate_evidence_id,
                             candidate_evidence_version,research_claim_id,
                             employer_fact_hash,directive)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            element.element_id,
                            strategy.strategy_id,
                            job_key,
                            strategy.fit_run_id,
                            element.kind,
                            element.requirement_id,
                            element.candidate_claim_id,
                            element.candidate_claim_version,
                            element.candidate_evidence_id,
                            element.candidate_evidence_version,
                            element.employer_research_claim_id,
                            element.employer_fact_sha256,
                            element.directive,
                        ),
                    )
            connection.commit()
            return strategy
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def load(
        self,
        strategy_id: str,
        *,
        as_of: date,
    ) -> ApplicationStrategy:
        """Load only a canonical strategy whose upstream authority is still current."""
        _digest(strategy_id, "strategy ID")
        with self._connect() as connection:
            parent = connection.execute(
                """SELECT strategy.*,run.candidate_profile_hash AS fit_profile_hash
                   FROM application_strategies strategy
                   JOIN fit_assessment_runs run
                     ON run.run_id=strategy.fit_run_id
                   WHERE strategy.strategy_id=?""",
                (strategy_id,),
            ).fetchone()
            if parent is None:
                raise KeyError(strategy_id)
            coverage_rows = connection.execute(
                """SELECT * FROM strategy_requirement_coverage
                   WHERE strategy_id=? ORDER BY requirement_id""",
                (strategy_id,),
            ).fetchall()
            element_rows = connection.execute(
                """SELECT * FROM strategy_elements
                   WHERE strategy_id=?""",
                (strategy_id,),
            ).fetchall()
        try:
            stored_document = json.loads(str(parent["document_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("stored application strategy is not valid JSON") from exc
        coverage = tuple(
            RequirementCoverage(
                str(row["requirement_id"]),
                str(row["coverage_state"]),
                tuple(json.loads(str(row["candidate_claim_ids_json"]))),
                tuple(json.loads(str(row["candidate_evidence_ids_json"]))),
                str(row["reason_code"]),
            )
            for row in coverage_rows
        )
        element_rows = sorted(
            element_rows,
            key=lambda row: (
                str(row["requirement_id"]),
                ELEMENT_KINDS.index(str(row["element_kind"])),
            ),
        )
        elements = tuple(
            StrategyElement(
                str(row["element_id"]),
                str(row["element_kind"]),
                str(row["requirement_id"]),
                str(row["candidate_claim_id"]),
                int(row["candidate_claim_version"]),
                str(row["candidate_evidence_id"]),
                int(row["candidate_evidence_version"]),
                str(row["research_claim_id"]),
                str(row["employer_fact_hash"]),
                str(row["directive"]),
            )
            for row in element_rows
        )
        strategy = ApplicationStrategy(
            str(parent["strategy_id"]),
            str(parent["fit_run_id"]),
            str(parent["dossier_hash"]),
            str(parent["candidate_profile_hash"]),
            date.fromisoformat(str(parent["as_of"])),
            str(parent["decision"]),
            coverage,
            elements,
            str(parent["input_hash"]),
            str(parent["policy_hash"]),
            str(parent["document_hash"]),
        )
        verify_strategy_identity(strategy)
        if (
            not isinstance(stored_document, dict)
            or canonical_json(stored_document) != str(parent["document_json"])
            or canonical_json(stored_document)
            != canonical_json(strategy.document())
            or str(parent["fit_profile_hash"]) != strategy.candidate_profile_hash
            or as_of < strategy.as_of
        ):
            raise ValueError("stored application strategy identity is inconsistent")
        database = CareerDatabase(self.path)
        dossier_result = database.post_research_dossier(str(parent["job_key"]))
        if dossier_result is None or dossier_result[1] != strategy.dossier_hash:
            raise ValueError("stored strategy dossier authority is unavailable")
        evidence = candidate_graph_evidence(self.path, as_of=as_of)
        if evidence_projection_hash(evidence) != strategy.candidate_profile_hash:
            raise ValueError("stored strategy candidate authority is no longer current")
        with self._connect() as connection:
            current_facts = self._employer_facts(
                connection,
                job_key=str(parent["job_key"]),
                dossier=dossier_result[0],
                as_of=as_of,
            )
        fact_bindings = {
            (row.claim_id, row.content_sha256)
            for row in current_facts
        }
        if any(
            (row.employer_research_claim_id, row.employer_fact_sha256)
            not in fact_bindings
            for row in strategy.elements
        ):
            raise ValueError("stored strategy employer authority is no longer current")
        self.lifecycle.verify()
        return strategy
