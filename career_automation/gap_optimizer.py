"""Deterministic JAA-05 gap classification and improvement-task ranking."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable, Mapping

from .evidence_matching import (
    PROOF_CLASSES,
    CandidateMatchBatch,
    MatchProposal,
    MatchResult,
    MatchingPolicy,
    Requirement,
    canonical_json,
    content_hash,
    match_candidate_graph,
)
from .lifecycle import LifecycleReducer, PolicyIdentity
from .migrations import apply_jaa_05_migrations
from .models import PipelineState


HEX_64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class TaskTemplate:
    action_kind: str
    verification_method: str
    resulting_proof_class: str
    verifier_kinds: tuple[str, ...]
    cost_units: int
    reuse_value_bp: int


DEFAULT_TEMPLATES: Mapping[str, TaskTemplate] = {
    "presentation": TaskTemplate(
        "present_verified_evidence", "approved-claim-link", "verified_claim",
        ("deterministic", "human"), 1, 9000,
    ),
    "retrieval": TaskTemplate(
        "retrieve_existing_evidence", "source-and-content-hash", "work_artifact",
        ("deterministic", "human"), 2, 9000,
    ),
    "knowledge": TaskTemplate(
        "learn_and_test", "locked-assessment-pass", "test_result",
        ("deterministic", "human"), 4, 8000,
    ),
    "execution": TaskTemplate(
        "execute_and_verify", "reproducible-task-receipt", "work_artifact",
        ("deterministic", "human"), 6, 8500,
    ),
    "evidence": TaskTemplate(
        "build_evidence", "artifact-and-independent-review", "portfolio_artifact",
        ("deterministic", "human"), 5, 9000,
    ),
    "experience": TaskTemplate(
        "gain_real_experience", "external-outcome-receipt", "external_outcome",
        ("external", "human"), 10, 7000,
    ),
    "credential": TaskTemplate(
        "earn_credential", "issuer-verification", "credential",
        ("external",), 12, 6500,
    ),
}


@dataclass(frozen=True)
class Gap:
    gap_id: str
    requirement_id: str
    kind: str
    status: str
    blocking: bool
    reason: str


@dataclass(frozen=True)
class ResultingEvidenceContract:
    proof_class: str
    verification_method: str
    verifier_kinds: tuple[str, ...]
    approval_state: str = "pending"

    def __post_init__(self) -> None:
        if self.proof_class not in PROOF_CLASSES:
            raise ValueError("task contract has an unsupported proof class")
        if not self.verification_method.strip():
            raise ValueError("task contract verification method is required")
        if (
            not self.verifier_kinds
            or len(set(self.verifier_kinds)) != len(self.verifier_kinds)
            or not set(self.verifier_kinds).issubset(
                {"deterministic", "configured", "human", "external"}
            )
        ):
            raise ValueError("task contract verifier kinds are invalid")
        if self.approval_state != "pending":
            raise ValueError("task outcomes must remain pending graph verification")


@dataclass(frozen=True)
class ImprovementTask:
    task_id: str
    gap_id: str
    requirement_id: str
    action_kind: str
    opportunity_weight_bp: int
    reuse_value_bp: int
    cost_units: int
    priority_score: int
    verification: ResultingEvidenceContract


@dataclass(frozen=True)
class OptimisationPlan:
    gaps: tuple[Gap, ...]
    tasks: tuple[ImprovementTask, ...]
    blocks_candidacy: bool
    policy_sha256: str


@dataclass(frozen=True)
class TaskEvidence:
    task_id: str
    proof_class: str
    verification_method: str
    verifier_kind: str
    artifact_sha256: str | None
    external_outcome_id: str | None = None
    generated_text: str | None = None


@dataclass(frozen=True)
class PendingEvidencePromotion:
    task_id: str
    proof_class: str
    artifact_sha256: str
    verification_method: str
    verifier_kind: str
    external_outcome_id: str | None
    approval_state: str = "pending"

    def __post_init__(self) -> None:
        if self.approval_state != "pending":
            raise ValueError("improvement output cannot approve candidate evidence")


@dataclass(frozen=True)
class FitAssessmentReceipt:
    run_id: str
    status: str
    document_hash: str
    lifecycle_receipt_id: int | None


def _hash(parts: object) -> str:
    return hashlib.sha256(canonical_json(parts).encode("utf-8")).hexdigest()


def gap_policy_hash(templates: Mapping[str, TaskTemplate] = DEFAULT_TEMPLATES) -> str:
    return _hash({
        kind: {
            "action_kind": template.action_kind,
            "verification_method": template.verification_method,
            "resulting_proof_class": template.resulting_proof_class,
            "verifier_kinds": template.verifier_kinds,
            "cost_units": template.cost_units,
            "reuse_value_bp": template.reuse_value_bp,
        }
        for kind, template in sorted(templates.items())
    })


def optimise_gaps(
    requirements: Iterable[Requirement],
    results: Iterable[MatchResult],
    *,
    templates: Mapping[str, TaskTemplate] = DEFAULT_TEMPLATES,
) -> OptimisationPlan:
    """Classify every non-match and rank only policy-bridgeable work."""
    requirement_rows = tuple(requirements)
    result_rows = tuple(results)
    by_result = {row.requirement_id: row for row in result_rows}
    if len(by_result) != len(result_rows):
        raise ValueError("match results must be unique by requirement")
    if set(by_result) != {row.requirement_id for row in requirement_rows}:
        raise ValueError("requirements and match results must align exactly")
    gaps: list[Gap] = []
    tasks: list[ImprovementTask] = []
    for requirement in requirement_rows:
        result = by_result[requirement.requirement_id]
        if result.decision == "matched":
            continue
        blocking = (
            requirement.essential
            and (
                requirement.gap_kind == "structural"
                or requirement.bridge_policy in {"fatal", "unbridgeable"}
            )
        )
        status = "unknown" if result.decision == "abstain" else "confirmed"
        gap_id = (
            f"gap-{_hash((
                requirement.requirement_id,
                result.decision,
                result.policy_sha256,
            ))}"
        )
        gaps.append(Gap(
            gap_id,
            requirement.requirement_id,
            requirement.gap_kind,
            status,
            blocking,
            result.reason,
        ))
        if blocking:
            continue
        template = templates.get(requirement.gap_kind)
        if template is None:
            raise ValueError(f"no bridge template for {requirement.gap_kind}")
        if (
            template.cost_units < 1
            or not 1 <= template.reuse_value_bp <= 10_000
            or not template.action_kind.strip()
        ):
            raise ValueError("task template cost and value must be positive")
        priority = (
            requirement.opportunity_weight_bp
            * template.reuse_value_bp
            // (template.cost_units * 10_000)
        )
        contract = ResultingEvidenceContract(
            template.resulting_proof_class,
            template.verification_method,
            template.verifier_kinds,
        )
        tasks.append(ImprovementTask(
            f"task-{_hash((gap_id, template.action_kind, gap_policy_hash(templates)))}",
            gap_id,
            requirement.requirement_id,
            template.action_kind,
            requirement.opportunity_weight_bp,
            template.reuse_value_bp,
            template.cost_units,
            priority,
            contract,
        ))
    tasks.sort(key=lambda task: (-task.priority_score, task.cost_units, task.task_id))
    return OptimisationPlan(
        tuple(gaps),
        tuple(tasks),
        any(gap.blocking for gap in gaps),
        gap_policy_hash(templates),
    )


def validate_task_evidence(
    task: ImprovementTask,
    evidence: TaskEvidence,
) -> PendingEvidencePromotion:
    """Validate an outcome contract without ever approving candidate evidence."""
    if evidence.task_id != task.task_id:
        raise ValueError("task evidence identity mismatch")
    contract = task.verification
    if evidence.generated_text:
        raise ValueError("generated learning text cannot become evidence")
    if evidence.proof_class != contract.proof_class:
        raise ValueError("resulting proof class does not satisfy the task contract")
    if evidence.verification_method != contract.verification_method:
        raise ValueError("verification method does not satisfy the task contract")
    if evidence.verifier_kind not in contract.verifier_kinds:
        raise ValueError("verifier kind does not satisfy the task contract")
    if (
        evidence.artifact_sha256 is None
        or not HEX_64.fullmatch(evidence.artifact_sha256)
    ):
        raise ValueError("a content-addressed test, artefact or outcome receipt is required")
    if (
        contract.proof_class in {"external_outcome", "credential"}
        and (
            evidence.external_outcome_id is None
            or not evidence.external_outcome_id.strip()
        )
    ):
        raise ValueError("external evidence requires an issuer or outcome identity")
    return PendingEvidencePromotion(
        evidence.task_id,
        evidence.proof_class,
        str(evidence.artifact_sha256),
        evidence.verification_method,
        evidence.verifier_kind,
        evidence.external_outcome_id,
    )


def _requirement_document(requirement: Requirement) -> dict[str, object]:
    return {
        "requirement_id": requirement.requirement_id,
        "criterion": requirement.criterion,
        "text": requirement.text,
        "essential": requirement.essential,
        "gap_kind": requirement.gap_kind,
        "bridge_policy": requirement.bridge_policy,
        "accepted_proof_classes": requirement.accepted_proof_classes,
        "opportunity_weight_bp": requirement.opportunity_weight_bp,
        "source_identity": requirement.source_identity,
        "source_span": requirement.source_span,
    }


def _result_document(result: MatchResult) -> dict[str, object]:
    receipt = result.receipt
    return {
        "requirement_id": result.requirement_id,
        "decision": result.decision,
        "evidence_ids": result.evidence_ids,
        "confidence_bp": result.confidence_bp,
        "reason": result.reason,
        "policy_sha256": result.policy_sha256,
        "proposal_sha256": result.proposal_sha256,
        "receipt": None if receipt is None else {
            "provider": receipt.provider,
            "model": receipt.model,
            "prompt_sha256": receipt.prompt_sha256,
            "policy_sha256": receipt.policy_sha256,
            "candidate_profile_sha256": receipt.candidate_profile_sha256,
            "input_sha256": receipt.input_sha256,
        },
    }


def _plan_document(plan: OptimisationPlan) -> dict[str, object]:
    return {
        "blocks_candidacy": plan.blocks_candidacy,
        "policy_sha256": plan.policy_sha256,
        "gaps": [vars(gap) for gap in plan.gaps],
        "tasks": [{
            **{
                key: value
                for key, value in vars(task).items()
                if key != "verification"
            },
            "verification": vars(task.verification),
        } for task in plan.tasks],
    }


def _vacancy_text(payload_json: str) -> str:
    payload = json.loads(payload_json)
    if not isinstance(payload, Mapping):
        raise ValueError("job payload must be an object")
    for key in ("body", "description", "text", "content", "requirements"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    raise ValueError("job payload has no source text for atomic requirements")


class FitAssessmentStore:
    """Atomic persistence and lifecycle integration for production JAA-05."""

    POLICY_ID = "career.fit-assessment"
    POLICY_VERSION = "1"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        apply_jaa_05_migrations(self.path)
        self.lifecycle = LifecycleReducer(self.path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def assess(
        self,
        *,
        job_key: str,
        requirements: Iterable[Requirement],
        proposals: Iterable[MatchProposal],
        as_of: date,
        matching_policy: MatchingPolicy = MatchingPolicy(),
    ) -> FitAssessmentReceipt:
        """Match the canonical graph, optimise gaps and commit one exact run."""
        requirement_rows = tuple(requirements)
        if not requirement_rows:
            raise ValueError("fit assessment requires atomic requirements")
        batch = match_candidate_graph(
            requirement_rows,
            proposals,
            self.path,
            as_of=as_of,
            policy=matching_policy,
        )
        plan = optimise_gaps(requirement_rows, batch.results)
        return self._record(job_key, requirement_rows, batch, plan)

    def _record(
        self,
        job_key: str,
        requirements: tuple[Requirement, ...],
        batch: CandidateMatchBatch,
        plan: OptimisationPlan,
    ) -> FitAssessmentReceipt:
        requirement_ids = [row.requirement_id for row in requirements]
        if len(set(requirement_ids)) != len(requirement_ids):
            raise ValueError("fit assessment requirement IDs must be unique")
        if {row.requirement_id for row in batch.results} != set(requirement_ids):
            raise ValueError("fit assessment results do not cover every requirement")
        expected_plan = optimise_gaps(requirements, batch.results)
        if plan != expected_plan:
            raise ValueError("fit assessment plan is not the deterministic policy result")
        requirement_document = [_requirement_document(row) for row in requirements]
        result_document = [_result_document(row) for row in batch.results]
        plan_document = _plan_document(plan)
        status = (
            "blocked"
            if plan.blocks_candidacy
            else "gap_identified"
            if plan.gaps
            else "ready"
        )
        requirements_hash = content_hash(requirement_document)
        results_hash = content_hash(result_document)
        plan_hash = content_hash(plan_document)
        document = {
            "schema_version": "jaa05.fit-assessment-run.v1",
            "job_key": job_key,
            "as_of": batch.as_of.isoformat(),
            "status": status,
            "requirements_hash": requirements_hash,
            "candidate_profile_hash": batch.candidate_profile_sha256,
            "match_policy_hash": batch.policy_sha256,
            "gap_policy_hash": plan.policy_sha256,
            "results_hash": results_hash,
            "plan_hash": plan_hash,
            "requirements": requirement_document,
            "results": result_document,
            "plan": plan_document,
        }
        document_json = canonical_json(document)
        document_hash = hashlib.sha256(document_json.encode("utf-8")).hexdigest()
        run_id = content_hash({
            "contract": "jaa05.fit-assessment-run.v1",
            "document_hash": document_hash,
        })
        policy_hash = content_hash({
            "policy_id": self.POLICY_ID,
            "version": self.POLICY_VERSION,
            "match_policy_hash": batch.policy_sha256,
            "gap_policy_hash": plan.policy_sha256,
        })
        transition_target = (
            PipelineState.CANDIDATE_REJECTED
            if status == "blocked"
            else PipelineState.GAP_IDENTIFIED
            if status == "gap_identified"
            else None
        )
        lifecycle_inputs = {
            "run_id": run_id,
            "requirements_hash": requirements_hash,
            "candidate_profile_hash": batch.candidate_profile_sha256,
        }
        lifecycle_outputs = {
            "status": status,
            "results_hash": results_hash,
            "plan_hash": plan_hash,
        }
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            job = connection.execute(
                "SELECT state,payload_json,payload_hash FROM pipeline_jobs WHERE job_key=?",
                (job_key,),
            ).fetchone()
            if job is None:
                raise KeyError(job_key)
            source_text = _vacancy_text(str(job["payload_json"]))
            expected_source = f"vacancy:{job_key}:{job['payload_hash']}"
            for requirement in requirements:
                start, end = requirement.source_span
                if (
                    requirement.source_identity != expected_source
                    or end > len(source_text)
                    or source_text[start:end] != requirement.text
                ):
                    raise ValueError(
                        "atomic requirement does not resolve to the exact vacancy payload"
                    )
            existing = connection.execute(
                "SELECT document_json FROM fit_assessment_runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            conflicting = connection.execute(
                """SELECT run_id FROM fit_assessment_runs
                   WHERE job_key=? AND as_of=? AND requirements_hash=?
                     AND candidate_profile_hash=? AND match_policy_hash=?
                     AND gap_policy_hash=? AND run_id<>?""",
                (
                    job_key, batch.as_of.isoformat(), requirements_hash,
                    batch.candidate_profile_sha256, batch.policy_sha256,
                    plan.policy_sha256, run_id,
                ),
            ).fetchone()
            if conflicting is not None:
                raise ValueError(
                    "fit assessment inputs already have a different durable result"
                )
            if existing is not None:
                if str(existing["document_json"]) != document_json:
                    raise ValueError("fit assessment run identity conflicts with stored bytes")
            else:
                if str(job["state"]) not in {
                    PipelineState.FIT_ASSESSED.value,
                    PipelineState.FIT_REASSESSED.value,
                }:
                    raise ValueError(
                        "fit assessment requires a fit assessment lifecycle boundary"
                    )
                connection.execute(
                    """INSERT INTO fit_assessment_runs(
                         run_id,job_key,as_of,status,requirements_hash,candidate_profile_hash,
                         match_policy_hash,gap_policy_hash,results_hash,plan_hash,
                         document_json,document_hash)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        run_id, job_key, batch.as_of.isoformat(), status,
                        requirements_hash,
                        batch.candidate_profile_sha256, batch.policy_sha256,
                        plan.policy_sha256, results_hash, plan_hash,
                        document_json, document_hash,
                    ),
                )
                for requirement in requirements:
                    connection.execute(
                        """INSERT INTO vacancy_requirements(
                             run_id,requirement_id,criterion,requirement_text,essential,
                             gap_kind,bridge_policy,accepted_proof_classes_json,
                             opportunity_weight_bp,source_identity,source_start,source_end)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            run_id, requirement.requirement_id, requirement.criterion,
                            requirement.text, int(requirement.essential),
                            requirement.gap_kind, requirement.bridge_policy,
                            canonical_json(requirement.accepted_proof_classes),
                            requirement.opportunity_weight_bp,
                            requirement.source_identity,
                            requirement.source_span[0], requirement.source_span[1],
                        ),
                    )
                assessment_ids: dict[str, str] = {}
                for result in batch.results:
                    receipt = result.receipt
                    assessment_id = content_hash({
                        "run_id": run_id,
                        "result": _result_document(result),
                    })
                    assessment_ids[result.requirement_id] = assessment_id
                    connection.execute(
                        """INSERT INTO evidence_match_assessments(
                             assessment_id,run_id,requirement_id,decision,
                             evidence_ids_json,confidence_bp,reason,policy_hash,
                             proposal_hash,provider,model,prompt_hash,input_hash)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            assessment_id, run_id, result.requirement_id,
                            result.decision, canonical_json(result.evidence_ids),
                            result.confidence_bp, result.reason,
                            result.policy_sha256, result.proposal_sha256,
                            receipt.provider if receipt else None,
                            receipt.model if receipt else None,
                            receipt.prompt_sha256 if receipt else None,
                            receipt.input_sha256 if receipt else None,
                        ),
                    )
                for gap in plan.gaps:
                    connection.execute(
                        """INSERT INTO candidate_gaps(
                             gap_id,run_id,requirement_id,match_assessment_id,
                             gap_kind,status,blocking,reason)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (
                            gap.gap_id, run_id, gap.requirement_id,
                            assessment_ids[gap.requirement_id], gap.kind,
                            gap.status, int(gap.blocking), gap.reason,
                        ),
                    )
                for task in plan.tasks:
                    connection.execute(
                        """INSERT INTO improvement_tasks(
                             task_id,run_id,gap_id,requirement_id,action_kind,
                             opportunity_weight_bp,reuse_value_bp,cost_units,
                             priority_score,verification_json)
                           VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (
                            task.task_id, run_id, task.gap_id,
                            task.requirement_id, task.action_kind,
                            task.opportunity_weight_bp, task.reuse_value_bp,
                            task.cost_units, task.priority_score,
                            canonical_json(vars(task.verification)),
                        ),
                    )
            lifecycle_receipt_id = None
            if transition_target is not None:
                # Exact run replay intentionally re-enters the certified JAA-01
                # idempotency gate.  It verifies every binding field before
                # returning the original immutable receipt.
                transition = self.lifecycle.commit_in_transaction(
                    connection,
                    job_key=job_key,
                    to_state=transition_target,
                    policy=PolicyIdentity(
                        self.POLICY_ID,
                        self.POLICY_VERSION,
                        policy_hash,
                    ),
                    inputs=lifecycle_inputs,
                    outputs=lifecycle_outputs,
                    idempotency_key=f"fit-assessment:{job_key}:{run_id}",
                )
                lifecycle_receipt_id = transition.receipt_id
            connection.commit()
            return FitAssessmentReceipt(
                run_id, status, document_hash, lifecycle_receipt_id
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_task_evidence(
        self,
        run_id: str,
        evidence: TaskEvidence,
    ) -> PendingEvidencePromotion:
        """Persist a content-addressed candidate; JAA-02 approval remains separate."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM improvement_tasks WHERE run_id=? AND task_id=?",
                (run_id, evidence.task_id),
            ).fetchone()
            if row is None:
                raise KeyError(evidence.task_id)
            verification = json.loads(str(row["verification_json"]))
            task = ImprovementTask(
                task_id=str(row["task_id"]),
                gap_id=str(row["gap_id"]),
                requirement_id=str(row["requirement_id"]),
                action_kind=str(row["action_kind"]),
                opportunity_weight_bp=int(row["opportunity_weight_bp"]),
                reuse_value_bp=int(row["reuse_value_bp"]),
                cost_units=int(row["cost_units"]),
                priority_score=int(row["priority_score"]),
                verification=ResultingEvidenceContract(
                    proof_class=str(verification["proof_class"]),
                    verification_method=str(verification["verification_method"]),
                    verifier_kinds=tuple(verification["verifier_kinds"]),
                    approval_state=str(verification["approval_state"]),
                ),
            )
            promotion = validate_task_evidence(task, evidence)
            promotion_id = content_hash({
                "run_id": run_id,
                "task_id": promotion.task_id,
                "proof_class": promotion.proof_class,
                "artifact_sha256": promotion.artifact_sha256,
                "verification_method": promotion.verification_method,
                "verifier_kind": promotion.verifier_kind,
                "external_outcome_id": promotion.external_outcome_id,
            })
            expected = (
                promotion_id, run_id, promotion.task_id,
                promotion.proof_class, promotion.artifact_sha256,
                promotion.verification_method, promotion.verifier_kind,
                promotion.external_outcome_id, "pending",
            )
            existing = connection.execute(
                """SELECT promotion_id,run_id,task_id,proof_class,
                          artifact_sha256,verification_method,verifier_kind,
                          external_outcome_id,approval_state
                   FROM improvement_evidence_candidates
                   WHERE run_id=? AND task_id=? AND artifact_sha256=?""",
                (run_id, promotion.task_id, promotion.artifact_sha256),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != expected:
                    raise ValueError(
                        "task and artifact already have different verification evidence"
                    )
            else:
                connection.execute(
                    """INSERT INTO improvement_evidence_candidates(
                         promotion_id,run_id,task_id,proof_class,artifact_sha256,
                         verification_method,verifier_kind,external_outcome_id,
                         approval_state)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    expected,
                )
            connection.commit()
            return promotion
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
