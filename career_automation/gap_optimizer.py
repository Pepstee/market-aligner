"""Deterministic JAA-05 gap classification and improvement-task ranking."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Iterable, Mapping

from .evidence_matching import (
    EVIDENCE_KIND_PROOF_CLASS,
    PROOF_CLASSES,
    CandidateMatchBatch,
    MatchProposal,
    MatchResult,
    MatchingPolicy,
    Requirement,
    candidate_graph_evidence,
    canonical_json,
    content_hash,
    evidence_projection_hash,
    match_candidate_graph,
    match_requirements,
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
    executor_identity: str
    external_outcome_id: str | None = None
    generated_text: str | None = None

    def __post_init__(self) -> None:
        if not self.executor_identity.strip():
            raise ValueError("task executor identity is required")


@dataclass(frozen=True)
class PendingEvidencePromotion:
    task_id: str
    proof_class: str
    artifact_sha256: str
    verification_method: str
    verifier_kind: str
    external_outcome_id: str | None
    approval_state: str = "pending"
    promotion_id: str | None = None

    def __post_init__(self) -> None:
        if self.approval_state != "pending":
            raise ValueError("improvement output cannot approve candidate evidence")


@dataclass(frozen=True)
class FitAssessmentReceipt:
    run_id: str
    status: str
    document_hash: str
    lifecycle_receipt_id: int | None


@dataclass(frozen=True)
class TaskActivationReceipt:
    activation_id: str
    run_id: str
    task_id: str
    job_key: str
    target_state: str
    executor_identity: str
    lifecycle_receipt_id: int


@dataclass(frozen=True)
class GapVerificationReceipt:
    verification_id: str
    run_id: str
    task_id: str
    promotion_id: str
    evidence_id: str
    evidence_version: int
    claim_id: str
    claim_version: int
    artefact_id: str
    artefact_version: int
    verified_as_of: date
    lifecycle_receipt_id: int


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
    GAP_EVIDENCE_POLICY_ID = "career.gap-evidence-verification"
    GAP_EVIDENCE_POLICY_VERSION = "1"
    ACTIVATION_POLICY_ID = "career.improvement-task-activation"
    ACTIVATION_POLICY_VERSION = "1"
    GAP_VERIFICATION_POLICY_ID = "career.gap-verification"
    GAP_VERIFICATION_POLICY_VERSION = "1"
    REASSESSMENT_POLICY_ID = "career.fit-reassessment"
    REASSESSMENT_POLICY_VERSION = "1"
    ACTION_STATES = {
        "present_verified_evidence": PipelineState.GAP_RECOVERY,
        "retrieve_existing_evidence": PipelineState.GAP_RECOVERY,
        "learn_and_test": PipelineState.LEARNING,
        "earn_credential": PipelineState.LEARNING,
        "execute_and_verify": PipelineState.EVIDENCE_BUILDING,
        "build_evidence": PipelineState.EVIDENCE_BUILDING,
        "gain_real_experience": PipelineState.EVIDENCE_BUILDING,
    }

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

    def reassess(
        self,
        *,
        predecessor_run_id: str,
        requirements: Iterable[Requirement],
        proposals: Iterable[MatchProposal],
        as_of: date,
        matching_policy: MatchingPolicy = MatchingPolicy(),
    ) -> FitAssessmentReceipt:
        """Create one fresh fit run after an exact verified-gap predecessor."""
        requirement_rows = tuple(requirements)
        if not requirement_rows:
            raise ValueError("fit reassessment requires atomic requirements")
        with self._connect() as connection:
            predecessor = connection.execute(
                """SELECT run.job_key,verification.evidence_id,
                          verification.evidence_version
                   FROM fit_assessment_runs run
                   JOIN improvement_task_activations activation
                     ON activation.run_id=run.run_id
                   JOIN gap_verification_receipts verification
                     ON verification.activation_id=activation.activation_id
                   WHERE run.run_id=?""",
                (predecessor_run_id,),
            ).fetchone()
        if predecessor is None:
            raise ValueError("fit reassessment requires a verified predecessor run")
        job_key = str(predecessor["job_key"])
        evidence = candidate_graph_evidence(self.path, as_of=as_of)
        if (
            str(predecessor["evidence_id"]),
            int(predecessor["evidence_version"]),
        ) not in {
            (row.evidence_id, row.version)
            for row in evidence
        }:
            raise ValueError(
                "verified gap evidence is not current in the reassessment profile"
            )
        results = match_requirements(
            requirement_rows,
            proposals,
            evidence,
            as_of=as_of,
            policy=matching_policy,
        )
        batch = CandidateMatchBatch(
            results,
            evidence_projection_hash(evidence),
            matching_policy.policy_hash,
            as_of,
        )
        plan = optimise_gaps(requirement_rows, batch.results)
        return self._record(
            job_key,
            requirement_rows,
            batch,
            plan,
            predecessor_run_id=predecessor_run_id,
        )

    def _record(
        self,
        job_key: str,
        requirements: tuple[Requirement, ...],
        batch: CandidateMatchBatch,
        plan: OptimisationPlan,
        *,
        predecessor_run_id: str | None = None,
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
            "schema_version": (
                "jaa05.fit-assessment-run.v2"
                if predecessor_run_id is not None
                else "jaa05.fit-assessment-run.v1"
            ),
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
        if predecessor_run_id is not None:
            document["predecessor_run_id"] = predecessor_run_id
        document_json = canonical_json(document)
        document_hash = hashlib.sha256(document_json.encode("utf-8")).hexdigest()
        run_id = content_hash({
            "contract": str(document["schema_version"]),
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
            predecessor = None
            if predecessor_run_id is not None:
                predecessor = connection.execute(
                    """SELECT prior.*,verification.verification_id,
                              verification.verified_as_of
                       FROM fit_assessment_runs prior
                       JOIN improvement_task_activations activation
                         ON activation.run_id=prior.run_id
                       JOIN gap_verification_receipts verification
                         ON verification.activation_id=activation.activation_id
                       WHERE prior.run_id=? AND prior.job_key=?""",
                    (predecessor_run_id, job_key),
                ).fetchone()
                if predecessor is None:
                    raise ValueError(
                        "fit reassessment requires a verified predecessor run"
                    )
                if (
                    str(predecessor["status"]) != "gap_identified"
                    or requirements_hash != str(predecessor["requirements_hash"])
                    or batch.candidate_profile_sha256
                    == str(predecessor["candidate_profile_hash"])
                    or batch.as_of
                    <= date.fromisoformat(str(predecessor["as_of"]))
                    or batch.as_of
                    <= date.fromisoformat(str(predecessor["verified_as_of"]))
                ):
                    raise ValueError(
                        "fit reassessment must advance the exact verified predecessor"
                    )
            existing = connection.execute(
                """SELECT document_json,predecessor_run_id
                   FROM fit_assessment_runs WHERE run_id=?""",
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
            conflicting_successor = (
                connection.execute(
                    """SELECT run_id FROM fit_assessment_runs
                       WHERE predecessor_run_id=? AND run_id<>?""",
                    (predecessor_run_id, run_id),
                ).fetchone()
                if predecessor_run_id is not None
                else None
            )
            if conflicting_successor is not None:
                raise ValueError(
                    "verified predecessor already has a different fit reassessment"
                )
            reassessment_receipt_id = None
            if existing is not None:
                if (
                    str(existing["document_json"]) != document_json
                    or existing["predecessor_run_id"] != predecessor_run_id
                ):
                    raise ValueError("fit assessment run identity conflicts with stored bytes")
            else:
                required_state = (
                    PipelineState.GAP_VERIFIED
                    if predecessor_run_id is not None
                    else PipelineState.FIT_ASSESSED
                )
                if str(job["state"]) != required_state.value:
                    raise ValueError(
                        "fit assessment requires a fit assessment lifecycle boundary"
                    )
                if predecessor is not None:
                    reassessment_policy_hash = content_hash({
                        "policy_id": self.REASSESSMENT_POLICY_ID,
                        "version": self.REASSESSMENT_POLICY_VERSION,
                        "predecessor_run_id": predecessor_run_id,
                        "verification_id": str(predecessor["verification_id"]),
                    })
                    reassessment_transition = self.lifecycle.commit_in_transaction(
                        connection,
                        job_key=job_key,
                        to_state=PipelineState.FIT_REASSESSED,
                        policy=PolicyIdentity(
                            self.REASSESSMENT_POLICY_ID,
                            self.REASSESSMENT_POLICY_VERSION,
                            reassessment_policy_hash,
                        ),
                        inputs={
                            "predecessor_run_id": predecessor_run_id,
                            "verification_id": str(predecessor["verification_id"]),
                            "successor_run_id": run_id,
                            "requirements_hash": requirements_hash,
                            "candidate_profile_hash": batch.candidate_profile_sha256,
                            "as_of": batch.as_of.isoformat(),
                        },
                        outputs={"state": PipelineState.FIT_REASSESSED.value},
                        idempotency_key=(
                            f"fit-reassessment:{job_key}:{predecessor_run_id}"
                        ),
                    )
                    reassessment_receipt_id = reassessment_transition.receipt_id
                connection.execute(
                    """INSERT INTO fit_assessment_runs(
                         run_id,job_key,as_of,status,requirements_hash,candidate_profile_hash,
                         match_policy_hash,gap_policy_hash,results_hash,plan_hash,
                         document_json,document_hash,predecessor_run_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        run_id, job_key, batch.as_of.isoformat(), status,
                        requirements_hash,
                        batch.candidate_profile_sha256, batch.policy_sha256,
                        plan.policy_sha256, results_hash, plan_hash,
                        document_json, document_hash, predecessor_run_id,
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
            lifecycle_receipt_id = reassessment_receipt_id
            if predecessor is not None and existing is not None:
                reassessment_policy_hash = content_hash({
                    "policy_id": self.REASSESSMENT_POLICY_ID,
                    "version": self.REASSESSMENT_POLICY_VERSION,
                    "predecessor_run_id": predecessor_run_id,
                    "verification_id": str(predecessor["verification_id"]),
                })
                reassessment_transition = self.lifecycle.commit_in_transaction(
                    connection,
                    job_key=job_key,
                    to_state=PipelineState.FIT_REASSESSED,
                    policy=PolicyIdentity(
                        self.REASSESSMENT_POLICY_ID,
                        self.REASSESSMENT_POLICY_VERSION,
                        reassessment_policy_hash,
                    ),
                    inputs={
                        "predecessor_run_id": predecessor_run_id,
                        "verification_id": str(predecessor["verification_id"]),
                        "successor_run_id": run_id,
                        "requirements_hash": requirements_hash,
                        "candidate_profile_hash": batch.candidate_profile_sha256,
                        "as_of": batch.as_of.isoformat(),
                    },
                    outputs={"state": PipelineState.FIT_REASSESSED.value},
                    idempotency_key=(
                        f"fit-reassessment:{job_key}:{predecessor_run_id}"
                    ),
                )
                lifecycle_receipt_id = reassessment_transition.receipt_id
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

    def activate_task(
        self,
        run_id: str,
        task_id: str,
        *,
        executor_identity: str,
    ) -> TaskActivationReceipt:
        """Activate only the deterministic highest-priority task in one run."""
        if not executor_identity.strip():
            raise ValueError("task executor identity is required")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT task.*,run.job_key,run.status,job.state AS job_state
                   FROM improvement_tasks task
                   JOIN fit_assessment_runs run ON run.run_id=task.run_id
                   JOIN pipeline_jobs job ON job.job_key=run.job_key
                   WHERE task.run_id=? AND task.task_id=?""",
                (run_id, task_id),
            ).fetchone()
            if row is None:
                raise KeyError((run_id, task_id))
            highest = connection.execute(
                """SELECT task_id FROM improvement_tasks
                   WHERE run_id=?
                   ORDER BY priority_score DESC,cost_units,task_id LIMIT 1""",
                (run_id,),
            ).fetchone()
            if highest is None or str(highest["task_id"]) != task_id:
                raise ValueError("only the highest-priority task may be activated")
            target = self.ACTION_STATES.get(str(row["action_kind"]))
            if target is None:
                raise ValueError("task action has no recovery lifecycle mapping")
            policy_hash = content_hash({
                "policy_id": self.ACTIVATION_POLICY_ID,
                "version": self.ACTIVATION_POLICY_VERSION,
                "action_states": {
                    action: state.value
                    for action, state in sorted(self.ACTION_STATES.items())
                },
                "selection": "priority_score DESC,cost_units,task_id",
            })
            activation_id = content_hash({
                "run_id": run_id,
                "task_id": task_id,
                "job_key": str(row["job_key"]),
                "target_state": target.value,
                "executor_identity": executor_identity,
                "policy_hash": policy_hash,
            })
            existing = connection.execute(
                "SELECT * FROM improvement_task_activations WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if existing is not None:
                expected = (
                    activation_id, run_id, task_id, str(row["job_key"]),
                    target.value, executor_identity, policy_hash,
                )
                actual = tuple(existing[key] for key in (
                    "activation_id", "run_id", "task_id", "job_key",
                    "target_state", "executor_identity", "policy_hash",
                ))
                if actual != expected:
                    raise ValueError("fit run already activated a different task")
            else:
                if (
                    str(row["status"]) != "gap_identified"
                    or str(row["job_state"]) != PipelineState.GAP_IDENTIFIED.value
                ):
                    raise ValueError("task activation requires gap_identified state")
                connection.execute(
                    """INSERT INTO improvement_task_activations(
                         activation_id,run_id,task_id,job_key,target_state,
                         executor_identity,policy_hash)
                       VALUES(?,?,?,?,?,?,?)""",
                    (
                        activation_id, run_id, task_id, str(row["job_key"]),
                        target.value, executor_identity, policy_hash,
                    ),
                )
            transition = self.lifecycle.commit_in_transaction(
                connection,
                job_key=str(row["job_key"]),
                to_state=target,
                policy=PolicyIdentity(
                    self.ACTIVATION_POLICY_ID,
                    self.ACTIVATION_POLICY_VERSION,
                    policy_hash,
                ),
                inputs={
                    "run_id": run_id,
                    "task_id": task_id,
                    "executor_identity": executor_identity,
                },
                outputs={"target_state": target.value},
                idempotency_key=f"task-activation:{row['job_key']}:{run_id}",
            )
            connection.commit()
            return TaskActivationReceipt(
                activation_id, run_id, task_id, str(row["job_key"]),
                target.value, executor_identity, transition.receipt_id,
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
                """SELECT task.*,activation.executor_identity,
                          activation.target_state,run.job_key,
                          job.state AS job_state
                   FROM improvement_tasks task
                   JOIN improvement_task_activations activation
                     ON activation.run_id=task.run_id
                    AND activation.task_id=task.task_id
                   JOIN fit_assessment_runs run ON run.run_id=task.run_id
                   JOIN pipeline_jobs job ON job.job_key=run.job_key
                   WHERE task.run_id=? AND task.task_id=?""",
                (run_id, evidence.task_id),
            ).fetchone()
            if row is None:
                raise ValueError("task evidence requires an active task")
            if (
                evidence.executor_identity != str(row["executor_identity"])
                or str(row["job_state"]) != str(row["target_state"])
            ):
                raise ValueError("task evidence does not match the active executor and state")
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
                "executor_identity": evidence.executor_identity,
            })
            expected = (
                promotion_id, run_id, promotion.task_id,
                promotion.proof_class, promotion.artifact_sha256,
                promotion.verification_method, promotion.verifier_kind,
                promotion.external_outcome_id, "pending",
                evidence.executor_identity,
            )
            existing = connection.execute(
                """SELECT promotion_id,run_id,task_id,proof_class,
                          artifact_sha256,verification_method,verifier_kind,
                          external_outcome_id,approval_state,executor_identity
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
                         approval_state,executor_identity)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    expected,
                )
            connection.commit()
            return replace(promotion, promotion_id=promotion_id)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def verify_gap(
        self,
        *,
        run_id: str,
        task_id: str,
        promotion_id: str,
        evidence_id: str,
        evidence_version: int,
        claim_id: str,
        claim_version: int,
        artefact_id: str,
        artefact_version: int,
        verification_decision_id: str,
        as_of: date,
    ) -> GapVerificationReceipt:
        """Advance only an exact independently approved JAA-02 graph binding."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT activation.activation_id,activation.executor_identity,
                          activation.target_state,activation.job_key,
                          run.as_of AS assessment_as_of,
                          task.verification_json,task.requirement_id,
                          requirement.criterion,
                          promotion.proof_class AS promotion_proof_class,
                          promotion.artifact_sha256,
                          promotion.executor_identity AS promotion_executor,
                          evidence.evidence_kind,evidence.source_identity,
                          evidence.epistemic_state,evidence.approval_state,
                          evidence.negative,evidence.valid_until,
                          claim.epistemic_state AS claim_epistemic_state,
                          claim.approval_state AS claim_approval_state,
                          claim.valid_until AS claim_valid_until,
                          claim_provenance.source_identity AS claim_source_identity,
                          artefact.content_hash AS artefact_hash,
                          artefact.source_identity AS artefact_source_identity,
                          decision.decision,decision.verifier_kind,
                          decision.policy_id,decision.policy_version,
                          verifier.source_identity AS verifier_identity,
                          job.state AS job_state
                   FROM improvement_task_activations activation
                   JOIN improvement_tasks task
                     ON task.run_id=activation.run_id
                    AND task.task_id=activation.task_id
                   JOIN fit_assessment_runs run
                     ON run.run_id=task.run_id
                   JOIN vacancy_requirements requirement
                     ON requirement.run_id=task.run_id
                    AND requirement.requirement_id=task.requirement_id
                   JOIN improvement_evidence_candidates promotion
                     ON promotion.run_id=task.run_id
                    AND promotion.task_id=task.task_id
                    AND promotion.promotion_id=?
                   JOIN candidate_evidence evidence
                     ON evidence.evidence_id=? AND evidence.version=?
                   JOIN candidate_claims claim
                     ON claim.claim_id=? AND claim.version=?
                   JOIN candidate_provenance claim_provenance
                     ON claim_provenance.provenance_id=claim.provenance_id
                   JOIN candidate_artefacts artefact
                     ON artefact.artefact_id=? AND artefact.version=?
                   JOIN candidate_verification_decisions decision
                     ON decision.decision_id=?
                    AND decision.target_kind='evidence'
                    AND decision.target_id=evidence.evidence_id
                    AND decision.target_version=evidence.version
                   JOIN candidate_provenance verifier
                     ON verifier.provenance_id=decision.provenance_id
                   JOIN pipeline_jobs job ON job.job_key=activation.job_key
                   WHERE activation.run_id=? AND activation.task_id=?""",
                (
                    promotion_id, evidence_id, evidence_version,
                    claim_id, claim_version, artefact_id, artefact_version,
                    verification_decision_id, run_id, task_id,
                ),
            ).fetchone()
            if row is None:
                raise ValueError("gap verification identities do not resolve")
            existing_gap_verification = connection.execute(
                """SELECT verification_id,activation_id,promotion_id,
                          evidence_id,evidence_version,claim_id,claim_version,
                          artefact_id,artefact_version,verification_decision_id,
                          verifier_identity,verified_as_of,policy_hash
                   FROM gap_verification_receipts WHERE activation_id=?""",
                (str(row["activation_id"]),),
            ).fetchone()
            contract = json.loads(str(row["verification_json"]))
            promotion_source = f"jaa05:promotion:{promotion_id}"
            proof_class = EVIDENCE_KIND_PROOF_CLASS.get(str(row["evidence_kind"]))
            if (
                (
                    str(row["job_state"]) != str(row["target_state"])
                    and not (
                        existing_gap_verification is not None
                        and str(row["job_state"]) == PipelineState.GAP_VERIFIED.value
                    )
                )
                or as_of < date.fromisoformat(str(row["assessment_as_of"]))
                or str(row["promotion_executor"]) != str(row["executor_identity"])
                or str(row["criterion"]) != claim_id
                or str(row["promotion_proof_class"]) != str(contract["proof_class"])
                or proof_class != str(contract["proof_class"])
                or str(row["artifact_sha256"]) != str(row["artefact_hash"])
                or str(row["source_identity"]) != promotion_source
                or str(row["claim_source_identity"]) != promotion_source
                or str(row["artefact_source_identity"]) != promotion_source
                or row["approval_state"] != "approved"
                or row["epistemic_state"] not in {"fact", "evidence"}
                or bool(row["negative"])
                or row["claim_approval_state"] != "approved"
                or row["claim_epistemic_state"] not in {"fact", "evidence"}
                or row["decision"] != "approved"
                or row["policy_id"] != self.GAP_EVIDENCE_POLICY_ID
                or row["policy_version"] != self.GAP_EVIDENCE_POLICY_VERSION
                or row["verifier_kind"] not in set(contract["verifier_kinds"])
                or str(row["verifier_identity"]) == str(row["executor_identity"])
                or (
                    row["valid_until"] is not None
                    and date.fromisoformat(str(row["valid_until"])) < as_of
                )
                or (
                    row["claim_valid_until"] is not None
                    and date.fromisoformat(str(row["claim_valid_until"])) < as_of
                )
            ):
                raise ValueError("JAA-02 graph approval does not satisfy the task contract")
            evidence_edge = connection.execute(
                """SELECT 1 FROM candidate_claim_edges
                   WHERE claim_id=? AND claim_version=?
                     AND evidence_id=? AND evidence_version=?
                     AND edge_type IN ('supports','demonstrated_by')""",
                (claim_id, claim_version, evidence_id, evidence_version),
            ).fetchone()
            artefact_edge = connection.execute(
                """SELECT 1 FROM candidate_claim_edges
                   WHERE claim_id=? AND claim_version=?
                     AND artefact_id=? AND artefact_version=?
                     AND edge_type IN ('demonstrated_by','documented_in')""",
                (claim_id, claim_version, artefact_id, artefact_version),
            ).fetchone()
            decision_count = int(connection.execute(
                """SELECT COUNT(*) FROM candidate_verification_decisions
                   WHERE target_kind='evidence' AND target_id=?
                     AND target_version=? AND decision='approved'""",
                (evidence_id, evidence_version),
            ).fetchone()[0])
            newer_evidence = connection.execute(
                """SELECT 1 FROM candidate_evidence
                   WHERE evidence_id=? AND version>?""",
                (evidence_id, evidence_version),
            ).fetchone()
            newer_claim = connection.execute(
                """SELECT 1 FROM candidate_claims
                   WHERE claim_id=? AND version>?""",
                (claim_id, claim_version),
            ).fetchone()
            newer_artefact = connection.execute(
                """SELECT 1 FROM candidate_artefacts
                   WHERE artefact_id=? AND version>?""",
                (artefact_id, artefact_version),
            ).fetchone()
            if (
                evidence_edge is None
                or artefact_edge is None
                or decision_count != 1
                or newer_evidence is not None
                or newer_claim is not None
                or newer_artefact is not None
            ):
                raise ValueError("JAA-02 graph approval binding is incomplete or ambiguous")
            policy_hash = content_hash({
                "policy_id": self.GAP_VERIFICATION_POLICY_ID,
                "version": self.GAP_VERIFICATION_POLICY_VERSION,
                "requirements": [
                    "active highest-priority task",
                    "exact pending promotion artifact",
                    "one independent JAA-02 evidence approval",
                    "approved criterion claim with evidence and artefact edges",
                ],
            })
            verification_id = content_hash({
                "activation_id": str(row["activation_id"]),
                "promotion_id": promotion_id,
                "evidence": (evidence_id, evidence_version),
                "claim": (claim_id, claim_version),
                "artefact": (artefact_id, artefact_version),
                "verification_decision_id": verification_decision_id,
                "verifier_identity": str(row["verifier_identity"]),
                "verified_as_of": as_of.isoformat(),
                "policy_hash": policy_hash,
            })
            expected = (
                verification_id, str(row["activation_id"]), promotion_id,
                evidence_id, evidence_version, claim_id, claim_version,
                artefact_id, artefact_version, verification_decision_id,
                str(row["verifier_identity"]), as_of.isoformat(), policy_hash,
            )
            existing = existing_gap_verification
            if existing is not None:
                if tuple(existing) != expected:
                    raise ValueError("active task already has different gap verification")
            else:
                connection.execute(
                    """INSERT INTO gap_verification_receipts(
                         verification_id,activation_id,promotion_id,
                         evidence_id,evidence_version,claim_id,claim_version,
                         artefact_id,artefact_version,verification_decision_id,
                         verifier_identity,verified_as_of,policy_hash)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    expected,
                )
            transition = self.lifecycle.commit_in_transaction(
                connection,
                job_key=str(row["job_key"]),
                to_state=PipelineState.GAP_VERIFIED,
                policy=PolicyIdentity(
                    self.GAP_VERIFICATION_POLICY_ID,
                    self.GAP_VERIFICATION_POLICY_VERSION,
                    policy_hash,
                ),
                inputs={
                    "run_id": run_id,
                    "task_id": task_id,
                    "promotion_id": promotion_id,
                    "artifact_sha256": str(row["artifact_sha256"]),
                    "evidence": (evidence_id, evidence_version),
                    "claim": (claim_id, claim_version),
                    "artefact": (artefact_id, artefact_version),
                    "verification_decision_id": verification_decision_id,
                    "verifier_identity": str(row["verifier_identity"]),
                    "verified_as_of": as_of.isoformat(),
                },
                outputs={
                    "proof_class": proof_class,
                    "approval_state": "approved",
                },
                idempotency_key=f"gap-verified:{row['job_key']}:{run_id}:{task_id}",
            )
            connection.commit()
            return GapVerificationReceipt(
                verification_id, run_id, task_id, promotion_id,
                evidence_id, evidence_version, claim_id, claim_version,
                artefact_id, artefact_version, as_of, transition.receipt_id,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
