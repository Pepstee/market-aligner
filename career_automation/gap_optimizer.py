"""Deterministic JAA-05 gap classification and improvement-task ranking."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from .evidence_matching import PROOF_CLASSES, MatchResult, Requirement, canonical_json


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
        gap_id = f"gap-{_hash((requirement.requirement_id, result.decision, result.policy_sha256))[:24]}"
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
            f"task-{_hash((gap_id, template.action_kind, gap_policy_hash(templates)))[:24]}",
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
