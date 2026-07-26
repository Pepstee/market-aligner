"""Independent acceptance tests for the bounded offline JAA-05 contract."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from career_automation.evidence_matching import (
    Evidence,
    InferenceReceipt,
    MatchProposal,
    MatchResult,
    MatchingPolicy,
    Requirement,
    candidate_graph_evidence,
    evidence_projection_hash,
    match_candidate_graph,
    match_requirements,
    matching_input_hash,
    score_locked_labels,
)
from career_automation.candidate_graph import CandidateGraph
from career_automation.gap_optimizer import (
    TaskEvidence,
    optimise_gaps,
    validate_task_evidence,
)


AS_OF = date(2030, 1, 1)
POLICY = MatchingPolicy()
ROOT = Path(__file__).resolve().parent
HASHES = {
    name: hashlib.sha256(name.encode("utf-8")).hexdigest()
    for name in ("prompt", "profile", "input", "artifact")
}
BRIDGES = {
    "presentation": "present",
    "retrieval": "retrieve",
    "knowledge": "learn_and_test",
    "execution": "execute_and_verify",
    "evidence": "build_evidence",
    "experience": "gain_experience",
    "credential": "earn_credential",
    "structural": "fatal",
}
PROOFS = {
    "presentation": ("verified_claim",),
    "retrieval": ("work_artifact",),
    "knowledge": ("test_result",),
    "execution": ("work_artifact",),
    "evidence": ("portfolio_artifact",),
    "experience": ("employment_record", "external_outcome"),
    "credential": ("credential",),
    "structural": ("verified_claim",),
}


def _requirement(
    requirement_id: str,
    *,
    criterion: str = "python-delivery",
    kind: str = "evidence",
    essential: bool = True,
    weight: int = 8000,
) -> Requirement:
    return Requirement(
        requirement_id=requirement_id,
        criterion=criterion,
        text=f"Atomic requirement {requirement_id}.",
        essential=essential,
        gap_kind=kind,
        bridge_policy=BRIDGES[kind],
        accepted_proof_classes=PROOFS[kind],
        opportunity_weight_bp=weight,
        source_identity="vacancy:locked",
        source_span=(10, 20),
    )


def _receipt(
    requirement: Requirement,
    evidence: tuple[Evidence, ...],
) -> InferenceReceipt:
    profile_sha256 = evidence_projection_hash(evidence)
    return InferenceReceipt(
        provider="locked-review",
        model="reviewed-labels-v1",
        prompt_sha256=HASHES["prompt"],
        policy_sha256=POLICY.policy_hash,
        candidate_profile_sha256=profile_sha256,
        input_sha256=matching_input_hash(
            requirement,
            candidate_profile_sha256=profile_sha256,
        ),
    )


def _proposal(
    requirement: Requirement,
    evidence: tuple[Evidence, ...],
    evidence_ids: tuple[str, ...] = (),
    *,
    confidence: int = 9000,
    basis: str | None = None,
) -> MatchProposal:
    return MatchProposal(
        requirement.requirement_id,
        evidence_ids,
        confidence,
        basis or ("direct" if evidence_ids else "none"),
        "Locked independent reviewer decision.",
        _receipt(requirement, evidence),
    )


def _evidence(
    evidence_id: str,
    *,
    criterion: str = "python-delivery",
    proof: str = "portfolio_artifact",
    approval: str = "approved",
    epistemic: str = "evidence",
    verification: str = "approved",
    valid_until: date | None = date(2035, 1, 1),
    negative: bool = False,
) -> Evidence:
    statement = f"Content-addressed proof {evidence_id}."
    return Evidence(
        evidence_id=evidence_id,
        version=1,
        statement=statement,
        demonstrates=(criterion,),
        proof_class=proof,
        approval_state=approval,
        epistemic_state=epistemic,
        verification_decision=verification,
        verification_method="independent-artifact-review",
        content_sha256=hashlib.sha256(statement.encode("utf-8")).hexdigest(),
        valid_until=valid_until,
        negative=negative,
    )


def test_atomic_matching_requires_current_approved_compatible_evidence() -> None:
    requirement = _requirement("essential-python")
    evidence = _evidence("python-receipt")
    result, = match_requirements(
        (requirement,),
        (_proposal(requirement, (evidence,), (evidence.evidence_id,)),),
        (evidence,),
        as_of=AS_OF,
        policy=POLICY,
    )
    assert result.decision == "matched"
    assert result.evidence_ids == ("python-receipt",)
    assert result.policy_sha256 == POLICY.policy_hash
    assert result.proposal_sha256 is not None


def test_production_match_projection_is_derived_from_approved_jaa02_graph(
    tmp_path: Path,
) -> None:
    graph = CandidateGraph(tmp_path / "candidate.sqlite3")
    statement = "A content-addressed portfolio artefact proves API delivery."
    graph.add_evidence(
        "api-artifact",
        statement=statement,
        source_identity="test:artifact",
        state="evidence",
        evidence_kind="portfolio_artifact",
        valid_until="2035-01-01",
    )
    graph.verify_evidence(
        "api-artifact",
        1,
        decision="approved",
        verifier_kind="deterministic",
        policy_id="artifact-review",
        policy_version="1",
        policy_hash=HASHES["artifact"],
        reason="content hash and test receipt verified",
        source_identity="test:verifier",
    )
    graph.add_claim(
        "public-api-delivery",
        statement="Delivered and tested a public API.",
        claim_type="achievement",
        state="evidence",
        source_identity="test:claim",
        valid_until="2035-01-01",
    )
    graph.link_claim_evidence(
        "public-api-delivery",
        "api-artifact",
        source_identity="test:edge",
        edge_type="demonstrated_by",
    )
    graph.approve_claim("public-api-delivery")
    evidence = candidate_graph_evidence(graph.path, as_of=AS_OF)
    assert len(evidence) == 1
    assert evidence[0].demonstrates == ("public-api-delivery",)
    assert evidence[0].proof_class == "portfolio_artifact"
    requirement = _requirement(
        "api-requirement",
        criterion="public-api-delivery",
        kind="evidence",
    )
    proposal = _proposal(
        requirement,
        evidence,
        ("api-artifact",),
    )
    result, = match_candidate_graph(
        (requirement,),
        (proposal,),
        graph.path,
        as_of=AS_OF,
    )
    assert result.decision == "matched"


def test_low_confidence_and_missing_proposals_abstain_instead_of_guessing() -> None:
    requirements = (
        _requirement("uncertain"),
        _requirement("unreviewed", essential=False),
    )
    evidence = _evidence("proof")
    results = match_requirements(
        requirements,
        (_proposal(requirements[0], (evidence,), ("proof",), confidence=7000),),
        (evidence,),
        as_of=AS_OF,
    )
    assert [result.decision for result in results] == ["abstain", "abstain"]
    assert "confidence" in results[0].reason
    assert "no match proposal" in results[1].reason


def test_locked_label_metrics_measure_precision_recall_and_abstention() -> None:
    results = (
        MatchResult("matched", "matched", ("proof",), 9000, "direct", POLICY.policy_hash, HASHES["input"]),
        MatchResult("absent", "no_match", (), 9000, "none", POLICY.policy_hash, HASHES["input"]),
        MatchResult("uncertain", "abstain", (), 6000, "uncertain", POLICY.policy_hash, HASHES["input"]),
    )
    metrics = score_locked_labels(
        results,
        {"matched": "matched", "absent": "no_match", "uncertain": "abstain"},
    )
    assert metrics == {
        "precision_bp": 10_000,
        "recall_bp": 10_000,
        "abstention_precision_bp": 10_000,
        "abstention_recall_bp": 10_000,
        "exact_accuracy_bp": 10_000,
        "examples": 3,
    }
    with pytest.raises(ValueError, match="undefined"):
        score_locked_labels(
            (MatchResult("absent", "no_match", (), 9000, "none", POLICY.policy_hash, None),),
            {"absent": "no_match"},
        )


def test_all_gap_classes_are_explicit_and_structural_gap_blocks_candidacy() -> None:
    requirements = tuple(
        _requirement(
            f"requirement-{kind}",
            kind=kind,
            essential=kind == "structural",
            weight=9000 if kind == "retrieval" else 6000,
        )
        for kind in BRIDGES
    )
    results = tuple(
        MatchResult(
            requirement.requirement_id,
            "no_match",
            (),
            9000,
            "locked absence",
            POLICY.policy_hash,
            HASHES["input"],
        )
        for requirement in requirements
    )
    plan = optimise_gaps(requirements, results)
    assert {gap.kind for gap in plan.gaps} == set(BRIDGES)
    assert plan.blocks_candidacy
    assert len(plan.tasks) == 7
    assert all(task.requirement_id != "requirement-structural" for task in plan.tasks)
    assert plan.tasks[0].requirement_id == "requirement-presentation"
    assert [task.priority_score for task in plan.tasks] == sorted(
        (task.priority_score for task in plan.tasks),
        reverse=True,
    )
    assert len(plan.policy_sha256) == 64


def test_improvement_task_requires_a_verifiable_artifact_and_stays_pending() -> None:
    requirement = _requirement("knowledge", kind="knowledge", essential=False)
    result = MatchResult(
        "knowledge", "no_match", (), 9000, "knowledge not demonstrated",
        POLICY.policy_hash, HASHES["input"],
    )
    task, = optimise_gaps((requirement,), (result,)).tasks
    promotion = validate_task_evidence(
        task,
        TaskEvidence(
            task.task_id,
            task.verification.proof_class,
            task.verification.verification_method,
            "deterministic",
            HASHES["artifact"],
        ),
    )
    assert promotion.approval_state == "pending"
    assert promotion.artifact_sha256 == HASHES["artifact"]


def test_requirement_contract_rejects_non_atomic_or_inconsistent_policy() -> None:
    with pytest.raises(ValueError, match="source span"):
        Requirement(
            "bad", "criterion", "Bad requirement.", True, "knowledge",
            "learn_and_test", ("test_result",), 5000, "vacancy", (1, 1),
        )
    with pytest.raises(ValueError, match="inconsistent"):
        Requirement(
            "bad", "criterion", "Bad requirement.", True, "experience",
            "learn_and_test", ("external_outcome",), 5000, "vacancy", (1, 2),
        )


def test_synthetic_locked_evaluation_is_explicitly_not_slice_certification() -> None:
    completed = subprocess.run(
        (sys.executable, "scripts/evaluate_jaa05_locked_labels.py"),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["status"] == "SOFTWARE_CONTRACT_PASS"
    assert result["certifies_slice"] is False
    assert result["dependency_gate"] == "JAA-04"
    assert result["metrics"] == {
        "precision_bp": 10_000,
        "recall_bp": 10_000,
        "abstention_precision_bp": 10_000,
        "abstention_recall_bp": 10_000,
        "exact_accuracy_bp": 10_000,
        "examples": 8,
    }
