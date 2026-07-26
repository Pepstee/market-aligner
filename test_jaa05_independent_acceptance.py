"""Independent acceptance tests for the bounded offline JAA-05 contract."""

from __future__ import annotations

import hashlib
import json
import sqlite3
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
from career_automation.database import CareerDatabase
from career_automation.gap_optimizer import (
    FitAssessmentStore,
    TaskEvidence,
    optimise_gaps,
    validate_task_evidence,
)
from career_automation.lifecycle import PolicyIdentity, canonical_hash
from career_automation.migrations import (
    JAA_05_MIGRATIONS,
    apply_jaa_05_migrations,
    verify_jaa05_installed_schema,
)
from career_automation.models import PipelineState, ScoredJob


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
    *,
    as_of: date = AS_OF,
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
            as_of=as_of,
        ),
    )


def _proposal(
    requirement: Requirement,
    evidence: tuple[Evidence, ...],
    evidence_ids: tuple[str, ...] = (),
    *,
    confidence: int = 9000,
    basis: str | None = None,
    as_of: date = AS_OF,
) -> MatchProposal:
    return MatchProposal(
        requirement.requirement_id,
        evidence_ids,
        confidence,
        basis or ("direct" if evidence_ids else "none"),
        "Locked independent reviewer decision.",
        _receipt(requirement, evidence, as_of=as_of),
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


def _job_at_fit(path: Path, job_key: str, body: str) -> CareerDatabase:
    database = CareerDatabase(path)
    payload = {"body": body}
    database.upsert_scored_job(ScoredJob(
        key=job_key,
        board="synthetic",
        job_id=job_key,
        url=f"https://example.test/jobs/{job_key}",
        title="Synthetic role",
        company="Synthetic employer",
        fit=None,
        opportunity=0.9,
        final_score=None,
        extraction_confidence=1.0,
        payload=payload,
        payload_hash=canonical_hash(payload),
    ))
    policy = PolicyIdentity("test.fit-prerequisite", "1", HASHES["artifact"])
    for target in (
        PipelineState.EMPLOYER_RESEARCH_QUEUED,
        PipelineState.EMPLOYER_RESEARCHING,
        PipelineState.EMPLOYER_RESEARCHED,
        PipelineState.OPPORTUNITY_1_ASSESSED,
        PipelineState.FIT_ASSESSED,
    ):
        database.lifecycle.commit(
            job_key=job_key,
            to_state=target,
            policy=policy,
            inputs={"target": target.value},
            outputs={"advanced": True},
            idempotency_key=f"test-prerequisite:{job_key}:{target.value}",
        )
    return database


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


def test_jaa05_migration_is_forward_only_and_schema_verified(tmp_path: Path) -> None:
    path = tmp_path / "migration.sqlite3"
    assert apply_jaa_05_migrations(path) == tuple(
        migration.version for migration in JAA_05_MIGRATIONS
    )
    assert apply_jaa_05_migrations(path) == ()
    with sqlite3.connect(path) as connection:
        assert verify_jaa05_installed_schema(connection)
        tables = {
            row[0] for row in connection.execute(
                """SELECT name FROM sqlite_schema
                   WHERE type='table' AND name IN (
                     'fit_assessment_runs','vacancy_requirements',
                     'evidence_match_assessments','candidate_gaps',
                     'improvement_tasks','improvement_evidence_candidates',
                     'improvement_task_activations','gap_verification_receipts'
                   )"""
            )
        }
    assert len(tables) == 8


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
    batch = match_candidate_graph(
        (requirement,),
        (proposal,),
        graph.path,
        as_of=AS_OF,
    )
    result, = batch.results
    assert result.decision == "matched"
    assert batch.candidate_profile_sha256 == evidence_projection_hash(evidence)


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
        MatchResult("matched", "matched", ("proof",), 9000, "direct", POLICY.policy_hash, None),
        MatchResult("absent", "no_match", (), 9000, "none", POLICY.policy_hash, None),
        MatchResult("uncertain", "abstain", (), 6000, "uncertain", POLICY.policy_hash, None),
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
            None,
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
        POLICY.policy_hash, None,
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
            "test:executor",
        ),
    )
    assert promotion.approval_state == "pending"
    assert promotion.artifact_sha256 == HASHES["artifact"]


def test_fit_assessment_persists_gaps_tasks_and_lifecycle_atomically(
    tmp_path: Path,
) -> None:
    text = "Demonstrate systems knowledge."
    database = _job_at_fit(tmp_path / "fit.sqlite3", "gap-job", text)
    with database.connect() as connection:
        payload_hash = str(connection.execute(
            "SELECT payload_hash FROM pipeline_jobs WHERE job_key='gap-job'"
        ).fetchone()[0])
    requirement = Requirement(
        "systems-knowledge", "systems-knowledge", text, False,
        "knowledge", "learn_and_test", ("test_result",), 8000,
        f"vacancy:gap-job:{payload_hash}", (0, len(text)),
    )
    proposal = _proposal(requirement, ())
    store = FitAssessmentStore(database.path)
    receipt = store.assess(
        job_key="gap-job",
        requirements=(requirement,),
        proposals=(proposal,),
        as_of=AS_OF,
    )
    assert receipt.status == "gap_identified"
    assert receipt.lifecycle_receipt_id is not None
    assert store.assess(
        job_key="gap-job",
        requirements=(requirement,),
        proposals=(proposal,),
        as_of=AS_OF,
    ) == receipt
    with store._connect() as connection:
        assert connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key='gap-job'"
        ).fetchone()[0] == "gap_identified"
        assert connection.execute(
            "SELECT COUNT(*) FROM vacancy_requirements"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM evidence_match_assessments"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM candidate_gaps"
        ).fetchone()[0] == 1
        task_id = str(connection.execute(
            "SELECT task_id FROM improvement_tasks"
        ).fetchone()[0])
    task_evidence = TaskEvidence(
        task_id,
        "test_result",
        "locked-assessment-pass",
        "deterministic",
        HASHES["artifact"],
        "test:executor",
    )
    activation = store.activate_task(
        receipt.run_id,
        task_id,
        executor_identity="test:executor",
    )
    assert activation.target_state == "learning"
    promotion = store.record_task_evidence(receipt.run_id, task_evidence)
    assert promotion.approval_state == "pending"
    assert promotion.promotion_id is not None
    assert store.record_task_evidence(receipt.run_id, task_evidence) == promotion
    with store._connect() as connection:
        assert connection.execute(
            "SELECT approval_state FROM improvement_evidence_candidates"
        ).fetchone()[0] == "pending"
    graph = CandidateGraph(database.path)
    source_identity = f"jaa05:promotion:{promotion.promotion_id}"
    graph.add_artefact(
        "systems-test-artifact",
        artefact_type="test_result",
        source_identity=source_identity,
        content_hash=HASHES["artifact"],
    )
    graph.add_evidence(
        "systems-test-evidence",
        statement="The locked systems assessment passed.",
        source_identity=source_identity,
        state="evidence",
        evidence_kind="test_result",
        valid_until="2035-01-01",
    )
    decision_id = graph.verify_evidence(
        "systems-test-evidence", 1, decision="approved",
        verifier_kind="deterministic",
        policy_id=FitAssessmentStore.GAP_EVIDENCE_POLICY_ID,
        policy_version=FitAssessmentStore.GAP_EVIDENCE_POLICY_VERSION,
        policy_hash=HASHES["artifact"],
        reason="independent locked assessment verification",
        source_identity="test:independent-verifier",
    )
    graph.add_claim(
        "systems-knowledge",
        statement="Passed the locked systems assessment.",
        claim_type="capability",
        state="evidence",
        source_identity=source_identity,
        valid_until="2035-01-01",
    )
    graph.link_claim_evidence(
        "systems-knowledge", "systems-test-evidence",
        source_identity=source_identity, edge_type="demonstrated_by",
    )
    graph.link_claim_artefact(
        "systems-knowledge", "systems-test-artifact",
        source_identity=source_identity, edge_type="documented_in",
    )
    graph.approve_claim("systems-knowledge")
    verification_arguments = {
        "run_id": receipt.run_id,
        "task_id": task_id,
        "promotion_id": str(promotion.promotion_id),
        "evidence_id": "systems-test-evidence",
        "evidence_version": 1,
        "claim_id": "systems-knowledge",
        "claim_version": 1,
        "artefact_id": "systems-test-artifact",
        "artefact_version": 1,
        "verification_decision_id": decision_id,
        "as_of": AS_OF,
    }
    verified = store.verify_gap(**verification_arguments)
    assert verified.lifecycle_receipt_id
    assert store.verify_gap(**verification_arguments) == verified
    reassessment_as_of = date(2030, 1, 2)
    current_evidence = candidate_graph_evidence(
        database.path,
        as_of=reassessment_as_of,
    )
    reassessed = store.reassess(
        predecessor_run_id=receipt.run_id,
        requirements=(requirement,),
        proposals=(_proposal(
            requirement,
            current_evidence,
            ("systems-test-evidence",),
            as_of=reassessment_as_of,
        ),),
        as_of=reassessment_as_of,
    )
    assert reassessed.status == "ready"
    assert store.reassess(
        predecessor_run_id=receipt.run_id,
        requirements=(requirement,),
        proposals=(_proposal(
            requirement,
            current_evidence,
            ("systems-test-evidence",),
            as_of=reassessment_as_of,
        ),),
        as_of=reassessment_as_of,
    ) == reassessed
    with store._connect() as connection:
        successor = connection.execute(
            """SELECT predecessor_run_id,as_of,status
               FROM fit_assessment_runs WHERE run_id=?""",
            (reassessed.run_id,),
        ).fetchone()
        assert tuple(successor) == (
            receipt.run_id,
            reassessment_as_of.isoformat(),
            "ready",
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM fit_assessment_runs"
        ).fetchone()[0] == 2
    for table in (
        "fit_assessment_runs",
        "vacancy_requirements",
        "evidence_match_assessments",
        "candidate_gaps",
        "improvement_tasks",
        "improvement_evidence_candidates",
        "improvement_task_activations",
        "gap_verification_receipts",
    ):
        with store._connect() as connection, pytest.raises(
            sqlite3.IntegrityError,
            match="immutable",
        ):
            connection.execute(f"DELETE FROM {table}")
    assert database.lifecycle.replay()["gap-job"] is PipelineState.FIT_REASSESSED


def test_fully_matched_fit_run_stays_at_fit_boundary_for_jaa06(tmp_path: Path) -> None:
    text = "Deliver a public API."
    database = _job_at_fit(tmp_path / "ready.sqlite3", "ready-job", text)
    graph = CandidateGraph(database.path)
    graph.add_evidence(
        "api-artifact",
        statement="Content-addressed API test and artefact.",
        source_identity="test:artifact",
        state="evidence",
        evidence_kind="portfolio_artifact",
        valid_until="2035-01-01",
    )
    graph.verify_evidence(
        "api-artifact", 1, decision="approved",
        verifier_kind="deterministic", policy_id="artifact-review",
        policy_version="1", policy_hash=HASHES["artifact"],
        reason="test and artefact verified", source_identity="test:verifier",
    )
    graph.add_claim(
        "public-api-delivery",
        statement="Delivered a tested public API.",
        claim_type="achievement",
        state="evidence",
        source_identity="test:claim",
        valid_until="2035-01-01",
    )
    graph.link_claim_evidence(
        "public-api-delivery", "api-artifact",
        source_identity="test:edge", edge_type="demonstrated_by",
    )
    graph.approve_claim("public-api-delivery")
    evidence = candidate_graph_evidence(graph.path, as_of=AS_OF)
    with database.connect() as connection:
        payload_hash = str(connection.execute(
            "SELECT payload_hash FROM pipeline_jobs WHERE job_key='ready-job'"
        ).fetchone()[0])
    requirement = Requirement(
        "api", "public-api-delivery", text, False,
        "evidence", "build_evidence", ("portfolio_artifact",), 9000,
        f"vacancy:ready-job:{payload_hash}", (0, len(text)),
    )
    store = FitAssessmentStore(database.path)
    receipt = store.assess(
        job_key="ready-job",
        requirements=(requirement,),
        proposals=(_proposal(requirement, evidence, ("api-artifact",)),),
        as_of=AS_OF,
    )
    assert receipt.status == "ready"
    assert receipt.lifecycle_receipt_id is None
    with store._connect() as connection:
        assert connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key='ready-job'"
        ).fetchone()[0] == "fit_assessed"
        assert connection.execute(
            "SELECT COUNT(*) FROM candidate_gaps"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM improvement_tasks"
        ).fetchone()[0] == 0


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
