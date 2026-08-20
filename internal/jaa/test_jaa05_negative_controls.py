"""Adversarial truth controls for JAA-05 evidence and recovery."""

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
    MatchingPolicy,
    Requirement,
    candidate_graph_evidence,
    content_hash,
    evidence_projection_hash,
    evaluate_match,
    matching_input_hash,
)
from career_automation.candidate_graph import CandidateGraph
from career_automation.database import CareerDatabase
from career_automation.gap_optimizer import (
    DEFAULT_TEMPLATES,
    FitAssessmentStore,
    TaskEvidence,
    TaskTemplate,
    optimise_gaps,
    validate_task_evidence,
)
from career_automation.lifecycle import InvalidTransition, PolicyIdentity, canonical_hash
from career_automation.migrations import apply_jaa_05_migrations
from career_automation.models import PipelineState, ScoredJob


AS_OF = date(2030, 1, 1)
POLICY = MatchingPolicy()
DIGEST = hashlib.sha256(b"negative-control").hexdigest()
ROOT = Path(__file__).resolve().parent
LOCKED = ROOT / "career_automation/fixtures/jaa05_locked_labels.json"
PRODUCTION_EXPERIENCE_REQUIREMENT_IDS = (
    "jaa05-gold-anthropic-5115935008-r04",
    "jaa05-gold-anthropic-5198999008-r04",
    "jaa05-gold-brunswickgroup-8593698002-r01",
    "jaa05-gold-brunswickgroup-8593698002-r02",
    "jaa05-gold-brunswickgroup-8593698002-r04",
    "jaa05-gold-chaosindustries-5162751007-r04",
    "jaa05-gold-graphcore-8466438002-r04",
    "jaa05-gold-graphcore-8630718002-r03",
    "jaa05-gold-graphcore-8630718002-r05",
    "jaa05-gold-graphcore-8632581002-r01",
    "jaa05-gold-jetbrains-4695363101-r01",
    "jaa05-gold-jetbrains-4754978101-r01",
    "jaa05-gold-jetbrains-4754978101-r04",
    "jaa05-gold-jetbrains-4769511101-r01",
    "jaa05-gold-jetbrains-4769511101-r02",
    "jaa05-gold-jetbrains-4769511101-r03",
    "jaa05-gold-jetbrains-4771939101-r01",
    "jaa05-gold-koboldmetals-4678367005-r01",
    "jaa05-gold-monzo-8038447-r01",
    "jaa05-gold-physicsx-4652630101-r04",
)


def _requirement() -> Requirement:
    return Requirement(
        "professional-python",
        "professional-python",
        "Professional Python delivery experience.",
        True,
        "experience",
        "gain_experience",
        ("employment_record", "external_outcome"),
        9000,
        "vacancy:negative-control",
        (0, 40),
    )


def _receipt(
    requirement: Requirement,
    evidence: tuple[Evidence, ...],
    *,
    policy_hash: str | None = None,
    profile_hash: str | None = None,
    input_hash: str | None = None,
    as_of: date = AS_OF,
) -> InferenceReceipt:
    candidate_profile_sha256 = profile_hash or evidence_projection_hash(evidence)
    return InferenceReceipt(
        "locked-review",
        "negative-control-v1",
        DIGEST,
        policy_hash or POLICY.policy_hash,
        candidate_profile_sha256,
        input_hash or matching_input_hash(
            requirement,
            candidate_profile_sha256=candidate_profile_sha256,
            as_of=as_of,
        ),
    )


def _evidence(
    evidence_id: str,
    proof_class: str,
    *,
    approval: str = "approved",
    state: str = "evidence",
    verification: str = "approved",
    valid_until: date | None = date(2035, 1, 1),
    negative: bool = False,
) -> Evidence:
    statement = "Python appears in this self-authored description of a complex project."
    return Evidence(
        evidence_id,
        1,
        statement,
        ("professional-python",),
        proof_class,
        approval,
        state,
        verification,
        "independent-review",
        hashlib.sha256(statement.encode()).hexdigest(),
        valid_until,
        negative,
    )


def _proposal(
    requirement: Requirement,
    evidence: tuple[Evidence, ...],
    evidence_id: str,
    *,
    receipt: InferenceReceipt | None = None,
) -> MatchProposal:
    return MatchProposal(
        "professional-python",
        (evidence_id,),
        9900,
        "direct",
        "The words are semantically similar.",
        receipt or _receipt(requirement, evidence),
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
    policy = PolicyIdentity("test.fit-prerequisite", "1", DIGEST)
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


def _pending_knowledge_gap(
    path: Path,
    *,
    job_key: str,
    executor_identity: str = "test:executor",
) -> tuple[
    CareerDatabase,
    FitAssessmentStore,
    object,
    Requirement,
    str,
    object,
]:
    text = "Demonstrate systems knowledge."
    database = _job_at_fit(path, job_key, text)
    with database.connect() as connection:
        payload_hash = str(connection.execute(
            "SELECT payload_hash FROM pipeline_jobs WHERE job_key=?",
            (job_key,),
        ).fetchone()[0])
    requirement = Requirement(
        f"{job_key}-systems", f"{job_key}-systems", text, False,
        "knowledge", "learn_and_test", ("test_result",), 8000,
        f"vacancy:{job_key}:{payload_hash}", (0, len(text)),
    )
    store = FitAssessmentStore(database.path)
    run = store.assess(
        job_key=job_key,
        requirements=(requirement,),
        proposals=(MatchProposal(
            requirement.requirement_id, (), 9000, "none", "No evidence.",
            _receipt(requirement, ()),
        ),),
        as_of=AS_OF,
    )
    with store._connect() as connection:
        task_id = str(connection.execute(
            "SELECT task_id FROM improvement_tasks WHERE run_id=?",
            (run.run_id,),
        ).fetchone()[0])
    store.activate_task(
        run.run_id,
        task_id,
        executor_identity=executor_identity,
    )
    promotion = store.record_task_evidence(
        run.run_id,
        TaskEvidence(
            task_id, "test_result", "locked-assessment-pass",
            "deterministic", DIGEST, executor_identity,
        ),
    )
    return database, store, run, requirement, task_id, promotion


def _approved_gap_material(
    database: CareerDatabase,
    *,
    promotion_id: str,
    criterion: str,
    verifier_identity: str,
    proof_class: str = "test_result",
    artifact_hash: str = DIGEST,
    valid_until: str = "2035-01-01",
    policy_id: str = FitAssessmentStore.GAP_EVIDENCE_POLICY_ID,
    claim_source_identity: str | None = None,
) -> dict[str, object]:
    graph = CandidateGraph(database.path)
    source_identity = f"jaa05:promotion:{promotion_id}"
    artefact_id = f"artifact-{promotion_id[:12]}"
    evidence_id = f"evidence-{promotion_id[:12]}"
    graph.add_artefact(
        artefact_id,
        artefact_type=proof_class,
        source_identity=source_identity,
        content_hash=artifact_hash,
    )
    graph.add_evidence(
        evidence_id,
        statement=f"Independently reviewed {criterion}.",
        source_identity=source_identity,
        state="evidence",
        evidence_kind=proof_class,
        valid_until=valid_until,
    )
    decision_id = graph.verify_evidence(
        evidence_id, 1, decision="approved",
        verifier_kind="deterministic",
        policy_id=policy_id,
        policy_version=FitAssessmentStore.GAP_EVIDENCE_POLICY_VERSION,
        policy_hash=DIGEST,
        reason="independent gap evidence review",
        source_identity=verifier_identity,
    )
    graph.add_claim(
        criterion,
        statement=f"Verified criterion {criterion}.",
        claim_type="capability",
        state="evidence",
        source_identity=claim_source_identity or source_identity,
        valid_until="2035-01-01",
    )
    graph.link_claim_evidence(
        criterion, evidence_id,
        source_identity=source_identity,
        edge_type="demonstrated_by",
    )
    graph.link_claim_artefact(
        criterion, artefact_id,
        source_identity=source_identity,
        edge_type="documented_in",
    )
    graph.approve_claim(criterion)
    return {
        "evidence_id": evidence_id,
        "evidence_version": 1,
        "claim_id": criterion,
        "claim_version": 1,
        "artefact_id": artefact_id,
        "artefact_version": 1,
        "verification_decision_id": decision_id,
    }


def _verified_knowledge_gap(
    path: Path,
    *,
    job_key: str,
) -> tuple[
    CareerDatabase,
    FitAssessmentStore,
    object,
    Requirement,
    str,
    object,
]:
    database, store, run, requirement, task_id, promotion = (
        _pending_knowledge_gap(path, job_key=job_key)
    )
    identities = _approved_gap_material(
        database,
        promotion_id=str(promotion.promotion_id),
        criterion=requirement.criterion,
        verifier_identity="test:reviewer",
    )
    store.verify_gap(
        run_id=run.run_id,
        task_id=task_id,
        promotion_id=str(promotion.promotion_id),
        as_of=AS_OF,
        **identities,
    )
    return database, store, run, requirement, task_id, promotion


@pytest.mark.parametrize("proof_class", ("verified_claim", "portfolio_artifact", "test_result"))
def test_similarity_interest_or_project_complexity_cannot_become_professional_experience(
    proof_class: str,
) -> None:
    evidence = _evidence("similar-text", proof_class)
    requirement = _requirement()
    result = evaluate_match(
        requirement,
        _proposal(requirement, (evidence,), evidence.evidence_id),
        {evidence.evidence_id: evidence},
        as_of=AS_OF,
    )
    assert result.decision == "no_match"
    assert result.evidence_ids == ()
    assert "proof class" in result.reason


@pytest.mark.parametrize(
    "evidence",
    (
        _evidence("pending", "employment_record", approval="pending"),
        _evidence("inference", "employment_record", state="inference"),
        _evidence("unverified", "employment_record", verification="abstained"),
        _evidence("expired", "employment_record", valid_until=date(2029, 12, 31)),
        _evidence("negative", "employment_record", negative=True),
    ),
)
def test_unapproved_unfactual_stale_or_negative_material_cannot_match(
    evidence: Evidence,
) -> None:
    requirement = _requirement()
    result = evaluate_match(
        requirement,
        _proposal(requirement, (evidence,), evidence.evidence_id),
        {evidence.evidence_id: evidence},
        as_of=AS_OF,
    )
    assert result.decision == "no_match"
    assert result.evidence_ids == ()


def test_unknown_evidence_and_policy_drift_fail_closed() -> None:
    requirement = _requirement()
    evidence = _evidence("valid", "employment_record")
    with pytest.raises(ValueError, match="unknown evidence"):
        evaluate_match(
            requirement,
            _proposal(requirement, (), "forged"),
            {},
            as_of=AS_OF,
        )
    with pytest.raises(ValueError, match="input hash mismatch"):
        evaluate_match(
            requirement,
            _proposal(requirement, (evidence,), "valid"),
            {"valid": evidence},
            as_of=date(2030, 1, 2),
        )
    with pytest.raises(ValueError, match="policy hash mismatch"):
        evaluate_match(
            requirement,
            _proposal(
                requirement,
                (evidence,),
                "valid",
                receipt=_receipt(requirement, (evidence,), policy_hash="0" * 64),
            ),
            {"valid": evidence},
            as_of=AS_OF,
        )


def test_candidate_graph_projection_rejects_caller_self_approval_and_newer_drift(
    tmp_path: Path,
) -> None:
    graph = CandidateGraph(tmp_path / "candidate.sqlite3")
    graph.add_evidence(
        "self-assertion",
        statement="I assert that I have professional Python experience.",
        source_identity="test:self",
        state="evidence",
        evidence_kind="employment_record",
    )
    assert candidate_graph_evidence(graph.path, as_of=AS_OF) == ()
    with sqlite3.connect(graph.path) as connection, pytest.raises(
        sqlite3.IntegrityError,
        match="approved evidence requires verification",
    ):
        connection.execute(
            """UPDATE candidate_evidence SET approval_state='approved'
               WHERE evidence_id='self-assertion'"""
        )
    graph.add_evidence(
        "versioned",
        statement="An externally recorded employment outcome.",
        source_identity="test:employer",
        state="evidence",
        evidence_kind="employment_record",
        valid_until="2035-01-01",
    )
    graph.verify_evidence(
        "versioned",
        1,
        decision="approved",
        verifier_kind="human",
        policy_id="employment-check",
        policy_version="1",
        policy_hash=DIGEST,
        reason="employer record checked",
        source_identity="test:verifier",
    )
    graph.add_claim(
        "professional-python",
        statement="Professional Python delivery is externally evidenced.",
        claim_type="experience",
        state="evidence",
        source_identity="test:claim",
        valid_until="2035-01-01",
    )
    graph.link_claim_evidence(
        "professional-python",
        "versioned",
        source_identity="test:edge",
    )
    graph.approve_claim("professional-python")
    assert [row.evidence_id for row in candidate_graph_evidence(graph.path, as_of=AS_OF)] == [
        "versioned"
    ]
    graph.add_evidence(
        "versioned",
        version=2,
        statement="A newer record is awaiting verification.",
        source_identity="test:employer:new",
        state="evidence",
        evidence_kind="employment_record",
        valid_until="2035-01-01",
    )
    assert candidate_graph_evidence(graph.path, as_of=AS_OF) == ()


def test_candidate_graph_projection_binds_and_supersedes_exact_claim_version(
    tmp_path: Path,
) -> None:
    graph = CandidateGraph(tmp_path / "claim-lineage.sqlite3")
    graph.add_evidence(
        "employment",
        statement="An externally recorded employment outcome.",
        source_identity="test:employer",
        state="evidence",
        evidence_kind="employment_record",
        valid_until="2035-01-01",
    )
    graph.verify_evidence(
        "employment",
        1,
        decision="approved",
        verifier_kind="human",
        policy_id="employment-check",
        policy_version="1",
        policy_hash=DIGEST,
        reason="employer record checked",
        source_identity="test:verifier",
    )
    original_statement = "Professional Python delivery is externally evidenced."
    graph.add_claim(
        "professional-python",
        statement=original_statement,
        claim_type="experience",
        state="evidence",
        source_identity="test:claim",
        valid_until="2035-01-01",
    )
    graph.link_claim_evidence(
        "professional-python",
        "employment",
        source_identity="test:edge",
    )
    graph.approve_claim("professional-python")
    with sqlite3.connect(graph.path) as connection:
        provenance_id, provenance_sha256 = connection.execute(
            """SELECT claim.provenance_id,provenance.source_hash
               FROM candidate_claims claim
               JOIN candidate_provenance provenance
                 ON provenance.provenance_id=claim.provenance_id
               WHERE claim.claim_id='professional-python' AND claim.version=1"""
        ).fetchone()
    projected, = candidate_graph_evidence(graph.path, as_of=AS_OF)
    assert projected.claim_lineage == ((
        "professional-python",
        1,
        content_hash({
            "claim_id": "professional-python",
            "version": 1,
            "statement": original_statement,
            "claim_type": "experience",
            "epistemic_state": "evidence",
            "approval_state": "approved",
            "valid_until": "2035-01-01",
            "provenance_id": provenance_id,
            "provenance_sha256": provenance_sha256,
        }),
    ),)
    assert projected.evidence_provenance is not None

    graph.add_claim(
        "professional-python",
        version=2,
        statement="A replacement claim is awaiting verification.",
        claim_type="experience",
        state="evidence",
        source_identity="test:replacement",
        valid_until="2035-01-01",
    )
    assert candidate_graph_evidence(graph.path, as_of=AS_OF) == ()


def test_candidate_projection_identity_binds_evidence_and_verifier_provenance(
    tmp_path: Path,
) -> None:
    graph = CandidateGraph(tmp_path / "provenance-lineage.sqlite3")
    graph.add_evidence(
        "employment",
        statement="An externally recorded employment outcome.",
        source_identity="test:employer",
        state="evidence",
        evidence_kind="employment_record",
        valid_until="2035-01-01",
    )
    graph.verify_evidence(
        "employment",
        1,
        decision="approved",
        verifier_kind="human",
        policy_id="employment-check",
        policy_version="1",
        policy_hash=DIGEST,
        reason="employer record checked",
        source_identity="test:verifier",
    )
    graph.add_claim(
        "professional-python",
        statement="Professional Python delivery is externally evidenced.",
        claim_type="experience",
        state="evidence",
        source_identity="test:claim",
        valid_until="2035-01-01",
    )
    graph.link_claim_evidence(
        "professional-python",
        "employment",
        source_identity="test:edge",
    )
    graph.approve_claim("professional-python")
    original = candidate_graph_evidence(graph.path, as_of=AS_OF)
    original_hash = evidence_projection_hash(original)

    graph.add_evidence(
        "decoy",
        statement="An externally recorded employment outcome.",
        source_identity="test:different-employer-source",
        state="evidence",
        evidence_kind="employment_record",
    )
    graph.verify_evidence(
        "decoy",
        1,
        decision="approved",
        verifier_kind="human",
        policy_id="employment-check",
        policy_version="1",
        policy_hash=DIGEST,
        reason="employer record checked",
        source_identity="test:different-verifier",
    )
    with sqlite3.connect(graph.path) as connection:
        original_evidence_provenance, decoy_evidence_provenance = (
            str(row[0]) for row in connection.execute(
                """SELECT provenance_id FROM candidate_evidence
                   WHERE evidence_id IN ('employment','decoy')
                   ORDER BY evidence_id DESC"""
            ).fetchall()
        )
        decoy_verifier_provenance = str(connection.execute(
            """SELECT provenance_id FROM candidate_verification_decisions
               WHERE target_kind='evidence' AND target_id='decoy'
                 AND target_version=1 AND decision='approved'"""
        ).fetchone()[0])
        connection.execute(
            """UPDATE candidate_evidence SET provenance_id=?
               WHERE evidence_id='employment' AND version=1""",
            (decoy_evidence_provenance,),
        )

    changed = candidate_graph_evidence(graph.path, as_of=AS_OF)
    assert changed[0].evidence_provenance != original[0].evidence_provenance
    assert evidence_projection_hash(changed) != original_hash

    with sqlite3.connect(graph.path) as connection:
        connection.execute(
            """UPDATE candidate_evidence SET provenance_id=?
               WHERE evidence_id='employment' AND version=1""",
            (original_evidence_provenance,),
        )
        connection.execute(
            """UPDATE candidate_verification_decisions SET provenance_id=?
               WHERE target_kind='evidence' AND target_id='employment'
                 AND target_version=1 AND decision='approved'""",
            (decoy_verifier_provenance,),
        )

    changed = candidate_graph_evidence(graph.path, as_of=AS_OF)
    assert changed[0].verification_method != original[0].verification_method
    assert evidence_projection_hash(changed) != original_hash


def test_candidate_graph_projection_rejects_multiple_approval_authorities(
    tmp_path: Path,
) -> None:
    graph = CandidateGraph(tmp_path / "ambiguous-approval.sqlite3")
    graph.add_evidence(
        "employment",
        statement="An externally recorded employment outcome.",
        source_identity="test:employer",
        state="evidence",
        evidence_kind="employment_record",
        valid_until="2035-01-01",
    )
    graph.verify_evidence(
        "employment",
        1,
        decision="approved",
        verifier_kind="human",
        policy_id="employment-check",
        policy_version="1",
        policy_hash=DIGEST,
        reason="employer record checked",
        source_identity="test:first-verifier",
    )
    graph.add_claim(
        "professional-python",
        statement="Professional Python delivery is externally evidenced.",
        claim_type="experience",
        state="evidence",
        source_identity="test:claim",
        valid_until="2035-01-01",
    )
    graph.link_claim_evidence(
        "professional-python",
        "employment",
        source_identity="test:edge",
    )
    graph.approve_claim("professional-python")
    with sqlite3.connect(graph.path) as connection:
        original = connection.execute(
            """SELECT target_kind,target_id,target_version,decision,
                      verifier_kind,policy_id,policy_version,policy_hash,
                      reason,provenance_id
               FROM candidate_verification_decisions
               WHERE target_kind='evidence' AND target_id='employment'
                 AND target_version=1"""
        ).fetchone()
        connection.execute(
            """INSERT INTO candidate_verification_decisions(
                 decision_id,target_kind,target_id,target_version,decision,
                 verifier_kind,policy_id,policy_version,policy_hash,reason,
                 provenance_id)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            ("test:second-approval", *original),
        )
    with pytest.raises(ValueError, match="ambiguous approval decisions"):
        candidate_graph_evidence(graph.path, as_of=AS_OF)


def test_generated_learning_text_or_self_assertion_cannot_close_a_gap() -> None:
    requirement = Requirement(
        "knowledge",
        "systems-knowledge",
        "Demonstrate systems knowledge.",
        False,
        "knowledge",
        "learn_and_test",
        ("test_result",),
        7000,
        "vacancy:negative-control",
        (0, 30),
    )
    no_match = evaluate_match(
        requirement,
        MatchProposal(
            "knowledge", (), 9000, "none", "No verified evidence.",
            _receipt(requirement, ()),
        ),
        {},
        as_of=AS_OF,
    )
    task, = optimise_gaps((requirement,), (no_match,)).tasks
    base = {
        "task_id": task.task_id,
        "proof_class": "test_result",
        "verification_method": "locked-assessment-pass",
        "verifier_kind": "deterministic",
        "executor_identity": "test:executor",
    }
    with pytest.raises(ValueError, match="generated learning text"):
        validate_task_evidence(
            task,
            TaskEvidence(
                **base,
                artifact_sha256=DIGEST,
                generated_text="I now understand distributed systems.",
            ),
        )
    with pytest.raises(ValueError, match="content-addressed"):
        validate_task_evidence(
            task,
            TaskEvidence(**base, artifact_sha256=None),
        )
    unsafe_templates = dict(DEFAULT_TEMPLATES)
    unsafe_templates["knowledge"] = TaskTemplate(
        "write_learning_text",
        "self-assertion",
        "generated_text",
        ("human",),
        1,
        10_000,
    )
    with pytest.raises(ValueError, match="unsupported proof class"):
        optimise_gaps((requirement,), (no_match,), templates=unsafe_templates)


def test_improvement_task_must_be_capable_of_satisfying_requirement_proof() -> None:
    requirement = Requirement(
        "impossible-knowledge-task",
        "systems-knowledge",
        "Demonstrate systems knowledge.",
        False,
        "knowledge",
        "learn_and_test",
        ("employment_record",),
        7000,
        "vacancy:negative-control",
        (0, 30),
    )
    no_match = evaluate_match(
        requirement,
        MatchProposal(
            requirement.requirement_id,
            (),
            9000,
            "none",
            "No verified evidence.",
            _receipt(requirement, ()),
        ),
        {},
        as_of=AS_OF,
    )
    with pytest.raises(ValueError, match="cannot satisfy"):
        optimise_gaps((requirement,), (no_match,))


def test_all_production_experience_gaps_create_satisfiable_employment_tasks() -> None:
    template = DEFAULT_TEMPLATES["experience"]
    assert template == TaskTemplate(
        "gain_real_experience",
        "employer-attested-record",
        "employment_record",
        ("external", "human"),
        10,
        7000,
    )
    for requirement_id in PRODUCTION_EXPERIENCE_REQUIREMENT_IDS:
        requirement = Requirement(
            requirement_id,
            "professional-experience",
            "Demonstrate the required professional experience.",
            True,
            "experience",
            "gain_experience",
            ("employment_record", "verified_claim"),
            7000,
            "vacancy:production-control",
            (0, 49),
        )
        no_match = evaluate_match(
            requirement,
            MatchProposal(
                requirement_id,
                (),
                9000,
                "none",
                "No approved employment evidence.",
                _receipt(requirement, ()),
            ),
            {},
            as_of=AS_OF,
        )
        task, = optimise_gaps((requirement,), (no_match,)).tasks
        assert task.verification.proof_class in requirement.accepted_proof_classes
        assert task.verification.proof_class == "employment_record"


def test_employer_attested_experience_record_stays_pending_and_rejects_generated_text() -> None:
    requirement = Requirement(
        "experience-contract",
        "professional-experience",
        "Demonstrate the required professional experience.",
        True,
        "experience",
        "gain_experience",
        ("employment_record", "verified_claim"),
        7000,
        "vacancy:production-control",
        (0, 49),
    )
    no_match = evaluate_match(
        requirement,
        MatchProposal(
            requirement.requirement_id,
            (),
            9000,
            "none",
            "No approved employment evidence.",
            _receipt(requirement, ()),
        ),
        {},
        as_of=AS_OF,
    )
    task, = optimise_gaps((requirement,), (no_match,)).tasks
    evidence = TaskEvidence(
        task.task_id,
        "employment_record",
        "employer-attested-record",
        "external",
        DIGEST,
        "test:external-verifier",
    )
    promotion = validate_task_evidence(task, evidence)
    assert promotion.approval_state == "pending"
    assert promotion.proof_class == "employment_record"
    assert promotion.artifact_sha256 == DIGEST
    with pytest.raises(ValueError, match="generated learning text"):
        validate_task_evidence(
            task,
            TaskEvidence(
                task.task_id,
                "employment_record",
                "employer-attested-record",
                "external",
                DIGEST,
                "test:external-verifier",
                generated_text="I gained the required professional experience.",
            ),
        )


def test_external_outcome_experience_template_still_fails_closed() -> None:
    requirement = Requirement(
        "experience-proof-mismatch",
        "professional-experience",
        "Demonstrate the required professional experience.",
        True,
        "experience",
        "gain_experience",
        ("employment_record", "verified_claim"),
        7000,
        "vacancy:negative-control",
        (0, 49),
    )
    no_match = evaluate_match(
        requirement,
        MatchProposal(
            requirement.requirement_id,
            (),
            9000,
            "none",
            "No approved employment evidence.",
            _receipt(requirement, ()),
        ),
        {},
        as_of=AS_OF,
    )
    unsafe_templates = dict(DEFAULT_TEMPLATES)
    unsafe_templates["experience"] = TaskTemplate(
        "gain_real_experience",
        "external-outcome-receipt",
        "external_outcome",
        ("external", "human"),
        10,
        7000,
    )
    with pytest.raises(
        ValueError,
        match="task resulting evidence cannot satisfy the requirement proof contract",
    ):
        optimise_gaps((requirement,), (no_match,), templates=unsafe_templates)


def test_structural_gap_blocks_without_creating_a_task() -> None:
    requirement = Requirement(
        "mandatory-right",
        "mandatory-work-right",
        "Existing unrestricted work authorisation is mandatory.",
        True,
        "structural",
        "fatal",
        ("verified_claim",),
        10_000,
        "vacancy:negative-control",
        (0, 50),
    )
    result = evaluate_match(
        requirement,
        MatchProposal(
            "mandatory-right", (), 9500, "none", "No right exists.",
            _receipt(requirement, ()),
        ),
        {},
        as_of=AS_OF,
    )
    plan = optimise_gaps((requirement,), (result,))
    assert plan.blocks_candidacy
    assert plan.gaps[0].blocking
    assert plan.tasks == ()


def test_persisted_structural_gap_rejects_candidacy_without_a_task(
    tmp_path: Path,
) -> None:
    text = "Existing unrestricted work authorisation is mandatory."
    database = _job_at_fit(tmp_path / "blocked.sqlite3", "blocked-job", text)
    with database.connect() as connection:
        payload_hash = str(connection.execute(
            "SELECT payload_hash FROM pipeline_jobs WHERE job_key='blocked-job'"
        ).fetchone()[0])
    requirement = Requirement(
        "work-right", "existing-work-authorisation", text, True,
        "structural", "fatal", ("verified_claim",), 10_000,
        f"vacancy:blocked-job:{payload_hash}", (0, len(text)),
    )
    proposal = MatchProposal(
        "work-right", (), 9900, "none", "No current right.",
        _receipt(requirement, ()),
    )
    store = FitAssessmentStore(database.path)
    receipt = store.assess(
        job_key="blocked-job",
        requirements=(requirement,),
        proposals=(proposal,),
        as_of=AS_OF,
    )
    assert receipt.status == "blocked"
    with store._connect() as connection:
        assert connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key='blocked-job'"
        ).fetchone()[0] == "candidate_rejected"
        assert connection.execute(
            "SELECT blocking FROM candidate_gaps"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM improvement_tasks"
        ).fetchone()[0] == 0


def test_fit_persistence_rejects_unbound_requirement_and_rolls_back(
    tmp_path: Path,
) -> None:
    text = "Demonstrate systems knowledge."
    database = _job_at_fit(tmp_path / "unbound.sqlite3", "unbound-job", text)
    requirement = Requirement(
        "systems", "systems", text, False,
        "knowledge", "learn_and_test", ("test_result",), 8000,
        f"vacancy:unbound-job:{'0' * 64}", (0, len(text)),
    )
    store = FitAssessmentStore(database.path)
    with pytest.raises(ValueError, match="exact vacancy payload"):
        store.assess(
            job_key="unbound-job",
            requirements=(requirement,),
            proposals=(MatchProposal(
                "systems", (), 9000, "none", "No evidence.",
                _receipt(requirement, ()),
            ),),
            as_of=AS_OF,
        )
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM fit_assessment_runs"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key='unbound-job'"
        ).fetchone()[0] == "fit_assessed"


def test_task_artifact_identity_cannot_hide_conflicting_verification(
    tmp_path: Path,
) -> None:
    text = "Demonstrate systems knowledge."
    database = _job_at_fit(tmp_path / "task-conflict.sqlite3", "task-job", text)
    with database.connect() as connection:
        payload_hash = str(connection.execute(
            "SELECT payload_hash FROM pipeline_jobs WHERE job_key='task-job'"
        ).fetchone()[0])
    requirement = Requirement(
        "systems", "systems", text, False,
        "knowledge", "learn_and_test", ("test_result",), 8000,
        f"vacancy:task-job:{payload_hash}", (0, len(text)),
    )
    store = FitAssessmentStore(database.path)
    run = store.assess(
        job_key="task-job",
        requirements=(requirement,),
        proposals=(MatchProposal(
            "systems", (), 9000, "none", "No evidence.",
            _receipt(requirement, ()),
        ),),
        as_of=AS_OF,
    )
    with store._connect() as connection:
        task_id = str(connection.execute(
            "SELECT task_id FROM improvement_tasks"
        ).fetchone()[0])
    deterministic = TaskEvidence(
        task_id, "test_result", "locked-assessment-pass",
        "deterministic", DIGEST, "test:executor",
    )
    store.activate_task(
        run.run_id,
        task_id,
        executor_identity="test:executor",
    )
    store.record_task_evidence(run.run_id, deterministic)
    with pytest.raises(ValueError, match="different verification evidence"):
        store.record_task_evidence(
            run.run_id,
            TaskEvidence(
                task_id, "test_result", "locked-assessment-pass",
                "human", DIGEST, "test:executor",
            ),
        )
    with store._connect() as connection:
        assert connection.execute(
            "SELECT verifier_kind FROM improvement_evidence_candidates"
        ).fetchone()[0] == "deterministic"


def test_pending_promotion_cannot_verify_a_gap(tmp_path: Path) -> None:
    database, store, run, _requirement_row, task_id, promotion = (
        _pending_knowledge_gap(
            tmp_path / "pending.sqlite3",
            job_key="pending-job",
        )
    )
    with pytest.raises(ValueError, match="identities do not resolve"):
        store.verify_gap(
            run_id=run.run_id,
            task_id=task_id,
            promotion_id=str(promotion.promotion_id),
            evidence_id="not-approved",
            evidence_version=1,
            claim_id="not-approved",
            claim_version=1,
            artefact_id="not-approved",
            artefact_version=1,
            verification_decision_id="not-approved",
            as_of=AS_OF,
        )
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM gap_verification_receipts"
        ).fetchone()[0] == 0
    assert database.lifecycle.replay()["pending-job"] is PipelineState.LEARNING


@pytest.mark.parametrize(
    ("attack", "material"),
    (
        ("self-approval", {"verifier_identity": "test:executor"}),
        (
            "artifact-mismatch",
            {"verifier_identity": "test:reviewer", "artifact_hash": "0" * 64},
        ),
        (
            "wrong-proof",
            {"verifier_identity": "test:reviewer", "proof_class": "work_artifact"},
        ),
        (
            "expired",
            {"verifier_identity": "test:reviewer", "valid_until": "2029-12-31"},
        ),
        (
            "wrong-policy",
            {"verifier_identity": "test:reviewer", "policy_id": "test:wrong-policy"},
        ),
        (
            "wrong-claim-source",
            {
                "verifier_identity": "test:reviewer",
                "claim_source_identity": "test:unbound-claim",
            },
        ),
    ),
)
def test_gap_verification_rejects_non_independent_or_unbound_graph_material(
    tmp_path: Path,
    attack: str,
    material: dict[str, str],
) -> None:
    database, store, run, requirement, task_id, promotion = (
        _pending_knowledge_gap(
            tmp_path / f"{attack}.sqlite3",
            job_key=f"{attack}-job",
        )
    )
    identities = _approved_gap_material(
        database,
        promotion_id=str(promotion.promotion_id),
        criterion=requirement.criterion,
        **material,
    )
    with pytest.raises(ValueError, match="does not satisfy the task contract"):
        store.verify_gap(
            run_id=run.run_id,
            task_id=task_id,
            promotion_id=str(promotion.promotion_id),
            as_of=AS_OF,
            **identities,
        )
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM gap_verification_receipts"
        ).fetchone()[0] == 0
    assert database.lifecycle.replay()[f"{attack}-job"] is PipelineState.LEARNING


@pytest.mark.parametrize("newer_kind", ("claim", "artefact"))
def test_gap_verification_rejects_superseded_claim_or_artefact(
    tmp_path: Path,
    newer_kind: str,
) -> None:
    database, store, run, requirement, task_id, promotion = (
        _pending_knowledge_gap(
            tmp_path / f"newer-{newer_kind}.sqlite3",
            job_key=f"newer-{newer_kind}-job",
        )
    )
    promotion_id = str(promotion.promotion_id)
    identities = _approved_gap_material(
        database,
        promotion_id=promotion_id,
        criterion=requirement.criterion,
        verifier_identity="test:reviewer",
    )
    graph = CandidateGraph(database.path)
    source_identity = f"jaa05:promotion:{promotion_id}:replacement"
    if newer_kind == "claim":
        graph.add_claim(
            requirement.criterion,
            version=2,
            statement="Replacement claim awaits independent approval.",
            claim_type="capability",
            state="evidence",
            source_identity=source_identity,
            valid_until="2035-01-01",
        )
    else:
        graph.add_artefact(
            str(identities["artefact_id"]),
            version=2,
            artefact_type="test_result",
            source_identity=source_identity,
            content_hash=DIGEST,
        )
    with pytest.raises(ValueError, match="binding is incomplete or ambiguous"):
        store.verify_gap(
            run_id=run.run_id,
            task_id=task_id,
            promotion_id=promotion_id,
            as_of=AS_OF,
            **identities,
        )


def test_record_boundary_rejects_generated_text_without_persisting_it(
    tmp_path: Path,
) -> None:
    _database, store, run, _requirement_row, task_id, _promotion = (
        _pending_knowledge_gap(
            tmp_path / "generated.sqlite3",
            job_key="generated-job",
        )
    )
    with pytest.raises(ValueError, match="generated learning text"):
        store.record_task_evidence(
            run.run_id,
            TaskEvidence(
                task_id, "test_result", "locked-assessment-pass",
                "deterministic", hashlib.sha256(b"other").hexdigest(),
                "test:executor", generated_text="Model-authored answer.",
            ),
        )
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM improvement_evidence_candidates"
        ).fetchone()[0] == 1


def test_gap_verification_time_cannot_predate_fit_assessment(
    tmp_path: Path,
) -> None:
    database, store, run, requirement, task_id, promotion = (
        _pending_knowledge_gap(
            tmp_path / "backdated.sqlite3",
            job_key="backdated-job",
        )
    )
    promotion_id = str(promotion.promotion_id)
    identities = _approved_gap_material(
        database,
        promotion_id=promotion_id,
        criterion=requirement.criterion,
        verifier_identity="test:reviewer",
    )
    with pytest.raises(ValueError, match="does not satisfy the task contract"):
        store.verify_gap(
            run_id=run.run_id,
            task_id=task_id,
            promotion_id=promotion_id,
            as_of=date(2029, 12, 31),
            **identities,
        )
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM gap_verification_receipts"
        ).fetchone()[0] == 0


def test_only_one_highest_priority_task_can_activate_per_fit_run(
    tmp_path: Path,
) -> None:
    body = "Demonstrate systems knowledge. Produce a verified portfolio."
    database = _job_at_fit(tmp_path / "priority.sqlite3", "priority-job", body)
    with database.connect() as connection:
        payload_hash = str(connection.execute(
            "SELECT payload_hash FROM pipeline_jobs WHERE job_key='priority-job'"
        ).fetchone()[0])
    requirements = (
        Requirement(
            "knowledge", "systems-knowledge", body[:30], False,
            "knowledge", "learn_and_test", ("test_result",), 9000,
            f"vacancy:priority-job:{payload_hash}", (0, 30),
        ),
        Requirement(
            "evidence", "portfolio", body[31:], False,
            "evidence", "build_evidence", ("portfolio_artifact",), 8000,
            f"vacancy:priority-job:{payload_hash}", (31, len(body)),
        ),
    )
    store = FitAssessmentStore(database.path)
    run = store.assess(
        job_key="priority-job",
        requirements=requirements,
        proposals=tuple(
            MatchProposal(
                requirement.requirement_id, (), 9000, "none", "No evidence.",
                _receipt(requirement, ()),
            )
            for requirement in requirements
        ),
        as_of=AS_OF,
    )
    with store._connect() as connection:
        tasks = connection.execute(
            """SELECT task_id,requirement_id FROM improvement_tasks WHERE run_id=?
               ORDER BY priority_score DESC,cost_units,task_id""",
            (run.run_id,),
        ).fetchall()
    assert len(tasks) == 2
    store.activate_task(
        run.run_id,
        str(tasks[0][0]),
        executor_identity="test:executor",
    )
    with pytest.raises(ValueError, match="highest-priority"):
        store.activate_task(
            run.run_id,
            str(tasks[1][0]),
            executor_identity="test:executor",
        )
    first_task = str(tasks[0][0])
    promotion = store.record_task_evidence(
        run.run_id,
        TaskEvidence(
            first_task, "test_result", "locked-assessment-pass",
            "deterministic", DIGEST, "test:executor",
        ),
    )
    identities = _approved_gap_material(
        database,
        promotion_id=str(promotion.promotion_id),
        criterion=requirements[0].criterion,
        verifier_identity="test:reviewer",
    )
    store.verify_gap(
        run_id=run.run_id,
        task_id=first_task,
        promotion_id=str(promotion.promotion_id),
        as_of=AS_OF,
        **identities,
    )
    reassessment_as_of = date(2030, 1, 2)
    evidence = candidate_graph_evidence(
        database.path,
        as_of=reassessment_as_of,
    )
    proposals = (
        MatchProposal(
            requirements[0].requirement_id,
            (evidence[0].evidence_id,),
            9000,
            "direct",
            "First priority gap is independently verified.",
            _receipt(requirements[0], evidence, as_of=reassessment_as_of),
        ),
        MatchProposal(
            requirements[1].requirement_id,
            (),
            9000,
            "none",
            "Second gap remains.",
            _receipt(requirements[1], evidence, as_of=reassessment_as_of),
        ),
    )
    successor = store.reassess(
        predecessor_run_id=run.run_id,
        requirements=requirements,
        proposals=proposals,
        as_of=reassessment_as_of,
    )
    assert successor.status == "gap_identified"
    with store._connect() as connection:
        remaining = connection.execute(
            """SELECT task_id,requirement_id FROM improvement_tasks
               WHERE run_id=?""",
            (successor.run_id,),
        ).fetchall()
    assert len(remaining) == 1
    assert str(remaining[0]["requirement_id"]) == requirements[1].requirement_id
    store.activate_task(
        successor.run_id,
        str(remaining[0]["task_id"]),
        executor_identity="test:second-executor",
    )
    assert database.lifecycle.replay()["priority-job"] is (
        PipelineState.EVIDENCE_BUILDING
    )


def test_cross_run_task_and_promotion_identities_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cross-run.sqlite3"
    database, store, first_run, _first_requirement, first_task, first_promotion = (
        _pending_knowledge_gap(path, job_key="first-job")
    )
    _database, _second_store, second_run, second_requirement, _second_task, _promotion = (
        _pending_knowledge_gap(path, job_key="second-job")
    )
    with pytest.raises(ValueError, match="active task"):
        store.record_task_evidence(
            second_run.run_id,
            TaskEvidence(
                first_task, "test_result", "locked-assessment-pass",
                "deterministic", DIGEST, "test:executor",
            ),
        )
    identities = _approved_gap_material(
        database,
        promotion_id=str(first_promotion.promotion_id),
        criterion=second_requirement.criterion,
        verifier_identity="test:reviewer",
    )
    with pytest.raises(ValueError, match="identities do not resolve"):
        store.verify_gap(
            run_id=second_run.run_id,
            task_id=first_task,
            promotion_id=str(first_promotion.promotion_id),
            as_of=AS_OF,
            **identities,
        )


def test_lifecycle_cannot_skip_recovery_and_verification_states(
    tmp_path: Path,
) -> None:
    database = _job_at_fit(
        tmp_path / "skip.sqlite3",
        "skip-job",
        "Demonstrate systems knowledge.",
    )
    policy = PolicyIdentity("test:skip", "1", DIGEST)
    database.lifecycle.commit(
        job_key="skip-job",
        to_state=PipelineState.GAP_IDENTIFIED,
        policy=policy,
        inputs={"gap": True},
        outputs={"state": "gap_identified"},
        idempotency_key="test:skip:gap",
    )
    with pytest.raises(InvalidTransition):
        database.lifecycle.commit(
            job_key="skip-job",
            to_state=PipelineState.GAP_VERIFIED,
            policy=policy,
            inputs={"attempt": "skip"},
            outputs={"state": "gap_verified"},
            idempotency_key="test:skip:verified",
        )


def test_verified_gap_exact_replay_rejects_mutated_graph_binding(
    tmp_path: Path,
) -> None:
    database, store, run, requirement, task_id, promotion = (
        _pending_knowledge_gap(
            tmp_path / "mutated-replay.sqlite3",
            job_key="mutated-replay-job",
        )
    )
    promotion_id = str(promotion.promotion_id)
    first = _approved_gap_material(
        database,
        promotion_id=promotion_id,
        criterion=requirement.criterion,
        verifier_identity="test:reviewer",
    )
    arguments = {
        "run_id": run.run_id,
        "task_id": task_id,
        "promotion_id": promotion_id,
        "as_of": AS_OF,
        **first,
    }
    receipt = store.verify_gap(**arguments)
    assert store.verify_gap(**arguments) == receipt

    graph = CandidateGraph(database.path)
    source_identity = f"jaa05:promotion:{promotion_id}"
    graph.add_artefact(
        "alternate-artifact",
        artefact_type="test_result",
        source_identity=source_identity,
        content_hash=DIGEST,
    )
    graph.add_evidence(
        "alternate-evidence",
        statement="A second independently reviewed systems result.",
        source_identity=source_identity,
        state="evidence",
        evidence_kind="test_result",
        valid_until="2035-01-01",
    )
    alternate_decision = graph.verify_evidence(
        "alternate-evidence", 1, decision="approved",
        verifier_kind="deterministic",
        policy_id=FitAssessmentStore.GAP_EVIDENCE_POLICY_ID,
        policy_version=FitAssessmentStore.GAP_EVIDENCE_POLICY_VERSION,
        policy_hash=hashlib.sha256(b"alternate-policy").hexdigest(),
        reason="independent alternate review",
        source_identity="test:alternate-reviewer",
    )
    graph.link_claim_evidence(
        requirement.criterion,
        "alternate-evidence",
        source_identity=source_identity,
        edge_type="demonstrated_by",
    )
    graph.link_claim_artefact(
        requirement.criterion,
        "alternate-artifact",
        source_identity=source_identity,
        edge_type="documented_in",
    )
    with pytest.raises(ValueError, match="different gap verification"):
        store.verify_gap(
            **{
                **arguments,
                "evidence_id": "alternate-evidence",
                "artefact_id": "alternate-artifact",
                "verification_decision_id": alternate_decision,
            }
        )


def test_fit_reassessment_requires_a_verified_predecessor(
    tmp_path: Path,
) -> None:
    _database, store, run, requirement, _task_id, _promotion = (
        _pending_knowledge_gap(
            tmp_path / "unverified-reassessment.sqlite3",
            job_key="unverified-reassessment-job",
        )
    )
    with pytest.raises(ValueError, match="verified predecessor"):
        store.reassess(
            predecessor_run_id=run.run_id,
            requirements=(requirement,),
            proposals=(),
            as_of=date(2030, 1, 2),
        )


@pytest.mark.parametrize("attack", ("same-date", "changed-requirement"))
def test_fit_reassessment_rejects_stale_time_or_requirement_drift(
    tmp_path: Path,
    attack: str,
) -> None:
    database, store, run, requirement, _task_id, _promotion = (
        _verified_knowledge_gap(
            tmp_path / f"reassessment-{attack}.sqlite3",
            job_key=f"reassessment-{attack}-job",
        )
    )
    as_of = AS_OF if attack == "same-date" else date(2030, 1, 2)
    reassessment_requirement = (
        requirement
        if attack == "same-date"
        else Requirement(
            requirement.requirement_id,
            requirement.criterion,
            requirement.text,
            requirement.essential,
            requirement.gap_kind,
            requirement.bridge_policy,
            requirement.accepted_proof_classes,
            requirement.opportunity_weight_bp - 1,
            requirement.source_identity,
            requirement.source_span,
        )
    )
    evidence = candidate_graph_evidence(database.path, as_of=as_of)
    proposal = MatchProposal(
        reassessment_requirement.requirement_id,
        (evidence[0].evidence_id,),
        9000,
        "direct",
        "Independently reviewed reassessment.",
        _receipt(reassessment_requirement, evidence, as_of=as_of),
    )
    with pytest.raises(ValueError, match="advance the exact verified predecessor"):
        store.reassess(
            predecessor_run_id=run.run_id,
            requirements=(reassessment_requirement,),
            proposals=(proposal,),
            as_of=as_of,
        )
    assert database.lifecycle.replay()[f"reassessment-{attack}-job"] is (
        PipelineState.GAP_VERIFIED
    )
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM fit_assessment_runs"
        ).fetchone()[0] == 1


def test_fit_reassessment_mutation_conflicts_without_advancing_to_jaa06(
    tmp_path: Path,
) -> None:
    database, store, run, requirement, _task_id, _promotion = (
        _verified_knowledge_gap(
            tmp_path / "reassessment-conflict.sqlite3",
            job_key="reassessment-conflict-job",
        )
    )
    as_of = date(2030, 1, 2)
    evidence = candidate_graph_evidence(database.path, as_of=as_of)

    def proposal(reason: str) -> MatchProposal:
        return MatchProposal(
            requirement.requirement_id,
            (evidence[0].evidence_id,),
            9000,
            "direct",
            reason,
            _receipt(requirement, evidence, as_of=as_of),
        )

    successor = store.reassess(
        predecessor_run_id=run.run_id,
        requirements=(requirement,),
        proposals=(proposal("Accepted exact reassessment."),),
        as_of=as_of,
    )
    assert successor.status == "ready"
    with pytest.raises(ValueError, match="different durable result"):
        store.reassess(
            predecessor_run_id=run.run_id,
            requirements=(requirement,),
            proposals=(proposal("Mutated reassessment output."),),
            as_of=as_of,
        )
    assert database.lifecycle.replay()["reassessment-conflict-job"] is (
        PipelineState.FIT_REASSESSED
    )
    with store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM fit_assessment_runs"
        ).fetchone()[0] == 2


@pytest.mark.parametrize("attack", ("ledger", "trigger", "reassessment-index"))
def test_jaa05_migration_rejects_ledger_or_installed_schema_tampering(
    tmp_path: Path,
    attack: str,
) -> None:
    path = tmp_path / f"{attack}.sqlite3"
    apply_jaa_05_migrations(path)
    with sqlite3.connect(path) as connection:
        if attack == "ledger":
            connection.execute(
                """UPDATE career_schema_migrations SET checksum=?
                   WHERE version=4""",
                ("0" * 64,),
            )
        elif attack == "trigger":
            connection.execute(
                "DROP TRIGGER improvement_tasks_immutable_delete"
            )
        else:
            connection.execute(
                "DROP INDEX fit_assessment_runs_one_successor"
            )
    with pytest.raises(RuntimeError, match=(
        "modified after deployment" if attack == "ledger"
        else "installed JAA-05 schema"
    )):
        apply_jaa_05_migrations(path)


@pytest.mark.parametrize(
    ("attack", "error"),
    (
        ("profile-hash", "candidate profile hash mismatch"),
        ("input-hash", "input hash mismatch"),
        ("content-hash", "content hash does not bind"),
        ("limitations", "limitations are incomplete"),
    ),
)
def test_locked_evaluation_rejects_rehashed_internal_authority_tampering(
    tmp_path: Path,
    attack: str,
    error: str,
) -> None:
    payload = json.loads(LOCKED.read_text(encoding="utf-8"))
    example = payload["examples"][0]
    if attack == "profile-hash":
        example["proposal"]["receipt"]["candidate_profile_sha256"] = "0" * 64
    elif attack == "input-hash":
        example["proposal"]["receipt"]["input_sha256"] = "0" * 64
    elif attack == "content-hash":
        example["evidence"][0]["statement"] = "Rewritten unbound assertion."
    else:
        payload["limitations"] = ["not production calibration"]
    payload["examples_hash"] = content_hash(payload["examples"])
    attacked = tmp_path / f"{attack}.json"
    attacked.write_text(json.dumps(payload), encoding="utf-8")
    completed = subprocess.run(
        (
            sys.executable,
            "scripts/evaluate_jaa05_locked_labels.py",
            "--locked-set",
            str(attacked),
        ),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert error in completed.stderr


def test_locked_label_change_cannot_retain_a_passing_calibration(tmp_path: Path) -> None:
    payload = json.loads(LOCKED.read_text(encoding="utf-8"))
    payload["examples"][0]["label"] = "no_match"
    payload["examples_hash"] = content_hash(payload["examples"])
    attacked = tmp_path / "label-drift.json"
    attacked.write_text(json.dumps(payload), encoding="utf-8")
    completed = subprocess.run(
        (
            sys.executable,
            "scripts/evaluate_jaa05_locked_labels.py",
            "--locked-set",
            str(attacked),
        ),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    assert result["status"] == "SOFTWARE_CONTRACT_FAIL"
    assert result["metrics"]["precision_bp"] < 10_000


def test_wrong_abstention_cannot_hide_behind_match_precision(tmp_path: Path) -> None:
    payload = json.loads(LOCKED.read_text(encoding="utf-8"))
    payload["examples"][2]["label"] = "abstain"
    payload["examples_hash"] = content_hash(payload["examples"])
    attacked = tmp_path / "abstention-drift.json"
    attacked.write_text(json.dumps(payload), encoding="utf-8")
    completed = subprocess.run(
        (
            sys.executable,
            "scripts/evaluate_jaa05_locked_labels.py",
            "--locked-set",
            str(attacked),
        ),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 1
    metrics = json.loads(completed.stdout)["metrics"]
    assert metrics["precision_bp"] == 10_000
    assert metrics["recall_bp"] == 10_000
    assert metrics["abstention_recall_bp"] < 10_000
