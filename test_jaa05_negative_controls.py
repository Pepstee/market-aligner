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
from career_automation.lifecycle import PolicyIdentity, canonical_hash
from career_automation.migrations import apply_jaa_05_migrations
from career_automation.models import PipelineState, ScoredJob


AS_OF = date(2030, 1, 1)
POLICY = MatchingPolicy()
DIGEST = hashlib.sha256(b"negative-control").hexdigest()
ROOT = Path(__file__).resolve().parent
LOCKED = ROOT / "career_automation/fixtures/jaa05_locked_labels.json"


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
            as_of=AS_OF,
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
        "deterministic", DIGEST,
    )
    store.record_task_evidence(run.run_id, deterministic)
    with pytest.raises(ValueError, match="different verification evidence"):
        store.record_task_evidence(
            run.run_id,
            TaskEvidence(
                task_id, "test_result", "locked-assessment-pass",
                "human", DIGEST,
            ),
        )
    with store._connect() as connection:
        assert connection.execute(
            "SELECT verifier_kind FROM improvement_evidence_candidates"
        ).fetchone()[0] == "deterministic"


@pytest.mark.parametrize("attack", ("ledger", "trigger"))
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
        else:
            connection.execute(
                "DROP TRIGGER improvement_tasks_immutable_delete"
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
