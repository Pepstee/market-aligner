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
from career_automation.gap_optimizer import (
    DEFAULT_TEMPLATES,
    TaskEvidence,
    TaskTemplate,
    optimise_gaps,
    validate_task_evidence,
)


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
    with pytest.raises(ValueError, match="unknown evidence"):
        evaluate_match(
            requirement,
            _proposal(requirement, (), "forged"),
            {},
            as_of=AS_OF,
        )
    evidence = _evidence("valid", "employment_record")
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
