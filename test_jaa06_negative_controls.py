"""Adversarial controls for JAA-06 strategy authority and identity."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from career_automation.application_strategy import (
    CandidateSupport,
    EmployerResearchFact,
    compile_application_strategy,
    verify_strategy_identity,
)
from career_automation.evidence_matching import MatchResult, MatchingPolicy, Requirement
from career_automation.evidence_matching import content_hash
from career_automation.migrations import apply_jaa_06_migrations


AS_OF = date(2030, 1, 2)
DIGEST = hashlib.sha256(b"jaa06-negative").hexdigest()
POLICY = MatchingPolicy()
ROOT = Path(__file__).resolve().parent
LOCKED = ROOT / "career_automation/fixtures/jaa06_locked_strategies.json"
REQUIREMENT = Requirement(
    "python",
    "claim-python",
    "Deliver Python services.",
    True,
    "evidence",
    "build_evidence",
    ("portfolio_artifact",),
    9000,
    "vacancy:locked",
    (0, 10),
)
RESULT = MatchResult(
    "python",
    "matched",
    ("evidence-python",),
    9000,
    "approved evidence",
    POLICY.policy_hash,
    None,
)
SUPPORT = CandidateSupport(
    "python",
    "claim-python",
    1,
    "evidence-python",
    1,
    "portfolio_artifact",
    "approved",
    "evidence",
    "approved",
    "evidence",
    "approved",
    date(2035, 1, 1),
)
FACT = EmployerResearchFact(
    "research-company",
    "company",
    "fact",
    ("source:official-company",),
    DIGEST,
    "current",
)


def _compile(
    *,
    support: tuple[CandidateSupport, ...] = (SUPPORT,),
    facts: tuple[EmployerResearchFact, ...] = (FACT,),
):
    return compile_application_strategy(
        fit_run_id=DIGEST,
        dossier_hash=hashlib.sha256(b"dossier").hexdigest(),
        candidate_profile_hash=hashlib.sha256(b"profile").hexdigest(),
        requirements=(REQUIREMENT,),
        match_results=(RESULT,),
        candidate_support=support,
        employer_facts=facts,
        as_of=AS_OF,
    )


@pytest.mark.parametrize(
    "attack",
    (
        {"claim_approval_state": "pending"},
        {"claim_epistemic_state": "inference"},
        {"evidence_approval_state": "pending"},
        {"evidence_epistemic_state": "unverified"},
        {"verification_decision": "abstained"},
    ),
)
def test_unapproved_or_unfactual_candidate_support_is_rejected(
    attack: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="approved"):
        replace(SUPPORT, **attack)


@pytest.mark.parametrize("classification", ("hypothesis", "inference"))
def test_employer_hypothesis_or_inference_cannot_be_used_as_fact(
    classification: str,
) -> None:
    with pytest.raises(ValueError, match="hypotheses or inferences"):
        replace(FACT, classification=classification)


def test_generic_or_stale_employer_hook_is_rejected() -> None:
    with pytest.raises(ValueError, match="source identities"):
        replace(FACT, source_ids=())
    with pytest.raises(ValueError, match="must be current"):
        replace(FACT, freshness_classification="historical")
    with pytest.raises(ValueError, match="requires current source-backed"):
        _compile(facts=())


@pytest.mark.parametrize(
    "attack",
    (
        {"claim_id": "different-claim"},
        {"evidence_id": "different-evidence"},
        {"proof_class": "employment_record"},
        {"valid_until": date(2029, 12, 31)},
    ),
)
def test_support_must_bind_exact_requirement_match_and_current_proof(
    attack: dict[str, object],
) -> None:
    with pytest.raises(
        ValueError,
        match="align exactly|exact current approved",
    ):
        _compile(support=(replace(SUPPORT, **attack),))


def test_duplicate_or_extra_support_and_result_identity_fail_closed() -> None:
    with pytest.raises(ValueError, match="unique"):
        _compile(support=(SUPPORT, SUPPORT))
    extra = replace(SUPPORT, requirement_id="unmatched")
    with pytest.raises(ValueError, match="align exactly"):
        _compile(support=(SUPPORT, extra))


def test_duplicate_employer_fact_identity_fails_closed() -> None:
    with pytest.raises(ValueError, match="fact identities must be unique"):
        _compile(facts=(FACT, replace(FACT, content_sha256="0" * 64)))


def test_mixed_fit_policy_results_fail_closed() -> None:
    second_requirement = replace(
        REQUIREMENT,
        requirement_id="second",
        criterion="claim-second",
    )
    second_support = replace(
        SUPPORT,
        requirement_id="second",
        claim_id="claim-second",
        evidence_id="evidence-second",
    )
    second_result = replace(
        RESULT,
        requirement_id="second",
        evidence_ids=("evidence-second",),
        policy_sha256="0" * 64,
    )
    with pytest.raises(ValueError, match="one exact matching policy"):
        compile_application_strategy(
            fit_run_id=DIGEST,
            dossier_hash=hashlib.sha256(b"dossier").hexdigest(),
            candidate_profile_hash=hashlib.sha256(b"profile").hexdigest(),
            requirements=(REQUIREMENT, second_requirement),
            match_results=(RESULT, second_result),
            candidate_support=(SUPPORT, second_support),
            employer_facts=(FACT,),
            as_of=AS_OF,
        )


def test_offline_strategy_cannot_claim_slice_certification() -> None:
    strategy = _compile()
    with pytest.raises(ValueError, match="cannot certify"):
        replace(strategy, certifies_slice=True)


def test_strategy_identity_cannot_be_rehashed_or_mutated_by_a_caller() -> None:
    strategy = _compile()
    verify_strategy_identity(strategy)
    with pytest.raises(ValueError, match="exact document"):
        verify_strategy_identity(replace(strategy, strategy_id="0" * 64))
    with pytest.raises(ValueError, match="exact document"):
        verify_strategy_identity(replace(strategy, as_of=date(2030, 1, 3)))


def test_strategy_schema_requires_one_exact_directive_kind_per_requirement() -> None:
    strategy = _compile()
    with pytest.raises(ValueError, match="element identities must be unique"):
        replace(strategy, elements=(strategy.elements[0],) * len(strategy.elements))


def test_strategy_input_hash_binds_complete_requirement_and_result() -> None:
    original = _compile()
    changed_weight = replace(
        REQUIREMENT,
        opportunity_weight_bp=REQUIREMENT.opportunity_weight_bp - 1,
    )
    changed_requirement = compile_application_strategy(
        fit_run_id=DIGEST,
        dossier_hash=hashlib.sha256(b"dossier").hexdigest(),
        candidate_profile_hash=hashlib.sha256(b"profile").hexdigest(),
        requirements=(changed_weight,),
        match_results=(RESULT,),
        candidate_support=(SUPPORT,),
        employer_facts=(FACT,),
        as_of=AS_OF,
    )
    changed_result = compile_application_strategy(
        fit_run_id=DIGEST,
        dossier_hash=hashlib.sha256(b"dossier").hexdigest(),
        candidate_profile_hash=hashlib.sha256(b"profile").hexdigest(),
        requirements=(REQUIREMENT,),
        match_results=(replace(RESULT, reason="Changed exact fit result."),),
        candidate_support=(SUPPORT,),
        employer_facts=(FACT,),
        as_of=AS_OF,
    )
    assert changed_requirement.input_sha256 != original.input_sha256
    assert changed_requirement.strategy_id != original.strategy_id
    assert changed_result.input_sha256 != original.input_sha256
    assert changed_result.strategy_id != original.strategy_id


def test_jaa06_installed_schema_tamper_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "schema-tamper.sqlite3"
    apply_jaa_06_migrations(path)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER strategy_elements_immutable_delete")
    with pytest.raises(RuntimeError, match="installed JAA-06 schema"):
        apply_jaa_06_migrations(path)


def test_rehashed_locked_decision_tamper_fails_contract(tmp_path: Path) -> None:
    payload = json.loads(LOCKED.read_text(encoding="utf-8"))
    payload["examples"][0]["expected"]["decision"] = "close_gap_first"
    payload["examples_hash"] = content_hash(payload["examples"])
    attacked = tmp_path / "decision.json"
    attacked.write_text(json.dumps(payload), encoding="utf-8")
    completed = subprocess.run(
        (
            sys.executable,
            "scripts/evaluate_jaa06_locked_strategies.py",
            "--locked-set",
            str(attacked),
        ),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["status"] == "SOFTWARE_CONTRACT_FAIL"


def test_locked_evaluator_rejects_missing_noncertification_limit(
    tmp_path: Path,
) -> None:
    payload = json.loads(LOCKED.read_text(encoding="utf-8"))
    payload["limitations"].pop()
    attacked = tmp_path / "limitations.json"
    attacked.write_text(json.dumps(payload), encoding="utf-8")
    completed = subprocess.run(
        (
            sys.executable,
            "scripts/evaluate_jaa06_locked_strategies.py",
            "--locked-set",
            str(attacked),
        ),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert "limitations are incomplete" in completed.stderr
