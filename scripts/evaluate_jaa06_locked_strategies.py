#!/usr/bin/env python3
"""Evaluate the synthetic JAA-06 software contract without certifying the slice."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

from career_automation.application_strategy import (
    CandidateSupport,
    EmployerResearchFact,
    compile_application_strategy,
    verify_strategy_identity,
)
from career_automation.evidence_matching import MatchResult, Requirement, content_hash


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SET = ROOT / "career_automation/fixtures/jaa06_locked_strategies.json"
LIMITATIONS = {
    "synthetic software vectors are not production calibration",
    "does not certify JAA-06 while JAA-05 and JAA-04 remain dependency-blocked",
    "does not measure generated document quality or employer outcomes",
}


def _requirement(row: dict[str, Any]) -> Requirement:
    return Requirement(
        str(row["requirement_id"]),
        str(row["criterion"]),
        str(row["text"]),
        bool(row["essential"]),
        str(row["gap_kind"]),
        str(row["bridge_policy"]),
        tuple(str(value) for value in row["accepted_proof_classes"]),
        int(row["opportunity_weight_bp"]),
        str(row["source_identity"]),
        (int(row["source_span"][0]), int(row["source_span"][1])),
    )


def _result(row: dict[str, Any]) -> MatchResult:
    return MatchResult(
        str(row["requirement_id"]),
        str(row["decision"]),
        tuple(str(value) for value in row["evidence_ids"]),
        int(row["confidence_bp"]),
        str(row["reason"]),
        str(row["policy_sha256"]),
        None,
    )


def _support(row: dict[str, Any]) -> CandidateSupport:
    return CandidateSupport(
        str(row["requirement_id"]),
        str(row["claim_id"]),
        int(row["claim_version"]),
        str(row["evidence_id"]),
        int(row["evidence_version"]),
        str(row["proof_class"]),
        str(row["claim_approval_state"]),
        str(row["claim_epistemic_state"]),
        str(row["evidence_approval_state"]),
        str(row["evidence_epistemic_state"]),
        str(row["verification_decision"]),
        None
        if row.get("valid_until") is None
        else date.fromisoformat(str(row["valid_until"])),
    )


def _fact(row: dict[str, Any]) -> EmployerResearchFact:
    return EmployerResearchFact(
        str(row["claim_id"]),
        str(row["kind"]),
        str(row["classification"]),
        tuple(str(value) for value in row["source_ids"]),
        str(row["content_sha256"]),
        str(row["freshness_classification"]),
    )


def evaluate(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "jaa06.synthetic-locked-strategy.v1":
        raise ValueError("unsupported JAA-06 locked-set schema")
    examples = payload.get("examples")
    if not isinstance(examples, list) or len(examples) != 3:
        raise ValueError("JAA-06 locked set must contain exactly three scenarios")
    if payload.get("examples_hash") != content_hash(examples):
        raise ValueError("JAA-06 locked examples hash mismatch")
    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or set(limitations) != LIMITATIONS:
        raise ValueError("JAA-06 locked-set limitations are incomplete")
    exact = linkage = reproducible = 0
    results: list[dict[str, Any]] = []
    for example in examples:
        arguments = {
            "fit_run_id": str(example["fit_run_id"]),
            "dossier_hash": str(example["dossier_hash"]),
            "candidate_profile_hash": str(example["candidate_profile_hash"]),
            "requirements": tuple(
                _requirement(row) for row in example["requirements"]
            ),
            "match_results": tuple(
                _result(row) for row in example["match_results"]
            ),
            "candidate_support": tuple(
                _support(row) for row in example["candidate_support"]
            ),
            "employer_facts": tuple(
                _fact(row) for row in example["employer_facts"]
            ),
            "as_of": date.fromisoformat(str(example["as_of"])),
        }
        strategy = compile_application_strategy(**arguments)
        verify_strategy_identity(strategy)
        second = compile_application_strategy(**arguments)
        expected = example["expected"]
        coverage_states = [row.state for row in strategy.coverage]
        element_kinds = sorted({row.kind for row in strategy.elements})
        exact_case = (
            strategy.decision == expected["decision"]
            and coverage_states == expected["coverage_states"]
            and len(strategy.elements) == int(expected["element_count"])
            and element_kinds == sorted(expected["element_kinds"])
        )
        linked_case = all(
            row.requirement_id
            and row.candidate_claim_id
            and row.candidate_evidence_id
            and row.employer_research_claim_id
            and len(row.employer_fact_sha256) == 64
            for row in strategy.elements
        )
        reproducible_case = second == strategy
        exact += int(exact_case)
        linkage += int(linked_case)
        reproducible += int(reproducible_case)
        results.append({
            "id": str(example["id"]),
            "decision": strategy.decision,
            "coverage_states": coverage_states,
            "element_count": len(strategy.elements),
            "strategy_id": strategy.strategy_id,
            "document_sha256": strategy.document_sha256,
            "exact": exact_case,
            "linked": linked_case,
            "reproducible": reproducible_case,
        })
    denominator = len(examples)
    metrics = {
        "exact_accuracy_bp": exact * 10_000 // denominator,
        "linkage_completeness_bp": linkage * 10_000 // denominator,
        "reproducibility_bp": reproducible * 10_000 // denominator,
        "examples": denominator,
    }
    passed = all(value == 10_000 for key, value in metrics.items() if key != "examples")
    return {
        "schema_version": "jaa06.synthetic-strategy-evaluation.v1",
        "status": "SOFTWARE_CONTRACT_PASS" if passed else "SOFTWARE_CONTRACT_FAIL",
        "locked_set_id": payload["locked_set_id"],
        "locked_set_sha256": content_hash(payload),
        "metrics": metrics,
        "results": results,
        "certifies_slice": False,
        "dependency_gate": "JAA-05",
        "transitive_dependency_gate": "JAA-04",
        "limitations": limitations,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--locked-set", type=Path, default=DEFAULT_SET)
    arguments = parser.parse_args()
    try:
        result = evaluate(arguments.locked_set)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "SOFTWARE_CONTRACT_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
