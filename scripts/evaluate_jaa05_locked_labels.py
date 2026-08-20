#!/usr/bin/env python3
"""Evaluate the synthetic locked JAA-05 software-contract labels.

This command emits calibration metrics only.  It is intentionally not a slice
certifier and cannot override JAA-04's unsatisfied external dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.evidence_matching import (  # noqa: E402
    MATCH_DECISIONS,
    MatchingPolicy,
    content_hash,
    evidence_from_mapping,
    evaluate_match,
    proposal_from_mapping,
    requirement_from_mapping,
    score_locked_labels,
)


SCHEMA_VERSION = "jaa05.locked-labels.v1"
LOCKED_SET_KIND = "synthetic_offline_contract"


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def evaluate(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    payload = _mapping(json.loads(raw), "locked set")
    if set(payload) != {
        "schema_version", "locked_set_id", "locked_set_kind", "as_of",
        "configuration", "examples", "examples_hash", "limitations",
    }:
        raise ValueError("locked set fields do not match the v1 contract")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported JAA-05 locked-set schema")
    if payload["locked_set_kind"] != LOCKED_SET_KIND:
        raise ValueError("JAA-05 software labels must be explicitly synthetic")
    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or not {
        "not production calibration",
        "does not certify JAA-05 while JAA-04 is incomplete",
    }.issubset(set(limitations)):
        raise ValueError("locked-set limitations are incomplete")
    configuration = _mapping(payload["configuration"], "configuration")
    if set(configuration) != {
        "policy_identity", "match_confidence_bp", "abstain_confidence_bp",
        "policy_sha256",
    }:
        raise ValueError("locked-set policy fields do not match the v1 contract")
    policy = MatchingPolicy(
        identity=str(configuration["policy_identity"]),
        match_confidence_bp=int(configuration["match_confidence_bp"]),
        abstain_confidence_bp=int(configuration["abstain_confidence_bp"]),
    )
    if configuration["policy_sha256"] != policy.policy_hash:
        raise ValueError("locked-set policy hash mismatch")
    examples = payload.get("examples")
    if not isinstance(examples, list) or len(examples) < 8:
        raise ValueError("locked set requires at least eight reviewed examples")
    if payload["examples_hash"] != content_hash(examples):
        raise ValueError("locked examples hash mismatch")
    as_of = date.fromisoformat(str(payload["as_of"]))
    results = []
    labels: dict[str, str] = {}
    gap_kinds: set[str] = set()
    for raw_example in examples:
        example = _mapping(raw_example, "example")
        if set(example) != {"example_id", "requirement", "evidence", "proposal", "label"}:
            raise ValueError("locked example fields do not match the v1 contract")
        requirement = requirement_from_mapping(
            _mapping(example["requirement"], "requirement")
        )
        if example["example_id"] != requirement.requirement_id:
            raise ValueError("example and requirement identities differ")
        evidence_raw = example["evidence"]
        if not isinstance(evidence_raw, list):
            raise ValueError("example evidence must be a list")
        evidence = tuple(
            evidence_from_mapping(_mapping(value, "evidence"))
            for value in evidence_raw
        )
        proposal_value = example["proposal"]
        proposal = (
            None
            if proposal_value is None
            else proposal_from_mapping(_mapping(proposal_value, "proposal"))
        )
        result = evaluate_match(
            requirement,
            proposal,
            {item.evidence_id: item for item in evidence},
            as_of=as_of,
            policy=policy,
        )
        label = str(example["label"])
        if label not in MATCH_DECISIONS:
            raise ValueError("invalid locked label")
        if requirement.requirement_id in labels:
            raise ValueError("locked example IDs must be unique")
        labels[requirement.requirement_id] = label
        gap_kinds.add(requirement.gap_kind)
        results.append(result)
    if gap_kinds != {
        "presentation", "retrieval", "knowledge", "execution",
        "evidence", "experience", "credential", "structural",
    }:
        raise ValueError("locked labels must cover all eight gap classifications")
    metrics = score_locked_labels(results, labels)
    return {
        "schema_version": "jaa05.locked-evaluation.v1",
        "status": "SOFTWARE_CONTRACT_PASS"
        if all(metrics[key] == 10_000 for key in (
            "precision_bp", "recall_bp", "abstention_precision_bp",
            "abstention_recall_bp", "exact_accuracy_bp",
        ))
        else "SOFTWARE_CONTRACT_FAIL",
        "certifies_slice": False,
        "dependency_gate": "JAA-04",
        "locked_set_id": payload["locked_set_id"],
        "locked_set_sha256": hashlib.sha256(raw).hexdigest(),
        "policy_sha256": policy.policy_hash,
        "metrics": metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--locked-set",
        type=Path,
        default=ROOT / "career_automation/fixtures/jaa05_locked_labels.json",
    )
    args = parser.parse_args()
    try:
        result = evaluate(args.locked_set.resolve())
    except Exception as exc:
        print(f"JAA-05 locked evaluation: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "SOFTWARE_CONTRACT_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
