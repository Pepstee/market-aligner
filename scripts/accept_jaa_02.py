#!/usr/bin/env python3
"""Independent executable acceptance demonstration for JAA-02."""

from __future__ import annotations

import hashlib
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.candidate_graph import CandidateGraph  # noqa: E402


def main() -> int:
    policy_hash = hashlib.sha256(b"jaa-02-demo-policy-v1").hexdigest()
    with tempfile.TemporaryDirectory(prefix="jaa-02-") as temporary:
        graph = CandidateGraph(Path(temporary) / "candidate.sqlite3")
        graph.add_evidence(
            "ev-project", statement="Repository receipt demonstrates the shipped project.",
            source_identity="demo:repository-receipt", state="evidence",
        )
        graph.verify_evidence(
            "ev-project", 1, decision="approved", verifier_kind="deterministic",
            policy_id="demo.receipt", policy_version="1", policy_hash=policy_hash,
            reason="content-addressed receipt matched", source_identity="demo:verifier",
        )
        graph.add_claim(
            "claim-project", statement="Shipped the demonstrated project.",
            claim_type="achievement", state="fact", source_identity="demo:claim",
        )
        graph.link_claim_evidence(
            "claim-project", "ev-project", source_identity="demo:edge"
        )
        graph.approve_claim("claim-project")
        assert [item["claim_id"] for item in graph.release_claims(as_of=date(2030, 1, 1))] == [
            "claim-project"
        ]

        graph.add_claim(
            "claim-inferred", statement="Inferred unsupported title.", claim_type="title",
            state="inference", source_identity="demo:claim",
        )
        graph.link_claim_evidence("claim-inferred", "ev-project", source_identity="demo:edge")
        try:
            graph.approve_claim("claim-inferred")
        except ValueError:
            pass
        else:
            raise AssertionError("inferred claim was approved")

        credential_label = "api_" + "key"
        synthetic_value = "synthetic-" + "negative-control"
        assert graph.add_evidence(
            "ev-secret", statement=f"{credential_label}={synthetic_value}",
            source_identity="demo:unsafe", state="evidence",
        ) == "quarantined"

        graph.add_record(
            "right-uk-employee", kind="work_right", subject="employment permission",
            value={"permitted": True}, state="fact", source_identity="demo:right",
            jurisdiction="GB", contract_type="employee", valid_until="2035-01-01",
        )
        graph.verify_record(
            "right-uk-employee", 1, decision="approved", verifier_kind="configured",
            policy_id="demo.work-right", policy_version="1", policy_hash=policy_hash,
            reason="configured rule checked", source_identity="demo:verifier",
        )
        assert graph.resolve_work_right("GB", "employee", as_of=date(2030, 1, 1)).decision == "resolved"
        assert graph.resolve_work_right("GB", "contractor", as_of=date(2030, 1, 1)).decision == "abstain"
        projection = graph.worker_projection(as_of=date(2030, 1, 1))
        assert projection["claims"] == [{
            "id": "claim-project", "version": 1, "type": "achievement",
            "statement": "Shipped the demonstrated project.",
        }]
    print("JAA-02 acceptance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
