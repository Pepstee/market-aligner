"""Independent JAA-02 acceptance and negative-control tests.

These assertions deliberately use fresh SQLite databases and public graph APIs;
they do not rely on the executable acceptance demonstration for their results.
"""

from __future__ import annotations

import ast
import hashlib
import os
import sqlite3
import subprocess
from datetime import date
from pathlib import Path

import pytest

from career_automation.candidate_graph import CandidateGraph
from career_automation.migrations import JAA_02_MIGRATIONS, apply_jaa_02_migrations


POLICY_HASH = hashlib.sha256(b"independent-jaa-02-policy-v1").hexdigest()
AS_OF = date(2030, 1, 1)


def _verify_evidence(graph: CandidateGraph, evidence_id: str) -> None:
    graph.verify_evidence(
        evidence_id, 1, decision="approved", verifier_kind="deterministic",
        policy_id="independent.evidence", policy_version="1", policy_hash=POLICY_HASH,
        reason="independent content verification", source_identity="test:verifier",
    )


def _verify_right(graph: CandidateGraph, record_id: str) -> None:
    graph.verify_record(
        record_id, 1, decision="approved", verifier_kind="configured",
        policy_id="independent.work-right", policy_version="1", policy_hash=POLICY_HASH,
        reason="independent governing-rule verification", source_identity="test:verifier",
    )


def _approved_evidence(graph: CandidateGraph, evidence_id: str = "evidence") -> None:
    graph.add_evidence(
        evidence_id, statement="A signed project receipt confirms delivery.",
        source_identity="test:receipt", state="evidence", valid_until="2035-01-01",
    )
    _verify_evidence(graph, evidence_id)


def test_jaa02_migration_is_forward_only_and_schema_enforces_graph_integrity(tmp_path: Path) -> None:
    database = tmp_path / "candidate.sqlite3"
    assert apply_jaa_02_migrations(database) == tuple(
        migration.version for migration in JAA_02_MIGRATIONS
    )
    assert apply_jaa_02_migrations(database) == ()

    with sqlite3.connect(database) as connection:
        migrations = connection.execute(
            "SELECT version, name FROM career_schema_migrations ORDER BY version"
        ).fetchall()
        assert migrations == [
            (migration.version, migration.name) for migration in JAA_02_MIGRATIONS
        ]
        with pytest.raises(sqlite3.IntegrityError, match="approved claim requires approved evidence"):
            connection.execute(
                """INSERT INTO candidate_claims(
                    claim_id,version,claim_type,statement,epistemic_state,approval_state,provenance_id
                ) VALUES ('forged',1,'achievement','Forged metric','fact','approved','missing')"""
            )

    graph = CandidateGraph(database)
    graph.add_claim(
        "claim", statement="Delivered an audited project.", claim_type="achievement",
        state="fact", source_identity="test:claim",
    )
    with pytest.raises(sqlite3.IntegrityError):
        graph.link_claim_evidence("claim", "does-not-exist", source_identity="test:edge")
    with pytest.raises(sqlite3.IntegrityError, match="approved claim requires approved evidence"):
        graph.approve_claim("claim")


def test_legacy_profile_and_evidence_import_preserves_provenance_versions_and_fails_closed(tmp_path: Path) -> None:
    profile = tmp_path / "legacy-profile.yaml"
    evidence = tmp_path / "legacy-evidence.yaml"
    profile.write_text(
        """meta:\n  source_identity: legacy:profile\n  version: 7\ncandidate_profile:\n  capabilities:\n    python:\n      id: capability-python\n      version: 2\n      value: advanced\n      state: fact\ncareer_tracks:\n  engineering:\n    claim_id: imported-track\n    rationale: A plausible engineering direction.\n    evidence: [receipt]\n""",
        encoding="utf-8",
    )
    evidence.write_text(
        """meta:\n  source_identity: legacy:evidence\nevidence:\n  - id: receipt\n    claim: Release receipt proves a deployment.\n    state: evidence\n    version: 3\n    source: archive:receipt\n  - id: invented-metric\n    claim: Increased revenue by 999 percent.\n    state: unverified\n""",
        encoding="utf-8",
    )
    graph = CandidateGraph(tmp_path / "candidate.sqlite3")
    assert graph.import_yaml(profile, evidence) == {"records": 1, "evidence": 2, "claims": 1}

    with graph.connect() as connection:
        record = connection.execute(
            "SELECT version, epistemic_state, provenance_id FROM candidate_records WHERE record_id='capability-python'"
        ).fetchone()
        receipt = connection.execute(
            "SELECT version, source_identity, provenance_id FROM candidate_evidence WHERE evidence_id='receipt'"
        ).fetchone()
        imported_claim = connection.execute(
            "SELECT epistemic_state, approval_state FROM candidate_claims WHERE claim_id='imported-track'"
        ).fetchone()
        provenance = connection.execute("SELECT source_identity, source_hash FROM candidate_provenance").fetchall()
    assert tuple(record)[:2] == (2, "fact")
    assert tuple(receipt)[:2] == (3, "archive:receipt")
    assert tuple(imported_claim) == ("inference", "pending")
    assert {item[0] for item in provenance} == {"legacy:profile", "legacy:evidence"}
    assert all(len(item[1]) == 64 for item in provenance)
    with pytest.raises(ValueError, match="cannot be approved"):
        graph.verify_evidence(
            "invented-metric", 1, decision="approved", verifier_kind="human",
            policy_id="independent", policy_version="1", policy_hash=POLICY_HASH,
            reason="fabricated metrics must fail closed", source_identity="test:verifier",
        )
    with pytest.raises(ValueError, match="non-factual"):
        graph.approve_claim("imported-track")


@pytest.mark.parametrize("state", ["inference", "unknown", "expired", "disputed", "unverified"])
def test_non_factual_evidence_and_unsupported_titles_never_become_release_claims(
    tmp_path: Path, state: str
) -> None:
    graph = CandidateGraph(tmp_path / f"{state}.sqlite3")
    graph.add_evidence("bad-evidence", statement="Unsupported assertion.", source_identity="test:bad", state=state)
    with pytest.raises(ValueError, match="cannot be approved"):
        _verify_evidence(graph, "bad-evidence")

    _approved_evidence(graph)
    graph.add_claim(
        "unsupported-title", statement="Chief Architect", claim_type="title", state="inference",
        source_identity="test:claim",
    )
    graph.link_claim_evidence("unsupported-title", "evidence", source_identity="test:edge")
    with pytest.raises(ValueError, match="non-factual"):
        graph.approve_claim("unsupported-title")
    assert graph.release_claims(as_of=AS_OF) == []


def test_approved_claim_requires_current_approved_evidence_and_cannot_survive_staleness(tmp_path: Path) -> None:
    graph = CandidateGraph(tmp_path / "stale.sqlite3")
    _approved_evidence(graph, "expiry-proof")
    graph.add_claim(
        "claim", statement="Completed the independently evidenced project.", claim_type="achievement",
        state="fact", source_identity="test:claim", valid_until="2035-01-01",
    )
    graph.link_claim_evidence("claim", "expiry-proof", source_identity="test:edge")
    graph.approve_claim("claim")
    assert [item["claim_id"] for item in graph.release_claims(as_of=AS_OF)] == ["claim"]

    with graph.connect() as connection, pytest.raises(sqlite3.IntegrityError, match="evidence supports an approved claim"):
        connection.execute("UPDATE candidate_evidence SET valid_until='2020-01-01' WHERE evidence_id='expiry-proof'")


def test_secret_candidates_are_quarantined_and_private_conversation_cannot_reach_projection(tmp_path: Path) -> None:
    graph = CandidateGraph(tmp_path / "privacy.sqlite3")
    assert graph.add_evidence(
        "secret", statement="access_token=super-secret-value", source_identity="test:leak", state="evidence"
    ) == "quarantined"
    with pytest.raises(ValueError, match="quarantined"):
        _verify_evidence(graph, "secret")
    with graph.connect() as connection:
        quarantine = connection.execute(
            "SELECT reason_code, content_hash FROM candidate_quarantine WHERE target_id='secret'"
        ).fetchone()
    assert quarantine[0] == "secret_pattern" and len(quarantine[1]) == 64

    _approved_evidence(graph, "safe-proof")
    graph.add_claim(
        "private", statement="Private conversation about a family medical appointment.",
        claim_type="private_conversation", state="fact", source_identity="test:private",
    )
    graph.link_claim_evidence("private", "safe-proof", source_identity="test:edge")
    graph.approve_claim("private")
    assert graph.worker_projection(as_of=AS_OF)["claims"] == []


def test_work_right_is_jurisdiction_and_contract_specific_and_abstains_without_current_verification(tmp_path: Path) -> None:
    graph = CandidateGraph(tmp_path / "rights.sqlite3")
    graph.add_record(
        "gb-employee", kind="work_right", subject="permission", value={"permitted": True}, state="fact",
        source_identity="test:right", jurisdiction="GB", contract_type="employee", valid_until="2035-01-01",
    )
    graph.add_record(
        "nl-contractor", kind="work_right", subject="permission", value={"permitted": False}, state="fact",
        source_identity="test:right", jurisdiction="NL", contract_type="contractor", valid_until="2035-01-01",
    )
    _verify_right(graph, "gb-employee")
    _verify_right(graph, "nl-contractor")
    assert graph.resolve_work_right("GB", "employee", as_of=AS_OF).value == {"permitted": True}
    assert graph.resolve_work_right("NL", "contractor", as_of=AS_OF).value == {"permitted": False}
    assert graph.resolve_work_right("GB", "contractor", as_of=AS_OF).decision == "abstain"

    graph.add_record(
        "expired", kind="work_right", subject="permission", value={"permitted": True}, state="fact",
        source_identity="test:right", jurisdiction="US", contract_type="employee", valid_until="2029-12-31",
    )
    _verify_right(graph, "expired")
    graph.add_record(
        "unverified", kind="work_right", subject="permission", value={"permitted": True}, state="fact",
        source_identity="test:right", jurisdiction="CA", contract_type="employee", valid_until="2035-01-01",
    )
    assert graph.resolve_work_right("US", "employee", as_of=AS_OF).decision == "abstain"
    assert graph.resolve_work_right("CA", "employee", as_of=AS_OF).decision == "abstain"


def test_release_order_and_acceptance_declaration_are_deterministic_and_data_only(tmp_path: Path) -> None:
    graph = CandidateGraph(tmp_path / "deterministic.sqlite3")
    _approved_evidence(graph)
    for claim_id in ("zeta", "alpha"):
        graph.add_claim(
            claim_id, statement=f"{claim_id} project delivered.", claim_type="achievement",
            state="fact", source_identity="test:claim",
        )
        graph.link_claim_evidence(claim_id, "evidence", source_identity=f"test:edge:{claim_id}")
        graph.approve_claim(claim_id)
    assert [item["id"] for item in graph.worker_projection(as_of=AS_OF)["claims"]] == ["alpha", "zeta"]

    root = Path(__file__).resolve().parent
    declaration = root / "acceptance"
    commands = [
        line.strip() for line in declaration.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    # The declaration is executable data: each record is one shell command,
    # rather than an embedded multi-line program or a JAA-02 demo shortcut.
    assert commands == [
        'python3 "${BASH_SOURCE[0]:+${BASH_SOURCE[0]%/*}/}scripts/run_acceptance_declaration.py"',
    ]
    assert all("-c" not in command and "$0" not in command for command in commands)

    # Keep this inventory independent of the runner module: parse the source
    # and compare its literal command declaration with the release contract.
    runner = ast.parse((root / "scripts" / "run_acceptance_declaration.py").read_text(encoding="utf-8"))
    commands_node = next(
        node for node in runner.body
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "COMMANDS" for target in node.targets
        )
    )
    assert isinstance(commands_node.value, ast.Tuple)
    inventory = tuple(
        tuple(
            "__PYTHON__" if ast.unparse(argument) == "sys.executable" else ast.literal_eval(argument)
            for argument in command.elts
        )
        for command in commands_node.value.elts
        if isinstance(command, (ast.Tuple, ast.List))
    )
    assert inventory == (
        ("__PYTHON__", "scripts/run_acceptance.py"),
        ("__PYTHON__", "scripts/accept_jaa_02.py"),
        ("__PYTHON__", "scripts/accept_jaa02_receipt.py"),
        ("__PYTHON__", "scripts/accept_jaa03_receipt.py"),
        ("__PYTHON__", "scripts/accept_jaa04_coordination.py"),
        ("__PYTHON__", "scripts/accept_jaa_04.py"),
    )


def test_direct_root_acceptance_fails_closed_when_its_first_declared_gate_fails(tmp_path: Path) -> None:
    """A directly executable declaration must not hide an earlier failed gate."""
    root = Path(__file__).resolve().parent
    environment = os.environ | {"XDG_CONFIG_HOME": str(tmp_path / "no-runtime-config")}
    completed = subprocess.run(
        [str(root / "acceptance")], cwd=root, env=environment,
        text=True, capture_output=True, check=False, timeout=30,
    )
    assert completed.returncode != 0, completed.stdout + completed.stderr
