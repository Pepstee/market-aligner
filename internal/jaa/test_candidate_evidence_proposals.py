from __future__ import annotations

import hashlib
import subprocess

import pytest

from career_automation.evidence_proposals import (
    CandidateEvidenceProposal,
    EvidenceProposalError,
    RepositoryEvidence,
    build_evidence_proposal_packet,
    load_evidence_proposal_packet,
    verify_evidence_proposal_packet,
    write_evidence_proposal_packet,
)


def _repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "fixture@example.test"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Fixture"], check=True)
    (root / "source.py").write_text("PROVIDERS = ('claude', 'codex', 'ollama')\n")
    (root / "test_source.py").write_text("def test_provider_boundary(): assert True\n")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    return root, commit


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_packet_verifies_git_content_and_exact_replay(tmp_path) -> None:
    root, commit = _repo(tmp_path)
    evidence = RepositoryEvidence(
        "orchestrator-v3", commit, "source.py", _digest((root / "source.py").read_bytes()),
        "test_source.py", _digest((root / "test_source.py").read_bytes()),
        "a" * 64, "b" * 64,
    )
    packet = build_evidence_proposal_packet((CandidateEvidenceProposal(
        "P-001", "model-routing", "proposed", "Implemented bounded provider routing.",
        (evidence,), "repository_and_test_bound",
    ), CandidateEvidenceProposal(
        "P-002", "unsupported-count", "rejected", None, (), "exact_count_not_verified",
    )))
    verify_evidence_proposal_packet(packet, {"orchestrator-v3": root})
    target = tmp_path / "external" / "packet.json"
    write_evidence_proposal_packet(target, packet)
    write_evidence_proposal_packet(target, packet)
    assert load_evidence_proposal_packet(target) == packet
    assert packet.release_authority is False
    assert packet.authority_mutation is False

    tampered = RepositoryEvidence(**{**evidence.__dict__, "source_sha256": "0" * 64})
    drifted = build_evidence_proposal_packet((CandidateEvidenceProposal(
        "P-003", "model-routing", "proposed", "Implemented bounded provider routing.",
        (tampered,), "repository_and_test_bound",
    ),))
    with pytest.raises(EvidenceProposalError, match="drifted"):
        verify_evidence_proposal_packet(drifted, {"orchestrator-v3": root})


def test_rejected_proposal_cannot_smuggle_outward_claim() -> None:
    with pytest.raises(EvidenceProposalError, match="cannot carry outward claims"):
        CandidateEvidenceProposal("P-004", "security", "rejected", "Used every tool.", (), "no_source")
