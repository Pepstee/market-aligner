"""Executable receipt controls for the private JAA-05 production projection."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
import yaml

from career_automation.evidence_matching import (
    candidate_graph_evidence,
    evidence_projection_hash,
)
from career_automation.human_evidence_ingestion import (
    EXPECTED_HUMAN_AUTHORITY_SHA256,
    validate_ingestion_integrity,
)
from scripts import certify_jaa05_human_evidence as certifier


ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "profiler" / "data" / "candidate_evidence.yaml"
EVIDENCE_SHA256 = "7a7e18a686b0979e48716f983871568e018c04398e05b8c71af88059f6fb6195"
PROJECTION_SHA256 = "82ba6ca979b66fea25b1e987c50b8cdbbeca746869d0563a24480892c7ddab00"
SOURCE_CONTENT_REVISION = "sha256:" + "a" * 64
SOURCE_GIT_REVISION = "b" * 40


def _fixed_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        certifier,
        "source_content_revision",
        lambda _root: SOURCE_CONTENT_REVISION,
    )
    monkeypatch.setattr(
        certifier,
        "source_git_revision",
        lambda _root: SOURCE_GIT_REVISION,
    )


def test_receipt_proves_private_projection_and_idempotency_without_leaks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixed_source(monkeypatch)
    graph = tmp_path / "candidate-graph.sqlite3"
    receipts = tmp_path / "receipts"
    receipt = certifier.certify(
        graph_path=graph,
        evidence_path=EVIDENCE,
        receipt_directory=receipts,
        expected_evidence_sha256=EVIDENCE_SHA256,
        expected_projection_sha256=PROJECTION_SHA256,
    )

    payload = receipt.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    assert receipt.name == f"sha256-{digest}.json"
    assert receipt.stat().st_mode & 0o777 == 0o444
    assert graph.stat().st_mode & 0o777 == 0o600
    document = json.loads(payload)
    assert document["format"] == certifier.FORMAT
    assert document["source_git_revision"] == SOURCE_GIT_REVISION
    assert document["source_content_revision"] == SOURCE_CONTENT_REVISION
    assert document["private_evidence"] == {
        "location_class": "private_operator_supplied_ignored_input",
        "sha256": EVIDENCE_SHA256,
        "record_count": 18,
        "human_authority_sha256": EXPECTED_HUMAN_AUTHORITY_SHA256,
        "source_packet_sha256": (
            "6ee3cc29b2074b4244686ca938028ad397ca0a39ab6323de59b52eb20d6eadb7"
        ),
    }
    assert document["production_graph"]["mode"] == "0600"
    assert document["production_graph"]["projection_sha256"] == PROJECTION_SHA256
    assert document["production_graph"]["projection_record_count"] == 18
    assert document["production_graph"]["state"]["integrity_check"] == "ok"
    for table in (
        "candidate_evidence",
        "candidate_claims",
        "candidate_claim_edges",
        "candidate_verification_decisions",
    ):
        assert (
            document["production_graph"]["state"]["tables"][table]["row_count"]
            == 18
        )
    assert document["idempotency"]["executions"] == 2
    assert document["idempotency"]["projection_sha256_equal"] is True
    assert document["idempotency"]["graph_state_equal"] is True
    assert document["claims"]["certifies_jaa05_slice"] is False

    private = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    text = payload.decode("utf-8")
    assert str(private["human_authority"]) not in text
    assert all(str(row["statement"]) not in text for row in private["records"])
    assert "/home/" not in text
    assert "/Users/" not in text

    validate_ingestion_integrity(graph, EVIDENCE)
    projection = candidate_graph_evidence(
        graph,
        as_of=__import__("datetime").date.fromisoformat("2027-01-01"),
    )
    assert evidence_projection_hash(projection) == PROJECTION_SHA256

    with pytest.raises(certifier.CertificationError, match="must be absent"):
        certifier.certify(
            graph_path=graph,
            evidence_path=EVIDENCE,
            receipt_directory=receipts,
            expected_evidence_sha256=EVIDENCE_SHA256,
            expected_projection_sha256=PROJECTION_SHA256,
        )


def test_wrong_projection_binding_preserves_graph_without_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixed_source(monkeypatch)
    graph = tmp_path / "candidate-graph.sqlite3"
    receipts = tmp_path / "receipts"
    with pytest.raises(certifier.CertificationError, match="projection SHA-256"):
        certifier.certify(
            graph_path=graph,
            evidence_path=EVIDENCE,
            receipt_directory=receipts,
            expected_evidence_sha256=EVIDENCE_SHA256,
            expected_projection_sha256="0" * 64,
        )
    assert graph.is_file()
    assert not receipts.exists()
    with sqlite3.connect(graph) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM candidate_evidence"
        ).fetchone()[0] == 18
