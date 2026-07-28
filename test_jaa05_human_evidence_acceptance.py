"""Production-projection acceptance test for human-authored evidence ingestion.

Covers the 18 exact records in profiler/data/candidate_evidence.yaml ingested
into the JAA-02 CandidateGraph via the generic ingestion path.

Assertions:
- Exactly 18 Evidence objects appear in the production projection.
- evidence_projection_hash is stable and matches the bound fixture value.
- Every Evidence has non-empty claim_lineage.
- Ingestion is fully idempotent (second run produces identical hash).
- Tamper of any graph statement is detected (content_hash mismatch raises).
- Author identity and verifier identity are distinct source identities in provenance.
- Zero silent ingestion: all 18 evidence_ids from YAML appear in projection.
- Schema / authority / status / content_hash violations are rejected at validation time.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import date
from pathlib import Path

import pytest
import yaml

from career_automation.candidate_graph import CandidateGraph
from career_automation.evidence_matching import (
    Evidence,
    InferenceReceipt,
    MatchProposal,
    MatchingPolicy,
    Requirement,
    candidate_graph_evidence,
    evaluate_match,
    evidence_projection_hash,
    matching_input_hash,
)
from career_automation.human_evidence_ingestion import (
    AUTHOR_IDENTITY,
    EXPECTED_HUMAN_AUTHORITY,
    EXPECTED_RECORD_COUNT,
    EXPECTED_STATUS,
    INGESTION_POLICY_HASH,
    INGESTION_SCHEMA_VERSION,
    VERIFIER_IDENTITY,
    ingest_human_evidence_schema,
    validate_ingestion_integrity,
)


ROOT = Path(__file__).resolve().parent
YAML_PATH = ROOT / "profiler" / "data" / "candidate_evidence.yaml"
AS_OF = date(2027, 1, 1)

# Bound fixture: stable production-projection hash for all 18 records.
# Computed deterministically from the ingestion policy, evidence statements,
# claim IDs, and verifier provenance — all fixed constants.
EXPECTED_PROJECTION_HASH = (
    "b574f5949d0d95434f930660b62ccf5ff2e160089212daa1041b99387935b881"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _graph(tmp_path: Path) -> tuple[Path, tuple]:
    """Ingest once and return (graph_path, evidence_tuple)."""
    graph_path = tmp_path / "candidate.sqlite3"
    ingest_human_evidence_schema(graph_path, YAML_PATH)
    evidence = candidate_graph_evidence(graph_path, as_of=AS_OF)
    return graph_path, evidence


# ---------------------------------------------------------------------------
# Core projection assertions
# ---------------------------------------------------------------------------

def test_ingestion_produces_exactly_18_records(tmp_path: Path) -> None:
    _, evidence = _graph(tmp_path)
    assert len(evidence) == EXPECTED_RECORD_COUNT


def test_projection_hash_matches_stable_fixture(tmp_path: Path) -> None:
    _, evidence = _graph(tmp_path)
    assert evidence_projection_hash(evidence) == EXPECTED_PROJECTION_HASH


def test_every_evidence_has_non_empty_claim_lineage(tmp_path: Path) -> None:
    _, evidence = _graph(tmp_path)
    for ev in evidence:
        assert len(ev.claim_lineage) >= 1, (
            f"empty claim_lineage for {ev.evidence_id}"
        )


def test_all_18_evidence_ids_from_yaml_appear_in_projection(tmp_path: Path) -> None:
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_ids = {r["evidence_id"] for r in yaml_doc.get("records") or []}

    _, evidence = _graph(tmp_path)
    projection_ids = {ev.evidence_id for ev in evidence}

    assert projection_ids == yaml_ids, (
        f"missing: {yaml_ids - projection_ids}, unexpected: {projection_ids - yaml_ids}"
    )


def test_all_projected_evidence_uses_verified_claim_proof_class(tmp_path: Path) -> None:
    _, evidence = _graph(tmp_path)
    wrong = [(ev.evidence_id, ev.proof_class) for ev in evidence if ev.proof_class != "verified_claim"]
    assert not wrong, f"non-downgraded proof classes: {wrong}"


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

def test_ingestion_is_idempotent(tmp_path: Path) -> None:
    graph_path = tmp_path / "candidate.sqlite3"

    ingest_human_evidence_schema(graph_path, YAML_PATH)
    evidence1 = candidate_graph_evidence(graph_path, as_of=AS_OF)
    hash1 = evidence_projection_hash(evidence1)

    ingest_human_evidence_schema(graph_path, YAML_PATH)
    evidence2 = candidate_graph_evidence(graph_path, as_of=AS_OF)
    hash2 = evidence_projection_hash(evidence2)

    assert hash1 == hash2 == EXPECTED_PROJECTION_HASH
    assert len(evidence1) == len(evidence2) == EXPECTED_RECORD_COUNT


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

def test_statement_tamper_is_detected_by_candidate_graph_evidence(tmp_path: Path) -> None:
    graph_path, _ = _graph(tmp_path)

    # Modify the statement in the DB without updating content_hash —
    # the approved_evidence_cannot_be_degraded trigger guards approval_state,
    # not the statement column, so the write succeeds.
    with sqlite3.connect(graph_path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            "UPDATE candidate_evidence "
            "SET statement='tampered statement for E-001' "
            "WHERE evidence_id='E-001'"
        )

    # candidate_graph_evidence validates sha256(statement) == content_hash in
    # the Evidence constructor; a mismatch raises ValueError.
    with pytest.raises(ValueError, match="content hash does not bind"):
        candidate_graph_evidence(graph_path, as_of=AS_OF)


def test_statement_tamper_is_detected_by_validate_ingestion_integrity(
    tmp_path: Path,
) -> None:
    graph_path, _ = _graph(tmp_path)

    # validate_ingestion_integrity passes on the original graph.
    validate_ingestion_integrity(graph_path, YAML_PATH)

    # Tamper the statement.
    with sqlite3.connect(graph_path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            "UPDATE candidate_evidence "
            "SET statement='tampered statement for E-002' "
            "WHERE evidence_id='E-002'"
        )

    with pytest.raises(ValueError, match="tamper detected"):
        validate_ingestion_integrity(graph_path, YAML_PATH)


# ---------------------------------------------------------------------------
# Author / verifier separation
# ---------------------------------------------------------------------------

def test_author_and_verifier_identities_are_distinct() -> None:
    assert AUTHOR_IDENTITY != VERIFIER_IDENTITY
    assert EXPECTED_HUMAN_AUTHORITY in AUTHOR_IDENTITY
    assert EXPECTED_HUMAN_AUTHORITY not in VERIFIER_IDENTITY


def test_evidence_provenance_uses_author_identity(tmp_path: Path) -> None:
    graph_path, _ = _graph(tmp_path)
    with sqlite3.connect(graph_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT p.source_identity
               FROM candidate_evidence e
               JOIN candidate_provenance p ON p.provenance_id = e.provenance_id
               WHERE e.evidence_id IN ('E-001','E-009','E-018')"""
        ).fetchall()
    assert len(rows) == 3
    for row in rows:
        assert str(row["source_identity"]) == AUTHOR_IDENTITY


def test_verification_decision_provenance_uses_verifier_identity(tmp_path: Path) -> None:
    graph_path, _ = _graph(tmp_path)
    with sqlite3.connect(graph_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT p.source_identity
               FROM candidate_verification_decisions d
               JOIN candidate_provenance p ON p.provenance_id = d.provenance_id
               WHERE d.target_kind='evidence'
                 AND d.target_id IN ('E-001','E-009','E-018')"""
        ).fetchall()
    assert len(rows) == 3
    for row in rows:
        assert str(row["source_identity"]) == VERIFIER_IDENTITY


def test_no_evidence_provenance_uses_verifier_identity(tmp_path: Path) -> None:
    graph_path, _ = _graph(tmp_path)
    with sqlite3.connect(graph_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT e.evidence_id, p.source_identity
               FROM candidate_evidence e
               JOIN candidate_provenance p ON p.provenance_id = e.provenance_id
               WHERE p.source_identity = ?""",
            (VERIFIER_IDENTITY,),
        ).fetchall()
    assert not rows, (
        f"evidence provenance must use author identity, "
        f"not verifier identity; found: {[dict(r) for r in rows]}"
    )


def test_no_decision_provenance_uses_author_identity(tmp_path: Path) -> None:
    graph_path, _ = _graph(tmp_path)
    with sqlite3.connect(graph_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT d.decision_id, p.source_identity
               FROM candidate_verification_decisions d
               JOIN candidate_provenance p ON p.provenance_id = d.provenance_id
               WHERE p.source_identity = ?""",
            (AUTHOR_IDENTITY,),
        ).fetchall()
    assert not rows, (
        f"verification decision provenance must use verifier identity, "
        f"not author identity; found: {[dict(r) for r in rows]}"
    )


# ---------------------------------------------------------------------------
# Schema / authority / status / hash validation (fail-closed)
# ---------------------------------------------------------------------------

def test_wrong_schema_version_rejected(tmp_path: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_doc["schema_version"] = "jaa05.candidate-evidence.v99"
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="schema_version"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


def test_wrong_human_authority_rejected(tmp_path: Path) -> None:
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_doc["human_authority"] = "impostor@example.com"
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="human_authority"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


def test_wrong_status_rejected(tmp_path: Path) -> None:
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_doc["status"] = "DRAFT"
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="status"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


def test_content_sha256_mismatch_rejected(tmp_path: Path) -> None:
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_doc["records"][0]["content_sha256"] = "a" * 64
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="content_sha256 mismatch"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


def test_source_packet_sha256_invalid_format_rejected(tmp_path: Path) -> None:
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_doc["source_packet_sha256"] = "not-a-hash"
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="source_packet_sha256"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


# ---------------------------------------------------------------------------
# Citation matching (Fable architecture: separate vacancy/candidate namespaces)
# ---------------------------------------------------------------------------

def _citation_requirement(requirement_id: str) -> Requirement:
    """Build a Requirement that accepts verified_claim proof class."""
    return Requirement(
        requirement_id=requirement_id,
        criterion="vacancy-criterion-not-a-claim-id",
        text="Citation-path test requirement (vacancy namespace distinct from claim IDs).",
        essential=True,
        gap_kind="evidence",
        bridge_policy="build_evidence",
        accepted_proof_classes=("verified_claim",),
        opportunity_weight_bp=5000,
        source_identity="vacancy:citation-test",
        source_span=(1, 10),
    )


def _citation_receipt(
    requirement: Requirement,
    evidence_map: dict,
    *,
    as_of: date,
    policy: MatchingPolicy,
) -> InferenceReceipt:
    profile_sha256 = evidence_projection_hash(evidence_map.values())
    return InferenceReceipt(
        provider="citation-test",
        model="citation-test-v1",
        prompt_sha256=hashlib.sha256(b"citation-test-prompt").hexdigest(),
        policy_sha256=policy.policy_hash,
        candidate_profile_sha256=profile_sha256,
        input_sha256=matching_input_hash(
            requirement,
            candidate_profile_sha256=profile_sha256,
            as_of=as_of,
        ),
    )


def test_citation_matching_accepts_valid_claim_lineage(tmp_path: Path) -> None:
    """evaluate_match accepts a citation whose claim_id appears in the evidence claim_lineage.

    This exercises the Fable-mandated citation path: the requirement criterion is in
    the vacancy namespace; the claim_id is in the candidate namespace; the two are linked
    only through the explicit (evidence_id, claim_id) citation binding.
    """
    _, evidence_tuple = _graph(tmp_path)
    evidence_map = {ev.evidence_id: ev for ev in evidence_tuple}

    ev = evidence_map["E-001"]
    assert ev.claim_lineage, "E-001 must have non-empty claim_lineage after ingestion"
    real_claim_id = ev.claim_lineage[0][0]

    policy = MatchingPolicy()
    requirement = _citation_requirement("R-citation-accept")

    proposal = MatchProposal(
        requirement_id="R-citation-accept",
        evidence_ids=("E-001",),
        confidence_bp=9000,
        basis="direct",
        rationale="Citation binds E-001 claim_lineage entry to the requirement.",
        receipt=_citation_receipt(requirement, evidence_map, as_of=AS_OF, policy=policy),
        citations=(("E-001", real_claim_id),),
    )

    result = evaluate_match(requirement, proposal, evidence_map, as_of=AS_OF, policy=policy)
    assert result.decision == "matched", f"expected matched, got {result.decision}: {result.reason}"
    assert "E-001" in result.evidence_ids


def test_wrong_lineage_claim_id_rejected(tmp_path: Path) -> None:
    """evaluate_match returns no_match when the cited claim_id is absent from claim_lineage.

    A claim_id invented by the proposer that does not appear in the evidence
    claim_lineage must be rejected deterministically, regardless of confidence.
    """
    _, evidence_tuple = _graph(tmp_path)
    evidence_map = {ev.evidence_id: ev for ev in evidence_tuple}

    policy = MatchingPolicy()
    requirement = _citation_requirement("R-wrong-lineage")

    proposal = MatchProposal(
        requirement_id="R-wrong-lineage",
        evidence_ids=("E-001",),
        confidence_bp=9999,
        basis="direct",
        rationale="Deliberately cites a claim_id not present in E-001 claim_lineage.",
        receipt=_citation_receipt(requirement, evidence_map, as_of=AS_OF, policy=policy),
        citations=(("E-001", "nonexistent-claim-not-in-lineage"),),
    )

    result = evaluate_match(requirement, proposal, evidence_map, as_of=AS_OF, policy=policy)
    assert result.decision == "no_match", (
        f"expected no_match for wrong claim_id, got {result.decision}: {result.reason}"
    )
    assert "claim_lineage" in result.reason


def test_citation_mixed_valid_invalid_releasability_is_no_match(tmp_path: Path) -> None:
    """evaluate_match returns no_match when any cited pair resolves lineage but is not releasable.

    Even if one (evidence, claim_id) pair fully qualifies, a second pair whose claim_id
    IS in lineage but whose evidence is not releasable must cause no_match.  Every cited
    pair must pass both the lineage-resolution check AND the releasability+proof-class
    check; a mix of passing and failing pairs is not sufficient for a match.
    """
    _, evidence_tuple = _graph(tmp_path)
    evidence_map = {ev.evidence_id: ev for ev in evidence_tuple}

    # E-001 is releasable and uses verified_claim proof class — this citation is valid.
    ev_valid = evidence_map["E-001"]
    valid_claim_id = ev_valid.claim_lineage[0][0]

    # Build a synthetic Evidence whose claim_id IS in its claim_lineage, but which is
    # NOT releasable (approval_state="pending", verification_decision="pending").
    _invalid_stmt = "synthetic non-releasable evidence for mixed-citation test"
    _invalid_sha = hashlib.sha256(_invalid_stmt.encode()).hexdigest()
    _invalid_claim_id = "claim-synthetic-nonreleasable"
    _invalid_claim_sha = hashlib.sha256(b"synthetic-claim-content-nonreleasable").hexdigest()
    ev_invalid = Evidence(
        evidence_id="E-NONRELEASABLE",
        version=1,
        statement=_invalid_stmt,
        demonstrates=(_invalid_claim_id,),
        proof_class="verified_claim",
        approval_state="pending",
        epistemic_state="evidence",
        verification_decision="pending",
        verification_method="test-method-nonreleasable",
        content_sha256=_invalid_sha,
        negative=False,
        claim_lineage=((_invalid_claim_id, 1, _invalid_claim_sha),),
    )
    evidence_map["E-NONRELEASABLE"] = ev_invalid

    policy = MatchingPolicy()
    requirement = _citation_requirement("R-mixed-releasability")

    proposal = MatchProposal(
        requirement_id="R-mixed-releasability",
        evidence_ids=("E-001", "E-NONRELEASABLE"),
        confidence_bp=9000,
        basis="direct",
        rationale=(
            "Cites one releasable evidence (E-001) and one whose claim resolves lineage "
            "but whose approval state is pending — must still be no_match."
        ),
        receipt=_citation_receipt(requirement, evidence_map, as_of=AS_OF, policy=policy),
        citations=(
            ("E-001", valid_claim_id),
            ("E-NONRELEASABLE", _invalid_claim_id),
        ),
    )

    result = evaluate_match(requirement, proposal, evidence_map, as_of=AS_OF, policy=policy)
    assert result.decision == "no_match", (
        f"expected no_match for mixed valid/non-releasable citations, "
        f"got {result.decision}: {result.reason}"
    )
    assert "not releasable" in result.reason or "ineligible" in result.reason or "pair" in result.reason


# ---------------------------------------------------------------------------
# Hardening: per-field negative tests (source_packet, locator bytes, secret,
# negative flag, valid_until, and preflight atomicity)
# ---------------------------------------------------------------------------

def test_source_packet_sha_declared_mismatch_rejected(tmp_path: Path) -> None:
    """A well-formed but wrong source_packet_sha256 at document root is rejected."""
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_doc["source_packet_sha256"] = "a" * 64  # valid hex length, wrong value
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="source_packet_sha256"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


def test_source_locator_packet_bytes_hash_mismatch_rejected(tmp_path: Path) -> None:
    """Ingestion is rejected when sha256(file at source_locator) diverges from the declared SHA.

    Constructs a tampered packet file and points every record's source_locator at it while
    leaving source_sha256 unchanged.  The declared-vs-declared check passes; only the
    independent bytes verification (step 7) raises.
    """
    tampered_packet = tmp_path / "tampered_packet.json"
    tampered_packet.write_bytes(b'{"tampered": true}')

    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    for record in yaml_doc["records"]:
        record["evidence_provenance"]["source_locator"] = str(tampered_packet)

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="packet content mismatch"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


def test_secret_bearing_statement_rejected(tmp_path: Path) -> None:
    """A record whose statement matches a secret pattern is rejected before any write."""
    secret_stmt = "Competent engineer. password=hunter2 mentioned in passing."
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_doc["records"][0]["statement"] = secret_stmt
    yaml_doc["records"][0]["content_sha256"] = hashlib.sha256(
        secret_stmt.encode("utf-8")
    ).hexdigest()
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="secret pattern"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


def test_negative_true_rejected(tmp_path: Path) -> None:
    """A record with negative=True is rejected (v1 supports only negative=false)."""
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_doc["records"][0]["negative"] = True
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="negative"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


def test_valid_until_nonnull_rejected(tmp_path: Path) -> None:
    """A record with any non-null valid_until is rejected (v1 requires null)."""
    yaml_doc = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    yaml_doc["records"][0]["valid_until"] = "2027-12-31"
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text(__import__("yaml").dump(yaml_doc), encoding="utf-8")
    graph_path = tmp_path / "graph.sqlite3"
    with pytest.raises(ValueError, match="valid_until"):
        ingest_human_evidence_schema(graph_path, bad_yaml)


def test_preflight_conflict_on_last_record_leaves_no_partial_rows(tmp_path: Path) -> None:
    """Preflight scans all 18 records before BEGIN IMMEDIATE; a conflict on E-018 prevents any write.

    Plants a conflicting row only for E-018 (the final record).  If preflight ran
    record-by-record inside the transaction, the first 17 records could be committed
    before the conflict is detected.  Because preflight runs entirely outside BEGIN
    IMMEDIATE, zero rows must be written for any of the 18 evidence IDs.
    """
    graph_path = tmp_path / "candidate.sqlite3"
    graph = CandidateGraph(graph_path)

    conflicting_statement = "conflicting statement for E-018 only"
    conflicting_hash = hashlib.sha256(conflicting_statement.encode()).hexdigest()

    conn = graph.connect()
    try:
        conn.execute("BEGIN")
        fake_prov_id = "prov-" + hashlib.sha256(b"test-e018-conflict-prov").hexdigest()[:24]
        fake_prov_hash = hashlib.sha256(b"test-e018-conflict-source").hexdigest()
        conn.execute(
            """INSERT INTO candidate_provenance(
                 provenance_id, source_identity, source_kind, source_hash,
                 source_locator, observed_at, metadata_json)
               VALUES(?, 'other-author', 'manual', ?, NULL,
                      '2026-01-01T00:00:00+00:00', '{}')""",
            (fake_prov_id, fake_prov_hash),
        )
        conn.execute(
            """INSERT INTO candidate_evidence(
                 evidence_id, version, evidence_kind, statement, source_identity,
                 epistemic_state, approval_state, negative, valid_until,
                 content_hash, provenance_id)
               VALUES('E-018', 1, 'document', ?, 'other-author',
                      'evidence', 'pending', 0, NULL, ?, ?)""",
            (conflicting_statement, conflicting_hash, fake_prov_id),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(ValueError, match="conflict"):
        ingest_human_evidence_schema(graph_path, YAML_PATH)

    conn = graph.connect()
    try:
        row = conn.execute(
            "SELECT statement FROM candidate_evidence WHERE evidence_id='E-018' AND version=1"
        ).fetchone()
        assert row is not None, "pre-planted E-018 row must still exist"
        assert str(row["statement"]) == conflicting_statement

        count = conn.execute(
            "SELECT COUNT(*) FROM candidate_evidence WHERE evidence_id != 'E-018'"
        ).fetchone()[0]
        assert count == 0, (
            f"partial ingestion occurred: {count} rows written for E-001..E-017 "
            f"before the E-018 conflict was raised"
        )
    finally:
        conn.close()


def test_conflicting_preexisting_evidence_row_prevents_ingestion(tmp_path: Path) -> None:
    """Preflight rejects ingestion when a pre-existing evidence row has a different statement.

    No partial target ingestion occurs: the 17 other evidence records are also absent
    because the preflight runs over all 18 rows before the write transaction is opened.
    """
    graph_path = tmp_path / "candidate.sqlite3"
    graph = CandidateGraph(graph_path)  # initialises schema via migrations

    # Insert a conflicting row for E-001 with a statement that does NOT match the YAML.
    conflicting_statement = "conflicting statement that does not match E-001 in YAML"
    conflicting_hash = hashlib.sha256(conflicting_statement.encode()).hexdigest()

    conn = graph.connect()
    try:
        conn.execute("BEGIN")
        fake_prov_id = "prov-" + hashlib.sha256(b"test-fake-evidence-prov").hexdigest()[:24]
        fake_prov_hash = hashlib.sha256(b"test-fake-source-content").hexdigest()
        conn.execute(
            """INSERT INTO candidate_provenance(
                 provenance_id, source_identity, source_kind, source_hash,
                 source_locator, observed_at, metadata_json)
               VALUES(?, 'other-author', 'manual', ?, NULL,
                      '2026-01-01T00:00:00+00:00', '{}')""",
            (fake_prov_id, fake_prov_hash),
        )
        conn.execute(
            """INSERT INTO candidate_evidence(
                 evidence_id, version, evidence_kind, statement, source_identity,
                 epistemic_state, approval_state, negative, valid_until,
                 content_hash, provenance_id)
               VALUES('E-001', 1, 'document', ?, 'other-author',
                      'evidence', 'pending', 0, NULL, ?, ?)""",
            (conflicting_statement, conflicting_hash, fake_prov_id),
        )
        conn.commit()
    finally:
        conn.close()

    # Ingestion must fail in the preflight stage — before the write transaction is opened.
    with pytest.raises(ValueError, match="conflict"):
        ingest_human_evidence_schema(graph_path, YAML_PATH)

    # Verify graph state: only the pre-planted conflicting row exists; the other 17
    # target evidence records were NOT inserted (no partial ingestion).
    conn = graph.connect()
    try:
        row = conn.execute(
            "SELECT statement FROM candidate_evidence WHERE evidence_id='E-001' AND version=1"
        ).fetchone()
        assert row is not None, "pre-planted E-001 row must still exist"
        assert str(row["statement"]) == conflicting_statement

        count = conn.execute(
            "SELECT COUNT(*) FROM candidate_evidence WHERE evidence_id != 'E-001'"
        ).fetchone()[0]
        assert count == 0, (
            f"partial ingestion occurred: {count} unexpected evidence rows were written"
        )
    finally:
        conn.close()
