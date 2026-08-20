"""Deterministic ingestion of human-authored candidate evidence records into JAA-02 graph.

Reads profiler/data/candidate_evidence.yaml, validates schema/hashes/authority/status,
maps records into CandidateGraph, creates stable claim IDs and edges, and performs
deterministic independent verification with a verifier identity distinct from the human
author.

Proof-class downgrade rules (conservative, per JAA-05 Fable ruling):
- employment_record, credential: self-attested without external documentary proof
  → evidence_kind="document" → "verified_claim" in production projection.
- portfolio_artifact, test_result: no bound artefact/test provenance in this packet
  → evidence_kind="document" → "verified_claim" in production projection.

All 18 records use "document" evidence_kind so that the proof class in the evidence
projection is "verified_claim", not the staged proof_class label from the packet.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import yaml

from .candidate_graph import CandidateGraph, DEFAULT_SECRET_PATTERNS


# ---------------------------------------------------------------------------
# Policy / identity constants
# ---------------------------------------------------------------------------

INGESTION_SCHEMA_VERSION = "jaa05.candidate-evidence.v1"
EXPECTED_HUMAN_AUTHORITY_SHA256 = (
    "9cb26a0478b64bf8c5b63c602e7ad454cc79d2d4a81e93d4d3298ac7046c207b"
)
EXPECTED_STATUS = "HUMAN_AUTHORED_AND_APPROVED"
EXPECTED_RECORD_COUNT = 18
EXPECTED_SOURCE_PACKET_SHA256 = "074f036ea50a89bf75402a923fa1be1ddb6f583f385095d73fb96b61c8562eff"
KNOWN_INPUT_PROOF_CLASSES = frozenset({
    "verified_claim",
    "work_artifact",
    "test_result",
    "external_outcome",
    "employment_record",
    "credential",
    "portfolio_artifact",
})

INGESTION_POLICY_ID = "jaa05.human-evidence-ingestion.v1"
INGESTION_POLICY_VERSION = "1"

# Human author identity: the person who wrote and approved the evidence packet.
AUTHOR_IDENTITY = (
    f"jaa05:human-author:sha256:{EXPECTED_HUMAN_AUTHORITY_SHA256}:20260728"
)

# Verifier identity: the deterministic ingestion verifier, DISTINCT from human author.
VERIFIER_IDENTITY = "jaa05:deterministic-ingestion-verifier:v1"

assert AUTHOR_IDENTITY != VERIFIER_IDENTITY, "author and verifier identities must differ"

# Conservative downgrade: every human-authored record maps to "document" evidence_kind.
# The production evidence projection therefore yields "verified_claim" proof class for
# all 18 records.  Stronger proof classes (credential, employment_record,
# portfolio_artifact, test_result) are NOT used because no external documentary proof
# or bound artefact/test provenance is present in this ingestion packet.
EVIDENCE_KIND = "document"

# Fixed observation timestamp to keep provenance records deterministic across runs.
_OBSERVED_AT = "2026-07-28T00:00:00+00:00"

_SECRET_PATTERNS = tuple(re.compile(p) for p in DEFAULT_SECRET_PATTERNS)


def _check_no_secret(text: str, evidence_id: str) -> None:
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            raise ValueError(
                f"secret pattern detected in statement for {evidence_id}: "
                f"matched {pattern.pattern!r}"
            )


def _authority_sha256(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Internal helpers — mirror CandidateGraph._hash/_identifier/_provenance
# for direct SQL access (needed for idempotent INSERT OR IGNORE).
# ---------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _hash(value: Any) -> str:
    payload = value if isinstance(value, str) else _canonical(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _identifier(prefix: str, *parts: Any) -> str:
    return f"{prefix}-{_hash(parts)[:24]}"


def _compute_policy_hash() -> str:
    return _hash({
        "policy_id": INGESTION_POLICY_ID,
        "policy_version": INGESTION_POLICY_VERSION,
        "schema": INGESTION_SCHEMA_VERSION,
    })


INGESTION_POLICY_HASH: str = _compute_policy_hash()


def _insert_provenance(
    connection: sqlite3.Connection,
    *,
    source_identity: str,
    source_kind: str,
    source_locator: str | None,
    source_content: Any,
) -> str:
    """INSERT OR IGNORE a provenance record; return its stable, deterministic ID."""
    source_hash = _hash(source_content)
    provenance_id = _identifier("prov", source_identity, source_hash)
    connection.execute(
        """INSERT OR IGNORE INTO candidate_provenance(
             provenance_id,source_identity,source_kind,source_hash,source_locator,
             observed_at,metadata_json) VALUES(?,?,?,?,?,?,?)""",
        (
            provenance_id, source_identity, source_kind, source_hash,
            source_locator, _OBSERVED_AT, "{}",
        ),
    )
    return provenance_id


def _preflight_existing_rows(
    connection: sqlite3.Connection,
    records: list[dict],
    source_packet_sha256: str,
) -> None:
    """Check all 18 target rows for pre-existing conflicts before any writes begin.

    For each of the 18 records, if a row already exists with the target primary key in
    candidate_evidence, candidate_claims, candidate_claim_edges, or
    candidate_verification_decisions, every material field must exactly match the
    intended value.  Any mismatch raises ValueError before the transaction is opened.
    """
    for record in records:
        evidence_id = record["evidence_id"]
        version = int(record.get("version") or 1)
        statement = record["statement"]
        content_sha256 = record["content_sha256"]
        claim_id = f"claim-{evidence_id}"

        reason = (
            f"deterministic verification: content_sha256 bound to statement, "
            f"human_authority_sha256={EXPECTED_HUMAN_AUTHORITY_SHA256}, "
            f"status={EXPECTED_STATUS}, "
            f"schema={INGESTION_SCHEMA_VERSION}, "
            f"source_packet_sha256={source_packet_sha256}"
        )
        decision_content = {"policy_hash": INGESTION_POLICY_HASH, "reason": reason}
        decision_id = _identifier("decision", evidence_id, version, INGESTION_POLICY_HASH, "approved")

        expected_evidence_prov_id = _identifier("prov", AUTHOR_IDENTITY, _hash(statement))
        expected_verifier_prov_id = _identifier("prov", VERIFIER_IDENTITY, _hash(decision_content))
        expected_claim_prov_id = _identifier(
            "prov", AUTHOR_IDENTITY,
            _hash({"kind": "claim", "evidence_id": evidence_id, "statement": statement}),
        )
        edge_id = _identifier("edge", claim_id, 1, evidence_id, version, "demonstrated_by")
        expected_edge_prov_id = _identifier(
            "prov", AUTHOR_IDENTITY,
            _hash({"claim": claim_id, "evidence": evidence_id, "type": "demonstrated_by"}),
        )

        row = connection.execute(
            "SELECT evidence_kind, statement, content_hash, source_identity, "
            "epistemic_state, approval_state, negative, valid_until, provenance_id "
            "FROM candidate_evidence WHERE evidence_id=? AND version=?",
            (evidence_id, version),
        ).fetchone()
        if row is not None:
            if (
                str(row["evidence_kind"]) != EVIDENCE_KIND
                or str(row["statement"]) != statement
                or str(row["content_hash"]) != content_sha256
                or str(row["source_identity"]) != AUTHOR_IDENTITY
                or str(row["epistemic_state"]) != "evidence"
                or str(row["approval_state"]) not in {"pending", "approved"}
                or int(row["negative"]) != 0
                or row["valid_until"] is not None
                or str(row["provenance_id"]) != expected_evidence_prov_id
            ):
                raise ValueError(
                    f"pre-existing candidate_evidence row conflicts with intended "
                    f"ingestion contract for {evidence_id}:{version}"
                )

        row = connection.execute(
            "SELECT claim_type, statement, epistemic_state, approval_state, "
            "valid_until, provenance_id "
            "FROM candidate_claims WHERE claim_id=? AND version=1",
            (claim_id,),
        ).fetchone()
        if row is not None:
            if (
                str(row["claim_type"]) != "human_authored_claim"
                or str(row["statement"]) != statement
                or str(row["epistemic_state"]) != "evidence"
                or str(row["approval_state"]) not in {"pending", "approved"}
                or row["valid_until"] is not None
                or str(row["provenance_id"]) != expected_claim_prov_id
            ):
                raise ValueError(
                    f"pre-existing candidate_claims row conflicts with intended "
                    f"ingestion contract for {claim_id}:1"
                )

        row = connection.execute(
            "SELECT claim_id, claim_version, edge_type, evidence_id, "
            "evidence_version, provenance_id "
            "FROM candidate_claim_edges WHERE edge_id=?",
            (edge_id,),
        ).fetchone()
        if row is not None:
            if (
                str(row["claim_id"]) != claim_id
                or int(row["claim_version"]) != 1
                or str(row["edge_type"]) != "demonstrated_by"
                or str(row["evidence_id"]) != evidence_id
                or int(row["evidence_version"]) != version
                or str(row["provenance_id"]) != expected_edge_prov_id
            ):
                raise ValueError(
                    f"pre-existing candidate_claim_edges row conflicts with intended "
                    f"ingestion contract for edge {edge_id}"
                )

        row = connection.execute(
            "SELECT target_kind, target_id, target_version, decision, verifier_kind, "
            "policy_id, policy_version, policy_hash, provenance_id "
            "FROM candidate_verification_decisions WHERE decision_id=?",
            (decision_id,),
        ).fetchone()
        if row is not None:
            if (
                str(row["target_kind"]) != "evidence"
                or str(row["target_id"]) != evidence_id
                or int(row["target_version"]) != version
                or str(row["decision"]) != "approved"
                or str(row["verifier_kind"]) != "deterministic"
                or str(row["policy_id"]) != INGESTION_POLICY_ID
                or str(row["policy_version"]) != INGESTION_POLICY_VERSION
                or str(row["policy_hash"]) != INGESTION_POLICY_HASH
                or str(row["provenance_id"]) != expected_verifier_prov_id
            ):
                raise ValueError(
                    f"pre-existing candidate_verification_decisions row conflicts with "
                    f"intended ingestion contract for {decision_id}"
                )


def _ingest_one(
    connection: sqlite3.Connection,
    *,
    evidence_id: str,
    version: int,
    statement: str,
    content_sha256: str,
    yaml_path_str: str,
    source_packet_sha256: str,
) -> None:
    """Idempotently ingest one record into the JAA-02 graph in the correct order.

    Operation sequence (respects trigger ordering constraints):
    1. Insert evidence provenance (human author)
    2. INSERT OR IGNORE evidence (pending)
    3. Insert verifier provenance
    4. INSERT OR IGNORE verification decision (approved)
    5. UPDATE evidence → approved  (trigger checks decision exists)
    6. Insert claim provenance (human author, distinct content)
    7. INSERT OR IGNORE claim (pending)
    8. Insert edge provenance
    9. INSERT OR IGNORE claim-evidence edge (demonstrated_by)
    10. UPDATE claim → approved  (trigger checks approved evidence via edge)
    """
    reason = (
        f"deterministic verification: content_sha256 bound to statement, "
        f"human_authority_sha256={EXPECTED_HUMAN_AUTHORITY_SHA256}, "
        f"status={EXPECTED_STATUS}, "
        f"schema={INGESTION_SCHEMA_VERSION}, "
        f"source_packet_sha256={source_packet_sha256}"
    )
    decision_content = {"policy_hash": INGESTION_POLICY_HASH, "reason": reason}
    decision_id = _identifier("decision", evidence_id, version, INGESTION_POLICY_HASH, "approved")
    claim_id = f"claim-{evidence_id}"

    # 1. Evidence provenance (human author, source_content = statement text)
    evidence_prov_id = _insert_provenance(
        connection,
        source_identity=AUTHOR_IDENTITY,
        source_kind="human_authored_evidence",
        source_locator=yaml_path_str,
        source_content=statement,
    )

    # 2. Insert evidence with approval_state='pending'
    connection.execute(
        """INSERT OR IGNORE INTO candidate_evidence(
             evidence_id,version,evidence_kind,statement,source_identity,
             epistemic_state,approval_state,negative,valid_until,content_hash,provenance_id)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            evidence_id, version, EVIDENCE_KIND, statement, AUTHOR_IDENTITY,
            "evidence", "pending", 0, None, content_sha256, evidence_prov_id,
        ),
    )

    # 3. Verifier provenance (deterministic verifier — identity distinct from author)
    verifier_prov_id = _insert_provenance(
        connection,
        source_identity=VERIFIER_IDENTITY,
        source_kind="verification",
        source_locator=None,
        source_content=decision_content,
    )

    # 4. Verification decision (INSERT OR IGNORE — already idempotent in verify_evidence)
    connection.execute(
        """INSERT OR IGNORE INTO candidate_verification_decisions(
             decision_id,target_kind,target_id,target_version,decision,verifier_kind,
             policy_id,policy_version,policy_hash,reason,provenance_id)
           VALUES(?,'evidence',?,?,?,?,?,?,?,?,?)""",
        (
            decision_id, evidence_id, version, "approved", "deterministic",
            INGESTION_POLICY_ID, INGESTION_POLICY_VERSION, INGESTION_POLICY_HASH,
            reason, verifier_prov_id,
        ),
    )

    # 5. Promote evidence → approved (trigger checks decision exists; WHERE guards idempotency)
    connection.execute(
        """UPDATE candidate_evidence
           SET approval_state='approved'
           WHERE evidence_id=? AND version=? AND approval_state='pending'""",
        (evidence_id, version),
    )

    # 6. Claim provenance (author, distinct source_content from evidence provenance)
    claim_prov_id = _insert_provenance(
        connection,
        source_identity=AUTHOR_IDENTITY,
        source_kind="human_authored_claim",
        source_locator=yaml_path_str,
        source_content={"kind": "claim", "evidence_id": evidence_id, "statement": statement},
    )

    # 7. Insert claim with approval_state='pending'
    connection.execute(
        """INSERT OR IGNORE INTO candidate_claims(
             claim_id,version,claim_type,statement,epistemic_state,approval_state,
             valid_until,provenance_id)
           VALUES(?,?,?,?,?,?,?,?)""",
        (
            claim_id, 1, "human_authored_claim", statement, "evidence", "pending",
            None, claim_prov_id,
        ),
    )

    # 8. Edge provenance
    edge_prov_id = _insert_provenance(
        connection,
        source_identity=AUTHOR_IDENTITY,
        source_kind="claim_evidence_edge",
        source_locator=yaml_path_str,
        source_content={"claim": claim_id, "evidence": evidence_id, "type": "demonstrated_by"},
    )

    # 9. Insert claim-evidence edge (INSERT OR IGNORE)
    edge_id = _identifier("edge", claim_id, 1, evidence_id, version, "demonstrated_by")
    connection.execute(
        """INSERT OR IGNORE INTO candidate_claim_edges(
             edge_id,claim_id,claim_version,edge_type,evidence_id,
             evidence_version,provenance_id)
           VALUES(?,?,?,?,?,?,?)""",
        (edge_id, claim_id, 1, "demonstrated_by", evidence_id, version, edge_prov_id),
    )

    # 10. Promote claim → approved (trigger checks approved evidence via edge; WHERE guards)
    connection.execute(
        """UPDATE candidate_claims
           SET approval_state='approved'
           WHERE claim_id=? AND version=1 AND approval_state='pending'""",
        (claim_id,),
    )


def _assert_all_approved(
    connection: sqlite3.Connection,
    records: list[dict[str, Any]],
) -> None:
    failures: list[str] = []
    for record in records:
        evidence_id = str(record["evidence_id"])
        evidence_version = int(record.get("version") or 1)
        claim_id = f"claim-{evidence_id}"
        evidence = connection.execute(
            "SELECT approval_state FROM candidate_evidence "
            "WHERE evidence_id=? AND version=?",
            (evidence_id, evidence_version),
        ).fetchone()
        if evidence is None or str(evidence["approval_state"]) != "approved":
            failures.append(f"evidence:{evidence_id}:{evidence_version}")
        claim = connection.execute(
            "SELECT approval_state FROM candidate_claims "
            "WHERE claim_id=? AND version=1",
            (claim_id,),
        ).fetchone()
        if claim is None or str(claim["approval_state"]) != "approved":
            failures.append(f"claim:{claim_id}:1")
    if failures:
        raise ValueError(
            "ingestion did not produce approved evidence and claims for every record: "
            f"{failures}"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ingest_human_evidence_schema(
    graph_path: str | Path,
    yaml_path: str | Path,
) -> dict[str, Any]:
    """Idempotently ingest the human-authored evidence YAML into the JAA-02 graph.

    Validates schema version, human authority, status, source packet SHA-256, and
    per-record content hashes before writing anything to the graph.  Each record is
    inserted with INSERT OR IGNORE so repeated calls produce identical graph state.

    Returns a summary dict; raises ValueError for any validation failure.
    """
    yaml_path = Path(yaml_path)
    raw_text = yaml_path.read_text(encoding="utf-8")
    document = yaml.safe_load(raw_text)

    if not isinstance(document, dict):
        raise ValueError("evidence YAML root must be a mapping")

    # --- Top-level schema / authority / status validation ---
    schema_version = document.get("schema_version", "")
    if schema_version != INGESTION_SCHEMA_VERSION:
        raise ValueError(
            f"unexpected schema_version: {schema_version!r} "
            f"(expected {INGESTION_SCHEMA_VERSION!r})"
        )

    human_authority = document.get("human_authority", "")
    if _authority_sha256(human_authority) != EXPECTED_HUMAN_AUTHORITY_SHA256:
        raise ValueError("unexpected human_authority SHA-256 binding")

    status = document.get("status", "")
    if status != EXPECTED_STATUS:
        raise ValueError(
            f"unexpected status: {status!r} (expected {EXPECTED_STATUS!r})"
        )

    source_packet_sha256 = document.get("source_packet_sha256", "")
    if source_packet_sha256 != EXPECTED_SOURCE_PACKET_SHA256:
        raise ValueError(
            f"source_packet_sha256 mismatch: {source_packet_sha256!r} "
            f"(expected {EXPECTED_SOURCE_PACKET_SHA256!r})"
        )

    records = list(document.get("records") or [])
    if len(records) != EXPECTED_RECORD_COUNT:
        raise ValueError(
            f"expected {EXPECTED_RECORD_COUNT} records, got {len(records)}"
        )

    # --- Per-record content hash, authority, v1-constraint, secret, and locator validation ---
    for record in records:
        evidence_id = record.get("evidence_id", "<unknown>")
        statement = record.get("statement", "")
        content_sha256 = record.get("content_sha256", "")

        computed = hashlib.sha256(statement.encode("utf-8")).hexdigest()
        if content_sha256 != computed:
            raise ValueError(
                f"content_sha256 mismatch for {evidence_id}: "
                f"declared={content_sha256!r}, computed={computed!r}"
            )

        # v1 supports only negative=false; anything else is invalid.
        negative = record.get("negative")
        if negative is not False:
            raise ValueError(
                f"negative must be false for v1 (got {negative!r}) in {evidence_id}"
            )

        # v1 supports only valid_until=null; anything else is invalid.
        valid_until = record.get("valid_until")
        if valid_until is not None:
            raise ValueError(
                f"valid_until must be null for v1 (got {valid_until!r}) in {evidence_id}"
            )

        # Secret screening — fail before any write.
        _check_no_secret(statement, evidence_id)

        approval_state = record.get("approval_state")
        if approval_state != "approved":
            raise ValueError(
                f"approval_state must be approved for {evidence_id}"
            )
        verification_decision = record.get("verification_decision")
        if verification_decision != "approved":
            raise ValueError(
                f"verification_decision must be approved for {evidence_id}"
            )
        epistemic_state = record.get("epistemic_state")
        if epistemic_state != "evidence":
            raise ValueError(
                f"epistemic_state must be evidence for {evidence_id}"
            )
        proof_class = record.get("proof_class")
        if proof_class not in KNOWN_INPUT_PROOF_CLASSES:
            raise ValueError(
                f"proof_class is not recognized for {evidence_id}"
            )

        prov = record.get("evidence_provenance") or {}
        record_authority = prov.get("human_authority", "")
        if _authority_sha256(record_authority) != EXPECTED_HUMAN_AUTHORITY_SHA256:
            raise ValueError(
                f"authority SHA-256 mismatch in evidence_provenance for {evidence_id}"
            )
        record_packet_sha256 = prov.get("source_sha256", "")
        if record_packet_sha256 != source_packet_sha256:
            raise ValueError(
                f"source_sha256 mismatch in evidence_provenance for {evidence_id}: "
                f"declared={record_packet_sha256!r}, expected={source_packet_sha256!r}"
            )

        # Independently verify the packet file bytes hash to the pinned value.
        source_locator = prov.get("source_locator", "")
        if not source_locator:
            raise ValueError(
                f"evidence_provenance.source_locator missing for {evidence_id}"
            )
        locator_path = Path(source_locator)
        if not locator_path.exists():
            raise ValueError(
                f"evidence_provenance.source_locator does not exist for {evidence_id}: "
                f"{source_locator!r}"
            )
        locator_hash = hashlib.sha256(locator_path.read_bytes()).hexdigest()
        if locator_hash != EXPECTED_SOURCE_PACKET_SHA256:
            raise ValueError(
                f"packet content mismatch for {evidence_id}: "
                f"sha256({source_locator!r})={locator_hash!r}, "
                f"expected {EXPECTED_SOURCE_PACKET_SHA256!r}"
            )

    # --- Write to JAA-02 graph (single transaction, idempotent) ---
    graph = CandidateGraph(graph_path)
    yaml_path_str = str(yaml_path.resolve())

    connection = graph.connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        # Acquire the write lock before preflight so no concurrent writer can
        # insert a conflicting row between validation and INSERT OR IGNORE.
        _preflight_existing_rows(connection, records, source_packet_sha256)
        for record in records:
            _ingest_one(
                connection,
                evidence_id=record["evidence_id"],
                version=int(record.get("version") or 1),
                statement=record["statement"],
                content_sha256=record["content_sha256"],
                yaml_path_str=yaml_path_str,
                source_packet_sha256=source_packet_sha256,
            )
        _assert_all_approved(connection, records)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    return {
        "schema": INGESTION_SCHEMA_VERSION,
        "records_ingested": EXPECTED_RECORD_COUNT,
        "policy_id": INGESTION_POLICY_ID,
        "author_identity": AUTHOR_IDENTITY,
        "verifier_identity": VERIFIER_IDENTITY,
    }


def validate_ingestion_integrity(
    graph_path: str | Path,
    yaml_path: str | Path,
) -> None:
    """Verify that every ingested evidence record's content_hash matches sha256(statement).

    Raises ValueError if any record's stored content_hash diverges from sha256(statement),
    indicating that the graph has been tampered with after ingestion.
    """
    yaml_path = Path(yaml_path)
    document = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    yaml_records = {r["evidence_id"]: r for r in (document.get("records") or [])}

    graph = CandidateGraph(graph_path)
    connection = graph.connect()
    try:
        rows = connection.execute(
            "SELECT evidence_id, version, statement, content_hash FROM candidate_evidence"
        ).fetchall()
    finally:
        connection.close()

    for row in rows:
        evidence_id = str(row["evidence_id"])
        if evidence_id not in yaml_records:
            continue
        statement = str(row["statement"])
        stored_hash = str(row["content_hash"])
        computed = hashlib.sha256(statement.encode("utf-8")).hexdigest()
        if stored_hash != computed:
            raise ValueError(
                f"tamper detected: content_hash does not match sha256(statement) "
                f"for {evidence_id}: stored={stored_hash!r}, computed={computed!r}"
            )
        yaml_hash = yaml_records[evidence_id]["content_sha256"]
        if stored_hash != yaml_hash:
            raise ValueError(
                f"tamper detected: graph content_hash diverges from YAML content_sha256 "
                f"for {evidence_id}: stored={stored_hash!r}, yaml={yaml_hash!r}"
            )
