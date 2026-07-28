#!/usr/bin/env python3
"""Install private human evidence once and publish a hash-only JAA-05 receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.evidence_matching import (  # noqa: E402
    candidate_graph_evidence,
    evidence_projection_hash,
)
from career_automation.human_evidence_ingestion import (  # noqa: E402
    EXPECTED_HUMAN_AUTHORITY_SHA256,
    EXPECTED_RECORD_COUNT,
    EXPECTED_SOURCE_PACKET_SHA256,
    ingest_human_evidence_schema,
    validate_ingestion_integrity,
)
from tracked_source_revision import (  # noqa: E402
    TrackedSourceRevisionError,
    source_content_revision,
    source_content_revision_contract,
    source_git_revision,
    source_git_revision_contract,
)


FORMAT = "jaa05-human-evidence-production-ingestion/v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
AS_OF = "2027-01-01"
STATE_TABLES = {
    "candidate_provenance": "provenance_id",
    "candidate_evidence": "evidence_id,version",
    "candidate_claims": "claim_id,version",
    "candidate_claim_edges": "edge_id",
    "candidate_verification_decisions": "decision_id",
}
SOURCE_PATHS = (
    "career_automation/candidate_graph.py",
    "career_automation/evidence_matching.py",
    "career_automation/human_evidence_ingestion.py",
    "career_automation/migrations.py",
    "scripts/certify_jaa05_human_evidence.py",
)


class CertificationError(RuntimeError):
    """The private production ingestion could not be certified."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CertificationError(message)


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _no_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    for component in (absolute, *absolute.parents):
        require(not component.is_symlink(), "output path may not resolve through a symlink")


def _table_state(connection: sqlite3.Connection, table: str, order_by: str) -> dict[str, Any]:
    columns = [
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    ]
    require(bool(columns), f"missing production table: {table}")
    rows = connection.execute(
        f"SELECT * FROM {table} ORDER BY {order_by}"
    ).fetchall()
    canonical_rows = [
        {column: row[column] for column in columns}
        for row in rows
    ]
    return {
        "row_count": len(canonical_rows),
        "content_sha256": hashlib.sha256(_canonical_bytes(canonical_rows)).hexdigest(),
    }


def _graph_state(graph_path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{graph_path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        require(integrity == "ok", "production graph integrity check failed")
        schema_rows = connection.execute(
            """SELECT type,name,tbl_name,sql
               FROM sqlite_master
               WHERE sql IS NOT NULL
               ORDER BY type,name"""
        ).fetchall()
        schema = [
            {
                "type": str(row["type"]),
                "name": str(row["name"]),
                "table": str(row["tbl_name"]),
                "sql": str(row["sql"]),
            }
            for row in schema_rows
        ]
        tables = {
            table: _table_state(connection, table, order_by)
            for table, order_by in STATE_TABLES.items()
        }
    finally:
        connection.close()
    return {
        "integrity_check": integrity,
        "schema_sha256": hashlib.sha256(_canonical_bytes(schema)).hexdigest(),
        "tables": tables,
    }


def _source_hashes() -> dict[str, str]:
    return {path: _sha256(ROOT / path) for path in SOURCE_PATHS}


def _publish(directory: Path, payload: bytes) -> Path:
    _no_symlink_components(directory)
    directory.mkdir(parents=True, exist_ok=True)
    _no_symlink_components(directory)
    digest = hashlib.sha256(payload).hexdigest()
    destination = directory / f"sha256-{digest}.json"
    existing = sorted(directory.glob("*.json"))
    require(not existing, "refusing to overwrite or add a second production receipt")
    descriptor, name = tempfile.mkstemp(prefix=".jaa05-ingestion-", dir=directory)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
        os.chmod(destination, 0o444)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    require(
        destination.is_file()
        and not destination.is_symlink()
        and destination.read_bytes() == payload,
        "published production receipt bytes differ",
    )
    return destination


def certify(
    *,
    graph_path: Path,
    evidence_path: Path,
    receipt_directory: Path,
    expected_evidence_sha256: str,
    expected_projection_sha256: str,
) -> Path:
    require(
        HEX64.fullmatch(expected_evidence_sha256) is not None,
        "expected evidence SHA-256 is invalid",
    )
    require(
        HEX64.fullmatch(expected_projection_sha256) is not None,
        "expected projection SHA-256 is invalid",
    )
    require(
        evidence_path.is_file() and not evidence_path.is_symlink(),
        "private evidence input is missing or not a regular file",
    )
    _no_symlink_components(graph_path)
    require(not graph_path.exists(), "production graph path must be absent for one-shot ingestion")
    require(graph_path.parent.is_dir(), "production graph parent directory is missing")
    evidence_sha256 = _sha256(evidence_path)
    require(
        evidence_sha256 == expected_evidence_sha256,
        "private evidence SHA-256 mismatch",
    )
    try:
        git_revision = source_git_revision(ROOT)
        content_revision = source_content_revision(ROOT)
    except TrackedSourceRevisionError as exc:
        raise CertificationError(str(exc)) from exc
    source_hashes = _source_hashes()

    previous_umask = os.umask(0o077)
    try:
        first_summary = ingest_human_evidence_schema(graph_path, evidence_path)
        validate_ingestion_integrity(graph_path, evidence_path)
        first_projection = candidate_graph_evidence(
            graph_path,
            as_of=__import__("datetime").date.fromisoformat(AS_OF),
        )
        first_projection_sha256 = evidence_projection_hash(first_projection)
        first_state = _graph_state(graph_path)

        second_summary = ingest_human_evidence_schema(graph_path, evidence_path)
        validate_ingestion_integrity(graph_path, evidence_path)
        second_projection = candidate_graph_evidence(
            graph_path,
            as_of=__import__("datetime").date.fromisoformat(AS_OF),
        )
        second_projection_sha256 = evidence_projection_hash(second_projection)
        second_state = _graph_state(graph_path)
    finally:
        os.umask(previous_umask)

    require(
        first_summary == second_summary,
        "idempotent ingestion summaries differ",
    )
    require(
        first_projection_sha256
        == second_projection_sha256
        == expected_projection_sha256,
        "production evidence projection SHA-256 mismatch",
    )
    require(
        len(first_projection) == len(second_projection) == EXPECTED_RECORD_COUNT,
        "production projection record count differs",
    )
    require(first_state == second_state, "production graph state changed on idempotent replay")
    require(
        first_state["tables"]["candidate_evidence"]["row_count"]
        == first_state["tables"]["candidate_claims"]["row_count"]
        == first_state["tables"]["candidate_claim_edges"]["row_count"]
        == first_state["tables"]["candidate_verification_decisions"]["row_count"]
        == EXPECTED_RECORD_COUNT,
        "production graph authority row counts differ",
    )
    require(
        _sha256(evidence_path) == evidence_sha256,
        "private evidence bytes changed during ingestion",
    )
    try:
        require(
            source_git_revision(ROOT) == git_revision
            and source_content_revision(ROOT) == content_revision,
            "tracked source changed during production ingestion",
        )
    except TrackedSourceRevisionError as exc:
        raise CertificationError(str(exc)) from exc
    require(_source_hashes() == source_hashes, "bound source file changed during ingestion")
    os.chmod(graph_path, 0o600)

    document = {
        "format": FORMAT,
        "runtime": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
        },
        "source_git_revision": git_revision,
        "source_git_revision_contract": source_git_revision_contract(),
        "source_content_revision": content_revision,
        "source_content_revision_contract": source_content_revision_contract(),
        "source_files": source_hashes,
        "private_evidence": {
            "location_class": "private_operator_supplied_ignored_input",
            "sha256": evidence_sha256,
            "record_count": EXPECTED_RECORD_COUNT,
            "human_authority_sha256": EXPECTED_HUMAN_AUTHORITY_SHA256,
            "source_packet_sha256": EXPECTED_SOURCE_PACKET_SHA256,
        },
        "production_graph": {
            "location_class": "private_operator_data",
            "file_sha256": _sha256(graph_path),
            "mode": "0600",
            "projection_as_of": AS_OF,
            "projection_sha256": first_projection_sha256,
            "projection_record_count": len(first_projection),
            "state": first_state,
        },
        "idempotency": {
            "executions": 2,
            "summary_sha256": hashlib.sha256(
                _canonical_bytes(first_summary)
            ).hexdigest(),
            "projection_sha256_equal": True,
            "graph_state_equal": True,
        },
        "claims": {
            "installs_private_evidence_into_jaa02_authority_graph": True,
            "all_evidence_and_claim_rows_approved": True,
            "receipt_contains_candidate_statements": False,
            "receipt_contains_raw_human_authority": False,
            "receipt_contains_host_paths": False,
            "certifies_jaa05_slice": False,
        },
    }
    payload = _canonical_bytes(document)
    return _publish(receipt_directory, payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--receipt-directory", required=True)
    parser.add_argument("--expected-evidence-sha256", required=True)
    parser.add_argument("--expected-projection-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        receipt = certify(
            graph_path=Path(args.graph),
            evidence_path=Path(args.evidence),
            receipt_directory=Path(args.receipt_directory),
            expected_evidence_sha256=args.expected_evidence_sha256,
            expected_projection_sha256=args.expected_projection_sha256,
        )
    except (CertificationError, OSError, sqlite3.DatabaseError, UnicodeError) as exc:
        print(f"jaa05-human-evidence-certification: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(
        {
            "receipt": receipt.name,
            "receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
            "status": "production_ingestion_receipted_not_slice_certified",
        },
        sort_keys=True,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
