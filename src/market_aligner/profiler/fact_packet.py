"""Strict source-bound packet serialization for native-selected facts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


_PROOF_CLASSES = frozenset(
    {
        "verified_claim",
        "work_artifact",
        "test_result",
        "external_outcome",
        "employment_record",
        "credential",
        "portfolio_artifact",
    }
)
_DOCUMENT_TARGETS = frozenset({"cv", "cover_letter"})
_SOURCE_HASH_KEYS = frozenset({"recovery_manifest", "profile", "evidence"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INVALID = "current_fact_packet_invalid"


def _invalid() -> None:
    raise ValueError(_INVALID)


def compile_selected_facts(
    records: list[dict[str, Any]],
    selection: list[dict[str, Any]],
    excluded_ids: list[str],
    source_hashes: dict[str, str],
) -> tuple[bytes, list[dict[str, str]]]:
    """Serialize an already-authorised native selection without granting authority."""
    if type(records) is not list or type(selection) is not list or type(excluded_ids) is not list:
        _invalid()
    if (
        type(source_hashes) is not dict
        or any(type(key) is not str for key in source_hashes)
        or set(source_hashes) != _SOURCE_HASH_KEYS
    ):
        _invalid()
    if any(
        type(value) is not str or _SHA256.fullmatch(value) is None
        for value in source_hashes.values()
    ):
        _invalid()

    by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        if type(record) is not dict:
            _invalid()
        evidence_id = record.get("evidence_id")
        claim = record.get("claim")
        status = record.get("status")
        if (
            type(evidence_id) is not str
            or not evidence_id
            or evidence_id != evidence_id.strip()
            or type(claim) is not str
            or not claim.strip()
            or type(status) is not str
            or status not in {"explicit", "verified", "inference", "unverified_current"}
            or evidence_id in by_id
        ):
            _invalid()
        by_id[evidence_id] = {"claim": claim, "status": status}

    excluded: set[str] = set()
    for evidence_id in excluded_ids:
        if (
            type(evidence_id) is not str
            or evidence_id not in by_id
            or evidence_id in excluded
        ):
            _invalid()
        excluded.add(evidence_id)

    if type(selection) is not list or not selection:
        _invalid()
    selected_ids: set[str] = set()
    statements: list[dict[str, Any]] = []
    bindings: list[dict[str, str]] = []
    for selected in selection:
        if (
            type(selected) is not dict
            or any(type(key) is not str for key in selected)
            or set(selected)
            != {"evidence_id", "proof_class", "document_targets"}
        ):
            _invalid()
        evidence_id = selected["evidence_id"]
        proof_class = selected["proof_class"]
        targets = selected["document_targets"]
        if (
            type(evidence_id) is not str
            or evidence_id in selected_ids
            or evidence_id in excluded
        ):
            _invalid()
        record = by_id.get(evidence_id)
        if (
            record is None
            or record["status"] not in {"explicit", "verified"}
            or type(proof_class) is not str
            or proof_class not in _PROOF_CLASSES
            or type(targets) is not list
            or not targets
            or any(
                type(target) is not str or target not in _DOCUMENT_TARGETS
                for target in targets
            )
            or len(set(targets)) != len(targets)
        ):
            _invalid()
        selected_ids.add(evidence_id)
        statement = record["claim"]
        try:
            statement_sha256 = hashlib.sha256(statement.encode("utf-8")).hexdigest()
        except UnicodeEncodeError:
            _invalid()
        statements.append(
            {
                "id": evidence_id,
                "kind": proof_class,
                "proof_class": proof_class,
                "statement": statement,
                "document_targets": sorted(targets),
            }
        )
        bindings.append(
            {
                "id": evidence_id,
                "kind": proof_class,
                "proof_class": proof_class,
                "statement_sha256": statement_sha256,
            }
        )

    packet = {
        "schema_version": "market-aligner.current-factual-statements.v1",
        "source_hashes": dict(source_hashes),
        "statements": statements,
    }
    try:
        packet_bytes = (
            json.dumps(
                packet,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        _invalid()
    return packet_bytes, bindings
