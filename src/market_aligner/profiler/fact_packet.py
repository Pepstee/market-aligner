"""Strict source-bound packet serialization for native-selected facts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from market_aligner.profiler.schema import validate_profile_id


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


def _canonical_document_bytes(value: object) -> bytes:
    try:
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
    except (TypeError, ValueError, UnicodeEncodeError):
        _invalid()


def _valid_sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def validate_current_profile_binding(
    receipt: object,
    authority: object,
    *,
    profile_id: str,
    profile_sha256: str,
    evidence_ledger_sha256: str,
) -> None:
    """Bind a current-projection authority and receipt to the live snapshot."""
    invalid = "current_profile_binding_invalid"
    if type(receipt) is not dict or type(authority) is not dict:
        raise ValueError(invalid)
    try:
        validate_profile_id(profile_id)
    except (TypeError, ValueError):
        raise ValueError(invalid) from None
    if not _valid_sha256(profile_sha256) or not _valid_sha256(evidence_ledger_sha256):
        raise ValueError(invalid)
    if (
        receipt.get("schema") != "market-aligner.current-profile-projection.v1"
        or receipt.get("release_authority") is not False
        or authority.get("schema_version") != "jaa.production-candidate-authority.v2"
        or authority.get("source_kind") != "approved_current_profile_activation"
        or any(
            authority.get(flag) is not False
            for flag in (
                "application_authority",
                "release_authority",
                "submission_authority",
            )
        )
    ):
        raise ValueError(invalid)
    binding = authority.get("profile_binding")
    if (
        type(binding) is not dict
        or set(binding)
        != {"profile_id", "profile_sha256", "evidence_ledger_sha256"}
    ):
        raise ValueError(invalid)
    expected = {
        "profile_id": profile_id,
        "profile_sha256": profile_sha256,
        "evidence_ledger_sha256": evidence_ledger_sha256,
    }
    for key, wanted in expected.items():
        if (
            type(binding[key]) is not str
            or binding[key] != wanted
            or type(receipt.get(key)) is not str
            or receipt[key] != wanted
        ):
            raise ValueError(invalid)


def serialize_projection_documents(
    *,
    profile_id: str,
    activation_sha256: str,
    packet_bytes: bytes,
    bindings: list[dict[str, str]],
    source_hashes: dict[str, str],
    profile_sha256: str,
    evidence_ledger_sha256: str,
) -> dict[str, bytes]:
    """Bind a validated current-facts packet to existing candidate schemas."""
    try:
        validate_profile_id(profile_id)
    except (TypeError, ValueError):
        _invalid()
    if (
        not _valid_sha256(activation_sha256)
        or not _valid_sha256(profile_sha256)
        or not _valid_sha256(evidence_ledger_sha256)
        or type(packet_bytes) is not bytes
        or type(bindings) is not list
        or type(source_hashes) is not dict
        or any(type(key) is not str for key in source_hashes)
        or set(source_hashes) != _SOURCE_HASH_KEYS
        or any(not _valid_sha256(value) for value in source_hashes.values())
    ):
        _invalid()
    try:
        packet = json.loads(packet_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        _invalid()
    if (
        type(packet) is not dict
        or set(packet) != {"schema_version", "source_hashes", "statements"}
        or packet.get("schema_version") != "market-aligner.current-factual-statements.v1"
        or packet.get("source_hashes") != source_hashes
        or type(packet.get("statements")) is not list
        or not packet["statements"]
        or _canonical_document_bytes(packet) != packet_bytes
        or len(bindings) != len(packet["statements"])
    ):
        _invalid()

    normalized_bindings: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for statement, binding in zip(packet["statements"], bindings, strict=True):
        if (
            type(statement) is not dict
            or set(statement)
            != {"id", "kind", "proof_class", "statement", "document_targets"}
            or type(statement.get("id")) is not str
            or not statement["id"]
            or statement["id"] in seen_ids
            or type(statement.get("kind")) is not str
            or statement["kind"] not in _PROOF_CLASSES
            or statement.get("proof_class") != statement["kind"]
            or type(statement.get("statement")) is not str
            or not statement["statement"].strip()
            or type(statement.get("document_targets")) is not list
            or not statement["document_targets"]
            or any(
                type(target) is not str or target not in _DOCUMENT_TARGETS
                for target in statement["document_targets"]
            )
            or statement["document_targets"]
            != sorted(set(statement["document_targets"]))
            or type(binding) is not dict
            or any(type(key) is not str for key in binding)
            or set(binding)
            != {"id", "kind", "proof_class", "statement_sha256"}
            or binding.get("id") != statement["id"]
            or binding.get("kind") != statement["kind"]
            or binding.get("proof_class") != statement["proof_class"]
            or not _valid_sha256(binding.get("statement_sha256"))
        ):
            _invalid()
        try:
            statement_sha256 = hashlib.sha256(
                statement["statement"].encode("utf-8")
            ).hexdigest()
        except UnicodeEncodeError:
            _invalid()
        if binding["statement_sha256"] != statement_sha256:
            _invalid()
        seen_ids.add(statement["id"])
        normalized_bindings.append(
            {
                "id": binding["id"],
                "kind": binding["kind"],
                "proof_class": binding["proof_class"],
                "statement_sha256": binding["statement_sha256"],
            }
        )

    packet_sha256 = hashlib.sha256(packet_bytes).hexdigest()
    projection_body: dict[str, Any] = {
        "schema_version": "jaa.candidate-authority-projection.v1",
        "source_hashes": {
            "approved_evidence": packet_sha256,
            "current_profile_activation": activation_sha256,
            "recovery_manifest": source_hashes["recovery_manifest"],
            "profile": source_hashes["profile"],
            "evidence": source_hashes["evidence"],
        },
        "approved_evidence": normalized_bindings,
    }
    projection_body["projection_sha256"] = hashlib.sha256(
        _canonical_document_bytes(projection_body)
    ).hexdigest()
    projection_bytes = _canonical_document_bytes(projection_body)
    authority_bytes = _canonical_document_bytes(
        {
            "schema_version": "jaa.production-candidate-authority.v2",
            "source_kind": "approved_current_profile_activation",
            "activation_sha256": activation_sha256,
            "profile_binding": {
                "profile_id": profile_id,
                "profile_sha256": profile_sha256,
                "evidence_ledger_sha256": evidence_ledger_sha256,
            },
            "candidate_projection": projection_body,
            "application_authority": False,
            "release_authority": False,
            "submission_authority": False,
        }
    )
    receipt_bytes = _canonical_document_bytes(
        {
            "schema": "market-aligner.current-profile-projection.v1",
            "profile_id": profile_id,
            "activation_sha256": activation_sha256,
            "authority_sha256": hashlib.sha256(authority_bytes).hexdigest(),
            "authority_projection_sha256": projection_body["projection_sha256"],
            "evidence_packet_sha256": packet_sha256,
            "profile_sha256": profile_sha256,
            "evidence_ledger_sha256": evidence_ledger_sha256,
            "release_authority": False,
        }
    )
    documents = {
        "evidence_packet_bytes": packet_bytes,
        "candidate_projection_bytes": projection_bytes,
        "candidate_authority_bytes": authority_bytes,
        "profile_projection_receipt_bytes": receipt_bytes,
    }
    validate_current_profile_projection_receipt(
        receipt_bytes,
        profile_id=profile_id,
        activation_sha256=activation_sha256,
        evidence_packet_bytes=packet_bytes,
        candidate_projection_bytes=projection_bytes,
        candidate_authority_bytes=authority_bytes,
        profile_sha256=profile_sha256,
        evidence_ledger_sha256=evidence_ledger_sha256,
    )
    return documents


def validate_current_profile_projection_receipt(
    receipt_bytes: bytes,
    *,
    profile_id: str,
    activation_sha256: str,
    evidence_packet_bytes: bytes,
    candidate_projection_bytes: bytes,
    candidate_authority_bytes: bytes,
    profile_sha256: str,
    evidence_ledger_sha256: str,
) -> dict[str, Any]:
    """Verify the explicit non-release receipt against all emitted documents."""
    invalid = "current_profile_projection_receipt_invalid"
    if any(
        type(value) is not bytes
        for value in (
            receipt_bytes,
            evidence_packet_bytes,
            candidate_projection_bytes,
            candidate_authority_bytes,
        )
    ):
        raise ValueError(invalid)
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8", errors="strict"))
        projection = json.loads(
            candidate_projection_bytes.decode("utf-8", errors="strict")
        )
        authority = json.loads(candidate_authority_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(invalid) from None
    required = {
        "schema",
        "profile_id",
        "activation_sha256",
        "authority_sha256",
        "authority_projection_sha256",
        "evidence_packet_sha256",
        "profile_sha256",
        "evidence_ledger_sha256",
        "release_authority",
    }
    projection_body = dict(projection) if type(projection) is dict else {}
    projection_sha256 = projection_body.pop("projection_sha256", None)
    try:
        computed_projection_sha256 = hashlib.sha256(
            _canonical_document_bytes(projection_body)
        ).hexdigest()
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ValueError(invalid) from None
    if (
        type(receipt) is not dict
        or set(receipt) != required
        or receipt.get("schema") != "market-aligner.current-profile-projection.v1"
        or receipt.get("profile_id") != profile_id
        or receipt.get("activation_sha256") != activation_sha256
        or receipt.get("authority_sha256")
        != hashlib.sha256(candidate_authority_bytes).hexdigest()
        or type(projection) is not dict
        or set(projection)
        != {
            "schema_version",
            "source_hashes",
            "approved_evidence",
            "projection_sha256",
        }
        or projection.get("schema_version")
        != "jaa.candidate-authority-projection.v1"
        or not _valid_sha256(projection_sha256)
        or projection_sha256 != computed_projection_sha256
        or receipt.get("authority_projection_sha256")
        != projection_sha256
        or receipt.get("evidence_packet_sha256")
        != hashlib.sha256(evidence_packet_bytes).hexdigest()
        or receipt.get("profile_sha256") != profile_sha256
        or receipt.get("evidence_ledger_sha256") != evidence_ledger_sha256
        or receipt.get("release_authority") is not False
        or _canonical_document_bytes(receipt) != receipt_bytes
        or _canonical_document_bytes(projection) != candidate_projection_bytes
        or type(authority) is not dict
        or authority.get("schema_version") != "jaa.production-candidate-authority.v2"
        or authority.get("source_kind") != "approved_current_profile_activation"
        or authority.get("activation_sha256") != activation_sha256
        or authority.get("candidate_projection") != projection
        or authority.get("application_authority") is not False
        or authority.get("release_authority") is not False
        or authority.get("submission_authority") is not False
    ):
        raise ValueError(invalid)
    try:
        validate_current_profile_binding(
            receipt,
            authority,
            profile_id=profile_id,
            profile_sha256=profile_sha256,
            evidence_ledger_sha256=evidence_ledger_sha256,
        )
    except ValueError:
        raise ValueError(invalid) from None
    return receipt
