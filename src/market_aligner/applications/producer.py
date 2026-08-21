"""Small, deterministic producer from persisted assessment state to JAA handoff v1."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from market_aligner.applications.handoff import (
    HandoffEnvelope,
    canonical_json_bytes,
    encode_handoff_v1,
)
from market_aligner.research.store import AssessmentStore

_MANIFEST_KEYS = {
    "assessment_receipt_sha256",
    "candidate_intent_sha256",
    "created_at",
    "eligibility",
    "employer_dossier_sha256",
    "evidence_ledger_sha256",
    "producer_commit_sha",
    "selection",
    "vacancy",
}


class HandoffProducerError(ValueError):
    """The persisted assessment and supplied evidence manifest cannot form a handoff."""


@dataclass(frozen=True)
class HandoffReference:
    """One typed object to place in the protected MA outbox."""

    exact_bytes: bytes
    type_id: str
    schema_version: str
    subject: Mapping[str, str]
    issued_at: str
    valid_until: str | None
    issuer_id: str = "market-aligner"


@dataclass(frozen=True)
class WrittenHandoffBundle:
    path: Path
    source_record_sha256: str
    manifest_sha256: str
    handoff_root_sha256: str


def _write_exact(path: Path, value: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


def _private_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HandoffProducerError(f"{label} is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise HandoffProducerError(f"{label} is not an owner-private directory")


def _exact_private_file(path: Path, expected: bytes) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise HandoffProducerError(
            "content-addressed bundle replay is incomplete"
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise HandoffProducerError(
            "content-addressed bundle replay bytes or mode differ"
        )
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
        with os.fdopen(descriptor, "rb") as handle:
            current = os.fstat(handle.fileno())
            actual = handle.read()
    except OSError as exc:
        raise HandoffProducerError(
            "content-addressed bundle replay is incomplete"
        ) from exc
    if (
        current.st_dev != metadata.st_dev
        or current.st_ino != metadata.st_ino
        or actual != expected
    ):
        raise HandoffProducerError(
            "content-addressed bundle replay bytes or identity differ"
        )


def _verify_exact_private_bundle(
    destination: Path, expected_files: Mapping[Path, bytes]
) -> None:
    _private_directory(destination, "content-addressed bundle")
    for category in ("objects", "metadata"):
        _private_directory(destination / category, f"bundle {category} category")
    expected_root = {
        "context.json",
        "handoff.json",
        "manifest.json",
        "metadata",
        "objects",
        "source-record.json",
    }
    if {path.name for path in destination.iterdir()} != expected_root:
        raise HandoffProducerError("content-addressed bundle replay file set differs")
    for category in ("objects", "metadata"):
        expected_names = {
            relative.name
            for relative in expected_files
            if relative.parts[0] == category
        }
        if {path.name for path in (destination / category).iterdir()} != expected_names:
            raise HandoffProducerError(
                f"content-addressed bundle replay {category} set differs"
            )
    for relative, exact in expected_files.items():
        _exact_private_file(destination / relative, exact)


def _reference_metadata(
    *,
    reference_key: str,
    reference: HandoffReference,
    object_sha256: str,
    handoff_root_sha256: str,
    producer_commit_sha: str,
    trust_root_id: str,
) -> bytes:
    proof_basis = {
        "handoff_root_sha256": handoff_root_sha256,
        "issued_at": reference.issued_at,
        "issuer_id": reference.issuer_id,
        "object_sha256": object_sha256,
        "producer_commit_sha": producer_commit_sha,
        "reference_key": reference_key,
        "schema_version": reference.schema_version,
        "subject": dict(reference.subject),
        "trust_root_id": trust_root_id,
        "type_id": reference.type_id,
        "valid_until": reference.valid_until,
    }
    return canonical_json_bytes(
        {
            "issued_at": reference.issued_at,
            "issuer_id": reference.issuer_id,
            "object_sha256": object_sha256,
            "reference_key": reference_key,
            "schema_version": reference.schema_version,
            "subject": dict(reference.subject),
            "trust_proof_sha256": hashlib.sha256(
                canonical_json_bytes(proof_basis)
            ).hexdigest(),
            "trust_root_id": trust_root_id,
            "type_id": reference.type_id,
            "valid_until": reference.valid_until,
        }
    )


def write_protected_handoff_bundle(
    output_root: str | Path,
    handoff: HandoffEnvelope,
    *,
    references: Mapping[str, HandoffReference],
    environment: str,
    trust_root_id: str,
    issued_at: str,
    source_job_key: str,
) -> WrittenHandoffBundle:
    """Create or verify one content-addressed protected-local-outbox bundle.

    The bundle contains no credential.  JAA must be configured with the exact
    ``source_record_sha256`` and producer commit before it can authenticate it.
    Replaying identical inputs returns the existing immutable directory.
    """

    if environment not in {"production", "synthetic"}:
        raise HandoffProducerError("bundle environment is unsupported")
    if not references:
        raise HandoffProducerError("bundle requires typed reference objects")
    payload = handoff.payload
    handoff_bytes = getattr(handoff, "exact_bytes", None)
    if handoff_bytes is None:
        handoff_bytes = getattr(handoff, "original_bytes", None)
    if not isinstance(handoff_bytes, bytes) or not handoff_bytes:
        raise HandoffProducerError("handoff exact bytes are unavailable")
    producer_commit = payload["producer"]["commit_sha"]
    handoff_root = handoff.root_sha256
    rows: list[dict[str, str]] = []
    materialized: list[tuple[str, bytes, bytes, str, str]] = []
    for key in sorted(references):
        reference = references[key]
        if not isinstance(reference, HandoffReference) or not reference.exact_bytes:
            raise HandoffProducerError(f"reference {key!r} is invalid")
        object_sha = hashlib.sha256(reference.exact_bytes).hexdigest()
        metadata = _reference_metadata(
            reference_key=key,
            reference=reference,
            object_sha256=object_sha,
            handoff_root_sha256=handoff_root,
            producer_commit_sha=producer_commit,
            trust_root_id=trust_root_id,
        )
        metadata_sha = hashlib.sha256(metadata).hexdigest()
        rows.append(
            {
                "metadata_sha256": metadata_sha,
                "object_sha256": object_sha,
                "reference_key": key,
            }
        )
        materialized.append(
            (key, reference.exact_bytes, metadata, object_sha, metadata_sha)
        )
    source_record = {
        "entries": rows,
        "handoff_root_sha256": handoff_root,
        "producer_commit_sha": producer_commit,
        "schema_version": "market-aligner.protected-outbox-source-record.v1",
        "source_job_key": source_job_key,
        "trust_root_id": trust_root_id,
    }
    source_record_bytes = canonical_json_bytes(source_record)
    source_record_sha = hashlib.sha256(source_record_bytes).hexdigest()
    context_basis = {
        "environment": environment,
        "handoff_root_sha256": handoff_root,
        "issued_at": issued_at,
        "producer_commit_sha": producer_commit,
        "producer_product": "market-aligner",
        "source_record_sha256": source_record_sha,
        "trust_mode": "protected_local_outbox",
        "trust_root_id": trust_root_id,
    }
    context = dict(context_basis)
    context["trust_proof_sha256"] = hashlib.sha256(
        canonical_json_bytes(context_basis)
    ).hexdigest()
    context_bytes = canonical_json_bytes(context)
    manifest = {
        "context_sha256": hashlib.sha256(context_bytes).hexdigest(),
        "handoff_root_sha256": handoff_root,
        "schema_version": "market-aligner.protected-handoff-bundle.v1",
        "source_record_sha256": source_record_sha,
    }
    manifest_bytes = canonical_json_bytes(manifest)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    expected_files: dict[Path, bytes] = {
        Path("context.json"): context_bytes,
        Path("handoff.json"): handoff_bytes,
        Path("manifest.json"): manifest_bytes,
        Path("source-record.json"): source_record_bytes,
    }
    for _key, exact, metadata, object_sha, metadata_sha in materialized:
        object_path = Path("objects") / object_sha
        prior = expected_files.setdefault(object_path, exact)
        if prior != exact:
            raise HandoffProducerError("content-addressed reference object collision")
        expected_files[Path("metadata") / metadata_sha] = metadata
    root = Path(output_root).resolve()
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    _private_directory(root, "protected outbox root")
    bundles = root / "bundles"
    bundles.mkdir(mode=0o700, exist_ok=True)
    _private_directory(bundles, "protected bundle category")
    destination = bundles / source_record_sha
    if destination.exists() or destination.is_symlink():
        _verify_exact_private_bundle(destination, expected_files)
        return WrittenHandoffBundle(
            destination, source_record_sha, manifest_sha, handoff_root
        )
    temporary = Path(tempfile.mkdtemp(prefix=".handoff-", dir=root))
    os.chmod(temporary, 0o700)
    try:
        (temporary / "objects").mkdir(mode=0o700)
        (temporary / "metadata").mkdir(mode=0o700)
        for relative, exact in sorted(
            expected_files.items(), key=lambda item: str(item[0])
        ):
            _write_exact(temporary / relative, exact)
        os.replace(temporary, destination)
        _verify_exact_private_bundle(destination, expected_files)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return WrittenHandoffBundle(
        destination, source_record_sha, manifest_sha, handoff_root
    )


def _exact_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HandoffProducerError("handoff manifest must be an object")
    if set(value) != _MANIFEST_KEYS:
        missing = sorted(_MANIFEST_KEYS - set(value))
        extra = sorted(set(value) - _MANIFEST_KEYS)
        raise HandoffProducerError(
            f"handoff manifest keys differ; missing={missing}, extra={extra}"
        )
    return dict(value)


def produce_handoff(
    store: AssessmentStore,
    *,
    profile_id: str,
    profile_version: str,
    job_key: str,
    manifest: Mapping[str, Any],
    handoff_job_key: str | None = None,
) -> HandoffEnvelope:
    """Read one admitted score and compose its exact, hash-bound v1 wire document.

    The caller supplies evidence identities and vacancy facts, while every score,
    profile identity, opportunity decision, and selection-policy identity is read
    back from durable Market Aligner state.
    """

    inputs = _exact_manifest(manifest)
    row = store.assessment(profile_id, job_key)
    if row["opportunity_decision"] != "pass":
        raise HandoffProducerError("handoff requires a persisted opportunity-gate pass")
    if not isinstance(row["policy_hash"], str) or len(row["policy_hash"]) != 64:
        raise HandoffProducerError("persisted opportunity policy is not SHA-256-bound")
    if row["extraction_confidence"] is None:
        raise HandoffProducerError("handoff requires persisted extraction confidence")
    try:
        promotion = store.processing_promotion(profile_id, job_key)
    except KeyError as exc:
        raise HandoffProducerError(
            "handoff requires a canonical processing assessment promotion"
        ) from exc
    try:
        promotion_document = json.loads(bytes(promotion["receipt_bytes"]))
        promotion_body = dict(promotion_document)
        promotion_body.pop("receipt_sha256", None)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise HandoffProducerError(
            "canonical processing promotion is malformed"
        ) from exc
    if (
        promotion["score_payload_hash"] != row["score_payload_hash"]
        or promotion["policy_hash"] != row["policy_hash"]
        or row["opportunity_reason"]
        != f"processing-promotion:{promotion['receipt_sha256']}"
        or hashlib.sha256(canonical_json_bytes(promotion_body)).hexdigest()
        != promotion["receipt_sha256"]
        or promotion_document.get("receipt_sha256") != promotion["receipt_sha256"]
    ):
        raise HandoffProducerError(
            "canonical processing promotion differs from assessment"
        )

    try:
        score = json.loads(row["score_payload_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise HandoffProducerError("persisted score payload is invalid") from exc
    if score.get("profile_id") != profile_id or score.get("job_key") != job_key:
        raise HandoffProducerError(
            "persisted score identity differs from requested handoff"
        )
    for score_key, row_key in (
        ("fit", "fit"),
        ("opportunity", "opportunity"),
        ("final", "final_score"),
    ):
        if float(score.get(score_key, -1)) != float(row[row_key]):
            raise HandoffProducerError(
                f"persisted {score_key} projection differs from its row"
            )

    selection = inputs["selection"]
    if not isinstance(selection, Mapping):
        raise HandoffProducerError("selection manifest must be an object")
    if selection.get("selection_policy_sha256") != row["policy_hash"]:
        raise HandoffProducerError(
            "selection policy differs from the persisted gate policy"
        )

    vacancy = inputs["vacancy"]
    if not isinstance(vacancy, Mapping):
        raise HandoffProducerError("vacancy manifest must be an object")
    provenance = vacancy.get("provenance")
    if (
        not isinstance(provenance, Mapping)
        or provenance.get("canonical_url") != row["url"]
    ):
        raise HandoffProducerError("vacancy URL differs from the persisted assessment")
    if (
        vacancy.get("role_title") != row["title"]
        or vacancy.get("company_name") != row["company"]
    ):
        raise HandoffProducerError(
            "vacancy title or company differs from the persisted assessment"
        )

    wire_job_key = handoff_job_key or job_key
    payload = {
        "assessment": {
            "assessment_receipt_sha256": inputs["assessment_receipt_sha256"],
            "extraction_confidence": float(row["extraction_confidence"]),
            "final": float(row["final_score"]) / 100.0,
            "fit": float(row["fit"]),
            "fit_components": score["fit_subscores"],
            "fit_status": row["fit_status"],
            "opportunity": float(row["opportunity"]),
            "opportunity_components": score["opportunity_subscores"],
            "scoring_parameters_sha256": score["parameters_hash"],
        },
        "candidate_intent_sha256": inputs["candidate_intent_sha256"],
        "created_at": inputs["created_at"],
        "eligibility": inputs["eligibility"],
        "employer_dossier_sha256": inputs["employer_dossier_sha256"],
        "evidence_ledger_sha256": inputs["evidence_ledger_sha256"],
        "job_key": wire_job_key,
        "producer": {
            "commit_sha": inputs["producer_commit_sha"],
            "product": "market-aligner",
        },
        "profile_id": profile_id,
        "profile_version": profile_version,
        "selection": selection,
        "vacancy": vacancy,
    }
    return encode_handoff_v1(payload)


def write_handoff(path: str | Path, handoff: HandoffEnvelope) -> None:
    """Atomically write the exact wire bytes to the explicitly selected output."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(handoff.exact_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
