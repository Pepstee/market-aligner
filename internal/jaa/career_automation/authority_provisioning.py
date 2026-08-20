"""Operator-only provisioning of preparation authority on Gigabyte."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .candidate_contact_authority import (
    ATTESTATION,
    ENROLLED_OPERATOR_PUBLIC_KEY_SHA256,
    REGISTRY_ATTESTATION,
    REGISTRY_SCHEMA_VERSION,
    SCHEMA_VERSION,
)
from .current_time import (
    AuthenticatedCurrentTimeWitness,
    installed_production_current_time_witness,
    obtain_current_time,
)
from .evidence_matching import canonical_json
from .provider_observation_capture import exact_committed_source_identity


CONTACT_KEY_ENV = "JAA_OPERATOR_CONTACT_PRIVATE_KEY"
CONTACT_SCHEMA = "jaa.gigabyte-contact-provisioning.v1"
TIME_SCHEMA = "jaa.gigabyte-current-time-provisioning.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _protected_directory(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("provisioning root must be an absolute non-symlink path")
    if path.exists():
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        if not resolved.is_dir() or metadata.st_uid != os.geteuid():
            raise ValueError("provisioning root has the wrong owner or type")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("provisioning root is not operator-only")
        return resolved
    parent = path.parent.resolve(strict=True)
    resolved = parent / path.name
    resolved.mkdir(mode=0o700)
    return resolved


def _directory(path: Path) -> Path:
    if path.exists():
        if path.is_symlink() or not path.is_dir() or stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ValueError("provisioning directory is unsafe")
    else:
        path.mkdir(mode=0o700)
    return path


def _create_or_exact(path: Path, value: bytes) -> None:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file():
            raise ValueError("provisioned object path is unsafe")
        if stat.S_IMODE(path.stat().st_mode) != 0o600 or path.read_bytes() != value:
            raise ValueError("provisioned object replay differs")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Gigabyte UTC clock returned a naive observation")
    return value.astimezone(timezone.utc)


def _candidate_contact(value: bytes, expected_sha256: str) -> dict[str, object]:
    if not _SHA256.fullmatch(expected_sha256) or _sha256(value) != expected_sha256:
        raise ValueError("approved candidate authority hash differs")
    try:
        document = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("approved candidate authority is invalid JSON") from exc
    if not isinstance(document, dict) or value != _bytes(document):
        raise ValueError("approved candidate authority is not canonical JSON")
    projection = document.get("candidate_projection")
    contact = projection.get("contact") if isinstance(projection, Mapping) else None
    if not isinstance(contact, dict) or set(contact) != {"full_name", "email", "phone", "city"}:
        raise ValueError("approved candidate authority has no exact contact projection")
    if any(not isinstance(contact[key], str) for key in ("full_name", "email", "city")):
        raise ValueError("approved candidate contact projection is malformed")
    if contact["phone"] is not None and not isinstance(contact["phone"], str):
        raise ValueError("approved candidate contact projection is malformed")
    return contact


def _private_key(repository: Path, configured: str | None) -> tuple[Ed25519PrivateKey, str]:
    path_value = configured or os.environ.get(CONTACT_KEY_ENV)
    if not path_value:
        raise ValueError(f"missing Gigabyte contact signing trust root: {CONTACT_KEY_ENV}")
    path = Path(path_value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("contact signing key path is unsafe")
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not resolved.is_file()
        or repository == resolved
        or repository in resolved.parents
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("contact signing key is not protected local authority")
    loaded = serialization.load_pem_private_key(resolved.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("contact signing key is not Ed25519")
    public = loaded.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    identity = _sha256(public)
    if identity != ENROLLED_OPERATOR_PUBLIC_KEY_SHA256:
        raise ValueError("contact signing key does not match enrolled trust root")
    return loaded, identity


def _signed(private_key: Ed25519PrivateKey, payload: dict[str, object], identity: str) -> tuple[dict[str, object], str]:
    signed = {
        **payload,
        "signature_base64": base64.b64encode(private_key.sign(_bytes(payload))).decode(),
    }
    digest = _sha256(_bytes(signed))
    return {**signed, identity: digest}, digest


def provision_contact_authority(
    *,
    candidate_authority_path: Path,
    candidate_authority_sha256: str,
    output_root: Path,
    repository_root: Path,
    private_key_path: str | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    repository = repository_root.resolve(strict=True)
    source = candidate_authority_path.resolve(strict=True)
    if repository == source or repository in source.parents or source.is_symlink():
        raise ValueError("candidate authority must be protected state outside the repository")
    contact = _candidate_contact(source.read_bytes(), candidate_authority_sha256)
    private_key, signer_sha256 = _private_key(repository, private_key_path)
    manifest_path = output_root / "contact-provisioning-manifest.json"
    replay_issued_at: str | None = None
    if manifest_path.exists() and not manifest_path.is_symlink():
        try:
            replay = json.loads(manifest_path.read_bytes())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("contact provisioning replay manifest is invalid") from exc
        if (
            not isinstance(replay, dict)
            or manifest_path.read_bytes() != _bytes(replay)
            or replay.get("candidate_authority_sha256") != candidate_authority_sha256
            or replay.get("candidate_authority_path") != str(source)
            or replay.get("scope") != "preparation_contact_authority_only"
            or replay.get("release_authority") is not False
            or not isinstance(replay.get("issued_at"), str)
        ):
            raise ValueError("contact provisioning replay differs")
        replay_issued_at = replay["issued_at"]
    root = _protected_directory(output_root)
    authorities = _directory(root / "authorities")
    registries = _directory(root / "registry")
    issued = replay_issued_at or _utc(clock()).replace(microsecond=0).isoformat()
    authority_payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_explicit_operator_attestation",
        "operator_attestation": ATTESTATION,
        "issued_at": issued,
        "record_id": "operator-contact-primary",
        "record_version": 1,
        "contact": contact,
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": signer_sha256,
    }
    authority, authority_sha256 = _signed(private_key, authority_payload, "authority_sha256")
    authority_path = authorities / f"{authority_sha256}.json"
    _create_or_exact(authority_path, _bytes(authority))
    registry_payload: dict[str, object] = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_operator_contact_registry",
        "operator_attestation": REGISTRY_ATTESTATION,
        "issued_at": issued,
        "registry_id": "operator-contact-primary",
        "registry_version": 1,
        "current": {"record_id": "operator-contact-primary", "record_version": 1, "authority_sha256": authority_sha256},
        "revoked_authority_sha256s": [],
        "prior_registry_sha256": None,
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": signer_sha256,
    }
    registry, registry_sha256 = _signed(private_key, registry_payload, "registry_sha256")
    registry_path = registries / f"{registry_sha256}.json"
    _create_or_exact(registry_path, _bytes(registry))
    manifest = {
        "schema_version": CONTACT_SCHEMA,
        "candidate_authority_sha256": candidate_authority_sha256,
        "candidate_authority_path": str(source),
        "contact_authority_sha256": authority_sha256,
        "contact_authority_path": str(authority_path),
        "contact_registry_sha256": registry_sha256,
        "contact_registry_path": str(registry_path),
        "issued_at": issued,
        "provenance": "exact approved candidate authority contact projection",
        "release_authority": False,
        "scope": "preparation_contact_authority_only",
        "signer_public_key_sha256": signer_sha256,
    }
    manifest_path = root / "contact-provisioning-manifest.json"
    _create_or_exact(manifest_path, _bytes(manifest))
    return {**manifest, "manifest_path": str(manifest_path)}


def provision_current_time(
    *,
    output_root: Path,
    repository_root: Path,
    subject_sha256: str,
    witness: AuthenticatedCurrentTimeWitness | None = None,
    utc_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    monotonic_clock: Callable[[], int] = time.monotonic_ns,
    maximum_clock_skew_seconds: int = 5,
) -> dict[str, object]:
    if not _SHA256.fullmatch(subject_sha256):
        raise ValueError("time provisioning subject must be SHA-256")
    selected = witness or installed_production_current_time_witness()
    before_mono = monotonic_clock()
    before_utc = _utc(utc_clock())
    evidence = obtain_current_time(
        selected,
        environment=selected.environment,
        purpose="preparation_authority",
        subject_sha256=subject_sha256,
        maximum_clock_skew_seconds=maximum_clock_skew_seconds,
    )
    after_utc = _utc(utc_clock())
    after_mono = monotonic_clock()
    if after_mono < before_mono or after_utc < before_utc:
        raise ValueError("Gigabyte clock rollback detected during provisioning")
    if not before_utc <= evidence.instant <= after_utc:
        skew = min(abs((evidence.instant - before_utc).total_seconds()), abs((evidence.instant - after_utc).total_seconds()))
        if skew > maximum_clock_skew_seconds:
            raise ValueError("Gigabyte current-time witness drift or staleness detected")
    runtime = exact_committed_source_identity(repository_root)
    python_path = Path(sys.executable).resolve(strict=True)
    root = _protected_directory(output_root)
    receipts = _directory(root / "time-receipts")
    manifests = _directory(root / "time-manifests")
    for prior_path in manifests.glob("*.json"):
        if prior_path.is_symlink() or not prior_path.is_file():
            raise ValueError("current-time provisioning history is unsafe")
        try:
            prior = json.loads(prior_path.read_bytes())
            prior_instant = datetime.fromisoformat(str(prior["evaluated_at"]).replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("current-time provisioning history is invalid") from exc
        if evidence.instant < _utc(prior_instant):
            raise ValueError("Gigabyte current-time witness rollback detected")
    receipt_path = receipts / f"{evidence.receipt_sha256}.json"
    _create_or_exact(receipt_path, evidence.receipt_bytes)
    manifest = {
        "schema_version": TIME_SCHEMA,
        "content_revision": runtime.content_revision,
        "evaluated_at": evidence.evaluated_at,
        "git_head": runtime.head,
        "monotonic_elapsed_ns": after_mono - before_mono,
        "provider_environment": evidence.environment,
        "provenance": "authenticated Gigabyte UTC current-time witness",
        "python_sha256": _sha256(python_path.read_bytes()),
        "receipt_sha256": evidence.receipt_sha256,
        "receipt_path": str(receipt_path),
        "release_authority": False,
        "scope": "preparation_current_time_only",
        "subject_sha256": subject_sha256,
        "trust_root_id": evidence.trust_root_id,
        "utc_observed_after": after_utc.isoformat(),
        "utc_observed_before": before_utc.isoformat(),
        "witness_identity_sha256": evidence.witness_identity_sha256,
    }
    manifest_sha256 = _sha256(_bytes(manifest))
    manifest_path = manifests / f"{manifest_sha256}.json"
    _create_or_exact(manifest_path, _bytes({**manifest, "manifest_sha256": manifest_sha256}))
    return {**manifest, "manifest_sha256": manifest_sha256, "manifest_path": str(manifest_path)}


__all__ = ["CONTACT_KEY_ENV", "provision_contact_authority", "provision_current_time"]
