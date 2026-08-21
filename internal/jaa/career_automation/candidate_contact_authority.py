"""Explicit operator authority for the employer-facing contact projection."""

from __future__ import annotations

import hashlib
import json
import re
import os
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .application_compiler import CandidateContact
from .evidence_matching import canonical_json


SCHEMA_VERSION = "jaa.operator-contact-authority.v2"
ATTESTATION = (
    "I confirm these contact details are current and approved for job applications."
)
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_AUTHORITY_AGE = timedelta(days=30)
PUBLIC_KEY_ENV = "JAA_OPERATOR_CONTACT_PUBLIC_KEY"
REGISTRY_ENV = "JAA_OPERATOR_CONTACT_REGISTRY"
REGISTRY_SCHEMA_VERSION = "jaa.operator-contact-registry.v1"
REGISTRY_ATTESTATION = (
    "I designate the current contact record and revoke every superseded record "
    "listed in this registry."
)
# The operator contact key was generated and retained outside the repository.
# Only its raw public-key identity is enrolled here.
ENROLLED_OPERATOR_PUBLIC_KEY_SHA256: str | None = (
    "03f20d82d47ab08d3dbcdf7ef0e7d15eebd3accf243639eb1865418c9b2d349c"
)
PLACEHOLDER = re.compile(
    r"(?i)(?:\btest\b|\bexample\b|\bplaceholder\b|\bdummy\b|\bunknown\b|"
    r"example\.(?:com|org|net|test)$|@example\.|\.test$)"
)


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


@dataclass(frozen=True)
class CandidateContactAuthority:
    contact: CandidateContact
    issued_at: str
    authority_sha256: str
    envelope_sha256: str
    registry_sha256: str
    signer_public_key_sha256: str
    source_path: Path


@dataclass(frozen=True)
class CandidateContactResourceLease:
    """Exact already-open resource bytes supplied by the production boundary."""

    authority_path: Path
    authority_bytes: bytes
    public_key_path: Path
    public_key_bytes: bytes
    registry_path: Path
    registry_bytes: bytes

    def __post_init__(self) -> None:
        for path, value in (
            (self.authority_path, self.authority_bytes),
            (self.public_key_path, self.public_key_bytes),
            (self.registry_path, self.registry_bytes),
        ):
            if not path.is_absolute() or not isinstance(value, bytes) or not value:
                raise ValueError("contact resource lease is malformed")


@dataclass(frozen=True)
class _VerifiedRegistry:
    sha256: str
    version: int
    issued_at: datetime
    record_id: str
    record_version: int
    authority_sha256: str
    revoked: tuple[str, ...]
    prior_sha256: str | None


def _load_contact_registry(
    *,
    repository: Path,
    public_key: Ed25519PublicKey,
    enrolled_key_sha256: str,
    verified_at: datetime,
    authority_sha256: str,
    record_id: str,
    record_version: int,
    resource_lease: CandidateContactResourceLease | None = None,
) -> str:
    configured = os.environ.get(REGISTRY_ENV)
    if not configured:
        raise ValueError(f"{REGISTRY_ENV} is required")
    candidate = Path(configured)
    if resource_lease is not None:
        if type(resource_lease) is not CandidateContactResourceLease:
            raise ValueError("contact registry resource lease type is invalid")
        resource_lease.__post_init__()
        if candidate != resource_lease.registry_path:
            raise ValueError("contact registry resource lease path differs")
        paths_and_values = ((candidate, resource_lease.registry_bytes),)
    else:
        paths_and_values = None
    if not candidate.is_absolute() or candidate.is_symlink():
        raise ValueError("operator contact registry must be an absolute directory")
    if paths_and_values is None:
        directory = candidate.resolve(strict=True)
        if (
            not directory.is_dir()
            or repository == directory
            or repository in directory.parents
        ):
            raise ValueError("operator contact registry must be outside the repository")
        paths = sorted(directory.iterdir())
        if not paths or any(
            path.is_symlink() or not path.is_file() or path.suffix != ".json"
            for path in paths
        ):
            raise ValueError("operator contact registry directory is unsafe or empty")
        paths_and_values = tuple((path, path.read_bytes()) for path in paths)
    else:
        paths = [candidate]

    registries: dict[str, _VerifiedRegistry] = {}
    for path, value in paths_and_values:
        try:
            document = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("operator contact registry is invalid JSON") from exc
        if not isinstance(document, dict) or value != _json_bytes(document):
            raise ValueError("operator contact registry must be canonical JSON")
        if set(document) != {
            "schema_version",
            "authority_kind",
            "operator_attestation",
            "issued_at",
            "registry_id",
            "registry_version",
            "current",
            "revoked_authority_sha256s",
            "prior_registry_sha256",
            "signature_algorithm",
            "signer_public_key_sha256",
            "signature_base64",
            "registry_sha256",
        }:
            raise ValueError("operator contact registry fields are incomplete")
        content_addressed = dict(document)
        registry_sha256 = content_addressed.pop("registry_sha256", None)
        expected_sha256 = hashlib.sha256(_json_bytes(content_addressed)).hexdigest()
        signed_payload = dict(content_addressed)
        signature_base64 = signed_payload.pop("signature_base64", None)
        current = document.get("current")
        revoked = document.get("revoked_authority_sha256s")
        prior = document.get("prior_registry_sha256")
        try:
            issued_at = datetime.fromisoformat(
                str(document["issued_at"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError) as exc:
            raise ValueError("operator contact registry issue time is invalid") from exc
        if (
            document.get("schema_version") != REGISTRY_SCHEMA_VERSION
            or document.get("authority_kind")
            != "ed25519_signed_operator_contact_registry"
            or document.get("operator_attestation") != REGISTRY_ATTESTATION
            or document.get("registry_id") != "operator-contact-primary"
            or not isinstance(document.get("registry_version"), int)
            or isinstance(document.get("registry_version"), bool)
            or int(document["registry_version"]) < 1
            or issued_at.tzinfo is None
            or not isinstance(registry_sha256, str)
            or not HEX_64.fullmatch(registry_sha256)
            or registry_sha256 != expected_sha256
            or path.name != f"{registry_sha256}.json"
            or not isinstance(current, Mapping)
            or set(current) != {"record_id", "record_version", "authority_sha256"}
            or not isinstance(current.get("record_id"), str)
            or not str(current["record_id"]).strip()
            or not isinstance(current.get("record_version"), int)
            or isinstance(current.get("record_version"), bool)
            or int(current["record_version"]) < 1
            or not isinstance(current.get("authority_sha256"), str)
            or not HEX_64.fullmatch(str(current["authority_sha256"]))
            or not isinstance(revoked, list)
            or any(not isinstance(item, str) or not HEX_64.fullmatch(item) for item in revoked)
            or revoked != sorted(set(revoked))
            or (prior is not None and (not isinstance(prior, str) or not HEX_64.fullmatch(prior)))
            or document.get("signature_algorithm") != "Ed25519"
            or document.get("signer_public_key_sha256") != enrolled_key_sha256
            or not isinstance(signature_base64, str)
        ):
            raise ValueError("operator contact registry identity is invalid")
        try:
            signature = base64.b64decode(signature_base64, validate=True)
            public_key.verify(signature, _json_bytes(signed_payload))
        except (ValueError, InvalidSignature) as exc:
            raise ValueError("operator contact registry signature is invalid") from exc
        registries[registry_sha256] = _VerifiedRegistry(
            sha256=registry_sha256,
            version=int(document["registry_version"]),
            issued_at=issued_at.astimezone(timezone.utc),
            record_id=str(current["record_id"]),
            record_version=int(current["record_version"]),
            authority_sha256=str(current["authority_sha256"]),
            revoked=tuple(revoked),
            prior_sha256=prior,
        )
    if len(registries) != len(paths):
        raise ValueError("operator contact registry contains duplicate identities")
    referenced = {
        row.prior_sha256 for row in registries.values() if row.prior_sha256 is not None
    }
    if not referenced.issubset(registries):
        raise ValueError("operator contact registry chain is incomplete")
    heads = set(registries) - referenced
    if len(heads) != 1:
        raise ValueError("operator contact registry has no unique current head")
    chain: list[_VerifiedRegistry] = []
    cursor: str | None = next(iter(heads))
    while cursor is not None:
        if cursor in {row.sha256 for row in chain}:
            raise ValueError("operator contact registry chain contains a cycle")
        row = registries[cursor]
        chain.append(row)
        cursor = row.prior_sha256
    if len(chain) != len(registries):
        raise ValueError("operator contact registry contains a disconnected chain")
    chain.reverse()
    first = chain[0]
    if (
        first.version != 1
        or first.prior_sha256 is not None
        or first.record_version != 1
        or first.revoked
    ):
        raise ValueError("operator contact registry genesis is invalid")
    for older, newer in zip(chain, chain[1:], strict=False):
        changed = newer.authority_sha256 != older.authority_sha256
        expected_revoked = set(older.revoked)
        if changed:
            expected_revoked.add(older.authority_sha256)
        if (
            newer.version != older.version + 1
            or newer.issued_at < older.issued_at
            or newer.record_id != older.record_id
            or newer.record_version
            != older.record_version + (1 if changed else 0)
            or set(newer.revoked) != expected_revoked
            or newer.authority_sha256 in newer.revoked
        ):
            raise ValueError("operator contact registry transition is invalid")
    head = chain[-1]
    age = verified_at.astimezone(timezone.utc) - head.issued_at
    if age < timedelta(minutes=-5) or age > MAX_AUTHORITY_AGE:
        raise ValueError("operator contact registry head is stale")
    if (
        head.authority_sha256 != authority_sha256
        or head.record_id != record_id
        or head.record_version != record_version
        or authority_sha256 in head.revoked
    ):
        raise ValueError("contact authority is not the registry current record")
    return head.sha256


def load_candidate_contact_authority(
    path: str | Path,
    *,
    repository_root: str | Path,
    verified_at: datetime | None = None,
    resource_lease: CandidateContactResourceLease | None = None,
) -> CandidateContactAuthority:
    """Load one content-addressed operator file without accepting repo fixtures."""
    candidate = Path(path)
    repository = Path(repository_root).resolve(strict=True)
    if resource_lease is not None:
        if type(resource_lease) is not CandidateContactResourceLease:
            raise ValueError("contact resource lease type is invalid")
        resource_lease.__post_init__()
        if candidate != resource_lease.authority_path:
            raise ValueError("contact authority resource lease path differs")
    if not candidate.is_absolute() or (resource_lease is None and candidate.is_symlink()):
        raise ValueError("contact authority must be an absolute non-symlink file")
    resolved = candidate if resource_lease is not None else candidate.resolve(strict=True)
    if (
        (resource_lease is None and not resolved.is_file())
        or repository == resolved
        or repository in resolved.parents
    ):
        raise ValueError("contact authority must be a regular file outside the repository")
    value = (
        resource_lease.authority_bytes
        if resource_lease is not None
        else resolved.read_bytes()
    )
    try:
        document = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("contact authority is invalid JSON") from exc
    if not isinstance(document, dict) or value != _json_bytes(document):
        raise ValueError("contact authority must be canonical JSON")
    if set(document) != {
        "schema_version",
        "authority_kind",
        "operator_attestation",
        "issued_at",
        "record_id",
        "record_version",
        "contact",
        "signature_algorithm",
        "signer_public_key_sha256",
        "signature_base64",
        "authority_sha256",
    }:
        raise ValueError("contact authority fields are incomplete")
    content_addressed = dict(document)
    authority_sha256 = content_addressed.pop("authority_sha256", None)
    expected_sha256 = hashlib.sha256(_json_bytes(content_addressed)).hexdigest()
    signed_payload = dict(content_addressed)
    signature_base64 = signed_payload.pop("signature_base64", None)
    contact = document.get("contact")
    try:
        issued_at = datetime.fromisoformat(
            str(document["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("contact authority issue time is invalid") from exc
    now = verified_at or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("contact authority verification time must be timezone-aware")
    age = now.astimezone(timezone.utc) - issued_at.astimezone(timezone.utc)
    if (
        document.get("schema_version") != SCHEMA_VERSION
        or document.get("authority_kind")
        != "ed25519_signed_explicit_operator_attestation"
        or document.get("operator_attestation") != ATTESTATION
        or issued_at.tzinfo is None
        or age < timedelta(minutes=-5)
        or age > MAX_AUTHORITY_AGE
        or not isinstance(authority_sha256, str)
        or not HEX_64.fullmatch(authority_sha256)
        or authority_sha256 != expected_sha256
        or resolved.name != f"{authority_sha256}.json"
        or not isinstance(contact, dict)
        or set(contact) != {"full_name", "email", "phone", "city"}
        or not isinstance(document.get("record_id"), str)
        or not document["record_id"].strip()
        or not isinstance(document.get("record_version"), int)
        or isinstance(document.get("record_version"), bool)
        or document.get("signature_algorithm") != "Ed25519"
        or not isinstance(document.get("signer_public_key_sha256"), str)
        or not HEX_64.fullmatch(str(document["signer_public_key_sha256"]))
        or not isinstance(signature_base64, str)
    ):
        raise ValueError("contact authority identity or attestation is invalid")
    enrolled = ENROLLED_OPERATOR_PUBLIC_KEY_SHA256
    public_key_value = os.environ.get(PUBLIC_KEY_ENV)
    if enrolled is None:
        raise ValueError("no operator contact signing key is enrolled")
    if not HEX_64.fullmatch(enrolled):
        raise ValueError("operator contact signing key enrollment is invalid")
    if not public_key_value:
        raise ValueError(f"{PUBLIC_KEY_ENV} is required")
    public_key_path = Path(public_key_value)
    if (
        not public_key_path.is_absolute()
        or (resource_lease is None and public_key_path.is_symlink())
    ):
        raise ValueError("operator contact public key must be an absolute non-symlink file")
    if resource_lease is not None and public_key_path != resource_lease.public_key_path:
        raise ValueError("contact public-key resource lease path differs")
    resolved_public_key = (
        public_key_path
        if resource_lease is not None
        else public_key_path.resolve(strict=True)
    )
    if repository == resolved_public_key or repository in resolved_public_key.parents:
        raise ValueError("operator contact public key must be outside the repository")
    try:
        loaded = serialization.load_pem_public_key(
            resource_lease.public_key_bytes
            if resource_lease is not None
            else resolved_public_key.read_bytes()
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("operator contact public key is invalid") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("operator contact public key must be Ed25519")
    raw_public_key = loaded.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key_sha256 = hashlib.sha256(raw_public_key).hexdigest()
    if (
        public_key_sha256 != enrolled
        or document["signer_public_key_sha256"] != enrolled
    ):
        raise ValueError("contact authority signer is not the enrolled operator key")
    try:
        signature = base64.b64decode(signature_base64, validate=True)
        loaded.verify(signature, _json_bytes(signed_payload))
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("contact authority operator signature is invalid") from exc
    registry_sha256 = _load_contact_registry(
        repository=repository,
        public_key=loaded,
        enrolled_key_sha256=enrolled,
        verified_at=now,
        authority_sha256=authority_sha256,
        record_id=str(document["record_id"]),
        record_version=int(document["record_version"]),
        resource_lease=resource_lease,
    )
    projected_values = (
        contact.get("full_name"),
        contact.get("email"),
        contact.get("city"),
        contact.get("phone") if contact.get("phone") is not None else "",
    )
    if any(not isinstance(value, str) for value in projected_values) or any(
        PLACEHOLDER.search(value) for value in projected_values if value
    ):
        raise ValueError("contact authority contains placeholder identity data")
    phone = contact["phone"]
    if isinstance(phone, str) and re.fullmatch(r"[\s()+-]*0[\s0()+-]*", phone):
        raise ValueError("contact authority contains placeholder identity data")
    if phone == "":
        raise ValueError("absent candidate phone must be explicit null")
    projection = CandidateContact(
        full_name=str(contact["full_name"]),
        email=str(contact["email"]),
        phone=str(phone) if phone is not None else None,
        city=str(contact["city"]),
        record_id=str(document["record_id"]),
        record_version=int(document["record_version"]),
        provenance_sha256=authority_sha256,
    )
    return CandidateContactAuthority(
        contact=projection,
        issued_at=issued_at.isoformat(),
        authority_sha256=authority_sha256,
        envelope_sha256=hashlib.sha256(value).hexdigest(),
        registry_sha256=registry_sha256,
        signer_public_key_sha256=enrolled,
        source_path=resolved,
    )


__all__ = [
    "ATTESTATION",
    "CandidateContactAuthority",
    "CandidateContactResourceLease",
    "SCHEMA_VERSION",
    "PUBLIC_KEY_ENV",
    "REGISTRY_ATTESTATION",
    "REGISTRY_ENV",
    "REGISTRY_SCHEMA_VERSION",
    "ENROLLED_OPERATOR_PUBLIC_KEY_SHA256",
    "load_candidate_contact_authority",
]
