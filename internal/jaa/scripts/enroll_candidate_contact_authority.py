#!/usr/bin/env python3
"""Create the genesis JAA operator contact authority outside the repository."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.application_compiler import CandidateContact  # noqa: E402
from career_automation.candidate_contact_authority import (  # noqa: E402
    ATTESTATION,
    PLACEHOLDER,
    REGISTRY_ATTESTATION,
    REGISTRY_SCHEMA_VERSION,
    SCHEMA_VERSION,
)
from career_automation.evidence_matching import canonical_json  # noqa: E402


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _create_file(path: Path, value: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _signed_document(
    private_key: Ed25519PrivateKey,
    payload: dict[str, object],
    identity_field: str,
) -> tuple[dict[str, object], str]:
    signature = base64.b64encode(private_key.sign(_json_bytes(payload))).decode()
    content_addressed = {**payload, "signature_base64": signature}
    digest = hashlib.sha256(_json_bytes(content_addressed)).hexdigest()
    return {**content_addressed, identity_field: digest}, digest


def _validate_contact(
    *, full_name: str, email: str, phone: str | None, city: str
) -> None:
    CandidateContact(
        full_name=full_name,
        email=email,
        phone=phone,
        city=city,
        record_id="operator-contact-primary",
        record_version=1,
        provenance_sha256="0" * 64,
    )
    values = (full_name, email, city, phone or "")
    if any(PLACEHOLDER.search(value) for value in values if value):
        raise ValueError("contact enrollment contains placeholder identity data")
    if phone is not None and re.fullmatch(r"[\s()+-]*0[\s0()+-]*", phone):
        raise ValueError("contact enrollment contains placeholder identity data")


def enroll_contact_authority(
    *,
    output_root: Path,
    repository_root: Path,
    full_name: str,
    email: str,
    city: str,
    phone: str | None = None,
    issued_at: datetime | None = None,
) -> dict[str, str]:
    """Create one key, signed contact record and signed genesis registry."""
    repository = repository_root.resolve(strict=True)
    parent = output_root.parent.resolve(strict=True)
    candidate = parent / output_root.name
    if repository == candidate or repository in candidate.parents:
        raise ValueError("contact enrollment root must be outside the repository")
    if candidate.exists() or candidate.is_symlink():
        raise FileExistsError("contact enrollment root already exists")
    _validate_contact(full_name=full_name, email=email, phone=phone, city=city)

    timestamp = issued_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("contact enrollment issue time must be timezone-aware")
    issued = timestamp.astimezone(timezone.utc).replace(microsecond=0).isoformat()

    candidate.mkdir(mode=0o700)
    keys = candidate / "keys"
    authorities = candidate / "authorities"
    registry = candidate / "registry"
    for directory in (keys, authorities, registry):
        directory.mkdir(mode=0o700)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_sha256 = hashlib.sha256(raw_public).hexdigest()
    private_path = keys / "operator-contact-private-key.pem"
    public_path = keys / "operator-contact-public-key.pem"
    _create_file(
        private_path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    _create_file(
        public_path,
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )

    authority_payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_explicit_operator_attestation",
        "operator_attestation": ATTESTATION,
        "issued_at": issued,
        "record_id": "operator-contact-primary",
        "record_version": 1,
        "contact": {
            "full_name": full_name,
            "email": email,
            "phone": phone,
            "city": city,
        },
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": public_sha256,
    }
    authority, authority_sha256 = _signed_document(
        private_key, authority_payload, "authority_sha256"
    )
    authority_path = authorities / f"{authority_sha256}.json"
    _create_file(authority_path, _json_bytes(authority))

    registry_payload: dict[str, object] = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_operator_contact_registry",
        "operator_attestation": REGISTRY_ATTESTATION,
        "issued_at": issued,
        "registry_id": "operator-contact-primary",
        "registry_version": 1,
        "current": {
            "record_id": "operator-contact-primary",
            "record_version": 1,
            "authority_sha256": authority_sha256,
        },
        "revoked_authority_sha256s": [],
        "prior_registry_sha256": None,
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": public_sha256,
    }
    registry_document, registry_sha256 = _signed_document(
        private_key, registry_payload, "registry_sha256"
    )
    registry_path = registry / f"{registry_sha256}.json"
    _create_file(registry_path, _json_bytes(registry_document))

    manifest = {
        "schema_version": "jaa.operator-contact-enrollment-manifest.v1",
        "issued_at": issued,
        "public_key_sha256": public_sha256,
        "public_key_path": str(public_path),
        "authority_sha256": authority_sha256,
        "authority_path": str(authority_path),
        "registry_sha256": registry_sha256,
        "registry_path": str(registry_path),
    }
    manifest_path = candidate / "enrollment-manifest.json"
    _create_file(manifest_path, _json_bytes(manifest))
    return {**manifest, "manifest_path": str(manifest_path)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--full-name", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--city", required=True)
    parser.add_argument("--phone")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = enroll_contact_authority(
        output_root=args.output_root,
        repository_root=args.repository_root,
        full_name=args.full_name,
        email=args.email,
        city=args.city,
        phone=args.phone,
    )
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
