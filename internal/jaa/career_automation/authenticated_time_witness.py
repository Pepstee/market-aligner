"""Fail-closed offline verification for JAA-10 time attestations.

This module verifies operator-supplied evidence only.  It cannot acquire an
attestation, read a clock, browse, release, submit, certify, or claim that a
time-authenticated receipt came from a live execution.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ATTESTATION_SCHEMA_VERSION = "jaa10.authenticated-time-witness.v1"
VERDICT_SCHEMA_VERSION = "jaa10.authenticated-time-verdict.v1"
SIGNATURE_DOMAIN = b"jaa10-authenticated-time-witness-v1\0"

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$")
_B64URL_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_TOKEN_KEYS = frozenset(
    {
        "schema_version",
        "issuer_key_sha256",
        "receipt_sha256",
        "attested_time_utc",
        "signature",
    }
)
_UNSIGNED_KEYS = (
    "schema_version",
    "issuer_key_sha256",
    "receipt_sha256",
    "attested_time_utc",
)


class TimeEvidenceClass(str, Enum):
    UNAUTHENTICATED_HOST_TIME = "unauthenticated_host_time"
    SAME_BOOT_KERNEL_MONOTONIC = "same_boot_kernel_monotonic"
    EXTERNAL_TIME_ATTESTATION = "external_time_attestation"


class TimeVerificationStatus(str, Enum):
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


@dataclass(frozen=True, init=False)
class AuthenticatedTimeVerdict:
    evidence_class: TimeEvidenceClass
    verification_status: TimeVerificationStatus
    reason: str
    receipt_sha256: str
    attestation_sha256: str | None
    issuer_key_sha256: str | None
    attested_time_utc: str | None

    def document(self) -> dict[str, object]:
        return {
            "schema_version": VERDICT_SCHEMA_VERSION,
            "evidence_class": self.evidence_class.value,
            "verification_status": self.verification_status.value,
            "reason": self.reason,
            "receipt_sha256": self.receipt_sha256,
            "attestation_sha256": self.attestation_sha256,
            "issuer_key_sha256": self.issuer_key_sha256,
            "attested_time_utc": self.attested_time_utc,
        }


def _verdict(
    *,
    status: TimeVerificationStatus,
    reason: str,
    receipt_sha256: str,
    attestation_sha256: str | None,
    issuer_key_sha256: str | None = None,
    attested_time_utc: str | None = None,
) -> AuthenticatedTimeVerdict:
    verdict = object.__new__(AuthenticatedTimeVerdict)
    evidence_class = (
        TimeEvidenceClass.EXTERNAL_TIME_ATTESTATION
        if status is TimeVerificationStatus.VERIFIED
        else TimeEvidenceClass.UNAUTHENTICATED_HOST_TIME
    )
    for field, value in (
        ("evidence_class", evidence_class),
        ("verification_status", status),
        ("reason", reason),
        ("receipt_sha256", receipt_sha256),
        ("attestation_sha256", attestation_sha256),
        ("issuer_key_sha256", issuer_key_sha256),
        ("attested_time_utc", attested_time_utc),
    ):
        object.__setattr__(verdict, field, value)
    return verdict


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate attestation key")
        document[key] = value
    return document


def _parse_token(attestation: bytes) -> dict[str, str]:
    decoded = attestation.decode("utf-8")
    document = json.loads(
        decoded,
        object_pairs_hook=_strict_object,
        parse_float=lambda _value: (_ for _ in ()).throw(
            ValueError("floating-point attestation value")
        ),
        parse_constant=lambda _value: (_ for _ in ()).throw(
            ValueError("non-finite attestation value")
        ),
    )
    if not isinstance(document, dict) or set(document) != _TOKEN_KEYS:
        raise ValueError("attestation inventory differs")
    if any(not isinstance(value, str) for value in document.values()):
        raise ValueError("attestation values must be strings")
    typed = {str(key): str(value) for key, value in document.items()}
    if _canonical_json(typed) != attestation:
        raise ValueError("attestation bytes are not canonical")
    return typed


def _strict_utc(value: str) -> bool:
    if not _UTC_TIME.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def _decode_signature(value: str) -> bytes:
    if not _B64URL_SIGNATURE.fullmatch(value):
        raise ValueError("attestation signature encoding differs")
    signature = base64.urlsafe_b64decode(value + "==")
    if len(signature) != 64:
        raise ValueError("attestation signature length differs")
    canonical = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ValueError("attestation signature is not canonical")
    return signature


def _load_issuer(
    trust_anchor_pem: bytes,
) -> tuple[Ed25519PublicKey, str]:
    public_key = serialization.load_pem_public_key(trust_anchor_pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("issuer key algorithm is not Ed25519")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key, hashlib.sha256(der).hexdigest()


def verify_external_time_attestation(
    attestation_bytes: bytes,
    target_receipt_bytes: bytes,
    issuer_trust_anchor_pem: bytes | None,
    issuer_key_pin: str | None,
) -> AuthenticatedTimeVerdict:
    """Verify a supplied attestation without consulting network or clocks."""

    if not isinstance(target_receipt_bytes, bytes):
        raise TypeError("target receipt must be exact bytes")
    receipt_sha256 = hashlib.sha256(target_receipt_bytes).hexdigest()
    attestation_sha256 = (
        hashlib.sha256(attestation_bytes).hexdigest()
        if isinstance(attestation_bytes, bytes)
        else None
    )
    if (
        not isinstance(issuer_trust_anchor_pem, bytes)
        or not isinstance(issuer_key_pin, str)
        or not _HEX_64.fullmatch(issuer_key_pin)
    ):
        return _verdict(
            status=TimeVerificationStatus.VERIFICATION_UNAVAILABLE,
            reason="issuer_trust_anchor_or_pin_unavailable",
            receipt_sha256=receipt_sha256,
            attestation_sha256=attestation_sha256,
        )
    try:
        issuer, computed_pin = _load_issuer(issuer_trust_anchor_pem)
    except (TypeError, ValueError):
        return _verdict(
            status=TimeVerificationStatus.VERIFICATION_UNAVAILABLE,
            reason="issuer_trust_anchor_unavailable",
            receipt_sha256=receipt_sha256,
            attestation_sha256=attestation_sha256,
        )
    if computed_pin != issuer_key_pin:
        return _verdict(
            status=TimeVerificationStatus.VERIFICATION_FAILED,
            reason="issuer_key_pin_mismatch",
            receipt_sha256=receipt_sha256,
            attestation_sha256=attestation_sha256,
            issuer_key_sha256=computed_pin,
        )
    if not isinstance(attestation_bytes, bytes):
        return _verdict(
            status=TimeVerificationStatus.VERIFICATION_FAILED,
            reason="attestation_bytes_invalid",
            receipt_sha256=receipt_sha256,
            attestation_sha256=None,
            issuer_key_sha256=computed_pin,
        )
    try:
        token = _parse_token(attestation_bytes)
        if token["schema_version"] != ATTESTATION_SCHEMA_VERSION:
            raise ValueError("attestation schema differs")
        if token["issuer_key_sha256"] != computed_pin:
            raise ValueError("attestation issuer differs")
        if token["receipt_sha256"] != receipt_sha256:
            raise ValueError("attestation receipt imprint differs")
        if not _strict_utc(token["attested_time_utc"]):
            raise ValueError("attested time differs")
        signature = _decode_signature(token["signature"])
        unsigned = {key: token[key] for key in _UNSIGNED_KEYS}
        issuer.verify(signature, SIGNATURE_DOMAIN + _canonical_json(unsigned))
    except (InvalidSignature, KeyError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        return _verdict(
            status=TimeVerificationStatus.VERIFICATION_FAILED,
            reason="attestation_verification_failed",
            receipt_sha256=receipt_sha256,
            attestation_sha256=attestation_sha256,
            issuer_key_sha256=computed_pin,
        )
    return _verdict(
        status=TimeVerificationStatus.VERIFIED,
        reason="external_time_attestation_verified",
        receipt_sha256=receipt_sha256,
        attestation_sha256=attestation_sha256,
        issuer_key_sha256=computed_pin,
        attested_time_utc=token["attested_time_utc"],
    )
