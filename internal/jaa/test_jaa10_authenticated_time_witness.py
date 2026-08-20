"""Positive controls for the JAA-10 authenticated-time witness contract."""

import base64
import hashlib
import inspect
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from career_automation.authenticated_time_witness import (
    ATTESTATION_SCHEMA_VERSION,
    SIGNATURE_DOMAIN,
    AuthenticatedTimeVerdict,
    TimeEvidenceClass,
    TimeVerificationStatus,
    verify_external_time_attestation,
)


ROOT = Path(__file__).resolve().parent
RECEIPT = b'{"receipt":"exact"}\n'
ATTESTED_TIME = "2026-07-31T12:34:56.123456Z"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _issuer():
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = private.public_key()
    pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    der = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, pem, hashlib.sha256(der).hexdigest()


def _token(
    receipt: bytes = RECEIPT,
    *,
    attested_time: str = ATTESTED_TIME,
) -> tuple[bytes, bytes, str]:
    private, pem, pin = _issuer()
    unsigned = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "issuer_key_sha256": pin,
        "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
        "attested_time_utc": attested_time,
    }
    signature = private.sign(SIGNATURE_DOMAIN + _canonical(unsigned))
    envelope = {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature)
        .rstrip(b"=")
        .decode("ascii"),
    }
    return _canonical(envelope), pem, pin


def test_verified_attestation_binds_exact_receipt_time_and_issuer() -> None:
    token, pem, pin = _token()

    verdict = verify_external_time_attestation(token, RECEIPT, pem, pin)

    assert isinstance(verdict, AuthenticatedTimeVerdict)
    assert verdict.evidence_class is TimeEvidenceClass.EXTERNAL_TIME_ATTESTATION
    assert verdict.verification_status is TimeVerificationStatus.VERIFIED
    assert verdict.receipt_sha256 == hashlib.sha256(RECEIPT).hexdigest()
    assert verdict.attestation_sha256 == hashlib.sha256(token).hexdigest()
    assert verdict.issuer_key_sha256 == pin
    assert verdict.attested_time_utc == ATTESTED_TIME


def test_verdict_document_is_pure_data_without_authority_or_liveness() -> None:
    token, pem, pin = _token()
    document = verify_external_time_attestation(token, RECEIPT, pem, pin).document()

    assert document == {
        "schema_version": "jaa10.authenticated-time-verdict.v1",
        "evidence_class": "external_time_attestation",
        "verification_status": "verified",
        "reason": "external_time_attestation_verified",
        "receipt_sha256": hashlib.sha256(RECEIPT).hexdigest(),
        "attestation_sha256": hashlib.sha256(token).hexdigest(),
        "issuer_key_sha256": pin,
        "attested_time_utc": ATTESTED_TIME,
    }
    assert not set(document) & {
        "live_time_separated_execution",
        "submission_authority",
        "release_authority",
        "credential_authority",
        "browser_authority",
        "certifies_slice",
        "production_certification",
        "objective_satisfied",
    }


def test_evidence_taxonomy_is_closed_and_does_not_default_upward() -> None:
    assert {item.value for item in TimeEvidenceClass} == {
        "unauthenticated_host_time",
        "same_boot_kernel_monotonic",
        "external_time_attestation",
    }
    token, pem, pin = _token()
    unavailable = verify_external_time_attestation(token, RECEIPT, pem, None)
    assert unavailable.evidence_class is TimeEvidenceClass.UNAUTHENTICATED_HOST_TIME
    assert unavailable.verification_status is TimeVerificationStatus.VERIFICATION_UNAVAILABLE


def test_verification_is_deterministic_and_has_no_hidden_inputs() -> None:
    token, pem, pin = _token()
    first = verify_external_time_attestation(token, RECEIPT, pem, pin)
    second = verify_external_time_attestation(token, RECEIPT, pem, pin)

    assert first == second
    assert set(inspect.signature(verify_external_time_attestation).parameters) == {
        "attestation_bytes",
        "target_receipt_bytes",
        "issuer_trust_anchor_pem",
        "issuer_key_pin",
    }


def test_dependency_and_lock_pins_are_declared_for_clean_bootstrap() -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    lock = (ROOT / "requirements-test.lock").read_text(encoding="utf-8")

    assert project.count('"cryptography==49.0.0",') == 1
    pins = [line for line in lock.splitlines() if line and not line.startswith("#")]
    assert pins == sorted(pins, key=str.casefold)
    for pin in ("cffi==2.1.0", "cryptography==49.0.0", "pycparser==3.0"):
        assert pins.count(pin) == 1
