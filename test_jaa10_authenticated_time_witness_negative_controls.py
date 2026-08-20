"""Negative controls for the JAA-10 authenticated-time witness contract."""

import ast
import base64
import hashlib
import json
from dataclasses import fields
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from career_automation.authenticated_time_witness import (
    ATTESTATION_SCHEMA_VERSION,
    SIGNATURE_DOMAIN,
    AuthenticatedTimeVerdict,
    TimeEvidenceClass,
    TimeVerificationStatus,
    verify_external_time_attestation,
)


ROOT = Path(__file__).resolve().parent
MODULE = ROOT / "career_automation" / "authenticated_time_witness.py"
RECEIPT = b"exact target receipt\n"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _material():
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
    pin = hashlib.sha256(der).hexdigest()
    unsigned = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "issuer_key_sha256": pin,
        "receipt_sha256": hashlib.sha256(RECEIPT).hexdigest(),
        "attested_time_utc": "2026-07-31T12:34:56.123456Z",
    }
    signature = private.sign(SIGNATURE_DOMAIN + _canonical(unsigned))
    document = {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature)
        .rstrip(b"=")
        .decode("ascii"),
    }
    return private, pem, pin, document


def _verify(token: bytes, *, pem=None, pin=None, receipt=RECEIPT):
    _, expected_pem, expected_pin, _ = _material()
    return verify_external_time_attestation(
        token,
        receipt,
        expected_pem if pem is None else pem,
        expected_pin if pin is None else pin,
    )


def _failed(verdict) -> None:
    assert verdict.evidence_class is TimeEvidenceClass.UNAUTHENTICATED_HOST_TIME
    assert verdict.verification_status is not TimeVerificationStatus.VERIFIED
    assert verdict.attested_time_utc is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: {**row, "schema_version": "jaa10.authenticated-time-witness.v2"},
        lambda row: {**row, "receipt_sha256": "0" * 64},
        lambda row: {**row, "issuer_key_sha256": "0" * 64},
        lambda row: {**row, "attested_time_utc": "2026-07-31T12:34:56Z"},
        lambda row: {**row, "attested_time_utc": "2026-02-30T12:34:56.123456Z"},
        lambda row: {
            **row,
            "signature": ("A" if row["signature"][0] != "A" else "B")
            + row["signature"][1:],
        },
        lambda row: {key: value for key, value in row.items() if key != "signature"},
        lambda row: {**row, "extra": "forbidden"},
        lambda row: {**row, "receipt_sha256": 0},
    ],
)
def test_any_envelope_tamper_or_schema_drift_fails_closed(mutation) -> None:
    _, _, _, document = _material()
    _failed(_verify(_canonical(mutation(document))))


@pytest.mark.parametrize(
    "encoding",
    [
        b"{",
        b"[]",
        b"not json",
        b'{"schema_version":NaN}',
    ],
)
def test_truncated_or_malformed_encoding_fails_closed(encoding: bytes) -> None:
    _failed(_verify(encoding))


def test_noncanonical_and_duplicate_key_encodings_fail_closed() -> None:
    _, _, _, document = _material()
    _failed(_verify(json.dumps(document, sort_keys=True).encode("utf-8")))
    canonical = _canonical(document).decode("utf-8")
    duplicate = canonical.replace(
        '"schema_version":',
        '"schema_version":"duplicate","schema_version":',
        1,
    ).encode("utf-8")
    _failed(_verify(duplicate))


def test_exact_receipt_imprint_is_mandatory() -> None:
    _, _, _, document = _material()
    _failed(_verify(_canonical(document), receipt=RECEIPT + b"tampered"))


def test_wrong_absent_or_unsupported_issuer_never_authenticates() -> None:
    _, pem, pin, document = _material()
    token = _canonical(document)
    _failed(verify_external_time_attestation(token, RECEIPT, pem, None))
    _failed(verify_external_time_attestation(token, RECEIPT, pem, "0" * 64))
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _failed(verify_external_time_attestation(token, RECEIPT, other, pin))
    rsa_pem = generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _failed(verify_external_time_attestation(token, RECEIPT, rsa_pem, pin))


@pytest.mark.parametrize("invalid_attestation", [None, "string", 42])
def test_non_bytes_attestation_with_valid_anchor_fails_closed(
    invalid_attestation: object,
) -> None:
    _, pem, pin, _ = _material()

    verdict = verify_external_time_attestation(
        invalid_attestation,  # type: ignore[arg-type]
        RECEIPT,
        pem,
        pin,
    )

    _failed(verdict)
    assert verdict.verification_status is TimeVerificationStatus.VERIFICATION_FAILED
    assert verdict.reason == "attestation_bytes_invalid"
    assert verdict.attestation_sha256 is None


def test_external_class_cannot_be_forged_through_public_constructor() -> None:
    with pytest.raises(TypeError):
        AuthenticatedTimeVerdict(
            TimeEvidenceClass.EXTERNAL_TIME_ATTESTATION,
            TimeVerificationStatus.VERIFIED,
            "forged",
            "0" * 64,
            None,
            None,
            None,
        )


def test_verdict_shape_cannot_carry_authority_or_liveness_fields() -> None:
    names = {field.name for field in fields(AuthenticatedTimeVerdict)}
    assert not names & {
        "live_time_separated_execution",
        "submission_authority",
        "release_authority",
        "credential_authority",
        "browser_authority",
        "certifies_slice",
        "production_certification",
        "objective_satisfied",
    }
    _, pem, pin, document = _material()
    verdict = verify_external_time_attestation(_canonical(document), RECEIPT, pem, pin)
    assert verdict.evidence_class is TimeEvidenceClass.EXTERNAL_TIME_ATTESTATION


def test_module_has_no_network_browser_clock_runtime_or_control_surface() -> None:
    source = MODULE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imports & {
        "requests",
        "socket",
        "subprocess",
        "time",
        "urllib",
        "browser_executor",
        "browser_workflows",
    }
    assert "runtime_evidence" not in source
    assert ".control" not in source
