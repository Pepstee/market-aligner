"""Negative controls for the bounded JAA-10 external-time package."""

import ast
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from career_automation import external_time_attestation as external_time
from career_automation.external_time_attestation import (
    ExternalTimeStatus,
    acquire_external_time_attestation,
    verify_external_time_response,
)
from test_jaa10_external_time_attestation import (
    CALLER_ENTROPY,
    GENUINE_CLOUDFLARE_RESPONSE,
    TARGET_RECEIPT,
)


MODULE = Path(external_time.__file__)


def _public_bytes(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _synthetic_response(
    *,
    root_private: Ed25519PrivateKey,
    midpoint: int = 1_785_587_120,
    radius: int = 1,
    receipt: bytes = TARGET_RECEIPT,
    entropy: bytes = CALLER_ENTROPY,
) -> bytes:
    online_private = Ed25519PrivateKey.generate()
    nonce = external_time._nonce(receipt, entropy)
    delegation = external_time._encode_message(
        {
            external_time.TAG_PUBK: _public_bytes(online_private),
            external_time.TAG_MINT: struct.pack("<Q", midpoint - 3600),
            external_time.TAG_MAXT: struct.pack("<Q", midpoint + 3600),
        }
    )
    certificate = external_time._encode_message(
        {
            external_time.TAG_SIG: root_private.sign(
                external_time._CERTIFICATE_CONTEXT + delegation
            ),
            external_time.TAG_DELE: delegation,
        }
    )
    signed_response = external_time._encode_message(
        {
            external_time.TAG_MIDP: struct.pack("<Q", midpoint),
            external_time.TAG_RADI: struct.pack("<I", radius),
            external_time.TAG_ROOT: hashlib.sha512(b"\x00" + nonce).digest()[:32],
        }
    )
    reply = external_time._encode_message(
        {
            external_time.TAG_SIG: online_private.sign(
                external_time._SIGNED_RESPONSE_CONTEXT + signed_response
            ),
            external_time.TAG_VER: struct.pack(
                "<I", external_time.PROTOCOL_VERSION
            ),
            external_time.TAG_PATH: b"",
            external_time.TAG_SREP: signed_response,
            external_time.TAG_CERT: certificate,
            external_time.TAG_INDX: struct.pack("<I", 0),
        }
    )
    return b"ROUGHTIM" + struct.pack("<I", len(reply)) + reply


def _failed(response, receipt=TARGET_RECEIPT, entropy=CALLER_ENTROPY):
    result = verify_external_time_response(response, receipt, entropy)
    assert result.status is ExternalTimeStatus.VERIFICATION_FAILED
    assert result.midpoint_unix is None
    assert result.radius_seconds is None
    assert result.document()["external_time_authenticated"] is False
    return result


def test_genuine_response_signature_tamper_fails_closed() -> None:
    tampered = bytearray(GENUINE_CLOUDFLARE_RESPONSE)
    tampered[64] ^= 1

    result = _failed(bytes(tampered))

    assert "signature" in result.reason.lower()


def test_locally_generated_issuer_cannot_replace_pinned_cloudflare_key() -> None:
    local_issuer = Ed25519PrivateKey.generate()

    result = _failed(_synthetic_response(root_private=local_issuer))

    assert "signature" in result.reason.lower()


@pytest.mark.parametrize(
    "receipt,entropy",
    [
        (TARGET_RECEIPT + b"replayed", CALLER_ENTROPY),
        (TARGET_RECEIPT, bytes(reversed(CALLER_ENTROPY))),
    ],
)
def test_nonce_receipt_or_entropy_replay_fails_merkle_proof(
    receipt: bytes, entropy: bytes
) -> None:
    result = _failed(GENUINE_CLOUDFLARE_RESPONSE, receipt, entropy)

    assert "Merkle" in result.reason


@pytest.mark.parametrize(
    "malformed",
    [
        b"",
        b"ROUGHTIM",
        b"ROUGHTIM\x00\x00\x00\x00",
        GENUINE_CLOUDFLARE_RESPONSE[:-1],
        b'{"schema_version":"jaa10.authenticated-time-witness.v1"}',
    ],
)
def test_truncated_malformed_or_local_witness_bytes_never_authenticate(
    malformed: bytes,
) -> None:
    _failed(malformed)


def test_excessive_uncertainty_radius_fails_after_valid_signatures(
    monkeypatch,
) -> None:
    local_issuer = Ed25519PrivateKey.generate()
    monkeypatch.setattr(
        external_time,
        "ISSUER_PUBLIC_KEY",
        _public_bytes(local_issuer),
    )
    response = _synthetic_response(
        root_private=local_issuer,
        radius=external_time.MAX_RADIUS_SECONDS + 1,
    )

    result = _failed(response)

    assert result.reason == "Roughtime uncertainty radius is excessive"


def test_prior_anchor_rollback_is_rejected_after_valid_verification(
    monkeypatch,
) -> None:
    local_issuer = Ed25519PrivateKey.generate()
    monkeypatch.setattr(
        external_time,
        "ISSUER_PUBLIC_KEY",
        _public_bytes(local_issuer),
    )
    later = verify_external_time_response(
        _synthetic_response(root_private=local_issuer, midpoint=1_785_587_220),
        TARGET_RECEIPT,
        CALLER_ENTROPY,
    )
    assert later.status is ExternalTimeStatus.VERIFIED

    result = verify_external_time_response(
        _synthetic_response(root_private=local_issuer, midpoint=1_785_587_120),
        TARGET_RECEIPT,
        CALLER_ENTROPY,
        later,
    )

    assert result.status is ExternalTimeStatus.VERIFICATION_FAILED
    assert result.reason == "external time rollback detected"


@pytest.mark.parametrize(
    "attempts,timeout",
    [(0, 1.0), (4, 1.0), (True, 1.0), (1, 0), (1, 10.1), (1, True)],
)
def test_retry_and_timeout_bounds_are_not_caller_weakenable(
    tmp_path, attempts, timeout
) -> None:
    with pytest.raises(ValueError):
        acquire_external_time_attestation(
            TARGET_RECEIPT,
            CALLER_ENTROPY,
            tmp_path / "evidence",
            attempts=attempts,
            timeout_seconds=timeout,
        )


@pytest.mark.parametrize("entropy", [b"", b"x" * 31, b"x" * 1025])
def test_entropy_bounds_fail_before_network(tmp_path, monkeypatch, entropy) -> None:
    called = False

    def forbidden(*_args):
        nonlocal called
        called = True
        raise AssertionError("network reached")

    monkeypatch.setattr(external_time, "_exchange", forbidden)
    with pytest.raises(ValueError):
        acquire_external_time_attestation(
            TARGET_RECEIPT,
            entropy,
            tmp_path / "evidence",
        )
    assert called is False


def test_network_failure_is_preserved_and_never_promoted(
    tmp_path, monkeypatch
) -> None:
    def unavailable(*_args):
        raise OSError("udp unavailable")

    monkeypatch.setattr(external_time, "_exchange", unavailable)
    destination = tmp_path / "failed-evidence"

    result = acquire_external_time_attestation(
        TARGET_RECEIPT,
        CALLER_ENTROPY,
        destination,
        attempts=3,
        timeout_seconds=1,
    )

    assert result.status is ExternalTimeStatus.ACQUISITION_FAILED
    assert result.reason == "udp unavailable"
    assert not (destination / "response.bin").exists()
    assert json.loads((destination / "attestation.json").read_bytes())[
        "external_time_authenticated"
    ] is False
    assert (destination / "request.bin").exists()
    assert (destination / "entropy.bin").exists()


def test_existing_or_symlink_destination_fails_before_network(
    tmp_path, monkeypatch
) -> None:
    called = False

    def forbidden(*_args):
        nonlocal called
        called = True
        raise AssertionError("network reached")

    monkeypatch.setattr(external_time, "_exchange", forbidden)
    existing = tmp_path / "existing"
    existing.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    for destination in (existing, link):
        with pytest.raises(FileExistsError):
            acquire_external_time_attestation(
                TARGET_RECEIPT,
                CALLER_ENTROPY,
                destination,
            )
    assert called is False


def test_module_has_one_explicit_network_surface_and_no_cross_package_authority() -> None:
    source = MODULE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imports & {
        "browser_executor",
        "browser_workflows",
        "hard_metrics_evaluation",
        "shadow_elapsed_cohort",
        "shadow_certification",
        "ats_fixture",
    }
    assert "submission" not in {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert source.count("socket.getaddrinfo(") == 1
    assert source.count("socket.socket(") == 1
    assert "requests" not in imports
    assert "urllib" not in imports


def test_published_evidence_is_exclusive(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        external_time,
        "_exchange",
        lambda *_args: GENUINE_CLOUDFLARE_RESPONSE,
    )
    destination = tmp_path / "exclusive"
    acquire_external_time_attestation(
        TARGET_RECEIPT,
        CALLER_ENTROPY,
        destination,
    )

    with pytest.raises(FileExistsError):
        acquire_external_time_attestation(
            TARGET_RECEIPT,
            CALLER_ENTROPY,
            destination,
        )
