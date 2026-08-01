"""Positive controls for the bounded JAA-10 external-time package."""

import base64
import hashlib
import inspect
import json
import stat

from career_automation import external_time_attestation as external_time
from career_automation.external_time_attestation import (
    ExternalTimeStatus,
    acquire_external_time_attestation,
    verify_external_time_response,
)


TARGET_RECEIPT = b"JAA-10 external time package live drill v1\n"
CALLER_ENTROPY = base64.b64decode(
    "DYg6MkdjrI1AOCn8lYJBIYJnAk23KoR6tVXzntb6h/Y="
)
GENUINE_CLOUDFLARE_RESPONSE = base64.b64decode(
    "Uk9VR0hUSU1UAQAABgAAAEAAAABEAAAARAAAAIgAAAAgAQAAU0lHAFZFUgBQQVRI"
    "U1JFUENFUlRJTkRY9nGuEGVy8d6E+g1Co59Hia78q//hHLukUQfhwyy+MZkSHVQS"
    "3qdupKF3bE94YR5YLm5SnI/d4wraLVUkX03dBgsAAIADAAAABAAAAAwAAABSQURJ"
    "TUlEUFJPT1QBAAAAsOVtagAAAAAcjn2T316KnzgZ+9s3DI9FuR0yQVdzASMJqBnh"
    "40C6twIAAABAAAAAU0lHAERFTEVZgdBiQzf7SmjV38R2IElWDtwgQ6az7uT5RDaD"
    "+vrrH1eKOgV3QvmrGWThAhJPb8EKFAWMcRiJFVZbMY3rha0PAwAAACAAAAAoAAAA"
    "UFVCS01JTlRNQVhUpoWBqPdl6wZ4MDtkv6N2jwPfYCezIjeYEeO4iXUKzmd7TG1q"
    "AAAAAPudbmoAAAAAAAAAAA=="
)


def test_official_cloudflare_identity_is_exactly_pinned() -> None:
    assert external_time.ISSUER == "Cloudflare-Roughtime-2"
    assert external_time.ISSUER_HOST == "roughtime.cloudflare.com"
    assert external_time.ISSUER_PORT == 2003
    assert external_time.ISSUER_TRANSPORT == "udp"
    assert external_time.ISSUER_PUBLIC_KEY_BASE64 == (
        "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
    )
    assert external_time.ISSUER_PUBLIC_KEY_SHA256 == (
        "0c5b53954debf2e8730c7173ea59639cc1a538c17d61b896c0bb9229256a460f"
    )
    assert external_time.ISSUER_KEY_SOURCE_URL == (
        "https://developers.cloudflare.com/time-services/roughtime/usage/"
    )


def test_recorded_genuine_response_verifies_offline_deterministically() -> None:
    first = verify_external_time_response(
        GENUINE_CLOUDFLARE_RESPONSE,
        TARGET_RECEIPT,
        CALLER_ENTROPY,
    )
    second = verify_external_time_response(
        GENUINE_CLOUDFLARE_RESPONSE,
        TARGET_RECEIPT,
        CALLER_ENTROPY,
    )

    assert first == second
    assert first.status is ExternalTimeStatus.VERIFIED
    assert first.reason == "cloudflare_roughtime_response_verified"
    assert first.receipt_sha256 == (
        "e04dbe07a6df3c602b552756387451e14c3b3fbdf36427a198676522764e5d6d"
    )
    assert first.entropy_sha256 == (
        "2382f481e9ed5525d5fa61eca65ad329a4ad9e3a305e522a3ffcf4fc6fce873d"
    )
    assert first.request_sha256 == (
        "b5f855a6bdf392eef71892c4bb7c35fb82ec61506e217216cc77b5340af7ba7c"
    )
    assert first.response_sha256 == (
        "b46701534b4641d624bf03cc69fd9d15c1338ae77fd645f5b68bbd92b3282875"
    )
    assert first.midpoint_unix == 1_785_587_120
    assert first.radius_seconds == 1
    assert first.midpoint_utc == "2026-08-01T12:25:20.000000Z"
    assert first.lower_bound_utc == "2026-08-01T12:25:19.000000Z"
    assert first.upper_bound_utc == "2026-08-01T12:25:21.000000Z"
    assert first.evidence_sha256 == (
        "365c7af8d6a24f015a8ba67a9f228b0bc5a1af9e64c00f8b855e60f66f6067a1"
    )


def test_request_is_exactly_padded_and_receipt_bound() -> None:
    nonce, request = external_time._build_request(TARGET_RECEIPT, CALLER_ENTROPY)
    other_nonce, other_request = external_time._build_request(
        TARGET_RECEIPT + b"changed",
        CALLER_ENTROPY,
    )

    assert len(nonce) == 32
    assert len(request) == 1024
    assert request[:8] == b"ROUGHTIM"
    assert nonce != other_nonce
    assert request != other_request
    assert hashlib.sha256(nonce).hexdigest() == (
        "c0380496534446b86e998e814c11f2375d61c37b67c06e02b313b041a4e35e15"
    )


def test_explicit_acquisition_entry_seals_raw_bytes_read_only(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        external_time,
        "_exchange",
        lambda request, attempts, timeout: GENUINE_CLOUDFLARE_RESPONSE,
    )
    destination = tmp_path / "external-time-evidence"

    result = acquire_external_time_attestation(
        TARGET_RECEIPT,
        CALLER_ENTROPY,
        destination,
        attempts=1,
        timeout_seconds=0.5,
    )

    assert result.status is ExternalTimeStatus.VERIFIED
    assert destination.stat().st_mode & 0o777 == 0o700
    assert (destination / "request.bin").read_bytes() == (
        external_time._build_request(TARGET_RECEIPT, CALLER_ENTROPY)[1]
    )
    assert (destination / "response.bin").read_bytes() == (
        GENUINE_CLOUDFLARE_RESPONSE
    )
    assert (destination / "entropy.bin").read_bytes() == CALLER_ENTROPY
    published = json.loads((destination / "attestation.json").read_bytes())
    assert published == result.document()
    for path in destination.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o444


def test_verdict_shape_withholds_certification_and_submission() -> None:
    result = verify_external_time_response(
        GENUINE_CLOUDFLARE_RESPONSE,
        TARGET_RECEIPT,
        CALLER_ENTROPY,
    ).document()

    assert result["external_time_authenticated"] is True
    assert result["certifies_slice"] is False
    assert result["submission_authority"] is False
    assert not set(result) & {
        "production_certification",
        "objective_satisfied",
        "live_time_separated_execution",
        "release_token_authority",
        "credential_authority",
    }


def test_offline_verifier_has_only_explicit_exact_inputs() -> None:
    assert set(inspect.signature(verify_external_time_response).parameters) == {
        "response_bytes",
        "target_receipt_bytes",
        "caller_entropy",
        "prior_anchor",
    }
    assert set(inspect.signature(acquire_external_time_attestation).parameters) == {
        "target_receipt_bytes",
        "caller_entropy",
        "destination",
        "attempts",
        "timeout_seconds",
        "prior_anchor",
    }
