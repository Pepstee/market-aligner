from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import gigabyte_current_time_service as service
from scripts.install_gigabyte_current_time import CONFIG_TARGET, SERVICE_TARGET, SOCKET_TARGET, _unit


def _request() -> bytes:
    value = {
        "environment": "production",
        "nonce_b64": base64.b64encode(b"n" * 32).decode("ascii"),
        "provider_id": service.PROVIDER_ID,
        "purpose": "deployment_verification",
        "schema_version": service.REQUEST_SCHEMA,
        "subject_sha256": "1" * 64,
        "trust_root_id": service.TRUST_ROOT_ID,
        "witness_identity_sha256": service.WITNESS_IDENTITY_SHA256,
    }
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def test_service_response_is_exact_challenge_bound_ed25519(monkeypatch: pytest.MonkeyPatch) -> None:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(service, "PUBLIC_KEY_SHA256", hashlib.sha256(public).hexdigest())
    response = service.issue_response(
        _request(),
        private,
        clock=lambda: datetime(2026, 8, 20, 12, tzinfo=timezone.utc),
    )
    document = json.loads(response)
    signature = base64.b64decode(document.pop("signature_b64"), validate=True)
    private.public_key().verify(signature, json.dumps(document, separators=(",", ":"), sort_keys=True).encode())
    assert document["evaluated_at"] == "2026-08-20T12:00:00Z"
    assert document["nonce_sha256"] == hashlib.sha256(b"n" * 32).hexdigest()
    assert document["subject_sha256"] == "1" * 64


def test_service_rejects_noncanonical_or_substituted_request() -> None:
    private = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="canonical"):
        service.issue_response(b"{ }", private)
    request = json.loads(_request())
    request["trust_root_id"] = "substituted"
    with pytest.raises(ValueError, match="binding"):
        service.issue_response(json.dumps(request, separators=(",", ":"), sort_keys=True).encode(), private)


def test_unit_preserves_root_service_and_exact_socket_contract(tmp_path) -> None:
    unit = _unit(python=tmp_path / "python", key=tmp_path / "device-key.pem").decode()
    assert "User=root" in unit
    assert "Group=root" in unit
    assert f"--socket {SOCKET_TARGET}" in unit
    assert f"ExecStart={tmp_path / 'python'} {SERVICE_TARGET}" in unit
    assert str(CONFIG_TARGET) == "/etc/gigabyte/majaa/jaa-current-time-v1.json"
    assert "UMask=0077" in unit
