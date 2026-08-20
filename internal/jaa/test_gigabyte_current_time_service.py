from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import gigabyte_current_time_service as service
from scripts import install_gigabyte_current_time as installer
from scripts.install_gigabyte_current_time import (
    BROKER_TARGET,
    CONFIG_TARGET,
    SERVICE_TARGET,
    SIGNER_SOCKET_TARGET,
    SOCKET_TARGET,
    _broker_unit,
    _unit,
)


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


def test_deployment_verification_executes_required_clock_skew_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def signature_strict_obtain(
        witness,
        *,
        environment: str,
        purpose: str,
        subject_sha256: str,
        maximum_clock_skew_seconds: int,
    ):
        calls.append(
            {
                "witness": witness,
                "environment": environment,
                "purpose": purpose,
                "subject_sha256": subject_sha256,
                "maximum_clock_skew_seconds": maximum_clock_skew_seconds,
            }
        )
        return SimpleNamespace(purpose=purpose, subject_sha256=subject_sha256)

    monkeypatch.setattr(installer, "obtain_current_time", signature_strict_obtain)
    witness = object()
    evidence = installer._obtain_deployment_verification(witness)
    assert installer.DEPLOYMENT_MAXIMUM_CLOCK_SKEW_SECONDS == 5
    assert evidence.purpose == "deployment_verification"
    assert evidence.subject_sha256 == installer.STAGED_CONFIG_SHA256
    assert calls == [
        {
            "witness": witness,
            "environment": "production",
            "purpose": "deployment_verification",
            "subject_sha256": installer.STAGED_CONFIG_SHA256,
            "maximum_clock_skew_seconds": 5,
        }
    ]


def test_deployment_probe_drops_to_exact_uid1000_and_preserves_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []
    receipt = "4" * 64
    result = {
        "effective_gid": 1000,
        "effective_uid": 1000,
        "receipt_sha256": receipt,
        "subject_sha256": installer.STAGED_CONFIG_SHA256,
        "witness_identity_sha256": installer.PRODUCTION_TIME_WITNESS_IDENTITY_SHA256,
    }

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(
            stdout=json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n",
            stderr="",
        )

    monkeypatch.setattr(installer.subprocess, "run", run)
    python = tmp_path / "venv" / "bin" / "python"
    assert installer._nonroot_deployment_verification(python) == result
    args, kwargs = calls[0]
    assert args[:5] == [
        "/usr/bin/setpriv",
        "--reuid=1000",
        "--regid=1000",
        "--clear-groups",
        "--",
    ]
    assert args[5:8] == [str(python), "-I", "-c"]
    assert "maximum_clock_skew_seconds=5" in args[8]
    assert kwargs == {
        "check": True,
        "capture_output": True,
        "text": True,
        "env": {"PATH": "/usr/bin:/bin"},
    }


def test_unit_preserves_root_service_and_exact_socket_contract(tmp_path) -> None:
    unit = _unit(python=tmp_path / "python", key=tmp_path / "device-key.pem").decode()
    assert "User=root" in unit
    assert "Group=root" in unit
    assert f"--socket {SIGNER_SOCKET_TARGET}" in unit
    assert f"ExecStart={tmp_path / 'python'} {SERVICE_TARGET}" in unit
    assert str(CONFIG_TARGET) == "/etc/gigabyte/majaa-public/jaa-current-time-v1.json"
    assert "UMask=0077" in unit
    assert "RuntimeDirectory=gigabyte/majaa" in unit
    assert "RuntimeDirectoryMode=0755" in unit
    broker = _broker_unit(python=tmp_path / "python").decode()
    assert f"ExecStart={tmp_path / 'python'} {BROKER_TARGET}" in broker
    assert f"--socket {SOCKET_TARGET}" in broker
    assert f"--signer-socket {SIGNER_SOCKET_TARGET}" in broker
    assert "--client-uid 1000 --client-gid 1000" in broker
    assert "User=root" in broker and "Group=root" in broker


def test_unit_upgrade_accepts_only_exact_prior_bytes(tmp_path: Path) -> None:
    target = tmp_path / "service.unit"
    previous = b"exact-prior-unit\n"
    current = b"runtime-directory-unit\n"
    target.write_bytes(previous)
    target.chmod(0o644)
    assert installer._upgrade_exact(
        target,
        current,
        previous=previous,
        mode=0o644,
        expected_uid=os.geteuid(),
    ) == "upgraded-exact-prior"
    assert target.read_bytes() == current
    assert installer._upgrade_exact(
        target,
        current,
        previous=previous,
        mode=0o644,
        expected_uid=os.geteuid(),
    ) == "exact-replay"
    target.write_bytes(b"unrecognized-drift\n")
    with pytest.raises(FileExistsError, match="unrecognized"):
        installer._upgrade_exact(
            target,
            current,
            previous=previous,
            mode=0o644,
            expected_uid=os.geteuid(),
        )


def test_config_upgrade_is_bound_to_canonical_and_exact_legacy_bytes(tmp_path: Path) -> None:
    assert installer.STAGED_CONFIG_SHA256 == "2ab67684897303a619283c94ecab166a840f4b9efbf1df90d7e67aab46ea31a7"
    assert installer.LEGACY_CONFIG_SHA256 == "db98c0b1071fb7eb34681a9765a4c943deba7749597299a7de808e009f8a95bb"

    target = tmp_path / "configuration.json"
    canonical = b'{"canonical":"reviewed"}'
    target.write_bytes(canonical + b"\n")
    target.chmod(0o600)
    assert installer._upgrade_exact(
        target,
        canonical,
        previous=canonical + b"\n",
        mode=0o600,
        expected_uid=os.geteuid(),
    ) == "upgraded-exact-prior"
    target.write_bytes(canonical + b" ")
    with pytest.raises(FileExistsError, match="unrecognized"):
        installer._upgrade_exact(
            target,
            canonical,
            previous=canonical + b"\n",
            mode=0o600,
            expected_uid=os.geteuid(),
        )


def _runtime_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    venv = tmp_path / "venv"
    bin_dir = venv / "bin"
    local_bin = tmp_path / "local" / "bin"
    uv = tmp_path / "uv"
    runtime = uv / "runtime"
    for directory in (bin_dir, local_bin, runtime / "bin"):
        directory.mkdir(parents=True, mode=0o700)
    entry = bin_dir / "python"
    venv_python = bin_dir / "python3.12"
    local_python = local_bin / "python3.12"
    alias = uv / "alias"
    resolved = runtime / "bin" / "python3.12"
    resolved.write_bytes(b"pinned-runtime")
    resolved.chmod(0o755)
    entry.symlink_to("python3.12")
    venv_python.symlink_to(local_python)
    local_python.symlink_to(alias / "bin" / "python3.12")
    alias.symlink_to(runtime)
    pyvenv = venv / "pyvenv.cfg"
    pyvenv.write_bytes(b"home = pinned\n")
    identity = {"runtime": "pinned"}
    monkeypatch.setattr(installer, "PINNED_COMPONENT_ROOT", tmp_path)
    monkeypatch.setattr(installer, "PINNED_VENV_PYTHON", entry)
    monkeypatch.setattr(installer, "PINNED_RUNTIME", resolved)
    monkeypatch.setattr(installer, "PINNED_RUNTIME_SHA256", hashlib.sha256(resolved.read_bytes()).hexdigest())
    monkeypatch.setattr(installer, "PINNED_PYVENV_SHA256", hashlib.sha256(pyvenv.read_bytes()).hexdigest())
    monkeypatch.setattr(
        installer,
        "PINNED_LINKS",
        {entry: "python3.12", venv_python: str(local_python), local_python: str(alias / "bin" / "python3.12"), alias: str(runtime)},
    )
    monkeypatch.setattr(installer, "PINNED_CRYPTOGRAPHY_IDENTITY", identity)
    monkeypatch.setattr(
        installer.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(identity) + "\n", stderr=""),
    )
    return entry, venv_python, resolved, pyvenv


def test_verified_runtime_link_accepts_exact_pinned_venv_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    entry, _, _, _ = _runtime_fixture(tmp_path, monkeypatch)
    assert installer._verified_runtime_link(entry) == entry


@pytest.mark.parametrize("fault", ["escape", "retarget", "writable", "missing_pyvenv", "runtime_hash", "import_drift"])
def test_verified_runtime_link_rejects_runtime_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    entry, venv_python, resolved, pyvenv = _runtime_fixture(tmp_path, monkeypatch)
    if fault == "escape":
        entry.unlink()
        entry.symlink_to("../escape")
        installer.PINNED_LINKS[entry] = "../escape"
    elif fault == "retarget":
        venv_python.unlink()
        venv_python.symlink_to("/tmp/substituted-python")
    elif fault == "writable":
        entry.parents[1].chmod(0o777)
    elif fault == "missing_pyvenv":
        pyvenv.unlink()
    elif fault == "runtime_hash":
        resolved.write_bytes(b"changed-runtime")
    else:
        monkeypatch.setattr(
            installer.subprocess,
            "run",
            lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps({"runtime": "drifted"}) + "\n", stderr=""),
        )
    with pytest.raises((FileNotFoundError, ValueError)):
        installer._verified_runtime_link(entry)
