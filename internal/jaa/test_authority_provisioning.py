from __future__ import annotations

import hashlib
import json
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from career_automation import authority_provisioning as provisioning
from career_automation.current_time import (
    CurrentTimeWitnessError,
    synthetic_hmac_current_time_witness_for_test,
)
from career_automation.evidence_matching import canonical_json


def _write(path: Path, value: object, mode: int = 0o600) -> bytes:
    raw = (canonical_json(value) + "\n").encode()
    path.write_bytes(raw)
    path.chmod(mode)
    return raw


def _contact_source(tmp_path: Path, *, with_contact: bool = True) -> tuple[Path, str]:
    projection: dict[str, object] = {"projection_sha256": "1" * 64}
    if with_contact:
        projection["contact"] = {
            "full_name": "Alex Example",
            "email": "alex@example.invalid",
            "phone": None,
            "city": "Example City",
        }
    path = tmp_path / "candidate-authority.json"
    raw = _write(path, {"schema_version": "candidate.test.v1", "candidate_projection": projection})
    return path, hashlib.sha256(raw).hexdigest()


def _key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    private = Ed25519PrivateKey.generate()
    path = tmp_path / "operator-contact-key.pem"
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    monkeypatch.setattr(provisioning, "ENROLLED_OPERATOR_PUBLIC_KEY_SHA256", hashlib.sha256(public).hexdigest())
    return path


def _witness(instant: datetime):
    return synthetic_hmac_current_time_witness_for_test(
        authentication_key=b"synthetic-current-time-key" * 2,
        environment="synthetic",
        trust_root_id="synthetic-trust-root",
        witness_identity_sha256="2" * 64,
        clock=lambda: instant,
        nonce_source=lambda: b"fixed-synthetic-nonce",
    )


def test_contact_provisioning_is_signed_private_and_exactly_replayable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, digest = _contact_source(tmp_path)
    key = _key(tmp_path, monkeypatch)
    output = tmp_path / "protected-contact"
    repository = tmp_path / "repository"
    repository.mkdir()
    first = provisioning.provision_contact_authority(
        candidate_authority_path=source,
        candidate_authority_sha256=digest,
        output_root=output,
        repository_root=repository,
        private_key_path=str(key),
        clock=lambda: datetime(2026, 8, 20, 12, tzinfo=timezone.utc),
    )
    second = provisioning.provision_contact_authority(
        candidate_authority_path=source,
        candidate_authority_sha256=digest,
        output_root=output,
        repository_root=repository,
        private_key_path=str(key),
        clock=lambda: datetime(2026, 8, 21, 12, tzinfo=timezone.utc),
    )
    assert first == second
    assert first["release_authority"] is False
    assert first["scope"] == "preparation_contact_authority_only"
    assert "alex@example.invalid" not in json.dumps(first)
    for path in output.rglob("*"):
        expected = 0o700 if path.is_dir() else 0o600
        assert stat.S_IMODE(path.stat().st_mode) == expected


@pytest.mark.parametrize("fault", ["wrong_hash", "missing_contact", "missing_key"])
def test_contact_provisioning_fails_closed_without_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    source, digest = _contact_source(tmp_path, with_contact=fault != "missing_contact")
    key = _key(tmp_path, monkeypatch)
    if fault == "wrong_hash":
        digest = "0" * 64
    if fault == "missing_key":
        key = None
    output = tmp_path / "protected-contact"
    repository = tmp_path / "repository"
    repository.mkdir()
    with pytest.raises(ValueError):
        provisioning.provision_contact_authority(
            candidate_authority_path=source,
            candidate_authority_sha256=digest,
            output_root=output,
            repository_root=repository,
            private_key_path=None if key is None else str(key),
        )
    assert not output.exists()


def test_current_time_provisioning_binds_runtime_and_rejects_release_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    instant = datetime(2026, 8, 20, 12, tzinfo=timezone.utc)
    monkeypatch.setattr(
        provisioning,
        "exact_committed_source_identity",
        lambda _: SimpleNamespace(head="3" * 40, content_revision="4" * 64),
    )
    observations = iter((instant - timedelta(seconds=1), instant + timedelta(seconds=1)))
    monotonic = iter((100, 200))
    result = provisioning.provision_current_time(
        output_root=tmp_path / "protected-time",
        repository_root=tmp_path,
        subject_sha256="5" * 64,
        witness=_witness(instant),
        utc_clock=lambda: next(observations),
        monotonic_clock=lambda: next(monotonic),
    )
    assert result["release_authority"] is False
    assert result["scope"] == "preparation_current_time_only"
    assert result["git_head"] == "3" * 40
    assert result["monotonic_elapsed_ns"] == 100
    assert stat.S_IMODE(Path(result["receipt_path"]).stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(result["manifest_path"]).stat().st_mode) == 0o600


def test_current_time_provisioning_rejects_clock_rollback_before_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    instant = datetime(2026, 8, 20, 12, tzinfo=timezone.utc)
    observations = iter((instant + timedelta(seconds=1), instant - timedelta(seconds=1)))
    monotonic = iter((200, 100))
    with pytest.raises(ValueError, match="rollback"):
        provisioning.provision_current_time(
            output_root=tmp_path / "protected-time",
            repository_root=tmp_path,
            subject_sha256="5" * 64,
            witness=_witness(instant),
            utc_clock=lambda: next(observations),
            monotonic_clock=lambda: next(monotonic),
        )
    assert not (tmp_path / "protected-time").exists()


def test_current_time_missing_deployment_trust_root_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def missing():
        raise CurrentTimeWitnessError("time_configuration_missing", "installed current-time configuration is absent")

    monkeypatch.setattr(provisioning, "installed_production_current_time_witness", missing)
    with pytest.raises(CurrentTimeWitnessError, match="time_configuration_missing"):
        provisioning.provision_current_time(
            output_root=tmp_path / "protected-time",
            repository_root=tmp_path,
            subject_sha256="5" * 64,
        )
    assert not (tmp_path / "protected-time").exists()
