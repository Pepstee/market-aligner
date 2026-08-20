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
import career_automation.candidate_contact_authority as contact_module
from scripts.enroll_candidate_contact_authority import enroll_contact_authority


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


def _device_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "device"
    root.mkdir(mode=0o700)
    private = Ed25519PrivateKey.generate()
    key_path = root / "device-signing-key.pem"
    key_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(provisioning, "GIGABYTE_DEVICE_PUBLIC_KEY_SHA256", hashlib.sha256(public).hexdigest())
    return root


def _contact_pdf(path: Path, *, include_phone: bool = False) -> str:
    header = "London | jordan.smith@proton.me | example.invalid/jordan"
    if include_phone:
        header = "London | +44 7000 000000 | jordan.smith@proton.me | example.invalid/jordan"
    stream = f"BT /F1 12 Tf 72 760 Td (Jordan Smith) Tj 0 -20 Td (Automation Engineer) Tj 0 -20 Td ({header}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    raw = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, value in enumerate(objects, 1):
        offsets.append(len(raw))
        raw.extend(f"{index} 0 obj\n".encode() + value + b"\nendobj\n")
    xref = len(raw)
    raw.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        raw.extend(f"{offset:010d} 00000 n \n".encode())
    raw.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    path.write_bytes(bytes(raw))
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def test_device_enrollment_is_signed_nonretroactive_and_stages_time_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    root = _device_root(tmp_path, monkeypatch)
    result = provisioning.provision_device_enrollment(
        output_root=root,
        repository_root=repository,
        clock=lambda: datetime(2026, 8, 10, 12, tzinfo=timezone.utc),
    )
    assert result["retroactive_evidence_authority"] is False
    assert result["current_time_deployed"] is False
    enrollment = json.loads(Path(result["enrollment_path"]).read_text())
    assert enrollment["rotation"]["prior_key_id"] is None
    assert enrollment["revocation"]["revoked"] is False
    assert stat.S_IMODE(Path(result["enrollment_path"]).stat().st_mode) == 0o600
    config_bytes = Path(result["current_time_configuration_path"]).read_bytes()
    assert not config_bytes.endswith(b"\n")
    assert config_bytes == canonical_json(json.loads(config_bytes)).encode("utf-8")
    assert hashlib.sha256(config_bytes).hexdigest() == result["current_time_configuration_sha256"]
    assert result["current_time_configuration_outcome"] == "created"


def test_device_enrollment_migrates_only_exact_legacy_staged_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    root = _device_root(tmp_path, monkeypatch)
    first = provisioning.provision_device_enrollment(
        output_root=root,
        repository_root=repository,
        clock=lambda: datetime(2026, 8, 10, 12, tzinfo=timezone.utc),
    )
    config_path = Path(first["current_time_configuration_path"])
    canonical = config_path.read_bytes()
    config_path.write_bytes(canonical + b"\n")
    config_path.chmod(0o600)

    migrated = provisioning.provision_device_enrollment(
        output_root=root,
        repository_root=repository,
        clock=lambda: datetime(2026, 8, 11, 12, tzinfo=timezone.utc),
    )
    assert migrated["current_time_configuration_outcome"] == "upgraded-exact-prior"
    assert config_path.read_bytes() == canonical

    config_path.write_bytes(canonical + b" ")
    config_path.chmod(0o600)
    with pytest.raises(ValueError, match="replay differs"):
        provisioning.provision_device_enrollment(
            output_root=root,
            repository_root=repository,
            clock=lambda: datetime(2026, 8, 12, 12, tzinfo=timezone.utc),
        )


def test_existing_contact_is_adopted_only_when_exact_pdf_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    device = _device_root(tmp_path, monkeypatch)
    contact_root = tmp_path / "existing-contact"
    contact = enroll_contact_authority(
        output_root=contact_root,
        repository_root=repository,
        full_name="Jordan Smith",
        email="jordan.smith@proton.me",
        city="London",
        phone=None,
        issued_at=datetime(2026, 8, 10, 12, tzinfo=timezone.utc),
    )
    monkeypatch.setattr(contact_module, "ENROLLED_OPERATOR_PUBLIC_KEY_SHA256", contact["public_key_sha256"])
    candidate, candidate_sha256 = _contact_source(tmp_path, with_contact=False)
    pdf = tmp_path / "operator-cv.pdf"
    pdf_sha256 = _contact_pdf(pdf)
    result = provisioning.adopt_existing_contact_authority(
        candidate_authority_path=candidate,
        candidate_authority_sha256=candidate_sha256,
        source_pdf_path=pdf,
        source_pdf_sha256=pdf_sha256,
        contact_authority_path=Path(contact["authority_path"]),
        contact_public_key_path=contact_root / "keys" / "operator-contact-public-key.pem",
        contact_registry_path=contact_root / "registry",
        device_key_path=device / "device-signing-key.pem",
        output_root=device / "contact-adoption",
        repository_root=repository,
        operator_ratified=True,
        clock=lambda: datetime(2026, 8, 10, 12, tzinfo=timezone.utc),
    )
    assert result["release_authority"] is False
    assert "Jordan" not in json.dumps(result)
    assert "proton" not in json.dumps(result)
    receipt = json.loads(Path(result["adoption_path"]).read_text())
    assert receipt["source_pdf_authority_scope"] == "provenance_only_not_contact_authority"


def test_existing_contact_adoption_requires_operator_ratification(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ratification"):
        provisioning.adopt_existing_contact_authority(
            candidate_authority_path=tmp_path / "missing",
            candidate_authority_sha256="0" * 64,
            source_pdf_path=tmp_path / "missing.pdf",
            source_pdf_sha256="0" * 64,
            contact_authority_path=tmp_path / "missing-contact",
            contact_public_key_path=tmp_path / "missing-public",
            contact_registry_path=tmp_path / "missing-registry",
            device_key_path=tmp_path / "missing-device",
            output_root=tmp_path / "output",
            repository_root=tmp_path,
            operator_ratified=False,
        )


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
