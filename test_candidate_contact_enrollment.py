from __future__ import annotations

import json
import stat
from datetime import datetime, timezone

import pytest

import career_automation.candidate_contact_authority as contact_module
from career_automation.candidate_contact_authority import (
    PUBLIC_KEY_ENV,
    REGISTRY_ENV,
    load_candidate_contact_authority,
)
from scripts.enroll_candidate_contact_authority import enroll_contact_authority


def test_production_operator_contact_key_is_enrolled() -> None:
    enrolled = contact_module.ENROLLED_OPERATOR_PUBLIC_KEY_SHA256
    assert isinstance(enrolled, str)
    assert len(enrolled) == 64


def _enrol(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    output = tmp_path / "private" / "contact"
    output.parent.mkdir()
    result = enroll_contact_authority(
        output_root=output,
        repository_root=repository,
        full_name="Jordan Smith",
        email="jordan.smith@proton.me",
        city="London",
        phone=None,
        issued_at=datetime(2026, 8, 10, 12, tzinfo=timezone.utc),
    )
    return repository, output, result


def test_enrollment_creates_loadable_genesis_without_phone(
    tmp_path, monkeypatch
) -> None:
    repository, output, result = _enrol(tmp_path)
    public_path = output / "keys" / "operator-contact-public-key.pem"
    private_path = output / "keys" / "operator-contact-private-key.pem"
    monkeypatch.setattr(
        contact_module,
        "ENROLLED_OPERATOR_PUBLIC_KEY_SHA256",
        result["public_key_sha256"],
    )
    monkeypatch.setenv(PUBLIC_KEY_ENV, str(public_path))
    monkeypatch.setenv(REGISTRY_ENV, str(output / "registry"))
    authority = load_candidate_contact_authority(
        result["authority_path"],
        repository_root=repository,
        verified_at=datetime(2026, 8, 10, 12, tzinfo=timezone.utc),
    )
    assert authority.contact.full_name == "Jordan Smith"
    assert authority.contact.phone is None
    assert authority.authority_sha256 == result["authority_sha256"]
    assert authority.registry_sha256 == result["registry_sha256"]
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(public_path.stat().st_mode) == 0o600
    manifest = json.loads((output / "enrollment-manifest.json").read_text())
    assert "full_name" not in manifest
    assert "email" not in manifest


def test_enrollment_is_create_only_and_must_be_outside_repository(tmp_path) -> None:
    repository, output, _ = _enrol(tmp_path)
    with pytest.raises(FileExistsError, match="already exists"):
        enroll_contact_authority(
            output_root=output,
            repository_root=repository,
            full_name="Jordan Smith",
            email="jordan.smith@proton.me",
            city="London",
        )
    with pytest.raises(ValueError, match="outside the repository"):
        enroll_contact_authority(
            output_root=repository / "private",
            repository_root=repository,
            full_name="Jordan Smith",
            email="jordan.smith@proton.me",
            city="London",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("full_name", "Test User"),
        ("email", "test@example.test"),
        ("city", "Example City"),
        ("phone", "000000"),
    ),
)
def test_enrollment_rejects_placeholder_values(tmp_path, field, value) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    arguments = {
        "output_root": tmp_path / "private",
        "repository_root": repository,
        "full_name": "Jordan Smith",
        "email": "jordan.smith@proton.me",
        "city": "London",
        "phone": None,
    }
    arguments[field] = value
    with pytest.raises(ValueError, match="placeholder"):
        enroll_contact_authority(**arguments)
