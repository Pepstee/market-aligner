from __future__ import annotations

import hashlib
import json
import base64
import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import career_automation.candidate_contact_authority as contact_module
from career_automation.candidate_contact_authority import (
    ATTESTATION,
    REGISTRY_ATTESTATION,
    REGISTRY_ENV,
    REGISTRY_SCHEMA_VERSION,
    SCHEMA_VERSION,
    CandidateContactResourceLease,
    load_candidate_contact_authority,
)
from career_automation.evidence_matching import canonical_json
from career_automation.production_form_binding import approved_authority_values


ROOT = Path(__file__).resolve().parent
TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()
TEST_PUBLIC_RAW = TEST_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
TEST_PUBLIC_SHA256 = hashlib.sha256(TEST_PUBLIC_RAW).hexdigest()


@pytest.fixture(autouse=True)
def _enrol_test_operator_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public_key_path = tmp_path / "operator-contact-public-key.pem"
    public_key_path.write_bytes(
        TEST_PRIVATE_KEY.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setattr(
        contact_module,
        "ENROLLED_OPERATOR_PUBLIC_KEY_SHA256",
        TEST_PUBLIC_SHA256,
    )
    monkeypatch.setenv(contact_module.PUBLIC_KEY_ENV, str(public_key_path))
    registry = tmp_path / "contact-registry"
    registry.mkdir()
    monkeypatch.setenv(REGISTRY_ENV, str(registry))


def _registry(
    directory: Path,
    authority_path: Path,
    *,
    issued_at: str,
    registry_version: int = 1,
    prior: Path | None = None,
    revoked: tuple[str, ...] = (),
) -> Path:
    authority = json.loads(authority_path.read_text())
    signed_payload = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_operator_contact_registry",
        "operator_attestation": REGISTRY_ATTESTATION,
        "issued_at": issued_at,
        "registry_id": "operator-contact-primary",
        "registry_version": registry_version,
        "current": {
            "record_id": authority["record_id"],
            "record_version": authority["record_version"],
            "authority_sha256": authority_path.stem,
        },
        "revoked_authority_sha256s": sorted(revoked),
        "prior_registry_sha256": prior.stem if prior is not None else None,
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": TEST_PUBLIC_SHA256,
    }
    signature = base64.b64encode(
        TEST_PRIVATE_KEY.sign((canonical_json(signed_payload) + "\n").encode())
    ).decode()
    content_addressed = {**signed_payload, "signature_base64": signature}
    digest = hashlib.sha256(
        (canonical_json(content_addressed) + "\n").encode()
    ).hexdigest()
    path = directory / "contact-registry" / f"{digest}.json"
    path.write_text(
        canonical_json({**content_addressed, "registry_sha256": digest}) + "\n"
    )
    return path


def _authority(
    directory: Path,
    *,
    issued_at: str = "2026-08-06T12:00:00+00:00",
    record_version: int = 1,
    create_registry: bool = True,
    **contact_changes: object,
) -> Path:
    contact = {
        "full_name": "Jordan Smith",
        "email": "jordan.smith@proton.me",
        "phone": "+44 7700 900123",
        "city": "London",
        **contact_changes,
    }
    signed_payload = {
        "schema_version": SCHEMA_VERSION,
        "authority_kind": "ed25519_signed_explicit_operator_attestation",
        "operator_attestation": ATTESTATION,
        "issued_at": issued_at,
        "record_id": "operator-contact-primary",
        "record_version": record_version,
        "contact": contact,
        "signature_algorithm": "Ed25519",
        "signer_public_key_sha256": TEST_PUBLIC_SHA256,
    }
    signature = base64.b64encode(
        TEST_PRIVATE_KEY.sign((canonical_json(signed_payload) + "\n").encode())
    ).decode()
    content_addressed = {**signed_payload, "signature_base64": signature}
    digest = hashlib.sha256(
        (canonical_json(content_addressed) + "\n").encode()
    ).hexdigest()
    path = directory / f"{digest}.json"
    path.write_text(
        canonical_json({**content_addressed, "authority_sha256": digest}) + "\n"
    )
    if create_registry:
        _registry(directory, path, issued_at=issued_at)
    return path


def test_loads_explicit_content_addressed_contact_outside_repository(
    tmp_path: Path,
) -> None:
    path = _authority(tmp_path)
    authority = load_candidate_contact_authority(
        path,
        repository_root=ROOT,
        verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
    )
    assert authority.source_path == path
    assert authority.authority_sha256 == path.stem
    assert len(authority.registry_sha256) == 64
    assert authority.contact.city == "London"
    assert authority.contact.provenance_sha256 == path.stem


def test_rejects_renamed_or_modified_authority(tmp_path: Path) -> None:
    path = _authority(tmp_path)
    renamed = tmp_path / ("f" * 64 + ".json")
    path.rename(renamed)
    with pytest.raises(ValueError, match="identity or attestation"):
        load_candidate_contact_authority(renamed, repository_root=ROOT)

    path = _authority(tmp_path)
    document = json.loads(path.read_text())
    document["contact"]["city"] = "Bristol"
    path.write_text(canonical_json(document) + "\n")
    with pytest.raises(ValueError, match="identity or attestation"):
        load_candidate_contact_authority(path, repository_root=ROOT)


def test_rejects_repository_enrolled_contact_fixture() -> None:
    with pytest.raises(ValueError, match="outside the repository"):
        load_candidate_contact_authority(
            ROOT / "career_automation/fixtures/candidate-authority-schema-v1.json",
            repository_root=ROOT,
        )


def test_city_is_never_optional_or_inferred(tmp_path: Path) -> None:
    path = _authority(tmp_path, city="")
    with pytest.raises(ValueError, match="candidate city is required"):
        load_candidate_contact_authority(
            path,
            repository_root=ROOT,
            verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
        )


def test_phone_may_be_explicitly_absent(tmp_path: Path) -> None:
    path = _authority(tmp_path, phone=None)
    authority = load_candidate_contact_authority(
        path,
        repository_root=ROOT,
        verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
    )
    assert authority.contact.phone is None
    values = approved_authority_values(
        SimpleNamespace(contact=authority.contact, facts=(), style_slots=(), answers=()),
        SimpleNamespace(editable=SimpleNamespace(answers_text="")),
    )
    assert "contact.phone" not in values


@pytest.mark.parametrize(
    "changes",
    (
        {"full_name": "Test User"},
        {"email": "test@example.test"},
        {"phone": "0000000000"},
        {"city": "Example City"},
    ),
)
def test_rejects_placeholder_contact_values(
    tmp_path: Path,
    changes: dict[str, object],
) -> None:
    path = _authority(tmp_path, **changes)
    with pytest.raises(ValueError, match="placeholder"):
        load_candidate_contact_authority(
            path,
            repository_root=ROOT,
            verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
        )


def test_rejects_stale_contact_authority(tmp_path: Path) -> None:
    path = _authority(tmp_path, issued_at="1999-01-01T00:00:00+00:00")
    with pytest.raises(ValueError, match="identity or attestation"):
        load_candidate_contact_authority(
            path,
            repository_root=ROOT,
            verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
        )


def test_rejects_contact_signed_by_an_unenrolled_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _authority(tmp_path)
    alternate = Ed25519PrivateKey.generate()
    alternate_path = tmp_path / "alternate-public-key.pem"
    alternate_path.write_bytes(
        alternate.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv(contact_module.PUBLIC_KEY_ENV, str(alternate_path))
    with pytest.raises(ValueError, match="not the enrolled operator key"):
        load_candidate_contact_authority(
            path,
            repository_root=ROOT,
            verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
        )


def test_production_fails_closed_without_operator_key_enrollment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _authority(tmp_path)
    monkeypatch.setattr(
        contact_module, "ENROLLED_OPERATOR_PUBLIC_KEY_SHA256", None
    )
    with pytest.raises(ValueError, match="no operator contact signing key"):
        load_candidate_contact_authority(
            path,
            repository_root=ROOT,
            verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
        )


def test_conflicting_signed_records_have_no_unique_current_head(
    tmp_path: Path,
) -> None:
    first = _authority(tmp_path)
    _authority(tmp_path, city="Bristol")

    with pytest.raises(ValueError, match="no unique current head"):
        load_candidate_contact_authority(
            first,
            repository_root=ROOT,
            verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
        )


def test_version_two_requires_monotonic_signed_revocation_chain(
    tmp_path: Path,
) -> None:
    first = _authority(tmp_path)
    first_registry = next((tmp_path / "contact-registry").iterdir())
    second = _authority(
        tmp_path,
        record_version=2,
        create_registry=False,
        city="Bristol",
    )
    _registry(
        tmp_path,
        second,
        issued_at="2026-08-06T12:01:00+00:00",
        registry_version=2,
        prior=first_registry,
        revoked=(first.stem,),
    )

    current = load_candidate_contact_authority(
        second,
        repository_root=ROOT,
        verified_at=datetime(2026, 8, 6, 12, 1, tzinfo=timezone.utc),
    )
    assert current.contact.record_version == 2
    with pytest.raises(ValueError, match="not the registry current record"):
        load_candidate_contact_authority(
            first,
            repository_root=ROOT,
            verified_at=datetime(2026, 8, 6, 12, 1, tzinfo=timezone.utc),
        )


def test_pinned_resource_lease_carries_complete_signed_registry_chain(
    tmp_path: Path,
) -> None:
    first = _authority(tmp_path)
    first_registry = next((tmp_path / "contact-registry").iterdir())
    second = _authority(
        tmp_path,
        record_version=2,
        create_registry=False,
        city="Bristol",
    )
    second_registry = _registry(
        tmp_path,
        second,
        issued_at="2026-08-06T12:01:00+00:00",
        registry_version=2,
        prior=first_registry,
        revoked=(first.stem,),
    )
    public_key_path = Path(os.environ[contact_module.PUBLIC_KEY_ENV])
    os.environ[REGISTRY_ENV] = str(second_registry)
    lease = CandidateContactResourceLease(
        authority_path=second,
        authority_bytes=second.read_bytes(),
        public_key_path=public_key_path,
        public_key_bytes=public_key_path.read_bytes(),
        registry_path=second_registry,
        registry_bytes=second_registry.read_bytes(),
        registry_chain=(
            (second_registry, second_registry.read_bytes()),
            (first_registry, first_registry.read_bytes()),
        ),
    )

    current = load_candidate_contact_authority(
        second,
        repository_root=ROOT,
        verified_at=datetime(2026, 8, 6, 12, 1, tzinfo=timezone.utc),
        resource_lease=lease,
    )
    assert current.contact.record_version == 2
    assert current.contact.city == "Bristol"

    with pytest.raises(ValueError, match="chain is incomplete"):
        load_candidate_contact_authority(
            second,
            repository_root=ROOT,
            verified_at=datetime(2026, 8, 6, 12, 1, tzinfo=timezone.utc),
            resource_lease=CandidateContactResourceLease(
                authority_path=second,
                authority_bytes=second.read_bytes(),
                public_key_path=public_key_path,
                public_key_bytes=public_key_path.read_bytes(),
                registry_path=second_registry,
                registry_bytes=second_registry.read_bytes(),
            ),
        )


def test_independent_version_two_cannot_skip_registry_history(tmp_path: Path) -> None:
    second = _authority(tmp_path, record_version=2)
    with pytest.raises(ValueError, match="genesis is invalid"):
        load_candidate_contact_authority(
            second,
            repository_root=ROOT,
            verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
        )
