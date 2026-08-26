import base64
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

import career_automation.provider_observation_authority as authority_module
from career_automation.browser_executor import (
    GreenhouseSuccessEvidence,
    validate_greenhouse_success_observation,
)
from career_automation.provider_observation_authority import (
    load_provider_observation_authority,
    verify_provider_observation_authority,
)
from career_automation.provider_observation_capture import (
    exact_committed_source_identity,
)


ROOT = Path(__file__).resolve().parent
FIXTURE = (
    ROOT / "career_automation" / "fixtures" / "greenhouse-success-test-observation.json"
)
APPLICATION_URL = "https://job-boards.greenhouse.io/example/jobs/1234567"


def _write_signed_acceptance(path: Path, payload: dict[str, object], private_key) -> None:
    signature = private_key.sign(
        authority_module.canonical_json(payload).encode("utf-8")
    )
    unsigned = payload | {
        "signature_b64": base64.b64encode(signature).decode("ascii")
    }
    document = unsigned | {
        "envelope_sha256": hashlib.sha256(
            authority_module.canonical_json(unsigned).encode("utf-8")
        ).hexdigest()
    }
    path.write_bytes(
        (authority_module.canonical_json(document) + "\n").encode("utf-8")
    )
    os.chmod(path, 0o600)


def _signed_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    not_before: str = "2026-08-27T11:00:00Z",
    expires_at: str = "2026-08-27T13:00:00Z",
) -> dict[str, object]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    archive_root = tmp_path / "archive"
    archive_root.mkdir(mode=0o700)
    os.chmod(archive_root, 0o700)
    consumption_root_sha256 = (
        authority_module.prepare_provider_observation_consumption_root(archive_root)
    )
    external_root = tmp_path / "operator-authority"
    external_root.mkdir(mode=0o700)
    os.chmod(external_root, 0o700)
    acceptances = external_root / "acceptances"
    acceptances.mkdir(mode=0o700)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_der_sha256 = hashlib.sha256(public_der).hexdigest()
    key_id = "market-observation-test-key"
    monkeypatch.setattr(authority_module, "MARKET_OBSERVATION_KEY_ID", key_id)
    monkeypatch.setattr(
        authority_module,
        "MARKET_OBSERVATION_PUBLIC_DER_SHA256",
        public_der_sha256,
    )
    public_key_path = external_root / "operator-observation-public.pem"
    public_key_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(public_key_path, 0o644)
    values = {
        "acceptance_id": "physicsx-observation-test",
        "nonce": "1" * 64,
        "not_before": not_before,
        "expires_at": expires_at,
        "job_key": "job_" + "2" * 64,
        "source_url": APPLICATION_URL,
        "source_job_id": "1234567",
        "timeout_ms": 30_000,
        "repository_commit": "3" * 40,
        "repository_tree": "4" * 40,
        "collector_source_sha256": "5" * 64,
        "consumption_root_sha256": consumption_root_sha256,
        "key_id": key_id,
        "public_der_sha256": public_der_sha256,
    }
    payload = authority_module.build_provider_observation_acceptance_payload(**values)
    envelope_path = acceptances / "physicsx-observation-test.json"
    _write_signed_acceptance(envelope_path, payload, private_key)
    verify = {
        "envelope_path": envelope_path,
        "public_key_path": public_key_path,
        "archive_root": archive_root,
        "job_key": values["job_key"],
        "source_url": values["source_url"],
        "source_job_id": values["source_job_id"],
        "timeout_ms": values["timeout_ms"],
        "repository_commit": values["repository_commit"],
        "repository_tree": values["repository_tree"],
        "collector_source_sha256": values["collector_source_sha256"],
        "now": "2026-08-27T12:00:00Z",
    }
    return {
        "archive_root": archive_root,
        "consumption_root_sha256": consumption_root_sha256,
        "envelope_path": envelope_path,
        "external_root": external_root,
        "key_id": key_id,
        "private_key": private_key,
        "public_der_sha256": public_der_sha256,
        "public_key_path": public_key_path,
        "values": values,
        "verify": verify,
    }


def _clone_authority_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    identity = exact_committed_source_identity(ROOT)
    checkout = tmp_path / "authority-repository"
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--no-hardlinks",
            str(identity.repository_root),
            str(checkout),
        ],
        check=True,
    )
    clone = checkout / identity.source_root.relative_to(identity.repository_root)
    fixtures = clone / "career_automation" / "fixtures"
    monkeypatch.setattr(authority_module, "_FIXTURE_ROOT", fixtures)
    monkeypatch.setattr(
        authority_module,
        "_POLICY_PATH",
        fixtures / "trusted-greenhouse-success-observations.json",
    )
    monkeypatch.setattr(
        authority_module,
        "_CAPTURE_OBJECT_ROOT",
        fixtures / "provider-observation-capture-objects",
    )
    return clone


def test_repository_trusted_observation_resolves_collector_and_manifest() -> None:
    value = FIXTURE.read_bytes()
    receipt = verify_provider_observation_authority(
        value,
        source_url=APPLICATION_URL,
        archive_root=ROOT,
        repository_root=ROOT,
    )
    assert receipt.collector_identity == ("jaa.repository-playwright-route-fixture.v1")
    assert receipt.scope == "repository_fixture"
    assert receipt.observation_sha256 == hashlib.sha256(value).hexdigest()
    assert len(receipt.capture_manifest_sha256) == 64
    assert len(receipt.collector_source_sha256) == 64
    assert len(receipt.trust_policy_sha256) == 64


def test_factory_loader_resolves_only_policy_selected_capture_bytes() -> None:
    value, receipt = load_provider_observation_authority(
        source_url=APPLICATION_URL,
        archive_root=ROOT,
        repository_root=ROOT,
    )
    assert value == FIXTURE.read_bytes()
    assert receipt.observation_sha256 == hashlib.sha256(value).hexdigest()


def test_factory_minted_self_consistent_observation_cannot_authorize_release() -> None:
    document = json.loads(FIXTURE.read_bytes())
    document["observed_at"] = "2026-08-06T10:00:00+00:00"
    value = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    evidence = GreenhouseSuccessEvidence(
        observation_sha256=hashlib.sha256(value).hexdigest(),
        observed_at=str(document["observed_at"]),
        confirmation_url=APPLICATION_URL + "/confirmation",
        required_visible_markers=("Thank you for applying",),
    )
    validate_greenhouse_success_observation(
        value,
        evidence,
        application_url=APPLICATION_URL,
        application_id="1234567",
        verified_at=datetime(2026, 8, 6, 12, tzinfo=timezone.utc),
    )
    with pytest.raises(ValueError, match="not a unique repository-trusted"):
        verify_provider_observation_authority(
            value,
            source_url=APPLICATION_URL,
            archive_root=ROOT,
            repository_root=ROOT,
        )


def test_trusted_bytes_cannot_be_substituted_for_another_vacancy() -> None:
    with pytest.raises(ValueError, match="not a unique repository-trusted"):
        verify_provider_observation_authority(
            FIXTURE.read_bytes(),
            source_url="https://job-boards.greenhouse.io/example/jobs/7654321",
            archive_root=ROOT,
            repository_root=ROOT,
        )


def test_runtime_trust_policy_injection_cannot_mint_production_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = FIXTURE.read_bytes()
    injected = {
        "schema_version": "jaa.trusted-provider-observations.v2",
        "authorities": [
            {
                "attempt_id": "jaa-20260806T120000Z-0000000000000000",
                "authority_id": "factory-minted",
                "collector_identity": "factory-minted",
                "network_evidence_sha256": "0" * 64,
                "observation_sha256": hashlib.sha256(value).hexdigest(),
                "observed_at": "2026-08-05T10:00:00+00:00",
                "scope": "production_archive",
                "source_url": APPLICATION_URL,
                "capture_manifest_sha256": "0" * 64,
                "vacancy_capture_sha256": "0" * 64,
            }
        ],
    }
    policy = tmp_path / "injected-policy.json"
    policy.write_text(
        json.dumps(injected, sort_keys=True, separators=(",", ":")) + "\n"
    )
    monkeypatch.setattr(authority_module, "_POLICY_PATH", policy)
    with pytest.raises(ValueError, match="differs from exact HEAD"):
        verify_provider_observation_authority(
            value,
            source_url=APPLICATION_URL,
            archive_root=tmp_path,
            repository_root=ROOT,
        )


def test_dirty_fixture_self_enrollment_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clone = _clone_authority_repository(tmp_path, monkeypatch)
    policy_path = authority_module._POLICY_PATH
    policy = json.loads(policy_path.read_bytes())
    policy["authorities"][0]["authority_id"] = "attacker.self-enrolled.v999"
    policy_path.write_text(
        json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n"
    )
    with pytest.raises(ValueError, match="exact clean HEAD"):
        verify_provider_observation_authority(
            FIXTURE.read_bytes(),
            source_url=APPLICATION_URL,
            archive_root=tmp_path,
            repository_root=clone,
        )


def test_committed_policy_cannot_relabel_capture_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clone = _clone_authority_repository(tmp_path, monkeypatch)
    policy_path = authority_module._POLICY_PATH
    policy = json.loads(policy_path.read_bytes())
    policy["authorities"][0]["collector_identity"] = "attacker.relabelled.v999"
    policy_path.write_text(
        json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n"
    )
    subprocess.run(
        ["git", "-C", str(clone), "add", str(policy_path)],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(clone),
            "-c",
            "user.name=JAA Test",
            "-c",
            "user.email=jaa-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "attempt collector relabel",
        ],
        check=True,
    )
    with pytest.raises(ValueError, match="must not assert or relabel"):
        verify_provider_observation_authority(
            FIXTURE.read_bytes(),
            source_url=APPLICATION_URL,
            archive_root=tmp_path,
            repository_root=clone,
        )


def test_signed_observation_acceptance_consumes_once_and_replays_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _signed_acceptance(tmp_path, monkeypatch)
    receipt, created = (
        authority_module.verify_and_consume_provider_observation_acceptance(
            **fixture["verify"]
        )
    )
    receipt_path = (
        fixture["archive_root"]
        / "provider-observation-acceptance-consumptions"
        / f"{receipt.nonce}.json"
    )
    original = receipt_path.read_bytes()
    replay, replay_created = (
        authority_module.verify_and_consume_provider_observation_acceptance(
            **fixture["verify"]
        )
    )
    assert created is True
    assert replay_created is False
    assert replay == receipt
    assert receipt_path.read_bytes() == original
    assert receipt.job_key == fixture["values"]["job_key"]
    assert receipt.source_url == APPLICATION_URL
    assert receipt.repository_commit == "3" * 40
    assert receipt.repository_tree == "4" * 40


def test_signed_observation_acceptance_rejects_forgery_and_wrong_target_pre_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _signed_acceptance(tmp_path, monkeypatch)
    document = json.loads(fixture["envelope_path"].read_bytes())
    signature = bytearray(base64.b64decode(document["signature_b64"]))
    signature[0] ^= 1
    document["signature_b64"] = base64.b64encode(signature).decode("ascii")
    unsigned = {
        key: value
        for key, value in document.items()
        if key != "envelope_sha256"
    }
    document["envelope_sha256"] = hashlib.sha256(
        authority_module.canonical_json(unsigned).encode("utf-8")
    ).hexdigest()
    fixture["envelope_path"].write_bytes(
        (authority_module.canonical_json(document) + "\n").encode("utf-8")
    )
    with pytest.raises(ValueError, match="signature is invalid"):
        authority_module.verify_and_consume_provider_observation_acceptance(
            **fixture["verify"]
        )
    store = fixture["archive_root"] / "provider-observation-acceptance-consumptions"
    assert tuple(store.iterdir()) == ()

    clean = _signed_acceptance(tmp_path / "wrong-target", monkeypatch)
    wrong = dict(clean["verify"])
    wrong["source_url"] = "https://job-boards.greenhouse.io/example/jobs/7654321"
    wrong["source_job_id"] = "7654321"
    with pytest.raises(ValueError, match="does not bind the exact request"):
        authority_module.verify_and_consume_provider_observation_acceptance(**wrong)
    assert tuple(
        (
            clean["archive_root"]
            / "provider-observation-acceptance-consumptions"
        ).iterdir()
    ) == ()


@pytest.mark.parametrize(
    ("not_before", "expires_at"),
    (
        ("2026-08-27T09:00:00Z", "2026-08-27T10:00:00Z"),
        ("2026-08-27T13:00:00Z", "2026-08-27T14:00:00Z"),
    ),
)
def test_signed_observation_acceptance_window_refuses_before_state_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    not_before: str,
    expires_at: str,
) -> None:
    fixture = _signed_acceptance(
        tmp_path,
        monkeypatch,
        not_before=not_before,
        expires_at=expires_at,
    )
    with pytest.raises(ValueError, match="outside its validity window"):
        authority_module.verify_and_consume_provider_observation_acceptance(
            **fixture["verify"]
        )
    assert tuple(
        (
            fixture["archive_root"]
            / "provider-observation-acceptance-consumptions"
        ).iterdir()
    ) == ()


def test_signed_observation_acceptance_nonce_cannot_retarget_or_change_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _signed_acceptance(tmp_path, monkeypatch)
    authority_module.verify_and_consume_provider_observation_acceptance(
        **fixture["verify"]
    )
    values = dict(fixture["values"])
    values.update(
        {
            "acceptance_id": "physicsx-observation-drift",
            "job_key": "job_" + "6" * 64,
            "source_url": "https://job-boards.greenhouse.io/example/jobs/7654321",
            "source_job_id": "7654321",
        }
    )
    drift_payload = authority_module.build_provider_observation_acceptance_payload(
        **values
    )
    drift_path = fixture["external_root"] / "acceptances" / "drift.json"
    _write_signed_acceptance(drift_path, drift_payload, fixture["private_key"])
    drift_verify = dict(fixture["verify"])
    drift_verify.update(
        {
            "envelope_path": drift_path,
            "job_key": values["job_key"],
            "source_url": values["source_url"],
            "source_job_id": values["source_job_id"],
        }
    )
    with pytest.raises(ValueError, match="nonce binds different evidence"):
        authority_module.verify_and_consume_provider_observation_acceptance(
            **drift_verify
        )

    alternate_root = tmp_path / "alternate-archive"
    alternate_root.mkdir(mode=0o700)
    os.chmod(alternate_root, 0o700)
    authority_module.prepare_provider_observation_consumption_root(alternate_root)
    alternate = dict(fixture["verify"])
    alternate["archive_root"] = alternate_root
    with pytest.raises(ValueError, match="does not bind the exact request"):
        authority_module.verify_and_consume_provider_observation_acceptance(
            **alternate
        )
    assert tuple(
        (
            alternate_root / "provider-observation-acceptance-consumptions"
        ).iterdir()
    ) == ()


@pytest.mark.parametrize("attack", ("symlink", "hardlink", "mode", "root_swap"))
def test_signed_observation_acceptance_refuses_unsafe_external_or_replay_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    fixture = _signed_acceptance(tmp_path, monkeypatch)
    verify = dict(fixture["verify"])
    if attack == "symlink":
        link = fixture["external_root"] / "acceptances" / "linked.json"
        link.symlink_to(fixture["envelope_path"])
        verify["envelope_path"] = link
    elif attack == "hardlink":
        os.link(
            fixture["public_key_path"],
            fixture["external_root"] / "second-public.pem",
        )
    elif attack == "mode":
        os.chmod(fixture["envelope_path"], 0o644)
    else:
        archive_root = fixture["archive_root"]
        archive_root.rename(tmp_path / "original-archive")
        archive_root.mkdir(mode=0o700)
        os.chmod(archive_root, 0o700)
        authority_module.prepare_provider_observation_consumption_root(archive_root)
    with pytest.raises(ValueError):
        authority_module.verify_and_consume_provider_observation_acceptance(**verify)
