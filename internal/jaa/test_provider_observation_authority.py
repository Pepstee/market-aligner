import hashlib
import json
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
