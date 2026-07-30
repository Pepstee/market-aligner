"""Negative controls for the network-witnessed local fixture boundary."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from career_automation.network_witnessed_fixture import (
    COMPOSITE_SCHEMA_VERSION,
    EFFECTIVE_ARGV_DOMAIN,
    ENVIRONMENT_DOMAIN,
    LIMITATIONS,
    REQUEST_DOMAIN,
    REQUIRED_CHROMIUM_FLAGS,
    RESULT_SCHEMA_VERSION,
    STRONGEST_CLAIM,
    WORKER_INVENTORY_DOMAIN,
    NetworkWitnessedFixtureError,
    NetworkWitnessedFixtureObservationReceipt,
    _canonical_json,
    _domain_hash,
    run_network_witnessed_fixture,
    validate_worker_result,
)
from test_jaa10_independent_acceptance import _observation


ROOT = Path(__file__).resolve().parent


def _request() -> dict[str, object]:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": "/tmp/integration-tmp",
    }
    return {
        "source": {
            "git_revision": "a" * 40,
            "tree": "b" * 40,
            "content_revision": "sha256:" + ("c" * 64),
        },
        "integration_nonce_sha256": "d" * 64,
        "cooperative_policy_sha256": "e" * 64,
        "environment": environment,
        "environment_sha256": _domain_hash(
            ENVIRONMENT_DOMAIN,
            _canonical_json(environment),
        ),
    }


def _valid_result(output_root: Path) -> tuple[dict[str, object], dict[str, object], bytes]:
    request = _request()
    request_bytes = _canonical_json(request)
    artifact = output_root / "artifact.txt"
    artifact.write_bytes(b"bounded synthetic artifact")
    artifact.chmod(0o444)
    inventory = [
        {
            "relative_path": "artifact.txt",
            "mode": "0444",
            "size": artifact.stat().st_size,
            "sha256": __import__("hashlib").sha256(
                artifact.read_bytes()
            ).hexdigest(),
        }
    ]
    observation = _observation(
        "negative-control",
        datetime(2030, 1, 2, tzinfo=timezone.utc),
    ).document()
    argv = ["/pinned/chromium", *REQUIRED_CHROMIUM_FLAGS]
    result: dict[str, object] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "request_sha256": _domain_hash(REQUEST_DOMAIN, request_bytes),
        "integration_nonce_sha256": request["integration_nonce_sha256"],
        "source": request["source"],
        "cooperative_policy_sha256": request["cooperative_policy_sha256"],
        "environment": request["environment"],
        "environment_sha256": request["environment_sha256"],
        "shared_memory": {
            "path": "/dev/shm",
            "disable_dev_shm_usage_required": True,
        },
        "chromium_effective_argv": argv,
        "chromium_effective_argv_sha256": _domain_hash(
            EFFECTIVE_ARGV_DOMAIN,
            _canonical_json({"argv": argv}),
        ),
        "runtime_identities": {},
        "fixture_receipt": observation["fixture_receipt"],
        "submission_proof": observation["submission_proof"],
        "observation": observation,
        "artifact_inventory": inventory,
        "worker_artifact_inventory_sha256": _domain_hash(
            WORKER_INVENTORY_DOMAIN,
            _canonical_json({"files": inventory}),
        ),
        "evidence_kind": "synthetic_shadow",
        "execution_claim": "structural_lineage_only",
        "external_actions": 0,
        "real_applications_submitted": 0,
    }
    return result, request, request_bytes


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        ("external_actions", 1, "authority"),
        ("real_applications_submitted", 1, "authority"),
        ("evidence_kind", "live_external", "authority"),
        ("execution_claim", "production_certified", "authority"),
    ),
)
def test_worker_result_cannot_elevate_its_claim(
    tmp_path: Path,
    field: str,
    value: object,
    match: str,
) -> None:
    result, request, request_bytes = _valid_result(tmp_path)
    result[field] = value
    with pytest.raises(NetworkWitnessedFixtureError, match=match):
        validate_worker_result(
            result,
            request=request,
            request_bytes=request_bytes,
            output_root=tmp_path,
        )


def test_worker_result_rejects_future_or_fd_self_report_fields(
    tmp_path: Path,
) -> None:
    result, request, request_bytes = _valid_result(tmp_path)
    result["network_witness_sha256"] = "f" * 64
    result["worker_fd_inventory"] = []
    with pytest.raises(NetworkWitnessedFixtureError, match="field set"):
        validate_worker_result(
            result,
            request=request,
            request_bytes=request_bytes,
            output_root=tmp_path,
        )


def test_effective_browser_policy_cannot_omit_required_flag(
    tmp_path: Path,
) -> None:
    result, request, request_bytes = _valid_result(tmp_path)
    argv = list(result["chromium_effective_argv"])
    argv.remove(REQUIRED_CHROMIUM_FLAGS[0])
    result["chromium_effective_argv"] = argv
    result["chromium_effective_argv_sha256"] = _domain_hash(
        EFFECTIVE_ARGV_DOMAIN,
        _canonical_json({"argv": argv}),
    )
    with pytest.raises(NetworkWitnessedFixtureError, match="policy"):
        validate_worker_result(
            result,
            request=request,
            request_bytes=request_bytes,
            output_root=tmp_path,
        )


def test_worker_artifact_tamper_fails_independent_reconstruction(
    tmp_path: Path,
) -> None:
    result, request, request_bytes = _valid_result(tmp_path)
    (tmp_path / "artifact.txt").chmod(0o600)
    (tmp_path / "artifact.txt").write_bytes(b"changed after result")
    (tmp_path / "artifact.txt").chmod(0o444)
    with pytest.raises(NetworkWitnessedFixtureError, match="inventory"):
        validate_worker_result(
            result,
            request=request,
            request_bytes=request_bytes,
            output_root=tmp_path,
        )


def _composite() -> NetworkWitnessedFixtureObservationReceipt:
    return NetworkWitnessedFixtureObservationReceipt.issue(
        {
            "schema_version": COMPOSITE_SCHEMA_VERSION,
            "integration_status": (
                "network_witnessed_local_fixture_single_execution"
            ),
            "source": {
                "git_revision": "a" * 40,
                "tree": "b" * 40,
                "content_revision": "sha256:" + ("c" * 64),
            },
            "request_sha256": "d" * 64,
            "integration_nonce_sha256": "e" * 64,
            "cooperative_policy_sha256": "f" * 64,
            "worker_result_sha256": "1" * 64,
            "worker_artifact_inventory_sha256": "2" * 64,
            "network_witness_sha256": "3" * 64,
            "network_receipt_sha256": "4" * 64,
            "observation_sha256": "5" * 64,
            "component_inventory": [],
            "component_inventory_sha256": "6" * 64,
            "strongest_claim": STRONGEST_CLAIM,
            "limitations": list(LIMITATIONS),
            "evidence_kind": "synthetic_shadow",
            "execution_claim": "structural_lineage_only",
            "objective_satisfied": False,
            "certifies_slice": False,
            "external_actions": 0,
            "real_applications_submitted": 0,
        }
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("certifies_slice", True),
        ("objective_satisfied", True),
        ("external_actions", 1),
        ("real_applications_submitted", 1),
        ("integration_status", "production"),
    ),
)
def test_composite_truth_elevation_fails_closed(
    field: str,
    value: object,
) -> None:
    receipt = _composite()
    document = receipt.document()
    document[field] = value
    with pytest.raises(NetworkWitnessedFixtureError):
        NetworkWitnessedFixtureObservationReceipt(
            _canonical_json(document)
        )


def test_composite_receipt_hash_detects_reordering_or_mutation() -> None:
    receipt = _composite()
    document = json.loads(receipt.canonical_document)
    document["network_witness_sha256"] = "7" * 64
    with pytest.raises(NetworkWitnessedFixtureError, match="hash"):
        NetworkWitnessedFixtureObservationReceipt(
            _canonical_json(document)
        )


def test_existing_or_relative_execution_root_fails_before_browser(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(NetworkWitnessedFixtureError, match="new absolute"):
        run_network_witnessed_fixture(
            repository_root=ROOT,
            execution_root=existing,
            python_executable=ROOT / ".venv/bin/python",
            chromium_executable=Path("/does/not/matter"),
        )
    with pytest.raises(NetworkWitnessedFixtureError, match="new absolute"):
        run_network_witnessed_fixture(
            repository_root=ROOT,
            execution_root=Path("relative-execution"),
            python_executable=ROOT / ".venv/bin/python",
            chromium_executable=Path("/does/not/matter"),
        )
