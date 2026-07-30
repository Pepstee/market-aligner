"""Negative controls for the network-witnessed local fixture boundary."""

from __future__ import annotations

import inspect
import json
import socket
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

import career_automation.linux_network_namespace_witness as witness_module
import career_automation.network_witnessed_fixture as fixture_module
from career_automation.linux_network_namespace_witness import SourceIdentity
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
    _document_inventory,
    _domain_hash,
    _finalize_worker_database,
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
        "runtime_tmp_root": "/tmp/.jaa10rt-0123456789abcdef",
        "runtime_tmp_root_derivation": {
            "schema_version": (
                "jaa10.network-witnessed-runtime-tmp-derivation.v1"
            ),
            "domain": "jaa10-network-witnessed-runtime-tmp-path-v1\0",
            "canonical_input_sha256": "f" * 64,
            "token": "0123456789abcdef",
        },
        "socket_budget": {
            "schema_version": (
                "jaa10.network-witnessed-runtime-tmp-socket-budget.v1"
            ),
            "af_unix_path_capacity_bytes": 107,
            "chromium_suffix_bytes": 45,
            "maximum_root_bytes": 62,
            "observed_root_bytes": 34,
            "observed_total_bytes": 79,
        },
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
        "runtime_tmp_root": request["runtime_tmp_root"],
        "runtime_tmp_root_derivation": request[
            "runtime_tmp_root_derivation"
        ],
        "socket_budget": request["socket_budget"],
        "worker_database_finalization": {
            "journal_mode": "wal",
            "checkpoint_mode": "truncate",
            "busy": 0,
            "log_frames": 0,
            "checkpointed_frames": 0,
        },
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


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("runtime_tmp_root", "/tmp/other"),
        ("runtime_tmp_root_derivation", {}),
        ("socket_budget", {}),
    ),
)
def test_worker_result_rejects_runtime_tmp_binding_tamper(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    result, request, request_bytes = _valid_result(tmp_path)
    result[field] = value
    with pytest.raises(NetworkWitnessedFixtureError, match="authority"):
        validate_worker_result(
            result,
            request=request,
            request_bytes=request_bytes,
            output_root=tmp_path,
        )


def test_worker_result_rejects_database_finalization_tamper(
    tmp_path: Path,
) -> None:
    result, request, request_bytes = _valid_result(tmp_path)
    result["worker_database_finalization"] = {
        "journal_mode": "wal",
        "checkpoint_mode": "truncate",
        "busy": 1,
        "log_frames": 1,
        "checkpointed_frames": 0,
    }
    with pytest.raises(
        NetworkWitnessedFixtureError,
        match="finalization differs",
    ):
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
            "runtime_tmp_root": "/tmp/.jaa10rt-0123456789abcdef",
            "runtime_tmp_root_derivation": {
                "schema_version": (
                    "jaa10.network-witnessed-runtime-tmp-derivation.v1"
                ),
                "domain": (
                    "jaa10-network-witnessed-runtime-tmp-path-v1\0"
                ),
                "canonical_input_sha256": "7" * 64,
                "token": "0123456789abcdef",
            },
            "socket_budget": {
                "schema_version": (
                    "jaa10.network-witnessed-runtime-tmp-socket-budget.v1"
                ),
                "af_unix_path_capacity_bytes": 107,
                "chromium_suffix_bytes": 45,
                "maximum_root_bytes": 62,
                "observed_root_bytes": 34,
                "observed_total_bytes": 79,
            },
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


def test_runtime_tmp_path_is_not_a_caller_parameter() -> None:
    parameters = inspect.signature(run_network_witnessed_fixture).parameters
    assert "runtime_tmp_root" not in parameters
    assert "tmpdir" not in parameters


@pytest.mark.parametrize(
    "kind",
    ("file", "directory", "symlink", "dangling_symlink", "socket"),
)
def test_preexisting_runtime_tmp_object_fails_before_browser(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
    kind: str,
) -> None:
    source = SourceIdentity(
        "a" * 40,
        "b" * 40,
        "sha256:" + ("c" * 64),
    )
    anchor = tmp_path_factory.getbasetemp()
    monkeypatch.setattr(
        witness_module,
        "RUNTIME_TMP_HOME_ANCHOR",
        anchor,
    )
    monkeypatch.setattr(fixture_module, "_source_identity", lambda _root: source)
    execution_root = tmp_path / f"collision-{kind}"
    runtime_tmp_root, _derivation, _budget = (
        witness_module.derive_runtime_tmp_binding(source, execution_root)
    )
    endpoint: socket.socket | None = None
    if kind == "file":
        runtime_tmp_root.write_bytes(b"occupied")
    elif kind == "directory":
        runtime_tmp_root.mkdir(mode=0o700)
    elif kind == "symlink":
        runtime_tmp_root.symlink_to(anchor)
    elif kind == "dangling_symlink":
        runtime_tmp_root.symlink_to(anchor / "absent-target")
    else:
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        endpoint.bind(str(runtime_tmp_root))
    try:
        with pytest.raises(
            NetworkWitnessedFixtureError,
            match="preflight",
        ):
            run_network_witnessed_fixture(
                repository_root=ROOT,
                execution_root=execution_root,
                python_executable=Path("/usr/bin/python3"),
                chromium_executable=Path("/bin/true"),
            )
    finally:
        if endpoint is not None:
            endpoint.close()
    assert not execution_root.exists()


def test_runtime_tmp_contract_literals_and_schema_versions_are_pinned() -> None:
    witness_source = (
        ROOT / "career_automation/linux_network_namespace_witness.py"
    ).read_text(encoding="utf-8")
    fixture_source = (
        ROOT / "career_automation/network_witnessed_fixture.py"
    ).read_text(encoding="utf-8")

    for literal in (
        'RUNTIME_TMP_HOME_ANCHOR = Path("/home/gutua")',
        "AF_UNIX_PATH_CAPACITY = 107",
        "CHROMIUM_RUNTIME_TMP_SUFFIX_BYTES = 45",
        'b"jaa10-network-witnessed-runtime-tmp-path-v1\\0"',
        '"jaa10.cooperative-browser-expectation.v2"',
        '"jaa10.network-witnessed-fixture-worker-result.v2"',
    ):
        assert literal in witness_source
    for literal in (
        '"jaa10.network-witnessed-fixture-request.v2"',
        '"jaa10.network-witnessed-fixture-worker-result.v2"',
        '"jaa10.network-witnessed-fixture-observation-receipt.v2"',
        '"jaa10.network-witnessed-reconstruction.v2"',
    ):
        assert literal in fixture_source


def test_worker_database_finalization_fails_on_active_reader(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database = tmp_path / "workflow.sqlite3"
    writer = sqlite3.connect(database)
    reader = sqlite3.connect(database)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == (
            "wal",
        )
        writer.execute("CREATE TABLE evidence(value TEXT)")
        writer.execute("INSERT INTO evidence VALUES ('first')")
        writer.commit()
        reader.execute("BEGIN")
        assert reader.execute("SELECT * FROM evidence").fetchone() == (
            "first",
        )
        writer.execute("INSERT INTO evidence VALUES ('second')")
        writer.commit()
        real_connect = sqlite3.connect

        def immediate_connect(path, timeout=30):
            return real_connect(path, timeout=0)

        monkeypatch.setattr(fixture_module.sqlite3, "connect", immediate_connect)
        with pytest.raises(
            NetworkWitnessedFixtureError,
            match="did not quiesce",
        ):
            _finalize_worker_database(database)
    finally:
        reader.close()
        writer.close()


def test_worker_inventory_sidecar_exclusion_is_root_exact(
    tmp_path: Path,
) -> None:
    (tmp_path / "workflow.sqlite3").write_bytes(b"database")
    (tmp_path / "workflow.sqlite3-wal").write_bytes(b"root wal")
    (tmp_path / "workflow.sqlite3-shm").write_bytes(b"root shm")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "workflow.sqlite3-wal").write_bytes(b"nested wal")
    for path in tmp_path.rglob("*"):
        if path.is_file():
            path.chmod(0o444)

    inventory, _inventory_sha256 = _document_inventory(
        tmp_path,
        domain=WORKER_INVENTORY_DOMAIN,
    )
    relative_paths = {row["relative_path"] for row in inventory}
    assert "workflow.sqlite3" in relative_paths
    assert "workflow.sqlite3-wal" not in relative_paths
    assert "workflow.sqlite3-shm" not in relative_paths
    assert "sub/workflow.sqlite3-wal" in relative_paths
