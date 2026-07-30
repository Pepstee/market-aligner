"""Positive controls for the standalone Linux network witness."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from career_automation.linux_network_namespace_witness import (
    CAPABILITY_FIELDS,
    COMMAND_ENVIRONMENT,
    COOPERATIVE_BROWSER_CONTROLS_DOMAIN,
    CooperativeBrowserExpectation,
    FD_INVENTORY_DOMAIN,
    PINNED_TOOLS,
    RECEIPT_SCHEMA_VERSION,
    RECEIPT_SCHEMA_VERSION_V1,
    SCHEMA_VERSION,
    SCHEMA_VERSION_V1,
    WITNESS_DOMAIN_V1,
    LinuxNetworkNamespaceWitness,
    NetworkNamespaceWitnessReceipt,
    _canonical_json,
    _domain_hash,
    _source_identity,
    run_isolated_network_witness,
)
from career_automation.network_witnessed_fixture import (
    EFFECTIVE_ARGV_DOMAIN,
    REQUEST_DOMAIN,
    RESULT_SCHEMA_VERSION,
    WORKER_INVENTORY_DOMAIN,
    _request_document,
)
from test_jaa10_independent_acceptance import _observation

ROOT = Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def accepted_witness(tmp_path_factory: pytest.TempPathFactory):
    evidence_root = tmp_path_factory.mktemp("network-witness") / "evidence"
    witness, receipt = run_isolated_network_witness(
        (
            sys.executable,
            "-c",
            (
                "import socket; "
                "s=socket.socket(); "
                "s.bind(('127.0.0.1', 0)); "
                "print('isolated-loopback-ok'); "
                "s.close()"
            ),
        ),
        repository_root=ROOT,
        evidence_directory=evidence_root,
    )
    return evidence_root, witness, receipt


def test_exact_source_tool_and_schema_binding(accepted_witness) -> None:
    _, witness, receipt = accepted_witness
    document = witness.document()

    assert document["schema_version"] == SCHEMA_VERSION
    assert receipt.schema_version == RECEIPT_SCHEMA_VERSION
    assert document["source"] == receipt.source.document()
    assert document["source"]["git_revision"]
    assert document["source"]["tree"]
    assert document["source"]["content_revision"].startswith("sha256:")
    assert set(document["tools"]) == set(PINNED_TOOLS)
    for path, expected in PINNED_TOOLS.items():
        assert document["tools"][path]["sha256"] == expected["sha256"]
        assert document["tools"][path]["version"] == expected["version"]
    assert COMMAND_ENVIRONMENT["PYTHONDONTWRITEBYTECODE"] == "1"
    assert (
        document["cooperative_browser_controls"]
        == {
            "schema_version": "jaa10.cooperative-browser-controls.v2",
            "integration_status": "not_integrated_standalone_harness",
            "existing_loopback_controls_required_for_future_integration": True,
            "external_actions": 0,
            "real_applications_submitted": 0,
        }
    )


def test_kernel_namespace_capability_claim_is_exact(
    accepted_witness,
) -> None:
    _, witness, _ = accepted_witness
    document = witness.document()
    pre = document["pre_state"]
    post = document["post_state"]

    assert document["claim"] == {
        "external_ip_network_capability": (
            "absent_under_linux_network_namespace"
        ),
        "network_syscall_attempts": "not_measured",
        "packet_history": "not_captured",
        "host_wide_traffic": "not_claimed",
    }
    assert pre["network_namespace"] == post["network_namespace"]
    assert pre["network_namespace"] != (
        document["supervisor"]["network_namespace"]
    )
    assert pre["user_namespace"] == post["user_namespace"]
    assert pre["interfaces"] == ["lo"]
    assert pre["ipv4_routes"] == []
    assert set(pre["ipv4_fib_addresses"]) == {
        "127.0.0.0",
        "127.0.0.1",
        "127.255.255.255",
    }
    assert pre["ipv6_addresses"] == [
        {
            "address": "::1",
            "interface_index": 1,
            "prefix": 128,
            "scope": 16,
            "flags": 128,
            "interface": "lo",
        }
    ]
    for state in (pre, post):
        assert state["no_new_privs"] == "1"
        assert set(state["capabilities"]) == set(CAPABILITY_FIELDS)
        assert set(state["capabilities"].values()) == {
            "0000000000000000"
        }


def test_raw_ipv6_route_evidence_is_explicitly_fail_closed(
    accepted_witness,
) -> None:
    _, witness, _ = accepted_witness
    document = witness.document()
    pre = document["pre_state"]

    classifications = {
        row["classification"] for row in pre["ipv6_routes"]
    }
    assert classifications == {
        "loopback_local_host",
        "loopback_namespace_unreachable_default",
    }
    assert all(row["interface"] == "lo" for row in pre["ipv6_routes"])
    assert all(row["next_hop"] == "::" for row in pre["ipv6_routes"])
    assert pre["raw_proc_net_sha256"]["ipv6_route"]
    assert (
        pre["raw_proc_net_sha256"]["ipv6_route"]
        == document["post_state"]["raw_proc_net_sha256"]["ipv6_route"]
    )


def test_descriptor_inventory_is_exact_and_socket_free(
    accepted_witness,
) -> None:
    _, witness, receipt = accepted_witness
    document = witness.document()
    pre = document["fd_inventory_pre"]
    post = document["fd_inventory_post"]
    policy = document["descriptor_policy"]

    assert pre == post
    assert len(pre) == 5
    assert {row["fd"] for row in pre} == {
        0,
        1,
        2,
        *policy["pass_fds"],
    }
    assert all(
        not row["target"].startswith("socket:[") for row in pre
    )
    assert document["inherited_ip_socket_count"] == 0
    assert document["inherited_socket_count"] == 0
    assert document["post_execution_socket_count"] == 0
    assert tuple(document["designated_pipe_inodes"]) == (
        receipt.designated_pipe_inodes
    )
    assert policy["fd_passing_capability"] is False
    assert receipt.fd_inventory_pre_sha256 == _domain_hash(
        FD_INVENTORY_DOMAIN,
        _canonical_json({"fds": pre}),
    )
    assert receipt.fd_inventory_post_sha256 == _domain_hash(
        FD_INVENTORY_DOMAIN,
        _canonical_json({"fds": post}),
    )


def test_execution_result_and_descendants_are_bound(
    accepted_witness,
) -> None:
    evidence_root, witness, receipt = accepted_witness
    document = witness.document()
    result = document["execution_result"]

    assert result["returncode"] == 0
    assert (
        result["stdout_sha256"]
        == hashlib.sha256(
            (evidence_root / "command.stdout.log").read_bytes()
        ).hexdigest()
    )
    assert (
        result["stderr_sha256"]
        == hashlib.sha256(
            (evidence_root / "command.stderr.log").read_bytes()
        ).hexdigest()
    )
    assert document["execution_result_sha256"] == (
        receipt.execution_result_sha256
    )
    assert all(
        row["network_namespace"]
        == document["worker"]["network_namespace"]
        for row in document["descendant_namespace_inventory"]
    )
    assert document["external_actions"] == 0
    assert document["real_applications_submitted"] == 0


def test_canonical_witness_and_receipt_reconstruct_exactly(
    accepted_witness,
) -> None:
    evidence_root, witness, receipt = accepted_witness
    witness_path = evidence_root / "network-witness.json"
    receipt_path = evidence_root / "network-witness-receipt.json"

    assert witness_path.read_bytes() == witness.canonical_document
    reconstructed_witness = LinuxNetworkNamespaceWitness(
        witness_path.read_bytes()
    )
    reconstructed_receipt = NetworkNamespaceWitnessReceipt.from_document(
        json.loads(receipt_path.read_bytes())
    )
    assert reconstructed_witness.witness_sha256 == witness.witness_sha256
    assert reconstructed_receipt == receipt
    assert reconstructed_receipt.witness_sha256 == witness.witness_sha256
    assert stat.S_IMODE(witness_path.stat().st_mode) == 0o444
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o444


def test_evidence_inventory_reconstructs_from_locked_inputs(
    accepted_witness,
) -> None:
    evidence_root, witness, _ = accepted_witness
    inventory = witness.document()["evidence_inventory"]

    assert {row["name"] for row in inventory["files"]} == {
        "worker-config.json",
        "namespace-supervisor.stdout.log",
        "namespace-supervisor.stderr.log",
        "command.stdout.log",
        "command.stderr.log",
    }
    for row in inventory["files"]:
        path = evidence_root / row["name"]
        assert row["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert row["size"] == path.stat().st_size
        assert row["mode"] == f"{stat.S_IMODE(path.stat().st_mode):04o}"


def test_current_cohort_and_browser_integration_are_not_in_surface() -> None:
    import career_automation.linux_network_namespace_witness as module

    public = {
        name
        for name in dir(module)
        if not name.startswith("_")
    }
    assert "open_elapsed_cohort" not in public
    assert "close_elapsed_cohort" not in public
    assert "LocalBrowserExecutor" not in public
    assert "sync_playwright" not in public
    assert "NetworkWitnessedFixtureObservationReceipt" not in public


def test_v1_witness_and_receipt_remain_reconstructable(
    accepted_witness,
) -> None:
    _, witness, receipt = accepted_witness
    document = witness.document()
    document["schema_version"] = SCHEMA_VERSION_V1
    document["cooperative_browser_controls"] = {
        "integration_status": "not_integrated_standalone_harness",
        "playwright_launch_flags": "not_applicable",
        "existing_loopback_controls_required_for_future_integration": True,
    }
    v1_witness = LinuxNetworkNamespaceWitness.from_document(document)
    assert v1_witness.witness_sha256 == _domain_hash(
        WITNESS_DOMAIN_V1,
        v1_witness.canonical_document,
    )

    receipt_document = receipt.core_document()
    receipt_document["schema_version"] = RECEIPT_SCHEMA_VERSION_V1
    from career_automation.linux_network_namespace_witness import (
        RECEIPT_DOMAIN_V1,
    )

    receipt_document["receipt_sha256"] = _domain_hash(
        RECEIPT_DOMAIN_V1,
        _canonical_json(receipt_document),
    )
    v1_receipt = NetworkNamespaceWitnessReceipt.from_document(
        receipt_document
    )
    assert v1_receipt.schema_version == RECEIPT_SCHEMA_VERSION_V1


def test_v2_direct_cooperative_result_binding(tmp_path: Path) -> None:
    execution_root = tmp_path / "execution"
    execution_root.mkdir(mode=0o700)
    worker_output = execution_root / "worker-output"
    worker_output.mkdir(mode=0o700)
    integration_tmp = execution_root / "integration-tmp"
    integration_tmp.mkdir(mode=0o700)
    request_path = execution_root / "integration-request.json"
    chromium = next(
        Path("/home/gutua/.cache/ms-playwright").glob(
            "chromium-*/chrome-linux64/chrome"
        )
    ).resolve(strict=True)
    source = _source_identity(ROOT)
    nonce = b"i" * 32
    request = _request_document(
        source=source,
        execution_root=execution_root,
        python_executable=Path(sys.executable).resolve(strict=True),
        chromium_executable=chromium,
        integration_nonce=nonce,
    )
    request_payload = _canonical_json(request)
    request_path.write_bytes(request_payload)
    request_path.chmod(0o444)
    request_sha256 = _domain_hash(REQUEST_DOMAIN, request_payload)
    nonce_sha256 = str(request["integration_nonce_sha256"])
    policy_sha256 = str(request["cooperative_policy_sha256"])
    artifact = b"synthetic direct-binding control"
    artifact_inventory = [
        {
            "relative_path": "binding-control.txt",
            "mode": "0444",
            "size": len(artifact),
            "sha256": hashlib.sha256(artifact).hexdigest(),
        }
    ]
    artifact_inventory_sha256 = _domain_hash(
        WORKER_INVENTORY_DOMAIN,
        _canonical_json({"files": artifact_inventory}),
    )
    observation = _observation(
        "direct-binding",
        datetime(2030, 1, 2, tzinfo=timezone.utc),
    ).document()
    proof = observation["submission_proof"]
    fixture = observation["fixture_receipt"]
    argv = [str(chromium), "--disable-background-networking"]
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "request_sha256": request_sha256,
        "integration_nonce_sha256": nonce_sha256,
        "source": source.document(),
        "cooperative_policy_sha256": policy_sha256,
        "environment": request["environment"],
        "environment_sha256": request["environment_sha256"],
        "shared_memory": {},
        "chromium_effective_argv": argv,
        "chromium_effective_argv_sha256": _domain_hash(
            EFFECTIVE_ARGV_DOMAIN,
            _canonical_json({"argv": argv}),
        ),
        "runtime_identities": request["runtime_identities"],
        "fixture_receipt": fixture,
        "submission_proof": proof,
        "observation": observation,
        "artifact_inventory": artifact_inventory,
        "worker_artifact_inventory_sha256": artifact_inventory_sha256,
        "evidence_kind": "synthetic_shadow",
        "execution_claim": "structural_lineage_only",
        "external_actions": 0,
        "real_applications_submitted": 0,
    }
    result_payload = _canonical_json(result)
    result_path = worker_output / "worker-result.json"
    code = (
        "import os;"
        f"a={str(worker_output / 'binding-control.txt')!r};"
        f"d={artifact!r};"
        "g=os.open(a,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);"
        "os.write(g,d);os.fsync(g);os.close(g);os.chmod(a,0o444);"
        f"p={str(result_path)!r};"
        f"b={result_payload!r};"
        "f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);"
        "os.write(f,b);os.fsync(f);os.close(f);os.chmod(p,0o444)"
    )
    expectation = CooperativeBrowserExpectation(
        execution_root,
        request_path,
        request_sha256,
        result_path,
        nonce_sha256,
        policy_sha256,
        source,
    )
    witness, receipt = run_isolated_network_witness(
        (sys.executable, "-c", code),
        repository_root=ROOT,
        evidence_directory=execution_root / "network-evidence",
        cooperative_browser_expectation=expectation,
    )
    controls = witness.document()["cooperative_browser_controls"]
    assert controls["worker_result_sha256"] == hashlib.sha256(
        result_payload
    ).hexdigest()
    assert controls["worker_artifact_inventory_sha256"] == (
        artifact_inventory_sha256
    )
    assert receipt.worker_result_sha256 == controls["worker_result_sha256"]
    assert receipt.cooperative_browser_controls_sha256 == _domain_hash(
        COOPERATIVE_BROWSER_CONTROLS_DOMAIN,
        _canonical_json(controls),
    )
    assert os.environ.get("TMPDIR") != str(integration_tmp)
