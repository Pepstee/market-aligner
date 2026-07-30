"""Positive controls for the standalone Linux network witness."""

from __future__ import annotations

import hashlib
import json
import stat
import sys
from pathlib import Path

import pytest

from career_automation.linux_network_namespace_witness import (
    CAPABILITY_FIELDS,
    COMMAND_ENVIRONMENT,
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
    run_isolated_network_witness,
)

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
