"""Negative controls for the standalone Linux network witness."""

from __future__ import annotations

import copy
import hashlib
import os
import socket
import stat
import sys
from pathlib import Path

import pytest

import career_automation.linux_network_namespace_witness as witness_module
from career_automation.linux_network_namespace_witness import (
    CooperativeBrowserExpectation,
    LinuxNetworkNamespaceWitness,
    NetworkNamespaceWitnessReceipt,
    NetworkWitnessError,
    _source_identity,
    _parse_ipv6_routes,
    _validate_fd_inventory,
    run_isolated_network_witness,
)

ROOT = Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def accepted(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("network-negative-base") / "evidence"
    witness, receipt = run_isolated_network_witness(
        (sys.executable, "-c", "print('negative-control-base')"),
        repository_root=ROOT,
        evidence_directory=root,
    )
    return root, witness, receipt


def _mutated_document(accepted, mutation):
    document = copy.deepcopy(accepted[1].document())
    mutation(document)
    return document


@pytest.mark.parametrize(
    "mutation",
    (
        lambda document: document.__setitem__("unexpected", True),
        lambda document: document.__setitem__(
            "schema_version",
            "jaa10.linux-network-namespace-witness.v3",
        ),
        lambda document: document.__setitem__("external_actions", 1),
        lambda document: document.__setitem__(
            "real_applications_submitted",
            1,
        ),
        lambda document: document.__setitem__(
            "inherited_ip_socket_count",
            1,
        ),
        lambda document: document.__setitem__(
            "inherited_socket_count",
            1,
        ),
        lambda document: document.__setitem__(
            "post_execution_socket_count",
            1,
        ),
        lambda document: document["claim"].__setitem__(
            "network_syscall_attempts",
            "none",
        ),
        lambda document: document["limitations"].pop(),
        lambda document: document["pre_state"]["capabilities"].__setitem__(
            "CapEff",
            "0000000000001000",
        ),
        lambda document: document["pre_state"].__setitem__(
            "no_new_privs",
            "0",
        ),
        lambda document: document["pre_state"].__setitem__(
            "interfaces",
            ["lo", "eth0"],
        ),
        lambda document: document["pre_state"]["ipv4_routes"].append(
            {
                "interface": "eth0",
                "destination_hex": "00000000",
                "gateway_hex": "0100007f",
                "flags_hex": "0003",
                "mask_hex": "00000000",
            }
        ),
        lambda document: document["pre_state"][
            "ipv4_fib_addresses"
        ].append("192.0.2.1"),
        lambda document: document["pre_state"].__setitem__(
            "ipv6_addresses",
            [],
        ),
        lambda document: document["post_state"].__setitem__(
            "network_namespace",
            "net:[999999999]",
        ),
        lambda document: document["post_state"].__setitem__(
            "process_start_ticks",
            int(document["pre_state"]["process_start_ticks"]) + 1,
        ),
        lambda document: document["fd_inventory_post"][0].__setitem__(
            "target",
            "/dev/zero",
        ),
        lambda document: document["descriptor_policy"].__setitem__(
            "close_fds",
            False,
        ),
        lambda document: document["raw_socket_table_sha256"].__setitem__(
            "pre",
            {},
        ),
        lambda document: document["execution_result"].__setitem__(
            "returncode",
            1,
        ),
        lambda document: document[
            "descendant_namespace_inventory"
        ].append(
            {
                "pid": 999,
                "process_start_ticks": 1,
                "network_namespace": "net:[999999999]",
            }
        ),
        lambda document: document["worker"].__setitem__(
            "process_start_ticks",
            1,
        ),
        lambda document: document["supervisor"].__setitem__(
            "network_namespace",
            document["worker"]["network_namespace"],
        ),
        lambda document: document["evidence_inventory"].__setitem__(
            "inventory_sha256",
            "0" * 64,
        ),
    ),
    ids=(
        "extra-field",
        "schema-drift",
        "external-action",
        "real-application",
        "inherited-ip-socket-count",
        "inherited-socket-count",
        "post-socket-count",
        "stronger-attempt-claim",
        "missing-limitation",
        "effective-capability",
        "no-new-privs-off",
        "extra-interface",
        "ipv4-forwarding-route",
        "non-loopback-ipv4",
        "missing-ipv6-loopback",
        "namespace-change",
        "process-start-change",
        "fd-inventory-change",
        "descriptor-closure-off",
        "socket-table-binding",
        "command-failure",
        "descendant-namespace-escape",
        "process-identity-change",
        "supervisor-namespace",
        "evidence-inventory-hash",
    ),
)
def test_canonical_witness_mutations_fail_closed(
    accepted,
    mutation,
) -> None:
    with pytest.raises(NetworkWitnessError):
        LinuxNetworkNamespaceWitness.from_document(
            _mutated_document(accepted, mutation)
        )


def test_raw_ipv6_flag_mutation_fails_closed(accepted) -> None:
    document = copy.deepcopy(accepted[1].document())
    row = document["pre_state"]["ipv6_routes"][0]
    fields = row["raw"].split()
    fields[8] = "00000002"
    row["raw"] = " ".join(fields)
    raw = "".join(
        f"{item['raw']}\n"
        for item in document["pre_state"]["ipv6_routes"]
    ).encode("ascii")
    document["pre_state"]["raw_proc_net_sha256"]["ipv6_route"] = (
        hashlib.sha256(raw).hexdigest()
    )

    with pytest.raises(NetworkWitnessError, match="IPv6 route"):
        LinuxNetworkNamespaceWitness.from_document(document)


@pytest.mark.parametrize(
    "payload",
    (
        b"malformed\n",
        (
            b"20010db8000000000000000000000000 20 "
            b"00000000000000000000000000000000 00 "
            b"00000000000000000000000000000000 "
            b"00000000 00000001 00000000 00000001 eth0\n"
        ),
        (
            b"00000000000000000000000000000000 00 "
            b"00000000000000000000000000000000 00 "
            b"00000000000000000000000000000000 "
            b"ffffffff 00000001 00000000 00000002 lo\n"
        ),
    ),
    ids=("malformed", "off-loopback", "unknown-flags"),
)
def test_raw_ipv6_parser_rejects_unsafe_rows(payload: bytes) -> None:
    with pytest.raises(NetworkWitnessError):
        _parse_ipv6_routes(payload)


@pytest.mark.parametrize(
    "family",
    (
        socket.AF_INET,
        socket.AF_INET6,
        socket.AF_UNIX,
    ),
    ids=("connected-af-inet", "unbound-af-inet6", "unix-scm-rights"),
)
def test_outer_fd_inventory_rejects_an_inherited_socket(
    accepted,
    family: socket.AddressFamily,
) -> None:
    document = accepted[1].document()
    policy = document["descriptor_policy"]
    rows = copy.deepcopy(document["fd_inventory_pre"])
    opened: list[socket.socket] = []
    try:
        if family == socket.AF_UNIX:
            inherited, peer = socket.socketpair()
            opened.extend((inherited, peer))
        else:
            inherited = socket.socket(family, socket.SOCK_STREAM)
            opened.append(inherited)
        if family == socket.AF_INET:
            inherited.bind(("127.0.0.1", 0))
            inherited.listen(1)
        rows.append(
            {
                "fd": 99,
                "target": f"socket:[{os.fstat(inherited.fileno()).st_ino}]",
                "inode": os.fstat(inherited.fileno()).st_ino,
                "mode": stat.S_IFSOCK,
                "flags": 0,
            }
        )
        with pytest.raises(NetworkWitnessError, match="not allowlisted"):
            _validate_fd_inventory(
                rows,
                control_fd=policy["pass_fds"][0],
                evidence_fd=policy["pass_fds"][1],
                control_inode=document["designated_pipe_inodes"][0],
                evidence_inode=document["designated_pipe_inodes"][1],
                stdout_path=Path(policy["stdout"]),
                stderr_path=Path(policy["stderr"]),
            )
    finally:
        for descriptor in opened:
            descriptor.close()


def test_live_worker_inventory_has_no_hidden_socket(accepted) -> None:
    document = accepted[1].document()
    rows = document["fd_inventory_pre"]

    assert all(not row["target"].startswith("socket:[") for row in rows)
    assert len(rows) == 5


@pytest.mark.parametrize(
    "command",
    (
        (),
        "not-an-argv",
        ("relative-command",),
        ("/path/that/does/not/exist",),
        (sys.executable, ""),
    ),
    ids=(
        "empty",
        "string",
        "relative",
        "missing",
        "empty-argument",
    ),
)
def test_invalid_command_surface_fails_before_namespace(
    tmp_path: Path,
    command,
) -> None:
    with pytest.raises(NetworkWitnessError):
        run_isolated_network_witness(
            command,
            repository_root=ROOT,
            evidence_directory=tmp_path / "evidence",
        )
    assert not (tmp_path / "evidence" / "network-witness.json").exists()


def test_existing_evidence_directory_fails_closed(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    with pytest.raises(
        NetworkWitnessError,
        match="newly creatable",
    ):
        run_isolated_network_witness(
            (sys.executable, "-c", "pass"),
            repository_root=ROOT,
            evidence_directory=evidence,
        )


def test_nonzero_command_creates_no_witness(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"

    with pytest.raises(
        NetworkWitnessError,
        match="exited unsuccessfully",
    ):
        run_isolated_network_witness(
            (sys.executable, "-c", "raise SystemExit(7)"),
            repository_root=ROOT,
            evidence_directory=evidence,
        )
    assert not (evidence / "network-witness.json").exists()
    assert not (evidence / "network-witness-receipt.json").exists()


def test_reserved_non_loopback_connect_is_kernel_blocked(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    code = (
        "import socket; "
        "s=socket.socket(); s.settimeout(0.2); "
        "blocked=False\n"
        "try:\n"
        " s.connect(('192.0.2.1', 9))\n"
        "except OSError:\n"
        " blocked=True\n"
        "finally:\n"
        " s.close()\n"
        "assert blocked\n"
    )

    witness, _ = run_isolated_network_witness(
        (sys.executable, "-c", code),
        repository_root=ROOT,
        evidence_directory=evidence,
    )

    assert witness.document()["claim"][
        "external_ip_network_capability"
    ] == "absent_under_linux_network_namespace"


def test_surviving_descendant_fails_and_creates_no_witness(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    code = (
        "import os,time; "
        "pid=os.fork(); "
        "(time.sleep(10) if pid == 0 else None)"
    )

    with pytest.raises(NetworkWitnessError, match="surviving descendant"):
        run_isolated_network_witness(
            (sys.executable, "-c", code),
            repository_root=ROOT,
            evidence_directory=evidence,
        )
    assert not (evidence / "network-witness.json").exists()


def test_tool_byte_drift_fails_before_namespace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    replacement = copy.deepcopy(witness_module.PINNED_TOOLS)
    replacement[str(witness_module.UNSHARE)]["sha256"] = "0" * 64
    monkeypatch.setattr(witness_module, "PINNED_TOOLS", replacement)

    with pytest.raises(NetworkWitnessError, match="tool bytes differ"):
        run_isolated_network_witness(
            (sys.executable, "-c", "pass"),
            repository_root=ROOT,
            evidence_directory=tmp_path / "evidence",
        )


def test_receipt_mutation_fails_closed(accepted) -> None:
    document = accepted[2].document()
    document["fd_inventory_pre_sha256"] = "0" * 64

    with pytest.raises(NetworkWitnessError, match="receipt hash"):
        NetworkNamespaceWitnessReceipt.from_document(document)


def test_integrated_request_rejects_legacy_raw_hash_binding(
    tmp_path: Path,
) -> None:
    execution_root = tmp_path / "execution"
    execution_root.mkdir(mode=0o700)
    output_root = execution_root / "worker-output"
    output_root.mkdir(mode=0o700)
    (execution_root / "integration-tmp").mkdir(mode=0o700)
    request = execution_root / "integration-request.json"
    request.write_bytes(b"{}")
    request.chmod(0o444)
    result = output_root / "worker-result.json"
    expectation = CooperativeBrowserExpectation(
        execution_root,
        request,
        hashlib.sha256(b"{}").hexdigest(),
        result,
        hashlib.sha256(b"nonce").hexdigest(),
        hashlib.sha256(b"policy").hexdigest(),
        _source_identity(ROOT),
    )

    with pytest.raises(NetworkWitnessError, match="request identity"):
        run_isolated_network_witness(
            (sys.executable, "-c", "pass"),
            repository_root=ROOT,
            evidence_directory=execution_root / "network-evidence",
            cooperative_browser_expectation=expectation,
        )
