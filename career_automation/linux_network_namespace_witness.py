"""Fail-closed Linux network-namespace capability witness.

This standalone harness is deliberately separate from browser execution and
from the active JAA-10 elapsed cohort.  It supervises one explicit command in
an ephemeral, loopback-only network namespace and returns evidence only when
the complete kernel-state predicate succeeds.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import select
import stat
import subprocess
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from tracked_source_revision import source_content_revision

SCHEMA_VERSION_V1 = "jaa10.linux-network-namespace-witness.v1"
RECEIPT_SCHEMA_VERSION_V1 = (
    "jaa10.linux-network-namespace-witness-receipt.v1"
)
SCHEMA_VERSION = "jaa10.linux-network-namespace-witness.v2"
RECEIPT_SCHEMA_VERSION = (
    "jaa10.linux-network-namespace-witness-receipt.v2"
)
WITNESS_DOMAIN_V1 = b"jaa10-linux-network-namespace-witness-v1\0"
RECEIPT_DOMAIN_V1 = b"jaa10-linux-network-namespace-receipt-v1\0"
WITNESS_DOMAIN = b"jaa10-linux-network-namespace-witness-v2\0"
RECEIPT_DOMAIN = b"jaa10-linux-network-namespace-receipt-v2\0"
EXECUTION_RESULT_DOMAIN = b"jaa10-linux-network-execution-result-v1\0"
DESCRIPTOR_POLICY_DOMAIN = b"jaa10-linux-network-descriptor-policy-v1\0"
INVENTORY_DOMAIN = b"jaa10-linux-network-evidence-inventory-v1\0"
FD_INVENTORY_DOMAIN = b"jaa10-linux-network-fd-inventory-v1\0"
COOPERATIVE_BROWSER_CONTROLS_DOMAIN = (
    b"jaa10-cooperative-browser-controls-v2\0"
)

UNSHARE = Path("/usr/bin/unshare")
IP = Path("/usr/sbin/ip")
SETPRIV = Path("/usr/bin/setpriv")

PINNED_TOOLS = {
    str(UNSHARE): {
        "version": "unshare from util-linux 2.41.3",
        "sha256": (
            "978a4aec5a404ad0a05faac981df501d4"
            "b7eb0c5a3ad9c1a7b929a0bfd84f6c8"
        ),
        "version_argv": ("--version",),
    },
    str(IP): {
        "version": "ip utility, iproute2-6.19.0, libbpf 1.6.3",
        "sha256": (
            "19d7990bf9e818121a7423179611ac59b"
            "e9d37b3f21b3cb9249c048072a06a08"
        ),
        "version_argv": ("-Version",),
    },
    str(SETPRIV): {
        "version": "setpriv from util-linux 2.41.3",
        "sha256": (
            "9e0d70d26a02c1cb4b984ab6f49a582"
            "b7a2c3508b1063ac23adc60073292ae7e"
        ),
        "version_argv": ("--version",),
    },
}

CAPABILITY_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
SOCKET_TABLES = (
    "tcp",
    "tcp6",
    "udp",
    "udp6",
    "raw",
    "raw6",
    "unix",
    "packet",
    "netlink",
)
ALLOWED_FIB_ADDRESSES = {
    "127.0.0.0",
    "127.0.0.1",
    "127.255.255.255",
}
LOOPBACK_IPV6_HEX = "00000000000000000000000000000001"
UNSPECIFIED_IPV6_HEX = "00000000000000000000000000000000"
UNREACHABLE_DEFAULT_FLAGS = 0x00200200
LOCAL_HOST_FLAGS = 0x80200001
COMMAND_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
}


class NetworkWitnessError(RuntimeError):
    """The namespace witness could not satisfy its exact predicate."""


def _canonical_json(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _domain_hash(domain: bytes, payload: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise NetworkWitnessError(f"{name} must be an object")
    return value


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """Exact tracked source identity bound into a witness."""

    git_revision: str
    tree: str
    content_revision: str

    def document(self) -> dict[str, str]:
        return {
            "git_revision": self.git_revision,
            "tree": self.tree,
            "content_revision": self.content_revision,
        }


@dataclass(frozen=True, slots=True)
class CooperativeBrowserExpectation:
    """Exact application result that an integrated v2 witness must bind."""

    execution_root: Path
    request_path: Path
    request_sha256: str
    result_path: Path
    integration_nonce_sha256: str
    cooperative_policy_sha256: str
    expected_source: SourceIdentity
    schema_version: str = "jaa10.cooperative-browser-expectation.v1"
    result_schema_version: str = (
        "jaa10.network-witnessed-fixture-worker-result.v1"
    )

    def __post_init__(self) -> None:
        if self.schema_version != "jaa10.cooperative-browser-expectation.v1":
            raise NetworkWitnessError(
                "cooperative expectation schema is invalid"
            )
        if self.result_schema_version != (
            "jaa10.network-witnessed-fixture-worker-result.v1"
        ):
            raise NetworkWitnessError(
                "cooperative result schema is invalid"
            )
        for value, name in (
            (self.request_sha256, "request hash"),
            (self.integration_nonce_sha256, "integration nonce hash"),
            (self.cooperative_policy_sha256, "cooperative policy hash"),
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise NetworkWitnessError(f"{name} is invalid")
        for value, name in (
            (self.execution_root, "execution root"),
            (self.request_path, "request path"),
            (self.result_path, "result path"),
        ):
            if not isinstance(value, Path) or not value.is_absolute():
                raise NetworkWitnessError(f"{name} must be an absolute Path")


@dataclass(frozen=True, slots=True)
class LinuxNetworkNamespaceWitness:
    """Immutable canonical witness bytes with exhaustive validation."""

    canonical_document: bytes

    def __post_init__(self) -> None:
        document = self.document()
        _validate_witness_document(document)
        if _canonical_json(document) != self.canonical_document:
            raise NetworkWitnessError("witness document is not canonical JSON")

    def document(self) -> dict[str, Any]:
        try:
            value = json.loads(self.canonical_document)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NetworkWitnessError("witness JSON is invalid") from error
        return dict(_mapping(value, "witness"))

    @property
    def witness_sha256(self) -> str:
        schema = self.document().get("schema_version")
        domain = (
            WITNESS_DOMAIN_V1
            if schema == SCHEMA_VERSION_V1
            else WITNESS_DOMAIN
        )
        return _domain_hash(domain, self.canonical_document)

    @classmethod
    def from_document(
        cls,
        document: Mapping[str, Any],
    ) -> LinuxNetworkNamespaceWitness:
        return cls(_canonical_json(document))


@dataclass(frozen=True, slots=True)
class NetworkNamespaceWitnessReceipt:
    """Content-addressed receipt binding a witness and execution result."""

    schema_version: str
    witness_sha256: str
    execution_result_sha256: str
    source: SourceIdentity
    supervisor_nonce_sha256: str
    descriptor_policy_sha256: str
    fd_inventory_pre_sha256: str
    fd_inventory_post_sha256: str
    designated_pipe_inodes: tuple[int, int]
    evidence_inventory_sha256: str
    receipt_sha256: str
    cooperative_browser_controls_sha256: str | None = None
    worker_result_sha256: str | None = None
    request_sha256: str | None = None
    integration_nonce_sha256: str | None = None

    def core_document(self) -> dict[str, Any]:
        document = {
            "schema_version": self.schema_version,
            "witness_sha256": self.witness_sha256,
            "execution_result_sha256": self.execution_result_sha256,
            "source": self.source.document(),
            "supervisor_nonce_sha256": self.supervisor_nonce_sha256,
            "descriptor_policy_sha256": self.descriptor_policy_sha256,
            "fd_inventory_pre_sha256": self.fd_inventory_pre_sha256,
            "fd_inventory_post_sha256": self.fd_inventory_post_sha256,
            "designated_pipe_inodes": list(self.designated_pipe_inodes),
            "evidence_inventory_sha256": self.evidence_inventory_sha256,
        }
        if self.schema_version == RECEIPT_SCHEMA_VERSION:
            integrated = self.worker_result_sha256 is not None
            if integrated:
                document.update(
                    {
                        "cooperative_browser_controls_sha256": (
                            self.cooperative_browser_controls_sha256
                        ),
                        "worker_result_sha256": self.worker_result_sha256,
                        "request_sha256": self.request_sha256,
                        "integration_nonce_sha256": (
                            self.integration_nonce_sha256
                        ),
                    }
                )
        return document

    def document(self) -> dict[str, Any]:
        document = self.core_document()
        document["receipt_sha256"] = self.receipt_sha256
        return document

    def __post_init__(self) -> None:
        if self.schema_version not in {
            RECEIPT_SCHEMA_VERSION_V1,
            RECEIPT_SCHEMA_VERSION,
        }:
            raise NetworkWitnessError("receipt schema version is invalid")
        integrated_values = (
            self.cooperative_browser_controls_sha256,
            self.worker_result_sha256,
            self.request_sha256,
            self.integration_nonce_sha256,
        )
        if self.schema_version == RECEIPT_SCHEMA_VERSION_V1 and any(
            value is not None for value in integrated_values
        ):
            raise NetworkWitnessError("v1 receipt contains v2 fields")
        if self.schema_version == RECEIPT_SCHEMA_VERSION and (
            any(value is None for value in integrated_values)
            and any(value is not None for value in integrated_values)
        ):
            raise NetworkWitnessError(
                "integrated receipt fields are incomplete"
            )
        domain = (
            RECEIPT_DOMAIN_V1
            if self.schema_version == RECEIPT_SCHEMA_VERSION_V1
            else RECEIPT_DOMAIN
        )
        expected = _domain_hash(
            domain,
            _canonical_json(self.core_document()),
        )
        if self.receipt_sha256 != expected:
            raise NetworkWitnessError("receipt hash is invalid")

    @classmethod
    def issue(
        cls,
        *,
        witness_sha256: str,
        execution_result_sha256: str,
        source: SourceIdentity,
        supervisor_nonce_sha256: str,
        descriptor_policy_sha256: str,
        fd_inventory_pre_sha256: str,
        fd_inventory_post_sha256: str,
        designated_pipe_inodes: tuple[int, int],
        evidence_inventory_sha256: str,
        cooperative_browser_controls_sha256: str | None = None,
        worker_result_sha256: str | None = None,
        request_sha256: str | None = None,
        integration_nonce_sha256: str | None = None,
    ) -> NetworkNamespaceWitnessReceipt:
        provisional = cls.__new__(cls)
        object.__setattr__(
            provisional,
            "schema_version",
            RECEIPT_SCHEMA_VERSION,
        )
        object.__setattr__(
            provisional,
            "witness_sha256",
            witness_sha256,
        )
        object.__setattr__(
            provisional,
            "execution_result_sha256",
            execution_result_sha256,
        )
        object.__setattr__(provisional, "source", source)
        object.__setattr__(
            provisional,
            "supervisor_nonce_sha256",
            supervisor_nonce_sha256,
        )
        object.__setattr__(
            provisional,
            "descriptor_policy_sha256",
            descriptor_policy_sha256,
        )
        object.__setattr__(
            provisional,
            "fd_inventory_pre_sha256",
            fd_inventory_pre_sha256,
        )
        object.__setattr__(
            provisional,
            "fd_inventory_post_sha256",
            fd_inventory_post_sha256,
        )
        object.__setattr__(
            provisional,
            "designated_pipe_inodes",
            designated_pipe_inodes,
        )
        object.__setattr__(
            provisional,
            "evidence_inventory_sha256",
            evidence_inventory_sha256,
        )
        for name, value in (
            (
                "cooperative_browser_controls_sha256",
                cooperative_browser_controls_sha256,
            ),
            ("worker_result_sha256", worker_result_sha256),
            ("request_sha256", request_sha256),
            ("integration_nonce_sha256", integration_nonce_sha256),
        ):
            object.__setattr__(provisional, name, value)
        receipt_sha256 = _domain_hash(
            RECEIPT_DOMAIN,
            _canonical_json(provisional.core_document()),
        )
        return cls(
            RECEIPT_SCHEMA_VERSION,
            witness_sha256,
            execution_result_sha256,
            source,
            supervisor_nonce_sha256,
            descriptor_policy_sha256,
            fd_inventory_pre_sha256,
            fd_inventory_post_sha256,
            designated_pipe_inodes,
            evidence_inventory_sha256,
            receipt_sha256,
            cooperative_browser_controls_sha256,
            worker_result_sha256,
            request_sha256,
            integration_nonce_sha256,
        )

    @classmethod
    def from_document(
        cls,
        document: Mapping[str, Any],
    ) -> NetworkNamespaceWitnessReceipt:
        source = _mapping(document.get("source"), "receipt source")
        pipes = document.get("designated_pipe_inodes")
        if not isinstance(pipes, list) or len(pipes) != 2:
            raise NetworkWitnessError("receipt pipe identities are invalid")
        schema_version = str(document.get("schema_version"))
        integrated_keys = {
            "cooperative_browser_controls_sha256",
            "worker_result_sha256",
            "request_sha256",
            "integration_nonce_sha256",
        }
        expected_keys = {
            "schema_version",
            "witness_sha256",
            "execution_result_sha256",
            "source",
            "supervisor_nonce_sha256",
            "descriptor_policy_sha256",
            "fd_inventory_pre_sha256",
            "fd_inventory_post_sha256",
            "designated_pipe_inodes",
            "evidence_inventory_sha256",
            "receipt_sha256",
        }
        if schema_version == RECEIPT_SCHEMA_VERSION and integrated_keys & set(
            document
        ):
            expected_keys |= integrated_keys
        if set(document) != expected_keys:
            raise NetworkWitnessError("receipt field set is invalid")
        return cls(
            schema_version,
            str(document.get("witness_sha256")),
            str(document.get("execution_result_sha256")),
            SourceIdentity(
                str(source.get("git_revision")),
                str(source.get("tree")),
                str(source.get("content_revision")),
            ),
            str(document.get("supervisor_nonce_sha256")),
            str(document.get("descriptor_policy_sha256")),
            str(document.get("fd_inventory_pre_sha256")),
            str(document.get("fd_inventory_post_sha256")),
            (int(pipes[0]), int(pipes[1])),
            str(document.get("evidence_inventory_sha256")),
            str(document.get("receipt_sha256")),
            (
                str(document.get("cooperative_browser_controls_sha256"))
                if "cooperative_browser_controls_sha256" in document
                else None
            ),
            (
                str(document.get("worker_result_sha256"))
                if "worker_result_sha256" in document
                else None
            ),
            (
                str(document.get("request_sha256"))
                if "request_sha256" in document
                else None
            ),
            (
                str(document.get("integration_nonce_sha256"))
                if "integration_nonce_sha256" in document
                else None
            ),
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_status(pid: int | str) -> dict[str, str]:
    path = Path(f"/proc/{pid}/status")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise NetworkWitnessError(f"cannot read {path}") from error
    status: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition(":")
        if separator:
            status[key] = value.strip()
    return status


def _process_start_ticks(pid: int | str) -> int:
    path = Path(f"/proc/{pid}/stat")
    try:
        payload = path.read_text(encoding="utf-8")
    except OSError as error:
        raise NetworkWitnessError(f"cannot read {path}") from error
    closing = payload.rfind(")")
    fields = payload[closing + 2 :].split()
    if closing < 0 or len(fields) < 20:
        raise NetworkWitnessError("process stat is malformed")
    return int(fields[19])


def _namespace_identity(pid: int | str, namespace: str) -> str:
    path = Path(f"/proc/{pid}/ns/{namespace}")
    try:
        target = os.readlink(path)
    except OSError as error:
        raise NetworkWitnessError(f"cannot resolve {path}") from error
    if not re.fullmatch(r"[a-z]+:\[\d+\]", target):
        raise NetworkWitnessError("namespace identity is malformed")
    return target


def _read_proc_net(pid: int | str, name: str) -> bytes:
    path = Path(f"/proc/{pid}/net/{name}")
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b""
    except OSError as error:
        raise NetworkWitnessError(f"cannot read {path}") from error


def _parse_interfaces(payload: bytes) -> list[str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise NetworkWitnessError("network device table is invalid") from error
    interfaces: list[str] = []
    for line in lines[2:]:
        name, separator, _ = line.partition(":")
        if not separator:
            raise NetworkWitnessError("network device row is malformed")
        interfaces.append(name.strip())
    if len(interfaces) != len(set(interfaces)):
        raise NetworkWitnessError("network device rows are duplicated")
    return interfaces


def _parse_ipv4_routes(payload: bytes) -> list[dict[str, Any]]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise NetworkWitnessError("IPv4 route table is invalid") from error
    if not lines or not lines[0].startswith("Iface"):
        raise NetworkWitnessError("IPv4 route header is missing")
    routes: list[dict[str, Any]] = []
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 11:
            raise NetworkWitnessError("IPv4 route row is malformed")
        routes.append(
            {
                "interface": fields[0],
                "destination_hex": fields[1],
                "gateway_hex": fields[2],
                "flags_hex": fields[3],
                "mask_hex": fields[7],
            }
        )
    return routes


def _parse_ipv6_routes(payload: bytes) -> list[dict[str, Any]]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise NetworkWitnessError("IPv6 route table is invalid") from error
    routes: list[dict[str, Any]] = []
    for line in lines:
        fields = line.split()
        if len(fields) != 10:
            raise NetworkWitnessError("IPv6 route row is malformed")
        (
            destination,
            destination_prefix,
            source,
            source_prefix,
            next_hop,
            metric,
            reference_count,
            use_count,
            flags,
            interface,
        ) = fields
        for encoded, length, label in (
            (destination, 32, "destination"),
            (source, 32, "source"),
            (next_hop, 32, "next hop"),
            (destination_prefix, 2, "destination prefix"),
            (source_prefix, 2, "source prefix"),
            (metric, 8, "metric"),
            (reference_count, 8, "reference count"),
            (use_count, 8, "use count"),
            (flags, 8, "flags"),
        ):
            if len(encoded) != length or not re.fullmatch(
                r"[0-9a-fA-F]+",
                encoded,
            ):
                raise NetworkWitnessError(f"IPv6 route {label} is malformed")
        row = {
            "destination": str(
                ipaddress.IPv6Address(int(destination, 16))
            ),
            "destination_prefix": int(destination_prefix, 16),
            "source": str(ipaddress.IPv6Address(int(source, 16))),
            "source_prefix": int(source_prefix, 16),
            "next_hop": str(ipaddress.IPv6Address(int(next_hop, 16))),
            "metric": int(metric, 16),
            "reference_count": int(reference_count, 16),
            "use_count": int(use_count, 16),
            "flags": int(flags, 16),
            "interface": interface,
            "raw": line,
        }
        if (
            interface == "lo"
            and destination == LOOPBACK_IPV6_HEX
            and int(destination_prefix, 16) == 128
            and source == UNSPECIFIED_IPV6_HEX
            and int(source_prefix, 16) == 0
            and next_hop == UNSPECIFIED_IPV6_HEX
            and int(flags, 16) == LOCAL_HOST_FLAGS
        ):
            row["classification"] = "loopback_local_host"
        elif (
            interface == "lo"
            and destination == UNSPECIFIED_IPV6_HEX
            and int(destination_prefix, 16) == 0
            and source == UNSPECIFIED_IPV6_HEX
            and int(source_prefix, 16) == 0
            and next_hop == UNSPECIFIED_IPV6_HEX
            and int(metric, 16) == 0xFFFFFFFF
            and int(flags, 16) == UNREACHABLE_DEFAULT_FLAGS
        ):
            row["classification"] = (
                "loopback_namespace_unreachable_default"
            )
        else:
            raise NetworkWitnessError(
                "IPv6 route is not an accepted loopback kernel entry"
            )
        routes.append(row)
    classifications = {row["classification"] for row in routes}
    if classifications != {
        "loopback_local_host",
        "loopback_namespace_unreachable_default",
    }:
        raise NetworkWitnessError("IPv6 loopback route set is incomplete")
    return routes


def _parse_if_inet6(payload: bytes) -> list[dict[str, Any]]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise NetworkWitnessError("IPv6 address table is invalid") from error
    addresses: list[dict[str, Any]] = []
    for line in lines:
        fields = line.split()
        if len(fields) != 6:
            raise NetworkWitnessError("IPv6 address row is malformed")
        address, index, prefix, scope, flags, interface = fields
        if not re.fullmatch(r"[0-9a-fA-F]{32}", address):
            raise NetworkWitnessError("IPv6 address is malformed")
        addresses.append(
            {
                "address": str(ipaddress.IPv6Address(int(address, 16))),
                "interface_index": int(index, 16),
                "prefix": int(prefix, 16),
                "scope": int(scope, 16),
                "flags": int(flags, 16),
                "interface": interface,
            }
        )
    return addresses


def _parse_fib_addresses(payload: bytes) -> list[str]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise NetworkWitnessError("IPv4 FIB table is invalid") from error
    addresses = sorted(
        {
            match.group(0)
            for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        }
    )
    for address in addresses:
        try:
            ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError as error:
            raise NetworkWitnessError("IPv4 FIB address is invalid") from error
    return addresses


def _socket_table_hashes(pid: int | str) -> dict[str, str]:
    return {
        name: hashlib.sha256(_read_proc_net(pid, name)).hexdigest()
        for name in SOCKET_TABLES
    }


def _fd_inventory(pid: int) -> list[dict[str, Any]]:
    root = Path(f"/proc/{pid}/fd")
    try:
        descriptor_names = sorted(root.iterdir(), key=lambda path: int(path.name))
    except (OSError, ValueError) as error:
        raise NetworkWitnessError("cannot enumerate worker descriptors") from error
    inventory: list[dict[str, Any]] = []
    for descriptor_path in descriptor_names:
        try:
            descriptor = int(descriptor_path.name)
            target = os.readlink(descriptor_path)
            descriptor_stat = descriptor_path.stat()
            fdinfo = Path(
                f"/proc/{pid}/fdinfo/{descriptor}"
            ).read_text(encoding="ascii")
        except (OSError, ValueError) as error:
            raise NetworkWitnessError(
                "worker descriptor changed during enumeration"
            ) from error
        flags_line = next(
            (line for line in fdinfo.splitlines() if line.startswith("flags:")),
            None,
        )
        if flags_line is None:
            raise NetworkWitnessError("worker descriptor flags are missing")
        inventory.append(
            {
                "fd": descriptor,
                "target": target,
                "inode": descriptor_stat.st_ino,
                "mode": stat.S_IFMT(descriptor_stat.st_mode),
                "flags": int(flags_line.split()[1], 8),
            }
        )
    return inventory


def _pipe_inode(target: str) -> int:
    match = re.fullmatch(r"pipe:\[(\d+)\]", target)
    if match is None:
        raise NetworkWitnessError("designated channel is not an anonymous pipe")
    return int(match.group(1))


def _validate_fd_inventory(
    inventory: Sequence[Mapping[str, Any]],
    *,
    control_fd: int,
    evidence_fd: int,
    control_inode: int,
    evidence_inode: int,
    stdout_path: Path,
    stderr_path: Path,
) -> None:
    by_fd = {int(row["fd"]): row for row in inventory}
    if len(by_fd) != len(inventory):
        raise NetworkWitnessError("descriptor inventory is duplicated")
    if set(by_fd) != {0, 1, 2, control_fd, evidence_fd}:
        raise NetworkWitnessError(
            "descriptor inventory is not allowlisted: "
            f"{[(fd, by_fd[fd]['target']) for fd in sorted(by_fd)]}"
        )
    if by_fd[0]["target"] != "/dev/null":
        raise NetworkWitnessError("worker stdin is not /dev/null")
    for descriptor, expected_path in (
        (1, stdout_path),
        (2, stderr_path),
    ):
        target = str(by_fd[descriptor]["target"])
        if Path(target).resolve(strict=False) != expected_path.resolve(
            strict=False
        ):
            raise NetworkWitnessError("worker output descriptor is unexpected")
    for descriptor, expected_inode in (
        (control_fd, control_inode),
        (evidence_fd, evidence_inode),
    ):
        target = str(by_fd[descriptor]["target"])
        if _pipe_inode(target) != expected_inode:
            raise NetworkWitnessError("designated pipe identity changed")
    if any(str(row["target"]).startswith("socket:[") for row in inventory):
        raise NetworkWitnessError("worker inherited a socket descriptor")


def _capture_process_state(pid: int) -> dict[str, Any]:
    status = _read_status(pid)
    capabilities = {
        field: status.get(field, "")
        for field in CAPABILITY_FIELDS
    }
    raw_proc_net = {
        name: _read_proc_net(pid, name)
        for name in (
            "dev",
            "route",
            "fib_trie",
            "if_inet6",
            "ipv6_route",
        )
    }
    state = {
        "pid": pid,
        "process_start_ticks": _process_start_ticks(pid),
        "network_namespace": _namespace_identity(pid, "net"),
        "user_namespace": _namespace_identity(pid, "user"),
        "capabilities": capabilities,
        "no_new_privs": status.get("NoNewPrivs"),
        "interfaces": _parse_interfaces(raw_proc_net["dev"]),
        "ipv4_routes": _parse_ipv4_routes(raw_proc_net["route"]),
        "ipv4_fib_addresses": _parse_fib_addresses(
            raw_proc_net["fib_trie"]
        ),
        "ipv6_addresses": _parse_if_inet6(
            raw_proc_net["if_inet6"]
        ),
        "ipv6_routes": _parse_ipv6_routes(
            raw_proc_net["ipv6_route"]
        ),
        "raw_proc_net_sha256": {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in raw_proc_net.items()
        },
        "raw_socket_table_sha256": _socket_table_hashes(pid),
    }
    _validate_process_state(state)
    return state


def _validate_process_state(state: Mapping[str, Any]) -> None:
    capabilities = _mapping(state.get("capabilities"), "capabilities")
    if set(capabilities) != set(CAPABILITY_FIELDS):
        raise NetworkWitnessError("capability field set is incomplete")
    if any(str(value) != "0000000000000000" for value in capabilities.values()):
        raise NetworkWitnessError("worker retained a capability")
    if str(state.get("no_new_privs")) != "1":
        raise NetworkWitnessError("worker NoNewPrivs is not enabled")
    if state.get("interfaces") != ["lo"]:
        raise NetworkWitnessError("worker interface inventory is not loopback-only")
    if state.get("ipv4_routes") != []:
        raise NetworkWitnessError("worker has an IPv4 forwarding route")
    if set(state.get("ipv4_fib_addresses", [])) != ALLOWED_FIB_ADDRESSES:
        raise NetworkWitnessError("worker IPv4 addresses are not loopback-only")
    if state.get("ipv6_addresses") != [
        {
            "address": "::1",
            "interface_index": 1,
            "prefix": 128,
            "scope": 16,
            "flags": 128,
            "interface": "lo",
        }
    ]:
        raise NetworkWitnessError("worker IPv6 addresses are not loopback-only")
    routes = state.get("ipv6_routes")
    if not isinstance(routes, list) or not routes:
        raise NetworkWitnessError("worker IPv6 route evidence is missing")
    if any(not isinstance(row, dict) for row in routes):
        raise NetworkWitnessError("worker IPv6 route row is invalid")
    raw_ipv6 = "".join(f"{row['raw']}\n" for row in routes).encode("ascii")
    if _parse_ipv6_routes(raw_ipv6) != routes:
        raise NetworkWitnessError(
            "worker normalized IPv6 route evidence differs from raw rows"
        )
    raw_hashes = _mapping(
        state.get("raw_proc_net_sha256"),
        "raw proc-net hashes",
    )
    if raw_hashes.get("ipv6_route") != hashlib.sha256(raw_ipv6).hexdigest():
        raise NetworkWitnessError("worker raw IPv6 route hash differs")


def _state_fingerprint(state: Mapping[str, Any]) -> str:
    selected = {
        key: state[key]
        for key in (
            "network_namespace",
            "user_namespace",
            "capabilities",
            "no_new_privs",
            "interfaces",
            "ipv4_routes",
            "ipv4_fib_addresses",
            "ipv6_addresses",
            "ipv6_routes",
            "raw_proc_net_sha256",
            "raw_socket_table_sha256",
        )
    }
    return hashlib.sha256(_canonical_json(selected)).hexdigest()


def _is_descendant(pid: int, ancestor: int) -> bool:
    current = pid
    visited: set[int] = set()
    while current > 1 and current not in visited:
        if current == ancestor:
            return True
        visited.add(current)
        path = Path(f"/proc/{current}/stat")
        try:
            payload = path.read_text(encoding="utf-8")
        except OSError:
            return False
        closing = payload.rfind(")")
        fields = payload[closing + 2 :].split()
        if closing < 0 or len(fields) < 2:
            return False
        current = int(fields[1])
    return current == ancestor


def _descendants(pid: int) -> list[int]:
    descendants: list[int] = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        candidate = int(path.name)
        if candidate != pid and _is_descendant(candidate, pid):
            descendants.append(candidate)
    return sorted(descendants)


def _read_git_ref(common: Path, reference: str) -> str:
    loose = common / reference
    if loose.is_file():
        return loose.read_text(encoding="ascii").strip()
    packed = common / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="ascii").splitlines():
            if not line or line.startswith(("#", "^")):
                continue
            revision, name = line.split(" ", 1)
            if name == reference:
                return revision
    raise NetworkWitnessError("Git HEAD reference cannot be resolved")


def _source_identity(repository_root: Path) -> SourceIdentity:
    root = repository_root.resolve(strict=True)
    dot_git = root / ".git"
    if dot_git.is_file():
        line = dot_git.read_text(encoding="utf-8").strip()
        prefix = "gitdir: "
        if not line.startswith(prefix):
            raise NetworkWitnessError("worktree Git file is malformed")
        git_dir = Path(line[len(prefix) :]).resolve(strict=True)
    elif dot_git.is_dir():
        git_dir = dot_git
    else:
        raise NetworkWitnessError("repository Git metadata is missing")
    common_file = git_dir / "commondir"
    common = (
        (git_dir / common_file.read_text(encoding="ascii").strip()).resolve()
        if common_file.is_file()
        else git_dir
    )
    head_text = (git_dir / "HEAD").read_text(encoding="ascii").strip()
    if head_text.startswith("ref: "):
        revision = _read_git_ref(common, head_text[5:])
    else:
        revision = head_text
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise NetworkWitnessError("Git revision is invalid")
    object_path = common / "objects" / revision[:2] / revision[2:]
    try:
        raw_object = zlib.decompress(object_path.read_bytes())
    except (OSError, zlib.error) as error:
        raise NetworkWitnessError(
            "Git commit is not available as an exact loose object"
        ) from error
    if hashlib.sha1(raw_object).hexdigest() != revision:
        raise NetworkWitnessError("Git commit object hash is invalid")
    header, separator, payload = raw_object.partition(b"\0")
    if separator != b"\0" or header != f"commit {len(payload)}".encode():
        raise NetworkWitnessError("Git commit object is malformed")
    tree_line = payload.splitlines()[0]
    if not tree_line.startswith(b"tree "):
        raise NetworkWitnessError("Git commit tree is missing")
    tree = tree_line[5:].decode("ascii")
    return SourceIdentity(
        revision,
        tree,
        source_content_revision(root),
    )


def _tool_inventory() -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for raw_path, expected in PINNED_TOOLS.items():
        path = Path(raw_path)
        try:
            descriptor = path.stat()
        except OSError as error:
            raise NetworkWitnessError(f"required tool is missing: {path}") from error
        if not path.is_file() or _sha256_file(path) != expected["sha256"]:
            raise NetworkWitnessError(f"required tool bytes differ: {path}")
        completed = subprocess.run(
            [raw_path, *expected["version_argv"]],
            check=False,
            capture_output=True,
            text=True,
            close_fds=True,
            env=COMMAND_ENVIRONMENT,
        )
        version = (completed.stdout or completed.stderr).strip()
        if completed.returncode != 0 or version != expected["version"]:
            raise NetworkWitnessError(f"required tool version differs: {path}")
        inventory[raw_path] = {
            "version": version,
            "sha256": expected["sha256"],
            "mode": f"{stat.S_IMODE(descriptor.st_mode):04o}",
            "size": descriptor.st_size,
        }
    return inventory


def _write_exclusive(path: Path, payload: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _read_message(stream: Any, timeout_seconds: float) -> dict[str, Any]:
    ready, _, _ = select.select([stream], [], [], timeout_seconds)
    if not ready:
        raise NetworkWitnessError("namespace worker protocol timed out")
    line = stream.readline()
    if not line:
        raise NetworkWitnessError("namespace worker exited before evidence")
    try:
        message = json.loads(line)
    except json.JSONDecodeError as error:
        raise NetworkWitnessError("namespace worker message is invalid") from error
    return dict(_mapping(message, "worker message"))


def _send_control(stream: Any, command: str, nonce: str) -> None:
    stream.write(f"{command} {nonce}\n")
    stream.flush()


def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)) or not command:
        raise NetworkWitnessError("command must be a non-empty argv sequence")
    normalized = tuple(str(argument) for argument in command)
    executable = Path(normalized[0])
    if not executable.is_absolute() or not executable.is_file():
        raise NetworkWitnessError("command executable must be an absolute file")
    if any(not argument or "\0" in argument for argument in normalized):
        raise NetworkWitnessError("command argv contains an invalid argument")
    return normalized


def _cooperative_preflight(
    expectation: CooperativeBrowserExpectation,
    source: SourceIdentity,
    evidence_root: Path,
) -> dict[str, tuple[int, int, int]]:
    if expectation.expected_source != source:
        raise NetworkWitnessError("cooperative source identity differs")
    root = expectation.execution_root.resolve(strict=True)
    request = expectation.request_path.resolve(strict=True)
    output_root = expectation.result_path.parent.resolve(strict=True)
    temp_root = (root / "integration-tmp").resolve(strict=True)
    if (
        root != expectation.execution_root
        or request != expectation.request_path
        or output_root != expectation.result_path.parent
        or evidence_root.parent.resolve(strict=True) != root
        or evidence_root.name != "network-evidence"
        or request != root / "integration-request.json"
        or output_root != root / "worker-output"
        or temp_root != root / "integration-tmp"
        or expectation.result_path != output_root / "worker-result.json"
    ):
        raise NetworkWitnessError("cooperative path layout is invalid")
    if evidence_root.exists() or expectation.result_path.exists():
        raise NetworkWitnessError(
            "cooperative output paths must not already exist"
        )
    if (
        not request.is_file()
        or request.is_symlink()
        or stat.S_IMODE(request.stat().st_mode) != 0o444
        or _sha256_file(request) != expectation.request_sha256
    ):
        raise NetworkWitnessError("cooperative request identity differs")
    identities: dict[str, tuple[int, int, int]] = {}
    for name, path in (
        ("execution_root", root),
        ("worker_output", output_root),
        ("integration_tmp", temp_root),
    ):
        status = path.stat()
        if (
            not path.is_dir()
            or path.is_symlink()
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            raise NetworkWitnessError(
                "cooperative directory identity is invalid"
            )
        if name != "execution_root" and any(path.iterdir()):
            raise NetworkWitnessError(
                "cooperative directory must start empty"
            )
        identities[name] = (status.st_dev, status.st_ino, status.st_mode)
    return identities


def _cooperative_result(
    expectation: CooperativeBrowserExpectation,
    identities: Mapping[str, tuple[int, int, int]],
) -> tuple[dict[str, Any], str]:
    output_root = expectation.result_path.parent
    current = output_root.stat()
    if (
        current.st_dev,
        current.st_ino,
        current.st_mode,
    ) != identities["worker_output"]:
        raise NetworkWitnessError("cooperative output directory changed")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(expectation.result_path, flags)
    except OSError as error:
        raise NetworkWitnessError("cooperative result is missing") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_size < 2
            or before.st_size > 4_000_000
        ):
            raise NetworkWitnessError("cooperative result file is invalid")
        payload = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(payload) != before.st_size
        or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
        )
    ):
        raise NetworkWitnessError("cooperative result changed while read")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NetworkWitnessError("cooperative result JSON is invalid") from error
    result = dict(_mapping(value, "cooperative result"))
    if _canonical_json(result) != payload:
        raise NetworkWitnessError("cooperative result is not canonical")
    expected_keys = {
        "schema_version",
        "request_sha256",
        "integration_nonce_sha256",
        "source",
        "cooperative_policy_sha256",
        "environment",
        "environment_sha256",
        "shared_memory",
        "chromium_effective_argv",
        "chromium_effective_argv_sha256",
        "runtime_identities",
        "fixture_receipt",
        "submission_proof",
        "observation",
        "artifact_inventory",
        "worker_artifact_inventory_sha256",
        "evidence_kind",
        "execution_claim",
        "external_actions",
        "real_applications_submitted",
    }
    if set(result) != expected_keys:
        raise NetworkWitnessError("cooperative result field set differs")
    source = _mapping(result.get("source"), "cooperative result source")
    if (
        result.get("schema_version") != expectation.result_schema_version
        or result.get("request_sha256") != expectation.request_sha256
        or result.get("integration_nonce_sha256")
        != expectation.integration_nonce_sha256
        or result.get("cooperative_policy_sha256")
        != expectation.cooperative_policy_sha256
        or dict(source) != expectation.expected_source.document()
        or result.get("evidence_kind") != "synthetic_shadow"
        or result.get("execution_claim") != "structural_lineage_only"
        or result.get("external_actions") != 0
        or result.get("real_applications_submitted") != 0
    ):
        raise NetworkWitnessError("cooperative result authority differs")
    artifact_hash = str(result.get("worker_artifact_inventory_sha256"))
    if not re.fullmatch(r"[0-9a-f]{64}", artifact_hash):
        raise NetworkWitnessError("cooperative artifact inventory is invalid")
    return result, hashlib.sha256(payload).hexdigest()


def _descriptor_policy(
    control_fd: int,
    evidence_fd: int,
    control_inode: int,
    evidence_inode: int,
    stdout_path: Path,
    stderr_path: Path,
) -> dict[str, Any]:
    return {
        "close_fds": True,
        "pass_fds": [control_fd, evidence_fd],
        "stdin": "/dev/null",
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "control_channel": {
            "kind": "anonymous_pipe",
            "inode": control_inode,
            "worker_fd": control_fd,
        },
        "evidence_channel": {
            "kind": "anonymous_pipe",
            "inode": evidence_inode,
            "worker_fd": evidence_fd,
        },
        "socket_fds_allowed_at_readiness": 0,
        "socket_fds_allowed_at_finalization": 0,
        "fd_passing_capability": False,
    }


def _evidence_inventory(
    paths: Sequence[Path],
) -> tuple[list[dict[str, Any]], str]:
    rows = [
        {
            "name": path.name,
            "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        for path in sorted(paths, key=lambda item: item.name)
    ]
    return rows, _domain_hash(INVENTORY_DOMAIN, _canonical_json({"files": rows}))


def _validate_cooperative_browser_controls(
    document: Mapping[str, Any],
    schema_version: str,
) -> bool:
    controls = _mapping(
        document.get("cooperative_browser_controls"),
        "cooperative browser controls",
    )
    if schema_version == SCHEMA_VERSION_V1:
        if controls != {
            "integration_status": "not_integrated_standalone_harness",
            "playwright_launch_flags": "not_applicable",
            "existing_loopback_controls_required_for_future_integration": True,
        }:
            raise NetworkWitnessError(
                "v1 cooperative browser controls differ"
            )
        return False
    standalone = {
        "schema_version": "jaa10.cooperative-browser-controls.v2",
        "integration_status": "not_integrated_standalone_harness",
        "existing_loopback_controls_required_for_future_integration": True,
        "external_actions": 0,
        "real_applications_submitted": 0,
    }
    if controls == standalone:
        return False
    expected_keys = {
        "schema_version",
        "integration_status",
        "binding_mode",
        "request_sha256",
        "integration_nonce_sha256",
        "worker_result_schema_version",
        "worker_result_sha256",
        "worker_artifact_inventory_sha256",
        "cooperative_policy_sha256",
        "fixture_origin_class",
        "existing_loopback_controls_required",
        "external_actions",
        "real_applications_submitted",
    }
    if set(controls) != expected_keys:
        raise NetworkWitnessError(
            "integrated cooperative browser field set differs"
        )
    literals = {
        "schema_version": "jaa10.cooperative-browser-controls.v2",
        "integration_status": (
            "network_witnessed_local_fixture_single_execution"
        ),
        "binding_mode": (
            "direct_result_path_independently_read_post_command"
        ),
        "worker_result_schema_version": (
            "jaa10.network-witnessed-fixture-worker-result.v1"
        ),
        "fixture_origin_class": "exact_loopback_http_origin_only",
        "existing_loopback_controls_required": True,
        "external_actions": 0,
        "real_applications_submitted": 0,
    }
    if any(controls.get(key) != value for key, value in literals.items()):
        raise NetworkWitnessError(
            "integrated cooperative browser control differs"
        )
    for key in (
        "request_sha256",
        "integration_nonce_sha256",
        "worker_result_sha256",
        "worker_artifact_inventory_sha256",
        "cooperative_policy_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(controls.get(key))):
            raise NetworkWitnessError(
                "integrated cooperative browser hash is invalid"
            )
    return True


def _validate_witness_document(document: Mapping[str, Any]) -> None:
    expected_keys = {
        "schema_version",
        "source",
        "execution_id",
        "supervisor_nonce_sha256",
        "kernel",
        "tools",
        "supervisor",
        "worker",
        "pre_state",
        "post_state",
        "descendant_namespace_inventory",
        "cooperative_browser_controls",
        "claim",
        "limitations",
        "external_actions",
        "real_applications_submitted",
        "descriptor_policy",
        "designated_pipe_inodes",
        "fd_inventory_pre",
        "fd_inventory_post",
        "raw_socket_table_sha256",
        "inherited_ip_socket_count",
        "inherited_socket_count",
        "post_execution_socket_count",
        "execution_result",
        "execution_result_sha256",
        "evidence_inventory",
    }
    if set(document) != expected_keys:
        raise NetworkWitnessError("witness field set is not exhaustive")
    schema_version = str(document.get("schema_version"))
    if schema_version not in {SCHEMA_VERSION_V1, SCHEMA_VERSION}:
        raise NetworkWitnessError("witness schema version is invalid")
    _validate_cooperative_browser_controls(document, schema_version)
    if document.get("external_actions") != 0:
        raise NetworkWitnessError("witness cannot record an external action")
    if document.get("real_applications_submitted") != 0:
        raise NetworkWitnessError("witness cannot record a real application")
    if document.get("inherited_ip_socket_count") != 0:
        raise NetworkWitnessError("witness inherited an IP socket")
    if document.get("inherited_socket_count") != 0:
        raise NetworkWitnessError("witness inherited a socket")
    if document.get("post_execution_socket_count") != 0:
        raise NetworkWitnessError("witness retained a socket")
    limitations = document.get("limitations")
    if limitations != [
        "pre_post_snapshots_and_descendant_inventory_are_sampled",
        "no_packet_capture_or_ebpf_witness",
        "filesystem_unix_shared_memory_and_filesystem_side_channels_unbounded",
        "honest_kernel_and_unprivileged_host_assumed",
        "privileged_writer_can_mutate_local_evidence",
        "calendar_and_signed_time_not_authenticated",
        "no_live_external_vacancy_metric_production_slice_or_external_authority",
    ]:
        raise NetworkWitnessError("witness limitations are incomplete")
    claim = _mapping(document.get("claim"), "claim")
    if claim != {
        "external_ip_network_capability": (
            "absent_under_linux_network_namespace"
        ),
        "network_syscall_attempts": "not_measured",
        "packet_history": "not_captured",
        "host_wide_traffic": "not_claimed",
    }:
        raise NetworkWitnessError("witness claim is invalid")
    pre_state = _mapping(document.get("pre_state"), "pre state")
    post_state = _mapping(document.get("post_state"), "post state")
    _validate_process_state(pre_state)
    _validate_process_state(post_state)
    for key in (
        "network_namespace",
        "user_namespace",
        "process_start_ticks",
    ):
        if pre_state.get(key) != post_state.get(key):
            raise NetworkWitnessError(f"worker {key} changed")
    fd_pre = document.get("fd_inventory_pre")
    fd_post = document.get("fd_inventory_post")
    if not isinstance(fd_pre, list) or not isinstance(fd_post, list):
        raise NetworkWitnessError("worker descriptor inventory is invalid")
    if fd_pre != fd_post:
        raise NetworkWitnessError("worker descriptor inventory changed")
    policy = _mapping(document.get("descriptor_policy"), "descriptor policy")
    pass_fds = policy.get("pass_fds")
    pipe_inodes = document.get("designated_pipe_inodes")
    if (
        not isinstance(pass_fds, list)
        or len(pass_fds) != 2
        or not isinstance(pipe_inodes, list)
        or len(pipe_inodes) != 2
    ):
        raise NetworkWitnessError("witness descriptor policy is invalid")
    if policy.get("close_fds") is not True:
        raise NetworkWitnessError("witness descriptor closure is disabled")
    if policy.get("fd_passing_capability") is not False:
        raise NetworkWitnessError("witness descriptor passing is enabled")
    _validate_fd_inventory(
        fd_pre,
        control_fd=int(pass_fds[0]),
        evidence_fd=int(pass_fds[1]),
        control_inode=int(pipe_inodes[0]),
        evidence_inode=int(pipe_inodes[1]),
        stdout_path=Path(str(policy.get("stdout"))),
        stderr_path=Path(str(policy.get("stderr"))),
    )
    _validate_fd_inventory(
        fd_post,
        control_fd=int(pass_fds[0]),
        evidence_fd=int(pass_fds[1]),
        control_inode=int(pipe_inodes[0]),
        evidence_inode=int(pipe_inodes[1]),
        stdout_path=Path(str(policy.get("stdout"))),
        stderr_path=Path(str(policy.get("stderr"))),
    )
    if document.get("raw_socket_table_sha256") != {
        "pre": pre_state.get("raw_socket_table_sha256"),
        "post": post_state.get("raw_socket_table_sha256"),
    }:
        raise NetworkWitnessError("witness socket-table binding differs")
    execution_result = _mapping(
        document.get("execution_result"),
        "execution result",
    )
    if document.get("execution_result_sha256") != _domain_hash(
        EXECUTION_RESULT_DOMAIN,
        _canonical_json(execution_result),
    ):
        raise NetworkWitnessError("execution-result hash is invalid")
    if execution_result.get("returncode") != 0:
        raise NetworkWitnessError("witness command did not succeed")
    descendants = document.get("descendant_namespace_inventory")
    if not isinstance(descendants, list):
        raise NetworkWitnessError("descendant inventory is invalid")
    expected_namespace = pre_state.get("network_namespace")
    if any(
        not isinstance(row, dict)
        or row.get("network_namespace") != expected_namespace
        for row in descendants
    ):
        raise NetworkWitnessError("descendant left the worker namespace")
    worker = _mapping(document.get("worker"), "worker")
    if (
        worker.get("network_namespace")
        != pre_state.get("network_namespace")
        or worker.get("user_namespace") != pre_state.get("user_namespace")
        or worker.get("process_start_ticks")
        != pre_state.get("process_start_ticks")
    ):
        raise NetworkWitnessError("worker identity binding differs")
    supervisor = _mapping(document.get("supervisor"), "supervisor")
    if (
        supervisor.get("network_namespace")
        == worker.get("network_namespace")
    ):
        raise NetworkWitnessError("worker shares the supervisor namespace")
    evidence_inventory = _mapping(
        document.get("evidence_inventory"),
        "evidence inventory",
    )
    files = evidence_inventory.get("files")
    if not isinstance(files, list):
        raise NetworkWitnessError("evidence file inventory is invalid")
    if evidence_inventory.get("inventory_sha256") != _domain_hash(
        INVENTORY_DOMAIN,
        _canonical_json({"files": files}),
    ):
        raise NetworkWitnessError("evidence inventory hash differs")


def run_isolated_network_witness(
    command: Sequence[str],
    *,
    repository_root: str | Path,
    evidence_directory: str | Path,
    timeout_seconds: float = 30.0,
    cooperative_browser_expectation: (
        CooperativeBrowserExpectation | None
    ) = None,
) -> tuple[
    LinuxNetworkNamespaceWitness,
    NetworkNamespaceWitnessReceipt,
]:
    """Run one explicit command under the accepted fail-closed predicate."""

    argv = _validate_command(command)
    if not 1.0 <= timeout_seconds <= 300.0:
        raise NetworkWitnessError("timeout must be between 1 and 300 seconds")
    repository = Path(repository_root).resolve(strict=True)
    source = _source_identity(repository)
    tools = _tool_inventory()
    evidence_root = Path(evidence_directory)
    cooperative_identities = (
        _cooperative_preflight(
            cooperative_browser_expectation,
            source,
            evidence_root,
        )
        if cooperative_browser_expectation is not None
        else None
    )
    command_environment = dict(COMMAND_ENVIRONMENT)
    if cooperative_browser_expectation is not None:
        command_environment["TMPDIR"] = str(
            cooperative_browser_expectation.execution_root
            / "integration-tmp"
        )
    try:
        evidence_root.mkdir(mode=0o700)
    except OSError as error:
        raise NetworkWitnessError(
            "evidence directory must be newly creatable"
        ) from error
    if stat.S_IMODE(evidence_root.stat().st_mode) != 0o700:
        raise NetworkWitnessError("evidence directory mode is not 0700")

    nonce = os.urandom(32)
    nonce_hex = nonce.hex()
    nonce_sha256 = hashlib.sha256(nonce).hexdigest()
    execution_id = _domain_hash(
        b"jaa10-linux-network-execution-id-v1\0",
        nonce + source.git_revision.encode("ascii"),
    )
    config_path = evidence_root / "worker-config.json"
    supervisor_stdout = evidence_root / "namespace-supervisor.stdout.log"
    supervisor_stderr = evidence_root / "namespace-supervisor.stderr.log"
    command_stdout = evidence_root / "command.stdout.log"
    command_stderr = evidence_root / "command.stderr.log"
    config = {
        "schema_version": "jaa10.linux-network-worker-config.v1",
        "execution_id": execution_id,
        "nonce": nonce_hex,
        "command": list(argv),
        "repository_root": str(repository),
        "command_stdout": str(command_stdout),
        "command_stderr": str(command_stderr),
        "command_environment": command_environment,
    }
    _write_exclusive(config_path, _canonical_json(config), 0o600)

    control_read, control_write = os.pipe2(os.O_CLOEXEC)
    evidence_read, evidence_write = os.pipe2(os.O_CLOEXEC)
    os.set_inheritable(control_read, True)
    os.set_inheritable(evidence_write, True)
    control_inode = os.fstat(control_read).st_ino
    evidence_inode = os.fstat(evidence_write).st_ino
    descriptor_policy = _descriptor_policy(
        control_read,
        evidence_write,
        control_inode,
        evidence_inode,
        supervisor_stdout,
        supervisor_stderr,
    )
    process: subprocess.Popen[bytes] | None = None
    control_stream: Any = None
    evidence_stream: Any = None
    try:
        with (
            Path("/dev/null").open("rb") as stdin,
            supervisor_stdout.open("xb") as stdout,
            supervisor_stderr.open("xb") as stderr,
        ):
            os.chmod(supervisor_stdout, 0o600)
            os.chmod(supervisor_stderr, 0o600)
            process = subprocess.Popen(
                [
                    str(UNSHARE),
                    "--user",
                    "--map-root-user",
                    "--net",
                    "--mount",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                    sys.executable,
                    "-m",
                    "career_automation.linux_network_namespace_witness",
                    "--setup",
                    str(config_path),
                    str(control_read),
                    str(evidence_write),
                ],
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                close_fds=True,
                pass_fds=(control_read, evidence_write),
                cwd=repository,
                env=COMMAND_ENVIRONMENT,
            )
        os.close(control_read)
        control_read = -1
        os.close(evidence_write)
        evidence_write = -1
        control_stream = os.fdopen(
            control_write,
            "w",
            encoding="ascii",
            buffering=1,
        )
        control_write = -1
        evidence_stream = os.fdopen(
            evidence_read,
            "r",
            encoding="utf-8",
            buffering=1,
        )
        evidence_read = -1

        ready = _read_message(evidence_stream, timeout_seconds)
        if ready.get("type") == "ERROR":
            raise NetworkWitnessError(str(ready.get("message")))
        if ready.get("type") != "READY":
            raise NetworkWitnessError("worker readiness message is invalid")
        if ready.get("execution_id") != execution_id:
            raise NetworkWitnessError("worker execution identity differs")
        if process is None:
            raise NetworkWitnessError("namespace supervisor is missing")
        worker_candidates = _descendants(process.pid)
        if len(worker_candidates) != 1:
            raise NetworkWitnessError(
                "worker process identity is not unique"
            )
        worker_pid = worker_candidates[0]
        pre_state = _capture_process_state(worker_pid)
        if pre_state["network_namespace"] == _namespace_identity("self", "net"):
            raise NetworkWitnessError("worker did not enter a network namespace")
        if pre_state["user_namespace"] == _namespace_identity("self", "user"):
            raise NetworkWitnessError("worker did not enter a user namespace")
        if ready.get("state_fingerprint") != _state_fingerprint(pre_state):
            raise NetworkWitnessError("inner and outer readiness state differs")
        fd_pre = _fd_inventory(worker_pid)
        _validate_fd_inventory(
            fd_pre,
            control_fd=int(ready.get("control_fd")),
            evidence_fd=int(ready.get("evidence_fd")),
            control_inode=control_inode,
            evidence_inode=evidence_inode,
            stdout_path=supervisor_stdout,
            stderr_path=supervisor_stderr,
        )
        if _descendants(worker_pid):
            raise NetworkWitnessError("worker has a descendant before execution")
        _send_control(control_stream, "EXECUTE", nonce_hex)

        finished = _read_message(evidence_stream, timeout_seconds)
        if finished.get("type") == "ERROR":
            raise NetworkWitnessError(str(finished.get("message")))
        if finished.get("type") != "POST_READY":
            raise NetworkWitnessError("worker final message is invalid")
        if finished.get("execution_id") != execution_id:
            raise NetworkWitnessError("worker final identity differs")
        post_state = _capture_process_state(worker_pid)
        if finished.get("state_fingerprint") != _state_fingerprint(post_state):
            raise NetworkWitnessError("inner and outer final state differs")
        fd_post = _fd_inventory(worker_pid)
        _validate_fd_inventory(
            fd_post,
            control_fd=int(ready.get("control_fd")),
            evidence_fd=int(ready.get("evidence_fd")),
            control_inode=control_inode,
            evidence_inode=evidence_inode,
            stdout_path=supervisor_stdout,
            stderr_path=supervisor_stderr,
        )
        surviving = _descendants(worker_pid)
        if surviving:
            raise NetworkWitnessError("worker has a surviving descendant")
        if fd_pre != fd_post:
            raise NetworkWitnessError("worker descriptor inventory changed")
        if (
            pre_state["network_namespace"]
            != post_state["network_namespace"]
            or pre_state["user_namespace"] != post_state["user_namespace"]
        ):
            raise NetworkWitnessError("worker namespace identity changed")
        _send_control(control_stream, "FINALIZE", nonce_hex)
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            raise NetworkWitnessError(
                "namespace supervisor did not finalize"
            ) from error
        if returncode != 0:
            raise NetworkWitnessError("namespace supervisor exited unsuccessfully")
        result = _mapping(finished.get("execution_result"), "execution result")
        if result.get("returncode") != 0:
            raise NetworkWitnessError("explicit command exited unsuccessfully")
        if not command_stdout.is_file() or not command_stderr.is_file():
            raise NetworkWitnessError("command output evidence is missing")
        expected_result = {
            "returncode": 0,
            "command_sha256": hashlib.sha256(
                _canonical_json({"argv": list(argv)})
            ).hexdigest(),
            "stdout_sha256": _sha256_file(command_stdout),
            "stderr_sha256": _sha256_file(command_stderr),
        }
        if result != expected_result:
            raise NetworkWitnessError("command result binding differs")
        cooperative_result: dict[str, Any] | None = None
        worker_result_sha256: str | None = None
        if cooperative_browser_expectation is not None:
            if cooperative_identities is None:
                raise NetworkWitnessError(
                    "cooperative preflight identity is missing"
                )
            cooperative_result, worker_result_sha256 = _cooperative_result(
                cooperative_browser_expectation,
                cooperative_identities,
            )
        execution_result_sha256 = _domain_hash(
            EXECUTION_RESULT_DOMAIN,
            _canonical_json(expected_result),
        )
        evidence_paths = [
            config_path,
            supervisor_stdout,
            supervisor_stderr,
            command_stdout,
            command_stderr,
        ]
        inventory, inventory_sha256 = _evidence_inventory(evidence_paths)
        descriptor_policy_sha256 = _domain_hash(
            DESCRIPTOR_POLICY_DOMAIN,
            _canonical_json(descriptor_policy),
        )
        fd_pre_sha256 = _domain_hash(
            FD_INVENTORY_DOMAIN,
            _canonical_json({"fds": fd_pre}),
        )
        fd_post_sha256 = _domain_hash(
            FD_INVENTORY_DOMAIN,
            _canonical_json({"fds": fd_post}),
        )
        if cooperative_result is None:
            cooperative_controls = {
                "schema_version": "jaa10.cooperative-browser-controls.v2",
                "integration_status": "not_integrated_standalone_harness",
                "existing_loopback_controls_required_for_future_integration": True,
                "external_actions": 0,
                "real_applications_submitted": 0,
            }
        else:
            cooperative_controls = {
                "schema_version": "jaa10.cooperative-browser-controls.v2",
                "integration_status": (
                    "network_witnessed_local_fixture_single_execution"
                ),
                "binding_mode": (
                    "direct_result_path_independently_read_post_command"
                ),
                "request_sha256": (
                    cooperative_browser_expectation.request_sha256
                ),
                "integration_nonce_sha256": (
                    cooperative_browser_expectation.integration_nonce_sha256
                ),
                "worker_result_schema_version": (
                    cooperative_browser_expectation.result_schema_version
                ),
                "worker_result_sha256": worker_result_sha256,
                "worker_artifact_inventory_sha256": cooperative_result[
                    "worker_artifact_inventory_sha256"
                ],
                "cooperative_policy_sha256": (
                    cooperative_browser_expectation.cooperative_policy_sha256
                ),
                "fixture_origin_class": "exact_loopback_http_origin_only",
                "existing_loopback_controls_required": True,
                "external_actions": 0,
                "real_applications_submitted": 0,
            }
        witness_document = {
            "schema_version": SCHEMA_VERSION,
            "source": source.document(),
            "execution_id": execution_id,
            "supervisor_nonce_sha256": nonce_sha256,
            "kernel": {
                "sysname": os.uname().sysname,
                "release": os.uname().release,
                "boot_id_sha256": _sha256_file(
                    Path("/proc/sys/kernel/random/boot_id")
                ),
            },
            "tools": tools,
            "supervisor": {
                "pid": os.getpid(),
                "process_start_ticks": _process_start_ticks("self"),
                "network_namespace": _namespace_identity("self", "net"),
            },
            "worker": {
                "outer_pid": worker_pid,
                "inner_pid": int(ready.get("inner_pid")),
                "process_start_ticks": pre_state["process_start_ticks"],
                "user_namespace": pre_state["user_namespace"],
                "network_namespace": pre_state["network_namespace"],
            },
            "pre_state": pre_state,
            "post_state": post_state,
            "descendant_namespace_inventory": list(
                finished.get("descendant_namespace_inventory", [])
            ),
            "cooperative_browser_controls": cooperative_controls,
            "claim": {
                "external_ip_network_capability": (
                    "absent_under_linux_network_namespace"
                ),
                "network_syscall_attempts": "not_measured",
                "packet_history": "not_captured",
                "host_wide_traffic": "not_claimed",
            },
            "limitations": [
                "pre_post_snapshots_and_descendant_inventory_are_sampled",
                "no_packet_capture_or_ebpf_witness",
                "filesystem_unix_shared_memory_and_filesystem_side_channels_unbounded",
                "honest_kernel_and_unprivileged_host_assumed",
                "privileged_writer_can_mutate_local_evidence",
                "calendar_and_signed_time_not_authenticated",
                "no_live_external_vacancy_metric_production_slice_or_external_authority",
            ],
            "external_actions": 0,
            "real_applications_submitted": 0,
            "descriptor_policy": descriptor_policy,
            "designated_pipe_inodes": [control_inode, evidence_inode],
            "fd_inventory_pre": fd_pre,
            "fd_inventory_post": fd_post,
            "raw_socket_table_sha256": {
                "pre": pre_state["raw_socket_table_sha256"],
                "post": post_state["raw_socket_table_sha256"],
            },
            "inherited_ip_socket_count": 0,
            "inherited_socket_count": 0,
            "post_execution_socket_count": 0,
            "execution_result": expected_result,
            "execution_result_sha256": execution_result_sha256,
            "evidence_inventory": {
                "files": inventory,
                "inventory_sha256": inventory_sha256,
            },
        }
        witness = LinuxNetworkNamespaceWitness.from_document(witness_document)
        receipt = NetworkNamespaceWitnessReceipt.issue(
            witness_sha256=witness.witness_sha256,
            execution_result_sha256=execution_result_sha256,
            source=source,
            supervisor_nonce_sha256=nonce_sha256,
            descriptor_policy_sha256=descriptor_policy_sha256,
            fd_inventory_pre_sha256=fd_pre_sha256,
            fd_inventory_post_sha256=fd_post_sha256,
            designated_pipe_inodes=(control_inode, evidence_inode),
            evidence_inventory_sha256=inventory_sha256,
            cooperative_browser_controls_sha256=(
                _domain_hash(
                    COOPERATIVE_BROWSER_CONTROLS_DOMAIN,
                    _canonical_json(cooperative_controls),
                )
                if cooperative_result is not None
                else None
            ),
            worker_result_sha256=worker_result_sha256,
            request_sha256=(
                cooperative_browser_expectation.request_sha256
                if cooperative_browser_expectation is not None
                else None
            ),
            integration_nonce_sha256=(
                cooperative_browser_expectation.integration_nonce_sha256
                if cooperative_browser_expectation is not None
                else None
            ),
        )
        witness_path = evidence_root / "network-witness.json"
        receipt_path = evidence_root / "network-witness-receipt.json"
        _write_exclusive(
            witness_path,
            witness.canonical_document,
            0o600,
        )
        _write_exclusive(
            receipt_path,
            _canonical_json(receipt.document()),
            0o600,
        )
        os.chmod(witness_path, 0o444)
        os.chmod(receipt_path, 0o444)
        return witness, receipt
    except (NetworkWitnessError, OSError, ValueError) as error:
        if isinstance(error, NetworkWitnessError):
            raise
        raise NetworkWitnessError("namespace witness failed closed") from error
    finally:
        for descriptor in (
            control_read,
            control_write,
            evidence_read,
            evidence_write,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        for stream in (control_stream, evidence_stream):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def _inner_state() -> dict[str, Any]:
    return _capture_process_state(os.getpid())


def _worker_send(descriptor: int, document: Mapping[str, Any]) -> None:
    payload = _canonical_json(document) + b"\n"
    while payload:
        written = os.write(descriptor, payload)
        payload = payload[written:]


def _worker_control(descriptor: int, expected: str, nonce: str) -> None:
    payload = bytearray()
    while not payload.endswith(b"\n"):
        block = os.read(descriptor, 256)
        if not block or len(payload) + len(block) > 1024:
            raise NetworkWitnessError("worker control token is truncated")
        payload.extend(block)
    if bytes(payload) != f"{expected} {nonce}\n".encode("ascii"):
        raise NetworkWitnessError("worker control token is invalid")


def _close_unexpected_descriptors(allowed: set[int]) -> None:
    try:
        descriptors = [
            int(path.name)
            for path in Path("/proc/self/fd").iterdir()
            if path.name.isdigit()
        ]
    except (OSError, ValueError) as error:
        raise NetworkWitnessError(
            "worker cannot enumerate inherited descriptors"
        ) from error
    for descriptor in descriptors:
        if descriptor not in allowed:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _worker(config_path: Path, control_fd: int, evidence_fd: int) -> int:
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        _close_unexpected_descriptors(
            {0, 1, 2, control_fd, evidence_fd}
        )
        nonce = str(config["nonce"])
        execution_id = str(config["execution_id"])
        status = _read_status("self")
        nspid = [int(value) for value in status.get("NSpid", "").split()]
        if not nspid:
            raise NetworkWitnessError("worker PID namespace identity is missing")
        pre_state = _inner_state()
        _worker_send(
            evidence_fd,
            {
                "type": "READY",
                "execution_id": execution_id,
                "inner_pid": nspid[-1],
                "control_fd": control_fd,
                "evidence_fd": evidence_fd,
                "state_fingerprint": _state_fingerprint(pre_state),
            },
        )
        _worker_control(control_fd, "EXECUTE", nonce)
        command = [str(value) for value in config["command"]]
        command_environment = {
            str(key): str(value)
            for key, value in _mapping(
                config["command_environment"],
                "command environment",
            ).items()
        }
        allowed_environment = dict(COMMAND_ENVIRONMENT)
        if "TMPDIR" in command_environment:
            allowed_environment["TMPDIR"] = command_environment["TMPDIR"]
        if command_environment != allowed_environment:
            raise NetworkWitnessError("command environment is invalid")
        stdout_path = Path(str(config["command_stdout"]))
        stderr_path = Path(str(config["command_stderr"]))
        descendant_inventory: list[dict[str, Any]] = []
        with (
            stdout_path.open("xb") as stdout,
            stderr_path.open("xb") as stderr,
        ):
            os.chmod(stdout_path, 0o600)
            os.chmod(stderr_path, 0o600)
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                close_fds=True,
                cwd=str(config["repository_root"]),
                env=command_environment,
            )
            try:
                descendant_inventory.append(
                    {
                        "pid": process.pid,
                        "process_start_ticks": _process_start_ticks(process.pid),
                        "network_namespace": _namespace_identity(
                            process.pid,
                            "net",
                        ),
                    }
                )
            except NetworkWitnessError:
                pass
            returncode = process.wait()
        if _descendants(os.getpid()):
            raise NetworkWitnessError("command left a surviving descendant")
        post_state = _inner_state()
        result = {
            "returncode": returncode,
            "command_sha256": hashlib.sha256(
                _canonical_json({"argv": command})
            ).hexdigest(),
            "stdout_sha256": _sha256_file(stdout_path),
            "stderr_sha256": _sha256_file(stderr_path),
        }
        _worker_send(
            evidence_fd,
            {
                "type": "POST_READY",
                "execution_id": execution_id,
                "state_fingerprint": _state_fingerprint(post_state),
                "descendant_namespace_inventory": descendant_inventory,
                "execution_result": result,
            },
        )
        _worker_control(control_fd, "FINALIZE", nonce)
        return 0
    except Exception as error:
        try:
            _worker_send(
                evidence_fd,
                {
                    "type": "ERROR",
                    "message": f"{type(error).__name__}: {error}",
                },
            )
        except OSError:
            pass
        return 91


def _setup(config_path: Path, control_fd: int, evidence_fd: int) -> int:
    completed = subprocess.run(
        [str(IP), "link", "set", "lo", "up"],
        check=False,
        close_fds=True,
        env=COMMAND_ENVIRONMENT,
    )
    if completed.returncode != 0:
        _worker_send(
            evidence_fd,
            {"type": "ERROR", "message": "loopback setup failed"},
        )
        return 90
    argv = [
        str(SETPRIV),
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        sys.executable,
        "-m",
        "career_automation.linux_network_namespace_witness",
        "--worker",
        str(config_path),
        str(control_fd),
        str(evidence_fd),
    ]
    os.execve(str(SETPRIV), argv, COMMAND_ENVIRONMENT)
    return 90


def _main(arguments: Sequence[str]) -> int:
    if len(arguments) != 4 or arguments[0] not in {"--setup", "--worker"}:
        return 64
    mode, config_path, control_fd, evidence_fd = arguments
    if mode == "--setup":
        return _setup(
            Path(config_path),
            int(control_fd),
            int(evidence_fd),
        )
    return _worker(
        Path(config_path),
        int(control_fd),
        int(evidence_fd),
    )


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
