"""Policy contracts for isolated, licence-aware document sidecars.

The core pipeline uses small deterministic PDF tools.  This module governs any
future OCR/repair/conversion sidecar so a large document platform cannot
silently gain network, storage, telemetry, or licensing authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^[a-z0-9./_-]+(?:[:][a-z0-9._-]+)?@sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class DocumentEngineManifest:
    engine: str
    version: str
    source_repository: str
    source_revision: str
    licence_identifier: str
    licence_zone: str
    image: str

    def __post_init__(self) -> None:
        required = (
            self.engine, self.version, self.source_repository, self.source_revision,
            self.licence_identifier, self.licence_zone, self.image,
        )
        if any(not value.strip() for value in required):
            raise ValueError("document engine manifest fields are required")
        if not IMAGE_DIGEST.fullmatch(self.image):
            raise ValueError("document sidecar image must be pinned by sha256 digest")


@dataclass(frozen=True)
class DocumentOperationManifest:
    operation_id: str
    operation: str
    input_sha256: str
    output_format: str
    engine: DocumentEngineManifest
    network_disabled: bool
    analytics_disabled: bool
    persistent_storage_disabled: bool
    sharing_disabled: bool
    read_only_root: bool

    def __post_init__(self) -> None:
        if not self.operation_id.strip() or not self.operation.strip() or not self.output_format.strip():
            raise ValueError("operation id, operation and output format are required")
        if not SHA256_HEX.fullmatch(self.input_sha256):
            raise ValueError("input_sha256 must be a lowercase sha256 hex digest")


@dataclass(frozen=True)
class ContainerRunSpec:
    argv: tuple[str, ...]
    input_directory: Path
    output_directory: Path


class DocumentSidecarPolicy:
    """Fail-closed policy for untrusted personal-document processing."""

    def __init__(
        self,
        *,
        allowed_licences: Iterable[str] = ("MIT", "Apache-2.0", "BSD-3-Clause"),
        allowed_zones: Iterable[str] = ("core", "oss", "mit-core"),
    ) -> None:
        self.allowed_licences = frozenset(allowed_licences)
        self.allowed_zones = frozenset(allowed_zones)

    def validate(self, manifest: DocumentOperationManifest) -> None:
        engine = manifest.engine
        if engine.licence_identifier not in self.allowed_licences:
            raise PermissionError(f"unapproved document-engine licence: {engine.licence_identifier}")
        if engine.licence_zone.casefold() not in {zone.casefold() for zone in self.allowed_zones}:
            raise PermissionError(f"unapproved document-engine licence zone: {engine.licence_zone}")
        required_flags = {
            "network_disabled": manifest.network_disabled,
            "analytics_disabled": manifest.analytics_disabled,
            "persistent_storage_disabled": manifest.persistent_storage_disabled,
            "sharing_disabled": manifest.sharing_disabled,
            "read_only_root": manifest.read_only_root,
        }
        missing = [name for name, enabled in required_flags.items() if not enabled]
        if missing:
            raise PermissionError(f"unsafe document sidecar policy: {', '.join(missing)}")

    def docker_run_spec(
        self,
        manifest: DocumentOperationManifest,
        *,
        input_directory: str | Path,
        output_directory: str | Path,
        sidecar_command: Iterable[str],
    ) -> ContainerRunSpec:
        self.validate(manifest)
        source = Path(input_directory).resolve(strict=True)
        destination = Path(output_directory).resolve(strict=True)
        if not source.is_dir() or not destination.is_dir():
            raise ValueError("document sidecar mounts must be directories")
        if source == destination:
            raise ValueError("input and output directories must be separate")
        command = tuple(sidecar_command)
        if not command or any("\x00" in value for value in command):
            raise ValueError("sidecar command must be non-empty argv without NUL bytes")
        argv = (
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--memory", "1g", "--cpus", "1",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
            "--mount", f"type=bind,src={source},dst=/input,readonly",
            "--mount", f"type=bind,src={destination},dst=/output",
            manifest.engine.image,
            *command,
        )
        return ContainerRunSpec(argv=argv, input_directory=source, output_directory=destination)


@dataclass(frozen=True)
class EngineVerification:
    engine: str
    artifact_sha256: str
    passed: bool
    findings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.engine.strip() or not SHA256_HEX.fullmatch(self.artifact_sha256):
            raise ValueError("verification engine and artifact hash are required")


def require_verification_consensus(
    results: Iterable[EngineVerification], *, required_engines: Iterable[str]
) -> tuple[EngineVerification, ...]:
    """Require independent engines to agree on the exact same artifact."""
    values = tuple(results)
    by_engine = {result.engine: result for result in values}
    required = tuple(required_engines)
    missing = [engine for engine in required if engine not in by_engine]
    if missing:
        raise ValueError(f"missing required verification engines: {missing}")
    hashes = {by_engine[engine].artifact_sha256 for engine in required}
    if len(hashes) != 1:
        raise ValueError("verification engines did not inspect the same artifact")
    failed = [engine for engine in required if not by_engine[engine].passed]
    if failed:
        raise RuntimeError(f"document verification failed: {failed}")
    return tuple(by_engine[engine] for engine in required)

