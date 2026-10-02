"""Authenticated production-time entrypoint for deterministic Market handoffs.

This is the only production-facing constructor. It obtains current time from
the installed deployment-owned witness and passes that instant to the internal
deterministic builder only for freshness evaluation. It issues no release token
and grants no submission authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from market_aligner.applications import production_handoff
from market_aligner.applications.handoff import canonical_json_bytes
from market_aligner.applications.production_handoff import (
    PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
    ProductionHandoffReceipt,
    _build_production_handoff_from_authenticated_time,
    _ProductionHandoffDeployment,
)

from .current_time import installed_production_current_time_witness, obtain_current_time

PRODUCTION_HANDOFF_DEPLOYMENT_CONFIG_PATH = Path(
    "/etc/gigabyte/majaa-public/market-handoff-v1.json"
)
PRODUCTION_MARKET_DATA_HOME = Path(
    "/home/gutua/software-factory/.control/market-aligner-recovery-20260820/live-data"
)
PRODUCTION_MARKET_REPOSITORY_ROOT = Path(
    "/home/gutua/software-factory/projects/market-aligner-integration-20260820"
)
PRODUCTION_COLLECTION_CONFIG_PATH = (
    PRODUCTION_MARKET_REPOSITORY_ROOT / "internal/jaa/skeleton/config.overnight.yaml"
)
PRODUCTION_COLLECTION_CONFIG_SHA256 = (
    "8868d381087729776e6eb5b689520fc74bf2239b59ccc94854b8feff8b627698"
)
PRODUCTION_COLLECTION_CONFIG_FILE_SHA256 = (
    "ad6c247fbbb48a6e22d8f18fff3a1aed37f2f1da6099973a29c90c08cced7bf4"
)
PRODUCTION_MARKET_OUTBOX_ROOT = Path(
    "/home/gutua/software-factory/protected/majaa-20260810/market-handoff"
)
PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT = PRODUCTION_MARKET_OUTBOX_ROOT / "receipts"
PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY = "state/public-employer-research-v2"
_DEPLOYMENT_SCHEMA = "jaa.production-market-handoff-deployment.v1"
_MAX_CONFIG_BYTES = 8192
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COLLECTION_CONFIG_RELATIVE_PATH = Path(
    "internal/jaa/skeleton/config.overnight.yaml"
)


class ProductionHandoffDeploymentError(ValueError):
    """The installed production deployment authority is absent or differs."""


def _expected_deployment_document(
    *,
    data_home: str | Path = PRODUCTION_MARKET_DATA_HOME,
    repository_root: str | Path = PRODUCTION_MARKET_REPOSITORY_ROOT,
    output_root: str | Path = PRODUCTION_MARKET_OUTBOX_ROOT,
    candidate_authority_path: str | Path | None = None,
    candidate_authority_sha256: str = PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
) -> dict[str, str]:
    repository = Path(repository_root)
    candidate = Path(
        production_handoff.PRODUCTION_CANDIDATE_AUTHORITY_PATH
        if candidate_authority_path is None
        else candidate_authority_path
    )
    return {
        "candidate_authority_path": str(candidate),
        "candidate_authority_sha256": candidate_authority_sha256,
        "collection_config_path": str(repository / _COLLECTION_CONFIG_RELATIVE_PATH),
        "collection_config_sha256": PRODUCTION_COLLECTION_CONFIG_SHA256,
        "collection_config_file_sha256": PRODUCTION_COLLECTION_CONFIG_FILE_SHA256,
        "data_home": str(Path(data_home)),
        "output_root": str(Path(output_root)),
        "repository_root": str(repository),
        "research_archive_root_identity": PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY,
        "schema_version": _DEPLOYMENT_SCHEMA,
        "trust_root_id": production_handoff.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    }


def _normalized_absolute_path(document: dict[str, object], key: str) -> Path:
    value = document.get(key)
    if type(value) is not str:
        raise ProductionHandoffDeploymentError(
            f"deployment configuration {key} is invalid"
        )
    path = Path(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or str(path) != value
        or path == Path("/")
    ):
        raise ProductionHandoffDeploymentError(
            f"deployment configuration {key} is not a normalized absolute path"
        )
    return path


def _validate_deployment_document(document: object) -> dict[str, object]:
    expected_keys = set(_expected_deployment_document())
    if type(document) is not dict:
        raise ProductionHandoffDeploymentError(
            "deployment configuration keys differ from the supported schema"
        )
    if set(document) != expected_keys:
        raise ProductionHandoffDeploymentError(
            "deployment configuration keys differ from the supported schema"
        )
    if (
        document["schema_version"] != _DEPLOYMENT_SCHEMA
        or document["trust_root_id"]
        != production_handoff.PRODUCTION_HANDOFF_TRUST_ROOT_ID
        or document["research_archive_root_identity"]
        != PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY
        or document["collection_config_sha256"]
        != PRODUCTION_COLLECTION_CONFIG_SHA256
        or document["collection_config_file_sha256"]
        != PRODUCTION_COLLECTION_CONFIG_FILE_SHA256
    ):
        raise ProductionHandoffDeploymentError(
            "deployment configuration trust or code identity differs"
        )
    for key in ("candidate_authority_sha256",):
        if type(document[key]) is not str or not _SHA256.fullmatch(document[key]):
            raise ProductionHandoffDeploymentError(
                f"deployment configuration {key} is invalid"
            )
    data_home = _normalized_absolute_path(document, "data_home")
    repository_root = _normalized_absolute_path(document, "repository_root")
    output_root = _normalized_absolute_path(document, "output_root")
    candidate_authority = _normalized_absolute_path(
        document, "candidate_authority_path"
    )
    collection_config = _normalized_absolute_path(
        document, "collection_config_path"
    )
    if collection_config != repository_root / _COLLECTION_CONFIG_RELATIVE_PATH:
        raise ProductionHandoffDeploymentError(
            "collection configuration path does not belong to the deployed repository"
        )
    if (
        candidate_authority == repository_root
        or repository_root in candidate_authority.parents
        or data_home == repository_root
        or repository_root in data_home.parents
        or data_home in repository_root.parents
        or output_root == repository_root
        or repository_root in output_root.parents
        or output_root in repository_root.parents
        or output_root in candidate_authority.parents
        or output_root == data_home
        or data_home in output_root.parents
        or output_root in data_home.parents
    ):
        raise ProductionHandoffDeploymentError(
            "production data, repository, output and candidate authority roots overlap"
        )
    return document


def production_handoff_deployment_configuration_bytes(
    *,
    data_home: str | Path | None = None,
    repository_root: str | Path | None = None,
    output_root: str | Path | None = None,
    candidate_authority_path: str | Path | None = None,
    candidate_authority_sha256: str | None = None,
) -> bytes:
    """Return canonical deployment bytes for one explicitly provisioned host."""
    values = (
        data_home,
        repository_root,
        output_root,
        candidate_authority_path,
        candidate_authority_sha256,
    )
    if any(value is not None for value in values) and not all(
        value is not None for value in values
    ):
        raise ProductionHandoffDeploymentError(
            "host deployment requires all five host-specific authority values"
        )
    if not any(value is not None for value in values):
        data_home = PRODUCTION_MARKET_DATA_HOME
        repository_root = PRODUCTION_MARKET_REPOSITORY_ROOT
        output_root = PRODUCTION_MARKET_OUTBOX_ROOT
        candidate_authority_path = production_handoff.PRODUCTION_CANDIDATE_AUTHORITY_PATH
        candidate_authority_sha256 = PRODUCTION_CANDIDATE_AUTHORITY_SHA256
    document = _expected_deployment_document(
        data_home=data_home,
        repository_root=repository_root,
        output_root=output_root,
        candidate_authority_path=candidate_authority_path,
        candidate_authority_sha256=candidate_authority_sha256,
    )
    _validate_deployment_document(document)
    return canonical_json_bytes(document)


def _parse_deployment_configuration(raw: bytes) -> str:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionHandoffDeploymentError(
            "deployment configuration is invalid JSON"
        ) from exc
    try:
        validated = _validate_deployment_document(document)
    except ProductionHandoffDeploymentError:
        raise
    if canonical_json_bytes(validated) != raw:
        raise ProductionHandoffDeploymentError(
            "deployment configuration is not canonical JSON"
        )
    return hashlib.sha256(raw).hexdigest()


def _read_root_owned_configuration(path: Path) -> bytes:
    if not path.is_absolute() or ".." in path.parts:
        raise ProductionHandoffDeploymentError(
            "deployment configuration path is invalid"
        )
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parent.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            metadata = os.fstat(next_descriptor)
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
                os.close(next_descriptor)
                raise ProductionHandoffDeploymentError(
                    "deployment configuration directory is not root-owned and protected"
                )
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
        try:
            metadata = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise ProductionHandoffDeploymentError(
                    "deployment configuration is not a protected root-owned regular file"
                )
            raw = os.read(file_descriptor, _MAX_CONFIG_BYTES + 1)
            if not raw or len(raw) > _MAX_CONFIG_BYTES:
                raise ProductionHandoffDeploymentError(
                    "deployment configuration size is invalid"
                )
            return raw
        finally:
            os.close(file_descriptor)
    except OSError as exc:
        raise ProductionHandoffDeploymentError(
            "deployment configuration cannot be opened without following links"
        ) from exc
    finally:
        os.close(descriptor)


def installed_production_handoff_deployment() -> _ProductionHandoffDeployment:
    """Load the protected, root-owned live Market state and output authority."""

    raw = _read_root_owned_configuration(PRODUCTION_HANDOFF_DEPLOYMENT_CONFIG_PATH)
    configuration_sha256 = _parse_deployment_configuration(raw)
    document = json.loads(raw)
    _validate_deployment_document(document)
    data_home = Path(document["data_home"])
    repository_root = Path(document["repository_root"])
    output_root = Path(document["output_root"])
    collection_config_path = Path(document["collection_config_path"])
    candidate_authority_path = Path(document["candidate_authority_path"])
    executing_repository = Path(__file__).resolve().parents[3]
    if executing_repository != repository_root:
        raise ProductionHandoffDeploymentError(
            "executing repository differs from the installed production repository"
        )
    return _ProductionHandoffDeployment(
        data_home=data_home,
        repository_root=repository_root,
        output_root=output_root,
        collection_config_path=collection_config_path,
        collection_config_sha256=str(document["collection_config_sha256"]),
        collection_config_file_sha256=str(
            document["collection_config_file_sha256"]
        ),
        deployment_configuration_sha256=configuration_sha256,
        research_archive_root_identity=str(document["research_archive_root_identity"]),
        candidate_authority_path=candidate_authority_path,
        candidate_authority_sha256=str(document["candidate_authority_sha256"]),
    )


def _validate_deployment_roots(deployment: _ProductionHandoffDeployment) -> None:
    """Reject link substitution or permission drift before time/state access."""

    for label, path, private in (
        ("data home", deployment.data_home, True),
        ("repository", deployment.repository_root, False),
        ("candidate authority parent", deployment.candidate_authority_path.parent, True),
    ):
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ProductionHandoffDeploymentError(
                f"production {label} is unavailable"
            ) from exc
        if (
            path.is_symlink()
            or resolved != path
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & (0o077 if private else 0o022)
        ):
            raise ProductionHandoffDeploymentError(
                f"production {label} identity or permissions differ"
            )
    output = deployment.output_root
    parent = output.parent
    try:
        parent_metadata = parent.lstat()
        parent_resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise ProductionHandoffDeploymentError(
            "production outbox parent is unavailable"
        ) from exc
    if (
        parent.is_symlink()
        or parent_resolved != parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise ProductionHandoffDeploymentError(
            "production outbox parent identity or permissions differ"
        )
    try:
        output_metadata = output.lstat()
    except FileNotFoundError:
        return
    if (
        output.is_symlink()
        or not stat.S_ISDIR(output_metadata.st_mode)
        or output_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(output_metadata.st_mode) & 0o077
    ):
        raise ProductionHandoffDeploymentError(
            "production outbox identity or permissions differ"
        )


def run_production_handoff(
    *,
    profile_id: str,
    track: str,
    source_job_key: str,
) -> ProductionHandoffReceipt:
    """Build a preparation handoff using authenticated production time."""

    deployment = installed_production_handoff_deployment()
    _validate_deployment_roots(deployment)
    subject = {
        "candidate_authority_sha256": deployment.candidate_authority_sha256,
        "collection_config_path": str(deployment.collection_config_path),
        "collection_config_sha256": deployment.collection_config_sha256,
        "collection_config_file_sha256": deployment.collection_config_file_sha256,
        "data_home": str(deployment.data_home.absolute()),
        "deployment_configuration_sha256": deployment.deployment_configuration_sha256,
        "execution_receipt_root": str(deployment.output_root / "receipts"),
        "output_root": str(deployment.output_root.absolute()),
        "profile_id": profile_id,
        "repository_root": str(deployment.repository_root.absolute()),
        "schema_version": "jaa.production-handoff-freshness-subject.v1",
        "source_job_key": source_job_key,
        "track": track,
    }
    subject_sha256 = hashlib.sha256(canonical_json_bytes(subject)).hexdigest()
    evidence = obtain_current_time(
        installed_production_current_time_witness(),
        environment="production",
        purpose="production_handoff_freshness",
        subject_sha256=subject_sha256,
        maximum_clock_skew_seconds=300,
    )
    evaluated_at = datetime.fromisoformat(
        evidence.evaluated_at[:-1] + "+00:00"
        if evidence.evaluated_at.endswith("Z")
        else evidence.evaluated_at
    ).astimezone(timezone.utc)
    return _build_production_handoff_from_authenticated_time(
        deployment=deployment,
        profile_id=profile_id,
        track=track,
        source_job_key=source_job_key,
        freshness_time=evaluated_at,
    )


__all__ = [
    "PRODUCTION_COLLECTION_CONFIG_FILE_SHA256",
    "PRODUCTION_COLLECTION_CONFIG_PATH",
    "PRODUCTION_COLLECTION_CONFIG_SHA256",
    "PRODUCTION_HANDOFF_DEPLOYMENT_CONFIG_PATH",
    "PRODUCTION_MARKET_DATA_HOME",
    "PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT",
    "PRODUCTION_MARKET_OUTBOX_ROOT",
    "PRODUCTION_MARKET_REPOSITORY_ROOT",
    "PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY",
    "ProductionHandoffDeploymentError",
    "installed_production_handoff_deployment",
    "production_handoff_deployment_configuration_bytes",
    "run_production_handoff",
]
