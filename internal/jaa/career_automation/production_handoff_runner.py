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
import stat
from datetime import datetime, timezone
from pathlib import Path

from market_aligner.applications.handoff import canonical_json_bytes
from market_aligner.applications import production_handoff
from market_aligner.applications.production_handoff import (
    PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
    ProductionHandoffReceipt,
    _ProductionHandoffDeployment,
    _build_production_handoff_from_authenticated_time,
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
PRODUCTION_MARKET_OUTBOX_ROOT = Path(
    "/home/gutua/software-factory/protected/majaa-20260810/market-handoff"
)
PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT = PRODUCTION_MARKET_OUTBOX_ROOT / "receipts"
PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY = "state/public-employer-research-v2"
_DEPLOYMENT_SCHEMA = "jaa.production-market-handoff-deployment.v1"
_MAX_CONFIG_BYTES = 8192


class ProductionHandoffDeploymentError(ValueError):
    """The installed production deployment authority is absent or differs."""


def _expected_deployment_document() -> dict[str, str]:
    return {
        "candidate_authority_path": str(production_handoff.PRODUCTION_CANDIDATE_AUTHORITY_PATH),
        "candidate_authority_sha256": PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
        "data_home": str(PRODUCTION_MARKET_DATA_HOME),
        "output_root": str(PRODUCTION_MARKET_OUTBOX_ROOT),
        "repository_root": str(PRODUCTION_MARKET_REPOSITORY_ROOT),
        "research_archive_root_identity": PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY,
        "schema_version": _DEPLOYMENT_SCHEMA,
        "trust_root_id": production_handoff.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    }


def _parse_deployment_configuration(raw: bytes) -> str:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionHandoffDeploymentError("deployment configuration is invalid JSON") from exc
    expected = _expected_deployment_document()
    if (
        type(document) is not dict
        or document != expected
        or canonical_json_bytes(document) != raw
    ):
        raise ProductionHandoffDeploymentError(
            "deployment configuration differs from the compiled canonical roots"
        )
    return hashlib.sha256(raw).hexdigest()


def _read_root_owned_configuration(path: Path) -> bytes:
    if not path.is_absolute() or ".." in path.parts:
        raise ProductionHandoffDeploymentError("deployment configuration path is invalid")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parent.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
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
    """Load the compiled, root-owned live Market state and output authority."""

    raw = _read_root_owned_configuration(PRODUCTION_HANDOFF_DEPLOYMENT_CONFIG_PATH)
    configuration_sha256 = _parse_deployment_configuration(raw)
    executing_repository = Path(__file__).resolve().parents[3]
    if executing_repository != PRODUCTION_MARKET_REPOSITORY_ROOT:
        raise ProductionHandoffDeploymentError(
            "executing repository differs from the compiled production repository"
        )
    return _ProductionHandoffDeployment(
        data_home=PRODUCTION_MARKET_DATA_HOME,
        repository_root=PRODUCTION_MARKET_REPOSITORY_ROOT,
        output_root=PRODUCTION_MARKET_OUTBOX_ROOT,
        deployment_configuration_sha256=configuration_sha256,
        research_archive_root_identity=PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY,
    )


def _validate_deployment_roots(deployment: _ProductionHandoffDeployment) -> None:
    """Reject link substitution or permission drift before time/state access."""

    for label, path, private in (
        ("data home", deployment.data_home, True),
        ("repository", deployment.repository_root, False),
    ):
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ProductionHandoffDeploymentError(f"production {label} is unavailable") from exc
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
        raise ProductionHandoffDeploymentError("production outbox parent is unavailable") from exc
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
        "candidate_authority_sha256": PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
        "data_home": str(deployment.data_home.absolute()),
        "deployment_configuration_sha256": deployment.deployment_configuration_sha256,
        "execution_receipt_root": str(PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT),
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
    "PRODUCTION_HANDOFF_DEPLOYMENT_CONFIG_PATH",
    "PRODUCTION_MARKET_DATA_HOME",
    "PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT",
    "PRODUCTION_MARKET_OUTBOX_ROOT",
    "PRODUCTION_MARKET_REPOSITORY_ROOT",
    "PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY",
    "ProductionHandoffDeploymentError",
    "installed_production_handoff_deployment",
    "run_production_handoff",
]
