"""Authenticated production-time entrypoint for deterministic Market handoffs.

This is the only production-facing constructor. It obtains current time from
the installed deployment-owned witness and passes that instant to the internal
deterministic builder only for freshness evaluation. It issues no release token
and grants no submission authority.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

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
_DEPLOYMENT_SCHEMA_V2 = "jaa.production-market-handoff-deployment.v2"
_CURRENT_RUNTIME_DEPLOYMENT_SCHEMA = (
    "market-aligner.current-runtime-handoff-deployment.v1"
)
_CURRENT_RUNTIME_TRUST_ROOT_ID = "market-aligner-current-runtime-non-release-v1"
_MAX_CONFIG_BYTES = 8192
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COLLECTION_CONFIG_RELATIVE_PATH = Path(
    "internal/jaa/skeleton/config.overnight.yaml"
)


class ProductionHandoffDeploymentError(ValueError):
    """The installed production deployment authority is absent or differs."""


def _validate_runtime_route_path(name: str, value: object) -> None:
    if type(value) is not str:
        raise ValueError(f"{name} must be a plain str")
    if not value or value != value.strip():
        raise ValueError(f"{name} must be nonempty and stripped")
    path = PurePosixPath(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be absolute")
    if ".." in path.parts:
        raise ValueError(f"{name} must not contain a '..' component")


def select_runtime_deployment(
    *,
    config_path: str | None = None,
    config_sha256: str | None = None,
    private_root: str | None = None,
    legacy_loader,
    current_loader,
) -> tuple[bool, object]:
    if not callable(legacy_loader) or not callable(current_loader):
        raise ValueError("runtime route options differ")
    present = (
        config_path is not None,
        config_sha256 is not None,
        private_root is not None,
    )
    if all(present):
        if type(config_sha256) is not str or _SHA256.fullmatch(config_sha256) is None:
            raise ValueError("config_sha256 must be 64 lowercase ASCII hex chars")
        _validate_runtime_route_path("config_path", config_path)
        _validate_runtime_route_path("private_root", private_root)
        result = current_loader(
            configuration_path=config_path,
            configuration_sha256=config_sha256,
            private_root=private_root,
        )
        return True, result
    if not any(present):
        return False, legacy_loader()
    raise ValueError("current runtime opt-in requires config path, raw hash and private root")


def decode_bound_json(
    raw: bytes, expected_sha256: str, max_bytes: int = _MAX_CONFIG_BYTES
) -> dict[str, object]:
    """Decode one size-bounded JSON object only after verifying its raw hash."""
    try:
        if type(raw) is not bytes:
            raise ValueError
        if type(expected_sha256) is not str or not _SHA256.fullmatch(expected_sha256):
            raise ValueError
        if type(max_bytes) is not int or not 1 <= max_bytes <= 1_048_576:
            raise ValueError
        if not 0 < len(raw) <= max_bytes:
            raise ValueError
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ValueError
        text = raw.decode("utf-8", "strict")

        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        def finite_float(value: str) -> float:
            result = float(value)
            if not math.isfinite(result):
                raise ValueError
            return result

        def reject_constant(_value: str) -> object:
            raise ValueError

        document = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_float=finite_float,
            parse_constant=reject_constant,
        )
        if type(document) is not dict:
            raise ValueError
        return document
    except Exception:
        raise ValueError("private_runtime_config_invalid") from None


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


def _validate_deployment_document(
    document: object,
    *,
    current_runtime_root: Path | None = None,
) -> dict[str, object]:
    expected_keys = set(_expected_deployment_document())
    if type(document) is not dict:
        raise ProductionHandoffDeploymentError(
            "deployment configuration keys differ from the supported schema"
        )
    if set(document) != expected_keys:
        raise ProductionHandoffDeploymentError(
            "deployment configuration keys differ from the supported schema"
        )
    schema_version = document["schema_version"]
    is_current_runtime = schema_version == _CURRENT_RUNTIME_DEPLOYMENT_SCHEMA
    expected_trust_root = (
        _CURRENT_RUNTIME_TRUST_ROOT_ID
        if is_current_runtime
        else production_handoff.PRODUCTION_HANDOFF_TRUST_ROOT_ID
    )
    if (
        type(schema_version) is not str
        or (is_current_runtime and current_runtime_root is None)
        or (current_runtime_root is not None and not is_current_runtime)
        or (
            not is_current_runtime
            and schema_version not in {_DEPLOYMENT_SCHEMA, _DEPLOYMENT_SCHEMA_V2}
        )
        or document["trust_root_id"] != expected_trust_root
        or document["research_archive_root_identity"]
        != PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY
    ):
        raise ProductionHandoffDeploymentError(
            "deployment configuration trust or code identity differs"
        )
    for key in (
        "candidate_authority_sha256",
        "collection_config_sha256",
        "collection_config_file_sha256",
    ):
        if type(document[key]) is not str or not _SHA256.fullmatch(document[key]):
            raise ProductionHandoffDeploymentError(
                f"deployment configuration {key} is invalid"
            )
    if schema_version == _DEPLOYMENT_SCHEMA and (
        document["collection_config_sha256"]
        != PRODUCTION_COLLECTION_CONFIG_SHA256
        or document["collection_config_file_sha256"]
        != PRODUCTION_COLLECTION_CONFIG_FILE_SHA256
    ):
        raise ProductionHandoffDeploymentError(
            "deployment configuration trust or code identity differs"
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
    if is_current_runtime and (
        current_runtime_root is None
        or data_home != current_runtime_root
        or str(document["collection_config_path"]).startswith("//")
    ):
        raise ProductionHandoffDeploymentError(
            "current runtime configuration path or private root differs"
        )
    if schema_version == _DEPLOYMENT_SCHEMA_V2 and str(
        document["collection_config_path"]
    ).startswith("//"):
        raise ProductionHandoffDeploymentError(
            "deployment configuration collection_config_path is not a normalized absolute path"
        )
    if schema_version == _DEPLOYMENT_SCHEMA and (
        collection_config != repository_root / _COLLECTION_CONFIG_RELATIVE_PATH
    ):
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
    collection_config_path: str | Path | None = None,
    collection_config_sha256: str | None = None,
    collection_config_file_sha256: str | None = None,
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
    collection_values = (
        collection_config_path,
        collection_config_sha256,
        collection_config_file_sha256,
    )
    if any(value is not None for value in collection_values) and not all(
        value is not None for value in collection_values
    ):
        raise ProductionHandoffDeploymentError(
            "collection configuration requires its path and both hashes together"
        )
    if all(value is not None for value in collection_values) and not all(
        value is not None for value in values
    ):
        raise ProductionHandoffDeploymentError(
            "current collection configuration requires all five host-specific authority values"
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
    if all(value is not None for value in collection_values):
        if not isinstance(collection_config_path, (str, Path)):
            raise ProductionHandoffDeploymentError(
                "deployment configuration collection_config_path is invalid"
            )
        document.update(
            {
                "collection_config_path": str(collection_config_path),
                "collection_config_sha256": collection_config_sha256,
                "collection_config_file_sha256": collection_config_file_sha256,
                "schema_version": _DEPLOYMENT_SCHEMA_V2,
            }
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


def _current_runtime_path(value: str | Path, label: str) -> Path:
    if not isinstance(value, (str, Path)):
        raise ProductionHandoffDeploymentError(
            f"current runtime {label} is invalid"
        )
    raw = str(value)
    path = Path(raw)
    if (
        not path.is_absolute()
        or str(path).startswith("//")
        or ".." in path.parts
        or str(path) != raw
        or path == Path("/")
    ):
        raise ProductionHandoffDeploymentError(
            f"current runtime {label} is not a normalized absolute path"
        )
    return path


def _read_current_runtime_configuration(
    path_value: str | Path,
    private_root_value: str | Path,
    expected_sha256: str,
) -> bytes:
    path = _current_runtime_path(path_value, "configuration path")
    private_root = _current_runtime_path(private_root_value, "private root")
    if private_root not in path.parents:
        raise ProductionHandoffDeploymentError(
            "current runtime configuration must be beneath its private root"
        )
    if type(expected_sha256) is not str or not _SHA256.fullmatch(expected_sha256):
        raise ProductionHandoffDeploymentError(
            "current runtime configuration hash is invalid"
        )

    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        private_root_depth = len(private_root.parts) - 1
        for depth, component in enumerate(path.parent.parts[1:], start=1):
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                metadata = os.fstat(next_descriptor)
                mode = stat.S_IMODE(metadata.st_mode)
                if depth < private_root_depth:
                    valid_directory = (
                        metadata.st_uid in {0, os.geteuid()} and not mode & 0o022
                    )
                else:
                    valid_directory = (
                        metadata.st_uid == os.geteuid() and mode == 0o700
                    )
                if not stat.S_ISDIR(metadata.st_mode) or not valid_directory:
                    raise ProductionHandoffDeploymentError(
                        "current runtime configuration directory is not protected"
                    )
            except BaseException:
                try:
                    os.close(next_descriptor)
                except OSError:
                    pass
                raise
            os.close(descriptor)
            descriptor = next_descriptor

        file_descriptor = os.open(
            path.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=descriptor,
        )
        try:
            before = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > _MAX_CONFIG_BYTES
            ):
                raise ProductionHandoffDeploymentError(
                    "current runtime configuration file is not private"
                )
            chunks: list[bytes] = []
            remaining = _MAX_CONFIG_BYTES + 1
            while remaining:
                chunk = os.read(file_descriptor, min(4096, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(file_descriptor)
            before_state = (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            after_state = (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if (
                before_state != after_state
                or len(raw) != before.st_size
                or len(raw) > _MAX_CONFIG_BYTES
                or hashlib.sha256(raw).hexdigest() != expected_sha256
            ):
                raise ProductionHandoffDeploymentError(
                    "current runtime configuration binding differs"
                )
            return raw
        finally:
            os.close(file_descriptor)
    except OSError:
        raise ProductionHandoffDeploymentError(
            "current runtime configuration cannot be opened safely"
        ) from None
    finally:
        os.close(descriptor)


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


def installed_current_runtime_handoff_deployment(
    *,
    configuration_path: str | Path,
    configuration_sha256: str,
    private_root: str | Path,
) -> _ProductionHandoffDeployment:
    """Load one explicitly selected, private non-release deployment document."""
    root = _current_runtime_path(private_root, "private root")
    raw = _read_current_runtime_configuration(
        configuration_path, root, configuration_sha256
    )
    document = decode_bound_json(raw, configuration_sha256)
    validated = _validate_deployment_document(
        document, current_runtime_root=root
    )
    if canonical_json_bytes(validated) != raw:
        raise ProductionHandoffDeploymentError(
            "current runtime configuration is not canonical JSON"
        )
    repository_root = Path(str(validated["repository_root"]))
    executing_repository = Path(__file__).resolve().parents[3]
    if executing_repository != repository_root:
        raise ProductionHandoffDeploymentError(
            "executing repository differs from the current runtime repository"
        )
    return _ProductionHandoffDeployment(
        data_home=root,
        repository_root=repository_root,
        output_root=Path(str(validated["output_root"])),
        collection_config_path=Path(str(validated["collection_config_path"])),
        collection_config_sha256=str(validated["collection_config_sha256"]),
        collection_config_file_sha256=str(
            validated["collection_config_file_sha256"]
        ),
        deployment_configuration_sha256=configuration_sha256,
        research_archive_root_identity=str(
            validated["research_archive_root_identity"]
        ),
        candidate_authority_path=Path(str(validated["candidate_authority_path"])),
        candidate_authority_sha256=str(validated["candidate_authority_sha256"]),
        environment="current_runtime",
        trust_root_id=_CURRENT_RUNTIME_TRUST_ROOT_ID,
        freshness_provenance="local_system_utc",
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
    current_runtime_config_path: str | Path | None = None,
    current_runtime_config_sha256: str | None = None,
    current_runtime_private_root: str | Path | None = None,
    current_recovery_manifest_relative_path: str | None = None,
) -> ProductionHandoffReceipt:
    """Build the default production handoff or explicit non-release preparation."""
    if current_recovery_manifest_relative_path is not None and not all(
        value is not None
        for value in (
            current_runtime_config_path,
            current_runtime_config_sha256,
            current_runtime_private_root,
        )
    ):
        raise ProductionHandoffDeploymentError(
            "current recovery manifest locator requires current runtime opt-in"
        )
    config_path = (
        str(current_runtime_config_path)
        if isinstance(current_runtime_config_path, Path)
        else current_runtime_config_path
    )
    private_root = (
        str(current_runtime_private_root)
        if isinstance(current_runtime_private_root, Path)
        else current_runtime_private_root
    )
    current_runtime, deployment = select_runtime_deployment(
        config_path=config_path,
        config_sha256=current_runtime_config_sha256,
        private_root=private_root,
        legacy_loader=installed_production_handoff_deployment,
        current_loader=lambda **options: installed_current_runtime_handoff_deployment(
            configuration_path=Path(options["configuration_path"]),
            configuration_sha256=options["configuration_sha256"],
            private_root=Path(options["private_root"]),
        ),
    )
    _validate_deployment_roots(deployment)
    if current_runtime:
        evaluated_at = datetime.now(timezone.utc)
    else:
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
        current_recovery_manifest_relative_path=(
            current_recovery_manifest_relative_path
        ),
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
    "decode_bound_json",
    "installed_current_runtime_handoff_deployment",
    "installed_production_handoff_deployment",
    "production_handoff_deployment_configuration_bytes",
    "run_production_handoff",
]
