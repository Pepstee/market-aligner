"""Primary frozen-fixture replay-pair evidence for bounded JAA-10 metrics.

This module validates and records two already-produced typed localhost fixture
observations.  It cannot drive a browser, contact a network, issue a release,
or submit an application.  Runtime execution remains a separately gated act.
"""

from __future__ import annotations

import copy
import hashlib
import os
import platform
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping

import tracked_source_revision as _source_revision
from career_automation.hard_metrics_evaluation import (
    _domain_hash,
    _publish_canonical_receipt,
)
from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    HARD_QUALITY_TARGETS,
    ShadowObservation,
)


REPLAY_OBSERVATION_SCHEMA_VERSION = "jaa10.frozen-replay-observation.v1"
REPLAY_PAIR_SCHEMA_VERSION = "jaa10.frozen-replay-pair.v1"
STABLE_PROJECTION_VERSION = "jaa10.replay-stable-projection.v1"
REPLAY_EEI_VERSION = "jaa10.replay-eei.v1"

REPLAY_OBSERVATION_DOMAIN = b"jaa10-frozen-replay-observation-v1\0"
REPLAY_PAIR_DOMAIN = b"jaa10-frozen-replay-pair-v1\0"
STABLE_PROJECTION_DOMAIN = b"jaa10-replay-stable-projection-v1\0"
REPLAY_EEI_DOMAIN = b"jaa10-replay-eei-v1\0"

REPLAY_OBSERVATION_1_FILENAME = "replay-observation-1.json"
REPLAY_OBSERVATION_2_FILENAME = "replay-observation-2.json"
REPLAY_PAIR_FILENAME = "replay-pair.json"

_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_OBSERVATION_KEYS = frozenset(
    {
        "schema_version",
        "observation_id",
        "observed_at",
        "evidence_kind",
        "execution_claim",
        "run_id",
        "step_id",
        "workflow_sha256",
        "durable_workflow_sha256",
        "release_manifest_sha256",
        "receipt_id",
        "receipt_payload_sha256",
        "field_map_sha256",
        "screenshot_sha256",
        "submit_event_sha256",
        "normalized_submit_event_sha256",
        "submission_proof",
        "fixture_receipt",
        "action_elapsed_ms",
        "browser_launch_count",
        "database_bytes",
        "screenshot_bytes",
        "interruptions",
        "mutations",
        "model_version",
        "prompt_version",
        "model_cost_microusd",
    }
)
_STABLE_KEYS = (
    "schema_version",
    "evidence_kind",
    "execution_claim",
    "step_id",
    "workflow_sha256",
    "receipt_id",
    "receipt_payload_sha256",
    "field_map_sha256",
    "screenshot_sha256",
    "normalized_submit_event_sha256",
    "browser_launch_count",
    "interruptions",
    "mutations",
    "model_version",
    "prompt_version",
    "model_cost_microusd",
    "fixture_receipt",
)
_GOLDEN_FIELDS = (
    ("workflow_sha256", "workflow_sha256"),
    ("receipt_id", "receipt_id"),
    ("receipt_payload_sha256", "receipt_payload_sha256"),
    ("field_map_sha256", "field_map_sha256"),
    ("screenshot_sha256", "screenshot_sha256"),
    ("normalized_submit_event_sha256", "submit_event_sha256"),
)
_FORBIDDEN_ENVIRONMENT = (
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
)
_WITHHELD = MappingProxyType(
    {
        "evidence_class": "fixture_frozen",
        "objective_satisfied": False,
        "certifies_slice": False,
        "live_time_separated_execution": "not_collected",
        "production_certification": "withheld",
        "external_action_capability": False,
        "real_applications_submitted": 0,
    }
)


class FrozenReplayPairError(RuntimeError):
    """Base error for bounded frozen replay-pair evidence."""


class ReplayPairIntegrityError(FrozenReplayPairError):
    """Replay evidence, projection, or lineage is inconsistent."""


class ReplayExecutionEnvironmentError(FrozenReplayPairError):
    """The frozen source or replay execution environment is inadmissible."""


def _digest(value: object, label: str, *, length: int = 64) -> str:
    pattern = _HEX_64 if length == 64 else _HEX_40
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ReplayPairIntegrityError(f"{label} is invalid")
    return value


def _stable_projection_document(document: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(document, Mapping):
        raise TypeError("stable projection requires an observation document")
    copied = copy.deepcopy(dict(document))
    if (
        set(copied) != _OBSERVATION_KEYS
        or copied.get("schema_version") != "jaa10.shadow-observation.v2"
    ):
        raise ReplayPairIntegrityError(
            "shadow observation key inventory or schema differs"
        )
    return {key: copied[key] for key in _STABLE_KEYS}


def stable_projection(observation: ShadowObservation) -> dict[str, object]:
    """Return the exhaustive authority-defined stable output projection."""
    if not isinstance(observation, ShadowObservation):
        raise TypeError("stable projection requires a typed observation")
    observation.__post_init__()
    return _stable_projection_document(observation.document())


def stable_projection_sha256(observation: ShadowObservation) -> str:
    """Hash the stable projection with the frozen v1 domain."""
    return _domain_hash(
        STABLE_PROJECTION_DOMAIN,
        {
            "stable_projection_version": STABLE_PROJECTION_VERSION,
            "projection": stable_projection(observation),
        },
    )


def _mismatched_paths(first: object, second: object, prefix: str = "") -> tuple[str, ...]:
    if type(first) is not type(second):
        return (prefix or "$",)
    if isinstance(first, dict):
        left = set(first)
        right = set(second)  # type: ignore[arg-type]
        if left != right:
            return tuple(
                sorted(
                    f"{prefix}.{key}" if prefix else str(key)
                    for key in left ^ right
                )
            )
        paths: list[str] = []
        for key in sorted(left):
            child = f"{prefix}.{key}" if prefix else str(key)
            paths.extend(
                _mismatched_paths(first[key], second[key], child)  # type: ignore[index]
            )
        return tuple(paths)
    if isinstance(first, list):
        other = second  # type: ignore[assignment]
        if len(first) != len(other):
            return (f"{prefix}.length",)
        paths = []
        for index, value in enumerate(first):
            paths.extend(
                _mismatched_paths(value, other[index], f"{prefix}[{index}]")
            )
        return tuple(paths)
    return () if first == second else (prefix or "$",)


def _repository_root() -> Path:
    root = Path(__file__).resolve(strict=True).parents[1]
    if not (root / "canonical-repository.json").is_file():
        raise ReplayExecutionEnvironmentError(
            "canonical repository root is unavailable"
        )
    return root


def _git(root: Path, *arguments: str) -> bytes:
    try:
        return _source_revision._git(root, *arguments)  # type: ignore[attr-defined]
    except _source_revision.TrackedSourceRevisionError as exc:
        raise ReplayExecutionEnvironmentError(
            "frozen replay Git identity is unavailable"
        ) from exc


def _capture_replay_execution_identity() -> dict[str, str]:
    root = _repository_root()
    revision = _source_revision.source_git_revision(root)
    content_revision = _source_revision.source_content_revision(root)
    tree = _git(root, "rev-parse", "--verify", f"{revision}^{{tree}}").strip()
    branch = _git(root, "branch", "--show-current").strip()
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if branch or status:
        raise ReplayExecutionEnvironmentError(
            "replay source must be a clean detached worktree"
        )
    identity = {
        "source_git_revision": revision,
        "source_tree": tree.decode("ascii", errors="strict"),
        "source_content_revision": content_revision,
    }
    _digest(identity["source_git_revision"], "source Git revision", length=40)
    _digest(identity["source_tree"], "source tree", length=40)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", content_revision):
        raise ReplayExecutionEnvironmentError(
            "source-content revision is invalid"
        )
    return identity


def _inventory_regular_tree(root: Path) -> tuple[list[dict[str, object]], str]:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ReplayExecutionEnvironmentError(
            "Playwright browser root is unavailable"
        ) from exc
    if not resolved.is_dir() or root.is_symlink():
        raise ReplayExecutionEnvironmentError(
            "Playwright browser root is not a real directory"
        )
    entries: list[dict[str, object]] = []
    for candidate in sorted(resolved.rglob("*"), key=lambda item: item.as_posix()):
        relative = candidate.relative_to(resolved)
        if any(part in {"", ".", ".."} for part in PurePosixPath(relative.as_posix()).parts):
            raise ReplayExecutionEnvironmentError("browser inventory path is unsafe")
        metadata_before = candidate.lstat()
        if stat.S_ISDIR(metadata_before.st_mode):
            continue
        if not stat.S_ISREG(metadata_before.st_mode) or candidate.is_symlink():
            raise ReplayExecutionEnvironmentError(
                "browser inventory contains a non-regular entry"
            )
        payload = candidate.read_bytes()
        metadata_after = candidate.lstat()
        identity_before = (
            metadata_before.st_dev,
            metadata_before.st_ino,
            metadata_before.st_mode,
            metadata_before.st_size,
            metadata_before.st_mtime_ns,
        )
        identity_after = (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_mode,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise ReplayExecutionEnvironmentError(
                "browser inventory changed during capture"
            )
        entries.append(
            {
                "relative_path": relative.as_posix(),
                "mode": stat.S_IMODE(metadata_before.st_mode),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if not entries:
        raise ReplayExecutionEnvironmentError("browser inventory is empty")
    inventory_sha256 = _domain_hash(
        REPLAY_EEI_DOMAIN,
        {"kind": "playwright-browser-inventory", "files": entries},
    )
    return entries, inventory_sha256


def _capture_replay_eei(identity: Mapping[str, str]) -> str:
    if os.environ.get("PYTHONDONTWRITEBYTECODE") != "1" or not sys.dont_write_bytecode:
        raise ReplayExecutionEnvironmentError(
            "bytecode writes are not disabled"
        )
    forbidden = [name for name in _FORBIDDEN_ENVIRONMENT if name in os.environ]
    if forbidden:
        raise ReplayExecutionEnvironmentError(
            "forbidden replay environment variable is present"
        )
    cache_value = os.environ.get("PYTHONPYCACHEPREFIX")
    if not cache_value or sys.pycache_prefix != cache_value:
        raise ReplayExecutionEnvironmentError(
            "fresh Python cache prefix is not in effect"
        )
    cache_root = Path(cache_value)
    try:
        cache_resolved = cache_root.resolve(strict=True)
    except OSError as exc:
        raise ReplayExecutionEnvironmentError(
            "Python cache prefix is unavailable"
        ) from exc
    if (
        not cache_resolved.is_dir()
        or cache_root.is_symlink()
        or any(cache_resolved.iterdir())
    ):
        raise ReplayExecutionEnvironmentError(
            "Python cache prefix is not a fresh empty directory"
        )
    preload = Path("/etc/ld.so.preload")
    if preload.exists() and preload.stat().st_size != 0:
        raise ReplayExecutionEnvironmentError(
            "dynamic-loader preload configuration is active"
        )
    executable = Path(sys.executable).resolve(strict=True)
    executable_metadata = executable.stat()
    if not stat.S_ISREG(executable_metadata.st_mode):
        raise ReplayExecutionEnvironmentError(
            "Python executable is not a regular file"
        )
    browser_value = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    browser_root = (
        Path(browser_value)
        if browser_value
        else Path.home() / ".cache" / "ms-playwright"
    )
    browser_entries, browser_inventory_sha256 = _inventory_regular_tree(
        browser_root
    )
    document = {
        "schema_version": REPLAY_EEI_VERSION,
        "source_identity": dict(identity),
        "python_executable": {
            "resolved_path": str(executable),
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        },
        "python_version": sys.version,
        "platform_triple": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "playwright_browser": {
            "resolved_root": str(browser_root.resolve(strict=True)),
            "file_count": len(browser_entries),
            "inventory_sha256": browser_inventory_sha256,
        },
        "environment_controls": {
            "python_dont_write_bytecode": True,
            "python_pycache_prefix": str(cache_resolved),
            "forbidden_environment_absent": list(_FORBIDDEN_ENVIRONMENT),
            "ld_so_preload_absent_or_empty": True,
        },
    }
    return _domain_hash(REPLAY_EEI_DOMAIN, document)


def _golden_set_check(observation: ShadowObservation) -> None:
    observation.__post_init__()
    for observation_field, contract_field in _GOLDEN_FIELDS:
        if getattr(observation, observation_field) != getattr(
            FROZEN_SHADOW_CONTRACT,
            contract_field,
        ):
            raise ReplayPairIntegrityError(
                "shadow observation golden-set field differs: "
                f"{observation_field}"
            )


def _observation_receipt(
    observation: ShadowObservation,
    identity: Mapping[str, str],
    eei_sha256: str,
) -> dict[str, object]:
    core: dict[str, object] = {
        "schema_version": REPLAY_OBSERVATION_SCHEMA_VERSION,
        "observation": observation.document(),
        "observation_sha256": observation.observation_sha256,
        "replay_execution_identity": dict(identity),
        "execution_environment_sha256": eei_sha256,
        **dict(_WITHHELD),
    }
    return {
        **core,
        "receipt_sha256": _domain_hash(REPLAY_OBSERVATION_DOMAIN, core),
    }


@dataclass(frozen=True, init=False)
class FrozenReplayPair:
    replay_execution_identity: Mapping[str, str]
    execution_environment_sha256: str
    observation_1: ShadowObservation
    observation_2: ShadowObservation
    observation_1_sha256: str
    observation_2_sha256: str
    stable_field_hash_1: str
    stable_field_hash_2: str
    mismatched_stable_fields: tuple[str, ...]
    mismatch_count: int
    receipt_sha256: str

    def __init__(self) -> None:
        raise TypeError("frozen replay pairs require the verified recorder")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": REPLAY_PAIR_SCHEMA_VERSION,
            "contract_sha256": FROZEN_SHADOW_CONTRACT.contract_sha256,
            "replay_execution_identity": dict(self.replay_execution_identity),
            "execution_environment_sha256": self.execution_environment_sha256,
            "observation_1": self.observation_1.document(),
            "observation_2": self.observation_2.document(),
            "observation_1_sha256": self.observation_1_sha256,
            "observation_2_sha256": self.observation_2_sha256,
            "stable_projection_version": STABLE_PROJECTION_VERSION,
            "stable_field_hash_1": self.stable_field_hash_1,
            "stable_field_hash_2": self.stable_field_hash_2,
            "mismatched_stable_fields": list(self.mismatched_stable_fields),
            "mismatch_count": self.mismatch_count,
            "time_authenticated": False,
            **dict(_WITHHELD),
        }
        if include_hash:
            document["receipt_sha256"] = self.receipt_sha256
        return document

    def verify(self) -> None:
        identity = dict(self.replay_execution_identity)
        if set(identity) != {
            "source_git_revision",
            "source_tree",
            "source_content_revision",
        }:
            raise ReplayPairIntegrityError(
                "replay execution identity shape differs"
            )
        _digest(identity["source_git_revision"], "source Git revision", length=40)
        _digest(identity["source_tree"], "source tree", length=40)
        if not re.fullmatch(
            r"sha256:[0-9a-f]{64}", identity["source_content_revision"]
        ):
            raise ReplayPairIntegrityError("source-content revision differs")
        _digest(self.execution_environment_sha256, "replay EEI hash")
        for observation in (self.observation_1, self.observation_2):
            if not isinstance(observation, ShadowObservation):
                raise TypeError("replay pair requires typed observations")
            _golden_set_check(observation)
        if (
            self.observation_1.observation_id
            == self.observation_2.observation_id
            or self.observation_1.release_manifest_sha256
            == self.observation_2.release_manifest_sha256
        ):
            raise ReplayPairIntegrityError(
                "replay observations are not distinct executions"
            )
        expected_observation_hashes = (
            self.observation_1.observation_sha256,
            self.observation_2.observation_sha256,
        )
        if (
            self.observation_1_sha256,
            self.observation_2_sha256,
        ) != expected_observation_hashes:
            raise ReplayPairIntegrityError(
                "replay observation binding differs"
            )
        projections = (
            stable_projection(self.observation_1),
            stable_projection(self.observation_2),
        )
        stable_hashes = (
            stable_projection_sha256(self.observation_1),
            stable_projection_sha256(self.observation_2),
        )
        mismatches = tuple(
            sorted(set(_mismatched_paths(projections[0], projections[1])))
        )
        mismatch_count = 0 if stable_hashes[0] == stable_hashes[1] else 1
        if (
            (self.stable_field_hash_1, self.stable_field_hash_2)
            != stable_hashes
            or self.mismatched_stable_fields != mismatches
            or self.mismatch_count != mismatch_count
            or bool(mismatches) != bool(mismatch_count)
        ):
            raise ReplayPairIntegrityError(
                "replay stable-field derivation differs"
            )
        expected_receipt = _domain_hash(
            REPLAY_PAIR_DOMAIN,
            self.document(include_hash=False),
        )
        if self.receipt_sha256 != expected_receipt:
            raise ReplayPairIntegrityError("replay pair receipt hash differs")


def _build_pair(
    first: ShadowObservation,
    second: ShadowObservation,
    identity: Mapping[str, str],
    eei_sha256: str,
) -> FrozenReplayPair:
    projections = (stable_projection(first), stable_projection(second))
    stable_hashes = (
        stable_projection_sha256(first),
        stable_projection_sha256(second),
    )
    mismatches = tuple(
        sorted(set(_mismatched_paths(projections[0], projections[1])))
    )
    pair = object.__new__(FrozenReplayPair)
    values = {
        "replay_execution_identity": MappingProxyType(dict(identity)),
        "execution_environment_sha256": eei_sha256,
        "observation_1": first,
        "observation_2": second,
        "observation_1_sha256": first.observation_sha256,
        "observation_2_sha256": second.observation_sha256,
        "stable_field_hash_1": stable_hashes[0],
        "stable_field_hash_2": stable_hashes[1],
        "mismatched_stable_fields": mismatches,
        "mismatch_count": 0 if stable_hashes[0] == stable_hashes[1] else 1,
        "receipt_sha256": "",
    }
    for name, value in values.items():
        object.__setattr__(pair, name, value)
    object.__setattr__(
        pair,
        "receipt_sha256",
        _domain_hash(REPLAY_PAIR_DOMAIN, pair.document(include_hash=False)),
    )
    pair.verify()
    return pair


def _validated_destination(destination_directory: Path) -> Path:
    if not isinstance(destination_directory, Path):
        raise TypeError("replay destination directory must be a Path")
    if destination_directory.is_symlink():
        raise ReplayPairIntegrityError(
            "replay destination directory cannot be a symlink"
        )
    try:
        destination = destination_directory.resolve(strict=True)
    except OSError as exc:
        raise ReplayPairIntegrityError(
            "replay destination directory is unavailable"
        ) from exc
    if not destination.is_dir():
        raise ReplayPairIntegrityError(
            "replay destination is not a directory"
        )
    names = (
        REPLAY_OBSERVATION_1_FILENAME,
        REPLAY_OBSERVATION_2_FILENAME,
        REPLAY_PAIR_FILENAME,
    )
    if any((destination / name).exists() or (destination / name).is_symlink() for name in names):
        raise ReplayPairIntegrityError(
            "replay destination filenames must all be absent"
        )
    return destination


def record_frozen_replay_pair(
    first: ShadowObservation,
    second: ShadowObservation,
    *,
    destination_directory: Path,
) -> FrozenReplayPair:
    """Record two typed fixture runs; does not execute either run."""
    if not isinstance(first, ShadowObservation) or not isinstance(
        second, ShadowObservation
    ):
        raise TypeError("replay recorder requires two typed observations")
    _golden_set_check(first)
    _golden_set_check(second)
    if (
        first.observation_id == second.observation_id
        or first.release_manifest_sha256 == second.release_manifest_sha256
    ):
        raise ReplayPairIntegrityError(
            "replay observations are not distinct executions"
        )
    destination = _validated_destination(destination_directory)
    identity = _capture_replay_execution_identity()
    eei_sha256 = _capture_replay_eei(identity)
    pair = _build_pair(first, second, identity, eei_sha256)
    if (
        _capture_replay_execution_identity() != identity
        or _capture_replay_eei(identity) != eei_sha256
    ):
        raise ReplayExecutionEnvironmentError(
            "replay source or execution environment changed before publication"
        )
    _publish_canonical_receipt(
        _observation_receipt(first, identity, eei_sha256),
        destination / REPLAY_OBSERVATION_1_FILENAME,
    )
    _publish_canonical_receipt(
        _observation_receipt(second, identity, eei_sha256),
        destination / REPLAY_OBSERVATION_2_FILENAME,
    )
    _publish_canonical_receipt(
        pair.document(),
        destination / REPLAY_PAIR_FILENAME,
    )
    return pair


if HARD_QUALITY_TARGETS.get("deterministic_replay_mismatch") != 0:
    raise RuntimeError("replay-pair target differs from canonical policy")
