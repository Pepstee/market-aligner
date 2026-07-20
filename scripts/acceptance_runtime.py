"""Private runtime configuration for independently executable acceptance."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
CONFIG_FIELDS = {
    "schema_version",
    "original_source_root",
    "recertification_evidence_directory",
}
SOURCE_DATABASES = (
    Path("scraper/data_overnight/jobs.sqlite3"),
    Path("outputs/career_automation/career_pipeline.sqlite3"),
)


class RuntimeConfigurationError(RuntimeError):
    """The private acceptance runtime configuration is absent or unsafe."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_config_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    if not base.is_absolute():
        raise RuntimeConfigurationError("XDG_CONFIG_HOME must be an absolute path")
    return base / "market-aligner" / "runtime.json"


def _absolute_unlinked(path: Path, label: str, *, may_be_absent: bool = False) -> Path:
    if not path.is_absolute():
        raise RuntimeConfigurationError(f"{label} must be an absolute path: {path}")
    normalized = Path(os.path.abspath(path))
    for component in (normalized, *normalized.parents):
        if component.is_symlink():
            raise RuntimeConfigurationError(f"{label} must not contain symlinks: {path}")
    try:
        resolved = normalized.resolve(strict=not may_be_absent)
    except OSError as exc:
        raise RuntimeConfigurationError(f"cannot resolve {label}: {path}: {exc}") from exc
    if resolved != normalized:
        raise RuntimeConfigurationError(f"{label} must not resolve through symlinks: {path}")
    return normalized


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def validate_runtime_values(source_value: str, evidence_value: str) -> tuple[Path, Path]:
    source = _absolute_unlinked(Path(source_value), "original_source_root")
    evidence = _absolute_unlinked(
        Path(evidence_value), "recertification_evidence_directory", may_be_absent=True
    )
    repository = repository_root().resolve(strict=True)

    if not source.is_dir():
        raise RuntimeConfigurationError(f"original_source_root is not a directory: {source}")
    for relative in SOURCE_DATABASES:
        database = _absolute_unlinked(source / relative, f"expected source database {relative}")
        if not database.is_file() or not stat.S_ISREG(database.stat().st_mode):
            raise RuntimeConfigurationError(f"expected source database is not a regular file: {relative}")

    if _overlaps(source, repository):
        raise RuntimeConfigurationError(
            "original_source_root must not overlap the product repository"
        )
    if _overlaps(evidence, repository):
        raise RuntimeConfigurationError(
            "recertification_evidence_directory must be outside and must not overlap the product repository"
        )
    if _overlaps(evidence, source):
        raise RuntimeConfigurationError(
            "recertification_evidence_directory must be outside and must not overlap the preserved source"
        )
    if evidence.exists() and not evidence.is_dir():
        raise RuntimeConfigurationError(
            f"recertification_evidence_directory is not a directory: {evidence}"
        )
    return source, evidence


def validate_config_path(path: Path, *, may_be_absent: bool) -> Path:
    result = _absolute_unlinked(path, "runtime config path", may_be_absent=may_be_absent)
    if _overlaps(result, repository_root().resolve(strict=True)):
        raise RuntimeConfigurationError("runtime config must be stored outside the product repository")
    return result


def load_runtime_config(path: Path) -> dict[str, Any]:
    config_path = validate_config_path(path, may_be_absent=False)
    try:
        mode = stat.S_IMODE(config_path.stat().st_mode)
        if mode != 0o600 or not config_path.is_file():
            raise RuntimeConfigurationError(
                f"runtime config must be a regular mode-0600 file: {config_path}"
            )
        document = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeConfigurationError(
            f"runtime config is absent; create it with {os.path.basename(os.sys.executable)} "
            "scripts/configure_acceptance.py"
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeConfigurationError(f"cannot load runtime config: {exc}") from exc
    if not isinstance(document, dict) or set(document) != CONFIG_FIELDS:
        raise RuntimeConfigurationError(
            "runtime config must contain only schema_version, original_source_root, "
            "and recertification_evidence_directory"
        )
    if document["schema_version"] != SCHEMA_VERSION:
        raise RuntimeConfigurationError(
            f"unsupported runtime config schema_version: {document['schema_version']!r}"
        )
    if not isinstance(document["original_source_root"], str) or not isinstance(
        document["recertification_evidence_directory"], str
    ):
        raise RuntimeConfigurationError("runtime config paths must be strings")
    source, evidence = validate_runtime_values(
        document["original_source_root"], document["recertification_evidence_directory"]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "original_source_root": str(source),
        "recertification_evidence_directory": str(evidence),
    }
