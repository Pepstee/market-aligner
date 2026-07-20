"""JAA-00 brownfield database verification and adoption.

The frozen contract deliberately lives in code: changing an input requires a reviewed
new snapshot rather than silently teaching the importer to accept the changed file.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import quote


class AdoptionError(RuntimeError):
    """A baseline failed certification or could not be copied safely."""


@dataclass(frozen=True)
class BaselineSpec:
    name: str
    source_relative: str
    destination_relative: str
    size: int
    sha256: str
    schema_sha256: str
    schema_objects: int
    table_counts: Mapping[str, int]


BASELINES: tuple[BaselineSpec, ...] = (
    BaselineSpec(
        "raw_jobs", "scraper/data_overnight/jobs.sqlite3", "databases/jobs.sqlite3",
        117_551_104, "87aefc638ae5c0d5b11e6dd8dfb8da5cd8bbfaed5cdba630f5aa3216bf170e57",
        "d40bb9b317ccbbf30cc60fecd6bab4231b663782ccd37226966f353ba064040c", 6,
        {"collection_runs": 0, "normalised_jobs": 548, "postings": 9407,
         "scores": 548, "source_state": 39},
    ),
    BaselineSpec(
        "career_pipeline", "outputs/career_automation/career_pipeline.sqlite3",
        "databases/career_pipeline.sqlite3", 6_238_208,
        "dd99efe519b5fcfe09cba2a0d08d18ce6ce84d570ef8649c5d250ebba03f9a8b",
        "2b582efd6d32d907149fbbc0eb1002a78f78c7b161b524fc5d0e14381f269205", 39,
        {
            "browser_workflow_checkpoints": 0, "browser_workflow_definitions": 0,
            "browser_workflow_events": 0, "browser_workflow_runs": 0,
            "ca_fetch_attempts": 0, "ca_fetch_policies": 2, "ca_fetch_relocations": 0,
            "ca_fetch_selector_fingerprints": 0, "ca_obs_events": 0,
            "ca_obs_flows": 2, "ca_obs_outbox": 0, "ca_obs_spans": 0,
            "ca_obs_traces": 0, "career_deployment_checks": 0,
            "career_deployment_events": 0, "career_deployment_releases": 0,
            "career_schema_migrations": 0, "employer_dossiers": 0,
            "employer_research_queue": 58, "pipeline_events": 924, "pipeline_jobs": 462,
        },
    ),
)

REQUIRED_DISTRIBUTIONS = ("PyYAML", "requests", "openpyxl", "pypdf")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=1024 * 1024) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _readonly_connection(path: Path) -> sqlite3.Connection:
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=30)
    connection.execute("PRAGMA query_only=ON")
    return connection


def _schema_rows(connection: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()


def _verify_database(path: Path, spec: BaselineSpec) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise AdoptionError(f"{spec.name}: source must be a regular, non-symlink file")
    sidecars = [Path(str(path) + suffix) for suffix in ("-journal", "-wal", "-shm")]
    present_sidecars = [item.name for item in sidecars if item.exists()]
    if present_sidecars:
        raise AdoptionError(
            f"{spec.name}: database is live or dirty; SQLite sidecars present: {present_sidecars}"
        )
    before = path.stat()
    if before.st_size != spec.size:
        raise AdoptionError(f"{spec.name}: byte size mismatch: expected {spec.size}, got {before.st_size}")
    digest = _hash_file(path)
    if digest != spec.sha256:
        raise AdoptionError(f"{spec.name}: SHA-256 mismatch: expected {spec.sha256}, got {digest}")
    try:
        with closing(_readonly_connection(path)) as connection:
            integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()]
            if integrity != ["ok"]:
                raise AdoptionError(f"{spec.name}: integrity_check failed: {integrity}")
            schema = _schema_rows(connection)
            schema_hash = hashlib.sha256(_canonical_bytes(schema)).hexdigest()
            if len(schema) != spec.schema_objects or schema_hash != spec.schema_sha256:
                raise AdoptionError(
                    f"{spec.name}: schema mismatch: expected {spec.schema_objects} objects/"
                    f"{spec.schema_sha256}, got {len(schema)} objects/{schema_hash}"
                )
            actual_tables = {row[1] for row in schema if row[0] == "table"}
            if actual_tables != set(spec.table_counts):
                raise AdoptionError(f"{spec.name}: table set mismatch")
            counts = {
                table: int(connection.execute(
                    'SELECT COUNT(*) FROM "' + table.replace('"', '""') + '"'
                ).fetchone()[0])
                for table in sorted(actual_tables)
            }
    except sqlite3.Error as exc:
        raise AdoptionError(f"{spec.name}: SQLite verification failed: {exc}") from exc
    if counts != dict(sorted(spec.table_counts.items())):
        raise AdoptionError(f"{spec.name}: table count mismatch: expected {dict(spec.table_counts)}, got {counts}")
    after = path.stat()
    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
        raise AdoptionError(f"{spec.name}: source changed during verification")
    return {"bytes": before.st_size, "sha256": digest, "schema_sha256": schema_hash,
            "schema_objects": len(schema), "table_counts": counts, "integrity_check": integrity}


def _runtime_versions() -> dict[str, Any]:
    if sys.version_info < (3, 10):
        raise AdoptionError("Python >=3.10 is required")
    dependencies: dict[str, str] = {}
    missing: list[str] = []
    for name in REQUIRED_DISTRIBUTIONS:
        try:
            dependencies[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            missing.append(name)
    if missing:
        raise AdoptionError("missing runtime dependencies: " + ", ".join(missing))
    return {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
            "platform": platform.platform(), "dependencies": dependencies}


def _repository_revision(repository: Path) -> str:
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=repository,
                             check=True, capture_output=True, text=True).stdout.strip()
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository,
                                  check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AdoptionError("canonical repository revision is unavailable") from exc
    if Path(top).resolve() != repository.resolve() or len(revision) != 40:
        raise AdoptionError("repository is not the canonical worktree root")
    return revision


def _validate_roots(source_root: Path, data_root: Path, repository: Path) -> None:
    source = source_root.resolve()
    data = data_root.resolve()
    repo = repository.resolve()
    lowered = [part.lower() for part in data.parts]
    if data == source or source in data.parents or data in source.parents:
        raise AdoptionError("data root must be separate from the preserved source")
    if data == repo or repo in data.parents:
        raise AdoptionError("runtime databases must not be stored inside the canonical repository")
    if "giga-user" in lowered or any("market-aligner" in part for part in lowered):
        raise AdoptionError("data root resembles a historical market-aligner copy")


def _atomic_copy(source: Path, destination: Path, spec: BaselineSpec) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise AdoptionError(f"refusing to overwrite destination: {spec.destination_relative}")
    fd, temporary_name = tempfile.mkstemp(prefix=".adopting-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        verified = _verify_database(temporary, spec)
        try:
            os.link(temporary, destination)  # atomic create-if-absent; never replaces
        except FileExistsError as exc:
            raise AdoptionError(f"destination appeared during copy: {spec.destination_relative}") from exc
        os.unlink(temporary)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return verified
    finally:
        temporary.unlink(missing_ok=True)


def adopt(source_root: str | Path, data_root: str | Path, *, repository: str | Path,
          secret_references: Sequence[str] = ()) -> Path:
    """Verify both frozen sources, atomically copy them, and write a hashed receipt."""
    source_root, data_root, repository = Path(source_root), Path(data_root), Path(repository)
    _validate_roots(source_root, data_root, repository)
    runtime = _runtime_versions()
    revision = _repository_revision(repository.resolve())
    invalid_refs = [name for name in secret_references if not name or "=" in name or os.sep in name]
    if invalid_refs:
        raise AdoptionError("secret references must be names only, never values or paths")
    sources: dict[str, dict[str, Any]] = {}
    for spec in BASELINES:  # verify every input before creating any destination
        sources[spec.name] = _verify_database(source_root / spec.source_relative, spec)
    destinations: dict[str, dict[str, Any]] = {}
    created: list[Path] = []
    try:
        for spec in BASELINES:
            destination = data_root / spec.destination_relative
            destinations[spec.name] = _atomic_copy(source_root / spec.source_relative, destination, spec)
            created.append(destination)
        # Re-read sources after all copies to prove the adoption did not mutate them.
        for spec in BASELINES:
            _verify_database(source_root / spec.source_relative, spec)
        content = {
            "format": "jaa-00-migration-receipt/v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "repository": {"identity": "canonical-repository", "revision": revision},
            "runtime": runtime,
            "secret_references": sorted(set(secret_references)),
            "databases": {
                spec.name: {
                    "source": {"location": spec.source_relative, **sources[spec.name]},
                    "destination": {"location": spec.destination_relative, **destinations[spec.name]},
                    "rollback": {"preserved_source": spec.source_relative,
                                 "remove_destination": spec.destination_relative},
                } for spec in BASELINES
            },
        }
        content_hash = hashlib.sha256(_canonical_bytes(content)).hexdigest()
        receipt = {"content_sha256": content_hash, "content": content}
        receipt_dir = data_root / "receipts"
        receipt_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = receipt_dir / f"migration-{content_hash}.json"
        if receipt_path.exists():
            raise AdoptionError("migration receipt already exists")
        payload = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"
        fd, temporary_name = tempfile.mkstemp(prefix=".receipt-", dir=receipt_dir)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload); stream.flush(); os.fsync(stream.fileno())
            os.link(temporary, receipt_path)
        finally:
            temporary.unlink(missing_ok=True)
        return receipt_path
    except Exception:
        # Never leave a partial adoption that could be mistaken for complete.
        for path in created:
            path.unlink(missing_ok=True)
        raise


def _load_receipt(path: Path) -> dict[str, Any]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        content = receipt["content"]
        expected = receipt["content_sha256"]
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise AdoptionError(f"invalid receipt: {exc}") from exc
    actual = hashlib.sha256(_canonical_bytes(content)).hexdigest()
    if actual != expected or path.name != f"migration-{actual}.json":
        raise AdoptionError("receipt content hash or filename mismatch")
    return receipt


def reconcile(receipt_path: str | Path, data_root: str | Path) -> dict[str, Any]:
    """Re-certify adopted files against both the receipt and frozen contract."""
    receipt = _load_receipt(Path(receipt_path))
    data_root = Path(data_root)
    results: dict[str, Any] = {}
    for spec in BASELINES:
        recorded = receipt["content"]["databases"][spec.name]["destination"]
        result = _verify_database(data_root / spec.destination_relative, spec)
        for field in ("bytes", "sha256", "schema_sha256", "schema_objects", "table_counts", "integrity_check"):
            if result[field] != recorded[field]:
                raise AdoptionError(f"{spec.name}: destination disagrees with migration receipt")
        results[spec.name] = result
    return {"status": "ok", "receipt_content_sha256": receipt["content_sha256"], "databases": results}


def rollback_manifest(receipt_path: str | Path, data_root: str | Path) -> dict[str, Any]:
    """Produce an executable-safe manifest; this command intentionally deletes nothing."""
    receipt = _load_receipt(Path(receipt_path))
    root = Path(data_root).resolve()
    entries = []
    for spec in BASELINES:
        destination = (root / spec.destination_relative).resolve()
        if root not in destination.parents:
            raise AdoptionError("rollback destination escapes data root")
        current = _verify_database(destination, spec)
        entries.append({"database": spec.name, "action": "remove_adopted_copy",
                        "target": spec.destination_relative, "expected_sha256": current["sha256"],
                        "preserved_source": spec.source_relative})
    return {"format": "jaa-00-rollback-manifest/v1", "receipt_content_sha256":
            receipt["content_sha256"], "precondition": "reconcile must pass immediately before removal",
            "actions": entries}
