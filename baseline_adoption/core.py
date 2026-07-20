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
CANONICAL_MARKER = "canonical-repository.json"
CANONICAL_REPOSITORY_ID = "market-aligner"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=1024 * 1024) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _readonly_connection(path: Path) -> sqlite3.Connection:
    """Open a live database read-only, including any committed WAL contents."""
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=30)
    connection.execute("PRAGMA query_only=ON")
    return connection


def _immutable_connection(path: Path) -> sqlite3.Connection:
    """Open a closed snapshot without permitting SQLite filesystem mutations."""
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True, timeout=30)
    connection.execute("PRAGMA query_only=ON")
    return connection


def _schema_rows(connection: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()


def _file_identity(path: Path, label: str) -> dict[str, Any]:
    """Return a receipt-safe identity without disclosing the host path."""
    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"label": label, "exists": False}
    if not path.is_file() or path.is_symlink():
        raise AdoptionError(f"{label}: must be a regular, non-symlink file")
    return {
        "label": label,
        "exists": True,
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _source_identities(path: Path, source_label: str) -> dict[str, dict[str, Any]]:
    return {
        "main": _file_identity(path, source_label + ":main"),
        "wal": _file_identity(Path(str(path) + "-wal"), source_label + ":wal"),
        "shm": _file_identity(Path(str(path) + "-shm"), source_label + ":shm"),
    }


def _inspect_database(path: Path) -> dict[str, Any]:
    """Measure a closed SQLite snapshot without relying on a historical byte hash."""
    if not path.is_file() or path.is_symlink():
        raise AdoptionError("snapshot must be a regular, non-symlink file")
    try:
        with closing(_immutable_connection(path)) as connection:
            integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()]
            if integrity != ["ok"]:
                raise AdoptionError(f"snapshot integrity_check failed: {integrity}")
            schema = _schema_rows(connection)
            schema_hash = hashlib.sha256(_canonical_bytes(schema)).hexdigest()
            tables = sorted(row[1] for row in schema if row[0] == "table")
            counts = {
                table: int(connection.execute(
                    'SELECT COUNT(*) FROM "' + table.replace('"', '""') + '"'
                ).fetchone()[0])
                for table in tables
            }
    except sqlite3.Error as exc:
        raise AdoptionError(f"snapshot SQLite verification failed: {exc}") from exc
    return {
        "bytes": path.stat().st_size,
        "sha256": _hash_file(path),
        "schema_sha256": schema_hash,
        "schema_objects": len(schema),
        "table_counts": counts,
        "integrity_check": integrity,
    }


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
        with closing(_immutable_connection(path)) as connection:
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
    _validate_canonical_marker(repository)
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


def _validate_canonical_marker(repository: Path) -> None:
    """Refuse imports through a similarly named checkout without the canonical contract."""
    try:
        marker = json.loads((repository / CANONICAL_MARKER).read_text(encoding="utf-8"))
        identity = marker["canonical_repository"]
        contract = marker["brownfield_import_contract"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise AdoptionError("canonical repository marker is missing or invalid") from exc
    if (marker.get("schema_version") != 1 or
            identity.get("id") != CANONICAL_REPOSITORY_ID or
            identity.get("product_name") != "Market Aligner" or
            identity.get("status") != "active" or
            contract.get("implicit_host_paths") is not False or
            contract.get("required_operator_paths") != [
                "source_root", "runtime_data_root", "repository_root"
            ]):
        raise AdoptionError("repository does not carry the active Market Aligner import contract")


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


def _historical_observation(spec: BaselineSpec) -> dict[str, Any]:
    return {
        "observed_bytes": spec.size,
        "observed_sha256": spec.sha256,
        "observed_schema_sha256": spec.schema_sha256,
        "observed_schema_objects": spec.schema_objects,
        "observed_table_counts": dict(sorted(spec.table_counts.items())),
    }


def _atomic_online_backup(source: Path, destination: Path, spec: BaselineSpec) -> dict[str, Any]:
    """Freeze a live source with sqlite3_backup and publish it create-if-absent."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise AdoptionError(f"refusing to overwrite destination: {spec.destination_relative}")

    source_label = f"source:{spec.name}"
    start = _source_identities(source, source_label)
    if not start["main"]["exists"]:
        raise AdoptionError(f"{spec.name}: live source does not exist")
    if start["wal"]["exists"] and not start["shm"]["exists"]:
        raise AdoptionError(
            f"{spec.name}: WAL exists without SHM; refusing a read that could initialise source state"
        )

    fd, temporary_name = tempfile.mkstemp(prefix=".snapshotting-", dir=destination.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    temporary_sidecars = [Path(str(temporary) + suffix) for suffix in ("-journal", "-wal", "-shm")]
    started_at = datetime.now(timezone.utc).isoformat()
    published = False
    try:
        try:
            with closing(_readonly_connection(source)) as source_connection, \
                    closing(sqlite3.connect(temporary)) as destination_connection:
                source_connection.backup(destination_connection)
                # sqlite3_backup copies a consistent logical database but may leave
                # the destination header in WAL mode.  Convert the private temporary
                # copy to a closed rollback-journal database before it is measured or
                # published, so immutable reconciliation never needs WAL/SHM state.
                journal_mode = destination_connection.execute(
                    "PRAGMA journal_mode=DELETE"
                ).fetchone()[0]
                if str(journal_mode).lower() != "delete":
                    raise AdoptionError(
                        f"{spec.name}: could not finalise online backup in DELETE journal mode"
                    )
        except sqlite3.Error as exc:
            raise AdoptionError(f"{spec.name}: SQLite online backup failed: {exc}") from exc
        ended_at = datetime.now(timezone.utc).isoformat()
        end = _source_identities(source, source_label)
        measured = _inspect_database(temporary)

        # A live baseline may gain rows, but it must still be the expected database family.
        if (measured["schema_sha256"] != spec.schema_sha256 or
                measured["schema_objects"] != spec.schema_objects or
                set(measured["table_counts"]) != set(spec.table_counts)):
            raise AdoptionError(f"{spec.name}: live source schema does not match the historical baseline")

        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise AdoptionError(f"destination appeared during snapshot: {spec.destination_relative}") from exc
        published = True
        os.unlink(temporary)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

        changed = [name for name in ("main", "wal", "shm") if start[name] != end[name]]
        return {
            "capture": {
                "method": "sqlite-online-backup",
                "started_at": started_at,
                "ended_at": ended_at,
                "source_identities_start": start,
                "source_identities_end": end,
                "drift_observed": bool(changed),
                "changed_components": changed,
            },
            "snapshot": measured,
            "destination_identity": _file_identity(
                destination, f"destination:{spec.name}"
            ),
        }
    except Exception:
        if published:
            destination.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)
        for sidecar in temporary_sidecars:
            sidecar.unlink(missing_ok=True)


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


def adopt_online(source_root: str | Path, data_root: str | Path, *, repository: str | Path,
                 secret_references: Sequence[str] = ()) -> Path:
    """Transactionally freeze changing SQLite sources using the online backup API.

    Historical observations identify the database family; the new snapshot's counts,
    size and digest are measured facts and are never substituted into that history.
    """
    source_root, data_root, repository = Path(source_root), Path(data_root), Path(repository)
    _validate_roots(source_root, data_root, repository)
    runtime = _runtime_versions()
    revision = _repository_revision(repository.resolve())
    invalid_refs = [name for name in secret_references if not name or "=" in name or os.sep in name]
    if invalid_refs:
        raise AdoptionError("secret references must be names only, never values or paths")

    destinations = [data_root / spec.destination_relative for spec in BASELINES]
    for spec, destination in zip(BASELINES, destinations):
        if destination.exists() or destination.is_symlink():
            raise AdoptionError(f"refusing to overwrite destination: {spec.destination_relative}")

    captures: dict[str, dict[str, Any]] = {}
    created: list[Path] = []
    try:
        for spec, destination in zip(BASELINES, destinations):
            captures[spec.name] = _atomic_online_backup(
                source_root / spec.source_relative, destination, spec
            )
            created.append(destination)
        content = {
            "format": "jaa-00-online-snapshot-receipt/v2",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "repository": {"label": "canonical-repository", "revision": revision},
            "runtime": runtime,
            "secret_references": sorted(set(secret_references)),
            "databases": {
                spec.name: {
                    "source": {"label": f"source:{spec.name}"},
                    "historical_observation": _historical_observation(spec),
                    "capture": captures[spec.name]["capture"],
                    "frozen_snapshot": captures[spec.name]["snapshot"],
                    "destination": {
                        "label": f"destination:{spec.name}",
                        "relative_location": spec.destination_relative,
                        "identity": captures[spec.name]["destination_identity"],
                    },
                    "rollback": {
                        "preserved_source_label": f"source:{spec.name}",
                        "remove_destination_label": f"destination:{spec.name}",
                        "remove_relative_location": spec.destination_relative,
                    },
                }
                for spec in BASELINES
            },
        }
        content_hash = hashlib.sha256(_canonical_bytes(content)).hexdigest()
        receipt = {"content_sha256": content_hash, "content": content}
        receipt_dir = data_root / "receipts"
        receipt_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = receipt_dir / f"migration-{content_hash}.json"
        payload = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"
        fd, temporary_name = tempfile.mkstemp(prefix=".receipt-", dir=receipt_dir)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, receipt_path)
            except FileExistsError as exc:
                raise AdoptionError("migration receipt already exists") from exc
        finally:
            temporary.unlink(missing_ok=True)
        return receipt_path
    except Exception:
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
    if not isinstance(content, dict) or not isinstance(expected, str):
        raise AdoptionError("invalid receipt: content and content_sha256 have invalid types")
    actual = hashlib.sha256(_canonical_bytes(content)).hexdigest()
    if actual != expected or path.name != f"migration-{actual}.json":
        raise AdoptionError("receipt content hash or filename mismatch")
    if content.get("format") not in {
        "jaa-00-migration-receipt/v1", "jaa-00-online-snapshot-receipt/v2"
    }:
        raise AdoptionError("unsupported receipt format")
    return receipt


def reconcile(receipt_path: str | Path, data_root: str | Path) -> dict[str, Any]:
    """Re-certify adopted files against both the receipt and frozen contract."""
    receipt = _load_receipt(Path(receipt_path))
    data_root = Path(data_root)
    results: dict[str, Any] = {}
    for spec in BASELINES:
        try:
            record = receipt["content"]["databases"][spec.name]
            if receipt["content"]["format"] == "jaa-00-online-snapshot-receipt/v2":
                destination_record = record["destination"]
                if record["historical_observation"] != _historical_observation(spec):
                    raise AdoptionError(f"{spec.name}: historical observation was rewritten")
                if record["source"] != {"label": f"source:{spec.name}"}:
                    raise AdoptionError(f"{spec.name}: unexpected source label in receipt")
                if (destination_record["label"] != f"destination:{spec.name}" or
                        destination_record["relative_location"] != spec.destination_relative):
                    raise AdoptionError(f"{spec.name}: unexpected destination in receipt")
                expected_rollback = {
                    "preserved_source_label": f"source:{spec.name}",
                    "remove_destination_label": f"destination:{spec.name}",
                    "remove_relative_location": spec.destination_relative,
                }
                if record["rollback"] != expected_rollback:
                    raise AdoptionError(f"{spec.name}: unexpected rollback instructions in receipt")
                destination = data_root / spec.destination_relative
                sidecars = [Path(str(destination) + suffix) for suffix in ("-journal", "-wal", "-shm")]
                if any(item.exists() for item in sidecars):
                    raise AdoptionError(f"{spec.name}: adopted snapshot has SQLite sidecars")
                result = _inspect_database(destination)
                if result != record["frozen_snapshot"]:
                    raise AdoptionError(f"{spec.name}: destination disagrees with snapshot receipt")
                if (result["schema_sha256"] != spec.schema_sha256 or
                        result["schema_objects"] != spec.schema_objects or
                        set(result["table_counts"]) != set(spec.table_counts)):
                    raise AdoptionError(f"{spec.name}: destination schema violates baseline contract")
                identity = _file_identity(destination, f"destination:{spec.name}")
                if identity != destination_record["identity"]:
                    raise AdoptionError(f"{spec.name}: destination identity changed")
            else:
                recorded = record["destination"]
                result = _verify_database(data_root / spec.destination_relative, spec)
                for field in ("bytes", "sha256", "schema_sha256", "schema_objects",
                              "table_counts", "integrity_check"):
                    if result[field] != recorded[field]:
                        raise AdoptionError(f"{spec.name}: destination disagrees with migration receipt")
        except (KeyError, TypeError) as exc:
            raise AdoptionError(f"{spec.name}: malformed database receipt") from exc
        results[spec.name] = result
    return {"status": "ok", "receipt_content_sha256": receipt["content_sha256"], "databases": results}


def rollback_manifest(receipt_path: str | Path, data_root: str | Path) -> dict[str, Any]:
    """Produce an executable-safe manifest; this command intentionally deletes nothing."""
    receipt = _load_receipt(Path(receipt_path))
    root = Path(data_root).resolve()
    online = receipt["content"]["format"] == "jaa-00-online-snapshot-receipt/v2"
    if online:
        reconcile(receipt_path, data_root)
    entries = []
    for spec in BASELINES:
        destination = (root / spec.destination_relative).resolve()
        if root not in destination.parents:
            raise AdoptionError("rollback destination escapes data root")
        record = receipt["content"]["databases"].get(spec.name)
        if not isinstance(record, dict):
            raise AdoptionError(f"{spec.name}: malformed database receipt")
        if online:
            current = _inspect_database(destination)
            preserved_source = record["rollback"]["preserved_source_label"]
        else:
            current = _verify_database(destination, spec)
            preserved_source = spec.source_relative
        entries.append({"database": spec.name, "action": "remove_adopted_copy",
                        "target": spec.destination_relative, "expected_sha256": current["sha256"],
                        "preserved_source": preserved_source})
    return {"format": "jaa-00-rollback-manifest/v1", "receipt_content_sha256":
            receipt["content_sha256"], "precondition": "reconcile must pass immediately before removal",
            "actions": entries}
