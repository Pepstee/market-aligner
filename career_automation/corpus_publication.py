"""Fail-closed, content-addressed publication for acquired JAA-04 corpora."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
from pathlib import Path
from typing import Any, Callable


INVENTORY_FORMAT = "jaa04.corpus-inventory.v1"


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_inventory(corpus: Path) -> dict[str, Any]:
    """Inventory all evidence bytes, excluding the inventory and its receipt."""
    records: list[dict[str, Any]] = []
    for path in sorted(item for item in corpus.rglob("*") if item.is_file()):
        relative = path.relative_to(corpus).as_posix()
        if relative in {"corpus_inventory.json", "capture_receipt.json"}:
            continue
        stat = path.stat()
        records.append({"path": relative, "sha256": sha256_file(path),
                        "size_bytes": stat.st_size})
    payload: dict[str, Any] = {"schema_version": INVENTORY_FORMAT, "files": records}
    payload["files_hash"] = hashlib.sha256(canonical_bytes(records)).hexdigest()
    return payload


def validate_inventory(corpus: Path, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    inventory = inventory or json.loads((corpus / "corpus_inventory.json").read_text())
    if inventory.get("schema_version") != INVENTORY_FORMAT:
        raise ValueError("unsupported JAA-04 corpus inventory")
    expected = build_inventory(corpus)
    if inventory != expected:
        raise ValueError("JAA-04 corpus inventory does not match published bytes")
    paths = [row.get("path") for row in inventory.get("files", [])]
    if len(paths) != len(set(paths)) or not {"frozen_dossiers.json", "research_manifest.json"}.issubset(paths):
        raise ValueError("JAA-04 corpus inventory is incomplete or duplicated")
    return inventory


def write_inventory(corpus: Path) -> Path:
    target = corpus / "corpus_inventory.json"
    target.write_bytes(canonical_bytes(build_inventory(corpus)))
    return target


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_by_pointer(staged: Path, destination: Path,
                       validator: Callable[[Path], None]) -> Path:
    """Publish with one atomic symlink replacement after complete validation.

    Immutable releases live beside the public pointer.  Consequently a failed
    acquisition or validator can neither expose partial bytes nor disturb the
    previously certified release.
    """
    staged = staged.resolve()
    destination = destination.absolute()
    if not staged.is_dir() or destination.exists() and not destination.is_symlink():
        raise RuntimeError("atomic corpus destination must be absent or a managed symlink")
    validator(staged)
    inventory = validate_inventory(staged)
    identity = hashlib.sha256(canonical_bytes(inventory)).hexdigest()
    releases = destination.parent / f".{destination.name}-releases"
    releases.mkdir(parents=True, exist_ok=True)
    release = releases / f"sha256-{identity}"
    if release.exists():
        validate_inventory(release)
        if build_inventory(release) != inventory:
            raise RuntimeError("content-addressed release identity collision")
        shutil.rmtree(staged)
    else:
        os.rename(staged, release)
        _fsync_directory(releases)
    relative_target = os.path.relpath(release, destination.parent)
    temporary = destination.parent / f".{destination.name}-{secrets.token_hex(12)}"
    try:
        os.symlink(relative_target, temporary)
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        if temporary.is_symlink():
            temporary.unlink()
    return release
