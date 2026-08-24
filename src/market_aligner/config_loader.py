"""Recursive external YAML configuration with deterministic deep merge.

``snapshot_config`` binds semantics and raw file identity to one coherent
snapshot: every file of the ``extends`` closure is read exactly once through a
verified nofollow single-link regular-file open, parsed from those bytes, and
re-read afterwards to prove nothing changed during the load. A concurrent
replacement rejects before any provider or journal activity, so semantic
configuration A is never executed while recording raw identity from file B.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Callable

import yaml


Reader = Callable[[Path], bytes]


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _read_verified(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"configuration {path} must be a single-link regular file")
        chunks = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def snapshot_config(
    path: str | Path,
    *,
    reader: Reader = _read_verified,
    _stack: tuple[Path, ...] = (),
) -> tuple[dict[str, Any], dict[str, str]]:
    """Return ``(merged_configuration, {resolved_path: sha256})`` coherently.

    The returned mapping and identities derive from one read per file; a
    re-read verifies each dependency stayed stable across the load.
    """
    source = Path(path).expanduser().resolve()
    if source in _stack:
        chain = " -> ".join(str(item) for item in (*_stack, source))
        raise ValueError(f"configuration extends cycle: {chain}")
    try:
        payload_bytes = reader(source)
    except OSError as exc:
        raise ValueError(f"configuration {source} could not be read: {exc}") from exc

    def parse(raw: bytes) -> dict[str, Any]:
        payload = yaml.safe_load(raw.decode("utf-8")) or {}
        if not isinstance(payload, dict):
            raise ValueError(f"configuration root of {source} must be a mapping")
        return payload

    payload = parse(payload_bytes)
    parent = payload.pop("extends", None)

    child_identity = hashlib.sha256(payload_bytes).hexdigest()
    identities: dict[str, str] = {}

    if not parent:
        merged = payload
    else:
        parent_path = Path(str(parent)).expanduser()
        if not parent_path.is_absolute():
            parent_path = source.parent / parent_path
        base, base_identities = snapshot_config(parent_path, reader=reader, _stack=(*_stack, source))
        identities.update(base_identities)
        merged = deep_merge(base, payload)
    identities[str(source)] = child_identity

    # Coherence proof: every dependency must still be byte-identical now that
    # the whole closure has been loaded.
    for dependency, expected in identities.items():
        try:
            current = hashlib.sha256(reader(Path(dependency))).hexdigest()
        except (OSError, ValueError) as exc:
            raise ValueError(f"configuration {dependency} changed during load: {exc}") from exc
        if current != expected:
            raise ValueError(
                f"configuration {dependency} changed during load; refusing incoherent snapshot"
            )
    return merged, identities


def load_config(path: str | Path, _stack: tuple[Path, ...] = ()) -> dict[str, Any]:
    """Backward-compatible plain recursive load without identity binding."""
    source = Path(path).expanduser().resolve()
    if source in _stack:
        chain = " -> ".join(str(item) for item in (*_stack, source))
        raise ValueError(f"configuration extends cycle: {chain}")
    payload = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError("configuration root must be a mapping")
    parent = payload.pop("extends", None)
    if not parent:
        return payload
    parent_path = Path(str(parent)).expanduser()
    if not parent_path.is_absolute():
        parent_path = source.parent / parent_path
    return deep_merge(load_config(parent_path, (*_stack, source)), payload)


def closure_identity(identities: dict[str, str]) -> str:
    """One SHA-256 over the whole resolved file identity mapping."""
    canonical = json.dumps(identities, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
