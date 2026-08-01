"""Recursive external YAML configuration with deterministic deep merge."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | Path, _stack: tuple[Path, ...] = ()) -> dict[str, Any]:
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
