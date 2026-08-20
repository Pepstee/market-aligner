"""Canonical inherited YAML configuration loader for Market Aligner."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    output = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(output.get(key), dict):
            output[key] = _merge(output[key], value)
        else:
            output[key] = value
    return output


def load_config(
    path: str | Path,
    *,
    _ancestors: tuple[Path, ...] = (),
) -> dict[str, Any]:
    """Load one config with recursive mapping merge and list replacement."""
    import yaml

    resolved = Path(path).resolve()
    if resolved in _ancestors:
        chain = " -> ".join(item.name for item in (*_ancestors, resolved))
        raise ValueError(f"configuration extends cycle: {chain}")
    payload = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError(f"configuration must be a mapping: {resolved}")
    config = dict(payload)
    parent = config.pop("extends", None)
    if parent is None:
        return config
    if not isinstance(parent, str) or not parent.strip():
        raise ValueError("extends must be a non-empty string path")
    parent_path = Path(parent)
    if not parent_path.is_absolute():
        parent_path = resolved.parent / parent_path
    base = load_config(parent_path, _ancestors=(*_ancestors, resolved))
    return _merge(base, config)
