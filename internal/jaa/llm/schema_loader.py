"""
llm/schema_loader.py — load the structured-output JSON schemas.

The schema FILES (llm/schemas/*.json) are the source of truth; this just loads
them so capabilities.py can pass one to LLMClient.complete_json for validation.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    """Load schemas/<name>.json (name without extension)."""
    path = _SCHEMA_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"no schema '{name}' at {path}")
    return json.loads(path.read_text(encoding="utf-8"))
