"""Backward-compatible, multi-root raw-cache import without source mutation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator

from market_aligner.domain.contracts import RawPosting, from_dict, read_jsonl


def iter_raw_cache_roots(roots: Iterable[str | Path]) -> Iterator[RawPosting]:
    """Yield one record per key from JSON object/array or historical JSONL files."""

    seen: set[str] = set()
    for root in (Path(item).expanduser().resolve() for item in roots):
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.json")):
            parsed: list[RawPosting]
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                values = payload if isinstance(payload, list) else [payload]
                parsed = [
                    from_dict(RawPosting, value)
                    for value in values
                    if isinstance(value, dict)
                ]
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                try:
                    parsed = list(read_jsonl(path, RawPosting))
                except (OSError, json.JSONDecodeError, TypeError, ValueError):
                    continue
            for row in parsed:
                if row.key in seen:
                    continue
                seen.add(row.key)
                yield row
