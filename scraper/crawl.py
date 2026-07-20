"""
scraper/crawl.py — the two cached, resumable crawl stages.

Build spec §1: do NOT score live during the crawl. Stages are decoupled and
idempotent, each writing to disk so a crash resumes without re-fetching:

    discover()  listing pages -> job_urls.jsonl            (C1 JobUrl)
    fetch()     each detail   -> raw_cache/{board}/{id}.json (C2 RawPosting)

Both keep a `seen` set keyed by "board:job_id" so re-runs skip cached items,
sleep a configurable rate-limit between board requests, and send a realistic
user-agent. All C1/C2 IO goes through skeleton/contracts (write_jsonl /
read_jsonl), so the shapes stay frozen.

Fixture-driven: the adapters read saved fixtures instead of hitting the live
boards, so this whole module runs standalone and offline. Wiring real HTTP /
Playwright is confined to the adapters (see each adapter's TODO markers); this
orchestrator does not change.

Stdlib only.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Optional

# --- module + skeleton paths ------------------------------------------------ #
_HERE = Path(__file__).resolve()
_MODULE_ROOT = _HERE.parent
_REPO_ROOT = _HERE.parents[1]
_SKELETON = _REPO_ROOT / "skeleton"
if str(_SKELETON) not in sys.path:
    sys.path.insert(0, str(_SKELETON))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import contracts  # noqa: E402
from contracts import JobUrl, RawPosting, read_jsonl, write_jsonl  # noqa: E402
from scraper.adapters import load_adapter  # noqa: E402

# --- constants -------------------------------------------------------------- #
# A realistic user-agent (build spec §1). Kept here as a module constant so both
# stages and every adapter can share one identity.
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36 KoreaJobScraper/0.1 (personal use)"
)

DATA_DIR = _MODULE_ROOT / "data"
JOB_URLS_PATH = DATA_DIR / "job_urls.jsonl"
RAW_CACHE_DIR = DATA_DIR / "raw_cache"

# Config defaults, overridden by skeleton/config.yaml (read, never hardcoded).
_DEFAULT_CONFIG_PATH = _SKELETON / "config.yaml"


# --------------------------------------------------------------------------- #
# config — read boards / search_terms / rate_limit from skeleton/config.yaml
# --------------------------------------------------------------------------- #
def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load config.yaml. Uses PyYAML if present; else a tiny stdlib parser that
    covers the subset this module needs (boards, search_terms, rate limit)."""
    p = Path(path) if path else _DEFAULT_CONFIG_PATH
    text = p.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except Exception:
        return _mini_yaml(text)


def _mini_yaml(text: str) -> dict[str, Any]:
    """Minimal YAML reader for the config keys crawl.py needs. Handles nested
    maps by indentation, `key: value` scalars, inline `[a, b]` lists, and
    `- item` block lists. Good enough for boards/search_terms/rate_limit; not a
    general YAML parser.

    A key with an empty value is a container whose kind is decided by its first
    child: a `- ` line makes it a list, a `key:` line makes it a map. We defer
    that choice via a pending (parent_dict, key) slot.
    """
    root: dict[str, Any] = {}
    # stack of (indent, container). container is a dict or list.
    stack: list[tuple[int, Any]] = [(-1, root)]
    # a key seen with empty value, awaiting its first child to decide list vs map
    pending: Optional[tuple[int, dict, str]] = None  # (indent, parent_dict, key)

    def _materialise(new_indent: int, as_list: bool) -> Any:
        """Turn a deferred empty-valued key into a list or map container."""
        nonlocal pending
        assert pending is not None
        _, parent_dict, key = pending
        container: Any = [] if as_list else {}
        parent_dict[key] = container
        stack.append((pending[0], container))
        pending = None
        return container

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip() if not _in_quotes_hash(raw) else raw.rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if stripped.startswith("- "):
            # a block-list item belongs to the nearest pending empty-valued key
            item = _scalar(stripped[2:].strip())
            if pending is not None and indent > pending[0]:
                container = _materialise(indent, as_list=True)
                container.append(item)
            else:
                # already-open list on the stack
                while stack and indent <= stack[-1][0]:
                    stack.pop()
                parent = stack[-1][1]
                if isinstance(parent, list):
                    parent.append(item)
            continue

        # a normal `key: ...` line resolves any pending key as a MAP first
        if pending is not None and indent > pending[0]:
            _materialise(indent, as_list=False)

        # pop to the right depth
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if not isinstance(parent, dict):
                continue
            if val == "":
                # defer: kind decided by first child
                pending = (indent, parent, key)
            elif val.startswith("[") and val.endswith("]"):
                inner = val[1:-1].strip()
                parent[key] = [
                    _scalar(x.strip()) for x in _split_top(inner) if x.strip()
                ]
            else:
                parent[key] = _scalar(val)
    return root


def _in_quotes_hash(line: str) -> bool:
    # very rough: keep the line intact if a '#' sits inside quotes
    return '"' in line and line.count('"') >= 2 and "#" in line


def _split_top(s: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def _scalar(v: str) -> Any:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", "none"):
        return None
    try:
        if "." in v:
            return float(v)
        return int(v)
    except ValueError:
        return v


def enabled_boards(cfg: dict[str, Any]) -> list[str]:
    return list((cfg.get("boards", {}) or {}).get("enabled", []) or [])


def _live_mode(cfg: dict[str, Any]) -> bool:
    """boards.mode: 'live' → real HTTP; anything else (incl. absent) → fixtures.

    crawl.py defaults to FIXTURE when the key is missing (it is the offline
    walking-skeleton tool); the shipped config sets mode: live explicitly, and
    the packaged runner (skeleton/run.py) defaults to live."""
    return str((cfg.get("boards", {}) or {}).get("mode", "fixture")).lower() == "live"


def search_terms(cfg: dict[str, Any]) -> list[str]:
    return list(cfg.get("search_terms", []) or [])


def rate_limit_seconds(cfg: dict[str, Any]) -> float:
    return float((cfg.get("boards", {}) or {}).get("rate_limit_seconds", 0.0) or 0.0)


# --------------------------------------------------------------------------- #
# resume / seen sets
# --------------------------------------------------------------------------- #
def load_seen_urls(path: str | Path = JOB_URLS_PATH) -> set[str]:
    """Keys ('board:job_id') already present in job_urls.jsonl."""
    p = Path(path)
    if not p.exists():
        return set()
    seen: set[str] = set()
    for rec in read_jsonl(p, JobUrl):
        seen.add(rec.key)
    return seen


def load_seen_raw(cache_dir: str | Path = RAW_CACHE_DIR) -> set[str]:
    """Keys already fetched into raw_cache/{board}/{id}.json."""
    d = Path(cache_dir)
    seen: set[str] = set()
    if not d.exists():
        return seen
    for board_dir in d.iterdir():
        if not board_dir.is_dir():
            continue
        for f in board_dir.glob("*.json"):
            seen.add(f"{board_dir.name}:{f.stem}")
    return seen


# --------------------------------------------------------------------------- #
# stage 1 — discover
# --------------------------------------------------------------------------- #
def discover(
    cfg: Optional[dict[str, Any]] = None,
    out_path: str | Path = JOB_URLS_PATH,
    fixture_dir: Optional[Path] = None,
    sleep: Optional[float] = None,
) -> list[JobUrl]:
    """Run every enabled board's discover() over the config search terms and
    APPEND new C1 JobUrl records to job_urls.jsonl. Resume: already-seen keys
    are skipped. Returns the list of NEW records written this run."""
    cfg = cfg or load_config()
    terms = search_terms(cfg)
    boards = enabled_boards(cfg)
    delay = rate_limit_seconds(cfg) if sleep is None else sleep
    live = _live_mode(cfg)

    seen = load_seen_urls(out_path)
    new: list[JobUrl] = []

    for board in boards:
        adapter = load_adapter(board, fixture_dir=fixture_dir,
                               config=(cfg.get(board) or {}))
        for job_url in adapter.discover(terms, live=live):
            if job_url.key in seen:
                continue                       # resume: skip already-discovered
            seen.add(job_url.key)
            new.append(job_url)
        _sleep(delay)                          # polite rate-limit, once per board

    if new:
        _append_jsonl(out_path, new)
    return new


# --------------------------------------------------------------------------- #
# stage 2 — fetch
# --------------------------------------------------------------------------- #
def fetch(
    cfg: Optional[dict[str, Any]] = None,
    urls_path: str | Path = JOB_URLS_PATH,
    cache_dir: str | Path = RAW_CACHE_DIR,
    fixture_dir: Optional[Path] = None,
    sleep: Optional[float] = None,
) -> list[RawPosting]:
    """Read C1 records from job_urls.jsonl and fetch each posting's detail into
    raw_cache/{board}/{id}.json as a C2 RawPosting. Resume: postings already in
    the cache are skipped. Returns the list of NEW postings fetched this run."""
    cfg = cfg or load_config()
    delay = rate_limit_seconds(cfg) if sleep is None else sleep
    live = _live_mode(cfg)
    cache_dir = Path(cache_dir)

    seen = load_seen_raw(cache_dir)
    new: list[RawPosting] = []
    adapters: dict[str, Any] = {}

    p = Path(urls_path)
    if not p.exists():
        return new

    for job_url in read_jsonl(p, JobUrl):
        if job_url.key in seen:
            continue                           # resume: skip already-fetched
        adapter = adapters.get(job_url.board)
        if adapter is None:
            adapter = adapters[job_url.board] = load_adapter(
                job_url.board, fixture_dir=fixture_dir,
                config=(cfg.get(job_url.board) or {}),
            )
        posting = adapter.fetch(job_url, live=live)
        _write_raw(cache_dir, posting)
        seen.add(posting.key)
        new.append(posting)
        _sleep(delay)                          # polite rate-limit, per request

    return new


def read_raw(board: str, job_id: str, cache_dir: str | Path = RAW_CACHE_DIR) -> RawPosting:
    """Load one cached C2 RawPosting back off disk."""
    path = Path(cache_dir) / board / f"{job_id}.json"
    d = json.loads(path.read_text(encoding="utf-8"))
    return contracts.from_dict(RawPosting, d)


# --------------------------------------------------------------------------- #
# small IO helpers
# --------------------------------------------------------------------------- #
def _append_jsonl(path: str | Path, rows: Iterable[Any]) -> None:
    """Append C1 records without clobbering earlier runs (write_jsonl truncates,
    so for resumable appends we merge)."""
    path = Path(path)
    existing = list(read_jsonl(path, JobUrl)) if path.exists() else []
    write_jsonl(path, existing + list(rows))


def _write_raw(cache_dir: Path, posting: RawPosting) -> Path:
    out = cache_dir / posting.board
    out.mkdir(parents=True, exist_ok=True)
    dest = out / f"{posting.job_id}.json"
    dest.write_text(
        json.dumps(contracts.to_dict(posting), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return dest


def _sleep(seconds: float) -> None:
    if seconds and seconds > 0:
        time.sleep(seconds)


# --------------------------------------------------------------------------- #
# CLI: python -m scraper.crawl [discover|fetch|all]
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else "all"
    cfg = load_config()
    if stage in ("discover", "all"):
        d = discover(cfg)
        print(f"discover: +{len(d)} new job urls -> {JOB_URLS_PATH}")
    if stage in ("fetch", "all"):
        f = fetch(cfg)
        print(f"fetch: +{len(f)} new raw postings -> {RAW_CACHE_DIR}")
