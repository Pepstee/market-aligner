"""
The Adapter interface every board implements.

An Adapter is the seam between "a job board" and the crawl orchestrator. It
exposes exactly two capabilities, both defined in terms of the frozen
versioned product contracts:

    discover(search_terms) -> Iterable[JobUrl]     # C1 records
    fetch(job_url)         -> RawPosting           # C2 record

Everything else — rate limiting, the seen/resume set, JSONL IO, the raw cache
layout — lives in crawl.py, so an adapter stays a thin, testable "given these
search terms, here are the URLs; given a URL, here is the raw posting".

Design notes:
  * Discovery is paged and keyword-driven on the live boards; here it reads a
    per-board listing fixture so the shape is identical without a network hop.
  * fetch() returns the raw posting UNPARSED into the C2 shape: JSON boards
    populate raw_json, HTML boards populate raw_text. The LLM module does the
    structured extraction downstream (Architecture.md: extraction is horizontal).
  * Each concrete adapter marks `# TODO: wire live endpoint` at the exact point
    the real api.wanted.co.kr / oapi.saramin.co.kr / Playwright call goes.

Stdlib only.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Iterable, Optional

import market_aligner.domain.contracts as contracts
from market_aligner.domain.contracts import JobUrl, RawPosting

# Where each board's hand-made sample postings live. Fixtures sit OUTSIDE
# scraper/data/ on purpose: data/ holds mutable stage outputs and is safe to
# `rm -rf`; fixtures are version-controlled test inputs.
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures"


class SourceUnavailable(RuntimeError):
    """A configured source cannot run until an external prerequisite exists.

    This is deliberately distinct from a network failure: the collector reports
    a missing API key once and keeps every other source running.
    """


class Adapter:
    """Interface + shared fixture plumbing for a single job board.

    Concrete boards subclass this and either reuse the fixture-backed
    `discover`/`fetch` below (overriding the small `_parse_*` hooks) or replace
    them wholesale once the live endpoint is wired.
    """

    #: board id — must be one of the contract's board literals.
    board: str = ""

    def __init__(self, fixture_dir: Optional[Path] = None,
                 config: Optional[dict[str, Any]] = None) -> None:
        self.fixture_dir = Path(fixture_dir) if fixture_dir else FIXTURE_DIR
        # Per-board configuration is injected from external operator config.
        self._config = config

    # -- capability 1: discover --------------------------------------------- #
    def discover(self, search_terms: Iterable[str], live: bool = False) -> Iterable[JobUrl]:
        """Yield C1 JobUrl records for postings matching any search term.

        ``live=False`` (default, used by tests): reads
        ``{fixture_dir}/{board}_listing.json`` (a saved copy of the board's
        listing/search response) and filters by term — no network, no deps.
        ``live=True``: pages the real search endpoint (see the concrete board's
        ``_discover_live``); ``requests``/``playwright`` are imported lazily
        only on that branch.
        """
        terms = [t for t in search_terms]
        if live:
            yield from self._discover_live(terms)
            return
        lowered = [t.lower() for t in terms]
        for entry in self._load_listing():
            if lowered and not self._matches(entry, lowered):
                continue
            yield self._to_job_url(entry)

    # -- capability 2: fetch ------------------------------------------------- #
    def fetch(self, job_url: JobUrl, live: bool = False) -> RawPosting:
        """Fetch one posting's detail and return it as a C2 RawPosting.

        ``live=False`` (default, used by tests): reads
        ``{fixture_dir}/{board}/{job_id}.json``. ``live=True``: hits the per-job
        detail endpoint (JSON boards) or renders the detail page (HTML/Playwright
        boards) via the concrete board's ``_fetch_live``.
        """
        if live:
            return self._fetch_live(job_url)
        detail = self._load_detail(job_url.job_id)
        return self._to_raw_posting(job_url, detail)

    # -- live hooks (subclasses override with real request logic) ----------- #
    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        raise NotImplementedError(
            f"{type(self).__name__}._discover_live is not wired; live discovery "
            f"unavailable for board '{self.board}'."
        )

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        raise NotImplementedError(
            f"{type(self).__name__}._fetch_live is not wired; live fetch "
            f"unavailable for board '{self.board}'."
        )

    # -- hooks a subclass can override -------------------------------------- #
    def _matches(self, entry: dict[str, Any], terms: list[str]) -> bool:
        """Does this listing entry match any (lower-cased) search term?

        Default: substring match against the entry's searchable text blob.
        Korean and English terms both work because we match raw substrings.
        """
        blob = self._searchable_text(entry).lower()
        return any(t in blob for t in terms)

    def _searchable_text(self, entry: dict[str, Any]) -> str:
        """Fields to match search terms against. Boards override for their shape."""
        parts = [
            str(entry.get("title", "")),
            str(entry.get("company", "")),
            " ".join(str(x) for x in entry.get("tags", []) or []),
            str(entry.get("category", "")),
        ]
        return " ".join(parts)

    def _to_job_url(self, entry: dict[str, Any]) -> JobUrl:
        """Map a raw listing entry -> C1. Boards override for their id/url shape."""
        job_id = str(entry["id"])
        return JobUrl(
            board=self.board,
            job_id=job_id,
            url=entry.get("url") or self._detail_url(job_id),
            posted_at=entry.get("posted_at"),
        )

    def _to_raw_posting(self, job_url: JobUrl, detail: dict[str, Any]) -> RawPosting:
        """Map a raw detail payload -> C2. JSON boards keep raw_json; HTML boards
        set raw_text. Default treats the payload as JSON."""
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=detail,
        )

    def _detail_url(self, job_id: str) -> str:
        """Synthesize a detail URL when the listing doesn't carry one."""
        return f"https://{self.board}.example/jobs/{job_id}"

    # -- fixture IO --------------------------------------------------------- #
    def _load_listing(self) -> list[dict[str, Any]]:
        path = self.fixture_dir / f"{self.board}_listing.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        # Listing fixtures may be a bare list or {"data": [...]} (API style).
        if isinstance(data, dict):
            return list(data.get("data") or data.get("jobs") or [])
        return list(data)

    def _load_detail(self, job_id: str) -> dict[str, Any]:
        path = self.fixture_dir / self.board / f"{job_id}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    # -- config access (for live branches only) ----------------------------- #
    def _board_config(self) -> dict[str, Any]:
        """Return injected board configuration; source trees are never consulted."""
        if self._config is None:
            raise ValueError(
                f"live adapter '{self.board}' requires explicitly injected configuration"
            )
        return self._config


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def http_get_json(url: str, *, params: Optional[dict[str, Any]] = None,
                  headers: Optional[dict[str, str]] = None, timeout: float = 30.0,
                  attempts: int = 3, backoff: float = 2.0, session: Any = None) -> Any:
    """GET → parsed JSON, with small retries on transient network errors.

    Lazy-imports requests (live branches only). Retries DNS/connection/timeout
    errors and 5xx responses with linear backoff; re-raises the last error after
    `attempts`. Keeps a long crawl alive through momentary blips."""
    import time as _time

    import requests  # lazy: only imported on the live branch

    last: Optional[Exception] = None
    for i in range(1, attempts + 1):
        try:
            if session is not None:
                resp = session.get(url, params=params, timeout=timeout)
            else:
                resp = requests.get(url, params=params, headers=headers, timeout=timeout)
            if resp.status_code >= 500:
                raise requests.exceptions.HTTPError(f"server error {resp.status_code}")
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # noqa: BLE001 — DNS, conn reset, timeout, 5xx…
            last = exc
            if i < attempts:
                _time.sleep(backoff * i)
    assert last is not None
    raise last


def contracts_now() -> str:
    """ISO-8601 UTC timestamp for RawPosting.fetched_at (stdlib only)."""
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# A descriptive browser-compatible user agent for public vacancy endpoints.
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36 MarketAligner/1.0"
)


# Registry of concrete adapters, filled in by each board module on import.
ADAPTERS: dict[str, type[Adapter]] = {}
_IMPORT_LOCK = threading.Lock()
_IMPORTS_COMPLETE = False


def register(cls: type[Adapter]) -> type[Adapter]:
    """Decorator: register a concrete adapter under its board id."""
    if not cls.board:
        raise ValueError(f"{cls.__name__} must set a non-empty .board")
    ADAPTERS[cls.board] = cls
    return cls


def load_adapter(board: str, fixture_dir: Optional[Path] = None,
                 config: Optional[dict[str, Any]] = None) -> Adapter:
    """Instantiate the adapter for a board id, importing board modules lazily.

    ``config`` is required for live runs. Offline fixture runs may leave it unset.
    """
    if not _IMPORTS_COMPLETE:
        _import_all()
    if board not in ADAPTERS:
        raise KeyError(f"no adapter registered for board '{board}'. "
                       f"Known: {sorted(ADAPTERS)}")
    return ADAPTERS[board](fixture_dir=fixture_dir, config=config)


def _import_all() -> None:
    """Import every board module so they self-register."""
    global _IMPORTS_COMPLETE
    with _IMPORT_LOCK:
        if _IMPORTS_COMPLETE:
            return
        from . import (  # noqa: F401
            adzuna,
            ashby,
            arbeitnow,
            greenhouse,
            jobicy,
            jobsch,
            jobscout24,
            jooble,
            lever,
            himalayas,
            iamexpatnl,
            ireland_boards,
            muse,
            personio,
            public_uk_boards,
            recruitee,
            remotive,
            remoteok,
            remotefirst,
            reed,
            smartrecruiters,
            techjobsie,
            netherlands_boards,
            switzerland_boards,
            uprotterdam,
            workable,
            workday,
            weworkremotely,
            wanted,
            saramin,
            jobkorea,
            notefolio,
        )
        _IMPORTS_COMPLETE = True
