"""
scraper/adapters/notefolio.py — Notefolio (노트폴리오) adapter, live + fixture.

Notefolio is a design-native SPA (build spec §2: best for VMD/graphic/spatial).
The live implementation renders the recruit list + detail with Playwright and
extracts the embedded JSON / rendered content. This adapter is fixture-backed
against that JSON shape for offline tests:

    data/fixtures/notefolio_listing.json   — the recruits list ({"results": [...]})
    data/fixtures/notefolio/{id}.json        — the per-recruit detail JSON (description block)

Live URL comes from config (notefolio.recruit_url):
    recruit_url : https://notefolio.net/recruit

Notefolio is a clean JSON board, so fetch() returns raw_json (the description
block); we still render via Playwright because the pages are SPA-hydrated.

Playwright is lazy-imported INSIDE the live methods, so the module imports and
the fixture-driven self-test runs without Playwright installed.
"""

from __future__ import annotations

import json as _json
import re
import hashlib
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit
from typing import Any, Iterable

from .base import Adapter, JobUrl, RawPosting, USER_AGENT, contracts_now, register

NOTEFOLIO_RECRUIT_URL = "https://notefolio.net/recruit"


@register
class NotefolioAdapter(Adapter):
    board = "notefolio"

    # ------------------------------------------------------------------ #
    # FIXTURE path (live=False) — used by tests.
    # ------------------------------------------------------------------ #
    def _load_listing(self) -> list[dict[str, Any]]:
        import json
        path = self.fixture_dir / "notefolio_listing.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        return list(data.get("results", []))

    def _searchable_text(self, entry: dict[str, Any]) -> str:
        return " ".join(str(x) for x in (
            entry.get("title", ""),
            entry.get("company_name", ""),
            " ".join(entry.get("categories", []) or []),
        ))

    def _to_job_url(self, entry: dict[str, Any]) -> JobUrl:
        job_id = str(entry["id"])
        return JobUrl(
            board=self.board,
            job_id=job_id,
            url=self._detail_url(job_id),
            posted_at=entry.get("created_at"),
        )

    def _detail_url(self, job_id: str) -> str:
        cfg = self._config or {}
        base = (cfg.get("recruit_url") or NOTEFOLIO_RECRUIT_URL).rstrip("/")
        # detail pages hang off the recruit base, e.g. /recruit/{id} (recruits/{id}
        # historically). Confirm the exact path in your env.
        return f"{base}/{job_id}"

    def fetch(self, job_url: JobUrl, live: bool = False) -> RawPosting:
        if live:
            return self._fetch_live(job_url)
        detail = self._load_detail(job_url.job_id)
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=detail,      # clean JSON board -> raw_json
        )

    # ------------------------------------------------------------------ #
    # LIVE path (live=True) — Playwright render then extract.
    # ------------------------------------------------------------------ #
    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        """Render the recruit list per term; extract embedded state, recruit
        anchors, and donor banner-link external listings with scrolling."""
        from playwright.sync_api import sync_playwright  # lazy import

        cfg = self._board_config()
        recruit_url = (cfg.get("recruit_url") or NOTEFOLIO_RECRUIT_URL).rstrip("/")
        max_scrolls = max(1, int(cfg.get("max_scrolls", 100) or 100))
        scroll_wait_ms = max(250, int(cfg.get("scroll_wait_ms", 1200) or 1200))
        drop_params = {"oem_code", "ref"}

        seen_ids: set[str] = set()
        seen_urls: set[str] = set()
        collected: list[JobUrl] = []

        def _track(job_id: str, url: str, posted_at: Any) -> JobUrl | None:
            if not job_id or job_id in seen_ids:
                return
            if url and url in seen_urls:
                return
            seen_ids.add(job_id)
            if url:
                seen_urls.add(url)
            row = JobUrl(board=self.board, job_id=job_id, url=url, posted_at=posted_at)
            collected.append(row)
            return row

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent=USER_AGENT)
            try:
                for kw in terms or [""]:
                    url = (
                        f"{recruit_url}?search={quote_plus(kw)}" if kw else recruit_url
                    )
                    page.goto(url, wait_until="networkidle", timeout=45000)
                    page.wait_for_timeout(scroll_wait_ms)

                    unchanged = 0
                    for _ in range(max_scrolls):
                        before = len(collected)

                        # 1) Canonical: embedded __NEXT_DATA__ state.
                        results: list[dict[str, Any]] = []
                        try:
                            raw = page.evaluate(
                                "() => (window.__NEXT_DATA__ "
                                "&& JSON.stringify(window.__NEXT_DATA__)) || null"
                            )
                            if raw:
                                results = self._extract_results(_json.loads(raw))
                        except Exception:
                            results = []

                        if results:
                            for entry in results:
                                job_id = str(
                                    entry.get("id") or entry.get("slug") or ""
                                )
                                added = _track(
                                    job_id,
                                    self._detail_url(job_id) if job_id else "",
                                    entry.get("created_at"),
                                )
                                if added is not None:
                                    yield added
                        else:
                            # 2) Canonical fallback: recruit anchor hrefs.
                            hrefs = page.eval_on_selector_all(
                                "a[href*='/recruit']",
                                "els => els.map(e => e.getAttribute('href'))",
                            )
                            for href in hrefs or []:
                                m = re.search(r"/recruit[s]?/([^/?#]+)", href or "")
                                if not m:
                                    continue
                                job_id = m.group(1)
                                added = _track(job_id, self._detail_url(job_id), None)
                                if added is not None:
                                    yield added

                        # 3) Donor: external banner-link listings.
                        banners = page.eval_on_selector_all(
                            "a.banner-link[href]",
                            """els => els.map(e => ({
                                href: e.href || e.getAttribute("href") || "",
                                text: (e.innerText || e.textContent || "")
                                    .replace(/\\s+/g, " ").trim()
                            })).filter(x => x.href && x.text)""",
                        )
                        for banner in banners or []:
                            href = str(banner.get("href") or "").strip()
                            parts = urlsplit(href)
                            if parts.scheme not in {"http", "https"} or not parts.netloc:
                                continue
                            query = urlencode(
                                [
                                    (key, value)
                                    for key, value in parse_qsl(
                                        parts.query, keep_blank_values=True
                                    )
                                    if not key.lower().startswith("utm_")
                                    and key.lower() not in drop_params
                                ]
                            )
                            normalised = urlunsplit(
                                (
                                    parts.scheme.lower(),
                                    parts.netloc.lower(),
                                    parts.path.rstrip("/") or "/",
                                    query,
                                    "",
                                )
                            )
                            if normalised in seen_urls:
                                continue
                            job_id = hashlib.sha256(
                                normalised.encode("utf-8")
                            ).hexdigest()[:20]
                            added = _track(job_id, href, None)
                            seen_urls.add(normalised)
                            if added is not None:
                                yield added

                        unchanged = (
                            unchanged + 1 if len(collected) == before else 0
                        )
                        if unchanged >= 3:
                            break
                        page.evaluate(
                            "window.scrollTo(0, document.body.scrollHeight)"
                        )
                        page.wait_for_timeout(scroll_wait_ms)
            finally:
                browser.close()


    @staticmethod
    def _extract_results(next_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Best-effort dig for the recruit results list inside a __NEXT_DATA__
        blob. TODO: confirm the exact path in your env."""
        try:
            props = next_data.get("props", {}).get("pageProps", {})
        except AttributeError:
            return []
        for key in ("results", "recruits", "jobs", "items"):
            val = props.get(key)
            if isinstance(val, list):
                return val
            if isinstance(val, dict) and isinstance(val.get("results"), list):
                return val["results"]
        return []

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        """Render the detail page and pull the recruit JSON / description block."""
        from playwright.sync_api import sync_playwright  # lazy import

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent=USER_AGENT)
            detail: dict[str, Any] = {"id": job_url.job_id, "url": job_url.url}
            html = None
            embedded = False
            try:
                page.goto(job_url.url, wait_until="domcontentloaded", timeout=45000)
                page.wait_for_timeout(1000)
                try:
                    raw = page.evaluate(
                        "() => (window.__NEXT_DATA__ "
                        "&& JSON.stringify(window.__NEXT_DATA__)) || null"
                    )
                    if raw:
                        props = _json.loads(raw).get("props", {}).get("pageProps", {})
                        rec = props.get("recruit") or props.get("data") or {}
                        if isinstance(rec, dict) and rec:
                            detail.update(rec)
                            embedded = any(
                                key not in {"id", "url"} and value not in (None, "", [], {})
                                for key, value in rec.items()
                            )
                except Exception:
                    pass
                if "description" not in detail:
                    try:
                        if page.locator("main").count():
                            detail["description_text"] = page.inner_text("main")
                    except Exception:
                        pass
                for selector in ("main", "article", "body"):
                    try:
                        if not page.locator(selector).count():
                            continue
                        candidate = page.inner_html(selector)
                        if candidate and len(candidate) >= 200:
                            html = candidate
                            break
                    except Exception:
                        continue
                if html:
                    detail["rendered_title"] = page.title()
                    detail["source"] = "playwright"
            finally:
                browser.close()

        description = detail.get("description_text")
        has_description = isinstance(description, str) and bool(description.strip())
        if not embedded and not html and not has_description:
            raise RuntimeError(f"Notefolio detail body missing for {job_url.job_id}")

        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=detail,      # clean JSON board -> raw_json
            raw_text=html,
        )
