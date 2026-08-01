"""
scraper/adapters/jobkorea.py — JobKorea (jobkorea.co.kr) adapter, live + fixture.

JobKorea has no public API (build spec §2): it's an SPA/HTML board, so the live
implementation renders listing + detail pages with Playwright and extracts the
rows/JD from the rendered DOM. This adapter is fixture-backed with the same
shape for offline tests:

    data/fixtures/jobkorea_listing.json   — the listing page's embedded state ({"recruits": [...]})
    data/fixtures/jobkorea/{id}.json       — a detail record whose `html` is the rendered JD body

Live URLs come from config (jobkorea.search_url / jobkorea.detail_url):
    search_url : https://www.jobkorea.co.kr/Search/?stext={kw}
    detail_url : https://www.jobkorea.co.kr/Recruit/GI_Read/{id}

Because JobKorea is HTML-first, fetch() returns the JD in raw_text (the LLM
extractor consumes HTML for these boards); raw_json keeps light metadata.

Playwright is lazy-imported INSIDE the live methods, so the module imports and
the fixture-driven self-test runs without Playwright installed.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .base import Adapter, JobUrl, RawPosting, USER_AGENT, contracts_now, register

JOBKOREA_SEARCH_URL = "https://www.jobkorea.co.kr/Search/?stext={kw}"
JOBKOREA_DETAIL_URL = "https://www.jobkorea.co.kr/Recruit/GI_Read/{id}"


@register
class JobKoreaAdapter(Adapter):
    board = "jobkorea"

    # ------------------------------------------------------------------ #
    # FIXTURE path (live=False) — used by tests.
    # ------------------------------------------------------------------ #
    def _load_listing(self) -> list[dict[str, Any]]:
        import json
        path = self.fixture_dir / "jobkorea_listing.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        return list(data.get("recruits", []))

    def _searchable_text(self, entry: dict[str, Any]) -> str:
        return " ".join(str(x) for x in (
            entry.get("title", ""),
            entry.get("company", ""),
            " ".join(entry.get("tags", []) or []),
        ))

    def _to_job_url(self, entry: dict[str, Any]) -> JobUrl:
        job_id = str(entry["id"])
        return JobUrl(
            board=self.board,
            job_id=job_id,
            url=entry.get("url") or self._detail_url(job_id),
            posted_at=entry.get("posted_at"),
        )

    def _detail_url(self, job_id: str) -> str:
        cfg = self._config or {}
        return (cfg.get("detail_url") or JOBKOREA_DETAIL_URL).format(id=job_id)

    def fetch(self, job_url: JobUrl, live: bool = False) -> RawPosting:
        if live:
            return self._fetch_live(job_url)
        detail = self._load_detail(job_url.job_id)
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_text=detail.get("html"),                      # HTML board -> raw_text
            raw_json={k: v for k, v in detail.items() if k != "html"},
        )

    # ------------------------------------------------------------------ #
    # LIVE path (live=True) — Playwright render then extract.
    # ------------------------------------------------------------------ #
    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        """Render the search page per term with Playwright and extract recruit
        rows. Selectors are best-effort; confirm them in your env.
        """
        from playwright.sync_api import sync_playwright  # lazy import

        cfg = self._board_config()
        search_tpl = cfg.get("search_url") or JOBKOREA_SEARCH_URL

        seen_ids: set[str] = set()
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent=USER_AGENT)
            try:
                for kw in terms or [""]:
                    page.goto(search_tpl.format(kw=kw), wait_until="networkidle", timeout=45000)
                    # TODO: confirm selector in your env — JobKorea's result list
                    # anchors carry the recruit id in the GI_Read/{id} href.
                    hrefs = page.eval_on_selector_all(
                        "a[href*='GI_Read']",
                        "els => els.map(e => e.getAttribute('href'))",
                    )
                    for href in hrefs or []:
                        m = re.search(r"GI_Read/(\d+)", href or "")
                        if not m:
                            continue
                        job_id = m.group(1)
                        if job_id in seen_ids:
                            continue
                        seen_ids.add(job_id)
                        yield JobUrl(
                            board=self.board,
                            job_id=job_id,
                            url=self._detail_url(job_id),
                            posted_at=None,
                        )
            finally:
                browser.close()

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        """Render the detail page and pull the JD block HTML into raw_text."""
        from playwright.sync_api import sync_playwright  # lazy import

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent=USER_AGENT)
            try:
                page.goto(job_url.url, wait_until="networkidle", timeout=45000)
                # TODO: confirm selector in your env — the JD body container.
                # ".detailArea" / ".tbCol" / ".dt" are the historical containers;
                # fall back to the whole body if the specific block is absent.
                html = None
                for sel in (".detailArea", "#tab02", ".secReadItem", "body"):
                    try:
                        html = page.inner_html(sel)
                        if html:
                            break
                    except Exception:
                        continue
                title = None
                try:
                    title = page.title()
                except Exception:
                    pass
            finally:
                browser.close()

        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_text=html,                                    # HTML board -> raw_text
            raw_json={"id": job_url.job_id, "url": job_url.url, "title": title},
        )
