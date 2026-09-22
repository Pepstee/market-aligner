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
import time
from urllib.parse import parse_qs, quote_plus, urlparse
from typing import Any, Iterable

from .base import Adapter, JobUrl, RawPosting, USER_AGENT, contracts_now, register

JOBKOREA_SEARCH_URL = "https://www.jobkorea.co.kr/Search/?stext={kw}"
JOBKOREA_DETAIL_URL = "https://www.jobkorea.co.kr/Recruit/GI_Read/{id}"


def _looks_entry_level_listing(text: str) -> bool:
    """Conservative listing-level gate used before expensive detail fetches."""
    return bool(re.search(r"신입|경력무관", text or "", flags=re.IGNORECASE))


def _is_organic_listing_href(href: str, search_code: str = "630") -> bool:
    """Exclude recommendation/ad carousels mixed into search pages."""
    return (parse_qs(urlparse(href or "").query).get("sc") or [""])[0] == search_code

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
        """Render paged JobKorea search results and extract recruit rows.

        The donor implementation targets the 2026-07 search structure: result links carry
        ``/Recruit/GI_Read/{id}``, while each card's rendered text carries the
        entry/seniority label. ``entry_only`` avoids spending detail requests
        on experienced-only positions during the calibration crawl.
        """
        from playwright.sync_api import sync_playwright  # lazy import

        cfg = self._board_config()
        search_tpl = cfg.get("search_url") or JOBKOREA_SEARCH_URL
        max_pages = max(1, int(cfg.get("max_pages", 1) or 1))
        entry_only = bool(cfg.get("entry_only", False))
        organic_search_code = str(cfg.get("organic_search_code", "630"))
        delay = max(0.0, float(cfg.get("rate_limit_seconds", 2.0) or 0.0))

        seen_ids: set[str] = set()
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent=USER_AGENT)
            try:
                for kw in terms or [""]:
                    base_url = search_tpl.format(kw=quote_plus(kw))
                    for page_no in range(1, max_pages + 1):
                        sep = "&" if "?" in base_url else "?"
                        url = f"{base_url}{sep}Page_No={page_no}"
                        page.goto(url, wait_until="domcontentloaded", timeout=45000)
                        page.wait_for_selector(
                            "main a[href*='/Recruit/GI_Read/']", timeout=30000
                        )
                        records = page.eval_on_selector_all(
                            "main a[href*='/Recruit/GI_Read/']",
                            r"""els => {
                              const byId = new Map();
                              const titles = els.filter(a =>
                                typeof a.className === 'string' &&
                                a.className.includes('max-w-[700px]') &&
                                (a.innerText || '').trim()
                              );
                              for (const a of titles) {
                                const href = a.href || a.getAttribute('href') || '';
                                const match = href.match(/GI_Read\/(\d+)/);
                                if (!match) continue;
                                const id = match[1];
                                const card = a.closest('div.w-full');
                                const text = (card?.innerText || a.innerText || '').trim();
                                if (text.length > 0 && text.length < 2500) {
                                  byId.set(id, {
                                    id,
                                    href,
                                    title: (a.innerText || '').trim(),
                                    text
                                  });
                                }
                              }
                              return Array.from(byId.values());
                            }""",
                        )
                        for record in records or []:
                            job_id = str(record.get("id", ""))
                            if not job_id or job_id in seen_ids:
                                continue
                            if not _is_organic_listing_href(
                                str(record.get("href", "")), organic_search_code
                            ):
                                continue
                            if entry_only and not _looks_entry_level_listing(
                                str(record.get("text", ""))
                            ):
                                continue
                            seen_ids.add(job_id)
                            yield JobUrl(
                                board=self.board,
                                job_id=job_id,
                                url=self._detail_url(job_id),
                                posted_at=None,
                            )
                        if delay and page_no < max_pages:
                            time.sleep(delay)
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
