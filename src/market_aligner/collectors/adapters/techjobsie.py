"""TechJobs.ie sitemap discovery and complete public vacancy pages.

The board publishes a crawlable sitemap and links each listing back to the
original employer vacancy.  We retain both URLs and the complete requirements
text while leaving UK-residence compatibility to the deterministic gate.
"""

from __future__ import annotations

import hashlib
import html
import re
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Iterable

from .base import Adapter, USER_AGENT, contracts_now, register
from .uk_common import plain_text
from market_aligner.domain.contracts import JobUrl, RawPosting


BASE_URL = "https://techjobs.ie"
SITEMAP_URL = f"{BASE_URL}/sitemap.xml"
JOB_PATH = re.compile(r"^https://techjobs\.ie/jobs/([^/]+)/([^/]+)$", re.I)


def _get(url: str, *, timeout: float = 30.0, attempts: int = 3):
    import requests

    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            response = requests.get(
                url,
                headers={"User-Agent": USER_AGENT, "Accept-Language": "en-GB,en;q=0.9"},
                timeout=timeout,
            )
            if response.status_code == 429 or response.status_code >= 500:
                raise requests.HTTPError(
                    f"transient TechJobs.ie status {response.status_code}", response=response
                )
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last = exc
            if attempt < attempts:
                time.sleep(float(attempt))
    assert last is not None
    raise last


def _match(page: str, pattern: str, *, flags: int = 0) -> str:
    found = re.search(pattern, page, flags)
    return html.unescape(found.group(1)).strip() if found else ""


def _parse_detail(page: str, source_url: str) -> dict[str, Any]:
    title = plain_text(_match(page, r'<h1\b[^>]*>(.*?)</h1>', flags=re.S | re.I))
    company = plain_text(_match(
        page, r'<div\b[^>]*class="[^"]*text-base text-gray-600[^"]*"[^>]*>(.*?)</div>',
        flags=re.S | re.I,
    ))
    header = _match(
        page,
        r'<div\b[^>]*class="[^"]*flex flex-wrap items-center gap-3 text-gray-500 text-sm[^"]*"'
        r'[^>]*>(.*?)</div>',
        flags=re.S | re.I,
    )
    header_parts = [plain_text(value) for value in re.findall(r'<span[^>]*>(.*?)</span>', header, re.S | re.I)]
    location = next(
        (part for part in reversed(header_parts) if "ireland" in part.casefold() or "remote" in part.casefold()),
        "Ireland",
    )
    content_html = _match(
        page,
        r'<div\b[^>]*class="[^"]*markdown-content[^"]*"[^>]*>(.*?)</div></div>'
        r'<div\b[^>]*class="mt-8"',
        flags=re.S | re.I,
    )
    content = plain_text(content_html)
    apply_url = _match(
        page, r'<a\b[^>]*href="([^"]+)"[^>]*>\s*Apply Now', flags=re.S | re.I
    )
    deadline = _match(page, r'Apply before:<!-- -->\s*<!-- -->([^<]+)</span>', flags=re.I)
    if not deadline:
        deadline = _match(page, r'Apply before:?\s*(?:<!--[^>]*-->\s*)*([^<]+)<', flags=re.I)
    if not title or len(content) < 80:
        raise ValueError("TechJobs.ie detail page omitted title or complete description")
    return {
        "title": title,
        "company": company,
        "location_text": location,
        "content_text": content,
        "description": content,
        "application_deadline": deadline,
        "source_url": source_url,
        "original_apply_url": apply_url,
        "source_attribution": "TechJobs.ie",
        "detail_fetch_status": "full_page",
    }


@register
class TechJobsIEAdapter(Adapter):
    board = "techjobsie"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._request_lock = threading.Lock()
        self._next_detail_request = 0.0

    def _pace_detail_request(self) -> None:
        interval = float(self._board_config().get("detail_request_interval_seconds", 0.2) or 0)
        if not interval:
            return
        with self._request_lock:
            delay = self._next_detail_request - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._next_detail_request = time.monotonic() + interval

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        response = _get(SITEMAP_URL, timeout=float(cfg.get("timeout_seconds", 30) or 30))
        root = ET.fromstring(response.content)
        seen: set[str] = set()
        for row in root.findall("{*}url"):
            url = str(row.findtext("{*}loc") or "").strip()
            match = JOB_PATH.match(url)
            if not match:
                continue
            category, slug = match.groups()
            # Slugs carry the job title. Keep all target families even if the
            # same advert is filed under a broad adjacent category.
            searchable = f"{category} {slug}".replace("-", " ").casefold()
            if terms and not any(term.casefold() in searchable for term in terms):
                target_categories = set(cfg.get("categories") or ())
                if category not in target_categories:
                    continue
            job_id = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
            if job_id in seen:
                continue
            seen.add(job_id)
            posted = str(row.findtext("{*}lastmod") or "").strip() or None
            yield JobUrl(self.board, job_id, url, posted)

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        self._pace_detail_request()
        response = _get(job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30))
        data = _parse_detail(response.text, response.url)
        return RawPosting(
            board=self.board,
            job_id=job.job_id,
            url=response.url,
            fetched_at=contracts_now(),
            raw_json=data,
        )
