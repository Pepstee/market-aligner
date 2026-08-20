"""Public UK job-board adapters that do not require accounts or API keys.

These adapters use the boards' public search/RSS surfaces and fetch the public
vacancy page for the complete advert text.  They do not log in, solve bot
challenges, or emulate private browser APIs.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable
from urllib.parse import quote_plus, urljoin

from .base import Adapter, USER_AGENT, contracts_now, register
from .uk_common import plain_text
from contracts import JobUrl, RawPosting


def _requests_get(url: str, *, params: dict[str, Any] | None = None,
                  timeout: float = 30.0):
    import requests

    response = requests.get(
        url,
        params=params,
        headers={"User-Agent": USER_AGENT, "Accept-Language": "en-GB,en;q=0.9"},
        timeout=timeout,
    )
    response.raise_for_status()
    return response


def _canonical_links(html: str, base_url: str, pattern: str) -> list[tuple[str, str]]:
    """Return unique ``(board-local id, absolute URL)`` pairs from a page."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in re.finditer(pattern, html, flags=re.IGNORECASE):
        job_id = match.group("id")
        href = match.group("href").replace("&amp;", "&")
        if job_id in seen:
            continue
        seen.add(job_id)
        found.append((job_id, urljoin(base_url, href).split("?", 1)[0]))
    return found


def _first_tag_text(html: str, tag: str) -> str:
    match = re.search(
        rf"<{tag}\b[^>]*>(?P<value>.*?)</{tag}>", html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return plain_text(match.group("value")) if match else ""


class _PublicDetailMixin:
    _summaries: dict[str, dict[str, Any]]

    def _fetch_public_detail(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        response = _requests_get(
            job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        summary = dict(self._summaries.get(job.job_id) or {})
        page_text = plain_text(response.text)
        fallback_text = str(summary.get("description") or "")
        title = str(summary.get("title") or _first_tag_text(response.text, "h1")
                    or _first_tag_text(response.text, "title"))
        location = str(summary.get("location_text") or "")
        if not location and self.board == "nhsjobs":
            location = "United Kingdom"
        elif not location and self.board == "guardianjobs":
            location = "United Kingdom"
        elif not location and self.board == "jobsacuk":
            # Avoid treating most of the page as a location when labels repeat.
            # A giant match can contain "UK" even when the actual job is abroad.
            location_values = [
                match.group("value").strip()
                for match in re.finditer(
                    r"\bLocation:\s*(?P<value>.{1,180}?)\s+Salary:",
                    page_text,
                    flags=re.IGNORECASE,
                )
            ]
            location = min(location_values, key=len) if location_values else ""
        summary.update(
            title=title,
            location_text=location,
            content_text=page_text or fallback_text,
            detail_fetch_status=("full_page" if page_text else "listing_excerpt_only"),
            source_url=response.url,
            source_attribution=self.board,
        )
        return RawPosting(
            board=self.board,
            job_id=job.job_id,
            url=response.url,
            fetched_at=contracts_now(),
            raw_json=summary,
        )


@register
class GuardianJobsAdapter(_PublicDetailMixin, Adapter):
    """Guardian Jobs' public keyword RSS feed plus full public adverts."""

    board = "guardianjobs"
    RSS_URL = "https://jobs.theguardian.com/jobsrss/"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._summaries = {}

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        queries = list(cfg.get("queries") or terms)
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        seen: set[str] = set()
        for query in queries:
            response = _requests_get(
                self.RSS_URL,
                params={"keywords": query, "countrycode": "GB"},
                timeout=timeout,
            )
            root = ET.fromstring(response.content)
            for item in root.findall(".//item"):
                def value(name: str) -> str:
                    return str(item.findtext(name) or "").strip()

                url = value("link") or value("guid")
                match = re.search(r"/job/(?P<id>\d+)/", url)
                job_id = match.group("id") if match else hashlib.sha1(url.encode()).hexdigest()
                if not url or job_id in seen:
                    continue
                seen.add(job_id)
                self._summaries[job_id] = {
                    "title": value("title"),
                    "description": plain_text(value("description")),
                    "published_at": value("pubDate"),
                    "query": query,
                }
                yield JobUrl(self.board, job_id, url.split("?", 1)[0], value("pubDate") or None)

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        return self._fetch_public_detail(job)


@register
class NHSJobsAdapter(_PublicDetailMixin, Adapter):
    """The public NHS Jobs candidate search and vacancy pages."""

    board = "nhsjobs"
    SEARCH_URL = "https://www.jobs.nhs.uk/candidate/search/results"
    LINK_PATTERN = (
        r'href=["\'](?P<href>/candidate/jobadvert/(?P<id>[^?"\']+)[^"\']*)["\']'
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._summaries = {}

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        queries = list(cfg.get("queries") or terms)
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        max_pages = int(cfg.get("max_pages_per_query", 5) or 5)
        seen: set[str] = set()
        for query in queries:
            for page in range(1, max_pages + 1):
                response = _requests_get(
                    self.SEARCH_URL,
                    params={
                        "keyword": query,
                        "language": "en",
                        "page": page,
                        "skipPhraseSuggester": "true",
                    },
                    timeout=timeout,
                )
                links = _canonical_links(response.text, self.SEARCH_URL, self.LINK_PATTERN)
                fresh = 0
                for job_id, url in links:
                    if job_id in seen:
                        continue
                    seen.add(job_id)
                    fresh += 1
                    self._summaries[job_id] = {"query": query, "source": "NHS Jobs"}
                    yield JobUrl(self.board, job_id, url)
                if not links or fresh == 0:
                    break

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        return self._fetch_public_detail(job)


@register
class JobsAcUkAdapter(_PublicDetailMixin, Adapter):
    """jobs.ac.uk public search and full academic/technical job adverts."""

    board = "jobsacuk"
    SEARCH_URL = "https://www.jobs.ac.uk/search/"
    LINK_PATTERN = r'href=["\'](?P<href>/job/(?P<id>[A-Z0-9]+)/[^"\']*)["\']'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._summaries = {}

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        queries = list(cfg.get("queries") or terms)
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        page_size = int(cfg.get("page_size", 100) or 100)
        max_pages = int(cfg.get("max_pages_per_query", 4) or 4)
        seen: set[str] = set()
        for query in queries:
            for page in range(max_pages):
                response = _requests_get(
                    self.SEARCH_URL,
                    params={
                        "keywords": query,
                        "pageSize": page_size,
                        "sortOrder": 1,
                        "startIndex": page * page_size + 1,
                    },
                    timeout=timeout,
                )
                links = _canonical_links(response.text, self.SEARCH_URL, self.LINK_PATTERN)
                fresh = 0
                for job_id, url in links:
                    if job_id in seen:
                        continue
                    seen.add(job_id)
                    fresh += 1
                    self._summaries[job_id] = {"query": query, "source": "jobs.ac.uk"}
                    yield JobUrl(self.board, job_id, url)
                if not links or fresh == 0:
                    break

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        return self._fetch_public_detail(job)
