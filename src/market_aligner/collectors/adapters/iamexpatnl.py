"""IamExpat Netherlands public sitemap and complete JobPosting adverts."""

from __future__ import annotations

import html
import json
import re
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Iterable
from urllib.parse import urlsplit

from .base import Adapter, USER_AGENT, contracts_now, register
from .uk_common import plain_text
from market_aligner.domain.contracts import JobUrl, RawPosting


SITEMAP_INDEX = "https://www.iamexpat.nl/sitemap.xml"
JOB_PREFIX = ("career", "jobs-netherlands")
TITLE_TERMS = (
    "ai", "artificial-intelligence", "machine-learning", "llm", "automation",
    "software", "python", "data", "cloud", "security", "cyber", "solutions",
    "technical", "developer", "technology", "systems-engineer", "devops", "platform",
)


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
                    f"transient IamExpat status {response.status_code}", response=response
                )
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last = exc
            if attempt < attempts:
                time.sleep(float(attempt))
    assert last is not None
    raise last


def _nested_jobposting(page: str) -> dict[str, Any]:
    """Decode Next.js script props whose ``children`` is JSON-LD text."""
    pattern = re.compile(r'"children":"((?:\\.|[^"\\])*)"', re.S)
    for match in pattern.finditer(page):
        encoded = match.group(1)
        if "JobPosting" not in encoded:
            continue
        try:
            text = json.loads(f'"{encoded}"')
            value = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(value, dict) and value.get("@type") == "JobPosting":
            return value
    raise ValueError("IamExpat detail page omitted JobPosting JSON-LD")


def _location(value: Any) -> str:
    rows = value if isinstance(value, list) else [value]
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        address = row.get("address") or {}
        if not isinstance(address, dict):
            continue
        text = ", ".join(str(address.get(k)) for k in
                         ("addressLocality", "addressRegion", "addressCountry") if address.get(k))
        if text:
            found.append(text)
    return "; ".join(found) or "Netherlands"


@register
class IamExpatNLAdapter(Adapter):
    board = "iamexpatnl"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._request_lock = threading.Lock()
        self._next_detail_request = 0.0

    def _pace_detail_request(self) -> None:
        interval = float(self._board_config().get("detail_request_interval_seconds", 1.0) or 0)
        if not interval:
            return
        with self._request_lock:
            delay = self._next_detail_request - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._next_detail_request = time.monotonic() + interval

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        index = ET.fromstring(_get(SITEMAP_INDEX, timeout=timeout).content)
        sitemap_urls = [str(node.text or "").strip() for node in index.findall(".//{*}loc")]
        seen: set[str] = set()
        for sitemap_url in sitemap_urls:
            root = ET.fromstring(_get(sitemap_url, timeout=timeout).content)
            for node in root.findall(".//{*}loc"):
                url = str(node.text or "").strip()
                parts = urlsplit(url).path.strip("/").split("/")
                if len(parts) != 5 or tuple(parts[:2]) != JOB_PREFIX:
                    continue
                category, slug, job_id = parts[2], parts[3], parts[4]
                relevant = category == "it-technology-positions" or any(
                    term in slug.casefold() for term in TITLE_TERMS
                )
                if not relevant or job_id in seen:
                    continue
                seen.add(job_id)
                yield JobUrl(self.board, job_id, url, None)

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        self._pace_detail_request()
        response = _get(job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30))
        data = _nested_jobposting(response.text)
        company = data.get("hiringOrganization") or {}
        if not isinstance(company, dict):
            company = {}
        data.update(
            title=str(data.get("title") or ""),
            company=str(company.get("name") or ""),
            location_text=_location(data.get("jobLocation")),
            content_text=plain_text(data.get("description")),
            source_url=response.url,
            source_attribution="IamExpat Netherlands",
            detail_fetch_status="full_page",
        )
        return RawPosting(
            board=self.board, job_id=job.job_id, url=response.url,
            fetched_at=contracts_now(), raw_json=data,
        )
