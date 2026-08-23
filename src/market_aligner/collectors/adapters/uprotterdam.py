"""Up!Rotterdam startup board public sitemap and complete Getro adverts."""

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
from .uk_common import plain_text, salary_text
from market_aligner.domain.contracts import JobUrl, RawPosting


BASE_URL = "https://jobs.uprotterdam.com"
SITEMAP_URL = f"{BASE_URL}/sitemap.xml"
TITLE_TERMS = (
    "ai", "artificial-intelligence", "machine-learning", "llm", "automation",
    "software", "python", "data-engineer", "cloud", "security", "cyber", "solutions",
    "technical", "developer", "technology", "systems-engineer", "devops", "platform",
    "infrastructure", "full-stack", "backend", "back-end",
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
                    f"transient Up!Rotterdam status {response.status_code}", response=response
                )
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last = exc
            if attempt < attempts:
                time.sleep(float(attempt))
    assert last is not None
    raise last


def _current_job(page: str) -> dict[str, Any]:
    match = re.search(
        r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', page, re.S
    )
    if not match:
        raise ValueError("Up!Rotterdam detail page omitted Next.js data")
    try:
        doc = json.loads(html.unescape(match.group(1)))
        job = doc["props"]["pageProps"]["initialState"]["jobs"]["currentJob"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("Up!Rotterdam detail page omitted currentJob") from exc
    if not isinstance(job, dict) or not job.get("title") or not job.get("description"):
        raise ValueError("Up!Rotterdam advert is inactive or has no complete description")
    return job


@register
class UpRotterdamAdapter(Adapter):
    board = "uprotterdam"

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
        for node in root.findall(".//{*}loc"):
            url = str(node.text or "").strip()
            parts = urlsplit(url).path.strip("/").split("/")
            if len(parts) != 4 or parts[0] != "companies" or parts[2] != "jobs":
                continue
            job_slug = parts[3]
            if not any(term in job_slug.casefold() for term in TITLE_TERMS):
                continue
            job_id = job_slug.split("-", 1)[0]
            if not job_id.isdigit() or job_id in seen:
                continue
            seen.add(job_id)
            yield JobUrl(self.board, job_id, url, None)

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        self._pace_detail_request()
        response = _get(job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30))
        data = _current_job(response.text)
        organization = data.get("organization") or {}
        if not isinstance(organization, dict):
            organization = {}
        locations = data.get("locations") or []
        location_text = "; ".join(
            str(row.get("description") or row.get("name") or "")
            for row in locations if isinstance(row, dict)
        ) or "Netherlands"
        data.update(
            company=str(organization.get("name") or ""),
            location_text=location_text,
            content_text=plain_text(data.get("description")),
            salary_text=salary_text(
                data.get("compensationAmountMinCents"), data.get("compensationAmountMaxCents"),
                data.get("compensationCurrency"), data.get("compensationPeriod"),
            ),
            original_apply_url=str(data.get("url") or ""),
            source_url=response.url,
            source_attribution="Up!Rotterdam",
            detail_fetch_status="full_page",
        )
        return RawPosting(
            board=self.board, job_id=job.job_id, url=response.url,
            fetched_at=contracts_now(), raw_json=data,
        )
