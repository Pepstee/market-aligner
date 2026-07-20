"""jobs.ch public Swiss vacancy search and complete JobPosting details."""

from __future__ import annotations

import html
import json
import threading
import time
from typing import Any, Iterable
from urllib.parse import urljoin

from .base import Adapter, USER_AGENT, contracts_now, register
from .uk_common import plain_text, salary_text
from contracts import JobUrl, RawPosting


BASE_URL = "https://www.jobs.ch"
SEARCH_URL = f"{BASE_URL}/en/vacancies/"


def _get(
    url: str, *, params: dict[str, Any] | None = None, timeout: float = 30.0,
    attempts: int = 3,
):
    import requests

    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            response = requests.get(
                url,
                params=params,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept-Language": "en-GB,en;q=0.9,de;q=0.7,fr;q=0.6",
                },
                timeout=timeout,
            )
            if response.status_code in (403, 429) or response.status_code >= 500:
                raise requests.HTTPError(
                    f"transient jobs.ch status {response.status_code}", response=response
                )
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last = exc
            if attempt < attempts:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                time.sleep(float(5 * attempt if status in (403, 429) else attempt))
    assert last is not None
    raise last


def _assigned_json(page: str, variable: str) -> dict[str, Any]:
    marker = f"{variable} = "
    start = page.find(marker)
    if start < 0:
        raise ValueError(f"jobs.ch page omitted {variable}")
    value, _ = json.JSONDecoder().raw_decode(page[start + len(marker):])
    if not isinstance(value, dict):
        raise ValueError(f"jobs.ch {variable} was not an object")
    return value


def _job_posting_json_ld(page: str) -> dict[str, Any]:
    import re

    for match in re.finditer(
        r'<script\b[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        page,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        try:
            value = json.loads(html.unescape(match.group(1)).strip())
        except (json.JSONDecodeError, TypeError):
            continue
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            if isinstance(candidate, dict) and candidate.get("@type") == "JobPosting":
                return candidate
    raise ValueError("jobs.ch detail page omitted JobPosting JSON-LD")


def _location(value: Any) -> str:
    rows = value if isinstance(value, list) else [value]
    locations: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        address = row.get("address") or {}
        if not isinstance(address, dict):
            address = {}
        parts = [
            address.get("addressLocality"), address.get("addressRegion"),
            address.get("postalCode"), address.get("addressCountry"),
        ]
        text = ", ".join(str(part) for part in parts if part)
        if text:
            locations.append(text)
    return "; ".join(locations) or "Switzerland"


@register
class JobsCHAdapter(Adapter):
    board = "jobsch"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._request_lock = threading.Lock()
        self._next_detail_request = 0.0

    def _pace_detail_request(self) -> None:
        interval = float(self._board_config().get("detail_request_interval_seconds", 0.3) or 0)
        if not interval:
            return
        with self._request_lock:
            delay = self._next_detail_request - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._next_detail_request = time.monotonic() + interval

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        queries = list(cfg.get("queries") or terms)
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        max_pages = int(cfg.get("max_pages_per_query", 8) or 8)
        delay = float(cfg.get("request_delay_seconds", 0.4) or 0)
        seen: set[str] = set()

        for query in queries:
            page = 1
            pages = 1
            while page <= min(pages, max_pages):
                response = _get(
                    SEARCH_URL,
                    params={"term": query, "page": page},
                    timeout=timeout,
                )
                state = _assigned_json(response.text, "__INIT__")
                main = (((state.get("vacancy") or {}).get("results") or {}).get("main") or {})
                rows = list(main.get("results") or [])
                meta = dict(main.get("meta") or {})
                pages = max(1, int(meta.get("numPages") or 1))
                if not rows:
                    break
                for row in rows:
                    job_id = str(row.get("id") or "").strip()
                    if not job_id or job_id in seen or row.get("isActive") is False:
                        continue
                    seen.add(job_id)
                    url = urljoin(BASE_URL, f"/en/vacancies/detail/{job_id}/")
                    posted = str(row.get("publicationDate") or row.get("initialPublicationDate") or "")
                    yield JobUrl(self.board, job_id, url, posted or None)
                page += 1
                if delay:
                    time.sleep(delay)

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        self._pace_detail_request()
        response = _get(job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30))
        data = _job_posting_json_ld(response.text)
        company = data.get("hiringOrganization") or {}
        if not isinstance(company, dict):
            company = {}
        salary = data.get("baseSalary") or {}
        salary_value = salary.get("value") if isinstance(salary, dict) else {}
        if not isinstance(salary_value, dict):
            salary_value = {}
        data.update(
            title=str(data.get("title") or ""),
            company=str(company.get("name") or ""),
            location_text=_location(data.get("jobLocation")),
            content_text=plain_text(data.get("description")),
            salary_text=salary_text(
                salary_value.get("minValue"), salary_value.get("maxValue"),
                salary.get("currency") if isinstance(salary, dict) else "",
            ),
            source_url=response.url,
            source_attribution="jobs.ch",
            detail_fetch_status="full_page",
        )
        return RawPosting(
            board=self.board,
            job_id=job.job_id,
            url=response.url,
            fetched_at=contracts_now(),
            raw_json=data,
        )
