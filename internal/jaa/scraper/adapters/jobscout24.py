"""JobScout24 Switzerland public listings and full JobPosting details."""

from __future__ import annotations

import re
import threading
import time
from typing import Any, Iterable
from urllib.parse import quote, urljoin

from .base import Adapter, USER_AGENT, contracts_now, register
from .jobsch import _job_posting_json_ld, _location
from .uk_common import plain_text, salary_text
from contracts import JobUrl, RawPosting


BASE_URL = "https://www.jobscout24.ch"


def _get(url: str, *, timeout: float = 30.0, attempts: int = 3):
    import requests

    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            response = requests.get(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept-Language": "en-GB,en;q=0.9,de;q=0.7,fr;q=0.6",
                },
                timeout=timeout,
            )
            if response.status_code in (403, 429) or response.status_code >= 500:
                raise requests.HTTPError(
                    f"transient JobScout24 status {response.status_code}", response=response
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


@register
class JobScout24Adapter(Adapter):
    board = "jobscout24"

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
        pattern = re.compile(
            r'data-job-detail-url="(?P<href>/en/job/(?P<id>[0-9a-f-]{36})/)"',
            flags=re.IGNORECASE,
        )

        for query in queries:
            for page in range(1, max_pages + 1):
                url = f"{BASE_URL}/en/jobs/{quote(query, safe='')}/?page={page}"
                response = _get(url, timeout=timeout)
                matches = list(pattern.finditer(response.text))
                if not matches:
                    break
                new_on_page = 0
                for match in matches:
                    job_id = match.group("id")
                    if job_id in seen:
                        continue
                    seen.add(job_id)
                    new_on_page += 1
                    yield JobUrl(
                        self.board, job_id, urljoin(BASE_URL, match.group("href")), None
                    )
                if not new_on_page:
                    break
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
            source_attribution="JobScout24 Switzerland",
            detail_fetch_status="full_page",
        )
        return RawPosting(
            board=self.board,
            job_id=job.job_id,
            url=response.url,
            fetched_at=contracts_now(),
            raw_json=data,
        )
