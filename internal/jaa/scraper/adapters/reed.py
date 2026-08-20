"""Reed UK Jobseeker API adapter (enabled when an API key is available)."""

from __future__ import annotations

import os
from typing import Any, Iterable

from .base import Adapter, SourceUnavailable, contracts_now, register
from .uk_common import plain_text
from contracts import JobUrl, RawPosting


SEARCH_URL = "https://www.reed.co.uk/api/1.0/search"
DETAIL_URL = "https://www.reed.co.uk/api/1.0/jobs/{job_id}"


@register
class ReedAdapter(Adapter):
    board = "reed"

    def _api_key(self) -> str:
        cfg = self._board_config()
        key = os.getenv(str(cfg.get("api_key_env", "REED_API_KEY")), "").strip()
        if not key:
            raise SourceUnavailable("Reed skipped: set REED_API_KEY")
        return key

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        import requests

        key = self._api_key()
        cfg = self._board_config()
        queries = list(cfg.get("queries") or terms or [""])
        take = min(100, int(cfg.get("results_per_page", 100) or 100))
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        seen: set[str] = set()
        for query in queries:
            skip = 0
            while True:
                response = requests.get(
                    SEARCH_URL,
                    params={"keywords": query, "locationName": "United Kingdom",
                            "resultsToTake": take, "resultsToSkip": skip},
                    auth=(key, ""), timeout=timeout,
                )
                response.raise_for_status()
                payload = response.json()
                rows = list(payload.get("results") or [])
                for job in rows:
                    job_id = str(job.get("jobId") or "").strip()
                    if not job_id or job_id in seen:
                        continue
                    seen.add(job_id)
                    yield JobUrl(
                        board=self.board, job_id=job_id,
                        url=str(job.get("jobUrl") or f"https://www.reed.co.uk/jobs/{job_id}"),
                        posted_at=str(job.get("date") or "") or None,
                    )
                skip += len(rows)
                if not rows or skip >= int(payload.get("totalResults") or 0):
                    break

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        import requests

        key = self._api_key()
        timeout = float(self._board_config().get("timeout_seconds", 30) or 30)
        response = requests.get(DETAIL_URL.format(job_id=job_url.job_id),
                                auth=(key, ""), timeout=timeout)
        response.raise_for_status()
        job = dict(response.json())
        job["company"] = str(job.get("employerName") or "")
        job["location_text"] = str(job.get("locationName") or "")
        job["content_text"] = plain_text(job.get("jobDescription"))
        return RawPosting(
            board=self.board, job_id=job_url.job_id, url=job_url.url,
            fetched_at=contracts_now(), raw_json=job,
        )
