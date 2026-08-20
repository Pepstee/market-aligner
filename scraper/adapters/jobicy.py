"""Jobicy public API for UK/Europe remote roles with full descriptions."""

from __future__ import annotations

from typing import Any, Iterable

from .base import Adapter, USER_AGENT, contracts_now, http_get_json, register
from .uk_common import matches_terms, plain_text
from contracts import JobUrl, RawPosting


API_URL = "https://jobicy.com/api/v2/remote-jobs"


@register
class JobicyAdapter(Adapter):
    board = "jobicy"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._discovered: dict[str, dict[str, Any]] = {}

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        geos = list(cfg.get("geos") or ["uk", "europe"])
        industries = list(cfg.get("industries") or [
            "dev", "data-science", "cybersecurity", "engineering",
            "project-management", "marketing",
        ])
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        seen: set[str] = set()
        for geo in geos:
            for industry in industries:
                payload = http_get_json(
                    API_URL,
                    params={"count": 100, "geo": geo, "industry": industry},
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                    timeout=timeout,
                    attempts=3,
                )
                for job in payload.get("jobs", []) or []:
                    native_id = str(job.get("id") or "").strip()
                    if not native_id or native_id in seen:
                        continue
                    if not matches_terms(
                        [job.get("jobTitle"), job.get("jobDescription"), job.get("jobIndustry")],
                        terms,
                    ):
                        continue
                    seen.add(native_id)
                    self._discovered[native_id] = dict(job)
                    yield JobUrl(
                        board=self.board,
                        job_id=native_id,
                        url=str(job.get("url") or f"https://jobicy.com/jobs/{native_id}"),
                        posted_at=str(job.get("pubDate") or "") or None,
                    )

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        job = dict(self._discovered.get(job_url.job_id) or {})
        if not job:
            raise RuntimeError(
                "Jobicy detail was not retained; collect discovery and fetch in one collector run"
            )
        job["company"] = str(job.get("companyName") or "")
        job["location_text"] = str(job.get("jobGeo") or "Remote")
        job["content_text"] = plain_text(job.get("jobDescription"))
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=job,
        )
