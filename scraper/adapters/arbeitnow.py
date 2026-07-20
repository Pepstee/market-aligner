"""Arbeitnow's public, paginated European jobs API."""

from __future__ import annotations

from typing import Any, Iterable

from .base import Adapter, USER_AGENT, contracts_now, http_get_json, register
from .uk_common import matches_terms, plain_text, uk_or_eligible_remote
from contracts import JobUrl, RawPosting


API_URL = "https://www.arbeitnow.com/api/job-board-api"


@register
class ArbeitnowAdapter(Adapter):
    board = "arbeitnow"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._discovered: dict[str, dict[str, Any]] = {}

    def _accept(self, job: dict[str, Any], terms: list[str]) -> bool:
        remote = bool(job.get("remote"))
        if not uk_or_eligible_remote(job.get("location"), remote=remote,
                                     body=job.get("description")):
            return False
        return matches_terms(
            [job.get("title"), job.get("description"), job.get("tags"), job.get("job_types")],
            terms,
        )

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        page = 1
        while True:
            payload = http_get_json(
                API_URL,
                params={"page": page},
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                timeout=timeout,
                attempts=3,
            )
            rows = list(payload.get("data") or [])
            for job in rows:
                slug = str(job.get("slug") or "").strip()
                if not slug or not self._accept(job, terms):
                    continue
                self._discovered[slug] = dict(job)
                yield JobUrl(
                    board=self.board,
                    job_id=slug,
                    url=str(job.get("url") or f"https://www.arbeitnow.com/jobs/{slug}"),
                    posted_at=str(job.get("created_at") or "") or None,
                )
            if not rows or not (payload.get("links") or {}).get("next"):
                break
            page += 1

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        job = dict(self._discovered.get(job_url.job_id) or {})
        if not job:
            raise RuntimeError(
                "Arbeitnow detail was not retained; collect discovery and fetch in one collector run"
            )
        job["company"] = str(job.get("company_name") or "")
        job["location_text"] = str(job.get("location") or "")
        job["content_text"] = plain_text(job.get("description"))
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=job,
        )
