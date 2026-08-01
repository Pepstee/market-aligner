"""Remotive's public delayed feed for genuine remote vacancies."""

from __future__ import annotations

from typing import Any, Iterable

from .base import Adapter, USER_AGENT, contracts_now, http_get_json, register
from .uk_common import matches_terms, plain_text, uk_or_eligible_remote
from market_aligner.domain.contracts import JobUrl, RawPosting


API_URL = "https://remotive.com/api/remote-jobs"


@register
class RemotiveAdapter(Adapter):
    board = "remotive"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._discovered: dict[str, dict[str, Any]] = {}

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        payload = http_get_json(
            API_URL,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=float(cfg.get("timeout_seconds", 30) or 30),
            attempts=3,
        )
        for job in payload.get("jobs", []) or []:
            native_id = str(job.get("id") or "").strip()
            location = job.get("candidate_required_location")
            if not native_id or not uk_or_eligible_remote(
                location, remote=True, body=job.get("description")
            ):
                continue
            if not matches_terms(
                [job.get("title"), job.get("description"), job.get("category"), job.get("tags")],
                terms,
            ):
                continue
            self._discovered[native_id] = dict(job)
            yield JobUrl(
                board=self.board,
                job_id=native_id,
                url=str(job.get("url") or f"https://remotive.com/remote-jobs/{native_id}"),
                posted_at=str(job.get("publication_date") or "") or None,
            )

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        job = dict(self._discovered.get(job_url.job_id) or {})
        if not job:
            raise RuntimeError(
                "Remotive detail was not retained; collect discovery and fetch in one collector run"
            )
        job["company"] = str(job.get("company_name") or "")
        job["location_text"] = str(job.get("candidate_required_location") or "Remote")
        job["content_text"] = plain_text(job.get("description"))
        job["source_attribution"] = "Remotive"
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=job,
        )
