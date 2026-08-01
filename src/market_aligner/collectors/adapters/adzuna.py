"""Adzuna UK API adapter (enabled when API credentials are available)."""

from __future__ import annotations

import os
from typing import Any, Iterable

from .base import Adapter, SourceUnavailable, USER_AGENT, contracts_now, http_get_json, register
from .uk_common import plain_text
from market_aligner.domain.contracts import JobUrl, RawPosting


API_URL = "https://api.adzuna.com/v1/api/jobs/gb/search/{page}"


@register
class AdzunaAdapter(Adapter):
    board = "adzuna"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._discovered: dict[str, dict[str, Any]] = {}

    def _credentials(self) -> tuple[str, str]:
        cfg = self._board_config()
        app_id = os.getenv(str(cfg.get("app_id_env", "ADZUNA_APP_ID")), "").strip()
        app_key = os.getenv(str(cfg.get("app_key_env", "ADZUNA_APP_KEY")), "").strip()
        if not app_id or not app_key:
            raise SourceUnavailable("Adzuna skipped: set ADZUNA_APP_ID and ADZUNA_APP_KEY")
        return app_id, app_key

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        app_id, app_key = self._credentials()
        cfg = self._board_config()
        queries = list(cfg.get("queries") or terms or [""])
        page_size = int(cfg.get("results_per_page", 100) or 100)
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        seen: set[str] = set()
        for query in queries:
            page = 1
            while True:
                payload = http_get_json(
                    API_URL.format(page=page),
                    params={
                        "app_id": app_id, "app_key": app_key,
                        "results_per_page": page_size, "what": query,
                        "content-type": "application/json",
                    },
                    headers={"User-Agent": USER_AGENT}, timeout=timeout,
                )
                rows = list(payload.get("results") or [])
                for job in rows:
                    job_id = str(job.get("id") or "").strip()
                    if not job_id or job_id in seen:
                        continue
                    seen.add(job_id)
                    self._discovered[job_id] = dict(job)
                    yield JobUrl(
                        board=self.board, job_id=job_id,
                        url=str(job.get("redirect_url") or ""),
                        posted_at=str(job.get("created") or "") or None,
                    )
                if not rows or page * page_size >= int(payload.get("count") or 0):
                    break
                page += 1

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        import requests

        job = dict(self._discovered.get(job_url.job_id) or {})
        if not job:
            raise RuntimeError("Adzuna detail was not retained in this collector run")
        text = plain_text(job.get("description"))
        try:
            response = requests.get(job_url.url, headers={"User-Agent": USER_AGENT}, timeout=30)
            response.raise_for_status()
            complete = plain_text(response.text)
            if len(complete) > len(text):
                text = complete
        except Exception:
            pass
        job["company"] = str((job.get("company") or {}).get("display_name") or "")
        job["location_text"] = str((job.get("location") or {}).get("display_name") or "")
        job["content_text"] = text
        return RawPosting(
            board=self.board, job_id=job_url.job_id, url=job_url.url,
            fetched_at=contracts_now(), raw_text=text, raw_json=job,
        )
