"""
scraper/adapters/saramin.py — Saramin (saramin.co.kr) adapter, live + fixture.

Saramin ships an official recruitment Open API (oapi.saramin.co.kr, free key),
so we prefer it over scraping (build spec §2: structured, ToS-clean, keyword +
job-category filters). The list response nests rows under jobs.job[], each with
company.detail.name / position.title / experience-level, etc.

Fixture-backed for offline tests:
    data/fixtures/saramin_listing.json     — the Open API list envelope
    data/fixtures/saramin/{id}.json         — a per-job detail record (with detail_html)

Live shape (confirmed):
    GET https://oapi.saramin.co.kr/job-search
        ?access-key={KEY}&keywords={kw}&job_mid_cd={design_job_mid_cd}
        &count={count}&start={page}&fields=posting-date,expiration-date&sort=pd
        header: Accept: application/json
    -> {"jobs": {"count","start","total","job": [
           {"id","url","company":{"detail":{"name"}},
            "position":{"title","location":{"name"},
                        "experience-level":{"code","min","max","name"},
                        "job-code":{"name"}},
            "keyword","salary":{"name"},"posting-date","expiration-date"}]}}
    entry_level = experience-level.code in (1 신입, 0 경력무관) OR min == 0.

The access key is read from the env var named by config saramin.access_key_env
(SARAMIN_ACCESS_KEY); it is NEVER hardcoded. The Open API returns list metadata
only (no full JD body), so the live fetch sets raw_json to the job object.

``requests`` is lazy-imported only on the live branch, so the module imports and
the fixture-driven self-test runs with no third-party dependency installed.
"""

from __future__ import annotations

import os
from typing import Any, Iterable

from .base import Adapter, JobUrl, RawPosting, USER_AGENT, contracts_now, register

SARAMIN_OAPI = "https://oapi.saramin.co.kr/job-search"
DEFAULT_DESIGN_JOB_MID_CD = "2"
DEFAULT_COUNT = 110
DEFAULT_ACCESS_KEY_ENV = "SARAMIN_ACCESS_KEY"


@register
class SaraminAdapter(Adapter):
    board = "saramin"

    # ------------------------------------------------------------------ #
    # FIXTURE path (live=False) — used by tests.
    # ------------------------------------------------------------------ #
    def _load_listing(self) -> list[dict[str, Any]]:
        import json
        path = self.fixture_dir / "saramin_listing.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        return list(data.get("jobs", {}).get("job", []))

    def _searchable_text(self, entry: dict[str, Any]) -> str:
        pos = entry.get("position", {}) or {}
        return " ".join(str(x) for x in (
            pos.get("title", ""),
            (pos.get("job-code", {}) or {}).get("name", ""),
            (pos.get("job-mid-code", {}) or {}).get("name", ""),
            entry.get("keyword", ""),
        ))

    def _to_job_url(self, entry: dict[str, Any]) -> JobUrl:
        job_id = str(entry["id"])
        return JobUrl(
            board=self.board,
            job_id=job_id,
            url=entry.get("url") or self._detail_url(job_id),
            posted_at=entry.get("posting-date"),
        )

    def _detail_url(self, job_id: str) -> str:
        return f"https://www.saramin.co.kr/zf_user/jobs/relay/view?rec_idx={job_id}"

    def fetch(self, job_url: JobUrl, live: bool = False) -> RawPosting:
        if live:
            return self._fetch_live(job_url)
        detail = self._load_detail(job_url.job_id)
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=detail,
            raw_text=detail.get("detail_html"),   # JD body for the LLM to extract
        )

    # ------------------------------------------------------------------ #
    # LIVE path (live=True) — real HTTP against the Open API.
    # ------------------------------------------------------------------ #
    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        """Query the Open API per keyword under the design job-mid category,
        paginate, and yield C1 JobUrl records. Bad/missing key -> graceful stop.
        """
        import requests  # lazy: only imported on the live branch

        cfg = self._board_config()
        base_url = cfg.get("base_url") or SARAMIN_OAPI
        key_env = cfg.get("access_key_env") or DEFAULT_ACCESS_KEY_ENV
        access_key = os.environ.get(key_env)
        if not access_key:
            # No key -> nothing to discover. Surface a clear message; don't crash.
            print(f"[saramin] missing access key: set env {key_env}. Skipping saramin.")
            return
        job_mid_cd = str(cfg.get("design_job_mid_cd", DEFAULT_DESIGN_JOB_MID_CD))
        count = int(cfg.get("count", DEFAULT_COUNT))

        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})

        seen_ids: set[str] = set()
        for kw in terms or [""]:
            page = 1
            while True:
                params = {
                    "access-key": access_key,
                    "keywords": kw,
                    "job_mid_cd": job_mid_cd,
                    "count": count,
                    "start": page,
                    "fields": "posting-date,expiration-date",
                    "sort": "pd",
                }
                resp = session.get(base_url, params=params, timeout=30)
                # Bad/missing key or other API error returns {"code","message"}.
                try:
                    payload = resp.json()
                except ValueError:
                    print(f"[saramin] non-JSON response for kw={kw!r}; stopping.")
                    break
                if isinstance(payload, dict) and payload.get("code") and "jobs" not in payload:
                    print(f"[saramin] API error for kw={kw!r}: "
                          f"{payload.get('code')} {payload.get('message')}")
                    break

                jobs = (payload.get("jobs") or {})
                rows = jobs.get("job") or []
                if not rows:
                    break

                for entry in rows:
                    job_id = str(entry.get("id"))
                    if not job_id or job_id in seen_ids:
                        continue
                    seen_ids.add(job_id)
                    yield JobUrl(
                        board=self.board,
                        job_id=job_id,
                        url=entry.get("url") or self._detail_url(job_id),
                        posted_at=entry.get("posting-date"),
                    )

                # Paginate by total/count; stop once we've covered the count.
                try:
                    total = int(jobs.get("total", 0))
                except (TypeError, ValueError):
                    total = 0
                if page * count >= total or len(rows) < count:
                    break
                page += 1

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        """Re-query the Open API for the single posting's metadata and return a
        C2 RawPosting. The Open API returns list metadata only (no full JD body),
        so raw_json holds the job object.

        # NOTE full JD requires page fetch — the Open API carries no JD body; a
        # separate render/scrape of job_url.url is needed for the full text.
        """
        import requests  # lazy: only imported on the live branch

        cfg = self._board_config()
        base_url = cfg.get("base_url") or SARAMIN_OAPI
        key_env = cfg.get("access_key_env") or DEFAULT_ACCESS_KEY_ENV
        access_key = os.environ.get(key_env)
        if not access_key:
            raise RuntimeError(
                f"[saramin] missing access key: set env {key_env} for live fetch."
            )

        # The Open API has no by-id endpoint; filter the search result by id.
        params = {
            "access-key": access_key,
            "keywords": job_url.job_id,
            "count": 10,
            "start": 1,
            "fields": "posting-date,expiration-date",
        }
        resp = requests.get(
            base_url, params=params,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=30,
        )
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        if isinstance(payload, dict) and payload.get("code") and "jobs" not in payload:
            # Bad/missing key handled gracefully: keep an id-only raw record.
            job_obj: dict[str, Any] = {"id": job_url.job_id, "url": job_url.url,
                                       "error": payload}
        else:
            rows = (payload.get("jobs") or {}).get("job") or []
            job_obj = next(
                (r for r in rows if str(r.get("id")) == job_url.job_id),
                {"id": job_url.job_id, "url": job_url.url},
            )

        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=job_obj,   # NOTE full JD requires page fetch
        )
