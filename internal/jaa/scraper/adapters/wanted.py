"""
scraper/adapters/wanted.py — Wanted (wanted.co.kr) adapter, live + fixture.

Wanted is the cleanest of the four boards: it exposes an unauthenticated JSON
API with a paged list endpoint and a per-job detail endpoint. Build spec §2
says start here to prove the pipeline end-to-end, so this adapter is wired
against the CONFIRMED live shapes AND a realistic saved copy of those two
responses for offline tests:

    data/fixtures/wanted_listing.json     — the list endpoint ({"data": [...], "links": {...}})
    data/fixtures/wanted/{id}.json         — the detail endpoint ({"data": {"job": {...}}})

Live shapes (confirmed):
    LIST  : GET https://www.wanted.co.kr/api/v4/jobs
            ?country=kr&job_sort=job.latest_order&years=-1&locations=all
            &limit={limit}&offset={offset}
            -> {"data": [{"id", "position", "company": {...}, "address": {...},
                          "due_time", "annual_from", "category_tags": [
                              {"parent_id", "id"}]}],
                "links": {"next": "...|null"}}
            DESIGN FILTER: keep a job only if any category_tags.parent_id ==
            config wanted.design_parent_id (518). Paginate offset += limit until
            data is empty or links.next is null.
    DETAIL: GET https://www.wanted.co.kr/api/v4/jobs/{id}
            -> {"job": {..., "detail": {"intro","main_tasks","requirements",
                        "preferred_points","benefits"}, "skill_tags": [
                        {"title"}], "category_tags": [...], "annual_from": 0}}
            entry_level = (job.annual_from == 0)
            JD text     = join detail.{intro,main_tasks,requirements,preferred_points}
            required_software candidates = skill_tags[].title

Both live methods lazy-import ``requests`` so the module imports (and the
fixture-driven self-test runs) without any third-party dependency installed.
"""

from __future__ import annotations

from typing import Any, Iterable

from .base import (Adapter, JobUrl, RawPosting, USER_AGENT, contracts_now,
                   http_get_json, register)

# Live API base (per the confirmed shapes; also mirrored in config wanted.*).
# LIST: the chaos/navigation endpoint — the only one that honours job_group_id
# (confirmed live 2026-07-14: /api/v4/jobs silently IGNORES job_group_id and
# serves the whole latest feed; parent_id 518 turned out to be 개발/development,
# design is 511). Entry shape: category_tag is a SINGLE object here, vs the
# category_tags LIST on v4 — _is_design handles both.
WANTED_LIST_URL = "https://www.wanted.co.kr/api/chaos/navigation/v1/results"
WANTED_DETAIL_URL = "https://www.wanted.co.kr/api/v4/jobs/{id}"
DEFAULT_DESIGN_GROUP_ID = 511    # job_group_id: 디자인
DEFAULT_DESIGN_PARENT_ID = 511   # category_tag(.s) parent_id: 디자인
DEFAULT_LIST_LIMIT = 20


@register
class WantedAdapter(Adapter):
    board = "wanted"

    # ------------------------------------------------------------------ #
    # FIXTURE path (live=False) — used by tests. The base default reads
    # the listing fixture; we only override the mapping hooks below.
    # ------------------------------------------------------------------ #
    def _searchable_text(self, entry: dict[str, Any]) -> str:
        return " ".join(str(x) for x in (
            entry.get("position", ""),
            entry.get("company_name", ""),
            entry.get("category_tag", ""),
        ))

    def _to_job_url(self, entry: dict[str, Any]) -> JobUrl:
        job_id = str(entry["id"])
        return JobUrl(
            board=self.board,
            job_id=job_id,
            url=self._detail_url(job_id),
            posted_at=entry.get("posted_at"),
        )

    def _detail_url(self, job_id: str) -> str:
        return f"https://www.wanted.co.kr/wd/{job_id}"

    def _to_raw_posting(self, job_url: JobUrl, detail: dict[str, Any]) -> RawPosting:
        # Fixture detail is the API envelope {"data": {"job": {...}}}; unwrap it.
        job = detail.get("data", {}).get("job", detail)
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=job,
        )

    # ------------------------------------------------------------------ #
    # LIVE path (live=True) — real HTTP against the confirmed JSON API.
    # ------------------------------------------------------------------ #
    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        """Page the live list endpoint, keep design jobs, yield C1 records.

        Wanted's list endpoint is not keyword-scoped in the confirmed shape, so
        we page the whole latest-order feed and keep a job only if any
        category_tags.parent_id == design_parent_id (config). ``terms`` are kept
        for parity/future keyword scoping but the design filter is authoritative.
        """
        import requests  # lazy: only imported on the live branch

        cfg = self._board_config()
        list_url = cfg.get("list_url") or WANTED_LIST_URL
        design_group_id = int(cfg.get("design_group_id", DEFAULT_DESIGN_GROUP_ID))
        design_parent_id = int(cfg.get("design_parent_id", DEFAULT_DESIGN_PARENT_ID))
        limit = int(cfg.get("list_limit", DEFAULT_LIST_LIMIT))
        # Hard page cap so live discovery can never walk the whole feed; the
        # The collector owns deduplication and persistence; discovery is uncapped.
        max_pages = int(cfg.get("max_pages", 5))

        seen_ids: set[str] = set()
        offset = 0
        pages = 0
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})

        while pages < max_pages:
            pages += 1
            params = {
                "country": "kr",
                "job_group_id": design_group_id,   # server-side design filter
                "job_sort": "job.latest_order",
                "years": -1,
                "locations": "all",
                "limit": limit,
                "offset": offset,
            }
            payload = http_get_json(list_url, params=params, session=session)
            rows = payload.get("data") or []
            if not rows:
                break

            for entry in rows:
                if not self._is_design(entry, design_parent_id):
                    continue
                job_id = str(entry.get("id"))
                if not job_id or job_id in seen_ids:
                    continue
                seen_ids.add(job_id)
                yield JobUrl(
                    board=self.board,
                    job_id=job_id,
                    url=self._detail_url(job_id),
                    posted_at=entry.get("due_time") or entry.get("posted_at"),
                )

            # Stop when the API says there is no next page.
            if (payload.get("links") or {}).get("next") is None:
                break
            offset += limit

    @staticmethod
    def _is_design(entry: dict[str, Any], design_parent_id: int) -> bool:
        """True iff the entry's category parent matches the design parent id.

        Belt-and-braces behind the server-side job_group_id filter. Handles both
        live shapes: chaos/navigation carries a single ``category_tag`` object;
        v4 carries a ``category_tags`` list.
        """
        tags = list(entry.get("category_tags") or [])
        single = entry.get("category_tag")
        if isinstance(single, dict):
            tags.append(single)
        for tag in tags:
            try:
                if int(tag.get("parent_id")) == design_parent_id:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        """GET the per-job detail endpoint and return a C2 RawPosting.

        raw_json = the ``job`` dict. entry_level = (job.annual_from == 0); the JD
        text and required_software candidates live inside detail/skill_tags for
        the downstream LLM extractor — we keep them intact in raw_json.
        """
        cfg = self._board_config()
        detail_url = (cfg.get("detail_url") or WANTED_DETAIL_URL).format(id=job_url.job_id)

        payload = http_get_json(
            detail_url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        # Live detail may be {"job": {...}} or {"data": {"job": {...}}}.
        job = payload.get("job") or payload.get("data", {}).get("job", payload)

        # entry_level derived here for convenience; the LLM extractor is the
        # authority, but surface it so downstream mapping is unambiguous.
        job = dict(job)
        job.setdefault("entry_level", job.get("annual_from") == 0)

        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=job,
        )
