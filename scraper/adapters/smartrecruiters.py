"""SmartRecruiters public Posting API adapter for UK technology vacancies."""

from __future__ import annotations

import html
import re
from typing import Any, Iterable

from .base import Adapter, USER_AGENT, contracts_now, http_get_json, register
from contracts import JobUrl, RawPosting


API_ROOT = "https://api.smartrecruiters.com/v1/companies"


def _plain(value: Any) -> str:
    text = html.unescape(str(value or ""))
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()


@register
class SmartRecruitersAdapter(Adapter):
    board = "smartrecruiters"

    def _companies(self) -> dict[str, str]:
        raw = self._board_config().get("companies") or {}
        return {str(token): str(name) for token, name in raw.items()}

    @staticmethod
    def _is_uk(job: dict[str, Any]) -> bool:
        location = job.get("location") or {}
        country = str(location.get("country") or "").casefold()
        text = str(location.get("fullLocation") or "").casefold()
        return country in {"gb", "uk"} or "united kingdom" in text

    def _matches(self, job: dict[str, Any], terms: list[str]) -> bool:
        if not self._is_uk(job):
            return False
        title = _plain(job.get("name")).casefold()
        excluded = self._board_config().get("exclude_title_terms") or []
        if any(str(term).casefold() in title for term in excluded):
            return False
        labels = " ".join(
            str((job.get(field) or {}).get("label") or "")
            for field in ("department", "function", "industry", "experienceLevel")
        )
        blob = f"{title} {labels.casefold()}"
        return not terms or any(str(term).casefold() in blob for term in terms)

    @staticmethod
    def _priority(job: dict[str, Any], terms: list[str]) -> tuple[int, str]:
        title = _plain(job.get("name")).casefold()
        score = 0
        if any(x in title for x in ("graduate", "junior", "associate", "intern", "apprentice")):
            score += 40
        score += 8 * sum(1 for term in terms if str(term).casefold() in title)
        if any(x in title for x in ("senior", "staff", "principal", "director", "head", "lead")):
            score -= 25
        return score, str(job.get("releasedDate") or "")

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        limit = int(cfg.get("page_size", 100) or 100)
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        matches: list[tuple[dict[str, Any], str]] = []
        for token in self._companies():
            page = 0
            while True:
                try:
                    data = http_get_json(
                        f"{API_ROOT}/{token}/postings",
                        params={"limit": limit, "offset": page * limit},
                        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                        timeout=timeout,
                        attempts=2,
                    )
                except Exception as exc:
                    print(f"[smartrecruiters] employer {token!r} failed: {exc}; continuing")
                    break
                rows = list(data.get("content") or [])
                for job in rows:
                    if self._matches(job, terms):
                        matches.append((job, token))
                if len(rows) < limit or (page + 1) * limit >= int(data.get("totalFound") or 0):
                    break
                page += 1
        matches.sort(key=lambda pair: self._priority(pair[0], terms), reverse=True)
        for job, token in matches:
            native_id = str(job.get("id") or "")
            if native_id:
                yield JobUrl(
                    board=self.board,
                    job_id=f"{token}:{native_id}",
                    url=f"https://jobs.smartrecruiters.com/{token}/{native_id}",
                    posted_at=job.get("releasedDate"),
                )

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        token, native_id = job_url.job_id.split(":", 1)
        cfg = self._board_config()
        payload = http_get_json(
            f"{API_ROOT}/{token}/postings/{native_id}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=float(cfg.get("timeout_seconds", 30) or 30),
            attempts=2,
        )
        payload = dict(payload)
        sections = ((payload.get("jobAd") or {}).get("sections") or {})
        payload["content_text"] = "\n".join(
            _plain(section.get("text")) for section in sections.values()
            if isinstance(section, dict) and section.get("text")
        )
        payload["location_text"] = str((payload.get("location") or {}).get("fullLocation") or "")
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=str(payload.get("postingUrl") or job_url.url),
            fetched_at=contracts_now(),
            raw_json=payload,
        )
