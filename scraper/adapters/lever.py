"""Lever public Postings API adapter for genuine UK employer vacancies."""

from __future__ import annotations

import html
import re
from typing import Any, Iterable

from .base import Adapter, USER_AGENT, contracts_now, http_get_json, register
from contracts import JobUrl, RawPosting


API_ROOT = "https://api.lever.co/v0/postings"


def _plain(value: Any) -> str:
    text = html.unescape(str(value or ""))
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()


@register
class LeverAdapter(Adapter):
    board = "lever"

    def _companies(self) -> dict[str, str]:
        raw = self._board_config().get("companies") or {}
        if isinstance(raw, list):
            return {str(token): str(token) for token in raw}
        return {str(token): str(name) for token, name in raw.items()}

    def _is_uk(self, job: dict[str, Any]) -> bool:
        categories = job.get("categories") or {}
        country = str(job.get("country") or "").upper()
        locations = " ".join(
            [str(categories.get("location") or "")]
            + [str(x) for x in (categories.get("allLocations") or [])]
        ).casefold()
        markers = self._board_config().get("uk_location_markers") or [
            "united kingdom", "london", "bristol", "cambridge", "manchester",
            "birmingham", "edinburgh", "glasgow", "remote (uk)", "remote - uk",
            "(gb)", "uk remote",
        ]
        return country == "GB" or any(str(marker).casefold() in locations for marker in markers)

    def _matches_live(self, job: dict[str, Any], terms: list[str]) -> bool:
        if not self._is_uk(job):
            return False
        title = _plain(job.get("text")).casefold()
        excluded = self._board_config().get("exclude_title_terms") or []
        if any(str(term).casefold() in title for term in excluded):
            return False
        if not terms:
            return True
        categories = job.get("categories") or {}
        blob = " ".join([
            _plain(job.get("text")),
            _plain(job.get("descriptionPlain") or job.get("description")),
            _plain(categories.get("team")),
            _plain(categories.get("department")),
        ]).casefold()
        return any(str(term).casefold() in blob for term in terms)

    @staticmethod
    def _priority(job: dict[str, Any], terms: list[str]) -> tuple[int, str]:
        title = _plain(job.get("text")).casefold()
        score = 0
        if any(x in title for x in ("graduate", "junior", "associate", "intern", "fellow")):
            score += 40
        score += 8 * sum(1 for term in terms if str(term).casefold() in title)
        if any(x in title for x in ("senior", "staff", "principal", "director", "head", "lead")):
            score -= 25
        return score, str(job.get("createdAt") or "")

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        matches: list[tuple[dict[str, Any], str]] = []
        page_size = int(cfg.get("page_size", 100) or 100)
        for token in self._companies():
            skip = 0
            while True:
                try:
                    rows = http_get_json(
                        f"{API_ROOT}/{token}",
                        params={"mode": "json", "limit": page_size, "skip": skip},
                        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                        timeout=timeout,
                        attempts=2,
                    )
                except Exception as exc:  # one employer must not sink the board
                    print(f"[lever] employer {token!r} failed: {exc}; continuing")
                    break
                rows = rows if isinstance(rows, list) else []
                for job in rows:
                    if self._matches_live(job, terms):
                        matches.append((job, token))
                if len(rows) < page_size:
                    break
                skip += len(rows)
        matches.sort(key=lambda pair: self._priority(pair[0], terms), reverse=True)
        for job, token in matches:
            native_id = str(job.get("id") or "")
            if native_id:
                yield JobUrl(
                    board=self.board,
                    job_id=f"{token}:{native_id}",
                    url=str(job.get("hostedUrl") or f"https://jobs.lever.co/{token}/{native_id}"),
                    posted_at=str(job.get("createdAt") or "") or None,
                )

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        token, native_id = job_url.job_id.split(":", 1)
        cfg = self._board_config()
        payload = http_get_json(
            f"{API_ROOT}/{token}/{native_id}",
            params={"mode": "json"},
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=float(cfg.get("timeout_seconds", 30) or 30),
        )
        payload = dict(payload)
        payload["company"] = self._companies().get(token, token)
        payload["location_text"] = str((payload.get("categories") or {}).get("location") or "")
        payload["content_text"] = _plain(
            payload.get("descriptionPlain") or payload.get("description")
        )
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=payload,
        )
