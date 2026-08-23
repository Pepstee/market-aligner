"""Public Greenhouse Job Board API adapter for UK AI/IT employers.

Greenhouse documents its GET job-board endpoints as public and unauthenticated.
The adapter searches a configured set of employer board tokens, restricts
results to UK locations, and keeps the employer token in the job id so ids from
different boards cannot collide.
"""

from __future__ import annotations

import html
import re
from typing import Any, Iterable

from .base import (
    Adapter,
    USER_AGENT,
    contracts_now,
    http_get_json,
    register,
)
from market_aligner.domain.contracts import JobUrl, RawPosting


API_ROOT = "https://boards-api.greenhouse.io/v1/boards"


def _plain(value: Any) -> str:
    text = html.unescape(str(value or ""))
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()


@register
class GreenhouseAdapter(Adapter):
    board = "greenhouse"

    def _companies(self) -> dict[str, str]:
        raw = self._board_config().get("companies") or {}
        if isinstance(raw, list):
            return {str(token): str(token) for token in raw}
        return {str(token): str(name) for token, name in raw.items()}

    def _uk_location(self, location: str) -> bool:
        markers = self._board_config().get("uk_location_markers") or [
            "united kingdom", " uk", "london", "bristol", "cambridge",
            "manchester", "birmingham", "edinburgh", "glasgow", "remote - uk",
        ]
        normal = f" {location.casefold()}"
        return any(str(marker).casefold() in normal for marker in markers)

    def _matches_live(self, job: dict[str, Any], terms: list[str]) -> bool:
        if not self._uk_location(str((job.get("location") or {}).get("name") or "")):
            return False
        title = _plain(job.get("title")).casefold()
        excluded = self._board_config().get("exclude_title_terms") or []
        if any(str(term).casefold() in title for term in excluded):
            return False
        if not terms:
            return True
        blob = " ".join(
            (_plain(job.get("title")), _plain(job.get("content")),
             _plain((job.get("departments") or [{}])[0].get("name"))))
        folded = blob.casefold()
        return any(term.casefold() in folded for term in terms)

    def _priority(self, job: dict[str, Any], terms: list[str]) -> tuple[int, str]:
        """Graduate/entry routes first, then direct title matches, then stretches."""
        title = _plain(job.get("title")).casefold()
        score = 0
        if any(token in title for token in ("graduate", "junior", "associate", "fellow")):
            score += 40
        score += 8 * sum(1 for term in terms if term.casefold() in title)
        if any(token in title for token in ("senior", "staff", "principal", "director", "head", "lead")):
            score -= 25
        return score, str(job.get("updated_at") or "")

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        matches: list[tuple[dict[str, Any], str]] = []
        for token, employer in self._companies().items():
            data = http_get_json(
                f"{API_ROOT}/{token}/jobs",
                params={"content": "true"},
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                timeout=timeout,
            )
            for job in data.get("jobs", []) or []:
                if not self._matches_live(job, terms):
                    continue
                matches.append((job, token))

        matches.sort(key=lambda pair: self._priority(pair[0], terms), reverse=True)
        for job, token in matches:
            native_id = str(job.get("id") or "")
            if not native_id:
                continue
            yield JobUrl(
                board=self.board,
                job_id=f"{token}:{native_id}",
                url=str(job.get("absolute_url") or f"{API_ROOT}/{token}/jobs/{native_id}"),
                posted_at=job.get("updated_at"),
            )

    def _fetch_live(self, job_url: JobUrl) -> RawPosting:
        token, native_id = job_url.job_id.split(":", 1)
        cfg = self._board_config()
        payload = http_get_json(
            f"{API_ROOT}/{token}/jobs/{native_id}",
            params={"questions": "false"},
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=float(cfg.get("timeout_seconds", 30) or 30),
        )
        payload["board_token"] = token
        payload["company"] = self._companies().get(token, token)
        payload["location_text"] = str((payload.get("location") or {}).get("name") or "")
        payload["content_text"] = _plain(payload.get("content"))
        return RawPosting(
            board=self.board,
            job_id=job_url.job_id,
            url=job_url.url,
            fetched_at=contracts_now(),
            raw_json=payload,
        )
