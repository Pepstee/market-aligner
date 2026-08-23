"""Small deterministic helpers shared by UK/remote job-feed adapters."""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from typing import Any, Iterable


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in {"script", "style", "noscript", "svg"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style", "noscript", "svg"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth and data.strip():
            self.parts.append(data)


def plain_text(value: Any) -> str:
    parser = _TextExtractor()
    parser.feed(html.unescape(str(value or "")))
    return re.sub(r"\s+", " ", " ".join(parser.parts)).strip()


def matches_terms(values: Iterable[Any], terms: Iterable[str]) -> bool:
    wanted = [str(term).casefold().strip() for term in terms if str(term).strip()]
    if not wanted:
        return True
    blob = " ".join(plain_text(value) for value in values).casefold()
    return any(term in blob for term in wanted)


def uk_or_eligible_remote(location: Any, *, remote: bool = False, body: Any = "") -> bool:
    text = f" {plain_text(location)} {plain_text(body)}".casefold()
    uk_markers = (
        " united kingdom", " uk", "u.k.", "great britain", "england",
        "scotland", "wales", "northern ireland", "london", "bristol",
        "cambridge", "manchester", "birmingham", "edinburgh", "glasgow",
    )
    if any(marker in text for marker in uk_markers):
        return True
    if not remote:
        return False
    eligibility = (
        "worldwide", "anywhere", "global", "europe", "emea", "gmt",
        "utc+0", "utc +0", "utc-1", "utc+1", "uk time",
    )
    return any(marker in text for marker in eligibility)


def salary_text(*values: Any) -> str:
    return " - ".join(str(value) for value in values if value not in (None, "", 0))
