"""Read-only Greenhouse vacancy classification for the production queue."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit


ACTIVE_MARKERS = (
    "apply for this job",
    "submit application",
    "application-form",
    "application_form",
)
CLOSED_MARKERS = (
    "this job is no longer available",
    "this job is no longer open",
    "the job you were looking for is no longer open",
    "job not found",
    "page not found",
)


def _normal_text(value: str) -> str:
    without_markup = re.sub(r"<[^>]+>", " ", html.unescape(value))
    return " ".join(without_markup.casefold().split())


def greenhouse_requisition_id(url: str) -> str | None:
    parsed = urlsplit(url)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.casefold() == "gh_jid" and re.fullmatch(r"[0-9]{6,15}", value):
            return value
    match = re.search(r"(?:^|/)jobs/([0-9]{6,15})(?:/|$)", parsed.path)
    return match.group(1) if match else None


@dataclass(frozen=True)
class GreenhouseLiveVerdict:
    live: bool
    reason: str
    active_markers: tuple[str, ...]
    closed_markers: tuple[str, ...]
    title_bound: bool
    requisition_bound: bool

    def document(self) -> dict[str, object]:
        return {
            "live": self.live,
            "reason": self.reason,
            "active_markers": list(self.active_markers),
            "closed_markers": list(self.closed_markers),
            "title_bound": self.title_bound,
            "requisition_bound": self.requisition_bound,
        }


def classify_greenhouse_response(
    *,
    requested_url: str,
    final_url: str,
    status: int,
    body: bytes,
    expected_title: str,
) -> GreenhouseLiveVerdict:
    """Fail closed unless response, requisition, title and form all agree."""
    source = body.decode("utf-8", errors="replace")
    folded = source.casefold()
    normal = _normal_text(source)
    active = tuple(marker for marker in ACTIVE_MARKERS if marker in folded)
    closed = tuple(marker for marker in CLOSED_MARKERS if marker in normal)
    expected_id = greenhouse_requisition_id(requested_url)
    final_id = greenhouse_requisition_id(final_url)
    requisition_bound = expected_id is not None and (
        final_id == expected_id
        or re.search(rf"(?<![0-9]){re.escape(expected_id)}(?![0-9])", source)
        is not None
    )
    title_bound = _normal_text(expected_title) in normal
    if not 200 <= status < 300:
        reason = "non_success_http_status"
    elif closed:
        reason = "provider_closed_marker"
    elif not requisition_bound:
        reason = "requisition_identity_mismatch"
    elif not title_bound:
        reason = "vacancy_title_mismatch"
    elif not active:
        reason = "application_form_not_observed"
    else:
        reason = "live_application_form_observed"
    return GreenhouseLiveVerdict(
        live=reason == "live_application_form_observed",
        reason=reason,
        active_markers=active,
        closed_markers=closed,
        title_bound=title_bound,
        requisition_bound=requisition_bound,
    )


__all__ = [
    "GreenhouseLiveVerdict",
    "classify_greenhouse_response",
    "greenhouse_requisition_id",
]
