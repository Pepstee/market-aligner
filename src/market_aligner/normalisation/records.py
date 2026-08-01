"""Lossless deterministic projection of raw postings into vacancy shells."""

from __future__ import annotations

from typing import Any, Iterable

from market_aligner.domain.contracts import RawPosting, Vacancy


def flatten(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        preferred = [
            value.get(key)
            for key in (
                "name",
                "title",
                "display_name",
                "location_str",
                "city",
                "country",
                "country_name",
                "label",
            )
            if value.get(key)
        ]
        return " ".join(flatten(item) for item in (preferred or value.values()))
    if isinstance(value, (list, tuple, set)):
        return "; ".join(flatten(item) for item in value if item is not None)
    return str(value)


def first(payload: dict[str, Any], names: Iterable[str]) -> str:
    for name in names:
        text = flatten(payload.get(name)).strip()
        if text:
            return text
    return ""


def vacancy_shell_from_raw(row: RawPosting) -> Vacancy:
    """Create a best-effort shell without pretending semantic extraction occurred."""

    payload = row.raw_json if isinstance(row.raw_json, dict) else {}
    title = first(payload, ("title", "job_title", "jobTitle", "name", "position", "text"))
    company = first(
        payload,
        ("company", "companyName", "employerName", "organization", "hiringOrganization"),
    )
    location = first(
        payload,
        ("location_text", "location", "locations", "jobLocation", "city", "country"),
    )
    description = first(
        payload,
        (
            "content_text",
            "descriptionPlain",
            "description",
            "jobDescription",
            "contents",
            "requirements",
        ),
    ) or str(row.raw_text or "")
    return Vacancy(
        board=row.board,
        job_id=row.job_id,
        url=row.url,
        title=title,
        company=company,
        location=location,
        description=description,
        posted_at=first(payload, ("datePosted", "postedAt", "published_at")) or None,
        expires_at=first(
            payload,
            ("expiryDate", "expires_at", "application_deadline", "validThrough", "deadline"),
        ) or None,
        source_content_sha256=row.content_sha256,
        extra={"normalisation_status": "deterministic_shell_requires_semantic_extraction"},
    )
