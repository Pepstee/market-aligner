"""Stable, explicit vacancy identities for supported ATS URL families."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def canonical_source_url(value: str) -> str:
    """Normalize non-semantic tracking while retaining vacancy-bearing query data."""
    parsed = urlsplit(value)
    query = urlencode(
        sorted(
            (key, item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
            if not key.casefold().startswith("utm_")
        )
    )
    return urlunsplit(
        (
            parsed.scheme.casefold(),
            parsed.netloc.casefold(),
            parsed.path.rstrip("/"),
            query,
            "",
        )
    )


def provider_vacancy_tokens(*, job_key: str, source_url: str) -> frozenset[str]:
    """Return only high-confidence provider IDs explicitly present in evidence."""
    parsed = urlsplit(source_url)
    host = parsed.netloc.casefold().split(":", 1)[0]
    path = parsed.path.strip("/")
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    folded_key = job_key.casefold()
    tokens: set[str] = {f"url:{canonical_source_url(source_url)}"}

    greenhouse_ids: set[str] = set()
    gh_query = next(
        (value for key, value in query.items() if key.casefold() == "gh_jid"),
        None,
    )
    if gh_query and re.fullmatch(r"[0-9]{6,15}", gh_query):
        greenhouse_ids.add(gh_query)
    match = re.search(r"(?:^|/)jobs/([0-9]{6,15})(?:/|$)", parsed.path)
    if match:
        greenhouse_ids.add(match.group(1))
    if "greenhouse" in folded_key:
        greenhouse_ids.update(
            re.findall(r"(?<![0-9])[0-9]{6,15}(?![0-9])", job_key)
        )
    tokens.update(f"greenhouse:{value}" for value in greenhouse_ids)

    if host == "jobs.ashbyhq.com":
        parts = path.split("/")
        if len(parts) >= 2 and re.fullmatch(_UUID, parts[1], re.IGNORECASE):
            tokens.add(f"ashby:{parts[1].casefold()}")
    if "ashby" in folded_key:
        tokens.update(
            f"ashby:{value.casefold()}"
            for value in re.findall(_UUID, job_key, re.IGNORECASE)
        )

    if host == "jobs.lever.co":
        parts = path.split("/")
        if len(parts) >= 2 and re.fullmatch(_UUID, parts[1], re.IGNORECASE):
            tokens.add(f"lever:{parts[1].casefold()}")
    if "lever" in folded_key:
        tokens.update(
            f"lever:{value.casefold()}"
            for value in re.findall(_UUID, job_key, re.IGNORECASE)
        )

    if host == "apply.workable.com":
        parts = path.split("/")
        code = None
        if len(parts) >= 2 and parts[0].casefold() == "j":
            code = parts[1]
        elif len(parts) >= 3 and parts[-2].casefold() == "j":
            code = parts[-1]
        if code and re.fullmatch(r"[A-Za-z0-9]{8,16}", code):
            tokens.add(f"workable:{code.casefold()}")
    if "workable" in folded_key:
        match = re.search(r"(?<![A-Za-z0-9])([A-Fa-f0-9]{10})(?![A-Za-z0-9])", job_key)
        if match:
            tokens.add(f"workable:{match.group(1).casefold()}")

    if host == "jobs.smartrecruiters.com":
        parts = path.split("/")
        if len(parts) >= 2 and re.fullmatch(r"[0-9]{9,18}", parts[1]):
            tokens.add(f"smartrecruiters:{parts[1]}")

    if host.endswith(".myworkdayjobs.com"):
        parts = path.split("/")
        if parts:
            match = re.search(r"(_[A-Za-z][A-Za-z0-9_.-]{2,})$", parts[-1])
            if match:
                tokens.add(f"workday:{host}:{match.group(1).casefold()}")

    return frozenset(tokens)


__all__ = ["canonical_source_url", "provider_vacancy_tokens"]
