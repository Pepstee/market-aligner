"""Cross-source vacancy deduplication selectively adopted from the audited gate."""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from market_aligner.domain.contracts import Vacancy


DEFAULT_SOURCE_PRIORITY: dict[str, int] = {
    "greenhouse": 0,
    "lever": 0,
    "smartrecruiters": 0,
    "ashby": 0,
    "workable": 0,
    "recruitee": 0,
    "personio": 0,
    "workday": 0,
}


def normalise_identity(value: str) -> str:
    value = value.casefold().replace("&", " and ")
    value = re.sub(r"\b(ltd|limited|plc|inc|llc|corp|corporation|company|co)\b", " ", value)
    return re.sub(r"[^a-z0-9]+", " ", value).strip()


def normalise_location(value: str) -> str:
    text = normalise_identity(value)
    if any(marker in text for marker in ("remote", "worldwide", "global", "distributed")):
        return "remote"
    return text


def canonical_url(value: str) -> str:
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    path = re.sub(r"/(apply|application)/?$", "", parts.path.rstrip("/"), flags=re.IGNORECASE)
    return urlunsplit((parts.scheme.casefold(), parts.netloc.casefold(), path, "", ""))


def canonical_key(vacancy: Vacancy) -> str:
    return "|".join(
        (
            normalise_identity(vacancy.company),
            normalise_identity(vacancy.title),
            normalise_location(vacancy.location),
        )
    )


def same_vacancy(left: Vacancy, right: Vacancy) -> bool:
    if left.board == right.board:
        return left.job_id == right.job_id
    if canonical_url(left.url) and canonical_url(left.url) == canonical_url(right.url):
        return True
    if not normalise_identity(left.company):
        return False
    if normalise_identity(left.company) != normalise_identity(right.company):
        return False
    if SequenceMatcher(
        None,
        normalise_identity(left.title),
        normalise_identity(right.title),
    ).ratio() < 0.92:
        return False
    left_location = normalise_location(left.location)
    right_location = normalise_location(right.location)
    return (
        left_location == right_location
        or "remote" in (left_location, right_location)
        or not left_location
        or not right_location
    )


@dataclass(frozen=True)
class DeduplicationResult:
    representative: Vacancy
    duplicate_keys: tuple[str, ...]
    canonical_key: str


def deduplicate(
    vacancies: Sequence[Vacancy],
    source_priority: Mapping[str, int] | None = None,
) -> list[DeduplicationResult]:
    priorities = dict(DEFAULT_SOURCE_PRIORITY if source_priority is None else source_priority)
    groups: list[list[Vacancy]] = []
    for vacancy in vacancies:
        for group in groups:
            if same_vacancy(vacancy, group[0]):
                group.append(vacancy)
                break
        else:
            groups.append([vacancy])
    output: list[DeduplicationResult] = []
    for group in groups:
        representative = min(
            group,
            key=lambda item: (
                priorities.get(item.board, 9),
                -len(item.description),
                item.key,
            ),
        )
        output.append(
            DeduplicationResult(
                representative=representative,
                duplicate_keys=tuple(sorted(item.key for item in group if item.key != representative.key)),
                canonical_key=canonical_key(representative),
            )
        )
    return output
