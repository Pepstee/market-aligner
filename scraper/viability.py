"""Deterministic pre-LLM gate for collected UK vacancies.

The raw ``postings`` table is immutable input.  This module produces an
auditable decision for every row and selects one representative for each
cross-source vacancy.  It never imports an LLM or performs scoring.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from difflib import SequenceMatcher
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit


UK_MARKERS = (
    "united kingdom", "great britain", " uk", "u.k.", "england", "scotland",
    "wales", "northern ireland", "london", "bristol", "cambridge", "manchester",
    "birmingham", "edinburgh", "glasgow", "leeds", "liverpool", "newcastle",
    "nottingham", "reading", "oxford", "cardiff", "belfast",
)
REMOTE_MARKERS = ("remote", "work from home", "distributed", "telecommut")
REMOTE_BOARDS = {"jobicy", "remotive", "himalayas", "weworkremotely", "remoteok", "remotefirst"}
FOREIGN_COUNTRY_BOARDS = {
    "jobsch", "jobscout24", "irishjobs", "jobsie", "techjobsie",
    "iamexpatnl", "uprotterdam",
}
NON_UK_ONLY = (
    "united states only", "us only", "u.s. only", "canada only", "india only",
    "australia only", "latin america only", "latam only", "must be based in the us",
    "authorized to work in the united states", "authorised to work in the united states",
)
FOREIGN_LOCATION_SUFFIX = re.compile(
    r"\b(?:china|united states|usa|canada|australia|india|singapore|hong kong|japan|"
    r"south korea|germany|france|spain|italy|netherlands|belgium|switzerland|austria|"
    r"sweden|norway|denmark|finland|ireland|poland|portugal|czechia|czech republic|"
    r"romania|hungary|greece|turkey|israel|united arab emirates|uae)\s*$",
    re.I,
)
CROSS_BORDER_REMOTE_SCOPE = re.compile(
    r"\b(?:remote(?:ly)?|work(?:ing)? from (?:home|anywhere))\b"
    r"[^.!?\n]{0,100}\b(?:united kingdom|u\.?k\.?|europe|european|emea|worldwide|anywhere|global)\b"
    r"|\b(?:united kingdom|u\.?k\.?|europe|emea|worldwide|global)\b"
    r"[^.!?\n]{0,100}\bremote(?:ly)?\b",
    re.I,
)
CROSS_BORDER_ENGAGEMENT = re.compile(
    r"\b(?:employer of record|eor|global payroll|hire (?:you )?in the uk|"
    r"uk payroll|international contractor|independent contractor|b2b contract)\b",
    re.I,
)
GLOBAL_REMOTE_LOCATION = re.compile(
    r"\b(?:anywhere(?: in the world)?|worldwide|global|europe|emea)\b",
    re.I,
)
# Citizenship is not residency.  These phrases tie a remote vacancy to a
# jurisdiction outside the UK and therefore cannot be satisfied by remaining
# UK-resident, even when the candidate is an EU citizen.
RESIDENCY_RESTRICTION = re.compile(
    r"\b(?:must|need|required) (?:to )?(?:be )?(?:based|located|resident|reside|live|work) (?:in|within) "
    r"(?:the )?(?!united kingdom\b|uk\b)[a-z][a-z .'-]{2,35}\b"
    r"|\bremote (?:only )?(?:in|within|from) (?:the )?"
    r"(?:eu|european union|eea|ireland|germany|france|spain|italy|netherlands|belgium|"
    r"switzerland|austria|sweden|norway|denmark|finland|poland|portugal|romania)\b"
    r"|\bremote work\b[^.!?\n]{0,60}\b(?:in|within|from) (?:the )?"
    r"(?:eu|european union|eea|ireland|germany|france|spain|italy|netherlands|belgium|"
    r"switzerland|austria|sweden|norway|denmark|finland|poland|portugal|romania)\b"
    r"|\b(?:eu|european union|eea|ireland|germany|france|spain|italy|netherlands|belgium|"
    r"switzerland|austria|sweden|norway|denmark|finland|poland|portugal|romania)[ -]only\b",
    re.I,
)

RELEVANT_TITLE = re.compile(
    r"\b(ai|artificial intelligence|machine learning|ml|llm|generative ai|agentic|"
    r"automation|python|software|backend|back-end|full[ -]?stack|platform|cloud|devops|"
    r"mlops|site reliability|sre|security|cyber|detection|solutions?|implementation|"
    r"technical|data engineer|data scientist|research engineer|pytorch|infrastructure|"
    r"developer|technology|systems? engineer)\b",
    re.I,
)
IRRELEVANT_TITLE = re.compile(
    r"\b(account executive|sales representative|sales manager|business development|"
    r"marketing manager|content writer|copywriter|recruiter|talent acquisition|human resources|"
    r"people partner|finance manager|financial controller|lawyer|legal counsel|paralegal|"
    r"graphic designer|product designer|ux designer|ui designer|motion designer|architectural designer|"
    r"nurse|physician|pharmacist|therapist|warehouse|driver|electrician|mechanical engineer|"
    r"electrical engineer|firmware engineer|embedded engineer|silicon engineer|hardware engineer|"
    r"medical technical officer)\b",
    re.I,
)
PHYSICAL_SECURITY_TITLE = re.compile(
    r"\b(?:fire safety and security|security\s+(?:co-?ordinator|officer|assistant|guard|porter)|"
    r"corporate security officer|site security officer|local security management)\b",
    re.I,
)
ACADEMIC_TEACHING_TITLE = re.compile(
    r"\b(?:associate professor|assistant professor|professor|lecturer|teaching\s+(?:associate|fellow)|"
    r"faculty position|faculty member|phd position|doctoral position|phd studentship|doctoral studentship)\b",
    re.I,
)
SENIOR_TITLE = re.compile(
    r"\b(senior|sr\.?|staff|principal|lead|manager|director|head|vice president|vp|chief)\b",
    re.I,
)
# "Associate" and "fellow" are not reliable entry-level markers in UK adverts:
# Associate Professor, Research Fellow, and Clinical Fellow are common counterexamples.
ENTRY_TITLE = re.compile(r"\b(graduate|junior|jr\.?|entry[ -]?level|intern)\b", re.I)
HARD_YEARS = re.compile(
    r"\b(?:minimum(?: of)?|at least|must have|requires?|required|you have|you'll have|"
    r"we are looking for|we're looking for)[^.!?\n]{0,100}?\b([4-9]|[1-9]\d)\+?\s*years?\b",
    re.I,
)

SOURCE_PRIORITY = {
    "greenhouse": 0, "lever": 0, "smartrecruiters": 0, "ashby": 0,
    "workable": 0, "recruitee": 0, "personio": 0, "workday": 0,
    "reed": 1, "guardianjobs": 1, "nhsjobs": 1, "jobsacuk": 1,
    "jobsch": 1, "jobscout24": 1,
    "techjobsie": 1,
    "iamexpatnl": 1, "uprotterdam": 1,
    "adzuna": 2, "jooble": 2,
    "arbeitnow": 3, "jobicy": 3, "remotive": 3, "himalayas": 3,
    "muse": 3, "weworkremotely": 3, "remoteok": 3, "remotefirst": 3,
}


@dataclass
class Vacancy:
    key: str
    board: str
    job_id: str
    url: str
    posted_at: str
    raw_text: str
    raw_json: dict[str, Any]
    title: str
    company: str
    location: str
    body: str
    expiry: str


@dataclass
class ViabilityDecision:
    key: str
    board: str
    job_id: str
    url: str
    title: str
    company: str
    location: str
    decision: str
    reason: str
    canonical_key: str
    representative_key: str = ""
    http_status: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _flatten(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        preferred = [
            value.get(k) for k in ("name", "title", "display_name", "location_str", "city",
                                     "country", "country_name", "label") if value.get(k)
        ]
        return " ".join(_flatten(v) for v in (preferred or value.values()))
    if isinstance(value, (list, tuple, set)):
        return "; ".join(_flatten(v) for v in value if v is not None)
    return str(value)


def _first(row: dict[str, Any], names: Iterable[str]) -> str:
    for name in names:
        value = row.get(name)
        text = _flatten(value).strip()
        if text:
            return text
    return ""


def vacancy_from_db_row(row: tuple[Any, ...]) -> Vacancy:
    key, board, job_id, url, posted_at, raw_text, raw_json = row
    try:
        payload = json.loads(raw_json) if raw_json else {}
    except (TypeError, json.JSONDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    title = _first(payload, ("title", "job_title", "jobTitle", "name", "position", "positionTitle", "text"))
    company = _first(payload, ("company", "companyName", "employerName", "organization", "hiringOrganization"))
    location = _first(payload, (
        "location_text", "location", "locations", "locationRestrictions", "jobLocation",
        "city", "country", "workplace",
    ))
    body = _first(payload, (
        "content_text", "descriptionPlain", "description", "jobDescription", "contents",
        "text", "snippet", "requirements",
    )) or str(raw_text or "")
    expiry = _first(payload, (
        "expiryDate", "expires_at", "expirationDate", "application_deadline", "validThrough",
        "deadline",
    ))
    effective_posted_at = str(posted_at or _first(payload, (
        "datePosted", "postedAt", "published_at", "publicationDate", "createdAt",
    )))
    return Vacancy(
        key=str(key), board=str(board), job_id=str(job_id), url=str(url or ""),
        posted_at=effective_posted_at, raw_text=str(raw_text or ""), raw_json=payload,
        title=title, company=company, location=location, body=body, expiry=expiry,
    )


def _normal(value: str) -> str:
    value = value.casefold().replace("&", " and ")
    value = re.sub(r"\b(ltd|limited|plc|inc|llc|corp|corporation|company|co)\b", " ", value)
    return re.sub(r"[^a-z0-9]+", " ", value).strip()


def _normal_location(value: str) -> str:
    text = _normal(value)
    if any(marker.strip() in f" {text}" for marker in ("remote", "worldwide", "europe", "emea")):
        return "remote"
    for city in ("london", "bristol", "cambridge", "manchester", "birmingham", "edinburgh",
                 "glasgow", "leeds", "liverpool", "newcastle", "nottingham", "reading", "oxford",
                 "cardiff", "belfast"):
        if city in text:
            return city
    return "uk" if any(m.strip() in f" {text}" for m in UK_MARKERS[:8]) else text


def canonical_key(vacancy: Vacancy) -> str:
    return "|".join((_normal(vacancy.company), _normal(vacancy.title), _normal_location(vacancy.location)))


def _parse_date(value: str) -> date | None:
    if not value:
        return None
    candidate = value.strip()[:10]
    try:
        return date.fromisoformat(candidate)
    except ValueError:
        return None


def _cross_border_remote_eligible(vacancy: Vacancy, location_blob: str, body_head: str) -> bool:
    """Return whether a non-UK job explicitly supports work from UK residence."""
    combined = f"{location_blob}\n{body_head}"
    remote = vacancy.board in REMOTE_BOARDS or any(
        marker in combined for marker in ("remote", "work from home", "telecommut")
    )
    if not remote or RESIDENCY_RESTRICTION.search(combined):
        return False

    # A scoped location is the strongest common board signal (for example,
    # "Remote — Europe" or "EMEA Remote").  In prose, require scope and
    # remote wording to occur close together so "global company" does not pass.
    location_scoped = bool(
        CROSS_BORDER_REMOTE_SCOPE.search(location_blob)
        or (vacancy.board in REMOTE_BOARDS and GLOBAL_REMOTE_LOCATION.search(location_blob))
    )
    prose_scoped = bool(CROSS_BORDER_REMOTE_SCOPE.search(body_head))
    engagement = bool(CROSS_BORDER_ENGAGEMENT.search(combined))
    return location_scoped or prose_scoped or engagement


def local_decision(vacancy: Vacancy, *, today: date | None = None) -> ViabilityDecision:
    today = today or datetime.now(timezone.utc).date()
    canonical = canonical_key(vacancy)
    base = dict(
        key=vacancy.key, board=vacancy.board, job_id=vacancy.job_id, url=vacancy.url,
        title=vacancy.title, company=vacancy.company, location=vacancy.location,
        canonical_key=canonical,
    )
    expiry = _parse_date(vacancy.expiry)
    if expiry and expiry < today:
        return ViabilityDecision(**base, decision="exclude", reason="expired")
    posted = _parse_date(vacancy.posted_at)
    if posted and posted < today - timedelta(days=365):
        return ViabilityDecision(**base, decision="exclude", reason="stale_posting")
    if not vacancy.url.startswith(("https://", "http://")):
        return ViabilityDecision(**base, decision="exclude", reason="missing_or_invalid_url")
    if not vacancy.title:
        return ViabilityDecision(**base, decision="exclude", reason="missing_title")
    if vacancy.raw_json.get("detail_fetch_status") == "listing_excerpt_only":
        return ViabilityDecision(**base, decision="exclude", reason="incomplete_description")
    if PHYSICAL_SECURITY_TITLE.search(vacancy.title):
        return ViabilityDecision(**base, decision="exclude", reason="physical_security_role")
    if ACADEMIC_TEACHING_TITLE.search(vacancy.title):
        return ViabilityDecision(**base, decision="exclude", reason="academic_teaching_role")
    if IRRELEVANT_TITLE.search(vacancy.title):
        return ViabilityDecision(**base, decision="exclude", reason="irrelevant_title")
    if not RELEVANT_TITLE.search(vacancy.title) and not ENTRY_TITLE.search(vacancy.title):
        return ViabilityDecision(**base, decision="exclude", reason="title_outside_target_families")
    if SENIOR_TITLE.search(vacancy.title) and not ENTRY_TITLE.search(vacancy.title):
        return ViabilityDecision(**base, decision="exclude", reason="unrealistic_seniority_title")
    if HARD_YEARS.search(vacancy.body):
        return ViabilityDecision(**base, decision="exclude", reason="hard_4plus_year_requirement")

    # Older jobs.ac.uk rows may contain an over-wide extraction spanning most
    # of the page.  The real location sits immediately before the Salary label,
    # i.e. at the end of that value; bound it here without mutating raw data.
    effective_location = vacancy.location
    if vacancy.board == "jobsacuk" and len(effective_location) > 80:
        effective_location = effective_location[-80:]
    location_blob = f" {effective_location.casefold()} "
    body_head = f" {vacancy.body[:5000].casefold()} "
    remote_location = vacancy.board in REMOTE_BOARDS or any(
        marker in location_blob for marker in REMOTE_MARKERS
    )
    if any(marker in location_blob or marker in body_head for marker in NON_UK_ONLY):
        return ViabilityDecision(**base, decision="exclude", reason="not_uk_eligible")
    if RESIDENCY_RESTRICTION.search(location_blob + body_head):
        return ViabilityDecision(**base, decision="exclude", reason="foreign_residency_required")
    uk_location = any(marker in location_blob for marker in UK_MARKERS)
    cross_border_remote = _cross_border_remote_eligible(vacancy, location_blob, body_head)
    if (
        vacancy.board in FOREIGN_COUNTRY_BOARDS
        or FOREIGN_LOCATION_SUFFIX.search(effective_location.strip())
    ) and not cross_border_remote:
        return ViabilityDecision(**base, decision="exclude", reason="not_uk_eligible")
    if not uk_location and not cross_border_remote:
        return ViabilityDecision(**base, decision="exclude", reason="uk_residence_compatibility_not_explicit")
    return ViabilityDecision(**base, decision="include", reason="viable")


def _canonical_url(value: str) -> str:
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    path = re.sub(r"/(apply|application)/?$", "", parts.path.rstrip("/"), flags=re.I)
    return urlunsplit((parts.scheme.casefold(), parts.netloc.casefold(), path, "", ""))


def _same_vacancy(a: Vacancy, b: Vacancy) -> bool:
    if a.board == b.board:
        return False
    if _canonical_url(a.url) and _canonical_url(a.url) == _canonical_url(b.url):
        return True
    if not _normal(a.company) or _normal(a.company) != _normal(b.company):
        return False
    title_similarity = SequenceMatcher(None, _normal(a.title), _normal(b.title)).ratio()
    if title_similarity < 0.92:
        return False
    loc_a, loc_b = _normal_location(a.location), _normal_location(b.location)
    return (
        loc_a == loc_b
        or "remote" in (loc_a, loc_b)
        or "uk" in (loc_a, loc_b)
        or not loc_a
        or not loc_b
    )


def _representative(vacancies: list[Vacancy]) -> Vacancy:
    return min(
        vacancies,
        key=lambda v: (
            SOURCE_PRIORITY.get(v.board, 9),
            -len(v.body),
            v.key,
        ),
    )


def deduplicate(vacancies: list[Vacancy], decisions: dict[str, ViabilityDecision]) -> None:
    candidates = [v for v in vacancies if decisions[v.key].decision == "include"]
    groups: list[list[Vacancy]] = []
    for vacancy in candidates:
        for group in groups:
            if _same_vacancy(vacancy, group[0]):
                group.append(vacancy)
                break
        else:
            groups.append([vacancy])
    for group in groups:
        representative = _representative(group)
        decisions[representative.key].representative_key = representative.key
        for vacancy in group:
            if vacancy.key == representative.key:
                continue
            decision = decisions[vacancy.key]
            decision.decision = "exclude"
            decision.reason = "cross_source_duplicate"
            decision.representative_key = representative.key


def probe_url(url: str, timeout: float = 8.0) -> int | None:
    """Return an HTTP status without treating access controls as dead links."""
    import requests

    headers = {"User-Agent": "Mozilla/5.0 (compatible; UKJobMatcher/2.0)"}
    try:
        response = requests.head(url, headers=headers, allow_redirects=True, timeout=timeout)
        if response.status_code in (405, 501):
            response = requests.get(url, headers={**headers, "Range": "bytes=0-2048"},
                                    allow_redirects=True, timeout=timeout, stream=True)
        return int(response.status_code)
    except requests.RequestException:
        return None


def apply_link_checks(
    vacancies: list[Vacancy], decisions: dict[str, ViabilityDecision], *, workers: int = 24,
    timeout: float = 8.0,
) -> None:
    by_key = {v.key: v for v in vacancies}
    selected = [d for d in decisions.values() if d.decision == "include"]
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(probe_url, by_key[d.key].url, timeout): d for d in selected}
        for future in as_completed(futures):
            decision = futures[future]
            status = future.result()
            decision.http_status = status
            if status in (404, 410):
                decision.decision = "exclude"
                decision.reason = "inaccessible_or_removed"


def evaluate(
    vacancies: list[Vacancy], *, check_links: bool = True, workers: int = 24,
    timeout: float = 8.0, today: date | None = None,
) -> list[ViabilityDecision]:
    decisions = {v.key: local_decision(v, today=today) for v in vacancies}
    deduplicate(vacancies, decisions)
    if check_links:
        apply_link_checks(vacancies, decisions, workers=workers, timeout=timeout)
    return [decisions[v.key] for v in vacancies]
