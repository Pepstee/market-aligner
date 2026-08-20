"""Shared HTTP, sitemap and JobPosting helpers for country-board adapters.

These helpers deliberately use only public pages and advertised sitemaps.  They
do not call private APIs, evade access controls, or move LLM work into the
collector.
"""

from __future__ import annotations

import html
import json
import re
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Iterable

from .base import USER_AGENT
from .uk_common import plain_text, salary_text


def get_public(
    url: str, *, timeout: float = 30.0, attempts: int = 3,
    params: dict[str, Any] | None = None,
):
    """Fetch a public page with conservative retries for transient failures."""
    import requests

    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            response = requests.get(
                url,
                params=params,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept-Language": "en-GB,en;q=0.9,de;q=0.7,nl;q=0.6",
                },
                timeout=timeout,
            )
            if response.status_code == 429 or response.status_code >= 500:
                raise requests.HTTPError(
                    f"transient status {response.status_code} for {url}", response=response
                )
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            last = exc
            if attempt < attempts:
                time.sleep(float(attempt))
    assert last is not None
    raise last


class PacedDetails:
    """Per-adapter detail-request pacing shared safely across fetch workers."""

    def _init_pacing(self) -> None:
        self._request_lock = threading.Lock()
        self._next_detail_request = 0.0

    def _pace_detail_request(self, default: float = 0.5) -> None:
        interval = float(
            self._board_config().get("detail_request_interval_seconds", default) or 0
        )
        if not interval:
            return
        with self._request_lock:
            delay = self._next_detail_request - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._next_detail_request = time.monotonic() + interval


def sitemap_rows(content: bytes | str) -> list[tuple[str, str | None]]:
    root = ET.fromstring(content)
    return [
        (
            str(row.findtext("{*}loc") or "").strip(),
            str(row.findtext("{*}lastmod") or "").strip() or None,
        )
        for row in root.findall(".//{*}url")
        if str(row.findtext("{*}loc") or "").strip()
    ]


def _walk_json(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def jobposting_json_ld(page: str) -> dict[str, Any]:
    """Find a JobPosting even when nested under @graph or mainEntity."""
    for match in re.finditer(
        r'<script\b[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        page,
        flags=re.I | re.S,
    ):
        raw = html.unescape(match.group(1)).strip()
        try:
            # A small number of otherwise valid vacancy scripts contain literal
            # tabs/newlines inside description strings. ``strict=False`` keeps
            # those public JobPosting records without weakening type checks.
            value = json.loads(raw, strict=False)
        except (json.JSONDecodeError, TypeError):
            recovered = _recover_broken_jobposting(raw)
            if recovered:
                return recovered
            continue
        for candidate in _walk_json(value):
            types = candidate.get("@type")
            if types == "JobPosting" or (
                isinstance(types, list) and "JobPosting" in types
            ):
                return dict(candidate)
    raise ValueError("detail page omitted JobPosting JSON-LD")


def _recover_broken_jobposting(raw: str) -> dict[str, Any] | None:
    """Recover public JSON-LD whose description contains unescaped quotes.

    Several boards emit otherwise complete JobPosting scripts that are invalid
    JSON only because employer prose contains literal quotation marks.  The
    full visible page remains the authoritative requirements source; this
    fallback recovers just the structured identity fields instead of dropping
    the advert.
    """
    if not re.search(r'"@type"\s*:\s*"JobPosting"', raw, re.I):
        return None

    def between(key: str, next_keys: str) -> str:
        match = re.search(
            rf'"{key}"\s*:\s*"(.*?)"\s*,\s*"(?:{next_keys})"\s*:',
            raw, re.I | re.S,
        )
        if not match:
            return ""
        value = match.group(1).replace(r'\"', '"').replace(r'\n', "\n")
        return value.replace(r'\/', "/")

    title = between("title", "description")
    description = between(
        "description", "datePosted|validThrough|hiringOrganization|employmentType"
    )
    if not title or not description:
        return None
    result: dict[str, Any] = {
        "@context": "https://schema.org", "@type": "JobPosting",
        "title": title, "description": description,
    }
    for key, next_keys in (
        ("datePosted", "validThrough|employmentType|hiringOrganization"),
        ("validThrough", "employmentType|hiringOrganization|jobLocation"),
        ("employmentType", "hiringOrganization|jobLocation|baseSalary"),
    ):
        value = between(key, next_keys)
        if value:
            result[key] = value
    organization = re.search(
        r'"hiringOrganization"\s*:\s*\{.*?"name"\s*:\s*"([^"]+)"',
        raw, re.I | re.S,
    )
    if organization:
        result["hiringOrganization"] = {
            "@type": "Organization", "name": organization.group(1)
        }
    locality = re.search(r'"addressLocality"\s*:\s*"([^"]+)"', raw, re.I)
    country = re.search(r'"addressCountry"\s*:\s*"([^"]+)"', raw, re.I)
    if locality or country:
        result["jobLocation"] = {
            "@type": "Place",
            "address": {
                "@type": "PostalAddress",
                "addressLocality": locality.group(1) if locality else "",
                "addressCountry": country.group(1) if country else "",
            },
        }
    result["structured_data_recovered"] = True
    return result


def location_text(value: Any, fallback: str) -> str:
    rows = value if isinstance(value, list) else [value]
    found: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        address = row.get("address") or {}
        if isinstance(address, str):
            found.append(address)
            continue
        if not isinstance(address, dict):
            continue
        parts = [
            address.get("streetAddress"), address.get("postalCode"),
            address.get("addressLocality"), address.get("addressRegion"),
            address.get("addressCountry"),
        ]
        rendered = ", ".join(str(part) for part in parts if part)
        if rendered:
            found.append(rendered)
    return "; ".join(dict.fromkeys(found)) or fallback


def enrich_jobposting(
    data: dict[str, Any], *, page: str, source_url: str,
    source_name: str, fallback_country: str, full_text: str = "",
) -> dict[str, Any]:
    company = data.get("hiringOrganization") or {}
    if not isinstance(company, dict):
        company = {}
    salary = data.get("baseSalary") or {}
    if not isinstance(salary, dict):
        salary = {}
    salary_value = salary.get("value") or {}
    if not isinstance(salary_value, dict):
        salary_value = {}
    description = plain_text(data.get("description"))
    complete = plain_text(full_text) or description
    data.update(
        title=str(data.get("title") or data.get("name") or ""),
        company=str(company.get("name") or ""),
        location_text=location_text(data.get("jobLocation"), fallback_country),
        content_text=complete,
        description=description or complete,
        salary_text=salary_text(
            salary_value.get("minValue"), salary_value.get("maxValue"),
            salary.get("currency"), salary_value.get("unitText"),
        ),
        source_url=source_url,
        source_attribution=source_name,
        detail_fetch_status="full_page",
    )
    return data


_TITLE_MARKERS = (
    # English target and adjacent implementation tracks.
    "artificial intelligence", "machine learning", "generative ai", " ai ",
    " llm ", " mlops ", "automation", "software", "python", "developer",
    "data engineer", "data scientist", "data analyst", "analytics",
    " cloud ", "platform", "devops", " sre ", "site reliability", "cyber",
    " security ", "infrastructure", "system engineer", "systems engineer", "solution architect",
    "solutions engineer", "technical consultant", "technical support",
    "application support", "implementation", "digital transformation",
    "product owner", "technical product", "business analyst", "it project",
    "research software", "computational", "algorithm", "robotic", " hpc ",
    "bioinformatic", "statistical programmer", "information technology",
    # German and Dutch equivalents common on Swiss/Dutch public boards.
    "informatik", "entwickler", "entwicklung", "daten", "kuenstliche intelligenz",
    "künstliche intelligenz", "automatisierung", "sicherheit", "systemingenieur",
    " ict ", "informatiebeveilig", "ontwikkelaar", "ontwikkeling", "gegevens",
    "kunstmatige intelligentie", "automatisering", "informatie technologie",
)


def relevant_title(value: Any, extra_terms: Iterable[str] = ()) -> bool:
    """Broad title-only gate; viability and candidate fit remain downstream."""
    title = " " + re.sub(r"[^\w+#.]+", " ", plain_text(value).casefold()) + " "
    markers = list(_TITLE_MARKERS)
    for term in extra_terms:
        norm = re.sub(r"[^\w+#.]+", " ", str(term).casefold()).strip()
        if norm and len(norm) > 2:
            markers.append(f" {norm} ")
    physical_security = (
        " security guard ", " security officer ", " security person ",
        " security installer ", " door supervisor ", " loss prevention ",
    )
    technical_security = (
        " cyber", " information security ", " application security ",
        " cloud security ", " network security ", " security engineer ",
        " security analyst ", " security architect ", " security operations ",
    )
    if any(marker in title for marker in physical_security) and not any(
        marker in title for marker in technical_security
    ):
        return False
    return any(marker in title for marker in markers)


def html_section(page: str, tag: str) -> str:
    match = re.search(rf'<{tag}\b[^>]*>(.*?)</{tag}>', page, re.I | re.S)
    return match.group(1) if match else ""
