"""Additional Dutch academic, government, startup and international boards."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from .base import Adapter, contracts_now, register
from .country_common import (
    PacedDetails, enrich_jobposting, get_public, html_section,
    jobposting_json_ld, relevant_title, sitemap_rows,
)
from contracts import JobUrl, RawPosting


class _DutchSitemapAdapter(PacedDetails, Adapter):
    sitemap_url = ""
    source_name = ""
    path_prefix = ""
    keep_all = False
    default_interval = 0.5

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._init_pacing()

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        response = get_public(
            self.sitemap_url, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        seen: set[str] = set()
        for url, lastmod in sitemap_rows(response.content):
            path = urlsplit(url).path
            if not path.startswith(self.path_prefix):
                continue
            slug = path.rstrip("/").split("/")[-1]
            if not self.keep_all and not relevant_title(slug, terms):
                continue
            job_id = self._job_id(url, slug)
            if job_id in seen:
                continue
            seen.add(job_id)
            yield JobUrl(self.board, job_id, url, lastmod)

    def _job_id(self, url: str, slug: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        self._pace_detail_request(self.default_interval)
        response = get_public(
            job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        data = jobposting_json_ld(response.text)
        enrich_jobposting(
            data, page=response.text, source_url=response.url,
            source_name=self.source_name, fallback_country="Netherlands",
            full_text=html_section(response.text, "main"),
        )
        return RawPosting(
            self.board, job.job_id, response.url, contracts_now(), raw_json=data
        )


@register
class AcademicTransferAdapter(_DutchSitemapAdapter):
    board = "academictransfer"
    sitemap_url = "https://www.academictransfer.com/sitemap-vacancies.xml"
    source_name = "AcademicTransfer"
    path_prefix = "/en/jobs/"
    default_interval = 10.0

    def _job_id(self, url: str, slug: str) -> str:
        parts = urlsplit(url).path.strip("/").split("/")
        return parts[2] if len(parts) > 2 and parts[2].isdigit() else super()._job_id(url, slug)


@register
class WerkenVoorNederlandAdapter(_DutchSitemapAdapter):
    board = "werkenvoornederland"
    sitemap_url = "https://www.werkenvoornederland.nl/sitemap-vacatures.xml"
    source_name = "Werken voor Nederland"
    path_prefix = "/vacatures/"
    default_interval = 0.2


@register
class MagnetMeAdapter(_DutchSitemapAdapter):
    board = "magnetme"
    sitemap_url = "https://magnet.me/sitemaps/en-opportunities.xml"
    source_name = "Magnet.me"
    path_prefix = "/en/opportunity/"
    default_interval = 1.0

    def _job_id(self, url: str, slug: str) -> str:
        parts = urlsplit(url).path.strip("/").split("/")
        return parts[2] if len(parts) > 2 and parts[2].isdigit() else super()._job_id(url, slug)


@register
class UndutchablesAdapter(_DutchSitemapAdapter):
    board = "undutchables"
    sitemap_url = "https://undutchables.nl/sitemaps-1-section-vacancies-1-sitemap.xml"
    source_name = "Undutchables"
    path_prefix = "/vacancies/"
    keep_all = True
    default_interval = 0.5

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        self._pace_detail_request(self.default_interval)
        response = get_public(
            job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        data = jobposting_json_ld(response.text)
        vacancy = re.search(
            r'<div\b[^>]*id=["\']vacancy-details["\'][^>]*>(.*?)'
            r'<div\b[^>]*id=["\']attention["\']',
            response.text, re.I | re.S,
        )
        full_text = vacancy.group(1) if vacancy else html_section(response.text, "main")
        enrich_jobposting(
            data, page=response.text, source_url=response.url,
            source_name=self.source_name, fallback_country="Netherlands",
            full_text=full_text,
        )
        return RawPosting(
            self.board, job.job_id, response.url, contracts_now(), raw_json=data
        )


@register
class GraduateNLAdapter(PacedDetails, Adapter):
    """Graduate Ventures portfolio-company board (public Getro sitemap)."""

    board = "graduatenl"
    sitemap_url = "https://jobs.graduate.nl/sitemap.xml"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._init_pacing()

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        response = get_public(
            self.sitemap_url, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        seen: set[str] = set()
        for url, lastmod in sitemap_rows(response.content):
            parts = urlsplit(url).path.strip("/").split("/")
            if len(parts) != 4 or parts[0] != "companies" or parts[2] != "jobs":
                continue
            job_id, _, slug = parts[3].partition("-")
            if not job_id.isdigit() or job_id in seen or "closed" in slug.casefold():
                continue
            seen.add(job_id)
            yield JobUrl(self.board, job_id, url, lastmod)

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        self._pace_detail_request()
        response = get_public(
            job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        data = jobposting_json_ld(response.text)
        enrich_jobposting(
            data, page=response.text, source_url=response.url,
            source_name="Graduate Ventures Job Board", fallback_country="Netherlands",
            full_text=html_section(response.text, "main"),
        )
        match = re.search(
            r'<a\b[^>]*data-testid=["\']button-apply-now["\'][^>]*href=["\']([^"\']+)',
            response.text, re.I,
        )
        if match:
            data["original_apply_url"] = match.group(1).replace("&amp;", "&")
        return RawPosting(
            self.board, job.job_id, response.url, contracts_now(), raw_json=data
        )
