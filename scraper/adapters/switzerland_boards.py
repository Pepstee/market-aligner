"""Public specialist Swiss technology vacancy sources."""

from __future__ import annotations

import hashlib
import html
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from .base import Adapter, contracts_now, register
from .country_common import (
    PacedDetails, enrich_jobposting, get_public, html_section,
    jobposting_json_ld, relevant_title, sitemap_rows,
)
from .uk_common import plain_text
from contracts import JobUrl, RawPosting


class _SwissSitemapAdapter(PacedDetails, Adapter):
    sitemap_url = ""
    source_name = ""
    path_prefix = ""
    fallback_country = "Switzerland"
    keep_all = False

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
        self._pace_detail_request()
        response = get_public(
            job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        data = jobposting_json_ld(response.text)
        main = html_section(response.text, "main")
        enrich_jobposting(
            data, page=response.text, source_url=response.url,
            source_name=self.source_name, fallback_country=self.fallback_country,
            full_text=main,
        )
        apply = re.search(
            r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>\s*'
            r'(?:Apply(?: now)?|Jetzt bewerben|Postuler)',
            response.text, re.I | re.S,
        )
        if apply:
            data["original_apply_url"] = html.unescape(apply.group(1))
        return RawPosting(
            self.board, job.job_id, response.url, contracts_now(), raw_json=data
        )


@register
class ITJobsCHAdapter(_SwissSitemapAdapter):
    board = "itjobsch"
    sitemap_url = "https://www.itjobs.ch/sitemap-jobs-1.xml"
    source_name = "IT Jobs Switzerland"
    path_prefix = "/jobs/"

    def _job_id(self, url: str, slug: str) -> str:
        match = re.match(r"(\d+)-", slug)
        return match.group(1) if match else super()._job_id(url, slug)


@register
class ITBoardCHAdapter(_SwissSitemapAdapter):
    board = "itboardch"
    sitemap_url = "https://www.itboard.ch/sitemap.xml"
    source_name = "ITBoard Switzerland"
    path_prefix = "/job/"

    def _job_id(self, url: str, slug: str) -> str:
        match = re.search(
            r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
            slug, re.I,
        )
        return match.group(1) if match else super()._job_id(url, slug)


@register
class SwissAIJobAdapter(PacedDetails, Adapter):
    board = "swissaijob"
    homepage = "https://swissaijob.ch/"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._init_pacing()

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        response = get_public(
            self.homepage, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        found = re.findall(r'href=["\'](/jobs/[^"\']+?-(\d+))["\']', response.text, re.I)
        seen: set[str] = set()
        for path, job_id in found:
            if job_id in seen:
                continue
            seen.add(job_id)
            yield JobUrl(self.board, job_id, f"https://swissaijob.ch{path}", None)

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        self._pace_detail_request()
        response = get_public(
            job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        data = jobposting_json_ld(response.text)
        enrich_jobposting(
            data, page=response.text, source_url=response.url,
            source_name="Swiss AI Jobs", fallback_country="Switzerland",
            full_text=html_section(response.text, "main"),
        )
        apply = re.search(
            r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>\s*(?:Apply|Jetzt bewerben)',
            response.text, re.I | re.S,
        )
        if apply:
            data["original_apply_url"] = apply.group(1)
        return RawPosting(
            self.board, job.job_id, response.url, contracts_now(), raw_json=data
        )


@register
class DeveloperJobsCHAdapter(_SwissSitemapAdapter):
    """English canonical URLs from a four-language Swiss developer sitemap."""

    board = "developerjobsch"
    sitemap_url = "https://developerjobs.ch/sitemaps/jobs-1.xml"
    source_name = "DeveloperJobs.ch"
    path_prefix = "/en/jobs/"
    keep_all = True

    def _job_id(self, url: str, slug: str) -> str:
        return slug


@register
class SwissFederalJobsAdapter(PacedDetails, Adapter):
    """Official Swiss Federal Administration public vacancy endpoint."""

    board = "swissfederal"
    jobs_url = "https://ohws.prospective.ch/public/v1/medium/1007546/jobs"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._init_pacing()
        self._jobs: dict[str, dict[str, Any]] = {}

    def _load_jobs(self) -> list[dict[str, Any]]:
        cfg = self._board_config()
        response = get_public(
            self.jobs_url,
            params={"lang": "en", "offset": 0, "limit": 96},
            timeout=float(cfg.get("timeout_seconds", 30) or 30),
        )
        payload = response.json()
        rows = list(payload.get("jobs") or []) if isinstance(payload, dict) else []
        self._jobs.update(
            {str(row.get("id")): row for row in rows if isinstance(row, dict) and row.get("id")}
        )
        return rows

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        for row in self._load_jobs():
            title = str(row.get("title") or "")
            if not relevant_title(title, terms):
                continue
            job_id = str(row.get("id"))
            links = row.get("links") or {}
            url = str(links.get("directlink") or "") if isinstance(links, dict) else ""
            if url:
                yield JobUrl(self.board, job_id, url, str(row.get("start_date") or "") or None)

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        self._pace_detail_request()
        row = self._jobs.get(job.job_id)
        if row is None:
            self._load_jobs()
            row = self._jobs.get(job.job_id)
        if row is None:
            raise ValueError(f"Swiss federal vacancy {job.job_id} is no longer current")
        data = dict(row)
        attrs = row.get("attributes") or {}
        szas = row.get("szas") or {}
        if not isinstance(attrs, dict):
            attrs = {}
        if not isinstance(szas, dict):
            szas = {}
        tasks = plain_text(szas.get("sza_tasks"))
        requirements = plain_text(szas.get("sza_requirements"))
        profile = plain_text(szas.get("sza_company_profil"))
        benefits = plain_text(szas.get("sza_benefits"))

        def first(key: str) -> str:
            values = attrs.get(key) or []
            return str(values[0]) if isinstance(values, list) and values else str(values or "")

        content = " ".join(value for value in (tasks, requirements, profile, benefits) if value)
        data.update(
            title=str(row.get("title") or szas.get("sza_title") or ""),
            company=first("verwaltungseinheit_1660323") or first("verwaltungseinheit"),
            location_text=first("arbeitsort") or str(szas.get("sza_location.city") or "Switzerland"),
            content_text=content,
            description=content,
            responsibilities_text=tasks,
            requirements_text=requirements,
            application_deadline=str(row.get("end_date") or ""),
            original_apply_url=str(szas.get("sza_apply_link") or ""),
            source_url=job.url,
            source_attribution="Swiss Federal Jobs Portal",
            detail_fetch_status="public_api_complete",
        )
        return RawPosting(
            self.board, job.job_id, job.url, contracts_now(), raw_json=data
        )
