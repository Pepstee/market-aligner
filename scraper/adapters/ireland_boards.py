"""Ireland state employment and public-service vacancy sources."""

from __future__ import annotations

import html
import io
import math
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterable

from .base import Adapter, contracts_now, register
from .country_common import PacedDetails, get_public, relevant_title
from .uk_common import plain_text
from contracts import JobUrl, RawPosting


def _hidden_rows(page: str) -> list[dict[str, str]]:
    """Parse JobsIreland cards without depending on duplicated HTML IDs."""
    starts = [match.start() for match in re.finditer(r'<div class="job-heading\b', page, re.I)]
    rows: list[dict[str, str]] = []
    for index, start in enumerate(starts):
        block = page[start: starts[index + 1] if index + 1 < len(starts) else len(page)]
        row: dict[str, str] = {}
        for field in ("JobId", "JobTitle", "Location", "StartDate", "EndDate"):
            match = re.search(
                rf'id=["\']{field}["\'][^>]*value=["\']([^"\']*)', block, re.I
            )
            row[field] = html.unescape(match.group(1)).strip() if match else ""
        if row["JobId"] and row["JobTitle"]:
            rows.append(row)
    return rows


def _total_jobs(page: str) -> int:
    match = re.search(r'class=["\']totalCount["\'][^>]*value=["\'](\d+)', page, re.I)
    return int(match.group(1)) if match else 0


def _jobsireland_detail(page: str, source_url: str) -> dict[str, Any]:
    main_match = re.search(r'<main\b[^>]*>(.*?)</main>', page, re.I | re.S)
    main = main_match.group(1) if main_match else page
    title_match = re.search(
        r'<div\b[^>]*class=["\'][^"\']*job-details[^"\']*["\'][^>]*>'
        r'.*?<h3\b[^>]*>(.*?)</h3>', main, re.I | re.S,
    )
    if not title_match:
        title_match = re.search(r'<h1\b[^>]*>(.*?)</h1>', main, re.I | re.S)
    description_match = re.search(
        r'<pre\b[^>]*ng-bind-html=["\']Description[^>]*>(.*?)</pre>', page, re.I | re.S
    )
    description = plain_text(description_match.group(1) if description_match else "")
    content = plain_text(main)
    if description and description not in content:
        content = f"{content} {description}".strip()
    title = plain_text(title_match.group(1) if title_match else "")
    if not title or len(description) < 40:
        raise ValueError("JobsIreland page omitted title or full job description")

    def labelled(label: str) -> str:
        match = re.search(
            rf'<(?:span|strong|h[1-6])\b[^>]*>\s*{label}\s*:?</(?:span|strong|h[1-6])>'
            r'\s*(.*?)(?=</li>|<li\b|</div>)', main, re.I | re.S,
        )
        return plain_text(match.group(1)) if match else ""

    def icon_value(label: str) -> str:
        match = re.search(
            rf'<li\b[^>]*>(?:(?!</li>).)*alt=["\'][^"\']*{label}[^"\']*["\']'
            r'(?:(?!</li>).)*?</div>\s*<div\b[^>]*>(.*?)</div>\s*</li>',
            main, re.I | re.S,
        )
        return plain_text(match.group(1)) if match else ""

    return {
        "title": title,
        "company": labelled("Company") or labelled("Employer") or icon_value("Employer"),
        "location_text": labelled("Location") or icon_value("Location") or "Ireland",
        "salary_text": labelled("Salary") or icon_value("Euro"),
        "contract_type": labelled("Type of Contract") or labelled("Contract Type"),
        "application_deadline": labelled("Closing On") or labelled("Closing Date") or icon_value("Closing"),
        "content_text": content,
        "description": description,
        "source_url": source_url,
        "source_attribution": "JobsIreland",
        "detail_fetch_status": "full_page",
    }


def _jobsireland_pdf_text(
    text: str, listing: dict[str, str], source_url: str, report_url: str,
) -> dict[str, Any]:
    """Map the official one-page JobsIreland vacancy report into raw fields."""
    content = text.strip()
    if len(content) < 200 or "Job Description" not in content:
        raise ValueError("JobsIreland official report omitted the job description")
    company_match = re.search(r"\A(.*?)\n#JOB-", content, re.S)
    company = " ".join((company_match.group(1) if company_match else "").split())
    title_match = re.search(r"\n([^\n]{3,200})\nApplication Details\b", content, re.I)
    title = listing.get("JobTitle", "") or plain_text(
        title_match.group(1) if title_match else ""
    )
    location_match = re.search(
        r"#JOB-\d+\s*\n(.*?)\nNo of positions\s*:", content, re.I | re.S
    )
    location = listing.get("Location", "") or " ".join(
        (location_match.group(1) if location_match else "").split()
    )
    dates = re.findall(r"\b\d{2}/\d{2}/\d{4}\b", content)
    salary_match = re.search(
        r"(?:\d[\d,.]*\s*-\s*)?\d[\d,.]*\s+Euro\s+(?:Annually|Monthly|Weekly|Hourly)",
        content, re.I,
    )
    return {
        "title": title,
        "company": company,
        "location_text": location or "Ireland",
        "salary_text": salary_match.group(0) if salary_match else "",
        "application_deadline": listing.get("EndDate", "") or (dates[-1] if dates else ""),
        "content_text": content,
        "description": content,
        "official_report_url": report_url,
        "source_url": source_url,
        "source_attribution": "JobsIreland",
        "detail_fetch_status": "official_pdf_complete",
    }


@register
class JobsIrelandAdapter(PacedDetails, Adapter):
    board = "jobsireland"
    browse_url = "https://jobsireland.ie/en-US/browse-jobs"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._init_pacing()
        self._listings: dict[str, dict[str, str]] = {}

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        page_size = min(250, int(cfg.get("page_size", 250) or 250))
        base_params = {
            "CareerlevelId": -1, "keyWord": "", "location": "",
            "pageSize": page_size, "VacancyTypeId": -1,
            "RemoteOrBlendedJobType": -1, "NaceCode": -1,
        }
        first = get_public(self.browse_url, params={**base_params, "page": 1}, timeout=timeout)
        total = _total_jobs(first.text)
        pages = max(1, math.ceil(total / page_size))
        page_responses = {1: first}
        discovery_workers = min(4, int(cfg.get("discovery_workers", 4) or 4))
        with ThreadPoolExecutor(max_workers=max(1, discovery_workers)) as pool:
            futures = {
                pool.submit(
                    get_public, self.browse_url,
                    params={**base_params, "page": page_number}, timeout=timeout,
                ): page_number
                for page_number in range(2, pages + 1)
            }
            for future in as_completed(futures):
                page_responses[futures[future]] = future.result()

        seen: set[str] = set()
        for page_number in range(1, pages + 1):
            page = page_responses[page_number]
            rows = _hidden_rows(page.text)
            if not rows:
                break
            for row in rows:
                job_id, title = row["JobId"], row["JobTitle"]
                if job_id in seen or not relevant_title(title, terms):
                    continue
                seen.add(job_id)
                self._listings[job_id] = dict(row)
                yield JobUrl(
                    self.board, job_id,
                    f"https://jobsireland.ie/en-US/job-Details?id={job_id}",
                    row.get("StartDate") or None,
                )

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        self._pace_detail_request()
        response = get_public(
            job.url, timeout=float(cfg.get("timeout_seconds", 30) or 30)
        )
        try:
            data = _jobsireland_detail(response.text, response.url)
        except ValueError:
            report_url = (
                "https://employer.jobsireland.ie/Reports/GetJobsDetail?id=" + job.job_id
            )
            self._pace_detail_request()
            report = get_public(report_url, timeout=float(cfg.get("timeout_seconds", 30) or 30))
            text = _extract_pdf(report)
            if not text:
                raise ValueError("JobsIreland HTML and official PDF were both incomplete")
            listing = self._listings.get(job.job_id) or {
                "JobId": job.job_id, "JobTitle": "", "Location": "",
                "StartDate": "", "EndDate": "",
            }
            data = _jobsireland_pdf_text(text, listing, response.url, report.url)
        return RawPosting(
            self.board, job.job_id, response.url, contracts_now(), raw_json=data
        )


def _publicjobs_rows(page: str) -> list[dict[str, str]]:
    blocks = re.findall(
        r'<li\b[^>]*class=["\'][^"\']*opp-container[^"\']*["\'][^>]*>(.*?)</li>',
        page, re.I | re.S,
    )
    rows: list[dict[str, str]] = []
    for block in blocks:
        identity = re.search(r'data-oppid=["\'](\d+)', block, re.I)
        link = re.search(
            r'<a\b[^>]*class=["\'][^"\']*subject[^"\']*["\'][^>]*href=["\']([^"\']+)',
            block, re.I,
        )
        title = re.search(r'data-title=["\']([^"\']+)', block, re.I)
        advertised = re.search(
            r'Advertising Date:</span>\s*([^<]+)', block, re.I
        )
        if identity and link and title:
            rows.append({
                "id": identity.group(1), "url": html.unescape(link.group(1)),
                "title": html.unescape(title.group(1)),
                "posted": html.unescape(advertised.group(1)).strip() if advertised else "",
            })
    return rows


def _publicjobs_detail(page: str, source_url: str) -> dict[str, Any]:
    vacancy = re.search(r'<div id=["\']vac_desc["\']>(.*?)(?:</main>|$)', page, re.I | re.S)
    body = vacancy.group(1) if vacancy else page
    title_match = re.search(r'<h1\b[^>]*>(.*?)</h1>', body, re.I | re.S)
    title = plain_text(title_match.group(1) if title_match else "")

    fields: dict[str, str] = {}
    for label, value in re.findall(
        r'<h4\b[^>]*>(.*?)</h4>\s*<p\b[^>]*>(.*?)</p>', body, re.I | re.S
    ):
        fields[plain_text(label).casefold()] = plain_text(value)

    attachments: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in re.finditer(
        r'<a\b[^>]*class=["\'][^"\']*file_application_pdf[^"\']*["\']'
        r'[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', body, re.I | re.S,
    ):
        url = html.unescape(match.group(1))
        if url in seen:
            continue
        seen.add(url)
        attachments.append({"url": url, "label": plain_text(match.group(2))})

    content = plain_text(body)
    if not title or len(content) < 80:
        raise ValueError("publicjobs detail omitted vacancy content")
    return {
        "title": title,
        "company": fields.get("department/authority", ""),
        "location_text": fields.get("location", "") or fields.get("county", "") or "Ireland",
        "contract_type": fields.get("contract", ""),
        "grade": fields.get("grade", ""),
        "application_deadline": fields.get("closing date for application", ""),
        "content_text": content,
        "description": content,
        "attachments": attachments,
        "source_url": source_url,
        "source_attribution": "publicjobs Ireland",
        "detail_fetch_status": "full_page",
    }


def _extract_pdf(response: Any) -> str:
    try:
        from pypdf import PdfReader
    except ImportError:
        return ""
    try:
        reader = PdfReader(io.BytesIO(response.content))
        return "\n".join((page.extract_text() or "") for page in reader.pages).strip()
    except Exception:
        return ""


@register
class PublicJobsIEAdapter(PacedDetails, Adapter):
    board = "publicjobsie"
    search_url = "https://www.publicjobs.ie/en/job-search"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._init_pacing()

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        cfg = self._board_config()
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        page_size = 50
        start = 0
        board_url = self.search_url
        total = 0
        seen: set[str] = set()
        while True:
            response = get_public(
                board_url, params={"start": start} if start else None, timeout=timeout
            )
            if start == 0:
                board_url = response.url
                total_match = re.search(r'<h2\b[^>]*>\s*(\d+) results match', response.text, re.I)
                total = int(total_match.group(1)) if total_match else 0
            rows = _publicjobs_rows(response.text)
            if not rows:
                break
            for row in rows:
                if row["id"] in seen or not relevant_title(row["title"], terms):
                    continue
                seen.add(row["id"])
                yield JobUrl(self.board, row["id"], row["url"], row["posted"] or None)
            if len(rows) < page_size:
                break
            start += page_size
            if total and start >= total:
                break

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        cfg = self._board_config()
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        self._pace_detail_request()
        response = get_public(job.url, timeout=timeout)
        data = _publicjobs_detail(response.text, response.url)
        if bool(cfg.get("extract_pdf_attachments", True)):
            texts: list[dict[str, str]] = []
            for attachment in data["attachments"]:
                self._pace_detail_request()
                pdf = get_public(attachment["url"], timeout=timeout)
                text = _extract_pdf(pdf)
                if text:
                    texts.append({**attachment, "text": text})
            data["attachment_texts"] = texts
            if texts:
                data["content_text"] += "\n\n" + "\n\n".join(
                    row["text"] for row in texts
                )
                data["description"] = data["content_text"]
        return RawPosting(
            self.board, job.job_id, response.url, contracts_now(), raw_json=data
        )
