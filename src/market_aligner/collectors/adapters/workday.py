"""Configured-employer Workday public career-site adapter.

Workday does not expose a supported global job-search API.  Each employer's
public career site does expose its own CXS listing and detail transport, so this
adapter covers explicitly configured employers without pretending that one
tenant enumerates the entire Workday estate.
"""

from __future__ import annotations

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterable

from .base import Adapter, USER_AGENT, contracts_now, register
from .uk_common import matches_terms, plain_text, uk_or_eligible_remote
from market_aligner.domain.contracts import JobUrl, RawPosting


@register
class WorkdayAdapter(Adapter):
    board = "workday"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._jobs: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _base(tenant: str, cluster: str, site: str) -> tuple[str, str]:
        host = f"{tenant}.{cluster}.myworkdayjobs.com"
        return host, f"https://{host}/wday/cxs/{tenant}/{site}"

    def _discover_live(self, terms: list[str]) -> Iterable[JobUrl]:
        import requests

        cfg = self._board_config()
        timeout = float(cfg.get("timeout_seconds", 30) or 30)
        page_size = min(20, int(cfg.get("page_size", 20) or 20))
        employers = dict(cfg.get("employers") or {})
        employer_workers = int(cfg.get("employer_workers", 6) or 6)
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        def scan(label: str, spec: dict[str, Any]) -> tuple[str, int, list[tuple[JobUrl, dict[str, Any]]]]:
            tenant = str(spec.get("tenant") or "").strip()
            cluster = str(spec.get("cluster") or "").strip()
            site = str(spec.get("site") or "").strip()
            if not all((tenant, cluster, site)):
                raise ValueError("tenant/cluster/site incomplete")
            host, base = self._base(tenant, cluster, site)
            # Enumerate the tenant once and filter locally. Repeating the same
            # tenant crawl per keyword multiplies traffic and delays every
            # other source; an empty search returns the employer's public set.
            def request_page(offset: int, applied: dict[str, list[str]]) -> dict[str, Any]:
                response = requests.post(
                    f"{base}/jobs",
                    json={
                        "appliedFacets": applied,
                        "limit": page_size,
                        "offset": offset,
                        "searchText": "",
                    },
                    headers=headers,
                    timeout=timeout,
                )
                response.raise_for_status()
                return response.json()

            # Workday exposes public location facet ids. Applying every UK
            # location advertised by the tenant avoids downloading thousands
            # of US/Asia listings while remaining uncapped within the UK set.
            probe = request_page(0, {})
            uk_location_ids: list[str] = []
            def is_uk_location(value: str) -> bool:
                text = value.casefold().strip()
                if any(marker in text for marker in (
                    "united kingdom", "great britain", "northern ireland",
                    "england", "scotland", "wales", ", uk", ", eng",
                )):
                    return True
                return bool(re.fullmatch(
                    r"(london|bristol|manchester|birmingham|edinburgh|glasgow|"
                    r"leeds|liverpool|newcastle|nottingham|reading|oxford|"
                    r"cardiff|belfast|cambridge)", text,
                ))
            def collect_locations(value: Any, inside_locations: bool = False) -> None:
                if isinstance(value, dict):
                    here = inside_locations or value.get("facetParameter") == "locations"
                    descriptor = str(value.get("descriptor") or "")
                    identifier = str(value.get("id") or "")
                    if here and identifier and is_uk_location(descriptor):
                        uk_location_ids.append(identifier)
                    for child in value.values():
                        collect_locations(child, here)
                elif isinstance(value, list):
                    for child in value:
                        collect_locations(child, inside_locations)
            collect_locations(probe.get("facets") or [])
            applied = {"locations": sorted(set(uk_location_ids))} if uk_location_ids else {}
            offset = 0
            scanned = 0
            local_seen: set[str] = set()
            rows: list[tuple[JobUrl, dict[str, Any]]] = []
            while True:
                payload = probe if offset == 0 and not applied else request_page(offset, applied)
                postings = list(payload.get("jobPostings") or [])
                scanned += len(postings)
                for posting in postings:
                    title = str(posting.get("title") or "")
                    location = str(posting.get("locationsText") or "")
                    if not matches_terms([title], terms):
                        continue
                    # Keep multi-location rows because the compact listing
                    # hides the actual countries; viability checks the full
                    # detail after fetch.
                    multi = "location" in location.casefold() and any(
                        char.isdigit() for char in location
                    )
                    if not (multi or uk_or_eligible_remote(
                        location, remote="remote" in title.casefold()
                    )):
                        continue
                    external = str(posting.get("externalPath") or "")
                    if not external:
                        continue
                    requisition = str((posting.get("bulletFields") or [""])[0])
                    native = requisition or hashlib.sha1(external.encode()).hexdigest()
                    job_id = f"{tenant}:{native}"
                    if job_id in local_seen:
                        continue
                    local_seen.add(job_id)
                    url = f"https://{host}/en-US/{site}{external}"
                    metadata = {
                        "company": label,
                        "tenant": tenant,
                        "site": site,
                        "base": base,
                        "external_path": external,
                        "listing": posting,
                    }
                    rows.append((JobUrl(self.board, job_id, url), metadata))
                offset += len(postings)
                total = int(payload.get("total") or 0)
                if not postings or offset >= total:
                    break
            return label, scanned, rows

        with ThreadPoolExecutor(max_workers=max(1, employer_workers)) as pool:
            futures = {
                pool.submit(scan, label, dict(spec or {})): label
                for label, spec in employers.items()
            }
            for future in as_completed(futures):
                label = futures[future]
                try:
                    _, scanned, rows = future.result()
                except Exception as exc:
                    print(f"[workday] {label} listing failed: {exc}")
                    continue
                print(f"[workday] {label}: scanned {scanned}, matched {len(rows)}")
                for job, metadata in rows:
                    self._jobs[job.job_id] = metadata
                    yield job

    def _fetch_live(self, job: JobUrl) -> RawPosting:
        import requests

        cfg = self._board_config()
        cached = dict(self._jobs[job.job_id])
        response = requests.get(
            f"{cached['base']}{cached['external_path']}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=float(cfg.get("timeout_seconds", 30) or 30),
        )
        response.raise_for_status()
        detail = response.json()
        info = dict(detail.get("jobPostingInfo") or {})
        cached.update(
            detail=detail,
            title=info.get("title") or cached["listing"].get("title"),
            location_text=info.get("location") or cached["listing"].get("locationsText"),
            content_text=plain_text(info.get("jobDescription") or detail),
            source_attribution="Workday public employer career site",
        )
        return RawPosting(
            board=self.board,
            job_id=job.job_id,
            url=job.url,
            fetched_at=contracts_now(),
            raw_json=cached,
        )
