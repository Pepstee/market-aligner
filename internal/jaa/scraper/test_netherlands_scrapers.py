#!/usr/bin/env python3
"""Offline parser checks for Netherlands adapters."""

import html
import json

from scraper.adapters.iamexpatnl import _nested_jobposting
from scraper.adapters.uprotterdam import _current_job


def main() -> None:
    posting = {
        "@context": "https://schema.org", "@type": "JobPosting",
        "title": "Junior AI Engineer", "description": "<p>Full requirements here.</p>",
    }
    encoded = json.dumps(json.dumps(posting), ensure_ascii=False)[1:-1]
    parsed = _nested_jobposting(f'<script>self.x={{"children":"{encoded}"}}</script>')
    assert parsed["title"] == "Junior AI Engineer"

    job = {
        "id": 123, "title": "Python Engineer", "description": "<p>Build APIs.</p>",
        "organization": {"name": "Small Dutch Firm"}, "locations": [{"name": "Remote"}],
    }
    payload = {"props": {"pageProps": {"initialState": {"jobs": {"currentJob": job}}}}}
    page = '<script id="__NEXT_DATA__" type="application/json">' + html.escape(
        json.dumps(payload)
    ) + "</script>"
    assert _current_job(page)["organization"]["name"] == "Small Dutch Firm"
    print("test_netherlands_scrapers: PASS")


if __name__ == "__main__":
    main()
