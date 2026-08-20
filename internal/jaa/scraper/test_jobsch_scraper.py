#!/usr/bin/env python3
"""Offline parser regressions for the jobs.ch adapter."""

from scraper.adapters.jobsch import _assigned_json, _job_posting_json_ld, _location


def main() -> None:
    state = _assigned_json('<script>__INIT__ = {"vacancy":{"ok":true}};</script>', "__INIT__")
    assert state["vacancy"]["ok"] is True
    page = '''<script type="application/ld+json">{
      "@context":"https://schema.org", "@type":"JobPosting", "title":"AI Engineer",
      "description":"<p>Python and automation</p>",
      "jobLocation":{"@type":"Place","address":{"addressLocality":"Zürich","addressCountry":"CH"}}
    }</script>'''
    posting = _job_posting_json_ld(page)
    assert posting["title"] == "AI Engineer"
    assert _location(posting["jobLocation"]) == "Zürich, CH"
    print("test_jobsch_scraper: PASS")


if __name__ == "__main__":
    main()
