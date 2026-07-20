#!/usr/bin/env python3
"""Offline parser regression for JobScout24's public listing shape."""

import re


def main() -> None:
    page = '<li data-job-detail-url="/en/job/1244b96c-a949-4643-9a6b-455a52e6c168/"></li>'
    match = re.search(
        r'data-job-detail-url="(?P<href>/en/job/(?P<id>[0-9a-f-]{36})/)"', page
    )
    assert match
    assert match.group("id") == "1244b96c-a949-4643-9a6b-455a52e6c168"
    print("test_jobscout24_scraper: PASS")


if __name__ == "__main__":
    main()
