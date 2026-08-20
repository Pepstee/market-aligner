#!/usr/bin/env python3
"""Offline parser checks for TechJobs.ie."""

from scraper.adapters.techjobsie import _parse_detail


def main() -> None:
    page = '''
    <h1 class="font-semibold text-2xl">Junior AI Engineer</h1>
    <div class="text-base text-gray-600">Small Travel Agency</div>
    <div class="flex flex-wrap items-center gap-3 text-gray-500 text-sm">
      <span>Full-time</span><span>•</span><span>AI</span><span>•</span>
      <span>Ireland · Remote worldwide</span>
    </div>
    <a href="https://employer.test/apply?a=1&amp;b=2">Apply Now</a>
    <div class="markdown-content x"><p>Build Python automation and LLM workflows for a
    travel marketing team. Applicants may work remotely worldwide. Required skills include
    Python, APIs, SQL, testing, and clear written communication.</p></div></div><div class="mt-8">
    <span>Apply before:<!-- --> <!-- -->August 16, 2026</span>
    '''
    parsed = _parse_detail(page, "https://techjobs.ie/jobs/ai/example")
    assert parsed["title"] == "Junior AI Engineer"
    assert parsed["company"] == "Small Travel Agency"
    assert parsed["location_text"] == "Ireland · Remote worldwide"
    assert "Python automation" in parsed["content_text"]
    assert parsed["original_apply_url"] == "https://employer.test/apply?a=1&b=2"
    assert parsed["application_deadline"] == "August 16, 2026"
    print("test_techjobsie_scraper: PASS")


if __name__ == "__main__":
    main()
