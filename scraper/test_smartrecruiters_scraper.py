"""Hermetic contract test for the SmartRecruiters adapter."""

from scraper.adapters import smartrecruiters
from scraper.adapters.smartrecruiters import SmartRecruitersAdapter


def main() -> int:
    original = smartrecruiters.http_get_json

    def fake_get(url, **kwargs):
        if url.endswith("/postings"):
            return {"totalFound": 1, "content": [{
                "id": "123", "name": "Graduate Cloud Engineer",
                "releasedDate": "2026-07-18T00:00:00Z",
                "location": {"country": "gb", "fullLocation": "London, United Kingdom"},
                "department": {"label": "Cloud Engineering"},
            }]}
        return {
            "id": "123", "name": "Graduate Cloud Engineer",
            "company": {"name": "Example"},
            "location": {"country": "gb", "fullLocation": "London, United Kingdom"},
            "postingUrl": "https://jobs.smartrecruiters.com/Example/123",
            "jobAd": {"sections": {"jobDescription": {"text": "<p>Python AWS automation</p>"}}},
        }

    smartrecruiters.http_get_json = fake_get
    try:
        adapter = SmartRecruitersAdapter(config={"companies": {"Example": "Example"}})
        found = list(adapter.discover(["cloud engineer"], live=True))
        assert len(found) == 1 and found[0].key == "smartrecruiters:Example:123"
        raw = adapter.fetch(found[0], live=True)
        assert raw.raw_json["content_text"] == "Python AWS automation"
    finally:
        smartrecruiters.http_get_json = original
    print("UK SmartRecruiters adapter PASSED — UK filter, C1 id, C2 detail")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
