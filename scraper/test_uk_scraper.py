"""Hermetic contract test for the UK Greenhouse adapter."""

from __future__ import annotations

from scraper.adapters import greenhouse
from scraper.adapters.greenhouse import GreenhouseAdapter


LISTING = {
    "jobs": [
        {
            "id": 101,
            "title": "Graduate AI Automation Engineer",
            "location": {"name": "Bristol, UK"},
            "content": "Python agentic AI workflow automation",
            "updated_at": "2026-07-18T08:00:00Z",
            "absolute_url": "https://job-boards.greenhouse.io/example/jobs/101",
            "departments": [{"name": "Engineering"}],
        },
        {
            "id": 102,
            "title": "Senior AI Engineer",
            "location": {"name": "San Francisco, CA"},
            "content": "Python LLM systems",
            "updated_at": "2026-07-18T07:00:00Z",
            "absolute_url": "https://job-boards.greenhouse.io/example/jobs/102",
            "departments": [{"name": "Engineering"}],
        },
    ]
}


def main() -> int:
    original = greenhouse.http_get_json

    def fake_get(url, **kwargs):
        if url.endswith("/jobs"):
            return LISTING
        return {
            "id": 101,
            "title": "Graduate AI Automation Engineer",
            "location": {"name": "Bristol, UK"},
            "content": "<p>Python and AWS agentic workflow automation.</p>",
            "updated_at": "2026-07-18T08:00:00Z",
        }

    greenhouse.http_get_json = fake_get
    try:
        adapter = GreenhouseAdapter(config={
            "companies": {"example": "Example AI"},
            "uk_location_markers": [" uk", "united kingdom"],
        })
        found = list(adapter.discover(["agentic ai", "automation"], live=True))
        assert len(found) == 1, found
        assert found[0].key == "greenhouse:example:101"
        raw = adapter.fetch(found[0], live=True)
        assert raw.raw_json["company"] == "Example AI"
        assert raw.raw_json["location_text"] == "Bristol, UK"
        assert "Python and AWS" in raw.raw_json["content_text"]
    finally:
        greenhouse.http_get_json = original
    print("UK Greenhouse adapter PASSED — UK filter, C1 id, C2 detail")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
