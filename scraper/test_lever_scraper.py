"""Hermetic contract test for the UK Lever adapter."""

from scraper.adapters import lever
from scraper.adapters.lever import LeverAdapter


def main() -> int:
    original = lever.http_get_json

    def fake_get(url, **kwargs):
        if url.endswith("/example"):
            return [{
                "id": "abc",
                "text": "Graduate AI Automation Engineer",
                "country": "GB",
                "categories": {"location": "London, United Kingdom", "team": "Engineering"},
                "descriptionPlain": "Python agentic AI workflow automation",
                "hostedUrl": "https://jobs.lever.co/example/abc",
                "createdAt": 123,
            }]
        return {
            "id": "abc", "text": "Graduate AI Automation Engineer",
            "categories": {"location": "London, United Kingdom"},
            "descriptionPlain": "Python and AWS agentic workflow automation",
        }

    lever.http_get_json = fake_get
    try:
        adapter = LeverAdapter(config={"companies": {"example": "Example AI"}})
        found = list(adapter.discover(["agentic ai", "automation"], live=True))
        assert len(found) == 1
        assert found[0].key == "lever:example:abc"
        raw = adapter.fetch(found[0], live=True)
        assert raw.raw_json["company"] == "Example AI"
        assert "Python and AWS" in raw.raw_json["content_text"]
    finally:
        lever.http_get_json = original
    print("UK Lever adapter PASSED — UK filter, C1 id, C2 detail")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
