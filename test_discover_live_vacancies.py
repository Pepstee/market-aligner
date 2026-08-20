import asyncio

from scripts.discover_live_vacancies import _crawl


class _Response:
    def __init__(self, url: str, body: bytes) -> None:
        self.url = url
        self.status = 200
        self.body = body
        self.history = ()


class _Session:
    instances = 0
    calls: list[str] = []
    configuration: dict[str, object] = {}

    def __init__(self, **configuration: object) -> None:
        type(self).instances += 1
        type(self).configuration = configuration

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def get(self, url: str) -> _Response:
        type(self).calls.append(url)
        if url == "https://careers.example.test/graduate-engineer":
            return _Response(
                url,
                (
                    b"<h1>Graduate Engineer</h1><p>Apply now</p>"
                    b"<a href='https://job-boards.greenhouse.io/acme/jobs/7654321'>"
                    b"Apply now</a>"
                ),
            )
        return _Response(
            url,
            b"<h1>Graduate Engineer</h1><p>Acme</p><p>Apply now</p>",
        )


def test_crawl_reuses_one_safe_session_and_fetches_native_destination() -> None:
    _Session.instances = 0
    _Session.calls = []
    entries = [
        {
            "url": "https://careers.example.test/graduate-engineer",
            "job_title": "Graduate Engineer",
        }
    ]
    source_results, destination_results = asyncio.run(
        _crawl(entries, 2, session_factory=_Session)
    )
    assert len(source_results) == 1
    assert len(destination_results) == 1
    assert _Session.instances == 1
    assert _Session.calls == [
        "https://careers.example.test/graduate-engineer",
        "https://job-boards.greenhouse.io/acme/jobs/7654321",
    ]
    assert _Session.configuration["follow_redirects"] == "safe"
    assert destination_results[0][0]["source_index"] == 1
