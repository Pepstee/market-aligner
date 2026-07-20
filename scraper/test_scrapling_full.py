from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, AsyncGenerator

from scraper.scrapling_client import ScraplingClient


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".venv-scrapling/bin/python"
if str(ROOT / "skeleton") not in sys.path:
    sys.path.insert(0, str(ROOT / "skeleton"))

from contracts import JobUrl  # noqa: E402
from scraper.collector import Collector  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api":
            body = json.dumps({"requirements": ["Python", "LLMs"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            body = b"""<!doctype html><html><body><h1>AI Engineer</h1>
            <div id='requirements'>Python</div><script>
            fetch('/api').then(r => r.json()).then(v => {
              const node = document.createElement('div');
              node.id = 'loaded'; node.textContent = v.requirements.join(',');
              document.body.appendChild(node);
            });</script></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


try:
    from scrapling.spiders import Spider
except ImportError:  # Imported by the Python 3.14 test runner.
    Spider = object  # type: ignore[assignment,misc]


class OnePageSpider(Spider):  # type: ignore[misc,valid-type]
    name = "full-sidecar-smoke"

    def __init__(self, url: str) -> None:
        self.start_urls = [url]
        super().__init__()

    async def parse(self, response: Any) -> AsyncGenerator[dict[str, Any], None]:
        yield {"title": response.css("h1::text").get()}


def install_page_marker(page: Any) -> None:
    page.add_init_script("window.__scraplingSetup = 'setup-hook';")


def append_page_marker(page: Any) -> None:
    page.evaluate("""() => {
      const node = document.createElement('div');
      node.id = 'hook-marker'; node.textContent = window.__scraplingSetup;
      document.body.appendChild(node);
    }""")


class _FailingAdapter:
    def fetch(self, _row: JobUrl, _live: bool) -> None:
        raise RuntimeError("primary adapter deliberately failed")


@unittest.skipUnless(RUNTIME.is_file(), "full Scrapling sidecar is not installed")
class FullScraplingIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/"
        cls.client = ScraplingClient(ROOT, {"command_timeout_seconds": 120})

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_complete_capability_manifest(self) -> None:
        manifest = self.client.capabilities()
        self.assertEqual(manifest["scrapling_version"], "0.4.11")
        self.assertEqual(manifest["engines"], ["static", "dynamic", "stealth"])
        self.assertIn("spider", manifest["operations"])
        self.assertIn("call", manifest["operations"])
        self.assertIn("mcp", manifest["upstream_cli"])
        self.assertTrue(any("AsyncStealthySession" in item for item in manifest["exports"]))

    def test_static_fetch_session_parser_and_extension_call(self) -> None:
        fetched = self.client.fetch("static", self.url, timeout=10, retries=1)
        self.assertEqual(fetched["status"], 200)
        self.assertIn("AI Engineer", fetched["text"])
        self.assertTrue(fetched["body_base64"])
        self.assertIn("headers", fetched)

        session_rows = self.client.execute({
            "operation": "session_batch",
            "engine": "static",
            "session_kwargs": {"timeout": 10, "retries": 1},
            "requests": [{"url": self.url}, {"url": self.url + "api"}],
        })
        self.assertEqual([row["status"] for row in session_rows], [200, 200])

        parsed = self.client.execute({
            "operation": "parse",
            "content": fetched["text"],
            "url": self.url,
            "operations": [{
                "name": "title",
                "method": "css",
                "args": ["h1::text"],
            }],
        })
        self.assertEqual(parsed["outputs"]["title"][0]["text"], "AI Engineer")

        called = self.client.execute({
            "operation": "call",
            "callable_ref": "builtins:sorted",
            "args": [[3, 1, 2]],
        })
        self.assertEqual(called, [1, 2, 3])

    def test_dynamic_and_stealth_engines_with_xhr_and_hooks_surface(self) -> None:
        dynamic = self.client.fetch(
            "dynamic",
            self.url,
            headless=True,
            timeout=30000,
            wait_selector="#loaded",
            capture_xhr="api",
            page_setup={"$ref": "scraper.test_scrapling_full:install_page_marker"},
            page_action={"$ref": "scraper.test_scrapling_full:append_page_marker"},
        )
        self.assertEqual(dynamic["status"], 200)
        self.assertIn("Python,LLMs", dynamic["text"])
        self.assertIn("setup-hook", dynamic["text"])
        self.assertEqual(len(dynamic["captured_xhr"]), 1)
        self.assertIn("requirements", dynamic["captured_xhr"][0]["text"])

        stealth = self.client.fetch(
            "stealth",
            self.url,
            headless=True,
            timeout=30000,
            wait_selector="#loaded",
            solve_cloudflare=True,
            hide_canvas=True,
            block_webrtc=True,
            allow_webgl=True,
        )
        self.assertEqual(stealth["status"], 200)
        self.assertIn("Python,LLMs", stealth["text"])

    def test_custom_spider_class_runs_in_the_native_framework(self) -> None:
        result = self.client.execute({
            "operation": "spider",
            "class_ref": "scraper.test_scrapling_full:OnePageSpider",
            "init_args": [self.url],
        })
        self.assertFalse(result["paused"])
        self.assertEqual(result["items"], [{"title": "AI Engineer"}])
        self.assertEqual(result["stats"]["items_scraped"], 1)

    def test_collector_recovers_adapter_failure_and_preserves_full_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = {
                "io": {
                    "job_urls": str(Path(temporary) / "urls.jsonl"),
                    "raw_cache": str(Path(temporary) / "raw"),
                    "database": str(Path(temporary) / "jobs.sqlite3"),
                },
                "scrapling": {
                    "enabled": True,
                    "runtime_python": str(RUNTIME),
                    "command_timeout_seconds": 60,
                    "fallback_chain": [{
                        "engine": "static",
                        "method": "get",
                        "kwargs": {"timeout": 10, "retries": 1},
                    }],
                },
            }
            collector = Collector(config, ROOT, log=lambda _message: None)
            row = JobUrl("test", "job-1", self.url)
            raw, engine = collector._fetch_row(_FailingAdapter(), row)
            self.assertEqual(engine, "static")
            self.assertIn("AI Engineer", raw.raw_text or "")
            self.assertEqual(raw.raw_json["_collector"]["fallback"], "scrapling-full")
            response = raw.raw_json["_scrapling"]["attempts"][0]["response"]
            self.assertTrue(response["body_base64"])
            self.assertIn("request_headers", response)
            self.assertIn("cookies", response)


if __name__ == "__main__":
    unittest.main()
