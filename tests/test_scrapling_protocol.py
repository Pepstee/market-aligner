from __future__ import annotations

import os
import unittest
from packaging.version import Version
from pathlib import Path

from market_aligner.collectors.scrapling_client import ScraplingClient
from market_aligner.collectors.scrapling_worker import _hydrate, _jsonable


class ScraplingProtocolTests(unittest.TestCase):
    def test_typed_json_protocol_is_not_reduced(self) -> None:
        value = _hydrate(
            {
                "path": {"$path": "/tmp/example"},
                "tuple": {"$tuple": [1, 2]},
                "set": {"$set": ["a", "b"]},
                "callable": {"$ref": "builtins:sorted"},
            }
        )
        self.assertEqual(Path("/tmp/example"), value["path"])
        self.assertEqual((1, 2), value["tuple"])
        self.assertEqual({"a", "b"}, value["set"])
        self.assertEqual([1, 2, 3], value["callable"]([3, 1, 2]))
        self.assertEqual("base64", _jsonable(b"full")["encoding"])

    @unittest.skipUnless(
        os.environ.get("MARKET_ALIGNER_SCRAPLING_PYTHON"),
        "set MARKET_ALIGNER_SCRAPLING_PYTHON for full sidecar certification",
    )
    def test_installed_runtime_reports_complete_capabilities(self) -> None:
        # Do not resolve a virtualenv interpreter symlink into its base Python;
        # doing so intentionally discards the virtualenv's site-packages.
        runtime = Path(os.environ["MARKET_ALIGNER_SCRAPLING_PYTHON"]).absolute()
        client = ScraplingClient(
            runtime.parent.parent,
            {"runtime_python": str(runtime), "command_timeout_seconds": 120},
        )
        capabilities = client.capabilities()
        self.assertGreaterEqual(Version(capabilities["scrapling_version"]), Version("0.4.11"))
        self.assertEqual({"http": "static"}, capabilities["engine_aliases"])
        self.assertEqual(capabilities["static_methods"], capabilities["http_methods"])
        self.assertEqual(["static", "dynamic", "stealth"], capabilities["engines"])
        self.assertEqual(
            {"fetch", "session_batch", "parse", "spider", "call", "capabilities"},
            set(capabilities["operations"]),
        )
        self.assertIn("$proxy_rotator", capabilities["typed_json"])
        self.assertIn("mcp", capabilities["upstream_cli"])
        self.assertTrue(any("AsyncStealthySession" in item for item in capabilities["exports"]))

        # Exercise the legacy engine spelling through the actual worker process,
        # against a local public-shaped fixture rather than an external site.
        import base64
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        exact = b"<html><body><main>Synthetic vacancy details</main></body></html>"
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(exact)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/vacancy"
            chain_client = ScraplingClient(runtime.parent.parent, {
                "runtime_python": str(runtime), "minimum_body_bytes": 1,
                "fallback_chain": [{"engine": "http", "kwargs": {}}],
            })
            recovered = chain_client.fetch_with_chain(url)
            self.assertEqual("static", recovered.engine)
            self.assertEqual("static", recovered.attempts[0]["engine"])
            self.assertEqual(exact, base64.b64decode(recovered.response["body_base64"], validate=True))
            static = client.fetch("static", url)
            legacy = client.fetch("http", url)
            batch = client.execute({"operation": "session_batch", "engine": "http",
                                    "requests": [{"url": url}]})
            for response in (static, legacy, batch[0]):
                self.assertEqual(200, response["status"])
                self.assertEqual(exact, base64.b64decode(response["body_base64"], validate=True))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
