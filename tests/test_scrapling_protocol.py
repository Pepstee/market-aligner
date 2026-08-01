from __future__ import annotations

import os
import unittest
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
        self.assertEqual("0.4.11", capabilities["scrapling_version"])
        self.assertEqual(["static", "dynamic", "stealth"], capabilities["engines"])
        self.assertEqual(
            {"fetch", "session_batch", "parse", "spider", "call", "capabilities"},
            set(capabilities["operations"]),
        )
        self.assertIn("$proxy_rotator", capabilities["typed_json"])
        self.assertIn("mcp", capabilities["upstream_cli"])
        self.assertTrue(any("AsyncStealthySession" in item for item in capabilities["exports"]))


if __name__ == "__main__":
    unittest.main()
