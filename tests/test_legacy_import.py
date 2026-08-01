from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from market_aligner.config_loader import load_config
from market_aligner.state.importers import iter_raw_cache_roots


class LegacyImportTests(unittest.TestCase):
    def test_recursive_config_extension_and_cycle_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "base.yaml").write_text(
                yaml.safe_dump({"collection": {"workers": 4, "delay": 2}, "market": "one"}),
                encoding="utf-8",
            )
            (root / "child.yaml").write_text(
                yaml.safe_dump({"extends": "base.yaml", "collection": {"workers": 8}}),
                encoding="utf-8",
            )
            self.assertEqual(
                {"collection": {"workers": 8, "delay": 2}, "market": "one"},
                load_config(root / "child.yaml"),
            )
            (root / "a.yaml").write_text("extends: b.yaml\n", encoding="utf-8")
            (root / "b.yaml").write_text("extends: a.yaml\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "extends cycle"):
                load_config(root / "a.yaml")

    def test_multi_root_json_jsonl_and_key_deduplication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "one" / "board"
            second = root / "two" / "board"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            row = {
                "board": "board",
                "job_id": "1",
                "url": "https://example.test/1",
                "fetched_at": "2026-08-01T00:00:00Z",
                "raw_text": "complete",
            }
            (first / "one.json").write_text(json.dumps(row), encoding="utf-8")
            (second / "duplicate.json").write_text(json.dumps([row]), encoding="utf-8")
            (second / "two.json").write_text(
                json.dumps({**row, "job_id": "2", "url": "https://example.test/2"}) + "\n",
                encoding="utf-8",
            )
            rows = list(iter_raw_cache_roots([root / "one", root / "two"]))
            self.assertEqual(["board:1", "board:2"], [item.key for item in rows])


if __name__ == "__main__":
    unittest.main()
