from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProductPrivacyTests(unittest.TestCase):
    def test_no_person_identity_in_package_or_metadata(self) -> None:
        forbidden = (("ar", "tiom"), ("hy", "un"))
        needles = tuple("".join(parts).lower() for parts in forbidden)
        targets = [ROOT / "pyproject.toml", *sorted((ROOT / "src").rglob("*"))]
        violations: list[str] = []
        for path in targets:
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if any(needle in text for needle in needles):
                violations.append(str(path.relative_to(ROOT)))
        self.assertEqual([], violations)

    def test_package_has_no_private_data_or_generated_outputs(self) -> None:
        forbidden_suffixes = {".yaml", ".yml", ".jsonl", ".sqlite", ".db", ".pdf"}
        leaked = [
            str(path.relative_to(ROOT))
            for path in (ROOT / "src").rglob("*")
            if path.is_file() and path.suffix.lower() in forbidden_suffixes
        ]
        self.assertEqual([], leaked)


if __name__ == "__main__":
    unittest.main()
