from __future__ import annotations

import pathlib
import os
import subprocess
import tempfile
import unittest
import zipfile


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

    @unittest.skipUnless(
        os.environ.get("MARKET_ALIGNER_BUILD_PYTHON"),
        "set MARKET_ALIGNER_BUILD_PYTHON to a Python with the build backend installed",
    )
    def test_built_wheel_contains_no_private_or_generated_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            subprocess.run(
                [
                    os.environ["MARKET_ALIGNER_BUILD_PYTHON"],
                    "-m",
                    "pip",
                    "wheel",
                    str(ROOT),
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    temporary,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            wheels = list(pathlib.Path(temporary).glob("*.whl"))
            self.assertEqual(1, len(wheels))
            with zipfile.ZipFile(wheels[0]) as archive:
                names = archive.namelist()
                forbidden_suffixes = (".yaml", ".yml", ".jsonl", ".sqlite", ".db", ".pdf")
                self.assertEqual([], [name for name in names if name.lower().endswith(forbidden_suffixes)])
                self.assertFalse(any("profiles/" in name.lower() for name in names))


if __name__ == "__main__":
    unittest.main()
