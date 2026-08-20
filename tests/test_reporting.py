from __future__ import annotations

import csv
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from matplotlib import image as matplotlib_image

from market_aligner.assessment.scoring import AssessmentAxes, score
from market_aligner.domain.contracts import Vacancy
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.reporting.reports import RankedVacancy, skill_frequency, write_reports


class ReportingTests(unittest.TestCase):
    def test_ranked_jobs_requirements_and_scatter_outputs(self) -> None:
        profile = CandidateProfile(
            new_profile_id(),
            "v1",
            {"track": TrackProfile(8, 7, 0.8, 6, rationale="fixture")},
        )
        rows = []
        for index, skills in enumerate((("Python", "SQL"), ("Python", "AWS")), 1):
            vacancy = Vacancy(
                "board",
                str(index),
                f"https://example.test/{index}",
                title=f"Role {index}",
                company="Example",
                description="Complete role.",
                required_skills=skills,
                preferred_skills=("Docker",),
            )
            result = score(profile, vacancy.key, "track", AssessmentAxes(8, 7, 8, 2, 8))
            rows.append(RankedVacancy(vacancy, result))
        frequencies = skill_frequency(rows)
        self.assertEqual("Python", frequencies[0]["skill"])
        self.assertEqual(2, frequencies[0]["required_frequency"])
        with tempfile.TemporaryDirectory() as temporary:
            paths = write_reports(profile.profile_id, rows, Path(temporary))
            self.assertTrue(paths.jobs_csv.is_file())
            self.assertTrue(paths.requirements_csv.is_file())
            self.assertTrue(paths.scatter_html.is_file())
            self.assertTrue(paths.scatter_png.is_file())
            with paths.jobs_csv.open(encoding="utf-8") as handle:
                exported = list(csv.DictReader(handle))
            self.assertEqual("uncalibrated", exported[0]["fit_status"])
            scatter = paths.scatter_html.read_text(encoding="utf-8")
            self.assertIn("const points=", scatter)
            self.assertIn("fit is uncalibrated", scatter)
            png = paths.scatter_png.read_bytes()
            width, height, metadata = _inspect_png(png)
            self.assertEqual((1800, 1200), (width, height))
            self.assertEqual("Fit vs Opportunity", metadata["Title"])
            pixels = matplotlib_image.imread(paths.scatter_png)
            self.assertEqual((1200, 1800), pixels.shape[:2])
            self.assertGreater(float(pixels[:, :, :3].std()), 0.05)
            original_png = png
            reversed_paths = write_reports(profile.profile_id, list(reversed(rows)), Path(temporary))
            self.assertEqual(original_png, reversed_paths.scatter_png.read_bytes())
            preference_rows = [
                RankedVacancy(rows[0].vacancy, rows[0].score, "eu_remote", 4),
                RankedVacancy(rows[1].vacancy, rows[1].score, "uk_remote", 0),
            ]
            preferred_paths = write_reports(profile.profile_id, preference_rows, Path(temporary))
            preferred = json.loads(preferred_paths.ranked_json.read_text(encoding="utf-8"))
            self.assertEqual(["board:2", "board:1"], [job["job_key"] for job in preferred["jobs"]])
            self.assertEqual("uk_remote", preferred["jobs"][0]["preference_classification"])


def _inspect_png(payload: bytes) -> tuple[int, int, dict[str, str]]:
    """Validate the PNG container while the declared renderer validates raster decoding."""
    if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
        raise AssertionError("missing PNG signature")
    offset = 8
    width = height = 0
    saw_iend = False
    saw_idat = False
    metadata: dict[str, str] = {}
    while offset < len(payload):
        length = struct.unpack(">I", payload[offset : offset + 4])[0]
        kind = payload[offset + 4 : offset + 8]
        body = payload[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", payload[offset + 8 + length : offset + 12 + length])[0]
        if zlib.crc32(kind + body) & 0xFFFFFFFF != expected_crc:
            raise AssertionError(f"invalid {kind!r} CRC")
        if kind == b"IHDR":
            width, height, depth, color_type, _, _, _ = struct.unpack(">IIBBBBB", body)
            if depth != 8 or color_type not in (2, 6):
                raise AssertionError("expected 8-bit RGB/RGBA PNG")
        elif kind == b"IDAT":
            saw_idat = True
        elif kind == b"tEXt":
            key, value = body.split(b"\0", 1)
            metadata[key.decode("latin-1")] = value.decode("latin-1")
        elif kind == b"IEND":
            saw_iend = True
        offset += 12 + length
    if not saw_iend or not saw_idat:
        raise AssertionError("missing PNG image chunks")
    return width, height, metadata


if __name__ == "__main__":
    unittest.main()
