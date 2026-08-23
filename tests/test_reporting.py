from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from market_aligner.assessment.scoring import AssessmentAxes, score
from market_aligner.domain.contracts import Vacancy
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.reporting.reports import RankedVacancy, skill_frequency, write_reports


class ReportingTests(unittest.TestCase):
    def test_ranked_jobs_requirements_and_interactive_scatter(self) -> None:
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
            with paths.jobs_csv.open(encoding="utf-8") as handle:
                exported = list(csv.DictReader(handle))
            self.assertEqual("uncalibrated", exported[0]["fit_status"])
            scatter = paths.scatter_html.read_text(encoding="utf-8")
            self.assertIn("const points=", scatter)
            self.assertIn("fit is uncalibrated", scatter)


if __name__ == "__main__":
    unittest.main()
