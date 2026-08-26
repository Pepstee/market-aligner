from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from market_aligner.assessment.scoring import AssessmentAxes, FitStatus
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.profiler.store import ProfileStore
from market_aligner.service.api import AssessmentRequest, MarketAlignerService


class ServiceTests(unittest.TestCase):
    def test_fresh_assessment_database_is_owner_private_under_common_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "assessments.sqlite3"
            previous = os.umask(0o022)
            try:
                MarketAlignerService(temporary)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_same_service_code_runs_multiple_profiles_and_new_user(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ProfileStore(temporary)
            profiles = []
            for index in range(3):
                candidate = CandidateProfile(
                    profile_id=new_profile_id(),
                    version=f"v{index}",
                    tracks={
                        "track": TrackProfile(
                            interest=9 - index,
                            demonstrated_skill=7 - index,
                            confidence=0.8,
                            market_readiness=6,
                            rationale="Evidence-free execution fixture.",
                        )
                    },
                )
                store.save(candidate, [])
                profiles.append(candidate)

            service = MarketAlignerService(temporary)
            results = []
            for candidate in profiles:
                results.append(
                    service.assess(
                        AssessmentRequest(
                            profile_id=candidate.profile_id,
                            job_key="board:1",
                            track="track",
                            url="https://jobs.example.test/1",
                            title="Engineer",
                            company="Example",
                            extraction_confidence=0.9,
                            axes=AssessmentAxes(8, 7, 8, 2, 8),
                        )
                    )
                )
            self.assertEqual({item.profile_id for item in profiles}, {item.profile_id for item in results})
            self.assertTrue(all(item.fit_status is FitStatus.UNCALIBRATED for item in results))
            self.assertEqual(3, sum(len(service.assessments.ranked(item.profile_id)) for item in profiles))


if __name__ == "__main__":
    unittest.main()
