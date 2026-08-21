from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from market_aligner.assessment.opportunity import apply_gate
from market_aligner.assessment.scoring import AssessmentAxes, score
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.research.store import AssessmentStore
from market_aligner.research.worker import ResearchWorker


class WrongTaskProvider:
    def research(self, task):
        from market_aligner.research.models import ResearchDossier

        return ResearchDossier(task.profile_id, "different:job", task.company, task.title, (), ())


class ResearchWorkerTests(unittest.TestCase):
    def test_invalid_provider_output_is_requeued_without_a_dossier(self) -> None:
        profile = CandidateProfile(
            new_profile_id(),
            "v1",
            {"track": TrackProfile(8, 7, 0.8, 6, rationale="fixture")},
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = AssessmentStore(Path(temporary) / "state.sqlite3")
            result = score(profile, "board:1", "track", AssessmentAxes(8, 8, 9, 1, 9))
            store.upsert_score(
                result,
                url="https://example.test/1",
                title="Engineer",
                company="Example",
                extraction_confidence=0.95,
            )
            apply_gate(store, profile.profile_id, "board:1")
            run = ResearchWorker(store, WrongTaskProvider(), "worker").run_one()
            self.assertEqual("retry_scheduled", run.status)
            with store.connection() as connection:
                queue = connection.execute(
                    "SELECT status,last_error FROM employer_research_queue"
                ).fetchone()
                dossiers = connection.execute("SELECT COUNT(*) FROM employer_dossiers").fetchone()[0]
            self.assertEqual("queued", queue["status"])
            self.assertIn("different task", queue["last_error"])
            self.assertEqual(0, dossiers)

    def test_iso_retry_time_becomes_claimable_without_rewriting_queue_state(
        self,
    ) -> None:
        profile = CandidateProfile(
            new_profile_id(),
            "v1",
            {"track": TrackProfile(8, 7, 0.8, 6, rationale="fixture")},
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = AssessmentStore(Path(temporary) / "state.sqlite3")
            result = score(
                profile, "board:1", "track", AssessmentAxes(8, 8, 9, 1, 9)
            )
            store.upsert_score(
                result,
                url="https://example.test/1",
                title="Engineer",
                company="Example",
                extraction_confidence=0.95,
            )
            apply_gate(store, profile.profile_id, "board:1")
            with store.connection() as connection:
                connection.execute(
                    "UPDATE employer_research_queue SET available_at=?",
                    ("2000-01-01T00:00:00+00:00",),
                )
            task = store.claim_research("retry-worker")
            self.assertIsNotNone(task)
            self.assertEqual("board:1", task.job_key)


if __name__ == "__main__":
    unittest.main()
