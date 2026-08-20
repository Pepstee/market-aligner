from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from career_automation.database import CareerDatabase
from career_automation.engine import OpportunityGate, OpportunityPolicy, scored_job_from_payload
from career_automation.lifecycle import canonical_hash
from career_automation.models import PipelineState


def _job(job_id: str, opportunity: float, confidence: float = 0.95) -> dict:
    return {
        "board": "testboard",
        "job_id": job_id,
        "url": f"https://example.test/jobs/{job_id}",
        "job_title": f"Job {job_id}",
        "company": "Example",
        "fit": 0.8,
        "opportunity": opportunity,
        "final": 75.0,
        "extraction_confidence": confidence,
    }


class OpportunityGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = CareerDatabase(Path(self.temporary.name) / "career.sqlite3")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_opportunity_gate_is_the_only_path_to_employer_research(self) -> None:
        gate = OpportunityGate(
            self.database,
            OpportunityPolicy(
                minimum_opportunity=0.55,
                minimum_extraction_confidence=0.70,
                high_priority_opportunity=0.75,
            ),
        )
        summary = gate.bootstrap(
            [
                scored_job_from_payload(_job("strong", 0.82)),
                scored_job_from_payload(_job("weak", 0.40)),
            ]
        )
        self.assertEqual(summary.imported, 2)
        self.assertEqual(summary.passed, 1)
        self.assertEqual(summary.rejected, 1)
        self.assertEqual(
            [task.job_key for task in self.database.list_research_queue()],
            ["testboard:strong"],
        )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "passed opportunity gate"):
            self.database.enqueue_research("testboard:weak", priority=999)

    def test_gate_is_idempotent_for_the_same_score_and_policy(self) -> None:
        gate = OpportunityGate(self.database)
        row = scored_job_from_payload(_job("same", 0.80))
        gate.bootstrap([row])
        gate.bootstrap([row])
        with self.database.connection() as conn:
            event_count = conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
            queue_count = conn.execute("SELECT COUNT(*) FROM employer_research_queue").fetchone()[0]
        self.assertEqual(event_count, 2)  # one import and one gate event
        self.assertEqual(queue_count, 1)

    def test_low_confidence_score_does_not_consume_research(self) -> None:
        gate = OpportunityGate(self.database)
        summary = gate.bootstrap(
            [scored_job_from_payload(_job("uncertain", 0.90, confidence=0.4))]
        )
        self.assertEqual(summary.rejected, 1)
        self.assertEqual(summary.queued, 0)

    def test_research_lease_and_cited_dossier_completion(self) -> None:
        OpportunityGate(self.database).bootstrap(
            [scored_job_from_payload(_job("research", 0.90))]
        )
        task = self.database.claim_research("worker-1", lease_seconds=60)
        self.assertIsNotNone(task)
        assert task is not None
        self.assertEqual(task.job_key, "testboard:research")

        bad_dossier = {
            "job_key": task.job_key,
            "sources": [{"id": "s1", "url": "https://example.test"}],
            "claims": [{"text": "Claim", "source_ids": ["missing"]}],
        }
        with self.assertRaisesRegex(ValueError, "known source IDs"):
            self.database.complete_research(
                job_key=task.job_key,
                worker_id="worker-1",
                dossier=bad_dossier,
                dossier_hash=canonical_hash(bad_dossier),
            )

        dossier = {
            "job_key": task.job_key,
            "sources": [{"id": "s1", "url": "https://example.test"}],
            "claims": [{"text": "Claim", "source_ids": ["s1"], "confidence": 0.9}],
        }
        digest = canonical_hash(dossier)
        self.database.complete_research(
            job_key=task.job_key,
            worker_id="worker-1",
            dossier=dossier,
            dossier_hash=digest,
        )
        with self.database.connection() as conn:
            state = conn.execute(
                "SELECT state FROM pipeline_jobs WHERE job_key=?", (task.job_key,)
            ).fetchone()[0]
        self.assertEqual(state, PipelineState.EMPLOYER_RESEARCHED.value)


if __name__ == "__main__":
    unittest.main()
