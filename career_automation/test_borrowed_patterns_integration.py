from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from career_automation.blueprints import backend_capability_authorizer, career_pipeline_flow
from career_automation.browser_workflows import BrowserWorkflowStore
from career_automation.database import CareerDatabase
from career_automation.deployment import DeploymentStore
from career_automation.engine import OpportunityGate, scored_job_from_payload
from career_automation.fetching import FetchControlStore, default_job_fetch_policy
from career_automation.migrations import MigrationRunner
from career_automation.observability import ObservabilityStore
from career_automation.retrieval import EvidenceDocument, HybridEvidenceIndex
from career_automation.security import OutboundURLPolicy


class BorrowedPatternsIntegrationTests(unittest.TestCase):
    def test_all_control_stores_coexist_without_changing_job_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "career.sqlite3"
            database = CareerDatabase(path)
            summary = OpportunityGate(database).bootstrap([
                scored_job_from_payload({
                    "board": "test", "job_id": "1", "url": "https://example.test/jobs/1",
                    "job_title": "AI Engineer", "company": "Example", "fit": 0.7,
                    "opportunity": 0.8, "final": 75.0, "extraction_confidence": 0.95,
                })
            ])
            self.assertEqual(summary.queued, 1)

            observability = ObservabilityStore(path)
            BrowserWorkflowStore(path)
            DeploymentStore(path)
            fetching = FetchControlStore(path)
            self.assertTrue(fetching.register_policy(default_job_fetch_policy()))
            MigrationRunner(path)
            self.assertTrue(observability.register_flow(career_pipeline_flow()))

            self.assertEqual(database.stats()["total"], 1)
            self.assertEqual(database.stats()["research_queued"], 1)
            with database.connection() as conn:
                tables = {row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()}
            self.assertIn("pipeline_jobs", tables)
            self.assertIn("ca_obs_flows", tables)
            self.assertIn("browser_workflow_runs", tables)
            self.assertIn("career_deployment_releases", tables)
            self.assertIn("career_schema_migrations", tables)
            self.assertIn("ca_fetch_policies", tables)
            self.assertIn("ca_fetch_attempts", tables)
            self.assertIn("ca_fetch_selector_fingerprints", tables)
            self.assertIn("ca_fetch_relocations", tables)

    def test_retrieval_capability_and_ssrf_controls_compose(self) -> None:
        index = HybridEvidenceIndex(
            [EvidenceDocument("e1", "Verified Python automation evidence")],
            profile_version="profile-v1",
        )
        result = index.search("Python")[0]
        self.assertEqual(result.evidence_id, "e1")

        authorizer = backend_capability_authorizer()
        self.assertTrue(authorizer.authorize(
            "evidence-retriever", "evidence.read", "evidence/projections/profile-v1"
        ).allowed)
        self.assertFalse(authorizer.authorize(
            "evidence-retriever", "application.submit", "applications/releases/r1"
        ).allowed)

        policy = OutboundURLPolicy(resolver=lambda host, port: ("93.184.216.34",))
        validated = policy.validate("https://example.com/jobs")
        validated.assert_connected_peer("93.184.216.34")


if __name__ == "__main__":
    unittest.main()
