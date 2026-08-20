from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from career_automation.deployment import DeploymentPlan, DeploymentStore, HealthCheckDefinition


def _plan(release_id: str) -> DeploymentPlan:
    return DeploymentPlan(
        service="career-api",
        release_id=release_id,
        artifact_digest="sha256:" + hashlib.sha256(release_id.encode()).hexdigest(),
        config_hash=hashlib.sha256((release_id + "-config").encode()).hexdigest(),
        checks=(
            HealthCheckDefinition("http", "http", "/health"),
            HealthCheckDefinition("db", "sqlite", "PRAGMA quick_check"),
        ),
    )


class DeploymentStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = DeploymentStore(Path(self.temporary.name) / "career.sqlite3")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _healthy_promote(self, release_id: str) -> None:
        self.store.stage(_plan(release_id))
        self.store.record_external_receipt(release_id, f"receipt-{release_id}")
        self.store.record_check(release_id, "http", passed=True)
        self.store.record_check(release_id, "db", passed=True)
        self.store.promote(release_id)

    def test_release_requires_digest_receipt_and_health(self) -> None:
        with self.assertRaisesRegex(ValueError, "sha256"):
            DeploymentPlan(
                service="x", release_id="bad", artifact_digest="latest",
                config_hash="0" * 64, checks=(HealthCheckDefinition("h", "http", "/"),),
            )
        self.store.stage(_plan("r1"))
        with self.assertRaisesRegex(RuntimeError, "receipt"):
            self.store.promote("r1")
        self.store.record_external_receipt("r1", "receipt")
        with self.assertRaisesRegex(RuntimeError, "health checks"):
            self.store.promote("r1")

    def test_stage_is_idempotent_but_release_id_is_immutable(self) -> None:
        self.assertTrue(self.store.stage(_plan("r1")))
        self.assertFalse(self.store.stage(_plan("r1")))
        changed = DeploymentPlan(
            service="career-api", release_id="r1",
            artifact_digest="sha256:" + "f" * 64,
            config_hash="e" * 64,
            checks=(HealthCheckDefinition("http", "http", "/health"),),
        )
        with self.assertRaisesRegex(ValueError, "different immutable plan"):
            self.store.stage(changed)

    def test_promote_and_rollback_are_audited(self) -> None:
        self._healthy_promote("r1")
        self._healthy_promote("r2")
        target = self.store.rollback("career-api", reason="failed live canary")
        self.assertEqual(target, "r1")
        with self.store.connection() as conn:
            states = dict(conn.execute(
                "SELECT release_id,status FROM career_deployment_releases"
            ).fetchall())
            event_types = [row[0] for row in conn.execute(
                "SELECT event_type FROM career_deployment_events ORDER BY id"
            ).fetchall()]
        self.assertEqual(states["r1"], "active")
        self.assertEqual(states["r2"], "rolled_back")
        self.assertIn("release_rolled_back", event_types)


if __name__ == "__main__":
    unittest.main()
