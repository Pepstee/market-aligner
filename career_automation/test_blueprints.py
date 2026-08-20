from __future__ import annotations

import unittest

from career_automation.blueprints import backend_capability_authorizer, career_pipeline_flow
from career_automation.observability import FlowDefinition


class BlueprintTests(unittest.TestCase):
    def test_flow_round_trips_and_preserves_security_critical_order(self) -> None:
        flow = career_pipeline_flow()
        restored = FlowDefinition.from_json(flow.to_json())
        self.assertEqual(restored.content_hash, flow.content_hash)
        steps = {step.step_id: step for step in flow.steps}
        self.assertEqual(steps["research_employer"].depends_on, ("admit_opportunity",))
        self.assertEqual(steps["submit_application"].depends_on, ("validate_release",))
        self.assertFalse(flow.metadata["probabilistic_output_advances_state"])

    def test_capability_authorizer_is_default_deny_and_scoped(self) -> None:
        authorizer = backend_capability_authorizer()
        self.assertTrue(authorizer.authorize(
            "employer-research", "network.public_read", "web/employers/acme"
        ).allowed)
        self.assertFalse(authorizer.authorize(
            "employer-research", "network.public_read", "web/jobs/acme"
        ).allowed)
        self.assertFalse(authorizer.authorize(
            "style-critic", "application.submit", "applications/releases/r1"
        ).allowed)
        self.assertTrue(authorizer.authorize(
            "submission-browser", "application.submit", "applications/releases/r1"
        ).allowed)


if __name__ == "__main__":
    unittest.main()
