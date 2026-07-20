from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from career_automation.browser_workflows import (
    ActionKind,
    ApprovalRequiredError,
    ApprovedValue,
    BrowserAction,
    BrowserWorkflow,
    BrowserWorkflowStore,
    IdempotencyConflictError,
    ReleaseGateError,
    SelectorCandidate,
    SelectorOutcome,
    SelectorPlan,
    SelectorStrategy,
    StepResult,
    ValueReference,
    ValueSource,
)
from career_automation.database import CareerDatabase


class FakeClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _selectors() -> SelectorPlan:
    return SelectorPlan(
        (
            SelectorCandidate(SelectorStrategy.LABEL, "Email address"),
            SelectorCandidate(SelectorStrategy.TEST_ID, "candidate-email"),
            SelectorCandidate(SelectorStrategy.CSS, "input[type=email]"),
        )
    )


def _workflow(*, submit: bool = False) -> BrowserWorkflow:
    actions = [
        BrowserAction("open", ActionKind.NAVIGATE, target_url="https://jobs.example/apply"),
        BrowserAction(
            "email",
            ActionKind.FILL,
            selectors=_selectors(),
            value_reference=ValueReference(ValueSource.EVIDENCE, "EV_CONTACT_EMAIL"),
            required_output_keys=("field_status",),
        ),
        BrowserAction(
            "review",
            ActionKind.CLICK,
            selectors=SelectorPlan(
                (SelectorCandidate(SelectorStrategy.ROLE, "button:Review application"),)
            ),
        ),
    ]
    if submit:
        actions.append(
            BrowserAction(
                "submit",
                ActionKind.SUBMIT,
                selectors=SelectorPlan(
                    (SelectorCandidate(SelectorStrategy.ROLE, "button:Submit application"),)
                ),
                required_output_keys=("receipt_id",),
            )
        )
    return BrowserWorkflow("example_application", tuple(actions))


class BrowserWorkflowModelTests(unittest.TestCase):
    def test_content_hash_is_stable_and_selector_order_is_versioned(self) -> None:
        first = _workflow()
        same = BrowserWorkflow.from_dict(first.to_dict())
        self.assertEqual(first.content_hash, same.content_hash)
        self.assertEqual(first.version, same.version)

        reversed_plan = SelectorPlan(tuple(reversed(_selectors().candidates)))
        changed = BrowserWorkflow(
            "example_application",
            (
                first.actions[0],
                BrowserAction(
                    "email",
                    ActionKind.FILL,
                    selectors=reversed_plan,
                    value_reference=ValueReference(ValueSource.EVIDENCE, "EV_CONTACT_EMAIL"),
                    required_output_keys=("field_status",),
                ),
                first.actions[2],
            ),
        )
        self.assertNotEqual(first.content_hash, changed.content_hash)

    def test_selector_recovery_is_ordered_and_deterministic(self) -> None:
        plan = _selectors()
        report = plan.assess(
            (SelectorOutcome.NOT_FOUND, SelectorOutcome.NOT_VISIBLE, SelectorOutcome.MATCHED)
        )
        self.assertTrue(report.succeeded)
        self.assertTrue(report.recovered)
        self.assertEqual(report.selected_index, 2)
        self.assertEqual(
            report.failure_codes,
            ("not_found", "not_visible", "matched"),
        )
        self.assertEqual(report.to_dict(), plan.assess(tuple(a.outcome for a in report.attempts)).to_dict())
        with self.assertRaisesRegex(ValueError, "stop at the first match"):
            plan.assess((SelectorOutcome.MATCHED, SelectorOutcome.NOT_FOUND))

    def test_raw_values_and_nonfinal_submit_are_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "never raw values"):
            BrowserAction(
                "email",
                ActionKind.FILL,
                selectors=_selectors(),
                value_reference="person@example.com",  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "value reference"):
            BrowserAction("email", ActionKind.FILL, selectors=_selectors())
        with self.assertRaisesRegex(ValueError, "must be final"):
            BrowserWorkflow(
                "unsafe",
                (
                    BrowserAction("submit", ActionKind.SUBMIT, selectors=_selectors()),
                    BrowserAction("later", ActionKind.CLICK, selectors=_selectors()),
                ),
            )


class BrowserWorkflowStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "career.sqlite3"
        self.clock = FakeClock()
        self.store = BrowserWorkflowStore(self.path, clock=self.clock)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_store_coexists_with_career_database(self) -> None:
        CareerDatabase(self.path)
        self.store.register_workflow(_workflow())
        with self.store.connection() as conn:
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        self.assertIn("pipeline_jobs", tables)
        self.assertIn("browser_workflow_runs", tables)

    def test_resume_skips_checkpoints_and_exact_retries_are_idempotent(self) -> None:
        workflow = _workflow()
        run_id = self.store.create_run(workflow, idempotency_key="job-42")
        self.assertEqual(run_id, self.store.create_run(workflow, idempotency_key="job-42"))
        lease = self.store.claim_run("worker_one", run_id=run_id, lease_seconds=10)
        self.assertIsNotNone(lease)

        pending = self.store.next_action(run_id, "worker_one")
        assert pending is not None
        self.assertEqual(pending.action.step_id, "open")
        self.assertTrue(
            self.store.complete_step(
                run_id, "worker_one", step_id="open", result=StepResult({"url_loaded": True})
            )
        )
        self.assertFalse(
            self.store.complete_step(
                run_id, "worker_one", step_id="open", result=StepResult({"url_loaded": True})
            )
        )
        with self.assertRaises(IdempotencyConflictError):
            self.store.complete_step(
                run_id, "worker_one", step_id="open", result=StepResult({"url_loaded": False})
            )

        approval = ApprovedValue(
            ValueReference(ValueSource.EVIDENCE, "EV_CONTACT_EMAIL"), "APPROVAL_42"
        )
        pending = self.store.next_action(run_id, "worker_one", approved_values=(approval,))
        assert pending is not None
        self.assertEqual(pending.action.step_id, "email")
        self.assertIn("open", pending.prior_outputs)
        fallback = _selectors().assess((SelectorOutcome.NOT_FOUND, SelectorOutcome.MATCHED))
        self.store.complete_step(
            run_id,
            "worker_one",
            step_id="email",
            result=StepResult({"field_status": "filled"}, fallback),
            approved_values=(approval,),
        )

        self.clock.advance(11)
        resumed = self.store.claim_run("worker_two", run_id=run_id, lease_seconds=10)
        self.assertIsNotNone(resumed)
        assert resumed is not None
        self.assertEqual(resumed.lease_attempt, 2)
        pending = self.store.next_action(run_id, "worker_two")
        assert pending is not None
        self.assertEqual(pending.action.step_id, "review")
        report = pending.action.selectors.assess((SelectorOutcome.MATCHED,))  # type: ignore[union-attr]
        self.store.complete_step(
            run_id,
            "worker_two",
            step_id="review",
            result=StepResult({}, report),
        )
        snapshot = self.store.run_snapshot(run_id)
        self.assertEqual(snapshot["status"], "completed")
        self.assertEqual(snapshot["checkpoint_count"], 3)
        step_events = [e for e in self.store.events(run_id) if e["event_type"] == "step_completed"]
        self.assertEqual(len(step_events), 3)

    def test_missing_approval_cannot_be_replaced_with_a_guessed_value(self) -> None:
        workflow = _workflow()
        run_id = self.store.create_run(workflow)
        self.store.claim_run("worker", run_id=run_id)
        self.store.complete_step(run_id, "worker", step_id="open", result=StepResult())

        with self.assertRaises(ApprovalRequiredError):
            self.store.next_action(run_id, "worker")
        wrong = ApprovedValue(
            ValueReference(ValueSource.PLACEHOLDER, "CONTACT_EMAIL"), "APPROVAL_WRONG"
        )
        with self.assertRaises(ApprovalRequiredError):
            self.store.next_action(run_id, "worker", approved_values=(wrong,))
        with self.assertRaises(ApprovalRequiredError):
            self.store.complete_step(
                run_id,
                "worker",
                step_id="email",
                result=StepResult(
                    {"field_status": "filled"},
                    _selectors().assess((SelectorOutcome.MATCHED,)),
                ),
            )
        with self.store.connection() as conn:
            definition = conn.execute(
                "SELECT definition_json FROM browser_workflow_definitions"
            ).fetchone()[0]
        self.assertIn("EV_CONTACT_EMAIL", definition)
        self.assertNotIn("person@example.com", definition)

    def test_selector_failure_is_reported_idempotently_without_advancing(self) -> None:
        workflow = BrowserWorkflow(
            "one_click",
            (BrowserAction("click", ActionKind.CLICK, selectors=_selectors()),),
        )
        run_id = self.store.create_run(workflow)
        self.store.claim_run("worker", run_id=run_id)
        failure = _selectors().assess(
            (
                SelectorOutcome.NOT_FOUND,
                SelectorOutcome.NOT_VISIBLE,
                SelectorOutcome.AMBIGUOUS,
            )
        )
        self.assertTrue(
            self.store.record_selector_failure(
                run_id,
                "worker",
                step_id="click",
                report=failure,
                idempotency_key="attempt-1",
            )
        )
        self.assertFalse(
            self.store.record_selector_failure(
                run_id,
                "worker",
                step_id="click",
                report=failure,
                idempotency_key="attempt-1",
            )
        )
        different_failure = _selectors().assess(
            (
                SelectorOutcome.NOT_VISIBLE,
                SelectorOutcome.NOT_VISIBLE,
                SelectorOutcome.AMBIGUOUS,
            )
        )
        with self.assertRaises(IdempotencyConflictError):
            self.store.record_selector_failure(
                run_id,
                "worker",
                step_id="click",
                report=different_failure,
                idempotency_key="attempt-1",
            )
        pending = self.store.next_action(run_id, "worker")
        self.assertIsNotNone(pending)
        self.assertEqual(pending.action.step_id, "click")  # type: ignore[union-attr]
        failures = [
            event
            for event in self.store.events(run_id)
            if event["event_type"] == "selector_candidates_exhausted"
        ]
        self.assertEqual(len(failures), 1)

    def test_submit_is_withheld_until_one_use_release_token_is_presented(self) -> None:
        submit_action = BrowserAction(
            "submit",
            ActionKind.SUBMIT,
            selectors=SelectorPlan(
                (SelectorCandidate(SelectorStrategy.ROLE, "button:Submit application"),)
            ),
            required_output_keys=("receipt_id",),
        )
        workflow = BrowserWorkflow("submit_only", (submit_action,))
        run_id = self.store.create_run(workflow)
        self.store.claim_run("worker", run_id=run_id)
        token = "a-release-token-with-enough-entropy"

        with self.assertRaises(ReleaseGateError):
            self.store.next_action(run_id, "worker")
        self.assertTrue(
            self.store.authorize_release(
                run_id,
                token=token,
                authorization_reference="RELEASE_POLICY_42",
                idempotency_key="decision-42",
            )
        )
        self.assertFalse(
            self.store.authorize_release(
                run_id,
                token=token,
                authorization_reference="RELEASE_POLICY_42",
                idempotency_key="decision-42",
            )
        )
        with self.assertRaises(ReleaseGateError):
            self.store.next_action(run_id, "worker", release_gate_token="wrong-token-value!")
        pending = self.store.next_action(run_id, "worker", release_gate_token=token)
        assert pending is not None
        report = submit_action.selectors.assess((SelectorOutcome.MATCHED,))  # type: ignore[union-attr]
        with self.assertRaises(ReleaseGateError):
            self.store.complete_step(
                run_id,
                "worker",
                step_id="submit",
                result=StepResult({"receipt_id": "receipt-42"}, report),
                release_gate_token="wrong-token-value!",
            )
        self.store.complete_step(
            run_id,
            "worker",
            step_id="submit",
            result=StepResult({"receipt_id": "receipt-42"}, report),
            release_gate_token=token,
        )
        snapshot = self.store.run_snapshot(run_id)
        self.assertEqual(snapshot["status"], "completed")
        self.assertIsNotNone(snapshot["release_gate_used_at"])
        self.assertNotEqual(snapshot["release_gate_hash"], token)
        events = self.store.events(run_id)
        self.assertEqual(sum(e["event_type"] == "release_gate_consumed" for e in events), 1)
        self.assertNotIn(token, "".join(str(event) for event in events))

    def test_events_are_physically_append_only(self) -> None:
        run_id = self.store.create_run(_workflow())
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            with self.store.connection() as conn:
                conn.execute(
                    "UPDATE browser_workflow_events SET event_type='changed' WHERE run_id=?",
                    (run_id,),
                )


if __name__ == "__main__":
    unittest.main()
