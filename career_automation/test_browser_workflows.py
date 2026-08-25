from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from career_automation.browser_workflows import (
    ActionKind,
    ApplicationPreflightQualityReview,
    ApplicationQualityIssue,
    ApplicationQualityReview,
    ApprovalRequiredError,
    ApprovedValue,
    BrowserAction,
    BrowserWorkflow,
    BrowserWorkflowStore,
    CanaryEvidenceArtifact,
    CanaryOutcomeKind,
    CanaryStage,
    CanaryTerminalObservation,
    IdempotencyConflictError,
    QualityIssueSeverity,
    QualityReviewDisposition,
    ReleaseGateError,
    SelectorCandidate,
    SelectorOutcome,
    SelectorPlan,
    SelectorStrategy,
    StepResult,
    ValueReference,
    ValueSource,
    WorkflowError,
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


def _artifact(seed: str, *, kind: str = "provider_snapshot") -> CanaryEvidenceArtifact:
    return CanaryEvidenceArtifact(
        kind=kind,
        path=f"output/evidence/{seed}.json",
        sha256=seed * 64,
        size_bytes=100,
        media_type="application/json",
    )


def _terminal_failure(
    *,
    vacancy_sha256: str = "a" * 64,
    job_key: str = "ashby:example:low-priority",
    outcome: CanaryOutcomeKind = CanaryOutcomeKind.INELIGIBLE,
    final_click_attempted: bool = False,
) -> CanaryTerminalObservation:
    return CanaryTerminalObservation(
        observed_at="2026-08-26T12:00:00Z",
        stage=CanaryStage.ELIGIBILITY,
        outcome=outcome,
        ats="Ashby",
        official_url="https://jobs.example/low-priority",
        job_key=job_key,
        vacancy_sha256=vacancy_sha256,
        reason_code="essential_requirements_absent",
        summary="The official vacancy requires evidence that is absent.",
        technical_detail="Official vacancy bytes were evaluated before applicant-data entry.",
        applicant_data_exposed=False,
        final_click_attempted=final_click_attempted,
        provider_confirmed=False,
        provider_receipt_sha256=None,
        provider_screenshot_sha256=None,
        artifacts=(_artifact("b"),),
        next_engineering_action="Preserve the eligibility refusal and select a lower-risk vacancy.",
    )


def _failure_review(
    observation: CanaryTerminalObservation,
    *,
    release_blocking: bool = False,
) -> ApplicationQualityReview:
    return ApplicationQualityReview(
        reviewed_at="2026-08-26T12:01:00Z",
        terminal_observation_sha256=observation.content_sha256,
        disposition=QualityReviewDisposition.NOT_SUBMITTED,
        factual_accuracy_score=None,
        role_targeting_score=None,
        natural_voice_score=None,
        evidence_capture_score=9,
        technical_execution_score=10,
        application_source_sha256=None,
        artifact_receipt_sha256=None,
        cv_sha256=None,
        cover_letter_sha256=None,
        field_answers_sha256=None,
        form_inventory_sha256=None,
        provider_receipt_sha256=None,
        issues=(
            ApplicationQualityIssue(
                code="eligibility_refusal",
                severity=QualityIssueSeverity.INFO,
                category="eligibility",
                release_blocking=release_blocking,
                enforceable_by_code=True,
                summary="The vacancy was rejected before applicant-data entry.",
                evidence="The terminal observation binds the official vacancy snapshot.",
                remediation="Keep essential-requirement admission enabled for later canaries.",
            ),
        ),
        summary="No application was sent; the refusal was truthful and well evidenced.",
        next_cycle_decision="Proceed only when no release-blocking issue remains.",
    )


def _preflight_review(
    *,
    disposition: QualityReviewDisposition,
    vacancy_sha256: str = "a" * 64,
) -> ApplicationPreflightQualityReview:
    accepted = disposition is QualityReviewDisposition.ACCEPTED
    return ApplicationPreflightQualityReview(
        reviewed_at="2026-08-26T11:59:00Z",
        vacancy_sha256=vacancy_sha256,
        candidate_authority_sha256="1" * 64,
        application_source_sha256="2" * 64,
        artifact_receipt_sha256="3" * 64,
        cv_sha256="4" * 64,
        cover_letter_sha256="5" * 64,
        field_answers_sha256="6" * 64,
        form_inventory_sha256="7" * 64,
        quality_policy_sha256="8" * 64,
        reviewer_receipt_sha256="9" * 64,
        disposition=disposition,
        factual_accuracy_score=10 if accepted else 7,
        role_targeting_score=8 if accepted else 4,
        natural_voice_score=7 if accepted else 4,
        cross_application_consistency_score=10 if accepted else 6,
        evidence_capture_score=10 if accepted else 8,
        technical_execution_score=10 if accepted else 8,
        issues=()
        if accepted
        else (
            ApplicationQualityIssue(
                code="generic_cover_letter",
                severity=QualityIssueSeverity.ERROR,
                category="prose_quality",
                release_blocking=True,
                enforceable_by_code=True,
                summary="The cover letter is insufficiently role-specific.",
                evidence="The reviewer receipt records a failed company-specificity check.",
                remediation="Rebuild the package and obtain a fresh exact preflight review.",
            ),
        ),
        summary=(
            "The exact package passed every pre-release quality threshold."
            if accepted
            else "The exact package requires remediation before release."
        ),
    )


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
        with self.assertRaisesRegex(
            ReleaseGateError,
            "canonical submission proof",
        ):
            self.store.complete_step(
                run_id,
                "worker",
                step_id="submit",
                result=StepResult({"receipt_id": "receipt-42"}, report),
                release_gate_token=token,
            )
        snapshot = self.store.run_snapshot(run_id)
        self.assertEqual(snapshot["status"], "leased")
        self.assertIsNone(snapshot["release_gate_used_at"])
        self.assertNotEqual(snapshot["release_gate_hash"], token)
        events = self.store.events(run_id)
        self.assertEqual(
            sum(
                e["event_type"] == "release_gate_consumed"
                for e in events
            ),
            0,
        )
        self.assertNotIn(token, "".join(str(event) for event in events))

    def test_events_are_physically_append_only(self) -> None:
        run_id = self.store.create_run(_workflow())
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            with self.store.connection() as conn:
                conn.execute(
                    "UPDATE browser_workflow_events SET event_type='changed' WHERE run_id=?",
                    (run_id,),
                )

    def test_canary_requires_terminal_review_before_the_next_canary(self) -> None:
        workflow = _workflow()
        run_id = self.store.create_canary_run(
            workflow,
            profile_id="profile_one",
            job_key="ashby:example:low-priority",
            vacancy_rank=50,
            vacancy_sha256="a" * 64,
            idempotency_key="canary_50",
        )
        self.assertEqual(
            run_id,
            self.store.create_canary_run(
                workflow,
                profile_id="profile_one",
                job_key="ashby:example:low-priority",
                vacancy_rank=50,
                vacancy_sha256="a" * 64,
                idempotency_key="canary_50",
            ),
        )
        with self.assertRaisesRegex(WorkflowError, "already active"):
            self.store.create_canary_run(
                workflow,
                profile_id="profile_one",
                job_key="ashby:example:other",
                vacancy_rank=49,
                vacancy_sha256="c" * 64,
                idempotency_key="canary_49",
            )

        observation = _terminal_failure()
        self.assertTrue(self.store.record_canary_terminal_observation(run_id, observation))
        self.assertFalse(self.store.record_canary_terminal_observation(run_id, observation))
        with self.assertRaises(IdempotencyConflictError):
            self.store.record_canary_terminal_observation(
                run_id,
                _terminal_failure(outcome=CanaryOutcomeKind.VACANCY_CLOSED),
            )
        with self.assertRaisesRegex(WorkflowError, "requires a sealed quality review"):
            self.store.create_canary_run(
                workflow,
                profile_id="profile_one",
                job_key="ashby:example:other",
                vacancy_rank=49,
                vacancy_sha256="c" * 64,
                idempotency_key="canary_49",
            )

        review = _failure_review(observation)
        self.assertTrue(self.store.record_application_quality_review(run_id, review))
        self.assertFalse(self.store.record_application_quality_review(run_id, review))
        with self.assertRaises(IdempotencyConflictError):
            self.store.record_application_quality_review(
                run_id,
                ApplicationQualityReview(
                    **{**review.__dict__, "summary": "Substituted review text."}
                ),
            )
        with self.assertRaisesRegex(WorkflowError, "move upward"):
            self.store.create_canary_run(
                workflow,
                profile_id="profile_one",
                job_key="ashby:example:not-worse-first",
                vacancy_rank=50,
                vacancy_sha256="d" * 64,
                idempotency_key="canary_not_worse_first",
            )
        next_run = self.store.create_canary_run(
            workflow,
            profile_id="profile_one",
            job_key="ashby:example:other",
            vacancy_rank=49,
            vacancy_sha256="c" * 64,
            idempotency_key="canary_49",
        )
        self.assertNotEqual(run_id, next_run)
        snapshot = self.store.canary_snapshot(run_id)
        self.assertEqual(snapshot["state"], "reviewed")
        self.assertEqual(
            snapshot["terminal_observation"]["outcome"],
            CanaryOutcomeKind.INELIGIBLE.value,
        )
        self.assertEqual(
            snapshot["quality_review"]["disposition"],
            QualityReviewDisposition.NOT_SUBMITTED.value,
        )

    def test_release_blocking_quality_issue_holds_the_cycle(self) -> None:
        workflow = _workflow()
        run_id = self.store.create_canary_run(
            workflow,
            profile_id="profile_one",
            job_key="ashby:example:low-priority",
            vacancy_rank=50,
            vacancy_sha256="a" * 64,
            idempotency_key="canary_blocked",
        )
        observation = _terminal_failure()
        self.store.record_canary_terminal_observation(run_id, observation)
        self.store.record_application_quality_review(
            run_id,
            _failure_review(observation, release_blocking=True),
        )
        with self.assertRaisesRegex(WorkflowError, "unresolved release-blocking"):
            self.store.create_canary_run(
                workflow,
                profile_id="profile_one",
                job_key="ashby:example:next",
                vacancy_rank=49,
                vacancy_sha256="c" * 64,
                idempotency_key="canary_after_blocker",
            )

    def test_canary_release_requires_the_latest_accepted_preflight_review(self) -> None:
        run_id = self.store.create_canary_run(
            _workflow(submit=True),
            profile_id="profile_one",
            job_key="ashby:example:low-priority",
            vacancy_rank=50,
            vacancy_sha256="a" * 64,
            idempotency_key="canary_preflight",
        )
        token = "a-release-token-with-enough-entropy"
        with self.assertRaisesRegex(ReleaseGateError, "preflight quality review"):
            self.store.authorize_release(
                run_id,
                token=token,
                authorization_reference="RELEASE_POLICY_42",
                idempotency_key="release_before_review",
            )

        needs_work = _preflight_review(
            disposition=QualityReviewDisposition.NEEDS_REMEDIATION
        )
        self.assertTrue(
            self.store.record_application_preflight_quality_review(run_id, needs_work)
        )
        self.assertFalse(
            self.store.record_application_preflight_quality_review(run_id, needs_work)
        )
        with self.assertRaisesRegex(ReleaseGateError, "does not admit release"):
            self.store.authorize_release(
                run_id,
                token=token,
                authorization_reference="RELEASE_POLICY_42",
                idempotency_key="release_failed_review",
            )

        accepted = _preflight_review(disposition=QualityReviewDisposition.ACCEPTED)
        self.assertTrue(
            self.store.record_application_preflight_quality_review(run_id, accepted)
        )
        self.assertTrue(
            self.store.authorize_release(
                run_id,
                token=token,
                authorization_reference="RELEASE_POLICY_42",
                idempotency_key="release_accepted_review",
            )
        )
        with self.assertRaisesRegex(WorkflowError, "cannot change after release"):
            self.store.record_application_preflight_quality_review(
                run_id,
                ApplicationPreflightQualityReview(
                    **{
                        **accepted.__dict__,
                        "reviewed_at": "2026-08-26T12:00:00Z",
                        "reviewer_receipt_sha256": "f" * 64,
                    }
                ),
            )
        snapshot = self.store.canary_snapshot(run_id)
        self.assertEqual(
            snapshot["latest_preflight_quality_review"]["disposition"],
            QualityReviewDisposition.ACCEPTED.value,
        )

    def test_accepted_preflight_requires_exact_deterministic_scores(self) -> None:
        accepted = _preflight_review(disposition=QualityReviewDisposition.ACCEPTED)
        with self.assertRaisesRegex(ValueError, "exact deterministic quality scores"):
            ApplicationPreflightQualityReview(
                **{**accepted.__dict__, "factual_accuracy_score": 9}
            )
        with self.assertRaisesRegex(ValueError, "minimum targeting"):
            ApplicationPreflightQualityReview(
                **{**accepted.__dict__, "role_targeting_score": 5}
            )

    def test_concurrent_canary_creation_admits_exactly_one_active_run(self) -> None:
        workflow = _workflow()
        barrier = Barrier(2)

        def create(index: int) -> str:
            store = BrowserWorkflowStore(self.path, clock=self.clock)
            barrier.wait(timeout=5)
            return store.create_canary_run(
                workflow,
                profile_id="profile_one",
                job_key=f"ashby:example:concurrent-{index}",
                vacancy_rank=50 - index,
                vacancy_sha256=("a" if index == 0 else "b") * 64,
                idempotency_key=f"concurrent_canary_{index}",
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(create, index) for index in range(2)]
            results: list[str] = []
            errors: list[Exception] = []
            for future in futures:
                try:
                    results.append(future.result(timeout=10))
                except Exception as exc:  # noqa: BLE001 - exact competing outcome is asserted
                    errors.append(exc)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], WorkflowError)
        with self.store.connection() as conn:
            active = conn.execute(
                "SELECT COUNT(*) FROM browser_canary_runs WHERE state='active'"
            ).fetchone()[0]
        self.assertEqual(active, 1)

    def test_click_or_claim_alone_cannot_be_provider_confirmed(self) -> None:
        workflow = BrowserWorkflow(
            "official_overview",
            (
                BrowserAction(
                    "open",
                    ActionKind.NAVIGATE,
                    target_url="https://jobs.example/low-priority",
                ),
            ),
        )
        run_id = self.store.create_canary_run(
            workflow,
            profile_id="profile_one",
            job_key="ashby:example:low-priority",
            vacancy_rank=50,
            vacancy_sha256="a" * 64,
            idempotency_key="canary_no_dispatch",
        )
        self.store.claim_run("worker", run_id=run_id)
        self.store.complete_step(
            run_id,
            "worker",
            step_id="open",
            result=StepResult({"url_loaded": True}),
        )
        receipt = _artifact("d", kind="provider_receipt")
        screenshot = _artifact("e", kind="provider_screenshot")
        claimed_success = CanaryTerminalObservation(
            observed_at="2026-08-26T12:00:00Z",
            stage=CanaryStage.PROVIDER_CONFIRMATION,
            outcome=CanaryOutcomeKind.PROVIDER_CONFIRMED_SUBMISSION,
            ats="Ashby",
            official_url="https://jobs.example/low-priority",
            job_key="ashby:example:low-priority",
            vacancy_sha256="a" * 64,
            reason_code="provider_success",
            summary="A click was followed by a claimed success state.",
            technical_detail="The claim intentionally lacks a durable submit dispatch.",
            applicant_data_exposed=True,
            final_click_attempted=True,
            provider_confirmed=True,
            provider_receipt_sha256=receipt.sha256,
            provider_screenshot_sha256=screenshot.sha256,
            artifacts=(receipt, screenshot),
            next_engineering_action="Reject success without exact provider proof.",
        )
        with self.assertRaisesRegex(WorkflowError, "submit receipt"):
            self.store.record_canary_terminal_observation(run_id, claimed_success)
        with self.assertRaisesRegex(WorkflowError, "durable submit dispatch"):
            self.store.record_canary_terminal_observation(
                run_id,
                _terminal_failure(
                    outcome=CanaryOutcomeKind.OUTCOME_UNKNOWN,
                    final_click_attempted=True,
                ),
            )

    def test_canary_terminal_and_review_rows_are_physically_immutable(self) -> None:
        run_id = self.store.create_canary_run(
            _workflow(),
            profile_id="profile_one",
            job_key="ashby:example:low-priority",
            vacancy_rank=50,
            vacancy_sha256="a" * 64,
            idempotency_key="canary_immutable",
        )
        observation = _terminal_failure()
        review = _failure_review(observation)
        self.store.record_application_preflight_quality_review(
            run_id,
            _preflight_review(disposition=QualityReviewDisposition.ACCEPTED),
        )
        self.store.record_canary_terminal_observation(run_id, observation)
        self.store.record_application_quality_review(run_id, review)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            with self.store.connection() as conn:
                conn.execute(
                    """UPDATE browser_application_preflight_quality_reviews
                       SET document_json='{}' WHERE run_id=?""",
                    (run_id,),
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            with self.store.connection() as conn:
                conn.execute(
                    """UPDATE browser_canary_terminal_observations
                       SET document_json='{}' WHERE run_id=?""",
                    (run_id,),
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            with self.store.connection() as conn:
                conn.execute(
                    "DELETE FROM browser_application_quality_reviews WHERE run_id=?",
                    (run_id,),
                )


if __name__ == "__main__":
    unittest.main()
