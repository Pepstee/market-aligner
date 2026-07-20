from __future__ import annotations

import dataclasses
import hashlib
import tempfile
import unittest
from pathlib import Path

from career_automation.fetching import (
    ElementFingerprint,
    FetchAction,
    FetchAttempt,
    FetchControlStore,
    FetchEngine,
    FetchEscalationMachine,
    FetchOutcome,
    FetchPolicyError,
    RelocationPolicy,
    RelocationStatus,
    default_job_fetch_policy,
    relocate_fingerprint,
)


CONTENT_HASH = hashlib.sha256(b"job page").hexdigest()
SNAPSHOT_HASH = hashlib.sha256(b"snapshot").hexdigest()
WORKFLOW_HASH = hashlib.sha256(b"workflow").hexdigest()


def attempt(
    sequence_no: int,
    stage_index: int,
    outcome: FetchOutcome,
    *,
    attempt_id: str | None = None,
) -> FetchAttempt:
    policy = default_job_fetch_policy()
    successful = outcome is FetchOutcome.SUCCEEDED
    return FetchAttempt(
        attempt_id=attempt_id or f"attempt-{sequence_no}",
        resource_key="greenhouse:job-123",
        policy_hash=policy.content_hash,
        sequence_no=sequence_no,
        stage_index=stage_index,
        engine=policy.stages[stage_index].engine,
        requested_url="https://example.com/jobs/123",
        final_url="https://example.com/jobs/123",
        started_at="2026-07-19T12:00:00Z",
        elapsed_ms=120,
        outcome=outcome,
        status_code=200 if successful else 503,
        response_bytes=1200 if successful else 0,
        content_sha256=CONTENT_HASH if successful else None,
        raw_snapshot_ref="snapshots/job-123" if successful else None,
        diagnostics=(outcome.value,),
    )


class FetchEscalationTests(unittest.TestCase):
    def test_bounded_retries_then_one_way_escalation(self) -> None:
        machine = FetchEscalationMachine(default_job_fetch_policy())
        first = machine.decide(())
        self.assertEqual((first.action, first.engine), (
            FetchAction.RUN, FetchEngine.DIRECT_ADAPTER
        ))

        retry = machine.decide((attempt(1, 0, FetchOutcome.TRANSIENT_FAILURE),))
        self.assertEqual((retry.action, retry.stage_index, retry.attempt_number), (
            FetchAction.RETRY, 0, 2
        ))

        escalate = machine.decide((
            attempt(1, 0, FetchOutcome.TRANSIENT_FAILURE),
            attempt(2, 0, FetchOutcome.TRANSIENT_FAILURE),
        ))
        self.assertEqual((escalate.action, escalate.engine), (
            FetchAction.ESCALATE, FetchEngine.PUBLIC_HTTP
        ))

        browser = machine.decide((
            attempt(1, 0, FetchOutcome.TRANSIENT_FAILURE),
            attempt(2, 0, FetchOutcome.TRANSIENT_FAILURE),
            attempt(3, 1, FetchOutcome.JAVASCRIPT_REQUIRED),
        ))
        self.assertEqual((browser.action, browser.engine), (
            FetchAction.ESCALATE, FetchEngine.DYNAMIC_BROWSER
        ))

    def test_challenges_escalate_to_the_full_stealth_engine(self) -> None:
        machine = FetchEscalationMachine(default_job_fetch_policy())
        history = (
            attempt(1, 0, FetchOutcome.CAPTCHA_REQUIRED),
            attempt(2, 1, FetchOutcome.CAPTCHA_REQUIRED),
            attempt(3, 2, FetchOutcome.CAPTCHA_REQUIRED),
        )
        decision = machine.decide(history)
        self.assertEqual(decision.action, FetchAction.ESCALATE)
        self.assertEqual(decision.engine, FetchEngine.STEALTH_BROWSER)

    def test_policy_still_honours_explicit_non_fetch_boundaries(self) -> None:
        machine = FetchEscalationMachine(default_job_fetch_policy())
        for outcome in (
            FetchOutcome.AUTHENTICATION_REQUIRED,
            FetchOutcome.ROBOTS_DISALLOWED,
            FetchOutcome.AUTOMATION_PROHIBITED,
            FetchOutcome.POLICY_DENIED,
        ):
            with self.subTest(outcome=outcome):
                decision = machine.decide((attempt(1, 0, outcome),))
                self.assertEqual(decision.action, FetchAction.BLOCK)
                self.assertIsNone(decision.engine)

    def test_accepts_snapshot_and_exhausts_last_engine(self) -> None:
        machine = FetchEscalationMachine(default_job_fetch_policy())
        accepted = machine.decide((attempt(1, 0, FetchOutcome.SUCCEEDED),))
        self.assertEqual(accepted.action, FetchAction.ACCEPT)

        exhausted = machine.decide((
            attempt(1, 0, FetchOutcome.INCOMPLETE_CONTENT),
            attempt(2, 1, FetchOutcome.INCOMPLETE_CONTENT),
            attempt(3, 2, FetchOutcome.INVALID_CONTENT),
            attempt(4, 3, FetchOutcome.INVALID_CONTENT),
        ))
        self.assertEqual(exhausted.action, FetchAction.EXHAUST)

    def test_rejects_non_contiguous_or_wrong_policy_history(self) -> None:
        machine = FetchEscalationMachine(default_job_fetch_policy())
        with self.assertRaises(FetchPolicyError):
            machine.decide((attempt(2, 0, FetchOutcome.TRANSIENT_FAILURE),))
        wrong = dataclasses.replace(attempt(1, 0, FetchOutcome.TRANSIENT_FAILURE), policy_hash="0" * 64)
        with self.assertRaises(FetchPolicyError):
            machine.decide((wrong,))


class AdaptiveFingerprintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = ElementFingerprint(
            "apply-button-old",
            "button",
            (("aria-label", "Apply now"), ("role", "button"), ("type", "submit")),
            "Apply now",
            ("html", "body", "main", "form"),
            ("label", "button"),
        )

    def test_unique_high_confidence_candidate_is_selected(self) -> None:
        changed = ElementFingerprint(
            "apply-button-new",
            "button",
            (("aria-label", "Apply now"), ("role", "button"), ("type", "submit")),
            "Submit application",
            ("html", "body", "main", "section", "form"),
            ("label", "button"),
        )
        unrelated = ElementFingerprint(
            "cancel-button", "a", (("role", "link"),), "Cancel", ("html", "body", "nav"), ()
        )
        decision = relocate_fingerprint(self.source, (unrelated, changed))
        self.assertEqual(decision.status, RelocationStatus.MATCHED)
        self.assertEqual(decision.selected_locator_key, "apply-button-new")

    def test_close_candidates_are_ambiguous(self) -> None:
        first = dataclasses.replace(self.source, locator_key="candidate-a")
        second = dataclasses.replace(self.source, locator_key="candidate-b", text="Apply Now")
        decision = relocate_fingerprint(self.source, (first, second))
        self.assertEqual(decision.status, RelocationStatus.AMBIGUOUS)
        self.assertIsNone(decision.selected_locator_key)

    def test_low_score_is_not_silently_accepted(self) -> None:
        unrelated = ElementFingerprint(
            "other", "div", (("class", "footer"),), "Privacy policy", ("html", "body"), ()
        )
        decision = relocate_fingerprint(
            self.source, (unrelated,), RelocationPolicy(minimum_score=0.9)
        )
        self.assertEqual(decision.status, RelocationStatus.NO_MATCH)

    def test_weak_fingerprint_cannot_authorize_relocation(self) -> None:
        weak = ElementFingerprint("weak", "button")
        with self.assertRaisesRegex(ValueError, "insufficient independent signals"):
            relocate_fingerprint(weak, (ElementFingerprint("candidate", "button"),))


class FetchControlStoreTests(unittest.TestCase):
    def test_immutable_policy_attempt_and_relocation_ledgers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = FetchControlStore(Path(temporary) / "career.sqlite3")
            policy = default_job_fetch_policy()
            self.assertTrue(store.register_policy(policy))
            self.assertFalse(store.register_policy(policy))

            row = attempt(1, 0, FetchOutcome.TRANSIENT_FAILURE)
            self.assertTrue(store.record_attempt(row))
            self.assertFalse(store.record_attempt(row))
            self.assertEqual(store.attempts(row.resource_key, policy.content_hash), (row,))

            skipped = attempt(2, 2, FetchOutcome.INVALID_CONTENT, attempt_id="attempt-skipped")
            with self.assertRaisesRegex(FetchPolicyError, "not authorized"):
                store.record_attempt(skipped)

            changed = dataclasses.replace(row, elapsed_ms=121)
            with self.assertRaises(FetchPolicyError):
                store.record_attempt(changed)

            fingerprint = ElementFingerprint(
                "submit", "button", (("type", "submit"),), "Apply", ("form",), ()
            )
            self.assertTrue(store.register_fingerprint(
                site_host="example.com",
                workflow_hash=WORKFLOW_HASH,
                step_id="submit",
                version="1.0.0",
                fingerprint=fingerprint,
            ))
            decision = relocate_fingerprint(
                fingerprint, (dataclasses.replace(fingerprint, locator_key="submit-new"),)
            )
            self.assertTrue(store.record_relocation(
                decision, observed_snapshot_hash=SNAPSHOT_HASH
            ))
            self.assertFalse(store.record_relocation(
                decision, observed_snapshot_hash=SNAPSHOT_HASH
            ))


if __name__ == "__main__":
    unittest.main()
