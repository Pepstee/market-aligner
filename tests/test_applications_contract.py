from __future__ import annotations

import hashlib
import unittest

from market_aligner.applications.contracts import ApplicationEvent, ApplicationHandoff
from market_aligner.profiler.schema import new_profile_id


DIGEST = hashlib.sha256(b"fixture").hexdigest()


class ApplicationContractTests(unittest.TestCase):
    def test_provisional_handoff_is_hash_bound_and_uncalibrated(self) -> None:
        handoff = ApplicationHandoff(
            profile_id=new_profile_id(),
            profile_version="v1",
            job_key="board:1",
            vacancy_snapshot_sha256=DIGEST,
            evidence_ledger_sha256=DIGEST,
            eligibility_receipt_sha256=DIGEST,
            assessment_receipt_sha256=DIGEST,
            employer_dossier_sha256=None,
            fit_status="uncalibrated",
            fit=0.7,
            opportunity=0.8,
            created_at="2026-08-01T00:00:00Z",
        )
        self.assertEqual("market-aligner.jaa-handoff.v0", handoff.schema_version)
        with self.assertRaisesRegex(ValueError, "uncalibrated"):
            ApplicationHandoff(**{**handoff.__dict__, "fit_status": "calibrated"})

    def test_submission_and_receipt_events_are_operator_and_receipt_gated(self) -> None:
        common = {
            "application_id": "app-1",
            "profile_id": new_profile_id(),
            "job_key": "board:1",
            "occurred_at": "2026-08-01T00:00:00Z",
            "idempotency_key": "event-1",
            "payload_sha256": DIGEST,
        }
        with self.assertRaisesRegex(ValueError, "operator approval"):
            ApplicationEvent(event_type="submission_authorized", **common)
        authorized = ApplicationEvent(
            event_type="submission_authorized",
            operator_approval_sha256=DIGEST,
            **common,
        )
        self.assertEqual(DIGEST, authorized.operator_approval_sha256)
        with self.assertRaisesRegex(ValueError, "external receipt"):
            ApplicationEvent(event_type="receipt_captured", **common)


if __name__ == "__main__":
    unittest.main()
