from __future__ import annotations

import hashlib
import subprocess
import sys
import unittest

import market_aligner.applications as applications
from market_aligner.applications import contracts, observe_ats_form_or_recover
from market_aligner.applications.contracts import ApplicationEvent, ApplicationHandoff
from market_aligner.profiler.schema import new_profile_id


DIGEST = hashlib.sha256(b"fixture").hexdigest()

_JAA_EXPORT_NAMES = (
    "ApplicationSource",
    "ATSForensicLearningEvent",
    "ATSForensicReceipt",
    "ATSForensicRecorder",
    "AtsFieldOption",
    "AtsFixturePreSubmitAuthority",
    "AtsFormInventory",
    "AtsObservationAcceptance",
    "AtsObservationAcceptanceReceipt",
    "AtsObservationAuthority",
    "AtsObservedField",
    "AtsPreSubmitField",
    "AtsReadOnlyObservation",
    "CaptureBackend",
    "FixtureCaptureBackend",
    "MARKET_OBSERVATION_KEY_ID",
    "MARKET_OBSERVATION_PUBLIC_DER_SHA256",
    "SanityReviewReceipt",
    "capture_or_recover",
    "compile_fixture_pre_submit_plan",
    "execute_fixture_pre_submit_or_recover",
    "list_canary_learning_events",
    "load_forensic_receipt",
    "market_observation_consumption_root_sha256",
    "observe_ats_form_or_recover",
    "prepare_from_market",
    "record_canary_learning_event",
    "verify_and_consume_market_observation_acceptance",
    "verify_canary_learning_event",
)

_CONTRACT_EXPORT_NAMES = (
    "ApplicationEvent",
    "ApplicationHandoff",
    "EventEnvelope",
    "EventProjector",
    "HandoffEnvelope",
    "HandoffReplayIndex",
    "JAAClient",
    "encode_event_v1",
    "encode_handoff_v1",
    "parse_event_v1",
    "parse_handoff_v1",
)


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

    def test_restored_jaa_exports_are_object_identical_to_jaa_owners(self) -> None:
        from market_aligner.applications import jaa

        for name in _JAA_EXPORT_NAMES:
            self.assertIs(getattr(applications, name), getattr(jaa, name), name)
        self.assertIn("observe_ats_form_or_recover", applications.__all__)

    def test_contract_exports_are_unaffected(self) -> None:
        for name in _CONTRACT_EXPORT_NAMES:
            self.assertIs(getattr(applications, name), getattr(contracts, name), name)
        self.assertEqual(
            [*applications.__all__],
            [*_CONTRACT_EXPORT_NAMES, *sorted(_JAA_EXPORT_NAMES)],
        )

    def test_fresh_interpreter_import_does_not_eagerly_load_jaa(self) -> None:
        probe = (
            "import sys\n"
            "import market_aligner.applications as applications\n"
            "assert 'market_aligner.applications.jaa' not in sys.modules\n"
            "applications.JAAClient  # contract access stays cycle-free\n"
            "assert 'market_aligner.applications.jaa' not in sys.modules\n"
            "from market_aligner.applications import observe_ats_form_or_recover\n"
            "from market_aligner.applications import jaa\n"
            "assert observe_ats_form_or_recover is jaa.observe_ats_form_or_recover\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_explicit_observer_import_succeeds(self) -> None:
        self.assertTrue(callable(observe_ats_form_or_recover))

    def test_unknown_names_still_raise_attribute_error(self) -> None:
        with self.assertRaises(AttributeError):
            getattr(applications, "not_a_historical_export")


if __name__ == "__main__":
    unittest.main()
