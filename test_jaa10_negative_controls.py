"""Adversarial controls for the withheld JAA-10 shadow evidence contract."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.browser_workflows import fixture_submit_event_sha256
from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    MUTATION_TEST_NODES,
    InterruptionObservation,
    MutationObservation,
    WithheldShadowEvidence,
    compile_withheld_shadow_evidence,
)
from test_jaa10_independent_acceptance import _observation


def test_fabricated_receipt_cannot_match_the_frozen_golden_set() -> None:
    first_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    first = _observation("shadow-001", first_time)
    with pytest.raises(ValueError, match="submission proof differs"):
        replace(first, receipt_id="0" * 64)


def test_stub_executor_output_cannot_enter_shadow_evidence() -> None:
    class StubExecutor:
        def run(self) -> dict[str, object]:
            return {
                "receipt_id": FROZEN_SHADOW_CONTRACT.receipt_id,
                "certifies_slice": True,
            }

    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="two typed"):
        compile_withheld_shadow_evidence(
            FROZEN_SHADOW_CONTRACT,
            (
                StubExecutor().run(),
                _observation(
                    "shadow-002",
                    observed_at + timedelta(days=1),
                ),
            ),  # type: ignore[arg-type]
        )


def test_missing_or_duplicate_time_separation_cannot_compile() -> None:
    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    first = _observation("shadow-001", observed_at)
    with pytest.raises(ValueError, match="two typed"):
        compile_withheld_shadow_evidence(
            FROZEN_SHADOW_CONTRACT,
            (first,),
        )
    with pytest.raises(ValueError, match="time-separated"):
        compile_withheld_shadow_evidence(
            FROZEN_SHADOW_CONTRACT,
            (
                first,
                _observation("shadow-002", observed_at),
            ),
        )
    with pytest.raises(ValueError, match="at least 24 hours"):
        compile_withheld_shadow_evidence(
            FROZEN_SHADOW_CONTRACT,
            (
                first,
                _observation(
                    "shadow-002",
                    observed_at + timedelta(hours=23, minutes=59),
                ),
            ),
        )
    with pytest.raises(ValueError, match="IDs must be unique"):
        compile_withheld_shadow_evidence(
            FROZEN_SHADOW_CONTRACT,
            (
                first,
                _observation(
                    "shadow-001",
                    observed_at + timedelta(days=1),
                ),
            ),
        )
    second = _observation(
        "shadow-002",
        observed_at + timedelta(days=1),
    )
    duplicate_event = fixture_submit_event_sha256(
        run_id=second.run_id,
        workflow_sha256=second.durable_workflow_sha256,
        step_id=second.step_id,
        release_manifest_sha256=first.release_manifest_sha256,
        receipt_id=second.receipt_id,
        receipt_payload_sha256=second.receipt_payload_sha256,
        screenshot_sha256=second.screenshot_sha256,
        field_map_sha256=second.field_map_sha256,
    )
    duplicate_manifest = replace(
        second,
        release_manifest_sha256=first.release_manifest_sha256,
        submit_event_sha256=duplicate_event,
        submission_proof=replace(
            second.submission_proof,
            release_manifest_sha256=first.release_manifest_sha256,
            submit_event_sha256=duplicate_event,
        ),
    )
    with pytest.raises(ValueError, match="distinct release manifests"):
        compile_withheld_shadow_evidence(
            FROZEN_SHADOW_CONTRACT,
            (
                first,
                duplicate_manifest,
            ),
        )


def test_caller_defined_shadow_contract_cannot_replace_frozen_authority() -> None:
    with pytest.raises(ValueError, match="standing JAA-09 real vacancy"):
        replace(
            FROZEN_SHADOW_CONTRACT,
            application_id="caller-defined-fixture",
        )


def test_superseded_synthetic_baseline_cannot_replace_real_vacancy_authority() -> None:
    with pytest.raises(ValueError, match="standing JAA-09 source triple"):
        replace(
            FROZEN_SHADOW_CONTRACT,
            baseline_revision="8107f09beb3c5651850ad40a0ff8842ac2de1e47",
        )
    with pytest.raises(ValueError, match="standing JAA-09 real vacancy"):
        replace(
            FROZEN_SHADOW_CONTRACT,
            job_key="jaa06-synthetic:strategy-job",
        )
    with pytest.raises(ValueError, match="authority differs"):
        replace(
            FROZEN_SHADOW_CONTRACT,
            official_response_sha256="0" * 64,
        )


def test_interruption_and_mutation_rows_fail_if_they_claim_unsafe_success() -> None:
    with pytest.raises(ValueError, match="at most one"):
        InterruptionObservation(
            "post_click_pre_checkpoint",
            "recovered",
            2,
            1,
        )
    with pytest.raises(ValueError, match="cannot perform a click"):
        InterruptionObservation(
            "post_mark_pre_click",
            "fail_closed",
            1,
            0,
        )
    with pytest.raises(ValueError, match="different executable test"):
        MutationObservation(
            "release_token_tamper",
            MUTATION_TEST_NODES["selector_drift"],
            blocked=True,
            receipt_created=False,
        )
    with pytest.raises(ValueError, match="did not fail closed"):
        MutationObservation(
            "release_token_tamper",
            MUTATION_TEST_NODES["release_token_tamper"],
            blocked=False,
            receipt_created=True,
        )


def test_frozen_field_map_drift_cannot_enter_shadow_evidence() -> None:
    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    first = _observation("shadow-001", observed_at)
    with pytest.raises(ValueError, match="submission proof differs"):
        replace(first, field_map_sha256="f" * 64)


def test_shadow_evidence_has_no_certifying_or_action_capability() -> None:
    source_value = (
        __import__(
            "career_automation.shadow_certification",
            fromlist=[""],
        )
        .__file__
    )
    assert source_value is not None
    text = Path(source_value).read_text(encoding="utf-8")
    for forbidden in (
        "aiohttp",
        "http.client",
        "httpx",
        "playwright",
        "socket",
        "urllib.request",
        "urlopen",
        "requests.",
        "subprocess",
        "consume_release_token",
        "evaluate_and_issue",
        "certifies_slice: bool = True",
    ):
        assert forbidden not in text

    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    evidence = compile_withheld_shadow_evidence(
        FROZEN_SHADOW_CONTRACT,
        (
            _observation("shadow-001", observed_at),
            _observation(
                "shadow-002",
                observed_at + timedelta(days=1),
            ),
        ),
    )
    with pytest.raises(ValueError, match="cannot certify production"):
        replace(evidence, certifies_slice=True)
    with pytest.raises(ValueError, match="cannot certify production"):
        replace(
            evidence,
            withheld_reason="upstream_jaa04_authentic_authority_blocked",
        )


def test_durable_submit_event_and_typed_proof_cannot_drift() -> None:
    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    first = _observation("shadow-001", observed_at)
    with pytest.raises(ValueError, match="submission proof differs"):
        replace(
            first,
            submit_event_sha256="f" * 64,
        )
    with pytest.raises(ValueError, match="submission proof differs"):
        replace(
            first,
            submission_proof=replace(
                first.submission_proof,
                release_manifest_sha256="e" * 64,
            ),
        )
    with pytest.raises(ValueError, match="fixture receipt differs"):
        replace(
            first,
            fixture_receipt=replace(
                first.fixture_receipt,
                job_key="forged:job",
                receipt_id="0" * 64,
            ),
        )


def test_caller_only_observation_cannot_self_attest_execution() -> None:
    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    first = _observation("shadow-001", observed_at)
    assert first.execution_claim == "structural_lineage_only"
    with pytest.raises(ValueError, match="cannot self-attest execution"):
        replace(first, execution_claim="executed")


def test_withheld_evidence_cannot_replace_embedded_lineage_with_digests() -> None:
    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    observations = (
        _observation("shadow-001", observed_at),
        _observation("shadow-002", observed_at + timedelta(days=1)),
    )
    evidence = compile_withheld_shadow_evidence(
        FROZEN_SHADOW_CONTRACT,
        observations,
    )
    assert evidence.document()["contract"] == (
        FROZEN_SHADOW_CONTRACT.document()
    )
    assert evidence.document()["observations"] == [
        row.document() for row in observations
    ]
    with pytest.raises(TypeError):
        WithheldShadowEvidence(  # type: ignore[call-arg]
            contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
            observation_sha256s=evidence.observation_sha256s,
            release_manifest_sha256s=evidence.release_manifest_sha256s,
            hard_quality_targets=evidence.hard_quality_targets,
            evidence_id=evidence.evidence_id,
        )
    with pytest.raises(ValueError, match="two typed observations"):
        WithheldShadowEvidence(
            contract=FROZEN_SHADOW_CONTRACT,
            observations=(observations[0],),
            hard_quality_targets=evidence.hard_quality_targets,
            evidence_id="0" * 64,
        )
