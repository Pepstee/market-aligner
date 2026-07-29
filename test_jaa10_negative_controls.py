"""Adversarial controls for the withheld JAA-10 shadow evidence contract."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    MUTATION_TEST_NODES,
    InterruptionObservation,
    MutationObservation,
    compile_withheld_shadow_evidence,
)
from test_jaa10_independent_acceptance import _observation


def test_fabricated_receipt_cannot_match_the_frozen_golden_set() -> None:
    first_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    first = _observation("shadow-001", first_time)
    fabricated = replace(first, receipt_id="0" * 64)
    with pytest.raises(ValueError, match="frozen golden"):
        compile_withheld_shadow_evidence(
            FROZEN_SHADOW_CONTRACT,
            (
                fabricated,
                _observation(
                    "shadow-002",
                    first_time + timedelta(days=1),
                ),
            ),
        )


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
    with pytest.raises(ValueError, match="distinct release manifests"):
        compile_withheld_shadow_evidence(
            FROZEN_SHADOW_CONTRACT,
            (
                first,
                replace(
                    _observation(
                        "shadow-002",
                        observed_at + timedelta(days=1),
                    ),
                    release_manifest_sha256=(
                        first.release_manifest_sha256
                    ),
                ),
            ),
        )


def test_caller_defined_shadow_contract_cannot_replace_frozen_authority() -> None:
    observed_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    replacement = replace(
        FROZEN_SHADOW_CONTRACT,
        application_id="caller-defined-fixture",
    )
    with pytest.raises(ValueError, match="canonical frozen contract"):
        compile_withheld_shadow_evidence(
            replacement,
            (
                _observation("shadow-001", observed_at),
                _observation(
                    "shadow-002",
                    observed_at + timedelta(days=1),
                ),
            ),
        )


def test_interruption_and_mutation_rows_fail_if_they_claim_unsafe_success() -> None:
    with pytest.raises(ValueError, match="at most one"):
        InterruptionObservation(
            "post_click_pre_checkpoint",
            "recovered",
            2,
            1,
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
    changed = replace(first, field_map_sha256="f" * 64)
    with pytest.raises(ValueError, match="frozen golden"):
        compile_withheld_shadow_evidence(
            FROZEN_SHADOW_CONTRACT,
            (
                changed,
                _observation(
                    "shadow-002",
                    observed_at + timedelta(days=1),
                ),
            ),
        )


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
