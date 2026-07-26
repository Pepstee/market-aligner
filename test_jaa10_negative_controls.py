"""Adversarial controls for the withheld JAA-10 shadow evidence contract."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
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


def test_interruption_and_mutation_rows_fail_if_they_claim_unsafe_success() -> None:
    with pytest.raises(ValueError, match="at most one"):
        InterruptionObservation(
            "post_click_pre_checkpoint",
            "recovered",
            2,
            1,
        )
    with pytest.raises(ValueError, match="did not fail closed"):
        MutationObservation(
            "release_token_tamper",
            blocked=False,
            receipt_created=True,
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
