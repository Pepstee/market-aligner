"""Fail-closed controls for the JAA-11 operator-authority intake."""

from __future__ import annotations

from dataclasses import replace

import pytest

from career_automation.live_canary_authority import (
    AUTHORITY_FILE_SHA256,
    FROZEN_LIVE_CANARY_AUTHORITY,
    LiveCanaryOperatorAuthority,
    compile_canary_selection,
    evaluate_live_canary_authority,
)
from test_jaa11_live_canary_authority_intake import _selection


@pytest.mark.parametrize("selected_rank", range(1, 21))
def test_forbidden_top_20_ranks_fail_closed(selected_rank: int) -> None:
    with pytest.raises(ValueError, match="outside ranks 1-20"):
        _selection(selected_rank=selected_rank)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("ranked_snapshot_sha256", "", "lowercase SHA-256"),
        ("ranked_snapshot_sha256", "0" * 63, "lowercase SHA-256"),
        ("snapshot_entry_count", 20, "at least 21"),
        ("snapshot_entry_count", None, "at least 21"),
        ("selected_rank", None, "outside ranks 1-20"),
        ("selected_rank", 26, "outside ranks 1-20"),
        ("ranking_algorithm", "", "required"),
        ("ranking_version", " v1", "surrounding whitespace"),
        ("vacancy_identity", "", "required"),
        (
            "vacancy_retrieved_at",
            "2026-07-31T12:00:00",
            "aware ISO",
        ),
        ("vacancy_content_sha256", "x" * 64, "lowercase SHA-256"),
        ("selected_entry_sha256", "A" * 64, "lowercase SHA-256"),
    ),
)
def test_missing_ambiguous_underfilled_or_hash_invalid_snapshot_fails_closed(
    field: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        _selection(**{field: value})


def test_duplicate_or_failed_eligibility_truth_or_route_fails_closed() -> None:
    cases = (
        ("duplicate_application_found", True, "duplicate application"),
        ("eligibility_gate_passed", False, "eligibility and truth"),
        ("truth_gate_passed", False, "eligibility and truth"),
        ("vacancy_open", False, "open on an official route"),
        ("official_route", False, "open on an official route"),
        (
            "selected_only_for_submission_ease",
            True,
            "cannot be based only on ease",
        ),
    )
    for field, value, message in cases:
        with pytest.raises(ValueError, match=message):
            _selection(**{field: value})


@pytest.mark.parametrize(
    "field",
    (
        "account_creation_required",
        "login_required",
        "mfa_required",
        "captcha_required",
        "payment_required",
        "missing_approved_fact",
    ),
)
def test_each_documented_fail_closed_trigger_blocks_selection(
    field: str,
) -> None:
    with pytest.raises(ValueError, match="fail-closed trigger"):
        _selection(**{field: True})


def test_marketing_consent_must_remain_declined() -> None:
    with pytest.raises(ValueError, match="must remain declined"):
        _selection(optional_marketing_consent="accepted")


def test_authority_exhausts_on_first_submission_or_certification() -> None:
    submitted = evaluate_live_canary_authority(
        FROZEN_LIVE_CANARY_AUTHORITY,
        submission_count=1,
        jaa11_certified=False,
    )
    assert submitted.status == "exhausted"
    assert submitted.remaining_canaries == 0
    assert submitted.may_submit is False
    assert submitted.reasons == ("single_use_submission_consumed",)

    certified = evaluate_live_canary_authority(
        FROZEN_LIVE_CANARY_AUTHORITY,
        submission_count=0,
        jaa11_certified=True,
    )
    assert certified.status == "exhausted"
    assert certified.reasons == ("jaa11_already_certified",)

    second_attempt = evaluate_live_canary_authority(
        FROZEN_LIVE_CANARY_AUTHORITY,
        submission_count=2,
        jaa11_certified=False,
    )
    assert second_attempt.status == "exhausted"
    assert second_attempt.remaining_canaries == 0


@pytest.mark.parametrize(
    ("submission_count", "jaa11_certified"),
    (
        (None, False),
        (-1, False),
        (False, False),
        (0, None),
        (0, "false"),
    ),
)
def test_ambiguous_authority_state_is_withheld(
    submission_count: object,
    jaa11_certified: object,
) -> None:
    state = evaluate_live_canary_authority(
        FROZEN_LIVE_CANARY_AUTHORITY,
        submission_count=submission_count,  # type: ignore[arg-type]
        jaa11_certified=jaa11_certified,  # type: ignore[arg-type]
    )
    assert state.status == "withheld"
    assert state.remaining_canaries == 0
    assert state.may_submit is False


def test_tampered_authority_file_hash_is_rejected() -> None:
    with pytest.raises(ValueError, match="differs from the frozen scope"):
        replace(
            FROZEN_LIVE_CANARY_AUTHORITY,
            authority_file_sha256="0" * 64,
        )

    assert AUTHORITY_FILE_SHA256 != "0" * 64


def test_public_acquisition_cannot_be_enabled_without_new_authority() -> None:
    with pytest.raises(ValueError, match="differs from the frozen scope"):
        replace(
            FROZEN_LIVE_CANARY_AUTHORITY,
            public_multi_vacancy_acquisition_authorized=True,
        )
    with pytest.raises(ValueError, match="new operator referral"):
        _selection(public_acquisition_used=True)


def test_unaccepted_authority_record_cannot_compile_selection() -> None:
    shell = object.__new__(LiveCanaryOperatorAuthority)
    for field, value in vars(FROZEN_LIVE_CANARY_AUTHORITY).items():
        object.__setattr__(shell, field, value)
    object.__setattr__(shell, "relative_path", "different-authority.md")
    with pytest.raises(ValueError, match="frozen operator authority"):
        compile_canary_selection(
            shell,
            **{
                key: value
                for key, value in vars(_selection()).items()
                if key not in {
                    "authority_record_sha256",
                    "contract_sha256",
                    "operational_release",
                    "external_action_capability",
                    "schema_version",
                }
            },
        )


def test_selection_contract_cannot_open_operational_release() -> None:
    accepted = _selection()
    with pytest.raises(ValueError, match="cannot grant operational release"):
        replace(accepted, operational_release="granted")
    with pytest.raises(ValueError, match="cannot grant operational release"):
        replace(accepted, external_action_capability=True)
