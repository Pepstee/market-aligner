"""Positive controls for the bounded JAA-11 operator-authority intake."""

from __future__ import annotations

import hashlib

from career_automation.live_canary_authority import (
    AUTHORITY_FILE_SHA256,
    AUTHORITY_RELATIVE_PATH,
    FAIL_CLOSED_TRIGGERS,
    FORBIDDEN_RANKS,
    FROZEN_LIVE_CANARY_AUTHORITY,
    compile_canary_selection,
    evaluate_live_canary_authority,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _selection(**overrides):
    fields = {
        "ranked_snapshot_sha256": _hash("complete-ranked-snapshot"),
        "ranking_algorithm": "deterministic-opportunity-ranking",
        "ranking_version": "2026-07-31.v1",
        "snapshot_entry_count": 25,
        "selected_rank": 21,
        "vacancy_identity": "employer:vacancy:123",
        "vacancy_url": "https://jobs.example.test/vacancies/123",
        "vacancy_retrieved_at": "2026-07-31T12:00:00+01:00",
        "vacancy_content_sha256": _hash("vacancy-content"),
        "selected_entry_sha256": _hash("ranked-entry-21"),
        "duplicate_application_found": False,
        "eligibility_gate_passed": True,
        "truth_gate_passed": True,
        "vacancy_open": True,
        "official_route": True,
        "selected_only_for_submission_ease": False,
        "account_creation_required": False,
        "login_required": False,
        "mfa_required": False,
        "captcha_required": False,
        "payment_required": False,
        "missing_approved_fact": False,
        "optional_marketing_consent": "declined",
        "public_acquisition_used": False,
    }
    fields.update(overrides)
    return compile_canary_selection(
        FROZEN_LIVE_CANARY_AUTHORITY,
        **fields,
    )


def test_frozen_authority_binds_exact_document_and_narrow_scope() -> None:
    authority = FROZEN_LIVE_CANARY_AUTHORITY
    assert authority.path_base == "software_factory_root"
    assert authority.relative_path == AUTHORITY_RELATIVE_PATH
    assert authority.authority_file_sha256 == AUTHORITY_FILE_SHA256
    assert authority.max_canaries == 1
    assert authority.forbidden_ranks == FORBIDDEN_RANKS
    assert authority.minimum_selected_rank == 21
    assert authority.optional_marketing_consent == "declined"
    assert authority.fail_closed_triggers == FAIL_CLOSED_TRIGGERS
    assert authority.public_multi_vacancy_acquisition_authorized is False
    assert authority.public_acquisition_referral_required is True
    assert authority.expires_on_first_submission is True
    assert authority.expires_on_jaa11_certification is True
    assert authority.operational_release == "withheld"
    assert len(authority.record_sha256) == 64


def test_rank_21_selection_binds_complete_caller_supplied_evidence() -> None:
    selection = _selection()
    assert selection.snapshot_entry_count == 25
    assert selection.selected_rank == 21
    assert selection.authority_record_sha256 == (
        FROZEN_LIVE_CANARY_AUTHORITY.record_sha256
    )
    assert selection.contract_sha256 == _hash_document_without_hash(selection)
    assert selection.operational_release == "withheld"
    assert selection.external_action_capability is False


def _hash_document_without_hash(selection) -> str:
    import json

    document = selection.document(include_hash=False)
    encoded = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def test_authority_state_separates_scope_from_operational_release() -> None:
    state = evaluate_live_canary_authority(
        FROZEN_LIVE_CANARY_AUTHORITY,
        submission_count=0,
        jaa11_certified=False,
    )
    assert state.status == "permitted"
    assert state.remaining_canaries == 1
    assert state.reasons == (
        "operator_scope_available_release_still_withheld",
    )
    assert state.operational_release == "withheld"
    assert state.may_submit is False
