"""Positive controls for the JAA-11 ranked-snapshot fixture dry run."""

from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from career_automation.live_canary_authority import (
    FROZEN_LIVE_CANARY_AUTHORITY,
)
from career_automation.live_canary_fixture_dry_run import (
    SNAPSHOT_SCHEMA,
    compile_live_canary_fixture_dry_run,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _snapshot(count: int = 25) -> dict[str, object]:
    return {
        "schema_version": SNAPSHOT_SCHEMA,
        "ranking_algorithm": "fixture-opportunity-ranking",
        "ranking_version": "2026-07-31.fixture.v1",
        "snapshot_taken_at": "2026-07-31T12:00:00+01:00",
        "entries": [
            {
                "rank": rank,
                "vacancy_identity": f"fixture:vacancy:{rank}",
                "vacancy_url": (
                    f"https://jobs.example.test/vacancies/{rank}"
                ),
                "vacancy_content_sha256": _hash(f"vacancy-{rank}"),
                "vacancy_retrieved_at": (
                    "2026-07-31T11:00:00+01:00"
                ),
            }
            for rank in range(1, count + 1)
        ],
    }


def _evidence(selected_rank: int = 23) -> dict[str, object]:
    return {
        "selected_rank": selected_rank,
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


def _dry_run(
    snapshot: dict[str, object] | None = None,
    evidence: dict[str, object] | None = None,
):
    return compile_live_canary_fixture_dry_run(
        snapshot or _snapshot(),
        evidence or _evidence(),
        submission_count=0,
        jaa11_certified=False,
    )


def test_happy_path_computes_and_binds_all_hashes() -> None:
    result = _dry_run()
    assert result.selected_entry.rank == 23
    assert result.selected_entry.vacancy_identity == "fixture:vacancy:23"
    assert result.ranked_snapshot_sha256 == result.snapshot.snapshot_sha256
    assert result.selection_contract.ranked_snapshot_sha256 == (
        result.ranked_snapshot_sha256
    )
    assert result.selection_contract.selected_entry_sha256 == (
        result.selected_entry_sha256
    )
    assert result.selection_contract.authority_record_sha256 == (
        FROZEN_LIVE_CANARY_AUTHORITY.record_sha256
    )
    assert len(result.dry_run_sha256) == 64


def test_rank_21_and_last_rank_boundaries_are_supported() -> None:
    rank_21 = _dry_run(_snapshot(21), _evidence(21))
    last_rank = _dry_run(_snapshot(25), _evidence(25))
    assert rank_21.selected_entry.rank == 21
    assert last_rank.selected_entry.rank == 25


def test_identical_inputs_are_byte_deterministic() -> None:
    first = _dry_run()
    second = _dry_run()
    assert first.document() == second.document()
    assert first.ranked_snapshot_sha256 == second.ranked_snapshot_sha256
    assert first.selected_entry_sha256 == second.selected_entry_sha256
    assert first.selection_contract.contract_sha256 == (
        second.selection_contract.contract_sha256
    )
    assert first.dry_run_sha256 == second.dry_run_sha256


def test_nonselected_mutation_changes_only_snapshot_level_bindings() -> None:
    baseline = _dry_run()
    changed_snapshot = _snapshot()
    entries = changed_snapshot["entries"]
    assert isinstance(entries, list)
    entries[0]["vacancy_content_sha256"] = _hash("changed-first-entry")
    changed = _dry_run(changed_snapshot)
    assert changed.ranked_snapshot_sha256 != baseline.ranked_snapshot_sha256
    assert changed.selected_entry_sha256 == baseline.selected_entry_sha256
    assert changed.selection_contract.contract_sha256 != (
        baseline.selection_contract.contract_sha256
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("vacancy_identity", "fixture:vacancy:changed"),
        (
            "vacancy_url",
            "https://jobs.example.test/vacancies/changed",
        ),
        ("vacancy_content_sha256", _hash("changed-content")),
        ("vacancy_retrieved_at", "2026-07-31T10:59:59+01:00"),
    ),
)
def test_each_nonselected_entry_identity_field_changes_snapshot_hash(
    field: str,
    value: object,
) -> None:
    baseline = _dry_run()
    changed_snapshot = deepcopy(_snapshot())
    entries = changed_snapshot["entries"]
    assert isinstance(entries, list)
    entries[0][field] = value
    changed = _dry_run(changed_snapshot)
    assert changed.ranked_snapshot_sha256 != baseline.ranked_snapshot_sha256
    assert changed.selected_entry_sha256 == baseline.selected_entry_sha256


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("ranking_algorithm", "changed-ranking"),
        ("ranking_version", "changed-version"),
        ("snapshot_taken_at", "2026-07-31T12:00:01+01:00"),
    ),
)
def test_each_snapshot_metadata_field_changes_snapshot_hash(
    field: str,
    value: str,
) -> None:
    baseline = _dry_run()
    changed_snapshot = _snapshot()
    changed_snapshot[field] = value
    changed = _dry_run(changed_snapshot)
    assert changed.ranked_snapshot_sha256 != baseline.ranked_snapshot_sha256


def test_selected_mutation_changes_snapshot_and_selected_bindings() -> None:
    baseline = _dry_run()
    changed_snapshot = _snapshot()
    entries = changed_snapshot["entries"]
    assert isinstance(entries, list)
    entries[22]["vacancy_content_sha256"] = _hash("changed-selected-entry")
    changed = _dry_run(changed_snapshot)
    assert changed.ranked_snapshot_sha256 != baseline.ranked_snapshot_sha256
    assert changed.selected_entry_sha256 != baseline.selected_entry_sha256


def test_result_disclosures_are_fixture_only_and_nonoperational() -> None:
    result = _dry_run()
    assert result.snapshot_source == "caller_supplied_fixture"
    assert result.snapshot_is_live is False
    assert result.snapshot_is_current is False
    assert result.selected_vacancy_status == (
        "fixture_only_not_selected_for_external_use"
    )
    assert result.operational_release == "withheld"
    assert result.may_submit is False
    assert result.external_action_capability is False
    assert result.certifies_slice is False
    assert result.receipt_written is False
    assert result.real_applications == 0
