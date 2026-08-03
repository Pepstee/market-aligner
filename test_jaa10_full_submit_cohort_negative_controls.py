"""Fail-closed controls for JAA-10 runtime receipts and cohort admission."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation.shadow_full_submit_cohort import compile_full_submit_cohort
from career_automation.shadow_mutation_runtime import (
    ADDITIONAL_RUNTIME_TWINS,
    RUNTIME_CONTROL_IDS,
    RuntimeControlReceipt,
    mutation_observations_from_runtime,
    observe_fail_closed_control,
    read_immutable_runtime_receipt,
)
from test_jaa10_full_submit_cohort import (
    REVISION,
    SOURCE_CONTENT,
    TREE,
    _receipts,
    _state,
)


def _blocked() -> None:
    raise RuntimeError("runtime control blocked")


def test_normal_return_cannot_be_laundered_into_fail_closed_receipt() -> None:
    with pytest.raises(ValueError, match="returned normally"):
        observe_fail_closed_control(
            control_id="stub_executor",
            executable_identity="runtime-twin:stub_executor",
            operation=lambda: None,
            state_probe=_state,
            source_git_revision=REVISION,
            source_tree=TREE,
            source_content_revision=SOURCE_CONTENT,
        )


@pytest.mark.parametrize("changed_field", ["receipt_count", "submit_click_count"])
def test_runtime_effect_prevents_fail_closed_receipt(changed_field: str) -> None:
    calls = 0

    def probe() -> dict[str, object]:
        nonlocal calls
        value = _state()
        if calls:
            value[changed_field] = 1
        calls += 1
        return value

    with pytest.raises(ValueError, match="created a receipt|performed a submit click"):
        observe_fail_closed_control(
            control_id="fabricated_receipt",
            executable_identity="runtime-twin:fabricated_receipt",
            operation=_blocked,
            state_probe=probe,
            source_git_revision=REVISION,
            source_tree=TREE,
            source_content_revision=SOURCE_CONTENT,
        )


def test_legacy_mutation_inventory_requires_runtime_receipts_in_exact_order() -> None:
    receipts = _receipts()
    required = tuple(row for row in receipts if row.control_id not in ADDITIONAL_RUNTIME_TWINS)
    mutation_observations_from_runtime(required)
    with pytest.raises(ValueError, match="incomplete or unordered"):
        mutation_observations_from_runtime(required[:-1])
    with pytest.raises(ValueError, match="incomplete or unordered"):
        mutation_observations_from_runtime(tuple(reversed(required)))


def test_cross_source_receipt_and_caller_selected_state_are_rejected() -> None:
    receipt = _receipts()[0]
    with pytest.raises(ValueError, match="source revision"):
        replace(receipt, source_git_revision="not-a-revision")
    with pytest.raises(ValueError, match="unsupported field inventory"):
        RuntimeControlReceipt(
            control_id="caller_state",
            executable_identity="runtime-twin:caller_state",
            exception_type="builtins.ValueError",
            exception_message_sha256="4" * 64,
            before_state={**_state(), "caller_verdict": True},
            after_state=_state(),
            result_sha256="5" * 64,
            source_git_revision=REVISION,
            source_tree=TREE,
            source_content_revision=SOURCE_CONTENT,
        )


def test_immutable_reader_rejects_mutable_symlink_and_special_file(
    tmp_path: Path,
) -> None:
    mutable = tmp_path / "mutable.json"
    mutable.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="immutable"):
        read_immutable_runtime_receipt(mutable)
    mutable.chmod(0o444)
    symlink = tmp_path / "receipt-link.json"
    symlink.symlink_to(mutable)
    with pytest.raises(OSError):
        read_immutable_runtime_receipt(symlink)
    fifo = tmp_path / "receipt.fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular file"):
        read_immutable_runtime_receipt(fifo)


def test_closed_runtime_inventory_names_every_prior_ruling_twin() -> None:
    assert tuple(control for control in RUNTIME_CONTROL_IDS if control in ADDITIONAL_RUNTIME_TWINS) == ADDITIONAL_RUNTIME_TWINS
    assert {
        "stub_executor",
        "fabricated_receipt",
        "missing_receipt",
        "zero_denominator",
        "omitted_unit",
        "cross_cohort_substitution",
        "observed_time_tamper",
        "content_hash_tamper",
        "symlink_evidence",
        "special_file_evidence",
        "caller_verdict",
        "caller_target",
        "caller_count",
        "caller_state",
    } == set(ADDITIONAL_RUNTIME_TWINS)
    assert "release_token_tamper" in RUNTIME_CONTROL_IDS


def test_cohort_compiler_refuses_omitted_units_before_caller_counts_apply() -> None:
    with pytest.raises(ValueError, match="exactly two typed executions"):
        compile_full_submit_cohort(
            (),
            _receipts(),
            source_git_revision=REVISION,
            source_tree=TREE,
            source_content_revision=SOURCE_CONTENT,
        )
    with pytest.raises(TypeError):
        compile_full_submit_cohort(  # type: ignore[call-arg]
            (),
            _receipts(),
            source_git_revision=REVISION,
            source_tree=TREE,
            source_content_revision=SOURCE_CONTENT,
            metrics_evaluated=True,
        )
