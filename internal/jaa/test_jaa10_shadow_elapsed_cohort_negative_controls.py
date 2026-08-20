"""Adversarial controls for the bounded same-boot cohort rehearsal."""

import ast
import copy
import inspect
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import career_automation.shadow_elapsed_cohort as cohort_module
from career_automation.shadow_certification import (
    normalized_submit_event_sha256,
)
from career_automation.shadow_elapsed_cohort import (
    CLAIM,
    CONTAMINATION_POLICY,
    EVIDENCE_CLASS,
    FORBIDDEN_EVIDENCE_CLASSES,
    LIVE_EXECUTION,
    MAX_COUNTER_NS,
    MINIMUM_ELAPSED_NS,
    ElapsedCohortCloseReceipt,
    ElapsedCohortIntegrityError,
    ElapsedCohortOpenReceipt,
    ElapsedCohortStateError,
    ElapsedCohortTimeWitnessError,
    _close_with_witness,
    capture_elapsed_time_witness,
    close_elapsed_cohort,
    open_elapsed_cohort,
    verify_elapsed_cohort,
)
from career_automation.shadow_fixture_measures import (
    compile_fixture_measures_report,
)
from career_automation.shadow_observation_ledger import (
    ObservationLedgerIdentity,
    ObservationLedgerReceipt,
)
from test_jaa10_independent_acceptance import _observation
from test_jaa10_shadow_elapsed_cohort import (
    SOURCE_CONTENT,
    SOURCE_REVISION,
    SOURCE_TREE,
    _close_fixture_cohort,
    _open_fixture_cohort,
    _witness,
)


def _tampered(receipt, attribute, content):
    changed = copy.copy(receipt)
    object.__setattr__(changed, attribute, content)
    return changed


def _forged_ledger_receipt(receipt, *, document=None, receipt_sha256=None):
    forged = object.__new__(ObservationLedgerReceipt)
    object.__setattr__(
        forged,
        "document",
        receipt.document if document is None else document,
    )
    object.__setattr__(
        forged,
        "receipt_sha256",
        receipt.receipt_sha256
        if receipt_sha256 is None
        else receipt_sha256,
    )
    return forged


def _ready_to_close(tmp_path):
    database, ledger, first, first_report, opened = _open_fixture_cohort(
        tmp_path
    )
    second = _observation(
        "elapsed-negative-second",
        datetime(2024, 1, 2, tzinfo=timezone.utc),
    )
    ledger.record_observation(ledger.begin_session(), second)
    second_report = compile_fixture_measures_report(
        ledger,
        ledger.identity,
        (first, second),
    )
    return (
        database,
        ledger,
        first,
        second,
        first_report,
        second_report,
        opened,
    )


def _close(
    opened,
    ledger,
    second,
    second_report,
    witness,
    *,
    revision=SOURCE_REVISION,
    tree=SOURCE_TREE,
    content=SOURCE_CONTENT,
):
    return _close_with_witness(
        opened,
        ledger,
        ledger.identity,
        second,
        second_report,
        revision,
        tree,
        content,
        witness,
    )


def test_apparent_source_separation_cannot_replace_boottime(
    tmp_path,
) -> None:
    (
        _,
        ledger,
        _,
        second,
        _,
        second_report,
        opened,
    ) = _ready_to_close(tmp_path)
    insufficient = _witness(
        opened.first_witness.clock_boottime_ns
        + MINIMUM_ELAPSED_NS
        - 1,
        wall_time=datetime(2035, 1, 1, tzinfo=timezone.utc),
    )

    with pytest.raises(ElapsedCohortTimeWitnessError):
        _close(opened, ledger, second, second_report, insufficient)


@pytest.mark.parametrize(
    "second_wall",
    (
        datetime(1999, 1, 1, tzinfo=timezone.utc),
        datetime(2040, 1, 1, tzinfo=timezone.utc),
    ),
)
def test_wall_clock_jumps_are_informational_only(
    tmp_path,
    second_wall,
) -> None:
    (
        _,
        ledger,
        _,
        second,
        _,
        second_report,
        opened,
    ) = _ready_to_close(tmp_path)
    sufficient = _witness(
        opened.first_witness.clock_boottime_ns + MINIMUM_ELAPSED_NS,
        monotonic_ns=(
            opened.first_witness.monotonic_ns + MINIMUM_ELAPSED_NS
        ),
        wall_time=second_wall,
    )

    closed = _close(
        opened,
        ledger,
        second,
        second_report,
        sufficient,
    )
    assert closed.elapsed_boottime_ns == MINIMUM_ELAPSED_NS


def test_changed_boot_identity_invalidates_then_valid_close_can_restart(
    tmp_path,
) -> None:
    (
        _,
        ledger,
        _,
        second,
        _,
        second_report,
        opened,
    ) = _ready_to_close(tmp_path)
    changed_boot = _witness(
        opened.first_witness.clock_boottime_ns + MINIMUM_ELAPSED_NS,
        boot_id="d" * 64,
    )
    with pytest.raises(ElapsedCohortTimeWitnessError):
        _close(opened, ledger, second, second_report, changed_boot)

    valid = _witness(
        opened.first_witness.clock_boottime_ns + MINIMUM_ELAPSED_NS,
        monotonic_ns=(
            opened.first_witness.monotonic_ns + MINIMUM_ELAPSED_NS
        ),
    )
    assert _close(
        opened,
        ledger,
        second,
        second_report,
        valid,
    ).same_boot is True


@pytest.mark.parametrize("delta", (0, -1))
def test_duplicate_or_regressed_boottime_is_rejected(
    tmp_path,
    delta,
) -> None:
    (
        _,
        ledger,
        _,
        second,
        _,
        second_report,
        opened,
    ) = _ready_to_close(tmp_path)
    witness = _witness(
        opened.first_witness.clock_boottime_ns + delta,
        monotonic_ns=opened.first_witness.monotonic_ns + 1,
    )
    with pytest.raises(ElapsedCohortTimeWitnessError):
        _close(opened, ledger, second, second_report, witness)


def test_counter_overflow_and_same_process_regression_are_rejected(
    tmp_path,
) -> None:
    with pytest.raises(ValueError, match="invalid"):
        _witness(MAX_COUNTER_NS + 1)

    (
        _,
        ledger,
        _,
        second,
        _,
        second_report,
        opened,
    ) = _ready_to_close(tmp_path)
    regressed_monotonic = _witness(
        opened.first_witness.clock_boottime_ns + MINIMUM_ELAPSED_NS,
        monotonic_ns=opened.first_witness.monotonic_ns,
    )
    with pytest.raises(
        ElapsedCohortTimeWitnessError,
        match="monotonic",
    ):
        _close(
            opened,
            ledger,
            second,
            second_report,
            regressed_monotonic,
        )


def test_close_requires_exactly_the_next_current_observation(
    tmp_path,
) -> None:
    (
        _,
        ledger,
        first,
        second,
        first_report,
        second_report,
        opened,
    ) = _ready_to_close(tmp_path)
    sufficient = _witness(
        opened.first_witness.clock_boottime_ns + MINIMUM_ELAPSED_NS,
        monotonic_ns=(
            opened.first_witness.monotonic_ns + MINIMUM_ELAPSED_NS
        ),
    )
    with pytest.raises((ElapsedCohortIntegrityError, ElapsedCohortStateError)):
        _close(opened, ledger, first, first_report, sufficient)
    with pytest.raises(ElapsedCohortIntegrityError):
        _close(opened, ledger, first, second_report, sufficient)

    third = _observation(
        "elapsed-negative-third",
        datetime(2024, 1, 3, tzinfo=timezone.utc),
    )
    ledger.record_observation(ledger.begin_session(), third)
    third_report = compile_fixture_measures_report(
        ledger,
        ledger.identity,
        (first, second, third),
    )
    with pytest.raises(ElapsedCohortStateError):
        _close(opened, ledger, third, third_report, sufficient)


def test_stale_phase_b_report_and_open_head_are_rejected(tmp_path) -> None:
    (
        _,
        ledger,
        _,
        _,
        first_report,
        _,
        opened,
    ) = _ready_to_close(tmp_path)

    with pytest.raises(ElapsedCohortStateError):
        opened.verify_current(ledger, first_report)


@pytest.mark.parametrize(
    ("revision", "tree", "content"),
    (
        ("4" * 40, SOURCE_TREE, SOURCE_CONTENT),
        (SOURCE_REVISION, "5" * 40, SOURCE_CONTENT),
        (SOURCE_REVISION, SOURCE_TREE, "sha256:" + ("6" * 64)),
    ),
)
def test_changed_source_triple_is_rejected(
    tmp_path,
    revision,
    tree,
    content,
) -> None:
    (
        _,
        ledger,
        _,
        second,
        _,
        second_report,
        opened,
    ) = _ready_to_close(tmp_path)
    witness = _witness(
        opened.first_witness.clock_boottime_ns + MINIMUM_ELAPSED_NS,
        monotonic_ns=(
            opened.first_witness.monotonic_ns + MINIMUM_ELAPSED_NS
        ),
    )
    with pytest.raises(ElapsedCohortIntegrityError, match="source"):
        _close(
            opened,
            ledger,
            second,
            second_report,
            witness,
            revision=revision,
            tree=tree,
            content=content,
        )


def test_wrong_ledger_identity_and_fabricated_receipt_are_rejected(
    tmp_path,
) -> None:
    _, ledger, _, first_report, opened = _open_fixture_cohort(tmp_path)
    wrong_identity = ObservationLedgerIdentity(
        ledger.identity.contract_sha256,
        "f" * 64,
        ledger.identity.genesis_receipt_sha256,
        ledger.identity.fixture_policy_sha256,
    )
    first = first_report.observations[-1]
    with pytest.raises(ElapsedCohortIntegrityError):
        open_elapsed_cohort(
            ledger,
            wrong_identity,
            first,
            first_report,
            SOURCE_REVISION,
            SOURCE_TREE,
            SOURCE_CONTENT,
        )

    forged_document = dict(opened.first_ledger_receipt.document)
    forged_document["observation_id"] = "fabricated"
    forged = _forged_ledger_receipt(
        opened.first_ledger_receipt,
        document=forged_document,
    )
    with pytest.raises(ElapsedCohortIntegrityError):
        _tampered(opened, "first_ledger_receipt", forged).verify()


def test_self_consistent_noncanonical_observation_is_rejected(
    tmp_path,
) -> None:
    _, ledger, _, first_report, _ = _open_fixture_cohort(tmp_path)
    observation = first_report.observations[-1]
    alternative_workflow = "f" * 64
    alternative = replace(
        observation,
        workflow_sha256=alternative_workflow,
        normalized_submit_event_sha256=normalized_submit_event_sha256(
            workflow_sha256=alternative_workflow,
            receipt_id=observation.receipt_id,
            receipt_payload_sha256=observation.receipt_payload_sha256,
            screenshot_sha256=observation.screenshot_sha256,
            field_map_sha256=observation.field_map_sha256,
        ),
    )
    with pytest.raises(ElapsedCohortIntegrityError):
        open_elapsed_cohort(
            ledger,
            ledger.identity,
            alternative,
            first_report,
            SOURCE_REVISION,
            SOURCE_TREE,
            SOURCE_CONTENT,
        )

def test_double_close_is_rejected_in_the_active_process(tmp_path) -> None:
    (
        _,
        ledger,
        _,
        second,
        _,
        second_report,
        opened,
    ) = _ready_to_close(tmp_path)
    witness = _witness(
        opened.first_witness.clock_boottime_ns + MINIMUM_ELAPSED_NS,
        monotonic_ns=(
            opened.first_witness.monotonic_ns + MINIMUM_ELAPSED_NS
        ),
    )
    closed = _close(opened, ledger, second, second_report, witness)
    verify_elapsed_cohort(opened, closed)
    with pytest.raises(ElapsedCohortStateError, match="already CLOSED"):
        _close(opened, ledger, second, second_report, witness)


def test_receipt_hash_claim_and_limitation_tamper_are_rejected(
    tmp_path,
    monkeypatch,
) -> None:
    _, _, _, _, opened, closed = _close_fixture_cohort(tmp_path)
    with pytest.raises(ElapsedCohortIntegrityError):
        _tampered(closed, "receipt_sha256", "f" * 64).verify()
    with pytest.raises(ElapsedCohortIntegrityError):
        _tampered(closed, "claim", "live_time_collected").verify()
    with pytest.raises(ElapsedCohortIntegrityError):
        _tampered(opened, "receipt_sha256", "f" * 64).verify()

    monkeypatch.setattr(
        cohort_module,
        "CONTAMINATION_POLICY",
        "tuning_allowed",
    )
    with pytest.raises(ElapsedCohortIntegrityError):
        closed.verify()
    monkeypatch.setattr(
        cohort_module,
        "CONTAMINATION_POLICY",
        CONTAMINATION_POLICY,
    )
    monkeypatch.setattr(
        cohort_module,
        "KERNEL_TIME_LIMIT",
        "stronger_claim",
    )
    with pytest.raises(ElapsedCohortIntegrityError):
        closed.verify()


def test_evidence_classes_and_withholding_are_not_caller_controlled(
    tmp_path,
    monkeypatch,
) -> None:
    _, _, _, _, opened, closed = _close_fixture_cohort(tmp_path)
    assert EVIDENCE_CLASS not in FORBIDDEN_EVIDENCE_CLASSES
    assert opened.document()["evidence_class"] == EVIDENCE_CLASS
    assert closed.document()["evidence_class"] == EVIDENCE_CLASS
    assert closed.document()["live_time_separated_execution"] == (
        LIVE_EXECUTION
    )
    assert all(
        forbidden not in closed.document().values()
        for forbidden in FORBIDDEN_EVIDENCE_CLASSES
    )

    monkeypatch.setattr(
        cohort_module,
        "EVIDENCE_CLASS",
        FORBIDDEN_EVIDENCE_CLASSES[0],
    )
    with pytest.raises(ElapsedCohortIntegrityError):
        opened.verify()


def test_production_capture_fails_closed_without_kernel_sources(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cohort_module,
        "BOOT_ID_PATH",
        Path("/definitely/missing/boot-id"),
    )
    with pytest.raises(ElapsedCohortTimeWitnessError):
        capture_elapsed_time_witness()

    monkeypatch.setattr(cohort_module, "BOOT_ID_PATH", Path("/proc/version"))
    with pytest.raises(ElapsedCohortTimeWitnessError):
        capture_elapsed_time_witness()


def test_public_api_and_module_capabilities_are_closed() -> None:
    with pytest.raises(TypeError, match="verified opener"):
        ElapsedCohortOpenReceipt()
    with pytest.raises(TypeError, match="verified closer"):
        ElapsedCohortCloseReceipt()

    forbidden_parameters = {
        "certification",
        "evidence_class",
        "interval",
        "metric",
        "objective",
        "pass_status",
        "verdict",
    }
    for function in (
        open_elapsed_cohort,
        close_elapsed_cohort,
        verify_elapsed_cohort,
        capture_elapsed_time_witness,
    ):
        assert not (
            set(inspect.signature(function).parameters)
            & forbidden_parameters
        )
    assert inspect.signature(capture_elapsed_time_witness).parameters == {}

    source = Path(cohort_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imported_modules.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert imported_modules <= {
        "career_automation.shadow_certification",
        "career_automation.shadow_fixture_measures",
        "career_automation.shadow_observation_ledger",
        "dataclasses",
        "datetime",
        "hashlib",
        "json",
        "os",
        "pathlib",
        "re",
        "time",
        "types",
        "typing",
    }
    for forbidden_module in (
        "playwright",
        "socket",
        "urllib",
        "http",
        "requests",
        "subprocess",
        "browser_executor",
        "browser_workflows",
        "release_gate",
        "credential",
    ):
        assert forbidden_module not in imported_modules
    assert str(cohort_module.BOOT_ID_PATH) == (
        "/proc/sys/kernel/random/boot_id"
    )
    assert cohort_module.CLAIM == CLAIM
