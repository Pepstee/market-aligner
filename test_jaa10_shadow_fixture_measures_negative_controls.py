"""Adversarial controls for JAA-10 descriptive fixture measures."""

import ast
import copy
import inspect
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import career_automation.shadow_fixture_measures as measures_module
from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    HARD_QUALITY_TARGETS,
    MUTATION_TEST_NODES,
    normalized_submit_event_sha256,
)
from career_automation.shadow_fixture_measures import (
    FixtureMeasuresIntegrityError,
    FixtureMeasuresReport,
    FixtureMeasuresStaleSnapshotError,
    compile_fixture_measures_report,
)
from career_automation.shadow_observation_ledger import (
    ObservationLedgerIdentity,
    ObservationLedgerIntegrityError,
    ObservationLedgerReceipt,
    ShadowObservationLedger,
)
from test_jaa10_independent_acceptance import _observation


def _ledger_with_observations(tmp_path, *, far_apart: bool = False):
    ledger = ShadowObservationLedger.initialize(
        tmp_path / "shadow-observations.sqlite3",
        contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
    )
    first_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
    delta = timedelta(days=30) if far_apart else timedelta(minutes=1)
    observations = (
        _observation("negative-first", first_time),
        _observation("negative-second", first_time + delta),
    )
    for observation in observations:
        ledger.record_observation(
            ledger.begin_session(),
            observation,
        )
    return ledger, observations


def _report(tmp_path):
    ledger, observations = _ledger_with_observations(tmp_path)
    return (
        ledger,
        observations,
        compile_fixture_measures_report(
            ledger,
            ledger.identity,
            observations,
        ),
    )


def _tampered(report, attribute, content):
    changed = copy.copy(report)
    object.__setattr__(changed, attribute, content)
    return changed


def _forged_receipt(receipt, *, receipt_sha256=None, document=None):
    forged = object.__new__(ObservationLedgerReceipt)
    object.__setattr__(
        forged,
        "receipt_sha256",
        receipt.receipt_sha256
        if receipt_sha256 is None
        else receipt_sha256,
    )
    object.__setattr__(
        forged,
        "document",
        receipt.document if document is None else document,
    )
    return forged


def test_compiler_rejects_nonledger_wrong_identity_and_corruption(
    tmp_path,
) -> None:
    ledger, observations = _ledger_with_observations(tmp_path)
    wrong_identity = ObservationLedgerIdentity(
        ledger.identity.contract_sha256,
        "f" * 64,
        ledger.identity.genesis_receipt_sha256,
        ledger.identity.fixture_policy_sha256,
    )

    with pytest.raises(TypeError, match="typed observation ledger"):
        compile_fixture_measures_report(
            object(),  # type: ignore[arg-type]
            ledger.identity,
            observations,
        )
    with pytest.raises(FixtureMeasuresIntegrityError, match="identity"):
        compile_fixture_measures_report(
            ledger,
            wrong_identity,
            observations,
        )

    connection = sqlite3.connect(ledger.database_path)
    try:
        connection.execute("DROP TRIGGER ledger_receipt_no_update")
        connection.execute(
            "UPDATE ledger_receipt SET content_json = ? WHERE sequence = 1",
            ("{}",),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ObservationLedgerIntegrityError):
        compile_fixture_measures_report(
            ledger,
            ledger.identity,
            observations,
        )


def test_compiler_rejects_empty_and_dangling_session_ledgers(tmp_path) -> None:
    with pytest.raises(TypeError, match="verified compiler"):
        FixtureMeasuresReport()

    empty = ShadowObservationLedger.initialize(
        tmp_path / "empty.sqlite3",
        contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
    )
    with pytest.raises(ValueError, match="recorded observation"):
        compile_fixture_measures_report(empty, empty.identity, ())

    dangling = ShadowObservationLedger.initialize(
        tmp_path / "dangling.sqlite3",
        contract_sha256=FROZEN_SHADOW_CONTRACT.contract_sha256,
    )
    observation = _observation(
        "dangling",
        datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    dangling.record_observation(dangling.begin_session(), observation)
    dangling.begin_session()
    with pytest.raises(FixtureMeasuresIntegrityError, match="session"):
        compile_fixture_measures_report(
            dangling,
            dangling.identity,
            (observation,),
        )


def test_compiler_rejects_noncanonical_observation(tmp_path) -> None:
    ledger, observations = _ledger_with_observations(tmp_path)
    original = observations[0]
    alternative_workflow = "f" * 64
    alternative = replace(
        original,
        workflow_sha256=alternative_workflow,
        normalized_submit_event_sha256=normalized_submit_event_sha256(
            workflow_sha256=alternative_workflow,
            receipt_id=original.receipt_id,
            receipt_payload_sha256=original.receipt_payload_sha256,
            screenshot_sha256=original.screenshot_sha256,
            field_map_sha256=original.field_map_sha256,
        ),
    )

    with pytest.raises(
        FixtureMeasuresIntegrityError,
        match="canonical frozen contract",
    ):
        compile_fixture_measures_report(
            ledger,
            ledger.identity,
            (alternative, observations[1]),
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "extra",
        "reordered",
        "duplicated",
        "non_typed",
        "changed_bytes",
        "changed_id",
        "changed_source_time",
    ),
)
def test_compiler_rejects_unbound_observation_inventories(
    tmp_path,
    mutation,
) -> None:
    ledger, observations = _ledger_with_observations(tmp_path)
    changed = observations
    if mutation == "missing":
        changed = observations[:1]
    elif mutation == "extra":
        changed = (
            *observations,
            _observation(
                "negative-extra",
                datetime(2024, 1, 2, tzinfo=timezone.utc),
            ),
        )
    elif mutation == "reordered":
        changed = tuple(reversed(observations))
    elif mutation == "duplicated":
        changed = (observations[0], observations[0])
    elif mutation == "non_typed":
        changed = (observations[0], object())  # type: ignore[assignment]
    elif mutation == "changed_bytes":
        changed = (
            replace(
                observations[0],
                database_bytes=observations[0].database_bytes + 1,
            ),
            observations[1],
        )
    elif mutation == "changed_id":
        changed = (
            replace(observations[0], observation_id="changed-id"),
            observations[1],
        )
    elif mutation == "changed_source_time":
        changed = (
            replace(
                observations[0],
                observed_at=datetime(
                    2035,
                    1,
                    1,
                    tzinfo=timezone.utc,
                ).isoformat(),
            ),
            observations[1],
        )

    with pytest.raises((FixtureMeasuresIntegrityError, TypeError)):
        compile_fixture_measures_report(
            ledger,
            ledger.identity,
            changed,
        )


def test_report_rejects_aggregate_policy_and_limitation_tamper(
    tmp_path,
) -> None:
    _, _, report = _report(tmp_path)
    measures = report.document()["descriptive_fixture_measures"]
    measures["observation_count"] = 99
    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(
            report,
            "descriptive_fixture_measures",
            measures,
        ).verify()

    policy = dict(report.policy)
    policy["metrics_evaluated"] = True
    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(report, "policy", policy).verify()

    for key in (
        "span_meaning",
        "clock_authentication",
        "monotonic_witness_scope",
        "filesystem_privileged_writer_limit",
    ):
        changed = report.document()["descriptive_fixture_measures"]
        changed["host_recording"][key] = "changed"
        with pytest.raises(FixtureMeasuresIntegrityError):
            _tampered(
                report,
                "descriptive_fixture_measures",
                changed,
            ).verify()


def test_report_rejects_receipt_document_hash_and_head_tamper(
    tmp_path,
) -> None:
    _, _, report = _report(tmp_path)
    first = report.observation_receipts[0]
    document = dict(first.document)
    document["observation_id"] = "forged"

    changed_receipts = (
        _forged_receipt(first, document=document),
        report.observation_receipts[1],
    )
    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(
            report,
            "observation_receipts",
            changed_receipts,
        ).verify()

    changed_receipts = (
        _forged_receipt(first, receipt_sha256="f" * 64),
        report.observation_receipts[1],
    )
    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(
            report,
            "observation_receipts",
            changed_receipts,
        ).verify()

    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(
            report,
            "chain_head_receipt",
            report.observation_receipts[0],
        ).verify()


@pytest.mark.parametrize(
    ("attribute", "content"),
    (
        ("hard_quality_metric_status", "passed"),
        ("metrics_evaluated", True),
        ("fixture_scope_only", False),
        ("live_time_separated_execution", "collected"),
        ("production_certification", "certified"),
        ("withheld_reason", "changed"),
        ("certifies_slice", True),
        ("objective_satisfied", True),
        ("external_action_capability", True),
        ("assessment", "accepted"),
    ),
)
def test_report_rejects_every_withholding_boundary_tamper(
    tmp_path,
    attribute,
    content,
) -> None:
    _, _, report = _report(tmp_path)

    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(report, attribute, content).verify()


@pytest.mark.parametrize("target_name", tuple(HARD_QUALITY_TARGETS))
def test_report_rejects_each_hard_target_status_tamper(
    tmp_path,
    target_name,
) -> None:
    _, _, report = _report(tmp_path)
    hard_targets = report.document()["hard_quality_targets"]
    hard_targets[target_name]["status"] = "passed"

    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(report, "hard_quality_targets", hard_targets).verify()


@pytest.mark.parametrize(
    ("injected_key", "injected_content"),
    (
        ("measured_value", 0),
        ("pass", True),
        ("result", "met"),
    ),
)
def test_report_rejects_invented_hard_target_results(
    tmp_path,
    injected_key,
    injected_content,
) -> None:
    _, _, report = _report(tmp_path)
    hard_targets = report.document()["hard_quality_targets"]
    hard_targets["ats_parse_success_bp"][injected_key] = injected_content

    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(report, "hard_quality_targets", hard_targets).verify()


def test_report_rejects_identity_and_caller_verdict_tamper(tmp_path) -> None:
    _, _, report = _report(tmp_path)
    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(report, "report_id", "f" * 64).verify()

    measures = report.document()["descriptive_fixture_measures"]
    measures["separation_met"] = True
    with pytest.raises(FixtureMeasuresIntegrityError):
        _tampered(
            report,
            "descriptive_fixture_measures",
            measures,
        ).verify()

    with pytest.raises(TypeError):
        compile_fixture_measures_report(
            object(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
            (),
            certification="accepted",  # type: ignore[call-arg]
        )


def test_apparent_source_time_distance_produces_no_source_time_result(
    tmp_path,
) -> None:
    ledger, observations = _ledger_with_observations(
        tmp_path,
        far_apart=True,
    )
    report = compile_fixture_measures_report(
        ledger,
        ledger.identity,
        observations,
    )
    measures = report.document()["descriptive_fixture_measures"]

    assert [
        row["source_observed_at"] for row in measures["observations"]
    ] == [row.observed_at for row in observations]
    assert measures_module.SOURCE_TIME_AUTHORITY == (
        "caller_supplied_untrusted_not_time_authority"
    )
    assert all(
        "source" not in key or key == "source_observed_at_authority"
        for key in measures
    )
    assert "separation_met" not in json.dumps(report.document())


def test_later_append_preserves_offline_report_but_is_not_current(
    tmp_path,
) -> None:
    ledger, _, report = _report(tmp_path)
    third = _observation(
        "negative-third",
        datetime(2024, 1, 2, tzinfo=timezone.utc),
    )
    ledger.record_observation(ledger.begin_session(), third)

    report.verify()
    with pytest.raises(FixtureMeasuresStaleSnapshotError):
        report.verify_current(ledger)


def test_module_api_imports_and_vocabulary_are_strictly_bounded(
    tmp_path,
) -> None:
    _, _, report = _report(tmp_path)
    source_path = Path(measures_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert imports == {
        "career_automation",
        "dataclasses",
        "datetime",
        "hashlib",
        "json",
        "types",
        "typing",
    }
    assert "MINIMUM_SHADOW_SEPARATION" not in source
    for forbidden_capability in (
        "playwright",
        "requests",
        "socket",
        "subprocess",
        "credential",
        "release_token",
    ):
        assert forbidden_capability not in source.lower()

    forbidden_parameters = {
        "certification",
        "clock",
        "metric",
        "pass_state",
        "timestamp",
        "time_separation",
        "withheld_claim",
    }
    for _, function in inspect.getmembers(
        measures_module,
        inspect.isfunction,
    ):
        if function.__module__ == measures_module.__name__:
            assert not (
                set(inspect.signature(function).parameters)
                & forbidden_parameters
            )
    for method_name in ("document", "verify", "verify_current"):
        method = getattr(measures_module.FixtureMeasuresReport, method_name)
        assert not (
            set(inspect.signature(method).parameters)
            & forbidden_parameters
        )

    serialized = json.dumps(
        report.document(),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).lower()
    for forbidden in (
        "certified",
        "ratified",
        "accepted",
        "separation_met",
    ):
        assert forbidden not in serialized
    without_satisfied = serialized.replace(
        '"objective_satisfied":false',
        "",
    )
    assert "satisfied" not in without_satisfied
    without_eligible = serialized
    for allowed in (
        '"ineligible_submissions"',
        '"ineligible_contract"',
        json.dumps(
            MUTATION_TEST_NODES["ineligible_contract"],
            ensure_ascii=False,
            separators=(",", ":"),
        ).lower(),
    ):
        without_eligible = without_eligible.replace(allowed, "")
    assert "eligible" not in without_eligible
