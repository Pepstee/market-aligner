"""Operational and adversarial acceptance for the local JAA-16 supervisor."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.operations_live import (
    BackpressureError,
    BudgetExhaustedError,
    CapabilityBudget,
    ConsequentialDispatchError,
    InjectedFailure,
    LeaseError,
    LocalProbeFailure,
    LocalProbeResult,
    OperationsSupervisor,
    ProviderExhaustedError,
    RuntimeRoute,
    ScheduleSpec,
    SchemaDriftError,
    UnsafeResumeError,
    WorkRequest,
    assess_release_boundary,
)
from career_automation.release_certification import (
    FROZEN_RELEASE_CERTIFICATION_CONTRACT,
    REQUIRED_PRIOR_SLICES,
    REQUIRED_RELEASE_EVIDENCE,
    record_distribution_scan,
    record_prior_slice_certification,
    record_release_evidence_reference,
)


BASE = datetime(2030, 1, 1, 12, tzinfo=timezone.utc)
SCHEMA = hashlib.sha256(b"output-schema").hexdigest()
POLICY = hashlib.sha256(b"policy").hexdigest()
WORKFLOW = hashlib.sha256(b"workflow").hexdigest()
INPUT = hashlib.sha256(b"input").hexdigest()
EVIDENCE = hashlib.sha256(b"route-evidence").hexdigest()
RUNGS = ("schema_validation", "truth_validation")


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _schedule() -> ScheduleSpec:
    return ScheduleSpec(
        schedule_id="schedule:status",
        capability="status_classification",
        workflow_sha256=WORKFLOW,
        first_due_at=BASE,
        cadence_seconds=60,
        queue_high_watermark=5,
        queue_hard_stop=10,
        resume_below=3,
        lease_seconds=5,
    )


def _budget(
    *, attempts: int = 20, tokens: int = 10_000, cost: int = 10_000
) -> CapabilityBudget:
    return CapabilityBudget(
        capability="status_classification",
        max_attempts_per_utc_day=attempts,
        max_tokens_per_utc_day=tokens,
        max_cost_microusd_per_utc_day=cost,
    )


def _routes() -> tuple[RuntimeRoute, RuntimeRoute]:
    return tuple(
        RuntimeRoute(
            route_id=f"route:{name}",
            capability="status_classification",
            priority=priority,
            output_schema_sha256=SCHEMA,
            policy_sha256=POLICY,
            verification_rungs=RUNGS,
            tested_evidence_sha256=_digest(f"{EVIDENCE}:{name}"),
        )
        for priority, name in ((1, "primary"), (2, "fallback"))
    )


def _request(name: str = "one", *, consequential: bool = False) -> WorkRequest:
    return WorkRequest(
        work_id=f"work:{name}",
        input_sha256=_digest(f"{INPUT}:{name}"),
        payload={"record": name},
        consequential=consequential,
    )


def _supervisor(
    path: Path,
    *,
    budget: CapabilityBudget | None = None,
    initialized_at: datetime = BASE - timedelta(seconds=1),
) -> OperationsSupervisor:
    return OperationsSupervisor(
        path,
        schedules=(_schedule(),),
        budgets=(budget or _budget(),),
        routes=_routes(),
        initialized_at=initialized_at,
    )


def _probe(
    route_id: str,
    *,
    success: bool = True,
    tokens: int = 5,
    cost: int = 7,
    schema: str = SCHEMA,
    rungs: tuple[str, ...] = RUNGS,
):
    def probe(_request_row: WorkRequest, _route: RuntimeRoute) -> LocalProbeResult:
        return LocalProbeResult(
            route_id=route_id,
            success=success,
            output={"status": "ok"} if success else None,
            output_schema_sha256=schema,
            verification_rungs=rungs,
            tokens_used=tokens,
            cost_microusd=cost,
        )

    probe.__jaa_local_probe__ = True
    return probe


def _probes() -> dict[str, object]:
    return {
        "route:primary": _probe("route:primary"),
        "route:fallback": _probe("route:fallback"),
    }


def _event_kinds(supervisor: OperationsSupervisor) -> list[str]:
    return [row["event_kind"] for row in supervisor.ledger.rows()]


def test_due_schedule_executes_marked_local_probe_and_is_durable(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")
    receipt = supervisor.run_due(
        "schedule:status",
        request=_request(),
        queue_depth=0,
        probes=_probes(),
        owner_id="worker:one",
        now=BASE,
    )

    assert receipt is not None
    assert receipt.route_id == "route:primary"
    assert receipt.external_action is False
    assert receipt.consequential_queue_mutated is False
    assert receipt.certifies_slice is False
    assert supervisor.ledger.head_sha256 != "0" * 64
    assert "lease_acquired" in _event_kinds(supervisor)
    assert "run_completed" in _event_kinds(supervisor)

    restarted = _supervisor(tmp_path / "operations.sqlite3")
    assert restarted.ledger.head_sha256 == supervisor.ledger.head_sha256


def test_idempotency_returns_receipt_without_second_probe(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")
    calls = 0

    def primary(_request_row: WorkRequest, _route: RuntimeRoute) -> LocalProbeResult:
        nonlocal calls
        calls += 1
        return LocalProbeResult(
            route_id="route:primary",
            success=True,
            output={"status": "ok"},
            output_schema_sha256=SCHEMA,
            verification_rungs=RUNGS,
            tokens_used=1,
            cost_microusd=1,
        )

    primary.__jaa_local_probe__ = True
    probes = {"route:primary": primary, "route:fallback": _probe("route:fallback")}
    request = _request("idempotent")
    first = supervisor.run_due(
        "schedule:status",
        request=request,
        queue_depth=0,
        probes=probes,
        owner_id="worker:one",
        now=BASE,
    )
    second = supervisor.run_due(
        "schedule:status",
        request=request,
        queue_depth=0,
        probes=probes,
        owner_id="worker:two",
        now=BASE + timedelta(seconds=1),
    )
    assert first == second
    assert calls == 1


def test_consequential_work_and_unmarked_callable_are_rejected(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")
    with pytest.raises(ConsequentialDispatchError, match="no consequential"):
        supervisor.run_due(
            "schedule:status",
            request=_request("submit", consequential=True),
            queue_depth=0,
            probes=_probes(),
            owner_id="worker:one",
            now=BASE,
        )
    assert "local_alert" in _event_kinds(supervisor)

    supervisor = _supervisor(tmp_path / "unmarked.sqlite3")
    probes = _probes()
    probes["route:primary"] = lambda *_args: None
    with pytest.raises(ConsequentialDispatchError, match="local-only probe"):
        supervisor.run_due(
            "schedule:status",
            request=_request("unmarked"),
            queue_depth=0,
            probes=probes,
            owner_id="worker:one",
            now=BASE,
        )


@pytest.mark.parametrize("failure", ["quota", "network", "model_failure"])
def test_failure_drills_use_schema_preserving_fallback(
    tmp_path: Path, failure: str
) -> None:
    supervisor = _supervisor(tmp_path / f"{failure}.sqlite3")
    receipt = supervisor.run_due(
        "schedule:status",
        request=_request(failure),
        queue_depth=0,
        probes=_probes(),
        owner_id="worker:one",
        now=BASE,
        injected_failure=failure,
    )
    assert receipt is not None
    assert receipt.route_id == "route:fallback"
    payloads = [
        json.loads(row["payload_json"])
        for row in supervisor.ledger.rows()
        if row["event_kind"] == "drill_observed"
    ]
    assert payloads[-1] == {
        "failure_kind": failure,
        "fallback_preserved_schema": True,
        "no_consequential_action": True,
    }


def test_fallback_schema_drift_pauses_instead_of_pretending_success(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")
    probes = _probes()
    probes["route:fallback"] = _probe("route:fallback", schema=_digest("changed"))
    with pytest.raises(SchemaDriftError, match="changed schema"):
        supervisor.run_due(
            "schedule:status",
            request=_request("drift"),
            queue_depth=0,
            probes=probes,
            owner_id="worker:one",
            now=BASE,
            injected_failure="quota",
        )
    assert supervisor.is_paused("schedule:status")
    assert any(
        json.loads(row["payload_json"]).get("signal") == "schema_drift"
        for row in supervisor.ledger.rows()
        if row["event_kind"] == "local_alert"
    )


def test_exhausted_routes_pause_without_fabricated_progress(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")

    def failed(_request_row: WorkRequest, _route: RuntimeRoute):
        raise LocalProbeFailure("model_failure")

    failed.__jaa_local_probe__ = True
    with pytest.raises(ProviderExhaustedError):
        supervisor.run_due(
            "schedule:status",
            request=_request("exhausted"),
            queue_depth=0,
            probes={"route:primary": failed, "route:fallback": failed},
            owner_id="worker:one",
            now=BASE,
        )
    assert supervisor.is_paused("schedule:status")
    assert "run_completed" not in _event_kinds(supervisor)


def test_backpressure_defers_then_hard_stops_and_requires_safe_resume(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")
    assert (
        supervisor.run_due(
            "schedule:status",
            request=_request("defer"),
            queue_depth=5,
            probes=_probes(),
            owner_id="worker:one",
            now=BASE,
        )
        is None
    )
    with pytest.raises(BackpressureError):
        supervisor.run_due(
            "schedule:status",
            request=_request("stop"),
            queue_depth=10,
            probes=_probes(),
            owner_id="worker:one",
            now=BASE + timedelta(seconds=1),
        )
    pause = next(
        row["event_sha256"]
        for row in reversed(supervisor.ledger.rows())
        if row["event_kind"] == "schedule_paused"
    )
    with pytest.raises(UnsafeResumeError):
        supervisor.resume(
            "schedule:status",
            expected_pause_sha256=pause,
            resolution_sha256=_digest("resolution"),
            queue_depth=3,
            now=BASE + timedelta(seconds=2),
        )
    supervisor.resume(
        "schedule:status",
        expected_pause_sha256=pause,
        resolution_sha256=_digest("resolution"),
        queue_depth=0,
        now=BASE + timedelta(seconds=3),
    )
    assert not supervisor.is_paused("schedule:status")


def test_capability_budget_is_durable_and_blocks_exhaustion(tmp_path: Path) -> None:
    supervisor = _supervisor(
        tmp_path / "operations.sqlite3", budget=_budget(attempts=1, tokens=10, cost=10)
    )
    supervisor.run_due(
        "schedule:status",
        request=_request("first"),
        queue_depth=0,
        probes=_probes(),
        owner_id="worker:one",
        now=BASE,
    )
    restarted = _supervisor(
        tmp_path / "operations.sqlite3", budget=_budget(attempts=1, tokens=10, cost=10)
    )
    with pytest.raises(BudgetExhaustedError):
        restarted.run_due(
            "schedule:status",
            request=_request("second"),
            queue_depth=0,
            probes=_probes(),
            owner_id="worker:one",
            now=BASE + timedelta(seconds=60),
        )


@pytest.mark.parametrize("failure", ["crash", "restart"])
def test_pre_probe_crash_and_restart_lease_recover_losslessly(
    tmp_path: Path, failure: str
) -> None:
    path = tmp_path / f"{failure}.sqlite3"
    supervisor = _supervisor(path)
    request = _request(failure)
    with pytest.raises(InjectedFailure, match=failure):
        supervisor.run_due(
            "schedule:status",
            request=request,
            queue_depth=0,
            probes=_probes(),
            owner_id="worker:one",
            now=BASE,
            injected_failure=failure,
        )
    restarted = _supervisor(path)
    recovered = restarted.restart(now=BASE + timedelta(seconds=6))
    assert recovered == (f"run:{request.idempotency_key[:32]}",)
    receipt = restarted.run_due(
        "schedule:status",
        request=request,
        queue_depth=0,
        probes=_probes(),
        owner_id="worker:two",
        now=BASE + timedelta(seconds=7),
    )
    assert receipt is not None


def test_lost_lease_after_probe_is_paused_not_replayed(tmp_path: Path) -> None:
    path = tmp_path / "operations.sqlite3"
    supervisor = _supervisor(path)

    def uncertain(_request_row: WorkRequest, _route: RuntimeRoute):
        raise RuntimeError("worker died after entering probe")

    uncertain.__jaa_local_probe__ = True
    with pytest.raises(RuntimeError, match="worker died"):
        supervisor.run_due(
            "schedule:status",
            request=_request("uncertain"),
            queue_depth=0,
            probes={"route:primary": uncertain, "route:fallback": uncertain},
            owner_id="worker:one",
            now=BASE,
        )
    restarted = _supervisor(path)
    with pytest.raises(LeaseError, match="uncertain"):
        restarted.restart(now=BASE + timedelta(seconds=6))
    assert restarted.is_paused("schedule:status")


def test_stale_source_drill_pauses_and_records_weather_alert(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")
    with pytest.raises(InjectedFailure, match="stale_source"):
        supervisor.run_due(
            "schedule:status",
            request=_request("stale"),
            queue_depth=0,
            probes=_probes(),
            owner_id="worker:one",
            now=BASE,
            injected_failure="stale_source",
        )
    alert = next(
        json.loads(row["payload_json"])
        for row in supervisor.ledger.rows()
        if row["event_kind"] == "local_alert"
    )
    assert alert["signal"] == "stale_source"
    assert alert["classification"] == "weather"
    assert supervisor.is_paused("schedule:status")


def test_event_ledger_is_append_only_and_detects_tampering(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")
    with (
        sqlite3.connect(supervisor.ledger.path),
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
    ):
        connection = sqlite3.connect(supervisor.ledger.path)
        try:
            connection.execute("UPDATE operations_events SET event_kind='forged'")
        finally:
            connection.close()


def test_backup_restore_requires_clean_current_binding(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")
    head = supervisor.ledger.head_sha256
    source = _digest("source-db")
    with pytest.raises(ValueError, match="dirty or not bound"):
        supervisor.record_backup(
            backup_id="backup:dirty",
            source_sha256=source,
            backup_sha256=_digest("backup"),
            manifest_sha256=_digest("manifest"),
            bound_ledger_head_sha256=head,
            clean=False,
            now=BASE,
        )
    supervisor.record_backup(
        backup_id="backup:clean",
        source_sha256=source,
        backup_sha256=_digest("backup"),
        manifest_sha256=_digest("manifest"),
        bound_ledger_head_sha256=head,
        clean=True,
        now=BASE,
    )
    with pytest.raises(ValueError, match="does not reproduce"):
        supervisor.verify_restore(
            backup_id="backup:clean",
            restored_source_sha256=_digest("wrong"),
            restore_manifest_sha256=_digest("restore-manifest"),
            now=BASE + timedelta(seconds=1),
        )
    verified = supervisor.verify_restore(
        backup_id="backup:clean",
        restored_source_sha256=source,
        restore_manifest_sha256=_digest("restore-manifest"),
        now=BASE + timedelta(seconds=1),
    )
    assert verified.restore_verified is True
    assert verified.release_evidence_authority is False


def test_reports_are_hash_bound_local_drafts(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path / "operations.sqlite3")
    report = supervisor.compile_local_report(
        report_kind="daily_operations",
        period_start=BASE - timedelta(days=1),
        period_end=BASE,
        now=BASE + timedelta(seconds=1),
    )
    assert report.event_counts == {"configuration_registered": 1}
    assert report.send_authority is False
    assert report.certifies_slice is False
    assert len(report.report_sha256) == 64


def _release_inputs(*, clean: bool = True):
    contract = FROZEN_RELEASE_CERTIFICATION_CONTRACT
    artifact_version = "0.1.0"
    artifact_hash = _digest("release-artifact")
    prior = tuple(
        record_prior_slice_certification(
            contract,
            slice_id=slice_id,
            source_git_revision=_digest(f"git:{slice_id}"),
            source_tree_sha256=_digest(f"tree:{slice_id}"),
            source_content_revision=_digest(f"content:{slice_id}"),
            receipt_sha256=_digest(f"receipt:{slice_id}"),
            independent_ruling_sha256=_digest(f"ruling:{slice_id}"),
            certification_status="independently_certified",
        )
        for slice_id in REQUIRED_PRIOR_SLICES
    )
    evidence = tuple(
        record_release_evidence_reference(
            contract,
            evidence_kind=kind,
            artifact_version=artifact_version,
            environment="clean-supported-mac",
            evidence_sha256=_digest(f"evidence:{kind}"),
            observed_at=BASE,
            independently_verified=True,
        )
        for kind in REQUIRED_RELEASE_EVIDENCE
    )
    scan = record_distribution_scan(
        contract,
        artifact_version=artifact_version,
        artifact_sha256=artifact_hash,
        person_specific_items=0 if clean else 1,
        test_data_items=0,
        claim_items=0,
        credential_items=0,
        host_path_items=0,
        scanner_report_sha256=_digest("scanner"),
        scanned_at=BASE,
    )
    return artifact_version, artifact_hash, prior, evidence, scan


def test_exact_release_inputs_only_enable_independent_review_never_authority() -> None:
    version, artifact, prior, evidence, scan = _release_inputs()
    assessment = assess_release_boundary(
        prior_certifications=prior,
        release_evidence=evidence,
        distribution_scan=scan,
        artifact_version=version,
        artifact_sha256=artifact,
    )
    assert assessment.eligible_for_independent_review is True
    assert assessment.reason_codes == ()
    assert assessment.release_authority is False
    assert assessment.deployment_authority is False
    assert assessment.report_send_authority is False
    assert assessment.entitlement_authority is False
    assert assessment.production_certification is False
    assert assessment.certifies_slice is False


def test_missing_forged_or_dirty_release_inputs_fail_closed() -> None:
    version, artifact, prior, evidence, scan = _release_inputs(clean=False)
    assessment = assess_release_boundary(
        prior_certifications=prior[:-1],
        release_evidence=evidence[:-1],
        distribution_scan=scan,
        artifact_version=version,
        artifact_sha256=artifact,
    )
    assert assessment.eligible_for_independent_review is False
    assert assessment.reason_codes == (
        "missing_or_duplicate_prior_slice_certification",
        "missing_unverified_or_unbound_release_evidence",
        "dirty_or_unbound_distribution",
    )
    with pytest.raises(ValueError, match="identity"):
        assess_release_boundary(
            prior_certifications=(replace(prior[0], receipt_sha256=_digest("forged")),),
            release_evidence=evidence,
            distribution_scan=scan,
            artifact_version=version,
            artifact_sha256=artifact,
        )
