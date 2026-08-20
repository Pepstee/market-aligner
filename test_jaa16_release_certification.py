from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from career_automation.operations import (
    FAILURE_KINDS,
    FROZEN_OPERATIONS_CONTRACT,
    classify_operation_alert,
    compile_operational_report,
    compile_operations_plan,
    compile_provider_route,
    compile_provider_route_set,
    compile_schedule_definition,
    evaluate_failure_drills,
    record_failure_drill_observation,
)
from career_automation.release_certification import (
    FROZEN_RELEASE_CERTIFICATION_CONTRACT,
    PRE_JAA16_MANIFEST_SHA256,
    REQUIRED_PRIOR_SLICES,
    REQUIRED_RELEASE_EVIDENCE,
    assess_release_candidate,
    compile_release_candidate,
    record_distribution_scan,
    record_prior_slice_certification,
    record_release_evidence_reference,
)


NOW = datetime(2026, 7, 29, 10, 0, tzinfo=timezone.utc)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def operations_plan():
    contract = FROZEN_OPERATIONS_CONTRACT
    schedule = compile_schedule_definition(
        contract,
        schedule_name="opportunity-refresh",
        workflow_sha256=digest("workflow"),
        cadence_seconds=3600,
        jitter_seconds=120,
        max_concurrent_runs=1,
    )
    routes = tuple(
        compile_provider_route(
            contract,
            capability="bounded-review",
            route_id=f"route-{index}",
            provider_id=f"provider-{index}",
            model_id=f"model-{index}",
            priority=index,
            output_schema_sha256=digest("output-schema"),
            policy_sha256=digest("provider-policy"),
            verification_rungs=(
                "deterministic_validation",
                "independent_review",
            ),
            max_input_tokens=20_000,
            max_output_tokens=4_000,
            max_cost_microusd=500_000,
        )
        for index in (1, 2)
    )
    route_set = compile_provider_route_set(contract, routes)
    return compile_operations_plan(
        contract,
        schedules=(schedule,),
        provider_route_sets=(route_set,),
        heartbeat_timeout_seconds=300,
        queue_high_watermark=50,
        queue_hard_stop=100,
        resume_below=25,
        daily_cost_budget_microusd=2_000_000,
        daily_token_budget=500_000,
        max_consequential_actions_per_run=0,
        pause_resume_policy_sha256=digest("pause-resume"),
        rollback_policy_sha256=digest("rollback"),
    )


def drill_suite(plan=None):
    plan = plan or operations_plan()
    drills = tuple(
        record_failure_drill_observation(
            FROZEN_OPERATIONS_CONTRACT,
            plan,
            failure_kind=failure_kind,
            input_snapshot_sha256=digest(f"input-{failure_kind}"),
            ledger_before_sha256=digest(f"before-{failure_kind}"),
            ledger_after_sha256=digest(f"after-{failure_kind}"),
            checkpoint_sha256=digest(f"checkpoint-{failure_kind}"),
            consequential_action_ids=(),
            duplicate_consequential_actions=0,
            lost_record_count=0,
            affected_work_paused=failure_kind
            in {"quota", "network", "stale_source", "model_failure"},
            resumed_from_checkpoint=failure_kind in {"crash", "restart"},
            fallback_schema_preserved=True,
            verification_rungs_preserved=True,
            fabricated_progress=False,
            observed_at=NOW,
        )
        for failure_kind in FAILURE_KINDS
    )
    return evaluate_failure_drills(
        FROZEN_OPERATIONS_CONTRACT,
        plan,
        drills,
    )


def clean_scan():
    return record_distribution_scan(
        FROZEN_RELEASE_CERTIFICATION_CONTRACT,
        artifact_version="0.1.0-candidate",
        artifact_sha256=digest("artifact"),
        person_specific_items=0,
        test_data_items=0,
        claim_items=0,
        credential_items=0,
        host_path_items=0,
        scanner_report_sha256=digest("scanner-report"),
        scanned_at=NOW,
    )


def prior_certifications():
    return tuple(
        record_prior_slice_certification(
            FROZEN_RELEASE_CERTIFICATION_CONTRACT,
            slice_id=slice_id,
            source_git_revision=digest(f"git-{slice_id}"),
            source_tree_sha256=digest(f"tree-{slice_id}"),
            source_content_revision=digest(f"content-{slice_id}"),
            receipt_sha256=digest(f"receipt-{slice_id}"),
            independent_ruling_sha256=digest(f"ruling-{slice_id}"),
            certification_status="independently_certified",
        )
        for slice_id in REQUIRED_PRIOR_SLICES
    )


def release_evidence(
    *,
    independently_verified: bool = True,
    artifact_version: str = "0.1.0-candidate",
):
    return tuple(
        record_release_evidence_reference(
            FROZEN_RELEASE_CERTIFICATION_CONTRACT,
            evidence_kind=evidence_kind,
            artifact_version=artifact_version,
            environment="supported-mac-clean-install",
            evidence_sha256=digest(f"evidence-{evidence_kind}"),
            observed_at=NOW,
            independently_verified=independently_verified,
        )
        for evidence_kind in REQUIRED_RELEASE_EVIDENCE
    )


def release_candidate(
    *,
    plan=None,
    assessment=None,
    priors=(),
    evidence=(),
    scan=None,
):
    plan = plan or operations_plan()
    assessment = assessment or drill_suite(plan)
    scan = scan or clean_scan()
    return compile_release_candidate(
        FROZEN_RELEASE_CERTIFICATION_CONTRACT,
        artifact_version="0.1.0-candidate",
        artifact_sha256=digest("artifact"),
        operations_plan=plan,
        drill_assessment=assessment,
        prior_certifications=priors,
        release_evidence=evidence,
        distribution_scan=scan,
    )


def test_frozen_contract_binds_exact_inputs_and_withholds_all_authority():
    contract = FROZEN_RELEASE_CERTIFICATION_CONTRACT
    assert contract.pre_slice_manifest_sha256 == PRE_JAA16_MANIFEST_SHA256
    assert contract.required_prior_slices == REQUIRED_PRIOR_SLICES
    assert contract.required_release_evidence == REQUIRED_RELEASE_EVIDENCE
    assert contract.release_authority == "withheld"
    assert contract.distribution_authority == "withheld"
    assert contract.entitlement_activation_authority == "withheld"
    assert contract.production_certification == "withheld"
    assert contract.dependency_satisfied is False
    assert contract.certifies_slice is False


def test_operations_plan_is_content_addressed_paused_and_non_executing():
    plan = operations_plan()
    assert plan.schedules[0].paused_by_default is True
    assert plan.schedules[0].scheduler_authority == "withheld"
    assert plan.provider_route_sets[0].on_exhaustion == "pause_affected_work"
    assert plan.provider_route_sets[0].fabricated_progress_allowed is False
    assert plan.max_consequential_actions_per_run == 0
    assert plan.execution_authority == "withheld"
    assert plan.deployment_authority == "withheld"
    plan.verify()


def test_all_six_local_failure_drills_are_review_eligible_not_runtime_proof():
    assessment = drill_suite()
    assert assessment.plan.plan_id == assessment.plan_id
    assert tuple(row.drill_id for row in assessment.drills) == (
        assessment.drill_ids
    )
    assert assessment.failure_kinds == tuple(sorted(FAILURE_KINDS))
    assert assessment.reason_codes == ()
    assert assessment.eligible_for_independent_runtime_review is True
    assert assessment.runtime_evidence_verified is False
    assert assessment.production_certification == "withheld"
    assert assessment.certifies_slice is False


def test_alerts_and_reports_are_deterministic_local_drafts():
    plan = operations_plan()
    alerts = tuple(
        classify_operation_alert(
            FROZEN_OPERATIONS_CONTRACT,
            signal_kind=signal,
            affected_work_id="work-1",
            evidence_sha256=digest(signal),
            observed_at=NOW,
        )
        for signal in (
            "external_network",
            "credential_required",
            "invariant_breach",
        )
    )
    assert tuple(row.classification for row in alerts) == (
        "weather",
        "blocked_work",
        "product_defect",
    )
    report = compile_operational_report(
        FROZEN_OPERATIONS_CONTRACT,
        plan,
        report_kind="daily_operations",
        period_start=NOW,
        period_end=NOW + timedelta(days=1),
        event_ledger_sha256=digest("event-ledger"),
        operation_count=5,
        succeeded_count=2,
        failed_count=1,
        blocked_count=2,
        cost_microusd=75_000,
        alerts=alerts,
    )
    assert report.report_status == "local_draft"
    assert report.send_authority == "withheld"
    assert report.production_certification == "withheld"


def test_current_local_candidate_names_every_missing_release_requirement():
    assessment = assess_release_candidate(
        FROZEN_RELEASE_CERTIFICATION_CONTRACT,
        release_candidate(),
    )
    assert assessment.reason_codes == (
        "missing_prior_slice_certification",
        "missing_release_evidence",
        "operations_plan_dependency_unsatisfied",
        "drill_runtime_not_independently_verified",
    )
    assert assessment.candidate.candidate_id == assessment.candidate_id
    assert assessment.eligible_for_independent_release_review is False
    assert assessment.release_certificate_id is None
    assert assessment.released is False
    assert assessment.certifies_slice is False


def test_complete_synthetic_references_cannot_bypass_unsatisfied_dependency():
    candidate = release_candidate(
        priors=prior_certifications(),
        evidence=release_evidence(),
    )
    assessment = assess_release_candidate(
        FROZEN_RELEASE_CERTIFICATION_CONTRACT,
        candidate,
    )
    assert all(
        row.artifact_version == candidate.artifact_version
        for row in candidate.release_evidence
    )
    assert assessment.reason_codes == (
        "unauthenticated_prior_slice_certifications",
        "unauthenticated_release_evidence",
        "operations_plan_dependency_unsatisfied",
    )
    assert assessment.eligible_for_independent_release_review is False
    assert assessment.release_certificate_id is None
    assert assessment.released is False
    assert assessment.production_certification == "withheld"
