from __future__ import annotations

from dataclasses import replace

import pytest

from career_automation.operations import (
    FROZEN_OPERATIONS_CONTRACT,
    compile_operations_plan,
    compile_provider_route,
    compile_provider_route_set,
    evaluate_failure_drills,
    record_failure_drill_observation,
)
from career_automation.release_certification import (
    FROZEN_RELEASE_CERTIFICATION_CONTRACT,
    assess_release_candidate,
    compile_release_candidate,
    record_distribution_scan,
    record_prior_slice_certification,
    record_release_evidence_reference,
)
from test_jaa16_release_certification import (
    NOW,
    digest,
    drill_suite,
    operations_plan,
    prior_certifications,
    release_candidate,
    release_evidence,
)


def test_schedule_rejects_execution_authority_and_forged_identity():
    schedule = operations_plan().schedules[0]
    with pytest.raises(ValueError, match="cannot execute"):
        replace(schedule, scheduler_authority="granted")
    with pytest.raises(ValueError, match="identity"):
        replace(schedule, cadence_seconds=7200)


def test_operations_plan_rejects_invalid_backpressure_thresholds():
    base = operations_plan()
    with pytest.raises(ValueError, match="thresholds"):
        compile_operations_plan(
            FROZEN_OPERATIONS_CONTRACT,
            schedules=base.schedules,
            provider_route_sets=base.provider_route_sets,
            heartbeat_timeout_seconds=300,
            queue_high_watermark=50,
            queue_hard_stop=50,
            resume_below=25,
            daily_cost_budget_microusd=1,
            daily_token_budget=1,
            max_consequential_actions_per_run=0,
            pause_resume_policy_sha256=digest("pause"),
            rollback_policy_sha256=digest("rollback"),
        )


def test_operations_plan_rejects_deployment_authority():
    with pytest.raises(ValueError, match="cannot execute or certify"):
        replace(operations_plan(), deployment_authority="granted")


def test_provider_route_set_rejects_missing_fallback():
    route = operations_plan().provider_route_sets[0].routes[0]
    with pytest.raises(ValueError, match="primary and fallback"):
        compile_provider_route_set(FROZEN_OPERATIONS_CONTRACT, (route,))


def test_provider_fallback_cannot_change_schema_or_verification_rungs():
    first = operations_plan().provider_route_sets[0].routes[0]
    changed = compile_provider_route(
        FROZEN_OPERATIONS_CONTRACT,
        capability=first.capability,
        route_id="changed-route",
        provider_id="changed-provider",
        model_id="changed-model",
        priority=2,
        output_schema_sha256=digest("changed-schema"),
        policy_sha256=first.policy_sha256,
        verification_rungs=("deterministic_validation",),
        max_input_tokens=100,
        max_output_tokens=100,
        max_cost_microusd=100,
    )
    with pytest.raises(ValueError, match="fallback changes"):
        compile_provider_route_set(
            FROZEN_OPERATIONS_CONTRACT,
            (first, changed),
        )


def test_provider_route_set_rejects_execution_authority():
    route_set = operations_plan().provider_route_sets[0]
    with pytest.raises(ValueError, match="cannot fabricate or execute"):
        replace(route_set, execution_authority="granted")


@pytest.mark.parametrize(
    ("failure_kind", "updates", "reason"),
    [
        ("quota", {"affected_work_paused": False}, "affected_work_not_paused"),
        ("model_failure", {"fallback_schema_preserved": False}, "fallback_schema_changed"),
        ("restart", {"resumed_from_checkpoint": False}, "checkpoint_not_resumed"),
        ("network", {"lost_record_count": 1}, "data_loss"),
        (
            "stale_source",
            {"duplicate_consequential_actions": 1},
            "duplicate_consequential_action",
        ),
    ],
)
def test_drill_suite_rejects_failure_invariants(failure_kind, updates, reason):
    plan = operations_plan()
    rows = []
    for kind in (
        "crash",
        "quota",
        "network",
        "stale_source",
        "model_failure",
        "restart",
    ):
        values = {
            "duplicate_consequential_actions": 0,
            "lost_record_count": 0,
            "affected_work_paused": kind
            in {"quota", "network", "stale_source", "model_failure"},
            "resumed_from_checkpoint": kind in {"crash", "restart"},
            "fallback_schema_preserved": True,
        }
        if kind == failure_kind:
            values.update(updates)
        rows.append(
            record_failure_drill_observation(
                FROZEN_OPERATIONS_CONTRACT,
                plan,
                failure_kind=kind,
                input_snapshot_sha256=digest(f"input-{kind}"),
                ledger_before_sha256=digest(f"before-{kind}"),
                ledger_after_sha256=digest(f"after-{kind}"),
                checkpoint_sha256=digest(f"checkpoint-{kind}"),
                consequential_action_ids=(),
                verification_rungs_preserved=True,
                fabricated_progress=False,
                observed_at=NOW,
                **values,
            )
        )
    assessment = evaluate_failure_drills(
        FROZEN_OPERATIONS_CONTRACT,
        plan,
        tuple(rows),
    )
    assert reason in assessment.reason_codes
    assert assessment.eligible_for_independent_runtime_review is False


def test_fabricated_progress_is_rejected_at_observation_boundary():
    with pytest.raises(ValueError, match="cannot certify runtime"):
        record_failure_drill_observation(
            FROZEN_OPERATIONS_CONTRACT,
            operations_plan(),
            failure_kind="quota",
            input_snapshot_sha256=digest("input"),
            ledger_before_sha256=digest("before"),
            ledger_after_sha256=digest("after"),
            checkpoint_sha256=digest("checkpoint"),
            consequential_action_ids=(),
            duplicate_consequential_actions=0,
            lost_record_count=0,
            affected_work_paused=True,
            resumed_from_checkpoint=False,
            fallback_schema_preserved=True,
            verification_rungs_preserved=True,
            fabricated_progress=True,
            observed_at=NOW,
        )


def test_missing_drill_kind_blocks_runtime_review():
    plan = operations_plan()
    complete = drill_suite(plan)
    assert len(complete.drill_ids) == 6
    rows = tuple(
        record_failure_drill_observation(
            FROZEN_OPERATIONS_CONTRACT,
            plan,
            failure_kind=kind,
            input_snapshot_sha256=digest(f"partial-input-{kind}"),
            ledger_before_sha256=digest(f"partial-before-{kind}"),
            ledger_after_sha256=digest(f"partial-after-{kind}"),
            checkpoint_sha256=digest(f"partial-checkpoint-{kind}"),
            consequential_action_ids=(),
            duplicate_consequential_actions=0,
            lost_record_count=0,
            affected_work_paused=kind in {"quota", "network"},
            resumed_from_checkpoint=kind == "crash",
            fallback_schema_preserved=True,
            verification_rungs_preserved=True,
            fabricated_progress=False,
            observed_at=NOW,
        )
        for kind in ("crash", "quota", "network")
    )
    partial = evaluate_failure_drills(
        FROZEN_OPERATIONS_CONTRACT,
        plan,
        rows,
    )
    assert partial.reason_codes == ("missing_failure_drill",)


def test_prior_slice_rejects_provisional_or_deputy_status():
    for status in (
        "implementation_complete",
        "TEMPORARY_SOL_DEPUTY_PENDING_FABLE_RATIFICATION",
    ):
        with pytest.raises(ValueError, match="independent certification"):
            record_prior_slice_certification(
                FROZEN_RELEASE_CERTIFICATION_CONTRACT,
                slice_id="JAA-15",
                source_git_revision=digest("git"),
                source_tree_sha256=digest("tree"),
                source_content_revision=digest("content"),
                receipt_sha256=digest("receipt"),
                independent_ruling_sha256=digest("ruling"),
                certification_status=status,
            )


def test_unverified_runtime_evidence_blocks_release_review():
    candidate = release_candidate(
        priors=prior_certifications(),
        evidence=release_evidence(independently_verified=False),
    )
    assessment = assess_release_candidate(
        FROZEN_RELEASE_CERTIFICATION_CONTRACT,
        candidate,
    )
    assert "unverified_release_evidence" in assessment.reason_codes
    assert "drill_runtime_not_independently_verified" in assessment.reason_codes
    assert assessment.release_certificate_id is None


@pytest.mark.parametrize(
    "contamination_field",
    [
        "person_specific_items",
        "test_data_items",
        "claim_items",
        "credential_items",
        "host_path_items",
    ],
)
def test_distribution_contamination_blocks_release_review(
    contamination_field,
):
    values = {
        "person_specific_items": 0,
        "test_data_items": 0,
        "claim_items": 0,
        "credential_items": 0,
        "host_path_items": 0,
    }
    values[contamination_field] = 1
    scan = record_distribution_scan(
        FROZEN_RELEASE_CERTIFICATION_CONTRACT,
        artifact_version="0.1.0-candidate",
        artifact_sha256=digest("artifact"),
        scanner_report_sha256=digest("scanner-report"),
        scanned_at=NOW,
        **values,
    )
    assessment = assess_release_candidate(
        FROZEN_RELEASE_CERTIFICATION_CONTRACT,
        release_candidate(
            priors=prior_certifications(),
            evidence=release_evidence(),
            scan=scan,
        ),
    )
    assert "distributable_contamination" in assessment.reason_codes
    assert assessment.released is False


def test_candidate_rejects_artifact_scan_mismatch():
    scan = record_distribution_scan(
        FROZEN_RELEASE_CERTIFICATION_CONTRACT,
        artifact_version="0.1.0-candidate",
        artifact_sha256=digest("different-artifact"),
        person_specific_items=0,
        test_data_items=0,
        claim_items=0,
        credential_items=0,
        host_path_items=0,
        scanner_report_sha256=digest("scanner-report"),
        scanned_at=NOW,
    )
    with pytest.raises(ValueError, match="mixes plan or artifact"):
        compile_release_candidate(
            FROZEN_RELEASE_CERTIFICATION_CONTRACT,
            artifact_version="0.1.0-candidate",
            artifact_sha256=digest("artifact"),
            operations_plan=operations_plan(),
            drill_assessment=drill_suite(),
            prior_certifications=(),
            release_evidence=(),
            distribution_scan=scan,
        )


def test_release_evidence_rejects_unknown_kind_and_naive_time():
    with pytest.raises(ValueError, match="invalid"):
        record_release_evidence_reference(
            FROZEN_RELEASE_CERTIFICATION_CONTRACT,
            evidence_kind="marketing_claim",
            artifact_version="0.1.0-candidate",
            environment="local",
            evidence_sha256=digest("evidence"),
            observed_at=NOW,
            independently_verified=False,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        record_release_evidence_reference(
            FROZEN_RELEASE_CERTIFICATION_CONTRACT,
            evidence_kind="privacy_controls",
            artifact_version="0.1.0-candidate",
            environment="local",
            evidence_sha256=digest("evidence"),
            observed_at=NOW.replace(tzinfo=None),
            independently_verified=False,
        )


def test_release_assessment_cannot_be_forged_into_certificate():
    assessment = assess_release_candidate(
        FROZEN_RELEASE_CERTIFICATION_CONTRACT,
        release_candidate(),
    )
    with pytest.raises(ValueError, match="cannot release or certify"):
        replace(
            assessment,
            release_certificate_id=digest("fake-certificate"),
            released=True,
            production_certification="granted",
            certifies_slice=True,
        )
