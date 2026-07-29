"""Independent acceptance for the bounded local JAA-13 contract."""

from __future__ import annotations

import hashlib
from datetime import date, datetime, timedelta, timezone

from career_automation.interview_communication import (
    FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
    compile_follow_up_draft_plan,
    compile_interview_preparation_pack,
    compile_local_debrief_evidence,
)
from career_automation.models import PipelineState
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    classify_status_evidence,
    compile_local_export_evidence,
    compile_status_timeline,
)
from test_jaa07_independent_acceptance import _source


APPLICATION_ID = "application:local-interview-fixture"
BASE_TIME = datetime(2030, 1, 2, 9, 0, tzinfo=timezone.utc)
RELEASED_SHA256 = hashlib.sha256(b"released-application").hexdigest()


def _timeline(*, final_state: PipelineState = PipelineState.INTERVIEW):
    source, _strategy = _source()
    codes = ["under_review"]
    if final_state is not PipelineState.SCREENING:
        codes.append("interview_requested")
    if final_state is PipelineState.FINAL_STAGE:
        codes.append("final_stage")
    observations = []
    for index, code in enumerate(codes):
        raw = compile_local_export_evidence(
            FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
            application_id=APPLICATION_ID,
            job_key=source.job_key,
            source_kind="local_portal_export",
            source_record_id=f"status-{index}",
            raw_export_bytes=code.encode(),
            observed_at=BASE_TIME + timedelta(hours=index),
        )
        observations.append(
            classify_status_evidence(
                FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
                raw,
                explicit_status_code=code,
            )
        )
    return compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=source.job_key,
        observations=tuple(observations),
    )


def _pack():
    source, _strategy = _source()
    candidate_ids = tuple(
        row.sentence_id for row in source.facts if row.fact_kind == "candidate"
    )
    employer_ids = tuple(
        row.sentence_id for row in source.facts if row.fact_kind == "employer"
    )
    pack = compile_interview_preparation_pack(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        application_id=APPLICATION_ID,
        released_application_sha256=RELEASED_SHA256,
        source=source,
        timeline=_timeline(),
        as_of=date(2030, 1, 3),
        candidate_sentence_ids=candidate_ids,
        employer_sentence_ids=employer_ids,
    )
    return pack, source


def test_contract_is_content_addressed_and_withholds_every_action() -> None:
    contract = FROZEN_INTERVIEW_COMMUNICATION_CONTRACT
    document = contract.document()
    assert len(contract.contract_sha256) == 64
    assert document["source_refresh_authority"] == "withheld"
    assert document["candidate_fact_mutation_authority"] is False
    assert document["private_person_inference"] is False
    assert document["connector_authority"] == "withheld"
    assert document["message_send_authority"] == "withheld"
    assert document["dependency_satisfied"] is False
    assert document["certifies_slice"] is False


def test_preparation_pack_reuses_exact_fact_authority_and_current_sources() -> None:
    pack, source = _pack()
    replay, _source_again = _pack()
    assert replay == pack
    assert pack.application_source_id == source.source_id
    assert pack.application_source_content_sha256 == source.content_sha256
    assert {row.kind for row in pack.items} == {
        "candidate_story",
        "likely_objection",
        "technical_drill",
        "candidate_question",
    }
    by_id = {row.sentence_id: row for row in source.facts}
    for row in pack.candidate_authorities:
        fact = by_id[row.sentence_id]
        assert row.approved_text_sha256 == hashlib.sha256(
            fact.approved_source_text.encode()
        ).hexdigest()
        assert row.candidate_evidence_id == fact.authority.candidate_evidence_id
    for row in pack.employer_authorities:
        assert row.source_ids == ("source:official-company",)
        assert row.freshness_status == "current"
        assert row.private_person_inference is False
    assert pack.source_refresh_authority == "withheld"
    assert pack.dependency_satisfied is False
    assert pack.certifies_slice is False


def test_local_debrief_is_hashed_not_retained_and_never_becomes_fact() -> None:
    raw = b"The interviewer asked about delivery tradeoffs."
    evidence = compile_local_debrief_evidence(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        _timeline(),
        source_record_id="local-debrief-1",
        raw_debrief_bytes=raw,
        recorded_at=BASE_TIME + timedelta(hours=3),
    )
    assert evidence.source_sha256 == hashlib.sha256(raw).hexdigest()
    assert raw.decode() not in repr(evidence)
    assert raw.decode() not in str(evidence.document())
    assert evidence.assertion_status == "unverified_operator_statement"
    assert evidence.candidate_fact_authority is False
    assert evidence.employer_fact_authority is False
    assert evidence.dependency_satisfied is False


def test_follow_up_plan_is_natural_fact_bound_and_non_sendable() -> None:
    pack, _source_row = _pack()
    debrief = compile_local_debrief_evidence(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        _timeline(),
        source_record_id="local-debrief-1",
        raw_debrief_bytes=b"Conversation notes",
        recorded_at=BASE_TIME + timedelta(hours=3),
    )
    facts = (
        pack.candidate_authorities[0].sentence_id,
        pack.employer_authorities[0].sentence_id,
    )
    plan = compile_follow_up_draft_plan(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        pack,
        debrief,
        factual_authority_ids=facts,
        connective_text=(
            "Thank you for your time.",
            "Kind regards.",
        ),
    )
    assert plan.factual_authority_ids == facts
    assert plan.debrief_fact_authority is False
    assert plan.operator_confirmation_required is True
    assert plan.truth_release_authority == "withheld"
    assert plan.connector_authority == "withheld"
    assert plan.send_authority == "withheld"
    assert plan.sent_count == 0
    assert plan.dependency_satisfied is False
    assert plan.certifies_slice is False
