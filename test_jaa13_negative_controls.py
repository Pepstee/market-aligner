"""Adversarial controls for the bounded local JAA-13 contract."""

from __future__ import annotations

import json
import hashlib
from dataclasses import replace
from datetime import date, timedelta

import pytest

from career_automation.interview_communication import (
    FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
    InterviewCommunicationContract,
    PreparationItem,
    compile_follow_up_draft_plan,
    compile_interview_preparation_pack,
    compile_local_debrief_evidence,
)
from career_automation.models import PipelineState
from test_jaa07_independent_acceptance import _source
from test_jaa13_independent_acceptance import (
    APPLICATION_ID,
    BASE_TIME,
    RELEASED_SHA256,
    _pack,
    _timeline,
)


def _selections():
    source, _strategy = _source()
    candidate_ids = tuple(
        row.sentence_id for row in source.facts if row.fact_kind == "candidate"
    )
    employer_ids = tuple(
        row.sentence_id for row in source.facts if row.fact_kind == "employer"
    )
    return source, candidate_ids, employer_ids


def _debrief():
    return compile_local_debrief_evidence(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        _timeline(),
        source_record_id="debrief-negative-control",
        raw_debrief_bytes=b"local notes",
        recorded_at=BASE_TIME + timedelta(hours=4),
    )


def test_noncanonical_contract_is_rejected() -> None:
    contract = FROZEN_INTERVIEW_COMMUNICATION_CONTRACT
    with pytest.raises(ValueError, match="differs from accepted"):
        InterviewCommunicationContract(
            upstream_status_contract_sha256="0" * 64,
            preparation_policy_sha256=contract.preparation_policy_sha256,
            debrief_policy_sha256=contract.debrief_policy_sha256,
            draft_policy_sha256=contract.draft_policy_sha256,
        )
    with pytest.raises(ValueError, match="cannot act or certify"):
        replace(contract, message_send_authority="granted")


def test_tampered_application_source_cannot_enter_preparation() -> None:
    source, candidate_ids, employer_ids = _selections()
    with pytest.raises(ValueError, match="identity differs"):
        compile_interview_preparation_pack(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            application_id=APPLICATION_ID,
            released_application_sha256=RELEASED_SHA256,
            source=replace(source, role_title="Different role"),
            timeline=_timeline(),
            as_of=date(2030, 1, 3),
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )


def test_preparation_requires_matching_interview_stage_inputs() -> None:
    source, candidate_ids, employer_ids = _selections()
    with pytest.raises(ValueError, match="interview-stage"):
        compile_interview_preparation_pack(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            application_id=APPLICATION_ID,
            released_application_sha256=RELEASED_SHA256,
            source=source,
            timeline=_timeline(final_state=PipelineState.SCREENING),
            as_of=date(2030, 1, 3),
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )
    with pytest.raises(ValueError, match="different application"):
        compile_interview_preparation_pack(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            application_id="another-application",
            released_application_sha256=RELEASED_SHA256,
            source=source,
            timeline=_timeline(),
            as_of=date(2030, 1, 3),
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )


def test_unknown_duplicate_or_wrong_kind_fact_selection_fails() -> None:
    source, candidate_ids, employer_ids = _selections()
    base = {
        "contract": FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        "application_id": APPLICATION_ID,
        "released_application_sha256": RELEASED_SHA256,
        "source": source,
        "timeline": _timeline(),
        "as_of": date(2030, 1, 3),
    }
    with pytest.raises(ValueError, match="unknown fact"):
        compile_interview_preparation_pack(
            **base,
            candidate_sentence_ids=("f" * 64,),
            employer_sentence_ids=employer_ids,
        )
    with pytest.raises(ValueError, match="non-empty and unique"):
        compile_interview_preparation_pack(
            **base,
            candidate_sentence_ids=(candidate_ids[0], candidate_ids[0]),
            employer_sentence_ids=employer_ids,
        )
    with pytest.raises(ValueError, match="candidate fact"):
        compile_interview_preparation_pack(
            **base,
            candidate_sentence_ids=employer_ids,
            employer_sentence_ids=employer_ids,
        )


def test_stale_or_future_employer_guidance_requires_refresh() -> None:
    source, candidate_ids, employer_ids = _selections()
    with pytest.raises(ValueError, match="stale.*refresh"):
        compile_interview_preparation_pack(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            application_id=APPLICATION_ID,
            released_application_sha256=RELEASED_SHA256,
            source=source,
            timeline=_timeline(),
            as_of=date(2032, 1, 3),
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )
    with pytest.raises(ValueError, match="future employer evidence"):
        compile_interview_preparation_pack(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            application_id=APPLICATION_ID,
            released_application_sha256=RELEASED_SHA256,
            source=source,
            timeline=_timeline(),
            as_of=date(2029, 1, 3),
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )


def test_direct_pack_construction_cannot_bypass_freshness_policy() -> None:
    pack, _source_row = _pack()
    with pytest.raises(ValueError, match="deadline differs from policy"):
        replace(
            pack.employer_authorities[0],
            freshness_deadline="2032-01-02",
        )

    for as_of, message in (
        ("2029-01-03", "future employer evidence"),
        ("2032-01-03", "stale.*refresh"),
    ):
        body = pack.document(include_identity=False)
        body["as_of"] = as_of
        pack_id = hashlib.sha256(
            json.dumps(
                body,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        with pytest.raises(ValueError, match=message):
            type(pack)(**{
                **vars(pack),
                "as_of": as_of,
                "pack_id": pack_id,
            })


def test_preparation_pack_tamper_cannot_claim_action_or_new_authority() -> None:
    pack, _source_row = _pack()
    with pytest.raises(ValueError, match="cannot act or certify"):
        replace(pack, source_refresh_authority="granted")
    with pytest.raises(ValueError, match="differs from exact content"):
        replace(pack, as_of="2030-01-04")
    with pytest.raises(ValueError, match="unknown authority"):
        original = pack.items[0]
        body = {
            "kind": original.kind,
            "prompt": original.prompt,
            "authority_ids": ("0" * 64,),
        }
        item = PreparationItem(
            hashlib.sha256(
                json.dumps(
                    body,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            ).hexdigest(),
            original.kind,
            original.prompt,
            ("0" * 64,),
        )
        replace(pack, items=(item, *pack.items[1:]))
    with pytest.raises(ValueError, match="item differs from exact content"):
        replace(pack.items[0], prompt="A changed preparation prompt.")
    with pytest.raises(ValueError, match="different contract"):
        replace(pack, contract_sha256="0" * 64)


def test_debrief_requires_bytes_typed_timeline_and_interview_stage() -> None:
    with pytest.raises(ValueError, match="bytes are required"):
        compile_local_debrief_evidence(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            _timeline(),
            source_record_id="empty",
            raw_debrief_bytes=b"",
            recorded_at=BASE_TIME,
        )
    with pytest.raises(TypeError, match="StatusTimeline"):
        compile_local_debrief_evidence(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            object(),
            source_record_id="wrong-type",
            raw_debrief_bytes=b"notes",
            recorded_at=BASE_TIME,
        )
    with pytest.raises(ValueError, match="interview-stage"):
        compile_local_debrief_evidence(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            _timeline(final_state=PipelineState.SCREENING),
            source_record_id="screening",
            raw_debrief_bytes=b"notes",
            recorded_at=BASE_TIME,
        )


def test_debrief_tamper_cannot_promote_unverified_notes_to_facts() -> None:
    debrief = _debrief()
    with pytest.raises(ValueError, match="cannot become fact authority"):
        replace(debrief, candidate_fact_authority=True)
    with pytest.raises(ValueError, match="cannot become fact authority"):
        replace(debrief, assertion_status="verified_fact")
    with pytest.raises(ValueError, match="differs from exact content"):
        replace(debrief, source_record_id="different")
    with pytest.raises(ValueError, match="different contract"):
        replace(debrief, contract_sha256="0" * 64)


def test_draft_plan_rejects_unknown_duplicate_or_cross_application_facts() -> None:
    pack, _source_row = _pack()
    debrief = _debrief()
    with pytest.raises(ValueError, match="unknown or duplicate"):
        compile_follow_up_draft_plan(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            pack,
            debrief,
            factual_authority_ids=("0" * 64,),
            connective_text=("Thank you for your time.",),
        )
    known = pack.candidate_authorities[0].sentence_id
    with pytest.raises(ValueError, match="unknown or duplicate"):
        compile_follow_up_draft_plan(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            pack,
            debrief,
            factual_authority_ids=(known, known),
            connective_text=("Thank you for your time.",),
        )
    with pytest.raises(ValueError, match="different authority"):
        compile_follow_up_draft_plan(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            pack,
            compile_local_debrief_evidence(
                FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
                _timeline(final_state=PipelineState.FINAL_STAGE),
                source_record_id="different-timeline",
                raw_debrief_bytes=b"local notes from a different timeline",
                recorded_at=BASE_TIME + timedelta(hours=5),
            ),
            factual_authority_ids=(known,),
            connective_text=("Thank you for your time.",),
        )


@pytest.mark.parametrize(
    "text",
    (
        "I am writing to express my interest.",
        "This is a pivotal opportunity.",
        "Let me know if you need anything.",
        "Results matter \u2014 especially here.",
        "Improved delivery by 40 percent.",
    ),
)
def test_draft_connective_rejects_ai_cliches_or_new_fact_tokens(text: str) -> None:
    pack, _source_row = _pack()
    with pytest.raises(ValueError, match="natural-language|fact-like"):
        compile_follow_up_draft_plan(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            pack,
            _debrief(),
            factual_authority_ids=(
                pack.candidate_authorities[0].sentence_id,
            ),
            connective_text=(text,),
        )


def test_draft_plan_tamper_cannot_claim_release_send_or_certification() -> None:
    pack, _source_row = _pack()
    plan = compile_follow_up_draft_plan(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        pack,
        _debrief(),
        factual_authority_ids=(pack.candidate_authorities[0].sentence_id,),
        connective_text=("Thank you for your time.",),
    )
    for field, value in (
        ("debrief_fact_authority", True),
        ("operator_confirmation_required", False),
        ("truth_release_authority", "granted"),
        ("connector_authority", "granted"),
        ("send_authority", "granted"),
        ("sent_count", 1),
        ("dependency_satisfied", True),
        ("certifies_slice", True),
    ):
        with pytest.raises(ValueError, match="cannot claim truth release or send"):
            replace(plan, **{field: value})
    with pytest.raises(ValueError, match="differs from exact content"):
        replace(plan, connective_text=("A different note.",))
    with pytest.raises(ValueError, match="different contract"):
        replace(plan, contract_sha256="0" * 64)
