"""Adversarial controls for the bounded local JAA-13 contract."""

from __future__ import annotations

import base64
import json
import hashlib
from dataclasses import replace
from datetime import date, timedelta

import pytest

from career_automation.browser_workflows import fixture_submit_event_sha256
from career_automation.interview_communication import (
    EmbeddedPublicCapture,
    EmployerDossierEvidence,
    FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
    InterviewCommunicationContract,
    PreparationItem,
    compile_follow_up_draft_plan,
    compile_interview_preparation_pack,
    compile_local_debrief_evidence,
    compile_local_submission_context,
)
from career_automation.models import PipelineState
from career_automation.release_gate import (
    compile_release_manifest,
)
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    classify_status_evidence,
    compile_local_export_evidence,
    compile_status_timeline,
)
from test_jaa13_independent_acceptance import (
    APPLICATION_ID,
    BASE_TIME,
    SUBMISSION_RUN_ID,
    SUBMISSION_STEP_ID,
    SUBMISSION_WORKFLOW,
    _canonical_json,
    _hash,
    _pack,
    _timeline,
)


def _selections():
    pack, source = _pack()
    candidate_ids = tuple(
        row.sentence_id for row in source.facts if row.fact_kind == "candidate"
    )
    employer_ids = tuple(
        row.sentence_id for row in source.facts if row.fact_kind == "employer"
    )
    return pack, source, candidate_ids, employer_ids


def _preparation_base():
    pack, source = _pack()
    return {
        "contract": FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        "application_id": APPLICATION_ID,
        "source": source,
        "timeline": pack.timeline,
        "release_manifest": pack.release_manifest,
        "publication_receipt": pack.publication_receipt,
        "submission_context": pack.submission_context,
        "submission_proof": pack.submission_proof,
        "fixture_receipt": pack.fixture_receipt,
        "employer_evidence": pack.employer_evidence,
        "as_of": date(2030, 1, 3),
    }


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
    _pack_row, source, candidate_ids, employer_ids = _selections()
    base = _preparation_base()
    with pytest.raises(ValueError, match="identity differs"):
        compile_interview_preparation_pack(
            **{
                **base,
                "source": replace(source, role_title="Different role"),
            },
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )


def test_preparation_requires_matching_interview_stage_inputs() -> None:
    _pack_row, _source_row, candidate_ids, employer_ids = _selections()
    base = _preparation_base()
    with pytest.raises(ValueError, match="interview-stage"):
        compile_interview_preparation_pack(
            **{
                **base,
                "timeline": _timeline(
                    final_state=PipelineState.SCREENING
                ),
            },
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )
    with pytest.raises(ValueError, match="different application"):
        compile_interview_preparation_pack(
            **{
                **base,
                "application_id": "another-application",
            },
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )


@pytest.mark.parametrize(
    "changes",
    (
        {"token_sha256": "e" * 64},
        {"screenshot_sha256": "d" * 64},
        {"field_map_sha256": "c" * 64},
        {"submit_event_sha256": "f" * 64},
    ),
)
def test_preparation_rejects_inconsistent_submission_proof(
    changes: dict[str, str],
) -> None:
    _pack_row, _source_row, candidate_ids, employer_ids = _selections()
    base = _preparation_base()
    with pytest.raises(
        ValueError,
        match="submission proof differs|submit event differs",
    ):
        compile_interview_preparation_pack(
            **{
                **base,
                "submission_proof": replace(
                    base["submission_proof"],
                    **changes,
                ),
            },
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )


@pytest.mark.parametrize(
    "field",
    ("run_id", "workflow", "step_id"),
)
def test_preparation_rederives_event_from_exact_jaa09_context(
    field: str,
) -> None:
    _pack_row, _source_row, candidate_ids, employer_ids = _selections()
    base = _preparation_base()
    context_values = {
        "run_id": SUBMISSION_RUN_ID,
        "workflow": SUBMISSION_WORKFLOW,
        "step_id": SUBMISSION_STEP_ID,
        "release_manifest_sha256": (
            base["submission_context"].release_manifest_sha256
        ),
        "token_sha256": base["submission_context"].token_sha256,
        "field_map_sha256": base["submission_context"].field_map_sha256,
    }
    if field == "run_id":
        context_values["run_id"] = "run:different-local-fixture"
    elif field == "workflow":
        context_values["workflow"] = replace(
            SUBMISSION_WORKFLOW,
            name="jaa13_different_local_fixture_submission",
        )
    else:
        changed_step_id = "different-submit-step"
        context_values["workflow"] = replace(
            SUBMISSION_WORKFLOW,
            actions=(
                replace(
                    SUBMISSION_WORKFLOW.actions[0],
                    step_id=changed_step_id,
                ),
            ),
        )
        context_values["step_id"] = changed_step_id
    context = compile_local_submission_context(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        **context_values,
    )
    with pytest.raises(ValueError, match="submit event differs"):
        compile_interview_preparation_pack(
            **{
                **base,
                "submission_context": context,
            },
            candidate_sentence_ids=candidate_ids,
            employer_sentence_ids=employer_ids,
        )


def test_unknown_duplicate_or_wrong_kind_fact_selection_fails() -> None:
    _pack_row, _source_row, candidate_ids, employer_ids = _selections()
    base = _preparation_base()
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
    pack, _source_row = _pack()
    with pytest.raises(ValueError, match="stale.*refresh|as-of"):
        replace(pack, as_of="2032-01-03")
    with pytest.raises(
        ValueError,
        match="predates status timeline|future employer evidence",
    ):
        replace(pack, as_of="2029-01-03")


def test_direct_pack_construction_cannot_bypass_freshness_policy() -> None:
    pack, _source_row = _pack()
    with pytest.raises(ValueError, match="deadline differs from policy"):
        replace(
            pack.employer_authorities[0],
            freshness_deadline="2032-01-02",
        )

    with pytest.raises(ValueError, match="predates status timeline"):
        replace(pack, as_of="2029-01-03")
    with pytest.raises(ValueError, match="stale.*refresh|as-of"):
        replace(pack, as_of="2032-01-03")


def test_preparation_pack_tamper_cannot_claim_action_or_new_authority() -> None:
    pack, _source_row = _pack()
    with pytest.raises(ValueError, match="cannot act or certify"):
        replace(pack, source_refresh_authority="granted")
    with pytest.raises(ValueError, match="as-of|differs from exact content"):
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


def test_pack_revalidates_candidate_authority_from_embedded_source() -> None:
    pack, _source_row = _pack()
    forged = replace(
        pack.candidate_authorities[0],
        candidate_claim_id="not-approved",
        candidate_evidence_id="not-verified",
    )
    with pytest.raises(ValueError, match="embedded source lineage"):
        replace(
            pack,
            candidate_authorities=(
                forged,
                *pack.candidate_authorities[1:],
            ),
        )


def test_release_publication_proof_and_receipt_lineage_cannot_drift() -> None:
    pack, _source_row = _pack()
    changed_binding = replace(
        pack.release_manifest.binding,
        application_source_id="0" * 64,
    )
    changed_validations = tuple(
        replace(row, input_sha256=changed_binding.input_sha256)
        for row in pack.release_manifest.validations
    )
    changed_manifest = compile_release_manifest(
        changed_binding,
        changed_validations,
    )
    with pytest.raises(ValueError, match="different source bytes"):
        replace(pack, release_manifest=changed_manifest)

    publication = replace(
        pack.publication_receipt,
        source_id="f" * 64,
        receipt_sha256="0" * 64,
    )
    publication = replace(
        publication,
        receipt_sha256=_hash(
            publication.document(include_receipt_hash=False)
        ),
    )
    with pytest.raises(ValueError, match="different source bytes"):
        replace(pack, publication_receipt=publication)

    with pytest.raises(ValueError, match="submission proof differs"):
        replace(
            pack,
            submission_proof=replace(
                pack.submission_proof,
                release_manifest_sha256="e" * 64,
            ),
        )

    fixture = replace(
        pack.fixture_receipt,
        job_key="different:job",
        receipt_id="0" * 64,
    )
    fixture = replace(
        fixture,
        receipt_id=_hash(fixture.document(include_identity=False)),
    )
    changed_proof = replace(
        pack.submission_proof,
        receipt_id=fixture.receipt_id,
        submit_event_sha256=fixture_submit_event_sha256(
            run_id=pack.submission_context.run_id,
            workflow_sha256=pack.submission_context.workflow_sha256,
            step_id=pack.submission_context.step_id,
            release_manifest_sha256=(
                pack.submission_context.release_manifest_sha256
            ),
            receipt_id=fixture.receipt_id,
            receipt_payload_sha256=fixture.payload_sha256,
            screenshot_sha256=pack.submission_proof.screenshot_sha256,
            field_map_sha256=pack.submission_context.field_map_sha256,
        ),
    )
    with pytest.raises(ValueError, match="different application"):
        replace(
            pack,
            fixture_receipt=fixture,
            submission_proof=changed_proof,
        )


def test_employer_dossier_rejects_nested_protected_information() -> None:
    pack, _source_row = _pack()
    evidence = pack.employer_evidence
    dossier = evidence.dossier()
    dossier["claims"][0]["details"] = {  # type: ignore[index]
        "health": "private medical condition"
    }
    dossier_json = _canonical_json(dossier)
    dossier_sha256 = _hash(dossier)
    body = evidence.document(include_identity=False)
    body["dossier_json"] = dossier_json
    body["dossier_sha256"] = dossier_sha256
    with pytest.raises(ValueError, match="protected or private information"):
        replace(
            evidence,
            dossier_json=dossier_json,
            dossier_sha256=dossier_sha256,
            evidence_id=_hash(body),
        )


def test_employer_dossier_rejects_nested_private_prose() -> None:
    pack, _source_row = _pack()
    evidence = pack.employer_evidence
    dossier = evidence.dossier()
    dossier["claims"][0]["details"] = {  # type: ignore[index]
        "notes": "Your private medical condition explains the team decision."
    }
    dossier_json = _canonical_json(dossier)
    dossier_sha256 = _hash(dossier)
    body = evidence.document(include_identity=False)
    body["dossier_json"] = dossier_json
    body["dossier_sha256"] = dossier_sha256
    with pytest.raises(ValueError, match="protected or private information"):
        replace(
            evidence,
            dossier_json=dossier_json,
            dossier_sha256=dossier_sha256,
            evidence_id=_hash(body),
        )


def test_pack_rejects_rehashed_employer_authority_drift() -> None:
    pack, _source_row = _pack()
    forged = replace(
        pack.employer_authorities[0],
        source_urls=("https://8.8.4.4/forged-source",),
    )
    with pytest.raises(ValueError, match="embedded source lineage"):
        replace(pack, employer_authorities=(forged,))


def test_employer_guidance_does_not_promote_unapproved_excerpt_tail() -> None:
    pack, source = _pack()
    evidence = pack.employer_evidence
    dossier = evidence.dossier()
    authority = pack.employer_authorities[0]
    claim = next(
        row
        for row in dossier["claims"]  # type: ignore[union-attr]
        if row["id"] == authority.employer_claim_id
    )
    source_row = next(
        row
        for row in dossier["sources"]  # type: ignore[union-attr]
        if row["id"] == claim["source_ids"][0]
    )
    plan_row = next(
        row
        for row in dossier["source_plan"]  # type: ignore[union-attr]
        if row["id"] == claim["source_plan_id"]
    )
    approved = next(
        row.approved_source_text
        for row in source.facts
        if row.sentence_id == authority.sentence_id
    )
    excerpt = f"<p>{approved} The company also guarantees the role.</p>"
    content = excerpt.encode()
    content_sha256 = hashlib.sha256(content).hexdigest()
    claim["citation_excerpt"] = excerpt
    source_row["content_sha256"] = content_sha256
    plan_row["excerpt_sha256"] = content_sha256
    captures = tuple(
        EmbeddedPublicCapture(
            raw_response_ref=row.raw_response_ref,
            content_sha256=(
                content_sha256
                if row.raw_response_ref == source_row["raw_response_ref"]
                else row.content_sha256
            ),
            content_base64=(
                base64.b64encode(content).decode()
                if row.raw_response_ref == source_row["raw_response_ref"]
                else row.content_base64
            ),
        )
        for row in evidence.captures
    )
    dossier_json = _canonical_json(dossier)
    dossier_sha256 = _hash(dossier)
    body = {
        "schema_version": evidence.schema_version,
        "dossier_json": dossier_json,
        "captures": tuple(row.document() for row in captures),
        "as_of": evidence.as_of,
        "dossier_sha256": dossier_sha256,
        "authority_claim": "structural_public_lineage_only",
    }
    tainted = EmployerDossierEvidence(
        dossier_json=dossier_json,
        captures=captures,
        as_of=evidence.as_of,
        dossier_sha256=dossier_sha256,
        evidence_id=_hash(body),
    )
    candidate_ids = tuple(
        row.sentence_id
        for row in source.facts
        if row.fact_kind == "candidate"
    )
    employer_ids = tuple(
        row.sentence_id
        for row in source.facts
        if row.fact_kind == "employer"
    )
    rebuilt = compile_interview_preparation_pack(
        **{
            **_preparation_base(),
            "employer_evidence": tainted,
        },
        candidate_sentence_ids=candidate_ids,
        employer_sentence_ids=employer_ids,
    )
    assert rebuilt.employer_authorities[0].citation_excerpt == approved
    assert "guarantees the role" not in (
        rebuilt.employer_authorities[0].citation_excerpt
    )


def test_preparation_as_of_cannot_predate_latest_timeline_evidence() -> None:
    pack, _source_row = _pack()
    observations = []
    for index, code in enumerate(
        ("under_review", "interview_requested")
    ):
        raw = compile_local_export_evidence(
            FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
            application_id=APPLICATION_ID,
            job_key=pack.job_key,
            source_kind="local_portal_export",
            source_record_id=f"future-status-{index}",
            raw_export_bytes=code.encode(),
            observed_at=BASE_TIME.replace(year=2032)
            + timedelta(hours=index),
        )
        observations.append(
            classify_status_evidence(
                FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
                raw,
                explicit_status_code=code,
            )
        )
    future_timeline = compile_status_timeline(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
        application_id=APPLICATION_ID,
        job_key=pack.job_key,
        observations=tuple(observations),
    )
    with pytest.raises(ValueError, match="predates status timeline"):
        replace(pack, timeline=future_timeline)


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
            connective_template_ids=("thank_you_for_time",),
        )
    known = pack.candidate_authorities[0].sentence_id
    with pytest.raises(ValueError, match="unknown or duplicate"):
        compile_follow_up_draft_plan(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            pack,
            debrief,
            factual_authority_ids=(known, known),
            connective_template_ids=("thank_you_for_time",),
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
            connective_template_ids=("thank_you_for_time",),
        )


@pytest.mark.parametrize(
    "text",
    (
        "I am writing to express my interest.",
        "This is a pivotal opportunity.",
        "Let me know if you need anything.",
        "Results matter \u2014 especially here.",
        "Improved delivery by 40 percent.",
        "I led the migration and the interviewer promised me the role.",
        "Your private medical condition explains the team decision.",
    ),
)
def test_draft_connective_rejects_arbitrary_prose(text: str) -> None:
    pack, _source_row = _pack()
    with pytest.raises(ValueError, match="template is unsupported"):
        compile_follow_up_draft_plan(
            FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
            pack,
            _debrief(),
            factual_authority_ids=(
                pack.candidate_authorities[0].sentence_id,
            ),
            connective_template_ids=(text,),
        )


def test_draft_plan_tamper_cannot_claim_release_send_or_certification() -> None:
    pack, _source_row = _pack()
    plan = compile_follow_up_draft_plan(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        pack,
        _debrief(),
        factual_authority_ids=(pack.candidate_authorities[0].sentence_id,),
        connective_template_ids=("thank_you_for_time",),
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
    with pytest.raises(ValueError, match="template is unsupported"):
        replace(plan, connective_template_ids=("caller-authored",))
    forged_ids = ("0" * 64,)
    forged_body = plan.document(include_identity=False)
    forged_body["factual_authority_ids"] = forged_ids
    with pytest.raises(ValueError, match="embedded fact authority"):
        replace(
            plan,
            factual_authority_ids=forged_ids,
            draft_plan_id=_hash(forged_body),
        )
    with pytest.raises(ValueError, match="different contract"):
        replace(plan, contract_sha256="0" * 64)
