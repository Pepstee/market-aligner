"""Independent acceptance for the bounded local JAA-13 contract."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from tempfile import TemporaryDirectory

from career_automation.application_artifacts import (
    ARTIFACT_FILENAMES,
    ArtifactFileReceipt,
    PublishedArtifactReceipt,
)
from career_automation.ats_fixture import FixtureReceipt
from career_automation.browser_workflows import (
    ActionKind,
    BrowserAction,
    BrowserWorkflow,
    SelectorCandidate,
    SelectorPlan,
    SelectorStrategy,
    SubmissionProof,
    fixture_submit_event_sha256,
)
from career_automation.employer_research import (
    FRESHNESS_DAYS,
    RawResponseCache,
)
from career_automation.interview_communication import (
    FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
    compile_employer_dossier_evidence,
    compile_follow_up_draft_plan,
    compile_interview_preparation_pack,
    compile_local_submission_context,
    compile_local_debrief_evidence,
)
from career_automation.models import PipelineState
from career_automation.release_gate import (
    REQUIRED_VALIDATORS,
    OfficialRouteBinding,
    ReleaseBinding,
    ValidationReceipt,
    WorkRightBinding,
    compile_release_manifest,
)
from career_automation.status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    classify_status_evidence,
    compile_local_export_evidence,
    compile_status_timeline,
)
from test_jaa07_independent_acceptance import _source


APPLICATION_ID = "application:local-interview-fixture"
BASE_TIME = datetime(2030, 1, 2, 9, 0, tzinfo=timezone.utc)
SUBMISSION_RUN_ID = "run:local-interview-fixture"
SUBMISSION_STEP_ID = "submit"
SUBMISSION_WORKFLOW = BrowserWorkflow(
    "jaa13_local_fixture_submission",
    (
        BrowserAction(
            SUBMISSION_STEP_ID,
            ActionKind.SUBMIT,
            selectors=SelectorPlan(
                (
                    SelectorCandidate(
                        SelectorStrategy.TEST_ID,
                        "final-submit",
                    ),
                )
            ),
            required_output_keys=(
                "receipt_id",
                "receipt_payload_sha256",
                "screenshot_sha256",
                "field_map_sha256",
                "submit_event_sha256",
            ),
        ),
    ),
)
KINDS = ("company", "role", "product", "hiring", "operational_health")
EXCERPTS = {
    "company": (
        "The company confirms that Example Ltd operates a documented service."
    ),
    "role": "This role has documented job responsibilities and duties.",
    "product": "The product platform provides a service for customers.",
    "hiring": "The careers vacancy invites candidates to apply through hiring.",
    "operational_health": (
        "In 2030 the company reported current operational revenue and profit."
    ),
}


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


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


def _employer_evidence(source):
    employer_fact = next(
        row for row in source.facts if row.fact_kind == "employer"
    )
    fact_document = json.loads(employer_fact.employer_fact_json)
    with TemporaryDirectory(prefix="jaa13-employer-") as directory:
        cache = RawResponseCache(directory)
        sources = []
        plan = []
        claims = []
        timestamp = "2030-01-02T00:00:00+00:00"
        for index, kind in enumerate(KINDS):
            excerpt = f"<p>{EXCERPTS[kind]}</p>"
            digest, reference = cache.store(excerpt.encode())
            source_id = (
                fact_document["source_ids"][0]
                if kind == "company"
                else f"source:{kind}"
            )
            plan_id = f"plan:{kind}"
            sources.append({
                "id": source_id,
                "url": f"https://8.8.8.8/jaa13/{index}",
                "captured_at": timestamp,
                "retrieved_at": timestamp,
                "published_at": timestamp,
                "updated_at": None,
                "content_sha256": digest,
                "raw_response_ref": reference,
                "status_code": 200,
                "source_kind": "official_company",
            })
            plan.append({
                "id": plan_id,
                "kind": kind,
                "source_id": source_id,
                "source_type": {
                    "company": "official_company",
                    "role": "official_vacancy",
                    "product": "official_product",
                    "hiring": "official_careers",
                    "operational_health": "official_financial",
                }[kind],
                "permitted_purposes": [kind],
                "freshness_days": next(
                    value
                    for key, value in FRESHNESS_DAYS.items()
                    if key.value == kind
                ),
                "excerpt_sha256": hashlib.sha256(
                    excerpt.encode()
                ).hexdigest(),
            })
            claims.append({
                "id": (
                    fact_document["id"]
                    if kind == "company"
                    else f"claim:{kind}"
                ),
                "kind": kind,
                "classification": (
                    "fact" if kind == "company" else "inference"
                ),
                "subject_type": (
                    "organisation" if kind == "company" else None
                ),
                "text": (
                    fact_document["text"]
                    if kind == "company"
                    else EXCERPTS[kind]
                ),
                "observed_at": timestamp,
                "source_captured_at": timestamp,
                "freshness_classification": "current",
                "source_ids": [source_id],
                "source_plan_id": plan_id,
                "citation_excerpt": excerpt,
            })
        dossier = {
            "schema_version": "jaa04.dossier.v1",
            "job_key": source.job_key,
            "sources": sources,
            "source_plan": plan,
            "claims": claims,
            "edges": [],
        }
        return compile_employer_dossier_evidence(
            dossier,
            cache,
            as_of=date(2030, 1, 3),
        )


def _release_lineage(source, employer_evidence):
    files = tuple(
        ArtifactFileReceipt(
            filename,
            hashlib.sha256(filename.encode()).hexdigest(),
            1,
        )
        for filename in ARTIFACT_FILENAMES
    )
    artifact_set_sha256 = hashlib.sha256(
        b"jaa13-artifact-set"
    ).hexdigest()
    publication = PublishedArtifactReceipt(
        artifact_set_sha256=artifact_set_sha256,
        source_id=source.source_id,
        relative_directory=artifact_set_sha256,
        files=files,
        receipt_sha256="0" * 64,
    )
    publication = replace(
        publication,
        receipt_sha256=_hash(
            publication.document(include_receipt_hash=False)
        ),
    )
    binding = ReleaseBinding(
        job_key=source.job_key,
        candidate_identity_sha256=hashlib.sha256(b"candidate").hexdigest(),
        vacancy_sha256=source.vacancy_sha256,
        vacancy_observed_at=date(2030, 1, 1),
        vacancy_valid_until=date(2030, 1, 31),
        dossier_sha256=employer_evidence.dossier_sha256,
        candidate_profile_sha256=hashlib.sha256(b"profile").hexdigest(),
        strategy_id=source.strategy_id,
        strategy_document_sha256=hashlib.sha256(
            b"strategy-document"
        ).hexdigest(),
        application_source_id=source.source_id,
        application_source_sha256=source.content_sha256,
        artifact_set_sha256=publication.artifact_set_sha256,
        artifact_receipt_sha256=publication.receipt_sha256,
        deterministic_writer_policy_sha256=hashlib.sha256(
            b"writer-policy"
        ).hexdigest(),
        model_receipt_sha256s=(),
        work_right=WorkRightBinding(
            "GB",
            "employee",
            "work-right",
            1,
            hashlib.sha256(b"work-right").hexdigest(),
            date(2029, 1, 1),
            date(2031, 1, 1),
            True,
        ),
        official_route=OfficialRouteBinding(
            "route:official",
            "fixture-adapter",
            "1",
            "official:fixture",
            hashlib.sha256(b"route-policy").hexdigest(),
            date(2030, 1, 1),
            date(2030, 2, 1),
            True,
        ),
        evaluated_at=date(2030, 1, 2),
        prior_application_count=0,
    )
    validations = tuple(
        ValidationReceipt(
            validator,
            "1",
            hashlib.sha256(f"impl:{validator}".encode()).hexdigest(),
            binding.input_sha256,
            binding.artifact_set_sha256,
            "pass",
        )
        for validator in REQUIRED_VALIDATORS
    )
    manifest = compile_release_manifest(binding, validations)
    fixture = FixtureReceipt(
        receipt_id="0" * 64,
        application_id=APPLICATION_ID,
        job_key=source.job_key,
        payload_sha256=hashlib.sha256(b"payload").hexdigest(),
    )
    fixture = replace(
        fixture,
        receipt_id=_hash(fixture.document(include_identity=False)),
    )
    token_sha256 = hashlib.sha256(b"token").hexdigest()
    screenshot_sha256 = hashlib.sha256(b"screenshot").hexdigest()
    field_map_sha256 = hashlib.sha256(b"field-map").hexdigest()
    submission_context = compile_local_submission_context(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        run_id=SUBMISSION_RUN_ID,
        workflow=SUBMISSION_WORKFLOW,
        step_id=SUBMISSION_STEP_ID,
        release_manifest_sha256=manifest.release_manifest_sha256,
        token_sha256=token_sha256,
        field_map_sha256=field_map_sha256,
    )
    proof = SubmissionProof(
        release_manifest_sha256=manifest.release_manifest_sha256,
        token_sha256=token_sha256,
        receipt_id=fixture.receipt_id,
        receipt_payload_sha256=fixture.payload_sha256,
        screenshot_sha256=screenshot_sha256,
        field_map_sha256=field_map_sha256,
        submit_event_sha256=fixture_submit_event_sha256(
            run_id=submission_context.run_id,
            workflow_sha256=submission_context.workflow_sha256,
            step_id=submission_context.step_id,
            release_manifest_sha256=(
                submission_context.release_manifest_sha256
            ),
            receipt_id=fixture.receipt_id,
            receipt_payload_sha256=fixture.payload_sha256,
            screenshot_sha256=screenshot_sha256,
            field_map_sha256=submission_context.field_map_sha256,
        ),
    )
    return manifest, publication, submission_context, proof, fixture


def _pack():
    source, _strategy = _source()
    employer_evidence = _employer_evidence(source)
    manifest, publication, submission_context, proof, fixture = _release_lineage(
        source,
        employer_evidence,
    )
    candidate_ids = tuple(
        row.sentence_id for row in source.facts if row.fact_kind == "candidate"
    )
    employer_ids = tuple(
        row.sentence_id for row in source.facts if row.fact_kind == "employer"
    )
    pack = compile_interview_preparation_pack(
        FROZEN_INTERVIEW_COMMUNICATION_CONTRACT,
        application_id=APPLICATION_ID,
        source=source,
        timeline=_timeline(),
        release_manifest=manifest,
        publication_receipt=publication,
        submission_context=submission_context,
        submission_proof=proof,
        fixture_receipt=fixture,
        employer_evidence=employer_evidence,
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
    assert pack.release_manifest.binding.application_source_id == (
        source.source_id
    )
    assert pack.publication_receipt.source_id == source.source_id
    assert pack.submission_proof.release_manifest_sha256 == (
        pack.release_manifest.release_manifest_sha256
    )
    assert pack.submission_proof.token_sha256 == (
        pack.submission_context.token_sha256
    )
    assert pack.submission_proof.field_map_sha256 == (
        pack.submission_context.field_map_sha256
    )
    assert pack.submission_proof.submit_event_sha256 == (
        fixture_submit_event_sha256(
            run_id=pack.submission_context.run_id,
            workflow_sha256=pack.submission_context.workflow_sha256,
            step_id=pack.submission_context.step_id,
            release_manifest_sha256=(
                pack.submission_context.release_manifest_sha256
            ),
            receipt_id=pack.fixture_receipt.receipt_id,
            receipt_payload_sha256=pack.fixture_receipt.payload_sha256,
            screenshot_sha256=pack.submission_proof.screenshot_sha256,
            field_map_sha256=pack.submission_context.field_map_sha256,
        )
    )
    assert pack.fixture_receipt.application_id == APPLICATION_ID
    assert pack.timeline == _timeline()
    assert pack.lineage_claim == (
        "unauthenticated_structural_lineage_only"
    )
    assert pack.submission_context.assertion_status == (
        "unauthenticated_structural_assertion"
    )
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
        connective_template_ids=(
            "thank_you_for_time",
            "kind_regards",
        ),
    )
    assert plan.factual_authority_ids == facts
    assert plan.connective_template_ids == (
        "thank_you_for_time",
        "kind_regards",
    )
    assert plan.connective_text == (
        "Thank you for your time.",
        "Kind regards.",
    )
    assert plan.preparation == pack
    assert plan.debrief == debrief
    assert plan.debrief_fact_authority is False
    assert plan.operator_confirmation_required is True
    assert plan.truth_release_authority == "withheld"
    assert plan.connector_authority == "withheld"
    assert plan.send_authority == "withheld"
    assert plan.sent_count == 0
    assert plan.dependency_satisfied is False
    assert plan.certifies_slice is False
