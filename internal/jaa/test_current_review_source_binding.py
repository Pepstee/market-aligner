"""Synthetic regression for the unmocked current-review source binding helper.

The existing review tests monkeypatch ``_current_review_binding_and_evidence``
entirely, so its actual original/outward matching, answer coverage and pending
receipt checks have never been exercised.  These cases run the helper for real
against actual ``ApplicationSource``/``FactualSentence`` objects carrying real
generic ``FactAuthority`` values, plus failure cases.

FIXTURE BOUNDARY (test-only): full current admission/authentication is out of
scope. ``MarketApplicationMaterializationContext`` is built with
``object.__new__`` plus explicit fields, and only that outer admission
``__post_init__`` is monkeypatched. ``CandidateApplicationMaterializationReceipt``
uses a valid synthetic current receipt and its real ``__post_init__`` runs for
both parent and child. Everything the helper verifies (source
verification, fact matching, pending draft binding, placement/coverage and
evidence row generation) runs unmocked production code.  This file does NOT
test full current admission/authentication and must not be cited as doing so.

The synthetic persona reuses the generic JAA-07 fixture (Alex Example,
alex@example.test) with deduplicated unique visible placements.  No applicant
facts are used.
"""

from __future__ import annotations

import hashlib
from dataclasses import fields, replace

import pytest

from cv_generation.constraints import (
    PreEditorialSourceEnvelopeReceipt,
    validate_pre_editorial_source,
)
from career_automation.application_compiler import (
    CV_SECTION_ORDER,
    CandidateContact,
    DocumentSection,
    FactualSentence,
    PendingCurrentOutwardDraft,
    StructuredAnswer,
    compile_application_source,
    verify_application_source,
)
from career_automation.application_sanity_review import (
    CurrentClaimReviewEvidence,
    _current_review_binding_and_evidence,
)
from career_automation.candidate_application_factory import (
    CURRENT_RUNTIME_DECISION_AUTHORITY_SCHEMA,
    CURRENT_RUNTIME_ENVIRONMENT,
    CURRENT_RUNTIME_MATERIALIZATION_RECEIPT_SCHEMA,
    CandidateApplicationMaterialization,
    CandidateApplicationMaterializationReceipt,
    MarketApplicationDecisionAuthority,
    build_candidate_application_deployment_binding,
)
from career_automation.candidate_authority import (
    CANONICAL_REQUIREMENTS_MATRIX_POLICY_SHA256,
)
from career_automation.evidence_matching import canonical_json, content_hash
from career_automation.market_aligner_preparation import MarketApplicationMaterializationContext
from career_automation.rendering import render_editable_text
from cv_generation.service import _reidentify_source
from test_jaa07_independent_acceptance import (
    _employer_fact_document,
    _sentence,
    _slot,
    _strategy,
)

CV_TEXT = "Delivered reliable services with tested evidence."
CV_REWRITTEN_TEXT = "Delivered dependable services with tested evidence."
APPLICATION_ID = "app_" + hashlib.sha256(b"synthetic-application").hexdigest()
CANDIDATE_PROJECTION_SHA256 = hashlib.sha256(b"synthetic-projection").hexdigest()
EDITORIAL_REQUEST_SHA256 = hashlib.sha256(b"synthetic-editorial-request").hexdigest()
FORM_BINDINGS = (("delivery-field", "delivery-example"),)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _original_source():
    strategy = _strategy()
    elements = {row.kind: row for row in strategy.elements}
    cv = _sentence(
        elements["cv_emphasis"],
        text=CV_TEXT,
        fact_kind="candidate",
        document_kind="cv",
    )
    letter_candidate = _sentence(
        elements["cover_letter_argument"],
        text=CV_TEXT,
        fact_kind="candidate",
        document_kind="cover_letter",
    )
    letter_employer = _sentence(
        elements["employer_hook"],
        text="Example Ltd operates a documented service.",
        fact_kind="employer",
        document_kind="cover_letter",
        employer_fact=_employer_fact_document(),
    )
    answer = _sentence(
        elements["structured_answer"],
        text=CV_TEXT,
        fact_kind="candidate",
        document_kind="answer",
    )
    cv_slot = _slot("cv", "Relevant evidence")
    letter_slot = _slot("cover_letter", "This work is relevant to the role.")
    answer_slot = _slot("answer", "A concise example follows.")
    return compile_application_source(
        strategy=strategy,
        job_key="synthetic:example:engineer",
        role_title="Software Engineer",
        company_name="Example Ltd",
        vacancy_source_identity="vacancy:synthetic:example",
        vacancy_sha256=hashlib.sha256(b"vacancy").hexdigest(),
        contact=CandidateContact(
            "Alex Example",
            "alex@example.test",
            "+44 7700 900123",
            "London",
            "contact-primary",
            4,
            hashlib.sha256(b"contact-provenance").hexdigest(),
        ),
        facts=(cv, letter_candidate, letter_employer, answer),
        style_slots=(cv_slot, letter_slot, answer_slot),
        cv_sections=(
            DocumentSection(
                CV_SECTION_ORDER[0], (cv.sentence_id,), (cv_slot.slot_id,)
            ),
            DocumentSection(CV_SECTION_ORDER[2], (), (cv_slot.slot_id,)),
        ),
        letter_sections=(
            DocumentSection(
                "Opening", (letter_employer.sentence_id,), (letter_slot.slot_id,)
            ),
            DocumentSection("Evidence Match", (letter_candidate.sentence_id,)),
            DocumentSection("Close", (), (letter_slot.slot_id,)),
        ),
        answers=(
            StructuredAnswer(
                "delivery-example",
                "Describe a relevant delivery example.",
                (answer.sentence_id,),
                (answer_slot.slot_id,),
            ),
        ),
    )


def _rewritten_cv_fact(fact, materialization_receipt_sha256):
    return FactualSentence(
        sentence_id=fact.sentence_id,
        text=CV_REWRITTEN_TEXT,
        approved_source_text=fact.approved_source_text,
        fact_kind=fact.fact_kind,
        document_kind=fact.document_kind,
        authority=fact.authority,
        employer_fact_json=None,
        pending_current_outward_draft=PendingCurrentOutwardDraft(
            sentence_id=fact.sentence_id,
            document_kind=fact.document_kind,
            materialization_receipt_sha256=materialization_receipt_sha256,
            editorial_request_sha256=EDITORIAL_REQUEST_SHA256,
            original_text_sha256=hashlib.sha256(
                fact.approved_source_text.encode("utf-8")
            ).hexdigest(),
            outward_text_sha256=hashlib.sha256(
                CV_REWRITTEN_TEXT.encode("utf-8")
            ).hexdigest(),
        ),
    )


def _emitted_source(original, materialization_receipt_sha256):
    facts = tuple(
        _rewritten_cv_fact(fact, materialization_receipt_sha256)
        if fact.document_kind == "cv"
        else fact
        for fact in original.facts
    )
    return _reidentify_source(replace(original, facts=facts))


def _decision_authority(current_boundary_sha256=None):
    if current_boundary_sha256 is None:
        current_boundary_sha256 = _digest("boundary")
    matrix = (
        {
            "requirement_id": "delivery",
            "evidence_ids": ["evidence-delivery"],
            "state": "covered",
        },
    )
    authority = object.__new__(MarketApplicationDecisionAuthority)
    for name, value in (
        ("application_id", APPLICATION_ID),
        ("environment", CURRENT_RUNTIME_ENVIRONMENT),
        ("handoff_root_sha256", _digest("handoff")),
        ("admission_receipt_sha256", _digest("admission")),
        ("current_boundary_receipt_sha256", current_boundary_sha256),
        ("source_job_key", "synthetic:example:engineer"),
        ("internal_job_key", "synthetic:example:engineer"),
        ("vacancy_snapshot_sha256", _digest("vacancy-snapshot")),
        ("raw_listing_sha256", hashlib.sha256(b"vacancy").hexdigest()),
        ("requirements_sha256", _digest("requirements")),
        ("assessment_receipt_sha256", _digest("assessment")),
        ("eligibility_receipt_sha256", _digest("eligibility")),
        ("selection_receipt_sha256", _digest("selection")),
        ("candidate_projection_sha256", CANDIDATE_PROJECTION_SHA256),
        ("candidate_authority_file_sha256", _digest("candidate-authority")),
        ("candidate_authority_object_sha256", _digest("candidate-authority-object")),
        ("evidence_ledger_sha256", _digest("evidence-ledger")),
        ("approved_evidence_file_sha256", _digest("approved-evidence-file")),
        ("approved_evidence_object_sha256", _digest("approved-evidence-object")),
        ("evidence_projection_sha256", _digest("evidence-projection")),
        ("matrix_policy_sha256", CANONICAL_REQUIREMENTS_MATRIX_POLICY_SHA256),
        ("evidence_matrix_sha256", content_hash([dict(row) for row in matrix])),
        ("evidence_matrix", matrix),
        ("source_url", "https://example.invalid/jobs/synthetic"),
        ("role_title", "Software Engineer"),
        ("company_name", "Example Ltd"),
        ("observed_at", "2030-01-02T00:00:00+00:00"),
        ("authority_sha256", "0" * 64),
        ("schema_version", CURRENT_RUNTIME_DECISION_AUTHORITY_SCHEMA),
        ("release_authority", False),
    ):
        object.__setattr__(authority, name, value)
    object.__setattr__(
        authority,
        "authority_sha256",
        content_hash(
            MarketApplicationDecisionAuthority.document(
                authority, include_identity=False
            )
        ),
    )
    MarketApplicationDecisionAuthority.__post_init__(authority)
    return authority


def _admitted_context(monkeypatch, original_source):
    # FIXTURE BOUNDARY: test-only admission objects (see module docstring).
    monkeypatch.setattr(
        MarketApplicationMaterializationContext, "__post_init__", lambda self: None
    )
    authority = _decision_authority()
    decision_receipt = authority.decision_receipt()
    decision_receipt_sha256 = hashlib.sha256(
        (canonical_json(decision_receipt) + "\n").encode("utf-8")
    ).hexdigest()
    editable = render_editable_text(original_source)
    facts_by_id = {fact.sentence_id: fact for fact in original_source.facts}
    sections = {
        section.heading: tuple(facts_by_id[value].text for value in section.sentence_ids)
        for section in original_source.cv_sections
        if section.sentence_ids
    }
    source_policy_receipt = PreEditorialSourceEnvelopeReceipt.from_document(
        validate_pre_editorial_source(
            source_id=original_source.source_id,
            cv_text=editable.cv_text,
            cv_sha256=editable.cv_sha256,
            sections=sections,
        )
    )
    fact_bindings = tuple(
        {
            "sentence_id": fact.sentence_id,
            "document_kind": fact.document_kind,
            "text": fact.text,
            "text_sha256": hashlib.sha256(fact.text.encode("utf-8")).hexdigest(),
            "evidence_ids": (fact.authority.candidate_evidence_id,),
        }
        for fact in original_source.facts
    )
    deployment_binding = build_candidate_application_deployment_binding(
        application_id=authority.application_id,
        environment=authority.environment,
        handoff_root_sha256=authority.handoff_root_sha256,
        admission_receipt_sha256=authority.admission_receipt_sha256,
        current_boundary_receipt_sha256=authority.current_boundary_receipt_sha256,
        candidate_authority_file_sha256=authority.candidate_authority_file_sha256,
    )
    receipt = object.__new__(CandidateApplicationMaterializationReceipt)
    for name, value in (
        ("candidate_authority_file_sha256", authority.candidate_authority_file_sha256),
        ("candidate_authority_object_sha256", authority.candidate_authority_object_sha256),
        ("candidate_projection_sha256", authority.candidate_projection_sha256),
        ("deployment_binding", deployment_binding),
        ("contact_authority_sha256", None),
        ("contact_envelope_sha256", None),
        ("contact_registry_sha256", None),
        ("contact_signer_public_key_sha256", None),
        (
            "cv_claim_set_sha256",
            content_hash(
                [dict(row) for row in fact_bindings if row["document_kind"] == "cv"]
            ),
        ),
        ("approved_evidence_file_sha256", authority.approved_evidence_file_sha256),
        ("approved_evidence_object_sha256", authority.approved_evidence_object_sha256),
        ("decision_receipt_sha256", decision_receipt_sha256),
        ("vacancy_sha256", authority.raw_listing_sha256),
        ("vacancy_snapshot_sha256", authority.vacancy_snapshot_sha256),
        ("decision_authority_schema", authority.schema_version),
        ("decision_authority_sha256", authority.authority_sha256),
        ("job_key", authority.source_job_key),
        ("role_title", authority.role_title),
        ("company_name", authority.company_name),
        ("source_url", authority.source_url),
        ("application_source_id", original_source.source_id),
        ("application_source_sha256", original_source.content_sha256),
        ("fact_bindings", fact_bindings),
        ("style_bindings", ()),
        ("source_policy_receipt", source_policy_receipt),
        ("receipt_sha256", "0" * 64),
        ("schema_version", CURRENT_RUNTIME_MATERIALIZATION_RECEIPT_SCHEMA),
        ("release_authority", False),
        ("contact_provenance_sha256", _digest("contact-provenance")),
        ("contact_provenance_schema", "current-contact-provenance-v1"),
        (
            "contact_source_hashes",
            tuple(sorted((_digest("cv-a"), _digest("cv-b")))),
        ),
    ):
        object.__setattr__(receipt, name, value)
    object.__setattr__(
        receipt,
        "receipt_sha256",
        content_hash(receipt.document(include_identity=False)),
    )
    CandidateApplicationMaterializationReceipt.__post_init__(receipt)
    materialization = CandidateApplicationMaterialization(
        source=original_source,
        editable=None,
        vacancy_requirements=("REQ-delivery: Deliver reliable services.",),
        receipt=receipt,
    )
    context = object.__new__(MarketApplicationMaterializationContext)
    for name, value in (
        ("application_id", APPLICATION_ID),
        ("materialization", materialization),
        ("market_decision_authority", authority),
        ("decision_receipt", decision_receipt),
        ("candidate_projection", {}),
        ("raw_listing_bytes", b"synthetic raw listing"),
        ("candidate_authority_bytes", b"{}"),
        ("contact_authority_path", None),
        ("profile_id", "synthetic-profile"),
        ("profile_version", "1"),
        ("candidate_intent_sha256", _digest("candidate-intent")),
        ("final_score", 50.0),
        ("opportunity_score", 0.5),
        ("geography_priority_rank", 1),
        ("source_observed_at", "2030-01-02T00:00:00+00:00"),
        ("release_authority", False),
        ("contact_provenance", None),
    ):
        object.__setattr__(context, name, value)
    return context


def _child_materialization(context, label="child"):
    parent_receipt = context.materialization.receipt
    parent_binding = parent_receipt.deployment_binding
    authority = _decision_authority(_digest(f"{label}-boundary"))
    binding = build_candidate_application_deployment_binding(
        application_id=parent_binding.application_id,
        environment=parent_binding.environment,
        handoff_root_sha256=parent_binding.handoff_root_sha256,
        admission_receipt_sha256=parent_binding.admission_receipt_sha256,
        current_boundary_receipt_sha256=(
            authority.current_boundary_receipt_sha256
        ),
        candidate_authority_file_sha256=(
            parent_binding.candidate_authority_file_sha256
        ),
    )
    receipt = object.__new__(CandidateApplicationMaterializationReceipt)
    for item in fields(CandidateApplicationMaterializationReceipt):
        object.__setattr__(receipt, item.name, getattr(parent_receipt, item.name))
    object.__setattr__(receipt, "deployment_binding", binding)
    object.__setattr__(receipt, "decision_authority_schema", authority.schema_version)
    object.__setattr__(receipt, "decision_authority_sha256", authority.authority_sha256)
    object.__setattr__(
        receipt,
        "receipt_sha256",
        content_hash(receipt.document(include_identity=False)),
    )
    CandidateApplicationMaterializationReceipt.__post_init__(receipt)
    materialization = CandidateApplicationMaterialization(
        source=context.materialization.source,
        editable=context.materialization.editable,
        vacancy_requirements=context.materialization.vacancy_requirements,
        receipt=receipt,
    )
    return materialization, authority


def _clone_receipt(receipt, **changes):
    clone = object.__new__(CandidateApplicationMaterializationReceipt)
    for item in fields(CandidateApplicationMaterializationReceipt):
        object.__setattr__(clone, item.name, getattr(receipt, item.name))
    for name, value in changes.items():
        object.__setattr__(clone, name, value)
    if "receipt_sha256" not in changes:
        object.__setattr__(
            clone,
            "receipt_sha256",
            content_hash(clone.document(include_identity=False)),
        )
    return clone


def _invoke_binding(
    *,
    emitted_source,
    current_runtime_context,
    form_answer_bindings,
    child_materialization=None,
    child_decision_authority=None,
):
    if child_materialization is None and child_decision_authority is None:
        child_materialization = current_runtime_context.materialization
        child_decision_authority = current_runtime_context.market_decision_authority
    return _current_review_binding_and_evidence(
        emitted_source=emitted_source,
        current_runtime_context=current_runtime_context,
        child_materialization=child_materialization,
        child_decision_authority=child_decision_authority,
        form_answer_bindings=form_answer_bindings,
    )


def _cv_fact(source):
    return next(fact for fact in source.facts if fact.document_kind == "cv")


def _emitted_for_context(source, context):
    return _emitted_source(
        source, context.materialization.receipt.receipt_sha256
    )


def test_unmocked_helper_binds_rewrite_and_keeps_original_unchanged(monkeypatch):
    original = _original_source()
    verify_application_source(original)
    original_snapshot = original.document()
    context = _admitted_context(monkeypatch, original)
    child_materialization, child_authority = _child_materialization(context)
    emitted = _emitted_source(
        original, child_materialization.receipt.receipt_sha256
    )
    verify_application_source(emitted)
    assert emitted.source_id != original.source_id

    binding, rows = _invoke_binding(
        emitted_source=emitted,
        current_runtime_context=context,
        child_materialization=child_materialization,
        child_decision_authority=child_authority,
        form_answer_bindings=FORM_BINDINGS,
    )

    assert all(type(row) is CurrentClaimReviewEvidence for row in rows)
    assert rows == tuple(
        sorted(rows, key=lambda row: (row.document_kind, row.sentence_id))
    )
    by_kind = {row.document_kind: row for row in rows}
    assert set(by_kind) == {"cv", "cover_letter", "answer"}
    cv_row = by_kind["cv"]
    letter_row = by_kind["cover_letter"]
    answer_row = by_kind["answer"]
    assert cv_row.sentence_id == _cv_fact(emitted).sentence_id
    assert _cv_fact(emitted).pending_current_outward_draft.materialization_receipt_sha256 == (
        child_materialization.receipt.receipt_sha256
    )
    assert cv_row.original_source_text == CV_TEXT
    assert cv_row.outward_text == CV_REWRITTEN_TEXT
    assert cv_row.original_source_text != cv_row.outward_text
    assert (
        cv_row.original_source_sha256
        == hashlib.sha256(CV_TEXT.encode("utf-8")).hexdigest()
    )
    assert (
        cv_row.outward_sha256
        == hashlib.sha256(CV_REWRITTEN_TEXT.encode("utf-8")).hexdigest()
    )
    assert letter_row.original_source_text == letter_row.outward_text
    assert answer_row.original_source_text == answer_row.outward_text
    employer_ids = {
        fact.sentence_id for fact in emitted.facts if fact.fact_kind == "employer"
    }
    assert employer_ids
    assert all(row.sentence_id not in employer_ids for row in rows)
    fact_by_key = {
        (fact.document_kind, fact.sentence_id): fact for fact in emitted.facts
    }
    for row in rows:
        authority = fact_by_key[(row.document_kind, row.sentence_id)].authority
        assert row.evidence_identity == (
            f"{authority.candidate_claim_id}:v{authority.candidate_claim_version}:"
            f"{authority.candidate_evidence_id}:"
            f"v{authority.candidate_evidence_version}"
        )
    assert binding.application_id == APPLICATION_ID
    assert binding.materialization_receipt_sha256 == (
        context.materialization.receipt.receipt_sha256
    )
    assert (
        binding.child_materialization_receipt_sha256
        == child_materialization.receipt.receipt_sha256
    )
    assert binding.parent_decision_authority_sha256 == (
        context.market_decision_authority.authority_sha256
    )
    assert binding.child_decision_authority_sha256 == child_authority.authority_sha256
    assert binding.parent_decision_authority_sha256 != binding.child_decision_authority_sha256
    assert binding.candidate_projection_sha256 == CANDIDATE_PROJECTION_SHA256
    assert binding.original_source_identity == original.source_id
    assert binding.original_source_sha256 == original.content_sha256
    assert binding.emitted_source_identity == emitted.source_id
    assert binding.emitted_source_sha256 == emitted.content_sha256
    assert original.document() == original_snapshot
    verify_application_source(original)

    _binding_two, rows_two = _invoke_binding(
        emitted_source=emitted,
        current_runtime_context=context,
        child_materialization=child_materialization,
        child_decision_authority=child_authority,
        form_answer_bindings=(),
    )
    answer_ids = {
        fact.sentence_id for fact in emitted.facts if fact.document_kind == "answer"
    }
    assert {row.document_kind for row in rows_two} == {"cv", "cover_letter"}
    assert all(row.sentence_id not in answer_ids for row in rows_two)


def test_pending_rewrite_with_wrong_materialization_receipt_hash_is_refused(
    monkeypatch,
):
    original = _original_source()
    context = _admitted_context(monkeypatch, original)
    emitted = _emitted_source(original, _digest("other-materialization-receipt"))
    verify_application_source(emitted)
    with pytest.raises(
        ValueError, match="current outward rewrite differs from its exact binding"
    ):
        _invoke_binding(
            emitted_source=emitted,
            current_runtime_context=context,
            form_answer_bindings=FORM_BINDINGS,
        )


def test_child_receipt_identity_tamper_is_rejected_without_rebinding_pending_hash(
    monkeypatch,
):
    original = _original_source()
    context = _admitted_context(monkeypatch, original)
    child_materialization, child_authority = _child_materialization(context)
    emitted = _emitted_source(
        original, child_materialization.receipt.receipt_sha256
    )
    pending_hash = _cv_fact(emitted).pending_current_outward_draft.materialization_receipt_sha256
    tampered_receipt = _clone_receipt(
        child_materialization.receipt,
        receipt_sha256=_digest("incorrect-receipt-identity"),
    )
    tampered_materialization = CandidateApplicationMaterialization(
        source=child_materialization.source,
        editable=child_materialization.editable,
        vacancy_requirements=child_materialization.vacancy_requirements,
        receipt=tampered_receipt,
    )
    assert pending_hash == child_materialization.receipt.receipt_sha256
    with pytest.raises(ValueError, match="materialization receipt identity is invalid"):
        _invoke_binding(
            emitted_source=emitted,
            current_runtime_context=context,
            child_materialization=tampered_materialization,
            child_decision_authority=child_authority,
            form_answer_bindings=FORM_BINDINGS,
        )
    assert _cv_fact(emitted).pending_current_outward_draft.materialization_receipt_sha256 == pending_hash


def test_child_stable_receipt_tamper_is_rejected_by_carrier_comparison(monkeypatch):
    original = _original_source()
    context = _admitted_context(monkeypatch, original)
    child_materialization, child_authority = _child_materialization(context)
    emitted = _emitted_source(
        original, child_materialization.receipt.receipt_sha256
    )
    changed_receipt = _clone_receipt(
        child_materialization.receipt,
        vacancy_snapshot_sha256=_digest("changed-vacancy-snapshot"),
    )
    changed_receipt.__post_init__()
    changed_materialization = CandidateApplicationMaterialization(
        source=child_materialization.source,
        editable=child_materialization.editable,
        vacancy_requirements=child_materialization.vacancy_requirements,
        receipt=changed_receipt,
    )
    with pytest.raises(
        ValueError, match="current materialization stable receipt fields differ"
    ):
        _invoke_binding(
            emitted_source=emitted,
            current_runtime_context=context,
            child_materialization=changed_materialization,
            child_decision_authority=child_authority,
            form_answer_bindings=FORM_BINDINGS,
        )


def test_child_binding_and_authority_tampering_are_rejected(monkeypatch):
    original = _original_source()
    context = _admitted_context(monkeypatch, original)
    child_materialization, child_authority = _child_materialization(context)
    emitted = _emitted_source(
        original, child_materialization.receipt.receipt_sha256
    )
    previous_binding = child_materialization.receipt.deployment_binding
    changed_binding = build_candidate_application_deployment_binding(
        application_id=previous_binding.application_id,
        environment=previous_binding.environment,
        handoff_root_sha256=previous_binding.handoff_root_sha256,
        admission_receipt_sha256=_digest("changed-admission"),
        current_boundary_receipt_sha256=(
            previous_binding.current_boundary_receipt_sha256
        ),
        candidate_authority_file_sha256=(
            previous_binding.candidate_authority_file_sha256
        ),
    )
    changed_receipt = _clone_receipt(
        child_materialization.receipt,
        deployment_binding=changed_binding,
    )
    changed_receipt.__post_init__()
    changed_materialization = CandidateApplicationMaterialization(
        source=child_materialization.source,
        editable=child_materialization.editable,
        vacancy_requirements=child_materialization.vacancy_requirements,
        receipt=changed_receipt,
    )
    with pytest.raises(ValueError, match="current child materialization bindings differ"):
        _invoke_binding(
            emitted_source=emitted,
            current_runtime_context=context,
            child_materialization=changed_materialization,
            child_decision_authority=child_authority,
            form_answer_bindings=FORM_BINDINGS,
        )

    tampered_authority = object.__new__(MarketApplicationDecisionAuthority)
    for item in fields(MarketApplicationDecisionAuthority):
        object.__setattr__(
            tampered_authority, item.name, getattr(child_authority, item.name)
        )
    object.__setattr__(tampered_authority, "source_url", "https://tampered.invalid")
    with pytest.raises(ValueError, match="market application decision identity is invalid"):
        _invoke_binding(
            emitted_source=emitted,
            current_runtime_context=context,
            child_materialization=child_materialization,
            child_decision_authority=tampered_authority,
            form_answer_bindings=FORM_BINDINGS,
        )


@pytest.mark.parametrize("mutation", ("approved_source_text", "authority_identity"))
def test_changed_original_fact_is_refused_by_actual_helper_comparison(
    monkeypatch, mutation
):
    original = _original_source()
    cv_fact = _cv_fact(original)
    if mutation == "approved_source_text":
        changed_text = "Delivered reliable services with documented evidence."
        changed = FactualSentence(
            sentence_id=cv_fact.sentence_id,
            text=changed_text,
            approved_source_text=changed_text,
            fact_kind=cv_fact.fact_kind,
            document_kind=cv_fact.document_kind,
            authority=cv_fact.authority,
        )
    else:
        changed = replace(
            cv_fact,
            authority=replace(
                cv_fact.authority, candidate_evidence_id="evidence-other"
            ),
        )
    mutated = _reidentify_source(
        replace(
            original,
            facts=tuple(
                changed if fact.sentence_id == cv_fact.sentence_id else fact
                for fact in original.facts
            ),
        )
    )
    # The mutated admitted source is itself internally valid, so the refusal
    # below is the helper's own original/outward comparison boundary, not an
    # earlier object-validation failure.
    verify_application_source(mutated)
    context = _admitted_context(monkeypatch, mutated)
    emitted = _emitted_for_context(original, context)
    with pytest.raises(
        ValueError, match="current review emitted fact differs from original authority"
    ):
        _invoke_binding(
            emitted_source=emitted,
            current_runtime_context=context,
            form_answer_bindings=FORM_BINDINGS,
        )


def test_repeated_placement_and_coverage_gap_are_refused(monkeypatch):
    original = _original_source()
    context = _admitted_context(monkeypatch, original)
    emitted = _emitted_for_context(original, context)
    cv_sentence_id = _cv_fact(emitted).sentence_id
    cv_slot_id = emitted.style_slots[0].slot_id
    repeated = _reidentify_source(
        replace(
            emitted,
            cv_sections=(
                DocumentSection(
                    CV_SECTION_ORDER[0], (cv_sentence_id,), (cv_slot_id,)
                ),
                DocumentSection(CV_SECTION_ORDER[2], (cv_sentence_id,), ()),
            ),
        )
    )
    verify_application_source(repeated)
    with pytest.raises(
        ValueError, match="current review repeats an outward fact placement"
    ):
        _invoke_binding(
            emitted_source=repeated,
            current_runtime_context=context,
            form_answer_bindings=FORM_BINDINGS,
        )
    hidden = _reidentify_source(
        replace(
            emitted,
            cv_sections=(
                DocumentSection(CV_SECTION_ORDER[0], (), (cv_slot_id,)),
                DocumentSection(CV_SECTION_ORDER[2], (), (cv_slot_id,)),
            ),
        )
    )
    verify_application_source(hidden)
    with pytest.raises(
        ValueError, match="current CV or cover evidence coverage is incomplete"
    ):
        _invoke_binding(
            emitted_source=hidden,
            current_runtime_context=context,
            form_answer_bindings=FORM_BINDINGS,
        )


def test_unknown_bound_answer_question_is_refused(monkeypatch):
    original = _original_source()
    context = _admitted_context(monkeypatch, original)
    emitted = _emitted_for_context(original, context)
    with pytest.raises(
        ValueError, match="current form answer binding has no source answer"
    ):
        _invoke_binding(
            emitted_source=emitted,
            current_runtime_context=context,
            form_answer_bindings=(("delivery-field", "unknown-question"),),
        )


def test_wrong_runtime_context_type_is_refused():
    original = _original_source()
    emitted = _emitted_source(original, _digest("untrusted-context"))
    with pytest.raises(TypeError, match="exact admitted materialization context"):
        _current_review_binding_and_evidence(
            emitted_source=emitted,
            current_runtime_context=object(),
            child_materialization=object(),
            child_decision_authority=object(),
            form_answer_bindings=(),
        )
