"""Adversarial controls for JAA-07 fact, style and ATS source boundaries."""

from __future__ import annotations

import hashlib
import os
import json
import subprocess
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from career_automation import rendering as rendering_module
from career_automation.application_compiler import (
    CandidateContact,
    FactualSentence,
    ModelReceipt,
    ProductionApplicationCompiler,
    StyleProposal,
    StyleSlot,
    apply_style_proposal,
    compile_application_source,
    verify_application_source,
)
from career_automation.application_artifacts import (
    load_published_artifacts,
    publish_application_artifacts,
)
from career_automation.application_strategy import ApplicationStrategyStore
from career_automation.candidate_graph import CandidateGraph
from career_automation.evidence_matching import canonical_json, content_hash
from career_automation.rendering import (
    ApplicationArtifacts,
    PDF_FORBIDDEN,
    PdfArtifact,
    RENDERER_POLICY_SHA256,
    render_pdf_artifacts,
    validate_pdf_artifact,
    validate_pdf_geometry,
    verify_application_artifacts,
)
from test_jaa07_independent_acceptance import (
    DIGEST,
    LOCKED_PACKS,
    ROOT,
    _employer_fact_document,
    _source,
)
from test_jaa06_independent_acceptance import _fit_database


def test_factual_sentence_cannot_paraphrase_or_add_an_unsupported_metric() -> None:
    source, _ = _source()
    fact = source.facts[0]
    with pytest.raises(ValueError, match="equal its approved"):
        replace(fact, text=f"{fact.text} Improved availability by 40%.")


@pytest.mark.parametrize(
    "text",
    (
        "<table><tr><td>hidden</td></tr></table>",
        '<span style="display:none">keywords</span>',
        "![profile](portrait.png)",
        "<svg>graphic</svg>",
    ),
)
def test_tables_graphics_and_hidden_text_fail(text: str) -> None:
    source, _ = _source()
    fact = source.facts[0]
    with pytest.raises(ValueError, match="forbidden rich or hidden"):
        FactualSentence(
            fact.sentence_id,
            text,
            text,
            fact.fact_kind,
            fact.document_kind,
            fact.authority,
            fact.employer_fact_json,
        )


def test_generic_wrong_company_cover_letter_fails() -> None:
    source, strategy = _source()
    with pytest.raises(ValueError, match="company-specific"):
        compile_application_source(
            strategy=strategy,
            job_key=source.job_key,
            role_title=source.role_title,
            company_name="Wrong Target Ltd",
            vacancy_source_identity=source.vacancy_source_identity,
            vacancy_sha256=source.vacancy_sha256,
            contact=source.contact,
            facts=source.facts,
            style_slots=source.style_slots,
            cv_sections=source.cv_sections,
            letter_sections=source.letter_sections,
            answers=source.answers,
        )


def test_style_critic_cannot_add_metrics_contacts_or_ai_cliches() -> None:
    for text in (
        "Improved delivery by 40 percent.",
        "Improved delivery by forty percent.",
        "Ranked 3rd for service.",
        "A 21st-century approach.",
        "Contact alex@example.test for details.",
        "This is a pivotal opportunity.",
        "Results matter — especially here.",
    ):
        with pytest.raises(ValueError, match="fact-like|natural-language"):
            StyleSlot(content_hash({"text": text}), "answer", text)


def test_style_receipt_and_exact_target_are_mandatory() -> None:
    source, _ = _source()
    slot = source.style_slots[0]
    proposed = "Evidence relevant to the role"
    bad_receipt = ModelReceipt(
        "provider",
        "critic",
        DIGEST,
        DIGEST,
        hashlib.sha256(b"different input").hexdigest(),
        hashlib.sha256(proposed.encode()).hexdigest(),
    )
    with pytest.raises(ValueError, match="input does not match"):
        StyleProposal(
            "0" * 64,
            slot.slot_id,
            slot.text,
            proposed,
            bad_receipt,
        )


def test_style_proposal_must_change_its_exact_target() -> None:
    source, _ = _source()
    slot = source.style_slots[0]
    text_sha256 = hashlib.sha256(slot.text.encode()).hexdigest()
    receipt = ModelReceipt(
        "provider",
        "critic",
        DIGEST,
        DIGEST,
        text_sha256,
        text_sha256,
    )
    proposal_id = content_hash(
        {
            "contract": "jaa07.style-proposal.v1",
            "slot_id": slot.slot_id,
            "input_sha256": receipt.input_sha256,
            "output_sha256": receipt.output_sha256,
            "provider": receipt.provider,
            "model": receipt.model,
            "prompt_sha256": receipt.prompt_sha256,
            "policy_sha256": receipt.policy_sha256,
        }
    )
    with pytest.raises(ValueError, match="must change"):
        StyleProposal(
            proposal_id,
            slot.slot_id,
            slot.text,
            slot.text,
            receipt,
        )


def test_tampered_source_and_contact_privacy_fields_fail_closed() -> None:
    source, _ = _source()
    with pytest.raises(ValueError, match="identity differs"):
        verify_application_source(replace(source, role_title="Different Role"))
    with pytest.raises(ValueError, match="city only"):
        CandidateContact(
            "Alex Example",
            "alex@example.test",
            "+44 7700 900123",
            "London, 10 Private Street",
            "contact",
            1,
            DIGEST,
        )


def test_style_proposal_cannot_target_changed_or_unknown_source_slot() -> None:
    source, _ = _source()
    slot = source.style_slots[0]
    proposed = "Evidence relevant to this role"
    receipt = ModelReceipt(
        "provider",
        "critic",
        DIGEST,
        DIGEST,
        hashlib.sha256(slot.text.encode()).hexdigest(),
        hashlib.sha256(proposed.encode()).hexdigest(),
    )
    proposal_id = content_hash(
        {
            "contract": "jaa07.style-proposal.v1",
            "slot_id": slot.slot_id,
            "input_sha256": receipt.input_sha256,
            "output_sha256": receipt.output_sha256,
            "provider": receipt.provider,
            "model": receipt.model,
            "prompt_sha256": receipt.prompt_sha256,
            "policy_sha256": receipt.policy_sha256,
        }
    )
    proposal = StyleProposal(
        proposal_id,
        slot.slot_id,
        slot.text,
        proposed,
        receipt,
    )
    changed = replace(
        source,
        style_slots=tuple(
            replace(row, text="Changed connective prose")
            if row.slot_id == slot.slot_id
            else row
            for row in source.style_slots
        ),
    )
    with pytest.raises(ValueError, match="exact content|exact source"):
        apply_style_proposal(changed, proposal)
    with pytest.raises(ValueError, match="identity differs"):
        apply_style_proposal(
            replace(source, role_title="Different Role"),
            proposal,
        )


def test_employer_sentence_must_match_hashed_fact_not_caller_label() -> None:
    source, _ = _source()
    employer = next(row for row in source.facts if row.fact_kind == "employer")
    changed_text = "Example Ltd operates an unsupported different service."
    with pytest.raises(ValueError, match="exact source-backed fact"):
        replace(
            employer,
            text=changed_text,
            approved_source_text=changed_text,
            employer_fact_json=canonical_json(
                _employer_fact_document(text=changed_text)
            ),
        )


def test_pdf_hash_page_count_and_extracted_text_tamper_fail_closed() -> None:
    source, _ = _source()
    artifact = render_pdf_artifacts(source).cv_pdf
    with pytest.raises(ValueError, match="content hash|text-only subset"):
        validate_pdf_artifact(
            replace(artifact, pdf_bytes=artifact.pdf_bytes + b" "),
            expected_page_count=1,
            required_values=("Alex Example",),
        )
    with pytest.raises(ValueError, match="page count"):
        validate_pdf_artifact(
            artifact,
            expected_page_count=2,
            required_values=("Alex Example",),
        )
    with pytest.raises(ValueError, match="retained artifact"):
        validate_pdf_artifact(
            replace(artifact, extracted_text="tampered\n"),
            expected_page_count=1,
            required_values=("Alex Example",),
        )


def test_pdf_rich_or_hidden_feature_markers_fail_closed() -> None:
    source, _ = _source()
    artifact = render_pdf_artifacts(source).cover_letter_pdf
    marker = PDF_FORBIDDEN[0]
    poisoned = artifact.pdf_bytes + b"\n% " + marker
    attacked = PdfArtifact(
        artifact.document_kind,
        poisoned,
        hashlib.sha256(poisoned).hexdigest(),
        artifact.extracted_text,
        artifact.extracted_text_sha256,
        artifact.page_count,
        artifact.rendered_lines,
    )
    with pytest.raises(ValueError, match="forbidden"):
        validate_pdf_artifact(
            attacked,
            expected_page_count=1,
            required_values=("Example Ltd",),
        )
    newline_hidden = artifact.pdf_bytes + b"\n3 Tr\n"
    attacked = replace(
        artifact,
        pdf_bytes=newline_hidden,
        pdf_sha256=hashlib.sha256(newline_hidden).hexdigest(),
    )
    with pytest.raises(ValueError, match="text-only subset"):
        validate_pdf_artifact(
            attacked,
            expected_page_count=1,
            required_values=("Example Ltd",),
        )


def test_pdf_geometry_rejects_clipping_overlap_and_page_budget() -> None:
    source, _ = _source()
    artifacts = render_pdf_artifacts(source)
    first_page = artifacts.cv_pdf.layout_boxes[0]
    clipped = replace(first_page[0], x=594.0)
    with pytest.raises(ValueError, match="clips"):
        validate_pdf_geometry(((clipped, *first_page[1:]),))
    overlapping = replace(first_page[1], baseline_y=first_page[0].baseline_y)
    with pytest.raises(ValueError, match="overlap"):
        validate_pdf_geometry(((first_page[0], overlapping, *first_page[2:]),))

    blocks = tuple(
        (
            rendering_module._LineSpec(
                f"Synthetic evidence line {index}",
                "body",
                rendering_module._BODY,
            ),
        )
        for index in range(80)
    )
    layout = rendering_module._layout_blocks(blocks, max_pages=2)
    assert len(layout) == 2
    validate_pdf_geometry(layout)
    with pytest.raises(ValueError, match="page budget"):
        rendering_module._layout_blocks(blocks, max_pages=1)


def test_coherently_rehashed_pdf_from_another_source_fails_exact_rerender() -> None:
    source, _ = _source()
    original = render_pdf_artifacts(source)
    slot = source.style_slots[0]
    proposed = "Evidence relevant to this role"
    receipt = ModelReceipt(
        "provider",
        "critic",
        DIGEST,
        DIGEST,
        hashlib.sha256(slot.text.encode()).hexdigest(),
        hashlib.sha256(proposed.encode()).hexdigest(),
    )
    proposal = StyleProposal(
        content_hash(
            {
                "contract": "jaa07.style-proposal.v1",
                "input_sha256": receipt.input_sha256,
                "model": receipt.model,
                "output_sha256": receipt.output_sha256,
                "policy_sha256": receipt.policy_sha256,
                "prompt_sha256": receipt.prompt_sha256,
                "provider": receipt.provider,
                "slot_id": slot.slot_id,
            }
        ),
        slot.slot_id,
        slot.text,
        proposed,
        receipt,
    )
    other = render_pdf_artifacts(apply_style_proposal(source, proposal))
    tampered_hash = hashlib.sha256(
        "\n".join(
            (
                original.source_id,
                RENDERER_POLICY_SHA256,
                original.editable.cv_sha256,
                original.editable.cover_letter_sha256,
                original.editable.answers_sha256,
                other.cv_pdf.pdf_sha256,
                other.cv_pdf.extracted_text_sha256,
                original.cover_letter_pdf.pdf_sha256,
                original.cover_letter_pdf.extracted_text_sha256,
            )
        ).encode("utf-8")
    ).hexdigest()
    tampered = ApplicationArtifacts(
        source_id=original.source_id,
        editable=original.editable,
        cv_pdf=other.cv_pdf,
        cover_letter_pdf=original.cover_letter_pdf,
        artifact_set_sha256=tampered_hash,
    )
    with pytest.raises(ValueError, match="exact source rerender"):
        verify_application_artifacts(tampered, source)


def test_artifact_publication_rejects_repository_and_symlink_roots(
    tmp_path: Path,
) -> None:
    source, _ = _source()
    artifacts = render_pdf_artifacts(source)
    with pytest.raises(ValueError, match="outside"):
        publish_application_artifacts(
            source,
            artifacts,
            root=ROOT / "runtime_evidence" / "jaa07",
            repository_root=ROOT,
        )
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    os.symlink(real, link)
    with pytest.raises(ValueError, match="symlink"):
        publish_application_artifacts(
            source,
            artifacts,
            root=link,
            repository_root=ROOT,
        )


def test_artifact_tamper_and_changed_set_identity_never_overwrite(
    tmp_path: Path,
) -> None:
    source, _ = _source()
    artifacts = render_pdf_artifacts(source)
    root = tmp_path / "artifacts"
    receipt = publish_application_artifacts(
        source,
        artifacts,
        root=root,
        repository_root=ROOT,
    )
    target = root / receipt.relative_directory / "cv.txt"
    original = target.read_bytes()
    target.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="differs from its receipt"):
        load_published_artifacts(
            artifacts.artifact_set_sha256,
            root=root,
            repository_root=ROOT,
        )
    with pytest.raises(ValueError, match="differs from its receipt"):
        publish_application_artifacts(
            source,
            artifacts,
            root=root,
            repository_root=ROOT,
        )
    assert target.read_bytes() == b"tampered"
    target.write_bytes(original)
    with pytest.raises(ValueError, match="artifact-set identity"):
        publish_application_artifacts(
            source,
            replace(artifacts, artifact_set_sha256="0" * 64),
            root=root,
            repository_root=ROOT,
        )


@pytest.mark.parametrize("attack", ("missing", "symlink"))
def test_missing_or_symlinked_published_artifact_fails_closed(
    tmp_path: Path,
    attack: str,
) -> None:
    source, _ = _source()
    artifacts = render_pdf_artifacts(source)
    root = tmp_path / "artifacts"
    receipt = publish_application_artifacts(
        source,
        artifacts,
        root=root,
        repository_root=ROOT,
    )
    directory = root / receipt.relative_directory
    target = directory / "cv.txt"
    target.unlink()
    if attack == "symlink":
        target.symlink_to(directory / "cover-letter.txt")
    with pytest.raises(ValueError, match="missing or unsafe"):
        load_published_artifacts(
            artifacts.artifact_set_sha256,
            root=root,
            repository_root=ROOT,
        )


def test_artifact_publication_rejects_source_mismatch(tmp_path: Path) -> None:
    source, _ = _source()
    artifacts = render_pdf_artifacts(source)
    with pytest.raises(ValueError, match="different application source"):
        publish_application_artifacts(
            source,
            replace(artifacts, source_id="0" * 64),
            root=tmp_path / "artifacts",
            repository_root=ROOT,
        )


def test_production_compiler_rejects_unverified_or_changed_contact(
    tmp_path: Path,
) -> None:
    database, run, _requirement = _fit_database(tmp_path, matched=True)
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    )
    contact = CandidateContact(
        "Alex Example",
        "alex@example.test",
        "+44 7700 900123",
        "London",
        "missing-contact",
        1,
        DIGEST,
    )
    with pytest.raises(ValueError, match="verified authority"):
        ProductionApplicationCompiler(database.path).compile(
            strategy.strategy_id,
            as_of=date.today(),
            contact=contact,
        )


def test_production_compiler_rejects_ambiguous_contact_verification(
    tmp_path: Path,
) -> None:
    database, run, _requirement = _fit_database(tmp_path, matched=True)
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    )
    graph = CandidateGraph(database.path)
    value = {
        "full_name": "Alex Example",
        "email": "alex@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
    }
    graph.add_record(
        "contact",
        kind="fact",
        subject="contact",
        value=value,
        state="fact",
        source_identity="test:contact",
    )
    for decision in ("approved", "rejected"):
        graph.verify_record(
            "contact",
            1,
            decision=decision,
            verifier_kind="configured",
            policy_id=f"test.contact.{decision}",
            policy_version="1",
            policy_hash=hashlib.sha256(decision.encode()).hexdigest(),
            reason=f"{decision} test decision",
            source_identity=f"test:contact:{decision}",
        )
    with database.connection() as connection:
        source_hash = str(
            connection.execute(
                """SELECT provenance.source_hash
               FROM candidate_records record
               JOIN candidate_provenance provenance
                 ON provenance.provenance_id=record.provenance_id
               WHERE record.record_id='contact'"""
            ).fetchone()[0]
        )
    with pytest.raises(ValueError, match="verified authority"):
        ProductionApplicationCompiler(database.path).compile(
            strategy.strategy_id,
            as_of=date.today(),
            contact=CandidateContact(
                record_id="contact",
                record_version=1,
                provenance_sha256=source_hash,
                **value,
            ),
        )


@pytest.mark.parametrize("attack", ("value", "provenance"))
def test_production_compiler_rejects_contact_authority_drift(
    tmp_path: Path,
    attack: str,
) -> None:
    database, run, _requirement = _fit_database(tmp_path, matched=True)
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id,
        as_of=date.today(),
    )
    graph = CandidateGraph(database.path)
    value = {
        "full_name": "Alex Example",
        "email": "alex@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
    }
    graph.add_record(
        "contact",
        kind="fact",
        subject="contact",
        value=value,
        state="fact",
        source_identity="test:contact",
    )
    graph.verify_record(
        "contact",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="test.contact",
        policy_version="1",
        policy_hash=DIGEST,
        reason="verified contact",
        source_identity="test:contact:review",
    )
    with database.connection() as connection:
        source_hash = str(
            connection.execute(
                """SELECT provenance.source_hash
               FROM candidate_records record
               JOIN candidate_provenance provenance
                 ON provenance.provenance_id=record.provenance_id
               WHERE record.record_id='contact'"""
            ).fetchone()[0]
        )
    supplied = dict(value)
    if attack == "value":
        supplied["full_name"] = "Changed Name"
    else:
        source_hash = DIGEST
    with pytest.raises(ValueError, match="differs from its durable authority"):
        ProductionApplicationCompiler(database.path).compile(
            strategy.strategy_id,
            as_of=date.today(),
            contact=CandidateContact(
                record_id="contact",
                record_version=1,
                provenance_sha256=source_hash,
                **supplied,
            ),
        )


@pytest.mark.parametrize(
    ("attack", "expected"),
    (
        ("artifact_hash", "metrics differ"),
        ("certifies", "truth boundary"),
        ("limitations", "truth boundary"),
        ("pack_count", "exactly 20"),
    ),
)
def test_locked_pack_truth_and_expected_outputs_cannot_be_rehashed(
    tmp_path: Path,
    attack: str,
    expected: str,
) -> None:
    fixture = json.loads(LOCKED_PACKS.read_text(encoding="utf-8"))
    if attack == "artifact_hash":
        fixture["cases"][0]["expected_artifact_set_sha256"] = "0" * 64
    elif attack == "certifies":
        fixture["certifies_slice"] = True
    elif attack == "limitations":
        fixture["limitations"] = fixture["limitations"][:-1]
    else:
        fixture["cases"] = fixture["cases"][:-1]
    attacked = tmp_path / "attacked.json"
    attacked.write_text(json.dumps(fixture), encoding="utf-8")
    completed = subprocess.run(
        (
            sys.executable,
            "scripts/evaluate_jaa07_locked_packs.py",
            "--fixture",
            str(attacked),
        ),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert expected in completed.stderr
