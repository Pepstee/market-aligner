"""Positive controls for the fixture-only JAA-11 application package."""

from __future__ import annotations

import json
from pathlib import Path

from career_automation.live_canary_application_package import (
    APPLICATION_PACKAGE_SCHEMA,
    compose_application_package_dry_run,
)
from career_automation.live_canary_authority import _content_hash
from career_automation.live_canary_operator_answer_composition import (
    compose_operator_answers_dry_run,
)
from career_automation.live_canary_operator_answers import (
    ApprovedEvidenceReference,
    OperatorAnswerRequest,
)
from career_automation.live_canary_operator_document_intake import (
    intake_operator_document_dry_run,
)
from career_automation.release_gate import compile_release_manifest
from career_automation.rendering import render_pdf_artifacts
from test_jaa07_independent_acceptance import _source
from test_jaa08_independent_acceptance import _binding, _validations
from test_jaa11_live_canary_fixture_dry_run import _evidence, _snapshot
from test_jaa11_live_canary_operator_answer_composition import _answers_bytes
from test_jaa11_live_canary_operator_answers import _hash


ROOT = Path(__file__).resolve().parent


def _work_authorisation(jurisdiction: str = "GB") -> OperatorAnswerRequest:
    return OperatorAnswerRequest(
        topic="work_authorisation",
        answer_kind="boolean",
        subtopic="current_work_authorisation",
        jurisdiction=jurisdiction,
        evidence=ApprovedEvidenceReference(
            source_kind="identity_work_rights_ledger",
            source_sha256=_hash("fixture-work-rights"),
            topic="work_authorisation",
            exact_claim="current_work_authorisation",
            jurisdiction=jurisdiction,
        ),
    )


def _package_inputs(
    *requests: OperatorAnswerRequest,
    request_jurisdiction: str = "GB",
    snapshot_vacancy_identity: str | None = None,
):
    source, _strategy = _source()
    artifacts = render_pdf_artifacts(source)
    snapshot = _snapshot()
    entries = snapshot["entries"]
    assert isinstance(entries, list)
    entries[20]["vacancy_identity"] = (
        snapshot_vacancy_identity or source.vacancy_source_identity
    )
    entries[20]["vacancy_content_sha256"] = source.vacancy_sha256
    raw = json.dumps(
        snapshot,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    intake = intake_operator_document_dry_run(
        raw,
        _evidence(21),
        submission_count=0,
        jaa11_certified=False,
    )
    answers = compose_operator_answers_dry_run(
        intake,
        _answers_bytes(),
        requests or (_work_authorisation(request_jurisdiction),),
    )
    binding = _binding(
        job_key=source.job_key,
        vacancy_sha256=source.vacancy_sha256,
        application_source_id=source.source_id,
        application_source_sha256=source.content_sha256,
        artifact_set_sha256=artifacts.artifact_set_sha256,
    )
    manifest = compile_release_manifest(binding, _validations(binding))
    return answers, source, artifacts, manifest


def _package(*requests: OperatorAnswerRequest):
    return compose_application_package_dry_run(*_package_inputs(*requests))


def test_aligned_package_binds_every_application_and_release_identity() -> None:
    result = _package()
    assert result.schema_version == APPLICATION_PACKAGE_SCHEMA
    assert result.intake_sha256 == result.answer_composition.intake_sha256
    assert result.application_source_id == result.application_source.source_id
    assert result.application_source_content_sha256 == (
        result.application_source.content_sha256
    )
    assert result.artifact_set_sha256 == (
        result.application_artifacts.artifact_set_sha256
    )
    assert result.editable_answers_sha256 == (
        result.application_artifacts.editable.answers_sha256
    )
    assert result.cv_pdf_sha256 == result.application_artifacts.cv_pdf.pdf_sha256
    assert result.cover_letter_pdf_sha256 == (
        result.application_artifacts.cover_letter_pdf.pdf_sha256
    )
    assert result.release_manifest_sha256 == (
        result.release_manifest.release_manifest_sha256
    )
    assert result.release_input_sha256 == result.release_manifest.input_sha256
    assert result.vacancy_content_sha256 == (
        result.release_manifest.binding.vacancy_sha256
    )
    assert result.work_right_jurisdiction == "GB"
    assert result.application_package_sha256 == _content_hash(
        result.document(include_hash=False)
    )


def test_identical_inputs_are_document_and_hash_deterministic() -> None:
    first = _package()
    second = _package()
    assert first.document() == second.document()
    assert first.application_package_sha256 == second.application_package_sha256


def test_every_external_boundary_remains_closed() -> None:
    result = _package()
    assert result.positive_evidence_is_fixture_only is True
    assert result.snapshot_source == "operator_supplied_document"
    assert result.acquired_by_system is False
    assert result.snapshot_is_live is False
    assert result.snapshot_is_current is False
    assert result.selected_vacancy_status == (
        "operator_supplied_not_selected_for_external_use"
    )
    assert result.answers_used_for_external_submission is False
    assert result.package_used_for_external_submission is False
    assert result.release_token == "withheld"
    assert result.token_consumed is False
    assert result.operational_release == "withheld"
    assert result.may_submit is False
    assert result.external_action_capability is False
    assert result.certifies_slice is False
    assert result.receipt_written is False
    assert result.real_applications == 0
    assert result.production_certification == "withheld"


def test_public_surface_is_exact() -> None:
    from career_automation import live_canary_application_package

    assert live_canary_application_package.__all__ == [
        "APPLICATION_PACKAGE_SCHEMA",
        "ApplicationPackageComposition",
        "compose_application_package_dry_run",
    ]
