from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from career_automation.adversarial_recruiter import (
    RecruiterAssessmentReceipt,
    RESULT_SCHEMA_VERSION,
)
from career_automation.adversarial_recruiter_archive import (
    RecruiterDiagnosticArchiveError,
    archive_recruiter_diagnostic,
    verify_recruiter_diagnostic_archive,
)
from career_automation.adversarial_recruiter_runtime import (
    RUNTIME_SCHEMA_VERSION,
    DetachedTransportReceipt,
)
from career_automation.evidence_matching import content_hash
from career_automation.external_document_assurance import IntendedVacancy


def _assessment() -> RecruiterAssessmentReceipt:
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "calibration_status": "uncalibrated",
        "fit_percent": 41,
        "fit_range_percent": {"low": 25, "high": 55},
        "overall_verdict": "weak_fit",
        "ats_reaction": {
            "progression_probability_percent": 42,
            "verdict": "borderline",
            "reasons": ["Relevant project, unclear commercial depth."],
        },
        "human_reaction": {
            "progression_probability_percent": 40,
            "verdict": "borderline",
            "reasons": ["Evidence is credible but narrow."],
        },
        "strengths": [{"location": "cv:projects", "assessment": "Relevant Python project."}],
        "risks": [{
            "category": "experience", "severity": "high", "location": "cv:experience",
            "assessment": "No comparable production ownership is demonstrated.",
        }],
        "application_improvements": [{
            "target": "cv",
            "recommendation": "Lead with the closest production-grade evidence.",
            "expected_effect": "Makes relevance visible during screening.",
        }],
        "profile_improvements": [{
            "category": "experience",
            "recommendation": "Build evidence of operating a deployed service.",
            "time_horizon": "months", "expected_effect": "Addresses the seniority gap.",
        }],
    }
    vacancy = IntendedVacancy(
        "example:123", hashlib.sha256(b"listing").hexdigest(),
        "Infrastructure Engineer", "Example Systems",
    )
    package_hashes = {
        "listing_text_sha256": hashlib.sha256(b"listing").hexdigest(),
        "cv_pdf_sha256": hashlib.sha256(b"cv pdf").hexdigest(),
        "cv_text_sha256": hashlib.sha256(b"cv text").hexdigest(),
        "cover_letter_pdf_sha256": hashlib.sha256(b"letter pdf").hexdigest(),
        "cover_letter_text_sha256": hashlib.sha256(b"letter text").hexdigest(),
        "form_fields_sha256": hashlib.sha256(b"forms").hexdigest(),
    }
    from career_automation.adversarial_recruiter import (
        POLICY_SHA256, PROMPT_SHA256, RECEIPT_SCHEMA_VERSION, SCHEMA_SHA256,
    )
    preimage = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "package_hashes": package_hashes,
        "intended_vacancy": vacancy.document(),
        "vacancy_intent_sha256": vacancy.intent_sha256,
        "prompt_sha256": PROMPT_SHA256,
        "schema_sha256": SCHEMA_SHA256,
        "policy_sha256": POLICY_SHA256,
        "backend_identity": "detached_test",
        "model_identity": "detached-test-v1",
        "model_result": result,
        "model_result_sha256": content_hash(result),
        "release_authority": False,
        "mutation_authority": False,
    }
    return RecruiterAssessmentReceipt(
        package_hashes=package_hashes, intended_vacancy=vacancy,
        prompt_sha256=PROMPT_SHA256, schema_sha256=SCHEMA_SHA256,
        policy_sha256=POLICY_SHA256, backend_identity="detached_test",
        model_identity="detached-test-v1", model_result=result,
        model_result_sha256=content_hash(result), receipt_sha256=content_hash(preimage),
    )


def _transport() -> DetachedTransportReceipt:
    provider = "openai-codex-cli"
    model = "detached-test-v1"
    preimage = {
        "schema_version": RUNTIME_SCHEMA_VERSION,
        "provider_identity": provider,
        "provider_sha256": content_hash({"provider": provider}),
        "model_identity": model,
        "model_sha256": content_hash({"model": model}),
        "transport_sha256": hashlib.sha256(b"transport policy").hexdigest(),
        "request_sha256": hashlib.sha256(b"exact request").hexdigest(),
        "response_sha256": hashlib.sha256(b"exact response").hexdigest(),
        "binary_sha256": hashlib.sha256(b"exact binary").hexdigest(),
        "invocation_count": 1,
        "cache_enabled": False, "history_enabled": False,
        "tools_enabled": False, "retrieval_enabled": False,
    }
    return DetachedTransportReceipt(
        provider_identity=provider, provider_sha256=preimage["provider_sha256"],
        model_identity=model, model_sha256=preimage["model_sha256"],
        transport_sha256=preimage["transport_sha256"],
        request_sha256=preimage["request_sha256"],
        response_sha256=preimage["response_sha256"],
        binary_sha256=preimage["binary_sha256"], invocation_count=1,
        receipt_sha256=content_hash(preimage),
    )


def test_archive_is_content_addressed_diagnostic_only_and_replays_offline(tmp_path) -> None:
    assessment = _assessment()
    transport = _transport()
    archived = archive_recruiter_diagnostic(assessment, transport, root=tmp_path.resolve())
    replayed = verify_recruiter_diagnostic_archive(archived, root=tmp_path.resolve())
    assert replayed.assessment == assessment
    assert replayed.transport == transport
    assert archived.diagnostic_only is True
    assert archived.release_authority is False
    assert archived.mutation_authority is False
    assert archived.submission_authority is False
    assert archived.assessment_receipt_sha256 == assessment.receipt_sha256
    assert archived.model_result_sha256 == assessment.model_result_sha256
    assert archived.transport_receipt_sha256 == transport.receipt_sha256
    assert archived.request_sha256 == transport.request_sha256
    assert dict(archived.package_hashes) == dict(assessment.package_hashes)
    files = [path for path in tmp_path.rglob("*") if path.is_file()]
    assert len(files) == 3
    raw = b"\n".join(path.read_bytes() for path in files)
    assert b"Infrastructure Engineer" in raw  # validated receipt only
    assert b"cv pdf" not in raw and b"cv text" not in raw


def test_rearchive_is_idempotent_but_conflicting_existing_bytes_fail(tmp_path) -> None:
    assessment = _assessment()
    transport = _transport()
    first = archive_recruiter_diagnostic(assessment, transport, root=tmp_path.resolve())
    assert archive_recruiter_diagnostic(assessment, transport, root=tmp_path.resolve()) == first
    manifest = tmp_path / first.manifest_relative_path
    manifest.chmod(0o600)
    manifest.write_bytes(b"{}\n")
    with pytest.raises(RecruiterDiagnosticArchiveError, match="differs"):
        archive_recruiter_diagnostic(assessment, transport, root=tmp_path.resolve())


@pytest.mark.parametrize("target", ("manifest", "assessment_object", "transport_object"))
def test_offline_verification_detects_tampering(tmp_path, target) -> None:
    archived = archive_recruiter_diagnostic(_assessment(), _transport(), root=tmp_path.resolve())
    if target == "manifest":
        path = tmp_path / archived.manifest_relative_path
    elif target == "assessment_object":
        digest = archived.assessment_object_sha256
        path = tmp_path / "objects" / digest[:2] / f"{digest}.json"
    else:
        digest = archived.transport_object_sha256
        path = tmp_path / "objects" / digest[:2] / f"{digest}.json"
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(RecruiterDiagnosticArchiveError, match="hash differs"):
        verify_recruiter_diagnostic_archive(archived, root=tmp_path.resolve())


def test_archive_receipt_authority_or_hash_mutation_fails(tmp_path) -> None:
    archived = archive_recruiter_diagnostic(_assessment(), _transport(), root=tmp_path.resolve())
    for changes in (
        {"release_authority": True},
        {"mutation_authority": True},
        {"submission_authority": True},
        {"model_result_sha256": "0" * 64},
        {"package_hashes": {**archived.package_hashes, "cv_pdf_sha256": "0" * 64}},
        {"transport_receipt_sha256": "0" * 64},
        {"request_sha256": "0" * 64},
        {"response_sha256": "0" * 64},
        {"binary_sha256": "0" * 64},
        {"provider_sha256": "0" * 64},
        {"model_sha256": "0" * 64},
    ):
        with pytest.raises(RecruiterDiagnosticArchiveError):
            mutation = replace(archived, **changes)
            verify_recruiter_diagnostic_archive(mutation, root=tmp_path.resolve())


def test_raw_package_content_is_not_accepted_or_archived(tmp_path) -> None:
    with pytest.raises(TypeError):
        archive_recruiter_diagnostic(  # type: ignore[arg-type]
            {"cv": "raw candidate PII", "receipt": _assessment()},
            _transport(),
            root=tmp_path.resolve(),
        )
