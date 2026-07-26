"""Independent acceptance tests for the pure deterministic JAA-08 manifest."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import date

from career_automation.release_gate import (
    REQUIRED_VALIDATORS,
    OfficialRouteBinding,
    ReleaseBinding,
    ValidationReceipt,
    WorkRightBinding,
    compile_release_manifest,
    verify_release_manifest,
)


AS_OF = date(2030, 1, 2)
DIGEST = hashlib.sha256(b"jaa08-pure-contract").hexdigest()


def _binding(**overrides: object) -> ReleaseBinding:
    values: dict[str, object] = {
        "job_key": "locked:release-job",
        "candidate_identity_sha256": hashlib.sha256(b"candidate").hexdigest(),
        "vacancy_sha256": hashlib.sha256(b"vacancy").hexdigest(),
        "vacancy_observed_at": date(2030, 1, 1),
        "vacancy_valid_until": date(2030, 1, 31),
        "dossier_sha256": hashlib.sha256(b"dossier").hexdigest(),
        "candidate_profile_sha256": hashlib.sha256(b"profile").hexdigest(),
        "strategy_id": hashlib.sha256(b"strategy").hexdigest(),
        "strategy_document_sha256": hashlib.sha256(
            b"strategy-document"
        ).hexdigest(),
        "application_source_id": hashlib.sha256(b"source-id").hexdigest(),
        "application_source_sha256": hashlib.sha256(b"source").hexdigest(),
        "artifact_set_sha256": hashlib.sha256(b"artifacts").hexdigest(),
        "artifact_receipt_sha256": hashlib.sha256(
            b"artifact-receipt"
        ).hexdigest(),
        "deterministic_writer_policy_sha256": hashlib.sha256(
            b"writer-policy"
        ).hexdigest(),
        "model_receipt_sha256s": (),
        "work_right": WorkRightBinding(
            "GB",
            "employee",
            "work-right-gb",
            2,
            hashlib.sha256(b"work-right-verification").hexdigest(),
            date(2029, 1, 1),
            date(2031, 1, 1),
            True,
        ),
        "official_route": OfficialRouteBinding(
            "route:official",
            "ats-adapter",
            "1",
            "official:ats-documentation",
            hashlib.sha256(b"route-policy").hexdigest(),
            date(2030, 1, 1),
            date(2030, 2, 1),
            True,
        ),
        "evaluated_at": AS_OF,
        "prior_application_count": 0,
    }
    values.update(overrides)
    return ReleaseBinding(**values)


def _validations(
    binding: ReleaseBinding,
) -> tuple[ValidationReceipt, ...]:
    return tuple(
        ValidationReceipt(
            validator_id,
            "1",
            hashlib.sha256(f"impl:{validator_id}".encode()).hexdigest(),
            binding.input_sha256,
            binding.artifact_set_sha256,
            "pass",
        )
        for validator_id in REQUIRED_VALIDATORS
    )


def test_release_manifest_binds_every_consequential_input_and_validator() -> None:
    binding = _binding()
    manifest = compile_release_manifest(binding, _validations(binding))
    verify_release_manifest(manifest)
    assert manifest.binding == binding
    assert manifest.input_sha256 == binding.input_sha256
    assert tuple(
        row.validator_id for row in manifest.validations
    ) == REQUIRED_VALIDATORS
    assert {
        row.artifact_set_sha256 for row in manifest.validations
    } == {binding.artifact_set_sha256}
    assert manifest.certifies_slice is False
    assert manifest.dependency_gate == "JAA-07"


def test_release_manifest_is_reproducible_and_has_no_action_capability() -> None:
    binding = _binding()
    first = compile_release_manifest(binding, _validations(binding))
    second = compile_release_manifest(binding, _validations(binding))
    assert first == second
    document = first.document()
    assert document["verdict"] == "pass"
    assert all(
        token not in document
        for token in ("submit", "browser", "portal", "message", "upload")
    )


def test_changed_bound_input_invalidates_exact_manifest_identity() -> None:
    binding = _binding()
    manifest = compile_release_manifest(binding, _validations(binding))
    changed = replace(
        binding,
        vacancy_sha256=hashlib.sha256(b"changed-vacancy").hexdigest(),
    )
    tampered = replace(manifest, binding=changed)
    try:
        verify_release_manifest(tampered)
    except ValueError as exc:
        assert "input identity" in str(exc)
    else:  # pragma: no cover - explicit fail message
        raise AssertionError("changed release input was accepted")
