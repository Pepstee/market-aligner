"""Adversarial controls for deterministic JAA-08 release manifests."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from datetime import date

import pytest

from career_automation.release_gate import (
    REQUIRED_VALIDATORS,
    ApplicationCompilationStore,
    ValidationReceipt,
    compile_release_manifest,
    verify_release_manifest,
)
from test_jaa08_independent_acceptance import (
    AS_OF,
    ROOT,
    _binding,
    _compilation_inputs,
    _validations,
)


@pytest.mark.parametrize(
    ("attack", "message"),
    (
        ("stale_vacancy", "vacancy is stale"),
        ("future_vacancy", "predates"),
        ("ineligible", "work right"),
        ("expired_right", "work right"),
        ("missing_route", "official application route"),
        ("stale_route", "official application route"),
        ("duplicate", "duplicate application"),
    ),
)
def test_non_bypassable_deterministic_preconditions(
    attack: str,
    message: str,
) -> None:
    binding = _binding()
    if attack == "stale_vacancy":
        binding = replace(binding, vacancy_valid_until=date(2030, 1, 1))
    elif attack == "future_vacancy":
        binding = replace(binding, vacancy_observed_at=date(2030, 1, 3))
    elif attack == "ineligible":
        binding = replace(
            binding,
            work_right=replace(binding.work_right, permitted=False),
        )
    elif attack == "expired_right":
        binding = replace(
            binding,
            work_right=replace(
                binding.work_right,
                valid_until=date(2030, 1, 1),
            ),
        )
    elif attack == "missing_route":
        binding = replace(
            binding,
            official_route=replace(binding.official_route, allowed=False),
        )
    elif attack == "stale_route":
        binding = replace(
            binding,
            official_route=replace(
                binding.official_route,
                valid_until=date(2030, 1, 1),
            ),
        )
    else:
        binding = replace(binding, prior_application_count=1)
    with pytest.raises(ValueError, match=message):
        compile_release_manifest(binding, _validations(binding))


@pytest.mark.parametrize("missing", REQUIRED_VALIDATORS)
def test_every_validator_is_mandatory(missing: str) -> None:
    binding = _binding()
    receipts = tuple(
        row for row in _validations(binding) if row.validator_id != missing
    )
    with pytest.raises(ValueError, match="missing, duplicated or unordered"):
        compile_release_manifest(binding, receipts)


def test_failed_probabilistic_or_deterministic_validator_cannot_mint_manifest() -> None:
    binding = _binding()
    rows = list(_validations(binding))
    truth_index = REQUIRED_VALIDATORS.index("truth")
    rows[truth_index] = replace(
        rows[truth_index],
        decision="block",
        finding_codes=("unsupported_claim",),
    )
    with pytest.raises(ValueError, match="unsupported_claim"):
        compile_release_manifest(binding, rows)
    with pytest.raises(ValueError, match="only deterministic"):
        replace(rows[0], authority_kind="probabilistic")


def test_receipts_for_different_input_or_artifact_cannot_be_reused() -> None:
    binding = _binding()
    rows = list(_validations(binding))
    rows[0] = replace(rows[0], input_sha256="0" * 64)
    with pytest.raises(ValueError, match="different inputs"):
        compile_release_manifest(binding, rows)
    rows = list(_validations(binding))
    rows[-1] = replace(rows[-1], artifact_set_sha256="0" * 64)
    with pytest.raises(ValueError, match="different inputs"):
        compile_release_manifest(binding, rows)


def test_validator_order_duplicate_and_finding_shape_fail_closed() -> None:
    binding = _binding()
    rows = _validations(binding)
    with pytest.raises(ValueError, match="missing, duplicated or unordered"):
        compile_release_manifest(binding, tuple(reversed(rows)))
    duplicated_impl = list(rows)
    duplicated_impl[1] = replace(
        duplicated_impl[1],
        validator_impl_sha256=duplicated_impl[0].validator_impl_sha256,
    )
    with pytest.raises(ValueError, match="independent implementations"):
        compile_release_manifest(binding, duplicated_impl)
    with pytest.raises(ValueError, match="cannot retain findings"):
        replace(rows[0], finding_codes=("hidden_text",))
    with pytest.raises(ValueError, match="requires findings"):
        ValidationReceipt(
            "truth",
            "1",
            hashlib.sha256(b"truth").hexdigest(),
            binding.input_sha256,
            binding.artifact_set_sha256,
            "block",
        )


def test_manifest_identity_cannot_be_rehashed_by_caller() -> None:
    binding = _binding()
    manifest = compile_release_manifest(binding, _validations(binding))
    with pytest.raises(ValueError, match="exact content"):
        verify_release_manifest(
            replace(manifest, release_manifest_sha256="0" * 64)
        )


def test_clock_is_explicit_and_not_implicitly_today() -> None:
    binding = _binding(evaluated_at=AS_OF)
    assert compile_release_manifest(binding, _validations(binding)).binding.evaluated_at == AS_OF


def test_compilation_registration_rejects_external_tamper_without_state_change(
    tmp_path,
) -> None:
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        receipt,
    ) = _compilation_inputs(tmp_path)
    target = artifact_root / receipt.relative_directory / "cv.txt"
    target.write_text("tampered", encoding="utf-8")
    store = ApplicationCompilationStore(database.path)
    with pytest.raises(ValueError, match="differs from its receipt"):
        store.register(
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            as_of=date.today(),
        )
    with database.connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM application_compilations"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?",
            (source.job_key,),
        ).fetchone()[0] == "strategy_ready"


def test_compilation_insert_failure_rolls_back_lifecycle_transition(
    tmp_path,
) -> None:
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _receipt,
    ) = _compilation_inputs(tmp_path)
    store = ApplicationCompilationStore(database.path)
    with sqlite3.connect(database.path) as connection:
        connection.execute(
            """CREATE TRIGGER test_block_compilation
               BEFORE INSERT ON application_compilations
               BEGIN SELECT RAISE(ABORT,'blocked test insert'); END"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="blocked test insert"):
        store.register(
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            as_of=date.today(),
        )
    with database.connection() as connection:
        assert connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?",
            (source.job_key,),
        ).fetchone()[0] == "strategy_ready"
        assert connection.execute(
            """SELECT COUNT(*) FROM lifecycle_transition_receipts
               WHERE to_state='application_compiled'"""
        ).fetchone()[0] == 0


def test_compilation_register_rejects_stale_source(tmp_path) -> None:
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _receipt,
    ) = _compilation_inputs(tmp_path)
    tampered = replace(source, role_title="Different Role")
    with pytest.raises(ValueError, match="differs from current authority"):
        ApplicationCompilationStore(database.path).register(
            source=tampered,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            as_of=date.today(),
        )


def test_publication_verification_never_creates_missing_root(tmp_path) -> None:
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        _artifact_root,
        _receipt,
    ) = _compilation_inputs(tmp_path)
    missing = tmp_path / "missing-read-root"
    with pytest.raises(KeyError):
        ApplicationCompilationStore(database.path).register(
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=missing,
            repository_root=ROOT,
            as_of=date.today(),
        )
    assert not missing.exists()
