"""Adversarial controls for deterministic JAA-08 release manifests."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone

import pytest

from career_automation.candidate_graph import CandidateGraph
from career_automation.release_gate import (
    REQUIRED_VALIDATORS,
    ApplicationCompilationStore,
    ReleaseGateStore,
    ValidationReceipt,
    compile_release_manifest,
    verify_release_manifest,
)
from test_jaa08_independent_acceptance import (
    AS_OF,
    DIGEST,
    ROOT,
    _authorized_release_inputs,
    _binding,
    _compilation_inputs,
    _issued_release_inputs,
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


def test_release_gate_rejects_external_tamper_without_token_or_release(
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
        publication,
        compilation,
        gate,
        _route,
    ) = _authorized_release_inputs(tmp_path)
    target = artifact_root / publication.relative_directory / "cover-letter.txt"
    target.write_text("tampered after compilation", encoding="utf-8")
    with pytest.raises(ValueError, match="differs from its receipt"):
        gate.evaluate_and_issue(
            compilation_id=compilation.compilation_id,
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            jurisdiction="GB",
            contract_type="employee",
            evaluated_at=date.today(),
        )
    with database.connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM release_tokens"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?",
            (source.job_key,),
        ).fetchone()[0] == "application_compiled"


def test_release_gate_rejects_missing_work_right_without_token(tmp_path) -> None:
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _publication,
    ) = _compilation_inputs(tmp_path)
    compilation = ApplicationCompilationStore(database.path).register(
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        as_of=date.today(),
    )
    gate = ReleaseGateStore(database.path)
    today = date.today()
    gate.register_official_route(
        job_key=source.job_key,
        route=replace(
            _binding().official_route,
            verified_at=today,
            valid_until=today.replace(year=today.year + 1),
        ),
    )
    with pytest.raises(ValueError, match="work-right authority"):
        gate.evaluate_and_issue(
            compilation_id=compilation.compilation_id,
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            jurisdiction="GB",
            contract_type="employee",
            evaluated_at=date.today(),
        )
    with database.connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM release_tokens"
        ).fetchone()[0] == 0


def test_release_insert_failure_rolls_back_release_transition(tmp_path) -> None:
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _publication,
        compilation,
        gate,
        _route,
    ) = _authorized_release_inputs(tmp_path)
    with sqlite3.connect(database.path) as connection:
        connection.execute(
            """CREATE TRIGGER test_block_release_token
               BEFORE INSERT ON release_tokens
               BEGIN SELECT RAISE(ABORT,'blocked test token'); END"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="blocked test token"):
        gate.evaluate_and_issue(
            compilation_id=compilation.compilation_id,
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            jurisdiction="GB",
            contract_type="employee",
            evaluated_at=date.today(),
        )
    with database.connection() as connection:
        assert connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?",
            (source.job_key,),
        ).fetchone()[0] == "application_compiled"
        assert connection.execute(
            "SELECT COUNT(*) FROM release_gate_attempts"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM release_manifests"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM release_tokens"
        ).fetchone()[0] == 0


def test_second_release_for_same_candidate_and_job_cannot_mint_token(
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
        _publication,
        compilation,
        gate,
        _route,
    ) = _authorized_release_inputs(tmp_path)
    arguments = {
        "compilation_id": compilation.compilation_id,
        "source": source,
        "artifacts": artifacts,
        "contact": contact,
        "questions": questions,
        "artifact_root": artifact_root,
        "repository_root": ROOT,
        "jurisdiction": "GB",
        "contract_type": "employee",
        "evaluated_at": date.today(),
    }
    gate.evaluate_and_issue(**arguments)
    with pytest.raises(ValueError):
        gate.evaluate_and_issue(**arguments)
    with database.connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM release_tokens"
        ).fetchone()[0] == 1


@pytest.mark.parametrize(
    "authority_failure",
    ("disallowed_route", "expired_route", "expired_work_right"),
)
def test_release_gate_rejects_expired_or_disallowed_authority(
    tmp_path,
    authority_failure: str,
) -> None:
    today = date.today()
    options = {
        "route_allowed": authority_failure != "disallowed_route",
        "route_verified_at": (
            today
            if authority_failure != "expired_route"
            else today.replace(year=today.year - 2)
        ),
        "route_valid_until": (
            today
            if authority_failure != "expired_route"
            else today.replace(year=today.year - 1)
        ),
        "work_right_valid_until": (
            today
            if authority_failure != "expired_work_right"
            else today.replace(year=today.year - 1)
        ),
    }
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _publication,
        compilation,
        gate,
        _route,
    ) = _authorized_release_inputs(tmp_path, **options)
    with pytest.raises(ValueError):
        gate.evaluate_and_issue(
            compilation_id=compilation.compilation_id,
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            jurisdiction="GB",
            contract_type="employee",
            evaluated_at=today,
        )
    with database.connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM release_tokens"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?",
            (source.job_key,),
        ).fetchone()[0] == "application_compiled"


def test_release_gate_rejects_mismatched_compilation_identity(tmp_path) -> None:
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _publication,
        _compilation,
        gate,
        _route,
    ) = _authorized_release_inputs(tmp_path)
    with pytest.raises(ValueError, match="different compilation identity"):
        gate.evaluate_and_issue(
            compilation_id="0" * 64,
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=ROOT,
            jurisdiction="GB",
            contract_type="employee",
            evaluated_at=date.today(),
        )
    with database.connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM release_tokens"
        ).fetchone()[0] == 0


def _consume_arguments(values):
    (
        _database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _publication,
        _compilation,
        _gate,
        _route,
        issued,
    ) = values
    return {
        "release_token": issued.release_token,
        "source": source,
        "artifacts": artifacts,
        "contact": contact,
        "questions": questions,
        "artifact_root": artifact_root,
        "repository_root": ROOT,
        "jurisdiction": "GB",
        "contract_type": "employee",
        "consumed_at": datetime.combine(
            date.today(),
            datetime.min.time(),
            tzinfo=timezone.utc,
        ),
    }


def test_release_token_replay_is_rejected(tmp_path) -> None:
    values = _issued_release_inputs(tmp_path)
    database, *_, gate, _route, _issued = values
    arguments = _consume_arguments(values)
    first = gate.consume_release_token(**arguments)
    with pytest.raises(ValueError, match="already consumed"):
        gate.consume_release_token(**arguments)
    with database.connection() as connection:
        stored = connection.execute(
            "SELECT consumed_at FROM release_tokens"
        ).fetchone()[0]
    assert stored == first.consumed_at


def test_unknown_release_token_is_rejected_without_consumption(tmp_path) -> None:
    values = _issued_release_inputs(tmp_path)
    database, *_, gate, _route, _issued = values
    arguments = _consume_arguments(values)
    arguments["release_token"] = (
        "jaa08." + "0" * 64 + ".not-the-issued-secret"
    )
    with pytest.raises(ValueError, match="unknown"):
        gate.consume_release_token(**arguments)
    with database.connection() as connection:
        assert connection.execute(
            "SELECT consumed_at FROM release_tokens"
        ).fetchone()[0] is None


@pytest.mark.parametrize("day_delta", (-1, 1))
def test_release_token_rejects_other_utc_dates(
    tmp_path,
    day_delta: int,
) -> None:
    values = _issued_release_inputs(tmp_path)
    database, *_, gate, _route, _issued = values
    arguments = _consume_arguments(values)
    arguments["consumed_at"] += timedelta(days=day_delta)
    with pytest.raises(ValueError, match="only on its evaluated UTC date"):
        gate.consume_release_token(**arguments)
    with database.connection() as connection:
        assert connection.execute(
            "SELECT consumed_at FROM release_tokens"
        ).fetchone()[0] is None


def test_release_token_drift_check_rejects_post_issue_artifact_tamper(
    tmp_path,
) -> None:
    values = _issued_release_inputs(tmp_path)
    (
        database,
        _strategy,
        _contact,
        _questions,
        _source,
        _artifacts,
        artifact_root,
        publication,
        _compilation,
        gate,
        _route,
        _issued,
    ) = values
    target = artifact_root / publication.relative_directory / "cv.pdf"
    target.write_bytes(target.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="differs from its receipt"):
        gate.consume_release_token(**_consume_arguments(values))
    with database.connection() as connection:
        assert connection.execute(
            "SELECT consumed_at FROM release_tokens"
        ).fetchone()[0] is None


def test_release_token_requires_timezone_aware_consumption_clock(
    tmp_path,
) -> None:
    values = _issued_release_inputs(tmp_path)
    database, *_, gate, _route, _issued = values
    arguments = _consume_arguments(values)
    arguments["consumed_at"] = datetime.combine(
        date.today(),
        datetime.min.time(),
    )
    with pytest.raises(ValueError, match="timezone"):
        gate.consume_release_token(**arguments)
    with database.connection() as connection:
        assert connection.execute(
            "SELECT consumed_at FROM release_tokens"
        ).fetchone()[0] is None


def test_release_token_drift_check_rejects_newer_contact_authority(
    tmp_path,
) -> None:
    values = _issued_release_inputs(tmp_path)
    (
        database,
        _strategy,
        _contact,
        _questions,
        _source,
        _artifacts,
        _artifact_root,
        _publication,
        _compilation,
        gate,
        _route,
        _issued,
    ) = values
    graph = CandidateGraph(database.path)
    graph.add_record(
        "contact-primary",
        kind="fact",
        subject="contact",
        value={
            "full_name": "Alex Example",
            "email": "changed@example.test",
            "phone": "+44 7700 900123",
            "city": "London",
        },
        state="fact",
        source_identity="test:newer-contact",
        version=2,
    )
    graph.verify_record(
        "contact-primary",
        2,
        decision="approved",
        verifier_kind="configured",
        policy_id="test.contact",
        policy_version="2",
        policy_hash=DIGEST,
        reason="newer operator-verified contact",
        source_identity="test:newer-contact-verifier",
    )
    with pytest.raises(ValueError):
        gate.consume_release_token(**_consume_arguments(values))
    with database.connection() as connection:
        assert connection.execute(
            "SELECT consumed_at FROM release_tokens"
        ).fetchone()[0] is None
