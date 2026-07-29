"""Independent acceptance tests for the pure deterministic JAA-08 manifest."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from datetime import date, datetime, timezone
from pathlib import Path

from career_automation.application_artifacts import publish_application_artifacts
from career_automation.application_compiler import (
    CandidateContact,
    ProductionApplicationCompiler,
)
from career_automation.application_strategy import ApplicationStrategyStore
from career_automation.candidate_graph import CandidateGraph
from career_automation.migrations import (
    JAA08_INSTALLED_SCHEMA_SHA256,
    JAA_08_MIGRATIONS,
    apply_jaa_08_migrations,
    jaa08_installed_schema_digest,
)
from career_automation.release_gate import (
    REQUIRED_VALIDATORS,
    ApplicationCompilationStore,
    ConsumedRelease,
    IssuedRelease,
    OfficialRouteBinding,
    ReleaseBinding,
    ReleaseGateStore,
    ValidationReceipt,
    WorkRightBinding,
    compile_release_manifest,
    verify_release_manifest,
)
from career_automation.rendering import render_pdf_artifacts
from test_jaa06_independent_acceptance import _fit_database


AS_OF = date(2030, 1, 2)
DIGEST = hashlib.sha256(b"jaa08-pure-contract").hexdigest()
ROOT = Path(__file__).resolve().parent


def _fixture_date(database) -> date:
    with database.connection() as connection:
        value = connection.execute(
            """SELECT as_of FROM fit_assessment_runs
               ORDER BY rowid DESC LIMIT 1"""
        ).fetchone()[0]
    return date.fromisoformat(str(value))


def _fixture_now(database) -> datetime:
    value = _fixture_date(database)
    return datetime(
        value.year,
        value.month,
        value.day,
        12,
        tzinfo=timezone.utc,
    )


def _release_gate(database) -> ReleaseGateStore:
    fixed_now = _fixture_now(database)
    return ReleaseGateStore(
        database.path,
        clock=lambda: fixed_now,
    )


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


def _compilation_inputs(tmp_path: Path):
    database, run, requirement = _fit_database(tmp_path, matched=True)
    as_of = _fixture_date(database)
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id,
        as_of=as_of,
    )
    graph = CandidateGraph(database.path)
    contact_value = {
        "full_name": "Alex Example",
        "email": "alex@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
    }
    graph.add_record(
        "contact-primary",
        kind="fact",
        subject="contact",
        value=contact_value,
        state="fact",
        source_identity="test:verified-contact",
    )
    graph.verify_record(
        "contact-primary",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="test.contact",
        policy_version="1",
        policy_hash=DIGEST,
        reason="operator-verified contact projection",
        source_identity="test:contact-verifier",
    )
    with database.connection() as connection:
        source_hash = str(connection.execute(
            """SELECT provenance.source_hash
               FROM candidate_records record
               JOIN candidate_provenance provenance
                 ON provenance.provenance_id=record.provenance_id
               WHERE record.record_id='contact-primary'"""
        ).fetchone()[0])
    contact = CandidateContact(
        record_id="contact-primary",
        record_version=1,
        provenance_sha256=source_hash,
        **contact_value,
    )
    questions = {
        requirement.requirement_id: (
            "delivery-example",
            "Describe a relevant delivery example.",
        )
    }
    source = ProductionApplicationCompiler(database.path).compile(
        strategy.strategy_id,
        as_of=as_of,
        contact=contact,
        questions=questions,
    )
    artifacts = render_pdf_artifacts(source)
    artifact_root = tmp_path / "published"
    receipt = publish_application_artifacts(
        source,
        artifacts,
        root=artifact_root,
        repository_root=ROOT,
    )
    return (
        database,
        strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        receipt,
    )


def _authorized_release_inputs(
    tmp_path: Path,
    *,
    route_allowed: bool = True,
    route_expired: bool = False,
    work_right_expired: bool = False,
):
    values = _compilation_inputs(tmp_path)
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _receipt,
    ) = values
    today = _fixture_date(database)
    graph = CandidateGraph(database.path)
    graph.add_record(
        "work-right-gb",
        kind="work_right",
        subject="permission",
        value={"permitted": True},
        state="fact",
        source_identity="test:operator-work-right",
        jurisdiction="GB",
        contract_type="employee",
        valid_from=today.replace(year=today.year - 1).isoformat(),
        valid_until=(
            today.replace(year=today.year - 1)
            if work_right_expired
            else today.replace(year=today.year + 1)
        ).isoformat(),
    )
    graph.verify_record(
        "work-right-gb",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="test.work-right",
        policy_version="1",
        policy_hash=DIGEST,
        reason="operator-verified work-right authority",
        source_identity="test:work-right-verifier",
    )
    compilation = ApplicationCompilationStore(database.path).register(
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        as_of=today,
    )
    gate = _release_gate(database)
    route = gate.register_official_route(
        job_key=source.job_key,
        route=OfficialRouteBinding(
            "route:official-test",
            "offline-test-adapter",
            "1",
            "test:official-route-policy",
            DIGEST,
            (
                today.replace(year=today.year - 2)
                if route_expired
                else today
            ),
            (
                today.replace(year=today.year - 1)
                if route_expired
                else today.replace(year=today.year + 1)
            ),
            route_allowed,
        ),
    )
    return (*values, compilation, gate, route)


def _issued_release_inputs(tmp_path: Path):
    values = _authorized_release_inputs(tmp_path)
    (
        database,
        strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        _publication,
        compilation,
        gate,
        _route,
    ) = values
    issued = gate.evaluate_and_issue(
        compilation_id=compilation.compilation_id,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        jurisdiction="GB",
        contract_type="employee",
        evaluated_at=strategy.as_of,
    )
    return (*values, issued)


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


def test_compilation_registration_revalidates_external_bytes_and_advances_atomically(
    tmp_path: Path,
) -> None:
    (
        database,
        strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        receipt,
    ) = _compilation_inputs(tmp_path)
    store = ApplicationCompilationStore(database.path)
    compilation = store.register(
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        as_of=strategy.as_of,
    )
    assert compilation.strategy_id == strategy.strategy_id
    assert compilation.application_source_id == source.source_id
    assert compilation.artifact_set_sha256 == artifacts.artifact_set_sha256
    assert compilation.artifact_receipt_sha256 == receipt.receipt_sha256
    assert store.register(
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        as_of=strategy.as_of,
    ) == compilation
    with database.connection() as connection:
        row = connection.execute(
            "SELECT * FROM application_compilations"
        ).fetchone()
        state = connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?",
            (source.job_key,),
        ).fetchone()[0]
    assert row["compilation_id"] == compilation.compilation_id
    assert row["lifecycle_receipt_id"] == compilation.lifecycle_receipt_id
    assert state == "application_compiled"


def test_jaa08_migration_is_forward_only_and_exact_schema_checked(
    tmp_path: Path,
) -> None:
    path = tmp_path / "release.sqlite3"
    assert apply_jaa_08_migrations(path) == tuple(
        row.version for row in JAA_08_MIGRATIONS
    )
    assert apply_jaa_08_migrations(path) == ()
    with sqlite3.connect(path) as connection:
        assert jaa08_installed_schema_digest(
            connection
        ) == JAA08_INSTALLED_SCHEMA_SHA256


def test_release_gate_reresolves_authority_and_issues_hash_only_token_atomically(
    tmp_path: Path,
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
    issued = gate.evaluate_and_issue(
        compilation_id=compilation.compilation_id,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        jurisdiction="GB",
        contract_type="employee",
        evaluated_at=_fixture_date(database),
    )
    assert isinstance(issued, IssuedRelease)
    verify_release_manifest(issued.manifest)
    assert issued.manifest.binding.work_right.permitted is True
    assert issued.manifest.binding.official_route.allowed is True
    assert tuple(
        row.validator_id for row in issued.manifest.validations
    ) == REQUIRED_VALIDATORS
    with database.connection() as connection:
        state = connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?",
            (source.job_key,),
        ).fetchone()[0]
        attempt = connection.execute(
            "SELECT verdict,finding_codes_json FROM release_gate_attempts"
        ).fetchone()
        stored = connection.execute(
            "SELECT token_hash,consumed_at FROM release_tokens"
        ).fetchone()
        validation_count = connection.execute(
            "SELECT COUNT(*) FROM release_validation_receipts"
        ).fetchone()[0]
        all_text = "\n".join(
            str(value)
            for table in (
                "release_gate_attempts",
                "release_manifests",
                "release_validation_receipts",
                "release_tokens",
            )
            for row in connection.execute(f"SELECT * FROM {table}").fetchall()
            for value in row
        )
    assert state == "released"
    assert tuple(attempt) == ("pass", "[]")
    assert tuple(stored) == (issued.token_sha256, None)
    assert validation_count == len(REQUIRED_VALIDATORS)
    assert issued.release_token not in all_text


def test_release_token_consumes_once_only_after_exact_authority_replay(
    tmp_path: Path,
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
        _compilation,
        gate,
        _route,
        issued,
    ) = _issued_release_inputs(tmp_path)
    consumed_at = _fixture_now(database)
    consumed = gate.consume_release_token(
        release_token=issued.release_token,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=consumed_at,
    )
    assert isinstance(consumed, ConsumedRelease)
    assert consumed.release_manifest_sha256 == (
        issued.manifest.release_manifest_sha256
    )
    assert consumed.token_sha256 == issued.token_sha256
    assert consumed.consumed_at == consumed_at.isoformat()
    with database.connection() as connection:
        stored = connection.execute(
            "SELECT token_hash,consumed_at FROM release_tokens"
        ).fetchone()
        state = connection.execute(
            "SELECT state FROM pipeline_jobs WHERE job_key=?",
            (source.job_key,),
        ).fetchone()[0]
    assert tuple(stored) == (issued.token_sha256, consumed_at.isoformat())
    assert state == "released"


def test_consumed_release_can_be_revalidated_without_second_consumption(
    tmp_path: Path,
) -> None:
    values = _issued_release_inputs(tmp_path)
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
        issued,
    ) = values
    consumed_at = _fixture_now(database)
    consumed = gate.consume_release_token(
        release_token=issued.release_token,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=consumed_at,
    )
    replay = gate.verify_consumed_release_token(
        release_token=issued.release_token,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=ROOT,
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=consumed_at,
    )
    assert replay == consumed
    with database.connection() as connection:
        assert connection.execute(
            "SELECT consumed_at FROM release_tokens"
        ).fetchone()[0] == consumed_at.isoformat()
