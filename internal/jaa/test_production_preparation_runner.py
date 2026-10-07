from __future__ import annotations

import hashlib
import inspect
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation import candidate_application_factory as candidate_factory
from career_automation import market_aligner_preparation as preparation
from career_automation import production_preparation_runner as runner
from career_automation.market_aligner_preparation import MarketApplicationPreparation


def _cv_binding_row(sentence_id: str, text: str, document_kind: str = "cv") -> dict[str, str]:
    return {
        "document_kind": document_kind,
        "sentence_id": sentence_id,
        "text": text,
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def test_current_contact_json_codecs_keep_artifact_and_wire_formats_separate() -> None:
    artifact_bytes = b'{"value":1}\n'
    wire_bytes = b'{"value":1}'

    assert runner._decode_current_artifact_document(artifact_bytes) == {"value": 1}
    with pytest.raises(ValueError):
        runner._decode_current_artifact_document(wire_bytes)
    assert runner.decode_canonical_json(wire_bytes, label="selection receipt") == {
        "value": 1
    }
    with pytest.raises(runner.HandoffContractError):
        runner.decode_canonical_json(artifact_bytes, label="selection receipt")
    with pytest.raises(TypeError, match="label"):
        runner.decode_canonical_json(wire_bytes)


def test_current_runtime_tool_paths_resolve_available_tools(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tool_directory = tmp_path / "tools"
    tool_directory.mkdir(mode=0o700)
    names = ("codex", *runner.PRODUCTION_POPPLER_SHA256)
    tool_paths = {}
    for name in names:
        tool_path = tool_directory / name
        tool_path.write_bytes(b"tool")
        tool_path.chmod(0o700)
        tool_paths[name] = tool_path
    monkeypatch.setattr(
        runner.shutil,
        "which",
        lambda name: str(tool_paths[name]) if name in tool_paths else None,
    )

    codex_path, poppler_directory = runner._current_runtime_tool_paths()

    assert codex_path == tool_paths["codex"]
    assert poppler_directory == tool_directory


def test_current_evidence_archive_is_exact_and_content_addressed() -> None:
    document = {"schema_version": "fixture.v1", "rows": [{"id": "row-1"}]}
    references, objects = preparation._current_evidence_archive(
        {"materialization": document, "duplicate": document, "absent": None}
    )
    encoded = preparation._json_bytes(document)
    digest = hashlib.sha256(encoded).hexdigest()

    assert references == {"materialization": digest, "duplicate": digest}
    assert objects == {digest: encoded}


def test_cv_binding_partition_excludes_whole_rejected_rows_and_preserves_order() -> None:
    first = _cv_binding_row("cv-1", "Synthetic first supported statement.")
    cover = _cv_binding_row(
        "cover-1", "Synthetic internal review cover detail.", "cover_letter"
    )
    excluded_text = "Synthetic positive claim with an internal review qualification."
    excluded = _cv_binding_row("cv-2", excluded_text)
    last = _cv_binding_row("cv-3", "Synthetic final supported statement.")
    rows = [first, cover, excluded, last]
    seen: list[str] = []

    def prohibited_text(text: str) -> bool:
        seen.append(text)
        return "internal review" in text

    accepted, exclusions = candidate_factory.partition_cv_claim_bindings(
        rows, prohibited_text=prohibited_text
    )

    assert accepted == (first, last)
    assert accepted[0] is first
    assert accepted[1] is last
    assert seen == [first["text"], excluded_text, last["text"]]
    assert exclusions == (
        {
            "sentence_id": "cv-2",
            "text_sha256": excluded["text_sha256"],
            "reason": "internal_evidence_only",
        },
    )
    assert "text" not in exclusions[0]
    assert excluded_text not in str(exclusions)
    assert excluded["text"] == excluded_text


def test_cv_binding_partition_refuses_empty_or_all_excluded_cv_sets() -> None:
    with pytest.raises(ValueError, match="no accepted CV rows"):
        candidate_factory.partition_cv_claim_bindings(
            [], prohibited_text=lambda text: False
        )
    with pytest.raises(ValueError, match="no accepted CV rows"):
        candidate_factory.partition_cv_claim_bindings(
            [_cv_binding_row("cv-1", "Synthetic internal review only.")],
            prohibited_text=lambda text: True,
        )


def test_cv_binding_partition_rejects_duplicate_ids_across_document_kinds() -> None:
    rows = [
        _cv_binding_row("same-id", "Synthetic CV statement."),
        _cv_binding_row("same-id", "Synthetic cover statement.", "cover_letter"),
    ]

    with pytest.raises(ValueError, match="duplicate sentence_id"):
        candidate_factory.partition_cv_claim_bindings(
            rows, prohibited_text=lambda text: False
        )


def test_cv_binding_partition_rejects_malformed_rows_and_hashes() -> None:
    invalid_id = _cv_binding_row("cv-1", "Synthetic statement.")
    invalid_id["sentence_id"] = ""
    invalid_kind = _cv_binding_row("cv-2", "Synthetic statement.")
    invalid_kind["document_kind"] = "report"
    invalid_text = _cv_binding_row("cv-3", "Synthetic statement.")
    invalid_text["text"] = ""
    invalid_hash_type = _cv_binding_row("cv-4", "Synthetic statement.")
    invalid_hash_type["text_sha256"] = 7
    invalid_hash = _cv_binding_row("cv-5", "Synthetic statement.")
    invalid_hash["text_sha256"] = "0" * 64
    uppercase_hash = _cv_binding_row("cv-6", "Synthetic statement.")
    uppercase_hash["text_sha256"] = uppercase_hash["text_sha256"].upper()
    cases = (
        "not-a-row-list",
        ["not-a-dict"],
        [{"document_kind": "cv"}],
        [invalid_id],
        [invalid_kind],
        [invalid_text],
        [invalid_hash_type],
        [invalid_hash],
        [uppercase_hash],
    )

    for rows in cases:
        with pytest.raises(ValueError):
            candidate_factory.partition_cv_claim_bindings(
                rows, prohibited_text=lambda text: False
            )


def test_cv_binding_partition_rejects_invalid_predicates_and_results() -> None:
    rows = [
        _cv_binding_row("cv-1", "Synthetic first statement."),
        _cv_binding_row("cv-2", "Synthetic second statement."),
    ]
    with pytest.raises(ValueError, match="prohibited_text must be callable"):
        candidate_factory.partition_cv_claim_bindings(
            rows, prohibited_text="not-callable"
        )
    with pytest.raises(ValueError, match="callback returned non-bool"):
        candidate_factory.partition_cv_claim_bindings(
            rows, prohibited_text=lambda text: 1
        )

    calls = 0

    def non_bool_on_second(text: str) -> object:
        nonlocal calls
        calls += 1
        return False if calls == 1 else "not-bool"

    with pytest.raises(ValueError, match="callback returned non-bool"):
        candidate_factory.partition_cv_claim_bindings(
            rows, prohibited_text=non_bool_on_second
        )


def test_current_cv_binding_partition_uses_existing_rejection_predicate() -> None:
    safe = _cv_binding_row("cv-safe", "Synthetic supported project result.")
    qualified_text = "Synthetic supported work with an internal review qualification."
    qualified = _cv_binding_row("cv-qualified", qualified_text)
    rows = [safe, qualified]
    snapshot = [dict(row) for row in rows]

    accepted, exclusions = candidate_factory.partition_current_cv_claim_bindings(rows)

    assert accepted == (safe,)
    assert exclusions == (
        {
            "sentence_id": "cv-qualified",
            "text_sha256": qualified["text_sha256"],
            "reason": "internal_evidence_only",
        },
    )
    assert rows == snapshot
    assert qualified["text"] == qualified_text


def test_current_preparation_uses_luna_and_legacy_model_is_unchanged(
    tmp_path: Path,
) -> None:
    legacy = _deployment(tmp_path)
    current = runner._current_preparation_deployment(
        SimpleNamespace(
            data_home=tmp_path,
            repository_root=tmp_path / "repo",
            output_root=tmp_path / "outbox",
            candidate_authority_path=tmp_path / "candidate.json",
            candidate_authority_sha256="a" * 64,
        ),
        "recovered-inputs/approved/recovery-manifest.json",
    )

    assert legacy.model == "gpt-test"
    assert runner.PRODUCTION_CODEX_MODEL == "gpt-5.6-sol"
    assert current.model == "gpt-6-luna"


def test_current_contact_projection_bundle_keeps_receipt_separate() -> None:
    activation_sha256 = "a" * 64
    documents = {"candidate_projection_bytes": b'{"projection":"current"}\n'}
    receipt = {"activation_sha256": activation_sha256}

    assert runner._projection_from_current_bundle(
        documents,
        receipt,
        expected_activation_sha256=activation_sha256,
    ) == {"projection": "current"}
    with pytest.raises(ValueError):
        runner._projection_from_current_bundle(
            receipt,
            documents,
            expected_activation_sha256=activation_sha256,
        )
    with pytest.raises(ValueError):
        runner._projection_from_current_bundle(
            documents,
            receipt,
            expected_activation_sha256="b" * 64,
        )


def _current_selection_and_promotion() -> tuple[dict[str, object], dict[str, object]]:
    profile_id = "profile-current"
    source_job_key = "greenhouse:example:123"
    promotion_sha256 = "1" * 64
    selection = {
        "decision": "selected_for_application",
        "geography_bucket": "uk_remote",
        "geography_priority_rank": 0,
        "hard_gate_passed": True,
        "promotion_receipt_sha256": promotion_sha256,
        "rationale_codes": [],
        "source_job_key": source_job_key,
    }
    promotion = {
        "binding": {
            "schema_version": "market-aligner.assessment-promotion-binding.v1",
            "profile_id": profile_id,
            "job_key": source_job_key,
            "track": "Applied_AI_Engineer",
        },
        "decision": "pass",
        "job_key": source_job_key,
        "profile_id": profile_id,
        "receipt_sha256": promotion_sha256,
        "schema_version": "market-aligner.assessment-promotion-receipt.v1",
    }
    return selection, promotion


def test_current_selected_track_comes_from_linked_promotion() -> None:
    selection, promotion = _current_selection_and_promotion()
    selection.update(
        {
            "job_key": "internal-not-source-key",
            "profile_id": "untrusted-profile",
            "profile_version": "untrusted-version",
            "schema_version": "untrusted-selection-schema",
            "track": "untrusted-track",
        }
    )

    assert runner._resolve_current_selected_track(
        selection,
        promotion,
        expected_profile_id="profile-current",
        expected_source_job_key="greenhouse:example:123",
    ) == "Applied_AI_Engineer"


def test_current_selected_track_rejects_unbound_promotion_and_gate() -> None:
    selection, promotion = _current_selection_and_promotion()
    unlinked_promotion = dict(promotion, receipt_sha256="2" * 64)
    with pytest.raises(ValueError, match="selected track binding invalid"):
        runner._resolve_current_selected_track(
            selection,
            unlinked_promotion,
            expected_profile_id="profile-current",
            expected_source_job_key="greenhouse:example:123",
        )

    failed_gate = dict(selection, hard_gate_passed=1)
    with pytest.raises(ValueError, match="selected track binding invalid"):
        runner._resolve_current_selected_track(
            failed_gate,
            promotion,
            expected_profile_id="profile-current",
            expected_source_job_key="greenhouse:example:123",
        )


def test_current_selected_track_rejects_profile_or_source_mismatch() -> None:
    selection, promotion = _current_selection_and_promotion()
    wrong_profile = dict(promotion, profile_id="other-profile")
    with pytest.raises(ValueError, match="selected track binding invalid"):
        runner._resolve_current_selected_track(
            selection,
            wrong_profile,
            expected_profile_id="profile-current",
            expected_source_job_key="greenhouse:example:123",
        )

    with pytest.raises(ValueError, match="selected track binding invalid"):
        runner._resolve_current_selected_track(
            selection,
            promotion,
            expected_profile_id="profile-current",
            expected_source_job_key="greenhouse:other:456",
        )


def test_candidate_editorial_authority_uses_exact_candidate_policy() -> None:
    authority = preparation._candidate_editorial_authority(
        candidate_name="Artiom Gutu",
        candidate_city="Birmingham",
        source_sha256="a" * 64,
    )
    assert authority.graduation_month_year == "July 2026"
    assert authority.dissertation_title == (
        "SCAFAD: A Seven-Layer, Privacy-Preserving, Explainable "
        "Anomaly-Detection Pipeline for Serverless Workloads"
    )
    assert authority.require_dissertation is True

    unrelated = preparation._candidate_editorial_authority(
        candidate_name="Another Candidate",
        candidate_city="Birmingham",
        source_sha256="b" * 64,
    )
    assert unrelated.graduation_month_year is None
    assert unrelated.dissertation_title is None
    assert unrelated.require_dissertation is False


def _deployment(tmp_path: Path) -> runner._ProductionPreparationDeployment:
    binary = tmp_path / "codex"
    binary.write_bytes(b"fixture executable")
    binary.chmod(0o700)
    return runner._ProductionPreparationDeployment(
        repository_root=tmp_path / "repository",
        data_home=tmp_path / "data-home",
        admission_database=tmp_path / "admissions.sqlite3",
        outbox_root=tmp_path / "outbox",
        candidate_authority_path=tmp_path / "candidate.json",
        contact_authority_path=tmp_path / "contact.json",
        contact_public_key_path=tmp_path / "public.pem",
        contact_registry_path=tmp_path / "registry.json",
        output_root=tmp_path / "preparations",
        recruiter_archive_root=tmp_path / "recruiter",
        codex_binary=binary,
        poppler_bin=tmp_path,
        model="gpt-test",
        timeout_seconds=30,
    )


def _write_admission_fixture(
    database: Path,
    application_id: str,
    *,
    context_producer: str,
    stored_producer: str | None = None,
    canonical: bool = True,
    context_sha256: str | None = None,
    handoff_root_sha256: str = "4" * 64,
) -> None:
    context = {
        "environment": "production",
        "handoff_root_sha256": handoff_root_sha256,
        "producer_commit_sha": context_producer,
        "producer_product": "market-aligner",
        "source_record_sha256": "3" * 64,
        "trust_root_id": runner.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    }
    if canonical:
        context_bytes = runner.canonical_json_bytes(context)
    else:
        context_bytes = json.dumps(context, indent=2, sort_keys=True).encode() + b"\n"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE application_admissions ("
        "application_id TEXT PRIMARY KEY, admission_context_bytes BLOB NOT NULL, "
        "admission_context_sha256 TEXT NOT NULL, producer_commit_sha TEXT NOT NULL, "
        "producer_product TEXT NOT NULL, environment TEXT NOT NULL, "
        "trust_root_id TEXT NOT NULL, handoff_root_sha256 TEXT NOT NULL, "
        "sealed INTEGER NOT NULL)"
    )
    connection.execute(
        "INSERT INTO application_admissions VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
        (
            application_id,
            context_bytes,
            context_sha256 or hashlib.sha256(context_bytes).hexdigest(),
            stored_producer or context_producer,
            "market-aligner",
            "production",
            runner.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
            handoff_root_sha256,
        ),
    )
    connection.commit()
    connection.close()


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _real_preflight_deployment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[runner._ProductionPreparationDeployment, dict[str, Path]]:
    data_home = tmp_path / "data-home"
    data_home.mkdir(mode=0o700)
    data_state = data_home / "state"
    data_state.mkdir(mode=0o700)
    admission_root = data_state / "jaa-production-admissions"
    admission_root.mkdir(mode=0o700)
    database = admission_root / "admissions.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE fixture (identity TEXT NOT NULL)")
    connection.commit()
    connection.close()
    database.chmod(0o600)

    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    outbox = tmp_path / "outbox"
    outbox.mkdir(mode=0o700)
    poppler = tmp_path / "poppler"
    poppler.mkdir(mode=0o700)
    library_root = tmp_path / "lib"
    library_root.mkdir(mode=0o700)
    poppler_libraries = library_root / "x86_64-linux-gnu"
    poppler_libraries.mkdir(mode=0o700)
    codex = tmp_path / "codex"
    codex.write_bytes(b"exact codex")
    codex.chmod(0o755)
    authority_root = tmp_path / "authority"
    authority_root.mkdir(mode=0o700)
    contact_root = tmp_path / "contact"
    contact_root.mkdir(mode=0o700)
    paths = {
        "candidate": authority_root / "candidate.json",
        "contact": contact_root / "contact.json",
        "public_key": contact_root / "public.pem",
        "registry": contact_root / "registry.json",
        "codex": codex,
        "database": database,
        "output": tmp_path / "output",
        "recruiter": tmp_path / "recruiter",
    }
    for name in ("candidate", "contact", "public_key", "registry"):
        value = (
            b'{"prior_registry_sha256":null}'
            if name == "registry"
            else name.encode()
        )
        paths[name].write_bytes(value)
        paths[name].chmod(0o600)
    poppler_hashes: dict[str, str] = {}
    for name in runner.PRODUCTION_POPPLER_SHA256:
        path = poppler / name
        path.write_bytes(name.encode())
        path.chmod(0o755)
        poppler_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    poppler_library_hashes: dict[str, str] = {}
    for name in runner.PRODUCTION_POPPLER_LIBRARY_SHA256:
        path = poppler_libraries / name
        path.write_bytes(name.encode())
        path.chmod(0o644)
        poppler_library_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    paths["poppler"] = poppler / "pdfinfo"

    deployment = runner._ProductionPreparationDeployment(
        repository_root=repository,
        data_home=data_home,
        admission_database=database,
        outbox_root=outbox,
        candidate_authority_path=paths["candidate"],
        contact_authority_path=paths["contact"],
        contact_public_key_path=paths["public_key"],
        contact_registry_path=paths["registry"],
        output_root=paths["output"],
        recruiter_archive_root=paths["recruiter"],
        codex_binary=codex,
        poppler_bin=poppler,
        model="gpt-test",
        timeout_seconds=30,
    )
    monkeypatch.setattr(runner, "PRODUCTION_MARKET_DATA_HOME", data_home)
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_BIN", poppler)
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_SHA256", poppler_hashes)
    monkeypatch.setattr(
        runner, "PRODUCTION_POPPLER_LIBRARY_DIRECTORY", poppler_libraries
    )
    monkeypatch.setattr(
        runner, "PRODUCTION_POPPLER_LIBRARY_SHA256", poppler_library_hashes
    )
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CODEX_BINARY_SHA256",
        hashlib.sha256(codex.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(runner, "PRODUCTION_CODEX_OWNER_UID", os.geteuid())
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CANDIDATE_AUTHORITY_SHA256",
        hashlib.sha256(paths["candidate"].read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CONTACT_ENVELOPE_SHA256",
        hashlib.sha256(paths["contact"].read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256",
        hashlib.sha256(paths["public_key"].read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        runner,
        "PRODUCTION_CONTACT_REGISTRY_FILE_SHA256",
        hashlib.sha256(paths["registry"].read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(runner, "_git_commit", lambda *args, **kwargs: "2" * 40)

    class _Pinned:
        def __init__(self, _deployment):
            self.data_descriptor = os.open(data_home, os.O_RDONLY | os.O_DIRECTORY)
            self.repository_descriptor = os.open(
                repository, os.O_RDONLY | os.O_DIRECTORY
            )
            self.bundle_descriptor: int | None = None

        def open_bundle(self, _source):
            self.bundle_descriptor = os.open(outbox, os.O_RDONLY | os.O_DIRECTORY)
            return self.bundle_descriptor

        def register_adapter(self, _adapter):
            pass

        def verify_references(self):
            pass

        def close(self):
            if self.bundle_descriptor is not None:
                os.close(self.bundle_descriptor)
            os.close(self.repository_descriptor)
            os.close(self.data_descriptor)

    monkeypatch.setattr(runner, "_PinnedProductionPaths", _Pinned)
    monkeypatch.setattr(
        runner,
        "_source_record_for_application",
        lambda *args: runner._AdmittedSourceRecord("3" * 64, "2" * 40),
    )
    monkeypatch.setattr(runner, "ProtectedLocalOutbox", lambda *args, **kwargs: object())
    monkeypatch.setattr(runner, "HandoffAdmissionStore", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        runner, "installed_production_current_time_witness", lambda: object()
    )
    return deployment, paths


def test_public_runner_accepts_only_application_id() -> None:
    assert tuple(inspect.signature(runner.run_production_preparation).parameters) == (
        "application_id",
    )


def test_registry_chain_predecessors_remain_in_the_resource_lease(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    prior_identity = "1" * 64
    head = registry / ("2" * 64 + ".json")
    prior = registry / f"{prior_identity}.json"
    head.write_bytes(
        json.dumps(
            {"prior_registry_sha256": prior_identity},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    prior.write_bytes(b'{"prior_registry_sha256":null}')
    head.chmod(0o600)
    prior.chmod(0o600)
    resources = runner._PinnedPreparationResources()
    try:
        resources.pin_file(
            head,
            expected_sha256=hashlib.sha256(head.read_bytes()).hexdigest(),
            expected_mode=0o600,
            expected_uid=os.geteuid(),
            label="contact registry",
        )
        chain = resources.pin_contact_registry_chain(head)
        assert tuple(path for path, _value in chain) == (head, prior)
        assert tuple(value for _path, value in chain) == (
            head.read_bytes(),
            prior.read_bytes(),
        )

        replacement = registry / "replacement.json"
        replacement.write_bytes(prior.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(prior)
        with pytest.raises(
            runner.ProductionPreparationDeploymentError,
            match="changed during operation",
        ):
            resources.verify()
    finally:
        resources.close()


def test_installed_deployment_resolves_host_paths_bound_to_handoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    values = {
        "data_home": tmp_path / "private-state",
        "repository_root": Path(__file__).resolve().parents[2],
        "outbox_root": tmp_path / "private-outbox",
        "candidate_authority_path": tmp_path / "authority" / "candidate.json",
        "contact_authority_path": tmp_path / "authority" / "contact.json",
        "contact_public_key_path": tmp_path / "authority" / "operator.pem",
        "contact_registry_path": tmp_path / "authority" / "registry.json",
        "codex_binary": tmp_path / "codex" / "bin" / "codex.js",
        "poppler_bin": tmp_path / "poppler" / "usr" / "bin",
    }
    raw = runner.production_preparation_configuration_bytes(**values)
    monkeypatch.setattr(runner, "_read_root_owned_configuration", lambda _path: raw)
    monkeypatch.setattr(
        runner,
        "installed_production_handoff_deployment",
        lambda: SimpleNamespace(
            data_home=values["data_home"],
            repository_root=values["repository_root"],
            output_root=values["outbox_root"],
            candidate_authority_path=values["candidate_authority_path"],
            candidate_authority_sha256=runner.PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
        ),
    )

    deployment = runner.installed_production_preparation_deployment()

    assert deployment.data_home == values["data_home"]
    assert deployment.repository_root == values["repository_root"]
    assert deployment.outbox_root == values["outbox_root"]
    assert deployment.candidate_authority_path == values["candidate_authority_path"]
    assert deployment.admission_database == (
        values["data_home"] / "state/jaa-production-admissions/admissions.sqlite3"
    )
    assert deployment.poppler_library_directory == (
        values["poppler_bin"].parent / "lib/x86_64-linux-gnu"
    )


def test_source_record_binds_exact_sealed_producer_context(tmp_path: Path) -> None:
    application_id = "app_" + "1" * 64
    database = tmp_path / "admissions.sqlite3"
    _write_admission_fixture(
        database,
        application_id,
        context_producer="2" * 40,
    )
    admitted = runner._source_record_for_application(database, application_id)
    assert admitted == runner._AdmittedSourceRecord("3" * 64, "2" * 40)


@pytest.mark.parametrize(
    "substitution",
    ("stored-producer", "context-encoding", "context-hash"),
)
def test_source_record_rejects_sealed_context_substitution(
    tmp_path: Path, substitution: str
) -> None:
    application_id = "app_" + "1" * 64
    database = tmp_path / "admissions.sqlite3"
    _write_admission_fixture(
        database,
        application_id,
        context_producer="2" * 40,
        stored_producer="1" * 40 if substitution == "stored-producer" else None,
        canonical=substitution != "context-encoding",
        context_sha256="0" * 64 if substitution == "context-hash" else None,
    )
    with pytest.raises(
        runner.ProductionPreparationDeploymentError,
        match="sealed admission context differs",
    ):
        runner._source_record_for_application(database, application_id)


def test_admitted_ancestor_with_unchanged_handoff_authority_is_compatible(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Artiom Gutu")
    _git(repository, "config", "user.email", "gutu.artiom444@gmail.com")
    authority = repository / runner._HANDOFF_AUTHORITY_PATHS[0]
    authority.parent.mkdir(parents=True)
    authority.write_text("sealed authority\n")
    _git(repository, "add", str(authority.relative_to(repository)))
    _git(repository, "commit", "-qm", "admitted")
    admitted = _git(repository, "rev-parse", "HEAD")
    (repository / "unrelated.txt").write_text("current runtime\n")
    _git(repository, "add", "unrelated.txt")
    _git(repository, "commit", "-qm", "runtime-only change")
    current = _git(repository, "rev-parse", "HEAD")
    descriptor = os.open(repository, os.O_RDONLY | os.O_DIRECTORY)
    try:
        runner._require_compatible_admitted_producer(
            repository_descriptor=descriptor,
            admitted_producer_commit=admitted,
            current_commit=current,
        )
    finally:
        os.close(descriptor)


def test_admitted_producer_rejects_authority_change_and_nonancestor(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Artiom Gutu")
    _git(repository, "config", "user.email", "gutu.artiom444@gmail.com")
    authority = repository / runner._HANDOFF_AUTHORITY_PATHS[0]
    authority.parent.mkdir(parents=True)
    authority.write_text("sealed authority\n")
    _git(repository, "add", str(authority.relative_to(repository)))
    _git(repository, "commit", "-qm", "admitted")
    admitted = _git(repository, "rev-parse", "HEAD")
    authority.write_text("changed authority\n")
    _git(repository, "add", str(authority.relative_to(repository)))
    _git(repository, "commit", "-qm", "changed authority")
    changed = _git(repository, "rev-parse", "HEAD")
    descriptor = os.open(repository, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(
            runner.ProductionPreparationDeploymentError,
            match="handoff authority changed",
        ):
            runner._require_compatible_admitted_producer(
                repository_descriptor=descriptor,
                admitted_producer_commit=admitted,
                current_commit=changed,
            )
        empty_tree = _git(repository, "hash-object", "-t", "tree", "/dev/null")
        diverged = _git(repository, "commit-tree", empty_tree, "-m", "diverged")
        with pytest.raises(
            runner.ProductionPreparationDeploymentError,
            match="not an ancestor",
        ):
            runner._require_compatible_admitted_producer(
                repository_descriptor=descriptor,
                admitted_producer_commit=diverged,
                current_commit=changed,
            )
    finally:
        os.close(descriptor)


def _verified_current_strategy_input(
    application_id: str,
    handoff_root_sha256: str,
) -> runner.VerifiedApplicationInput:
    return runner.VerifiedApplicationInput(
        application_id=application_id,
        admission_kind=runner.ADMISSION_KIND_CURRENT_RUNTIME,
        environment=runner.CURRENT_RUNTIME_ENVIRONMENT,
        authority_scope=runner.CURRENT_RUNTIME_AUTHORITY_SCOPE,
        handoff_root_sha256=handoff_root_sha256,
        vacancy_source_identity="source-identity",
        profile_id="profile-test",
        profile_version="v1",
        candidate_authority_sha256="a" * 64,
        job_key="greenhouse:example:1",
        vacancy_snapshot_sha256="b" * 64,
        raw_listing_sha256="c" * 64,
        raw_listing_bytes=b"listing",
        requirements_sha256="d" * 64,
        requirements_bytes=b"requirements",
        canonical_url="https://example.test/jobs/1",
        company_name="Example",
        role_title="Engineer",
        location={},
        admission_receipt_sha256="e" * 64,
        current_boundary="strategy",
        current_boundary_receipt_sha256="f" * 64,
    )


def test_current_reader_change_requires_revalidated_original_bundle(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Artiom Gutu")
    _git(repository, "config", "user.email", "gutu.artiom444@gmail.com")
    producer = repository / runner._HANDOFF_AUTHORITY_PATHS[0]
    reader_names = tuple(sorted(runner._CURRENT_RUNTIME_READER_PATHS))
    producer.parent.mkdir(parents=True)
    for reader_name in reader_names:
        (repository / reader_name).parent.mkdir(parents=True, exist_ok=True)
    producer.write_text("original producer\n")
    for reader_name in reader_names:
        (repository / reader_name).write_text("original reader\n")
    _git(repository, "add", runner._HANDOFF_AUTHORITY_PATHS[0], *reader_names)
    _git(repository, "commit", "-qm", "admitted producer")
    admitted = _git(repository, "rev-parse", "HEAD")
    for reader_name in reader_names:
        (repository / reader_name).write_text("compatible current reader\n")
    _git(repository, "add", *reader_names)
    _git(repository, "commit", "-qm", "current reader repair")
    current = _git(repository, "rev-parse", "HEAD")
    application_id = "app_" + "1" * 64
    handoff_root_sha256 = "2" * 64
    verified = _verified_current_strategy_input(
        application_id, handoff_root_sha256
    )
    descriptor = os.open(repository, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(
            runner.ProductionPreparationDeploymentError,
            match="current reader compatibility not established",
        ):
            runner._require_compatible_admitted_producer(
                repository_descriptor=descriptor,
                admitted_producer_commit=admitted,
                current_commit=current,
                current_runtime=True,
                expected_application_id=application_id,
                expected_handoff_root_sha256=handoff_root_sha256,
            )
        runner._require_compatible_admitted_producer(
            repository_descriptor=descriptor,
            admitted_producer_commit=admitted,
            current_commit=current,
            current_runtime=True,
            verified_current_input=verified,
            expected_application_id=application_id,
            expected_handoff_root_sha256=handoff_root_sha256,
        )
        with pytest.raises(
            runner.ProductionPreparationDeploymentError,
            match="handoff authority changed",
        ):
            runner._require_compatible_admitted_producer(
                repository_descriptor=descriptor,
                admitted_producer_commit=admitted,
                current_commit=current,
            )
        producer.write_text("changed producer\n")
        _git(repository, "add", runner._HANDOFF_AUTHORITY_PATHS[0])
        _git(repository, "commit", "-qm", "producer mutation")
        changed_producer = _git(repository, "rev-parse", "HEAD")
        with pytest.raises(
            runner.ProductionPreparationDeploymentError,
            match="current reader compatibility not established",
        ):
            runner._require_compatible_admitted_producer(
                repository_descriptor=descriptor,
                admitted_producer_commit=admitted,
                current_commit=changed_producer,
                current_runtime=True,
                verified_current_input=verified,
                expected_application_id=application_id,
                expected_handoff_root_sha256=handoff_root_sha256,
            )
    finally:
        os.close(descriptor)


def test_consumer_compatibility_helper_fails_closed_on_invalid_reports() -> None:
    admitted = "a" * 40
    current = "b" * 40
    protected = frozenset(runner._HANDOFF_AUTHORITY_PATHS)
    readers = runner._CURRENT_RUNTIME_READER_PATHS
    assert readers == frozenset(
        {
            "internal/jaa/career_automation/handoff_admission.py",
            "internal/jaa/career_automation/production_handoff_admission_runner.py",
        }
    )
    common = {
        "admitted_commit": admitted,
        "current_commit": current,
        "ancestor_status": 0,
        "diff_status": 0,
        "changed_paths": tuple(sorted(readers)),
        "protected_paths": protected,
        "reader_paths": readers,
        "current_runtime": True,
        "current_bundle_revalidated": True,
    }
    assert runner.require_consumer_compatibility(**common) == (
        "current_reader_revalidated"
    )
    for change in (
        {"current_runtime": False},
        {"current_bundle_revalidated": False},
        {"changed_paths": (runner._HANDOFF_AUTHORITY_PATHS[0],)},
        {"changed_paths": ("untracked-protected.py",)},
        {"ancestor_status": 1},
        {"diff_status": 1},
        {"current_runtime": 1},
        {"ancestor_status": True},
        {"changed_paths": [next(iter(readers))]},
        {"changed_paths": (next(iter(readers)), next(iter(readers)))},
    ):
        with pytest.raises(ValueError):
            runner.require_consumer_compatibility(**(common | change))
    assert runner.require_consumer_compatibility(
        admitted_commit=admitted,
        current_commit=admitted,
        ancestor_status=0,
        diff_status=0,
        changed_paths=(),
        protected_paths=protected,
        reader_paths=readers,
        current_runtime=False,
    ) == "same_commit"


def test_current_strategy_boundary_precedes_compatibility_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application_id = "app_" + "3" * 64
    handoff_root_sha256 = "4" * 64
    verified = _verified_current_strategy_input(
        application_id, handoff_root_sha256
    )
    events: list[str] = []

    class _Store:
        def for_boundary(self, requested_application_id: str, boundary: str):
            assert requested_application_id == application_id
            assert boundary == "strategy"
            events.append("authenticated_boundary")
            return verified

    class _Adapter:
        handoff_bytes = b"authenticated current handoff"

    class _Handoff:
        root_sha256 = handoff_root_sha256

    monkeypatch.setattr(
        runner,
        "_parse_current_runtime_handoff",
        lambda raw: _Handoff(),
    )
    monkeypatch.setattr(
        runner,
        "_git_commit",
        lambda path, **kwargs: "5" * 40,
    )

    def require_compatibility(**kwargs):
        assert kwargs["verified_current_input"] is verified
        events.append("compatibility")

    monkeypatch.setattr(
        runner,
        "_require_compatible_admitted_producer",
        require_compatibility,
    )
    result = runner._current_runtime_strategy_input(
        store=_Store(),
        application_id=application_id,
        adapter=_Adapter(),
        repository_root=Path("/registered/canon"),
        repository_descriptor=9,
        admitted_producer_commit="6" * 40,
        current_commit="5" * 40,
    )
    assert result is verified
    assert events == ["authenticated_boundary", "compatibility"]


def test_fixed_runner_wires_cv_cover_and_recruiter_without_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    application_id = "app_" + "1" * 64
    captured: dict[str, object] = {}
    adapter_arguments: dict[str, object] = {}
    editorial_arguments: list[dict[str, object]] = []
    recruiter_arguments: dict[str, object] = {}
    poppler_arguments: dict[str, object] = {}
    producer_compatibility: dict[str, object] = {}
    stages: list[str] = []
    monkeypatch.delenv(runner.PUBLIC_KEY_ENV, raising=False)
    monkeypatch.delenv(runner.REGISTRY_ENV, raising=False)
    monkeypatch.delenv("JAA_POPPLER_BIN", raising=False)

    monkeypatch.setattr(runner, "_git_commit", lambda path, **kwargs: "2" * 40)
    monkeypatch.setattr(
        runner,
        "_source_record_for_application",
        lambda *args: runner._AdmittedSourceRecord("3" * 64, "1" * 40),
    )
    monkeypatch.setattr(
        runner,
        "_require_compatible_admitted_producer",
        lambda **kwargs: producer_compatibility.update(kwargs),
    )
    def protected_outbox(*args, **kwargs):
        adapter_arguments.update(kwargs)
        return object()

    monkeypatch.setattr(runner, "ProtectedLocalOutbox", protected_outbox)
    monkeypatch.setattr(runner, "HandoffAdmissionStore", lambda *args, **kwargs: object())
    monkeypatch.setattr(runner, "installed_production_current_time_witness", lambda: object())
    monkeypatch.setattr(
        runner,
        "PRODUCTION_POPPLER_BIN",
        tmp_path,
    )
    hashes = {}
    for name in runner.PRODUCTION_POPPLER_SHA256:
        path = tmp_path / name
        path.write_bytes(name.encode())
        hashes[name] = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_SHA256", hashes)
    deployment.poppler_library_directory.mkdir(mode=0o700, parents=True)
    library_hashes = {}
    for name in runner.PRODUCTION_POPPLER_LIBRARY_SHA256:
        path = deployment.poppler_library_directory / name
        path.write_bytes(name.encode())
        library_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        runner, "PRODUCTION_POPPLER_LIBRARY_SHA256", library_hashes
    )
    authority_constants = (
        (deployment.candidate_authority_path, "PRODUCTION_CANDIDATE_AUTHORITY_SHA256"),
        (deployment.contact_authority_path, "PRODUCTION_CONTACT_ENVELOPE_SHA256"),
        (deployment.contact_public_key_path, "PRODUCTION_CONTACT_PUBLIC_KEY_FILE_SHA256"),
        (deployment.contact_registry_path, "PRODUCTION_CONTACT_REGISTRY_FILE_SHA256"),
    )
    for path, name in authority_constants:
        path.write_bytes(name.encode())
        monkeypatch.setattr(runner, name, hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setattr(
        runner,
        "_expected_configuration",
        lambda: {"codex_binary_sha256": hashlib.sha256(deployment.codex_binary.read_bytes()).hexdigest()},
    )

    descriptor_holder: dict[str, int] = {}
    pin_calls: list[tuple[Path, dict[str, object]]] = []

    class _Resources:
        def __init__(self):
            self.directory_descriptors: list[int] = []
        def pin_file(self, *args, **kwargs):
            pin_calls.append((args[0], dict(kwargs)))
            return args[0]
        def pin_private_directory(self, path):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            return path
        def file_bytes(self, path): return path.read_bytes()
        def file_descriptor(self, path):
            return (
                descriptor_holder["database"]
                if path == deployment.admission_database
                else 44
            )
        def pin_contact_registry_chain(self, path):
            return ((path, path.read_bytes()),)
        def directory_descriptor(self, path):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            self.directory_descriptors.append(descriptor)
            return descriptor
        def verify(self): pass
        def close(self):
            while self.directory_descriptors:
                os.close(self.directory_descriptors.pop())

    monkeypatch.setattr(runner, "_PinnedPreparationResources", _Resources)
    pinned_poppler = object()
    def pin_poppler(
        descriptors,
        hashes,
        *,
        library_descriptors,
        expected_library_sha256,
    ):
        poppler_arguments.update(
            {
                "descriptors": descriptors,
                "hashes": hashes,
                "library_descriptors": library_descriptors,
                "library_hashes": expected_library_sha256,
            }
        )
        return pinned_poppler

    monkeypatch.setattr(runner, "pinned_poppler_runtime", pin_poppler)

    class _Pinned:
        repository_descriptor = 10
        data_descriptor = 9
        def __init__(self, deployment): pass
        def open_bundle(self, source): return 11
        def register_adapter(self, adapter): pass
        def verify_references(self): pass
        def close(self): pass

    monkeypatch.setattr(runner, "_PinnedProductionPaths", _Pinned)
    def open_admission(_parent):
        database = os.open(deployment.codex_binary, os.O_RDONLY)
        descriptor_holder["database"] = database
        return (os.open(tmp_path, os.O_RDONLY), database)

    monkeypatch.setattr(
        runner,
        "_open_admission_database",
        open_admission,
    )

    class _Adapter:
        provider = "fixture"
        model = "gpt-test"
        transport_identity = "4" * 64
        environment = "production"

        def __init__(self, *, stage: str, **kwargs):
            self.stage = stage
            stages.append(stage)
            editorial_arguments.append(dict(kwargs))

    monkeypatch.setattr(runner, "DetachedCodexEditorialAdapter", _Adapter)
    assessor = object()
    def production_assessor(**kwargs):
        recruiter_arguments.update(kwargs)
        return assessor

    monkeypatch.setattr(runner, "ProductionDetachedRecruiterAssessor", production_assessor)
    preparation_id = "5" * 64
    destination = deployment.output_root / "preparations" / preparation_id
    expected = MarketApplicationPreparation(
        preparation_id=preparation_id,
        path=destination,
        receipt_sha256=hashlib.sha256(b"receipt").hexdigest(),
        orchestration_sha256="7" * 64,
    )

    def prepare(**kwargs):
        captured.update(kwargs)
        objects = destination / "objects"
        objects.mkdir(parents=True, mode=0o700, exist_ok=True)
        deployment.output_root.chmod(0o700)
        destination.parent.chmod(0o700)
        destination.chmod(0o700)
        objects.chmod(0o700)
        for path, value in (
            (objects / ("a" * 64), b"authority"),
            (destination / "cv.pdf", b"cv"),
            (destination / "cover-letter.pdf", b"letter"),
            (destination / "receipt.json", b"receipt"),
        ):
            if not path.exists():
                path.write_bytes(value)
                path.chmod(0o600)
        return expected

    monkeypatch.setattr(runner, "prepare_admitted_market_application_from_authorities", prepare)
    result = runner._run_production_preparation(application_id, deployment)
    assert result == expected
    legacy_file_pins = {path: values for path, values in pin_calls}
    for name, digest in hashes.items():
        poppler_pin = legacy_file_pins[tmp_path / name]
        assert poppler_pin["expected_sha256"] == digest
        assert poppler_pin["expected_mode"] == 0o755
        assert poppler_pin["expected_uid"] == os.geteuid()
    codex_pin = legacy_file_pins[deployment.codex_binary]
    assert codex_pin["expected_sha256"] == runner.PRODUCTION_CODEX_BINARY_SHA256
    assert codex_pin["expected_mode"] == 0o755
    assert codex_pin["expected_uid"] == runner.PRODUCTION_CODEX_OWNER_UID
    assert stages == [
        "resume_writer", "humanizer", "cover_letter_writer", "cover_letter_humanizer"
    ]
    assert captured["environment"] == "production"
    assert captured["input_materializer"].materialization_only is False
    assert captured["editorial_runtime"].document_kind == "cv"
    assert captured["cover_letter_editorial_runtime"].document_kind == "cover_letter"
    assert captured["editorial_runtime"] is not captured["cover_letter_editorial_runtime"]
    assert adapter_arguments["expected_source_record_sha256"] == "3" * 64
    assert adapter_arguments["allowed_producer_commits"] == frozenset({"1" * 40})
    assert producer_compatibility["admitted_producer_commit"] == "1" * 40
    assert producer_compatibility["current_commit"] == "2" * 40
    assert captured["orchestration_extras"]["production_recruiter_assessor"] is assessor
    assert captured["orchestration_extras"]["poppler_runtime"] is pinned_poppler
    assert {row["codex_binary_fd"] for row in editorial_arguments} == {44}
    assert recruiter_arguments["codex_binary_fd"] == 44
    assert isinstance(recruiter_arguments["archive_descriptor"], int)
    assert set(poppler_arguments["descriptors"]) == set(
        runner.PRODUCTION_POPPLER_SHA256
    )
    assert set(poppler_arguments["library_descriptors"]) == set(
        runner.PRODUCTION_POPPLER_LIBRARY_SHA256
    )
    assert poppler_arguments["library_hashes"] == (
        runner.PRODUCTION_POPPLER_LIBRARY_SHA256
    )
    assert captured["candidate_authority_bytes"] == (
        deployment.candidate_authority_path.read_bytes()
    )
    assert captured["contact_resource_lease"].authority_bytes == (
        deployment.contact_authority_path.read_bytes()
    )
    assert result.release_authority is False
    assert runner.PUBLIC_KEY_ENV not in __import__("os").environ
    assert runner.REGISTRY_ENV not in __import__("os").environ
    assert "JAA_POPPLER_BIN" not in __import__("os").environ

    os.environ[runner.PUBLIC_KEY_ENV] = "prior-public-key"
    os.environ[runner.REGISTRY_ENV] = "prior-registry"
    os.environ["JAA_POPPLER_BIN"] = "prior-poppler"

    def fail_preparation(**kwargs):
        raise RuntimeError("injected preparation failure")

    monkeypatch.setattr(
        runner,
        "prepare_admitted_market_application_from_authorities",
        fail_preparation,
    )
    with pytest.raises(RuntimeError, match="injected preparation failure"):
        runner._run_production_preparation(application_id, deployment)
    assert os.environ[runner.PUBLIC_KEY_ENV] == "prior-public-key"
    assert os.environ[runner.REGISTRY_ENV] == "prior-registry"
    assert os.environ["JAA_POPPLER_BIN"] == "prior-poppler"


@pytest.mark.parametrize("application_id", ("bad", "app_" + "z" * 64))
def test_fixed_runner_rejects_malformed_application_before_transport(
    tmp_path: Path,
    application_id: str,
) -> None:
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="application ID"):
        runner._run_production_preparation(application_id, _deployment(tmp_path))


def test_poppler_substitution_rejects_before_provider_availability(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    calls = {"adapter": 0, "recruiter": 0}
    monkeypatch.setattr(runner, "PRODUCTION_POPPLER_SHA256", {"pdfinfo": "0" * 64})
    (tmp_path / "pdfinfo").write_bytes(b"substituted")
    monkeypatch.setattr(
        runner,
        "DetachedCodexEditorialAdapter",
        lambda **kwargs: calls.__setitem__("adapter", calls["adapter"] + 1),
    )
    monkeypatch.setattr(
        runner,
        "ProductionDetachedRecruiterAssessor",
        lambda **kwargs: calls.__setitem__("recruiter", calls["recruiter"] + 1),
    )
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="Poppler"):
        runner._run_production_preparation("app_" + "1" * 64, deployment)
    assert calls == {"adapter": 0, "recruiter": 0}


@pytest.mark.parametrize(
    ("authority", "change", "message"),
    (
        ("candidate", "missing", "compiled authority file is unavailable"),
        ("candidate", "tampered", "compiled authority file identity differs"),
        ("contact", "missing", "compiled authority file is unavailable"),
        ("contact", "tampered", "compiled authority file identity differs"),
    ),
)
def test_materialization_only_still_rejects_missing_or_tampered_shared_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    authority: str,
    change: str,
    message: str,
) -> None:
    deployment, paths = _real_preflight_deployment(monkeypatch, tmp_path)
    calls = {"materializer": 0}
    monkeypatch.setattr(
        runner,
        "installed_production_preparation_deployment",
        lambda: deployment,
    )
    monkeypatch.setattr(
        runner,
        "prepare_admitted_market_application_from_authorities",
        lambda **kwargs: calls.__setitem__("materializer", calls["materializer"] + 1),
    )
    path = paths[authority]
    if change == "missing":
        path.unlink()
    else:
        original = path.read_bytes()
        path.write_bytes(bytes((original[0] ^ 1,)) + original[1:])
        path.chmod(0o600)

    with pytest.raises(runner.ProductionPreparationDeploymentError, match=message):
        runner.run_production_market_materialization(
            application_id="app_" + "1" * 64
        )
    assert calls["materializer"] == 0


def test_pinned_file_rejects_hash_mode_link_and_symlink_substitution(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authority.json"
    path.write_bytes(b"authority")
    path.chmod(0o600)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    path.chmod(0o644)
    resources = runner._PinnedPreparationResources()
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="identity"):
        resources.pin_file(
            path,
            expected_sha256=digest,
            expected_mode=0o600,
            expected_uid=os.geteuid(),
        )
    resources.close()

    path.chmod(0o600)
    hardlink = tmp_path / "authority-hardlink.json"
    os.link(path, hardlink)
    resources = runner._PinnedPreparationResources()
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="identity"):
        resources.pin_file(
            path,
            expected_sha256=digest,
            expected_mode=0o600,
            expected_uid=os.geteuid(),
        )
    resources.close()
    hardlink.unlink()

    target = tmp_path / "target.json"
    path.rename(target)
    path.symlink_to(target)
    resources = runner._PinnedPreparationResources()
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="unavailable"):
        resources.pin_file(
            path,
            expected_sha256=digest,
            expected_mode=0o600,
            expected_uid=os.geteuid(),
        )
    resources.close()


def test_pinned_file_detects_leaf_and_ancestor_replacement(tmp_path: Path) -> None:
    parent = tmp_path / "authority-root"
    parent.mkdir(mode=0o700)
    path = parent / "authority.json"
    path.write_bytes(b"authority")
    path.chmod(0o600)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    resources = runner._PinnedPreparationResources()
    resources.pin_file(
        path,
        expected_sha256=digest,
        expected_mode=0o600,
        expected_uid=os.geteuid(),
    )
    path.unlink()
    path.write_bytes(b"authority")
    path.chmod(0o600)
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="changed"):
        resources.verify()
    resources.close()

    path.unlink()
    path.write_bytes(b"authority")
    path.chmod(0o600)
    resources = runner._PinnedPreparationResources()
    resources.pin_file(
        path,
        expected_sha256=digest,
        expected_mode=0o600,
        expected_uid=os.geteuid(),
    )
    moved = tmp_path / "authority-root-old"
    parent.rename(moved)
    parent.mkdir(mode=0o700)
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="directory changed"):
        resources.verify()
    resources.close()


def test_pinned_output_directory_detects_reference_replacement(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    output = state / "preparations"
    resources = runner._PinnedPreparationResources()
    resources.pin_private_directory(output)
    moved = state / "preparations-old"
    output.rename(moved)
    output.mkdir(mode=0o700)
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="directory changed"):
        resources.verify()
    resources.close()


def test_preparation_output_requires_exact_private_replay(tmp_path: Path) -> None:
    preparation_id = "5" * 64
    output_root = tmp_path / "output"
    destination = output_root / "preparations" / preparation_id
    objects = destination / "objects"
    objects.mkdir(parents=True, mode=0o700)
    output_root.chmod(0o700)
    (output_root / "preparations").chmod(0o700)
    destination.chmod(0o700)
    objects.chmod(0o700)
    for path, value in (
        (objects / ("a" * 64), b"authority"),
        (destination / "cv.pdf", b"cv"),
        (destination / "cover-letter.pdf", b"letter"),
        (destination / "receipt.json", b"receipt"),
    ):
        path.write_bytes(value)
        path.chmod(0o600)
    result = MarketApplicationPreparation(
        preparation_id=preparation_id,
        path=destination,
        receipt_sha256=hashlib.sha256(b"receipt").hexdigest(),
        orchestration_sha256="7" * 64,
    )
    runner._verify_preparation_output(result, output_root)

    hardlink = tmp_path / "cv-hardlink"
    os.link(destination / "cv.pdf", hardlink)
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="output file"):
        runner._verify_preparation_output(result, output_root)
    hardlink.unlink()

    (destination / "receipt.json").write_bytes(b"substituted")
    with pytest.raises(runner.ProductionPreparationDeploymentError, match="receipt differs"):
        runner._verify_preparation_output(result, output_root)


@pytest.mark.parametrize(
    ("resource_name", "stage"),
    (
        ("database", "database"),
        ("candidate", "resources"),
        ("contact", "resources"),
        ("public_key", "resources"),
        ("registry", "resources"),
        ("codex", "resources"),
        ("poppler", "resources"),
        ("output", "resources"),
        ("recruiter", "resources"),
    ),
)
def test_after_preflight_resource_replacement_fails_before_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    resource_name: str,
    stage: str,
) -> None:
    deployment, paths = _real_preflight_deployment(monkeypatch, tmp_path)
    calls = {"editorial": 0, "recruiter": 0, "preparation": 0}
    monkeypatch.setattr(
        runner,
        "DetachedCodexEditorialAdapter",
        lambda **kwargs: calls.__setitem__("editorial", calls["editorial"] + 1),
    )
    monkeypatch.setattr(
        runner,
        "ProductionDetachedRecruiterAssessor",
        lambda **kwargs: calls.__setitem__("recruiter", calls["recruiter"] + 1),
    )
    monkeypatch.setattr(
        runner,
        "prepare_admitted_market_application_from_authorities",
        lambda **kwargs: calls.__setitem__("preparation", calls["preparation"] + 1),
    )

    def replace_resource(current_stage: str) -> None:
        if current_stage != stage:
            return
        path = paths[resource_name]
        if path.is_dir():
            displaced = path.with_name(path.name + "-pinned")
            path.rename(displaced)
            path.mkdir(mode=0o700)
            return
        mode = path.stat().st_mode & 0o777
        content = path.read_bytes()
        path.unlink()
        path.write_bytes(content)
        path.chmod(mode)

    with pytest.raises(
        runner.ProductionPreparationDeploymentError,
        match="changed during operation|descriptor differs",
    ):
        runner._run_production_preparation(
            "app_" + "1" * 64,
            deployment,
            after_preflight_hook=replace_resource,
        )
    assert calls == {"editorial": 0, "recruiter": 0, "preparation": 0}


def test_after_preflight_authority_ancestor_replacement_fails_before_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    deployment, paths = _real_preflight_deployment(monkeypatch, tmp_path)
    calls = {"editorial": 0, "recruiter": 0}
    monkeypatch.setattr(
        runner,
        "DetachedCodexEditorialAdapter",
        lambda **kwargs: calls.__setitem__("editorial", calls["editorial"] + 1),
    )
    monkeypatch.setattr(
        runner,
        "ProductionDetachedRecruiterAssessor",
        lambda **kwargs: calls.__setitem__("recruiter", calls["recruiter"] + 1),
    )

    def replace_ancestor(stage: str) -> None:
        if stage != "resources":
            return
        parent = paths["candidate"].parent
        content = paths["candidate"].read_bytes()
        displaced = parent.with_name(parent.name + "-pinned")
        parent.rename(displaced)
        parent.mkdir(mode=0o700)
        replacement = parent / paths["candidate"].name
        replacement.write_bytes(content)
        replacement.chmod(0o600)

    with pytest.raises(
        runner.ProductionPreparationDeploymentError,
        match="directory changed during operation",
    ):
        runner._run_production_preparation(
            "app_" + "1" * 64,
            deployment,
            after_preflight_hook=replace_ancestor,
        )
    assert calls == {"editorial": 0, "recruiter": 0}


def test_cli_help_bootstraps_from_unrelated_locked_working_directory(
    tmp_path: Path,
) -> None:
    script = (
        Path(__file__).resolve().parent
        / "scripts"
        / "run_production_application_preparation.py"
    )
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--application-id" in completed.stdout


@pytest.mark.parametrize("substitution", ["symlink", "different-directory"])
def test_directory_descriptor_rejects_path_substitution(tmp_path: Path, substitution: str) -> None:
    original = tmp_path / "original"
    original.mkdir()
    target = tmp_path / "target"
    if substitution == "symlink":
        target.symlink_to(original, target_is_directory=True)
    else:
        target.mkdir()
    descriptor = os.open(original, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError):
            runner._require_descriptor_path_identity(descriptor, str(target))
    finally:
        os.close(descriptor)
