from __future__ import annotations

import hashlib
import importlib.util
import inspect
import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from career_automation import production_handoff_admission_runner as admission_runner
from career_automation import production_handoff_runner
from career_automation.current_time import AuthenticatedCurrentTimeWitness
from career_automation.market_aligner_handoff import canonical_json_bytes

from market_aligner.service import api as service_api

COMMIT = "a" * 40
SHA = "b" * 64


def _deployment(tmp_path: Path) -> admission_runner._ProductionAdmissionDeployment:
    data = tmp_path / "data"
    outbox = tmp_path / "outbox"
    receipts = outbox / "receipts"
    repo = tmp_path / "repo"
    data.mkdir(mode=0o700)
    receipts.mkdir(parents=True, mode=0o700)
    os.chmod(outbox, 0o700)
    repo.mkdir(mode=0o755)
    return admission_runner._ProductionAdmissionDeployment(
        data_home=data,
        repository_root=repo,
        outbox_root=outbox,
        execution_receipt_root=receipts,
        admission_root=data / "state" / "jaa-production-admissions",
    )


def _execution(deployment, **changes) -> Path:
    basis = {
        "application_id": "app_" + "1" * 64,
        "bundle_identity": f"bundles/{SHA}",
        "canonical_vacancy_metadata_sha256": SHA,
        "canonical_vacancy_object_sha256": SHA,
        "employer_dossier_sha256": SHA,
        "environment": "production",
        "handoff_job_key": "job_" + "2" * 64,
        "handoff_root_sha256": SHA,
        "manifest_sha256": SHA,
        "processing_promotion_sha256": SHA,
        "producer_commit_sha": COMMIT,
        "release_token_issued": False,
        "research_archive_root_identity": "state/public-employer-research-v2",
        "research_receipt_file_sha256": SHA,
        "research_semantic_receipt_sha256": SHA,
        "research_vacancy_snapshot_sha256": SHA,
        "schema_version": admission_runner.EXECUTION_SCHEMA,
        "source_content_sha256": SHA,
        "source_job_key": "workable:cogna:847CFBC5F4",
        "source_record_sha256": SHA,
        "submission_authority": False,
        "trust_root_id": admission_runner.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
    }
    basis.update(changes)
    semantic = hashlib.sha256(canonical_json_bytes(basis)).hexdigest()
    document = {**basis, "semantic_receipt_sha256": semantic}
    path = deployment.execution_receipt_root / f"{semantic}.json"
    path.write_bytes(canonical_json_bytes(document))
    os.chmod(path, 0o600)
    return path


def _witness():
    witness = object.__new__(AuthenticatedCurrentTimeWitness)
    witness.environment = "production"
    return witness


class _Outbox:
    calls = 0

    def __init__(self, path, **kwargs):
        type(self).calls += 1
        assert path.name == SHA
        assert kwargs["expected_source_record_sha256"] == SHA
        assert kwargs["allowed_producer_commits"] == frozenset({COMMIT})
        self.handoff_bytes = b"handoff"
        self.context_bytes = b"context"
        self._manifest_bytes = b"manifest"
        self._manifest = {"handoff_root_sha256": SHA}
        self._source_record = {
            "source_job_key": "workable:cogna:847CFBC5F4",
            "trust_root_id": admission_runner.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
        }


class _Store:
    created = True

    def __init__(self, database, **kwargs):
        self.database = Path(database)
        self.database.touch(mode=0o600)
        assert kwargs["context_authenticator"] is kwargs["resolver"]
        assert (
            type(kwargs["current_time_witness"]).__name__
            == "AuthenticatedCurrentTimeWitness"
        )

    def admit_authenticated(self, handoff, context):
        assert (handoff, context) == (b"handoff", b"context")
        return SimpleNamespace(
            application_id="app_" + "1" * 64,
            job_key="job_" + "2" * 64,
            handoff_root_sha256=SHA,
            environment="production",
            authority_scope="production",
            verification_receipt_sha256="d" * 64,
            created=type(self).created,
        )


def test_admission_created_then_replay_are_explicit_and_non_release(
    monkeypatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    path = _execution(
        deployment, manifest_sha256=hashlib.sha256(b"manifest").hexdigest()
    )
    monkeypatch.setattr(admission_runner, "ProtectedLocalOutbox", _Outbox)
    monkeypatch.setattr(admission_runner, "HandoffAdmissionStore", _Store)
    _Store.created = True
    created = admission_runner._run_production_handoff_admission(
        execution_receipt_path=path,
        deployment=deployment,
        witness=_witness(),
        commit_resolver=lambda _: COMMIT,
    )
    _Store.created = False
    replay = admission_runner._run_production_handoff_admission(
        execution_receipt_path=path,
        deployment=deployment,
        witness=_witness(),
        commit_resolver=lambda _: COMMIT,
    )
    assert created.operation == "created"
    assert replay.operation == "replay"
    assert created.operation_receipt_path != replay.operation_receipt_path
    for result in (created, replay):
        document = result.document()
        assert document["release_token_issued"] is False
        assert document["submission_authority"] is False
        assert result.operation_receipt_path.stat().st_mode & 0o777 == 0o600
    assert deployment.admission_root.stat().st_mode & 0o777 == 0o700
    assert (
        deployment.admission_root / "admissions.sqlite3"
    ).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"environment": "synthetic"}, "authority"),
        ({"release_token_issued": True}, "authority"),
        ({"submission_authority": True}, "authority"),
        ({"trust_root_id": "other"}, "authority"),
        ({"bundle_identity": "bundles/" + "e" * 64}, "bundle identity"),
        ({"producer_commit_sha": "f" * 40}, "current clean HEAD"),
    ],
)
def test_receipt_authority_and_commit_substitutions_fail_before_outbox(
    monkeypatch, tmp_path: Path, change, message
) -> None:
    deployment = _deployment(tmp_path)
    path = _execution(deployment, **change)
    _Outbox.calls = 0
    monkeypatch.setattr(admission_runner, "ProtectedLocalOutbox", _Outbox)
    with pytest.raises(admission_runner.ProductionHandoffAdmissionError, match=message):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=deployment,
            witness=_witness(),
            commit_resolver=lambda _: COMMIT,
        )
    assert _Outbox.calls == 0


def test_receipt_path_mode_filename_and_canonical_substitutions_fail(
    tmp_path: Path,
) -> None:
    deployment = _deployment(tmp_path)
    path = _execution(deployment)
    outside = tmp_path / path.name
    outside.write_bytes(path.read_bytes())
    os.chmod(outside, 0o600)
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError, match="escapes"
    ):
        admission_runner._read_execution_receipt(
            outside, deployment.execution_receipt_root
        )
    os.chmod(path, 0o644)
    with pytest.raises(admission_runner.ProductionHandoffAdmissionError, match="mode"):
        admission_runner._read_execution_receipt(
            path, deployment.execution_receipt_root
        )
    os.chmod(path, 0o600)
    renamed = path.with_name("e" * 64 + ".json")
    path.rename(renamed)
    document, _ = admission_runner._read_execution_receipt(
        renamed, deployment.execution_receipt_root
    )
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError, match="filename"
    ):
        admission_runner._validate_execution_receipt(document, renamed)
    renamed.write_bytes(renamed.read_bytes() + b"\n")
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError, match="canonical"
    ):
        admission_runner._read_execution_receipt(
            renamed, deployment.execution_receipt_root
        )


def test_root_time_and_symlink_substitution_fail_before_outbox(
    monkeypatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    path = _execution(deployment)
    _Outbox.calls = 0
    monkeypatch.setattr(admission_runner, "ProtectedLocalOutbox", _Outbox)
    bad = admission_runner._ProductionAdmissionDeployment(
        **{**deployment.__dict__, "admission_root": tmp_path / "alternate"}
    )
    with pytest.raises(admission_runner.ProductionHandoffAdmissionError, match="roots"):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=bad,
            witness=_witness(),
            commit_resolver=lambda _: COMMIT,
        )
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError, match="witness"
    ):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=deployment,
            witness=object(),
            commit_resolver=lambda _: COMMIT,
        )
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "linked"
    link.symlink_to(real, target_is_directory=True)
    linked = admission_runner._ProductionAdmissionDeployment(
        data_home=link,
        repository_root=deployment.repository_root,
        outbox_root=deployment.outbox_root,
        execution_receipt_root=deployment.execution_receipt_root,
        admission_root=link / "state/jaa-production-admissions",
    )
    with pytest.raises(admission_runner.ProductionHandoffAdmissionError, match="link"):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=linked,
            witness=_witness(),
            commit_resolver=lambda _: COMMIT,
        )
    assert _Outbox.calls == 0


def test_authenticated_bundle_identity_substitution_fails_before_database(
    monkeypatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    path = _execution(deployment)
    monkeypatch.setattr(admission_runner, "ProtectedLocalOutbox", _Outbox)
    monkeypatch.setattr(
        admission_runner,
        "HandoffAdmissionStore",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("database must not open")
        ),
    )
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError, match="bundle differ"
    ):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=deployment,
            witness=_witness(),
            commit_resolver=lambda _: COMMIT,
        )


@pytest.mark.parametrize("unsafe", ["symlink", "mode"])
def test_admission_database_must_be_private_exact_regular_file(
    tmp_path: Path, unsafe: str
) -> None:
    root = tmp_path / "admission"
    root.mkdir(mode=0o700)
    database = root / "admissions.sqlite3"
    if unsafe == "symlink":
        target = tmp_path / "target.sqlite3"
        target.write_bytes(b"")
        database.symlink_to(target)
    else:
        database.write_bytes(b"")
        database.chmod(0o644)
    descriptor = admission_runner._open_private_directory(root)
    try:
        with pytest.raises(
            admission_runner.ProductionHandoffAdmissionError,
            match="database",
        ):
            admission_runner._prepare_database(descriptor)
    finally:
        os.close(descriptor)


def test_derived_bundle_symlink_is_rejected_before_adapter(
    monkeypatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    path = _execution(deployment)
    bundles = deployment.outbox_root / "bundles"
    bundles.mkdir(mode=0o700)
    real = tmp_path / "real-bundle"
    real.mkdir(mode=0o700)
    (bundles / SHA).symlink_to(real, target_is_directory=True)
    _Outbox.calls = 0
    monkeypatch.setattr(admission_runner, "ProtectedLocalOutbox", _Outbox)
    with pytest.raises(admission_runner.ProductionHandoffAdmissionError, match="link"):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=deployment,
            witness=_witness(),
            commit_resolver=lambda _: COMMIT,
        )
    assert _Outbox.calls == 0


def test_public_signatures_expose_no_roots_time_commit_database_or_release() -> None:
    handoff = inspect.signature(
        production_handoff_runner.run_production_handoff
    ).parameters
    assert set(handoff) == {"profile_id", "track", "source_job_key"}
    admission = inspect.signature(
        admission_runner.run_production_handoff_admission
    ).parameters
    assert set(admission) == {"execution_receipt_path"}
    forbidden = {
        "data_home",
        "outbox_root",
        "repository_root",
        "database",
        "bundle_path",
        "current_time",
        "producer_commit",
        "release",
        "submission",
    }
    assert forbidden.isdisjoint(handoff)
    assert forbidden.isdisjoint(admission)


@pytest.mark.parametrize(
    ("script_name", "call_name", "argv", "expected"),
    [
        (
            "run_production_market_handoff.py",
            "run_production_handoff",
            [
                "--profile-id",
                "prf_1",
                "--track",
                "software",
                "--source-job-key",
                "workable:x:1",
            ],
            {
                "profile_id": "prf_1",
                "track": "software",
                "source_job_key": "workable:x:1",
            },
        ),
        (
            "run_production_handoff_admission.py",
            "run_production_handoff_admission",
            ["--execution-receipt", "/fixed/receipt.json"],
            {"execution_receipt_path": "/fixed/receipt.json"},
        ),
    ],
)
def test_scripts_emit_one_canonical_json_document_and_only_forward_operator_inputs(
    monkeypatch, script_name, call_name, argv, expected
) -> None:
    script = Path(__file__).parent / "scripts" / script_name
    spec = importlib.util.spec_from_file_location("_production_surface", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    observed = {}

    class _Receipt:
        def document(self):
            return {"z": False, "a": "receipt"}

    def run(**kwargs):
        observed.update(kwargs)
        return _Receipt()

    sink = SimpleNamespace(buffer=io.BytesIO())
    monkeypatch.setattr(module, call_name, run)
    monkeypatch.setattr(module.sys, "stdout", sink)
    assert module.main(argv) == 0
    assert observed == expected
    assert sink.buffer.getvalue() == b'{"a":"receipt","z":false}\n'


def test_service_handoff_forwards_distinct_source_and_handoff_job_keys(
    monkeypatch, tmp_path: Path
) -> None:
    service = service_api.MarketAlignerService(tmp_path)
    service.profiles.load = lambda _: (
        SimpleNamespace(profile_id="prf_source", version="version_1"),
        None,
    )
    observed = {}
    expected = object()

    def produce(store, **kwargs):
        observed.update(kwargs)
        assert store is service.assessments
        return expected

    monkeypatch.setattr(service_api, "produce_handoff", produce)
    assert (
        service.handoff(
            "prf_source",
            "workable:cogna:847CFBC5F4",
            {"manifest": "exact"},
            handoff_job_key="job_" + "9" * 64,
        )
        is expected
    )
    assert observed == {
        "profile_id": "prf_source",
        "profile_version": "version_1",
        "job_key": "workable:cogna:847CFBC5F4",
        "manifest": {"manifest": "exact"},
        "handoff_job_key": "job_" + "9" * 64,
    }
