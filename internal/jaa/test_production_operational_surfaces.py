from __future__ import annotations

import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from career_automation import production_preparation_runner as preparation_runner
from career_automation import production_handoff_admission_runner as admission_runner
from career_automation import production_handoff_runner
from career_automation.candidate_contact_authority import CandidateContactResourceLease
from career_automation.current_time import AuthenticatedCurrentTimeWitness
from career_automation.handoff_admission import (
    HandoffAdmissionError,
    _context_document,
)
from career_automation.market_aligner_handoff import canonical_json_bytes

from market_aligner.service import api as service_api

COMMIT = "a" * 40
SHA = "b" * 64
SOURCE_JOB_KEY = "workable:cogna:847CFBC5F4"
_PROMOTION_BINDING = {
    "evidence_authority_sha256": "1" * 64,
    "processing_config_sha256": "2" * 64,
    "processing_receipt_sha256": "3" * 64,
    "processing_result_sha256": "4" * 64,
    "source_content_sha256": "5" * 64,
    "track": "AI_Automation_Engineer",
}
_PROMOTION_POLICY = {
    "processing_config_sha256": "2" * 64,
    "schema_version": "market-aligner.selection-policy.v1",
}
_PROMOTION_BODY = {
    "binding": _PROMOTION_BINDING,
    "binding_sha256": hashlib.sha256(
        canonical_json_bytes(_PROMOTION_BINDING)
    ).hexdigest(),
    "decision": "pass",
    "job_key": SOURCE_JOB_KEY,
    "policy": _PROMOTION_POLICY,
    "policy_sha256": hashlib.sha256(
        canonical_json_bytes(_PROMOTION_POLICY)
    ).hexdigest(),
    "profile_id": "prf_" + "6" * 32,
    "schema_version": "market-aligner.assessment-promotion-receipt.v1",
    "score_payload_hash": "7" * 64,
}
PROMOTION_SEMANTIC_SHA = hashlib.sha256(
    canonical_json_bytes(_PROMOTION_BODY)
).hexdigest()
PROMOTION_BYTES = canonical_json_bytes(
    {**_PROMOTION_BODY, "receipt_sha256": PROMOTION_SEMANTIC_SHA}
)
PROMOTION_OBJECT_SHA = hashlib.sha256(PROMOTION_BYTES).hexdigest()


def _deployment(tmp_path: Path) -> admission_runner._ProductionAdmissionDeployment:
    data = tmp_path / "data"
    outbox = tmp_path / "outbox"
    receipts = outbox / "receipts"
    repo = tmp_path / "repo"
    data.mkdir(mode=0o700)
    receipts.mkdir(parents=True, mode=0o700)
    os.chmod(outbox, 0o700)
    (outbox / "bundles" / SHA).mkdir(parents=True, mode=0o700)
    os.chmod(outbox / "bundles", 0o700)
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
        "employer_dossier_sha256": SHA,
        "environment": "production",
        "handoff_job_key": "job_" + "2" * 64,
        "handoff_root_sha256": SHA,
        "manifest_sha256": SHA,
        "processing_promotion_sha256": PROMOTION_SEMANTIC_SHA,
        "producer_commit_sha": COMMIT,
        "release_token_issued": False,
        "schema_version": admission_runner.EXECUTION_SCHEMA,
        "source_job_key": SOURCE_JOB_KEY,
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


def test_current_runtime_context_requires_exact_nonrelease_bindings() -> None:
    class Authenticator:
        authenticator_identity_sha256 = SHA

        def authenticate(self, **_kwargs) -> None:
            return None

    document = {
        "environment": "current_runtime",
        "handoff_root_sha256": SHA,
        "issued_at": "2026-10-06T00:00:00Z",
        "producer_commit_sha": COMMIT,
        "producer_product": "market-aligner",
        "source_record_sha256": SHA,
        "trust_mode": "current_runtime_non_release",
        "trust_proof_sha256": SHA,
        "trust_root_id": "market-aligner-current-runtime-non-release-v1",
    }
    handoff = SimpleNamespace(
        emission_profile="current_runtime_non_release_v1",
        strict_profile=False,
        root_sha256=SHA,
        original_bytes=b"current-runtime-handoff",
        payload={"producer": {"commit_sha": COMMIT, "product": "market-aligner"}},
    )
    raw = canonical_json_bytes(document)
    validated, context_sha256, auth_sha256 = _context_document(
        raw,
        handoff,
        Authenticator(),
        "2026-10-06T00:00:01Z",
    )
    assert validated == document
    assert context_sha256 == hashlib.sha256(raw).hexdigest()
    assert auth_sha256 == SHA

    for field, value in (
        ("trust_mode", "protected_local_outbox"),
        ("trust_root_id", "different-current-runtime-root"),
    ):
        changed = dict(document)
        changed[field] = value
        with pytest.raises(HandoffAdmissionError) as caught:
            _context_document(
                canonical_json_bytes(changed),
                handoff,
                Authenticator(),
                "2026-10-06T00:00:01Z",
            )
        assert caught.value.code == "context_environment"

    strict_handoff = SimpleNamespace(**{**vars(handoff), "strict_profile": True})
    with pytest.raises(HandoffAdmissionError) as caught:
        _context_document(raw, strict_handoff, Authenticator(), "2026-10-06T00:00:01Z")
    assert caught.value.code == "context_environment"


def test_preparation_scope_separates_current_runtime_from_legacy_contact_authority(
    tmp_path: Path,
) -> None:
    current_deployment = SimpleNamespace(current_runtime=True)
    assert preparation_runner._preparation_environment_and_contact_bytes(
        current_deployment, None
    ) == ("current_runtime", None)

    lease = CandidateContactResourceLease(
        authority_path=tmp_path / "contact.json",
        authority_bytes=b"legacy-contact-authority",
        public_key_path=tmp_path / "public-key.pem",
        public_key_bytes=b"legacy-public-key",
        registry_path=tmp_path / "registry.json",
        registry_bytes=b"legacy-registry",
    )
    legacy_deployment = SimpleNamespace(current_runtime=False)
    assert preparation_runner._preparation_environment_and_contact_bytes(
        legacy_deployment, lease
    ) == ("production", b"legacy-contact-authority")

    with pytest.raises(
        preparation_runner.ProductionPreparationDeploymentError,
        match="current preparation rejects legacy contact authority",
    ):
        preparation_runner._preparation_environment_and_contact_bytes(
            current_deployment, lease
        )
    with pytest.raises(
        preparation_runner.ProductionPreparationDeploymentError,
        match="legacy preparation requires pinned contact authority",
    ):
        preparation_runner._preparation_environment_and_contact_bytes(
            legacy_deployment, None
        )


def _witness():
    witness = object.__new__(AuthenticatedCurrentTimeWitness)
    witness.environment = "production"
    return witness


class _Outbox:
    calls = 0

    def __init__(self, path, **kwargs):
        type(self).calls += 1
        assert kwargs["allowed_producer_commits"] == frozenset({COMMIT})
        self.handoff_bytes = b"handoff"
        self.context_bytes = canonical_json_bytes(
            {
                "environment": "production",
                "handoff_root_sha256": SHA,
                "producer_commit_sha": COMMIT,
                "source_record_sha256": SHA,
                "trust_root_id": admission_runner.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
            }
        )
        self._manifest_bytes = b"manifest"
        self._manifest = {"handoff_root_sha256": SHA}
        self._source_record = {
            "source_job_key": SOURCE_JOB_KEY,
            "trust_root_id": admission_runner.PRODUCTION_HANDOFF_TRUST_ROOT_ID,
        }
        self._entries = {
            "employer_dossier": {"object_sha256": SHA},
            "assessment.receipt": {"object_sha256": PROMOTION_OBJECT_SHA},
        }

    def _read(self, relative):
        if relative == f"objects/{PROMOTION_OBJECT_SHA}":
            return PROMOTION_BYTES
        raise AssertionError(f"unexpected fake outbox read: {relative}")

    def close(self):
        return None


@pytest.fixture(autouse=True)
def _parsed_handoff(monkeypatch):
    monkeypatch.setattr(
        admission_runner,
        "parse_handoff",
        lambda _: SimpleNamespace(
            root_sha256=SHA,
            application_id="app_" + "1" * 64,
            payload={
                "assessment": {
                    "assessment_receipt_sha256": PROMOTION_OBJECT_SHA,
                },
                "job_key": "job_" + "2" * 64,
            },
        ),
    )


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
        assert handoff == b"handoff"
        assert json.loads(context)["environment"] == "production"
        return SimpleNamespace(
            application_id="app_" + "1" * 64,
            job_key="job_" + "2" * 64,
            handoff_root_sha256=SHA,
            environment="production",
            authority_scope="production",
            admission_kind="market_aligner_handoff_v1",
            verification_receipt_sha256="d" * 64,
            created=type(self).created,
        )


def test_real_shape_promotion_binds_distinct_semantic_and_exact_object_domains() -> (
    None
):
    assert PROMOTION_SEMANTIC_SHA != PROMOTION_OBJECT_SHA
    outbox = _Outbox(
        Path("/unused"),
        allowed_producer_commits=frozenset({COMMIT}),
    )
    handoff = SimpleNamespace(
        payload={
            "assessment": {
                "assessment_receipt_sha256": PROMOTION_OBJECT_SHA,
            }
        }
    )
    assert (
        admission_runner._promotion_receipt_semantic_identity(
            outbox,
            handoff,
            outbox._entries["assessment.receipt"],
            source_job_key=SOURCE_JOB_KEY,
        )
        == PROMOTION_SEMANTIC_SHA
    )


@pytest.mark.parametrize("mutation", ["handoff_object", "source_job", "semantic"])
def test_promotion_domain_substitutions_fail_closed(mutation: str) -> None:
    promotion = json.loads(PROMOTION_BYTES)
    handoff_object = PROMOTION_OBJECT_SHA
    source_job_key = SOURCE_JOB_KEY
    if mutation == "handoff_object":
        handoff_object = "9" * 64
    elif mutation == "source_job":
        source_job_key = "workable:other:1"
    else:
        promotion["receipt_sha256"] = "9" * 64
    exact = canonical_json_bytes(promotion)
    exact_sha256 = hashlib.sha256(exact).hexdigest()
    if mutation == "semantic":
        handoff_object = exact_sha256
    adapter = SimpleNamespace(_read=lambda _: exact)
    handoff = SimpleNamespace(
        payload={"assessment": {"assessment_receipt_sha256": handoff_object}}
    )
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="promotion",
    ):
        admission_runner._promotion_receipt_semantic_identity(
            adapter,
            handoff,
            {"object_sha256": exact_sha256},
            source_job_key=source_job_key,
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
        commit_resolver=lambda _, __: COMMIT,
    )
    _Store.created = False
    replay = admission_runner._run_production_handoff_admission(
        execution_receipt_path=path,
        deployment=deployment,
        witness=_witness(),
        commit_resolver=lambda _, __: COMMIT,
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
        ({"application_id": "app_" + "9" * 64}, "bundle differ"),
        ({"employer_dossier_sha256": "9" * 64}, "bundle differ"),
        ({"handoff_job_key": "job_" + "9" * 64}, "bundle differ"),
        ({"handoff_root_sha256": "9" * 64}, "bundle differ"),
        ({"manifest_sha256": "9" * 64}, "bundle differ"),
        ({"processing_promotion_sha256": "9" * 64}, "bundle differ"),
        ({"source_job_key": "workable:other:1"}, "promotion object"),
        (
            {"schema_version": "market-aligner.production-handoff-execution.v1"},
            "authority",
        ),
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
            commit_resolver=lambda _, __: COMMIT,
        )
    assert _Outbox.calls == (
        1 if message in {"bundle differ", "promotion object"} else 0
    )


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
            commit_resolver=lambda _, __: COMMIT,
        )
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError, match="witness"
    ):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=deployment,
            witness=object(),
            commit_resolver=lambda _, __: COMMIT,
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
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="unavailable|link",
    ):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=linked,
            witness=_witness(),
            commit_resolver=lambda _, __: COMMIT,
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
            commit_resolver=lambda _, __: COMMIT,
        )


def test_self_rehashed_source_record_and_bundle_substitution_fails_before_database(
    monkeypatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    substituted = "e" * 64
    (deployment.outbox_root / "bundles" / substituted).mkdir(mode=0o700)
    path = _execution(
        deployment,
        source_record_sha256=substituted,
        bundle_identity=f"bundles/{substituted}",
    )
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
            commit_resolver=lambda _, __: COMMIT,
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


def test_operation_receipt_partial_write_cleans_up_and_retry_publishes_atomically(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "receipts"
    root.mkdir(mode=0o700)
    descriptor = admission_runner._open_private_directory(root)
    value = b"x" * 2048
    real_write = admission_runner.os.write
    calls = 0

    def interrupted(file_descriptor, remaining):
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(file_descriptor, remaining[:512])
        raise OSError("injected write failure")

    monkeypatch.setattr(admission_runner.os, "write", interrupted)
    try:
        with pytest.raises(OSError, match="injected"):
            admission_runner._create_or_exact(descriptor, "receipt.json", value)
        assert not (root / "receipt.json").exists()
        assert list(root.iterdir()) == []
        monkeypatch.setattr(admission_runner.os, "write", real_write)
        admission_runner._create_or_exact(descriptor, "receipt.json", value)
        assert (root / "receipt.json").read_bytes() == value
        admission_runner._create_or_exact(descriptor, "receipt.json", value)
    finally:
        os.close(descriptor)


def test_derived_bundle_symlink_is_rejected_before_adapter(
    monkeypatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    path = _execution(deployment)
    bundles = deployment.outbox_root / "bundles"
    (bundles / SHA).rmdir()
    real = tmp_path / "real-bundle"
    real.mkdir(mode=0o700)
    (bundles / SHA).symlink_to(real, target_is_directory=True)
    _Outbox.calls = 0
    monkeypatch.setattr(admission_runner, "ProtectedLocalOutbox", _Outbox)
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="unavailable|link",
    ):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=deployment,
            witness=_witness(),
            commit_resolver=lambda _, __: COMMIT,
        )
    assert _Outbox.calls == 0


def test_mid_operation_compiled_ancestor_replacement_is_rejected(
    monkeypatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    path = _execution(deployment)
    _Outbox.calls = 0
    monkeypatch.setattr(admission_runner, "ProtectedLocalOutbox", _Outbox)

    def replace_outbox(_repository, _descriptor):
        moved = tmp_path / "moved-outbox"
        deployment.outbox_root.rename(moved)
        deployment.outbox_root.mkdir(mode=0o700)
        return COMMIT

    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="reference changed",
    ):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=deployment,
            witness=_witness(),
            commit_resolver=replace_outbox,
        )
    assert _Outbox.calls == 0


def test_mid_operation_intermediate_parent_replacement_is_rejected(
    monkeypatch, tmp_path: Path
) -> None:
    deployment = _deployment(tmp_path)
    path = _execution(deployment)
    _Outbox.calls = 0
    monkeypatch.setattr(admission_runner, "ProtectedLocalOutbox", _Outbox)

    def replace_parent(_repository, _descriptor):
        moved = tmp_path.with_name(f"{tmp_path.name}-moved")
        tmp_path.rename(moved)
        tmp_path.mkdir(mode=0o700)
        return COMMIT

    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="reference changed",
    ):
        admission_runner._run_production_handoff_admission(
            execution_receipt_path=path,
            deployment=deployment,
            witness=_witness(),
            commit_resolver=replace_parent,
        )
    assert _Outbox.calls == 0


def test_public_signatures_expose_no_roots_time_commit_database_or_release() -> None:
    handoff = inspect.signature(
        production_handoff_runner.run_production_handoff
    ).parameters
    assert set(handoff) == {
        "profile_id",
        "track",
        "source_job_key",
        "current_runtime_config_path",
        "current_runtime_config_sha256",
        "current_runtime_private_root",
        "current_recovery_manifest_relative_path",
    }
    admission = inspect.signature(
        admission_runner.run_production_handoff_admission
    ).parameters
    assert set(admission) == {
        "execution_receipt_path",
        "current_runtime_config_path",
        "current_runtime_config_sha256",
        "current_runtime_private_root",
    }
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
        "current_runtime": False,
    }


@pytest.mark.parametrize("filter_field", [None, "profile_id", "profile_version", "candidate_intent_sha256",
                                        "non_strict", "selection_blocked", "eligibility_blocked"])
def test_published_selection_reads_verified_bundle_without_admission(
    monkeypatch, tmp_path, filter_field,
):
    deployment = _deployment(tmp_path)
    _execution(deployment, manifest_sha256=hashlib.sha256(b"manifest").hexdigest())
    profile_id = "prf_" + "6" * 32
    payload = {
        "assessment": {"assessment_receipt_sha256": PROMOTION_OBJECT_SHA,
                       "final": 0.75, "opportunity": 0.8},
        "job_key": "job_" + "2" * 64,
        "profile_id": profile_id,
        "profile_version": "version-1",
        "candidate_intent_sha256": "8" * 64,
        "selection": {"decision": "selected_for_application", "hard_gate_passed": True,
                      "geography_bucket": "UK_remote", "geography_priority_rank": 1},
        "eligibility": {"hard_gate_passed": True},
        "vacancy": {"vacancy_snapshot_sha256": "9" * 64},
        "created_at": "2026-09-13T00:00:00Z",
    }
    monkeypatch.setattr(admission_runner, "ProtectedLocalOutbox", _Outbox)
    monkeypatch.setattr(admission_runner, "parse_handoff", lambda _: SimpleNamespace(
        root_sha256=SHA, application_id="app_" + "1" * 64,
        payload=payload, strict_profile=filter_field != "non_strict",
    ))
    if filter_field == "selection_blocked":
        payload["selection"]["hard_gate_passed"] = False
    if filter_field == "eligibility_blocked":
        payload["eligibility"]["hard_gate_passed"] = False
    def forbid(*args, **kwargs):
        raise AssertionError("read-only selection attempted an admission write")
    monkeypatch.setattr(admission_runner, "HandoffAdmissionStore", forbid)
    monkeypatch.setattr(admission_runner, "_prepare_database", forbid)
    filters = dict(profile_id=profile_id, profile_version="version-1",
                   candidate_intent_sha256="8" * 64)
    if filter_field in {"non_strict", "selection_blocked", "eligibility_blocked"}:
        with pytest.raises(admission_runner.ProductionHandoffAdmissionError, match="not strict|blocked"):
            admission_runner._selected_published_handoffs(
                **filters, deployment=deployment, commit_resolver=lambda *_: COMMIT,
            )
        assert not deployment.admission_root.exists()
        return
    if filter_field:
        filters[filter_field] = {"profile_id": "prf_" + "7" * 32,
                                "profile_version": "version-2",
                                "candidate_intent_sha256": "a" * 64}[filter_field]
    rows = admission_runner._selected_published_handoffs(
        **filters, deployment=deployment, commit_resolver=lambda *_: COMMIT,
    )
    assert not deployment.admission_root.exists()
    if filter_field:
        assert rows == []
    else:
        assert len(rows) == 1
        assert rows[0]["final_score"] == 75.0
        assert rows[0]["handoff_root_sha256"] == SHA
        assert rows[0]["release_authority"] is False
        assert rows[0]["submission_authority"] is False


def test_published_selection_ignores_unpublished_temporary_receipt(monkeypatch, tmp_path):
    deployment = _deployment(tmp_path)
    (deployment.execution_receipt_root / ".interrupted.tmp").write_bytes(b"incomplete")
    def forbid(*args, **kwargs):
        raise AssertionError("temporary publication became query input")
    monkeypatch.setattr(admission_runner, "_read_published_handoff_pinned", forbid)
    assert admission_runner._selected_published_handoffs(
        profile_id="prf_" + "6" * 32, profile_version="version-1",
        candidate_intent_sha256="8" * 64, deployment=deployment,
        commit_resolver=lambda *_: COMMIT,
    ) == []
    assert not deployment.admission_root.exists()


def test_current_selection_requires_a_stored_root_before_full_validation():
    application_id = "app_" + "1" * 64
    root_sha256 = "2" * 64
    producer_commit = "3" * 40
    row = {
        "handoff_root_sha256": root_sha256,
        "producer_commit_sha": producer_commit,
    }
    document = {
        "schema_version": admission_runner.CURRENT_RUNTIME_EXECUTION_SCHEMA,
        "application_id": application_id,
        "handoff_root_sha256": root_sha256,
        "producer_commit_sha": producer_commit,
    }

    assert admission_runner._admitted_current_runtime_receipt_row(document, {}) is None
    assert admission_runner._admitted_current_runtime_receipt_row(
        document,
        {
            application_id: {
                "handoff_root_sha256": "4" * 64,
                "producer_commit_sha": producer_commit,
            }
        },
    ) is None
    assert admission_runner._admitted_current_runtime_receipt_row(
        document, {application_id: row}
    ) is row
    changed_producer = {**document, "producer_commit_sha": "5" * 40}
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="stored admission",
    ):
        admission_runner._admitted_current_runtime_receipt_row(
            changed_producer, {application_id: row}
        )


def _install_admissible_handoff_reader(
    monkeypatch,
    *,
    environment,
    producer_commit_sha,
    admitted_row,
    current_commit=COMMIT,
    reader_error=None,
    verify_error=None,
):
    events = []
    application_id = "app_" + "1" * 64
    root_sha256 = "2" * 64
    document = {
        "schema_version": admission_runner.CURRENT_RUNTIME_EXECUTION_SCHEMA,
        "application_id": application_id,
        "handoff_root_sha256": root_sha256,
        "producer_commit_sha": producer_commit_sha,
    }
    handoff = SimpleNamespace(
        payload={"profile_id": "prf_" + "3" * 32, "profile_version": "v1.10"},
        application_id=application_id,
        root_sha256=root_sha256,
    )
    adapter = SimpleNamespace(handoff_bytes=b"synthetic handoff", context_bytes=b"context")
    pinned = (document, b"receipt bytes", current_commit, "4" * 64, adapter, handoff)
    captured = {}

    class FakeConnection:
        closed = False

        def close(self):
            self.closed = True
            events.append("close")

    def read_published_handoff(
        *,
        execution_receipt_path,
        deployment,
        paths,
        commit_resolver,
        allow_admitted_current_ancestor=False,
    ):
        events.append(("read", allow_admitted_current_ancestor))
        captured["allow_admitted_current_ancestor"] = allow_admitted_current_ancestor
        if reader_error is not None:
            raise reader_error
        return pinned

    def read_admission_index(deployment, *, profile_id, profile_version):
        events.append(("index", profile_id, profile_version))
        connection = FakeConnection()
        captured["connection"] = connection
        rows = {application_id: admitted_row} if admitted_row is not None else {}
        return connection, rows

    def verify_admission_row(row, *, adapter):
        events.append("verify_stored_row")
        if verify_error is not None:
            raise verify_error

    monkeypatch.setattr(
        admission_runner,
        "_read_published_handoff_pinned",
        read_published_handoff,
    )
    monkeypatch.setattr(
        admission_runner,
        "_read_current_runtime_admission_index",
        read_admission_index,
    )
    monkeypatch.setattr(
        admission_runner,
        "_verify_current_runtime_admission_row",
        verify_admission_row,
    )
    deployment = SimpleNamespace(environment=environment)
    paths = SimpleNamespace(
        verify_references=lambda: events.append("verify_references")
    )
    return pinned, captured, deployment, paths, events


def test_admissible_reader_verifies_exact_stored_ancestor_before_return(monkeypatch):
    ancestor_commit = "b" * 40
    root_sha256 = "2" * 64
    admitted_row = {
        "handoff_root_sha256": root_sha256,
        "producer_commit_sha": ancestor_commit,
    }
    pinned, captured, deployment, paths, events = _install_admissible_handoff_reader(
        monkeypatch,
        environment=admission_runner.CURRENT_RUNTIME_ENVIRONMENT,
        producer_commit_sha=ancestor_commit,
        admitted_row=admitted_row,
    )

    result = admission_runner._read_admissible_published_handoff_pinned(
        execution_receipt_path=Path("receipt.json"),
        deployment=deployment,
        paths=paths,
        commit_resolver=lambda *_: COMMIT,
    )

    assert result is pinned
    assert result[0]["producer_commit_sha"] == ancestor_commit
    assert captured["allow_admitted_current_ancestor"] is True
    assert captured["connection"].closed is True
    assert events == [
        ("read", True),
        ("index", "prf_" + "3" * 32, "v1.10"),
        "verify_stored_row",
        "close",
        "verify_references",
    ]


def test_admissible_reader_refuses_unmatched_ancestor_and_closes_index(monkeypatch):
    pinned, captured, deployment, paths, events = _install_admissible_handoff_reader(
        monkeypatch,
        environment=admission_runner.CURRENT_RUNTIME_ENVIRONMENT,
        producer_commit_sha="b" * 40,
        admitted_row={
            "handoff_root_sha256": "5" * 64,
            "producer_commit_sha": "b" * 40,
        },
    )

    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="matching stored admission",
    ) as error:
        admission_runner._read_admissible_published_handoff_pinned(
            execution_receipt_path=Path("receipt.json"),
            deployment=deployment,
            paths=paths,
            commit_resolver=lambda *_: COMMIT,
        )

    assert "app_" not in str(error.value)
    assert captured["connection"].closed is True
    assert "verify_stored_row" not in events
    assert "verify_references" not in events


def test_admissible_reader_refuses_stored_producer_mismatch_and_closes_index(
    monkeypatch,
):
    pinned, captured, deployment, paths, events = _install_admissible_handoff_reader(
        monkeypatch,
        environment=admission_runner.CURRENT_RUNTIME_ENVIRONMENT,
        producer_commit_sha="b" * 40,
        admitted_row={
            "handoff_root_sha256": "2" * 64,
            "producer_commit_sha": "c" * 40,
        },
    )

    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="stored admission",
    ):
        admission_runner._read_admissible_published_handoff_pinned(
            execution_receipt_path=Path("receipt.json"),
            deployment=deployment,
            paths=paths,
            commit_resolver=lambda *_: COMMIT,
        )

    assert captured["connection"].closed is True
    assert "verify_stored_row" not in events
    assert "verify_references" not in events


def test_admissible_reader_closes_index_when_stored_verification_fails(monkeypatch):
    pinned, captured, deployment, paths, events = _install_admissible_handoff_reader(
        monkeypatch,
        environment=admission_runner.CURRENT_RUNTIME_ENVIRONMENT,
        producer_commit_sha="b" * 40,
        admitted_row={
            "handoff_root_sha256": "2" * 64,
            "producer_commit_sha": "b" * 40,
        },
        verify_error=admission_runner.ProductionHandoffAdmissionError(
            "stored admission mismatch"
        ),
    )

    with pytest.raises(admission_runner.ProductionHandoffAdmissionError):
        admission_runner._read_admissible_published_handoff_pinned(
            execution_receipt_path=Path("receipt.json"),
            deployment=deployment,
            paths=paths,
            commit_resolver=lambda *_: COMMIT,
        )

    assert captured["connection"].closed is True
    assert events[-1] == "close"
    assert "verify_references" not in events


def test_admissible_reader_keeps_fresh_and_legacy_modes_strict(monkeypatch):
    pinned, captured, deployment, paths, events = _install_admissible_handoff_reader(
        monkeypatch,
        environment=admission_runner.CURRENT_RUNTIME_ENVIRONMENT,
        producer_commit_sha=COMMIT,
        admitted_row=None,
    )
    result = admission_runner._read_admissible_published_handoff_pinned(
        execution_receipt_path=Path("receipt.json"),
        deployment=deployment,
        paths=paths,
        commit_resolver=lambda *_: COMMIT,
    )
    assert result is pinned
    assert events == [("read", True)]
    assert "connection" not in captured

    legacy_error = admission_runner.ProductionHandoffAdmissionError(
        "producer is not current HEAD"
    )
    _, legacy_captured, legacy_deployment, legacy_paths, legacy_events = (
        _install_admissible_handoff_reader(
            monkeypatch,
            environment="production",
            producer_commit_sha="a" * 40,
            admitted_row=None,
            reader_error=legacy_error,
        )
    )
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="producer is not current HEAD",
    ):
        admission_runner._read_admissible_published_handoff_pinned(
            execution_receipt_path=Path("receipt.json"),
            deployment=legacy_deployment,
            paths=legacy_paths,
            commit_resolver=lambda *_: COMMIT,
        )
    assert legacy_captured["allow_admitted_current_ancestor"] is False
    assert legacy_events == [("read", False)]
    assert "connection" not in legacy_captured


def test_admissible_reader_propagates_nonancestor_refusal_before_index(monkeypatch):
    reader_error = admission_runner.ProductionHandoffAdmissionError(
        "producer is not an ancestor of current HEAD"
    )
    _, captured, deployment, paths, events = _install_admissible_handoff_reader(
        monkeypatch,
        environment=admission_runner.CURRENT_RUNTIME_ENVIRONMENT,
        producer_commit_sha="a" * 40,
        admitted_row=None,
        reader_error=reader_error,
    )

    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="producer is not an ancestor",
    ):
        admission_runner._read_admissible_published_handoff_pinned(
            execution_receipt_path=Path("receipt.json"),
            deployment=deployment,
            paths=paths,
            commit_resolver=lambda *_: COMMIT,
        )

    assert captured["allow_admitted_current_ancestor"] is True
    assert events == [("read", True)]
    assert "connection" not in captured


def test_ancestor_replay_receipts_keep_authenticated_producer_commit(
    monkeypatch, tmp_path: Path
):
    ancestor_commit = "b" * 40
    document = {
        "application_id": "app_" + "1" * 64,
        "handoff_job_key": "job_" + "2" * 64,
        "handoff_root_sha256": "3" * 64,
        "producer_commit_sha": ancestor_commit,
        "semantic_receipt_sha256": "4" * 64,
    }
    source_record_sha256 = "5" * 64
    adapter = SimpleNamespace(handoff_bytes=b"original handoff", context_bytes=b"context")
    pinned = (
        document,
        b"execution receipt bytes",
        COMMIT,
        source_record_sha256,
        adapter,
        SimpleNamespace(),
    )
    events = []
    operation_documents = []

    class FakeStore:
        def __init__(self, *_args, **_kwargs):
            pass

        def admit_current_runtime_nonrelease(self, handoff_bytes, context_bytes):
            events.append(("store_admit", handoff_bytes, context_bytes))
            return SimpleNamespace(
                environment=admission_runner.CURRENT_RUNTIME_ENVIRONMENT,
                authority_scope=admission_runner.CURRENT_RUNTIME_AUTHORITY_SCOPE,
                admission_kind=admission_runner.ADMISSION_KIND_CURRENT_RUNTIME,
                application_id=document["application_id"],
                job_key=document["handoff_job_key"],
                handoff_root_sha256=document["handoff_root_sha256"],
                created=False,
                verification_receipt_sha256="6" * 64,
            )

    def read_admissible(*, execution_receipt_path, deployment, paths, commit_resolver):
        events.append("authenticated_ancestor_checked")
        return pinned

    def save_operation(_descriptor, _name, value):
        operation_documents.append(json.loads(value))

    deployment = admission_runner._ProductionAdmissionDeployment(
        data_home=tmp_path / "data",
        repository_root=tmp_path / "repo",
        outbox_root=tmp_path / "outbox",
        execution_receipt_root=tmp_path / "outbox" / "receipts",
        admission_root=tmp_path / "data" / "state" / "jaa-production-admissions",
        environment=admission_runner.CURRENT_RUNTIME_ENVIRONMENT,
        trust_root_id=admission_runner.CURRENT_RUNTIME_TRUST_ROOT_ID,
        freshness_provenance=admission_runner.CURRENT_RUNTIME_FRESHNESS_PROVENANCE,
    )
    paths = SimpleNamespace(
        data_descriptor=10,
        verify_references=lambda: events.append("verify_references"),
    )
    child_descriptors = {"state": 20, "jaa-production-admissions": 21, "receipts": 22}
    monkeypatch.setattr(
        admission_runner,
        "_read_admissible_published_handoff_pinned",
        read_admissible,
    )
    monkeypatch.setattr(admission_runner, "HandoffAdmissionStore", FakeStore)
    monkeypatch.setattr(admission_runner, "_prepare_database", lambda *_: None)
    monkeypatch.setattr(admission_runner, "_create_or_exact", save_operation)
    monkeypatch.setattr(
        admission_runner,
        "_open_private_child",
        lambda _parent, name: child_descriptors[name],
    )
    monkeypatch.setattr(admission_runner.os, "dup", lambda _descriptor: 11)
    monkeypatch.setattr(admission_runner.os, "close", lambda _descriptor: None)

    result = admission_runner._run_production_handoff_admission_pinned(
        execution_receipt_path=Path("receipt.json"),
        deployment=deployment,
        witness=None,
        paths=paths,
        commit_resolver=lambda *_: COMMIT,
    )

    assert events.index("authenticated_ancestor_checked") < next(
        index for index, event in enumerate(events) if isinstance(event, tuple) and event[0] == "store_admit"
    )
    assert result.producer_commit_sha == ancestor_commit
    assert operation_documents[0]["producer_commit_sha"] == ancestor_commit
    assert result.document()["producer_commit_sha"] == ancestor_commit
    assert result.document()["release_token_issued"] is False
    assert result.document()["submission_authority"] is False


def test_current_selection_accepts_only_verified_ancestor_producers(
    monkeypatch,
):
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(admission_runner.subprocess, "run", run)
    assert admission_runner._producer_commit_is_ancestor(
        17, "1" * 40, "2" * 40
    ) is True
    assert calls[0][0] == [
        "git", "merge-base", "--is-ancestor", "1" * 40, "2" * 40
    ]
    assert calls[0][1]["pass_fds"] == (17,)

    monkeypatch.setattr(
        admission_runner.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )
    assert admission_runner._producer_commit_is_ancestor(
        17, "1" * 40, "2" * 40
    ) is False
    with pytest.raises(
        admission_runner.ProductionHandoffAdmissionError,
        match="ancestry could not be verified",
    ):
        monkeypatch.setattr(
            admission_runner.subprocess,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(returncode=128),
        )
        admission_runner._producer_commit_is_ancestor(17, "1" * 40, "2" * 40)


def test_service_selected_handoffs_uses_installed_read_boundary(monkeypatch):
    expected = [{"application_id": "synthetic", "release_authority": False}]
    observed = {}

    def query(profile_id, **kwargs):
        observed.update(profile_id=profile_id, **kwargs)
        return expected

    monkeypatch.setattr(admission_runner, "selected_published_handoffs", query)
    assert service_api.MarketAlignerService.selected_handoffs(
        "prf_" + "6" * 32, profile_version="version-1",
        candidate_intent_sha256="8" * 64,
    ) is expected
    assert observed == {"profile_id": "prf_" + "6" * 32,
                        "profile_version": "version-1", "candidate_intent_sha256": "8" * 64}


def test_published_selection_preserves_geography_score_and_stable_tie_order(monkeypatch, tmp_path):
    deployment = _deployment(tmp_path)
    # Receipt validation is covered above; vary only the already-verified sort inputs here.
    cases = {
        "a": (2, 1.0, 1.0, "job_a", "app_a"),
        "b": (1, 0.6, 0.9, "job_a", "app_b"),
        "c": (1, 0.8, 0.7, "job_a", "app_c"),
        "d": (1, 0.8, 0.9, "job_b", "app_d"),
        "e": (1, 0.8, 0.9, "job_a", "app_f"),
        "f": (1, 0.8, 0.9, "job_a", "app_e"),
    }
    for name in cases:
        (deployment.execution_receipt_root / name).write_bytes(b"synthetic validated input")

    def read(*, execution_receipt_path, **kwargs):
        rank, score, opportunity, job_key, application_id = cases[execution_receipt_path.name]
        handoff = SimpleNamespace(strict_profile=True, root_sha256=SHA,
            application_id=application_id, payload={
                "profile_id": "prf_" + "6" * 32, "profile_version": "version-1",
                "candidate_intent_sha256": "8" * 64,
                "selection": {"decision": "selected_for_application", "hard_gate_passed": True,
                              "geography_bucket": "UK_remote", "geography_priority_rank": rank},
                "eligibility": {"hard_gate_passed": True},
                "assessment": {"final": score, "opportunity": opportunity},
                "job_key": job_key, "vacancy": {"vacancy_snapshot_sha256": SHA},
                "created_at": "2026-09-13T00:00:00Z",
            })
        return {"semantic_receipt_sha256": SHA, "source_job_key": job_key}, None, None, None, None, handoff

    monkeypatch.setattr(admission_runner, "_read_published_handoff_pinned", read)
    rows = admission_runner._selected_published_handoffs(
        profile_id="prf_" + "6" * 32, profile_version="version-1",
        candidate_intent_sha256="8" * 64, deployment=deployment,
        commit_resolver=lambda *_: COMMIT,
    )
    assert [row["application_id"] for row in rows] == [
        "app_e", "app_f", "app_d", "app_c", "app_b", "app_a",
    ]
    assert not deployment.admission_root.exists()
