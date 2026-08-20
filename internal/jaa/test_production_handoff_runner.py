from __future__ import annotations

import hashlib
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest
from career_automation import production_handoff_runner as runner

from market_aligner.applications import production_handoff as production_module
from market_aligner.applications.handoff import canonical_json_bytes
from market_aligner.applications.production_handoff import _ProductionHandoffDeployment


def test_public_runner_owns_current_time_and_exposes_no_release_path(
    monkeypatch, tmp_path: Path
) -> None:
    data_home = tmp_path / "data"
    repository_root = tmp_path / "repo"
    data_home.mkdir(mode=0o700)
    repository_root.mkdir(mode=0o755)
    deployment = _ProductionHandoffDeployment(
        data_home=data_home,
        repository_root=repository_root,
        output_root=runner.PRODUCTION_MARKET_OUTBOX_ROOT,
        collection_config_path=runner.PRODUCTION_COLLECTION_CONFIG_PATH,
        collection_config_sha256=runner.PRODUCTION_COLLECTION_CONFIG_SHA256,
        collection_config_file_sha256=runner.PRODUCTION_COLLECTION_CONFIG_FILE_SHA256,
        deployment_configuration_sha256="d" * 64,
        research_archive_root_identity=runner.PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY,
    )
    witness = object()
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        runner, "installed_production_current_time_witness", lambda: witness
    )

    def obtain(value, **kwargs):
        observed.update(kwargs)
        assert value is witness
        return SimpleNamespace(evaluated_at="2026-08-21T00:01:00Z")

    expected = object()

    def build(**kwargs):
        observed["builder"] = kwargs
        return expected

    monkeypatch.setattr(runner, "obtain_current_time", obtain)
    monkeypatch.setattr(
        runner, "_build_production_handoff_from_authenticated_time", build
    )
    monkeypatch.setattr(
        runner, "installed_production_handoff_deployment", lambda: deployment
    )
    assert (
        runner.run_production_handoff(
            profile_id="prf_" + "1" * 32,
            track="software-engineering",
            source_job_key="workable:cogna:847CFBC5F4",
        )
        is expected
    )
    assert (
        "freshness_time"
        not in inspect.signature(runner.run_production_handoff).parameters
    )
    assert (
        "deployment" not in inspect.signature(runner.run_production_handoff).parameters
    )
    assert not hasattr(production_module, "ProductionHandoffDeployment")
    assert observed["environment"] == "production"
    assert observed["purpose"] == "production_handoff_freshness"
    expected_subject = {
        "candidate_authority_sha256": production_module.PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
        "collection_config_path": str(runner.PRODUCTION_COLLECTION_CONFIG_PATH),
        "collection_config_sha256": runner.PRODUCTION_COLLECTION_CONFIG_SHA256,
        "collection_config_file_sha256": runner.PRODUCTION_COLLECTION_CONFIG_FILE_SHA256,
        "data_home": str(data_home),
        "deployment_configuration_sha256": "d" * 64,
        "execution_receipt_root": str(runner.PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT),
        "output_root": str(runner.PRODUCTION_MARKET_OUTBOX_ROOT),
        "profile_id": "prf_" + "1" * 32,
        "repository_root": str(repository_root),
        "schema_version": "jaa.production-handoff-freshness-subject.v1",
        "source_job_key": "workable:cogna:847CFBC5F4",
        "track": "software-engineering",
    }
    assert (
        observed["subject_sha256"]
        == hashlib.sha256(canonical_json_bytes(expected_subject)).hexdigest()
    )
    assert (
        observed["builder"]["freshness_time"].isoformat() == "2026-08-21T00:01:00+00:00"
    )


@pytest.mark.parametrize(
    "field",
    [
        "collection_config_path",
        "collection_config_sha256",
        "collection_config_file_sha256",
        "data_home",
        "output_root",
        "repository_root",
    ],
)
def test_alternate_roots_fail_before_time_or_state_read(
    monkeypatch, tmp_path: Path, field: str
) -> None:
    alternate_document = runner._expected_deployment_document()
    alternate_document[field] = str(tmp_path / f"alternate-{field}")
    alternate = canonical_json_bytes(alternate_document)
    calls = {"time": 0, "build": 0}

    def rejected_deployment():
        runner._parse_deployment_configuration(alternate)

    def forbidden_time(*args, **kwargs):
        calls["time"] += 1
        raise AssertionError("time witness must not run")

    def forbidden_build(**kwargs):
        calls["build"] += 1
        raise AssertionError("state builder must not run")

    monkeypatch.setattr(
        runner, "installed_production_handoff_deployment", rejected_deployment
    )
    monkeypatch.setattr(
        runner, "installed_production_current_time_witness", forbidden_time
    )
    monkeypatch.setattr(
        runner, "_build_production_handoff_from_authenticated_time", forbidden_build
    )
    with pytest.raises(
        runner.ProductionHandoffDeploymentError, match="compiled canonical roots"
    ):
        runner.run_production_handoff(
            profile_id="prf_" + "1" * 32,
            track="software-engineering",
            source_job_key="workable:cogna:847CFBC5F4",
        )
    assert calls == {"time": 0, "build": 0}
    parameters = inspect.signature(runner.run_production_handoff).parameters
    assert {"data_home", "output_root", "execution_receipt_root"}.isdisjoint(parameters)


def test_compiled_deployment_document_is_exact_and_receipt_root_is_derived() -> None:
    exact = canonical_json_bytes(runner._expected_deployment_document())
    assert (
        runner._parse_deployment_configuration(exact)
        == hashlib.sha256(exact).hexdigest()
    )
    assert runner.PRODUCTION_MARKET_EXECUTION_RECEIPT_ROOT == (
        runner.PRODUCTION_MARKET_OUTBOX_ROOT / "receipts"
    )
    assert runner.PRODUCTION_COLLECTION_CONFIG_PATH == (
        runner.PRODUCTION_MARKET_REPOSITORY_ROOT
        / "internal/jaa/skeleton/config.overnight.yaml"
    )
    assert runner.PRODUCTION_COLLECTION_CONFIG_SHA256 == (
        "8868d381087729776e6eb5b689520fc74bf2239b59ccc94854b8feff8b627698"
    )
    assert runner.PRODUCTION_COLLECTION_CONFIG_FILE_SHA256 == (
        "ad6c247fbbb48a6e22d8f18fff3a1aed37f2f1da6099973a29c90c08cced7bf4"
    )


def test_outbox_symlink_is_rejected_before_time_or_state(
    monkeypatch, tmp_path: Path
) -> None:
    data_home = tmp_path / "data"
    repository_root = tmp_path / "repo"
    output_parent = tmp_path / "protected"
    real_output = tmp_path / "real-output"
    data_home.mkdir(mode=0o700)
    repository_root.mkdir(mode=0o755)
    output_parent.mkdir(mode=0o700)
    real_output.mkdir(mode=0o700)
    output = output_parent / "outbox"
    output.symlink_to(real_output, target_is_directory=True)
    deployment = _ProductionHandoffDeployment(
        data_home=data_home,
        repository_root=repository_root,
        output_root=output,
        collection_config_path=runner.PRODUCTION_COLLECTION_CONFIG_PATH,
        collection_config_sha256=runner.PRODUCTION_COLLECTION_CONFIG_SHA256,
        collection_config_file_sha256=runner.PRODUCTION_COLLECTION_CONFIG_FILE_SHA256,
        deployment_configuration_sha256="e" * 64,
        research_archive_root_identity=runner.PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY,
    )
    called = {"time": False}
    monkeypatch.setattr(
        runner, "installed_production_handoff_deployment", lambda: deployment
    )
    monkeypatch.setattr(
        runner,
        "installed_production_current_time_witness",
        lambda: called.update(time=True),
    )
    with pytest.raises(
        runner.ProductionHandoffDeploymentError, match="outbox identity"
    ):
        runner.run_production_handoff(
            profile_id="prf_" + "1" * 32,
            track="software-engineering",
            source_job_key="workable:cogna:847CFBC5F4",
        )
    assert called["time"] is False
