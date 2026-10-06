from __future__ import annotations

import hashlib
import inspect
import json
from itertools import combinations
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
    output_root = tmp_path / "market-handoff"
    data_home.mkdir(mode=0o700)
    repository_root.mkdir(mode=0o755)
    candidate_directory = tmp_path / "candidate"
    candidate_directory.mkdir(mode=0o700)
    deployment = _ProductionHandoffDeployment(
        data_home=data_home,
        repository_root=repository_root,
        output_root=output_root,
        collection_config_path=runner.PRODUCTION_COLLECTION_CONFIG_PATH,
        collection_config_sha256=runner.PRODUCTION_COLLECTION_CONFIG_SHA256,
        collection_config_file_sha256=runner.PRODUCTION_COLLECTION_CONFIG_FILE_SHA256,
        deployment_configuration_sha256="d" * 64,
        research_archive_root_identity=runner.PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY,
        candidate_authority_path=candidate_directory / "candidate_authority.json",
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
        "execution_receipt_root": str(output_root / "receipts"),
        "output_root": str(output_root),
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
    ],
)
def test_alternate_roots_fail_before_time_or_state_read(
    monkeypatch, tmp_path: Path, field: str
) -> None:
    alternate_document = runner._expected_deployment_document()
    alternate_document[field] = (
        str(tmp_path / f"alternate-{field}")
        if field == "collection_config_path"
        else "f" * 64
    )
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
        runner.ProductionHandoffDeploymentError,
        match="differs|collection configuration",
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


def test_host_deployment_paths_are_accepted_when_bound_to_the_repository(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "artvault" / "market-aligner"
    data_home = tmp_path / "artvault" / "ma-state"
    output_root = tmp_path / "artvault" / "ma-outbox"
    candidate = tmp_path / "artvault" / "private" / "candidate_authority.json"
    raw = runner.production_handoff_deployment_configuration_bytes(
        data_home=data_home,
        repository_root=repository,
        output_root=output_root,
        candidate_authority_path=candidate,
        candidate_authority_sha256="a" * 64,
    )

    assert runner._parse_deployment_configuration(raw) == hashlib.sha256(raw).hexdigest()
    document = __import__("json").loads(raw)
    assert document["repository_root"] == str(repository)
    assert document["collection_config_path"] == str(
        repository / "internal/jaa/skeleton/config.overnight.yaml"
    )
    assert document["candidate_authority_path"] == str(candidate)
    assert document["candidate_authority_sha256"] == "a" * 64


def _synthetic_host_deployment_values(tmp_path: Path) -> dict[str, object]:
    return {
        "data_home": tmp_path / "artvault" / "ma-state",
        "repository_root": tmp_path / "artvault" / "market-aligner",
        "output_root": tmp_path / "artvault" / "ma-outbox",
        "candidate_authority_path": tmp_path / "artvault" / "private" / "candidate.json",
        "candidate_authority_sha256": "a" * 64,
    }


def test_legacy_builder_bytes_remain_exact() -> None:
    assert hashlib.sha256(
        runner.production_handoff_deployment_configuration_bytes()
    ).hexdigest() == "7f06b79bdc90ec20bd03d93224bc3307cff2b4cf7a6a5308d1fa52b5643df6aa"
    host_values = {
        "data_home": "/var/lib/synthetic-ma/data",
        "repository_root": "/srv/synthetic-ma/source",
        "output_root": "/var/lib/synthetic-ma/outbox",
        "candidate_authority_path": "/var/lib/synthetic-ma/authority/current.json",
        "candidate_authority_sha256": "a" * 64,
    }
    assert hashlib.sha256(
        runner.production_handoff_deployment_configuration_bytes(**host_values)
    ).hexdigest() == "db3b74cb854913354c75559e69e7e69ea9157530ff2da5632881a20f03a534c5"


def test_current_collection_binding_round_trips_as_v2(tmp_path: Path) -> None:
    host_values = _synthetic_host_deployment_values(tmp_path)
    collection_values = {
        "collection_config_path": "/etc/market-aligner/collection.yaml",
        "collection_config_sha256": "b" * 64,
        "collection_config_file_sha256": "c" * 64,
    }
    raw = runner.production_handoff_deployment_configuration_bytes(
        **host_values, **collection_values
    )
    document = json.loads(raw)

    assert document["schema_version"] == runner._DEPLOYMENT_SCHEMA_V2
    assert document["collection_config_path"] == collection_values["collection_config_path"]
    assert document["collection_config_sha256"] != document[
        "collection_config_file_sha256"
    ]
    assert runner._parse_deployment_configuration(raw) == hashlib.sha256(raw).hexdigest()


_HOST_DEPLOYMENT_FIELDS = (
    "data_home",
    "repository_root",
    "output_root",
    "candidate_authority_path",
    "candidate_authority_sha256",
)
_COLLECTION_DEPLOYMENT_FIELDS = (
    "collection_config_path",
    "collection_config_sha256",
    "collection_config_file_sha256",
)


@pytest.mark.parametrize(
    "provided_fields",
    [
        fields
        for count in range(1, len(_HOST_DEPLOYMENT_FIELDS))
        for fields in combinations(_HOST_DEPLOYMENT_FIELDS, count)
    ],
)
def test_partial_host_deployment_bundles_refuse(
    tmp_path: Path, provided_fields: tuple[str, ...]
) -> None:
    values = _synthetic_host_deployment_values(tmp_path)
    with pytest.raises(runner.ProductionHandoffDeploymentError):
        runner.production_handoff_deployment_configuration_bytes(
            **{key: values[key] for key in provided_fields}
        )


@pytest.mark.parametrize(
    "provided_fields",
    [
        fields
        for count in range(1, len(_COLLECTION_DEPLOYMENT_FIELDS))
        for fields in combinations(_COLLECTION_DEPLOYMENT_FIELDS, count)
    ],
)
def test_partial_collection_binding_refuses(
    tmp_path: Path, provided_fields: tuple[str, ...]
) -> None:
    values = {
        "collection_config_path": "/etc/market-aligner/collection.yaml",
        "collection_config_sha256": "b" * 64,
        "collection_config_file_sha256": "c" * 64,
    }
    arguments = _synthetic_host_deployment_values(tmp_path)
    arguments.update({key: values[key] for key in provided_fields})
    with pytest.raises(runner.ProductionHandoffDeploymentError):
        runner.production_handoff_deployment_configuration_bytes(**arguments)


def test_current_collection_binding_requires_all_host_values() -> None:
    with pytest.raises(
        runner.ProductionHandoffDeploymentError,
        match="all five host-specific authority values",
    ):
        runner.production_handoff_deployment_configuration_bytes(
            collection_config_path="/etc/market-aligner/collection.yaml",
            collection_config_sha256="b" * 64,
            collection_config_file_sha256="c" * 64,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("collection_config_sha256", True),
        ("collection_config_sha256", "B" * 64),
        ("collection_config_sha256", "g" * 64),
        ("collection_config_file_sha256", True),
        ("collection_config_file_sha256", "C" * 64),
        ("collection_config_file_sha256", "z" * 64),
    ],
)
def test_current_collection_binding_rejects_invalid_hashes(
    tmp_path: Path, field: str, value: object
) -> None:
    arguments = _synthetic_host_deployment_values(tmp_path)
    arguments.update(
        {
            "collection_config_path": "/etc/market-aligner/collection.yaml",
            "collection_config_sha256": "b" * 64,
            "collection_config_file_sha256": "c" * 64,
        }
    )
    arguments[field] = value
    with pytest.raises(runner.ProductionHandoffDeploymentError):
        runner.production_handoff_deployment_configuration_bytes(**arguments)


@pytest.mark.parametrize(
    "path",
    (
        "relative/collection.yaml",
        "/",
        "/var/../etc/collection.yaml",
        "/var//etc/collection.yaml",
        "/var/./etc/collection.yaml",
        "/var/etc/",
        "//a/b",
    ),
)
def test_current_collection_binding_rejects_noncanonical_paths(
    tmp_path: Path, path: str
) -> None:
    arguments = _synthetic_host_deployment_values(tmp_path)
    arguments.update(
        {
            "collection_config_path": path,
            "collection_config_sha256": "b" * 64,
            "collection_config_file_sha256": "c" * 64,
        }
    )
    with pytest.raises(runner.ProductionHandoffDeploymentError):
        runner.production_handoff_deployment_configuration_bytes(**arguments)


def test_v1_binding_and_unknown_schema_are_rejected_when_changed() -> None:
    legacy = json.loads(runner.production_handoff_deployment_configuration_bytes())
    changed_legacy = dict(legacy)
    changed_legacy["collection_config_path"] = "/etc/market-aligner/collection.yaml"
    changed_legacy["collection_config_sha256"] = "b" * 64
    changed_legacy["collection_config_file_sha256"] = "c" * 64
    with pytest.raises(
        runner.ProductionHandoffDeploymentError,
        match="trust or code identity differs",
    ):
        runner._parse_deployment_configuration(canonical_json_bytes(changed_legacy))

    unknown_schema = dict(legacy)
    unknown_schema["schema_version"] = "jaa.production-market-handoff-deployment.v3"
    with pytest.raises(
        runner.ProductionHandoffDeploymentError,
        match="trust or code identity differs",
    ):
        runner._parse_deployment_configuration(canonical_json_bytes(unknown_schema))


def test_v2_still_requires_the_fixed_trust_identity(tmp_path: Path) -> None:
    arguments = _synthetic_host_deployment_values(tmp_path)
    arguments.update(
        {
            "collection_config_path": "/etc/market-aligner/collection.yaml",
            "collection_config_sha256": "b" * 64,
            "collection_config_file_sha256": "c" * 64,
        }
    )
    document = json.loads(
        runner.production_handoff_deployment_configuration_bytes(**arguments)
    )
    document["trust_root_id"] = "untrusted-root"
    with pytest.raises(
        runner.ProductionHandoffDeploymentError,
        match="trust or code identity differs",
    ):
        runner._parse_deployment_configuration(canonical_json_bytes(document))


def test_host_deployment_configuration_requires_all_authority_values(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        runner.ProductionHandoffDeploymentError,
        match="all five host-specific authority values",
    ):
        runner.production_handoff_deployment_configuration_bytes(
            data_home=tmp_path / "private-state"
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
    candidate_directory = tmp_path / "candidate"
    candidate_directory.mkdir(mode=0o700)
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
        candidate_authority_path=candidate_directory / "candidate_authority.json",
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
