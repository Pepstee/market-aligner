from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import replace
from datetime import timezone
from itertools import combinations
from pathlib import Path
from types import SimpleNamespace

import pytest
from career_automation import production_handoff_runner as runner
from career_automation.market_aligner_handoff import parse_handoff_for_runtime

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


def _current_runtime_document(
    tmp_path: Path, *, repository_root: Path | None = None
) -> tuple[dict[str, object], Path]:
    private_root = tmp_path / "private-runtime"
    document = runner._expected_deployment_document()
    document.update(
        {
            "candidate_authority_path": str(
                tmp_path / "authority" / "candidate-authority.json"
            ),
            "candidate_authority_sha256": "a" * 64,
            "collection_config_path": "/srv/artvault/control/programme/collection.yaml",
            "collection_config_sha256": "b" * 64,
            "collection_config_file_sha256": "c" * 64,
            "data_home": str(private_root),
            "output_root": str(tmp_path / "handoff-outbox"),
            "repository_root": str(repository_root or tmp_path / "repository"),
            "schema_version": "market-aligner.current-runtime-handoff-deployment.v1",
            "trust_root_id": "market-aligner-current-runtime-non-release-v1",
        }
    )
    return document, private_root


def test_bound_json_decoder_rejects_mismatch_duplicates_and_nonfinite_values() -> None:
    raw = b'{"a":1,"nested":{"b":"x"}}'
    assert runner.decode_bound_json(raw, hashlib.sha256(raw).hexdigest()) == {
        "a": 1,
        "nested": {"b": "x"},
    }
    for invalid in (
        (raw + b"\n", hashlib.sha256(raw).hexdigest()),
        (b'{"a":1,"a":2}', hashlib.sha256(b'{"a":1,"a":2}').hexdigest()),
        (b'{"v":1e999}', hashlib.sha256(b'{"v":1e999}').hexdigest()),
        (b'{"v":NaN}', hashlib.sha256(b'{"v":NaN}').hexdigest()),
        (b"[1]", hashlib.sha256(b"[1]").hexdigest()),
        (b'{"v":"\xff"}', hashlib.sha256(b'{"v":"\xff"}').hexdigest()),
    ):
        with pytest.raises(ValueError, match="^private_runtime_config_invalid$"):
            runner.decode_bound_json(*invalid)


def test_current_runtime_configuration_has_distinct_schema_and_trust_root(
    tmp_path: Path,
) -> None:
    document, private_root = _current_runtime_document(tmp_path)
    raw = canonical_json_bytes(document)

    assert runner._validate_deployment_document(
        document, current_runtime_root=private_root
    ) == document
    assert document["collection_config_path"] not in str(private_root)
    with pytest.raises(runner.ProductionHandoffDeploymentError):
        runner._validate_deployment_document(document)
    with pytest.raises(runner.ProductionHandoffDeploymentError):
        runner._parse_deployment_configuration(raw)

    for field, value in (
        ("schema_version", runner._DEPLOYMENT_SCHEMA_V2),
        ("trust_root_id", production_module.PRODUCTION_HANDOFF_TRUST_ROOT_ID),
        ("data_home", str(tmp_path / "other-private-root")),
    ):
        changed = dict(document)
        changed[field] = value
        with pytest.raises(runner.ProductionHandoffDeploymentError):
            runner._validate_deployment_document(
                changed, current_runtime_root=private_root
            )


def test_current_runtime_loader_binds_raw_hash_and_exact_private_root(
    monkeypatch, tmp_path: Path
) -> None:
    document, private_root = _current_runtime_document(
        tmp_path, repository_root=Path(__file__).resolve().parents[2]
    )
    raw = canonical_json_bytes(document)
    digest = hashlib.sha256(raw).hexdigest()
    config_path = private_root / "deployment" / "market-handoff.json"
    observed: dict[str, object] = {}

    def read(path, root, expected):
        observed.update(path=path, root=root, expected=expected)
        return raw

    monkeypatch.setattr(runner, "_read_current_runtime_configuration", read)
    deployment = runner.installed_current_runtime_handoff_deployment(
        configuration_path=config_path,
        configuration_sha256=digest,
        private_root=private_root,
    )
    assert observed == {"path": config_path, "root": private_root, "expected": digest}
    assert deployment.data_home == private_root
    assert deployment.environment == "current_runtime"
    assert deployment.trust_root_id == "market-aligner-current-runtime-non-release-v1"
    assert deployment.freshness_provenance == "local_system_utc"


def test_current_runtime_config_path_must_be_strictly_beneath_private_root(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        runner.ProductionHandoffDeploymentError,
        match="must be beneath its private root",
    ):
        runner._read_current_runtime_configuration(
            tmp_path / "public-config.json",
            tmp_path / "private-runtime",
            "a" * 64,
        )


@pytest.mark.parametrize(
    "provided",
    [
        {"current_runtime_config_path": "/private/config.json"},
        {"current_runtime_config_sha256": "a" * 64},
        {"current_runtime_private_root": "/private"},
    ],
)
def test_current_runtime_cli_arguments_are_all_or_none(provided: dict[str, str]) -> None:
    with pytest.raises(
        runner.ProductionHandoffDeploymentError,
        match="requires config path, raw hash and private root",
    ):
        runner.run_production_handoff(
            profile_id="prf_" + "1" * 32,
            track="software-engineering",
            source_job_key="workable:cogna:847CFBC5F4",
            **provided,
        )


def test_current_recovery_manifest_locator_requires_current_runtime() -> None:
    with pytest.raises(
        runner.ProductionHandoffDeploymentError,
        match="requires current runtime opt-in",
    ):
        runner.run_production_handoff(
            profile_id="prf_" + "1" * 32,
            track="software-engineering",
            source_job_key="workable:cogna:847CFBC5F4",
            current_recovery_manifest_relative_path=(
                "recovered-inputs/synthetic/recovery-manifest.json"
            ),
        )


def test_handoff_consumer_dispatch_is_explicit_and_keeps_current_nonrelease() -> None:
    payload = {"synthetic": True}
    payload_sha256 = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    envelope = {
        "payload": payload,
        "payload_sha256": payload_sha256,
        "schema_version": "market-aligner.jaa-handoff.current-runtime.v1",
    }
    raw = canonical_json_bytes(envelope)
    current_value = SimpleNamespace(
        exact_bytes=raw,
        payload_sha256=payload_sha256,
        root_sha256=hashlib.sha256(raw).hexdigest(),
        schema_version=envelope["schema_version"],
        emission_profile="current_runtime_non_release_v1",
        release_blocked=True,
    )
    legacy_calls: list[bytes] = []
    current_calls: list[bytes] = []
    made: list[dict[str, object]] = []

    def legacy_parser(value: bytes, *, require_strict_profile: bool) -> str:
        legacy_calls.append(value)
        assert require_strict_profile is False
        return "legacy"

    def current_parser(value: bytes) -> SimpleNamespace:
        current_calls.append(value)
        return current_value

    def make_parsed(**values: object) -> SimpleNamespace:
        made.append(values)
        return SimpleNamespace(**values)

    legacy_result = parse_handoff_for_runtime(
        b"legacy-bytes",
        current_runtime=False,
        require_strict_profile=False,
        legacy_parser=legacy_parser,
        current_parser=current_parser,
        make_parsed=make_parsed,
    )
    assert legacy_result == "legacy"
    assert legacy_calls == [b"legacy-bytes"]
    assert current_calls == []
    assert made == []

    parsed = parse_handoff_for_runtime(
        raw,
        current_runtime=True,
        require_strict_profile=False,
        legacy_parser=legacy_parser,
        current_parser=current_parser,
        make_parsed=make_parsed,
    )
    assert current_calls == [raw]
    assert parsed.original_bytes == raw
    assert parsed.emission_profile == "current_runtime_non_release_v1"
    assert parsed.strict_profile_violations == ()
    assert legacy_calls == [b"legacy-bytes"]

    with pytest.raises(ValueError, match="invalid handoff consumer dispatch"):
        parse_handoff_for_runtime(
            raw,
            current_runtime=True,
            require_strict_profile=True,
            legacy_parser=legacy_parser,
            current_parser=current_parser,
            make_parsed=make_parsed,
        )
    assert legacy_calls == [b"legacy-bytes"]


def test_current_runtime_runner_uses_local_time_and_never_calls_production_witness(
    monkeypatch, tmp_path: Path
) -> None:
    data_home = tmp_path / "data"
    repository_root = tmp_path / "repository"
    output_root = tmp_path / "outbox"
    candidate_directory = tmp_path / "authority"
    deployment = _ProductionHandoffDeployment(
        data_home=data_home,
        repository_root=repository_root,
        output_root=output_root,
        collection_config_path=Path("/srv/artvault/collection.yaml"),
        collection_config_sha256="b" * 64,
        collection_config_file_sha256="c" * 64,
        deployment_configuration_sha256="d" * 64,
        research_archive_root_identity=runner.PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY,
        candidate_authority_path=candidate_directory / "candidate.json",
        candidate_authority_sha256="a" * 64,
        environment="current_runtime",
        trust_root_id="market-aligner-current-runtime-non-release-v1",
        freshness_provenance="local_system_utc",
    )
    observed: dict[str, object] = {}
    expected = object()
    monkeypatch.setattr(
        runner,
        "installed_current_runtime_handoff_deployment",
        lambda **kwargs: deployment,
    )
    monkeypatch.setattr(runner, "_validate_deployment_roots", lambda _value: None)
    monkeypatch.setattr(
        runner,
        "installed_production_current_time_witness",
        lambda: (_ for _ in ()).throw(AssertionError("production witness used")),
    )

    def build(**kwargs):
        observed.update(kwargs)
        return expected

    monkeypatch.setattr(
        runner, "_build_production_handoff_from_authenticated_time", build
    )
    result = runner.run_production_handoff(
        profile_id="prf_" + "1" * 32,
        track="software-engineering",
        source_job_key="workable:cogna:847CFBC5F4",
        current_runtime_config_path="/private/config.json",
        current_runtime_config_sha256="e" * 64,
        current_runtime_private_root="/private",
        current_recovery_manifest_relative_path=(
            "recovered-inputs/synthetic/recovery-manifest.json"
        ),
    )
    assert result is expected
    assert observed["deployment"].environment == "current_runtime"
    assert observed["freshness_time"].tzinfo == timezone.utc
    assert observed["current_recovery_manifest_relative_path"] == (
        "recovered-inputs/synthetic/recovery-manifest.json"
    )


def test_current_runtime_receipt_document_is_distinct_and_nonrelease() -> None:
    production_receipt = production_module.ProductionHandoffReceipt(
        source_job_key="source",
        handoff_job_key="handoff",
        application_id="application",
        handoff_root_sha256="a" * 64,
        source_record_sha256="b" * 64,
        manifest_sha256="c" * 64,
        bundle_path=Path("/private/bundle"),
        canonical_vacancy_metadata_sha256="d" * 64,
        canonical_vacancy_object_sha256="e" * 64,
        research_semantic_receipt_sha256="f" * 64,
        research_receipt_file_sha256="1" * 64,
        research_archive_root_identity=runner.PRODUCTION_RESEARCH_ARCHIVE_ROOT_IDENTITY,
        research_vacancy_snapshot_sha256="2" * 64,
        source_content_sha256="3" * 64,
        processing_promotion_sha256="4" * 64,
        employer_dossier_sha256="5" * 64,
        execution_receipt_path=Path("/private/receipt.json"),
        execution_receipt_sha256="6" * 64,
    )
    assert production_receipt.document()["schema_version"] == (
        "market-aligner.production-handoff-receipt.v2"
    )
    current_receipt = replace(
        production_receipt,
        environment="current_runtime",
        trust_root_id="market-aligner-current-runtime-non-release-v1",
        freshness_provenance="local_system_utc",
    ).document()
    assert current_receipt["schema_version"] == (
        "market-aligner.current-runtime-handoff-receipt.v1"
    )
    assert current_receipt["environment"] == "current_runtime"
    assert current_receipt["trust_root_id"] == (
        "market-aligner-current-runtime-non-release-v1"
    )
    assert current_receipt["freshness_provenance"] == "local_system_utc"
    assert current_receipt["release_authority"] is False
    assert current_receipt["release_token_issued"] is False
    assert current_receipt["submission_authority"] is False
