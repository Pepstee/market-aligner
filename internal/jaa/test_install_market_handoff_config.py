from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from career_automation import production_handoff_runner as runner
from career_automation import production_preparation_runner as preparation_runner

from scripts import install_market_handoff_config as installer


def _parent_tree(tmp_path: Path) -> Path:
    parent = tmp_path
    for component in ("etc", "gigabyte", "majaa-public"):
        parent = parent / component
        parent.mkdir(mode=0o755)
    return parent


def test_exported_configuration_bytes_are_exact_runner_authority() -> None:
    value = runner.production_handoff_deployment_configuration_bytes()
    assert value == installer.production_handoff_deployment_configuration_bytes()
    assert (
        runner._parse_deployment_configuration(value)
        == hashlib.sha256(value).hexdigest()
    )
    assert not value.endswith(b"\n")


def test_exported_preparation_configuration_is_exact_fixed_authority() -> None:
    value = preparation_runner.production_preparation_configuration_bytes()
    assert value == installer.production_preparation_configuration_bytes()
    assert hashlib.sha256(value).hexdigest() == (
        "d11a0f2f144fc40e5a215f9f882086416b2424ff2404755a376e51eb151061d3"
    )
    assert not value.endswith(b"\n")
    document = __import__("json").loads(value)
    assert document["schema_version"] == (
        "jaa.production-application-preparation-deployment.v1"
    )
    assert document["candidate_authority_sha256"] == (
        preparation_runner.PRODUCTION_CANDIDATE_AUTHORITY_SHA256
    )
    assert document["codex_binary_sha256"] == (
        preparation_runner.PRODUCTION_CODEX_BINARY_SHA256
    )
    assert document["poppler_sha256"] == preparation_runner.PRODUCTION_POPPLER_SHA256


def test_create_then_exact_replay(tmp_path: Path) -> None:
    target = _parent_tree(tmp_path) / "market-handoff-v1.json"
    value = runner.production_handoff_deployment_configuration_bytes()
    kwargs = {
        "trusted_root": tmp_path,
        "expected_uid": os.geteuid(),
    }
    assert installer._create_or_exact_at(target, value, **kwargs) == "created"
    assert target.read_bytes() == value
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert target.stat().st_uid == os.geteuid()
    assert installer._create_or_exact_at(target, value, **kwargs) == "exact-replay"


def test_differing_target_is_never_overwritten(tmp_path: Path) -> None:
    target = _parent_tree(tmp_path) / "market-handoff-v1.json"
    target.write_bytes(b"different")
    target.chmod(0o644)
    with pytest.raises(FileExistsError, match="refusing to overwrite differing"):
        installer._create_or_exact_at(
            target,
            runner.production_handoff_deployment_configuration_bytes(),
            trusted_root=tmp_path,
            expected_uid=os.geteuid(),
        )
    assert target.read_bytes() == b"different"


def test_exact_installed_prior_configuration_is_atomically_upgraded(
    tmp_path: Path,
) -> None:
    target = _parent_tree(tmp_path) / "market-handoff-v1.json"
    target.write_bytes(installer._PRIOR_DEPLOYMENT_CONFIGURATION)
    target.chmod(0o644)
    value = runner.production_handoff_deployment_configuration_bytes()
    outcome = installer._create_or_exact_at(
        target,
        value,
        trusted_root=tmp_path,
        expected_uid=os.geteuid(),
    )
    assert outcome == "upgraded-exact-prior"
    assert target.read_bytes() == value
    assert not any(path.name.endswith(".tmp") for path in target.parent.iterdir())


def test_prior_upgrade_partial_write_keeps_exact_prior_and_retry_succeeds(
    monkeypatch, tmp_path: Path
) -> None:
    target = _parent_tree(tmp_path) / "market-handoff-v1.json"
    target.write_bytes(installer._PRIOR_DEPLOYMENT_CONFIGURATION)
    target.chmod(0o644)
    value = runner.production_handoff_deployment_configuration_bytes()

    def partial(descriptor: int, content: bytes) -> None:
        os.write(descriptor, content[:11])
        raise OSError("injected installer crash")

    monkeypatch.setattr(installer, "_write_all", partial)
    with pytest.raises(OSError, match="injected"):
        installer._create_or_exact_at(
            target,
            value,
            trusted_root=tmp_path,
            expected_uid=os.geteuid(),
        )
    assert target.read_bytes() == installer._PRIOR_DEPLOYMENT_CONFIGURATION
    assert not any(path.name.endswith(".tmp") for path in target.parent.iterdir())
    monkeypatch.undo()
    assert (
        installer._create_or_exact_at(
            target,
            value,
            trusted_root=tmp_path,
            expected_uid=os.geteuid(),
        )
        == "upgraded-exact-prior"
    )


def test_symlink_target_is_rejected(tmp_path: Path) -> None:
    parent = _parent_tree(tmp_path)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    target = parent / "market-handoff-v1.json"
    target.symlink_to(outside)
    with pytest.raises(OSError):
        installer._create_or_exact_at(
            target,
            runner.production_handoff_deployment_configuration_bytes(),
            trusted_root=tmp_path,
            expected_uid=os.geteuid(),
        )
    assert outside.read_bytes() == b"outside"


def test_unsafe_parent_is_rejected_before_target_write(tmp_path: Path) -> None:
    parent = _parent_tree(tmp_path)
    parent.chmod(0o777)
    target = parent / "market-handoff-v1.json"
    with pytest.raises(PermissionError, match="protected directory"):
        installer._create_or_exact_at(
            target,
            runner.production_handoff_deployment_configuration_bytes(),
            trusted_root=tmp_path,
            expected_uid=os.geteuid(),
        )
    assert not target.exists()


def test_symlink_parent_component_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o755)
    (tmp_path / "etc").symlink_to(real, target_is_directory=True)
    target = tmp_path / "etc" / "gigabyte" / "majaa-public" / "market-handoff-v1.json"
    with pytest.raises(OSError):
        installer._create_or_exact_at(
            target,
            runner.production_handoff_deployment_configuration_bytes(),
            trusted_root=tmp_path,
            expected_uid=os.geteuid(),
        )


def test_non_root_install_refuses_before_opening_fixed_target(monkeypatch) -> None:
    monkeypatch.setattr(installer.os, "geteuid", lambda: 1000)
    called = {"create": False}

    def forbidden(*args, **kwargs):
        called["create"] = True
        raise AssertionError("target must not be opened")

    monkeypatch.setattr(installer, "_create_or_exact_at", forbidden)
    with pytest.raises(PermissionError, match="requires root"):
        installer.install()
    assert called["create"] is False


def test_non_root_preparation_install_refuses_before_opening_fixed_target(
    monkeypatch,
) -> None:
    monkeypatch.setattr(installer.os, "geteuid", lambda: 1000)
    called = {"create": False}

    def forbidden(*args, **kwargs):
        called["create"] = True
        raise AssertionError("target must not be opened")

    monkeypatch.setattr(installer, "_create_or_exact_at", forbidden)
    with pytest.raises(PermissionError, match="requires root"):
        installer.install_preparation()
    assert called["create"] is False


def test_print_config_cli_is_byte_exact(capsys) -> None:
    assert installer.main(["--print-config"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert (
        captured.out.encode()
        == runner.production_handoff_deployment_configuration_bytes()
    )


def test_print_config_cli_accepts_complete_host_deployment(capsys, tmp_path: Path) -> None:
    values = {
        "data_home": tmp_path / "private-state",
        "repository_root": tmp_path / "deployed-repository",
        "output_root": tmp_path / "private-outbox",
        "candidate_authority_path": tmp_path / "private" / "candidate.json",
        "candidate_authority_sha256": "a" * 64,
    }
    args = ["--print-config"]
    for key, value in values.items():
        args.extend(("--" + key.replace("_", "-"), str(value)))

    assert installer.main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.encode() == runner.production_handoff_deployment_configuration_bytes(
        **values
    )


def test_print_config_cli_accepts_current_collection_binding(
    capsys, tmp_path: Path
) -> None:
    values = {
        "data_home": tmp_path / "private-state",
        "repository_root": tmp_path / "deployed-repository",
        "output_root": tmp_path / "private-outbox",
        "candidate_authority_path": tmp_path / "private" / "candidate.json",
        "candidate_authority_sha256": "a" * 64,
        "collection_config_path": "/etc/market-aligner/collection.yaml",
        "collection_config_sha256": "b" * 64,
        "collection_config_file_sha256": "c" * 64,
    }
    arguments = ["--print-config"]
    for key, value in values.items():
        arguments.extend(("--" + key.replace("_", "-"), str(value)))

    assert installer.main(arguments) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.encode() == runner.production_handoff_deployment_configuration_bytes(
        **values
    )
    assert runner._parse_deployment_configuration(captured.out.encode()) == (
        hashlib.sha256(captured.out.encode()).hexdigest()
    )


def test_collection_options_require_all_three_cli_values(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        installer.main(
            ["--print-config", "--collection-config-path", "/etc/collection.yaml"]
        )
    assert raised.value.code == 2
    assert "requires --collection-config-path" in capsys.readouterr().err


def test_collection_options_require_all_five_host_values(capsys) -> None:
    arguments = [
        "--print-config",
        "--collection-config-path",
        "/etc/collection.yaml",
        "--collection-config-sha256",
        "b" * 64,
        "--collection-config-file-sha256",
        "c" * 64,
    ]
    with pytest.raises(SystemExit) as raised:
        installer.main(arguments)
    assert raised.value.code == 2
    assert "requires all five host options" in capsys.readouterr().err


def test_collection_options_cannot_be_combined_with_preparation_action(capsys) -> None:
    arguments = [
        "--print-preparation-config",
        "--data-home",
        "/var/lib/ma/state",
        "--repository-root",
        "/srv/ma/source",
        "--output-root",
        "/var/lib/ma/outbox",
        "--candidate-authority-path",
        "/var/lib/ma/authority/candidate.json",
        "--candidate-authority-sha256",
        "a" * 64,
        "--collection-config-path",
        "/etc/ma/collection.yaml",
        "--collection-config-sha256",
        "b" * 64,
        "--collection-config-file-sha256",
        "c" * 64,
    ]
    with pytest.raises(SystemExit) as raised:
        installer.main(arguments)
    assert raised.value.code == 2
    assert "cannot be used for preparation" in capsys.readouterr().err


def test_host_deployment_cli_rejects_partial_configuration(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        installer.main(["--print-config", "--data-home", "/tmp/ma-state"])
    assert raised.value.code == 2
    assert "requires --data-home" in capsys.readouterr().err


def test_print_preparation_config_cli_is_byte_exact(capsys) -> None:
    assert installer.main(["--print-preparation-config"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert (
        captured.out.encode()
        == preparation_runner.production_preparation_configuration_bytes()
    )


def test_print_preparation_config_cli_accepts_complete_host_paths(
    capsys, tmp_path: Path
) -> None:
    values = {
        "data_home": tmp_path / "private-state",
        "repository_root": tmp_path / "deployed-repository",
        "outbox_root": tmp_path / "private-outbox",
        "candidate_authority_path": tmp_path / "private" / "candidate.json",
        "contact_authority_path": tmp_path / "private" / "contact.json",
        "contact_public_key_path": tmp_path / "private" / "operator.pem",
        "contact_registry_path": tmp_path / "private" / "registry.json",
        "codex_binary": tmp_path / "codex" / "bin" / "codex.js",
        "poppler_bin": tmp_path / "poppler" / "usr" / "bin",
    }
    args = ["--print-preparation-config"]
    for key, value in values.items():
        args.extend(("--preparation-" + key.replace("_", "-"), str(value)))

    assert installer.main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    document = __import__("json").loads(captured.out)
    assert document["repository_root"] == str(values["repository_root"])
    assert document["candidate_authority_path"] == str(
        values["candidate_authority_path"]
    )
    assert document["admission_database"] == str(
        values["data_home"] / "state/jaa-production-admissions/admissions.sqlite3"
    )
    assert document["output_root"] == str(
        values["data_home"] / "state/jaa-production-preparations"
    )
    assert document["recruiter_archive_root"] == str(
        values["data_home"] / "state/jaa-production-recruiter-diagnostics"
    )
    assert document["contact_envelope_sha256"] == (
        preparation_runner.PRODUCTION_CONTACT_ENVELOPE_SHA256
    )
    assert document["poppler_sha256"] == preparation_runner.PRODUCTION_POPPLER_SHA256


def test_preparation_config_cli_rejects_partial_host_paths(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        installer.main(
            ["--print-preparation-config", "--preparation-data-home", "/tmp/ma-state"]
        )
    assert raised.value.code == 2
    assert "all nine" in capsys.readouterr().err
