from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from career_automation import production_handoff_runner as runner

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


def test_print_config_cli_is_byte_exact(capsys) -> None:
    assert installer.main(["--print-config"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert (
        captured.out.encode()
        == runner.production_handoff_deployment_configuration_bytes()
    )
