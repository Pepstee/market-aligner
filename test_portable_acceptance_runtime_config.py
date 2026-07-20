"""Black-box acceptance tests for portable private runtime configuration.

These tests deliberately never execute the runner's final recursive pytest
stage.  Configuration validation is exercised through its public scripts and
the runner boundary is observed with only ``subprocess.run`` replaced.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent
CONFIGURER = ROOT / "scripts" / "configure_acceptance.py"
RUNNER = ROOT / "scripts" / "run_acceptance.py"
LEGACY_PATH_VARIABLES = (
    "JAA_ORIGINAL_SOURCE_ROOT",
    "JAA_RECERTIFICATION_EVIDENCE_DIR",
)


def _source_root(tmp_path: Path) -> Path:
    """Create only the two regular source database files the contract needs."""
    source = tmp_path / "preserved-source"
    for relative in (
        Path("scraper/data_overnight/jobs.sqlite3"),
        Path("outputs/career_automation/career_pipeline.sqlite3"),
    ):
        database = source / relative
        database.parent.mkdir(parents=True, exist_ok=True)
        database.write_bytes(b"SQLite format 3\x00")
    return source


def _configure(
    source: Path, evidence: Path, *, environment: dict[str, str], config: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(CONFIGURER),
        "--original-source-root",
        str(source),
        "--recertification-evidence-directory",
        str(evidence),
    ]
    if config is not None:
        command.extend(("--config", str(config)))
    return subprocess.run(command, cwd=ROOT, env=environment, text=True, capture_output=True, check=False)


def _private_environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["XDG_CONFIG_HOME"] = str(tmp_path / "xdg")
    environment["HOME"] = str(tmp_path / "home")
    for name in LEGACY_PATH_VARIABLES:
        environment.pop(name, None)
    return environment


def _load_runner(monkeypatch: pytest.MonkeyPatch):
    """Load an isolated runner module while retaining its public implementation."""
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    name = "portable_acceptance_runner_under_test"
    spec = importlib.util.spec_from_file_location(name, RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_default_config_is_mode_0600_atomic_publication_and_override_is_deterministic(
    tmp_path: Path,
) -> None:
    environment = _private_environment(tmp_path)
    source = _source_root(tmp_path)
    evidence = tmp_path / "new-evidence"

    published = _configure(source, evidence, environment=environment)
    assert published.returncode == 0, published.stderr
    default = Path(environment["XDG_CONFIG_HOME"]) / "market-aligner" / "runtime.json"
    assert default.is_file()
    assert stat.S_IMODE(default.stat().st_mode) == 0o600
    assert json.loads(default.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "original_source_root": str(source),
        "recertification_evidence_directory": str(evidence),
    }
    # Publication leaves neither an incomplete destination nor a temporary file.
    assert not list(default.parent.glob(".runtime-*"))

    override = tmp_path / "override" / "runtime.json"
    override_evidence = tmp_path / "override-evidence"
    overridden = _configure(source, override_evidence, environment=environment, config=override)
    assert overridden.returncode == 0, overridden.stderr
    assert stat.S_IMODE(override.stat().st_mode) == 0o600
    assert json.loads(default.read_text(encoding="utf-8"))["recertification_evidence_directory"] == str(evidence)
    assert json.loads(override.read_text(encoding="utf-8"))["recertification_evidence_directory"] == str(override_evidence)


def test_runner_uses_default_without_legacy_variables_and_only_recertifier_gets_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _private_environment(tmp_path)
    source = _source_root(tmp_path)
    evidence = tmp_path / "evidence"
    assert _configure(source, evidence, environment=environment).returncode == 0
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    for name in LEGACY_PATH_VARIABLES:
        monkeypatch.delenv(name, raising=False)

    runner = _load_runner(monkeypatch)
    calls: list[tuple[str, ...]] = []

    def observe(command: tuple[str, ...], **_kwargs: object):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(runner.subprocess, "run", observe)
    monkeypatch.setattr(sys, "argv", [str(RUNNER)])
    assert runner.main() == 0
    assert calls == [
        (sys.executable, "-m", "baseline_adoption.cli", "recertify-sources", "--source-root", str(source),
         "--evidence-directory", str(evidence)),
        (sys.executable, "scripts/accept_jaa_01c.py"),
        (sys.executable, "-m", "pytest", "-q", "career_automation/test_jaa_01e_lifecycle_no_bypass.py"),
        (sys.executable, "scripts/reproduce_jaa01_terra_rejection.py"),
        (sys.executable, "-m", "pytest", "-q"),
    ]
    assert all(str(source) not in command and str(evidence) not in command for command in calls[1:])


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        ("{", "cannot load runtime config"),
        (json.dumps({"schema_version": 1}), "runtime config must contain only"),
        (json.dumps({"schema_version": 2, "original_source_root": "/x", "recertification_evidence_directory": "/y"}), "unsupported runtime config schema_version"),
        (json.dumps({"schema_version": 1, "original_source_root": 1, "recertification_evidence_directory": "/y"}), "runtime config paths must be strings"),
    ],
)
def test_runner_rejects_malformed_config_before_acceptance_stages(
    tmp_path: Path, document: str, reason: str,
) -> None:
    config = tmp_path / "runtime.json"
    config.write_text(document, encoding="utf-8")
    config.chmod(0o600)
    result = subprocess.run(
        [sys.executable, str(RUNNER), "--config", str(config)],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 2
    assert reason in result.stderr


@pytest.mark.parametrize(
    ("source_value", "evidence_value", "message"),
    [
        ("relative-source", "/tmp/evidence", "original_source_root must be an absolute path"),
        ("SOURCE", "relative-evidence", "recertification_evidence_directory must be an absolute path"),
        ("SOURCE", "EVIDENCE", "expected source database"),
    ],
)
def test_configurer_rejects_relative_and_missing_database_inputs_without_evidence(
    tmp_path: Path, source_value: str, evidence_value: str, message: str,
) -> None:
    environment = _private_environment(tmp_path)
    source = _source_root(tmp_path)
    evidence = tmp_path / "must-remain-unwritten"
    selected_source = source if source_value == "SOURCE" else Path(source_value)
    selected_evidence = evidence if evidence_value == "EVIDENCE" else Path(evidence_value)
    if message == "expected source database":
        (source / "scraper/data_overnight/jobs.sqlite3").unlink()
    result = _configure(selected_source, selected_evidence, environment=environment)
    assert result.returncode == 2
    assert message in result.stderr
    assert not evidence.exists()


def test_configurer_rejects_symlink_overlap_and_repository_evidence_before_writing(
    tmp_path: Path,
) -> None:
    environment = _private_environment(tmp_path)
    source = _source_root(tmp_path)
    target = tmp_path / "real-evidence"
    target.mkdir()
    link = tmp_path / "linked-evidence"
    link.symlink_to(target, target_is_directory=True)

    symlinked = _configure(source, link, environment=environment)
    assert symlinked.returncode == 2
    assert "must not contain symlinks" in symlinked.stderr
    assert list(target.iterdir()) == []

    overlapping = _configure(source, source / "evidence", environment=environment)
    assert overlapping.returncode == 2
    assert "must not overlap the preserved source" in overlapping.stderr
    assert not (source / "evidence").exists()

    repository_evidence = ROOT / "runtime_evidence"
    contained = _configure(source, repository_evidence, environment=environment)
    assert contained.returncode == 2
    assert "must not overlap the product repository" in contained.stderr


def test_acceptance_declaration_commands_are_independent_and_direct_execution_fails_closed() -> None:
    lines = [line.strip() for line in (ROOT / "acceptance").read_text(encoding="utf-8").splitlines()]
    commands = [line for line in lines if line and not line.startswith("#")]
    assert commands == [
        'python3 "$(test -n "${BASH_SOURCE:-}" && dirname "${BASH_SOURCE}" || pwd)/scripts/run_acceptance.py" || exit $?',
        'python3 "$(test -n "${BASH_SOURCE:-}" && dirname "${BASH_SOURCE}" || pwd)/scripts/accept_jaa_02.py" || exit $?',
        'python3 "$(test -n "${BASH_SOURCE:-}" && dirname "${BASH_SOURCE}" || pwd)/scripts/accept_jaa02_receipt.py" || exit $?',
    ]
