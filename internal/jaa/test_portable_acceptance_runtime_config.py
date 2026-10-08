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


def test_current_greenhouse_scope_is_separate_and_records_one_local_canary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    runner = _load_runner(monkeypatch)
    binding = {"source": {"head": "a" * 40}, "runtime": {"python": "fixture"}}
    monkeypatch.setattr(runner, "_execution_binding", lambda: binding)
    monkeypatch.setattr(runner, "OUTPUT_PARENT", tmp_path)
    monkeypatch.setattr(
        runner,
        "load_runtime_config",
        lambda *_args, **_kwargs: pytest.fail("current scope must not load historical config"),
    )
    monkeypatch.setattr(
        runner,
        "default_config_path",
        lambda: pytest.fail("current scope must not inspect historical config"),
    )
    monkeypatch.setattr(
        runner.sys,
        "argv",
        [str(RUNNER), "--scope", "current-greenhouse-mvp"],
    )
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def successful_native_result(basetemp: Path) -> None:
        destination = basetemp / "test_native_prepare_release_one_call_local_diagnostic0"
        destination.mkdir(parents=True)
        document = {
            "status": "prepared_no_submit",
            "attempt_id": "synthetic-attempt",
            "provider_dispatches": 1,
            "provider_responses": 1,
            "provider_response_capture_status": "written",
            "provider_response_sha256": "b" * 64,
            "sanity_receipt_sha256": "c" * 64,
            "native_fill_returned": True,
            "prepared_returned": True,
            "attempt_finalized": True,
            "external_network_requests": 0,
            "intercepted_post_attempts": 0,
            "external_submission": 0,
            "terminal_archive_roles": ["submission.result"],
            "default_production_verifier_rejected_actual_diagnostic_receipt": True,
        }
        runner._write_private(
            destination / "safe-result.json",
            (json.dumps(document, sort_keys=True) + "\n").encode(),
        )

    def observe(command, **kwargs):
        argv = tuple(command)
        calls.append((argv, kwargs))
        environment = kwargs["env"]
        assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
        assert environment["PYTHONPATH"] == os.pathsep.join(
            (str(runner.PROJECT_ROOT / "src"), str(runner.ROOT))
        )
        assert kwargs["cwd"] == runner.ROOT
        if runner.CURRENT_MVP_NATIVE_TEST in argv:
            assert environment["MA_RUN_NATIVE_BROWSER_DIAGNOSTIC"] == "1"
            successful_native_result(Path(argv[argv.index("--basetemp") + 1]))
            output = "1 passed in 0.1s\n"
        else:
            assert "MA_RUN_NATIVE_BROWSER_DIAGNOSTIC" not in environment
            assert all(node in argv for node in runner.CURRENT_MVP_FUNCTIONAL_TESTS)
            output = "19 passed in 0.1s\n"
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

    monkeypatch.setattr(runner.subprocess, "run", observe)
    assert runner.main() == 0
    assert len(calls) == 2
    assert runner.CURRENT_MVP_NATIVE_TEST in calls[1][0]
    assert "recertify-sources" not in calls[0][0]
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "current_functional_scope_pass_historical_unproven"
    assert summary["historical_certification"] == "unproven_not_run"
    assert summary["external_application"] == "not_performed"
    assert summary["release_claim"] is False
    evidence = Path(summary["evidence_directory"])
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o700
    record = json.loads((evidence / "result.json").read_text(encoding="utf-8"))
    assert [entry["exit_code"] for entry in record["commands"]] == [0, 0]
    assert record["commands"][1]["native_result"]["provider_dispatches"] == 1
    for name in (
        "argv.json",
        "functional.stdout.log",
        "functional.stderr.log",
        "native.stdout.log",
        "native.stderr.log",
        "result.json",
    ):
        assert stat.S_IMODE((evidence / name).stat().st_mode) == 0o600


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


@pytest.mark.parametrize("missing_parent", [False, True])
def test_runner_reports_missing_config_with_setup_guidance(
    tmp_path: Path, missing_parent: bool,
) -> None:
    config_parent = tmp_path / "config"
    if not missing_parent:
        config_parent.mkdir()
    config = config_parent / "runtime.json"
    result = subprocess.run(
        [sys.executable, str(RUNNER), "--config", str(config)],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 2
    assert "runtime config is absent; create it with" in result.stderr
    assert "No such file or directory" not in result.stderr


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


def test_acceptance_declaration_commands_are_independent_and_direct_execution_is_portable(
    tmp_path: Path,
) -> None:
    lines = [line.strip() for line in (ROOT / "acceptance").read_text(encoding="utf-8").splitlines()]
    commands = [line for line in lines if line and not line.startswith("#")]
    assert len(commands) == 1
    assert "scripts/run_acceptance_declaration.py" in commands[0]
    assert commands[0].startswith("if [ -f scripts/run_acceptance_declaration.py ]")
    assert "BASH_SOURCE" in commands[0] and commands[0].endswith("; fi")
    assert all("-c" not in command and "$0" not in command for command in commands)

    # Run every extracted record independently.  A tiny isolated runner keeps
    # this test about declaration execution and path resolution, rather than
    # requiring private commercial runtime credentials.
    project = tmp_path / "project"
    scripts = project / "scripts"
    scripts.mkdir(parents=True)
    declaration = project / "acceptance"
    declaration.write_text((ROOT / "acceptance").read_text(encoding="utf-8"), encoding="utf-8")
    declaration.chmod(0o755)
    (scripts / "run_acceptance_declaration.py").write_text(
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    for command in commands:
        extracted = subprocess.run(
            ["bash", "-c", command], cwd=project, text=True, capture_output=True, check=False,
        )
        assert extracted.returncode == 0, extracted.stdout + extracted.stderr

    direct = subprocess.run(
        [str(declaration)], cwd=tmp_path, text=True, capture_output=True, check=False,
    )
    assert direct.returncode == 0, direct.stdout + direct.stderr
