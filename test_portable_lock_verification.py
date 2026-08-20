"""Fast contract tests for portable locked-test-environment verification.

These tests deliberately exercise the verifier against real import metadata.  A
clean bootstrap belongs to the runtime validation command, not this pytest
suite, so this module never creates or installs a virtual environment.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent
GENERATOR = ROOT / "scripts" / "generate-test-evidence.py"
BOOTSTRAP = ROOT / "scripts" / "bootstrap-test-env.sh"


def _generator_module():
    spec = importlib.util.spec_from_file_location("portable_lock_generator", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = _generator_module()


def _lock(tmp_path: Path, contents: str, monkeypatch: pytest.MonkeyPatch) -> None:
    lock = tmp_path / "requirements-test.lock"
    lock.write_text(contents, encoding="utf-8")
    monkeypatch.setattr(VERIFIER, "LOCK_FILE", lock)


def test_locked_environment_accepts_the_exact_real_installed_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The public verifier compares installed versions exactly, not by range."""
    installed = importlib.metadata.version("pytest")
    _lock(tmp_path, f"pytest=={installed}\n", monkeypatch)

    environment = VERIFIER.locked_environment()

    assert environment["dependency_lock"]["path"] == "requirements-test.lock"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", environment["environment_identity"])


@pytest.mark.parametrize(
    "contents, error",
    [
        ("pytest>=9\n", "unsupported unlocked requirement"),
        ("pytest==\n", "unsupported unlocked requirement"),
        ("pytest==1\nPyTest==1\n", "duplicate locked requirement"),
        ("pytest==1\nPYTEST==2\n", "conflicting locked requirement"),
    ],
)
def test_locked_environment_refuses_unportable_or_ambiguous_lock_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contents: str, error: str
) -> None:
    _lock(tmp_path, contents, monkeypatch)

    with pytest.raises(VERIFIER.EvidenceError, match=error):
        VERIFIER.locked_environment()


def test_locked_environment_reports_a_missing_real_distribution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _lock(tmp_path, "not-installed-for-portable-lock-test==1.0\n", monkeypatch)

    with pytest.raises(VERIFIER.EvidenceError, match="missing: not-installed-for-portable-lock-test"):
        VERIFIER.locked_environment()


def test_locked_environment_reports_an_exact_version_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed = importlib.metadata.version("pytest")
    wrong = "0.0.0" if installed != "0.0.0" else "0.0.1"
    _lock(tmp_path, f"pytest=={wrong}\n", monkeypatch)

    with pytest.raises(VERIFIER.EvidenceError, match=rf"wrong versions: pytest=={re.escape(installed)}"):
        VERIFIER.locked_environment()


def test_locked_environment_reports_conflicting_installed_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed = importlib.metadata.version("pytest")
    conflicting = tmp_path / "PyTest-999.dist-info"
    conflicting.mkdir()
    (conflicting / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: PyTest\nVersion: 999\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    _lock(tmp_path, f"pytest=={installed}\n", monkeypatch)

    with pytest.raises(VERIFIER.EvidenceError, match=r"extra conflicting versions: pytest: 999"):
        VERIFIER.locked_environment()


def test_locked_environment_refuses_an_import_from_another_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    foreign = tmp_path / "foreign_project"
    foreign.mkdir()
    (foreign / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(VERIFIER, "LOCAL_IMPORT", "foreign_project")
    _lock(tmp_path, f"pytest=={importlib.metadata.version('pytest')}\n", monkeypatch)

    with pytest.raises(VERIFIER.EvidenceError, match="does not resolve to this repository"):
        VERIFIER.locked_environment()


def test_bootstrap_constructs_only_relative_locked_install_arguments() -> None:
    """The bootstrap remains portable; it is never run from pytest."""
    script = BOOTSTRAP.read_text(encoding="utf-8")
    pip_commands = [line.strip() for line in script.splitlines() if ' -m pip install ' in line]

    assert '"$TEST_PYTHON" -m pip install --no-build-isolation --requirement requirements-test.lock' in pip_commands
    assert '"$TEST_PYTHON" -m pip install --no-build-isolation --no-deps --editable .' in pip_commands
    assert all("$REPOSITORY_ROOT" not in command for command in pip_commands)
    assert all(not re.search(r"(?:^|[ =])/(?:Users|home)/", command) for command in pip_commands)
    assert all("~/" not in command and "$HOME" not in command for command in pip_commands)
