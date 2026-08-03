from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import run_jaa_certification_profile as runner


def _fake_document(test_names: list[str]) -> dict[str, object]:
    return {
        "schema_version": "test.profile.v1",
        "profile_sha256": "a" * 64,
        "applicable_tests": test_names,
        "claims": {
            "current_source_linux_execution_verified": False,
            "post_import_independent_certification_required": True,
        },
    }


def _patch_profile(
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
) -> None:
    hooks = [
        SimpleNamespace(evidence_id="jaa09_exact_corpus", root=Path("/corpus")),
        SimpleNamespace(
            evidence_id="jaa10_external_control", root=Path("/controls")
        ),
    ]
    monkeypatch.setattr(runner.profile, "load_evidence_config", lambda _path: hooks)
    monkeypatch.setattr(
        runner.profile,
        "build_profile",
        lambda _repository_root, _hooks: document,
    )
    monkeypatch.setattr(
        runner.profile,
        "selection_receipt",
        lambda _document: {"schema_version": "test.selection.v1"},
    )
    monkeypatch.setattr(
        runner.profile,
        "bind_execution_results",
        lambda _document, outcomes: {
            "schema_version": "test.execution.v1",
            "outcomes": outcomes,
        },
    )


def test_execute_records_passed_test_and_binds_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test_file = tmp_path / "test_pass.py"
    test_file.write_text("def test_pass():\n    assert True\n", encoding="utf-8")
    document = _fake_document([test_file.name])
    _patch_profile(monkeypatch, document)

    bundle, all_passed = runner.execute(
        repository_root=tmp_path,
        evidence_config=tmp_path / "unused.json",
        output_directory=tmp_path / "run",
        python_executable=Path(sys.executable).resolve(),
        timeout_seconds=30,
    )

    assert all_passed is True
    assert bundle["runs"][0]["status"] == "passed"
    assert bundle["execution_receipt"] is not None
    assert bundle["claims"]["product_certified"] is False
    persisted = json.loads((tmp_path / "run" / "run-bundle.json").read_text())
    assert persisted == bundle
    stdout = tmp_path / "run" / bundle["runs"][0]["stdout"]["path"]
    assert hashlib.sha256(stdout.read_bytes()).hexdigest() == bundle["runs"][0][
        "stdout"
    ]["sha256"]


def test_execute_records_failure_without_execution_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test_file = tmp_path / "test_fail.py"
    test_file.write_text("def test_fail():\n    assert False\n", encoding="utf-8")
    document = _fake_document([test_file.name])
    _patch_profile(monkeypatch, document)

    bundle, all_passed = runner.execute(
        repository_root=tmp_path,
        evidence_config=tmp_path / "unused.json",
        output_directory=tmp_path / "run",
        python_executable=Path(sys.executable).resolve(),
        timeout_seconds=30,
    )

    assert all_passed is False
    assert bundle["runs"][0]["status"] == "failed"
    assert bundle["execution_receipt"] is None


def test_executable_rejects_arbitrary_symlink(tmp_path: Path) -> None:
    link = tmp_path / "python"
    link.symlink_to(Path(sys.executable).resolve())
    with pytest.raises(
        runner.profile.CertificationProfileError, match="virtual-environment"
    ):
        runner._executable(link, tmp_path)


def test_executable_allows_and_binds_repository_venv_launcher(
    tmp_path: Path,
) -> None:
    bin_directory = tmp_path / ".venv" / "bin"
    bin_directory.mkdir(parents=True)
    link = bin_directory / "python"
    link.symlink_to(Path(sys.executable).resolve())
    launcher, identity = runner._executable(link, tmp_path)
    assert launcher == link
    assert identity["launcher_is_symlink"] is True
    assert identity["resolved_target"] == str(Path(sys.executable).resolve())
    assert len(identity["resolved_target_sha256"]) == 64
