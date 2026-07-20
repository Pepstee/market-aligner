"""Adversarial tests for the public test-evidence receipt generator."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPOSITORY = Path(__file__).resolve().parent
GENERATOR = REPOSITORY / "scripts" / "generate-test-evidence.py"


def _generator_module():
    spec = importlib.util.spec_from_file_location("test_evidence_generator", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR_MODULE = _generator_module()


def _identity_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "identity-repository"
    root.mkdir()
    (root / "product.txt").write_bytes(b"product\n")
    subprocess.run(("git", "init", "-q"), cwd=root, check=True)
    subprocess.run(("git", "add", "product.txt"), cwd=root, check=True)
    subprocess.run(
        ("git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "product snapshot"), cwd=root, check=True,
    )
    monkeypatch.setattr(GENERATOR_MODULE, "ROOT", root)
    return root


def _public_repository(
    tmp_path: Path, complete_output: str, career_output: str,
    complete_status: int = 0, career_status: int = 0,
) -> Path:
    """Execute an unmodified copy through its documented script entry point."""
    root = tmp_path / "isolated-repository"
    script = root / "scripts" / GENERATOR.name
    script.parent.mkdir(parents=True)
    shutil.copy2(GENERATOR, script)
    requirements = []
    for line in (REPOSITORY / "requirements-test.lock").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            distribution = line.split("==", 1)[0]
            requirements.append(f"{distribution}=={importlib.metadata.version(distribution)}")
    (root / "requirements-test.lock").write_text("\n".join(requirements) + "\n", encoding="utf-8")
    (root / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    (root / "pytest.py").write_text(
        "import sys\n"
        f"career = {career_output!r}\n"
        f"complete = {complete_output!r}\n"
        "print(career if 'career_automation' in sys.argv else complete)\n"
        f"raise SystemExit({career_status} if 'career_automation' in sys.argv else {complete_status})\n",
        encoding="utf-8",
    )
    subprocess.run(("git", "init", "-q"), cwd=root, check=True)
    subprocess.run(
        ("git", "add", ".gitignore", "scripts", "pytest.py", "requirements-test.lock"),
        cwd=root, check=True,
    )
    subprocess.run(
        (
            "git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", "product snapshot",
        ),
        cwd=root,
        check=True,
    )
    return root


def _run_public_generator(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, str(root / "scripts" / GENERATOR.name)), cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def _public_generator(
    tmp_path: Path, complete_output: str, career_output: str
) -> subprocess.CompletedProcess[str]:
    root = _public_repository(tmp_path, complete_output, career_output)
    return _run_public_generator(root)


def _commit(root: Path, message: str) -> None:
    subprocess.run(("git", "add", "."), cwd=root, check=True)
    subprocess.run(
        ("git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", message), cwd=root, check=True,
    )


def _receipt_revision(completed: subprocess.CompletedProcess[str], root: Path) -> str:
    assert completed.returncode == 0, completed.stderr
    return json.loads((root / completed.stdout.strip()).read_text(encoding="utf-8"))["tested_product_content_revision"]


def test_parse_summary_requires_exact_supported_totals() -> None:
    assert GENERATOR_MODULE.parse_summary("================ 12 passed, 3 skipped in 0.42s ================\n") == {
        "collected": 15, "passed": 12, "skipped": 3, "failed": 0,
    }


@pytest.mark.parametrize("output", [
    "================ 1 failed, 4 passed in 0.01s ================\n",
    "pytest output without a final summary\n",
    "================ 4 passed, 1 xfailed in 0.01s ================\n",
])
def test_parse_summary_refuses_failed_or_malformed_output(output: str) -> None:
    with pytest.raises(GENERATOR_MODULE.EvidenceError):
        GENERATOR_MODULE.parse_summary(output)


def test_suite_executes_current_interpreter_but_records_portable_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def fake_run(command, **_kwargs):
        observed.extend(command)
        return subprocess.CompletedProcess(command, 0, "==== 3 passed in 0.01s ====\n")

    monkeypatch.setattr(GENERATOR_MODULE.subprocess, "run", fake_run)
    result = GENERATOR_MODULE.run_suite("complete", GENERATOR_MODULE.COMPLETE_ARGV)
    assert observed == [sys.executable, "-m", "pytest", "-q"]
    assert result["argv"] == ["python", "-m", "pytest", "-q"]
    assert sys.executable not in result["argv"]


def test_receipt_argv_has_no_environment_path_and_reexecutes_from_path(
    tmp_path: Path,
) -> None:
    """A consumer can run the recorded command after activating the locked environment."""
    completed = _public_generator(
        tmp_path,
        "================ 4 passed in 0.01s ================",
        "================ 2 passed in 0.01s ================",
    )
    root = tmp_path / "isolated-repository"
    receipt = json.loads((root / completed.stdout.strip()).read_text(encoding="utf-8"))

    locked_bin = tmp_path / "locked-cpython-312" / "bin"
    locked_bin.mkdir(parents=True)
    (locked_bin / "python").symlink_to(sys.executable)
    environment = {**os.environ, "PATH": str(locked_bin) + os.pathsep + os.environ["PATH"]}

    for suite in receipt["suites"]:
        argv = suite["argv"]
        assert all(".venv" not in argument for argument in argv)
        assert all(not Path(argument).is_absolute() for argument in argv)
        reexecuted = subprocess.run(
            argv, cwd=root, env=environment, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        assert reexecuted.returncode == 0, reexecuted.stderr


def test_environment_validation_reports_missing_locked_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / "requirements-test.lock"
    lock.write_text("definitely-absent-distribution==1.0\n", encoding="utf-8")
    monkeypatch.setattr(GENERATOR_MODULE, "LOCK_FILE", lock)
    with pytest.raises(GENERATOR_MODULE.EvidenceError, match="missing:.*bootstrap-test-env"):
        GENERATOR_MODULE.locked_environment()


def test_missing_openpyxl_rejects_environment_before_a_stale_suite_can_pass(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    original_version = importlib.metadata.version
    suite_was_run = False

    def missing_openpyxl(distribution: str) -> str:
        if distribution == "openpyxl":
            raise importlib.metadata.PackageNotFoundError(distribution)
        return original_version(distribution)

    def stale_success(*_args, **_kwargs):
        nonlocal suite_was_run
        suite_was_run = True
        return {"name": "stale", "argv": [], "counts": {}}

    monkeypatch.setattr(GENERATOR_MODULE.importlib.metadata, "version", missing_openpyxl)
    monkeypatch.setattr(GENERATOR_MODULE, "product_content_revision", lambda: "sha256:stable")
    monkeypatch.setattr(GENERATOR_MODULE, "tested_git_parent", lambda: "a" * 40)
    monkeypatch.setattr(GENERATOR_MODULE, "run_suite", stale_success)

    assert GENERATOR_MODULE.main() == 1
    assert suite_was_run is False
    assert "locked test dependencies are unavailable (missing: openpyxl" in capsys.readouterr().err


def test_product_revision_is_stable_across_excluded_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _identity_repository(tmp_path, monkeypatch)
    revision = GENERATOR_MODULE.product_content_revision()
    receipt = root / "runtime_evidence" / "pytest" / "receipt.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text("{}\n", encoding="utf-8")
    subprocess.run(("git", "add", "-f", str(receipt.relative_to(root))), cwd=root, check=True)
    assert GENERATOR_MODULE.product_content_revision() == revision


def test_public_script_content_revision_changes_for_every_product_content_class(
    tmp_path: Path,
) -> None:
    """Only pytest receipts are outside the content-addressed product identity."""
    root = _public_repository(
        tmp_path,
        "================ 4 passed in 0.01s ================",
        "================ 2 passed in 0.01s ================",
    )
    product_files = {
        "feature.py": "VALUE = 1\n",
        "test_feature.py": "def test_placeholder(): pass\n",
        "settings.yaml": "enabled: true\n",
        "docs/guide.md": "# Guide\n",
    }
    for relative, content in product_files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _commit(root, "add product classes")

    revisions = [_receipt_revision(_run_public_generator(root), root)]
    for index, relative in enumerate(product_files, start=2):
        path = root / relative
        path.write_text(path.read_text(encoding="utf-8") + f"# change {index}\n", encoding="utf-8")
        _commit(root, f"change {relative}")
        revisions.append(_receipt_revision(_run_public_generator(root), root))

    executable = root / "feature.py"
    executable.chmod(0o755)
    _commit(root, "make feature executable")
    revisions.append(_receipt_revision(_run_public_generator(root), root))
    assert len(set(revisions)) == len(revisions)

    sidecar = root / "runtime_evidence" / "pytest" / "manual-receipt.json"
    sidecar.write_text('{"first": true}\n', encoding="utf-8")
    unchanged = _receipt_revision(_run_public_generator(root), root)
    sidecar.write_text('{"second": true}\n', encoding="utf-8")
    assert _receipt_revision(_run_public_generator(root), root) == unchanged


@pytest.mark.parametrize("condition", ["dirty", "untracked", "missing", "symlink"])
def test_product_revision_refuses_incomplete_or_unsafe_trees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, condition: str
) -> None:
    root = _identity_repository(tmp_path, monkeypatch)
    product = root / "product.txt"
    if condition == "dirty":
        product.write_bytes(b"changed\n")
    elif condition == "untracked":
        (root / "new-product.py").write_bytes(b"print('untracked')\n")
    elif condition == "missing":
        product.unlink()
    else:
        product.unlink()
        product.symlink_to("target.txt")
    with pytest.raises(GENERATOR_MODULE.EvidenceError):
        GENERATOR_MODULE.product_content_revision()


@pytest.mark.parametrize("condition", ["dirty", "untracked_executable", "path", "mode"])
def test_public_script_refuses_dirty_executable_and_path_mode_ambiguity(
    tmp_path: Path, condition: str
) -> None:
    root = _public_repository(
        tmp_path,
        "================ 4 passed in 0.01s ================",
        "================ 2 passed in 0.01s ================",
    )
    product = root / "scripts" / GENERATOR.name
    if condition == "dirty":
        product.write_text(product.read_text(encoding="utf-8") + "\n# dirty\n", encoding="utf-8")
    elif condition == "untracked_executable":
        executable = root / "unexpected-product-executable"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
    elif condition == "path":
        path_ambiguous = root / ".gitignore"
        path_ambiguous.unlink()
        path_ambiguous.symlink_to("alternate-ignore")
    else:
        product.chmod(0o644)

    completed = _run_public_generator(root)
    assert completed.returncode == 1
    assert "test evidence rejected:" in completed.stderr
    assert not (root / "runtime_evidence" / "pytest").exists()


def test_public_script_writes_hashed_content_revision_bound_and_redacted_receipt(
    tmp_path: Path,
) -> None:
    private_path = "/Users/receipt-test-user/private-worktree"
    secret = "TOP-SECRET-RECEIPT-TOKEN"
    completed = _public_generator(
        tmp_path,
        f"runner diagnostic: {private_path} token={secret}\n"
        "================ 70 passed, 5 skipped in 0.10s ================",
        "================ 65 passed in 0.05s ================",
    )
    assert completed.returncode == 0, completed.stderr
    root = tmp_path / "isolated-repository"
    receipt = root / completed.stdout.strip()
    payload = receipt.read_bytes()
    document = json.loads(payload)

    assert receipt.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", document["tested_product_content_revision"])
    assert re.fullmatch(r"[0-9a-f]{40,64}", document["tested_git_parent"])
    assert "tested_source_revision" not in document
    assert document["schema_version"] == 3
    assert document["interpreter"] == {
        "implementation": "CPython", "version": GENERATOR_MODULE.platform.python_version()
    }
    assert document["dependency_lock"]["path"] == "requirements-test.lock"
    assert re.fullmatch(r"[0-9a-f]{64}", document["dependency_lock"]["sha256"])
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", document["environment_identity"])
    complete, career = document["suites"]
    assert complete["name"] == "complete"
    assert complete["argv"] == ["python", "-m", "pytest", "-q"]
    assert complete["counts"] == {"collected": 75, "passed": 70, "skipped": 5, "failed": 0}
    assert "historical_baseline_passed" not in complete
    assert career["name"] == "career_automation"
    assert career["argv"] == ["python", "-m", "pytest", "-q", "career_automation"]
    assert career["counts"] == {"collected": 65, "passed": 65, "skipped": 0, "failed": 0}
    assert career["historical_baseline_passed"] == 65
    rendered = payload.decode("utf-8")
    assert str(Path.home()) not in rendered
    assert private_path not in rendered
    assert secret not in rendered
    assert sys.executable not in rendered


@pytest.mark.parametrize("suite, output", [
    ("complete", "================ 1 failed, 4 passed in 0.01s ================"),
    ("complete", "not a pytest summary"),
    ("complete", "================ 4 passed, 1 xfailed in 0.01s ================"),
    ("career", "================ 1 failed, 4 passed in 0.01s ================"),
    ("career", "not a pytest summary"),
    ("career", "================ 4 passed, 1 xfailed in 0.01s ================"),
])
def test_public_script_refuses_every_failing_or_malformed_suite_without_receipt(
    tmp_path: Path, suite: str, output: str
) -> None:
    good = "================ 65 passed in 0.01s ================"
    completed = _public_generator(
        tmp_path, output if suite == "complete" else good, output if suite == "career" else good,
    )
    assert completed.returncode == 1
    assert "test evidence rejected:" in completed.stderr
    evidence_directory = tmp_path / "isolated-repository" / "runtime_evidence"
    assert not evidence_directory.exists() or not list(evidence_directory.rglob("*.json"))


@pytest.mark.parametrize("suite", ["complete", "career"])
def test_public_script_refuses_nonzero_exit_from_each_suite(tmp_path: Path, suite: str) -> None:
    root = _public_repository(
        tmp_path,
        "================ 4 passed in 0.01s ================",
        "================ 2 passed in 0.01s ================",
        complete_status=9 if suite == "complete" else 0,
        career_status=9 if suite == "career" else 0,
    )
    completed = _run_public_generator(root)
    assert completed.returncode == 1
    assert "suite exited with status 9" in completed.stderr
    assert not (root / "runtime_evidence" / "pytest").exists()
