"""Adversarial tests for the public test-evidence receipt generator."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

import test_jaa04_increment_a_certifier_fail_closed as inplace_fixture


REPOSITORY = Path(__file__).resolve().parent
GENERATOR = REPOSITORY / "scripts" / "generate-test-evidence.py"
GENERATOR_README_PATH = "internal/jaa/README.md"
GENERATOR_SOURCE_PATH = "internal/jaa/scripts/certify_jaa04_increment_a.py"
GENERATOR_TEST_PATH = "internal/jaa/test_jaa04_increment_a_authority_canaries.py"
GENERATOR_CONFIG_PATH = "internal/jaa/runtime_evidence/JAA-00-online-snapshot.yaml"
GENERATOR_UNTRACKED_EXECUTABLE_PATH = "internal/jaa/untracked-product-executable.py"
GENERATOR_RECEIPT_SIDECAR_PATH = inplace_fixture.TEST_EVIDENCE_RECEIPT_SIDECAR_PATH
GENERATOR_RECEIPT_SIDECAR_BASE = b'{"synthetic":"pytest-sidecar"}\n'
GENERATOR_RECEIPT_SIDECAR_CHANGED = GENERATOR_RECEIPT_SIDECAR_BASE + b" \n"


@dataclass(frozen=True)
class _CanonicalGeneratorRun:
    returncode: int
    stdout: str
    stderr: str
    receipt_path: str | None
    receipt_payload: bytes | None
    tested_git_parent: str
    runner_directory: Path


@dataclass(frozen=True)
class _CanonicalGeneratorSession:
    state: inplace_fixture._FixtureBranch
    python: Path | str
    runner_directory: Path
    environment: dict[str, str]


def _generator_module():
    spec = importlib.util.spec_from_file_location("test_evidence_generator", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR_MODULE = _generator_module()


def _write_scripted_pytest(
    directory: Path,
    complete_output: str,
    career_output: str,
    complete_status: int = 0,
    career_status: int = 0,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    runner = directory / "pytest.py"
    runner.write_text(
        "import json, os, sys\n"
        "from pathlib import Path\n"
        f"career = {career_output!r}\n"
        f"complete = {complete_output!r}\n"
        f"career_status = {career_status!r}\n"
        f"complete_status = {complete_status!r}\n"
        "arguments = sys.argv[1:]\n"
        "with (Path(__file__).parent / 'invocations.jsonl').open('a', encoding='utf-8') as stream:\n"
        "    stream.write(json.dumps({'argv': arguments, 'cwd': os.getcwd()}) + '\\n')\n"
        "print(career if 'career_automation' in arguments else complete)\n"
        "raise SystemExit(career_status if 'career_automation' in arguments else complete_status)\n",
        encoding="utf-8",
    )


def _generator_environment(
    python: Path | str,
    *,
    runner_directory: Path | None,
    use_pythonpath: bool = True,
) -> dict[str, str]:
    environment = {
        "PATH": os.pathsep.join(
            (str(Path(python).parent), "/usr/local/bin", "/usr/bin", "/bin")
        ),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_NO_INDEX": "1",
    }
    if runner_directory is not None and use_pythonpath:
        environment["PYTHONPATH"] = str(runner_directory)
    return environment


@contextmanager
def _canonical_public_cli_session(
    tmp_path: Path,
    complete_output: str,
    career_output: str,
    complete_status: int = 0,
    career_status: int = 0,
    *,
    python: Path | str = sys.executable,
    runner_directory: Path | None = None,
    use_pythonpath: bool = True,
    allowed_mutations: set[str] | frozenset[str] | None = None,
    commit_sequence: tuple[tuple[str, str], ...] | None = inplace_fixture.TEST_EVIDENCE_GENERATOR_COMMIT_SEQUENCE,
) -> Iterator[_CanonicalGeneratorSession]:
    if runner_directory is None:
        runner_directory = tmp_path / "scripted-test-runner"
        _write_scripted_pytest(
            runner_directory,
            complete_output,
            career_output,
            complete_status,
            career_status,
        )
    elif not (runner_directory / "pytest.py").is_file():
        raise AssertionError("scripted pytest runner is not present in the supplied environment")

    environment = _generator_environment(
        python,
        runner_directory=runner_directory,
        use_pythonpath=use_pythonpath,
    )
    if allowed_mutations is None:
        if commit_sequence is None:
            raise ValueError("unsequenced public CLI sessions require explicit mutation paths")
        allowed_mutations = {path for path, _operation in commit_sequence}

    with inplace_fixture._committed_inplace_branch(
        "test-evidence-cli",
        allowed_mutations=allowed_mutations,
        commit_sequence=commit_sequence,
    ) as state:
        original_readme = (REPOSITORY / "README.md").read_bytes()
        marker = f"\n<!-- test-evidence-cli:{uuid.uuid4().hex} -->\n"
        inplace_fixture._commit_mutation(
            state,
            GENERATOR_README_PATH,
            original_readme.decode("utf-8") + marker,
            "test-evidence-cli",
        )
        yield _CanonicalGeneratorSession(state, python, runner_directory, environment)


def _run_canonical_public_cli_in_session(
    session: _CanonicalGeneratorSession,
    *,
    expected_status: tuple[str, ...] = (),
    expected_sidecar: bytes | None = None,
) -> _CanonicalGeneratorRun:
    state = session.state
    runner_directory = session.runner_directory
    receipt_directory = REPOSITORY / "runtime_evidence" / "pytest"
    evidence_root = receipt_directory.parent
    receipt_directory_existed = receipt_directory.exists()
    evidence_root_existed = evidence_root.exists()
    expected_before = list(expected_status)
    sidecar_path: Path | None = None
    if expected_sidecar is not None:
        if expected_status or expected_sidecar not in {
            GENERATOR_RECEIPT_SIDECAR_BASE,
            GENERATOR_RECEIPT_SIDECAR_CHANGED,
        }:
            raise AssertionError("canonical generator sidecar is outside its exact fixture values")
        sidecar_path = REPOSITORY / Path(GENERATOR_RECEIPT_SIDECAR_PATH).relative_to(
            "internal/jaa"
        )
        sidecar_stat = sidecar_path.lstat()
        if (
            sidecar_path.parent.resolve() != receipt_directory.resolve()
            or any(parent.is_symlink() for parent in (evidence_root, receipt_directory))
            or not stat.S_ISREG(sidecar_stat.st_mode)
            or sidecar_path.is_symlink()
            or sidecar_stat.st_mode & 0o111
            or sidecar_path.read_bytes() != expected_sidecar
            or inplace_fixture._git_path_blob_sha256(
                state.head, GENERATOR_RECEIPT_SIDECAR_PATH
            ) != hashlib.sha256(GENERATOR_RECEIPT_SIDECAR_BASE).hexdigest()
            or inplace_fixture._git_path_mode(
                state.head, GENERATOR_RECEIPT_SIDECAR_PATH
            ) != "100644"
        ):
            raise AssertionError("canonical generator sidecar differs from its exact tracked fixture")
        expected_before = (
            []
            if expected_sidecar == GENERATOR_RECEIPT_SIDECAR_BASE
            else [f" M {GENERATOR_RECEIPT_SIDECAR_PATH}"]
        )
    if inplace_fixture._git("status", "--porcelain", "--untracked-files=all").splitlines() != expected_before:
        raise AssertionError("canonical generator session has unexpected project dirt")
    inplace_fixture._assert_admission(state.branch, state.head, bool(expected_before))
    completed = subprocess.run(
        (str(session.python), str(GENERATOR)),
        cwd=REPOSITORY,
        env=session.environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        if inplace_fixture._git("status", "--porcelain", "--untracked-files=all").splitlines() != expected_before:
            raise AssertionError("rejected generator run left unexpected repository changes")
        if sidecar_path is not None and sidecar_path.read_bytes() != expected_sidecar:
            raise AssertionError("rejected generator run changed the exact preserved sidecar")
        inplace_fixture._assert_admission(state.branch, state.head, bool(expected_before))
        return _CanonicalGeneratorRun(
            completed.returncode,
            completed.stdout,
            completed.stderr,
            None,
            None,
            state.head,
            runner_directory,
        )

    if expected_before and sidecar_path is None:
        raise AssertionError("successful generator run cannot retain fixture mutations")
    output_lines = completed.stdout.splitlines()
    if (
        len(output_lines) != 1
        or re.fullmatch(
            r"runtime_evidence/pytest/sha256-[0-9a-f]{64}\.json",
            output_lines[0],
        ) is None
    ):
        raise AssertionError("canonical generator returned an unexpected receipt path")
    receipt_relative_path = output_lines[0]
    receipt_path = REPOSITORY / receipt_relative_path
    if (
        receipt_path.parent.resolve() != receipt_directory.resolve()
        or any(parent.is_symlink() for parent in (receipt_path.parent, evidence_root))
        or not stat.S_ISREG(receipt_path.lstat().st_mode)
    ):
        raise AssertionError("canonical generator receipt is not a regular in-root file")
    receipt_payload = receipt_path.read_bytes()
    receipt_digest = hashlib.sha256(receipt_payload).hexdigest()
    receipt_repository_path = receipt_path.relative_to(
        inplace_fixture.REPOSITORY_ROOT
    ).as_posix()
    expected_after = [*expected_before, f"?? {receipt_repository_path}"]
    expected_after.sort(key=lambda row: row[3:])
    inplace_fixture._assert_admission(state.branch, state.head, True)
    actual_status_rows = inplace_fixture._git(
        "status", "--porcelain", "--untracked-files=all"
    ).splitlines()
    if (
        Path(receipt_relative_path).name != f"sha256-{receipt_digest}.json"
        or sorted(actual_status_rows) != sorted(expected_after)
    ):
        raise AssertionError("canonical generator receipt is not the sole exact runtime artifact")
    if sidecar_path is not None and sidecar_path.read_bytes() != expected_sidecar:
        raise AssertionError("canonical generator changed the exact preserved sidecar")

    inplace_fixture._assert_admission(state.branch, state.head, True)
    if (
        not receipt_path.is_file()
        or receipt_path.is_symlink()
        or hashlib.sha256(receipt_path.read_bytes()).hexdigest() != receipt_digest
    ):
        raise AssertionError("canonical generator receipt changed before exact cleanup")
    if sidecar_path is not None and sidecar_path.read_bytes() != expected_sidecar:
        raise AssertionError("canonical generator sidecar changed before receipt cleanup")
    receipt_path.unlink()
    if not receipt_directory_existed:
        if receipt_directory.is_symlink() or any(receipt_directory.iterdir()):
            raise AssertionError("new receipt directory contains an unowned artifact")
        inplace_fixture._assert_admission(state.branch, state.head, False)
        receipt_directory.rmdir()
    if not evidence_root_existed and evidence_root.is_dir() and not any(evidence_root.iterdir()):
        inplace_fixture._assert_admission(state.branch, state.head, False)
        evidence_root.rmdir()
    inplace_fixture._assert_admission(state.branch, state.head, bool(expected_before))
    if (
        inplace_fixture._git("status", "--porcelain", "--untracked-files=all").splitlines()
        != expected_before
    ):
        raise AssertionError("canonical generator receipt cleanup did not restore clean status")
    if sidecar_path is not None and sidecar_path.read_bytes() != expected_sidecar:
        raise AssertionError("canonical generator receipt cleanup changed the preserved sidecar")
    inplace_fixture._assert_admission(state.branch, state.head, bool(expected_before))
    return _CanonicalGeneratorRun(
        completed.returncode,
        completed.stdout,
        completed.stderr,
        receipt_relative_path,
        receipt_payload,
        state.head,
        runner_directory,
    )


def _run_canonical_public_cli(
    tmp_path: Path,
    complete_output: str,
    career_output: str,
    complete_status: int = 0,
    career_status: int = 0,
    *,
    python: Path | str = sys.executable,
    runner_directory: Path | None = None,
    use_pythonpath: bool = True,
) -> _CanonicalGeneratorRun:
    with _canonical_public_cli_session(
        tmp_path,
        complete_output,
        career_output,
        complete_status,
        career_status,
        python=python,
        runner_directory=runner_directory,
        use_pythonpath=use_pythonpath,
    ) as session:
        return _run_canonical_public_cli_in_session(session)


def test_canonical_public_cli_writes_a_bound_receipt_and_restores_clean_tree(
    tmp_path: Path,
) -> None:
    complete = "================ 4 passed in 0.01s ================"
    career = "================ 2 passed in 0.01s ================"
    run = _run_canonical_public_cli(tmp_path, complete, career)

    assert run.returncode == 0, run.stderr
    assert run.receipt_path is not None
    assert run.receipt_payload is not None
    assert run.stdout == f"{run.receipt_path}\n"
    receipt = json.loads(run.receipt_payload)
    assert receipt["tested_git_parent"] == run.tested_git_parent
    assert receipt["suites"] == [
        {
            "name": "complete",
            "argv": ["python", "-m", "pytest", "-q"],
            "counts": {"collected": 4, "passed": 4, "skipped": 0, "failed": 0},
        },
        {
            "name": "career_automation",
            "argv": ["python", "-m", "pytest", "-q", "career_automation"],
            "counts": {"collected": 2, "passed": 2, "skipped": 0, "failed": 0},
            "historical_baseline_passed": 65,
        },
    ]
    invocations = [
        json.loads(line)
        for line in (run.runner_directory / "invocations.jsonl").read_text().splitlines()
    ]
    assert invocations == [
        {"argv": ["-q"], "cwd": str(REPOSITORY)},
        {"argv": ["-q", "career_automation"], "cwd": str(REPOSITORY)},
    ]
    assert not (REPOSITORY / run.receipt_path).exists()


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


def _commit(root: Path, message: str) -> None:
    subprocess.run(("git", "add", "."), cwd=root, check=True)
    subprocess.run(
        ("git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", message), cwd=root, check=True,
    )


def test_parse_summary_requires_exact_supported_totals() -> None:
    assert GENERATOR_MODULE.parse_summary("================ 12 passed, 3 skipped in 0.42s ================\n") == {
        "collected": 15, "passed": 12, "skipped": 3, "failed": 0,
    }


def test_parse_summary_preserves_successful_subtests_without_inflating_collection() -> None:
    assert GENERATOR_MODULE.parse_summary(
        "================ 219 passed, 25 subtests passed in 1.23s ================\n"
    ) == {
        "collected": 219,
        "passed": 219,
        "skipped": 0,
        "failed": 0,
        "subtests_passed": 25,
    }


@pytest.mark.parametrize("output", [
    "================ 1 failed, 4 passed in 0.01s ================\n",
    "================ 1 error, 4 passed in 0.01s ================\n",
    "pytest output without a final summary\n",
    "================ 4 passed, 1 xfailed in 0.01s ================\n",
    "================ 4 passed, 1 mysterious in 0.01s ================\n",
    "================ 4 passed, 2 passed in 0.01s ================\n",
    "================ 4 passed, 1 subtests failed in 0.01s ================\n",
    "================ 4 passed, broken outcome in 0.01s ================\n",
    (
        "================ 4 passed in 0.01s ================\n"
        "================ 4 passed in 0.01s ================\n"
    ),
])
def test_parse_summary_refuses_failed_unknown_duplicate_or_ambiguous_output(
    output: str,
) -> None:
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


def test_public_generator_is_bytecode_hermetic_when_parent_opt_out_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public script must enforce its child bytecode boundary itself."""
    monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
    run = _run_canonical_public_cli(
        tmp_path,
        "================ 4 passed in 0.01s ================",
        "================ 2 passed in 0.01s ================",
    )

    assert run.returncode == 0, run.stderr
    assert not list(run.runner_directory.rglob("__pycache__"))
    assert not list(run.runner_directory.rglob("*.pyc"))


def test_receipt_argv_has_no_environment_path_and_reexecutes_from_path(
    tmp_path: Path,
) -> None:
    """A consumer can run the recorded command after activating the locked environment."""
    completed = _run_canonical_public_cli(
        tmp_path,
        "================ 4 passed in 0.01s ================",
        "================ 2 passed in 0.01s ================",
    )
    assert completed.receipt_payload is not None
    receipt = json.loads(completed.receipt_payload)

    locked_bin = tmp_path / "locked-cpython-312" / "bin"
    locked_bin.mkdir(parents=True)
    (locked_bin / "python").symlink_to(sys.executable)
    environment = {
        key: value for key, value in os.environ.items() if key != "PYTHONPATH"
    }
    environment.update(
        {
            "PATH": str(locked_bin) + os.pathsep + os.environ["PATH"],
            "PYTHONPATH": str(completed.runner_directory),
        }
    )

    for suite in receipt["suites"]:
        argv = suite["argv"]
        assert all(".venv" not in argument for argument in argv)
        assert all(not Path(argument).is_absolute() for argument in argv)
        reexecuted = subprocess.run(
            argv, cwd=REPOSITORY, env=environment, text=True, stdout=subprocess.PIPE,
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
    """Canonical CLI binds content classes and remains stable across generated receipts."""
    mutation_paths = frozenset(
        path for path, _operation in inplace_fixture.TEST_EVIDENCE_CONTENT_COMMIT_SEQUENCE
    )
    sidecar_directory = REPOSITORY / "runtime_evidence" / "pytest"
    sidecar_directory_created = False
    branch_restored = False
    session: _CanonicalGeneratorSession | None = None
    try:
        with _canonical_public_cli_session(
            tmp_path,
            "================ 4 passed in 0.01s ================",
            "================ 2 passed in 0.01s ================",
            allowed_mutations=mutation_paths,
            commit_sequence=inplace_fixture.TEST_EVIDENCE_CONTENT_COMMIT_SEQUENCE,
        ) as session:
            if (
                sidecar_directory.exists()
                or sidecar_directory.is_symlink()
                or sidecar_directory.parent.is_symlink()
            ):
                raise AssertionError("synthetic pytest sidecar directory already exists")
            inplace_fixture._assert_admission(session.state.branch, session.state.head, False)
            sidecar_directory.mkdir(mode=0o755)
            sidecar_directory_created = True
            inplace_fixture._assert_admission(session.state.branch, session.state.head, False)
            inplace_fixture._commit_added_file(
                session.state,
                GENERATOR_RECEIPT_SIDECAR_PATH,
                GENERATOR_RECEIPT_SIDECAR_BASE,
                "test-evidence-receipt-sidecar",
            )

            def revision_for_current_tree(sidecar: bytes) -> str:
                run = _run_canonical_public_cli_in_session(
                    session, expected_sidecar=sidecar
                )
                assert run.returncode == 0, run.stderr
                assert run.stderr == ""
                assert run.receipt_path is not None
                assert run.receipt_payload is not None
                assert run.stdout == f"{run.receipt_path}\n"
                document = json.loads(run.receipt_payload)
                assert document["tested_git_parent"] == session.state.head
                assert Path(run.receipt_path).name == (
                    f"sha256-{hashlib.sha256(run.receipt_payload).hexdigest()}.json"
                )
                assert not (REPOSITORY / run.receipt_path).exists()
                assert (
                    sidecar_directory / Path(GENERATOR_RECEIPT_SIDECAR_PATH).name
                ).read_bytes() == sidecar
                return document["tested_product_content_revision"]

            revisions = [revision_for_current_tree(GENERATOR_RECEIPT_SIDECAR_BASE)]
            assert revision_for_current_tree(GENERATOR_RECEIPT_SIDECAR_BASE) == revisions[0]
            sidecar_target = sidecar_directory / Path(GENERATOR_RECEIPT_SIDECAR_PATH).name
            with inplace_fixture._temporarily_dirty_tracked_path_on_branch(
                session.state,
                GENERATOR_RECEIPT_SIDECAR_PATH,
                GENERATOR_RECEIPT_SIDECAR_CHANGED[len(GENERATOR_RECEIPT_SIDECAR_BASE):],
            ):
                assert sidecar_target.read_bytes() == GENERATOR_RECEIPT_SIDECAR_CHANGED
                changed_sidecar_revision = revision_for_current_tree(
                    GENERATOR_RECEIPT_SIDECAR_CHANGED
                )
            assert changed_sidecar_revision == revisions[0]

            for path, marker in (
                (GENERATOR_SOURCE_PATH, "# content-class:python-source"),
                (GENERATOR_TEST_PATH, "# content-class:python-test"),
                (GENERATOR_CONFIG_PATH, "# content-class:yaml-data"),
                (GENERATOR_README_PATH, "<!-- content-class:markdown -->"),
            ):
                target = inplace_fixture.REPOSITORY_ROOT / path
                current = target.read_text(encoding="utf-8")
                inplace_fixture._commit_mutation(
                    session.state,
                    path,
                    current + f"\n{marker}\n",
                    "test-evidence-content-class",
                )
                revisions.append(revision_for_current_tree(GENERATOR_RECEIPT_SIDECAR_BASE))

            inplace_fixture._commit_mode_change(
                session.state,
                GENERATOR_SOURCE_PATH,
                0o755,
                "test-evidence-executable-mode",
            )
            revisions.append(revision_for_current_tree(GENERATOR_RECEIPT_SIDECAR_BASE))
            assert len(set(revisions)) == len(revisions)
        branch_restored = True
    finally:
        if sidecar_directory_created and session is not None and branch_restored:
            inplace_fixture._assert_admission(
                session.state.base_branch, session.state.base_head, False
            )
            if (
                not sidecar_directory.is_symlink()
                and sidecar_directory.is_dir()
                and not any(sidecar_directory.iterdir())
            ):
                inplace_fixture._assert_admission(
                    session.state.base_branch, session.state.base_head, False
                )
                sidecar_directory.rmdir()


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
    if condition == "path":
        allowed_mutations = {GENERATOR_README_PATH}
        commit_sequence = inplace_fixture.TEST_EVIDENCE_SYMLINK_COMMIT_SEQUENCE
    elif condition == "untracked_executable":
        allowed_mutations = {GENERATOR_README_PATH, GENERATOR_UNTRACKED_EXECUTABLE_PATH}
        commit_sequence = None
    else:
        allowed_mutations = {GENERATOR_README_PATH, GENERATOR_SOURCE_PATH}
        commit_sequence = None

    with _canonical_public_cli_session(
        tmp_path,
        "================ 4 passed in 0.01s ================",
        "================ 2 passed in 0.01s ================",
        allowed_mutations=allowed_mutations,
        commit_sequence=commit_sequence,
    ) as session:
        def assert_rejected(expected_status: tuple[str, ...], detail: str) -> None:
            run = _run_canonical_public_cli_in_session(
                session, expected_status=expected_status
            )
            assert run.returncode == 1
            assert run.stdout == ""
            assert run.stderr.startswith("test evidence rejected:")
            assert detail in run.stderr
            assert run.receipt_path is None
            assert run.receipt_payload is None
            receipts = REPOSITORY / "runtime_evidence" / "pytest"
            assert not receipts.exists()

        if condition == "dirty":
            with inplace_fixture._temporarily_dirty_tracked_path_on_branch(
                session.state, GENERATOR_SOURCE_PATH, b"\n# dirty product source\n"
            ):
                assert_rejected(
                    (f" M {GENERATOR_SOURCE_PATH}",),
                    "dirty tracked product tree",
                )
        elif condition == "untracked_executable":
            with inplace_fixture._uncommitted_control_file(
                session.state,
                GENERATOR_UNTRACKED_EXECUTABLE_PATH,
                b"#!/bin/sh\nexit 0\n",
                mode=0o755,
            ):
                assert_rejected(
                    (f"?? {GENERATOR_UNTRACKED_EXECUTABLE_PATH}",),
                    "untracked product file",
                )
        elif condition == "path":
            inplace_fixture._commit_symlink_change(
                session.state,
                GENERATOR_README_PATH,
                "missing-target.md",
                "test-evidence-symlink-path",
            )
            assert_rejected((), "symlink product file refused: README.md")
        else:
            with inplace_fixture._temporarily_dirty_tracked_path_on_branch(
                session.state,
                GENERATOR_SOURCE_PATH,
                b"",
                mode=0o755,
            ):
                assert_rejected(
                    (f" M {GENERATOR_SOURCE_PATH}",),
                    "dirty product file mode",
                )


def test_public_script_writes_hashed_content_revision_bound_and_redacted_receipt(
    tmp_path: Path,
) -> None:
    private_path = "/Users/receipt-test-user/private-worktree"
    secret = "TOP-SECRET-RECEIPT-TOKEN"
    completed = _run_canonical_public_cli(
        tmp_path,
        f"runner diagnostic: {private_path} token={secret}\n"
        "================ 70 passed, 5 skipped in 0.10s ================",
        "================ 65 passed in 0.05s ================",
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.receipt_path is not None
    assert completed.receipt_payload is not None
    payload = completed.receipt_payload
    document = json.loads(payload)

    assert Path(completed.receipt_path).name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
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


def test_public_receipt_preserves_subtest_count_separately(tmp_path: Path) -> None:
    completed = _run_canonical_public_cli(
        tmp_path,
        "================ 219 passed, 25 subtests passed in 0.10s ================",
        "================ 65 passed in 0.05s ================",
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.receipt_payload is not None
    receipt = json.loads(completed.receipt_payload)
    assert receipt["suites"][0]["counts"] == {
        "collected": 219,
        "passed": 219,
        "skipped": 0,
        "failed": 0,
        "subtests_passed": 25,
    }


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
    completed = _run_canonical_public_cli(
        tmp_path, output if suite == "complete" else good, output if suite == "career" else good,
    )
    assert completed.returncode == 1
    assert "test evidence rejected:" in completed.stderr
    assert completed.receipt_path is None
    assert completed.receipt_payload is None
    assert not list((REPOSITORY / "runtime_evidence" / "pytest").rglob("*.json"))


@pytest.mark.parametrize("suite", ["complete", "career"])
def test_public_script_refuses_nonzero_exit_from_each_suite(tmp_path: Path, suite: str) -> None:
    completed = _run_canonical_public_cli(
        tmp_path,
        "================ 4 passed in 0.01s ================",
        "================ 2 passed in 0.01s ================",
        complete_status=9 if suite == "complete" else 0,
        career_status=9 if suite == "career" else 0,
    )
    assert completed.returncode == 1
    assert "suite exited with status 9" in completed.stderr
    assert completed.receipt_path is None
    assert completed.receipt_payload is None
    assert not (REPOSITORY / "runtime_evidence" / "pytest").exists()


@pytest.mark.parametrize("body,accepted", [
    ("def test_ok(): assert True", True),
    ("import pytest\ndef test_skip(): pytest.skip('required case')", False),
    ("import pytest\npytest.skip('module unavailable', allow_module_level=True)", False),
    ("import pytest\n@pytest.mark.xfail(reason='known broken')\ndef test_xfail(): assert False", False),
])
def test_mandatory_runner_rejects_real_skipped_execution(tmp_path, body, accepted):
    test_file = tmp_path / "test_mandatory_fixture.py"
    test_file.write_text(body + "\n")
    result = subprocess.run(
        [sys.executable, str(REPOSITORY / "scripts/run-pytest-no-skips.py"),
         "-q", str(test_file)],
        cwd=tmp_path, capture_output=True, text=True, timeout=20,
    )
    assert (result.returncode == 0) is accepted, result.stdout + result.stderr
    if not accepted:
        assert "MANDATORY SKIP:" in result.stderr


def test_environment_gate_requires_installed_protected_binding_only_when_requested(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "environment_gate", REPOSITORY / "scripts/verify-gate-environment.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from career_automation import protected_corpus_binding as binding

    for name in ("requirements-bootstrap.lock", "requirements-test.lock", "jaa.whl", "market.whl"):
        (tmp_path / name).write_bytes(b"synthetic gate input")
    monkeypatch.setattr(module, "_clean_head", lambda root: ("a" * 40, "b" * 40, 1))
    monkeypatch.setattr(module, "_installed_manifest", lambda: ("1.0.0", "c" * 64))
    monkeypatch.setattr(module, "_market_manifest", lambda: "d" * 64)
    receipt = tmp_path / "receipt.json"
    monkeypatch.setattr(module, "_receipt_path", lambda: receipt)
    document = module._expected(tmp_path, wheel=tmp_path / "jaa.whl",
                                market_wheel=tmp_path / "market.whl", browser_cache=None)
    receipt.write_bytes(module._canonical(document))
    calls = []
    def reject(root):
        calls.append(root)
        raise binding.ProtectedCorpusBindingError("synthetic_missing_binding", "missing")
    monkeypatch.setattr(binding, "load_installed_protected_corpus_binding", reject)
    assert module.verify(tmp_path, None) == document
    assert not calls
    with pytest.raises(SystemExit, match="synthetic_missing_binding"):
        module.verify(tmp_path, None, require_protected_corpus=True)
    assert calls == [tmp_path]


@pytest.mark.parametrize("configuration", ["environment", "installed-binding"])
def test_generic_environment_gate_refuses_protected_configuration_before_receipt(tmp_path, monkeypatch, configuration):
    spec = importlib.util.spec_from_file_location(
        "isolated_environment_gate", REPOSITORY / "scripts/verify-gate-environment.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from career_automation import protected_corpus_binding as binding
    pin = tmp_path / "synthetic-binding"
    monkeypatch.setattr(binding, "_COMPILED_BINDING_PATH", pin)
    for name in (*binding.FORBIDDEN_RUNTIME_LOCATORS, "JAA09_EVIDENCE_CONTROL_ROOT"):
        monkeypatch.delenv(name, raising=False)
    if configuration == "environment":
        monkeypatch.setenv("JAA_CERTIFIED_CORPUS_ROOT", "synthetic-never-read")
    else:
        pin.write_bytes(b"synthetic never-read binding")
    with pytest.raises(SystemExit, match="generic gate refuses"):
        module.verify(tmp_path, None, forbid_protected_corpus=True)
