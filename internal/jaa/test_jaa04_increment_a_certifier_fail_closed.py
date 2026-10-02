"""Independent black-box checks for the JAA-04 Increment A certifier."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Iterator, NoReturn

import pytest


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
CERTIFIER = "scripts/certify_jaa04_increment_a.py"
CANON_ROOT = Path("/srv/artvault/projects/market-aligner")
GOVERNANCE_ROOT = Path("/srv/artvault/projects/agent-governance")
AUTHORITY_REGISTER = Path("/srv/artvault/control/machine-authority.v1.json")
NAMED_TEST_ROOT = Path("/srv/artvault/control/operator-glm/programme/canary/market-aligner-linux-verification")
FIXTURE_LOCK = Path("/tmp/ma-jaa04-certifier-fixture.lock")
OWNER_SESSION = "01a0d922-49e4-72b1-a4f4-8f8271305dea"
PROJECT_ID = "market-aligner"
BASE_BRANCH = "codex/ma0112-successor"
ALLOWED_MUTATIONS = {
    f"internal/jaa/{CERTIFIER}",
    "internal/jaa/test_jaa04_increment_a_authority_canaries.py",
}
CERTIFICATION_SURFACE_MUTATIONS = {
    "internal/jaa/career_automation/fixtures/jaa04_authority_canaries/greenhouse.json",
    "internal/jaa/career_automation/fixtures/jaa04_authority_canaries/ashby.json",
    "internal/jaa/career_automation/fixtures/jaa04_authority_canaries/unexpected.json",
    "internal/jaa/career_automation/dirty-certifier-control.txt",
}
JAA02_RECEIPT_MUTATION = "@jaa02-content-addressed-receipt"
JAA02_INITIAL_RECEIPT_PATH = (
    "internal/jaa/runtime_evidence/jaa02/"
    "sha256-8d49a1543093644703e95a78d424c971f55465111baece7a45f6e3c0a71805d2.json"
)
JAA02_CLEAN_COMMIT_SEQUENCE = (
    (JAA02_INITIAL_RECEIPT_PATH, "deleted"),
    (JAA02_RECEIPT_MUTATION, "added"),
)
PERMITTED_MUTATION_PATHS = ALLOWED_MUTATIONS | {
    "internal/jaa/README.md",
    "internal/jaa/scripts/jaa04_increment_a_test_inventory.json",
    "internal/jaa/test_jaa04_sidecar_temporal_semantics.py",
    "internal/jaa/baseline_adoption/cli.py",
    "internal/jaa/runtime_evidence/JAA-00-online-snapshot.yaml",
    JAA02_INITIAL_RECEIPT_PATH,
    JAA02_RECEIPT_MUTATION,
} | CERTIFICATION_SURFACE_MUTATIONS
PUBLICATION_EVIDENCE_PATH = "internal/jaa/runtime_evidence/JAA-00-online-snapshot.yaml"
PUBLICATION_SOURCE_PATH = "internal/jaa/baseline_adoption/cli.py"
PUBLICATION_COMMIT_SEQUENCE = (
    (PUBLICATION_EVIDENCE_PATH, "modified"),
    (PUBLICATION_SOURCE_PATH, "modified"),
)
SUITES = (
    "test_jaa04_increment_a_authority_canaries.py",
    "test_jaa04_increment_a_temporal_authority_regression.py",
    "test_jaa04_sidecar_temporal_semantics.py",
    "test_jaa04_portable_authority_contract.py",
)


def _run(
    directory: Path,
    *argv: str,
    timeout: int = 240,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=directory, text=True, capture_output=True,
                          check=False, timeout=timeout, env=env)


def _git(*argv: str) -> str:
    result = _run(REPOSITORY_ROOT, "git", *argv)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(argv)} failed: {result.stderr.strip()}")
    return result.stdout.rstrip("\n")


def _git_blob_sha256(revision_path: str) -> str:
    result = subprocess.run(
        ("git", "show", revision_path),
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git show {revision_path} failed")
    return hashlib.sha256(result.stdout).hexdigest()


def _abort_suite(message: str) -> NoReturn:
    pytest.exit(message, returncode=2)


def _fixture_run_id() -> str:
    if os.environ.get("MA_JAA04_INPLACE_FIXTURE_MODE") != "admitted-serial-v1":
        raise RuntimeError("in-place certifier fixtures require explicit admitted serial mode")
    if "PYTEST_XDIST_WORKER" in os.environ or "PYTEST_XDIST_TESTRUNUID" in os.environ:
        raise RuntimeError("in-place certifier fixtures refuse parallel pytest execution")
    run_id = os.environ.get("MA_JAA04_INPLACE_RUN_ID", "")
    if not re.fullmatch(r"[a-z0-9-]{1,40}", run_id):
        raise RuntimeError("in-place certifier fixture run ID is absent or invalid")
    return run_id


def _expected_named_test_head() -> str:
    head = os.environ.get("MA_JAA04_INPLACE_NAMED_TEST_HEAD", "")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise RuntimeError("registered named-test HEAD is absent or invalid")
    return head


def _assert_admission(expected_branch: str, expected_head: str, expected_dirty: bool) -> None:
    run_id = _fixture_run_id()
    expected_base_head = os.environ.get("MA_JAA04_INPLACE_BASE_HEAD", "")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_base_head):
        raise RuntimeError("in-place certifier fixture base HEAD is absent or invalid")
    if expected_branch != BASE_BRANCH and not expected_branch.startswith(f"codex/ma-ja04-{run_id}-"):
        raise RuntimeError("in-place certifier fixture branch is outside the admitted run")
    if REPOSITORY_ROOT.resolve() != CANON_ROOT.resolve():
        raise RuntimeError("in-place certifier fixtures are restricted to the registered canon")

    preflight_environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(GOVERNANCE_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    preflight = subprocess.run(
        (
            sys.executable,
            "-m",
            "agent_governance.canon_preflight",
            "--root",
            str(CANON_ROOT),
            "--surface",
            "canon",
            "--project-id",
            PROJECT_ID,
        ),
        cwd=CANON_ROOT,
        env=preflight_environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if preflight.returncode != 0:
        raise RuntimeError("installed canon preflight did not complete successfully")
    try:
        admission = json.loads(preflight.stdout)
        register = json.loads(AUTHORITY_REGISTER.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise RuntimeError("current admission or owner register is unavailable") from error

    owner_row = register.get("execution_supervisor", {}).get("project_agents", {}).get(PROJECT_ID, {})
    scope = owner_row.get("scope")
    if (
        owner_row.get("status") != "active_project_scoped"
        or owner_row.get("source_owner_retained") != OWNER_SESSION
        or not isinstance(scope, list)
        or PROJECT_ID not in scope
    ):
        raise RuntimeError("current MA register no longer confirms this source owner and project scope")

    identity = admission.get("identity", {})
    registered_owner = admission.get("registered_owner", {})
    expected_common = (CANON_ROOT / ".git").resolve()
    if (
        admission.get("status") != "PASS"
        or identity.get("actual_host") != "artvault"
        or Path(identity.get("git_root", "")).resolve() != CANON_ROOT.resolve()
        or Path(identity.get("git_common_dir", "")).resolve() != expected_common
        or identity.get("branch") != expected_branch
        or identity.get("head") != expected_head
        or identity.get("dirty") is not expected_dirty
        or registered_owner.get("host") != "artvault"
        or registered_owner.get("path") != str(CANON_ROOT)
        or registered_owner.get("project_id") != PROJECT_ID
        or registered_owner.get("worker_session") != OWNER_SESSION
        or admission.get("register", {}).get("path") != str(AUTHORITY_REGISTER)
    ):
        raise RuntimeError("installed admission does not match the expected canon state")
    test_exceptions = admission.get("named_supervised_test_exceptions", [])
    matching_exceptions = [
        item for item in test_exceptions
        if item.get("id") == "supervised_test_workflow.projects.market-aligner.test"
    ]
    if (
        len(matching_exceptions) != 1
        or matching_exceptions[0].get("path") != str(NAMED_TEST_ROOT)
        or matching_exceptions[0].get("current_writer", {}).get("session") != OWNER_SESSION
    ):
        raise RuntimeError("registered named-test responsibility changed")

    worktrees = {
        Path(item.get("path", "")).resolve(): item
        for item in identity.get("worktrees", [])
    }
    expected_test_head = _expected_named_test_head()
    if set(worktrees) != {CANON_ROOT.resolve(), NAMED_TEST_ROOT.resolve()}:
        raise RuntimeError("registered worktree set changed")
    if (
        worktrees[CANON_ROOT.resolve()].get("branch") != expected_branch
        or worktrees[CANON_ROOT.resolve()].get("head") != expected_head
        or worktrees[NAMED_TEST_ROOT.resolve()].get("branch") is not None
        or worktrees[NAMED_TEST_ROOT.resolve()].get("head") != expected_test_head
    ):
        raise RuntimeError("registered worktree branch or HEAD changed")
    if _git("branch", "--show-current") != expected_branch or _git("rev-parse", "HEAD") != expected_head:
        raise RuntimeError("current Git branch or HEAD changed after admission")
    dirty = bool(_git("status", "--porcelain", "--untracked-files=all"))
    if dirty is not expected_dirty:
        raise RuntimeError("current Git dirty state changed after admission")


@dataclass
class _FixtureCommit:
    parent_head: str
    head: str
    path: str
    operation: str
    parent_blob_sha256: str | None
    result_blob_sha256: str | None


@dataclass
class _FixtureBranch:
    base_branch: str
    base_head: str
    branch: str
    run_id: str
    head: str
    allowed_mutations: frozenset[str]
    commit_sequence: tuple[tuple[str, str], ...] | None = None
    commit_records: list[_FixtureCommit] = field(default_factory=list)


@pytest.fixture(autouse=True)
def _admit_each_test() -> Iterator[None]:
    expected_head = os.environ.get("MA_JAA04_INPLACE_BASE_HEAD", "")
    try:
        _assert_admission(BASE_BRANCH, expected_head, False)
    except pytest.exit.Exception:
        raise
    except Exception:
        _abort_suite("MA test admission failed at test start")
    yield
    try:
        _assert_admission(BASE_BRANCH, expected_head, False)
    except pytest.exit.Exception:
        raise
    except Exception:
        _abort_suite("MA test admission failed at test completion; preserving current state")


@contextmanager
def _committed_inplace_branch(
    case: str,
    *,
    allowed_mutations: frozenset[str] | set[str] | None = None,
    commit_sequence: tuple[tuple[str, str], ...] | None = None,
) -> Iterator[_FixtureBranch]:
    try:
        lock_fd = os.open(FIXTURE_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError:
        _abort_suite("cannot establish the in-place certifier fixture lock")
    locked = False
    try:
        try:
            lock_stat = os.fstat(lock_fd)
        except OSError:
            _abort_suite("cannot inspect the in-place certifier fixture lock")
        if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != os.getuid():
            _abort_suite("in-place certifier lock is not an owned regular file")
        if stat.S_IMODE(lock_stat.st_mode) != 0o600:
            _abort_suite("in-place certifier lock does not have mode 0600")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError:
            _abort_suite("another in-place certifier fixture is active")
        try:
            run_id = _fixture_run_id()
        except pytest.exit.Exception:
            raise
        except Exception:
            _abort_suite("in-place certifier fixture run is not admitted")
        exact_mutations = frozenset(
            ALLOWED_MUTATIONS if allowed_mutations is None else allowed_mutations
        )
        if not exact_mutations <= PERMITTED_MUTATION_PATHS:
            _abort_suite("fixture mutation scope is outside its reviewed exact paths")
        if commit_sequence is not None:
            permitted_sequences = (PUBLICATION_COMMIT_SEQUENCE, JAA02_CLEAN_COMMIT_SEQUENCE)
            if (
                commit_sequence not in permitted_sequences
                or exact_mutations != frozenset(path for path, _ in commit_sequence)
            ):
                _abort_suite("multi-commit fixture is outside its exact admitted history")
        base_branch = BASE_BRANCH
        base_head = os.environ.get("MA_JAA04_INPLACE_BASE_HEAD", "")
        try:
            _assert_admission(base_branch, base_head, False)
        except pytest.exit.Exception:
            raise
        except Exception:
            _abort_suite("in-place certifier fixture admission failed before branch creation")
        branch = f"codex/ma-ja04-{run_id}-{case}-{uuid.uuid4().hex[:8]}"
        try:
            created = _run(
                REPOSITORY_ROOT,
                "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
                "switch", "--create", branch,
            )
        except (OSError, subprocess.SubprocessError):
            _abort_suite("in-place fixture branch creation did not complete safely")
        if created.returncode != 0:
            _abort_suite("cannot create the admitted in-place fixture branch")
        state = _FixtureBranch(
            base_branch,
            base_head,
            branch,
            run_id,
            base_head,
            exact_mutations,
            commit_sequence,
        )
        try:
            _assert_admission(branch, base_head, False)
            yield state
        finally:
            try:
                _assert_admission(branch, state.head, False)
                if _git("rev-parse", base_branch) != base_head:
                    raise RuntimeError("original branch ref changed")
                expected_records = state.commit_sequence
                actual_sequence = tuple(
                    (record.path, record.operation) for record in state.commit_records
                )
                if expected_records is None:
                    if len(state.commit_records) > 1:
                        raise RuntimeError("single-commit fixture contains multiple commits")
                    if state.commit_records and state.commit_records[0].parent_head != base_head:
                        raise RuntimeError("single fixture commit does not descend from its base")
                    if state.commit_records and not _mutation_path_allowed(
                        state.commit_records[0].path, state.allowed_mutations
                    ):
                        raise RuntimeError("single fixture commit changed an unapproved path")
                elif (
                    len(actual_sequence) != len(expected_records)
                    or any(
                        operation != expected_operation
                        or not _mutation_path_matches(expected_path, actual_path)
                        for (actual_path, operation), (expected_path, expected_operation)
                        in zip(actual_sequence, expected_records)
                    )
                    or state.allowed_mutations
                    != frozenset(path for path, _ in expected_records)
                ):
                    raise RuntimeError("fixture commit sequence differs from its exact admitted history")
                previous_head = base_head
                for record in state.commit_records:
                    expected_status = {
                        "modified": "M",
                        "added": "A",
                        "deleted": "D",
                        "symlink": "T",
                    }.get(record.operation)
                    if (
                        expected_status is None
                        or record.parent_head != previous_head
                        or _git("rev-parse", f"{record.head}^") != record.parent_head
                        or _git("diff", "--name-status", f"{record.parent_head}..{record.head}").splitlines()
                        != [f"{expected_status}\t{record.path}"]
                        or _git_path_blob_sha256(record.parent_head, record.path)
                        != record.parent_blob_sha256
                        or _git_path_blob_sha256(record.head, record.path)
                        != record.result_blob_sha256
                        or (record.operation == "added" and record.parent_blob_sha256 is not None)
                        or (record.operation == "modified" and (
                            record.parent_blob_sha256 is None or record.result_blob_sha256 is None
                        ))
                        or (record.operation == "deleted" and (
                            record.parent_blob_sha256 is None or record.result_blob_sha256 is not None
                        ))
                        or (record.operation == "symlink" and (
                            record.parent_blob_sha256 is None or record.result_blob_sha256 is None
                        ))
                    ):
                        raise RuntimeError("fixture commit record differs from its exact path or blob history")
                    previous_head = record.head
                expected_count = str(len(state.commit_records))
                if (
                    state.head != previous_head
                    or _git("rev-list", "--count", f"{base_head}..{branch}") != expected_count
                    or _git("status", "--porcelain", "--untracked-files=all")
                ):
                    raise RuntimeError("fixture branch history or working tree is unexpected")
            except pytest.exit.Exception:
                raise
            except Exception:
                _abort_suite("fixture teardown could not validate current admission; preserving work")
            try:
                _assert_admission(branch, state.head, False)
            except pytest.exit.Exception:
                raise
            except Exception:
                _abort_suite("fixture branch failed admission before restoration; preserving work")
            try:
                restored = _run(
                    REPOSITORY_ROOT,
                    "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
                    "switch", base_branch,
                )
            except (OSError, subprocess.SubprocessError):
                _abort_suite("ordinary fixture branch restoration did not complete safely")
            if restored.returncode != 0:
                _abort_suite("ordinary fixture branch restoration failed; preserving work")
            try:
                _assert_admission(base_branch, base_head, False)
            except pytest.exit.Exception:
                raise
            except Exception:
                _abort_suite("restored source state failed admission; stopping pytest")
    finally:
        if locked:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _safe_mutation_target(path: str) -> Path:
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != path:
        _abort_suite("fixture mutation path is not a canonical repository-relative path")
    target = REPOSITORY_ROOT / relative
    if target.resolve(strict=False) != target:
        _abort_suite("fixture mutation path resolves through an unexpected alias")
    for parent in target.parents:
        if parent == REPOSITORY_ROOT:
            break
        if parent.is_symlink():
            _abort_suite("fixture mutation path crosses a symlinked parent")
    return target


def _git_path_blob_sha256(revision: str, path: str) -> str | None:
    listed = _run(
        REPOSITORY_ROOT,
        "git",
        "ls-tree",
        "-r",
        "--name-only",
        revision,
        "--",
        path,
    )
    if listed.returncode != 0:
        raise RuntimeError("cannot inspect exact fixture path in Git tree")
    paths = listed.stdout.splitlines()
    if not paths:
        return None
    if paths != [path]:
        raise RuntimeError("Git tree path lookup returned an unexpected path")
    return _git_blob_sha256(f"{revision}:{path}")


def _is_jaa02_receipt_path(path: str) -> bool:
    return re.fullmatch(
        r"internal/jaa/runtime_evidence/jaa02/sha256-[0-9a-f]{64}\.json",
        path,
    ) is not None


def _mutation_path_matches(expected: str, actual: str) -> bool:
    return actual == expected or (
        expected == JAA02_RECEIPT_MUTATION and _is_jaa02_receipt_path(actual)
    )


def _mutation_path_allowed(path: str, allowed: frozenset[str]) -> bool:
    return any(_mutation_path_matches(expected, path) for expected in allowed)


def _commit_path_change(
    state: _FixtureBranch,
    path: str,
    operation: str,
    content: bytes | None,
    case: str,
    *,
    preexisting_added: bool = False,
) -> None:
    if not _mutation_path_allowed(path, state.allowed_mutations):
        _abort_suite("fixture mutation path is not allowlisted")
    commit_index = len(state.commit_records)
    if state.commit_sequence is None:
        if commit_index != 0:
            _abort_suite("single-commit fixture cannot accept another commit")
    elif (
        commit_index >= len(state.commit_sequence)
        or state.commit_sequence[commit_index][1] != operation
        or not _mutation_path_matches(state.commit_sequence[commit_index][0], path)
    ):
        _abort_suite("fixture commit does not match its exact admitted sequence")
    _assert_admission(state.branch, state.head, preexisting_added)
    target = _safe_mutation_target(path)
    parent_head = state.head
    parent_blob_sha256 = _git_path_blob_sha256(parent_head, path)
    if preexisting_added and (
        _git("status", "--porcelain", "--untracked-files=all").splitlines()
        != [f"?? {path}"]
    ):
        _abort_suite("generated receipt is not the sole exact untracked path")
    if operation in {"modified", "deleted", "symlink"}:
        if (
            parent_blob_sha256 is None
            or not target.is_file()
            or target.is_symlink()
            or hashlib.sha256(target.read_bytes()).hexdigest() != parent_blob_sha256
        ):
            _abort_suite("fixture mutation source differs from its admitted base blob")
    elif operation == "added":
        if parent_blob_sha256 is not None or target.is_symlink():
            _abort_suite("fixture addition target already exists in the admitted source")
        if preexisting_added:
            if (
                not _is_jaa02_receipt_path(path)
                or not target.is_file()
                or content is None
                or target.read_bytes() != content
            ):
                _abort_suite("existing generated receipt differs from its exact fixture bytes")
        elif target.exists():
            _abort_suite("fixture addition target already exists in the admitted source")
    else:
        _abort_suite("fixture mutation operation is not permitted")
    if operation == "deleted" and content is not None:
        _abort_suite("fixture deletion unexpectedly supplied replacement bytes")
    if operation != "deleted" and content is None:
        _abort_suite("fixture write is missing its exact content bytes")

    result_blob_sha256 = hashlib.sha256(content).hexdigest() if content is not None else None
    if operation == "added" and _mutation_path_matches(JAA02_RECEIPT_MUTATION, path) and (
        result_blob_sha256 is None
        or Path(path).name != f"sha256-{result_blob_sha256}.json"
    ):
        _abort_suite("JAA-02 receipt path is not bound to its exact content hash")
    try:
        if operation == "modified":
            target.write_bytes(content or b"")
        elif operation == "symlink":
            target.unlink()
            _assert_admission(state.branch, state.head, True)
            target.symlink_to(os.fsdecode(content or b""))
        elif operation == "added":
            if not preexisting_added:
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o644,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content or b"")
                    stream.flush()
                    os.fsync(stream.fileno())
        elif operation == "deleted":
            target.unlink()
    except OSError:
        _abort_suite("fixture path change failed; preserving current branch state")

    expected_unstaged = {
        "modified": f" M {path}",
        "added": f"?? {path}",
        "deleted": f" D {path}",
        "symlink": f" T {path}",
    }[operation]
    if _git("status", "--porcelain", "--untracked-files=all").splitlines() != [expected_unstaged]:
        _abort_suite("fixture working diff is not the single exact allowlisted path")
    if content is not None:
        if operation == "symlink":
            if not target.is_symlink() or os.fsencode(os.readlink(target)) != content:
                _abort_suite("fixture symlink differs from its exact admitted target")
        elif (
            not target.is_file()
            or target.is_symlink()
            or hashlib.sha256(target.read_bytes()).hexdigest() != result_blob_sha256
        ):
            _abort_suite("fixture working bytes differ from the exact admitted content")
    _assert_admission(state.branch, state.head, True)
    staged = _run(
        REPOSITORY_ROOT,
        "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
        "add", "--", path,
    )
    if staged.returncode != 0:
        _abort_suite("fixture could not stage its exact allowlisted path")
    expected_staged = {
        "modified": f"M  {path}",
        "added": f"A  {path}",
        "deleted": f"D  {path}",
        "symlink": f"T  {path}",
    }[operation]
    if (
        _git("status", "--porcelain", "--untracked-files=all").splitlines() != [expected_staged]
        or _git("diff", "--cached", "--name-only").splitlines() != [path]
        or _git("diff", "--name-only")
        or (
            content is not None
            and operation == "symlink"
            and (not target.is_symlink() or os.fsencode(os.readlink(target)) != content)
        )
        or (
            content is not None
            and operation != "symlink"
            and hashlib.sha256(target.read_bytes()).hexdigest() != result_blob_sha256
        )
        or (content is None and target.exists())
    ):
        _abort_suite("fixture staged diff is not exactly its allowlisted path")
    _assert_admission(state.branch, state.head, True)
    committed = _run(
        REPOSITORY_ROOT,
        "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
        "-c", "user.email=tester@example.invalid", "-c", "user.name=Independent tester",
        "commit", "--only", "-m", f"adversarial certification control: {case}", "--", path,
    )
    if committed.returncode != 0:
        _abort_suite("fixture commit failed; preserving staged work")
    new_head = _git("rev-parse", "HEAD")
    state.commit_records.append(
        _FixtureCommit(
            parent_head,
            new_head,
            path,
            operation,
            parent_blob_sha256,
            result_blob_sha256,
        )
    )
    state.head = new_head
    _assert_admission(state.branch, state.head, False)
    expected_diff = {
        "modified": "M",
        "added": "A",
        "deleted": "D",
        "symlink": "T",
    }[operation]
    if (
        _git("rev-parse", f"{new_head}^") != parent_head
        or _git("diff", "--name-status", f"{parent_head}..{new_head}").splitlines()
        != [f"{expected_diff}\t{path}"]
        or _git_path_blob_sha256(parent_head, path) != parent_blob_sha256
        or _git_path_blob_sha256(new_head, path) != result_blob_sha256
        or _git("status", "--porcelain", "--untracked-files=all")
    ):
        _abort_suite("fixture commit changed more than the exact intended path")


def _commit_mutation(state: _FixtureBranch, path: str, content: str, case: str) -> None:
    _commit_path_change(state, path, "modified", content.encode("utf-8"), case)


def _commit_added_file(state: _FixtureBranch, path: str, content: bytes, case: str) -> None:
    _commit_path_change(state, path, "added", content, case)


def _commit_existing_added_file(
    state: _FixtureBranch, path: str, content: bytes, case: str
) -> None:
    _commit_path_change(
        state, path, "added", content, case, preexisting_added=True
    )


def _commit_deleted_file(state: _FixtureBranch, path: str, case: str) -> None:
    _commit_path_change(state, path, "deleted", None, case)


def _commit_symlink_change(
    state: _FixtureBranch, path: str, target: str, case: str
) -> None:
    _commit_path_change(state, path, "symlink", os.fsencode(target), case)


@contextmanager
def _temporarily_dirty_tracked_path(path: str, suffix: bytes) -> Iterator[Path]:
    if path not in PERMITTED_MUTATION_PATHS or not suffix:
        _abort_suite("temporary dirty path is outside the exact fixture scope")
    try:
        lock_fd = os.open(FIXTURE_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError:
        _abort_suite("cannot establish the in-place certifier fixture lock")
    locked = False
    write_started = False
    changed = False
    try:
        lock_stat = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != os.getuid():
            _abort_suite("in-place certifier lock is not an owned regular file")
        if stat.S_IMODE(lock_stat.st_mode) != 0o600:
            _abort_suite("in-place certifier lock does not have mode 0600")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError:
            _abort_suite("another in-place certifier fixture is active")

        branch = _git("branch", "--show-current")
        head = _git("rev-parse", "HEAD")
        _assert_admission(branch, head, False)
        target = _safe_mutation_target(path)
        base_blob_sha256 = _git_path_blob_sha256(head, path)
        if (
            base_blob_sha256 is None
            or not target.is_file()
            or target.is_symlink()
        ):
            _abort_suite("temporary dirty source is not an exact tracked regular file")
        original = target.read_bytes()
        if hashlib.sha256(original).hexdigest() != base_blob_sha256:
            _abort_suite("temporary dirty source differs from its admitted HEAD blob")
        changed_bytes = original + suffix
        changed_sha256 = hashlib.sha256(changed_bytes).hexdigest()
        if _git("status", "--porcelain", "--untracked-files=all"):
            _abort_suite("temporary dirty source requires an initially clean canon")

        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            write_started = True
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(changed_bytes)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            _abort_suite("temporary dirty source write failed; preserving current bytes")
        changed = True
        if (
            _git("status", "--porcelain", "--untracked-files=all").splitlines()
            != [f" M {path}"]
            or not target.is_file()
            or target.is_symlink()
            or hashlib.sha256(target.read_bytes()).hexdigest() != changed_sha256
        ):
            _abort_suite("temporary dirty source is not the exact appended mutation")
        _assert_admission(branch, head, True)
        yield target
    finally:
        if write_started:
            if not changed:
                if (
                    target.is_file()
                    and not target.is_symlink()
                    and hashlib.sha256(target.read_bytes()).hexdigest() == changed_sha256
                    and _git("status", "--porcelain", "--untracked-files=all").splitlines()
                    == [f" M {path}"]
                ):
                    changed = True
                else:
                    _abort_suite("partial or unexpected source bytes detected; preserving work")
            try:
                _assert_admission(branch, head, True)
            except pytest.exit.Exception:
                raise
            except Exception:
                _abort_suite("temporary dirty source lost admission; preserving work")
            if (
                not target.is_file()
                or target.is_symlink()
                or hashlib.sha256(target.read_bytes()).hexdigest() != changed_sha256
                or _git("status", "--porcelain", "--untracked-files=all").splitlines()
                != [f" M {path}"]
            ):
                _abort_suite("unexpected source drift detected; preserving work")
            try:
                _assert_admission(branch, head, True)
            except pytest.exit.Exception:
                raise
            except Exception:
                _abort_suite("temporary dirty source lost admission before restoration")
            try:
                descriptor = os.open(target, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(original)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError:
                _abort_suite("cannot restore exact source bytes; preserving current work")
            try:
                _assert_admission(branch, head, False)
            except pytest.exit.Exception:
                raise
            except Exception:
                _abort_suite("source bytes restored but canon admission is not clean")
            if (
                hashlib.sha256(target.read_bytes()).hexdigest() != base_blob_sha256
                or _git("status", "--porcelain", "--untracked-files=all")
            ):
                _abort_suite("source restoration did not reproduce the exact clean HEAD")
        if locked:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


@contextmanager
def _uncommitted_control_file(
    state: _FixtureBranch,
    path: str,
    content: bytes,
) -> Iterator[Path]:
    if path not in state.allowed_mutations:
        _abort_suite("uncommitted control path is not allowlisted")
    _assert_admission(state.branch, state.head, False)
    target = _safe_mutation_target(path)
    if _git_path_blob_sha256(state.base_head, path) is not None or target.exists() or target.is_symlink():
        _abort_suite("uncommitted control path already exists in the admitted source")
    created = False
    try:
        try:
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except OSError:
            _abort_suite("cannot create exact uncommitted dirty-state control")
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_status = [f"?? {path}"]
        _assert_admission(state.branch, state.head, True)
        if (
            _git("status", "--porcelain", "--untracked-files=all").splitlines() != expected_status
            or not target.is_file()
            or target.is_symlink()
            or hashlib.sha256(target.read_bytes()).hexdigest() != expected_sha256
        ):
            _abort_suite("dirty-state control is not the exact single untracked file")
        yield target
    finally:
        if created:
            expected_sha256 = hashlib.sha256(content).hexdigest()
            expected_status = [f"?? {path}"]
            if (
                not target.is_file()
                or target.is_symlink()
                or hashlib.sha256(target.read_bytes()).hexdigest() != expected_sha256
                or _git("status", "--porcelain", "--untracked-files=all").splitlines()
                != expected_status
            ):
                _abort_suite("unexpected dirty-state changes detected; preserving work")
            _assert_admission(state.branch, state.head, True)
            try:
                target.unlink()
            except OSError:
                _abort_suite("cannot remove only the exact dirty-state control")
            try:
                _assert_admission(state.branch, state.head, False)
            except pytest.exit.Exception:
                raise
            except Exception:
                _abort_suite("unexpected work remains after dirty-state control removal")
            if target.exists() or target.is_symlink() or _git(
                "status", "--porcelain", "--untracked-files=all"
            ):
                _abort_suite("dirty-state control did not restore the exact clean branch")


def _certify(
    tmp_path: Path,
    branch: str,
    head: str,
    *,
    env: dict[str, str] | None = None,
    expected_dirty: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    _assert_admission(branch, head, expected_dirty)
    receipt_directory = tmp_path / "receipt"
    try:
        receipt_directory.resolve().relative_to(Path("/tmp").resolve())
    except ValueError as error:
        raise RuntimeError("certifier receipts must remain under /tmp") from error
    return (
        _run(
            ROOT,
            sys.executable,
            CERTIFIER,
            "--receipt",
            str(receipt_directory),
            env=env,
        ),
        receipt_directory,
    )


def _rejects(tmp_path: Path, branch: str, head: str) -> None:
    result, directory = _certify(tmp_path, branch, head)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "JAA-04 Increment A certification: ERROR:" in result.stderr
    assert not list(directory.glob("sha256-*.json"))


def test_clean_certifier_records_each_required_suite_and_all_thirteen_portable_contracts(tmp_path: Path) -> None:
    base_head = os.environ["MA_JAA04_INPLACE_BASE_HEAD"]
    result, directory = _certify(tmp_path, BASE_BRANCH, base_head)
    assert result.returncode == 0, result.stdout + result.stderr
    receipts = list(directory.glob("sha256-*.json"))
    assert len(receipts) == 1
    payload = receipts[0].read_bytes()
    receipt = json.loads(payload)
    assert receipts[0].name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    assert receipt["status"] == "SUCCESS"
    assert receipt["source_revision"] == base_head
    results = receipt["executed_suite_results"]
    assert [row["suite"] for row in results] == list(SUITES)
    assert sum(row["passed"] for row in results) == 47
    assert all(row["exit_code"] == row["failed"] == row["errors"] == row["skipped"] == 0 for row in results)
    portable = next(row for row in results if row["suite"] == SUITES[-1])
    assert portable["passed"] == 13


def test_omitted_required_suite_fails_closed(tmp_path: Path) -> None:
    with _committed_inplace_branch("omitted-suite") as state:
        certifier = ROOT / CERTIFIER
        text = certifier.read_text(encoding="utf-8")
        suite_declaration = '    "test_jaa04_sidecar_temporal_semantics.py",\n'
        expected_count = "EXPECTED_TESTS = 47"
        assert text.count(suite_declaration) == 1
        assert text.count(expected_count) == 1
        changed = text.replace(suite_declaration, "").replace(expected_count, "EXPECTED_TESTS = 44")
        assert (
            suite_declaration not in changed
            and expected_count not in changed
            and changed.count("EXPECTED_TESTS = 44") == 1
        )
        path = f"internal/jaa/{CERTIFIER}"
        _commit_mutation(state, path, changed, "omitted-suite")
        _rejects(tmp_path, state.branch, state.head)


def test_failed_suite_fails_closed(tmp_path: Path) -> None:
    with _committed_inplace_branch("failed-suite") as state:
        suite = ROOT / SUITES[0]
        content = suite.read_text(encoding="utf-8") + "\n\ndef test_independent_failure_control():\n    assert False\n"
        path = f"internal/jaa/{SUITES[0]}"
        _commit_mutation(state, path, content, "failed-suite")
        _rejects(tmp_path, state.branch, state.head)


def test_skipped_suite_outcome_fails_closed(tmp_path: Path) -> None:
    with _committed_inplace_branch("skipped-suite") as state:
        suite = ROOT / SUITES[0]
        content = suite.read_text(encoding="utf-8") + "\n\nimport pytest\n\n@pytest.mark.skip(reason='independent control')\ndef test_independent_skip_control():\n    pass\n"
        path = f"internal/jaa/{SUITES[0]}"
        _commit_mutation(state, path, content, "skipped-suite")
        _rejects(tmp_path, state.branch, state.head)


def test_unknown_xfail_outcome_fails_closed(tmp_path: Path) -> None:
    with _committed_inplace_branch("unknown-xfail") as state:
        suite = ROOT / SUITES[0]
        content = suite.read_text(encoding="utf-8") + "\n\nimport pytest\n\n@pytest.mark.xfail(reason='independent control')\ndef test_independent_unknown_outcome_control():\n    assert False\n"
        path = f"internal/jaa/{SUITES[0]}"
        _commit_mutation(state, path, content, "unknown-xfail")
        _rejects(tmp_path, state.branch, state.head)


def test_acceptance_declaration_is_data_without_command_substitution() -> None:
    declaration = ROOT / "acceptance"
    lines = [line.strip() for line in declaration.read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    assert lines and all("$(" not in line and "`" not in line for line in lines), (
        "acceptance declarations are data: each command must be directly executable "
        "from the project root without command substitution"
    )


def test_existing_receipt_tampering_fails_closed(tmp_path: Path) -> None:
    base_head = os.environ["MA_JAA04_INPLACE_BASE_HEAD"]
    result, directory = _certify(tmp_path, BASE_BRANCH, base_head)
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = next(directory.glob("sha256-*.json"))
    receipt.write_bytes(receipt.read_bytes() + b" tampered")
    tampered = receipt.read_bytes()
    rejected, _ = _certify(tmp_path, BASE_BRANCH, base_head)
    assert rejected.returncode != 0
    assert "JAA-04 Increment A certification: ERROR:" in rejected.stderr
    assert receipt.read_bytes() == tampered
    assert receipt.name != f"sha256-{hashlib.sha256(tampered).hexdigest()}.json"
