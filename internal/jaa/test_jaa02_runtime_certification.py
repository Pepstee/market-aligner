"""Black-box certification and checked-receipt tests for JAA-02."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

import test_jaa04_increment_a_certifier_fail_closed as inplace_fixture


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parents[1]
CERTIFIER = Path("scripts/certify_jaa02_runtime.py")
VALIDATOR = Path("scripts/accept_jaa02_receipt.py")
EXPECTED_TOTALS = {"passed": 12, "failed": 0, "errors": 0, "skipped": 0}
INPLACE_TEST_NAME = "test_clean_certification_executes_real_commands_and_checked_validator_passes"
_ACTIVE_INPLACE_STATE = None
_ACTIVE_INPLACE_DIRTY_STATUS: tuple[str, ...] = ()

_JAA02_SCENARIOS = {
    INPLACE_TEST_NAME: (
        "jaa02-clean",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH, inplace_fixture.JAA02_RECEIPT_MUTATION}),
        inplace_fixture.JAA02_CLEAN_COMMIT_SEQUENCE,
    ),
    "test_certifier_rejects_symlinked_output_without_writing": (
        "jaa02-symlink",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH}),
        inplace_fixture.JAA02_DELETE_RECEIPT_SEQUENCE,
    ),
    "test_certifier_refuses_conflicting_existing_receipt": (
        "jaa02-conflict",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH}),
        inplace_fixture.JAA02_DELETE_RECEIPT_SEQUENCE,
    ),
    "test_certifier_fails_closed_on_command_failure": (
        "jaa02-command-failure",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH, inplace_fixture.JAA02_COMMAND_FAILURE_PATH}),
        inplace_fixture.JAA02_COMMAND_FAILURE_SEQUENCE,
    ),
    "test_certifier_rejects_wrong_independent_test_totals": (
        "jaa02-wrong-totals",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH, inplace_fixture.JAA02_WRONG_TOTALS_PATH}),
        inplace_fixture.JAA02_WRONG_TOTALS_SEQUENCE,
    ),
    "test_validator_rejects_tampered_receipt_bytes": (
        "jaa02-tampered-receipt",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH, inplace_fixture.JAA02_RECEIPT_MUTATION}),
        inplace_fixture.JAA02_CLEAN_COMMIT_SEQUENCE,
    ),
    "test_validator_preserves_receipt_as_historical_evidence_after_source_changes": (
        "jaa02-historical-receipt",
        frozenset({
            inplace_fixture.JAA02_INITIAL_RECEIPT_PATH,
            inplace_fixture.JAA02_RECEIPT_MUTATION,
            inplace_fixture.JAA02_HISTORICAL_SOURCE_PATH,
        }),
        inplace_fixture.JAA02_HISTORICAL_COMMIT_SEQUENCE,
    ),
    "test_validator_rejects_rehashed_wrong_test_totals": (
        "jaa02-rehashed-wrong-totals",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH, inplace_fixture.JAA02_RECEIPT_MUTATION}),
        inplace_fixture.JAA02_CLEAN_COMMIT_SEQUENCE,
    ),
    "test_validator_rejects_rehashed_reordered_or_omitted_acceptance_commands": (
        "jaa02-rehashed-command-semantics",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH, inplace_fixture.JAA02_RECEIPT_MUTATION}),
        inplace_fixture.JAA02_CLEAN_COMMIT_SEQUENCE,
    ),
    "test_validator_rejects_absent_and_multiple_checked_receipts": (
        "jaa02-absent-multiple-receipts",
        frozenset({inplace_fixture.JAA02_INITIAL_RECEIPT_PATH, inplace_fixture.JAA02_TWO_RECEIPTS_MUTATION}),
        inplace_fixture.JAA02_MULTIPLE_RECEIPTS_COMMIT_SEQUENCE,
    ),
}


def _assert_active_inplace_state() -> None:
    if _ACTIVE_INPLACE_STATE is None:
        return
    actual_status = tuple(
        inplace_fixture._git("status", "--porcelain", "--untracked-files=all").splitlines()
    )
    if actual_status != _ACTIVE_INPLACE_DIRTY_STATUS:
        raise RuntimeError("JAA-02 subprocess boundary has unexpected working-tree paths")
    inplace_fixture._assert_admission(
        _ACTIVE_INPLACE_STATE.branch,
        _ACTIVE_INPLACE_STATE.head,
        bool(_ACTIVE_INPLACE_DIRTY_STATUS),
    )


@contextmanager
def _expect_inplace_status(status: tuple[str, ...]) -> Iterator[None]:
    global _ACTIVE_INPLACE_DIRTY_STATUS
    if _ACTIVE_INPLACE_STATE is None:
        raise RuntimeError("JAA-02 temporary dirt requires the admitted in-place branch")
    actual_status = tuple(
        inplace_fixture._git("status", "--porcelain", "--untracked-files=all").splitlines()
    )
    if actual_status != status:
        raise RuntimeError("JAA-02 temporary path set differs from its exact expected status")
    _ACTIVE_INPLACE_DIRTY_STATUS = status
    try:
        _assert_active_inplace_state()
        yield
    finally:
        _ACTIVE_INPLACE_DIRTY_STATUS = ()


def _run(root: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    _assert_active_inplace_state()
    return subprocess.run(
        (sys.executable, *argv),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _git(root: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *argv),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


@pytest.fixture()
def repository(request: pytest.FixtureRequest) -> Path:
    global _ACTIVE_INPLACE_STATE, _ACTIVE_INPLACE_DIRTY_STATUS
    node_name = getattr(request.node, "originalname", request.node.name)
    scenario = _JAA02_SCENARIOS.get(node_name)
    if scenario is None:
        pytest.exit(
            "this JAA-02 case has not been adapted to the admitted in-place fixture",
            returncode=2,
        )
    case, allowed, commit_sequence = scenario
    with inplace_fixture._committed_inplace_branch(
        case,
        allowed_mutations=allowed,
        commit_sequence=commit_sequence,
    ) as state:
        initial_receipt = Path(
            inplace_fixture.JAA02_INITIAL_RECEIPT_PATH
        ).relative_to("internal/jaa").as_posix()
        tracked_receipts = _git(
            ROOT, "ls-files", "runtime_evidence/jaa02/sha256-*.json"
        ).stdout.splitlines()
        assert tracked_receipts == [initial_receipt]
        inplace_fixture._commit_deleted_file(
            state,
            inplace_fixture.JAA02_INITIAL_RECEIPT_PATH,
            "remove checked receipt for JAA-02 clean certification",
        )
        _ACTIVE_INPLACE_STATE = state
        _ACTIVE_INPLACE_DIRTY_STATUS = ()
        try:
            yield ROOT
        finally:
            _ACTIVE_INPLACE_STATE = None
            _ACTIVE_INPLACE_DIRTY_STATUS = ()


def _commit_source_change(path: Path, content: bytes, message: str) -> None:
    if _ACTIVE_INPLACE_STATE is None:
        raise RuntimeError("JAA-02 source mutation requires the admitted in-place branch")
    relative_path = path.relative_to(PROJECT_ROOT).as_posix()
    inplace_fixture._commit_mutation(
        _ACTIVE_INPLACE_STATE,
        relative_path,
        content.decode("utf-8"),
        message,
    )


def _certify(root: Path) -> tuple[Path, dict[str, object]]:
    completed = _run(root, str(CERTIFIER))
    assert completed.returncode == 0, completed.stderr
    relative = Path(json.loads(completed.stdout)["receipt"])
    receipt = root / relative
    payload = receipt.read_bytes()
    assert receipt.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    if _ACTIVE_INPLACE_STATE is not None:
        project_relative = receipt.relative_to(PROJECT_ROOT).as_posix()
        expected_status = (f"?? {project_relative}",)
        assert tuple(
            inplace_fixture._git("status", "--porcelain", "--untracked-files=all").splitlines()
        ) == expected_status
        inplace_fixture._assert_admission(
            _ACTIVE_INPLACE_STATE.branch,
            _ACTIVE_INPLACE_STATE.head,
            True,
        )
    return receipt, json.loads(payload)


def _track_receipt(root: Path, receipt: Path) -> None:
    if _ACTIVE_INPLACE_STATE is None:
        raise RuntimeError("JAA-02 receipt tracking requires the admitted in-place branch")
    project_relative = receipt.relative_to(PROJECT_ROOT).as_posix()
    inplace_fixture._commit_existing_added_file(
        _ACTIVE_INPLACE_STATE,
        project_relative,
        receipt.read_bytes(),
        "track JAA-02 runtime receipt",
    )


def _replace_receipt(receipt: Path, payload: bytes) -> Path:
    if _ACTIVE_INPLACE_STATE is None:
        raise RuntimeError("JAA-02 receipt replacement requires the admitted in-place branch")
    old_path = receipt.relative_to(PROJECT_ROOT).as_posix()
    new_path = receipt.with_name(f"sha256-{hashlib.sha256(payload).hexdigest()}.json")
    return inplace_fixture._replace_untracked_jaa02_receipt(
        _ACTIVE_INPLACE_STATE,
        old_path,
        new_path.relative_to(PROJECT_ROOT).as_posix(),
        payload,
    )


def test_clean_certification_executes_real_commands_and_checked_validator_passes(
    repository: Path,
) -> None:
    receipt, document = _certify(repository)
    assert document["format"] == "jaa02-runtime-certification/v1"
    assert document["source_content_revision"].startswith("sha256:")
    assert document["source_content_revision_contract"]["exclusions"] == [
        "runtime_evidence/"
    ]
    commands = document["command_semantics"]
    assert [item["role"] for item in commands] == [
        "acceptance_demo",
        "independent_negative_controls",
    ]
    assert commands[0]["parsed_test_totals"] == {
        "passed": 1,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
    }
    assert commands[1]["parsed_test_totals"] == EXPECTED_TOTALS
    assert all(item["exit_code"] == 0 for item in commands)
    assert all(item["argv"][0] == "{python}" for item in commands)
    assert len(document["negative_controls"]) >= 7

    _track_receipt(repository, receipt)
    accepted = _run(repository, str(VALIDATOR))
    assert accepted.returncode == 0, accepted.stderr
    assert json.loads(accepted.stdout)["status"] == "accepted"


def test_certifier_rejects_symlinked_output_without_writing(
    repository: Path, tmp_path: Path
) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    completed = _run(repository, str(CERTIFIER), "--evidence-directory", str(linked))
    assert completed.returncode == 2
    assert "must not resolve through a symlink" in completed.stderr
    assert list(actual.iterdir()) == []


def test_certifier_refuses_conflicting_existing_receipt(repository: Path) -> None:
    conflict_path = inplace_fixture.JAA02_CONFLICT_RECEIPT_PATH
    with inplace_fixture._uncommitted_control_file(
        _ACTIVE_INPLACE_STATE, conflict_path, b"{}\n"
    ) as conflict:
        with _expect_inplace_status((f"?? {conflict_path}",)):
            completed = _run(repository, str(CERTIFIER))
            assert completed.returncode == 2
            assert "multiple JAA-02 certification receipts" in completed.stderr
            assert conflict.read_bytes() == b"{}\n"


def test_certifier_fails_closed_on_command_failure(repository: Path) -> None:
    demo = repository / "scripts" / "accept_jaa_02.py"
    _commit_source_change(
        demo,
        b"raise SystemExit(7)\n",
        "force demo failure",
    )
    completed = _run(repository, str(CERTIFIER))
    assert completed.returncode == 2
    assert "acceptance_demo command failed with exit code 7" in completed.stderr
    assert not list((repository / "runtime_evidence" / "jaa02").glob("*.json"))


def test_certifier_rejects_wrong_independent_test_totals(repository: Path) -> None:
    tests = repository / "test_jaa02_independent_acceptance.py"
    _commit_source_change(
        tests,
        b"def test_only():\n    assert True\n",
        "force wrong totals",
    )
    completed = _run(repository, str(CERTIFIER))
    assert completed.returncode == 2
    assert "independent JAA-02 test totals were" in completed.stderr
    assert not list((repository / "runtime_evidence" / "jaa02").glob("*.json"))


def test_validator_rejects_tampered_receipt_bytes(repository: Path) -> None:
    receipt, _document = _certify(repository)
    _track_receipt(repository, receipt)
    relative = receipt.relative_to(PROJECT_ROOT).as_posix()
    with inplace_fixture._temporarily_dirty_tracked_path_on_branch(
        _ACTIVE_INPLACE_STATE, relative, b"\n"
    ):
        with _expect_inplace_status((f" M {relative}",)):
            rejected = _run(repository, str(VALIDATOR))
            assert rejected.returncode == 2
            assert "receipt file hash mismatch" in rejected.stderr


def test_validator_preserves_receipt_as_historical_evidence_after_source_changes(
    repository: Path,
) -> None:
    receipt, _document = _certify(repository)
    _track_receipt(repository, receipt)
    source = repository / "career_automation" / "candidate_graph.py"
    _commit_source_change(
        source,
        source.read_bytes() + b"\n# later source revision\n",
        "change source after certification",
    )
    accepted = _run(repository, str(VALIDATOR))
    assert accepted.returncode == 0, accepted.stderr
    assert json.loads(accepted.stdout)["status"] == "accepted"


def test_validator_rejects_rehashed_wrong_test_totals(repository: Path) -> None:
    receipt, document = _certify(repository)
    document["command_semantics"][1]["parsed_test_totals"]["passed"] = 11
    payload = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    replacement = _replace_receipt(receipt, payload)
    _track_receipt(repository, replacement)
    rejected = _run(repository, str(VALIDATOR))
    assert rejected.returncode == 2
    assert "test totals mismatch" in rejected.stderr


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda commands: commands.reverse(), "command semantics mismatch"),
        (lambda commands: commands.pop(), "must contain exactly two commands"),
    ],
)
def test_validator_rejects_rehashed_reordered_or_omitted_acceptance_commands(
    repository: Path,
    mutation,
    message: str,
) -> None:
    """The receipt is an ordered, complete execution record—not a command set."""
    receipt, document = _certify(repository)
    commands = document["command_semantics"]
    assert isinstance(commands, list)
    mutation(commands)
    payload = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    replacement = _replace_receipt(receipt, payload)
    _track_receipt(repository, replacement)

    rejected = _run(repository, str(VALIDATOR))
    assert rejected.returncode == 2
    assert message in rejected.stderr


def test_validator_rejects_absent_and_multiple_checked_receipts(
    repository: Path,
) -> None:
    absent = _run(repository, str(VALIDATOR))
    assert absent.returncode == 2
    assert "found 0" in absent.stderr

    inplace_fixture._commit_added_receipts(
        _ACTIVE_INPLACE_STATE,
        tuple(
            (path, b"{}\n")
            for path in inplace_fixture.JAA02_MULTIPLE_RECEIPT_PATHS
        ),
        "track conflicting receipts",
    )
    multiple = _run(repository, str(VALIDATOR))
    assert multiple.returncode == 2
    assert "found 2" in multiple.stderr
