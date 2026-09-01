"""Black-box certification and checked-receipt tests for JAA-02."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from testing_repository import clone_jaa_repository


ROOT = Path(__file__).resolve().parent
CERTIFIER = Path("scripts/certify_jaa02_runtime.py")
VALIDATOR = Path("scripts/accept_jaa02_receipt.py")
EXPECTED_TOTALS = {"passed": 12, "failed": 0, "errors": 0, "skipped": 0}


def _run(root: Path, *argv: str) -> subprocess.CompletedProcess[str]:
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
def repository(tmp_path: Path) -> Path:
    clone = clone_jaa_repository(ROOT, tmp_path / "repository")
    assert (
        _git(clone, "config", "user.name", "JAA-02 certification test").returncode == 0
    )
    assert _git(clone, "config", "user.email", "jaa02@example.test").returncode == 0
    tracked_receipts = [
        line
        for line in _git(
            clone, "ls-files", "runtime_evidence/jaa02/sha256-*.json"
        ).stdout.splitlines()
        if line
    ]
    if tracked_receipts:
        removed = _git(clone, "rm", "-f", "--", *tracked_receipts)
        assert removed.returncode == 0, removed.stderr
        committed = _git(
            clone, "commit", "-m", "remove checked receipt for certifier test"
        )
        assert committed.returncode == 0, committed.stderr
    return clone


def _commit(root: Path, *paths: str, message: str) -> None:
    added = _git(root, "add", "-f", "--", *paths)
    assert added.returncode == 0, added.stderr
    committed = _git(root, "commit", "-m", message)
    assert committed.returncode == 0, committed.stderr


def _certify(root: Path) -> tuple[Path, dict[str, object]]:
    completed = _run(root, str(CERTIFIER))
    assert completed.returncode == 0, completed.stderr
    relative = Path(json.loads(completed.stdout)["receipt"])
    receipt = root / relative
    payload = receipt.read_bytes()
    assert receipt.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    return receipt, json.loads(payload)


def _track_receipt(root: Path, receipt: Path) -> None:
    _commit(
        root,
        receipt.relative_to(root).as_posix(),
        message="track JAA-02 runtime receipt",
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
    directory = repository / "runtime_evidence" / "jaa02"
    directory.mkdir(parents=True, exist_ok=True)
    conflict = directory / f"sha256-{'0' * 64}.json"
    conflict.write_text("{}\n", encoding="utf-8")
    completed = _run(repository, str(CERTIFIER))
    assert completed.returncode == 2
    assert "multiple JAA-02 certification receipts" in completed.stderr
    assert conflict.read_text(encoding="utf-8") == "{}\n"


def test_certifier_fails_closed_on_command_failure(repository: Path) -> None:
    demo = repository / "scripts" / "accept_jaa_02.py"
    demo.write_text("raise SystemExit(7)\n", encoding="utf-8")
    _commit(
        repository,
        demo.relative_to(repository).as_posix(),
        message="force demo failure",
    )
    completed = _run(repository, str(CERTIFIER))
    assert completed.returncode == 2
    assert "acceptance_demo command failed with exit code 7" in completed.stderr
    assert not list((repository / "runtime_evidence" / "jaa02").glob("*.json"))


def test_certifier_rejects_wrong_independent_test_totals(repository: Path) -> None:
    tests = repository / "test_jaa02_independent_acceptance.py"
    tests.write_text("def test_only():\n    assert True\n", encoding="utf-8")
    _commit(repository, tests.name, message="force wrong totals")
    completed = _run(repository, str(CERTIFIER))
    assert completed.returncode == 2
    assert "independent JAA-02 test totals were" in completed.stderr
    assert not list((repository / "runtime_evidence" / "jaa02").glob("*.json"))


def test_validator_rejects_tampered_receipt_bytes(repository: Path) -> None:
    receipt, _document = _certify(repository)
    _track_receipt(repository, receipt)
    receipt.write_bytes(receipt.read_bytes() + b"\n")
    rejected = _run(repository, str(VALIDATOR))
    assert rejected.returncode == 2
    assert "receipt file hash mismatch" in rejected.stderr


def test_validator_preserves_receipt_as_historical_evidence_after_source_changes(
    repository: Path,
) -> None:
    receipt, _document = _certify(repository)
    _track_receipt(repository, receipt)
    source = repository / "career_automation" / "candidate_graph.py"
    source.write_bytes(source.read_bytes() + b"\n# later source revision\n")
    _commit(
        repository,
        source.relative_to(repository).as_posix(),
        message="change source after certification",
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
    replacement = receipt.with_name(
        f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    )
    receipt.unlink()
    replacement.write_bytes(payload)
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
    replacement = receipt.with_name(
        f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    )
    receipt.unlink()
    replacement.write_bytes(payload)
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

    directory = repository / "runtime_evidence" / "jaa02"
    directory.mkdir(parents=True, exist_ok=True)
    first = directory / f"sha256-{'1' * 64}.json"
    second = directory / f"sha256-{'2' * 64}.json"
    first.write_text("{}\n", encoding="utf-8")
    second.write_text("{}\n", encoding="utf-8")
    _commit(
        repository,
        first.relative_to(repository).as_posix(),
        second.relative_to(repository).as_posix(),
        message="track conflicting receipts",
    )
    multiple = _run(repository, str(VALIDATOR))
    assert multiple.returncode == 2
    assert "found 2" in multiple.stderr
