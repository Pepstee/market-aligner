"""Independent command-list tamper controls for the historical JAA-02 receipt."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest

import test_jaa04_increment_a_certifier_fail_closed as inplace_fixture


ROOT = Path(__file__).resolve().parent
VALIDATOR = Path("scripts/accept_jaa02_receipt.py")


def _git(root: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *argv),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _canonical(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


@pytest.fixture()
def certified_repository(
    request: pytest.FixtureRequest,
) -> Iterator[tuple[Path, inplace_fixture._FixtureBranch]]:
    case = "jaa02-command-tamper"
    with inplace_fixture._committed_inplace_branch(
        case,
        allowed_mutations={inplace_fixture.JAA02_REHASHED_RECEIPT_COMMIT},
        commit_sequence=inplace_fixture.JAA02_REHASHED_RECEIPT_COMMIT_SEQUENCE,
    ) as state:
        expected_receipt = Path(
            inplace_fixture.JAA02_INITIAL_RECEIPT_PATH
        ).relative_to("internal/jaa").as_posix()
        tracked_receipts = _git(
            ROOT, "ls-files", "runtime_evidence/jaa02/sha256-*.json"
        ).stdout.splitlines()
        assert tracked_receipts == [expected_receipt]
        yield ROOT, state


@pytest.mark.parametrize("attack", ["omission", "reordering"])
def test_jaa02_rehashed_command_omission_and_reordering_fail_closed(
    certified_repository: tuple[Path, inplace_fixture._FixtureBranch],
    attack: str,
) -> None:
    repository_root, state = certified_repository
    evidence = repository_root / "runtime_evidence" / "jaa02"
    receipt = next(evidence.glob("sha256-*.json"))
    old_path = receipt.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix()
    assert old_path == inplace_fixture.JAA02_INITIAL_RECEIPT_PATH
    document = json.loads(receipt.read_text(encoding="utf-8"))
    commands = document["command_semantics"]
    assert isinstance(commands, list) and len(commands) == 2
    if attack == "omission":
        commands.pop()
    else:
        commands.reverse()
    payload = _canonical(document)
    replacement = evidence / f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    replacement_path = replacement.relative_to(inplace_fixture.REPOSITORY_ROOT).as_posix()
    inplace_fixture._commit_rehashed_receipt_replacement(
        state,
        replacement_path,
        payload,
        f"command-{attack}",
    )

    rejected = subprocess.run(
        (sys.executable, str(VALIDATOR)),
        cwd=repository_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert rejected.returncode != 0
