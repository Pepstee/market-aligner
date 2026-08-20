"""Independent command-list tamper controls for the historical JAA-02 receipt."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent
VALIDATOR = Path("scripts/accept_jaa02_receipt.py")


def _git(root: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *argv), cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def _canonical(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


@pytest.fixture()
def certified_repository(tmp_path: Path) -> Path:
    clone = tmp_path / "certified"
    copied = subprocess.run(
        ("git", "clone", "--no-local", str(ROOT), str(clone)), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert copied.returncode == 0, copied.stderr
    assert _git(clone, "config", "user.name", "independent JAA-02 receipt tester").returncode == 0
    assert _git(clone, "config", "user.email", "jaa02-tester@example.test").returncode == 0
    return clone


@pytest.mark.parametrize("attack", ["omission", "reordering"])
def test_jaa02_rehashed_command_omission_and_reordering_fail_closed(
    certified_repository: Path,
    attack: str,
) -> None:
    evidence = certified_repository / "runtime_evidence" / "jaa02"
    receipt = next(evidence.glob("sha256-*.json"))
    document = json.loads(receipt.read_text(encoding="utf-8"))
    commands = document["command_semantics"]
    assert isinstance(commands, list) and len(commands) == 2
    if attack == "omission":
        commands.pop()
    else:
        commands.reverse()
    payload = _canonical(document)
    replacement = evidence / f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    receipt.unlink()
    replacement.write_bytes(payload)
    assert _git(certified_repository, "add", "-A", "--", "runtime_evidence/jaa02").returncode == 0
    assert _git(certified_repository, "commit", "-m", "tamper JAA-02 receipt").returncode == 0

    rejected = subprocess.run(
        (sys.executable, str(VALIDATOR)), cwd=certified_repository, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert rejected.returncode != 0
