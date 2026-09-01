"""Black-box controls for the non-self-invalidating JAA-03 evidence validator."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from testing_repository import clone_jaa_repository

ROOT = Path(__file__).resolve().parent
VALIDATOR = "scripts/accept_jaa03_receipt.py"


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *arguments), cwd=root, text=True, capture_output=True, check=False
    )


def _validate(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, VALIDATOR),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.fixture()
def certified_clone(tmp_path: Path) -> Path:
    clone = clone_jaa_repository(ROOT, tmp_path / "certified-clone")
    assert _git(clone, "config", "user.name", "JAA-03 receipt tester").returncode == 0
    assert (
        _git(clone, "config", "user.email", "jaa03-receipt@example.test").returncode
        == 0
    )
    return clone


def _receipt(root: Path) -> Path:
    receipts = list((root / "runtime_evidence" / "jaa03").glob("sha256-*.json"))
    assert len(receipts) == 1
    return receipts[0]


def test_authentic_historical_receipt_and_unrelated_change_remain_valid(
    certified_clone: Path,
) -> None:
    assert _validate(certified_clone).returncode == 0
    readme = certified_clone / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8") + "\nunrelated docs\n", encoding="utf-8"
    )
    assert _git(certified_clone, "add", "README.md").returncode == 0
    assert _git(certified_clone, "commit", "-m", "unrelated docs").returncode == 0
    accepted = _validate(certified_clone)
    assert accepted.returncode == 0, accepted.stderr


def test_rehashed_runtime_substitution_is_rejected(certified_clone: Path) -> None:
    receipt = _receipt(certified_clone)
    document = json.loads(receipt.read_text(encoding="utf-8"))
    document["runtime"]["python_version"] = "0.0.0-forged"
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    replacement = receipt.with_name(
        f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    )
    receipt.unlink()
    replacement.write_bytes(payload)
    assert (
        _git(certified_clone, "add", "-A", "--", "runtime_evidence/jaa03").returncode
        == 0
    )
    assert _git(certified_clone, "commit", "-m", "forge runtime").returncode == 0
    rejected = _validate(certified_clone)
    assert rejected.returncode == 2
    assert "runtime identity mismatch" in rejected.stderr
