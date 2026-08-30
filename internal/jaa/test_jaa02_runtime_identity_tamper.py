"""Black-box JAA-02 receipt identity tamper tests.

These checks intentionally use the checked-in validator through subprocesses.
Each attack is made in an isolated clone. The legacy receipt remains immutable
historical runtime evidence; current source is bound by the orchestrator's
scoped component certificate rather than this former whole-tree receipt.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from testing_repository import clone_jaa_repository


ROOT = Path(__file__).resolve().parent
VALIDATOR = "scripts/accept_jaa02_receipt.py"


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *arguments), cwd=root, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )


def _validate(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, VALIDATOR), cwd=root, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )


@pytest.fixture()
def certified_clone(tmp_path: Path) -> Path:
    clone = clone_jaa_repository(ROOT, tmp_path / "certified-clone")
    assert _git(clone, "config", "user.name", "JAA-02 independent tester").returncode == 0
    assert _git(clone, "config", "user.email", "jaa02-tester@example.test").returncode == 0
    return clone


def _receipt(root: Path) -> Path:
    receipts = list((root / "runtime_evidence" / "jaa02").glob("sha256-*.json"))
    assert len(receipts) == 1
    return receipts[0]


def _commit_runtime_evidence(root: Path, message: str) -> None:
    staged = _git(root, "add", "-A", "--", "runtime_evidence/jaa02")
    assert staged.returncode == 0, staged.stderr
    committed = _git(root, "commit", "-m", message)
    assert committed.returncode == 0, committed.stderr


def test_authentic_jaa02_historical_receipt_binds_runtime(certified_clone: Path) -> None:
    accepted = _validate(certified_clone)
    assert accepted.returncode == 0, accepted.stderr
    assert json.loads(accepted.stdout)["status"] == "accepted"


def test_unrelated_source_change_does_not_rewrite_historical_runtime_evidence(
    certified_clone: Path,
) -> None:
    readme = certified_clone / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "\nunrelated documentation\n", encoding="utf-8")
    assert _git(certified_clone, "add", "README.md").returncode == 0
    assert _git(certified_clone, "commit", "-m", "unrelated documentation").returncode == 0
    accepted = _validate(certified_clone)
    assert accepted.returncode == 0, accepted.stderr


def test_jaa02_validator_rejects_missing_receipt(certified_clone: Path) -> None:
    receipt = _receipt(certified_clone)
    removed = _git(certified_clone, "rm", "--", receipt.relative_to(certified_clone).as_posix())
    assert removed.returncode == 0, removed.stderr
    committed = _git(certified_clone, "commit", "-m", "remove JAA-02 receipt")
    assert committed.returncode == 0, committed.stderr

    rejected = _validate(certified_clone)
    assert rejected.returncode == 2
    assert "expected exactly one checked-in JAA-02 receipt, found 0" in rejected.stderr


def test_jaa02_validator_rejects_malformed_receipt(certified_clone: Path) -> None:
    receipt = _receipt(certified_clone)
    malformed = b"{ this is not valid JSON\n"
    receipt.write_bytes(malformed)
    renamed = receipt.with_name(f"sha256-{hashlib.sha256(malformed).hexdigest()}.json")
    receipt.rename(renamed)
    _commit_runtime_evidence(certified_clone, "replace JAA-02 receipt with malformed JSON")

    rejected = _validate(certified_clone)
    assert rejected.returncode == 2
    assert "invalid JAA-02 receipt JSON" in rejected.stderr


def test_jaa02_validator_rejects_rehashed_runtime_identity_mismatch(certified_clone: Path) -> None:
    receipt = _receipt(certified_clone)
    document = json.loads(receipt.read_text(encoding="utf-8"))
    runtime = document["runtime"]
    assert isinstance(runtime, dict)
    runtime["python_version"] = "0.0.0-forged-runtime"
    forged = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    replacement = receipt.with_name(f"sha256-{hashlib.sha256(forged).hexdigest()}.json")
    receipt.unlink()
    replacement.write_bytes(forged)
    _commit_runtime_evidence(certified_clone, "forge JAA-02 runtime identity")

    rejected = _validate(certified_clone)
    assert rejected.returncode == 2
    assert "JAA-02 runtime identity mismatch" in rejected.stderr
