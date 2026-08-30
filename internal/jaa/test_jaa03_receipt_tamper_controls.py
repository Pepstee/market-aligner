"""Independent black-box tamper controls for immutable JAA-03 runtime evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from testing_repository import clone_jaa_repository


ROOT = Path(__file__).resolve().parent
VALIDATOR = Path("scripts/accept_jaa03_receipt.py")


def _run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, str(VALIDATOR)), cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


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
    clone = clone_jaa_repository(ROOT, tmp_path / "certified")
    assert _git(clone, "config", "user.name", "independent JAA-03 receipt tester").returncode == 0
    assert _git(clone, "config", "user.email", "jaa03-tester@example.test").returncode == 0
    return clone


def _replace_receipt(root: Path, document: dict[str, object]) -> Path:
    evidence = root / "runtime_evidence" / "jaa03"
    originals = list(evidence.glob("sha256-*.json"))
    assert len(originals) == 1
    payload = _canonical(document)
    replacement = evidence / f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    originals[0].unlink()
    replacement.write_bytes(payload)
    assert _git(root, "add", "-A", "--", "runtime_evidence/jaa03").returncode == 0
    assert _git(root, "commit", "-m", "tamper JAA-03 receipt").returncode == 0
    return replacement


def test_historical_receipt_acceptance_survives_a_later_source_revision(
    certified_repository: Path,
) -> None:
    accepted = _run(certified_repository)
    assert accepted.returncode == 0, accepted.stderr
    readme = certified_repository / "README.md"
    readme.write_bytes(readme.read_bytes() + b"\nindependent source-revision drift\n")
    assert _git(certified_repository, "add", "README.md").returncode == 0
    assert _git(certified_repository, "commit", "-m", "later source revision").returncode == 0
    accepted = _run(certified_repository)
    assert accepted.returncode == 0, accepted.stderr


def test_jaa03_rehashed_runtime_identity_substitution_fails_closed(
    certified_repository: Path,
) -> None:
    receipt = next((certified_repository / "runtime_evidence" / "jaa03").glob("sha256-*.json"))
    document = json.loads(receipt.read_text(encoding="utf-8"))
    runtime = document["runtime"]
    assert isinstance(runtime, dict)
    runtime["python_version"] = "0.0.0-attacker"
    _replace_receipt(certified_repository, document)
    rejected = _run(certified_repository)
    assert rejected.returncode != 0, rejected.stdout


@pytest.mark.parametrize("attack", ["byte_tamper", "rehashed_result_tamper"])
def test_jaa03_receipt_tampering_fails_closed(
    certified_repository: Path,
    attack: str,
) -> None:
    receipt = next((certified_repository / "runtime_evidence" / "jaa03").glob("sha256-*.json"))
    if attack == "byte_tamper":
        receipt.write_bytes(receipt.read_bytes() + b" ")
    else:
        document = json.loads(receipt.read_text(encoding="utf-8"))
        result = document["acceptance_result"]
        assert isinstance(result, dict)
        result["metrics_hash"] = "sha256:" + "0" * 64
        _replace_receipt(certified_repository, document)
    rejected = _run(certified_repository)
    assert rejected.returncode != 0, rejected.stdout
