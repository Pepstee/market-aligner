"""Independent black-box tamper controls for regenerated JAA-02 and JAA-03 receipts.

The checks use a clean clone of the certified tree.  This makes the authentic
receipt test meaningful even while the parent worktree contains test-author
changes, and ensures every attack is evaluated by the public acceptance entry
points rather than their internal helpers.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent
JAA02 = Path("scripts/accept_jaa02_receipt.py")
JAA03 = Path("scripts/accept_jaa03_receipt.py")


def _run(root: Path, *argv: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, *argv), cwd=cwd or root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def _shell(root: Path, command: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("/bin/sh", "-c", command), cwd=cwd, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def _git(root: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *argv), cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def _canonical(document: object) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _replace_receipt(root: Path, directory: str, document: dict[str, object]) -> Path:
    evidence = root / directory
    originals = list(evidence.glob("sha256-*.json"))
    assert len(originals) == 1
    payload = _canonical(document)
    replacement = evidence / f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    originals[0].unlink()
    replacement.write_bytes(payload)
    staged = _git(root, "add", "-A", "--", directory)
    assert staged.returncode == 0, staged.stderr
    committed = _git(root, "commit", "-m", "tamper receipt")
    assert committed.returncode == 0, committed.stderr
    return replacement


@pytest.fixture()
def certified_repository(tmp_path: Path) -> Path:
    clone = tmp_path / "certified"
    copied = subprocess.run(
        ("git", "clone", "--no-local", str(ROOT), str(clone)), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert copied.returncode == 0, copied.stderr
    assert _git(clone, "config", "user.name", "independent receipt tester").returncode == 0
    assert _git(clone, "config", "user.email", "tester@example.test").returncode == 0
    return clone


def test_acceptance_declaration_runs_directly_and_as_extracted_data(certified_repository: Path, tmp_path: Path) -> None:
    declaration = certified_repository / "acceptance"
    records = [
        line.strip() for line in declaration.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert len(records) == 1
    assert "-c" not in records[0] and "$0" not in records[0]

    # The declaration's execution contexts are tested with a deliberately
    # minimal declared runner.  Full commercial acceptance needs private
    # source-runtime configuration and is exercised independently by the
    # preserved acceptance suite.
    runner = certified_repository / "scripts" / "run_acceptance_declaration.py"
    runner.write_text("raise SystemExit(0)\n", encoding="utf-8")
    direct = subprocess.run(
        ("bash", str(declaration)), cwd=tmp_path, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert direct.returncode == 0, direct.stderr
    extracted = _shell(certified_repository, records[0], certified_repository)
    assert extracted.returncode == 0, extracted.stderr


def test_historical_receipt_acceptance_survives_a_later_source_revision(
    certified_repository: Path,
) -> None:
    jaa02 = _run(certified_repository, str(JAA02))
    jaa03 = _run(certified_repository, str(JAA03))
    assert jaa02.returncode == jaa03.returncode == 0, (jaa02.stderr, jaa03.stderr)

    readme = certified_repository / "README.md"
    readme.write_bytes(readme.read_bytes() + b"\nindependent source-revision drift\n")
    staged = _git(certified_repository, "add", "README.md")
    assert staged.returncode == 0, staged.stderr
    committed = _git(certified_repository, "commit", "-m", "source revision drift")
    assert committed.returncode == 0, committed.stderr

    assert _run(certified_repository, str(JAA02)).returncode == 0
    assert _run(certified_repository, str(JAA03)).returncode == 0


@pytest.mark.parametrize("attack", ["omission", "reordering"])
def test_jaa02_rehashed_command_omission_and_reordering_fail_closed(
    certified_repository: Path, attack: str,
) -> None:
    receipt = next((certified_repository / "runtime_evidence" / "jaa02").glob("sha256-*.json"))
    document = json.loads(receipt.read_text(encoding="utf-8"))
    commands = document["command_semantics"]
    assert isinstance(commands, list) and len(commands) == 2
    if attack == "omission":
        commands.pop()
    else:
        commands.reverse()
    _replace_receipt(certified_repository, "runtime_evidence/jaa02", document)
    rejected = _run(certified_repository, str(JAA02))
    assert rejected.returncode != 0


def test_jaa03_rehashed_runtime_identity_substitution_fails_closed(certified_repository: Path) -> None:
    """A content-addressed filename alone must not authenticate the runtime."""
    receipt = next((certified_repository / "runtime_evidence" / "jaa03").glob("sha256-*.json"))
    document = json.loads(receipt.read_text(encoding="utf-8"))
    runtime = document["runtime"]
    assert isinstance(runtime, dict)
    runtime["python_version"] = "0.0.0-attacker"
    _replace_receipt(certified_repository, "runtime_evidence/jaa03", document)
    rejected = _run(certified_repository, str(JAA03))
    assert rejected.returncode != 0, rejected.stdout


@pytest.mark.parametrize("attack", ["byte_tamper", "rehashed_result_tamper"])
def test_jaa03_receipt_tampering_fails_closed(certified_repository: Path, attack: str) -> None:
    receipt = next((certified_repository / "runtime_evidence" / "jaa03").glob("sha256-*.json"))
    if attack == "byte_tamper":
        receipt.write_bytes(receipt.read_bytes() + b" ")
    else:
        document = json.loads(receipt.read_text(encoding="utf-8"))
        result = document["acceptance_result"]
        assert isinstance(result, dict)
        result["metrics_hash"] = "sha256:" + "0" * 64
        _replace_receipt(certified_repository, "runtime_evidence/jaa03", document)
    rejected = _run(certified_repository, str(JAA03))
    assert rejected.returncode != 0, rejected.stdout
