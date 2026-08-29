"""Adversarial, independent certification tests for JAA-04 Increment A.

The tests deliberately use committed clones: a clean working tree is a
precondition of certification, so each control must be able to get past that
precondition before the certifier rejects it.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
CERTIFIER = "scripts/certify_jaa04_increment_a.py"
INVENTORY = "scripts/jaa04_increment_a_test_inventory.json"
TEMPORAL_SUITE = "test_jaa04_sidecar_temporal_semantics.py"


def _run(
    directory: Path,
    *argv: str,
    timeout: int = 240,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=directory,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
        env=env,
    )


def _clone(tmp_path: Path) -> Path:
    repository = tmp_path / "certifier-clone"
    result = _run(
        REPOSITORY_ROOT, "git", "clone", "--no-local", "--single-branch", "--depth", "1",
        str(REPOSITORY_ROOT), str(repository), timeout=120,
    )
    assert result.returncode == 0, result.stderr
    clone = repository / "internal" / "jaa"
    for key, value in (
        ("user.email", "independent@example.invalid"),
        ("user.name", "Independent certification tester"),
    ):
        result = _run(clone, "git", "config", key, value)
        assert result.returncode == 0, result.stderr
    return clone


def _commit(clone: Path, *paths: str) -> None:
    result = _run(clone, "git", "add", *paths)
    assert result.returncode == 0, result.stderr
    result = _run(clone, "git", "commit", "-m", "independent adversarial control")
    assert result.returncode == 0, result.stderr


def _certify(clone: Path, receipt: Path) -> subprocess.CompletedProcess[str]:
    return _run(clone, sys.executable, CERTIFIER, "--receipt", str(receipt))


def _assert_rejected(clone: Path, receipt: Path) -> None:
    result = _certify(clone, receipt)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "JAA-04 Increment A certification: ERROR:" in result.stderr
    assert not list(receipt.glob("sha256-*.json"))


@pytest.mark.parametrize(
    "outcome", ("skipped", "xfailed", "xpassed", "failed", "error", "deselected")
)
def test_every_non_passing_pytest_outcome_reaches_and_is_rejected_by_certifier(
    tmp_path: Path, outcome: str
) -> None:
    """Inject one real pytest outcome without changing the pinned 47-suite bytes."""
    clone = _clone(tmp_path)
    hook = clone / "conftest.py"
    hook.write_text(
        f'''\
import pytest

MODE = {outcome!r}

def _target(item):
    return item.nodeid.startswith("test_jaa04_increment_a_authority_canaries.py::")

def pytest_collection_modifyitems(config, items):
    target = next(item for item in items if _target(item))
    if MODE == "xpassed":
        target.add_marker(pytest.mark.xfail(reason="independent xpass control"))
    elif MODE == "deselected":
        items.remove(target)
        config.hook.pytest_deselected(items=[target])

def pytest_runtest_setup(item):
    if _target(item) and MODE == "skipped":
        pytest.skip("independent skip control")

def pytest_runtest_call(item):
    if not _target(item):
        return
    if MODE == "xfailed":
        pytest.xfail("independent xfail control")
    if MODE == "failed":
        pytest.fail("independent failure control")
    if MODE == "error":
        raise RuntimeError("independent error control")
''',
        encoding="utf-8",
    )
    _commit(clone, "conftest.py")
    _assert_rejected(clone, tmp_path / "receipt")


def test_omitting_temporal_semantics_and_lowering_legacy_count_cannot_mint_success(
    tmp_path: Path,
) -> None:
    clone = _clone(tmp_path)
    certifier = clone / CERTIFIER
    source = certifier.read_text(encoding="utf-8")
    source = source.replace(f'    "{TEMPORAL_SUITE}",\n', "")
    certifier.write_text(
        source.replace("EXPECTED_TESTS = 47", "EXPECTED_TESTS = 44"), encoding="utf-8"
    )
    _commit(clone, CERTIFIER)
    _assert_rejected(clone, tmp_path / "receipt")


@pytest.mark.parametrize("target", ("inventory", "source"))
def test_committed_inventory_and_canonical_suite_tampering_are_rejected(
    tmp_path: Path, target: str
) -> None:
    clone = _clone(tmp_path)
    if target == "inventory":
        path = clone / INVENTORY
        path.write_bytes(path.read_bytes() + b"\n")
        changed = INVENTORY
    else:
        path = clone / TEMPORAL_SUITE
        path.write_text(
            path.read_text(encoding="utf-8") + "\n# committed control\n", encoding="utf-8"
        )
        changed = TEMPORAL_SUITE
    _commit(clone, changed)
    _assert_rejected(clone, tmp_path / "receipt")


def test_authentic_run_is_revision_bound_content_addressed_and_rejects_receipt_tampering(
    tmp_path: Path,
) -> None:
    clone = _clone(tmp_path)
    receipt_directory = tmp_path / "receipt"
    result = _certify(clone, receipt_directory)
    assert result.returncode == 0, result.stdout + result.stderr
    receipts = list(receipt_directory.glob("sha256-*.json"))
    assert len(receipts) == 1
    receipt = receipts[0]
    payload = receipt.read_bytes()
    document = json.loads(payload)
    assert receipt.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    assert document["status"] == "SUCCESS"
    assert document["source_revision"] == _run(
        clone, "git", "rev-parse", "HEAD"
    ).stdout.strip()
    tampered = payload + b"tampered"
    receipt.write_bytes(tampered)
    rejected = _certify(clone, receipt_directory)
    assert rejected.returncode != 0, rejected.stdout + rejected.stderr
    assert "JAA-04 Increment A certification: ERROR:" in rejected.stderr
    # A failed recertification must not overwrite or silently repair evidence.
    assert receipt.read_bytes() == tampered


def test_each_root_acceptance_declaration_is_executable_from_root_and_directly_when_supported(
    tmp_path: Path,
) -> None:
    """The declaration is data: extracted lines receive a root working directory."""
    # Root acceptance runs the complete pytest suite. Mark that child so this
    # test becomes a successful leaf instead of recursively invoking acceptance.
    if (
        os.environ.get("JAA04_ACCEPTANCE_DECLARATION_CHILD") == "1"
        or os.environ.get("AGENTIC_PROJECT_TEST_GATE_ACTIVE") == "1"
        or os.environ.get("AGENTIC_ACCEPTANCE_GATE_ACTIVE") == "1"
    ):
        return
    child_environment = os.environ.copy()
    child_environment["JAA04_ACCEPTANCE_DECLARATION_CHILD"] = "1"
    declaration = ROOT / "acceptance"
    commands = [
        line.strip()
        for line in declaration.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert commands
    for command in commands:
        extracted = _run(
            ROOT, "bash", "-c", command, timeout=900, env=child_environment
        )
        # Increment B's receipt is intentionally absent; a declaration may therefore
        # fail closed, but it must run rather than fail due to shell/path syntax.
        assert "No such file or directory" not in extracted.stderr
        direct = subprocess.run(
            [str(declaration)],
            cwd=tmp_path,
            text=True,
            capture_output=True,
            check=False,
            timeout=900,
            env=child_environment,
        )
        assert direct.returncode == extracted.returncode
        assert "No such file or directory" not in direct.stderr
