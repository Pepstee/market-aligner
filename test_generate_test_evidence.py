"""Adversarial tests for the public test-evidence receipt generator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPOSITORY = Path(__file__).resolve().parent
GENERATOR = REPOSITORY / "scripts" / "generate-test-evidence.py"


def _generator_module():
    spec = importlib.util.spec_from_file_location("test_evidence_generator", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR_MODULE = _generator_module()


def _public_generator(tmp_path: Path, complete_output: str, career_output: str) -> subprocess.CompletedProcess[str]:
    """Execute an unmodified copy through its documented script entry point."""
    root = tmp_path / "isolated-repository"
    script = root / "scripts" / GENERATOR.name
    script.parent.mkdir(parents=True)
    shutil.copy2(GENERATOR, script)

    python = root / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in\n"
        f"  *career_automation*) printf '%s\\n' {career_output!r} ;;\n"
        f"  *) printf '%s\\n' {complete_output!r} ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    python.chmod(0o755)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    git = fake_bin / "git"
    git.write_text(f"#!/bin/sh\nprintf '%s\\n' '{'a' * 40}'\n", encoding="utf-8")
    git.chmod(0o755)
    environment = os.environ | {"PATH": f"{fake_bin}:{os.environ['PATH']}"}
    return subprocess.run(
        (sys.executable, str(script)), cwd=root, env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def test_parse_summary_requires_exact_supported_totals() -> None:
    assert GENERATOR_MODULE.parse_summary("================ 12 passed, 3 skipped in 0.42s ================\n") == {
        "collected": 15, "passed": 12, "skipped": 3, "failed": 0,
    }


@pytest.mark.parametrize("output", [
    "================ 1 failed, 4 passed in 0.01s ================\n",
    "pytest output without a final summary\n",
    "================ 4 passed, 1 xfailed in 0.01s ================\n",
])
def test_parse_summary_refuses_failed_or_malformed_output(output: str) -> None:
    with pytest.raises(GENERATOR_MODULE.EvidenceError):
        GENERATOR_MODULE.parse_summary(output)


def test_public_script_writes_hashed_revision_bound_and_redacted_receipt(tmp_path: Path) -> None:
    private_path = "/Users/receipt-test-user/private-worktree"
    secret = "TOP-SECRET-RECEIPT-TOKEN"
    completed = _public_generator(
        tmp_path,
        f"runner diagnostic: {private_path} token={secret}\n"
        "================ 70 passed, 5 skipped in 0.10s ================",
        "================ 65 passed in 0.05s ================",
    )
    assert completed.returncode == 0, completed.stderr
    root = tmp_path / "isolated-repository"
    receipt = root / completed.stdout.strip()
    payload = receipt.read_bytes()
    document = json.loads(payload)

    assert receipt.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    assert document["tested_source_revision"] == "a" * 40
    complete, career = document["suites"]
    assert complete["name"] == "complete"
    assert complete["counts"] == {"collected": 75, "passed": 70, "skipped": 5, "failed": 0}
    assert "historical_baseline_passed" not in complete
    assert career["name"] == "career_automation"
    assert career["counts"] == {"collected": 65, "passed": 65, "skipped": 0, "failed": 0}
    assert career["historical_baseline_passed"] == 65
    rendered = payload.decode("utf-8")
    assert str(Path.home()) not in rendered
    assert private_path not in rendered
    assert secret not in rendered


@pytest.mark.parametrize("complete_output", [
    "================ 1 failed, 4 passed in 0.01s ================",
    "not a pytest summary",
])
def test_public_script_refuses_failed_or_unparseable_suite_without_receipt(
    tmp_path: Path, complete_output: str
) -> None:
    completed = _public_generator(
        tmp_path, complete_output, "================ 65 passed in 0.01s ================",
    )
    assert completed.returncode == 1
    assert "test evidence rejected:" in completed.stderr
    evidence_directory = tmp_path / "isolated-repository" / "runtime_evidence"
    assert not evidence_directory.exists() or not list(evidence_directory.rglob("*.json"))
