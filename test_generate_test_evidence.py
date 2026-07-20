"""Adversarial tests for the public test-evidence receipt generator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
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


def _identity_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "identity-repository"
    root.mkdir()
    (root / "product.txt").write_bytes(b"product\n")
    subprocess.run(("git", "init", "-q"), cwd=root, check=True)
    subprocess.run(("git", "add", "product.txt"), cwd=root, check=True)
    subprocess.run(
        ("git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "product snapshot"), cwd=root, check=True,
    )
    monkeypatch.setattr(GENERATOR_MODULE, "ROOT", root)
    return root


def _public_generator(
    tmp_path: Path, complete_output: str, career_output: str
) -> subprocess.CompletedProcess[str]:
    """Execute an unmodified copy through its documented script entry point."""
    root = tmp_path / "isolated-repository"
    script = root / "scripts" / GENERATOR.name
    script.parent.mkdir(parents=True)
    shutil.copy2(GENERATOR, script)
    (root / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q"), cwd=root, check=True)
    subprocess.run(("git", "add", ".gitignore", "scripts"), cwd=root, check=True)
    subprocess.run(
        (
            "git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", "product snapshot",
        ),
        cwd=root,
        check=True,
    )

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

    return subprocess.run(
        (sys.executable, str(script)), cwd=root, text=True,
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


def test_product_revision_is_stable_across_excluded_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _identity_repository(tmp_path, monkeypatch)
    revision = GENERATOR_MODULE.product_content_revision()
    receipt = root / "runtime_evidence" / "pytest" / "receipt.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text("{}\n", encoding="utf-8")
    subprocess.run(("git", "add", "-f", str(receipt.relative_to(root))), cwd=root, check=True)
    assert GENERATOR_MODULE.product_content_revision() == revision


@pytest.mark.parametrize("condition", ["dirty", "untracked", "missing", "symlink"])
def test_product_revision_refuses_incomplete_or_unsafe_trees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, condition: str
) -> None:
    root = _identity_repository(tmp_path, monkeypatch)
    product = root / "product.txt"
    if condition == "dirty":
        product.write_bytes(b"changed\n")
    elif condition == "untracked":
        (root / "new-product.py").write_bytes(b"print('untracked')\n")
    elif condition == "missing":
        product.unlink()
    else:
        product.unlink()
        product.symlink_to("target.txt")
    with pytest.raises(GENERATOR_MODULE.EvidenceError):
        GENERATOR_MODULE.product_content_revision()


def test_public_script_writes_hashed_content_revision_bound_and_redacted_receipt(
    tmp_path: Path,
) -> None:
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
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", document["tested_product_content_revision"])
    assert re.fullmatch(r"[0-9a-f]{40,64}", document["tested_git_parent"])
    assert "tested_source_revision" not in document
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
