"""Independent black-box checks for the JAA-04 Increment A certifier.

The controls run against committed clones: a clean-source certifier must reject
committed bad inputs too, not merely uncommitted working-tree changes.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
CERTIFIER = "scripts/certify_jaa04_increment_a.py"
SUITES = (
    "test_jaa04_increment_a_authority_canaries.py",
    "test_jaa04_increment_a_temporal_authority_regression.py",
    "test_jaa04_sidecar_temporal_semantics.py",
    "test_jaa04_portable_authority_contract.py",
)


def _run(directory: Path, *argv: str, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=directory, text=True, capture_output=True,
                          check=False, timeout=timeout)


def _clone(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    copied = _run(
        REPOSITORY_ROOT, "git", "clone", "--no-local",
        str(REPOSITORY_ROOT), str(repository), timeout=120,
    )
    assert copied.returncode == 0, copied.stderr
    clone = repository / "internal" / "jaa"
    configured = _run(clone, "git", "config", "user.email", "tester@example.invalid")
    assert configured.returncode == 0, configured.stderr
    configured = _run(clone, "git", "config", "user.name", "Independent tester")
    assert configured.returncode == 0, configured.stderr
    return clone


def _commit(clone: Path, path: str) -> None:
    staged = _run(clone, "git", "add", path)
    assert staged.returncode == 0, staged.stderr
    committed = _run(clone, "git", "commit", "-m", "adversarial certification control")
    assert committed.returncode == 0, committed.stderr


def _certify(clone: Path) -> tuple[subprocess.CompletedProcess[str], Path]:
    receipt_directory = clone / "runtime_evidence" / "independent-jaa04-increment-a"
    return _run(clone, sys.executable, CERTIFIER, "--receipt", str(receipt_directory)), receipt_directory


def _rejects(clone: Path) -> None:
    result, directory = _certify(clone)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "JAA-04 Increment A certification: ERROR:" in result.stderr
    assert not list(directory.glob("sha256-*.json"))


def test_clean_certifier_records_each_required_suite_and_all_thirteen_portable_contracts(tmp_path: Path) -> None:
    clone = _clone(tmp_path)
    result, directory = _certify(clone)
    assert result.returncode == 0, result.stdout + result.stderr
    receipts = list(directory.glob("sha256-*.json"))
    assert len(receipts) == 1
    payload = receipts[0].read_bytes()
    receipt = json.loads(payload)
    assert receipts[0].name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    assert receipt["status"] == "SUCCESS"
    assert receipt["source_revision"] == _run(clone, "git", "rev-parse", "HEAD").stdout.strip()
    results = receipt["executed_suite_results"]
    assert [row["suite"] for row in results] == list(SUITES)
    assert sum(row["passed"] for row in results) == 47
    assert all(row["exit_code"] == row["failed"] == row["errors"] == row["skipped"] == 0 for row in results)
    portable = next(row for row in results if row["suite"] == SUITES[-1])
    assert portable["passed"] == 13


def test_omitted_required_suite_fails_closed(tmp_path: Path) -> None:
    clone = _clone(tmp_path)
    certifier = clone / CERTIFIER
    text = certifier.read_text(encoding="utf-8")
    text = text.replace('    "test_jaa04_sidecar_temporal_semantics.py",\n', "")
    certifier.write_text(text.replace("EXPECTED_TESTS = 47", "EXPECTED_TESTS = 44"), encoding="utf-8")
    _commit(clone, CERTIFIER)
    _rejects(clone)


def test_failed_suite_fails_closed(tmp_path: Path) -> None:
    clone = _clone(tmp_path)
    suite = clone / SUITES[0]
    suite.write_text(suite.read_text(encoding="utf-8") + "\n\ndef test_independent_failure_control():\n    assert False\n", encoding="utf-8")
    _commit(clone, SUITES[0])
    _rejects(clone)


def test_skipped_suite_outcome_fails_closed(tmp_path: Path) -> None:
    clone = _clone(tmp_path)
    suite = clone / SUITES[0]
    suite.write_text(suite.read_text(encoding="utf-8") + "\n\nimport pytest\n\n@pytest.mark.skip(reason='independent control')\ndef test_independent_skip_control():\n    pass\n", encoding="utf-8")
    _commit(clone, SUITES[0])
    _rejects(clone)


def test_unknown_xfail_outcome_fails_closed(tmp_path: Path) -> None:
    clone = _clone(tmp_path)
    suite = clone / SUITES[0]
    suite.write_text(suite.read_text(encoding="utf-8") + "\n\nimport pytest\n\n@pytest.mark.xfail(reason='independent control')\ndef test_independent_unknown_outcome_control():\n    assert False\n", encoding="utf-8")
    _commit(clone, SUITES[0])
    _rejects(clone)


def test_acceptance_declaration_is_data_without_command_substitution() -> None:
    declaration = ROOT / "acceptance"
    lines = [line.strip() for line in declaration.read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    assert lines and all("$(" not in line and "`" not in line for line in lines), (
        "acceptance declarations are data: each command must be directly executable "
        "from the project root without command substitution"
    )


def test_existing_receipt_tampering_fails_closed(tmp_path: Path) -> None:
    clone = _clone(tmp_path)
    result, directory = _certify(clone)
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = next(directory.glob("sha256-*.json"))
    receipt.write_bytes(receipt.read_bytes() + b" tampered")
    tampered = receipt.read_bytes()
    rejected, _ = _certify(clone)
    assert rejected.returncode != 0
    assert "JAA-04 Increment A certification: ERROR:" in rejected.stderr
    assert receipt.read_bytes() == tampered
    assert receipt.name != f"sha256-{hashlib.sha256(tampered).hexdigest()}.json"
