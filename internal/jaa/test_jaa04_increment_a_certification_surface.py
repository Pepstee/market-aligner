"""Black-box certification-surface tests for JAA-04 Increment A.

Each certifier probe runs in a committed clone.  That is intentional: the
certifier correctly treats an uncommitted mutation as dirty source, whereas a
committed malicious change tests the validation that follows the clean-source
check.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

import pytest


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
CERTIFIER = ("scripts/certify_jaa04_increment_a.py",)
FOCUSED_SUITES = (
    "test_jaa04_increment_a_authority_canaries.py",
    "test_jaa04_increment_a_temporal_authority_regression.py",
    "test_jaa04_sidecar_temporal_semantics.py",
    "test_jaa04_portable_authority_contract.py",
)
def _run(directory: Path, *argv: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=directory, text=True, capture_output=True,
                          check=False, timeout=timeout)


def _clone(tmp_path: Path) -> Path:
    repository = tmp_path / "clean-certifier"
    copied = _run(
        REPOSITORY_ROOT, "git", "clone", "--no-local",
        str(REPOSITORY_ROOT), str(repository), timeout=120,
    )
    assert copied.returncode == 0, copied.stderr
    return repository / "internal" / "jaa"


def _commit(clone: Path, *paths: str) -> None:
    configured = _run(clone, "git", "config", "user.email", "certifier-test@example.invalid")
    assert configured.returncode == 0, configured.stderr
    configured = _run(clone, "git", "config", "user.name", "Certification Test")
    assert configured.returncode == 0, configured.stderr
    staged = _run(clone, "git", "add", *paths)
    assert staged.returncode == 0, staged.stderr
    committed = _run(clone, "git", "commit", "-m", "committed adversarial certifier control")
    assert committed.returncode == 0, committed.stderr


def _canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def _mutate_canary(clone: Path, mutate: Callable[[dict[str, object]], None]) -> None:
    path = clone / "career_automation/fixtures/jaa04_authority_canaries/greenhouse.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    path.write_bytes(_canonical(document))
    _commit(clone, str(path.relative_to(clone)))


def _certify(clone: Path, receipt: Path) -> subprocess.CompletedProcess[str]:
    return _run(clone, sys.executable, *CERTIFIER, "--receipt", str(receipt))


def _assert_rejected_without_receipt(result: subprocess.CompletedProcess[str], receipt: Path) -> None:
    assert result.returncode != 0
    assert "JAA-04 Increment A certification: ERROR:" in result.stderr
    assert not receipt.exists() or not list(receipt.glob("sha256-*.json"))


def test_current_temporal_contract_and_focused_suites_pass_in_clean_clone(
    tmp_path: Path,
) -> None:
    """The current independent contract remains runnable from committed bytes."""
    clone = _clone(tmp_path)
    result = _run(clone, sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                  "test_jaa04_increment_a_temporal_provenance_certification.py", *FOCUSED_SUITES,
                  timeout=360)
    assert result.returncode == 0, result.stdout + result.stderr


def test_clean_certifier_emits_one_content_addressed_revision_bound_receipt_and_pass_marker(
    tmp_path: Path,
) -> None:
    clone = _clone(tmp_path)
    receipt_directory = tmp_path / "receipt"
    first = _certify(clone, receipt_directory)
    assert first.returncode == 0, first.stderr
    receipts = list(receipt_directory.glob("sha256-*.json"))
    assert len(receipts) == 1
    payload = receipts[0].read_bytes()
    document = json.loads(payload)
    assert receipts[0].name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    assert document["status"] == "SUCCESS"
    assert document["source_revision"] == _run(clone, "git", "rev-parse", "HEAD").stdout.strip()
    assert document["executed_suite_results"]
    assert {row["suite"] for row in document["executed_suite_results"]} == set(FOCUSED_SUITES)
    assert "JAA-04 Increment A certification: PASS" in first.stdout


@pytest.mark.parametrize("attack", (
    "embedded-byte-tampering", "digest-mismatch", "reference-mismatch",
    "timestamp-field-substitution", "sidecar-body-disagreement",
))
def test_committed_canary_tampering_fails_closed_and_suppresses_receipt(
    tmp_path: Path, attack: str,
) -> None:
    clone = _clone(tmp_path)

    def mutate(document: dict[str, object]) -> None:
        row = document["captures"][0]  # type: ignore[index]
        assert isinstance(row, dict)
        if attack == "embedded-byte-tampering":
            raw = base64.b64decode(row["raw_response_base64"])
            row["raw_response_base64"] = base64.b64encode(raw + b" ").decode("ascii")
        elif attack == "digest-mismatch":
            row["content_sha256"] = "0" * 64
        elif attack == "reference-mismatch":
            row["sidecar_raw_response_ref"] = "sha256/00/" + "0" * 64
        elif attack == "timestamp-field-substitution":
            row["published_at"], row["updated_at"] = row.get("updated_at"), row.get("published_at")
        else:
            raw = base64.b64decode(row["raw_response_base64"])
            row["content_sha256"] = hashlib.sha256(raw + b"different sidecar body").hexdigest()
            row["sidecar_raw_response_ref"] = "sha256/" + row["content_sha256"][:2] + "/" + row["content_sha256"]

    _mutate_canary(clone, mutate)
    _assert_rejected_without_receipt(_certify(clone, tmp_path / "receipt"), tmp_path / "receipt")


@pytest.mark.parametrize("attack", ("missing", "extra"))
def test_canary_cardinality_controls_fail_closed_and_suppress_receipt(tmp_path: Path, attack: str) -> None:
    clone = _clone(tmp_path)
    directory = clone / "career_automation/fixtures/jaa04_authority_canaries"
    if attack == "missing":
        (directory / "ashby.json").unlink()
        _commit(clone, "career_automation/fixtures/jaa04_authority_canaries/ashby.json")
    else:
        shutil.copyfile(directory / "greenhouse.json", directory / "unexpected.json")
        _commit(clone, "career_automation/fixtures/jaa04_authority_canaries/unexpected.json")
    _assert_rejected_without_receipt(_certify(clone, tmp_path / "receipt"), tmp_path / "receipt")


def test_dirty_source_state_fails_closed_and_suppresses_receipt(tmp_path: Path) -> None:
    clone = _clone(tmp_path)
    (clone / "career_automation" / "dirty-certifier-control.txt").write_text("uncommitted\n")
    _assert_rejected_without_receipt(_certify(clone, tmp_path / "receipt"), tmp_path / "receipt")


def test_failed_focused_suite_suppresses_receipt(tmp_path: Path) -> None:
    clone = _clone(tmp_path)
    suite = clone / FOCUSED_SUITES[0]
    suite.write_text(suite.read_text() + "\n\ndef test_certifier_negative_control_failure():\n    assert False\n")
    _commit(clone, FOCUSED_SUITES[0])
    _assert_rejected_without_receipt(_certify(clone, tmp_path / "receipt"), tmp_path / "receipt")


def test_full_jaa04_gate_fails_closed_without_external_capture_and_policy(tmp_path: Path) -> None:
    clone = _clone(tmp_path)
    manifest = json.loads((ROOT / "ASSURANCE_MANIFEST.json").read_text(encoding="utf-8"))
    corpus = next(
        row for row in manifest["components"]["JAA-04"]["evidence"]
        if row["scope"] == "JAA-04-corpus"
    )
    assert corpus["argv"] == [
        "{python}",
        "scripts/accept_jaa_04.py",
        "--capture",
        "{external_jaa04_corpus}",
        "--access-policy",
        "{external_jaa04_access_policy}",
        "--receipt",
        "{external_jaa04_receipts}",
    ]
    receipt = tmp_path / "receipt"
    absent = tmp_path / "deliberately-absent-external-input.json"
    for supplied, required in (
        (("--capture", str(absent)), "--access-policy"),
        (("--access-policy", str(absent)), "--capture"),
        (
            (
                "--capture",
                str(absent),
                "--access-policy",
                str(absent),
            ),
            "--receipt",
        ),
    ):
        receipt_args = () if required == "--receipt" else ("--receipt", str(receipt))
        result = _run(
            clone,
            sys.executable,
            "scripts/accept_jaa_04.py",
            *supplied,
            *receipt_args,
        )
        assert result.returncode != 0
        assert required in result.stderr
        assert "PASS" not in result.stdout
        assert not receipt.exists()
