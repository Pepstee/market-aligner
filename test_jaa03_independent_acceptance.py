"""Independent black-box acceptance checks for the JAA-03 certificate.

These checks deliberately reconstruct the receipt contract instead of invoking
the certifier's helpers.  They exercise a disposable Git checkout so a receipt
is always bound to the exact revision that produced it.
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent
CERTIFIER = Path("scripts/accept_jaa_03.py")
LOCKED_SET = Path("career_automation/fixtures/jaa03_vacancies.json")
LOCKED_METRICS = Path("career_automation/fixtures/jaa03_locked_metrics.json")
FORMAT = "jaa03-revision-certification/v1"
LOCKED_SET_AUTHORITY_HASH = "sha256:b1f4b1386903b1f9de437fcccde21872f449f70ea63d374aed4229b87b588d4e"
EXPECTED_POLICY = {
    "minimum_confidence_bp": 7_500,
    "minimum_opportunity_bp": 5_500,
    "weights": [45, 35, 20],
}


def _run(root: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (sys.executable, *argv), cwd=root, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )


def _git(root: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("git", *argv), cwd=root, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )


@pytest.fixture(scope="module")
def repository(tmp_path_factory: pytest.TempPathFactory) -> Path:
    clone = tmp_path_factory.mktemp("jaa03-repository") / "repository"
    copied = subprocess.run(
        ("git", "clone", "--no-local", str(ROOT), str(clone)), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert copied.returncode == 0, copied.stderr
    assert _git(clone, "config", "user.name", "JAA-03 independent test").returncode == 0
    assert _git(clone, "config", "user.email", "jaa03@example.test").returncode == 0
    shutil.rmtree(clone / "runtime_evidence" / "jaa03", ignore_errors=True)
    return clone


def _canonical(document: object) -> bytes:
    return (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _content_hash(document: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _certify(root: Path) -> tuple[Path, dict[str, object]]:
    completed = _run(root, str(CERTIFIER))
    assert completed.returncode == 0, completed.stderr
    response = json.loads(completed.stdout)
    assert response == {"receipt": response["receipt"], "status": "PASS"}
    receipt = root / Path(response["receipt"])
    assert receipt.is_file()
    return receipt, json.loads(receipt.read_text(encoding="utf-8"))


def _verify_receipt(root: Path, receipt: Path) -> None:
    """Independent verifier for the immutable JAA-03 receipt contract."""
    payload = receipt.read_bytes()
    document = json.loads(payload)
    assert receipt.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    assert payload == _canonical(document)
    assert document["format"] == FORMAT
    assert document["status"] == "PASS"
    origin = document["source_revision"]
    assert isinstance(origin, str) and len(origin) == 40
    assert _git(root, "rev-parse", "--verify", f"{origin}^{{commit}}").returncode == 0
    assert _git(root, "merge-base", "--is-ancestor", origin, "HEAD").returncode == 0
    # This command is intentionally outside the certifier and binds every
    # tracked product byte except generated runtime evidence.
    source_revision = _run(root, "-c", "from tracked_source_revision import source_content_revision; print(source_content_revision('.'))")
    assert source_revision.returncode == 0, source_revision.stderr
    assert document["source_content_revision"] == source_revision.stdout.strip()
    assert document["source_content_revision_contract"] == {
        "algorithm": "sha256", "domain": "jaa-source-content-revision-v2",
        "entry_encoding": "uint64be-length-prefixed-path-mode-content",
        "scope": "current-tracked-source-tree", "ordering": "repository-relative-path-byte-order",
        "exclusions": ["runtime_evidence/"],
    }
    assert document["runtime"] == {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
    }
    assert document["runtime_inputs"] == {
        "locked_set_file_sha256": _digest(root / LOCKED_SET),
        "locked_metrics_file_sha256": _digest(root / LOCKED_METRICS),
    }
    assert document["configuration"]["locked_set_id"] == "JAA-03-reviewed-historical-calibration-2026-07-20"
    assert document["configuration"]["decision_rule_version"] == "jaa03.gold-decision-rules.v1"
    assert document["configuration"]["policy"] == EXPECTED_POLICY
    assert document["configuration"]["policy_hash"] == _content_hash(EXPECTED_POLICY)

    envelope = json.loads((root / LOCKED_SET).read_text(encoding="utf-8"))
    metrics = json.loads((root / LOCKED_METRICS).read_text(encoding="utf-8"))
    expected_locked_set_hash = _content_hash(envelope["records"])
    authority_document = {
        "domain": "jaa03-locked-set-authority-v1",
        "locked_set_id": envelope["locked_set_id"],
        "decision_rule_version": envelope["decision_rule_version"],
        "policy": EXPECTED_POLICY,
        "schema_version": envelope["schema_version"],
        "frozen_at": envelope["frozen_at"],
        "stratification": envelope["stratification"],
        "records": envelope["records"],
    }
    assert envelope["records_hash"] == expected_locked_set_hash
    assert metrics["locked_set_hash"] == expected_locked_set_hash
    assert _content_hash(authority_document) == LOCKED_SET_AUTHORITY_HASH
    result = document["acceptance_result"]
    assert result["status"] == "PASS"
    assert result["locked_set_hash"] == expected_locked_set_hash
    assert result["locked_set_authority_hash"] == LOCKED_SET_AUTHORITY_HASH
    assert result["metrics_hash"] == _content_hash(metrics["metrics"])
    assert result["negative_controls"] == [
        "expired", "inaccessible", "ineligible", "implausibly_senior",
        "low_confidence_extraction", "candidate_fit_and_interest_forbidden",
        "label_change_with_recomputed_envelope_hash",
    ]


def _rehash(envelope: dict[str, object]) -> None:
    records = envelope["records"]
    envelope["records_hash"] = "sha256:" + hashlib.sha256(
        json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@pytest.mark.parametrize("record_index", range(100))
def test_every_gold_decision_label_rehash_fails_independent_authority(
    repository: Path, tmp_path: Path, record_index: int,
) -> None:
    """A changed decision cannot be legitimised by rehashing its envelope."""
    envelope = json.loads((repository / LOCKED_SET).read_text(encoding="utf-8"))
    decision = envelope["records"][record_index]["labels"]["opportunity0_decision"]
    decision["decision"] = "reject" if decision["decision"] != "reject" else "pass"
    _rehash(envelope)
    altered = tmp_path / f"decision-{record_index}.json"
    altered.write_bytes(_canonical(envelope))
    probe = _run(repository, "-c", "from career_automation.opportunity_calibration import load_locked_set; from pathlib import Path; import sys; load_locked_set(Path(sys.argv[1]))", str(altered))
    assert probe.returncode != 0
    assert "authority mismatch" in probe.stderr


@pytest.mark.parametrize("attack", ["canonical_input", "rule_identity", "locked_set_identity", "malformed"])
def test_locked_set_attack_classes_fail_closed(repository: Path, tmp_path: Path, attack: str) -> None:
    envelope = json.loads((repository / LOCKED_SET).read_text(encoding="utf-8"))
    if attack == "canonical_input":
        row = envelope["records"][0]
        row["vacancy"]["text"] += " attacker-controlled canonical input"
        row["content_hash"] = "sha256:" + hashlib.sha256(json.dumps(row["vacancy"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    elif attack == "rule_identity":
        envelope["decision_rule_version"] = "attacker-rule-v999"
    elif attack == "locked_set_identity":
        envelope["locked_set_id"] = "attacker-locked-set"
    else:
        envelope["records"] = envelope["records"][:-1]
    _rehash(envelope)
    altered = tmp_path / f"{attack}.json"
    altered.write_bytes(_canonical(envelope))
    probe = _run(repository, "-c", "from career_automation.opportunity_calibration import load_locked_set; from pathlib import Path; import sys; load_locked_set(Path(sys.argv[1]))", str(altered))
    assert probe.returncode != 0
    assert any(marker in probe.stderr for marker in ("mismatch", "exactly 100"))


def test_real_certifier_receipt_and_negative_receipt_controls(repository: Path) -> None:
    receipt, _document = _certify(repository)
    _verify_receipt(repository, receipt)

    # Deletion, byte mutation, a different Git revision, and a fully rehashed
    # fabricated PASS document must all fail the verifier's binding checks.
    deleted = receipt.with_name("deleted.json")
    receipt.rename(deleted)
    with pytest.raises(FileNotFoundError):
        _verify_receipt(repository, receipt)
    deleted.rename(receipt)

    receipt.chmod(0o644)
    receipt.write_bytes(receipt.read_bytes() + b" ")
    with pytest.raises(AssertionError):
        _verify_receipt(repository, receipt)
    receipt.write_bytes(_canonical(_document))

    # A fabricated PASS must fail while every revision-binding field remains
    # valid; otherwise a stale-revision failure could mask an unsigned result.
    fabricated = dict(_document)
    fabricated["acceptance_result"] = dict(fabricated["acceptance_result"])
    fabricated["acceptance_result"]["status"] = "PASS"
    fabricated["acceptance_result"]["locked_set_hash"] = "sha256:" + "0" * 64
    payload = _canonical(fabricated)
    forged = receipt.with_name(f"sha256-{hashlib.sha256(payload).hexdigest()}.json")
    forged.write_bytes(payload)
    with pytest.raises(AssertionError):
        _verify_receipt(repository, forged)
    forged.unlink()

    # Tracking a receipt changes Git HEAD but not the certified source-content
    # tree.  Re-running certification must reuse the one receipt, not create an
    # endless chain of self-invalidating evidence files.
    assert _git(repository, "add", str(receipt.relative_to(repository))).returncode == 0
    assert _git(repository, "commit", "-m", "track JAA-03 receipt").returncode == 0
    _verify_receipt(repository, receipt)
    replay = _run(repository, str(CERTIFIER))
    assert replay.returncode == 0, replay.stderr
    assert json.loads(replay.stdout)["receipt"] == receipt.relative_to(repository).as_posix()
    assert list((repository / "runtime_evidence" / "jaa03").glob("sha256-*.json")) == [receipt]

    (repository / "README.md").write_bytes((repository / "README.md").read_bytes() + b"\nrevision replay\n")
    assert _git(repository, "add", "README.md").returncode == 0
    assert _git(repository, "commit", "-m", "different revision").returncode == 0
    with pytest.raises(AssertionError):
        _verify_receipt(repository, receipt)
