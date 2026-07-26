"""Clean-clone controls for the external JAA-04 certification boundary."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parent


def _policy(path: Path) -> tuple[Path, str]:
    records = [{
        "host": "jobs.example.test",
        "terms_url": "https://jobs.example.test/terms",
        "determination": "public_read_only_research_permitted",
        "reviewed_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        "reviewed_by": "Offline Test Operator",
        "reviewer_type": "human_operator",
        "notes": "Synthetic offline fixture only; not production authority.",
    }]
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    payload = {
        "schema_version": "jaa04.public-access-policy.v1",
        "hosts": records,
        "records_hash": hashlib.sha256(canonical).hexdigest(),
    }
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _runner() -> ModuleType:
    path = ROOT / "scripts/run_acceptance_declaration.py"
    spec = importlib.util.spec_from_file_location("jaa04_acceptance_declaration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runtime_corpus_is_external_and_manifest_declares_exact_command() -> None:
    tracked = subprocess.run(
        ("git", "ls-files", "-z", "--", "career_automation/fixtures/jaa04_capture",
         "runtime_evidence/jaa04/inflight"),
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    assert tracked.stdout == b""

    component = json.loads(
        (ROOT / "ASSURANCE_MANIFEST.json").read_text(encoding="utf-8")
    )["components"]["JAA-04"]
    corpus = next(item for item in component["evidence"] if item["kind"] == "corpus")
    assert corpus == {
        "kind": "corpus",
        "scope": "JAA-04-corpus",
        "required": True,
        "tracked": False,
        "argv": [
            "{python}", "scripts/accept_jaa_04.py", "--capture",
            "{external_jaa04_corpus}", "--access-policy",
            "{external_jaa04_access_policy}", "--receipt",
            "{external_jaa04_receipts}",
        ],
    }


def test_corpus_certifier_requires_an_explicit_external_capture(tmp_path: Path) -> None:
    destination = tmp_path / "receipts"
    completed = subprocess.run(
        (sys.executable, "scripts/accept_jaa_04.py", "--receipt", str(destination)),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    assert "--capture" in completed.stderr and "--access-policy" in completed.stderr
    assert not destination.exists()


@pytest.mark.parametrize("attack", ("unsupported-receipt-schema", "manifest-digest-mismatch"))
def test_corpus_certifier_rejects_malformed_external_bytes_without_receipt(
    tmp_path: Path,
    attack: str,
) -> None:
    capture = tmp_path / "malformed-capture"
    capture.mkdir()
    policy, policy_hash = _policy(tmp_path / "access-policy.json")
    manifest = capture / "research_manifest.json"
    manifest.write_text("{}\n", encoding="utf-8")
    (capture / "frozen_dossiers.json").write_text(json.dumps({
        "dossiers": [{
            "sources": [{
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }) + "\n", encoding="utf-8")
    receipt = {
        "schema_version": "jaa04.capture-receipt.v6",
        "status": "SUCCESS",
        "manifest_sha256": "0" * 64,
        "dossiers_sha256": "0" * 64,
        "access_policy_sha256": policy_hash,
    }
    if attack == "unsupported-receipt-schema":
        receipt["schema_version"] = "jaa04.capture-receipt.v5"
    (capture / "capture_receipt.json").write_text(
        json.dumps(receipt) + "\n",
        encoding="utf-8",
    )
    destination = tmp_path / "receipts"
    completed = subprocess.run(
        (
            sys.executable,
            "scripts/accept_jaa_04.py",
            "--capture",
            str(capture),
            "--access-policy",
            str(policy),
            "--receipt",
            str(destination),
        ),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    expected = (
        "capture has no authentic acquisition receipt"
        if attack == "unsupported-receipt-schema"
        else "capture metadata or dossier bytes were modified"
    )
    assert expected in completed.stderr
    assert not destination.exists()


def test_root_acceptance_is_blocked_when_corpus_was_not_certified(
    monkeypatch,
    capsys,
) -> None:
    runner = _runner()
    calls: list[tuple[str, ...]] = []

    def successful_source(command, **_kwargs):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.delenv("JAA04_CORPUS", raising=False)
    monkeypatch.setattr(runner.subprocess, "run", successful_source)
    assert runner.main() == 3
    assert calls == list(runner.SOURCE_COMMANDS)
    assert "BLOCKED" in capsys.readouterr().err


def test_root_acceptance_is_blocked_without_operator_access_policy(
    monkeypatch,
    capsys,
) -> None:
    runner = _runner()
    calls: list[tuple[str, ...]] = []

    def successful_source(command, **_kwargs):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setenv("JAA04_CORPUS", "/external/corpus")
    monkeypatch.delenv("JAA04_ACCESS_POLICY", raising=False)
    monkeypatch.setattr(runner.subprocess, "run", successful_source)
    assert runner.main() == 3
    assert calls == list(runner.SOURCE_COMMANDS)
    assert "JAA04_ACCESS_POLICY" in capsys.readouterr().err


def test_root_acceptance_runs_external_certifier_last(monkeypatch) -> None:
    runner = _runner()
    calls: list[tuple[str, ...]] = []

    def successful(command, **_kwargs):
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setenv("JAA04_CORPUS", "/external/corpus")
    monkeypatch.setenv("JAA04_ACCESS_POLICY", "/external/access-policy.json")
    monkeypatch.setenv("JAA04_RECEIPTS", "/external/receipts")
    monkeypatch.setattr(runner.subprocess, "run", successful)
    assert runner.main() == 0
    assert calls[:-2] == list(runner.SOURCE_COMMANDS)
    assert calls[-2] == (
        sys.executable,
        "scripts/accept_jaa04_coordination.py",
        "--capture",
        "/external/corpus",
        "--access-policy",
        "/external/access-policy.json",
    )
    assert calls[-1] == (
        sys.executable,
        "scripts/accept_jaa_04.py",
        "--capture",
        "/external/corpus",
        "--access-policy",
        "/external/access-policy.json",
        "--receipt",
        "/external/receipts",
    )
