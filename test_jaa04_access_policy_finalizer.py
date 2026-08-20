"""Offline negative controls for human-authored JAA-04 policy finalization."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.public_access import PublicAccessPolicy


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "scripts/finalize_jaa04_access_policy.py"


def _record() -> dict[str, str]:
    return {
        "host": "jobs.example.test",
        "terms_url": "https://jobs.example.test/terms",
        "determination": "public_read_only_research_permitted",
        "reviewed_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        "reviewed_by": "Offline Test Operator",
        "reviewer_type": "human_operator",
        "notes": "Synthetic offline fixture only; not production authority.",
    }


def _draft(path: Path, records: list[dict[str, str]] | None = None) -> bytes:
    encoded = (
        json.dumps({
            "schema_version": "jaa04.public-access-policy-draft.v1",
            "hosts": records if records is not None else [_record()],
        }, sort_keys=True)
        + "\n"
    ).encode()
    path.write_bytes(encoded)
    return encoded


def _run(draft: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (
            sys.executable,
            str(SCRIPT),
            "--draft",
            str(draft),
            "--output",
            str(output),
        ),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_finalizer_only_packages_exact_human_authored_records(tmp_path: Path) -> None:
    draft = tmp_path / "policy-draft.json"
    original = _draft(draft)
    output = tmp_path / "public-access-policy.json"

    completed = _run(draft, output)

    assert completed.returncode == 0, completed.stderr
    response = json.loads(completed.stdout)
    assert response["status"] == "SUCCESS"
    assert hashlib.sha256(output.read_bytes()).hexdigest() == response["policy_sha256"]
    assert draft.read_bytes() == original
    assert os.stat(output).st_mode & 0o777 == 0o600
    payload = json.loads(output.read_bytes())
    assert payload["hosts"] == json.loads(original)["hosts"]
    records = json.dumps(
        payload["hosts"],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert payload["records_hash"] == hashlib.sha256(records).hexdigest()
    assert PublicAccessPolicy.load(output).policy_sha256 == response["policy_sha256"]


@pytest.mark.parametrize(
    "attack",
    (
        "machine-reviewer",
        "denied-determination",
        "stale-review",
        "duplicate-host",
        "extra-field",
        "wrong-draft-schema",
    ),
)
def test_finalizer_rejects_invalid_or_nonhuman_authority(
    tmp_path: Path,
    attack: str,
) -> None:
    records = [_record()]
    if attack == "machine-reviewer":
        records[0]["reviewer_type"] = "automation"
    elif attack == "denied-determination":
        records[0]["determination"] = "not_reviewed"
    elif attack == "stale-review":
        records[0]["reviewed_at"] = (
            datetime.now(timezone.utc) - timedelta(days=91)
        ).isoformat()
    elif attack == "duplicate-host":
        records.append(deepcopy(records[0]))
    elif attack == "extra-field":
        records[0]["generated_by"] = "test"  # type: ignore[typeddict-unknown-key]
    draft = tmp_path / "policy-draft.json"
    _draft(draft, records)
    if attack == "wrong-draft-schema":
        payload = json.loads(draft.read_bytes())
        payload["schema_version"] = "jaa04.public-access-policy-draft.v0"
        draft.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "public-access-policy.json"

    completed = _run(draft, output)

    assert completed.returncode == 2
    assert "ERROR" in completed.stderr
    assert not output.exists()


def test_finalizer_refuses_repository_output_and_existing_destination(
    tmp_path: Path,
) -> None:
    draft = tmp_path / "policy-draft.json"
    _draft(draft)
    repository_output = ROOT / "never-write-jaa04-access-policy.json"
    assert not repository_output.exists()
    denied = _run(draft, repository_output)
    assert denied.returncode == 2
    assert "outside the product repository" in denied.stderr
    assert not repository_output.exists()

    existing = tmp_path / "existing-policy.json"
    existing.write_bytes(b"preserve me")
    denied = _run(draft, existing)
    assert denied.returncode == 2
    assert existing.read_bytes() == b"preserve me"

    symlink = tmp_path / "policy-symlink.json"
    symlink.symlink_to(tmp_path / "symlink-target.json")
    denied = _run(draft, symlink)
    assert denied.returncode == 2
    assert symlink.is_symlink()
    assert not (tmp_path / "symlink-target.json").exists()

    real_draft = tmp_path / "real-policy-draft.json"
    _draft(real_draft)
    symlink_draft = tmp_path / "policy-draft-symlink.json"
    symlink_draft.symlink_to(real_draft)
    denied = _run(symlink_draft, tmp_path / "symlink-draft-output.json")
    assert denied.returncode == 2
    assert "symlink" in denied.stderr
    assert not (tmp_path / "symlink-draft-output.json").exists()

    denied = _run(SCRIPT, tmp_path / "repository-draft-output.json")
    assert denied.returncode == 2
    assert "outside the product repository" in denied.stderr
    assert not (tmp_path / "repository-draft-output.json").exists()
