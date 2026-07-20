"""Black-box source-revision binding checks for JAA-01 runtime receipts.

The digest below is intentionally implemented here, rather than imported from
the certifier.  It is the verifier's view of the documented receipt contract:
the current Git index names the inputs and the checked-out bytes supply their
content.  Each test runs the public certifier in a disposable Git clone.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from career_automation.database import SCHEMA


ROOT = Path(__file__).resolve().parent
DOMAIN = b"jaa01-source-content-revision-v1\0"
EXCLUDED_PREFIXES = (b"runtime_evidence/jaa01/", b"runtime_evidence/pytest/")


def _git(root: Path, *args: str, input: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ("git", *args), cwd=root, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return completed.stdout


def _independent_source_revision(root: Path) -> str:
    """Calculate the published revision without importing certifier code."""
    entries: list[tuple[bytes, bytes]] = []
    seen: set[bytes] = set()
    for record in _git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        mode, _object_id, stage = metadata.split()
        assert separator and stage == b"0" and path not in seen
        seen.add(path)
        if not path.startswith(EXCLUDED_PREFIXES):
            entries.append((path, mode))

    digest = hashlib.sha256(DOMAIN)
    for path, declared_mode in sorted(entries):
        candidate = root / os.fsdecode(path)
        status = candidate.lstat()
        if declared_mode == b"120000":
            assert stat.S_ISLNK(status.st_mode)
            payload = os.fsencode(os.readlink(candidate))
        else:
            assert declared_mode in {b"100644", b"100755"}
            assert stat.S_ISREG(status.st_mode)
            payload = candidate.read_bytes()
        for field in (path, declared_mode, payload):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return f"sha256:{digest.hexdigest()}"


def _make_legacy_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA)
        connection.executemany(
            "INSERT INTO pipeline_jobs(job_key,board,job_id,url,title,company,opportunity,"
            "payload_json,payload_hash,state) VALUES(?,?,?,?,?,?,?,?,?,?)",
            [(f"legacy:{n}", "legacy", str(n), f"https://example.test/{n}", "Engineer",
              "Example", 0.5, "{}", f"{n:064x}", "opportunity_rejected") for n in range(462)],
        )
        connection.executemany(
            "INSERT INTO pipeline_events(job_key,event_type,from_state,to_state,actor_kind,"
            "payload_json,idempotency_key) VALUES(?,?,?,?,?,?,?)",
            [(f"legacy:{n // 2}",
              "score_snapshot_imported" if n % 2 == 0 else "opportunity_gate_decided",
              None if n % 2 == 0 else "scored",
              "scored" if n % 2 == 0 else "opportunity_rejected",
              "deterministic", "{}", f"source-revision:{n}") for n in range(924)],
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA journal_mode=DELETE")


def _migration_receipt(path: Path, database: Path) -> Path:
    content = {"format": "jaa-00-online-snapshot-receipt/v2", "databases": {
        "career_pipeline": {"frozen_snapshot": {"sha256": hashlib.sha256(
            database.read_bytes()).hexdigest(), "table_counts": {"pipeline_jobs": 462, "pipeline_events": 924}}}
    }}
    content_sha256 = hashlib.sha256(json.dumps(
        content, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()).hexdigest()
    receipt = path / f"migration-{content_sha256}.json"
    receipt.write_text(json.dumps({"content": content, "content_sha256": content_sha256}), encoding="utf-8")
    return receipt


@pytest.fixture()
def isolated_repository(tmp_path: Path) -> Path:
    clone = tmp_path / "repository"
    completed = subprocess.run(
        ("git", "clone", "--no-local", str(ROOT), str(clone)), text=True, capture_output=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
    _git(clone, "config", "user.email", "jaa01-test@example.test")
    _git(clone, "config", "user.name", "JAA-01 test")
    return clone


def _certify(root: Path, evidence_name: str = "evidence") -> tuple[Path, dict[str, object]]:
    database = root / "legacy.sqlite3"
    _make_legacy_database(database)
    receipt = _migration_receipt(root, database)
    completed = subprocess.run(
        (sys.executable, "scripts/certify_jaa01_runtime.py", "--baseline-database", str(database),
         "--migration-receipt", str(receipt), "--evidence-directory", evidence_name),
        cwd=root, text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    output = root / Path(json.loads(completed.stdout)["receipt"])
    return output, json.loads(output.read_text(encoding="utf-8"))


def _assert_source_binding(root: Path, receipt: Path, document: dict[str, object]) -> None:
    rendered = receipt.read_text(encoding="utf-8")
    assert receipt.name == f"sha256-{hashlib.sha256(receipt.read_bytes()).hexdigest()}.json"
    assert document["source_content_revision"] == _independent_source_revision(root)
    assert document["source_content_revision_contract"] == {
        "algorithm": "sha256", "domain": "jaa01-source-content-revision-v1",
        "entry_encoding": "uint64be-length-prefixed-path-mode-content",
        "scope": "current-tracked-source-tree", "ordering": "repository-relative-path-byte-order",
        "exclusions": ["runtime_evidence/jaa01/", "runtime_evidence/pytest/"],
    }
    assert str(root) not in rendered
    assert not any(value.startswith("/") for value in _strings(document))


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _strings(child)]
    return []


def test_fresh_receipt_matches_independent_current_tree_revision(isolated_repository: Path) -> None:
    receipt, document = _certify(isolated_repository)
    _assert_source_binding(isolated_repository, receipt, document)


@pytest.mark.parametrize("relative", [
    "career_automation/lifecycle.py", "career_automation/migrations.py",
    "test_jaa01_adversarial_runtime.py", "SOURCE_BASELINE.md", "README.md",
])
def test_every_source_class_byte_changes_the_independent_revision(
    isolated_repository: Path, relative: str,
) -> None:
    before = _independent_source_revision(isolated_repository)
    target = isolated_repository / relative
    target.write_bytes(target.read_bytes() + b"\nsource-revision-adversarial-byte\n")
    assert _independent_source_revision(isolated_repository) != before


@pytest.mark.parametrize("relative", [
    "canonical-repository.json", "skeleton/config.yaml", "llm/schemas/job_extract.json",
    "scraper/fixtures/jobkorea_listing.json", "scripts/advance_career_pipeline.py",
    "requirements-test.lock", "acceptance",
])
def test_every_remaining_tracked_source_class_changes_the_independent_revision(
    isolated_repository: Path, relative: str,
) -> None:
    """Configuration, fixtures, locks, and executable sources are digest inputs too."""
    before = _independent_source_revision(isolated_repository)
    target = isolated_repository / relative
    target.write_bytes(target.read_bytes() + b"\nindependent-revision-class-probe\n")
    assert _independent_source_revision(isolated_repository) != before


@pytest.mark.parametrize("relative", [
    "runtime_evidence/jaa01/manual-receipt.json", "runtime_evidence/pytest/manual-receipt.json",
])
def test_generated_receipt_bytes_do_not_change_source_revision(
    isolated_repository: Path, relative: str,
) -> None:
    before = _independent_source_revision(isolated_repository)
    target = isolated_repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b'{"generated":"changed"}\n')
    _git(isolated_repository, "add", "-f", relative)
    assert _independent_source_revision(isolated_repository) == before


@pytest.mark.parametrize("attack, expected", [
    ("dirty", "dirty tracked source tree"),
    # Git reports a deleted tracked file as dirty before the certifier opens it.
    ("missing", "dirty tracked source tree"),
    ("unmerged", "unmerged tracked source path"),
    ("symlink_escape", "tracked symlink escapes or has a missing target"),
])
def test_certifier_rejects_unsafe_tracked_source_trees(
    isolated_repository: Path, attack: str, expected: str,
) -> None:
    target = isolated_repository / "README.md"
    if attack == "dirty":
        target.write_bytes(target.read_bytes() + b"\ndirty\n")
    elif attack == "missing":
        target.unlink()
    elif attack == "unmerged":
        blob = _git(isolated_repository, "hash-object", "-w", "README.md").strip()
        _git(isolated_repository, "update-index", "-z", "--index-info", input=(
            b"100644 " + blob + b" 1\tREADME.md\0" + b"100644 " + blob + b" 2\tREADME.md\0"
        ))
    else:
        target.unlink()
        target.symlink_to("/private/jaa01-source-revision-escape")
        _git(isolated_repository, "add", "README.md")
        _git(isolated_repository, "commit", "-m", "tracked escape")

    completed = subprocess.run(
        (sys.executable, "scripts/certify_jaa01_runtime.py", "--baseline-database", "absent.sqlite3",
         "--migration-receipt", "absent.json", "--evidence-directory", "evidence"),
        cwd=isolated_repository, text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 2
    assert expected in completed.stderr


@pytest.mark.parametrize("attack", ["mode", "type"])
def test_certifier_fails_closed_for_tracked_mode_and_type_drift(
    isolated_repository: Path, attack: str,
) -> None:
    """A Git index entry must never be trusted when its checkout type changes."""
    target = isolated_repository / "README.md"
    if attack == "mode":
        target.chmod(target.stat().st_mode | stat.S_IXUSR)
    else:
        target.unlink()
        target.symlink_to("SOURCE_BASELINE.md")

    completed = subprocess.run(
        (sys.executable, "scripts/certify_jaa01_runtime.py", "--baseline-database", "absent.sqlite3",
         "--migration-receipt", "absent.json", "--evidence-directory", "evidence"),
        cwd=isolated_repository, text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 2
    assert "dirty tracked source tree" in completed.stderr
    assert not list((isolated_repository / "evidence").glob("*.json"))


def test_tampered_and_stale_source_revision_fields_are_rejected_by_independent_verifier(
    isolated_repository: Path,
) -> None:
    receipt, document = _certify(isolated_repository)
    _assert_source_binding(isolated_repository, receipt, document)

    tampered = dict(document)
    tampered["source_content_revision"] = "sha256:" + "0" * 64
    with pytest.raises(AssertionError):
        _assert_source_binding(isolated_repository, receipt, tampered)

    (isolated_repository / "docs" / "UK_SOURCE_RESEARCH.md").write_bytes(b"stale receipt source byte\n")
    with pytest.raises(AssertionError):
        _assert_source_binding(isolated_repository, receipt, document)
