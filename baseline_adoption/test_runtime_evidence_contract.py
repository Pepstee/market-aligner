"""Black-box contract test for the tracked JAA-00 frozen runtime evidence."""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "runtime_evidence" / "JAA-00-online-snapshot.yaml"
RECEIPT_HASH = "4f2dddaab89ea49ef991ad8a4d8598c03062c4b3ecbf11f85451ab9239a8ec66"
RUNTIME_NAME = "job-application-baseline-20260720-v2"


def test_tracked_identity_documents_are_credential_free_and_consistent() -> None:
    """Reject credential material or identity drift in the published JAA-00 record."""
    marker_path = ROOT / "canonical-repository.json"
    baseline_path = ROOT / "SOURCE_BASELINE.md"
    tracked_paths = (marker_path, baseline_path, EVIDENCE)
    texts = {path: path.read_text(encoding="utf-8") for path in tracked_paths}

    credential_value_patterns = (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"(?i)://[^/\s:@]+:[^/\s@]+@",
        r"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)"
        r"\s*[:=]\s*[\"']?(?!false\b|true\b|null\b|none\b|\[\])[^\s,}\]]{8,}",
    )
    for path, text in texts.items():
        for pattern in credential_value_patterns:
            assert re.search(pattern, text) is None, f"credential value pattern in {path.name}"

    marker = json.loads(texts[marker_path])
    canonical = marker["canonical_repository"]
    original = marker["original_project"]
    historical = marker["historical_copies"]
    assert canonical["role"] == "neutral-versioned-successor"
    assert original["canonical"] is False
    assert original["status"] == "preserved-recoverable-source"
    assert historical["canonical"] is False
    assert historical["status"] == "historical-only"
    assert historical["identities"] == [
        "giga-user/market-aligner:historical-copy-1",
        "giga-user/market-aligner:historical-copy-2",
    ]

    baseline = texts[baseline_path]
    assert "neutral successor repository" in baseline
    assert "recoverable, unmodified, explicitly non-canonical source" in baseline
    assert "Both known `giga-user/market-aligner` copies are historical only" in baseline

    evidence = _evidence_document(EVIDENCE)
    assert evidence["repository"]["label"] == "canonical-repository"
    assert evidence["canonical_adoption"] == {
        "repository_role": canonical["role"],
        "original_project_canonical": original["canonical"],
        "original_project_recoverable": True,
        "historical_market_aligner_copies_canonical": historical["canonical"],
    }
    assert evidence["secret_policy"] == {
        "references_only": True,
        "values_persisted": False,
    }


def _runtime_root() -> Path:
    """Find the operator-provided frozen runtime without tracking its host path."""
    for ancestor in ROOT.parents:
        candidate = ancestor / "state" / "runtime" / RUNTIME_NAME
        if candidate.is_dir():
            return candidate
    pytest.fail("the frozen JAA-00 runtime is unavailable")


def _evidence_document(path: Path) -> dict[str, object]:
    """Parse the deliberately small mapping-only evidence file without PyYAML."""
    root: dict[str, object] = {}
    stack: list[tuple[int, dict[str, object]]] = [(-1, root)]
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        key, separator, value = raw.strip().partition(":")
        assert separator and key
        while indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        value = value.strip()
        if not value:
            child: dict[str, object] = {}
            parent[key] = child
            stack.append((indent, child))
        elif value in {"true", "false"}:
            parent[key] = value == "true"
        elif value.startswith("[") and value.endswith("]"):
            parent[key] = [part.strip() for part in value[1:-1].split(",") if part.strip()]
        else:
            try:
                parent[key] = int(value)
            except ValueError:
                parent[key] = value
    return root


def _receipt(runtime_root: Path) -> Path:
    receipt = runtime_root / "receipts" / f"migration-{RECEIPT_HASH}.json"
    assert receipt.is_file(), receipt
    return receipt


def _public(
    *arguments: str, dependency_root: Path | None = None
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if dependency_root is not None:
        for distribution in ("PyYAML", "requests", "openpyxl", "pypdf"):
            metadata = dependency_root / f"{distribution}-0.0-test.dist-info"
            metadata.mkdir(parents=True, exist_ok=True)
            (metadata / "METADATA").write_text(
                f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 0.0-test\n",
                encoding="utf-8",
            )
        environment["PYTHONPATH"] = (
            str(dependency_root) + os.pathsep + environment.get("PYTHONPATH", "")
        )
    return subprocess.run(
        [sys.executable, "-m", "baseline_adoption.cli", *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )


def _runtime_files(root: Path) -> set[Path]:
    return {path.relative_to(root) for path in root.rglob("*") if path.is_file()}


def _assert_no_sidecars_or_temporaries(root: Path) -> None:
    forbidden_suffixes = ("-journal", "-wal", "-shm")
    forbidden_prefixes = (".receipt-", ".adopting-", ".snapshotting-")
    offenders = [
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_file()
        and (path.name.endswith(forbidden_suffixes) or path.name.startswith(forbidden_prefixes))
    ]
    assert not offenders


def test_tracked_online_snapshot_evidence_matches_frozen_receipt_and_public_commands(
    tmp_path: Path,
) -> None:
    runtime = _runtime_root()
    receipt = _receipt(runtime)
    evidence = _evidence_document(EVIDENCE)
    receipt_document = json.loads(receipt.read_text(encoding="utf-8"))
    content = receipt_document["content"]
    before = _runtime_files(runtime)
    reconciled = _public("reconcile", "--receipt", str(receipt), "--data-root", str(runtime))
    assert reconciled.returncode == 0, reconciled.stderr
    reconciliation = json.loads(reconciled.stdout)

    # Run the public rollback-manifest command after reconciliation, exactly as its
    # precondition requires.  It must describe removal only; it must not remove data.
    manifest_result = _public(
        "rollback-manifest", "--receipt", str(receipt), "--data-root", str(runtime)
    )
    assert manifest_result.returncode == 0, manifest_result.stderr
    manifest = json.loads(manifest_result.stdout)

    review_result = _public(
        "independent-review",
        "--receipt", str(receipt),
        "--data-root", str(runtime),
        "--repository", str(ROOT),
        dependency_root=tmp_path / "review-runtime-dependencies",
    )
    assert review_result.returncode == 0, review_result.stderr
    review = json.loads(review_result.stdout)
    assert review["status"] == "certified"
    assert review["receipt_provenance"]["content_sha256"] == receipt_document["content_sha256"]
    assert review["receipt_provenance"]["tracked_evidence"] == str(
        EVIDENCE.relative_to(ROOT)
    )
    assert review["canonical_repository"]["adoption_revision"] == content["repository"]["revision"]
    assert review["database_reconciliation"] == reconciliation
    assert review["preserved_originals_and_rollback"] == manifest

    inventory = review["current_review"]["content_inventory"]
    certified_inventory = review["secret_free_inventory"]
    assert inventory
    assert all(certified_inventory[key] == value for key, value in inventory.items())
    runtime_prerequisites = review["runtime_prerequisites"]
    assert runtime_prerequisites["result"] == "ok"
    assert runtime_prerequisites["observed"] == review["current_review"]["runtime"]
    assert set(runtime_prerequisites["observed"]["dependencies"]) == {
        "PyYAML", "requests", "openpyxl", "pypdf"
    }
    assert review["pre_adoption_test_observation"] == {
        "label": "pre-adoption career-control observation",
        "observed_on": "2026-07-20",
        "passed": 65,
        "classification": "historical-observation-not-current-suite-total",
    }

    assert evidence["evidence"] == "JAA-00:first-adopted-frozen-baseline"
    assert evidence["receipt"] == {
        "label": f"runtime:{runtime.name}:receipt",
        "content_sha256": receipt_document["content_sha256"],
    }
    assert receipt.name == f"migration-{receipt_document['content_sha256']}.json"
    assert evidence["repository"] == {
        "label": content["repository"]["label"],
        "revision": content["repository"]["revision"],
    }

    expected_reconciliation = evidence["reconciliation"]
    assert reconciliation["status"] == expected_reconciliation["result"] == "ok"
    assert expected_reconciliation["receipt_filename_matches_content_sha256"] is True
    assert expected_reconciliation["adopted_database_hashes_match"] is True
    assert expected_reconciliation["integrity_check"] == "ok"
    assert expected_reconciliation["counts_match"] is True
    assert expected_reconciliation["schema_matches"] is True
    assert expected_reconciliation["adopted_snapshots_sidecar_free"] is True

    manifest_actions = {action["database"]: action for action in manifest["actions"]}
    for database, tracked in evidence["databases"].items():
        record = content["databases"][database]
        actual = reconciliation["databases"][database]
        frozen = record["frozen_snapshot"]
        assert tracked["source_label"] == record["source"]["label"]
        assert tracked["destination_label"] == record["destination"]["label"]
        assert tracked["snapshot_sha256"] == frozen["sha256"] == actual["sha256"]
        assert tracked["schema_sha256"] == frozen["schema_sha256"] == actual["schema_sha256"]
        assert tracked["schema_objects"] == frozen["schema_objects"] == actual["schema_objects"]
        assert tracked["counts"] == frozen["table_counts"] == actual["table_counts"]
        assert actual["integrity_check"] == ["ok"]
        assert manifest_actions[database] == {
            "database": database,
            "action": "remove_adopted_copy",
            "target": record["destination"]["relative_location"],
            "expected_sha256": frozen["sha256"],
            "preserved_source": f"source:{database}",
        }
        if "historical_observation" in tracked:
            historical = record["historical_observation"]
            assert tracked["historical_observation"] == {
                "status": "superseded",
                "snapshot_sha256": historical["observed_sha256"],
                "schema_sha256": historical["observed_schema_sha256"],
                "schema_objects": historical["observed_schema_objects"],
                "counts": historical["observed_table_counts"],
            }

    capture = evidence["capture_and_drift_semantics"]
    assert capture["method"] == "sqlite-online-backup"
    assert capture["adopted_snapshot"] == "frozen"
    assert capture["live_source_after_capture"] == "may_continue_changing"
    assert capture["source_open"] == "read-only-query-only"
    assert capture["source_write_operations"] == "none"
    for database in evidence["databases"]:
        observed = content["databases"][database]["capture"]
        tracked = capture[database]
        assert tracked["main_content_unchanged_during_capture"] == observed["main_content_unchanged"]
        assert tracked["wal_content_unchanged_during_capture"] == observed["wal_content_unchanged"]
        assert tracked["drift_observed"] == observed["drift_observed"]
        assert tracked.get("changed_components", []) == observed["changed_components"]
        if "shm_comparison" in tracked:
            assert tracked["shm_comparison"] == "identity-metadata-only"
            assert observed["shm_observation"]["scope"] == "identity-metadata-only"
        assert observed["source_open_semantics"] == {
            "sqlite_uri_mode": "ro",
            "query_only": True,
            "source_write_operations": "none",
        }

    assert evidence["rollback"] == {
        "precondition": "reconcile-must-pass-immediately-before-removal",
        "preserved_source_labels": ["source:raw_jobs", "source:career_pipeline"],
        "removable_destination_labels": ["destination:raw_jobs", "destination:career_pipeline"],
    }
    assert manifest["precondition"] == "reconcile must pass immediately before removal"
    assert _runtime_files(runtime) == before
    _assert_no_sidecars_or_temporaries(runtime)

    # Tampering a receipt copy must be rejected by the same public verifier.
    tampered_receipt = tmp_path / receipt.name
    tampered_receipt.write_text(
        receipt.read_text(encoding="utf-8").replace("canonical-repository", "forged-repository", 1),
        encoding="utf-8",
    )
    tampered = _public("reconcile", "--receipt", str(tampered_receipt), "--data-root", str(runtime))
    assert tampered.returncode == 2
    assert "receipt content hash or filename mismatch" in tampered.stderr

    # An altered adopted copy must also fail closed through public reconciliation.
    altered_root = tmp_path / "altered-runtime"
    altered_database = altered_root / "databases" / "jobs.sqlite3"
    altered_database.parent.mkdir(parents=True)
    shutil.copyfile(runtime / "databases" / "jobs.sqlite3", altered_database)
    with sqlite3.connect(altered_database) as connection:
        connection.execute("PRAGMA user_version = 1")
    altered = _public("reconcile", "--receipt", str(receipt), "--data-root", str(altered_root))
    assert altered.returncode == 2
    assert "raw_jobs:" in altered.stderr
    _assert_no_sidecars_or_temporaries(altered_root)
    assert _runtime_files(runtime) == before


def test_tracked_repository_excludes_runtime_data_personal_paths_and_environment_credentials() -> None:
    runtime = _runtime_root()
    receipt = _receipt(runtime)
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout.split(b"\0")
    tracked = [item for item in tracked if item]
    tracked_paths = [item.decode("utf-8") for item in tracked]

    database_suffixes = (".sqlite", ".sqlite3", ".db", "-wal", "-shm")
    jaa00_evidence_prefixes = ("baseline_adoption/", "runtime_evidence/JAA-00")
    operational_data_prefixes = ("scraper/data/", "profiler/data/", "outputs/", "state/")
    assert not [
        path for path in tracked_paths
        if path.startswith(operational_data_prefixes)
        or (path.startswith(jaa00_evidence_prefixes) and path.endswith(database_suffixes))
    ]
    tracked_text = b"\n".join(
        (ROOT / path).read_bytes()
        for path in tracked_paths
        if (ROOT / path).is_file()
    )
    assert str(runtime).encode() not in tracked_text
    assert str(receipt).encode() not in tracked_text

    # Only compare actual configured secret values; names and redaction examples are
    # legitimate source code and do not demonstrate a tracked credential.
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"):
        value = os.environ.get(name)
        if value and len(value) >= 8:
            assert value.encode() not in tracked_text, name
