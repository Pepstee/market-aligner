"""Adversarial black-box checks for JAA-00 evidence publication."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


def _git_repository(destination: Path) -> Path:
    """Make a clean repository from the caller's currently tracked bytes."""
    destination.mkdir()
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout.split(b"\0")
    for encoded in tracked:
        if not encoded:
            continue
        relative = Path(os.fsdecode(encoded))
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        else:
            shutil.copyfile(source, target)
    subprocess.run(["git", "init", "-q"], cwd=destination, check=True)
    subprocess.run(["git", "add", "-A"], cwd=destination, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "fixture"], cwd=destination, check=True
    )
    return destination


def _database(path: Path, rows: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE ledger(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        connection.executemany("INSERT INTO ledger(value) VALUES (?)", [(f"row-{n}",) for n in range(rows)])


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _contract(source_root: Path, name: str, rows: int) -> dict[str, object]:
    path = source_root / "inputs" / f"{name}.sqlite3"
    with sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True) as connection:
        schema = [list(row) for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        )]
    return {
        "name": name,
        "source_relative": str(path.relative_to(source_root)),
        "destination_relative": f"databases/{name}.sqlite3",
        "size": path.stat().st_size,
        "sha256": _sha(path),
        "schema_sha256": hashlib.sha256(json.dumps(
            schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
        "schema_objects": len(schema),
        "table_counts": {"ledger": rows},
    }


def _cli(repository: Path, contract: list[dict[str, object]], *arguments: str) -> subprocess.CompletedProcess[str]:
    bootstrap = """
import json, sys
from baseline_adoption import cli, core
core.BASELINES = tuple(core.BaselineSpec(**item) for item in json.loads(sys.argv[1]))
raise SystemExit(cli.main(sys.argv[2:]))
"""
    dependency_root = repository.parent / "test-distributions"
    for distribution in ("PyYAML", "requests", "openpyxl", "pypdf"):
        metadata = dependency_root / f"{distribution}-1.0.dist-info"
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 1.0\n", encoding="utf-8"
        )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(dependency_root)
    return subprocess.run(
        [sys.executable, "-c", bootstrap, json.dumps(contract), *arguments],
        cwd=repository, env=environment, text=True, capture_output=True, check=False,
    )


def _cli_with_publication_race(
    repository: Path,
    contract: list[dict[str, object]],
    mutation: str,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    """Mutate a reviewed binding after its first capture, before replacement."""
    bootstrap = r'''
import json, sqlite3, sys
from pathlib import Path
from baseline_adoption import cli, core

core.BASELINES = tuple(core.BaselineSpec(**item) for item in json.loads(sys.argv[1]))
mutation = sys.argv[2]
original_bindings = core._publication_input_bindings
binding_calls = 0

def racing_bindings(receipt_path, data_root, repository, databases):
    global binding_calls
    result = original_bindings(receipt_path, data_root, repository, databases)
    binding_calls += 1
    if binding_calls == 1:
        if mutation == "source":
            target = Path(repository) / "baseline_adoption" / "cli.py"
        elif mutation == "database":
            target = None
            snapshot = Path(data_root) / databases["jobs"]["destination"]["relative_location"]
            with sqlite3.connect(snapshot) as connection:
                connection.execute("UPDATE ledger SET value = value || '-raced' WHERE id = 1")
        else:
            target = None
        if target is not None:
            target.write_bytes(target.read_bytes() + b"\n# publication race\n")
    return result

core._publication_input_bindings = racing_bindings
raise SystemExit(cli.main(sys.argv[3:]))
'''
    dependency_root = repository.parent / "test-distributions"
    for distribution in ("PyYAML", "requests", "openpyxl", "pypdf"):
        metadata = dependency_root / f"{distribution}-1.0.dist-info"
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 1.0\n", encoding="utf-8"
        )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(dependency_root)
    return subprocess.run(
        [sys.executable, "-c", bootstrap, json.dumps(contract), mutation, *arguments],
        cwd=repository, env=environment, text=True, capture_output=True, check=False,
    )


def _cli_with_replace_boundary_race(
    repository: Path,
    contract: list[dict[str, object]],
    mutation: str,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    """Mutate a bound input inside the final os.replace call boundary."""
    bootstrap = r'''
import json, os, sqlite3, sys
from pathlib import Path
from baseline_adoption import cli, core

core.BASELINES = tuple(core.BaselineSpec(**item) for item in json.loads(sys.argv[1]))
mutation = sys.argv[2]
arguments = sys.argv[3:]
repository = Path(arguments[arguments.index("--repository") + 1])
data_root = Path(arguments[arguments.index("--data-root") + 1])
original_replace = os.replace
race_injected = False

def racing_replace(source, destination):
    global race_injected
    if not race_injected:
        race_injected = True
        if mutation == "source":
            target = repository / "baseline_adoption" / "cli.py"
            target.write_bytes(target.read_bytes() + b"\n# replace-boundary race\n")
        elif mutation == "database":
            snapshot = data_root / core.BASELINES[0].destination_relative
            with sqlite3.connect(snapshot) as connection:
                connection.execute("UPDATE ledger SET value = value || '-replace-raced' WHERE id = 1")
    return original_replace(source, destination)

core.os.replace = racing_replace
raise SystemExit(cli.main(arguments))
'''
    dependency_root = repository.parent / "test-distributions"
    for distribution in ("PyYAML", "requests", "openpyxl", "pypdf"):
        metadata = dependency_root / f"{distribution}-1.0.dist-info"
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 1.0\n", encoding="utf-8"
        )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(dependency_root)
    return subprocess.run(
        [sys.executable, "-c", bootstrap, json.dumps(contract), mutation, *arguments],
        cwd=repository, env=environment, text=True, capture_output=True, check=False,
    )


def _cli_with_first_post_replace_fsync_failure(
    repository: Path,
    contract: list[dict[str, object]],
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    """Fail the first publication directory fsync, immediately after replacement."""
    bootstrap = r'''
import json, sys
from baseline_adoption import cli, core

core.BASELINES = tuple(core.BaselineSpec(**item) for item in json.loads(sys.argv[1]))
original_fsync_directory = core._fsync_directory
fsync_calls = 0

def failing_fsync_directory(path):
    global fsync_calls
    fsync_calls += 1
    if fsync_calls == 1:
        raise OSError("injected post-replace directory fsync failure")
    return original_fsync_directory(path)

core._fsync_directory = failing_fsync_directory
raise SystemExit(cli.main(sys.argv[2:]))
'''
    dependency_root = repository.parent / "test-distributions"
    for distribution in ("PyYAML", "requests", "openpyxl", "pypdf"):
        metadata = dependency_root / f"{distribution}-1.0.dist-info"
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 1.0\n", encoding="utf-8"
        )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(dependency_root)
    return subprocess.run(
        [sys.executable, "-c", bootstrap, json.dumps(contract), *arguments],
        cwd=repository, env=environment, text=True, capture_output=True, check=False,
    )


def _cli_with_assert_to_close_race(
    repository: Path,
    contract: list[dict[str, object]],
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    """Mutate tracked source after the body's clean assertion, before watcher teardown."""
    bootstrap = r'''
import json, sys
from pathlib import Path
from baseline_adoption import cli, core

core.BASELINES = tuple(core.BaselineSpec(**item) for item in json.loads(sys.argv[1]))
arguments = sys.argv[2:]
repository = Path(arguments[arguments.index("--repository") + 1])
original_assert_clean = core._MutationBoundary.assert_clean
assertions = 0

def racing_assert_clean(self, label):
    global assertions
    result = original_assert_clean(self, label)
    assertions += 1
    if assertions == 1:
        target = repository / "baseline_adoption" / "cli.py"
        target.write_bytes(target.read_bytes() + b"\n# assert-to-close race\n")
    return result

core._MutationBoundary.assert_clean = racing_assert_clean
raise SystemExit(cli.main(arguments))
'''
    dependency_root = repository.parent / "test-distributions"
    for distribution in ("PyYAML", "requests", "openpyxl", "pypdf"):
        metadata = dependency_root / f"{distribution}-1.0.dist-info"
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 1.0\n", encoding="utf-8"
        )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(dependency_root)
    return subprocess.run(
        [sys.executable, "-c", bootstrap, json.dumps(contract), *arguments],
        cwd=repository, env=environment, text=True, capture_output=True, check=False,
    )


@pytest.fixture
def publication_case(tmp_path: Path) -> tuple[Path, Path, Path, list[dict[str, object]], Path]:
    repository = _git_repository(tmp_path / "repository")
    source = tmp_path / "source"
    for name, rows in (("jobs", 3), ("pipeline", 4)):
        _database(source / "inputs" / f"{name}.sqlite3", rows)
    contract = [_contract(source, "jobs", 3), _contract(source, "pipeline", 4)]
    data = tmp_path / "data"
    adopted = _cli(repository, contract, "adopt-online", "--source-root", str(source),
                   "--data-root", str(data), "--repository", str(repository))
    assert adopted.returncode == 0, adopted.stderr
    receipt = Path(json.loads(adopted.stdout)["receipt"])
    return repository, source, data, contract, receipt


def test_public_cli_publishes_v2_receipt_with_bound_hashes_and_dependencies(
    publication_case: tuple[Path, Path, Path, list[dict[str, object]], Path], tmp_path: Path,
) -> None:
    repository, _source, data, contract, receipt = publication_case
    output = tmp_path / "published.yaml"
    result = _cli(repository, contract, "publish-evidence", "--receipt", str(receipt),
                  "--data-root", str(data), "--repository", str(repository), "--output", str(output))

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"status": "published", "path": str(output.resolve())}
    evidence = yaml.safe_load(output.read_text(encoding="utf-8"))
    receipt_document = json.loads(receipt.read_text(encoding="utf-8"))
    assert receipt_document["content"]["format"] == "jaa-00-online-snapshot-receipt/v2"
    assert receipt_document["content_sha256"] == hashlib.sha256(json.dumps(
        receipt_document["content"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    assert evidence["publication"]["format"] == "jaa-00-deterministic-evidence/v2"
    assert evidence["receipt"]["content_sha256"] == receipt_document["content_sha256"]
    assert evidence["repository"]["revision"] == subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repository, check=True, text=True, capture_output=True
    ).stdout.strip()
    assert evidence["reconciliation"]["result"] == "ok"
    for item in contract:
        name = str(item["name"])
        snapshot = data / str(item["destination_relative"])
        assert evidence["databases"][name]["snapshot_sha256"] == _sha(snapshot)
        assert evidence["databases"][name]["counts"] == {"ledger": item["table_counts"]["ledger"]}
        assert evidence["databases"][name]["schema_sha256"] == item["schema_sha256"]
    dependencies = {record["path"]: record for record in evidence["dependency_records"]}
    assert set(dependencies) == {"requirements-test.lock", "requirements-scrapling-full.txt"}
    for relative, record in dependencies.items():
        assert record["sha256"] == _sha(repository / relative)
        assert record["bytes"] == (repository / relative).stat().st_size


@pytest.mark.parametrize("mutation", ["source", "database"])
def test_publication_rejects_inputs_raced_after_review_before_replace(
    publication_case: tuple[Path, Path, Path, list[dict[str, object]], Path],
    tmp_path: Path,
    mutation: str,
) -> None:
    repository, _source, data, contract, receipt = publication_case
    output = tmp_path / "published.yaml"
    prior_evidence = b"prior-certified-evidence\n\x00byte-stable"
    output.write_bytes(prior_evidence)

    result = _cli_with_publication_race(
        repository, contract, mutation, "publish-evidence", "--receipt", str(receipt),
        "--data-root", str(data), "--repository", str(repository), "--output", str(output),
    )

    assert result.returncode == 2
    if mutation == "source":
        # The second binding pass reuses the ordinary source-integrity guard, which names the
        # dirty checkout before the outer binding comparison can emit its generic drift message.
        assert "dirty tracked source tree" in result.stderr.lower()
    else:
        assert "drifted before atomic replacement" in result.stderr.lower()
    assert "published" not in result.stdout.lower()
    assert output.read_bytes() == prior_evidence
    assert not list(output.parent.glob(f".{output.name}.*"))


def test_publication_without_a_post_review_race_still_replaces_atomically(
    publication_case: tuple[Path, Path, Path, list[dict[str, object]], Path],
    tmp_path: Path,
) -> None:
    repository, _source, data, contract, receipt = publication_case
    output = tmp_path / "published.yaml"
    prior_evidence = b"prior-certified-evidence"
    output.write_bytes(prior_evidence)

    result = _cli_with_publication_race(
        repository, contract, "none", "publish-evidence", "--receipt", str(receipt),
        "--data-root", str(data), "--repository", str(repository), "--output", str(output),
    )

    assert result.returncode == 0, result.stderr
    assert output.read_bytes() != prior_evidence
    assert yaml.safe_load(output.read_bytes())["evidence"] == \
        "JAA-00:first-adopted-frozen-baseline"
    assert not list(output.parent.glob(f".{output.name}.*"))


@pytest.mark.parametrize("mutation", ["source", "database"])
def test_publication_rejects_input_race_inside_atomic_replace_boundary(
    publication_case: tuple[Path, Path, Path, list[dict[str, object]], Path],
    tmp_path: Path,
    mutation: str,
) -> None:
    repository, _source, data, contract, receipt = publication_case
    output = tmp_path / "published.yaml"
    prior_evidence = b"prior-certified-evidence\nreplace-boundary"
    output.write_bytes(prior_evidence)

    result = _cli_with_replace_boundary_race(
        repository, contract, mutation, "publish-evidence", "--receipt", str(receipt),
        "--data-root", str(data), "--repository", str(repository), "--output", str(output),
    )

    assert result.returncode == 2
    assert "atomic replacement boundary" in result.stderr.lower()
    assert "published" not in result.stdout.lower()
    assert output.read_bytes() == prior_evidence
    assert not list(output.parent.glob(f".{output.name}.*"))


def test_post_replace_directory_fsync_failure_restores_prior_evidence(
    publication_case: tuple[Path, Path, Path, list[dict[str, object]], Path],
    tmp_path: Path,
) -> None:
    repository, _source, data, contract, receipt = publication_case
    output = tmp_path / "published.yaml"
    prior_evidence = b"prior-certified-evidence\nfsync-boundary"
    output.write_bytes(prior_evidence)

    result = _cli_with_first_post_replace_fsync_failure(
        repository, contract, "publish-evidence", "--receipt", str(receipt),
        "--data-root", str(data), "--repository", str(repository), "--output", str(output),
    )

    assert result.returncode != 0
    assert "published" not in result.stdout.lower()
    assert output.read_bytes() == prior_evidence
    assert not list(output.parent.glob(f".{output.name}.*"))


def test_publication_rejects_mutation_between_clean_assertion_and_watcher_close(
    publication_case: tuple[Path, Path, Path, list[dict[str, object]], Path],
    tmp_path: Path,
) -> None:
    repository, _source, data, contract, receipt = publication_case
    output = tmp_path / "published.yaml"
    prior_evidence = b"prior-certified-evidence\nassert-to-close"
    output.write_bytes(prior_evidence)

    result = _cli_with_assert_to_close_race(
        repository, contract, "publish-evidence", "--receipt", str(receipt),
        "--data-root", str(data), "--repository", str(repository), "--output", str(output),
    )

    assert result.returncode == 2
    assert "atomic replacement boundary" in result.stderr.lower()
    assert "published" not in result.stdout.lower()
    assert output.read_bytes() == prior_evidence
    assert not list(output.parent.glob(f".{output.name}.*"))


def test_tracked_publication_is_stable_after_its_own_evidence_commit(
    publication_case: tuple[Path, Path, Path, list[dict[str, object]], Path],
) -> None:
    repository, _source, data, contract, receipt = publication_case
    output = repository / "runtime_evidence" / "JAA-00-online-snapshot.yaml"
    first_result = _cli(
        repository, contract, "publish-evidence", "--receipt", str(receipt),
        "--data-root", str(data), "--repository", str(repository),
    )
    assert first_result.returncode == 0, first_result.stderr
    first = output.read_bytes()
    receipt_document = json.loads(receipt.read_text(encoding="utf-8"))
    capture_revision = receipt_document["content"]["repository"]["revision"]

    subprocess.run(["git", "add", str(output.relative_to(repository))], cwd=repository, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "track generated evidence"],
        cwd=repository,
        check=True,
    )
    current_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repository, check=True,
        text=True, capture_output=True,
    ).stdout.strip()
    assert current_revision != capture_revision

    second_result = _cli(
        repository, contract, "publish-evidence", "--receipt", str(receipt),
        "--data-root", str(data), "--repository", str(repository),
    )
    assert second_result.returncode == 0, second_result.stderr
    assert output.read_bytes() == first
    evidence = yaml.safe_load(first)
    assert evidence["repository"]["revision"] == capture_revision
    assert evidence["revision_binding"]["certified_revision"] == capture_revision

    source_file = repository / "baseline_adoption" / "cli.py"
    source_file.write_text(
        source_file.read_text(encoding="utf-8") + "\n# committed source drift\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", str(source_file.relative_to(repository))], cwd=repository, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "change product source"],
        cwd=repository,
        check=True,
    )
    rejected = _cli(
        repository, contract, "publish-evidence", "--receipt", str(receipt),
        "--data-root", str(data), "--repository", str(repository),
    )
    assert rejected.returncode == 2
    assert "source revision" in rejected.stderr.lower() or "inventory" in rejected.stderr.lower()
    assert output.read_bytes() == first


def test_dirty_tracked_source_cannot_publish_certification_evidence(
    publication_case: tuple[Path, Path, Path, list[dict[str, object]], Path], tmp_path: Path,
) -> None:
    repository, _source, data, contract, receipt = publication_case
    (repository / "baseline_adoption" / "cli.py").write_text(
        (repository / "baseline_adoption" / "cli.py").read_text(encoding="utf-8") + "\n# dirty\n",
        encoding="utf-8",
    )
    output = tmp_path / "must-not-exist.yaml"
    result = _cli(repository, contract, "publish-evidence", "--receipt", str(receipt),
                  "--data-root", str(data), "--repository", str(repository), "--output", str(output))

    assert result.returncode == 2
    assert not output.exists()
    assert "published" not in result.stdout
    assert "source" in result.stderr.lower() or "tracked" in result.stderr.lower()


def test_online_row_floor_regression_precedes_every_snapshot_and_receipt(tmp_path: Path) -> None:
    repository = _git_repository(tmp_path / "repository")
    source = tmp_path / "source"
    for name in ("jobs", "pipeline"):
        _database(source / "inputs" / f"{name}.sqlite3", 3)
    contract = [_contract(source, name, 3) for name in ("jobs", "pipeline")]
    with sqlite3.connect(source / "inputs" / "jobs.sqlite3") as connection:
        connection.execute("DELETE FROM ledger WHERE id = 1")
    data = tmp_path / "data"

    result = _cli(repository, contract, "adopt-online", "--source-root", str(source),
                  "--data-root", str(data), "--repository", str(repository))

    assert result.returncode == 2
    assert "row counts regressed below historical floors" in result.stderr
    assert not any((data / item["destination_relative"]).exists() for item in contract)
    assert not (data / "receipts").exists()
