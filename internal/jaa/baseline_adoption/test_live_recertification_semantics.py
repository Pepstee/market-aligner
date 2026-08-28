"""Independent black-box tests for live source recertification.

These tests never replace a product verifier or SQLite connection factory.  They
exercise ``jaa-baseline recertify-sources`` in a new interpreter against ordinary
SQLite files, including an owner-writable WAL source.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
LIVE_ROOT = Path("/Users/admin/Claude/Projects/Korea Job Scraper")
LIVE_RELATIVE = {
    "raw_jobs": "scraper/data_overnight/jobs.sqlite3",
    "career_pipeline": "outputs/career_automation/career_pipeline.sqlite3",
}
SOURCE_REVISION_DOMAIN = b"jaa-source-content-revision-v2\0"
SOURCE_REVISION_EXCLUSIONS = (b"runtime_evidence/",)


def _git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", *arguments), cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return completed.stdout


def _independent_source_revision(root: Path) -> str:
    """Reimplement the published byte framing without importing product code."""
    entries: list[tuple[bytes, bytes]] = []
    for record in _git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        mode, _object_id, stage = metadata.split()
        assert separator and stage == b"0"
        if not path.startswith(SOURCE_REVISION_EXCLUSIONS):
            entries.append((path, mode))
    digest = hashlib.sha256(SOURCE_REVISION_DOMAIN)
    for path, mode in sorted(entries):
        candidate = root / os.fsdecode(path)
        status = candidate.lstat()
        if mode == b"120000":
            assert stat.S_ISLNK(status.st_mode)
            payload = os.fsencode(os.readlink(candidate))
        else:
            assert mode in {b"100644", b"100755"} and stat.S_ISREG(status.st_mode)
            payload = candidate.read_bytes()
        for field in (path, mode, payload):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return f"sha256:{digest.hexdigest()}"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _live_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=30)


def _contract(name: str, source_root: Path, path: Path, *, counts: dict[str, int] | None = None,
              schema: list[list[Any]] | None = None) -> dict[str, object]:
    with _live_connection(path) as connection:
        observed_schema = [list(row) for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        )]
        observed_counts = {
            row[1]: int(connection.execute(
                'SELECT COUNT(*) FROM "' + row[1].replace('"', '""') + '"'
            ).fetchone()[0])
            for row in observed_schema if row[0] == "table"
        }
    chosen_schema = observed_schema if schema is None else schema
    return {
        "name": name,
        "source_relative": str(path.relative_to(source_root)),
        "destination_relative": f"databases/{name}.sqlite3",
        # Historical hashes and sizes are deliberately supplied but the live
        # command must retain them as historical observations, not remeasurements.
        "size": path.stat().st_size,
        "sha256": _sha256(path),
        "schema_sha256": hashlib.sha256(json.dumps(
            chosen_schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
        "schema_objects": len(chosen_schema),
        "table_counts": observed_counts if counts is None else counts,
    }


def _run(source_root: Path, evidence: Path, contract: list[dict[str, object]] | None = None) -> subprocess.CompletedProcess[str]:
    # The command certifies its own tracked source tree.  Run it from a fresh
    # clone so this test module's deliberately uncommitted edits cannot mask
    # the source-side behaviour being tested.
    repository = evidence.parent / "certification-repository"
    if not repository.exists():
        cloned = subprocess.run(
            (
                "git",
                "clone",
                "--no-local",
                str(REPOSITORY_ROOT),
                str(repository),
            ),
            text=True, capture_output=True, check=False,
        )
        assert cloned.returncode == 0, cloned.stderr
    if contract is None:
        command = [sys.executable, "-m", "baseline_adoption.cli"]
    else:
        bootstrap = """
import json, sys
from baseline_adoption import cli, core
core.BASELINES = tuple(core.BaselineSpec(**item) for item in json.loads(sys.argv[1]))
raise SystemExit(cli.main(sys.argv[2:]))
"""
        command = [sys.executable, "-c", bootstrap, json.dumps(contract)]
    return subprocess.run(
        [*command, "recertify-sources", "--source-root", str(source_root),
         "--evidence-directory", str(evidence)],
        cwd=repository / "internal" / "jaa",
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )


def _receipt(result: subprocess.CompletedProcess[str]) -> tuple[Path, dict[str, Any]]:
    assert result.returncode == 0, result.stderr
    rendered = json.loads(result.stdout)
    assert rendered["status"] == "recertified"
    path = Path(rendered["receipt"])
    document = json.loads(path.read_text(encoding="utf-8"))
    return path, document


def _make_wal(path: Path, *, rows: int = 8) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = sqlite3.connect(path, isolation_level=None, timeout=30)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE ledger (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    writer.executemany("INSERT INTO ledger(value) VALUES (?)", [(f"seed-{n}",) for n in range(rows)])
    assert Path(str(path) + "-wal").is_file()
    assert Path(str(path) + "-shm").is_file()
    return writer


def _source_state(path: Path) -> dict[str, bytes | None]:
    return {name: candidate.read_bytes() if candidate.exists() else None for name, candidate in {
        "main": path, "wal": Path(str(path) + "-wal")
    }.items()}


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for child in value.values() for text in _strings(child)]
    if isinstance(value, list):
        return [text for child in value for text in _strings(child)]
    return []


def test_real_operator_sources_recertify_without_path_disclosure_or_source_mutation(tmp_path: Path) -> None:
    """The real operator root is covered without copying it into the repository."""
    paths = {name: LIVE_ROOT / relative for name, relative in LIVE_RELATIVE.items()}
    assert all(path.is_file() and not path.is_symlink() for path in paths.values())
    before = {name: _source_state(path) for name, path in paths.items()}

    result = _run(LIVE_ROOT, tmp_path / "evidence")

    receipt, document = _receipt(result)
    assert document["content"]["format"] == "jaa-00-source-recertification/v2"
    assert set(document["content"]["databases"]) == set(LIVE_RELATIVE)
    assert str(LIVE_ROOT) not in receipt.read_text(encoding="utf-8")
    assert {name: _source_state(path) for name, path in paths.items()} == before
    for name, record in document["content"]["databases"].items():
        assert record["source"]["relative_location"] == LIVE_RELATIVE[name]
        assert record["open_semantics"]["sqlite_uri_mode"] == "ro"
        assert record["open_semantics"]["query_only"] is True
        assert record["open_semantics"]["negative_write_probe"]["rejected"] is True
        # The historical source contract is not silently updated to its live view.
        assert record["historical_observation"]["observed_table_counts"] != {}
        assert record["historical_observation"]["observed_sha256"] != record["current_measurement"].get("sha256")


def test_two_live_sources_emit_path_free_content_addressed_utc_provenance(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    raw_jobs = source_root / "inputs" / "raw_jobs.sqlite3"
    career_pipeline = source_root / "inputs" / "career_pipeline.sqlite3"
    raw_writer = _make_wal(raw_jobs)
    pipeline_writer = _make_wal(career_pipeline, rows=11)
    try:
        contract = [
            _contract("raw_jobs", source_root, raw_jobs),
            _contract("career_pipeline", source_root, career_pipeline),
        ]
        before = {"raw_jobs": _source_state(raw_jobs), "career_pipeline": _source_state(career_pipeline)}
        result = _run(source_root, tmp_path / "evidence", contract)
        receipt, document = _receipt(result)
        content = document["content"]
        observed = datetime.fromisoformat(content["observed_at_utc"].replace("Z", "+00:00"))
        assert observed.tzinfo is not None and observed.utcoffset() == timezone.utc.utcoffset(observed)
        assert content["observed_at_utc"].endswith("Z")
        assert content["source_content_revision"] == _independent_source_revision(
            (tmp_path / "evidence").parent / "certification-repository"
        )
        assert set(content["databases"]) == {"raw_jobs", "career_pipeline"}
        assert content["isolation"] == {
            "source_connections": "read-only-query-only",
            "source_write_operations": "none-successful; transactional schema probes rejected",
            "adopted_product_databases": "not-opened-by-recertification",
        }
        canonical_content = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        assert document["content_sha256"] == hashlib.sha256(canonical_content).hexdigest()
        assert receipt.name == f"source-recertification-{document['content_sha256']}.json"
        assert receipt.read_bytes() == json.dumps(
            document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode() + b"\n"
        rendered = receipt.read_text(encoding="utf-8")
        assert str(source_root) not in rendered and str(tmp_path) not in rendered
        assert not any(text.startswith("/") for text in _strings(document))
        for name, expected_rows in (("raw_jobs", 8), ("career_pipeline", 11)):
            record = content["databases"][name]
            assert record["source"] == {
                "label": f"source:{name}",
                "relative_location": f"inputs/{name}.sqlite3",
            }
            assert record["open_semantics"] == {
                "sqlite_uri_mode": "ro", "query_only": True,
                "negative_write_probe": {
                    "attempted": True, "operation": "transactional-main-schema-create",
                    "rejected": True, "sqlite_primary_error": "SQLITE_READONLY",
                },
            }
            assert record["current_measurement"]["row_counts"] == {"ledger": expected_rows}
            assert {"main", "wal", "shm"} == set(record["source_observations_start"])
        assert {"raw_jobs": _source_state(raw_jobs), "career_pipeline": _source_state(career_pipeline)} == before
        assert raw_writer.execute("SELECT COUNT(*) FROM ledger").fetchone() == (8,)
        assert pipeline_writer.execute("SELECT COUNT(*) FROM ledger").fetchone() == (11,)
        for writer in (raw_writer, pipeline_writer):
            assert writer.execute("SELECT name FROM sqlite_schema WHERE name='__jaa_recertification_write_probe'").fetchone() is None
    finally:
        raw_writer.close()
        pipeline_writer.close()


@pytest.mark.parametrize("case", ["missing", "symlink", "corrupt", "schema", "regression"])
def test_recertification_negative_source_controls_fail_closed(tmp_path: Path, case: str) -> None:
    source_root = tmp_path / "source"
    database = source_root / "inputs" / "source.sqlite3"
    writer = _make_wal(database, rows=3)
    try:
        contract = [_contract("source", source_root, database)]
        if case == "missing":
            writer.close()
            database.unlink()
        elif case == "symlink":
            writer.close()
            target = tmp_path / "target.sqlite3"
            database.replace(target)
            database.symlink_to(target)
        elif case == "corrupt":
            writer.close()
            Path(str(database) + "-wal").unlink(missing_ok=True)
            Path(str(database) + "-shm").unlink(missing_ok=True)
            database.write_bytes(b"not a sqlite database")
            contract[0]["size"] = database.stat().st_size
            contract[0]["sha256"] = _sha256(database)
        elif case == "schema":
            contract[0]["schema_sha256"] = "0" * 64
        else:
            contract[0]["table_counts"] = {"ledger": 4}

        result = _run(source_root, tmp_path / case, contract)

        assert result.returncode == 2
        expected = {
            "missing": "source does not exist", "symlink": "regular, non-symlink",
            "corrupt": "schema write probe failed for a reason other than read-only", "schema": "schema mismatch",
            "regression": "row counts regressed",
        }[case]
        assert expected in result.stderr
        assert not list((tmp_path / case).glob("source-recertification-*.json"))
    finally:
        if case not in {"missing", "symlink", "corrupt"}:
            writer.close()


def test_recertification_rejects_a_real_before_after_wal_mutation_and_leaves_no_receipt(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    database = source_root / "inputs" / "racing.sqlite3"
    writer = _make_wal(database, rows=150_000)
    contract = [_contract("racing", source_root, database)]
    evidence = tmp_path / "evidence"
    started = threading.Event()
    stop = threading.Event()
    write_errors: list[BaseException] = []

    def mutate_wal() -> None:
        connection = sqlite3.connect(database, isolation_level=None, timeout=30)
        try:
            # Repeated committed writes make a genuine main/WAL observation
            # race; no result is accepted unless it is detected and failed closed.
            connection.execute("INSERT INTO ledger(value) VALUES ('race-ready')")
            started.set()
            number = 0
            while not stop.is_set():
                connection.execute("INSERT INTO ledger(value) VALUES (?)", (f"race-{number}",))
                number += 1
        except BaseException as exc:  # surfaced in the asserting thread
            write_errors.append(exc)
        finally:
            connection.close()

    thread = threading.Thread(target=mutate_wal)
    thread.start()
    try:
        assert started.wait(timeout=10), "race writer did not start"
        result = _run(source_root, evidence, contract)
    finally:
        stop.set()
        thread.join(timeout=20)
        writer.close()

    assert not thread.is_alive(), "test writer did not complete"
    assert not write_errors, repr(write_errors)
    assert result.returncode == 2, (
        "a genuine source mutation was not failed closed; stderr=" + result.stderr
    )
    assert "main/WAL content changed or was uncertain" in result.stderr
    assert not list(evidence.glob("source-recertification-*.json"))


def test_malformed_existing_evidence_is_never_overwritten_and_historical_contract_stays_historical(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    database = source_root / "inputs" / "stable.sqlite3"
    writer = _make_wal(database, rows=2)
    try:
        historical = _contract("stable", source_root, database)
        historical["sha256"] = "f" * 64
        historical["size"] = 1
        historical["table_counts"] = {"ledger": 1}
        result = _run(source_root, tmp_path / "evidence", [historical])
        receipt, document = _receipt(result)
        record = document["content"]["databases"]["stable"]
        assert record["historical_observation"]["observed_sha256"] == "f" * 64
        assert record["historical_observation"]["observed_bytes"] == 1
        assert record["historical_observation"]["observed_table_counts"] == {"ledger": 1}
        assert record["current_measurement"]["row_counts"] == {"ledger": 2}

        receipt.write_text("{malformed evidence", encoding="utf-8")
        rejected = _run(source_root, tmp_path / "evidence", [historical])
        assert rejected.returncode == 2
        assert "certified recertification receipt content mismatch" in rejected.stderr
        assert receipt.read_text(encoding="utf-8") == "{malformed evidence"
    finally:
        writer.close()
