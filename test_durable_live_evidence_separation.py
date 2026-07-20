"""Adversarial ownership checks for frozen JAA-01 and live JAA-00 evidence.

This module computes receipt facts independently. JAA-01 is historical
evidence: no later operator database observation may become an input to its
validity. JAA-00 is the only owner of a new live observation.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from baseline_adoption import core


ROOT = Path(__file__).resolve().parent
DOMAIN = b"jaa-source-content-revision-v2\0"
EXCLUDED = (b"runtime_evidence/",)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _receipt() -> tuple[Path, dict[str, Any]]:
    paths = sorted((ROOT / "runtime_evidence" / "jaa01").glob("sha256-*.json"))
    assert len(paths) == 1
    payload = paths[0].read_bytes()
    assert paths[0].name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
    return paths[0], json.loads(payload)


def _git(*arguments: str) -> bytes:
    import subprocess

    completed = subprocess.run(
        ("git", *arguments), cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return completed.stdout


def _independent_revision() -> str:
    """Implement the published framing without calling product revision code."""
    entries: list[tuple[bytes, bytes]] = []
    for record in _git("ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, tab, relative = record.partition(b"\t")
        mode, _object, stage = metadata.split()
        assert tab and stage == b"0"
        if not relative.startswith(EXCLUDED):
            entries.append((relative, mode))
    digest = hashlib.sha256(DOMAIN)
    for relative, mode in sorted(entries):
        candidate = ROOT / os.fsdecode(relative)
        status = candidate.lstat()
        if mode == b"120000":
            assert stat.S_ISLNK(status.st_mode)
            data = os.fsencode(os.readlink(candidate))
        else:
            assert mode in {b"100644", b"100755"} and stat.S_ISREG(status.st_mode)
            data = candidate.read_bytes()
        for field in (relative, mode, data):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return f"sha256:{digest.hexdigest()}"


def _make_live_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = sqlite3.connect(path, isolation_level=None, timeout=30)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE ledger (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    writer.executemany(
        "INSERT INTO ledger(value) VALUES (?)", [(f"row-{number}",) for number in range(4)]
    )
    assert Path(str(path) + "-wal").is_file()
    return writer


def _spec(name: str, source_root: Path, path: Path) -> core.BaselineSpec:
    with sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True) as connection:
        schema = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
    return core.BaselineSpec(
        name=name,
        source_relative=str(path.relative_to(source_root)),
        destination_relative=f"databases/{name}.sqlite3",
        size=path.stat().st_size,
        sha256=_sha256(path),
        schema_sha256=hashlib.sha256(json.dumps(
            schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
        schema_objects=len(schema),
        table_counts={"ledger": 4},
    )


def test_checked_in_jaa01_is_frozen_and_ignores_a_later_live_source_change(
    tmp_path: Path,
) -> None:
    evidence, document = _receipt()
    original_bytes = evidence.read_bytes()
    rendered = original_bytes.decode("utf-8")
    simulated_live = tmp_path / "operator" / "mutable.sqlite3"
    writer = _make_live_database(simulated_live)
    try:
        wal = Path(str(simulated_live) + "-wal")
        original_live_hashes = (_sha256(simulated_live), _sha256(wal))
        writer.execute("INSERT INTO ledger(value) VALUES ('changed-after-certification')")
        changed_live_hashes = (_sha256(simulated_live), _sha256(wal))

        assert changed_live_hashes != original_live_hashes
        assert evidence.read_bytes() == original_bytes
        assert document["source_content_revision"] == _independent_revision()
        assert document["hashes"]["baseline_sha256_before"] == document["hashes"][
            "baseline_sha256_after"
        ]
        assert not any(value in rendered for value in (*original_live_hashes, *changed_live_hashes))
        forbidden = (
            "source_root", "source_relative", "relative_location", "source_observations",
            "current_measurement", "historical_observation", "live.sqlite", "operator",
        )
        assert not any(token in rendered for token in forbidden)
        assert str(simulated_live) not in rendered
    finally:
        writer.close()


def test_recertification_records_two_live_originals_with_utc_and_read_only_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "live"
    raw = source_root / "originals" / "raw.sqlite3"
    pipeline = source_root / "originals" / "pipeline.sqlite3"
    writers = [_make_live_database(raw), _make_live_database(pipeline)]
    monkeypatch.setattr(
        core, "BASELINES",
        (_spec("raw_jobs", source_root, raw), _spec("career_pipeline", source_root, pipeline)),
    )
    try:
        receipt = core.recertify_sources(source_root, tmp_path / "evidence")
        document = json.loads(receipt.read_text(encoding="utf-8"))["content"]
        observed = datetime.fromisoformat(document["observed_at_utc"].replace("Z", "+00:00"))
        assert observed.tzinfo is not None
        assert observed.utcoffset() == timezone.utc.utcoffset(observed)
        assert document["source_content_revision"] == _independent_revision()
        assert set(document["databases"]) == {"raw_jobs", "career_pipeline"}
        for name, relative in (
            ("raw_jobs", "originals/raw.sqlite3"),
            ("career_pipeline", "originals/pipeline.sqlite3"),
        ):
            record = document["databases"][name]
            assert record["source"] == {
                "label": f"source:{name}", "relative_location": relative,
            }
            assert record["open_semantics"]["sqlite_uri_mode"] == "ro"
            assert record["open_semantics"]["query_only"] is True
            assert record["open_semantics"]["negative_write_probe"]["rejected"] is True
            assert record["content_comparison"]["main_unchanged"] is True
            assert record["content_comparison"]["wal_unchanged"] is True
    finally:
        for writer in writers:
            writer.close()


@pytest.mark.parametrize("component", ["main", "wal"])
def test_recertification_fails_closed_when_a_main_or_wal_read_drifts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, component: str,
) -> None:
    source_root = tmp_path / "live"
    database = source_root / "originals" / "racing.sqlite3"
    writer = _make_live_database(database)
    monkeypatch.setattr(core, "BASELINES", (_spec("racing", source_root, database),))
    real_hash = core._hash_file
    injected = False

    def mutate_after_first_hash(path: Path) -> str:
        nonlocal injected
        digest = real_hash(path)
        target = database if component == "main" else Path(str(database) + "-wal")
        if path == target and not injected:
            injected = True
            writer.execute("INSERT INTO ledger(value) VALUES (?)", (f"{component}-drift",))
            if component == "main":
                writer.execute("PRAGMA wal_checkpoint(FULL)")
        return digest

    monkeypatch.setattr(core, "_hash_file", mutate_after_first_hash)
    try:
        with pytest.raises(
            core.AdoptionError, match="main/WAL content changed or was uncertain"
        ):
            core.recertify_sources(source_root, tmp_path / component)
        assert injected, f"did not inject the requested {component} mutation"
        assert not list((tmp_path / component).glob("source-recertification-*.json"))
    finally:
        writer.close()
