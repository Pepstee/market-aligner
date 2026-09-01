"""Adversarial ownership checks for frozen JAA-01 and live JAA-00 evidence.

This module computes receipt facts independently. JAA-01 is historical
evidence: no later operator database observation may become an input to its
validity. JAA-00 is the only owner of a new live observation.
"""

from __future__ import annotations

import copy
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
SOURCE_CONTENT_REVISION_CONTRACT = {
    "algorithm": "sha256",
    "domain": "jaa-source-content-revision-v2",
    "entry_encoding": "uint64be-length-prefixed-path-mode-content",
    "exclusions": ["runtime_evidence/"],
    "ordering": "repository-relative-path-byte-order",
    "scope": "current-tracked-source-tree",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _receipt() -> tuple[Path, dict[str, Any]]:
    paths = sorted((ROOT / "runtime_evidence" / "jaa01").glob("sha256-*.json"))
    assert paths
    documents: list[tuple[Path, bytes, dict[str, Any]]] = []
    for path in paths:
        payload = path.read_bytes()
        assert path.name == f"sha256-{hashlib.sha256(payload).hexdigest()}.json"
        documents.append((path, payload, json.loads(payload)))

    first_parent_lineage = {
        revision.decode("ascii"): position
        for position, revision in enumerate(
            _git("rev-list", "--first-parent", "HEAD").splitlines()
        )
    }
    current = sorted(
        (
            first_parent_lineage[document["source_git_revision"]],
            path,
            document,
        )
        for path, _payload, document in documents
        if document.get("source_git_revision") in first_parent_lineage
    )
    assert current, "no JAA-01 receipt is bound to the current first-parent lineage"
    _position, path, document = current[0]
    return path, document


def _git_at(root: Path, *arguments: str) -> bytes:
    import subprocess

    completed = subprocess.run(
        ("git", *arguments),
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return completed.stdout


def _git(*arguments: str) -> bytes:
    return _git_at(ROOT, *arguments)


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


def _independent_revision_at(revision: str, root: Path = ROOT) -> str:
    """Recompute the published framing at one exact ancestral commit."""
    assert (
        len(revision) == 40
        and revision == revision.lower()
        and all(character in "0123456789abcdef" for character in revision)
    ), "historical source revision must be one exact lowercase SHA-1"
    resolved = _git_at(root, "rev-parse", "--verify", f"{revision}^{{commit}}").strip()
    assert resolved == revision.encode("ascii"), (
        "historical source revision must resolve to the exact recorded commit"
    )
    _git_at(root, "merge-base", "--is-ancestor", revision, "HEAD")

    current_prefix = _git_at(root, "rev-parse", "--show-prefix").rstrip(b"\r\n")
    prefixed_paths = set(
        _git_at(
            root,
            "ls-tree",
            "-r",
            "--name-only",
            "--full-tree",
            revision,
        ).splitlines()
    )
    prefix = (
        current_prefix
        if current_prefix + b"tracked_source_revision.py" in prefixed_paths
        else b""
    )

    entries: list[tuple[bytes, bytes, bytes]] = []
    for record in _git_at(root, "ls-tree", "-r", "-z", "--full-tree", revision).split(
        b"\0"
    ):
        if not record:
            continue
        metadata, tab, relative = record.partition(b"\t")
        mode, object_type, object_id = metadata.split()
        assert tab and object_type == b"blob"
        assert mode in {b"100644", b"100755", b"120000"}
        if prefix and not relative.startswith(prefix):
            continue
        relative = relative[len(prefix) :]
        if not relative.startswith(EXCLUDED):
            entries.append(
                (
                    relative,
                    mode,
                    _git_at(root, "cat-file", "blob", object_id.decode("ascii")),
                )
            )

    digest = hashlib.sha256(DOMAIN)
    for relative, mode, payload in sorted(entries):
        for field in (relative, mode, payload):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return f"sha256:{digest.hexdigest()}"


def _assert_historical_receipt_binding(
    document: dict[str, Any], root: Path = ROOT
) -> str:
    assert (
        document["source_content_revision_contract"] == SOURCE_CONTENT_REVISION_CONTRACT
    )
    recomputed = _independent_revision_at(document["source_git_revision"], root)
    assert document["source_content_revision"] == recomputed
    return recomputed


def _make_live_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = sqlite3.connect(path, isolation_level=None, timeout=30)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE ledger (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    writer.executemany(
        "INSERT INTO ledger(value) VALUES (?)",
        [(f"row-{number}",) for number in range(4)],
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
        schema_sha256=hashlib.sha256(
            json.dumps(
                schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest(),
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
        writer.execute(
            "INSERT INTO ledger(value) VALUES ('changed-after-certification')"
        )
        changed_live_hashes = (_sha256(simulated_live), _sha256(wal))

        assert changed_live_hashes != original_live_hashes
        assert evidence.read_bytes() == original_bytes
        historical_revision = _assert_historical_receipt_binding(document)
        assert historical_revision != _independent_revision()
        assert (
            document["hashes"]["baseline_sha256_before"]
            == document["hashes"]["baseline_sha256_after"]
        )
        assert not any(
            value in rendered for value in (*original_live_hashes, *changed_live_hashes)
        )
        forbidden = (
            "source_root",
            "source_relative",
            "relative_location",
            "source_observations",
            "current_measurement",
            "historical_observation",
            "live.sqlite",
            "operator",
        )
        assert not any(token in rendered for token in forbidden)
        assert str(simulated_live) not in rendered
    finally:
        writer.close()


@pytest.mark.parametrize("revision", ["not-a-revision", "0" * 64])
def test_historical_revision_helper_rejects_malformed_or_missing_commit(
    revision: str,
) -> None:
    with pytest.raises(AssertionError):
        _independent_revision_at(revision)


def test_historical_revision_helper_rejects_non_commit_object() -> None:
    tree = _git("rev-parse", "HEAD^{tree}").decode("ascii").strip()
    with pytest.raises(AssertionError):
        _independent_revision_at(tree)


def test_historical_revision_binding_rejects_divergence_and_tampering(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "history"
    repository.mkdir()
    _git_at(repository, "init", "--quiet")
    _git_at(repository, "config", "user.name", "JAA test")
    _git_at(repository, "config", "user.email", "jaa-test@example.test")
    (repository / "alpha.txt").write_bytes(b"alpha\n")
    _git_at(repository, "add", "alpha.txt")
    _git_at(repository, "commit", "--quiet", "-m", "first")
    first = _git_at(repository, "rev-parse", "HEAD").decode("ascii").strip()

    expected = hashlib.sha256(DOMAIN)
    for field in (b"alpha.txt", b"100644", b"alpha\n"):
        expected.update(len(field).to_bytes(8, "big"))
        expected.update(field)
    expected_revision = f"sha256:{expected.hexdigest()}"

    _git_at(repository, "checkout", "--quiet", "-b", "divergent")
    (repository / "divergent.txt").write_bytes(b"divergent\n")
    _git_at(repository, "add", "divergent.txt")
    _git_at(repository, "commit", "--quiet", "-m", "divergent")
    divergent = _git_at(repository, "rev-parse", "HEAD").decode("ascii").strip()

    _git_at(repository, "checkout", "--quiet", "--detach", first)
    (repository / "current.txt").write_bytes(b"current\n")
    _git_at(repository, "add", "current.txt")
    _git_at(repository, "commit", "--quiet", "-m", "current")

    assert _independent_revision_at(first, repository) == expected_revision
    with pytest.raises(AssertionError):
        _independent_revision_at(divergent, repository)

    _, document = _receipt()
    tampered_content = copy.deepcopy(document)
    tampered_content["source_content_revision"] = "sha256:" + ("0" * 64)
    with pytest.raises(AssertionError):
        _assert_historical_receipt_binding(tampered_content)

    tampered_commit = copy.deepcopy(document)
    tampered_commit["source_git_revision"] = divergent
    with pytest.raises(AssertionError):
        _assert_historical_receipt_binding(tampered_commit, repository)


def test_recertification_records_two_live_originals_with_utc_and_read_only_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "live"
    raw = source_root / "originals" / "raw.sqlite3"
    pipeline = source_root / "originals" / "pipeline.sqlite3"
    writers = [_make_live_database(raw), _make_live_database(pipeline)]
    monkeypatch.setattr(
        core,
        "BASELINES",
        (
            _spec("raw_jobs", source_root, raw),
            _spec("career_pipeline", source_root, pipeline),
        ),
    )
    try:
        receipt = core.recertify_sources(source_root, tmp_path / "evidence")
        document = json.loads(receipt.read_text(encoding="utf-8"))["content"]
        observed = datetime.fromisoformat(
            document["observed_at_utc"].replace("Z", "+00:00")
        )
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
                "label": f"source:{name}",
                "relative_location": relative,
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
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    component: str,
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
            writer.execute(
                "INSERT INTO ledger(value) VALUES (?)", (f"{component}-drift",)
            )
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
