"""Linux kernel controls for the multi-file mutation observation boundary."""

from __future__ import annotations

import errno
import hashlib
import os
import sqlite3
import struct
import sys
from pathlib import Path

import pytest

from baseline_adoption import core
from baseline_adoption.core import AdoptionError, _MutationBoundary


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux inotify assurance controls",
)


def test_read_only_access_is_clean_and_provider_is_truthful(
    tmp_path: Path,
) -> None:
    target = tmp_path / "source.sqlite3"
    target.write_bytes(b"stable")

    with _MutationBoundary([target], directories=[tmp_path]) as boundary:
        assert boundary.provider == "linux-inotify-in-modify"
        assert target.read_bytes() == b"stable"
        target.stat()
        boundary.assert_clean("read-only")


def test_quiescent_sqlite_wal_recertification_is_clean(
    tmp_path: Path,
) -> None:
    target = tmp_path / "source.sqlite3"
    writer = sqlite3.connect(target, isolation_level=None)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute(
        "CREATE TABLE ledger (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
    )
    writer.execute("INSERT INTO ledger(value) VALUES ('stable')")
    with sqlite3.connect(
        f"file:{target.resolve()}?mode=ro",
        uri=True,
    ) as reader:
        schema = core._schema_rows(reader)
    spec = core.BaselineSpec(
        name="quiescent",
        source_relative=target.name,
        destination_relative="databases/source.sqlite3",
        size=target.stat().st_size,
        sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
        schema_sha256=hashlib.sha256(
            core._canonical_bytes(schema)
        ).hexdigest(),
        schema_objects=len(schema),
        table_counts={"ledger": 1},
    )
    try:
        evidence = core._recertify_source(target, spec)
    finally:
        writer.close()

    assert evidence["content_comparison"]["kernel_mutation_boundary"] == {
        "provider": "linux-inotify-in-modify",
        "main_wal_and_directory_clean_through_final_observation": True,
    }


@pytest.mark.parametrize(
    "mutation",
    ("write", "chmod", "atomic_replace", "unlink_recreate", "sidecar"),
)
def test_file_and_namespace_mutations_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    target = tmp_path / "source.sqlite3"
    target.write_bytes(b"stable")

    with pytest.raises(AdoptionError, match="observed input drift"):
        with _MutationBoundary([target], directories=[tmp_path]) as boundary:
            if mutation == "write":
                target.write_bytes(b"changed")
            elif mutation == "chmod":
                target.chmod(0o600)
            elif mutation == "atomic_replace":
                replacement = tmp_path / "replacement"
                replacement.write_bytes(b"changed")
                os.replace(replacement, target)
            elif mutation == "unlink_recreate":
                target.unlink()
                target.write_bytes(b"changed")
            else:
                (tmp_path / "source.sqlite3-wal").write_bytes(b"sidecar")
            boundary.assert_clean(mutation)


def test_final_disarm_detects_a_write_after_the_body_check(
    tmp_path: Path,
) -> None:
    target = tmp_path / "source.sqlite3"
    target.write_bytes(b"stable")

    with pytest.raises(
        AdoptionError,
        match="final disarm: mutation boundary observed input drift",
    ):
        with _MutationBoundary([target], directories=[tmp_path]) as boundary:
            boundary.assert_clean("body")
            target.write_bytes(b"after-body-check")


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (
            struct.pack("iIII", -1, 0x00004000, 0, 0),
            "event queue overflowed",
        ),
        (b"\x00", "malformed event"),
        (
            struct.pack("iIII", 2_147_483_647, 0x00000002, 0, 0),
            "unknown watch",
        ),
    ),
)
def test_overflow_malformed_and_unknown_events_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    message: str,
) -> None:
    target = tmp_path / "source.sqlite3"
    target.write_bytes(b"stable")

    with _MutationBoundary([target], directories=[tmp_path]) as boundary:
        calls = iter((payload, BlockingIOError(errno.EAGAIN, "again")))

        def event_read(_descriptor: int, _size: int) -> bytes:
            result = next(calls)
            if isinstance(result, BaseException):
                raise result
            return result

        with monkeypatch.context() as patch:
            patch.setattr(os, "read", event_read)
            with pytest.raises(AdoptionError, match=message):
                boundary.assert_clean("injected")


def test_watch_invalidation_cannot_be_rearmed_or_reused(
    tmp_path: Path,
) -> None:
    target = tmp_path / "source.sqlite3"
    target.write_bytes(b"stable")

    with pytest.raises(AdoptionError, match="observed input drift"):
        with _MutationBoundary([target], directories=[tmp_path]) as boundary:
            target.unlink()
            for index in range(32):
                candidate = tmp_path / f"replacement-{index}"
                candidate.write_bytes(b"replacement")
                candidate.unlink()
            target.write_bytes(b"new inode")
            boundary.assert_clean("watch reuse")


def test_real_kernel_queue_overflow_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "source.sqlite3"
    target.write_bytes(b"stable")
    queue_limit = int(
        Path("/proc/sys/fs/inotify/max_queued_events").read_text(
            encoding="ascii"
        )
    )

    with pytest.raises(AdoptionError, match="event queue overflowed"):
        with _MutationBoundary([target], directories=[tmp_path]) as boundary:
            for index in range(queue_limit // 2 + 1_024):
                candidate = tmp_path / f"overflow-{index}"
                descriptor = os.open(
                    candidate,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC,
                    0o600,
                )
                os.close(descriptor)
                candidate.unlink()
            boundary.assert_clean("real overflow")
