from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from market_aligner.state.operations import (
    INGEST_CYCLE_KIND,
    OperationJournal,
    OperationRefused,
    SealConflict,
    canonical_json,
    make_record,
    new_owner_id,
    parse_record,
)


def _record(operation_id: str, *, disposition: str = "in_flight") -> dict[str, object]:
    values: dict[str, object] = {
        "operation_id": operation_id,
        "kind": INGEST_CYCLE_KIND,
        "config_source": "/private/config.yaml",
        "config_file_sha256": "a" * 64,
        "config_sha256": "b" * 64,
        "source_scope": ["ashby", "greenhouse"],
        "data_home": "/private/data",
        "disposition": disposition,
        "owner_id": new_owner_id(),
        "started_at": "2026-08-28T08:00:00+00:00",
    }
    if disposition == "completed":
        values.update(
            finished_at="2026-08-28T08:00:01+00:00",
            result={
                "seen": 2,
                "new": 2,
                "fetched": 2,
                "errors": 0,
                "database_total": 2,
            },
        )
    return make_record(**values)  # type: ignore[arg-type]


def test_claim_and_owner_cas_publish_one_terminal_record(tmp_path: Path) -> None:
    journal = OperationJournal(tmp_path / "operations")
    claim = _record("collect-fixture-0001")
    claim_bytes = canonical_json(claim).encode()
    assert journal.claim(claim)
    assert not journal.claim(claim)
    completed = _record("collect-fixture-0001", disposition="completed")
    # Terminal identity retains the live owner's authority.
    completed = make_record(
        **{
            **{key: completed[key] for key in (
                "operation_id", "kind", "config_source", "config_file_sha256",
                "config_sha256", "source_scope", "data_home", "disposition",
                "finished_at", "result",
            )},
            "owner_id": claim["owner_id"],
            "started_at": claim["started_at"],
        }
    )
    journal.cas_replace(
        completed,
        claim_bytes,
        operation_id="collect-fixture-0001",
    )
    assert journal.load("collect-fixture-0001") == completed


def test_cas_conflict_preserves_exact_foreign_bytes(tmp_path: Path) -> None:
    journal = OperationJournal(tmp_path / "operations")
    claim = _record("collect-fixture-0002")
    assert journal.claim(claim)
    before = journal.record_path("collect-fixture-0002").read_bytes()
    completed = _record("collect-fixture-0002", disposition="completed")
    with pytest.raises(SealConflict):
        journal.cas_replace(
            completed,
            b"not-the-claimed-bytes",
            operation_id="collect-fixture-0002",
        )
    assert journal.record_path("collect-fixture-0002").read_bytes() == before


def test_unknown_rehashed_field_is_still_rejected() -> None:
    record = _record("collect-fixture-0003")
    record["forged"] = True
    unsigned = dict(record)
    unsigned.pop("record_sha256")
    record["record_sha256"] = hashlib.sha256(
        canonical_json(unsigned).encode()
    ).hexdigest()
    with pytest.raises(OperationRefused, match="field set mismatch"):
        parse_record(
            (canonical_json(record)).encode(),
            "collect-fixture-0003",
            "collect-fixture-0003.json",
        )


def test_journal_refuses_symlinked_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "operations"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(OperationRefused):
        OperationJournal(link)


def test_unresolved_intersecting_scope_is_reported(tmp_path: Path) -> None:
    journal = OperationJournal(tmp_path / "operations")
    assert journal.claim(_record("collect-fixture-0004"))
    blockers = journal.scan_unresolved_scope_blockers(
        "/private/data", ["greenhouse"]
    )
    assert [row["operation_id"] for row in blockers] == ["collect-fixture-0004"]
    assert blockers[0]["intersecting_boards"] == ["greenhouse"]
