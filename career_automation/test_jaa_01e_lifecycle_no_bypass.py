"""Adversarial, on-disk checks for the production gate-to-research lifecycle."""

from __future__ import annotations

import inspect
import json
import re
import sqlite3
from pathlib import Path

import pytest

from career_automation.database import CareerDatabase
from career_automation.engine import OpportunityGate, OpportunityPolicy, scored_job_from_payload
from career_automation.lifecycle import (
    IdempotencyConflict,
    InvalidTransition,
    LedgerDivergence,
    canonical_hash,
)
from career_automation.models import PipelineState


def _job(job_id: str = "lifecycle") -> object:
    return scored_job_from_payload({
        "board": "adversarial", "job_id": job_id,
        "url": f"https://example.test/jobs/{job_id}", "job_title": "Lifecycle Engineer",
        "company": "Example", "fit": 0.8, "opportunity": 0.9, "final": 80.0,
        "extraction_confidence": 0.95,
    })


def _dossier(job_key: str, claim: str = "A cited observation") -> dict[str, object]:
    return {
        "job_key": job_key,
        "model": {"provider": "test", "model_id": "researcher", "version": "1"},
        "sources": [{"id": "source-1", "url": "https://example.test/source"}],
        "claims": [{"text": claim, "source_ids": ["source-1"], "confidence": 0.8}],
    }


def _digest(value: object) -> str:
    return canonical_hash(value)


def _rows(path: Path, job_key: str) -> tuple[list[sqlite3.Row], list[sqlite3.Row]]:
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        return (
            conn.execute("SELECT * FROM pipeline_events WHERE job_key=? ORDER BY id", (job_key,)).fetchall(),
            conn.execute("SELECT * FROM lifecycle_transition_receipts WHERE job_key=? ORDER BY event_id", (job_key,)).fetchall(),
        )


def _assert_committed_receipts(path: Path, job_key: str, expected: int) -> None:
    events, receipts = _rows(path, job_key)
    committed = [event for event in events if event["event_type"] == "lifecycle_transition_committed"]
    assert len(committed) == expected
    assert len(receipts) == expected
    for event, receipt in zip(committed, receipts, strict=True):
        assert (receipt["event_id"], receipt["job_key"], receipt["from_state"], receipt["to_state"], receipt["idempotency_key"]) == (
            event["id"], event["job_key"], event["from_state"], event["to_state"], event["idempotency_key"]
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            with sqlite3.connect(path) as conn:
                conn.execute("UPDATE lifecycle_transition_receipts SET policy_id='altered' WHERE receipt_id=?", (receipt["receipt_id"],))


def _state(path: Path, job_key: str) -> str:
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT state FROM pipeline_jobs WHERE job_key=?", (job_key,)).fetchone()[0]


def _queue_and_dossier(path: Path, job_key: str) -> tuple[tuple[object, ...] | None, tuple[object, ...] | None]:
    with sqlite3.connect(path) as conn:
        return (
            conn.execute("SELECT status,lease_owner,attempts FROM employer_research_queue WHERE job_key=?", (job_key,)).fetchone(),
            conn.execute("SELECT dossier_hash,worker_id FROM employer_dossiers WHERE job_key=?", (job_key,)).fetchone(),
        )


def test_complete_gate_to_research_sequence_has_one_receipt_per_post_root_state_change(tmp_path: Path) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    database = CareerDatabase(path)
    gate = OpportunityGate(database)
    job = _job()
    job_key = job.key
    gate.import_jobs([job])

    assert gate.apply() == (1, 0)
    assert _state(path, job_key) == PipelineState.EMPLOYER_RESEARCH_QUEUED.value
    _assert_committed_receipts(path, job_key, 1)
    queue, dossier = _queue_and_dossier(path, job_key)
    assert queue == ("queued", None, 0) and dossier is None

    task = database.claim_research("worker-a", lease_seconds=60)
    assert task is not None and task.job_key == job_key
    assert _state(path, job_key) == PipelineState.EMPLOYER_RESEARCHING.value
    _assert_committed_receipts(path, job_key, 2)

    dossier_value = _dossier(job_key)
    database.complete_research(job_key=job_key, worker_id="worker-a", dossier=dossier_value, dossier_hash=_digest(dossier_value))
    assert _state(path, job_key) == PipelineState.EMPLOYER_RESEARCHED.value
    _assert_committed_receipts(path, job_key, 3)
    events, _ = _rows(path, job_key)
    proposal = [event for event in events if event["event_type"] == "lifecycle_transition_proposed"]
    assert len(proposal) == 1
    assert proposal[0]["actor_kind"] == "probabilistic"
    assert proposal[0]["to_state"] is None
    assert json.loads(proposal[0]["payload_json"])["proposed_state"] == PipelineState.EMPLOYER_RESEARCHED.value


def test_proposal_cannot_advance_state_and_receipt_or_transition_failures_rollback_everything(tmp_path: Path) -> None:
    path = tmp_path / "atomic.sqlite3"
    database = CareerDatabase(path)
    gate = OpportunityGate(database)
    job = _job("atomic")
    gate.import_jobs([job])
    key = job.key

    # A real SQLite receipt failure must roll back the gate's queue materialisation too.
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TRIGGER reject_gate_receipt BEFORE INSERT ON lifecycle_transition_receipts BEGIN SELECT RAISE(ABORT, 'forced receipt failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="forced receipt failure"):
        gate.apply()
    assert _state(path, key) == PipelineState.SCORED.value
    assert _queue_and_dossier(path, key) == (None, None)
    assert [event["event_type"] for event in _rows(path, key)[0]] == ["score_snapshot_imported"]

    with sqlite3.connect(path) as conn:
        conn.execute("DROP TRIGGER reject_gate_receipt")
    gate.apply()
    # The lease write precedes the reducer call, so a state-transition failure
    # is an especially useful check that the surrounding queue update rolls back.
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TRIGGER reject_lease_transition BEFORE UPDATE OF state ON pipeline_jobs WHEN NEW.state='employer_researching' BEGIN SELECT RAISE(ABORT, 'forced transition failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="forced transition failure"):
        database.claim_research("owner", lease_seconds=60)
    assert _state(path, key) == PipelineState.EMPLOYER_RESEARCH_QUEUED.value
    assert _queue_and_dossier(path, key) == (("queued", None, 0), None)
    _assert_committed_receipts(path, key, 1)
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TRIGGER reject_lease_transition")
    task = database.claim_research("owner", lease_seconds=60)
    assert task is not None
    before = _rows(path, key)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TRIGGER reject_completion_receipt BEFORE INSERT ON lifecycle_transition_receipts BEGIN SELECT RAISE(ABORT, 'forced completion failure'); END")
    dossier_value = _dossier(key)
    with pytest.raises(sqlite3.IntegrityError, match="forced completion failure"):
        database.complete_research(job_key=key, worker_id="owner", dossier=dossier_value, dossier_hash=_digest(dossier_value))
    assert _state(path, key) == PipelineState.EMPLOYER_RESEARCHING.value
    assert _queue_and_dossier(path, key) == (("leased", "owner", 1), None)
    assert _rows(path, key) == before  # proposal, event and receipt shared the failed transaction.


def test_retries_conflicts_lease_owner_and_replay_stay_equal_across_sequence(tmp_path: Path) -> None:
    path = tmp_path / "retries.sqlite3"
    database = CareerDatabase(path)
    gate = OpportunityGate(database)
    job = _job("retry")
    gate.import_jobs([job])
    key = job.key
    assert gate.apply() == gate.apply() == (1, 0)
    first_events, first_receipts = _rows(path, key)
    assert len(first_events) == 2 and len(first_receipts) == 1

    with pytest.raises((IdempotencyConflict, InvalidTransition)):
        OpportunityGate(database, OpportunityPolicy(minimum_opportunity=0.8, high_priority_opportunity=0.85)).apply()
    assert _rows(path, key) == (first_events, first_receipts)

    assert database.claim_research("owner", lease_seconds=60) is not None
    dossier_value = _dossier(key)
    digest = _digest(dossier_value)
    with pytest.raises(RuntimeError, match="not leased"):
        database.complete_research(job_key=key, worker_id="intruder", dossier=dossier_value, dossier_hash=digest)
    database.complete_research(job_key=key, worker_id="owner", dossier=dossier_value, dossier_hash=digest)
    stable = _rows(path, key)
    database.complete_research(job_key=key, worker_id="owner", dossier=dossier_value, dossier_hash=digest)
    assert _rows(path, key) == stable

    changed = _dossier(key, "Changed dossier")
    with pytest.raises((IdempotencyConflict, InvalidTransition)):
        database.complete_research(job_key=key, worker_id="owner", dossier=changed, dossier_hash=_digest(changed))
    assert _rows(path, key) == stable
    assert database.lifecycle.replay()[key] is PipelineState.EMPLOYER_RESEARCHED
    database.lifecycle.verify()


def test_all_dossiers_require_canonical_hash_and_replay_rejects_side_table_drift(
    tmp_path: Path,
) -> None:
    path = tmp_path / "dossier-integrity.sqlite3"
    database = CareerDatabase(path)
    job = _job("dossier-integrity")
    OpportunityGate(database).bootstrap([job])
    task = database.claim_research("owner", lease_seconds=60)
    assert task is not None
    dossier = _dossier(job.key)
    before = _rows(path, job.key)

    with pytest.raises(ValueError, match="canonical content"):
        database.complete_research(
            job_key=job.key,
            worker_id="owner",
            dossier=dossier,
            dossier_hash="0" * 64,
        )
    assert _state(path, job.key) == PipelineState.EMPLOYER_RESEARCHING.value
    assert _queue_and_dossier(path, job.key) == (("leased", "owner", 1), None)
    assert _rows(path, job.key) == before

    database.complete_research(
        job_key=job.key,
        worker_id="owner",
        dossier=dossier,
        dossier_hash=_digest(dossier),
    )
    database.lifecycle.verify()
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE employer_dossiers SET dossier_hash=? WHERE job_key=?",
            ("f" * 64, job.key),
        )
    with pytest.raises(LedgerDivergence, match="research side tables diverge"):
        database.lifecycle.replay()


def test_opportunity1_atomically_rejects_a_dossier_that_no_longer_matches_completion(
    tmp_path: Path,
) -> None:
    path = tmp_path / "opportunity1-dossier-seam.sqlite3"
    database = CareerDatabase(path)
    job = _job("opportunity1-dossier-seam")
    OpportunityGate(database).bootstrap([job])
    assert database.claim_research("owner", lease_seconds=60) is not None
    dossier = _dossier(job.key)
    database.complete_research(
        job_key=job.key,
        worker_id="owner",
        dossier=dossier,
        dossier_hash=_digest(dossier),
    )
    altered = {**dossier, "claims": [{
        "text": "Injected observation",
        "source_ids": ["source-1"],
        "confidence": 0.8,
    }]}
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE employer_dossiers SET dossier_json=? WHERE job_key=?",
            (json.dumps(altered, ensure_ascii=False, sort_keys=True), job.key),
        )
    stable = _rows(path, job.key)

    with pytest.raises(RuntimeError, match="identity or hash"):
        database.apply_opportunity1(job_key=job.key, signals=[])
    assert _rows(path, job.key) == stable
    assert _state(path, job.key) == PipelineState.EMPLOYER_RESEARCHED.value
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM opportunity_reassessments WHERE job_key=?", (job.key,),
        ).fetchone()[0] == 0


def test_opportunity1_identical_retry_returns_the_durable_result_without_new_rows(tmp_path: Path) -> None:
    path = tmp_path / "opportunity1-retry.sqlite3"
    database = CareerDatabase(path)
    job = _job("opportunity1-retry")
    OpportunityGate(database).bootstrap([job])
    task = database.claim_research("owner", lease_seconds=60)
    assert task is not None
    dossier_value = _dossier(job.key)
    database.complete_research(
        job_key=job.key,
        worker_id="owner",
        dossier=dossier_value,
        dossier_hash=_digest(dossier_value),
    )

    first = database.apply_opportunity1(job_key=job.key, signals=[])
    stable_events, stable_receipts = _rows(path, job.key)
    with sqlite3.connect(path) as conn:
        stable_reassessments = conn.execute(
            "SELECT * FROM opportunity_reassessments WHERE job_key=?", (job.key,),
        ).fetchall()

    assert database.apply_opportunity1(job_key=job.key, signals=[]) == first
    assert _rows(path, job.key) == (stable_events, stable_receipts)
    with sqlite3.connect(path) as conn:
        assert conn.execute(
            "SELECT * FROM opportunity_reassessments WHERE job_key=?", (job.key,),
        ).fetchall() == stable_reassessments
    database.lifecycle.verify()


def test_gate_materialises_the_same_policy_identity_as_its_lifecycle_receipt(tmp_path: Path) -> None:
    path = tmp_path / "gate-policy.sqlite3"
    database = CareerDatabase(path)
    job = _job("gate-policy")
    database.upsert_scored_job(job)
    lifecycle_digest = "1" * 64

    database.apply_opportunity_result(
        job_key=job.key,
        passed=True,
        reason="verified opportunity",
        policy_hash=lifecycle_digest,
        priority=1,
    )

    with sqlite3.connect(path) as conn:
        materialised = conn.execute(
            "SELECT policy_hash FROM pipeline_jobs WHERE job_key=?", (job.key,),
        ).fetchone()[0]
        receipt = conn.execute(
            "SELECT policy_hash FROM lifecycle_transition_receipts WHERE job_key=?",
            (job.key,),
        ).fetchone()[0]
    assert materialised == receipt == lifecycle_digest
    assert "lifecycle_policy_hash" not in inspect.signature(
        CareerDatabase.apply_opportunity_result
    ).parameters
    database.lifecycle.verify()


def test_career_database_source_cannot_directly_change_state_or_emit_non_root_state_event() -> None:
    """A small source guard catches the tempting bypass before runtime review does."""
    source = inspect.getsource(CareerDatabase)
    direct_updates = re.findall(r"UPDATE\s+pipeline_jobs\s+SET\s+([^;\"]+)", source, flags=re.IGNORECASE | re.DOTALL)
    assert direct_updates
    assert all(not re.search(r"\bstate\s*=", statement, flags=re.IGNORECASE) for statement in direct_updates)

    event_insert = re.search(
        r"INSERT(?:\s+OR\s+IGNORE)?\s+INTO\s+pipeline_events", source,
        flags=re.IGNORECASE,
    )
    assert event_insert is not None
    assert len(re.findall(
        r"INSERT(?:\s+OR\s+IGNORE)?\s+INTO\s+pipeline_events", source,
        flags=re.IGNORECASE,
    )) == 1
    start = event_insert.start()
    root_insert = source[start:start + 1_500]
    assert "score_snapshot_imported" in root_insert
    assert "PipelineState.SCORED.value" in root_insert
    assert "None" in root_insert
