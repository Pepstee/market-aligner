"""Independent adversarial checks for the JAA-01 lifecycle contract.

These tests deliberately exercise the public migration/database/reducer APIs
against on-disk SQLite files.  They do not share fixtures with implementation
tests so ledger corruption and ordering checks remain meaningful.
"""

from __future__ import annotations

import sqlite3
import tempfile
from collections import deque
from pathlib import Path

import pytest

from career_automation.database import CareerDatabase, SCHEMA
from career_automation.lifecycle import (
    LEGAL_TRANSITIONS,
    IdempotencyConflict,
    InvalidTransition,
    LedgerDivergence,
    LifecycleReducer,
    ModelIdentity,
    PolicyIdentity,
    canonical_hash,
)
from career_automation.migrations import (
    JAA_01_MIGRATIONS,
    Migration,
    MigrationRunner,
    apply_jaa_01_migrations,
)
from career_automation.models import ActorKind, PipelineState, ScoredJob


POLICY = PolicyIdentity("independent-contract", "1", canonical_hash({"revision": 1}))


def _job(key: str) -> ScoredJob:
    return ScoredJob(
        key=key, board="independent", job_id=key, url=f"https://example.test/{key}",
        title="Independent test job", company="Example", fit=0.8, opportunity=0.8,
        final_score=80.0, extraction_confidence=0.99, payload={"key": key},
        payload_hash=canonical_hash({"key": key}),
    )


def _seed_discovered(database: CareerDatabase, key: str) -> None:
    """Create a real legacy-style root event; no reducer API creates discovered jobs."""
    payload_hash = canonical_hash({"key": key})
    with database.transaction(immediate=True) as conn:
        conn.execute(
            """INSERT INTO pipeline_jobs(
                   job_key,board,job_id,url,title,company,opportunity,payload_json,
                   payload_hash,state
                 ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (key, "independent", key, f"https://example.test/{key}", "Job", "Example",
             0.8, "{}", payload_hash, PipelineState.DISCOVERED.value),
        )
        conn.execute(
            """INSERT INTO pipeline_events(
                   job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
                 ) VALUES(?,?,?,?,?,?,?)""",
            (key, "score_snapshot_imported", None, PipelineState.DISCOVERED.value,
             ActorKind.DETERMINISTIC.value, "{}", f"root:{key}"),
        )


def _path(start: PipelineState, goal: PipelineState) -> list[PipelineState]:
    queue: deque[tuple[PipelineState, list[PipelineState]]] = deque([(start, [])])
    seen = {start}
    while queue:
        state, steps = queue.popleft()
        if state == goal:
            return steps
        for next_state in LEGAL_TRANSITIONS[state]:
            if next_state not in seen:
                seen.add(next_state)
                queue.append((next_state, [*steps, next_state]))
    raise AssertionError(f"{goal.value} is not reachable from {start.value}")


def _counts(path: Path) -> tuple[int, int, str]:
    with sqlite3.connect(path) as conn:
        return (
            conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM lifecycle_transition_receipts").fetchone()[0],
            conn.execute("SELECT state FROM pipeline_jobs WHERE job_key='idempotent'").fetchone()[0],
        )


def test_migrations_cover_clean_and_large_legacy_ledgers_without_rewriting_them(tmp_path: Path) -> None:
    clean = tmp_path / "clean.sqlite3"
    assert apply_jaa_01_migrations(clean) == (1,)
    assert apply_jaa_01_migrations(clean) == ()
    with sqlite3.connect(clean) as conn:
        ledger = conn.execute(
            "SELECT version,name,checksum FROM career_schema_migrations ORDER BY version"
        ).fetchall()
    assert ledger == [(migration.version, migration.name, migration.checksum) for migration in JAA_01_MIGRATIONS]

    ordered = tmp_path / "ordered.sqlite3"
    ordered_migrations = (
        Migration(1, "first", ("CREATE TABLE first_table(id INTEGER)",)),
        Migration(2, "second", ("CREATE TABLE second_table(id INTEGER)",)),
    )
    ordered_runner = MigrationRunner(ordered)
    assert ordered_runner.apply(ordered_migrations) == (1, 2)
    assert ordered_runner.apply(ordered_migrations) == ()
    with sqlite3.connect(ordered) as conn:
        assert conn.execute("SELECT version,checksum FROM career_schema_migrations ORDER BY version").fetchall() == [
            (migration.version, migration.checksum) for migration in ordered_migrations
        ]

    legacy = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(legacy) as conn:
        conn.executescript(SCHEMA)
        jobs = [
            (f"legacy:{number}", "legacy", str(number), f"https://example.test/{number}",
             "Engineer", "Example", 0.7, "{}", canonical_hash({"number": number}), "scored")
            for number in range(462)
        ]
        conn.executemany(
            """INSERT INTO pipeline_jobs(job_key,board,job_id,url,title,company,opportunity,
               payload_json,payload_hash,state) VALUES(?,?,?,?,?,?,?,?,?,?)""", jobs,
        )
        events = [
            (f"legacy:{number // 2}", "score_snapshot_imported", None, "scored", "deterministic", "{}", f"legacy-event:{number}")
            for number in range(924)
        ]
        conn.executemany(
            """INSERT INTO pipeline_events(job_key,event_type,from_state,to_state,actor_kind,
               payload_json,idempotency_key) VALUES(?,?,?,?,?,?,?)""", events,
        )
    assert CareerDatabase(legacy).path == legacy
    with sqlite3.connect(legacy) as conn:
        assert conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 462
        assert conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == 924
        assert conn.execute("SELECT checksum FROM career_schema_migrations WHERE version=1").fetchone()[0] == JAA_01_MIGRATIONS[0].checksum


def test_migration_rejects_modified_applied_version_and_rolls_back_failed_version(tmp_path: Path) -> None:
    path = tmp_path / "transactional.sqlite3"
    runner = MigrationRunner(path)
    original = Migration(1, "items", ("CREATE TABLE items(id INTEGER PRIMARY KEY)",))
    assert runner.apply((original,)) == (1,)
    with pytest.raises(RuntimeError, match="modified"):
        runner.apply((Migration(1, "items", ("CREATE TABLE items(id TEXT PRIMARY KEY)",)),))
    broken = Migration(2, "broken", ("CREATE TABLE should_rollback(id INTEGER)", "INSERT INTO absent VALUES(1)"))
    with pytest.raises(sqlite3.OperationalError):
        runner.apply((original, broken))
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT version,checksum FROM career_schema_migrations ORDER BY version").fetchall() == [(1, original.checksum)]
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='should_rollback'").fetchone() is None


def test_reducer_accepts_every_declared_edge_and_rejects_research_release_submit_shortcuts(tmp_path: Path) -> None:
    path = tmp_path / "edges.sqlite3"
    database = CareerDatabase(path)
    reducer = LifecycleReducer(path)
    edge_number = 0
    for source, targets in LEGAL_TRANSITIONS.items():
        for target in targets:
            key = f"edge:{edge_number}"
            edge_number += 1
            _seed_discovered(database, key)
            current = PipelineState.DISCOVERED
            for step in _path(current, source):
                reducer.commit(job_key=key, to_state=step, policy=POLICY, inputs={"edge": key, "to": step.value}, outputs={"ok": True}, idempotency_key=f"{key}:{step.value}")
            receipt = reducer.commit(job_key=key, to_state=target, policy=POLICY, inputs={"edge": key, "to": target.value}, outputs={"ok": True}, idempotency_key=f"{key}:target")
            assert (receipt.from_state, receipt.to_state) == (source, target)

    # Each of these is plausible-looking but skips a mandatory ordering gate.
    for name, destination in (("research", PipelineState.EMPLOYER_RESEARCHED), ("release", PipelineState.RELEASED), ("submit", PipelineState.SUBMITTED)):
        key = f"illegal:{name}"
        _seed_discovered(database, key)
        with pytest.raises(InvalidTransition, match="illegal or out-of-order"):
            reducer.commit(job_key=key, to_state=destination, policy=POLICY, inputs={}, outputs={}, idempotency_key=key)

    assert reducer.replay()["edge:0"] in PipelineState


def test_probabilistic_and_external_actors_only_record_non_mutating_proposals(tmp_path: Path) -> None:
    path = tmp_path / "actors.sqlite3"
    database = CareerDatabase(path)
    database.upsert_scored_job(_job("actors"))
    reducer = LifecycleReducer(path)
    for actor in (ActorKind.PROBABILISTIC, ActorKind.EXTERNAL):
        event_id = reducer.record_proposal(job_key="actors", proposed_state=PipelineState.EMPLOYER_RESEARCH_QUEUED, actor=actor, observation={"actor": actor.value}, idempotency_key=f"proposal:{actor.value}")
        assert event_id > 0
    with database.connection() as conn:
        assert conn.execute("SELECT state FROM pipeline_jobs WHERE job_key='actors'").fetchone()[0] == PipelineState.SCORED.value
        assert conn.execute("SELECT COUNT(*) FROM lifecycle_transition_receipts").fetchone()[0] == 0
    with pytest.raises(ValueError, match="probabilistic or external"):
        reducer.record_proposal(job_key="actors", proposed_state=PipelineState.EMPLOYER_RESEARCH_QUEUED, actor=ActorKind.DETERMINISTIC, observation={}, idempotency_key="deterministic-proposal")


def test_transition_idempotency_is_exact_and_conflicts_leave_no_mutation(tmp_path: Path) -> None:
    path = tmp_path / "idempotency.sqlite3"
    database = CareerDatabase(path)
    database.upsert_scored_job(_job("idempotent"))
    reducer = LifecycleReducer(path)
    base = dict(job_key="idempotent", to_state=PipelineState.EMPLOYER_RESEARCH_QUEUED, policy=POLICY, inputs={"a": 1}, outputs={"result": "pass"}, idempotency_key="same-key")
    first = reducer.commit(**base)
    assert reducer.commit(**base) == first
    before = _counts(path)
    variations = (
        {"inputs": {"a": 2}}, {"outputs": {"result": "different"}},
        {"policy": PolicyIdentity("other", "1", canonical_hash({"revision": 1}))},
        {"model": ModelIdentity("provider", "model", "1")},
        {"to_state": PipelineState.OPPORTUNITY_REJECTED},
    )
    for changed in variations:
        with pytest.raises(IdempotencyConflict):
            reducer.commit(**{**base, **changed})
        assert _counts(path) == before


def test_replay_reconstructs_states_and_detects_divergence_order_and_receipt_identity_tampering(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    database = CareerDatabase(path)
    _seed_discovered(database, "replay")
    reducer = LifecycleReducer(path)
    first = reducer.commit(job_key="replay", to_state=PipelineState.FETCHED, policy=POLICY, inputs={"n": 1}, outputs={}, idempotency_key="replay:1")
    reducer.commit(job_key="replay", to_state=PipelineState.NORMALISED, policy=POLICY, inputs={"n": 2}, outputs={}, idempotency_key="replay:2")
    assert reducer.replay() == {"replay": PipelineState.NORMALISED}

    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE pipeline_jobs SET state='eligible' WHERE job_key='replay'")
    with pytest.raises(LedgerDivergence, match="materialised state diverges"):
        reducer.verify()
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE pipeline_jobs SET state='normalised' WHERE job_key='replay'")
        conn.execute("UPDATE pipeline_events SET idempotency_key='tampered-event-key' WHERE id=?", (first.event_id,))
    with pytest.raises(LedgerDivergence, match="tampered receipt identity"):
        reducer.verify()

    impossible = tmp_path / "impossible.sqlite3"
    other_database = CareerDatabase(impossible)
    _seed_discovered(other_database, "impossible")
    with other_database.transaction(immediate=True) as conn:
        conn.execute("UPDATE pipeline_jobs SET state='eligible' WHERE job_key='impossible'")
        conn.execute(
            """INSERT INTO pipeline_events(job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key)
               VALUES(?,?,?,?,?,?,?)""",
            ("impossible", "score_snapshot_imported", PipelineState.DISCOVERED.value,
             PipelineState.ELIGIBLE.value, ActorKind.DETERMINISTIC.value, "{}", "impossible-order"),
        )
    with pytest.raises(LedgerDivergence, match="out of order or illegal"):
        LifecycleReducer(impossible).replay()
