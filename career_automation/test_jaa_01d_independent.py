"""Independent adversarial checks for the JAA-01 lifecycle contract.

These tests deliberately exercise the public migration/database/reducer APIs
against on-disk SQLite files.  They do not share fixtures with implementation
tests so ledger corruption and ordering checks remain meaningful.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from dataclasses import replace
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
    canonical_json,
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


def _seed_state_without_history(
    database: CareerDatabase, key: str, state: PipelineState,
) -> None:
    """Place a job at one reducer input state without manufacturing replay evidence."""
    payload_hash = canonical_hash({"key": key})
    with database.transaction(immediate=True) as conn:
        conn.execute(
            """INSERT INTO pipeline_jobs(
                   job_key,board,job_id,url,title,company,opportunity,payload_json,
                   payload_hash,state
                 ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (key, "independent", key, f"https://example.test/{key}", "Job", "Example",
             0.8, "{}", payload_hash, state.value),
        )


def _counts(path: Path) -> tuple[int, int, str]:
    with sqlite3.connect(path) as conn:
        return (
            conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM lifecycle_transition_receipts").fetchone()[0],
            conn.execute("SELECT state FROM pipeline_jobs WHERE job_key='idempotent'").fetchone()[0],
        )


def test_migrations_cover_clean_and_large_legacy_ledgers_without_rewriting_them(tmp_path: Path) -> None:
    clean = tmp_path / "clean.sqlite3"
    assert apply_jaa_01_migrations(clean) == tuple(
        migration.version for migration in JAA_01_MIGRATIONS
    )
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
        payloads = [
            (json.dumps({"number": number}, sort_keys=True),
             canonical_hash({"number": number}))
            for number in range(462)
        ]
        jobs = [
            (f"legacy:{number}", "legacy", str(number), f"https://example.test/{number}",
             "Engineer", "Example", 0.7, payloads[number][0], payloads[number][1],
             "opportunity_rejected")
            for number in range(462)
        ]
        conn.executemany(
            """INSERT INTO pipeline_jobs(job_key,board,job_id,url,title,company,opportunity,
               payload_json,payload_hash,state) VALUES(?,?,?,?,?,?,?,?,?,?)""", jobs,
        )
        events = []
        for number in range(462):
            payload_hash = payloads[number][1]
            events.extend((
                (f"legacy:{number}", "score_snapshot_imported", None, "scored",
                 "deterministic", json.dumps({"payload_hash": payload_hash}, sort_keys=True),
                 f"score-import:legacy:{number}:{payload_hash}"),
                (f"legacy:{number}", "opportunity_gate_decided", "scored",
                 "opportunity_rejected", "deterministic",
                 json.dumps({"decision": "reject", "reason": "below_opportunity_threshold"},
                            sort_keys=True),
                 f"opportunity-gate:legacy:{number}:{payload_hash}:b38a8ff32e7d74ce"),
            ))
        conn.executemany(
            """INSERT INTO pipeline_events(job_key,event_type,from_state,to_state,actor_kind,
               payload_json,idempotency_key) VALUES(?,?,?,?,?,?,?)""", events,
        )
    assert CareerDatabase(legacy).path == legacy
    with sqlite3.connect(legacy) as conn:
        assert conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 462
        assert conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == 924
        assert conn.execute(
            "SELECT COUNT(*) FROM legacy_score_snapshot_cohort"
        ).fetchone()[0] == 462
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


@pytest.mark.parametrize(
    ("column", "changed"),
    [
        ("board", "changed-board"),
        ("job_id", "changed-id"),
        ("url", "https://example.test/changed"),
        ("title", "Changed title"),
        ("company", "Changed company"),
        ("fit", 0.1),
        ("opportunity", 0.1),
        ("final_score", 1.0),
        ("extraction_confidence", 0.1),
    ],
)
def test_frozen_legacy_cohort_binds_complete_materialised_score_snapshot(
    tmp_path: Path, column: str, changed: object,
) -> None:
    path = tmp_path / f"legacy-{column}.sqlite3"
    payload = {"legacy": "snapshot"}
    payload_json = json.dumps(payload, sort_keys=True)
    payload_hash = canonical_hash(payload)
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            """INSERT INTO pipeline_jobs(
                 job_key,board,job_id,url,title,company,fit,opportunity,final_score,
                 extraction_confidence,payload_json,payload_hash,state
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "legacy-snapshot", "legacy", "legacy-id",
                "https://example.test/legacy", "Legacy title", "Legacy company",
                0.8, 0.7, 70.0, 0.9, payload_json, payload_hash,
                PipelineState.SCORED.value,
            ),
        )
        conn.execute(
            """INSERT INTO pipeline_events(
                 job_key,event_type,from_state,to_state,actor_kind,payload_json,
                 idempotency_key
               ) VALUES(?,?,?,?,?,?,?)""",
            (
                "legacy-snapshot", "score_snapshot_imported", None,
                PipelineState.SCORED.value, ActorKind.DETERMINISTIC.value,
                json.dumps({"payload_hash": payload_hash}, sort_keys=True),
                f"score-import:legacy-snapshot:{payload_hash}",
            ),
        )
    reducer = LifecycleReducer(path)
    assert reducer.replay() == {"legacy-snapshot": PipelineState.SCORED}

    with sqlite3.connect(path) as conn:
        conn.execute(
            f"UPDATE pipeline_jobs SET {column}=? WHERE job_key='legacy-snapshot'",
            (changed,),
        )
    with pytest.raises(LedgerDivergence, match="materialised score snapshot diverges"):
        reducer.replay()


def test_replay_rejects_semantically_equal_payload_byte_reformatting(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy-payload-bytes.sqlite3"
    payload = {"legacy": "payload"}
    legacy_bytes = json.dumps(payload, sort_keys=True)
    payload_hash = canonical_hash(payload)
    with sqlite3.connect(legacy) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            """INSERT INTO pipeline_jobs(
                 job_key,board,job_id,url,title,company,opportunity,payload_json,
                 payload_hash,state
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                "legacy-payload", "legacy", "1", "https://example.test/legacy",
                "Legacy", "Example", 0.5, legacy_bytes, payload_hash,
                PipelineState.SCORED.value,
            ),
        )
        conn.execute(
            """INSERT INTO pipeline_events(
                 job_key,event_type,from_state,to_state,actor_kind,payload_json,
                 idempotency_key
               ) VALUES(?,?,?,?,?,?,?)""",
            (
                "legacy-payload", "score_snapshot_imported", None,
                PipelineState.SCORED.value, ActorKind.DETERMINISTIC.value,
                json.dumps({"payload_hash": payload_hash}, sort_keys=True),
                f"score-import:legacy-payload:{payload_hash}",
            ),
        )
    legacy_reducer = LifecycleReducer(legacy)
    assert legacy_reducer.replay() == {"legacy-payload": PipelineState.SCORED}
    with sqlite3.connect(legacy) as conn:
        conn.execute(
            "UPDATE pipeline_jobs SET payload_json=? WHERE job_key='legacy-payload'",
            (canonical_json(payload),),
        )
    with pytest.raises(LedgerDivergence, match="materialised score snapshot diverges"):
        legacy_reducer.replay()

    current = tmp_path / "current-payload-bytes.sqlite3"
    current_database = CareerDatabase(current)
    current_job = _job("current-payload")
    current_database.upsert_scored_job(current_job)
    with sqlite3.connect(current) as conn:
        conn.execute(
            "UPDATE pipeline_jobs SET payload_json=? WHERE job_key=?",
            (json.dumps(current_job.payload, ensure_ascii=False, sort_keys=True), current_job.key),
        )
    with pytest.raises(LedgerDivergence, match="canonical payload bytes"):
        LifecycleReducer(current).replay()


def test_reducer_accepts_every_declared_edge_and_rejects_research_release_submit_shortcuts(tmp_path: Path) -> None:
    path = tmp_path / "edges.sqlite3"
    database = CareerDatabase(path)
    reducer = LifecycleReducer(path)
    edge_number = 0
    for source, targets in LEGAL_TRANSITIONS.items():
        for target in targets:
            key = f"edge:{edge_number}"
            edge_number += 1
            _seed_state_without_history(database, key, source)
            receipt = reducer.commit(job_key=key, to_state=target, policy=POLICY, inputs={"edge": key, "to": target.value}, outputs={"ok": True}, idempotency_key=f"{key}:target")
            assert (receipt.from_state, receipt.to_state) == (source, target)

    # Each of these is plausible-looking but skips a mandatory ordering gate.
    for name, destination in (("research", PipelineState.EMPLOYER_RESEARCHED), ("release", PipelineState.RELEASED), ("submit", PipelineState.SUBMITTED)):
        key = f"illegal:{name}"
        _seed_state_without_history(database, key, PipelineState.DISCOVERED)
        with pytest.raises(InvalidTransition, match="illegal or out-of-order"):
            reducer.commit(job_key=key, to_state=destination, policy=POLICY, inputs={}, outputs={}, idempotency_key=key)

    replay_path = tmp_path / "reachable-replay.sqlite3"
    replay_database = CareerDatabase(replay_path)
    replay_database.upsert_scored_job(_job("reachable-replay"))
    LifecycleReducer(replay_path).commit(
        job_key="reachable-replay", to_state=PipelineState.EMPLOYER_RESEARCH_QUEUED,
        policy=POLICY, inputs={}, outputs={}, idempotency_key="reachable-replay:queue",
    )
    assert LifecycleReducer(replay_path).replay() == {
        "reachable-replay": PipelineState.EMPLOYER_RESEARCH_QUEUED,
    }


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


def test_changed_score_snapshot_is_rejected_without_corrupting_replay(tmp_path: Path) -> None:
    path = tmp_path / "changed-score-snapshot.sqlite3"
    database = CareerDatabase(path)
    original = _job("changed-score-snapshot")
    assert database.upsert_scored_job(original) is True
    assert database.upsert_scored_job(original) is False
    changed_payload = {"key": original.key, "revision": 2}
    changed = replace(
        original,
        payload=changed_payload,
        payload_hash=canonical_hash(changed_payload),
        title="Changed title",
    )
    with database.connection() as conn:
        before_job = tuple(conn.execute(
            "SELECT title,payload_json,payload_hash,state FROM pipeline_jobs WHERE job_key=?",
            (original.key,),
        ).fetchone())
        before_events = conn.execute(
            "SELECT COUNT(*) FROM pipeline_events WHERE job_key=?", (original.key,),
        ).fetchone()[0]

    with pytest.raises(IdempotencyConflict, match="changed score snapshot"):
        database.upsert_scored_job(changed)

    aliased = replace(
        original,
        payload={"key": original.key, "silently_changed": True},
        title="Aliased title",
    )
    with pytest.raises(ValueError, match="does not match canonical payload"):
        database.upsert_scored_job(aliased)

    metadata_only = replace(original, title="Changed outside the hashed payload")
    with pytest.raises(IdempotencyConflict, match="changed score snapshot"):
        database.upsert_scored_job(metadata_only)

    string_key_payload = {"1": "value"}
    key_aliases = (
        {1: "value"},
        {"nested": [{2: "value"}]},
    )
    for key_alias in key_aliases:
        ambiguous = replace(
            original,
            payload=key_alias,
            payload_hash=canonical_hash(string_key_payload),
        )
        with pytest.raises(ValueError, match="JSON object keys must be strings"):
            database.upsert_scored_job(ambiguous)

    with database.connection() as conn:
        after_job = tuple(conn.execute(
            "SELECT title,payload_json,payload_hash,state FROM pipeline_jobs WHERE job_key=?",
            (original.key,),
        ).fetchone())
        after_events = conn.execute(
            "SELECT COUNT(*) FROM pipeline_events WHERE job_key=?", (original.key,),
        ).fetchone()[0]
    assert after_job == before_job
    assert after_events == before_events == 1
    assert LifecycleReducer(path).replay() == {
        original.key: PipelineState.SCORED,
    }


def test_score_snapshot_persists_canonical_payload_and_rejects_non_finite_metadata_atomically(
    tmp_path: Path,
) -> None:
    path = tmp_path / "canonical-finite-score-snapshot.sqlite3"
    database = CareerDatabase(path)
    original = replace(
        _job("canonical-finite"),
        payload={"unicode": "Moldova → UK", "nested": {"b": 2, "a": 1}},
    )
    original = replace(original, payload_hash=canonical_hash(original.payload))
    assert database.upsert_scored_job(original) is True

    with database.connection() as conn:
        stored_payload = conn.execute(
            "SELECT payload_json FROM pipeline_jobs WHERE job_key=?", (original.key,),
        ).fetchone()[0]
        before_jobs = conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0]
        before_events = conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0]
    assert stored_payload == canonical_json(original.payload)
    assert canonical_hash(json.loads(stored_payload)) == original.payload_hash

    for field in ("fit", "opportunity", "final_score", "extraction_confidence"):
        for invalid in (float("nan"), float("inf"), float("-inf")):
            rejected = replace(_job(f"non-finite-{field}-{invalid}"), **{field: invalid})
            with pytest.raises(ValueError, match=rf"{field} must be a finite number"):
                database.upsert_scored_job(rejected)

    with database.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == before_jobs
        assert conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == before_events

    for field in ("fit", "opportunity", "final_score", "extraction_confidence"):
        integer = replace(_job(f"integer-{field}"), **{field: 1})
        assert database.upsert_scored_job(integer) is True
        assert database.upsert_scored_job(integer) is False
        with database.connection() as conn:
            stable = (
                conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0],
            )
        with pytest.raises(IdempotencyConflict, match="score snapshot|immutable import event"):
            database.upsert_scored_job(replace(integer, **{field: 1.0}))
        with database.connection() as conn:
            assert (
                conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0],
            ) == stable

        # SQLite REAL erases the distinction between 1 and 1.0.  Rewriting the
        # mutable root event and recomputing both of its public digests must
        # still fail because the separately persisted receipt retains the
        # original typed binding bytes.
        with sqlite3.connect(path) as conn:
            original_event = conn.execute(
                "SELECT id,payload_json,idempotency_key FROM pipeline_events WHERE job_key=?",
                (integer.key,),
            ).fetchone()
            forged_binding = json.loads(original_event[1])
            forged_binding["snapshot"][field] = {
                "type": "float", "value": float(1).hex(),
            }
            forged_binding["snapshot_hash"] = canonical_hash(forged_binding["snapshot"])
            forged_payload = canonical_json(forged_binding)
            forged_key = (
                f"score-import-v2:{integer.key}:{canonical_hash(forged_binding)}"
            )
            conn.execute(
                "UPDATE pipeline_events SET payload_json=?,idempotency_key=? WHERE id=?",
                (forged_payload, forged_key, original_event[0]),
            )
        with pytest.raises(LedgerDivergence, match="exact deterministic historical event"):
            LifecycleReducer(path).replay()
        with sqlite3.connect(path) as conn:
            conn.execute(
                "UPDATE pipeline_events SET payload_json=?,idempotency_key=? WHERE id=?",
                (original_event[1], original_event[2], original_event[0]),
            )

        negative_zero = replace(_job(f"negative-zero-{field}"), **{field: -0.0})
        with pytest.raises(ValueError, match="must not use negative zero"):
            database.upsert_scored_job(negative_zero)
        canonical_zero = replace(_job(f"canonical-zero-{field}"), **{field: 0.0})
        assert database.upsert_scored_job(canonical_zero) is True
        assert database.upsert_scored_job(canonical_zero) is False
        with pytest.raises(ValueError, match="must not use negative zero"):
            database.upsert_scored_job(replace(canonical_zero, **{field: -0.0}))

        # The same independent receipt prevents a signed-zero alias even after
        # an attacker recomputes every identity stored in the root event.
        with sqlite3.connect(path) as conn:
            original_event = conn.execute(
                "SELECT id,payload_json,idempotency_key FROM pipeline_events WHERE job_key=?",
                (canonical_zero.key,),
            ).fetchone()
            forged_binding = json.loads(original_event[1])
            forged_binding["snapshot"][field] = {
                "type": "float", "value": (-0.0).hex(),
            }
            forged_binding["snapshot_hash"] = canonical_hash(forged_binding["snapshot"])
            forged_payload = canonical_json(forged_binding)
            forged_key = (
                f"score-import-v2:{canonical_zero.key}:{canonical_hash(forged_binding)}"
            )
            conn.execute(
                "UPDATE pipeline_events SET payload_json=?,idempotency_key=? WHERE id=?",
                (forged_payload, forged_key, original_event[0]),
            )
        with pytest.raises(LedgerDivergence, match="exact deterministic historical event"):
            LifecycleReducer(path).replay()
        with sqlite3.connect(path) as conn:
            conn.execute(
                "UPDATE pipeline_events SET payload_json=?,idempotency_key=? WHERE id=?",
                (original_event[1], original_event[2], original_event[0]),
            )

    assert set(LifecycleReducer(path).replay()) == {
        "canonical-finite",
        *(f"integer-{field}" for field in (
            "fit", "opportunity", "final_score", "extraction_confidence"
        )),
        *(f"canonical-zero-{field}" for field in (
            "fit", "opportunity", "final_score", "extraction_confidence"
        )),
    }

    with database.connection() as conn:
        event = conn.execute(
            """SELECT id,job_key,payload_json,idempotency_key
               FROM pipeline_events WHERE job_key='integer-fit'"""
        ).fetchone()
        receipt = conn.execute(
            """SELECT binding_json,binding_hash,idempotency_key
               FROM score_snapshot_receipts WHERE job_key='integer-fit'"""
        ).fetchone()
    assert event is not None and receipt is not None
    assert (receipt["binding_json"], receipt["idempotency_key"]) == (
        event["payload_json"], event["idempotency_key"],
    )
    assert receipt["binding_hash"] == canonical_hash(json.loads(event["payload_json"]))

    altered_binding = json.loads(event["payload_json"])
    altered_binding["snapshot"]["fit"] = {
        "type": "float", "value": float(1).hex(),
    }
    altered_binding["snapshot_hash"] = canonical_hash(altered_binding["snapshot"])
    altered_payload = canonical_json(altered_binding)
    altered_key = (
        f"score-import-v2:{event['job_key']}:{canonical_hash(altered_binding)}"
    )
    with database.transaction(immediate=True) as conn:
        conn.execute(
            "UPDATE pipeline_events SET payload_json=?,idempotency_key=? WHERE id=?",
            (altered_payload, altered_key, event["id"]),
        )
    with pytest.raises(LedgerDivergence, match="exact deterministic historical event"):
        LifecycleReducer(path).replay()
    with database.transaction(immediate=True) as conn:
        conn.execute(
            "UPDATE pipeline_events SET payload_json=?,idempotency_key=? WHERE id=?",
            (event["payload_json"], event["idempotency_key"], event["id"]),
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        with database.transaction(immediate=True) as conn:
            conn.execute(
                "UPDATE score_snapshot_receipts SET binding_hash=? WHERE job_key=?",
                ("0" * 64, "integer-fit"),
            )


def test_replay_reconstructs_states_and_detects_divergence_order_and_receipt_identity_tampering(tmp_path: Path) -> None:
    path = tmp_path / "replay.sqlite3"
    database = CareerDatabase(path)
    database.upsert_scored_job(_job("replay"))
    reducer = LifecycleReducer(path)
    first = reducer.commit(
        job_key="replay", to_state=PipelineState.EMPLOYER_RESEARCH_QUEUED,
        policy=POLICY, inputs={"n": 1}, outputs={}, idempotency_key="replay:1",
        model=ModelIdentity("provider", "model", "1"),
    )
    reducer.commit(job_key="replay", to_state=PipelineState.EMPLOYER_RESEARCHING, policy=POLICY, inputs={"n": 2}, outputs={}, idempotency_key="replay:2")
    assert reducer.replay() == {"replay": PipelineState.EMPLOYER_RESEARCHING}

    with sqlite3.connect(path) as conn:
        stored_job_payload = conn.execute(
            "SELECT payload_json FROM pipeline_jobs WHERE job_key='replay'"
        ).fetchone()[0]
        conn.execute(
            "UPDATE pipeline_jobs SET payload_json=? WHERE job_key='replay'",
            (canonical_json({"key": "tampered"}),),
        )
    with pytest.raises(LedgerDivergence, match="payload content diverges"):
        reducer.verify()
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE pipeline_jobs SET payload_json=? WHERE job_key='replay'",
            (stored_job_payload,),
        )
        original_binding = conn.execute(
            "SELECT payload_json FROM pipeline_events WHERE id=?", (first.event_id,),
        ).fetchone()[0]

    for addition in ("top", "policy", "model"):
        changed_binding = json.loads(original_binding)
        if addition == "top":
            changed_binding["extra"] = True
        else:
            changed_binding[addition]["extra"] = True
        with sqlite3.connect(path) as conn:
            conn.execute(
                "UPDATE pipeline_events SET payload_json=? WHERE id=?",
                (canonical_json(changed_binding), first.event_id),
            )
        with pytest.raises(LedgerDivergence, match="malformed binding data"):
            reducer.verify()
        with sqlite3.connect(path) as conn:
            conn.execute(
                "UPDATE pipeline_events SET payload_json=? WHERE id=?",
                (original_binding, first.event_id),
            )

    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE pipeline_jobs SET state='employer_researched' WHERE job_key='replay'")
    with pytest.raises(LedgerDivergence, match="materialised state diverges"):
        reducer.verify()
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE pipeline_jobs SET state='employer_researching' WHERE job_key='replay'")
        conn.execute("UPDATE pipeline_jobs SET policy_hash=? WHERE job_key='replay'", ("0" * 64,))
    with pytest.raises(LedgerDivergence, match="materialised policy identity diverges"):
        reducer.verify()
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE pipeline_jobs SET policy_hash=? WHERE job_key='replay'", (POLICY.sha256,))
        conn.execute("UPDATE pipeline_events SET idempotency_key='tampered-event-key' WHERE id=?", (first.event_id,))
    with pytest.raises(LedgerDivergence, match="tampered receipt identity"):
        reducer.verify()

    impossible = tmp_path / "impossible.sqlite3"
    other_database = CareerDatabase(impossible)
    other_database.upsert_scored_job(_job("impossible"))
    with other_database.transaction(immediate=True) as conn:
        conn.execute("UPDATE pipeline_jobs SET state='employer_researched' WHERE job_key='impossible'")
        conn.execute(
            """INSERT INTO pipeline_events(job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key)
               VALUES(?,?,?,?,?,?,?)""",
            ("impossible", "opportunity_gate_decided", PipelineState.SCORED.value,
             PipelineState.EMPLOYER_RESEARCHED.value, ActorKind.DETERMINISTIC.value,
             "{}", "impossible-order"),
        )
    with pytest.raises(LedgerDivergence, match="out of order or illegal"):
        LifecycleReducer(impossible).replay()


def test_receiptless_legacy_replay_accepts_only_exact_historical_deterministic_shapes(
    tmp_path: Path,
) -> None:
    authentic = tmp_path / "authentic-legacy.sqlite3"
    authentic_database = CareerDatabase(authentic)
    authentic_job = _job("authentic-legacy")
    authentic_database.upsert_scored_job(authentic_job)
    gate_payload = {
        "decision": "pass",
        "reason": "opportunity_warrants_employer_reconnaissance",
    }
    gate_key = (
        f"opportunity-gate:{authentic_job.key}:{authentic_job.payload_hash}:"
        "b38a8ff32e7d74ce"
    )
    with authentic_database.transaction(immediate=True) as conn:
        conn.execute(
            """INSERT INTO pipeline_events(
                 job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
               ) VALUES(?,?,?,?,?,?,?)""",
            (authentic_job.key, "opportunity_gate_decided", "scored",
             "employer_research_queued", "deterministic",
             json.dumps(gate_payload, sort_keys=True), gate_key),
        )
        conn.execute(
            """UPDATE pipeline_jobs
               SET state='employer_research_queued',policy_hash='b38a8ff32e7d74ce'
               WHERE job_key=?""",
            (authentic_job.key,),
        )
    assert LifecycleReducer(authentic).replay() == {
        authentic_job.key: PipelineState.EMPLOYER_RESEARCH_QUEUED,
    }
    with authentic_database.transaction(immediate=True) as conn:
        event_id = conn.execute(
            "SELECT id FROM pipeline_events WHERE idempotency_key=?", (gate_key,),
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO lifecycle_transition_receipts(
                 event_id,job_key,from_state,to_state,policy_id,policy_version,policy_hash,
                 input_hash,output_hash,idempotency_key
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (event_id, authentic_job.key, "scored", "employer_research_queued",
             "forged-legacy-receipt", "1", "1" * 64, "2" * 64, "3" * 64,
             gate_key),
        )
    with pytest.raises(LedgerDivergence, match="unowned transition receipt"):
        LifecycleReducer(authentic).replay()

    for attack in ("actor", "payload", "idempotency"):
        path = tmp_path / f"forged-legacy-{attack}.sqlite3"
        database = CareerDatabase(path)
        job = _job(f"forged-legacy-{attack}")
        database.upsert_scored_job(job)
        payload = dict(gate_payload)
        actor = "deterministic"
        idempotency_key = f"opportunity-gate:{job.key}:{job.payload_hash}:b38a8ff32e7d74ce"
        if attack == "actor":
            actor = "external"
        elif attack == "payload":
            payload["reason"] = "forged"
        else:
            idempotency_key += ":forged"
        with database.transaction(immediate=True) as conn:
            conn.execute(
                """INSERT INTO pipeline_events(
                     job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
                   ) VALUES(?,?,?,?,?,?,?)""",
                (job.key, "opportunity_gate_decided", "scored",
                 "employer_research_queued", actor,
                 json.dumps(payload, sort_keys=True), idempotency_key),
            )
            conn.execute(
                "UPDATE pipeline_jobs SET state='employer_research_queued' WHERE job_key=?",
                (job.key,),
            )
        with pytest.raises(LedgerDivergence, match="exact deterministic historical event"):
            LifecycleReducer(path).replay()

    root_actor = tmp_path / "forged-legacy-root-actor.sqlite3"
    root_database = CareerDatabase(root_actor)
    root_database.upsert_scored_job(_job("forged-legacy-root-actor"))
    with root_database.transaction(immediate=True) as conn:
        conn.execute("UPDATE pipeline_events SET actor_kind='probabilistic'")
    with pytest.raises(LedgerDivergence, match="exact deterministic historical event"):
        LifecycleReducer(root_actor).replay()

    post_boundary = tmp_path / "post-boundary-v1.sqlite3"
    post_boundary_database = CareerDatabase(post_boundary)
    post_payload = {"key": "post-boundary-v1"}
    post_hash = canonical_hash(post_payload)
    post_binding = json.dumps({"payload_hash": post_hash}, sort_keys=True)
    post_key = f"score-import:post-boundary-v1:{post_hash}"
    with post_boundary_database.transaction(immediate=True) as conn:
        conn.execute(
            """INSERT INTO pipeline_jobs(
                 job_key,board,job_id,url,title,company,opportunity,payload_json,
                 payload_hash,state
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            ("post-boundary-v1", "forged", "1", "https://example.test/forged",
             "Forged", "Example", 0.5, canonical_json(post_payload), post_hash,
             PipelineState.SCORED.value),
        )
        event_id = conn.execute(
            """INSERT INTO pipeline_events(
                 job_key,event_type,from_state,to_state,actor_kind,payload_json,
                 idempotency_key
               ) VALUES(?,?,?,?,?,?,?)""",
            ("post-boundary-v1", "score_snapshot_imported", None,
             PipelineState.SCORED.value, ActorKind.DETERMINISTIC.value,
             post_binding, post_key),
        ).lastrowid
    with pytest.raises(LedgerDivergence, match="outside the frozen cohort"):
        LifecycleReducer(post_boundary).replay()
    with pytest.raises(sqlite3.IntegrityError, match="cohort is immutable"):
        with post_boundary_database.transaction(immediate=True) as conn:
            conn.execute(
                """INSERT INTO legacy_score_snapshot_cohort(
                     event_id,job_key,payload_hash,binding_json,idempotency_key
                   ) VALUES(?,?,?,?,?)""",
                (event_id, "post-boundary-v1", post_hash, post_binding, post_key),
            )

    retired = tmp_path / "retired-legacy-name.sqlite3"
    retired_database = CareerDatabase(retired)
    retired_job = _job("retired-legacy-name")
    retired_database.upsert_scored_job(retired_job)
    retired_reducer = LifecycleReducer(retired)
    retired_reducer.commit(
        job_key=retired_job.key,
        to_state=PipelineState.EMPLOYER_RESEARCH_QUEUED,
        policy=POLICY, inputs={}, outputs={}, idempotency_key="retired:queue",
    )
    retired_reducer.commit(
        job_key=retired_job.key,
        to_state=PipelineState.EMPLOYER_RESEARCHING,
        policy=POLICY, inputs={}, outputs={}, idempotency_key="retired:researching",
    )
    with retired_database.transaction(immediate=True) as conn:
        conn.execute(
            """INSERT INTO pipeline_events(
                 job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
               ) VALUES(?,?,?,?,?,?,?)""",
            (retired_job.key, "employer_research_completed", "employer_researching",
             "employer_researched", "deterministic", "{}", "retired:completed"),
        )
        conn.execute(
            "UPDATE pipeline_jobs SET state='employer_researched' WHERE job_key=?",
            (retired_job.key,),
        )
    with pytest.raises(LedgerDivergence, match="without reducer authority"):
        retired_reducer.replay()
