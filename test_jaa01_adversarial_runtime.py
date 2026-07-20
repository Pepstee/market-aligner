"""Independent process-level tests for the JAA-01 lifecycle contract.

These deliberately use the installed CLI and an on-disk SQLite ledger.  SQL is
used only to create a pre-JAA-01 fixture or to simulate an attacker changing
already-persisted data; lifecycle changes themselves go through runtime entry
points.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from career_automation.database import SCHEMA
from career_automation.lifecycle import ModelIdentity, PolicyIdentity, canonical_hash
from career_automation.migrations import JAA_02_MIGRATIONS
from career_automation.models import ActorKind, PipelineState


ROOT = Path(__file__).resolve().parent
POLICY_HASH = canonical_hash({"policy": "independent-runtime-test"})


def _cli(database: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "career_automation.cli", "--database", str(database), *arguments],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )


def _legacy_ledger(path: Path, *, jobs: int = 1, events: int = 1) -> None:
    """Create a genuine pre-migration five-state ledger, not a reducer fixture."""
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA)
        connection.executemany(
            """INSERT INTO pipeline_jobs(
                 job_key,board,job_id,url,title,company,opportunity,payload_json,payload_hash,state
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            [
                (f"legacy:{number}", "legacy", str(number), f"https://example.test/{number}",
                 "Engineer", "Example", 0.5, "{}", f"{number:064x}", "discovered")
                for number in range(jobs)
            ],
        )
        connection.executemany(
            """INSERT INTO pipeline_events(
                 job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key
               ) VALUES(?,?,?,?,?,?,?)""",
            [
                (f"legacy:{number % jobs}", "score_snapshot_imported", None, "discovered",
                 "deterministic", "{}", f"legacy-event:{number}")
                for number in range(events)
            ],
        )


def _transition(key: str, target: str, idempotency_key: str) -> tuple[str, ...]:
    return (
        "transition", "--job-key", key, "--to-state", target,
        "--policy-id", "independent", "--policy-version", "1",
        "--policy-hash", POLICY_HASH, "--inputs", '{"source":"test"}',
        "--outputs", '{"decision":"deterministic"}',
        "--idempotency-key", idempotency_key,
    )


def test_cli_migrates_462_jobs_and_924_events_without_reinterpretation_or_duplicate_apply(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.sqlite3"
    _legacy_ledger(database, jobs=462, events=924)
    with sqlite3.connect(database) as connection:
        before = connection.execute(
            "SELECT job_key,payload_hash,state FROM pipeline_jobs ORDER BY job_key"
        ).fetchall()
        before_events = connection.execute(
            "SELECT job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key "
            "FROM pipeline_events ORDER BY id"
        ).fetchall()

    first = _cli(database, "migrate")
    second = _cli(database, "migrate")  # a separate process models restart/retry.
    assert first.returncode == second.returncode == 0, (first.stderr, second.stderr)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0] == 462
        assert connection.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == 924
        assert connection.execute(
            "SELECT version,name,checksum FROM career_schema_migrations ORDER BY version"
        ).fetchall() == [
            (migration.version, migration.name, migration.checksum)
            for migration in JAA_02_MIGRATIONS
        ]
        assert connection.execute(
            "SELECT job_key,payload_hash,state FROM pipeline_jobs ORDER BY job_key"
        ).fetchall() == before
        assert connection.execute(
            "SELECT job_key,event_type,from_state,to_state,actor_kind,payload_json,idempotency_key "
            "FROM pipeline_events ORDER BY id"
        ).fetchall() == before_events


def test_cli_rejects_out_of_order_research_release_submit_and_preserves_ledger(tmp_path: Path) -> None:
    database = tmp_path / "negative.sqlite3"
    _legacy_ledger(database)
    assert _cli(database, "migrate").returncode == 0
    attempts = {
        "research": PipelineState.EMPLOYER_RESEARCHING.value,
        "release": PipelineState.RELEASED.value,
        "submit": PipelineState.SUBMITTED.value,
    }
    for name, target in attempts.items():
        result = _cli(database, *_transition("legacy:0", target, f"out-of-order-{name}"))
        assert result.returncode != 0
        assert "illegal or out-of-order transition" in result.stderr
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT state FROM pipeline_jobs").fetchone()[0] == "discovered"
        assert connection.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM lifecycle_transition_receipts").fetchone()[0] == 0


def test_model_proposal_never_advances_state_but_deterministic_cli_transition_is_durable_and_idempotent(
    tmp_path: Path,
) -> None:
    database = tmp_path / "model-boundary.sqlite3"
    _legacy_ledger(database)
    assert _cli(database, "migrate").returncode == 0

    # This public worker entry point accepts a model's requested consequential
    # state.  Its only durable effect must be an observation/proposal event.
    from career_automation.lifecycle import LifecycleReducer

    reducer = LifecycleReducer(database)
    event_id = reducer.record_proposal(
        job_key="legacy:0", proposed_state=PipelineState.SUBMITTED,
        actor=ActorKind.PROBABILISTIC, observation={"model says": "submit now"},
        idempotency_key="untrusted-model-output",
        model=ModelIdentity("test", "untrusted", "1"),
    )
    assert event_id > 0
    restarted_replay = _cli(database, "replay")
    assert restarted_replay.returncode == 0, restarted_replay.stderr
    assert json.loads(restarted_replay.stdout) == {"legacy:0": "discovered"}

    command = _transition("legacy:0", PipelineState.FETCHED.value, "deterministic-fetch")
    first, retry = _cli(database, *command), _cli(database, *command)
    assert first.returncode == retry.returncode == 0, (first.stderr, retry.stderr)
    assert json.loads(first.stdout)["receipt_id"] == json.loads(retry.stdout)["receipt_id"]
    assert json.loads(_cli(database, "replay").stdout) == {"legacy:0": "fetched"}
    assert _cli(database, "verify").returncode == 0
    with sqlite3.connect(database) as connection:
        proposal = connection.execute(
            "SELECT to_state,actor_kind FROM pipeline_events WHERE idempotency_key='untrusted-model-output'"
        ).fetchone()
        assert proposal == (None, "probabilistic")
        assert connection.execute("SELECT COUNT(*) FROM lifecycle_transition_receipts").fetchone()[0] == 1


def test_applied_migration_checksum_and_missing_runtime_prerequisites_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "tampered.sqlite3"
    _legacy_ledger(database)
    assert _cli(database, "migrate").returncode == 0
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE career_schema_migrations SET checksum=? WHERE version=1", ("0" * 64,))
    rejected = _cli(database, "verify")
    assert rejected.returncode != 0
    assert "modified after deployment" in rejected.stderr

    missing = _cli(tmp_path / "missing.sqlite3", *_transition("does-not-exist", "fetched", "missing-job"))
    assert missing.returncode != 0
    assert "does-not-exist" in missing.stderr
    partial_model = _cli(
        tmp_path / "partial-model.sqlite3", "transition", "--job-key", "none", "--to-state", "fetched",
        "--policy-id", "p", "--policy-version", "1", "--policy-hash", POLICY_HASH,
        "--inputs", "{}", "--outputs", "{}", "--idempotency-key", "partial", "--model-provider", "only",
    )
    assert partial_model.returncode != 0
    assert "model provider, id and version must be supplied together" in partial_model.stderr
