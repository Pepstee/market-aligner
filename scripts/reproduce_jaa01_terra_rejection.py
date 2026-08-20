#!/usr/bin/env python3
"""Reproduce the JAA-01 Terra research-completion rejection scenario."""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from career_automation.database import CareerDatabase
from career_automation.engine import OpportunityGate, scored_job_from_payload
from career_automation.lifecycle import canonical_hash
from career_automation.models import PipelineState


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def reproduce() -> dict[str, Any]:
    """Run the real on-disk scenario and return path-free observations."""
    with tempfile.TemporaryDirectory(prefix="jaa01-terra-") as directory:
        path = Path(directory) / "career_pipeline.sqlite3"
        database = CareerDatabase(path)
        gate = OpportunityGate(database)
        job = scored_job_from_payload({
            "board": "terra", "job_id": "rejected-complete-research",
            "url": "https://example.invalid/terra/research",
            "job_title": "Terra Research Engineer", "company": "Terra",
            "fit": 0.82, "opportunity": 0.91, "final": 86.0,
            "extraction_confidence": 0.97,
        })
        require(gate.import_jobs([job]) == 1, "Terra job import failed")
        require(gate.apply() == (1, 0), "Terra opportunity gate did not pass")
        task = database.claim_research("terra-dossier-worker", lease_seconds=300)
        require(task is not None and task.job_key == job.key, "Terra lease failed")

        dossier = {
            "job_key": job.key,
            "model": {"provider": "terra", "model_id": "dossier-worker", "version": "1"},
            "sources": [{"id": "terra-public-1", "url": "https://example.invalid/terra"}],
            "claims": [{
                "text": "Terra publishes employer information.",
                "source_ids": ["terra-public-1"], "confidence": 0.83,
            }],
        }
        dossier_hash = canonical_hash(dossier)
        try:
            database.complete_research(
                job_key=job.key, worker_id="not-the-lease-owner",
                dossier=dossier, dossier_hash=dossier_hash,
            )
        except RuntimeError as exc:
            require("not leased" in str(exc), "unexpected rejected-completion reason")
        else:
            raise AssertionError("non-owner complete_research was accepted")

        with database.connection() as conn:
            rejected_counts = {
                "events": int(conn.execute(
                    "SELECT COUNT(*) FROM pipeline_events WHERE job_key=?", (job.key,)
                ).fetchone()[0]),
                "receipts": int(conn.execute(
                    "SELECT COUNT(*) FROM lifecycle_transition_receipts WHERE job_key=?", (job.key,)
                ).fetchone()[0]),
                "dossiers": int(conn.execute(
                    "SELECT COUNT(*) FROM employer_dossiers WHERE job_key=?", (job.key,)
                ).fetchone()[0]),
            }
        require(rejected_counts == {"events": 3, "receipts": 2, "dossiers": 0},
                "rejected complete_research mutated the ledger")

        database.complete_research(
            job_key=job.key, worker_id="terra-dossier-worker",
            dossier=dossier, dossier_hash=dossier_hash,
        )
        first_replay = database.lifecycle.replay()
        database.lifecycle.verify()
        with database.connection() as conn:
            state = conn.execute(
                "SELECT state FROM pipeline_jobs WHERE job_key=?", (job.key,)
            ).fetchone()[0]
            events = conn.execute(
                "SELECT * FROM pipeline_events WHERE job_key=? ORDER BY id", (job.key,)
            ).fetchall()
            receipts = conn.execute(
                "SELECT * FROM lifecycle_transition_receipts WHERE job_key=? ORDER BY event_id",
                (job.key,),
            ).fetchall()
        proposal = [row for row in events if row["event_type"] == "lifecycle_transition_proposed"]
        completion = [row for row in events if row["idempotency_key"].startswith("research-complete:")]
        completion_receipts = [
            row for row in receipts
            if row["idempotency_key"].startswith("research-complete:")
        ]
        require(len(proposal) == 1, "expected exactly one probabilistic proposal")
        require(proposal[0]["actor_kind"] == "probabilistic" and proposal[0]["to_state"] is None,
                "dossier proposal mutated lifecycle state")
        require(json.loads(proposal[0]["payload_json"])["proposed_state"] ==
                PipelineState.EMPLOYER_RESEARCHED.value, "proposal target was not recorded")
        require(len(completion) == len(completion_receipts) == 1,
                "completion did not have exactly one bound receipt")
        require(completion[0]["actor_kind"] == "deterministic",
                "completion was not committed by deterministic policy")
        require(completion[0]["from_state"] == PipelineState.EMPLOYER_RESEARCHING.value and
                completion[0]["to_state"] == PipelineState.EMPLOYER_RESEARCHED.value,
                "completion transition states were wrong")
        require(completion_receipts[0]["event_id"] == completion[0]["id"],
                "completion receipt was not bound to its event")
        require(state == first_replay[job.key].value == PipelineState.EMPLOYER_RESEARCHED.value,
                "replay did not equal materialised state")

        stable = ([tuple(row) for row in events], [tuple(row) for row in receipts])
        database.complete_research(
            job_key=job.key, worker_id="terra-dossier-worker",
            dossier=dossier, dossier_hash=dossier_hash,
        )
        with database.connection() as conn:
            retried = (
                [tuple(row) for row in conn.execute(
                    "SELECT * FROM pipeline_events WHERE job_key=? ORDER BY id", (job.key,)
                )],
                [tuple(row) for row in conn.execute(
                    "SELECT * FROM lifecycle_transition_receipts WHERE job_key=? ORDER BY event_id",
                    (job.key,),
                )],
            )
        require(retried == stable, "identical retry changed events or receipts")
        require(database.lifecycle.replay() == first_replay, "retry changed replay result")

        return {
            "scenario": "jaa01-terra-rejected-complete-research",
            "database": "real-temporary-sqlite-file",
            "rejected_attempt": rejected_counts,
            "final_state": state,
            "events": len(events),
            "receipts": len(receipts),
            "proposal_events": len(proposal),
            "completion_events": len(completion),
            "completion_receipts": len(completion_receipts),
            "replay_equal": True,
            "identical_retry_unchanged": True,
            "completion_receipt_binding": "event_id",
        }


def main() -> int:
    print(json.dumps(reproduce(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
