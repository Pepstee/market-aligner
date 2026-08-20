"""Adversarial JAA-04 recertification tests, independent of acceptance helpers."""

from __future__ import annotations

import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from career_automation.database import CareerDatabase
from career_automation.employer_research import (
    Citation,
    EmployerResearchWorker,
    Opportunity1Coordinator,
    RawResponseCache,
)
from career_automation.engine import OpportunityGate, scored_job_from_payload


ROOT = Path(__file__).resolve().parent


def _job(job_id: str):
    return scored_job_from_payload({
        "board": "jaa04-recertification", "job_id": job_id,
        "url": f"https://jobs.example.test/{job_id}", "job_title": "Engineer",
        "company": "Example", "fit": .8, "opportunity": .9,
        "final": 80.0, "extraction_confidence": .99,
    })


def _database(tmp_path: Path, job_id: str = "coordinator") -> tuple[CareerDatabase, str, RawResponseCache]:
    database = CareerDatabase(tmp_path / "career.sqlite3")
    job = _job(job_id)
    OpportunityGate(database).bootstrap([job])
    return database, job.key, RawResponseCache(tmp_path / "raw")


class _CapturedRetriever:
    def __init__(self, cache: RawResponseCache) -> None:
        self.cache = cache

    def retrieve(self, source_id: str, url: str) -> Citation:
        body = (
            b"<p>Example operates a documented public business serving customers.</p>"
            b"<p>The Engineer role has documented responsibilities and duties.</p>"
            b"<p>The product platform provides a service for customers.</p>"
            b"<p>The careers vacancy invites candidates to apply through hiring.</p>"
            b"<p>In 2026 Example reported operational revenue and profit performance.</p>"
        )
        digest, reference = self.cache.store(body)
        timestamp = date.today().isoformat() + "T00:00:00+00:00"
        return Citation(source_id, "https://8.8.8.8/public", timestamp, timestamp,
                        digest, reference, 200)


def test_coordinator_advances_only_after_real_worker_completion_and_never_after_failure(tmp_path: Path) -> None:
    database, job_key, cache = _database(tmp_path / "success")
    worker = EmployerResearchWorker(database, "researcher", cache, retriever=_CapturedRetriever(cache))
    coordinator = Opportunity1Coordinator(database, worker)
    outcome = coordinator.run_once()
    assert outcome is not None
    with database.connection() as conn:
        event_types = [row[0] for row in conn.execute(
            "SELECT event_type FROM pipeline_events WHERE job_key=? ORDER BY id", (job_key,)
        )]
        assert conn.execute("SELECT status FROM employer_research_queue WHERE job_key=?", (job_key,)).fetchone()[0] == "completed"
        assert conn.execute("SELECT COUNT(*) FROM employer_dossiers WHERE job_key=?", (job_key,)).fetchone()[0] == 1
    # The two Opportunity-1 lifecycle commits are subsequent to the real
    # research-completion commit; this is durable ordering, not mock call order.
    completion = [index for index, event in enumerate(event_types) if event == "lifecycle_transition_committed"][-3]
    assert event_types[completion:completion + 3] == [
        "lifecycle_transition_committed", "lifecycle_transition_committed", "lifecycle_transition_committed",
    ]

    failed_db, failed_key, failed_cache = _database(tmp_path / "failure", "failure")

    class FailingRetriever:
        def retrieve(self, source_id: str, url: str) -> Citation:
            raise RuntimeError("network failed")

    failed = Opportunity1Coordinator(
        failed_db, EmployerResearchWorker(failed_db, "failed", failed_cache, retriever=FailingRetriever())
    )
    with pytest.raises(RuntimeError, match="network failed"):
        failed.run_once()
    with failed_db.connection() as conn:
        assert conn.execute("SELECT status FROM employer_research_queue WHERE job_key=?", (failed_key,)).fetchone()[0] == "leased"
        assert conn.execute("SELECT COUNT(*) FROM opportunity_reassessments WHERE job_key=?", (failed_key,)).fetchone()[0] == 0

    incomplete_db, incomplete_key, incomplete_cache = _database(tmp_path / "incomplete", "incomplete")

    class IncompleteWorker:
        database = incomplete_db

        def run_once(self) -> str:
            return incomplete_key

    with pytest.raises(RuntimeError, match="did not durably complete"):
        Opportunity1Coordinator(incomplete_db, IncompleteWorker()).run_once()  # type: ignore[arg-type]
    with incomplete_db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM opportunity_reassessments WHERE job_key=?", (incomplete_key,)).fetchone()[0] == 0
    with pytest.raises(RuntimeError, match="completed employer research|incomplete"):
        incomplete_db.apply_opportunity1(job_key=incomplete_key, signals=[])


def test_missing_external_authority_cannot_emit_a_jaa04_receipt(tmp_path: Path) -> None:
    clone = tmp_path / "clone"
    copied = subprocess.run(("git", "clone", "--no-local", str(ROOT), str(clone)), text=True,
                            capture_output=True, check=False)
    assert copied.returncode == 0, copied.stderr
    receipt = tmp_path / "receipt"
    completed = subprocess.run(
        (sys.executable, "scripts/accept_jaa_04.py", "--receipt", str(receipt)),
        cwd=clone,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode != 0
    assert "--capture" in completed.stderr and "--access-policy" in completed.stderr
    assert not receipt.exists()
