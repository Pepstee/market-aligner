"""Independent, real-worker retest of Opportunity-1 lifecycle provenance."""

from __future__ import annotations

import sqlite3
import hashlib
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
from career_automation.employer_research import FRESHNESS_DAYS, IntelligenceKind
from career_automation.engine import OpportunityGate, scored_job_from_payload
from career_automation.lifecycle import LedgerDivergence


class CapturedRetriever:
    """A deterministic public response, persisted through the production cache."""

    def __init__(self, cache: RawResponseCache) -> None:
        self.cache = cache

    def retrieve(self, source_id: str, url: str) -> Citation:
        body = (
            b"<p>Example Engineer job vacancy: Example documents its public service, "
            b"products, delivery work, customers, hiring plans, and operational constraints.</p>"
        )
        digest, reference = self.cache.store(body)
        captured_at = date.today().isoformat() + "T00:00:00+00:00"
        return Citation(source_id, "https://8.8.8.8/public", captured_at, captured_at,
                        digest, reference, 200)

    def retrieve_plan(self, task: object) -> tuple[list[Citation], list[dict[str, object]]]:
        """Supply one byte-bound product outcome and four explicit abstentions."""
        body = (
            b"<p>Example product service platform provides documented public value to customers "
            b"and clients through reliable engineering technology.</p>"
        )
        digest, reference = self.cache.store(body)
        captured_at = date.today().isoformat() + "T00:00:00+00:00"
        source = Citation(
            f"source:{getattr(task, 'job_key')}:product", "https://8.8.8.8/product",
            captured_at, captured_at, digest, reference, 200, source_kind="official_product",
            canonical_publisher="8.8.8.8", canonical_article="https://8.8.8.8/product",
            retrieval_engine="deterministic-retriever",
        )
        excerpt = body.decode("utf-8")
        plan: list[dict[str, object]] = []
        for kind in IntelligenceKind:
            base: dict[str, object] = {
                "id": f"plan:{kind.value}", "kind": kind.value,
                "permitted_purposes": [kind.value], "freshness_days": FRESHNESS_DAYS[kind],
            }
            if kind is IntelligenceKind.PRODUCT:
                plan.append({**base, "outcome": "supported", "source_id": source.id,
                             "source_type": "official_product", "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
                             "excerpt_byte_start": 0, "excerpt_byte_length": len(body)})
            else:
                plan.append({**base, "outcome": "unknown",
                             "reason": "No purpose-specific official authority excerpt was captured."})
        return [source], plan


def _database(tmp_path: Path, opportunities: dict[str, float]) -> tuple[CareerDatabase, dict[str, str], RawResponseCache]:
    database = CareerDatabase(tmp_path / "career.sqlite3")
    jobs = []
    keys: dict[str, str] = {}
    for job_id, opportunity in opportunities.items():
        job = scored_job_from_payload({
            "board": "independent-opportunity1-retest", "job_id": job_id,
            "url": f"https://jobs.example.test/{job_id}", "job_title": "Engineer",
            "company": "Example", "fit": 0.8, "opportunity": opportunity,
            "final": 80.0, "extraction_confidence": 0.99,
        })
        jobs.append(job)
        keys[job_id] = job.key
    assert OpportunityGate(database).bootstrap(jobs).queued == len(jobs)
    return database, keys, RawResponseCache(tmp_path / "raw")


def _coordinator(database: CareerDatabase, cache: RawResponseCache, worker_id: str = "worker", *, reject: bool = False) -> Opportunity1Coordinator:
    def signals(dossier: dict[str, object]) -> list[dict[str, object]]:
        if not reject:
            return []
        claim = next(
            claim for claim in dossier["claims"]
            if isinstance(claim, dict) and claim.get("outcome", "supported") == "supported"
        )
        return [{"claim_id": claim["id"], "reason": "documented public service", "delta_bp": -3000}]

    return Opportunity1Coordinator(
        database, EmployerResearchWorker(database, worker_id, cache, retriever=CapturedRetriever(cache)),
        signal_deriver=signals,
    )


def _advance(tmp_path: Path, *, opportunity: float = 0.9, reject: bool = False) -> tuple[CareerDatabase, str, RawResponseCache]:
    database, keys, cache = _database(tmp_path, {"job": opportunity})
    outcome = _coordinator(database, cache, reject=reject).run_once()
    assert outcome is not None
    return database, keys["job"], cache


def _receipt_id(database: CareerDatabase, job_key: str, policy_id: str) -> int:
    with database.connection() as conn:
        row = conn.execute(
            "SELECT receipt_id FROM lifecycle_transition_receipts WHERE job_key=? AND policy_id=?",
            (job_key, policy_id),
        ).fetchone()
    assert row is not None
    return int(row["receipt_id"])


def _offline_receipt_tamper(database: CareerDatabase, receipt_id: int, column: str, value: str) -> None:
    # The database normally rejects writes.  Removing that guard models an
    # offline SQLite edit, so the read/verifier must still fail closed.
    with database.connection() as conn:
        conn.execute("DROP TRIGGER lifecycle_transition_receipt_immutable_update")
        conn.execute(f"UPDATE lifecycle_transition_receipts SET {column}=? WHERE receipt_id=?", (value, receipt_id))


def test_real_coordinator_routes_one_pass_and_one_reject_without_replacement(tmp_path: Path) -> None:
    passed_db, passed_key, _ = _advance(tmp_path / "pass")
    rejected_db, rejected_key, _ = _advance(tmp_path / "reject", opportunity=0.6, reject=True)
    with passed_db.connection() as conn:
        assert conn.execute("SELECT state FROM pipeline_jobs WHERE job_key=?", (passed_key,)).fetchone()[0] == "fit_assessed"
    with rejected_db.connection() as conn:
        assert conn.execute("SELECT state FROM pipeline_jobs WHERE job_key=?", (rejected_key,)).fetchone()[0] == "opportunity_rejected_after_research"


def test_completed_research_is_exact_state_only_but_post_research_dossier_survives_both_routes(tmp_path: Path) -> None:
    exact_database, exact_keys, exact_cache = _database(tmp_path / "exact", {"exact": 0.9})
    assert EmployerResearchWorker(exact_database, "exact-worker", exact_cache,
                                  retriever=CapturedRetriever(exact_cache)).run_once() == exact_keys["exact"]
    exact_dossier, exact_digest = exact_database.completed_research(exact_keys["exact"]) or (None, None)
    assert exact_dossier is not None and exact_dossier["job_key"] == exact_keys["exact"]
    assert exact_database.post_research_dossier(exact_keys["exact"]) == (exact_dossier, exact_digest)
    for label, opportunity, reject in (("pass", 0.9, False), ("reject", 0.6, True)):
        database, job_key, _ = _advance(tmp_path / label, opportunity=opportunity, reject=reject)
        assert database.completed_research(job_key) is None
        dossier, digest = database.post_research_dossier(job_key) or (None, None)
        assert dossier is not None and dossier["job_key"] == job_key and isinstance(digest, str)


def test_four_completed_jobs_and_one_expired_lease_resume_once_with_all_receipts(tmp_path: Path) -> None:
    database, keys, cache = _database(tmp_path, {f"job-{number}": 0.9 for number in range(5)})
    coordinator = _coordinator(database, cache)
    assert [coordinator.run_once() is not None for _ in range(4)] == [True] * 4
    stale = database.claim_research("stale-worker", lease_seconds=60)
    assert stale is not None
    with database.connection() as conn:
        conn.execute("UPDATE employer_research_queue SET lease_until='2000-01-01T00:00:00+00:00' WHERE job_key=?", (stale.job_key,))
    resumed = _coordinator(database, cache, "resuming-worker").run_once()
    assert resumed is not None and resumed["job_key"] == stale.job_key
    assert _coordinator(database, cache).run_once() is None
    with database.connection() as conn:
        for job_key in keys.values():
            assert conn.execute("SELECT status,attempts FROM employer_research_queue WHERE job_key=?", (job_key,)).fetchone()[:] in (("completed", 1), ("completed", 2))
            assert conn.execute("SELECT COUNT(*) FROM employer_dossiers WHERE job_key=?", (job_key,)).fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM opportunity_reassessments WHERE job_key=?", (job_key,)).fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM lifecycle_transition_receipts WHERE job_key=? AND policy_id=?", (job_key, "career.research-completion-validation")).fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM lifecycle_transition_receipts WHERE job_key=? AND policy_id=?", (job_key, "career.opportunity-1")).fetchone()[0] == 1


def test_each_research_receipt_identity_input_output_and_policy_tamper_fails_closed(tmp_path: Path) -> None:
    for column, value in (("idempotency_key", "offline-research-identity"), ("input_hash", "0" * 64), ("output_hash", "0" * 64), ("policy_hash", "0" * 64)):
        database, job_key, _ = _advance(tmp_path / column)
        _offline_receipt_tamper(database, _receipt_id(database, job_key, "career.research-completion-validation"), column, value)
        with pytest.raises(LedgerDivergence):
            database.lifecycle.verify()


def test_each_opportunity1_receipt_identity_input_output_and_policy_tamper_fails_closed(tmp_path: Path) -> None:
    for column, value in (("idempotency_key", "offline-opportunity1-identity"), ("input_hash", "0" * 64), ("output_hash", "0" * 64), ("policy_hash", "0" * 64)):
        database, job_key, _ = _advance(tmp_path / column)
        _offline_receipt_tamper(database, _receipt_id(database, job_key, "career.opportunity-1"), column, value)
        with pytest.raises(LedgerDivergence):
            database.lifecycle.verify()


def test_queue_lifecycle_dossier_and_reassessment_tampering_is_rejected_by_durable_reads(tmp_path: Path) -> None:
    for target in ("queue", "lifecycle", "dossier", "reassessment"):
        database, job_key, _ = _advance(tmp_path / target)
        with database.connection() as conn:
            if target == "queue":
                conn.execute("UPDATE employer_research_queue SET status='queued' WHERE job_key=?", (job_key,))
            elif target == "lifecycle":
                conn.execute("UPDATE pipeline_jobs SET state='employer_researched' WHERE job_key=?", (job_key,))
            elif target == "dossier":
                conn.execute("UPDATE employer_dossiers SET dossier_hash=? WHERE job_key=?", ("0" * 64, job_key))
            else:
                conn.execute("UPDATE opportunity_reassessments SET decision='reject' WHERE job_key=?", (job_key,))
        with pytest.raises(RuntimeError):
            database.opportunity1_reassessment(job_key)


def test_reassessment_read_is_bound_to_the_original_dossier_hash(tmp_path: Path) -> None:
    database, job_key, _ = _advance(tmp_path / "binding")
    dossier, digest = database.post_research_dossier(job_key) or (None, None)
    assert dossier is not None and digest is not None
    assert database.opportunity1_reassessment(job_key, expected_dossier_hash=digest) is not None
    with pytest.raises(RuntimeError, match="different dossier"):
        database.opportunity1_reassessment(job_key, expected_dossier_hash="0" * 64)
