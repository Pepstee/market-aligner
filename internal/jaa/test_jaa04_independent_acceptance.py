"""Independent adversarial acceptance checks for the JAA-04 research runtime.

The assertions deliberately use only public runtime APIs and inspect durable
SQLite effects.  They do not import an acceptance runner or its helpers.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.database import CareerDatabase
from career_automation.employer_research import (
    Citation,
    EmployerResearchWorker,
    FRESHNESS_DAYS,
    RawResponseCache,
    content_hash,
    validate_dossier,
)
from career_automation.engine import OpportunityGate, scored_job_from_payload
from career_automation.models import IntelligenceKind, PipelineState


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]


def _utc_today():
    return datetime.now(timezone.utc).date()


def _job(job_id: str, opportunity: float = 0.9):
    return scored_job_from_payload({
        "board": "jaa04-independent", "job_id": job_id,
        "url": f"https://jobs.example.test/{job_id}", "job_title": "Engineer",
        "company": "Example", "fit": 0.8, "opportunity": opportunity,
        "final": 80.0, "extraction_confidence": 0.99,
    })


def _strict_dossier(cache: RawResponseCache, job_key: str) -> dict[str, object]:
    paragraphs = {
        IntelligenceKind.COMPANY: "Example operates a documented public business serving customers.",
        IntelligenceKind.ROLE: "The Engineer role has documented responsibilities and duties.",
        IntelligenceKind.PRODUCT: "The product platform provides a service for customers.",
        IntelligenceKind.HIRING: "The careers vacancy invites candidates to apply through hiring.",
        IntelligenceKind.OPERATIONAL_HEALTH: (
            "In 2026 Example reported operational revenue and profit performance."
        ),
    }
    source_types = {
        IntelligenceKind.COMPANY: "official_company",
        IntelligenceKind.ROLE: "official_vacancy",
        IntelligenceKind.PRODUCT: "official_product",
        IntelligenceKind.HIRING: "official_careers",
        IntelligenceKind.OPERATIONAL_HEALTH: "official_financial",
    }
    timestamp = f"{_utc_today().isoformat()}T00:00:00+00:00"
    sources: list[dict[str, object]] = []
    plan: list[dict[str, object]] = []
    claims: list[dict[str, object]] = []
    for index, kind in enumerate(IntelligenceKind):
        excerpt = f"<p>{paragraphs[kind]}</p>"
        digest, reference = cache.store(excerpt.encode())
        source_id = f"source-{kind.value}"
        plan_id = f"plan-{kind.value}"
        sources.append({
            "id": source_id,
            "url": f"https://8.8.8.8/{job_key}/{index}",
            "captured_at": timestamp,
            "retrieved_at": timestamp,
            "published_at": timestamp,
            "updated_at": None,
            "content_sha256": digest,
            "raw_response_ref": reference,
            "status_code": 200,
        })
        plan.append({
            "id": plan_id,
            "kind": kind.value,
            "source_id": source_id,
            "source_type": source_types[kind],
            "permitted_purposes": [kind.value],
            "freshness_days": FRESHNESS_DAYS[kind],
            "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
        })
        claims.append({
            "id": f"claim-{kind.value}",
            "kind": kind.value,
            "classification": "fact" if kind is IntelligenceKind.COMPANY else "inference",
            "text": f"Example has independently evidenced {kind.value} intelligence.",
            "observed_at": timestamp,
            "source_captured_at": timestamp,
            "freshness_classification": "current",
            "source_ids": [source_id],
            "source_plan_id": plan_id,
            "citation_excerpt": excerpt,
        })
    return {
        "schema_version": "jaa04.dossier.v1",
        "job_key": job_key,
        "raw_cache_root": str(cache.root),
        "sources": sources,
        "source_plan": plan,
        "claims": claims,
        "edges": [],
    }


def _ready_database(tmp_path: Path, job_id: str = "strong") -> tuple[CareerDatabase, str, RawResponseCache]:
    database = CareerDatabase(tmp_path / "career.sqlite3")
    job = _job(job_id)
    OpportunityGate(database).bootstrap([job])
    return database, job.key, RawResponseCache(tmp_path / "raw-cache")


def _complete(database: CareerDatabase, job_key: str, cache: RawResponseCache, worker: str) -> dict[str, object]:
    dossier = _strict_dossier(cache, job_key)
    database.complete_research(
        job_key=job_key, worker_id=worker, dossier=dossier, dossier_hash=content_hash(dossier),
    )
    return dossier


@pytest.mark.parametrize("attack", ["uncited", "hallucinated", "stale-current", "protected", "private-person"])
def test_invalid_or_unsafe_claims_fail_closed(tmp_path: Path, attack: str) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    dossier = _strict_dossier(cache, "negative")
    claim = dossier["claims"][0]
    if attack == "uncited":
        claim["source_ids"] = []
    elif attack == "hallucinated":
        claim["source_ids"] = ["invented-source"]
    elif attack == "stale-current":
        claim["observed_at"] = (_utc_today() - timedelta(days=366)).isoformat() + "T00:00:00+00:00"
    elif attack == "protected":
        claim["health"] = "attacker-supplied private attribute"
    else:
        claim["subject_type"] = "private_person"
    with pytest.raises(ValueError):
        validate_dossier(dossier, cache)
    # The durable worker path must reject the same payload before it records
    # either a dossier or a completion transition.
    database, job_key, worker_cache = _ready_database(tmp_path / "worker", f"{attack}-worker")
    task = database.claim_research("validator")
    assert task is not None
    runtime_dossier = _strict_dossier(worker_cache, job_key)
    runtime_claim = runtime_dossier["claims"][0]
    if attack == "uncited":
        runtime_claim["source_ids"] = []
    elif attack == "hallucinated":
        runtime_claim["source_ids"] = ["invented-source"]
    elif attack == "stale-current":
        runtime_claim["observed_at"] = (_utc_today() - timedelta(days=366)).isoformat() + "T00:00:00+00:00"
    elif attack == "protected":
        runtime_claim["health"] = "attacker-supplied private attribute"
    else:
        runtime_claim["subject_type"] = "private_person"
    with pytest.raises(ValueError):
        database.complete_research(job_key=job_key, worker_id="validator", dossier=runtime_dossier, dossier_hash=content_hash(runtime_dossier))
    with database.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM employer_dossiers WHERE job_key=?", (job_key,)).fetchone()[0] == 0
        assert conn.execute("SELECT status FROM employer_research_queue WHERE job_key=?", (job_key,)).fetchone()[0] == "leased"


def test_every_rejected_opportunity_zero_queue_bypass_fails_closed(tmp_path: Path) -> None:
    database = CareerDatabase(tmp_path / "rejected.sqlite3")
    job = _job("rejected", opportunity=0.1)
    OpportunityGate(database).bootstrap([job])
    with database.connection() as conn:
        assert conn.execute("SELECT opportunity_decision FROM pipeline_jobs WHERE job_key=?", (job.key,)).fetchone()[0] == "reject"
        with pytest.raises(sqlite3.IntegrityError, match="passed opportunity gate"):
            conn.execute("INSERT INTO employer_research_queue(job_key,priority) VALUES(?,?)", (job.key, 999))
    with pytest.raises(sqlite3.IntegrityError, match="passed opportunity gate"):
        database.enqueue_research(job.key, 999)
    assert database.claim_research("bypass-worker") is None


def test_opportunity_one_demotes_strong_vacancy_and_retains_zero_with_sorted_reasons(tmp_path: Path) -> None:
    database, job_key, cache = _ready_database(tmp_path, "demotion")
    task = database.claim_research("researcher")
    assert task is not None
    _complete(database, job_key, cache, "researcher")
    # Deliberately reverse input order: persisted explanation must be deterministic.
    result = database.apply_opportunity1(job_key=job_key, signals=[
        {"claim_id": "claim-role", "reason": "Role scope materially narrowed.", "delta_bp": -2_000},
        {
            "claim_id": "claim-operational_health",
            "reason": "Funding was withdrawn.",
            "delta_bp": -2_000,
        },
    ])
    assert result["opportunity0_score_bp"] == 9000
    assert result["score_bp"] == 5000 and result["decision"] == "reject"
    assert [row["claim_id"] for row in result["changes"]] == [
        "claim-operational_health",
        "claim-role",
    ]
    with database.connection() as conn:
        job = conn.execute("SELECT opportunity,opportunity_decision,state FROM pipeline_jobs WHERE job_key=?", (job_key,)).fetchone()
        reassessment = conn.execute("SELECT opportunity0_score_bp,opportunity1_score_bp,decision,changes_json FROM opportunity_reassessments WHERE job_key=?", (job_key,)).fetchone()
    assert tuple(job) == (0.9, "pass", PipelineState.OPPORTUNITY_REJECTED_AFTER_RESEARCH.value)
    assert tuple(reassessment)[:3] == (9000, 5000, "reject")
    assert [item["claim_id"] for item in json.loads(reassessment["changes_json"])] == [
        "claim-operational_health",
        "claim-role",
    ]


def test_expired_lease_concurrent_replay_completes_exactly_one_dossier(tmp_path: Path) -> None:
    database, job_key, cache = _ready_database(tmp_path, "lease")
    assert database.claim_research("interrupted", lease_seconds=1) is not None
    # Model a dead worker after its lease expired; resumption must be safe.
    with database.connection() as conn:
        conn.execute("UPDATE employer_research_queue SET lease_until='2000-01-01T00:00:00+00:00' WHERE job_key=?", (job_key,))
    resumed = database.claim_research("resumer", lease_seconds=60)
    assert resumed is not None and resumed.attempts == 2
    dossier = _strict_dossier(cache, job_key)
    digest = content_hash(dossier)
    with pytest.raises(RuntimeError, match="not leased"):
        database.complete_research(job_key=job_key, worker_id="interrupted", dossier=dossier, dossier_hash=digest)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(database.complete_research, job_key=job_key, worker_id="resumer", dossier=dossier, dossier_hash=digest) for _ in range(2)]
        for future in futures:
            future.result()
    with database.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM employer_dossiers WHERE job_key=?", (job_key,)).fetchone()[0] == 1
        assert tuple(conn.execute("SELECT status,attempts FROM employer_research_queue WHERE job_key=?", (job_key,)).fetchone()) == ("completed", 2)
        assert conn.execute("SELECT COUNT(*) FROM pipeline_events WHERE job_key=? AND event_type='lifecycle_transition_committed'", (job_key,)).fetchone()[0] == 3
    assert database.lifecycle.replay()[job_key] is PipelineState.EMPLOYER_RESEARCHED


def test_production_worker_consumes_real_database_queue_and_fails_closed_for_retrieval_and_invalid_dossier(
    tmp_path: Path,
) -> None:
    """Exercise the public worker with on-disk SQLite, never a mock queue."""
    database, job_key, cache = _ready_database(tmp_path / "success", "worker-success")

    class PublicRetriever:
        def retrieve(self, source_id: str, url: str) -> Citation:
            body = (
                b"<p>Example operates a documented public business serving customers.</p>"
                b"<p>The Engineer role has documented responsibilities and duties.</p>"
                b"<p>The product platform provides a service for customers.</p>"
                b"<p>The careers vacancy invites candidates to apply through hiring.</p>"
                b"<p>In 2026 Example reported operational revenue and profit performance.</p>"
            )
            digest, reference = cache.store(body)
            timestamp = _utc_today().isoformat() + "T00:00:00+00:00"
            return Citation(source_id, "https://8.8.8.8/public", timestamp, timestamp,
                            digest, reference, 200)

    worker = EmployerResearchWorker(database, "successful-worker", cache,
                                    retriever=PublicRetriever(), lease_seconds=60)
    assert worker.run_once() == job_key
    assert worker.run_once() is None
    with database.connection() as conn:
        assert tuple(conn.execute(
            "SELECT status, attempts FROM employer_research_queue WHERE job_key=?", (job_key,)
        ).fetchone()) == ("completed", 1)
        assert conn.execute("SELECT COUNT(*) FROM employer_dossiers WHERE job_key=?", (job_key,)).fetchone()[0] == 1

    for failure in ("retrieval", "invalid-dossier"):
        failed_database, failed_key, failed_cache = _ready_database(tmp_path / failure, failure)

        class FailingRetriever:
            def retrieve(self, source_id: str, url: str) -> Citation:
                if failure == "retrieval":
                    raise RuntimeError("retrieval unavailable")
                # No substantive paragraph makes the production dossier builder
                # reject the result before completion.
                digest, reference = failed_cache.store(b"<html>unusable</html>")
                timestamp = _utc_today().isoformat() + "T00:00:00+00:00"
                return Citation(source_id, "https://8.8.8.8/public", timestamp, timestamp,
                                digest, reference, 200)

        with pytest.raises((RuntimeError, ValueError)):
            EmployerResearchWorker(failed_database, f"{failure}-worker", failed_cache,
                                   retriever=FailingRetriever(), lease_seconds=60).run_once()
        with failed_database.connection() as conn:
            assert tuple(conn.execute(
                "SELECT status, lease_owner, attempts FROM employer_research_queue WHERE job_key=?", (failed_key,)
            ).fetchone()) == ("leased", f"{failure}-worker", 1)
            assert conn.execute("SELECT COUNT(*) FROM employer_dossiers WHERE job_key=?", (failed_key,)).fetchone()[0] == 0


def test_jaa04_command_is_declared_and_refuses_missing_external_authority(tmp_path: Path) -> None:
    declaration = (ROOT / "acceptance").read_text(encoding="utf-8")
    assert "scripts/run_acceptance_declaration.py" in declaration
    repository = tmp_path / "certification-repository"
    copied = subprocess.run(("git", "clone", "--no-local", "--single-branch", "--depth", "1",
                             str(REPOSITORY_ROOT), str(repository)), text=True,
                            capture_output=True, check=False)
    assert copied.returncode == 0, copied.stderr
    clone = repository / "internal" / "jaa"
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
