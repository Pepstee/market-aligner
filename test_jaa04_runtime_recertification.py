"""Adversarial JAA-04 recertification tests, independent of acceptance helpers."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
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
    content_hash,
    load_frozen_dossiers,
    validate_dossier,
)
from career_automation.engine import OpportunityGate, scored_job_from_payload


ROOT = Path(__file__).resolve().parent
CAPTURE = ROOT / "career_automation/fixtures/jaa04_capture"
KIND_SET = {"company", "role", "product", "hiring", "operational_health"}


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
            b"<p>Example operates a documented public service with distinct products, "
            b"delivery responsibilities, customers, hiring context, and operating constraints.</p>"
        )
        digest, reference = self.cache.store(body)
        timestamp = date.today().isoformat() + "T00:00:00+00:00"
        return Citation(source_id, "https://8.8.8.8/public", timestamp, timestamp,
                        digest, reference, 200)


def test_frozen_dossiers_are_employer_specific_after_name_normalization_and_byte_exact() -> None:
    """Do not trust the production loader to prove its own corpus assertions."""
    envelope = json.loads((CAPTURE / "frozen_dossiers.json").read_text(encoding="utf-8"))
    dossiers = envelope["dossiers"]
    cache = RawResponseCache(CAPTURE / "raw")
    assert len(dossiers) == 30
    normalized_by_kind = {kind: set() for kind in KIND_SET}
    for dossier in dossiers:
        validate_dossier(dossier, cache)
        claims = dossier["claims"]
        employer = claims[0]["text"].split(":", 1)[0].strip()
        assert employer and {claim["kind"] for claim in claims} == KIND_SET
        sources = {source["id"]: source for source in dossier["sources"]}
        for claim in claims:
            excerpt = claim["citation_excerpt"]
            assert isinstance(excerpt, str) and excerpt.strip()
            assert any(
                excerpt.encode("utf-8") == body[offset:offset + len(excerpt.encode("utf-8"))]
                for source_id in claim["source_ids"]
                for body in [cache.resolve(sources[source_id]["raw_response_ref"], sources[source_id]["content_sha256"])]
                for offset in [body.find(excerpt.encode("utf-8"))]
                if offset >= 0
            ), "excerpt must resolve to the captured bytes, not merely a decoded approximation"
            normalized = claim["text"].casefold().replace(employer.casefold(), "<employer>")
            assert len(normalized.split()) >= 8
            normalized_by_kind[claim["kind"]].add(normalized)
    assert {kind: len(values) for kind, values in normalized_by_kind.items()} == {
        kind: 30 for kind in KIND_SET
    }


def test_strict_corpus_rejects_boilerplate_and_altered_or_broken_capture_provenance(tmp_path: Path) -> None:
    source = json.loads((CAPTURE / "frozen_dossiers.json").read_text(encoding="utf-8"))
    cache = RawResponseCache(CAPTURE / "raw")

    # Identical intelligence after employer-name replacement is boilerplate,
    # even when each original source and claim hash remains otherwise valid.
    boilerplate = json.loads(json.dumps(source))
    for dossier in boilerplate["dossiers"]:
        employer = dossier["claims"][0]["text"].split(":", 1)[0]
        for claim in dossier["claims"]:
            claim["text"] = f"{employer}: stable generic {claim['kind']} intelligence for every employer."
    boilerplate["dossiers_hash"] = content_hash(boilerplate["dossiers"])
    boilerplate_path = tmp_path / "boilerplate.json"
    boilerplate_path.write_text(json.dumps(boilerplate), encoding="utf-8")
    with pytest.raises(ValueError, match="employer-normalized"):
        load_frozen_dossiers(boilerplate_path, cache, strict_corpus=True)

    dossier = json.loads(json.dumps(source["dossiers"][0]))
    raw = cache.root / dossier["sources"][0]["raw_response_ref"]
    original = raw.read_bytes()
    raw.write_bytes(original + b" altered")
    try:
        with pytest.raises(ValueError, match="hash mismatch"):
            validate_dossier(dossier, cache)
    finally:
        raw.write_bytes(original)
    dossier["sources"][0]["raw_response_ref"] = "sha256/00/not-the-captured-object"
    with pytest.raises((OSError, ValueError)):
        validate_dossier(dossier, cache)


def test_coordinator_advances_only_after_real_worker_completion_and_never_after_failure(tmp_path: Path) -> None:
    database, job_key, cache = _database(tmp_path / "success")
    worker = EmployerResearchWorker(database, "researcher", cache, retriever=_CapturedRetriever(cache))
    coordinator = Opportunity1Coordinator(database, worker)
    outcome = coordinator.run_once()
    assert outcome is not None
    with database.connection() as conn:
        event_types = [row[0] for row in conn.execute(
            "SELECT event_type FROM pipeline_events WHERE job_key=? ORDER BY event_id", (job_key,)
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
    with pytest.raises(RuntimeError, match="requires completed employer research"):
        incomplete_db.apply_opportunity1(job_key=incomplete_key, signals=[])


def test_failed_acceptance_runtime_cannot_emit_a_jaa04_receipt(tmp_path: Path) -> None:
    """A corrupt capture must fail before receipt publication in an isolated clone."""
    clone = tmp_path / "clone"
    copied = subprocess.run(("git", "clone", "--no-local", str(ROOT), str(clone)), text=True,
                            capture_output=True, check=False)
    assert copied.returncode == 0, copied.stderr
    manifest = clone / "career_automation/fixtures/jaa04_capture/research_manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")
    completed = subprocess.run((sys.executable, "scripts/accept_jaa_04.py"), cwd=clone,
                               text=True, capture_output=True, check=False)
    assert completed.returncode != 0
    assert not list((clone / "runtime_evidence/jaa04").glob("*.json"))

