"""Operator-level JAA-04 evidence-authority and decision-provenance contract."""

from __future__ import annotations

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


def test_opportunity_one_rejects_reason_not_grounded_in_completed_claim(tmp_path: Path) -> None:
    database = CareerDatabase(tmp_path / "career.sqlite3")
    job = scored_job_from_payload({
        "board": "jaa04-authority", "job_id": "ungrounded-signal",
        "url": "https://jobs.example.test/ungrounded-signal", "job_title": "Engineer",
        "company": "Example", "fit": .8, "opportunity": .9, "final": 80,
        "extraction_confidence": .99,
    })
    OpportunityGate(database).bootstrap([job])
    cache = RawResponseCache(tmp_path / "raw")

    class RelevantRetriever:
        def retrieve(self, source_id: str, url: str) -> Citation:
            body = (
                b"<p>Example operates a public business serving regulated customers.</p>"
                b"<p>The Engineer role has documented responsibilities and duties.</p>"
                b"<p>The product platform provides a service for customers.</p>"
                b"<p>The careers vacancy invites candidates to apply through hiring.</p>"
                b"<p>In 2026 Example reported operational revenue and profit performance.</p>"
            )
            digest, reference = cache.store(body)
            timestamp = f"{date.today().isoformat()}T00:00:00+00:00"
            return Citation(source_id, "https://8.8.8.8/evidence", timestamp, timestamp,
                            digest, reference, 200)

    worker = EmployerResearchWorker(database, "authority-worker", cache,
                                    retriever=RelevantRetriever(), lease_seconds=60)
    coordinator = Opportunity1Coordinator(
        database,
        worker,
        signal_deriver=lambda dossier: [{
            "claim_id": "health-inference",
            "reason": "Funding was withdrawn.",
            "delta_bp": -2000,
        }],
    )
    with pytest.raises(ValueError, match="grounded|evidence|claim"):
        coordinator.run_once()
