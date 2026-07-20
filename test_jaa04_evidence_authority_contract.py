"""Operator-level JAA-04 evidence-authority and decision-provenance contract."""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import pytest

from career_automation.database import CareerDatabase
from career_automation.employer_research import (
    Citation,
    EmployerResearchWorker,
    FRESHNESS_DAYS,
    Opportunity1Coordinator,
    RawResponseCache,
)
from career_automation.engine import OpportunityGate, scored_job_from_payload
from career_automation.models import IntelligenceKind


ROOT = Path(__file__).resolve().parent
CAPTURE = ROOT / "career_automation/fixtures/jaa04_capture"
CAPTURE_PLAN = ROOT / "career_automation/fixtures/jaa04_capture_plan.json"


def test_capture_plan_uses_purpose_specific_authorities() -> None:
    """Different URLs do not become different authorities merely by relabelling them."""
    payload = json.loads(CAPTURE_PLAN.read_text(encoding="utf-8"))
    assert payload.get("schema_version") == "jaa04.capture-plan.v2"
    assert len(payload.get("records", [])) == 30
    permitted_types = {
        "company": {"official_company", "corporate_profile", "authoritative_company_record"},
        "product": {"official_company", "official_product", "official_product_documentation"},
        "role": {"official_vacancy", "official_role"},
        "hiring": {"official_vacancy", "official_careers"},
        "operational_health": {
            "dated_operational", "official_financial", "regulatory_filing",
            "regulatory_status_record", "independent_reporting",
        },
    }
    for record in payload["records"]:
        sources = record.get("sources", [])
        assert {source.get("kind") for source in sources} == set(permitted_types)
        identities = {
            ((urlparse(str(source.get("url", ""))).hostname or "").casefold(),
             urlparse(str(source.get("url", ""))).path)
            for source in sources
        }
        assert len(identities) == 5, f"{record['id']} aliases one publication across purposes"
        for source in sources:
            kind = source["kind"]
            host = (urlparse(source["url"]).hostname or "").casefold()
            assert source.get("source_type") in permitted_types[kind], (
                f"{record['id']} labels {source.get('source_type')} as {kind} authority"
            )
            if kind in {"role", "hiring", "operational_health"}:
                assert not host.endswith("wikipedia.org")


def test_frozen_source_purposes_are_distinct_and_authority_bound() -> None:
    """Renaming one response five times cannot create five evidence sources."""
    dossiers = json.loads((CAPTURE / "frozen_dossiers.json").read_text(encoding="utf-8"))["dossiers"]
    assert len(dossiers) == 30
    for dossier in dossiers:
        sources = {source["id"]: source for source in dossier["sources"]}
        plans = dossier["source_plan"]
        assert len(sources) == len(plans) == 5
        capture_identities = {
            (source["url"], source["content_sha256"], source["raw_response_ref"])
            for source in sources.values()
        }
        assert len(capture_identities) == 5, f"{dossier['job_key']} aliases one capture across purposes"

        for plan in plans:
            source = sources[plan["source_id"]]
            host = (urlparse(source["url"]).hostname or "").casefold()
            if plan["kind"] in {"role", "hiring", "operational_health"}:
                assert not host.endswith("wikipedia.org"), (
                    f"{dossier['job_key']} self-declares Wikipedia as {plan['source_type']}"
                )


def test_historical_paragraphs_are_not_represented_as_current_intelligence() -> None:
    dossiers = json.loads((CAPTURE / "frozen_dossiers.json").read_text(encoding="utf-8"))["dossiers"]
    for dossier in dossiers:
        for claim in dossier["claims"]:
            if claim.get("freshness_classification") != "current":
                continue
            years = [int(value) for value in re.findall(r"\b(?:19|20)\d{2}\b", claim["citation_excerpt"])]
            if not years:
                continue
            observed_year = date.fromisoformat(claim["observed_at"][:10]).year
            freshness_years = max(1, FRESHNESS_DAYS[IntelligenceKind(claim["kind"])] // 365)
            assert max(years) >= observed_year - freshness_years, (
                f"{dossier['job_key']} labels evidence ending in {max(years)} current at {observed_year}"
            )


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
                b"<p>In 2026 the company operates a business product platform service for customers; "
                b"the hiring vacancy asks candidates to apply for an engineering role with stated "
                b"responsibilities, and reported operational revenue and profit performance.</p>"
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
