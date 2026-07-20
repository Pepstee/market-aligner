"""Independent semantic-contract probes for JAA-04 reconnaissance.

These deliberately construct byte-addressed source plans rather than relying
on the frozen corpus or acceptance implementation to validate itself.
"""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path

import pytest

from career_automation.employer_research import (
    FRESHNESS_DAYS,
    RawResponseCache,
    load_frozen_dossiers,
    validate_dossier,
)


ROOT = Path(__file__).resolve().parent
CAPTURE = ROOT / "career_automation" / "fixtures" / "jaa04_capture"
KINDS = ("company", "role", "product", "hiring", "operational_health")

RELEVANT = {
    "company": "The company operates as an employer and business serving regulated customers.",
    "role": "This role has job responsibilities and duties for the successful position holder.",
    "product": "The product platform service gives customers technology for their daily work.",
    "hiring": "The careers vacancy invites each candidate to apply through the hiring application.",
    "operational_health": "In 2026 the company reported current operational revenue and profit performance.",
}
UNRELATED = {
    # Each control intentionally contains a policy keyword, is unique bytes,
    # and occupies the matching source-plan position.  Keyword coincidence or
    # correct provenance cannot make it evidence of the requested kind.
    "company": "The museum company in a historical novel is a fictional business from 1890.",
    "role": "Company history says its role in the town began during the 1901 exhibition.",
    "product": "This product brochure describes a discontinued souvenir sold at a 1998 museum event.",
    "hiring": "The university careers article explains how alumni hired a speaker in 2003, not a vacancy.",
    "operational_health": "The product page calls its colour current and operational, without financial results.",
}


def _dossier(cache: RawResponseCache, *, excerpts: dict[str, str] | None = None) -> dict[str, object]:
    today = date.today().isoformat()
    excerpts = excerpts or RELEVANT
    sources, plan, claims = [], [], []
    for index, kind in enumerate(KINDS):
        body = f"<p>{excerpts[kind]}</p>".encode()
        digest, reference = cache.store(body)
        source_id, plan_id = f"source-{index}", f"plan-{index}"
        timestamp = f"{today}T00:00:00+00:00"
        sources.append({
            "id": source_id, "url": f"https://8.8.8.8/jaa04/{index}",
            "captured_at": timestamp, "retrieved_at": timestamp,
            "content_sha256": digest, "raw_response_ref": reference, "status_code": 200,
        })
        plan.append({
            "id": plan_id, "kind": kind, "source_id": source_id,
            "source_type": {
                "company": "official_company", "role": "official_vacancy",
                "product": "official_product", "hiring": "official_careers",
                "operational_health": "official_financial",
            }[kind],
            "permitted_purposes": [kind], "freshness_days": FRESHNESS_DAYS[next(
                key for key in FRESHNESS_DAYS if key.value == kind
            )],
            "relevance_terms": {
                "company": ["company"], "role": ["role"], "product": ["product"],
                "hiring": ["careers"], "operational_health": ["operational"],
            }[kind],
            "excerpt_sha256": hashlib.sha256(body).hexdigest(),
        })
        claims.append({
            "id": f"claim-{index}", "kind": kind,
            "classification": "fact" if index == 0 else "inference",
            "text": f"Example employer has independently evidenced {kind} intelligence.",
            "observed_at": timestamp, "source_captured_at": timestamp,
            "freshness_classification": "current", "source_ids": [source_id],
            "source_plan_id": plan_id, "citation_excerpt": body.decode(),
        })
    return {"schema_version": "jaa04.dossier.v1", "job_key": "semantic-probe",
            "sources": sources, "source_plan": plan, "claims": claims, "edges": []}


@pytest.mark.parametrize("kind", KINDS)
def test_each_intelligence_kind_accepts_relevant_byte_resolvable_evidence(tmp_path: Path, kind: str) -> None:
    """Every kind must accept its own relevant source-plan evidence."""
    dossier = _dossier(RawResponseCache(tmp_path / kind))
    validate_dossier(dossier, RawResponseCache(tmp_path / kind))
    assert next(claim for claim in dossier["claims"] if claim["kind"] == kind)["citation_excerpt"] == f"<p>{RELEVANT[kind]}</p>"


@pytest.mark.parametrize("kind", KINDS)
def test_each_kind_rejects_unique_ordered_but_semantically_unrelated_evidence(tmp_path: Path, kind: str) -> None:
    """Position, unique bytes, source resolution and one keyword are insufficient."""
    excerpts = dict(RELEVANT)
    excerpts[kind] = UNRELATED[kind]
    cache = RawResponseCache(tmp_path / kind)
    dossier = _dossier(cache, excerpts=excerpts)
    # The attack is deliberately otherwise perfect provenance.
    source = dossier["sources"][KINDS.index(kind)]
    assert cache.resolve(source["raw_response_ref"], source["content_sha256"])
    with pytest.raises(ValueError, match="kind-irrelevant"):
        validate_dossier(dossier, cache)


def test_frozen_dossiers_bind_every_claim_to_declared_kind_specific_source_plan_and_exact_bytes() -> None:
    cache = RawResponseCache(CAPTURE / "raw")
    dossiers = load_frozen_dossiers(CAPTURE / "frozen_dossiers.json", cache, strict_corpus=True)
    assert len(dossiers) == 30
    for dossier in dossiers:
        sources = {source["id"]: source for source in dossier["sources"]}
        plans = {entry["id"]: entry for entry in dossier["source_plan"]}
        assert {entry["kind"] for entry in plans.values()} == set(KINDS)
        assert {claim["kind"] for claim in dossier["claims"]} == set(KINDS)
        for claim in dossier["claims"]:
            entry = plans[claim["source_plan_id"]]
            source = sources[entry["source_id"]]
            assert entry["kind"] == claim["kind"]
            assert claim["source_ids"] == [entry["source_id"]]
            assert claim["source_captured_at"] == source["captured_at"]
            assert hashlib.sha256(claim["citation_excerpt"].encode()).hexdigest() == entry["excerpt_sha256"]
            assert claim["citation_excerpt"].encode() in cache.resolve(source["raw_response_ref"], source["content_sha256"])


@pytest.mark.parametrize("attack", ("undeclared-source", "missing-kind", "stale-current"))
def test_required_evidence_and_freshness_controls_fail_closed(tmp_path: Path, attack: str) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    dossier = _dossier(cache)
    if attack == "undeclared-source":
        dossier["claims"][0]["source_ids"] = ["not-in-the-plan"]
    elif attack == "missing-kind":
        dossier["claims"] = dossier["claims"][:-1]
        dossier["source_plan"] = dossier["source_plan"][:-1]
    else:
        dossier["claims"][1]["observed_at"] = "2000-01-01T00:00:00+00:00"
        dossier["claims"][1]["freshness_classification"] = "current"
    with pytest.raises(ValueError):
        validate_dossier(dossier, cache)
