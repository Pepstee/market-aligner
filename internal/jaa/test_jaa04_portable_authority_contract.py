"""Independent fail-closed probes for the portable JAA-04 authority contract."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from career_automation.employer_research import (
    FRESHNESS_DAYS,
    Citation,
    PortableAuthorityRetriever,
    RawResponseCache,
    validate_dossier,
)
from career_automation.models import IntelligenceKind


KINDS = tuple(IntelligenceKind)
STAMP = "2026-07-01T00:00:00+00:00"


def _citation(cache: RawResponseCache, body: bytes, *, source_kind: str = "official_company") -> Citation:
    digest, reference = cache.store(body)
    return Citation("shared", "https://acme.example.test/evidence", STAMP, STAMP, digest, reference, 200,
                    source_kind=source_kind, canonical_publisher="acme.example.test",
                    canonical_article="https://acme.example.test/evidence", retrieval_engine="test-retriever")


def _portable(cache: RawResponseCache, body: bytes, supported: dict[str, tuple[str, str]]) -> dict[str, object]:
    """Build a v3 dossier with supported entries or deliberately non-claims."""
    citation = _citation(cache, body, source_kind=next(iter(supported.values()))[1] if supported else "official_company")
    plan, claims = [], []
    for kind in KINDS:
        key = kind.value
        common = {"id": f"plan:{key}", "kind": key, "permitted_purposes": [key],
                  "freshness_days": FRESHNESS_DAYS[kind]}
        if key not in supported:
            outcome = "abstained" if key == "hiring" else "unknown"
            reason = f"No purpose-specific public authority was available for {key} in this capture."
            plan.append({**common, "outcome": outcome, "reason": reason})
            claims.append({"id": f"claim:{key}", "kind": key, "outcome": outcome,
                           "classification": None, "text": reason, "source_ids": [],
                           "citation_excerpt": None, "score_delta_bp": 0})
            continue
        excerpt, source_type = supported[key]
        raw = excerpt.encode()
        start = body.index(raw)
        plan.append({**common, "outcome": "supported", "source_id": citation.id,
                     "source_type": source_type, "source_content_sha256": citation.content_sha256,
                     "excerpt_sha256": hashlib.sha256(raw).hexdigest(), "excerpt_byte_start": start,
                     "excerpt_byte_length": len(raw)})
        claims.append({"id": f"claim:{key}", "kind": key, "outcome": "supported",
                       "classification": "fact", "text": f"Acme: {excerpt.replace('<p>', '').replace('</p>', '')}",
                       "source_ids": [citation.id], "citation_excerpt": excerpt,
                       "observed_at": None, "temporal_semantics": "retrieval_snapshot", "score_delta_bp": 0})
    return {"schema_version": "jaa04.dossier.v3", "job_key": "portable-contract",
            "sources": [vars(citation)], "source_plan": plan, "claims": claims, "edges": []}


def test_one_authentic_capture_can_support_two_kinds_only_with_disjoint_exact_excerpts(tmp_path: Path) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    company = "<p>Acme company operates a public business that serves regulated customers worldwide.</p>"
    product = "<p>Acme product platform provides a technology service that enables customers to work.</p>"
    dossier = _portable(cache, (company + product).encode(), {
        "company": (company, "official_company"), "product": (product, "official_company"),
    })
    validate_dossier(dossier, cache)


@pytest.mark.parametrize("attack", ("reused", "overlapping"))
def test_shared_capture_reused_or_overlapping_excerpt_fails_closed(tmp_path: Path, attack: str) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    shared = "<p>Acme company operates a product platform service for customers and public business users.</p>"
    body = shared.encode()
    product = shared if attack == "reused" else "company operates a product platform service for customers"
    dossier = _portable(cache, body, {"company": (shared, "official_company"),
                                      "product": (product, "official_company")})
    with pytest.raises(ValueError, match="capture|excerpt|range"):
        validate_dossier(dossier, cache)


@pytest.mark.parametrize("attack", ("missing-kind", "duplicate-outcome", "uncited", "reasonless"))
def test_five_kind_mixed_outcome_dossiers_are_complete_and_fail_closed(tmp_path: Path, attack: str) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    company = "<p>Acme company operates a public business that serves regulated customers worldwide.</p>"
    dossier = _portable(cache, company.encode(), {"company": (company, "official_company")})
    validate_dossier(dossier, cache)
    if attack == "missing-kind":
        dossier["claims"].pop()  # type: ignore[index]
    elif attack == "duplicate-outcome":
        dossier["source_plan"][1]["kind"] = "company"  # type: ignore[index]
    elif attack == "uncited":
        dossier["claims"][0]["source_ids"] = []  # type: ignore[index]
    else:
        dossier["source_plan"][1]["reason"] = ""  # type: ignore[index]
        dossier["claims"][1]["text"] = ""  # type: ignore[index]
    with pytest.raises(ValueError):
        validate_dossier(dossier, cache)


@pytest.mark.parametrize("excerpt, passes", (
    ("<p>In 2026 Acme employs 300 staff and operates a popular customer platform.</p>", False),
    ("<p>In 2026 Acme reported revenue of £10 million and profit financial performance.</p>", True),
))
def test_operational_health_requires_purpose_specific_substantive_evidence(
    tmp_path: Path, excerpt: str, passes: bool,
) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    dossier = _portable(cache, excerpt.encode(), {"operational_health": (excerpt, "official_financial")})
    source = dossier["sources"][0]  # type: ignore[index]
    dated = b'<meta property="article:published_time" content="2026-07-01T00:00:00+00:00">'
    body = dated + excerpt.encode()
    digest, ref = cache.store(body)
    source.update({"content_sha256": digest, "raw_response_ref": ref, "published_at": STAMP,
                   "publisher_date_evidence": dated.decode()})
    outcome = next(row for row in dossier["source_plan"] if row["kind"] == "operational_health")  # type: ignore[index]
    outcome.update({"source_content_sha256": digest, "excerpt_byte_start": len(dated),
                    "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest()})
    claim = next(row for row in dossier["claims"] if row["kind"] == "operational_health")  # type: ignore[index]
    claim.update({"observed_at": STAMP, "temporal_semantics": "publisher_time"})
    if passes:
        validate_dossier(dossier, cache)
    else:
        with pytest.raises(ValueError, match="kind-irrelevant operational_health"):
            validate_dossier(dossier, cache)


class _Routes:
    def __init__(self, cache: RawResponseCache, routes: dict[str, bytes]) -> None:
        self.cache, self.routes = cache, routes

    def retrieve(self, source_id: str, url: str, **_: object) -> Citation:
        body = self.routes[url]
        digest, ref = self.cache.store(body)
        host = url.split("/")[2]
        return Citation(source_id, url, STAMP, STAMP, digest, ref, 200, source_kind="official_company",
                        canonical_publisher=host, canonical_article=url, retrieval_engine="test-retriever")


@pytest.mark.parametrize("route, body, expected", (
    ("https://acme.example.test/products", b"<p>Acme product platform offers customers a technology service that enables users to manage daily work reliably and securely.</p>", True),
    ("https://other.example.test/products", b"<p>Other product platform offers customers a technology service that enables users to manage daily work reliably and securely.</p>", False),
    ("http://127.0.0.1/private", b"<p>Acme product platform offers customers a technology service that enables users to manage daily work reliably and securely.</p>", False),
    ("ftp://acme.example.test/non-public", b"<p>Acme product platform offers customers a technology service that enables users to manage daily work reliably and securely.</p>", False),
))
def test_portable_discovery_uses_lawful_vacancy_links_without_jobposting_hiringorganisation(
    tmp_path: Path, route: str, body: bytes, expected: bool,
) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    vacancy = "https://jobs.example.test/role"
    vacancy_body = (f'<a href="{route}">published authority</a>'
                    "<p>Acme engineering role has responsibilities and candidates may apply to this vacancy today.</p>").encode()
    retriever = PortableAuthorityRetriever(cache, retriever=_Routes(cache, {vacancy: vacancy_body, route: body}))
    task = type("Task", (), {"job_key": "portable", "url": vacancy, "company": "Acme"})()
    citations, plan = retriever.retrieve_plan(task)
    assert b"hiringOrganization" not in vacancy_body
    product = next(row for row in plan if row["kind"] == "product")
    assert (product["outcome"] == "supported") is expected
    if expected:
        assert len(citations) == 2 and product["source_id"] != citations[0].id
