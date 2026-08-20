"""Adversarial temporal-authority regression tests for JAA-04 Increment A."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from career_automation.employer_research import (
    ATS_AUTHORITY_CANARIES,
    Citation,
    PortableAuthorityRetriever,
    RawResponseCache,
)


ROOT = Path(__file__).resolve().parent
SIDECARS = ROOT / "career_automation/fixtures/jaa04_authority_canaries"
BODY_DATE = "2026-07-20T00:00:00+00:00"
FORGED_DATE = "2025-07-20T00:00:00+00:00"


def _date_tag(value: str) -> str:
    return f'<meta property="article:published_time" content="{value}">'


def _citation(record) -> tuple[Citation, bytes]:
    evidence = _date_tag(BODY_DATE)
    body = f"{evidence}<main>{record.company} — {record.title}</main>".encode()
    return Citation(
        id=f"independent:{record.job_key}",
        url=record.authority_url,
        captured_at=BODY_DATE,
        retrieved_at=BODY_DATE,
        content_sha256=hashlib.sha256(body).hexdigest(),
        raw_response_ref="independent:body",
        status_code=200,
        requested_url=record.authority_url,
        published_at=BODY_DATE,
        source_kind="official_vacancy",
        canonical_publisher=record.authority_url.split("/")[2],
        canonical_article=record.authority_url,
        publisher_date_evidence=evidence,
        retrieval_engine="test",
    ), body


@pytest.mark.parametrize("record", ATS_AUTHORITY_CANARIES, ids=lambda row: row.job_key)
def test_exact_body_date_succeeds_for_every_typed_ats_authority_canary(record) -> None:
    citation, body = _citation(record)

    PortableAuthorityRetriever._validate_canary_capture(record, citation, body)


@pytest.mark.parametrize("record", ATS_AUTHORITY_CANARIES, ids=lambda row: row.job_key)
def test_mutually_consistent_forged_citation_year_is_rejected_against_body(record) -> None:
    """A self-consistent citation cannot substitute for the captured response."""
    citation, body = _citation(record)
    forged = replace(
        citation,
        published_at=FORGED_DATE,
        publisher_date_evidence=_date_tag(FORGED_DATE),
    )

    with pytest.raises(ValueError, match="cited response bytes"):
        PortableAuthorityRetriever._validate_canary_capture(record, forged, body)


@pytest.mark.parametrize("record", ATS_AUTHORITY_CANARIES, ids=lambda row: row.job_key)
@pytest.mark.parametrize("attack", ("missing", "ambiguous", "malformed", "digest-mismatched"))
def test_canary_rejects_unresolvable_or_digest_mismatched_date_evidence(record, attack: str) -> None:
    citation, body = _citation(record)
    if attack == "missing":
        attacked = replace(citation, published_at=None, publisher_date_evidence=None)
    elif attack == "ambiguous":
        attacked = replace(
            citation,
            publisher_date_evidence=_date_tag(BODY_DATE) + _date_tag(FORGED_DATE),
        )
    elif attack == "malformed":
        attacked = replace(citation, publisher_date_evidence="<meta content=\"not-a-date\">")
    else:
        attacked = replace(citation, content_sha256=hashlib.sha256(b"different bytes").hexdigest())

    with pytest.raises(ValueError):
        PortableAuthorityRetriever._validate_canary_capture(record, attacked, body)


def test_certified_sidecar_genuine_raw_response_sha256_references_resolve(tmp_path: Path) -> None:
    """The three checked-in production captures remain byte-addressable by SHA-256."""
    cache = RawResponseCache(tmp_path / "raw")
    resolved: set[str] = set()
    for record in ATS_AUTHORITY_CANARIES:
        artifact = json.loads(
            (SIDECARS / f"{record.job_key.split(':', 1)[0]}.json").read_text(encoding="utf-8")
        )
        assert artifact["admitted_record"]["job_key"] == record.job_key
        capture = artifact["captures"][0]
        raw = base64.b64decode(capture["raw_response_base64"], validate=True)
        digest, reference = cache.store(raw)
        assert digest == capture["content_sha256"]
        assert reference == capture["sidecar_raw_response_ref"]
        assert cache.resolve(reference, digest) == raw
        resolved.add(reference)
    assert len(resolved) == 3

