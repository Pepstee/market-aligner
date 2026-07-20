"""Independent acceptance tests for JAA-04 Increment A ATS authority canaries."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from career_automation.employer_research import (
    ATS_AUTHORITY_CANARIES,
    Citation,
    PortableAuthorityRetriever,
    RawResponseCache,
    validate_dossier,
)
from career_automation.models import IntelligenceKind


ROOT = Path(__file__).resolve().parent
CAPTURE_SCRIPT = ROOT / "scripts/capture_jaa04_authority_canaries.py"
STAMP = "2026-07-20T00:00:00+00:00"


def _record(key: str):
    return next(item for item in ATS_AUTHORITY_CANARIES if item.job_key == key)


def _canary_body(record) -> bytes:
    return (
        f'<meta property="article:published_time" content="{STAMP}">'
        f"<main>{record.company} is recruiting for {record.title}.</main>"
    ).encode()


def _citation(record, cache: RawResponseCache, *, url: str | None = None,
              body: bytes | None = None, temporal: bool = True,
              redirects: list[dict[str, object]] | None = None) -> tuple[Citation, bytes]:
    body = body if body is not None else _canary_body(record)
    digest, ref = cache.store(body)
    final_url = url or record.authority_url
    return Citation("fixture", final_url, STAMP, STAMP, digest, ref, 200,
                    record.authority_url, redirects or [],
                    STAMP if temporal else None, None,
                    "official_vacancy", final_url.split("/")[2], final_url,
                    '<meta property="article:published_time" content="2026-07-20T00:00:00+00:00">'
                    if temporal else None, "scrapling-static"), body


def test_real_production_canary_acquisition_writes_three_byte_bound_sidecars_without_touching_corpus_receipt(
    tmp_path: Path,
) -> None:
    """The public capture command must use the sidecar and publish no corpus receipt."""
    receipts_before = {
        path.relative_to(ROOT): path.read_bytes()
        for path in ROOT.glob("**/capture_receipt.json")
    }
    destination = tmp_path / "canaries"
    completed = subprocess.run((sys.executable, str(CAPTURE_SCRIPT), "--destination", str(destination)),
                               cwd=ROOT, text=True, capture_output=True, check=False, timeout=240)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["artifacts"] == 3
    receipts_after = {
        path.relative_to(ROOT): path.read_bytes()
        for path in ROOT.glob("**/capture_receipt.json")
    }
    assert receipts_after == receipts_before
    assert not (destination / "capture_receipt.json").exists()

    expected = {"greenhouse": "greenhouse:anthropic:5030244008",
                "ashby": "ashby:lendable:36d47627-9b4e-4864-9f05-2dbbd1052380",
                "workable": "workable:cogna:847CFBC5F4"}
    assert {path.stem for path in destination.glob("*.json")} == set(expected)
    for provider, job_key in expected.items():
        artifact = json.loads((destination / f"{provider}.json").read_text(encoding="utf-8"))
        assert artifact["schema_version"] == "jaa04.typed-authority-canary.v1"
        assert artifact["admitted_record"]["job_key"] == job_key
        assert artifact["captures"]
        for capture in artifact["captures"]:
            raw = base64.b64decode(capture["raw_response_base64"], validate=True)
            assert hashlib.sha256(raw).hexdigest() == capture["content_sha256"]
            assert capture["raw_response_ref"] == "embedded:raw_response_base64"
            assert capture["sidecar_raw_response_ref"].endswith(capture["content_sha256"])
            assert capture["retrieval_engine"].startswith("scrapling-")


@pytest.mark.parametrize("attack", (
    "asset", "form", "unrelated", "employer-mismatch", "vacancy-mismatch",
    "off-chain-redirect", "missing-temporal", "forged-temporal",
))
def test_canary_admission_negative_controls_fail_closed(tmp_path: Path, attack: str) -> None:
    record = _record("workable:cogna:847CFBC5F4")
    cache = RawResponseCache(tmp_path / "raw")
    body = _canary_body(record)
    url, temporal, redirects = record.authority_url, True, []
    if attack == "asset":
        url = "https://apply.workable.com/cogna/jobs/view/847CFBC5F4.md/logo.svg"
    elif attack == "form":
        url = "https://apply.workable.com/cogna/j/847CFBC5F4/apply"
    elif attack == "unrelated":
        url = "https://apply.workable.com/cogna/jobs/view/OTHER.md"
    elif attack == "employer-mismatch":
        body = body.replace(b"Cogna", b"OtherCorp")
    elif attack == "vacancy-mismatch":
        body = body.replace(b"Software Engineer", b"Product Manager")
    elif attack == "off-chain-redirect":
        redirects = [{"url": "https://evil.example.test/landing", "status_code": 302}]
    elif attack == "missing-temporal":
        temporal = False
    elif attack == "forged-temporal":
        body = body.replace(b"2026-07-20", b"2025-01-01")
    citation, body = _citation(record, cache, url=url, body=body, temporal=temporal, redirects=redirects)
    with pytest.raises(ValueError):
        PortableAuthorityRetriever._validate_canary_capture(record, citation, body)


def _portable_dossier(cache: RawResponseCache) -> dict[str, object]:
    excerpts = {
        IntelligenceKind.COMPANY: "<p>Acme company operates a public business serving customers.</p>",
        IntelligenceKind.PRODUCT: "<p>Acme product platform provides technology services to customers.</p>",
    }
    body = "".join(excerpts.values()).encode()
    digest, ref = cache.store(body)
    source = {"id": "source", "url": "https://acme.example.test/evidence", "captured_at": STAMP,
              "retrieved_at": STAMP, "content_sha256": digest, "raw_response_ref": ref, "status_code": 200,
              "source_kind": "official_company", "canonical_publisher": "acme.example.test",
              "canonical_article": "https://acme.example.test/evidence", "retrieval_engine": "test"}
    plan, claims = [], []
    for kind in IntelligenceKind:
        common = {"id": f"plan:{kind.value}", "kind": kind.value, "permitted_purposes": [kind.value],
                  "freshness_days": {"company": 365, "role": 45, "product": 180, "hiring": 45,
                                     "operational_health": 90}[kind.value]}
        if kind not in excerpts:
            reason = f"No purpose-specific public authority was available for {kind.value} in this capture."
            plan.append({**common, "outcome": "unknown", "reason": reason})
            claims.append({"id": f"claim:{kind.value}", "kind": kind.value, "outcome": "unknown",
                           "classification": None, "text": reason, "source_ids": [], "citation_excerpt": None,
                           "score_delta_bp": 0})
            continue
        excerpt = excerpts[kind]
        start = body.index(excerpt.encode())
        plan.append({**common, "outcome": "supported", "source_id": "source", "source_type": "official_company",
                     "source_content_sha256": digest, "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
                     "excerpt_byte_start": start, "excerpt_byte_length": len(excerpt.encode())})
        claims.append({"id": f"claim:{kind.value}", "kind": kind.value, "outcome": "supported",
                       "classification": "fact", "text": f"Acme: {excerpt[3:-4]}", "source_ids": ["source"],
                       "citation_excerpt": excerpt, "observed_at": None,
                       "temporal_semantics": "retrieval_snapshot", "score_delta_bp": 0})
    return {"schema_version": "jaa04.dossier.v3", "job_key": "range-test", "sources": [source],
            "source_plan": plan, "claims": claims, "edges": []}


@pytest.mark.parametrize("attack", ("partial-overlap", "reversed", "out-of-bounds"))
def test_full_containment_range_validation_rejects_every_non_exact_range(tmp_path: Path, attack: str) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    dossier = _portable_dossier(cache)
    product = next(row for row in dossier["source_plan"] if row["kind"] == "product")
    if attack == "partial-overlap":
        product["excerpt_byte_start"] -= 8
        product["excerpt_byte_length"] += 8
    elif attack == "reversed":
        product["excerpt_byte_start"] = 50
        product["excerpt_byte_length"] = -1
    else:
        product["excerpt_byte_start"] = 10**6
    with pytest.raises(ValueError):
        validate_dossier(dossier, cache)

