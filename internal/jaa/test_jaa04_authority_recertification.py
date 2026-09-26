"""Independent adversarial checks for JAA-04 authority recertification."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from career_automation.employer_research import (
    FRESHNESS_DAYS,
    SOURCE_KIND_POLICY,
    RawResponseCache,
    validate_dossier,
)
from career_automation.models import IntelligenceKind


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
KINDS = tuple(IntelligenceKind)


def _paragraph(kind: IntelligenceKind) -> str:
    return {
        IntelligenceKind.COMPANY: "The company operates a public business and serves customers.",
        IntelligenceKind.PRODUCT: "The product platform provides a service for customers and clients.",
        IntelligenceKind.ROLE: "The engineering role has job responsibilities and duties for the team.",
        IntelligenceKind.HIRING: "The careers vacancy invites each candidate to apply for hiring.",
        IntelligenceKind.OPERATIONAL_HEALTH: (
            "In 2026 the company reported revenue and profit financial performance."
        ),
    }[kind]


def _authority_dossier(
    tmp_path: Path,
    *,
    published: str = "2026-07-01T00:00:00+00:00",
    same_article: bool = False,
    same_visible_content: bool = False,
) -> tuple[dict[str, object], RawResponseCache]:
    cache = RawResponseCache(tmp_path / "raw")
    sources: list[dict[str, object]] = []
    plan: list[dict[str, object]] = []
    claims: list[dict[str, object]] = []
    for number, kind in enumerate(KINDS):
        host = f"publisher-{number}.example.test"
        article = (
            "https://publisher-0.example.test/shared"
            if same_article
            else f"https://{host}/article"
        )
        visible = _paragraph(IntelligenceKind.COMPANY) if same_visible_content else _paragraph(kind)
        excerpt = f"<p>{visible}</p>"
        metadata = f'<meta property="article:published_time" content="{published}">'
        body = f"<!-- {article} -->{metadata}{excerpt}".encode()
        digest, reference = cache.store(body)
        source_id = f"source-{kind.value}"
        source_type = sorted(SOURCE_KIND_POLICY[kind]["source_types"])[0]
        sources.append({
            "id": source_id,
            "url": f"https://{host}/article",
            "requested_url": f"https://{host}/article",
            "captured_at": "2026-07-20T00:00:00+00:00",
            "retrieved_at": "2026-07-20T00:00:00+00:00",
            "content_sha256": digest,
            "raw_response_ref": reference,
            "status_code": 200,
            "published_at": published,
            "updated_at": None,
            "source_kind": source_type,
            "canonical_publisher": host,
            "canonical_article": article,
            "publisher_date_evidence": metadata,
            "retrieval_engine": "scrapling-static",
        })
        plan_id = f"plan-{kind.value}"
        plan.append({
            "id": plan_id,
            "kind": kind.value,
            "source_id": source_id,
            "source_type": source_type,
            "permitted_purposes": [kind.value],
            "freshness_days": FRESHNESS_DAYS[kind],
            "source_content_sha256": digest,
            "raw_response_ref": reference,
            "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
            "excerpt_byte_start": body.index(excerpt.encode()),
            "excerpt_byte_length": len(excerpt.encode()),
            "requires_current": True,
        })
        claims.append({
            "id": f"claim-{kind.value}",
            "kind": kind.value,
            "classification": "fact",
            "text": f"Example: {visible}",
            "citation_excerpt": excerpt,
            "source_plan_id": plan_id,
            "source_ids": [source_id],
            "source_captured_at": "2026-07-20T00:00:00+00:00",
            "observed_at": published,
            "freshness_classification": "current",
        })
    return ({
        "schema_version": "jaa04.dossier.v2",
        "job_key": "independent-authority",
        "raw_cache_root": str(cache.root),
        "sources": sources,
        "source_plan": plan,
        "claims": claims,
        "edges": [],
    }, cache)


def test_valid_authority_dossier_positive_control(tmp_path: Path) -> None:
    dossier, cache = _authority_dossier(tmp_path)
    validate_dossier(dossier, cache, as_of=date(2026, 7, 20))


def test_runtime_authority_evidence_is_external_and_required() -> None:
    manifest = json.loads((ROOT / "ASSURANCE_MANIFEST.json").read_text(encoding="utf-8"))
    evidence = manifest["components"]["JAA-04"]["evidence"]
    assert {(row["scope"], row["required"], row["tracked"]) for row in evidence} == {
        ("JAA-04-corpus", True, False),
        ("JAA-04-live-canary", True, False),
    }
    assert not (ROOT / "career_automation/fixtures/jaa04_capture").exists()
    assert not (ROOT / "career_automation/fixtures/jaa04_capture_plan.json").exists()


@pytest.mark.parametrize(
    "attack",
    ["missing-publisher-date", "retrieval-time-only", "stale-as-current", "uncited", "hallucinated", "private-person"],
)
def test_claim_provenance_and_freshness_controls_fail_closed(
    tmp_path: Path, attack: str,
) -> None:
    published = "2020-01-01T00:00:00+00:00" if attack == "stale-as-current" else "2026-07-01T00:00:00+00:00"
    dossier, cache = _authority_dossier(tmp_path, published=published)
    claim = dossier["claims"][0]  # type: ignore[index]
    source = dossier["sources"][0]  # type: ignore[index]
    if attack in {"missing-publisher-date", "retrieval-time-only"}:
        source["published_at"] = None
        source["updated_at"] = None
        source["publisher_date_evidence"] = None
        claim["observed_at"] = source["retrieved_at"]
    elif attack == "uncited":
        claim["source_ids"] = []
    elif attack == "hallucinated":
        claim["source_ids"] = ["does-not-exist"]
    elif attack == "private-person":
        claim["subject_type"] = "private_person"
    with pytest.raises(ValueError):
        validate_dossier(dossier, cache, as_of=date(2026, 7, 20))


@pytest.mark.parametrize(
    "attack", ["canonical-duplicate", "identical-visible-content", "uniform-mislabel"],
)
def test_alias_mirror_and_uniform_kind_relabelling_fail_closed(
    tmp_path: Path, attack: str,
) -> None:
    dossier, cache = _authority_dossier(
        tmp_path,
        same_article=attack == "canonical-duplicate",
        same_visible_content=attack == "identical-visible-content",
    )
    if attack == "uniform-mislabel":
        for source, entry in zip(dossier["sources"], dossier["source_plan"], strict=True):  # type: ignore[arg-type]
            source["source_kind"] = "official_company"
            entry["source_type"] = "official_company"
    with pytest.raises(ValueError):
        validate_dossier(dossier, cache)


@pytest.mark.parametrize("attack", ("divergent-assertion", "missing-employer-prefix"))
def test_v2_authority_claim_text_must_exactly_reflect_its_excerpt(
    tmp_path: Path,
    attack: str,
) -> None:
    dossier, cache = _authority_dossier(tmp_path)
    health = next(
        claim for claim in dossier["claims"]  # type: ignore[union-attr]
        if claim["kind"] == "operational_health"
    )
    if attack == "divergent-assertion":
        health["text"] = "Example: entered insolvency proceedings and closed all operations."
    else:
        health["text"] = _paragraph(IntelligenceKind.OPERATIONAL_HEALTH)
    with pytest.raises(ValueError, match="exactly reflect"):
        validate_dossier(dossier, cache, as_of=date(2026, 7, 20))


def test_operator_gate_declares_zero_skip_authority_suite() -> None:
    declaration = (ROOT / "acceptance").read_text(encoding="utf-8")
    assert "scripts/run_acceptance_declaration.py" in declaration
    runner = (ROOT / "scripts/run_acceptance_declaration.py").read_text(encoding="utf-8")
    assert "JAA04_CORPUS" in runner and "JAA04_ACCESS_POLICY" in runner
    assert "return 3" in runner


def test_recertification_refuses_receipt_for_invalid_authority_corpus(tmp_path: Path) -> None:
    repository = tmp_path / "clone"
    copied = subprocess.run(
        ("git", "clone", "--no-local", "--single-branch", "--depth", "1",
         str(REPOSITORY_ROOT), str(repository)),
        text=True,
        capture_output=True,
    )
    assert copied.returncode == 0, copied.stderr
    clone = repository / "internal" / "jaa"
    result = subprocess.run(
        (sys.executable, "scripts/accept_jaa_04.py"),
        cwd=clone,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert not list((clone / "runtime_evidence/jaa04").glob("*.json"))
