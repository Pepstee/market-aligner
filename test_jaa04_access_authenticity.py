"""Offline controls for the JAA-04 operator-authority certification seam."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

from career_automation.employer_research import (
    RawResponseCache,
    content_hash,
    load_frozen_dossiers,
    validate_dossier,
)
from career_automation.public_access import (
    PublicAccessPolicy,
    RobotsReceipt,
    TermsAttestation,
    USER_AGENT,
)
from test_jaa04_portable_authority_contract import _portable


STAMP = "2026-07-01T00:00:00+00:00"


def _access_bound(
    dossier: dict[str, object],
    cache: RawResponseCache,
) -> dict[str, PublicAccessPolicy]:
    attestation = TermsAttestation(
        host="acme.example.test",
        terms_url="https://acme.example.test/terms",
        determination="public_read_only_research_permitted",
        reviewed_at="2026-06-30T00:00:00+00:00",
        reviewed_by="Offline Test Operator",
        reviewer_type="human_operator",
        notes="Synthetic offline fixture only; not production authority.",
    )
    policy_hash = hashlib.sha256(b"portable-test-policy").hexdigest()
    policy = PublicAccessPolicy(
        {attestation.host: attestation},
        policy_sha256=policy_hash,
        now=datetime(2026, 7, 1, tzinfo=timezone.utc),
    )
    robots = b"User-agent: *\nAllow: /\n"
    digest, reference = cache.store(robots)
    source = dossier["sources"][0]  # type: ignore[index]
    source["retrieval_engine"] = "scrapling-static"
    source["access_receipt"] = asdict(RobotsReceipt(
        host=attestation.host,
        robots_url="https://acme.example.test/robots.txt",
        final_url="https://acme.example.test/robots.txt",
        status_code=200,
        content_sha256=digest,
        raw_response_ref=reference,
        redirect_history=[],
        retrieved_at=STAMP,
        user_agent=USER_AGENT,
        requested_url="https://acme.example.test/evidence",
        allowed=True,
        crawl_delay_seconds=10.0,
        terms_policy_sha256=policy_hash,
        terms_attestation=asdict(attestation),
    ))
    dossier["schema_version"] = "jaa04.dossier.v4"
    return {policy_hash: policy}


def _dossier(cache: RawResponseCache) -> dict[str, object]:
    company = (
        "<p>Acme company operates a public business that serves "
        "regulated customers worldwide.</p>"
    )
    return _portable(
        cache,
        company.encode(),
        {"company": (company, "official_company")},
    )


def test_v4_dossier_replays_operator_policy_and_exact_robots_bytes(
    tmp_path: Path,
) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    dossier = _dossier(cache)
    policies = _access_bound(dossier, cache)
    validate_dossier(dossier, cache, access_policies=policies)


@pytest.mark.parametrize("attack", ("missing-receipt", "fake-engine", "policy-substitution"))
def test_v4_dossier_rejects_self_declared_acquisition_authority(
    tmp_path: Path,
    attack: str,
) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    dossier = _dossier(cache)
    policies = _access_bound(dossier, cache)
    source = dossier["sources"][0]  # type: ignore[index]
    if attack == "missing-receipt":
        source["access_receipt"] = None
    elif attack == "fake-engine":
        source["retrieval_engine"] = "deterministic-retriever"
    else:
        source["access_receipt"]["terms_policy_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        validate_dossier(dossier, cache, access_policies=policies)


@pytest.mark.parametrize("attack", ("legacy-dossiers", "missing-operator-policy"))
def test_strict_corpus_refuses_legacy_or_self_declared_authority(
    tmp_path: Path,
    attack: str,
) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    template = _dossier(cache)
    policies = _access_bound(template, cache)
    dossiers = []
    for number in range(30):
        dossier = deepcopy(template)
        dossier["job_key"] = f"synthetic:{number:02d}"
        dossiers.append(dossier)
    if attack == "legacy-dossiers":
        for dossier in dossiers:
            dossier["schema_version"] = "jaa04.dossier.v3"
    envelope = {
        "schema_version": "jaa04.frozen-dossiers.v5",
        "dossiers": dossiers,
        "dossiers_hash": content_hash(dossiers),
    }
    path = tmp_path / "synthetic-frozen-dossiers.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="access-policy|access receipts"):
        load_frozen_dossiers(
            path,
            cache,
            strict_corpus=True,
            access_policies=None if attack == "missing-operator-policy" else policies,
        )


def test_strict_corpus_rejects_cross_employer_normalized_boilerplate(
    tmp_path: Path,
) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    template = _dossier(cache)
    policies = _access_bound(template, cache)
    dossiers = []
    for number in range(30):
        dossier = deepcopy(template)
        dossier["job_key"] = f"synthetic:{number:02d}"
        dossiers.append(dossier)
    envelope = {
        "schema_version": "jaa04.frozen-dossiers.v5",
        "dossiers": dossiers,
        "dossiers_hash": content_hash(dossiers),
    }
    path = tmp_path / "synthetic-boilerplate.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="employer-normalized boilerplate"):
        load_frozen_dossiers(
            path,
            cache,
            strict_corpus=True,
            access_policies=policies,
        )
