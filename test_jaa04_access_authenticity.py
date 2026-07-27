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


def _strict_corpus(
    tmp_path: Path,
) -> tuple[RawResponseCache, list[dict[str, object]], dict[str, PublicAccessPolicy]]:
    cache = RawResponseCache(tmp_path / "raw")
    dossiers: list[dict[str, object]] = []
    policies: dict[str, PublicAccessPolicy] | None = None
    for number in range(30):
        company = (
            "<p>Acme company operates a documented public business serving "
            f"regulated customers with cohort marker {number:02d}.</p>"
        )
        dossier = _portable(
            cache,
            company.encode(),
            {"company": (company, "official_company")},
        )
        row_policies = _access_bound(dossier, cache)
        if policies is None:
            policies = row_policies
        else:
            assert row_policies.keys() == policies.keys()
            policy_hash = next(iter(policies))
            assert (
                row_policies[policy_hash].attestations
                == policies[policy_hash].attestations
            )
        dossier["job_key"] = f"synthetic:{number:02d}"
        dossiers.append(dossier)
    assert policies is not None
    return cache, dossiers, policies


def _write_strict_corpus(
    path: Path,
    dossiers: list[dict[str, object]],
) -> None:
    path.write_text(json.dumps({
        "schema_version": "jaa04.frozen-dossiers.v5",
        "dossiers": dossiers,
        "dossiers_hash": content_hash(dossiers),
    }), encoding="utf-8")


def test_v4_dossier_replays_operator_policy_and_exact_robots_bytes(
    tmp_path: Path,
) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    dossier = _dossier(cache)
    policies = _access_bound(dossier, cache)
    validate_dossier(dossier, cache, access_policies=policies)


def test_strict_corpus_accepts_same_robots_bytes_from_two_valid_observations(
    tmp_path: Path,
) -> None:
    cache, dossiers, policies = _strict_corpus(tmp_path)
    receipt = dossiers[-1]["sources"][0]["access_receipt"]  # type: ignore[index]
    receipt["retrieved_at"] = "2026-06-30T23:59:59+00:00"
    path = tmp_path / "two-robots-observations.json"
    _write_strict_corpus(path, dossiers)

    loaded = load_frozen_dossiers(
        path,
        cache,
        strict_corpus=True,
        access_policies=policies,
    )

    assert len(loaded) == 30
    identities = {
        (
            row["sources"][0]["access_receipt"]["content_sha256"],
            row["sources"][0]["access_receipt"]["raw_response_ref"],
        )
        for row in loaded
    }
    assert len(identities) == 1
    assert {
        row["sources"][0]["access_receipt"]["retrieved_at"]
        for row in loaded
    } == {STAMP, "2026-06-30T23:59:59+00:00"}


def test_strict_corpus_accepts_same_employer_repeated_intelligence(
    tmp_path: Path,
) -> None:
    cache, dossiers, policies = _strict_corpus(tmp_path)
    repeated = deepcopy(dossiers[0])
    repeated["job_key"] = dossiers[1]["job_key"]
    dossiers[1] = repeated
    path = tmp_path / "same-employer-repeat.json"
    _write_strict_corpus(path, dossiers)

    loaded = load_frozen_dossiers(
        path,
        cache,
        strict_corpus=True,
        access_policies=policies,
    )

    assert len(loaded) == 30
    assert loaded[0]["claims"][0]["text"] == loaded[1]["claims"][0]["text"]


def test_strict_corpus_rejects_supported_claim_without_employer_prefix(
    tmp_path: Path,
) -> None:
    cache, dossiers, policies = _strict_corpus(tmp_path)
    dossiers[-1]["claims"][0]["text"] = (
        "Supported intelligence without the required employer prefix delimiter"
    )
    path = tmp_path / "missing-employer-prefix.json"
    _write_strict_corpus(path, dossiers)

    with pytest.raises(
        ValueError,
        match="supported assertion|employer-prefixed text",
    ):
        load_frozen_dossiers(
            path,
            cache,
            strict_corpus=True,
            access_policies=policies,
        )


@pytest.mark.parametrize("attack", ("different-content", "different-reference"))
def test_strict_corpus_rejects_inconsistent_robots_byte_identity(
    tmp_path: Path,
    attack: str,
) -> None:
    cache, dossiers, policies = _strict_corpus(tmp_path)
    receipt = dossiers[-1]["sources"][0]["access_receipt"]  # type: ignore[index]
    if attack == "different-content":
        digest, reference = cache.store(b"User-agent: *\nAllow: /\n# changed\n")
        receipt["content_sha256"] = digest
        receipt["raw_response_ref"] = reference
    else:
        body = cache.resolve(receipt["raw_response_ref"], receipt["content_sha256"])
        alternate = cache.root / "alternate" / "robots.txt"
        alternate.parent.mkdir(parents=True)
        alternate.write_bytes(body)
        receipt["raw_response_ref"] = str(alternate.relative_to(cache.root))
    path = tmp_path / f"{attack}.json"
    _write_strict_corpus(path, dossiers)

    with pytest.raises(
        ValueError,
        match="certified corpus has inconsistent robots bytes for one host",
    ):
        load_frozen_dossiers(
            path,
            cache,
            strict_corpus=True,
            access_policies=policies,
        )


def test_strict_corpus_still_rejects_invalid_individual_access_receipt(
    tmp_path: Path,
) -> None:
    cache, dossiers, policies = _strict_corpus(tmp_path)
    receipt = dossiers[-1]["sources"][0]["access_receipt"]  # type: ignore[index]
    receipt["retrieved_at"] = "2026-07-02T00:00:00+00:00"
    path = tmp_path / "invalid-individual-receipt.json"
    _write_strict_corpus(path, dossiers)

    with pytest.raises(ValueError, match="access receipt time is later"):
        load_frozen_dossiers(
            path,
            cache,
            strict_corpus=True,
            access_policies=policies,
        )


def test_dossier_citation_gate_still_rejects_requests_static(
    tmp_path: Path,
) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    dossier = _dossier(cache)
    policies = _access_bound(dossier, cache)
    source = dossier["sources"][0]  # type: ignore[index]
    source["retrieval_engine"] = "requests-static"
    with pytest.raises(ValueError, match="forbidden retrieval engine"):
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
    cache, dossiers, policies = _strict_corpus(tmp_path)
    company = (
        "<p>Contoso company operates a documented public business serving "
        "regulated customers with cohort marker 00.</p>"
    )
    substituted = _portable(
        cache,
        company.encode(),
        {"company": (company, "official_company")},
    )
    _access_bound(substituted, cache)
    substituted["claims"][0]["text"] = substituted["claims"][0]["text"].replace(
        "Acme:", "Contoso:", 1
    )
    substituted["job_key"] = dossiers[1]["job_key"]
    dossiers[1] = substituted
    path = tmp_path / "cross-employer-boilerplate.json"
    _write_strict_corpus(path, dossiers)

    with pytest.raises(ValueError, match="employer-normalized boilerplate"):
        load_frozen_dossiers(
            path,
            cache,
            strict_corpus=True,
            access_policies=policies,
        )
