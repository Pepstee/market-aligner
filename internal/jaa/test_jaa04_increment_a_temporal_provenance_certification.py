"""Independent JAA-04 Increment A temporal-provenance certification probes."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import career_automation.employer_research as research
from career_automation.employer_research import (
    ATS_AUTHORITY_CANARIES,
    Citation,
    PortableAuthorityRetriever,
    RawResponseCache,
    ScraplingPublicRetriever,
)
from career_automation.public_access import RobotsReceipt


ROOT = Path(__file__).resolve().parent
GREENHOUSE = next(row for row in ATS_AUTHORITY_CANARIES if row.job_key.startswith("greenhouse:"))
UPDATED = "2026-07-19T12:34:56+00:00"
FORGED = "2025-07-19T12:34:56+00:00"


def _greenhouse_body(updated: str = UPDATED) -> bytes:
    """A genuine-shaped Greenhouse response: no published field, only update time."""
    return json.dumps({
        "id": 5030244008,
        "title": GREENHOUSE.title,
        "updated_at": updated,
        "content": f"<p>{GREENHOUSE.company} — {GREENHOUSE.title}</p>",
    }, separators=(",", ":")).encode()


def _citation(body: bytes, cache: RawResponseCache) -> Citation:
    digest, reference = cache.store(body)
    return Citation(
        id="independent:greenhouse",
        url=GREENHOUSE.authority_url,
        captured_at="2026-07-20T00:00:00+00:00",
        retrieved_at="2026-07-20T00:00:00+00:00",
        content_sha256=digest,
        raw_response_ref=reference,
        status_code=200,
        requested_url=GREENHOUSE.authority_url,
        published_at=None,
        updated_at=UPDATED,
        source_kind="official_vacancy",
        canonical_publisher="api.greenhouse.io",
        canonical_article=GREENHOUSE.authority_url,
        publisher_date_evidence='"updated_at":"2026-07-19T12:34:56+00:00"',
        retrieval_engine="scrapling-static",
    )


def test_greenhouse_updated_only_response_retains_null_published_at_through_retrieval_and_citation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retrieval must not promote updated_at into a fictional published_at."""
    body = _greenhouse_body()
    cache = RawResponseCache(tmp_path / "raw")
    receipt = RobotsReceipt(
        "api.greenhouse.io", "https://api.greenhouse.io/robots.txt",
        "https://api.greenhouse.io/robots.txt", 404, hashlib.sha256(b"").hexdigest(),
        "sha256/empty", [], "2026-07-20T00:00:00+00:00",
        "JAA-Public-Research", GREENHOUSE.authority_url, True, 10.0,
        "policy-hash", {"reviewer_type": "human_operator"},
    )
    access = SimpleNamespace(before_request=lambda _: receipt)
    retriever = ScraplingPublicRetriever(cache, access_controller=access)
    retriever.client = SimpleNamespace(fetch=lambda *_args, **_kwargs: {
        "url": GREENHOUSE.authority_url, "status": 200,
        "body_base64": base64.b64encode(body).decode(),
        "body_bytes": len(body), "history": [], "text": body.decode(),
    })
    monkeypatch.setattr(research, "_public_url", lambda _: None)

    citation = retriever.retrieve("greenhouse-updated-only", GREENHOUSE.authority_url)

    assert citation.published_at is None
    assert citation.updated_at == UPDATED
    assert citation.publisher_date_evidence == '"updated_at":"2026-07-19T12:34:56+00:00"'
    assert cache.resolve(citation.raw_response_ref, citation.content_sha256) == body
    PortableAuthorityRetriever._validate_canary_capture(GREENHOUSE, citation, cache)


@pytest.mark.parametrize("attack", ("field-substitution", "forged-body-year", "sidecar-body-disagreement"))
def test_greenhouse_temporal_metadata_attacks_fail_closed(tmp_path: Path, attack: str) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    body = _greenhouse_body()
    citation = _citation(body, cache)
    if attack == "field-substitution":
        citation = replace(citation, published_at=UPDATED, updated_at=None)
    elif attack == "forged-body-year":
        forged_body = _greenhouse_body(FORGED)
        citation = replace(citation, content_sha256=hashlib.sha256(forged_body).hexdigest())
        body = forged_body
    else:
        citation = replace(citation, publisher_date_evidence='"updated_at":"2025-07-19T12:34:56+00:00"')

    with pytest.raises(ValueError):
        PortableAuthorityRetriever._validate_canary_capture(GREENHOUSE, citation, body)


def test_greenhouse_response_byte_tampering_fails_before_temporal_validation(tmp_path: Path) -> None:
    cache = RawResponseCache(tmp_path / "raw")
    citation = _citation(_greenhouse_body(), cache)
    target = cache.root / citation.raw_response_ref
    target.chmod(0o644)
    target.write_bytes(_greenhouse_body(FORGED))

    with pytest.raises(ValueError, match="hash mismatch"):
        PortableAuthorityRetriever._validate_canary_capture(GREENHOUSE, citation, cache)


def test_real_passing_certification_runtime_emits_content_addressed_revision_bound_receipt(
    tmp_path: Path,
) -> None:
    """Only the public runtime command is allowed to mint the certification receipt."""
    clone = tmp_path / "clean-certification-source"
    copied = subprocess.run(
        ("git", "clone", "--no-local", str(ROOT), str(clone)),
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert copied.returncode == 0, copied.stderr
    destination = tmp_path / "receipt"
    completed = subprocess.run(
        (sys.executable, "scripts/certify_jaa04_increment_a.py", "--receipt", str(destination)),
        cwd=clone, text=True, capture_output=True, check=False, timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    receipts = list(destination.glob("sha256-*.json"))
    assert len(receipts) == 1
    payload = receipts[0].read_bytes()
    assert receipts[0].stem == f"sha256-{hashlib.sha256(payload).hexdigest()}"
    receipt = json.loads(payload)
    assert receipt["status"] == "SUCCESS"
    assert receipt["source_revision"]
    assert receipt["source_content_revision"]
    assert "JAA-04 Increment A certification: PASS" in completed.stdout
