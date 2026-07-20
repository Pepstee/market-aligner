"""Preserve publisher-date semantics in the three authentic JAA-04 ATS sidecars."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from career_automation.employer_research import (
    ATS_AUTHORITY_CANARIES,
    Citation,
    PortableAuthorityRetriever,
    extract_publisher_timestamps,
)


SIDECARS = Path(__file__).parent / "career_automation/fixtures/jaa04_authority_canaries"


@pytest.mark.parametrize("record", ATS_AUTHORITY_CANARIES, ids=lambda row: row.job_key)
def test_authentic_sidecar_preserves_exact_published_and_updated_field_semantics(record) -> None:
    artifact = json.loads(
        (SIDECARS / f"{record.job_key.split(':', 1)[0]}.json").read_text(encoding="utf-8")
    )
    assert len(artifact["captures"]) == 1
    row = dict(artifact["captures"][0])
    raw = base64.b64decode(row.pop("raw_response_base64"), validate=True)
    row.pop("raw_response_encoding", None)
    row.pop("sidecar_raw_response_ref", None)
    row["raw_response_ref"] = "embedded:raw_response_base64"
    citation = Citation(**row)

    published, updated, evidence = extract_publisher_timestamps(raw)
    assert (citation.published_at, citation.updated_at) == (published, updated)
    assert citation.publisher_date_evidence == evidence
    PortableAuthorityRetriever._validate_canary_capture(record, citation, raw)
