from __future__ import annotations

import hashlib
import json

import pytest

from cv_generation.benchmark_learning import (
    CVBenchmarkEntry,
    CVBenchmarkError,
    CVBenchmarkFeatures,
    build_benchmark_manifest,
    evaluate_cv_benchmark,
    load_benchmark_manifest,
)
from cv_generation.editorial_composition import (
    CVSection,
    EditorialAtom,
    build_editorial_draft,
)


def _manifest():
    entry = CVBenchmarkEntry(
        exemplar_id="fixture-licensed-uk-1",
        source_sha256="1" * 64,
        source_uri_sha256="2" * 64,
        license_id="fixture-permission",
        provenance_sha256="3" * 64,
        outcome_kind="interview",
        outcome_sha256="4" * 64,
        features=CVBenchmarkFeatures(10_000, 10_000, 8_000, 8_000, 10_000, 10_000, 7_000),
    )
    return build_benchmark_manifest((entry,))


def _draft():
    return build_editorial_draft(
        candidate_name="Alex Example",
        candidate_city="London",
        sections=(
            CVSection("Professional Summary", (EditorialAtom("approved_claim", "Built a tested service for 20 users.", "claim-1"),)),
            CVSection("Core Capabilities", (EditorialAtom("approved_claim", "Designed workflow automation.", "claim-2"),)),
        ),
    )


def test_benchmark_is_diagnostic_only_and_cannot_change_candidate_prose() -> None:
    draft = _draft()
    before = draft.document()
    listing = "Build tested workflow automation services"
    receipt = evaluate_cv_benchmark(
        draft=draft,
        listing_text=listing,
        vacancy_sha256=hashlib.sha256(listing.encode()).hexdigest(),
        manifest=_manifest(),
    )
    assert draft.document() == before
    assert receipt.release_authority is False
    assert receipt.factual_authority == "candidate_evidence_only"
    assert all(code.startswith("improve_") for code in receipt.proposal_codes)


def test_manifest_loader_rejects_exemplar_prose_field(tmp_path) -> None:
    payload = _manifest().document()
    payload["entries"][0]["raw_text"] = "COPY THIS EXTERNAL CLAIM INTO THE CV"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CVBenchmarkError, match="unsupported fields"):
        load_benchmark_manifest(path)
