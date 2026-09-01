from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from market_aligner.applications.canonical import ContractValidationError
from market_aligner.profiler.intent import (
    CandidateIntentDocument,
    serialize_candidate_intent,
)
from market_aligner.profiler.intent_store import CandidateIntentAuthorityStore
from market_aligner.profiler.schema import CandidateProfile, TrackProfile


PROFILE_ID = "prf_0123456789abcdef0123456789abcdef"
PROFILE_VERSION = "2026-08-29"
AUTHORITY_SOURCE = b"authority-source"


def _payload(*, authority_revision: int = 1, role_track_ids: list[str] | None = None):
    return {
        "authority_revision": authority_revision,
        "authority_source_sha256": hashlib.sha256(AUTHORITY_SOURCE).hexdigest(),
        "created_at": "2026-08-29T00:00:00Z",
        "geography_priority": [
            {"rank": 1, "region_code": "UK", "work_mode": "remote"},
            {"rank": 2, "region_code": "UK", "work_mode": "hybrid"},
            {"rank": 3, "region_code": "UK", "work_mode": "onsite"},
            {"rank": 4, "region_code": "RO", "work_mode": "remote"},
            {"rank": 5, "region_code": "EU", "work_mode": "remote"},
        ],
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "role_track_ids": role_track_ids or ["synthetic_track"],
        "schema_version": "market-aligner.candidate-intent.v1",
    }


def _document(*, authority_revision: int = 1, role_track_ids: list[str] | None = None):
    return CandidateIntentDocument.parse(
        serialize_candidate_intent(
            _payload(
                authority_revision=authority_revision,
                role_track_ids=role_track_ids,
            )
        )
    )


def test_candidate_intent_round_trip_is_exact_immutable_and_profile_bound() -> None:
    document = _document()
    assert CandidateIntentDocument.parse(document.exact_bytes) == document
    assert hashlib.sha256(document.exact_bytes).hexdigest() == document.candidate_intent_sha256
    with pytest.raises(TypeError):
        document.value["profile_version"] = "mutated"

    profile = CandidateProfile(
        PROFILE_ID,
        PROFILE_VERSION,
        {"synthetic_track": TrackProfile(8, 7, 0.8, 7)},
    )
    document.require_profile(profile)
    with pytest.raises(ContractValidationError, match="profile version"):
        document.require_profile(
            CandidateProfile(
                PROFILE_ID,
                "different",
                {"synthetic_track": TrackProfile(8, 7, 0.8, 7)},
            )
        )


def test_candidate_intent_refuses_schema_drift_and_noncanonical_bytes() -> None:
    wrong_geography = _payload()
    wrong_geography["geography_priority"][0]["work_mode"] = "hybrid"
    with pytest.raises(ContractValidationError, match="geography_priority"):
        serialize_candidate_intent(wrong_geography)
    with pytest.raises(ContractValidationError, match="sorted and unique"):
        serialize_candidate_intent(_payload(role_track_ids=["z", "a"]))
    with pytest.raises(ContractValidationError, match="NFC"):
        serialize_candidate_intent(_payload(role_track_ids=["cafe\u0301"]))

    exact = serialize_candidate_intent(_payload())
    duplicate = exact.replace(
        b'"authority_revision":1',
        b'"authority_revision":1,"authority_revision":1',
    )
    with pytest.raises(ContractValidationError, match="duplicate"):
        CandidateIntentDocument.parse(duplicate)
    with pytest.raises(ContractValidationError, match="digest differs"):
        CandidateIntentDocument(
            json.loads(exact),
            exact,
            "0" * 64,
        )


def test_authority_store_is_append_only_and_current_head_is_monotonic(tmp_path: Path) -> None:
    store = CandidateIntentAuthorityStore(tmp_path)
    revision_one = _document(authority_revision=1)
    revision_two = _document(authority_revision=2)
    start = Barrier(2)

    def register(document: CandidateIntentDocument):
        start.wait()
        return store.register(
            document,
            AUTHORITY_SOURCE,
            valid_until="2026-09-29T00:00:00Z",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            future.result()
            for future in (
                executor.submit(register, revision_two),
                executor.submit(register, revision_one),
            )
        )
    assert len(results) == 2
    root = tmp_path / "profiles" / PROFILE_ID / "intents"
    current = json.loads((root / "current.json").read_bytes())
    assert current["authority_revision"] == 2
    assert current["candidate_intent_sha256"] == revision_two.candidate_intent_sha256
    for document in (revision_one, revision_two):
        stored = store.load(PROFILE_ID, document.candidate_intent_sha256)
        assert stored.document == document
        assert stored.authority_source_exact_bytes == AUTHORITY_SOURCE
        assert (root / "revisions" / document.candidate_intent_sha256 / "intent.json").is_file()

    conflicting = _document(authority_revision=2, role_track_ids=["different_track"])
    with pytest.raises(ContractValidationError, match="already identifies different bytes"):
        store.register(
            conflicting,
            AUTHORITY_SOURCE,
            valid_until="2026-09-29T00:00:00Z",
        )


def test_authority_store_refuses_wrong_source_bytes(tmp_path: Path) -> None:
    store = CandidateIntentAuthorityStore(tmp_path)
    with pytest.raises(ContractValidationError, match="authority-source digest"):
        store.register(
            _document(),
            b"different-source",
            valid_until="2026-09-29T00:00:00Z",
        )
