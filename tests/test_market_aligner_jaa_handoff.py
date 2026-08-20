"""Cross-product contract for the recovered Market Aligner -> JAA boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

import pytest


JAA_ROOT = Path(__file__).resolve().parents[1] / "internal" / "jaa"
sys.path.insert(0, str(JAA_ROOT))

from career_automation.current_time import configured_hmac_current_time_witness
from career_automation.handoff_admission import (
    ADMISSION_KIND_V1,
    HandoffAdmissionStore,
    ResolvedReference,
)
from career_automation.market_aligner_handoff import (
    COMPATIBILITY_PROFILE,
    STRICT_EMISSION_PROFILE,
    HandoffContractError,
    canonical_json_bytes,
    parse_handoff,
)


MARKET_VECTOR_SHA256 = (
    "421d39504c4828c928389d5c30c2147fb7c01249b299972a11e204e956350160"
)
MARKET_HANDOFF_ROOT = (
    "f6303777b7ea5c9962904e5c6adc6cdffb69a257e62cb0cc26126aad2ca0212f"
)
MARKET_APPLICATION_ID = (
    "app_571f6fbc56b70ab27d526e720a5159ad3d0587fdf44da9323f07fddaf4dfa819"
)
MARKET_JOB_KEY = (
    "job_14877e94d4ed2635f6ef6b6d834a62636f1712a7f7011701f9655bdf1d6bfe09"
)
ADMISSION_TIME = datetime(2026, 8, 10, 10, 5, tzinfo=timezone.utc)


class _MarketVectorContextAuthenticator:
    authenticator_identity_sha256 = hashlib.sha256(
        b"jaa.market-vector-context-authenticator.v1"
    ).hexdigest()

    def authenticate(self, *, context_bytes: bytes, handoff_bytes: bytes, **_) -> None:
        context = json.loads(context_bytes)
        assert context["handoff_root_sha256"] == hashlib.sha256(handoff_bytes).hexdigest()
        assert context["trust_root_id"] == "synthetic-market-root"


class _MarketVectorResolver:
    resolver_identity_sha256 = hashlib.sha256(
        b"jaa.market-vector-reference-resolver.v1"
    ).hexdigest()

    def __init__(self, document: dict[str, object]) -> None:
        entries = document["reference_bundle"]["value"]["entries"]
        self._entries = {
            row["metadata"]["reference_key"]: (
                base64.b64decode(row["object_base64"], validate=True),
                canonical_json_bytes(row["metadata"]),
                row,
            )
            for row in entries
        }

    def resolve(self, request) -> ResolvedReference:
        exact, metadata, _ = self._entries[request.spec.reference_key]
        assert hashlib.sha256(exact).hexdigest() == request.sha256
        return ResolvedReference(exact, metadata)

    def authenticate(self, *, metadata_bytes: bytes, exact_bytes: bytes, **_) -> None:
        metadata = json.loads(metadata_bytes)
        expected_exact, expected_metadata, row = self._entries[
            metadata["reference_key"]
        ]
        assert row["authenticated"] is True and row["current"] is True
        assert exact_bytes == expected_exact and metadata_bytes == expected_metadata


def test_recovered_market_vector_is_parsed_and_atomically_admitted(tmp_path) -> None:
    fixture_bytes = files("career_automation").joinpath(
        "fixtures/market-aligner-v1-vectors.json"
    ).read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == MARKET_VECTOR_SHA256
    document = json.loads(fixture_bytes)
    handoff_bytes = base64.b64decode(
        document["handoff"]["canonical_base64"], validate=True
    )

    parsed = parse_handoff(handoff_bytes)
    assert parsed.root_sha256 == document["handoff"]["root_sha256"] == MARKET_HANDOFF_ROOT
    assert parsed.application_id == MARKET_APPLICATION_ID
    assert parsed.payload["job_key"] == MARKET_JOB_KEY
    assert parsed.emission_profile == STRICT_EMISSION_PROFILE

    context = canonical_json_bytes(
        {
            "environment": "synthetic",
            "handoff_root_sha256": MARKET_HANDOFF_ROOT,
            "issued_at": "2026-08-10T10:04:00Z",
            "producer_commit_sha": parsed.payload["producer"]["commit_sha"],
            "producer_product": "market-aligner",
            "source_record_sha256": MARKET_VECTOR_SHA256,
            "trust_mode": "authenticated_attestation",
            "trust_proof_sha256": hashlib.sha256(
                b"jaa-market-vector-context-proof-v1"
            ).hexdigest(),
            "trust_root_id": "synthetic-market-root",
        }
    )
    witness = configured_hmac_current_time_witness(
        authentication_key=b"market-vector-time-key-32-bytes!",
        environment="synthetic",
        trust_root_id="synthetic-market-time-root",
        witness_identity_sha256=hashlib.sha256(
            b"synthetic-market-time-witness"
        ).hexdigest(),
        clock=lambda: ADMISSION_TIME,
        nonce_source=lambda: b"market-vector-fixed-time-nonce",
    )
    store = HandoffAdmissionStore(
        tmp_path / "exact-market-vector.sqlite3",
        context_authenticator=_MarketVectorContextAuthenticator(),
        resolver=_MarketVectorResolver(document),
        current_time_witness=witness,
    )

    admission = store.admit_authenticated(handoff_bytes, context)
    assert admission.application_id == MARKET_APPLICATION_ID
    assert admission.job_key == MARKET_JOB_KEY
    assert admission.handoff_root_sha256 == MARKET_HANDOFF_ROOT
    assert admission.admission_kind == ADMISSION_KIND_V1

    replay = store.admit_authenticated(handoff_bytes, context)
    assert replay.application_id == admission.application_id
    assert replay.verification_receipt_sha256 == admission.verification_receipt_sha256
    assert admission.created is True
    assert replay.created is False


def test_recovered_canonical_vectors_preserve_declared_dispositions() -> None:
    fixture_bytes = files("career_automation").joinpath(
        "fixtures/market-aligner-v1-vectors.json"
    ).read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == MARKET_VECTOR_SHA256
    document = json.loads(fixture_bytes)

    for vector in document["canonical_negative_vectors"]:
        candidate = base64.b64decode(vector["canonical_base64"], validate=True)
        if vector["expected"] == "reject":
            with pytest.raises(HandoffContractError):
                parse_handoff(candidate)
            continue
        assert vector["expected"] == "admit_base_release_blocked"
        parsed = parse_handoff(candidate)
        assert parsed.emission_profile == COMPATIBILITY_PROFILE, vector["id"]
