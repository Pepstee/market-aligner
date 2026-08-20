"""Cross-product contract for the recovered Market Aligner -> JAA boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

import pytest


JAA_ROOT = Path(__file__).resolve().parents[1] / "internal" / "jaa"
SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE_ROOT))
sys.path.insert(0, str(JAA_ROOT))

from market_aligner.assessment.scoring import FitStatus, ScoreResult
from market_aligner.applications.producer import (
    HandoffProducerError,
    HandoffReference,
    write_protected_handoff_bundle,
)
from market_aligner.cli import main as market_aligner_main
from market_aligner.profiler.schema import CandidateProfile, TrackProfile
from market_aligner.profiler.store import ProfileStore
from market_aligner.service.api import MarketAlignerService

from career_automation.current_time import configured_hmac_current_time_witness
from career_automation.handoff_admission import (
    ADMISSION_KIND_V1,
    HandoffAdmissionError,
    HandoffAdmissionStore,
    ProtectedLocalOutbox,
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
    admitted_candidate_sha256 = store.reference_sha256(
        admission.application_id, "candidate_intent.authority_source"
    )
    expected_candidate_sha256 = next(
        row["metadata"]["object_sha256"]
        for row in document["reference_bundle"]["value"]["entries"]
        if row["metadata"]["reference_key"]
        == "candidate_intent.authority_source"
    )
    assert admitted_candidate_sha256 == expected_candidate_sha256
    with pytest.raises(HandoffAdmissionError, match="unsupported"):
        store.reference_sha256(admission.application_id, "candidate.claims")


def test_protected_outbox_bundle_authenticates_and_replays_idempotently(tmp_path) -> None:
    fixture_bytes = files("career_automation").joinpath(
        "fixtures/market-aligner-v1-vectors.json"
    ).read_bytes()
    document = json.loads(fixture_bytes)
    handoff_bytes = base64.b64decode(
        document["handoff"]["canonical_base64"], validate=True
    )
    handoff = parse_handoff(handoff_bytes)
    references = {}
    for row in document["reference_bundle"]["value"]["entries"]:
        metadata = row["metadata"]
        references[metadata["reference_key"]] = HandoffReference(
            exact_bytes=base64.b64decode(row["object_base64"], validate=True),
            type_id=metadata["type_id"],
            schema_version=metadata["schema_version"],
            subject=metadata["subject"],
            issued_at=metadata["issued_at"],
            valid_until=metadata["valid_until"],
            issuer_id=metadata["issuer_id"],
        )
    output_root = tmp_path / "external-data-home"
    first = write_protected_handoff_bundle(
        output_root,
        handoff,
        references=references,
        environment="synthetic",
        trust_root_id="synthetic-market-root",
        issued_at="2026-08-10T10:04:00Z",
        source_job_key="workable:synthetic:42",
    )
    second = write_protected_handoff_bundle(
        output_root,
        handoff,
        references=references,
        environment="synthetic",
        trust_root_id="synthetic-market-root",
        issued_at="2026-08-10T10:04:00Z",
        source_job_key="workable:synthetic:42",
    )
    assert second == first
    adapter = ProtectedLocalOutbox(
        first.path,
        repository_root=Path(__file__).resolve().parents[1],
        expected_source_record_sha256=first.source_record_sha256,
        allowed_producer_commits=frozenset({handoff.payload["producer"]["commit_sha"]}),
    )
    witness = configured_hmac_current_time_witness(
        authentication_key=b"protected-outbox-time-key-32bytes",
        environment="synthetic",
        trust_root_id="synthetic-market-time-root",
        witness_identity_sha256=hashlib.sha256(b"protected-outbox-time").hexdigest(),
        clock=lambda: ADMISSION_TIME,
        nonce_source=lambda: b"protected-outbox-time-nonce",
    )
    store = HandoffAdmissionStore(
        tmp_path / "protected-outbox.sqlite3",
        context_authenticator=adapter,
        resolver=adapter,
        current_time_witness=witness,
    )
    admitted = store.admit_authenticated(adapter.handoff_bytes, adapter.context_bytes)
    replay = store.admit_authenticated(adapter.handoff_bytes, adapter.context_bytes)
    assert admitted.created is True
    assert replay.created is False
    assert admitted.application_id == handoff.application_id

    os.chmod(first.path / "context.json", 0o644)
    with pytest.raises(HandoffAdmissionError, match="outbox file is not private"):
        ProtectedLocalOutbox(
            first.path,
            repository_root=Path(__file__).resolve().parents[1],
            expected_source_record_sha256=first.source_record_sha256,
            allowed_producer_commits=frozenset({handoff.payload["producer"]["commit_sha"]}),
        ).context_bytes


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


def test_persisted_gated_assessment_emits_exact_handoff_and_enters_jaa(
    tmp_path, capsys
) -> None:
    fixture_bytes = files("career_automation").joinpath(
        "fixtures/market-aligner-v1-vectors.json"
    ).read_bytes()
    document = json.loads(fixture_bytes)
    expected_bytes = base64.b64decode(
        document["handoff"]["canonical_base64"], validate=True
    )
    expected = json.loads(expected_bytes)["payload"]
    assessment = expected["assessment"]

    data_home = tmp_path / "market-data"
    ProfileStore(data_home).save(
        CandidateProfile(
            profile_id=expected["profile_id"],
            version=expected["profile_version"],
            tracks={
                "synthetic_track": TrackProfile(
                    interest=8,
                    demonstrated_skill=8,
                    confidence=0.95,
                    market_readiness=8,
                    rationale="Synthetic cross-product contract fixture.",
                )
            },
        ),
        [],
    )
    service = MarketAlignerService(data_home)
    service.assessments.upsert_score(
        ScoreResult(
            profile_id=expected["profile_id"],
            job_key=expected["job_key"],
            track="synthetic_track",
            fit=assessment["fit"],
            opportunity=assessment["opportunity"],
            final=assessment["final"] * 100.0,
            fit_status=FitStatus.UNCALIBRATED,
            parameters_hash=assessment["scoring_parameters_sha256"],
            fit_subscores=assessment["fit_components"],
            opportunity_subscores=assessment["opportunity_components"],
        ),
        url=expected["vacancy"]["provenance"]["canonical_url"],
        title=expected["vacancy"]["role_title"],
        company=expected["vacancy"]["company_name"],
        extraction_confidence=assessment["extraction_confidence"],
    )
    manifest = {
        "assessment_receipt_sha256": assessment["assessment_receipt_sha256"],
        "candidate_intent_sha256": expected["candidate_intent_sha256"],
        "created_at": expected["created_at"],
        "eligibility": expected["eligibility"],
        "employer_dossier_sha256": expected["employer_dossier_sha256"],
        "evidence_ledger_sha256": expected["evidence_ledger_sha256"],
        "producer_commit_sha": expected["producer"]["commit_sha"],
        "selection": expected["selection"],
        "vacancy": expected["vacancy"],
    }
    with pytest.raises(HandoffProducerError, match="opportunity-gate pass"):
        service.handoff(expected["profile_id"], expected["job_key"], manifest)

    service.assessments.apply_opportunity_gate(
        profile_id=expected["profile_id"],
        job_key=expected["job_key"],
        passed=True,
        reason="legacy_manual_gate_is_insufficient",
        policy_hash=expected["selection"]["selection_policy_sha256"],
        priority=1,
    )
    with pytest.raises(HandoffProducerError, match="canonical processing"):
        service.handoff(expected["profile_id"], expected["job_key"], manifest)

    selection_entry = next(
        row
        for row in document["reference_bundle"]["value"]["entries"]
        if row["metadata"]["reference_key"] == "selection.policy"
    )
    selection_policy = json.loads(
        base64.b64decode(selection_entry["object_base64"], validate=True)
    )
    promotion_binding = {
        "evidence_authority_sha256": "1" * 64,
        "processing_config_sha256": "2" * 64,
        "processing_receipt_sha256": "3" * 64,
        "processing_result_sha256": "4" * 64,
        "source_content_sha256": "5" * 64,
        "track": "synthetic_track",
    }
    promotion_body = {
        "binding": promotion_binding,
        "binding_sha256": hashlib.sha256(
            canonical_json_bytes(promotion_binding)
        ).hexdigest(),
        "decision": "pass",
        "evidence_authority_sha256": "1" * 64,
        "job_key": expected["job_key"],
        "policy": selection_policy,
        "policy_sha256": expected["selection"]["selection_policy_sha256"],
        "processing_receipt_bytes_sha256": "6" * 64,
        "profile_id": expected["profile_id"],
        "schema_version": "market-aligner.assessment-promotion-receipt.v1",
        "score_payload_hash": service.assessments.assessment(
            expected["profile_id"], expected["job_key"]
        )["score_payload_hash"],
    }
    promotion_sha = hashlib.sha256(
        canonical_json_bytes(promotion_body)
    ).hexdigest()
    service.assessments.promote_processing_gate(
        profile_id=expected["profile_id"],
        job_key=expected["job_key"],
        score={
            "fit": assessment["fit"],
            "opportunity": assessment["opportunity"],
            "final": assessment["final"] * 100.0,
            "fit_status": assessment["fit_status"],
        },
        policy_hash=expected["selection"]["selection_policy_sha256"],
        processing_receipt_sha256="3" * 64,
        processing_result_sha256="4" * 64,
        source_content_sha256="5" * 64,
        authority_sha256="1" * 64,
        processing_config_sha256="2" * 64,
        track="synthetic_track",
        receipt_bytes=canonical_json_bytes(
            {**promotion_body, "receipt_sha256": promotion_sha}
        ),
        receipt_sha256=promotion_sha,
    )
    substituted_manifest = json.loads(json.dumps(manifest))
    substituted_manifest["selection"]["selection_policy_sha256"] = "f" * 64
    with pytest.raises(HandoffProducerError, match="persisted gate policy"):
        service.handoff(
            expected["profile_id"], expected["job_key"], substituted_manifest
        )

    manifest_path = tmp_path / "handoff-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output_path = tmp_path / "handoff.json"

    assert (
        market_aligner_main(
            [
                "handoff",
                "--profile-id",
                expected["profile_id"],
                "--job-key",
                expected["job_key"],
                "--manifest",
                str(manifest_path),
                "--output",
                str(output_path),
                "--data-home",
                str(data_home),
            ]
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out)
    assert output_path.read_bytes() == expected_bytes
    assert receipt["root_sha256"] == MARKET_HANDOFF_ROOT
    assert receipt["application_id"] == MARKET_APPLICATION_ID

    context = canonical_json_bytes(
        {
            "environment": "synthetic",
            "handoff_root_sha256": receipt["root_sha256"],
            "issued_at": "2026-08-10T10:04:00Z",
            "producer_commit_sha": expected["producer"]["commit_sha"],
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
    admission = HandoffAdmissionStore(
        tmp_path / "jaa-admission.sqlite3",
        context_authenticator=_MarketVectorContextAuthenticator(),
        resolver=_MarketVectorResolver(document),
        current_time_witness=witness,
    ).admit_authenticated(output_path.read_bytes(), context)
    assert admission.application_id == MARKET_APPLICATION_ID
    assert admission.job_key == MARKET_JOB_KEY
    assert admission.admission_kind == ADMISSION_KIND_V1
