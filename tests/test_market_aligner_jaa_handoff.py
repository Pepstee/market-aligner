"""Cross-product contract for the recovered Market Aligner -> JAA boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

import pytest

JAA_ROOT = Path(__file__).resolve().parents[1] / "internal" / "jaa"
SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SOURCE_ROOT))
sys.path.insert(0, str(JAA_ROOT))

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
from career_automation.production_handoff_admission_runner import (
    _promotion_receipt_semantic_identity,
)

from market_aligner.applications.handoff import encode_handoff_v1
from market_aligner.applications.producer import (
    HandoffProducerError,
    HandoffReference,
    write_protected_handoff_bundle,
)
from market_aligner.applications.production_handoff import (
    _deterministic_handoff_issuance,
)
from market_aligner.assessment.scoring import FitStatus, ScoreResult
from market_aligner.cli import main as market_aligner_main
from market_aligner.profiler.schema import CandidateProfile, TrackProfile
from market_aligner.profiler.store import ProfileStore
from market_aligner.research.models import (
    ClaimSupport,
    ResearchClaim,
    ResearchDossier,
    SourceCitation,
)
from market_aligner.service.api import MarketAlignerService

MARKET_VECTOR_SHA256 = (
    "421d39504c4828c928389d5c30c2147fb7c01249b299972a11e204e956350160"
)
MARKET_HANDOFF_ROOT = "f6303777b7ea5c9962904e5c6adc6cdffb69a257e62cb0cc26126aad2ca0212f"
MARKET_APPLICATION_ID = (
    "app_571f6fbc56b70ab27d526e720a5159ad3d0587fdf44da9323f07fddaf4dfa819"
)
MARKET_JOB_KEY = "job_14877e94d4ed2635f6ef6b6d834a62636f1712a7f7011701f9655bdf1d6bfe09"
ADMISSION_TIME = datetime(2026, 8, 10, 10, 5, tzinfo=timezone.utc)


def _promotion_bundle(tmp_path: Path):
    fixture_bytes = (
        files("career_automation")
        .joinpath("fixtures/market-aligner-v1-vectors.json")
        .read_bytes()
    )
    document = json.loads(fixture_bytes)
    original = parse_handoff(
        base64.b64decode(document["handoff"]["canonical_base64"], validate=True)
    )
    source_job_key = "workable:synthetic:promotion"
    body = {
        "binding": {"source_content_sha256": "1" * 64},
        "binding_sha256": hashlib.sha256(
            canonical_json_bytes({"source_content_sha256": "1" * 64})
        ).hexdigest(),
        "decision": "pass",
        "job_key": source_job_key,
        "policy": {"schema_version": "market-aligner.selection-policy.v1"},
        "policy_sha256": hashlib.sha256(
            canonical_json_bytes(
                {"schema_version": "market-aligner.selection-policy.v1"}
            )
        ).hexdigest(),
        "profile_id": original.payload["profile_id"],
        "schema_version": "market-aligner.assessment-promotion-receipt.v1",
        "score_payload_hash": "2" * 64,
    }
    semantic_sha256 = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    promotion_bytes = canonical_json_bytes({**body, "receipt_sha256": semantic_sha256})
    promotion_object_sha256 = hashlib.sha256(promotion_bytes).hexdigest()
    payload = json.loads(json.dumps(original.payload))
    payload["assessment"]["assessment_receipt_sha256"] = promotion_object_sha256
    handoff = encode_handoff_v1(payload)
    references = {
        "assessment.receipt": HandoffReference(
            exact_bytes=promotion_bytes,
            type_id="assessment_receipt",
            schema_version="market-aligner.assessment-promotion-receipt.v1",
            subject={
                "application_id": handoff.application_id,
                "job_key": handoff.payload["job_key"],
            },
            issued_at="2026-08-10T10:04:00Z",
            valid_until=None,
        )
    }
    arguments = {
        "references": references,
        "environment": "synthetic",
        "trust_root_id": "synthetic-market-root",
        "issued_at": "2026-08-10T10:04:00Z",
        "source_job_key": source_job_key,
    }
    written = write_protected_handoff_bundle(
        tmp_path / "external-data-home", handoff, **arguments
    )
    return written, handoff, arguments, semantic_sha256


class _MarketVectorContextAuthenticator:
    authenticator_identity_sha256 = hashlib.sha256(
        b"jaa.market-vector-context-authenticator.v1"
    ).hexdigest()

    def authenticate(self, *, context_bytes: bytes, handoff_bytes: bytes, **_) -> None:
        context = json.loads(context_bytes)
        assert (
            context["handoff_root_sha256"] == hashlib.sha256(handoff_bytes).hexdigest()
        )
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
    fixture_bytes = (
        files("career_automation")
        .joinpath("fixtures/market-aligner-v1-vectors.json")
        .read_bytes()
    )
    assert hashlib.sha256(fixture_bytes).hexdigest() == MARKET_VECTOR_SHA256
    document = json.loads(fixture_bytes)
    handoff_bytes = base64.b64decode(
        document["handoff"]["canonical_base64"], validate=True
    )

    parsed = parse_handoff(handoff_bytes)
    assert (
        parsed.root_sha256 == document["handoff"]["root_sha256"] == MARKET_HANDOFF_ROOT
    )
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
        if row["metadata"]["reference_key"] == "candidate_intent.authority_source"
    )
    assert admitted_candidate_sha256 == expected_candidate_sha256
    verified = store.for_boundary_at_for_test(
        admission.application_id,
        "strategy",
        evaluated_at=ADMISSION_TIME,
    )
    assert verified.candidate_authority_sha256 == expected_candidate_sha256
    with pytest.raises(HandoffAdmissionError, match="unsupported"):
        store.reference_sha256(admission.application_id, "candidate.claims")


def test_protected_outbox_bundle_authenticates_and_replays_idempotently(
    tmp_path,
) -> None:
    fixture_bytes = (
        files("career_automation")
        .joinpath("fixtures/market-aligner-v1-vectors.json")
        .read_bytes()
    )
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
    for directory in (
        output_root,
        output_root / "bundles",
        first.path,
        first.path / "objects",
        first.path / "metadata",
    ):
        assert directory.stat().st_mode & 0o777 == 0o700
    for file_path in (
        first.path / "context.json",
        first.path / "handoff.json",
        first.path / "manifest.json",
        first.path / "source-record.json",
        *(first.path / "objects").iterdir(),
        *(first.path / "metadata").iterdir(),
    ):
        assert file_path.stat().st_mode & 0o777 == 0o600
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
            allowed_producer_commits=frozenset(
                {handoff.payload["producer"]["commit_sha"]}
            ),
        ).context_bytes


def test_later_dossier_anchor_survives_real_producer_and_admission_replay(
    tmp_path: Path,
) -> None:
    fixture_bytes = (
        files("career_automation")
        .joinpath("fixtures/market-aligner-v1-vectors.json")
        .read_bytes()
    )
    document = json.loads(fixture_bytes)
    original = parse_handoff(
        base64.b64decode(document["handoff"]["canonical_base64"], validate=True)
    )
    source_issued = datetime(2026, 8, 10, 10, 4, tzinfo=timezone.utc)
    dossier_issued = datetime(2026, 8, 10, 10, 4, 30, tzinfo=timezone.utc)
    handoff_issued, _, dossier_valid_until = _deterministic_handoff_issuance(
        source_observed_at=source_issued,
        dossier_issued_at=dossier_issued,
        evaluated_at=ADMISSION_TIME,
        vacancy_maximum_age_seconds=24 * 60 * 60,
        dossier_maximum_age_seconds=24 * 60 * 60,
    )
    assert handoff_issued == dossier_issued

    official_excerpt = "Build agentic software systems."
    official_object_sha256 = hashlib.sha256(official_excerpt.encode()).hexdigest()
    support = ClaimSupport(
        citation_id="official_job",
        selector=f"bytes:0-{len(official_excerpt.encode())}",
        excerpt=official_excerpt,
        excerpt_sha256=hashlib.sha256(official_excerpt.encode()).hexdigest(),
    )
    dossier = ResearchDossier(
        profile_id=original.payload["profile_id"],
        job_key=original.payload["job_key"],
        company=original.payload["vacancy"]["company_name"],
        role=original.payload["vacancy"]["role_title"],
        claims=(
            ResearchClaim(
                claim=official_excerpt,
                citation_ids=("official_job",),
                confidence=1.0,
                supports=(support,),
            ),
        ),
        citations=(
            SourceCitation(
                citation_id="official_job",
                url=original.payload["vacancy"]["provenance"]["canonical_url"],
                title="Canonical collector vacancy",
                accessed_at=handoff_issued.isoformat().replace("+00:00", "Z"),
                content_sha256=official_object_sha256,
                source_kind="canonical_vacancy",
            ),
        ),
        source_content_sha256=original.payload["vacancy"]["raw_listing_sha256"],
        vacancy_snapshot_sha256=original.payload["vacancy"]["vacancy_snapshot_sha256"],
        promotion_receipt_sha256=original.payload["assessment"][
            "assessment_receipt_sha256"
        ],
        canonical_vacancy_object_sha256=official_object_sha256,
        schema_version="market-aligner.employer-dossier.v2",
    )
    dossier.validate()
    dossier_bytes = canonical_json_bytes(asdict(dossier))
    dossier_sha256 = hashlib.sha256(dossier_bytes).hexdigest()
    payload = json.loads(json.dumps(original.payload))
    payload["created_at"] = handoff_issued.isoformat().replace("+00:00", "Z")
    payload["employer_dossier_sha256"] = dossier_sha256
    handoff = encode_handoff_v1(payload)

    references = {}
    for row in document["reference_bundle"]["value"]["entries"]:
        metadata = row["metadata"]
        subject = dict(metadata["subject"])
        if "application_id" in subject:
            subject["application_id"] = handoff.application_id
        references[metadata["reference_key"]] = HandoffReference(
            exact_bytes=base64.b64decode(row["object_base64"], validate=True),
            type_id=metadata["type_id"],
            schema_version=metadata["schema_version"],
            subject=subject,
            issued_at=metadata["issued_at"],
            valid_until=metadata["valid_until"],
            issuer_id=metadata["issuer_id"],
        )
    references["employer_dossier"] = HandoffReference(
        exact_bytes=dossier_bytes,
        type_id="employer_dossier",
        schema_version="market-aligner.employer-dossier.v2",
        subject={
            "job_key": handoff.payload["job_key"],
            "vacancy_snapshot_sha256": handoff.payload["vacancy"][
                "vacancy_snapshot_sha256"
            ],
        },
        issued_at=handoff_issued.isoformat().replace("+00:00", "Z"),
        valid_until=dossier_valid_until.isoformat().replace("+00:00", "Z"),
    )

    arguments = {
        "references": references,
        "environment": "synthetic",
        "trust_root_id": "synthetic-market-root",
        "issued_at": handoff_issued.isoformat().replace("+00:00", "Z"),
        "source_job_key": "workable:synthetic:42",
    }
    first = write_protected_handoff_bundle(
        tmp_path / "external-data-home", handoff, **arguments
    )
    second = write_protected_handoff_bundle(
        tmp_path / "external-data-home", handoff, **arguments
    )
    assert second == first

    adapter = ProtectedLocalOutbox(
        first.path,
        repository_root=Path(__file__).resolve().parents[1],
        expected_source_record_sha256=first.source_record_sha256,
        allowed_producer_commits=frozenset({handoff.payload["producer"]["commit_sha"]}),
    )
    witness = configured_hmac_current_time_witness(
        authentication_key=b"later-dossier-time-key-32bytes--",
        environment="synthetic",
        trust_root_id="synthetic-market-time-root",
        witness_identity_sha256=hashlib.sha256(b"later-dossier-time").hexdigest(),
        clock=lambda: ADMISSION_TIME,
        nonce_source=lambda: b"later-dossier-time-nonce",
    )
    database = tmp_path / "later-dossier.sqlite3"
    HandoffAdmissionStore(
        database,
        context_authenticator=adapter,
        resolver=adapter,
        current_time_witness=witness,
    )
    store = HandoffAdmissionStore(
        database,
        context_authenticator=adapter,
        resolver=adapter,
        current_time_witness=witness,
    )
    admitted = store.admit_authenticated(adapter.handoff_bytes, adapter.context_bytes)
    replay_store = HandoffAdmissionStore(
        database,
        context_authenticator=adapter,
        resolver=adapter,
        current_time_witness=witness,
    )
    replay = replay_store.admit_authenticated(
        adapter.handoff_bytes, adapter.context_bytes
    )
    assert admitted.created is True
    assert replay.created is False
    assert admitted.application_id == handoff.application_id


def test_private_producer_real_descriptor_reader_binds_promotion_semantic(
    tmp_path: Path,
) -> None:
    written, handoff, _arguments, semantic_sha256 = _promotion_bundle(tmp_path)
    parsed = parse_handoff(handoff.exact_bytes)
    descriptor = os.open(written.path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        adapter = ProtectedLocalOutbox(
            written.path,
            repository_root=Path(__file__).resolve().parents[1],
            expected_source_record_sha256=written.source_record_sha256,
            allowed_producer_commits=frozenset(
                {handoff.payload["producer"]["commit_sha"]}
            ),
            bundle_descriptor=descriptor,
        )
    finally:
        os.close(descriptor)
    try:
        assert (
            _promotion_receipt_semantic_identity(
                adapter,
                parsed,
                adapter._entries["assessment.receipt"],
                source_job_key="workable:synthetic:promotion",
            )
            == semantic_sha256
        )
    finally:
        adapter.close()


def test_legacy_public_category_mode_rejects_replay_and_real_reader(
    tmp_path: Path,
) -> None:
    written, handoff, arguments, _semantic_sha256 = _promotion_bundle(tmp_path)
    os.chmod(written.path / "objects", 0o755)
    with pytest.raises(HandoffProducerError, match="owner-private"):
        write_protected_handoff_bundle(
            tmp_path / "external-data-home", handoff, **arguments
        )
    descriptor = os.open(written.path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        adapter = ProtectedLocalOutbox(
            written.path,
            repository_root=Path(__file__).resolve().parents[1],
            expected_source_record_sha256=written.source_record_sha256,
            allowed_producer_commits=frozenset(
                {handoff.payload["producer"]["commit_sha"]}
            ),
            bundle_descriptor=descriptor,
        )
    finally:
        os.close(descriptor)
    try:
        with pytest.raises(HandoffAdmissionError, match="category is not private"):
            adapter._read(
                "objects/" + adapter._entries["assessment.receipt"]["object_sha256"]
            )
    finally:
        adapter.close()


@pytest.mark.parametrize(
    ("target", "mode", "message"),
    [
        ("bundle", 0o755, "owner-private"),
        ("manifest", 0o644, "bytes or mode"),
    ],
)
def test_producer_replay_rejects_unsafe_bundle_and_file_modes(
    tmp_path: Path, target: str, mode: int, message: str
) -> None:
    written, handoff, arguments, _semantic_sha256 = _promotion_bundle(tmp_path)
    path = written.path if target == "bundle" else written.path / "manifest.json"
    os.chmod(path, mode)
    with pytest.raises(HandoffProducerError, match=message):
        write_protected_handoff_bundle(
            tmp_path / "external-data-home", handoff, **arguments
        )


def test_recovered_canonical_vectors_preserve_declared_dispositions() -> None:
    fixture_bytes = (
        files("career_automation")
        .joinpath("fixtures/market-aligner-v1-vectors.json")
        .read_bytes()
    )
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
    fixture_bytes = (
        files("career_automation")
        .joinpath("fixtures/market-aligner-v1-vectors.json")
        .read_bytes()
    )
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
    promotion_sha = hashlib.sha256(canonical_json_bytes(promotion_body)).hexdigest()
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


def _synthetic_candidate_materialization_authority(
    expected: dict[str, object],
) -> tuple[tuple[tuple[str, str, str], ...], dict[str, object], bytes]:
    from career_automation.evidence_matching import canonical_json, content_hash

    statements = (
        (
            "E-001",
            "credential",
            "Completed a synthetic computing degree covering dependable software design, testing, and delivery practices.",
        ),
        (
            "E-002",
            "project_evidence",
            "Built a synthetic dissertation system that evaluated privacy preserving detection methods through repeatable experiments.",
        ),
        (
            "E-011",
            "project_evidence",
            "Built a synthetic job workflow with collectors, validation, persistent state, retries, and deterministic recovery.",
        ),
        (
            "E-012",
            "project_evidence",
            "Designed synthetic multi-stage automation with explicit requirements, bounded decisions, and measurable acceptance checks.",
        ),
        (
            "E-013",
            "project_evidence",
            "Delivered synthetic Python services with stable interfaces, repeatable tests, and clear operational ownership.",
        ),
        (
            "E-014",
            "project_evidence",
            "Directed a synthetic media workflow from product requirements through a tested local working demonstration.",
        ),
        (
            "E-015",
            "project_evidence",
            "Verified a synthetic audio pipeline with automated checks and a timeline-correct local output artifact.",
        ),
        (
            "E-016",
            "project_evidence",
            "Built a synthetic learning service with question generation, spaced review, persistence, and progress analysis.",
        ),
        (
            "E-017",
            "project_evidence",
            "Implemented a synthetic anomaly detection package with documented interfaces and reproducible local evaluation.",
        ),
    )
    projection_body = {
        "approved_evidence": [
            {
                "id": evidence_id,
                "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
            }
            for evidence_id, _kind, statement in statements
        ],
        "policy_sha256": hashlib.sha256(b"synthetic-projection-policy").hexdigest(),
        "schema_version": "jaa.synthetic-candidate-projection.v1",
    }
    candidate_projection = {
        **projection_body,
        "projection_sha256": content_hash(projection_body),
    }
    vacancy = expected["vacancy"]
    requirement_text = "Deliver reliable services through tested software."
    decision_receipt = {
        "candidate_projection_sha256": candidate_projection["projection_sha256"],
        "company_name": vacancy["company_name"],
        "decision": "eligible",
        "evidence_matrix": [
            {
                "classification": "essential",
                "evidence_ids": ["E-011"],
                "requirement_id": "delivery",
                "requirement_text": requirement_text,
                "requirement_text_sha256": hashlib.sha256(
                    requirement_text.encode()
                ).hexdigest(),
                "status": "matched",
            }
        ],
        "job_key": expected["job_key"],
        "observed_at": "2026-08-10T10:05:00Z",
        "role_title": vacancy["role_title"],
        "source_url": vacancy["provenance"]["canonical_url"],
        "vacancy_description_sha256": hashlib.sha256(
            b"synthetic vacancy description"
        ).hexdigest(),
        "vacancy_sha256": vacancy["vacancy_snapshot_sha256"],
    }
    authority = {
        "candidate_projection": candidate_projection,
        "decisions": [
            {
                "receipt": decision_receipt,
                "receipt_sha256": hashlib.sha256(
                    (canonical_json(decision_receipt) + "\n").encode()
                ).hexdigest(),
            }
        ],
        "schema_version": "jaa.production-candidate-authority.v2",
    }
    return statements, decision_receipt, (canonical_json(authority) + "\n").encode()


def _canonical_market_jaa_materialization(
    tmp_path, capsys, monkeypatch, *, upload_kind="cv"
):
    import career_automation.candidate_application_factory as candidate_factory_module
    from career_automation.application_compiler import CandidateContact
    from career_automation.candidate_application_factory import (
        CandidateApplicationPackage,
        build_candidate_application_deployment_binding,
        materialize_candidate_application_source,
    )
    from career_automation.candidate_contact_authority import CandidateContactAuthority
    from career_automation.evidence_matching import canonical_json
    from career_automation.rendering import render_pdf_artifacts
    from career_automation.workable_live_adapter import WorkableUpload

    document = json.loads(
        files("career_automation")
        .joinpath("fixtures/market-aligner-v1-vectors.json")
        .read_bytes()
    )
    expected = json.loads(
        base64.b64decode(document["handoff"]["canonical_base64"], validate=True)
    )["payload"]
    assessment = expected["assessment"]
    statements, decision_receipt, candidate_authority_bytes = (
        _synthetic_candidate_materialization_authority(expected)
    )
    candidate_authority = json.loads(candidate_authority_bytes)
    candidate_projection = candidate_authority["candidate_projection"]
    candidate_authority_sha256 = hashlib.sha256(candidate_authority_bytes).hexdigest()

    entries = document["reference_bundle"]["value"]["entries"]
    candidate_intent_entry = next(
        row
        for row in entries
        if row["metadata"]["reference_key"] == "candidate_intent"
    )
    candidate_intent = json.loads(
        base64.b64decode(candidate_intent_entry["object_base64"], validate=True)
    )
    candidate_intent["authority_source_sha256"] = candidate_authority_sha256
    candidate_intent_bytes = canonical_json_bytes(candidate_intent)
    candidate_intent_sha256 = hashlib.sha256(candidate_intent_bytes).hexdigest()
    candidate_intent_entry["object_base64"] = base64.b64encode(
        candidate_intent_bytes
    ).decode()
    candidate_intent_entry["metadata"]["object_sha256"] = candidate_intent_sha256
    authority_entry = next(
        row
        for row in entries
        if row["metadata"]["reference_key"] == "candidate_intent.authority_source"
    )
    authority_entry["object_base64"] = base64.b64encode(
        candidate_authority_bytes
    ).decode()
    authority_entry["metadata"]["object_sha256"] = candidate_authority_sha256

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
    service.assessments.apply_opportunity_gate(
        profile_id=expected["profile_id"],
        job_key=expected["job_key"],
        passed=True,
        reason="legacy_manual_gate_is_insufficient",
        policy_hash=expected["selection"]["selection_policy_sha256"],
        priority=1,
    )
    selection_entry = next(
        row
        for row in entries
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
    promotion_sha256 = hashlib.sha256(
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
            {**promotion_body, "receipt_sha256": promotion_sha256}
        ),
        receipt_sha256=promotion_sha256,
    )
    manifest = {
        "assessment_receipt_sha256": assessment["assessment_receipt_sha256"],
        "candidate_intent_sha256": candidate_intent_sha256,
        "created_at": expected["created_at"],
        "eligibility": expected["eligibility"],
        "employer_dossier_sha256": expected["employer_dossier_sha256"],
        "evidence_ledger_sha256": expected["evidence_ledger_sha256"],
        "producer_commit_sha": expected["producer"]["commit_sha"],
        "selection": expected["selection"],
        "vacancy": expected["vacancy"],
    }
    manifest_path = tmp_path / "bridge-handoff-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    handoff_path = tmp_path / "bridge-handoff.json"
    assert market_aligner_main(
        [
            "handoff",
            "--profile-id",
            expected["profile_id"],
            "--job-key",
            expected["job_key"],
            "--manifest",
            str(manifest_path),
            "--output",
            str(handoff_path),
            "--data-home",
            str(data_home),
        ]
    ) == 0
    handoff_receipt = json.loads(capsys.readouterr().out)
    context = canonical_json_bytes(
        {
            "environment": "synthetic",
            "handoff_root_sha256": handoff_receipt["root_sha256"],
            "issued_at": "2026-08-10T10:04:00Z",
            "producer_commit_sha": expected["producer"]["commit_sha"],
            "producer_product": "market-aligner",
            "source_record_sha256": hashlib.sha256(
                canonical_json_bytes(document)
            ).hexdigest(),
            "trust_mode": "authenticated_attestation",
            "trust_proof_sha256": hashlib.sha256(
                b"jaa-synthetic-materialization-context-proof-v1"
            ).hexdigest(),
            "trust_root_id": "synthetic-market-root",
        }
    )
    time_nonces = iter(range(32))
    witness = configured_hmac_current_time_witness(
        authentication_key=b"market-vector-time-key-32-bytes!",
        environment="synthetic",
        trust_root_id="synthetic-market-time-root",
        witness_identity_sha256=hashlib.sha256(
            b"synthetic-market-time-witness"
        ).hexdigest(),
        clock=lambda: ADMISSION_TIME,
        nonce_source=lambda: f"market-jaa-bridge-{next(time_nonces)}".encode(),
    )
    admission_store = HandoffAdmissionStore(
        tmp_path / "bridge-admission.sqlite3",
        context_authenticator=_MarketVectorContextAuthenticator(),
        resolver=_MarketVectorResolver(document),
        current_time_witness=witness,
    )
    admission = admission_store.admit_authenticated(handoff_path.read_bytes(), context)
    built = {}

    def package_builder(verified):
        assert verified.candidate_authority_sha256 == candidate_authority_sha256
        assert verified.candidate_authority_bytes == candidate_authority_bytes
        contact = CandidateContact(
            full_name="Alex Example",
            email="alex@example.test",
            phone=None,
            city="London",
            record_id="synthetic-contact",
            record_version=1,
            provenance_sha256=hashlib.sha256(
                b"synthetic-contact-authority"
            ).hexdigest(),
        )
        contact_bytes = b'{"fixture":"synthetic-signed-contact"}\n'
        contact_path = tmp_path / "synthetic-contact.json"
        contact_path.write_bytes(contact_bytes)
        contact_path.chmod(0o600)
        contact_authority = CandidateContactAuthority(
            contact=contact,
            issued_at="2026-08-10T10:05:00+00:00",
            authority_sha256=contact.provenance_sha256,
            envelope_sha256=hashlib.sha256(contact_bytes).hexdigest(),
            registry_sha256=hashlib.sha256(
                b"synthetic-contact-registry"
            ).hexdigest(),
            signer_public_key_sha256=hashlib.sha256(
                b"synthetic-contact-test-key"
            ).hexdigest(),
            source_path=contact_path,
        )
        evidence_document = {
            "schema_version": "jaa.synthetic-approved-evidence.v1",
            "statements": [
                {
                    "id": evidence_id,
                    "kind": kind,
                    "proof_class": kind,
                    "statement": statement,
                }
                for evidence_id, kind, statement in statements
            ],
        }
        evidence_bytes = (canonical_json(evidence_document) + "\n").encode()
        evidence_path = tmp_path / "synthetic-approved-evidence.json"
        evidence_path.write_bytes(evidence_bytes)
        evidence_path.chmod(0o600)
        monkeypatch.setitem(
            candidate_factory_module.APPROVED_CANDIDATE_SOURCE_HASHES,
            "approved_evidence",
            hashlib.sha256(evidence_bytes).hexdigest(),
        )
        monkeypatch.setattr(
            candidate_factory_module,
            "OUTWARD_PROFILE_REWRITES",
            {
                evidence_id: statement
                for evidence_id, _kind, statement in statements
            },
        )
        monkeypatch.setattr(
            candidate_factory_module, "OUTWARD_LETTER_REWRITES", {}
        )
        candidate_authority_path = tmp_path / "synthetic-candidate-authority.json"
        candidate_authority_path.write_bytes(candidate_authority_bytes)
        candidate_authority_path.chmod(0o600)
        deployment_binding = build_candidate_application_deployment_binding(
            application_id=verified.application_id,
            environment=verified.environment,
            handoff_root_sha256=verified.handoff_root_sha256,
            admission_receipt_sha256=verified.admission_receipt_sha256,
            current_boundary_receipt_sha256=verified.current_boundary_receipt_sha256,
            candidate_authority_file_sha256=candidate_authority_sha256,
        )
        materialization = materialize_candidate_application_source(
            candidate_authority_path=candidate_authority_path,
            deployment_binding=deployment_binding,
            contact_authority=contact_authority,
            decision_receipt=decision_receipt,
            candidate_projection=candidate_projection,
            job_key=verified.job_key,
            vacancy_sha256=verified.vacancy_snapshot_sha256,
            source_url=verified.canonical_url,
            role_title=verified.role_title,
            company_name=verified.company_name,
            contact=contact,
            approved_evidence_path=evidence_path,
            candidate_authority_bytes=candidate_authority_bytes,
            contact_authority_bytes=contact_bytes,
        )
        artifacts = render_pdf_artifacts(materialization.source)
        candidate_package = CandidateApplicationPackage(
            materialization.source,
            artifacts,
            materialization.vacancy_requirements,
        )
        cv_path = tmp_path / "synthetic-cv.pdf"
        cv_path.write_bytes(artifacts.cv_pdf.pdf_bytes)
        cv_path.chmod(0o600)
        cover_path = tmp_path / "synthetic-cover-letter.pdf"
        cover_path.write_bytes(artifacts.cover_letter_pdf.pdf_bytes)
        cover_path.chmod(0o600)
        selected_path, selected_sha256 = (
            (cv_path, artifacts.cv_pdf.pdf_sha256)
            if upload_kind == "cv"
            else (cover_path, artifacts.cover_letter_pdf.pdf_sha256)
        )
        uploads = {"resume": WorkableUpload(selected_path, selected_sha256)}
        built.update(
            {
                "artifacts": artifacts,
                "candidate_package": candidate_package,
                "cover_path": cover_path,
                "cv_path": cv_path,
                "materialization": materialization,
                "verified": verified,
            }
        )
        return materialization, candidate_package, uploads

    return {
        "admission": admission,
        "admission_store": admission_store,
        "built": built,
        "job_key": expected["job_key"],
        "package_builder": package_builder,
    }


def test_admitted_market_materialization_binds_workable_diagnostic_package(
    tmp_path, capsys, monkeypatch
) -> None:
    pytest.importorskip("playwright.sync_api")
    from career_automation.workable_live_adapter import (
        SyntheticWorkableFixtureAdapter,
        WorkableBoundaryError,
        WorkableField,
        WorkableLiveAdapter,
        WorkableOneUseCircuit,
        WorkablePolicy,
    )

    fixture = _canonical_market_jaa_materialization(tmp_path, capsys, monkeypatch)
    policy = WorkablePolicy(
        tenant="synthetic",
        vacancy_id="MARKETJAA1",
        job_key=fixture["job_key"],
        fields=(
            WorkableField("full_name", "text", True, "Full name"),
            WorkableField("email", "email", True, "Email"),
            WorkableField("resume", "file", True, "Resume"),
        ),
    )
    circuit = WorkableOneUseCircuit(tmp_path / "workable-no-submit.sqlite3")
    adapter = SyntheticWorkableFixtureAdapter(circuit, JAA_ROOT)
    arguments = {
        "admission_store": fixture["admission_store"],
        "application_id": fixture["admission"].application_id,
        "package_builder": fixture["package_builder"],
        "policy": policy,
    }
    with pytest.raises(WorkableBoundaryError, match="synthetic Workable fixture"):
        WorkableLiveAdapter(circuit, JAA_ROOT)._admitted_diagnostic_application(
            **arguments
        )
    application = adapter._admitted_diagnostic_application(**arguments)
    built = fixture["built"]
    materialization = built["materialization"]
    artifacts = built["artifacts"]
    document = application.package_document()
    assert document["application_id"] == fixture["admission"].application_id
    assert document["handoff_root_sha256"] == fixture["admission"].handoff_root_sha256
    assert document["materialization_receipt_sha256"] == (
        materialization.receipt.receipt_sha256
    )
    assert document["artifact_set_sha256"] == artifacts.artifact_set_sha256
    assert document["upload_roles"] == {"resume": "cv"}
    assert document["diagnostic_only"] is True
    assert document["release_authority"] is False
    assert document["submission_authority"] is False

    consent_root = tmp_path / "unowned-consent"
    consent_root.mkdir()
    consent_fixture = _canonical_market_jaa_materialization(
        consent_root, capsys, monkeypatch
    )
    consent_policy = WorkablePolicy(
        tenant="synthetic",
        vacancy_id="MARKETJAA1",
        job_key=consent_fixture["job_key"],
        fields=(
            WorkableField("full_name", "text", True, "Full name"),
            WorkableField("email", "email", True, "Email"),
            WorkableField("terms", "checkbox", True, "Terms"),
            WorkableField("resume", "file", True, "Resume"),
        ),
    )
    consent_circuit = WorkableOneUseCircuit(consent_root / "workable.sqlite3")
    with pytest.raises(WorkableBoundaryError):
        SyntheticWorkableFixtureAdapter(
            consent_circuit, JAA_ROOT
        )._admitted_diagnostic_application(
            admission_store=consent_fixture["admission_store"],
            application_id=consent_fixture["admission"].application_id,
            package_builder=consent_fixture["package_builder"],
            policy=consent_policy,
        )

    cover_root = tmp_path / "cover-role-swap"
    cover_root.mkdir()
    cover_fixture = _canonical_market_jaa_materialization(
        cover_root, capsys, monkeypatch, upload_kind="cover_letter"
    )
    cover_policy = WorkablePolicy(
        tenant="synthetic",
        vacancy_id="MARKETJAA1",
        job_key=cover_fixture["job_key"],
        fields=policy.fields,
    )
    with pytest.raises(WorkableBoundaryError, match="uploads differ"):
        SyntheticWorkableFixtureAdapter(
            WorkableOneUseCircuit(cover_root / "workable.sqlite3"), JAA_ROOT
        )._admitted_diagnostic_application(
            admission_store=cover_fixture["admission_store"],
            application_id=cover_fixture["admission"].application_id,
            package_builder=cover_fixture["package_builder"],
            policy=cover_policy,
        )

    phone_root = tmp_path / "canonical-none-phone"
    phone_root.mkdir()
    phone_fixture = _canonical_market_jaa_materialization(
        phone_root, capsys, monkeypatch
    )
    phone_policy = WorkablePolicy(
        tenant="synthetic",
        vacancy_id="MARKETJAA1",
        job_key=phone_fixture["job_key"],
        fields=(
            WorkableField("full_name", "text", True, "Full name"),
            WorkableField("email", "email", True, "Email"),
            WorkableField("phone", "tel", False, "Phone"),
            WorkableField("resume", "file", True, "Resume"),
        ),
    )
    with pytest.raises(WorkableBoundaryError):
        SyntheticWorkableFixtureAdapter(
            WorkableOneUseCircuit(phone_root / "workable.sqlite3"), JAA_ROOT
        )._admitted_diagnostic_application(
            admission_store=phone_fixture["admission_store"],
            application_id=phone_fixture["admission"].application_id,
            package_builder=phone_fixture["package_builder"],
            policy=phone_policy,
        )
    assert circuit.journal() == ()
    assert consent_circuit.journal() == ()


def test_admitted_market_package_real_chrome_readback_never_submits(
    tmp_path, capsys, monkeypatch
) -> None:
    pytest.importorskip("playwright.sync_api")
    import career_automation.workable_live_adapter as workable_module
    from career_automation.workable_live_adapter import (
        SyntheticWorkableFixtureAdapter,
        WorkableBoundaryError,
        WorkableField,
        WorkableOneUseCircuit,
        WorkablePolicy,
    )
    from playwright.sync_api import sync_playwright

    try:
        expected_source_identity = workable_module._source_identity(JAA_ROOT)
    except (ValueError, WorkableBoundaryError):
        pytest.skip("real Chrome proof requires the committed clean candidate tree")
    fixture = _canonical_market_jaa_materialization(tmp_path, capsys, monkeypatch)
    policy = WorkablePolicy(
        tenant="synthetic",
        vacancy_id="MARKETJAA1",
        job_key=fixture["job_key"],
        fields=(
            WorkableField("full_name", "text", True, "Full name"),
            WorkableField("email", "email", True, "Email"),
            WorkableField("resume", "file", True, "Resume"),
        ),
    )
    circuit = WorkableOneUseCircuit(tmp_path / "workable-chrome-no-submit.sqlite3")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page()
        fixture_html = """<!doctype html><html><body>
          <form>
            <label for="full-name">Full name</label>
            <input id="full-name" name="full_name" type="text" required>
            <label for="email">Email</label>
            <input id="email" name="email" type="email" required>
            <label for="resume">Resume</label>
            <input id="resume" name="resume" type="file" required>
            <button type="submit">Submit application</button>
          </form>
          <script>
            window.submitClicks = 0;
            document.querySelector('form').addEventListener('submit', event => {
              event.preventDefault(); window.submitClicks += 1;
            });
          </script>
        </body></html>"""

        def fulfill_fixture(route) -> None:
            route.fulfill(status=200, content_type="text/html", body=fixture_html)

        page.route("**/*", fulfill_fixture)
        page.goto(
            "http://127.0.0.1/fixture/workable/synthetic/j/"
            "MARKETJAA1/apply/",
            wait_until="domcontentloaded",
        )
        page.evaluate("window.__JAA_WORKABLE_FIXTURE__ = true")
        application, review = SyntheticWorkableFixtureAdapter(
            circuit, JAA_ROOT
        ).prepare_admitted_diagnostic_review(
            page,
            admission_store=fixture["admission_store"],
            application_id=fixture["admission"].application_id,
            package_builder=fixture["package_builder"],
            policy=policy,
        )
        built = fixture["built"]
        answers = {
            "full_name": built["materialization"].source.contact.full_name,
            "email": built["materialization"].source.contact.email,
        }
        assert page.locator('[name="full_name"]').input_value() == answers["full_name"]
        assert page.locator('[name="email"]').input_value() == answers["email"]
        assert page.locator('[name="resume"]').evaluate(
            "el => ({name: el.files[0].name, size: el.files[0].size})"
        ) == {
            "name": built["cv_path"].name,
            "size": built["cv_path"].stat().st_size,
        }
        assert page.evaluate("window.submitClicks") == 0
        browser.close()
    assert application.package_document()["application_id"] == (
        fixture["admission"].application_id
    )
    assert (review.source_head, review.source_sha256s) == expected_source_identity
    assert review.consequential_click_authority is False
    assert circuit.journal() == ()
