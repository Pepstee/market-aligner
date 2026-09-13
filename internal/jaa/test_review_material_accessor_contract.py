from __future__ import annotations

import hashlib
import inspect
import json
import sqlite3
import unicodedata
from datetime import datetime, timezone
from dataclasses import fields
from pathlib import Path

import pytest

from career_automation.current_time import (
    AuthenticatedCurrentTimeWitness,
    AuthenticatedTimeEvidence,
    HMACCurrentTimeIssuer,
    obtain_current_time,
)
from career_automation.handoff_admission import HandoffAdmissionError, HandoffAdmissionStore
from career_automation.market_aligner_handoff import (
    CONTRACT_BUNDLE_SHA256,
    canonical_json_bytes,
    canonical_sha256,
    decode_canonical_json,
)
from career_automation.review_material import (
    EMPLOYER_REVIEW_INPUT_SCHEMA,
    MAX_REVIEW_TEXT_BYTES,
    REVIEW_MATERIAL_RECEIPT_SCHEMA,
    REVIEW_MATERIAL_REQUEST_SCHEMA,
    REVIEW_TEXT_PROJECTION_ID,
    REVIEW_TEXT_PROJECTION_SCHEMA,
    ResolvedApplicationArtifacts,
    ResolvedReviewMaterial,
    ReviewMaterialAssembler,
    ReviewMaterialError,
)
from career_automation.testing_handoff_contract import (
    ISSUED_AT,
    TRUST_ROOT_ID,
    VALID_UNTIL,
    SyntheticContextAuthenticator,
    build_handoff_fixture,
)


APPLICATION_SOURCE_IDENTITY = "a" * 64
REVIEW_TIME = "2026-08-10T10:06:00Z"
CV_PDF_BYTES = b"%PDF-1.4\nsynthetic-cv-retained-bytes\n%%EOF"
COVER_LETTER_PDF_BYTES = b"%PDF-1.4\nsynthetic-cover-retained-bytes\n%%EOF"
VISIBLE_TEXT = "First line\r\nCafe\u0301 role\rThird  line \n".encode("utf-8")
PROJECTED_TEXT = "First line\nCafé role\nThird  line \n".encode("utf-8")
GOLDEN_HASHES = {
    "evaluation_time_receipt_sha256": "03e5f552d117f70f117bc51336d7194bb738dff509622dc4fbc9b1e5837203d1",
    "projection_metadata_sha256": "16d06d8495ddf12e286c5b8c7e513c387c052bf08853557e70b62bd7020c63bb",
    "projection_sha256": "affa6e8374596f4392135f253941acaad26f650f3ad5c310dfad3366e8705fb3",
    "raw_listing_metadata_sha256": "5341373d06e67707508ae2c86a8f0b8f164db3ba2d810d4fdacc48c1e080489e",
    "request_sha256": "d6dc40ac237f640e3117242e94182e0fe708533185604db7412b8bbd5865df94",
    "review_input_sha256": "29f00cf477069bcfee6a43bae33d43e23690009a92320f0f4d24037928f34b41",
    "review_text_sha256": "f8af5a716e271d1e0ecc792455ca8d5bdb5dda2d9936943fab9dfca84c40fb24",
    "vacancy_snapshot_metadata_sha256": "d57aaedf94d2a1c53a99aa4cdc91b282514dbc30b1c13e54786457f56ff90f84",
    "verification_receipt_sha256": "06fa1a8ed960141ce4d0c384519f29ee58218c0773e6b289082b9ef7e53c62ef",
}


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _application_package() -> bytes:
    return canonical_json_bytes(
        {
            "cover_letter": {
                "exact_pdf_sha256": _sha(COVER_LETTER_PDF_BYTES),
                "exact_pdf_text": "Synthetic cover letter",
            },
            "cv": {
                "exact_pdf_sha256": _sha(CV_PDF_BYTES),
                "exact_pdf_text": "Synthetic CV",
            },
            "form_answers": [
                {
                    "answer": "Synthetic answer",
                    "question": "Why this role?",
                    "question_id": "motivation",
                }
            ],
        }
    )


class SyntheticApplicationArtifactAccessor:
    accessor_identity_sha256 = _sha(b"synthetic-application-artifact-accessor-v1")
    environment = "synthetic"

    def __init__(self) -> None:
        self.cv_pdf_bytes = CV_PDF_BYTES
        self.cover_letter_pdf_bytes = COVER_LETTER_PDF_BYTES
        self.authenticate_calls = 0
        self.authentication_valid = True

    def resolve(self, **_kwargs) -> ResolvedApplicationArtifacts:
        return ResolvedApplicationArtifacts(
            cv_pdf_bytes=self.cv_pdf_bytes,
            cover_letter_pdf_bytes=self.cover_letter_pdf_bytes,
        )

    def authenticate(self, **kwargs) -> None:
        self.authenticate_calls += 1
        if not self.authentication_valid:
            raise ValueError("synthetic application artifact proof differs")
        assert kwargs["application_source_identity"] == APPLICATION_SOURCE_IDENTITY
        assert kwargs["application_package_sha256"] == _sha(_application_package())


class SyntheticPDFTextExtractor:
    extractor_id = "synthetic.deterministic-pdf-text"
    extractor_version = "1.0"

    def __init__(self) -> None:
        self.text_overrides: dict[bytes, str] = {}

    def extract_text(self, pdf_bytes: bytes) -> str:
        if pdf_bytes in self.text_overrides:
            return self.text_overrides[pdf_bytes]
        return {
            CV_PDF_BYTES: "Synthetic CV",
            COVER_LETTER_PDF_BYTES: "Synthetic cover letter",
        }[pdf_bytes]


_TIME_KEY = hashlib.sha256(b"public-synthetic-review-time-key-v1").digest()
_TIME_IDENTITY = _sha(b"synthetic-current-time-witness-v1")


class _FixedClock:
    def __init__(self, value: str) -> None:
        self.current = datetime.fromisoformat(value[:-1] + "+00:00")

    def __call__(self) -> datetime:
        return self.current


class _ReplayIssuer:
    def __init__(self, issuer: HMACCurrentTimeIssuer) -> None:
        self.issuer = issuer
        self.first: AuthenticatedTimeEvidence | None = None

    def issue(self, *, purpose: str, subject_sha256: str) -> AuthenticatedTimeEvidence:
        if self.first is None:
            self.first = self.issuer.issue(purpose=purpose, subject_sha256=subject_sha256)
        return self.first


class _StaticEvidenceIssuer:
    def __init__(self, evidence: AuthenticatedTimeEvidence) -> None:
        self.evidence = evidence

    def issue(self, *, purpose: str, subject_sha256: str) -> AuthenticatedTimeEvidence:
        return self.evidence


def _witness_for_evidence(
    evidence: AuthenticatedTimeEvidence,
) -> AuthenticatedCurrentTimeWitness:
    return AuthenticatedCurrentTimeWitness(
        _StaticEvidenceIssuer(evidence),
        authentication_key=_TIME_KEY,
        environment="synthetic",
        trust_root_id=TRUST_ROOT_ID,
        witness_identity_sha256=_TIME_IDENTITY,
        trusted_clock=_FixedClock(REVIEW_TIME),
    )


def SyntheticCurrentTimeWitness(
    *,
    evaluated_at: str = REVIEW_TIME,
    trusted_now: str = REVIEW_TIME,
    environment: str = "synthetic",
    trust_root_id: str = TRUST_ROOT_ID,
    evidence_trust_root_id: str | None = None,
    reuse_evidence: bool = False,
    proof_valid: bool = True,
) -> AuthenticatedCurrentTimeWitness:
    counter = iter(range(1, 1_000_000))
    issuer = HMACCurrentTimeIssuer(
        authentication_key=(
            _TIME_KEY if proof_valid else hashlib.sha256(b"wrong-time-key").digest()
        ),
        environment=environment,
        trust_root_id=evidence_trust_root_id or trust_root_id,
        witness_identity_sha256=_TIME_IDENTITY,
        clock=_FixedClock(evaluated_at),
        nonce_source=lambda: hashlib.sha256(
            f"review-time-nonce:{next(counter)}".encode()
        ).digest(),
    )
    source = _ReplayIssuer(issuer) if reuse_evidence else issuer
    return AuthenticatedCurrentTimeWitness(
        source,
        authentication_key=_TIME_KEY,
        environment=environment,
        trust_root_id=trust_root_id,
        witness_identity_sha256=_TIME_IDENTITY,
        trusted_clock=_FixedClock(trusted_now),
    )


class SyntheticReviewMaterialAccessor:
    trusted_issuer_ids = frozenset({"synthetic-market-review-accessor-v1"})
    accessor_identity_sha256 = _sha(b"synthetic-review-material-accessor-v1")

    def __init__(self, fixture, *, visible_text: bytes = VISIBLE_TEXT) -> None:
        self.fixture = fixture
        self.visible_text = visible_text
        self.environment = "synthetic"
        self.trust_root_id = TRUST_ROOT_ID
        self.resolve_calls: list[bytes] = []
        self.authenticate_calls = 0
        self.snapshot_bytes_override: bytes | None = None
        self.raw_bytes_override: bytes | None = None
        self.snapshot_metadata_mutation: dict[str, object] = {}
        self.raw_metadata_mutation: dict[str, object] = {}
        self.projection_metadata_mutation: dict[str, object] = {}

    @staticmethod
    def _proof(
        request_sha256: str, reference_key: str, object_sha256: str, trust_root_id: str
    ) -> str:
        return canonical_sha256(
            {
                "object_sha256": object_sha256,
                "reference_key": reference_key,
                "request_sha256": request_sha256,
                "trust_root_id": trust_root_id,
            }
        )

    def _metadata(
        self,
        *,
        request_sha256: str,
        exact_bytes: bytes,
        reference_key: str,
        type_id: str,
        schema_version: str,
        subject: dict[str, str],
        issued_at: str,
        mutation: dict[str, object],
    ) -> bytes:
        object_sha256 = _sha(exact_bytes)
        document = {
            "issued_at": issued_at,
            "issuer_id": "synthetic-market-review-accessor-v1",
            "object_sha256": object_sha256,
            "reference_key": reference_key,
            "schema_version": schema_version,
            "subject": subject,
            "trust_proof_sha256": self._proof(
                request_sha256, reference_key, object_sha256, self.trust_root_id
            ),
            "trust_root_id": self.trust_root_id,
            "type_id": type_id,
            "valid_until": VALID_UNTIL,
        }
        document.update(mutation)
        return canonical_json_bytes(document)

    def resolve(self, *, request_bytes: bytes) -> ResolvedReviewMaterial:
        self.resolve_calls.append(request_bytes)
        request = decode_canonical_json(request_bytes, label="synthetic review request")
        assert set(request) == {
            "admission_context_sha256",
            "evaluated_at",
            "evaluation_time_receipt_sha256",
            "handoff_root_sha256",
            "job_key",
            "raw_listing_sha256",
            "schema_version",
            "vacancy_snapshot_sha256",
        }
        assert request["schema_version"] == REVIEW_MATERIAL_REQUEST_SCHEMA
        snapshot = self.snapshot_bytes_override or self.fixture.resolver.objects[
            request["vacancy_snapshot_sha256"]
        ]
        raw = self.raw_bytes_override or self.fixture.resolver.objects[
            request["raw_listing_sha256"]
        ]
        request_sha256 = _sha(request_bytes)
        source_subject = {
            "job_key": request["job_key"],
            "vacancy_snapshot_sha256": request["vacancy_snapshot_sha256"],
        }
        try:
            projected_text = unicodedata.normalize(
                "NFC",
                self.visible_text.decode("utf-8")
                .replace("\r\n", "\n")
                .replace("\r", "\n"),
            ).encode("utf-8")
        except UnicodeDecodeError:
            # The assembler must reject invalid visible bytes before it trusts
            # projection metadata.  A shaped placeholder keeps the accessor
            # response structurally complete for that negative vector.
            projected_text = b"invalid-visible-text"
        review_text_sha256 = _sha(projected_text)
        projection = canonical_json_bytes(
            {
                "job_key": request["job_key"],
                "projection_id": REVIEW_TEXT_PROJECTION_ID,
                "raw_listing_sha256": request["raw_listing_sha256"],
                "review_text_sha256": review_text_sha256,
                "schema_version": REVIEW_TEXT_PROJECTION_SCHEMA,
                "vacancy_snapshot_sha256": request["vacancy_snapshot_sha256"],
            }
        )
        projection_subject = {
            "handoff_root_sha256": request["handoff_root_sha256"],
            "job_key": request["job_key"],
            "raw_listing_sha256": request["raw_listing_sha256"],
            "review_text_sha256": review_text_sha256,
            "vacancy_snapshot_sha256": request["vacancy_snapshot_sha256"],
        }
        return ResolvedReviewMaterial(
            vacancy_snapshot_bytes=snapshot,
            raw_listing_bytes=raw,
            visible_listing_text_bytes=self.visible_text,
            vacancy_snapshot_metadata_bytes=self._metadata(
                request_sha256=request_sha256,
                exact_bytes=snapshot,
                reference_key="vacancy.snapshot",
                type_id="vacancy_snapshot",
                schema_version="market-aligner.vacancy-snapshot.v1",
                subject=source_subject,
                issued_at=ISSUED_AT,
                mutation=self.snapshot_metadata_mutation,
            ),
            raw_listing_metadata_bytes=self._metadata(
                request_sha256=request_sha256,
                exact_bytes=raw,
                reference_key="vacancy.raw_listing",
                type_id="raw_listing",
                schema_version="market-aligner.raw-listing-evidence.v1",
                subject=source_subject,
                issued_at=ISSUED_AT,
                mutation=self.raw_metadata_mutation,
            ),
            projection_metadata_bytes=self._metadata(
                request_sha256=request_sha256,
                exact_bytes=projection,
                reference_key="vacancy.review_text_projection",
                type_id="review_text_projection",
                schema_version=REVIEW_TEXT_PROJECTION_SCHEMA,
                subject=projection_subject,
                issued_at=request["evaluated_at"],
                mutation=self.projection_metadata_mutation,
            ),
        )

    def authenticate(
        self,
        *,
        request_bytes: bytes,
        resolution: ResolvedReviewMaterial,
        projection_bytes: bytes,
        admission_context_bytes: bytes,
    ) -> None:
        self.authenticate_calls += 1
        context = json.loads(admission_context_bytes)
        if context["trust_root_id"] != self.trust_root_id:
            raise ValueError("context trust root differs")
        request_sha256 = _sha(request_bytes)
        for metadata_bytes, exact_bytes in (
            (resolution.vacancy_snapshot_metadata_bytes, resolution.vacancy_snapshot_bytes),
            (resolution.raw_listing_metadata_bytes, resolution.raw_listing_bytes),
            (resolution.projection_metadata_bytes, projection_bytes),
        ):
            metadata = json.loads(metadata_bytes)
            expected = self._proof(
                request_sha256,
                metadata["reference_key"],
                _sha(exact_bytes),
                metadata["trust_root_id"],
            )
            if metadata["trust_proof_sha256"] != expected:
                raise ValueError("accessor proof differs")


def _ready(tmp_path, *, visible_text: bytes = VISIBLE_TEXT):
    fixture = build_handoff_fixture()
    witness = SyntheticCurrentTimeWitness()
    store = HandoffAdmissionStore(
        tmp_path / "review-material.sqlite3",
        context_authenticator=SyntheticContextAuthenticator(),
        resolver=fixture.resolver,
        current_time_witness=witness,
    )
    admission = store.admit_authenticated(fixture.raw, fixture.context_bytes)
    witness.issue_count = 0
    witness.authentication_calls.clear()
    accessor = SyntheticReviewMaterialAccessor(fixture, visible_text=visible_text)
    assembler = ReviewMaterialAssembler(
        store,
        accessor=accessor,
        application_artifact_accessor=SyntheticApplicationArtifactAccessor(),
        pdf_text_extractor=SyntheticPDFTextExtractor(),
        current_time_witness=witness,
    )
    return fixture, admission, accessor, witness, assembler


def test_atomic_review_boundary_rejects_a_valid_receipt_for_another_subject(
    tmp_path,
) -> None:
    fixture, admission, _accessor, witness, assembler = _ready(tmp_path)
    fixture.resolver.resolve_calls.clear()
    evidence = obtain_current_time(
        witness,
        environment="synthetic",
        purpose="review_material",
        subject_sha256="f" * 64,
        maximum_clock_skew_seconds=300,
    )
    connection = sqlite3.connect(assembler.admission_store.database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(HandoffAdmissionError) as raised:
            assembler.admission_store.for_boundary_in_transaction(
                connection,
                admission.application_id,
                "review",
                time_evidence=evidence,
                expected_time_purpose="review_material",
                expected_time_subject_sha256=admission.handoff_root_sha256,
            )
        assert raised.value.code == "time_substitution"
        assert fixture.resolver.resolve_calls == []
    finally:
        connection.rollback()
        connection.close()


def test_exact_request_projection_review_input_and_receipt_bindings(tmp_path) -> None:
    fixture, admission, accessor, witness, assembler = _ready(tmp_path)
    result = assembler.assemble(
        admission.application_id,
        application_source_identity=APPLICATION_SOURCE_IDENTITY,
        application_package_bytes=_application_package(),
    )

    assert result.projected_text_bytes == PROJECTED_TEXT
    assert result.review_text_sha256 == _sha(PROJECTED_TEXT)
    assert witness.issue_count == 1
    assert witness.authentication_calls == [
        ("review_material", admission.handoff_root_sha256, 300)
    ]
    assert accessor.authenticate_calls == 1
    with sqlite3.connect(assembler.admission_store.database) as connection:
        persisted_time = connection.execute(
            """SELECT receipt_bytes,consumer_kind,consumer_id
               FROM authenticated_time_evidence WHERE receipt_sha256=?""",
            (result.evaluation_time_receipt_sha256,),
        ).fetchone()
    assert persisted_time == (
        result.evaluation_time_receipt_bytes,
        "review_request",
        result.request_sha256,
    )

    request = json.loads(result.request_bytes)
    assert request == {
        "admission_context_sha256": _sha(fixture.context_bytes),
        "evaluated_at": REVIEW_TIME,
        "evaluation_time_receipt_sha256": result.evaluation_time_receipt_sha256,
        "handoff_root_sha256": admission.handoff_root_sha256,
        "job_key": admission.job_key,
        "raw_listing_sha256": fixture.payload["vacancy"]["raw_listing_sha256"],
        "schema_version": REVIEW_MATERIAL_REQUEST_SCHEMA,
        "vacancy_snapshot_sha256": fixture.payload["vacancy"]["vacancy_snapshot_sha256"],
    }
    assert result.request_sha256 == _sha(result.request_bytes)

    projection = json.loads(result.projection_bytes)
    assert projection == {
        "job_key": admission.job_key,
        "projection_id": REVIEW_TEXT_PROJECTION_ID,
        "raw_listing_sha256": fixture.payload["vacancy"]["raw_listing_sha256"],
        "review_text_sha256": _sha(PROJECTED_TEXT),
        "schema_version": REVIEW_TEXT_PROJECTION_SCHEMA,
        "vacancy_snapshot_sha256": fixture.payload["vacancy"]["vacancy_snapshot_sha256"],
    }
    review_input = json.loads(result.review_input_bytes)
    assert review_input == {
        "application": json.loads(_application_package()),
        "job_listing": {
            "exact_text": PROJECTED_TEXT.decode(),
            "sha256": _sha(PROJECTED_TEXT),
        },
        "schema_version": EMPLOYER_REVIEW_INPUT_SCHEMA,
    }
    assert "trust_root_id" not in review_input["job_listing"]
    assert "evaluation_time_receipt_sha256" not in result.review_input_bytes.decode()

    receipt = json.loads(result.verification_receipt_bytes)
    assert receipt["schema_version"] == REVIEW_MATERIAL_RECEIPT_SCHEMA
    assert receipt["application_source_identity"] == APPLICATION_SOURCE_IDENTITY
    assert receipt["application_artifact_accessor_identity_sha256"] == _sha(
        b"synthetic-application-artifact-accessor-v1"
    )
    assert receipt["pdf_extractor_id"] == "synthetic.deterministic-pdf-text"
    assert receipt["pdf_extractor_version"] == "1.0"
    assert receipt["cv_pdf_sha256"] == _sha(CV_PDF_BYTES)
    assert receipt["cover_letter_pdf_sha256"] == _sha(COVER_LETTER_PDF_BYTES)
    assert receipt["cv_pdf_text_sha256"] == _sha(b"Synthetic CV")
    assert receipt["cover_letter_pdf_text_sha256"] == _sha(
        b"Synthetic cover letter"
    )
    assert receipt["form_answers_sha256"] == _sha(
        canonical_json_bytes(
            {
                "form_answers": json.loads(_application_package())["form_answers"],
                "schema_version": "jaa.form-answers.v1",
            }
        )
    )
    assert receipt["consumer_contract_bundle_sha256"] == list(CONTRACT_BUNDLE_SHA256)
    assert len(receipt["consumer_contract_bundle_sha256"]) == 10
    assert receipt["request_sha256"] == result.request_sha256
    assert receipt["review_input_sha256"] == result.review_input_sha256
    assert receipt["review_text_projection_sha256"] == result.projection_sha256
    assert receipt["review_text_sha256"] == result.review_text_sha256
    assert receipt["evaluation_time_receipt_sha256"] == result.evaluation_time_receipt_sha256
    assert receipt["vacancy_snapshot_metadata_sha256"] == _sha(
        result.vacancy_snapshot_metadata_bytes
    )
    assert receipt["raw_listing_metadata_sha256"] == _sha(
        result.raw_listing_metadata_bytes
    )
    assert receipt["review_text_projection_metadata_sha256"] == _sha(
        result.projection_metadata_bytes
    )
    assert result.verification_receipt_sha256 == _sha(result.verification_receipt_bytes)
    assert {
        "evaluation_time_receipt_sha256": result.evaluation_time_receipt_sha256,
        "projection_metadata_sha256": _sha(result.projection_metadata_bytes),
        "projection_sha256": result.projection_sha256,
        "raw_listing_metadata_sha256": _sha(result.raw_listing_metadata_bytes),
        "request_sha256": result.request_sha256,
        "review_input_sha256": result.review_input_sha256,
        "review_text_sha256": result.review_text_sha256,
        "vacancy_snapshot_metadata_sha256": _sha(
            result.vacancy_snapshot_metadata_bytes
        ),
        "verification_receipt_sha256": result.verification_receipt_sha256,
    } == GOLDEN_HASHES


@pytest.mark.parametrize(
    "mutation,expected_code",
    [
        ("pdf_bytes", "application_pdf_digest"),
        ("pdf_text", "application_pdf_text"),
        ("extractor", "application_pdf_extractor"),
        ("artifact_proof", "artifact_authentication"),
    ],
)
def test_exact_pdf_bytes_text_extractor_and_artifact_proof_are_recomputed(
    tmp_path, mutation, expected_code
) -> None:
    _, admission, accessor, witness, assembler = _ready(tmp_path)
    artifact_accessor = assembler.application_artifact_accessor
    extractor = assembler.pdf_text_extractor
    if mutation == "pdf_bytes":
        artifact_accessor.cv_pdf_bytes = CV_PDF_BYTES + b"mutated"
    elif mutation == "pdf_text":
        extractor.text_overrides[CV_PDF_BYTES] = "changed extracted text"
    elif mutation == "extractor":
        extractor.extractor_version = "2.0"
    else:
        artifact_accessor.authentication_valid = False

    with pytest.raises(ReviewMaterialError) as failure:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert failure.value.code == expected_code
    assert witness.issue_count == 0
    assert accessor.resolve_calls == []


def test_caller_cannot_supply_time_listing_or_projection(tmp_path) -> None:
    _, admission, accessor, witness, assembler = _ready(tmp_path)
    parameters = inspect.signature(assembler.assemble).parameters
    assert set(parameters) == {
        "application_id",
        "application_source_identity",
        "application_package_bytes",
    }
    with pytest.raises(TypeError):
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
            evaluated_at=datetime.now(timezone.utc),  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError):
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
            visible_listing_text_bytes=b"caller text",  # type: ignore[call-arg]
        )
    assert witness.issue_count == 0
    assert accessor.resolve_calls == []


@pytest.mark.parametrize(
    "evaluated_at,trusted_now,expected_code",
    [
        ("2026-08-10T09:00:00Z", REVIEW_TIME, "time_backdated"),
        (REVIEW_TIME, "2026-08-10T10:11:01Z", "time_stale"),
        ("2026-08-10T11:00:00Z", REVIEW_TIME, "time_future"),
    ],
)
def test_noncurrent_time_blocks_before_source_resolution(
    tmp_path, evaluated_at, trusted_now, expected_code
) -> None:
    _, admission, accessor, _, assembler = _ready(tmp_path)
    witness = SyntheticCurrentTimeWitness(
        evaluated_at=evaluated_at, trusted_now=trusted_now
    )
    assembler.admission_store.current_time_witness = witness
    assembler = ReviewMaterialAssembler(
        assembler.admission_store,
        accessor=accessor,
        application_artifact_accessor=assembler.application_artifact_accessor,
        pdf_text_extractor=assembler.pdf_text_extractor,
        current_time_witness=witness,
    )
    with pytest.raises(ReviewMaterialError) as failure:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert failure.value.code == expected_code
    assert accessor.resolve_calls == []


def test_stale_nonlisting_reference_blocks_review_before_accessor_resolution(tmp_path) -> None:
    fixture, admission, accessor, _, assembler = _ready(tmp_path)
    fixture.resolver.valid_until_by_reference["candidate_intent"] = (
        "2026-08-10T10:05:30Z"
    )
    with pytest.raises(ReviewMaterialError) as stale:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert stale.value.code == "stale_reference"
    assert accessor.resolve_calls == []
    with sqlite3.connect(assembler.admission_store.database) as connection:
            assert connection.execute(
                """SELECT COUNT(*) FROM authenticated_time_evidence
                   WHERE purpose='review_material'"""
            ).fetchone()[0] == 0


@pytest.mark.parametrize("persisted", [False, True])
def test_absent_or_replayed_time_proof_blocks_before_new_resolution(tmp_path, persisted) -> None:
    fixture, admission, accessor, _, assembler = _ready(tmp_path)
    archive = _review_archive(tmp_path, fixture, admission) if persisted else None

    def run_review(actor):
        arguments = {
            "application_source_identity": APPLICATION_SOURCE_IDENTITY,
            "application_package_bytes": _application_package(),
        }
        if persisted:
            return actor.assemble_and_archive(admission.application_id, archive=archive, **arguments)
        return actor.assemble(admission.application_id, **arguments)

    invalid = SyntheticCurrentTimeWitness(proof_valid=False)
    assembler.admission_store.current_time_witness = invalid
    invalid_assembler = ReviewMaterialAssembler(
        assembler.admission_store,
        accessor=accessor,
        application_artifact_accessor=assembler.application_artifact_accessor,
        pdf_text_extractor=assembler.pdf_text_extractor,
        current_time_witness=invalid,
    )
    with pytest.raises(ReviewMaterialError) as proof:
        run_review(invalid_assembler)
    assert proof.value.code == "time_authentication"
    assert accessor.resolve_calls == []

    replay = SyntheticCurrentTimeWitness(reuse_evidence=True)
    assembler.admission_store.current_time_witness = replay
    replay_assembler = ReviewMaterialAssembler(
        assembler.admission_store,
        accessor=accessor,
        application_artifact_accessor=assembler.application_artifact_accessor,
        pdf_text_extractor=assembler.pdf_text_extractor,
        current_time_witness=replay,
    )
    run_review(replay_assembler)
    assert isinstance(replay._issuer, _ReplayIssuer)
    assert replay._issuer.first is not None
    restarted_witness = _witness_for_evidence(replay._issuer.first)
    assembler.admission_store.current_time_witness = restarted_witness
    restarted_assembler = ReviewMaterialAssembler(
        assembler.admission_store,
        accessor=accessor,
        application_artifact_accessor=assembler.application_artifact_accessor,
        pdf_text_extractor=assembler.pdf_text_extractor,
        current_time_witness=restarted_witness,
    )
    with pytest.raises(ReviewMaterialError) as repeated:
        run_review(restarted_assembler)
    assert repeated.value.code == "time_replay"
    assert len(accessor.resolve_calls) == 1

    if persisted:
        objects = archive._objects(archive._events())
        assert len(objects) == 13
        assert sum(obj.role == "review.material.visible_listing_text_bytes" for obj in objects) == 1
        assert sum(obj.role == "review.material.manifest" for obj in objects) == 1


@pytest.mark.parametrize(
    "boundary,changed",
    [
        ("time_environment", "production"),
        ("time_substitution", "synthetic-other-root"),
        ("accessor_environment", "production"),
        ("accessor_trust", "synthetic-other-root"),
    ],
)
def test_environment_and_trust_swaps_block_before_resolution(tmp_path, boundary, changed) -> None:
    _, admission, accessor, witness, assembler = _ready(tmp_path)
    if boundary == "time_environment":
        witness.environment = changed
    elif boundary == "time_substitution":
        witness = SyntheticCurrentTimeWitness(evidence_trust_root_id=changed)
        assembler.admission_store.current_time_witness = witness
        assembler = ReviewMaterialAssembler(
            assembler.admission_store,
            accessor=accessor,
            application_artifact_accessor=assembler.application_artifact_accessor,
            pdf_text_extractor=assembler.pdf_text_extractor,
            current_time_witness=witness,
        )
    elif boundary == "accessor_environment":
        accessor.environment = changed
    else:
        accessor.trust_root_id = changed
    with pytest.raises(ReviewMaterialError) as failure:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert failure.value.code == boundary
    assert accessor.resolve_calls == []


@pytest.mark.parametrize(
    "visible,code",
    [
        (b"", "review_text_empty"),
        (b"\xef\xbb\xbftext", "review_text_bom"),
        (b"bad\x00text", "review_text_nul"),
        (b"\xff", "review_text_utf8"),
        (b"\xed\xa0\x80", "review_text_utf8"),
        (b"x" * (MAX_REVIEW_TEXT_BYTES + 1), "review_text_too_large"),
    ],
)
def test_visible_text_scalar_and_size_controls(tmp_path, visible, code) -> None:
    _, admission, accessor, witness, assembler = _ready(tmp_path, visible_text=visible)
    with pytest.raises(ReviewMaterialError) as failure:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert failure.value.code == code
    assert witness.authentication_calls
    assert len(accessor.resolve_calls) == 1
    assert accessor.authenticate_calls == 0


def test_visible_text_exact_500000_byte_boundary_is_accepted(tmp_path) -> None:
    visible = b"x" * MAX_REVIEW_TEXT_BYTES
    _, admission, accessor, _, assembler = _ready(tmp_path, visible_text=visible)
    result = assembler.assemble(
        admission.application_id,
        application_source_identity=APPLICATION_SOURCE_IDENTITY,
        application_package_bytes=_application_package(),
    )
    assert result.projected_text_bytes == visible
    assert result.review_text_sha256 == _sha(visible)
    assert accessor.authenticate_calls == 1


@pytest.mark.parametrize(
    "target,mutation,code",
    [
        ("snapshot", {"type_id": "wrong"}, "metadata_substitution"),
        ("snapshot", {"subject": {"job_key": "swap"}}, "metadata_substitution"),
        ("raw", {"trust_root_id": "other-root"}, "metadata_substitution"),
        ("raw", {"valid_until": "2026-08-10T11:59:59Z"}, "metadata_freshness"),
        ("raw", {"unexpected": "field"}, "schema_mismatch"),
        (
            "projection",
            {
                "subject": {
                    "handoff_root_sha256": "f" * 64,
                    "job_key": "swap",
                    "raw_listing_sha256": "e" * 64,
                    "review_text_sha256": "d" * 64,
                    "vacancy_snapshot_sha256": "c" * 64,
                }
            },
            "metadata_substitution",
        ),
        ("projection", {"object_sha256": "0" * 64}, "metadata_substitution"),
        (
            "projection",
            {"valid_until": "2026-08-10T11:59:59Z"},
            "metadata_freshness",
        ),
    ],
)
def test_source_projection_metadata_substitutions_fail(
    tmp_path, target, mutation, code
) -> None:
    _, admission, accessor, _, assembler = _ready(tmp_path)
    getattr(accessor, f"{target}_metadata_mutation").update(mutation)
    with pytest.raises(ReviewMaterialError) as failure:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert failure.value.code == code


def test_source_byte_and_authenticated_proof_substitution_fail(tmp_path) -> None:
    _, admission, accessor, _, assembler = _ready(tmp_path)
    accessor.raw_bytes_override = b"different raw listing bytes"
    with pytest.raises(ReviewMaterialError) as source:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert source.value.code == "source_digest"

    _, admission, accessor, _, assembler = _ready(tmp_path / "proof")
    accessor.projection_metadata_mutation["trust_proof_sha256"] = "0" * 64
    with pytest.raises(ReviewMaterialError) as proof:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert proof.value.code == "accessor_authentication"


def test_application_package_is_exact_canonical_and_bounded(tmp_path) -> None:
    _, admission, accessor, witness, assembler = _ready(tmp_path)
    noncanonical = _application_package() + b"\n"
    with pytest.raises(ReviewMaterialError) as wire:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=noncanonical,
        )
    assert wire.value.code == "invalid_canonical_bytes"

    oversized = json.loads(_application_package())
    oversized["form_answers"][0]["answer"] = "x" * 8_001
    with pytest.raises(ReviewMaterialError) as answer:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=canonical_json_bytes(oversized),
        )
    assert answer.value.code == "form_answers"

    oversized_id = json.loads(_application_package())
    oversized_id["form_answers"][0]["question_id"] = "q" * 8_001
    with pytest.raises(ReviewMaterialError) as identifier:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=canonical_json_bytes(oversized_id),
        )
    assert identifier.value.code == "form_answers"

    reversed_answers = json.loads(_application_package())
    reversed_answers["form_answers"] = [
        {"answer": "Second", "question": "Second?", "question_id": "z_second"},
        {"answer": "First", "question": "First?", "question_id": "a_first"},
    ]
    with pytest.raises(ReviewMaterialError) as order:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=canonical_json_bytes(reversed_answers),
        )
    assert order.value.code == "form_answers"
    assert witness.issue_count == 0
    assert accessor.resolve_calls == []


def test_compatibility_admission_cannot_assemble_release_review(tmp_path) -> None:
    fixture = build_handoff_fixture(compatibility=True)
    witness = SyntheticCurrentTimeWitness()
    store = HandoffAdmissionStore(
        tmp_path / "compatibility.sqlite3",
        context_authenticator=SyntheticContextAuthenticator(),
        resolver=fixture.resolver,
        current_time_witness=witness,
    )
    admission = store.admit_authenticated(fixture.raw, fixture.context_bytes)
    witness.issue_count = 0
    witness.authentication_calls.clear()
    accessor = SyntheticReviewMaterialAccessor(fixture)
    assembler = ReviewMaterialAssembler(
        store,
        accessor=accessor,
        application_artifact_accessor=SyntheticApplicationArtifactAccessor(),
        pdf_text_extractor=SyntheticPDFTextExtractor(),
        current_time_witness=witness,
    )
    with pytest.raises(ReviewMaterialError) as failure:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert failure.value.code == "review_admission_blocked"
    assert witness.issue_count == 0
    assert accessor.resolve_calls == []


@pytest.mark.parametrize("field", ["snapshot_metadata_mutation", "raw_metadata_mutation", "projection_metadata_mutation"])
def test_review_metadata_rejects_unlisted_issuer_before_authentication(tmp_path, field):
    _fixture, admission, accessor, _witness, assembler = _ready(tmp_path)
    getattr(accessor, field)["issuer_id"] = "unlisted-but-well-formed-issuer"
    with pytest.raises(ReviewMaterialError) as raised:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert raised.value.code == "metadata_issuer"
    assert accessor.authenticate_calls == 0


@pytest.mark.parametrize("issuers", [None, frozenset(), {"synthetic-market-review-accessor-v1"}])
def test_review_requires_explicit_immutable_issuer_allowlist(tmp_path, issuers):
    _fixture, admission, accessor, witness, assembler = _ready(tmp_path)
    accessor.trusted_issuer_ids = issuers
    with pytest.raises(ReviewMaterialError) as raised:
        assembler.assemble(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
        )
    assert raised.value.code == "accessor_issuers"
    assert accessor.resolve_calls == []
    assert witness.issue_count == 0


def _review_archive(tmp_path, fixture, admission, *, vacancy_sha256=None):
    from career_automation.application_archive import ApplicationArchive, VacancyArchiveIdentity
    archive = ApplicationArchive(tmp_path / "archive", repository_root=Path(__file__).parent)
    return archive.create_attempt(VacancyArchiveIdentity(
        job_key=admission.job_key,
        vacancy_sha256=vacancy_sha256 or fixture.payload["vacancy"]["raw_listing_sha256"],
        role_title="Synthetic role",
        company_name="Synthetic employer",
        source_url="https://example.test/synthetic-review",
    ))


def test_persisted_review_reopens_every_exact_material_byte_and_completion_link(tmp_path):
    from career_automation.application_archive import ApplicationArchive
    fixture, admission, _accessor, _witness, assembler = _ready(tmp_path)
    attempt = _review_archive(tmp_path, fixture, admission)
    result = assembler.assemble_and_archive(
        admission.application_id,
        application_source_identity=APPLICATION_SOURCE_IDENTITY,
        application_package_bytes=_application_package(),
        archive=attempt,
    )
    assert result.material.visible_listing_text_bytes == VISIBLE_TEXT
    assert result.material.projected_text_bytes == PROJECTED_TEXT
    assert VISIBLE_TEXT != PROJECTED_TEXT
    reopened = ApplicationArchive(
        attempt.archive.root, repository_root=Path(__file__).parent, create=False
    ).open_attempt(result.attempt_id)
    objects = reopened._objects(reopened._events())
    manifests = [obj for obj in objects if obj.role == "review.material.manifest"]
    assert manifests == [result.manifest]
    manifest = json.loads((attempt.archive.root / result.manifest.relative_path).read_bytes())
    expected_bytes = {
        field.name: getattr(result.material, field.name)
        for field in fields(result.material)
        if isinstance(getattr(result.material, field.name), bytes)
    }
    assert set(manifest["objects"]) == set(expected_bytes)
    for name, value in expected_bytes.items():
        obj = next(obj for obj in objects if obj.role == "review.material." + name)
        assert (attempt.archive.root / obj.relative_path).read_bytes() == value
        assert manifest["objects"][name] == {"sha256": _sha(value), "byte_length": len(value)}
        assert obj.sha256 in result.manifest.lineage
    assert manifest["verification_receipt_sha256"] == result.material.verification_receipt_sha256
    assert manifest["request_sha256"] == result.material.request_sha256
    with sqlite3.connect(assembler.admission_store.database) as connection:
        assert connection.execute(
            "SELECT consumer_id FROM authenticated_time_evidence WHERE receipt_sha256=?",
            (manifest["evaluation_time_receipt_sha256"],),
        ).fetchone() == (manifest["request_sha256"],)


@pytest.mark.parametrize("fail_at", [4, 12])
def test_archive_failure_preserves_consumed_time_and_never_records_completion(tmp_path, monkeypatch, fail_at):
    fixture, admission, _accessor, _witness, assembler = _ready(tmp_path)
    attempt = _review_archive(tmp_path, fixture, admission)
    original = attempt.add_artifact
    calls = []
    def fail_archive(*args, **kwargs):
        calls.append(args[0])
        if len(calls) == fail_at:
            raise OSError("synthetic archive failure")
        return original(*args, **kwargs)
    monkeypatch.setattr(attempt, "add_artifact", fail_archive)
    with pytest.raises(OSError, match="synthetic archive failure"):
        assembler.assemble_and_archive(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
            archive=attempt,
        )
    assert not any(obj.role == "review.material.manifest" for obj in attempt._objects(attempt._events()))
    assert len(attempt._objects(attempt._events())) == fail_at - 1
    with sqlite3.connect(assembler.admission_store.database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM authenticated_time_evidence WHERE consumer_kind='review_request'"
        ).fetchone() == (1,)


def test_wrong_review_archive_subject_is_refused_before_consuming_time(tmp_path):
    fixture, admission, accessor, witness, assembler = _ready(tmp_path)
    attempt = _review_archive(tmp_path, fixture, admission, vacancy_sha256="f" * 64)
    with pytest.raises(ReviewMaterialError) as raised:
        assembler.assemble_and_archive(
            admission.application_id,
            application_source_identity=APPLICATION_SOURCE_IDENTITY,
            application_package_bytes=_application_package(),
            archive=attempt,
        )
    assert raised.value.code == "archive_subject"
    assert witness.issue_count == 0
    assert accessor.resolve_calls == []
    assert attempt._objects(attempt._events()) == ()
