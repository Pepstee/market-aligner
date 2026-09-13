"""Authenticated Market Aligner review-material access for employer review.

The handoff admission store deliberately retains Market-owned objects as opaque
bytes.  This module implements the one frozen exception: a configured accessor
re-resolves the exact vacancy sources and authoritative visible listing text for
one fresh review.  Callers can supply the application identity and exact outward
application bytes, but they cannot supply listing material or evaluation time.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from .current_time import (
    AuthenticatedCurrentTimeWitness,
    AuthenticatedTimeEvidence,
    CurrentTimeWitnessError,
    obtain_current_time,
    validate_current_time_witness_configuration,
)
from .handoff_admission import (
    ADMISSION_KIND_V1,
    HandoffAdmissionError,
    HandoffAdmissionStore,
    SelectionPolicyRules,
    VERIFICATION_SCHEMA,
)
from .market_aligner_handoff import (
    CONTRACT_BUNDLE_SHA256,
    MAX_SAFE_INTEGER,
    MAX_WIRE_BYTES,
    STRICT_EMISSION_PROFILE,
    HandoffContractError,
    canonical_json_bytes,
    decode_canonical_json,
    parse_handoff,
)


REVIEW_MATERIAL_REQUEST_SCHEMA = "majaa.review-material-request.v1"
REVIEW_TEXT_PROJECTION_ID = "market-aligner.review-text-projection.utf8-nfc-lf.v1"
REVIEW_TEXT_PROJECTION_SCHEMA = "market-aligner.review-text-projection.v1"
EMPLOYER_REVIEW_INPUT_SCHEMA = "jaa.employer-review-input.v1"
REVIEW_MATERIAL_RECEIPT_SCHEMA = "jaa.review-material-verification.v1"
REVIEW_TIME_PURPOSE = "review_material"
MAX_REVIEW_TEXT_BYTES = 500_000
MAX_DOCUMENT_TEXT_BYTES = 250_000
MAX_FORM_ANSWER_ROWS = 200
MAX_FORM_VALUE_BYTES = 8_000
MAX_PDF_BYTES = 20 * 1024 * 1024
PDF_EXTRACTOR_ALLOWLIST = {
    "production": ("pypdf.PdfReader.extract_text", "6.6.0"),
    "synthetic": ("synthetic.deterministic-pdf-text", "1.0"),
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_METADATA_KEYS = {
    "issued_at",
    "issuer_id",
    "object_sha256",
    "reference_key",
    "schema_version",
    "subject",
    "trust_proof_sha256",
    "trust_root_id",
    "type_id",
    "valid_until",
}


class ReviewMaterialError(ValueError):
    """Stable fail-closed error for the review-material trust boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ResolvedReviewMaterial:
    """Three separate source byte strings and their authenticated metadata."""

    vacancy_snapshot_bytes: bytes
    raw_listing_bytes: bytes
    visible_listing_text_bytes: bytes
    vacancy_snapshot_metadata_bytes: bytes
    raw_listing_metadata_bytes: bytes
    projection_metadata_bytes: bytes


class TrustedReviewMaterialAccessor(Protocol):
    """Configured Market-owned accessor; callers cannot provide source text/time."""

    accessor_identity_sha256: str
    environment: str
    trust_root_id: str
    trusted_issuer_ids: frozenset[str]

    def resolve(self, *, request_bytes: bytes) -> ResolvedReviewMaterial:
        """Resolve the exact canonical request into separate protected bytes."""

    def authenticate(
        self,
        *,
        request_bytes: bytes,
        resolution: ResolvedReviewMaterial,
        projection_bytes: bytes,
        admission_context_bytes: bytes,
    ) -> None:
        """Authenticate all metadata proofs against configured protected state."""


@dataclass(frozen=True)
class ResolvedApplicationArtifacts:
    cv_pdf_bytes: bytes
    cover_letter_pdf_bytes: bytes


class TrustedApplicationArtifactAccessor(Protocol):
    """Resolve retained candidate-visible PDF bytes; digest claims are not data."""

    accessor_identity_sha256: str
    environment: str

    def resolve(
        self,
        *,
        application_id: str,
        application_source_identity: str,
        application_package_sha256: str,
    ) -> ResolvedApplicationArtifacts:
        """Return the exact retained PDF bytes for this application package."""

    def authenticate(
        self,
        *,
        application_id: str,
        application_source_identity: str,
        application_package_sha256: str,
        artifacts: ResolvedApplicationArtifacts,
    ) -> None:
        """Authenticate the artifact-store binding for the returned bytes."""


class DeterministicPDFTextExtractor(Protocol):
    extractor_id: str
    extractor_version: str

    def extract_text(self, pdf_bytes: bytes) -> str:
        """Extract deterministic text from exact PDF bytes."""


@dataclass(frozen=True)
class AssembledReviewMaterial:
    application_id: str
    application_source_identity: str
    environment: str
    evaluated_at: str
    evaluation_time_receipt_bytes: bytes
    evaluation_time_receipt_sha256: str
    request_bytes: bytes
    request_sha256: str
    vacancy_snapshot_bytes: bytes
    raw_listing_bytes: bytes
    projected_text_bytes: bytes
    review_text_sha256: str
    projection_bytes: bytes
    projection_sha256: str
    vacancy_snapshot_metadata_bytes: bytes
    raw_listing_metadata_bytes: bytes
    projection_metadata_bytes: bytes
    review_input_bytes: bytes
    review_input_sha256: str
    verification_receipt_bytes: bytes
    verification_receipt_sha256: str


@dataclass(frozen=True)
class _AdmissionReviewContext:
    application_id: str
    environment: str
    handoff_root_sha256: str
    job_key: str
    vacancy_snapshot_sha256: str
    raw_listing_sha256: str
    handoff_created_at: str
    admitted_at: str
    admission_context_bytes: bytes
    admission_context_sha256: str
    trust_root_id: str
    maximum_clock_skew_seconds: int


@dataclass(frozen=True)
class _MetadataEvidence:
    metadata_sha256: str
    valid_until: str


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ReviewMaterialError("invalid_digest", f"{label} must be lowercase SHA-256")
    return value


def _strict_identity(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise ReviewMaterialError("invalid_identity", f"{label} is invalid")
    return value


def _strict_json_scalars(value: object, label: str) -> None:
    if isinstance(value, str):
        if (
            "\x00" in value
            or unicodedata.normalize("NFC", value) != value
            or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
        ):
            raise ReviewMaterialError("noncanonical_scalar", f"{label} contains invalid text")
        return
    if type(value) is list:
        for item in value:
            _strict_json_scalars(item, label)
        return
    if type(value) is dict:
        for key, item in value.items():
            _strict_json_scalars(key, label)
            _strict_json_scalars(item, label)


def _decode(raw: bytes, label: str, *, maximum_bytes: int = MAX_WIRE_BYTES) -> Any:
    try:
        value = decode_canonical_json(raw, label=label, maximum_bytes=maximum_bytes)
    except HandoffContractError as exc:
        raise ReviewMaterialError("invalid_canonical_bytes", f"{label}: {exc.message}") from exc
    _strict_json_scalars(value, label)
    return value


def _timestamp(value: object, label: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ReviewMaterialError("invalid_timestamp", f"{label} must be whole-second UTC")
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReviewMaterialError("invalid_timestamp", f"{label} is not a real instant") from exc
    if instant.tzinfo != timezone.utc:
        raise ReviewMaterialError("invalid_timestamp", f"{label} must be UTC")
    return value, instant


def _exact_mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise ReviewMaterialError("schema_mismatch", f"{label} keys differ")
    return value


def _application_document(exact_bytes: bytes) -> dict[str, Any]:
    document = _exact_mapping(
        _decode(exact_bytes, "review application package"),
        {"cover_letter", "cv", "form_answers"},
        "review application package",
    )
    for role in ("cover_letter", "cv"):
        material = _exact_mapping(
            document[role], {"exact_pdf_sha256", "exact_pdf_text"}, f"{role} material"
        )
        _digest(material["exact_pdf_sha256"], f"{role} PDF")
        text = material["exact_pdf_text"]
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_DOCUMENT_TEXT_BYTES:
            raise ReviewMaterialError("application_text", f"{role} extracted text is invalid")
    answers = document["form_answers"]
    if type(answers) is not list or len(answers) > MAX_FORM_ANSWER_ROWS:
        raise ReviewMaterialError("form_answers", "form-answer row count is invalid")
    question_ids: list[str] = []
    for row in answers:
        answer = _exact_mapping(
            row, {"answer", "question", "question_id"}, "form-answer row"
        )
        for key in ("answer", "question", "question_id"):
            text = answer[key]
            if not isinstance(text, str) or (key != "answer" and not text):
                raise ReviewMaterialError("form_answers", f"form-answer {key} is invalid")
            if key in {"answer", "question"} and len(text.encode("utf-8")) > MAX_FORM_VALUE_BYTES:
                raise ReviewMaterialError("form_answers", f"form-answer {key} is oversized")
        question_ids.append(answer["question_id"])
    if len(question_ids) != len(set(question_ids)) or question_ids != sorted(question_ids):
        raise ReviewMaterialError(
            "form_answers", "form answers must use ascending unique question IDs"
        )
    return document


def _load_admission_context(
    store: HandoffAdmissionStore, application_id: str
) -> _AdmissionReviewContext:
    if not isinstance(store, HandoffAdmissionStore):
        raise TypeError("review assembler requires a HandoffAdmissionStore")
    with sqlite3.connect(store.database) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM application_admissions WHERE application_id=?", (application_id,)
        ).fetchone()
    if row is None:
        raise ReviewMaterialError("admission_missing", "application admission does not exist")
    if (
        row["sealed"] != 1
        or row["admission_kind"] != ADMISSION_KIND_V1
        or row["emission_profile"] != STRICT_EMISSION_PROFILE
        or row["environment"] not in {"production", "synthetic"}
        or row["authority_scope"] != row["environment"]
        or row["admission_context_bytes"] is None
        or row["admission_context_sha256"] is None
    ):
        raise ReviewMaterialError(
            "review_admission_blocked", "review requires a sealed authenticated strict-v1 admission"
        )

    original_bytes = bytes(row["original_bytes"])
    try:
        handoff = parse_handoff(original_bytes, require_strict_profile=True)
    except HandoffContractError as exc:
        raise ReviewMaterialError("stored_admission_invalid", exc.message) from exc
    vacancy = handoff.payload["vacancy"]
    expected_row = {
        "application_id": handoff.application_id,
        "handoff_root_sha256": handoff.root_sha256,
        "job_key": handoff.payload["job_key"],
        "original_bytes_sha256": handoff.root_sha256,
        "payload_sha256": handoff.payload_sha256,
        "vacancy_snapshot_sha256": vacancy["vacancy_snapshot_sha256"],
    }
    if any(row[key] != value for key, value in expected_row.items()):
        raise ReviewMaterialError("stored_admission_invalid", "stored handoff identity differs")

    context_bytes = bytes(row["admission_context_bytes"])
    context_sha256 = hashlib.sha256(context_bytes).hexdigest()
    if context_sha256 != row["admission_context_sha256"]:
        raise ReviewMaterialError("stored_admission_invalid", "admission context digest differs")
    context = _exact_mapping(
        _decode(context_bytes, "stored admission context"),
        {
            "environment",
            "handoff_root_sha256",
            "issued_at",
            "producer_commit_sha",
            "producer_product",
            "source_record_sha256",
            "trust_mode",
            "trust_proof_sha256",
            "trust_root_id",
        },
        "stored admission context",
    )
    if (
        context["environment"] != row["environment"]
        or context["handoff_root_sha256"] != handoff.root_sha256
        or context["trust_root_id"] != row["trust_root_id"]
        or context["trust_mode"] != row["trust_mode"]
        or context["producer_product"] != "market-aligner"
        or context["producer_commit_sha"] != handoff.payload["producer"]["commit_sha"]
    ):
        raise ReviewMaterialError("stored_admission_invalid", "admission context binding differs")
    _timestamp(context["issued_at"], "admission context issued_at")
    _digest(context["source_record_sha256"], "admission source record")
    _digest(context["trust_proof_sha256"], "admission trust proof")
    trust_root_id = _strict_identity(context["trust_root_id"], "admission trust root")

    verification_bytes = bytes(row["verification_receipt_bytes"])
    if hashlib.sha256(verification_bytes).hexdigest() != row["verification_receipt_sha256"]:
        raise ReviewMaterialError("stored_admission_invalid", "verification receipt digest differs")
    verification = _exact_mapping(
        _decode(verification_bytes, "stored admission verification"),
        {
            "admission_context_sha256",
            "admission_kind",
            "admitted_at",
            "authority_scope",
            "consumer_contract_bundle_sha256",
            "context_authenticator_sha256",
            "current_time_receipt_sha256",
            "emission_profile",
            "environment",
            "handoff_root_sha256",
            "payload_sha256",
            "references",
            "schema_version",
            "consumer_freshness_policy",
            "trust_mode",
            "trust_root_id",
        },
        "stored admission verification",
    )
    receipt_expected = {
        "admission_context_sha256": context_sha256,
        "admission_kind": ADMISSION_KIND_V1,
        "admitted_at": row["admitted_at"],
        "authority_scope": row["authority_scope"],
        "context_authenticator_sha256": row["context_authenticator_sha256"],
        "emission_profile": STRICT_EMISSION_PROFILE,
        "environment": row["environment"],
        "handoff_root_sha256": handoff.root_sha256,
        "payload_sha256": handoff.payload_sha256,
        "schema_version": VERIFICATION_SCHEMA,
        "trust_mode": row["trust_mode"],
        "trust_root_id": trust_root_id,
    }
    if any(verification.get(key) != value for key, value in receipt_expected.items()):
        raise ReviewMaterialError("stored_admission_invalid", "verification receipt binding differs")
    _digest(
        verification["current_time_receipt_sha256"],
        "admission current-time receipt",
    )
    if verification["consumer_contract_bundle_sha256"] != list(CONTRACT_BUNDLE_SHA256):
        raise ReviewMaterialError("contract_bundle_stale", "verification receipt contract bundle differs")
    if (
        type(verification["references"]) is not list
        or len(verification["references"]) != row["reference_count"]
    ):
        raise ReviewMaterialError("stored_admission_invalid", "verification reference set differs")
    rules_document = _exact_mapping(
        verification["consumer_freshness_policy"],
        {
            "clock_skew_seconds",
            "employer_dossier_required",
            "maximum_dossier_age_seconds",
            "maximum_vacancy_age_seconds",
        },
        "consumer freshness policy",
    )
    try:
        rules = SelectionPolicyRules(
            rules_document["clock_skew_seconds"],
            rules_document["maximum_vacancy_age_seconds"],
            rules_document["maximum_dossier_age_seconds"],
            rules_document["employer_dossier_required"],
        )
    except (TypeError, ValueError) as exc:
        raise ReviewMaterialError("stored_admission_invalid", "consumer freshness policy differs") from exc
    if not 0 <= rules.clock_skew_seconds <= MAX_SAFE_INTEGER:
        raise ReviewMaterialError("stored_admission_invalid", "selection-policy skew is invalid")
    handoff_created_at, _ = _timestamp(handoff.payload["created_at"], "handoff created_at")
    admitted_at, _ = _timestamp(row["admitted_at"], "admission admitted_at")
    return _AdmissionReviewContext(
        application_id=handoff.application_id,
        environment=str(row["environment"]),
        handoff_root_sha256=handoff.root_sha256,
        job_key=str(handoff.payload["job_key"]),
        vacancy_snapshot_sha256=str(vacancy["vacancy_snapshot_sha256"]),
        raw_listing_sha256=str(vacancy["raw_listing_sha256"]),
        handoff_created_at=handoff_created_at,
        admitted_at=admitted_at,
        admission_context_bytes=context_bytes,
        admission_context_sha256=context_sha256,
        trust_root_id=trust_root_id,
        maximum_clock_skew_seconds=rules.clock_skew_seconds,
    )


def _validate_metadata(
    metadata_bytes: bytes,
    *,
    exact_bytes: bytes,
    reference_key: str,
    type_id: str,
    schema_version: str,
    subject: Mapping[str, str],
    trust_root_id: str,
    trusted_issuer_ids: frozenset[str],
    evaluated_at: str,
    handoff_created_at: str | None,
    expected_valid_until: str | None = None,
) -> _MetadataEvidence:
    metadata = _exact_mapping(
        _decode(metadata_bytes, f"{reference_key} metadata"),
        _METADATA_KEYS,
        f"{reference_key} metadata",
    )
    expected = {
        "object_sha256": hashlib.sha256(exact_bytes).hexdigest(),
        "reference_key": reference_key,
        "schema_version": schema_version,
        "subject": dict(subject),
        "trust_root_id": trust_root_id,
        "type_id": type_id,
    }
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ReviewMaterialError("metadata_substitution", f"{reference_key} metadata differs")
    _strict_identity(metadata["issuer_id"], f"{reference_key} issuer")
    if metadata["issuer_id"] not in trusted_issuer_ids:
        raise ReviewMaterialError("metadata_issuer", f"{reference_key} issuer is not trusted")
    _digest(metadata["trust_proof_sha256"], f"{reference_key} trust proof")
    _, issued = _timestamp(metadata["issued_at"], f"{reference_key} issued_at")
    evaluated_text, evaluated = _timestamp(evaluated_at, "review evaluated_at")
    if metadata["valid_until"] is None:
        raise ReviewMaterialError("metadata_freshness", f"{reference_key} lacks valid_until")
    valid_until, valid = _timestamp(metadata["valid_until"], f"{reference_key} valid_until")
    if expected_valid_until is not None and valid_until != expected_valid_until:
        raise ReviewMaterialError("metadata_freshness", f"{reference_key} validity differs")
    if issued > evaluated or not evaluated < valid:
        raise ReviewMaterialError("metadata_freshness", f"{reference_key} is not current")
    if handoff_created_at is not None:
        _, created = _timestamp(handoff_created_at, "handoff created_at")
        if issued > created or not created < valid:
            raise ReviewMaterialError("metadata_freshness", f"{reference_key} was not valid at handoff")
    assert evaluated_text == evaluated_at
    return _MetadataEvidence(hashlib.sha256(metadata_bytes).hexdigest(), valid_until)


def _project_visible_text(exact_bytes: bytes) -> tuple[bytes, str]:
    if type(exact_bytes) is not bytes:
        raise ReviewMaterialError("review_text_type", "visible listing text must be exact bytes")
    if not exact_bytes:
        raise ReviewMaterialError("review_text_empty", "visible listing text is empty")
    if len(exact_bytes) > MAX_REVIEW_TEXT_BYTES:
        raise ReviewMaterialError("review_text_too_large", "visible listing text exceeds 500000 bytes")
    try:
        text = exact_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReviewMaterialError("review_text_utf8", "visible listing text is not UTF-8") from exc
    if "\ufeff" in text:
        raise ReviewMaterialError("review_text_bom", "visible listing text contains a BOM")
    if "\x00" in text:
        raise ReviewMaterialError("review_text_nul", "visible listing text contains NUL")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in text):
        raise ReviewMaterialError("review_text_scalar", "visible listing text has an isolated surrogate")
    projected = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    projected_bytes = projected.encode("utf-8")
    if not projected_bytes or len(projected_bytes) > MAX_REVIEW_TEXT_BYTES:
        raise ReviewMaterialError("review_text_too_large", "projected listing text is invalid")
    return projected_bytes, hashlib.sha256(projected_bytes).hexdigest()


class ReviewMaterialAssembler:
    """Build one exact employer-review input from fresh trusted listing material."""

    def __init__(
        self,
        admission_store: HandoffAdmissionStore,
        *,
        accessor: TrustedReviewMaterialAccessor,
        application_artifact_accessor: TrustedApplicationArtifactAccessor,
        pdf_text_extractor: DeterministicPDFTextExtractor,
        current_time_witness: AuthenticatedCurrentTimeWitness,
    ) -> None:
        self.admission_store = admission_store
        self.accessor = accessor
        self.application_artifact_accessor = application_artifact_accessor
        self.pdf_text_extractor = pdf_text_extractor
        self.current_time_witness = current_time_witness
        validate_current_time_witness_configuration(
            current_time_witness,
            environment=getattr(current_time_witness, "environment", ""),
        )
        if admission_store.current_time_witness is not current_time_witness:
            raise ValueError(
                "review assembler and admission store must share the current-time witness"
            )

    def _validate_boundary_and_persist_time(
        self,
        evidence: AuthenticatedTimeEvidence,
        *,
        application_id: str,
        handoff_root_sha256: str,
        request_sha256: str,
    ) -> None:
        """Revalidate the complete graph and consume time in one DB transaction.

        The concrete witness prevents replay within one process.  This shared,
        immutable row closes the restart boundary and deliberately remains even
        when the subsequent review-material accessor fails.
        """

        connection = sqlite3.connect(self.admission_store.database, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("BEGIN IMMEDIATE")
            source = self.admission_store.for_boundary_in_transaction(
                connection,
                application_id,
                "review",
                time_evidence=evidence,
                expected_time_purpose=REVIEW_TIME_PURPOSE,
                expected_time_subject_sha256=handoff_root_sha256,
            )
            if (
                source.application_id != application_id
                or source.handoff_root_sha256 != handoff_root_sha256
                or source.current_boundary != "review"
            ):
                raise ReviewMaterialError(
                    "boundary_substitution", "review boundary differs from stored admission"
                )
            connection.execute(
                """INSERT INTO authenticated_time_evidence(
                     receipt_sha256,receipt_bytes,environment,purpose,
                     subject_sha256,evaluated_at,witness_identity_sha256,
                     trust_root_id,consumer_kind,consumer_id
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence.receipt_sha256,
                    sqlite3.Binary(evidence.receipt_bytes),
                    evidence.environment,
                    evidence.purpose,
                    evidence.subject_sha256,
                    evidence.evaluated_at,
                    evidence.witness_identity_sha256,
                    evidence.trust_root_id,
                    "review_request",
                    request_sha256,
                ),
            )
            connection.commit()
        except ReviewMaterialError:
            connection.rollback()
            raise
        except HandoffAdmissionError as exc:
            connection.rollback()
            raise ReviewMaterialError(exc.code, exc.message) from exc
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ReviewMaterialError(
                "time_replay", "review time receipt or request was already consumed"
            ) from exc
        except sqlite3.Error as exc:
            connection.rollback()
            raise ReviewMaterialError(
                "time_persistence", "review time evidence could not be persisted"
            ) from exc
        finally:
            connection.close()

    def assemble(
        self,
        application_id: str,
        *,
        application_source_identity: str,
        application_package_bytes: bytes,
    ) -> AssembledReviewMaterial:
        """Assemble without accepting caller listing material or ``evaluated_at``."""

        application_source_identity = _digest(
            application_source_identity, "application source identity"
        )
        application_document = _application_document(application_package_bytes)
        application_package_sha256 = hashlib.sha256(
            application_package_bytes
        ).hexdigest()
        context = _load_admission_context(self.admission_store, application_id)

        artifact_accessor_identity = _digest(
            getattr(
                self.application_artifact_accessor,
                "accessor_identity_sha256",
                None,
            ),
            "application artifact accessor identity",
        )
        if (
            getattr(self.application_artifact_accessor, "environment", None)
            != context.environment
        ):
            raise ReviewMaterialError(
                "artifact_accessor_environment",
                "application artifact accessor environment differs",
            )
        extractor_id = _strict_identity(
            getattr(self.pdf_text_extractor, "extractor_id", None),
            "PDF extractor ID",
        )
        extractor_version = _strict_identity(
            getattr(self.pdf_text_extractor, "extractor_version", None),
            "PDF extractor version",
        )
        if (extractor_id, extractor_version) != PDF_EXTRACTOR_ALLOWLIST[
            context.environment
        ]:
            raise ReviewMaterialError(
                "application_pdf_extractor",
                "PDF extractor identity/version is not allowlisted for this environment",
            )
        try:
            artifacts = self.application_artifact_accessor.resolve(
                application_id=application_id,
                application_source_identity=application_source_identity,
                application_package_sha256=application_package_sha256,
            )
        except ReviewMaterialError:
            raise
        except Exception as exc:
            raise ReviewMaterialError(
                "artifact_resolution", "application artifact resolution failed"
            ) from exc
        if type(artifacts) is not ResolvedApplicationArtifacts:
            raise ReviewMaterialError(
                "artifact_contract", "application artifact accessor returned the wrong type"
            )
        artifact_bindings: dict[str, dict[str, str]] = {}
        for role, pdf_bytes in (
            ("cover_letter", artifacts.cover_letter_pdf_bytes),
            ("cv", artifacts.cv_pdf_bytes),
        ):
            if (
                type(pdf_bytes) is not bytes
                or not pdf_bytes
                or len(pdf_bytes) > MAX_PDF_BYTES
            ):
                raise ReviewMaterialError(
                    "application_pdf", f"{role} exact PDF bytes are invalid"
                )
            pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
            if pdf_sha256 != application_document[role]["exact_pdf_sha256"]:
                raise ReviewMaterialError(
                    "application_pdf_digest", f"{role} PDF bytes differ from the package"
                )
            try:
                extracted_text = self.pdf_text_extractor.extract_text(pdf_bytes)
            except Exception as exc:
                raise ReviewMaterialError(
                    "application_pdf_extraction", f"{role} PDF extraction failed"
                ) from exc
            if type(extracted_text) is not str:
                raise ReviewMaterialError(
                    "application_pdf_extraction", f"{role} extractor returned the wrong type"
                )
            _strict_json_scalars(extracted_text, f"{role} extracted text")
            if (
                len(extracted_text.encode("utf-8")) > MAX_DOCUMENT_TEXT_BYTES
                or extracted_text != application_document[role]["exact_pdf_text"]
            ):
                raise ReviewMaterialError(
                    "application_pdf_text", f"{role} extracted text differs from the package"
                )
            artifact_bindings[role] = {
                "pdf_sha256": pdf_sha256,
                "text_sha256": hashlib.sha256(
                    extracted_text.encode("utf-8")
                ).hexdigest(),
            }
        try:
            self.application_artifact_accessor.authenticate(
                application_id=application_id,
                application_source_identity=application_source_identity,
                application_package_sha256=application_package_sha256,
                artifacts=artifacts,
            )
        except ReviewMaterialError:
            raise
        except Exception as exc:
            raise ReviewMaterialError(
                "artifact_authentication", "application artifact proof is not trusted"
            ) from exc
        form_answers_sha256 = hashlib.sha256(
            canonical_json_bytes(
                {
                    "answers": application_document["form_answers"],
                    "schema_version": "jaa.form-answers.v1",
                }
            )
        ).hexdigest()

        accessor_identity = _digest(
            getattr(self.accessor, "accessor_identity_sha256", None), "accessor identity"
        )
        if getattr(self.accessor, "environment", None) != context.environment:
            raise ReviewMaterialError("accessor_environment", "accessor environment differs")
        if getattr(self.accessor, "trust_root_id", None) != context.trust_root_id:
            raise ReviewMaterialError("accessor_trust", "accessor trust root differs")
        trusted_issuer_ids = getattr(self.accessor, "trusted_issuer_ids", None)
        if type(trusted_issuer_ids) is not frozenset or not trusted_issuer_ids:
            raise ReviewMaterialError("accessor_issuers", "accessor issuer allowlist is absent or invalid")
        for issuer in trusted_issuer_ids:
            _strict_identity(issuer, "accessor trusted issuer")
        try:
            time_evidence = obtain_current_time(
                self.current_time_witness,
                environment=context.environment,
                purpose=REVIEW_TIME_PURPOSE,
                subject_sha256=context.handoff_root_sha256,
                maximum_clock_skew_seconds=context.maximum_clock_skew_seconds,
            )
        except CurrentTimeWitnessError as exc:
            raise ReviewMaterialError(exc.code, exc.message) from exc
        _, admitted = _timestamp(context.admitted_at, "admission admitted_at")
        if time_evidence.instant < admitted:
            raise ReviewMaterialError("time_backdated", "review time predates admission")

        request_bytes = canonical_json_bytes(
            {
                "admission_context_sha256": context.admission_context_sha256,
                "evaluated_at": time_evidence.evaluated_at,
                "evaluation_time_receipt_sha256": time_evidence.receipt_sha256,
                "handoff_root_sha256": context.handoff_root_sha256,
                "job_key": context.job_key,
                "raw_listing_sha256": context.raw_listing_sha256,
                "schema_version": REVIEW_MATERIAL_REQUEST_SCHEMA,
                "vacancy_snapshot_sha256": context.vacancy_snapshot_sha256,
            }
        )
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        self._validate_boundary_and_persist_time(
            time_evidence,
            application_id=context.application_id,
            handoff_root_sha256=context.handoff_root_sha256,
            request_sha256=request_sha256,
        )
        try:
            resolution = self.accessor.resolve(request_bytes=request_bytes)
        except ReviewMaterialError:
            raise
        except Exception as exc:
            raise ReviewMaterialError("accessor_resolution", "review accessor failed") from exc
        if not isinstance(resolution, ResolvedReviewMaterial):
            raise ReviewMaterialError("accessor_contract", "review accessor returned the wrong type")
        for value, label in (
            (resolution.vacancy_snapshot_bytes, "vacancy snapshot"),
            (resolution.raw_listing_bytes, "raw listing"),
        ):
            if type(value) is not bytes or not value or len(value) > MAX_WIRE_BYTES:
                raise ReviewMaterialError("source_bytes", f"{label} exact bytes are invalid")
        if hashlib.sha256(resolution.vacancy_snapshot_bytes).hexdigest() != context.vacancy_snapshot_sha256:
            raise ReviewMaterialError("source_digest", "vacancy snapshot bytes differ")
        if hashlib.sha256(resolution.raw_listing_bytes).hexdigest() != context.raw_listing_sha256:
            raise ReviewMaterialError("source_digest", "raw listing bytes differ")

        source_subject = {
            "job_key": context.job_key,
            "vacancy_snapshot_sha256": context.vacancy_snapshot_sha256,
        }
        snapshot_evidence = _validate_metadata(
            resolution.vacancy_snapshot_metadata_bytes,
            exact_bytes=resolution.vacancy_snapshot_bytes,
            reference_key="vacancy.snapshot",
            type_id="vacancy_snapshot",
            schema_version="market-aligner.vacancy-snapshot.v1",
            subject=source_subject,
            trust_root_id=context.trust_root_id,
            trusted_issuer_ids=trusted_issuer_ids,
            evaluated_at=time_evidence.evaluated_at,
            handoff_created_at=context.handoff_created_at,
        )
        raw_evidence = _validate_metadata(
            resolution.raw_listing_metadata_bytes,
            exact_bytes=resolution.raw_listing_bytes,
            reference_key="vacancy.raw_listing",
            type_id="raw_listing",
            schema_version="market-aligner.raw-listing-evidence.v1",
            subject=source_subject,
            trust_root_id=context.trust_root_id,
            trusted_issuer_ids=trusted_issuer_ids,
            evaluated_at=time_evidence.evaluated_at,
            handoff_created_at=context.handoff_created_at,
            expected_valid_until=snapshot_evidence.valid_until,
        )

        projected_text_bytes, review_text_sha256 = _project_visible_text(
            resolution.visible_listing_text_bytes
        )
        projection_document = {
            "job_key": context.job_key,
            "projection_id": REVIEW_TEXT_PROJECTION_ID,
            "raw_listing_sha256": context.raw_listing_sha256,
            "review_text_sha256": review_text_sha256,
            "schema_version": REVIEW_TEXT_PROJECTION_SCHEMA,
            "vacancy_snapshot_sha256": context.vacancy_snapshot_sha256,
        }
        projection_bytes = canonical_json_bytes(projection_document)
        projection_sha256 = hashlib.sha256(projection_bytes).hexdigest()
        projection_subject = {
            "handoff_root_sha256": context.handoff_root_sha256,
            "job_key": context.job_key,
            "raw_listing_sha256": context.raw_listing_sha256,
            "review_text_sha256": review_text_sha256,
            "vacancy_snapshot_sha256": context.vacancy_snapshot_sha256,
        }
        projection_evidence = _validate_metadata(
            resolution.projection_metadata_bytes,
            exact_bytes=projection_bytes,
            reference_key="vacancy.review_text_projection",
            type_id="review_text_projection",
            schema_version=REVIEW_TEXT_PROJECTION_SCHEMA,
            subject=projection_subject,
            trust_root_id=context.trust_root_id,
            trusted_issuer_ids=trusted_issuer_ids,
            evaluated_at=time_evidence.evaluated_at,
            handoff_created_at=None,
            expected_valid_until=snapshot_evidence.valid_until,
        )
        try:
            self.accessor.authenticate(
                request_bytes=request_bytes,
                resolution=resolution,
                projection_bytes=projection_bytes,
                admission_context_bytes=context.admission_context_bytes,
            )
        except ReviewMaterialError:
            raise
        except Exception as exc:
            raise ReviewMaterialError(
                "accessor_authentication", "review accessor proof is not trusted"
            ) from exc

        review_input_bytes = canonical_json_bytes(
            {
                "application": application_document,
                "job_listing": {
                    "exact_text": projected_text_bytes.decode("utf-8"),
                    "sha256": review_text_sha256,
                },
                "schema_version": EMPLOYER_REVIEW_INPUT_SCHEMA,
            }
        )
        review_input_sha256 = hashlib.sha256(review_input_bytes).hexdigest()
        verification_receipt_bytes = canonical_json_bytes(
            {
                "accessor_identity_sha256": accessor_identity,
                "admission_context_sha256": context.admission_context_sha256,
                "application_artifact_accessor_identity_sha256": artifact_accessor_identity,
                "application_package_sha256": application_package_sha256,
                "application_source_identity": application_source_identity,
                "cover_letter_pdf_sha256": artifact_bindings["cover_letter"]["pdf_sha256"],
                "cover_letter_pdf_text_sha256": artifact_bindings["cover_letter"]["text_sha256"],
                "consumer_contract_bundle_sha256": list(CONTRACT_BUNDLE_SHA256),
                "environment": context.environment,
                "evaluated_at": time_evidence.evaluated_at,
                "evaluation_time_receipt_sha256": time_evidence.receipt_sha256,
                "form_answers_sha256": form_answers_sha256,
                "handoff_root_sha256": context.handoff_root_sha256,
                "raw_listing_metadata_sha256": raw_evidence.metadata_sha256,
                "raw_listing_sha256": context.raw_listing_sha256,
                "pdf_extractor_id": extractor_id,
                "pdf_extractor_version": extractor_version,
                "request_sha256": request_sha256,
                "review_input_sha256": review_input_sha256,
                "review_text_projection_metadata_sha256": projection_evidence.metadata_sha256,
                "review_text_projection_sha256": projection_sha256,
                "review_text_sha256": review_text_sha256,
                "cv_pdf_sha256": artifact_bindings["cv"]["pdf_sha256"],
                "cv_pdf_text_sha256": artifact_bindings["cv"]["text_sha256"],
                "schema_version": REVIEW_MATERIAL_RECEIPT_SCHEMA,
                "trust_root_id": context.trust_root_id,
                "vacancy_snapshot_metadata_sha256": snapshot_evidence.metadata_sha256,
                "vacancy_snapshot_sha256": context.vacancy_snapshot_sha256,
                "witness_identity_sha256": time_evidence.witness_identity_sha256,
            }
        )
        return AssembledReviewMaterial(
            application_id=context.application_id,
            application_source_identity=application_source_identity,
            environment=context.environment,
            evaluated_at=time_evidence.evaluated_at,
            evaluation_time_receipt_bytes=time_evidence.receipt_bytes,
            evaluation_time_receipt_sha256=time_evidence.receipt_sha256,
            request_bytes=request_bytes,
            request_sha256=request_sha256,
            vacancy_snapshot_bytes=resolution.vacancy_snapshot_bytes,
            raw_listing_bytes=resolution.raw_listing_bytes,
            projected_text_bytes=projected_text_bytes,
            review_text_sha256=review_text_sha256,
            projection_bytes=projection_bytes,
            projection_sha256=projection_sha256,
            vacancy_snapshot_metadata_bytes=resolution.vacancy_snapshot_metadata_bytes,
            raw_listing_metadata_bytes=resolution.raw_listing_metadata_bytes,
            projection_metadata_bytes=resolution.projection_metadata_bytes,
            review_input_bytes=review_input_bytes,
            review_input_sha256=review_input_sha256,
            verification_receipt_bytes=verification_receipt_bytes,
            verification_receipt_sha256=hashlib.sha256(verification_receipt_bytes).hexdigest(),
        )


__all__ = [
    "AssembledReviewMaterial",
    "DeterministicPDFTextExtractor",
    "EMPLOYER_REVIEW_INPUT_SCHEMA",
    "MAX_REVIEW_TEXT_BYTES",
    "PDF_EXTRACTOR_ALLOWLIST",
    "REVIEW_MATERIAL_RECEIPT_SCHEMA",
    "REVIEW_MATERIAL_REQUEST_SCHEMA",
    "REVIEW_TEXT_PROJECTION_ID",
    "REVIEW_TEXT_PROJECTION_SCHEMA",
    "ResolvedApplicationArtifacts",
    "ResolvedReviewMaterial",
    "ReviewMaterialAssembler",
    "ReviewMaterialError",
    "TrustedApplicationArtifactAccessor",
    "TrustedReviewMaterialAccessor",
]
