"""Gutua production session backed by archived live-discovery evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Mapping
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import sync_playwright

from .application_archive import VacancyArchiveIdentity
from .application_artifacts import publish_application_artifacts
from .application_quality import (
    ApplicationQualityInput,
    build_deterministic_preflight_quality_review,
    review_application_package_with_pinned_skills,
)
from .application_quality_contracts import (
    ApplicationPreflightQualityReview,
    QualityReviewDisposition,
)
from .application_sanity_review import (
    ApplicationSanityReviewError,
    LocalSyntheticReviewContext,
    SanityReviewReceipt,
    build_local_synthetic_review_context,
    build_vacancy_review_material,
    package_from_application,
    review_application_package,
)
from .form_answers import source_form_answers
from .browser_executor import GreenhouseSuccessEvidence
from .ats_application_authority import build_ats_application_authority
from cv_generation.service import CandidateApplicationPackage
from .candidate_contact_authority import load_candidate_contact_authority
from .candidate_release_gate import (
    CandidateAuthorityFiles,
    CandidateAuthorityReleaseGate,
    POLICY_SHA256,
)
from .candidate_authority import (
    APPROVED_CANDIDATE_SOURCE_HASHES,
    APPROVED_EVIDENCE_IDS,
    AVAILABILITY_AUTHORITY,
    HARD_ELIGIBLE,
    HARD_INELIGIBLE,
    HARD_UNRESOLVED,
    JOBS_DATABASE_PATH,
    build_candidate_authority_document,
    fit_from_evidence_matrix,
)
from .evidence_matching import canonical_json, content_hash
from .external_document_assurance import (
    IntendedVacancy,
    assert_application_artifacts,
)
from .gmail_confirmation import ACCESS_TOKEN_ENV, GmailAPIConfirmationChecker
from .live_vacancy_discovery import verify_vacancy_body_equivalence
from .production_attempt import GreenhouseAttemptRecorder, ProductionIdentity
from .production_ats_executor import GREENHOUSE_HOSTS, ProductionATSBoundaryError
from .production_ats_executor import capture_or_recover_greenhouse_forensic_observation
from .production_ats_executor import compile_greenhouse_ats_plans
from .production_ats_executor import collect_greenhouse_form_inventory
from .production_ats_executor import greenhouse_ats_inventory_from_capture
from .production_ats_executor import is_greenhouse_auxiliary_field
from form_filling.ats_forensics import runtime_fingerprint, verify_forensic_receipt
from form_filling.service import approved_authority_values
from .production_queue import LiveVacancy, QueueItem
from .production_runner import (
    GeneratedRevisionSink,
    PreparedGreenhouseRelease,
    PreparedGreenhouseReview,
    ProductionRunCandidate,
)
from .market_aligner_preparation import MarketApplicationMaterializationContext
from .production_handoff_admission_runner import (
    run_production_handoff_admission,
    selected_published_handoffs,
)
from .production_preparation_runner import run_production_market_materialization
from .provider_observation_authority import load_provider_observation_authority
from .provider_observation_capture import exact_clean_head
from llm.client import LLMClient


DISCOVERY_ENV = "JAA_GREENHOUSE_DISCOVERY"
ELIGIBILITY_ENV = "JAA_GREENHOUSE_ELIGIBILITY"
CONTACT_ENV = "JAA_CANDIDATE_CONTACT_AUTHORITY"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class GreenhouseFormPlan:
    questions: dict[str, tuple[str, str]] | None
    answer_field_bindings: tuple[tuple[str, str], ...]
    review_form_fields: tuple[tuple[str, str, str], ...]
    form_field_authorities: tuple[tuple[str, str], ...]
    field_authority_names: tuple[tuple[str, str], ...]
    consent_states: tuple[tuple[str, bool | str], ...]
    inventory_sha256: str


@dataclass(frozen=True)
class PreparedLocalSyntheticDiagnostic:
    sanity_review_receipt: SanityReviewReceipt
    quality_review: ApplicationPreflightQualityReview
    diagnostic_context: LocalSyntheticReviewContext
    application_source_identity: str
    artifact_set_sha256: str
    native_fill_completed: bool = True
    production_admission: bool = False
    submission_authority: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.sanity_review_receipt) is not SanityReviewReceipt
            or self.sanity_review_receipt.schema_version
            != "jaa.application-sanity-local-diagnostic-receipt.v1"
            or type(self.diagnostic_context) is not LocalSyntheticReviewContext
            or self.native_fill_completed is not True
            or self.production_admission is not False
            or self.submission_authority is not False
            or self.application_source_identity
            != self.diagnostic_context.application_source_identity
            or not HEX_64.fullmatch(self.artifact_set_sha256)
        ):
            raise ValueError("local synthetic preparation result is not diagnostic-only")
CANDIDATE_SCHEMA_SHA256 = (
    "338bd48974f07266003aee510f42286ef29285e007515e73f41900069468367f"
)
CANDIDATE_POLICY_SHA256 = (
    "0cc512ec28d22921ce60832294070e2e9c8c3ad3f0c4d8b7fe214aca8f471fd0"
)


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _store_market_candidate_authority(archive_root: Path, value: bytes) -> Path:
    if not isinstance(value, bytes):
        raise TypeError("market candidate authority must be exact bytes")
    digest = hashlib.sha256(value).hexdigest()
    directory = archive_root / "candidate-authorities"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("candidate authority archive directory is unsafe")
    directory.chmod(0o700)
    path = directory / f"{digest}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        if path.is_symlink() or not path.is_file() or path.read_bytes() != value:
            raise ValueError("content-addressed market candidate authority differs")
        if path.stat().st_mode & 0o777 != 0o600:
            raise ValueError("market candidate authority permissions differ")
        return path
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if _file_sha256(path) != digest:
        raise ValueError("stored market candidate authority hash differs")
    return path


def _require_lowest_ranked_market_handoff(
    context: MarketApplicationMaterializationContext,
    rows: list[dict[str, object]],
) -> dict[str, object]:
    from market_aligner.assessment.geography import selection_sort_key

    if len(rows) < 2:
        raise ValueError(
            "a Market canary requires at least two verified selected handoffs"
        )
    application_ids = [row.get("application_id") for row in rows]
    if any(not isinstance(value, str) for value in application_ids) or len(
        set(application_ids)
    ) != len(application_ids):
        raise ValueError("verified Market selections contain ambiguous application IDs")
    try:
        expected_order = sorted(
            rows,
            key=lambda row: (
                *selection_sort_key(
                    row["geography_rank"],
                    row["final_score"],
                    row["opportunity"],
                    row["job_key"],
                ),
                row["application_id"],
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("verified Market selection ranking is malformed") from exc
    if rows != expected_order:
        raise ValueError("verified Market selections are not in canonical rank order")
    matching = [
        row for row in rows if row.get("application_id") == context.application_id
    ]
    if len(matching) != 1:
        raise ValueError("admitted MA application is absent from verified selections")
    selected = matching[0]
    authority = context.market_decision_authority
    if (
        selected.get("handoff_root_sha256") != authority.handoff_root_sha256
        or selected.get("candidate_intent_sha256") != context.candidate_intent_sha256
        or selected.get("geography_rank") != context.geography_priority_rank
        or selected.get("final_score") != context.final_score
        or selected.get("opportunity") != context.opportunity_score
        or selected.get("release_authority") is not False
        or selected.get("submission_authority") is not False
    ):
        raise ValueError("admitted MA ranking differs from verified selection")
    if rows[-1].get("application_id") != context.application_id:
        raise ValueError("MA canary must be the lowest-ranked selected handoff")
    return selected


def _vacancy_description_hashes(job_keys: set[str]) -> dict[str, str]:
    path = JOBS_DATABASE_PATH.resolve(strict=True)
    if _file_sha256(path) != APPROVED_CANDIDATE_SOURCE_HASHES["jobs_database"]:
        raise ValueError("approved jobs database content hash differs")
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        placeholders = ",".join("?" for _ in job_keys)
        rows = connection.execute(
            f"SELECT key, raw_json FROM postings WHERE key IN ({placeholders})",
            tuple(sorted(job_keys)),
        ).fetchall()
    finally:
        connection.close()
    descriptions: dict[str, str] = {}
    for key, raw_json in rows:
        document = json.loads(raw_json)
        description = document.get("content_text")
        if not isinstance(description, str) or not description.strip():
            raise ValueError("jobs database vacancy description is unavailable")
        descriptions[str(key)] = hashlib.sha256(description.encode()).hexdigest()
    if set(descriptions) != job_keys:
        raise ValueError("jobs database does not exactly cover candidate decisions")
    return descriptions


def _decision_receipt(
    row: Mapping[str, object],
    *,
    vacancy: Mapping[str, object],
    projection: Mapping[str, object],
    discovery_sha256: str,
    vacancy_description_sha256: str,
    duplicate_snapshot_sha256: str,
) -> tuple[bool, str, str]:
    receipt = row.get("receipt")
    if not isinstance(receipt, Mapping):
        raise ValueError("candidate authority decision receipt is missing")
    receipt_sha256 = _digest(row.get("receipt_sha256"), "decision receipt hash")
    if hashlib.sha256(_json_bytes(receipt)).hexdigest() != receipt_sha256:
        raise ValueError("candidate authority decision receipt hash differs")
    decision = receipt.get("decision")
    reasons = receipt.get("reasons")
    missing_facts = receipt.get("missing_facts")
    evidence_matrix = receipt.get("evidence_matrix")
    checks = receipt.get("eligibility_checks")
    required_checks = {
        "live_deadline",
        "uk_work_right",
        "sponsorship",
        "location_attendance",
        "mandatory_credentials",
        "duplicate_replay",
    }
    if not isinstance(checks, Mapping) or set(checks) != required_checks:
        raise ValueError("candidate authority eligibility checks are incomplete")
    check_statuses: list[str] = []
    for check in checks.values():
        if (
            not isinstance(check, Mapping)
            or check.get("status") not in {"pass", "fail", "unresolved"}
            or not isinstance(check.get("evidence_ids"), list)
            or not check["evidence_ids"]
        ):
            raise ValueError("candidate authority eligibility check is malformed")
        check_statuses.append(str(check["status"]))
    expected_decision = (
        "ineligible"
        if "fail" in check_statuses
        else "unresolved"
        if "unresolved" in check_statuses
        else "eligible"
    )
    job_key = str(vacancy.get("job_key"))
    duplicate_failed = checks["duplicate_replay"]["status"] == "fail"
    if duplicate_failed:
        policy_decision = "ineligible"
        policy_facts = {"prior_submission_or_click_intent_quarantine"}
    elif job_key in HARD_INELIGIBLE:
        policy_decision = "ineligible"
        policy_facts = HARD_INELIGIBLE[job_key]
    elif job_key in HARD_UNRESOLVED:
        policy_decision = "unresolved"
        policy_facts = HARD_UNRESOLVED[job_key]
    elif job_key in HARD_ELIGIBLE:
        policy_decision = "eligible"
        policy_facts = set()
    else:
        raise ValueError("candidate decision is outside the approved vacancy cohort")
    if (
        receipt.get("schema_version") != "jaa.candidate-vacancy-decision-receipt.v1"
        or receipt.get("job_key") != vacancy.get("job_key")
        or receipt.get("role_title") != vacancy.get("role_title")
        or receipt.get("company_name") != vacancy.get("company_name")
        or receipt.get("vacancy_sha256") != vacancy.get("vacancy_sha256")
        or receipt.get("discovery_body_sha256") != vacancy.get("vacancy_sha256")
        or receipt.get("discovery_sha256") != discovery_sha256
        or receipt.get("duplicate_snapshot_sha256") != duplicate_snapshot_sha256
        or receipt.get("source_url") != vacancy.get("source_url")
        or receipt.get("observed_at") != vacancy.get("live_verified_at")
        or receipt.get("vacancy_description_sha256") != vacancy_description_sha256
        or receipt.get("database_sha256")
        != APPROVED_CANDIDATE_SOURCE_HASHES["jobs_database"]
        or receipt.get("candidate_projection_sha256")
        != projection.get("projection_sha256")
        or receipt.get("schema_sha256") != projection.get("schema_sha256")
        or receipt.get("policy_sha256") != projection.get("policy_sha256")
        or receipt.get("source_hashes") != projection.get("source_hashes")
        or decision != expected_decision
        or decision != policy_decision
        or not isinstance(reasons, list)
        or not reasons
        or not all(isinstance(value, str) and value for value in reasons)
        or not isinstance(missing_facts, list)
        or not all(isinstance(value, str) and value for value in missing_facts)
        or not isinstance(evidence_matrix, list)
        or not evidence_matrix
    ):
        raise ValueError("candidate authority decision receipt bindings are incomplete")
    if policy_decision == "ineligible" and not policy_facts.issubset(set(reasons)):
        raise ValueError("ineligible decision omits mandatory policy reasons")
    if policy_decision == "unresolved" and set(missing_facts) != policy_facts:
        raise ValueError("unresolved decision differs from mandatory missing facts")
    requirement_ids: set[str] = set()
    for requirement in evidence_matrix:
        if (
            not isinstance(requirement, Mapping)
            or not isinstance(requirement.get("requirement_id"), str)
            or not requirement["requirement_id"]
            or requirement["requirement_id"] in requirement_ids
            or requirement.get("classification") not in {"essential", "desirable"}
            or not isinstance(requirement.get("requirement_text"), str)
            or not requirement["requirement_text"].strip()
            or not HEX_64.fullmatch(str(requirement.get("requirement_text_sha256", "")))
            or hashlib.sha256(str(requirement["requirement_text"]).encode()).hexdigest()
            != requirement["requirement_text_sha256"]
            or requirement.get("status")
            not in {"matched", "gap", "suppressed", "unresolved"}
            or not isinstance(requirement.get("evidence_ids"), list)
            or not isinstance(requirement.get("suppressor_ids"), list)
            or requirement.get("weight")
            != ("2" if requirement.get("classification") == "essential" else "1")
        ):
            raise ValueError("candidate authority evidence matrix is malformed")
        requirement_ids.add(str(requirement["requirement_id"]))
        evidence_ids = requirement["evidence_ids"]
        suppressor_ids = requirement["suppressor_ids"]
        if (
            (requirement["status"] == "matched") != bool(evidence_ids)
            or any(value not in APPROVED_EVIDENCE_IDS for value in evidence_ids)
            or (requirement["status"] == "suppressed") != bool(suppressor_ids)
            or any(
                not re.fullmatch(r"Q-[0-9]{3}", str(value)) for value in suppressor_ids
            )
        ):
            raise ValueError("candidate authority evidence status is inconsistent")
    fit = receipt.get("fit")
    if decision == "eligible":
        try:
            fit_value = Decimal(str(fit))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("eligible candidate fit is invalid") from exc
        if not fit_value.is_finite() or not Decimal("0") <= fit_value <= Decimal("1"):
            raise ValueError("eligible candidate fit is outside zero to one")
        if str(fit) != fit_from_evidence_matrix(evidence_matrix):
            raise ValueError("eligible candidate fit differs from evidence matrix")
        if missing_facts:
            raise ValueError("eligible candidate decision retains unresolved facts")
        return True, str(fit), receipt_sha256
    if fit is not None:
        raise ValueError("non-eligible candidate decision cannot carry fit")
    if decision == "unresolved" and not missing_facts:
        raise ValueError("unresolved candidate decision lacks missing facts")
    return False, "", receipt_sha256


def _required_file(environment_name: str) -> Path:
    value = os.environ.get(environment_name)
    if not value:
        raise ValueError(f"{environment_name} is required")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{environment_name} must name an absolute regular file")
    return path.resolve(strict=True)


class GutuaGreenhouseSession:
    def __init__(self, arguments) -> None:
        self.approved_evidence_path = getattr(
            arguments, "approved_evidence_path", None
        )
        market_receipt = getattr(arguments, "market_execution_receipt", None)
        if market_receipt is not None:
            self.archive_root = Path(arguments.archive_root).resolve(strict=True)
            self.repository_root = Path(arguments.repository_root).resolve(strict=True)
            self.market_context_by_key: dict[
                str, MarketApplicationMaterializationContext
            ] = {}
            self._initialize_market_execution(arguments, Path(market_receipt))
            return
        discovery_path = _required_file(DISCOVERY_ENV)
        eligibility_path = _required_file(ELIGIBILITY_ENV)
        discovery_bytes = discovery_path.read_bytes()
        eligibility_bytes = eligibility_path.read_bytes()
        discovery = json.loads(discovery_bytes)
        eligibility = json.loads(eligibility_bytes)
        discovery_sha256 = hashlib.sha256(discovery_bytes).hexdigest()
        if (
            discovery.get("schema_version") != "jaa.greenhouse-live-discovery.v2"
            or discovery.get("eligibility_authority") is not False
            or discovery.get("ranking_candidate_profile")
            not in {"empty", "candidate-authority-required"}
            or eligibility.get("schema_version")
            != "jaa.production-candidate-authority.v2"
            or eligibility.get("snapshot_sha256") != discovery.get("snapshot_sha256")
            or eligibility.get("discovery_sha256") != discovery_sha256
        ):
            raise ValueError(
                "live discovery requires non-empty, receipt-bound candidate authority"
            )
        if eligibility_bytes != _json_bytes(eligibility):
            raise ValueError("candidate authority document is not canonical JSON")
        projection = eligibility.get("candidate_projection")
        claim_suppressors = (
            projection.get("claim_suppressors")
            if isinstance(projection, Mapping)
            else None
        )
        if (
            not isinstance(projection, Mapping)
            or projection.get("schema_version")
            != "jaa.candidate-authority-projection.v1"
            or projection.get("source_hashes") != APPROVED_CANDIDATE_SOURCE_HASHES
            or projection.get("schema_sha256") != CANDIDATE_SCHEMA_SHA256
            or projection.get("policy_sha256") != CANDIDATE_POLICY_SHA256
            or projection.get("availability") != AVAILABILITY_AUTHORITY
            or not isinstance(claim_suppressors, Mapping)
            or claim_suppressors.get("source_sha256")
            != APPROVED_CANDIDATE_SOURCE_HASHES["negative_claim_suppressors"]
            or claim_suppressors.get("mode") != "suppress_only"
            or not isinstance(claim_suppressors.get("items"), list)
            or tuple(
                row.get("id")
                for row in claim_suppressors["items"]
                if isinstance(row, Mapping)
            )
            != tuple(f"Q-{index:03d}" for index in range(1, 11))
            or any(
                not isinstance(row, Mapping)
                or not HEX_64.fullmatch(str(row.get("claim_sha256", "")))
                or not HEX_64.fullmatch(str(row.get("ruling_sha256", "")))
                for row in claim_suppressors["items"]
            )
            or not all(
                HEX_64.fullmatch(str(projection.get(key, "")))
                for key in (
                    "projection_sha256",
                    "schema_sha256",
                    "policy_sha256",
                )
            )
        ):
            raise ValueError("candidate authority projection is not approved")
        approved_evidence = projection.get("approved_evidence")
        if (
            not isinstance(approved_evidence, list)
            or tuple(
                row.get("id") for row in approved_evidence if isinstance(row, Mapping)
            )
            != APPROVED_EVIDENCE_IDS
            or any(
                not isinstance(row, Mapping)
                or not HEX_64.fullmatch(str(row.get("statement_sha256", "")))
                or row.get("kind")
                not in {
                    "credential",
                    "portfolio_artifact",
                    "employment_record",
                    "test_result",
                }
                or row.get("proof_class") != row.get("kind")
                for row in approved_evidence
            )
        ):
            raise ValueError("candidate authority approved evidence projection differs")
        projection_payload = {
            key: value
            for key, value in projection.items()
            if key != "projection_sha256"
        }
        if (
            hashlib.sha256(_json_bytes(projection_payload)).hexdigest()
            != (projection["projection_sha256"])
        ):
            raise ValueError("candidate authority projection hash differs")
        pending = discovery.get("live_pending_eligibility")
        decisions = eligibility.get("decisions")
        observations = discovery.get("observations")
        if (
            not all(
                isinstance(value, list) for value in (pending, decisions, observations)
            )
            or not pending
        ):
            raise ValueError("production discovery documents are malformed")
        duplicate_snapshot_sha256 = _digest(
            eligibility.get("duplicate_snapshot_sha256"),
            "duplicate snapshot hash",
        )
        decision_by_key = {str(row["job_key"]): row for row in decisions}
        observation_by_key = {str(row["job_key"]): row for row in observations}
        pending_keys = {str(row["job_key"]) for row in pending}
        if (
            len(decision_by_key) != len(decisions)
            or len(observation_by_key) != len(observations)
            or set(decision_by_key) != pending_keys
        ):
            raise ValueError("eligibility decisions must exactly cover live vacancies")
        archive_root = Path(arguments.archive_root).resolve(strict=True)
        repository_root = Path(arguments.repository_root).resolve(strict=True)
        self.archive_root = archive_root
        self.repository_root = repository_root
        self.market_context_by_key = {}
        expected_authority = build_candidate_authority_document(
            discovery_path=discovery_path,
            archive_root=archive_root,
            repository_root=repository_root,
        )
        if expected_authority != eligibility:
            raise ValueError(
                "candidate authority differs from deterministic current materialization"
            )
        description_hashes = _vacancy_description_hashes(pending_keys)
        self.archive_root = archive_root
        self.repository_root = repository_root
        self.discovery_path = discovery_path
        self.eligibility_path = eligibility_path
        self.candidate_projection = dict(projection)
        self.decision_by_key = decision_by_key
        object_root = archive_root / "objects"
        candidates: list[ProductionRunCandidate] = []
        for row in pending:
            job_key = str(row["job_key"])
            decision = decision_by_key[job_key]
            eligible, fit, receipt_sha256 = _decision_receipt(
                decision,
                vacancy=row,
                projection=projection,
                discovery_sha256=discovery_sha256,
                vacancy_description_sha256=description_hashes[job_key],
                duplicate_snapshot_sha256=duplicate_snapshot_sha256,
            )
            if not eligible:
                continue
            observation = observation_by_key[job_key]
            body_sha256 = str(observation["body_sha256"])
            body_path = object_root / body_sha256[:2] / body_sha256
            body = body_path.read_bytes()
            if body_sha256 != str(row["vacancy_sha256"]):
                raise ValueError("live candidate differs from its archived body")
            network_sha256 = str(observation["network_evidence_sha256"])
            network_path = object_root / network_sha256[:2] / network_sha256
            network = json.loads(network_path.read_bytes())
            events = network.get("events")
            if not isinstance(events, list) or not events:
                raise ValueError("live candidate lacks observed HTTP evidence")
            vacancy = VacancyArchiveIdentity(
                job_key=job_key,
                vacancy_sha256=body_sha256,
                role_title=str(row["role_title"]),
                company_name=str(row["company_name"]),
                source_url=str(row["source_url"]),
            )
            candidates.append(
                ProductionRunCandidate(
                    vacancy=LiveVacancy.create(
                        vacancy=vacancy,
                        provider="greenhouse",
                        fit_score=fit,
                        live=True,
                        eligible=True,
                        duplicate=False,
                        live_verified_at=str(row["live_verified_at"]),
                        scoring_inputs_sha256=receipt_sha256,
                    ),
                    complete_vacancy=body,
                    structured_vacancy={
                        "job_key": job_key,
                        "role_title": vacancy.role_title,
                        "company_name": vacancy.company_name,
                        "source_url": vacancy.source_url,
                        "live_observation": observation,
                    },
                    assessment={
                        "live": True,
                        "eligible": True,
                        "duplicate": False,
                        "fit_score": fit,
                        "candidate_authority_receipt": decision,
                    },
                    network_evidence=tuple(dict(event) for event in events),
                )
            )
        self.candidates = tuple(candidates)
        self.complete_vacancy_by_key = {
            candidate.vacancy.vacancy.job_key: candidate.complete_vacancy
            for candidate in self.candidates
        }
        self._start_browser(arguments)

    def _initialize_market_execution(self, arguments, execution_receipt: Path) -> None:
        if (
            not execution_receipt.is_absolute()
            or execution_receipt.is_symlink()
            or not execution_receipt.is_file()
        ):
            raise ValueError("Market execution receipt must be an absolute regular file")
        admission = run_production_handoff_admission(
            execution_receipt_path=execution_receipt
        )
        admission_document = admission.document()
        if (
            admission.operation not in {"created", "replay"}
            or admission.environment != "production"
            or admission_document.get("release_token_issued") is not False
            or admission_document.get("submission_authority") is not False
        ):
            raise ValueError("Market handoff admission did not retain the no-release boundary")
        context = run_production_market_materialization(
            application_id=admission.application_id
        )
        if type(context) is not MarketApplicationMaterializationContext:
            raise TypeError("production Market materializer returned an invalid context")
        authority = context.market_decision_authority
        if (
            context.application_id != admission.application_id
            or authority.handoff_root_sha256 != admission.handoff_root_sha256
            or authority.admission_receipt_sha256
            != admission.verification_receipt_sha256
        ):
            raise ValueError("Market materialization differs from admitted handoff")
        try:
            parsed_source = urlsplit(authority.source_url)
            supported_greenhouse_source = (
                parsed_source.scheme == "https"
                and parsed_source.hostname in GREENHOUSE_HOSTS
                and parsed_source.username is None
                and parsed_source.password is None
                and parsed_source.port is None
            )
        except ValueError:
            supported_greenhouse_source = False
        if not supported_greenhouse_source:
            raise ValueError(
                "the certified production runner supports only Greenhouse handoffs"
            )
        selected_rows = selected_published_handoffs(
            context.profile_id,
            profile_version=context.profile_version,
            candidate_intent_sha256=context.candidate_intent_sha256,
        )
        selected = _require_lowest_ranked_market_handoff(context, selected_rows)

        authority_path = _store_market_candidate_authority(
            self.archive_root, context.candidate_authority_bytes
        )
        job_key = authority.source_job_key
        if context.materialization.source.job_key != job_key:
            raise ValueError("materialized source differs from Market job identity")
        vacancy = VacancyArchiveIdentity(
            job_key=job_key,
            vacancy_sha256=authority.raw_listing_sha256,
            role_title=authority.role_title,
            company_name=authority.company_name,
            source_url=authority.source_url,
        )
        candidate = ProductionRunCandidate(
            vacancy=LiveVacancy.create(
                vacancy=vacancy,
                provider="greenhouse",
                fit_score=context.final_score / 100.0,
                live=True,
                eligible=True,
                duplicate=False,
                live_verified_at=context.source_observed_at,
                scoring_inputs_sha256=authority.assessment_receipt_sha256,
            ),
            complete_vacancy=context.raw_listing_bytes,
            structured_vacancy={
                "application_id": context.application_id,
                "candidate_intent_sha256": context.candidate_intent_sha256,
                "company_name": authority.company_name,
                "final_score": context.final_score,
                "geography_priority_rank": context.geography_priority_rank,
                "handoff_root_sha256": authority.handoff_root_sha256,
                "job_key": job_key,
                "market_admission": {
                    "admission_operation": admission.operation,
                    "admission_operation_receipt_sha256": (
                        admission.operation_receipt_sha256
                    ),
                    "execution_receipt_file_sha256": (
                        admission.execution_receipt_file_sha256
                    ),
                    "execution_receipt_semantic_sha256": (
                        admission.execution_receipt_semantic_sha256
                    ),
                    "verification_receipt_sha256": (
                        admission.verification_receipt_sha256
                    ),
                },
                "opportunity_score": context.opportunity_score,
                "role_title": authority.role_title,
                "selected_handoff": dict(selected),
                "selection_snapshot": [dict(row) for row in selected_rows],
                "source_observed_at": context.source_observed_at,
                "source_url": authority.source_url,
            },
            assessment={
                "live": True,
                "eligible": True,
                "duplicate": False,
                "fit_score": context.final_score,
                "candidate_authority_receipt": dict(context.decision_receipt),
            },
        )
        self.discovery_path = None
        self.eligibility_path = authority_path
        self.candidate_projection = dict(context.candidate_projection)
        self.decision_by_key = {
            job_key: {
                "receipt": dict(context.decision_receipt),
                "receipt_sha256": context.materialization.receipt.decision_receipt_sha256,
            }
        }
        self.market_context_by_key = {job_key: context}
        self.candidates = (candidate,)
        self.complete_vacancy_by_key = {job_key: context.raw_listing_bytes}
        self._start_browser(arguments)

    def _start_browser(self, arguments) -> None:
        self.gmail_confirmation_checker = (
            GmailAPIConfirmationChecker(repository_root=self.repository_root)
            if not getattr(arguments, "review_only", False)
            and os.environ.get(ACCESS_TOKEN_ENV)
            else None
        )
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)
        self.page = self._browser.new_page(
            **({"service_workers": "block"} if getattr(arguments, "review_only", False) else {})
        )

    def open_vacancy(self, item: QueueItem, page) -> Mapping[str, object] | None:
        response = page.goto(
            item.vacancy.vacancy.source_url,
            wait_until="domcontentloaded",
            timeout=30_000,
        )
        page.wait_for_timeout(500)
        if response is None:
            return None
        request = response.request
        redirected_from = request.redirected_from
        return {
            "url": response.url,
            "status": response.status,
            "method": request.method,
            "redirected_from": (
                redirected_from.url if redirected_from is not None else None
            ),
        }

    @staticmethod
    def _field_identity(field: Mapping[str, object]) -> str:
        identity = str(field.get("name") or field.get("id") or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", identity):
            raise ProductionATSBoundaryError(
                "employer-facing field lacks a stable supported identity"
            )
        return identity

    @staticmethod
    def _field_authority(field: Mapping[str, object]) -> str | None:
        labels = " ".join(str(value) for value in field.get("labels", []))
        text = f"{field.get('name', '')} {field.get('id', '')} {labels}".casefold()
        if "email" in text:
            return "contact.email"
        if "phone" in text or "telephone" in text:
            return "contact.phone"
        if "first" in text and "name" in text:
            return "contact.given_name"
        if ("last" in text or "family" in text) and "name" in text:
            return "contact.family_name"
        if "full name" in text or str(field.get("name")) in {"name", "full_name"}:
            return "contact.full_name"
        if re.search(r"\b(?:city|location)\b", text):
            return "contact.city"
        if "cover note" in text:
            return "answers.full"
        if "full legal name" in text:
            return "candidate.legal_name_complete"
        if "legal right to work in the uk" in text:
            return "candidate.uk_work_right"
        if "right to work status" in text:
            return "candidate.uk_work_status"
        if "how did you hear" in text:
            return "candidate.discovery_source"
        if "identify my gender" in text:
            return "candidate.gender_nondisclosure"
        if "what is your ethnicity" in text:
            return "candidate.ethnicity_nondisclosure"
        if "consider yourself to have a disability" in text:
            return "candidate.disability_nondisclosure"
        return None

    @staticmethod
    def _locator(page, identity: str):
        controls = "input, select, textarea"
        return page.locator(
            f'form :is({controls})[name="{identity}"], '
            f'form :is({controls})[id="{identity}"]'
        )

    @staticmethod
    def _select_dynamic_option(page, locator, *, identity: str, value: str) -> None:
        """Select one option from the exact dynamic control being filled.

        Greenhouse commonly renders several React comboboxes whose options repeat
        labels such as ``I don't wish to answer``.  A page-global role lookup can
        therefore be ambiguous even though each combobox has exactly one approved
        choice.  Prefer the listbox named by the input's ARIA relationship; older
        widgets without that relationship may use the sole visible matching option.
        """

        locator.fill(value)
        # React Select removes ``aria-controls`` while its menu is closed.
        # Filling searches the value but does not reliably reopen the menu;
        # ArrowDown establishes the exact input -> listbox relationship.
        locator.press("ArrowDown")
        controlled_id = locator.get_attribute("aria-controls")
        if controlled_id:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", controlled_id):
                raise ProductionATSBoundaryError(
                    "Greenhouse dynamic choice has an unsafe controlled identity"
                )
            listbox = page.locator(f'[id="{controlled_id}"]')
            if listbox.count() != 1:
                raise ProductionATSBoundaryError(
                    "Greenhouse dynamic choice does not control one listbox"
                )
            options = listbox.get_by_role("option", name=value, exact=True)
            visible_indexes = [
                index
                for index in range(options.count())
                if options.nth(index).is_visible()
            ]
            if len(visible_indexes) != 1:
                raise ProductionATSBoundaryError(
                    f"approved Greenhouse option is ambiguous for field {identity}"
                )
            options.nth(visible_indexes[0]).click()
            return

        options = page.get_by_role("option", name=value, exact=True)
        visible_indexes = [
            index for index in range(options.count()) if options.nth(index).is_visible()
        ]
        if len(visible_indexes) != 1:
            raise ProductionATSBoundaryError(
                f"approved Greenhouse option is ambiguous for field {identity}"
            )
        options.nth(visible_indexes[0]).click()

    def _fill_supported_form(
        self,
        page,
        package: CandidateApplicationPackage,
        *,
        artifact_directory: Path,
        recorder: GreenhouseAttemptRecorder | None = None,
        inventory_bytes: bytes | None = None,
        expected_form_plan: GreenhouseFormPlan | None = None,
    ) -> tuple[
        tuple[str, ...],
        tuple[tuple[str, str], ...],
        tuple[tuple[str, str], ...],
        tuple[tuple[str, bool | str], ...],
        dict[str, Path],
    ]:
        effective_inventory_bytes = (
            inventory_bytes
            if inventory_bytes is not None
            else collect_greenhouse_form_inventory(page)
        )
        inventory = json.loads(effective_inventory_bytes)
        fields = inventory["form_state"]["fields"]
        if not isinstance(fields, list):
            raise ProductionATSBoundaryError("Greenhouse form inventory is malformed")
        form_plan = self._plan_supported_form(package, effective_inventory_bytes)
        if expected_form_plan is not None and (
            form_plan.questions != expected_form_plan.questions
            or form_plan.answer_field_bindings != expected_form_plan.answer_field_bindings
            or form_plan.review_form_fields != expected_form_plan.review_form_fields
            or form_plan.form_field_authorities != expected_form_plan.form_field_authorities
            or form_plan.field_authority_names != expected_form_plan.field_authority_names
            or form_plan.consent_states != expected_form_plan.consent_states
        ):
            raise ProductionATSBoundaryError(
                "Greenhouse form changed after its sanity-reviewed plan"
            )
        identities: set[str] = set()
        field_authorities: list[tuple[str, str]] = []
        consents: list[tuple[str, bool | str]] = []
        uploads: dict[str, tuple[str, Path]] = {}
        approved = approved_authority_values(package.source, package.artifacts)
        planned_authorities = dict(form_plan.form_field_authorities)
        planned_consents = dict(form_plan.consent_states)
        select_inventories = {
            str(row["field_identity"]): row
            for row in inventory["select_inventories"]
            if isinstance(row, Mapping) and isinstance(row.get("field_identity"), str)
        }
        for field in fields:
            if not isinstance(field, Mapping):
                raise ProductionATSBoundaryError("Greenhouse field is malformed")
            field_type = str(field.get("type", "")).casefold()
            if field_type in {"hidden", "submit", "button", "reset"}:
                continue
            identity = self._field_identity(field)
            if identity in identities:
                raise ProductionATSBoundaryError(
                    "Greenhouse form contains an ambiguous field identity"
                )
            identities.add(identity)
            labels = " ".join(str(value) for value in field.get("labels", []))
            folded = f"{identity} {labels}".casefold()
            required = field.get("required") is True
            if is_greenhouse_auxiliary_field(
                identity=identity,
                field_type=field_type,
                required=required,
            ):
                # intl-tel-input creates this transient country-picker search
                # control. It may be visible while inventory is collected and
                # hidden again before filling; it is not an application answer.
                continue
            locator = self._locator(page, identity)
            if locator.count() != 1:
                raise ProductionATSBoundaryError(
                    "Greenhouse field identity is not unique in the live form"
                )
            if field_type == "file":
                role = (
                    "cover_letter"
                    if "cover" in folded and "letter" in folded
                    else "cv"
                    if "resume" in folded or re.search(r"\bcv\b", folded)
                    else ""
                )
                if not role:
                    if required:
                        raise ProductionATSBoundaryError(
                            "required upload field has no approved document role"
                        )
                    continue
                if role in uploads:
                    raise ProductionATSBoundaryError(
                        "Greenhouse upload role is ambiguous"
                    )
                filename = "cv.pdf" if role == "cv" else "cover-letter.pdf"
                path = artifact_directory / filename
                locator.set_input_files(str(path))
                browser_file = locator.evaluate(
                    """element => {
                        const file = element.files && element.files[0];
                        return file ? {name: file.name, size: file.size, type: file.type} : null;
                    }"""
                )
                if (
                    not isinstance(browser_file, Mapping)
                    or browser_file.get("name") != path.name
                    or browser_file.get("size") != path.stat().st_size
                ):
                    raise ProductionATSBoundaryError(
                        "browser upload readback differs from the selected document"
                    )
                if recorder is not None:
                    content_sha256 = _file_sha256(path)
                    recorder.record_field_action(
                        event_kind="file_uploaded",
                        field_id=identity,
                        field_type=field_type,
                        required=required,
                        options=(),
                        provenance=f"document.{role}.final_pdf",
                        readback=_json_bytes(
                            {
                                "browser_file": dict(browser_file),
                                "source_path": str(path),
                                "source_sha256": content_sha256,
                            }
                        ),
                        document_role=role,
                        source_path=path,
                        content_sha256=content_sha256,
                        file_name=str(browser_file["name"]),
                        file_size=int(browser_file["size"]),
                        mime_type=str(browser_file.get("type") or "application/pdf"),
                    )
                uploads[role] = (identity, path)
                continue
            if field_type == "radio":
                raise ProductionATSBoundaryError(
                    "radio choice requires explicit answer authority"
                )
            if field_type == "checkbox":
                if identity not in planned_consents:
                    raise ProductionATSBoundaryError(
                        "Greenhouse checkbox differs from the reviewed plan"
                    )
                expected = planned_consents[identity]
                locator.check() if expected else locator.uncheck()
                if locator.is_checked() is not expected:
                    raise ProductionATSBoundaryError(
                        "checkbox readback differs from the approved consent"
                    )
                if recorder is not None:
                    recorder.record_field_action(
                        event_kind="click",
                        field_id=identity,
                        field_type=field_type,
                        required=required,
                        options=("false", "true"),
                        provenance="consent.required" if expected else "blank.optional",
                        readback=None,
                        checked=expected,
                        selected=expected,
                    )
                    recorder.record_field_action(
                        event_kind="field_selected",
                        field_id=identity,
                        field_type=field_type,
                        required=required,
                        options=("false", "true"),
                        provenance="consent.required" if expected else "blank.optional",
                        readback=(b"true" if expected else b"false"),
                        checked=expected,
                        selected=expected,
                    )
                consents.append((identity, expected))
                continue
            authority = planned_authorities.get(identity)
            if authority is None:
                if required:
                    raise ProductionATSBoundaryError(
                        "required Greenhouse question lacks approved answer authority"
                    )
                authority = "blank.optional"
            if authority not in approved:
                if required:
                    raise ProductionATSBoundaryError(
                        "required contact field lacks explicit approved value"
                    )
                authority = "blank.optional"
            value = approved[authority]
            tag = str(field.get("tag", "")).casefold()
            clicked = False
            if tag == "select":
                locator.select_option(label=value)
                readback = locator.locator("option:checked").inner_text()
            elif identity in select_inventories and value:
                option_values = {
                    str(row.get("text"))
                    for row in select_inventories[identity].get("options", [])
                    if isinstance(row, Mapping)
                }
                if value not in option_values:
                    raise ProductionATSBoundaryError(
                        "approved answer is absent from Greenhouse options for "
                        f"field {identity}: {value!r}"
                    )
                self._select_dynamic_option(
                    page,
                    locator,
                    identity=identity,
                    value=value,
                )
                clicked = True
                readback = locator.input_value()
            else:
                locator.fill(value)
                readback = locator.input_value()
            if readback != value:
                raise ProductionATSBoundaryError(
                    "field readback differs from the approved answer"
                )
            if recorder is not None:
                option_rows = select_inventories.get(identity, {}).get("options", [])
                option_labels = tuple(
                    str(row.get("text"))
                    for row in option_rows
                    if isinstance(row, Mapping) and row.get("text") is not None
                )
                if clicked:
                    recorder.record_field_action(
                        event_kind="click",
                        field_id=identity,
                        field_type=field_type,
                        required=required,
                        options=option_labels,
                        provenance=authority,
                        readback=None,
                        selected=True,
                    )
                recorder.record_field_action(
                    event_kind=(
                        "field_selected"
                        if tag == "select" or identity in select_inventories
                        else "field_filled"
                    ),
                    field_id=identity,
                    field_type=field_type,
                    required=required,
                    options=option_labels,
                    provenance=authority,
                    readback=readback.encode("utf-8"),
                    selected=(
                        True
                        if tag == "select" or identity in select_inventories
                        else None
                    ),
                )
            field_authorities.append((identity, authority))
        if recorder is not None:
            recorder.record_postfill(page)
        if "cv" not in uploads:
            raise ProductionATSBoundaryError("Greenhouse form lacks one CV upload")
        attached_roles = tuple(
            role for role in ("cv", "cover_letter") if role in uploads
        )
        upload_field_names = tuple((role, uploads[role][0]) for role in attached_roles)
        upload_paths = {role: uploads[role][1] for role in attached_roles}
        return (
            attached_roles,
            upload_field_names,
            tuple(field_authorities),
            tuple(consents),
            upload_paths,
        )

    def _plan_supported_form(
        self,
        package: CandidateApplicationPackage,
        inventory_bytes: bytes,
    ) -> GreenhouseFormPlan:
        try:
            inventory = json.loads(inventory_bytes)
            fields = inventory["form_state"]["fields"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProductionATSBoundaryError(
                "Greenhouse form inventory is malformed"
            ) from exc
        if not isinstance(fields, list):
            raise ProductionATSBoundaryError("Greenhouse form inventory is malformed")

        def display_question(field: Mapping[str, object]) -> str:
            labels = field.get("labels", [])
            if not isinstance(labels, list):
                raise ProductionATSBoundaryError("Greenhouse field labels are malformed")
            return " ".join(" ".join(str(value).split()) for value in labels).strip()

        def question_key(value: str) -> str:
            return re.sub(r"\s*\*\s*$", "", " ".join(value.split())).casefold()

        answers = tuple(getattr(package.source, "answers", ()))
        questions: dict[str, tuple[str, str]] | None = {} if answers else None
        answer_by_field: dict[str, object] = {}
        for answer in answers:
            question = getattr(answer, "question", None)
            question_id = getattr(answer, "question_id", None)
            if not isinstance(question, str) or not isinstance(question_id, str):
                raise ProductionATSBoundaryError(
                    "application source answer identity is malformed"
                )
            matches = [
                field
                for field in fields
                if isinstance(field, Mapping)
                and question_key(display_question(field)) == question_key(question)
            ]
            if len(matches) != 1:
                raise ProductionATSBoundaryError(
                    "source answer does not identify one exact live Greenhouse question"
                )
            identity = self._field_identity(matches[0])
            if identity in answer_by_field or question_id in questions:
                raise ProductionATSBoundaryError(
                    "Greenhouse source answer binding is ambiguous"
                )
            answer_by_field[identity] = answer
            questions[question_id] = (question_id, question)

        canonical_answers = (
            {row[0]: (row[1], row[2]) for row in source_form_answers(package.source, questions)}
            if questions is not None
            else {}
        )
        approved = approved_authority_values(package.source, package.artifacts)
        identities: set[str] = set()
        upload_roles: set[str] = set()
        planned_fields: list[tuple[str, str, str]] = []
        field_authorities: list[tuple[str, str]] = []
        field_authority_names: list[tuple[str, str]] = []
        consent_states: list[tuple[str, bool | str]] = []
        answer_field_bindings: list[tuple[str, str]] = []

        for field in fields:
            if not isinstance(field, Mapping):
                raise ProductionATSBoundaryError("Greenhouse field is malformed")
            field_type = str(field.get("type", "")).casefold()
            if field_type in {"hidden", "submit", "button", "reset"}:
                continue
            identity = self._field_identity(field)
            if identity in identities:
                raise ProductionATSBoundaryError(
                    "Greenhouse form contains an ambiguous field identity"
                )
            identities.add(identity)
            labels = " ".join(str(value) for value in field.get("labels", []))
            folded = f"{identity} {labels}".casefold()
            required = field.get("required") is True
            if is_greenhouse_auxiliary_field(
                identity=identity,
                field_type=field_type,
                required=required,
            ):
                continue
            if field_type == "file":
                role = (
                    "cover_letter"
                    if "cover" in folded and "letter" in folded
                    else "cv"
                    if "resume" in folded or re.search(r"\bcv\b", folded)
                    else ""
                )
                if not role and required:
                    raise ProductionATSBoundaryError(
                        "required upload field has no approved document role"
                    )
                if role and role in upload_roles:
                    raise ProductionATSBoundaryError(
                        "Greenhouse upload role is ambiguous"
                    )
                if role:
                    upload_roles.add(role)
                continue
            if field_type == "radio":
                raise ProductionATSBoundaryError(
                    "radio choice requires explicit answer authority"
                )
            question = display_question(field) or identity
            matched_answer = answer_by_field.get(identity)
            if field_type == "checkbox":
                consent = any(
                    marker in folded
                    for marker in ("consent", "privacy", "terms and conditions")
                )
                if required and not consent:
                    raise ProductionATSBoundaryError(
                        "required choice lacks explicit consent authority"
                    )
                expected: bool | str = bool(required and consent)
                authority = "consent.required" if expected else "blank.optional"
                consent_states.append((identity, expected))
                planned_fields.append(
                    (identity, question, "true" if expected else "false")
                )
                field_authorities.append((identity, authority))
                continue

            authority = self._field_authority(field)
            if authority == "answers.full" or authority is None:
                if matched_answer is not None:
                    authority = f"answer.{matched_answer.question_id}"
            if authority is None:
                if required:
                    raise ProductionATSBoundaryError(
                        "required Greenhouse question lacks approved answer authority"
                    )
                authority = "blank.optional"
            if authority not in approved:
                if required:
                    raise ProductionATSBoundaryError(
                        "required contact field lacks explicit approved value"
                    )
                authority = "blank.optional"
            if authority.startswith("answer."):
                question_id = authority.removeprefix("answer.")
                if (
                    matched_answer is None
                    or matched_answer.question_id != question_id
                    or question_id not in canonical_answers
                ):
                    raise ProductionATSBoundaryError(
                        "Greenhouse answer differs from its exact source question"
                    )
                question, source_answer = canonical_answers[question_id]
                if source_answer != approved[authority]:
                    raise ProductionATSBoundaryError(
                        "Greenhouse answer differs from approved source content"
                    )
                question = matched_answer.question
                answer_field_bindings.append((identity, question_id))
            elif matched_answer is not None:
                question_id = matched_answer.question_id
                if canonical_answers.get(question_id) != (
                    matched_answer.question,
                    approved[authority],
                ):
                    raise ProductionATSBoundaryError(
                        "stable authority conflicts with its authored source answer"
                    )
                question = matched_answer.question
            planned_fields.append((identity, question, approved[authority]))
            field_authorities.append((identity, authority))
            field_authority_names.append((identity, authority))

        if "cv" not in upload_roles:
            raise ProductionATSBoundaryError("Greenhouse form lacks one CV upload")
        return GreenhouseFormPlan(
            questions=questions,
            answer_field_bindings=tuple(sorted(answer_field_bindings)),
            review_form_fields=tuple(sorted(planned_fields)),
            form_field_authorities=tuple(sorted(field_authorities)),
            field_authority_names=tuple(sorted(field_authority_names)),
            consent_states=tuple(sorted(consent_states)),
            inventory_sha256=hashlib.sha256(inventory_bytes).hexdigest(),
        )

    def prepare_release(
        self,
        item: QueueItem,
        recorder,
        page,
        sink: GeneratedRevisionSink,
    ) -> PreparedGreenhouseRelease | PreparedLocalSyntheticDiagnostic:
        return self._prepare_application(item, recorder, page, sink, review_only=False)

    def prepare_review(
        self, item: QueueItem, recorder, page, sink: GeneratedRevisionSink,
    ) -> PreparedGreenhouseReview:
        return self._prepare_application(item, recorder, page, sink, review_only=True)

    def _prepare_application(
        self, item: QueueItem, recorder, page, sink: GeneratedRevisionSink, *, review_only: bool,
    ) -> PreparedGreenhouseRelease | PreparedGreenhouseReview | PreparedLocalSyntheticDiagnostic:
        vacancy = item.vacancy.vacancy
        market_context = getattr(self, "market_context_by_key", {}).get(
            vacancy.job_key
        )
        source_body = self.complete_vacancy_by_key.get(vacancy.job_key)
        if source_body is None or hashlib.sha256(source_body).hexdigest() != (
            vacancy.vacancy_sha256
        ):
            raise ValueError("production vacancy source bytes are unavailable")
        equivalence = verify_vacancy_body_equivalence(
            source_body,
            page.content().encode("utf-8"),
        )
        visible_listing_bytes = page.locator("body").inner_text().encode("utf-8")
        recorder.attempt.add_artifact(
            "vacancy.visible_listing_capture",
            visible_listing_bytes,
            media_type="text/plain",
            lineage=(vacancy.vacancy_sha256,),
            disposition="observed",
        )
        vacancy_review_material = build_vacancy_review_material(
            raw_listing_bytes=source_body,
            visible_listing_text_bytes=visible_listing_bytes,
            expected_raw_listing_sha256=vacancy.vacancy_sha256,
        )
        recorder.add_revision(
            role="vacancy.destination_reverification",
            value=_json_bytes(equivalence),
            media_type="application/json",
            prior_sha256=None,
            approved=True,
        )
        recorder.add_revision(
            role="vacancy.review_material",
            value=_json_bytes(vacancy_review_material.document()),
            media_type="application/json",
            prior_sha256=None,
            approved=True,
        )
        contact_path = (
            market_context.contact_authority_path
            if market_context is not None
            else _required_file(CONTACT_ENV)
        )
        contact_authority = load_candidate_contact_authority(
            contact_path, repository_root=self.repository_root
        )
        decision_row = self.decision_by_key[vacancy.job_key]
        decision = (
            market_context.market_decision_authority.decision_receipt()
            if market_context is not None
            else decision_row["receipt"]
        )

        product = sink.generate_candidate_application(
            decision_receipt=decision,
            candidate_projection=self.candidate_projection,
            approved_evidence_path=self.approved_evidence_path,
            job_key=vacancy.job_key,
            vacancy_sha256=vacancy.vacancy_sha256,
            source_url=vacancy.source_url,
            role_title=vacancy.role_title,
            company_name=vacancy.company_name,
            contact=contact_authority.contact,
        )
        if type(product) is not CandidateApplicationPackage:
            raise TypeError("owned candidate generator returned an invalid package")
        package = product
        if market_context is not None and package.source != market_context.materialization.source:
            raise ValueError(
                "owned candidate generator differs from admitted Market materialization"
            )
        generation_authority = sink.seal()
        artifact_root = self.archive_root / "production-artifacts"
        publication = publish_application_artifacts(
            package.source,
            package.artifacts,
            root=artifact_root,
            repository_root=self.repository_root,
        )
        artifact_directory = artifact_root / publication.relative_directory
        intended = IntendedVacancy(
            job_key=vacancy.job_key,
            vacancy_sha256=vacancy.vacancy_sha256,
            role_title=vacancy.role_title,
            company_name=vacancy.company_name,
        )
        document_receipts = assert_application_artifacts(
            cv_pdf_bytes=package.artifacts.cv_pdf.pdf_bytes,
            cover_letter_pdf_bytes=package.artifacts.cover_letter_pdf.pdf_bytes,
            answers_text=package.artifacts.editable.answers_text,
            intended_vacancy=intended,
        )
        if not review_only:
            success_observation, observation_authority = (
                load_provider_observation_authority(
                    source_url=vacancy.source_url,
                    archive_root=self.archive_root,
                    repository_root=self.repository_root,
                )
            )
            observation = json.loads(success_observation)
            paths = observation["provider_loader_paths"]
            marker = " ".join(
                re.sub(r"<[^>]+>", " ", str(paths["confirmation_message"])).strip().split()
            )
            if not marker:
                raise ValueError("provider observation confirmation marker is empty")
            success_evidence = GreenhouseSuccessEvidence(
                observation_sha256=observation_authority.observation_sha256,
                observed_at=str(observation["observed_at"]),
                confirmation_url=urljoin(
                    vacancy.source_url, str(paths["confirmationPath"])
                ),
                required_visible_markers=(marker,),
            )
        client = LLMClient.from_config(
            cache_enabled=False,
            cache_dir=self.archive_root / "review-cache",
            max_retries=1,
            temperature=0,
            transport_archive_dir=self.archive_root / "provider-exchanges",
            usage_log=self.archive_root / "review-usage.jsonl",
        )
        form_inventory = collect_greenhouse_form_inventory(page, passive=True)
        form_plan = self._plan_supported_form(package, form_inventory)
        existing_inventory = [
            row
            for row in recorder.attempt._objects(recorder.attempt._events())
            if row.role == "review.form_inventory"
        ]
        inventory_sha256 = hashlib.sha256(form_inventory).hexdigest()
        if existing_inventory:
            if len(existing_inventory) != 1 or recorder.attempt.read_artifact(
                existing_inventory[0]
            ) != form_inventory:
                raise ProductionATSBoundaryError(
                    "resumed Greenhouse form inventory differs from its archive"
                )
        else:
            recorder.attempt.add_artifact(
                "review.form_inventory",
                form_inventory,
                media_type="application/json",
                disposition="observed",
            )
        try:
            sanity_package = package_from_application(
                source=package.source,
                artifacts=package.artifacts,
                questions=form_plan.questions,
                field_answer_bindings=form_plan.answer_field_bindings,
                vacancy_requirements=package.vacancy_requirements,
                vacancy_review_material=vacancy_review_material,
                planned_form_fields=form_plan.review_form_fields,
                form_field_authorities=form_plan.form_field_authorities,
                form_inventory_sha256=inventory_sha256 if review_only else None,
            )
            local_synthetic_context = None
            local_fixture_sha256 = getattr(
                self, "local_synthetic_review_fixture_sha256", None
            )
            if local_fixture_sha256 is not None:
                if review_only:
                    raise ValueError(
                        "local synthetic diagnostic context is unavailable in review-only mode"
                    )
                local_synthetic_context = build_local_synthetic_review_context(
                    fixture_sha256=local_fixture_sha256,
                    package=sanity_package,
                    source_url=vacancy.source_url,
                    observed_page_url=page.url,
                    repository_root=self.repository_root,
                )
            if review_only:
                sanity_receipt = recorder.review_once(
                    sanity_package,
                    lambda: review_application_package(sanity_package, client=client),
                )
            elif local_synthetic_context is not None:
                sanity_receipt = review_application_package_with_pinned_skills(
                    sanity_package,
                    client=client,
                    local_synthetic_context=local_synthetic_context,
                    repository_root=self.repository_root,
                    actual_source_url=vacancy.source_url,
                    observed_page_url=page.url,
                )
            else:
                sanity_receipt = review_application_package_with_pinned_skills(
                    sanity_package,
                    client=client,
                )
        except ApplicationSanityReviewError as exc:
            if exc.result is not None:
                recorder.add_revision(
                    role="review.sanity_result",
                    value=_json_bytes(exc.result),
                    media_type="application/json",
                    prior_sha256=None,
                    approved=False,
                    rejection_codes=(exc.code,),
                )
            elif exc.backend_failure is not None:
                recorder.add_revision(
                    role="review.sanity_result",
                    value=_json_bytes(exc.document()),
                    media_type="application/json",
                    prior_sha256=None,
                    approved=False,
                    rejection_codes=(exc.code,),
                )
            raise
        # Passive, no-interaction ATS diagnostic: captured after the sanity
        # review passes but before any release gate issue or page mutation,
        # preserving the donor pre-release timing. Diagnostic-only; it grants
        # no release or submission authority.
        forensic_root = self.archive_root / "passive-forensics"
        forensic_runtime = runtime_fingerprint(
            browser_name=self._browser.browser_type.name,
            browser_version=self._browser.version,
            headless=True,
            user_agent=page.evaluate("navigator.userAgent"),
        )
        forensic_receipt = capture_or_recover_greenhouse_forensic_observation(
            page,
            forensic_root=forensic_root,
            attempt_id=recorder.attempt.attempt_id,
            application_id=vacancy.source_url.rstrip("/").rsplit("/", 1)[-1],
            application_url=vacancy.source_url,
            runtime=forensic_runtime,
            release_manifest_sha256=None,
            artifact_set_sha256=publication.artifact_set_sha256,
            **({"passive_inventory": True} if review_only else {}),
        )
        forensic_document = verify_forensic_receipt(forensic_root, forensic_receipt)
        if (
            forensic_document.get("diagnostic_only") is not True
            or forensic_document.get("release_authority") is not False
            or forensic_document.get("submission_authority") is not False
        ):
            raise ProductionATSBoundaryError(
                "passive ATS forensics did not retain the no-submit boundary"
            )
        recorder.attempt.add_artifact(
            "review.ats_passive_forensics",
            _json_bytes(forensic_document),
            media_type="application/json",
            disposition="observed",
            metadata={
                "artifact_set_sha256": publication.artifact_set_sha256,
                "forensic_attempt_id": forensic_receipt.attempt_id,
                "forensic_manifest_path": forensic_receipt.manifest_path,
                "forensic_manifest_sha256": forensic_receipt.manifest_sha256,
                "forensic_root": forensic_root.name,
                "outcome": forensic_receipt.outcome,
                "release_manifest_sha256": None,
            },
        )
        if forensic_receipt.outcome != "prepared":
            raise ProductionATSBoundaryError(
                "passive ATS observation blocked release before any gate issue: "
                + str(forensic_document.get("failure_class"))
            )
        if review_only:
            return PreparedGreenhouseReview(
                source=package.source,
                artifacts=package.artifacts,
                document_assurance_receipts=document_receipts,
                sanity_review_receipt=sanity_receipt,
                production_identity=ProductionIdentity(
                    code_revision=exact_clean_head(self.repository_root),
                    policy_identity=POLICY_SHA256,
                    configuration_identity=content_hash({
                        "candidate_decision": decision_row["receipt_sha256"],
                        "contact_authority": contact_authority.authority_sha256,
                    }),
                ),
                generation_authority=generation_authority,
                vacancy_review_material=vacancy_review_material,
                vacancy_requirements=package.vacancy_requirements,
                questions=form_plan.questions,
                form_answer_bindings=form_plan.answer_field_bindings,
                review_form_fields=form_plan.review_form_fields,
                form_field_authorities=form_plan.form_field_authorities,
                form_inventory_sha256=inventory_sha256,
                form_inventory=form_inventory,
                forensic_root=forensic_root,
                forensic_receipt=forensic_receipt,
            )
        gate = None
        issued = None
        if local_synthetic_context is None:
            gate_root = self.archive_root / "production-runtime"
            gate_root.mkdir(mode=0o700, exist_ok=True)
            gate = CandidateAuthorityReleaseGate(
                gate_root / "release-gate.sqlite3",
                repository_root=self.repository_root,
                vacancy_requirements=package.vacancy_requirements,
                authority_files=CandidateAuthorityFiles(
                    archive_root=self.archive_root,
                    discovery_path=self.discovery_path,
                    candidate_authority_path=self.eligibility_path,
                    contact_authority_path=contact_path,
                    job_key=vacancy.job_key,
                    decision_receipt_sha256=str(decision_row["receipt_sha256"]),
                ),
                **(
                    {
                        "market_decision_authority": (
                            market_context.market_decision_authority
                        ),
                        "materialization_receipt": (
                            market_context.materialization.receipt
                        ),
                    }
                    if market_context is not None
                    else {}
                ),
            )
            issued = gate.issue(
                source=package.source,
                artifacts=package.artifacts,
                contact=contact_authority.contact,
                questions=form_plan.questions,
                artifact_root=artifact_root,
                repository_root=self.repository_root,
                jurisdiction="GB",
                contract_type="employee",
                application_url=vacancy.source_url,
            )
        # Employer-visible page mutation is admitted only after every local,
        # provider, semantic, and one-use release authority has passed.
        observed_capture = collect_greenhouse_form_inventory(page)
        observed_form_plan = self._plan_supported_form(package, observed_capture)
        if (
            observed_form_plan.questions != form_plan.questions
            or observed_form_plan.answer_field_bindings != form_plan.answer_field_bindings
            or observed_form_plan.review_form_fields != form_plan.review_form_fields
            or observed_form_plan.form_field_authorities != form_plan.form_field_authorities
            or observed_form_plan.field_authority_names != form_plan.field_authority_names
            or observed_form_plan.consent_states != form_plan.consent_states
        ):
            raise ProductionATSBoundaryError(
                "Greenhouse form changed after its sanity-reviewed plan"
            )
        observed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        observed_inventory = greenhouse_ats_inventory_from_capture(
            observed_capture,
            captured_at=observed_at,
            page_snapshot_sha256=hashlib.sha256(
                page.content().encode("utf-8")
            ).hexdigest(),
            screenshot_sha256=hashlib.sha256(
                page.screenshot(full_page=True)
            ).hexdigest(),
            local_synthetic_context=local_synthetic_context,
        )
        (
            attached_roles,
            upload_field_names,
            field_authority_names,
            consent_states,
            upload_paths,
        ) = self._fill_supported_form(
            page,
            package,
            artifact_directory=artifact_directory,
            recorder=recorder,
            inventory_bytes=observed_capture,
            expected_form_plan=form_plan,
        )
        reviewed_capture = collect_greenhouse_form_inventory(page)
        reviewed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        uploaded_sha256_by_field = {
            field_name: (
                package.artifacts.cv_pdf.pdf_sha256
                if role == "cv"
                else package.artifacts.cover_letter_pdf.pdf_sha256
            )
            for role, field_name in upload_field_names
        }
        reviewed_inventory = greenhouse_ats_inventory_from_capture(
            reviewed_capture,
            captured_at=reviewed_at,
            page_snapshot_sha256=hashlib.sha256(
                page.content().encode("utf-8")
            ).hexdigest(),
            screenshot_sha256=hashlib.sha256(
                page.screenshot(full_page=True)
            ).hexdigest(),
            uploaded_sha256_by_field=uploaded_sha256_by_field,
            local_synthetic_context=local_synthetic_context,
        )
        plans = compile_greenhouse_ats_plans(
            observed_inventory,
            field_authority_names=dict(field_authority_names),
            consent_states=dict(consent_states),
            upload_roles_by_field={
                field_name: role for role, field_name in upload_field_names
            },
        )
        candidate_authority_sha256 = _file_sha256(self.eligibility_path)
        ats_authority = build_ats_application_authority(
            reviewed_at=max(reviewed_at, reviewed_inventory.captured_at),
            candidate_authority_sha256=candidate_authority_sha256,
            source=package.source,
            artifacts=package.artifacts,
            publication_receipt=publication,
            inventory=observed_inventory,
            reviewed_inventory=reviewed_inventory,
            plans=plans,
            local_synthetic_context=local_synthetic_context,
        )
        quality_input = ApplicationQualityInput(
            reviewed_at=max(reviewed_at, reviewed_inventory.captured_at),
            candidate_authority_sha256=candidate_authority_sha256,
            source=package.source,
            artifacts=package.artifacts,
            publication_receipt=publication,
            field_answers_bytes=ats_authority.answer_bytes,
            form_inventory_bytes=ats_authority.inventory_bytes,
            ats_application_authority=ats_authority,
            combined_review_receipt=sanity_receipt,
            reviewed_form_fields=form_plan.review_form_fields,
            reviewed_form_answer_bindings=form_plan.answer_field_bindings,
            reviewed_form_field_authorities=form_plan.form_field_authorities,
            reviewed_vacancy_requirements=tuple(package.vacancy_requirements),
        )
        if local_synthetic_context is None:
            quality_review = build_deterministic_preflight_quality_review(quality_input)
        else:
            quality_review = build_deterministic_preflight_quality_review(
                quality_input,
                local_synthetic_context=local_synthetic_context,
                sanity_package=sanity_package,
                repository_root=self.repository_root,
                actual_source_url=vacancy.source_url,
                observed_page_url=page.url,
            )
        if quality_review.disposition is not QualityReviewDisposition.ACCEPTED:
            raise ProductionATSBoundaryError(
                "deterministic application quality review refused release: "
                + ", ".join(issue.code for issue in quality_review.issues)
            )
        if local_synthetic_context is not None:
            return PreparedLocalSyntheticDiagnostic(
                sanity_review_receipt=sanity_receipt,
                quality_review=quality_review,
                diagnostic_context=local_synthetic_context,
                application_source_identity=package.source.source_id,
                artifact_set_sha256=publication.artifact_set_sha256,
            )
        if gate is None or issued is None:
            raise ProductionATSBoundaryError(
                "production release gate was not issued for a production preparation"
            )
        head = exact_clean_head(self.repository_root)
        return PreparedGreenhouseRelease(
            source=package.source,
            artifacts=package.artifacts,
            contact=contact_authority.contact,
            questions=form_plan.questions,
            document_assurance_receipts=document_receipts,
            sanity_review_receipt=sanity_receipt,
            ats_application_authority=ats_authority,
            quality_input=quality_input,
            quality_review=quality_review,
            production_identity=ProductionIdentity(
                code_revision=head,
                policy_identity=POLICY_SHA256,
                configuration_identity=content_hash(
                    {
                        "candidate_decision": decision_row["receipt_sha256"],
                        "contact_authority": contact_authority.authority_sha256,
                        "provider_observation": (
                            observation_authority.observation_sha256
                        ),
                    }
                ),
            ),
            generation_authority=generation_authority,
            attached_roles=attached_roles,
            upload_field_names=upload_field_names,
            field_authority_names=field_authority_names,
            consent_states=consent_states,
            success_evidence=success_evidence,
            success_observation=success_observation,
            gate=gate,
            release_token=issued.release_token,
            artifact_root=artifact_root,
            upload_paths=upload_paths,
            application_url=vacancy.source_url,
            application_id=vacancy.source_url.rstrip("/").rsplit("/", 1)[-1],
            receipt_url=success_evidence.confirmation_url,
            jurisdiction="GB",
            contract_type="employee",
            consumed_at=issued.issued_at,
            vacancy_review_material=vacancy_review_material,
            vacancy_requirements=package.vacancy_requirements,
            form_answer_bindings=form_plan.answer_field_bindings,
            review_form_fields=form_plan.review_form_fields,
            form_field_authorities=form_plan.form_field_authorities,
            form_inventory_sha256=None,
            form_inventory=form_inventory,
        )

    def close(self) -> None:
        self._browser.close()
        self._playwright.stop()


def create_session(arguments) -> GutuaGreenhouseSession:
    return GutuaGreenhouseSession(arguments)


__all__ = ["GutuaGreenhouseSession", "create_session"]
