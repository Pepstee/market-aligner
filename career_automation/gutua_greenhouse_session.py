"""Gutua production session backed by archived live-discovery evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Mapping
from urllib.parse import urljoin

from playwright.sync_api import sync_playwright

from .application_archive import VacancyArchiveIdentity
from .application_artifacts import publish_application_artifacts
from .application_sanity_review import (
    ApplicationSanityReviewError,
    package_from_application,
    review_application_package,
)
from .browser_executor import GreenhouseSuccessEvidence
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
from .production_attempt import ProductionIdentity
from .production_ats_executor import ProductionATSBoundaryError
from .production_ats_executor import collect_greenhouse_form_inventory
from .production_ats_executor import is_greenhouse_auxiliary_field
from form_filling.service import approved_authority_values
from .production_queue import LiveVacancy, QueueItem
from .production_runner import (
    GeneratedRevisionSink,
    PreparedGreenhouseRelease,
    ProductionRunCandidate,
)
from .provider_observation_authority import load_provider_observation_authority
from .provider_observation_capture import exact_clean_head
from llm.client import LLMClient


DISCOVERY_ENV = "JAA_GREENHOUSE_DISCOVERY"
ELIGIBILITY_ENV = "JAA_GREENHOUSE_ELIGIBILITY"
CONTACT_ENV = "JAA_CANDIDATE_CONTACT_AUTHORITY"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
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
        self.gmail_confirmation_checker = (
            GmailAPIConfirmationChecker(repository_root=repository_root)
            if os.environ.get(ACCESS_TOKEN_ENV)
            else None
        )
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)
        self.page = self._browser.new_page()

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
    ) -> tuple[
        tuple[str, ...],
        tuple[tuple[str, str], ...],
        tuple[tuple[str, str], ...],
        tuple[tuple[str, bool | str], ...],
        dict[str, Path],
    ]:
        inventory = json.loads(collect_greenhouse_form_inventory(page))
        fields = inventory["form_state"]["fields"]
        if not isinstance(fields, list):
            raise ProductionATSBoundaryError("Greenhouse form inventory is malformed")
        identities: set[str] = set()
        field_authorities: list[tuple[str, str]] = []
        consents: list[tuple[str, bool | str]] = []
        uploads: dict[str, tuple[str, Path]] = {}
        approved = approved_authority_values(package.source, package.artifacts)
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
                uploads[role] = (identity, path)
                continue
            if field_type == "radio":
                raise ProductionATSBoundaryError(
                    "radio choice requires explicit answer authority"
                )
            if field_type == "checkbox":
                consent = any(
                    marker in folded
                    for marker in ("consent", "privacy", "terms and conditions")
                )
                if required and not consent:
                    raise ProductionATSBoundaryError(
                        "required choice lacks explicit consent authority"
                    )
                expected = bool(required and consent)
                locator.check() if expected else locator.uncheck()
                consents.append((identity, expected))
                continue
            authority = self._field_authority(field)
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
            if tag == "select":
                locator.select_option(label=value)
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
            else:
                locator.fill(value)
            field_authorities.append((identity, authority))
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

    def prepare_release(
        self,
        item: QueueItem,
        recorder,
        page,
        sink: GeneratedRevisionSink,
    ) -> PreparedGreenhouseRelease:
        vacancy = item.vacancy.vacancy
        source_body = self.complete_vacancy_by_key.get(vacancy.job_key)
        if source_body is None or hashlib.sha256(source_body).hexdigest() != (
            vacancy.vacancy_sha256
        ):
            raise ValueError("production vacancy source bytes are unavailable")
        equivalence = verify_vacancy_body_equivalence(
            source_body,
            page.content().encode("utf-8"),
        )
        recorder.add_revision(
            role="vacancy.destination_reverification",
            value=_json_bytes(equivalence),
            media_type="application/json",
            prior_sha256=None,
            approved=True,
        )
        contact_path = _required_file(CONTACT_ENV)
        contact_authority = load_candidate_contact_authority(
            contact_path, repository_root=self.repository_root
        )
        decision_row = self.decision_by_key[vacancy.job_key]
        decision = decision_row["receipt"]

        product = sink.generate_candidate_application(
            decision_receipt=decision,
            candidate_projection=self.candidate_projection,
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
            cache_dir=self.archive_root / "review-cache",
            usage_log=self.archive_root / "review-usage.jsonl",
        )
        try:
            sanity_receipt = review_application_package(
                package_from_application(
                    source=package.source,
                    artifacts=package.artifacts,
                    questions=None,
                    vacancy_requirements=package.vacancy_requirements,
                ),
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
            raise
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
        )
        issued = gate.issue(
            source=package.source,
            artifacts=package.artifacts,
            contact=contact_authority.contact,
            questions=None,
            artifact_root=artifact_root,
            repository_root=self.repository_root,
            jurisdiction="GB",
            contract_type="employee",
            application_url=vacancy.source_url,
        )
        # Employer-visible page mutation is admitted only after every local,
        # provider, semantic, and one-use release authority has passed.
        (
            attached_roles,
            upload_field_names,
            field_authority_names,
            consent_states,
            upload_paths,
        ) = self._fill_supported_form(
            page, package, artifact_directory=artifact_directory
        )
        head = exact_clean_head(self.repository_root)
        return PreparedGreenhouseRelease(
            source=package.source,
            artifacts=package.artifacts,
            contact=contact_authority.contact,
            questions=None,
            document_assurance_receipts=document_receipts,
            sanity_review_receipt=sanity_receipt,
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
            vacancy_requirements=package.vacancy_requirements,
        )

    def close(self) -> None:
        self._browser.close()
        self._playwright.stop()


def create_session(arguments) -> GutuaGreenhouseSession:
    return GutuaGreenhouseSession(arguments)


__all__ = ["GutuaGreenhouseSession", "create_session"]
