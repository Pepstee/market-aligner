"""One-use production release gate for candidate-authority applications.

This gate keeps the JAA-08 one-use boundary while binding the newer production
candidate receipt directly, instead of pretending that the historical JAA-06
SQLite graph contains the imported candidate authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urlsplit

from .application_compiler import (
    ApplicationSource,
    CandidateContact,
    verify_application_source,
)
from .candidate_authority import build_candidate_authority_document
from .candidate_application_factory import (
    CandidateApplicationMaterializationReceipt,
    MarketApplicationDecisionAuthority,
)
from .candidate_contact_authority import load_candidate_contact_authority
from .evidence_matching import canonical_json, content_hash
from .provider_observation_capture import exact_clean_head
from .release_gate import ConsumedRelease, ReleaseGateStore
from .rendering import ApplicationArtifacts, render_pdf_artifacts


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
POLICY_SHA256 = content_hash(
    {
        "contract": "jaa.candidate-authority-release-gate.v1",
        "rules": [
            "exact-clean-repository-head",
            "candidate-decision-job-vacancy-and-projection-binding",
            "current-operator-contact-registry-binding",
            "deterministic-source-and-artifact-replay",
            "content-addressed-upload-file-reverification",
            "exact-typed-official-provider-route",
            "sealed-workable-prefill-and-inventory-binding",
            "one-use-durable-token",
        ],
    }
)


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class CandidateIssuedRelease:
    release_token: str
    manifest_sha256: str
    issued_at: datetime


@dataclass(frozen=True)
class CandidateAuthorityFiles:
    """Exact durable sources from which release authority is recomputed."""

    archive_root: Path
    discovery_path: Path
    candidate_authority_path: Path
    contact_authority_path: Path
    job_key: str
    decision_receipt_sha256: str


@dataclass(frozen=True)
class WorkableUploadBinding:
    """One actual Workable file control bound to one assured PDF."""

    field_name: str
    document_kind: str
    pdf_sha256: str
    assurance_receipt_sha256: str

    def __post_init__(self) -> None:
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", self.field_name)
            or self.document_kind not in {"cv", "cover_letter"}
            or not HEX_64.fullmatch(self.pdf_sha256)
            or not HEX_64.fullmatch(self.assurance_receipt_sha256)
        ):
            raise ValueError("Workable upload binding is invalid")

    def document(self) -> dict[str, str]:
        return {
            "assurance_receipt_sha256": self.assurance_receipt_sha256,
            "document_kind": self.document_kind,
            "field_name": self.field_name,
            "pdf_sha256": self.pdf_sha256,
        }


@dataclass(frozen=True)
class WorkableReleaseBinding:
    """Content-addressed Workable route and reviewed prefill boundary."""

    tenant: str
    vacancy_id: str
    source_url: str
    application_url: str
    policy_sha256: str
    package_sha256: str
    answers_sha256: str
    inventory_sha256: str
    preflight_sha256: str
    cv_pdf_sha256: str
    cover_letter_pdf_sha256: str
    cv_assurance_receipt_sha256: str
    cover_letter_assurance_receipt_sha256: str
    upload_bindings: tuple[WorkableUploadBinding, ...] = ()
    adapter_id: str = "workable.production"
    adapter_version: str = "v1"

    def __post_init__(self) -> None:
        component = r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}"
        if ((self.tenant and not re.fullmatch(component, self.tenant))
                or not re.fullmatch(component, self.vacancy_id)
                or self.adapter_id != "workable.production"
                or self.adapter_version != "v1"):
            raise ValueError("Workable release route identity is invalid")
        prefix = f"/{self.tenant}" if self.tenant else ""
        expected_source = f"https://apply.workable.com{prefix}/j/{self.vacancy_id}"
        expected_application = expected_source + "/apply/"
        if (
            self.source_url.rstrip("/") != expected_source
            or self.application_url != expected_application
        ):
            raise ValueError("Workable release URL differs from its typed route")
        for value in (self.policy_sha256, self.package_sha256, self.answers_sha256,
                      self.inventory_sha256, self.preflight_sha256,
                      self.cv_pdf_sha256, self.cover_letter_pdf_sha256,
                      self.cv_assurance_receipt_sha256,
                      self.cover_letter_assurance_receipt_sha256):
            if not HEX_64.fullmatch(value):
                raise ValueError("Workable release binding contains an invalid hash")
        if any(type(row) is not WorkableUploadBinding for row in self.upload_bindings):
            raise TypeError("Workable release upload bindings must be exact typed objects")
        roles = [row.document_kind for row in self.upload_bindings]
        fields = [row.field_name for row in self.upload_bindings]
        if (
            len(set(roles)) != len(roles)
            or len(set(fields)) != len(fields)
            or "cv" not in roles
        ):
            raise ValueError("Workable release upload roles are incomplete or ambiguous")
        for row in self.upload_bindings:
            expected = (
                (self.cv_pdf_sha256, self.cv_assurance_receipt_sha256)
                if row.document_kind == "cv"
                else (
                    self.cover_letter_pdf_sha256,
                    self.cover_letter_assurance_receipt_sha256,
                )
            )
            if (row.pdf_sha256, row.assurance_receipt_sha256) != expected:
                raise ValueError("Workable upload differs from assured document")

    def document(self) -> dict[str, object]:
        return {
            **{
                name: str(getattr(self, name))
                for name in self.__dataclass_fields__
                if name != "upload_bindings"
            },
            "upload_bindings": [row.document() for row in self.upload_bindings],
        }


def _regular_absolute_file(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{label} must be an absolute non-symlink file")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{label} must be a regular file")
    return resolved


def _verify_durable_candidate_authority(
    files: CandidateAuthorityFiles,
    *,
    repository_root: Path,
    vacancy_requirements: tuple[str, ...],
    market_decision_authority: MarketApplicationDecisionAuthority | None = None,
    materialization_receipt: CandidateApplicationMaterializationReceipt | None = None,
    required_environment: str = "production",
) -> dict[str, str]:
    """Re-read and deterministically authenticate every release authority object."""
    archive_root = files.archive_root.resolve(strict=True)
    discovery_path = _regular_absolute_file(files.discovery_path, "discovery authority")
    authority_path = _regular_absolute_file(
        files.candidate_authority_path, "candidate authority"
    )
    contact_path = _regular_absolute_file(
        files.contact_authority_path, "contact authority"
    )
    authority_root = archive_root / "candidate-authorities"
    if authority_path.parent != authority_root:
        raise ValueError("candidate authority is outside the production archive")
    authority_bytes = authority_path.read_bytes()
    authority_sha256 = _sha256(authority_bytes)
    if authority_path.name != f"{authority_sha256}.json":
        raise ValueError("candidate authority is not content-addressed")
    try:
        authority = json.loads(authority_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("candidate authority is invalid JSON") from exc
    if (
        not isinstance(authority, dict)
        or authority_bytes != _json_bytes(authority)
        or authority.get("schema_version")
        != "jaa.production-candidate-authority.v2"
    ):
        raise ValueError("candidate authority is not canonical production authority")
    current = build_candidate_authority_document(
        discovery_path=discovery_path,
        archive_root=archive_root,
        repository_root=repository_root,
    )
    if current != authority:
        raise ValueError("candidate authority differs from current durable sources")
    if market_decision_authority is not None or materialization_receipt is not None:
        if (
            type(market_decision_authority) is not MarketApplicationDecisionAuthority
            or type(materialization_receipt)
            is not CandidateApplicationMaterializationReceipt
        ):
            raise TypeError(
                "integrated release requires exact market decision and materialization"
            )
        market_decision_authority.__post_init__()
        materialization_receipt.__post_init__()
        projection = authority.get("candidate_projection")
        if not isinstance(projection, Mapping):
            raise ValueError("candidate projection is malformed")
        projection_payload = {
            key: value for key, value in projection.items() if key != "projection_sha256"
        }
        projection_sha256 = _sha256(_json_bytes(projection_payload))
        contact = load_candidate_contact_authority(
            contact_path, repository_root=repository_root
        )
        exact_requirements = tuple(
            f"{row['requirement_id']}: {row['requirement_text']}"
            for row in market_decision_authority.evidence_matrix
        )
        deployment = materialization_receipt.deployment_binding
        if (
            required_environment not in {"production", "synthetic"}
            or market_decision_authority.environment != required_environment
            or market_decision_authority.release_authority is not False
            or materialization_receipt.release_authority is not False
            or materialization_receipt.decision_authority_schema
            != market_decision_authority.schema_version
            or materialization_receipt.decision_authority_sha256
            != market_decision_authority.authority_sha256
            or deployment.application_id != market_decision_authority.application_id
            or deployment.environment != market_decision_authority.environment
            or deployment.handoff_root_sha256
            != market_decision_authority.handoff_root_sha256
            or deployment.admission_receipt_sha256
            != market_decision_authority.admission_receipt_sha256
            or deployment.current_boundary_receipt_sha256
            != market_decision_authority.current_boundary_receipt_sha256
            or materialization_receipt.job_key
            != market_decision_authority.source_job_key
            or files.job_key != market_decision_authority.source_job_key
            or files.decision_receipt_sha256
            != materialization_receipt.decision_receipt_sha256
            or materialization_receipt.vacancy_sha256
            != market_decision_authority.raw_listing_sha256
            or materialization_receipt.vacancy_snapshot_sha256
            != market_decision_authority.vacancy_snapshot_sha256
            or materialization_receipt.candidate_authority_file_sha256
            != authority_sha256
            or market_decision_authority.candidate_authority_file_sha256
            != authority_sha256
            or materialization_receipt.candidate_authority_object_sha256
            != content_hash(authority)
            or market_decision_authority.candidate_authority_object_sha256
            != content_hash(authority)
            or materialization_receipt.candidate_projection_sha256
            != projection_sha256
            or market_decision_authority.candidate_projection_sha256
            != projection_sha256
            or projection.get("projection_sha256") != projection_sha256
            or materialization_receipt.approved_evidence_file_sha256
            != market_decision_authority.approved_evidence_file_sha256
            or materialization_receipt.approved_evidence_object_sha256
            != market_decision_authority.approved_evidence_object_sha256
            or materialization_receipt.contact_authority_sha256
            != contact.authority_sha256
            or materialization_receipt.contact_envelope_sha256
            != contact.envelope_sha256
            or materialization_receipt.contact_registry_sha256
            != contact.registry_sha256
            or materialization_receipt.contact_signer_public_key_sha256
            != contact.signer_public_key_sha256
            or materialization_receipt.source_url
            != market_decision_authority.source_url
            or materialization_receipt.role_title
            != market_decision_authority.role_title
            or materialization_receipt.company_name
            != market_decision_authority.company_name
            or exact_requirements != vacancy_requirements
        ):
            raise ValueError("integrated market release authority differs")
        return {
            "job_key": market_decision_authority.source_job_key,
            "role_title": market_decision_authority.role_title,
            "company_name": market_decision_authority.company_name,
            "vacancy_sha256": market_decision_authority.raw_listing_sha256,
            "vacancy_snapshot_sha256": market_decision_authority.vacancy_snapshot_sha256,
            "source_url": market_decision_authority.source_url,
            "candidate_authority_sha256": authority_sha256,
            "candidate_decision_receipt_sha256": materialization_receipt.decision_receipt_sha256,
            "candidate_projection_sha256": projection_sha256,
            "market_decision_authority_sha256": market_decision_authority.authority_sha256,
            "materialization_receipt_sha256": materialization_receipt.receipt_sha256,
            "contact_authority_sha256": contact.authority_sha256,
            "contact_envelope_sha256": contact.envelope_sha256,
            "contact_registry_sha256": contact.registry_sha256,
            "contact_signer_public_key_sha256": contact.signer_public_key_sha256,
        }
    decisions = authority.get("decisions")
    if not isinstance(decisions, list):
        raise ValueError("candidate authority decisions are malformed")
    selected = [
        row
        for row in decisions
        if isinstance(row, Mapping) and row.get("job_key") == files.job_key
    ]
    if len(selected) != 1:
        raise ValueError("candidate authority does not uniquely cover the vacancy")
    row = selected[0]
    receipt = row.get("receipt")
    if not isinstance(receipt, Mapping):
        raise ValueError("candidate decision receipt is malformed")
    receipt_sha256 = _sha256(_json_bytes(dict(receipt)))
    projection = authority.get("candidate_projection")
    if not isinstance(projection, Mapping):
        raise ValueError("candidate projection is malformed")
    projection_payload = {
        key: value for key, value in projection.items() if key != "projection_sha256"
    }
    projection_sha256 = _sha256(_json_bytes(projection_payload))
    matrix = receipt.get("evidence_matrix")
    exact_requirements = (
        tuple(
            f"{item['requirement_id']}: {item['requirement_text']}"
            for item in matrix
            if isinstance(item, Mapping)
        )
        if isinstance(matrix, list)
        else ()
    )
    duplicate_sha256 = str(authority.get("duplicate_snapshot_sha256", ""))
    duplicate_path = archive_root / "objects" / duplicate_sha256[:2] / duplicate_sha256
    if (
        receipt.get("decision") != "eligible"
        or receipt.get("job_key") != files.job_key
        or row.get("receipt_sha256") != receipt_sha256
        or files.decision_receipt_sha256 != receipt_sha256
        or receipt.get("candidate_projection_sha256") != projection_sha256
        or projection.get("projection_sha256") != projection_sha256
        or receipt.get("duplicate_snapshot_sha256") != duplicate_sha256
        or exact_requirements != vacancy_requirements
        or not HEX_64.fullmatch(duplicate_sha256)
        or not duplicate_path.is_file()
        or duplicate_path.is_symlink()
        or _sha256(duplicate_path.read_bytes()) != duplicate_sha256
    ):
        raise ValueError("candidate decision durable authority binding differs")
    contact = load_candidate_contact_authority(
        contact_path, repository_root=repository_root
    )
    required_text = {
        "job_key": receipt.get("job_key"),
        "role_title": receipt.get("role_title"),
        "company_name": receipt.get("company_name"),
        "vacancy_sha256": receipt.get("vacancy_sha256"),
        "source_url": receipt.get("source_url"),
    }
    if any(not isinstance(value, str) or not value for value in required_text.values()):
        raise ValueError("candidate decision vacancy identity is incomplete")
    return {
        **required_text,  # type: ignore[arg-type]
        "candidate_authority_sha256": authority_sha256,
        "candidate_decision_receipt_sha256": receipt_sha256,
        "candidate_projection_sha256": projection_sha256,
        "duplicate_snapshot_sha256": duplicate_sha256,
        "contact_authority_sha256": contact.authority_sha256,
        "contact_registry_sha256": contact.registry_sha256,
    }


class CandidateAuthorityReleaseGate(ReleaseGateStore):
    """Durable exact-input gate admitted by the shared final-click boundary."""

    def __init__(
        self,
        path: str | Path,
        *,
        repository_root: str | Path,
        authority_files: CandidateAuthorityFiles,
        vacancy_requirements: tuple[str, ...],
        workable_release_binding: WorkableReleaseBinding | None = None,
        market_decision_authority: MarketApplicationDecisionAuthority | None = None,
        materialization_receipt: CandidateApplicationMaterializationReceipt | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(path, clock=clock)
        self.repository_root = Path(repository_root).resolve(strict=True)
        if type(authority_files) is not CandidateAuthorityFiles:
            raise TypeError("candidate release requires durable authority files")
        self.authority_files = authority_files
        if (
            type(vacancy_requirements) is not tuple
            or not vacancy_requirements
            or any(
                not isinstance(value, str) or not value.strip()
                for value in vacancy_requirements
            )
        ):
            raise ValueError("candidate release vacancy requirements are invalid")
        self.vacancy_requirements = vacancy_requirements
        if (market_decision_authority is None) != (materialization_receipt is None):
            raise ValueError("market decision and materialization must be supplied together")
        if (
            workable_release_binding is not None
            and type(workable_release_binding) is not WorkableReleaseBinding
        ):
            raise TypeError("candidate Workable release requires an exact typed binding")
        if (
            workable_release_binding is not None
            and market_decision_authority is None
        ):
            raise ValueError(
                "production Workable release requires market decision materialization"
            )
        self.market_decision_authority = market_decision_authority
        self.materialization_receipt = materialization_receipt
        self.authority_binding = _verify_durable_candidate_authority(
            authority_files,
            repository_root=self.repository_root,
            vacancy_requirements=self.vacancy_requirements,
            market_decision_authority=self.market_decision_authority,
            materialization_receipt=self.materialization_receipt,
        )
        self.workable_release_binding = workable_release_binding
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS candidate_authority_release_tokens(
                     manifest_sha256 TEXT PRIMARY KEY,
                     token_sha256 TEXT NOT NULL UNIQUE,
                     job_key TEXT NOT NULL,
                     candidate_contact_sha256 TEXT NOT NULL,
                     manifest_json TEXT NOT NULL,
                     issued_at TEXT NOT NULL,
                     consumed_at TEXT,
                     UNIQUE(job_key,candidate_contact_sha256)
                   )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS candidate_authority_release_token_supersessions(
                     manifest_sha256 TEXT PRIMARY KEY,
                     token_sha256 TEXT NOT NULL UNIQUE,
                     job_key TEXT NOT NULL,
                     candidate_contact_sha256 TEXT NOT NULL,
                     manifest_json TEXT NOT NULL,
                     issued_at TEXT NOT NULL,
                     superseded_at TEXT NOT NULL,
                     replacement_manifest_sha256 TEXT NOT NULL UNIQUE
                   )"""
            )
            connection.commit()
        finally:
            connection.close()

    def _connect_candidate_gate(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _binding(
        self,
        *,
        source: ApplicationSource,
        artifacts: ApplicationArtifacts,
        contact: CandidateContact,
        questions: dict[str, tuple[str, str]] | None,
        artifact_root: str | Path,
        repository_root: str | Path,
        jurisdiction: str,
        contract_type: str,
        application_url: str,
        repository_head: str,
        issued_on: str,
    ) -> dict[str, object]:
        current_authority = _verify_durable_candidate_authority(
            self.authority_files,
            repository_root=self.repository_root,
            vacancy_requirements=self.vacancy_requirements,
            market_decision_authority=self.market_decision_authority,
            materialization_receipt=self.materialization_receipt,
        )
        if current_authority != self.authority_binding:
            raise ValueError("candidate release durable authority drifted")
        repository = Path(repository_root).resolve(strict=True)
        if repository != self.repository_root:
            raise ValueError("candidate release repository authority differs")
        if jurisdiction != "GB" or contract_type != "employee":
            raise ValueError("candidate release work-right scope is unsupported")
        if (
            source.job_key != self.authority_binding["job_key"]
            or source.role_title != self.authority_binding["role_title"]
            or source.company_name != self.authority_binding["company_name"]
            or source.vacancy_sha256
            != self.authority_binding["vacancy_sha256"]
            or (
                self.workable_release_binding is None
                and application_url != self.authority_binding["source_url"]
            )
            or contact.provenance_sha256
            != self.authority_binding["contact_authority_sha256"]
            or source.contact != contact
            or (
                self.materialization_receipt is not None
                and (
                    source.source_id
                    != self.materialization_receipt.application_source_id
                    or source.content_sha256
                    != self.materialization_receipt.application_source_sha256
                )
            )
        ):
            raise ValueError("candidate release differs from approved authority")
        route = urlsplit(application_url)
        if self.workable_release_binding is None:
            application_id = application_url.rstrip("/").rsplit("/", 1)[-1]
            if (route.scheme != "https"
                    or route.hostname not in {"job-boards.greenhouse.io", "job-boards.eu.greenhouse.io"}
                    or route.query or route.fragment or not application_id.isdigit()
                    or application_id not in source.job_key.split(":")):
                raise ValueError("candidate release official route is invalid")
        else:
            workable = self.workable_release_binding
            if (application_url != workable.application_url
                    or str(self.authority_binding["source_url"]).rstrip("/")
                    != workable.source_url.rstrip("/")
                    or workable.cv_pdf_sha256 != artifacts.cv_pdf.pdf_sha256
                    or workable.cover_letter_pdf_sha256 != artifacts.cover_letter_pdf.pdf_sha256):
                raise ValueError("candidate Workable release binding differs")
        verify_application_source(source)
        if render_pdf_artifacts(source) != artifacts:
            raise ValueError("candidate release artifacts are not deterministic")
        root = Path(artifact_root).resolve(strict=True)
        directory = root / artifacts.artifact_set_sha256
        expected_files = {
            "cv.pdf": artifacts.cv_pdf.pdf_bytes,
            "cover-letter.pdf": artifacts.cover_letter_pdf.pdf_bytes,
        }
        for name, expected in expected_files.items():
            path = directory / name
            if path.is_symlink() or path.read_bytes() != expected:
                raise ValueError("candidate release upload file differs from exact PDF")
        return {
            "schema_version": "jaa.candidate-authority-release-manifest.v1",
            "policy_sha256": POLICY_SHA256,
            "repository_head": repository_head,
            "issued_on": issued_on,
            "application_url": application_url,
            "jurisdiction": jurisdiction,
            "contract_type": contract_type,
            "authority": self.authority_binding,
            "source": {
                "source_id": source.source_id,
                "content_sha256": source.content_sha256,
                "strategy_id": source.strategy_id,
            },
            "artifacts": {
                "artifact_set_sha256": artifacts.artifact_set_sha256,
                "cv_pdf_sha256": artifacts.cv_pdf.pdf_sha256,
                "cover_letter_pdf_sha256": artifacts.cover_letter_pdf.pdf_sha256,
            },
            "official_route": {
                "adapter_id": "greenhouse.production" if self.workable_release_binding is None else "workable.production",
                "adapter_version": "v1",
                "source_identity": application_url,
            },
            "workable_release_binding": None if self.workable_release_binding is None else self.workable_release_binding.document(),
            "contact": {
                "record_id": contact.record_id,
                "record_version": contact.record_version,
                "provenance_sha256": contact.provenance_sha256,
            },
            "questions_sha256": _sha256(_json_bytes(questions or {})),
            "vacancy_requirements": list(self.vacancy_requirements),
            "vacancy_requirements_sha256": _sha256(
                _json_bytes(list(self.vacancy_requirements))
            ),
        }

    @staticmethod
    def _token(manifest_sha256: str) -> str:
        suffix = content_hash(
            {
                "contract": "jaa.candidate-authority-release-token.v1",
                "manifest_sha256": manifest_sha256,
            }
        )
        return f"jaa08.{manifest_sha256}.{suffix}"

    def issue(
        self,
        *,
        source: ApplicationSource,
        artifacts: ApplicationArtifacts,
        contact: CandidateContact,
        questions: dict[str, tuple[str, str]] | None,
        artifact_root: str | Path,
        repository_root: str | Path,
        jurisdiction: str,
        contract_type: str,
        application_url: str,
    ) -> CandidateIssuedRelease:
        now = self._trusted_utc_now()
        head = exact_clean_head(self.repository_root)
        binding = self._binding(
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=repository_root,
            jurisdiction=jurisdiction,
            contract_type=contract_type,
            application_url=application_url,
            repository_head=head,
            issued_on=now.date().isoformat(),
        )
        value = _json_bytes(binding)
        manifest_sha256 = _sha256(value)
        token = self._token(manifest_sha256)
        token_sha256 = _sha256(token.encode())
        contact_sha256 = str(self.authority_binding["contact_authority_sha256"])
        connection = self._connect_candidate_gate()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT * FROM candidate_authority_release_tokens
                   WHERE job_key=? AND candidate_contact_sha256=?""",
                (source.job_key, contact_sha256),
            ).fetchone()
            expected = (
                manifest_sha256,
                token_sha256,
                source.job_key,
                contact_sha256,
                value.decode(),
            )
            if existing is None:
                connection.execute(
                    """INSERT INTO candidate_authority_release_tokens(
                         manifest_sha256,token_sha256,job_key,
                         candidate_contact_sha256,manifest_json,issued_at
                       ) VALUES(?,?,?,?,?,?)""",
                    (*expected, now.isoformat()),
                )
            elif tuple(existing[key] for key in (
                "manifest_sha256",
                "token_sha256",
                "job_key",
                "candidate_contact_sha256",
                "manifest_json",
            )) != expected:
                if existing["consumed_at"] is not None:
                    raise ValueError("candidate release duplicate authority differs")
                connection.execute(
                    """INSERT INTO candidate_authority_release_token_supersessions(
                         manifest_sha256,token_sha256,job_key,
                         candidate_contact_sha256,manifest_json,issued_at,
                         superseded_at,replacement_manifest_sha256
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        existing["manifest_sha256"],
                        existing["token_sha256"],
                        existing["job_key"],
                        existing["candidate_contact_sha256"],
                        existing["manifest_json"],
                        existing["issued_at"],
                        now.isoformat(),
                        manifest_sha256,
                    ),
                )
                changed = connection.execute(
                    """UPDATE candidate_authority_release_tokens
                       SET manifest_sha256=?,token_sha256=?,manifest_json=?,
                           issued_at=?,consumed_at=NULL
                       WHERE manifest_sha256=? AND consumed_at IS NULL""",
                    (
                        manifest_sha256,
                        token_sha256,
                        value.decode(),
                        now.isoformat(),
                        existing["manifest_sha256"],
                    ),
                ).rowcount
                if changed != 1:
                    raise ValueError("candidate release supersession race detected")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return CandidateIssuedRelease(token, manifest_sha256, now)

    def _stored(self, release_token: str) -> tuple[sqlite3.Row, dict[str, object]]:
        parts = release_token.split(".")
        if (
            len(parts) != 3
            or parts[0] != "jaa08"
            or not HEX_64.fullmatch(parts[1])
            or release_token != self._token(parts[1])
        ):
            raise ValueError("candidate release token identity is invalid")
        connection = self._connect_candidate_gate()
        try:
            row = connection.execute(
                """SELECT * FROM candidate_authority_release_tokens
                   WHERE token_sha256=?""",
                (_sha256(release_token.encode()),),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ValueError("candidate release token is unknown")
        document = json.loads(str(row["manifest_json"]))
        if (
            canonical_json(document) + "\n" != row["manifest_json"]
            or _sha256(str(row["manifest_json"]).encode())
            != row["manifest_sha256"]
        ):
            raise ValueError("candidate release manifest is corrupt")
        return row, document

    def _verify_current(self, release_token: str, **arguments: object) -> sqlite3.Row:
        row, stored = self._stored(release_token)
        current = self._binding(
            **arguments,
            application_url=str(stored["application_url"]),
            repository_head=exact_clean_head(self.repository_root),
            issued_on=self._trusted_utc_now().date().isoformat(),
        )
        if _json_bytes(current).decode() != row["manifest_json"]:
            raise ValueError("candidate release was invalidated by authority drift")
        return row

    def verify_token_official_route(
        self,
        *,
        release_token: str,
        adapter_id: str,
        adapter_version: str,
        source_identity: str,
    ) -> object:
        _, stored = self._stored(release_token)
        route = stored.get("official_route")
        if not isinstance(route, dict):
            route = {"adapter_id": "greenhouse.production", "adapter_version": "v1", "source_identity": stored["application_url"]}
        if (
            adapter_id != route.get("adapter_id")
            or adapter_version != route.get("adapter_version")
            or source_identity != route.get("source_identity")
        ):
            raise ValueError("candidate release token cites a different official route")
        return route["source_identity"]

    def verify_current_release_token(
        self,
        *,
        release_token: str,
        **arguments: object,
    ) -> None:
        """Reapply every durable authority without changing token state."""
        self._verify_current(release_token, **arguments)

    def consume_release_token(
        self,
        *,
        release_token: str,
        consumed_at: datetime,
        **arguments: object,
    ) -> ConsumedRelease:
        if consumed_at.tzinfo is None or consumed_at.utcoffset() is None:
            raise ValueError("token consumption time must include a timezone")
        row = self._verify_current(release_token, **arguments)
        consumed = consumed_at.astimezone(timezone.utc).isoformat()
        connection = self._connect_candidate_gate()
        try:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                """UPDATE candidate_authority_release_tokens SET consumed_at=?
                   WHERE token_sha256=? AND consumed_at IS NULL""",
                (consumed, row["token_sha256"]),
            ).rowcount
            if changed != 1:
                raise ValueError("candidate release token was already consumed")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return ConsumedRelease(row["manifest_sha256"], row["token_sha256"], consumed)

    def verify_consumed_release_token(
        self,
        *,
        release_token: str,
        consumed_at: datetime,
        **arguments: object,
    ) -> ConsumedRelease:
        if consumed_at.tzinfo is None or consumed_at.utcoffset() is None:
            raise ValueError("token consumption time must include a timezone")
        row = self._verify_current(release_token, **arguments)
        consumed = consumed_at.astimezone(timezone.utc).isoformat()
        if row["consumed_at"] != consumed:
            raise ValueError("candidate release token consumption differs")
        return ConsumedRelease(row["manifest_sha256"], row["token_sha256"], consumed)


__all__ = [
    "CandidateAuthorityFiles",
    "CandidateAuthorityReleaseGate",
    "CandidateIssuedRelease",
    "POLICY_SHA256",
    "WorkableReleaseBinding",
    "WorkableUploadBinding",
]
