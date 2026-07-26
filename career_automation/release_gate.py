"""Deterministic, content-addressed JAA-08 release manifest contract.

This module can emit verdict data only. It has no browser, network, portal,
message, upload or submission capability.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from .application_artifacts import (
    PublishedArtifactReceipt,
    verify_published_application_artifacts,
)
from .application_compiler import (
    ApplicationSource,
    CandidateContact,
    ProductionApplicationCompiler,
    verify_application_source,
)
from .evidence_matching import canonical_json, content_hash
from .lifecycle import LifecycleReducer, PolicyIdentity
from .migrations import apply_jaa_08_migrations
from .models import PipelineState
from .rendering import (
    ApplicationArtifacts,
    render_pdf_artifacts,
    validate_pdf_artifact,
    verify_application_artifacts,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_VALIDATORS = (
    "authority",
    "truth",
    "eligibility",
    "freshness",
    "consistency",
    "ats",
    "duplicate",
    "official_route",
)


def _required(value: str, label: str) -> str:
    clean = value.strip()
    if not clean:
        raise ValueError(f"{label} is required")
    return clean


def _digest(value: str, label: str) -> str:
    if not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class WorkRightBinding:
    jurisdiction: str
    contract_type: str
    record_id: str
    record_version: int
    verification_sha256: str
    valid_from: date
    valid_until: date
    permitted: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.jurisdiction, "work-right jurisdiction"),
            (self.contract_type, "work-right contract type"),
            (self.record_id, "work-right record ID"),
        ):
            _required(value, label)
        if self.record_version < 1:
            raise ValueError("work-right record version must be positive")
        _digest(self.verification_sha256, "work-right verification hash")
        if self.valid_until < self.valid_from:
            raise ValueError("work-right validity interval is invalid")

    def document(self) -> dict[str, object]:
        return {
            "jurisdiction": self.jurisdiction,
            "contract_type": self.contract_type,
            "record_id": self.record_id,
            "record_version": self.record_version,
            "verification_sha256": self.verification_sha256,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "permitted": self.permitted,
        }


@dataclass(frozen=True)
class OfficialRouteBinding:
    route_id: str
    adapter_id: str
    adapter_version: str
    source_identity: str
    route_policy_sha256: str
    verified_at: date
    valid_until: date
    allowed: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.route_id, "official route ID"),
            (self.adapter_id, "official route adapter ID"),
            (self.adapter_version, "official route adapter version"),
            (self.source_identity, "official route source identity"),
        ):
            _required(value, label)
        _digest(self.route_policy_sha256, "official route policy hash")
        if self.valid_until < self.verified_at:
            raise ValueError("official route validity interval is invalid")

    def document(self) -> dict[str, object]:
        return {
            "route_id": self.route_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "source_identity": self.source_identity,
            "route_policy_sha256": self.route_policy_sha256,
            "verified_at": self.verified_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "allowed": self.allowed,
        }


@dataclass(frozen=True)
class ReleaseBinding:
    """Exact release inputs; ``job_key`` is an opaque handle, not a digest."""

    job_key: str
    candidate_identity_sha256: str
    vacancy_sha256: str
    vacancy_observed_at: date
    vacancy_valid_until: date
    dossier_sha256: str
    candidate_profile_sha256: str
    strategy_id: str
    strategy_document_sha256: str
    application_source_id: str
    application_source_sha256: str
    artifact_set_sha256: str
    artifact_receipt_sha256: str
    deterministic_writer_policy_sha256: str
    model_receipt_sha256s: tuple[str, ...]
    work_right: WorkRightBinding
    official_route: OfficialRouteBinding
    evaluated_at: date
    prior_application_count: int

    def __post_init__(self) -> None:
        _required(self.job_key, "release job key")
        for value, label in (
            (self.candidate_identity_sha256, "candidate identity hash"),
            (self.vacancy_sha256, "vacancy hash"),
            (self.dossier_sha256, "dossier hash"),
            (self.candidate_profile_sha256, "candidate profile hash"),
            (self.strategy_id, "strategy ID"),
            (self.strategy_document_sha256, "strategy document hash"),
            (self.application_source_id, "application source ID"),
            (self.application_source_sha256, "application source hash"),
            (self.artifact_set_sha256, "artifact-set hash"),
            (self.artifact_receipt_sha256, "artifact receipt hash"),
            (
                self.deterministic_writer_policy_sha256,
                "deterministic writer policy hash",
            ),
        ):
            _digest(value, label)
        if (
            len(set(self.model_receipt_sha256s))
            != len(self.model_receipt_sha256s)
        ):
            raise ValueError("model receipt hashes must be unique")
        for value in self.model_receipt_sha256s:
            _digest(value, "model receipt hash")
        if self.vacancy_valid_until < self.vacancy_observed_at:
            raise ValueError("vacancy validity interval is invalid")
        if self.prior_application_count < 0:
            raise ValueError("prior application count cannot be negative")

    def document(self) -> dict[str, object]:
        return {
            "job_key": self.job_key,
            "candidate_identity_sha256": self.candidate_identity_sha256,
            "vacancy_sha256": self.vacancy_sha256,
            "vacancy_observed_at": self.vacancy_observed_at.isoformat(),
            "vacancy_valid_until": self.vacancy_valid_until.isoformat(),
            "dossier_sha256": self.dossier_sha256,
            "candidate_profile_sha256": self.candidate_profile_sha256,
            "strategy_id": self.strategy_id,
            "strategy_document_sha256": self.strategy_document_sha256,
            "application_source_id": self.application_source_id,
            "application_source_sha256": self.application_source_sha256,
            "artifact_set_sha256": self.artifact_set_sha256,
            "artifact_receipt_sha256": self.artifact_receipt_sha256,
            "deterministic_writer_policy_sha256": (
                self.deterministic_writer_policy_sha256
            ),
            "model_receipt_sha256s": self.model_receipt_sha256s,
            "work_right": self.work_right.document(),
            "official_route": self.official_route.document(),
            "evaluated_at": self.evaluated_at.isoformat(),
            "prior_application_count": self.prior_application_count,
        }

    @property
    def input_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json(self.document()).encode()
        ).hexdigest()


@dataclass(frozen=True)
class ValidationReceipt:
    validator_id: str
    validator_version: str
    validator_impl_sha256: str
    input_sha256: str
    artifact_set_sha256: str
    decision: str
    finding_codes: tuple[str, ...] = ()
    authority_kind: str = "deterministic"

    def __post_init__(self) -> None:
        if self.validator_id not in REQUIRED_VALIDATORS:
            raise ValueError("release validator ID is unsupported")
        if self.authority_kind != "deterministic":
            raise ValueError("only deterministic validators have release authority")
        _required(self.validator_version, "release validator version")
        for value, label in (
            (self.validator_impl_sha256, "validator implementation hash"),
            (self.input_sha256, "validator input hash"),
            (self.artifact_set_sha256, "validator artifact-set hash"),
        ):
            _digest(value, label)
        if self.decision not in {"pass", "block"}:
            raise ValueError("release validation decision is invalid")
        if self.decision == "pass" and self.finding_codes:
            raise ValueError("passing validator receipt cannot retain findings")
        if self.decision == "block" and not self.finding_codes:
            raise ValueError("blocking validator receipt requires findings")
        if (
            len(set(self.finding_codes)) != len(self.finding_codes)
            or any(not value.strip() for value in self.finding_codes)
        ):
            raise ValueError("validator findings must be unique reason codes")

    def document(self) -> dict[str, object]:
        return {
            "validator_id": self.validator_id,
            "validator_version": self.validator_version,
            "validator_impl_sha256": self.validator_impl_sha256,
            "input_sha256": self.input_sha256,
            "artifact_set_sha256": self.artifact_set_sha256,
            "decision": self.decision,
            "finding_codes": self.finding_codes,
            "authority_kind": self.authority_kind,
        }


@dataclass(frozen=True)
class ReleaseManifest:
    release_manifest_sha256: str
    input_sha256: str
    binding: ReleaseBinding
    validations: tuple[ValidationReceipt, ...]
    verdict: str
    schema_version: str = "jaa08.release-manifest.v1"
    certifies_slice: bool = False
    dependency_gate: str = "JAA-07"

    def __post_init__(self) -> None:
        if self.schema_version != "jaa08.release-manifest.v1":
            raise ValueError("unsupported release manifest schema")
        if self.certifies_slice is not False or self.dependency_gate != "JAA-07":
            raise ValueError("offline release manifest cannot certify JAA-08")
        _digest(self.release_manifest_sha256, "release manifest hash")
        _digest(self.input_sha256, "release manifest input hash")
        if self.verdict != "pass":
            raise ValueError("only passing inputs can produce a release manifest")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "input_sha256": self.input_sha256,
            "binding": self.binding.document(),
            "validations": [row.document() for row in self.validations],
            "verdict": self.verdict,
            "certifies_slice": False,
            "dependency_gate": "JAA-07",
        }
        if include_identity:
            result["release_manifest_sha256"] = self.release_manifest_sha256
        return result


def _deterministic_preconditions(binding: ReleaseBinding) -> None:
    if binding.evaluated_at < binding.vacancy_observed_at:
        raise ValueError("release evaluation predates the vacancy observation")
    if binding.evaluated_at > binding.vacancy_valid_until:
        raise ValueError("vacancy is stale at release evaluation")
    work_right = binding.work_right
    if (
        not work_right.permitted
        or binding.evaluated_at < work_right.valid_from
        or binding.evaluated_at > work_right.valid_until
    ):
        raise ValueError("current work right does not permit this release")
    route = binding.official_route
    if (
        not route.allowed
        or binding.evaluated_at < route.verified_at
        or binding.evaluated_at > route.valid_until
    ):
        raise ValueError("no current allowed official application route")
    if binding.prior_application_count:
        raise ValueError("duplicate application identity blocks release")


def compile_release_manifest(
    binding: ReleaseBinding,
    validations: Iterable[ValidationReceipt],
) -> ReleaseManifest:
    """Compile a pass verdict only when every deterministic gate agrees."""
    _deterministic_preconditions(binding)
    rows = tuple(validations)
    if tuple(row.validator_id for row in rows) != REQUIRED_VALIDATORS:
        raise ValueError("release validations are missing, duplicated or unordered")
    if len({row.validator_impl_sha256 for row in rows}) != len(rows):
        raise ValueError("release validators must have independent implementations")
    if any(
        row.input_sha256 != binding.input_sha256
        or row.artifact_set_sha256 != binding.artifact_set_sha256
        for row in rows
    ):
        raise ValueError("release validator receipt binds different inputs")
    blocked = tuple(
        finding
        for row in rows
        if row.decision != "pass"
        for finding in row.finding_codes
    )
    if blocked:
        raise ValueError(f"release validation blocked: {blocked}")
    provisional = ReleaseManifest(
        "0" * 64,
        binding.input_sha256,
        binding,
        rows,
        "pass",
    )
    manifest_hash = hashlib.sha256(
        canonical_json(provisional.document(include_identity=False)).encode()
    ).hexdigest()
    return replace(provisional, release_manifest_sha256=manifest_hash)


def verify_release_manifest(manifest: ReleaseManifest) -> None:
    if manifest.input_sha256 != manifest.binding.input_sha256:
        raise ValueError("release manifest input identity is inconsistent")
    expected = hashlib.sha256(
        canonical_json(manifest.document(include_identity=False)).encode()
    ).hexdigest()
    if manifest.release_manifest_sha256 != expected:
        raise ValueError("release manifest differs from its exact content")
    replay = compile_release_manifest(manifest.binding, manifest.validations)
    if replay != manifest:
        raise ValueError("release manifest deterministic replay differs")


@dataclass(frozen=True)
class ApplicationCompilation:
    compilation_id: str
    job_key: str
    strategy_id: str
    application_source_id: str
    application_source_sha256: str
    artifact_set_sha256: str
    artifact_receipt_sha256: str
    artifact_relative_directory: str
    contact_record_id: str
    contact_record_version: int
    questions_sha256: str
    lifecycle_receipt_id: int
    schema_version: str = "jaa07.application-compilation.v1"
    certifies_slice: bool = False

    def __post_init__(self) -> None:
        for value, label in (
            (self.compilation_id, "compilation ID"),
            (self.strategy_id, "compilation strategy ID"),
            (self.application_source_id, "compilation source ID"),
            (self.application_source_sha256, "compilation source hash"),
            (self.artifact_set_sha256, "compilation artifact-set hash"),
            (self.artifact_receipt_sha256, "compilation receipt hash"),
            (self.artifact_relative_directory, "artifact directory identity"),
            (self.questions_sha256, "compilation questions hash"),
        ):
            _digest(value, label)
        _required(self.job_key, "compilation job key")
        _required(self.contact_record_id, "compilation contact record ID")
        if self.contact_record_version < 1 or self.lifecycle_receipt_id < 1:
            raise ValueError("compilation versions and receipt must be positive")
        if self.artifact_relative_directory != self.artifact_set_sha256:
            raise ValueError("compilation artifact directory is inconsistent")
        if self.certifies_slice is not False:
            raise ValueError("application compilation cannot certify JAA-07")

    def document(self, *, include_receipt: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "compilation_id": self.compilation_id,
            "job_key": self.job_key,
            "strategy_id": self.strategy_id,
            "application_source_id": self.application_source_id,
            "application_source_sha256": self.application_source_sha256,
            "artifact_set_sha256": self.artifact_set_sha256,
            "artifact_receipt_sha256": self.artifact_receipt_sha256,
            "artifact_relative_directory": self.artifact_relative_directory,
            "contact_record_id": self.contact_record_id,
            "contact_record_version": self.contact_record_version,
            "questions_sha256": self.questions_sha256,
            "certifies_slice": False,
        }
        if include_receipt:
            result["lifecycle_receipt_id"] = self.lifecycle_receipt_id
        return result


class ApplicationCompilationStore:
    """Atomically bind verified external JAA-07 artifacts into the lifecycle."""

    POLICY_ID = "career.application-compilation"
    POLICY_VERSION = "1"
    POLICY_SHA256 = hashlib.sha256(
        canonical_json(
            {
                "contract": "jaa07.application-compilation.v1",
                "rules": [
                    "recompile from current authority",
                    "rerender exact artifacts",
                    "verify existing external publication",
                    "advance atomically to application_compiled",
                ],
            }
        ).encode()
    ).hexdigest()

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        apply_jaa_08_migrations(self.path)
        self.lifecycle = LifecycleReducer(self.path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _questions_document(
        questions: dict[str, tuple[str, str]] | None,
    ) -> dict[str, tuple[str, str]]:
        values = questions or {}
        result: dict[str, tuple[str, str]] = {}
        for requirement_id, pair in sorted(values.items()):
            _required(requirement_id, "question requirement ID")
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not all(isinstance(value, str) and value.strip() for value in pair)
            ):
                raise ValueError("portal question binding must be two non-empty strings")
            result[requirement_id] = pair
        return result

    @staticmethod
    def _compilation(
        *,
        source: ApplicationSource,
        receipt: PublishedArtifactReceipt,
        contact: CandidateContact,
        questions_sha256: str,
        lifecycle_receipt_id: int,
    ) -> ApplicationCompilation:
        body = {
            "contract": "jaa07.application-compilation.v1",
            "job_key": source.job_key,
            "strategy_id": source.strategy_id,
            "application_source_id": source.source_id,
            "application_source_sha256": source.content_sha256,
            "artifact_set_sha256": receipt.artifact_set_sha256,
            "artifact_receipt_sha256": receipt.receipt_sha256,
            "artifact_relative_directory": receipt.relative_directory,
            "contact_record_id": contact.record_id,
            "contact_record_version": contact.record_version,
            "questions_sha256": questions_sha256,
        }
        return ApplicationCompilation(
            content_hash(body),
            source.job_key,
            source.strategy_id,
            source.source_id,
            source.content_sha256,
            receipt.artifact_set_sha256,
            receipt.receipt_sha256,
            receipt.relative_directory,
            contact.record_id,
            contact.record_version,
            questions_sha256,
            lifecycle_receipt_id,
        )

    def register(
        self,
        *,
        source: ApplicationSource,
        artifacts: ApplicationArtifacts,
        contact: CandidateContact,
        questions: dict[str, tuple[str, str]] | None,
        artifact_root: str | Path,
        repository_root: str | Path,
        as_of: date,
    ) -> ApplicationCompilation:
        """Re-resolve and atomically register one exact existing publication."""
        question_rows = self._questions_document(questions)
        expected_source = ProductionApplicationCompiler(self.path).compile(
            source.strategy_id,
            as_of=as_of,
            contact=contact,
            questions=question_rows,
        )
        if expected_source != source:
            raise ValueError("application source differs from current authority")
        expected_artifacts = render_pdf_artifacts(expected_source)
        if expected_artifacts != artifacts:
            raise ValueError("application artifacts differ from deterministic rendering")
        publication = verify_published_application_artifacts(
            source,
            artifacts,
            root=artifact_root,
            repository_root=repository_root,
        )
        questions_sha256 = hashlib.sha256(
            canonical_json(question_rows).encode()
        ).hexdigest()
        provisional = self._compilation(
            source=source,
            receipt=publication,
            contact=contact,
            questions_sha256=questions_sha256,
            lifecycle_receipt_id=1,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM application_compilations WHERE strategy_id=?",
                (source.strategy_id,),
            ).fetchone()
            transition = self.lifecycle.commit_in_transaction(
                connection,
                job_key=source.job_key,
                to_state=PipelineState.APPLICATION_COMPILED,
                policy=PolicyIdentity(
                    self.POLICY_ID,
                    self.POLICY_VERSION,
                    self.POLICY_SHA256,
                ),
                inputs={
                    "strategy_id": source.strategy_id,
                    "source_id": source.source_id,
                    "source_sha256": source.content_sha256,
                    "artifact_set_sha256": artifacts.artifact_set_sha256,
                    "artifact_receipt_sha256": publication.receipt_sha256,
                    "questions_sha256": questions_sha256,
                },
                outputs={
                    "compilation_id": provisional.compilation_id,
                    "artifact_relative_directory": (
                        publication.relative_directory
                    ),
                },
                idempotency_key=(
                    f"application-compilation:{source.job_key}:"
                    f"{provisional.compilation_id}"
                ),
            )
            compilation = replace(
                provisional,
                lifecycle_receipt_id=transition.receipt_id,
            )
            document_json = canonical_json(
                compilation.document(include_receipt=False)
            )
            expected = (
                compilation.compilation_id,
                compilation.job_key,
                compilation.strategy_id,
                compilation.application_source_id,
                compilation.application_source_sha256,
                compilation.artifact_set_sha256,
                compilation.artifact_receipt_sha256,
                compilation.artifact_relative_directory,
                compilation.contact_record_id,
                compilation.contact_record_version,
                compilation.questions_sha256,
                document_json,
                compilation.lifecycle_receipt_id,
            )
            if existing is not None:
                actual = tuple(existing[key] for key in (
                    "compilation_id",
                    "job_key",
                    "strategy_id",
                    "application_source_id",
                    "application_source_hash",
                    "artifact_set_hash",
                    "artifact_receipt_hash",
                    "artifact_relative_directory",
                    "contact_record_id",
                    "contact_record_version",
                    "questions_hash",
                    "compilation_document_json",
                    "lifecycle_receipt_id",
                ))
                if actual != expected:
                    raise ValueError(
                        "strategy already has a different application compilation"
                    )
            else:
                connection.execute(
                    """INSERT INTO application_compilations(
                         compilation_id,job_key,strategy_id,
                         application_source_id,application_source_hash,
                         artifact_set_hash,artifact_receipt_hash,
                         artifact_relative_directory,contact_record_id,
                         contact_record_version,questions_hash,
                         compilation_document_json,lifecycle_receipt_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    expected,
                )
            connection.commit()
            return compilation
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


@dataclass(frozen=True)
class IssuedRelease:
    manifest: ReleaseManifest
    release_token: str
    token_sha256: str
    lifecycle_receipt_id: int

    def __post_init__(self) -> None:
        if not self.release_token.startswith("jaa08."):
            raise ValueError("release token format is invalid")
        _digest(self.token_sha256, "release token hash")
        if (
            hashlib.sha256(self.release_token.encode()).hexdigest()
            != self.token_sha256
        ):
            raise ValueError("release token differs from its hash")
        if self.lifecycle_receipt_id < 1:
            raise ValueError("release lifecycle receipt must be positive")


@dataclass(frozen=True)
class ConsumedRelease:
    release_manifest_sha256: str
    token_sha256: str
    consumed_at: str

    def __post_init__(self) -> None:
        _digest(self.release_manifest_sha256, "consumed manifest hash")
        _digest(self.token_sha256, "consumed token hash")
        parsed = datetime.fromisoformat(self.consumed_at)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("token consumption time must include a timezone")


class ReleaseGateStore:
    """Re-resolve all authority and atomically issue one offline release token."""

    POLICY_ID = "career.release-gate"
    POLICY_VERSION = "1"
    POLICY_SHA256 = hashlib.sha256(
        canonical_json(
            {
                "contract": "jaa08.release-gate.v1",
                "validators": REQUIRED_VALIDATORS,
                "vacancy_freshness_days": 30,
                "token": "one-use-hash-only-storage",
                "action_capability": "none",
            }
        ).encode()
    ).hexdigest()
    WRITER_POLICY_SHA256 = hashlib.sha256(
        canonical_json(
            {
                "contract": "jaa07.deterministic-writer.v1",
                "style_slots": (
                    "Relevant evidence",
                    "Dear Hiring Manager",
                    "Kind regards",
                    "A relevant example follows.",
                ),
                "factual_mode": "verbatim-approved-atoms",
            }
        ).encode()
    ).hexdigest()
    VALIDATOR_CONTRACTS = {
        "authority": "bind-current-compilation-source-contact-and-publication",
        "truth": "recompile-source-from-current-approved-authority",
        "eligibility": "require-current-approved-permitted-work-right",
        "freshness": "require-explicit-clock-within-vacancy-validity",
        "consistency": "require-source-render-compilation-publication-hash-agreement",
        "ats": "strict-parse-and-reconstruct-two-page-cv-one-page-letter",
        "duplicate": "require-zero-prior-release-for-job-and-candidate",
        "official_route": "require-one-current-allowed-exact-official-route",
    }
    VALIDATOR_IMPL_SHA256S = {
        validator_id: content_hash(
            {
                "contract": f"jaa08.{validator_id}-validator.v1",
                "rule": rule,
                "authority_kind": "deterministic",
            }
        )
        for validator_id, rule in VALIDATOR_CONTRACTS.items()
    }

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        apply_jaa_08_migrations(self.path)
        self.lifecycle = LifecycleReducer(self.path)
        self.compilations = ApplicationCompilationStore(self.path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def register_official_route(
        self,
        *,
        job_key: str,
        route: OfficialRouteBinding,
    ) -> OfficialRouteBinding:
        """Register an exact offline route policy; never probe or use the route."""
        document_json = canonical_json(route.document())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM pipeline_jobs WHERE job_key=?",
                (job_key,),
            ).fetchone() is None:
                raise KeyError(job_key)
            existing = connection.execute(
                "SELECT * FROM official_application_routes WHERE route_id=?",
                (route.route_id,),
            ).fetchone()
            expected = (
                route.route_id,
                job_key,
                route.adapter_id,
                route.adapter_version,
                route.source_identity,
                route.route_policy_sha256,
                route.verified_at.isoformat(),
                route.valid_until.isoformat(),
                int(route.allowed),
                document_json,
            )
            if existing is None:
                connection.execute(
                    """INSERT INTO official_application_routes(
                         route_id,job_key,adapter_id,adapter_version,
                         source_identity,route_policy_hash,verified_at,
                         valid_until,allowed,route_document_json)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    expected,
                )
            else:
                actual = tuple(existing[key] for key in (
                    "route_id",
                    "job_key",
                    "adapter_id",
                    "adapter_version",
                    "source_identity",
                    "route_policy_hash",
                    "verified_at",
                    "valid_until",
                    "allowed",
                    "route_document_json",
                ))
                if actual != expected:
                    raise ValueError(
                        "official route identity already has different authority"
                    )
            connection.commit()
        return route

    @staticmethod
    def _work_right(
        connection: sqlite3.Connection,
        *,
        jurisdiction: str,
        contract_type: str,
        as_of: date,
    ) -> WorkRightBinding:
        rows = connection.execute(
            """SELECT record.*,provenance.source_hash,
                      decision.decision_id,decision.verifier_kind,
                      decision.policy_id,decision.policy_version,
                      decision.policy_hash,decision.reason
               FROM candidate_records record
               JOIN candidate_provenance provenance
                 ON provenance.provenance_id=record.provenance_id
               JOIN candidate_verification_decisions decision
                 ON decision.target_kind='record'
                AND decision.target_id=record.record_id
                AND decision.target_version=record.version
                AND decision.decision='approved'
               WHERE record.record_kind='work_right'
                 AND record.subject='permission'
                 AND record.epistemic_state='fact'
                 AND record.jurisdiction IN (?, '*')
                 AND record.contract_type IN (?, '*')
                 AND (record.valid_from IS NULL OR record.valid_from<=?)
                 AND (record.valid_until IS NULL OR record.valid_until>=?)
                 AND NOT EXISTS(
                   SELECT 1 FROM candidate_records newer
                   WHERE newer.record_id=record.record_id
                     AND newer.version>record.version
                 )
               ORDER BY (record.jurisdiction=?) DESC,
                        (record.contract_type=?) DESC,record.version DESC""",
            (
                jurisdiction,
                contract_type,
                as_of.isoformat(),
                as_of.isoformat(),
                jurisdiction,
                contract_type,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise ValueError("work-right authority is missing or ambiguous")
        row = rows[0]
        try:
            value = json.loads(str(row["value_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("work-right authority is not valid JSON") from exc
        if (
            not isinstance(value, dict)
            or canonical_json(value) != str(row["value_json"])
            or value.get("permitted") is not True
        ):
            raise ValueError("work-right authority does not permit release")
        verification = {
            "decision_id": str(row["decision_id"]),
            "verifier_kind": str(row["verifier_kind"]),
            "policy_id": str(row["policy_id"]),
            "policy_version": str(row["policy_version"]),
            "policy_hash": str(row["policy_hash"]),
            "reason": str(row["reason"]),
            "record_source_hash": str(row["source_hash"]),
        }
        return WorkRightBinding(
            jurisdiction,
            contract_type,
            str(row["record_id"]),
            int(row["version"]),
            content_hash(verification),
            (
                date.min
                if row["valid_from"] is None
                else date.fromisoformat(str(row["valid_from"]))
            ),
            (
                date.max
                if row["valid_until"] is None
                else date.fromisoformat(str(row["valid_until"]))
            ),
            True,
        )

    @staticmethod
    def _official_route(
        connection: sqlite3.Connection,
        *,
        job_key: str,
        as_of: date,
    ) -> OfficialRouteBinding:
        rows = connection.execute(
            """SELECT * FROM official_application_routes
               WHERE job_key=? AND allowed=1
                 AND verified_at<=? AND valid_until>=?""",
            (job_key, as_of.isoformat(), as_of.isoformat()),
        ).fetchall()
        if len(rows) != 1:
            raise ValueError("official application route is missing or ambiguous")
        row = rows[0]
        route = OfficialRouteBinding(
            str(row["route_id"]),
            str(row["adapter_id"]),
            str(row["adapter_version"]),
            str(row["source_identity"]),
            str(row["route_policy_hash"]),
            date.fromisoformat(str(row["verified_at"])),
            date.fromisoformat(str(row["valid_until"])),
            bool(row["allowed"]),
        )
        try:
            stored = json.loads(str(row["route_document_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("official route document is invalid") from exc
        if (
            not isinstance(stored, dict)
            or canonical_json(stored) != str(row["route_document_json"])
            or stored != route.document()
        ):
            raise ValueError("official route differs from its exact document")
        return route

    @staticmethod
    def _compilation_row(
        connection: sqlite3.Connection,
        compilation_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """SELECT compilation.*,strategy.dossier_hash,
                      strategy.candidate_profile_hash,
                      strategy.document_hash AS strategy_document_hash,
                      job.payload_hash AS vacancy_hash,
                      job.created_at AS vacancy_created_at,
                      job.state AS job_state
               FROM application_compilations compilation
               JOIN application_strategies strategy
                 ON strategy.strategy_id=compilation.strategy_id
               JOIN pipeline_jobs job ON job.job_key=compilation.job_key
               WHERE compilation.compilation_id=?""",
            (compilation_id,),
        ).fetchone()
        if row is None:
            raise KeyError(compilation_id)
        return row

    def _binding(
        self,
        connection: sqlite3.Connection,
        *,
        compilation: ApplicationCompilation,
        contact: CandidateContact,
        jurisdiction: str,
        contract_type: str,
        evaluated_at: date,
        expected_state: PipelineState = PipelineState.APPLICATION_COMPILED,
    ) -> ReleaseBinding:
        row = self._compilation_row(connection, compilation.compilation_id)
        if (
            str(row["job_state"]) != expected_state.value
            or str(row["strategy_id"]) != compilation.strategy_id
            or str(row["application_source_id"])
            != compilation.application_source_id
            or str(row["application_source_hash"])
            != compilation.application_source_sha256
            or str(row["artifact_set_hash"])
            != compilation.artifact_set_sha256
            or str(row["artifact_receipt_hash"])
            != compilation.artifact_receipt_sha256
            or str(row["contact_record_id"]) != contact.record_id
            or int(row["contact_record_version"]) != contact.record_version
        ):
            raise ValueError("durable application compilation is inconsistent")
        observed_at = datetime.fromisoformat(
            str(row["vacancy_created_at"]).replace("Z", "+00:00")
        ).date()
        valid_until = observed_at + timedelta(days=30)
        route = self._official_route(
            connection,
            job_key=compilation.job_key,
            as_of=evaluated_at,
        )
        work_right = self._work_right(
            connection,
            jurisdiction=jurisdiction,
            contract_type=contract_type,
            as_of=evaluated_at,
        )
        candidate_identity = content_hash(
            {
                "contact_record_id": contact.record_id,
                "contact_record_version": contact.record_version,
                "contact_provenance_sha256": contact.provenance_sha256,
                "candidate_profile_sha256": str(
                    row["candidate_profile_hash"]
                ),
            }
        )
        prior_count = int(connection.execute(
            """SELECT COUNT(*) FROM release_manifests
               WHERE job_key=? AND candidate_identity_hash=?""",
            (compilation.job_key, candidate_identity),
        ).fetchone()[0])
        return ReleaseBinding(
            compilation.job_key,
            candidate_identity,
            str(row["vacancy_hash"]),
            observed_at,
            valid_until,
            str(row["dossier_hash"]),
            str(row["candidate_profile_hash"]),
            compilation.strategy_id,
            str(row["strategy_document_hash"]),
            compilation.application_source_id,
            compilation.application_source_sha256,
            compilation.artifact_set_sha256,
            compilation.artifact_receipt_sha256,
            self.WRITER_POLICY_SHA256,
            (),
            work_right,
            route,
            evaluated_at,
            prior_count,
        )

    @staticmethod
    def _validate_authority(
        binding: ReleaseBinding,
        compilation: ApplicationCompilation,
        source: ApplicationSource,
        contact: CandidateContact,
        publication: PublishedArtifactReceipt,
    ) -> None:
        if (
            compilation.job_key != binding.job_key
            or compilation.strategy_id != binding.strategy_id
            or compilation.application_source_id
            != binding.application_source_id
            or compilation.application_source_sha256
            != binding.application_source_sha256
            or compilation.contact_record_id != contact.record_id
            or compilation.contact_record_version != contact.record_version
            or source.source_id != binding.application_source_id
            or source.content_sha256 != binding.application_source_sha256
            or publication.receipt_sha256
            != binding.artifact_receipt_sha256
        ):
            raise ValueError("authority validator found a stale release input")

    @staticmethod
    def _validate_truth(
        source: ApplicationSource,
        current_source: ApplicationSource,
    ) -> None:
        verify_application_source(source)
        if source != current_source:
            raise ValueError("truth validator found source authority drift")

    @staticmethod
    def _validate_eligibility(binding: ReleaseBinding) -> None:
        work_right = binding.work_right
        if (
            not work_right.permitted
            or binding.evaluated_at < work_right.valid_from
            or binding.evaluated_at > work_right.valid_until
        ):
            raise ValueError("eligibility validator found no current work right")

    @staticmethod
    def _validate_freshness(binding: ReleaseBinding) -> None:
        if (
            binding.evaluated_at < binding.vacancy_observed_at
            or binding.evaluated_at > binding.vacancy_valid_until
        ):
            raise ValueError("freshness validator found a stale vacancy")

    @staticmethod
    def _validate_consistency(
        binding: ReleaseBinding,
        compilation: ApplicationCompilation,
        source: ApplicationSource,
        artifacts: ApplicationArtifacts,
        current_artifacts: ApplicationArtifacts,
        publication: PublishedArtifactReceipt,
    ) -> None:
        if (
            artifacts != current_artifacts
            or artifacts.source_id != source.source_id
            or artifacts.artifact_set_sha256
            != binding.artifact_set_sha256
            or compilation.artifact_set_sha256
            != binding.artifact_set_sha256
            or publication.artifact_set_sha256
            != binding.artifact_set_sha256
            or compilation.artifact_receipt_sha256
            != publication.receipt_sha256
        ):
            raise ValueError("consistency validator found an artifact mismatch")

    @staticmethod
    def _validate_ats(
        source: ApplicationSource,
        artifacts: ApplicationArtifacts,
    ) -> None:
        verify_application_artifacts(artifacts)
        cv_facts = tuple(
            row.text for row in source.facts if row.document_kind == "cv"
        )
        letter_facts = tuple(
            row.text
            for row in source.facts
            if row.document_kind == "cover_letter"
        )
        validate_pdf_artifact(
            artifacts.cv_pdf,
            expected_page_count=2,
            required_values=(
                source.contact.full_name,
                source.contact.email,
                source.contact.phone,
                source.contact.city,
                *cv_facts,
            ),
        )
        validate_pdf_artifact(
            artifacts.cover_letter_pdf,
            expected_page_count=1,
            required_values=(
                source.contact.full_name,
                source.contact.email,
                source.contact.phone,
                source.contact.city,
                source.role_title,
                source.company_name,
                *letter_facts,
            ),
        )

    @staticmethod
    def _validate_duplicate(binding: ReleaseBinding) -> None:
        if binding.prior_application_count != 0:
            raise ValueError("duplicate validator found a prior release")

    @staticmethod
    def _validate_official_route(binding: ReleaseBinding) -> None:
        route = binding.official_route
        if (
            not route.allowed
            or binding.evaluated_at < route.verified_at
            or binding.evaluated_at > route.valid_until
        ):
            raise ValueError(
                "official-route validator found no current allowed route"
            )

    @classmethod
    def _validations(
        cls,
        binding: ReleaseBinding,
        *,
        compilation: ApplicationCompilation,
        source: ApplicationSource,
        current_source: ApplicationSource,
        artifacts: ApplicationArtifacts,
        current_artifacts: ApplicationArtifacts,
        contact: CandidateContact,
        publication: PublishedArtifactReceipt,
    ) -> tuple[ValidationReceipt, ...]:
        """Execute each named deterministic validator before attesting pass."""
        cls._validate_authority(
            binding,
            compilation,
            source,
            contact,
            publication,
        )
        cls._validate_truth(source, current_source)
        cls._validate_eligibility(binding)
        cls._validate_freshness(binding)
        cls._validate_consistency(
            binding,
            compilation,
            source,
            artifacts,
            current_artifacts,
            publication,
        )
        cls._validate_ats(source, artifacts)
        cls._validate_duplicate(binding)
        cls._validate_official_route(binding)
        return tuple(
            ValidationReceipt(
                validator_id,
                "1",
                cls.VALIDATOR_IMPL_SHA256S[validator_id],
                binding.input_sha256,
                binding.artifact_set_sha256,
                "pass",
            )
            for validator_id in REQUIRED_VALIDATORS
        )

    def evaluate_and_issue(
        self,
        *,
        compilation_id: str,
        source: ApplicationSource,
        artifacts: ApplicationArtifacts,
        contact: CandidateContact,
        questions: dict[str, tuple[str, str]] | None,
        artifact_root: str | Path,
        repository_root: str | Path,
        jurisdiction: str,
        contract_type: str,
        evaluated_at: date,
    ) -> IssuedRelease:
        """Issue one token; never invoke or expose any consequential action."""
        compilation = self.compilations.register(
            source=source,
            artifacts=artifacts,
            contact=contact,
            questions=questions,
            artifact_root=artifact_root,
            repository_root=repository_root,
            as_of=evaluated_at,
        )
        if compilation.compilation_id != compilation_id:
            raise ValueError("release cites a different compilation identity")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            # The reserved writer lock makes the authority snapshot stable
            # while the compiler reads it through its own read connection.
            current_source = ProductionApplicationCompiler(self.path).compile(
                source.strategy_id,
                as_of=evaluated_at,
                contact=contact,
                questions=(
                    ApplicationCompilationStore._questions_document(questions)
                ),
            )
            current_artifacts = render_pdf_artifacts(current_source)
            publication = verify_published_application_artifacts(
                source,
                artifacts,
                root=artifact_root,
                repository_root=repository_root,
            )
            binding = self._binding(
                connection,
                compilation=compilation,
                contact=contact,
                jurisdiction=jurisdiction,
                contract_type=contract_type,
                evaluated_at=evaluated_at,
            )
            validations = self._validations(
                binding,
                compilation=compilation,
                source=source,
                current_source=current_source,
                artifacts=artifacts,
                current_artifacts=current_artifacts,
                contact=contact,
                publication=publication,
            )
            manifest = compile_release_manifest(binding, validations)
            token = (
                f"jaa08.{manifest.release_manifest_sha256}."
                f"{secrets.token_urlsafe(32)}"
            )
            token_sha256 = hashlib.sha256(token.encode()).hexdigest()
            attempt_id = content_hash(
                {
                    "contract": "jaa08.release-attempt.v1",
                    "compilation_id": compilation.compilation_id,
                    "evaluated_at": evaluated_at.isoformat(),
                    "input_sha256": binding.input_sha256,
                    "verdict": "pass",
                }
            )
            transition = self.lifecycle.commit_in_transaction(
                connection,
                job_key=compilation.job_key,
                to_state=PipelineState.RELEASED,
                policy=PolicyIdentity(
                    self.POLICY_ID,
                    self.POLICY_VERSION,
                    self.POLICY_SHA256,
                ),
                inputs=binding.document(),
                outputs={
                    "attempt_id": attempt_id,
                    "release_manifest_sha256": (
                        manifest.release_manifest_sha256
                    ),
                    "token_sha256": token_sha256,
                },
                idempotency_key=(
                    f"release-gate:{compilation.job_key}:"
                    f"{manifest.release_manifest_sha256}"
                ),
            )
            connection.execute(
                """INSERT INTO release_gate_attempts(
                     attempt_id,compilation_id,evaluated_at,input_hash,
                     verdict,finding_codes_json,lifecycle_receipt_id)
                   VALUES(?,?,?,?,?,'[]',?)""",
                (
                    attempt_id,
                    compilation.compilation_id,
                    evaluated_at.isoformat(),
                    binding.input_sha256,
                    "pass",
                    transition.receipt_id,
                ),
            )
            connection.execute(
                """INSERT INTO release_manifests(
                     release_manifest_hash,attempt_id,compilation_id,job_key,
                     candidate_identity_hash,input_hash,artifact_set_hash,
                     manifest_document_json)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (
                    manifest.release_manifest_sha256,
                    attempt_id,
                    compilation.compilation_id,
                    compilation.job_key,
                    binding.candidate_identity_sha256,
                    binding.input_sha256,
                    binding.artifact_set_sha256,
                    canonical_json(manifest.document()),
                ),
            )
            for validation in validations:
                connection.execute(
                    """INSERT INTO release_validation_receipts(
                         release_manifest_hash,validator_id,validator_version,
                         validator_impl_hash,input_hash,artifact_set_hash,
                         decision,receipt_document_json)
                       VALUES(?,?,?,?,?,?,'pass',?)""",
                    (
                        manifest.release_manifest_sha256,
                        validation.validator_id,
                        validation.validator_version,
                        validation.validator_impl_sha256,
                        validation.input_sha256,
                        validation.artifact_set_sha256,
                        canonical_json(validation.document()),
                    ),
                )
            issued_at = datetime.combine(
                evaluated_at,
                datetime.min.time(),
                tzinfo=timezone.utc,
            ).isoformat()
            connection.execute(
                """INSERT INTO release_tokens(
                     token_hash,release_manifest_hash,issued_at)
                   VALUES(?,?,?)""",
                (
                    token_sha256,
                    manifest.release_manifest_sha256,
                    issued_at,
                ),
            )
            connection.commit()
            return IssuedRelease(
                manifest,
                token,
                token_sha256,
                transition.receipt_id,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _stored_compilation(row: sqlite3.Row) -> ApplicationCompilation:
        compilation = ApplicationCompilation(
            str(row["compilation_id"]),
            str(row["job_key"]),
            str(row["strategy_id"]),
            str(row["application_source_id"]),
            str(row["application_source_hash"]),
            str(row["artifact_set_hash"]),
            str(row["artifact_receipt_hash"]),
            str(row["artifact_relative_directory"]),
            str(row["contact_record_id"]),
            int(row["contact_record_version"]),
            str(row["questions_hash"]),
            int(row["lifecycle_receipt_id"]),
        )
        try:
            document = json.loads(str(row["compilation_document_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "stored application compilation is invalid JSON"
            ) from exc
        if (
            not isinstance(document, dict)
            or canonical_json(document)
            != str(row["compilation_document_json"])
            or document != compilation.document(include_receipt=False)
        ):
            raise ValueError(
                "stored application compilation differs from its identity"
            )
        return compilation

    @staticmethod
    def _stored_manifest_document(
        row: sqlite3.Row,
    ) -> dict[str, object]:
        try:
            document = json.loads(str(row["manifest_document_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("stored release manifest is invalid JSON") from exc
        if (
            not isinstance(document, dict)
            or canonical_json(document)
            != str(row["manifest_document_json"])
        ):
            raise ValueError("stored release manifest is not canonical")
        identity = document.get("release_manifest_sha256")
        unsigned = dict(document)
        unsigned.pop("release_manifest_sha256", None)
        expected = hashlib.sha256(canonical_json(unsigned).encode()).hexdigest()
        if (
            identity != str(row["release_manifest_hash"])
            or expected != str(row["release_manifest_hash"])
            or document.get("input_sha256") != str(row["input_hash"])
        ):
            raise ValueError("stored release manifest identity is invalid")
        return document

    @staticmethod
    def _verify_stored_validations(
        connection: sqlite3.Connection,
        manifest: ReleaseManifest,
    ) -> None:
        rows = connection.execute(
            """SELECT * FROM release_validation_receipts
               WHERE release_manifest_hash=?
               ORDER BY CASE validator_id
                 WHEN 'authority' THEN 1
                 WHEN 'truth' THEN 2
                 WHEN 'eligibility' THEN 3
                 WHEN 'freshness' THEN 4
                 WHEN 'consistency' THEN 5
                 WHEN 'ats' THEN 6
                 WHEN 'duplicate' THEN 7
                 WHEN 'official_route' THEN 8
               END""",
            (manifest.release_manifest_sha256,),
        ).fetchall()
        if len(rows) != len(REQUIRED_VALIDATORS):
            raise ValueError("stored release validations are incomplete")
        for row, expected in zip(rows, manifest.validations, strict=True):
            try:
                document = json.loads(str(row["receipt_document_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    "stored release validation is invalid JSON"
                ) from exc
            if (
                str(row["validator_id"]) != expected.validator_id
                or str(row["validator_version"])
                != expected.validator_version
                or str(row["validator_impl_hash"])
                != expected.validator_impl_sha256
                or str(row["input_hash"]) != expected.input_sha256
                or str(row["artifact_set_hash"])
                != expected.artifact_set_sha256
                or str(row["decision"]) != expected.decision
                or canonical_json(document)
                != str(row["receipt_document_json"])
                or canonical_json(document)
                != canonical_json(expected.document())
            ):
                raise ValueError(
                    "stored release validation differs from current authority"
                )

    def consume_release_token(
        self,
        *,
        release_token: str,
        source: ApplicationSource,
        artifacts: ApplicationArtifacts,
        contact: CandidateContact,
        questions: dict[str, tuple[str, str]] | None,
        artifact_root: str | Path,
        repository_root: str | Path,
        jurisdiction: str,
        contract_type: str,
        consumed_at: datetime,
    ) -> ConsumedRelease:
        """Consume once after full same-day drift checks; perform no action."""
        if (
            not release_token.startswith("jaa08.")
            or len(release_token.split(".")) != 3
        ):
            raise ValueError("release token format is invalid")
        if consumed_at.tzinfo is None or consumed_at.utcoffset() is None:
            raise ValueError("token consumption time must include a timezone")
        consumed_utc = consumed_at.astimezone(timezone.utc)
        consumed_iso = consumed_utc.isoformat()
        token_sha256 = hashlib.sha256(release_token.encode()).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT token.token_hash,token.consumed_at,
                          manifest.release_manifest_hash,
                          manifest.input_hash,
                          manifest.manifest_document_json,
                          compilation.compilation_id,
                          compilation.job_key,
                          compilation.strategy_id,
                          compilation.application_source_id,
                          compilation.application_source_hash,
                          compilation.artifact_set_hash,
                          compilation.artifact_receipt_hash,
                          compilation.artifact_relative_directory,
                          compilation.contact_record_id,
                          compilation.contact_record_version,
                          compilation.questions_hash,
                          compilation.compilation_document_json,
                          compilation.lifecycle_receipt_id
                   FROM release_tokens token
                   JOIN release_manifests manifest
                     ON manifest.release_manifest_hash=
                        token.release_manifest_hash
                   JOIN application_compilations compilation
                     ON compilation.compilation_id=manifest.compilation_id
                   WHERE token.token_hash=?""",
                (token_sha256,),
            ).fetchone()
            if row is None:
                raise ValueError("release token is unknown")
            if row["consumed_at"] is not None:
                raise ValueError("release token was already consumed")
            if (
                release_token.split(".")[1]
                != str(row["release_manifest_hash"])
            ):
                raise ValueError(
                    "release token cites a different manifest identity"
                )
            stored_document = self._stored_manifest_document(row)
            binding_document = stored_document.get("binding")
            if not isinstance(binding_document, dict):
                raise ValueError("stored release binding is invalid")
            try:
                issued_date = date.fromisoformat(
                    str(binding_document["evaluated_at"])
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    "stored release clock is invalid"
                ) from exc
            if consumed_utc.date() != issued_date:
                raise ValueError(
                    "release token is valid only on its evaluated UTC date"
                )
            compilation = self._stored_compilation(row)
            current_source = ProductionApplicationCompiler(
                self.path
            ).compile(
                source.strategy_id,
                as_of=consumed_utc.date(),
                contact=contact,
                questions=(
                    ApplicationCompilationStore._questions_document(questions)
                ),
            )
            current_artifacts = render_pdf_artifacts(current_source)
            publication = verify_published_application_artifacts(
                source,
                artifacts,
                root=artifact_root,
                repository_root=repository_root,
            )
            current_binding = self._binding(
                connection,
                compilation=compilation,
                contact=contact,
                jurisdiction=jurisdiction,
                contract_type=contract_type,
                evaluated_at=consumed_utc.date(),
                expected_state=PipelineState.RELEASED,
            )
            if current_binding.prior_application_count != 1:
                raise ValueError(
                    "release identity has an unexpected application count"
                )
            replay_binding = replace(
                current_binding,
                evaluated_at=issued_date,
                prior_application_count=0,
            )
            validations = self._validations(
                replay_binding,
                compilation=compilation,
                source=source,
                current_source=current_source,
                artifacts=artifacts,
                current_artifacts=current_artifacts,
                contact=contact,
                publication=publication,
            )
            replay_manifest = compile_release_manifest(
                replay_binding,
                validations,
            )
            verify_release_manifest(replay_manifest)
            if canonical_json(replay_manifest.document()) != canonical_json(
                stored_document
            ):
                raise ValueError(
                    "release token was invalidated by bound-input drift"
                )
            self._verify_stored_validations(connection, replay_manifest)
            changed = connection.execute(
                """UPDATE release_tokens SET consumed_at=?
                   WHERE token_hash=? AND consumed_at IS NULL""",
                (consumed_iso, token_sha256),
            ).rowcount
            if changed != 1:
                raise ValueError("release token consumption lost its lease")
            connection.commit()
            return ConsumedRelease(
                replay_manifest.release_manifest_sha256,
                token_sha256,
                consumed_iso,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
