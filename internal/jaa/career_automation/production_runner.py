"""Executable queue-to-recorder-to-certified-executor production runner."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import pickle
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Mapping, Protocol, Sequence

from playwright.sync_api import Page

from .application_archive import ApplicationArchive
from .application_compiler import ApplicationSource, CandidateContact
from .application_sanity_review import SanityReviewReceipt
from .browser_executor import (
    GreenhouseSuccessEvidence,
)
from .candidate_release_authority import CandidateReleaseExecutionAuthority
from cv_generation.service import CandidateApplicationPackage
from .external_document_assurance import ExternalDocumentAssuranceReceipt
from .evidence_matching import canonical_json
from .production_ats_executor import (
    CertifiedGreenhouseSubmitExecutor,
    GmailConfirmationChecker,
    GreenhouseSubmissionPlan,
    ProductionATSBoundaryError,
    ProductionSubmissionReceipt,
)
from .production_attempt import GreenhouseAttemptRecorder, ProductionIdentity
from .production_queue import (
    LiveVacancy,
    QueueItem,
    build_ascending_queue,
    prior_attempts_from_archive,
)
from .provider_observation_capture import exact_clean_head
from .release_gate import ReleaseGateStore
from .rendering import ApplicationArtifacts


PRODUCTION_FACTORY_REFERENCE = (
    "career_automation.gutua_greenhouse_session:create_session"
)
OWNED_CANDIDATE_GENERATOR = (
    "career_automation.production_runner:GeneratedRevisionSink."
    "generate_candidate_application.v3"
)
_GENERATOR_SOURCE_PATHS = (
    "cv_generation/constraints.py",
    "cv_generation/service.py",
    "career_automation/candidate_generation_worker.py",
    "career_automation/production_runner.py",
    "career_automation/candidate_application_factory.py",
    "career_automation/application_compiler.py",
    "career_automation/application_strategy.py",
    "career_automation/candidate_authority.py",
    "career_automation/database.py",
    "career_automation/employer_research.py",
    "career_automation/evidence_matching.py",
    "career_automation/external_document_assurance.py",
    "career_automation/lifecycle.py",
    "career_automation/migrations.py",
    "career_automation/models.py",
    "career_automation/rendering.py",
)


@dataclass(frozen=True)
class ProductionRunCandidate:
    vacancy: LiveVacancy
    complete_vacancy: bytes
    structured_vacancy: dict[str, object]
    assessment: dict[str, object]
    network_evidence: tuple[Mapping[str, object], ...] = ()


@dataclass(frozen=True)
class GeneratedApplicationRevision:
    role: str
    value: bytes
    media_type: str
    prior_sha256: str | None
    approved: bool
    rejection_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class SinkBoundGenerationAuthority:
    """Sealed identity derived only from revisions already sent to the archive."""

    revisions: tuple[GeneratedApplicationRevision, ...]
    inventory_sha256: str
    generator_identity: str
    repository_head: str
    generator_source_sha256s: tuple[tuple[str, str], ...]
    archive_event_sha256s: tuple[str, ...]
    _sink_marker: object

    def document(self) -> dict[str, object]:
        return {
            "schema_version": "jaa.sink-bound-generation-authority.v2",
            "inventory_sha256": self.inventory_sha256,
            "generator_identity": self.generator_identity,
            "repository_head": self.repository_head,
            "generator_source_sha256s": dict(self.generator_source_sha256s),
            "archive_event_sha256s": list(self.archive_event_sha256s),
            "revisions": [
                {
                    "role": row.role,
                    "sha256": hashlib.sha256(row.value).hexdigest(),
                    "media_type": row.media_type,
                    "prior_sha256": row.prior_sha256,
                    "approved": row.approved,
                    "rejection_codes": list(row.rejection_codes),
                }
                for row in self.revisions
            ],
        }


class GeneratedRevisionSink:
    """Create-only archive sink invoked at every generation boundary."""

    def __init__(self, recorder: GreenhouseAttemptRecorder) -> None:
        self._recorder = recorder
        self._revisions: list[GeneratedApplicationRevision] = []
        self._marker = object()
        self._authority: SinkBoundGenerationAuthority | None = None
        self._owned_generation_active = False
        self._archive_event_sha256s: list[str] = []

    @property
    def revisions(self) -> tuple[GeneratedApplicationRevision, ...]:
        return tuple(self._revisions)

    @property
    def authority(self) -> SinkBoundGenerationAuthority | None:
        return self._authority

    def archive_revision(
        self,
        *,
        role: str,
        media_type: str,
        value: bytes,
        prior_sha256: str | None,
        approved: bool,
        rejection_codes: tuple[str, ...] = (),
    ) -> GeneratedApplicationRevision:
        """Archive already-observed bytes; this path cannot authorize release."""
        if self._authority is not None or self._owned_generation_active:
            raise ValueError("sealed generation sink cannot emit another revision")
        if not isinstance(value, bytes):
            raise TypeError("generation revision must contain exact bytes")
        revision = GeneratedApplicationRevision(
            role=role,
            value=value,
            media_type=media_type,
            prior_sha256=prior_sha256,
            approved=approved,
            rejection_codes=rejection_codes,
        )
        archived = self._recorder.add_revision(
            role=revision.role,
            value=revision.value,
            media_type=revision.media_type,
            prior_sha256=revision.prior_sha256,
            approved=revision.approved,
            rejection_codes=revision.rejection_codes,
        )
        event_sha256 = getattr(archived, "event_sha256", None)
        if isinstance(event_sha256, str):
            self._archive_event_sha256s.append(event_sha256)
        self._revisions.append(revision)
        return revision

    def generate_candidate_application(
        self,
        *,
        decision_receipt: Mapping[str, object],
        candidate_projection: Mapping[str, object],
        job_key: str,
        vacancy_sha256: str,
        source_url: str,
        role_title: str,
        company_name: str,
        contact: CandidateContact,
        approved_evidence_path: Path | None = None,
    ) -> object:
        """Generate and archive the concrete package without a caller callback.

        The audited production path owns the generator invocation and the exact
        revision inventory.  A session cannot run an undisclosed producer and
        report only whichever outputs it chooses afterwards.
        """
        if self._authority is not None or self._revisions:
            raise ValueError("owned generation requires a pristine archive sink")
        if type(self._recorder) is not GreenhouseAttemptRecorder:
            raise ValueError("owned generation requires the durable attempt recorder")
        repository_head, source_sha256s = self._generator_source_identity()
        arguments: dict[str, object] = {
            "decision_receipt": decision_receipt,
            "candidate_projection": candidate_projection,
            "job_key": job_key,
            "vacancy_sha256": vacancy_sha256,
            "source_url": source_url,
            "role_title": role_title,
            "company_name": company_name,
            "contact": {
                "full_name": contact.full_name,
                "email": contact.email,
                "phone": contact.phone,
                "city": contact.city,
                "record_id": contact.record_id,
                "record_version": contact.record_version,
                "provenance_sha256": contact.provenance_sha256,
            },
        }
        if approved_evidence_path is not None:
            arguments["approved_evidence_path"] = str(approved_evidence_path)
        self._owned_generation_active = True
        try:
            repository = self._recorder.attempt.archive.repository_root
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "career_automation.candidate_generation_worker",
                ],
                cwd=repository,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            process.stdin.write(canonical_json(arguments))
            process.stdin.close()
            package_pickle_sha256: str | None = None
            for line in process.stdout:
                message = json.loads(line)
                if not isinstance(message, dict):
                    process.kill()
                    raise ValueError(
                        "isolated candidate generator emitted malformed output"
                    )
                if message.get("kind") == "revision":
                    try:
                        value = base64.b64decode(
                            str(message["value_base64"]), validate=True
                        )
                    except (KeyError, ValueError) as exc:
                        process.kill()
                        raise ValueError(
                            "isolated candidate generator revision is malformed"
                        ) from exc
                    self._archive_owned_revision(
                        role=message.get("role"),
                        value=value,
                        media_type=message.get("media_type"),
                        prior_sha256=message.get("prior_sha256"),
                        approved=message.get("approved"),
                        rejection_codes=message.get("rejection_codes", ()),
                    )
                elif message.get("kind") == "result" and package_pickle_sha256 is None:
                    package_pickle_sha256 = str(
                        message.get("package_pickle_sha256", "")
                    )
                    if not re.fullmatch(r"[0-9a-f]{64}", package_pickle_sha256):
                        process.kill()
                        raise ValueError(
                            "isolated candidate generator result is malformed"
                        )
                else:
                    process.kill()
                    raise ValueError("isolated candidate generator protocol differs")
            return_code = process.wait()
            stderr = process.stderr.read() if process.stderr is not None else ""
            if return_code != 0:
                raise RuntimeError(
                    "isolated candidate generator failed: "
                    + (
                        stderr.strip().splitlines()[-1]
                        if stderr.strip()
                        else "unknown error"
                    )
                )
            durable = self._verified_durable_revisions()
            package_rows = [
                row for row in durable if row.role == "generation.package_pickle"
            ]
            if (
                len(package_rows) != 1
                or package_pickle_sha256 is None
                or hashlib.sha256(package_rows[0].value).hexdigest()
                != package_pickle_sha256
            ):
                raise ValueError(
                    "isolated candidate generator returned no durable package"
                )
            try:
                package = pickle.loads(  # noqa: S301 - exact-clean worker object
                    package_rows[0].value
                )
            except pickle.UnpicklingError as exc:
                raise ValueError("durable candidate package is malformed") from exc
        finally:
            self._owned_generation_active = False
        if type(package) is not CandidateApplicationPackage:
            raise TypeError("owned candidate generator returned an invalid package")
        required = {
            "generation.inputs",
            "document.source_inputs",
            "document.cv.constraints",
            "document.cv.source",
            "document.cv.final_pdf",
            "document.cover_letter.source",
            "document.cover_letter.final_pdf",
            "form.answers",
            "generation.package_pickle",
        }
        if {row.role for row in self._revisions} != required:
            raise ValueError("owned generator emitted an incomplete revision inventory")
        durable = self._verified_durable_revisions()
        inventory_sha256 = self._inventory_sha256(durable)
        self._authority = SinkBoundGenerationAuthority(
            durable,
            inventory_sha256,
            OWNED_CANDIDATE_GENERATOR,
            repository_head,
            source_sha256s,
            tuple(self._archive_event_sha256s),
            self._marker,
        )
        return package

    def _archive_owned_revision(
        self, **arguments: object
    ) -> GeneratedApplicationRevision:
        if not self._owned_generation_active or self._authority is not None:
            raise ValueError("owned revisions may only be emitted during generation")
        revision = GeneratedApplicationRevision(
            role=str(arguments["role"]),
            value=arguments["value"],  # type: ignore[arg-type]
            media_type=str(arguments["media_type"]),
            prior_sha256=arguments.get("prior_sha256"),  # type: ignore[arg-type]
            approved=bool(arguments.get("approved", True)),
            rejection_codes=tuple(arguments.get("rejection_codes", ())),  # type: ignore[arg-type]
        )
        if not isinstance(revision.value, bytes):
            raise TypeError("generation revision must contain exact bytes")
        archived = self._recorder.add_revision(
            role=revision.role,
            value=revision.value,
            media_type=revision.media_type,
            prior_sha256=revision.prior_sha256,
            approved=revision.approved,
            rejection_codes=revision.rejection_codes,
        )
        event_sha256 = getattr(archived, "event_sha256", None)
        if isinstance(event_sha256, str):
            self._archive_event_sha256s.append(event_sha256)
        self._revisions.append(revision)
        return revision

    def _generator_source_identity(self) -> tuple[str, tuple[tuple[str, str], ...]]:
        repository = self._recorder.attempt.archive.repository_root
        head = exact_clean_head(repository)
        prefix = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--show-prefix"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if prefix and not prefix.endswith("/"):
            raise ValueError("repository prefix is not canonical")
        identities: list[tuple[str, str]] = []
        for relative in _GENERATOR_SOURCE_PATHS:
            committed_path = f"{prefix}{relative}"
            completed = subprocess.run(
                ["git", "-C", str(repository), "show", f"{head}:{committed_path}"],
                check=True,
                capture_output=True,
            )
            committed = completed.stdout
            if committed != (repository / relative).read_bytes():
                raise ValueError(
                    "running candidate generator differs from exact clean HEAD"
                )
            identities.append((relative, hashlib.sha256(committed).hexdigest()))
        return head, tuple(identities)

    def _verified_durable_revisions(self) -> tuple[GeneratedApplicationRevision, ...]:
        if type(self._recorder) is not GreenhouseAttemptRecorder:
            raise ValueError("generation authority requires durable recorder receipts")
        rows = self._recorder.attempt._objects(self._recorder.attempt._events())
        by_event = {row.event_sha256: row for row in rows}
        if len(self._archive_event_sha256s) != len(self._revisions):
            raise ValueError("generation archive receipts are incomplete")
        durable: list[GeneratedApplicationRevision] = []
        for revision, event_sha256 in zip(
            self._revisions, self._archive_event_sha256s, strict=True
        ):
            archived = by_event.get(event_sha256)
            if archived is None:
                raise ValueError("generation archive receipt is absent")
            path = self._recorder.attempt.archive.root / archived.relative_path
            if path.is_symlink() or not path.is_file():
                raise ValueError("generation archive object is unsafe")
            value = path.read_bytes()
            if (
                archived.role != revision.role
                or archived.sha256 != hashlib.sha256(value).hexdigest()
                or value != revision.value
                or archived.media_type != revision.media_type
                or archived.lineage
                != (() if revision.prior_sha256 is None else (revision.prior_sha256,))
                or archived.disposition
                != ("approved" if revision.approved else "rejected")
                or archived.metadata.get("rejection_codes")
                != list(revision.rejection_codes)
            ):
                raise ValueError(
                    "generation archive receipt differs from emitted bytes"
                )
            durable.append(revision)
        return tuple(durable)

    @staticmethod
    def _inventory_sha256(revisions: tuple[GeneratedApplicationRevision, ...]) -> str:
        document = [
            {
                "role": row.role,
                "sha256": hashlib.sha256(row.value).hexdigest(),
                "media_type": row.media_type,
                "prior_sha256": row.prior_sha256,
                "approved": row.approved,
                "rejection_codes": list(row.rejection_codes),
            }
            for row in revisions
        ]
        return hashlib.sha256((canonical_json(document) + "\n").encode()).hexdigest()

    def seal(self) -> SinkBoundGenerationAuthority:
        """Seal the exact in-memory view after all writes have succeeded."""
        if self._authority is None:
            raise ValueError("only completed owned generation can be sealed")
        durable = self._verified_durable_revisions()
        repository_head, source_sha256s = self._generator_source_identity()
        if (
            self._authority._sink_marker is not self._marker
            or self._authority.revisions != durable
            or self._authority.inventory_sha256 != self._inventory_sha256(durable)
            or self._authority.generator_identity != OWNED_CANDIDATE_GENERATOR
            or self._authority.repository_head != repository_head
            or self._authority.generator_source_sha256s != source_sha256s
            or self._authority.archive_event_sha256s
            != tuple(self._archive_event_sha256s)
        ):
            raise ValueError(
                "generation authority differs from durable exact-clean bytes"
            )
        return self._authority


@dataclass(frozen=True)
class PreparedGreenhouseRelease:
    source: ApplicationSource
    artifacts: ApplicationArtifacts
    contact: CandidateContact
    questions: dict[str, tuple[str, str]] | None
    document_assurance_receipts: tuple[
        ExternalDocumentAssuranceReceipt,
        ExternalDocumentAssuranceReceipt,
    ]
    sanity_review_receipt: SanityReviewReceipt
    production_identity: ProductionIdentity
    generation_authority: SinkBoundGenerationAuthority
    attached_roles: tuple[str, ...]
    upload_field_names: tuple[tuple[str, str], ...]
    field_authority_names: tuple[tuple[str, str], ...]
    consent_states: tuple[tuple[str, bool | str], ...]
    success_evidence: GreenhouseSuccessEvidence
    success_observation: bytes
    gate: ReleaseGateStore
    release_token: str
    artifact_root: Path
    upload_paths: dict[str, Path]
    application_url: str
    application_id: str
    receipt_url: str
    jurisdiction: str
    contract_type: str
    consumed_at: datetime
    vacancy_requirements: tuple[str, ...] = ()
    submit_button_name: str = "Submit Application"
    timeout_ms: int = 20_000


PrepareRelease = Callable[
    [QueueItem, GreenhouseAttemptRecorder, Page, GeneratedRevisionSink],
    PreparedGreenhouseRelease,
]
OpenVacancy = Callable[[QueueItem, Page], Mapping[str, object] | None]


class ProductionRunnerSession(Protocol):
    page: Page
    candidates: Sequence[ProductionRunCandidate]
    open_vacancy: OpenVacancy
    prepare_release: PrepareRelease
    gmail_confirmation_checker: GmailConfirmationChecker | None

    def close(self) -> None: ...


class GreenhouseProductionRunner:
    """Advance the durable ascending queue one terminal attempt at a time."""

    def __init__(
        self,
        *,
        repository_root: str | Path,
        archive_root: str | Path,
        gmail_confirmation_checker: GmailConfirmationChecker | None = None,
        retry_repairable_preclick_blocks: bool = False,
    ) -> None:
        if type(retry_repairable_preclick_blocks) is not bool:
            raise TypeError("repairable-block retry policy must be boolean")
        self.repository_root = Path(repository_root).resolve(strict=True)
        self.archive = ApplicationArchive(
            archive_root,
            repository_root=self.repository_root,
        )
        self.executor = CertifiedGreenhouseSubmitExecutor(
            repository_root=self.repository_root,
            gmail_confirmation_checker=gmail_confirmation_checker,
        )
        self.retry_repairable_preclick_blocks = retry_repairable_preclick_blocks

    def _queue(self, candidates: Iterable[ProductionRunCandidate]):
        return build_ascending_queue(
            (candidate.vacancy for candidate in candidates),
            prior_attempts=prior_attempts_from_archive(self.archive),
            retry_repairable_preclick_blocks=self.retry_repairable_preclick_blocks,
        )

    @staticmethod
    def _validate_generation_inventory(
        prepared: PreparedGreenhouseRelease,
        sink: GeneratedRevisionSink,
    ) -> None:
        authority = prepared.generation_authority
        durable = sink._verified_durable_revisions()
        repository_head, source_sha256s = sink._generator_source_identity()
        if (
            authority is not sink.authority
            or authority._sink_marker is not sink._marker
        ):
            raise ValueError(
                "generation authority was not sealed by the active archive sink"
            )
        if authority.revisions != sink.revisions or authority.revisions != durable:
            raise ValueError(
                "sealed generation inventory differs from the archive sink"
            )
        if (
            authority.generator_identity != OWNED_CANDIDATE_GENERATOR
            or authority.repository_head != repository_head
            or authority.generator_source_sha256s != source_sha256s
            or authority.inventory_sha256 != sink._inventory_sha256(durable)
        ):
            raise ValueError(
                "generation authority does not identify the owned candidate generator"
            )
        expected = {
            "document.source_inputs": (
                canonical_json(prepared.source.document()) + "\n"
            ).encode(),
            "document.cv.source": prepared.artifacts.editable.cv_text.encode(),
            "document.cv.final_pdf": prepared.artifacts.cv_pdf.pdf_bytes,
            "document.cover_letter.source": (
                prepared.artifacts.editable.cover_letter_text.encode()
            ),
            "document.cover_letter.final_pdf": (
                prepared.artifacts.cover_letter_pdf.pdf_bytes
            ),
            "form.answers": prepared.artifacts.editable.answers_text.encode(),
        }
        approved = {
            (row.role, hashlib.sha256(row.value).hexdigest())
            for row in authority.revisions
            if row.approved
        }
        missing = sorted(
            role
            for role, value in expected.items()
            if (role, hashlib.sha256(value).hexdigest()) not in approved
        )
        if missing:
            raise ValueError(
                "final generated artifacts are absent from revision inventory: "
                + ", ".join(missing)
            )
        for row in authority.revisions:
            if row.approved and row.rejection_codes:
                raise ValueError("approved generated revision has rejection codes")
            if not row.approved and not row.rejection_codes:
                raise ValueError("rejected generated revision lacks rejection codes")

    def execute_next(
        self,
        page: Page,
        *,
        candidates: Sequence[ProductionRunCandidate],
        open_vacancy: OpenVacancy,
        prepare_release: PrepareRelease,
    ) -> ProductionSubmissionReceipt | None:
        queue = self._queue(candidates)
        item = queue.next_action
        if item is None:
            return None
        by_identity = {
            (
                candidate.vacancy.vacancy.job_key,
                candidate.vacancy.vacancy.vacancy_sha256,
            ): candidate
            for candidate in candidates
        }
        candidate = by_identity[
            (
                item.vacancy.vacancy.job_key,
                item.vacancy.vacancy.vacancy_sha256,
            )
        ]
        navigation = open_vacancy(item, page)
        recorder = (
            GreenhouseAttemptRecorder.resume(
                archive_root=self.archive.root,
                repository_root=self.repository_root,
                attempt_id=str(item.attempt_id),
            )
            if item.action == "resume_attempt"
            else GreenhouseAttemptRecorder.create(
                archive_root=self.archive.root,
                repository_root=self.repository_root,
                vacancy=candidate.vacancy.vacancy,
                complete_vacancy=candidate.complete_vacancy,
                structured_vacancy=candidate.structured_vacancy,
                assessment={**candidate.assessment, "queue_rank": item.queue_rank},
            )
        )
        boundary_signals = self.executor.boundary_signals(page)
        if boundary_signals:
            observed_network = list(candidate.network_evidence)
            if navigation is not None:
                observed_network.append(dict(navigation))
            recorder.finalize_provider_boundary(
                page,
                signals=boundary_signals,
                network_evidence=tuple(observed_network),
            )
            return None
        roles = {
            row.role for row in recorder.attempt._objects(recorder.attempt._events())
        }
        if "browser.prefill_snapshot" not in roles:
            recorder.record_prefill(page)
        try:
            revision_sink = GeneratedRevisionSink(recorder)
            prepared = prepare_release(item, recorder, page, revision_sink)
        except Exception as exc:
            recorder.finalize_preintent_failure(
                page,
                reason_code="release_preparation_failed",
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            raise
        try:
            self._validate_generation_inventory(prepared, revision_sink)
        except Exception as exc:
            recorder.finalize_preintent_failure(
                page,
                reason_code="generation_inventory_rejected",
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            raise
        archive_receipt = recorder.finalize_release(
            page,
            source=prepared.source,
            artifacts=prepared.artifacts,
            document_assurance_receipts=prepared.document_assurance_receipts,
            sanity_review_receipt=prepared.sanity_review_receipt,
            production_identity=prepared.production_identity,
            attached_roles=prepared.attached_roles,
            upload_field_names=prepared.upload_field_names,
            field_authority_names=prepared.field_authority_names,
            consent_states=prepared.consent_states,
            success_evidence=prepared.success_evidence,
            success_observation=prepared.success_observation,
        )
        authority = CandidateReleaseExecutionAuthority(
            gate=prepared.gate,
            release_token=prepared.release_token,
            source=prepared.source,
            artifacts=prepared.artifacts,
            contact=prepared.contact,
            questions=prepared.questions,
            document_assurance_receipts=prepared.document_assurance_receipts,
            sanity_review_receipt=prepared.sanity_review_receipt,
            archive_receipt=archive_receipt,
            archive_root=self.archive.root,
            artifact_root=prepared.artifact_root,
            repository_root=self.repository_root,
            ats_provider="greenhouse",
            application_url=prepared.application_url,
            attached_roles=prepared.attached_roles,
            upload_field_names=prepared.upload_field_names,
            field_authority_names=prepared.field_authority_names,
            consent_states=prepared.consent_states,
            success_evidence=prepared.success_evidence,
            jurisdiction=prepared.jurisdiction,
            contract_type=prepared.contract_type,
            consumed_at=prepared.consumed_at,
            receipt_url=prepared.receipt_url,
            application_id=prepared.application_id,
            job_key=prepared.source.job_key,
            vacancy_requirements=prepared.vacancy_requirements,
        )
        return self.executor.execute(
            page,
            authority=authority,
            plan=GreenhouseSubmissionPlan(
                upload_input_names=prepared.upload_paths,
                consent_states=dict(prepared.consent_states),
                submit_button_name=prepared.submit_button_name,
                timeout_ms=prepared.timeout_ms,
            ),
        )

    def execute_all(
        self,
        page: Page,
        *,
        candidates: Sequence[ProductionRunCandidate],
        open_vacancy: OpenVacancy,
        prepare_release: PrepareRelease,
        max_terminal_attempts: int | None = None,
    ) -> tuple[ProductionSubmissionReceipt, ...]:
        if max_terminal_attempts is not None and max_terminal_attempts < 1:
            raise ValueError("max_terminal_attempts must be at least one")
        receipts: list[ProductionSubmissionReceipt] = []
        terminal_attempts = 0
        while self._queue(candidates).next_action is not None:
            if (
                max_terminal_attempts is not None
                and terminal_attempts >= max_terminal_attempts
            ):
                break
            active = self._queue(candidates).next_action
            if active is None:
                break
            try:
                receipt = self.execute_next(
                    page,
                    candidates=candidates,
                    open_vacancy=open_vacancy,
                    prepare_release=prepare_release,
                )
            except ProductionATSBoundaryError:
                queue = self._queue(candidates)
                if (
                    queue.next_action is not None
                    and queue.next_action.vacancy.vacancy.job_key
                    == active.vacancy.vacancy.job_key
                ):
                    raise
                terminal_attempts += 1
                continue
            terminal_attempts += 1
            if receipt is not None:
                receipts.append(receipt)
        return tuple(receipts)


def _load_factory(reference: str):
    if reference != PRODUCTION_FACTORY_REFERENCE:
        raise ValueError("runner factory must be the repository production factory")
    module_name, function_name = reference.split(":", 1)
    factory = getattr(importlib.import_module(module_name), function_name)
    if not callable(factory):
        raise TypeError("runner factory is not callable")
    return factory


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--factory", default=PRODUCTION_FACTORY_REFERENCE)
    parser.add_argument(
        "--execute-live",
        action="store_true",
        help="required acknowledgement for consequential production execution",
    )
    parser.add_argument(
        "--max-terminal-attempts",
        type=int,
        default=None,
        help="stop after this many terminal queue outcomes",
    )
    parser.add_argument(
        "--retry-repairable-preclick-blocks",
        action="store_true",
        help=(
            "retry only archived human-verification blocks that contain no click intent"
        ),
    )
    arguments = parser.parse_args(argv)
    if not arguments.execute_live:
        parser.error("--execute-live is required")
    session: ProductionRunnerSession = _load_factory(arguments.factory)(arguments)
    try:
        GreenhouseProductionRunner(
            repository_root=arguments.repository_root,
            archive_root=arguments.archive_root,
            gmail_confirmation_checker=session.gmail_confirmation_checker,
            retry_repairable_preclick_blocks=(
                arguments.retry_repairable_preclick_blocks
            ),
        ).execute_all(
            session.page,
            candidates=session.candidates,
            open_vacancy=session.open_vacancy,
            prepare_release=session.prepare_release,
            max_terminal_attempts=arguments.max_terminal_attempts,
        )
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "GreenhouseProductionRunner",
    "GeneratedApplicationRevision",
    "GeneratedRevisionSink",
    "PreparedGreenhouseRelease",
    "ProductionRunCandidate",
    "ProductionRunnerSession",
    "SinkBoundGenerationAuthority",
    "main",
]
