"""Crash-resumable archive preparation for a real Greenhouse attempt."""

from __future__ import annotations

import importlib.metadata
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from playwright.sync_api import Page

from .application_archive import (
    ApplicationArchive,
    ApplicationArchiveReceipt,
    ArchivedObject,
    AttemptArchive,
    VacancyArchiveIdentity,
    release_upload_mapping_bytes,
)
from .application_compiler import (
    ApplicationSource,
    FactAuthority,
    ProfileFactAuthority,
    VacancyFactAuthority,
)
from .application_sanity_review import SanityReviewReceipt
from .application_quality import ApplicationQualityInput
from .application_quality_contracts import ApplicationPreflightQualityReview
from .ats_application_authority import AtsApplicationAuthority
from .browser_executor import (
    GreenhouseSuccessEvidence,
    validate_greenhouse_success_observation,
)
from .evidence_matching import canonical_json
from .external_document_assurance import ExternalDocumentAssuranceReceipt
from .production_ats_executor import (
    canonical_non_secret_form_state,
    collect_greenhouse_form_inventory,
)
from .production_queue import ProductionCheckpointLedger
from form_filling.service import approved_form_mapping_bytes
from form_filling.ats_forensics import redact_text, sanitize_url
from .provider_observation_authority import verify_provider_observation_authority
from .rendering import ApplicationArtifacts


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _utc_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _approved_fact_authorities(source: ApplicationSource) -> list[dict[str, object]]:
    """Serialize every fact authority without assuming it is candidate-owned."""

    authority_kinds = {
        FactAuthority: "strategy",
        ProfileFactAuthority: "candidate_profile",
        VacancyFactAuthority: "vacancy",
    }
    rows: list[dict[str, object]] = []
    for fact in source.facts:
        authority_kind = authority_kinds.get(type(fact.authority))
        if authority_kind is None:
            raise ValueError("application fact has an unsupported authority kind")
        rows.append(
            {
                "sentence_id": fact.sentence_id,
                "fact_kind": fact.fact_kind,
                "document_kind": fact.document_kind,
                "authority_kind": authority_kind,
                "authority": vars(fact.authority),
            }
        )
    return rows


@dataclass(frozen=True)
class ProductionIdentity:
    code_revision: str
    policy_identity: str
    configuration_identity: str
    adapter_identity: str = "greenhouse.production:v1"

    def __post_init__(self) -> None:
        for value in (
            self.code_revision,
            self.policy_identity,
            self.configuration_identity,
            self.adapter_identity,
        ):
            if not value or value != value.strip():
                raise ValueError("production identity values are required")

    def document(self) -> dict[str, str]:
        return {
            "code_revision": self.code_revision,
            "policy_identity": self.policy_identity,
            "configuration_identity": self.configuration_identity,
            "adapter_identity": self.adapter_identity,
        }


class GreenhouseAttemptRecorder:
    """Record an attempt before fill, then finalize it from the live form."""

    def __init__(self, attempt: AttemptArchive) -> None:
        self.attempt = attempt
        self._attached_pages: set[int] = set()

    @classmethod
    def create(
        cls,
        *,
        archive_root: str | Path | None,
        repository_root: str | Path,
        vacancy: VacancyArchiveIdentity,
        complete_vacancy: bytes,
        structured_vacancy: Mapping[str, object],
        assessment: Mapping[str, object],
    ) -> "GreenhouseAttemptRecorder":
        archive = ApplicationArchive(
            archive_root,
            repository_root=repository_root,
        )
        attempt = archive.create_attempt(vacancy)
        ProductionCheckpointLedger(archive).record_attempt_started(
            attempt.attempt_id
        )
        recorder = cls(attempt)
        recorder._add(
            "vacancy.source_identity",
            _json_bytes(vacancy.document()),
            "application/json",
        )
        recorder._add(
            "vacancy.capture",
            complete_vacancy,
            "text/html",
            metadata={"capture": "complete_raw_response"},
        )
        recorder._add(
            "vacancy.structured",
            _json_bytes(structured_vacancy),
            "application/json",
        )
        recorder._add(
            "vacancy.assessment",
            _json_bytes(assessment),
            "application/json",
        )
        return recorder

    @classmethod
    def resume(
        cls,
        *,
        archive_root: str | Path | None,
        repository_root: str | Path,
        attempt_id: str,
    ) -> "GreenhouseAttemptRecorder":
        archive = ApplicationArchive(
            archive_root,
            repository_root=repository_root,
            create=False,
        )
        return cls(archive.open_attempt(attempt_id))

    def _add(
        self,
        role: str,
        value: bytes,
        media_type: str,
        *,
        lineage: Sequence[str] = (),
        disposition: str = "approved",
        metadata: Mapping[str, object] | None = None,
    ) -> ArchivedObject:
        return self.attempt.add_artifact(
            role,
            value,
            media_type=media_type,
            lineage=lineage,
            disposition=disposition,
            metadata=metadata,
        )

    def _record_evidence(
        self,
        event_kind: str,
        *,
        result: str,
        members: Mapping[str, str] | None = None,
        details: Mapping[str, object] | None = None,
        private_value: bytes | None = None,
        private_media_type: str = "application/octet-stream",
    ) -> str:
        return self.attempt.record_evidence_event(
            event_id=self.attempt.next_evidence_event_id(event_kind),
            event_kind=event_kind,
            occurred_at=_utc_z(),
            result=result,
            member_sha256s=members,
            details=details,
            private_value=private_value,
            private_media_type=private_media_type,
        )

    @staticmethod
    def _url_sha256(value: str) -> str:
        return hashlib.sha256(sanitize_url(value).encode("utf-8")).hexdigest()

    def attach_page_evidence(self, page: Page) -> None:
        """Attach append-only sanitized browser evidence to this attempt once."""
        page_identity = id(page)
        if page_identity in self._attached_pages:
            return
        self._attached_pages.add(page_identity)

        def on_request(request) -> None:
            self._record_evidence(
                "request",
                result="observed",
                details={
                    "method": str(request.method).upper(),
                    "resource_type": str(request.resource_type),
                    "url_sha256": self._url_sha256(str(request.url)),
                },
            )

        def on_response(response) -> None:
            self._record_evidence(
                "response",
                result="observed",
                details={
                    "method": str(response.request.method).upper(),
                    "status": int(response.status),
                    "url_sha256": self._url_sha256(str(response.url)),
                },
            )

        def on_request_failed(request) -> None:
            self._record_evidence(
                "request_failed",
                result="failed",
                details={
                    "method": str(request.method).upper(),
                    "resource_type": str(request.resource_type),
                    "url_sha256": self._url_sha256(str(request.url)),
                    "error_code": "request_failed",
                },
            )

        def on_console(message) -> None:
            if str(message.type).casefold() not in {"error", "warning"}:
                return
            self._record_evidence(
                "console_error",
                result="observed",
                details={"provenance": "browser.console"},
                private_value=redact_text(str(message.text)).encode("utf-8"),
                private_media_type="text/plain",
            )

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfailed", on_request_failed)
        page.on("console", on_console)
        page.on(
            "pageerror",
            lambda error: self._record_evidence(
                "console_error",
                result="failed",
                details={"provenance": "browser.pageerror"},
                private_value=redact_text(str(error)).encode("utf-8"),
                private_media_type="text/plain",
            ),
        )

    def record_navigation(self, evidence: Mapping[str, object] | None) -> str:
        row = dict(evidence or {})
        details: dict[str, object] = {
            "method": str(row.get("method", "GET")).upper(),
            "url_sha256": self._url_sha256(
                str(row.get("url") or self.attempt.vacancy.source_url)
            ),
        }
        if isinstance(row.get("status"), int):
            details["status"] = int(row["status"])
        return self._record_evidence(
            "navigation", result="completed", details=details
        )

    def record_field_action(
        self,
        *,
        event_kind: str,
        field_id: str,
        field_type: str,
        required: bool,
        options: Sequence[str],
        provenance: str,
        readback: bytes | None,
        result: str = "completed",
        document_role: str | None = None,
        source_path: Path | None = None,
        content_sha256: str | None = None,
        file_name: str | None = None,
        file_size: int | None = None,
        mime_type: str | None = None,
        checked: bool | None = None,
        selected: bool | None = None,
    ) -> str:
        details: dict[str, object] = {
            "field_id": field_id,
            "field_type": field_type,
            "required": required,
            "options": list(options),
            "provenance": provenance,
        }
        members: dict[str, str] = {}
        if readback is not None:
            details.update(
                {
                    "value_sha256": hashlib.sha256(readback).hexdigest(),
                    "value_byte_length": len(readback),
                    "readback_sha256": hashlib.sha256(readback).hexdigest(),
                    "readback_byte_length": len(readback),
                }
            )
        if document_role is not None:
            details["document_role"] = document_role
            archive_role = f"document.{document_role}.final_pdf"
            rows = [
                row
                for row in self.attempt._objects(self.attempt._events())
                if row.role == archive_role
            ]
            if len(rows) != 1:
                raise ValueError("uploaded document lacks one archived source object")
            if content_sha256 is None or rows[0].sha256 != content_sha256:
                raise ValueError("uploaded document differs from archived source bytes")
            members[archive_role] = rows[0].sha256
            details["content_sha256"] = content_sha256
        if source_path is not None:
            details["source_path_sha256"] = hashlib.sha256(
                str(source_path).encode("utf-8")
            ).hexdigest()
        if file_name is not None:
            details["file_name_sha256"] = hashlib.sha256(
                file_name.encode("utf-8")
            ).hexdigest()
        if file_size is not None:
            details["file_size"] = file_size
        if mime_type is not None:
            details["mime_type"] = mime_type
        if checked is not None:
            details["checked"] = checked
        if selected is not None:
            details["selected"] = selected
        return self._record_evidence(
            event_kind,
            result=result,
            members=members,
            details=details,
            private_value=readback,
            private_media_type=(
                "application/json" if event_kind == "file_uploaded" else "text/plain"
            ),
        )

    def add_revision(
        self,
        *,
        role: str,
        value: bytes,
        media_type: str,
        prior_sha256: str | None,
        approved: bool,
        rejection_codes: Sequence[str] = (),
    ) -> ArchivedObject:
        if approved and rejection_codes:
            raise ValueError("approved revision cannot carry rejection codes")
        if not approved and not rejection_codes:
            raise ValueError("rejected revision requires stable rejection codes")
        return self._add(
            role,
            value,
            media_type,
            lineage=(() if prior_sha256 is None else (prior_sha256,)),
            disposition="approved" if approved else "rejected",
            metadata={"rejection_codes": list(rejection_codes)},
        )

    def record_prefill(self, page: Page) -> ArchivedObject:
        state = canonical_non_secret_form_state(page)
        inventory = collect_greenhouse_form_inventory(page)
        prefill = self._add(
            "browser.prefill_snapshot",
            state,
            "application/json",
            metadata={"provider": "greenhouse", "phase": "before_fill"},
        )
        questions = self._add(
            "form.questions",
            inventory,
            "application/json",
            metadata={"includes_select_options": True, "values_are_prefill": True},
        )
        screenshot = self._add(
            "browser.prefill_screenshot",
            page.screenshot(full_page=True),
            "image/png",
            disposition="observed",
            metadata={"provider": "greenhouse", "phase": "before_fill"},
        )
        self._record_evidence(
            "preflight",
            result="completed",
            members={
                prefill.role: prefill.sha256,
                questions.role: questions.sha256,
                screenshot.role: screenshot.sha256,
            },
            details={
                "provenance": "greenhouse.form_inventory",
                "interaction_counts": {
                    "fields_filled": 0,
                    "files_uploaded": 0,
                    "submit_clicks": 0,
                },
            },
        )
        return prefill

    def record_postfill(self, page: Page) -> tuple[ArchivedObject, ArchivedObject]:
        state = self._add(
            "browser.post_fill_state",
            canonical_non_secret_form_state(page),
            "application/json",
            disposition="observed",
            metadata={"provider": "greenhouse", "phase": "after_fill"},
        )
        screenshot = self._add(
            "browser.post_fill_screenshot",
            page.screenshot(full_page=True),
            "image/png",
            disposition="observed",
            metadata={"provider": "greenhouse", "phase": "after_fill"},
        )
        self._record_evidence(
            "screenshot",
            result="completed",
            members={state.role: state.sha256, screenshot.role: screenshot.sha256},
            details={"provenance": "greenhouse.post_fill"},
        )
        return state, screenshot

    def finalize_preintent_failure(
        self,
        page: Page,
        *,
        reason_code: str,
        error_type: str,
        error_message: str,
    ) -> str:
        """Archive a repairable failure without implying a click may have occurred."""
        if not reason_code or reason_code != reason_code.strip():
            raise ValueError("pre-intent failure reason is required")
        selected = self._selected()
        failure = {
            "state": "abandoned",
            "phase": "before_click_intent",
            "reason_code": reason_code,
            "error_type": error_type,
            "error_message": error_message,
            "click_intent_recorded": False,
            "click_may_have_occurred": False,
            "submit_clicks": 0,
        }
        result = self._add(
            "submission.result",
            _json_bytes(failure),
            "application/json",
            disposition="rejected",
        )
        selected["submission.result"] = result.sha256
        try:
            state = self._add(
                "browser.failed_state_evidence",
                canonical_non_secret_form_state(page),
                "application/json",
                disposition="observed",
                metadata={"phase": "before_click_intent"},
            )
            selected[state.role] = state.sha256
        except Exception:
            pass
        try:
            visible = self._add(
                "browser.failed_visible_text",
                page.locator("body").inner_text().encode("utf-8"),
                "text/plain",
                disposition="observed",
                metadata={"phase": "before_click_intent"},
            )
            selected[visible.role] = visible.sha256
        except Exception:
            pass
        try:
            screenshot = self._add(
                "browser.failed_screenshot",
                page.screenshot(full_page=True),
                "image/png",
                disposition="observed",
                metadata={"phase": "before_click_intent"},
            )
            selected[screenshot.role] = screenshot.sha256
        except Exception:
            pass
        terminal_sha256 = self.attempt.finalize_terminal(
            outcome="abandoned",
            selected=selected,
        )
        ProductionCheckpointLedger(self.attempt.archive).record_attempt_terminal(
            self.attempt.attempt_id
        )
        return terminal_sha256

    def finalize_provider_boundary(
        self,
        page: Page,
        *,
        signals: Sequence[str],
        network_evidence: Sequence[Mapping[str, object]] = (),
    ) -> str:
        """Terminalize a provider boundary before generation or form fill."""
        if not signals or any(not value.strip() for value in signals):
            raise ValueError("provider boundary requires observed signals")
        selected = self._selected()
        boundary_document = {
            "classification": "human_verification_boundary",
            "description": "Provider human-verification control observed before form fill.",
            "signals": sorted(set(signals)),
            "phase": "before_generation_or_fill",
            "future_queue": "technical_boundary",
            "secret_value": None,
        }
        payloads = (
            (
                "technical.boundary",
                _json_bytes(boundary_document),
                "application/json",
            ),
            (
                "submission.result",
                _json_bytes(
                    {
                        "state": "blocked",
                        "provider": "greenhouse",
                        "reason": "human_verification_boundary",
                        "signals": sorted(set(signals)),
                        "fields_filled": 0,
                        "files_uploaded": 0,
                        "submit_clicks": 0,
                        "click_intent_recorded": False,
                    }
                ),
                "application/json",
            ),
            (
                "browser.blocked_screenshot",
                page.screenshot(full_page=True),
                "image/png",
            ),
            (
                "browser.blocked_visible_text",
                page.locator("body").inner_text().encode("utf-8"),
                "text/plain",
            ),
            (
                "browser.blocked_state_evidence",
                canonical_non_secret_form_state(page),
                "application/json",
            ),
            (
                "browser.redirect_http_evidence",
                _json_bytes(
                    {
                        "schema_version": "jaa.browser-http-evidence.v1",
                        "events": list(network_evidence),
                        "availability": (
                            "observed"
                            if network_evidence
                            else "listener_not_started_before_boundary"
                        ),
                    }
                ),
                "application/json",
            ),
        )
        for role, value, media_type in payloads:
            row = self._add(
                role,
                value,
                media_type,
                disposition="observed",
                metadata={"phase": "before_generation_or_fill"},
            )
            selected[role] = row.sha256
        terminal_sha256 = self.attempt.finalize_terminal(
            outcome="blocked",
            selected=selected,
        )
        ProductionCheckpointLedger(self.attempt.archive).record_attempt_terminal(
            self.attempt.attempt_id
        )
        return terminal_sha256

    def _selected(self) -> dict[str, str]:
        rows = self.attempt._objects(self.attempt._events())
        selected: dict[str, str] = {}
        for row in rows:
            if row.disposition == "approved":
                selected[row.role] = row.sha256
        return selected

    def finalize_release(
        self,
        page: Page,
        *,
        source: ApplicationSource,
        artifacts: ApplicationArtifacts,
        document_assurance_receipts: tuple[
            ExternalDocumentAssuranceReceipt,
            ExternalDocumentAssuranceReceipt,
        ],
        sanity_review_receipt: SanityReviewReceipt,
        ats_application_authority: AtsApplicationAuthority | None = None,
        quality_input: ApplicationQualityInput | None = None,
        quality_review: ApplicationPreflightQualityReview | None = None,
        production_identity: ProductionIdentity,
        attached_roles: Sequence[str] = ("cv", "cover_letter"),
        upload_field_names: Sequence[tuple[str, str]] = (
            ("cv", "resume"),
            ("cover_letter", "cover_letter"),
        ),
        field_authority_names: Sequence[tuple[str, str]],
        consent_states: Sequence[tuple[str, bool | str]],
        success_evidence: GreenhouseSuccessEvidence,
        success_observation: bytes,
        finalized_at: datetime | None = None,
    ) -> ApplicationArchiveReceipt:
        release_time = finalized_at or datetime.now(timezone.utc)
        validate_greenhouse_success_observation(
            success_observation,
            success_evidence,
            application_url=self.attempt.vacancy.source_url,
            application_id=self.attempt.vacancy.source_url.rstrip("/").rsplit("/", 1)[-1],
            verified_at=release_time,
        )
        provider_authority = verify_provider_observation_authority(
            success_observation,
            source_url=self.attempt.vacancy.source_url,
            archive_root=self.attempt.archive.root,
            repository_root=self.attempt.archive.repository_root,
        )
        selected = self._selected()
        if "browser.prefill_snapshot" not in selected:
            raise ValueError("prefill snapshot must be archived before release")
        claims = _approved_fact_authorities(source)
        pypdf_version = importlib.metadata.version("pypdf")
        quality_values = (
            ats_application_authority,
            quality_input,
            quality_review,
        )
        if any(value is not None for value in quality_values) and not all(
            value is not None for value in quality_values
        ):
            raise ValueError("release quality authority must be complete or absent")
        quality_payloads: tuple[
            tuple[str, bytes, str, Mapping[str, object]], ...
        ] = ()
        if (
            ats_application_authority is not None
            and quality_input is not None
            and quality_review is not None
        ):
            quality_payloads = (
                (
                    "assurance.ats_application_authority",
                    _json_bytes(ats_application_authority.document()),
                    "application/json",
                    {
                        "authority_sha256": ats_application_authority.authority_sha256,
                    },
                ),
                (
                    "assurance.ats_inventory",
                    ats_application_authority.inventory_bytes,
                    "application/json",
                    {},
                ),
                (
                    "assurance.ats_answers",
                    ats_application_authority.answer_bytes,
                    "application/json",
                    {},
                ),
                (
                    "assurance.application_quality",
                    _json_bytes(quality_review.to_dict()),
                    "application/json",
                    {
                        "reviewer_receipt_sha256": quality_review.reviewer_receipt_sha256,
                    },
                ),
                *(
                    (
                        f"assurance.editorial.{receipt.skill_name.replace('-', '_')}",
                        _json_bytes(receipt.to_dict()),
                        "application/json",
                        {"receipt_sha256": receipt.receipt_sha256},
                    )
                    for receipt in quality_input.editorial_skill_reviews
                ),
            )
        payloads: tuple[
            tuple[str, bytes, str, Mapping[str, object]], ...
        ] = (
            (
                "document.source_inputs",
                _json_bytes(source.document()),
                "application/json",
                {"reproduction_input": True},
            ),
            (
                "document.cv.source",
                artifacts.editable.cv_text.encode(),
                "text/plain",
                {"source_id": source.source_id},
            ),
            (
                "document.cv.final_pdf",
                artifacts.cv_pdf.pdf_bytes,
                "application/pdf",
                {"page_count": artifacts.cv_pdf.page_count},
            ),
            (
                "document.cv.extracted_text",
                artifacts.cv_pdf.extracted_text.encode(),
                "text/plain",
                {"extraction_tool": "pypdf", "extraction_version": pypdf_version},
            ),
            (
                "document.cover_letter.source",
                artifacts.editable.cover_letter_text.encode(),
                "text/plain",
                {"source_id": source.source_id},
            ),
            (
                "document.cover_letter.final_pdf",
                artifacts.cover_letter_pdf.pdf_bytes,
                "application/pdf",
                {"page_count": artifacts.cover_letter_pdf.page_count},
            ),
            (
                "document.cover_letter.extracted_text",
                artifacts.cover_letter_pdf.extracted_text.encode(),
                "text/plain",
                {"extraction_tool": "pypdf", "extraction_version": pypdf_version},
            ),
            (
                "form.answers",
                artifacts.editable.answers_text.encode(),
                "text/plain",
                {"application_source_id": source.source_id},
            ),
            (
                "form.approved_field_mapping",
                approved_form_mapping_bytes(
                    source=source,
                    artifacts=artifacts,
                    field_authority_names=field_authority_names,
                    consent_states=consent_states,
                ),
                "application/json",
                {"provider": "greenhouse"},
            ),
            (
                "evidence.approved_claim_ids",
                _json_bytes(claims),
                "application/json",
                {},
            ),
            (
                "assurance.cv.receipt",
                _json_bytes(document_assurance_receipts[0].document()),
                "application/json",
                {},
            ),
            (
                "assurance.cover_letter.receipt",
                _json_bytes(document_assurance_receipts[1].document()),
                "application/json",
                {},
            ),
            (
                "assurance.semantic.receipt",
                _json_bytes(sanity_review_receipt.document()),
                "application/json",
                {
                    "backend": sanity_review_receipt.backend_identity,
                    "model": sanity_review_receipt.model_identity,
                },
            ),
            *quality_payloads,
            (
                "browser.pre_submit_state",
                canonical_non_secret_form_state(page),
                "application/json",
                {"provider": "greenhouse", "phase": "immediately_pre_submit"},
            ),
            (
                "browser.pre_submit_screenshot",
                page.screenshot(full_page=True),
                "image/png",
                {"provider": "greenhouse", "phase": "immediately_pre_submit"},
            ),
            (
                "browser.upload_mapping",
                release_upload_mapping_bytes(
                    artifacts.cv_pdf.pdf_sha256,
                    artifacts.cover_letter_pdf.pdf_sha256,
                    attached_roles=attached_roles,
                    upload_field_names=upload_field_names,
                ),
                "application/json",
                {},
            ),
            (
                "provider.success_semantics",
                _json_bytes(success_evidence.document()),
                "application/json",
                {
                    "provider": "greenhouse",
                    "observation_sha256": success_evidence.observation_sha256,
                },
            ),
            (
                "provider.success_observation",
                success_observation,
                "application/json",
                {"provider": "greenhouse", "phase": "non_consequential_canary"},
            ),
            (
                "provider.success_authority",
                _json_bytes(provider_authority.document()),
                "application/json",
                {
                    "provider": "greenhouse",
                    "collector_identity": provider_authority.collector_identity,
                    "capture_manifest_sha256": (
                        provider_authority.capture_manifest_sha256
                    ),
                },
            ),
            (
                "production.identities",
                _json_bytes(
                    {
                        **production_identity.document(),
                        "application_source_id": source.source_id,
                        "document_assurance_policy": document_assurance_receipts[0].policy_sha256,
                        "semantic_policy": sanity_review_receipt.policy_sha256,
                        "semantic_prompt": sanity_review_receipt.prompt_sha256,
                        "semantic_schema": sanity_review_receipt.schema_sha256,
                    }
                ),
                "application/json",
                {},
            ),
        )
        for role, value, media_type, metadata in payloads:
            row = self._add(role, value, media_type, metadata=metadata)
            selected[role] = row.sha256
        self._record_evidence(
            "release",
            result="completed",
            members=selected,
            details={
                "provenance": "greenhouse.release",
                "interaction_counts": {
                    "fields_filled": len(tuple(field_authority_names)),
                    "files_uploaded": len(tuple(attached_roles)),
                    "submit_clicks": 0,
                },
            },
        )
        return self.attempt.finalize_release(
            selected=selected,
            finalized_at=release_time.isoformat(),
        )


__all__ = ["GreenhouseAttemptRecorder", "ProductionIdentity"]
