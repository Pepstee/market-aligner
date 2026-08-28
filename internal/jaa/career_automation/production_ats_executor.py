"""Certified, fail-closed production submit executor for Greenhouse.

The adapter deliberately owns only the last boundary.  Form preparation may
use deterministic tooling or remain manual, but the final click can occur only
here after the exact-PDF, semantic and release-archive authorities are rebound.
Unsupported providers and any human-verification signal are parked without a
click.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit

from playwright.sync_api import (
    Locator,
    Page,
    TimeoutError as PlaywrightTimeoutError,
)

from .application_archive import (
    ApplicationArchive,
    ApplicationArchiveError,
    selected_archive_hashes,
    selected_archive_object_bytes,
)
from .application_sanity_review import verify_sanity_review_receipt
from .browser_executor import (
    FinalClickRevalidationError,
    GreenhouseSuccessEvidence,
    ReleaseExecutionAuthority,
    certified_final_submit_click,
)
from .browser_workflows import ReleaseGateError
from .candidate_release_gate import CandidateAuthorityReleaseGate
from .evidence_matching import canonical_json
from .external_document_assurance import IntendedVacancy, verify_receipt_for_pdf
from form_filling.service import approved_form_mapping_bytes
from .production_queue import ProductionCheckpointLedger


GREENHOUSE_HOSTS = frozenset(
    {"job-boards.greenhouse.io", "job-boards.eu.greenhouse.io"}
)
BOUNDARY_MARKERS = (
    "hcaptcha",
    "turnstile",
    "challenges.cloudflare.com",
    "human verification",
    "verify you are human",
    "complete the captcha",
    "i'm not a robot",
    "multi-factor",
    "two-factor",
)
_PHONE_WIDGET_SEARCH = re.compile(r"iti-\d+__search-input")


def is_greenhouse_auxiliary_field(
    *, identity: str, field_type: str, required: bool
) -> bool:
    """Recognize the exact optional search control owned by intl-tel-input."""

    return (
        not required
        and field_type.casefold() == "search"
        and _PHONE_WIDGET_SEARCH.fullmatch(identity) is not None
    )


class ProductionATSBoundaryError(RuntimeError):
    """The live page requires human action or an unsupported control."""


class ProductionSubmissionIndeterminate(RuntimeError):
    """Click intent exists but no provider result can be proved."""


@dataclass(frozen=True)
class GmailConfirmationEvidence:
    """Secret-free result of one narrow, read-only Gmail confirmation query."""

    collector_identity: str
    checked_at: str
    result: str
    matched_message_metadata: tuple[Mapping[str, str], ...] = ()
    match_reasons: tuple[str, ...] = ()
    query_receipt: Mapping[str, object] | None = None
    schema_version: str = "jaa.gmail-confirmation-evidence.v1"

    def __post_init__(self) -> None:
        try:
            checked_at = datetime.fromisoformat(self.checked_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValueError("Gmail confirmation evidence time is invalid") from exc
        if (
            self.schema_version != "jaa.gmail-confirmation-evidence.v1"
            or not self.collector_identity
            or self.collector_identity != self.collector_identity.strip()
            or checked_at.tzinfo is None
            or self.result not in {"match", "no_match"}
            or (self.result == "match") is not bool(self.matched_message_metadata)
            or self.result == "match"
            and set(self.match_reasons)
            != {
                "positive_confirmation",
                "provider_sender",
                "vacancy_identity",
                "post_intent_time",
            }
            or self.result == "no_match"
            and bool(self.match_reasons)
        ):
            raise ValueError("Gmail confirmation evidence is invalid")
        for row in self.matched_message_metadata:
            if (
                set(row)
                != {
                    "message_id_sha256",
                    "received_at",
                    "sender_domain",
                    "subject_sha256",
                }
                or not re.fullmatch(r"[0-9a-f]{64}", row["message_id_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", row["subject_sha256"])
                or not row["sender_domain"]
            ):
                raise ValueError("Gmail confirmation metadata is invalid")
            try:
                received_at = datetime.fromisoformat(
                    row["received_at"].replace("Z", "+00:00")
                )
            except (AttributeError, ValueError) as exc:
                raise ValueError("Gmail confirmation metadata time is invalid") from exc
            if received_at.tzinfo is None:
                raise ValueError("Gmail confirmation metadata time is invalid")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "collector_identity": self.collector_identity,
            "checked_at": self.checked_at,
            "result": self.result,
            "matched_message_metadata": [
                dict(row) for row in self.matched_message_metadata
            ],
            "match_reasons": list(self.match_reasons),
            "query_receipt": (
                None if self.query_receipt is None else dict(self.query_receipt)
            ),
        }


class GmailConfirmationChecker(Protocol):
    def check_confirmation(
        self,
        *,
        job_key: str,
        application_id: str,
        company_name: str,
        role_title: str,
        not_before: datetime,
        not_after: datetime,
    ) -> GmailConfirmationEvidence: ...


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _terminal_network_evidence_bytes(
    network_evidence: tuple[Mapping[str, object], ...],
) -> bytes:
    return _json_bytes(
        {
            "schema_version": "jaa.browser-http-evidence.v1",
            "capture_phase": "after_click_intent",
            "events": network_evidence,
            "availability": (
                "observed"
                if network_evidence
                else "no_response_event_observed_after_listener_started"
            ),
        }
    )


def _normal_url(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit(
        (
            parsed.scheme.casefold(),
            parsed.netloc.casefold(),
            parsed.path.rstrip("/"),
            "",
            "",
        )
    )


def canonical_non_secret_form_state(page: Page) -> bytes:
    """Capture reconstructable form state while redacting hidden/secret values."""
    if page.locator("input[type=password]").count():
        raise ProductionATSBoundaryError("password or login control is present")
    rows = page.locator("form input, form textarea, form select").evaluate_all(
        """(elements) => elements.filter((element) => {
          const identity = element.getAttribute('name') || element.id || '';
          return identity || !element.closest('.select__container');
        }).map((element) => {
          const type = (element.getAttribute('type') || '').toLowerCase();
          const labels = Array.from(element.labels || []).map(
            (label) => (label.textContent || '').trim()
          );
          const base = {
            id: element.id || '',
            name: element.getAttribute('name') || '',
            tag: element.tagName.toLowerCase(),
            type,
            labels,
            required: Boolean(element.required) || element.getAttribute('aria-required') === 'true',
            disabled: Boolean(element.disabled),
            aria_invalid: element.getAttribute('aria-invalid') || '',
          };
          if (type === 'hidden') {
            return {...base, value_redacted: true, value_present: Boolean(element.value)};
          }
          if (type === 'file') {
            return {...base, files: Array.from(element.files || []).map(
              (file) => ({name: file.name, size: file.size, type: file.type})
            )};
          }
          if (type === 'checkbox' || type === 'radio') {
            return {...base, checked: Boolean(element.checked), value: element.value || ''};
          }
          if (element.tagName.toLowerCase() === 'select') {
            const options = Array.from(element.options || []).map(
              (option) => ({value: option.value, text: option.text, selected: option.selected})
            );
            return {
              ...base,
              value: element.value || '',
              selected_text: options.filter((option) => option.selected).map(
                (option) => option.text
              ),
              options,
            };
          }
          const container = element.closest('.select__container');
          const selected = container ? Array.from(container.querySelectorAll(
            '.select__single-value, .select__multi-value__label'
          )).map((node) => (node.textContent || '').trim()).filter(Boolean) : [];
          return {...base, value: element.value || '', selected_text: selected};
        })"""
    )
    document = {
        "schema_version": "jaa.greenhouse-form-state.v1",
        "url": _normal_url(page.url),
        "title": page.title(),
        "provider": "greenhouse",
        "fields": rows,
    }
    return _json_bytes(document)


def collect_greenhouse_form_inventory(page: Page) -> bytes:
    """Capture questions and every currently enumerable select option."""
    state = json.loads(canonical_non_secret_form_state(page))
    inventories: list[dict[str, object]] = []
    comboboxes = page.get_by_role("combobox")
    for index in range(comboboxes.count()):
        combobox = comboboxes.nth(index)
        identity = combobox.get_attribute("id") or combobox.get_attribute("name")
        if not identity:
            raise ProductionATSBoundaryError(
                "Greenhouse combobox lacks a stable field identity"
            )
        tag = combobox.evaluate("(element) => element.tagName.toLowerCase()")
        if tag == "select":
            options = combobox.locator("option").evaluate_all(
                "(rows) => rows.map((row) => "
                "({value: row.value, text: row.text, disabled: row.disabled}))"
            )
            source = "native_select"
        else:
            combobox.focus()
            combobox.press("ArrowDown")
            option_rows = page.locator('[role="option"]:visible')
            options = option_rows.evaluate_all(
                "(rows) => rows.map((row) => ({"
                "value: row.getAttribute('data-value') || row.id || '', "
                "text: (row.textContent || '').trim(), "
                "disabled: row.getAttribute('aria-disabled') === 'true'}))"
            )
            combobox.press("Escape")
            source = "aria_combobox" if options else "dynamic_search"
        inventories.append(
            {
                "field_identity": identity,
                "option_source": source,
                "options": options,
            }
        )
    return _json_bytes(
        {
            "schema_version": "jaa.greenhouse-form-inventory.v1",
            "url": _normal_url(page.url),
            "title": page.title(),
            "form_state": state,
            "select_inventories": inventories,
        }
    )


@dataclass(frozen=True)
class GreenhouseSubmissionPlan:
    upload_input_names: Mapping[str, Path]
    consent_states: Mapping[str, bool | str]
    submit_button_name: str = "Submit Application"
    timeout_ms: int = 20_000
    schema_version: str = "jaa.greenhouse-submit-plan.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "jaa.greenhouse-submit-plan.v1":
            raise ValueError("Greenhouse submit plan schema is unsupported")
        if (
            not self.submit_button_name
            or self.submit_button_name != self.submit_button_name.strip()
        ):
            raise ValueError("Greenhouse submit button name is required")
        if not 1_000 <= self.timeout_ms <= 30_000:
            raise ValueError("Greenhouse submit timeout is outside the admitted bound")
        if "cv" not in self.upload_input_names or not set(self.upload_input_names) <= {
            "cv",
            "cover_letter",
        }:
            raise ValueError("Greenhouse plan requires an exact CV input")
        for name, path in self.upload_input_names.items():
            if not name or not isinstance(path, Path):
                raise TypeError("Greenhouse upload mapping is invalid")
        for name, state in self.consent_states.items():
            if (
                not name
                or not isinstance(state, (bool, str))
                or isinstance(state, str)
                and (not state or state != state.strip())
            ):
                raise TypeError("Greenhouse consent mapping is invalid")


@dataclass(frozen=True)
class ProductionSubmissionReceipt:
    attempt_id: str
    provider: str
    job_key: str
    vacancy_sha256: str
    confirmation_url: str
    page_title: str
    visible_text_sha256: str
    post_submit_screenshot_sha256: str
    submitted_at: str
    receipt_sha256: str
    provider_application_id: str | None = None
    confirmation_email_checked: bool = False
    schema_version: str = "jaa.production-submission-receipt.v1"

    def __post_init__(self) -> None:
        if (
            self.provider != "greenhouse"
            or self.schema_version != "jaa.production-submission-receipt.v1"
        ):
            raise ValueError("production submission receipt provider is unsupported")
        for value in (
            self.vacancy_sha256,
            self.visible_text_sha256,
            self.post_submit_screenshot_sha256,
            self.receipt_sha256,
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("production receipt contains an invalid hash")
        if self.receipt_sha256 != _sha256(_json_bytes(self.document(False))):
            raise ValueError("production submission receipt identity is invalid")

    def document(self, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "provider": self.provider,
            "job_key": self.job_key,
            "vacancy_sha256": self.vacancy_sha256,
            "confirmation_url": self.confirmation_url,
            "page_title": self.page_title,
            "visible_text_sha256": self.visible_text_sha256,
            "post_submit_screenshot_sha256": self.post_submit_screenshot_sha256,
            "submitted_at": self.submitted_at,
            "provider_application_id": self.provider_application_id,
            "confirmation_email_checked": self.confirmation_email_checked,
        }
        if include_identity:
            result["receipt_sha256"] = self.receipt_sha256
        return result


class CertifiedGreenhouseSubmitExecutor:
    """The sole admitted production implementation of the final click."""

    def __init__(
        self,
        *,
        repository_root: str | Path,
        gmail_confirmation_checker: GmailConfirmationChecker | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).resolve(strict=True)
        self.gmail_confirmation_checker = gmail_confirmation_checker

    @staticmethod
    def _submit_locator(page: Page, plan: GreenhouseSubmissionPlan) -> Locator:
        locator = page.get_by_role(
            "button",
            name=re.compile(
                rf"^{re.escape(plan.submit_button_name)}$",
                re.IGNORECASE,
            ),
        )
        if locator.count() != 1 or not locator.is_visible() or not locator.is_enabled():
            raise ProductionATSBoundaryError(
                "unique enabled Greenhouse final-submit control is unavailable"
            )
        return locator

    @staticmethod
    def _boundary_signals(page: Page) -> tuple[str, ...]:
        signals: set[str] = set()
        # Greenhouse embeds an invisible reCAPTCHA component on every ordinary
        # application form.  Its mere presence is not a human-verification
        # boundary: treating the dormant widget as one parked every vacancy.
        # A visible challenge frame remains fail-closed.  If an invisible
        # widget turns into a challenge after the legitimate submit click, the
        # post-intent reconciliation path quarantines the attempt and forbids a
        # second click; this detector never solves or bypasses the challenge.
        frame_sources = page.locator("iframe:visible").evaluate_all(
            "(frames) => frames.map((frame) => frame.getAttribute('src') || '')"
        )
        visible = page.locator("body").inner_text().casefold()
        haystack = " ".join(str(value).casefold() for value in frame_sources)
        for marker in BOUNDARY_MARKERS:
            if marker in haystack or marker in visible:
                signals.add(marker)
        # reCAPTCHA's visible anchor/badge frame and its explanatory footer are
        # present before any challenge.  The separate bframe is the interactive
        # image/audio challenge.  Detect that challenge specifically instead
        # of matching the provider name in ordinary form chrome.
        if "recaptcha" in haystack and any(
            marker in haystack for marker in ("/bframe", "challenge", "fallback")
        ):
            signals.add("recaptcha_challenge")
        if page.locator("input[type=password]").count():
            signals.add("password_or_login")
        return tuple(sorted(signals))

    @classmethod
    def boundary_signals(cls, page: Page) -> tuple[str, ...]:
        """Expose the same fail-closed boundary detector before preparation."""
        return cls._boundary_signals(page)

    @staticmethod
    def _verify_form_fields(
        page: Page,
        authority: ReleaseExecutionAuthority,
    ) -> None:
        expected_bytes = approved_form_mapping_bytes(
            source=authority.source,
            artifacts=authority.artifacts,
            field_authority_names=authority.field_authority_names,
            consent_states=authority.consent_states,
        )
        archived_bytes = selected_archive_object_bytes(
            authority.archive_receipt,
            "form.approved_field_mapping",
            root=authority.archive_root,
            repository_root=authority.repository_root,
        )
        if expected_bytes != archived_bytes:
            raise ProductionATSBoundaryError(
                "approved form mapping differs from release authority"
            )
        expected_document = json.loads(expected_bytes)
        expected_values = {
            str(row["field_identity"]): row["value"]
            for section in ("fields", "consents")
            for row in expected_document[section]
        }
        rows = page.locator("form input, form textarea, form select").evaluate_all(
            """(elements) => elements.map((element) => {
              const type = (element.getAttribute('type') || '').toLowerCase();
              const identity = element.getAttribute('name') || element.id || '';
              const container = element.closest('.select__container');
              const selected = container ? Array.from(container.querySelectorAll(
                '.select__single-value, .select__multi-value__label'
              )).map((node) => (node.textContent || '').trim()).filter(Boolean) : [];
              if (element.tagName.toLowerCase() === 'select') {
                selected.push(...Array.from(element.selectedOptions || []).map(
                  (option) => option.text
                ).filter(Boolean));
              }
              return {
                identity,
                type,
                tag: element.tagName.toLowerCase(),
                value: element.value || '',
                checked: Boolean(element.checked),
                required: Boolean(
                  element.required || element.getAttribute('aria-required') === 'true'
                ),
                selected: Array.from(new Set(selected)),
              };
            })"""
        )
        employer_rows = [
            row
            for row in rows
            if row["type"] not in {"hidden", "file", "submit", "button", "reset"}
            and not is_greenhouse_auxiliary_field(
                identity=str(row["identity"]),
                field_type=str(row["type"]),
                required=row["required"] is True,
            )
        ]
        if any(not row["identity"] for row in employer_rows):
            raise ProductionATSBoundaryError(
                "employer-facing field lacks a stable identity"
            )
        undeclared = sorted(
            {str(row["identity"]) for row in employer_rows} - set(expected_values)
        )
        if undeclared:
            raise ProductionATSBoundaryError(
                "employer-facing fields are not authority-bound: "
                + ", ".join(undeclared)
            )
        for identity, expected in expected_values.items():
            matches = [row for row in employer_rows if row["identity"] == identity]
            if len(matches) != 1:
                raise ProductionATSBoundaryError(
                    f"approved field identity is ambiguous: {identity}"
                )
            observed = matches[0]
            if type(expected) is bool:
                correct = (
                    observed["type"] in {"checkbox", "radio"}
                    and observed["checked"] is expected
                )
            else:
                correct = (
                    expected == observed["value"] or expected in observed["selected"]
                )
            if not correct:
                raise ProductionATSBoundaryError(
                    f"browser field differs from approved authority: {identity}"
                )

    @staticmethod
    def _verify_consents(
        page: Page,
        authority: ReleaseExecutionAuthority,
    ) -> None:
        expected_consents = dict(authority.consent_states)
        consent_fields = page.locator(
            "form input, form textarea, form select"
        ).evaluate_all(
            """(elements) => elements.filter((element) => {
              const labels = Array.from(element.labels || []).map(
                (label) => (label.textContent || '').toLowerCase()
              ).join(' ');
              return labels.includes('consent') || labels.includes('privacy') ||
                labels.includes('terms and conditions');
            }).map((element) => element.getAttribute('name') || element.id || '')
              .filter(Boolean)"""
        )
        undeclared = sorted(set(consent_fields) - set(expected_consents))
        if undeclared:
            raise ProductionATSBoundaryError(
                "consent-bearing fields are not explicitly declared: "
                + ", ".join(undeclared)
            )
        for name, expected in expected_consents.items():
            matches = page.locator(
                "form input, form textarea, form select"
            ).evaluate_all(
                "(elements, name) => elements.filter((element) => "
                "element.getAttribute('name') === name || element.id === name).map((element) => {"
                "const container = element.closest('.select__container'); "
                "const selected = container ? Array.from(container.querySelectorAll("
                "'.select__single-value, .select__multi-value__label')).map("
                "(node) => (node.textContent || '').trim()).filter(Boolean) : []; "
                "return {checked: Boolean(element.checked), type: element.type, "
                "value: element.value || '', selected};})",
                name,
            )
            correct = False
            if len(matches) == 1 and type(expected) is bool:
                correct = (
                    matches[0]["type"] in {"checkbox", "radio"}
                    and matches[0]["checked"] is expected
                )
            elif len(matches) == 1 and isinstance(expected, str):
                correct = (
                    expected == matches[0]["value"]
                    or expected in matches[0]["selected"]
                )
            if not correct:
                raise ProductionATSBoundaryError(
                    f"consent state differs for declared field {name}"
                )
        required = page.locator(
            "form input:required, form textarea:required, form select:required, "
            "form input[aria-required=true], form textarea[aria-required=true], "
            "form select[aria-required=true]"
        )
        invalid = required.evaluate_all(
            """(elements) => elements.filter((element) => {
              if (!element.checkValidity()) return true;
              if (element.getAttribute('aria-required') !== 'true') return false;
              if (element.type === 'file') return !(element.files || []).length;
              const container = element.closest('.select__container');
              const selected = container ? container.querySelector(
                '.select__single-value, .select__multi-value__label'
              ) : null;
              return !element.value && !selected;
            }).map((element) => element.getAttribute('name') || element.id || element.type)"""
        )
        if invalid:
            raise ProductionATSBoundaryError(
                "required Greenhouse fields are incomplete: " + ", ".join(invalid)
            )

    @staticmethod
    def _verify_uploads(
        page: Page,
        plan: GreenhouseSubmissionPlan,
        authority: ReleaseExecutionAuthority,
    ) -> None:
        expected_hashes = {
            "cv": authority.artifacts.cv_pdf.pdf_sha256,
            "cover_letter": authority.artifacts.cover_letter_pdf.pdf_sha256,
        }
        expected_inputs = dict(authority.upload_field_names)
        paths = {
            role: path.resolve(strict=True)
            for role, path in plan.upload_input_names.items()
        }
        expected_names = [path.name for path in paths.values()]
        if len(set(expected_names)) != len(expected_names):
            raise ProductionATSBoundaryError(
                "approved uploads contain duplicate basenames"
            )
        for role, path in plan.upload_input_names.items():
            if path.is_symlink():
                raise ProductionATSBoundaryError("upload path is a symlink")
            value = paths[role].read_bytes()
            if _sha256(value) != expected_hashes[role]:
                raise ProductionATSBoundaryError(
                    f"selected {role} bytes differ from approved PDF"
                )
        try:
            inventory = page.locator("form input[type=file]").evaluate_all(
                """async (elements) => Promise.all(elements.map(async (element) => {
                  const identity = element.getAttribute('name') || element.id || '';
                  const files = await Promise.all(Array.from(element.files || []).map(
                    async (file) => ({
                      name: file.name,
                      size: file.size,
                      type: file.type,
                      bytes: Array.from(new Uint8Array(await file.arrayBuffer())),
                    })
                  ));
                  return {identity, files};
                }))"""
            )
        except Exception as exc:
            raise ProductionATSBoundaryError(
                "browser-selected File bytes are inaccessible"
            ) from exc
        selected_inputs = [row for row in inventory if row["files"]]
        if any(not row["identity"] for row in selected_inputs):
            raise ProductionATSBoundaryError(
                "selected upload input lacks a stable identity"
            )
        if len({row["identity"] for row in selected_inputs}) != len(selected_inputs):
            raise ProductionATSBoundaryError("selected upload inputs are ambiguous")
        selected_identities = {row["identity"] for row in selected_inputs}
        if selected_inputs and selected_identities != set(expected_inputs.values()):
            raise ProductionATSBoundaryError(
                "browser has missing or extra selected upload inputs"
            )
        if not selected_inputs:
            attachments = page.locator(
                "form .file-upload__filename:visible"
            ).evaluate_all(
                """(rows) => rows.map((row) => ({
                  filename: (row.innerText || '').trim(),
                  remove_buttons: row.querySelectorAll(
                    'button[aria-label="Remove file"]'
                  ).length,
                }))"""
            )
            observed_names = [str(row["filename"]) for row in attachments]
            if (
                len(attachments) != len(expected_names)
                or len(set(observed_names)) != len(observed_names)
                or set(observed_names) != set(expected_names)
                or any(row["remove_buttons"] != 1 for row in attachments)
            ):
                raise ProductionATSBoundaryError(
                    "browser replacement upload UI differs from approved filenames"
                )
            return
        for role, path in plan.upload_input_names.items():
            matches = [
                row
                for row in selected_inputs
                if row["identity"] == expected_inputs[role]
            ]
            if len(matches) != 1 or len(matches[0]["files"]) != 1:
                raise ProductionATSBoundaryError(
                    f"browser upload role {role} is not bound to exactly one File"
                )
            selected = matches[0]["files"][0]
            try:
                browser_bytes = bytes(selected["bytes"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ProductionATSBoundaryError(
                    "browser-selected File bytes are inaccessible"
                ) from exc
            if (
                selected["name"] != paths[role].name
                or selected["size"] != len(browser_bytes)
                or _sha256(browser_bytes) != expected_hashes[role]
            ):
                raise ProductionATSBoundaryError(
                    f"browser-resident {role} File differs from approved PDF"
                )

    def _authoritative_revalidation(
        self,
        page: Page,
        plan: GreenhouseSubmissionPlan,
        authority: ReleaseExecutionAuthority,
        *,
        verified_at: datetime,
    ) -> Locator:
        """Recheck every in-memory and browser-resident release binding."""
        intended_vacancy = IntendedVacancy(
            job_key=authority.source.job_key,
            vacancy_sha256=authority.source.vacancy_sha256,
            role_title=authority.source.role_title,
            company_name=authority.source.company_name,
        )
        verify_receipt_for_pdf(
            authority.document_assurance_receipts[0],
            authority.artifacts.cv_pdf.pdf_bytes,
            intended_vacancy=intended_vacancy,
        )
        verify_receipt_for_pdf(
            authority.document_assurance_receipts[1],
            authority.artifacts.cover_letter_pdf.pdf_bytes,
            intended_vacancy=intended_vacancy,
        )
        verify_sanity_review_receipt(
            authority.sanity_review_receipt,
            authority.sanity_review_package(),
        )
        if isinstance(authority.gate, CandidateAuthorityReleaseGate):
            authority.gate.verify_current_release_token(
                **self._release_arguments(authority)
            )
        authority.verify_archive_receipt(verified_at=verified_at)
        if _normal_url(page.url) != _normal_url(authority.application_url):
            raise ProductionATSBoundaryError(
                "browser is not on the vacancy-bound Greenhouse application"
            )
        signals = self._boundary_signals(page)
        if signals:
            raise ProductionATSBoundaryError(
                "human-verification boundary detected: " + ", ".join(signals)
            )
        state = canonical_non_secret_form_state(page)
        archived_state = selected_archive_object_bytes(
            authority.archive_receipt,
            "browser.pre_submit_state",
            root=authority.archive_root,
            repository_root=self.repository_root,
        )
        if state != archived_state:
            raise ProductionATSBoundaryError(
                "current Greenhouse form differs from archived pre-submit state"
            )
        if tuple(sorted(plan.consent_states.items())) != tuple(
            sorted(authority.consent_states)
        ):
            raise ProductionATSBoundaryError(
                "submit plan consents differ from release authority"
            )
        self._verify_form_fields(page, authority)
        self._verify_consents(page, authority)
        self._verify_uploads(page, plan, authority)
        return self._submit_locator(page, plan)

    def _attempt(self, authority: ReleaseExecutionAuthority):
        archive = ApplicationArchive(
            authority.archive_root,
            repository_root=self.repository_root,
            create=False,
        )
        return archive.open_attempt(authority.archive_receipt.attempt_id)

    @staticmethod
    def _click_intent_sha256(attempt) -> str:
        rows = [
            row
            for row in attempt._objects(attempt._events())
            if row.role == "submission.click_intent"
        ]
        if len(rows) != 1:
            raise ProductionSubmissionIndeterminate(
                "post-intent reconciliation requires one durable click intent"
            )
        return rows[0].sha256

    def _reconcile_after_intent(
        self,
        page: Page,
        authority: ReleaseExecutionAuthority,
        *,
        network_evidence: tuple[Mapping[str, object], ...] = (),
    ) -> tuple[str, bytes, bytes, bytes]:
        """Check provider state and Gmail once without replaying the click."""
        checked_at = max(datetime.now(timezone.utc), authority.consumed_at)
        visible_text = page.locator("body").inner_text().encode("utf-8")
        screenshot = page.screenshot(full_page=True)
        provider_success = self._provider_success(page, authority.success_evidence)
        checker = self.gmail_confirmation_checker
        if checker is None:
            if not provider_success:
                raise ProductionSubmissionIndeterminate(
                    "prior click intent lacks both provider success and a configured "
                    "Gmail confirmation checker; submit replay is forbidden"
                )
            email_document: Mapping[str, object] = {
                "provider": "gmail",
                "checked": False,
                "result": "deferred_connector_verification",
                "verification_required": True,
            }
            email_result = "deferred_connector_verification"
        else:
            email = checker.check_confirmation(
                job_key=authority.job_key,
                application_id=authority.application_id,
                company_name=authority.source.company_name,
                role_title=authority.source.role_title,
                not_before=authority.consumed_at,
                not_after=checked_at,
            )
            if not isinstance(email, GmailConfirmationEvidence):
                raise ProductionSubmissionIndeterminate(
                    "Gmail confirmation checker returned unsupported evidence"
                )
            parsed_application = urlsplit(authority.application_url)
            repository_fixture = (
                parsed_application.hostname == "job-boards.greenhouse.io"
                and parsed_application.path.startswith("/example/jobs/")
            )
            if not repository_fixture:
                from .gmail_confirmation import GmailAPIConfirmationChecker

                if type(checker) is not GmailAPIConfirmationChecker:
                    raise ProductionSubmissionIndeterminate(
                        "live reconciliation requires the repository Gmail API collector"
                    )
                try:
                    checker.verify_evidence(email)
                except ValueError as exc:
                    raise ProductionSubmissionIndeterminate(
                        "Gmail confirmation evidence lacks exact collector authority"
                    ) from exc
            email_time = datetime.fromisoformat(email.checked_at.replace("Z", "+00:00"))
            if not authority.consumed_at <= email_time <= checked_at:
                raise ProductionSubmissionIndeterminate(
                    "Gmail confirmation evidence is outside the click-intent window"
                )
            email_document = {
                "provider": "gmail",
                "checked": True,
                **email.document(),
            }
            email_result = email.result
        outcome = (
            "submitted_success"
            if provider_success or email_result == "match"
            else "indeterminate"
        )
        document = {
            "schema_version": "jaa.submission-reconciliation.v2",
            "attempt_id": authority.archive_receipt.attempt_id,
            "provider": "greenhouse",
            "job_key": authority.job_key,
            "vacancy_sha256": authority.source.vacancy_sha256,
            "application_url": authority.application_url,
            "confirmation_url": authority.receipt_url,
            "click_intent_sha256": self._click_intent_sha256(self._attempt(authority)),
            "network_evidence_sha256": _sha256(
                _terminal_network_evidence_bytes(network_evidence)
            ),
            "checked_at": checked_at.isoformat(),
            "click_replay_attempted": False,
            "provider_state": {
                "url": _normal_url(page.url),
                "title": page.title(),
                "visible_text_sha256": _sha256(visible_text),
                "screenshot_sha256": _sha256(screenshot),
                "success_observed": provider_success,
            },
            "confirmation_email": {
                "query": {
                    "job_key": authority.job_key,
                    "application_id": authority.application_id,
                    "company_name_sha256": _sha256(
                        authority.source.company_name.encode()
                    ),
                    "role_title_sha256": _sha256(authority.source.role_title.encode()),
                    "not_before": authority.consumed_at.isoformat(),
                    "not_after": checked_at.isoformat(),
                },
                **email_document,
            },
            "conclusion": outcome,
        }
        return outcome, _json_bytes(document), screenshot, visible_text

    def _park(
        self,
        page: Page,
        authority: ReleaseExecutionAuthority,
        *,
        classification: str,
        description: str,
        network_evidence: tuple[Mapping[str, object], ...] = (),
    ) -> None:
        attempt = self._attempt(authority)
        selection = selected_archive_hashes(
            authority.archive_receipt,
            root=authority.archive_root,
            repository_root=self.repository_root,
        )
        boundary = attempt.add_artifact(
            "technical.boundary",
            _json_bytes(
                {
                    "classification": classification,
                    "description": description,
                    "safe_reproduction": (
                        "Open the official vacancy in a normal browser and stop "
                        "before any human-verification or authentication control."
                    ),
                    "future_queue": "technical_boundary",
                    "secret_value": None,
                }
            ),
            media_type="application/json",
            disposition="observed",
        )
        result = attempt.add_artifact(
            "submission.result",
            _json_bytes(
                {
                    "state": "blocked",
                    "provider": "greenhouse",
                    "url": _normal_url(page.url),
                    "title": page.title(),
                    "classification": classification,
                }
            ),
            media_type="application/json",
            disposition="observed",
        )
        screenshot = attempt.add_artifact(
            "browser.blocked_screenshot",
            page.screenshot(full_page=True),
            media_type="image/png",
            disposition="observed",
        )
        visible = attempt.add_artifact(
            "browser.blocked_visible_text",
            page.locator("body").inner_text().encode("utf-8"),
            media_type="text/plain",
            disposition="observed",
        )
        network = attempt.add_artifact(
            "browser.redirect_http_evidence",
            _json_bytes(
                {
                    "schema_version": "jaa.browser-http-evidence.v1",
                    "capture_phase": "before_click_intent",
                    "events": network_evidence,
                    "availability": (
                        "observed"
                        if network_evidence
                        else "listener_not_started_before_boundary"
                    ),
                }
            ),
            media_type="application/json",
            disposition="observed",
        )
        blocked_state = attempt.add_artifact(
            "browser.blocked_state_evidence",
            canonical_non_secret_form_state(page),
            media_type="application/json",
            disposition="observed",
        )
        attempt.finalize_terminal(
            outcome="blocked",
            selected={
                "vacancy.source_identity": selection["vacancy.source_identity"],
                "vacancy.capture": selection["vacancy.capture"],
                "technical.boundary": boundary.sha256,
                "submission.result": result.sha256,
                "browser.blocked_screenshot": screenshot.sha256,
                "browser.blocked_visible_text": visible.sha256,
                "browser.blocked_state_evidence": blocked_state.sha256,
                "browser.redirect_http_evidence": network.sha256,
            },
        )
        ProductionCheckpointLedger(attempt.archive).record_attempt_terminal(
            attempt.attempt_id
        )

    def _release_arguments(
        self, authority: ReleaseExecutionAuthority
    ) -> dict[str, object]:
        return {
            "release_token": authority.release_token,
            "source": authority.source,
            "artifacts": authority.artifacts,
            "contact": authority.contact,
            "questions": authority.questions,
            "artifact_root": authority.artifact_root,
            "repository_root": authority.repository_root,
            "jurisdiction": authority.jurisdiction,
            "contract_type": authority.contract_type,
        }

    def _record_preflight_rejection(
        self,
        page: Page,
        authority: ReleaseExecutionAuthority,
        *,
        description: str,
    ) -> None:
        """Archive a repairable rejection without recording click intent."""
        attempt = self._attempt(authority)
        attempt.add_artifact(
            "submission.preflight_rejection",
            _json_bytes(
                {
                    "state": "preflight_rejected",
                    "provider": "greenhouse",
                    "url": _normal_url(page.url),
                    "title": page.title(),
                    "description": description,
                    "click_may_have_occurred": False,
                }
            ),
            media_type="application/json",
            disposition="rejected",
        )
        attempt.add_artifact(
            "browser.preflight_rejection_screenshot",
            page.screenshot(full_page=True),
            media_type="image/png",
            disposition="observed",
        )

    @staticmethod
    def _provider_success(
        page: Page,
        evidence: GreenhouseSuccessEvidence,
    ) -> bool:
        if _normal_url(page.url) != _normal_url(evidence.confirmation_url):
            return False
        visible = page.locator("body").inner_text().casefold()
        return all(
            marker.casefold() in visible for marker in evidence.required_visible_markers
        )

    def _record_click_cancelled(
        self,
        page: Page,
        authority: ReleaseExecutionAuthority,
        *,
        description: str,
        network_evidence: tuple[Mapping[str, object], ...],
    ) -> None:
        """Finalize a proved no-click failure after intent was recorded."""
        attempt = self._attempt(authority)
        selection = selected_archive_hashes(
            authority.archive_receipt,
            root=authority.archive_root,
            repository_root=self.repository_root,
        )
        cancelled = attempt.add_artifact(
            "submission.click_cancelled",
            _json_bytes(
                {
                    "state": "revalidation_rejected_before_click_dispatch",
                    "click_may_have_occurred": False,
                    "description": description,
                }
            ),
            media_type="application/json",
            disposition="rejected",
        )
        result = attempt.add_artifact(
            "submission.result",
            _json_bytes(
                {
                    "state": "gate_rejected",
                    "provider": "greenhouse",
                    "url": _normal_url(page.url),
                    "title": page.title(),
                    "click_may_have_occurred": False,
                }
            ),
            media_type="application/json",
            disposition="rejected",
        )
        screenshot = attempt.add_artifact(
            "browser.failed_screenshot",
            page.screenshot(full_page=True),
            media_type="image/png",
            disposition="observed",
        )
        visible = attempt.add_artifact(
            "browser.failed_visible_text",
            page.locator("body").inner_text().encode("utf-8"),
            media_type="text/plain",
            disposition="observed",
        )
        state = attempt.add_artifact(
            "browser.failed_state_evidence",
            canonical_non_secret_form_state(page),
            media_type="application/json",
            disposition="observed",
        )
        network = attempt.add_artifact(
            "browser.redirect_http_evidence",
            _json_bytes(
                {
                    "schema_version": "jaa.browser-http-evidence.v1",
                    "capture_phase": "after_click_intent",
                    "events": network_evidence,
                    "availability": (
                        "observed"
                        if network_evidence
                        else "no_response_event_observed_after_listener_started"
                    ),
                }
            ),
            media_type="application/json",
            disposition="observed",
        )
        attempt.finalize_terminal(
            outcome="gate_rejected",
            selected={
                "vacancy.source_identity": selection["vacancy.source_identity"],
                "vacancy.capture": selection["vacancy.capture"],
                "submission.click_cancelled": cancelled.sha256,
                "submission.result": result.sha256,
                "browser.failed_screenshot": screenshot.sha256,
                "browser.failed_visible_text": visible.sha256,
                "browser.failed_state_evidence": state.sha256,
                "browser.redirect_http_evidence": network.sha256,
            },
        )
        ProductionCheckpointLedger(attempt.archive).record_attempt_terminal(
            attempt.attempt_id
        )

    def _record_terminal(
        self,
        page: Page,
        authority: ReleaseExecutionAuthority,
        *,
        state: str,
        outcome: str,
        submitted_at: str,
        reconciliation_evidence: bytes,
        reconciliation_screenshot: bytes,
        reconciliation_visible_text: bytes,
        network_evidence: tuple[Mapping[str, object], ...] = (),
    ) -> tuple[bytes, Mapping[str, object], ProductionSubmissionReceipt | None]:
        attempt = self._attempt(authority)
        selection = selected_archive_hashes(
            authority.archive_receipt,
            root=authority.archive_root,
            repository_root=self.repository_root,
        )
        screenshot = reconciliation_screenshot
        post = attempt.add_artifact(
            "browser.post_submit_screenshot",
            screenshot,
            media_type="image/png",
            disposition="observed",
        )
        visible_text = reconciliation_visible_text
        visible = attempt.add_artifact(
            "browser.post_submit_visible_text",
            visible_text,
            media_type="text/plain",
            disposition="observed",
        )
        network_value = _terminal_network_evidence_bytes(network_evidence)
        network = attempt.add_artifact(
            "browser.redirect_http_evidence",
            network_value,
            media_type="application/json",
            disposition="observed",
        )
        click_intent_sha256 = self._click_intent_sha256(attempt)
        reconciliation_document = json.loads(reconciliation_evidence)
        provider_state = reconciliation_document.get("provider_state")
        if (
            not isinstance(provider_state, Mapping)
            or provider_state.get("screenshot_sha256") != post.sha256
            or provider_state.get("visible_text_sha256") != visible.sha256
            or reconciliation_document.get("network_evidence_sha256") != network.sha256
        ):
            raise ProductionSubmissionIndeterminate(
                "reconciliation differs from exact archived provider evidence"
            )
        reconciliation = attempt.add_artifact(
            "submission.reconciliation",
            reconciliation_evidence,
            media_type="application/json",
            disposition="observed",
        )
        confirmation_email = reconciliation_document["confirmation_email"]
        confirmation_email_checked = confirmation_email["checked"] is True
        result_document = {
            "state": state,
            "provider": "greenhouse",
            "url": str(provider_state["url"]),
            "title": str(provider_state["title"]),
            "visible_text_sha256": visible.sha256,
            "provider_application_id": None,
            "confirmation_email_metadata": {
                "available": confirmation_email_checked,
                "checked": confirmation_email_checked,
                "result": confirmation_email["result"],
                "collector_identity": confirmation_email.get("collector_identity"),
            },
            "submitted_at": submitted_at,
        }
        result = attempt.add_artifact(
            "submission.result",
            _json_bytes(result_document),
            media_type="application/json",
            disposition="observed",
        )
        receipt = (
            self._receipt(
                authority,
                screenshot,
                result_document,
                confirmation_email_checked=confirmation_email_checked,
            )
            if outcome == "submitted_success"
            else None
        )
        receipt_object = (
            attempt.add_artifact(
                "submission.receipt",
                _json_bytes(receipt.document()),
                media_type="application/json",
                disposition="observed",
            )
            if receipt is not None
            else None
        )
        terminal_selection = {
            "vacancy.source_identity": selection["vacancy.source_identity"],
            "vacancy.capture": selection["vacancy.capture"],
            "provider.success_semantics": selection["provider.success_semantics"],
            "submission.click_intent": click_intent_sha256,
            "browser.post_submit_screenshot": post.sha256,
            "browser.post_submit_visible_text": visible.sha256,
            "browser.redirect_http_evidence": network.sha256,
            "submission.result": result.sha256,
        }
        if receipt_object is not None:
            terminal_selection["submission.receipt"] = receipt_object.sha256
        terminal_selection["submission.reconciliation"] = reconciliation.sha256
        attempt.record_evidence_event(
            event_id=attempt.next_evidence_event_id("terminal"),
            event_kind="terminal",
            occurred_at=datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            result=("completed" if outcome == "submitted_success" else "indeterminate"),
            member_sha256s=terminal_selection,
            details={
                "provenance": "greenhouse.terminal_reconciliation",
                "interaction_counts": {
                    "fields_filled": len(authority.field_authority_names),
                    "files_uploaded": len(authority.attached_roles),
                    "submit_clicks": 1,
                },
            },
        )
        attempt.finalize_terminal(
            outcome=outcome,
            selected=terminal_selection,
        )
        ProductionCheckpointLedger(attempt.archive).record_attempt_terminal(
            attempt.attempt_id
        )
        return screenshot, result_document, receipt

    def execute(
        self,
        page: Page,
        *,
        authority: ReleaseExecutionAuthority,
        plan: GreenhouseSubmissionPlan,
    ) -> ProductionSubmissionReceipt:
        if authority.ats_provider != "greenhouse":
            raise ProductionATSBoundaryError(
                "production executor admits only Greenhouse authorities"
            )
        if authority.repository_root.resolve(strict=True) != self.repository_root:
            raise ReleaseGateError("production executor repository authority differs")
        if set(plan.upload_input_names) != set(authority.attached_roles):
            raise ProductionATSBoundaryError(
                "browser attachment plan differs from release authority"
            )
        if set(dict(authority.upload_field_names)) != set(plan.upload_input_names):
            raise ProductionATSBoundaryError(
                "browser upload-input binding differs from release authority"
            )
        authority.gate.verify_token_official_route(
            release_token=authority.release_token,
            adapter_id="greenhouse.production",
            adapter_version="v1",
            source_identity=authority.application_url,
        )
        attempt = self._attempt(authority)
        existing_roles = {row.role for row in attempt._objects(attempt._events())}
        if "submission.click_intent" in existing_roles:
            authority.verify_archive_receipt(verified_at=authority.consumed_at)
            if (attempt.path / "terminal-manifest.json").exists():
                raise ProductionSubmissionIndeterminate(
                    "attempt already has a terminal outcome; submit replay is forbidden"
                )
            release_arguments = self._release_arguments(authority)
            authority.gate.verify_consumed_release_token(
                **release_arguments,
                consumed_at=authority.consumed_at,
            )
            (
                reconciled_outcome,
                reconciliation,
                reconciliation_screenshot,
                reconciliation_visible_text,
            ) = self._reconcile_after_intent(page, authority)
            if reconciled_outcome == "submitted_success":
                submitted_at = datetime.now(timezone.utc).isoformat()
                _screenshot, _result, receipt = self._record_terminal(
                    page,
                    authority,
                    state="submitted_success",
                    outcome="submitted_success",
                    submitted_at=submitted_at,
                    reconciliation_evidence=reconciliation,
                    reconciliation_screenshot=reconciliation_screenshot,
                    reconciliation_visible_text=reconciliation_visible_text,
                )
                if receipt is None:
                    raise AssertionError("successful terminal record lacks receipt")
                return receipt
            screenshot, _, _ = self._record_terminal(
                page,
                authority,
                state="indeterminate",
                outcome="indeterminate",
                submitted_at=datetime.now(timezone.utc).isoformat(),
                reconciliation_evidence=reconciliation,
                reconciliation_screenshot=reconciliation_screenshot,
                reconciliation_visible_text=reconciliation_visible_text,
            )
            raise ProductionSubmissionIndeterminate(
                f"prior click intent has no provider receipt; screenshot {_sha256(screenshot)}"
            )
        if _normal_url(page.url) != _normal_url(authority.application_url):
            raise ProductionATSBoundaryError(
                "browser is not on the vacancy-bound Greenhouse application"
            )
        signals = self._boundary_signals(page)
        if signals:
            description = "human-verification boundary detected: " + ", ".join(signals)
            self._park(
                page,
                authority,
                classification="human_verification",
                description=description,
            )
            raise ProductionATSBoundaryError(description)
        try:
            locator = self._authoritative_revalidation(
                page,
                plan,
                authority,
                verified_at=authority.consumed_at,
            )
        except (
            ApplicationArchiveError,
            OSError,
            ProductionATSBoundaryError,
            ValueError,
        ) as exc:
            description = f"pre-submit verification failed: {exc}"
            self._record_preflight_rejection(page, authority, description=description)
            raise ProductionATSBoundaryError(description) from exc

        release_arguments = self._release_arguments(authority)
        try:
            consumed = authority.gate.consume_release_token(
                **release_arguments,
                consumed_at=authority.consumed_at,
            )
            consumed_at = datetime.fromisoformat(consumed.consumed_at)
        except ValueError as exc:
            if str(exc) != "release token was already consumed":
                raise
            consumed_at = authority.consumed_at
        authority.gate.verify_consumed_release_token(
            **release_arguments,
            consumed_at=consumed_at,
        )
        authority.verify_archive_receipt(verified_at=consumed_at)
        attempt.add_artifact(
            "submission.click_intent",
            _json_bytes(
                {
                    "provider": "greenhouse",
                    "application_url": authority.application_url,
                    "confirmation_url": authority.receipt_url,
                    "release_manifest_sha256": authority.release_token.split(".")[1],
                    "archive_manifest_sha256": authority.archive_receipt.manifest_sha256,
                    "recorded_at": consumed_at.isoformat(),
                }
            ),
            media_type="application/json",
            disposition="approved",
        )
        network_evidence: list[Mapping[str, object]] = []

        def record_response(response) -> None:
            request = response.request
            redirected_from = request.redirected_from
            network_evidence.append(
                {
                    "url": _normal_url(response.url),
                    "status": response.status,
                    "method": request.method,
                    "redirected_from": (
                        _normal_url(redirected_from.url)
                        if redirected_from is not None
                        else None
                    ),
                }
            )
            attempt.record_evidence_event(
                event_id=attempt.next_evidence_event_id("response"),
                event_kind="response",
                occurred_at=datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                result="observed",
                details={
                    "method": str(request.method).upper(),
                    "status": int(response.status),
                    "url_sha256": _sha256(
                        _normal_url(response.url).encode("utf-8")
                    ),
                },
            )

        page.on("response", record_response)

        def record_request(request) -> None:
            attempt.record_evidence_event(
                event_id=attempt.next_evidence_event_id("request"),
                event_kind="request",
                occurred_at=datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                result="observed",
                details={
                    "method": str(request.method).upper(),
                    "resource_type": str(request.resource_type),
                    "url_sha256": _sha256(_normal_url(request.url).encode("utf-8")),
                },
            )

        page.on("request", record_request)
        try:
            certified_final_submit_click(
                locator,
                authority,
                verified_at=datetime.now(timezone.utc),
                immediate_revalidation=lambda: self._authoritative_revalidation(
                    page,
                    plan,
                    authority,
                    verified_at=datetime.now(timezone.utc),
                ),
            )
            attempt.record_evidence_event(
                event_id=attempt.next_evidence_event_id("click"),
                event_kind="click",
                occurred_at=datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
                result="completed",
                member_sha256s={
                    "submission.click_intent": self._click_intent_sha256(attempt)
                },
                details={
                    "provenance": "greenhouse.certified_final_submit_click",
                    "interaction_counts": {
                        "fields_filled": len(authority.field_authority_names),
                        "files_uploaded": len(authority.attached_roles),
                        "submit_clicks": 1,
                    },
                },
            )
        except FinalClickRevalidationError as exc:
            description = str(exc.__cause__ or exc)
            self._record_click_cancelled(
                page,
                authority,
                description=description,
                network_evidence=tuple(network_evidence),
            )
            raise ProductionATSBoundaryError(description) from exc
        try:
            page.wait_for_url(
                authority.success_evidence.confirmation_url,
                wait_until="domcontentloaded",
                timeout=plan.timeout_ms,
            )
        except PlaywrightTimeoutError as exc:
            (
                _reconciled_outcome,
                reconciliation,
                reconciliation_screenshot,
                reconciliation_visible_text,
            ) = self._reconcile_after_intent(
                page, authority, network_evidence=tuple(network_evidence)
            )
            screenshot, _, _ = self._record_terminal(
                page,
                authority,
                state="indeterminate",
                outcome="indeterminate",
                submitted_at=consumed_at.isoformat(),
                network_evidence=tuple(network_evidence),
                reconciliation_evidence=reconciliation,
                reconciliation_screenshot=reconciliation_screenshot,
                reconciliation_visible_text=reconciliation_visible_text,
            )
            raise ProductionSubmissionIndeterminate(
                f"Greenhouse click produced no confirmation; screenshot {_sha256(screenshot)}"
            ) from exc
        if not self._provider_success(page, authority.success_evidence):
            (
                _reconciled_outcome,
                reconciliation,
                reconciliation_screenshot,
                reconciliation_visible_text,
            ) = self._reconcile_after_intent(
                page, authority, network_evidence=tuple(network_evidence)
            )
            screenshot, _, _ = self._record_terminal(
                page,
                authority,
                state="indeterminate",
                outcome="indeterminate",
                submitted_at=consumed_at.isoformat(),
                network_evidence=tuple(network_evidence),
                reconciliation_evidence=reconciliation,
                reconciliation_screenshot=reconciliation_screenshot,
                reconciliation_visible_text=reconciliation_visible_text,
            )
            raise ProductionSubmissionIndeterminate(
                "Greenhouse page lacks observed positive success evidence; "
                f"screenshot {_sha256(screenshot)}"
            )
        (
            reconciled_outcome,
            reconciliation,
            reconciliation_screenshot,
            reconciliation_visible_text,
        ) = self._reconcile_after_intent(
            page, authority, network_evidence=tuple(network_evidence)
        )
        if reconciled_outcome != "submitted_success":
            raise ProductionSubmissionIndeterminate(
                "positive provider state did not survive authoritative reconciliation"
            )
        _screenshot, _result, receipt = self._record_terminal(
            page,
            authority,
            state="submitted_success",
            outcome="submitted_success",
            submitted_at=consumed_at.isoformat(),
            network_evidence=tuple(network_evidence),
            reconciliation_evidence=reconciliation,
            reconciliation_screenshot=reconciliation_screenshot,
            reconciliation_visible_text=reconciliation_visible_text,
        )
        if receipt is None:
            raise AssertionError("successful terminal record lacks receipt")
        return receipt

    @staticmethod
    def _receipt(
        authority: ReleaseExecutionAuthority,
        screenshot: bytes,
        result: Mapping[str, object],
        *,
        confirmation_email_checked: bool = False,
    ) -> ProductionSubmissionReceipt:
        preimage = {
            "schema_version": "jaa.production-submission-receipt.v1",
            "attempt_id": authority.archive_receipt.attempt_id,
            "provider": "greenhouse",
            "job_key": authority.job_key,
            "vacancy_sha256": authority.source.vacancy_sha256,
            "confirmation_url": authority.receipt_url,
            "page_title": str(result["title"]),
            "visible_text_sha256": str(result["visible_text_sha256"]),
            "post_submit_screenshot_sha256": _sha256(screenshot),
            "submitted_at": str(result["submitted_at"]),
            "provider_application_id": None,
            "confirmation_email_checked": confirmation_email_checked,
        }
        return ProductionSubmissionReceipt(
            attempt_id=authority.archive_receipt.attempt_id,
            provider="greenhouse",
            job_key=authority.job_key,
            vacancy_sha256=authority.source.vacancy_sha256,
            confirmation_url=authority.receipt_url,
            page_title=str(result["title"]),
            visible_text_sha256=str(result["visible_text_sha256"]),
            post_submit_screenshot_sha256=_sha256(screenshot),
            submitted_at=str(result["submitted_at"]),
            provider_application_id=None,
            confirmation_email_checked=confirmation_email_checked,
            receipt_sha256=_sha256(_json_bytes(preimage)),
        )


__all__ = [
    "CertifiedGreenhouseSubmitExecutor",
    "GreenhouseSubmissionPlan",
    "GmailConfirmationChecker",
    "GmailConfirmationEvidence",
    "ProductionATSBoundaryError",
    "ProductionSubmissionIndeterminate",
    "ProductionSubmissionReceipt",
    "canonical_non_secret_form_state",
    "collect_greenhouse_form_inventory",
]
