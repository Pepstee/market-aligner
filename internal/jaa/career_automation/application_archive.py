"""Durable, append-only local archives for consequential JAA attempts.

The archive has two immutable checkpoints.  ``release`` contains every item
which can exist before the final click and produces the receipt required by
release authority.  ``terminal`` extends that history with the observed
outcome.  Neither checkpoint is rewritten; post-submit evidence therefore
cannot retroactively change the bytes which authorised the click.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from .evidence_matching import canonical_json


ARCHIVE_ROOT_ENV = "JAA_APPLICATION_ARCHIVE_ROOT"
DEFAULT_ARCHIVE_ROOT = Path(
    os.sep, "home", "gutua", "software-factory", "application-artifacts"
)
ARCHIVE_SCHEMA_VERSION = "jaa.application-archive.v1"
RECEIPT_SCHEMA_VERSION = "jaa.application-archive-receipt.v1"
EVENT_SCHEMA_VERSION = "jaa.application-archive-event.v1"
EVIDENCE_VIEW_SCHEMA_VERSION = "jaa.application-evidence-view.v1"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
ATTEMPT_ID = re.compile(r"^jaa-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$")
ROLE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
EVIDENCE_EVENT_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
EVIDENCE_EVENT_KINDS = frozenset(
    {
        "preflight",
        "navigation",
        "field_observed",
        "field_filled",
        "field_selected",
        "file_uploaded",
        "click",
        "request",
        "response",
        "request_failed",
        "console_error",
        "screenshot",
        "release",
        "terminal",
    }
)
EVIDENCE_EVENT_RESULTS = frozenset(
    {
        "observed",
        "completed",
        "blocked",
        "refused",
        "indeterminate",
        "failed",
        "skipped",
        "unavailable",
    }
)
EVIDENCE_DETAIL_KEYS = frozenset(
    {
        "field_id",
        "field_type",
        "required",
        "options",
        "provenance",
        "document_role",
        "source_path_sha256",
        "content_sha256",
        "extracted_text_sha256",
        "interaction_counts",
        "url_sha256",
        "method",
        "status",
        "resource_type",
        "error_code",
        "value_sha256",
        "value_byte_length",
        "readback_sha256",
        "readback_byte_length",
        "file_name_sha256",
        "file_size",
        "mime_type",
        "checked",
        "selected",
    }
)

RELEASE_REQUIRED_ROLES = frozenset(
    {
        "vacancy.source_identity",
        "vacancy.capture",
        "vacancy.structured",
        "vacancy.assessment",
        "document.cv.source",
        "document.source_inputs",
        "document.cv.final_pdf",
        "document.cv.extracted_text",
        "document.cover_letter.source",
        "document.cover_letter.final_pdf",
        "document.cover_letter.extracted_text",
        "form.questions",
        "form.answers",
        "form.approved_field_mapping",
        "evidence.approved_claim_ids",
        "assurance.cv.receipt",
        "assurance.cover_letter.receipt",
        "assurance.semantic.receipt",
        "browser.prefill_snapshot",
        "browser.pre_submit_screenshot",
        "browser.pre_submit_state",
        "browser.upload_mapping",
        "provider.success_semantics",
        "provider.success_observation",
        "provider.success_authority",
        "production.identities",
    }
)

OUTCOME_VALUES = frozenset(
    {
        "submitted_success",
        "historical_submitted_success",
        "submitted_failure",
        "indeterminate",
        "blocked",
        "abandoned",
        "gate_rejected",
        "crashed",
        "timed_out",
    }
)
MAX_RELEASE_ARCHIVE_AGE = timedelta(hours=24)
SUBMIT_OUTCOMES = frozenset({"submitted_success", "submitted_failure", "indeterminate"})
NETWORK_UNAVAILABLE_VALUES = frozenset(
    {
        "not_preserved_in_legacy_record",
        "listener_not_started_before_boundary",
        "no_response_event_observed_after_listener_started",
    }
)

_SECRET_KEY = re.compile(
    r"(?:password|passwd|session(?:_?cookie)?|access_?token|refresh_?token|"
    r"one_?time_?code|otp|client_?secret|private_?key)",
    re.IGNORECASE,
)
_SECRET_TEXT = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(rb"(?i)(?:set-)?cookie\s*:\s*[^\r\n]{8,}"),
    re.compile(rb"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"),
)


class ApplicationArchiveError(ValueError):
    """The attempt archive is incomplete, unsafe, or internally inconsistent."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_bytes(document: object) -> bytes:
    return (canonical_json(document) + "\n").encode("utf-8")


def release_upload_mapping_bytes(
    cv_pdf_sha256: str,
    cover_letter_pdf_sha256: str,
    *,
    attached_roles: Sequence[str] = ("cv", "cover_letter"),
    upload_field_names: Sequence[tuple[str, str]] | None = None,
) -> bytes:
    """Canonical non-secret browser attachment mapping archived before submit."""
    _digest(cv_pdf_sha256, "CV PDF hash")
    _digest(cover_letter_pdf_sha256, "cover-letter PDF hash")
    roles = tuple(attached_roles)
    supplied_field_names = tuple(
        upload_field_names
        if upload_field_names is not None
        else ((role, "resume" if role == "cv" else "cover_letter") for role in roles)
    )
    field_names = dict(supplied_field_names)
    if (
        not roles
        or len(set(roles)) != len(roles)
        or "cv" not in roles
        or not set(roles) <= {"cv", "cover_letter"}
        or set(field_names) != set(roles)
        or len(field_names) != len(supplied_field_names)
        or len(set(field_names.values())) != len(field_names)
        or any(
            not isinstance(value, str) or not value or value != value.strip()
            for value in field_names.values()
        )
    ):
        raise ApplicationArchiveError("release attachment roles are invalid")
    return _json_bytes(
        {
            "cv": {
                "role": "document.cv.final_pdf",
                "sha256": cv_pdf_sha256,
                "selected_for_upload": "cv" in roles,
                "input_identity": field_names.get("cv"),
            },
            "cover_letter": {
                "role": "document.cover_letter.final_pdf",
                "sha256": cover_letter_pdf_sha256,
                "selected_for_upload": "cover_letter" in roles,
                "input_identity": field_names.get("cover_letter"),
            },
        }
    )


def release_authority_selected_sha256(
    *,
    cv_pdf_bytes: bytes,
    cover_letter_pdf_bytes: bytes,
    answers_text: str,
    cv_assurance_document: Mapping[str, object],
    cover_letter_assurance_document: Mapping[str, object],
    semantic_assurance_document: Mapping[str, object],
    attached_roles: Sequence[str] = ("cv", "cover_letter"),
    upload_field_names: Sequence[tuple[str, str]] | None = None,
    approved_form_mapping: bytes | None = None,
    provider_success_semantics: bytes | None = None,
    provider_success_observation_sha256: str | None = None,
    provider_success_authority: bytes | None = None,
) -> dict[str, str]:
    """Critical selected-object hashes independently rebound at authority use."""
    result = {
        "document.cv.final_pdf": _sha256(cv_pdf_bytes),
        "document.cover_letter.final_pdf": _sha256(cover_letter_pdf_bytes),
        "form.answers": _sha256(answers_text.encode("utf-8")),
        "assurance.cv.receipt": _sha256(_json_bytes(cv_assurance_document)),
        "assurance.cover_letter.receipt": _sha256(
            _json_bytes(cover_letter_assurance_document)
        ),
        "assurance.semantic.receipt": _sha256(_json_bytes(semantic_assurance_document)),
        "browser.upload_mapping": _sha256(
            release_upload_mapping_bytes(
                _sha256(cv_pdf_bytes),
                _sha256(cover_letter_pdf_bytes),
                attached_roles=attached_roles,
                upload_field_names=upload_field_names,
            )
        ),
    }
    if approved_form_mapping is not None:
        result["form.approved_field_mapping"] = _sha256(approved_form_mapping)
    if provider_success_semantics is not None:
        result["provider.success_semantics"] = _sha256(provider_success_semantics)
    if provider_success_observation_sha256 is not None:
        result["provider.success_observation"] = _digest(
            provider_success_observation_sha256,
            "provider success observation hash",
        )
    if provider_success_authority is not None:
        result["provider.success_authority"] = _sha256(provider_success_authority)
    return result


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ApplicationArchiveError(f"{label} must be lowercase SHA-256")
    return value


def _required_text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ApplicationArchiveError(
            f"{label} is required without surrounding whitespace"
        )
    return value


def _validate_relative_path(value: str) -> str:
    candidate = Path(value)
    if (
        not value
        or candidate.is_absolute()
        or ".." in candidate.parts
        or "." in candidate.parts
        or str(candidate) != value
    ):
        raise ApplicationArchiveError("archive path is not a canonical relative path")
    return value


def _no_secret_metadata(value: object, *, key: str = "") -> None:
    if key and _SECRET_KEY.search(key):
        raise ApplicationArchiveError("secret-bearing metadata keys cannot be archived")
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            if not isinstance(child_key, str):
                raise ApplicationArchiveError("archive metadata keys must be strings")
            _no_secret_metadata(child, key=child_key)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _no_secret_metadata(child)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise ApplicationArchiveError("archive metadata must be canonical JSON data")


def _scan_secret_bytes(value: bytes, media_type: str) -> None:
    if media_type.startswith("text/") or media_type in {
        "application/json",
        "application/x-ndjson",
        "application/xml",
    }:
        for pattern in _SECRET_TEXT:
            if pattern.search(value):
                raise ApplicationArchiveError("secret-like value cannot be archived")


def _terminal_required_roles(outcome: str) -> set[str]:
    required = {"vacancy.source_identity", "vacancy.capture", "submission.result"}
    if outcome in SUBMIT_OUTCOMES:
        required.update(
            {
                "submission.click_intent",
                "submission.reconciliation",
                "provider.success_semantics",
                "browser.post_submit_screenshot",
                "browser.post_submit_visible_text",
                "browser.redirect_http_evidence",
            }
        )
        if outcome == "submitted_success":
            required.add("submission.receipt")
    elif outcome == "historical_submitted_success":
        required.update(
            {"provider.confirmation_evidence", "browser.redirect_http_evidence"}
        )
    elif outcome == "blocked":
        required.update(
            {
                "technical.boundary",
                "browser.redirect_http_evidence",
            }
        )
    elif outcome == "gate_rejected":
        required.update(
            {
                "submission.click_cancelled",
                "browser.failed_screenshot",
                "browser.failed_visible_text",
                "browser.failed_state_evidence",
                "browser.redirect_http_evidence",
            }
        )
    return required


def _selected_object_bytes(
    objects: Sequence["ArchivedObject"],
    selected: Mapping[str, str],
    role: str,
    *,
    root: Path,
) -> bytes:
    digest = selected.get(role)
    matching = [row for row in objects if row.role == role and row.sha256 == digest]
    if len(matching) != 1:
        raise ApplicationArchiveError(f"terminal {role} evidence is ambiguous")
    return _regular_file_bytes(_safe_archive_path(root, matching[0].relative_path))


def _verify_reconciliation_evidence(
    value: bytes,
    *,
    vacancy: "VacancyArchiveIdentity",
    confirmation_url: str,
    click_intent_sha256: str,
    click_intent_recorded_at: datetime,
    post_submit_screenshot_sha256: str,
    post_submit_visible_text_sha256: str,
    network_evidence_sha256: str,
    outcome: str,
) -> None:
    try:
        document = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ApplicationArchiveError(
            "submission reconciliation evidence is invalid JSON"
        ) from exc
    if (
        not isinstance(document, Mapping)
        or value != _json_bytes(document)
        or document.get("schema_version") != "jaa.submission-reconciliation.v2"
        or document.get("provider") != "greenhouse"
        or document.get("job_key") != vacancy.job_key
        or document.get("vacancy_sha256") != vacancy.vacancy_sha256
        or document.get("application_url") != vacancy.source_url
        or document.get("confirmation_url") != confirmation_url
        or document.get("click_intent_sha256") != click_intent_sha256
        or document.get("network_evidence_sha256") != network_evidence_sha256
        or document.get("click_replay_attempted") is not False
        or document.get("conclusion") != outcome
    ):
        raise ApplicationArchiveError(
            "submission reconciliation identity is inconsistent"
        )
    try:
        checked_at = datetime.fromisoformat(
            str(document["checked_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ApplicationArchiveError(
            "submission reconciliation time is invalid"
        ) from exc
    provider_state = document.get("provider_state")
    email = document.get("confirmation_email")
    expected_application_id = vacancy.source_url.rstrip("/").rsplit("/", 1)[-1]
    if (
        checked_at.tzinfo is None
        or not isinstance(provider_state, Mapping)
        or not isinstance(provider_state.get("url"), str)
        or not isinstance(provider_state.get("title"), str)
        or provider_state.get("visible_text_sha256") != post_submit_visible_text_sha256
        or provider_state.get("screenshot_sha256") != post_submit_screenshot_sha256
        or type(provider_state.get("success_observed")) is not bool
        or not isinstance(email, Mapping)
        or email.get("provider") != "gmail"
        or type(email.get("checked")) is not bool
        or not isinstance(email.get("query"), Mapping)
        or email["query"].get("job_key") != vacancy.job_key
        or email["query"].get("application_id") != expected_application_id
        or email["query"].get("company_name_sha256")
        != _sha256(vacancy.company_name.encode())
        or email["query"].get("role_title_sha256")
        != _sha256(vacancy.role_title.encode())
    ):
        raise ApplicationArchiveError("submission reconciliation checks are incomplete")
    if email["checked"] is False:
        if (
            outcome != "submitted_success"
            or provider_state.get("success_observed") is not True
            or email.get("result") != "deferred_connector_verification"
            or email.get("verification_required") is not True
        ):
            raise ApplicationArchiveError(
                "deferred Gmail verification requires exact provider success"
            )
        try:
            not_before = datetime.fromisoformat(
                str(email["query"]["not_before"]).replace("Z", "+00:00")
            )
            not_after = datetime.fromisoformat(
                str(email["query"]["not_after"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError) as exc:
            raise ApplicationArchiveError(
                "deferred Gmail verification window is invalid"
            ) from exc
        if (
            not_before.tzinfo is None
            or not_after.tzinfo is None
            or not_before != click_intent_recorded_at
            or not_before > not_after
            or not_after > checked_at
        ):
            raise ApplicationArchiveError(
                "deferred Gmail verification window is inconsistent"
            )
        return
    if (
        email.get("schema_version") != "jaa.gmail-confirmation-evidence.v1"
        or not isinstance(email.get("collector_identity"), str)
        or not email["collector_identity"]
        or "/example/jobs/" not in vacancy.source_url
        and not re.fullmatch(
            r"jaa\.gmail-api-metadata-reconciler\.v1\+source-sha256:[0-9a-f]{64}",
            str(email["collector_identity"]),
        )
        or email.get("result") not in {"match", "no_match"}
        or not isinstance(email.get("matched_message_metadata"), list)
        or not isinstance(email.get("match_reasons"), list)
    ):
        raise ApplicationArchiveError("submission reconciliation checks are incomplete")
    try:
        email_checked_at = datetime.fromisoformat(
            str(email["checked_at"]).replace("Z", "+00:00")
        )
        not_before = datetime.fromisoformat(
            str(email["query"]["not_before"]).replace("Z", "+00:00")
        )
        not_after = datetime.fromisoformat(
            str(email["query"]["not_after"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ApplicationArchiveError(
            "submission reconciliation email window is invalid"
        ) from exc
    metadata = email["matched_message_metadata"]
    if (
        any(value.tzinfo is None for value in (email_checked_at, not_before, not_after))
        or not_before != click_intent_recorded_at
        or not_before > email_checked_at
        or email_checked_at > not_after
        or (email["result"] == "match") is not bool(metadata)
        or email["result"] == "match"
        and set(email["match_reasons"])
        != {
            "positive_confirmation",
            "provider_sender",
            "vacancy_identity",
            "post_intent_time",
        }
        or email["result"] == "no_match"
        and bool(email["match_reasons"])
    ):
        raise ApplicationArchiveError(
            "submission reconciliation email result is inconsistent"
        )
    if "/example/jobs/" not in vacancy.source_url:
        query_receipt = email.get("query_receipt")
        collector_source_sha256 = str(email["collector_identity"]).rsplit(":", 1)[-1]
        events = (
            query_receipt.get("events") if isinstance(query_receipt, Mapping) else None
        )
        if (
            not isinstance(query_receipt, Mapping)
            or query_receipt.get("schema_version") != "jaa.gmail-api-query-receipt.v1"
            or query_receipt.get("collector_source_sha256") != collector_source_sha256
            or query_receipt.get("job_key_sha256") != _sha256(vacancy.job_key.encode())
            or query_receipt.get("application_id_sha256")
            != _sha256(expected_application_id.encode())
            or query_receipt.get("company_name_sha256")
            != _sha256(vacancy.company_name.encode())
            or query_receipt.get("role_title_sha256")
            != _sha256(vacancy.role_title.encode())
            or query_receipt.get("not_before") != not_before.isoformat()
            or query_receipt.get("not_after") != not_after.isoformat()
            or not isinstance(events, list)
            or not events
        ):
            raise ApplicationArchiveError(
                "submission reconciliation Gmail query receipt is invalid"
            )
        for index, event in enumerate(events):
            if (
                not isinstance(event, Mapping)
                or set(event)
                != {
                    "path",
                    "parameters_sha256",
                    "request_url_sha256",
                    "response_sha256",
                    "response_byte_length",
                }
                or not isinstance(event.get("path"), str)
                or index == 0
                and event["path"] != "messages"
                or index > 0
                and not re.fullmatch(r"messages/[0-9a-f]{64}", str(event["path"]))
                or not HEX_64.fullmatch(str(event.get("parameters_sha256", "")))
                or not HEX_64.fullmatch(str(event.get("request_url_sha256", "")))
                or not HEX_64.fullmatch(str(event.get("response_sha256", "")))
                or type(event.get("response_byte_length")) is not int
                or event["response_byte_length"] <= 0
            ):
                raise ApplicationArchiveError(
                    "submission reconciliation Gmail query event is invalid"
                )
    for row in metadata:
        if (
            not isinstance(row, Mapping)
            or set(row)
            != {
                "message_id_sha256",
                "received_at",
                "sender_domain",
                "subject_sha256",
            }
            or not HEX_64.fullmatch(str(row.get("message_id_sha256", "")))
            or not HEX_64.fullmatch(str(row.get("subject_sha256", "")))
            or not isinstance(row.get("sender_domain"), str)
            or not row["sender_domain"]
        ):
            raise ApplicationArchiveError(
                "submission reconciliation email metadata is invalid"
            )
        try:
            received_at = datetime.fromisoformat(
                str(row["received_at"]).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ApplicationArchiveError(
                "submission reconciliation email metadata time is invalid"
            ) from exc
        if received_at.tzinfo is None or not not_before <= received_at <= not_after:
            raise ApplicationArchiveError(
                "submission reconciliation email metadata is outside the query window"
            )
    positive = provider_state["success_observed"] is True or email["result"] == "match"
    if provider_state["success_observed"] is True and (
        provider_state["url"] != document["confirmation_url"]
        or not provider_state["title"].strip()
    ):
        raise ApplicationArchiveError(
            "provider success is not bound to the observed confirmation state"
        )
    if (outcome == "submitted_success") is not positive:
        raise ApplicationArchiveError(
            "submission reconciliation conclusion differs from observed evidence"
        )


def _verify_terminal_evidence(
    outcome: str,
    objects: Sequence["ArchivedObject"],
    selected: Mapping[str, str],
    *,
    root: Path,
    vacancy: "VacancyArchiveIdentity",
) -> None:
    missing = sorted(_terminal_required_roles(outcome) - set(selected))
    if outcome == "blocked" and not (
        {"browser.blocked_state_evidence", "provider.success_observation"}
        & set(selected)
    ):
        missing.append("browser.blocked_state_evidence|provider.success_observation")
    if missing:
        raise ApplicationArchiveError(
            "terminal archive is missing roles: " + ", ".join(missing)
        )
    if outcome in SUBMIT_OUTCOMES:
        success_semantics_value = _selected_object_bytes(
            objects, selected, "provider.success_semantics", root=root
        )
        try:
            success_semantics = json.loads(success_semantics_value)
        except json.JSONDecodeError as exc:
            raise ApplicationArchiveError(
                "provider success semantics are invalid JSON"
            ) from exc
        if (
            not isinstance(success_semantics, Mapping)
            or success_semantics_value != _json_bytes(success_semantics)
            or success_semantics.get("schema_version")
            != "jaa.greenhouse-success-evidence.v1"
            or not isinstance(success_semantics.get("confirmation_url"), str)
            or not str(success_semantics["confirmation_url"]).startswith("https://")
        ):
            raise ApplicationArchiveError("provider success semantics are malformed")
        confirmation_url = str(success_semantics["confirmation_url"])
        click_intent_value = _selected_object_bytes(
            objects, selected, "submission.click_intent", root=root
        )
        try:
            click_intent = json.loads(click_intent_value)
        except json.JSONDecodeError as exc:
            raise ApplicationArchiveError("click intent is invalid JSON") from exc
        if (
            not isinstance(click_intent, Mapping)
            or click_intent_value != _json_bytes(click_intent)
            or click_intent.get("provider") != "greenhouse"
            or click_intent.get("application_url") != vacancy.source_url
            or click_intent.get("confirmation_url") != confirmation_url
            or not HEX_64.fullmatch(
                str(click_intent.get("release_manifest_sha256", ""))
            )
            or not HEX_64.fullmatch(
                str(click_intent.get("archive_manifest_sha256", ""))
            )
        ):
            raise ApplicationArchiveError("click intent identity is inconsistent")
        try:
            recorded_at = datetime.fromisoformat(
                str(click_intent["recorded_at"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError) as exc:
            raise ApplicationArchiveError("click intent time is invalid") from exc
        if recorded_at.tzinfo is None:
            raise ApplicationArchiveError("click intent time is invalid")
    network_hash = selected.get("browser.redirect_http_evidence")
    if network_hash is None:
        return
    value = _selected_object_bytes(
        objects, selected, "browser.redirect_http_evidence", root=root
    )
    try:
        document = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ApplicationArchiveError(
            "terminal network evidence is invalid JSON"
        ) from exc
    events = document.get("events") if isinstance(document, Mapping) else None
    if (
        value != _json_bytes(document)
        or document.get("schema_version") != "jaa.browser-http-evidence.v1"
        or not isinstance(events, list)
    ):
        raise ApplicationArchiveError("terminal network evidence is malformed")
    if (
        outcome in SUBMIT_OUTCOMES
        and document.get("capture_phase") != "after_click_intent"
    ):
        raise ApplicationArchiveError(
            "submitted terminal network evidence lacks post-intent provenance"
        )
    if outcome in SUBMIT_OUTCOMES:
        _verify_reconciliation_evidence(
            _selected_object_bytes(
                objects, selected, "submission.reconciliation", root=root
            ),
            vacancy=vacancy,
            confirmation_url=confirmation_url,
            click_intent_sha256=selected["submission.click_intent"],
            click_intent_recorded_at=recorded_at,
            post_submit_screenshot_sha256=selected["browser.post_submit_screenshot"],
            post_submit_visible_text_sha256=selected[
                "browser.post_submit_visible_text"
            ],
            network_evidence_sha256=selected["browser.redirect_http_evidence"],
            outcome=outcome,
        )
    if not events:
        if outcome in SUBMIT_OUTCOMES:
            return
        if document.get("availability") not in NETWORK_UNAVAILABLE_VALUES:
            raise ApplicationArchiveError(
                "empty terminal network evidence lacks an availability reason"
            )
        return
    vacancy_url = urlsplit(vacancy.source_url)
    vacancy_path = vacancy_url.path.rstrip("/")
    vacancy_identifiers = set(
        re.findall(
            r"(?<![A-Za-z0-9])[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}(?![A-Za-z0-9])|(?<![0-9])[0-9]{6,18}(?![0-9])",
            f"{vacancy.job_key}\n{vacancy.source_url}",
        )
    )
    relevant = False
    action_bound = False
    greenhouse_submit_hosts = {
        "boards.greenhouse.io",
        "boards.eu.greenhouse.io",
    }
    for event in events:
        if (
            not isinstance(event, Mapping)
            or not isinstance(event.get("url"), str)
            or not str(event["url"]).startswith(("https://", "http://"))
            or not isinstance(event.get("status"), int)
            or isinstance(event.get("status"), bool)
            or not 100 <= int(event["status"]) <= 599
            or not isinstance(event.get("method"), str)
            or not event["method"]
        ):
            raise ApplicationArchiveError("terminal network event is malformed")
        event_url = urlsplit(str(event["url"]))
        same_route = event_url.hostname == vacancy_url.hostname and (
            event_url.path.rstrip("/") == vacancy_path
            or event_url.path.rstrip("/").startswith(vacancy_path + "/")
        )
        identifier_bound = any(
            re.search(
                rf"(?<![A-Za-z0-9]){re.escape(identifier)}(?![A-Za-z0-9])",
                str(event["url"]),
                re.IGNORECASE,
            )
            for identifier in vacancy_identifiers
        )
        relevant = relevant or same_route or identifier_bound
        if outcome in SUBMIT_OUTCOMES:
            method = str(event["method"]).upper()
            event_path = event_url.path.rstrip("/")
            confirmation_route = (
                event_url.hostname == vacancy_url.hostname
                and event_path == vacancy_path + "/confirmation"
                and method == "GET"
                and 200 <= int(event["status"]) < 400
            )
            provider_submit = (
                event_url.hostname in greenhouse_submit_hosts
                and event_path == vacancy_path
                and method == "POST"
                and 200 <= int(event["status"]) < 400
            )
            action_bound = action_bound or confirmation_route or provider_submit
    if not relevant:
        raise ApplicationArchiveError(
            "terminal network evidence is unrelated to the vacancy"
        )
    if outcome in SUBMIT_OUTCOMES and not action_bound:
        raise ApplicationArchiveError(
            "terminal network evidence is not bound to a submit or confirmation action"
        )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _regular_file_bytes(path: Path) -> bytes:
    if path.is_symlink():
        raise ApplicationArchiveError("archive files cannot be symlinks")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ApplicationArchiveError(
            f"archive file is unavailable: {path.name}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ApplicationArchiveError("archive entry is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            value = handle.read()
        final = os.fstat(descriptor)
        if (
            len(value) != metadata.st_size
            or final.st_size != metadata.st_size
            or final.st_mtime_ns != metadata.st_mtime_ns
            or final.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise ApplicationArchiveError("archive file changed while being verified")
        return value
    finally:
        os.close(descriptor)


def _atomic_create(path: Path, value: bytes, *, mode: int = 0o600) -> None:
    """Create ``path`` without any overwrite window and fsync its directory."""
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            raise
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_create_or_verify(path: Path, value: bytes, *, mode: int = 0o600) -> None:
    """Recover a crash after a create, but never accept different bytes."""
    try:
        _atomic_create(path, value, mode=mode)
    except FileExistsError:
        if _regular_file_bytes(path) != value:
            raise ApplicationArchiveError(
                f"existing immutable archive file differs: {path.name}"
            )


@dataclass(frozen=True)
class VacancyArchiveIdentity:
    job_key: str
    vacancy_sha256: str
    role_title: str
    company_name: str
    source_url: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.job_key, "job key"),
            (self.role_title, "role title"),
            (self.company_name, "company name"),
            (self.source_url, "source URL"),
        ):
            _required_text(value, label)
        _digest(self.vacancy_sha256, "vacancy hash")
        if not re.match(r"^https?://[^\s]+$", self.source_url):
            raise ApplicationArchiveError("vacancy source URL must be HTTP(S)")

    def document(self) -> dict[str, str]:
        return {
            "job_key": self.job_key,
            "vacancy_sha256": self.vacancy_sha256,
            "role_title": self.role_title,
            "company_name": self.company_name,
            "source_url": self.source_url,
        }


@dataclass(frozen=True)
class ArchivedObject:
    role: str
    sha256: str
    relative_path: str
    media_type: str
    byte_length: int
    created_at: str
    lineage: tuple[str, ...]
    disposition: str
    metadata: Mapping[str, object]
    event_sha256: str

    def __post_init__(self) -> None:
        if not ROLE.fullmatch(self.role):
            raise ApplicationArchiveError("archive object role is invalid")
        _digest(self.sha256, "object hash")
        _digest(self.event_sha256, "event hash")
        _validate_relative_path(self.relative_path)
        if not MEDIA_TYPE.fullmatch(self.media_type):
            raise ApplicationArchiveError("archive object media type is invalid")
        if self.byte_length < 0:
            raise ApplicationArchiveError("archive object length cannot be negative")
        for parent in self.lineage:
            _digest(parent, "lineage hash")
        if self.disposition not in {"generated", "approved", "rejected", "observed"}:
            raise ApplicationArchiveError("archive object disposition is invalid")
        _no_secret_metadata(self.metadata)

    def document(self) -> dict[str, object]:
        return {
            "role": self.role,
            "sha256": self.sha256,
            "relative_path": self.relative_path,
            "media_type": self.media_type,
            "byte_length": self.byte_length,
            "created_at": self.created_at,
            "lineage": list(self.lineage),
            "disposition": self.disposition,
            "metadata": dict(self.metadata),
            "event_sha256": self.event_sha256,
        }


@dataclass(frozen=True)
class ApplicationArchiveReceipt:
    attempt_id: str
    vacancy: VacancyArchiveIdentity
    manifest_relative_path: str
    manifest_sha256: str
    event_head_sha256: str
    object_count: int
    finalized_at: str
    receipt_sha256: str
    phase: str = "release"
    schema_version: str = RECEIPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA_VERSION or self.phase != "release":
            raise ApplicationArchiveError("archive receipt is not release authority")
        if not ATTEMPT_ID.fullmatch(self.attempt_id):
            raise ApplicationArchiveError("archive receipt attempt ID is invalid")
        if not isinstance(self.vacancy, VacancyArchiveIdentity):
            raise ApplicationArchiveError("archive receipt vacancy is invalid")
        _validate_relative_path(self.manifest_relative_path)
        for value, label in (
            (self.manifest_sha256, "manifest hash"),
            (self.event_head_sha256, "event head hash"),
            (self.receipt_sha256, "receipt hash"),
        ):
            _digest(value, label)
        if self.object_count < len(RELEASE_REQUIRED_ROLES):
            raise ApplicationArchiveError("archive receipt object count is incomplete")
        if self.receipt_sha256 != _sha256(_json_bytes(self.document(False))):
            raise ApplicationArchiveError("archive receipt identity is invalid")

    def document(self, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "phase": self.phase,
            "attempt_id": self.attempt_id,
            "vacancy": self.vacancy.document(),
            "manifest_relative_path": self.manifest_relative_path,
            "manifest_sha256": self.manifest_sha256,
            "event_head_sha256": self.event_head_sha256,
            "object_count": self.object_count,
            "finalized_at": self.finalized_at,
        }
        if include_identity:
            result["receipt_sha256"] = self.receipt_sha256
        return result


def _receipt_from_document(document: Mapping[str, object]) -> ApplicationArchiveReceipt:
    try:
        vacancy = document["vacancy"]
        if not isinstance(vacancy, Mapping):
            raise TypeError
        return ApplicationArchiveReceipt(
            attempt_id=str(document["attempt_id"]),
            vacancy=VacancyArchiveIdentity(
                job_key=str(vacancy["job_key"]),
                vacancy_sha256=str(vacancy["vacancy_sha256"]),
                role_title=str(vacancy["role_title"]),
                company_name=str(vacancy["company_name"]),
                source_url=str(vacancy["source_url"]),
            ),
            manifest_relative_path=str(document["manifest_relative_path"]),
            manifest_sha256=str(document["manifest_sha256"]),
            event_head_sha256=str(document["event_head_sha256"]),
            object_count=int(document["object_count"]),
            finalized_at=str(document["finalized_at"]),
            receipt_sha256=str(document["receipt_sha256"]),
            phase=str(document["phase"]),
            schema_version=str(document["schema_version"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ApplicationArchiveError("archive receipt is malformed") from exc


class ApplicationArchive:
    """One configured archive root, with create-only attempts and objects."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        repository_root: str | Path,
        create: bool = True,
    ) -> None:
        configured = Path(
            root
            if root is not None
            else os.environ.get(ARCHIVE_ROOT_ENV, str(DEFAULT_ARCHIVE_ROOT))
        )
        if not configured.is_absolute():
            raise ApplicationArchiveError("application archive root must be absolute")
        repository = Path(repository_root).resolve(strict=True)
        if not repository.is_dir():
            raise ApplicationArchiveError("repository root must be a directory")
        if configured.is_symlink():
            raise ApplicationArchiveError(
                "application archive root cannot be a symlink"
            )
        parent = configured.parent.resolve(strict=True)
        resolved = parent / configured.name
        if (
            resolved == repository
            or resolved in repository.parents
            or repository in resolved.parents
        ):
            raise ApplicationArchiveError(
                "application archive must be outside the Git worktree"
            )
        if create:
            resolved.mkdir(mode=0o700, parents=False, exist_ok=True)
        if (
            not resolved.is_dir()
            or resolved.is_symlink()
            or resolved.resolve(strict=True) != resolved
        ):
            raise ApplicationArchiveError(
                "application archive root is unavailable or unsafe"
            )
        os.chmod(resolved, 0o700)
        self.root = resolved
        self.repository_root = repository
        if create:
            for name in ("objects", "attempts"):
                path = self.root / name
                path.mkdir(mode=0o700, exist_ok=True)
                if path.is_symlink() or path.resolve(strict=True).parent != self.root:
                    raise ApplicationArchiveError("archive namespace is unsafe")

    def _attempt_path(self, attempt_id: str) -> Path:
        if not ATTEMPT_ID.fullmatch(attempt_id):
            raise ApplicationArchiveError("attempt ID is invalid")
        path = self.root / "attempts" / attempt_id
        if path.is_symlink():
            raise ApplicationArchiveError("attempt directory cannot be a symlink")
        return path

    def create_attempt(
        self,
        vacancy: VacancyArchiveIdentity,
        *,
        attempt_id: str | None = None,
        created_at: str | None = None,
    ) -> "AttemptArchive":
        if not isinstance(vacancy, VacancyArchiveIdentity):
            raise TypeError("attempt requires a vacancy identity")
        timestamp = created_at or _utc_now()
        if attempt_id is None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            attempt_id = f"jaa-{stamp}-{uuid.uuid4().hex[:16]}"
        path = self._attempt_path(attempt_id)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise ApplicationArchiveError("attempt identity already exists") from exc
        (path / "events").mkdir(mode=0o700)
        _fsync_directory(path.parent)
        attempt = AttemptArchive(self, attempt_id)
        attempt._append_event(
            "attempt_created",
            {"vacancy": vacancy.document(), "created_at": timestamp},
            occurred_at=timestamp,
        )
        return attempt

    def open_attempt(self, attempt_id: str) -> "AttemptArchive":
        path = self._attempt_path(attempt_id)
        if not path.is_dir():
            raise KeyError(attempt_id)
        attempt = AttemptArchive(self, attempt_id)
        attempt._events()
        return attempt

    def query(self, *, job_key: str | None = None) -> tuple[dict[str, object], ...]:
        rows: list[dict[str, object]] = []
        namespace = self.root / "attempts"
        for path in sorted(namespace.iterdir(), key=lambda item: item.name):
            if (
                path.is_symlink()
                or not path.is_dir()
                or not ATTEMPT_ID.fullmatch(path.name)
            ):
                raise ApplicationArchiveError(
                    "attempt namespace contains an unsafe entry"
                )
            attempt = self.open_attempt(path.name)
            vacancy = attempt.vacancy
            if job_key is not None and vacancy.job_key != job_key:
                continue
            rows.append(
                {
                    "attempt_id": path.name,
                    "vacancy": vacancy.document(),
                    "release_finalized": (path / "release-receipt.json").is_file(),
                    "terminal_finalized": (path / "terminal-manifest.json").is_file(),
                    "outcome": (
                        json.loads(
                            _regular_file_bytes(path / "terminal-manifest.json")
                        ).get("outcome")
                        if (path / "terminal-manifest.json").is_file()
                        else None
                    ),
                }
            )
        return tuple(rows)


class AttemptArchive:
    def __init__(self, archive: ApplicationArchive, attempt_id: str) -> None:
        self.archive = archive
        self.attempt_id = attempt_id
        self.path = archive._attempt_path(attempt_id)

    def _event_paths(self) -> tuple[Path, ...]:
        directory = self.path / "events"
        if directory.is_symlink() or not directory.is_dir():
            raise ApplicationArchiveError("attempt event ledger is unavailable")
        paths = tuple(sorted(directory.iterdir(), key=lambda item: item.name))
        for index, path in enumerate(paths, start=1):
            if (
                path.is_symlink()
                or not path.is_file()
                or path.name != f"{index:08d}.json"
            ):
                raise ApplicationArchiveError("attempt event ledger is not contiguous")
        return paths

    def _events(self) -> tuple[dict[str, object], ...]:
        result: list[dict[str, object]] = []
        previous = "0" * 64
        for index, path in enumerate(self._event_paths(), start=1):
            raw = _regular_file_bytes(path)
            try:
                document = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ApplicationArchiveError("attempt event is invalid JSON") from exc
            if not isinstance(document, dict) or raw != _json_bytes(document):
                raise ApplicationArchiveError("attempt event is not canonical JSON")
            identity = document.get("event_sha256")
            unsigned = dict(document)
            unsigned.pop("event_sha256", None)
            expected = _sha256(_json_bytes(unsigned))
            if (
                document.get("schema_version") != EVENT_SCHEMA_VERSION
                or document.get("attempt_id") != self.attempt_id
                or document.get("sequence") != index
                or document.get("previous_event_sha256") != previous
                or identity != expected
            ):
                raise ApplicationArchiveError("attempt event chain is invalid")
            result.append(document)
            previous = expected
        if not result or result[0].get("event_type") != "attempt_created":
            raise ApplicationArchiveError("attempt has no creation event")
        return tuple(result)

    @property
    def vacancy(self) -> VacancyArchiveIdentity:
        events = self._events()
        try:
            payload = events[0]["payload"]
            if not isinstance(payload, Mapping):
                raise TypeError
            value = payload["vacancy"]
            if not isinstance(value, Mapping):
                raise TypeError
            return VacancyArchiveIdentity(
                str(value["job_key"]),
                str(value["vacancy_sha256"]),
                str(value["role_title"]),
                str(value["company_name"]),
                str(value["source_url"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ApplicationArchiveError(
                "attempt vacancy identity is malformed"
            ) from exc

    def _append_event(
        self,
        event_type: str,
        payload: Mapping[str, object],
        *,
        occurred_at: str | None = None,
    ) -> dict[str, object]:
        _required_text(event_type, "event type")
        _no_secret_metadata(payload)
        events = self._events() if self._event_paths() else ()
        sequence = len(events) + 1
        previous = str(events[-1]["event_sha256"]) if events else "0" * 64
        unsigned: dict[str, object] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "attempt_id": self.attempt_id,
            "sequence": sequence,
            "event_type": event_type,
            "occurred_at": occurred_at or _utc_now(),
            "previous_event_sha256": previous,
            "payload": dict(payload),
        }
        document = {**unsigned, "event_sha256": _sha256(_json_bytes(unsigned))}
        _atomic_create(
            self.path / "events" / f"{sequence:08d}.json", _json_bytes(document)
        )
        return document

    def _object_path(self, digest: str) -> tuple[str, Path]:
        _digest(digest, "object hash")
        relative = f"objects/{digest[:2]}/{digest}"
        directory = self.archive.root / "objects" / digest[:2]
        directory.mkdir(mode=0o700, exist_ok=True)
        if (
            directory.is_symlink()
            or directory.resolve(strict=True).parent != self.archive.root / "objects"
        ):
            raise ApplicationArchiveError("object namespace is unsafe")
        return relative, directory / digest

    def add_artifact(
        self,
        role: str,
        value: bytes,
        *,
        media_type: str,
        lineage: Sequence[str] = (),
        disposition: str = "observed",
        metadata: Mapping[str, object] | None = None,
        created_at: str | None = None,
    ) -> ArchivedObject:
        if (self.path / "terminal-manifest.json").exists():
            raise ApplicationArchiveError("terminal attempt archive is immutable")
        if not ROLE.fullmatch(role):
            raise ApplicationArchiveError("archive object role is invalid")
        if not isinstance(value, bytes):
            raise TypeError("archive objects require exact bytes")
        if not MEDIA_TYPE.fullmatch(media_type):
            raise ApplicationArchiveError("archive object media type is invalid")
        clean_metadata = dict(metadata or {})
        _no_secret_metadata(clean_metadata)
        _scan_secret_bytes(value, media_type)
        parents = tuple(lineage)
        for parent in parents:
            _digest(parent, "lineage hash")
            _, parent_path = self._object_path(parent)
            if (
                not parent_path.is_file()
                or _sha256(_regular_file_bytes(parent_path)) != parent
            ):
                raise ApplicationArchiveError("artifact lineage object is unavailable")
        digest = _sha256(value)
        relative, path = self._object_path(digest)
        try:
            _atomic_create(path, value)
        except FileExistsError:
            if _regular_file_bytes(path) != value:
                raise ApplicationArchiveError("content-addressed object collision")
        if _sha256(_regular_file_bytes(path)) != digest:
            raise ApplicationArchiveError("object verification failed after write")
        timestamp = created_at or _utc_now()
        event = self._append_event(
            "artifact_archived",
            {
                "role": role,
                "sha256": digest,
                "relative_path": relative,
                "media_type": media_type,
                "byte_length": len(value),
                "created_at": timestamp,
                "lineage": list(parents),
                "disposition": disposition,
                "metadata": clean_metadata,
            },
            occurred_at=timestamp,
        )
        return ArchivedObject(
            role,
            digest,
            relative,
            media_type,
            len(value),
            timestamp,
            parents,
            disposition,
            clean_metadata,
            str(event["event_sha256"]),
        )

    def next_evidence_event_id(self, event_kind: str) -> str:
        """Return the next append-only event ID for this exact attempt."""
        if event_kind not in EVIDENCE_EVENT_KINDS:
            raise ApplicationArchiveError("evidence event kind is invalid")
        count = sum(
            event.get("event_type") == "evidence_recorded"
            for event in self._events()
        )
        return f"{event_kind}.{count + 1:04d}"

    def record_evidence_event(
        self,
        *,
        event_id: str,
        event_kind: str,
        occurred_at: str,
        result: str,
        member_sha256s: Mapping[str, str] | None = None,
        details: Mapping[str, object] | None = None,
        private_value: bytes | None = None,
        private_media_type: str = "application/octet-stream",
    ) -> str:
        """Append or exactly recover one closed, hash-only application action event."""
        if not EVIDENCE_EVENT_ID.fullmatch(event_id):
            raise ApplicationArchiveError("evidence event ID is invalid")
        if event_kind not in EVIDENCE_EVENT_KINDS:
            raise ApplicationArchiveError("evidence event kind is invalid")
        if result not in EVIDENCE_EVENT_RESULTS:
            raise ApplicationArchiveError("evidence event result is invalid")
        if not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?Z",
            occurred_at,
        ):
            raise ApplicationArchiveError("evidence event time must be canonical UTC Z")
        try:
            parsed = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ApplicationArchiveError("evidence event time is invalid") from exc
        if parsed.utcoffset() != timedelta(0):
            raise ApplicationArchiveError("evidence event time must be UTC")
        clean_details = dict(details or {})
        if set(clean_details) - EVIDENCE_DETAIL_KEYS:
            raise ApplicationArchiveError("evidence event detail keys are invalid")
        _no_secret_metadata(clean_details)
        members = dict(member_sha256s or {})
        for label, digest in members.items():
            if not ROLE.fullmatch(label):
                raise ApplicationArchiveError("evidence member role is invalid")
            _digest(digest, "evidence member hash")
        value_role = f"evidence.private.{event_id}"
        if private_value is not None:
            if not isinstance(private_value, bytes):
                raise TypeError("private evidence requires exact bytes")
            _scan_secret_bytes(private_value, private_media_type)
            digest = _sha256(private_value)
            existing = [
                row
                for row in self._objects(self._events())
                if row.role == value_role
            ]
            if existing:
                if len(existing) != 1 or existing[0].sha256 != digest:
                    raise ApplicationArchiveError("private evidence event bytes drifted")
                if _regular_file_bytes(
                    _safe_archive_path(self.archive.root, existing[0].relative_path)
                ) != private_value:
                    raise ApplicationArchiveError("private evidence object differs")
            else:
                self.add_artifact(
                    value_role,
                    private_value,
                    media_type=private_media_type,
                    disposition="observed",
                    metadata={"privacy_class": "private", "event_id": event_id},
                    created_at=occurred_at,
                )
            members[value_role] = digest
        object_hashes = {row.sha256 for row in self._objects(self._events())}
        if not set(members.values()) <= object_hashes:
            raise ApplicationArchiveError("evidence event cites an unavailable member")
        payload: dict[str, object] = {
            "event_id": event_id,
            "event_kind": event_kind,
            "result": result,
            "member_sha256s": dict(sorted(members.items())),
            "details": clean_details,
        }
        prior = [
            event
            for event in self._events()
            if event.get("event_type") == "evidence_recorded"
            and isinstance(event.get("payload"), Mapping)
            and event["payload"].get("event_id") == event_id
        ]
        if prior:
            if (
                len(prior) != 1
                or prior[0].get("payload") != payload
                or prior[0].get("occurred_at") != occurred_at
            ):
                raise ApplicationArchiveError("evidence event replay differs")
            return str(prior[0]["event_sha256"])
        if (self.path / "terminal-manifest.json").exists():
            raise ApplicationArchiveError("terminal attempt archive is immutable")
        return str(
            self._append_event(
                "evidence_recorded", payload, occurred_at=occurred_at
            )["event_sha256"]
        )

    def _objects(
        self, events: Iterable[Mapping[str, object]]
    ) -> tuple[ArchivedObject, ...]:
        rows: list[ArchivedObject] = []
        for event in events:
            if event.get("event_type") != "artifact_archived":
                continue
            payload = event.get("payload")
            if not isinstance(payload, Mapping):
                raise ApplicationArchiveError("artifact event payload is malformed")
            try:
                metadata = payload["metadata"]
                if not isinstance(metadata, Mapping):
                    raise TypeError
                rows.append(
                    ArchivedObject(
                        role=str(payload["role"]),
                        sha256=str(payload["sha256"]),
                        relative_path=str(payload["relative_path"]),
                        media_type=str(payload["media_type"]),
                        byte_length=int(payload["byte_length"]),
                        created_at=str(payload["created_at"]),
                        lineage=tuple(str(value) for value in payload["lineage"]),
                        disposition=str(payload["disposition"]),
                        metadata=dict(metadata),
                        event_sha256=str(event["event_sha256"]),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ApplicationArchiveError("artifact event is malformed") from exc
        return tuple(rows)

    def _validate_selection(
        self,
        objects: Sequence[ArchivedObject],
        selected: Mapping[str, str],
        required_roles: Iterable[str],
    ) -> dict[str, str]:
        chosen = dict(selected)
        missing = sorted(set(required_roles) - set(chosen))
        if missing:
            raise ApplicationArchiveError(
                f"release archive is missing roles: {', '.join(missing)}"
            )
        by_role_hash = {(row.role, row.sha256) for row in objects}
        for role, digest in chosen.items():
            if not ROLE.fullmatch(role):
                raise ApplicationArchiveError("selected archive role is invalid")
            _digest(digest, "selected object hash")
            if (role, digest) not in by_role_hash:
                raise ApplicationArchiveError(
                    "selected object does not match its archived role"
                )
        return dict(sorted(chosen.items()))

    def finalize_release(
        self,
        *,
        selected: Mapping[str, str],
        finalized_at: str | None = None,
    ) -> ApplicationArchiveReceipt:
        receipt_path = self.path / "release-receipt.json"
        if receipt_path.exists():
            receipt = _receipt_from_document(
                json.loads(_regular_file_bytes(receipt_path))
            )
            return verify_application_archive_receipt(
                receipt,
                root=self.archive.root,
                repository_root=self.archive.repository_root,
            )
        events = self._events()
        objects = self._objects(events)
        chosen = self._validate_selection(objects, selected, RELEASE_REQUIRED_ROLES)
        vacancy = self.vacancy
        timestamp = finalized_at or _utc_now()
        summary = (
            f"JAA application attempt {self.attempt_id}\n"
            f"Vacancy: {vacancy.role_title} at {vacancy.company_name}\n"
            f"Job key: {vacancy.job_key}\n"
            f"Vacancy SHA-256: {vacancy.vacancy_sha256}\n"
            f"Release objects: {len(objects)}\n"
            f"Finalized: {timestamp}\n"
        ).encode("utf-8")
        summary_path = self.path / "release-summary.txt"
        _atomic_create_or_verify(summary_path, summary)
        summary_hash = _sha256(_regular_file_bytes(summary_path))
        event_head = str(events[-1]["event_sha256"])
        manifest_relative = f"attempts/{self.attempt_id}/release-manifest.json"
        manifest = {
            "schema_version": ARCHIVE_SCHEMA_VERSION,
            "phase": "release",
            "attempt_id": self.attempt_id,
            "vacancy": vacancy.document(),
            "event_count": len(events),
            "event_head_sha256": event_head,
            "objects": [row.document() for row in objects],
            "selected": chosen,
            "summary": {
                "relative_path": f"attempts/{self.attempt_id}/release-summary.txt",
                "media_type": "text/plain",
                "byte_length": len(summary),
                "sha256": summary_hash,
            },
            "finalized_at": timestamp,
        }
        manifest_bytes = _json_bytes(manifest)
        manifest_path = self.path / "release-manifest.json"
        _atomic_create(manifest_path, manifest_bytes)
        manifest_hash = _sha256(_regular_file_bytes(manifest_path))
        receipt_document = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "phase": "release",
            "attempt_id": self.attempt_id,
            "vacancy": vacancy.document(),
            "manifest_relative_path": manifest_relative,
            "manifest_sha256": manifest_hash,
            "event_head_sha256": event_head,
            "object_count": len(objects),
            "finalized_at": timestamp,
        }
        receipt = ApplicationArchiveReceipt(
            self.attempt_id,
            vacancy,
            manifest_relative,
            manifest_hash,
            event_head,
            len(objects),
            timestamp,
            _sha256(_json_bytes(receipt_document)),
        )
        _atomic_create(receipt_path, _json_bytes(receipt.document()))
        return verify_application_archive_receipt(
            receipt,
            root=self.archive.root,
            repository_root=self.archive.repository_root,
        )

    def finalize_terminal(
        self,
        *,
        outcome: str,
        selected: Mapping[str, str],
        finalized_at: str | None = None,
    ) -> str:
        if outcome not in OUTCOME_VALUES:
            raise ApplicationArchiveError("attempt outcome is invalid")
        target = self.path / "terminal-manifest.json"
        if target.exists():
            verification = verify_complete_attempt(
                self.attempt_id,
                root=self.archive.root,
                repository_root=self.archive.repository_root,
            )
            if verification["outcome"] != outcome:
                raise ApplicationArchiveError(
                    "terminal attempt outcome cannot be changed"
                )
            return _sha256(_regular_file_bytes(target))
        events = self._events()
        objects = self._objects(events)
        required = _terminal_required_roles(outcome)
        if outcome in SUBMIT_OUTCOMES:
            if not (self.path / "release-receipt.json").is_file():
                raise ApplicationArchiveError(
                    "submitted attempt lacks release archive authority"
                )
        chosen = self._validate_selection(objects, selected, required)
        _verify_terminal_evidence(
            outcome,
            objects,
            chosen,
            root=self.archive.root,
            vacancy=self.vacancy,
        )
        timestamp = finalized_at or _utc_now()
        release_manifest_sha256 = (
            _sha256(_regular_file_bytes(self.path / "release-manifest.json"))
            if (self.path / "release-manifest.json").is_file()
            else None
        )
        summary = (
            f"JAA application attempt {self.attempt_id}\n"
            f"Vacancy: {self.vacancy.role_title} at {self.vacancy.company_name}\n"
            f"Job key: {self.vacancy.job_key}\n"
            f"Vacancy SHA-256: {self.vacancy.vacancy_sha256}\n"
            f"Outcome: {outcome}\n"
            f"Release manifest SHA-256: {release_manifest_sha256 or 'none'}\n"
            f"Terminal objects: {len(objects)}\n"
            f"Finalized: {timestamp}\n"
        ).encode("utf-8")
        summary_path = self.path / "terminal-summary.txt"
        _atomic_create_or_verify(summary_path, summary)
        manifest = {
            "schema_version": ARCHIVE_SCHEMA_VERSION,
            "phase": "terminal",
            "attempt_id": self.attempt_id,
            "vacancy": self.vacancy.document(),
            "outcome": outcome,
            "release_manifest_sha256": release_manifest_sha256,
            "event_count": len(events),
            "event_head_sha256": str(events[-1]["event_sha256"]),
            "objects": [row.document() for row in objects],
            "selected": chosen,
            "summary": {
                "relative_path": (f"attempts/{self.attempt_id}/terminal-summary.txt"),
                "media_type": "text/plain",
                "byte_length": len(summary),
                "sha256": _sha256(summary),
            },
            "finalized_at": timestamp,
        }
        _atomic_create(target, _json_bytes(manifest))
        return _sha256(_regular_file_bytes(target))


def _safe_archive_path(root: Path, relative: str) -> Path:
    _validate_relative_path(relative)
    candidate = root.joinpath(*Path(relative).parts)
    resolved_parent = candidate.parent.resolve(strict=True)
    if resolved_parent != root and root not in resolved_parent.parents:
        raise ApplicationArchiveError("archive path escapes its configured root")
    if candidate.is_symlink():
        raise ApplicationArchiveError("archive paths cannot be symlinks")
    return candidate


def verify_application_archive_receipt(
    receipt: ApplicationArchiveReceipt,
    *,
    root: str | Path | None,
    repository_root: str | Path,
    expected_vacancy: VacancyArchiveIdentity | None = None,
    expected_selected_sha256: Mapping[str, str] | None = None,
    verified_at: datetime | None = None,
) -> ApplicationArchiveReceipt:
    """Rehash the receipt, manifest, ledger and every referenced object."""
    if not isinstance(receipt, ApplicationArchiveReceipt):
        raise TypeError("release authority requires an ApplicationArchiveReceipt")
    receipt.__post_init__()
    if verified_at is not None:
        if verified_at.tzinfo is None or verified_at.utcoffset() is None:
            raise ApplicationArchiveError(
                "archive verification time must include a timezone"
            )
        try:
            finalized = datetime.fromisoformat(
                receipt.finalized_at.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ApplicationArchiveError(
                "archive finalization time is invalid"
            ) from exc
        if finalized.tzinfo is None or finalized.utcoffset() is None:
            raise ApplicationArchiveError("archive finalization time lacks a timezone")
        age = verified_at.astimezone(timezone.utc) - finalized.astimezone(timezone.utc)
        if age < timedelta(minutes=-5) or age > MAX_RELEASE_ARCHIVE_AGE:
            raise ApplicationArchiveError("application archive receipt is stale")
    archive = ApplicationArchive(root, repository_root=repository_root, create=False)
    if expected_vacancy is not None and receipt.vacancy != expected_vacancy:
        raise ApplicationArchiveError("archive receipt cites the wrong vacancy")
    attempt = archive.open_attempt(receipt.attempt_id)
    receipt_path = attempt.path / "release-receipt.json"
    stored_raw = _regular_file_bytes(receipt_path)
    try:
        stored_document = json.loads(stored_raw)
    except json.JSONDecodeError as exc:
        raise ApplicationArchiveError("stored archive receipt is invalid JSON") from exc
    if stored_raw != _json_bytes(stored_document):
        raise ApplicationArchiveError("stored archive receipt is not canonical")
    stored = _receipt_from_document(stored_document)
    if stored != receipt:
        raise ApplicationArchiveError("archive receipt differs from durable receipt")
    manifest_path = _safe_archive_path(archive.root, receipt.manifest_relative_path)
    manifest_raw = _regular_file_bytes(manifest_path)
    if _sha256(manifest_raw) != receipt.manifest_sha256:
        raise ApplicationArchiveError("archive manifest hash mismatch")
    try:
        manifest = json.loads(manifest_raw)
    except json.JSONDecodeError as exc:
        raise ApplicationArchiveError("archive manifest is invalid JSON") from exc
    if not isinstance(manifest, dict) or manifest_raw != _json_bytes(manifest):
        raise ApplicationArchiveError("archive manifest is not canonical")
    if (
        manifest.get("schema_version") != ARCHIVE_SCHEMA_VERSION
        or manifest.get("phase") != "release"
        or manifest.get("attempt_id") != receipt.attempt_id
        or manifest.get("vacancy") != receipt.vacancy.document()
        or manifest.get("event_head_sha256") != receipt.event_head_sha256
    ):
        raise ApplicationArchiveError("archive manifest identity is inconsistent")
    events = attempt._events()
    manifest_event_count = manifest.get("event_count")
    if not isinstance(manifest_event_count, int) or manifest_event_count < 1:
        raise ApplicationArchiveError("archive manifest event count is invalid")
    if len(events) < manifest_event_count:
        raise ApplicationArchiveError("archive event ledger was truncated")
    release_events = events[:manifest_event_count]
    if str(release_events[-1]["event_sha256"]) != receipt.event_head_sha256:
        raise ApplicationArchiveError("archive event ledger differs from manifest")
    raw_objects = manifest.get("objects")
    if not isinstance(raw_objects, list) or len(raw_objects) != receipt.object_count:
        raise ApplicationArchiveError("archive object inventory is incomplete")
    selected = manifest.get("selected")
    if not isinstance(selected, dict) or not RELEASE_REQUIRED_ROLES.issubset(selected):
        raise ApplicationArchiveError("archive selected-object inventory is incomplete")
    object_pairs: set[tuple[str, str]] = set()
    for raw in raw_objects:
        if not isinstance(raw, Mapping):
            raise ApplicationArchiveError("archive object row is malformed")
        try:
            metadata = raw["metadata"]
            if not isinstance(metadata, Mapping):
                raise TypeError
            row = ArchivedObject(
                str(raw["role"]),
                str(raw["sha256"]),
                str(raw["relative_path"]),
                str(raw["media_type"]),
                int(raw["byte_length"]),
                str(raw["created_at"]),
                tuple(str(value) for value in raw["lineage"]),
                str(raw["disposition"]),
                dict(metadata),
                str(raw["event_sha256"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ApplicationArchiveError("archive object row is malformed") from exc
        path = _safe_archive_path(archive.root, row.relative_path)
        value = _regular_file_bytes(path)
        if len(value) != row.byte_length or _sha256(value) != row.sha256:
            raise ApplicationArchiveError("archived object hash or length mismatch")
        object_pairs.add((row.role, row.sha256))
    for role, digest in selected.items():
        if (str(role), str(digest)) not in object_pairs:
            raise ApplicationArchiveError("selected archive object is missing")
    for role, expected in (expected_selected_sha256 or {}).items():
        _digest(expected, "expected selected hash")
        if selected.get(role) != expected:
            raise ApplicationArchiveError(f"archive selected bytes differ for {role}")
    summary = manifest.get("summary")
    if not isinstance(summary, Mapping):
        raise ApplicationArchiveError("archive human-readable summary is missing")
    summary_value = _regular_file_bytes(
        _safe_archive_path(archive.root, str(summary.get("relative_path", "")))
    )
    if len(summary_value) != summary.get("byte_length") or _sha256(
        summary_value
    ) != summary.get("sha256"):
        raise ApplicationArchiveError("archive summary differs from manifest")
    return receipt


def verify_complete_attempt(
    attempt_id: str,
    *,
    root: str | Path | None,
    repository_root: str | Path,
) -> dict[str, object]:
    """Verify release-only or terminal state, including a blocked attempt."""
    archive = ApplicationArchive(root, repository_root=repository_root, create=False)
    attempt = archive.open_attempt(attempt_id)
    release_receipt_path = attempt.path / "release-receipt.json"
    release_manifest_sha256: str | None = None
    if release_receipt_path.is_file():
        receipt_document = json.loads(_regular_file_bytes(release_receipt_path))
        receipt = _receipt_from_document(receipt_document)
        verify_application_archive_receipt(
            receipt,
            root=archive.root,
            repository_root=archive.repository_root,
        )
        release_manifest_sha256 = receipt.manifest_sha256
    terminal_path = attempt.path / "terminal-manifest.json"
    if not terminal_path.is_file():
        if release_manifest_sha256 is None:
            raise ApplicationArchiveError(
                "attempt is incomplete and has no final manifest"
            )
        return {
            "attempt_id": attempt_id,
            "phase": "release",
            "verified": True,
            "release_manifest_sha256": release_manifest_sha256,
            "terminal_manifest_sha256": None,
            "outcome": None,
        }
    terminal_raw = _regular_file_bytes(terminal_path)
    try:
        terminal = json.loads(terminal_raw)
    except json.JSONDecodeError as exc:
        raise ApplicationArchiveError("terminal manifest is invalid JSON") from exc
    if not isinstance(terminal, dict) or terminal_raw != _json_bytes(terminal):
        raise ApplicationArchiveError("terminal manifest is not canonical")
    events = attempt._events()
    objects = attempt._objects(events)
    if (
        terminal.get("schema_version") != ARCHIVE_SCHEMA_VERSION
        or terminal.get("phase") != "terminal"
        or terminal.get("attempt_id") != attempt_id
        or terminal.get("vacancy") != attempt.vacancy.document()
        or terminal.get("outcome") not in OUTCOME_VALUES
        or terminal.get("event_count") != len(events)
        or terminal.get("event_head_sha256") != events[-1]["event_sha256"]
        or terminal.get("release_manifest_sha256") != release_manifest_sha256
        or terminal.get("objects") != [row.document() for row in objects]
    ):
        raise ApplicationArchiveError("terminal manifest identity is inconsistent")
    object_pairs: set[tuple[str, str]] = set()
    for row in objects:
        value = _regular_file_bytes(_safe_archive_path(archive.root, row.relative_path))
        if len(value) != row.byte_length or _sha256(value) != row.sha256:
            raise ApplicationArchiveError("terminal object hash or length mismatch")
        object_pairs.add((row.role, row.sha256))
    selected = terminal.get("selected")
    if not isinstance(selected, Mapping):
        raise ApplicationArchiveError("terminal selected-object inventory is malformed")
    for role, digest in selected.items():
        if (str(role), str(digest)) not in object_pairs:
            raise ApplicationArchiveError("terminal selected object is missing")
    _verify_terminal_evidence(
        str(terminal["outcome"]),
        objects,
        selected,
        root=archive.root,
        vacancy=attempt.vacancy,
    )
    summary = terminal.get("summary")
    if not isinstance(summary, Mapping):
        raise ApplicationArchiveError("terminal human-readable summary is missing")
    summary_value = _regular_file_bytes(
        _safe_archive_path(archive.root, str(summary.get("relative_path", "")))
    )
    if len(summary_value) != summary.get("byte_length") or _sha256(
        summary_value
    ) != summary.get("sha256"):
        raise ApplicationArchiveError("terminal summary differs from manifest")
    return {
        "attempt_id": attempt_id,
        "phase": "terminal",
        "verified": True,
        "release_manifest_sha256": release_manifest_sha256,
        "terminal_manifest_sha256": _sha256(terminal_raw),
        "outcome": terminal["outcome"],
    }


def load_complete_attempt_view(
    attempt_id: str,
    *,
    root: str | Path | None,
    repository_root: str | Path,
) -> dict[str, object]:
    """Return a verified, hash-only view without exposing archived private bytes."""
    archive = ApplicationArchive(root, repository_root=repository_root, create=False)
    attempt = archive.open_attempt(attempt_id)
    if (attempt.path / "terminal-manifest.json").is_file() or (
        attempt.path / "release-receipt.json"
    ).is_file():
        verification = verify_complete_attempt(
            attempt_id, root=archive.root, repository_root=repository_root
        )
    else:
        verification = {
            "attempt_id": attempt_id,
            "phase": "open",
            "verified": True,
            "release_manifest_sha256": None,
            "terminal_manifest_sha256": None,
            "outcome": None,
        }
    events = attempt._events()
    objects = attempt._objects(events)
    evidence_events = []
    for event in events:
        if event.get("event_type") != "evidence_recorded":
            continue
        evidence_events.append(
            {
                "sequence": event["sequence"],
                "occurred_at": event["occurred_at"],
                "event_sha256": event["event_sha256"],
                "payload": event["payload"],
            }
        )
    object_rows = [
        {
            "role": row.role,
            "sha256": row.sha256,
            "media_type": row.media_type,
            "byte_length": row.byte_length,
            "created_at": row.created_at,
            "disposition": row.disposition,
            "metadata_sha256": _sha256(_json_bytes(dict(row.metadata))),
        }
        for row in objects
    ]
    roles = {row.role for row in objects}
    kinds = {
        str(event["payload"]["event_kind"])
        for event in evidence_events
        if isinstance(event.get("payload"), Mapping)
    }
    gaps = {
        "form_inventory": not any(role.startswith("form.") for role in roles),
        "entered_values": "form.answers" not in roles,
        "documents": not {
            "document.cv.final_pdf",
            "document.cover_letter.final_pdf",
        }.issubset(roles),
        "action_timeline": not {
            "field_filled",
            "file_uploaded",
            "navigation",
        }.issubset(kinds),
        "network_evidence": not any(
            "network" in role or "http_evidence" in role for role in roles
        ),
        "console_errors": "console_error" not in kinds,
        "terminal_state": verification["phase"] != "terminal",
    }
    return {
        "schema_version": EVIDENCE_VIEW_SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "vacancy": attempt.vacancy.document(),
        "verification": verification,
        "event_count": len(events),
        "event_head_sha256": events[-1]["event_sha256"],
        "evidence_events": evidence_events,
        "objects": object_rows,
        "gaps": gaps,
    }


def render_complete_attempt_view(
    attempt_id: str,
    *,
    root: str | Path | None,
    repository_root: str | Path,
) -> str:
    """Render verified machine data without raw values, paths, or document bytes."""
    view = load_complete_attempt_view(
        attempt_id, root=root, repository_root=repository_root
    )
    vacancy = view["vacancy"]
    verification = view["verification"]
    lines = [
        f"Application attempt: {view['attempt_id']}",
        f"Vacancy: {vacancy['role_title']} at {vacancy['company_name']}",
        f"Job key: {vacancy['job_key']}",
        f"Outcome: {verification['outcome'] or 'not-terminal'}",
        f"Events: {view['event_count']}",
        "Evidence objects:",
    ]
    for row in view["objects"]:
        lines.append(
            f"- {row['role']} {row['sha256']} ({row['byte_length']} bytes)"
        )
    lines.append("Evidence gaps:")
    for name, missing in sorted(view["gaps"].items()):
        lines.append(f"- {name}: {'MISSING' if missing else 'PRESENT'}")
    return "\n".join(lines) + "\n"


def export_application_packet(
    attempt_id: str,
    *,
    root: str | Path | None,
    repository_root: str | Path,
    destination: str | Path,
) -> Path:
    archive = ApplicationArchive(root, repository_root=repository_root, create=False)
    attempt = archive.open_attempt(attempt_id)
    verification = verify_complete_attempt(
        attempt_id,
        root=archive.root,
        repository_root=archive.repository_root,
    )
    target = Path(destination)
    if target.exists() or target.is_symlink():
        raise ApplicationArchiveError("export destination must not already exist")
    target.mkdir(mode=0o700, parents=False)
    try:
        manifest_name = (
            "terminal-manifest.json"
            if verification["phase"] == "terminal"
            else "release-manifest.json"
        )
        manifest = json.loads(_regular_file_bytes(attempt.path / manifest_name))
        packet = target / "objects"
        packet.mkdir(mode=0o700)
        used: dict[str, int] = {}
        for row in manifest["objects"]:
            role = str(row["role"])
            used[role] = used.get(role, 0) + 1
            suffix = {
                "application/pdf": ".pdf",
                "application/json": ".json",
                "text/plain": ".txt",
                "image/png": ".png",
            }.get(str(row["media_type"]), ".bin")
            name = f"{role}.{used[role]:03d}.{row['sha256'][:12]}{suffix}"
            source = _safe_archive_path(archive.root, str(row["relative_path"]))
            _atomic_create(packet / name, _regular_file_bytes(source))
        for name in (
            "release-manifest.json",
            "release-receipt.json",
            "release-summary.txt",
            "terminal-manifest.json",
            "terminal-summary.txt",
        ):
            source = attempt.path / name
            if source.is_file():
                _atomic_create(target / name, _regular_file_bytes(source))
        event_target = target / "events"
        event_target.mkdir(mode=0o700)
        for source in attempt._event_paths():
            _atomic_create(event_target / source.name, _regular_file_bytes(source))
        return target
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise


def selected_archive_object_bytes(
    receipt: ApplicationArchiveReceipt,
    role: str,
    *,
    root: str | Path | None,
    repository_root: str | Path,
) -> bytes:
    """Return one verified selected object without trusting caller paths."""
    verify_application_archive_receipt(
        receipt,
        root=root,
        repository_root=repository_root,
    )
    archive = ApplicationArchive(root, repository_root=repository_root, create=False)
    manifest = json.loads(
        _regular_file_bytes(
            _safe_archive_path(archive.root, receipt.manifest_relative_path)
        )
    )
    selected = manifest.get("selected")
    if not isinstance(selected, Mapping) or role not in selected:
        raise ApplicationArchiveError("selected archive role is unavailable")
    digest = str(selected[role])
    for row in manifest["objects"]:
        if row.get("role") == role and row.get("sha256") == digest:
            return _regular_file_bytes(
                _safe_archive_path(archive.root, str(row["relative_path"]))
            )
    raise ApplicationArchiveError("selected archive object is unavailable")


def selected_archive_hashes(
    receipt: ApplicationArchiveReceipt,
    *,
    root: str | Path | None,
    repository_root: str | Path,
) -> dict[str, str]:
    """Return the verified role-to-object selection from a release manifest."""
    verify_application_archive_receipt(
        receipt,
        root=root,
        repository_root=repository_root,
    )
    archive = ApplicationArchive(root, repository_root=repository_root, create=False)
    manifest = json.loads(
        _regular_file_bytes(
            _safe_archive_path(archive.root, receipt.manifest_relative_path)
        )
    )
    selected = manifest.get("selected")
    if not isinstance(selected, Mapping):
        raise ApplicationArchiveError("archive selection is malformed")
    return {str(role): str(digest) for role, digest in selected.items()}


def selected_terminal_object_bytes(
    attempt_id: str,
    role: str,
    *,
    root: str | Path | None,
    repository_root: str | Path,
) -> bytes:
    """Return one verified selected terminal object without trusting paths."""
    verification = verify_complete_attempt(
        attempt_id,
        root=root,
        repository_root=repository_root,
    )
    if verification["phase"] != "terminal":
        raise ApplicationArchiveError("attempt has no terminal object selection")
    archive = ApplicationArchive(root, repository_root=repository_root, create=False)
    attempt = archive.open_attempt(attempt_id)
    manifest = json.loads(_regular_file_bytes(attempt.path / "terminal-manifest.json"))
    selected = manifest.get("selected")
    if not isinstance(selected, Mapping) or role not in selected:
        raise ApplicationArchiveError("selected terminal archive role is unavailable")
    digest = str(selected[role])
    for row in manifest["objects"]:
        if row.get("role") == role and row.get("sha256") == digest:
            return _regular_file_bytes(
                _safe_archive_path(archive.root, str(row["relative_path"]))
            )
    raise ApplicationArchiveError("selected terminal archive object is unavailable")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m career_automation.application_archive"
    )
    parser.add_argument("--root", default=None)
    parser.add_argument("--repository-root", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    query = commands.add_parser("query")
    query.add_argument("--job-key")
    verify = commands.add_parser("verify")
    verify.add_argument("attempt_id")
    export = commands.add_parser("export")
    export.add_argument("attempt_id")
    export.add_argument("destination")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    archive = ApplicationArchive(
        arguments.root,
        repository_root=arguments.repository_root,
        create=False,
    )
    if arguments.command == "query":
        print(canonical_json(archive.query(job_key=arguments.job_key)))
        return 0
    if arguments.command == "verify":
        verification = verify_complete_attempt(
            arguments.attempt_id,
            root=archive.root,
            repository_root=archive.repository_root,
        )
        print(canonical_json(verification))
        return 0
    export_application_packet(
        arguments.attempt_id,
        root=archive.root,
        repository_root=archive.repository_root,
        destination=arguments.destination,
    )
    print(str(Path(arguments.destination).resolve()))
    return 0


if __name__ == "__main__":  # pragma: no cover
    try:
        raise SystemExit(main())
    except (ApplicationArchiveError, KeyError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from error


__all__ = [
    "ARCHIVE_ROOT_ENV",
    "DEFAULT_ARCHIVE_ROOT",
    "MAX_RELEASE_ARCHIVE_AGE",
    "RELEASE_REQUIRED_ROLES",
    "ApplicationArchive",
    "ApplicationArchiveError",
    "ApplicationArchiveReceipt",
    "ArchivedObject",
    "AttemptArchive",
    "VacancyArchiveIdentity",
    "export_application_packet",
    "release_authority_selected_sha256",
    "release_upload_mapping_bytes",
    "selected_archive_object_bytes",
    "selected_archive_hashes",
    "selected_terminal_object_bytes",
    "verify_application_archive_receipt",
    "verify_complete_attempt",
]
