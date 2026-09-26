"""Faceless internal JAA preparation and deterministic no-submit evidence."""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit

from market_aligner.processing import parse_eligibility_receipt

SCHEMA_VERSION = "market-aligner.internal-jaa.v1"
_IDS = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$", re.ASCII)
_JOB_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,255}$", re.ASCII)
_DIGEST = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FAILURES = frozenset({"identity_required", "unsupported_ats", "human_verification", "provider_timeout", "redirect_detected", "observation_indeterminate", "read_only_interaction_attempted"})
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$", re.ASCII)
_LEARNING_STAGES = frozenset({"ats_preflight", "capture", "improvement"})
_LEARNING_ISSUES = frozenset({"prepared", "blocked", "identity_required", "unsupported_ats", "human_verification", "provider_timeout"})
_LEARNING_SUMMARIES = frozenset({"observation_captured", "outcome_blocked", "improvement_required"})
_ATS_CONTROL_KINDS = frozenset({"text", "email", "tel", "url", "textarea", "number", "select", "radio", "checkbox", "file", "hidden"})
_ATS_AUTOMATION_ROLES = frozenset({"applicant", "honeypot", "provider_managed"})
_ATS_PROVIDERS = frozenset({"ashby", "fixture", "greenhouse", "personio", "recruitee", "workable"})
_ATS_CAPTURE_TIME = re.compile(r"^(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$", re.ASCII)
_OBSERVATION_SCHEMA = "market-aligner.read-only-ats-observation.v1"
_PUBLIC_OBSERVATION_SCHEMA = "market-aligner.public-read-only-ats-observation.v1"
_OBSERVATION_CHECKPOINT = "read_only_ats_observation"
_PRE_SUBMIT_CHECKPOINT = "fixture_pre_submit"
MARKET_OBSERVATION_KEY_ID = "market-observation-operator-2026-08-27"
MARKET_OBSERVATION_PUBLIC_DER_SHA256 = "1f852ff70c3e7faf34e75c89e2dca9f067a045927967d069ac2bc544dd0bff1e"
_OBSERVATION_ACCEPTANCE_SCHEMA = "market-aligner.ats-observation-acceptance.v1"
_OBSERVATION_ACCEPTANCE_RECEIPT_SCHEMA = "market-aligner.ats-observation-acceptance-receipt.v1"
_OBSERVATION_ACCEPTANCE_DIRECTORY = "observation-acceptance-consumptions"
_PUBLIC_OBSERVATION_ADMISSION_DIRECTORY = "public-observation-admissions"
_PUBLIC_OBSERVATION_ADMISSION_SCHEMA = "market-aligner.public-observation-admission.v1"
_ACCEPTANCE_NONCE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_READ_ONLY_ATTEMPTS = frozenset({
    "click", "cookie", "download", "fill", "network", "popup", "redirect",
    "storage", "submit", "type", "upload", "websocket",
})
_TEST_TLS_SPKI = re.compile(r"^[A-Za-z0-9+/]{43}=$", re.ASCII)

_READ_ONLY_GUARD_SCRIPT = """(() => {
  const attempts = [];
  const record = (name) => { attempts.push(name); throw new Error(`market-aligner-read-only:${name}`); };
  Object.defineProperty(window, '__marketAlignerReadOnly', {value: {attempts}, configurable: false});
  const blockMethod = (prototype, name, kind) => {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
    if (descriptor && typeof descriptor.value === 'function') Object.defineProperty(prototype, name, {...descriptor, value() { return record(kind); }});
  };
  const blockSetter = (prototype, name, kind) => {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
    if (descriptor && typeof descriptor.set === 'function') Object.defineProperty(prototype, name, {...descriptor, set() { return record(kind); }});
  };
  blockMethod(HTMLElement.prototype, 'click', 'click');
  blockMethod(HTMLFormElement.prototype, 'submit', 'submit');
  blockMethod(HTMLFormElement.prototype, 'requestSubmit', 'submit');
  blockMethod(EventTarget.prototype, 'dispatchEvent', 'click');
  blockSetter(HTMLInputElement.prototype, 'value', 'fill');
  blockSetter(HTMLInputElement.prototype, 'checked', 'fill');
  blockSetter(HTMLTextAreaElement.prototype, 'value', 'type');
  blockSetter(HTMLSelectElement.prototype, 'value', 'fill');
  blockSetter(HTMLSelectElement.prototype, 'selectedIndex', 'fill');
  blockSetter(HTMLInputElement.prototype, 'files', 'upload');
  const elementSetAttribute = Element.prototype.setAttribute;
  Object.defineProperty(Element.prototype, 'setAttribute', {value(name, value) {
    if (/^(?:value|checked|selected|files|action|formaction)$/i.test(String(name))) return record('fill');
    return elementSetAttribute.call(this, name, value);
  }});
  window.fetch = () => record('network');
  if (navigator.sendBeacon) navigator.sendBeacon = () => record('network');
  blockMethod(XMLHttpRequest.prototype, 'open', 'network');
  const socket = window.WebSocket;
  Object.defineProperty(window, 'WebSocket', {value: function() { void socket; return record('websocket'); }});
  Object.defineProperty(window, 'open', {value() { return record('popup'); }});
  const cookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  if (cookie) Object.defineProperty(Document.prototype, 'cookie', {get() { return ''; }, set() { return record('cookie'); }});
  for (const method of ['setItem', 'removeItem', 'clear']) blockMethod(Storage.prototype, method, 'storage');
  if (window.indexedDB) {
    window.indexedDB.open = () => record('storage');
    window.indexedDB.deleteDatabase = () => record('storage');
  }
  if (window.caches) {
    window.caches.open = () => record('storage');
    window.caches.delete = () => record('storage');
  }
})()"""

_ATS_BLOCKER_SCRIPT = """(elements) => ({
  password: elements.some((element) => element.matches && element.matches('input[type=password]')),
  captcha: elements.some((element) => {
    const text = `${element.getAttribute('src') || ''} ${element.getAttribute('title') || ''} ${element.textContent || ''}`.toLowerCase();
    return /captcha|turnstile|challenge|human verification/.test(text) && !!(element.offsetWidth || element.offsetHeight || element.getClientRects().length);
  }),
  login: elements.some((element) => /(?:sign|log)\\s*in|account\\s+required/i.test(element.textContent || '') && !!(element.offsetWidth || element.offsetHeight || element.getClientRects().length))
})"""

_ATS_INVENTORY_SCRIPT = """(elements) => elements.map((element, index) => {
  const tag = element.tagName.toLowerCase();
  const inputType = (element.getAttribute('type') || 'text').toLowerCase();
  const controlKind = tag === 'textarea' ? 'textarea' : (tag === 'select' ? 'select' : inputType);
  const fieldId = element.id || element.getAttribute('name') || '';
  const label = Array.from(element.labels || []).map((item) => (item.textContent || '').trim()).find(Boolean) || element.getAttribute('aria-label') || fieldId || `field-${index}`;
  const options = tag === 'select' ? Array.from(element.options || []).map((option) => ({value: option.value || option.textContent || '', label: (option.textContent || '').trim() || option.value || ''})) : ((controlKind === 'radio' || controlKind === 'checkbox') ? [{value: element.getAttribute('value') || fieldId, label}] : []);
  return {field_id: fieldId, control_kind: controlKind, label, required: Boolean(element.required) || element.getAttribute('aria-required') === 'true', visible: Boolean(element.offsetWidth || element.offsetHeight || element.getClientRects().length), disabled: Boolean(element.disabled), read_only: Boolean(element.readOnly), multiple: Boolean(element.multiple), options};
})"""


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDS.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"{label} must be an ASCII path-safe ID")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _job_key(value: object) -> str:
    if not isinstance(value, str) or not _JOB_KEY.fullmatch(value):
        raise ValueError("job key must use the canonical Market key grammar")
    return value


def _ats_text(value: object, label: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
        or "\r" in value
    ):
        raise ValueError(f"{label} must be bounded normalized text")
    return value


def _ats_time(value: object) -> str:
    if not isinstance(value, str) or not _ATS_CAPTURE_TIME.fullmatch(value):
        raise ValueError("ATS inventory capture time must be second-precision RFC3339 UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("ATS inventory capture time must be valid") from exc
    return value


@dataclass(frozen=True)
class AtsFieldOption:
    """A public choice descriptor; it carries no candidate answer."""

    value: str
    label: str

    def __post_init__(self) -> None:
        _ats_text(self.value, "ATS option value", maximum=2048)
        _ats_text(self.label, "ATS option label", maximum=2048)

    def document(self) -> dict[str, str]:
        return {"value": self.value, "label": self.label}


@dataclass(frozen=True)
class AtsObservedField:
    """Sanitized, value-free form shape observed at a public ATS route."""

    field_id: str
    control_kind: str
    label: str
    required: bool
    visible: bool
    automation_role: str = "applicant"
    disabled: bool = False
    read_only: bool = False
    multiple: bool = False
    options: tuple[AtsFieldOption, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", tuple(self.options))
        _ats_text(self.field_id, "ATS field ID", maximum=512)
        if self.control_kind not in _ATS_CONTROL_KINDS:
            raise ValueError("ATS control kind is unsupported")
        if self.automation_role not in _ATS_AUTOMATION_ROLES:
            raise ValueError("ATS automation role is unsupported")
        _ats_text(self.label, "ATS field label")
        for name in ("required", "visible", "disabled", "read_only", "multiple"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"ATS field {name} must be bool")
        if not all(type(option) is AtsFieldOption for option in self.options):
            raise TypeError("ATS options must use exact typed descriptors")
        values = [option.value for option in self.options]
        if len(values) != len(set(values)):
            raise ValueError("ATS option values must be unique")
        if self.options and self.control_kind not in {"select", "radio", "checkbox"}:
            raise ValueError("only choice controls may carry options")
        if self.multiple and self.control_kind not in {"file", "select", "checkbox"}:
            raise ValueError("ATS control cannot accept multiple values")
        if self.control_kind == "hidden":
            if self.visible or self.automation_role == "applicant":
                raise ValueError("hidden ATS controls require a non-applicant role")
        elif self.automation_role == "honeypot" and self.visible:
            raise ValueError("honeypot ATS controls cannot be visible")
        elif self.automation_role == "applicant" and (
            not self.visible or self.disabled or self.read_only
        ):
            raise ValueError("non-actionable ATS controls require a non-applicant role")
        elif self.automation_role == "provider_managed" and not (
            self.disabled or self.read_only
        ):
            raise ValueError("provider-managed ATS controls must be non-actionable")

    def document(self) -> dict[str, object]:
        return {
            "field_id": self.field_id,
            "control_kind": self.control_kind,
            "label": self.label,
            "required": self.required,
            "visible": self.visible,
            "automation_role": self.automation_role,
            "disabled": self.disabled,
            "read_only": self.read_only,
            "multiple": self.multiple,
            "options": [option.document() for option in self.options],
        }


@dataclass(frozen=True)
class AtsFormInventory:
    """Content-addressed, no-action form shape for a future protected adapter."""

    provider: str
    application_url: str
    captured_at: str
    page_snapshot_sha256: str
    screenshot_sha256s: tuple[str, ...]
    fields: tuple[AtsObservedField, ...]
    schema_version: str = "market-aligner.ats-form-inventory.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "screenshot_sha256s", tuple(self.screenshot_sha256s))
        object.__setattr__(self, "fields", tuple(self.fields))
        if self.schema_version != "market-aligner.ats-form-inventory.v1":
            raise ValueError("unsupported ATS inventory schema")
        if not isinstance(self.provider, str) or self.provider not in _ATS_PROVIDERS:
            raise ValueError("ATS provider is unsupported")
        parsed = urlsplit(_ats_text(self.application_url, "ATS application URL"))
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("ATS application URL must be a fragment-free HTTPS route")
        _ats_time(self.captured_at)
        _digest(self.page_snapshot_sha256, "ATS page snapshot SHA-256")
        if len(set(self.screenshot_sha256s)) != len(self.screenshot_sha256s):
            raise ValueError("ATS screenshot hashes must be unique")
        for digest in self.screenshot_sha256s:
            _digest(digest, "ATS screenshot SHA-256")
        if not self.fields or len(self.fields) > 512:
            raise ValueError("ATS inventory field count is outside policy")
        if not all(type(field) is AtsObservedField for field in self.fields):
            raise TypeError("ATS inventory requires exact typed fields")
        field_ids = [field.field_id for field in self.fields]
        if len(field_ids) != len(set(field_ids)):
            raise ValueError("ATS inventory field IDs must be unique")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "application_url": self.application_url,
            "captured_at": self.captured_at,
            "page_snapshot_sha256": self.page_snapshot_sha256,
            "screenshot_sha256s": list(self.screenshot_sha256s),
            "fields": [field.document() for field in self.fields],
            "diagnostic_only": True,
            "raw_payloads_persisted": False,
            "identity_authority": False,
            "release_authority": False,
            "submission_authority": False,
        }

    @property
    def content_sha256(self) -> str:
        return sha256(canonical_json(self.document()).encode())


def _observation_url(value: object) -> str:
    parsed = urlsplit(_ats_text(value, "ATS observation application URL"))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("ATS observation URL must be a canonical HTTPS route")
    host = parsed.hostname.casefold()
    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
    return urlunsplit(("https", netloc, parsed.path.rstrip("/") or "/", "", ""))


@dataclass(frozen=True)
class AtsObservationAuthority:
    """Content-addressed request descriptor, not public operator authorization.

    A public target additionally needs an externally authenticated capability
    verifier, which is deliberately not present in this faceless increment.
    """

    job_key: str
    application_url: str
    timeout_ms: int
    max_network_events: int
    max_snapshot_bytes: int
    authority_state: str
    local_fixture_only: bool
    authority_sha256: str
    schema_version: str = "market-aligner.ats-observation-authority.v1"
    diagnostic_only: bool = True
    raw_payloads_persisted: bool = False
    identity_authority: bool = False
    release_authority: bool = False
    submission_authority: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != "market-aligner.ats-observation-authority.v1":
            raise ValueError("ATS observation authority schema differs")
        _job_key(self.job_key)
        if _observation_url(self.application_url) != self.application_url:
            raise ValueError("ATS observation authority URL is non-canonical")
        for name in ("timeout_ms", "max_network_events", "max_snapshot_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65_536:
                raise ValueError(f"ATS observation authority {name} is outside policy")
        if self.authority_state not in {"pending", "accepted"}:
            raise ValueError("ATS observation authority state differs")
        for name in (
            "local_fixture_only", "diagnostic_only", "raw_payloads_persisted",
            "identity_authority", "release_authority", "submission_authority",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"ATS observation authority {name} must be bool")
        if self.diagnostic_only is not True or self.raw_payloads_persisted is not False or any(
            getattr(self, name) is not False
            for name in ("identity_authority", "release_authority", "submission_authority")
        ):
            raise ValueError("ATS observation authority exceeds read-only scope")
        _digest(self.authority_sha256, "ATS observation authority SHA-256")
        if self.authority_sha256 != sha256(canonical_json(self.document(include_hash=False)).encode()):
            raise ValueError("ATS observation authority identity differs")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        value = {
            "schema_version": self.schema_version,
            "job_key": self.job_key,
            "application_url": self.application_url,
            "timeout_ms": self.timeout_ms,
            "max_network_events": self.max_network_events,
            "max_snapshot_bytes": self.max_snapshot_bytes,
            "authority_state": self.authority_state,
            "local_fixture_only": self.local_fixture_only,
            "diagnostic_only": self.diagnostic_only,
            "raw_payloads_persisted": self.raw_payloads_persisted,
            "identity_authority": self.identity_authority,
            "release_authority": self.release_authority,
            "submission_authority": self.submission_authority,
        }
        if include_hash:
            value["authority_sha256"] = self.authority_sha256
        return value

    def require_local_fixture(self) -> None:
        if self.authority_state != "accepted" or self.local_fixture_only is not True:
            raise ValueError("ATS observation authority is not accepted for a local fixture")
        if urlsplit(self.application_url).hostname != "localhost":
            raise ValueError("local fixture authority must bind localhost exactly")


@dataclass(frozen=True)
class AtsObservationAcceptance:
    """Externally signed, observation-only acceptance for one public request."""

    acceptance_id: str
    nonce: str
    request_sha256: str
    consumption_root_sha256: str
    job_key: str
    application_url: str
    timeout_ms: int
    max_network_events: int
    max_snapshot_bytes: int
    not_before: str
    expires_at: str
    key_id: str
    signature_b64: str
    envelope_sha256: str
    schema_version: str = _OBSERVATION_ACCEPTANCE_SCHEMA
    read_only_navigation: bool = True
    sanitized_hash_only_evidence: bool = True
    login_authority: bool = False
    cookie_authority: bool = False
    identity_authority: bool = False
    vault_authority: bool = False
    fill_authority: bool = False
    upload_authority: bool = False
    click_authority: bool = False
    submission_authority: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != _OBSERVATION_ACCEPTANCE_SCHEMA:
            raise ValueError("ATS observation acceptance schema differs")
        _id(self.acceptance_id, "ATS observation acceptance ID")
        if not isinstance(self.nonce, str) or not _ACCEPTANCE_NONCE.fullmatch(self.nonce):
            raise ValueError("ATS observation acceptance nonce must be a lowercase SHA-256 value")
        _digest(self.request_sha256, "ATS observation request SHA-256")
        _digest(self.consumption_root_sha256, "ATS observation consumption root SHA-256")
        _job_key(self.job_key)
        if _observation_url(self.application_url) != self.application_url:
            raise ValueError("ATS observation acceptance URL is non-canonical")
        for name in ("timeout_ms", "max_network_events", "max_snapshot_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65_536:
                raise ValueError(f"ATS observation acceptance {name} is outside policy")
        for value in (self.not_before, self.expires_at):
            _ats_time(value)
        if datetime.strptime(self.not_before, "%Y-%m-%dT%H:%M:%SZ") >= datetime.strptime(
            self.expires_at, "%Y-%m-%dT%H:%M:%SZ"
        ):
            raise ValueError("ATS observation acceptance time window is empty")
        _id(self.key_id, "ATS observation acceptance key ID")
        exact = {
            "read_only_navigation": True,
            "sanitized_hash_only_evidence": True,
            "login_authority": False,
            "cookie_authority": False,
            "identity_authority": False,
            "vault_authority": False,
            "fill_authority": False,
            "upload_authority": False,
            "click_authority": False,
            "submission_authority": False,
        }
        if any(type(getattr(self, name)) is not bool for name in exact):
            raise TypeError("ATS observation acceptance authority fields must be bool")
        if any(getattr(self, name) is not value for name, value in exact.items()):
            raise ValueError("ATS observation acceptance exceeds read-only scope")
        if not isinstance(self.signature_b64, str):
            raise TypeError("ATS observation acceptance signature must be base64 text")
        try:
            signature = base64.b64decode(self.signature_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("ATS observation acceptance signature is malformed") from exc
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != self.signature_b64:
            raise ValueError("ATS observation acceptance signature is non-canonical")
        _digest(self.envelope_sha256, "ATS observation acceptance envelope SHA-256")
        if self.envelope_sha256 != sha256(canonical_json(self.document(include_hash=False)).encode()):
            raise ValueError("ATS observation acceptance envelope identity differs")

    def signed_document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "acceptance_id": self.acceptance_id,
            "nonce": self.nonce,
            "request_sha256": self.request_sha256,
            "consumption_root_sha256": self.consumption_root_sha256,
            "job_key": self.job_key,
            "application_url": self.application_url,
            "timeout_ms": self.timeout_ms,
            "max_network_events": self.max_network_events,
            "max_snapshot_bytes": self.max_snapshot_bytes,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
            "read_only_navigation": self.read_only_navigation,
            "sanitized_hash_only_evidence": self.sanitized_hash_only_evidence,
            "login_authority": self.login_authority,
            "cookie_authority": self.cookie_authority,
            "identity_authority": self.identity_authority,
            "vault_authority": self.vault_authority,
            "fill_authority": self.fill_authority,
            "upload_authority": self.upload_authority,
            "click_authority": self.click_authority,
            "submission_authority": self.submission_authority,
        }

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        value = self.signed_document() | {"signature_b64": self.signature_b64}
        if include_hash:
            value["envelope_sha256"] = self.envelope_sha256
        return value


@dataclass(frozen=True)
class AtsObservationAcceptanceReceipt:
    """Immutable proof that one signed acceptance nonce was consumed once."""

    acceptance_id: str
    nonce: str
    request_sha256: str
    envelope_sha256: str
    signature_sha256: str
    consumption_root_sha256: str
    job_key: str
    application_url: str
    timeout_ms: int
    max_network_events: int
    max_snapshot_bytes: int
    not_before: str
    expires_at: str
    key_id: str
    public_der_sha256: str
    consumed_at: str
    root_identity: tuple[int, int]
    store_identity: tuple[int, int]
    receipt_sha256: str
    schema_version: str = _OBSERVATION_ACCEPTANCE_RECEIPT_SCHEMA
    diagnostic_only: bool = True
    raw_payloads_persisted: bool = False
    identity_authority: bool = False
    vault_authority: bool = False
    release_authority: bool = False
    submission_authority: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != _OBSERVATION_ACCEPTANCE_RECEIPT_SCHEMA:
            raise ValueError("ATS observation acceptance receipt schema differs")
        _id(self.acceptance_id, "ATS observation acceptance ID")
        if not isinstance(self.nonce, str) or not _ACCEPTANCE_NONCE.fullmatch(self.nonce):
            raise ValueError("ATS observation acceptance receipt nonce differs")
        for name in (
            "request_sha256", "envelope_sha256", "signature_sha256",
            "consumption_root_sha256", "public_der_sha256",
        ):
            _digest(getattr(self, name), name)
        _job_key(self.job_key)
        if _observation_url(self.application_url) != self.application_url:
            raise ValueError("ATS observation acceptance receipt URL differs")
        for name in ("timeout_ms", "max_network_events", "max_snapshot_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65_536:
                raise ValueError(f"ATS observation acceptance receipt {name} differs")
        _ats_time(self.not_before)
        _ats_time(self.expires_at)
        if self.not_before >= self.expires_at:
            raise ValueError("ATS observation acceptance receipt time window differs")
        _id(self.key_id, "ATS observation acceptance key ID")
        _ats_time(self.consumed_at)
        for name in ("root_identity", "store_identity"):
            identity = getattr(self, name)
            if (
                not isinstance(identity, tuple)
                or len(identity) != 2
                or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in identity)
            ):
                raise ValueError(f"ATS observation acceptance {name.replace('_', ' ')} differs")
        exact = {
            "diagnostic_only": True,
            "raw_payloads_persisted": False,
            "identity_authority": False,
            "vault_authority": False,
            "release_authority": False,
            "submission_authority": False,
        }
        if any(type(getattr(self, name)) is not bool for name in exact):
            raise TypeError("ATS observation acceptance receipt authority fields must be bool")
        if any(getattr(self, name) is not value for name, value in exact.items()):
            raise ValueError("ATS observation acceptance receipt exceeds read-only scope")
        _digest(self.receipt_sha256, "ATS observation acceptance receipt SHA-256")
        if self.receipt_sha256 != sha256(canonical_json(self.document(include_hash=False)).encode()):
            raise ValueError("ATS observation acceptance receipt identity differs")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        value = {
            "schema_version": self.schema_version,
            "acceptance_id": self.acceptance_id,
            "nonce": self.nonce,
            "request_sha256": self.request_sha256,
            "envelope_sha256": self.envelope_sha256,
            "signature_sha256": self.signature_sha256,
            "consumption_root_sha256": self.consumption_root_sha256,
            "job_key": self.job_key,
            "application_url": self.application_url,
            "timeout_ms": self.timeout_ms,
            "max_network_events": self.max_network_events,
            "max_snapshot_bytes": self.max_snapshot_bytes,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
            "public_der_sha256": self.public_der_sha256,
            "consumed_at": self.consumed_at,
            "root_identity": list(self.root_identity),
            "store_identity": list(self.store_identity),
            "diagnostic_only": self.diagnostic_only,
            "raw_payloads_persisted": self.raw_payloads_persisted,
            "identity_authority": self.identity_authority,
            "vault_authority": self.vault_authority,
            "release_authority": self.release_authority,
            "submission_authority": self.submission_authority,
        }
        if include_hash:
            value["receipt_sha256"] = self.receipt_sha256
        return value


def _inventory_from_document(value: object) -> AtsFormInventory:
    if not isinstance(value, dict):
        raise ValueError("ATS observation inventory is malformed")
    keys = {
        "schema_version", "provider", "application_url", "captured_at",
        "page_snapshot_sha256", "screenshot_sha256s", "fields", "diagnostic_only",
        "raw_payloads_persisted", "identity_authority", "release_authority",
        "submission_authority",
    }
    if set(value) != keys or any(value[name] is not False for name in (
        "raw_payloads_persisted", "identity_authority", "release_authority", "submission_authority"
    )) or value["diagnostic_only"] is not True:
        raise ValueError("ATS observation inventory authority differs")
    fields_value = value["fields"]
    if not isinstance(fields_value, list):
        raise ValueError("ATS observation inventory fields are malformed")
    fields: list[AtsObservedField] = []
    for field in fields_value:
        if not isinstance(field, dict) or set(field) != {
            "field_id", "control_kind", "label", "required", "visible",
            "automation_role", "disabled", "read_only", "multiple", "options",
        } or not isinstance(field["options"], list):
            raise ValueError("ATS observation field is malformed")
        options = tuple(
            AtsFieldOption(option["value"], option["label"])
            for option in field["options"]
            if isinstance(option, dict) and set(option) == {"value", "label"}
        )
        if len(options) != len(field["options"]):
            raise ValueError("ATS observation option is malformed")
        fields.append(AtsObservedField(
            field["field_id"], field["control_kind"], field["label"], field["required"],
            field["visible"], field["automation_role"], field["disabled"],
            field["read_only"], field["multiple"], options,
        ))
    inventory = AtsFormInventory(
        provider=value["provider"], application_url=value["application_url"],
        captured_at=value["captured_at"], page_snapshot_sha256=value["page_snapshot_sha256"],
        screenshot_sha256s=tuple(value["screenshot_sha256s"]), fields=tuple(fields),
        schema_version=value["schema_version"],
    )
    if inventory.document() != value:
        raise ValueError("ATS observation inventory is non-canonical")
    return inventory


def _observation_payload(value: object) -> tuple[AtsFormInventory | None, str | None]:
    if not isinstance(value, dict):
        raise ValueError("ATS observation payload is malformed")
    base_keys = {
        "schema_version", "provider", "requested_application_url", "final_application_url",
        "job_key", "authority_sha256", "captured_at", "page_snapshot_sha256", "inventory", "inventory_sha256",
        "network_evidence_sha256", "network_event_count", "interaction_counts", "blocked_interaction_attempts",
        "terminal_failure_class", "diagnostic_only", "raw_payloads_persisted",
        "identity_authority", "release_authority", "submission_authority",
    }
    public_keys = {
        "transport", "acceptance_receipt_sha256", "acceptance_envelope_sha256",
        "acceptance_signature_sha256", "consumption_root_sha256",
        "navigation_admission_sha256", "browser_policy_sha256",
        "browser_revision_sha256", "allowed_origin_sha256", "navigation_admitted",
        "browser_launch_performed", "recovered_without_renavigation",
        "capture_complete", "blocked_request_counts", "context_postconditions",
    }
    schema = value.get("schema_version")
    is_public = schema == _PUBLIC_OBSERVATION_SCHEMA
    expected_keys = base_keys | public_keys if is_public else base_keys
    if set(value) != expected_keys or schema not in {
        _OBSERVATION_SCHEMA,
        _PUBLIC_OBSERVATION_SCHEMA,
    }:
        raise ValueError("ATS observation schema differs")
    if value["provider"] not in _ATS_PROVIDERS or _observation_url(value["requested_application_url"]) != value["requested_application_url"] or _observation_url(value["final_application_url"]) != value["final_application_url"]:
        raise ValueError("ATS observation route differs")
    _job_key(value["job_key"])
    _digest(value["authority_sha256"], "ATS observation authority SHA-256")
    _ats_time(value["captured_at"])
    _digest(value["page_snapshot_sha256"], "ATS observation page snapshot SHA-256")
    _digest(value["network_evidence_sha256"], "ATS observation network evidence SHA-256")
    if isinstance(value["network_event_count"], bool) or not isinstance(value["network_event_count"], int) or value["network_event_count"] < 0:
        raise ValueError("ATS observation network event count differs")
    if value["interaction_counts"] != {"click": 0, "fill": 0, "submit": 0, "type": 0, "upload": 0}:
        raise ValueError("ATS observation interaction boundary differs")
    attempts = value["blocked_interaction_attempts"]
    allowed_attempts = _READ_ONLY_ATTEMPTS if is_public else {
        "click", "fill", "submit", "type", "upload", "network"
    }
    if not isinstance(attempts, list) or len(attempts) > 32 or any(
        attempt not in allowed_attempts
        for attempt in attempts
    ):
        raise ValueError("ATS observation blocked interaction evidence differs")
    if value["diagnostic_only"] is not True or value["raw_payloads_persisted"] is not False or any(value[name] is not False for name in ("identity_authority", "release_authority", "submission_authority")):
        raise ValueError("ATS observation authority differs")
    failure = value["terminal_failure_class"]
    if failure is not None and failure not in _FAILURES:
        raise ValueError("ATS observation terminal state differs")
    if not is_public and (failure == "read_only_interaction_attempted") != bool(attempts):
        raise ValueError("ATS observation interaction terminal differs")
    if is_public:
        if value["transport"] != "public_https":
            raise ValueError("public ATS observation transport differs")
        for name in (
            "acceptance_receipt_sha256", "acceptance_envelope_sha256",
            "acceptance_signature_sha256", "consumption_root_sha256",
            "navigation_admission_sha256", "browser_policy_sha256",
            "browser_revision_sha256", "allowed_origin_sha256",
        ):
            _digest(value[name], name)
        for name in (
            "navigation_admitted", "browser_launch_performed",
            "recovered_without_renavigation", "capture_complete",
        ):
            if type(value[name]) is not bool:
                raise ValueError(f"public ATS observation {name} differs")
        if value["navigation_admitted"] is not True:
            raise ValueError("public ATS observation lacks navigation admission")
        blocked_counts = value["blocked_request_counts"]
        blocked_keys = {
            "cookie", "cross_origin", "download", "method", "network",
            "popup", "redirect", "storage", "submit", "websocket",
        }
        if (
            not isinstance(blocked_counts, dict)
            or set(blocked_counts) != blocked_keys
            or any(
                isinstance(count, bool) or not isinstance(count, int) or count < 0
                for count in blocked_counts.values()
            )
        ):
            raise ValueError("public ATS observation blocked request counts differ")
        postconditions = value["context_postconditions"]
        postcondition_keys = {
            "cookie_count", "download_count", "local_storage_count",
            "page_count", "session_storage_count",
        }
        if (
            not isinstance(postconditions, dict)
            or set(postconditions) != postcondition_keys
            or any(
                isinstance(count, bool) or not isinstance(count, int) or count < 0
                for count in postconditions.values()
            )
        ):
            raise ValueError("public ATS observation context postconditions differ")
        if value["recovered_without_renavigation"] and value["browser_launch_performed"]:
            raise ValueError("public ATS observation recovery launched a browser")
        if failure is None:
            if (
                attempts
                or any(blocked_counts.values())
                or value["capture_complete"] is not True
                or value["browser_launch_performed"] is not True
                or value["recovered_without_renavigation"] is not False
                or postconditions
                != {
                    "cookie_count": 0,
                    "download_count": 0,
                    "local_storage_count": 0,
                    "page_count": 1,
                    "session_storage_count": 0,
                }
            ):
                raise ValueError("public ATS observation success postconditions differ")
        elif value["capture_complete"] is not False:
            raise ValueError("blocked public ATS observation claims complete capture")
    if value["inventory"] is None:
        if value["inventory_sha256"] is not None or failure is None:
            raise ValueError("ATS observation inventory binding differs")
        return None, failure
    inventory = _inventory_from_document(value["inventory"])
    if failure is not None or value["inventory_sha256"] != inventory.content_sha256:
        raise ValueError("ATS observation inventory identity differs")
    return inventory, None


def _pre_submit_payload(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {"schema_version", "observation_manifest_sha256", "inventory_sha256", "authority_sha256", "plan_sha256", "before_snapshot_sha256", "after_snapshot_sha256", "actions", "interaction_counts", "terminal_disposition", "diagnostic_only", "raw_payloads_persisted", "identity_authority", "vault_authority", "submission_authority"}:
        raise ValueError("ATS pre-submit evidence schema differs")
    if value["schema_version"] != "market-aligner.ats-pre-submit-evidence.v1" or value["terminal_disposition"] not in {"prepared_no_submit", "blocked"} or value["interaction_counts"] != {"click": 0, "network": 0, "submit": 0} or value["diagnostic_only"] is not True or value["raw_payloads_persisted"] is not False or any(value[name] is not False for name in ("identity_authority", "vault_authority", "submission_authority")) or not isinstance(value["actions"], list):
        raise ValueError("ATS pre-submit evidence boundary differs")
    for name in ("observation_manifest_sha256", "inventory_sha256", "authority_sha256", "plan_sha256", "before_snapshot_sha256", "after_snapshot_sha256"):
        _digest(value[name], name)
    for action in value["actions"]:
        if not isinstance(action, dict) or set(action) != {"field_id", "action", "value_sha256", "readback_sha256", "upload_name", "upload_mime", "upload_content_sha256"}:
            raise ValueError("ATS pre-submit action evidence differs")
        _ats_text(action["field_id"], "ATS pre-submit field ID", maximum=512)
        if action["action"] not in _PRE_SUBMIT_ACTIONS:
            raise ValueError("ATS pre-submit action differs")
        for name in ("value_sha256", "readback_sha256", "upload_content_sha256"):
            _digest(action[name], name)
        if action["action"] == "upload":
            _ats_text(action["upload_name"], "ATS upload name", maximum=256)
            _ats_text(action["upload_mime"], "ATS upload MIME", maximum=128)
        elif action["upload_name"] is not None or action["upload_mime"] is not None:
            raise ValueError("ATS non-upload action carries upload evidence")


def _canonical(raw: bytes) -> dict[str, object]:
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid forensic JSON") from exc
    if not isinstance(value, dict) or raw != (canonical_json(value) + "\n").encode():
        raise ValueError("forensic JSON is not canonical")
    return value


def _root(value: str | Path, *, create: bool) -> tuple[Path, tuple[int, int]]:
    root = Path(value)
    if not root.is_absolute() or any(part in {".", ".."} for part in root.parts[1:]):
        raise ValueError("forensic root must be absolute and canonical")
    current = Path("/")
    for index, part in enumerate(root.parts[1:]):
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if not create or index != len(root.parts) - 2:
                raise KeyError("forensic root is missing") from None
            current.mkdir(mode=0o700)
            info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("forensic root has unsafe path component")
    info = os.lstat(root)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("forensic root must be current-user 0700")
    return root, (info.st_dev, info.st_ino)


def _manifests(root: Path, *, create: bool) -> Path:
    path = root / "manifests"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if not create:
            raise KeyError("forensic manifests are missing") from None
        path.mkdir(mode=0o700)
        info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("forensic manifests are unsafe")
    return path


def _learning_events(root: Path, *, create: bool) -> Path:
    path = root / "learning-events"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if not create:
            raise KeyError("forensic learning events are missing") from None
        path.mkdir(mode=0o700)
        info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("forensic learning events are unsafe")
    return path


def _read(path: Path) -> bytes:
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError("forensic manifest is unsafe")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("forensic manifest changed while opening")
        data = b"".join(iter(lambda: os.read(fd, 65536), b""))
        after = os.lstat(path)
        if (after.st_dev, after.st_ino, after.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError("forensic manifest changed while reading")
        return data
    finally:
        os.close(fd)


def _write_once(directory: Path, name: str, data: bytes) -> None:
    target = directory / name
    try:
        if _read(target) == data:
            return
        raise FileExistsError("attempt ID already has different evidence")
    except FileNotFoundError:
        pass
    temporary = directory / f".{name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(temporary, target, follow_symlinks=False)
    except FileExistsError:
        if _read(target) != data:
            raise FileExistsError("attempt ID already has different evidence")
    finally:
        temporary.unlink(missing_ok=True)


@dataclass
class _ExternalOwnedFile:
    path: Path
    mode: int
    label: str
    data: bytes
    parent_fd: int
    file_fd: int
    parent_identity: tuple[int, int]
    file_identity: tuple[int, int, int]

    def verify(self) -> None:
        parent = os.fstat(self.parent_fd)
        if (parent.st_dev, parent.st_ino) != self.parent_identity:
            raise ValueError(f"{self.label} parent descriptor changed")
        current_parent = os.lstat(self.path.parent)
        if (current_parent.st_dev, current_parent.st_ino) != self.parent_identity:
            raise ValueError(f"{self.label} parent path changed")
        current = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
        opened = os.fstat(self.file_fd)
        identity = (current.st_dev, current.st_ino, current.st_size)
        if (
            identity != self.file_identity
            or (opened.st_dev, opened.st_ino, opened.st_size) != self.file_identity
            or not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.geteuid()
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != self.mode
            or os.pread(self.file_fd, current.st_size, 0) != self.data
        ):
            raise ValueError(f"{self.label} identity changed across acceptance consumption")

    def close(self) -> None:
        os.close(self.file_fd)
        os.close(self.parent_fd)


def _open_external_owned_file(
    path_value: str | Path,
    *,
    mode: int,
    label: str,
) -> _ExternalOwnedFile:
    path = Path(path_value)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts[1:]):
        raise ValueError(f"{label} path must be absolute and canonical")
    _, parent_identity = _root(path.parent, create=False)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    file_fd = -1
    try:
        parent = os.fstat(parent_fd)
        if (parent.st_dev, parent.st_ino) != parent_identity:
            raise ValueError(f"{label} parent changed while opening")
        before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_size > 65_536
        ):
            raise ValueError(f"{label} is unsafe")
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        identity = (before.st_dev, before.st_ino, before.st_size)
        if (opened.st_dev, opened.st_ino, opened.st_size) != identity:
            raise ValueError(f"{label} changed while opening")
        data = b"".join(iter(lambda: os.read(file_fd, 65_536), b""))
        handle = _ExternalOwnedFile(
            path=path,
            mode=mode,
            label=label,
            data=data,
            parent_fd=parent_fd,
            file_fd=file_fd,
            parent_identity=parent_identity,
            file_identity=identity,
        )
        handle.verify()
        return handle
    except BaseException:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)
        raise


def _consumption_root_binding(
    value: str | Path,
) -> tuple[Path, tuple[int, int], tuple[int, int], str]:
    root, root_identity = _root(value, create=False)
    store = _open_acceptance_store(root, root_identity, create=False)
    if store is None:
        raise KeyError("ATS observation acceptance store is missing")
    try:
        store_identity = store.directory_identity
        binding = sha256(canonical_json({
            "absolute_path": str(root),
            "root_identity": list(root_identity),
            "store_identity": list(store_identity),
        }).encode())
        return root, root_identity, store_identity, binding
    finally:
        store.close()


def market_observation_consumption_root_sha256(value: str | Path) -> str:
    """Describe the pre-existing private replay domain without granting authority."""

    return _consumption_root_binding(value)[3]


@dataclass
class _AcceptanceStore:
    root: Path
    root_identity: tuple[int, int]
    root_fd: int
    directory_fd: int
    directory_identity: tuple[int, int]
    directory_name: str = _OBSERVATION_ACCEPTANCE_DIRECTORY
    label: str = "ATS observation acceptance store"

    def verify(self) -> None:
        root_path = os.lstat(self.root)
        root_opened = os.fstat(self.root_fd)
        if (
            (root_path.st_dev, root_path.st_ino) != self.root_identity
            or (root_opened.st_dev, root_opened.st_ino) != self.root_identity
            or not stat.S_ISDIR(root_path.st_mode)
            or root_path.st_uid != os.geteuid()
            or stat.S_IMODE(root_path.st_mode) != 0o700
        ):
            raise ValueError("ATS observation consumption root identity changed")
        directory = os.stat(
            self.directory_name,
            dir_fd=self.root_fd,
            follow_symlinks=False,
        )
        opened = os.fstat(self.directory_fd)
        if (
            (directory.st_dev, directory.st_ino) != self.directory_identity
            or (opened.st_dev, opened.st_ino) != self.directory_identity
            or not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise ValueError(f"{self.label} identity changed")

    def close(self) -> None:
        os.close(self.directory_fd)
        os.close(self.root_fd)


def _open_acceptance_store(
    root: Path,
    root_identity: tuple[int, int],
    *,
    create: bool,
) -> _AcceptanceStore | None:
    return _open_owned_store(
        root,
        root_identity,
        directory_name=_OBSERVATION_ACCEPTANCE_DIRECTORY,
        label="ATS observation acceptance store",
        create=create,
    )


def _open_owned_store(
    root: Path,
    root_identity: tuple[int, int],
    *,
    directory_name: str,
    label: str,
    create: bool,
) -> _AcceptanceStore | None:
    _id(directory_name, "owned store directory")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory_fd = -1
    try:
        opened_root = os.fstat(root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != root_identity:
            raise ValueError("ATS observation consumption root changed while opening")
        try:
            directory = os.stat(
                directory_name,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if not create:
                os.close(root_fd)
                return None
            try:
                os.mkdir(directory_name, mode=0o700, dir_fd=root_fd)
                os.fsync(root_fd)
            except FileExistsError:
                pass
            directory = os.stat(
                directory_name,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise ValueError(f"{label} is unsafe")
        directory_fd = os.open(
            directory_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        directory_identity = (directory.st_dev, directory.st_ino)
        opened_directory = os.fstat(directory_fd)
        if (opened_directory.st_dev, opened_directory.st_ino) != directory_identity:
            raise ValueError("ATS observation acceptance store changed while opening")
        store = _AcceptanceStore(
            root=root,
            root_identity=root_identity,
            root_fd=root_fd,
            directory_fd=directory_fd,
            directory_identity=directory_identity,
            directory_name=directory_name,
            label=label,
        )
        store.verify()
        return store
    except BaseException:
        if directory_fd >= 0:
            os.close(directory_fd)
        if root_fd >= 0:
            os.close(root_fd)
        raise


def _recover_acceptance_publish(store: _AcceptanceStore, name: str) -> None:
    target = os.stat(name, dir_fd=store.directory_fd, follow_symlinks=False)
    if target.st_nlink == 1:
        return
    if (
        target.st_nlink != 2
        or not stat.S_ISREG(target.st_mode)
        or target.st_uid != os.geteuid()
        or stat.S_IMODE(target.st_mode) != 0o600
    ):
        raise ValueError("ATS observation acceptance receipt has unsafe links")
    linked_names: list[str] = []
    for entry in os.listdir(store.directory_fd):
        if entry == name:
            continue
        entry_info = os.stat(entry, dir_fd=store.directory_fd, follow_symlinks=False)
        if (entry_info.st_dev, entry_info.st_ino) == (target.st_dev, target.st_ino):
            linked_names.append(entry)
    pattern = rf"\.{re.escape(name)}\.[0-9a-f]{{32}}\.tmp"
    if len(linked_names) != 1 or re.fullmatch(pattern, linked_names[0], re.ASCII) is None:
        raise ValueError("ATS observation acceptance receipt hardlink is not recoverable")
    temporary = linked_names[0]
    temporary_info = os.stat(temporary, dir_fd=store.directory_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(temporary_info.st_mode)
        or temporary_info.st_uid != os.geteuid()
        or temporary_info.st_nlink != 2
        or stat.S_IMODE(temporary_info.st_mode) != 0o600
    ):
        raise ValueError("ATS observation acceptance recovery link is unsafe")
    os.unlink(temporary, dir_fd=store.directory_fd)
    os.fsync(store.directory_fd)


def _read_acceptance_at(store: _AcceptanceStore, name: str) -> bytes:
    store.verify()
    before = os.stat(name, dir_fd=store.directory_fd, follow_symlinks=False)
    if before.st_nlink == 2:
        _recover_acceptance_publish(store, name)
        before = os.stat(name, dir_fd=store.directory_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size > 65_536
    ):
        raise ValueError("ATS observation acceptance receipt is unsafe")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=store.directory_fd)
    try:
        opened = os.fstat(fd)
        identity = (before.st_dev, before.st_ino, before.st_size)
        if (opened.st_dev, opened.st_ino, opened.st_size) != identity:
            raise ValueError("ATS observation acceptance receipt changed while opening")
        data = b"".join(iter(lambda: os.read(fd, 65_536), b""))
        after = os.stat(name, dir_fd=store.directory_fd, follow_symlinks=False)
        if (after.st_dev, after.st_ino, after.st_size) != identity:
            raise ValueError("ATS observation acceptance receipt changed while reading")
    finally:
        os.close(fd)
    store.verify()
    return data


def _write_acceptance_once(
    store: _AcceptanceStore,
    name: str,
    data: bytes,
    *,
    prepublish_check,
) -> bytes:
    try:
        existing = _read_acceptance_at(store, name)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        return existing
    temporary = f".{name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=store.directory_fd,
    )
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        prepublish_check()
        store.verify()
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=store.directory_fd,
                dst_dir_fd=store.directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            pass
    finally:
        try:
            os.unlink(temporary, dir_fd=store.directory_fd)
        except FileNotFoundError:
            pass
        os.fsync(store.directory_fd)
    stored = _read_acceptance_at(store, name)
    return stored


def _acceptance_from_document(value: object) -> AtsObservationAcceptance:
    if not isinstance(value, dict):
        raise ValueError("ATS observation acceptance is malformed")
    keys = {
        "schema_version", "acceptance_id", "nonce", "request_sha256", "consumption_root_sha256", "job_key",
        "application_url", "timeout_ms", "max_network_events", "max_snapshot_bytes",
        "not_before", "expires_at", "key_id", "read_only_navigation",
        "sanitized_hash_only_evidence", "login_authority", "cookie_authority",
        "identity_authority", "vault_authority", "fill_authority", "upload_authority",
        "click_authority", "submission_authority", "signature_b64", "envelope_sha256",
    }
    if set(value) != keys:
        raise ValueError("ATS observation acceptance schema is not closed")
    acceptance = AtsObservationAcceptance(**value)
    if acceptance.document() != value:
        raise ValueError("ATS observation acceptance is non-canonical")
    return acceptance


def _acceptance_receipt_from_document(value: object) -> AtsObservationAcceptanceReceipt:
    if not isinstance(value, dict):
        raise ValueError("ATS observation acceptance receipt is malformed")
    keys = {
        "schema_version", "acceptance_id", "nonce", "request_sha256", "envelope_sha256",
        "signature_sha256", "consumption_root_sha256",
        "job_key", "application_url", "timeout_ms", "max_network_events",
        "max_snapshot_bytes", "not_before", "expires_at", "key_id", "public_der_sha256", "consumed_at",
        "root_identity", "store_identity", "diagnostic_only", "raw_payloads_persisted", "identity_authority",
        "vault_authority", "release_authority", "submission_authority", "receipt_sha256",
    }
    if (
        set(value) != keys
        or not isinstance(value["root_identity"], list)
        or not isinstance(value["store_identity"], list)
    ):
        raise ValueError("ATS observation acceptance receipt schema is not closed")
    receipt = AtsObservationAcceptanceReceipt(
        **(value | {
            "root_identity": tuple(value["root_identity"]),
            "store_identity": tuple(value["store_identity"]),
        })
    )
    if receipt.document() != value:
        raise ValueError("ATS observation acceptance receipt is non-canonical")
    return receipt


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verify_market_observation_signature(
    acceptance: AtsObservationAcceptance,
    public_pem: bytes,
) -> None:
    if acceptance.key_id != MARKET_OBSERVATION_KEY_ID:
        raise ValueError("ATS observation acceptance key ID is not trusted")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise RuntimeError("Ed25519 observation acceptance requires the optional cryptography package") from exc
    try:
        public_key = serialization.load_pem_public_key(public_pem)
    except ValueError as exc:
        raise ValueError("ATS observation public key is malformed") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("ATS observation public key type differs")
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if sha256(public_der) != MARKET_OBSERVATION_PUBLIC_DER_SHA256:
        raise ValueError("ATS observation public key identity differs")
    signature = base64.b64decode(acceptance.signature_b64, validate=True)
    try:
        public_key.verify(signature, canonical_json(acceptance.signed_document()).encode())
    except InvalidSignature as exc:
        raise ValueError("ATS observation acceptance signature is invalid") from exc


def _acceptance_receipt_matches(
    receipt: AtsObservationAcceptanceReceipt,
    acceptance: AtsObservationAcceptance,
    authority: AtsObservationAuthority,
    root_identity: tuple[int, int],
    store_identity: tuple[int, int],
) -> None:
    expected = {
        "acceptance_id": acceptance.acceptance_id,
        "nonce": acceptance.nonce,
        "request_sha256": authority.authority_sha256,
        "envelope_sha256": acceptance.envelope_sha256,
        "signature_sha256": sha256(base64.b64decode(acceptance.signature_b64, validate=True)),
        "consumption_root_sha256": acceptance.consumption_root_sha256,
        "job_key": authority.job_key,
        "application_url": authority.application_url,
        "timeout_ms": authority.timeout_ms,
        "max_network_events": authority.max_network_events,
        "max_snapshot_bytes": authority.max_snapshot_bytes,
        "not_before": acceptance.not_before,
        "expires_at": acceptance.expires_at,
        "key_id": MARKET_OBSERVATION_KEY_ID,
        "public_der_sha256": MARKET_OBSERVATION_PUBLIC_DER_SHA256,
        "root_identity": root_identity,
        "store_identity": store_identity,
    }
    if any(getattr(receipt, name) != value for name, value in expected.items()):
        raise ValueError("ATS observation acceptance nonce is bound to different evidence")


def _consume_verified_observation_acceptance(
    authority: AtsObservationAuthority,
    acceptance: AtsObservationAcceptance,
    root: Path,
    root_identity: tuple[int, int],
    store_identity: tuple[int, int],
    envelope_file: _ExternalOwnedFile,
    public_key_file: _ExternalOwnedFile,
) -> AtsObservationAcceptanceReceipt:
    receipt_name = f"{acceptance.nonce}.json"
    store = _open_acceptance_store(root, root_identity, create=False)
    try:
        if store is None or store.directory_identity != store_identity:
            raise ValueError("ATS observation acceptance store does not match signed replay domain")
        try:
            existing_raw = _read_acceptance_at(store, receipt_name)
        except FileNotFoundError:
            existing_raw = None
        if existing_raw is not None:
            existing = _acceptance_receipt_from_document(_canonical(existing_raw))
            _acceptance_receipt_matches(
                existing,
                acceptance,
                authority,
                root_identity,
                store_identity,
            )
            envelope_file.verify()
            public_key_file.verify()
            store.verify()
            return existing
        now = _utc_now()
        _ats_time(now)
        if not acceptance.not_before <= now < acceptance.expires_at:
            raise ValueError("ATS observation acceptance is outside its validity window")
        current_root, current_identity, current_store_identity, current_binding = (
            _consumption_root_binding(root)
        )
        if (
            current_root != root
            or current_identity != root_identity
            or current_store_identity != store_identity
            or current_binding != acceptance.consumption_root_sha256
        ):
            raise ValueError("ATS observation consumption root changed before publication")
        fields = {
            "schema_version": _OBSERVATION_ACCEPTANCE_RECEIPT_SCHEMA,
            "acceptance_id": acceptance.acceptance_id,
            "nonce": acceptance.nonce,
            "request_sha256": authority.authority_sha256,
            "envelope_sha256": acceptance.envelope_sha256,
            "signature_sha256": sha256(base64.b64decode(acceptance.signature_b64, validate=True)),
            "consumption_root_sha256": acceptance.consumption_root_sha256,
            "job_key": authority.job_key,
            "application_url": authority.application_url,
            "timeout_ms": authority.timeout_ms,
            "max_network_events": authority.max_network_events,
            "max_snapshot_bytes": authority.max_snapshot_bytes,
            "not_before": acceptance.not_before,
            "expires_at": acceptance.expires_at,
            "key_id": MARKET_OBSERVATION_KEY_ID,
            "public_der_sha256": MARKET_OBSERVATION_PUBLIC_DER_SHA256,
            "consumed_at": now,
            "root_identity": list(root_identity),
            "store_identity": list(store_identity),
            "diagnostic_only": True,
            "raw_payloads_persisted": False,
            "identity_authority": False,
            "vault_authority": False,
            "release_authority": False,
            "submission_authority": False,
        }
        receipt = AtsObservationAcceptanceReceipt(
            **(fields | {
                "root_identity": root_identity,
                "store_identity": store_identity,
                "receipt_sha256": sha256(canonical_json(fields).encode()),
            })
        )
        data = (canonical_json(receipt.document()) + "\n").encode()

        def prepublish_check() -> None:
            envelope_file.verify()
            public_key_file.verify()
            store.verify()
            _, identity, current_store_identity, binding = _consumption_root_binding(root)
            if (
                identity != root_identity
                or current_store_identity != store_identity
                or binding != acceptance.consumption_root_sha256
            ):
                raise ValueError("ATS observation consumption root changed before publication")

        stored_raw = _write_acceptance_once(
            store,
            receipt_name,
            data,
            prepublish_check=prepublish_check,
        )
        stored = _acceptance_receipt_from_document(_canonical(stored_raw))
        _acceptance_receipt_matches(
            stored,
            acceptance,
            authority,
            root_identity,
            store_identity,
        )
        store.verify()
        return stored
    finally:
        if store is not None:
            store.close()


def verify_and_consume_market_observation_acceptance(
    authority: AtsObservationAuthority,
    *,
    envelope_path: str | Path,
    public_key_path: str | Path,
    consumption_root: str | Path,
) -> AtsObservationAcceptanceReceipt:
    """Authenticate and atomically consume one public observation acceptance.

    The acceptance signs one pre-existing private replay-domain identity. Exact
    replay returns its immutable first receipt; callers cannot select a new root.
    """

    if type(authority) is not AtsObservationAuthority:
        raise TypeError("ATS observation request must use the canonical authority type")
    if authority.authority_state != "pending" or authority.local_fixture_only is not False:
        raise ValueError("public ATS observation request must remain a pending descriptor")
    envelope_file = _open_external_owned_file(
        envelope_path,
        mode=0o600,
        label="ATS observation acceptance envelope",
    )
    public_key_file = None
    try:
        acceptance = _acceptance_from_document(_canonical(envelope_file.data))
        bindings = {
            "request_sha256": authority.authority_sha256,
            "job_key": authority.job_key,
            "application_url": authority.application_url,
            "timeout_ms": authority.timeout_ms,
            "max_network_events": authority.max_network_events,
            "max_snapshot_bytes": authority.max_snapshot_bytes,
        }
        if any(getattr(acceptance, name) != value for name, value in bindings.items()):
            raise ValueError("ATS observation acceptance does not bind the exact request")
        root, root_identity, store_identity, root_binding = _consumption_root_binding(
            consumption_root
        )
        if acceptance.consumption_root_sha256 != root_binding:
            raise ValueError("ATS observation acceptance does not bind the replay domain")
        public_key_file = _open_external_owned_file(
            public_key_path,
            mode=0o644,
            label="ATS observation public key",
        )
        _verify_market_observation_signature(acceptance, public_key_file.data)
        envelope_file.verify()
        public_key_file.verify()
        return _consume_verified_observation_acceptance(
            authority,
            acceptance,
            root,
            root_identity,
            store_identity,
            envelope_file,
            public_key_file,
        )
    finally:
        if public_key_file is not None:
            public_key_file.close()
        envelope_file.close()


def verify_consumed_market_observation_acceptance(
    authority: AtsObservationAuthority,
    acceptance_receipt: AtsObservationAcceptanceReceipt,
    *,
    envelope_path: str | Path,
    public_key_path: str | Path,
    consumption_root: str | Path,
) -> AtsObservationAcceptanceReceipt:
    """Reverify a previously consumed capability without consuming a new nonce."""

    if type(acceptance_receipt) is not AtsObservationAcceptanceReceipt:
        raise TypeError("public ATS observation requires an exact acceptance receipt")
    root, root_identity = _root(consumption_root, create=False)
    if root_identity != acceptance_receipt.root_identity:
        raise ValueError("ATS observation acceptance receipt root differs")
    store = _open_acceptance_store(root, root_identity, create=False)
    if store is None:
        raise PermissionError("ATS observation acceptance was not consumed")
    try:
        if store.directory_identity != acceptance_receipt.store_identity:
            raise ValueError("ATS observation acceptance receipt store differs")
        try:
            stored_raw = _read_acceptance_at(store, f"{acceptance_receipt.nonce}.json")
        except FileNotFoundError:
            raise PermissionError("ATS observation acceptance was not consumed") from None
        stored = _acceptance_receipt_from_document(_canonical(stored_raw))
        if stored != acceptance_receipt:
            raise ValueError("ATS observation supplied acceptance receipt differs")
    finally:
        store.close()
    verified = verify_and_consume_market_observation_acceptance(
        authority,
        envelope_path=envelope_path,
        public_key_path=public_key_path,
        consumption_root=consumption_root,
    )
    if verified != acceptance_receipt:
        raise ValueError("ATS observation acceptance revalidation differs")
    return verified


@dataclass(frozen=True)
class _PublicObservationAdmission:
    attempt_id: str
    application_id: str
    operation_sha256: str
    request_sha256: str
    acceptance_receipt_sha256: str
    acceptance_envelope_sha256: str
    acceptance_signature_sha256: str
    consumption_root_sha256: str
    source_sha256: str
    sanity_receipt_sha256: str
    ats_name: str
    job_key: str
    application_url: str
    admitted_at: str
    root_identity: tuple[int, int]
    store_identity: tuple[int, int]
    admission_sha256: str
    schema_version: str = _PUBLIC_OBSERVATION_ADMISSION_SCHEMA
    diagnostic_only: bool = True
    raw_payloads_persisted: bool = False
    identity_authority: bool = False
    release_authority: bool = False
    submission_authority: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != _PUBLIC_OBSERVATION_ADMISSION_SCHEMA:
            raise ValueError("public ATS observation admission schema differs")
        _id(self.attempt_id, "attempt ID")
        _id(self.application_id, "application ID")
        for name in (
            "operation_sha256", "request_sha256", "acceptance_receipt_sha256",
            "acceptance_envelope_sha256", "acceptance_signature_sha256",
            "consumption_root_sha256", "source_sha256", "sanity_receipt_sha256",
            "admission_sha256",
        ):
            _digest(getattr(self, name), name)
        _id(self.ats_name, "ATS name")
        _job_key(self.job_key)
        if _observation_url(self.application_url) != self.application_url:
            raise ValueError("public ATS observation admission URL differs")
        _ats_time(self.admitted_at)
        for name in ("root_identity", "store_identity"):
            identity = getattr(self, name)
            if (
                not isinstance(identity, tuple)
                or len(identity) != 2
                or any(
                    isinstance(item, bool) or not isinstance(item, int) or item < 0
                    for item in identity
                )
            ):
                raise ValueError(f"public ATS observation {name.replace('_', ' ')} differs")
        exact = {
            "diagnostic_only": True,
            "raw_payloads_persisted": False,
            "identity_authority": False,
            "release_authority": False,
            "submission_authority": False,
        }
        if any(type(getattr(self, name)) is not bool for name in exact):
            raise TypeError("public ATS observation admission authority fields must be bool")
        if any(getattr(self, name) is not expected for name, expected in exact.items()):
            raise ValueError("public ATS observation admission exceeds read-only scope")
        if self.admission_sha256 != sha256(
            canonical_json(self.document(include_hash=False)).encode()
        ):
            raise ValueError("public ATS observation admission identity differs")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        value = {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "application_id": self.application_id,
            "operation_sha256": self.operation_sha256,
            "request_sha256": self.request_sha256,
            "acceptance_receipt_sha256": self.acceptance_receipt_sha256,
            "acceptance_envelope_sha256": self.acceptance_envelope_sha256,
            "acceptance_signature_sha256": self.acceptance_signature_sha256,
            "consumption_root_sha256": self.consumption_root_sha256,
            "source_sha256": self.source_sha256,
            "sanity_receipt_sha256": self.sanity_receipt_sha256,
            "ats_name": self.ats_name,
            "job_key": self.job_key,
            "application_url": self.application_url,
            "admitted_at": self.admitted_at,
            "root_identity": list(self.root_identity),
            "store_identity": list(self.store_identity),
            "diagnostic_only": self.diagnostic_only,
            "raw_payloads_persisted": self.raw_payloads_persisted,
            "identity_authority": self.identity_authority,
            "release_authority": self.release_authority,
            "submission_authority": self.submission_authority,
        }
        if include_hash:
            value["admission_sha256"] = self.admission_sha256
        return value


def _public_observation_admission_from_document(
    value: object,
) -> _PublicObservationAdmission:
    keys = {
        "schema_version", "attempt_id", "application_id", "operation_sha256",
        "request_sha256", "acceptance_receipt_sha256", "acceptance_envelope_sha256",
        "acceptance_signature_sha256", "consumption_root_sha256", "source_sha256",
        "sanity_receipt_sha256", "ats_name", "job_key", "application_url",
        "admitted_at", "root_identity", "store_identity", "diagnostic_only",
        "raw_payloads_persisted", "identity_authority", "release_authority",
        "submission_authority", "admission_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or not isinstance(value["root_identity"], list)
        or not isinstance(value["store_identity"], list)
    ):
        raise ValueError("public ATS observation admission schema is not closed")
    admission = _PublicObservationAdmission(
        **(
            value
            | {
                "root_identity": tuple(value["root_identity"]),
                "store_identity": tuple(value["store_identity"]),
            }
        )
    )
    if admission.document() != value:
        raise ValueError("public ATS observation admission is non-canonical")
    return admission


def _public_observation_lock(store: _AcceptanceStore, attempt_id: str) -> int:
    name = f".{_id(attempt_id, 'attempt ID')}.lock"
    fd = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
        dir_fd=store.directory_fd,
    )
    try:
        before = os.stat(name, dir_fd=store.directory_fd, follow_symlinks=False)
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError("public ATS observation operation lock is unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        after = os.stat(name, dir_fd=store.directory_fd, follow_symlinks=False)
        if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("public ATS observation operation lock changed")
        store.verify()
        return fd
    except BaseException:
        os.close(fd)
        raise


def _public_observation_admit(
    store: _AcceptanceStore,
    *,
    attempt_id: str,
    application_id: str,
    operation_sha256: str,
    source: ApplicationSource,
    sanity: SanityReviewReceipt,
    ats_name: str,
    authority: AtsObservationAuthority,
    acceptance: AtsObservationAcceptanceReceipt,
) -> tuple[_PublicObservationAdmission, bool]:
    name = f"{_id(attempt_id, 'attempt ID')}.json"
    expected = {
        "attempt_id": attempt_id,
        "application_id": _id(application_id, "application ID"),
        "operation_sha256": operation_sha256,
        "request_sha256": authority.authority_sha256,
        "acceptance_receipt_sha256": acceptance.receipt_sha256,
        "acceptance_envelope_sha256": acceptance.envelope_sha256,
        "acceptance_signature_sha256": acceptance.signature_sha256,
        "consumption_root_sha256": acceptance.consumption_root_sha256,
        "source_sha256": source.source_sha256,
        "sanity_receipt_sha256": sanity.receipt_sha256,
        "ats_name": ats_name,
        "job_key": authority.job_key,
        "application_url": authority.application_url,
        "root_identity": store.root_identity,
        "store_identity": store.directory_identity,
    }
    try:
        raw = _read_acceptance_at(store, name)
    except FileNotFoundError:
        raw = None
    if raw is not None:
        admission = _public_observation_admission_from_document(_canonical(raw))
        if any(getattr(admission, key) != value for key, value in expected.items()):
            raise ValueError("public ATS observation attempt is bound to different evidence")
        return admission, False
    now = _utc_now()
    if not acceptance.not_before <= now < acceptance.expires_at:
        raise ValueError("public ATS observation acceptance is outside its validity window")
    fields: dict[str, object] = {
        "schema_version": _PUBLIC_OBSERVATION_ADMISSION_SCHEMA,
        **expected,
        "admitted_at": now,
        "root_identity": list(store.root_identity),
        "store_identity": list(store.directory_identity),
        "diagnostic_only": True,
        "raw_payloads_persisted": False,
        "identity_authority": False,
        "release_authority": False,
        "submission_authority": False,
    }
    admission = _PublicObservationAdmission(
        **(
            fields
            | {
                "root_identity": store.root_identity,
                "store_identity": store.directory_identity,
                "admission_sha256": sha256(canonical_json(fields).encode()),
            }
        )
    )
    stored = _write_acceptance_once(
        store,
        name,
        (canonical_json(admission.document()) + "\n").encode(),
        prepublish_check=store.verify,
    )
    recovered = _public_observation_admission_from_document(_canonical(stored))
    if recovered != admission:
        raise ValueError("public ATS observation admission collision differs")
    return recovered, True


@dataclass(frozen=True)
class ApplicationSource:
    profile_id: str
    job_key: str
    eligibility_receipt_sha256: str
    fit_receipt_sha256: str
    evidence_reference_sha256: str
    contact_reference_sha256: str
    source_sha256: str

    def __post_init__(self) -> None:
        _id(self.profile_id, "profile ID")
        _job_key(self.job_key)
        for name in ("eligibility_receipt_sha256", "fit_receipt_sha256", "evidence_reference_sha256", "contact_reference_sha256", "source_sha256"):
            _digest(getattr(self, name), name)

    def document(self) -> dict[str, object]:
        return self.__dict__ | {"schema_version": SCHEMA_VERSION, "identity_authority": False, "submission_authority": False}


@dataclass(frozen=True)
class SanityReviewReceipt:
    source_sha256: str
    artifact_set_sha256: str
    receipt_sha256: str
    backend: str = "fixture_capture"
    model: str = "deterministic-v1"
    verdict: str = "pass"

    def __post_init__(self) -> None:
        for name in ("source_sha256", "artifact_set_sha256", "receipt_sha256"):
            _digest(getattr(self, name), name)
        if (self.backend, self.model, self.verdict) != ("fixture_capture", "deterministic-v1", "pass"):
            raise ValueError("unsupported faceless sanity receipt")


@dataclass(frozen=True)
class ATSForensicReceipt:
    attempt_id: str
    application_id: str
    manifest_sha256: str
    receipt_sha256: str
    outcome: str
    failure_class: str | None
    event_count: int
    root_identity: tuple[int, int]

    def __post_init__(self) -> None:
        _id(self.attempt_id, "attempt ID")
        _id(self.application_id, "application ID")
        _digest(self.manifest_sha256, "manifest SHA-256")
        _digest(self.receipt_sha256, "receipt SHA-256")
        if self.outcome not in {"prepared", "blocked"} or (self.outcome == "prepared") != (self.failure_class is None) or self.failure_class not in _FAILURES | {None} or self.event_count < 1:
            raise ValueError("invalid forensic outcome")

    def document(self) -> dict[str, object]:
        return {"schema_version": SCHEMA_VERSION, "attempt_id": self.attempt_id, "application_id": self.application_id, "manifest_path": f"manifests/{self.attempt_id}.json", "manifest_sha256": self.manifest_sha256, "receipt_sha256": self.receipt_sha256, "outcome": self.outcome, "failure_class": self.failure_class, "event_count": self.event_count, "root_identity": list(self.root_identity), "diagnostic_only": True, "raw_payloads_persisted": False, "identity_authority": False, "release_authority": False, "submission_authority": False}


@dataclass(frozen=True)
class ATSForensicLearningEvent:
    event_sha256: str
    recorded_at: str
    cycle_id: str
    stage: str
    issue_code: str
    summary: str
    attempt_id: str
    application_id: str
    manifest_sha256: str
    receipt_sha256: str
    outcome: str
    failure_class: str | None
    event_count: int

    def __post_init__(self) -> None:
        _digest(self.event_sha256, "learning event SHA-256")
        if not isinstance(self.recorded_at, str) or not _RFC3339_UTC.fullmatch(self.recorded_at):
            raise ValueError("learning event time must be canonical RFC3339 UTC")
        try:
            datetime.fromisoformat(f"{self.recorded_at[:-1]}+00:00")
        except ValueError as exc:
            raise ValueError("learning event time must be canonical RFC3339 UTC") from exc
        _id(self.cycle_id, "learning cycle ID")
        if self.stage not in _LEARNING_STAGES or self.issue_code not in _LEARNING_ISSUES or self.summary not in _LEARNING_SUMMARIES:
            raise ValueError("learning event uses an unsupported closed value")
        _id(self.attempt_id, "attempt ID")
        _id(self.application_id, "application ID")
        _digest(self.manifest_sha256, "manifest SHA-256")
        _digest(self.receipt_sha256, "receipt SHA-256")
        if self.outcome not in {"prepared", "blocked"} or (self.outcome == "prepared") != (self.failure_class is None) or self.failure_class not in _FAILURES | {None} or self.event_count < 1:
            raise ValueError("learning event forensic outcome is invalid")
        if self.event_sha256 != sha256(canonical_json(self.document(include_hash=False)).encode()):
            raise ValueError("learning event identity differs")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        value = {"schema_version": SCHEMA_VERSION, "recorded_at": self.recorded_at, "cycle_id": self.cycle_id, "stage": self.stage, "issue_code": self.issue_code, "summary": self.summary, "attempt_id": self.attempt_id, "application_id": self.application_id, "manifest_sha256": self.manifest_sha256, "receipt_sha256": self.receipt_sha256, "outcome": self.outcome, "failure_class": self.failure_class, "event_count": self.event_count, "diagnostic_only": True, "raw_payloads_persisted": False, "identity_authority": False, "release_authority": False, "submission_authority": False}
        if include_hash:
            value["event_sha256"] = self.event_sha256
        return value


class ATSForensicRecorder:
    def __init__(self, root: str | Path, *, attempt_id: str, application_id: str, binding_sha256: str) -> None:
        self.root, self.root_identity = _root(root, create=True)
        self.attempt_id = _id(attempt_id, "attempt ID")
        self.application_id = _id(application_id, "application ID")
        self.binding_sha256 = _digest(binding_sha256, "binding SHA-256")
        self.events: list[dict[str, object]] = []

    def checkpoint(self, name: str, *, observation: Mapping[str, object] | None = None, pre_submit: Mapping[str, object] | None = None) -> None:
        if name not in {"prepared", "blocked", _OBSERVATION_CHECKPOINT, _PRE_SUBMIT_CHECKPOINT}:
            raise ValueError("unsupported forensic checkpoint")
        event = {"sequence": len(self.events) + 1, "checkpoint": name}
        if name == _OBSERVATION_CHECKPOINT:
            if observation is None:
                raise ValueError("read-only ATS observation checkpoint requires evidence")
            _observation_payload(dict(observation))
            event["observation"] = json.loads(canonical_json(dict(observation)))
        elif name == _PRE_SUBMIT_CHECKPOINT:
            if pre_submit is None:
                raise ValueError("pre-submit checkpoint requires evidence")
            _pre_submit_payload(dict(pre_submit))
            event["pre_submit"] = json.loads(canonical_json(dict(pre_submit)))
        elif observation is not None or pre_submit is not None:
            raise ValueError("ordinary forensic checkpoints cannot carry observation evidence")
        self.events.append(event | {"event_sha256": sha256(canonical_json(event).encode())})

    def finalize(self, *, outcome: str, failure_class: str | None = None) -> ATSForensicReceipt:
        if not self.events:
            raise ValueError("forensic observation has no events")
        manifest = {"schema_version": SCHEMA_VERSION, "attempt_id": self.attempt_id, "application_id": self.application_id, "binding_sha256": self.binding_sha256, "root_identity": list(self.root_identity), "outcome": outcome, "failure_class": failure_class, "events": self.events, "diagnostic_only": True, "raw_payloads_persisted": False, "identity_authority": False, "release_authority": False, "submission_authority": False}
        data = (canonical_json(manifest) + "\n").encode()
        _write_once(_manifests(self.root, create=True), f"{self.attempt_id}.json", data)
        receipt = ATSForensicReceipt(self.attempt_id, self.application_id, sha256(data), "0" * 64, outcome, failure_class, len(self.events), self.root_identity)
        identity = receipt.document() | {"receipt_sha256": None}
        return ATSForensicReceipt(self.attempt_id, self.application_id, receipt.manifest_sha256, sha256(canonical_json(identity).encode()), outcome, failure_class, len(self.events), self.root_identity)


def _forensic_observation(events: object) -> dict[str, object] | None:
    if not isinstance(events, list) or not events:
        raise ValueError("forensic events are malformed")
    observation: dict[str, object] | None = None
    for sequence, event in enumerate(events, start=1):
        if not isinstance(event, dict) or event.get("sequence") != sequence:
            raise ValueError("forensic event sequence differs")
        checkpoint = event.get("checkpoint")
        expected = {"sequence", "checkpoint", "event_sha256"}
        if checkpoint == _OBSERVATION_CHECKPOINT:
            expected.add("observation")
        if checkpoint == _PRE_SUBMIT_CHECKPOINT:
            expected.add("pre_submit")
        if checkpoint not in {"prepared", "blocked", _OBSERVATION_CHECKPOINT, _PRE_SUBMIT_CHECKPOINT} or set(event) != expected:
            raise ValueError("forensic event schema differs")
        without_hash = {key: value for key, value in event.items() if key != "event_sha256"}
        if event["event_sha256"] != sha256(canonical_json(without_hash).encode()):
            raise ValueError("forensic event identity differs")
        if checkpoint == _OBSERVATION_CHECKPOINT:
            if observation is not None or not isinstance(event["observation"], dict):
                raise ValueError("forensic observation evidence differs")
            _observation_payload(event["observation"])
            observation = event["observation"]
        if checkpoint == _PRE_SUBMIT_CHECKPOINT:
            _pre_submit_payload(event["pre_submit"])
    return observation


def _manifest_observation(manifest: dict[str, object], receipt: ATSForensicReceipt) -> dict[str, object] | None:
    observation = _forensic_observation(manifest["events"])
    if observation is not None:
        _inventory, failure = _observation_payload(observation)
        if failure != receipt.failure_class or (failure is None) != (receipt.outcome == "prepared"):
            raise ValueError("forensic observation outcome differs")
    return observation


def load_forensic_receipt(root: str | Path, *, attempt_id: str, application_id: str, binding_sha256: str) -> ATSForensicReceipt:
    path, identity = _root(root, create=False)
    try:
        data = _read(_manifests(path, create=False) / f"{_id(attempt_id, 'attempt ID')}.json")
    except FileNotFoundError:
        raise KeyError(attempt_id) from None
    manifest = _canonical(data)
    exact = {"schema_version", "attempt_id", "application_id", "binding_sha256", "root_identity", "outcome", "failure_class", "events", "diagnostic_only", "raw_payloads_persisted", "identity_authority", "release_authority", "submission_authority"}
    if set(manifest) != exact or manifest["attempt_id"] != attempt_id or manifest["application_id"] != application_id or manifest["binding_sha256"] != _digest(binding_sha256, "binding SHA-256") or manifest["root_identity"] != list(identity) or manifest["diagnostic_only"] is not True or manifest["raw_payloads_persisted"] is not False or any(manifest[x] is not False for x in ("identity_authority", "release_authority", "submission_authority")) or not isinstance(manifest["events"], list):
        raise ValueError("forensic manifest binding differs")
    provisional = ATSForensicReceipt(attempt_id, application_id, sha256(data), "0" * 64, manifest["outcome"], manifest["failure_class"], len(manifest["events"]), identity)
    _manifest_observation(manifest, provisional)
    receipt_doc = provisional.document() | {"receipt_sha256": None}
    return ATSForensicReceipt(attempt_id, application_id, provisional.manifest_sha256, sha256(canonical_json(receipt_doc).encode()), provisional.outcome, provisional.failure_class, provisional.event_count, identity)


def _verify_learning_receipt(root: str | Path, receipt: ATSForensicReceipt) -> None:
    if not isinstance(receipt, ATSForensicReceipt):
        raise TypeError("learning events require ATSForensicReceipt")
    path, identity = _root(root, create=False)
    data = _read(_manifests(path, create=False) / f"{receipt.attempt_id}.json")
    manifest = _canonical(data)
    expected = {"schema_version", "attempt_id", "application_id", "binding_sha256", "root_identity", "outcome", "failure_class", "events", "diagnostic_only", "raw_payloads_persisted", "identity_authority", "release_authority", "submission_authority"}
    if set(manifest) != expected or manifest["schema_version"] != SCHEMA_VERSION or manifest["attempt_id"] != receipt.attempt_id or manifest["application_id"] != receipt.application_id or manifest["root_identity"] != list(identity) or manifest["outcome"] != receipt.outcome or manifest["failure_class"] != receipt.failure_class or manifest["diagnostic_only"] is not True or manifest["raw_payloads_persisted"] is not False or any(manifest[name] is not False for name in ("identity_authority", "release_authority", "submission_authority")) or not isinstance(manifest["events"], list) or len(manifest["events"]) != receipt.event_count or sha256(data) != receipt.manifest_sha256:
        raise ValueError("learning event forensic receipt binding differs")
    _manifest_observation(manifest, receipt)
    receipt_document = receipt.document() | {"receipt_sha256": None}
    if receipt.receipt_sha256 != sha256(canonical_json(receipt_document).encode()):
        raise ValueError("learning event forensic receipt identity differs")


def _learning_event_name(event_sha256: str) -> str:
    return f"{_digest(event_sha256, 'learning event SHA-256')}.json"


def _learning_event_from_document(value: object) -> ATSForensicLearningEvent:
    keys = {"schema_version", "recorded_at", "cycle_id", "stage", "issue_code", "summary", "attempt_id", "application_id", "manifest_sha256", "receipt_sha256", "outcome", "failure_class", "event_count", "diagnostic_only", "raw_payloads_persisted", "identity_authority", "release_authority", "submission_authority", "event_sha256"}
    if not isinstance(value, dict) or set(value) != keys or value["schema_version"] != SCHEMA_VERSION or value["diagnostic_only"] is not True or value["raw_payloads_persisted"] is not False or any(value[name] is not False for name in ("identity_authority", "release_authority", "submission_authority")):
        raise ValueError("learning event schema differs")
    event = ATSForensicLearningEvent(**{key: value[key] for key in keys if key not in {"schema_version", "diagnostic_only", "raw_payloads_persisted", "identity_authority", "release_authority", "submission_authority"}})
    return event


def record_canary_learning_event(root: str | Path, receipt: ATSForensicReceipt, *, recorded_at: str, cycle_id: str, stage: str, issue_code: str, summary: str) -> ATSForensicLearningEvent:
    """Create-or-verify one closed, receipt-bound, no-submit learning event."""
    _verify_learning_receipt(root, receipt)
    fields = {"recorded_at": recorded_at, "cycle_id": cycle_id, "stage": stage, "issue_code": issue_code, "summary": summary, "attempt_id": receipt.attempt_id, "application_id": receipt.application_id, "manifest_sha256": receipt.manifest_sha256, "receipt_sha256": receipt.receipt_sha256, "outcome": receipt.outcome, "failure_class": receipt.failure_class, "event_count": receipt.event_count}
    event = ATSForensicLearningEvent(**fields, event_sha256=sha256(canonical_json({"schema_version": SCHEMA_VERSION, **fields, "diagnostic_only": True, "raw_payloads_persisted": False, "identity_authority": False, "release_authority": False, "submission_authority": False}).encode()))
    root_path, _identity = _root(root, create=False)
    _write_once(_learning_events(root_path, create=True), _learning_event_name(event.event_sha256), (canonical_json(event.document()) + "\n").encode())
    return verify_canary_learning_event(root, event.event_sha256)


def verify_canary_learning_event(root: str | Path, event_sha256: str) -> ATSForensicLearningEvent:
    root_path, _identity = _root(root, create=False)
    event = _learning_event_from_document(_canonical(_read(_learning_events(root_path, create=False) / _learning_event_name(event_sha256))))
    if event.event_sha256 != event_sha256:
        raise ValueError("learning event path differs from identity")
    receipt = ATSForensicReceipt(event.attempt_id, event.application_id, event.manifest_sha256, event.receipt_sha256, event.outcome, event.failure_class, event.event_count, _identity)
    _verify_learning_receipt(root, receipt)
    return event


def list_canary_learning_events(root: str | Path) -> tuple[ATSForensicLearningEvent, ...]:
    root_path, _identity = _root(root, create=False)
    try:
        directory = _learning_events(root_path, create=False)
    except KeyError:
        return ()
    events: list[ATSForensicLearningEvent] = []
    for path in directory.iterdir():
        if not _DIGEST.fullmatch(path.stem) or path.suffix != ".json":
            raise ValueError("learning event inventory is unsafe")
        events.append(verify_canary_learning_event(root, path.stem))
    return tuple(sorted(events, key=lambda event: (event.recorded_at, event.event_sha256)))


@dataclass(frozen=True)
class CaptureRequest:
    attempt_id: str
    application_id: str
    binding_sha256: str


class CaptureBackend(Protocol):
    def capture(self, request: CaptureRequest, recorder: ATSForensicRecorder) -> tuple[str, str | None]: ...


@dataclass(frozen=True)
class FixtureCaptureBackend:
    outcome: str = "prepared"
    failure_class: str | None = None

    def capture(self, request: CaptureRequest, recorder: ATSForensicRecorder) -> tuple[str, str | None]:
        del request
        recorder.checkpoint(self.outcome)
        return self.outcome, self.failure_class


def prepare_from_market(*, eligibility_receipt: bytes, evidence_reference_sha256: str, contact_reference_sha256: str) -> tuple[ApplicationSource, SanityReviewReceipt]:
    receipt = parse_eligibility_receipt(eligibility_receipt)
    if receipt["decision"] != "pass" or receipt["eligibility_authority"] is not True or receipt["application_authority"] is not False:
        raise ValueError("Market eligibility receipt does not permit faceless preparation")
    fields = {"profile_id": receipt["profile_id"], "job_key": receipt["job_key"], "eligibility_receipt_sha256": receipt["self_hash"], "fit_receipt_sha256": receipt["fit_receipt_self_hash"], "evidence_reference_sha256": _digest(evidence_reference_sha256, "evidence reference"), "contact_reference_sha256": _digest(contact_reference_sha256, "contact reference")}
    source = ApplicationSource(**fields, source_sha256=sha256(canonical_json(fields).encode()))
    artifact = sha256(canonical_json({"source": source.source_sha256, "opaque_preview_only": True}).encode())
    review = {"source_sha256": source.source_sha256, "artifact_set_sha256": artifact, "backend": "fixture_capture", "model": "deterministic-v1", "verdict": "pass"}
    return source, SanityReviewReceipt(**review, receipt_sha256=sha256(canonical_json(review).encode()))


def capture_or_recover(*, root: str | Path, attempt_id: str, application_id: str, source: ApplicationSource, sanity: SanityReviewReceipt, ats_name: str, backend: CaptureBackend | None = None) -> ATSForensicReceipt:
    _id(ats_name, "ATS name")
    if sanity.source_sha256 != source.source_sha256:
        raise ValueError("sanity receipt source differs")
    binding = sha256(canonical_json({"source": source.source_sha256, "sanity": sanity.receipt_sha256, "ats": ats_name}).encode())
    try:
        return load_forensic_receipt(root, attempt_id=attempt_id, application_id=application_id, binding_sha256=binding)
    except KeyError:
        pass
    recorder = ATSForensicRecorder(root, attempt_id=attempt_id, application_id=application_id, binding_sha256=binding)
    if ats_name != "fixture":
        recorder.checkpoint("blocked")
        return recorder.finalize(outcome="blocked", failure_class="unsupported_ats")
    outcome, failure = (backend or FixtureCaptureBackend()).capture(CaptureRequest(attempt_id, application_id, binding), recorder)
    return recorder.finalize(outcome=outcome, failure_class=failure)


@dataclass(frozen=True)
class AtsReadOnlyObservation:
    """A reconstructed, no-interaction view bound to one forensic receipt."""

    receipt: ATSForensicReceipt
    inventory: AtsFormInventory | None
    requested_application_url: str
    final_application_url: str
    job_key: str
    observation_authority_sha256: str
    network_evidence_sha256: str
    network_event_count: int
    transport: str = "local_fixture"
    acceptance_receipt_sha256: str | None = None
    navigation_admission_sha256: str | None = None
    blocked_interaction_attempts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.receipt) is not ATSForensicReceipt:
            raise TypeError("read-only ATS observation requires an exact forensic receipt")
        _observation_url(self.requested_application_url)
        _observation_url(self.final_application_url)
        _job_key(self.job_key)
        _digest(self.observation_authority_sha256, "ATS observation authority SHA-256")
        _digest(self.network_evidence_sha256, "ATS observation network evidence SHA-256")
        if isinstance(self.network_event_count, bool) or not isinstance(self.network_event_count, int) or self.network_event_count < 0:
            raise ValueError("ATS observation network event count differs")
        object.__setattr__(self, "blocked_interaction_attempts", tuple(self.blocked_interaction_attempts))
        if self.transport not in {"local_fixture", "public_https"}:
            raise ValueError("ATS observation transport differs")
        if self.transport == "public_https":
            _digest(self.acceptance_receipt_sha256, "ATS acceptance receipt SHA-256")
            _digest(self.navigation_admission_sha256, "ATS navigation admission SHA-256")
        elif self.acceptance_receipt_sha256 is not None or self.navigation_admission_sha256 is not None:
            raise ValueError("local ATS observation carries public authority evidence")
        if any(attempt not in _READ_ONLY_ATTEMPTS for attempt in self.blocked_interaction_attempts):
            raise ValueError("ATS observation blocked interaction evidence differs")


def _network_route_sha256(value: object) -> str:
    if not isinstance(value, str):
        return sha256(b"invalid-network-route")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return sha256(b"invalid-network-route")
    netloc = parsed.hostname.casefold() if parsed.port is None else f"{parsed.hostname.casefold()}:{parsed.port}"
    return sha256(urlunsplit((parsed.scheme.casefold(), netloc, parsed.path or "/", "", "")).encode())


def _observed_fields(rows: object) -> tuple[AtsObservedField, ...]:
    if not isinstance(rows, list) or not rows:
        raise ValueError("ATS fixture form has no observable controls")
    grouped: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "field_id", "control_kind", "label", "required", "visible", "disabled",
            "read_only", "multiple", "options",
        } or not isinstance(row["options"], list):
            raise ValueError("ATS fixture control is malformed")
        field_id = _ats_text(row["field_id"], "ATS field ID", maximum=512)
        if row["control_kind"] not in _ATS_CONTROL_KINDS:
            raise ValueError("ATS fixture control kind is unsupported")
        for name in ("required", "visible", "disabled", "read_only", "multiple"):
            if type(row[name]) is not bool:
                raise ValueError("ATS fixture control state is malformed")
        if row["control_kind"] not in {"radio", "checkbox"} and field_id in grouped:
            raise ValueError("ATS fixture control identity is ambiguous")
        grouped.setdefault(field_id, []).append(row)
    fields: list[AtsObservedField] = []
    for field_id, controls in grouped.items():
        first = controls[0]
        kind = first["control_kind"]
        if any(control["control_kind"] != kind for control in controls):
            raise ValueError("ATS fixture control identity has conflicting kinds")
        if len(controls) > 1 and kind not in {"radio", "checkbox"}:
            raise ValueError("ATS fixture control identity is duplicated")
        options: list[AtsFieldOption] = []
        for control in controls:
            for option in control["options"]:
                if not isinstance(option, dict) or set(option) != {"value", "label"}:
                    raise ValueError("ATS fixture option is malformed")
                options.append(AtsFieldOption(option["value"], option["label"]))
        visible = any(control["visible"] for control in controls)
        disabled = any(control["disabled"] for control in controls)
        read_only = any(control["read_only"] for control in controls)
        if kind == "hidden" or not visible:
            role = "honeypot"
        elif disabled or read_only:
            role = "provider_managed"
        else:
            role = "applicant"
        fields.append(AtsObservedField(
            field_id=field_id,
            control_kind=kind,
            label=next((str(control["label"]) for control in controls if control["label"]), field_id),
            required=any(control["required"] for control in controls),
            visible=visible,
            automation_role=role,
            disabled=disabled,
            read_only=read_only,
            multiple=any(control["multiple"] for control in controls),
            options=tuple(options),
        ))
    return tuple(sorted(fields, key=lambda field: field.field_id))


def _observation_from_receipt(
    root: str | Path,
    receipt: ATSForensicReceipt,
) -> AtsReadOnlyObservation:
    path, identity = _root(root, create=False)
    if identity != receipt.root_identity:
        raise ValueError("ATS observation root identity differs")
    manifest = _canonical(_read(_manifests(path, create=False) / f"{receipt.attempt_id}.json"))
    if sha256((canonical_json(manifest) + "\n").encode()) != receipt.manifest_sha256:
        raise ValueError("ATS observation manifest identity differs")
    payload = _manifest_observation(manifest, receipt)
    if payload is None:
        raise ValueError("forensic receipt has no read-only ATS observation")
    inventory, terminal_failure = _observation_payload(payload)
    if terminal_failure != receipt.failure_class:
        raise ValueError("ATS observation terminal binding differs")
    return AtsReadOnlyObservation(
        receipt=receipt,
        inventory=inventory,
        requested_application_url=str(payload["requested_application_url"]),
        final_application_url=str(payload["final_application_url"]),
        job_key=str(payload["job_key"]),
        observation_authority_sha256=str(payload["authority_sha256"]),
        network_evidence_sha256=str(payload["network_evidence_sha256"]),
        network_event_count=int(payload["network_event_count"]),
        transport=str(payload.get("transport", "local_fixture")),
        acceptance_receipt_sha256=(
            str(payload["acceptance_receipt_sha256"])
            if "acceptance_receipt_sha256" in payload
            else None
        ),
        navigation_admission_sha256=(
            str(payload["navigation_admission_sha256"])
            if "navigation_admission_sha256" in payload
            else None
        ),
        blocked_interaction_attempts=tuple(payload["blocked_interaction_attempts"]),
    )


def observe_ats_form_or_recover(
    *,
    root: str | Path,
    attempt_id: str,
    application_id: str,
    source: ApplicationSource,
    sanity: SanityReviewReceipt,
    ats_name: str,
    authority: AtsObservationAuthority,
    captured_at: str,
    fixture_html: str | None = None,
    acceptance_receipt: AtsObservationAcceptanceReceipt | None = None,
    acceptance_envelope_path: str | Path | None = None,
    acceptance_public_key_path: str | Path | None = None,
    acceptance_consumption_root: str | Path | None = None,
    _test_tls_spki_sha256_b64: str | None = None,
    _test_crash_after_navigation: bool = False,
) -> AtsReadOnlyObservation:
    """Observe one authority-bound route without input, upload, click, or submission.

    The default transport remains the accepted ``localhost`` fixture. A public
    HTTPS target is observed only when an externally signed, fully consumed
    market-observation acceptance receipt is supplied and reverified through
    the canonical verifier; there is no second, weaker authority path.
    """
    if type(authority) is not AtsObservationAuthority:
        raise TypeError("ATS observation requires exact typed authority")
    acceptance_arguments = (
        acceptance_receipt,
        acceptance_envelope_path,
        acceptance_public_key_path,
        acceptance_consumption_root,
    )
    if authority.local_fixture_only is not True:
        if any(value is None for value in acceptance_arguments):
            raise PermissionError("public ATS observation requires an external verified operator capability")
        if fixture_html is not None:
            raise ValueError("public ATS observation cannot use fixture HTML")
        return _observe_public_ats_form_or_recover(
            root=root,
            attempt_id=attempt_id,
            application_id=application_id,
            source=source,
            sanity=sanity,
            ats_name=ats_name,
            authority=authority,
            captured_at=captured_at,
            acceptance_receipt=acceptance_receipt,
            acceptance_envelope_path=acceptance_envelope_path,
            acceptance_public_key_path=acceptance_public_key_path,
            acceptance_consumption_root=acceptance_consumption_root,
            test_tls_spki_sha256_b64=_test_tls_spki_sha256_b64,
            crash_after_navigation=_test_crash_after_navigation,
        )
    if any(value is not None for value in acceptance_arguments) or _test_tls_spki_sha256_b64 is not None or _test_crash_after_navigation:
        raise ValueError("local ATS fixture cannot consume public observation authority")
    authority.require_local_fixture()
    if authority.job_key != source.job_key:
        raise ValueError("ATS observation authority job differs from application source")
    if fixture_html is None or not isinstance(fixture_html, str) or not fixture_html or len(fixture_html.encode()) > authority.max_snapshot_bytes or "\x00" in fixture_html:
        raise ValueError("local ATS fixture body is outside authority limits")
    _ats_time(captured_at)
    _id(ats_name, "ATS name")
    if ats_name != "fixture" or sanity.source_sha256 != source.source_sha256:
        raise ValueError("ATS observation source binding differs")
    application_url = _observation_url(authority.application_url)
    binding = sha256(canonical_json({
        "source": source.source_sha256,
        "sanity": sanity.receipt_sha256,
        "ats": ats_name,
        "job_key": authority.job_key,
        "application_url": application_url,
        "authority": authority.authority_sha256,
    }).encode())
    try:
        return _observation_from_receipt(
            root,
            load_forensic_receipt(root, attempt_id=attempt_id, application_id=application_id, binding_sha256=binding),
        )
    except KeyError:
        pass
    recorder = ATSForensicRecorder(root, attempt_id=attempt_id, application_id=application_id, binding_sha256=binding)
    network_events: list[dict[str, object]] = []
    network_overflow = False
    final_url = application_url
    snapshot = sha256(b"")
    inventory: AtsFormInventory | None = None
    failure: str | None = None
    blocked_interaction_attempts: list[str] = []
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
    except ImportError:
        failure = "observation_indeterminate"
    else:
        with sync_playwright() as playwright:
            browser = None
            context = None

            def route_handler(route) -> None:
                route.fulfill(status=200, content_type="text/html; charset=utf-8", body=fixture_html)

            def record_response(response) -> None:
                nonlocal network_overflow
                if len(network_events) >= authority.max_network_events:
                    network_overflow = True
                    return
                request = response.request
                network_events.append({
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "status": response.status,
                    "route_sha256": _network_route_sha256(response.url),
                })

            try:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context()
                context.add_init_script(_READ_ONLY_GUARD_SCRIPT)
                page = context.new_page()
                page.route("**/*", route_handler)
                page.on("response", record_response)
                page.goto(application_url, wait_until="domcontentloaded", timeout=authority.timeout_ms)
                try:
                    final_url = _observation_url(page.url)
                except ValueError:
                    failure = "redirect_detected"
                raw_snapshot = page.content().encode()
                snapshot = sha256(raw_snapshot)
                if len(raw_snapshot) > authority.max_snapshot_bytes or network_overflow:
                    failure = "observation_indeterminate"
                blockers = page.locator("body, input[type=password], iframe").evaluate_all(
                    _ATS_BLOCKER_SCRIPT
                )
                if blockers["password"]:
                    failure = "identity_required"
                elif blockers["captcha"] or blockers["login"]:
                    failure = "human_verification"
                elif failure is None:
                    rows = page.locator("form input, form textarea, form select").evaluate_all(
                        _ATS_INVENTORY_SCRIPT
                    )
                    inventory = AtsFormInventory(
                        provider="fixture",
                        application_url=final_url,
                        captured_at=captured_at,
                        page_snapshot_sha256=snapshot,
                        screenshot_sha256s=(),
                        fields=_observed_fields(rows),
                    )
                attempts = page.evaluate("() => window.__marketAlignerReadOnly.attempts.slice()")
                if not isinstance(attempts, list) or any(
                    attempt not in _READ_ONLY_ATTEMPTS
                    for attempt in attempts
                ):
                    raise ValueError("read-only browser guard evidence is malformed")
                blocked_interaction_attempts = list(attempts)
                if blocked_interaction_attempts:
                    failure = "read_only_interaction_attempted"
                    inventory = None
            except PlaywrightTimeoutError:
                failure = "provider_timeout"
            finally:
                if context is not None:
                    context.close()
                if browser is not None:
                    browser.close()
    network_document = sorted(network_events, key=canonical_json)
    payload: dict[str, object] = {
        "schema_version": _OBSERVATION_SCHEMA,
        "provider": "fixture",
        "requested_application_url": application_url,
        "final_application_url": final_url,
        "job_key": authority.job_key,
        "authority_sha256": authority.authority_sha256,
        "captured_at": captured_at,
        "page_snapshot_sha256": snapshot,
        "inventory": None if inventory is None else inventory.document(),
        "inventory_sha256": None if inventory is None else inventory.content_sha256,
        "network_evidence_sha256": sha256(canonical_json(network_document).encode()),
        "network_event_count": len(network_events),
        "interaction_counts": {"click": 0, "fill": 0, "submit": 0, "type": 0, "upload": 0},
        "blocked_interaction_attempts": blocked_interaction_attempts,
        "terminal_failure_class": failure,
        "diagnostic_only": True,
        "raw_payloads_persisted": False,
        "identity_authority": False,
        "release_authority": False,
        "submission_authority": False,
    }
    recorder.checkpoint(_OBSERVATION_CHECKPOINT, observation=payload)
    try:
        receipt = recorder.finalize(outcome="prepared" if failure is None else "blocked", failure_class=failure)
    except FileExistsError as exc:
        if str(exc) != "forensic attempt ID already has evidence":
            raise
        receipt = load_forensic_receipt(root, attempt_id=attempt_id, application_id=application_id, binding_sha256=binding)
    return _observation_from_receipt(root, receipt)


def _public_observation_policy() -> tuple[dict[str, object], str]:
    """Describe the bounded browser policy truthfully for the default launch.

    The observer launches Playwright's default bundled Chromium (no channel
    override). WebSocket, storage, cookie, popup and download denial is
    enforced by page-script guards and recorded event accounting, not by a
    claim of total network mediation.
    """
    policy: dict[str, object] = {
        "schema_version": "market-aligner.public-ats-browser-policy.v1",
        "browser_family": "chromium",
        "browser_channel": "default",
        "ephemeral_context": True,
        "accepted_methods": ["GET", "HEAD"],
        "allowed_document_count": 1,
        "allowed_static_resource_types": ["font", "image", "script", "stylesheet"],
        "same_origin_only": True,
        "downloads": False,
        "extensions": False,
        "inherited_storage": False,
        "popups": False,
        "proxy_credentials": False,
        "service_workers": False,
        "websockets": False,
        "identity_authority": False,
        "submission_authority": False,
    }
    return policy, sha256(canonical_json(policy).encode())


def _public_observation_payload(
    *,
    ats_name: str,
    authority: AtsObservationAuthority,
    acceptance: AtsObservationAcceptanceReceipt,
    admission: _PublicObservationAdmission,
    captured_at: str,
    final_url: str,
    page_snapshot_sha256: str,
    inventory: AtsFormInventory | None,
    network_events: list[dict[str, object]],
    blocked_attempts: list[str],
    blocked_counts: dict[str, int],
    context_postconditions: dict[str, int],
    browser_policy_sha256: str,
    browser_revision_sha256: str,
    allowed_origin_sha256: str,
    browser_launch_performed: bool,
    recovered_without_renavigation: bool,
    failure: str | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": _PUBLIC_OBSERVATION_SCHEMA,
        "provider": ats_name,
        "requested_application_url": authority.application_url,
        "final_application_url": final_url,
        "job_key": authority.job_key,
        "authority_sha256": authority.authority_sha256,
        "captured_at": captured_at,
        "page_snapshot_sha256": page_snapshot_sha256,
        "inventory": None if inventory is None else inventory.document(),
        "inventory_sha256": None if inventory is None else inventory.content_sha256,
        "network_evidence_sha256": sha256(
            canonical_json(sorted(network_events, key=canonical_json)).encode()
        ),
        "network_event_count": len(network_events),
        "interaction_counts": {"click": 0, "fill": 0, "submit": 0, "type": 0, "upload": 0},
        "blocked_interaction_attempts": sorted(set(blocked_attempts)),
        "terminal_failure_class": failure,
        "transport": "public_https",
        "acceptance_receipt_sha256": acceptance.receipt_sha256,
        "acceptance_envelope_sha256": acceptance.envelope_sha256,
        "acceptance_signature_sha256": acceptance.signature_sha256,
        "consumption_root_sha256": acceptance.consumption_root_sha256,
        "navigation_admission_sha256": admission.admission_sha256,
        "browser_policy_sha256": browser_policy_sha256,
        "browser_revision_sha256": browser_revision_sha256,
        "allowed_origin_sha256": allowed_origin_sha256,
        "navigation_admitted": True,
        "browser_launch_performed": browser_launch_performed,
        "recovered_without_renavigation": recovered_without_renavigation,
        "capture_complete": failure is None,
        "blocked_request_counts": blocked_counts,
        "context_postconditions": context_postconditions,
        "diagnostic_only": True,
        "raw_payloads_persisted": False,
        "identity_authority": False,
        "release_authority": False,
        "submission_authority": False,
    }
    _observation_payload(payload)
    return payload


def _observe_public_ats_form_or_recover(
    *,
    root: str | Path,
    attempt_id: str,
    application_id: str,
    source: ApplicationSource,
    sanity: SanityReviewReceipt,
    ats_name: str,
    authority: AtsObservationAuthority,
    captured_at: str,
    acceptance_receipt: AtsObservationAcceptanceReceipt,
    acceptance_envelope_path: str | Path,
    acceptance_public_key_path: str | Path,
    acceptance_consumption_root: str | Path,
    test_tls_spki_sha256_b64: str | None,
    crash_after_navigation: bool,
) -> AtsReadOnlyObservation:
    """Run one authenticated, GET-only public observation in the existing owner."""

    if type(source) is not ApplicationSource or type(sanity) is not SanityReviewReceipt:
        raise TypeError("public ATS observation requires exact application authority types")
    if authority.authority_state != "pending" or authority.local_fixture_only is not False:
        raise ValueError("public ATS observation requires a pending public request descriptor")
    if authority.job_key != source.job_key or sanity.source_sha256 != source.source_sha256:
        raise ValueError("public ATS observation source binding differs")
    _ats_time(captured_at)
    _id(attempt_id, "attempt ID")
    _id(application_id, "application ID")
    _id(ats_name, "ATS name")
    if ats_name not in _ATS_PROVIDERS or ats_name == "fixture":
        raise ValueError("public ATS observation provider differs")
    if type(crash_after_navigation) is not bool:
        raise TypeError("public ATS observation crash injection must be bool")
    hostname = urlsplit(authority.application_url).hostname
    if test_tls_spki_sha256_b64 is not None:
        if hostname != "localhost" or not _TEST_TLS_SPKI.fullmatch(test_tls_spki_sha256_b64):
            raise ValueError("test TLS exception must bind one localhost SPKI identity")
    if crash_after_navigation and hostname != "localhost":
        raise ValueError("crash injection is restricted to the localhost transport test")
    acceptance = verify_consumed_market_observation_acceptance(
        authority,
        acceptance_receipt,
        envelope_path=acceptance_envelope_path,
        public_key_path=acceptance_public_key_path,
        consumption_root=acceptance_consumption_root,
    )
    policy, policy_sha256 = _public_observation_policy()
    del policy
    parsed_target = urlsplit(authority.application_url)
    allowed_origin = urlunsplit((parsed_target.scheme, parsed_target.netloc, "", "", ""))
    allowed_origin_sha256 = sha256(allowed_origin.encode())
    operation_sha256 = sha256(canonical_json({
        "schema_version": "market-aligner.public-ats-operation.v1",
        "attempt_id": attempt_id,
        "application_id": application_id,
        "source_sha256": source.source_sha256,
        "sanity_receipt_sha256": sanity.receipt_sha256,
        "ats_name": ats_name,
        "job_key": authority.job_key,
        "application_url": authority.application_url,
        "authority_sha256": authority.authority_sha256,
        "acceptance_receipt_sha256": acceptance.receipt_sha256,
        "acceptance_envelope_sha256": acceptance.envelope_sha256,
        "acceptance_signature_sha256": acceptance.signature_sha256,
        "consumption_root_sha256": acceptance.consumption_root_sha256,
        "browser_policy_sha256": policy_sha256,
        "allowed_origin_sha256": allowed_origin_sha256,
    }).encode())
    consumption_path, consumption_identity = _root(
        acceptance_consumption_root,
        create=False,
    )
    if consumption_identity != acceptance.root_identity:
        raise ValueError("public ATS observation replay root differs")
    now = _utc_now()
    _ats_time(now)
    store = _open_owned_store(
        consumption_path,
        consumption_identity,
        directory_name=_PUBLIC_OBSERVATION_ADMISSION_DIRECTORY,
        label="public ATS observation admission store",
        create=False,
    )
    if store is None:
        if not acceptance.not_before <= now < acceptance.expires_at:
            raise ValueError("public ATS observation acceptance is outside its validity window")
        store = _open_owned_store(
            consumption_path,
            consumption_identity,
            directory_name=_PUBLIC_OBSERVATION_ADMISSION_DIRECTORY,
            label="public ATS observation admission store",
            create=True,
        )
    elif not acceptance.not_before <= now < acceptance.expires_at:
        try:
            _read_acceptance_at(store, f"{attempt_id}.json")
        except FileNotFoundError:
            store.close()
            raise ValueError(
                "public ATS observation acceptance is outside its validity window"
            ) from None
    assert store is not None
    lock_fd = _public_observation_lock(store, attempt_id)
    try:
        admission, created = _public_observation_admit(
            store,
            attempt_id=attempt_id,
            application_id=application_id,
            operation_sha256=operation_sha256,
            source=source,
            sanity=sanity,
            ats_name=ats_name,
            authority=authority,
            acceptance=acceptance,
        )
        binding_sha256 = sha256(canonical_json({
            "operation_sha256": operation_sha256,
            "navigation_admission_sha256": admission.admission_sha256,
        }).encode())
        try:
            existing = load_forensic_receipt(
                root,
                attempt_id=attempt_id,
                application_id=application_id,
                binding_sha256=binding_sha256,
            )
        except KeyError:
            existing = None
        if existing is not None:
            return _observation_from_receipt(root, existing)
        recorder = ATSForensicRecorder(
            root,
            attempt_id=attempt_id,
            application_id=application_id,
            binding_sha256=binding_sha256,
        )
        blocked_counts = {
            "cookie": 0,
            "cross_origin": 0,
            "download": 0,
            "method": 0,
            "network": 0,
            "popup": 0,
            "redirect": 0,
            "storage": 0,
            "submit": 0,
            "websocket": 0,
        }
        postconditions = {
            "cookie_count": 0,
            "download_count": 0,
            "local_storage_count": 0,
            "page_count": 0,
            "session_storage_count": 0,
        }
        if not created:
            payload = _public_observation_payload(
                ats_name=ats_name,
                authority=authority,
                acceptance=acceptance,
                admission=admission,
                captured_at=captured_at,
                final_url=authority.application_url,
                page_snapshot_sha256=sha256(b""),
                inventory=None,
                network_events=[],
                blocked_attempts=[],
                blocked_counts=blocked_counts,
                context_postconditions=postconditions,
                browser_policy_sha256=policy_sha256,
                browser_revision_sha256=sha256(b"not-observed"),
                allowed_origin_sha256=allowed_origin_sha256,
                browser_launch_performed=False,
                recovered_without_renavigation=True,
                failure="observation_indeterminate",
            )
            recorder.checkpoint(_OBSERVATION_CHECKPOINT, observation=payload)
            receipt = recorder.finalize(
                outcome="blocked",
                failure_class="observation_indeterminate",
            )
            return _observation_from_receipt(root, receipt)

        network_events: list[dict[str, object]] = []
        blocked_attempts: list[str] = []
        final_url = authority.application_url
        snapshot_sha256 = sha256(b"")
        inventory: AtsFormInventory | None = None
        failure: str | None = None
        browser_revision_sha256 = sha256(b"not-observed")
        browser_launch_performed = False
        network_overflow = False
        document_request_seen = False
        non_guard_page_error = False

        def mark(category: str, attempt: str) -> None:
            blocked_counts[category] += 1
            blocked_attempts.append(attempt)

        def network_event(value: dict[str, object]) -> bool:
            nonlocal network_overflow
            if len(network_events) >= authority.max_network_events:
                network_overflow = True
                return False
            network_events.append(value)
            return True

        try:
            from playwright.sync_api import (
                Error as PlaywrightError,
                TimeoutError as PlaywrightTimeoutError,
                sync_playwright,
            )
        except ImportError:
            failure = "observation_indeterminate"
        else:
            try:
                with sync_playwright() as playwright:
                    browser = None
                    context = None
                    page = None
                    try:
                        launch_args = [
                            "--disable-background-networking",
                            "--disable-component-update",
                            "--disable-extensions",
                            "--disable-sync",
                            "--no-proxy-server",
                        ]
                        if test_tls_spki_sha256_b64 is not None:
                            launch_args.append(
                                "--ignore-certificate-errors-spki-list="
                                f"{test_tls_spki_sha256_b64}"
                            )
                        browser = playwright.chromium.launch(
                            headless=True,
                            args=launch_args,
                        )
                        browser_launch_performed = True
                        browser_revision_sha256 = sha256(
                            f"chromium:{browser.version}".encode()
                        )
                        context = browser.new_context(
                            accept_downloads=False,
                            service_workers="block",
                        )
                        context.clear_cookies()
                        context.clear_permissions()
                        if context.cookies():
                            raise ValueError("public ATS browser context inherited cookies")
                        context.add_init_script(_READ_ONLY_GUARD_SCRIPT)
                        page = context.new_page()

                        def route_handler(route) -> None:
                            nonlocal document_request_seen
                            request = route.request
                            method = request.method.upper()
                            resource_type = request.resource_type
                            request_url = request.url
                            parsed = urlsplit(request_url)
                            request_origin = urlunsplit(
                                (parsed.scheme.casefold(), parsed.netloc.casefold(), "", "", "")
                            )
                            is_navigation = request.is_navigation_request()
                            disposition = "allowed"
                            category: str | None = None
                            attempt = "network"
                            if method not in {"GET", "HEAD"}:
                                disposition = "blocked_method"
                                category = "method"
                                attempt = "submit" if is_navigation else "network"
                                if is_navigation:
                                    blocked_counts["submit"] += 1
                            elif request_origin != allowed_origin:
                                disposition = "blocked_cross_origin"
                                category = "cross_origin"
                            elif is_navigation:
                                if (
                                    request_url != authority.application_url
                                    or request.frame != page.main_frame
                                    or document_request_seen
                                ):
                                    disposition = "blocked_redirect"
                                    category = "redirect"
                                    attempt = "redirect"
                                else:
                                    document_request_seen = True
                            elif resource_type not in {"font", "image", "script", "stylesheet"}:
                                disposition = "blocked_resource_type"
                                category = "network"
                            if not network_event({
                                "phase": "request",
                                "method": method,
                                "resource_type": resource_type,
                                "route_sha256": _network_route_sha256(request_url),
                                "disposition": disposition,
                            }):
                                category = "network"
                                attempt = "network"
                            if category is not None:
                                mark(category, attempt)
                                route.abort("blockedbyclient")
                            else:
                                route.continue_()

                        def response_handler(response) -> None:
                            if 300 <= response.status < 400:
                                mark("redirect", "redirect")
                            network_event({
                                "phase": "response",
                                "method": response.request.method.upper(),
                                "resource_type": response.request.resource_type,
                                "route_sha256": _network_route_sha256(response.url),
                                "status": response.status,
                            })

                        def page_error_handler(error) -> None:
                            nonlocal non_guard_page_error
                            if "market-aligner-read-only:" not in str(error):
                                non_guard_page_error = True

                        def popup_handler(popup) -> None:
                            mark("popup", "popup")
                            try:
                                popup.close()
                            except PlaywrightError:
                                pass

                        def download_handler(download) -> None:
                            postconditions["download_count"] += 1
                            mark("download", "download")
                            try:
                                download.cancel()
                            except PlaywrightError:
                                pass

                        def websocket_handler(_socket) -> None:
                            mark("websocket", "websocket")

                        context.route("**/*", route_handler)
                        page.on("response", response_handler)
                        page.on("pageerror", page_error_handler)
                        page.on("popup", popup_handler)
                        page.on("download", download_handler)
                        page.on("websocket", websocket_handler)
                        page.goto(
                            authority.application_url,
                            wait_until="domcontentloaded",
                            timeout=authority.timeout_ms,
                        )
                        if crash_after_navigation:
                            raise RuntimeError(
                                "injected crash after public ATS navigation"
                            )
                        page.wait_for_timeout(min(100, authority.timeout_ms))
                        try:
                            final_url = _observation_url(page.url)
                        except ValueError:
                            final_url = authority.application_url
                            mark("redirect", "redirect")
                        if final_url != authority.application_url:
                            mark("redirect", "redirect")
                        snapshot = page.content().encode()
                        snapshot_sha256 = sha256(snapshot)
                        if len(snapshot) > authority.max_snapshot_bytes:
                            failure = "observation_indeterminate"
                        guard_attempts = page.evaluate(
                            "() => window.__marketAlignerReadOnly.attempts.slice()"
                        )
                        if not isinstance(guard_attempts, list) or any(
                            attempt not in _READ_ONLY_ATTEMPTS
                            for attempt in guard_attempts
                        ):
                            raise ValueError("public ATS browser guard evidence is malformed")
                        blocked_attempts.extend(guard_attempts)
                        for attempt in guard_attempts:
                            if attempt in {"cookie", "storage", "websocket", "popup"}:
                                blocked_counts[attempt] += 1
                            elif attempt == "submit":
                                blocked_counts["submit"] += 1
                            elif attempt == "network":
                                blocked_counts["network"] += 1
                        cookies = context.cookies()
                        postconditions["cookie_count"] = len(cookies)
                        if cookies:
                            mark("cookie", "cookie")
                            context.clear_cookies()
                        storage = page.evaluate(
                            "() => ({local: localStorage.length, session: sessionStorage.length})"
                        )
                        if not isinstance(storage, dict) or set(storage) != {"local", "session"}:
                            raise ValueError("public ATS browser storage evidence is malformed")
                        postconditions["local_storage_count"] = int(storage["local"])
                        postconditions["session_storage_count"] = int(storage["session"])
                        if storage["local"] or storage["session"]:
                            mark("storage", "storage")
                        postconditions["page_count"] = len(context.pages)
                        if postconditions["page_count"] != 1:
                            mark("popup", "popup")
                        blockers = page.locator(
                            "body, input[type=password], iframe"
                        ).evaluate_all(_ATS_BLOCKER_SCRIPT)
                        if not isinstance(blockers, dict) or set(blockers) != {
                            "password", "captcha", "login"
                        }:
                            raise ValueError("public ATS blocker evidence is malformed")
                        if blockers["password"] or blockers["login"]:
                            failure = "identity_required"
                        elif blockers["captcha"]:
                            failure = "human_verification"
                        elif blocked_counts["redirect"] or blocked_counts["cross_origin"]:
                            failure = "redirect_detected"
                        elif blocked_attempts or any(blocked_counts.values()):
                            failure = "read_only_interaction_attempted"
                        elif network_overflow or non_guard_page_error:
                            failure = "observation_indeterminate"
                        elif failure is None:
                            rows = page.locator(
                                "form input, form textarea, form select"
                            ).evaluate_all(_ATS_INVENTORY_SCRIPT)
                            inventory = AtsFormInventory(
                                provider=ats_name,
                                application_url=final_url,
                                captured_at=captured_at,
                                page_snapshot_sha256=snapshot_sha256,
                                screenshot_sha256s=(),
                                fields=_observed_fields(rows),
                            )
                    finally:
                        if context is not None:
                            context.close()
                        if browser is not None:
                            browser.close()
            except PlaywrightTimeoutError:
                failure = "provider_timeout"
            except PlaywrightError:
                if blocked_attempts or any(blocked_counts.values()):
                    failure = (
                        "redirect_detected"
                        if blocked_counts["redirect"] or blocked_counts["cross_origin"]
                        else "read_only_interaction_attempted"
                    )
                else:
                    raise
        if failure is not None:
            inventory = None
        payload = _public_observation_payload(
            ats_name=ats_name,
            authority=authority,
            acceptance=acceptance,
            admission=admission,
            captured_at=captured_at,
            final_url=final_url,
            page_snapshot_sha256=snapshot_sha256,
            inventory=inventory,
            network_events=network_events,
            blocked_attempts=blocked_attempts,
            blocked_counts=blocked_counts,
            context_postconditions=postconditions,
            browser_policy_sha256=policy_sha256,
            browser_revision_sha256=browser_revision_sha256,
            allowed_origin_sha256=allowed_origin_sha256,
            browser_launch_performed=browser_launch_performed,
            recovered_without_renavigation=False,
            failure=failure,
        )
        recorder.checkpoint(_OBSERVATION_CHECKPOINT, observation=payload)
        try:
            receipt = recorder.finalize(
                outcome="prepared" if failure is None else "blocked",
                failure_class=failure,
            )
        except FileExistsError as exc:
            if str(exc) != "forensic attempt ID already has evidence":
                raise
            receipt = load_forensic_receipt(
                root,
                attempt_id=attempt_id,
                application_id=application_id,
                binding_sha256=binding_sha256,
            )
        return _observation_from_receipt(root, receipt)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
            store.close()


_PRE_SUBMIT_ACTIONS = frozenset({"fill", "select", "check", "upload"})


@dataclass(frozen=True)
class AtsPreSubmitField:
    """A value-hash-bound local-fixture action; raw input stays in memory only."""

    field_id: str
    action: str
    value_sha256: str

    def __post_init__(self) -> None:
        _ats_text(self.field_id, "ATS pre-submit field ID", maximum=512)
        if self.action not in _PRE_SUBMIT_ACTIONS:
            raise ValueError("ATS pre-submit action is unsupported")
        _digest(self.value_sha256, "ATS pre-submit value SHA-256")

    def document(self) -> dict[str, str]:
        return {"field_id": self.field_id, "action": self.action, "value_sha256": self.value_sha256}


def _pre_submit_plan_sha256(fields: tuple[AtsPreSubmitField, ...]) -> str:
    return sha256(canonical_json({"schema_version": "market-aligner.ats-pre-submit-plan.v1", "fields": [field.document() for field in fields]}).encode())


@dataclass(frozen=True)
class AtsFixturePreSubmitAuthority:
    """Local synthetic pre-submit capability, explicitly excluding identity and submit."""

    job_key: str
    application_url: str
    observation_manifest_sha256: str
    inventory_sha256: str
    plan_sha256: str
    authority_sha256: str
    local_fixture_only: bool = True
    synthetic_values_only: bool = True
    identity_authority: bool = False
    vault_authority: bool = False
    submission_authority: bool = False
    schema_version: str = "market-aligner.ats-fixture-pre-submit-authority.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "market-aligner.ats-fixture-pre-submit-authority.v1":
            raise ValueError("ATS pre-submit authority schema differs")
        _job_key(self.job_key)
        if _observation_url(self.application_url) != self.application_url or urlsplit(self.application_url).hostname != "localhost":
            raise ValueError("ATS pre-submit authority must bind localhost exactly")
        for name in ("observation_manifest_sha256", "inventory_sha256", "plan_sha256", "authority_sha256"):
            _digest(getattr(self, name), name)
        if (self.local_fixture_only, self.synthetic_values_only, self.identity_authority, self.vault_authority, self.submission_authority) != (True, True, False, False, False):
            raise ValueError("ATS pre-submit authority exceeds local faceless scope")
        if self.authority_sha256 != sha256(canonical_json(self.document(include_hash=False)).encode()):
            raise ValueError("ATS pre-submit authority identity differs")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        value = {
            "schema_version": self.schema_version, "job_key": self.job_key,
            "application_url": self.application_url,
            "observation_manifest_sha256": self.observation_manifest_sha256,
            "inventory_sha256": self.inventory_sha256, "plan_sha256": self.plan_sha256,
            "local_fixture_only": self.local_fixture_only, "synthetic_values_only": self.synthetic_values_only,
            "identity_authority": self.identity_authority, "vault_authority": self.vault_authority,
            "submission_authority": self.submission_authority,
        }
        if include_hash:
            value["authority_sha256"] = self.authority_sha256
        return value


def compile_fixture_pre_submit_plan(
    observation: AtsReadOnlyObservation,
    values: Mapping[str, bytes],
) -> tuple[AtsPreSubmitField, ...]:
    """Compile only typed synthetic fixture actions from a sanitized inventory."""
    if type(observation) is not AtsReadOnlyObservation or observation.inventory is None:
        raise ValueError("ATS pre-submit requires a prepared read-only observation")
    if observation.receipt.outcome != "prepared":
        raise ValueError("blocked ATS observations cannot be prepared")
    fields: list[AtsPreSubmitField] = []
    actionable = {"text": "fill", "email": "fill", "tel": "fill", "url": "fill", "textarea": "fill", "number": "fill", "select": "select", "radio": "check", "checkbox": "check", "file": "upload"}
    inventory = {field.field_id: field for field in observation.inventory.fields}
    if set(values) - set(inventory):
        raise ValueError("ATS pre-submit values include an unknown field")
    for field_id, field in inventory.items():
        value = values.get(field_id)
        if field.automation_role != "applicant":
            if value is not None:
                raise ValueError("ATS pre-submit cannot target a non-applicant field")
            continue
        action = actionable.get(field.control_kind)
        if value is None:
            if field.required:
                raise ValueError("ATS pre-submit lacks a required fixture value")
            continue
        if action is None or not isinstance(value, bytes) or not value or len(value) > 65_536:
            raise ValueError("ATS pre-submit fixture value is unsupported")
        fields.append(AtsPreSubmitField(field_id, action, sha256(value)))
    return tuple(sorted(fields, key=lambda field: field.field_id))


def execute_fixture_pre_submit_or_recover(
    *,
    root: str | Path,
    attempt_id: str,
    application_id: str,
    observation: AtsReadOnlyObservation,
    authority: AtsFixturePreSubmitAuthority,
    values: Mapping[str, bytes],
    fixture_html: str,
    injected_crash_after_action: int | None = None,
) -> ATSForensicReceipt:
    """Run synthetic local fill/upload preparation and stop before every click/submit boundary."""
    if type(authority) is not AtsFixturePreSubmitAuthority or type(observation) is not AtsReadOnlyObservation:
        raise TypeError("ATS pre-submit requires exact typed inputs")
    plan = compile_fixture_pre_submit_plan(observation, values)
    plan_sha256 = _pre_submit_plan_sha256(plan)
    inventory = observation.inventory
    assert inventory is not None
    if authority.job_key != observation.job_key or authority.application_url != observation.final_application_url or authority.observation_manifest_sha256 != observation.receipt.manifest_sha256 or authority.inventory_sha256 != inventory.content_sha256 or authority.plan_sha256 != plan_sha256:
        raise ValueError("ATS pre-submit authority binding differs")
    if not isinstance(fixture_html, str) or not fixture_html or "\x00" in fixture_html:
        raise ValueError("ATS pre-submit fixture is malformed")
    binding = sha256(canonical_json({"observation_receipt": observation.receipt.receipt_sha256, "authority": authority.authority_sha256, "plan": plan_sha256}).encode())
    try:
        return load_forensic_receipt(root, attempt_id=attempt_id, application_id=application_id, binding_sha256=binding)
    except KeyError:
        pass
    recorder = ATSForensicRecorder(root, attempt_id=attempt_id, application_id=application_id, binding_sha256=binding)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        recorder.checkpoint("blocked")
        return recorder.finalize(outcome="blocked", failure_class="observation_indeterminate")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()
        context.add_init_script("""(() => {
          const attempts = []; window.__marketAlignerPreSubmit = {attempts};
          const block = (name) => { attempts.push(name); throw new Error(`market-aligner-pre-submit:${name}`); };
          HTMLFormElement.prototype.submit = () => block('submit');
          HTMLFormElement.prototype.requestSubmit = () => block('submit');
          HTMLElement.prototype.click = () => block('click');
          window.fetch = () => block('network');
        })()""")
        try:
            page = context.new_page()
            page.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html; charset=utf-8", body=fixture_html))
            page.goto(authority.application_url, wait_until="domcontentloaded", timeout=2_000)
            before_snapshot_sha256 = sha256(page.content().encode())
            if before_snapshot_sha256 != inventory.page_snapshot_sha256:
                raise ValueError("ATS pre-submit page snapshot differs from observation")
            controls = page.locator("form input, form textarea, form select")
            rows = controls.evaluate_all("""(elements) => elements.map((element, index) => {
              const tag = element.tagName.toLowerCase(); const inputType = (element.getAttribute('type') || 'text').toLowerCase();
              const controlKind = tag === 'textarea' ? 'textarea' : (tag === 'select' ? 'select' : inputType);
              const fieldId = element.id || element.getAttribute('name') || '';
              const label = Array.from(element.labels || []).map((label) => (label.textContent || '').trim()).find(Boolean) || element.getAttribute('aria-label') || fieldId || `field-${index}`;
              const options = tag === 'select' ? Array.from(element.options || []).map((option) => ({value: option.value || option.textContent || '', label: (option.textContent || '').trim() || option.value || ''})) : ((controlKind === 'radio' || controlKind === 'checkbox') ? [{value: element.getAttribute('value') || fieldId, label}] : []);
              return {field_id: fieldId, control_kind: controlKind, label, required: Boolean(element.required) || element.getAttribute('aria-required') === 'true', visible: Boolean(element.offsetWidth || element.offsetHeight || element.getClientRects().length), disabled: Boolean(element.disabled), read_only: Boolean(element.readOnly), multiple: Boolean(element.multiple), options, value: element.getAttribute('value') || ''};
            })""")
            if not isinstance(rows, list):
                raise ValueError("ATS pre-submit controls are malformed")
            shape_rows = [{key: value for key, value in row.items() if key != "value"} for row in rows]
            if [field.document() for field in _observed_fields(shape_rows)] != [field.document() for field in inventory.fields]:
                raise ValueError("ATS pre-submit page shape differs from observation")
            for action_index, field in enumerate(plan, start=1):
                candidates = [index for index, row in enumerate(rows) if row["field_id"] == field.field_id]
                if not candidates:
                    raise ValueError("ATS pre-submit form shape differs")
                value = values[field.field_id]
                if sha256(value) != field.value_sha256:
                    raise ValueError("ATS pre-submit value identity differs")
                if field.action == "check":
                    decoded = value.decode("utf-8")
                    candidates = [index for index in candidates if rows[index]["value"] == decoded]
                if len(candidates) != 1:
                    raise ValueError("ATS pre-submit selector is ambiguous")
                target = controls.nth(candidates[0])
                if field.action == "upload":
                    target.set_input_files({"name": "fixture.txt", "mimeType": "text/plain", "buffer": value})
                elif field.action == "select":
                    target.select_option(value.decode("utf-8"))
                elif field.action == "check":
                    target.check()
                else:
                    target.fill(value.decode("utf-8"))
                if injected_crash_after_action == action_index:
                    raise RuntimeError("injected pre-publication fixture crash")
            attempts = page.evaluate("() => window.__marketAlignerPreSubmit.attempts.slice()")
            after_snapshot_sha256 = sha256(page.content().encode())
            readbacks = controls.evaluate_all("""(rows) => rows.map((row) => ({field_id: row.id || row.getAttribute('name') || '', value: row.value || '', checked: Boolean(row.checked), files: Array.from(row.files || []).map((file) => ({name: file.name, size: file.size, type: file.type}))}))""")
            evidence_actions = []
            for field in plan:
                value = values[field.field_id]
                matches = [row for row in readbacks if row["field_id"] == field.field_id]
                if field.action == "check":
                    matches = [row for row in matches if row["value"] == value.decode("utf-8")]
                if len(matches) != 1:
                    raise ValueError("ATS pre-submit readback selector is ambiguous")
                row = matches[0]
                if field.action == "upload":
                    metadata = {"name": "fixture.txt", "size": len(value), "type": "text/plain"}
                    if row["files"] != [metadata]:
                        raise ValueError("ATS pre-submit upload readback differs")
                    readback_sha256 = sha256(canonical_json(metadata).encode())
                elif field.action == "check":
                    if row["checked"] is not True:
                        raise ValueError("ATS pre-submit checked readback differs")
                    readback_sha256 = sha256(canonical_json({"checked": True, "value": row["value"]}).encode())
                else:
                    if row["value"].encode() != value:
                        raise ValueError("ATS pre-submit value readback differs")
                    readback_sha256 = sha256(row["value"].encode())
                evidence_actions.append({"field_id": field.field_id, "action": field.action, "value_sha256": field.value_sha256, "readback_sha256": readback_sha256, "upload_name": "fixture.txt" if field.action == "upload" else None, "upload_mime": "text/plain" if field.action == "upload" else None, "upload_content_sha256": field.value_sha256 if field.action == "upload" else sha256(b"")})
            payload = {
                "schema_version": "market-aligner.ats-pre-submit-evidence.v1",
                "observation_manifest_sha256": observation.receipt.manifest_sha256,
                "inventory_sha256": inventory.content_sha256, "authority_sha256": authority.authority_sha256,
                "plan_sha256": plan_sha256, "before_snapshot_sha256": before_snapshot_sha256,
                "after_snapshot_sha256": after_snapshot_sha256, "actions": evidence_actions,
                "interaction_counts": {"click": 0, "network": 0, "submit": 0},
                "terminal_disposition": "blocked" if attempts else "prepared_no_submit",
                "diagnostic_only": True, "raw_payloads_persisted": False,
                "identity_authority": False, "vault_authority": False, "submission_authority": False,
            }
            if attempts:
                recorder.checkpoint(_PRE_SUBMIT_CHECKPOINT, pre_submit=payload)
                return recorder.finalize(outcome="blocked", failure_class="read_only_interaction_attempted")
            recorder.checkpoint(_PRE_SUBMIT_CHECKPOINT, pre_submit=payload)
            return recorder.finalize(outcome="prepared")
        finally:
            context.close()
            browser.close()
