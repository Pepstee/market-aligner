"""Faceless internal JAA preparation and deterministic no-submit evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime
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
_OBSERVATION_CHECKPOINT = "read_only_ats_observation"


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
    keys = {
        "schema_version", "provider", "requested_application_url", "final_application_url",
        "job_key", "authority_sha256", "captured_at", "page_snapshot_sha256", "inventory", "inventory_sha256",
        "network_evidence_sha256", "network_event_count", "interaction_counts", "blocked_interaction_attempts",
        "terminal_failure_class", "diagnostic_only", "raw_payloads_persisted",
        "identity_authority", "release_authority", "submission_authority",
    }
    if set(value) != keys or value["schema_version"] != _OBSERVATION_SCHEMA:
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
    if not isinstance(attempts, list) or len(attempts) > 32 or any(
        attempt not in {"click", "fill", "submit", "type", "upload", "network"}
        for attempt in attempts
    ):
        raise ValueError("ATS observation blocked interaction evidence differs")
    if value["diagnostic_only"] is not True or value["raw_payloads_persisted"] is not False or any(value[name] is not False for name in ("identity_authority", "release_authority", "submission_authority")):
        raise ValueError("ATS observation authority differs")
    failure = value["terminal_failure_class"]
    if failure is not None and failure not in _FAILURES:
        raise ValueError("ATS observation terminal state differs")
    if (failure == "read_only_interaction_attempted") != bool(attempts):
        raise ValueError("ATS observation interaction terminal differs")
    if value["inventory"] is None:
        if value["inventory_sha256"] is not None or failure is None:
            raise ValueError("ATS observation inventory binding differs")
        return None, failure
    inventory = _inventory_from_document(value["inventory"])
    if failure is not None or value["inventory_sha256"] != inventory.content_sha256:
        raise ValueError("ATS observation inventory identity differs")
    return inventory, None


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

    def checkpoint(self, name: str, *, observation: Mapping[str, object] | None = None) -> None:
        if name not in {"prepared", "blocked", _OBSERVATION_CHECKPOINT}:
            raise ValueError("unsupported forensic checkpoint")
        event = {"sequence": len(self.events) + 1, "checkpoint": name}
        if name == _OBSERVATION_CHECKPOINT:
            if observation is None:
                raise ValueError("read-only ATS observation checkpoint requires evidence")
            _observation_payload(dict(observation))
            event["observation"] = json.loads(canonical_json(dict(observation)))
        elif observation is not None:
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
        if checkpoint not in {"prepared", "blocked", _OBSERVATION_CHECKPOINT} or set(event) != expected:
            raise ValueError("forensic event schema differs")
        without_hash = {key: value for key, value in event.items() if key != "event_sha256"}
        if event["event_sha256"] != sha256(canonical_json(without_hash).encode()):
            raise ValueError("forensic event identity differs")
        if checkpoint == _OBSERVATION_CHECKPOINT:
            if observation is not None or not isinstance(event["observation"], dict):
                raise ValueError("forensic observation evidence differs")
            _observation_payload(event["observation"])
            observation = event["observation"]
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
    network_evidence_sha256: str
    network_event_count: int

    def __post_init__(self) -> None:
        if type(self.receipt) is not ATSForensicReceipt:
            raise TypeError("read-only ATS observation requires an exact forensic receipt")
        _observation_url(self.requested_application_url)
        _observation_url(self.final_application_url)
        _digest(self.network_evidence_sha256, "ATS observation network evidence SHA-256")
        if isinstance(self.network_event_count, bool) or not isinstance(self.network_event_count, int) or self.network_event_count < 0:
            raise ValueError("ATS observation network event count differs")


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
        network_evidence_sha256=str(payload["network_evidence_sha256"]),
        network_event_count=int(payload["network_event_count"]),
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
) -> AtsReadOnlyObservation:
    """Observe one authority-bound route without input, upload, click, or submission.

    This increment implements only the accepted ``localhost`` fixture transport.
    The content-addressed authority shape intentionally remains suitable for a
    separately approved public adapter without granting it here.
    """
    if type(authority) is not AtsObservationAuthority:
        raise TypeError("ATS observation requires exact typed authority")
    if authority.local_fixture_only is not True:
        raise PermissionError("public ATS observation requires an external verified operator capability")
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
                browser = playwright.chromium.launch(headless=True, channel="chrome")
                context = browser.new_context()
                context.add_init_script(
                    """(() => {
                      const attempts = [];
                      const block = (name) => { attempts.push(name); throw new Error(`market-aligner-read-only:${name}`); };
                      Object.defineProperty(window, '__marketAlignerReadOnly', {value: {attempts}, configurable: false});
                      const blockMethod = (prototype, name, kind) => {
                        const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
                        if (descriptor && typeof descriptor.value === 'function') Object.defineProperty(prototype, name, {...descriptor, value() { return block(kind); }});
                      };
                      const blockSetter = (prototype, name, kind) => {
                        const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
                        if (descriptor && typeof descriptor.set === 'function') Object.defineProperty(prototype, name, {...descriptor, set() { return block(kind); }});
                      };
                      blockMethod(HTMLElement.prototype, 'click', 'click');
                      blockMethod(HTMLFormElement.prototype, 'submit', 'submit');
                      blockMethod(HTMLFormElement.prototype, 'requestSubmit', 'submit');
                      blockSetter(HTMLInputElement.prototype, 'value', 'fill');
                      blockSetter(HTMLTextAreaElement.prototype, 'value', 'type');
                      blockSetter(HTMLSelectElement.prototype, 'value', 'fill');
                      blockSetter(HTMLInputElement.prototype, 'files', 'upload');
                      window.fetch = () => block('network');
                      if (navigator.sendBeacon) navigator.sendBeacon = () => block('network');
                      blockMethod(XMLHttpRequest.prototype, 'open', 'network');
                    })()"""
                )
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
                blockers = page.locator("input[type=password], iframe").evaluate_all(
                    """(elements) => ({
                      password: elements.some((element) => element.matches('input[type=password]')),
                      captcha: elements.some((element) => {
                        const text = `${element.getAttribute('src') || ''} ${element.getAttribute('title') || ''}`.toLowerCase();
                        return /captcha|turnstile|challenge/.test(text) && !!(element.offsetWidth || element.offsetHeight || element.getClientRects().length);
                      })
                    })"""
                )
                if blockers["password"]:
                    failure = "identity_required"
                elif blockers["captcha"]:
                    failure = "human_verification"
                elif failure is None:
                    rows = page.locator("form input, form textarea, form select").evaluate_all(
                        """(elements) => elements.map((element, index) => {
                          const tag = element.tagName.toLowerCase();
                          const inputType = (element.getAttribute('type') || 'text').toLowerCase();
                          const controlKind = tag === 'textarea' ? 'textarea' : (tag === 'select' ? 'select' : inputType);
                          const fieldId = element.id || element.getAttribute('name') || '';
                          const label = Array.from(element.labels || []).map((label) => (label.textContent || '').trim()).find(Boolean) || element.getAttribute('aria-label') || fieldId || `field-${index}`;
                          const options = tag === 'select' ? Array.from(element.options || []).map((option) => ({value: option.value || option.textContent || '', label: (option.textContent || '').trim() || option.value || ''})) : ((controlKind === 'radio' || controlKind === 'checkbox') ? [{value: element.getAttribute('value') || fieldId, label}] : []);
                          return {
                            field_id: fieldId,
                            control_kind: controlKind,
                            label,
                            required: Boolean(element.required) || element.getAttribute('aria-required') === 'true',
                            visible: Boolean(element.offsetWidth || element.offsetHeight || element.getClientRects().length),
                            disabled: Boolean(element.disabled),
                            read_only: Boolean(element.readOnly),
                            multiple: Boolean(element.multiple),
                            options,
                          };
                        })"""
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
                    attempt not in {"click", "fill", "submit", "type", "upload", "network"}
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
