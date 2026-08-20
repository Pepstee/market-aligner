"""Read-only, source-backed JAA-12 ingestion for local official exports.

This module deliberately has no mailbox, portal, browser, network, or message-
sending capability.  It reads operator-provided JSON, EML, and strict text
exports beneath one allowed directory, binds every observation to a known JAA
application and official receipt, and stores only deterministic follow-up due
records in a local append-only SQLite ledger.

All export content is untrusted.  Only designated status fields may influence
classification.  Message bodies and unknown JSON fields have no authority;
control-plane instructions and candidate-fact mutation requests fail closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import policy as email_policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence

from career_automation.lifecycle import LEGAL_TRANSITIONS
from career_automation.models import PipelineState


MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCES_PER_RUN = 128
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")

SOURCE_KINDS = frozenset({"official_portal_export", "official_message_export"})
TERMINAL_STATES = frozenset(
    {
        PipelineState.ACCEPTED,
        PipelineState.DECLINED,
        PipelineState.REJECTED,
        PipelineState.WITHDRAWN,
        PipelineState.EXPIRED,
    }
)

# Classification is intentionally limited to explicit values in a designated
# status field.  No free-text body inference occurs.
STATUS_VOCABULARY: Mapping[str, PipelineState] = MappingProxyType(
    {
        "accepted": PipelineState.ACCEPTED,
        "application received": PipelineState.RECEIPT_CONFIRMED,
        "application_received": PipelineState.RECEIPT_CONFIRMED,
        "declined by candidate": PipelineState.DECLINED,
        "declined_by_candidate": PipelineState.DECLINED,
        "expired": PipelineState.EXPIRED,
        "final stage": PipelineState.FINAL_STAGE,
        "final_stage": PipelineState.FINAL_STAGE,
        "interview requested": PipelineState.INTERVIEW,
        "interview_requested": PipelineState.INTERVIEW,
        "offer": PipelineState.OFFER,
        "rejected by employer": PipelineState.REJECTED,
        "rejected_by_employer": PipelineState.REJECTED,
        "screening": PipelineState.SCREENING,
        "under review": PipelineState.SCREENING,
        "under_review": PipelineState.SCREENING,
        "withdrawn by candidate": PipelineState.WITHDRAWN,
        "withdrawn_by_candidate": PipelineState.WITHDRAWN,
    }
)

_FORBIDDEN_KEYS = frozenset(
    {
        "candidate_fact",
        "candidate_facts",
        "candidate_profile",
        "developer_message",
        "instruction",
        "instructions",
        "overwrite_candidate",
        "prompt",
        "system_message",
        "system_prompt",
    }
)
_INJECTION_MARKERS = (
    "ignore all previous instructions",
    "ignore previous instructions",
    "system: mark",
    "developer: mark",
    "alter candidate fact",
    "change candidate fact",
    "overwrite candidate",
)


class LiveStatusIngestionError(RuntimeError):
    """Base class for a fail-closed local export ingestion failure."""


class SourceBoundaryError(LiveStatusIngestionError):
    """A source escaped the allowed local-file boundary."""


class SourceSchemaError(LiveStatusIngestionError):
    """A source did not satisfy its explicit export schema."""


class SourceSecurityError(LiveStatusIngestionError):
    """Untrusted content attempted to enter a control or fact channel."""


class IdentityBindingError(LiveStatusIngestionError):
    """Source identity did not match the released JAA application."""


class StatusTransitionError(LiveStatusIngestionError):
    """Source evidence asserted an impossible or ambiguous timeline."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be normalized non-empty text")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} must not contain control characters")
    return value


def _identifier(value: object, label: str) -> str:
    text = _required(value, label)
    if SAFE_TOKEN.fullmatch(text) is None:
        raise ValueError(f"{label} contains unsupported characters")
    return text


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _aware(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value


def _parse_time(value: object, label: str) -> datetime:
    text = _required(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceSchemaError(f"{label} is not an ISO-8601 timestamp") from exc
    return _aware(parsed, label)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normal_status(value: object) -> str:
    text = _required(value, "status")
    if len(text) > 128:
        raise SourceSchemaError("status exceeds the bounded vocabulary field")
    return re.sub(r"\s+", " ", text.casefold())


def _walk_untrusted(value: object) -> Iterable[tuple[str | None, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise SourceSchemaError("JSON object keys must be text")
            if isinstance(child, str):
                yield key.casefold(), child
            else:
                # A forbidden channel is forbidden even when its value is a
                # nested object rather than a scalar instruction.
                yield key.casefold(), ""
                yield from _walk_untrusted(child)
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, str):
                yield None, child
            else:
                yield from _walk_untrusted(child)


def _reject_control_content(value: object) -> None:
    for key, text in _walk_untrusted(value):
        normalized_key = "" if key is None else key.replace("-", "_")
        if any(
            normalized_key == forbidden
            or normalized_key.endswith(f"_{forbidden}")
            for forbidden in _FORBIDDEN_KEYS
        ):
            raise SourceSecurityError(
                "untrusted export attempted to carry instructions or candidate facts"
            )
        folded = text.casefold()
        if any(marker in folded for marker in _INJECTION_MARKERS):
            raise SourceSecurityError(
                "untrusted export contains a control-plane injection marker"
            )


@dataclass(frozen=True)
class ApplicationReceiptBinding:
    """Identity authority supplied from the released application ledger."""

    application_id: str
    job_key: str
    employer_key: str
    receipt_sha256: str
    released_application_sha256: str
    release_manifest_sha256: str
    receipt_observed_at: datetime
    schema_version: str = "jaa12.application-receipt-binding.v1"

    def __post_init__(self) -> None:
        _identifier(self.application_id, "application ID")
        _identifier(self.job_key, "job key")
        _identifier(self.employer_key, "employer key")
        _digest(self.receipt_sha256, "receipt identity")
        _digest(self.released_application_sha256, "released application hash")
        _digest(self.release_manifest_sha256, "release manifest hash")
        _aware(self.receipt_observed_at, "receipt observation time")
        if self.schema_version != "jaa12.application-receipt-binding.v1":
            raise ValueError("application receipt binding schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "employer_key": self.employer_key,
            "receipt_sha256": self.receipt_sha256,
            "released_application_sha256": self.released_application_sha256,
            "release_manifest_sha256": self.release_manifest_sha256,
            "receipt_observed_at": _utc_text(self.receipt_observed_at),
        }

    @property
    def binding_sha256(self) -> str:
        return _content_hash(self.document())


@dataclass(frozen=True)
class EmployerFollowUpPolicy:
    """Explicit per-employer scheduling policy; it contains no send authority."""

    employer_key: str
    policy_id: str
    version: str
    delay_seconds_by_state: Mapping[PipelineState, int]
    schema_version: str = "jaa12.employer-follow-up-policy.v1"

    def __post_init__(self) -> None:
        _identifier(self.employer_key, "policy employer key")
        _identifier(self.policy_id, "follow-up policy ID")
        _identifier(self.version, "follow-up policy version")
        normalized = dict(self.delay_seconds_by_state)
        if not normalized:
            raise ValueError("follow-up policy requires at least one eligible state")
        for state, delay in normalized.items():
            if not isinstance(state, PipelineState):
                raise TypeError("follow-up policy state must be PipelineState")
            if state in TERMINAL_STATES:
                raise ValueError("terminal states cannot schedule follow-ups")
            if isinstance(delay, bool) or not isinstance(delay, int) or delay < 0:
                raise ValueError("follow-up delay must be a non-negative integer")
            if delay > 365 * 24 * 60 * 60:
                raise ValueError("follow-up delay exceeds the bounded policy horizon")
        object.__setattr__(self, "delay_seconds_by_state", MappingProxyType(normalized))
        if self.schema_version != "jaa12.employer-follow-up-policy.v1":
            raise ValueError("follow-up policy schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "employer_key": self.employer_key,
            "policy_id": self.policy_id,
            "version": self.version,
            "delay_seconds_by_state": {
                state.value: delay
                for state, delay in sorted(
                    self.delay_seconds_by_state.items(), key=lambda item: item[0].value
                )
            },
            "send_authority": False,
        }

    @property
    def policy_sha256(self) -> str:
        return _content_hash(self.document())


@dataclass(frozen=True)
class RawSourceReference:
    relative_path: str
    source_kind: str
    source_sha256: str
    byte_count: int
    schema_version: str

    def __post_init__(self) -> None:
        path = Path(_required(self.relative_path, "source relative path"))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("source reference must remain below the allowed root")
        if self.source_kind not in SOURCE_KINDS:
            raise ValueError("source reference kind is unsupported")
        _digest(self.source_sha256, "source hash")
        if (
            isinstance(self.byte_count, bool)
            or not isinstance(self.byte_count, int)
            or self.byte_count <= 0
            or self.byte_count > MAX_SOURCE_BYTES
        ):
            raise ValueError("source byte count is outside the accepted bound")
        if self.schema_version not in {
            "jaa-status-export-v1",
            "jaa-status-email-v1",
            "jaa-status-text-v1",
        }:
            raise ValueError("source reference schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "source_kind": self.source_kind,
            "source_sha256": self.source_sha256,
            "byte_count": self.byte_count,
            "schema_version": self.schema_version,
            "untrusted_content": True,
            "instruction_authority": False,
            "candidate_fact_authority": False,
        }


@dataclass(frozen=True)
class ClassifiedStatusEvent:
    application_id: str
    job_key: str
    receipt_sha256: str
    source_record_id: str
    observed_at: str
    status_token_sha256: str
    observation_sha256: str
    classified_state: PipelineState | None
    confidence_bp: int
    abstained: bool
    sources: tuple[RawSourceReference, ...]
    event_sha256: str
    schema_version: str = "jaa12.classified-status-event.v1"

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "receipt_sha256": self.receipt_sha256,
            "source_record_id": self.source_record_id,
            "observed_at": self.observed_at,
            "status_token_sha256": self.status_token_sha256,
            "observation_sha256": self.observation_sha256,
            "classified_state": (
                None if self.classified_state is None else self.classified_state.value
            ),
            "confidence_bp": self.confidence_bp,
            "abstained": self.abstained,
            "sources": [source.document() for source in self.sources],
            "instruction_authority": False,
            "candidate_fact_authority": False,
        }
        if include_identity:
            result["event_sha256"] = self.event_sha256
        return result

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", tuple(self.sources))
        _identifier(self.application_id, "event application ID")
        _identifier(self.job_key, "event job key")
        _digest(self.receipt_sha256, "event receipt identity")
        _identifier(self.source_record_id, "event source record ID")
        _parse_time(self.observed_at, "event observation time")
        _digest(self.status_token_sha256, "event status token hash")
        _digest(self.observation_sha256, "event observation identity")
        _digest(self.event_sha256, "event identity")
        if not self.sources:
            raise ValueError("classified event requires raw source references")
        if any(not isinstance(row, RawSourceReference) for row in self.sources):
            raise TypeError("classified event sources must be RawSourceReference")
        if len({(row.source_sha256, row.relative_path) for row in self.sources}) != len(
            self.sources
        ):
            raise ValueError("classified event source references must be deduplicated")
        if self.classified_state is None:
            if self.confidence_bp != 0 or self.abstained is not True:
                raise ValueError("unclassified event must explicitly abstain")
        elif (
            not isinstance(self.classified_state, PipelineState)
            or not 0 < self.confidence_bp <= 10_000
            or self.abstained is not False
        ):
            raise ValueError("classified event confidence is inconsistent")
        expected_observation = _content_hash(
            {
                "schema_version": "jaa12.status-observation-identity.v1",
                "application_id": self.application_id,
                "job_key": self.job_key,
                "receipt_sha256": self.receipt_sha256,
                "source_record_id": self.source_record_id,
                "observed_at": self.observed_at,
                "status_token_sha256": self.status_token_sha256,
            }
        )
        if self.observation_sha256 != expected_observation:
            raise ValueError("classified event observation identity is inconsistent")
        if self.event_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("classified event differs from its content identity")


@dataclass(frozen=True)
class FollowUpDueRecord:
    due_key: str
    application_id: str
    job_key: str
    employer_key: str
    receipt_sha256: str
    released_application_sha256: str
    policy_sha256: str
    stage: PipelineState
    anchor_sha256: str
    due_at: str
    max_sends: int = 1
    sent_count: int = 0
    send_authority: bool = False
    schema_version: str = "jaa12.follow-up-due-record.v1"

    def __post_init__(self) -> None:
        _identifier(self.application_id, "follow-up application ID")
        _identifier(self.job_key, "follow-up job key")
        _identifier(self.employer_key, "follow-up employer key")
        if not self.due_key.startswith("jaa12-follow-up:"):
            raise ValueError("follow-up due key has an unsupported namespace")
        for value, label in (
            (self.receipt_sha256, "follow-up receipt identity"),
            (self.released_application_sha256, "follow-up released application hash"),
            (self.policy_sha256, "follow-up policy hash"),
            (self.anchor_sha256, "follow-up anchor identity"),
        ):
            _digest(value, label)
        _parse_time(self.due_at, "follow-up due time")
        if (
            not isinstance(self.stage, PipelineState)
            or self.stage in TERMINAL_STATES
            or self.max_sends != 1
            or self.sent_count != 0
            or self.send_authority is not False
        ):
            raise ValueError("follow-up due record cannot send or target a terminal state")
        scope = {
            "schema_version": "jaa12.follow-up-due-key.v1",
            "application_id": self.application_id,
            "job_key": self.job_key,
            "employer_key": self.employer_key,
            "receipt_sha256": self.receipt_sha256,
            "released_application_sha256": self.released_application_sha256,
            "stage": self.stage.value,
        }
        if self.due_key != f"jaa12-follow-up:{_content_hash(scope)}":
            raise ValueError("follow-up due key differs from its at-most-once scope")
        if self.schema_version != "jaa12.follow-up-due-record.v1":
            raise ValueError("follow-up due record schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "due_key": self.due_key,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "employer_key": self.employer_key,
            "receipt_sha256": self.receipt_sha256,
            "released_application_sha256": self.released_application_sha256,
            "policy_sha256": self.policy_sha256,
            "stage": self.stage.value,
            "anchor_sha256": self.anchor_sha256,
            "due_at": self.due_at,
            "max_sends": 1,
            "sent_count": 0,
            "send_authority": False,
        }


@dataclass(frozen=True)
class LiveStatusIngestionResult:
    binding_sha256: str
    source_references: tuple[RawSourceReference, ...]
    events: tuple[ClassifiedStatusEvent, ...]
    current_state: PipelineState
    current_confidence_bp: int
    silence_censored: bool
    rejection_inferred_from_silence: bool
    follow_up_due: FollowUpDueRecord | None
    result_sha256: str
    schema_version: str = "jaa12.live-status-ingestion-result.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_references", tuple(self.source_references))
        object.__setattr__(self, "events", tuple(self.events))
        _digest(self.binding_sha256, "result binding hash")
        _digest(self.result_sha256, "result identity")
        if any(
            not isinstance(row, RawSourceReference) for row in self.source_references
        ):
            raise TypeError("result sources must be RawSourceReference")
        if any(not isinstance(row, ClassifiedStatusEvent) for row in self.events):
            raise TypeError("result events must be ClassifiedStatusEvent")
        if not isinstance(self.current_state, PipelineState):
            raise TypeError("result current state must be PipelineState")
        if not 0 <= self.current_confidence_bp <= 10_000:
            raise ValueError("result confidence is outside basis-point bounds")
        if self.rejection_inferred_from_silence is not False:
            raise ValueError("silence cannot infer rejection")
        if self.schema_version != "jaa12.live-status-ingestion-result.v1":
            raise ValueError("ingestion result schema is unsupported")
        if self.result_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("ingestion result differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "binding_sha256": self.binding_sha256,
            "source_references": [row.document() for row in self.source_references],
            "events": [row.document() for row in self.events],
            "current_state": self.current_state.value,
            "current_confidence_bp": self.current_confidence_bp,
            "silence_censored": self.silence_censored,
            "rejection_inferred_from_silence": False,
            "follow_up_due": (
                None if self.follow_up_due is None else self.follow_up_due.document()
            ),
        }
        if include_identity:
            result["result_sha256"] = self.result_sha256
        return result


@dataclass(frozen=True)
class _ParsedEvent:
    source_record_id: str
    observed_at: datetime
    status: str
    source: RawSourceReference


def _read_bounded_source(path: Path, allowed_root: Path) -> tuple[bytes, str]:
    try:
        root = allowed_root.resolve(strict=True)
        candidate = path if path.is_absolute() else root / path
        # lexical path check happens before opening; resolved containment is
        # repeated after O_NOFOLLOW opening below.
        resolved_parent = candidate.parent.resolve(strict=True)
        if os.path.commonpath((str(root), str(resolved_parent))) != str(root):
            raise SourceBoundaryError("status source escapes the allowed root")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags)
    except SourceBoundaryError:
        raise
    except OSError as exc:
        raise SourceBoundaryError("status source is unavailable or unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SourceBoundaryError("status source must be a regular file")
        if before.st_size <= 0 or before.st_size > MAX_SOURCE_BYTES:
            raise SourceBoundaryError("status source size is outside the accepted bound")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_SOURCE_BYTES + 1)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after or len(raw) != before.st_size:
            raise SourceBoundaryError("status source changed while it was read")
        resolved = Path(os.path.realpath(candidate))
        if os.path.commonpath((str(root), str(resolved))) != str(root):
            raise SourceBoundaryError("status source resolves outside the allowed root")
        relative = resolved.relative_to(root).as_posix()
        return raw, relative
    finally:
        os.close(descriptor)


def _assert_identity(
    source: Mapping[str, object], binding: ApplicationReceiptBinding
) -> None:
    expected = {
        "application_id": binding.application_id,
        "job_key": binding.job_key,
        "receipt_sha256": binding.receipt_sha256,
    }
    for key, value in expected.items():
        if source.get(key) != value:
            raise IdentityBindingError(f"source {key} does not match the JAA receipt")


def _source_reference(
    *, relative_path: str, raw: bytes, source_kind: str, schema_version: str
) -> RawSourceReference:
    if source_kind not in SOURCE_KINDS:
        raise SourceSchemaError("source kind is not an official local export")
    return RawSourceReference(
        relative_path=relative_path,
        source_kind=source_kind,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        byte_count=len(raw),
        schema_version=schema_version,
    )


def _parse_json(
    raw: bytes, relative_path: str, binding: ApplicationReceiptBinding
) -> list[_ParsedEvent]:
    def object_without_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SourceSchemaError("JSON status export contains duplicate keys")
            result[key] = value
        return result

    try:
        document = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=object_without_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceSchemaError("JSON status export is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise SourceSchemaError("JSON status export must be an object")
    _reject_control_content(document)
    if document.get("schema_version") != "jaa-status-export-v1":
        raise SourceSchemaError("JSON status export schema is unsupported")
    _assert_identity(document, binding)
    source_kind = document.get("source_kind")
    if source_kind not in SOURCE_KINDS:
        raise SourceSchemaError("JSON source kind is unsupported")
    events = document.get("events")
    if not isinstance(events, list) or not events:
        raise SourceSchemaError("JSON status export requires a non-empty events list")
    source = _source_reference(
        relative_path=relative_path,
        raw=raw,
        source_kind=str(source_kind),
        schema_version="jaa-status-export-v1",
    )
    result: list[_ParsedEvent] = []
    for event in events:
        if not isinstance(event, dict):
            raise SourceSchemaError("JSON status event must be an object")
        result.append(
            _ParsedEvent(
                source_record_id=_identifier(event.get("event_id"), "event ID"),
                observed_at=_parse_time(event.get("observed_at"), "event time"),
                status=_normal_status(event.get("status")),
                source=source,
            )
        )
    return result


def _message_text(message: object) -> str:
    # email.message.EmailMessage is intentionally not imported as a type: the
    # parser may produce compatible Message subclasses.
    texts: list[str] = []
    parts = message.walk() if getattr(message, "is_multipart")() else (message,)
    for part in parts:
        if part.get_content_maintype() != "text":
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            continue
        if isinstance(content, str):
            texts.append(content)
    return "\n".join(texts)


def _parse_eml(
    raw: bytes, relative_path: str, binding: ApplicationReceiptBinding
) -> list[_ParsedEvent]:
    try:
        message = BytesParser(policy=email_policy.default).parsebytes(raw)
    except Exception as exc:
        raise SourceSchemaError("EML status export cannot be parsed") from exc
    singleton_headers = (
        "X-JAA-Export-Schema",
        "X-JAA-Application-ID",
        "X-JAA-Job-Key",
        "X-JAA-Receipt-SHA256",
        "X-JAA-Status",
        "Message-ID",
        "Date",
    )
    if any(len(message.get_all(name, [])) != 1 for name in singleton_headers):
        raise SourceSchemaError("EML identity and status headers must be unique")
    _reject_control_content({name: str(value) for name, value in message.items()})
    if message.get("X-JAA-Export-Schema") != "jaa-status-email-v1":
        raise SourceSchemaError("EML status export schema is unsupported")
    identity = {
        "application_id": message.get("X-JAA-Application-ID"),
        "job_key": message.get("X-JAA-Job-Key"),
        "receipt_sha256": message.get("X-JAA-Receipt-SHA256"),
    }
    _assert_identity(identity, binding)
    status = _normal_status(message.get("X-JAA-Status"))
    raw_record_id = _required(message.get("Message-ID"), "message ID")
    record_id = _identifier(raw_record_id.removeprefix("<").removesuffix(">"), "message ID")
    date_header = _required(message.get("Date"), "message date")
    try:
        observed = parsedate_to_datetime(date_header)
    except (TypeError, ValueError) as exc:
        raise SourceSchemaError("EML Date is invalid") from exc
    _aware(observed, "message date")
    body = _message_text(message)
    _reject_control_content({"message_body": body})
    source = _source_reference(
        relative_path=relative_path,
        raw=raw,
        source_kind="official_message_export",
        schema_version="jaa-status-email-v1",
    )
    return [_ParsedEvent(record_id, observed, status, source)]


def _parse_text(
    raw: bytes, relative_path: str, binding: ApplicationReceiptBinding
) -> list[_ParsedEvent]:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SourceSchemaError("text status export must be strict UTF-8") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            continue
        key, separator, value = line.partition(": ")
        if not separator or key in values:
            raise SourceSchemaError("text export must use unique 'key: value' lines")
        values[key] = value
    allowed = {
        "schema_version",
        "application_id",
        "job_key",
        "receipt_sha256",
        "event_id",
        "observed_at",
        "status",
    }
    if set(values) != allowed:
        raise SourceSchemaError("text export fields differ from the strict schema")
    _reject_control_content(values)
    if values["schema_version"] != "jaa-status-text-v1":
        raise SourceSchemaError("text status export schema is unsupported")
    _assert_identity(values, binding)
    source = _source_reference(
        relative_path=relative_path,
        raw=raw,
        source_kind="official_message_export",
        schema_version="jaa-status-text-v1",
    )
    return [
        _ParsedEvent(
            _identifier(values["event_id"], "event ID"),
            _parse_time(values["observed_at"], "event time"),
            _normal_status(values["status"]),
            source,
        )
    ]


def _parse_source(
    path: Path, allowed_root: Path, binding: ApplicationReceiptBinding
) -> list[_ParsedEvent]:
    raw, relative_path = _read_bounded_source(path, allowed_root)
    suffix = Path(relative_path).suffix.casefold()
    if suffix == ".json":
        return _parse_json(raw, relative_path, binding)
    if suffix == ".eml":
        return _parse_eml(raw, relative_path, binding)
    if suffix == ".txt":
        return _parse_text(raw, relative_path, binding)
    raise SourceSchemaError("status source extension must be .json, .eml, or .txt")


def _state_reachable(source: PipelineState, target: PipelineState) -> bool:
    """Return whether an explicit later state can follow unseen intermediates."""

    pending = list(LEGAL_TRANSITIONS[source])
    visited: set[PipelineState] = set()
    while pending:
        state = pending.pop()
        if state is target:
            return True
        if state in visited:
            continue
        visited.add(state)
        pending.extend(LEGAL_TRANSITIONS[state])
    return False


def _compile_events(
    parsed: Sequence[_ParsedEvent], binding: ApplicationReceiptBinding
) -> tuple[ClassifiedStatusEvent, ...]:
    # One official record identity may occur in multiple exports.  Exact
    # duplicates merge their source references; conflicts fail closed.
    grouped: dict[tuple[str, str, str], list[RawSourceReference]] = {}
    record_claims: dict[str, tuple[str, str]] = {}
    for row in parsed:
        observed = _utc_text(row.observed_at)
        if row.observed_at.astimezone(timezone.utc) < (
            binding.receipt_observed_at.astimezone(timezone.utc)
        ):
            raise StatusTransitionError(
                "status evidence predates the bound application receipt"
            )
        claim = (observed, row.status)
        previous = record_claims.setdefault(row.source_record_id, claim)
        if previous != claim:
            raise StatusTransitionError(
                "one source record ID asserts conflicting status evidence"
            )
        grouped.setdefault((row.source_record_id, observed, row.status), []).append(
            row.source
        )

    result: list[ClassifiedStatusEvent] = []
    for (record_id, observed_at, status), references in grouped.items():
        unique = {(row.source_sha256, row.relative_path): row for row in references}
        sources = tuple(
            sorted(unique.values(), key=lambda row: (row.source_sha256, row.relative_path))
        )
        state = STATUS_VOCABULARY.get(status)
        # Structured portal values are exact (100%); an explicitly designated
        # message header/status line is high confidence but not portal state.
        confidence = 0
        if state is not None:
            confidence = 10_000 if any(
                row.source_kind == "official_portal_export" for row in sources
            ) else 9_500
        status_token_sha256 = hashlib.sha256(status.encode()).hexdigest()
        observation_sha256 = _content_hash(
            {
                "schema_version": "jaa12.status-observation-identity.v1",
                "application_id": binding.application_id,
                "job_key": binding.job_key,
                "receipt_sha256": binding.receipt_sha256,
                "source_record_id": record_id,
                "observed_at": observed_at,
                "status_token_sha256": status_token_sha256,
            }
        )
        body = {
            "schema_version": "jaa12.classified-status-event.v1",
            "application_id": binding.application_id,
            "job_key": binding.job_key,
            "receipt_sha256": binding.receipt_sha256,
            "source_record_id": record_id,
            "observed_at": observed_at,
            "status_token_sha256": status_token_sha256,
            "observation_sha256": observation_sha256,
            "classified_state": None if state is None else state.value,
            "confidence_bp": confidence,
            "abstained": state is None,
            "sources": [row.document() for row in sources],
            "instruction_authority": False,
            "candidate_fact_authority": False,
        }
        result.append(
            ClassifiedStatusEvent(
                application_id=binding.application_id,
                job_key=binding.job_key,
                receipt_sha256=binding.receipt_sha256,
                source_record_id=record_id,
                observed_at=observed_at,
                status_token_sha256=status_token_sha256,
                observation_sha256=observation_sha256,
                classified_state=state,
                confidence_bp=confidence,
                abstained=state is None,
                sources=sources,
                event_sha256=_content_hash(body),
            )
        )
    result.sort(key=lambda row: (row.observed_at, row.source_record_id, row.event_sha256))

    state = PipelineState.RECEIPT_CONFIRMED
    same_time: dict[str, PipelineState] = {}
    for event in result:
        target = event.classified_state
        if target is None:
            continue
        prior_at_time = same_time.setdefault(event.observed_at, target)
        if prior_at_time is not target:
            raise StatusTransitionError(
                "conflicting classified states share one observation time"
            )
        if target is state:
            continue
        if not _state_reachable(state, target):
            raise StatusTransitionError(
                f"illegal status transition {state.value}->{target.value}"
            )
        state = target
    return tuple(result)


def _follow_up_record(
    *,
    binding: ApplicationReceiptBinding,
    policy: EmployerFollowUpPolicy,
    events: Sequence[ClassifiedStatusEvent],
    current_state: PipelineState,
) -> FollowUpDueRecord | None:
    delay = policy.delay_seconds_by_state.get(current_state)
    if delay is None or current_state in TERMINAL_STATES:
        return None
    anchor_time = binding.receipt_observed_at
    anchor_sha256 = binding.receipt_sha256
    for event in events:
        if event.classified_state is current_state:
            anchor_time = datetime.fromisoformat(event.observed_at.replace("Z", "+00:00"))
            anchor_sha256 = event.observation_sha256
            break
    due_at = _utc_text(anchor_time + timedelta(seconds=delay))
    scope = {
        "schema_version": "jaa12.follow-up-due-key.v1",
        "application_id": binding.application_id,
        "job_key": binding.job_key,
        "employer_key": binding.employer_key,
        "receipt_sha256": binding.receipt_sha256,
        "released_application_sha256": binding.released_application_sha256,
        "stage": current_state.value,
    }
    due_key = f"jaa12-follow-up:{_content_hash(scope)}"
    return FollowUpDueRecord(
        due_key=due_key,
        application_id=binding.application_id,
        job_key=binding.job_key,
        employer_key=binding.employer_key,
        receipt_sha256=binding.receipt_sha256,
        released_application_sha256=binding.released_application_sha256,
        policy_sha256=policy.policy_sha256,
        stage=current_state,
        anchor_sha256=anchor_sha256,
        due_at=due_at,
    )


class FollowUpDueLedger:
    """Append-only durable registration of non-sendable follow-up due records."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS follow_up_due (
                    due_key TEXT PRIMARY KEY,
                    application_id TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS follow_up_due_no_update
                BEFORE UPDATE ON follow_up_due
                BEGIN SELECT RAISE(ABORT, 'follow-up due records are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS follow_up_due_no_delete
                BEFORE DELETE ON follow_up_due
                BEGIN SELECT RAISE(ABORT, 'follow-up due records are immutable'); END;
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def register(self, record: FollowUpDueRecord) -> FollowUpDueRecord:
        if not isinstance(record, FollowUpDueRecord):
            raise TypeError("follow-up ledger requires FollowUpDueRecord")
        document = record.document()
        encoded = _canonical_json(document)
        record_sha256 = hashlib.sha256(encoded.encode()).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT record_sha256,record_json FROM follow_up_due WHERE due_key=?",
                (record.due_key,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """INSERT INTO follow_up_due(
                           due_key,application_id,receipt_sha256,record_sha256,record_json
                       ) VALUES(?,?,?,?,?)""",
                    (
                        record.due_key,
                        record.application_id,
                        record.receipt_sha256,
                        record_sha256,
                        encoded,
                    ),
                )
            elif existing != (record_sha256, encoded):
                raise LiveStatusIngestionError(
                    "durable at-most-once key already binds different content"
                )
            connection.commit()
            return record
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM follow_up_due").fetchone()
        return int(row[0])


def ingest_local_status_exports(
    *,
    source_paths: Sequence[str | Path],
    allowed_root: str | Path,
    binding: ApplicationReceiptBinding,
    follow_up_policy: EmployerFollowUpPolicy,
    follow_up_ledger: FollowUpDueLedger,
) -> LiveStatusIngestionResult:
    """Ingest official local exports without accessing or mutating accounts."""

    if not isinstance(binding, ApplicationReceiptBinding):
        raise TypeError("ingestion requires ApplicationReceiptBinding")
    if not isinstance(follow_up_policy, EmployerFollowUpPolicy):
        raise TypeError("ingestion requires EmployerFollowUpPolicy")
    if follow_up_policy.employer_key != binding.employer_key:
        raise IdentityBindingError("follow-up policy belongs to another employer")
    if not isinstance(follow_up_ledger, FollowUpDueLedger):
        raise TypeError("ingestion requires FollowUpDueLedger")
    if isinstance(source_paths, (str, bytes)):
        raise TypeError("source paths must be a sequence of individual paths")
    paths = tuple(Path(path) for path in source_paths)
    if len(paths) > MAX_SOURCES_PER_RUN:
        raise SourceBoundaryError("too many status sources in one bounded run")
    if len({str(path) for path in paths}) != len(paths):
        raise SourceBoundaryError("duplicate source paths are not accepted")

    parsed: list[_ParsedEvent] = []
    for path in paths:
        parsed.extend(_parse_source(path, Path(allowed_root), binding))
    events = _compile_events(parsed, binding)
    current_state = PipelineState.RECEIPT_CONFIRMED
    confidence = 10_000
    for event in events:
        if event.classified_state is not None:
            current_state = event.classified_state
            confidence = event.confidence_bp
    sources_by_hash = {
        (source.source_sha256, source.relative_path): source
        for event in events
        for source in event.sources
    }
    sources = tuple(
        sorted(sources_by_hash.values(), key=lambda row: (row.relative_path, row.source_sha256))
    )
    silence_censored = not any(event.classified_state is not None for event in events)
    due = _follow_up_record(
        binding=binding,
        policy=follow_up_policy,
        events=events,
        current_state=current_state,
    )
    if due is not None:
        follow_up_ledger.register(due)
    body = {
        "schema_version": "jaa12.live-status-ingestion-result.v1",
        "binding_sha256": binding.binding_sha256,
        "source_references": [row.document() for row in sources],
        "events": [row.document() for row in events],
        "current_state": current_state.value,
        "current_confidence_bp": confidence,
        "silence_censored": silence_censored,
        "rejection_inferred_from_silence": False,
        "follow_up_due": None if due is None else due.document(),
    }
    return LiveStatusIngestionResult(
        binding_sha256=binding.binding_sha256,
        source_references=sources,
        events=events,
        current_state=current_state,
        current_confidence_bp=confidence,
        silence_censored=silence_censored,
        rejection_inferred_from_silence=False,
        follow_up_due=due,
        result_sha256=_content_hash(body),
    )
