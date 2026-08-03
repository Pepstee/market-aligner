"""Local, source-backed JAA-13 interview preparation boundary.

The module consumes the typed, content-addressed output of JAA-12 and explicit
public-professional source snapshots supplied by the operator.  It has no
network, browser, mailbox, account, connector, or message-send capability.

Public-source text and local debrief text are untrusted.  Candidate facts must
remain bound to the released application, public facts are exact excerpts from
current snapshots, and debrief statements remain unverified.  Follow-up output
is a non-sendable draft that requires operator confirmation outside this
module.  Nothing here certifies JAA-13.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence
from urllib.parse import urlsplit

from career_automation.models import PipelineState
from career_automation.status_ingestion_live import (
    ApplicationReceiptBinding,
    ClassifiedStatusEvent,
    LiveStatusIngestionResult,
)


MAX_PUBLIC_SOURCE_BYTES = 512 * 1024
MAX_DEBRIEF_BYTES = 512 * 1024
MAX_PUBLIC_SOURCE_AGE_DAYS = 45
MAX_EXCERPT_BYTES = 4 * 1024
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")

INTERVIEW_STATES = frozenset(
    {PipelineState.INTERVIEW, PipelineState.FINAL_STAGE, PipelineState.OFFER}
)
PUBLIC_SOURCE_KINDS = frozenset(
    {
        "official_company",
        "official_role",
        "official_team",
        "public_professional_organisation",
        "public_professional_team",
    }
)
PUBLIC_SUBJECT_SCOPES = frozenset({"organisation", "team"})

_INJECTION_MARKERS = (
    "ignore all previous instructions",
    "ignore previous instructions",
    "system prompt:",
    "developer message:",
    "developer: mark",
    "system: mark",
    "overwrite candidate",
    "alter candidate fact",
    "change candidate fact",
    "grant send authority",
)
_PRIVATE_OR_PROTECTED_MARKERS = (
    "private email",
    "personal email",
    "home address",
    "medical condition",
    "health condition",
    "sexual orientation",
    "religious belief",
    "racial origin",
    "ethnic origin",
)


class LiveInterviewCommunicationError(RuntimeError):
    """A live JAA-13 boundary check failed closed."""


class StatusEvidenceError(LiveInterviewCommunicationError):
    """JAA-12 evidence is missing, inconsistent, or not interview-stage."""


class PublicEvidenceError(LiveInterviewCommunicationError):
    """Public-professional evidence is unsafe, stale, uncited, or inconsistent."""


class DebriefEvidenceError(LiveInterviewCommunicationError):
    """Local debrief evidence is unsafe or inconsistent."""


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


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _required(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be normalized non-empty text")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise ValueError(f"{label} contains unsupported control characters")
    return value


def _identifier(value: object, label: str) -> str:
    text = _required(value, label)
    if SAFE_TOKEN.fullmatch(text) is None:
        raise ValueError(f"{label} contains unsupported characters")
    return text


def _aware(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value


def _parse_time(value: object, label: str) -> datetime:
    text = _required(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be ISO-8601") from exc
    return _aware(parsed, label)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _reject_untrusted_control_text(value: str, label: str) -> None:
    folded = value.casefold()
    if any(marker in folded for marker in _INJECTION_MARKERS):
        raise ValueError(f"{label} contains a prompt/control-plane injection marker")


def _reject_private_or_protected_text(value: str, label: str) -> None:
    folded = value.casefold()
    if any(marker in folded for marker in _PRIVATE_OR_PROTECTED_MARKERS):
        raise ValueError(f"{label} contains private or protected-person material")


def _public_https_url(value: object) -> str:
    url = _required(value, "public source URL")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("public source requires a credential-free HTTPS URL")
    host = parsed.hostname.casefold()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if host == "localhost" or "." not in host:
            raise ValueError("public source hostname is not public")
    else:
        if not address.is_global:
            raise ValueError("public source address is not public")
    return url


def _verify_status_boundary(
    binding: ApplicationReceiptBinding,
    status: LiveStatusIngestionResult,
) -> tuple[ClassifiedStatusEvent, ...]:
    if not isinstance(binding, ApplicationReceiptBinding):
        raise TypeError("JAA-13 requires ApplicationReceiptBinding")
    if not isinstance(status, LiveStatusIngestionResult):
        raise TypeError("JAA-13 requires LiveStatusIngestionResult")
    if status.binding_sha256 != binding.binding_sha256:
        raise StatusEvidenceError("JAA-12 status belongs to another application binding")
    if status.current_state not in INTERVIEW_STATES:
        raise StatusEvidenceError("JAA-12 status is not at an interview-stage state")
    events = tuple(status.events)
    if not events:
        raise StatusEvidenceError("interview-stage status requires source-backed events")
    for event in events:
        if (
            event.application_id != binding.application_id
            or event.job_key != binding.job_key
            or event.receipt_sha256 != binding.receipt_sha256
        ):
            raise StatusEvidenceError("JAA-12 event identity differs from the application")
        if not event.sources:
            raise StatusEvidenceError("JAA-12 event lacks raw source references")
    if not any(event.classified_state is status.current_state for event in events):
        raise StatusEvidenceError("current interview state lacks a matching classified event")
    return events


@dataclass(frozen=True)
class PublicProfessionalSnapshot:
    source_id: str
    url: str
    source_kind: str
    subject_scope: str
    captured_at: str
    content_text: str
    content_sha256: str
    snapshot_sha256: str
    instruction_authority: bool = False
    private_person_inference: bool = False
    schema_version: str = "jaa13.public-professional-snapshot.v1"

    def __post_init__(self) -> None:
        _identifier(self.source_id, "public source ID")
        _public_https_url(self.url)
        if self.source_kind not in PUBLIC_SOURCE_KINDS:
            raise ValueError("public source kind is unsupported")
        if self.subject_scope not in PUBLIC_SUBJECT_SCOPES:
            raise ValueError("public evidence may concern only an organisation or team")
        _parse_time(self.captured_at, "public capture time")
        text = _required(self.content_text, "public source text")
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_PUBLIC_SOURCE_BYTES:
            raise ValueError("public source exceeds the bounded input size")
        _reject_untrusted_control_text(text, "public source")
        _digest(self.content_sha256, "public source content hash")
        _digest(self.snapshot_sha256, "public snapshot identity")
        if hashlib.sha256(encoded).hexdigest() != self.content_sha256:
            raise ValueError("public source content differs from its hash")
        if self.instruction_authority is not False or self.private_person_inference is not False:
            raise ValueError("public source cannot carry instructions or person inference")
        if self.schema_version != "jaa13.public-professional-snapshot.v1":
            raise ValueError("public snapshot schema is unsupported")
        if self.snapshot_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("public snapshot differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "source_id": self.source_id,
            "url": self.url,
            "source_kind": self.source_kind,
            "subject_scope": self.subject_scope,
            "captured_at": self.captured_at,
            "content_text": self.content_text,
            "content_sha256": self.content_sha256,
            "instruction_authority": False,
            "private_person_inference": False,
        }
        if include_identity:
            result["snapshot_sha256"] = self.snapshot_sha256
        return result


def compile_public_professional_snapshot(
    *,
    source_id: str,
    url: str,
    source_kind: str,
    subject_scope: str,
    captured_at: datetime,
    content_bytes: bytes,
) -> PublicProfessionalSnapshot:
    """Compile exact operator-supplied bytes; never retrieves the URL."""

    if not isinstance(content_bytes, bytes) or not content_bytes:
        raise TypeError("public snapshot content must be non-empty bytes")
    if len(content_bytes) > MAX_PUBLIC_SOURCE_BYTES:
        raise ValueError("public source exceeds the bounded input size")
    try:
        text = content_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("public snapshot must be strict UTF-8") from exc
    body = {
        "schema_version": "jaa13.public-professional-snapshot.v1",
        "source_id": source_id,
        "url": url,
        "source_kind": source_kind,
        "subject_scope": subject_scope,
        "captured_at": _utc_text(_aware(captured_at, "public capture time")),
        "content_text": text,
        "content_sha256": hashlib.sha256(content_bytes).hexdigest(),
        "instruction_authority": False,
        "private_person_inference": False,
    }
    return PublicProfessionalSnapshot(
        **body,
        snapshot_sha256=_content_hash(body),
    )


@dataclass(frozen=True)
class ReleasedCandidateFact:
    application_id: str
    job_key: str
    release_manifest_sha256: str
    released_application_sha256: str
    text: str
    approved_evidence_id: str
    approved_evidence_sha256: str
    source_location: str
    fact_sha256: str
    authority: str = "released_candidate_fact_only"
    schema_version: str = "jaa13.released-candidate-fact.v1"

    def __post_init__(self) -> None:
        _identifier(self.application_id, "candidate fact application ID")
        _identifier(self.job_key, "candidate fact job key")
        _digest(self.release_manifest_sha256, "candidate fact release manifest")
        _digest(self.released_application_sha256, "candidate fact released application")
        _required(self.text, "candidate fact text")
        _identifier(self.approved_evidence_id, "candidate evidence ID")
        _digest(self.approved_evidence_sha256, "candidate evidence hash")
        _required(self.source_location, "candidate fact source location")
        _digest(self.fact_sha256, "candidate fact identity")
        if self.authority != "released_candidate_fact_only":
            raise ValueError("candidate fact authority cannot be broadened")
        if self.schema_version != "jaa13.released-candidate-fact.v1":
            raise ValueError("candidate fact schema is unsupported")
        if self.fact_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("candidate fact differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "release_manifest_sha256": self.release_manifest_sha256,
            "released_application_sha256": self.released_application_sha256,
            "text": self.text,
            "approved_evidence_id": self.approved_evidence_id,
            "approved_evidence_sha256": self.approved_evidence_sha256,
            "source_location": self.source_location,
            "authority": "released_candidate_fact_only",
        }
        if include_identity:
            result["fact_sha256"] = self.fact_sha256
        return result


def compile_released_candidate_fact(
    binding: ApplicationReceiptBinding,
    *,
    text: str,
    approved_evidence_id: str,
    approved_evidence_sha256: str,
    source_location: str,
) -> ReleasedCandidateFact:
    if not isinstance(binding, ApplicationReceiptBinding):
        raise TypeError("candidate fact requires ApplicationReceiptBinding")
    body = {
        "schema_version": "jaa13.released-candidate-fact.v1",
        "application_id": binding.application_id,
        "job_key": binding.job_key,
        "release_manifest_sha256": binding.release_manifest_sha256,
        "released_application_sha256": binding.released_application_sha256,
        "text": text,
        "approved_evidence_id": approved_evidence_id,
        "approved_evidence_sha256": approved_evidence_sha256,
        "source_location": source_location,
        "authority": "released_candidate_fact_only",
    }
    return ReleasedCandidateFact(**body, fact_sha256=_content_hash(body))


@dataclass(frozen=True)
class CitedPublicFact:
    snapshot_sha256: str
    source_id: str
    source_url: str
    source_content_sha256: str
    source_captured_at: str
    subject_scope: str
    exact_excerpt: str
    excerpt_sha256: str
    fact_sha256: str
    inference_authority: bool = False
    schema_version: str = "jaa13.cited-public-fact.v1"

    def __post_init__(self) -> None:
        _digest(self.snapshot_sha256, "public fact snapshot identity")
        _identifier(self.source_id, "public fact source ID")
        _public_https_url(self.source_url)
        _digest(self.source_content_sha256, "public fact source hash")
        _parse_time(self.source_captured_at, "public fact capture time")
        if self.subject_scope not in PUBLIC_SUBJECT_SCOPES:
            raise ValueError("public fact may concern only an organisation or team")
        excerpt = _required(self.exact_excerpt, "public fact excerpt")
        if len(excerpt.encode("utf-8")) > MAX_EXCERPT_BYTES:
            raise ValueError("public fact excerpt exceeds the bounded size")
        _reject_untrusted_control_text(excerpt, "public fact excerpt")
        _reject_private_or_protected_text(excerpt, "public fact excerpt")
        _digest(self.excerpt_sha256, "public fact excerpt hash")
        _digest(self.fact_sha256, "public fact identity")
        if hashlib.sha256(excerpt.encode("utf-8")).hexdigest() != self.excerpt_sha256:
            raise ValueError("public fact excerpt differs from its hash")
        if self.inference_authority is not False:
            raise ValueError("exact public excerpts cannot authorize inference")
        if self.schema_version != "jaa13.cited-public-fact.v1":
            raise ValueError("public fact schema is unsupported")
        if self.fact_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("public fact differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "snapshot_sha256": self.snapshot_sha256,
            "source_id": self.source_id,
            "source_url": self.source_url,
            "source_content_sha256": self.source_content_sha256,
            "source_captured_at": self.source_captured_at,
            "subject_scope": self.subject_scope,
            "exact_excerpt": self.exact_excerpt,
            "excerpt_sha256": self.excerpt_sha256,
            "inference_authority": False,
        }
        if include_identity:
            result["fact_sha256"] = self.fact_sha256
        return result


def compile_cited_public_fact(
    snapshot: PublicProfessionalSnapshot,
    *,
    exact_excerpt: str,
) -> CitedPublicFact:
    if not isinstance(snapshot, PublicProfessionalSnapshot):
        raise TypeError("public fact requires PublicProfessionalSnapshot")
    excerpt = _required(exact_excerpt, "public fact excerpt")
    if excerpt not in snapshot.content_text:
        raise PublicEvidenceError("public fact is not an exact snapshot excerpt")
    body = {
        "schema_version": "jaa13.cited-public-fact.v1",
        "snapshot_sha256": snapshot.snapshot_sha256,
        "source_id": snapshot.source_id,
        "source_url": snapshot.url,
        "source_content_sha256": snapshot.content_sha256,
        "source_captured_at": snapshot.captured_at,
        "subject_scope": snapshot.subject_scope,
        "exact_excerpt": excerpt,
        "excerpt_sha256": hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
        "inference_authority": False,
    }
    return CitedPublicFact(**body, fact_sha256=_content_hash(body))


@dataclass(frozen=True)
class InterviewPreparationItem:
    kind: str
    prompt: str
    provenance_sha256s: tuple[str, ...]
    item_sha256: str
    schema_version: str = "jaa13.interview-preparation-item.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "provenance_sha256s", tuple(self.provenance_sha256s))
        if self.kind not in {
            "candidate_story",
            "likely_objection",
            "technical_drill",
            "candidate_question",
        }:
            raise ValueError("interview preparation item kind is unsupported")
        _required(self.prompt, "interview preparation prompt")
        if not self.provenance_sha256s or len(set(self.provenance_sha256s)) != len(
            self.provenance_sha256s
        ):
            raise ValueError("preparation item provenance must be non-empty and unique")
        for digest in self.provenance_sha256s:
            _digest(digest, "preparation item provenance")
        _digest(self.item_sha256, "preparation item identity")
        if self.schema_version != "jaa13.interview-preparation-item.v1":
            raise ValueError("preparation item schema is unsupported")
        if self.item_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("preparation item differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "prompt": self.prompt,
            "provenance_sha256s": list(self.provenance_sha256s),
        }
        if include_identity:
            result["item_sha256"] = self.item_sha256
        return result


def _item(kind: str, prompt: str, provenance: tuple[str, ...]) -> InterviewPreparationItem:
    body = {
        "schema_version": "jaa13.interview-preparation-item.v1",
        "kind": kind,
        "prompt": prompt,
        "provenance_sha256s": list(provenance),
    }
    return InterviewPreparationItem(
        kind=kind,
        prompt=prompt,
        provenance_sha256s=provenance,
        item_sha256=_content_hash(body),
    )


@dataclass(frozen=True)
class LiveInterviewPreparationPack:
    application_id: str
    job_key: str
    receipt_sha256: str
    binding_sha256: str
    status_result_sha256: str
    current_state: PipelineState
    status_event_sha256s: tuple[str, ...]
    status_source_sha256s: tuple[str, ...]
    as_of: str
    candidate_facts: tuple[ReleasedCandidateFact, ...]
    public_snapshots: tuple[PublicProfessionalSnapshot, ...]
    public_facts: tuple[CitedPublicFact, ...]
    items: tuple[InterviewPreparationItem, ...]
    pack_sha256: str
    network_authority: bool = False
    private_person_inference: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa13.live-interview-preparation-pack.v1"

    def __post_init__(self) -> None:
        for field in ("status_event_sha256s", "status_source_sha256s"):
            object.__setattr__(self, field, tuple(getattr(self, field)))
        for field in ("candidate_facts", "public_snapshots", "public_facts", "items"):
            object.__setattr__(self, field, tuple(getattr(self, field)))
        _identifier(self.application_id, "preparation application ID")
        _identifier(self.job_key, "preparation job key")
        for value, label in (
            (self.receipt_sha256, "preparation receipt"),
            (self.binding_sha256, "preparation binding"),
            (self.status_result_sha256, "preparation status result"),
            (self.pack_sha256, "preparation pack identity"),
        ):
            _digest(value, label)
        if self.current_state not in INTERVIEW_STATES:
            raise ValueError("preparation pack state is not interview-stage")
        _parse_time(self.as_of, "preparation as-of time")
        for values, label in (
            (self.status_event_sha256s, "status events"),
            (self.status_source_sha256s, "status sources"),
            (tuple(row.fact_sha256 for row in self.candidate_facts), "candidate facts"),
            (tuple(row.snapshot_sha256 for row in self.public_snapshots), "public snapshots"),
            (tuple(row.fact_sha256 for row in self.public_facts), "public facts"),
            (tuple(row.item_sha256 for row in self.items), "preparation items"),
        ):
            if not values or len(set(values)) != len(values):
                raise ValueError(f"preparation {label} must be non-empty and unique")
        if any(not isinstance(row, ReleasedCandidateFact) for row in self.candidate_facts):
            raise TypeError("preparation candidate facts must be released facts")
        if any(not isinstance(row, PublicProfessionalSnapshot) for row in self.public_snapshots):
            raise TypeError("preparation sources must be public snapshots")
        if any(not isinstance(row, CitedPublicFact) for row in self.public_facts):
            raise TypeError("preparation public facts must be exact cited facts")
        if any(not isinstance(row, InterviewPreparationItem) for row in self.items):
            raise TypeError("preparation items must be typed items")
        if (
            self.network_authority is not False
            or self.private_person_inference is not False
            or self.certifies_slice is not False
        ):
            raise ValueError("preparation pack cannot browse, infer about people, or certify")
        if self.schema_version != "jaa13.live-interview-preparation-pack.v1":
            raise ValueError("preparation pack schema is unsupported")
        if self.pack_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("preparation pack differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "receipt_sha256": self.receipt_sha256,
            "binding_sha256": self.binding_sha256,
            "status_result_sha256": self.status_result_sha256,
            "current_state": self.current_state.value,
            "status_event_sha256s": list(self.status_event_sha256s),
            "status_source_sha256s": list(self.status_source_sha256s),
            "as_of": self.as_of,
            "candidate_facts": [row.document() for row in self.candidate_facts],
            "public_snapshots": [row.document() for row in self.public_snapshots],
            "public_facts": [row.document() for row in self.public_facts],
            "items": [row.document() for row in self.items],
            "network_authority": False,
            "private_person_inference": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["pack_sha256"] = self.pack_sha256
        return result


def compile_live_interview_preparation_pack(
    *,
    binding: ApplicationReceiptBinding,
    status: LiveStatusIngestionResult,
    candidate_facts: Sequence[ReleasedCandidateFact],
    public_snapshots: Sequence[PublicProfessionalSnapshot],
    public_facts: Sequence[CitedPublicFact],
    as_of: datetime,
) -> LiveInterviewPreparationPack:
    events = _verify_status_boundary(binding, status)
    as_of_time = _aware(as_of, "preparation as-of time").astimezone(timezone.utc)
    candidate_rows = tuple(candidate_facts)
    snapshot_rows = tuple(public_snapshots)
    public_rows = tuple(public_facts)
    if not candidate_rows or len({row.fact_sha256 for row in candidate_rows}) != len(candidate_rows):
        raise ValueError("candidate facts must be non-empty and unique")
    if not snapshot_rows or len({row.snapshot_sha256 for row in snapshot_rows}) != len(snapshot_rows):
        raise ValueError("public snapshots must be non-empty and unique")
    if not public_rows or len({row.fact_sha256 for row in public_rows}) != len(public_rows):
        raise ValueError("public facts must be non-empty and unique")
    for row in candidate_rows:
        if not isinstance(row, ReleasedCandidateFact):
            raise TypeError("candidate facts must be ReleasedCandidateFact")
        if (
            row.application_id != binding.application_id
            or row.job_key != binding.job_key
            or row.release_manifest_sha256 != binding.release_manifest_sha256
            or row.released_application_sha256 != binding.released_application_sha256
        ):
            raise ValueError("candidate fact is not bound to this released application")
    snapshots_by_id: dict[str, PublicProfessionalSnapshot] = {}
    for row in snapshot_rows:
        if not isinstance(row, PublicProfessionalSnapshot):
            raise TypeError("public snapshots must be PublicProfessionalSnapshot")
        captured = _parse_time(row.captured_at, "public capture time").astimezone(timezone.utc)
        if captured > as_of_time:
            raise PublicEvidenceError("public snapshot is future-dated")
        if as_of_time - captured > timedelta(days=MAX_PUBLIC_SOURCE_AGE_DAYS):
            raise PublicEvidenceError("public snapshot is stale and requires refresh")
        snapshots_by_id[row.snapshot_sha256] = row
    cited_snapshot_ids: set[str] = set()
    for fact in public_rows:
        if not isinstance(fact, CitedPublicFact):
            raise TypeError("public facts must be CitedPublicFact")
        snapshot = snapshots_by_id.get(fact.snapshot_sha256)
        if snapshot is None:
            raise PublicEvidenceError("public fact cites an unknown snapshot")
        if (
            fact.source_id != snapshot.source_id
            or fact.source_url != snapshot.url
            or fact.source_content_sha256 != snapshot.content_sha256
            or fact.source_captured_at != snapshot.captured_at
            or fact.subject_scope != snapshot.subject_scope
            or fact.exact_excerpt not in snapshot.content_text
        ):
            raise PublicEvidenceError("public fact lineage differs from its exact snapshot")
        cited_snapshot_ids.add(snapshot.snapshot_sha256)
    if cited_snapshot_ids != set(snapshots_by_id):
        raise PublicEvidenceError("every supplied public snapshot must be cited")

    items: list[InterviewPreparationItem] = []
    for fact in candidate_rows:
        provenance = (fact.fact_sha256, fact.approved_evidence_sha256)
        items.extend(
            (
                _item(
                    "candidate_story",
                    "Rehearse this released candidate fact without adding details: " + fact.text,
                    provenance,
                ),
                _item(
                    "likely_objection",
                    "Identify what an interviewer could challenge in this released candidate fact, and answer only from its cited evidence: "
                    + fact.text,
                    provenance,
                ),
                _item(
                    "technical_drill",
                    "Explain only the technical details already established by this released candidate fact, and state what is not established: "
                    + fact.text,
                    provenance,
                ),
            )
        )
    for fact in public_rows:
        items.append(
            _item(
                "candidate_question",
                "Draft one interview question grounded only in this exact public statement: "
                + fact.exact_excerpt,
                (fact.fact_sha256, fact.snapshot_sha256, fact.excerpt_sha256),
            )
        )
    if len({row.item_sha256 for row in items}) != len(items):
        raise ValueError("preparation compilation produced duplicate items")
    event_ids = tuple(row.event_sha256 for row in events)
    source_ids = tuple(
        sorted({source.source_sha256 for event in events for source in event.sources})
    )
    body = {
        "schema_version": "jaa13.live-interview-preparation-pack.v1",
        "application_id": binding.application_id,
        "job_key": binding.job_key,
        "receipt_sha256": binding.receipt_sha256,
        "binding_sha256": binding.binding_sha256,
        "status_result_sha256": status.result_sha256,
        "current_state": status.current_state.value,
        "status_event_sha256s": list(event_ids),
        "status_source_sha256s": list(source_ids),
        "as_of": _utc_text(as_of_time),
        "candidate_facts": [row.document() for row in candidate_rows],
        "public_snapshots": [row.document() for row in snapshot_rows],
        "public_facts": [row.document() for row in public_rows],
        "items": [row.document() for row in items],
        "network_authority": False,
        "private_person_inference": False,
        "certifies_slice": False,
    }
    return LiveInterviewPreparationPack(
        application_id=binding.application_id,
        job_key=binding.job_key,
        receipt_sha256=binding.receipt_sha256,
        binding_sha256=binding.binding_sha256,
        status_result_sha256=status.result_sha256,
        current_state=status.current_state,
        status_event_sha256s=event_ids,
        status_source_sha256s=source_ids,
        as_of=_utc_text(as_of_time),
        candidate_facts=candidate_rows,
        public_snapshots=snapshot_rows,
        public_facts=public_rows,
        items=tuple(items),
        pack_sha256=_content_hash(body),
    )


@dataclass(frozen=True)
class UnverifiedDebriefFact:
    exact_excerpt: str
    raw_content_sha256: str
    fact_sha256: str
    verification_status: str = "unverified_operator_statement"
    candidate_fact_authority: bool = False
    employer_fact_authority: bool = False
    schema_version: str = "jaa13.unverified-debrief-fact.v1"

    def __post_init__(self) -> None:
        _required(self.exact_excerpt, "debrief fact excerpt")
        _reject_untrusted_control_text(self.exact_excerpt, "debrief fact excerpt")
        _digest(self.raw_content_sha256, "debrief raw content hash")
        _digest(self.fact_sha256, "debrief fact identity")
        if (
            self.verification_status != "unverified_operator_statement"
            or self.candidate_fact_authority is not False
            or self.employer_fact_authority is not False
        ):
            raise ValueError("debrief fact cannot be promoted without corroboration")
        if self.schema_version != "jaa13.unverified-debrief-fact.v1":
            raise ValueError("debrief fact schema is unsupported")
        if self.fact_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("debrief fact differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "exact_excerpt": self.exact_excerpt,
            "raw_content_sha256": self.raw_content_sha256,
            "verification_status": "unverified_operator_statement",
            "candidate_fact_authority": False,
            "employer_fact_authority": False,
        }
        if include_identity:
            result["fact_sha256"] = self.fact_sha256
        return result


@dataclass(frozen=True)
class LocalDebriefEvidence:
    application_id: str
    job_key: str
    receipt_sha256: str
    binding_sha256: str
    status_result_sha256: str
    recorded_at: str
    raw_content_sha256: str
    byte_count: int
    facts: tuple[UnverifiedDebriefFact, ...]
    debrief_sha256: str
    raw_content_retained: bool = False
    verification_status: str = "unverified_operator_statement"
    certifies_slice: bool = False
    schema_version: str = "jaa13.local-debrief-evidence.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "facts", tuple(self.facts))
        _identifier(self.application_id, "debrief application ID")
        _identifier(self.job_key, "debrief job key")
        for value, label in (
            (self.receipt_sha256, "debrief receipt"),
            (self.binding_sha256, "debrief binding"),
            (self.status_result_sha256, "debrief status result"),
            (self.raw_content_sha256, "debrief raw content hash"),
            (self.debrief_sha256, "debrief identity"),
        ):
            _digest(value, label)
        _parse_time(self.recorded_at, "debrief recording time")
        if not 0 < self.byte_count <= MAX_DEBRIEF_BYTES:
            raise ValueError("debrief byte count is outside the bounded range")
        if not self.facts or len({row.fact_sha256 for row in self.facts}) != len(self.facts):
            raise ValueError("debrief facts must be non-empty and unique")
        if any(not isinstance(row, UnverifiedDebriefFact) for row in self.facts):
            raise TypeError("debrief facts must be UnverifiedDebriefFact")
        if any(row.raw_content_sha256 != self.raw_content_sha256 for row in self.facts):
            raise ValueError("debrief facts refer to another raw content hash")
        if (
            self.raw_content_retained is not False
            or self.verification_status != "unverified_operator_statement"
            or self.certifies_slice is not False
        ):
            raise ValueError("debrief evidence cannot retain content, promote facts, or certify")
        if self.schema_version != "jaa13.local-debrief-evidence.v1":
            raise ValueError("debrief evidence schema is unsupported")
        if self.debrief_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("debrief evidence differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "receipt_sha256": self.receipt_sha256,
            "binding_sha256": self.binding_sha256,
            "status_result_sha256": self.status_result_sha256,
            "recorded_at": self.recorded_at,
            "raw_content_sha256": self.raw_content_sha256,
            "byte_count": self.byte_count,
            "facts": [row.document() for row in self.facts],
            "raw_content_retained": False,
            "verification_status": "unverified_operator_statement",
            "certifies_slice": False,
        }
        if include_identity:
            result["debrief_sha256"] = self.debrief_sha256
        return result


def ingest_local_debrief(
    *,
    binding: ApplicationReceiptBinding,
    status: LiveStatusIngestionResult,
    raw_debrief_bytes: bytes,
    fact_excerpts: Sequence[str],
    recorded_at: datetime,
) -> LocalDebriefEvidence:
    events = _verify_status_boundary(binding, status)
    if not isinstance(raw_debrief_bytes, bytes) or not raw_debrief_bytes:
        raise TypeError("local debrief must be non-empty bytes")
    if len(raw_debrief_bytes) > MAX_DEBRIEF_BYTES:
        raise DebriefEvidenceError("local debrief exceeds the bounded input size")
    try:
        text = raw_debrief_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise DebriefEvidenceError("local debrief must be strict UTF-8") from exc
    _reject_untrusted_control_text(text, "local debrief")
    excerpts = tuple(fact_excerpts)
    if not excerpts or len(set(excerpts)) != len(excerpts):
        raise DebriefEvidenceError("debrief excerpts must be non-empty and unique")
    raw_sha256 = hashlib.sha256(raw_debrief_bytes).hexdigest()
    facts: list[UnverifiedDebriefFact] = []
    for excerpt in excerpts:
        selected = _required(excerpt, "debrief excerpt")
        if selected not in text:
            raise DebriefEvidenceError("debrief fact is not an exact raw-content excerpt")
        body = {
            "schema_version": "jaa13.unverified-debrief-fact.v1",
            "exact_excerpt": selected,
            "raw_content_sha256": raw_sha256,
            "verification_status": "unverified_operator_statement",
            "candidate_fact_authority": False,
            "employer_fact_authority": False,
        }
        facts.append(UnverifiedDebriefFact(**body, fact_sha256=_content_hash(body)))
    recorded = _aware(recorded_at, "debrief recording time").astimezone(timezone.utc)
    latest_event = max(
        _parse_time(event.observed_at, "status event time").astimezone(timezone.utc)
        for event in events
    )
    if recorded < latest_event:
        raise DebriefEvidenceError("debrief predates the source-backed interview event")
    body = {
        "schema_version": "jaa13.local-debrief-evidence.v1",
        "application_id": binding.application_id,
        "job_key": binding.job_key,
        "receipt_sha256": binding.receipt_sha256,
        "binding_sha256": binding.binding_sha256,
        "status_result_sha256": status.result_sha256,
        "recorded_at": _utc_text(recorded),
        "raw_content_sha256": raw_sha256,
        "byte_count": len(raw_debrief_bytes),
        "facts": [row.document() for row in facts],
        "raw_content_retained": False,
        "verification_status": "unverified_operator_statement",
        "certifies_slice": False,
    }
    return LocalDebriefEvidence(
        application_id=binding.application_id,
        job_key=binding.job_key,
        receipt_sha256=binding.receipt_sha256,
        binding_sha256=binding.binding_sha256,
        status_result_sha256=status.result_sha256,
        recorded_at=_utc_text(recorded),
        raw_content_sha256=raw_sha256,
        byte_count=len(raw_debrief_bytes),
        facts=tuple(facts),
        debrief_sha256=_content_hash(body),
    )


FOLLOW_UP_TEXT = (
    "Thank you for your time during the interview. I appreciated the conversation "
    "and remain interested in the role. Kind regards."
)


@dataclass(frozen=True)
class NonSendableFollowUpDraft:
    draft_key: str
    application_id: str
    job_key: str
    receipt_sha256: str
    preparation_pack_sha256: str
    debrief_sha256: str
    text: str
    text_sha256: str
    draft_sha256: str
    operator_confirmation_required: bool = True
    operator_confirmed: bool = False
    send_authority: bool = False
    max_sends: int = 0
    certifies_slice: bool = False
    schema_version: str = "jaa13.non-sendable-follow-up-draft.v1"

    def __post_init__(self) -> None:
        if not self.draft_key.startswith("jaa13-draft:"):
            raise ValueError("follow-up draft key has an unsupported namespace")
        _identifier(self.application_id, "draft application ID")
        _identifier(self.job_key, "draft job key")
        for value, label in (
            (self.receipt_sha256, "draft receipt"),
            (self.preparation_pack_sha256, "draft preparation pack"),
            (self.debrief_sha256, "draft debrief"),
            (self.text_sha256, "draft text hash"),
            (self.draft_sha256, "draft identity"),
        ):
            _digest(value, label)
        if self.text != FOLLOW_UP_TEXT or hashlib.sha256(self.text.encode()).hexdigest() != self.text_sha256:
            raise ValueError("follow-up draft text differs from the fixed truthful template")
        if (
            self.operator_confirmation_required is not True
            or self.operator_confirmed is not False
            or self.send_authority is not False
            or self.max_sends != 0
            or self.certifies_slice is not False
        ):
            raise ValueError("follow-up draft must remain unconfirmed and non-sendable")
        if self.schema_version != "jaa13.non-sendable-follow-up-draft.v1":
            raise ValueError("follow-up draft schema is unsupported")
        scope = {
            "schema_version": "jaa13.follow-up-draft-key.v1",
            "application_id": self.application_id,
            "job_key": self.job_key,
            "receipt_sha256": self.receipt_sha256,
            "preparation_pack_sha256": self.preparation_pack_sha256,
            "debrief_sha256": self.debrief_sha256,
            "purpose": "post_interview_follow_up",
        }
        if self.draft_key != f"jaa13-draft:{_content_hash(scope)}":
            raise ValueError("follow-up draft key differs from its at-most-once scope")
        if self.draft_sha256 != _content_hash(self.document(include_identity=False)):
            raise ValueError("follow-up draft differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "draft_key": self.draft_key,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "receipt_sha256": self.receipt_sha256,
            "preparation_pack_sha256": self.preparation_pack_sha256,
            "debrief_sha256": self.debrief_sha256,
            "text": self.text,
            "text_sha256": self.text_sha256,
            "operator_confirmation_required": True,
            "operator_confirmed": False,
            "send_authority": False,
            "max_sends": 0,
            "certifies_slice": False,
        }
        if include_identity:
            result["draft_sha256"] = self.draft_sha256
        return result


def compile_non_sendable_follow_up_draft(
    *,
    preparation_pack: LiveInterviewPreparationPack,
    debrief: LocalDebriefEvidence,
) -> NonSendableFollowUpDraft:
    if not isinstance(preparation_pack, LiveInterviewPreparationPack):
        raise TypeError("follow-up draft requires LiveInterviewPreparationPack")
    if not isinstance(debrief, LocalDebriefEvidence):
        raise TypeError("follow-up draft requires LocalDebriefEvidence")
    if (
        debrief.application_id != preparation_pack.application_id
        or debrief.job_key != preparation_pack.job_key
        or debrief.receipt_sha256 != preparation_pack.receipt_sha256
        or debrief.binding_sha256 != preparation_pack.binding_sha256
        or debrief.status_result_sha256 != preparation_pack.status_result_sha256
    ):
        raise ValueError("follow-up inputs belong to different application evidence")
    scope = {
        "schema_version": "jaa13.follow-up-draft-key.v1",
        "application_id": preparation_pack.application_id,
        "job_key": preparation_pack.job_key,
        "receipt_sha256": preparation_pack.receipt_sha256,
        "preparation_pack_sha256": preparation_pack.pack_sha256,
        "debrief_sha256": debrief.debrief_sha256,
        "purpose": "post_interview_follow_up",
    }
    draft_key = f"jaa13-draft:{_content_hash(scope)}"
    text_sha256 = hashlib.sha256(FOLLOW_UP_TEXT.encode()).hexdigest()
    body = {
        "schema_version": "jaa13.non-sendable-follow-up-draft.v1",
        "draft_key": draft_key,
        "application_id": preparation_pack.application_id,
        "job_key": preparation_pack.job_key,
        "receipt_sha256": preparation_pack.receipt_sha256,
        "preparation_pack_sha256": preparation_pack.pack_sha256,
        "debrief_sha256": debrief.debrief_sha256,
        "text": FOLLOW_UP_TEXT,
        "text_sha256": text_sha256,
        "operator_confirmation_required": True,
        "operator_confirmed": False,
        "send_authority": False,
        "max_sends": 0,
        "certifies_slice": False,
    }
    return NonSendableFollowUpDraft(**body, draft_sha256=_content_hash(body))
