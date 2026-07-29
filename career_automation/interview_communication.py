"""Inert interview preparation and communication contract for JAA-13.

The module binds approved application facts to local preparation plans, marks
local debrief bytes as unverified, and creates non-sendable draft plans. It
does not retrieve sources, promote facts, render a message, or perform an
external action.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from types import MappingProxyType
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from .application_artifacts import PublishedArtifactReceipt
from .application_compiler import (
    ApplicationSource,
    FactualSentence,
    validate_style_text,
    verify_application_source,
)
from .ats_fixture import FixtureReceipt
from .browser_workflows import SubmissionProof
from .employer_research import (
    FRESHNESS_DAYS,
    PROTECTED_FIELDS,
    RawResponseCache,
    validate_dossier,
)
from .models import IntelligenceKind, PipelineState
from .release_gate import (
    ReleaseManifest,
    verify_release_manifest,
)
from .status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    StatusTimeline,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
INTERVIEW_STATES = (
    PipelineState.INTERVIEW,
    PipelineState.FINAL_STAGE,
    PipelineState.OFFER,
)
HUMANIZER_FORBIDDEN = (
    "\u2014",
    "\u2013",
    " -- ",
    "delve",
    "pivotal",
    "showcase",
    "tapestry",
    "i hope this helps",
    "let me know",
    "not only",
    "it's not just",
)
CONNECTIVE_TEMPLATES: Mapping[str, str] = MappingProxyType({
    "kind_regards": "Kind regards.",
    "thank_you_for_time": "Thank you for your time.",
})
SENSITIVE_EMPLOYER_TEXT = re.compile(
    r"\b(?:health condition|medical condition|private email|personal email)\b",
    re.IGNORECASE,
)
PREPARATION_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa13.interview-preparation-policy.v1",
    "candidate_authority": "exact_approved_application_fact",
    "employer_authority": "exact_current_cited_application_fact",
    "stale_evidence": "refresh_required_but_not_authorized",
    "private_person_inference": False,
})
DEBRIEF_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa13.local-debrief-policy.v1",
    "retention": "content_addressed_reference_only",
    "assertion_status": "unverified_operator_statement",
    "candidate_fact_authority": False,
    "employer_fact_authority": False,
})
DRAFT_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa13.follow-up-draft-plan-policy.v2",
    "factual_atoms": "exact_preparation_authority_only",
    "connective_templates": tuple(sorted(CONNECTIVE_TEMPLATES.items())),
    "debrief_fact_authority": False,
    "operator_confirmation_required": True,
    "truth_release_authority": "withheld",
    "connector_authority": "withheld",
    "send_authority": "withheld",
})


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _required(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    if value != value.strip():
        raise ValueError(f"{label} must not contain surrounding whitespace")
    return value


def _aware(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{label} must include a timezone")
    return value


def _connective_text(template_ids: tuple[str, ...]) -> tuple[str, ...]:
    if (
        not template_ids
        or len(template_ids) != len(set(template_ids))
        or any(value not in CONNECTIVE_TEMPLATES for value in template_ids)
    ):
        raise ValueError("draft connective template is unsupported or duplicated")
    values = tuple(CONNECTIVE_TEMPLATES[value] for value in template_ids)
    for value in values:
        validate_style_text(value)
        if any(
            pattern in value.casefold() for pattern in HUMANIZER_FORBIDDEN
        ):
            raise ValueError(
                "draft connective violates the natural-language policy"
            )
    return values


PREPARATION_POLICY_SHA256 = _content_hash(dict(PREPARATION_POLICY))
DEBRIEF_POLICY_SHA256 = _content_hash(dict(DEBRIEF_POLICY))
DRAFT_POLICY_SHA256 = _content_hash(dict(DRAFT_POLICY))


@dataclass(frozen=True)
class InterviewCommunicationContract:
    upstream_status_contract_sha256: str
    preparation_policy_sha256: str
    debrief_policy_sha256: str
    draft_policy_sha256: str
    source_refresh_authority: str = "withheld"
    private_person_inference: bool = False
    candidate_fact_mutation_authority: bool = False
    connector_authority: str = "withheld"
    message_send_authority: str = "withheld"
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa13.local-interview-communication-contract.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (self.upstream_status_contract_sha256, "upstream status hash"),
            (self.preparation_policy_sha256, "preparation policy hash"),
            (self.debrief_policy_sha256, "debrief policy hash"),
            (self.draft_policy_sha256, "draft policy hash"),
        ):
            _digest(value, label)
        expected = (
            FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256,
            PREPARATION_POLICY_SHA256,
            DEBRIEF_POLICY_SHA256,
            DRAFT_POLICY_SHA256,
        )
        actual = (
            self.upstream_status_contract_sha256,
            self.preparation_policy_sha256,
            self.debrief_policy_sha256,
            self.draft_policy_sha256,
        )
        if actual != expected:
            raise ValueError("interview contract differs from accepted policies")
        if (
            self.source_refresh_authority != "withheld"
            or self.private_person_inference is not False
            or self.candidate_fact_mutation_authority is not False
            or self.connector_authority != "withheld"
            or self.message_send_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError("local interview contract cannot act or certify")
        if self.schema_version != (
            "jaa13.local-interview-communication-contract.v1"
        ):
            raise ValueError("interview contract schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "upstream_status_contract_sha256": (
                self.upstream_status_contract_sha256
            ),
            "preparation_policy_sha256": self.preparation_policy_sha256,
            "debrief_policy_sha256": self.debrief_policy_sha256,
            "draft_policy_sha256": self.draft_policy_sha256,
            "source_refresh_authority": "withheld",
            "private_person_inference": False,
            "candidate_fact_mutation_authority": False,
            "connector_authority": "withheld",
            "message_send_authority": "withheld",
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_INTERVIEW_COMMUNICATION_CONTRACT = InterviewCommunicationContract(
    upstream_status_contract_sha256=(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
    ),
    preparation_policy_sha256=PREPARATION_POLICY_SHA256,
    debrief_policy_sha256=DEBRIEF_POLICY_SHA256,
    draft_policy_sha256=DRAFT_POLICY_SHA256,
)


def _public_source_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("employer evidence requires a public HTTPS source")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if (
            parsed.hostname.casefold() == "localhost"
            or "." not in parsed.hostname
        ):
            raise ValueError(
                "employer evidence requires a public source hostname"
            )
    else:
        if not address.is_global:
            raise ValueError(
                "employer evidence requires a public source address"
            )
    return value


def _contains_protected_key(value: object) -> bool:
    if isinstance(value, Mapping):
        if PROTECTED_FIELDS.intersection(
            str(key).casefold() for key in value
        ):
            return True
        return any(_contains_protected_key(row) for row in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_protected_key(row) for row in value)
    return False


def _contains_sensitive_text(value: object) -> bool:
    if isinstance(value, str):
        return SENSITIVE_EMPLOYER_TEXT.search(value) is not None
    if isinstance(value, Mapping):
        return any(_contains_sensitive_text(row) for row in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_text(row) for row in value)
    return False


@dataclass(frozen=True)
class EmbeddedPublicCapture:
    raw_response_ref: str
    content_sha256: str
    content_base64: str

    def __post_init__(self) -> None:
        _required(self.raw_response_ref, "embedded capture reference")
        _digest(self.content_sha256, "embedded capture hash")
        try:
            content = base64.b64decode(
                self.content_base64,
                validate=True,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "embedded capture must be canonical base64"
            ) from exc
        if (
            not content
            or base64.b64encode(content).decode() != self.content_base64
            or hashlib.sha256(content).hexdigest() != self.content_sha256
        ):
            raise ValueError(
                "embedded capture differs from its exact public bytes"
            )

    @property
    def content(self) -> bytes:
        return base64.b64decode(self.content_base64, validate=True)

    def document(self) -> dict[str, object]:
        return {
            "raw_response_ref": self.raw_response_ref,
            "content_sha256": self.content_sha256,
            "content_base64": self.content_base64,
        }


class _EmbeddedCaptureResolver:
    def __init__(self, captures: tuple[EmbeddedPublicCapture, ...]) -> None:
        self._captures = {
            (row.raw_response_ref, row.content_sha256): row.content
            for row in captures
        }

    def resolve(self, reference: str, digest: str) -> bytes:
        try:
            return self._captures[(reference, digest)]
        except KeyError as exc:
            raise ValueError(
                "employer dossier cites an unembedded public capture"
            ) from exc


@dataclass(frozen=True)
class EmployerDossierEvidence:
    dossier_json: str
    captures: tuple[EmbeddedPublicCapture, ...]
    as_of: str
    dossier_sha256: str
    evidence_id: str
    authority_claim: str = "structural_public_lineage_only"
    schema_version: str = "jaa13.employer-dossier-evidence.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "captures", tuple(self.captures))
        self.verify()

    def dossier(self) -> dict[str, object]:
        try:
            value = json.loads(self.dossier_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "employer dossier evidence is not valid JSON"
            ) from exc
        if (
            not isinstance(value, dict)
            or _canonical_json(value) != self.dossier_json
        ):
            raise ValueError(
                "employer dossier evidence is not canonical"
            )
        return value

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "dossier_json": self.dossier_json,
            "captures": tuple(row.document() for row in self.captures),
            "as_of": self.as_of,
            "dossier_sha256": self.dossier_sha256,
            "authority_claim": "structural_public_lineage_only",
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        dossier = self.dossier()
        _digest(self.dossier_sha256, "employer dossier hash")
        if self.dossier_sha256 != _content_hash(dossier):
            raise ValueError(
                "employer dossier hash differs from its exact content"
            )
        as_of = date.fromisoformat(self.as_of)
        if (
            not self.captures
            or len({
                (row.raw_response_ref, row.content_sha256)
                for row in self.captures
            })
            != len(self.captures)
        ):
            raise ValueError(
                "employer dossier captures must be non-empty and unique"
            )
        if (
            _contains_protected_key(dossier)
            or _contains_sensitive_text(dossier)
        ):
            raise ValueError(
                "employer dossier contains protected or private information"
            )
        claims = dossier.get("claims")
        if not isinstance(claims, list):
            raise ValueError("employer dossier claims are missing")
        for claim in claims:
            if not isinstance(claim, Mapping):
                raise ValueError("employer dossier claim is malformed")
            if (
                claim.get("classification") == "fact"
                and claim.get("subject_type") != "organisation"
            ):
                raise ValueError(
                    "employer fact must concern an organisation"
                )
        sources = dossier.get("sources")
        if not isinstance(sources, list):
            raise ValueError("employer dossier sources are missing")
        for source in sources:
            if not isinstance(source, Mapping):
                raise ValueError("employer dossier source is malformed")
            _public_source_url(str(source.get("url", "")))
        validate_dossier(
            dossier,
            _EmbeddedCaptureResolver(self.captures),  # type: ignore[arg-type]
            as_of=as_of,
        )
        if self.authority_claim != "structural_public_lineage_only":
            raise ValueError(
                "employer dossier cannot claim external authenticity"
            )
        if self.schema_version != "jaa13.employer-dossier-evidence.v1":
            raise ValueError("employer dossier evidence schema is unsupported")
        if self.evidence_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError(
                "employer dossier evidence differs from exact content"
            )


def compile_employer_dossier_evidence(
    dossier: Mapping[str, object],
    cache: RawResponseCache,
    *,
    as_of: date,
) -> EmployerDossierEvidence:
    canonical = _canonical_json(dict(dossier))
    parsed = json.loads(canonical)
    validate_dossier(parsed, cache, as_of=as_of)
    sources = parsed.get("sources")
    if not isinstance(sources, list):
        raise ValueError("employer dossier sources are missing")
    captures = tuple(
        EmbeddedPublicCapture(
            raw_response_ref=str(row["raw_response_ref"]),
            content_sha256=str(row["content_sha256"]),
            content_base64=base64.b64encode(
                cache.resolve(
                    str(row["raw_response_ref"]),
                    str(row["content_sha256"]),
                )
            ).decode(),
        )
        for row in sources
    )
    body = {
        "schema_version": "jaa13.employer-dossier-evidence.v1",
        "dossier_json": canonical,
        "captures": tuple(row.document() for row in captures),
        "as_of": as_of.isoformat(),
        "dossier_sha256": _content_hash(parsed),
        "authority_claim": "structural_public_lineage_only",
    }
    return EmployerDossierEvidence(
        dossier_json=canonical,
        captures=captures,
        as_of=as_of.isoformat(),
        dossier_sha256=str(body["dossier_sha256"]),
        evidence_id=_content_hash(body),
    )


@dataclass(frozen=True)
class CandidateStoryAuthority:
    sentence_id: str
    approved_text_sha256: str
    requirement_id: str
    candidate_claim_id: str
    candidate_claim_version: int
    candidate_evidence_id: str
    candidate_evidence_version: int

    def __post_init__(self) -> None:
        for value, label in (
            (self.sentence_id, "story sentence ID"),
            (self.approved_text_sha256, "story text hash"),
        ):
            _digest(value, label)
        for value, label in (
            (self.requirement_id, "story requirement ID"),
            (self.candidate_claim_id, "story claim ID"),
            (self.candidate_evidence_id, "story evidence ID"),
        ):
            _required(value, label)
        if self.candidate_claim_version < 1 or self.candidate_evidence_version < 1:
            raise ValueError("story authority versions must be positive")

    def document(self) -> dict[str, object]:
        return vars(self)


@dataclass(frozen=True)
class EmployerGuidanceAuthority:
    sentence_id: str
    approved_text_sha256: str
    employer_claim_id: str
    employer_fact_sha256: str
    intelligence_kind: str
    source_ids: tuple[str, ...]
    source_urls: tuple[str, ...]
    source_content_sha256s: tuple[str, ...]
    citation_excerpt: str
    citation_excerpt_sha256: str
    dossier_evidence_id: str
    dossier_sha256: str
    observed_at: str
    freshness_deadline: str
    freshness_status: str = "current"
    private_person_inference: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_ids", tuple(self.source_ids))
        object.__setattr__(self, "source_urls", tuple(self.source_urls))
        object.__setattr__(
            self,
            "source_content_sha256s",
            tuple(self.source_content_sha256s),
        )
        for value, label in (
            (self.sentence_id, "employer sentence ID"),
            (self.approved_text_sha256, "employer text hash"),
            (self.employer_fact_sha256, "employer fact hash"),
            (self.citation_excerpt_sha256, "employer excerpt hash"),
            (self.dossier_evidence_id, "employer dossier evidence ID"),
            (self.dossier_sha256, "employer dossier hash"),
        ):
            _digest(value, label)
        _required(self.employer_claim_id, "employer claim ID")
        kind = IntelligenceKind(self.intelligence_kind)
        if (
            not self.source_ids
            or len(self.source_ids) != len(set(self.source_ids))
            or not all(
                isinstance(value, str) and value.strip()
                for value in self.source_ids
            )
        ):
            raise ValueError("employer guidance requires unique source IDs")
        if (
            len(self.source_urls) != len(self.source_ids)
            or len(self.source_content_sha256s) != len(self.source_ids)
        ):
            raise ValueError(
                "employer guidance source lineage is incomplete"
            )
        for value in self.source_urls:
            _public_source_url(value)
        for value in self.source_content_sha256s:
            _digest(value, "employer source content hash")
        if (
            not self.citation_excerpt.strip()
            or hashlib.sha256(self.citation_excerpt.encode()).hexdigest()
            != self.citation_excerpt_sha256
            or SENSITIVE_EMPLOYER_TEXT.search(self.citation_excerpt)
        ):
            raise ValueError(
                "employer guidance excerpt is unsafe or inconsistent"
            )
        if self.freshness_status != "current":
            raise ValueError("interview guidance requires current evidence")
        if self.private_person_inference is not False:
            raise ValueError("private-person inference is forbidden")
        observed = datetime.fromisoformat(self.observed_at)
        deadline = date.fromisoformat(self.freshness_deadline)
        _aware(observed, "employer guidance observation time")
        expected_deadline = observed.date() + timedelta(
            days=FRESHNESS_DAYS[kind]
        )
        if deadline != expected_deadline:
            raise ValueError(
                "employer guidance freshness deadline differs from policy"
            )

    def document(self) -> dict[str, object]:
        return {
            **vars(self),
            "source_ids": self.source_ids,
        }


@dataclass(frozen=True)
class PreparationItem:
    item_id: str
    kind: str
    prompt: str
    authority_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "authority_ids", tuple(self.authority_ids))
        _digest(self.item_id, "preparation item ID")
        if self.kind not in {
            "candidate_story",
            "likely_objection",
            "technical_drill",
            "candidate_question",
        }:
            raise ValueError("preparation item kind is unsupported")
        validate_style_text(self.prompt)
        if not self.authority_ids or len(self.authority_ids) != len(
            set(self.authority_ids)
        ):
            raise ValueError("preparation item requires unique authority")
        expected = _content_hash({
            "kind": self.kind,
            "prompt": self.prompt,
            "authority_ids": self.authority_ids,
        })
        if self.item_id != expected:
            raise ValueError("preparation item differs from exact content")

    def document(self) -> dict[str, object]:
        return {
            "item_id": self.item_id,
            "kind": self.kind,
            "prompt": self.prompt,
            "authority_ids": self.authority_ids,
        }


def _submission_proof_document(
    proof: SubmissionProof,
) -> dict[str, object]:
    return {
        "release_manifest_sha256": proof.release_manifest_sha256,
        "token_sha256": proof.token_sha256,
        "receipt_id": proof.receipt_id,
        "receipt_payload_sha256": proof.receipt_payload_sha256,
        "screenshot_sha256": proof.screenshot_sha256,
        "field_map_sha256": proof.field_map_sha256,
        "submit_event_sha256": proof.submit_event_sha256,
    }


def _verify_publication_receipt(
    receipt: PublishedArtifactReceipt,
) -> None:
    if not isinstance(receipt, PublishedArtifactReceipt):
        raise TypeError(
            "preparation requires a typed publication receipt"
        )
    expected = hashlib.sha256(
        _canonical_json(
            receipt.document(include_receipt_hash=False)
        ).encode()
    ).hexdigest()
    if receipt.receipt_sha256 != expected:
        raise ValueError(
            "publication receipt differs from its exact content"
        )


def _timeline_latest_date(timeline: StatusTimeline) -> date | None:
    values = [
        datetime.fromisoformat(row.observed_at).date()
        for row in timeline.observations
    ]
    values.extend(
        datetime.fromisoformat(row.as_of).date()
        for row in timeline.censored_silence
    )
    return max(values) if values else None


@dataclass(frozen=True)
class InterviewPreparationPack:
    contract_sha256: str
    application_id: str
    source: ApplicationSource
    timeline: StatusTimeline
    release_manifest: ReleaseManifest
    publication_receipt: PublishedArtifactReceipt
    submission_proof: SubmissionProof
    fixture_receipt: FixtureReceipt
    employer_evidence: EmployerDossierEvidence
    as_of: str
    candidate_authorities: tuple[CandidateStoryAuthority, ...]
    employer_authorities: tuple[EmployerGuidanceAuthority, ...]
    items: tuple[PreparationItem, ...]
    pack_id: str
    source_refresh_authority: str = "withheld"
    private_person_inference: bool = False
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    lineage_claim: str = "structural_lineage_only"
    schema_version: str = "jaa13.interview-preparation-pack.v2"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "candidate_authorities",
            tuple(self.candidate_authorities),
        )
        object.__setattr__(
            self,
            "employer_authorities",
            tuple(self.employer_authorities),
        )
        object.__setattr__(self, "items", tuple(self.items))
        self.verify()

    @property
    def job_key(self) -> str:
        return self.source.job_key

    @property
    def released_application_sha256(self) -> str:
        return self.release_manifest.release_manifest_sha256

    @property
    def application_source_id(self) -> str:
        return self.source.source_id

    @property
    def application_source_content_sha256(self) -> str:
        return self.source.content_sha256

    @property
    def timeline_id(self) -> str:
        return self.timeline.timeline_id

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "released_application_sha256": self.released_application_sha256,
            "application_source_id": self.application_source_id,
            "application_source_content_sha256": (
                self.application_source_content_sha256
            ),
            "timeline_id": self.timeline_id,
            "source": self.source.document(),
            "timeline": self.timeline.document(),
            "release_manifest": self.release_manifest.document(),
            "publication_receipt": self.publication_receipt.document(),
            "submission_proof": _submission_proof_document(
                self.submission_proof
            ),
            "fixture_receipt": self.fixture_receipt.document(),
            "employer_evidence": self.employer_evidence.document(),
            "as_of": self.as_of,
            "candidate_authorities": tuple(
                row.document() for row in self.candidate_authorities
            ),
            "employer_authorities": tuple(
                row.document() for row in self.employer_authorities
            ),
            "items": tuple(row.document() for row in self.items),
            "source_refresh_authority": "withheld",
            "private_person_inference": False,
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
            "lineage_claim": "structural_lineage_only",
        }
        if include_identity:
            result["pack_id"] = self.pack_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "preparation contract hash"),
            (self.pack_id, "preparation pack ID"),
        ):
            _digest(value, label)
        _required(self.application_id, "preparation application ID")
        as_of = date.fromisoformat(self.as_of)
        if (
            self.contract_sha256
            != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT.contract_sha256
        ):
            raise ValueError("preparation pack binds a different contract")
        if not isinstance(self.source, ApplicationSource):
            raise TypeError(
                "preparation pack requires a typed application source"
            )
        if not isinstance(self.timeline, StatusTimeline):
            raise TypeError(
                "preparation pack requires a typed status timeline"
            )
        if not isinstance(self.release_manifest, ReleaseManifest):
            raise TypeError(
                "preparation pack requires a typed release manifest"
            )
        if not isinstance(self.submission_proof, SubmissionProof):
            raise TypeError(
                "preparation pack requires a typed submission proof"
            )
        if not isinstance(self.fixture_receipt, FixtureReceipt):
            raise TypeError(
                "preparation pack requires a typed fixture receipt"
            )
        if not isinstance(self.employer_evidence, EmployerDossierEvidence):
            raise TypeError(
                "preparation pack requires typed employer evidence"
            )
        verify_application_source(self.source)
        self.timeline.verify()
        verify_release_manifest(self.release_manifest)
        _verify_publication_receipt(self.publication_receipt)
        self.fixture_receipt.verify()
        self.employer_evidence.verify()
        binding = self.release_manifest.binding
        if (
            binding.job_key != self.source.job_key
            or binding.application_source_id != self.source.source_id
            or binding.application_source_sha256
            != self.source.content_sha256
            or binding.artifact_set_sha256
            != self.publication_receipt.artifact_set_sha256
            or binding.artifact_receipt_sha256
            != self.publication_receipt.receipt_sha256
            or self.publication_receipt.source_id != self.source.source_id
        ):
            raise ValueError(
                "preparation release lineage identifies different source bytes"
            )
        if (
            self.submission_proof.release_manifest_sha256
            != self.release_manifest.release_manifest_sha256
            or self.submission_proof.receipt_id
            != self.fixture_receipt.receipt_id
            or self.submission_proof.receipt_payload_sha256
            != self.fixture_receipt.payload_sha256
        ):
            raise ValueError(
                "preparation submission proof differs from release receipt"
            )
        if (
            self.timeline.application_id != self.application_id
            or self.timeline.job_key != self.source.job_key
            or self.fixture_receipt.application_id != self.application_id
            or self.fixture_receipt.job_key != self.source.job_key
        ):
            raise ValueError(
                "preparation lineage identifies a different application"
            )
        if self.timeline.final_state not in INTERVIEW_STATES:
            raise ValueError(
                "interview preparation requires an interview-stage timeline"
            )
        latest_timeline_date = _timeline_latest_date(self.timeline)
        if (
            latest_timeline_date is not None
            and as_of < latest_timeline_date
        ):
            raise ValueError(
                "preparation as-of predates status timeline evidence"
            )
        if as_of < binding.evaluated_at:
            raise ValueError(
                "preparation as-of predates release evaluation"
            )
        dossier = self.employer_evidence.dossier()
        if (
            dossier.get("job_key") != self.source.job_key
            or self.employer_evidence.as_of != self.as_of
        ):
            raise ValueError(
                "employer evidence identifies a different job or as-of date"
            )
        fact_by_id = {
            row.sentence_id: row for row in self.source.facts
        }
        candidate_ids = tuple(
            row.sentence_id for row in self.candidate_authorities
        )
        employer_ids = tuple(
            row.sentence_id for row in self.employer_authorities
        )
        if (
            not candidate_ids
            or not employer_ids
            or len(candidate_ids) != len(set(candidate_ids))
            or len(employer_ids) != len(set(employer_ids))
        ):
            raise ValueError("preparation authority must be non-empty and unique")
        try:
            expected_candidate = tuple(
                _candidate_authority(fact_by_id[value])
                for value in candidate_ids
            )
            expected_employer = tuple(
                _employer_authority(
                    fact_by_id[value],
                    evidence=self.employer_evidence,
                    as_of=as_of,
                )
                for value in employer_ids
            )
        except KeyError as exc:
            raise ValueError(
                "preparation authority cites an unknown source fact"
            ) from exc
        if (
            self.candidate_authorities != expected_candidate
            or self.employer_authorities != expected_employer
        ):
            raise ValueError(
                "preparation authorities differ from embedded source lineage"
            )
        for row in self.employer_authorities:
            observed = datetime.fromisoformat(row.observed_at)
            deadline = date.fromisoformat(row.freshness_deadline)
            if observed.date() > as_of:
                raise ValueError(
                    "future employer evidence cannot guide preparation"
                )
            if as_of > deadline:
                raise ValueError(
                    "employer guidance is stale; source refresh is required"
                )
        allowed = set(candidate_ids) | set(employer_ids)
        item_ids = tuple(row.item_id for row in self.items)
        if not item_ids or len(item_ids) != len(set(item_ids)):
            raise ValueError("preparation items must be non-empty and unique")
        if any(not set(row.authority_ids).issubset(allowed) for row in self.items):
            raise ValueError("preparation item cites unknown authority")
        if {row.kind for row in self.items} != {
            "candidate_story",
            "likely_objection",
            "technical_drill",
            "candidate_question",
        }:
            raise ValueError("preparation pack must cover every item kind")
        if (
            self.source_refresh_authority != "withheld"
            or self.private_person_inference is not False
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
            or self.lineage_claim != "structural_lineage_only"
        ):
            raise ValueError("local preparation pack cannot act or certify")
        if self.schema_version != "jaa13.interview-preparation-pack.v2":
            raise ValueError("preparation pack schema is unsupported")
        if self.pack_id != _content_hash(self.document(include_identity=False)):
            raise ValueError("preparation pack differs from exact content")


def _candidate_authority(fact: FactualSentence) -> CandidateStoryAuthority:
    if fact.fact_kind != "candidate":
        raise ValueError("interview story requires a candidate fact")
    authority = fact.authority
    return CandidateStoryAuthority(
        sentence_id=fact.sentence_id,
        approved_text_sha256=hashlib.sha256(
            fact.approved_source_text.encode()
        ).hexdigest(),
        requirement_id=authority.requirement_id,
        candidate_claim_id=authority.candidate_claim_id,
        candidate_claim_version=authority.candidate_claim_version,
        candidate_evidence_id=authority.candidate_evidence_id,
        candidate_evidence_version=authority.candidate_evidence_version,
    )


def _employer_authority(
    fact: FactualSentence,
    *,
    evidence: EmployerDossierEvidence,
    as_of: date,
) -> EmployerGuidanceAuthority:
    if fact.fact_kind != "employer" or fact.employer_fact_json is None:
        raise ValueError("interview guidance requires an employer fact")
    try:
        document = json.loads(fact.employer_fact_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("employer guidance fact is malformed") from exc
    if (
        not isinstance(document, dict)
        or document.get("classification") != "fact"
        or document.get("id") != fact.authority.employer_research_claim_id
        or document.get("text") != fact.approved_source_text
        or _contains_protected_key(document)
        or _contains_sensitive_text(document)
        or document.get("subject_type") == "private_person"
        or SENSITIVE_EMPLOYER_TEXT.search(fact.approved_source_text)
    ):
        raise ValueError("employer guidance lacks safe exact fact authority")
    try:
        kind = IntelligenceKind(document.get("kind"))
        observed = datetime.fromisoformat(str(document.get("observed_at")))
    except (TypeError, ValueError) as exc:
        raise ValueError("employer guidance lacks typed freshness evidence") from exc
    _aware(observed, "employer guidance observation time")
    source_ids = document.get("source_ids")
    if (
        not isinstance(source_ids, list)
        or not source_ids
        or not all(isinstance(value, str) and value.strip() for value in source_ids)
        or any(value.casefold().startswith("private:") for value in source_ids)
    ):
        raise ValueError("employer guidance requires cited source IDs")
    evidence.verify()
    dossier = evidence.dossier()
    claims = dossier.get("claims")
    sources = dossier.get("sources")
    if not isinstance(claims, list) or not isinstance(sources, list):
        raise ValueError("employer dossier evidence is incomplete")
    matches = [
        row
        for row in claims
        if (
            isinstance(row, Mapping)
            and row.get("id") == fact.authority.employer_research_claim_id
        )
    ]
    if len(matches) != 1:
        raise ValueError(
            "employer guidance claim does not resolve uniquely"
        )
    claim = matches[0]
    excerpt = claim.get("citation_excerpt")
    if (
        claim.get("classification") != "fact"
        or claim.get("subject_type") != "organisation"
        or claim.get("text") != fact.approved_source_text
        or claim.get("kind") != kind.value
        or claim.get("source_ids") != source_ids
        or claim.get("observed_at") != observed.isoformat()
        or not isinstance(excerpt, str)
        or fact.approved_source_text
        not in re.sub(r"<[^>]+>", "", excerpt).strip()
        or SENSITIVE_EMPLOYER_TEXT.search(excerpt)
    ):
        raise ValueError(
            "employer guidance differs from validated public dossier"
        )
    source_by_id = {
        str(row.get("id")): row
        for row in sources
        if isinstance(row, Mapping)
    }
    if not set(source_ids).issubset(source_by_id):
        raise ValueError(
            "employer guidance citations do not resolve"
        )
    selected_sources = tuple(source_by_id[value] for value in source_ids)
    source_urls = tuple(
        _public_source_url(str(row.get("url", "")))
        for row in selected_sources
    )
    source_content_sha256s = tuple(
        _digest(
            str(row.get("content_sha256", "")),
            "employer source content hash",
        )
        for row in selected_sources
    )
    deadline = observed.date() + timedelta(days=FRESHNESS_DAYS[kind])
    if observed.date() > as_of:
        raise ValueError("future employer evidence cannot guide preparation")
    if as_of > deadline:
        raise ValueError("employer guidance is stale; source refresh is required")
    return EmployerGuidanceAuthority(
        sentence_id=fact.sentence_id,
        approved_text_sha256=hashlib.sha256(
            fact.approved_source_text.encode()
        ).hexdigest(),
        employer_claim_id=fact.authority.employer_research_claim_id,
        employer_fact_sha256=fact.authority.employer_fact_sha256,
        intelligence_kind=kind.value,
        source_ids=tuple(source_ids),
        source_urls=source_urls,
        source_content_sha256s=source_content_sha256s,
        citation_excerpt=excerpt,
        citation_excerpt_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
        dossier_evidence_id=evidence.evidence_id,
        dossier_sha256=evidence.dossier_sha256,
        observed_at=observed.isoformat(),
        freshness_deadline=deadline.isoformat(),
    )


def _item(kind: str, prompt: str, authority_ids: tuple[str, ...]) -> PreparationItem:
    body = {
        "kind": kind,
        "prompt": prompt,
        "authority_ids": authority_ids,
    }
    return PreparationItem(_content_hash(body), kind, prompt, authority_ids)


def compile_interview_preparation_pack(
    contract: InterviewCommunicationContract,
    *,
    application_id: str,
    source: ApplicationSource,
    timeline: StatusTimeline,
    release_manifest: ReleaseManifest,
    publication_receipt: PublishedArtifactReceipt,
    submission_proof: SubmissionProof,
    fixture_receipt: FixtureReceipt,
    employer_evidence: EmployerDossierEvidence,
    as_of: date,
    candidate_sentence_ids: Iterable[str],
    employer_sentence_ids: Iterable[str],
) -> InterviewPreparationPack:
    if contract != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT:
        raise ValueError("preparation requires the canonical contract")
    if not isinstance(source, ApplicationSource):
        raise TypeError("preparation requires an ApplicationSource")
    if not isinstance(timeline, StatusTimeline):
        raise TypeError("preparation requires a StatusTimeline")
    if not isinstance(release_manifest, ReleaseManifest):
        raise TypeError("preparation requires a ReleaseManifest")
    if not isinstance(publication_receipt, PublishedArtifactReceipt):
        raise TypeError(
            "preparation requires a PublishedArtifactReceipt"
        )
    if not isinstance(submission_proof, SubmissionProof):
        raise TypeError("preparation requires a SubmissionProof")
    if not isinstance(fixture_receipt, FixtureReceipt):
        raise TypeError("preparation requires a FixtureReceipt")
    if not isinstance(employer_evidence, EmployerDossierEvidence):
        raise TypeError(
            "preparation requires EmployerDossierEvidence"
        )
    verify_application_source(source)
    timeline.verify()
    _required(application_id, "preparation application ID")
    if (
        timeline.application_id != application_id
        or timeline.job_key != source.job_key
    ):
        raise ValueError("preparation inputs identify a different application")
    if timeline.final_state not in INTERVIEW_STATES:
        raise ValueError("interview preparation requires an interview-stage timeline")
    fact_by_id = {row.sentence_id: row for row in source.facts}
    candidate_ids = tuple(candidate_sentence_ids)
    employer_ids = tuple(employer_sentence_ids)
    if (
        not candidate_ids
        or not employer_ids
        or len(candidate_ids) != len(set(candidate_ids))
        or len(employer_ids) != len(set(employer_ids))
    ):
        raise ValueError("preparation selections must be non-empty and unique")
    try:
        candidate = tuple(
            _candidate_authority(fact_by_id[value]) for value in candidate_ids
        )
        employer = tuple(
            _employer_authority(
                fact_by_id[value],
                evidence=employer_evidence,
                as_of=as_of,
            )
            for value in employer_ids
        )
    except KeyError as exc:
        raise ValueError("preparation selection cites an unknown fact") from exc
    candidate_authority_ids = tuple(row.sentence_id for row in candidate)
    employer_authority_ids = tuple(row.sentence_id for row in employer)
    items = (
        _item(
            "candidate_story",
            "Explain this approved evidence in its original terms.",
            candidate_authority_ids,
        ),
        _item(
            "likely_objection",
            "Prepare for questions about the supported requirement.",
            candidate_authority_ids,
        ),
        _item(
            "technical_drill",
            "Describe the decisions behind this approved evidence.",
            candidate_authority_ids,
        ),
        _item(
            "candidate_question",
            "Ask how this documented company fact affects the role.",
            employer_authority_ids,
        ),
    )
    body = {
        "schema_version": "jaa13.interview-preparation-pack.v2",
        "contract_sha256": contract.contract_sha256,
        "application_id": application_id,
        "job_key": source.job_key,
        "released_application_sha256": (
            release_manifest.release_manifest_sha256
        ),
        "application_source_id": source.source_id,
        "application_source_content_sha256": source.content_sha256,
        "timeline_id": timeline.timeline_id,
        "source": source.document(),
        "timeline": timeline.document(),
        "release_manifest": release_manifest.document(),
        "publication_receipt": publication_receipt.document(),
        "submission_proof": _submission_proof_document(
            submission_proof
        ),
        "fixture_receipt": fixture_receipt.document(),
        "employer_evidence": employer_evidence.document(),
        "as_of": as_of.isoformat(),
        "candidate_authorities": tuple(row.document() for row in candidate),
        "employer_authorities": tuple(row.document() for row in employer),
        "items": tuple(row.document() for row in items),
        "source_refresh_authority": "withheld",
        "private_person_inference": False,
        "dependency_satisfied": False,
        "production_certification": "withheld",
        "certifies_slice": False,
        "lineage_claim": "structural_lineage_only",
    }
    return InterviewPreparationPack(
        contract_sha256=contract.contract_sha256,
        application_id=application_id,
        source=source,
        timeline=timeline,
        release_manifest=release_manifest,
        publication_receipt=publication_receipt,
        submission_proof=submission_proof,
        fixture_receipt=fixture_receipt,
        employer_evidence=employer_evidence,
        as_of=as_of.isoformat(),
        candidate_authorities=candidate,
        employer_authorities=employer,
        items=items,
        pack_id=_content_hash(body),
    )


@dataclass(frozen=True)
class LocalDebriefEvidence:
    contract_sha256: str
    application_id: str
    job_key: str
    timeline_id: str
    source_record_id: str
    source_sha256: str
    recorded_at: str
    evidence_id: str
    retention: str = "content_addressed_reference_only"
    assertion_status: str = "unverified_operator_statement"
    candidate_fact_authority: bool = False
    employer_fact_authority: bool = False
    dependency_satisfied: bool = False
    schema_version: str = "jaa13.local-debrief-evidence.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "timeline_id": self.timeline_id,
            "source_record_id": self.source_record_id,
            "source_sha256": self.source_sha256,
            "recorded_at": self.recorded_at,
            "retention": "content_addressed_reference_only",
            "assertion_status": "unverified_operator_statement",
            "candidate_fact_authority": False,
            "employer_fact_authority": False,
            "dependency_satisfied": False,
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "debrief contract hash"),
            (self.timeline_id, "debrief timeline ID"),
            (self.source_sha256, "debrief source hash"),
            (self.evidence_id, "debrief evidence ID"),
        ):
            _digest(value, label)
        _required(self.application_id, "debrief application ID")
        _required(self.job_key, "debrief job key")
        _required(self.source_record_id, "debrief source record ID")
        _aware(datetime.fromisoformat(self.recorded_at), "debrief recorded time")
        if (
            self.contract_sha256
            != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT.contract_sha256
        ):
            raise ValueError("debrief evidence binds a different contract")
        if (
            self.retention != "content_addressed_reference_only"
            or self.assertion_status != "unverified_operator_statement"
            or self.candidate_fact_authority is not False
            or self.employer_fact_authority is not False
            or self.dependency_satisfied is not False
        ):
            raise ValueError("local debrief cannot become fact authority")
        if self.schema_version != "jaa13.local-debrief-evidence.v1":
            raise ValueError("debrief evidence schema is unsupported")
        if self.evidence_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("debrief evidence differs from exact content")


def compile_local_debrief_evidence(
    contract: InterviewCommunicationContract,
    timeline: StatusTimeline,
    *,
    source_record_id: str,
    raw_debrief_bytes: bytes,
    recorded_at: datetime,
) -> LocalDebriefEvidence:
    if contract != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT:
        raise ValueError("debrief requires the canonical contract")
    if not isinstance(timeline, StatusTimeline):
        raise TypeError("debrief requires a StatusTimeline")
    timeline.verify()
    if timeline.final_state not in INTERVIEW_STATES:
        raise ValueError("debrief requires an interview-stage timeline")
    _required(source_record_id, "debrief source record ID")
    if not isinstance(raw_debrief_bytes, bytes) or not raw_debrief_bytes:
        raise ValueError("local debrief bytes are required")
    _aware(recorded_at, "debrief recorded time")
    body = {
        "schema_version": "jaa13.local-debrief-evidence.v1",
        "contract_sha256": contract.contract_sha256,
        "application_id": timeline.application_id,
        "job_key": timeline.job_key,
        "timeline_id": timeline.timeline_id,
        "source_record_id": source_record_id,
        "source_sha256": hashlib.sha256(raw_debrief_bytes).hexdigest(),
        "recorded_at": recorded_at.isoformat(),
        "retention": "content_addressed_reference_only",
        "assertion_status": "unverified_operator_statement",
        "candidate_fact_authority": False,
        "employer_fact_authority": False,
        "dependency_satisfied": False,
    }
    return LocalDebriefEvidence(
        contract_sha256=contract.contract_sha256,
        application_id=timeline.application_id,
        job_key=timeline.job_key,
        timeline_id=timeline.timeline_id,
        source_record_id=source_record_id,
        source_sha256=str(body["source_sha256"]),
        recorded_at=recorded_at.isoformat(),
        evidence_id=_content_hash(body),
    )


@dataclass(frozen=True)
class FollowUpDraftPlan:
    contract_sha256: str
    preparation: InterviewPreparationPack
    debrief: LocalDebriefEvidence
    factual_authority_ids: tuple[str, ...]
    connective_template_ids: tuple[str, ...]
    draft_plan_id: str
    debrief_fact_authority: bool = False
    operator_confirmation_required: bool = True
    truth_release_authority: str = "withheld"
    connector_authority: str = "withheld"
    send_authority: str = "withheld"
    sent_count: int = 0
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa13.follow-up-draft-plan.v2"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "factual_authority_ids",
            tuple(self.factual_authority_ids),
        )
        object.__setattr__(
            self,
            "connective_template_ids",
            tuple(self.connective_template_ids),
        )
        self.verify()

    @property
    def preparation_pack_id(self) -> str:
        return self.preparation.pack_id

    @property
    def debrief_evidence_id(self) -> str:
        return self.debrief.evidence_id

    @property
    def application_id(self) -> str:
        return self.preparation.application_id

    @property
    def job_key(self) -> str:
        return self.preparation.job_key

    @property
    def connective_text(self) -> tuple[str, ...]:
        return _connective_text(self.connective_template_ids)

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "preparation_pack_id": self.preparation_pack_id,
            "debrief_evidence_id": self.debrief_evidence_id,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "preparation": self.preparation.document(),
            "debrief": self.debrief.document(),
            "factual_authority_ids": self.factual_authority_ids,
            "connective_template_ids": self.connective_template_ids,
            "connective_text": self.connective_text,
            "debrief_fact_authority": False,
            "operator_confirmation_required": True,
            "truth_release_authority": "withheld",
            "connector_authority": "withheld",
            "send_authority": "withheld",
            "sent_count": 0,
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["draft_plan_id"] = self.draft_plan_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "draft contract hash"),
            (self.draft_plan_id, "draft plan ID"),
        ):
            _digest(value, label)
        if (
            self.contract_sha256
            != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT.contract_sha256
        ):
            raise ValueError("draft plan binds a different contract")
        if not isinstance(self.preparation, InterviewPreparationPack):
            raise TypeError(
                "draft plan requires typed preparation lineage"
            )
        if not isinstance(self.debrief, LocalDebriefEvidence):
            raise TypeError("draft plan requires typed debrief lineage")
        self.preparation.verify()
        self.debrief.verify()
        if (
            self.preparation.contract_sha256 != self.contract_sha256
            or self.debrief.contract_sha256 != self.contract_sha256
            or self.preparation.application_id
            != self.debrief.application_id
            or self.preparation.job_key != self.debrief.job_key
            or self.preparation.timeline_id != self.debrief.timeline_id
        ):
            raise ValueError(
                "draft plan embedded lineage identifies different authority"
            )
        allowed = {
            row.sentence_id
            for row in self.preparation.candidate_authorities
        } | {
            row.sentence_id
            for row in self.preparation.employer_authorities
        }
        if (
            not self.factual_authority_ids
            or len(self.factual_authority_ids)
            != len(set(self.factual_authority_ids))
            or not set(self.factual_authority_ids).issubset(allowed)
        ):
            raise ValueError(
                "draft plan requires unique embedded fact authority"
            )
        _connective_text(self.connective_template_ids)
        if (
            self.debrief_fact_authority is not False
            or self.operator_confirmation_required is not True
            or self.truth_release_authority != "withheld"
            or self.connector_authority != "withheld"
            or self.send_authority != "withheld"
            or self.sent_count != 0
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError("draft plan cannot claim truth release or send")
        if self.schema_version != "jaa13.follow-up-draft-plan.v2":
            raise ValueError("draft plan schema is unsupported")
        if self.draft_plan_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("draft plan differs from exact content")


def compile_follow_up_draft_plan(
    contract: InterviewCommunicationContract,
    preparation: InterviewPreparationPack,
    debrief: LocalDebriefEvidence,
    *,
    factual_authority_ids: Iterable[str],
    connective_template_ids: Iterable[str],
) -> FollowUpDraftPlan:
    if contract != FROZEN_INTERVIEW_COMMUNICATION_CONTRACT:
        raise ValueError("draft plan requires the canonical contract")
    if not isinstance(preparation, InterviewPreparationPack):
        raise TypeError("draft plan requires an InterviewPreparationPack")
    if not isinstance(debrief, LocalDebriefEvidence):
        raise TypeError("draft plan requires LocalDebriefEvidence")
    preparation.verify()
    debrief.verify()
    if (
        preparation.contract_sha256 != contract.contract_sha256
        or debrief.contract_sha256 != contract.contract_sha256
        or preparation.application_id != debrief.application_id
        or preparation.job_key != debrief.job_key
        or preparation.timeline_id != debrief.timeline_id
    ):
        raise ValueError("draft plan inputs identify different authority")
    selected = tuple(factual_authority_ids)
    template_ids = tuple(connective_template_ids)
    allowed = {
        row.sentence_id for row in preparation.candidate_authorities
    } | {
        row.sentence_id for row in preparation.employer_authorities
    }
    if (
        not selected
        or len(selected) != len(set(selected))
        or not set(selected).issubset(allowed)
    ):
        raise ValueError("draft plan cites unknown or duplicate fact authority")
    connectives = _connective_text(template_ids)
    body = {
        "schema_version": "jaa13.follow-up-draft-plan.v2",
        "contract_sha256": contract.contract_sha256,
        "preparation_pack_id": preparation.pack_id,
        "debrief_evidence_id": debrief.evidence_id,
        "application_id": preparation.application_id,
        "job_key": preparation.job_key,
        "preparation": preparation.document(),
        "debrief": debrief.document(),
        "factual_authority_ids": selected,
        "connective_template_ids": template_ids,
        "connective_text": connectives,
        "debrief_fact_authority": False,
        "operator_confirmation_required": True,
        "truth_release_authority": "withheld",
        "connector_authority": "withheld",
        "send_authority": "withheld",
        "sent_count": 0,
        "dependency_satisfied": False,
        "production_certification": "withheld",
        "certifies_slice": False,
    }
    return FollowUpDraftPlan(
        contract_sha256=contract.contract_sha256,
        preparation=preparation,
        debrief=debrief,
        factual_authority_ids=selected,
        connective_template_ids=template_ids,
        draft_plan_id=_content_hash(body),
    )
