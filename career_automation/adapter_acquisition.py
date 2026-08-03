"""Non-activating acquisition boundary for JAA-15 adapter candidates.

The boundary accepts only bounded, content-addressed observations supplied by
an outer acquisition process.  It never imports an adapter implementation,
opens a URL, crawls, activates a connector, submits an application, or
certifies JAA-15.  Its output is a deterministic preparation decision whose
external-action authority is always withheld.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from career_automation.outcome_feedback import (
    FROZEN_OUTCOME_FEEDBACK_CONTRACT,
)
from career_automation.source_expansion import (
    FROZEN_SOURCE_EXPANSION_CONTRACT,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
HOST = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)

CAPTURE_MAX_BYTES = 2_000_000
CAPTURE_MAX_REDIRECTS = 8
REGISTRY_MAX_CANDIDATES = 256
REGISTRY_MAX_BLOCKED_OPPORTUNITIES = 10_000
EVIDENCE_MAX_AGE = timedelta(days=30)
EVIDENCE_KINDS = (
    "fixture_runtime",
    "independent_test",
    "real_runtime",
)
REQUIRED_EVIDENCE_KINDS = frozenset(EVIDENCE_KINDS)
BLOCKING_INTERACTIONS = frozenset(
    {"captcha", "login", "mfa", "payment"}
)
SOURCE_KINDS = ("official_employer", "official_ats")
CONTEXT_STATUSES = ("supported", "unsupported")
AUTHENTICATION_MODE = "independent_manifest_receipt"
UPSTREAM_AUTHENTICATION_MODE = "independent_certification_receipt"


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


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _aware(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{label} must be timezone-aware")
    return value


def _aware_iso(value: str, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an aware ISO timestamp")
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an aware ISO timestamp") from exc
    _aware(result, label)
    if result.isoformat() != value:
        raise ValueError(f"{label} must use canonical ISO form")
    return result


def _normalise_https_url(value: str, *, expected_host: str | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("official URL must be a trimmed non-empty string")
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("official URL must be credential-free fragment-free HTTPS")
    host = parsed.hostname.lower().rstrip(".")
    if not HOST.fullmatch(host):
        raise ValueError("official URL host is invalid")
    if expected_host is not None and host != expected_host:
        raise ValueError("capture URL is outside the exact official host")
    if parsed.port not in (None, 443):
        raise ValueError("official URL may use only the default HTTPS port")
    path = parsed.path or "/"
    # Sorting keeps caller-supplied captures deterministic while preserving
    # duplicate query parameters. Blank values are significant.
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit(("https", host, path, query, ""))


@dataclass(frozen=True)
class AdapterAcquisitionCandidate:
    expansion_contract_sha256: str
    adapter_id: str
    adapter_version: str
    source_kind: str
    official_host: str
    official_base_url: str
    route_sha256: str
    schema_sha256: str
    workflow_sha256: str
    rollback_sha256: str
    selector_policy_sha256: str
    eligibility_policy_sha256: str
    payroll_policy_sha256: str
    country_context: str
    employer_context: str
    eligibility_context_status: str
    payroll_context_status: str
    selector_origin_adapter_id: str
    selector_origin_adapter_version: str
    selector_inheritance_evidence_sha256: str | None
    candidate_id: str
    activation_authority: str = "withheld"
    crawl_authority: str = "withheld"
    submission_authority: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa15.adapter-acquisition-candidate.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "expansion_contract_sha256": self.expansion_contract_sha256,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "source_kind": self.source_kind,
            "official_host": self.official_host,
            "official_base_url": self.official_base_url,
            "route_sha256": self.route_sha256,
            "schema_sha256": self.schema_sha256,
            "workflow_sha256": self.workflow_sha256,
            "rollback_sha256": self.rollback_sha256,
            "selector_policy_sha256": self.selector_policy_sha256,
            "eligibility_policy_sha256": self.eligibility_policy_sha256,
            "payroll_policy_sha256": self.payroll_policy_sha256,
            "country_context": self.country_context,
            "employer_context": self.employer_context,
            "eligibility_context_status": self.eligibility_context_status,
            "payroll_context_status": self.payroll_context_status,
            "selector_origin_adapter_id": self.selector_origin_adapter_id,
            "selector_origin_adapter_version": (
                self.selector_origin_adapter_version
            ),
            "selector_inheritance_evidence_sha256": (
                self.selector_inheritance_evidence_sha256
            ),
            "activation_authority": "withheld",
            "crawl_authority": "withheld",
            "submission_authority": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["candidate_id"] = self.candidate_id
        return result

    def verify(self) -> None:
        _digest(self.expansion_contract_sha256, "expansion contract hash")
        if (
            self.expansion_contract_sha256
            != FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
        ):
            raise ValueError("acquisition candidate uses an unaccepted contract")
        _identifier(self.adapter_id, "adapter ID")
        _identifier(self.adapter_version, "adapter version")
        _identifier(self.selector_origin_adapter_id, "selector origin adapter ID")
        _identifier(
            self.selector_origin_adapter_version,
            "selector origin adapter version",
        )
        if self.source_kind not in SOURCE_KINDS:
            raise ValueError("source kind is unsupported")
        host = self.official_host.lower().rstrip(".")
        if host != self.official_host or not HOST.fullmatch(host):
            raise ValueError("official host must be canonical")
        if _normalise_https_url(
            self.official_base_url, expected_host=self.official_host
        ) != self.official_base_url:
            raise ValueError("official base URL must be canonical")
        for value, label in (
            (self.route_sha256, "route hash"),
            (self.schema_sha256, "schema hash"),
            (self.workflow_sha256, "workflow hash"),
            (self.rollback_sha256, "rollback hash"),
            (self.selector_policy_sha256, "selector policy hash"),
            (self.eligibility_policy_sha256, "eligibility policy hash"),
            (self.payroll_policy_sha256, "payroll policy hash"),
            (self.candidate_id, "candidate ID"),
        ):
            _digest(value, label)
        if not re.fullmatch(r"[A-Z]{2}", self.country_context):
            raise ValueError("country context must be an ISO alpha-2 code")
        _identifier(self.employer_context, "employer context")
        if (
            self.eligibility_context_status not in CONTEXT_STATUSES
            or self.payroll_context_status not in CONTEXT_STATUSES
        ):
            raise ValueError("eligibility/payroll context status is unsupported")
        inherited = (
            self.selector_origin_adapter_id != self.adapter_id
            or self.selector_origin_adapter_version != self.adapter_version
        )
        if inherited and self.selector_inheritance_evidence_sha256 is None:
            raise ValueError(
                "selector inheritance requires explicit versioned evidence"
            )
        if self.selector_inheritance_evidence_sha256 is not None:
            _digest(
                self.selector_inheritance_evidence_sha256,
                "selector inheritance evidence hash",
            )
        if (
            self.activation_authority != "withheld"
            or self.crawl_authority != "withheld"
            or self.submission_authority != "withheld"
            or self.certifies_slice is not False
            or self.schema_version != "jaa15.adapter-acquisition-candidate.v1"
        ):
            raise ValueError("acquisition candidate cannot activate or certify")
        if self.candidate_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("acquisition candidate identity is invalid")


def compile_acquisition_candidate(
    *,
    adapter_id: str,
    adapter_version: str,
    source_kind: str,
    official_base_url: str,
    route_sha256: str,
    schema_sha256: str,
    workflow_sha256: str,
    rollback_sha256: str,
    selector_policy_sha256: str,
    eligibility_policy_sha256: str,
    payroll_policy_sha256: str,
    country_context: str,
    employer_context: str,
    eligibility_context_status: str,
    payroll_context_status: str,
    selector_origin_adapter_id: str | None = None,
    selector_origin_adapter_version: str | None = None,
    selector_inheritance_evidence_sha256: str | None = None,
) -> AdapterAcquisitionCandidate:
    canonical_url = _normalise_https_url(official_base_url)
    host = urlsplit(canonical_url).hostname
    assert host is not None
    origin_id = selector_origin_adapter_id or adapter_id
    origin_version = selector_origin_adapter_version or adapter_version
    body: dict[str, object] = {
        "schema_version": "jaa15.adapter-acquisition-candidate.v1",
        "expansion_contract_sha256": (
            FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
        ),
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "source_kind": source_kind,
        "official_host": host,
        "official_base_url": canonical_url,
        "route_sha256": route_sha256,
        "schema_sha256": schema_sha256,
        "workflow_sha256": workflow_sha256,
        "rollback_sha256": rollback_sha256,
        "selector_policy_sha256": selector_policy_sha256,
        "eligibility_policy_sha256": eligibility_policy_sha256,
        "payroll_policy_sha256": payroll_policy_sha256,
        "country_context": country_context,
        "employer_context": employer_context,
        "eligibility_context_status": eligibility_context_status,
        "payroll_context_status": payroll_context_status,
        "selector_origin_adapter_id": origin_id,
        "selector_origin_adapter_version": origin_version,
        "selector_inheritance_evidence_sha256": (
            selector_inheritance_evidence_sha256
        ),
        "activation_authority": "withheld",
        "crawl_authority": "withheld",
        "submission_authority": "withheld",
        "certifies_slice": False,
    }
    return AdapterAcquisitionCandidate(
        **body,
        candidate_id=_content_hash(body),
    )


@dataclass(frozen=True)
class NormalizedCaptureInput:
    candidate_id: str
    route_url: str
    final_url: str
    captured_at: str
    content_sha256: str
    byte_length: int
    media_type: str
    status_code: int
    redirect_chain: tuple[str, ...]
    interaction_requirements: tuple[str, ...]
    capture_id: str
    network_authority: str = "withheld"
    certifies_runtime: bool = False
    schema_version: str = "jaa15.normalized-capture-input.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "route_url": self.route_url,
            "final_url": self.final_url,
            "captured_at": self.captured_at,
            "content_sha256": self.content_sha256,
            "byte_length": self.byte_length,
            "media_type": self.media_type,
            "status_code": self.status_code,
            "redirect_chain": self.redirect_chain,
            "interaction_requirements": self.interaction_requirements,
            "network_authority": "withheld",
            "certifies_runtime": False,
        }
        if include_identity:
            result["capture_id"] = self.capture_id
        return result

    def verify(self) -> None:
        _digest(self.candidate_id, "capture candidate ID")
        _digest(self.content_sha256, "capture content hash")
        _digest(self.capture_id, "capture ID")
        _aware_iso(self.captured_at, "capture time")
        for url in (self.route_url, self.final_url, *self.redirect_chain):
            if _normalise_https_url(
                url, expected_host=urlsplit(self.route_url).hostname
            ) != url:
                raise ValueError("capture URLs must be canonical")
        if len(self.redirect_chain) > CAPTURE_MAX_REDIRECTS:
            raise ValueError("capture redirect chain exceeds bound")
        if type(self.byte_length) is not int or not (
            0 < self.byte_length <= CAPTURE_MAX_BYTES
        ):
            raise ValueError("capture byte length exceeds bound")
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise ValueError("capture status code is invalid")
        if self.media_type not in {
            "application/json",
            "text/html",
            "application/ld+json",
        }:
            raise ValueError("capture media type is unsupported")
        if tuple(sorted(set(self.interaction_requirements))) != (
            self.interaction_requirements
        ):
            raise ValueError("interaction requirements must be unique and sorted")
        unknown = set(self.interaction_requirements) - BLOCKING_INTERACTIONS
        if unknown:
            raise ValueError("capture interaction requirement is unsupported")
        if (
            self.network_authority != "withheld"
            or self.certifies_runtime is not False
            or self.schema_version != "jaa15.normalized-capture-input.v1"
        ):
            raise ValueError("capture input cannot acquire or certify runtime")
        if self.capture_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("capture input identity is invalid")


def normalize_capture_input(
    candidate: AdapterAcquisitionCandidate,
    *,
    route_url: str,
    final_url: str,
    captured_at: datetime,
    content_sha256: str,
    byte_length: int,
    media_type: str,
    status_code: int,
    redirect_chain: Iterable[str] = (),
    interaction_requirements: Iterable[str] = (),
) -> NormalizedCaptureInput:
    candidate.verify()
    route = _normalise_https_url(route_url, expected_host=candidate.official_host)
    final = _normalise_https_url(final_url, expected_host=candidate.official_host)
    redirects = tuple(
        _normalise_https_url(url, expected_host=candidate.official_host)
        for url in redirect_chain
    )
    interactions = tuple(sorted(set(interaction_requirements)))
    captured = _aware(captured_at, "capture time").isoformat()
    body = {
        "schema_version": "jaa15.normalized-capture-input.v1",
        "candidate_id": candidate.candidate_id,
        "route_url": route,
        "final_url": final,
        "captured_at": captured,
        "content_sha256": content_sha256,
        "byte_length": byte_length,
        "media_type": media_type.lower().split(";", 1)[0].strip(),
        "status_code": status_code,
        "redirect_chain": redirects,
        "interaction_requirements": interactions,
        "network_authority": "withheld",
        "certifies_runtime": False,
    }
    return NormalizedCaptureInput(**body, capture_id=_content_hash(body))


@dataclass(frozen=True)
class AdapterEvidenceReference:
    candidate_id: str
    adapter_id: str
    adapter_version: str
    evidence_kind: str
    evidence_sha256: str
    capture_id: str
    observed_at: str
    verifier_id: str
    authentication_mode: str
    manifest_receipt_sha256: str
    evidence_id: str
    activation_authority: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa15.adapter-evidence-reference.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "evidence_kind": self.evidence_kind,
            "evidence_sha256": self.evidence_sha256,
            "capture_id": self.capture_id,
            "observed_at": self.observed_at,
            "verifier_id": self.verifier_id,
            "authentication_mode": self.authentication_mode,
            "manifest_receipt_sha256": self.manifest_receipt_sha256,
            "activation_authority": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.candidate_id, "evidence candidate ID"),
            (self.evidence_sha256, "evidence hash"),
            (self.capture_id, "evidence capture ID"),
            (self.manifest_receipt_sha256, "evidence manifest receipt hash"),
            (self.evidence_id, "evidence ID"),
        ):
            _digest(value, label)
        _identifier(self.adapter_id, "evidence adapter ID")
        _identifier(self.adapter_version, "evidence adapter version")
        _identifier(self.verifier_id, "evidence verifier ID")
        _aware_iso(self.observed_at, "evidence observation time")
        if self.evidence_kind not in EVIDENCE_KINDS:
            raise ValueError("evidence kind is unsupported")
        if self.authentication_mode != AUTHENTICATION_MODE:
            raise ValueError("evidence reference is unauthenticated")
        if (
            self.activation_authority != "withheld"
            or self.certifies_slice is not False
            or self.schema_version != "jaa15.adapter-evidence-reference.v1"
        ):
            raise ValueError("evidence reference cannot activate or certify")
        if self.evidence_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("evidence reference identity is invalid")


def record_adapter_evidence(
    candidate: AdapterAcquisitionCandidate,
    capture: NormalizedCaptureInput,
    *,
    evidence_kind: str,
    evidence_sha256: str,
    observed_at: datetime,
    verifier_id: str,
    manifest_receipt_sha256: str,
    authentication_mode: str = AUTHENTICATION_MODE,
) -> AdapterEvidenceReference:
    candidate.verify()
    capture.verify()
    if capture.candidate_id != candidate.candidate_id:
        raise ValueError("cross-adapter capture evidence is forbidden")
    observed = _aware(observed_at, "evidence observation time")
    capture_time = datetime.fromisoformat(capture.captured_at)
    if observed < capture_time:
        raise ValueError("evidence cannot predate its capture")
    body = {
        "schema_version": "jaa15.adapter-evidence-reference.v1",
        "candidate_id": candidate.candidate_id,
        "adapter_id": candidate.adapter_id,
        "adapter_version": candidate.adapter_version,
        "evidence_kind": evidence_kind,
        "evidence_sha256": evidence_sha256,
        "capture_id": capture.capture_id,
        "observed_at": observed.isoformat(),
        "verifier_id": verifier_id,
        "authentication_mode": authentication_mode,
        "manifest_receipt_sha256": manifest_receipt_sha256,
        "activation_authority": "withheld",
        "certifies_slice": False,
    }
    return AdapterEvidenceReference(**body, evidence_id=_content_hash(body))


@dataclass(frozen=True)
class BlockedOpportunity:
    opportunity_id: str
    candidate_id: str
    official_route_sha256: str
    reason_codes: tuple[str, ...]
    observed_at: str
    visibility: str = "retained_blocked"
    schema_version: str = "jaa15.blocked-opportunity.v1"

    def __post_init__(self) -> None:
        _identifier(self.opportunity_id, "opportunity ID")
        _digest(self.candidate_id, "blocked opportunity candidate ID")
        _digest(self.official_route_sha256, "blocked opportunity route hash")
        _aware_iso(self.observed_at, "blocked opportunity time")
        if (
            not self.reason_codes
            or tuple(sorted(set(self.reason_codes))) != self.reason_codes
        ):
            raise ValueError("blocked reasons must be non-empty, unique and sorted")
        for reason in self.reason_codes:
            _identifier(reason, "blocked reason")
        if self.visibility != "retained_blocked":
            raise ValueError("blocked opportunity visibility cannot be hidden")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "opportunity_id": self.opportunity_id,
            "candidate_id": self.candidate_id,
            "official_route_sha256": self.official_route_sha256,
            "reason_codes": self.reason_codes,
            "observed_at": self.observed_at,
            "visibility": "retained_blocked",
        }


def record_blocked_opportunity(
    candidate: AdapterAcquisitionCandidate,
    *,
    opportunity_id: str,
    official_route_sha256: str,
    reason_codes: Iterable[str],
    observed_at: datetime,
) -> BlockedOpportunity:
    candidate.verify()
    return BlockedOpportunity(
        opportunity_id=opportunity_id,
        candidate_id=candidate.candidate_id,
        official_route_sha256=official_route_sha256,
        reason_codes=tuple(sorted(set(reason_codes))),
        observed_at=_aware(observed_at, "blocked opportunity time").isoformat(),
    )


@dataclass(frozen=True)
class AdapterAcquisitionRegistry:
    candidates: tuple[AdapterAcquisitionCandidate, ...]
    blocked_opportunities: tuple[BlockedOpportunity, ...]
    registry_id: str
    activation_authority: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa15.adapter-acquisition-registry.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "candidates": tuple(row.document() for row in self.candidates),
            "blocked_opportunities": tuple(
                row.document() for row in self.blocked_opportunities
            ),
            "activation_authority": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["registry_id"] = self.registry_id
        return result

    def verify(self) -> None:
        _digest(self.registry_id, "registry ID")
        if not self.candidates or len(self.candidates) > REGISTRY_MAX_CANDIDATES:
            raise ValueError("registry candidate count is outside bounds")
        if len(self.blocked_opportunities) > REGISTRY_MAX_BLOCKED_OPPORTUNITIES:
            raise ValueError("registry blocked opportunity count exceeds bound")
        candidate_ids = tuple(row.candidate_id for row in self.candidates)
        if candidate_ids != tuple(sorted(set(candidate_ids))):
            raise ValueError("registry candidates must be unique and sorted")
        known = set(candidate_ids)
        keys = tuple(
            (row.opportunity_id, row.candidate_id)
            for row in self.blocked_opportunities
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("blocked opportunities must be unique and sorted")
        if any(row.candidate_id not in known for row in self.blocked_opportunities):
            raise ValueError("blocked opportunity references an unknown adapter")
        if (
            self.activation_authority != "withheld"
            or self.certifies_slice is not False
            or self.schema_version != "jaa15.adapter-acquisition-registry.v1"
        ):
            raise ValueError("registry cannot activate or certify")
        if self.registry_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("registry identity is invalid")


def build_acquisition_registry(
    candidates: Iterable[AdapterAcquisitionCandidate],
    blocked_opportunities: Iterable[BlockedOpportunity] = (),
) -> AdapterAcquisitionRegistry:
    candidate_rows = tuple(sorted(candidates, key=lambda row: row.candidate_id))
    blocked_rows = tuple(
        sorted(
            blocked_opportunities,
            key=lambda row: (row.opportunity_id, row.candidate_id),
        )
    )
    body = {
        "schema_version": "jaa15.adapter-acquisition-registry.v1",
        "candidates": tuple(row.document() for row in candidate_rows),
        "blocked_opportunities": tuple(row.document() for row in blocked_rows),
        "activation_authority": "withheld",
        "certifies_slice": False,
    }
    return AdapterAcquisitionRegistry(
        candidates=candidate_rows,
        blocked_opportunities=blocked_rows,
        registry_id=_content_hash(body),
    )


@dataclass(frozen=True)
class UpstreamJAA14CertificationEvidence:
    upstream_contract_sha256: str
    promotion_evaluation_sha256: str
    certification_receipt_sha256: str
    verifier_id: str
    authentication_mode: str
    issued_at: str
    expires_at: str
    certification_status: str = "certified"
    schema_version: str = "jaa14.independent-certification-evidence.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (self.upstream_contract_sha256, "upstream contract hash"),
            (self.promotion_evaluation_sha256, "promotion evaluation hash"),
            (self.certification_receipt_sha256, "certification receipt hash"),
        ):
            _digest(value, label)
        _identifier(self.verifier_id, "certification verifier ID")
        issued = _aware_iso(self.issued_at, "certification issue time")
        expires = _aware_iso(self.expires_at, "certification expiry time")
        if issued >= expires:
            raise ValueError("certification expiry must follow issue time")
        if (
            self.upstream_contract_sha256
            != FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256
            or self.authentication_mode != UPSTREAM_AUTHENTICATION_MODE
            or self.certification_status != "certified"
            or self.schema_version
            != "jaa14.independent-certification-evidence.v1"
        ):
            raise ValueError("upstream JAA-14 certification evidence is invalid")


@dataclass(frozen=True)
class AdapterActivationPreparationDecision:
    registry_id: str
    candidate_id: str
    evidence_ids: tuple[str, ...]
    capture_ids: tuple[str, ...]
    upstream_certification_receipt_sha256: str | None
    decision_status: str
    reason_codes: tuple[str, ...]
    evaluated_at: str
    decision_id: str
    activation_authority: str = "withheld"
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa15.activation-preparation-decision.v1"

    def __post_init__(self) -> None:
        _digest(self.registry_id, "decision registry ID")
        _digest(self.candidate_id, "decision candidate ID")
        _digest(self.decision_id, "decision ID")
        _aware_iso(self.evaluated_at, "decision time")
        for values, label in (
            (self.evidence_ids, "decision evidence IDs"),
            (self.capture_ids, "decision capture IDs"),
            (self.reason_codes, "decision reason codes"),
        ):
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{label} must be unique and sorted")
        for value in (*self.evidence_ids, *self.capture_ids):
            _digest(value, "decision lineage hash")
        if self.upstream_certification_receipt_sha256 is not None:
            _digest(
                self.upstream_certification_receipt_sha256,
                "upstream certification receipt hash",
            )
        if self.decision_status not in {
            "withheld_blocked",
            "withheld_upstream_jaa14_missing",
            "withheld_prepared_for_independent_activation_review",
        }:
            raise ValueError("activation preparation status is invalid")
        if (
            self.activation_authority != "withheld"
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
            or self.schema_version != "jaa15.activation-preparation-decision.v1"
        ):
            raise ValueError("preparation decision cannot activate or certify")
        if self.decision_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("activation preparation decision identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "registry_id": self.registry_id,
            "candidate_id": self.candidate_id,
            "evidence_ids": self.evidence_ids,
            "capture_ids": self.capture_ids,
            "upstream_certification_receipt_sha256": (
                self.upstream_certification_receipt_sha256
            ),
            "decision_status": self.decision_status,
            "reason_codes": self.reason_codes,
            "evaluated_at": self.evaluated_at,
            "activation_authority": "withheld",
            "production_certification": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["decision_id"] = self.decision_id
        return result


def prepare_activation_decision(
    registry: AdapterAcquisitionRegistry,
    candidate: AdapterAcquisitionCandidate,
    captures: Iterable[NormalizedCaptureInput],
    evidence: Iterable[AdapterEvidenceReference],
    *,
    evaluated_at: datetime,
    upstream_jaa14: UpstreamJAA14CertificationEvidence | None = None,
) -> AdapterActivationPreparationDecision:
    """Validate preparation evidence while retaining all activation authority."""

    registry.verify()
    candidate.verify()
    now = _aware(evaluated_at, "decision time")
    if candidate.candidate_id not in {row.candidate_id for row in registry.candidates}:
        raise ValueError("decision candidate is not registered")
    capture_rows = tuple(captures)
    evidence_rows = tuple(evidence)
    if not capture_rows:
        raise ValueError("activation preparation requires capture evidence")
    capture_by_id: dict[str, NormalizedCaptureInput] = {}
    for row in capture_rows:
        row.verify()
        if row.candidate_id != candidate.candidate_id:
            raise ValueError("cross-adapter capture evidence is forbidden")
        if row.capture_id in capture_by_id:
            raise ValueError("duplicate capture evidence is forbidden")
        if now - datetime.fromisoformat(row.captured_at) > EVIDENCE_MAX_AGE:
            raise ValueError("stale capture evidence is forbidden")
        if datetime.fromisoformat(row.captured_at) > now:
            raise ValueError("future capture evidence is forbidden")
        capture_by_id[row.capture_id] = row
    evidence_by_kind: dict[str, AdapterEvidenceReference] = {}
    for row in evidence_rows:
        row.verify()
        if (
            row.candidate_id != candidate.candidate_id
            or row.adapter_id != candidate.adapter_id
            or row.adapter_version != candidate.adapter_version
        ):
            raise ValueError("cross-adapter evidence reuse is forbidden")
        if row.capture_id not in capture_by_id:
            raise ValueError("evidence references an unbound capture")
        observed = datetime.fromisoformat(row.observed_at)
        if observed > now or now - observed > EVIDENCE_MAX_AGE:
            raise ValueError("stale or future adapter evidence is forbidden")
        if row.evidence_kind in evidence_by_kind:
            raise ValueError("duplicate adapter evidence kind is forbidden")
        evidence_by_kind[row.evidence_kind] = row

    reasons: set[str] = set()
    missing = REQUIRED_EVIDENCE_KINDS - set(evidence_by_kind)
    reasons.update(f"missing_{kind}_evidence" for kind in missing)
    if candidate.eligibility_context_status != "supported":
        reasons.add("unsupported_eligibility_context")
    if candidate.payroll_context_status != "supported":
        reasons.add("unsupported_payroll_context")
    for capture in capture_rows:
        reasons.update(
            f"blocked_interaction_{kind}"
            for kind in capture.interaction_requirements
        )
    if upstream_jaa14 is not None:
        # Construction validates exact contract, authentication, and status.
        issued = datetime.fromisoformat(upstream_jaa14.issued_at)
        expires = datetime.fromisoformat(upstream_jaa14.expires_at)
        if not issued <= now < expires:
            raise ValueError("upstream JAA-14 certification is stale or future")

    if reasons:
        status = "withheld_blocked"
    elif upstream_jaa14 is None:
        status = "withheld_upstream_jaa14_missing"
        reasons.add("upstream_jaa14_certification_missing")
    else:
        status = "withheld_prepared_for_independent_activation_review"

    body = {
        "schema_version": "jaa15.activation-preparation-decision.v1",
        "registry_id": registry.registry_id,
        "candidate_id": candidate.candidate_id,
        "evidence_ids": tuple(sorted(row.evidence_id for row in evidence_rows)),
        "capture_ids": tuple(sorted(capture_by_id)),
        "upstream_certification_receipt_sha256": (
            upstream_jaa14.certification_receipt_sha256
            if upstream_jaa14 is not None
            else None
        ),
        "decision_status": status,
        "reason_codes": tuple(sorted(reasons)),
        "evaluated_at": now.isoformat(),
        "activation_authority": "withheld",
        "production_certification": "withheld",
        "certifies_slice": False,
    }
    return AdapterActivationPreparationDecision(
        **body,
        decision_id=_content_hash(body),
    )


__all__ = [
    "AUTHENTICATION_MODE",
    "AdapterAcquisitionCandidate",
    "AdapterAcquisitionRegistry",
    "AdapterActivationPreparationDecision",
    "AdapterEvidenceReference",
    "BlockedOpportunity",
    "CAPTURE_MAX_BYTES",
    "EVIDENCE_MAX_AGE",
    "NormalizedCaptureInput",
    "UPSTREAM_AUTHENTICATION_MODE",
    "UpstreamJAA14CertificationEvidence",
    "build_acquisition_registry",
    "compile_acquisition_candidate",
    "normalize_capture_input",
    "prepare_activation_decision",
    "record_adapter_evidence",
    "record_blocked_opportunity",
]
