"""Inert fixture contract for the future JAA-11 official ATS adapter.

This module models exact adapter inputs, fixture observations, parking
decisions and a circuit breaker. It deliberately has no browser, HTTP,
credential, release-token or submission capability. A fixture result cannot
activate a real canary or certify JAA-11.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import date
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

from career_automation.ats_fixture import FixtureReceipt
from career_automation.browser_workflows import SubmissionProof
from career_automation.release_gate import OfficialRouteBinding
from career_automation.shadow_certification import FROZEN_SHADOW_CONTRACT


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
FIXTURE_ROUTE_URL = (
    "http://127.0.0.1:0/applications/jaa10-frozen-platform-engineer"
)
FIXTURE_ROUTE_VERIFIED_AT = date(2030, 1, 1)
FIXTURE_ROUTE_VALID_UNTIL = date(2030, 12, 31)
BLOCKING_SIGNALS = (
    "captcha",
    "login_required",
    "mfa",
    "prohibited_automation",
    "unknown_consent",
    "unknown_legal_attestation",
)
INVARIANT_BREACHES = (
    "changed_form_schema",
    "changed_selector_set",
    "changed_workflow",
    "fabricated_receipt",
    "mismatched_receipt",
    "missing_receipt",
    "missing_submit_dispatch",
    "second_submit_attempt",
    "changed_submission_proof",
)
FIXTURE_FORM_SCHEMA: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa11.fixture-form-schema.v1",
    "required_text_fields": (
        "full_name",
        "email",
        "phone",
        "city",
        "work_authorisation",
        "cover_note",
    ),
    "required_upload_fields": ("cv", "cover_letter"),
    "review_required": True,
    "submit_is_final": True,
})
FIXTURE_SELECTOR_SET: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa11.fixture-selectors.v1",
    "field_strategy": "data-testid-exact",
    "review_selector": "review-application",
    "submit_selector": "submit-application",
})
FIXTURE_RECEIPT_SEMANTICS: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa11.fixture-receipt-semantics.v1",
    "receipt_type": "jaa09.fixture-receipt.v1",
    "identity": "content-addressed",
    "official_runtime_receipt": False,
})
FIXTURE_CIRCUIT_BREAKER_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa11.fixture-circuit-breaker.v1",
    "trip_on": INVARIANT_BREACHES,
    "park_on": BLOCKING_SIGNALS,
    "real_canary_limit": 0,
    "manual_reset": False,
})
FIXTURE_ROUTE_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa11.fixture-route-policy.v1",
    "route_url": FIXTURE_ROUTE_URL,
    "fixture_only": True,
    "external_route_verified": False,
    "validity_basis": "synthetic_fixture_clock",
    "verified_at": FIXTURE_ROUTE_VERIFIED_AT.isoformat(),
    "valid_until": FIXTURE_ROUTE_VALID_UNTIL.isoformat(),
    "network_capability": False,
})


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
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
    if not isinstance(value, str):
        raise ValueError(f"{label} is required")
    clean = value.strip()
    if not clean:
        raise ValueError(f"{label} is required")
    if value != clean:
        raise ValueError(
            f"{label} must not contain surrounding whitespace"
        )
    return clean


def _fixture_route(value: str, application_id: str) -> bool:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or parsed.port != 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != f"/applications/{application_id}"
    ):
        return False
    if parsed.hostname.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


FORM_SCHEMA_SHA256 = _content_hash(dict(FIXTURE_FORM_SCHEMA))
SELECTOR_SET_SHA256 = _content_hash(dict(FIXTURE_SELECTOR_SET))
RECEIPT_SEMANTICS_SHA256 = _content_hash(
    dict(FIXTURE_RECEIPT_SEMANTICS)
)
CIRCUIT_BREAKER_POLICY_SHA256 = _content_hash(
    dict(FIXTURE_CIRCUIT_BREAKER_POLICY)
)
ROUTE_POLICY_SHA256 = _content_hash(dict(FIXTURE_ROUTE_POLICY))


@dataclass(frozen=True)
class FixtureAdapterContract:
    route_binding: OfficialRouteBinding
    route_url: str
    application_id: str
    job_key: str
    workflow_sha256: str
    upstream_shadow_contract_sha256: str
    form_schema_sha256: str
    selector_set_sha256: str
    receipt_semantics_sha256: str
    circuit_breaker_policy_sha256: str
    adapter_id: str = "jaa11.fixture-official-ats"
    adapter_version: str = "v1"
    environment: str = "fixture_only"
    real_canary_activation: str = (
        "withheld_explicit_operator_approval_required"
    )
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa11.fixture-adapter-contract.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.route_binding, OfficialRouteBinding):
            raise TypeError(
                "fixture adapter requires an OfficialRouteBinding"
            )
        for value, label in (
            (self.adapter_id, "adapter ID"),
            (self.adapter_version, "adapter version"),
            (self.application_id, "application ID"),
            (self.job_key, "job key"),
        ):
            _required(value, label)
        if (
            self.route_binding.adapter_id != self.adapter_id
            or self.route_binding.adapter_version != self.adapter_version
        ):
            raise ValueError(
                "fixture route binds a different adapter version"
            )
        if (
            not self.route_binding.allowed
            or self.route_binding.source_identity != self.route_url
            or self.route_binding.route_policy_sha256
            != ROUTE_POLICY_SHA256
        ):
            raise ValueError("fixture route authority differs from policy")
        if not _fixture_route(self.route_url, self.application_id):
            raise ValueError(
                "fixture adapter route must be loopback HTTP on port zero"
            )
        for value, label in (
            (self.workflow_sha256, "workflow hash"),
            (
                self.upstream_shadow_contract_sha256,
                "upstream shadow contract hash",
            ),
            (self.form_schema_sha256, "form-schema hash"),
            (self.selector_set_sha256, "selector-set hash"),
            (self.receipt_semantics_sha256, "receipt-semantics hash"),
            (
                self.circuit_breaker_policy_sha256,
                "circuit-breaker policy hash",
            ),
        ):
            _digest(value, label)
        expected = (
            FROZEN_SHADOW_CONTRACT.application_id,
            FROZEN_SHADOW_CONTRACT.job_key,
            FROZEN_SHADOW_CONTRACT.workflow_sha256,
            FROZEN_SHADOW_CONTRACT.contract_sha256,
            FORM_SCHEMA_SHA256,
            SELECTOR_SET_SHA256,
            RECEIPT_SEMANTICS_SHA256,
            CIRCUIT_BREAKER_POLICY_SHA256,
        )
        actual = (
            self.application_id,
            self.job_key,
            self.workflow_sha256,
            self.upstream_shadow_contract_sha256,
            self.form_schema_sha256,
            self.selector_set_sha256,
            self.receipt_semantics_sha256,
            self.circuit_breaker_policy_sha256,
        )
        if actual != expected:
            raise ValueError(
                "fixture adapter differs from its accepted JAA-10 contract"
            )
        if (
            self.environment != "fixture_only"
            or self.real_canary_activation
            != "withheld_explicit_operator_approval_required"
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError(
                "fixture adapter cannot activate or certify a real canary"
            )
        if self.schema_version != "jaa11.fixture-adapter-contract.v1":
            raise ValueError("fixture adapter contract schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "route_binding": self.route_binding.document(),
            "route_url": self.route_url,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "workflow_sha256": self.workflow_sha256,
            "upstream_shadow_contract_sha256": (
                self.upstream_shadow_contract_sha256
            ),
            "form_schema_sha256": self.form_schema_sha256,
            "selector_set_sha256": self.selector_set_sha256,
            "receipt_semantics_sha256": self.receipt_semantics_sha256,
            "circuit_breaker_policy_sha256": (
                self.circuit_breaker_policy_sha256
            ),
            "blocking_signals": BLOCKING_SIGNALS,
            "invariant_breaches": INVARIANT_BREACHES,
            "environment": "fixture_only",
            "real_canary_activation": (
                "withheld_explicit_operator_approval_required"
            ),
            "production_certification": "withheld",
            "certifies_slice": False,
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_FIXTURE_ADAPTER_CONTRACT = FixtureAdapterContract(
    route_binding=OfficialRouteBinding(
        route_id="jaa11-fixture-route",
        adapter_id="jaa11.fixture-official-ats",
        adapter_version="v1",
        source_identity=FIXTURE_ROUTE_URL,
        route_policy_sha256=ROUTE_POLICY_SHA256,
        verified_at=FIXTURE_ROUTE_VERIFIED_AT,
        valid_until=FIXTURE_ROUTE_VALID_UNTIL,
        allowed=True,
    ),
    route_url=FIXTURE_ROUTE_URL,
    application_id=FROZEN_SHADOW_CONTRACT.application_id,
    job_key=FROZEN_SHADOW_CONTRACT.job_key,
    workflow_sha256=FROZEN_SHADOW_CONTRACT.workflow_sha256,
    upstream_shadow_contract_sha256=(
        FROZEN_SHADOW_CONTRACT.contract_sha256
    ),
    form_schema_sha256=FORM_SCHEMA_SHA256,
    selector_set_sha256=SELECTOR_SET_SHA256,
    receipt_semantics_sha256=RECEIPT_SEMANTICS_SHA256,
    circuit_breaker_policy_sha256=CIRCUIT_BREAKER_POLICY_SHA256,
)


def _submission_proof_document(
    proof: SubmissionProof,
) -> dict[str, str]:
    return {
        "release_manifest_sha256": proof.release_manifest_sha256,
        "token_sha256": proof.token_sha256,
        "receipt_id": proof.receipt_id,
        "receipt_payload_sha256": proof.receipt_payload_sha256,
        "screenshot_sha256": proof.screenshot_sha256,
        "field_map_sha256": proof.field_map_sha256,
        "submit_event_sha256": proof.submit_event_sha256,
    }


@dataclass(frozen=True)
class AdapterFixtureObservation:
    adapter_contract_sha256: str
    workflow_sha256: str
    observed_form_schema_sha256: str
    observed_selector_set_sha256: str
    submission_proof: SubmissionProof
    receipt: FixtureReceipt | None
    submit_dispatch_count: int
    blocking_signals: tuple[str, ...] = ()
    evidence_kind: str = "fixture_only"
    schema_version: str = "jaa11.fixture-observation.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "blocking_signals",
            tuple(self.blocking_signals),
        )
        for value, label in (
            (self.adapter_contract_sha256, "adapter contract hash"),
            (self.workflow_sha256, "observed workflow hash"),
            (
                self.observed_form_schema_sha256,
                "observed form-schema hash",
            ),
            (
                self.observed_selector_set_sha256,
                "observed selector-set hash",
            ),
        ):
            _digest(value, label)
        if not isinstance(self.submission_proof, SubmissionProof):
            raise TypeError(
                "fixture observation requires a SubmissionProof"
            )
        if self.receipt is not None and not isinstance(
            self.receipt,
            FixtureReceipt,
        ):
            raise TypeError(
                "fixture observation receipt must be a FixtureReceipt"
            )
        if (
            not isinstance(self.submit_dispatch_count, int)
            or self.submit_dispatch_count < 0
        ):
            raise ValueError(
                "fixture submit dispatch count must be non-negative"
            )
        if (
            len(self.blocking_signals)
            != len(set(self.blocking_signals))
            or any(
                signal not in BLOCKING_SIGNALS
                for signal in self.blocking_signals
            )
        ):
            raise ValueError(
                "fixture observation has an unknown or duplicate blocker"
            )
        if self.evidence_kind != "fixture_only":
            raise ValueError(
                "fixture observation cannot claim a real environment"
            )
        if self.schema_version != "jaa11.fixture-observation.v1":
            raise ValueError("fixture observation schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "adapter_contract_sha256": self.adapter_contract_sha256,
            "workflow_sha256": self.workflow_sha256,
            "observed_form_schema_sha256": (
                self.observed_form_schema_sha256
            ),
            "observed_selector_set_sha256": (
                self.observed_selector_set_sha256
            ),
            "submission_proof": _submission_proof_document(
                self.submission_proof
            ),
            "receipt": (
                None if self.receipt is None else self.receipt.document()
            ),
            "submit_dispatch_count": self.submit_dispatch_count,
            "blocking_signals": self.blocking_signals,
            "evidence_kind": "fixture_only",
        }

    @property
    def observation_sha256(self) -> str:
        return _content_hash(self.document())


@dataclass(frozen=True)
class AdapterCircuitBreaker:
    adapter_contract_sha256: str
    state: str = "armed"
    assessed_attempts: int = 0
    breach_code: str | None = None
    schema_version: str = "jaa11.adapter-circuit-breaker-state.v1"

    def __post_init__(self) -> None:
        _digest(self.adapter_contract_sha256, "circuit contract hash")
        if self.state not in {"armed", "tripped"}:
            raise ValueError("adapter circuit state is invalid")
        if (
            not isinstance(self.assessed_attempts, int)
            or self.assessed_attempts < 0
        ):
            raise ValueError("adapter circuit attempt count is invalid")
        if self.state == "armed" and self.breach_code is not None:
            raise ValueError("armed adapter circuit cannot retain a breach")
        if self.state == "tripped" and self.breach_code not in (
            INVARIANT_BREACHES
        ):
            raise ValueError(
                "tripped adapter circuit requires an invariant breach"
            )
        if (
            self.schema_version
            != "jaa11.adapter-circuit-breaker-state.v1"
        ):
            raise ValueError("adapter circuit schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "adapter_contract_sha256": self.adapter_contract_sha256,
            "state": self.state,
            "assessed_attempts": self.assessed_attempts,
            "breach_code": self.breach_code,
        }

    @property
    def state_sha256(self) -> str:
        return _content_hash(self.document())


@dataclass(frozen=True)
class FixtureAdapterEvidence:
    adapter_contract_sha256: str
    observation_sha256: str
    release_manifest_sha256: str
    token_sha256: str
    receipt_id: str
    receipt_payload_sha256: str
    submit_event_sha256: str
    evidence_id: str
    real_canary_activation: str = "withheld"
    production_certification: str = "withheld"
    evidence_kind: str = "fixture_only"
    certifies_slice: bool = False
    schema_version: str = "jaa11.fixture-adapter-evidence.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "adapter_contract_sha256": self.adapter_contract_sha256,
            "observation_sha256": self.observation_sha256,
            "release_manifest_sha256": self.release_manifest_sha256,
            "token_sha256": self.token_sha256,
            "receipt_id": self.receipt_id,
            "receipt_payload_sha256": self.receipt_payload_sha256,
            "submit_event_sha256": self.submit_event_sha256,
            "real_canary_activation": "withheld",
            "production_certification": "withheld",
            "evidence_kind": "fixture_only",
            "certifies_slice": False,
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.adapter_contract_sha256, "evidence contract hash"),
            (self.observation_sha256, "evidence observation hash"),
            (self.release_manifest_sha256, "evidence release hash"),
            (self.token_sha256, "evidence token hash"),
            (self.receipt_id, "evidence receipt identity"),
            (self.receipt_payload_sha256, "evidence receipt payload hash"),
            (self.submit_event_sha256, "evidence submit-event hash"),
        ):
            _digest(value, label)
        if (
            self.real_canary_activation != "withheld"
            or self.production_certification != "withheld"
            or self.evidence_kind != "fixture_only"
            or self.certifies_slice is not False
        ):
            raise ValueError(
                "fixture evidence cannot activate or certify JAA-11"
            )
        if self.schema_version != "jaa11.fixture-adapter-evidence.v1":
            raise ValueError("fixture adapter evidence schema is unsupported")
        expected = _content_hash(self.document(include_identity=False))
        if self.evidence_id != expected:
            raise ValueError(
                "fixture adapter evidence differs from its exact content"
            )


@dataclass(frozen=True)
class AdapterAttemptResult:
    outcome: str
    reason_codes: tuple[str, ...]
    evidence_id: str | None
    receipt_id: str | None
    halts_canaries: bool
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa11.fixture-attempt-result.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        if self.outcome not in {
            "circuit_open",
            "fixture_pass",
            "parked",
        }:
            raise ValueError("fixture adapter attempt outcome is invalid")
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("fixture adapter result reasons must be unique")
        if self.outcome == "fixture_pass":
            _digest(self.evidence_id or "", "fixture evidence identity")
            _digest(self.receipt_id or "", "fixture receipt identity")
            if self.reason_codes or self.halts_canaries:
                raise ValueError(
                    "passing fixture attempt cannot retain blockers"
                )
        else:
            if self.evidence_id is not None or self.receipt_id is not None:
                raise ValueError(
                    "blocked fixture attempt cannot retain evidence or receipt"
                )
            valid = (
                BLOCKING_SIGNALS
                if self.outcome == "parked"
                else INVARIANT_BREACHES
            )
            if (
                not self.reason_codes
                or any(reason not in valid for reason in self.reason_codes)
            ):
                raise ValueError(
                    "blocked fixture attempt has invalid reasons"
                )
            if self.halts_canaries != (self.outcome == "circuit_open"):
                raise ValueError(
                    "only an invariant breach can halt adapter canaries"
                )
        if (
            self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError(
                "fixture attempt cannot certify a production adapter"
            )
        if self.schema_version != "jaa11.fixture-attempt-result.v1":
            raise ValueError("fixture adapter result schema is unsupported")


def armed_fixture_circuit(
    contract: FixtureAdapterContract,
) -> AdapterCircuitBreaker:
    if contract != FROZEN_FIXTURE_ADAPTER_CONTRACT:
        raise ValueError("fixture circuit requires the canonical contract")
    return AdapterCircuitBreaker(contract.contract_sha256)


def _hard_breach(
    contract: FixtureAdapterContract,
    observation: AdapterFixtureObservation,
) -> str | None:
    if observation.observed_form_schema_sha256 != (
        contract.form_schema_sha256
    ):
        return "changed_form_schema"
    if observation.observed_selector_set_sha256 != (
        contract.selector_set_sha256
    ):
        return "changed_selector_set"
    if observation.workflow_sha256 != contract.workflow_sha256:
        return "changed_workflow"
    if observation.submit_dispatch_count == 0:
        return "missing_submit_dispatch"
    if observation.submit_dispatch_count != 1:
        return "second_submit_attempt"
    receipt = observation.receipt
    if receipt is None:
        return "missing_receipt"
    try:
        receipt.verify()
    except (TypeError, ValueError):
        return "fabricated_receipt"
    proof = observation.submission_proof
    if (
        receipt.application_id != contract.application_id
        or receipt.job_key != contract.job_key
        or proof.receipt_id != receipt.receipt_id
        or proof.receipt_payload_sha256 != receipt.payload_sha256
    ):
        return "mismatched_receipt"
    if (
        proof.receipt_id != FROZEN_SHADOW_CONTRACT.receipt_id
        or proof.receipt_payload_sha256
        != FROZEN_SHADOW_CONTRACT.receipt_payload_sha256
        or proof.field_map_sha256
        != FROZEN_SHADOW_CONTRACT.field_map_sha256
        or proof.screenshot_sha256
        != FROZEN_SHADOW_CONTRACT.screenshot_sha256
        or proof.submit_event_sha256
        != FROZEN_SHADOW_CONTRACT.submit_event_sha256
    ):
        return "changed_submission_proof"
    return None


def assess_fixture_adapter_attempt(
    contract: FixtureAdapterContract,
    circuit: AdapterCircuitBreaker,
    observation: AdapterFixtureObservation,
) -> tuple[
    AdapterCircuitBreaker,
    AdapterAttemptResult,
    FixtureAdapterEvidence | None,
]:
    """Assess pure fixture evidence without executing or authorizing an action."""
    if contract != FROZEN_FIXTURE_ADAPTER_CONTRACT:
        raise ValueError(
            "fixture assessment requires the canonical adapter contract"
        )
    if not isinstance(circuit, AdapterCircuitBreaker):
        raise TypeError(
            "fixture assessment requires an AdapterCircuitBreaker"
        )
    if circuit.adapter_contract_sha256 != contract.contract_sha256:
        raise ValueError("fixture circuit binds a different contract")
    if circuit.state != "armed":
        raise RuntimeError("fixture adapter circuit breaker is open")
    if not isinstance(observation, AdapterFixtureObservation):
        raise TypeError(
            "fixture assessment requires an AdapterFixtureObservation"
        )
    if observation.adapter_contract_sha256 != contract.contract_sha256:
        raise ValueError("fixture observation binds a different contract")

    attempt_count = circuit.assessed_attempts + 1
    breach = _hard_breach(contract, observation)
    if breach is not None:
        next_circuit = AdapterCircuitBreaker(
            contract.contract_sha256,
            state="tripped",
            assessed_attempts=attempt_count,
            breach_code=breach,
        )
        result = AdapterAttemptResult(
            outcome="circuit_open",
            reason_codes=(breach,),
            evidence_id=None,
            receipt_id=None,
            halts_canaries=True,
        )
        return next_circuit, result, None

    if observation.blocking_signals:
        next_circuit = AdapterCircuitBreaker(
            contract.contract_sha256,
            assessed_attempts=attempt_count,
        )
        result = AdapterAttemptResult(
            outcome="parked",
            reason_codes=observation.blocking_signals,
            evidence_id=None,
            receipt_id=None,
            halts_canaries=False,
        )
        return next_circuit, result, None

    proof = observation.submission_proof
    body = {
        "schema_version": "jaa11.fixture-adapter-evidence.v1",
        "adapter_contract_sha256": contract.contract_sha256,
        "observation_sha256": observation.observation_sha256,
        "release_manifest_sha256": proof.release_manifest_sha256,
        "token_sha256": proof.token_sha256,
        "receipt_id": proof.receipt_id,
        "receipt_payload_sha256": proof.receipt_payload_sha256,
        "submit_event_sha256": proof.submit_event_sha256,
        "real_canary_activation": "withheld",
        "production_certification": "withheld",
        "evidence_kind": "fixture_only",
        "certifies_slice": False,
    }
    evidence = FixtureAdapterEvidence(
        adapter_contract_sha256=contract.contract_sha256,
        observation_sha256=observation.observation_sha256,
        release_manifest_sha256=proof.release_manifest_sha256,
        token_sha256=proof.token_sha256,
        receipt_id=proof.receipt_id,
        receipt_payload_sha256=proof.receipt_payload_sha256,
        submit_event_sha256=proof.submit_event_sha256,
        evidence_id=_content_hash(body),
    )
    next_circuit = AdapterCircuitBreaker(
        contract.contract_sha256,
        assessed_attempts=attempt_count,
    )
    result = AdapterAttemptResult(
        outcome="fixture_pass",
        reason_codes=(),
        evidence_id=evidence.evidence_id,
        receipt_id=evidence.receipt_id,
        halts_canaries=False,
    )
    return next_circuit, result, evidence
