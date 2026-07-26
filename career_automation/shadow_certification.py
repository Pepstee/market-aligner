"""Noncertifying frozen-shadow evidence contract for bounded JAA-10.

The contract can summarize synthetic localhost observations only. It has no
browser, network, release-token, lifecycle, publication, or certification
capability. Production certification is structurally withheld while upstream
authority remains blocked.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
BASELINE_REVISION = "6e627e3ae07744e2c658a2046f0cd3121b7c2254"
REQUIRED_INTERRUPTION_POINTS = (
    "post_prepare_pre_consume",
    "post_consume_pre_click",
    "post_click_pre_checkpoint",
)
REQUIRED_MUTATION_CONTROLS = (
    "upload_byte_drift",
    "selector_drift",
    "field_map_drift",
    "release_token_tamper",
    "disguised_submit",
    "duplicate_submit",
    "concurrent_submit",
)
REQUIRED_ACTIONS = (
    "open",
    "full_name",
    "email",
    "phone",
    "city",
    "work_authorisation",
    "cover_note",
    "cv",
    "cover_letter",
    "review",
    "submit",
)
HARD_QUALITY_TARGETS = {
    "ats_parse_success_bp": 10_000,
    "confirmed_without_receipt": 0,
    "deterministic_replay_mismatch": 0,
    "duplicate_submissions": 0,
    "ineligible_submissions": 0,
    "released_employer_claims_without_citations": 0,
    "unsupported_released_claims": 0,
}


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


@dataclass(frozen=True)
class FrozenShadowContract:
    workflow_sha256: str
    application_id: str
    job_key: str
    receipt_id: str
    receipt_payload_sha256: str
    field_map_sha256: str
    screenshot_sha256: str
    submit_event_sha256: str
    baseline_revision: str = BASELINE_REVISION
    schema_version: str = "jaa10.frozen-shadow-contract.v1"

    def __post_init__(self) -> None:
        if self.baseline_revision != BASELINE_REVISION:
            raise ValueError("shadow baseline must bind the accepted JAA-09 commit")
        if not re.fullmatch(r"[0-9a-f]{40}", self.baseline_revision):
            raise ValueError("shadow baseline revision is invalid")
        if not self.application_id or not self.job_key:
            raise ValueError("shadow fixture identity is incomplete")
        for value, label in (
            (self.workflow_sha256, "workflow hash"),
            (self.receipt_id, "receipt identity"),
            (self.receipt_payload_sha256, "receipt payload hash"),
            (self.field_map_sha256, "field-map hash"),
            (self.screenshot_sha256, "screenshot hash"),
            (self.submit_event_sha256, "submit-event hash"),
        ):
            _digest(value, label)
        if self.schema_version != "jaa10.frozen-shadow-contract.v1":
            raise ValueError("shadow contract schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "baseline_revision": self.baseline_revision,
            "workflow_sha256": self.workflow_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "receipt_id": self.receipt_id,
            "receipt_payload_sha256": self.receipt_payload_sha256,
            "field_map_sha256": self.field_map_sha256,
            "screenshot_sha256": self.screenshot_sha256,
            "submit_event_sha256": self.submit_event_sha256,
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_SHADOW_CONTRACT = FrozenShadowContract(
    workflow_sha256=(
        "ccd8f38596d1d31682ae126c45c61ee45fcff48df8f8650d25b6ccda8411e025"
    ),
    application_id="jaa10-frozen-platform-engineer",
    job_key="jaa06-synthetic:strategy-job",
    receipt_id=(
        "69a871ba9d9727c77a8eb06de29e186f64a3c75f036364a7fa0dda4064c9945a"
    ),
    receipt_payload_sha256=(
        "f914ca653f03eec5c2b28a3a32355f86571ae066a73f80a11cc6db72b40219d8"
    ),
    field_map_sha256=(
        "049d0e52a572d3341e353d1b48ef4b7ed3bc5d4b59f296efc6e345bd53b1fbd3"
    ),
    screenshot_sha256=(
        "91a316e9f44cb894792896ad063e975badff08e6c5fd762de47a8798a5b3feb4"
    ),
    submit_event_sha256=(
        "460b812d08197ba927b851193ef9a0bdc7191fb42f8ceecd3dbc2ab0b52ce1a7"
    ),
)


@dataclass(frozen=True)
class InterruptionObservation:
    injection_point: str
    outcome: str
    submit_click_count: int
    receipt_count: int
    fabricated_receipt: bool = False

    def __post_init__(self) -> None:
        if self.injection_point not in REQUIRED_INTERRUPTION_POINTS:
            raise ValueError("interruption point is outside the frozen contract")
        if self.outcome not in {"recovered", "fail_closed"}:
            raise ValueError("interruption outcome must recover or fail closed")
        if self.submit_click_count not in {0, 1}:
            raise ValueError("interruption may perform at most one submit click")
        if self.receipt_count not in {0, 1}:
            raise ValueError("interruption may produce at most one receipt")
        if self.fabricated_receipt:
            raise ValueError("shadow interruption cannot retain a fabricated receipt")
        if self.outcome == "recovered" and (
            self.submit_click_count != 1 or self.receipt_count != 1
        ):
            raise ValueError("recovered interruption requires one click and receipt")
        if self.outcome == "fail_closed" and self.receipt_count != 0:
            raise ValueError("fail-closed interruption cannot produce a receipt")

    def document(self) -> dict[str, object]:
        return {
            "injection_point": self.injection_point,
            "outcome": self.outcome,
            "submit_click_count": self.submit_click_count,
            "receipt_count": self.receipt_count,
            "fabricated_receipt": False,
        }


@dataclass(frozen=True)
class MutationObservation:
    control_id: str
    blocked: bool
    receipt_created: bool

    def __post_init__(self) -> None:
        if self.control_id not in REQUIRED_MUTATION_CONTROLS:
            raise ValueError("mutation control is outside the frozen contract")
        if not self.blocked or self.receipt_created:
            raise ValueError("shadow mutation control did not fail closed")

    def document(self) -> dict[str, object]:
        return {
            "control_id": self.control_id,
            "blocked": True,
            "receipt_created": False,
        }


@dataclass(frozen=True)
class ShadowObservation:
    observation_id: str
    observed_at: str
    workflow_sha256: str
    receipt_id: str
    receipt_payload_sha256: str
    field_map_sha256: str
    screenshot_sha256: str
    submit_event_sha256: str
    action_elapsed_ms: Mapping[str, int]
    browser_launch_count: int
    database_bytes: int
    screenshot_bytes: int
    interruptions: tuple[InterruptionObservation, ...]
    mutations: tuple[MutationObservation, ...]
    evidence_kind: str = "synthetic_shadow"
    model_version: str = "deterministic:none"
    prompt_version: str = "deterministic:none"
    model_cost_microusd: int = 0
    schema_version: str = "jaa10.shadow-observation.v1"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "action_elapsed_ms",
            MappingProxyType(dict(self.action_elapsed_ms)),
        )
        if not self.observation_id:
            raise ValueError("shadow observation ID is required")
        parsed = datetime.fromisoformat(self.observed_at)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("shadow observation time must include a timezone")
        for value, label in (
            (self.workflow_sha256, "observation workflow hash"),
            (self.receipt_id, "observation receipt identity"),
            (self.receipt_payload_sha256, "observation payload hash"),
            (self.field_map_sha256, "observation field-map hash"),
            (self.screenshot_sha256, "observation screenshot hash"),
            (self.submit_event_sha256, "observation submit-event hash"),
        ):
            _digest(value, label)
        if set(self.action_elapsed_ms) != set(REQUIRED_ACTIONS):
            raise ValueError("shadow action latency inventory is incomplete")
        if any(
            not isinstance(value, int) or value < 0
            for value in self.action_elapsed_ms.values()
        ):
            raise ValueError("shadow action latencies must be non-negative integers")
        if (
            self.browser_launch_count < 1
            or self.database_bytes < 1
            or self.screenshot_bytes < 1
        ):
            raise ValueError("shadow runtime metrics must be positive")
        if (
            self.evidence_kind != "synthetic_shadow"
            or self.model_version != "deterministic:none"
            or self.prompt_version != "deterministic:none"
            or self.model_cost_microusd != 0
        ):
            raise ValueError("shadow observation cannot claim live or model work")
        if tuple(row.injection_point for row in self.interruptions) != (
            REQUIRED_INTERRUPTION_POINTS
        ):
            raise ValueError("shadow interruption inventory is incomplete")
        if tuple(row.control_id for row in self.mutations) != (
            REQUIRED_MUTATION_CONTROLS
        ):
            raise ValueError("shadow mutation inventory is incomplete")
        if self.schema_version != "jaa10.shadow-observation.v1":
            raise ValueError("shadow observation schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "observed_at": self.observed_at,
            "evidence_kind": self.evidence_kind,
            "workflow_sha256": self.workflow_sha256,
            "receipt_id": self.receipt_id,
            "receipt_payload_sha256": self.receipt_payload_sha256,
            "field_map_sha256": self.field_map_sha256,
            "screenshot_sha256": self.screenshot_sha256,
            "submit_event_sha256": self.submit_event_sha256,
            "action_elapsed_ms": dict(sorted(self.action_elapsed_ms.items())),
            "browser_launch_count": self.browser_launch_count,
            "database_bytes": self.database_bytes,
            "screenshot_bytes": self.screenshot_bytes,
            "interruptions": [row.document() for row in self.interruptions],
            "mutations": [row.document() for row in self.mutations],
            "model_version": self.model_version,
            "prompt_version": self.prompt_version,
            "model_cost_microusd": self.model_cost_microusd,
        }

    @property
    def observation_sha256(self) -> str:
        return _content_hash(self.document())


@dataclass(frozen=True)
class WithheldShadowEvidence:
    contract_sha256: str
    observation_sha256s: tuple[str, ...]
    hard_quality_metrics: Mapping[str, int]
    evidence_id: str
    production_certification: str = "withheld"
    withheld_reason: str = "upstream_jaa04_authentic_authority_blocked"
    evidence_kind: str = "synthetic_shadow"
    certifies_slice: bool = False
    schema_version: str = "jaa10.withheld-shadow-evidence.v1"

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "observation_sha256s": self.observation_sha256s,
            "hard_quality_metrics": dict(sorted(self.hard_quality_metrics.items())),
            "production_certification": "withheld",
            "withheld_reason": self.withheld_reason,
            "evidence_kind": "synthetic_shadow",
            "certifies_slice": False,
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        _digest(self.contract_sha256, "shadow contract hash")
        if not self.observation_sha256s:
            raise ValueError("withheld shadow evidence requires observations")
        for value in self.observation_sha256s:
            _digest(value, "shadow observation hash")
        if len(set(self.observation_sha256s)) != len(
            self.observation_sha256s
        ):
            raise ValueError("shadow observation identities must be unique")
        if dict(self.hard_quality_metrics) != HARD_QUALITY_TARGETS:
            raise ValueError("shadow hard-quality metrics differ from policy")
        if (
            self.production_certification != "withheld"
            or self.withheld_reason
            != "upstream_jaa04_authentic_authority_blocked"
            or self.evidence_kind != "synthetic_shadow"
            or self.certifies_slice is not False
        ):
            raise ValueError("shadow evidence cannot certify production")
        if self.schema_version != "jaa10.withheld-shadow-evidence.v1":
            raise ValueError("withheld shadow schema is unsupported")
        expected = _content_hash(self.document(include_identity=False))
        if self.evidence_id != expected:
            raise ValueError("shadow evidence differs from its exact content")


def compile_withheld_shadow_evidence(
    contract: FrozenShadowContract,
    observations: tuple[ShadowObservation, ...],
) -> WithheldShadowEvidence:
    """Compile exact synthetic evidence while structurally withholding certification."""
    if not isinstance(contract, FrozenShadowContract):
        raise TypeError("shadow compilation requires a frozen contract")
    if len(observations) < 2 or not all(
        isinstance(row, ShadowObservation) for row in observations
    ):
        raise ValueError("shadow compilation requires two typed observations")
    times = tuple(datetime.fromisoformat(row.observed_at) for row in observations)
    if tuple(sorted(times)) != times or len(set(times)) != len(times):
        raise ValueError("shadow observations must be time-separated and ordered")
    for row in observations:
        actual = (
            row.workflow_sha256,
            row.receipt_id,
            row.receipt_payload_sha256,
            row.field_map_sha256,
            row.screenshot_sha256,
            row.submit_event_sha256,
        )
        expected = (
            contract.workflow_sha256,
            contract.receipt_id,
            contract.receipt_payload_sha256,
            contract.field_map_sha256,
            contract.screenshot_sha256,
            contract.submit_event_sha256,
        )
        if actual != expected:
            raise ValueError("shadow observation differs from its frozen golden set")
    body = {
        "schema_version": "jaa10.withheld-shadow-evidence.v1",
        "contract_sha256": contract.contract_sha256,
        "observation_sha256s": tuple(
            row.observation_sha256 for row in observations
        ),
        "hard_quality_metrics": HARD_QUALITY_TARGETS,
        "production_certification": "withheld",
        "withheld_reason": "upstream_jaa04_authentic_authority_blocked",
        "evidence_kind": "synthetic_shadow",
        "certifies_slice": False,
    }
    result = WithheldShadowEvidence(
        contract_sha256=contract.contract_sha256,
        observation_sha256s=tuple(body["observation_sha256s"]),
        hard_quality_metrics=HARD_QUALITY_TARGETS,
        evidence_id=_content_hash(body),
    )
    result.verify()
    return result
