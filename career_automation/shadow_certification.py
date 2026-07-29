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
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

from .ats_fixture import FixtureReceipt
from .browser_workflows import (
    SubmissionProof,
    fixture_submit_event_sha256,
)

HEX_64 = re.compile(r"^[0-9a-f]{64}$")
BASELINE_REVISION = "8107f09beb3c5651850ad40a0ff8842ac2de1e47"
MINIMUM_SHADOW_SEPARATION = timedelta(hours=24)
REQUIRED_INTERRUPTION_POINTS = (
    "post_prepare_pre_consume",
    "post_consume_pre_reconcile",
    "post_consume_pre_click",
    "post_mark_pre_click",
    "post_click_pre_checkpoint",
)
REQUIRED_MUTATION_CONTROLS = (
    "unsupported_metric",
    "stale_vacancy",
    "ineligible_contract",
    "duplicate_release",
    "release_clock_forgery",
    "upload_byte_drift",
    "selector_drift",
    "field_map_drift",
    "release_token_tamper",
    "receipt_payload_fabrication",
    "local_origin_drift",
    "disguised_submit",
    "duplicate_submit",
    "concurrent_submit",
)
MUTATION_TEST_NODES: Mapping[str, str] = MappingProxyType({
    "unsupported_metric": (
        "test_jaa07_negative_controls.py::"
        "test_factual_sentence_cannot_paraphrase_or_add_an_unsupported_metric"
    ),
    "stale_vacancy": (
        "test_jaa08_negative_controls.py::"
        "test_non_bypassable_deterministic_preconditions"
        "[stale_vacancy-vacancy is stale]"
    ),
    "ineligible_contract": (
        "test_jaa08_negative_controls.py::"
        "test_non_bypassable_deterministic_preconditions"
        "[ineligible-work right]"
    ),
    "duplicate_release": (
        "test_jaa08_negative_controls.py::"
        "test_non_bypassable_deterministic_preconditions"
        "[duplicate-duplicate application]"
    ),
    "release_clock_forgery": (
        "test_jaa08_negative_controls.py::"
        "test_action_capable_release_store_rejects_caller_forged_future_clock"
    ),
    "upload_byte_drift": (
        "test_jaa09_negative_controls.py::"
        "test_executor_detects_upload_mutation_before_browser_materialization"
    ),
    "selector_drift": (
        "test_jaa09_negative_controls.py::"
        "test_executor_records_ambiguous_selector_without_advancing"
    ),
    "field_map_drift": (
        "test_jaa10_negative_controls.py::"
        "test_frozen_field_map_drift_cannot_enter_shadow_evidence"
    ),
    "release_token_tamper": (
        "test_jaa09_negative_controls.py::"
        "test_invalid_jaa08_token_cannot_create_fixture_receipt"
    ),
    "receipt_payload_fabrication": (
        "test_jaa09_negative_controls.py::"
        "test_self_consistent_wrong_payload_receipt_is_not_recorded"
    ),
    "local_origin_drift": (
        "test_jaa09_negative_controls.py::"
        "test_fixture_refuses_other_loopback_host_port_or_origin"
    ),
    "disguised_submit": (
        "test_jaa09_negative_controls.py::"
        "test_click_action_cannot_disguise_final_submission"
    ),
    "duplicate_submit": (
        "test_jaa09_negative_controls.py::"
        "test_duplicate_submit_and_second_review_produce_no_second_receipt"
    ),
    "concurrent_submit": (
        "test_jaa09_negative_controls.py::"
        "test_one_jaa08_token_cannot_prepare_two_browser_submit_runs"
    ),
})
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
HARD_QUALITY_TARGETS: Mapping[str, int] = MappingProxyType({
    "ats_parse_success_bp": 10_000,
    "confirmed_without_receipt": 0,
    "deterministic_replay_mismatch": 0,
    "duplicate_submissions": 0,
    "ineligible_submissions": 0,
    "released_employer_claims_without_citations": 0,
    "unsupported_released_claims": 0,
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


def normalized_workflow_sha256(
    workflow_document: Mapping[str, object],
) -> str:
    """Hash a workflow after replacing its ephemeral loopback port with zero."""
    document = json.loads(_canonical_json(dict(workflow_document)))
    actions = document.get("actions")
    if not isinstance(actions, list):
        raise ValueError("workflow template actions are invalid")
    for action in actions:
        if not isinstance(action, dict):
            raise ValueError("workflow template action is invalid")
        if action.get("kind") != "navigate":
            continue
        target = action.get("target_url")
        if not isinstance(target, str):
            raise ValueError("workflow navigate target is invalid")
        parsed = urlsplit(target)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("shadow workflow target must be loopback HTTP")
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        action["target_url"] = (
            f"http://{host}:0{parsed.path}"
            + (f"?{parsed.query}" if parsed.query else "")
        )
    return _content_hash(document)


def normalized_submit_event_sha256(
    *,
    workflow_sha256: str,
    receipt_id: str,
    receipt_payload_sha256: str,
    screenshot_sha256: str,
    field_map_sha256: str,
) -> str:
    """Hash the stable semantic submit event without runtime run/origin IDs."""
    for value, label in (
        (workflow_sha256, "normalized workflow hash"),
        (receipt_id, "receipt identity"),
        (receipt_payload_sha256, "receipt payload hash"),
        (screenshot_sha256, "screenshot hash"),
        (field_map_sha256, "field-map hash"),
    ):
        _digest(value, label)
    return _content_hash(
        {
            "contract": "jaa10.normalized-submit-event.v1",
            "workflow_sha256": workflow_sha256,
            "receipt_id": receipt_id,
            "receipt_payload_sha256": receipt_payload_sha256,
            "screenshot_sha256": screenshot_sha256,
            "field_map_sha256": field_map_sha256,
        }
    )


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
        expected_submit_event = normalized_submit_event_sha256(
            workflow_sha256=self.workflow_sha256,
            receipt_id=self.receipt_id,
            receipt_payload_sha256=self.receipt_payload_sha256,
            screenshot_sha256=self.screenshot_sha256,
            field_map_sha256=self.field_map_sha256,
        )
        if self.submit_event_sha256 != expected_submit_event:
            raise ValueError(
                "shadow submit-event hash differs from its frozen inputs"
            )

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
            "minimum_shadow_separation_seconds": int(
                MINIMUM_SHADOW_SEPARATION.total_seconds()
            ),
            "required_actions": REQUIRED_ACTIONS,
            "required_interruption_points": REQUIRED_INTERRUPTION_POINTS,
            "mutation_test_nodes": dict(sorted(MUTATION_TEST_NODES.items())),
            "hard_quality_targets": dict(
                sorted(HARD_QUALITY_TARGETS.items())
            ),
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_SHADOW_CONTRACT = FrozenShadowContract(
    workflow_sha256=(
        "ec9329ec86534bc2a1fa37c0f12034806cdedbdd0ba472d34fc74b2ae69961da"
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
        "ab9985ca0792079093161d234036109d4769838b5335454425e93fe4a20eb7c9"
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
        if self.outcome == "fail_closed" and (
            self.submit_click_count != 0 or self.receipt_count != 0
        ):
            raise ValueError(
                "fail-closed interruption cannot perform a click or produce a receipt"
            )

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
    test_node: str
    blocked: bool
    receipt_created: bool

    def __post_init__(self) -> None:
        if self.control_id not in REQUIRED_MUTATION_CONTROLS:
            raise ValueError("mutation control is outside the frozen contract")
        if self.test_node != MUTATION_TEST_NODES[self.control_id]:
            raise ValueError("mutation control cites a different executable test")
        if not self.blocked or self.receipt_created:
            raise ValueError("shadow mutation control did not fail closed")

    def document(self) -> dict[str, object]:
        return {
            "control_id": self.control_id,
            "test_node": self.test_node,
            "blocked": True,
            "receipt_created": False,
        }


@dataclass(frozen=True)
class ShadowObservation:
    observation_id: str
    observed_at: str
    run_id: str
    step_id: str
    workflow_sha256: str
    durable_workflow_sha256: str
    release_manifest_sha256: str
    receipt_id: str
    receipt_payload_sha256: str
    field_map_sha256: str
    screenshot_sha256: str
    submit_event_sha256: str
    normalized_submit_event_sha256: str
    submission_proof: SubmissionProof
    fixture_receipt: FixtureReceipt
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
    execution_claim: str = "structural_lineage_only"
    schema_version: str = "jaa10.shadow-observation.v2"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "action_elapsed_ms",
            MappingProxyType(dict(self.action_elapsed_ms)),
        )
        if not self.observation_id or not self.run_id or not self.step_id:
            raise ValueError("shadow observation execution identity is incomplete")
        parsed = datetime.fromisoformat(self.observed_at)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("shadow observation time must include a timezone")
        for value, label in (
            (self.workflow_sha256, "observation workflow hash"),
            (
                self.durable_workflow_sha256,
                "observation durable workflow hash",
            ),
            (
                self.release_manifest_sha256,
                "observation release manifest hash",
            ),
            (self.receipt_id, "observation receipt identity"),
            (self.receipt_payload_sha256, "observation payload hash"),
            (self.field_map_sha256, "observation field-map hash"),
            (self.screenshot_sha256, "observation screenshot hash"),
            (self.submit_event_sha256, "observation submit-event hash"),
            (
                self.normalized_submit_event_sha256,
                "observation normalized submit-event hash",
            ),
        ):
            _digest(value, label)
        if not isinstance(self.submission_proof, SubmissionProof):
            raise TypeError("shadow observation requires a typed submission proof")
        if not isinstance(self.fixture_receipt, FixtureReceipt):
            raise TypeError("shadow observation requires a typed fixture receipt")
        self.fixture_receipt.verify()
        proof_values = (
            self.submission_proof.release_manifest_sha256,
            self.submission_proof.receipt_id,
            self.submission_proof.receipt_payload_sha256,
            self.submission_proof.field_map_sha256,
            self.submission_proof.screenshot_sha256,
            self.submission_proof.submit_event_sha256,
        )
        observation_values = (
            self.release_manifest_sha256,
            self.receipt_id,
            self.receipt_payload_sha256,
            self.field_map_sha256,
            self.screenshot_sha256,
            self.submit_event_sha256,
        )
        if proof_values != observation_values:
            raise ValueError(
                "shadow submission proof differs from observation lineage"
            )
        if (
            self.fixture_receipt.receipt_id != self.receipt_id
            or self.fixture_receipt.application_id
            != FROZEN_SHADOW_CONTRACT.application_id
            or self.fixture_receipt.job_key != FROZEN_SHADOW_CONTRACT.job_key
            or self.fixture_receipt.payload_sha256
            != self.receipt_payload_sha256
        ):
            raise ValueError(
                "shadow fixture receipt differs from observation lineage"
            )
        expected_submit_event = fixture_submit_event_sha256(
            run_id=self.run_id,
            workflow_sha256=self.durable_workflow_sha256,
            step_id=self.step_id,
            release_manifest_sha256=self.release_manifest_sha256,
            receipt_id=self.receipt_id,
            receipt_payload_sha256=self.receipt_payload_sha256,
            screenshot_sha256=self.screenshot_sha256,
            field_map_sha256=self.field_map_sha256,
        )
        if self.submit_event_sha256 != expected_submit_event:
            raise ValueError(
                "shadow durable submit event differs from its exact lineage"
            )
        expected_normalized_event = normalized_submit_event_sha256(
            workflow_sha256=self.workflow_sha256,
            receipt_id=self.receipt_id,
            receipt_payload_sha256=self.receipt_payload_sha256,
            screenshot_sha256=self.screenshot_sha256,
            field_map_sha256=self.field_map_sha256,
        )
        if self.normalized_submit_event_sha256 != expected_normalized_event:
            raise ValueError(
                "shadow normalized submit event differs from its exact lineage"
            )
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
        if self.execution_claim != "structural_lineage_only":
            raise ValueError(
                "shadow observation cannot self-attest execution"
            )
        if tuple(row.injection_point for row in self.interruptions) != (
            REQUIRED_INTERRUPTION_POINTS
        ):
            raise ValueError("shadow interruption inventory is incomplete")
        if tuple(row.control_id for row in self.mutations) != (
            REQUIRED_MUTATION_CONTROLS
        ):
            raise ValueError("shadow mutation inventory is incomplete")
        if self.schema_version != "jaa10.shadow-observation.v2":
            raise ValueError("shadow observation schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "observed_at": self.observed_at,
            "evidence_kind": self.evidence_kind,
            "execution_claim": self.execution_claim,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "workflow_sha256": self.workflow_sha256,
            "durable_workflow_sha256": self.durable_workflow_sha256,
            "release_manifest_sha256": self.release_manifest_sha256,
            "receipt_id": self.receipt_id,
            "receipt_payload_sha256": self.receipt_payload_sha256,
            "field_map_sha256": self.field_map_sha256,
            "screenshot_sha256": self.screenshot_sha256,
            "submit_event_sha256": self.submit_event_sha256,
            "normalized_submit_event_sha256": (
                self.normalized_submit_event_sha256
            ),
            "submission_proof": {
                "release_manifest_sha256": (
                    self.submission_proof.release_manifest_sha256
                ),
                "token_sha256": self.submission_proof.token_sha256,
                "receipt_id": self.submission_proof.receipt_id,
                "receipt_payload_sha256": (
                    self.submission_proof.receipt_payload_sha256
                ),
                "screenshot_sha256": (
                    self.submission_proof.screenshot_sha256
                ),
                "field_map_sha256": self.submission_proof.field_map_sha256,
                "submit_event_sha256": (
                    self.submission_proof.submit_event_sha256
                ),
            },
            "fixture_receipt": self.fixture_receipt.document(),
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


def _validate_shadow_observations(
    contract: FrozenShadowContract,
    observations: tuple[ShadowObservation, ...],
) -> None:
    if contract != FROZEN_SHADOW_CONTRACT:
        raise ValueError(
            "shadow evidence requires the canonical frozen contract"
        )
    if len(observations) < 2 or not all(
        isinstance(row, ShadowObservation) for row in observations
    ):
        raise ValueError("shadow evidence requires two typed observations")
    times = tuple(
        datetime.fromisoformat(row.observed_at) for row in observations
    )
    if tuple(sorted(times)) != times or len(set(times)) != len(times):
        raise ValueError("shadow observations must be time-separated and ordered")
    if any(
        later - earlier < MINIMUM_SHADOW_SEPARATION
        for earlier, later in zip(times, times[1:], strict=False)
    ):
        raise ValueError(
            "shadow observations must be separated by at least 24 hours"
        )
    if len({row.observation_id for row in observations}) != len(observations):
        raise ValueError("shadow observation IDs must be unique")
    if len({
        row.release_manifest_sha256 for row in observations
    }) != len(observations):
        raise ValueError(
            "shadow observations require distinct release manifests"
        )
    for row in observations:
        actual = (
            row.workflow_sha256,
            row.receipt_id,
            row.receipt_payload_sha256,
            row.field_map_sha256,
            row.screenshot_sha256,
            row.normalized_submit_event_sha256,
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
            raise ValueError(
                "shadow observation differs from its frozen golden set"
            )


@dataclass(frozen=True)
class WithheldShadowEvidence:
    contract: FrozenShadowContract
    observations: tuple[ShadowObservation, ...]
    hard_quality_targets: Mapping[str, int]
    evidence_id: str
    metrics_evaluated: bool = False
    production_certification: str = "withheld"
    withheld_reason: str = "upstream_jaa04_authentic_authority_blocked"
    evidence_kind: str = "synthetic_shadow"
    certifies_slice: bool = False
    schema_version: str = "jaa10.withheld-shadow-evidence.v3"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "hard_quality_targets",
            MappingProxyType(dict(self.hard_quality_targets)),
        )
        self.verify()

    @property
    def contract_sha256(self) -> str:
        return self.contract.contract_sha256

    @property
    def observation_sha256s(self) -> tuple[str, ...]:
        return tuple(row.observation_sha256 for row in self.observations)

    @property
    def release_manifest_sha256s(self) -> tuple[str, ...]:
        return tuple(
            row.release_manifest_sha256 for row in self.observations
        )

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract": self.contract.document(),
            "contract_sha256": self.contract.contract_sha256,
            "observations": [
                row.document() for row in self.observations
            ],
            "observation_sha256s": self.observation_sha256s,
            "release_manifest_sha256s": self.release_manifest_sha256s,
            "hard_quality_targets": dict(
                sorted(self.hard_quality_targets.items())
            ),
            "metrics_evaluated": False,
            "production_certification": "withheld",
            "withheld_reason": self.withheld_reason,
            "evidence_kind": "synthetic_shadow",
            "certifies_slice": False,
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        if (
            not isinstance(self.contract, FrozenShadowContract)
            or self.contract != FROZEN_SHADOW_CONTRACT
        ):
            raise ValueError(
                "withheld evidence requires the canonical frozen contract"
            )
        _validate_shadow_observations(self.contract, self.observations)
        if len(set(self.observation_sha256s)) != len(
            self.observation_sha256s
        ):
            raise ValueError("shadow observation identities must be unique")
        if dict(self.hard_quality_targets) != HARD_QUALITY_TARGETS:
            raise ValueError("shadow hard-quality targets differ from policy")
        if (
            self.metrics_evaluated is not False
            or self.production_certification != "withheld"
            or self.withheld_reason
            != "upstream_jaa04_authentic_authority_blocked"
            or self.evidence_kind != "synthetic_shadow"
            or self.certifies_slice is not False
        ):
            raise ValueError("shadow evidence cannot certify production")
        if self.schema_version != "jaa10.withheld-shadow-evidence.v3":
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
    if contract != FROZEN_SHADOW_CONTRACT:
        raise ValueError(
            "shadow compilation requires the canonical frozen contract"
        )
    _validate_shadow_observations(contract, observations)
    body = {
        "schema_version": "jaa10.withheld-shadow-evidence.v3",
        "contract": contract.document(),
        "contract_sha256": contract.contract_sha256,
        "observations": [row.document() for row in observations],
        "observation_sha256s": tuple(
            row.observation_sha256 for row in observations
        ),
        "release_manifest_sha256s": tuple(
            row.release_manifest_sha256 for row in observations
        ),
        "hard_quality_targets": dict(sorted(HARD_QUALITY_TARGETS.items())),
        "metrics_evaluated": False,
        "production_certification": "withheld",
        "withheld_reason": "upstream_jaa04_authentic_authority_blocked",
        "evidence_kind": "synthetic_shadow",
        "certifies_slice": False,
    }
    result = WithheldShadowEvidence(
        contract=contract,
        observations=observations,
        hard_quality_targets=dict(HARD_QUALITY_TARGETS),
        evidence_id=_content_hash(body),
    )
    result.verify()
    return result
