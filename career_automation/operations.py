"""Pure-data unattended-operations contracts for bounded JAA-16 preparation.

The module describes schedules, budgets, fallbacks, drills, alerts and local
reports. It does not schedule work, invoke a provider, mutate a queue, send an
alert, perform a health check, deploy software or certify a release.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping

from career_automation.source_expansion import (
    FROZEN_SOURCE_EXPANSION_CONTRACT,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
PREFIXED_HEX_64 = re.compile(r"^sha256:[0-9a-f]{64}$")
FAILURE_KINDS = (
    "crash",
    "quota",
    "network",
    "stale_source",
    "model_failure",
    "restart",
)
PROVIDER_FAILURE_KINDS = frozenset({"quota", "model_failure"})
PAUSE_FAILURE_KINDS = frozenset({
    "quota",
    "network",
    "stale_source",
    "model_failure",
})
CHECKPOINT_FAILURE_KINDS = frozenset({"crash", "restart"})
ALERT_SIGNAL_KINDS = (
    "external_network",
    "provider_quota",
    "portal_unavailable",
    "stale_source",
    "credential_required",
    "captcha_or_mfa",
    "receipt_unavailable",
    "unsupported_route",
    "invariant_breach",
    "replay_mismatch",
    "data_loss",
    "duplicate_consequential_action",
)
ALERT_CLASSIFICATIONS = ("weather", "blocked_work", "product_defect")
WEATHER_SIGNALS = frozenset({
    "external_network",
    "provider_quota",
    "portal_unavailable",
    "stale_source",
})
BLOCKED_WORK_SIGNALS = frozenset({
    "credential_required",
    "captcha_or_mfa",
    "receipt_unavailable",
    "unsupported_route",
})
PRODUCT_DEFECT_SIGNALS = frozenset({
    "invariant_breach",
    "replay_mismatch",
    "data_loss",
    "duplicate_consequential_action",
})
REPORT_KINDS = ("daily_operations", "weekly_outcomes")
OBSERVABILITY_SOURCE_SHA256 = (
    "0044c49dbcdb0f6ae560119c928e516e8086e319b93364f4cffcaf5a60b4e4c8"
)
DEPLOYMENT_SOURCE_SHA256 = (
    "9a8107b6078e69b4cafe388002066deaab499a007352755607fdb9d59b260fa5"
)
ENGINE_SOURCE_SHA256 = (
    "89ff078aa5812c350c5aa194174764bcca8213c0dd445708fe30c8cf0191e5ae"
)
DATABASE_SOURCE_SHA256 = (
    "2c8f3e17d1559c0a4b37dac0281879aebad4ffa9b88650d4b9729c7c668fc611"
)
LIFECYCLE_SOURCE_SHA256 = (
    "1dd905f4e24bf0105e787aa4c2a72964e5585620fb552bd51edd19e6424f0ddc"
)
ACCEPTANCE_RUNNER_SHA256 = (
    "6d512b654f5870ebabeb348e38b927b51448357c8097ce2c1526475b1dd810bc"
)
ACCEPTANCE_CONTRACT_TEST_SHA256 = (
    "226338c3f929164fd0450a49ce945cdacdf1816b3f3583a657d116bf8873fe33"
)
OPERATIONS_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa16.local-operations-policy.v1",
    "required_failure_drills": FAILURE_KINDS,
    "provider_exhaustion_action": "pause_affected_work",
    "fallback_schema_change_allowed": False,
    "fallback_verification_rung_change_allowed": False,
    "duplicate_consequential_actions_allowed": 0,
    "data_loss_allowed": 0,
    "reports_are_local_drafts": True,
    "external_execution_authority": False,
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


def _prefixed_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not PREFIXED_HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be prefixed lowercase SHA-256")
    return value


def _required(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} is required")
    clean = value.strip()
    if not clean or clean != value:
        raise ValueError(
            f"{label} is required without surrounding whitespace"
        )
    return clean


def _aware_iso(value: str, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an aware ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an aware ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must be an aware ISO timestamp")
    if parsed.isoformat() != value:
        raise ValueError(f"{label} must use canonical ISO form")
    return parsed


def _aware(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"{label} must be timezone-aware")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


OPERATIONS_POLICY_SHA256 = _content_hash(dict(OPERATIONS_POLICY))


@dataclass(frozen=True)
class OperationsContract:
    upstream_source_expansion_contract_sha256: str
    observability_source_sha256: str
    deployment_source_sha256: str
    engine_source_sha256: str
    database_source_sha256: str
    lifecycle_source_sha256: str
    acceptance_runner_sha256: str
    acceptance_contract_test_sha256: str
    operations_policy_sha256: str
    scheduler_authority: str = "withheld"
    provider_execution_authority: str = "withheld"
    external_health_check_authority: str = "withheld"
    deployment_authority: str = "withheld"
    report_send_authority: str = "withheld"
    production_certification: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa16.local-operations-contract.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (
                self.upstream_source_expansion_contract_sha256,
                "source expansion contract hash",
            ),
            (self.observability_source_sha256, "observability source hash"),
            (self.deployment_source_sha256, "deployment source hash"),
            (self.engine_source_sha256, "engine source hash"),
            (self.database_source_sha256, "database source hash"),
            (self.lifecycle_source_sha256, "lifecycle source hash"),
            (self.acceptance_runner_sha256, "acceptance runner hash"),
            (
                self.acceptance_contract_test_sha256,
                "acceptance contract-test hash",
            ),
            (self.operations_policy_sha256, "operations policy hash"),
        ):
            _digest(value, label)
        expected = (
            FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256,
            OBSERVABILITY_SOURCE_SHA256,
            DEPLOYMENT_SOURCE_SHA256,
            ENGINE_SOURCE_SHA256,
            DATABASE_SOURCE_SHA256,
            LIFECYCLE_SOURCE_SHA256,
            ACCEPTANCE_RUNNER_SHA256,
            ACCEPTANCE_CONTRACT_TEST_SHA256,
            OPERATIONS_POLICY_SHA256,
        )
        actual = (
            self.upstream_source_expansion_contract_sha256,
            self.observability_source_sha256,
            self.deployment_source_sha256,
            self.engine_source_sha256,
            self.database_source_sha256,
            self.lifecycle_source_sha256,
            self.acceptance_runner_sha256,
            self.acceptance_contract_test_sha256,
            self.operations_policy_sha256,
        )
        if actual != expected:
            raise ValueError("operations contract differs from accepted inputs")
        if (
            self.scheduler_authority != "withheld"
            or self.provider_execution_authority != "withheld"
            or self.external_health_check_authority != "withheld"
            or self.deployment_authority != "withheld"
            or self.report_send_authority != "withheld"
            or self.production_certification != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version != "jaa16.local-operations-contract.v1"
        ):
            raise ValueError(
                "local operations contract cannot execute or certify"
            )

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "upstream_source_expansion_contract_sha256": (
                self.upstream_source_expansion_contract_sha256
            ),
            "observability_source_sha256": self.observability_source_sha256,
            "deployment_source_sha256": self.deployment_source_sha256,
            "engine_source_sha256": self.engine_source_sha256,
            "database_source_sha256": self.database_source_sha256,
            "lifecycle_source_sha256": self.lifecycle_source_sha256,
            "acceptance_runner_sha256": self.acceptance_runner_sha256,
            "acceptance_contract_test_sha256": (
                self.acceptance_contract_test_sha256
            ),
            "operations_policy_sha256": self.operations_policy_sha256,
            "scheduler_authority": "withheld",
            "provider_execution_authority": "withheld",
            "external_health_check_authority": "withheld",
            "deployment_authority": "withheld",
            "report_send_authority": "withheld",
            "production_certification": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_OPERATIONS_CONTRACT = OperationsContract(
    upstream_source_expansion_contract_sha256=(
        FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
    ),
    observability_source_sha256=OBSERVABILITY_SOURCE_SHA256,
    deployment_source_sha256=DEPLOYMENT_SOURCE_SHA256,
    engine_source_sha256=ENGINE_SOURCE_SHA256,
    database_source_sha256=DATABASE_SOURCE_SHA256,
    lifecycle_source_sha256=LIFECYCLE_SOURCE_SHA256,
    acceptance_runner_sha256=ACCEPTANCE_RUNNER_SHA256,
    acceptance_contract_test_sha256=ACCEPTANCE_CONTRACT_TEST_SHA256,
    operations_policy_sha256=OPERATIONS_POLICY_SHA256,
)


@dataclass(frozen=True)
class ScheduleDefinition:
    contract_sha256: str
    schedule_name: str
    workflow_sha256: str
    cadence_seconds: int
    jitter_seconds: int
    max_concurrent_runs: int
    paused_by_default: bool
    schedule_id: str
    scheduler_authority: str = "withheld"
    schema_version: str = "jaa16.schedule-definition.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "schedule_name": self.schedule_name,
            "workflow_sha256": self.workflow_sha256,
            "cadence_seconds": self.cadence_seconds,
            "jitter_seconds": self.jitter_seconds,
            "max_concurrent_runs": self.max_concurrent_runs,
            "paused_by_default": self.paused_by_default,
            "scheduler_authority": "withheld",
        }
        if include_identity:
            result["schedule_id"] = self.schedule_id
        return result

    def verify(self) -> None:
        _digest(self.contract_sha256, "schedule contract hash")
        _digest(self.workflow_sha256, "schedule workflow hash")
        _digest(self.schedule_id, "schedule ID")
        _required(self.schedule_name, "schedule name")
        if (
            type(self.cadence_seconds) is not int
            or self.cadence_seconds < 60
            or type(self.jitter_seconds) is not int
            or not 0 <= self.jitter_seconds < self.cadence_seconds
            or type(self.max_concurrent_runs) is not int
            or self.max_concurrent_runs < 1
            or type(self.paused_by_default) is not bool
        ):
            raise ValueError("schedule limits are invalid")
        if (
            self.contract_sha256 != FROZEN_OPERATIONS_CONTRACT.contract_sha256
            or self.scheduler_authority != "withheld"
            or self.schema_version != "jaa16.schedule-definition.v1"
        ):
            raise ValueError("schedule cannot execute work")
        if self.schedule_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("schedule identity is invalid")


def compile_schedule_definition(
    contract: OperationsContract,
    *,
    schedule_name: str,
    workflow_sha256: str,
    cadence_seconds: int,
    jitter_seconds: int,
    max_concurrent_runs: int,
    paused_by_default: bool = True,
) -> ScheduleDefinition:
    if contract != FROZEN_OPERATIONS_CONTRACT:
        raise ValueError("schedule requires the canonical operations contract")
    body = {
        "schema_version": "jaa16.schedule-definition.v1",
        "contract_sha256": contract.contract_sha256,
        "schedule_name": schedule_name,
        "workflow_sha256": workflow_sha256,
        "cadence_seconds": cadence_seconds,
        "jitter_seconds": jitter_seconds,
        "max_concurrent_runs": max_concurrent_runs,
        "paused_by_default": paused_by_default,
        "scheduler_authority": "withheld",
    }
    return ScheduleDefinition(**body, schedule_id=_content_hash(body))


@dataclass(frozen=True)
class ProviderRoute:
    contract_sha256: str
    capability: str
    route_id: str
    provider_id: str
    model_id: str
    priority: int
    output_schema_sha256: str
    policy_sha256: str
    verification_rungs: tuple[str, ...]
    max_input_tokens: int
    max_output_tokens: int
    max_cost_microusd: int
    route_definition_id: str
    execution_authority: str = "withheld"
    schema_version: str = "jaa16.provider-route.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "capability": self.capability,
            "route_id": self.route_id,
            "provider_id": self.provider_id,
            "model_id": self.model_id,
            "priority": self.priority,
            "output_schema_sha256": self.output_schema_sha256,
            "policy_sha256": self.policy_sha256,
            "verification_rungs": self.verification_rungs,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_cost_microusd": self.max_cost_microusd,
            "execution_authority": "withheld",
        }
        if include_identity:
            result["route_definition_id"] = self.route_definition_id
        return result

    def verify(self) -> None:
        _digest(self.contract_sha256, "provider route contract hash")
        _digest(self.output_schema_sha256, "provider output schema hash")
        _digest(self.policy_sha256, "provider policy hash")
        _digest(self.route_definition_id, "provider route definition ID")
        for value, label in (
            (self.capability, "provider capability"),
            (self.route_id, "provider route ID"),
            (self.provider_id, "provider ID"),
            (self.model_id, "model ID"),
        ):
            _required(value, label)
        if (
            type(self.priority) is not int
            or self.priority < 1
            or not self.verification_rungs
            or tuple(sorted(set(self.verification_rungs)))
            != self.verification_rungs
        ):
            raise ValueError("provider route priority or rungs are invalid")
        for value in self.verification_rungs:
            _required(value, "verification rung")
        for value, label in (
            (self.max_input_tokens, "provider input-token budget"),
            (self.max_output_tokens, "provider output-token budget"),
            (self.max_cost_microusd, "provider cost budget"),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{label} must be a positive integer")
        if (
            self.contract_sha256 != FROZEN_OPERATIONS_CONTRACT.contract_sha256
            or self.execution_authority != "withheld"
            or self.schema_version != "jaa16.provider-route.v1"
        ):
            raise ValueError("provider route cannot execute")
        if self.route_definition_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("provider route identity is invalid")


def compile_provider_route(
    contract: OperationsContract,
    *,
    capability: str,
    route_id: str,
    provider_id: str,
    model_id: str,
    priority: int,
    output_schema_sha256: str,
    policy_sha256: str,
    verification_rungs: tuple[str, ...],
    max_input_tokens: int,
    max_output_tokens: int,
    max_cost_microusd: int,
) -> ProviderRoute:
    if contract != FROZEN_OPERATIONS_CONTRACT:
        raise ValueError(
            "provider route requires the canonical operations contract"
        )
    body = {
        "schema_version": "jaa16.provider-route.v1",
        "contract_sha256": contract.contract_sha256,
        "capability": capability,
        "route_id": route_id,
        "provider_id": provider_id,
        "model_id": model_id,
        "priority": priority,
        "output_schema_sha256": output_schema_sha256,
        "policy_sha256": policy_sha256,
        "verification_rungs": tuple(sorted(set(verification_rungs))),
        "max_input_tokens": max_input_tokens,
        "max_output_tokens": max_output_tokens,
        "max_cost_microusd": max_cost_microusd,
        "execution_authority": "withheld",
    }
    return ProviderRoute(
        **body,
        route_definition_id=_content_hash(body),
    )


@dataclass(frozen=True)
class ProviderRouteSet:
    contract_sha256: str
    capability: str
    routes: tuple[ProviderRoute, ...]
    output_schema_sha256: str
    policy_sha256: str
    verification_rungs: tuple[str, ...]
    on_exhaustion: str
    fabricated_progress_allowed: bool
    route_set_id: str
    execution_authority: str = "withheld"
    schema_version: str = "jaa16.provider-route-set.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "capability": self.capability,
            "routes": tuple(row.document() for row in self.routes),
            "output_schema_sha256": self.output_schema_sha256,
            "policy_sha256": self.policy_sha256,
            "verification_rungs": self.verification_rungs,
            "on_exhaustion": "pause_affected_work",
            "fabricated_progress_allowed": False,
            "execution_authority": "withheld",
        }
        if include_identity:
            result["route_set_id"] = self.route_set_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "route-set contract hash"),
            (self.output_schema_sha256, "route-set schema hash"),
            (self.policy_sha256, "route-set policy hash"),
            (self.route_set_id, "route-set ID"),
        ):
            _digest(value, label)
        _required(self.capability, "route-set capability")
        if len(self.routes) < 2 or not all(
            isinstance(row, ProviderRoute) for row in self.routes
        ):
            raise ValueError("route set requires primary and fallback routes")
        for row in self.routes:
            row.verify()
        if tuple(row.priority for row in self.routes) != tuple(
            range(1, len(self.routes) + 1)
        ):
            raise ValueError("provider route priorities must be contiguous")
        if len({row.route_id for row in self.routes}) != len(self.routes):
            raise ValueError("provider route IDs must be unique")
        for row in self.routes:
            if (
                row.capability != self.capability
                or row.output_schema_sha256 != self.output_schema_sha256
                or row.policy_sha256 != self.policy_sha256
                or row.verification_rungs != self.verification_rungs
            ):
                raise ValueError(
                    "provider fallback changes schema, policy or verification"
                )
        if (
            self.contract_sha256 != FROZEN_OPERATIONS_CONTRACT.contract_sha256
            or self.on_exhaustion != "pause_affected_work"
            or self.fabricated_progress_allowed is not False
            or self.execution_authority != "withheld"
            or self.schema_version != "jaa16.provider-route-set.v1"
        ):
            raise ValueError("provider route set cannot fabricate or execute")
        if self.route_set_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("provider route-set identity is invalid")


def compile_provider_route_set(
    contract: OperationsContract,
    routes: tuple[ProviderRoute, ...],
) -> ProviderRouteSet:
    if contract != FROZEN_OPERATIONS_CONTRACT:
        raise ValueError("route set requires the canonical operations contract")
    if len(routes) < 2 or not all(
        isinstance(row, ProviderRoute) for row in routes
    ):
        raise ValueError("route set requires typed primary and fallback routes")
    ordered = tuple(sorted(routes, key=lambda row: row.priority))
    primary = ordered[0]
    body = {
        "schema_version": "jaa16.provider-route-set.v1",
        "contract_sha256": contract.contract_sha256,
        "capability": primary.capability,
        "routes": tuple(row.document() for row in ordered),
        "output_schema_sha256": primary.output_schema_sha256,
        "policy_sha256": primary.policy_sha256,
        "verification_rungs": primary.verification_rungs,
        "on_exhaustion": "pause_affected_work",
        "fabricated_progress_allowed": False,
        "execution_authority": "withheld",
    }
    return ProviderRouteSet(
        contract_sha256=contract.contract_sha256,
        capability=primary.capability,
        routes=ordered,
        output_schema_sha256=primary.output_schema_sha256,
        policy_sha256=primary.policy_sha256,
        verification_rungs=primary.verification_rungs,
        on_exhaustion="pause_affected_work",
        fabricated_progress_allowed=False,
        route_set_id=_content_hash(body),
    )


@dataclass(frozen=True)
class OperationsPlan:
    contract_sha256: str
    schedules: tuple[ScheduleDefinition, ...]
    provider_route_sets: tuple[ProviderRouteSet, ...]
    heartbeat_timeout_seconds: int
    queue_high_watermark: int
    queue_hard_stop: int
    resume_below: int
    daily_cost_budget_microusd: int
    daily_token_budget: int
    max_consequential_actions_per_run: int
    pause_resume_policy_sha256: str
    rollback_policy_sha256: str
    plan_id: str
    execution_authority: str = "withheld"
    deployment_authority: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa16.operations-plan.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "schedules": tuple(row.document() for row in self.schedules),
            "provider_route_sets": tuple(
                row.document() for row in self.provider_route_sets
            ),
            "heartbeat_timeout_seconds": self.heartbeat_timeout_seconds,
            "queue_high_watermark": self.queue_high_watermark,
            "queue_hard_stop": self.queue_hard_stop,
            "resume_below": self.resume_below,
            "daily_cost_budget_microusd": self.daily_cost_budget_microusd,
            "daily_token_budget": self.daily_token_budget,
            "max_consequential_actions_per_run": (
                self.max_consequential_actions_per_run
            ),
            "pause_resume_policy_sha256": self.pause_resume_policy_sha256,
            "rollback_policy_sha256": self.rollback_policy_sha256,
            "execution_authority": "withheld",
            "deployment_authority": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["plan_id"] = self.plan_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "operations plan contract hash"),
            (self.pause_resume_policy_sha256, "pause/resume policy hash"),
            (self.rollback_policy_sha256, "rollback policy hash"),
            (self.plan_id, "operations plan ID"),
        ):
            _digest(value, label)
        if not self.schedules or not all(
            isinstance(row, ScheduleDefinition) for row in self.schedules
        ):
            raise ValueError("operations plan requires typed schedules")
        if not self.provider_route_sets or not all(
            isinstance(row, ProviderRouteSet)
            for row in self.provider_route_sets
        ):
            raise ValueError("operations plan requires typed provider routes")
        for row in self.schedules:
            row.verify()
        for row in self.provider_route_sets:
            row.verify()
        if (
            len({row.schedule_id for row in self.schedules})
            != len(self.schedules)
            or len({row.capability for row in self.provider_route_sets})
            != len(self.provider_route_sets)
        ):
            raise ValueError("operations plan entries must be unique")
        for value, label in (
            (self.heartbeat_timeout_seconds, "heartbeat timeout"),
            (self.queue_high_watermark, "queue high watermark"),
            (self.queue_hard_stop, "queue hard stop"),
            (self.resume_below, "queue resume threshold"),
            (self.daily_cost_budget_microusd, "daily cost budget"),
            (self.daily_token_budget, "daily token budget"),
            (
                self.max_consequential_actions_per_run,
                "consequential-action budget",
            ),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{label} must be a non-negative integer")
        if (
            self.heartbeat_timeout_seconds < 60
            or not 0 <= self.resume_below < self.queue_high_watermark
            or self.queue_high_watermark >= self.queue_hard_stop
            or self.daily_cost_budget_microusd < 1
            or self.daily_token_budget < 1
        ):
            raise ValueError("operations thresholds are invalid")
        if (
            self.contract_sha256 != FROZEN_OPERATIONS_CONTRACT.contract_sha256
            or self.execution_authority != "withheld"
            or self.deployment_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version != "jaa16.operations-plan.v1"
        ):
            raise ValueError("operations plan cannot execute or certify")
        if self.plan_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("operations plan identity is invalid")


def compile_operations_plan(
    contract: OperationsContract,
    *,
    schedules: tuple[ScheduleDefinition, ...],
    provider_route_sets: tuple[ProviderRouteSet, ...],
    heartbeat_timeout_seconds: int,
    queue_high_watermark: int,
    queue_hard_stop: int,
    resume_below: int,
    daily_cost_budget_microusd: int,
    daily_token_budget: int,
    max_consequential_actions_per_run: int,
    pause_resume_policy_sha256: str,
    rollback_policy_sha256: str,
) -> OperationsPlan:
    if contract != FROZEN_OPERATIONS_CONTRACT:
        raise ValueError(
            "operations plan requires the canonical operations contract"
        )
    sorted_schedules = tuple(
        sorted(schedules, key=lambda row: row.schedule_name)
    )
    sorted_routes = tuple(
        sorted(provider_route_sets, key=lambda row: row.capability)
    )
    body = {
        "schema_version": "jaa16.operations-plan.v1",
        "contract_sha256": contract.contract_sha256,
        "schedules": tuple(row.document() for row in sorted_schedules),
        "provider_route_sets": tuple(
            row.document() for row in sorted_routes
        ),
        "heartbeat_timeout_seconds": heartbeat_timeout_seconds,
        "queue_high_watermark": queue_high_watermark,
        "queue_hard_stop": queue_hard_stop,
        "resume_below": resume_below,
        "daily_cost_budget_microusd": daily_cost_budget_microusd,
        "daily_token_budget": daily_token_budget,
        "max_consequential_actions_per_run": (
            max_consequential_actions_per_run
        ),
        "pause_resume_policy_sha256": pause_resume_policy_sha256,
        "rollback_policy_sha256": rollback_policy_sha256,
        "execution_authority": "withheld",
        "deployment_authority": "withheld",
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return OperationsPlan(
        contract_sha256=contract.contract_sha256,
        schedules=sorted_schedules,
        provider_route_sets=sorted_routes,
        heartbeat_timeout_seconds=heartbeat_timeout_seconds,
        queue_high_watermark=queue_high_watermark,
        queue_hard_stop=queue_hard_stop,
        resume_below=resume_below,
        daily_cost_budget_microusd=daily_cost_budget_microusd,
        daily_token_budget=daily_token_budget,
        max_consequential_actions_per_run=max_consequential_actions_per_run,
        pause_resume_policy_sha256=pause_resume_policy_sha256,
        rollback_policy_sha256=rollback_policy_sha256,
        plan_id=_content_hash(body),
    )


@dataclass(frozen=True)
class FailureDrillObservation:
    contract_sha256: str
    plan_id: str
    failure_kind: str
    input_snapshot_sha256: str
    ledger_before_sha256: str
    ledger_after_sha256: str
    checkpoint_sha256: str
    consequential_action_ids: tuple[str, ...]
    duplicate_consequential_actions: int
    lost_record_count: int
    affected_work_paused: bool
    resumed_from_checkpoint: bool
    fallback_schema_preserved: bool
    verification_rungs_preserved: bool
    fabricated_progress: bool
    observed_at: str
    drill_id: str
    runtime_evidence_verified: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa16.failure-drill-observation.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "plan_id": self.plan_id,
            "failure_kind": self.failure_kind,
            "input_snapshot_sha256": self.input_snapshot_sha256,
            "ledger_before_sha256": self.ledger_before_sha256,
            "ledger_after_sha256": self.ledger_after_sha256,
            "checkpoint_sha256": self.checkpoint_sha256,
            "consequential_action_ids": self.consequential_action_ids,
            "duplicate_consequential_actions": (
                self.duplicate_consequential_actions
            ),
            "lost_record_count": self.lost_record_count,
            "affected_work_paused": self.affected_work_paused,
            "resumed_from_checkpoint": self.resumed_from_checkpoint,
            "fallback_schema_preserved": self.fallback_schema_preserved,
            "verification_rungs_preserved": (
                self.verification_rungs_preserved
            ),
            "fabricated_progress": False,
            "observed_at": self.observed_at,
            "runtime_evidence_verified": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["drill_id"] = self.drill_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "drill contract hash"),
            (self.plan_id, "drill plan ID"),
            (self.input_snapshot_sha256, "drill input hash"),
            (self.ledger_before_sha256, "pre-drill ledger hash"),
            (self.ledger_after_sha256, "post-drill ledger hash"),
            (self.checkpoint_sha256, "drill checkpoint hash"),
            (self.drill_id, "failure drill ID"),
        ):
            _digest(value, label)
        if self.failure_kind not in FAILURE_KINDS:
            raise ValueError("failure drill kind is unsupported")
        _aware_iso(self.observed_at, "failure drill time")
        if (
            tuple(sorted(set(self.consequential_action_ids)))
            != self.consequential_action_ids
        ):
            raise ValueError(
                "consequential action IDs must be unique and sorted"
            )
        for value in self.consequential_action_ids:
            _digest(value, "consequential action ID")
        for value, label in (
            (
                self.duplicate_consequential_actions,
                "duplicate consequential actions",
            ),
            (self.lost_record_count, "lost record count"),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{label} must be non-negative")
        for value, label in (
            (self.affected_work_paused, "pause result"),
            (self.resumed_from_checkpoint, "checkpoint resume result"),
            (self.fallback_schema_preserved, "fallback schema result"),
            (
                self.verification_rungs_preserved,
                "verification-rung result",
            ),
            (self.fabricated_progress, "fabricated-progress result"),
        ):
            if type(value) is not bool:
                raise ValueError(f"{label} must be boolean")
        if (
            self.contract_sha256 != FROZEN_OPERATIONS_CONTRACT.contract_sha256
            or self.runtime_evidence_verified is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
            or self.fabricated_progress is not False
            or self.schema_version
            != "jaa16.failure-drill-observation.v1"
        ):
            raise ValueError("local failure drill cannot certify runtime")
        if self.drill_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("failure drill identity is invalid")


def record_failure_drill_observation(
    contract: OperationsContract,
    plan: OperationsPlan,
    *,
    failure_kind: str,
    input_snapshot_sha256: str,
    ledger_before_sha256: str,
    ledger_after_sha256: str,
    checkpoint_sha256: str,
    consequential_action_ids: tuple[str, ...],
    duplicate_consequential_actions: int,
    lost_record_count: int,
    affected_work_paused: bool,
    resumed_from_checkpoint: bool,
    fallback_schema_preserved: bool,
    verification_rungs_preserved: bool,
    fabricated_progress: bool,
    observed_at: datetime,
) -> FailureDrillObservation:
    if contract != FROZEN_OPERATIONS_CONTRACT:
        raise ValueError("drill requires the canonical operations contract")
    if not isinstance(plan, OperationsPlan):
        raise TypeError("drill requires a typed operations plan")
    plan.verify()
    observed = _aware(observed_at, "failure drill time")
    body = {
        "schema_version": "jaa16.failure-drill-observation.v1",
        "contract_sha256": contract.contract_sha256,
        "plan_id": plan.plan_id,
        "failure_kind": failure_kind,
        "input_snapshot_sha256": input_snapshot_sha256,
        "ledger_before_sha256": ledger_before_sha256,
        "ledger_after_sha256": ledger_after_sha256,
        "checkpoint_sha256": checkpoint_sha256,
        "consequential_action_ids": tuple(
            sorted(set(consequential_action_ids))
        ),
        "duplicate_consequential_actions": (
            duplicate_consequential_actions
        ),
        "lost_record_count": lost_record_count,
        "affected_work_paused": affected_work_paused,
        "resumed_from_checkpoint": resumed_from_checkpoint,
        "fallback_schema_preserved": fallback_schema_preserved,
        "verification_rungs_preserved": verification_rungs_preserved,
        "fabricated_progress": fabricated_progress,
        "observed_at": observed.isoformat(),
        "runtime_evidence_verified": False,
        "production_certification": "withheld",
        "certifies_slice": False,
    }
    return FailureDrillObservation(
        contract_sha256=contract.contract_sha256,
        plan_id=plan.plan_id,
        failure_kind=failure_kind,
        input_snapshot_sha256=input_snapshot_sha256,
        ledger_before_sha256=ledger_before_sha256,
        ledger_after_sha256=ledger_after_sha256,
        checkpoint_sha256=checkpoint_sha256,
        consequential_action_ids=tuple(
            sorted(set(consequential_action_ids))
        ),
        duplicate_consequential_actions=duplicate_consequential_actions,
        lost_record_count=lost_record_count,
        affected_work_paused=affected_work_paused,
        resumed_from_checkpoint=resumed_from_checkpoint,
        fallback_schema_preserved=fallback_schema_preserved,
        verification_rungs_preserved=verification_rungs_preserved,
        fabricated_progress=fabricated_progress,
        observed_at=observed.isoformat(),
        drill_id=_content_hash(body),
    )


DRILL_REASON_ORDER = (
    "missing_failure_drill",
    "duplicate_consequential_action",
    "data_loss",
    "affected_work_not_paused",
    "checkpoint_not_resumed",
    "fallback_schema_changed",
    "verification_rung_skipped",
    "fabricated_progress",
)


@dataclass(frozen=True)
class DrillSuiteAssessment:
    contract_sha256: str
    plan_id: str
    drill_ids: tuple[str, ...]
    failure_kinds: tuple[str, ...]
    reason_codes: tuple[str, ...]
    eligible_for_independent_runtime_review: bool
    runtime_evidence_verified: bool
    assessment_id: str
    production_certification: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa16.drill-suite-assessment.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "plan_id": self.plan_id,
            "drill_ids": self.drill_ids,
            "failure_kinds": self.failure_kinds,
            "reason_codes": self.reason_codes,
            "eligible_for_independent_runtime_review": (
                self.eligible_for_independent_runtime_review
            ),
            "runtime_evidence_verified": False,
            "production_certification": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["assessment_id"] = self.assessment_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "drill assessment contract hash"),
            (self.plan_id, "drill assessment plan ID"),
            (self.assessment_id, "drill suite assessment ID"),
        ):
            _digest(value, label)
        if (
            not self.drill_ids
            or len(self.drill_ids) != len(set(self.drill_ids))
        ):
            raise ValueError("drill assessment IDs must be unique")
        for value in self.drill_ids:
            _digest(value, "assessed drill ID")
        if tuple(sorted(set(self.failure_kinds))) != self.failure_kinds:
            raise ValueError("assessed failure kinds must be unique and sorted")
        expected_reasons = tuple(
            reason for reason in DRILL_REASON_ORDER
            if reason in self.reason_codes
        )
        if expected_reasons != self.reason_codes:
            raise ValueError("drill assessment reasons are invalid")
        if (
            type(self.eligible_for_independent_runtime_review) is not bool
            or self.eligible_for_independent_runtime_review
            is not (not self.reason_codes)
            or self.runtime_evidence_verified is not False
        ):
            raise ValueError("drill assessment eligibility is invalid")
        if (
            self.contract_sha256 != FROZEN_OPERATIONS_CONTRACT.contract_sha256
            or self.production_certification != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version != "jaa16.drill-suite-assessment.v1"
        ):
            raise ValueError("drill assessment cannot certify runtime")
        if self.assessment_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("drill assessment identity is invalid")


def evaluate_failure_drills(
    contract: OperationsContract,
    plan: OperationsPlan,
    drills: tuple[FailureDrillObservation, ...],
) -> DrillSuiteAssessment:
    if contract != FROZEN_OPERATIONS_CONTRACT:
        raise ValueError(
            "drill assessment requires the canonical operations contract"
        )
    if not isinstance(plan, OperationsPlan):
        raise TypeError("drill assessment requires a typed operations plan")
    if not all(isinstance(row, FailureDrillObservation) for row in drills):
        raise TypeError("drill assessment requires typed drills")
    plan.verify()
    for row in drills:
        row.verify()
        if row.plan_id != plan.plan_id:
            raise ValueError("drill suite mixes operations plans")
    if len({row.drill_id for row in drills}) != len(drills):
        raise ValueError("drill suite cannot duplicate observations")
    kinds = {row.failure_kind for row in drills}
    reasons: list[str] = []
    if kinds != set(FAILURE_KINDS):
        reasons.append("missing_failure_drill")
    if any(row.duplicate_consequential_actions for row in drills):
        reasons.append("duplicate_consequential_action")
    if any(row.lost_record_count for row in drills):
        reasons.append("data_loss")
    if any(
        row.failure_kind in PAUSE_FAILURE_KINDS
        and not row.affected_work_paused
        for row in drills
    ):
        reasons.append("affected_work_not_paused")
    if any(
        row.failure_kind in CHECKPOINT_FAILURE_KINDS
        and not row.resumed_from_checkpoint
        for row in drills
    ):
        reasons.append("checkpoint_not_resumed")
    if any(
        row.failure_kind in PROVIDER_FAILURE_KINDS
        and not row.fallback_schema_preserved
        for row in drills
    ):
        reasons.append("fallback_schema_changed")
    if any(not row.verification_rungs_preserved for row in drills):
        reasons.append("verification_rung_skipped")
    if any(row.fabricated_progress for row in drills):
        reasons.append("fabricated_progress")
    reason_codes = tuple(
        reason for reason in DRILL_REASON_ORDER if reason in reasons
    )
    ordered = tuple(sorted(drills, key=lambda row: row.failure_kind))
    body = {
        "schema_version": "jaa16.drill-suite-assessment.v1",
        "contract_sha256": contract.contract_sha256,
        "plan_id": plan.plan_id,
        "drill_ids": tuple(row.drill_id for row in ordered),
        "failure_kinds": tuple(sorted(kinds)),
        "reason_codes": reason_codes,
        "eligible_for_independent_runtime_review": not reason_codes,
        "runtime_evidence_verified": False,
        "production_certification": "withheld",
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return DrillSuiteAssessment(
        contract_sha256=contract.contract_sha256,
        plan_id=plan.plan_id,
        drill_ids=tuple(row.drill_id for row in ordered),
        failure_kinds=tuple(sorted(kinds)),
        reason_codes=reason_codes,
        eligible_for_independent_runtime_review=not reason_codes,
        runtime_evidence_verified=False,
        assessment_id=_content_hash(body),
    )


@dataclass(frozen=True)
class OperationAlert:
    contract_sha256: str
    signal_kind: str
    affected_work_id: str
    evidence_sha256: str
    observed_at: str
    classification: str
    alert_id: str
    send_authority: str = "withheld"
    schema_version: str = "jaa16.operation-alert.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "signal_kind": self.signal_kind,
            "affected_work_id": self.affected_work_id,
            "evidence_sha256": self.evidence_sha256,
            "observed_at": self.observed_at,
            "classification": self.classification,
            "send_authority": "withheld",
        }
        if include_identity:
            result["alert_id"] = self.alert_id
        return result

    def verify(self) -> None:
        _digest(self.contract_sha256, "alert contract hash")
        _digest(self.evidence_sha256, "alert evidence hash")
        _digest(self.alert_id, "operation alert ID")
        _required(self.affected_work_id, "affected work ID")
        if self.signal_kind not in ALERT_SIGNAL_KINDS:
            raise ValueError("alert signal kind is unsupported")
        expected = _alert_classification(self.signal_kind)
        if self.classification != expected:
            raise ValueError("alert classification differs from policy")
        _aware_iso(self.observed_at, "alert time")
        if (
            self.contract_sha256 != FROZEN_OPERATIONS_CONTRACT.contract_sha256
            or self.send_authority != "withheld"
            or self.schema_version != "jaa16.operation-alert.v1"
        ):
            raise ValueError("local alert cannot be sent")
        if self.alert_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("operation alert identity is invalid")


def _alert_classification(signal_kind: str) -> str:
    if signal_kind in WEATHER_SIGNALS:
        return "weather"
    if signal_kind in BLOCKED_WORK_SIGNALS:
        return "blocked_work"
    if signal_kind in PRODUCT_DEFECT_SIGNALS:
        return "product_defect"
    raise ValueError("alert signal kind is unsupported")


def classify_operation_alert(
    contract: OperationsContract,
    *,
    signal_kind: str,
    affected_work_id: str,
    evidence_sha256: str,
    observed_at: datetime,
) -> OperationAlert:
    if contract != FROZEN_OPERATIONS_CONTRACT:
        raise ValueError("alert requires the canonical operations contract")
    observed = _aware(observed_at, "alert time")
    classification = _alert_classification(signal_kind)
    body = {
        "schema_version": "jaa16.operation-alert.v1",
        "contract_sha256": contract.contract_sha256,
        "signal_kind": signal_kind,
        "affected_work_id": affected_work_id,
        "evidence_sha256": evidence_sha256,
        "observed_at": observed.isoformat(),
        "classification": classification,
        "send_authority": "withheld",
    }
    return OperationAlert(**body, alert_id=_content_hash(body))


@dataclass(frozen=True)
class OperationalReport:
    contract_sha256: str
    plan_id: str
    report_kind: str
    period_start: str
    period_end: str
    event_ledger_sha256: str
    operation_count: int
    succeeded_count: int
    failed_count: int
    blocked_count: int
    cost_microusd: int
    alert_ids: tuple[str, ...]
    report_id: str
    report_status: str = "local_draft"
    send_authority: str = "withheld"
    production_certification: str = "withheld"
    schema_version: str = "jaa16.operational-report.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "plan_id": self.plan_id,
            "report_kind": self.report_kind,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "event_ledger_sha256": self.event_ledger_sha256,
            "operation_count": self.operation_count,
            "succeeded_count": self.succeeded_count,
            "failed_count": self.failed_count,
            "blocked_count": self.blocked_count,
            "cost_microusd": self.cost_microusd,
            "alert_ids": self.alert_ids,
            "report_status": "local_draft",
            "send_authority": "withheld",
            "production_certification": "withheld",
        }
        if include_identity:
            result["report_id"] = self.report_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "report contract hash"),
            (self.plan_id, "report plan ID"),
            (self.event_ledger_sha256, "report ledger hash"),
            (self.report_id, "operational report ID"),
        ):
            _digest(value, label)
        if self.report_kind not in REPORT_KINDS:
            raise ValueError("operational report kind is unsupported")
        start = _aware_iso(self.period_start, "report period start")
        end = _aware_iso(self.period_end, "report period end")
        if start >= end:
            raise ValueError("report period must be ordered")
        for value, label in (
            (self.operation_count, "operation count"),
            (self.succeeded_count, "success count"),
            (self.failed_count, "failure count"),
            (self.blocked_count, "blocked count"),
            (self.cost_microusd, "report cost"),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{label} must be non-negative")
        if (
            self.succeeded_count + self.failed_count + self.blocked_count
            != self.operation_count
        ):
            raise ValueError("report counts do not reconcile")
        if tuple(sorted(set(self.alert_ids))) != self.alert_ids:
            raise ValueError("report alert IDs must be unique and sorted")
        for value in self.alert_ids:
            _digest(value, "report alert ID")
        if (
            self.contract_sha256 != FROZEN_OPERATIONS_CONTRACT.contract_sha256
            or self.report_status != "local_draft"
            or self.send_authority != "withheld"
            or self.production_certification != "withheld"
            or self.schema_version != "jaa16.operational-report.v1"
        ):
            raise ValueError("local report cannot send or certify")
        if self.report_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("operational report identity is invalid")


def compile_operational_report(
    contract: OperationsContract,
    plan: OperationsPlan,
    *,
    report_kind: str,
    period_start: datetime,
    period_end: datetime,
    event_ledger_sha256: str,
    operation_count: int,
    succeeded_count: int,
    failed_count: int,
    blocked_count: int,
    cost_microusd: int,
    alerts: tuple[OperationAlert, ...],
) -> OperationalReport:
    if contract != FROZEN_OPERATIONS_CONTRACT:
        raise ValueError("report requires the canonical operations contract")
    if not isinstance(plan, OperationsPlan):
        raise TypeError("report requires a typed operations plan")
    if not all(isinstance(row, OperationAlert) for row in alerts):
        raise TypeError("report requires typed operation alerts")
    plan.verify()
    for row in alerts:
        row.verify()
    start = _aware(period_start, "report period start")
    end = _aware(period_end, "report period end")
    alert_ids = tuple(sorted({row.alert_id for row in alerts}))
    body = {
        "schema_version": "jaa16.operational-report.v1",
        "contract_sha256": contract.contract_sha256,
        "plan_id": plan.plan_id,
        "report_kind": report_kind,
        "period_start": start.isoformat(),
        "period_end": end.isoformat(),
        "event_ledger_sha256": event_ledger_sha256,
        "operation_count": operation_count,
        "succeeded_count": succeeded_count,
        "failed_count": failed_count,
        "blocked_count": blocked_count,
        "cost_microusd": cost_microusd,
        "alert_ids": alert_ids,
        "report_status": "local_draft",
        "send_authority": "withheld",
        "production_certification": "withheld",
    }
    return OperationalReport(**body, report_id=_content_hash(body))
