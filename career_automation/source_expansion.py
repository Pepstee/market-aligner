"""Pure-data ranking and gate contracts for bounded JAA-15 preparation.

This module does not fetch, crawl, render, activate an adapter, or certify
runtime behavior. It evaluates content-addressed caller-supplied records and
keeps every activation and external-action authority withheld.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping

from career_automation.official_ats_adapter import (
    FROZEN_FIXTURE_ADAPTER_CONTRACT,
)
from career_automation.models import PipelineState
from career_automation.opportunity_calibration import CalibrationPolicy
from career_automation.outcome_feedback import (
    FROZEN_OUTCOME_FEEDBACK_CONTRACT,
    PredictionReceipt,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
PREFIXED_HEX_64 = re.compile(r"^sha256:[0-9a-f]{64}$")
CAPABILITY_KINDS = ("source", "ats_route", "source_and_route")
ROUTE_STATUSES = ("supported", "unsupported")
EVIDENCE_KINDS = (
    "fixture_runtime",
    "independent_test",
    "real_runtime",
)
REQUIRED_EVIDENCE_KINDS = frozenset(EVIDENCE_KINDS)
QUALITY_PHASES = ("baseline", "candidate")
HARD_QUALITY_FIELDS = (
    "unsupported_release_claims",
    "ineligible_routes",
    "confirmed_without_receipt",
    "receipt_integrity_violations",
    "replay_mismatches",
)
REASON_ORDER = (
    "unsupported_route",
    "non_positive_incremental_value",
    "missing_fixture_runtime_evidence",
    "missing_independent_test_evidence",
    "missing_real_runtime_evidence",
    "source_freshness_regression",
    "baseline_hard_quality_not_clean",
    "candidate_hard_quality_regression",
)
SCRAPLING_REQUIREMENTS_SHA256 = (
    "bccc6c760d37c8467173d198efe26bbbb0566584fdeefd98079b483bbd903cd6"
)
SCRAPER_ADAPTER_INTERFACE_SHA256 = (
    "d9601bd5de253d267476cde24a138ebd639a40ed61fff9e37922f14015469294"
)
SCRAPER_COLLECTOR_SHA256 = (
    "245674e67d523c9edb3188ac82cd816ca4bbc16f28ca748c48620a182f172ea9"
)
SCRAPLING_CLIENT_SHA256 = (
    "84a13210768cdcc10ec7df4097a703a462579e2393a281bd119edf077f9e408a"
)
VIABILITY_POLICY_SOURCE_SHA256 = (
    "23833e0eceb619e1dc937be853c21bca61c2652610b2da2fd312ea638ff94c37"
)
COUNTRY_POLICY_SOURCE_SHA256 = (
    "96a5ee1422ba76437ac28fc0bd847809fab67914719a7d0ff82f1377ffd61837"
)
UK_POLICY_SOURCE_SHA256 = (
    "c653f446b5ad0a1b067ba27a628e59e504c3e610a3b12f21e9e64ab624f31fb6"
)
RANKING_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa15.expansion-ranking-policy.v1",
    "value_formula": (
        "worthwhile_vacancies*10000+expected_interviews_bp"
        "-implementation_cost_points*100"
        "-operational_friction_points*100"
    ),
    "integer_arithmetic": True,
    "ranking_order": (
        "eligible_first",
        "value_score_descending",
        "adapter_id_ascending",
        "adapter_version_ascending",
    ),
    "blocked_candidates_visible": True,
})
QUALITY_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa15.expansion-quality-policy.v1",
    "freshness_pass_rate_non_regression": True,
    "hard_quality_fields": HARD_QUALITY_FIELDS,
    "hard_quality_required_value": 0,
    "adapter_specific_evidence": True,
    "independent_fixture_and_real_runtime_evidence": True,
    "versioned_workflow_and_rollback": True,
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


RANKING_POLICY_SHA256 = _content_hash(dict(RANKING_POLICY))
QUALITY_POLICY_SHA256 = _content_hash(dict(QUALITY_POLICY))


@dataclass(frozen=True)
class SourceExpansionContract:
    upstream_outcome_contract_sha256: str
    upstream_fixture_adapter_contract_sha256: str
    opportunity_policy_sha256: str
    scrapling_requirements_sha256: str
    scraper_adapter_interface_sha256: str
    scraper_collector_sha256: str
    scrapling_client_sha256: str
    viability_policy_source_sha256: str
    country_policy_source_sha256: str
    uk_policy_source_sha256: str
    ranking_policy_sha256: str
    quality_policy_sha256: str
    crawl_authority: str = "withheld"
    adapter_activation_authority: str = "withheld"
    connector_authority: str = "withheld"
    submission_authority: str = "withheld"
    production_certification: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa15.local-source-expansion-contract.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (
                self.upstream_outcome_contract_sha256,
                "outcome contract hash",
            ),
            (
                self.upstream_fixture_adapter_contract_sha256,
                "fixture adapter contract hash",
            ),
            (self.scrapling_requirements_sha256, "Scrapling lock hash"),
            (
                self.scraper_adapter_interface_sha256,
                "adapter interface hash",
            ),
            (self.scraper_collector_sha256, "collector hash"),
            (self.scrapling_client_sha256, "Scrapling client hash"),
            (
                self.viability_policy_source_sha256,
                "viability source hash",
            ),
            (self.country_policy_source_sha256, "country policy hash"),
            (self.uk_policy_source_sha256, "UK policy hash"),
            (self.ranking_policy_sha256, "ranking policy hash"),
            (self.quality_policy_sha256, "quality policy hash"),
        ):
            _digest(value, label)
        _prefixed_digest(
            self.opportunity_policy_sha256,
            "opportunity policy hash",
        )
        expected = (
            FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256,
            FROZEN_FIXTURE_ADAPTER_CONTRACT.contract_sha256,
            CalibrationPolicy().policy_hash,
            SCRAPLING_REQUIREMENTS_SHA256,
            SCRAPER_ADAPTER_INTERFACE_SHA256,
            SCRAPER_COLLECTOR_SHA256,
            SCRAPLING_CLIENT_SHA256,
            VIABILITY_POLICY_SOURCE_SHA256,
            COUNTRY_POLICY_SOURCE_SHA256,
            UK_POLICY_SOURCE_SHA256,
            RANKING_POLICY_SHA256,
            QUALITY_POLICY_SHA256,
        )
        actual = (
            self.upstream_outcome_contract_sha256,
            self.upstream_fixture_adapter_contract_sha256,
            self.opportunity_policy_sha256,
            self.scrapling_requirements_sha256,
            self.scraper_adapter_interface_sha256,
            self.scraper_collector_sha256,
            self.scrapling_client_sha256,
            self.viability_policy_source_sha256,
            self.country_policy_source_sha256,
            self.uk_policy_source_sha256,
            self.ranking_policy_sha256,
            self.quality_policy_sha256,
        )
        if actual != expected:
            raise ValueError(
                "source expansion contract differs from accepted inputs"
            )
        if (
            self.crawl_authority != "withheld"
            or self.adapter_activation_authority != "withheld"
            or self.connector_authority != "withheld"
            or self.submission_authority != "withheld"
            or self.production_certification != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version
            != "jaa15.local-source-expansion-contract.v1"
        ):
            raise ValueError(
                "local source expansion contract cannot activate or certify"
            )

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "upstream_outcome_contract_sha256": (
                self.upstream_outcome_contract_sha256
            ),
            "upstream_fixture_adapter_contract_sha256": (
                self.upstream_fixture_adapter_contract_sha256
            ),
            "opportunity_policy_sha256": self.opportunity_policy_sha256,
            "scrapling_requirements_sha256": (
                self.scrapling_requirements_sha256
            ),
            "scraper_adapter_interface_sha256": (
                self.scraper_adapter_interface_sha256
            ),
            "scraper_collector_sha256": self.scraper_collector_sha256,
            "scrapling_client_sha256": self.scrapling_client_sha256,
            "viability_policy_source_sha256": (
                self.viability_policy_source_sha256
            ),
            "country_policy_source_sha256": (
                self.country_policy_source_sha256
            ),
            "uk_policy_source_sha256": self.uk_policy_source_sha256,
            "ranking_policy_sha256": self.ranking_policy_sha256,
            "quality_policy_sha256": self.quality_policy_sha256,
            "crawl_authority": "withheld",
            "adapter_activation_authority": "withheld",
            "connector_authority": "withheld",
            "submission_authority": "withheld",
            "production_certification": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_SOURCE_EXPANSION_CONTRACT = SourceExpansionContract(
    upstream_outcome_contract_sha256=(
        FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256
    ),
    upstream_fixture_adapter_contract_sha256=(
        FROZEN_FIXTURE_ADAPTER_CONTRACT.contract_sha256
    ),
    opportunity_policy_sha256=CalibrationPolicy().policy_hash,
    scrapling_requirements_sha256=SCRAPLING_REQUIREMENTS_SHA256,
    scraper_adapter_interface_sha256=SCRAPER_ADAPTER_INTERFACE_SHA256,
    scraper_collector_sha256=SCRAPER_COLLECTOR_SHA256,
    scrapling_client_sha256=SCRAPLING_CLIENT_SHA256,
    viability_policy_source_sha256=VIABILITY_POLICY_SOURCE_SHA256,
    country_policy_source_sha256=COUNTRY_POLICY_SOURCE_SHA256,
    uk_policy_source_sha256=UK_POLICY_SOURCE_SHA256,
    ranking_policy_sha256=RANKING_POLICY_SHA256,
    quality_policy_sha256=QUALITY_POLICY_SHA256,
)


@dataclass(frozen=True)
class AdapterCandidate:
    contract_sha256: str
    adapter_id: str
    adapter_version: str
    capability_kind: str
    route_status: str
    workflow_sha256: str
    extraction_policy_sha256: str
    selector_policy_sha256: str
    route_policy_sha256: str
    eligibility_policy_sha256: str
    payroll_policy_sha256: str
    rollback_adapter_version: str
    country_scopes: tuple[str, ...]
    employer_scopes: tuple[str, ...]
    candidate_id: str
    crawl_authority: str = "withheld"
    activation_authority: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa15.adapter-candidate.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "capability_kind": self.capability_kind,
            "route_status": self.route_status,
            "workflow_sha256": self.workflow_sha256,
            "extraction_policy_sha256": self.extraction_policy_sha256,
            "selector_policy_sha256": self.selector_policy_sha256,
            "route_policy_sha256": self.route_policy_sha256,
            "eligibility_policy_sha256": self.eligibility_policy_sha256,
            "payroll_policy_sha256": self.payroll_policy_sha256,
            "rollback_adapter_version": self.rollback_adapter_version,
            "country_scopes": self.country_scopes,
            "employer_scopes": self.employer_scopes,
            "crawl_authority": "withheld",
            "activation_authority": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["candidate_id"] = self.candidate_id
        return result

    def verify(self) -> None:
        _digest(self.contract_sha256, "candidate contract hash")
        for value, label in (
            (self.adapter_id, "adapter ID"),
            (self.adapter_version, "adapter version"),
            (self.rollback_adapter_version, "rollback adapter version"),
        ):
            _required(value, label)
        if self.adapter_version == self.rollback_adapter_version:
            raise ValueError("candidate rollback must name a different version")
        if self.capability_kind not in CAPABILITY_KINDS:
            raise ValueError("candidate capability kind is unsupported")
        if self.route_status not in ROUTE_STATUSES:
            raise ValueError("candidate route status is unsupported")
        for value, label in (
            (self.workflow_sha256, "candidate workflow hash"),
            (self.extraction_policy_sha256, "extraction policy hash"),
            (self.selector_policy_sha256, "selector policy hash"),
            (self.route_policy_sha256, "route policy hash"),
            (self.eligibility_policy_sha256, "eligibility policy hash"),
            (self.payroll_policy_sha256, "payroll policy hash"),
            (self.candidate_id, "candidate ID"),
        ):
            _digest(value, label)
        for values, label in (
            (self.country_scopes, "country scopes"),
            (self.employer_scopes, "employer scopes"),
        ):
            if not values or tuple(sorted(set(values))) != values:
                raise ValueError(
                    f"{label} must be non-empty, unique and sorted"
                )
            for value in values:
                _required(value, label)
        if (
            self.contract_sha256
            != FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
            or self.crawl_authority != "withheld"
            or self.activation_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version != "jaa15.adapter-candidate.v1"
        ):
            raise ValueError("adapter candidate cannot crawl or activate")
        if self.candidate_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("adapter candidate identity is invalid")


def compile_adapter_candidate(
    contract: SourceExpansionContract,
    *,
    adapter_id: str,
    adapter_version: str,
    capability_kind: str,
    route_status: str,
    workflow_sha256: str,
    extraction_policy_sha256: str,
    selector_policy_sha256: str,
    route_policy_sha256: str,
    eligibility_policy_sha256: str,
    payroll_policy_sha256: str,
    rollback_adapter_version: str,
    country_scopes: tuple[str, ...],
    employer_scopes: tuple[str, ...],
) -> AdapterCandidate:
    if contract != FROZEN_SOURCE_EXPANSION_CONTRACT:
        raise ValueError("candidate requires the canonical expansion contract")
    body = {
        "schema_version": "jaa15.adapter-candidate.v1",
        "contract_sha256": contract.contract_sha256,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "capability_kind": capability_kind,
        "route_status": route_status,
        "workflow_sha256": workflow_sha256,
        "extraction_policy_sha256": extraction_policy_sha256,
        "selector_policy_sha256": selector_policy_sha256,
        "route_policy_sha256": route_policy_sha256,
        "eligibility_policy_sha256": eligibility_policy_sha256,
        "payroll_policy_sha256": payroll_policy_sha256,
        "rollback_adapter_version": rollback_adapter_version,
        "country_scopes": tuple(sorted(set(country_scopes))),
        "employer_scopes": tuple(sorted(set(employer_scopes))),
        "crawl_authority": "withheld",
        "activation_authority": "withheld",
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return AdapterCandidate(
        **body,
        candidate_id=_content_hash(body),
    )


@dataclass(frozen=True)
class AdapterValueObservation:
    contract_sha256: str
    candidate_id: str
    adapter_id: str
    adapter_version: str
    job_key: str
    application_id: str
    source_snapshot_sha256: str
    viability_receipt_sha256: str
    prediction_id: str
    prediction_policy_sha256: str
    prediction_cohort_id: str
    prediction_cohort_kind: str
    prediction_target_state: str
    predicted_at: str
    expected_interview_bp: int
    worthwhile_vacancy: bool
    measurement_window_start: str
    measurement_window_end: str
    observation_id: str
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa15.adapter-value-observation.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "candidate_id": self.candidate_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "job_key": self.job_key,
            "application_id": self.application_id,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "viability_receipt_sha256": self.viability_receipt_sha256,
            "prediction_id": self.prediction_id,
            "prediction_policy_sha256": self.prediction_policy_sha256,
            "prediction_cohort_id": self.prediction_cohort_id,
            "prediction_cohort_kind": self.prediction_cohort_kind,
            "prediction_target_state": self.prediction_target_state,
            "predicted_at": self.predicted_at,
            "expected_interview_bp": self.expected_interview_bp,
            "worthwhile_vacancy": self.worthwhile_vacancy,
            "measurement_window_start": self.measurement_window_start,
            "measurement_window_end": self.measurement_window_end,
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["observation_id"] = self.observation_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "observation contract hash"),
            (self.candidate_id, "observation candidate ID"),
            (self.source_snapshot_sha256, "source snapshot hash"),
            (self.viability_receipt_sha256, "viability receipt hash"),
            (self.prediction_id, "observation prediction ID"),
            (self.prediction_policy_sha256, "prediction policy hash"),
            (self.observation_id, "value observation ID"),
        ):
            _digest(value, label)
        for value, label in (
            (self.adapter_id, "observation adapter ID"),
            (self.adapter_version, "observation adapter version"),
            (self.job_key, "observation job key"),
            (self.application_id, "observation application ID"),
            (self.prediction_cohort_id, "prediction cohort ID"),
        ):
            _required(value, label)
        if self.prediction_cohort_kind not in {"locked", "holdout", "live"}:
            raise ValueError("prediction cohort kind is unsupported")
        if self.prediction_target_state != PipelineState.INTERVIEW.value:
            raise ValueError(
                "expansion value requires an interview-target prediction"
            )
        start = _aware_iso(
            self.measurement_window_start,
            "measurement window start",
        )
        end = _aware_iso(
            self.measurement_window_end,
            "measurement window end",
        )
        predicted = _aware_iso(self.predicted_at, "observation prediction time")
        if start >= end or not start <= predicted < end:
            raise ValueError(
                "prediction must fall inside the measurement window"
            )
        if (
            type(self.expected_interview_bp) is not int
            or not 0 <= self.expected_interview_bp <= 10_000
            or type(self.worthwhile_vacancy) is not bool
        ):
            raise ValueError("observation value fields are invalid")
        if (
            self.contract_sha256
            != FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version
            != "jaa15.adapter-value-observation.v1"
        ):
            raise ValueError("value observation cannot certify expansion")
        if self.observation_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("value observation identity is invalid")


def record_adapter_value_observation(
    contract: SourceExpansionContract,
    candidate: AdapterCandidate,
    prediction: PredictionReceipt,
    *,
    source_snapshot_sha256: str,
    viability_receipt_sha256: str,
    worthwhile_vacancy: bool,
    measurement_window_start: datetime,
    measurement_window_end: datetime,
) -> AdapterValueObservation:
    if contract != FROZEN_SOURCE_EXPANSION_CONTRACT:
        raise ValueError(
            "value observation requires the canonical expansion contract"
        )
    if not isinstance(candidate, AdapterCandidate):
        raise TypeError("value observation requires a typed adapter candidate")
    if not isinstance(prediction, PredictionReceipt):
        raise TypeError("value observation requires a typed prediction")
    candidate.verify()
    prediction.verify()
    if prediction.target_state is not PipelineState.INTERVIEW:
        raise ValueError(
            "expansion value requires an interview-target prediction"
        )
    start = _aware(measurement_window_start, "measurement window start")
    end = _aware(measurement_window_end, "measurement window end")
    predicted = datetime.fromisoformat(prediction.predicted_at)
    if start >= end or not start <= predicted < end:
        raise ValueError("prediction must fall inside the measurement window")
    body = {
        "schema_version": "jaa15.adapter-value-observation.v1",
        "contract_sha256": contract.contract_sha256,
        "candidate_id": candidate.candidate_id,
        "adapter_id": candidate.adapter_id,
        "adapter_version": candidate.adapter_version,
        "job_key": prediction.job_key,
        "application_id": prediction.application_id,
        "source_snapshot_sha256": source_snapshot_sha256,
        "viability_receipt_sha256": viability_receipt_sha256,
        "prediction_id": prediction.prediction_id,
        "prediction_policy_sha256": prediction.predictor_policy_sha256,
        "prediction_cohort_id": prediction.cohort_id,
        "prediction_cohort_kind": prediction.cohort_kind,
        "prediction_target_state": prediction.target_state.value,
        "predicted_at": prediction.predicted_at,
        "expected_interview_bp": prediction.probability_bp,
        "worthwhile_vacancy": worthwhile_vacancy,
        "measurement_window_start": start.isoformat(),
        "measurement_window_end": end.isoformat(),
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return AdapterValueObservation(
        **body,
        observation_id=_content_hash(body),
    )


@dataclass(frozen=True)
class AdapterMeasurement:
    contract_sha256: str
    candidate_id: str
    adapter_id: str
    adapter_version: str
    cohort_id: str
    measurement_window_start: str
    measurement_window_end: str
    observation_ids: tuple[str, ...]
    job_keys: tuple[str, ...]
    sample_count: int
    worthwhile_vacancies: int
    expected_interviews_bp: int
    implementation_cost_points: int
    operational_friction_points: int
    value_score: int
    measurement_id: str
    activation_authority: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa15.adapter-measurement.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "candidate_id": self.candidate_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "cohort_id": self.cohort_id,
            "measurement_window_start": self.measurement_window_start,
            "measurement_window_end": self.measurement_window_end,
            "observation_ids": self.observation_ids,
            "job_keys": self.job_keys,
            "sample_count": self.sample_count,
            "worthwhile_vacancies": self.worthwhile_vacancies,
            "expected_interviews_bp": self.expected_interviews_bp,
            "implementation_cost_points": self.implementation_cost_points,
            "operational_friction_points": (
                self.operational_friction_points
            ),
            "value_score": self.value_score,
            "activation_authority": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["measurement_id"] = self.measurement_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "measurement contract hash"),
            (self.candidate_id, "measurement candidate ID"),
            (self.measurement_id, "measurement ID"),
        ):
            _digest(value, label)
        for value, label in (
            (self.adapter_id, "measurement adapter ID"),
            (self.adapter_version, "measurement adapter version"),
            (self.cohort_id, "measurement cohort ID"),
        ):
            _required(value, label)
        start = _aware_iso(
            self.measurement_window_start,
            "measurement window start",
        )
        end = _aware_iso(
            self.measurement_window_end,
            "measurement window end",
        )
        if start >= end:
            raise ValueError("measurement window must be ordered")
        if (
            not self.observation_ids
            or len(self.observation_ids) != len(set(self.observation_ids))
            or len(self.job_keys) != len(set(self.job_keys))
            or len(self.observation_ids) != len(self.job_keys)
        ):
            raise ValueError(
                "measurement observations and jobs must be non-empty and unique"
            )
        for value in self.observation_ids:
            _digest(value, "measurement observation ID")
        for value in self.job_keys:
            _required(value, "measurement job key")
        for value, label in (
            (self.sample_count, "measurement sample count"),
            (self.worthwhile_vacancies, "worthwhile vacancy count"),
            (self.expected_interviews_bp, "expected interviews"),
            (self.implementation_cost_points, "implementation cost"),
            (self.operational_friction_points, "operational friction"),
            (self.value_score, "measurement value score"),
        ):
            if type(value) is not int:
                raise ValueError(f"{label} must be an integer")
        if (
            self.sample_count != len(self.observation_ids)
            or not 0 <= self.worthwhile_vacancies <= self.sample_count
            or not 0
            <= self.expected_interviews_bp
            <= self.worthwhile_vacancies * 10_000
            or not 0 <= self.implementation_cost_points <= 10_000
            or not 0 <= self.operational_friction_points <= 10_000
        ):
            raise ValueError("measurement aggregate is invalid")
        expected_score = (
            self.worthwhile_vacancies * 10_000
            + self.expected_interviews_bp
            - self.implementation_cost_points * 100
            - self.operational_friction_points * 100
        )
        if self.value_score != expected_score:
            raise ValueError("measurement score differs from ranking policy")
        if (
            self.contract_sha256
            != FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
            or self.activation_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version != "jaa15.adapter-measurement.v1"
        ):
            raise ValueError("measurement cannot activate or certify")
        if self.measurement_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("measurement identity is invalid")


def compile_adapter_measurement(
    contract: SourceExpansionContract,
    candidate: AdapterCandidate,
    observations: tuple[AdapterValueObservation, ...],
    *,
    cohort_id: str,
    implementation_cost_points: int,
    operational_friction_points: int,
) -> AdapterMeasurement:
    if contract != FROZEN_SOURCE_EXPANSION_CONTRACT:
        raise ValueError(
            "measurement requires the canonical expansion contract"
        )
    if not isinstance(candidate, AdapterCandidate):
        raise TypeError("measurement requires a typed adapter candidate")
    if not observations or not all(
        isinstance(row, AdapterValueObservation) for row in observations
    ):
        raise TypeError("measurement requires typed value observations")
    candidate.verify()
    for row in observations:
        row.verify()
        if (
            row.candidate_id != candidate.candidate_id
            or row.adapter_id != candidate.adapter_id
            or row.adapter_version != candidate.adapter_version
        ):
            raise ValueError("measurement mixes adapter candidates")
    windows = {
        (row.measurement_window_start, row.measurement_window_end)
        for row in observations
    }
    if len(windows) != 1:
        raise ValueError("measurement mixes time windows")
    prediction_cohorts = {
        (row.prediction_cohort_id, row.prediction_cohort_kind)
        for row in observations
    }
    if len(prediction_cohorts) != 1:
        raise ValueError("measurement mixes prediction cohorts")
    prediction_cohort_id, _ = next(iter(prediction_cohorts))
    if cohort_id != prediction_cohort_id:
        raise ValueError(
            "measurement cohort differs from prediction membership"
        )
    observation_ids = tuple(row.observation_id for row in observations)
    job_keys = tuple(row.job_key for row in observations)
    if (
        len(observation_ids) != len(set(observation_ids))
        or len(job_keys) != len(set(job_keys))
        or len({row.source_snapshot_sha256 for row in observations})
        != len(observations)
        or len({row.prediction_id for row in observations})
        != len(observations)
    ):
        raise ValueError(
            "measurement cannot duplicate jobs, sources or predictions"
        )
    worthwhile = tuple(row for row in observations if row.worthwhile_vacancy)
    worthwhile_count = len(worthwhile)
    expected_interviews = sum(
        row.expected_interview_bp for row in worthwhile
    )
    value_score = (
        worthwhile_count * 10_000
        + expected_interviews
        - implementation_cost_points * 100
        - operational_friction_points * 100
    )
    window_start, window_end = next(iter(windows))
    body = {
        "schema_version": "jaa15.adapter-measurement.v1",
        "contract_sha256": contract.contract_sha256,
        "candidate_id": candidate.candidate_id,
        "adapter_id": candidate.adapter_id,
        "adapter_version": candidate.adapter_version,
        "cohort_id": cohort_id,
        "measurement_window_start": window_start,
        "measurement_window_end": window_end,
        "observation_ids": observation_ids,
        "job_keys": job_keys,
        "sample_count": len(observations),
        "worthwhile_vacancies": worthwhile_count,
        "expected_interviews_bp": expected_interviews,
        "implementation_cost_points": implementation_cost_points,
        "operational_friction_points": operational_friction_points,
        "value_score": value_score,
        "activation_authority": "withheld",
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return AdapterMeasurement(
        **body,
        measurement_id=_content_hash(body),
    )


@dataclass(frozen=True)
class AdapterEvidenceReference:
    contract_sha256: str
    candidate_id: str
    adapter_id: str
    adapter_version: str
    workflow_sha256: str
    extraction_policy_sha256: str
    selector_policy_sha256: str
    route_policy_sha256: str
    eligibility_policy_sha256: str
    payroll_policy_sha256: str
    evidence_kind: str
    evidence_sha256: str
    observed_at: str
    evidence_id: str
    activation_authority: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa15.adapter-evidence-reference.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "candidate_id": self.candidate_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "workflow_sha256": self.workflow_sha256,
            "extraction_policy_sha256": self.extraction_policy_sha256,
            "selector_policy_sha256": self.selector_policy_sha256,
            "route_policy_sha256": self.route_policy_sha256,
            "eligibility_policy_sha256": self.eligibility_policy_sha256,
            "payroll_policy_sha256": self.payroll_policy_sha256,
            "evidence_kind": self.evidence_kind,
            "evidence_sha256": self.evidence_sha256,
            "observed_at": self.observed_at,
            "activation_authority": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["evidence_id"] = self.evidence_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "evidence contract hash"),
            (self.candidate_id, "evidence candidate ID"),
            (self.workflow_sha256, "evidence workflow hash"),
            (self.extraction_policy_sha256, "evidence extraction hash"),
            (self.selector_policy_sha256, "evidence selector hash"),
            (self.route_policy_sha256, "evidence route hash"),
            (self.eligibility_policy_sha256, "evidence eligibility hash"),
            (self.payroll_policy_sha256, "evidence payroll hash"),
            (self.evidence_sha256, "referenced evidence hash"),
            (self.evidence_id, "adapter evidence ID"),
        ):
            _digest(value, label)
        _required(self.adapter_id, "evidence adapter ID")
        _required(self.adapter_version, "evidence adapter version")
        if self.evidence_kind not in EVIDENCE_KINDS:
            raise ValueError("adapter evidence kind is unsupported")
        _aware_iso(self.observed_at, "adapter evidence time")
        if (
            self.contract_sha256
            != FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
            or self.activation_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version
            != "jaa15.adapter-evidence-reference.v1"
        ):
            raise ValueError("adapter evidence cannot activate or certify")
        if self.evidence_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("adapter evidence identity is invalid")


def record_adapter_evidence_reference(
    contract: SourceExpansionContract,
    candidate: AdapterCandidate,
    *,
    evidence_kind: str,
    evidence_sha256: str,
    observed_at: datetime,
) -> AdapterEvidenceReference:
    if contract != FROZEN_SOURCE_EXPANSION_CONTRACT:
        raise ValueError(
            "evidence requires the canonical expansion contract"
        )
    if not isinstance(candidate, AdapterCandidate):
        raise TypeError("evidence requires a typed adapter candidate")
    candidate.verify()
    observed = _aware(observed_at, "adapter evidence time")
    body = {
        "schema_version": "jaa15.adapter-evidence-reference.v1",
        "contract_sha256": contract.contract_sha256,
        "candidate_id": candidate.candidate_id,
        "adapter_id": candidate.adapter_id,
        "adapter_version": candidate.adapter_version,
        "workflow_sha256": candidate.workflow_sha256,
        "extraction_policy_sha256": candidate.extraction_policy_sha256,
        "selector_policy_sha256": candidate.selector_policy_sha256,
        "route_policy_sha256": candidate.route_policy_sha256,
        "eligibility_policy_sha256": candidate.eligibility_policy_sha256,
        "payroll_policy_sha256": candidate.payroll_policy_sha256,
        "evidence_kind": evidence_kind,
        "evidence_sha256": evidence_sha256,
        "observed_at": observed.isoformat(),
        "activation_authority": "withheld",
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return AdapterEvidenceReference(
        **body,
        evidence_id=_content_hash(body),
    )


@dataclass(frozen=True)
class AdapterQualitySnapshot:
    contract_sha256: str
    candidate_id: str
    adapter_id: str
    evaluated_adapter_version: str
    phase: str
    eligibility_policy_sha256: str
    payroll_policy_sha256: str
    sample_ids: tuple[str, ...]
    freshness_pass_rate_bp: int
    unsupported_release_claims: int
    ineligible_routes: int
    confirmed_without_receipt: int
    receipt_integrity_violations: int
    replay_mismatches: int
    snapshot_id: str
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa15.adapter-quality-snapshot.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "candidate_id": self.candidate_id,
            "adapter_id": self.adapter_id,
            "evaluated_adapter_version": self.evaluated_adapter_version,
            "phase": self.phase,
            "eligibility_policy_sha256": self.eligibility_policy_sha256,
            "payroll_policy_sha256": self.payroll_policy_sha256,
            "sample_ids": self.sample_ids,
            "freshness_pass_rate_bp": self.freshness_pass_rate_bp,
            "unsupported_release_claims": self.unsupported_release_claims,
            "ineligible_routes": self.ineligible_routes,
            "confirmed_without_receipt": self.confirmed_without_receipt,
            "receipt_integrity_violations": (
                self.receipt_integrity_violations
            ),
            "replay_mismatches": self.replay_mismatches,
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["snapshot_id"] = self.snapshot_id
        return result

    @property
    def hard_quality_values(self) -> tuple[int, ...]:
        return tuple(getattr(self, field) for field in HARD_QUALITY_FIELDS)

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "quality contract hash"),
            (self.candidate_id, "quality candidate ID"),
            (self.eligibility_policy_sha256, "quality eligibility hash"),
            (self.payroll_policy_sha256, "quality payroll hash"),
            (self.snapshot_id, "quality snapshot ID"),
        ):
            _digest(value, label)
        _required(self.adapter_id, "quality adapter ID")
        _required(
            self.evaluated_adapter_version,
            "quality adapter version",
        )
        if self.phase not in QUALITY_PHASES:
            raise ValueError("quality snapshot phase is unsupported")
        if (
            not self.sample_ids
            or tuple(sorted(set(self.sample_ids))) != self.sample_ids
        ):
            raise ValueError(
                "quality sample IDs must be non-empty, unique and sorted"
            )
        for value in self.sample_ids:
            _digest(value, "quality sample ID")
        if (
            type(self.freshness_pass_rate_bp) is not int
            or not 0 <= self.freshness_pass_rate_bp <= 10_000
        ):
            raise ValueError("quality freshness rate is invalid")
        for value in self.hard_quality_values:
            if type(value) is not int or value < 0:
                raise ValueError("hard quality values must be non-negative")
        if (
            self.contract_sha256
            != FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version
            != "jaa15.adapter-quality-snapshot.v1"
        ):
            raise ValueError("quality snapshot cannot certify expansion")
        if self.snapshot_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("quality snapshot identity is invalid")


def record_adapter_quality_snapshot(
    contract: SourceExpansionContract,
    candidate: AdapterCandidate,
    *,
    phase: str,
    sample_ids: tuple[str, ...],
    freshness_pass_rate_bp: int,
    unsupported_release_claims: int = 0,
    ineligible_routes: int = 0,
    confirmed_without_receipt: int = 0,
    receipt_integrity_violations: int = 0,
    replay_mismatches: int = 0,
) -> AdapterQualitySnapshot:
    if contract != FROZEN_SOURCE_EXPANSION_CONTRACT:
        raise ValueError(
            "quality snapshot requires the canonical expansion contract"
        )
    if not isinstance(candidate, AdapterCandidate):
        raise TypeError("quality snapshot requires a typed adapter candidate")
    candidate.verify()
    if phase == "baseline":
        evaluated_version = candidate.rollback_adapter_version
    elif phase == "candidate":
        evaluated_version = candidate.adapter_version
    else:
        raise ValueError("quality snapshot phase is unsupported")
    body = {
        "schema_version": "jaa15.adapter-quality-snapshot.v1",
        "contract_sha256": contract.contract_sha256,
        "candidate_id": candidate.candidate_id,
        "adapter_id": candidate.adapter_id,
        "evaluated_adapter_version": evaluated_version,
        "phase": phase,
        "eligibility_policy_sha256": candidate.eligibility_policy_sha256,
        "payroll_policy_sha256": candidate.payroll_policy_sha256,
        "sample_ids": tuple(sorted(set(sample_ids))),
        "freshness_pass_rate_bp": freshness_pass_rate_bp,
        "unsupported_release_claims": unsupported_release_claims,
        "ineligible_routes": ineligible_routes,
        "confirmed_without_receipt": confirmed_without_receipt,
        "receipt_integrity_violations": receipt_integrity_violations,
        "replay_mismatches": replay_mismatches,
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return AdapterQualitySnapshot(
        **body,
        snapshot_id=_content_hash(body),
    )


@dataclass(frozen=True)
class AdapterExpansionEvaluation:
    contract_sha256: str
    candidate_id: str
    adapter_id: str
    adapter_version: str
    rollback_adapter_version: str
    measurement_id: str
    cohort_id: str
    measurement_window_start: str
    measurement_window_end: str
    value_score: int
    baseline_quality_snapshot_id: str
    candidate_quality_snapshot_id: str
    evidence_ids: tuple[str, ...]
    evidence_kinds: tuple[str, ...]
    reason_codes: tuple[str, ...]
    eligible_for_review: bool
    visible: bool
    evaluation_id: str
    crawl_authority: str = "withheld"
    activation_authority: str = "withheld"
    production_certification: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa15.adapter-expansion-evaluation.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "candidate_id": self.candidate_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "rollback_adapter_version": self.rollback_adapter_version,
            "measurement_id": self.measurement_id,
            "cohort_id": self.cohort_id,
            "measurement_window_start": self.measurement_window_start,
            "measurement_window_end": self.measurement_window_end,
            "value_score": self.value_score,
            "baseline_quality_snapshot_id": (
                self.baseline_quality_snapshot_id
            ),
            "candidate_quality_snapshot_id": (
                self.candidate_quality_snapshot_id
            ),
            "evidence_ids": self.evidence_ids,
            "evidence_kinds": self.evidence_kinds,
            "reason_codes": self.reason_codes,
            "eligible_for_review": self.eligible_for_review,
            "visible": True,
            "crawl_authority": "withheld",
            "activation_authority": "withheld",
            "production_certification": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["evaluation_id"] = self.evaluation_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "evaluation contract hash"),
            (self.candidate_id, "evaluation candidate ID"),
            (self.measurement_id, "evaluation measurement ID"),
            (
                self.baseline_quality_snapshot_id,
                "baseline quality snapshot ID",
            ),
            (
                self.candidate_quality_snapshot_id,
                "candidate quality snapshot ID",
            ),
            (self.evaluation_id, "adapter evaluation ID"),
        ):
            _digest(value, label)
        for value, label in (
            (self.adapter_id, "evaluation adapter ID"),
            (self.adapter_version, "evaluation adapter version"),
            (
                self.rollback_adapter_version,
                "evaluation rollback version",
            ),
            (self.cohort_id, "evaluation cohort ID"),
        ):
            _required(value, label)
        start = _aware_iso(
            self.measurement_window_start,
            "evaluation window start",
        )
        end = _aware_iso(
            self.measurement_window_end,
            "evaluation window end",
        )
        if start >= end:
            raise ValueError("evaluation window must be ordered")
        if type(self.value_score) is not int:
            raise ValueError("evaluation value score must be an integer")
        if (
            not self.evidence_ids
            or len(self.evidence_ids) != len(set(self.evidence_ids))
        ):
            raise ValueError("evaluation evidence IDs must be unique")
        for value in self.evidence_ids:
            _digest(value, "evaluation evidence ID")
        if tuple(sorted(set(self.evidence_kinds))) != self.evidence_kinds:
            raise ValueError("evaluation evidence kinds must be unique and sorted")
        if any(value not in EVIDENCE_KINDS for value in self.evidence_kinds):
            raise ValueError("evaluation evidence kind is unsupported")
        expected_reasons = tuple(
            reason for reason in REASON_ORDER if reason in self.reason_codes
        )
        if expected_reasons != self.reason_codes:
            raise ValueError("evaluation reasons are unsupported or unordered")
        if (
            type(self.eligible_for_review) is not bool
            or self.eligible_for_review is not (not self.reason_codes)
            or self.visible is not True
        ):
            raise ValueError("evaluation eligibility or visibility is invalid")
        if self.eligible_for_review and (
            frozenset(self.evidence_kinds) != REQUIRED_EVIDENCE_KINDS
        ):
            raise ValueError(
                "eligible adapter lacks all required evidence kinds"
            )
        if (
            self.contract_sha256
            != FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
            or self.crawl_authority != "withheld"
            or self.activation_authority != "withheld"
            or self.production_certification != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version
            != "jaa15.adapter-expansion-evaluation.v1"
        ):
            raise ValueError("adapter evaluation cannot activate or certify")
        if self.evaluation_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("adapter evaluation identity is invalid")


def evaluate_adapter_candidate(
    contract: SourceExpansionContract,
    candidate: AdapterCandidate,
    measurement: AdapterMeasurement,
    evidence: tuple[AdapterEvidenceReference, ...],
    *,
    baseline_quality: AdapterQualitySnapshot,
    candidate_quality: AdapterQualitySnapshot,
) -> AdapterExpansionEvaluation:
    if contract != FROZEN_SOURCE_EXPANSION_CONTRACT:
        raise ValueError(
            "evaluation requires the canonical expansion contract"
        )
    if not isinstance(candidate, AdapterCandidate):
        raise TypeError("evaluation requires a typed adapter candidate")
    if not isinstance(measurement, AdapterMeasurement):
        raise TypeError("evaluation requires a typed adapter measurement")
    if not all(isinstance(row, AdapterEvidenceReference) for row in evidence):
        raise TypeError("evaluation requires typed adapter evidence")
    if not isinstance(baseline_quality, AdapterQualitySnapshot) or not isinstance(
        candidate_quality,
        AdapterQualitySnapshot,
    ):
        raise TypeError("evaluation requires typed quality snapshots")
    candidate.verify()
    measurement.verify()
    baseline_quality.verify()
    candidate_quality.verify()
    expected_candidate = (
        candidate.candidate_id,
        candidate.adapter_id,
    )
    if (
        (measurement.candidate_id, measurement.adapter_id)
        != expected_candidate
        or (
            baseline_quality.candidate_id,
            baseline_quality.adapter_id,
        )
        != expected_candidate
        or (
            candidate_quality.candidate_id,
            candidate_quality.adapter_id,
        )
        != expected_candidate
    ):
        raise ValueError("evaluation mixes adapter candidates")
    if (
        measurement.adapter_version != candidate.adapter_version
        or baseline_quality.phase != "baseline"
        or baseline_quality.evaluated_adapter_version
        != candidate.rollback_adapter_version
        or candidate_quality.phase != "candidate"
        or candidate_quality.evaluated_adapter_version
        != candidate.adapter_version
    ):
        raise ValueError("evaluation mixes workflow or rollback versions")
    for snapshot in (baseline_quality, candidate_quality):
        if (
            snapshot.eligibility_policy_sha256
            != candidate.eligibility_policy_sha256
            or snapshot.payroll_policy_sha256
            != candidate.payroll_policy_sha256
        ):
            raise ValueError("evaluation mixes eligibility or payroll policy")
    if baseline_quality.sample_ids != candidate_quality.sample_ids:
        raise ValueError("quality comparison requires identical membership")
    evidence_ids: list[str] = []
    evidence_kinds: list[str] = []
    for row in evidence:
        row.verify()
        if (
            row.candidate_id != candidate.candidate_id
            or row.adapter_id != candidate.adapter_id
            or row.adapter_version != candidate.adapter_version
            or row.workflow_sha256 != candidate.workflow_sha256
            or row.extraction_policy_sha256
            != candidate.extraction_policy_sha256
            or row.selector_policy_sha256
            != candidate.selector_policy_sha256
            or row.route_policy_sha256 != candidate.route_policy_sha256
            or row.eligibility_policy_sha256
            != candidate.eligibility_policy_sha256
            or row.payroll_policy_sha256 != candidate.payroll_policy_sha256
        ):
            raise ValueError(
                "adapter evidence belongs to another adapter or policy"
            )
        if (
            datetime.fromisoformat(row.observed_at)
            < datetime.fromisoformat(measurement.measurement_window_end)
        ):
            raise ValueError(
                "adapter evidence must follow the measurement window"
            )
        evidence_ids.append(row.evidence_id)
        evidence_kinds.append(row.evidence_kind)
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("evaluation cannot reuse adapter evidence")
    kinds = frozenset(evidence_kinds)
    reasons: list[str] = []
    if candidate.route_status == "unsupported":
        reasons.append("unsupported_route")
    if measurement.value_score <= 0:
        reasons.append("non_positive_incremental_value")
    for kind in EVIDENCE_KINDS:
        if kind not in kinds:
            reasons.append(f"missing_{kind}_evidence")
    if (
        candidate_quality.freshness_pass_rate_bp
        < baseline_quality.freshness_pass_rate_bp
    ):
        reasons.append("source_freshness_regression")
    if any(baseline_quality.hard_quality_values):
        reasons.append("baseline_hard_quality_not_clean")
    if any(candidate_quality.hard_quality_values):
        reasons.append("candidate_hard_quality_regression")
    reason_codes = tuple(
        reason for reason in REASON_ORDER if reason in reasons
    )
    sorted_evidence = tuple(
        sorted(evidence, key=lambda row: (row.evidence_kind, row.evidence_id))
    )
    body = {
        "schema_version": "jaa15.adapter-expansion-evaluation.v1",
        "contract_sha256": contract.contract_sha256,
        "candidate_id": candidate.candidate_id,
        "adapter_id": candidate.adapter_id,
        "adapter_version": candidate.adapter_version,
        "rollback_adapter_version": candidate.rollback_adapter_version,
        "measurement_id": measurement.measurement_id,
        "cohort_id": measurement.cohort_id,
        "measurement_window_start": measurement.measurement_window_start,
        "measurement_window_end": measurement.measurement_window_end,
        "value_score": measurement.value_score,
        "baseline_quality_snapshot_id": baseline_quality.snapshot_id,
        "candidate_quality_snapshot_id": candidate_quality.snapshot_id,
        "evidence_ids": tuple(row.evidence_id for row in sorted_evidence),
        "evidence_kinds": tuple(
            sorted({row.evidence_kind for row in sorted_evidence})
        ),
        "reason_codes": reason_codes,
        "eligible_for_review": not reason_codes,
        "visible": True,
        "crawl_authority": "withheld",
        "activation_authority": "withheld",
        "production_certification": "withheld",
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return AdapterExpansionEvaluation(
        **body,
        evaluation_id=_content_hash(body),
    )


@dataclass(frozen=True)
class RankedAdapter:
    rank: int
    candidate_id: str
    evaluation_id: str
    adapter_id: str
    adapter_version: str
    value_score: int
    status: str
    reason_codes: tuple[str, ...]
    entry_id: str
    schema_version: str = "jaa15.ranked-adapter.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "rank": self.rank,
            "candidate_id": self.candidate_id,
            "evaluation_id": self.evaluation_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "value_score": self.value_score,
            "status": self.status,
            "reason_codes": self.reason_codes,
        }
        if include_identity:
            result["entry_id"] = self.entry_id
        return result

    def verify(self) -> None:
        if type(self.rank) is not int or self.rank < 1:
            raise ValueError("adapter rank must be positive")
        if type(self.value_score) is not int:
            raise ValueError("ranked value score must be an integer")
        for value, label in (
            (self.candidate_id, "ranked candidate ID"),
            (self.evaluation_id, "ranked evaluation ID"),
            (self.entry_id, "ranked entry ID"),
        ):
            _digest(value, label)
        _required(self.adapter_id, "ranked adapter ID")
        _required(self.adapter_version, "ranked adapter version")
        if self.status not in {"eligible_for_review", "blocked"}:
            raise ValueError("ranked adapter status is unsupported")
        expected_reasons = tuple(
            reason for reason in REASON_ORDER if reason in self.reason_codes
        )
        if expected_reasons != self.reason_codes:
            raise ValueError("ranked adapter reasons are invalid")
        if (self.status == "eligible_for_review") is not (
            not self.reason_codes
        ):
            raise ValueError("ranked adapter status differs from reasons")
        if (
            self.schema_version != "jaa15.ranked-adapter.v1"
            or self.entry_id
            != _content_hash(self.document(include_identity=False))
        ):
            raise ValueError("ranked adapter identity is invalid")


@dataclass(frozen=True)
class ExpansionPortfolio:
    contract_sha256: str
    cohort_id: str
    measurement_window_start: str
    measurement_window_end: str
    entries: tuple[RankedAdapter, ...]
    portfolio_id: str
    blocked_candidates_visible: bool = True
    crawl_authority: str = "withheld"
    activation_authority: str = "withheld"
    production_certification: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa15.expansion-portfolio.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "cohort_id": self.cohort_id,
            "measurement_window_start": self.measurement_window_start,
            "measurement_window_end": self.measurement_window_end,
            "entries": tuple(row.document() for row in self.entries),
            "blocked_candidates_visible": True,
            "crawl_authority": "withheld",
            "activation_authority": "withheld",
            "production_certification": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["portfolio_id"] = self.portfolio_id
        return result

    def verify(self) -> None:
        _digest(self.contract_sha256, "portfolio contract hash")
        _digest(self.portfolio_id, "portfolio ID")
        _required(self.cohort_id, "portfolio cohort ID")
        start = _aware_iso(
            self.measurement_window_start,
            "portfolio window start",
        )
        end = _aware_iso(
            self.measurement_window_end,
            "portfolio window end",
        )
        if start >= end or not self.entries:
            raise ValueError("portfolio requires one ordered measurement window")
        if not all(isinstance(row, RankedAdapter) for row in self.entries):
            raise TypeError("portfolio entries must be typed")
        for row in self.entries:
            row.verify()
        if tuple(row.rank for row in self.entries) != tuple(
            range(1, len(self.entries) + 1)
        ):
            raise ValueError("portfolio ranks must be contiguous")
        if (
            len({row.candidate_id for row in self.entries})
            != len(self.entries)
            or len({row.evaluation_id for row in self.entries})
            != len(self.entries)
        ):
            raise ValueError("portfolio candidates must be unique")
        if (
            self.contract_sha256
            != FROZEN_SOURCE_EXPANSION_CONTRACT.contract_sha256
            or self.blocked_candidates_visible is not True
            or self.crawl_authority != "withheld"
            or self.activation_authority != "withheld"
            or self.production_certification != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
            or self.schema_version != "jaa15.expansion-portfolio.v1"
        ):
            raise ValueError("portfolio cannot hide, activate or certify")
        if self.portfolio_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("portfolio identity is invalid")


def rank_expansion_candidates(
    contract: SourceExpansionContract,
    evaluations: tuple[AdapterExpansionEvaluation, ...],
) -> ExpansionPortfolio:
    if contract != FROZEN_SOURCE_EXPANSION_CONTRACT:
        raise ValueError("portfolio requires the canonical expansion contract")
    if not evaluations or not all(
        isinstance(row, AdapterExpansionEvaluation) for row in evaluations
    ):
        raise TypeError("portfolio requires typed adapter evaluations")
    for row in evaluations:
        row.verify()
    if (
        len({row.candidate_id for row in evaluations}) != len(evaluations)
        or len({row.evaluation_id for row in evaluations}) != len(evaluations)
    ):
        raise ValueError("portfolio cannot duplicate adapter evaluations")
    cohorts = {row.cohort_id for row in evaluations}
    windows = {
        (row.measurement_window_start, row.measurement_window_end)
        for row in evaluations
    }
    if len(cohorts) != 1 or len(windows) != 1:
        raise ValueError("portfolio candidates must share cohort and window")
    ordered = tuple(sorted(
        evaluations,
        key=lambda row: (
            not row.eligible_for_review,
            -row.value_score,
            row.adapter_id,
            row.adapter_version,
        ),
    ))
    entries: list[RankedAdapter] = []
    for rank, evaluation in enumerate(ordered, start=1):
        body = {
            "schema_version": "jaa15.ranked-adapter.v1",
            "rank": rank,
            "candidate_id": evaluation.candidate_id,
            "evaluation_id": evaluation.evaluation_id,
            "adapter_id": evaluation.adapter_id,
            "adapter_version": evaluation.adapter_version,
            "value_score": evaluation.value_score,
            "status": (
                "eligible_for_review"
                if evaluation.eligible_for_review
                else "blocked"
            ),
            "reason_codes": evaluation.reason_codes,
        }
        entries.append(RankedAdapter(**body, entry_id=_content_hash(body)))
    window_start, window_end = next(iter(windows))
    body = {
        "schema_version": "jaa15.expansion-portfolio.v1",
        "contract_sha256": contract.contract_sha256,
        "cohort_id": next(iter(cohorts)),
        "measurement_window_start": window_start,
        "measurement_window_end": window_end,
        "entries": tuple(row.document() for row in entries),
        "blocked_candidates_visible": True,
        "crawl_authority": "withheld",
        "activation_authority": "withheld",
        "production_certification": "withheld",
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return ExpansionPortfolio(
        contract_sha256=contract.contract_sha256,
        cohort_id=next(iter(cohorts)),
        measurement_window_start=window_start,
        measurement_window_end=window_end,
        entries=tuple(entries),
        portfolio_id=_content_hash(body),
    )
