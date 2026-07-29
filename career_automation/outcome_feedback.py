"""Pure local outcome-feedback contract for dependency-withheld JAA-14.

The module records configured-predictor receipts before outcome evidence,
scores only explicit local timeline outcomes, preserves censoring, and
evaluates policy candidates without promoting them. It performs no model,
connector, policy-mutation, candidate-fact, browser, network or external
action.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Iterable, Mapping

from .gap_optimizer import gap_policy_hash
from .models import PipelineState
from .opportunity_calibration import CalibrationPolicy
from .status_ingestion import (
    FROZEN_LOCAL_EXPORT_STATUS_CONTRACT,
    StatusTimeline,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
PREFIXED_HEX_64 = re.compile(r"^sha256:[0-9a-f]{64}$")
TARGET_STATES = (
    PipelineState.SCREENING,
    PipelineState.INTERVIEW,
    PipelineState.OFFER,
    PipelineState.ACCEPTED,
)
CENSORED_TERMINAL_STATES = (
    PipelineState.DECLINED,
    PipelineState.WITHDRAWN,
    PipelineState.EXPIRED,
)
COHORT_KINDS = ("locked", "holdout", "live")
EXPERIMENT_ARMS = ("baseline", "treatment")
PREDICTION_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa14.pre-outcome-prediction-policy.v1",
    "producer_kinds": ("configured_model", "deterministic_policy"),
    "target_states": tuple(state.value for state in TARGET_STATES),
    "manual_prediction": False,
    "post_hoc_prediction": False,
})
SCORING_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa14.outcome-scoring-policy.v2",
    "metric": "integer_brier_basis_points",
    "receipt_lineage": "typed_prediction_and_timeline",
    "explicit_negative_state": PipelineState.REJECTED.value,
    "censored_terminal_states": tuple(
        state.value for state in CENSORED_TERMINAL_STATES
    ),
    "silence": "censored",
    "censored_score": None,
})
EXPERIMENT_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa14.strategy-experiment-policy.v1",
    "arms": EXPERIMENT_ARMS,
    "changed_variable_count": 1,
    "assignment": "pre_outcome_content_addressed",
})
PROMOTION_POLICY: Mapping[str, object] = MappingProxyType({
    "schema_version": "jaa14.policy-promotion-review.v1",
    "minimum_resolved_per_report": 2,
    "locked_non_regression": "candidate_brier_lte_baseline",
    "holdout_improvement": "candidate_brier_lt_baseline",
    "distinct_holdout_required": True,
    "promotion_authority": "withheld",
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
        raise ValueError(f"{label} must be sha256:<lowercase SHA-256>")
    return value


def _required(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
    ):
        raise ValueError(f"{label} must be a trimmed non-empty string")
    return value


def _aware(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{label} must include a timezone")
    return value


def _aware_iso(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    return _aware(parsed, label)


PREDICTION_POLICY_SHA256 = _content_hash(dict(PREDICTION_POLICY))
SCORING_POLICY_SHA256 = _content_hash(dict(SCORING_POLICY))
EXPERIMENT_POLICY_SHA256 = _content_hash(dict(EXPERIMENT_POLICY))
PROMOTION_POLICY_SHA256 = _content_hash(dict(PROMOTION_POLICY))


@dataclass(frozen=True)
class OutcomeFeedbackContract:
    upstream_status_contract_sha256: str
    opportunity_policy_hash: str
    gap_policy_sha256: str
    prediction_policy_sha256: str
    scoring_policy_sha256: str
    experiment_policy_sha256: str
    promotion_policy_sha256: str
    runtime_learning_authority: str = "withheld"
    policy_promotion_authority: str = "withheld"
    gap_mutation_authority: str = "withheld"
    connector_authority: str = "withheld"
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa14.local-outcome-feedback-contract.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (
                self.upstream_status_contract_sha256,
                "upstream status contract hash",
            ),
            (self.gap_policy_sha256, "gap policy hash"),
            (self.prediction_policy_sha256, "prediction policy hash"),
            (self.scoring_policy_sha256, "scoring policy hash"),
            (self.experiment_policy_sha256, "experiment policy hash"),
            (self.promotion_policy_sha256, "promotion policy hash"),
        ):
            _digest(value, label)
        _prefixed_digest(
            self.opportunity_policy_hash,
            "opportunity policy hash",
        )
        expected = (
            FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256,
            CalibrationPolicy().policy_hash,
            gap_policy_hash(),
            PREDICTION_POLICY_SHA256,
            SCORING_POLICY_SHA256,
            EXPERIMENT_POLICY_SHA256,
            PROMOTION_POLICY_SHA256,
        )
        actual = (
            self.upstream_status_contract_sha256,
            self.opportunity_policy_hash,
            self.gap_policy_sha256,
            self.prediction_policy_sha256,
            self.scoring_policy_sha256,
            self.experiment_policy_sha256,
            self.promotion_policy_sha256,
        )
        if actual != expected:
            raise ValueError(
                "outcome contract differs from accepted upstream policies"
            )
        if (
            self.runtime_learning_authority != "withheld"
            or self.policy_promotion_authority != "withheld"
            or self.gap_mutation_authority != "withheld"
            or self.connector_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError("local outcome contract cannot mutate or certify")
        if self.schema_version != "jaa14.local-outcome-feedback-contract.v1":
            raise ValueError("outcome contract schema is unsupported")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "upstream_status_contract_sha256": (
                self.upstream_status_contract_sha256
            ),
            "opportunity_policy_hash": self.opportunity_policy_hash,
            "gap_policy_sha256": self.gap_policy_sha256,
            "prediction_policy_sha256": self.prediction_policy_sha256,
            "scoring_policy_sha256": self.scoring_policy_sha256,
            "experiment_policy_sha256": self.experiment_policy_sha256,
            "promotion_policy_sha256": self.promotion_policy_sha256,
            "runtime_learning_authority": "withheld",
            "policy_promotion_authority": "withheld",
            "gap_mutation_authority": "withheld",
            "connector_authority": "withheld",
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }

    @property
    def contract_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_OUTCOME_FEEDBACK_CONTRACT = OutcomeFeedbackContract(
    upstream_status_contract_sha256=(
        FROZEN_LOCAL_EXPORT_STATUS_CONTRACT.contract_sha256
    ),
    opportunity_policy_hash=CalibrationPolicy().policy_hash,
    gap_policy_sha256=gap_policy_hash(),
    prediction_policy_sha256=PREDICTION_POLICY_SHA256,
    scoring_policy_sha256=SCORING_POLICY_SHA256,
    experiment_policy_sha256=EXPERIMENT_POLICY_SHA256,
    promotion_policy_sha256=PROMOTION_POLICY_SHA256,
)


@dataclass(frozen=True)
class StrategyExperiment:
    contract_sha256: str
    experiment_name: str
    variable_names: tuple[str, ...]
    baseline_value_sha256: str
    treatment_value_sha256: str
    assignment_policy_sha256: str
    created_at: str
    experiment_id: str
    policy_promotion_authority: str = "withheld"
    dependency_satisfied: bool = False
    schema_version: str = "jaa14.strategy-experiment.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "variable_names", tuple(self.variable_names))
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "experiment_name": self.experiment_name,
            "variable_names": self.variable_names,
            "baseline_value_sha256": self.baseline_value_sha256,
            "treatment_value_sha256": self.treatment_value_sha256,
            "assignment_policy_sha256": self.assignment_policy_sha256,
            "created_at": self.created_at,
            "arms": EXPERIMENT_ARMS,
            "policy_promotion_authority": "withheld",
            "dependency_satisfied": False,
        }
        if include_identity:
            result["experiment_id"] = self.experiment_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "experiment contract hash"),
            (self.baseline_value_sha256, "baseline value hash"),
            (self.treatment_value_sha256, "treatment value hash"),
            (self.assignment_policy_sha256, "assignment policy hash"),
            (self.experiment_id, "experiment ID"),
        ):
            _digest(value, label)
        _required(self.experiment_name, "experiment name")
        if (
            len(self.variable_names) != 1
            or not all(
                isinstance(value, str)
                and value.strip()
                and value == value.strip()
                for value in self.variable_names
            )
        ):
            raise ValueError(
                "strategy experiment must change exactly one named variable"
            )
        if self.baseline_value_sha256 == self.treatment_value_sha256:
            raise ValueError("strategy experiment arms must differ")
        _aware_iso(self.created_at, "experiment creation time")
        if (
            self.contract_sha256
            != FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256
        ):
            raise ValueError("experiment binds a different outcome contract")
        if (
            self.policy_promotion_authority != "withheld"
            or self.dependency_satisfied is not False
        ):
            raise ValueError("local experiment cannot promote or satisfy")
        if self.schema_version != "jaa14.strategy-experiment.v1":
            raise ValueError("strategy experiment schema is unsupported")
        if self.experiment_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("strategy experiment differs from exact content")


def compile_strategy_experiment(
    contract: OutcomeFeedbackContract,
    *,
    experiment_name: str,
    variable_names: Iterable[str],
    baseline_value_sha256: str,
    treatment_value_sha256: str,
    assignment_policy_sha256: str,
    created_at: datetime,
) -> StrategyExperiment:
    if contract != FROZEN_OUTCOME_FEEDBACK_CONTRACT:
        raise ValueError("experiment requires the canonical outcome contract")
    _aware(created_at, "experiment creation time")
    variables = tuple(variable_names)
    body = {
        "schema_version": "jaa14.strategy-experiment.v1",
        "contract_sha256": contract.contract_sha256,
        "experiment_name": experiment_name,
        "variable_names": variables,
        "baseline_value_sha256": baseline_value_sha256,
        "treatment_value_sha256": treatment_value_sha256,
        "assignment_policy_sha256": assignment_policy_sha256,
        "created_at": created_at.isoformat(),
        "arms": EXPERIMENT_ARMS,
        "policy_promotion_authority": "withheld",
        "dependency_satisfied": False,
    }
    return StrategyExperiment(
        contract_sha256=contract.contract_sha256,
        experiment_name=experiment_name,
        variable_names=variables,
        baseline_value_sha256=baseline_value_sha256,
        treatment_value_sha256=treatment_value_sha256,
        assignment_policy_sha256=assignment_policy_sha256,
        created_at=created_at.isoformat(),
        experiment_id=_content_hash(body),
    )


@dataclass(frozen=True)
class PredictionReceipt:
    contract_sha256: str
    application_id: str
    job_key: str
    predictor_kind: str
    predictor_id: str
    predictor_version: str
    predictor_receipt_sha256: str
    predictor_policy_sha256: str
    input_snapshot_sha256: str
    strategy_id: str
    cohort_id: str
    cohort_kind: str
    experiment_id: str | None
    experiment_arm: str | None
    experiment_assignment_policy_sha256: str | None
    assignment_receipt_sha256: str | None
    target_state: PipelineState
    probability_bp: int
    predicted_at: str
    horizon_at: str
    prediction_id: str
    manual_prediction: bool = False
    dependency_satisfied: bool = False
    production_certification: str = "withheld"
    certifies_slice: bool = False
    schema_version: str = "jaa14.pre-outcome-prediction.v1"

    def __post_init__(self) -> None:
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract_sha256": self.contract_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "predictor_kind": self.predictor_kind,
            "predictor_id": self.predictor_id,
            "predictor_version": self.predictor_version,
            "predictor_receipt_sha256": self.predictor_receipt_sha256,
            "predictor_policy_sha256": self.predictor_policy_sha256,
            "input_snapshot_sha256": self.input_snapshot_sha256,
            "strategy_id": self.strategy_id,
            "cohort_id": self.cohort_id,
            "cohort_kind": self.cohort_kind,
            "experiment_id": self.experiment_id,
            "experiment_arm": self.experiment_arm,
            "experiment_assignment_policy_sha256": (
                self.experiment_assignment_policy_sha256
            ),
            "assignment_receipt_sha256": self.assignment_receipt_sha256,
            "target_state": self.target_state.value,
            "probability_bp": self.probability_bp,
            "predicted_at": self.predicted_at,
            "horizon_at": self.horizon_at,
            "manual_prediction": False,
            "dependency_satisfied": False,
            "production_certification": "withheld",
            "certifies_slice": False,
        }
        if include_identity:
            result["prediction_id"] = self.prediction_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.contract_sha256, "prediction contract hash"),
            (self.predictor_receipt_sha256, "predictor receipt hash"),
            (self.predictor_policy_sha256, "predictor policy hash"),
            (self.input_snapshot_sha256, "prediction input hash"),
            (self.strategy_id, "prediction strategy ID"),
            (self.prediction_id, "prediction ID"),
        ):
            _digest(value, label)
        for value, label in (
            (self.application_id, "prediction application ID"),
            (self.job_key, "prediction job key"),
            (self.predictor_id, "predictor ID"),
            (self.predictor_version, "predictor version"),
            (self.cohort_id, "prediction cohort ID"),
        ):
            _required(value, label)
        if self.predictor_kind not in PREDICTION_POLICY["producer_kinds"]:
            raise ValueError("prediction producer kind is not configured")
        if self.cohort_kind not in COHORT_KINDS:
            raise ValueError("prediction cohort kind is unsupported")
        if not isinstance(self.target_state, PipelineState):
            raise TypeError("prediction target state must be typed")
        if self.target_state not in TARGET_STATES:
            raise ValueError("prediction target state is unsupported")
        if (
            type(self.probability_bp) is not int
            or not 0 <= self.probability_bp <= 10_000
        ):
            raise ValueError("prediction probability must be integer basis points")
        predicted = _aware_iso(self.predicted_at, "prediction time")
        horizon = _aware_iso(self.horizon_at, "prediction horizon")
        if horizon <= predicted:
            raise ValueError("prediction horizon must follow prediction time")
        experiment_values = (
            self.experiment_id,
            self.experiment_arm,
            self.experiment_assignment_policy_sha256,
            self.assignment_receipt_sha256,
        )
        if any(value is None for value in experiment_values) and any(
            value is not None for value in experiment_values
        ):
            raise ValueError(
                "prediction experiment and assignment identities must align"
            )
        if self.experiment_id is not None:
            _digest(self.experiment_id, "prediction experiment ID")
            _digest(
                str(self.experiment_assignment_policy_sha256),
                "prediction experiment assignment policy hash",
            )
            _digest(
                str(self.assignment_receipt_sha256),
                "prediction assignment receipt hash",
            )
            if self.experiment_arm not in EXPERIMENT_ARMS:
                raise ValueError("prediction experiment arm is unsupported")
            expected_assignment = _content_hash({
                "schema_version": "jaa14.experiment-assignment.v1",
                "experiment_id": self.experiment_id,
                "assignment_policy_sha256": (
                    self.experiment_assignment_policy_sha256
                ),
                "application_id": self.application_id,
                "job_key": self.job_key,
                "cohort_id": self.cohort_id,
                "cohort_kind": self.cohort_kind,
                "experiment_arm": self.experiment_arm,
            })
            if self.assignment_receipt_sha256 != expected_assignment:
                raise ValueError(
                    "prediction experiment assignment receipt is invalid"
                )
        expected_predictor_receipt = _content_hash({
            "schema_version": "jaa14.configured-predictor-output.v1",
            "application_id": self.application_id,
            "job_key": self.job_key,
            "predictor_kind": self.predictor_kind,
            "predictor_id": self.predictor_id,
            "predictor_version": self.predictor_version,
            "predictor_policy_sha256": self.predictor_policy_sha256,
            "input_snapshot_sha256": self.input_snapshot_sha256,
            "strategy_id": self.strategy_id,
            "target_state": self.target_state.value,
            "probability_bp": self.probability_bp,
            "predicted_at": self.predicted_at,
        })
        if self.predictor_receipt_sha256 != expected_predictor_receipt:
            raise ValueError("configured predictor receipt differs from output")
        if (
            self.contract_sha256
            != FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256
        ):
            raise ValueError("prediction binds a different outcome contract")
        if (
            self.manual_prediction is not False
            or self.dependency_satisfied is not False
            or self.production_certification != "withheld"
            or self.certifies_slice is not False
        ):
            raise ValueError("local prediction cannot be manual or certify")
        if self.schema_version != "jaa14.pre-outcome-prediction.v1":
            raise ValueError("prediction schema is unsupported")
        if self.prediction_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("prediction differs from exact pre-outcome content")


def record_pre_outcome_prediction(
    contract: OutcomeFeedbackContract,
    *,
    application_id: str,
    job_key: str,
    predictor_kind: str,
    predictor_id: str,
    predictor_version: str,
    predictor_policy_sha256: str,
    input_snapshot_sha256: str,
    strategy_id: str,
    cohort_id: str,
    cohort_kind: str,
    target_state: PipelineState,
    probability_bp: int,
    predicted_at: datetime,
    horizon_at: datetime,
    experiment: StrategyExperiment | None = None,
    experiment_arm: str | None = None,
) -> PredictionReceipt:
    if contract != FROZEN_OUTCOME_FEEDBACK_CONTRACT:
        raise ValueError("prediction requires the canonical outcome contract")
    _aware(predicted_at, "prediction time")
    _aware(horizon_at, "prediction horizon")
    experiment_id = None
    if experiment is not None:
        if not isinstance(experiment, StrategyExperiment):
            raise TypeError("prediction experiment must be typed")
        experiment.verify()
        if datetime.fromisoformat(experiment.created_at) >= predicted_at:
            raise ValueError("experiment must exist before prediction")
        if experiment_arm not in EXPERIMENT_ARMS:
            raise ValueError("prediction requires an accepted experiment arm")
        experiment_id = experiment.experiment_id
        assignment_policy_sha256 = experiment.assignment_policy_sha256
        assignment_receipt_sha256 = _content_hash({
            "schema_version": "jaa14.experiment-assignment.v1",
            "experiment_id": experiment.experiment_id,
            "assignment_policy_sha256": experiment.assignment_policy_sha256,
            "application_id": application_id,
            "job_key": job_key,
            "cohort_id": cohort_id,
            "cohort_kind": cohort_kind,
            "experiment_arm": experiment_arm,
        })
    elif experiment_arm is not None:
        raise ValueError("prediction arm requires an exact experiment")
    else:
        assignment_policy_sha256 = None
        assignment_receipt_sha256 = None
    predictor_receipt_sha256 = _content_hash({
        "schema_version": "jaa14.configured-predictor-output.v1",
        "application_id": application_id,
        "job_key": job_key,
        "predictor_kind": predictor_kind,
        "predictor_id": predictor_id,
        "predictor_version": predictor_version,
        "predictor_policy_sha256": predictor_policy_sha256,
        "input_snapshot_sha256": input_snapshot_sha256,
        "strategy_id": strategy_id,
        "target_state": target_state.value,
        "probability_bp": probability_bp,
        "predicted_at": predicted_at.isoformat(),
    })
    body = {
        "schema_version": "jaa14.pre-outcome-prediction.v1",
        "contract_sha256": contract.contract_sha256,
        "application_id": application_id,
        "job_key": job_key,
        "predictor_kind": predictor_kind,
        "predictor_id": predictor_id,
        "predictor_version": predictor_version,
        "predictor_receipt_sha256": predictor_receipt_sha256,
        "predictor_policy_sha256": predictor_policy_sha256,
        "input_snapshot_sha256": input_snapshot_sha256,
        "strategy_id": strategy_id,
        "cohort_id": cohort_id,
        "cohort_kind": cohort_kind,
        "experiment_id": experiment_id,
        "experiment_arm": experiment_arm,
        "experiment_assignment_policy_sha256": assignment_policy_sha256,
        "assignment_receipt_sha256": assignment_receipt_sha256,
        "target_state": target_state.value,
        "probability_bp": probability_bp,
        "predicted_at": predicted_at.isoformat(),
        "horizon_at": horizon_at.isoformat(),
        "manual_prediction": False,
        "dependency_satisfied": False,
        "production_certification": "withheld",
        "certifies_slice": False,
    }
    return PredictionReceipt(
        contract_sha256=contract.contract_sha256,
        application_id=application_id,
        job_key=job_key,
        predictor_kind=predictor_kind,
        predictor_id=predictor_id,
        predictor_version=predictor_version,
        predictor_receipt_sha256=predictor_receipt_sha256,
        predictor_policy_sha256=predictor_policy_sha256,
        input_snapshot_sha256=input_snapshot_sha256,
        strategy_id=strategy_id,
        cohort_id=cohort_id,
        cohort_kind=cohort_kind,
        experiment_id=experiment_id,
        experiment_arm=experiment_arm,
        experiment_assignment_policy_sha256=assignment_policy_sha256,
        assignment_receipt_sha256=assignment_receipt_sha256,
        target_state=target_state,
        probability_bp=probability_bp,
        predicted_at=predicted_at.isoformat(),
        horizon_at=horizon_at.isoformat(),
        prediction_id=_content_hash(body),
    )


@dataclass(frozen=True)
class ScoredPrediction:
    prediction: PredictionReceipt
    timeline: StatusTimeline
    contract_sha256: str
    prediction_id: str
    application_id: str
    job_key: str
    predictor_policy_sha256: str
    cohort_id: str
    cohort_kind: str
    experiment_id: str | None
    experiment_arm: str | None
    timeline_id: str
    outcome_status: str
    resolution_at: str
    actual_bp: int | None
    squared_error_bp: int | None
    source_evidence_ids: tuple[str, ...]
    score_id: str
    outcome_attribution: str
    policy_promotion_authority: str = "withheld"
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa14.scored-prediction.v2"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source_evidence_ids",
            tuple(self.source_evidence_ids),
        )
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "prediction": self.prediction.document(),
            "timeline": self.timeline.document(),
            "contract_sha256": self.contract_sha256,
            "prediction_id": self.prediction_id,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "predictor_policy_sha256": self.predictor_policy_sha256,
            "cohort_id": self.cohort_id,
            "cohort_kind": self.cohort_kind,
            "experiment_id": self.experiment_id,
            "experiment_arm": self.experiment_arm,
            "timeline_id": self.timeline_id,
            "outcome_status": self.outcome_status,
            "resolution_at": self.resolution_at,
            "actual_bp": self.actual_bp,
            "squared_error_bp": self.squared_error_bp,
            "source_evidence_ids": self.source_evidence_ids,
            "outcome_attribution": self.outcome_attribution,
            "policy_promotion_authority": "withheld",
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["score_id"] = self.score_id
        return result

    def verify(self) -> None:
        if not isinstance(self.prediction, PredictionReceipt):
            raise TypeError("score requires a typed prediction receipt")
        if not isinstance(self.timeline, StatusTimeline):
            raise TypeError("score requires a typed status timeline")
        self.prediction.verify()
        self.timeline.verify()
        for value, label in (
            (self.contract_sha256, "score contract hash"),
            (self.prediction_id, "scored prediction ID"),
            (self.predictor_policy_sha256, "scored predictor policy hash"),
            (self.timeline_id, "score timeline ID"),
            (self.score_id, "score ID"),
        ):
            _digest(value, label)
        _required(self.application_id, "score application ID")
        _required(self.job_key, "score job key")
        _required(self.cohort_id, "score cohort ID")
        if self.cohort_kind not in COHORT_KINDS:
            raise ValueError("score cohort kind is unsupported")
        if (self.experiment_id is None) != (self.experiment_arm is None):
            raise ValueError("score experiment identity and arm must align")
        if self.experiment_id is not None:
            _digest(self.experiment_id, "score experiment ID")
            if self.experiment_arm not in EXPERIMENT_ARMS:
                raise ValueError("score experiment arm is unsupported")
        _aware_iso(self.resolution_at, "score resolution time")
        (
            expected_status,
            expected_attribution,
            expected_actual_bp,
            expected_error_bp,
            expected_resolution_at,
            expected_source_ids,
        ) = _derive_score_fields(self.prediction, self.timeline)
        if (
            self.contract_sha256
            != self.prediction.contract_sha256
            or self.prediction_id != self.prediction.prediction_id
            or self.application_id != self.prediction.application_id
            or self.application_id != self.timeline.application_id
            or self.job_key != self.prediction.job_key
            or self.job_key != self.timeline.job_key
            or self.predictor_policy_sha256
            != self.prediction.predictor_policy_sha256
            or self.cohort_id != self.prediction.cohort_id
            or self.cohort_kind != self.prediction.cohort_kind
            or self.experiment_id != self.prediction.experiment_id
            or self.experiment_arm != self.prediction.experiment_arm
            or self.timeline_id != self.timeline.timeline_id
            or self.outcome_status != expected_status
            or self.outcome_attribution != expected_attribution
            or self.actual_bp != expected_actual_bp
            or self.squared_error_bp != expected_error_bp
            or self.resolution_at != expected_resolution_at.isoformat()
            or self.source_evidence_ids != expected_source_ids
        ):
            raise ValueError(
                "score differs from its typed prediction and timeline"
            )
        if (
            len(self.source_evidence_ids)
            != len(set(self.source_evidence_ids))
        ):
            raise ValueError("score evidence identities must be unique")
        for value in self.source_evidence_ids:
            _digest(value, "score evidence identity")
        if (
            self.contract_sha256
            != FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256
            or self.policy_promotion_authority != "withheld"
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
        ):
            raise ValueError("local score cannot promote or certify")
        if self.schema_version != "jaa14.scored-prediction.v2":
            raise ValueError("scored prediction schema is unsupported")
        if self.score_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("scored prediction differs from exact content")


def _brier_bp(probability_bp: int, actual_bp: int) -> int:
    return ((probability_bp - actual_bp) ** 2 + 5_000) // 10_000


def _derive_score_fields(
    prediction: PredictionReceipt,
    timeline: StatusTimeline,
) -> tuple[str, str, int | None, int | None, datetime, tuple[str, ...]]:
    prediction.verify()
    timeline.verify()
    if (
        prediction.application_id != timeline.application_id
        or prediction.job_key != timeline.job_key
    ):
        raise ValueError(
            "prediction and timeline identify different applications"
        )
    predicted_at = datetime.fromisoformat(prediction.predicted_at)
    evidence_times = tuple(
        datetime.fromisoformat(value) for value in timeline.observed_at
    )
    if any(value <= predicted_at for value in evidence_times):
        raise ValueError(
            "prediction must predate every resolving evidence item"
        )
    path = (
        timeline.baseline_state,
        *(
            PipelineState(target)
            for _source, target in timeline.transitions
        ),
    )
    reached = prediction.target_state in path
    source_ids = timeline.evidence_ids
    if reached:
        if not evidence_times:
            raise ValueError(
                "progression requires explicit outcome evidence"
            )
        actual_bp = 10_000
        return (
            "progressed",
            "target_stage_observed",
            actual_bp,
            _brier_bp(prediction.probability_bp, actual_bp),
            evidence_times[-1],
            source_ids,
        )
    if timeline.final_state is PipelineState.REJECTED:
        if not evidence_times:
            raise ValueError("rejection requires explicit outcome evidence")
        actual_bp = 0
        return (
            "explicit_rejection",
            "explicit_employer_rejection",
            actual_bp,
            _brier_bp(prediction.probability_bp, actual_bp),
            evidence_times[-1],
            source_ids,
        )
    if timeline.final_state in CENSORED_TERMINAL_STATES:
        if not evidence_times:
            raise ValueError(
                "terminal censor requires explicit status evidence"
            )
        return (
            "censored",
            "candidate_or_expiry_censor",
            None,
            None,
            evidence_times[-1],
            source_ids,
        )
    horizon = datetime.fromisoformat(prediction.horizon_at)
    eligible_censors = tuple(
        datetime.fromisoformat(row.as_of)
        for row in timeline.censored_silence
        if datetime.fromisoformat(row.as_of) >= horizon
    )
    if not eligible_censors:
        raise ValueError(
            "outcome is unresolved; horizon censor evidence is required"
        )
    return (
        "censored",
        "censored_silence",
        None,
        None,
        max(eligible_censors),
        source_ids,
    )


def score_prediction(
    contract: OutcomeFeedbackContract,
    prediction: PredictionReceipt,
    timeline: StatusTimeline,
) -> ScoredPrediction:
    if contract != FROZEN_OUTCOME_FEEDBACK_CONTRACT:
        raise ValueError("scoring requires the canonical outcome contract")
    if not isinstance(prediction, PredictionReceipt):
        raise TypeError("scoring requires a PredictionReceipt")
    if not isinstance(timeline, StatusTimeline):
        raise TypeError("scoring requires a StatusTimeline")
    (
        outcome_status,
        attribution,
        actual_bp,
        error_bp,
        resolution_at,
        source_ids,
    ) = _derive_score_fields(prediction, timeline)
    if resolution_at <= datetime.fromisoformat(prediction.predicted_at):
        raise ValueError("outcome resolution must postdate prediction")
    body = {
        "schema_version": "jaa14.scored-prediction.v2",
        "prediction": prediction.document(),
        "timeline": timeline.document(),
        "contract_sha256": contract.contract_sha256,
        "prediction_id": prediction.prediction_id,
        "application_id": prediction.application_id,
        "job_key": prediction.job_key,
        "predictor_policy_sha256": prediction.predictor_policy_sha256,
        "cohort_id": prediction.cohort_id,
        "cohort_kind": prediction.cohort_kind,
        "experiment_id": prediction.experiment_id,
        "experiment_arm": prediction.experiment_arm,
        "timeline_id": timeline.timeline_id,
        "outcome_status": outcome_status,
        "resolution_at": resolution_at.isoformat(),
        "actual_bp": actual_bp,
        "squared_error_bp": error_bp,
        "source_evidence_ids": source_ids,
        "outcome_attribution": attribution,
        "policy_promotion_authority": "withheld",
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return ScoredPrediction(
        prediction=prediction,
        timeline=timeline,
        contract_sha256=contract.contract_sha256,
        prediction_id=prediction.prediction_id,
        application_id=prediction.application_id,
        job_key=prediction.job_key,
        predictor_policy_sha256=prediction.predictor_policy_sha256,
        cohort_id=prediction.cohort_id,
        cohort_kind=prediction.cohort_kind,
        experiment_id=prediction.experiment_id,
        experiment_arm=prediction.experiment_arm,
        timeline_id=timeline.timeline_id,
        outcome_status=outcome_status,
        resolution_at=resolution_at.isoformat(),
        actual_bp=actual_bp,
        squared_error_bp=error_bp,
        source_evidence_ids=source_ids,
        score_id=_content_hash(body),
        outcome_attribution=attribution,
    )


@dataclass(frozen=True)
class CalibrationReport:
    scores: tuple[ScoredPrediction, ...]
    contract_sha256: str
    predictor_policy_sha256: str
    cohort_id: str
    cohort_kind: str
    experiment_id: str | None
    experiment_arm: str | None
    application_ids: tuple[str, ...]
    score_ids: tuple[str, ...]
    resolved_count: int
    censored_count: int
    mean_brier_bp: int | None
    report_id: str
    policy_promotion_authority: str = "withheld"
    dependency_satisfied: bool = False
    schema_version: str = "jaa14.calibration-report.v2"

    def __post_init__(self) -> None:
        object.__setattr__(self, "scores", tuple(self.scores))
        object.__setattr__(
            self,
            "application_ids",
            tuple(self.application_ids),
        )
        object.__setattr__(self, "score_ids", tuple(self.score_ids))
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "scores": tuple(row.document() for row in self.scores),
            "contract_sha256": self.contract_sha256,
            "predictor_policy_sha256": self.predictor_policy_sha256,
            "cohort_id": self.cohort_id,
            "cohort_kind": self.cohort_kind,
            "experiment_id": self.experiment_id,
            "experiment_arm": self.experiment_arm,
            "application_ids": self.application_ids,
            "score_ids": self.score_ids,
            "resolved_count": self.resolved_count,
            "censored_count": self.censored_count,
            "mean_brier_bp": self.mean_brier_bp,
            "policy_promotion_authority": "withheld",
            "dependency_satisfied": False,
        }
        if include_identity:
            result["report_id"] = self.report_id
        return result

    def verify(self) -> None:
        if not self.scores or not all(
            isinstance(row, ScoredPrediction) for row in self.scores
        ):
            raise TypeError("calibration report requires typed scores")
        for row in self.scores:
            row.verify()
        for value, label in (
            (self.contract_sha256, "report contract hash"),
            (self.predictor_policy_sha256, "report predictor policy hash"),
            (self.report_id, "calibration report ID"),
        ):
            _digest(value, label)
        _required(self.cohort_id, "report cohort ID")
        if self.cohort_kind not in COHORT_KINDS:
            raise ValueError("report cohort kind is unsupported")
        if (self.experiment_id is None) != (self.experiment_arm is None):
            raise ValueError("report experiment identity and arm must align")
        if self.experiment_id is not None:
            _digest(self.experiment_id, "report experiment ID")
            if self.experiment_arm not in EXPERIMENT_ARMS:
                raise ValueError("report experiment arm is unsupported")
        if (
            not self.application_ids
            or len(self.application_ids) != len(set(self.application_ids))
            or len(self.application_ids) != len(self.score_ids)
            or not all(
                isinstance(value, str)
                and value.strip()
                and value == value.strip()
                for value in self.application_ids
            )
        ):
            raise ValueError(
                "calibration report requires unique application members"
            )
        if (
            not self.score_ids
            or len(self.score_ids) != len(set(self.score_ids))
        ):
            raise ValueError("calibration report requires unique scores")
        for value in self.score_ids:
            _digest(value, "calibration score ID")
        if (
            type(self.resolved_count) is not int
            or type(self.censored_count) is not int
            or self.resolved_count < 0
            or self.censored_count < 0
            or self.resolved_count + self.censored_count
            != len(self.score_ids)
        ):
            raise ValueError("calibration report counts are invalid")
        if self.resolved_count == 0:
            if self.mean_brier_bp is not None:
                raise ValueError("fully censored report cannot carry a score")
        elif (
            type(self.mean_brier_bp) is not int
            or not 0 <= self.mean_brier_bp <= 10_000
        ):
            raise ValueError("calibration mean Brier score is invalid")
        if (
            self.contract_sha256
            != FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256
            or self.policy_promotion_authority != "withheld"
            or self.dependency_satisfied is not False
        ):
            raise ValueError("local calibration report cannot promote")
        if self.schema_version != "jaa14.calibration-report.v2":
            raise ValueError("calibration report schema is unsupported")
        (
            expected_policy_id,
            expected_cohort_id,
            expected_cohort_kind,
            expected_experiment_id,
            expected_experiment_arm,
            expected_application_ids,
            expected_score_ids,
            expected_resolved_count,
            expected_censored_count,
            expected_mean_brier,
        ) = _derive_calibration_fields(self.scores)
        if (
            self.predictor_policy_sha256 != expected_policy_id
            or self.cohort_id != expected_cohort_id
            or self.cohort_kind != expected_cohort_kind
            or self.experiment_id != expected_experiment_id
            or self.experiment_arm != expected_experiment_arm
            or self.application_ids != expected_application_ids
            or self.score_ids != expected_score_ids
            or self.resolved_count != expected_resolved_count
            or self.censored_count != expected_censored_count
            or self.mean_brier_bp != expected_mean_brier
        ):
            raise ValueError(
                "calibration report differs from its typed scores"
            )
        if self.report_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("calibration report differs from exact scores")


def _derive_calibration_fields(
    rows: tuple[ScoredPrediction, ...],
) -> tuple[
    str,
    str,
    str,
    str | None,
    str | None,
    tuple[str, ...],
    tuple[str, ...],
    int,
    int,
    int | None,
]:
    if not rows or not all(isinstance(row, ScoredPrediction) for row in rows):
        raise TypeError("calibration report requires typed scores")
    for row in rows:
        row.verify()
    if len({row.score_id for row in rows}) != len(rows):
        raise ValueError("calibration report score identities must be unique")
    policy_ids = {row.predictor_policy_sha256 for row in rows}
    cohort_ids = {row.cohort_id for row in rows}
    cohort_kinds = {row.cohort_kind for row in rows}
    experiment_ids = {row.experiment_id for row in rows}
    experiment_arms = {row.experiment_arm for row in rows}
    application_ids = tuple(row.application_id for row in rows)
    if (
        len(policy_ids) != 1
        or len(cohort_ids) != 1
        or len(cohort_kinds) != 1
        or len(experiment_ids) != 1
        or len(experiment_arms) != 1
    ):
        raise ValueError(
            "calibration report cannot mix policy, cohort or experiment"
        )
    if len(application_ids) != len(set(application_ids)):
        raise ValueError(
            "calibration report application members must be unique"
        )
    resolved = tuple(
        row for row in rows if row.outcome_status != "censored"
    )
    censored_count = len(rows) - len(resolved)
    mean_brier = (
        None
        if not resolved
        else (
            sum(int(row.squared_error_bp) for row in resolved)
            + len(resolved) // 2
        )
        // len(resolved)
    )
    return (
        next(iter(policy_ids)),
        next(iter(cohort_ids)),
        next(iter(cohort_kinds)),
        next(iter(experiment_ids)),
        next(iter(experiment_arms)),
        application_ids,
        tuple(row.score_id for row in rows),
        len(resolved),
        censored_count,
        mean_brier,
    )


def compile_calibration_report(
    contract: OutcomeFeedbackContract,
    scores: Iterable[ScoredPrediction],
) -> CalibrationReport:
    if contract != FROZEN_OUTCOME_FEEDBACK_CONTRACT:
        raise ValueError("report requires the canonical outcome contract")
    rows = tuple(scores)
    (
        policy_id,
        cohort_id,
        cohort_kind,
        experiment_id,
        experiment_arm,
        application_ids,
        score_ids,
        resolved_count,
        censored_count,
        mean_brier,
    ) = _derive_calibration_fields(rows)
    body = {
        "schema_version": "jaa14.calibration-report.v2",
        "scores": tuple(row.document() for row in rows),
        "contract_sha256": contract.contract_sha256,
        "predictor_policy_sha256": policy_id,
        "cohort_id": cohort_id,
        "cohort_kind": cohort_kind,
        "experiment_id": experiment_id,
        "experiment_arm": experiment_arm,
        "application_ids": application_ids,
        "score_ids": score_ids,
        "resolved_count": resolved_count,
        "censored_count": censored_count,
        "mean_brier_bp": mean_brier,
        "policy_promotion_authority": "withheld",
        "dependency_satisfied": False,
    }
    return CalibrationReport(
        scores=rows,
        contract_sha256=contract.contract_sha256,
        predictor_policy_sha256=policy_id,
        cohort_id=cohort_id,
        cohort_kind=cohort_kind,
        experiment_id=experiment_id,
        experiment_arm=experiment_arm,
        application_ids=application_ids,
        score_ids=score_ids,
        resolved_count=resolved_count,
        censored_count=censored_count,
        mean_brier_bp=mean_brier,
        report_id=_content_hash(body),
    )


@dataclass(frozen=True)
class PromotionEvaluation:
    locked_baseline: CalibrationReport
    locked_candidate: CalibrationReport
    holdout_baseline: CalibrationReport
    holdout_candidate: CalibrationReport
    contract_sha256: str
    baseline_policy_sha256: str
    candidate_policy_sha256: str
    locked_baseline_report_id: str
    locked_candidate_report_id: str
    holdout_baseline_report_id: str
    holdout_candidate_report_id: str
    rollback_policy_sha256: str
    eligible_for_review: bool
    reason_codes: tuple[str, ...]
    evaluation_id: str
    promotion_authority: str = "withheld"
    applied: bool = False
    dependency_satisfied: bool = False
    certifies_slice: bool = False
    schema_version: str = "jaa14.promotion-evaluation.v2"

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        self.verify()

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "locked_baseline": self.locked_baseline.document(),
            "locked_candidate": self.locked_candidate.document(),
            "holdout_baseline": self.holdout_baseline.document(),
            "holdout_candidate": self.holdout_candidate.document(),
            "contract_sha256": self.contract_sha256,
            "baseline_policy_sha256": self.baseline_policy_sha256,
            "candidate_policy_sha256": self.candidate_policy_sha256,
            "locked_baseline_report_id": self.locked_baseline_report_id,
            "locked_candidate_report_id": self.locked_candidate_report_id,
            "holdout_baseline_report_id": self.holdout_baseline_report_id,
            "holdout_candidate_report_id": self.holdout_candidate_report_id,
            "rollback_policy_sha256": self.rollback_policy_sha256,
            "eligible_for_review": self.eligible_for_review,
            "reason_codes": self.reason_codes,
            "promotion_authority": "withheld",
            "applied": False,
            "dependency_satisfied": False,
            "certifies_slice": False,
        }
        if include_identity:
            result["evaluation_id"] = self.evaluation_id
        return result

    def verify(self) -> None:
        reports = (
            self.locked_baseline,
            self.locked_candidate,
            self.holdout_baseline,
            self.holdout_candidate,
        )
        if not all(isinstance(row, CalibrationReport) for row in reports):
            raise TypeError(
                "promotion review requires typed calibration reports"
            )
        for row in reports:
            row.verify()
        for value, label in (
            (self.contract_sha256, "promotion contract hash"),
            (self.baseline_policy_sha256, "baseline policy hash"),
            (self.candidate_policy_sha256, "candidate policy hash"),
            (self.locked_baseline_report_id, "locked baseline report ID"),
            (self.locked_candidate_report_id, "locked candidate report ID"),
            (self.holdout_baseline_report_id, "holdout baseline report ID"),
            (self.holdout_candidate_report_id, "holdout candidate report ID"),
            (self.rollback_policy_sha256, "rollback policy hash"),
            (self.evaluation_id, "promotion evaluation ID"),
        ):
            _digest(value, label)
        if self.baseline_policy_sha256 == self.candidate_policy_sha256:
            raise ValueError("promotion evaluation requires a new policy")
        if self.rollback_policy_sha256 != self.baseline_policy_sha256:
            raise ValueError("promotion rollback must bind the baseline policy")
        allowed_reasons = {
            "locked_non_regression",
            "holdout_improvement",
            "insufficient_resolved_evidence",
            "locked_regression",
            "holdout_not_improved",
        }
        if (
            not self.reason_codes
            or len(self.reason_codes) != len(set(self.reason_codes))
            or not set(self.reason_codes).issubset(allowed_reasons)
        ):
            raise ValueError("promotion evaluation reasons are invalid")
        eligible_reasons = (
            "locked_non_regression",
            "holdout_improvement",
        )
        if self.eligible_for_review is not (
            self.reason_codes == eligible_reasons
        ):
            raise ValueError("promotion review eligibility differs from reasons")
        if (
            self.contract_sha256
            != FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256
            or self.promotion_authority != "withheld"
            or self.applied is not False
            or self.dependency_satisfied is not False
            or self.certifies_slice is not False
        ):
            raise ValueError("local promotion evaluation cannot apply policy")
        if self.schema_version != "jaa14.promotion-evaluation.v2":
            raise ValueError("promotion evaluation schema is unsupported")
        (
            expected_baseline_policy,
            expected_candidate_policy,
            expected_eligible,
            expected_reasons,
        ) = _derive_promotion_fields(*reports)
        if (
            self.baseline_policy_sha256 != expected_baseline_policy
            or self.candidate_policy_sha256 != expected_candidate_policy
            or self.locked_baseline_report_id
            != self.locked_baseline.report_id
            or self.locked_candidate_report_id
            != self.locked_candidate.report_id
            or self.holdout_baseline_report_id
            != self.holdout_baseline.report_id
            or self.holdout_candidate_report_id
            != self.holdout_candidate.report_id
            or self.rollback_policy_sha256 != expected_baseline_policy
            or self.eligible_for_review is not expected_eligible
            or self.reason_codes != expected_reasons
        ):
            raise ValueError(
                "promotion evaluation differs from typed calibration reports"
            )
        if self.evaluation_id != _content_hash(
            self.document(include_identity=False)
        ):
            raise ValueError("promotion evaluation differs from exact reports")


def _derive_promotion_fields(
    locked_baseline: CalibrationReport,
    locked_candidate: CalibrationReport,
    holdout_baseline: CalibrationReport,
    holdout_candidate: CalibrationReport,
) -> tuple[str, str, bool, tuple[str, ...]]:
    reports = (
        locked_baseline,
        locked_candidate,
        holdout_baseline,
        holdout_candidate,
    )
    if not all(isinstance(row, CalibrationReport) for row in reports):
        raise TypeError("promotion review requires calibration reports")
    for row in reports:
        row.verify()
    if (
        locked_baseline.cohort_kind != "locked"
        or locked_candidate.cohort_kind != "locked"
        or holdout_baseline.cohort_kind not in {"holdout", "live"}
        or holdout_candidate.cohort_kind
        != holdout_baseline.cohort_kind
        or locked_baseline.cohort_id != locked_candidate.cohort_id
        or holdout_baseline.cohort_id != holdout_candidate.cohort_id
        or locked_baseline.cohort_id == holdout_baseline.cohort_id
    ):
        raise ValueError("promotion review requires distinct aligned cohorts")
    if (
        locked_baseline.application_ids
        != locked_candidate.application_ids
        or holdout_baseline.application_ids
        != holdout_candidate.application_ids
    ):
        raise ValueError(
            "promotion review requires identical cohort membership by policy"
        )
    experiment_id = locked_baseline.experiment_id
    if (
        experiment_id is None
        or any(row.experiment_id != experiment_id for row in reports)
        or locked_baseline.experiment_arm != "baseline"
        or holdout_baseline.experiment_arm != "baseline"
        or locked_candidate.experiment_arm != "treatment"
        or holdout_candidate.experiment_arm != "treatment"
    ):
        raise ValueError(
            "promotion review requires one aligned controlled experiment"
        )
    baseline_policy = locked_baseline.predictor_policy_sha256
    candidate_policy = locked_candidate.predictor_policy_sha256
    if (
        holdout_baseline.predictor_policy_sha256 != baseline_policy
        or holdout_candidate.predictor_policy_sha256 != candidate_policy
        or baseline_policy == candidate_policy
    ):
        raise ValueError("promotion reports do not bind two aligned policies")
    minimum = int(PROMOTION_POLICY["minimum_resolved_per_report"])
    insufficient = any(row.resolved_count < minimum for row in reports)
    reasons: tuple[str, ...]
    eligible = False
    if insufficient:
        reasons = ("insufficient_resolved_evidence",)
    else:
        locked_ok = (
            int(locked_candidate.mean_brier_bp)
            <= int(locked_baseline.mean_brier_bp)
        )
        holdout_ok = (
            int(holdout_candidate.mean_brier_bp)
            < int(holdout_baseline.mean_brier_bp)
        )
        if locked_ok and holdout_ok:
            reasons = ("locked_non_regression", "holdout_improvement")
            eligible = True
        else:
            reason_rows: list[str] = []
            if not locked_ok:
                reason_rows.append("locked_regression")
            if not holdout_ok:
                reason_rows.append("holdout_not_improved")
            reasons = tuple(reason_rows)
    return baseline_policy, candidate_policy, eligible, reasons


def evaluate_policy_candidate(
    contract: OutcomeFeedbackContract,
    *,
    locked_baseline: CalibrationReport,
    locked_candidate: CalibrationReport,
    holdout_baseline: CalibrationReport,
    holdout_candidate: CalibrationReport,
) -> PromotionEvaluation:
    if contract != FROZEN_OUTCOME_FEEDBACK_CONTRACT:
        raise ValueError("promotion review requires the canonical contract")
    (
        baseline_policy,
        candidate_policy,
        eligible,
        reasons,
    ) = _derive_promotion_fields(
        locked_baseline,
        locked_candidate,
        holdout_baseline,
        holdout_candidate,
    )
    body = {
        "schema_version": "jaa14.promotion-evaluation.v2",
        "locked_baseline": locked_baseline.document(),
        "locked_candidate": locked_candidate.document(),
        "holdout_baseline": holdout_baseline.document(),
        "holdout_candidate": holdout_candidate.document(),
        "contract_sha256": contract.contract_sha256,
        "baseline_policy_sha256": baseline_policy,
        "candidate_policy_sha256": candidate_policy,
        "locked_baseline_report_id": locked_baseline.report_id,
        "locked_candidate_report_id": locked_candidate.report_id,
        "holdout_baseline_report_id": holdout_baseline.report_id,
        "holdout_candidate_report_id": holdout_candidate.report_id,
        "rollback_policy_sha256": baseline_policy,
        "eligible_for_review": eligible,
        "reason_codes": reasons,
        "promotion_authority": "withheld",
        "applied": False,
        "dependency_satisfied": False,
        "certifies_slice": False,
    }
    return PromotionEvaluation(
        locked_baseline=locked_baseline,
        locked_candidate=locked_candidate,
        holdout_baseline=holdout_baseline,
        holdout_candidate=holdout_candidate,
        contract_sha256=contract.contract_sha256,
        baseline_policy_sha256=baseline_policy,
        candidate_policy_sha256=candidate_policy,
        locked_baseline_report_id=locked_baseline.report_id,
        locked_candidate_report_id=locked_candidate.report_id,
        holdout_baseline_report_id=holdout_baseline.report_id,
        holdout_candidate_report_id=holdout_candidate.report_id,
        rollback_policy_sha256=baseline_policy,
        eligible_for_review=eligible,
        reason_codes=reasons,
        evaluation_id=_content_hash(body),
    )
