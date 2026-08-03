"""Durable, non-promoting JAA-14 outcome calibration over live JAA-12 evidence.

The existing :mod:`career_automation.outcome_feedback` module defines the
immutable JAA-14 policy contract.  This module supplies the deliberately local
operational seam: predictions are committed before outcome evidence, official
JAA-12 events are appended, and calibration/promotion *evaluations* can be
derived without changing a policy, candidate fact, account, or external system.

There is no network, browser, model, connector, or policy-write capability in
this module.  SQLite tables are append-only and every row is content addressed.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from career_automation.lifecycle import LEGAL_TRANSITIONS
from career_automation.models import PipelineState
from career_automation.outcome_feedback import (
    COHORT_KINDS,
    EXPERIMENT_ARMS,
    FROZEN_OUTCOME_FEEDBACK_CONTRACT,
    TARGET_STATES,
    StrategyExperiment,
)
from career_automation.status_ingestion_live import (
    ApplicationReceiptBinding,
    ClassifiedStatusEvent,
    LiveStatusIngestionResult,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}$")
CANDIDATE_CENSORS = frozenset(
    {PipelineState.DECLINED, PipelineState.WITHDRAWN, PipelineState.EXPIRED}
)
RESOLVED_STATUSES = frozenset({"progressed", "explicit_rejection"})
MINIMUM_RESOLVED_PER_SUMMARY = 20


class OutcomeFeedbackLiveError(RuntimeError):
    """A live outcome-feedback invariant failed closed."""


class PredictionOrderError(OutcomeFeedbackLiveError):
    """A prediction was not demonstrably recorded before outcome evidence."""


class OutcomeEvidenceError(OutcomeFeedbackLiveError):
    """Outcome evidence was forged, duplicated, unbound, or insufficient."""


class ExperimentIdentificationError(OutcomeFeedbackLiveError):
    """An experiment did not isolate one deterministically assigned variable."""


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


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a normalized bounded identifier")
    return value


def _aware(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    return _aware(parsed, label)


def _utc_text(value: datetime) -> str:
    return _aware(value, "timestamp").astimezone(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _can_reach(source: PipelineState, target: PipelineState) -> bool:
    if source is target:
        return True
    seen = {source}
    stack = [source]
    while stack:
        current = stack.pop()
        for successor in LEGAL_TRANSITIONS.get(current, set()):
            if successor is target:
                return True
            if successor not in seen:
                seen.add(successor)
                stack.append(successor)
    return False


@dataclass(frozen=True)
class LivePrediction:
    binding_sha256: str
    application_id: str
    job_key: str
    receipt_sha256: str
    released_application_sha256: str
    release_manifest_sha256: str
    candidate_facts_sha256: str
    predictor_kind: str
    predictor_id: str
    predictor_version: str
    model_sha256: str
    data_sha256: str
    predictor_policy_sha256: str
    strategy_sha256: str
    cohort_id: str
    cohort_kind: str
    cohort_snapshot_sha256: str
    target_state: PipelineState
    probability_bp: int
    data_observed_through: str
    predicted_at: str
    horizon_at: str
    experiment_id: str | None
    experiment_variable: str | None
    experiment_arm: str | None
    assignment_receipt_sha256: str | None
    prediction_id: str
    manual_prediction: bool = False
    policy_promotion_authority: bool = False
    schema_version: str = "jaa14.live-pre-outcome-prediction.v1"

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "outcome_contract_sha256": FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256,
            "binding_sha256": self.binding_sha256,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "receipt_sha256": self.receipt_sha256,
            "released_application_sha256": self.released_application_sha256,
            "release_manifest_sha256": self.release_manifest_sha256,
            "candidate_facts_sha256": self.candidate_facts_sha256,
            "predictor_kind": self.predictor_kind,
            "predictor_id": self.predictor_id,
            "predictor_version": self.predictor_version,
            "model_sha256": self.model_sha256,
            "data_sha256": self.data_sha256,
            "predictor_policy_sha256": self.predictor_policy_sha256,
            "strategy_sha256": self.strategy_sha256,
            "cohort_id": self.cohort_id,
            "cohort_kind": self.cohort_kind,
            "cohort_snapshot_sha256": self.cohort_snapshot_sha256,
            "target_state": self.target_state.value,
            "probability_bp": self.probability_bp,
            "data_observed_through": self.data_observed_through,
            "predicted_at": self.predicted_at,
            "horizon_at": self.horizon_at,
            "experiment_id": self.experiment_id,
            "experiment_variable": self.experiment_variable,
            "experiment_arm": self.experiment_arm,
            "assignment_receipt_sha256": self.assignment_receipt_sha256,
            "manual_prediction": False,
            "policy_promotion_authority": False,
        }
        if include_identity:
            result["prediction_id"] = self.prediction_id
        return result

    def verify(self) -> None:
        for value, label in (
            (self.binding_sha256, "binding hash"),
            (self.receipt_sha256, "receipt hash"),
            (self.released_application_sha256, "released application hash"),
            (self.release_manifest_sha256, "release manifest hash"),
            (self.candidate_facts_sha256, "candidate facts hash"),
            (self.model_sha256, "model hash"),
            (self.data_sha256, "data hash"),
            (self.predictor_policy_sha256, "policy hash"),
            (self.strategy_sha256, "strategy hash"),
            (self.cohort_snapshot_sha256, "cohort snapshot hash"),
            (self.prediction_id, "prediction identity"),
        ):
            _digest(value, label)
        for value, label in (
            (self.application_id, "application ID"),
            (self.job_key, "job key"),
            (self.predictor_id, "predictor ID"),
            (self.predictor_version, "predictor version"),
            (self.cohort_id, "cohort ID"),
        ):
            _identifier(value, label)
        if self.predictor_kind not in {"configured_model", "deterministic_policy"}:
            raise ValueError("predictor kind is unsupported")
        if self.cohort_kind not in COHORT_KINDS:
            raise ValueError("cohort kind is unsupported")
        if not isinstance(self.target_state, PipelineState) or self.target_state not in TARGET_STATES:
            raise ValueError("prediction target state is unsupported")
        if type(self.probability_bp) is not int or not 0 <= self.probability_bp <= 10_000:
            raise ValueError("probability must be integer basis points")
        data_through = _parse_time(self.data_observed_through, "data cutoff")
        predicted = _parse_time(self.predicted_at, "prediction time")
        horizon = _parse_time(self.horizon_at, "prediction horizon")
        if not data_through < predicted < horizon:
            raise PredictionOrderError("data cutoff, prediction, and horizon must be ordered")
        experiment_values = (
            self.experiment_id,
            self.experiment_variable,
            self.experiment_arm,
            self.assignment_receipt_sha256,
        )
        if any(value is None for value in experiment_values) and any(
            value is not None for value in experiment_values
        ):
            raise ExperimentIdentificationError("experiment identities must be all present or absent")
        if self.experiment_id is not None:
            _digest(self.experiment_id, "experiment ID")
            _digest(self.assignment_receipt_sha256, "assignment receipt")
            _identifier(self.experiment_variable, "experiment variable")
            if self.experiment_arm not in EXPERIMENT_ARMS:
                raise ExperimentIdentificationError("experiment arm is unsupported")
        if self.manual_prediction is not False or self.policy_promotion_authority is not False:
            raise ValueError("live prediction cannot be manual or promote policy")
        if self.schema_version != "jaa14.live-pre-outcome-prediction.v1":
            raise ValueError("live prediction schema is unsupported")
        if self.prediction_id != _content_hash(self.document(include_identity=False)):
            raise ValueError("prediction differs from its content identity")


@dataclass(frozen=True)
class LiveOutcome:
    prediction_id: str
    application_id: str
    job_key: str
    status_result_sha256: str
    outcome_status: str
    outcome_attribution: str
    resolution_at: str
    actual_bp: int | None
    squared_error_bp: int | None
    source_event_sha256s: tuple[str, ...]
    source_file_sha256s: tuple[str, ...]
    outcome_id: str
    policy_promotion_authority: bool = False
    schema_version: str = "jaa14.live-outcome.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_event_sha256s", tuple(self.source_event_sha256s))
        object.__setattr__(self, "source_file_sha256s", tuple(self.source_file_sha256s))
        for value, label in (
            (self.prediction_id, "prediction ID"),
            (self.status_result_sha256, "status result hash"),
            (self.outcome_id, "outcome ID"),
        ):
            _digest(value, label)
        if self.outcome_status not in {*RESOLVED_STATUSES, "censored"}:
            raise ValueError("outcome status is unsupported")
        if self.outcome_status in RESOLVED_STATUSES:
            if self.actual_bp not in {0, 10_000} or not isinstance(self.squared_error_bp, int):
                raise ValueError("resolved outcome requires a binary score")
            if not self.source_event_sha256s or not self.source_file_sha256s:
                raise OutcomeEvidenceError("resolved outcome requires source-backed events")
        elif self.actual_bp is not None or self.squared_error_bp is not None:
            raise ValueError("censoring cannot be treated as a negative score")
        if len(set(self.source_event_sha256s)) != len(self.source_event_sha256s):
            raise OutcomeEvidenceError("outcome contains duplicate events")
        for value in (*self.source_event_sha256s, *self.source_file_sha256s):
            _digest(value, "outcome evidence hash")
        _parse_time(self.resolution_at, "outcome resolution time")
        if self.policy_promotion_authority is not False:
            raise ValueError("outcome cannot promote policy")
        if self.schema_version != "jaa14.live-outcome.v1":
            raise ValueError("live outcome schema is unsupported")
        if self.outcome_id != _content_hash(self.document(include_identity=False)):
            raise ValueError("outcome differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "prediction_id": self.prediction_id,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "status_result_sha256": self.status_result_sha256,
            "outcome_status": self.outcome_status,
            "outcome_attribution": self.outcome_attribution,
            "resolution_at": self.resolution_at,
            "actual_bp": self.actual_bp,
            "squared_error_bp": self.squared_error_bp,
            "source_event_sha256s": self.source_event_sha256s,
            "source_file_sha256s": self.source_file_sha256s,
            "policy_promotion_authority": False,
        }
        if include_identity:
            result["outcome_id"] = self.outcome_id
        return result


@dataclass(frozen=True)
class CalibrationSummary:
    predictor_policy_sha256: str
    model_sha256: str
    data_sha256: str
    cohort_id: str
    cohort_kind: str
    cohort_snapshot_sha256: str
    application_ids: tuple[str, ...]
    prediction_ids: tuple[str, ...]
    outcome_ids: tuple[str, ...]
    resolved_count: int
    censored_count: int
    mean_brier_bp: int | None
    calibration_bins: tuple[tuple[int, int, int, int], ...]
    summary_id: str
    policy_promotion_authority: bool = False
    schema_version: str = "jaa14.live-calibration-summary.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "application_ids", tuple(self.application_ids))
        object.__setattr__(self, "prediction_ids", tuple(self.prediction_ids))
        object.__setattr__(self, "outcome_ids", tuple(self.outcome_ids))
        object.__setattr__(
            self, "calibration_bins", tuple(tuple(row) for row in self.calibration_bins)
        )
        for value, label in (
            (self.predictor_policy_sha256, "summary policy hash"),
            (self.model_sha256, "summary model hash"),
            (self.data_sha256, "summary data hash"),
            (self.cohort_snapshot_sha256, "summary cohort snapshot hash"),
            (self.summary_id, "summary identity"),
        ):
            _digest(value, label)
        _identifier(self.cohort_id, "summary cohort ID")
        if self.cohort_kind not in COHORT_KINDS:
            raise ValueError("summary cohort kind is unsupported")
        if (
            not self.prediction_ids
            or len(self.application_ids) != len(self.prediction_ids)
            or len(self.prediction_ids) != len(self.outcome_ids)
            or len(set(self.application_ids)) != len(self.application_ids)
            or len(set(self.prediction_ids)) != len(self.prediction_ids)
            or len(set(self.outcome_ids)) != len(self.outcome_ids)
        ):
            raise ValueError("summary membership must be unique and aligned")
        for value in (*self.prediction_ids, *self.outcome_ids):
            _digest(value, "summary member identity")
        if (
            type(self.resolved_count) is not int
            or type(self.censored_count) is not int
            or self.resolved_count < 0
            or self.censored_count < 0
            or self.resolved_count + self.censored_count != len(self.prediction_ids)
        ):
            raise ValueError("summary counts are inconsistent")
        if self.resolved_count == 0:
            if self.mean_brier_bp is not None:
                raise ValueError("fully censored summary cannot carry a Brier score")
        elif type(self.mean_brier_bp) is not int or not 0 <= self.mean_brier_bp <= 10_000:
            raise ValueError("summary Brier score is invalid")
        for low, count, predicted_mean, actual_mean in self.calibration_bins:
            if (
                low not in range(0, 10_000, 1_000)
                or type(count) is not int
                or count <= 0
                or not 0 <= predicted_mean <= 10_000
                or not 0 <= actual_mean <= 10_000
            ):
                raise ValueError("summary calibration bin is invalid")
        if self.policy_promotion_authority is not False:
            raise ValueError("calibration summary cannot promote policy")
        if self.schema_version != "jaa14.live-calibration-summary.v1":
            raise ValueError("calibration summary schema is unsupported")
        if self.summary_id != _content_hash(self.document(include_identity=False)):
            raise ValueError("calibration summary differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "predictor_policy_sha256": self.predictor_policy_sha256,
            "model_sha256": self.model_sha256,
            "data_sha256": self.data_sha256,
            "cohort_id": self.cohort_id,
            "cohort_kind": self.cohort_kind,
            "cohort_snapshot_sha256": self.cohort_snapshot_sha256,
            "application_ids": self.application_ids,
            "prediction_ids": self.prediction_ids,
            "outcome_ids": self.outcome_ids,
            "resolved_count": self.resolved_count,
            "censored_count": self.censored_count,
            "mean_brier_bp": self.mean_brier_bp,
            "calibration_bins": self.calibration_bins,
            "policy_promotion_authority": False,
        }
        if include_identity:
            result["summary_id"] = self.summary_id
        return result


@dataclass(frozen=True)
class PromotionEvaluation:
    baseline_policy_sha256: str
    candidate_policy_sha256: str
    locked_baseline_summary_id: str
    locked_candidate_summary_id: str
    holdout_baseline_summary_id: str
    holdout_candidate_summary_id: str
    rollback_policy_sha256: str | None
    upstream_jaa13_certification_sha256: str | None
    locked_non_regression_evidence_sha256: str | None
    independent_holdout_evidence_sha256: str | None
    eligible_for_independent_review: bool
    reason_codes: tuple[str, ...]
    evaluation_id: str
    promotion_authority: bool = False
    applied: bool = False
    schema_version: str = "jaa14.live-policy-promotion-evaluation.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        for value, label in (
            (self.baseline_policy_sha256, "baseline policy hash"),
            (self.candidate_policy_sha256, "candidate policy hash"),
            (self.locked_baseline_summary_id, "locked baseline summary ID"),
            (self.locked_candidate_summary_id, "locked candidate summary ID"),
            (self.holdout_baseline_summary_id, "holdout baseline summary ID"),
            (self.holdout_candidate_summary_id, "holdout candidate summary ID"),
            (self.evaluation_id, "evaluation identity"),
        ):
            _digest(value, label)
        for optional, label in (
            (self.rollback_policy_sha256, "rollback policy hash"),
            (self.upstream_jaa13_certification_sha256, "JAA-13 certification hash"),
            (self.locked_non_regression_evidence_sha256, "locked evidence hash"),
            (self.independent_holdout_evidence_sha256, "holdout evidence hash"),
        ):
            if optional is not None:
                _digest(optional, label)
        if not self.reason_codes or len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("evaluation reasons must be non-empty and unique")
        if self.eligible_for_independent_review is not (
            self.reason_codes == ("all_evaluation_gates_satisfied",)
        ):
            raise ValueError("evaluation eligibility differs from its gate reasons")
        if self.promotion_authority is not False or self.applied is not False:
            raise ValueError("evaluation can neither promote nor apply policy")
        if self.schema_version != "jaa14.live-policy-promotion-evaluation.v1":
            raise ValueError("promotion evaluation schema is unsupported")
        if self.evaluation_id != _content_hash(self.document(include_identity=False)):
            raise ValueError("promotion evaluation differs from its content identity")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "baseline_policy_sha256": self.baseline_policy_sha256,
            "candidate_policy_sha256": self.candidate_policy_sha256,
            "locked_baseline_summary_id": self.locked_baseline_summary_id,
            "locked_candidate_summary_id": self.locked_candidate_summary_id,
            "holdout_baseline_summary_id": self.holdout_baseline_summary_id,
            "holdout_candidate_summary_id": self.holdout_candidate_summary_id,
            "rollback_policy_sha256": self.rollback_policy_sha256,
            "upstream_jaa13_certification_sha256": self.upstream_jaa13_certification_sha256,
            "locked_non_regression_evidence_sha256": self.locked_non_regression_evidence_sha256,
            "independent_holdout_evidence_sha256": self.independent_holdout_evidence_sha256,
            "eligible_for_independent_review": self.eligible_for_independent_review,
            "reason_codes": self.reason_codes,
            "promotion_authority": False,
            "applied": False,
        }
        if include_identity:
            result["evaluation_id"] = self.evaluation_id
        return result


def _prediction_from_json(encoded: str) -> LivePrediction:
    row = json.loads(encoded)
    row.pop("outcome_contract_sha256", None)
    row["target_state"] = PipelineState(row["target_state"])
    row["prediction_id"] = row.pop("prediction_id")
    prediction = LivePrediction(**row)
    prediction.verify()
    return prediction


class OutcomeFeedbackLedger:
    """Append-only prediction, event, outcome, and evaluation ledger."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS predictions (
                    prediction_id TEXT PRIMARY KEY,
                    application_id TEXT NOT NULL,
                    job_key TEXT NOT NULL,
                    predicted_at TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    cohort_id TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_events (
                    event_sha256 TEXT PRIMARY KEY,
                    observation_sha256 TEXT NOT NULL UNIQUE,
                    application_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outcomes (
                    outcome_id TEXT PRIMARY KEY,
                    prediction_id TEXT NOT NULL,
                    resolution_at TEXT NOT NULL,
                    outcome_status TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    FOREIGN KEY(prediction_id) REFERENCES predictions(prediction_id)
                );
                CREATE TABLE IF NOT EXISTS evaluations (
                    evaluation_id TEXT PRIMARY KEY,
                    record_sha256 TEXT NOT NULL,
                    record_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS predictions_group
                    ON predictions(policy_sha256,cohort_id);
                CREATE INDEX IF NOT EXISTS outcomes_prediction
                    ON outcomes(prediction_id,resolution_at);
                """
            )
            for table in ("predictions", "source_events", "outcomes", "evaluations"):
                connection.executescript(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END;
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END;
                    """
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _insert_exact(
        connection: sqlite3.Connection,
        *,
        table: str,
        identity_column: str,
        identity: str,
        columns: tuple[str, ...],
        values: tuple[object, ...],
        record_sha256: str,
        encoded: str,
    ) -> None:
        existing = connection.execute(
            f"SELECT record_sha256,record_json FROM {table} WHERE {identity_column}=?",
            (identity,),
        ).fetchone()
        if existing is None:
            names = (*columns, "record_sha256", "record_json")
            placeholders = ",".join("?" for _ in names)
            connection.execute(
                f"INSERT INTO {table}({','.join(names)}) VALUES({placeholders})",
                (*values, record_sha256, encoded),
            )
        elif existing != (record_sha256, encoded):
            raise OutcomeFeedbackLiveError(
                f"append-only {table} identity already binds different content"
            )

    def record_prediction(
        self,
        *,
        binding: ApplicationReceiptBinding,
        candidate_facts_sha256: str,
        predictor_kind: str,
        predictor_id: str,
        predictor_version: str,
        model_sha256: str,
        data_sha256: str,
        predictor_policy_sha256: str,
        strategy_sha256: str,
        cohort_id: str,
        cohort_kind: str,
        cohort_snapshot_sha256: str,
        target_state: PipelineState,
        probability_bp: int,
        data_observed_through: datetime,
        predicted_at: datetime,
        horizon_at: datetime,
        experiment: StrategyExperiment | None = None,
    ) -> LivePrediction:
        if not isinstance(binding, ApplicationReceiptBinding):
            raise TypeError("prediction requires a JAA-12 application binding")
        _aware(data_observed_through, "data cutoff")
        _aware(predicted_at, "prediction time")
        _aware(horizon_at, "prediction horizon")
        experiment_id = variable = arm = assignment = None
        if experiment is not None:
            if not isinstance(experiment, StrategyExperiment):
                raise TypeError("experiment must be StrategyExperiment")
            experiment.verify()
            if len(experiment.variable_names) != 1:
                raise ExperimentIdentificationError("experiment must change exactly one variable")
            if _parse_time(experiment.created_at, "experiment creation") >= predicted_at:
                raise ExperimentIdentificationError("experiment must predate assignment")
            experiment_id = experiment.experiment_id
            variable = experiment.variable_names[0]
            assignment_basis = {
                "schema_version": "jaa14.live-experiment-assignment.v1",
                "experiment_id": experiment_id,
                "assignment_policy_sha256": experiment.assignment_policy_sha256,
                "application_id": binding.application_id,
                "job_key": binding.job_key,
                "cohort_id": cohort_id,
                "cohort_snapshot_sha256": cohort_snapshot_sha256,
            }
            assignment = _content_hash(assignment_basis)
            arm = EXPERIMENT_ARMS[int(assignment[-1], 16) % len(EXPERIMENT_ARMS)]
        body = {
            "schema_version": "jaa14.live-pre-outcome-prediction.v1",
            "outcome_contract_sha256": FROZEN_OUTCOME_FEEDBACK_CONTRACT.contract_sha256,
            "binding_sha256": binding.binding_sha256,
            "application_id": binding.application_id,
            "job_key": binding.job_key,
            "receipt_sha256": binding.receipt_sha256,
            "released_application_sha256": binding.released_application_sha256,
            "release_manifest_sha256": binding.release_manifest_sha256,
            "candidate_facts_sha256": candidate_facts_sha256,
            "predictor_kind": predictor_kind,
            "predictor_id": predictor_id,
            "predictor_version": predictor_version,
            "model_sha256": model_sha256,
            "data_sha256": data_sha256,
            "predictor_policy_sha256": predictor_policy_sha256,
            "strategy_sha256": strategy_sha256,
            "cohort_id": cohort_id,
            "cohort_kind": cohort_kind,
            "cohort_snapshot_sha256": cohort_snapshot_sha256,
            "target_state": target_state.value,
            "probability_bp": probability_bp,
            "data_observed_through": _utc_text(data_observed_through),
            "predicted_at": _utc_text(predicted_at),
            "horizon_at": _utc_text(horizon_at),
            "experiment_id": experiment_id,
            "experiment_variable": variable,
            "experiment_arm": arm,
            "assignment_receipt_sha256": assignment,
            "manual_prediction": False,
            "policy_promotion_authority": False,
        }
        prediction = LivePrediction(
            **{
                key: value
                for key, value in body.items()
                if key
                not in {
                    "schema_version",
                    "outcome_contract_sha256",
                    "target_state",
                }
            },
            target_state=target_state,
            prediction_id=_content_hash(body),
        )
        prediction.verify()
        encoded = _canonical_json(prediction.document())
        record_sha256 = hashlib.sha256(encoded.encode()).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_events = connection.execute(
                "SELECT observed_at,record_json FROM source_events WHERE application_id=?",
                (prediction.application_id,),
            ).fetchall()
            data_cutoff = _parse_time(prediction.data_observed_through, "data cutoff")
            for observed_at, encoded_event in existing_events:
                event_document = json.loads(str(encoded_event))
                state_value = event_document.get("classified_state")
                state = None if state_value is None else PipelineState(state_value)
                resolving = state in {PipelineState.REJECTED, *CANDIDATE_CENSORS} or (
                    state is not None
                    and state not in {PipelineState.REJECTED, *CANDIDATE_CENSORS}
                    and _can_reach(prediction.target_state, state)
                )
                if resolving:
                    raise PredictionOrderError(
                        "prediction cannot be appended after source-backed resolving evidence"
                    )
                if _parse_time(str(observed_at), "prior status observation") > data_cutoff:
                    raise PredictionOrderError(
                        "prior non-resolving evidence is outside the prediction data cutoff"
                    )
            self._insert_exact(
                connection,
                table="predictions",
                identity_column="prediction_id",
                identity=prediction.prediction_id,
                columns=(
                    "prediction_id",
                    "application_id",
                    "job_key",
                    "predicted_at",
                    "policy_sha256",
                    "cohort_id",
                ),
                values=(
                    prediction.prediction_id,
                    prediction.application_id,
                    prediction.job_key,
                    prediction.predicted_at,
                    prediction.predictor_policy_sha256,
                    prediction.cohort_id,
                ),
                record_sha256=record_sha256,
                encoded=encoded,
            )
            connection.commit()
        return prediction

    def _load_prediction(self, prediction_id: str) -> LivePrediction:
        _digest(prediction_id, "prediction ID")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM predictions WHERE prediction_id=?", (prediction_id,)
            ).fetchone()
        if row is None:
            raise OutcomeEvidenceError("prediction is not durably recorded")
        return _prediction_from_json(str(row[0]))

    def score_status(
        self,
        *,
        prediction_id: str,
        status: LiveStatusIngestionResult,
        current_candidate_facts_sha256: str,
        as_of: datetime,
    ) -> LiveOutcome:
        prediction = self._load_prediction(prediction_id)
        _digest(current_candidate_facts_sha256, "current candidate facts hash")
        _aware(as_of, "outcome assessment time")
        if current_candidate_facts_sha256 != prediction.candidate_facts_sha256:
            raise OutcomeEvidenceError("untrusted candidate fact change is not outcome evidence")
        if not isinstance(status, LiveStatusIngestionResult):
            raise TypeError("scoring requires a live JAA-12 ingestion result")
        status.__post_init__()
        if status.binding_sha256 != prediction.binding_sha256:
            raise OutcomeEvidenceError("status result binds another released application")
        events = tuple(status.events)
        if len({row.event_sha256 for row in events}) != len(events):
            raise OutcomeEvidenceError("duplicate status events are not accepted")
        predicted_at = _parse_time(prediction.predicted_at, "prediction time")
        source_hashes: set[str] = set()
        classified: list[ClassifiedStatusEvent] = []
        data_cutoff = _parse_time(prediction.data_observed_through, "data cutoff")
        for event in events:
            event.__post_init__()
            if (
                event.application_id != prediction.application_id
                or event.job_key != prediction.job_key
                or event.receipt_sha256 != prediction.receipt_sha256
            ):
                raise OutcomeEvidenceError("status event identity differs from prediction")
            event_time = _parse_time(event.observed_at, "status observation")
            if event_time <= predicted_at and event_time > data_cutoff:
                raise PredictionOrderError(
                    "pre-prediction status evidence is outside the declared data cutoff"
                )
            for source in event.sources:
                source_hashes.add(source.source_sha256)
            if event.classified_state is not None:
                classified.append(event)
        leakage_hashes = {
            prediction.model_sha256,
            prediction.data_sha256,
            prediction.candidate_facts_sha256,
        }
        if source_hashes & leakage_hashes:
            raise OutcomeEvidenceError("prediction inputs leak resolving source evidence")
        progressed_event = next(
            (
                row
                for row in classified
                if row.classified_state is not None
                and row.classified_state not in {PipelineState.REJECTED, *CANDIDATE_CENSORS}
                and _can_reach(prediction.target_state, row.classified_state)
            ),
            None,
        )
        rejection_event = next(
            (row for row in classified if row.classified_state is PipelineState.REJECTED),
            None,
        )
        censor_event = next(
            (row for row in classified if row.classified_state in CANDIDATE_CENSORS),
            None,
        )
        for resolving_event in (progressed_event, rejection_event, censor_event):
            if resolving_event is not None and _parse_time(
                resolving_event.observed_at, "resolving observation"
            ) <= predicted_at:
                raise PredictionOrderError("post-hoc prediction detected from resolving evidence")
        if progressed_event is not None:
            outcome_status = "progressed"
            attribution = "source_backed_target_stage"
            actual = 10_000
            resolution = _parse_time(progressed_event.observed_at, "progression time")
        elif rejection_event is not None:
            outcome_status = "explicit_rejection"
            attribution = "source_backed_employer_rejection"
            actual = 0
            resolution = _parse_time(rejection_event.observed_at, "rejection time")
        elif censor_event is not None:
            outcome_status = "censored"
            attribution = "source_backed_candidate_or_expiry_censor"
            actual = None
            resolution = _parse_time(censor_event.observed_at, "censor time")
        elif as_of >= _parse_time(prediction.horizon_at, "prediction horizon"):
            outcome_status = "censored"
            attribution = "censored_silence_not_rejection"
            actual = None
            resolution = as_of
        else:
            raise OutcomeEvidenceError("prediction remains unresolved before its horizon")
        error = (
            None
            if actual is None
            else ((prediction.probability_bp - actual) ** 2 + 5_000) // 10_000
        )
        event_ids = tuple(row.event_sha256 for row in classified)
        file_ids = tuple(sorted(source_hashes))
        body = {
            "schema_version": "jaa14.live-outcome.v1",
            "prediction_id": prediction.prediction_id,
            "application_id": prediction.application_id,
            "job_key": prediction.job_key,
            "status_result_sha256": status.result_sha256,
            "outcome_status": outcome_status,
            "outcome_attribution": attribution,
            "resolution_at": _utc_text(resolution),
            "actual_bp": actual,
            "squared_error_bp": error,
            "source_event_sha256s": event_ids,
            "source_file_sha256s": file_ids,
            "policy_promotion_authority": False,
        }
        outcome = LiveOutcome(
            **{key: value for key, value in body.items() if key != "schema_version"},
            outcome_id=_content_hash(body),
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for event in events:
                encoded_event = _canonical_json(event.document())
                event_record_hash = hashlib.sha256(encoded_event.encode()).hexdigest()
                existing_observation = connection.execute(
                    "SELECT event_sha256,record_json FROM source_events WHERE observation_sha256=?",
                    (event.observation_sha256,),
                ).fetchone()
                if existing_observation is not None and existing_observation != (
                    event.event_sha256,
                    encoded_event,
                ):
                    raise OutcomeEvidenceError("observation identity binds forged event content")
                self._insert_exact(
                    connection,
                    table="source_events",
                    identity_column="event_sha256",
                    identity=event.event_sha256,
                    columns=(
                        "event_sha256",
                        "observation_sha256",
                        "application_id",
                        "observed_at",
                    ),
                    values=(
                        event.event_sha256,
                        event.observation_sha256,
                        event.application_id,
                        event.observed_at,
                    ),
                    record_sha256=event_record_hash,
                    encoded=encoded_event,
                )
            encoded = _canonical_json(outcome.document())
            self._insert_exact(
                connection,
                table="outcomes",
                identity_column="outcome_id",
                identity=outcome.outcome_id,
                columns=(
                    "outcome_id",
                    "prediction_id",
                    "resolution_at",
                    "outcome_status",
                ),
                values=(
                    outcome.outcome_id,
                    outcome.prediction_id,
                    outcome.resolution_at,
                    outcome.outcome_status,
                ),
                record_sha256=hashlib.sha256(encoded.encode()).hexdigest(),
                encoded=encoded,
            )
            connection.commit()
        return outcome

    def calibration_summary(
        self,
        *,
        predictor_policy_sha256: str,
        model_sha256: str,
        data_sha256: str,
        cohort_id: str,
        cohort_kind: str,
        cohort_snapshot_sha256: str,
    ) -> CalibrationSummary:
        for value, label in (
            (predictor_policy_sha256, "policy hash"),
            (model_sha256, "model hash"),
            (data_sha256, "data hash"),
            (cohort_snapshot_sha256, "cohort snapshot hash"),
        ):
            _digest(value, label)
        _identifier(cohort_id, "cohort ID")
        if cohort_kind not in COHORT_KINDS:
            raise ValueError("cohort kind is unsupported")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json FROM predictions WHERE policy_sha256=? AND cohort_id=?",
                (predictor_policy_sha256, cohort_id),
            ).fetchall()
            predictions = tuple(_prediction_from_json(str(row[0])) for row in rows)
            predictions = tuple(
                row
                for row in predictions
                if row.model_sha256 == model_sha256
                and row.data_sha256 == data_sha256
                and row.cohort_kind == cohort_kind
                and row.cohort_snapshot_sha256 == cohort_snapshot_sha256
            )
            if not predictions:
                raise OutcomeEvidenceError("calibration group contains no predictions")
            selected: list[tuple[LivePrediction, LiveOutcome]] = []
            for prediction in predictions:
                outcome_rows = connection.execute(
                    "SELECT record_json FROM outcomes WHERE prediction_id=? ORDER BY resolution_at",
                    (prediction.prediction_id,),
                ).fetchall()
                outcomes = []
                for raw in outcome_rows:
                    document = json.loads(str(raw[0]))
                    document.pop("schema_version", None)
                    outcomes.append(LiveOutcome(**document))
                resolved = [row for row in outcomes if row.outcome_status in RESOLVED_STATUSES]
                if len({row.actual_bp for row in resolved}) > 1:
                    raise OutcomeEvidenceError("one prediction has contradictory explicit outcomes")
                if resolved:
                    selected.append((prediction, resolved[0]))
                elif outcomes:
                    selected.append((prediction, outcomes[-1]))
        if not selected:
            raise OutcomeEvidenceError("calibration group contains no assessed outcomes")
        selected.sort(key=lambda pair: pair[0].application_id)
        resolved_pairs = [pair for pair in selected if pair[1].outcome_status in RESOLVED_STATUSES]
        brier = (
            None
            if not resolved_pairs
            else (sum(int(pair[1].squared_error_bp) for pair in resolved_pairs) + len(resolved_pairs) // 2)
            // len(resolved_pairs)
        )
        bins: list[tuple[int, int, int, int]] = []
        for low in range(0, 10_000, 1_000):
            bucket = [
                pair for pair in resolved_pairs if low <= pair[0].probability_bp <= low + 999
            ]
            if bucket:
                bins.append(
                    (
                        low,
                        len(bucket),
                        sum(pair[0].probability_bp for pair in bucket) // len(bucket),
                        sum(int(pair[1].actual_bp) for pair in bucket) // len(bucket),
                    )
                )
        # Include exact 100% forecasts in the final bucket.
        exact = [pair for pair in resolved_pairs if pair[0].probability_bp == 10_000]
        if exact:
            if bins and bins[-1][0] == 9_000:
                low, count, predicted_sum, actual_sum = bins[-1]
                prior = [pair for pair in resolved_pairs if low <= pair[0].probability_bp <= 9_999]
                combined = [*prior, *exact]
                bins[-1] = (
                    low,
                    len(combined),
                    sum(pair[0].probability_bp for pair in combined) // len(combined),
                    sum(int(pair[1].actual_bp) for pair in combined) // len(combined),
                )
            else:
                bins.append((9_000, len(exact), 10_000, sum(int(pair[1].actual_bp) for pair in exact) // len(exact)))
        body = {
            "schema_version": "jaa14.live-calibration-summary.v1",
            "predictor_policy_sha256": predictor_policy_sha256,
            "model_sha256": model_sha256,
            "data_sha256": data_sha256,
            "cohort_id": cohort_id,
            "cohort_kind": cohort_kind,
            "cohort_snapshot_sha256": cohort_snapshot_sha256,
            "application_ids": tuple(pair[0].application_id for pair in selected),
            "prediction_ids": tuple(pair[0].prediction_id for pair in selected),
            "outcome_ids": tuple(pair[1].outcome_id for pair in selected),
            "resolved_count": len(resolved_pairs),
            "censored_count": len(selected) - len(resolved_pairs),
            "mean_brier_bp": brier,
            "calibration_bins": tuple(bins),
            "policy_promotion_authority": False,
        }
        return CalibrationSummary(
            **{key: value for key, value in body.items() if key != "schema_version"},
            summary_id=_content_hash(body),
        )

    def evaluate_policy_candidate(
        self,
        *,
        locked_baseline: CalibrationSummary,
        locked_candidate: CalibrationSummary,
        holdout_baseline: CalibrationSummary,
        holdout_candidate: CalibrationSummary,
        rollback_policy_sha256: str | None,
        upstream_jaa13_certification_sha256: str | None,
        locked_non_regression_evidence_sha256: str | None,
        independent_holdout_evidence_sha256: str | None,
        minimum_resolved: int = MINIMUM_RESOLVED_PER_SUMMARY,
    ) -> PromotionEvaluation:
        summaries = (locked_baseline, locked_candidate, holdout_baseline, holdout_candidate)
        if not all(isinstance(row, CalibrationSummary) for row in summaries):
            raise TypeError("promotion evaluation requires calibration summaries")
        for summary in summaries:
            regenerated = self.calibration_summary(
                predictor_policy_sha256=summary.predictor_policy_sha256,
                model_sha256=summary.model_sha256,
                data_sha256=summary.data_sha256,
                cohort_id=summary.cohort_id,
                cohort_kind=summary.cohort_kind,
                cohort_snapshot_sha256=summary.cohort_snapshot_sha256,
            )
            if regenerated != summary:
                raise OutcomeEvidenceError(
                    "promotion evaluation requires exact ledger-derived summaries"
                )
        baseline_policy = locked_baseline.predictor_policy_sha256
        candidate_policy = locked_candidate.predictor_policy_sha256
        if baseline_policy == candidate_policy:
            raise ValueError("promotion evaluation requires two distinct policies")
        if locked_baseline.cohort_kind != "locked" or locked_candidate.cohort_kind != "locked":
            raise ValueError("locked evidence must use a locked cohort")
        if holdout_baseline.cohort_kind not in {"holdout", "live"} or holdout_candidate.cohort_kind != holdout_baseline.cohort_kind:
            raise ValueError("independent evidence must use one holdout/live cohort")
        if locked_baseline.cohort_id != locked_candidate.cohort_id or holdout_baseline.cohort_id != holdout_candidate.cohort_id:
            raise ValueError("baseline and candidate summaries must align by cohort")
        if locked_baseline.cohort_id == holdout_baseline.cohort_id:
            raise ValueError("locked and holdout cohorts must be distinct")
        if locked_baseline.application_ids != locked_candidate.application_ids or holdout_baseline.application_ids != holdout_candidate.application_ids:
            raise ValueError("policy summaries must have identical cohort membership")
        if set(locked_baseline.application_ids) & set(holdout_baseline.application_ids):
            raise ValueError("locked and holdout members must be independent")
        if locked_candidate.predictor_policy_sha256 != candidate_policy or holdout_candidate.predictor_policy_sha256 != candidate_policy or holdout_baseline.predictor_policy_sha256 != baseline_policy:
            raise ValueError("summary policies are not aligned")
        reasons: list[str] = []
        if upstream_jaa13_certification_sha256 is None:
            reasons.append("upstream_jaa13_not_certified")
        else:
            _digest(upstream_jaa13_certification_sha256, "JAA-13 certification hash")
        if rollback_policy_sha256 != baseline_policy:
            reasons.append("rollback_not_bound")
        if locked_non_regression_evidence_sha256 is None:
            reasons.append("locked_non_regression_not_certified")
        else:
            _digest(locked_non_regression_evidence_sha256, "locked evidence hash")
        if independent_holdout_evidence_sha256 is None:
            reasons.append("independent_holdout_not_certified")
        else:
            _digest(independent_holdout_evidence_sha256, "holdout evidence hash")
        if any(row.resolved_count < minimum_resolved for row in summaries):
            reasons.append("insufficient_resolved_samples")
        elif (
            locked_candidate.mean_brier_bp is None
            or locked_baseline.mean_brier_bp is None
            or locked_candidate.mean_brier_bp > locked_baseline.mean_brier_bp
        ):
            reasons.append("locked_regression")
        if (
            holdout_candidate.mean_brier_bp is None
            or holdout_baseline.mean_brier_bp is None
            or holdout_candidate.mean_brier_bp >= holdout_baseline.mean_brier_bp
        ):
            reasons.append("holdout_not_improved")
        eligible = not reasons
        body = {
            "schema_version": "jaa14.live-policy-promotion-evaluation.v1",
            "baseline_policy_sha256": baseline_policy,
            "candidate_policy_sha256": candidate_policy,
            "locked_baseline_summary_id": locked_baseline.summary_id,
            "locked_candidate_summary_id": locked_candidate.summary_id,
            "holdout_baseline_summary_id": holdout_baseline.summary_id,
            "holdout_candidate_summary_id": holdout_candidate.summary_id,
            "rollback_policy_sha256": rollback_policy_sha256,
            "upstream_jaa13_certification_sha256": upstream_jaa13_certification_sha256,
            "locked_non_regression_evidence_sha256": locked_non_regression_evidence_sha256,
            "independent_holdout_evidence_sha256": independent_holdout_evidence_sha256,
            "eligible_for_independent_review": eligible,
            "reason_codes": tuple(reasons) if reasons else ("all_evaluation_gates_satisfied",),
            "promotion_authority": False,
            "applied": False,
        }
        evaluation = PromotionEvaluation(
            **{key: value for key, value in body.items() if key != "schema_version"},
            evaluation_id=_content_hash(body),
        )
        encoded = _canonical_json(evaluation.document())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._insert_exact(
                connection,
                table="evaluations",
                identity_column="evaluation_id",
                identity=evaluation.evaluation_id,
                columns=("evaluation_id",),
                values=(evaluation.evaluation_id,),
                record_sha256=hashlib.sha256(encoded.encode()).hexdigest(),
                encoded=encoded,
            )
            connection.commit()
        return evaluation

    def counts(self) -> Mapping[str, int]:
        with self._connect() as connection:
            return {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("predictions", "source_events", "outcomes", "evaluations")
            }
