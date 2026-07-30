"""Descriptive measures for hash-bound JAA-10 fixture observations.

This module compiles an immutable historical snapshot from typed synthetic
observations and their verified local-ledger receipts.  It evaluates no hard
quality target, makes no time-separation claim, certifies no slice, and has no
external-action capability.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping

from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    HARD_QUALITY_TARGETS,
    WITHHELD_REASON,
    ShadowObservation,
)
from career_automation.shadow_observation_ledger import (
    ASSESSMENT,
    CLOCK_AUTHENTICATION,
    FILESYSTEM_WRITER_LIMIT,
    MONOTONIC_WITNESS_SCOPE,
    SPAN_MEANING,
    ObservationLedgerIdentity,
    ObservationLedgerIntegrityError,
    ObservationLedgerReceipt,
    ShadowObservationLedger,
    ledger_policy_document,
)


REPORT_SCHEMA_VERSION = "jaa10.shadow-fixture-measures-report.v1"
SOURCE_TIME_AUTHORITY = "caller_supplied_untrusted_not_time_authority"
HARD_TARGET_STATUS = "not_evaluable_from_fixture_ledger"
HARD_QUALITY_STATUS = "not_evaluated"
_REPORT_DOMAIN = b"jaa10-shadow-fixture-measures-report-v1\0"


class FixtureMeasuresError(RuntimeError):
    """Base error for the fixture-measures report."""


class FixtureMeasuresIntegrityError(FixtureMeasuresError):
    """The report or its observation-to-receipt binding differs."""


class FixtureMeasuresStaleSnapshotError(FixtureMeasuresError):
    """The historical report is not bound to the ledger's current head."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _domain_hash(domain: bytes, payload: bytes) -> str:
    digest = hashlib.sha256(domain)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def _report_hash(document: Mapping[str, object]) -> str:
    return _domain_hash(
        _REPORT_DOMAIN,
        _canonical_json(dict(document)).encode("utf-8"),
    )


def _immutable_mapping(document: Mapping[str, Any]) -> Mapping[str, Any]:
    copied = json.loads(_canonical_json(dict(document)))
    if not isinstance(copied, dict):
        raise TypeError("fixture measures require a JSON object")
    return MappingProxyType(copied)


def _receipt_document(receipt: ObservationLedgerReceipt) -> dict[str, object]:
    if not isinstance(receipt, ObservationLedgerReceipt):
        raise FixtureMeasuresIntegrityError(
            "fixture-measures receipt is not typed"
        )
    try:
        reconstructed = ObservationLedgerReceipt(
            receipt.receipt_sha256,
            dict(receipt.document),
        )
    except (TypeError, ValueError, ObservationLedgerIntegrityError) as exc:
        raise FixtureMeasuresIntegrityError(
            "fixture-measures receipt content differs"
        ) from exc
    return {
        "receipt_sha256": reconstructed.receipt_sha256,
        "document": dict(reconstructed.document),
    }


def _canonical_observation(observation: ShadowObservation) -> None:
    if not isinstance(observation, ShadowObservation):
        raise TypeError(
            "fixture measures require typed shadow observations"
        )
    expected = FROZEN_SHADOW_CONTRACT
    actual_lineage = (
        observation.workflow_sha256,
        observation.receipt_id,
        observation.receipt_payload_sha256,
        observation.field_map_sha256,
        observation.screenshot_sha256,
        observation.normalized_submit_event_sha256,
    )
    canonical_lineage = (
        expected.workflow_sha256,
        expected.receipt_id,
        expected.receipt_payload_sha256,
        expected.field_map_sha256,
        expected.screenshot_sha256,
        expected.submit_event_sha256,
    )
    if actual_lineage != canonical_lineage:
        raise FixtureMeasuresIntegrityError(
            "fixture observation differs from the canonical frozen contract"
        )


def _bind_observations(
    observation_receipts: tuple[ObservationLedgerReceipt, ...],
    observations: tuple[ShadowObservation, ...],
) -> None:
    if len(observation_receipts) != len(observations):
        raise FixtureMeasuresIntegrityError(
            "fixture observation and receipt counts differ"
        )
    observation_ids: set[str] = set()
    observation_hashes: set[str] = set()
    session_ids: set[str] = set()
    for receipt, observation in zip(
        observation_receipts,
        observations,
        strict=True,
    ):
        _canonical_observation(observation)
        document = _receipt_document(receipt)["document"]
        if document.get("event_type") != "observation_recorded":
            raise FixtureMeasuresIntegrityError(
                "fixture observation receipt has the wrong event type"
            )
        session_id = document.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise FixtureMeasuresIntegrityError(
                "fixture observation receipt has no session"
            )
        expected_binding = (
            observation.observation_id,
            observation.observation_sha256,
            observation.observed_at,
        )
        actual_binding = (
            document.get("observation_id"),
            document.get("observation_sha256"),
            document.get("source_observed_at"),
        )
        if actual_binding != expected_binding:
            raise FixtureMeasuresIntegrityError(
                "fixture observation differs from its ledger receipt"
            )
        if (
            observation.observation_id in observation_ids
            or observation.observation_sha256 in observation_hashes
            or session_id in session_ids
        ):
            raise FixtureMeasuresIntegrityError(
                "fixture observation identities must be unique"
            )
        observation_ids.add(observation.observation_id)
        observation_hashes.add(observation.observation_sha256)
        session_ids.add(session_id)


def _host_recording_measures(
    observation_receipts: tuple[ObservationLedgerReceipt, ...],
) -> dict[str, object]:
    host_times = [
        datetime.fromisoformat(
            str(receipt.document["host_recorded_at_utc"])
        )
        for receipt in observation_receipts
    ]
    span_seconds = (host_times[-1] - host_times[0]).total_seconds()
    return {
        "first_observation_host_recorded_at_utc": host_times[0].isoformat(),
        "last_observation_host_recorded_at_utc": host_times[-1].isoformat(),
        "recorded_wall_clock_span_seconds": span_seconds,
        "span_meaning": SPAN_MEANING,
        "clock_authentication": CLOCK_AUTHENTICATION,
        "monotonic_witness_scope": MONOTONIC_WITNESS_SCOPE,
        "filesystem_privileged_writer_limit": FILESYSTEM_WRITER_LIMIT,
    }


def _descriptive_fixture_measures(
    observations: tuple[ShadowObservation, ...],
    observation_receipts: tuple[ObservationLedgerReceipt, ...],
) -> dict[str, object]:
    actions = tuple(observations[0].action_elapsed_ms)
    per_action: dict[str, dict[str, int]] = {}
    for action in actions:
        elapsed = [row.action_elapsed_ms[action] for row in observations]
        per_action[action] = {
            "total": sum(elapsed),
            "min": min(elapsed),
            "max": max(elapsed),
        }
    database_sizes = [row.database_bytes for row in observations]
    screenshot_sizes = [row.screenshot_bytes for row in observations]
    rows: list[dict[str, object]] = []
    for observation in observations:
        rows.append(
            {
                "observation_id": observation.observation_id,
                "observation_sha256": observation.observation_sha256,
                "source_observed_at": observation.observed_at,
                "action_elapsed_ms": dict(
                    sorted(observation.action_elapsed_ms.items())
                ),
                "browser_launch_count": observation.browser_launch_count,
                "database_bytes": observation.database_bytes,
                "screenshot_bytes": observation.screenshot_bytes,
                "model_version": observation.model_version,
                "prompt_version": observation.prompt_version,
                "model_cost_microusd": observation.model_cost_microusd,
                "interruptions": [
                    row.document() for row in observation.interruptions
                ],
                "mutations": [
                    row.document() for row in observation.mutations
                ],
            }
        )
    return {
        "observation_count": len(observations),
        "observations": rows,
        "action_elapsed_ms": {
            "per_action": dict(sorted(per_action.items())),
            "grand_total": sum(
                sum(row.action_elapsed_ms.values())
                for row in observations
            ),
        },
        "browser_launch_count": {
            "per_observation": [
                row.browser_launch_count for row in observations
            ],
            "total": sum(
                row.browser_launch_count for row in observations
            ),
        },
        "database_bytes": {
            "per_observation": database_sizes,
            "total": sum(database_sizes),
            "min": min(database_sizes),
            "max": max(database_sizes),
        },
        "screenshot_bytes": {
            "per_observation": screenshot_sizes,
            "total": sum(screenshot_sizes),
            "min": min(screenshot_sizes),
            "max": max(screenshot_sizes),
        },
        "model_versions": sorted(
            {row.model_version for row in observations}
        ),
        "prompt_versions": sorted(
            {row.prompt_version for row in observations}
        ),
        "total_model_cost_microusd": sum(
            row.model_cost_microusd for row in observations
        ),
        "interruption_totals": {
            "submit_click_count": sum(
                item.submit_click_count
                for row in observations
                for item in row.interruptions
            ),
            "receipt_count": sum(
                item.receipt_count
                for row in observations
                for item in row.interruptions
            ),
        },
        "host_recording": _host_recording_measures(
            observation_receipts
        ),
        "source_observed_at_authority": SOURCE_TIME_AUTHORITY,
    }


def _hard_quality_targets() -> dict[str, dict[str, object]]:
    return {
        key: {
            "target": target,
            "status": HARD_TARGET_STATUS,
        }
        for key, target in sorted(HARD_QUALITY_TARGETS.items())
    }


@dataclass(frozen=True, init=False)
class FixtureMeasuresReport:
    """Content-addressed historical fixture-ledger snapshot."""

    schema_version: str
    contract: Mapping[str, Any]
    contract_sha256: str
    policy: Mapping[str, Any]
    fixture_policy_sha256: str
    ledger_instance_id: str
    genesis_receipt_sha256: str
    receipt_count: int
    observation_receipts: tuple[ObservationLedgerReceipt, ...]
    chain_head_receipt: ObservationLedgerReceipt
    observations: tuple[ShadowObservation, ...]
    descriptive_fixture_measures: Mapping[str, Any]
    hard_quality_targets: Mapping[str, Any]
    hard_quality_metric_status: str
    metrics_evaluated: bool
    fixture_scope_only: bool
    live_time_separated_execution: str
    production_certification: str
    withheld_reason: str
    certifies_slice: bool
    objective_satisfied: bool
    external_action_capability: bool
    assessment: str
    report_id: str

    def __init__(self) -> None:
        raise TypeError(
            "fixture-measures reports must use the verified compiler"
        )

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": self.schema_version,
            "contract": dict(self.contract),
            "contract_sha256": self.contract_sha256,
            "policy": dict(self.policy),
            "fixture_policy_sha256": self.fixture_policy_sha256,
            "ledger_instance_id": self.ledger_instance_id,
            "genesis_receipt_sha256": self.genesis_receipt_sha256,
            "receipt_count": self.receipt_count,
            "observation_receipts": [
                _receipt_document(receipt)
                for receipt in self.observation_receipts
            ],
            "chain_head_receipt": _receipt_document(
                self.chain_head_receipt
            ),
            "observations": [
                row.document() for row in self.observations
            ],
            "observation_sha256s": [
                row.observation_sha256 for row in self.observations
            ],
            "descriptive_fixture_measures": dict(
                self.descriptive_fixture_measures
            ),
            "hard_quality_targets": dict(self.hard_quality_targets),
            "hard_quality_metric_status": self.hard_quality_metric_status,
            "metrics_evaluated": self.metrics_evaluated,
            "fixture_scope_only": self.fixture_scope_only,
            "live_time_separated_execution": (
                self.live_time_separated_execution
            ),
            "production_certification": self.production_certification,
            "withheld_reason": self.withheld_reason,
            "certifies_slice": self.certifies_slice,
            "objective_satisfied": self.objective_satisfied,
            "external_action_capability": self.external_action_capability,
            "assessment": self.assessment,
        }
        if include_identity:
            document["report_id"] = self.report_id
        return document

    @property
    def ledger_identity(self) -> ObservationLedgerIdentity:
        return ObservationLedgerIdentity(
            self.contract_sha256,
            self.ledger_instance_id,
            self.genesis_receipt_sha256,
            self.fixture_policy_sha256,
        )

    def verify(self) -> None:
        try:
            self._verify()
        except FixtureMeasuresError:
            raise
        except ObservationLedgerIntegrityError as exc:
            raise FixtureMeasuresIntegrityError(
                "fixture-measures embedded receipt differs"
            ) from exc
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise FixtureMeasuresIntegrityError(
                "fixture-measures report content differs"
            ) from exc

    def _verify(self) -> None:
        canonical_contract = FROZEN_SHADOW_CONTRACT.document()
        canonical_policy = ledger_policy_document()
        if (
            self.schema_version != REPORT_SCHEMA_VERSION
            or _canonical_json(dict(self.contract))
            != _canonical_json(canonical_contract)
            or self.contract_sha256
            != FROZEN_SHADOW_CONTRACT.contract_sha256
            or self.contract_sha256 != _content_hash(canonical_contract)
            or _canonical_json(dict(self.policy))
            != _canonical_json(canonical_policy)
            or self.fixture_policy_sha256
            != _content_hash(canonical_policy)
        ):
            raise FixtureMeasuresIntegrityError(
                "fixture-measures contract or policy differs"
            )
        self.ledger_identity
        if (
            not isinstance(self.observations, tuple)
            or not self.observations
            or not isinstance(self.observation_receipts, tuple)
        ):
            raise FixtureMeasuresIntegrityError(
                "fixture-measures observation inventory differs"
            )
        reconstructed = tuple(
            ObservationLedgerReceipt(
                receipt.receipt_sha256,
                dict(receipt.document),
            )
            for receipt in self.observation_receipts
        )
        reconstructed_head = ObservationLedgerReceipt(
            self.chain_head_receipt.receipt_sha256,
            dict(self.chain_head_receipt.document),
        )
        if self.receipt_count != 1 + (2 * len(reconstructed)):
            raise FixtureMeasuresIntegrityError(
                "fixture-measures receipt count differs"
            )
        if (
            reconstructed_head.receipt_sha256
            != reconstructed[-1].receipt_sha256
            or reconstructed_head.document != reconstructed[-1].document
            or reconstructed_head.document.get("sequence")
            != self.receipt_count
        ):
            raise FixtureMeasuresIntegrityError(
                "fixture-measures chain-head binding differs"
            )
        expected_sequences = tuple(
            range(3, self.receipt_count + 1, 2)
        )
        if tuple(
            receipt.document.get("sequence")
            for receipt in reconstructed
        ) != expected_sequences:
            raise FixtureMeasuresIntegrityError(
                "fixture-measures receipt sequence differs"
            )
        for receipt in reconstructed:
            if (
                receipt.document.get("contract_sha256")
                != self.contract_sha256
                or receipt.document.get("ledger_instance_id")
                != self.ledger_instance_id
            ):
                raise FixtureMeasuresIntegrityError(
                    "fixture-measures receipt lineage differs"
                )
        _bind_observations(reconstructed, self.observations)
        expected_measures = _descriptive_fixture_measures(
            self.observations,
            reconstructed,
        )
        if dict(self.descriptive_fixture_measures) != expected_measures:
            raise FixtureMeasuresIntegrityError(
                "descriptive fixture measures differ"
            )
        if dict(self.hard_quality_targets) != _hard_quality_targets():
            raise FixtureMeasuresIntegrityError(
                "fixture hard-quality withholding differs"
            )
        if (
            self.hard_quality_metric_status != HARD_QUALITY_STATUS
            or self.metrics_evaluated is not False
            or self.fixture_scope_only is not True
            or self.live_time_separated_execution != "not_collected"
            or self.production_certification != "withheld"
            or self.withheld_reason != WITHHELD_REASON
            or self.certifies_slice is not False
            or self.objective_satisfied is not False
            or self.external_action_capability is not False
            or self.assessment != ASSESSMENT
        ):
            raise FixtureMeasuresIntegrityError(
                "fixture-measures withholding boundary differs"
            )
        expected_report_id = _report_hash(
            self.document(include_identity=False)
        )
        if self.report_id != expected_report_id:
            raise FixtureMeasuresIntegrityError(
                "fixture-measures report identity differs"
            )

    def verify_current(self, ledger: ShadowObservationLedger) -> None:
        self.verify()
        if not isinstance(ledger, ShadowObservationLedger):
            raise TypeError(
                "current fixture-measures verification requires a ledger"
            )
        receipts = ledger.receipts()
        if (
            ledger.identity != self.ledger_identity
            or len(receipts) != self.receipt_count
            or receipts[-1].receipt_sha256
            != self.chain_head_receipt.receipt_sha256
        ):
            raise FixtureMeasuresStaleSnapshotError(
                "fixture-measures report is not the current ledger snapshot"
            )


def compile_fixture_measures_report(
    ledger: ShadowObservationLedger,
    identity: ObservationLedgerIdentity,
    observations: tuple[ShadowObservation, ...],
) -> FixtureMeasuresReport:
    """Compile one verified, noncertifying historical fixture snapshot."""
    if not isinstance(ledger, ShadowObservationLedger):
        raise TypeError("fixture measures require a typed observation ledger")
    if not isinstance(identity, ObservationLedgerIdentity):
        raise TypeError("fixture measures require a typed ledger identity")
    if not isinstance(observations, tuple):
        raise TypeError("fixture measures require an observation tuple")
    receipts = ledger.receipts()
    if (
        identity != ledger.identity
        or identity.contract_sha256
        != FROZEN_SHADOW_CONTRACT.contract_sha256
    ):
        raise FixtureMeasuresIntegrityError(
            "fixture-measures ledger identity differs"
        )
    observation_receipts = tuple(
        receipt
        for receipt in receipts
        if receipt.document["event_type"] == "observation_recorded"
    )
    if not observation_receipts:
        raise ValueError(
            "fixture measures require a recorded observation"
        )
    session_ids = {
        receipt.document["session_id"]
        for receipt in receipts
        if receipt.document["event_type"] == "session_open"
    }
    observed_session_ids = {
        receipt.document["session_id"]
        for receipt in observation_receipts
    }
    if session_ids != observed_session_ids:
        raise FixtureMeasuresIntegrityError(
            "fixture-measures ledger has a session without an observation"
        )
    _bind_observations(observation_receipts, observations)
    copied_receipts = tuple(
        ObservationLedgerReceipt(
            receipt.receipt_sha256,
            dict(receipt.document),
        )
        for receipt in observation_receipts
    )
    copied_head = ObservationLedgerReceipt(
        receipts[-1].receipt_sha256,
        dict(receipts[-1].document),
    )
    measures = _descriptive_fixture_measures(
        observations,
        copied_receipts,
    )
    contract = FROZEN_SHADOW_CONTRACT.document()
    policy = ledger_policy_document()
    hard_targets = _hard_quality_targets()
    report = object.__new__(FixtureMeasuresReport)
    for name, content in (
        ("schema_version", REPORT_SCHEMA_VERSION),
        ("contract", _immutable_mapping(contract)),
        ("contract_sha256", FROZEN_SHADOW_CONTRACT.contract_sha256),
        ("policy", _immutable_mapping(policy)),
        ("fixture_policy_sha256", _content_hash(policy)),
        ("ledger_instance_id", identity.ledger_instance_id),
        ("genesis_receipt_sha256", identity.genesis_receipt_sha256),
        ("receipt_count", len(receipts)),
        ("observation_receipts", copied_receipts),
        ("chain_head_receipt", copied_head),
        ("observations", observations),
        (
            "descriptive_fixture_measures",
            _immutable_mapping(measures),
        ),
        ("hard_quality_targets", _immutable_mapping(hard_targets)),
        ("hard_quality_metric_status", HARD_QUALITY_STATUS),
        ("metrics_evaluated", False),
        ("fixture_scope_only", True),
        ("live_time_separated_execution", "not_collected"),
        ("production_certification", "withheld"),
        ("withheld_reason", WITHHELD_REASON),
        ("certifies_slice", False),
        ("objective_satisfied", False),
        ("external_action_capability", False),
        ("assessment", ASSESSMENT),
    ):
        object.__setattr__(report, name, content)
    object.__setattr__(
        report,
        "report_id",
        _report_hash(report.document(include_identity=False)),
    )
    report.verify()
    return report
