"""Dependency-independent JAA-10 hard-metric evaluation.

Only registry-pinned frozen fixture evidence is admissible here.  Live
evidence classes are deliberately unconstructable, five live-dependent
metrics remain unevaluable, and this module has no browser, network,
subprocess, release, lifecycle, or certification capability.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping

from career_automation.shadow_certification import HARD_QUALITY_TARGETS


METRICS_SCHEMA_VERSION = "jaa10.hard-metrics-evaluation.v1"
METRIC_RECEIPT_DOMAIN = b"jaa10-hard-metric-receipt-v1\0"
EVIDENCE_REGISTRY_DOMAIN = b"jaa10-metric-evidence-registry-v1\0"
METRICS_EVALUATION_DOMAIN = b"jaa10-hard-metrics-evaluation-v1\0"
MODEL_CALL_ACCOUNTING_SCHEMA_VERSION = "jaa10.model-call-accounting.v1"
DETERMINISTIC_ACCOUNTING = "deterministic:none"

LIVE_EXECUTION = "not_collected"
PRODUCTION_CERTIFICATION = "withheld"
WITHHELD_REASON = "live_time_separated_shadow_and_metrics_not_evaluated"

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_FIXTURE_SCHEMA = "jaa07.locked-application-packs.v1"
_REPORT_SCHEMA = "jaa07.locked-evaluation-report.v1"
_REPORT_STATUS = "SOFTWARE_CONTRACT_PASS"
_REPORT_SCOPE_ID = (
    "801349f4a13a9516e928d30035cfcab00adb4f1bd2783cbaa0c8cd61a4554e59"
)
_EXPECTED_PACK_IDS = tuple(f"pack-{index:02d}" for index in range(1, 21))


class MetricStatus(str, Enum):
    UNEVALUABLE = "UNEVALUABLE"
    FAIL = "FAIL"
    PASS = "PASS"


class EvidenceClass(str, Enum):
    FIXTURE_FROZEN = "fixture_frozen"


class HardMetricsError(RuntimeError):
    """Base error for dependency-independent metric evaluation."""


class EvidenceRegistryError(HardMetricsError):
    """Registry evidence is missing, mutable, substituted, or malformed."""


class MetricIntegrityError(HardMetricsError):
    """A derived metric receipt no longer matches its evidence and policy."""


class ReceiptPublicationError(HardMetricsError):
    """A content-addressed receipt could not be exclusively published."""


@dataclass(frozen=True)
class ModelCallAccounting:
    """Descriptive accounting for one probabilistic call.

    ``logical_request_sha256`` identifies canonical logical request content;
    ``transport_request_sha256`` identifies exact wire bytes when observable.
    Missing cost or latency remains unavailable rather than being zero-filled.
    """

    provider_name: str
    model_id_at_call: str
    model_id_from_response: str
    logical_request_sha256: str
    transport_request_sha256: str | None
    response_sha256: str
    tokens_input: int
    tokens_output: int
    tokens_cached_input: int
    cost_amount_decimal: str | None
    cost_currency: str | None
    latency_request_start_ns: int | None
    latency_first_byte_ns: int | None
    latency_last_byte_ns: int | None
    abstained: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.provider_name, "provider"),
            (self.model_id_at_call, "call model"),
            (self.model_id_from_response, "response model"),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"model-call {label} identity is required")
        for value, label in (
            (self.logical_request_sha256, "logical request"),
            (self.response_sha256, "response"),
        ):
            if not isinstance(value, str) or not _HEX_64.fullmatch(value):
                raise ValueError(f"model-call {label} hash is required")
        if (
            self.transport_request_sha256 is not None
            and not _HEX_64.fullmatch(self.transport_request_sha256)
        ):
            raise ValueError("model-call transport hash is invalid")
        for value, label in (
            (self.tokens_input, "input token"),
            (self.tokens_output, "output token"),
            (self.tokens_cached_input, "cached-input token"),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(f"model-call {label} count is invalid")
        if (self.cost_amount_decimal is None) != (
            self.cost_currency is None
        ):
            raise ValueError("model-call cost must be wholly available")
        if self.cost_amount_decimal is not None:
            try:
                cost = Decimal(self.cost_amount_decimal)
            except (InvalidOperation, TypeError) as exc:
                raise ValueError("model-call cost is invalid") from exc
            if (
                not cost.is_finite()
                or cost < 0
                or not isinstance(self.cost_currency, str)
                or not re.fullmatch(r"[A-Z]{3}", self.cost_currency)
            ):
                raise ValueError("model-call cost is invalid")
        latencies = (
            self.latency_request_start_ns,
            self.latency_first_byte_ns,
            self.latency_last_byte_ns,
        )
        if any(value is None for value in latencies):
            if not all(value is None for value in latencies):
                raise ValueError(
                    "model-call latency must be wholly available"
                )
        elif (
            any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in latencies
            )
            or not (
                latencies[0] <= latencies[1] <= latencies[2]  # type: ignore[operator]
            )
        ):
            raise ValueError("model-call latency is invalid")
        if not isinstance(self.abstained, bool):
            raise ValueError("model-call abstention must be typed")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": MODEL_CALL_ACCOUNTING_SCHEMA_VERSION,
            "provider_name": self.provider_name,
            "model_id_at_call": self.model_id_at_call,
            "model_id_from_response": self.model_id_from_response,
            "logical_request_sha256": self.logical_request_sha256,
            "transport_request_sha256": self.transport_request_sha256,
            "response_sha256": self.response_sha256,
            "tokens_input": self.tokens_input,
            "tokens_output": self.tokens_output,
            "tokens_cached_input": self.tokens_cached_input,
            "cost_amount_decimal": self.cost_amount_decimal,
            "cost_currency": self.cost_currency,
            "latency_request_start_ns": self.latency_request_start_ns,
            "latency_first_byte_ns": self.latency_first_byte_ns,
            "latency_last_byte_ns": self.latency_last_byte_ns,
            "abstained": self.abstained,
        }


@dataclass(frozen=True)
class _RegistryEntry:
    evidence_id: str
    path_base: str
    relative_path: str
    sha256: str

    def __post_init__(self) -> None:
        if (
            not self.evidence_id
            or self.path_base not in {"repository_root", "operator_control_root"}
            or not _HEX_64.fullmatch(self.sha256)
        ):
            raise ValueError("metric evidence registry entry is invalid")
        relative = PurePosixPath(self.relative_path)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("metric evidence registry path is invalid")

    def document(self) -> dict[str, str]:
        return {
            "evidence_id": self.evidence_id,
            "path_base": self.path_base,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
        }


_FIXTURE_ENTRY = _RegistryEntry(
    evidence_id="jaa07-locked-application-packs-v1",
    path_base="repository_root",
    relative_path="career_automation/fixtures/jaa07_locked_application_packs.json",
    sha256="e24029378de5a36d1a43f676efa6d1ef2417763305af0bdbf55d4700af66d6d5",
)
_REPORT_ENTRY = _RegistryEntry(
    evidence_id="jaa07-locked-evaluation-report-v1",
    path_base="operator_control_root",
    relative_path=(
        "jaa-single-codex-20260729/"
        "jaa07-post-review-repair-evaluator.log"
    ),
    sha256="5cf1f1f5bcee57aaf8a517edb734cf9dadf1802e44f831defd105418c41ef1fe",
)
EVIDENCE_REGISTRY: Mapping[str, _RegistryEntry] = MappingProxyType(
    {
        _FIXTURE_ENTRY.evidence_id: _FIXTURE_ENTRY,
        _REPORT_ENTRY.evidence_id: _REPORT_ENTRY,
    }
)

_LIVE_DEPENDENT_METRICS = frozenset(
    {
        "confirmed_without_receipt",
        "duplicate_submissions",
        "ineligible_submissions",
        "released_employer_claims_without_citations",
        "unsupported_released_claims",
    }
)
_FIXTURE_EVALUABLE_METRICS = frozenset(
    {"ats_parse_success_bp", "deterministic_replay_mismatch"}
)
if (
    _LIVE_DEPENDENT_METRICS | _FIXTURE_EVALUABLE_METRICS
    != frozenset(HARD_QUALITY_TARGETS)
):
    raise RuntimeError("hard-metric policy does not cover the canonical targets")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _domain_hash(domain: bytes, value: object) -> str:
    payload = _canonical_json(value).encode("utf-8")
    digest = hashlib.sha256(domain)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def evidence_registry_document() -> dict[str, object]:
    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "entries": [
            EVIDENCE_REGISTRY[key].document()
            for key in sorted(EVIDENCE_REGISTRY)
        ],
    }


def evidence_registry_sha256() -> str:
    return _domain_hash(
        EVIDENCE_REGISTRY_DOMAIN,
        evidence_registry_document(),
    )


def _repository_root() -> Path:
    root = Path(__file__).resolve(strict=True).parents[1]
    if not (root / "canonical-repository.json").is_file():
        raise EvidenceRegistryError("canonical repository root is unavailable")
    return root


def _operator_control_root(repository_root: Path) -> Path:
    parent = repository_root.parent
    if parent.name == ".worktrees":
        factory_root = parent.parent
    else:
        factory_root = parent
    control = factory_root / ".control"
    try:
        resolved = control.resolve(strict=True)
    except OSError as exc:
        raise EvidenceRegistryError(
            "operator control root is unavailable"
        ) from exc
    if not resolved.is_dir():
        raise EvidenceRegistryError("operator control root is not a directory")
    return resolved


def _read_regular_file_once(root: Path, relative_path: str) -> bytes:
    """Open every path component without following symlinks and read once."""
    parts = PurePosixPath(relative_path).parts
    flags = os.O_RDONLY | os.O_CLOEXEC
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = flags | no_follow | getattr(os, "O_DIRECTORY", 0)
    descriptors: list[int] = []
    try:
        current_fd = os.open(root, directory_flags)
        descriptors.append(current_fd)
        for part in parts[:-1]:
            current_fd = os.open(
                part,
                directory_flags,
                dir_fd=current_fd,
            )
            descriptors.append(current_fd)
        file_fd = os.open(
            parts[-1],
            flags | no_follow,
            dir_fd=current_fd,
        )
        descriptors.append(file_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceRegistryError(
                "metric evidence must be a regular file"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise EvidenceRegistryError(
            "metric evidence path cannot be opened safely"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_registry_entry(
    entry: _RegistryEntry,
    *,
    repository_root: Path,
    control_root: Path,
) -> bytes:
    root = (
        repository_root
        if entry.path_base == "repository_root"
        else control_root
    )
    payload = _read_regular_file_once(root, entry.relative_path)
    if hashlib.sha256(payload).hexdigest() != entry.sha256:
        raise EvidenceRegistryError(
            f"metric evidence hash differs: {entry.evidence_id}"
        )
    return payload


def _json_object(payload: bytes, label: str) -> dict[str, object]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceRegistryError(f"{label} is not canonical JSON") from exc
    if not isinstance(document, dict):
        raise EvidenceRegistryError(f"{label} must be a JSON object")
    return document


def _reject_informational_inputs(value: object) -> None:
    if isinstance(value, dict):
        if any(
            key.endswith("_status") and nested == "informational"
            for key, nested in value.items()
        ):
            raise EvidenceRegistryError(
                "informational fields cannot enter metric evidence"
            )
        for nested in value.values():
            _reject_informational_inputs(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_informational_inputs(nested)


def _validate_fixture_document(document: Mapping[str, object]) -> dict[str, str]:
    if (
        document.get("schema_version") != _FIXTURE_SCHEMA
        or document.get("certifies_slice") is not False
    ):
        raise EvidenceRegistryError("locked application-pack fixture differs")
    cases = document.get("cases")
    metrics = document.get("expected_metrics_bp")
    if not isinstance(cases, list) or not isinstance(metrics, dict):
        raise EvidenceRegistryError("locked application-pack fixture is incomplete")
    if (
        metrics.get("parse_success") != 10_000
        or metrics.get("deterministic_replay") != 10_000
    ):
        raise EvidenceRegistryError("locked fixture target declaration differs")
    actual_ids: list[str] = []
    artifact_hashes: dict[str, str] = {}
    for case in cases:
        if not isinstance(case, dict):
            raise EvidenceRegistryError("locked fixture case is invalid")
        case_id = case.get("id")
        artifact_hash = case.get("expected_artifact_set_sha256")
        if (
            not isinstance(case_id, str)
            or not isinstance(artifact_hash, str)
            or not _HEX_64.fullmatch(artifact_hash)
            or case_id in artifact_hashes
        ):
            raise EvidenceRegistryError("locked fixture case identity differs")
        actual_ids.append(case_id)
        artifact_hashes[case_id] = artifact_hash
    if tuple(actual_ids) != _EXPECTED_PACK_IDS:
        raise EvidenceRegistryError("locked fixture denominator differs")
    return artifact_hashes


def _validate_report_document(
    document: Mapping[str, object],
    *,
    fixture_artifacts: Mapping[str, str],
) -> tuple[int, int]:
    _reject_informational_inputs(document)
    if (
        document.get("schema_version") != _REPORT_SCHEMA
        or document.get("status") != _REPORT_STATUS
        or document.get("certifies_slice") is not False
        or document.get("live_requests") != 0
        or document.get("packs") != len(_EXPECTED_PACK_IDS)
        or document.get("fixture_sha256") != _REPORT_SCOPE_ID
    ):
        raise EvidenceRegistryError("locked evaluation report differs")
    metrics = document.get("metrics_bp")
    results = document.get("results")
    if not isinstance(metrics, dict) or not isinstance(results, list):
        raise EvidenceRegistryError("locked evaluation report is incomplete")
    if (
        metrics.get("parse_success") != 10_000
        or metrics.get("deterministic_replay") != 10_000
    ):
        raise EvidenceRegistryError("locked evaluation summary differs")
    parse_failures = 0
    replay_mismatches = 0
    seen: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            raise EvidenceRegistryError("locked evaluation row is invalid")
        case_id = result.get("id")
        checks = result.get("checks")
        artifact_hash = result.get("artifact_set_sha256")
        if (
            not isinstance(case_id, str)
            or not isinstance(checks, dict)
            or case_id not in fixture_artifacts
            or artifact_hash != fixture_artifacts[case_id]
        ):
            raise EvidenceRegistryError(
                "locked evaluation row binding differs"
            )
        parse_success = checks.get("parse_success")
        deterministic_replay = checks.get("deterministic_replay")
        if (
            not isinstance(parse_success, bool)
            or not isinstance(deterministic_replay, bool)
        ):
            raise EvidenceRegistryError(
                "locked evaluation row result is untyped"
            )
        seen.append(case_id)
        parse_failures += not parse_success
        replay_mismatches += not deterministic_replay
    if tuple(seen) != _EXPECTED_PACK_IDS:
        raise EvidenceRegistryError(
            "locked evaluation denominator is incomplete"
        )
    expected_parse_bp = (
        (len(_EXPECTED_PACK_IDS) - parse_failures) * 10_000
        // len(_EXPECTED_PACK_IDS)
    )
    expected_replay_bp = (
        (len(_EXPECTED_PACK_IDS) - replay_mismatches) * 10_000
        // len(_EXPECTED_PACK_IDS)
    )
    if (
        metrics.get("parse_success") != expected_parse_bp
        or metrics.get("deterministic_replay") != expected_replay_bp
    ):
        raise EvidenceRegistryError(
            "locked evaluation summary and denominator differ"
        )
    return parse_failures, replay_mismatches


def _withheld_fields() -> dict[str, object]:
    return {
        "objective_satisfied": False,
        "production_certification": PRODUCTION_CERTIFICATION,
        "certifies_slice": False,
        "live_time_separated_execution": LIVE_EXECUTION,
        "external_action_capability": False,
        "real_applications_submitted": 0,
    }


@dataclass(frozen=True, init=False)
class MetricReceipt:
    metric_name: str
    target: int
    status: MetricStatus
    numerator: int
    denominator: int
    value: int | None
    unit: str
    evidence_class: EvidenceClass | None
    evidence_item_ids: tuple[str, ...]
    evidence_scope_id: str | None
    registry_sha256: str
    missing_evidence_count: int
    receipt_sha256: str

    def __init__(self) -> None:
        raise TypeError("metric receipts require the verified evaluator")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": METRICS_SCHEMA_VERSION,
            "metric_name": self.metric_name,
            "target": self.target,
            "status": self.status.value,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "value": self.value,
            "unit": self.unit,
            "evidence_class": (
                None
                if self.evidence_class is None
                else self.evidence_class.value
            ),
            "evidence_item_ids": list(self.evidence_item_ids),
            "evidence_scope_id": self.evidence_scope_id,
            "registry_sha256": self.registry_sha256,
            "missing_evidence_count": self.missing_evidence_count,
            **_withheld_fields(),
        }
        if include_hash:
            document["receipt_sha256"] = self.receipt_sha256
        return document

    def verify(self) -> None:
        if (
            self.metric_name not in HARD_QUALITY_TARGETS
            or self.target != HARD_QUALITY_TARGETS[self.metric_name]
            or not isinstance(self.status, MetricStatus)
            or not isinstance(self.numerator, int)
            or isinstance(self.numerator, bool)
            or not isinstance(self.denominator, int)
            or isinstance(self.denominator, bool)
            or self.numerator < 0
            or self.denominator < 0
            or self.numerator > self.denominator
            or self.registry_sha256 != evidence_registry_sha256()
            or not _HEX_64.fullmatch(self.receipt_sha256)
        ):
            raise MetricIntegrityError("hard-metric receipt differs")
        if self.status is MetricStatus.UNEVALUABLE:
            if (
                self.denominator != 0
                or self.value is not None
                or self.missing_evidence_count < 1
                or self.evidence_class is not None
                or self.evidence_item_ids
                or self.evidence_scope_id is not None
            ):
                raise MetricIntegrityError(
                    "unevaluable metric receipt is gameable"
                )
        elif self.metric_name == "ats_parse_success_bp":
            expected_value = (
                (self.denominator - self.numerator) * 10_000
                // self.denominator
            )
            expected_status = (
                MetricStatus.PASS
                if expected_value == self.target
                else MetricStatus.FAIL
            )
            if (
                self.denominator != len(_EXPECTED_PACK_IDS)
                or self.value != expected_value
                or self.status is not expected_status
                or self.unit != "basis_points"
                or self.evidence_class is not EvidenceClass.FIXTURE_FROZEN
                or self.evidence_item_ids
                != (_FIXTURE_ENTRY.evidence_id, _REPORT_ENTRY.evidence_id)
                or self.evidence_scope_id != _REPORT_SCOPE_ID
                or self.missing_evidence_count != 0
            ):
                raise MetricIntegrityError("ATS-parse metric receipt differs")
        else:
            raise MetricIntegrityError(
                "only ATS parse is evaluable from the current registry"
            )
        expected_hash = _domain_hash(
            METRIC_RECEIPT_DOMAIN,
            self.document(include_hash=False),
        )
        if self.receipt_sha256 != expected_hash:
            raise MetricIntegrityError("hard-metric receipt hash differs")


def _build_metric_receipt(
    *,
    metric_name: str,
    status: MetricStatus,
    numerator: int,
    denominator: int,
    value: int | None,
    unit: str,
    evidence_class: EvidenceClass | None,
    evidence_item_ids: tuple[str, ...],
    evidence_scope_id: str | None,
    missing_evidence_count: int,
) -> MetricReceipt:
    receipt = object.__new__(MetricReceipt)
    values = {
        "metric_name": metric_name,
        "target": HARD_QUALITY_TARGETS[metric_name],
        "status": status,
        "numerator": numerator,
        "denominator": denominator,
        "value": value,
        "unit": unit,
        "evidence_class": evidence_class,
        "evidence_item_ids": evidence_item_ids,
        "evidence_scope_id": evidence_scope_id,
        "registry_sha256": evidence_registry_sha256(),
        "missing_evidence_count": missing_evidence_count,
        "receipt_sha256": "",
    }
    for name, value_item in values.items():
        object.__setattr__(receipt, name, value_item)
    object.__setattr__(
        receipt,
        "receipt_sha256",
        _domain_hash(
            METRIC_RECEIPT_DOMAIN,
            receipt.document(include_hash=False),
        ),
    )
    receipt.verify()
    return receipt


@dataclass(frozen=True, init=False)
class HardMetricsEvaluation:
    metrics: tuple[MetricReceipt, ...]
    registry_sha256: str
    model_call_accounting: str
    evaluation_sha256: str

    def __init__(self) -> None:
        raise TypeError("hard-metrics evaluations require the verified evaluator")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": METRICS_SCHEMA_VERSION,
            "registry": evidence_registry_document(),
            "registry_sha256": self.registry_sha256,
            "metrics": [metric.document() for metric in self.metrics],
            "model_call_accounting_schema_version": (
                MODEL_CALL_ACCOUNTING_SCHEMA_VERSION
            ),
            "model_call_accounting": self.model_call_accounting,
            "metrics_evaluated": True,
            "withheld_reason": WITHHELD_REASON,
            **_withheld_fields(),
        }
        if include_hash:
            document["evaluation_sha256"] = self.evaluation_sha256
        return document

    def verify(self) -> None:
        if (
            self.registry_sha256 != evidence_registry_sha256()
            or self.model_call_accounting != DETERMINISTIC_ACCOUNTING
            or tuple(metric.metric_name for metric in self.metrics)
            != tuple(sorted(HARD_QUALITY_TARGETS))
            or not _HEX_64.fullmatch(self.evaluation_sha256)
        ):
            raise MetricIntegrityError("hard-metrics evaluation differs")
        for metric in self.metrics:
            metric.verify()
        expected_hash = _domain_hash(
            METRICS_EVALUATION_DOMAIN,
            self.document(include_hash=False),
        )
        if self.evaluation_sha256 != expected_hash:
            raise MetricIntegrityError("hard-metrics evaluation hash differs")


def _derive_from_documents(
    fixture_document: Mapping[str, object],
    report_document: Mapping[str, object],
) -> HardMetricsEvaluation:
    fixture_artifacts = _validate_fixture_document(fixture_document)
    parse_failures, _replay_mismatches = _validate_report_document(
        report_document,
        fixture_artifacts=fixture_artifacts,
    )
    receipts: list[MetricReceipt] = []
    for metric_name in sorted(HARD_QUALITY_TARGETS):
        if metric_name == "ats_parse_success_bp":
            denominator = len(_EXPECTED_PACK_IDS)
            value = (denominator - parse_failures) * 10_000 // denominator
            status = (
                MetricStatus.PASS
                if value == HARD_QUALITY_TARGETS[metric_name]
                else MetricStatus.FAIL
            )
            receipt = _build_metric_receipt(
                metric_name=metric_name,
                status=status,
                numerator=parse_failures,
                denominator=denominator,
                value=value,
                unit="basis_points",
                evidence_class=EvidenceClass.FIXTURE_FROZEN,
                evidence_item_ids=(
                    _FIXTURE_ENTRY.evidence_id,
                    _REPORT_ENTRY.evidence_id,
                ),
                evidence_scope_id=_REPORT_SCOPE_ID,
                missing_evidence_count=0,
            )
        else:
            receipt = _build_metric_receipt(
                metric_name=metric_name,
                status=MetricStatus.UNEVALUABLE,
                numerator=0,
                denominator=0,
                value=None,
                unit=(
                    "count"
                ),
                evidence_class=None,
                evidence_item_ids=(),
                evidence_scope_id=None,
                missing_evidence_count=1,
            )
        receipts.append(receipt)
    evaluation = object.__new__(HardMetricsEvaluation)
    object.__setattr__(evaluation, "metrics", tuple(receipts))
    object.__setattr__(
        evaluation,
        "registry_sha256",
        evidence_registry_sha256(),
    )
    object.__setattr__(
        evaluation,
        "model_call_accounting",
        DETERMINISTIC_ACCOUNTING,
    )
    object.__setattr__(evaluation, "evaluation_sha256", "")
    object.__setattr__(
        evaluation,
        "evaluation_sha256",
        _domain_hash(
            METRICS_EVALUATION_DOMAIN,
            evaluation.document(include_hash=False),
        ),
    )
    evaluation.verify()
    return evaluation


def evaluate_hard_metrics() -> HardMetricsEvaluation:
    """Evaluate only the authority-registry evidence; accepts no caller input."""
    repository_root = _repository_root()
    control_root = _operator_control_root(repository_root)
    fixture_payload = _read_registry_entry(
        _FIXTURE_ENTRY,
        repository_root=repository_root,
        control_root=control_root,
    )
    report_payload = _read_registry_entry(
        _REPORT_ENTRY,
        repository_root=repository_root,
        control_root=control_root,
    )
    return _derive_from_documents(
        _json_object(fixture_payload, "locked application-pack fixture"),
        _json_object(report_payload, "locked evaluation report"),
    )


def _publish_canonical_receipt(
    document: Mapping[str, object],
    destination: Path,
) -> str:
    """Publish canonical bytes exactly once; the public name is born 0444."""
    if not isinstance(destination, Path):
        raise TypeError("receipt destination must be a Path")
    payload = (_canonical_json(dict(document)) + "\n").encode("utf-8")
    parent = destination.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ReceiptPublicationError("receipt parent is not a directory")
    temporary = parent / (
        f".{destination.name}.tmp-{os.getpid()}-"
        f"{hashlib.sha256(os.urandom(32)).hexdigest()}"
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReceiptPublicationError(
                "receipt staging target is not regular"
            )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, destination, follow_symlinks=False)
        os.unlink(temporary)
    except (FileExistsError, OSError) as exc:
        raise ReceiptPublicationError(
            "receipt publication must be exclusive"
        ) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    final_metadata = destination.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(final_metadata.st_mode)
        or stat.S_IMODE(final_metadata.st_mode) != 0o444
        or destination.read_bytes() != payload
    ):
        raise ReceiptPublicationError("published receipt differs")
    return hashlib.sha256(payload).hexdigest()


def publish_hard_metrics_evaluation(
    evaluation: HardMetricsEvaluation,
    destination: Path,
) -> str:
    if not isinstance(evaluation, HardMetricsEvaluation):
        raise TypeError("publication requires a typed hard-metrics evaluation")
    evaluation.verify()
    return _publish_canonical_receipt(evaluation.document(), destination)
