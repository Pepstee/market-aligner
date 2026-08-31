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
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping

from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    HARD_QUALITY_TARGETS,
)
from career_automation.shadow_mutation_runtime import (
    REQUIRED_OUTCOME_KIND,
    RUNTIME_CONTROL_IDS,
)


METRICS_SCHEMA_VERSION = "jaa10.hard-metrics-evaluation.v1"
METRIC_RECEIPT_DOMAIN = b"jaa10-hard-metric-receipt-v1\0"
EVIDENCE_REGISTRY_DOMAIN = b"jaa10-metric-evidence-registry-v1\0"
METRICS_EVALUATION_DOMAIN = b"jaa10-hard-metrics-evaluation-v1\0"
MODEL_CALL_ACCOUNTING_SCHEMA_VERSION = "jaa10.model-call-accounting.v1"
DETERMINISTIC_ACCOUNTING = "deterministic:none"

LIVE_EXECUTION = "not_collected"
PRODUCTION_CERTIFICATION = "withheld"
WITHHELD_REASON = "live_time_separated_shadow_and_metrics_not_evaluated"
FULL_SUBMIT_WITHHELD_REASON = "shadow_metrics_evaluated_certification_pending"

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_FIXTURE_SCHEMA = "jaa07.locked-application-packs.v1"
_REPORT_SCHEMA = "jaa07.locked-evaluation-report.v1"
_REPORT_STATUS = "SOFTWARE_CONTRACT_PASS"
_REPORT_SCOPE_ID = "801349f4a13a9516e928d30035cfcab00adb4f1bd2783cbaa0c8cd61a4554e59"
_EXPECTED_PACK_IDS = tuple(f"pack-{index:02d}" for index in range(1, 21))
REPLAY_PAIR_SCHEMA_VERSION = "jaa10.frozen-replay-pair.v1"
REPLAY_OBSERVATION_SCHEMA_VERSION = "jaa10.shadow-observation.v2"
STABLE_PROJECTION_VERSION = "jaa10.replay-stable-projection.v1"
REPLAY_PAIR_DOMAIN = b"jaa10-frozen-replay-pair-v1\0"
STABLE_PROJECTION_DOMAIN = b"jaa10-replay-stable-projection-v1\0"
_REPLAY_IDENTITY = {
    "source_git_revision": "95caa7254973523734d9cf5a633160e89a8e277e",
    "source_tree": "cd8866e519d3d0d55ebb482be371843920c05047",
    "source_content_revision": "sha256:0fa45f68150decc7b99e2ae92759850bf690805de33f89cbfaa9f5f330ac4ab7",
}
_REPLAY_EEI_SHA256 = "5cd96b3cb1ca8baeb87559d89df11670114d795282188ae893a549daf7bab5f1"
_REPLAY_PAIR_RECEIPT_SHA256 = (
    "0c6830ebe0a6bd0018eee869a32ab1d9dabbfe2ed9b78663c376feb040970cba"
)
_REPLAY_OBSERVATION_SHA256 = (
    "b6dd3fbd2580da722435323d717bf6806c433c7628fd6c5cf465d5df64ef4442",
    "5bf21fbdd2cac84f35d0bbaaa50abbb7d0cf8df67cabc18bb23c416852ec8915",
)
_REPLAY_OBSERVATION_KEYS = frozenset(
    {
        "schema_version",
        "observation_id",
        "observed_at",
        "evidence_kind",
        "execution_claim",
        "run_id",
        "step_id",
        "workflow_sha256",
        "durable_workflow_sha256",
        "release_manifest_sha256",
        "receipt_id",
        "receipt_payload_sha256",
        "field_map_sha256",
        "screenshot_sha256",
        "submit_event_sha256",
        "normalized_submit_event_sha256",
        "submission_proof",
        "fixture_receipt",
        "action_elapsed_ms",
        "browser_launch_count",
        "database_bytes",
        "screenshot_bytes",
        "interruptions",
        "mutations",
        "model_version",
        "prompt_version",
        "model_cost_microusd",
    }
)
_FULL_SUBMIT_COHORT_SHA256 = (
    "8fa735558bcb57845663b6c436cbfc922c422b9f4abef02232089e30e169a5ba"
)
_FULL_SUBMIT_COHORT_ID = (
    "5bb0970598505a57588a5440179a82e27d3190129ba803c963090724680665b3"
)
_FULL_SUBMIT_WITHHELD_EVIDENCE_ID = (
    "aee30d26d2e252d206519e1e4310440ddede1648de5da487b29da37b0874349a"
)
_FULL_SUBMIT_P4_SHA256 = (
    "e489ac40f4d0342223b5794946e2890e75a2a05730c56bfe580ba73bedc70840"
)
_FULL_SUBMIT_SOURCE_IDENTITY = {
    "git_revision": "6043964d02f8a741d1c0a9c2ba7d33d457af0614",
    "tree": "553e58c6593aa85cd84b795b0b0bf531fad4a7a9",
    "source_content_revision": (
        "sha256:50190935babb6ecd3276fe71c055d43b3629e6b6f307ce7cccd9a7f6b29da2d1"
    ),
}
_REPLAY_STABLE_KEYS = (
    "schema_version",
    "evidence_kind",
    "execution_claim",
    "step_id",
    "workflow_sha256",
    "receipt_id",
    "receipt_payload_sha256",
    "field_map_sha256",
    "screenshot_sha256",
    "normalized_submit_event_sha256",
    "browser_launch_count",
    "interruptions",
    "mutations",
    "model_version",
    "prompt_version",
    "model_cost_microusd",
    "fixture_receipt",
)
_REPLAY_PAIR_KEYS = frozenset(
    {
        "schema_version",
        "contract_sha256",
        "replay_execution_identity",
        "execution_environment_sha256",
        "observation_1",
        "observation_2",
        "observation_1_sha256",
        "observation_2_sha256",
        "stable_projection_version",
        "stable_field_hash_1",
        "stable_field_hash_2",
        "mismatched_stable_fields",
        "mismatch_count",
        "time_authenticated",
        "evidence_class",
        "objective_satisfied",
        "certifies_slice",
        "live_time_separated_execution",
        "production_certification",
        "external_action_capability",
        "real_applications_submitted",
        "receipt_sha256",
    }
)


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
        if self.transport_request_sha256 is not None and not _HEX_64.fullmatch(
            self.transport_request_sha256
        ):
            raise ValueError("model-call transport hash is invalid")
        for value, label in (
            (self.tokens_input, "input token"),
            (self.tokens_output, "output token"),
            (self.tokens_cached_input, "cached-input token"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"model-call {label} count is invalid")
        if (self.cost_amount_decimal is None) != (self.cost_currency is None):
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
                raise ValueError("model-call latency must be wholly available")
        elif any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in latencies
        ) or not (
            latencies[0] <= latencies[1] <= latencies[2]  # type: ignore[operator]
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
    relative_path=(
        "career_automation/fixtures/jaa07_locked_application_packs_hard_metrics_v1.json"
    ),
    sha256="e24029378de5a36d1a43f676efa6d1ef2417763305af0bdbf55d4700af66d6d5",
)
_REPORT_ENTRY = _RegistryEntry(
    evidence_id="jaa07-locked-evaluation-report-v1",
    path_base="operator_control_root",
    relative_path=("jaa-single-codex-20260729/jaa07-post-review-repair-evaluator.log"),
    sha256="5cf1f1f5bcee57aaf8a517edb734cf9dadf1802e44f831defd105418c41ef1fe",
)
_REPLAY_PAIR_ENTRY = _RegistryEntry(
    evidence_id="jaa10-frozen-replay-pair-primary-v1",
    path_base="operator_control_root",
    relative_path=(
        "jaa-single-codex-20260729/"
        "JAA10_FROZEN_REPLAY_PAIR_PRIMARY_95caa725/replay-pair.json"
    ),
    sha256="0b278e63b95fd3031d0f6b9181f7e5d783c08052a1a7abd591dbc1467662b786",
)
_FULL_SUBMIT_ENTRY = _RegistryEntry(
    evidence_id="jaa10-full-submit-v2-shadow-cohort-5bb09705",
    path_base="operator_control_root",
    relative_path=(
        "jaa-post-interval-20260803/jaa10-full-submit-cohort-v2/evidence/cohort.json"
    ),
    sha256=_FULL_SUBMIT_COHORT_SHA256,
)
EVIDENCE_REGISTRY: Mapping[str, _RegistryEntry] = MappingProxyType(
    {
        _FIXTURE_ENTRY.evidence_id: _FIXTURE_ENTRY,
        _REPORT_ENTRY.evidence_id: _REPORT_ENTRY,
        _REPLAY_PAIR_ENTRY.evidence_id: _REPLAY_PAIR_ENTRY,
    }
)
FULL_SUBMIT_EVIDENCE_REGISTRY: Mapping[str, _RegistryEntry] = MappingProxyType(
    {
        **EVIDENCE_REGISTRY,
        _FULL_SUBMIT_ENTRY.evidence_id: _FULL_SUBMIT_ENTRY,
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
if _LIVE_DEPENDENT_METRICS | _FIXTURE_EVALUABLE_METRICS != frozenset(
    HARD_QUALITY_TARGETS
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


def _registry_document(
    registry: Mapping[str, _RegistryEntry],
) -> dict[str, object]:
    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "entries": [registry[key].document() for key in sorted(registry)],
    }


def evidence_registry_document() -> dict[str, object]:
    return _registry_document(EVIDENCE_REGISTRY)


def evidence_registry_sha256() -> str:
    return _domain_hash(
        EVIDENCE_REGISTRY_DOMAIN,
        evidence_registry_document(),
    )


def full_submit_evidence_registry_document() -> dict[str, object]:
    return _registry_document(FULL_SUBMIT_EVIDENCE_REGISTRY)


def full_submit_evidence_registry_sha256() -> str:
    return _domain_hash(
        EVIDENCE_REGISTRY_DOMAIN,
        full_submit_evidence_registry_document(),
    )


def _registry_document_for_sha256(registry_sha256: str) -> dict[str, object]:
    if registry_sha256 == evidence_registry_sha256():
        return evidence_registry_document()
    if registry_sha256 == full_submit_evidence_registry_sha256():
        return full_submit_evidence_registry_document()
    raise MetricIntegrityError("hard-metrics registry identity differs")


def _repository_root() -> Path:
    root = Path(__file__).resolve(strict=True).parents[1]
    if not (root / "canonical-repository.json").is_file():
        raise EvidenceRegistryError("canonical repository root is unavailable")
    return root


def _operator_control_root(repository_root: Path) -> Path:
    configured = os.environ.get("JAA_OPERATOR_CONTROL_ROOT")
    if configured is not None:
        if not configured or "\0" in configured:
            raise EvidenceRegistryError(
                "operator control root configuration is invalid"
            )
        control = Path(configured)
        if not control.is_absolute() or control.is_symlink():
            raise EvidenceRegistryError(
                "operator control root configuration must be an absolute non-symlink"
            )
    else:
        parent = repository_root.parent
        if parent.name == ".worktrees":
            factory_root = parent.parent
        else:
            factory_root = parent
        control = factory_root / ".control"
    try:
        resolved = control.resolve(strict=True)
    except OSError as exc:
        raise EvidenceRegistryError("operator control root is unavailable") from exc
    if not resolved.is_dir():
        raise EvidenceRegistryError("operator control root is not a directory")
    if configured is not None and resolved != control:
        raise EvidenceRegistryError(
            "operator control root must be lexical and canonical"
        )
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
            raise EvidenceRegistryError("metric evidence must be a regular file")
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
    root = repository_root if entry.path_base == "repository_root" else control_root
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


_FULL_SUBMIT_KEYS = frozenset(
    {
        "schema_version",
        "source_identity",
        "p4_interval_provenance",
        "withheld_shadow_evidence_id",
        "observation_sha256s",
        "release_manifest_sha256s",
        "runtime_control_receipts",
        "runtime_control_receipt_sha256s",
        "claim_populations",
        "derived_counts",
        "hard_quality_targets",
        "model_call_accounting",
        "metrics_evaluated",
        "production_certification",
        "certifies_slice",
        "live_time_separated_execution",
        "external_action_capability",
        "real_applications_submitted",
        "cohort_id",
    }
)
_RUNTIME_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "control_id",
        "executable_identity",
        "observed_outcome",
        "before_state",
        "after_state",
        "source_identity",
        "fail_closed",
        "receipt_created",
    }
)
_RUNTIME_STATE_KEYS = frozenset(
    {"receipt_count", "submit_click_count", "dispatch_state", "event_count"}
)
_CLAIM_KEYS = frozenset(
    {
        "claim_id",
        "kind",
        "claim_text_sha256",
        "supported",
        "cited",
        "source_ids",
        "citation_excerpt_sha256",
        "release_manifest_sha256",
    }
)


def _plain_content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise EvidenceRegistryError(f"full-submit {label} is not a SHA-256")
    return value


def _validate_runtime_state(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _RUNTIME_STATE_KEYS:
        raise EvidenceRegistryError("full-submit runtime state inventory differs")
    for key in ("receipt_count", "submit_click_count", "event_count"):
        count = value[key]
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise EvidenceRegistryError("full-submit runtime state count differs")
    if value["dispatch_state"] is not None and not isinstance(
        value["dispatch_state"], str
    ):
        raise EvidenceRegistryError("full-submit dispatch state differs")
    return value


def _validate_runtime_outcome(control_id: str, value: object) -> None:
    if not isinstance(value, dict):
        raise EvidenceRegistryError("full-submit runtime outcome is not an object")
    kind = REQUIRED_OUTCOME_KIND[control_id]
    common = {"kind", "result_sha256", "artifact_materialized"}
    if value.get("kind") != kind or value.get("artifact_materialized") is not False:
        raise EvidenceRegistryError("full-submit runtime outcome kind differs")
    _require_sha256(value.get("result_sha256"), "runtime result")
    if kind in {"production_exception", "contract_rejection"}:
        expected = common | {"exception"}
        if kind == "contract_rejection":
            expected.add("callable_identity")
        if set(value) != expected:
            raise EvidenceRegistryError("full-submit exception proof inventory differs")
        exception = value["exception"]
        if (
            not isinstance(exception, dict)
            or set(exception) != {"type", "message_sha256"}
            or not isinstance(exception["type"], str)
            or not exception["type"].strip()
        ):
            raise EvidenceRegistryError("full-submit exception proof differs")
        _require_sha256(exception["message_sha256"], "exception message")
        if kind == "contract_rejection" and (
            not isinstance(value["callable_identity"], str)
            or not value["callable_identity"].strip()
        ):
            raise EvidenceRegistryError("full-submit callable proof differs")
        return
    if set(value) != common | {"http_statuses", "request_variants"}:
        raise EvidenceRegistryError("full-submit HTTP proof inventory differs")
    expected_statuses, expected_variants = (
        ([403, 403], ["host_wrong_port", "origin_wrong_port"])
        if kind == "fixture_http_rejection"
        else ([409, 409], ["duplicate_submit", "duplicate_review"])
    )
    if (
        value["http_statuses"] != expected_statuses
        or value["request_variants"] != expected_variants
    ):
        raise EvidenceRegistryError("full-submit HTTP proof differs")


def _validate_runtime_receipt(
    value: object,
    *,
    expected_control_id: str,
    source_identity: Mapping[str, object],
) -> str:
    if not isinstance(value, dict) or set(value) != _RUNTIME_RECEIPT_KEYS:
        raise EvidenceRegistryError("full-submit runtime receipt inventory differs")
    if (
        value["schema_version"] != "jaa10.runtime-control-receipt.v2"
        or value["control_id"] != expected_control_id
        or not isinstance(value["executable_identity"], str)
        or not value["executable_identity"].strip()
        or value["source_identity"] != source_identity
        or value["fail_closed"] is not True
        or value["receipt_created"] is not False
    ):
        raise EvidenceRegistryError("full-submit runtime receipt literal differs")
    before = _validate_runtime_state(value["before_state"])
    after = _validate_runtime_state(value["after_state"])
    if before != after:
        raise EvidenceRegistryError("full-submit runtime receipt changed state")
    _validate_runtime_outcome(expected_control_id, value["observed_outcome"])
    return _plain_content_hash(value)


def _validate_full_submit_cohort(
    document: Mapping[str, object],
) -> dict[str, tuple[int, int]]:
    if set(document) != _FULL_SUBMIT_KEYS:
        raise EvidenceRegistryError("full-submit cohort inventory differs")
    core = dict(document)
    cohort_id = core.pop("cohort_id")
    if (
        document["schema_version"] != "jaa10.full-submit-cohort.v1"
        or cohort_id != _FULL_SUBMIT_COHORT_ID
        or _plain_content_hash(core) != cohort_id
        or document["source_identity"] != _FULL_SUBMIT_SOURCE_IDENTITY
        or document["p4_interval_provenance"]
        != {
            "summary_sha256": _FULL_SUBMIT_P4_SHA256,
            "use": "authenticated_interval_only_not_submissions",
        }
        or document["withheld_shadow_evidence_id"] != _FULL_SUBMIT_WITHHELD_EVIDENCE_ID
        or document["hard_quality_targets"] != dict(HARD_QUALITY_TARGETS)
        or document["metrics_evaluated"] is not False
        or document["production_certification"] != "withheld"
        or document["certifies_slice"] is not False
        or document["live_time_separated_execution"] != "not_collected"
        or document["external_action_capability"] is not False
        or document["real_applications_submitted"] != 0
    ):
        raise EvidenceRegistryError("full-submit cohort authority literal differs")

    observations = document["observation_sha256s"]
    releases = document["release_manifest_sha256s"]
    if (
        not isinstance(observations, list)
        or len(observations) != 2
        or len(set(observations)) != 2
        or any(
            not isinstance(row, str) or not _HEX_64.fullmatch(row)
            for row in observations
        )
        or not isinstance(releases, list)
        or len(releases) != 2
        or len(set(releases)) != 2
        or any(
            not isinstance(row, str) or not _HEX_64.fullmatch(row) for row in releases
        )
    ):
        raise EvidenceRegistryError(
            "full-submit observation/release population differs"
        )

    receipts = document["runtime_control_receipts"]
    receipt_hashes = document["runtime_control_receipt_sha256s"]
    if (
        not isinstance(receipts, list)
        or not isinstance(receipt_hashes, list)
        or len(receipts) != len(RUNTIME_CONTROL_IDS)
        or len(receipt_hashes) != len(RUNTIME_CONTROL_IDS)
    ):
        raise EvidenceRegistryError("full-submit runtime denominator differs")
    derived_hashes = tuple(
        _validate_runtime_receipt(
            receipt,
            expected_control_id=control_id,
            source_identity=_FULL_SUBMIT_SOURCE_IDENTITY,
        )
        for receipt, control_id in zip(receipts, RUNTIME_CONTROL_IDS, strict=True)
    )
    if tuple(receipt_hashes) != derived_hashes or len(set(derived_hashes)) != len(
        derived_hashes
    ):
        raise EvidenceRegistryError("full-submit runtime receipt identity differs")

    populations = document["claim_populations"]
    if not isinstance(populations, list) or len(populations) != len(releases):
        raise EvidenceRegistryError("full-submit claim population differs")
    claim_rows: list[dict[str, object]] = []
    for release, population in zip(releases, populations, strict=True):
        if not isinstance(population, list) or not population:
            raise EvidenceRegistryError("full-submit claim denominator is zero")
        for claim in population:
            if (
                not isinstance(claim, dict)
                or set(claim) != _CLAIM_KEYS
                or claim["release_manifest_sha256"] != release
                or not isinstance(claim["claim_id"], str)
                or not claim["claim_id"]
                or not isinstance(claim["kind"], str)
                or not claim["kind"]
                or not isinstance(claim["source_ids"], list)
                or not claim["source_ids"]
                or any(
                    not isinstance(row, str) or not row for row in claim["source_ids"]
                )
            ):
                raise EvidenceRegistryError("full-submit claim binding differs")
            _require_sha256(claim["claim_text_sha256"], "claim text")
            _require_sha256(claim["citation_excerpt_sha256"], "citation excerpt")
            if not isinstance(claim["supported"], bool) or not isinstance(
                claim["cited"], bool
            ):
                raise EvidenceRegistryError("full-submit claim verdict is untyped")
            claim_rows.append(claim)

    counts = document["derived_counts"]
    expected_counts = {
        "successful_loopback_submissions": len(observations),
        "released_claims": len(claim_rows),
        "released_employer_claims": len(claim_rows),
        "runtime_negative_controls": len(receipts),
    }
    if counts != expected_counts:
        raise EvidenceRegistryError("full-submit derived denominator differs")
    accounting = document["model_call_accounting"]
    if accounting != {
        "model_version": "deterministic:none",
        "prompt_version": "deterministic:none",
        "invocation_count": 0,
        "cost_microusd": 0,
        "accounting_status": "abstained_no_model_invocation",
    }:
        raise EvidenceRegistryError("full-submit model accounting differs")

    successful = len(observations)
    if successful == 0 or len(claim_rows) == 0:
        raise EvidenceRegistryError("full-submit metric denominator is zero")
    required_controls = {
        "confirmed_without_receipt": {"missing_receipt", "fabricated_receipt"},
        "duplicate_submissions": {
            "duplicate_release",
            "duplicate_submit",
            "concurrent_submit",
        },
        "ineligible_submissions": {"ineligible_contract"},
    }
    control_ids = {str(row["control_id"]) for row in receipts}
    if any(not controls <= control_ids for controls in required_controls.values()):
        raise EvidenceRegistryError("full-submit metric control proof is missing")
    return {
        "confirmed_without_receipt": (0, successful),
        "duplicate_submissions": (0, successful),
        "ineligible_submissions": (0, successful),
        "released_employer_claims_without_citations": (
            sum(row["cited"] is not True for row in claim_rows),
            len(claim_rows),
        ),
        "unsupported_released_claims": (
            sum(row["supported"] is not True for row in claim_rows),
            len(claim_rows),
        ),
    }


def _mismatched_paths(
    first: object, second: object, prefix: str = ""
) -> tuple[str, ...]:
    if type(first) is not type(second):
        return (prefix or "$",)
    if isinstance(first, dict):
        other = second  # type: ignore[assignment]
        if set(first) != set(other):
            return tuple(
                sorted(
                    f"{prefix}.{key}" if prefix else key
                    for key in set(first) ^ set(other)
                )
            )
        paths: list[str] = []
        for key in sorted(first):
            paths.extend(
                _mismatched_paths(
                    first[key], other[key], f"{prefix}.{key}" if prefix else key
                )
            )
        return tuple(paths)
    if isinstance(first, list):
        other = second  # type: ignore[assignment]
        if len(first) != len(other):
            return (f"{prefix}.length",)
        return tuple(
            path
            for index, value in enumerate(first)
            for path in _mismatched_paths(value, other[index], f"{prefix}[{index}]")
        )
    return () if first == second else (prefix or "$",)


def _validate_replay_observation(document: object) -> dict[str, object]:
    if not isinstance(document, dict) or set(document) != _REPLAY_OBSERVATION_KEYS:
        raise EvidenceRegistryError("replay observation inventory differs")
    if (
        document["schema_version"] != REPLAY_OBSERVATION_SCHEMA_VERSION
        or document["evidence_kind"] != "synthetic_shadow"
        or document["execution_claim"] != "structural_lineage_only"
    ):
        raise EvidenceRegistryError("replay observation literals differ")
    try:
        observed = datetime.fromisoformat(
            str(document["observed_at"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise EvidenceRegistryError("replay observation time differs") from exc
    if observed.tzinfo is None:
        raise EvidenceRegistryError("replay observation time differs")
    golden = {
        "workflow_sha256": FROZEN_SHADOW_CONTRACT.workflow_sha256,
        "receipt_id": FROZEN_SHADOW_CONTRACT.receipt_id,
        "receipt_payload_sha256": FROZEN_SHADOW_CONTRACT.receipt_payload_sha256,
        "field_map_sha256": FROZEN_SHADOW_CONTRACT.field_map_sha256,
        "screenshot_sha256": FROZEN_SHADOW_CONTRACT.screenshot_sha256,
        "normalized_submit_event_sha256": FROZEN_SHADOW_CONTRACT.submit_event_sha256,
    }
    if any(document[key] != value for key, value in golden.items()):
        raise EvidenceRegistryError("replay observation golden field differs")
    fixture = document["fixture_receipt"]
    if (
        not isinstance(fixture, dict)
        or set(fixture)
        != {
            "schema_version",
            "receipt_id",
            "payload_sha256",
            "application_id",
            "job_key",
            "certifies_slice",
        }
        or fixture
        != {
            "schema_version": "jaa09.fixture-receipt.v1",
            "receipt_id": document["receipt_id"],
            "payload_sha256": document["receipt_payload_sha256"],
            "application_id": FROZEN_SHADOW_CONTRACT.application_id,
            "job_key": FROZEN_SHADOW_CONTRACT.job_key,
            "certifies_slice": False,
        }
    ):
        raise EvidenceRegistryError("replay fixture receipt differs")
    proof = document["submission_proof"]
    proof_fields = {
        "receipt_id": "receipt_id",
        "receipt_payload_sha256": "receipt_payload_sha256",
        "field_map_sha256": "field_map_sha256",
        "screenshot_sha256": "screenshot_sha256",
        "release_manifest_sha256": "release_manifest_sha256",
        "submit_event_sha256": "submit_event_sha256",
    }
    if (
        not isinstance(proof, dict)
        or set(proof) != {*proof_fields, "token_sha256"}
        or any(proof[key] != document[source] for key, source in proof_fields.items())
        or not isinstance(proof["token_sha256"], str)
        or not _HEX_64.fullmatch(proof["token_sha256"])
    ):
        raise EvidenceRegistryError("replay submission proof differs")
    return document


def _derive_replay_pair(document: Mapping[str, object]) -> int:
    if set(document) != _REPLAY_PAIR_KEYS:
        raise EvidenceRegistryError("replay pair inventory differs")
    withheld = {
        "schema_version": REPLAY_PAIR_SCHEMA_VERSION,
        "contract_sha256": FROZEN_SHADOW_CONTRACT.contract_sha256,
        "stable_projection_version": STABLE_PROJECTION_VERSION,
        "replay_execution_identity": _REPLAY_IDENTITY,
        "execution_environment_sha256": _REPLAY_EEI_SHA256,
        "evidence_class": "fixture_frozen",
        "objective_satisfied": False,
        "certifies_slice": False,
        "live_time_separated_execution": "not_collected",
        "production_certification": "withheld",
        "external_action_capability": False,
    }
    if any(
        type(document[key]) is not type(value) or document[key] != value
        for key, value in withheld.items()
    ):
        raise EvidenceRegistryError("replay pair authority literal differs")
    if document["time_authenticated"] is not False:
        raise EvidenceRegistryError("replay pair time authentication differs")
    applications = document["real_applications_submitted"]
    if (
        not isinstance(applications, int)
        or isinstance(applications, bool)
        or applications != 0
    ):
        raise EvidenceRegistryError("replay pair application count differs")
    observations = (
        _validate_replay_observation(document["observation_1"]),
        _validate_replay_observation(document["observation_2"]),
    )
    if (
        observations[0]["observation_id"] == observations[1]["observation_id"]
        or observations[0]["release_manifest_sha256"]
        == observations[1]["release_manifest_sha256"]
    ):
        raise EvidenceRegistryError("replay observations are not distinct")
    projections = tuple(
        {key: observation[key] for key in _REPLAY_STABLE_KEYS}
        for observation in observations
    )
    stable_hashes = tuple(
        _domain_hash(
            STABLE_PROJECTION_DOMAIN,
            {
                "stable_projection_version": STABLE_PROJECTION_VERSION,
                "projection": projection,
            },
        )
        for projection in projections
    )
    observation_hashes = tuple(
        hashlib.sha256(_canonical_json(observation).encode("utf-8")).hexdigest()
        for observation in observations
    )
    paths = tuple(sorted(set(_mismatched_paths(projections[0], projections[1]))))
    count = 0 if stable_hashes[0] == stable_hashes[1] else 1
    if (
        tuple(document[f"observation_{index}_sha256"] for index in (1, 2))
        != observation_hashes
        or tuple(document[f"stable_field_hash_{index}"] for index in (1, 2))
        != stable_hashes
        or document["mismatched_stable_fields"] != list(paths)
        or document["mismatch_count"] != count
        or bool(paths) != bool(count)
    ):
        raise EvidenceRegistryError("replay pair derivation differs")
    core = dict(document)
    stored_receipt = core.pop("receipt_sha256")
    if _domain_hash(REPLAY_PAIR_DOMAIN, core) != stored_receipt:
        raise EvidenceRegistryError("replay pair receipt differs")
    return count


def _validate_replay_pair(document: Mapping[str, object]) -> int:
    count = _derive_replay_pair(document)
    if (
        tuple(document[f"observation_{index}_sha256"] for index in (1, 2))
        != _REPLAY_OBSERVATION_SHA256
        or document["receipt_sha256"] != _REPLAY_PAIR_RECEIPT_SHA256
    ):
        raise EvidenceRegistryError("replay pair authority pin differs")
    return count


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
            raise EvidenceRegistryError("locked evaluation row binding differs")
        parse_success = checks.get("parse_success")
        deterministic_replay = checks.get("deterministic_replay")
        if not isinstance(parse_success, bool) or not isinstance(
            deterministic_replay, bool
        ):
            raise EvidenceRegistryError("locked evaluation row result is untyped")
        seen.append(case_id)
        parse_failures += not parse_success
        replay_mismatches += not deterministic_replay
    if tuple(seen) != _EXPECTED_PACK_IDS:
        raise EvidenceRegistryError("locked evaluation denominator is incomplete")
    expected_parse_bp = (
        (len(_EXPECTED_PACK_IDS) - parse_failures) * 10_000 // len(_EXPECTED_PACK_IDS)
    )
    expected_replay_bp = (
        (len(_EXPECTED_PACK_IDS) - replay_mismatches)
        * 10_000
        // len(_EXPECTED_PACK_IDS)
    )
    if (
        metrics.get("parse_success") != expected_parse_bp
        or metrics.get("deterministic_replay") != expected_replay_bp
    ):
        raise EvidenceRegistryError("locked evaluation summary and denominator differ")
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
                None if self.evidence_class is None else self.evidence_class.value
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
            or self.registry_sha256
            not in {
                evidence_registry_sha256(),
                full_submit_evidence_registry_sha256(),
            }
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
                or self.registry_sha256 != evidence_registry_sha256()
            ):
                raise MetricIntegrityError("unevaluable metric receipt is gameable")
        elif self.metric_name == "ats_parse_success_bp":
            expected_value = (
                (self.denominator - self.numerator) * 10_000 // self.denominator
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
        elif self.metric_name == "deterministic_replay_mismatch":
            expected_status = (
                MetricStatus.PASS
                if self.numerator == self.target
                else MetricStatus.FAIL
            )
            if (
                self.denominator != 1
                or self.value != self.numerator
                or self.status is not expected_status
                or self.unit != "count"
                or self.evidence_class is not EvidenceClass.FIXTURE_FROZEN
                or self.evidence_item_ids != (_REPLAY_PAIR_ENTRY.evidence_id,)
                or self.evidence_scope_id != _REPLAY_PAIR_RECEIPT_SHA256
                or self.missing_evidence_count != 0
            ):
                raise MetricIntegrityError("replay metric receipt differs")
        elif self.metric_name in _LIVE_DEPENDENT_METRICS:
            if self.registry_sha256 != full_submit_evidence_registry_sha256():
                raise MetricIntegrityError(
                    "only registry-pinned fixture metrics are evaluable"
                )
            expected_status = (
                MetricStatus.PASS
                if self.numerator == self.target
                else MetricStatus.FAIL
            )
            if (
                self.denominator <= 0
                or self.value != self.numerator
                or self.status is not expected_status
                or self.unit != "count"
                or self.evidence_class is not EvidenceClass.FIXTURE_FROZEN
                or self.evidence_item_ids != (_FULL_SUBMIT_ENTRY.evidence_id,)
                or self.evidence_scope_id != _FULL_SUBMIT_COHORT_ID
                or self.missing_evidence_count != 0
            ):
                raise MetricIntegrityError("full-submit metric receipt differs")
        else:
            raise MetricIntegrityError(
                "only registry-pinned fixture metrics are evaluable"
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
    registry_sha256: str | None = None,
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
        "registry_sha256": (
            evidence_registry_sha256() if registry_sha256 is None else registry_sha256
        ),
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


def _build_replay_metric_receipt(
    mismatch_count: int,
    *,
    registry_sha256: str | None = None,
) -> MetricReceipt:
    if mismatch_count not in {0, 1}:
        raise MetricIntegrityError("replay mismatch count differs")
    return _build_metric_receipt(
        metric_name="deterministic_replay_mismatch",
        status=(
            MetricStatus.PASS
            if mismatch_count == HARD_QUALITY_TARGETS["deterministic_replay_mismatch"]
            else MetricStatus.FAIL
        ),
        numerator=mismatch_count,
        denominator=1,
        value=mismatch_count,
        unit="count",
        evidence_class=EvidenceClass.FIXTURE_FROZEN,
        evidence_item_ids=(_REPLAY_PAIR_ENTRY.evidence_id,),
        evidence_scope_id=_REPLAY_PAIR_RECEIPT_SHA256,
        missing_evidence_count=0,
        registry_sha256=registry_sha256,
    )


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
            "registry": _registry_document_for_sha256(self.registry_sha256),
            "registry_sha256": self.registry_sha256,
            "metrics": [metric.document() for metric in self.metrics],
            "model_call_accounting_schema_version": (
                MODEL_CALL_ACCOUNTING_SCHEMA_VERSION
            ),
            "model_call_accounting": self.model_call_accounting,
            "metrics_evaluated": True,
            "withheld_reason": (
                FULL_SUBMIT_WITHHELD_REASON
                if self.registry_sha256 == full_submit_evidence_registry_sha256()
                else WITHHELD_REASON
            ),
            **_withheld_fields(),
        }
        if include_hash:
            document["evaluation_sha256"] = self.evaluation_sha256
        return document

    def verify(self) -> None:
        live_statuses = tuple(
            metric.status
            for metric in self.metrics
            if metric.metric_name in _LIVE_DEPENDENT_METRICS
        )
        if all(status is MetricStatus.UNEVALUABLE for status in live_statuses):
            expected_registry_sha256 = evidence_registry_sha256()
        elif all(status is not MetricStatus.UNEVALUABLE for status in live_statuses):
            expected_registry_sha256 = full_submit_evidence_registry_sha256()
        else:
            raise MetricIntegrityError("hard-metrics live population is partial")
        if (
            self.registry_sha256 != expected_registry_sha256
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
    replay_pair_document: Mapping[str, object],
) -> HardMetricsEvaluation:
    fixture_artifacts = _validate_fixture_document(fixture_document)
    parse_failures, _replay_mismatches = _validate_report_document(
        report_document,
        fixture_artifacts=fixture_artifacts,
    )
    replay_mismatch_count = _validate_replay_pair(replay_pair_document)
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
        elif metric_name == "deterministic_replay_mismatch":
            receipt = _build_replay_metric_receipt(replay_mismatch_count)
        else:
            receipt = _build_metric_receipt(
                metric_name=metric_name,
                status=MetricStatus.UNEVALUABLE,
                numerator=0,
                denominator=0,
                value=None,
                unit=("count"),
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


def _derive_full_submit_from_documents(
    fixture_document: Mapping[str, object],
    report_document: Mapping[str, object],
    replay_pair_document: Mapping[str, object],
    full_submit_document: Mapping[str, object],
) -> HardMetricsEvaluation:
    """Derive the admitted shadow metrics from fixed registry documents only."""

    fixture_artifacts = _validate_fixture_document(fixture_document)
    parse_failures, _replay_mismatches = _validate_report_document(
        report_document,
        fixture_artifacts=fixture_artifacts,
    )
    replay_mismatch_count = _validate_replay_pair(replay_pair_document)
    full_submit_counts = _validate_full_submit_cohort(full_submit_document)
    registry_sha256 = full_submit_evidence_registry_sha256()
    receipts: list[MetricReceipt] = []
    for metric_name in sorted(HARD_QUALITY_TARGETS):
        if metric_name == "ats_parse_success_bp":
            denominator = len(_EXPECTED_PACK_IDS)
            value = (denominator - parse_failures) * 10_000 // denominator
            receipt = _build_metric_receipt(
                metric_name=metric_name,
                status=(
                    MetricStatus.PASS
                    if value == HARD_QUALITY_TARGETS[metric_name]
                    else MetricStatus.FAIL
                ),
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
                registry_sha256=registry_sha256,
            )
        elif metric_name == "deterministic_replay_mismatch":
            receipt = _build_replay_metric_receipt(
                replay_mismatch_count,
                registry_sha256=registry_sha256,
            )
        else:
            numerator, denominator = full_submit_counts[metric_name]
            receipt = _build_metric_receipt(
                metric_name=metric_name,
                status=(
                    MetricStatus.PASS
                    if numerator == HARD_QUALITY_TARGETS[metric_name]
                    else MetricStatus.FAIL
                ),
                numerator=numerator,
                denominator=denominator,
                value=numerator,
                unit="count",
                evidence_class=EvidenceClass.FIXTURE_FROZEN,
                evidence_item_ids=(_FULL_SUBMIT_ENTRY.evidence_id,),
                evidence_scope_id=_FULL_SUBMIT_COHORT_ID,
                missing_evidence_count=0,
                registry_sha256=registry_sha256,
            )
        receipts.append(receipt)
    evaluation = object.__new__(HardMetricsEvaluation)
    object.__setattr__(evaluation, "metrics", tuple(receipts))
    object.__setattr__(evaluation, "registry_sha256", registry_sha256)
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
    replay_pair_payload = _read_registry_entry(
        _REPLAY_PAIR_ENTRY,
        repository_root=repository_root,
        control_root=control_root,
    )
    replay_pair_document = _json_object(replay_pair_payload, "frozen replay pair")
    if replay_pair_payload != (_canonical_json(replay_pair_document) + "\n").encode(
        "utf-8"
    ):
        raise EvidenceRegistryError("frozen replay pair is not canonical JSON")
    return _derive_from_documents(
        _json_object(fixture_payload, "locked application-pack fixture"),
        _json_object(report_payload, "locked evaluation report"),
        replay_pair_document,
    )


def evaluate_full_submit_hard_metrics() -> HardMetricsEvaluation:
    """Evaluate the admitted, registry-pinned localhost full-submit cohort."""

    repository_root = _repository_root()
    control_root = _operator_control_root(repository_root)
    payloads = {
        evidence_id: _read_registry_entry(
            entry,
            repository_root=repository_root,
            control_root=control_root,
        )
        for evidence_id, entry in FULL_SUBMIT_EVIDENCE_REGISTRY.items()
    }
    fixture_payload = payloads[_FIXTURE_ENTRY.evidence_id]
    report_payload = payloads[_REPORT_ENTRY.evidence_id]
    replay_pair_payload = payloads[_REPLAY_PAIR_ENTRY.evidence_id]
    full_submit_payload = payloads[_FULL_SUBMIT_ENTRY.evidence_id]
    replay_pair_document = _json_object(replay_pair_payload, "frozen replay pair")
    full_submit_document = _json_object(
        full_submit_payload,
        "full-submit shadow cohort",
    )
    for payload, document, label in (
        (replay_pair_payload, replay_pair_document, "frozen replay pair"),
        (full_submit_payload, full_submit_document, "full-submit shadow cohort"),
    ):
        if payload != (_canonical_json(document) + "\n").encode("utf-8"):
            raise EvidenceRegistryError(f"{label} is not canonical JSON")
    return _derive_full_submit_from_documents(
        _json_object(fixture_payload, "locked application-pack fixture"),
        _json_object(report_payload, "locked evaluation report"),
        replay_pair_document,
        full_submit_document,
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
            raise ReceiptPublicationError("receipt staging target is not regular")
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
        raise ReceiptPublicationError("receipt publication must be exclusive") from exc
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
