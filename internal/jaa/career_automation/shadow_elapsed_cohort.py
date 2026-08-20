"""Same-boot elapsed-time rehearsal for JAA-10 loopback fixture evidence.

This package cannot browse, submit, evaluate metrics, authenticate calendar
time, or collect live external evidence.  It wraps accepted typed fixture
observations with a local Linux same-boot elapsed witness only.
"""

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from career_automation.shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    HARD_QUALITY_TARGETS,
    MINIMUM_SHADOW_SEPARATION,
    ShadowObservation,
)
from career_automation.shadow_fixture_measures import (
    FixtureMeasuresReport,
    FixtureMeasuresStaleSnapshotError,
)
from career_automation.shadow_observation_ledger import (
    FILESYSTEM_WRITER_LIMIT,
    ObservationLedgerIdentity,
    ObservationLedgerIntegrityError,
    ObservationLedgerReceipt,
    ShadowObservationLedger,
)


COHORT_SCHEMA_VERSION = "jaa10.shadow-elapsed-cohort.v1"
COHORT_RECEIPT_DOMAIN = b"jaa10-shadow-elapsed-cohort-receipt-v1\0"
EVIDENCE_CLASS = "loopback_fixture_browser_elapsed"
FORBIDDEN_EVIDENCE_CLASSES = (
    "external_read_only_shadow",
    "externally_time_attested_shadow",
)
CALENDAR_TIME_AUTHENTICATION = "absent_same_boot_scope_only"
EXTERNAL_TIME_ATTESTATION = "absent"
CONTAMINATION_POLICY = (
    "cohort_outputs_are_locked_evidence_never_tuning_input_for_"
    "same_source_version"
)
CLAIM = "loopback_fixture_elapsed_interval_same_boot_local_only"
LIVE_EXECUTION = "not_collected"
PRODUCTION_CERTIFICATION = "withheld"
HARD_TARGET_STATUS = "not_evaluable_from_elapsed_fixture_cohort"
KERNEL_TIME_LIMIT = (
    "same_boot_clock_boottime_honest_kernel_not_calendar_authenticated"
)
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
MAX_COUNTER_NS = (1 << 63) - 1
MINIMUM_ELAPSED_NS = int(
    MINIMUM_SHADOW_SEPARATION.total_seconds() * 1_000_000_000
)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_GIT_ID = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_CONTENT_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_BOOT_ID = re.compile(
    rb"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    rb"[0-9a-f]{4}-[0-9a-f]{12}\n?$"
)
_COHORT_ID_DOMAIN = b"jaa10-shadow-elapsed-cohort-id-v1\0"
_PROCESS_TOKEN_DOMAIN = b"jaa10-shadow-elapsed-process-v1\0"
_PROCESS_TOKEN = hashlib.sha256(
    _PROCESS_TOKEN_DOMAIN + os.urandom(32)
).hexdigest()
_CLOSED_COHORT_IDS: set[str] = set()


class ElapsedCohortError(RuntimeError):
    """Base error for the bounded elapsed-cohort rehearsal."""


class ElapsedCohortIntegrityError(ElapsedCohortError):
    """A cohort receipt or accepted lineage differs."""


class ElapsedCohortStateError(ElapsedCohortError):
    """The requested OPEN-to-CLOSED transition is invalid."""


class ElapsedCohortTimeWitnessError(ElapsedCohortError):
    """The local same-boot time witness cannot support the bounded claim."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _domain_hash(domain: bytes, payload: bytes) -> str:
    digest = hashlib.sha256(domain)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _receipt_hash(document: Mapping[str, object]) -> str:
    return _domain_hash(
        COHORT_RECEIPT_DOMAIN,
        _canonical_json(dict(document)).encode("utf-8"),
    )


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _source_identity(
    git_revision: str,
    tree: str,
    content_revision: str,
) -> dict[str, str]:
    if (
        not isinstance(git_revision, str)
        or not _GIT_ID.fullmatch(git_revision)
        or not isinstance(tree, str)
        or not _GIT_ID.fullmatch(tree)
        or not isinstance(content_revision, str)
        or not _SOURCE_CONTENT_ID.fullmatch(content_revision)
    ):
        raise ValueError("elapsed cohort source identity is invalid")
    return {
        "git_revision": git_revision,
        "tree": tree,
        "content_revision": content_revision,
    }


def _hard_quality_targets() -> dict[str, dict[str, object]]:
    return {
        key: {"target": target, "status": HARD_TARGET_STATUS}
        for key, target in sorted(HARD_QUALITY_TARGETS.items())
    }


def _withheld_document() -> dict[str, object]:
    return {
        "objective_satisfied": False,
        "metrics_evaluated": False,
        "hard_quality_targets": _hard_quality_targets(),
        "live_time_separated_execution": LIVE_EXECUTION,
        "production_certification": PRODUCTION_CERTIFICATION,
        "certifies_slice": False,
        "external_action_capability": False,
        "real_applications_submitted": 0,
        "external_time_attestation": EXTERNAL_TIME_ATTESTATION,
        "calendar_time_authentication": CALENDAR_TIME_AUTHENTICATION,
        "filesystem_privileged_writer_limit": FILESYSTEM_WRITER_LIMIT,
        "kernel_time_witness_limit": KERNEL_TIME_LIMIT,
    }


@dataclass(frozen=True)
class ElapsedTimeWitness:
    boot_id_sha256: str
    clock_boottime_ns: int
    monotonic_ns: int
    process_token: str
    recorded_wall_clock: str

    def __post_init__(self) -> None:
        _digest(self.boot_id_sha256, "boot identity hash")
        _digest(self.process_token, "elapsed-witness process token")
        for content, label in (
            (self.clock_boottime_ns, "CLOCK_BOOTTIME witness"),
            (self.monotonic_ns, "monotonic witness"),
        ):
            if (
                not isinstance(content, int)
                or isinstance(content, bool)
                or content < 1
                or content > MAX_COUNTER_NS
            ):
                raise ValueError(f"{label} is invalid")
        try:
            recorded = datetime.fromisoformat(self.recorded_wall_clock)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "elapsed-witness wall clock is invalid"
            ) from exc
        if recorded.tzinfo is None or recorded.utcoffset() is None:
            raise ValueError(
                "elapsed-witness wall clock must include a timezone"
            )
        if recorded.astimezone(timezone.utc).isoformat() != (
            self.recorded_wall_clock
        ):
            raise ValueError(
                "elapsed-witness wall clock must be canonical UTC"
            )

    def document(self) -> dict[str, object]:
        return {
            "boot_id_sha256": self.boot_id_sha256,
            "clock_boottime_ns": self.clock_boottime_ns,
            "monotonic_ns": self.monotonic_ns,
            "process_token": self.process_token,
            "recorded_wall_clock": self.recorded_wall_clock,
        }


def _boot_id_bytes() -> bytes:
    try:
        boot_id = BOOT_ID_PATH.read_bytes()
    except OSError as exc:
        raise ElapsedCohortTimeWitnessError(
            "kernel boot identity is unavailable"
        ) from exc
    if not _BOOT_ID.fullmatch(boot_id):
        raise ElapsedCohortTimeWitnessError(
            "kernel boot identity is invalid"
        )
    return boot_id


def capture_elapsed_time_witness() -> ElapsedTimeWitness:
    """Capture raw Linux same-boot counters with no caller clock."""
    if not hasattr(time, "CLOCK_BOOTTIME"):
        raise ElapsedCohortTimeWitnessError(
            "CLOCK_BOOTTIME is unavailable"
        )
    boot_id_before = _boot_id_bytes()
    try:
        boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        monotonic_ns = time.monotonic_ns()
    except (OSError, ValueError) as exc:
        raise ElapsedCohortTimeWitnessError(
            "kernel elapsed-time witness is unavailable"
        ) from exc
    boot_id_after = _boot_id_bytes()
    if boot_id_before != boot_id_after:
        raise ElapsedCohortTimeWitnessError(
            "kernel boot identity changed during capture"
        )
    return ElapsedTimeWitness(
        hashlib.sha256(boot_id_before).hexdigest(),
        boottime_ns,
        monotonic_ns,
        _PROCESS_TOKEN,
        datetime.now(timezone.utc).isoformat(),
    )


def _ledger_identity_document(
    identity: ObservationLedgerIdentity,
) -> dict[str, str]:
    if not isinstance(identity, ObservationLedgerIdentity):
        raise TypeError("elapsed cohort requires a typed ledger identity")
    return {
        "contract_sha256": identity.contract_sha256,
        "ledger_instance_id": identity.ledger_instance_id,
        "genesis_receipt_sha256": identity.genesis_receipt_sha256,
        "fixture_policy_sha256": identity.fixture_policy_sha256,
    }


def _receipt_copy(
    receipt: ObservationLedgerReceipt,
) -> ObservationLedgerReceipt:
    if not isinstance(receipt, ObservationLedgerReceipt):
        raise TypeError("elapsed cohort requires a typed ledger receipt")
    try:
        return ObservationLedgerReceipt(
            receipt.receipt_sha256,
            dict(receipt.document),
        )
    except ObservationLedgerIntegrityError as exc:
        raise ElapsedCohortIntegrityError(
            "elapsed-cohort ledger receipt differs"
        ) from exc


def _embedded_receipt(
    receipt: ObservationLedgerReceipt,
) -> dict[str, object]:
    copied = _receipt_copy(receipt)
    return {
        "receipt_sha256": copied.receipt_sha256,
        "document": dict(copied.document),
    }


def _binding(
    observation: ShadowObservation,
    receipt: ObservationLedgerReceipt,
    head_sha256: str,
) -> dict[str, str]:
    if not isinstance(observation, ShadowObservation):
        raise TypeError("elapsed cohort requires a typed shadow observation")
    copied = _receipt_copy(receipt)
    expected = (
        observation.observation_id,
        observation.observation_sha256,
        observation.observed_at,
    )
    actual = (
        copied.document.get("observation_id"),
        copied.document.get("observation_sha256"),
        copied.document.get("source_observed_at"),
    )
    if (
        copied.document.get("event_type") != "observation_recorded"
        or actual != expected
        or copied.receipt_sha256 != head_sha256
    ):
        raise ElapsedCohortIntegrityError(
            "elapsed-cohort observation binding differs"
        )
    return {
        "observation_id": observation.observation_id,
        "observation_sha256": observation.observation_sha256,
        "ledger_receipt_sha256": copied.receipt_sha256,
        "ledger_head_receipt_sha256": head_sha256,
    }


def _verify_report_current(
    report: FixtureMeasuresReport,
    ledger: ShadowObservationLedger,
) -> None:
    try:
        report.verify_current(ledger)
    except FixtureMeasuresStaleSnapshotError as exc:
        raise ElapsedCohortStateError(
            "fixture-measures snapshot is stale"
        ) from exc


def _open_core(
    *,
    source: Mapping[str, str],
    ledger_identity: ObservationLedgerIdentity,
    report_id: str,
    receipt_count: int,
    binding: Mapping[str, str],
    receipt: ObservationLedgerReceipt,
    witness: ElapsedTimeWitness,
) -> dict[str, object]:
    return {
        "schema_version": COHORT_SCHEMA_VERSION,
        "state": "OPEN",
        "evidence_class": EVIDENCE_CLASS,
        "source": dict(source),
        "contract_sha256": FROZEN_SHADOW_CONTRACT.contract_sha256,
        "ledger_identity": _ledger_identity_document(ledger_identity),
        "fixture_measures_report_id": report_id,
        "ledger_receipt_count": receipt_count,
        "first_observation_binding": dict(binding),
        "first_ledger_receipt": _embedded_receipt(receipt),
        "first_witness": witness.document(),
        "contamination_policy": CONTAMINATION_POLICY,
        **_withheld_document(),
    }


@dataclass(frozen=True, init=False)
class ElapsedCohortOpenReceipt:
    cohort_id: str
    source: Mapping[str, str]
    ledger_identity: ObservationLedgerIdentity
    fixture_measures_report_id: str
    ledger_receipt_count: int
    first_observation_binding: Mapping[str, str]
    first_ledger_receipt: ObservationLedgerReceipt
    first_witness: ElapsedTimeWitness
    receipt_sha256: str

    def __init__(self) -> None:
        raise TypeError(
            "elapsed-cohort OPEN receipts require the verified opener"
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source",
            MappingProxyType(dict(self.source)),
        )
        object.__setattr__(
            self,
            "first_observation_binding",
            MappingProxyType(dict(self.first_observation_binding)),
        )
        self.verify()

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        core = _open_core(
            source=self.source,
            ledger_identity=self.ledger_identity,
            report_id=self.fixture_measures_report_id,
            receipt_count=self.ledger_receipt_count,
            binding=self.first_observation_binding,
            receipt=self.first_ledger_receipt,
            witness=self.first_witness,
        )
        document = {"cohort_id": self.cohort_id, **core}
        if include_hash:
            document["receipt_sha256"] = self.receipt_sha256
        return document

    def verify(self) -> None:
        source = _source_identity(
            self.source.get("git_revision", ""),
            self.source.get("tree", ""),
            self.source.get("content_revision", ""),
        )
        _digest(
            self.fixture_measures_report_id,
            "fixture-measures report identity",
        )
        if (
            self.ledger_identity.contract_sha256
            != FROZEN_SHADOW_CONTRACT.contract_sha256
            or not isinstance(self.ledger_receipt_count, int)
            or self.ledger_receipt_count < 3
            or self.ledger_receipt_count % 2 != 1
            or not isinstance(self.first_witness, ElapsedTimeWitness)
        ):
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort OPEN lineage differs"
            )
        copied = _receipt_copy(self.first_ledger_receipt)
        binding = dict(self.first_observation_binding)
        if set(binding) != {
            "observation_id",
            "observation_sha256",
            "ledger_receipt_sha256",
            "ledger_head_receipt_sha256",
        }:
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort OPEN binding shape differs"
            )
        _digest(binding["observation_sha256"], "first observation hash")
        for label in (
            "ledger_receipt_sha256",
            "ledger_head_receipt_sha256",
        ):
            _digest(binding[label], f"first {label}")
        if (
            copied.document.get("event_type") != "observation_recorded"
            or copied.document.get("sequence") != self.ledger_receipt_count
            or copied.document.get("contract_sha256")
            != self.ledger_identity.contract_sha256
            or copied.document.get("ledger_instance_id")
            != self.ledger_identity.ledger_instance_id
            or copied.document.get("observation_id")
            != binding["observation_id"]
            or copied.document.get("observation_sha256")
            != binding["observation_sha256"]
            or copied.receipt_sha256 != binding["ledger_receipt_sha256"]
            or copied.receipt_sha256
            != binding["ledger_head_receipt_sha256"]
        ):
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort OPEN receipt binding differs"
            )
        core = _open_core(
            source=source,
            ledger_identity=self.ledger_identity,
            report_id=self.fixture_measures_report_id,
            receipt_count=self.ledger_receipt_count,
            binding=binding,
            receipt=copied,
            witness=self.first_witness,
        )
        expected_cohort_id = _domain_hash(
            _COHORT_ID_DOMAIN,
            _canonical_json(core).encode("utf-8"),
        )
        if self.cohort_id != expected_cohort_id:
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort identity differs"
            )
        expected_receipt = _receipt_hash(
            {"cohort_id": self.cohort_id, **core}
        )
        if self.receipt_sha256 != expected_receipt:
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort OPEN receipt hash differs"
            )

    def verify_current(
        self,
        ledger: ShadowObservationLedger,
        report: FixtureMeasuresReport,
    ) -> None:
        self.verify()
        if (
            not isinstance(ledger, ShadowObservationLedger)
            or not isinstance(report, FixtureMeasuresReport)
        ):
            raise TypeError(
                "elapsed-cohort current verification requires typed inputs"
            )
        _verify_report_current(report, ledger)
        if (
            ledger.identity != self.ledger_identity
            or report.report_id != self.fixture_measures_report_id
            or report.receipt_count != self.ledger_receipt_count
            or report.chain_head_receipt.receipt_sha256
            != self.first_observation_binding[
                "ledger_head_receipt_sha256"
            ]
        ):
            raise ElapsedCohortStateError(
                "elapsed-cohort OPEN receipt is stale"
            )


def _validated_current_observation(
    ledger: ShadowObservationLedger,
    identity: ObservationLedgerIdentity,
    observation: ShadowObservation,
    report: FixtureMeasuresReport,
) -> tuple[ObservationLedgerReceipt, int]:
    if not isinstance(ledger, ShadowObservationLedger):
        raise TypeError("elapsed cohort requires a typed ledger")
    if not isinstance(identity, ObservationLedgerIdentity):
        raise TypeError("elapsed cohort requires a typed ledger identity")
    if not isinstance(observation, ShadowObservation):
        raise TypeError("elapsed cohort requires a typed observation")
    if not isinstance(report, FixtureMeasuresReport):
        raise TypeError("elapsed cohort requires a fixture-measures report")
    _verify_report_current(report, ledger)
    if (
        identity != ledger.identity
        or report.ledger_identity != identity
        or not report.observations
        or report.observations[-1].observation_id
        != observation.observation_id
        or report.observations[-1].observation_sha256
        != observation.observation_sha256
    ):
        raise ElapsedCohortIntegrityError(
            "elapsed-cohort current observation differs"
        )
    receipt = report.observation_receipts[-1]
    _binding(
        observation,
        receipt,
        report.chain_head_receipt.receipt_sha256,
    )
    return receipt, report.receipt_count


def _open_with_witness(
    ledger: ShadowObservationLedger,
    identity: ObservationLedgerIdentity,
    observation: ShadowObservation,
    report: FixtureMeasuresReport,
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
    witness: ElapsedTimeWitness,
) -> ElapsedCohortOpenReceipt:
    source = _source_identity(
        source_git_revision,
        source_tree,
        source_content_revision,
    )
    receipt, receipt_count = _validated_current_observation(
        ledger,
        identity,
        observation,
        report,
    )
    binding = _binding(
        observation,
        receipt,
        report.chain_head_receipt.receipt_sha256,
    )
    core = _open_core(
        source=source,
        ledger_identity=identity,
        report_id=report.report_id,
        receipt_count=receipt_count,
        binding=binding,
        receipt=receipt,
        witness=witness,
    )
    cohort_id = _domain_hash(
        _COHORT_ID_DOMAIN,
        _canonical_json(core).encode("utf-8"),
    )
    receipt_sha256 = _receipt_hash(
        {"cohort_id": cohort_id, **core}
    )
    opened = object.__new__(ElapsedCohortOpenReceipt)
    for name, content in (
        ("cohort_id", cohort_id),
        ("source", source),
        ("ledger_identity", identity),
        ("fixture_measures_report_id", report.report_id),
        ("ledger_receipt_count", receipt_count),
        ("first_observation_binding", binding),
        ("first_ledger_receipt", _receipt_copy(receipt)),
        ("first_witness", witness),
        ("receipt_sha256", receipt_sha256),
    ):
        object.__setattr__(opened, name, content)
    opened.__post_init__()
    return opened


def open_elapsed_cohort(
    ledger: ShadowObservationLedger,
    identity: ObservationLedgerIdentity,
    observation: ShadowObservation,
    report: FixtureMeasuresReport,
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
) -> ElapsedCohortOpenReceipt:
    """Open a bounded cohort using raw same-boot kernel evidence."""
    return _open_with_witness(
        ledger,
        identity,
        observation,
        report,
        source_git_revision,
        source_tree,
        source_content_revision,
        capture_elapsed_time_witness(),
    )


def _close_core(
    *,
    opened: ElapsedCohortOpenReceipt,
    source: Mapping[str, str],
    report_id: str,
    receipt_count: int,
    binding: Mapping[str, str],
    receipt: ObservationLedgerReceipt,
    witness: ElapsedTimeWitness,
    elapsed_ns: int,
) -> dict[str, object]:
    return {
        "schema_version": COHORT_SCHEMA_VERSION,
        "state": "CLOSED",
        "evidence_class": EVIDENCE_CLASS,
        "cohort_id": opened.cohort_id,
        "open_receipt": {
            "receipt_sha256": opened.receipt_sha256,
            "document": opened.document(include_hash=False),
        },
        "source": dict(source),
        "contract_sha256": FROZEN_SHADOW_CONTRACT.contract_sha256,
        "ledger_identity": _ledger_identity_document(
            opened.ledger_identity
        ),
        "fixture_measures_report_id": report_id,
        "ledger_receipt_count": receipt_count,
        "second_observation_binding": dict(binding),
        "second_ledger_receipt": _embedded_receipt(receipt),
        "second_witness": witness.document(),
        "same_boot": True,
        "elapsed_boottime_ns": elapsed_ns,
        "claim": CLAIM,
        "contamination_policy": CONTAMINATION_POLICY,
        **_withheld_document(),
    }


@dataclass(frozen=True, init=False)
class ElapsedCohortCloseReceipt:
    open_receipt: ElapsedCohortOpenReceipt
    source: Mapping[str, str]
    fixture_measures_report_id: str
    ledger_receipt_count: int
    second_observation_binding: Mapping[str, str]
    second_ledger_receipt: ObservationLedgerReceipt
    second_witness: ElapsedTimeWitness
    same_boot: bool
    elapsed_boottime_ns: int
    claim: str
    receipt_sha256: str

    def __init__(self) -> None:
        raise TypeError(
            "elapsed-cohort CLOSED receipts require the verified closer"
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source",
            MappingProxyType(dict(self.source)),
        )
        object.__setattr__(
            self,
            "second_observation_binding",
            MappingProxyType(dict(self.second_observation_binding)),
        )
        self.verify()

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        core = _close_core(
            opened=self.open_receipt,
            source=self.source,
            report_id=self.fixture_measures_report_id,
            receipt_count=self.ledger_receipt_count,
            binding=self.second_observation_binding,
            receipt=self.second_ledger_receipt,
            witness=self.second_witness,
            elapsed_ns=self.elapsed_boottime_ns,
        )
        if include_hash:
            core["receipt_sha256"] = self.receipt_sha256
        return core

    def verify(self) -> None:
        if not isinstance(
            self.open_receipt,
            ElapsedCohortOpenReceipt,
        ):
            raise TypeError("CLOSED receipt requires a typed OPEN receipt")
        self.open_receipt.verify()
        source = _source_identity(
            self.source.get("git_revision", ""),
            self.source.get("tree", ""),
            self.source.get("content_revision", ""),
        )
        if source != dict(self.open_receipt.source):
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort source changed before close"
            )
        _digest(
            self.fixture_measures_report_id,
            "closing fixture-measures report identity",
        )
        copied = _receipt_copy(self.second_ledger_receipt)
        binding = dict(self.second_observation_binding)
        if set(binding) != {
            "observation_id",
            "observation_sha256",
            "ledger_receipt_sha256",
            "ledger_head_receipt_sha256",
        }:
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort CLOSED binding shape differs"
            )
        if (
            self.ledger_receipt_count
            != self.open_receipt.ledger_receipt_count + 2
            or copied.document.get("sequence")
            != self.ledger_receipt_count
            or copied.document.get("event_type")
            != "observation_recorded"
            or copied.document.get("contract_sha256")
            != self.open_receipt.ledger_identity.contract_sha256
            or copied.document.get("ledger_instance_id")
            != self.open_receipt.ledger_identity.ledger_instance_id
            or copied.document.get("observation_id")
            != binding.get("observation_id")
            or copied.document.get("observation_sha256")
            != binding.get("observation_sha256")
            or copied.receipt_sha256
            != binding.get("ledger_receipt_sha256")
            or copied.receipt_sha256
            != binding.get("ledger_head_receipt_sha256")
            or binding.get("observation_id")
            == self.open_receipt.first_observation_binding[
                "observation_id"
            ]
            or binding.get("observation_sha256")
            == self.open_receipt.first_observation_binding[
                "observation_sha256"
            ]
        ):
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort CLOSED receipt lineage differs"
            )
        if not isinstance(self.second_witness, ElapsedTimeWitness):
            raise ElapsedCohortTimeWitnessError(
                "elapsed-cohort closing witness is untyped"
            )
        expected_elapsed = (
            self.second_witness.clock_boottime_ns
            - self.open_receipt.first_witness.clock_boottime_ns
        )
        if (
            self.second_witness.boot_id_sha256
            != self.open_receipt.first_witness.boot_id_sha256
            or self.same_boot is not True
            or not isinstance(self.elapsed_boottime_ns, int)
            or self.elapsed_boottime_ns != expected_elapsed
            or expected_elapsed < MINIMUM_ELAPSED_NS
            or expected_elapsed > MAX_COUNTER_NS
        ):
            raise ElapsedCohortTimeWitnessError(
                "same-boot elapsed witness is insufficient or changed"
            )
        if (
            self.second_witness.process_token
            == self.open_receipt.first_witness.process_token
            and self.second_witness.monotonic_ns
            <= self.open_receipt.first_witness.monotonic_ns
        ):
            raise ElapsedCohortTimeWitnessError(
                "same-process monotonic witness did not advance"
            )
        if self.claim != CLAIM:
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort claim differs"
            )
        core = _close_core(
            opened=self.open_receipt,
            source=source,
            report_id=self.fixture_measures_report_id,
            receipt_count=self.ledger_receipt_count,
            binding=binding,
            receipt=copied,
            witness=self.second_witness,
            elapsed_ns=expected_elapsed,
        )
        if self.receipt_sha256 != _receipt_hash(core):
            raise ElapsedCohortIntegrityError(
                "elapsed-cohort CLOSED receipt hash differs"
            )

    def verify_current(
        self,
        ledger: ShadowObservationLedger,
        report: FixtureMeasuresReport,
    ) -> None:
        self.verify()
        if (
            not isinstance(ledger, ShadowObservationLedger)
            or not isinstance(report, FixtureMeasuresReport)
        ):
            raise TypeError(
                "elapsed-cohort current verification requires typed inputs"
            )
        _verify_report_current(report, ledger)
        if (
            ledger.identity != self.open_receipt.ledger_identity
            or report.report_id != self.fixture_measures_report_id
            or report.receipt_count != self.ledger_receipt_count
            or report.chain_head_receipt.receipt_sha256
            != self.second_observation_binding[
                "ledger_head_receipt_sha256"
            ]
        ):
            raise ElapsedCohortStateError(
                "elapsed-cohort CLOSED receipt is stale"
            )


def _close_with_witness(
    opened: ElapsedCohortOpenReceipt,
    ledger: ShadowObservationLedger,
    identity: ObservationLedgerIdentity,
    observation: ShadowObservation,
    report: FixtureMeasuresReport,
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
    witness: ElapsedTimeWitness,
) -> ElapsedCohortCloseReceipt:
    if not isinstance(opened, ElapsedCohortOpenReceipt):
        raise TypeError("elapsed cohort close requires an OPEN receipt")
    opened.verify()
    if opened.cohort_id in _CLOSED_COHORT_IDS:
        raise ElapsedCohortStateError(
            "elapsed cohort is already CLOSED in this process"
        )
    source = _source_identity(
        source_git_revision,
        source_tree,
        source_content_revision,
    )
    if source != dict(opened.source) or identity != opened.ledger_identity:
        raise ElapsedCohortIntegrityError(
            "elapsed cohort source or ledger changed before close"
        )
    receipt, receipt_count = _validated_current_observation(
        ledger,
        identity,
        observation,
        report,
    )
    if receipt_count != opened.ledger_receipt_count + 2:
        raise ElapsedCohortStateError(
            "elapsed cohort close is not the next observation"
        )
    expected_observation_count = (
        (opened.ledger_receipt_count - 1) // 2
    ) + 1
    if (
        len(report.observations) != expected_observation_count
        or report.observations[-2].observation_sha256
        != opened.first_observation_binding["observation_sha256"]
    ):
        raise ElapsedCohortStateError(
            "elapsed cohort observation sequence differs"
        )
    binding = _binding(
        observation,
        receipt,
        report.chain_head_receipt.receipt_sha256,
    )
    elapsed_ns = (
        witness.clock_boottime_ns
        - opened.first_witness.clock_boottime_ns
    )
    core = _close_core(
        opened=opened,
        source=source,
        report_id=report.report_id,
        receipt_count=receipt_count,
        binding=binding,
        receipt=receipt,
        witness=witness,
        elapsed_ns=elapsed_ns,
    )
    closing = object.__new__(ElapsedCohortCloseReceipt)
    for name, content in (
        ("open_receipt", opened),
        ("source", source),
        ("fixture_measures_report_id", report.report_id),
        ("ledger_receipt_count", receipt_count),
        ("second_observation_binding", binding),
        ("second_ledger_receipt", _receipt_copy(receipt)),
        ("second_witness", witness),
        ("same_boot", True),
        ("elapsed_boottime_ns", elapsed_ns),
        ("claim", CLAIM),
        ("receipt_sha256", _receipt_hash(core)),
    ):
        object.__setattr__(closing, name, content)
    closing.__post_init__()
    _CLOSED_COHORT_IDS.add(opened.cohort_id)
    return closing


def close_elapsed_cohort(
    opened: ElapsedCohortOpenReceipt,
    ledger: ShadowObservationLedger,
    identity: ObservationLedgerIdentity,
    observation: ShadowObservation,
    report: FixtureMeasuresReport,
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
) -> ElapsedCohortCloseReceipt:
    """Close a bounded cohort using raw same-boot kernel evidence."""
    return _close_with_witness(
        opened,
        ledger,
        identity,
        observation,
        report,
        source_git_revision,
        source_tree,
        source_content_revision,
        capture_elapsed_time_witness(),
    )


def verify_elapsed_cohort(
    opened: ElapsedCohortOpenReceipt,
    closed: ElapsedCohortCloseReceipt,
) -> None:
    """Verify one complete bounded cohort entirely offline."""
    if (
        not isinstance(opened, ElapsedCohortOpenReceipt)
        or not isinstance(closed, ElapsedCohortCloseReceipt)
    ):
        raise TypeError("elapsed-cohort verification requires typed receipts")
    opened.verify()
    closed.verify()
    if closed.open_receipt.receipt_sha256 != opened.receipt_sha256:
        raise ElapsedCohortIntegrityError(
            "CLOSED receipt belongs to a different OPEN receipt"
        )
