"""Runtime evidence for fail-closed JAA-10 shadow controls.

This module does not decide certification or metrics.  It records what an
executed negative control actually did and rejects asserted verdicts, missing
exceptions, receipt creation, and mutable or non-regular evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import InitVar, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, TypeVar

from .shadow_certification import (
    MUTATION_TEST_NODES,
    REQUIRED_MUTATION_CONTROLS,
    MutationObservation,
)


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
ADDITIONAL_RUNTIME_TWINS = (
    "stub_executor",
    "fabricated_receipt",
    "missing_receipt",
    "zero_denominator",
    "omitted_unit",
    "cross_cohort_substitution",
    "observed_time_tamper",
    "content_hash_tamper",
    "symlink_evidence",
    "special_file_evidence",
    "caller_verdict",
    "caller_target",
    "caller_count",
    "caller_state",
)
RUNTIME_CONTROL_IDS = REQUIRED_MUTATION_CONTROLS + ADDITIONAL_RUNTIME_TWINS
OUTCOME_KINDS = (
    "production_exception",
    "fixture_http_rejection",
    "store_state_invariance",
    "contract_rejection",
)
_FIXTURE_HTTP_CONTROLS = {"local_origin_drift"}
_STORE_STATE_CONTROLS = {"duplicate_submit"}
_CONTRACT_CONTROLS = {
    "stub_executor",
    "zero_denominator",
    "omitted_unit",
    "cross_cohort_substitution",
    "caller_verdict",
    "caller_target",
}
REQUIRED_OUTCOME_KIND: Mapping[str, str] = MappingProxyType(
    {
        control_id: (
            "fixture_http_rejection"
            if control_id in _FIXTURE_HTTP_CONTROLS
            else "store_state_invariance"
            if control_id in _STORE_STATE_CONTROLS
            else "contract_rejection"
            if control_id in _CONTRACT_CONTROLS
            else "production_exception"
        )
        for control_id in RUNTIME_CONTROL_IDS
    }
)
_FACTORY_TOKEN = object()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _state_document(state: Mapping[str, object]) -> dict[str, object]:
    document = dict(state)
    if set(document) != {
        "receipt_count",
        "submit_click_count",
        "dispatch_state",
        "event_count",
    }:
        raise ValueError("runtime state proof has an unsupported field inventory")
    for name in ("receipt_count", "submit_click_count", "event_count"):
        value = document[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"runtime state {name} must be a non-negative integer")
    dispatch = document["dispatch_state"]
    if dispatch is not None and not isinstance(dispatch, str):
        raise ValueError("runtime dispatch state must be text or null")
    return document


@dataclass(frozen=True)
class ObservedOutcome:
    """Typed proof emitted by an executed control, never a caller verdict."""

    kind: str
    result_sha256: str
    exception_type: str | None = None
    exception_message_sha256: str | None = None
    http_statuses: tuple[int, ...] = ()
    request_variants: tuple[str, ...] = ()
    callable_identity: str | None = None
    artifact_materialized: bool = False
    _creation_token: InitVar[object] = None

    def __post_init__(self, _creation_token: object) -> None:
        if _creation_token is not _FACTORY_TOKEN:
            raise ValueError("observed outcome must be derived by a runtime factory")
        if self.kind not in OUTCOME_KINDS:
            raise ValueError("observed outcome kind is outside the closed inventory")
        _digest(self.result_sha256, "observed outcome result hash")
        if self.artifact_materialized:
            raise ValueError("fail-closed outcome materialized an artifact")
        exception_kind = self.kind in {
            "production_exception",
            "contract_rejection",
        }
        if exception_kind:
            if not self.exception_type or not self.exception_type.strip():
                raise ValueError("exception outcome lacks an exception type")
            if self.exception_message_sha256 is None:
                raise ValueError("exception outcome lacks a message hash")
            _digest(self.exception_message_sha256, "exception message hash")
            if self.http_statuses or self.request_variants:
                raise ValueError("exception outcome cannot carry HTTP proof")
            if self.kind == "contract_rejection" and not self.callable_identity:
                raise ValueError("contract rejection lacks callable identity")
            if self.kind == "production_exception" and self.callable_identity is not None:
                raise ValueError("production exception cannot claim call-contract proof")
        elif self.kind == "fixture_http_rejection":
            if self.http_statuses != (403, 403) or self.request_variants != (
                "host_wrong_port",
                "origin_wrong_port",
            ):
                raise ValueError("fixture HTTP rejection proof is incomplete")
            if any(
                value is not None
                for value in (
                    self.exception_type,
                    self.exception_message_sha256,
                    self.callable_identity,
                )
            ):
                raise ValueError("fixture HTTP outcome cannot claim exception proof")
        else:
            if self.http_statuses != (409, 409) or self.request_variants != (
                "duplicate_submit",
                "duplicate_review",
            ):
                raise ValueError("store-state invariance proof is incomplete")
            if any(
                value is not None
                for value in (
                    self.exception_type,
                    self.exception_message_sha256,
                    self.callable_identity,
                )
            ):
                raise ValueError("store-state outcome cannot claim exception proof")

    def document(self) -> dict[str, object]:
        result: dict[str, object] = {
            "kind": self.kind,
            "result_sha256": self.result_sha256,
            "artifact_materialized": False,
        }
        if self.exception_type is not None:
            result["exception"] = {
                "type": self.exception_type,
                "message_sha256": self.exception_message_sha256,
            }
        if self.http_statuses:
            result["http_statuses"] = self.http_statuses
            result["request_variants"] = self.request_variants
        if self.callable_identity is not None:
            result["callable_identity"] = self.callable_identity
        return result


@dataclass(frozen=True)
class RuntimeControlReceipt:
    """Canonical observation of one executed fail-closed control."""

    control_id: str
    executable_identity: str
    observed_outcome: ObservedOutcome
    before_state: Mapping[str, object]
    after_state: Mapping[str, object]
    source_git_revision: str
    source_tree: str
    source_content_revision: str
    schema_version: str = "jaa10.runtime-control-receipt.v2"
    _creation_token: InitVar[object] = None

    def __post_init__(self, _creation_token: object) -> None:
        if _creation_token is not _FACTORY_TOKEN:
            raise ValueError("runtime receipt must be derived by a runtime factory")
        if self.control_id not in RUNTIME_CONTROL_IDS:
            raise ValueError("runtime control is outside the closed inventory")
        if not self.executable_identity.strip():
            raise ValueError("runtime control requires executable identity")
        if not isinstance(self.observed_outcome, ObservedOutcome):
            raise TypeError("runtime control requires a typed observed outcome")
        if self.observed_outcome.kind != REQUIRED_OUTCOME_KIND[self.control_id]:
            raise ValueError("runtime control carries the wrong observed outcome kind")
        if not re.fullmatch(r"[0-9a-f]{40}", self.source_git_revision):
            raise ValueError("runtime source revision is invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", self.source_tree):
            raise ValueError("runtime source tree is invalid")
        if not re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.source_content_revision
        ):
            raise ValueError("runtime source-content revision is invalid")
        before = _state_document(self.before_state)
        after = _state_document(self.after_state)
        object.__setattr__(self, "before_state", MappingProxyType(before))
        object.__setattr__(self, "after_state", MappingProxyType(after))
        if after["receipt_count"] != before["receipt_count"]:
            raise ValueError("fail-closed runtime control created a receipt")
        if after["submit_click_count"] != before["submit_click_count"]:
            raise ValueError("fail-closed runtime control performed a submit click")
        if self.schema_version != "jaa10.runtime-control-receipt.v2":
            raise ValueError("runtime control receipt schema is unsupported")

    @property
    def fail_closed(self) -> bool:
        return True

    @property
    def receipt_created(self) -> bool:
        return False

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "control_id": self.control_id,
            "executable_identity": self.executable_identity,
            "observed_outcome": self.observed_outcome.document(),
            "before_state": dict(self.before_state),
            "after_state": dict(self.after_state),
            "source_identity": {
                "git_revision": self.source_git_revision,
                "tree": self.source_tree,
                "source_content_revision": self.source_content_revision,
            },
            "fail_closed": True,
            "receipt_created": False,
        }

    @property
    def receipt_sha256(self) -> str:
        return _content_hash(self.document())


_T = TypeVar("_T")


def observe_fail_closed_control(
    *,
    control_id: str,
    executable_identity: str,
    operation: Callable[[], _T],
    state_probe: Callable[[], Mapping[str, object]],
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
) -> RuntimeControlReceipt:
    """Execute one control and derive its verdict from observed runtime state.

    The operation must raise.  A normal return, a receipt-count increase, or a
    submit-click increase is rejected before a receipt can be constructed.
    """

    if control_id not in RUNTIME_CONTROL_IDS:
        raise ValueError("runtime control is outside the closed inventory")
    required_kind = REQUIRED_OUTCOME_KIND[control_id]
    if required_kind not in {"production_exception", "contract_rejection"}:
        raise ValueError("runtime control requires a non-exception observation factory")
    before = _state_document(state_probe())
    try:
        operation()
    except Exception as error:  # the exception identity is evidence
        exception_type = f"{type(error).__module__}.{type(error).__qualname__}"
        message_hash = hashlib.sha256(str(error).encode("utf-8")).hexdigest()
    else:
        raise ValueError("runtime control returned normally instead of failing closed")
    after = _state_document(state_probe())
    result_document = {
        "control_id": control_id,
        "executable_identity": executable_identity,
        "exception_type": exception_type,
        "exception_message_sha256": message_hash,
        "before_state": before,
        "after_state": after,
    }
    result_sha256 = _content_hash(result_document)
    outcome = ObservedOutcome(
        kind=required_kind,
        result_sha256=result_sha256,
        exception_type=exception_type,
        exception_message_sha256=message_hash,
        callable_identity=(
            executable_identity if required_kind == "contract_rejection" else None
        ),
        _creation_token=_FACTORY_TOKEN,
    )
    return RuntimeControlReceipt(
        control_id=control_id,
        executable_identity=executable_identity,
        observed_outcome=outcome,
        before_state=before,
        after_state=after,
        source_git_revision=source_git_revision,
        source_tree=source_tree,
        source_content_revision=source_content_revision,
        _creation_token=_FACTORY_TOKEN,
    )


def record_observed_exception(
    *,
    control_id: str,
    executable_identity: str,
    exception_type: str,
    exception_message_sha256: str,
    result_sha256: str,
    state: Mapping[str, object],
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
    callable_identity: str | None = None,
) -> RuntimeControlReceipt:
    """Bind an externally captured exception to the control's fixed kind."""

    if control_id not in RUNTIME_CONTROL_IDS:
        raise ValueError("runtime control is outside the closed inventory")
    kind = REQUIRED_OUTCOME_KIND[control_id]
    if kind not in {"production_exception", "contract_rejection"}:
        raise ValueError("runtime control requires HTTP or store-state observation")
    outcome = ObservedOutcome(
        kind=kind,
        result_sha256=result_sha256,
        exception_type=exception_type,
        exception_message_sha256=exception_message_sha256,
        callable_identity=(
            callable_identity or executable_identity
            if kind == "contract_rejection"
            else None
        ),
        _creation_token=_FACTORY_TOKEN,
    )
    frozen_state = _state_document(state)
    return RuntimeControlReceipt(
        control_id=control_id,
        executable_identity=executable_identity,
        observed_outcome=outcome,
        before_state=frozen_state,
        after_state=frozen_state,
        source_git_revision=source_git_revision,
        source_tree=source_tree,
        source_content_revision=source_content_revision,
        _creation_token=_FACTORY_TOKEN,
    )


def record_fixture_http_rejection(
    *,
    executable_identity: str,
    http_statuses: tuple[int, ...],
    request_variants: tuple[str, ...],
    result_sha256: str,
    before_state: Mapping[str, object],
    after_state: Mapping[str, object],
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
) -> RuntimeControlReceipt:
    """Record the exact two 403 loopback-origin rejections."""

    outcome = ObservedOutcome(
        kind="fixture_http_rejection",
        result_sha256=result_sha256,
        http_statuses=http_statuses,
        request_variants=request_variants,
        _creation_token=_FACTORY_TOKEN,
    )
    return RuntimeControlReceipt(
        control_id="local_origin_drift",
        executable_identity=executable_identity,
        observed_outcome=outcome,
        before_state=before_state,
        after_state=after_state,
        source_git_revision=source_git_revision,
        source_tree=source_tree,
        source_content_revision=source_content_revision,
        _creation_token=_FACTORY_TOKEN,
    )


def record_store_state_invariance(
    *,
    executable_identity: str,
    http_statuses: tuple[int, ...],
    request_variants: tuple[str, ...],
    result_sha256: str,
    before_state: Mapping[str, object],
    after_state: Mapping[str, object],
    source_git_revision: str,
    source_tree: str,
    source_content_revision: str,
) -> RuntimeControlReceipt:
    """Record duplicate submit/review 409s with one receipt unchanged."""

    outcome = ObservedOutcome(
        kind="store_state_invariance",
        result_sha256=result_sha256,
        http_statuses=http_statuses,
        request_variants=request_variants,
        _creation_token=_FACTORY_TOKEN,
    )
    return RuntimeControlReceipt(
        control_id="duplicate_submit",
        executable_identity=executable_identity,
        observed_outcome=outcome,
        before_state=before_state,
        after_state=after_state,
        source_git_revision=source_git_revision,
        source_tree=source_tree,
        source_content_revision=source_content_revision,
        _creation_token=_FACTORY_TOKEN,
    )


def mutation_observations_from_runtime(
    receipts: tuple[RuntimeControlReceipt, ...],
) -> tuple[MutationObservation, ...]:
    """Derive the legacy shadow inventory only from verified runtime receipts."""

    by_id: dict[str, RuntimeControlReceipt] = {}
    for receipt in receipts:
        if not isinstance(receipt, RuntimeControlReceipt):
            raise TypeError("mutation inventory requires typed runtime receipts")
        if receipt.control_id in REQUIRED_MUTATION_CONTROLS:
            if receipt.control_id in by_id:
                raise ValueError("runtime mutation receipt is duplicated")
            by_id[receipt.control_id] = receipt
    if tuple(by_id) != REQUIRED_MUTATION_CONTROLS:
        raise ValueError("runtime mutation receipt inventory is incomplete or unordered")
    return tuple(
        MutationObservation(
            control_id=control_id,
            test_node=MUTATION_TEST_NODES[control_id],
            blocked=by_id[control_id].fail_closed,
            receipt_created=by_id[control_id].receipt_created,
        )
        for control_id in REQUIRED_MUTATION_CONTROLS
    )


def read_immutable_runtime_receipt(path: Path) -> dict[str, object]:
    """Read a regular, immutable receipt without following symlinks."""

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("runtime receipt must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o222:
            raise ValueError("runtime receipt must be immutable")
        payload = os.read(descriptor, metadata.st_size + 1)
        if len(payload) != metadata.st_size:
            raise ValueError("runtime receipt changed while being read")
    finally:
        os.close(descriptor)
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise ValueError("runtime receipt document must be an object")
    return document
