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
from dataclasses import dataclass
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
class RuntimeControlReceipt:
    """Canonical observation of one executed fail-closed control."""

    control_id: str
    executable_identity: str
    exception_type: str
    exception_message_sha256: str
    before_state: Mapping[str, object]
    after_state: Mapping[str, object]
    result_sha256: str
    source_git_revision: str
    source_tree: str
    source_content_revision: str
    schema_version: str = "jaa10.runtime-control-receipt.v1"

    def __post_init__(self) -> None:
        if self.control_id not in RUNTIME_CONTROL_IDS:
            raise ValueError("runtime control is outside the closed inventory")
        if not self.executable_identity.strip():
            raise ValueError("runtime control requires executable identity")
        if not self.exception_type.strip():
            raise ValueError("runtime control did not observe an exception")
        _digest(self.exception_message_sha256, "exception message hash")
        _digest(self.result_sha256, "runtime result hash")
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
        if after["receipt_count"] > before["receipt_count"]:
            raise ValueError("fail-closed runtime control created a receipt")
        if after["submit_click_count"] > before["submit_click_count"]:
            raise ValueError("fail-closed runtime control performed a submit click")
        if self.schema_version != "jaa10.runtime-control-receipt.v1":
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
            "observed_exception": {
                "type": self.exception_type,
                "message_sha256": self.exception_message_sha256,
            },
            "before_state": dict(self.before_state),
            "after_state": dict(self.after_state),
            "result_sha256": self.result_sha256,
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
    return RuntimeControlReceipt(
        control_id=control_id,
        executable_identity=executable_identity,
        exception_type=exception_type,
        exception_message_sha256=message_hash,
        before_state=before,
        after_state=after,
        result_sha256=_content_hash(result_document),
        source_git_revision=source_git_revision,
        source_tree=source_tree,
        source_content_revision=source_content_revision,
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
