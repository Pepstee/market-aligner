"""Parse operator-supplied snapshot bytes into the accepted fixture schema.

This pure in-memory boundary delegates all snapshot-content validation to the
accepted ``_compile_snapshot`` implementation. It performs no selection,
authority evaluation, I/O, acquisition, release, submission, or certification.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from career_automation.live_canary_authority import _content_hash, _digest
from career_automation.live_canary_fixture_dry_run import (
    SNAPSHOT_SCHEMA,
    RankedSnapshotFixture,
    _compile_snapshot,
)


MAX_DOCUMENT_BYTES = 1_048_576
DOCUMENT_SCHEMA = "jaa11.live-canary-operator-snapshot-document.v1"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("operator snapshot JSON contains duplicate keys")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"operator snapshot JSON constant is invalid: {value}")


def _document_fields(
    snapshot: RankedSnapshotFixture,
    operator_document_sha256: str,
    normalized_fixture_sha256: str,
    *,
    schema_version: str = DOCUMENT_SCHEMA,
    snapshot_source: str = "operator_supplied_document",
    acquired_by_system: bool = False,
    snapshot_is_live: bool = False,
    snapshot_is_current: bool = False,
    selected_vacancy_status: str = (
        "operator_supplied_not_selected_for_external_use"
    ),
    operational_release: str = "withheld",
    may_submit: bool = False,
    external_action_capability: bool = False,
    certifies_slice: bool = False,
    receipt_written: bool = False,
    real_applications: int = 0,
) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "snapshot": snapshot.document(),
        "operator_document_sha256": operator_document_sha256,
        "normalized_fixture_sha256": normalized_fixture_sha256,
        "snapshot_source": snapshot_source,
        "acquired_by_system": acquired_by_system,
        "snapshot_is_live": snapshot_is_live,
        "snapshot_is_current": snapshot_is_current,
        "selected_vacancy_status": selected_vacancy_status,
        "operational_release": operational_release,
        "may_submit": may_submit,
        "external_action_capability": external_action_capability,
        "certifies_slice": certifies_slice,
        "receipt_written": receipt_written,
        "real_applications": real_applications,
    }


@dataclass(frozen=True)
class OperatorSnapshotDocument:
    snapshot: RankedSnapshotFixture
    operator_document_sha256: str
    normalized_fixture_sha256: str
    bounded_document_sha256: str
    snapshot_source: str = "operator_supplied_document"
    acquired_by_system: bool = False
    snapshot_is_live: bool = False
    snapshot_is_current: bool = False
    selected_vacancy_status: str = (
        "operator_supplied_not_selected_for_external_use"
    )
    operational_release: str = "withheld"
    may_submit: bool = False
    external_action_capability: bool = False
    certifies_slice: bool = False
    receipt_written: bool = False
    real_applications: int = 0
    schema_version: str = DOCUMENT_SCHEMA

    def __post_init__(self) -> None:
        if type(self.snapshot) is not RankedSnapshotFixture:
            raise ValueError("operator snapshot must use the accepted fixture")
        _digest(self.operator_document_sha256, "operator document hash")
        _digest(self.normalized_fixture_sha256, "normalized fixture hash")
        _digest(self.bounded_document_sha256, "bounded document hash")
        expected_boundary = (
            "operator_supplied_document",
            False,
            False,
            False,
            "operator_supplied_not_selected_for_external_use",
            "withheld",
            False,
            False,
            False,
            False,
            0,
            DOCUMENT_SCHEMA,
        )
        actual_boundary = (
            self.snapshot_source,
            self.acquired_by_system,
            self.snapshot_is_live,
            self.snapshot_is_current,
            self.selected_vacancy_status,
            self.operational_release,
            self.may_submit,
            self.external_action_capability,
            self.certifies_slice,
            self.receipt_written,
            self.real_applications,
            self.schema_version,
        )
        if actual_boundary != expected_boundary:
            raise ValueError("operator snapshot cannot open an external boundary")
        if self.normalized_fixture_sha256 != self.snapshot.snapshot_sha256:
            raise ValueError("normalized fixture hash is invalid")
        if self.bounded_document_sha256 != _content_hash(
            self.document(include_hash=False)
        ):
            raise ValueError("bounded operator document hash is invalid")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        document = _document_fields(
            self.snapshot,
            self.operator_document_sha256,
            self.normalized_fixture_sha256,
            schema_version=self.schema_version,
            snapshot_source=self.snapshot_source,
            acquired_by_system=self.acquired_by_system,
            snapshot_is_live=self.snapshot_is_live,
            snapshot_is_current=self.snapshot_is_current,
            selected_vacancy_status=self.selected_vacancy_status,
            operational_release=self.operational_release,
            may_submit=self.may_submit,
            external_action_capability=self.external_action_capability,
            certifies_slice=self.certifies_slice,
            receipt_written=self.receipt_written,
            real_applications=self.real_applications,
        )
        if include_hash:
            document["bounded_document_sha256"] = self.bounded_document_sha256
        return document


def parse_operator_snapshot_document(
    document_bytes: object,
) -> OperatorSnapshotDocument:
    """Validate exact operator bytes and normalize them without selecting."""

    if type(document_bytes) is not bytes:
        raise ValueError("operator snapshot document must be exact bytes")
    if not document_bytes:
        raise ValueError("operator snapshot document cannot be empty")
    if len(document_bytes) > MAX_DOCUMENT_BYTES:
        raise ValueError("operator snapshot document exceeds the size limit")
    if document_bytes.startswith(b"\xef\xbb\xbf"):
        raise ValueError("operator snapshot document cannot contain a BOM")
    try:
        text = document_bytes.decode("utf-8")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError, json.JSONDecodeError) as exc:
        raise ValueError("operator snapshot document is invalid JSON") from exc
    snapshot = _compile_snapshot(parsed)
    operator_document_sha256 = hashlib.sha256(document_bytes).hexdigest()
    normalized_fixture_sha256 = snapshot.snapshot_sha256
    bounded_document_sha256 = _content_hash(
        _document_fields(
            snapshot,
            operator_document_sha256,
            normalized_fixture_sha256,
        )
    )
    return OperatorSnapshotDocument(
        snapshot=snapshot,
        operator_document_sha256=operator_document_sha256,
        normalized_fixture_sha256=normalized_fixture_sha256,
        bounded_document_sha256=bounded_document_sha256,
    )


__all__ = [
    "DOCUMENT_SCHEMA",
    "MAX_DOCUMENT_BYTES",
    "OperatorSnapshotDocument",
    "SNAPSHOT_SCHEMA",
    "parse_operator_snapshot_document",
]
