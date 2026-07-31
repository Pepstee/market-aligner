"""Witness exact operator bytes against the accepted fixture composition."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from career_automation.live_canary_authority import _content_hash, _digest
from career_automation.live_canary_operator_fixture_composition import (
    OperatorFixtureComposition,
    compose_operator_document_dry_run,
)
from career_automation.live_canary_snapshot_document import (
    MAX_DOCUMENT_BYTES,
    parse_operator_snapshot_document,
)


INTAKE_SCHEMA = "jaa11.live-canary-operator-document-intake.v1"


@dataclass(frozen=True)
class OperatorDocumentIntake:
    composition: OperatorFixtureComposition
    operator_document_sha256: str
    document_byte_length: int
    composition_sha256: str
    intake_sha256: str
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
    schema_version: str = INTAKE_SCHEMA

    def __post_init__(self) -> None:
        if type(self.composition) is not OperatorFixtureComposition:
            raise ValueError("intake requires the exact accepted composition")
        for value, label in (
            (self.operator_document_sha256, "operator document hash"),
            (self.composition_sha256, "composition hash"),
            (self.intake_sha256, "intake hash"),
        ):
            _digest(value, label)
        if (
            type(self.document_byte_length) is not int
            or self.document_byte_length < 1
            or self.document_byte_length > MAX_DOCUMENT_BYTES
        ):
            raise ValueError("operator document byte length is invalid")
        if not (
            self.operator_document_sha256
            == self.composition.operator_document_sha256
            == self.composition.operator_document.operator_document_sha256
        ):
            raise ValueError("operator document byte provenance is invalid")
        if not (
            self.composition_sha256
            == self.composition.composition_sha256
            == _content_hash(
                self.composition.document(include_hash=False)
            )
        ):
            raise ValueError("composition hash binding is invalid")
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
            INTAKE_SCHEMA,
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
            raise ValueError("operator intake cannot open an external boundary")
        if self.intake_sha256 != _content_hash(
            self.document(include_hash=False)
        ):
            raise ValueError("operator intake hash is invalid")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "composition": self.composition.document(),
            "operator_document_sha256": self.operator_document_sha256,
            "document_byte_length": self.document_byte_length,
            "composition_sha256": self.composition_sha256,
            "snapshot_source": self.snapshot_source,
            "acquired_by_system": self.acquired_by_system,
            "snapshot_is_live": self.snapshot_is_live,
            "snapshot_is_current": self.snapshot_is_current,
            "selected_vacancy_status": self.selected_vacancy_status,
            "operational_release": self.operational_release,
            "may_submit": self.may_submit,
            "external_action_capability": self.external_action_capability,
            "certifies_slice": self.certifies_slice,
            "receipt_written": self.receipt_written,
            "real_applications": self.real_applications,
        }
        if include_hash:
            result["intake_sha256"] = self.intake_sha256
        return result


def intake_operator_document_dry_run(
    document_bytes: object,
    selected_entry_evidence: object,
    *,
    submission_count: int | None,
    jaa11_certified: bool | None,
) -> OperatorDocumentIntake:
    """Validate exact bytes and bind them to a fixture-only composition."""

    document = parse_operator_snapshot_document(document_bytes)
    composition = compose_operator_document_dry_run(
        document,
        selected_entry_evidence,
        submission_count=submission_count,
        jaa11_certified=jaa11_certified,
    )
    operator_document_sha256 = hashlib.sha256(document_bytes).hexdigest()  # type: ignore[arg-type]
    if not (
        operator_document_sha256
        == composition.operator_document_sha256
        == composition.operator_document.operator_document_sha256
    ):
        raise ValueError("exact operator bytes do not match the composition")
    document_byte_length = len(document_bytes)  # type: ignore[arg-type]
    fields: dict[str, object] = {
        "composition": composition,
        "operator_document_sha256": operator_document_sha256,
        "document_byte_length": document_byte_length,
        "composition_sha256": composition.composition_sha256,
        "snapshot_source": "operator_supplied_document",
        "acquired_by_system": False,
        "snapshot_is_live": False,
        "snapshot_is_current": False,
        "selected_vacancy_status": (
            "operator_supplied_not_selected_for_external_use"
        ),
        "operational_release": "withheld",
        "may_submit": False,
        "external_action_capability": False,
        "certifies_slice": False,
        "receipt_written": False,
        "real_applications": 0,
        "schema_version": INTAKE_SCHEMA,
    }
    preimage = {
        "schema_version": INTAKE_SCHEMA,
        "composition": composition.document(),
        "operator_document_sha256": operator_document_sha256,
        "document_byte_length": document_byte_length,
        "composition_sha256": composition.composition_sha256,
        "snapshot_source": "operator_supplied_document",
        "acquired_by_system": False,
        "snapshot_is_live": False,
        "snapshot_is_current": False,
        "selected_vacancy_status": (
            "operator_supplied_not_selected_for_external_use"
        ),
        "operational_release": "withheld",
        "may_submit": False,
        "external_action_capability": False,
        "certifies_slice": False,
        "receipt_written": False,
        "real_applications": 0,
    }
    fields["intake_sha256"] = _content_hash(preimage)
    return OperatorDocumentIntake(**fields)  # type: ignore[arg-type]


__all__ = [
    "INTAKE_SCHEMA",
    "OperatorDocumentIntake",
    "intake_operator_document_dry_run",
]
