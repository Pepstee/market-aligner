"""Bind an operator snapshot document to the accepted fixture dry run.

This pure in-memory composition performs no parsing, acquisition, I/O,
release, submission, receipt creation, or certification.
"""

from __future__ import annotations

from dataclasses import dataclass

from career_automation.live_canary_authority import _content_hash, _digest
from career_automation.live_canary_fixture_dry_run import (
    LiveCanaryFixtureDryRun,
    compile_live_canary_fixture_dry_run,
)
from career_automation.live_canary_snapshot_document import (
    OperatorSnapshotDocument,
)


COMPOSITION_SCHEMA = "jaa11.live-canary-operator-fixture-composition.v1"


@dataclass(frozen=True)
class OperatorFixtureComposition:
    operator_document: OperatorSnapshotDocument
    dry_run: LiveCanaryFixtureDryRun
    operator_document_sha256: str
    normalized_fixture_sha256: str
    bounded_document_sha256: str
    ranked_snapshot_sha256: str
    selected_entry_sha256: str
    dry_run_sha256: str
    composition_sha256: str
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
    schema_version: str = COMPOSITION_SCHEMA

    def __post_init__(self) -> None:
        if type(self.operator_document) is not OperatorSnapshotDocument:
            raise ValueError(
                "composition requires the exact operator snapshot document"
            )
        if type(self.dry_run) is not LiveCanaryFixtureDryRun:
            raise ValueError("composition requires the exact fixture dry run")
        for value, label in (
            (self.operator_document_sha256, "operator document hash"),
            (self.normalized_fixture_sha256, "normalized fixture hash"),
            (self.bounded_document_sha256, "bounded document hash"),
            (self.ranked_snapshot_sha256, "ranked snapshot hash"),
            (self.selected_entry_sha256, "selected entry hash"),
            (self.dry_run_sha256, "dry-run hash"),
            (self.composition_sha256, "composition hash"),
        ):
            _digest(value, label)

        operator_document = self.operator_document
        dry_run = self.dry_run
        if (
            self.operator_document_sha256
            != operator_document.operator_document_sha256
        ):
            raise ValueError("operator document hash binding is invalid")
        recomputed_fixture_sha256 = _content_hash(
            operator_document.snapshot.document()
        )
        if not (
            self.normalized_fixture_sha256
            == operator_document.normalized_fixture_sha256
            == recomputed_fixture_sha256
        ):
            raise ValueError("normalized fixture hash binding is invalid")
        recomputed_document_sha256 = _content_hash(
            operator_document.document(include_hash=False)
        )
        if not (
            self.bounded_document_sha256
            == operator_document.bounded_document_sha256
            == recomputed_document_sha256
        ):
            raise ValueError("bounded document hash binding is invalid")
        if not (
            self.ranked_snapshot_sha256
            == dry_run.ranked_snapshot_sha256
            == self.normalized_fixture_sha256
        ):
            raise ValueError("ranked snapshot bridge binding is invalid")
        if dry_run.snapshot != operator_document.snapshot:
            raise ValueError("dry run does not use the operator snapshot")
        if not (
            self.selected_entry_sha256
            == dry_run.selected_entry_sha256
            == _content_hash(dry_run.selected_entry.document())
        ):
            raise ValueError("selected entry hash binding is invalid")
        if not (
            self.dry_run_sha256
            == dry_run.dry_run_sha256
            == _content_hash(dry_run.document(include_hash=False))
        ):
            raise ValueError("dry-run hash binding is invalid")

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
            COMPOSITION_SCHEMA,
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
            raise ValueError("composition cannot open an external boundary")
        if self.composition_sha256 != _content_hash(
            self.document(include_hash=False)
        ):
            raise ValueError("composition hash is invalid")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "operator_document": self.operator_document.document(),
            "operator_document_sha256": self.operator_document_sha256,
            "normalized_fixture_sha256": self.normalized_fixture_sha256,
            "bounded_document_sha256": self.bounded_document_sha256,
            "dry_run": self.dry_run.document(),
            "ranked_snapshot_sha256": self.ranked_snapshot_sha256,
            "selected_entry_sha256": self.selected_entry_sha256,
            "dry_run_sha256": self.dry_run_sha256,
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
            result["composition_sha256"] = self.composition_sha256
        return result


def compose_operator_document_dry_run(
    document: object,
    selected_entry_evidence: object,
    *,
    submission_count: int | None,
    jaa11_certified: bool | None,
) -> OperatorFixtureComposition:
    """Compose one validated operator document with a fixture-only dry run."""

    if type(document) is not OperatorSnapshotDocument:
        raise ValueError("composition requires an exact operator document")
    dry_run = compile_live_canary_fixture_dry_run(
        document.snapshot.document(),
        selected_entry_evidence,
        submission_count=submission_count,
        jaa11_certified=jaa11_certified,
    )
    fields: dict[str, object] = {
        "operator_document": document,
        "dry_run": dry_run,
        "operator_document_sha256": document.operator_document_sha256,
        "normalized_fixture_sha256": document.normalized_fixture_sha256,
        "bounded_document_sha256": document.bounded_document_sha256,
        "ranked_snapshot_sha256": dry_run.ranked_snapshot_sha256,
        "selected_entry_sha256": dry_run.selected_entry_sha256,
        "dry_run_sha256": dry_run.dry_run_sha256,
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
        "schema_version": COMPOSITION_SCHEMA,
    }
    preimage = {
        "schema_version": COMPOSITION_SCHEMA,
        "operator_document": document.document(),
        "operator_document_sha256": document.operator_document_sha256,
        "normalized_fixture_sha256": document.normalized_fixture_sha256,
        "bounded_document_sha256": document.bounded_document_sha256,
        "dry_run": dry_run.document(),
        "ranked_snapshot_sha256": dry_run.ranked_snapshot_sha256,
        "selected_entry_sha256": dry_run.selected_entry_sha256,
        "dry_run_sha256": dry_run.dry_run_sha256,
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
    fields["composition_sha256"] = _content_hash(preimage)
    return OperatorFixtureComposition(**fields)  # type: ignore[arg-type]


__all__ = [
    "COMPOSITION_SCHEMA",
    "OperatorFixtureComposition",
    "compose_operator_document_dry_run",
]
