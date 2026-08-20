"""Bind fixture-only canary answers to verified application release inputs.

This pure in-memory composition closes the identity seam between the bounded
operator-answer chain and the certified JAA-07/JAA-08 application objects. It
does not issue or consume a token, drive a browser, write a receipt, or grant
submission authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from career_automation.application_compiler import (
    ApplicationSource,
    verify_application_source,
)
from career_automation.live_canary_authority import _content_hash, _digest
from career_automation.live_canary_operator_answer_composition import (
    OperatorAnswerComposition,
)
from career_automation.release_gate import (
    ReleaseManifest,
    verify_release_manifest,
)
from career_automation.rendering import (
    ApplicationArtifacts,
    verify_application_artifacts,
)


APPLICATION_PACKAGE_SCHEMA = "jaa11.live-canary-application-package.v1"


def _validate_inputs(
    answer_composition: object,
    application_source: object,
    application_artifacts: object,
    release_manifest: object,
) -> tuple[
    OperatorAnswerComposition,
    ApplicationSource,
    ApplicationArtifacts,
    ReleaseManifest,
]:
    if type(answer_composition) is not OperatorAnswerComposition:
        raise ValueError("package requires the exact answer composition")
    if type(application_source) is not ApplicationSource:
        raise ValueError("package requires the exact application source")
    if type(application_artifacts) is not ApplicationArtifacts:
        raise ValueError("package requires the exact application artifacts")
    if type(release_manifest) is not ReleaseManifest:
        raise ValueError("package requires the exact release manifest")

    if answer_composition.answer_composition_sha256 != _content_hash(
        answer_composition.document(include_hash=False)
    ):
        raise ValueError("answer composition hash binding is invalid")
    verify_application_source(application_source)
    verify_application_artifacts(application_artifacts)
    verify_release_manifest(release_manifest)

    entry = answer_composition.intake.composition.dry_run.selected_entry
    binding = release_manifest.binding
    if entry.vacancy_identity != application_source.vacancy_source_identity:
        raise ValueError("selected vacancy identity differs from application source")
    if not (
        entry.vacancy_content_sha256
        == application_source.vacancy_sha256
        == binding.vacancy_sha256
    ):
        raise ValueError("selected vacancy content hash differs from release inputs")
    if application_source.job_key != binding.job_key:
        raise ValueError("application job key differs from release binding")
    if not (
        application_artifacts.source_id
        == application_source.source_id
        == binding.application_source_id
    ):
        raise ValueError("application source identity differs across package inputs")
    if binding.application_source_sha256 != application_source.content_sha256:
        raise ValueError("application source content hash differs from release binding")
    if binding.artifact_set_sha256 != application_artifacts.artifact_set_sha256:
        raise ValueError("artifact-set hash differs from release binding")
    if answer_composition.all_requests_permitted is not True:
        raise ValueError("every composed answer must be permitted before packaging")
    for item in answer_composition.items:
        if (
            item.request.topic == "work_authorisation"
            and item.request.jurisdiction != binding.work_right.jurisdiction
        ):
            raise ValueError(
                "work-authorisation jurisdiction differs from release binding"
            )
    return (
        answer_composition,
        application_source,
        application_artifacts,
        release_manifest,
    )


@dataclass(frozen=True)
class ApplicationPackageComposition:
    answer_composition: OperatorAnswerComposition
    application_source: ApplicationSource
    application_artifacts: ApplicationArtifacts
    release_manifest: ReleaseManifest
    intake_sha256: str
    answer_composition_sha256: str
    selected_entry_sha256: str
    vacancy_identity: str
    vacancy_content_sha256: str
    application_source_id: str
    application_source_content_sha256: str
    job_key: str
    artifact_set_sha256: str
    editable_answers_sha256: str
    cv_pdf_sha256: str
    cover_letter_pdf_sha256: str
    release_manifest_sha256: str
    release_input_sha256: str
    work_right_jurisdiction: str
    application_package_sha256: str
    positive_evidence_is_fixture_only: bool = True
    snapshot_source: str = "operator_supplied_document"
    acquired_by_system: bool = False
    snapshot_is_live: bool = False
    snapshot_is_current: bool = False
    selected_vacancy_status: str = (
        "operator_supplied_not_selected_for_external_use"
    )
    answers_used_for_external_submission: bool = False
    package_used_for_external_submission: bool = False
    release_token: str = "withheld"
    token_consumed: bool = False
    operational_release: str = "withheld"
    may_submit: bool = False
    external_action_capability: bool = False
    certifies_slice: bool = False
    receipt_written: bool = False
    real_applications: int = 0
    production_certification: str = "withheld"
    schema_version: str = APPLICATION_PACKAGE_SCHEMA

    def __post_init__(self) -> None:
        answer_composition, source, artifacts, manifest = _validate_inputs(
            self.answer_composition,
            self.application_source,
            self.application_artifacts,
            self.release_manifest,
        )
        for value, label in (
            (self.intake_sha256, "intake hash"),
            (self.answer_composition_sha256, "answer composition hash"),
            (self.selected_entry_sha256, "selected entry hash"),
            (self.vacancy_content_sha256, "vacancy content hash"),
            (self.application_source_id, "application source ID"),
            (
                self.application_source_content_sha256,
                "application source content hash",
            ),
            (self.artifact_set_sha256, "artifact-set hash"),
            (self.editable_answers_sha256, "editable answers hash"),
            (self.cv_pdf_sha256, "CV PDF hash"),
            (self.cover_letter_pdf_sha256, "cover-letter PDF hash"),
            (self.release_manifest_sha256, "release manifest hash"),
            (self.release_input_sha256, "release input hash"),
            (self.application_package_sha256, "application package hash"),
        ):
            _digest(value, label)

        entry = answer_composition.intake.composition.dry_run.selected_entry
        expected_echoes = (
            answer_composition.intake_sha256,
            answer_composition.answer_composition_sha256,
            answer_composition.selected_entry_sha256,
            entry.vacancy_identity,
            entry.vacancy_content_sha256,
            source.source_id,
            source.content_sha256,
            source.job_key,
            artifacts.artifact_set_sha256,
            artifacts.editable.answers_sha256,
            artifacts.cv_pdf.pdf_sha256,
            artifacts.cover_letter_pdf.pdf_sha256,
            manifest.release_manifest_sha256,
            manifest.input_sha256,
            manifest.binding.work_right.jurisdiction,
        )
        actual_echoes = (
            self.intake_sha256,
            self.answer_composition_sha256,
            self.selected_entry_sha256,
            self.vacancy_identity,
            self.vacancy_content_sha256,
            self.application_source_id,
            self.application_source_content_sha256,
            self.job_key,
            self.artifact_set_sha256,
            self.editable_answers_sha256,
            self.cv_pdf_sha256,
            self.cover_letter_pdf_sha256,
            self.release_manifest_sha256,
            self.release_input_sha256,
            self.work_right_jurisdiction,
        )
        if actual_echoes != expected_echoes:
            raise ValueError("application package hash echoes are inconsistent")

        expected_boundary = (
            True,
            "operator_supplied_document",
            False,
            False,
            False,
            "operator_supplied_not_selected_for_external_use",
            False,
            False,
            "withheld",
            False,
            "withheld",
            False,
            False,
            False,
            False,
            0,
            "withheld",
            APPLICATION_PACKAGE_SCHEMA,
        )
        actual_boundary = (
            self.positive_evidence_is_fixture_only,
            self.snapshot_source,
            self.acquired_by_system,
            self.snapshot_is_live,
            self.snapshot_is_current,
            self.selected_vacancy_status,
            self.answers_used_for_external_submission,
            self.package_used_for_external_submission,
            self.release_token,
            self.token_consumed,
            self.operational_release,
            self.may_submit,
            self.external_action_capability,
            self.certifies_slice,
            self.receipt_written,
            self.real_applications,
            self.production_certification,
            self.schema_version,
        )
        if actual_boundary != expected_boundary:
            raise ValueError("application package cannot open an external boundary")
        if self.application_package_sha256 != _content_hash(
            self.document(include_hash=False)
        ):
            raise ValueError("application package hash is invalid")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "answer_composition": self.answer_composition.document(),
            "intake_sha256": self.intake_sha256,
            "answer_composition_sha256": self.answer_composition_sha256,
            "selected_entry_sha256": self.selected_entry_sha256,
            "vacancy_identity": self.vacancy_identity,
            "vacancy_content_sha256": self.vacancy_content_sha256,
            "application_source_id": self.application_source_id,
            "application_source_content_sha256": (
                self.application_source_content_sha256
            ),
            "job_key": self.job_key,
            "artifact_set_sha256": self.artifact_set_sha256,
            "editable_answers_sha256": self.editable_answers_sha256,
            "cv_pdf_sha256": self.cv_pdf_sha256,
            "cover_letter_pdf_sha256": self.cover_letter_pdf_sha256,
            "release_manifest_sha256": self.release_manifest_sha256,
            "release_input_sha256": self.release_input_sha256,
            "work_right_jurisdiction": self.work_right_jurisdiction,
            "positive_evidence_is_fixture_only": (
                self.positive_evidence_is_fixture_only
            ),
            "snapshot_source": self.snapshot_source,
            "acquired_by_system": self.acquired_by_system,
            "snapshot_is_live": self.snapshot_is_live,
            "snapshot_is_current": self.snapshot_is_current,
            "selected_vacancy_status": self.selected_vacancy_status,
            "answers_used_for_external_submission": (
                self.answers_used_for_external_submission
            ),
            "package_used_for_external_submission": (
                self.package_used_for_external_submission
            ),
            "release_token": self.release_token,
            "token_consumed": self.token_consumed,
            "operational_release": self.operational_release,
            "may_submit": self.may_submit,
            "external_action_capability": self.external_action_capability,
            "certifies_slice": self.certifies_slice,
            "receipt_written": self.receipt_written,
            "real_applications": self.real_applications,
            "production_certification": self.production_certification,
        }
        if include_hash:
            result["application_package_sha256"] = (
                self.application_package_sha256
            )
        return result


def compose_application_package_dry_run(
    answer_composition: object,
    application_source: object,
    application_artifacts: object,
    release_manifest: object,
) -> ApplicationPackageComposition:
    """Compose one verified fixture-only package without issuing a token."""

    answer_composition, source, artifacts, manifest = _validate_inputs(
        answer_composition,
        application_source,
        application_artifacts,
        release_manifest,
    )
    entry = answer_composition.intake.composition.dry_run.selected_entry
    fields: dict[str, object] = {
        "answer_composition": answer_composition,
        "application_source": source,
        "application_artifacts": artifacts,
        "release_manifest": manifest,
        "intake_sha256": answer_composition.intake_sha256,
        "answer_composition_sha256": (
            answer_composition.answer_composition_sha256
        ),
        "selected_entry_sha256": answer_composition.selected_entry_sha256,
        "vacancy_identity": entry.vacancy_identity,
        "vacancy_content_sha256": entry.vacancy_content_sha256,
        "application_source_id": source.source_id,
        "application_source_content_sha256": source.content_sha256,
        "job_key": source.job_key,
        "artifact_set_sha256": artifacts.artifact_set_sha256,
        "editable_answers_sha256": artifacts.editable.answers_sha256,
        "cv_pdf_sha256": artifacts.cv_pdf.pdf_sha256,
        "cover_letter_pdf_sha256": artifacts.cover_letter_pdf.pdf_sha256,
        "release_manifest_sha256": manifest.release_manifest_sha256,
        "release_input_sha256": manifest.input_sha256,
        "work_right_jurisdiction": manifest.binding.work_right.jurisdiction,
        "positive_evidence_is_fixture_only": True,
        "snapshot_source": "operator_supplied_document",
        "acquired_by_system": False,
        "snapshot_is_live": False,
        "snapshot_is_current": False,
        "selected_vacancy_status": (
            "operator_supplied_not_selected_for_external_use"
        ),
        "answers_used_for_external_submission": False,
        "package_used_for_external_submission": False,
        "release_token": "withheld",
        "token_consumed": False,
        "operational_release": "withheld",
        "may_submit": False,
        "external_action_capability": False,
        "certifies_slice": False,
        "receipt_written": False,
        "real_applications": 0,
        "production_certification": "withheld",
        "schema_version": APPLICATION_PACKAGE_SCHEMA,
    }
    preimage = {
        key: value
        for key, value in fields.items()
        if key
        not in {
            "application_source",
            "application_artifacts",
            "release_manifest",
        }
    }
    preimage["answer_composition"] = answer_composition.document()
    fields["application_package_sha256"] = _content_hash(preimage)
    return ApplicationPackageComposition(**fields)  # type: ignore[arg-type]


__all__ = [
    "APPLICATION_PACKAGE_SCHEMA",
    "ApplicationPackageComposition",
    "compose_application_package_dry_run",
]
