from __future__ import annotations

from dataclasses import replace

import pytest

from career_automation.ats_application_authority import (
    ATS_AUTHORITY_POLICY_SHA256,
    AtsFieldOption,
    AtsFieldPlan,
    AtsFormInventory,
    AtsObservedField,
    build_ats_application_authority,
    verify_ats_application_authority,
)
from test_application_quality import _quality_input, _quality_source


def _inventory(*, with_options: bool = False) -> AtsFormInventory:
    return AtsFormInventory(
        provider="fixture",
        application_url="https://jobs.example.test/application/one",
        captured_at="2026-08-26T12:00:00Z",
        page_snapshot_sha256="1" * 64,
        screenshot_sha256s=("2" * 64,),
        fields=(
            AtsObservedField("full_name", "text", "Full name", True, True),
            AtsObservedField("email", "email", "Email", True, True),
            AtsObservedField(
                "delivery",
                "select" if with_options else "textarea",
                "Describe a relevant delivery example",
                True,
                True,
                options=(AtsFieldOption("No", "No"),) if with_options else (),
            ),
            AtsObservedField("cv", "file", "CV", True, True),
            AtsObservedField(
                "cover_letter",
                "file",
                "Cover letter",
                False,
                True,
            ),
            AtsObservedField(
                "provider_state",
                "hidden",
                "",
                False,
                False,
                automation_role="provider_managed",
                current_value="csrf-state",
            ),
            AtsObservedField(
                "robot_check",
                "hidden",
                "",
                False,
                False,
                automation_role="honeypot",
            ),
        ),
    )


def _plans(*, observed_name=None, correction_reason=None):
    return (
        AtsFieldPlan(
            "full_name",
            "fill",
            "contact.full_name",
            observed_name,
            correction_reason,
        ),
        AtsFieldPlan("email", "fill", "contact.email"),
        AtsFieldPlan("delivery", "fill", "answer.delivery-example"),
        AtsFieldPlan("cv", "upload", "artifact.cv"),
        AtsFieldPlan("cover_letter", "upload", "artifact.cover_letter"),
        AtsFieldPlan("provider_state", "omit", "none", "csrf-state"),
        AtsFieldPlan("robot_check", "omit", "none"),
    )


def _build(tmp_path, *, inventory=None, plans=None):
    quality_input = _quality_input(tmp_path, _quality_source())
    plan_rows = tuple(plans or _plans())
    base_inventory = inventory or _inventory()
    observed_by_id = {row.field_id: row.observed_value for row in plan_rows}
    observed_inventory = replace(
        base_inventory,
        fields=tuple(
            replace(row, current_value=observed_by_id.get(row.field_id))
            for row in base_inventory.fields
        ),
    )
    final_values = {
        "full_name": quality_input.source.contact.full_name,
        "email": quality_input.source.contact.email,
        "delivery": (
            "A concise example follows.\n"
            "Delivered reliable services with tested evidence."
        ),
        "cv": quality_input.artifacts.cv_pdf.pdf_sha256,
        "cover_letter": quality_input.artifacts.cover_letter_pdf.pdf_sha256,
        "provider_state": "csrf-state",
        "robot_check": None,
    }
    authority = build_ats_application_authority(
        reviewed_at=quality_input.reviewed_at,
        candidate_authority_sha256=quality_input.candidate_authority_sha256,
        source=quality_input.source,
        artifacts=quality_input.artifacts,
        publication_receipt=quality_input.publication_receipt,
        inventory=observed_inventory,
        reviewed_inventory=replace(
            observed_inventory,
            captured_at="2026-08-26T12:00:00Z",
            page_snapshot_sha256="3" * 64,
            screenshot_sha256s=("4" * 64,),
            fields=tuple(
                replace(row, current_value=final_values[row.field_id])
                for row in observed_inventory.fields
            ),
        ),
        plans=plan_rows,
    )
    return quality_input, authority


def test_closed_inventory_and_answers_rebuild_from_exact_application(tmp_path) -> None:
    quality_input, authority = _build(tmp_path)
    assert authority.policy_sha256 == ATS_AUTHORITY_POLICY_SHA256
    assert authority.external_action_capability is False
    assert authority.answers[-1].field_id == "robot_check"
    assert authority.answers[-1].action == "omit"
    assert authority.answers[-1].final_value is None
    assert authority.answers[-2].observed_value == "csrf-state"
    assert authority.answers[-2].correction_reason is None
    assert authority.answers[2].final_value == (
        "A concise example follows.\n"
        "Delivered reliable services with tested evidence."
    )
    assert authority.inventory_bytes.endswith(b"\n")
    assert authority.inventory.content_sha256 != authority.reviewed_inventory.content_sha256
    assert authority.inventory_sha256 == authority.document()["inventory_pair_sha256"]
    assert authority.answer_bytes.endswith(b"\n")
    assert verify_ats_application_authority(
        authority,
        candidate_authority_sha256=quality_input.candidate_authority_sha256,
        source=quality_input.source,
        artifacts=quality_input.artifacts,
        publication_receipt=quality_input.publication_receipt,
    ) is authority


def test_provider_parser_correction_is_exact_and_reason_bound(tmp_path) -> None:
    quality_input, authority = _build(
        tmp_path,
        plans=_plans(
            observed_name="Wrong Candidate",
            correction_reason="resume_parser_drift",
        ),
    )
    entry = authority.answers[0]
    assert entry.observed_value == "Wrong Candidate"
    assert entry.final_value == quality_input.source.contact.full_name
    assert entry.correction_reason == "resume_parser_drift"


@pytest.mark.parametrize(
    "plans,match",
    (
        (
            lambda: (
                AtsFieldPlan("full_name", "omit", "none"),
                *_plans()[1:],
            ),
            "required ATS field",
        ),
        (
            lambda: (
                *_plans()[:-1],
                AtsFieldPlan("robot_check", "fill", "contact.full_name"),
            ),
            "hidden or non-actionable",
        ),
        (
            lambda: (
                *_plans()[:-1],
                AtsFieldPlan("robot_check", "omit", "none", "bot-value"),
            ),
            "honeypot",
        ),
        (
            lambda: _plans(observed_name="Wrong Candidate"),
            "correction reason",
        ),
    ),
)
def test_required_hidden_honeypot_and_correction_fail_closed(
    tmp_path,
    plans,
    match,
) -> None:
    with pytest.raises(ValueError, match=match):
        _build(tmp_path, plans=plans())


def test_answer_must_equal_an_exact_observed_option(tmp_path) -> None:
    with pytest.raises(ValueError, match="exact observed option"):
        _build(tmp_path, inventory=_inventory(with_options=True))


def test_missing_extra_and_unsupported_field_plans_refuse(tmp_path) -> None:
    with pytest.raises(ValueError, match="cover every observed field"):
        _build(tmp_path, plans=_plans()[:-1])
    with pytest.raises(ValueError, match="unsupported application authority"):
        _build(
            tmp_path,
            plans=(
                AtsFieldPlan("full_name", "fill", "external.claim"),
                *_plans()[1:],
            ),
        )


def test_authority_substitution_cannot_verify(tmp_path) -> None:
    quality_input, authority = _build(tmp_path)
    with pytest.raises(ValueError, match="identity is invalid"):
        replace(authority, vacancy_sha256="f" * 64)
    other_input = _quality_input(
        tmp_path / "other",
        _quality_source(
            job_key="example:other-job",
            vacancy_sha256="e" * 64,
        ),
    )
    with pytest.raises(ValueError):
        verify_ats_application_authority(
            authority,
            candidate_authority_sha256=other_input.candidate_authority_sha256,
            source=other_input.source,
            artifacts=other_input.artifacts,
            publication_receipt=other_input.publication_receipt,
        )


@pytest.mark.parametrize(
    "reviewed_inventory",
    (
        replace(_inventory(), provider="ashby"),
        replace(_inventory(), application_url="https://jobs.example.test/application/two"),
        replace(_inventory(), fields=tuple(reversed(_inventory().fields))),
        replace(_inventory(), captured_at="2026-08-26T11:59:59Z"),
    ),
)
def test_reviewed_inventory_must_preserve_exact_observed_form_shape(
    tmp_path,
    reviewed_inventory,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    with pytest.raises(ValueError, match="reviewed ATS inventory differs"):
        build_ats_application_authority(
            reviewed_at=quality_input.reviewed_at,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=quality_input.source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
            inventory=_inventory(),
            reviewed_inventory=reviewed_inventory,
            plans=_plans(),
        )


def test_reviewed_values_must_equal_exact_answers_and_preserve_provider_state(
    tmp_path,
) -> None:
    quality_input, authority = _build(tmp_path)
    for field_id, value in (
        ("full_name", "Another Candidate"),
        ("provider_state", "changed-state"),
        ("robot_check", "bot-value"),
    ):
        fields = tuple(
            replace(row, current_value=value) if row.field_id == field_id else row
            for row in authority.reviewed_inventory.fields
        )
        with pytest.raises(ValueError):
            build_ats_application_authority(
                reviewed_at=quality_input.reviewed_at,
                candidate_authority_sha256=quality_input.candidate_authority_sha256,
                source=quality_input.source,
                artifacts=quality_input.artifacts,
                publication_receipt=quality_input.publication_receipt,
                inventory=authority.inventory,
                reviewed_inventory=replace(authority.reviewed_inventory, fields=fields),
                plans=_plans(),
            )
