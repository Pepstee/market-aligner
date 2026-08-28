"""Closed ATS inventory, answer, omission and correction authority.

Provider adapters own DOM observation and execution.  This module owns the
provider-neutral, exact authority between those stages.  It is deliberately
pure: it has no browser, network, filesystem, release or submission ability.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable
from urllib.parse import urlsplit

from .application_artifacts import (
    PublishedArtifactReceipt,
    verify_application_artifact_receipt,
)
from .application_compiler import ApplicationSource, verify_application_source
from .evidence_matching import canonical_json, content_hash
from .rendering import ApplicationArtifacts, verify_application_artifacts


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(
    r"^(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$"
)
_PROVIDER = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_CONTROL_KINDS = frozenset(
    {
        "text",
        "email",
        "tel",
        "url",
        "textarea",
        "number",
        "select",
        "radio",
        "checkbox",
        "file",
        "hidden",
    }
)
_AUTOMATION_ROLES = frozenset({"applicant", "honeypot", "provider_managed"})
_PROVIDERS = frozenset(
    {"ashby", "fixture", "greenhouse", "personio", "recruitee", "workable"}
)
_ACTIONS = frozenset({"fill", "upload", "omit"})
_CORRECTION_REASONS = frozenset(
    {
        "provider_autofill_drift",
        "resume_parser_drift",
        "taxonomy_normalization",
        "provider_default_drift",
    }
)
_CONTACT_REFERENCES = {
    "contact.full_name": "full_name",
    "contact.email": "email",
    "contact.phone": "phone",
    "contact.city": "city",
}
_MAX_FIELDS = 512
_MAX_CAPTURE_BYTES = 4_194_304

ATS_AUTHORITY_POLICY = {
    "schema_version": "jaa.ats-application-authority-policy.v1",
    "inventory": {
        "maximum_fields": _MAX_FIELDS,
        "all_observed_fields_required": True,
        "unique_stable_field_ids": True,
        "required_visible_fields_must_be_bound": True,
        "reviewed_values_must_equal_approved_answers": True,
    },
    "providers": sorted(_PROVIDERS),
    "sources": [
        "contact.full_name",
        "contact.email",
        "contact.phone",
        "contact.city",
        "answer.<question_id>",
        "artifact.cv",
        "artifact.cover_letter",
    ],
    "hidden_controls": {
        "honeypot": "observe, require empty, omit",
        "provider_managed": "observe and omit without altering provider state",
    },
    "disabled_or_read_only_controls": "observe and omit",
    "corrections": sorted(_CORRECTION_REASONS),
    "unsupported_required_fields": "refuse authority",
    "external_action_capability": False,
}
ATS_AUTHORITY_POLICY_SHA256 = content_hash(ATS_AUTHORITY_POLICY)


def _require_text(value: object, label: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
        or "\r" in value
    ):
        raise ValueError(f"{label} must be bounded normalized text")
    return value


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _require_time(value: object, label: str) -> str:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        raise ValueError(f"{label} must be second-precision RFC3339 UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid RFC3339 UTC instant") from exc
    return value


def _exact_url(value: object) -> str:
    text = _require_text(value, "application URL", maximum=4096)
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("application URL must be an exact public HTTPS route")
    return text


def _captured_bytes(value: bytes, label: str) -> bytes:
    if not isinstance(value, bytes) or not value or len(value) > _MAX_CAPTURE_BYTES:
        raise ValueError(f"{label} must be bounded non-empty exact bytes")
    try:
        value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be UTF-8") from exc
    return value


def _canonical_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _value_kind(value: str | bool | int | None) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "text"
    raise TypeError("ATS values must be text, boolean, integer or null")


def _validate_value(
    value: str | bool | int | None,
    label: str,
    *,
    allow_empty: bool = False,
) -> None:
    if isinstance(value, str):
        if allow_empty and value == "":
            return
        _require_text(value, label, maximum=16384)
    elif value is not None and not isinstance(value, (bool, int)):
        raise TypeError(f"{label} has an unsupported type")


@dataclass(frozen=True)
class AtsFieldOption:
    value: str
    label: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.value, str)
            or len(self.value.encode("utf-8")) > 2048
            or "\x00" in self.value
            or "\r" in self.value
        ):
            raise ValueError("option value must be bounded normalized text")
        _require_text(self.label, "option label", maximum=2048)

    def document(self) -> dict[str, str]:
        return {"value": self.value, "label": self.label}


@dataclass(frozen=True)
class AtsObservedField:
    field_id: str
    control_kind: str
    label: str
    required: bool
    visible: bool
    automation_role: str = "applicant"
    disabled: bool = False
    read_only: bool = False
    multiple: bool = False
    options: tuple[AtsFieldOption, ...] = ()
    current_value: str | bool | int | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", tuple(self.options))
        _require_text(self.field_id, "ATS field ID", maximum=512)
        if self.control_kind not in _CONTROL_KINDS:
            raise ValueError("ATS control kind is unsupported")
        if self.automation_role not in _AUTOMATION_ROLES:
            raise ValueError("ATS automation role is unsupported")
        if not isinstance(self.label, str) or len(self.label.encode("utf-8")) > 4096:
            raise ValueError("ATS label must be bounded text")
        if "\x00" in self.label or "\r" in self.label:
            raise ValueError("ATS label contains unsafe controls")
        for name in ("required", "visible", "disabled", "read_only", "multiple"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"ATS field {name} must be bool")
        if not all(type(row) is AtsFieldOption for row in self.options):
            raise TypeError("ATS options must be exact typed options")
        _validate_value(self.current_value, "ATS field current value", allow_empty=True)
        option_values = [row.value for row in self.options]
        if len(option_values) != len(set(option_values)):
            raise ValueError("ATS option values must be unique")
        if self.options and self.control_kind not in {"select", "radio", "checkbox"}:
            raise ValueError("only choice controls may carry options")
        if self.multiple and self.control_kind not in {"file", "select", "checkbox"}:
            raise ValueError("ATS control cannot accept multiple values")
        if self.control_kind == "hidden":
            if self.visible or self.automation_role == "applicant":
                raise ValueError("hidden ATS controls require a non-applicant role")
        elif self.automation_role != "applicant" and self.visible:
            raise ValueError("non-applicant ATS controls cannot be visible")
        elif self.automation_role == "applicant" and (
            not self.visible or self.disabled or self.read_only
        ):
            raise ValueError("non-actionable ATS controls require a non-applicant role")

    def document(self) -> dict[str, object]:
        return {
            "field_id": self.field_id,
            "control_kind": self.control_kind,
            "label": self.label,
            "required": self.required,
            "visible": self.visible,
            "automation_role": self.automation_role,
            "disabled": self.disabled,
            "read_only": self.read_only,
            "multiple": self.multiple,
            "options": [row.document() for row in self.options],
            "current_value_kind": _value_kind(self.current_value),
            "current_value": self.current_value,
        }

    def shape_document(self) -> dict[str, object]:
        result = self.document()
        del result["current_value_kind"]
        del result["current_value"]
        return result


@dataclass(frozen=True)
class AtsFormInventory:
    provider: str
    application_url: str
    captured_at: str
    page_snapshot_sha256: str
    screenshot_sha256s: tuple[str, ...]
    fields: tuple[AtsObservedField, ...]
    schema_version: str = "jaa.ats-form-inventory.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "screenshot_sha256s", tuple(self.screenshot_sha256s))
        object.__setattr__(self, "fields", tuple(self.fields))
        if self.schema_version != "jaa.ats-form-inventory.v1":
            raise ValueError("unsupported ATS inventory schema")
        if (
            not isinstance(self.provider, str)
            or _PROVIDER.fullmatch(self.provider) is None
            or self.provider not in _PROVIDERS
        ):
            raise ValueError("ATS provider must be a stable lowercase identifier")
        _exact_url(self.application_url)
        _require_time(self.captured_at, "inventory capture time")
        _require_sha256(self.page_snapshot_sha256, "page snapshot hash")
        if (
            not self.screenshot_sha256s
            or len(set(self.screenshot_sha256s)) != len(self.screenshot_sha256s)
        ):
            raise ValueError("screenshot hashes must be non-empty, unique and ordered")
        for value in self.screenshot_sha256s:
            _require_sha256(value, "screenshot hash")
        if not self.fields or len(self.fields) > _MAX_FIELDS:
            raise ValueError("ATS inventory field count is outside policy")
        if not all(type(row) is AtsObservedField for row in self.fields):
            raise TypeError("ATS inventory requires exact typed fields")
        field_ids = [row.field_id for row in self.fields]
        if len(field_ids) != len(set(field_ids)):
            raise ValueError("ATS inventory field IDs must be unique")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "application_url": self.application_url,
            "captured_at": self.captured_at,
            "page_snapshot_sha256": self.page_snapshot_sha256,
            "screenshot_sha256s": list(self.screenshot_sha256s),
            "fields": [row.document() for row in self.fields],
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self.document())

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def shape_sha256(self) -> str:
        return content_hash(
            {
                "provider": self.provider,
                "application_url": self.application_url,
                "fields": [row.shape_document() for row in self.fields],
            }
        )


@dataclass(frozen=True)
class AtsFieldPlan:
    field_id: str
    action: str
    source_reference: str
    observed_value: str | bool | int | None = field(default=None, repr=False)
    correction_reason: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.field_id, "ATS plan field ID", maximum=512)
        if self.action not in _ACTIONS:
            raise ValueError("ATS field action is unsupported")
        _require_text(self.source_reference, "ATS source reference", maximum=512)
        _validate_value(self.observed_value, "observed ATS value", allow_empty=True)
        if self.correction_reason is not None and self.correction_reason not in _CORRECTION_REASONS:
            raise ValueError("ATS correction reason is unsupported")


@dataclass(frozen=True)
class AtsAnswerEntry:
    field_id: str
    action: str
    value_kind: str
    final_value: str | bool | int | None = field(repr=False)
    observed_value: str | bool | int | None = field(repr=False)
    source_reference: str
    source_sha256: str
    correction_reason: str | None

    def __post_init__(self) -> None:
        _require_text(self.field_id, "ATS answer field ID", maximum=512)
        if self.action not in _ACTIONS:
            raise ValueError("ATS answer action is unsupported")
        if self.value_kind != _value_kind(self.final_value):
            raise ValueError("ATS answer value kind is inconsistent")
        _validate_value(self.final_value, "final ATS value")
        _validate_value(self.observed_value, "observed ATS value", allow_empty=True)
        _require_text(self.source_reference, "ATS answer source reference", maximum=512)
        _require_sha256(self.source_sha256, "ATS answer source hash")
        if self.correction_reason is not None and self.correction_reason not in _CORRECTION_REASONS:
            raise ValueError("ATS answer correction reason is unsupported")
        changed = (
            self.action != "omit"
            and self.observed_value not in (None, "")
            and self.observed_value != self.final_value
        )
        if changed != (self.correction_reason is not None):
            raise ValueError("ATS correction reason must exactly describe changed observed data")

    def document(self) -> dict[str, object]:
        return {
            "field_id": self.field_id,
            "action": self.action,
            "value_kind": self.value_kind,
            "final_value": self.final_value,
            "observed_value": self.observed_value,
            "source_reference": self.source_reference,
            "source_sha256": self.source_sha256,
            "correction_reason": self.correction_reason,
        }


@dataclass(frozen=True)
class AtsApplicationAuthority:
    reviewed_at: str
    candidate_authority_sha256: str
    application_source_sha256: str
    artifact_receipt_sha256: str
    vacancy_sha256: str
    job_key: str
    inventory: AtsFormInventory
    reviewed_inventory: AtsFormInventory
    answers: tuple[AtsAnswerEntry, ...]
    cv_pdf_sha256: str
    cover_letter_pdf_sha256: str
    policy_sha256: str
    authority_sha256: str
    schema_version: str = "jaa.ats-application-authority.v1"
    external_action_capability: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "answers", tuple(self.answers))
        if self.schema_version != "jaa.ats-application-authority.v1":
            raise ValueError("unsupported ATS application authority schema")
        _require_time(self.reviewed_at, "ATS authority review time")
        for value, label in (
            (self.candidate_authority_sha256, "candidate authority hash"),
            (self.application_source_sha256, "application source hash"),
            (self.artifact_receipt_sha256, "artifact receipt hash"),
            (self.vacancy_sha256, "vacancy hash"),
            (self.cv_pdf_sha256, "CV PDF hash"),
            (self.cover_letter_pdf_sha256, "cover-letter PDF hash"),
            (self.policy_sha256, "ATS policy hash"),
            (self.authority_sha256, "ATS authority hash"),
        ):
            _require_sha256(value, label)
        _require_text(self.job_key, "ATS authority job key", maximum=512)
        if type(self.inventory) is not AtsFormInventory:
            raise TypeError("ATS authority requires the exact inventory type")
        if type(self.reviewed_inventory) is not AtsFormInventory:
            raise TypeError("ATS authority requires the exact reviewed inventory type")
        if not _inventories_share_shape(self.inventory, self.reviewed_inventory):
            raise ValueError("reviewed ATS inventory differs from the observed form shape")
        if self.reviewed_at < self.reviewed_inventory.captured_at:
            raise ValueError("ATS authority predates the reviewed inventory")
        if not all(type(row) is AtsAnswerEntry for row in self.answers):
            raise TypeError("ATS authority requires exact answer entries")
        if tuple(row.field_id for row in self.answers) != tuple(
            row.field_id for row in self.inventory.fields
        ):
            raise ValueError("ATS authority must cover every field in inventory order")
        _verify_reviewed_values(self.inventory, self.reviewed_inventory, self.answers)
        if self.policy_sha256 != ATS_AUTHORITY_POLICY_SHA256:
            raise ValueError("ATS application authority policy differs")
        if self.external_action_capability is not False:
            raise ValueError("ATS application authority cannot grant external action")
        _captured_bytes(self.inventory_bytes, "ATS inventory")
        _captured_bytes(self.answer_bytes, "ATS answers")
        if self.authority_sha256 != content_hash(self.document(include_hash=False)):
            raise ValueError("ATS application authority identity is invalid")

    def answer_document(self) -> dict[str, object]:
        return {
            "schema_version": "jaa.ats-field-answers.v1",
            "observed_inventory_sha256": self.inventory.content_sha256,
            "reviewed_inventory_sha256": self.reviewed_inventory.content_sha256,
            "application_source_sha256": self.application_source_sha256,
            "candidate_authority_sha256": self.candidate_authority_sha256,
            "answers": [row.document() for row in self.answers],
        }

    @property
    def answer_bytes(self) -> bytes:
        return _canonical_bytes(self.answer_document())

    @property
    def answer_sha256(self) -> str:
        return hashlib.sha256(self.answer_bytes).hexdigest()

    def inventory_document(self) -> dict[str, object]:
        return {
            "schema_version": "jaa.ats-inventory-pair.v1",
            "observed": self.inventory.document(),
            "reviewed": self.reviewed_inventory.document(),
        }

    @property
    def inventory_bytes(self) -> bytes:
        return _canonical_bytes(self.inventory_document())

    @property
    def inventory_sha256(self) -> str:
        return hashlib.sha256(self.inventory_bytes).hexdigest()

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "reviewed_at": self.reviewed_at,
            "candidate_authority_sha256": self.candidate_authority_sha256,
            "application_source_sha256": self.application_source_sha256,
            "artifact_receipt_sha256": self.artifact_receipt_sha256,
            "vacancy_sha256": self.vacancy_sha256,
            "job_key": self.job_key,
            "observed_inventory_sha256": self.inventory.content_sha256,
            "reviewed_inventory_sha256": self.reviewed_inventory.content_sha256,
            "inventory_pair_sha256": self.inventory_sha256,
            "answer_sha256": self.answer_sha256,
            "cv_pdf_sha256": self.cv_pdf_sha256,
            "cover_letter_pdf_sha256": self.cover_letter_pdf_sha256,
            "policy_sha256": self.policy_sha256,
            "external_action_capability": False,
        }
        if include_hash:
            result["authority_sha256"] = self.authority_sha256
        return result


def _structured_answer_values(source: ApplicationSource) -> dict[str, tuple[str, str]]:
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    result: dict[str, tuple[str, str]] = {}
    for answer in source.answers:
        value = "\n".join(
            (
                *(slots[row] for row in answer.style_slot_ids),
                *(facts[row] for row in answer.sentence_ids),
            )
        )
        source_sha256 = content_hash(
            {
                "question_id": answer.question_id,
                "question": answer.question,
                "value": value,
                "application_source_sha256": source.source_id,
            }
        )
        result[f"answer.{answer.question_id}"] = (value, source_sha256)
    return result


def _inventories_share_shape(
    observed: AtsFormInventory,
    reviewed: AtsFormInventory,
) -> bool:
    return (
        reviewed.provider == observed.provider
        and reviewed.application_url == observed.application_url
        and reviewed.shape_sha256 == observed.shape_sha256
        and reviewed.captured_at >= observed.captured_at
    )


def is_ats_omitted_value_empty(
    control_kind: str,
    value: str | bool | int | None,
) -> bool:
    """Exact kind-aware emptiness for an omitted applicant field.

    Provider-neutral: an omitted checkbox is empty only when its exact
    value is ``False`` (an unchecked control is exact DOM state, not an
    absence); every other omitted field is empty only when it holds exactly
    ``None`` or the empty string.  An omitted checkbox holding ``True`` is
    never empty.
    """
    if control_kind == "checkbox":
        return value is False
    return value in (None, "")


def _verify_reviewed_values(
    observed_inventory: AtsFormInventory,
    reviewed_inventory: AtsFormInventory,
    answers: tuple[AtsAnswerEntry, ...],
) -> None:
    for observed, reviewed, answer in zip(
        observed_inventory.fields,
        reviewed_inventory.fields,
        answers,
        strict=True,
    ):
        if observed.current_value != answer.observed_value:
            raise ValueError("ATS plan does not bind the exact initially observed value")
        if observed.automation_role == "provider_managed":
            if reviewed.current_value != observed.current_value:
                raise ValueError("provider-managed ATS state changed during review")
        elif observed.automation_role == "honeypot":
            if reviewed.current_value not in (None, ""):
                raise ValueError("ATS honeypot changed during review")
        elif answer.action in {"fill", "upload"}:
            if reviewed.current_value != answer.final_value:
                raise ValueError("reviewed ATS value differs from exact answer authority")
        elif not is_ats_omitted_value_empty(
            observed.control_kind, reviewed.current_value
        ):
            raise ValueError("omitted ATS field contains an unapproved reviewed value")


def _resolve_value(
    reference: str,
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
) -> tuple[str | bool | int | None, str]:
    if reference in _CONTACT_REFERENCES:
        name = _CONTACT_REFERENCES[reference]
        value = getattr(source.contact, name)
        return value, content_hash(
            {
                "source_reference": reference,
                "contact": source.contact.document(),
            }
        )
    answers = _structured_answer_values(source)
    if reference in answers:
        return answers[reference]
    if reference == "artifact.cv":
        return artifacts.cv_pdf.pdf_sha256, artifacts.cv_pdf.pdf_sha256
    if reference == "artifact.cover_letter":
        return (
            artifacts.cover_letter_pdf.pdf_sha256,
            artifacts.cover_letter_pdf.pdf_sha256,
        )
    if reference == "none":
        return None, ATS_AUTHORITY_POLICY_SHA256
    raise ValueError("ATS field cites an unsupported application authority")


def _build_entries(
    inventory: AtsFormInventory,
    plans: Iterable[AtsFieldPlan],
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
) -> tuple[AtsAnswerEntry, ...]:
    plan_rows = tuple(plans)
    if not all(type(row) is AtsFieldPlan for row in plan_rows):
        raise TypeError("ATS field plans must be exact typed plans")
    plan_by_id = {row.field_id: row for row in plan_rows}
    if len(plan_by_id) != len(plan_rows) or set(plan_by_id) != {
        row.field_id for row in inventory.fields
    }:
        raise ValueError("ATS plans must cover every observed field exactly once")
    entries: list[AtsAnswerEntry] = []
    for observed in inventory.fields:
        plan = plan_by_id[observed.field_id]
        if plan.observed_value != observed.current_value:
            raise ValueError("ATS plan does not bind the exact initially observed value")
        value, source_sha256 = _resolve_value(
            plan.source_reference,
            source,
            artifacts,
        )
        non_actionable = (
            observed.control_kind == "hidden"
            or observed.automation_role != "applicant"
            or not observed.visible
            or observed.disabled
            or observed.read_only
        )
        if non_actionable:
            if (
                plan.action != "omit"
                or plan.source_reference != "none"
                or plan.correction_reason is not None
            ):
                raise ValueError("hidden or non-actionable ATS fields must be omitted")
            if (
                observed.automation_role == "honeypot"
                and plan.observed_value not in (None, "")
            ):
                raise ValueError("ATS honeypot must remain empty")
        else:
            if observed.required and plan.action == "omit":
                raise ValueError("required ATS field lacks exact answer authority")
            if plan.action == "omit" and (
                plan.source_reference != "none"
                or plan.correction_reason is not None
            ):
                raise ValueError("omitted ATS fields cannot cite answer authority")
            if plan.action == "upload":
                if observed.control_kind != "file" or plan.source_reference not in {
                    "artifact.cv",
                    "artifact.cover_letter",
                }:
                    raise ValueError("ATS upload must bind an exact application PDF")
            elif plan.action == "fill":
                if observed.control_kind in {"file", "hidden"} or value is None:
                    raise ValueError("ATS fill action lacks a compatible exact value")
                if observed.options and str(value) not in {
                    row.value for row in observed.options
                }:
                    raise ValueError("ATS answer is not an exact observed option")
            elif value is not None:
                raise ValueError("omitted ATS field unexpectedly resolved a value")
        entries.append(
            AtsAnswerEntry(
                field_id=observed.field_id,
                action=plan.action,
                value_kind=_value_kind(value),
                final_value=value,
                observed_value=plan.observed_value,
                source_reference=plan.source_reference,
                source_sha256=source_sha256,
                correction_reason=plan.correction_reason,
            )
        )
    return tuple(entries)


def compile_ats_answer_entries(
    *,
    inventory: AtsFormInventory,
    plans: Iterable[AtsFieldPlan],
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
) -> tuple[AtsAnswerEntry, ...]:
    """Pure exact answer-compilation seam between observation and action.

    Verifies the exact typed inventory, plans, source and artifacts and
    returns immutable :class:`AtsAnswerEntry` rows.  It grants no external
    action of any kind: no browser, network, filesystem, release or
    submission capability passes through this seam.
    """
    if type(inventory) is not AtsFormInventory:
        raise TypeError("ATS authority requires the exact inventory type")
    if type(source) is not ApplicationSource:
        raise TypeError("ATS answers require the exact application source type")
    if type(artifacts) is not ApplicationArtifacts:
        raise TypeError("ATS answers require the exact artifact set type")
    verify_application_source(source)
    verify_application_artifacts(artifacts)
    return _build_entries(inventory, plans, source, artifacts)


def build_ats_application_authority(
    *,
    reviewed_at: str,
    candidate_authority_sha256: str,
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
    publication_receipt: PublishedArtifactReceipt,
    inventory: AtsFormInventory,
    reviewed_inventory: AtsFormInventory,
    plans: Iterable[AtsFieldPlan],
) -> AtsApplicationAuthority:
    """Build a closed, non-release ATS authority from exact application objects."""
    _require_time(reviewed_at, "ATS authority review time")
    _require_sha256(candidate_authority_sha256, "candidate authority hash")
    entries = compile_ats_answer_entries(
        inventory=inventory,
        plans=plans,
        source=source,
        artifacts=artifacts,
    )
    if type(reviewed_inventory) is not AtsFormInventory:
        raise TypeError("ATS authority requires the exact reviewed inventory type")
    if not _inventories_share_shape(inventory, reviewed_inventory):
        raise ValueError("reviewed ATS inventory differs from the observed form shape")
    if reviewed_at < reviewed_inventory.captured_at:
        raise ValueError("ATS authority predates the reviewed inventory")
    verify_application_artifact_receipt(source, artifacts, publication_receipt)
    _verify_reviewed_values(inventory, reviewed_inventory, entries)
    values = {
        "reviewed_at": reviewed_at,
        "candidate_authority_sha256": candidate_authority_sha256,
        "application_source_sha256": source.source_id,
        "artifact_receipt_sha256": publication_receipt.receipt_sha256,
        "vacancy_sha256": source.vacancy_sha256,
        "job_key": source.job_key,
        "inventory": inventory,
        "reviewed_inventory": reviewed_inventory,
        "answers": entries,
        "cv_pdf_sha256": artifacts.cv_pdf.pdf_sha256,
        "cover_letter_pdf_sha256": artifacts.cover_letter_pdf.pdf_sha256,
        "policy_sha256": ATS_AUTHORITY_POLICY_SHA256,
    }
    answer_document = {
        "schema_version": "jaa.ats-field-answers.v1",
        "observed_inventory_sha256": inventory.content_sha256,
        "reviewed_inventory_sha256": reviewed_inventory.content_sha256,
        "application_source_sha256": source.source_id,
        "candidate_authority_sha256": candidate_authority_sha256,
        "answers": [row.document() for row in entries],
    }
    answer_sha256 = hashlib.sha256(_canonical_bytes(answer_document)).hexdigest()
    inventory_pair_sha256 = hashlib.sha256(
        _canonical_bytes(
            {
                "schema_version": "jaa.ats-inventory-pair.v1",
                "observed": inventory.document(),
                "reviewed": reviewed_inventory.document(),
            }
        )
    ).hexdigest()
    document = {
        "schema_version": "jaa.ats-application-authority.v1",
        "reviewed_at": reviewed_at,
        "candidate_authority_sha256": candidate_authority_sha256,
        "application_source_sha256": source.source_id,
        "artifact_receipt_sha256": publication_receipt.receipt_sha256,
        "vacancy_sha256": source.vacancy_sha256,
        "job_key": source.job_key,
        "observed_inventory_sha256": inventory.content_sha256,
        "reviewed_inventory_sha256": reviewed_inventory.content_sha256,
        "inventory_pair_sha256": inventory_pair_sha256,
        "answer_sha256": answer_sha256,
        "cv_pdf_sha256": artifacts.cv_pdf.pdf_sha256,
        "cover_letter_pdf_sha256": artifacts.cover_letter_pdf.pdf_sha256,
        "policy_sha256": ATS_AUTHORITY_POLICY_SHA256,
        "external_action_capability": False,
    }
    return AtsApplicationAuthority(
        **values,
        authority_sha256=content_hash(document),
    )


def verify_ats_application_authority(
    authority: AtsApplicationAuthority,
    *,
    candidate_authority_sha256: str,
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
    publication_receipt: PublishedArtifactReceipt,
) -> AtsApplicationAuthority:
    """Rebuild an exact authority so forged or substituted objects fail closed."""
    if type(authority) is not AtsApplicationAuthority:
        raise TypeError("ATS authority must use the exact canonical type")
    plans = tuple(
        AtsFieldPlan(
            field_id=row.field_id,
            action=row.action,
            source_reference=row.source_reference,
            observed_value=row.observed_value,
            correction_reason=row.correction_reason,
        )
        for row in authority.answers
    )
    expected = build_ats_application_authority(
        reviewed_at=authority.reviewed_at,
        candidate_authority_sha256=candidate_authority_sha256,
        source=source,
        artifacts=artifacts,
        publication_receipt=publication_receipt,
        inventory=authority.inventory,
        reviewed_inventory=authority.reviewed_inventory,
        plans=plans,
    )
    if authority != expected:
        raise ValueError("ATS application authority differs from exact application evidence")
    _captured_bytes(authority.inventory_bytes, "ATS inventory")
    _captured_bytes(authority.answer_bytes, "ATS answers")
    return authority
