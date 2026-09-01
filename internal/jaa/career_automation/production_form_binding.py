"""Canonical authority for employer-facing Greenhouse field values."""

from __future__ import annotations

import hashlib
import re
from typing import Mapping, Sequence

from .application_compiler import ApplicationSource
from .ats_application_authority import (
    STANDARD_CANDIDATE_AUTHORITIES,
)
from .evidence_matching import canonical_json
from .rendering import ApplicationArtifacts


FIELD_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
CONTACT_AUTHORITIES = frozenset(
    {
        "contact.full_name",
        "contact.given_name",
        "contact.family_name",
        "contact.email",
        "contact.phone",
        "contact.city",
    }
)

# Stable operator facts already admitted by the candidate-authority policy.
# These values are deliberately narrow: they answer recurring Greenhouse
# identity/eligibility controls and choose non-disclosure for demographic
# surveys.  Vacancy-specific prose remains owned by ApplicationSource.answers.
STANDARD_FORM_AUTHORITIES: Mapping[str, str] = STANDARD_CANDIDATE_AUTHORITIES


class ProductionFormBindingError(ValueError):
    """A provider field cannot be bound to approved application authority."""


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _contact_value(source: ApplicationSource, authority_name: str) -> str:
    if authority_name == "contact.full_name":
        return source.contact.full_name
    if authority_name == "contact.email":
        return source.contact.email
    if authority_name == "contact.phone":
        if source.contact.phone is None:
            raise ProductionFormBindingError(
                "candidate phone lacks explicit contact authority"
            )
        return source.contact.phone
    if authority_name == "contact.city":
        return source.contact.city
    given, separator, family = source.contact.full_name.partition(" ")
    if not separator or not given.strip() or not family.strip():
        raise ProductionFormBindingError(
            "approved full name cannot be split into given and family names"
        )
    if authority_name == "contact.given_name":
        return given.strip()
    if authority_name == "contact.family_name":
        return family.strip()
    raise ProductionFormBindingError("contact field authority is unsupported")


def approved_authority_values(
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
) -> Mapping[str, str]:
    """Return exact values derivable from approved contact and answer objects."""
    values: dict[str, str] = {}
    for name in CONTACT_AUTHORITIES:
        if name == "contact.phone" and source.contact.phone is None:
            continue
        values[name] = _contact_value(source, name)
    values["answers.full"] = artifacts.editable.answers_text
    values["blank.optional"] = ""
    values.update(STANDARD_FORM_AUTHORITIES)
    facts = {row.sentence_id: row.text for row in source.facts}
    slots = {row.slot_id: row.text for row in source.style_slots}
    for answer in source.answers:
        value = "\n".join(
            (
                *(slots[slot_id] for slot_id in answer.style_slot_ids),
                *(facts[sentence_id] for sentence_id in answer.sentence_ids),
            )
        )
        values[f"answer.{answer.question_id}"] = value
    return values


def approved_form_mapping_bytes(
    *,
    source: ApplicationSource,
    artifacts: ApplicationArtifacts,
    field_authority_names: Sequence[tuple[str, str]],
    consent_states: Sequence[tuple[str, bool | str]],
) -> bytes:
    """Build the exact field/value contract included in release authority."""
    field_rows = tuple(field_authority_names)
    consent_rows = tuple(consent_states)
    identities = [row[0] for row in (*field_rows, *consent_rows)]
    if len(set(identities)) != len(identities):
        raise ProductionFormBindingError("provider field identities must be unique")
    approved = approved_authority_values(source, artifacts)
    fields: list[dict[str, object]] = []
    for identity, authority_name in field_rows:
        if not FIELD_IDENTITY.fullmatch(identity):
            raise ProductionFormBindingError("provider field identity is invalid")
        if authority_name not in approved:
            raise ProductionFormBindingError("field authority is not approved")
        value = approved[authority_name]
        fields.append(
            {
                "field_identity": identity,
                "authority": authority_name,
                "value": value,
                "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            }
        )
    consents: list[dict[str, object]] = []
    for identity, expected in consent_rows:
        if not FIELD_IDENTITY.fullmatch(identity):
            raise ProductionFormBindingError("consent field identity is invalid")
        if (
            not isinstance(expected, (bool, str))
            or isinstance(expected, str)
            and (not expected or expected != expected.strip())
        ):
            raise ProductionFormBindingError("consent state is invalid")
        consents.append(
            {
                "field_identity": identity,
                "authority": "operator.consent",
                "value": expected,
            }
        )
    if not fields:
        raise ProductionFormBindingError("at least one approved form field is required")
    return _json_bytes(
        {
            "schema_version": "jaa.greenhouse-approved-form-mapping.v1",
            "fields": sorted(fields, key=lambda row: str(row["field_identity"])),
            "consents": sorted(consents, key=lambda row: str(row["field_identity"])),
        }
    )


__all__ = [
    "ProductionFormBindingError",
    "STANDARD_FORM_AUTHORITIES",
    "approved_authority_values",
    "approved_form_mapping_bytes",
]
