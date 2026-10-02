"""Strict canonical Market Aligner to JAA handoff v1 codec and identities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from market_aligner.applications.canonical import (
    CODE_PATTERN,
    COMMIT_PATTERN,
    ContractValidationError,
    JOB_KEY_PATTERN,
    PROFILE_ID_PATTERN,
    canonical_json_bytes,
    deep_freeze_json,
    deep_thaw_json,
    digest_bytes,
    parse_canonical_json,
    parse_timestamp,
    require_exact_keys,
    require_mapping,
    require_nonempty_string,
    require_pattern,
    require_probability,
    require_sha256,
    require_sorted_unique_strings,
    require_timestamp,
    validate_strings,
)
from market_aligner.assessment.geography import EU_REMOTE_COUNTRIES
from market_aligner.collectors.evidence import validate_public_listing_url


JAA_HANDOFF_VERSION = "market-aligner.jaa-handoff.v1"
STRICT_PROFILE = "strict_v1"
BASE_COMPATIBILITY_PROFILE = "base_v1_compatibility"
UNCLASSIFIED_TRUST_CLASS = "unclassified"
SYNTHETIC_FIXTURE_TRUST_CLASS = "synthetic_fixture"
INSTALLED_PRODUCTION_TRUST_CLASS = "installed_production"
_TRUST_CLASSES = frozenset(
    {
        UNCLASSIFIED_TRUST_CLASS,
        SYNTHETIC_FIXTURE_TRUST_CLASS,
        INSTALLED_PRODUCTION_TRUST_CLASS,
    }
)
_ENVELOPE_KEYS = {"payload", "payload_sha256", "schema_version"}
_PAYLOAD_KEYS = {
    "assessment",
    "candidate_intent_sha256",
    "created_at",
    "eligibility",
    "employer_dossier_sha256",
    "evidence_ledger_sha256",
    "job_key",
    "producer",
    "profile_id",
    "profile_version",
    "selection",
    "vacancy",
}
_ASSESSMENT_KEYS = {
    "assessment_receipt_sha256",
    "extraction_confidence",
    "final",
    "fit",
    "fit_components",
    "fit_status",
    "opportunity",
    "opportunity_components",
    "scoring_parameters_sha256",
}
_ELIGIBILITY_KEYS = {"checks", "decision", "eligibility_receipt_sha256", "hard_gate_passed"}
_CHECK_KEYS = {"code", "evidence_sha256", "outcome"}
_PRODUCER_KEYS = {"commit_sha", "product"}
_SELECTION_KEYS = {
    "decision",
    "geography_bucket",
    "geography_priority_rank",
    "hard_gate_passed",
    "rationale_codes",
    "selection_policy_sha256",
    "selection_receipt_sha256",
}
_VACANCY_KEYS = {
    "company_name",
    "location",
    "provenance",
    "raw_listing_sha256",
    "requirements_sha256",
    "role_title",
    "vacancy_snapshot_sha256",
}
_LOCATION_KEYS = {"country_code", "facts_sha256", "locality", "raw_text", "region", "work_mode"}
_PROVENANCE_KEYS = {"adapter", "canonical_url", "discovered_at", "fetched_at", "source_job_id"}
_BUCKETS = {
    "UK_REMOTE": (1, "GB", "remote"),
    "UK_HYBRID": (2, "GB", "hybrid"),
    "UK_ONSITE": (3, "GB", "onsite"),
    "RO_REMOTE": (4, "RO", "remote"),
}
def job_key_for(
    *, adapter: str, canonical_url: str, source_job_id: str, strict_strings: bool = True
) -> str:
    preimage = {
        "adapter": adapter,
        "canonical_url": canonical_url,
        "source_job_id": source_job_id,
    }
    return "job_" + digest_bytes(canonical_json_bytes(preimage, strict_strings=strict_strings))


def logical_handoff_tuple(payload: Mapping[str, Any]) -> dict[str, str]:
    assessment = require_mapping(payload["assessment"], "assessment")
    eligibility = require_mapping(payload["eligibility"], "eligibility")
    selection = require_mapping(payload["selection"], "selection")
    vacancy = require_mapping(payload["vacancy"], "vacancy")
    return {
        "assessment_receipt_sha256": str(assessment["assessment_receipt_sha256"]),
        "candidate_intent_sha256": str(payload["candidate_intent_sha256"]),
        "eligibility_receipt_sha256": str(eligibility["eligibility_receipt_sha256"]),
        "job_key": str(payload["job_key"]),
        "profile_id": str(payload["profile_id"]),
        "profile_version": str(payload["profile_version"]),
        "selection_receipt_sha256": str(selection["selection_receipt_sha256"]),
        "vacancy_snapshot_sha256": str(vacancy["vacancy_snapshot_sha256"]),
    }


def application_id_for(payload: Mapping[str, Any], *, strict_strings: bool = True) -> str:
    return "app_" + digest_bytes(
        canonical_json_bytes(logical_handoff_tuple(payload), strict_strings=strict_strings)
    )


def _validate_score_components(value: Any, label: str, *, strict_profile: bool) -> None:
    mapping = require_mapping(value, label)
    if not mapping:
        raise ContractValidationError(f"{label} must not be empty")
    for code, score in mapping.items():
        if not CODE_PATTERN.fullmatch(code):
            raise ContractValidationError(f"{label} contains an invalid component code")
        require_probability(score, f"{label}.{code}", strict_profile=strict_profile)


def _require_wire_text(value: Any, label: str, *, strict_profile: bool) -> str:
    text = require_nonempty_string(value, label)
    if strict_profile and text != text.strip():
        raise ContractValidationError(f"{label} must be a trimmed string")
    return text


def _validate_canonical_url(value: Any, *, strict_profile: bool) -> str:
    url = _require_wire_text(
        value, "vacancy.provenance.canonical_url", strict_profile=strict_profile
    )
    validate_public_listing_url(url)
    if "#" in url:
        raise ContractValidationError("canonical_url must not contain a fragment")
    return url


def validate_handoff_payload(payload: Mapping[str, Any], *, strict_profile: bool) -> None:
    require_exact_keys(payload, _PAYLOAD_KEYS, "handoff payload")
    require_pattern(payload["profile_id"], PROFILE_ID_PATTERN, "profile_id")
    _require_wire_text(
        payload["profile_version"], "profile_version", strict_profile=strict_profile
    )
    require_pattern(payload["job_key"], JOB_KEY_PATTERN, "job_key")
    require_sha256(payload["candidate_intent_sha256"], "candidate_intent_sha256")
    require_sha256(payload["evidence_ledger_sha256"], "evidence_ledger_sha256")
    require_sha256(
        payload["employer_dossier_sha256"], "employer_dossier_sha256", nullable=True
    )
    require_timestamp(payload["created_at"], "created_at", strict_profile=strict_profile)

    producer = require_mapping(payload["producer"], "producer")
    require_exact_keys(producer, _PRODUCER_KEYS, "producer")
    if producer["product"] != "market-aligner":
        raise ContractValidationError("producer.product must be market-aligner")
    require_pattern(producer["commit_sha"], COMMIT_PATTERN, "producer.commit_sha")

    assessment = require_mapping(payload["assessment"], "assessment")
    require_exact_keys(assessment, _ASSESSMENT_KEYS, "assessment")
    for name in ("extraction_confidence", "final", "fit", "opportunity"):
        require_probability(assessment[name], f"assessment.{name}", strict_profile=strict_profile)
    _validate_score_components(
        assessment["fit_components"], "assessment.fit_components", strict_profile=strict_profile
    )
    _validate_score_components(
        assessment["opportunity_components"],
        "assessment.opportunity_components",
        strict_profile=strict_profile,
    )
    if assessment["fit_status"] != "uncalibrated":
        raise ContractValidationError("assessment.fit_status must be uncalibrated")
    require_sha256(
        assessment["assessment_receipt_sha256"], "assessment.assessment_receipt_sha256"
    )
    require_sha256(
        assessment["scoring_parameters_sha256"], "assessment.scoring_parameters_sha256"
    )

    eligibility = require_mapping(payload["eligibility"], "eligibility")
    require_exact_keys(eligibility, _ELIGIBILITY_KEYS, "eligibility")
    if eligibility["decision"] != "eligible" or eligibility["hard_gate_passed"] is not True:
        raise ContractValidationError("a handoff requires an eligible hard-gate decision")
    require_sha256(
        eligibility["eligibility_receipt_sha256"],
        "eligibility.eligibility_receipt_sha256",
    )
    checks = eligibility["checks"]
    if not isinstance(checks, list) or not checks:
        raise ContractValidationError("eligibility.checks must be a non-empty array")
    check_codes: list[str] = []
    for index, check_value in enumerate(checks):
        check = require_mapping(check_value, f"eligibility.checks[{index}]")
        require_exact_keys(check, _CHECK_KEYS, f"eligibility.checks[{index}]")
        code = require_nonempty_string(check["code"], f"eligibility.checks[{index}].code")
        if not CODE_PATTERN.fullmatch(code):
            raise ContractValidationError("eligibility check code is invalid")
        check_codes.append(code)
        require_sha256(
            check["evidence_sha256"], f"eligibility.checks[{index}].evidence_sha256"
        )
        if check["outcome"] != "pass":
            raise ContractValidationError("every emitted handoff eligibility check must pass")
    if check_codes != sorted(set(check_codes)):
        raise ContractValidationError("eligibility checks must sort by unique code")

    selection = require_mapping(payload["selection"], "selection")
    require_exact_keys(selection, _SELECTION_KEYS, "selection")
    if selection["decision"] != "selected_for_application" or selection["hard_gate_passed"] is not True:
        raise ContractValidationError("handoff selection must be selected with hard gates passed")
    bucket = selection["geography_bucket"]
    rank = selection["geography_priority_rank"]
    if isinstance(rank, bool) or not isinstance(rank, int):
        raise ContractValidationError("selection geography rank must be an integer")
    if bucket not in {*_BUCKETS, "EU_REMOTE"}:
        raise ContractValidationError("unknown geography bucket")
    expected_rank = _BUCKETS[bucket][0] if bucket in _BUCKETS else 5
    if rank != expected_rank:
        raise ContractValidationError("geography bucket/rank pair differs")
    require_sorted_unique_strings(
        selection["rationale_codes"], "selection.rationale_codes", code_values=True
    )
    require_sha256(selection["selection_policy_sha256"], "selection.selection_policy_sha256")
    require_sha256(
        selection["selection_receipt_sha256"], "selection.selection_receipt_sha256"
    )

    vacancy = require_mapping(payload["vacancy"], "vacancy")
    require_exact_keys(vacancy, _VACANCY_KEYS, "vacancy")
    _require_wire_text(
        vacancy["company_name"], "vacancy.company_name", strict_profile=strict_profile
    )
    _require_wire_text(
        vacancy["role_title"], "vacancy.role_title", strict_profile=strict_profile
    )
    for name in ("raw_listing_sha256", "requirements_sha256", "vacancy_snapshot_sha256"):
        require_sha256(vacancy[name], f"vacancy.{name}")
    location = require_mapping(vacancy["location"], "vacancy.location")
    require_exact_keys(location, _LOCATION_KEYS, "vacancy.location")
    country = require_nonempty_string(location["country_code"], "vacancy.location.country_code")
    if country == "UNKNOWN" or len(country) != 2 or country.upper() != country or country == "UK":
        raise ContractValidationError("selected handoff requires a known ISO-like country code")
    require_sha256(location["facts_sha256"], "vacancy.location.facts_sha256")
    for name in ("locality", "raw_text", "region"):
        if not isinstance(location[name], str):
            raise ContractValidationError(f"vacancy.location.{name} must be a string")
    if not location["raw_text"]:
        raise ContractValidationError("vacancy.location.raw_text must retain listing evidence")
    mode = location["work_mode"]
    if mode not in {"remote", "hybrid", "onsite"}:
        raise ContractValidationError("selected handoff requires a known work mode")
    if bucket in _BUCKETS:
        _, expected_country, expected_mode = _BUCKETS[bucket]
        if (country, mode) != (expected_country, expected_mode):
            raise ContractValidationError("location facts disagree with selected geography bucket")
    elif country not in EU_REMOTE_COUNTRIES or mode != "remote":
        raise ContractValidationError("EU_REMOTE requires EU27-minus-RO country and remote mode")

    provenance = require_mapping(vacancy["provenance"], "vacancy.provenance")
    require_exact_keys(provenance, _PROVENANCE_KEYS, "vacancy.provenance")
    adapter = _require_wire_text(
        provenance["adapter"],
        "vacancy.provenance.adapter",
        strict_profile=strict_profile,
    )
    canonical_url = _validate_canonical_url(
        provenance["canonical_url"], strict_profile=strict_profile
    )
    source_job_id = _require_wire_text(
        provenance["source_job_id"],
        "vacancy.provenance.source_job_id",
        strict_profile=strict_profile,
    )
    discovered = require_timestamp(
        provenance["discovered_at"],
        "vacancy.provenance.discovered_at",
        strict_profile=strict_profile,
    )
    fetched = require_timestamp(
        provenance["fetched_at"],
        "vacancy.provenance.fetched_at",
        strict_profile=strict_profile,
    )
    if not parse_timestamp(discovered) <= parse_timestamp(fetched) <= parse_timestamp(
        str(payload["created_at"])
    ):
        raise ContractValidationError("provenance chronology must be discovered <= fetched <= created")
    expected_job_key = job_key_for(
        adapter=adapter,
        canonical_url=canonical_url,
        source_job_id=source_job_id,
        strict_strings=strict_profile,
    )
    if payload["job_key"] != expected_job_key:
        raise ContractValidationError("job_key does not match its exact provenance preimage")
    validate_strings(payload, require_nfc=strict_profile)


@dataclass(frozen=True)
class HandoffEnvelope:
    payload: Mapping[str, Any]
    exact_bytes: bytes
    payload_sha256: str
    root_sha256: str
    emission_profile: str
    delivery_trust_class: str

    def __post_init__(self) -> None:
        if self.delivery_trust_class not in _TRUST_CLASSES:
            raise ContractValidationError("handoff delivery trust class is invalid")

    @property
    def idempotency_key(self) -> str:
        return self.root_sha256

    @property
    def application_id(self) -> str:
        return application_id_for(
            self.payload, strict_strings=self.emission_profile == STRICT_PROFILE
        )

    @property
    def logical_tuple(self) -> Mapping[str, str]:
        return logical_handoff_tuple(self.payload)

    @property
    def release_blocked(self) -> bool:
        return (
            self.emission_profile != STRICT_PROFILE
            or self.delivery_trust_class != INSTALLED_PRODUCTION_TRUST_CLASS
        )

    def with_delivery_trust(self, trust_class: str) -> "HandoffEnvelope":
        """Attach verified local delivery state without changing contract bytes."""

        if trust_class not in _TRUST_CLASSES:
            raise ContractValidationError("handoff delivery trust class is invalid")
        return HandoffEnvelope(
            self.payload,
            self.exact_bytes,
            self.payload_sha256,
            self.root_sha256,
            self.emission_profile,
            trust_class,
        )


def encode_handoff_v1(payload: Mapping[str, Any]) -> HandoffEnvelope:
    value = deep_thaw_json(payload)
    validate_handoff_payload(value, strict_profile=True)
    payload_bytes = canonical_json_bytes(value)
    payload_sha = digest_bytes(payload_bytes)
    envelope = {
        "payload": value,
        "payload_sha256": payload_sha,
        "schema_version": JAA_HANDOFF_VERSION,
    }
    exact_bytes = canonical_json_bytes(envelope)
    return HandoffEnvelope(
        deep_freeze_json(value),
        exact_bytes,
        payload_sha,
        digest_bytes(exact_bytes),
        STRICT_PROFILE,
        UNCLASSIFIED_TRUST_CLASS,
    )


def parse_handoff_v1(data: bytes) -> HandoffEnvelope:
    envelope = require_mapping(parse_canonical_json(data), "handoff envelope")
    require_exact_keys(envelope, _ENVELOPE_KEYS, "handoff envelope")
    if envelope["schema_version"] != JAA_HANDOFF_VERSION:
        raise ContractValidationError("unsupported handoff envelope schema")
    require_sha256(envelope["payload_sha256"], "payload_sha256")
    payload = require_mapping(envelope["payload"], "handoff payload")
    payload_bytes = canonical_json_bytes(payload, strict_strings=False)
    if digest_bytes(payload_bytes) != envelope["payload_sha256"]:
        raise ContractValidationError("handoff payload digest differs")
    validate_handoff_payload(payload, strict_profile=False)
    emission_profile = BASE_COMPATIBILITY_PROFILE
    try:
        validate_handoff_payload(payload, strict_profile=True)
    except ContractValidationError:
        pass
    else:
        emission_profile = STRICT_PROFILE
    return HandoffEnvelope(
        deep_freeze_json(payload),
        data,
        str(envelope["payload_sha256"]),
        digest_bytes(data),
        emission_profile,
        UNCLASSIFIED_TRUST_CLASS,
    )


class HandoffReplayIndex:
    """Exact-root and logical-tuple conflict semantics independent of persistence."""

    def __init__(self) -> None:
        self._by_root: dict[str, HandoffEnvelope] = {}
        self._root_by_tuple: dict[bytes, str] = {}

    def admit(self, handoff: HandoffEnvelope) -> tuple[HandoffEnvelope, bool]:
        existing = self._by_root.get(handoff.root_sha256)
        if existing is not None:
            if existing.exact_bytes != handoff.exact_bytes:
                raise ContractValidationError("same handoff root has different exact bytes")
            return existing, True
        tuple_bytes = canonical_json_bytes(
            dict(handoff.logical_tuple),
            strict_strings=handoff.emission_profile == STRICT_PROFILE,
        )
        previous_root = self._root_by_tuple.get(tuple_bytes)
        if previous_root is not None and previous_root != handoff.root_sha256:
            raise ContractValidationError("same logical handoff tuple has a different root")
        self._by_root[handoff.root_sha256] = handoff
        self._root_by_tuple[tuple_bytes] = handoff.root_sha256
        return handoff, False
