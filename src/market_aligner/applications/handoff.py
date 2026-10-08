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
CURRENT_RUNTIME_HANDOFF_VERSION = "market-aligner.jaa-handoff.current-runtime.v1"
_HANDOFF_RUNTIME_DISPATCH_ERROR = "invalid handoff runtime dispatch"
STRICT_PROFILE = "strict_v1"
CURRENT_RUNTIME_NON_RELEASE_PROFILE = "current_runtime_non_release_v1"
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
_STRICT_STRING_PROFILES = frozenset(
    {STRICT_PROFILE, CURRENT_RUNTIME_NON_RELEASE_PROFILE}
)


def handoff_release_blocked(
    schema_version: object,
    emission_profile: object,
    delivery_trust_class: object,
) -> bool:
    return not (
        type(schema_version) is str
        and type(emission_profile) is str
        and type(delivery_trust_class) is str
        and (schema_version, emission_profile, delivery_trust_class)
        == (JAA_HANDOFF_VERSION, STRICT_PROFILE, INSTALLED_PRODUCTION_TRUST_CLASS)
    )


def _uses_strict_string_validation(emission_profile: object) -> bool:
    return (
        type(emission_profile) is str
        and emission_profile in _STRICT_STRING_PROFILES
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
_CURRENT_RUNTIME_PAYLOAD_KEYS = _PAYLOAD_KEYS | {"preparation_geography"}
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
_CURRENT_RUNTIME_SELECTION_KEYS = _SELECTION_KEYS | {
    "geographic_preference_policy_sha256"
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

_PREPARATION_GEOGRAPHY_SCHEMA = "market-aligner.preparation-geography.v1"
_EU26_REMOTE_COUNTRIES = frozenset(
    {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
        "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT",
        "SI", "SK", "ES", "SE",
    }
)
_PREPARATION_GEOGRAPHY_KEYS = frozenset(
    {
        "schema_version",
        "country_code",
        "work_mode",
        "geography_bucket",
        "geography_priority_rank",
        "application_authority",
        "release_authority",
        "submission_authority",
    }
)


def _preparation_geography_row(country_code: object, work_mode: object) -> tuple[str | None, int | None]:
    if type(country_code) is not str or type(work_mode) is not str:
        raise ValueError("preparation geography requires exact str country_code and work_mode")
    if country_code == "GB" and work_mode == "remote":
        return "UK_REMOTE", 1
    if country_code == "GB" and work_mode == "hybrid":
        return "UK_HYBRID", 2
    if country_code == "GB" and work_mode == "onsite":
        return "UK_ONSITE", 3
    if country_code == "RO" and work_mode == "remote":
        return "RO_REMOTE", 4
    if country_code in _EU26_REMOTE_COUNTRIES and work_mode == "remote":
        return "EU_REMOTE", 5
    if country_code == "GB" and work_mode == "unknown":
        return None, None
    raise ValueError("unsupported preparation geography country and work mode combination")


@dataclass(frozen=True)
class PreparationGeography:
    country_code: str
    work_mode: str
    geography_bucket: str | None
    geography_priority_rank: int | None

    def __post_init__(self) -> None:
        if type(self.country_code) is not str or type(self.work_mode) is not str:
            raise ValueError("preparation geography requires exact str country_code and work_mode")
        bucket, rank = _preparation_geography_row(self.country_code, self.work_mode)
        if bucket is None:
            if self.geography_bucket is not None or self.geography_priority_rank is not None:
                raise ValueError("unknown UK mode requires None bucket and None rank")
            return
        if type(self.geography_bucket) is not str or self.geography_bucket != bucket:
            raise ValueError("geography_bucket does not match resolved bucket")
        if type(self.geography_priority_rank) is not int or self.geography_priority_rank != rank:
            raise ValueError("geography_priority_rank does not match resolved rank")


def resolve_preparation_geography(
    *, country_code: object, work_mode: object, current_runtime: object,
    unknown_uk_mode_allowed: object,
) -> PreparationGeography:
    if type(current_runtime) is not bool or type(unknown_uk_mode_allowed) is not bool:
        raise ValueError("current_runtime and unknown_uk_mode_allowed must be exact bool")
    bucket, rank = _preparation_geography_row(country_code, work_mode)
    if bucket is None and not (current_runtime is True and unknown_uk_mode_allowed is True):
        raise ValueError(
            "unknown UK mode requires both current_runtime and unknown_uk_mode_allowed True"
        )
    return PreparationGeography(country_code, work_mode, bucket, rank)


def validate_preparation_geography(
    document: object, *, current_runtime: object, unknown_uk_mode_allowed: object
) -> PreparationGeography:
    if type(document) is not dict:
        raise ValueError("document must be an exact dict")
    if type(current_runtime) is not bool or type(unknown_uk_mode_allowed) is not bool:
        raise ValueError("current_runtime and unknown_uk_mode_allowed must be exact bool")
    if any(type(key) is not str for key in document):
        raise ValueError("document keys must be exact str")
    if set(document) != set(_PREPARATION_GEOGRAPHY_KEYS):
        raise ValueError("document keys must match the preparation geography schema exactly")
    if type(document["schema_version"]) is not str or document["schema_version"] != _PREPARATION_GEOGRAPHY_SCHEMA:
        raise ValueError("unsupported schema_version")
    for key in ("application_authority", "release_authority", "submission_authority"):
        if document[key] is not False:
            raise ValueError("authority flags must each be literal False")
    candidate = PreparationGeography(
        document["country_code"],
        document["work_mode"],
        document["geography_bucket"],
        document["geography_priority_rank"],
    )
    expected = resolve_preparation_geography(
        country_code=document["country_code"],
        work_mode=document["work_mode"],
        current_runtime=current_runtime,
        unknown_uk_mode_allowed=unknown_uk_mode_allowed,
    )
    if candidate != expected:
        raise ValueError("document fields do not match resolved preparation geography")
    return candidate


def preparation_geography_document(
    value: PreparationGeography, *, current_runtime: object,
    unknown_uk_mode_allowed: object,
) -> dict[str, Any]:
    if type(value) is not PreparationGeography:
        raise ValueError("value must be an exact PreparationGeography instance")
    expected = resolve_preparation_geography(
        country_code=value.country_code,
        work_mode=value.work_mode,
        current_runtime=current_runtime,
        unknown_uk_mode_allowed=unknown_uk_mode_allowed,
    )
    for name in (
        "country_code", "work_mode", "geography_bucket", "geography_priority_rank"
    ):
        field_value = getattr(value, name)
        reference_value = getattr(expected, name)
        if type(field_value) is not type(reference_value) or field_value != reference_value:
            raise ValueError("value field does not match resolved preparation geography")
    document = {
        "schema_version": _PREPARATION_GEOGRAPHY_SCHEMA,
        "country_code": value.country_code,
        "work_mode": value.work_mode,
        "geography_bucket": value.geography_bucket,
        "geography_priority_rank": value.geography_priority_rank,
        "application_authority": False,
        "release_authority": False,
        "submission_authority": False,
    }
    validate_preparation_geography(
        document,
        current_runtime=current_runtime,
        unknown_uk_mode_allowed=unknown_uk_mode_allowed,
    )
    return document


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


def validate_handoff_payload(
    payload: Mapping[str, Any], *, strict_profile: bool, current_runtime: bool = False
) -> None:
    if type(current_runtime) is not bool:
        raise ContractValidationError("current_runtime must be a JSON boolean")
    require_exact_keys(
        payload,
        _CURRENT_RUNTIME_PAYLOAD_KEYS if current_runtime else _PAYLOAD_KEYS,
        "handoff payload",
    )
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
    require_exact_keys(
        selection,
        _CURRENT_RUNTIME_SELECTION_KEYS if current_runtime else _SELECTION_KEYS,
        "selection",
    )
    if selection["decision"] != "selected_for_application" or selection["hard_gate_passed"] is not True:
        raise ContractValidationError("handoff selection must be selected with hard gates passed")
    bucket = selection["geography_bucket"]
    rank = selection["geography_priority_rank"]
    preparation_geography = None
    if current_runtime:
        try:
            preparation_geography = validate_preparation_geography(
                payload["preparation_geography"],
                current_runtime=True,
                unknown_uk_mode_allowed=True,
            )
        except ValueError as exc:
            raise ContractValidationError(
                "current-runtime preparation geography is invalid"
            ) from exc
        expected_geography = (
            preparation_geography.geography_bucket,
            preparation_geography.geography_priority_rank,
        )
        if any(
            type(actual) is not type(expected) or actual != expected
            for actual, expected in zip((bucket, rank), expected_geography, strict=True)
        ):
            raise ContractValidationError(
                "selection geography differs from preparation geography"
            )
        require_sha256(
            selection["geographic_preference_policy_sha256"],
            "selection.geographic_preference_policy_sha256",
        )
    else:
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
    if current_runtime:
        if (country, mode) != (
            preparation_geography.country_code,
            preparation_geography.work_mode,
        ):
            raise ContractValidationError(
                "location facts differ from current-runtime preparation geography"
            )
    else:
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
    schema_version: str = JAA_HANDOFF_VERSION

    def __post_init__(self) -> None:
        if self.delivery_trust_class not in _TRUST_CLASSES:
            raise ContractValidationError("handoff delivery trust class is invalid")

    @property
    def idempotency_key(self) -> str:
        return self.root_sha256

    @property
    def application_id(self) -> str:
        return application_id_for(
            self.payload,
            strict_strings=_uses_strict_string_validation(self.emission_profile),
        )

    @property
    def logical_tuple(self) -> Mapping[str, str]:
        return logical_handoff_tuple(self.payload)

    @property
    def release_blocked(self) -> bool:
        return handoff_release_blocked(
            self.schema_version,
            self.emission_profile,
            self.delivery_trust_class,
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
            self.schema_version,
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


def encode_current_runtime_handoff_v1(payload: Mapping[str, Any]) -> HandoffEnvelope:
    value = deep_thaw_json(payload)
    validate_handoff_payload(value, strict_profile=True, current_runtime=True)
    payload_bytes = canonical_json_bytes(value)
    payload_sha = digest_bytes(payload_bytes)
    exact_bytes = canonical_json_bytes(
        {
            "payload": value,
            "payload_sha256": payload_sha,
            "schema_version": CURRENT_RUNTIME_HANDOFF_VERSION,
        }
    )
    return HandoffEnvelope(
        deep_freeze_json(value),
        exact_bytes,
        payload_sha,
        digest_bytes(exact_bytes),
        CURRENT_RUNTIME_NON_RELEASE_PROFILE,
        UNCLASSIFIED_TRUST_CLASS,
        CURRENT_RUNTIME_HANDOFF_VERSION,
    )


def encode_handoff_for_runtime(
    payload: Mapping[str, Any],
    *,
    current_runtime: bool = False,
    preparation_geography: Mapping[str, Any] | None = None,
) -> HandoffEnvelope:
    if (
        type(current_runtime) is not bool
        or not isinstance(payload, Mapping)
        or any(type(key) is not str for key in payload)
        or "preparation_geography" in payload
    ):
        raise ContractValidationError(_HANDOFF_RUNTIME_DISPATCH_ERROR)
    if not current_runtime:
        if preparation_geography is not None:
            raise ContractValidationError(_HANDOFF_RUNTIME_DISPATCH_ERROR)
        return encode_handoff_v1(payload)
    if (
        not isinstance(preparation_geography, Mapping)
        or any(type(key) is not str for key in preparation_geography)
    ):
        raise ContractValidationError(_HANDOFF_RUNTIME_DISPATCH_ERROR)
    current_payload = dict(payload)
    current_payload["preparation_geography"] = dict(preparation_geography)
    return encode_current_runtime_handoff_v1(current_payload)


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


def parse_current_runtime_handoff_v1(data: bytes) -> HandoffEnvelope:
    envelope = require_mapping(parse_canonical_json(data), "current-runtime handoff envelope")
    require_exact_keys(envelope, _ENVELOPE_KEYS, "current-runtime handoff envelope")
    if envelope["schema_version"] != CURRENT_RUNTIME_HANDOFF_VERSION:
        raise ContractValidationError("unsupported current-runtime handoff schema")
    require_sha256(envelope["payload_sha256"], "payload_sha256")
    payload = require_mapping(envelope["payload"], "current-runtime handoff payload")
    payload_bytes = canonical_json_bytes(payload, strict_strings=False)
    if digest_bytes(payload_bytes) != envelope["payload_sha256"]:
        raise ContractValidationError("current-runtime handoff payload digest differs")
    validate_handoff_payload(payload, strict_profile=True, current_runtime=True)
    return HandoffEnvelope(
        deep_freeze_json(payload),
        data,
        str(envelope["payload_sha256"]),
        digest_bytes(data),
        CURRENT_RUNTIME_NON_RELEASE_PROFILE,
        UNCLASSIFIED_TRUST_CLASS,
        CURRENT_RUNTIME_HANDOFF_VERSION,
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
            strict_strings=_uses_strict_string_validation(
                handoff.emission_profile
            ),
        )
        previous_root = self._root_by_tuple.get(tuple_bytes)
        if previous_root is not None and previous_root != handoff.root_sha256:
            raise ContractValidationError("same logical handoff tuple has a different root")
        self._by_root[handoff.root_sha256] = handoff
        self._root_by_tuple[tuple_bytes] = handoff.root_sha256
        return handoff, False
