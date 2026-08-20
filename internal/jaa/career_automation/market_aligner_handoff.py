"""Canonical Market Aligner -> JAA handoff v1 codec.

The frozen v1.2 clarification deliberately separates two concerns:

* every byte-canonical form allowed by base v1 remains readable; and
* new producers must emit the stricter NFC/whole-second/float profile.

The parser therefore never rewrites accepted bytes.  It labels a base-compatible
document so admission can preserve it as immutable, release-blocked evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit


HANDOFF_SCHEMA = "market-aligner.jaa-handoff.v1"
CANDIDATE_INTENT_SCHEMA = "market-aligner.candidate-intent.v1"
STRICT_EMISSION_PROFILE = "strict_v1"
COMPATIBILITY_PROFILE = "base_v1_compatibility"
MAX_WIRE_BYTES = 1024 * 1024
MAX_SAFE_INTEGER = 9_007_199_254_740_991

CONTRACT_SHA256 = "b3a60e92d1c227dda57e32c37bf3414a602a3e2c3e8002b06369dd8448a2b197"
CONTRACT_V1_1_SHA256 = "b199257ec426889d537620bcef9f470ab4ca3b08d0f1ff8363fcff0f81b751f3"
REFERENCE_REGISTRY_SHA256 = "23bc7844419915d25e5063ae898d298241542d58fe31dfbe0fb5584d8985e6de"
REFERENCE_REGISTRY_V1_1_SHA256 = "8685c02cd18e33d2a02d30c4005b165a94892924c0edeb80b1238e1f9dbad6df"
CONTRACT_V1_2_SHA256 = "ed869dc90d374b57422a05fe30cd5c805e9c2c4d690006800203d33a79a63d2b"
CONTRACT_V1_3_SHA256 = "e19ced19e1dc626fcdedc4d37e02261368b525375857ed17633b01ca2b4e3fa3"
ACCEPTANCE_MATRIX_SHA256 = "e4598935b732f67d924067892bd228cab2295e564c79cfa7289d7d0d544fc635"
ACCEPTANCE_MATRIX_V1_1_SHA256 = "df69722a8f9d98011f1ff86ab56b34b63fe07b79f41db3aa8cfed5b7ef0b1145"
ACCEPTANCE_MATRIX_V1_2_SHA256 = "ee338ade5f06d2fb018b31e20ed3a8ee8231a2c7a43582516894d2b66913a56d"
ACCEPTANCE_MATRIX_V1_3_SHA256 = "4ffcbd7b144f9fa9776fc9256432ee7538eceb5a64f139a1cb5bbb0461bf874f"

CONTRACT_BUNDLE_SHA256 = (
    CONTRACT_SHA256,
    CONTRACT_V1_1_SHA256,
    REFERENCE_REGISTRY_SHA256,
    CONTRACT_V1_2_SHA256,
    CONTRACT_V1_3_SHA256,
    ACCEPTANCE_MATRIX_SHA256,
    ACCEPTANCE_MATRIX_V1_1_SHA256,
    ACCEPTANCE_MATRIX_V1_2_SHA256,
    ACCEPTANCE_MATRIX_V1_3_SHA256,
    REFERENCE_REGISTRY_V1_1_SHA256,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PROFILE = re.compile(r"^prf_[0-9a-f]{32}$")
_STRICT_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_UTC_COMPAT = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)
_UTC_STRICT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_EU_REMOTE_COUNTRIES = frozenset(
    {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
        "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
        "PL", "PT", "SK", "SI", "ES", "SE",
    }
)


class HandoffContractError(ValueError):
    """Stable, machine-readable handoff validation failure."""

    def __init__(self, code: str, pointer: str, message: str) -> None:
        super().__init__(f"{code} at {pointer}: {message}")
        self.code = code
        self.pointer = pointer
        self.message = message


@dataclass(frozen=True)
class ParsedHandoff:
    original_bytes: bytes
    envelope: dict[str, Any]
    payload: dict[str, Any]
    payload_sha256: str
    root_sha256: str
    emission_profile: str
    strict_profile_violations: tuple[str, ...]

    @property
    def logical_identity_document(self) -> dict[str, str]:
        assessment = self.payload["assessment"]
        eligibility = self.payload["eligibility"]
        selection = self.payload["selection"]
        vacancy = self.payload["vacancy"]
        return {
            "assessment_receipt_sha256": assessment["assessment_receipt_sha256"],
            "candidate_intent_sha256": self.payload["candidate_intent_sha256"],
            "eligibility_receipt_sha256": eligibility["eligibility_receipt_sha256"],
            "job_key": self.payload["job_key"],
            "profile_id": self.payload["profile_id"],
            "profile_version": self.payload["profile_version"],
            "selection_receipt_sha256": selection["selection_receipt_sha256"],
            "vacancy_snapshot_sha256": vacancy["vacancy_snapshot_sha256"],
        }

    @property
    def logical_identity_sha256(self) -> str:
        return canonical_sha256(self.logical_identity_document)

    @property
    def application_id(self) -> str:
        return f"app_{self.logical_identity_sha256}"

    @property
    def vacancy_source_identity(self) -> str:
        return f"market-aligner-handoff:{self.root_sha256}"

    @property
    def strict_profile(self) -> bool:
        return self.emission_profile == STRICT_EMISSION_PROFILE


class _DuplicateKey(ValueError):
    pass


class _InvalidConstant(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole canonical byte representation used by the frozen bundle."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _validate_unicode_scalars(value: object, pointer: str = "$") -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise HandoffContractError(
                "unicode_scalar", pointer, "contains an isolated surrogate"
            )
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_unicode_scalars(item, f"{pointer}/{index}")
        return
    if type(value) is dict:
        for key, item in value.items():
            _validate_unicode_scalars(key, f"{pointer}/<key>")
            _validate_unicode_scalars(item, f"{pointer}/{key}")


def decode_canonical_json(
    raw: bytes,
    *,
    label: str,
    maximum_bytes: int = MAX_WIRE_BYTES,
) -> Any:
    """Decode exact base-v1 canonical bytes without silently normalising them."""

    if type(raw) is not bytes:
        raise HandoffContractError("wire_type", "$", f"{label} must be exact bytes")
    if not raw:
        raise HandoffContractError("wire_empty", "$", f"{label} is empty")
    if len(raw) > maximum_bytes:
        raise HandoffContractError(
            "wire_too_large", "$", f"{label} exceeds {maximum_bytes} bytes"
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise HandoffContractError("wire_bom", "$", f"{label} must not contain a BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HandoffContractError("wire_utf8", "$", f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                _InvalidConstant(constant)
            ),
        )
    except _DuplicateKey as exc:
        raise HandoffContractError(
            "duplicate_key", "$", f"{label} repeats key {exc.args[0]!r}"
        ) from exc
    except _InvalidConstant as exc:
        raise HandoffContractError(
            "nonfinite_number", "$", f"{label} contains {exc.args[0]}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise HandoffContractError(
            "wire_json", "$", f"{label} is malformed JSON at byte {exc.pos}"
        ) from exc
    _validate_unicode_scalars(value)
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise HandoffContractError(
            "wire_value", "$", f"{label} contains an unsupported JSON value"
        ) from exc
    if canonical != raw:
        raise HandoffContractError(
            "noncanonical_bytes", "$", f"{label} is not canonical JSON"
        )
    return value


def _exact(value: object, keys: set[str], pointer: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise HandoffContractError("schema_type", pointer, "must be an object")
    actual = set(value)
    if actual != keys:
        details: list[str] = []
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        if missing:
            details.append(f"missing={missing}")
        if extra:
            details.append(f"unknown={extra}")
        raise HandoffContractError("schema_keys", pointer, ", ".join(details))
    return value


def _text(value: object, pointer: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise HandoffContractError("schema_string", pointer, "must be a string")
    _validate_unicode_scalars(value, pointer)
    if not allow_empty and not value:
        raise HandoffContractError("schema_string", pointer, "must be non-empty")
    return value


def _digest(value: object, pointer: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise HandoffContractError(
            "schema_digest", pointer, "must be a lowercase SHA-256 digest"
        )
    return value


def _timestamp(value: object, pointer: str) -> str:
    text = _text(value, pointer)
    if not _UTC_COMPAT.fullmatch(text):
        raise HandoffContractError(
            "schema_timestamp", pointer, "must be RFC 3339 UTC with a literal Z"
        )
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise HandoffContractError(
            "schema_timestamp", pointer, "is not a real UTC timestamp"
        ) from exc
    if parsed.tzinfo != timezone.utc:
        raise HandoffContractError(
            "schema_timestamp", pointer, "must represent a UTC instant"
        )
    return text


def _number(value: object, pointer: str) -> int | float:
    if isinstance(value, bool) or type(value) not in {int, float}:
        raise HandoffContractError(
            "schema_number", pointer, "must be a JSON number, not a boolean"
        )
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise HandoffContractError("schema_number", pointer, "must be finite in [0,1]")
    return value


def _positive_int(value: object, pointer: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        raise HandoffContractError(
            "schema_integer", pointer, "must be a positive safe JSON integer"
        )
    return value


def _literal_bool(value: object, expected: bool, pointer: str) -> None:
    if type(value) is not bool or value is not expected:
        raise HandoffContractError(
            "schema_boolean", pointer, f"must be {str(expected).lower()}"
        )


def _code(value: object, pointer: str) -> str:
    # Base v1 says only that codes are stable and non-empty.  v1.1 introduced
    # the lexical regex, which v1.2 classifies as a strict emission rule rather
    # than a reason to reject historical byte-canonical v1 input.
    return _text(value, pointer)


def _sorted_codes(value: object, pointer: str) -> tuple[str, ...]:
    if type(value) is not list or not value:
        raise HandoffContractError("schema_list", pointer, "must be non-empty")
    rows = tuple(_code(item, f"{pointer}/{index}") for index, item in enumerate(value))
    if tuple(sorted(set(rows))) != rows:
        raise HandoffContractError(
            "schema_order", pointer, "must be unique and lexicographically sorted"
        )
    return rows


def _component_map(value: object, pointer: str) -> None:
    if type(value) is not dict or not value:
        raise HandoffContractError(
            "schema_components", pointer, "must be a non-empty component object"
        )
    for key, component in value.items():
        _code(key, f"{pointer}/{key}")
        _number(component, f"{pointer}/{key}")


def _validate_location_agreement(location: Mapping[str, Any], bucket: str) -> None:
    expected_mode = {
        "UK_REMOTE": "remote",
        "UK_HYBRID": "hybrid",
        "UK_ONSITE": "onsite",
        "RO_REMOTE": "remote",
        "EU_REMOTE": "remote",
    }[bucket]
    country = str(location["country_code"])
    if location["work_mode"] != expected_mode:
        raise HandoffContractError(
            "location_swap",
            "/payload/vacancy/location/work_mode",
            "does not match the selected geography bucket",
        )
    valid_country = (
        (bucket.startswith("UK_") and country == "GB")
        or (bucket == "RO_REMOTE" and country == "RO")
        or (bucket == "EU_REMOTE" and country in _EU_REMOTE_COUNTRIES)
    )
    if not valid_country:
        raise HandoffContractError(
            "location_swap",
            "/payload/vacancy/location/country_code",
            "does not match the selected geography bucket",
        )


def validate_handoff_payload(payload: object) -> dict[str, Any]:
    """Validate the complete base-v1 payload without applying strict emission rules."""

    body = _exact(
        payload,
        {
            "assessment", "candidate_intent_sha256", "created_at", "eligibility",
            "employer_dossier_sha256", "evidence_ledger_sha256", "job_key",
            "producer", "profile_id", "profile_version", "selection", "vacancy",
        },
        "/payload",
    )
    _digest(body["candidate_intent_sha256"], "/payload/candidate_intent_sha256")
    _timestamp(body["created_at"], "/payload/created_at")
    if body["employer_dossier_sha256"] is not None:
        _digest(body["employer_dossier_sha256"], "/payload/employer_dossier_sha256")
    _digest(body["evidence_ledger_sha256"], "/payload/evidence_ledger_sha256")
    _text(body["job_key"], "/payload/job_key")
    if not isinstance(body["profile_id"], str) or not _PROFILE.fullmatch(body["profile_id"]):
        raise HandoffContractError(
            "schema_profile", "/payload/profile_id", "must be prf_ plus 32 lowercase hex"
        )
    _text(body["profile_version"], "/payload/profile_version")

    producer = _exact(body["producer"], {"commit_sha", "product"}, "/payload/producer")
    if not isinstance(producer["commit_sha"], str) or not _COMMIT.fullmatch(
        producer["commit_sha"]
    ):
        raise HandoffContractError(
            "schema_commit", "/payload/producer/commit_sha", "must be 40 lowercase hex"
        )
    if producer["product"] != "market-aligner":
        raise HandoffContractError(
            "schema_literal", "/payload/producer/product", "must be market-aligner"
        )

    assessment = _exact(
        body["assessment"],
        {
            "assessment_receipt_sha256", "extraction_confidence", "final", "fit",
            "fit_components", "fit_status", "opportunity", "opportunity_components",
            "scoring_parameters_sha256",
        },
        "/payload/assessment",
    )
    _digest(
        assessment["assessment_receipt_sha256"],
        "/payload/assessment/assessment_receipt_sha256",
    )
    for key in ("extraction_confidence", "final", "fit", "opportunity"):
        _number(assessment[key], f"/payload/assessment/{key}")
    _component_map(assessment["fit_components"], "/payload/assessment/fit_components")
    _component_map(
        assessment["opportunity_components"],
        "/payload/assessment/opportunity_components",
    )
    if assessment["fit_status"] != "uncalibrated":
        raise HandoffContractError(
            "schema_literal", "/payload/assessment/fit_status", "must be uncalibrated"
        )
    _digest(
        assessment["scoring_parameters_sha256"],
        "/payload/assessment/scoring_parameters_sha256",
    )

    eligibility = _exact(
        body["eligibility"],
        {"checks", "decision", "eligibility_receipt_sha256", "hard_gate_passed"},
        "/payload/eligibility",
    )
    if eligibility["decision"] != "eligible":
        raise HandoffContractError(
            "eligibility_block", "/payload/eligibility/decision", "must be eligible"
        )
    _literal_bool(
        eligibility["hard_gate_passed"], True, "/payload/eligibility/hard_gate_passed"
    )
    _digest(
        eligibility["eligibility_receipt_sha256"],
        "/payload/eligibility/eligibility_receipt_sha256",
    )
    checks = eligibility["checks"]
    if type(checks) is not list or not checks:
        raise HandoffContractError(
            "schema_list", "/payload/eligibility/checks", "must be non-empty"
        )
    check_codes: list[str] = []
    for index, value in enumerate(checks):
        pointer = f"/payload/eligibility/checks/{index}"
        check = _exact(value, {"code", "evidence_sha256", "outcome"}, pointer)
        check_codes.append(_code(check["code"], f"{pointer}/code"))
        _digest(check["evidence_sha256"], f"{pointer}/evidence_sha256")
        if check["outcome"] not in {"pass", "fail", "unknown"}:
            raise HandoffContractError(
                "schema_literal", f"{pointer}/outcome", "is not an allowed outcome"
            )
        if check["outcome"] != "pass":
            raise HandoffContractError(
                "eligibility_block", f"{pointer}/outcome", "valid handoffs require pass"
            )
    if check_codes != sorted(set(check_codes)):
        raise HandoffContractError(
            "schema_order", "/payload/eligibility/checks", "codes must be unique and sorted"
        )

    selection = _exact(
        body["selection"],
        {
            "decision", "geography_bucket", "geography_priority_rank",
            "hard_gate_passed", "rationale_codes", "selection_policy_sha256",
            "selection_receipt_sha256",
        },
        "/payload/selection",
    )
    if selection["decision"] != "selected_for_application":
        raise HandoffContractError(
            "selection_block",
            "/payload/selection/decision",
            "must be selected_for_application",
        )
    _literal_bool(selection["hard_gate_passed"], True, "/payload/selection/hard_gate_passed")
    bucket_ranks = {
        "UK_REMOTE": 1,
        "UK_HYBRID": 2,
        "UK_ONSITE": 3,
        "RO_REMOTE": 4,
        "EU_REMOTE": 5,
    }
    bucket = selection["geography_bucket"]
    rank = _positive_int(
        selection["geography_priority_rank"],
        "/payload/selection/geography_priority_rank",
    )
    if bucket not in bucket_ranks or bucket_ranks[bucket] != rank:
        raise HandoffContractError(
            "location_swap", "/payload/selection", "geography bucket/rank is invalid"
        )
    _sorted_codes(selection["rationale_codes"], "/payload/selection/rationale_codes")
    _digest(selection["selection_policy_sha256"], "/payload/selection/selection_policy_sha256")
    _digest(selection["selection_receipt_sha256"], "/payload/selection/selection_receipt_sha256")

    vacancy = _exact(
        body["vacancy"],
        {
            "company_name", "location", "provenance", "raw_listing_sha256",
            "requirements_sha256", "role_title", "vacancy_snapshot_sha256",
        },
        "/payload/vacancy",
    )
    _text(vacancy["company_name"], "/payload/vacancy/company_name")
    _text(vacancy["role_title"], "/payload/vacancy/role_title")
    for key in ("raw_listing_sha256", "requirements_sha256", "vacancy_snapshot_sha256"):
        _digest(vacancy[key], f"/payload/vacancy/{key}")
    location = _exact(
        vacancy["location"],
        {"country_code", "facts_sha256", "locality", "raw_text", "region", "work_mode"},
        "/payload/vacancy/location",
    )
    if not isinstance(location["country_code"], str) or not _COUNTRY.fullmatch(
        location["country_code"]
    ):
        raise HandoffContractError(
            "schema_country", "/payload/vacancy/location/country_code", "must be two uppercase letters"
        )
    _digest(location["facts_sha256"], "/payload/vacancy/location/facts_sha256")
    _text(location["locality"], "/payload/vacancy/location/locality", allow_empty=True)
    _text(location["raw_text"], "/payload/vacancy/location/raw_text")
    _text(location["region"], "/payload/vacancy/location/region", allow_empty=True)
    if location["work_mode"] not in {"remote", "hybrid", "onsite", "unknown"}:
        raise HandoffContractError(
            "schema_literal", "/payload/vacancy/location/work_mode", "is unsupported"
        )
    if location["work_mode"] == "unknown":
        raise HandoffContractError(
            "location_swap", "/payload/vacancy/location/work_mode", "selected handoff cannot be unknown"
        )
    _validate_location_agreement(location, str(bucket))

    provenance = _exact(
        vacancy["provenance"],
        {"adapter", "canonical_url", "discovered_at", "fetched_at", "source_job_id"},
        "/payload/vacancy/provenance",
    )
    _text(provenance["adapter"], "/payload/vacancy/provenance/adapter")
    canonical_url = _text(provenance["canonical_url"], "/payload/vacancy/provenance/canonical_url")
    parsed_url = urlsplit(canonical_url)
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.fragment
    ):
        raise HandoffContractError(
            "schema_url", "/payload/vacancy/provenance/canonical_url", "must be an absolute public HTTP(S) URL"
        )
    _timestamp(provenance["discovered_at"], "/payload/vacancy/provenance/discovered_at")
    _timestamp(provenance["fetched_at"], "/payload/vacancy/provenance/fetched_at")
    _text(provenance["source_job_id"], "/payload/vacancy/provenance/source_job_id")

    expected_job_key = "job_" + canonical_sha256(
        {
            "adapter": provenance["adapter"],
            "canonical_url": provenance["canonical_url"],
            "source_job_id": provenance["source_job_id"],
        }
    )
    if body["job_key"] != expected_job_key:
        raise HandoffContractError(
            "job_identity", "/payload/job_key", "does not match vacancy provenance"
        )
    discovered = datetime.fromisoformat(provenance["discovered_at"][:-1] + "+00:00")
    fetched = datetime.fromisoformat(provenance["fetched_at"][:-1] + "+00:00")
    created = datetime.fromisoformat(body["created_at"][:-1] + "+00:00")
    if not discovered <= fetched <= created:
        raise HandoffContractError(
            "timestamp_order",
            "/payload/vacancy/provenance",
            "must satisfy discovered_at <= fetched_at <= handoff.created_at",
        )
    return body


def _strict_profile_violations(payload: Mapping[str, Any]) -> tuple[str, ...]:
    violations: set[str] = set()

    def strings(value: object, pointer: str) -> None:
        if isinstance(value, str):
            if "\x00" in value:
                violations.add(f"nul:{pointer}")
            if unicodedata.normalize("NFC", value) != value:
                violations.add(f"non_nfc:{pointer}")
            if value and value != value.strip():
                violations.add(f"padded_text:{pointer}")
            return
        if type(value) is list:
            for index, item in enumerate(value):
                strings(item, f"{pointer}/{index}")
        elif type(value) is dict:
            for key, item in value.items():
                strings(key, f"{pointer}/<key>")
                strings(item, f"{pointer}/{key}")

    strings(payload, "/payload")
    timestamp_paths = (
        (payload["created_at"], "/payload/created_at"),
        (payload["vacancy"]["provenance"]["discovered_at"], "/payload/vacancy/provenance/discovered_at"),
        (payload["vacancy"]["provenance"]["fetched_at"], "/payload/vacancy/provenance/fetched_at"),
    )
    for value, pointer in timestamp_paths:
        if not _UTC_STRICT.fullmatch(value):
            violations.add(f"fractional_timestamp:{pointer}")

    assessment = payload["assessment"]
    number_paths: list[tuple[object, str]] = [
        (assessment[key], f"/payload/assessment/{key}")
        for key in ("extraction_confidence", "final", "fit", "opportunity")
    ]
    for map_name in ("fit_components", "opportunity_components"):
        number_paths.extend(
            (value, f"/payload/assessment/{map_name}/{key}")
            for key, value in assessment[map_name].items()
        )
    for value, pointer in number_paths:
        if type(value) is not float:
            violations.add(f"integer_score:{pointer}")
        elif value == 0.0 and math.copysign(1.0, value) < 0:
            violations.add(f"negative_zero:{pointer}")

    code_paths: list[tuple[object, str]] = []
    for map_name in ("fit_components", "opportunity_components"):
        code_paths.extend(
            (key, f"/payload/assessment/{map_name}/{key}")
            for key in assessment[map_name]
        )
    code_paths.extend(
        (check["code"], f"/payload/eligibility/checks/{index}/code")
        for index, check in enumerate(payload["eligibility"]["checks"])
    )
    code_paths.extend(
        (code, f"/payload/selection/rationale_codes/{index}")
        for index, code in enumerate(payload["selection"]["rationale_codes"])
    )
    for value, pointer in code_paths:
        if not _STRICT_CODE.fullmatch(value):
            violations.add(f"unstable_code:{pointer}")
    return tuple(sorted(violations))


def parse_handoff(raw: bytes, *, require_strict_profile: bool = False) -> ParsedHandoff:
    envelope = _exact(
        decode_canonical_json(raw, label="handoff envelope"),
        {"payload", "payload_sha256", "schema_version"},
        "$",
    )
    if envelope["schema_version"] != HANDOFF_SCHEMA:
        raise HandoffContractError(
            "unknown_version", "/schema_version", f"must be {HANDOFF_SCHEMA}"
        )
    supplied_payload_hash = _digest(envelope["payload_sha256"], "/payload_sha256")
    payload = validate_handoff_payload(envelope["payload"])
    actual_payload_hash = canonical_sha256(payload)
    if supplied_payload_hash != actual_payload_hash:
        raise HandoffContractError(
            "payload_digest_mismatch", "/payload_sha256", "does not match payload bytes"
        )
    violations = _strict_profile_violations(payload)
    profile = STRICT_EMISSION_PROFILE if not violations else COMPATIBILITY_PROFILE
    if require_strict_profile and violations:
        raise HandoffContractError(
            "strict_profile_required",
            "$",
            "new-producer input violates the strict profile: " + ", ".join(violations),
        )
    return ParsedHandoff(
        original_bytes=raw,
        envelope=envelope,
        payload=payload,
        payload_sha256=actual_payload_hash,
        root_sha256=hashlib.sha256(raw).hexdigest(),
        emission_profile=profile,
        strict_profile_violations=violations,
    )


__all__ = [
    "ACCEPTANCE_MATRIX_SHA256",
    "ACCEPTANCE_MATRIX_V1_1_SHA256",
    "ACCEPTANCE_MATRIX_V1_2_SHA256",
    "ACCEPTANCE_MATRIX_V1_3_SHA256",
    "CANDIDATE_INTENT_SCHEMA",
    "COMPATIBILITY_PROFILE",
    "CONTRACT_BUNDLE_SHA256",
    "CONTRACT_SHA256",
    "CONTRACT_V1_1_SHA256",
    "CONTRACT_V1_2_SHA256",
    "CONTRACT_V1_3_SHA256",
    "HANDOFF_SCHEMA",
    "HandoffContractError",
    "MAX_WIRE_BYTES",
    "ParsedHandoff",
    "REFERENCE_REGISTRY_SHA256",
    "REFERENCE_REGISTRY_V1_1_SHA256",
    "STRICT_EMISSION_PROFILE",
    "canonical_json_bytes",
    "canonical_sha256",
    "decode_canonical_json",
    "parse_handoff",
    "validate_handoff_payload",
]
