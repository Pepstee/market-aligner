"""Canonical JSON and scalar validation for the Market Aligner/JAA v1 seam."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from copy import deepcopy
from collections.abc import Iterator
from datetime import datetime, timezone
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Iterable, Mapping


MAX_WIRE_BYTES = 1024 * 1024
MAX_SAFE_INTEGER = 9007199254740991
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
PROFILE_ID_PATTERN = re.compile(r"^prf_[0-9a-f]{32}$")
JOB_KEY_PATTERN = re.compile(r"^job_[0-9a-f]{64}$")
APPLICATION_ID_PATTERN = re.compile(r"^app_[0-9a-f]{64}$")
EVENT_ID_PATTERN = re.compile(r"^evt_[0-9a-f]{64}$")
_BASE_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_STRICT_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ContractValidationError(ValueError):
    """The exact contract bytes or their decoded value are invalid."""


class FrozenJSONObject(Mapping[str, Any]):
    """A read-only JSON mapping with no inherited dictionary mutation escape."""

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, Any]) -> None:
        object.__setattr__(self, "_values", MappingProxyType(dict(values)))

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("accepted wire values are deeply immutable")

    def __getitem__(self, key: str) -> Any:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __copy__(self) -> "FrozenJSONObject":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[str, Any]:
        del memo
        return deep_thaw_json(self)


def deep_freeze_json(value: Any) -> Any:
    """Copy a decoded JSON tree into immutable objects and tuples."""

    if isinstance(value, Mapping):
        return FrozenJSONObject(
            {str(key): deep_freeze_json(child) for key, child in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(deep_freeze_json(child) for child in value)
    return value


def deep_thaw_json(value: Any) -> Any:
    """Return an independent mutable JSON tree for deliberate local editing."""

    if isinstance(value, Mapping):
        return {str(key): deep_thaw_json(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [deep_thaw_json(child) for child in value]
    return deepcopy(value)


def _reject_constant(value: str) -> Any:
    raise ContractValidationError(f"non-finite JSON number is forbidden: {value}")


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_unicode(value: str, label: str, *, require_nfc: bool) -> str:
    if "\x00" in value:
        raise ContractValidationError(f"{label} must not contain NUL")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ContractValidationError(f"{label} contains an isolated surrogate")
    if require_nfc and unicodedata.normalize("NFC", value) != value:
        raise ContractValidationError(f"{label} must already be NFC-normalised")
    return value


def validate_strings(value: Any, *, require_nfc: bool, label: str = "root") -> None:
    if isinstance(value, str):
        validate_unicode(value, label, require_nfc=require_nfc)
    elif isinstance(value, Mapping):
        for key, child in value.items():
            validate_unicode(str(key), f"{label}.<key>", require_nfc=require_nfc)
            validate_strings(child, require_nfc=require_nfc, label=f"{label}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            validate_strings(child, require_nfc=require_nfc, label=f"{label}[{index}]")


def canonical_json_bytes(value: Any, *, strict_strings: bool = True) -> bytes:
    validate_strings(value, require_nfc=strict_strings)
    try:
        rendered = json.dumps(
            deep_thaw_json(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return rendered.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContractValidationError(f"value cannot be encoded as canonical JSON: {exc}") from exc


def parse_canonical_json(data: bytes, *, maximum_bytes: int = MAX_WIRE_BYTES) -> Any:
    if not isinstance(data, bytes):
        raise TypeError("wire document must be bytes")
    if not data:
        raise ContractValidationError("wire document is empty")
    if len(data) > maximum_bytes:
        raise ContractValidationError(f"wire document exceeds {maximum_bytes} bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise ContractValidationError("UTF-8 BOM is forbidden")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ContractValidationError("wire document is not valid UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_constant,
        )
    except ContractValidationError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ContractValidationError(f"malformed JSON: {exc}") from exc
    validate_strings(value, require_nfc=False)
    if canonical_json_bytes(value, strict_strings=False) != data:
        raise ContractValidationError("wire document is not canonical JSON")
    return value


def digest_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def digest_value(value: Any) -> str:
    return digest_bytes(canonical_json_bytes(value))


def require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractValidationError(f"{label} must be an object")
    return value


def require_exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual = set(value)
    if actual != expected_set:
        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        raise ContractValidationError(f"{label} keys differ; missing={missing}, extra={extra}")


def require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{label} must be a non-empty string")
    return value


def require_string(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise ContractValidationError(f"{label} must be a string")
    return value


def require_boolean(value: Any, label: str, *, nullable: bool = False) -> bool | None:
    if value is None and nullable:
        return None
    if not isinstance(value, bool):
        domain = "true, false, or null" if nullable else "true or false"
        raise ContractValidationError(f"{label} must be {domain}")
    return value


def require_number(
    value: Any,
    label: str,
    *,
    nullable: bool = False,
    minimum: float | None = None,
    maximum: float | None = None,
    require_float: bool = False,
) -> float | int | None:
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractValidationError(f"{label} must be a JSON number")
    if require_float and not isinstance(value, float):
        raise ContractValidationError(f"{label} must be emitted as a JSON float")
    if not math.isfinite(value):
        raise ContractValidationError(f"{label} must be finite")
    if minimum is not None and value < minimum:
        raise ContractValidationError(f"{label} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ContractValidationError(f"{label} must be at most {maximum}")
    if require_float and value == 0.0 and math.copysign(1.0, value) < 0:
        raise ContractValidationError(f"{label} must not be negative zero")
    return value


def require_sha256(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ContractValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ContractValidationError(f"{label} has an invalid format")
    return value


def require_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractValidationError(f"{label} must be a JSON integer")
    if not minimum <= value <= MAX_SAFE_INTEGER:
        raise ContractValidationError(
            f"{label} must be in [{minimum}, {MAX_SAFE_INTEGER}]"
        )
    return value


def require_probability(value: Any, label: str, *, strict_profile: bool) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractValidationError(f"{label} must be a JSON number")
    if not math.isfinite(float(value)) or not 0.0 <= float(value) <= 1.0:
        raise ContractValidationError(f"{label} must be finite and in [0,1]")
    if strict_profile and not isinstance(value, float):
        raise ContractValidationError(f"{label} must be emitted as a JSON float")
    if strict_profile and float(value) == 0.0 and math.copysign(1.0, float(value)) < 0:
        raise ContractValidationError(f"{label} must not be negative zero")
    return value


def require_timestamp(value: Any, label: str, *, strict_profile: bool) -> str:
    if not isinstance(value, str):
        raise ContractValidationError(f"{label} must be a timestamp string")
    pattern = _STRICT_TIMESTAMP_PATTERN if strict_profile else _BASE_TIMESTAMP_PATTERN
    if not pattern.fullmatch(value):
        requirement = "whole-second RFC 3339 UTC" if strict_profile else "RFC 3339 UTC"
        raise ContractValidationError(f"{label} must be {requirement} with literal Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractValidationError(f"{label} is not a real UTC instant") from exc
    if parsed.tzinfo != timezone.utc:
        raise ContractValidationError(f"{label} is not UTC")
    return value


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def require_sorted_unique_strings(
    value: Any,
    label: str,
    *,
    nonempty: bool = True,
    code_values: bool = False,
) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ContractValidationError(f"{label} must be a non-empty array")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ContractValidationError(f"{label} entries must be non-empty strings")
    if code_values and any(not CODE_PATTERN.fullmatch(item) for item in value):
        raise ContractValidationError(f"{label} contains an invalid stable code")
    if value != sorted(set(value)):
        raise ContractValidationError(f"{label} must be sorted and unique")
    return value
