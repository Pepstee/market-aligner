"""Structural separation of public listing bytes from transport diagnostics."""

from __future__ import annotations

import base64
import html
import ipaddress
import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, unquote, urlsplit

from market_aligner.applications.canonical import (
    ContractValidationError,
    canonical_json_bytes,
    deep_thaw_json,
    digest_bytes,
)
from market_aligner.domain.contracts import RawPosting


_FORBIDDEN_KEYS = frozenset(
    {
        "authorization",
        "proxyauthorization",
        "cookie",
        "setcookie",
        "cookies",
        "cookiejar",
        "requestcookies",
        "responsecookies",
        "headers",
        "requestheaders",
        "responseheaders",
        "history",
        "redirect",
        "redirects",
        "redirectchain",
        "redirecthistory",
        "capturedxhr",
        "xhr",
        "xhrrequests",
        "xhrresponses",
        "browsermeta",
        "browsermetadata",
        "transportmeta",
        "transportmetadata",
        "credentials",
        "collector",
        "scrapling",
        "error",
        "errors",
        "exception",
        "stacktrace",
        "traceback",
    }
)
_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "clientsecret",
        "cookie",
        "credential",
        "password",
        "secret",
        "signature",
        "token",
        "xamzcredential",
        "xamzsecuritytoken",
        "xamzsignature",
    }
)
_FETCH_ENGINES = frozenset({"dynamic", "static", "stealth"})
_SAFE_FETCH_ERROR_CODES = frozenset(
    {"fetch_error", "invalid_worker_response", "worker_error", "worker_timeout"}
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SECRET_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{12,}",
        r"\b(?:api[_-]?key|password|secret|token)\s*[=:]\s*[^\s,;]{8,}",
        r"\b(?:set[-_ ]?)?cookie\s*[=:]\s*[^\s,;]{8,}",
        r"-----begin [a-z ]+private key-----",
    )
)
_TRANSPORT_MARKER_PATTERNS = tuple(
    re.compile(rf"(?im)(?:^|[\s,;{{]){marker}\s*[:=]")
    for marker in (
        "browser_metadata",
        "captured_xhr",
        "redirect_history",
        "request_headers",
        "response_headers",
        "transport_metadata",
    )
)
_ABSOLUTE_URL = re.compile(
    r"(?i)(?<![a-z0-9+.-])(?=([a-z][a-z0-9+.-]*://[^\s\"'<>]+))"
)
_PROTOCOL_RELATIVE_URL = re.compile(
    r"(?i)(?<![:/])(?=(//[^\s\"'<>]+))"
)
_UNICODE_ASCII_ESCAPE = re.compile(r"\\+u([0-9a-f]{4})", re.IGNORECASE)
_HEX_ASCII_ESCAPE = re.compile(r"\\+x([0-9a-f]{2})", re.IGNORECASE)
_ESCAPED_SLASH = re.compile(r"\\+/")
_HTTP_BACKSLASH_AUTHORITY = re.compile(r"(?i)\b(https?):[\\/]+")
_BACKSLASH_PROTOCOL_RELATIVE_AUTHORITY = re.compile(
    r"(?ix)"
    r"(?<![a-z0-9+.:/\\-])"
    r"[\\/]{2,}"
    r"(?="
    r"(?:[^\\/\s\"'<>@]+@[^\\/\s\"'<>]+)"
    r"|(?:localhost(?:[.:/\\]|$))"
    r"|(?:(?:[a-z0-9-]+\.)+[a-z0-9-]+(?:[.:/\\]|$))"
    r"|(?:(?:\d{1,3}\.){3}\d{1,3}(?:[.:/\\]|$))"
    r"|(?:\[[0-9a-f:.]+\](?:[:/\\]|$))"
    r")"
)
_URL_IGNORED_CONTROLS = str.maketrans({"\t": None, "\r": None, "\n": None})
_URL_PARAMETER = re.compile(r"(?i)(?:^|[?&#;/])([^?&#;/=:\s]+)\s*[=:]")
_MAX_URL_DECODE_LAYERS = 32


def _normal_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _decode_ascii_escape(match: re.Match[str]) -> str:
    value = int(match.group(1), 16)
    return chr(value) if 0 <= value <= 0x7F else match.group(0)


def _decode_url_scan_layer(value: str) -> str:
    decoded = html.unescape(value)
    decoded = _UNICODE_ASCII_ESCAPE.sub(_decode_ascii_escape, decoded)
    decoded = _HEX_ASCII_ESCAPE.sub(_decode_ascii_escape, decoded)
    decoded = _BACKSLASH_PROTOCOL_RELATIVE_AUTHORITY.sub("//", decoded)
    decoded = _ESCAPED_SLASH.sub("/", decoded)
    decoded = unquote(decoded)
    decoded = decoded.translate(_URL_IGNORED_CONTROLS)
    decoded = _HTTP_BACKSLASH_AUTHORITY.sub(
        lambda match: f"{match.group(1)}://", decoded
    )
    return _BACKSLASH_PROTOCOL_RELATIVE_AUTHORITY.sub("//", decoded)


def _url_scan_variants(value: str) -> tuple[str, ...]:
    """Expose common text/HTML/JSON/percent encodings before URL validation."""

    variants: list[str] = []
    current = value
    for _ in range(_MAX_URL_DECODE_LAYERS):
        if current not in variants:
            variants.append(current)
        decoded = _decode_url_scan_layer(current)
        if decoded == current:
            return tuple(variants)
        current = decoded
    if current not in variants:
        variants.append(current)
    probe = _decode_url_scan_layer(current)
    if probe != current:
        raise ContractValidationError("public listing URL encoding exceeds scan bounds")
    return tuple(variants)


def _scan_embedded_urls(value: str) -> None:
    for variant in _url_scan_variants(value):
        for match in _ABSOLUTE_URL.finditer(variant):
            _validate_url_candidate(match.group(1).rstrip(".,);}"))
        for match in _PROTOCOL_RELATIVE_URL.finditer(variant):
            _validate_url_candidate(f"https:{match.group(1).rstrip('.,);}')}")


def _scan_public_value(value: Any, *, protected_roots: tuple[str, ...], path: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normal_key = _normal_key(key) if isinstance(key, str) else ""
            if (
                not isinstance(key, str)
                or normal_key in _FORBIDDEN_KEYS
                or normal_key in _SENSITIVE_QUERY_KEYS
            ):
                raise ContractValidationError(f"public listing contains forbidden transport key at {path}")
            _scan_public_value(child, protected_roots=protected_roots, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _scan_public_value(child, protected_roots=protected_roots, path=f"{path}[{index}]")
    elif isinstance(value, str):
        if any(root and root in value for root in protected_roots):
            raise ContractValidationError("public listing contains a protected local path")
        if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
            raise ContractValidationError("public listing contains credential-shaped transport data")
        if any(pattern.search(value) for pattern in _TRANSPORT_MARKER_PATTERNS):
            raise ContractValidationError(
                "public listing contains plaintext transport diagnostics"
            )
        _scan_embedded_urls(value)


def _validate_url_candidate(url: str) -> None:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
        raise ContractValidationError("public listing URL contains a control character")
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        # Accessing port performs urllib's syntax and range validation.
        parts.port
    except (TypeError, ValueError) as exc:
        raise ContractValidationError("public listing URL is malformed") from exc
    if (
        parts.scheme.casefold() != "https"
        or not parts.netloc
        or not hostname
        or parts.username is not None
        or parts.password is not None
        or "@" in parts.netloc
    ):
        raise ContractValidationError("public listing URL must be credential-free HTTPS")
    hostname_text = hostname.rstrip(".").casefold()
    if hostname_text == "localhost" or hostname_text.endswith(".localhost"):
        raise ContractValidationError("public listing URL host must be public")
    try:
        address = ipaddress.ip_address(hostname_text)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ContractValidationError("public listing URL host must be public")
    parameters = (
        *parse_qsl(parts.query, keep_blank_values=True),
        *parse_qsl(parts.fragment.replace("?", "&"), keep_blank_values=True),
    )
    if any(_normal_key(key) in _SENSITIVE_QUERY_KEYS for key, _ in parameters):
        raise ContractValidationError("public listing URL contains a sensitive query parameter")
    for component in (parts.path, parts.query, parts.fragment):
        if any(
            _normal_key(match.group(1)) in _SENSITIVE_QUERY_KEYS
            for match in _URL_PARAMETER.finditer(component)
        ):
            raise ContractValidationError(
                "public listing URL contains a sensitive parameter"
            )
    if any(pattern.search(url) for pattern in _SECRET_PATTERNS):
        raise ContractValidationError("public listing URL contains credential-shaped data")


def _validate_public_url(url: str) -> None:
    if not isinstance(url, str):
        raise ContractValidationError("public listing URL must be a string")
    if any(character.isspace() for character in url):
        raise ContractValidationError("public listing URL contains literal whitespace")
    for variant in _url_scan_variants(url):
        _validate_url_candidate(variant)
    # A safe outer URL must not conceal a nested or encoded unsafe URL in its
    # path, query, or fragment. Look-ahead scanning intentionally overlaps.
    _scan_embedded_urls(url)


def validate_public_listing_url(url: str) -> None:
    """Reject transport credentials before a discovered URL reaches state."""

    _validate_public_url(url)


def _protected_roots(values: tuple[str | Path, ...]) -> tuple[str, ...]:
    return tuple(str(Path(value).resolve()) for value in values)


def _decode_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise ContractValidationError(f"{label} must be base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ContractValidationError(f"{label} is invalid") from exc


def _scan_public_bytes(
    exact: bytes, *, protected_roots: tuple[str, ...], path: str
) -> None:
    if not exact:
        raise ContractValidationError("public listing exact bytes are empty")
    text = exact.decode("utf-8", errors="replace")
    _scan_public_value(
        text,
        protected_roots=protected_roots,
        path=path,
    )
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        return
    _scan_public_value(decoded, protected_roots=protected_roots, path=f"{path}.json")


def public_listing_bytes(
    row: RawPosting, *, protected_roots: tuple[str | Path, ...] = ()
) -> bytes:
    roots = _protected_roots(protected_roots)
    _validate_public_url(row.url)
    _scan_public_value(row.raw_text, protected_roots=roots, path="raw_text")
    _scan_public_value(row.raw_json, protected_roots=roots, path="raw_json")
    if row.public_content_base64 is not None:
        exact = _decode_base64(row.public_content_base64, "public_content_base64")
        _scan_public_bytes(exact, protected_roots=roots, path="public_content")
        return exact
    value = {
        "content_type": row.content_type,
        "raw_json": deep_thaw_json(row.raw_json),
        "raw_text": row.raw_text,
        "schema_version": "market-aligner.public-listing-capture.v1",
    }
    exact = canonical_json_bytes(value)
    if not row.raw_text and row.raw_json is None:
        raise ContractValidationError("public listing capture has no content")
    return exact


def bind_public_listing(
    row: RawPosting, *, protected_roots: tuple[str | Path, ...] = ()
) -> tuple[RawPosting, bytes]:
    exact = public_listing_bytes(row, protected_roots=protected_roots)
    digest = digest_bytes(exact)
    if row.content_sha256 is not None and row.content_sha256 != digest:
        raise ContractValidationError("raw posting content digest differs from exact public bytes")
    return replace(row, content_sha256=digest), exact


def validate_handoff_listing_evidence(
    value: Mapping[str, Any], *, protected_roots: tuple[str | Path, ...] = ()
) -> bytes:
    """Validate the public raw-listing object immediately before handoff.

    The handoff contract performs its own structural validation. This collector
    boundary check is intentionally concerned only with transport-data
    separation and the identity of the exact public bytes.
    """

    if not isinstance(value, Mapping):
        raise ContractValidationError("raw listing evidence must be an object")
    expected_keys = {
        "adapter",
        "canonical_url",
        "content_base64",
        "content_sha256",
        "fetched_at",
        "job_key",
        "schema_version",
        "source_job_id",
    }
    if set(value) != expected_keys:
        raise ContractValidationError("raw listing evidence fields do not match its schema")
    roots = _protected_roots(protected_roots)
    if value.get("schema_version") != "market-aligner.raw-listing-evidence.v1":
        raise ContractValidationError("raw listing evidence has the wrong schema")
    _scan_public_value(value, protected_roots=roots, path="raw_listing_evidence")
    _validate_public_url(value.get("canonical_url"))
    exact = _decode_base64(value.get("content_base64"), "raw listing content_base64")
    _scan_public_bytes(exact, protected_roots=roots, path="raw_listing_evidence.content")
    digest = value.get("content_sha256")
    if not isinstance(digest, str) or digest != digest_bytes(exact):
        raise ContractValidationError("raw listing evidence digest differs from exact bytes")
    return exact


def sanitized_worker_response(
    response: Mapping[str, Any], *, protected_roots: tuple[str | Path, ...] = ()
) -> dict[str, Any]:
    """Reconstruct the fetch result from the public byte allowlist only."""

    if not isinstance(response, Mapping):
        raise ContractValidationError("worker fetch response must be an object")
    body = _decode_base64(response.get("body_base64"), "worker response body_base64")
    _scan_public_bytes(
        body,
        protected_roots=_protected_roots(protected_roots),
        path="worker_response.body",
    )
    declared_size = response.get("body_bytes")
    if isinstance(declared_size, bool) or not isinstance(declared_size, int):
        raise ContractValidationError("worker response body_bytes must be an integer")
    if declared_size != len(body):
        raise ContractValidationError("worker response body length differs from exact bytes")
    status = response.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        raise ContractValidationError("worker response status must be an HTTP status integer")
    encoding = response.get("encoding")
    if not isinstance(encoding, str) or not encoding:
        raise ContractValidationError("worker response encoding must be non-empty text")
    try:
        text = body.decode(encoding, errors="replace")
    except LookupError as exc:
        raise ContractValidationError("worker response encoding is unknown") from exc
    return {
        "status": status,
        "encoding": encoding,
        "body_bytes": len(body),
        "body_base64": base64.b64encode(body).decode("ascii"),
        "text": text,
    }


def sanitized_fetch_engine(value: Any) -> str:
    if not isinstance(value, str):
        raise ContractValidationError("fetch engine must be text")
    engine = value.casefold()
    if engine == "stealthy":
        engine = "stealth"
    if engine not in _FETCH_ENGINES:
        raise ContractValidationError("fetch engine is unsupported")
    return engine


def sanitized_transport_receipt(
    response: Mapping[str, Any], *, engine: str, outcome: str = "succeeded"
) -> dict[str, Any]:
    safe_response = sanitized_worker_response(response)
    body = base64.b64decode(safe_response["body_base64"], validate=True)
    if outcome != "succeeded":
        raise ContractValidationError("successful transport receipt has an invalid outcome")
    return {
        "body_bytes": len(body),
        "content_sha256": digest_bytes(body),
        "engine": sanitized_fetch_engine(engine),
        "outcome": outcome,
        "schema_version": "market-aligner.sanitized-fetch-receipt.v1",
        "status": safe_response["status"],
    }


def sanitized_attempts(
    attempts: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Apply a second allowlist before transport receipts reach disk."""

    rows: list[dict[str, Any]] = []
    for attempt in attempts:
        if not isinstance(attempt, Mapping) or not isinstance(attempt.get("ok"), bool):
            raise ContractValidationError("fetch attempt must be an object with boolean ok")
        engine = sanitized_fetch_engine(attempt.get("engine"))
        if attempt["ok"]:
            body_bytes = attempt.get("body_bytes")
            status = attempt.get("status")
            digest = attempt.get("content_sha256")
            if (
                isinstance(body_bytes, bool)
                or not isinstance(body_bytes, int)
                or body_bytes < 0
                or isinstance(status, bool)
                or not isinstance(status, int)
                or not 100 <= status <= 599
                or not isinstance(digest, str)
                or _SHA256_PATTERN.fullmatch(digest) is None
                or attempt.get("outcome") != "succeeded"
                or attempt.get("schema_version")
                != "market-aligner.sanitized-fetch-receipt.v1"
            ):
                raise ContractValidationError("successful fetch attempt is malformed")
            rows.append(
                {
                    "body_bytes": body_bytes,
                    "content_sha256": digest,
                    "engine": engine,
                    "ok": True,
                    "outcome": "succeeded",
                    "schema_version": "market-aligner.sanitized-fetch-receipt.v1",
                    "status": status,
                }
            )
            continue
        error_code = attempt.get("error_code")
        if error_code not in _SAFE_FETCH_ERROR_CODES:
            error_code = "fetch_error"
        rows.append({"engine": engine, "error_code": error_code, "ok": False})
    return tuple(rows)
