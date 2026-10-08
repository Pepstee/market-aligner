"""Strict parser for Greenhouse public job-post loader configuration."""

from __future__ import annotations

import hashlib
import json
import math
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

__all__ = ["LoaderContractError", "parse_current_greenhouse_loader"]


class LoaderContractError(ValueError):
    """Raised when a response or loader configuration violates the contract."""


_REMIX_ASSIGNMENT_RE = re.compile(
    r"\A\s*window\.__remixContext\s*=\s*(\{.*\})\s*;?\s*\Z", re.DOTALL
)
_REMIX_ASSIGNMENT_MARKER_RE = re.compile(r"\bwindow\s*\.\s*__remixContext\s*=")
_ROUTE_KEY = "routes/$url_token_.jobs_.$job_post_id"
_JOB_PATH_RE = re.compile(r"\A/([A-Za-z0-9_-]+)/jobs/([0-9]+)/?\Z")
_EU_HOSTS = frozenset({"boards.eu.greenhouse.io", "job-boards.eu.greenhouse.io"})
_US_HOSTS = frozenset({"boards.greenhouse.io", "job-boards.greenhouse.io"})
_ALLOWED_SOURCE_HOSTS = _EU_HOSTS | _US_HOSTS


class _ScriptCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.inline_scripts: list[str] = []
        self.external_script_seen = False
        self.in_script = False
        self._script_is_inline = False
        self._chunks: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag == "script":
            if self.in_script:
                raise LoaderContractError("nested script element")
            self.in_script = True
            self._script_is_inline = not any(name == "src" for name, _ in attrs)
            if not self._script_is_inline:
                self.external_script_seen = True
            self._chunks = []

    def handle_startendtag(self, tag, attrs) -> None:
        if tag == "script" and any(name == "src" for name, _ in attrs):
            self.external_script_seen = True

    def handle_endtag(self, tag) -> None:
        if tag == "script":
            if not self.in_script:
                raise LoaderContractError("unmatched script close tag")
            self.in_script = False
            if self._script_is_inline:
                self.inline_scripts.append("".join(self._chunks))
            self._chunks = []

    def handle_data(self, data) -> None:
        if self.in_script:
            self._chunks.append(data)


class _VisibleTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self.skip_depth = 0
        self.unbalanced_skip = False

    def handle_starttag(self, tag, attrs) -> None:
        if tag in {"script", "style"}:
            self.skip_depth += 1

    def handle_endtag(self, tag) -> None:
        if tag in {"script", "style"}:
            if self.skip_depth:
                self.skip_depth -= 1
            else:
                self.unbalanced_skip = True

    def handle_data(self, data) -> None:
        if not self.skip_depth:
            self.chunks.append(data)


def _extract_remix_json(html_text: str) -> str:
    parser = _ScriptCollector()
    try:
        parser.feed(html_text)
        parser.close()
    except LoaderContractError:
        raise
    except Exception as exc:
        raise LoaderContractError("malformed HTML") from exc
    if parser.in_script:
        raise LoaderContractError("truncated script element")
    if parser.external_script_seen:
        raise LoaderContractError("external script source present")
    candidates: list[str] = []
    for script in parser.inline_scripts:
        if not _REMIX_ASSIGNMENT_MARKER_RE.search(script):
            continue
        match = _REMIX_ASSIGNMENT_RE.fullmatch(script)
        if match is None:
            raise LoaderContractError("Remix assignment is not one JSON literal")
        candidates.append(match.group(1))
    if len(candidates) != 1:
        raise LoaderContractError("Remix assignment is missing or ambiguous")
    return candidates[0]


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LoaderContractError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(name):
    raise LoaderContractError("nonfinite JSON constant")


def _parse_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise LoaderContractError("nonfinite JSON number")
    return value


def _assert_no_surrogates(node) -> None:
    if isinstance(node, str):
        if any("\ud800" <= character <= "\udfff" for character in node):
            raise LoaderContractError("unpaired surrogate in JSON string")
    elif isinstance(node, list):
        for item in node:
            _assert_no_surrogates(item)
    elif isinstance(node, dict):
        for key, value in node.items():
            _assert_no_surrogates(key)
            _assert_no_surrogates(value)


def _load_strict_json(text: str):
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
    except LoaderContractError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise LoaderContractError("invalid loader JSON") from exc
    _assert_no_surrogates(value)
    return value


def _reject_unsafe_url_chars(value: str) -> None:
    if "\\" in value or "%" in value or any(
        ord(character) < 0x20 or ord(character) == 0x7f for character in value
    ):
        raise LoaderContractError("URL contains unsafe characters")


def _split_canonical_url(value: str, allowed_hosts: frozenset[str]):
    if type(value) is not str or not value:
        raise LoaderContractError("URL must be a nonempty string")
    _reject_unsafe_url_chars(value)
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise LoaderContractError("URL is malformed") from exc
    host = parts.hostname
    if (
        parts.scheme != "https"
        or host is None
        or host not in allowed_hosts
        or parts.netloc != host
        or parts.username is not None
        or parts.password is not None
        or port is not None
        or parts.query
        or parts.fragment
    ):
        raise LoaderContractError("URL is not canonical Greenhouse HTTPS")
    match = _JOB_PATH_RE.fullmatch(parts.path)
    if match is None:
        raise LoaderContractError("URL is not an exact Greenhouse job route")
    return host, match.group(1), match.group(2), parts.path


def _validate_confirmation_path(
    value: str, source_url: str, source_host: str, board: str, job_id: str
) -> str:
    if type(value) is not str or not value:
        raise LoaderContractError("confirmationPath must be a nonempty string")
    _reject_unsafe_url_chars(value)
    if value.startswith("//"):
        raise LoaderContractError("protocol-relative confirmationPath is forbidden")
    expected_path = f"/{board}/jobs/{job_id}/confirmation"
    try:
        raw = urlsplit(value)
        if raw.scheme or raw.netloc:
            if (
                raw.scheme != "https"
                or raw.hostname != source_host
                or raw.netloc != source_host
                or raw.username is not None
                or raw.password is not None
                or raw.port is not None
                or raw.query
                or raw.fragment
                or raw.path.rstrip("/") != expected_path
            ):
                raise LoaderContractError("confirmationPath is not the exact route")
        else:
            if (
                raw.query
                or raw.fragment
                or raw.path.rstrip("/") != expected_path
            ):
                raise LoaderContractError("confirmationPath is not the exact route")
    except ValueError as exc:
        if isinstance(exc, LoaderContractError):
            raise
        raise LoaderContractError("confirmationPath is malformed") from exc
    resolved = urljoin(source_url, value)
    parts = urlsplit(resolved)
    if (
        parts.scheme != "https"
        or parts.hostname != source_host
        or parts.netloc != source_host
        or parts.username is not None
        or parts.password is not None
        or parts.port is not None
        or parts.query
        or parts.fragment
        or parts.path.rstrip("/") != expected_path
    ):
        raise LoaderContractError("resolved confirmationPath differs from source")
    return resolved


def _visible_text_marker(markup: str) -> str:
    extractor = _VisibleTextExtractor()
    try:
        extractor.feed(markup)
        extractor.close()
    except Exception as exc:
        raise LoaderContractError("confirmation message is malformed") from exc
    if extractor.skip_depth or extractor.unbalanced_skip:
        raise LoaderContractError("confirmation message has unsafe parser state")
    marker = " ".join(" ".join(extractor.chunks).split())
    if not marker:
        raise LoaderContractError("confirmation message has no visible text")
    return marker


def _require_mapping(value, name: str) -> dict:
    if type(value) is not dict:
        raise LoaderContractError(f"{name} must be an object")
    return value


def _require_string(mapping: dict, key: str, name: str) -> str:
    value = mapping.get(key)
    if type(value) is not str or not value:
        raise LoaderContractError(f"{name}.{key} must be a nonempty string")
    return value


def parse_current_greenhouse_loader(
    primary_response: bytes, *, source_url: str
) -> dict[str, object]:
    if type(primary_response) is not bytes:
        raise LoaderContractError("primary_response must be bytes")
    if type(source_url) is not str:
        raise LoaderContractError("source_url must be a string")
    source_host, board, job_id, source_path = _split_canonical_url(
        source_url, _ALLOWED_SOURCE_HOSTS
    )
    region_hosts = _EU_HOSTS if source_host in _EU_HOSTS else _US_HOSTS
    try:
        html_text = primary_response.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise LoaderContractError("primary_response is not strict UTF-8") from exc
    if html_text.startswith("\ufeff"):
        raise LoaderContractError("byte order mark in primary_response")
    root = _require_mapping(
        _load_strict_json(_extract_remix_json(html_text)), "Remix root"
    )
    state = _require_mapping(root.get("state"), "state")
    loader_data = _require_mapping(state.get("loaderData"), "state.loaderData")
    route = _require_mapping(
        loader_data.get(_ROUTE_KEY), f"state.loaderData[{_ROUTE_KEY!r}]"
    )
    job_post_id = _require_string(route, "jobPostId", "route")
    token = _require_string(route, "urlToken", "route")
    if not token:
        raise LoaderContractError("route.urlToken is empty")
    job_post = _require_mapping(route.get("jobPost"), "route.jobPost")
    public_url = _require_string(job_post, "public_url", "jobPost")
    message = _require_string(job_post, "confirmation_message", "jobPost")
    submit_path = _require_string(route, "submitPath", "route")
    confirmation_path = _require_string(route, "confirmationPath", "route")
    if job_post_id != job_id:
        raise LoaderContractError("jobPostId differs from source URL")
    public_host, public_board, public_job, public_path = _split_canonical_url(
        public_url, region_hosts
    )
    if (
        (public_host, public_board, public_job) != (source_host, board, job_id)
        or public_path.rstrip("/") != source_path.rstrip("/")
    ):
        raise LoaderContractError("jobPost.public_url differs from exact source URL")
    submit_host, submit_board, submit_job, _ = _split_canonical_url(
        submit_path, region_hosts
    )
    if submit_host not in region_hosts or (submit_board, submit_job) != (board, job_id):
        raise LoaderContractError("submitPath differs from source region or job")
    confirmation_url = _validate_confirmation_path(
        confirmation_path, source_url, source_host, board, job_id
    )
    marker = _visible_text_marker(message)
    return {
        "source_url": source_url,
        "job_post_id": job_post_id,
        "primary_response_sha256": hashlib.sha256(primary_response).hexdigest(),
        "confirmationPath": confirmation_path,
        "submitPath": submit_path,
        "confirmation_message": message,
        "confirmation_url": confirmation_url,
        "required_visible_markers": (marker,),
    }
