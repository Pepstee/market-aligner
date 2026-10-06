"""Pure selector for the two approved current-profile recovery inputs."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


_SCHEMA = "market-aligner.private-input-recovery.v1"
_REQUIRED_KINDS = (
    "candidate_profile_and_job_preferences",
    "existing_profile_claims_and_provenance",
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INVALID = "recovered_input_manifest_invalid"


class _InvalidJson(ValueError):
    pass


def _invalid() -> None:
    raise ValueError(_INVALID)


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidJson
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise _InvalidJson


def _valid_relative_path(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    if (
        value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or "\\" in value
        or "\x00" in value
        or ":" in value
    ):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def select_recovered_input_descriptors(
    manifest_bytes: bytes,
    expected_sha256: str,
    expected_approval_id: str,
) -> dict[str, dict[str, object]]:
    """Select exact descriptor metadata; this function never opens a path."""
    if type(manifest_bytes) is not bytes:
        _invalid()
    actual_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if (
        type(expected_sha256) is not str
        or _SHA256.fullmatch(expected_sha256) is None
        or actual_sha256 != expected_sha256
        or type(expected_approval_id) is not str
        or not expected_approval_id
        or expected_approval_id != expected_approval_id.strip()
    ):
        _invalid()
    try:
        document = json.loads(
            manifest_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _InvalidJson, RecursionError):
        _invalid()
    if (
        type(document) is not dict
        or document.get("schema") != _SCHEMA
        or document.get("approval_id") != expected_approval_id
        or type(document.get("files")) is not list
    ):
        _invalid()

    selected: dict[str, dict[str, object]] = {}
    for row in document["files"]:
        if type(row) is not dict:
            _invalid()
        kind = row.get("kind")
        if kind not in _REQUIRED_KINDS:
            continue
        if kind in selected:
            _invalid()
        path = row.get("destination_relative")
        digest = row.get("sha256")
        size = row.get("bytes")
        if (
            not _valid_relative_path(path)
            or type(digest) is not str
            or _SHA256.fullmatch(digest) is None
            or type(size) is not int
            or size <= 0
        ):
            _invalid()
        selected[kind] = {"relative_path": path, "sha256": digest, "bytes": size}

    if set(selected) != set(_REQUIRED_KINDS):
        _invalid()
    if (
        selected[_REQUIRED_KINDS[0]]["relative_path"]
        == selected[_REQUIRED_KINDS[1]]["relative_path"]
    ):
        _invalid()
    return {kind: selected[kind] for kind in _REQUIRED_KINDS}
