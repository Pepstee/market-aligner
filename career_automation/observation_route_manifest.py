"""Immutable, hash-bound route manifests for JAA-10 observations.

The manifest is authority data, not product configuration.  It must live outside
the repository as canonical, mode-0444 bytes and is identified by an expected
SHA-256 supplied by the authority packet that invokes the loader.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


ROUTE_MANIFEST_SCHEMA = "jaa10.route-manifest.v1"
LEVER_LIST_ROUTE_CLASS = "lever_public_postings_list.v1"
LEVER_API_HOST = "api.lever.co"
REQUIRED_OBSERVATION_UNITS = 10
MINIMUM_FULLY_VERIFIED_UNITS = 8
MINIMUM_DISTINCT_EMPLOYERS = 3
MINIMUM_CANDIDATES = REQUIRED_OBSERVATION_UNITS + 1
REPLACEMENT_RULE = "ordered_first_acceptable_until_required_or_exhausted.v1"
ROOT = Path(__file__).resolve().parents[1]

_MANIFEST_FIELDS = frozenset({
    "schema",
    "route_class",
    "required_observation_units",
    "minimum_fully_verified_units",
    "minimum_distinct_employers_or_boards",
    "maximum_candidate_attempts",
    "replacement_rule",
    "candidates",
})
_CANDIDATE_FIELDS = frozenset({"employer_or_board_id", "url"})
_EMPLOYER_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class RouteManifestError(ValueError):
    """Fail-closed rejection of route-manifest authority data."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RouteManifestError(
                f"ROUTE_MANIFEST_REJECTED: duplicate JSON key {key!r}"
            )
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise RouteManifestError(
        f"ROUTE_MANIFEST_REJECTED: non-finite JSON value {value!r}"
    )


def _validate_route_url(url: object, employer_id: object) -> str:
    if not isinstance(url, str) or not isinstance(employer_id, str):
        raise RouteManifestError(
            "ROUTE_MANIFEST_REJECTED: candidate identity and URL must be strings"
        )
    if _EMPLOYER_ID.fullmatch(employer_id) is None:
        raise RouteManifestError(
            "ROUTE_MANIFEST_REJECTED: employer_or_board_id is not canonical"
        )
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise RouteManifestError(
            "ROUTE_MANIFEST_REJECTED: URL port is malformed"
        ) from exc
    expected_path = f"/v0/postings/{employer_id}"
    expected_url = (
        f"https://{LEVER_API_HOST}{expected_path}"
        "?limit=1&mode=json&skip=0"
    )
    if (
        parsed.scheme != "https"
        or parsed.netloc != LEVER_API_HOST
        or parsed.hostname != LEVER_API_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path != expected_path
        or parsed.query != "limit=1&mode=json&skip=0"
        or parsed.fragment
        or url != expected_url
    ):
        raise RouteManifestError(
            f"ROUTE_MANIFEST_REJECTED: URL is not an exact admitted Lever list route: {url!r}"
        )
    return url


@dataclass(frozen=True, slots=True)
class ObservationRoute:
    """One exact route in authority-defined order."""

    employer_or_board_id: str
    url: str


@dataclass(frozen=True, slots=True)
class ObservationRouteManifest:
    """Frozen route authority loaded from exact external bytes."""

    source_path: Path
    manifest_sha256: str
    route_class: str
    required_observation_units: int
    minimum_fully_verified_units: int
    minimum_distinct_employers_or_boards: int
    maximum_candidate_attempts: int
    replacement_rule: str
    candidates: tuple[ObservationRoute, ...]

    @property
    def allowed_urls(self) -> frozenset[str]:
        return frozenset(candidate.url for candidate in self.candidates)

    def admits(self, url: str, route_class: str) -> bool:
        return route_class == self.route_class and url in self.allowed_urls

    @classmethod
    def load(
        cls,
        source_path: Path,
        *,
        expected_sha256: str,
    ) -> "ObservationRouteManifest":
        if not _is_sha256(expected_sha256):
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: expected_sha256 must be lowercase hex"
            )
        supplied_path = Path(source_path)
        if supplied_path.is_symlink():
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: source must not be a symlink"
            )
        resolved = supplied_path.resolve()
        try:
            resolved.relative_to(ROOT)
        except ValueError:
            pass
        else:
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: source must live outside the product repository"
            )
        if not resolved.is_file() or resolved.is_symlink():
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: source must be one regular file"
            )
        if resolved.stat().st_mode & 0o777 != 0o444:
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: source must be immutable mode 0444"
            )
        try:
            raw = resolved.read_bytes()
        except OSError as exc:
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: source cannot be read"
            ) from exc
        actual_sha256 = hashlib.sha256(raw).hexdigest()
        if actual_sha256 != expected_sha256:
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: source SHA-256 differs from authority"
            )
        if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: source must have exactly one final newline"
            )
        try:
            document = json.loads(
                raw,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: source is not UTF-8 JSON"
            ) from exc
        if not isinstance(document, dict) or raw != _canonical_json(document) + b"\n":
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: source is not canonical JSON"
            )
        if set(document) != _MANIFEST_FIELDS:
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: manifest field set differs"
            )
        if (
            document["schema"] != ROUTE_MANIFEST_SCHEMA
            or document["route_class"] != LEVER_LIST_ROUTE_CLASS
            or type(document["required_observation_units"]) is not int
            or document["required_observation_units"] != REQUIRED_OBSERVATION_UNITS
            or type(document["minimum_fully_verified_units"]) is not int
            or document["minimum_fully_verified_units"] != MINIMUM_FULLY_VERIFIED_UNITS
            or type(document["minimum_distinct_employers_or_boards"]) is not int
            or document["minimum_distinct_employers_or_boards"]
            != MINIMUM_DISTINCT_EMPLOYERS
            or type(document["maximum_candidate_attempts"]) is not int
            or document["replacement_rule"] != REPLACEMENT_RULE
        ):
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: fixed cohort or route contract differs"
            )
        candidates_value = document["candidates"]
        if not isinstance(candidates_value, list):
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: candidates must be an ordered array"
            )
        if len(candidates_value) < MINIMUM_CANDIDATES:
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: candidates are not oversubscribed"
            )
        if document["maximum_candidate_attempts"] != len(candidates_value):
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: maximum attempts must equal candidate count"
            )
        candidates: list[ObservationRoute] = []
        seen_ids: set[str] = set()
        seen_urls: set[str] = set()
        for value in candidates_value:
            if not isinstance(value, dict) or set(value) != _CANDIDATE_FIELDS:
                raise RouteManifestError(
                    "ROUTE_MANIFEST_REJECTED: candidate field set differs"
                )
            employer_id = value["employer_or_board_id"]
            url = _validate_route_url(value["url"], employer_id)
            if employer_id in seen_ids or url in seen_urls:
                raise RouteManifestError(
                    "ROUTE_MANIFEST_REJECTED: duplicate candidate identity or URL"
                )
            seen_ids.add(employer_id)
            seen_urls.add(url)
            candidates.append(ObservationRoute(employer_id, url))
        if len(seen_ids) < MINIMUM_DISTINCT_EMPLOYERS:
            raise RouteManifestError(
                "ROUTE_MANIFEST_REJECTED: insufficient distinct employers or boards"
            )
        return cls(
            source_path=resolved,
            manifest_sha256=actual_sha256,
            route_class=LEVER_LIST_ROUTE_CLASS,
            required_observation_units=REQUIRED_OBSERVATION_UNITS,
            minimum_fully_verified_units=MINIMUM_FULLY_VERIFIED_UNITS,
            minimum_distinct_employers_or_boards=MINIMUM_DISTINCT_EMPLOYERS,
            maximum_candidate_attempts=len(candidates),
            replacement_rule=REPLACEMENT_RULE,
            candidates=tuple(candidates),
        )
