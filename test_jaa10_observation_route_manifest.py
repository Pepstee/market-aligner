"""Positive controls for the immutable JAA-10 route manifest."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from career_automation.observation_route_manifest import (
    LEVER_LIST_ROUTE_CLASS,
    REPLACEMENT_RULE,
    ROUTE_MANIFEST_SCHEMA,
    ObservationRouteManifest,
)


EMPLOYERS = (
    "jobgether",
    "palantir",
    "spotify",
    "octoenergy",
    "electric-twin",
    "firstup",
    "moneyboxapp",
    "starcompliance",
    "kitmanlabs",
    "binance",
    "gearset",
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _document(employers: tuple[str, ...] = EMPLOYERS) -> dict[str, object]:
    return {
        "schema": ROUTE_MANIFEST_SCHEMA,
        "route_class": LEVER_LIST_ROUTE_CLASS,
        "required_observation_units": 10,
        "minimum_fully_verified_units": 8,
        "minimum_distinct_employers_or_boards": 3,
        "maximum_candidate_attempts": len(employers),
        "replacement_rule": REPLACEMENT_RULE,
        "candidates": [
            {
                "employer_or_board_id": employer,
                "url": (
                    f"https://api.lever.co/v0/postings/{employer}"
                    "?limit=1&mode=json&skip=0"
                ),
            }
            for employer in employers
        ],
    }


def _write_manifest(path: Path, document: object | None = None) -> str:
    raw = _canonical(_document() if document is None else document) + b"\n"
    path.write_bytes(raw)
    path.chmod(0o444)
    return hashlib.sha256(raw).hexdigest()


def test_load_retains_exact_external_identity_and_order(tmp_path: Path) -> None:
    path = tmp_path / "routes.json"
    digest = _write_manifest(path)

    manifest = ObservationRouteManifest.load(path, expected_sha256=digest)

    assert manifest.source_path == path.resolve()
    assert manifest.manifest_sha256 == digest
    assert manifest.route_class == LEVER_LIST_ROUTE_CLASS
    assert manifest.required_observation_units == 10
    assert manifest.minimum_fully_verified_units == 8
    assert manifest.minimum_distinct_employers_or_boards == 3
    assert manifest.maximum_candidate_attempts == 11
    assert manifest.replacement_rule == REPLACEMENT_RULE
    assert tuple(item.employer_or_board_id for item in manifest.candidates) == EMPLOYERS


def test_loaded_manifest_is_frozen_and_admits_only_exact_members(tmp_path: Path) -> None:
    path = tmp_path / "routes.json"
    manifest = ObservationRouteManifest.load(
        path,
        expected_sha256=_write_manifest(path),
    )
    first = manifest.candidates[0]

    assert manifest.admits(first.url, LEVER_LIST_ROUTE_CLASS)
    assert not manifest.admits(first.url, "lever_detail.v1")
    assert not manifest.admits(
        "https://api.lever.co/v0/postings/not-listed?limit=1&mode=json&skip=0",
        LEVER_LIST_ROUTE_CLASS,
    )
    assert manifest.allowed_urls == frozenset(item.url for item in manifest.candidates)
    assert isinstance(manifest.candidates, tuple)


def test_reload_of_unchanged_bytes_has_same_authority_identity(tmp_path: Path) -> None:
    path = tmp_path / "routes.json"
    digest = _write_manifest(path)
    first = ObservationRouteManifest.load(path, expected_sha256=digest)
    second = ObservationRouteManifest.load(path, expected_sha256=digest)

    assert first == second
