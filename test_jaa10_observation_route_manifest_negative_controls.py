"""Fail-closed controls for JAA-10 route-manifest authority data."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import career_automation.observation_route_manifest as route_module
from career_automation.observation_route_manifest import (
    LEVER_LIST_ROUTE_CLASS,
    REPLACEMENT_RULE,
    ROUTE_MANIFEST_SCHEMA,
    ObservationRouteManifest,
    RouteManifestError,
)


EMPLOYERS = tuple(f"employer-{index}" for index in range(11))


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def _document() -> dict[str, object]:
    return {
        "schema": ROUTE_MANIFEST_SCHEMA,
        "route_class": LEVER_LIST_ROUTE_CLASS,
        "required_observation_units": 10,
        "minimum_fully_verified_units": 8,
        "minimum_distinct_employers_or_boards": 3,
        "maximum_candidate_attempts": 11,
        "replacement_rule": REPLACEMENT_RULE,
        "candidates": [
            {
                "employer_or_board_id": employer,
                "url": (
                    f"https://api.lever.co/v0/postings/{employer}"
                    "?limit=1&mode=json&skip=0"
                ),
            }
            for employer in EMPLOYERS
        ],
    }


def _write(path: Path, raw: bytes, *, mode: int = 0o444) -> str:
    path.write_bytes(raw)
    path.chmod(mode)
    return hashlib.sha256(raw).hexdigest()


def _load_document(path: Path, document: object) -> ObservationRouteManifest:
    raw = _canonical(document) + b"\n"
    digest = _write(path, raw)
    return ObservationRouteManifest.load(path, expected_sha256=digest)


def test_expected_hash_is_strict_and_hash_mismatch_fails(tmp_path: Path) -> None:
    path = tmp_path / "routes.json"
    digest = _write(path, _canonical(_document()) + b"\n")
    with pytest.raises(RouteManifestError, match="expected_sha256"):
        ObservationRouteManifest.load(path, expected_sha256=digest.upper())
    with pytest.raises(RouteManifestError, match="SHA-256 differs"):
        ObservationRouteManifest.load(path, expected_sha256="0" * 64)


def test_mutable_source_and_symlink_fail(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    digest = _write(target, _canonical(_document()) + b"\n", mode=0o644)
    with pytest.raises(RouteManifestError, match="mode 0444"):
        ObservationRouteManifest.load(target, expected_sha256=digest)

    target.chmod(0o444)
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(RouteManifestError, match="symlink"):
        ObservationRouteManifest.load(link, expected_sha256=digest)


def test_source_inside_product_root_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "routes.json"
    digest = _write(path, _canonical(_document()) + b"\n")
    monkeypatch.setattr(route_module, "ROOT", tmp_path.resolve())
    with pytest.raises(RouteManifestError, match="outside"):
        ObservationRouteManifest.load(path, expected_sha256=digest)


@pytest.mark.parametrize(
    "raw",
    (
        b"{}",
        b"{}\n\n",
        b'{"schema":"jaa10.route-manifest.v1","schema":"duplicate"}\n',
        b'{"value":NaN}\n',
        b'{ "schema" : "jaa10.route-manifest.v1" }\n',
        b"\xff\n",
    ),
)
def test_noncanonical_or_ambiguous_json_fails(tmp_path: Path, raw: bytes) -> None:
    path = tmp_path / "routes.json"
    digest = _write(path, raw)
    with pytest.raises(RouteManifestError, match="ROUTE_MANIFEST_REJECTED"):
        ObservationRouteManifest.load(path, expected_sha256=digest)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema", "jaa10.route-manifest.v2"),
        ("route_class", "lever_detail.v1"),
        ("required_observation_units", 9),
        ("required_observation_units", True),
        ("minimum_fully_verified_units", 7),
        ("minimum_distinct_employers_or_boards", 2),
        ("maximum_candidate_attempts", 12),
        ("replacement_rule", "pick-any-live-route"),
    ),
)
def test_fixed_contract_mutation_fails(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    document = _document()
    document[field] = value
    with pytest.raises(RouteManifestError, match="ROUTE_MANIFEST_REJECTED"):
        _load_document(tmp_path / "routes.json", document)


def test_unknown_manifest_or_candidate_field_fails(tmp_path: Path) -> None:
    document = _document()
    document["authority_note"] = "not admitted"
    with pytest.raises(RouteManifestError, match="field set"):
        _load_document(tmp_path / "manifest-extra.json", document)

    document = _document()
    candidates = document["candidates"]
    assert isinstance(candidates, list)
    candidates[0]["detail_url"] = "https://example.invalid"  # type: ignore[index]
    with pytest.raises(RouteManifestError, match="candidate field set"):
        _load_document(tmp_path / "candidate-extra.json", document)


def test_manifest_must_be_oversubscribed_and_unique(tmp_path: Path) -> None:
    document = _document()
    candidates = document["candidates"]
    assert isinstance(candidates, list)
    document["candidates"] = candidates[:10]
    document["maximum_candidate_attempts"] = 10
    with pytest.raises(RouteManifestError, match="oversubscribed"):
        _load_document(tmp_path / "short.json", document)

    document = _document()
    candidates = document["candidates"]
    assert isinstance(candidates, list)
    candidates[-1] = dict(candidates[0])  # type: ignore[arg-type]
    with pytest.raises(RouteManifestError, match="duplicate candidate"):
        _load_document(tmp_path / "duplicate.json", document)


@pytest.mark.parametrize(
    "url",
    (
        "http://api.lever.co/v0/postings/employer-0?limit=1&mode=json&skip=0",
        "https://user@api.lever.co/v0/postings/employer-0?limit=1&mode=json&skip=0",
        "https://api.lever.co:443/v0/postings/employer-0?limit=1&mode=json&skip=0",
        "https://127.0.0.1/v0/postings/employer-0?limit=1&mode=json&skip=0",
        "https://api.lever.co/v0/postings/employer-0/job-id?limit=1&mode=json&skip=0",
        "https://api.lever.co/v0/postings/employer-0?mode=json&limit=1&skip=0",
        "https://api.lever.co/v0/postings/employer-0?limit=1&mode=json&skip=0&limit=1",
        "https://api.lever.co/v0/postings/employer-0?limit=1&mode=json&skip=0#fragment",
    ),
)
def test_nonexact_route_fails(tmp_path: Path, url: str) -> None:
    document = _document()
    candidates = document["candidates"]
    assert isinstance(candidates, list)
    candidates[0]["url"] = url  # type: ignore[index]
    with pytest.raises(RouteManifestError, match="exact admitted Lever list route"):
        _load_document(tmp_path / "routes.json", document)


def test_employer_identity_must_match_path_token(tmp_path: Path) -> None:
    document = _document()
    candidates = document["candidates"]
    assert isinstance(candidates, list)
    candidates[0]["employer_or_board_id"] = "different"  # type: ignore[index]
    with pytest.raises(RouteManifestError, match="exact admitted Lever list route"):
        _load_document(tmp_path / "routes.json", document)
