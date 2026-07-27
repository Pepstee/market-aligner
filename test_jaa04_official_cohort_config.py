"""Canonical configuration contracts for the JAA-04 official cohort."""

from __future__ import annotations

from pathlib import Path

import pytest

from career_automation.employer_research import (
    ATS_AUTHORITY_CANARIES,
    DEFAULT_ATS_ROUTE_ADAPTERS,
    LIVE_ATS_AUTHORITY_CANARIES,
)
from career_automation.official_cohort import (
    AGGREGATORS,
    OFFICIAL_ADAPTERS,
    _validate_config,
    build,
)
from skeleton.configuration import load_config


ROOT = Path(__file__).resolve().parent
OVERNIGHT = ROOT / "skeleton" / "config.overnight.yaml"


def test_overnight_config_projects_one_canonical_official_interface() -> None:
    config = load_config(OVERNIGHT)
    assert "official_sources" not in config

    names, sections, terms = _validate_config(config)
    enabled = set(config["boards"]["enabled"])
    assert names == sorted(enabled & OFFICIAL_ADAPTERS)
    assert set(names) == OFFICIAL_ADAPTERS, (
        "config.overnight.yaml must enable every supported official adapter"
    )
    assert set(names).isdisjoint(AGGREGATORS)
    assert sections == {name: config.get(name, {}) for name in names}
    assert sections["greenhouse"]["companies"]["anthropic"] == "Anthropic"
    assert sections["lever"]["companies"]["palantir"] == "Palantir Technologies"
    assert terms == config["search_terms"]


def test_discovery_boards_are_filtered_without_becoming_authorities() -> None:
    config = {
        "boards": {
            "enabled": [
                "himalayas", "greenhouse", "jobicy", "workable", "remotefirst",
            ]
        },
        "greenhouse": {"companies": {"example": "Example"}},
        "workable": {"companies": {"example": "Example"}},
        "search_terms": ["software engineer"],
    }
    names, sections, terms = _validate_config(config)
    assert names == ["greenhouse", "workable"]
    assert set(sections) == set(names)
    assert terms == ["software engineer"]


def test_live_official_cohort_refuses_to_start_without_access_authority(
    tmp_path: Path,
) -> None:
    with pytest.raises(RuntimeError, match="requires public access authority"):
        build(
            tmp_path / "not-read-without-authority.yaml",
            tmp_path / "output.json",
            tmp_path / "raw",
        )


def test_live_greenhouse_authority_uses_current_public_job_board_api_host() -> None:
    frozen = next(
        row for row in ATS_AUTHORITY_CANARIES
        if row.job_key.startswith("greenhouse:")
    )
    live = next(
        row for row in LIVE_ATS_AUTHORITY_CANARIES
        if row.job_key == frozen.job_key
    )
    assert frozen.authority_url.startswith("https://api.greenhouse.io/")
    assert live.authority_url == (
        "https://boards-api.greenhouse.io/v1/boards/anthropic/jobs/5030244008"
    )
    assert live.authority_hosts == (
        "job-boards.greenhouse.io",
        "boards-api.greenhouse.io",
    )
    assert DEFAULT_ATS_ROUTE_ADAPTERS["greenhouse"].authority_hosts == (
        "boards-api.greenhouse.io",
    )


@pytest.mark.parametrize(
    ("config", "message"),
    (
        (
            {"official_sources": {"greenhouse": {}}},
            "official_sources is retired",
        ),
        (
            {"boards": {"enabled": ["himalayas", "jobicy"]}},
            "no supported official adapters",
        ),
        (
            {"boards": {"enabled": "greenhouse"}},
            "boards.enabled must be a non-empty list",
        ),
        (
            {"boards": {"enabled": ["greenhouse"]}, "greenhouse": []},
            "greenhouse configuration must be a mapping",
        ),
        (
            {
                "boards": {"enabled": ["greenhouse"]},
                "search_terms": ["software", ""],
            },
            "search_terms entries must be non-empty strings",
        ),
        (
            {
                "boards": {"enabled": ["greenhouse"]},
                "search_terms": [],
            },
            "search_terms must be a non-empty list",
        ),
    ),
)
def test_competing_or_malformed_config_fails_explicitly(
    config: dict[str, object], message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _validate_config(config)


@pytest.mark.parametrize("extends", (False, 7, [], ""))
def test_inherited_config_rejects_non_path_extends(
    tmp_path: Path, extends: object,
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(f"extends: {extends!r}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="extends must be a non-empty string path"):
        load_config(path)


def test_inherited_config_rejects_cycles(tmp_path: Path) -> None:
    first, second = tmp_path / "first.yaml", tmp_path / "second.yaml"
    first.write_text("extends: second.yaml\n", encoding="utf-8")
    second.write_text("extends: first.yaml\n", encoding="utf-8")
    with pytest.raises(ValueError, match="configuration extends cycle"):
        load_config(first)


@pytest.mark.parametrize("payload", ("[]\n", "false\n", "'scalar'\n"))
def test_config_root_must_be_a_mapping(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "invalid-root.yaml"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError, match="configuration must be a mapping"):
        load_config(path)
