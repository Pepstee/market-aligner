"""Canonical configuration contracts for the JAA-04 official cohort."""

from __future__ import annotations

from pathlib import Path

import pytest

from career_automation.official_cohort import (
    AGGREGATORS,
    OFFICIAL_ADAPTERS,
    _validate_config,
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
