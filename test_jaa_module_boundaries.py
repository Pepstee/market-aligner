from pathlib import Path

from jaa_core.module_boundaries import (
    LEGACY_OWNERSHIP,
    MODULE_DEPENDENCIES,
    assert_public_module_boundaries,
)


ROOT = Path(__file__).resolve().parent


def test_public_modules_obey_one_way_dependencies() -> None:
    assert_public_module_boundaries(ROOT)
    assert MODULE_DEPENDENCIES["jaa_core"] == frozenset()
    assert "form_filling" not in MODULE_DEPENDENCIES["cv_generation"]


def test_legacy_files_have_one_explicit_owner_and_exist() -> None:
    assert len(LEGACY_OWNERSHIP) == len(set(LEGACY_OWNERSHIP))
    assert set(LEGACY_OWNERSHIP.values()) == {
        "jaa_core",
        "cv_generation",
        "form_filling",
    }
    assert all((ROOT / path).is_file() for path in LEGACY_OWNERSHIP)
