"""Hermetic unit tests for the Playwright/Chromium runtime identity gate."""

from __future__ import annotations

import importlib.metadata
import json
import sys
import types
from pathlib import Path

import pytest

from career_automation import runtime_compatibility as runtime


class _FakePlaywrightError(Exception):
    pass


@pytest.fixture
def compatible_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    package_root = tmp_path / "site-packages" / "playwright"
    registry_path = package_root / "driver" / "package" / "browsers.json"
    registry_path.parent.mkdir(parents=True)
    registry_path.write_text(
        json.dumps(
            {
                "browsers": [
                    {
                        "name": "chromium",
                        "revision": runtime.CHROMIUM_REVISION,
                        "installByDefault": True,
                        "browserVersion": runtime.CHROMIUM_BROWSER_VERSION,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    browser_cache = tmp_path / "browser-cache"
    executable = browser_cache / f"chromium-{runtime.CHROMIUM_REVISION}" / "chrome-linux64" / "chrome"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"synthetic executable marker")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(browser_cache))

    class Distribution:
        version = runtime.PLAYWRIGHT_VERSION

        @staticmethod
        def locate_file(name: str) -> Path:
            assert name == "playwright"
            return package_root

    state: dict[str, object] = {
        "distribution": Distribution(),
        "launch_error": None,
        "launched_version": runtime.CHROMIUM_BROWSER_VERSION,
        "manager_entries": 0,
    }

    def distribution(name: str) -> object:
        assert name == "playwright"
        error = state.get("distribution_error")
        if isinstance(error, BaseException):
            raise error
        return state["distribution"]

    monkeypatch.setattr(runtime.importlib.metadata, "distribution", distribution)
    monkeypatch.setattr(
        runtime,
        "platform",
        types.SimpleNamespace(
            python_implementation=lambda: "CPython",
            python_version=lambda: "3.12.13",
        ),
    )
    monkeypatch.setattr(runtime, "sys", types.SimpleNamespace(version_info=(3, 12, 13)))

    class Browser:
        version = runtime.CHROMIUM_BROWSER_VERSION

        def __init__(self) -> None:
            self.version = str(state["launched_version"])
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class Chromium:
        executable_path = str(executable)

        @staticmethod
        def launch(*, headless: bool) -> Browser:
            assert headless is True
            error = state.get("launch_error")
            if isinstance(error, BaseException):
                raise error
            return Browser()

    class Playwright:
        chromium = Chromium()

    class Manager:
        def __enter__(self) -> Playwright:
            state["manager_entries"] = int(state["manager_entries"]) + 1
            return Playwright()

        def __exit__(self, *_args: object) -> None:
            return None

    package = types.ModuleType("playwright")
    package.__path__ = []  # type: ignore[attr-defined]
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.Error = _FakePlaywrightError  # type: ignore[attr-defined]
    sync_api.sync_playwright = Manager  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    state.update(
        {
            "executable": executable,
            "browser_cache": browser_cache,
            "registry_path": registry_path,
            "sync_api": sync_api,
        }
    )
    return state


def test_exact_runtime_tuple_and_launch_are_reported(
    compatible_runtime: dict[str, object],
) -> None:
    identity = runtime.inspect_runtime(launch=True)

    assert identity.python_version == "3.12.13"
    assert identity.playwright_version == runtime.PLAYWRIGHT_VERSION
    assert identity.chromium_revision == runtime.CHROMIUM_REVISION
    assert identity.chromium_browser_version == runtime.CHROMIUM_BROWSER_VERSION
    assert identity.launched_browser_version == runtime.CHROMIUM_BROWSER_VERSION
    assert compatible_runtime["manager_entries"] == 1


def test_metadata_only_inspection_does_not_start_playwright_driver(
    compatible_runtime: dict[str, object],
) -> None:
    identity = runtime.inspect_runtime(launch=False)

    assert identity.chromium_revision == runtime.CHROMIUM_REVISION
    assert identity.launched_browser_version is None
    assert compatible_runtime["manager_entries"] == 0


def test_wrong_python_is_an_external_environment_limitation(
    compatible_runtime: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        runtime,
        "platform",
        types.SimpleNamespace(
            python_implementation=lambda: "CPython",
            python_version=lambda: "3.13.0",
        ),
    )

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "python_runtime_mismatch",
        "external_environment_limitation",
    )


def test_wrong_python_patch_is_an_external_environment_limitation(
    compatible_runtime: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        runtime,
        "platform",
        types.SimpleNamespace(
            python_implementation=lambda: "CPython",
            python_version=lambda: "3.12.12",
        ),
    )

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "python_runtime_mismatch",
        "external_environment_limitation",
    )


def test_missing_distribution_is_an_incomplete_installation(
    compatible_runtime: dict[str, object],
) -> None:
    compatible_runtime["distribution_error"] = importlib.metadata.PackageNotFoundError(
        "playwright"
    )

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "playwright_distribution_missing",
        "incomplete_installation",
    )


def test_wrong_playwright_version_is_a_product_contract_mismatch(
    compatible_runtime: dict[str, object],
) -> None:
    distribution = compatible_runtime["distribution"]
    distribution.version = "1.61.0"  # type: ignore[attr-defined]

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "playwright_version_mismatch",
        "product_contract_mismatch",
    )


def test_missing_registry_is_an_incomplete_installation(
    compatible_runtime: dict[str, object],
) -> None:
    registry_path = compatible_runtime["registry_path"]
    assert isinstance(registry_path, Path)
    registry_path.unlink()

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "playwright_registry_unavailable",
        "incomplete_installation",
    )


def test_malformed_registry_is_a_product_contract_mismatch(
    compatible_runtime: dict[str, object],
) -> None:
    registry_path = compatible_runtime["registry_path"]
    assert isinstance(registry_path, Path)
    registry_path.write_text("{", encoding="utf-8")

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "playwright_registry_invalid",
        "product_contract_mismatch",
    )


def test_malformed_registry_row_is_a_product_contract_mismatch(
    compatible_runtime: dict[str, object],
) -> None:
    registry_path = compatible_runtime["registry_path"]
    assert isinstance(registry_path, Path)
    registry_path.write_text(json.dumps({"browsers": ["chromium"]}), encoding="utf-8")

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "playwright_registry_invalid",
        "product_contract_mismatch",
    )


def test_wrong_registry_tuple_is_a_product_contract_mismatch(
    compatible_runtime: dict[str, object],
) -> None:
    registry_path = compatible_runtime["registry_path"]
    assert isinstance(registry_path, Path)
    registry_path.write_text(
        json.dumps(
            {
                "browsers": [
                    {
                        "name": "chromium",
                        "revision": "1228",
                        "installByDefault": True,
                        "browserVersion": runtime.CHROMIUM_BROWSER_VERSION,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "chromium_registry_mismatch",
        "product_contract_mismatch",
    )


def test_broken_playwright_import_is_an_incomplete_installation(
    compatible_runtime: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime(launch=True)
    assert (failure.value.code, failure.value.classification) == (
        "playwright_runtime_import_failed",
        "incomplete_installation",
    )


def test_missing_browser_binary_is_an_incomplete_installation(
    compatible_runtime: dict[str, object],
) -> None:
    executable = compatible_runtime["executable"]
    assert isinstance(executable, Path)
    executable.unlink()

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "chromium_binary_missing",
        "incomplete_installation",
    )


def test_missing_explicit_browser_cache_is_an_incomplete_installation(
    compatible_runtime: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH")

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "browser_cache_unpinned",
        "incomplete_installation",
    )


def test_selected_executable_cannot_escape_explicit_cache(
    compatible_runtime: dict[str, object], tmp_path: Path
) -> None:
    outside = tmp_path / "outside" / "chromium-1234" / "chrome-linux64" / "chrome"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"ambient browser")

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime._certified_chromium_executable(outside)
    assert (failure.value.code, failure.value.classification) == (
        "chromium_cache_escape",
        "product_contract_mismatch",
    )


def test_symlinked_browser_cache_is_rejected(
    compatible_runtime: dict[str, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    browser_cache = compatible_runtime["browser_cache"]
    assert isinstance(browser_cache, Path)
    alias = tmp_path / "browser-cache-alias"
    alias.symlink_to(browser_cache, target_is_directory=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(alias))

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime()
    assert (failure.value.code, failure.value.classification) == (
        "browser_cache_symlink",
        "product_contract_mismatch",
    )


def test_browser_launch_failure_is_an_external_environment_limitation(
    compatible_runtime: dict[str, object],
) -> None:
    compatible_runtime["launch_error"] = _FakePlaywrightError("host refused launch")

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime(launch=True)
    assert (failure.value.code, failure.value.classification) == (
        "chromium_launch_failed",
        "external_environment_limitation",
    )


def test_launched_browser_version_mismatch_is_a_product_contract_mismatch(
    compatible_runtime: dict[str, object],
) -> None:
    compatible_runtime["launched_version"] = "150.0.0.0"

    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime.inspect_runtime(launch=True)
    assert (failure.value.code, failure.value.classification) == (
        "chromium_launch_version_mismatch",
        "product_contract_mismatch",
    )


@pytest.mark.parametrize("version_matches", (True, False))
def test_active_browser_is_bound_without_starting_another_driver(
    compatible_runtime: dict[str, object], version_matches: bool,
) -> None:
    browser = types.SimpleNamespace(
        browser_type=types.SimpleNamespace(
            name="chromium", executable_path=str(compatible_runtime["executable"]),
        ),
        version=runtime.CHROMIUM_BROWSER_VERSION if version_matches else "0.0.0.0",
    )
    if version_matches:
        identity = runtime.inspect_active_browser(browser)
        assert identity.launched_browser_version == runtime.CHROMIUM_BROWSER_VERSION
    else:
        with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
            runtime.inspect_active_browser(browser)
        assert failure.value.code == "chromium_launch_version_mismatch"
    assert compatible_runtime["manager_entries"] == 0


def test_intermediate_executable_symlink_is_rejected(
    compatible_runtime: dict[str, object],
) -> None:
    executable = compatible_runtime["executable"]
    assert isinstance(executable, Path)
    alias = executable.parent.parent / "alias"
    alias.symlink_to(executable.parent, target_is_directory=True)
    with pytest.raises(runtime.RuntimeCompatibilityError) as failure:
        runtime._certified_chromium_executable(alias / executable.name)
    assert failure.value.code == "chromium_binary_symlink"


def test_cli_reports_blocked_classification_without_launch(
    compatible_runtime: dict[str, object], monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(runtime, "sys", sys)
    monkeypatch.setattr(runtime.platform, "python_version", lambda: "0.0.0")
    assert runtime.main([]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    document = json.loads(output.err)
    assert document["status"] == "blocked"
    assert document["code"] == "python_runtime_mismatch"
    assert document["classification"] == "external_environment_limitation"
    assert compatible_runtime["manager_entries"] == 0
