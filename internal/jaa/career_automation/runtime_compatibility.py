"""Fail-closed identity check for JAA's supported Playwright/Chromium pair."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from playwright.sync_api import Browser


PLAYWRIGHT_VERSION = "1.62.0"
CHROMIUM_REVISION = "1234"
CHROMIUM_BROWSER_VERSION = "151.0.7922.34"
CERTIFIED_PYTHON_VERSION = "3.12.13"
CHROMIUM_EXECUTABLE_RELATIVES = (
    Path("chrome-linux64/chrome"),
    Path("chrome-linux/chrome"),
    Path(
        "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/"
        "Google Chrome for Testing"
    ),
    Path(
        "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/"
        "Google Chrome for Testing"
    ),
    Path("chrome-win64/chrome.exe"),
)


class RuntimeCompatibilityError(RuntimeError):
    """The current process cannot prove the supported browser runtime."""

    def __init__(self, code: str, classification: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.classification = classification


@dataclass(frozen=True)
class BrowserRuntimeIdentity:
    python_implementation: str
    python_version: str
    playwright_version: str
    chromium_revision: str
    chromium_browser_version: str
    chromium_executable: str
    launched_browser_version: str | None


def _fail(code: str, classification: str, message: str) -> None:
    raise RuntimeCompatibilityError(code, classification, message)


def _certified_chromium_executable(value: str | Path) -> Path:
    """Bind Playwright's selected executable to the explicit pinned cache.

    Merely matching ``browsers.json`` is insufficient: Playwright may otherwise
    resolve a compatible-looking executable from an ambient user cache.  Both
    certification gates therefore name one cache, and the selected executable
    must be a real, non-symlinked file beneath its exact revision directory.
    """

    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if not configured:
        _fail(
            "browser_cache_unpinned",
            "incomplete_installation",
            "PLAYWRIGHT_BROWSERS_PATH must name the explicit certified cache",
        )
    declared = Path(configured)
    if not declared.is_absolute():
        _fail(
            "browser_cache_relative",
            "product_contract_mismatch",
            "PLAYWRIGHT_BROWSERS_PATH must be absolute",
        )
    if declared.is_symlink():
        _fail(
            "browser_cache_symlink",
            "product_contract_mismatch",
            "the certified browser cache cannot be a symlink",
        )
    try:
        cache = declared.resolve(strict=True)
    except OSError as exc:
        raise RuntimeCompatibilityError(
            "browser_cache_missing",
            "incomplete_installation",
            "the explicit certified browser cache is unavailable",
        ) from exc
    if not cache.is_dir():
        _fail(
            "browser_cache_invalid",
            "incomplete_installation",
            "the explicit certified browser cache is not a directory",
        )
    if cache != declared:
        _fail(
            "browser_cache_symlink",
            "product_contract_mismatch",
            "the certified browser cache path must be lexical and symlink-free",
        )

    selected = Path(value)
    if selected.is_symlink():
        _fail(
            "chromium_binary_symlink",
            "product_contract_mismatch",
            "the selected Chromium executable cannot be a symlink",
        )
    try:
        executable = selected.resolve(strict=True)
    except OSError as exc:
        raise RuntimeCompatibilityError(
            "chromium_binary_missing",
            "incomplete_installation",
            "run `python -m playwright install chromium` for revision 1234",
        ) from exc
    if not executable.is_file():
        _fail(
            "chromium_binary_missing",
            "incomplete_installation",
            "run `python -m playwright install chromium` for revision 1234",
        )
    try:
        lexical_relative = selected.relative_to(cache)
    except ValueError as exc:
        raise RuntimeCompatibilityError(
            "chromium_cache_escape",
            "product_contract_mismatch",
            "Playwright selected Chromium outside the explicit certified cache",
        ) from exc
    cursor = cache
    for part in lexical_relative.parts:
        cursor /= part
        if cursor.is_symlink():
            _fail(
                "chromium_binary_symlink",
                "product_contract_mismatch",
                "the selected Chromium path cannot contain a symlink",
            )
    try:
        relative = executable.relative_to(cache)
    except ValueError as exc:
        raise RuntimeCompatibilityError(
            "chromium_cache_escape",
            "product_contract_mismatch",
            "Playwright selected Chromium outside the explicit certified cache",
        ) from exc
    if not relative.parts or relative.parts[0] not in {
        f"chromium-{CHROMIUM_REVISION}",
        f"chromium_headless_shell-{CHROMIUM_REVISION}",
    }:
        _fail(
            "chromium_revision_path_mismatch",
            "product_contract_mismatch",
            "the selected executable is not inside the pinned Chromium revision directory",
        )
    return executable


def _installed_chromium_executable() -> Path:
    """Resolve the pinned executable without starting Playwright's driver."""

    configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if not configured:
        return _certified_chromium_executable(Path("/__missing_chromium__"))
    cache = Path(configured)
    revision = cache / f"chromium-{CHROMIUM_REVISION}"
    candidates = [revision / relative for relative in CHROMIUM_EXECUTABLE_RELATIVES]
    present = [candidate for candidate in candidates if candidate.is_file()]
    if len(present) != 1:
        _fail(
            "chromium_binary_missing",
            "incomplete_installation",
            "the explicit cache must contain exactly one pinned Chromium executable",
        )
    return _certified_chromium_executable(present[0])


def inspect_runtime(*, launch: bool = False) -> BrowserRuntimeIdentity:
    """Verify metadata, registry, selected executable and optionally a real launch."""
    implementation = platform.python_implementation()
    python_version = platform.python_version()
    if implementation != "CPython" or python_version != CERTIFIED_PYTHON_VERSION:
        _fail(
            "python_runtime_mismatch",
            "external_environment_limitation",
            f"the certified browser runtime is CPython {CERTIFIED_PYTHON_VERSION}",
        )
    try:
        distribution = importlib.metadata.distribution("playwright")
    except importlib.metadata.PackageNotFoundError:
        _fail(
            "playwright_distribution_missing",
            "incomplete_installation",
            "install the committed dependency lock before running browser gates",
        )
    version = distribution.version
    if version != PLAYWRIGHT_VERSION:
        _fail(
            "playwright_version_mismatch",
            "product_contract_mismatch",
            f"expected {PLAYWRIGHT_VERSION}, found {version}",
        )
    package_root = Path(distribution.locate_file("playwright")).resolve()
    registry_path = package_root / "driver" / "package" / "browsers.json"
    try:
        registry_bytes = registry_path.read_bytes()
    except OSError as exc:
        raise RuntimeCompatibilityError(
            "playwright_registry_unavailable",
            "incomplete_installation",
            "Playwright's installed Chromium registry is unavailable",
        ) from exc
    try:
        registry = json.loads(registry_bytes)
        chromium = next(
            row for row in registry["browsers"]
            if row.get("name") == "chromium" and row.get("installByDefault") is True
        )
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError) as exc:
        raise RuntimeCompatibilityError(
            "playwright_registry_invalid",
            "product_contract_mismatch",
            "Playwright's installed Chromium registry is malformed",
        ) from exc
    revision = str(chromium.get("revision", ""))
    browser_version = str(chromium.get("browserVersion", ""))
    if revision != CHROMIUM_REVISION or browser_version != CHROMIUM_BROWSER_VERSION:
        _fail(
            "chromium_registry_mismatch",
            "product_contract_mismatch",
            "expected revision "
            f"{CHROMIUM_REVISION}/{CHROMIUM_BROWSER_VERSION}, found "
            f"{revision}/{browser_version}",
        )

    try:
        executable = _installed_chromium_executable()
        launched_version: str | None = None
        if launch:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright

            with sync_playwright() as runtime:
                selected = _certified_chromium_executable(
                    runtime.chromium.executable_path
                )
                if selected != executable:
                    _fail(
                        "chromium_selected_executable_mismatch",
                        "product_contract_mismatch",
                        "Playwright selected a different pinned executable",
                    )
                try:
                    browser = runtime.chromium.launch(headless=True)
                except PlaywrightError as exc:
                    raise RuntimeCompatibilityError(
                        "chromium_launch_failed",
                        "external_environment_limitation",
                        "the pinned Chromium binary could not launch on this host",
                    ) from exc
                try:
                    launched_version = browser.version
                finally:
                    browser.close()
                if launched_version != CHROMIUM_BROWSER_VERSION:
                    _fail(
                        "chromium_launch_version_mismatch",
                        "product_contract_mismatch",
                        f"expected {CHROMIUM_BROWSER_VERSION}, launched {launched_version}",
                    )
    except RuntimeCompatibilityError:
        raise
    except ImportError as exc:
        raise RuntimeCompatibilityError(
            "playwright_runtime_import_failed",
            "incomplete_installation",
            "Playwright's Python runtime is missing or cannot be imported",
        ) from exc
    except OSError as exc:
        raise RuntimeCompatibilityError(
            "playwright_runtime_unavailable",
            "external_environment_limitation",
            "Playwright could not inspect the selected Chromium executable",
        ) from exc

    return BrowserRuntimeIdentity(
        python_implementation=implementation,
        python_version=python_version,
        playwright_version=version,
        chromium_revision=revision,
        chromium_browser_version=browser_version,
        chromium_executable=str(executable),
        launched_browser_version=launched_version,
    )


def inspect_active_browser(browser: "Browser") -> BrowserRuntimeIdentity:
    """Bind a corridor-owned browser to the pinned installed runtime.

    Unlike :func:`inspect_runtime`, this does not start a second Playwright
    driver.  It is intended for the immediate certified-click boundary where
    the active browser itself, not a separately launchable binary, is evidence.
    """

    implementation = platform.python_implementation()
    python_version = platform.python_version()
    if implementation != "CPython" or python_version != CERTIFIED_PYTHON_VERSION:
        _fail(
            "python_runtime_mismatch",
            "external_environment_limitation",
            f"the certified browser runtime is CPython {CERTIFIED_PYTHON_VERSION}",
        )
    try:
        distribution = importlib.metadata.distribution("playwright")
    except importlib.metadata.PackageNotFoundError:
        _fail(
            "playwright_distribution_missing",
            "incomplete_installation",
            "install the committed dependency lock before running browser gates",
        )
    if distribution.version != PLAYWRIGHT_VERSION:
        _fail(
            "playwright_version_mismatch",
            "product_contract_mismatch",
            f"expected {PLAYWRIGHT_VERSION}, found {distribution.version}",
        )
    registry_path = (
        Path(distribution.locate_file("playwright")).resolve()
        / "driver"
        / "package"
        / "browsers.json"
    )
    try:
        registry = json.loads(registry_path.read_bytes())
        chromium = next(
            row
            for row in registry["browsers"]
            if row.get("name") == "chromium" and row.get("installByDefault") is True
        )
    except (AttributeError, KeyError, OSError, StopIteration, TypeError, ValueError) as exc:
        raise RuntimeCompatibilityError(
            "playwright_registry_invalid",
            "product_contract_mismatch",
            "Playwright's installed Chromium registry is unavailable or malformed",
        ) from exc
    revision = str(chromium.get("revision", ""))
    browser_version = str(chromium.get("browserVersion", ""))
    if revision != CHROMIUM_REVISION or browser_version != CHROMIUM_BROWSER_VERSION:
        _fail(
            "chromium_registry_mismatch",
            "product_contract_mismatch",
            "the installed Chromium registry differs from the pinned runtime",
        )
    browser_type = getattr(browser, "browser_type", None)
    if getattr(browser_type, "name", None) != "chromium":
        _fail(
            "browser_type_mismatch",
            "product_contract_mismatch",
            "the active browser is not Chromium",
        )
    executable = _certified_chromium_executable(
        str(browser_type.executable_path)
    )
    launched_version = str(getattr(browser, "version", ""))
    if launched_version != CHROMIUM_BROWSER_VERSION:
        _fail(
            "chromium_launch_version_mismatch",
            "product_contract_mismatch",
            f"expected {CHROMIUM_BROWSER_VERSION}, launched {launched_version}",
        )
    return BrowserRuntimeIdentity(
        python_implementation=implementation,
        python_version=python_version,
        playwright_version=distribution.version,
        chromium_revision=revision,
        chromium_browser_version=browser_version,
        chromium_executable=str(executable),
        launched_browser_version=launched_version,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launch", action="store_true", help="launch the pinned browser")
    args = parser.parse_args(argv)
    try:
        identity = inspect_runtime(launch=args.launch)
    except RuntimeCompatibilityError as exc:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "code": exc.code,
                    "classification": exc.classification,
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps({"status": "ok", **asdict(identity)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
